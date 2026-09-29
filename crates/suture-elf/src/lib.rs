//! ELF64 parsing and file rebuilding.
//!
//! Reading uses `goblin`; **writing is ours**, because the file-rebuild logic
//! (shifting `p_offset` for a grown program header table, appending a new
//! `PT_LOAD`) is a core part of suture and no off-the-shelf library exposes it.
//!
//! Layout math is the load-bearing part of this module. See `docs/DESIGN.md`
//! §5 and the unit tests at the bottom of this file, which pin the invariants.

use anyhow::{bail, Context, Result};
use goblin::elf::header::{ELFCLASS64, EM_X86_64, ELFDATA2LSB, ET_DYN, ET_EXEC};
// ET_EXEC is 2 in the System V ABI; 1 is ET_NONE. Getting this wrong is the
// single easiest way to make a valid binary look unparseable.
const _: () = assert!(ET_EXEC == 2 && ET_DYN == 3 && EM_X86_64 == 62);

/// Program header types and permission bits, re-exported so the pipeline and
/// its tests do not each grow a private copy of these magic numbers.
pub use goblin::elf::program_header::{PF_R, PF_W, PF_X, PT_LOAD};
use goblin::elf::Elf;
use std::path::Path;

pub const PAGE: u64 = 0x1000;
pub const EHDR_SIZE: u64 = 64;
pub const PHDR_SIZE: u64 = 56;
pub const SHDR_SIZE: u64 = 64;

/// Default gap between the end of the last `PT_LOAD` and suture's arena.
///
/// Deliberately non-zero: a zero gap would place our mapping immediately after
/// the binary's, where ASan shadow reservations and the early brk() region may
/// already live. 64 KiB clears both in practice.
pub const DEFAULT_GUARD: u64 = 0x10000;

/// Reject absurd inputs before we try to allocate for them.
///
/// `MAX_SHNUM` is deliberately far below `u16::MAX`: 65535 section headers is
/// already 4 MB of table, and using `u16::MAX` as the ceiling made the
/// `e_shnum > MAX_SHNUM` guard dead code -- it could never fire, so it looked
/// like validation while validating nothing.
const MAX_PHNUM: u16 = 4096;
const MAX_SHNUM: u16 = 4096;
/// An arena larger than this is almost certainly a bug, not a real binary.
const MAX_ARENA: u64 = 1 << 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProgramHeader {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

impl ProgramHeader {
    fn read(b: &[u8], off: usize) -> Result<Self> {
        // Fixed-width reads. Every call site is bounds-checked by the caller
        // (the phdr table is validated against the file length before we get
        // here), so `unwrap` on the slice conversion cannot fire.
        let u32at = |i: usize| u32::from_le_bytes(b[off + i..off + i + 4].try_into().unwrap());
        let u64at =
            |i: usize| u64::from_le_bytes(b[off + i..off + i + 8].try_into().unwrap());
        Ok(ProgramHeader {
            p_type: u32at(0),
            p_flags: u32at(4),
            p_offset: u64at(8),
            p_vaddr: u64at(16),
            p_paddr: u64at(24),
            p_filesz: u64at(32),
            p_memsz: u64at(40),
            p_align: u64at(48),
        })
    }

    /// Serialize into `b` at byte offset `off`. Public so tests and the
    /// pipeline can build synthetic images without re-implementing the layout.
    pub fn write(&self, b: &mut [u8], off: usize) {
        b[off..off + 4].copy_from_slice(&self.p_type.to_le_bytes());
        b[off + 4..off + 8].copy_from_slice(&self.p_flags.to_le_bytes());
        b[off + 8..off + 16].copy_from_slice(&self.p_offset.to_le_bytes());
        b[off + 16..off + 24].copy_from_slice(&self.p_vaddr.to_le_bytes());
        b[off + 24..off + 32].copy_from_slice(&self.p_paddr.to_le_bytes());
        b[off + 32..off + 40].copy_from_slice(&self.p_filesz.to_le_bytes());
        b[off + 40..off + 48].copy_from_slice(&self.p_memsz.to_le_bytes());
        b[off + 48..off + 56].copy_from_slice(&self.p_align.to_le_bytes());
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SectionHeader {
    pub sh_name: u32,
    pub sh_type: u32,
    pub sh_flags: u64,
    pub sh_addr: u64,
    pub sh_offset: u64,
    pub sh_size: u64,
    pub sh_link: u32,
    pub sh_info: u32,
    pub sh_addralign: u64,
    pub sh_entsize: u64,
}

impl SectionHeader {
    fn read(b: &[u8], off: usize) -> Result<Self> {
        let u32at = |i: usize| u32::from_le_bytes(b[off + i..off + i + 4].try_into().unwrap());
        let u64at =
            |i: usize| u64::from_le_bytes(b[off + i..off + i + 8].try_into().unwrap());
        Ok(SectionHeader {
            sh_name: u32at(0),
            sh_type: u32at(4),
            sh_flags: u64at(8),
            sh_addr: u64at(16),
            sh_offset: u64at(24),
            sh_size: u64at(32),
            sh_link: u32at(36),
            sh_info: u32at(40),
            sh_addralign: u64at(48),
            sh_entsize: u64at(56),
        })
    }

    fn write(&self, b: &mut [u8], off: usize) {
        b[off..off + 4].copy_from_slice(&self.sh_name.to_le_bytes());
        b[off + 4..off + 8].copy_from_slice(&self.sh_type.to_le_bytes());
        b[off + 8..off + 16].copy_from_slice(&self.sh_flags.to_le_bytes());
        b[off + 16..off + 24].copy_from_slice(&self.sh_addr.to_le_bytes());
        b[off + 24..off + 32].copy_from_slice(&self.sh_offset.to_le_bytes());
        b[off + 32..off + 40].copy_from_slice(&self.sh_size.to_le_bytes());
        b[off + 36..off + 40].copy_from_slice(&self.sh_link.to_le_bytes());
        b[off + 40..off + 44].copy_from_slice(&self.sh_info.to_le_bytes());
        b[off + 48..off + 56].copy_from_slice(&self.sh_addralign.to_le_bytes());
        b[off + 56..off + 64].copy_from_slice(&self.sh_entsize.to_le_bytes());
    }
}

/// A parsed ELF64 image, held together with the original bytes so it can be
/// rebuilt into a new file.
#[derive(Debug)]
pub struct Elf64Image {
    pub bytes: Vec<u8>,
    pub e_type: u16,
    pub e_machine: u16,
    pub e_entry: u64,
    pub e_phoff: u64,
    pub e_shoff: u64,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
    pub phdrs: Vec<ProgramHeader>,
    pub sections: Vec<SectionHeader>,
}

impl Elf64Image {
    pub fn from_path(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path)
            .with_context(|| format!("reading {}", path.display()))?;
        Self::parse(bytes).with_context(|| format!("parsing {}", path.display()))
    }

    pub fn parse(bytes: Vec<u8>) -> Result<Self> {
        // Sanity-check the header ourselves before handing to goblin, so error
        // messages are ours and we never index out of bounds.
        if bytes.len() < EHDR_SIZE as usize {
            bail!("file is {} bytes, too small for an ELF64 header", bytes.len());
        }
        if &bytes[0..4] != b"\x7fELF" {
            bail!("not an ELF file (bad magic)");
        }
        if bytes[4] != ELFCLASS64 {
            bail!("not ELFCLASS64 (got class byte {:#x}); suture is x86-64 only", bytes[4]);
        }
        if bytes[5] != ELFDATA2LSB {
            bail!("not little-endian");
        }

        // Bounds are established by the size checks immediately below, before
        // any of these closures are called.
        let rd16 = |o: usize| u16::from_le_bytes(bytes[o..o + 2].try_into().unwrap());
        let rd64 = |o: usize| u64::from_le_bytes(bytes[o..o + 8].try_into().unwrap());

        let e_type = rd16(16);
        let e_machine = rd16(18);
        let e_entry = rd64(24);
        let e_phoff = rd64(32);
        let e_shoff = rd64(40);
        let e_phentsize = rd16(54);
        let e_phnum = rd16(56);
        let e_shentsize = rd16(58);
        let e_shnum = rd16(60);
        let e_shstrndx = rd16(62);

        if e_machine != EM_X86_64 {
            bail!("not x86-64 (e_machine = {:#x}); suture is x86-64 only", e_machine);
        }
        if e_type != ET_EXEC && e_type != ET_DYN {
            bail!("e_type {:#x} is neither ET_EXEC nor ET_DYN", e_type);
        }
        if e_phentsize != PHDR_SIZE as u16 {
            bail!("unexpected e_phentsize {} (want {})", e_phentsize, PHDR_SIZE);
        }
        if e_phnum > MAX_PHNUM {
            bail!("implausible e_phnum {}", e_phnum);
        }
        if e_shnum > MAX_SHNUM {
            bail!("implausible e_shnum {}", e_shnum);
        }
        if e_phnum == 0 {
            bail!("no program headers; nothing to instrument");
        }

        let ph_end = e_phoff
            .checked_add(u64::from(e_phnum) * PHDR_SIZE)
            .context("program header table overflows")?;
        if ph_end > bytes.len() as u64 {
            bail!(
                "program header table ends at {} but file is {} bytes",
                ph_end,
                bytes.len()
            );
        }

        let mut phdrs = Vec::with_capacity(usize::from(e_phnum));
        for i in 0..usize::from(e_phnum) {
            phdrs.push(ProgramHeader::read(
                &bytes,
                (e_phoff + (i as u64) * PHDR_SIZE) as usize,
            )?);
        }

        let mut sections = Vec::new();
        if e_shoff != 0 && e_shnum > 0 {
            if e_shentsize != SHDR_SIZE as u16 {
                bail!("unexpected e_shentsize {}", e_shentsize);
            }
            let sh_end = e_shoff
                .checked_add(u64::from(e_shnum) * SHDR_SIZE)
                .context("section header table overflows")?;
            if sh_end > bytes.len() as u64 {
                bail!("section header table ends past end of file");
            }
            sections.reserve(usize::from(e_shnum));
            for i in 0..usize::from(e_shnum) {
                sections.push(SectionHeader::read(
                    &bytes,
                    (e_shoff + (i as u64) * SHDR_SIZE) as usize,
                )?);
            }
        }

        // Validate every segment's file range. A `PT_LOAD` whose p_offset is
        // past the end of the file parses fine structurally but cannot be
        // mapped -- and if we did not catch it here, `rebuild_with_arena`
        // would happily produce an output that fails at execve time, with the
        // real cause buried in a kernel log.
        for (i, p) in phdrs.iter().enumerate() {
            // Only file-backed segments have a meaningful p_filesz.
            let end = p.p_offset.checked_add(p.p_filesz);
            match end {
                None => bail!(
                    "program header {}: p_offset + p_filesz overflows ({:#x} + {:#x})",
                    i,
                    p.p_offset,
                    p.p_filesz
                ),
                Some(end) if end > bytes.len() as u64 => bail!(
                    "program header {}: file range {:#x}..{:#x} is outside the \
                     {}-byte file",
                    i,
                    p.p_offset,
                    end,
                    bytes.len()
                ),
                _ => {}
            }
            if p.p_memsz < p.p_filesz {
                bail!(
                    "program header {}: p_memsz {:#x} < p_filesz {:#x}",
                    i,
                    p.p_memsz,
                    p.p_filesz
                );
            }
        }

        // Cross-check against goblin. Two independent parsers disagreeing is
        // exactly the situation where we must not emit a binary.
        if let Ok(g) = Elf::parse(&bytes) {
            if g.header.e_type != e_type || g.program_headers.len() != phdrs.len() {
                bail!("internal inconsistency between our parse and goblin");
            }
        }

        Ok(Elf64Image {
            bytes,
            e_type,
            e_machine,
            e_entry,
            e_phoff,
            e_shoff,
            e_phentsize,
            e_phnum,
            e_shentsize,
            e_shnum,
            e_shstrndx,
            phdrs,
            sections,
        })
    }

    /// First executable, non-writable, file-backed `PT_LOAD`. This is `.text`
    /// for every realistic binary.
    pub fn text_segment(&self) -> Option<ProgramHeader> {
        self.phdrs
            .iter()
            .find(|p| p.p_type == PT_LOAD && p.p_flags & PF_X != 0 && p.p_filesz > 0)
            .copied()
    }

    /// Virtual address one past the end of every `PT_LOAD` mapping.
    pub fn max_vaddr_end(&self) -> u64 {
        self.phdrs
            .iter()
            .filter(|p| p.p_type == PT_LOAD)
            .map(|p| p.p_vaddr + p.p_memsz)
            .max()
            .unwrap_or(0)
    }

    pub fn find_section_by_name(&self, name: &str) -> Option<&SectionHeader> {
        if self.sections.is_empty() || usize::from(self.e_shstrndx) >= self.sections.len() {
            return None;
        }
        let strtab = &self.sections[usize::from(self.e_shstrndx)];
        let str_off = strtab.sh_offset as usize;
        let str_end = str_off + strtab.sh_size as usize;
        if str_end > self.bytes.len() {
            return None;
        }
        self.sections.iter().find(|s| {
            let start = str_off + s.sh_name as usize;
            if start >= str_end {
                return false;
            }
            let tail = &self.bytes[start..str_end];
            let end = tail.iter().position(|&c| c == 0).unwrap_or(tail.len());
            &tail[..end] == name.as_bytes()
        })
    }

    pub fn section_data(&self, s: &SectionHeader) -> &[u8] {
        let o = s.sh_offset as usize;
        let n = s.sh_size as usize;
        &self.bytes[o..(o + n).min(self.bytes.len())]
    }

    /// The virtual address suture's arena will occupy.
    ///
    /// Depends only on the original image and the guard -- **not** on the
    /// arena's contents or size. That is load-bearing: it lets the instrumenter
    /// know the arena's final address *before* emitting a single stub, so stubs
    /// and relocated blocks can be encoded against the real address in one pass
    /// instead of being encoded twice or carrying placeholder displacements.
    pub fn arena_vaddr(&self, guard: u64) -> u64 {
        (self.max_vaddr_end() + guard).div_ceil(PAGE) * PAGE
    }

    /// Rebuild the file with suture's two segments appended.
    ///
    /// * `code` is the stub/relocated-block arena, mapped **R|X**.
    /// * `table` is the coverage map, mapped **R|W**.
    ///
    /// Two segments rather than one RW segment, because a stub must be
    /// *executed* and the map must be *written*: on a system with NX enforced
    /// (every modern Linux default) a single writable segment would fault the
    /// moment a stub ran, and a single executable one would fault on the
    /// counter increment.
    ///
    /// The two segments do not have to be adjacent. RIP-relative addressing is
    /// a signed 32-bit *relative* displacement, and since both vaddrs are fixed
    /// at rewrite time and neither is randomised independently, the
    /// displacement computed offline stays correct at run time. That is what
    /// keeps PIE binaries working, and it is the same property the
    /// single-segment design had -- DESIGN.md §2.1's *reasoning* survives, only
    /// its conclusion about segment count was wrong.
    ///
    /// Returns the new file bytes, the arena's vaddr, and the table's vaddr.
    pub fn rebuild_with_arena(
        &self,
        code: &[u8],
        table: &[u8],
        guard: u64,
    ) -> Result<(Vec<u8>, u64, u64)> {
        if code.is_empty() {
            bail!("refusing to build an empty arena");
        }
        if table.is_empty() {
            bail!("refusing to build an empty coverage table");
        }
        for (name, buf) in [("arena", code), ("table", table)] {
            if buf.len() as u64 > MAX_ARENA {
                bail!("{} is {} bytes, over the {}-byte cap", name, buf.len(), MAX_ARENA);
            }
        }
        // `checked_add` rather than `e_phnum + 2 > u16::MAX`: the addition
        // itself would wrap first, and the comparison against `u16::MAX` is
        // always false for a `u16` that has not already overflowed -- so the
        // original guard could never fire.
        if self.e_phnum.checked_add(2).is_none() {
            bail!("e_phnum is too large to append two program headers");
        }

        let new_phnum = self.e_phnum + 2;

        // ---- Step 1: how far must existing file content move? ----
        //
        // The new program header table is one entry (56 bytes) larger. The
        // kernel requires p_offset == p_vaddr (mod p_align); shifting every
        // existing p_offset by a *page multiple* while leaving p_vaddr alone
        // preserves that congruence. So pad the header region to a page.
        let phdr_table_end = EHDR_SIZE + u64::from(new_phnum) * PHDR_SIZE;
        let delta = phdr_table_end.div_ceil(PAGE) * PAGE;

        // ---- Step 2: lay out the file ----
        let copy_end = delta + self.bytes.len() as u64;
        let code_off = copy_end.div_ceil(PAGE) * PAGE;
        // The table gets its own page-aligned slot after the code. Page
        // alignment keeps the congruence invariant satisfiable and costs
        // nothing measurable next to the .text growth.
        let table_off = (code_off + code.len() as u64).div_ceil(PAGE) * PAGE;
        let file_len = table_off
            .checked_add(table.len() as u64)
            .context("output file size overflows")?;
        if file_len > u32::MAX as u64 * 4 {
            bail!("output file would be implausibly large ({} bytes)", file_len);
        }

        let mut out = vec![0u8; file_len as usize];

        // Copy the whole original image verbatim, at `delta`. Keeping the
        // original header+phdrs inside the copy (rather than stripping them)
        // means every internal offset is corrected by the same single
        // `+delta`, with no per-structure special cases.
        out[delta as usize..copy_end as usize].copy_from_slice(&self.bytes);

        // ---- Step 3: rewrite the ELF header ----
        out[0..4].copy_from_slice(b"\x7fELF");
        out[4] = ELFCLASS64;
        out[5] = ELFDATA2LSB;
        out[6] = 1; // EI_VERSION
        out[16..18].copy_from_slice(&self.e_type.to_le_bytes());
        out[18..20].copy_from_slice(&self.e_machine.to_le_bytes());
        out[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version
        out[24..32].copy_from_slice(&self.e_entry.to_le_bytes());
        out[32..40].copy_from_slice(&(EHDR_SIZE).to_le_bytes()); // e_phoff
        // e_shoff shifts with everything else.
        let new_shoff = if self.e_shoff == 0 { 0 } else { self.e_shoff + delta };
        out[40..48].copy_from_slice(&new_shoff.to_le_bytes());
        out[48..52].copy_from_slice(&0u32.to_le_bytes()); // e_flags
        out[52..54].copy_from_slice(&(EHDR_SIZE as u16).to_le_bytes());
        out[54..56].copy_from_slice(&(PHDR_SIZE as u16).to_le_bytes());
        out[56..58].copy_from_slice(&new_phnum.to_le_bytes());
        out[58..60].copy_from_slice(&self.e_shentsize.to_le_bytes());
        out[60..62].copy_from_slice(&self.e_shnum.to_le_bytes());
        out[62..64].copy_from_slice(&self.e_shstrndx.to_le_bytes());

        // ---- Step 4: existing program headers, shifted ----
        for (i, p) in self.phdrs.iter().enumerate() {
            let off = (EHDR_SIZE + (i as u64) * PHDR_SIZE) as usize;
            let mut q = *p;
            q.p_offset += delta;
            q.write(&mut out, off);
        }

        // ---- Step 5: the two new PT_LOADs ----
        //
        // Both vaddrs sit after every existing mapping plus the guard. p_align is
        // PAGE and both p_vaddrs are page-aligned, so p_offset must be too --
        // `code_off` and `table_off` are page-aligned by construction.
        //
        // R|X for the code and R|W for the table. A single R|W segment would
        // fault on execution under NX; a single R|X one would fault on the
        // counter increment.
        let code_vaddr = (self.max_vaddr_end() + guard).div_ceil(PAGE) * PAGE;
        let code_page_len = code.len() as u64;
        let table_vaddr = (code_vaddr + code_page_len).div_ceil(PAGE) * PAGE;

        let code_phdr = ProgramHeader {
            p_type: PT_LOAD,
            p_flags: PF_R | PF_X,
            p_offset: code_off,
            p_vaddr: code_vaddr,
            p_paddr: code_vaddr,
            p_filesz: code_page_len,
            p_memsz: code_page_len,
            p_align: PAGE,
        };
        let table_phdr = ProgramHeader {
            p_type: PT_LOAD,
            p_flags: PF_R | PF_W,
            p_offset: table_off,
            p_vaddr: table_vaddr,
            p_paddr: table_vaddr,
            p_filesz: table.len() as u64,
            p_memsz: table.len() as u64,
            p_align: PAGE,
        };
        for p in [&code_phdr, &table_phdr] {
            debug_assert_eq!(p.p_offset % PAGE, 0);
            debug_assert_eq!(p.p_vaddr % PAGE, 0);
        }
        code_phdr.write(
            &mut out,
            (EHDR_SIZE + (self.phdrs.len() as u64) * PHDR_SIZE) as usize,
        );
        table_phdr.write(
            &mut out,
            (EHDR_SIZE + (self.phdrs.len() as u64 + 1) * PHDR_SIZE) as usize,
        );

        // ---- Step 6: section headers, shifted ----
        //
        // SHT_NOBITS (.bss) occupies no file space, so shifting it would be
        // meaningless; leave it and every non-file offset alone.
        if !self.sections.is_empty() {
            let shdr_base = new_shoff as usize;
            for (i, s) in self.sections.iter().enumerate() {
                let mut t = *s;
                if t.sh_type != 8 /* SHT_NOBITS */ {
                    t.sh_offset += delta;
                }
                t.write(&mut out, shdr_base + i * SHDR_SIZE as usize);
            }
        }

        // ---- Step 7: the segment contents ----
        out[code_off as usize..(code_off as usize) + code.len()].copy_from_slice(code);
        out[table_off as usize..(table_off as usize) + table.len()].copy_from_slice(table);

        // ---- Step 8: patch .init_array in the copied image ----
        //
        // The bootstrap stub must run before the target's own constructors, so
        // its pointer is appended to `.init_array`. That needs spare *file* room
        // at the end of the array, which the early-pad trick does not create on
        // its own -- so we require zeroed padding there and refuse otherwise,
        // rather than silently overwriting the next section.
        self.patch_init_array(&mut out, delta, code_vaddr)?;

        Ok((out, code_vaddr, table_vaddr))
    }

    /// Append suture's bootstrap pointer to `.init_array`.
    ///
    /// Returns the number of bytes of headroom consumed, for reporting.
    fn patch_init_array(
        &self,
        out: &mut [u8],
        delta: u64,
        arena_vaddr: u64,
    ) -> Result<usize> {
        let Some(sec) = self.find_section_by_name(".init_array") else {
            // No .init_array: static, linker-garbage-collected binaries often
            // lack one. Not fatal for the *instrumentation* itself, only for
            // the fork-server bootstrap. Caller decides.
            return Ok(0);
        };
        if sec.sh_size == 0 {
            return Ok(0);
        }
        if sec.sh_size % 8 != 0 {
            bail!(".init_array size {} is not a multiple of 8", sec.sh_size);
        }

        let new_off = sec.sh_offset + delta;
        let new_end = new_off + sec.sh_size;
        if new_end > out.len() as u64 {
            bail!(".init_array extends past the rebuilt file");
        }

        // We need 8 more bytes of file-backed space. The segment that
        // contains .init_array must have p_filesz room before its p_offset
        // + p_filesz; the gap up to the next thing in the file is what we
        // must not trample. Rather than guess, require the containing
        // PT_LOAD to have padding: p_memsz > p_filesz is the wrong direction,
        // so we check that the bytes right after the array are inside the
        // same segment and zero (the usual linker padding).
        let seg = self
            .phdrs
            .iter()
            .find(|p| {
                p.p_type == PT_LOAD
                    && sec.sh_addr >= p.p_vaddr
                    && sec.sh_addr + sec.sh_size <= p.p_vaddr + p.p_memsz
            })
            .copied()
            .with_context(|| "no PT_LOAD contains .init_array")?;

        let seg_file_end = seg.p_offset + delta + seg.p_filesz;
        if new_end + 8 > seg_file_end {
            bail!(
                ".init_array is flush against the end of its segment ({} bytes free, need 8); \
                 refusing to overwrite the next section",
                seg_file_end - new_end
            );
        }
        // Only safe if those 8 bytes are already zero padding.
        let tail = &out[new_end as usize..(new_end + 8) as usize];
        if tail.iter().any(|&b| b != 0) {
            bail!(
                "the 8 bytes after .init_array are not zero padding; appending a \
                 constructor would clobber real data"
            );
        }

        out[new_end as usize..(new_end + 8) as usize]
            .copy_from_slice(&arena_vaddr.to_le_bytes());
        // Widen the segment so the new entry is actually file-backed.
        let idx = self
            .phdrs
            .iter()
            .position(|p| p.p_offset == seg.p_offset && p.p_vaddr == seg.p_vaddr)
            .context("segment index lookup failed")?;
        let phoff = (EHDR_SIZE + (idx as u64) * PHDR_SIZE) as usize;
        let cur_filesz = u64::from_le_bytes(out[phoff + 32..phoff + 40].try_into().unwrap());
        out[phoff + 32..phoff + 40]
            .copy_from_slice(&(cur_filesz + 8 + delta).to_le_bytes());
        Ok(8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal but *valid* static ELF64/x86-64 image so the layout
    /// tests exercise real code rather than a mock.
    fn synth_elf(text_vaddr: u64) -> Vec<u8> {
        let text: &[u8] = &[
            0xb8, 0x2a, 0x00, 0x00, 0x00, // mov eax, 42
            0x0f, 0x1f, 0x40, 0x00, // nop (4 bytes)
            0xc3, // ret
        ];
        let file_len = 0x2000usize;
        let mut b = vec![0u8; file_len];

        b[0..4].copy_from_slice(b"\x7fELF");
        b[4] = ELFCLASS64;
        b[5] = ELFDATA2LSB;
        b[6] = 1;
        b[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC (2, not 1: 1 is ET_NONE)
        b[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
        b[20..24].copy_from_slice(&1u32.to_le_bytes());
        b[24..32].copy_from_slice(&text_vaddr.to_le_bytes()); // e_entry
        b[32..40].copy_from_slice(&EHDR_SIZE.to_le_bytes()); // e_phoff
        b[40..48].copy_from_slice(&0u64.to_le_bytes()); // e_shoff (no sections)
        b[52..54].copy_from_slice(&(EHDR_SIZE as u16).to_le_bytes());
        b[54..56].copy_from_slice(&(PHDR_SIZE as u16).to_le_bytes());
        b[56..58].copy_from_slice(&1u16.to_le_bytes()); // e_phnum
        b[58..60].copy_from_slice(&(SHDR_SIZE as u16).to_le_bytes());
        b[60..62].copy_from_slice(&0u16.to_le_bytes()); // e_shnum

        let p = ProgramHeader {
            p_type: PT_LOAD,
            p_flags: PF_R | PF_X,
            p_offset: 0,
            p_vaddr: text_vaddr,
            p_paddr: text_vaddr,
            p_filesz: 0x1000,
            p_memsz: 0x1000,
            p_align: PAGE,
        };
        p.write(&mut b, EHDR_SIZE as usize);
        b[0x100..0x100 + text.len()].copy_from_slice(text);
        b
    }

    #[test]
    fn parses_a_synthetic_binary() {
        let img = Elf64Image::parse(synth_elf(0x400000)).unwrap();
        assert_eq!(img.e_type, ET_EXEC);
        assert_eq!(img.e_machine, 62);
        assert_eq!(img.e_entry, 0x400000);
        assert_eq!(img.phdrs.len(), 1);
        assert_eq!(img.text_segment().unwrap().p_vaddr, 0x400000);
        assert_eq!(img.max_vaddr_end(), 0x401000);
    }

    #[test]
    fn rejects_non_elf_and_wrong_arch() {
        assert!(Elf64Image::parse(vec![0u8; 128]).is_err());
        let mut b = synth_elf(0x400000);
        b[18..20].copy_from_slice(&183u16.to_le_bytes()); // EM_AARCH64
        let e = Elf64Image::parse(b).unwrap_err().to_string();
        assert!(e.contains("not x86-64"), "got: {e}");
    }

    #[test]
    fn rejects_truncated_phdr_table() {
        let b = synth_elf(0x400000);
        let mut img = Elf64Image::parse(b).unwrap();
        img.phdrs[0].p_offset = 1 << 40;
        // Re-parse must fail, not silently succeed.
        let mut b2 = synth_elf(0x400000);
        b2[64 + 8..64 + 16].copy_from_slice(&(1u64 << 40).to_le_bytes());
        assert!(Elf64Image::parse(b2).is_err());
    }

    #[test]
    fn rebuild_preserves_the_offset_congruence_invariant() {
        // The kernel's loader requirement: p_offset == p_vaddr (mod p_align).
        // If this breaks, the output will not even load, so it is the single
        // most important assertion in this file.
        let img = Elf64Image::parse(synth_elf(0x400000)).unwrap();
        let code = vec![0xccu8; 0x800];
        let table = vec![0x11u8; 0x4000];
        let (out, code_vaddr, table_vaddr) =
            img.rebuild_with_arena(&code, &table, 0).unwrap();

        let out_img = Elf64Image::parse(out.clone()).expect("output must re-parse");
        assert_eq!(out_img.phdrs.len(), 3, "two program headers must be appended");
        for p in &out_img.phdrs {
            if p.p_align > 1 {
                assert_eq!(
                    p.p_offset % p.p_align,
                    p.p_vaddr % p.p_align,
                    "congruence broken for {:?}",
                    p
                );
            }
        }
        // The original load segment must still describe the same virtual
        // range as before -- only p_offset moves.
        let orig_text = img.text_segment().unwrap();
        let new_text = out_img.text_segment().unwrap();
        assert_eq!(orig_text.p_vaddr, new_text.p_vaddr);
        assert_eq!(orig_text.p_filesz, new_text.p_filesz);
        assert!(new_text.p_offset > orig_text.p_offset, "p_offset must shift");

        // The arena segments must be where we said, with our bytes, and with the
        // permissions the scheme needs: code executed, table written.
        let (cs, ts) = (out_img.phdrs[1], out_img.phdrs[2]);
        assert_eq!(cs.p_vaddr, code_vaddr);
        assert_eq!(ts.p_vaddr, table_vaddr);
        assert_eq!(cs.p_flags & PF_X, PF_X, "arena must be executable");
        assert_eq!(cs.p_flags & PF_W, 0, "arena must not be writable");
        assert_eq!(ts.p_flags & PF_W, PF_W, "table must be writable");
        assert_eq!(ts.p_flags & PF_X, 0, "table need not be executable");

        let s = cs.p_offset as usize;
        assert_eq!(&out[s..s + code.len()], &code[..]);
        let t = ts.p_offset as usize;
        assert_eq!(&out[t..t + table.len()], &table[..]);
        // The two mappings must not overlap, or one would clobber the other.
        assert!(
            cs.p_vaddr + cs.p_memsz <= ts.p_vaddr,
            "arena and table mappings must not overlap"
        );
    }

    #[test]
    fn rebuild_handles_pie_and_zero_vaddr() {
        // ET_DYN with a low base is the PIE case; the arena must not collide.
        let mut b = synth_elf(0);
        b[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN
        b[24..32].copy_from_slice(&0x1000u64.to_le_bytes()); // e_entry
        let img = Elf64Image::parse(b).unwrap();
        let (out, vaddr, tvaddr) =
            img.rebuild_with_arena(&vec![0x11u8; 0x100], &vec![0u8; 0x100], 0).unwrap();
        let out_img = Elf64Image::parse(out).unwrap();
        assert_eq!(out_img.e_type, 3, "e_type must survive");
        assert!(vaddr >= img.max_vaddr_end(), "arena must sit after all segments");
        assert!(tvaddr > vaddr, "table must sit after the code");
        assert_eq!(out_img.phdrs[1].p_vaddr, vaddr);
        assert_eq!(out_img.phdrs[2].p_vaddr, tvaddr);
    }

    #[test]
    fn rebuild_does_not_truncate_arena_contents() {
        // Guards against an off-by-one in the append step: a 1-byte arena and
        // an arena that is an exact multiple of the page are the interesting
        // cases for `div_ceil` alignment.
        for len in [1usize, 4095, 4096, 4097] {
            let img = Elf64Image::parse(synth_elf(0x400000)).unwrap();
            let code: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let (out, cv, _) = img
                .rebuild_with_arena(&code, &vec![0u8; 64], 0)
                .unwrap();
            let oi = Elf64Image::parse(out).unwrap();
            let seg = oi.phdrs[1];
            assert_eq!(seg.p_filesz as usize, len);
            assert_eq!(seg.p_vaddr, cv);
            let s = seg.p_offset as usize;
            assert_eq!(&oi.bytes[s..s + len], &code[..], "len {len}");
        }
    }

    #[test]
    fn refuses_impossible_arenas() {
        let img = Elf64Image::parse(synth_elf(0x400000)).unwrap();
        assert!(
            img.rebuild_with_arena(&[], &[0u8; 8], 0).is_err(),
            "empty arena"
        );
        assert!(
            img.rebuild_with_arena(&[0u8; 8], &[], 0).is_err(),
            "empty table"
        );
    }

    #[test]
    fn guard_gap_moves_the_arena() {
        let img = Elf64Image::parse(synth_elf(0x400000)).unwrap();
        let (_, v0, t0) = img.rebuild_with_arena(&[0u8; 0x100], &[0u8; 8], 0).unwrap();
        let (_, v1, t1) = img.rebuild_with_arena(&[0u8; 0x100], &[0u8; 8], 0x10000).unwrap();
        // The table sits one page past the code arena, so widening the guard by
        // 0x10000 must move both by exactly that much.
        assert_eq!(v1 - v0, 0x10000, "the code arena must move by the guard");
        assert_eq!(t1 - t0, 0x10000, "the table must move with the code");
        // And the gap between them must not change.
        assert_eq!((t0 - v0), (t1 - v1), "the code-to-table gap is fixed");
        assert!(v1 > v0);
        assert_eq!(v1 - v0, 0x10000);
    }
}
