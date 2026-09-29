//! The arena: the single `PT_LOAD` holding every stub and the coverage table.
//!
//! Everything here exists to serve one invariant from DESIGN.md §2.1:
//!
//! > **all stubs and the coverage table live in one mapping, so a stub's
//! > RIP-relative displacement to its counter is valid at any load address.**
//!
//! Break that invariant (put the table in its own segment, or compute the
//! displacement at runtime) and PIE binaries break. Everything below is an
//! implementation of that one sentence.

pub mod analyze;
pub mod pipeline;

pub use analyze::{analyze_file, AnalysisReport};
pub use pipeline::{instrument_file, InstrumentReport};

use anyhow::{bail, Context, Result};
use suture_ir::BasicBlock;
use iced_x86::{BlockEncoder, Instruction, InstructionBlock, Mnemonic, OpKind};
use std::collections::HashMap;

/// Re-exported so callers get the encodings and the pipeline in one import.
pub use suture_ir::{INC_BYTE_RIP, JMP_REL32};

/// How one block is instrumented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    /// The block's terminator has a 32-bit displacement and fits: patch in
    /// place, redirect to a dispatch stub in the arena. No relocation.
    PatchInPlace,
    /// The block must be re-emitted into the arena. Needed when the branch is
    /// `jcc rel8` (2 bytes, too small for a `jmp rel32`) or when re-encoding
    /// would not fit. See DESIGN.md §4.2.
    Relocate,
    /// Left alone: indirect transfer, or a block we chose not to instrument.
    Skip,
    /// The block has no terminator, so there is nothing to overwrite. Its exit
    /// edge is recorded by a jump appended after the block's last instruction,
    /// with the original bytes copied verbatim.
    ///
    /// Separate from `Relocate` because no *re-encoding* is involved: the bytes
    /// are unchanged, only extended. Folding it into `Relocate` would inflate
    /// the reported relocation ratio with blocks that were never re-encoded,
    /// making the headline metric in EVALUATION.md §3 wrong.
    AppendTail,
}

/// Statistics for the `blocks_relocated / blocks_total` metric that belongs in
/// the paper. See EVALUATION.md §3.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ArenaStats {
    pub blocks_total: u32,
    pub blocks_patched: u32,
    pub blocks_relocated: u32,
    pub blocks_skipped: u32,
    /// Blocks whose exit edge is recorded by an appended tail jump.
    pub blocks_appended: u32,
    /// Bytes the instrumented `.text` grew by.
    pub code_growth: u64,
    /// Bytes the arena occupies.
    pub arena_size: u64,
}

impl ArenaStats {
    pub fn relocation_ratio(&self) -> f64 {
        if self.blocks_total == 0 {
            return 0.0;
        }
        self.blocks_relocated as f64 / self.blocks_total as f64
    }
}

/// The arena builder. Owns the byte vector, the stub allocator, and the
/// knowledge of where the coverage table sits.
pub struct ArenaBuilder {
    /// The arena's virtual address, i.e. the vaddr of `bytes[0]`.
    ///
    /// The caller sets this with [`ArenaBuilder::set_base`] *before* emitting
    /// anything, which is possible because the arena's address is determined by
    /// the original image and the guard gap, not by the arena's contents. Having
    /// it up front means relocated blocks can be encoded against their real
    /// address on the first pass.
    arena_base: u64,
    /// Offset from `arena_base` to the coverage table.
    ///
    /// The table is a *separate segment* (R|W) from the code arena (R|X), so
    /// counter displacements are not simply `table_offset - stub_offset`: they
    /// must go through this base. See [`ArenaBuilder::set_table_base`].
    table_base: u64,
    bytes: Vec<u8>,
    /// Stubs record *offsets*, not absolute addresses; `finalize` turns them
    /// into displacements once every address is settled.
    stubs: Vec<StubRecord>,
    table_offset: u64,
    map_size: u32,
    stats: ArenaStats,
    /// Deduplicates identical dispatch stubs.
    stub_cache: HashMap<StubKey, u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct StubKey {
    cc: u8,
    edge_taken: u32,
    edge_nottaken: u32,
    /// Destination the stub must jump to, as an arena-relative or original
    /// address. Kept in the key because the same condition on the same edges
    /// going to different targets is a different stub.
    target: u64,
}

#[derive(Debug, Clone)]
struct StubRecord {
    /// Offset of the stub within the arena.
    offset: u64,
    kind: StubKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StubKind {
    /// Re-tests the condition and bumps one of two counters.
    DispatchCc { cc: u8, edge_taken: u32, edge_nottaken: u32 },
    /// Bumps one counter and jumps.
    BumpAndJump { edge: u32 },
}

impl ArenaBuilder {
    /// `arena_base` may be set later with [`ArenaBuilder::set_base`]; stubs
    /// emitted before then are relocated in place (their offsets do not change,
    /// only the recorded base does).
    pub fn new(map_size: u32) -> Self {
        ArenaBuilder {
            arena_base: 0,
            table_base: 0,
            bytes: Vec::new(),
            stubs: Vec::new(),
            table_offset: 0,
            map_size,
            stats: ArenaStats::default(),
            stub_cache: HashMap::new(),
        }
    }

    /// Set the arena's virtual address. Must be called before `finalize`.
    pub fn set_base(&mut self, vaddr: u64) {
        self.arena_base = vaddr;
    }

    pub fn base(&self) -> u64 {
        self.arena_base
    }

    /// Offset of the coverage table relative to `arena_base`.
    ///
    /// Required because the table is a separate mapping: the code arena is R|X
    /// (it has to be executed) and the table is R|W (it has to be written), and
    /// a single segment satisfying both would fault under NX. Set this after
    /// `finish`, which is where the table's size becomes known.
    pub fn set_table_base(&mut self, offset: u64) {
        self.table_base = offset;
    }

    pub fn stats(&self) -> ArenaStats {
        self.stats
    }

    /// Where the next stub may be emitted.
    ///
    /// Before `finish` this is the current arena length. After `finish` it is
    /// pinned to the table's offset, because the coverage table occupies the
    /// rest of the arena and no code may be written into it.
    pub fn code_len(&self) -> u64 {
        match self.table_offset {
            0 => self.bytes.len() as u64,
            t => t,
        }
    }

    fn align_to(&mut self, n: u64) {
        while self.bytes.len() % n as usize != 0 {
            self.bytes.push(0x90); // int3 would be safer; nop keeps it decodable
        }
    }

    /// Emit a conditional-branch dispatch stub.
    ///
    /// Layout, per DESIGN.md §4.1:
    /// ```text
    ///   jcc  .nt          ; still-live flags decide, 2 bytes, no displacement
    ///   inc  byte [t]     ; taken path
    ///   jmp  target
    /// .nt:
    ///   inc  byte [nt]    ; fallthrough path
    ///   <falls into the original successor>
    /// ```
    ///
    /// The `jcc` with no displacement is `jcc +2`: it skips the 6-byte `inc` and
    /// lands on `.nt`. This is the whole trick -- the original condition is
    /// re-evaluated on flags that nothing has touched.
    pub fn emit_dispatch(
        &mut self,
        cc: u8,
        edge_taken: u32,
        edge_nottaken: u32,
        target: u64,
    ) -> Result<u32> {
        let key = StubKey { cc, edge_taken, edge_nottaken, target };
        if let Some(&off) = self.stub_cache.get(&key) {
            return Ok(off as u32);
        }

        let offset = self.bytes.len() as u64;
        // 2 bytes: jcc +2 over the taken-path `inc`.
        self.bytes.extend_from_slice(&[0x70 | (cc & 0x0f), 0x02]);
        // 6 bytes: inc byte [rip+disp32] -- displacement patched in finalize.
        self.bytes.extend_from_slice(&INC_BYTE_RIP);
        self.bytes.extend_from_slice(&0i32.to_le_bytes());
        // 5 bytes: jmp rel32 to the real target -- patched in finalize.
        self.bytes.extend_from_slice(&JMP_REL32);
        self.bytes.extend_from_slice(&0i32.to_le_bytes());
        // 6 bytes: inc byte [rip+disp32] for the fallthrough edge.
        self.bytes.extend_from_slice(&INC_BYTE_RIP);
        self.bytes.extend_from_slice(&0i32.to_le_bytes());

        self.stubs.push(StubRecord {
            offset,
            kind: StubKind::DispatchCc { cc, edge_taken, edge_nottaken },
        });
        self.stub_cache.insert(key, offset as u32);
        Ok(offset as u32)
    }

    /// Reserve a bare 5-byte `jmp rel32` whose displacement is patched later.
    ///
    /// Needed for a relocated block whose body is empty -- a block whose *first*
    /// instruction is the branch. Such a block has nothing to re-encode, so the
    /// relocation degenerates to a single jump. Returns the block's new vaddr.
    pub fn emit_jmp_placeholder(&mut self) -> u64 {
        self.align_to(16);
        let vaddr = self.arena_base + self.code_len();
        self.bytes.extend_from_slice(&JMP_REL32);
        self.bytes.extend_from_slice(&0i32.to_le_bytes());
        vaddr
    }

    /// Emit `inc byte [edge]; jmp target` -- for a straight-line fallthrough or
    /// an unconditional direct jump.
    pub fn emit_bump_and_jump(&mut self, edge: u32, target: u64) -> u32 {
        let key = StubKey { cc: 0xff, edge_taken: edge, edge_nottaken: 0, target };
        if let Some(&off) = self.stub_cache.get(&key) {
            return off;
        }
        let offset = self.bytes.len() as u64;
        self.bytes.extend_from_slice(&INC_BYTE_RIP);
        self.bytes.extend_from_slice(&0i32.to_le_bytes());
        self.bytes.extend_from_slice(&JMP_REL32);
        self.bytes.extend_from_slice(&0i32.to_le_bytes());
        self.stubs.push(StubRecord { offset, kind: StubKind::BumpAndJump { edge } });
        self.stub_cache.insert(key, offset as u32);
        offset as u32
    }

    /// Append a relocated copy of a basic block, re-encoding every instruction
    /// at its new address. Returns the block's new vaddr and its new size.
    ///
    /// This is DESIGN.md §4.2. The subtlety is RIP-relative operands: the
    /// decoded instruction carries the displacement that makes `[rip+d]` point
    /// where it did in the *original* block, so a raw byte copy would compute
    /// the wrong address at the new location. `InstructionBlock::encode`
    /// re-encodes with the new base IP and fixes the displacement up.
    pub fn relocate_block(
        &mut self,
        block: &BasicBlock,
        target_vaddr: u64,
    ) -> Result<(u64, u64)> {
        self.align_to(16);
        let new_vaddr = target_vaddr + self.code_len();
        let instrs: Vec<Instruction> = block.instrs.clone();
        if instrs.is_empty() {
            bail!("cannot relocate an empty block");
        }

        let ib = InstructionBlock::new(&instrs, new_vaddr);
        let result = BlockEncoder::encode(64, ib, 0)
            .with_context(|| format!("re-encoding relocated block at {:#x}", new_vaddr))?;
        if result.code_buffer.is_empty() {
            bail!(
                "encoder produced no bytes for a {}-instruction block",
                instrs.len()
            );
        }
        // A rewritten instruction means the encoder changed the instruction's
        // semantics' *encoding* (e.g. a 2-byte jcc promoted to near). That is
        // allowed, but we must know, because the caller patches the terminator
        // by offset.
        let size = result.code_buffer.len() as u64;
        self.bytes.extend_from_slice(&result.code_buffer);
        Ok((new_vaddr, size))
    }

    /// Pad, then reserve the coverage table.
    ///
    /// Called once, after all stubs are emitted. After this, `bytes` is the
    /// complete arena and no further code may be added.
    pub fn finish(&mut self) -> Result<()>
        {
        // 64-byte alignment: the table is scanned linearly by the fuzzer, so
        // keeping it off shared cache lines with the stub code is worth the
        // padding.
        // 64-byte alignment: the table is scanned linearly by the fuzzer, so
        // keeping it off shared cache lines with the stub code is worth the
        // padding.
        self.align_to(64);
        self.table_offset = self.bytes.len() as u64;
        // The table is appended to the builder's buffer for convenience, but it
        // becomes its own segment. `table_base` is therefore the *segment*
        // offset -- normally the arena's size rounded up to a page -- and the
        // caller must set it, because it depends on the final file layout.
        let table_bytes = u64::from(self.map_size) + 8;
        self.stats.arena_size = self.table_offset + table_bytes;
        self.bytes.resize(self.stats.arena_size as usize, 0);
        Ok(())
    }

    pub fn table_offset(&self) -> u64 {
        self.table_offset
    }

    pub fn table_len(&self) -> usize {
        self.bytes.len()
    }

    /// Patch every `disp32` now that the arena's final vaddr is known.
    ///
    /// This is the step that makes the scheme load-address independent: the
    /// displacements are computed once, here, against a concrete arena vaddr,
    /// and are then correct forever after.
    pub fn finalize(&mut self, arena_vaddr: u64) -> Result<()> {
        if arena_vaddr != self.arena_base && self.arena_base != 0 {
            bail!(
                "finalize called with {:#x} but the arena base is {:#x}; \
                 set_base and finalize must agree",
                arena_vaddr,
                self.arena_base
            );
        }
        self.arena_base = arena_vaddr;
        // Every displacement is `table_base + edge`, independent of where the
        // arena itself landed. That is the whole point: the same bytes work at
        // any load address, which is what makes PIE binaries safe.
        for rec in self.stubs.clone() {
            let base = arena_vaddr + rec.offset;
            match rec.kind {
                StubKind::DispatchCc { edge_taken, edge_nottaken, .. } => {
                    // RIP-relative addressing resolves against the address of the
                    // *next* instruction, so the displacement is measured from
                    // the end of the `inc`, not its start. Getting this off by
                    // the instruction length (6) produces a table hit 6 bytes
                    // past the intended slot -- the kind of bug that looks like
                    // "coverage is slightly wrong" and is nearly impossible to
                    // spot without these assertions.
                    //
                    // Layout: [0..2) jcc  [2..8) inc-taken  [8..13) jmp
                    //         [13..19) inc-nottaken
                    let taken_disp = disp_to_table(
                        arena_vaddr, self.table_base, edge_taken, base + 8,
                    )?;
                    write_disp32(&mut self.bytes, (rec.offset + 4) as usize, taken_disp);
                    let nt_disp = disp_to_table(
                        arena_vaddr, self.table_base, edge_nottaken, base + 19,
                    )?;
                    write_disp32(&mut self.bytes, (rec.offset + 15) as usize, nt_disp);
                }
                StubKind::BumpAndJump { edge } => {
                    // [0..6) inc  [6..11) jmp -- next_ip is +6.
                    let disp = disp_to_table(arena_vaddr, self.table_base, edge, base + 6)?;
                    write_disp32(&mut self.bytes, (rec.offset + 2) as usize, disp);
                }
            }
        }
        Ok(())
    }

    /// Retarget every `jmp rel32` in the arena.
    ///
    /// Split out from `finalize` because the destinations are not known until
    /// the caller has decided where every original block landed.
    pub fn patch_jump(&mut self, stub_offset: u64, from_vaddr: u64, to_vaddr: u64) -> Result<()> {
        // The `jmp rel32` sits 8 bytes into a dispatch stub (2 jcc + 6 inc) and
        // 6 bytes into a bump stub (6 inc). Its displacement is relative to the
        // end of the instruction, i.e. from_vaddr + 5.
        let jump_at = if self.is_dispatch(stub_offset) { 8 } else { 6 };
        let rel = rel32(from_vaddr + 5, to_vaddr)
            .with_context(|| format!("jump from {:#x} to {:#x} is out of rel32 range", from_vaddr, to_vaddr))?;
        let at = (stub_offset + jump_at + 1) as usize;
        if at + 4 > self.bytes.len() {
            bail!(
                "patch_jump would write past the arena ({} bytes)",
                self.bytes.len()
            );
        }
        write_disp32(&mut self.bytes, at, rel);
        Ok(())
    }

    fn is_dispatch(&self, stub_offset: u64) -> bool {
        self.stubs
            .iter()
            .any(|s| s.offset == stub_offset && matches!(s.kind, StubKind::DispatchCc { .. }))
    }

    /// Record a per-block outcome for the reported metrics.
    pub fn note_strategy(&mut self, s: Strategy) {
        self.stats.blocks_total += 1;
        match s {
            Strategy::PatchInPlace => self.stats.blocks_patched += 1,
            Strategy::Relocate => self.stats.blocks_relocated += 1,
            Strategy::Skip => self.stats.blocks_skipped += 1,
            Strategy::AppendTail => self.stats.blocks_appended += 1,
        }
    }

    pub fn add_growth(&mut self, n: u64) {
        self.stats.code_growth += n;
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The finished arena bytes, for handing to `rebuild_with_arena`.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// `disp32` from an instruction at `instr_vaddr` to `table[edge]`, checked
/// against the architectural `rel32` range.
///
/// `table_base` is the table's offset from the code arena's base, not from the
/// arena's start: the two live in separate mappings (DESIGN.md §5), so the
/// distance is `table_base + edge`, not `table_offset_in_arena + edge`.
///
/// The range check matters: a table placed on the far side of a 2 GiB boundary
/// produces a displacement that silently truncates. Failing here turns a mystery
/// segfault in the target into a clear error at instrumentation time.
fn disp_to_table(
    arena_vaddr: u64,
    table_base: u64,
    edge: u32,
    next_ip: u64,
) -> Result<i32> {
    // The instruction resolves `[rip + disp]` from `next_ip`. We want it to land
    // on `arena_vaddr + table_base + edge`, so:
    //
    //     disp = (arena_vaddr + table_base + edge) - next_ip
    //
    // Both sides are computed in i128 and the result range-checked, because a
    // wrapping subtraction here yields a plausible-looking displacement that
    // silently points into the middle of nowhere.
    let dest = (arena_vaddr as i128) + (table_base as i128) + (edge as i128);
    let delta = dest - (next_ip as i128);
    if delta < i32::MIN as i128 || delta > i32::MAX as i128 {
        bail!(
            "table[{}] is at {:#x}, which is {} bytes from the instruction at {:#x} \
             -- out of rel32 range",
            edge,
            dest as u64,
            delta,
            next_ip
        );
    }
    Ok(delta as i32)
}

fn rel32(from_after: u64, to: u64) -> Result<i32> {
    let delta = to as i64 - from_after as i64;
    if delta < i32::MIN as i64 || delta > i32::MAX as i64 {
        bail!("rel32 displacement {} out of range", delta);
    }
    Ok(delta as i32)
}

fn write_disp32(buf: &mut [u8], at: usize, v: i32) {
    buf[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

/// Classify a terminator: can it be patched in place, or must it be relocated?
///
/// The rule, and the reason for it: a `jcc rel8` is 2 bytes and a `jmp rel32` is
/// 5, so there is no in-place encoding and the block must move (DESIGN.md §4.2).
/// A `jcc rel32` is 6 bytes and fits `E9 rel32` plus a 1-byte pad.
pub fn classify(terminator: &Instruction) -> Strategy {
    let mn = terminator.mnemonic();
    if mn == Mnemonic::Jmp {
        return if terminator.op0_kind() == OpKind::NearBranch64 {
            // `jmp rel32` is 5 bytes; `jmp rel8` is 2. Same problem as jcc.
            if terminator.len() >= 5 {
                Strategy::PatchInPlace
            } else {
                Strategy::Relocate
            }
        } else {
            Strategy::Skip // jmp rax / jmp [mem]
        };
    }
    if is_cond(mn) {
        return if terminator.len() >= 5 { Strategy::PatchInPlace } else { Strategy::Relocate };
    }
    // ret / call / trap: not a branch edge, nothing to patch.
    Strategy::Skip
}

fn is_cond(m: Mnemonic) -> bool {
    matches!(
        m,
        Mnemonic::Jo | Mnemonic::Jno
            | Mnemonic::Jb | Mnemonic::Jae
            | Mnemonic::Je | Mnemonic::Jne
            | Mnemonic::Jbe | Mnemonic::Ja
            | Mnemonic::Js | Mnemonic::Jns
            | Mnemonic::Jp | Mnemonic::Jnp
            | Mnemonic::Jl | Mnemonic::Jge
            | Mnemonic::Jle | Mnemonic::Jg
            | Mnemonic::Jcxz | Mnemonic::Jecxz | Mnemonic::Jrcxz
    )
}

/// The `cc` nibble for a `0x70`-based short jcc, so the dispatch stub can
/// re-test the same condition.
pub fn cc_nibble(m: Mnemonic) -> Option<u8> {
    Some(match m {
        Mnemonic::Jo => 0x0,
        Mnemonic::Jno => 0x1,
        Mnemonic::Jb => 0x2,
        Mnemonic::Jae => 0x3,
        Mnemonic::Je => 0x4,
        Mnemonic::Jne => 0x5,
        Mnemonic::Jbe => 0x6,
        Mnemonic::Ja => 0x7,
        Mnemonic::Js => 0x8,
        Mnemonic::Jns => 0x9,
        Mnemonic::Jp => 0xa,
        Mnemonic::Jnp => 0xb,
        Mnemonic::Jl => 0xc,
        Mnemonic::Jge => 0xd,
        Mnemonic::Jle => 0xe,
        Mnemonic::Jg => 0xf,
        Mnemonic::Jcxz | Mnemonic::Jecxz | Mnemonic::Jrcxz => return None, // rel8 only
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use iced_x86::{Decoder, DecoderOptions};

    fn decode(bytes: &[u8]) -> Instruction {
        let mut d = Decoder::with_ip(64, bytes, 0x1000, DecoderOptions::NONE);
        d.decode()
    }

    #[test]
    fn dispatch_stub_has_the_expected_shape() {
        // jcc +2 ; inc byte[rip+d32] ; jmp rel32 ; inc byte[rip+d32]
        //  2        6                      5            6              = 19
        let mut a = ArenaBuilder::new(1024);
        let off = a.emit_dispatch(0x4, 7, 9, 0x2000).unwrap();
        assert_eq!(off, 0);
        assert_eq!(a.code_len(), 19, "stub size must be exactly 19 bytes");
        let b = a.bytes();
        assert_eq!(b[0], 0x74, "must start with je (0x70|0x4)");
        assert_eq!(b[1], 0x02, "jcc must skip the 6-byte inc");
        assert_eq!(&b[2..4], &INC_BYTE_RIP);
        assert_eq!(b[8], 0xE9, "taken path must jmp");
        assert_eq!(&b[13..15], &INC_BYTE_RIP, "fallthrough inc position");
    }

    #[test]
    fn identical_stubs_are_shared() {
        // Stub dedup matters: without it a hot binary gets tens of thousands of
        // identical stubs and the arena dominates the file.
        let mut a = ArenaBuilder::new(1024);
        let s1 = a.emit_dispatch(0x4, 7, 9, 0x2000).unwrap();
        let len_after_1 = a.code_len();
        let s2 = a.emit_dispatch(0x4, 7, 9, 0x2000).unwrap();
        assert_eq!(s1, s2);
        assert_eq!(a.code_len(), len_after_1, "no new bytes for a duplicate");

        let s3 = a.emit_dispatch(0x4, 7, 9, 0x3000).unwrap();
        assert_ne!(s1, s3, "a different target is a different stub");
        assert!(a.code_len() > len_after_1);
    }

    #[test]
    fn bump_and_jump_is_eleven_bytes() {
        let mut a = ArenaBuilder::new(1024);
        a.emit_bump_and_jump(3, 0x4000);
        assert_eq!(a.code_len(), 11);
    }

    #[test]
    fn finalize_produces_displacements_that_point_at_the_table() {
        // The load-bearing test of the whole design. Each emitted `inc byte
        // [rip+d]` is decoded back and resolved, and the result must equal
        // `table_vaddr + edge` exactly.
        //
        // The table is a *separate segment*, so the test has to supply the
        // segment base -- a page past the code arena -- and check against that,
        // not against the table's offset within the arena. Confusing the two is
        // precisely the bug this test exists to catch.
        let arena_vaddr = 0x100000u64;
        let mut a = ArenaBuilder::new(1024);
        a.emit_dispatch(0x4, 7, 9, 0x2000);
        a.emit_bump_and_jump(11, 0x4000);
        a.finish().unwrap();
        // What the ELF builder will do: page-align past the code arena.
        let table_vaddr = (arena_vaddr + a.table_offset()).div_ceil(0x1000) * 0x1000;
        a.set_table_base(table_vaddr - arena_vaddr);
        a.finalize(arena_vaddr).unwrap();

        // Resolve each emitted `[rip+disp]` exactly as the CPU would, from the
        // address of the *following* instruction.
        let resolve = |disp_at: usize, next_ip_off: u64| -> u64 {
            let disp = i32::from_le_bytes(a.bytes()[disp_at..disp_at + 4].try_into().unwrap());
            (arena_vaddr + next_ip_off).wrapping_add(disp as i64 as u64)
        };

        // taken inc: opcode at arena+2, disp32 at arena+4, next_ip = arena+8
        assert_eq!(resolve(4, 8), table_vaddr + 7, "taken edge must address table[7]");
        // fallthrough inc: opcode at arena+13, disp32 at arena+15, next_ip = +19
        assert_eq!(resolve(15, 19), table_vaddr + 9, "not-taken must address table[9]");
        // bump stub at arena+19: disp32 at +21, next_ip = +25
        assert_eq!(resolve(21, 25), table_vaddr + 11, "bump must address table[11]");
    }

    #[test]
    fn table_is_placed_after_all_code_and_aligned() {
        let mut a = ArenaBuilder::new(1024);
        a.emit_bump_and_jump(1, 0x10);
        a.emit_dispatch(0x4, 2, 3, 0x20);
        let code_end = a.code_len();
        a.finish().unwrap();
        assert_eq!(a.table_offset() % 64, 0, "table must be cache-line aligned");
        assert!(
            a.table_offset() >= code_end,
            "table must start at or after the end of the code"
        );
        // After finish(), code_len() reports the end of code (== table start),
        // not the end of the whole arena, so a caller cannot append a stub into
        // the table.
        assert_eq!(a.code_len(), a.table_offset());
        assert_eq!(a.table_len() as u64, a.table_offset() + 1024 + 8);
    }

    #[test]
    fn relocations_are_address_independent() {
        // The load-bearing property from DESIGN.md §2.1: an arena built
        // identically but placed at two different vaddrs must contain
        // *byte-identical* code, because every displacement is relative and
        // both the stubs and the table move together.
        //
        // If this test ever fails, PIE binaries break: the same file loaded at
        // two addresses would take different code paths.
        let build = |vaddr: u64| {
            let mut a = ArenaBuilder::new(64);
            a.emit_dispatch(0x4, 7, 9, 0x2000);
            a.emit_bump_and_jump(11, 0x4000);
            a.finish().unwrap();
            // Mirror what the ELF builder does: the table is a second segment one
            // page past the code, so its base is derived from the code's.
            let tbase = (vaddr + a.table_offset()).div_ceil(0x1000) * 0x1000 - vaddr;
            a.set_table_base(tbase);
            a.finalize(vaddr).unwrap();
            a.bytes().to_vec()
        };
        let lo = build(0x100000);
        let hi = build(0x7f0000000000);
        assert_eq!(lo.len(), hi.len());
        assert_eq!(
            lo, hi,
            "the arena must be byte-identical regardless of load address"
        );
    }

    #[test]
    fn classify_splits_short_and_near_branches() {
        // je rel8  -> 2 bytes  -> must relocate
        let short = decode(&[0x74, 0x02, 0x90, 0x90]);
        assert_eq!(short.len(), 2);
        assert_eq!(classify(&short), Strategy::Relocate);

        // je rel32 -> 6 bytes  -> patch in place
        let near = decode(&[0x0f, 0x84, 0x10, 0x00, 0x00, 0x00]);
        assert_eq!(near.len(), 6);
        assert_eq!(classify(&near), Strategy::PatchInPlace);

        // eb rel8 (jmp short) -> 2 bytes -> relocate
        let jmp_short = decode(&[0xeb, 0x10]);
        assert_eq!(classify(&jmp_short), Strategy::Relocate);

        // e9 rel32 (jmp near) -> 5 bytes -> patch
        let jmp_near = decode(&[0xe9, 0x10, 0x00, 0x00, 0x00]);
        assert_eq!(classify(&jmp_near), Strategy::PatchInPlace);

        // ff e0 (jmp rax) -> indirect -> skip
        let ind = decode(&[0xff, 0xe0]);
        assert_eq!(classify(&ind), Strategy::Skip);

        // c3 (ret) -> nothing to patch
        let ret = decode(&[0xc3]);
        assert_eq!(classify(&ret), Strategy::Skip);
    }

    #[test]
    fn cc_nibble_matches_encoding() {
        // The nibble must reproduce the original opcode's low 4 bits, or the
        // dispatch stub would test the wrong condition and silently attribute
        // coverage to the wrong edge.
        for (bytes, expect) in [
            (vec![0x74u8, 0x01], 0x4u8), // je
            (vec![0x75, 0x01], 0x5),      // jne
            (vec![0x7c, 0x01], 0xc),      // jl
            (vec![0x7f, 0x01], 0xf),      // jg
        ] {
            let instr = decode(&bytes);
            let cc = cc_nibble(instr.mnemonic()).unwrap();
            assert_eq!(cc, expect);
            assert_eq!(0x70 | cc, bytes[0], "re-encoded opcode must match");
        }
    }

    #[test]
    fn stats_track_the_relocation_ratio() {
        let mut s = ArenaStats::default();
        for _ in 0..7 {
            s.blocks_total += 1;
            s.blocks_patched += 1;
        }
        for _ in 0..3 {
            s.blocks_total += 1;
            s.blocks_relocated += 1;
        }
        assert_eq!(s.blocks_total, 10);
        assert!((s.relocation_ratio() - 0.3).abs() < 1e-9);
        assert_eq!(ArenaStats::default().relocation_ratio(), 0.0);
    }
}
