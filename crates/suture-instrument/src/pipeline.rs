//! End-to-end instrumentation: ELF in, instrumented ELF out.
//!
//! This is where the crates stop being libraries and become suture. The order of
//! operations matters and is not obvious:
//!
//! 1. Disassemble `.text` **from the original bytes**.
//! 2. Build the edge list and assign ids.
//! 3. Decide, per block, whether it can be patched in place.
//! 4. Emit every stub and every relocated block into the arena.
//! 5. Only then call `rebuild_with_arena`, which is what finally assigns the
//!    arena a vaddr.
//! 6. `finalize` patches all displacements against that vaddr.
//!
//! Steps 4-6 are in that order because stub contents depend on the arena's
//! final address, and the arena's address depends on how big the arena is. Doing
//! it the other way round is the classic way to get an instrumenter that works
//! on small binaries and corrupts large ones.

use anyhow::{bail, Context, Result};
use suture_coverage::MapLayout;
use suture_elf::Elf64Image;
use suture_ir::{Disassembler, Edge, SweepResult};
use crate::{ArenaBuilder, ArenaStats, Strategy};
use serde::Serialize;
use std::collections::HashMap;
use std::path::Path;

/// Everything worth knowing about an instrumentation run. Serialized into the
/// output binary's sibling `.json`, so a result is reproducible and auditable.
#[derive(Debug, Clone, Default, Serialize)]
pub struct InstrumentReport {
    pub input_path: String,
    pub input_size: u64,
    pub output_size: u64,
    pub text_vaddr: u64,
    pub text_size: u64,
    pub blocks_total: u32,
    pub blocks_patched: u32,
    pub blocks_relocated: u32,
    pub blocks_skipped: u32,
    /// Blocks whose exit edge is recorded by a jump appended after a copy in
    /// the arena, because the block had no terminator to overwrite.
    pub blocks_appended: u32,
    pub edges_total: u32,
    pub map_size: u32,
    /// vaddr of the R|X stub arena.
    pub arena_vaddr: u64,
    /// vaddr of the R|W coverage table. Separate from `arena_vaddr` because
    /// code must be executable and the map must be writable.
    pub table_vaddr: u64,
    /// Total bytes across both segments.
    pub arena_size: u64,
    pub stubs_emitted: u32,
    pub skipped_indirect: u32,
    /// Every byte range suture overwrote, as `(vaddr, length)`.
    ///
    /// Reported so the output can be audited: any byte of the original `.text`
    /// that differs from the input must be inside one of these ranges. This is
    /// the machine-checkable form of "suture only touched what it said it would",
    /// and `suture-verify` uses it to bound its differential comparison.
    pub patched_ranges: Vec<(u64, u32)>,
    /// Wall-clock milliseconds for the whole run (C3 in EVALUATION.md).
    pub elapsed_ms: u128,
    /// Non-fatal notes: indirect branches skipped, suspicious decodes, etc.
    pub warnings: Vec<String>,
}

impl InstrumentReport {
    pub fn relocation_ratio(&self) -> f64 {
        if self.blocks_total == 0 {
            return 0.0;
        }
        self.blocks_relocated as f64 / self.blocks_total as f64
    }

    /// Total code growth in bytes, for the `size(instrumented)/size(original)`
    /// row of EVALUATION.md §3.
    pub fn growth_ratio(&self) -> f64 {
        if self.input_size == 0 {
            return 0.0;
        }
        self.output_size as f64 / self.input_size as f64
    }

    pub fn summary(&self) -> String {
        format!(
            "{} -> {}\n  blocks   {} total / {} patched / {} relocated / {} skipped \
             ({:.1}% relocated)\n  edges    {} (map {} KiB)\n  arena    {:#x}, {} bytes, {} stubs\n  growth   {:.2}x\n  indirect branches skipped: {}\n  elapsed  {} ms",
            self.input_path,
            self.output_size,
            self.blocks_total,
            self.blocks_patched,
            self.blocks_relocated,
            self.blocks_skipped,
            self.relocation_ratio() * 100.0,
            self.edges_total,
            self.map_size / 1024,
            self.arena_vaddr,
            self.arena_size,
            self.stubs_emitted,
            self.growth_ratio(),
            self.skipped_indirect,
            self.elapsed_ms,
        )
    }
}

/// Instrument `input` and write the result to `output`.
///
/// The map is placed at the *end* of the arena so the code stays dense and the
/// table is a single contiguous run of bytes the fuzzer can memcmp against.
pub fn instrument_file(input: &Path, output: &Path) -> Result<InstrumentReport> {
    let started = std::time::Instant::now();
    let mut report = InstrumentReport {
        input_path: input.display().to_string(),
        input_size: std::fs::metadata(input)?.len(),
        ..Default::default()
    };

    let img = Elf64Image::from_path(input)?;
    let text = img
        .text_segment()
        .with_context(|| format!("no executable PT_LOAD in {}", input.display()))?;
    report.text_vaddr = text.p_vaddr;
    report.text_size = text.p_filesz;

    let text_off = text.p_offset as usize;
    let text_end = text_off + text.p_filesz as usize;
    if text_end > img.bytes.len() {
        bail!("text segment extends past end of file");
    }
    let code = &img.bytes[text_off..text_end];

    // ---- 1-2: disassemble and build the edge list ----
    let dis = Disassembler::new();
    let sweep = dis
        .sweep(code, text.p_vaddr)
        .with_context(|| format!("sweeping {} ({} bytes of .text)", input.display(), code.len()))?;
    let (edges, index) = sweep.build_edges();
    let map_size = suture_ir::SweepResult::map_size(&edges) as u32;
    let layout = MapLayout::new(map_size, 0); // real offset assigned in the arena

    report.blocks_total = sweep.blocks.len() as u32;
    report.edges_total = edges.len() as u32;
    report.map_size = map_size;
    report.skipped_indirect = sweep.skipped_indirect.len() as u32;
    if let suture_ir::SweepStop::Undecodable(addr) = sweep.stop {
        report.warnings.push(format!(
            "linear sweep stopped at undecodable byte {:#x} (expected where .text holds data)",
            addr
        ));
    }
    if report.skipped_indirect > 0 {
        report.warnings.push(format!(
            "{} indirect branches not instrumented (DESIGN.md 4.3); coverage is an \
             under-approximation for switch tables and jump tables",
            report.skipped_indirect
        ));
    }

    // ---- 3-4: plan and emit ----
    //
    // The arena's final vaddr is known *now* -- it depends only on the original
    // image and the guard, not on what we are about to emit. So relocated
    // blocks are encoded against their real address in a single pass, and
    // `finalize` only has to fill in displacements.
    let arena_vaddr = img.arena_vaddr(suture_elf::DEFAULT_GUARD);
    let mut plan = plan_instrumentation(&sweep, &edges, &index)?;
    let mut arena = ArenaBuilder::new(map_size);
    arena.set_base(arena_vaddr);
    let mut patch_sites: Vec<PatchSite> = Vec::new();
    let mut relocated: HashMap<u64, u64> = HashMap::new();
    let mut relocated_sizes: HashMap<u32, u64> = HashMap::new();

    // Sanity-check the plan before emitting anything: a misclassified block
    // would corrupt the output silently, and a partial arena is no use.
    let mut short_blocks: Vec<u64> = Vec::new();
    let mut out_of_range_blocks: Vec<u64> = Vec::new();
    let mut reloc_failures: Vec<(u64, String)> = Vec::new();
    for step in plan.iter_mut() {
        if step.strategy == Strategy::PatchInPlace && step.orig_len < 5 {
            bail!(
                "plan error: block {:#x} has a {}-byte terminator marked PatchInPlace",
                step.block_vaddr,
                step.orig_len
            );
        }
        // A relocated or appended block is redirected by a 5-byte jump written at
        // the block's *entry*, so the block must be at least 5 bytes. Anything
        // smaller is left uninstrumented and reported, never half-patched.
        // A block too short to hold the 5-byte redirect jump cannot be
        // instrumented at its *entry*.
        //
        // For a relocated block there is an alternative that always fits: leave
        // the original bytes alone and have the *predecessor's* stub jump to the
        // arena copy instead. That works because the predecessor is already
        // being redirected, so no 5-byte jump has to fit in the short block at
        // all. It is the right general strategy for relocation, and it is why
        // the `blocks_relocated` number stays honest.
        //
        // The entry block is the exception: it is reached by the program's entry
        // point rather than by any stub, so nothing can redirect it. That case
        // is reported as a coverage gap.
        if matches!(step.strategy, Strategy::Relocate | Strategy::AppendTail)
            && step.block_len < 5
            && step.block_vaddr == text.p_vaddr
        {
            short_blocks.push(step.block_vaddr);
        }
        if step.term_vaddr < text.p_vaddr
            || step.term_vaddr >= text.p_vaddr + text.p_filesz
        {
            // The disassembler reported a terminator at or past the end of the
            // segment. That is not a patchable site -- writing a 5-byte jump
            // there would land outside `.text` -- so the block is demoted to
            // "no terminator" and its exit edge is recorded by an appended tail
            // instead. Reported, not silently dropped.
            out_of_range_blocks.push(step.block_vaddr);
            step.strategy = Strategy::AppendTail;
            step.orig_len = 0;
        }
    }

        for step in plan.iter_mut() {
        if out_of_range_blocks.contains(&step.block_vaddr) {
            step.strategy = Strategy::AppendTail;
        }
        // Only the entry block can be un-instrumentable: every other short block
        // is redirected via its predecessor's stub, which needs no room here.
        if short_blocks.contains(&step.block_vaddr) {
            step.strategy = Strategy::Skip;
        }
        match step.strategy {
            Strategy::Skip => arena.note_strategy(Strategy::Skip),

            Strategy::PatchInPlace => {
                // The terminator is overwritten in place by a jump straight to
                // the dispatch stub. The stub re-tests the condition on flags
                // that are still live, so no other instruction is touched.
                //
                // Note the site is the *terminator's* address, not the block's:
                // the body before it must survive byte for byte.
                let stub = emit_stub(&mut arena, step);
                // Only patch when there is room. A 5-byte jump needs 5 bytes; a
                // shorter terminator (the 2-byte `jcc rel8` case) goes down the
                // Relocate arm instead, so this is a belt-and-braces check.
                if step.orig_len < 5 {
                    bail!(
                        "internal error: PatchInPlace chosen for a {}-byte terminator at \
                         {:#x}; classify() must return Relocate",
                        step.orig_len,
                        step.term_vaddr
                    );
                }
                patch_sites.push(PatchSite {
                    site_vaddr: step.term_vaddr,
                    orig_len: u32::from(step.orig_len),
                    arena_offset: stub,
                });
                arena.note_strategy(Strategy::PatchInPlace);
            }

            Strategy::AppendTail => {
                // A terminator-less block has nothing we may safely overwrite:
                // its bytes *are* the code, and there is no branch to redirect.
                // So instead of patching the block, we copy it into the arena,
                // append a jump to the stub after the copy, and record the copy
                // in `relocated` -- which is what every predecessor's stub
                // consults when choosing where to jump. The original block is
                // left byte-for-byte intact and becomes unreachable.
                //
                // Patching the block's *entry* would be the obvious shortcut and
                // is wrong: it would destroy the first instruction of the block.
                let body = suture_ir::BasicBlock {
                    id: step.block_id,
                    vaddr: step.block_vaddr,
                    instrs: step.body.clone(),
                    terminator: None,
                    no_fallthrough: false,
                };
                if step.block_len < 5 {
                    report.warnings.push(format!(
                        "block at {:#x} is {} bytes; cannot hold the 5-byte jump needed to \
                         redirect it, so its exit edge is not instrumented",
                        step.block_vaddr, step.block_len
                    ));
                    arena.note_strategy(Strategy::Skip);
                    continue;
                }
                let (copy_vaddr, size) = match arena.relocate_block(&body, arena_vaddr) {
                    Ok(v) => v,
                    Err(e) => {
                        // Same deal as the Relocate arm: an un-encodable block
                        // costs its own coverage, not the whole binary.
                        reloc_failures.push((step.block_vaddr, format!("{e:#}")));
                        arena.note_strategy(Strategy::Skip);
                        relocated.insert(step.block_vaddr, step.block_vaddr);
                        let so = emit_stub(&mut arena, step);
                        arena.patch_jump(so, arena_vaddr + so, step.block_vaddr)?;
                        continue;
                    }
                };
                let stub = emit_stub(&mut arena, step);
                // The appended tail jump goes immediately after the copy. The
                // block's own terminator is *not* re-emitted, so the copy is
                // `size` bytes long and the jump sits right after it.
                patch_sites.push(PatchSite {
                    site_vaddr: copy_vaddr + size,
                    orig_len: 5,
                    arena_offset: stub,
                });
                // A terminator-less block that *is* the segment entry is reached
                // by the program's own entry point, not by any stub we emit, so
                // there is nothing to redirect. Say so rather than letting the
                // gap look covered.
                if step.block_vaddr == text.p_vaddr {
                    report.warnings.push(format!(
                        "block at the segment entry {:#x} has no terminator and is not \
                         reachable by redirection; its exit edge is not instrumented",
                        step.block_vaddr
                    ));
                    arena.note_strategy(Strategy::Skip);
                    continue;
                }
                // Redirect the block's entry to the copy, if there is room for
                // the 5-byte jump. A short block is still reached, because its
                // predecessors' stubs now target `relocated`.
                if step.block_len >= 5 {
                    patch_sites.push(PatchSite {
                        site_vaddr: step.block_vaddr,
                        orig_len: step.block_len.min(u32::MAX as u64) as u32,
                        arena_offset: copy_vaddr - arena_vaddr,
                    });
                }
                arena.note_strategy(Strategy::AppendTail);
            }

            Strategy::Relocate => {
                // Two-stage redirection:
                //
                //   original block --jmp--> arena copy --jmp--> dispatch stub
                //
                // The first hop is a 5-byte `jmp rel32` written at the block's
                // *entry*: relocation exists precisely because the terminator is
                // too short to hold one (a 2-byte `jcc rel8`), and the bytes
                // before it are the block's own body, which we may abandon
                // because the copy lives in the arena.
                //
                // When the block is itself shorter than 5 bytes there is no room
                // for the entry jump either. The copy is still emitted and
                // recorded in `relocated`, so every *predecessor's* stub jumps
                // straight to it and the block is instrumented anyway -- only
                // its original bytes are left in place, unreachable. That is why
                // the entry jump is conditional on there being room, and why the
                // short-block case is not a coverage gap except at the segment
                // entry (handled by `short_blocks`).
                let has_room_for_entry_jump = step.block_len >= 5;
                //
                // The body may legitimately be empty: a block whose *first*
                // instruction is the branch has nothing before it, and that is
                // exactly the case which forces relocation. Such a block gets a
                // bare 5-byte jump with no re-encoding.
                let relocated_body = if step.body.is_empty() {
                    // The block *is* its branch. Nothing to re-encode, so the
                    // "copy" is just a jump to the stub -- which
                    // `emit_jmp_placeholder` gives us, and which the patch site
                    // below retargets.
                    Some(arena.emit_jmp_placeholder())
                } else {
                    let body = suture_ir::BasicBlock {
                        id: step.block_id,
                        vaddr: step.block_vaddr,
                        instrs: step.body.clone(),
                        terminator: None,
                        no_fallthrough: false,
                    };
                    // Encoded against the arena's real address: its vaddr is
                    // known before emission, so RIP-relative operands inside the
                    // block resolve correctly on this first pass.
                    match arena.relocate_block(&body, arena_vaddr) {
                        Ok((v, size)) => {
                            relocated_sizes.insert(step.block_id, size);
                            Some(v)
                        }
                        Err(e) => {
                            // A block whose RIP-relative operand cannot survive
                            // the move. Not fatal: leaving the block alone keeps
                            // the binary correct and costs one block of coverage.
                            // Aborting the whole binary over one un-encodable
                            // block -- which a linear sweep can easily produce by
                            // mis-decoding a jump table -- would be worse.
                            reloc_failures.push((step.block_vaddr, format!("{e:#}")));
                            arena.note_strategy(Strategy::Skip);
                            // No arena copy exists, so leave the original in place
                            // and point the stub back at it. The edge is still
                            // counted; only the relocation was lost.
                            relocated.insert(step.block_vaddr, step.block_vaddr);
                            let so = emit_stub(&mut arena, step);
                            arena.patch_jump(so, arena_vaddr + so, step.block_vaddr)?;
                            None
                        }
                    }
                };
                let Some(copy_vaddr) = relocated_body else {
                    continue;
                };
                relocated.insert(step.block_vaddr, copy_vaddr);

                let stub = emit_stub(&mut arena, step);
                // The copy's terminator is a 5-byte jump to the stub, placed
                // after the re-encoded body. The short `jcc` is never
                // re-emitted: the stub re-tests the condition on flags that are
                // still live at the end of the body, so re-encoding the branch
                // itself would be redundant work.
                let tail = if step.body.is_empty() {
                    // The placeholder *is* the terminator; the site below
                    // overwrites its displacement in place.
                    copy_vaddr
                } else {
                    copy_vaddr + relocated_sizes[&step.block_id]
                };
                patch_sites.push(PatchSite {
                    site_vaddr: tail,
                    orig_len: 5,
                    arena_offset: stub,
                });
                // The original block's entry -> the arena copy, overwriting the
                // whole block and nop-padding the tail. Only when there is room.
                if has_room_for_entry_jump {
                    patch_sites.push(PatchSite {
                        site_vaddr: step.block_vaddr,
                        orig_len: step.block_len.min(u32::MAX as u64) as u32,
                        arena_offset: copy_vaddr - arena_vaddr,
                    });
                }
                arena.note_strategy(Strategy::Relocate);
            }
        }
    }

    // ---- 5: reserve the coverage table, then patch every displacement ----
    //
    // `finish` must run before `finalize` because finalize needs to know where
    // the table ended up.
    arena.finish()?;
    // The table lives in its *own* segment, so displacements are computed
    // against the table's vaddr, not the code arena's. That address is derived
    // from the arena's size, which is only known after `finish` -- and it is
    // still a pure function of the original image, so the rebuilt file can be
    // checked against it afterwards.
    let code_len = arena.table_offset();
    let table_vaddr = (arena_vaddr + code_len).div_ceil(suture_elf::PAGE) * suture_elf::PAGE;
    arena.set_table_base(table_vaddr - arena_vaddr);
    arena.finalize(arena_vaddr)?;
    // Retarget each stub at its real successor, which may itself be a relocated
    // block. Only stubs have a `jmp` to fix; a relocated block's trailing jump
    // is a plain placeholder whose target is already known.
        //
        // A stub's successor is looked up in `relocated` first, so when a
        // successor was copied into the arena the jump lands on the copy rather
        // than the now-unreachable original. This is also what makes short
        // blocks work: nothing points at their original bytes any more.
        for step in &plan {
            let Some(stub_offset) = step.stub_offset else { continue };
            let stub_vaddr = arena_vaddr + stub_offset;
            let target = relocated
                .get(&step.target_vaddr)
                .copied()
                .unwrap_or(step.target_vaddr);
            arena.patch_jump(stub_offset, stub_vaddr, target)?;
        }
    // Split the finished arena into the two mappings it must become: the code
    // goes into an R|X segment, the table into an R|W one. The split point is
    // `table_offset`, which `finish` recorded.
    let arena_all = arena.bytes();
    let split = arena.table_offset() as usize;
    if split >= arena_all.len() {
        bail!("internal error: table offset {} is past the arena", split);
    }
    let code_bytes = arena_all[..split].to_vec();
    let table_bytes = arena_all[split..].to_vec();
    let arena_size = arena.stats().arena_size;
    let stats: ArenaStats = arena.stats();
    report.blocks_patched = stats.blocks_patched;
    report.blocks_relocated = stats.blocks_relocated;
    report.blocks_skipped = stats.blocks_skipped;
    report.blocks_appended = stats.blocks_appended;
    drop(arena);

    // ---- 6: build the file ----
    //
    // The rebuilt file must land the code arena at the address we assumed. If it
    // did not, every displacement we just computed would be wrong, so this is
    // checked rather than assumed.
    let (mut out, actual_vaddr, table_vaddr) =
        img.rebuild_with_arena(&code_bytes, &table_bytes, suture_elf::DEFAULT_GUARD)?;
    if actual_vaddr != arena_vaddr {
        bail!(
            "internal error: arena vaddr moved between planning ({:#x}) and \
             emission ({:#x}); displacements would be wrong",
            arena_vaddr,
            actual_vaddr
        );
    }
    report.arena_vaddr = arena_vaddr;
    report.table_vaddr = table_vaddr;
    report.arena_size = arena_size;

    // ---- 7: apply the jumps ----
    //
    // Two kinds of site: terminators in the shifted copy of `.text`, and the
    // trailing jumps of relocated blocks inside the arena. Both are written here
    // because both need the arena's file offset, which only the rebuilt file
    // knows.
    let arena_file_off = Elf64Image::parse(out.clone())?
        .phdrs
        .iter()
        .find(|p| p.p_type == suture_elf::PT_LOAD && p.p_vaddr == arena_vaddr)
        .map(|p| p.p_offset as usize)
        .context("arena segment missing from the rebuilt file")?;
    let delta = delta_of(&img);
    apply_patches(&mut out, &text, &patch_sites, arena_vaddr, arena_file_off, delta)?;
    for s in &patch_sites {
        // Only ranges in the *original* image are interesting for auditing; the
        // arena is entirely ours.
        if s.site_vaddr < arena_vaddr {
            report.patched_ranges.push((s.site_vaddr, u32::from(s.orig_len)));
        }
    }

    report.output_size = out.len() as u64;
    report.stubs_emitted = patch_sites.len() as u32;
    report.elapsed_ms = started.elapsed().as_millis();

    if !reloc_failures.is_empty() {
        let sample: Vec<String> = reloc_failures
            .iter()
            .take(3)
            .map(|(addr, e)| {
                format!(
                    "{addr:#x}: {}",
                    e.lines().next().unwrap_or("(no detail)")
                )
            })
            .collect();
        report.warnings.push(format!(
            "{} block(s) could not be re-encoded and are left uninstrumented, \
             costing that much coverage. The cause is almost always a \
             RIP-relative operand the encoder could not re-base. First few: {:?}",
            reloc_failures.len(),
            sample
        ));
    }

    if !out_of_range_blocks.is_empty() {
        report.warnings.push(format!(
            "{} block(s) had a terminator at or past the end of .text and were \
             re-planned as terminator-less. First few: {:?}",
            out_of_range_blocks.len(),
            &out_of_range_blocks[..out_of_range_blocks.len().min(5)]
        ));
    }

    if !short_blocks.is_empty() {
        // Summarised, not listed: a pathological binary could have thousands,
        // and a warning per block would bury the warnings that matter.
        report.warnings.push(format!(
            "{} block(s) shorter than 5 bytes were not instrumented: their branches \
             cannot hold a rel32 jump. First few: {:?}",
            short_blocks.len(),
            &short_blocks[..short_blocks.len().min(5)]
        ));
    }

    std::fs::write(output, &out)
        .with_context(|| format!("writing {}", output.display()))?;

    // The fork server needs the map's absolute address and size. Assert the
    // layout matches what the table segment actually contains, so a mismatch
    // between `MapLayout` and the emitted segment fails here rather than as a
    // silent misread at fuzzing time.
    let final_layout = MapLayout::new(map_size, 0);
    assert_eq!(
        final_layout.total_bytes(),
        table_bytes.len() as u64,
        "the emitted table segment must match the declared map layout"
    );
    let _ = layout;
    Ok(report)
}

/// The shift applied to every original file offset by `rebuild_with_arena`.
///
/// Must track the number of program headers suture appends: the header region is
/// padded to a page, so growing `e_phnum` by two changes `delta`. Getting this
/// wrong would patch bytes at the wrong file offset -- a silent corruption.
fn delta_of(img: &Elf64Image) -> u64 {
    let new_phnum = u64::from(img.e_phnum) + 2;
    (suture_elf::EHDR_SIZE + new_phnum * suture_elf::PHDR_SIZE).div_ceil(suture_elf::PAGE)
        * suture_elf::PAGE
}

/// A place in the output where a 5-byte `jmp rel32` must be written.
///
/// `site_vaddr` is either an address in the original `.text` or an address
/// inside the arena; `apply_patches` handles both, since only the file offset
/// differs.
struct PatchSite {
    site_vaddr: u64,
    /// Bytes available at the site. A 5-byte jump always fits; anything beyond
    /// 5 is padded with `nop`.
    ///
    /// `u32`, not `u8`: an earlier version truncated here, so a block longer
    /// than 255 bytes produced a reported range *shorter* than what was
    /// actually overwritten. `suture-verify` audits the output against exactly
    /// these ranges, so a truncated range is a false all-clear -- the audit
    /// would pass a binary we had quietly corrupted.
    orig_len: u32,
    /// Offset within the arena of the destination.
    arena_offset: u64,
}

/// Emit the dispatch stub a step needs, recording its offset on the step.
///
/// A conditional branch gets the two-counter dispatch stub; anything else gets
/// the single-counter bump-and-jump. Recording the offset on the step is what
/// lets the caller distinguish stubs (which have a `jmp` needing a target) from
/// relocated blocks (whose trailing jump is a bare placeholder).
fn emit_stub(arena: &mut ArenaBuilder, step: &mut Step) -> u64 {
    let off = match step.cc {
        Some(cc) => arena
            .emit_dispatch(cc, step.edge_taken, step.edge_nottaken, step.target_vaddr)
            .expect(
                "emitting a dispatch stub only fails on a rel32 range check, \
                 which is deferred to finalize",
            )
            as u64,
        None => arena.emit_bump_and_jump(step.edge_taken, step.target_vaddr) as u64,
    };
    step.stub_offset = Some(off);
    off
}

/// One block's instrumentation plan.
struct Step {
    block_id: u32,
    block_vaddr: u64,
    orig_len: u8,
    strategy: Strategy,
    /// `Some(cc)` for a conditional branch dispatch stub.
    cc: Option<u8>,
    edge_taken: u32,
    edge_nottaken: u32,
    target_vaddr: u64,
    body: Vec<iced_x86::Instruction>,
    /// Total size of the block's original bytes.
    block_len: u64,
    /// Address of the terminator, which is where the jump is written.
    ///
    /// Not the block's start: a block is `body ++ terminator`, and the body must
    /// be left alone. This distinction is the whole reason a block-with-a-body
    /// and a block-whose-first-instruction-is-the-branch are different cases.
    term_vaddr: u64,
    /// Arena offset of this step's dispatch stub, recorded so the caller can
    /// tell stubs apart from relocated blocks when fixing jumps.
    stub_offset: Option<u64>,
}

/// Decide how each block is instrumented.
///
/// The important rule, and the reason `orig_len` matters: a terminator can only
/// be patched in place if `jmp rel32` (5 bytes) plus padding fits inside the
/// original instruction. A 2-byte `jcc rel8` cannot, so the block is relocated.
fn plan_instrumentation(
    sweep: &SweepResult,
    edges: &[Edge],
    index: &HashMap<u64, u32>,
) -> Result<Vec<Step>> {
    let mut out = Vec::new();

    for b in &sweep.blocks {
        // Collect this block's outgoing edges. A block with none cannot happen
        // (`build_edges` always emits at least one), but if it did we must skip
        // it rather than fabricate a target.
        let mine: Vec<&Edge> = edges.iter().filter(|e| e.from == b.id).collect();
        if mine.is_empty() {
            continue;
        }

        let Some(term_idx) = b.terminator else {
            // A block with no terminator: straight-line code that runs to the end
            // of what the sweep could decode. It still has an exit edge, so it
            // is instrumented at the *end* of the block -- after the last
            // instruction, not over one of them.
            let last = b.instrs.last().expect("block with no terminator is non-empty");
            out.push(Step {
                block_id: b.id,
                block_vaddr: b.vaddr,
                orig_len: 0,
                strategy: Strategy::AppendTail,
                cc: None,
                edge_taken: mine[0].id,
                edge_nottaken: mine[0].id,
                target_vaddr: last.next_ip(),
                body: b.instrs.clone(),
                block_len: b.size(),
                term_vaddr: last.next_ip(),
                stub_offset: None,
            });
            continue;
        };
        let term = &b.instrs[term_idx];
        let mn = term.mnemonic();

        let strategy = crate::classify(term);
        let cc = crate::cc_nibble(mn);

        // Successor addresses, in the order the stub expects: taken first, then
        // fallthrough.
        let taken = mine.iter().find(|e| e.taken).copied();
        let fallthrough = mine.iter().find(|e| !e.taken).copied();

        let target_vaddr = match taken {
            Some(e) => e.to.and_then(|to| vaddr_of(sweep, to)).unwrap_or(term.next_ip()),
            None => term.next_ip(),
        };

        let body: Vec<iced_x86::Instruction> = b.instrs[..term_idx].to_vec();

        out.push(Step {
            block_id: b.id,
            block_vaddr: b.vaddr,
            orig_len: term.len() as u8,
            strategy,
            cc,
            edge_taken: taken.map(|e| e.id).unwrap_or_else(|| mine[0].id),
            edge_nottaken: fallthrough.map(|e| e.id).unwrap_or(mine[0].id),
            target_vaddr,
            body,
            block_len: b.size(),
            term_vaddr: term.ip(),
            stub_offset: None,
        });
    }
    let _ = index;
    Ok(out)
}

fn vaddr_of(sweep: &SweepResult, id: u32) -> Option<u64> {
    sweep.blocks.iter().find(|b| b.id == id).map(|b| b.vaddr)
}

/// Overwrite each patch site with `jmp rel32` to its arena destination.
///
/// A site may be in the original `.text` or inside the arena, so the file offset
/// is computed by asking which region the address falls in.
fn apply_patches(
    out: &mut [u8],
    text: &suture_elf::ProgramHeader,
    sites: &[PatchSite],
    arena_vaddr: u64,
    arena_file_off: usize,
    delta: u64,
) -> Result<()> {
    for s in sites {
        let dest_vaddr = arena_vaddr + s.arena_offset;
        let rel = i32::try_from((dest_vaddr as i64) - ((s.site_vaddr + 5) as i64)).with_context(
            || format!("jump from {:#x} to {:#x} is out of rel32 range", s.site_vaddr, dest_vaddr),
        )?;

        // Which region does this site live in? Everything at or above the arena's
        // base is arena code; everything else is the original `.text`. The table
        // segment is never a patch site, so it needs no case.
        let file_off = if s.site_vaddr >= arena_vaddr {
            arena_file_off + (s.site_vaddr - arena_vaddr) as usize
        } else if s.site_vaddr >= text.p_vaddr
            && s.site_vaddr < text.p_vaddr + text.p_filesz
        {
            (text.p_offset + (s.site_vaddr - text.p_vaddr) + delta) as usize
        } else {
            bail!(
                "patch site {:#x} is in neither .text ({:#x}..{:#x}) nor the arena \
                 ({:#x}..); the sweep and the ELF layout disagree",
                s.site_vaddr,
                text.p_vaddr,
                text.p_vaddr + text.p_filesz,
                arena_vaddr
            );
        };

        if file_off + s.orig_len as usize > out.len() {
            bail!("patch site {:#x} is outside the rebuilt file", s.site_vaddr);
        }
        out[file_off] = crate::JMP_REL32[0];
        out[file_off + 1..file_off + 5].copy_from_slice(&rel.to_le_bytes());
        // Pad the remainder with `nop` rather than zeroes: if control ever fell
        // into the padding through a bug, a nop sled is legible in a crash
        // trace instead of looking like a jump table.
        for i in 5..s.orig_len as usize {
            out[file_off + i] = 0x90;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use std::path::PathBuf;

    /// A minimal static ELF with a `.text` that exercises every instrumentation
    /// decision: a `jcc rel8` (must relocate), a `jcc rel32` (patch in place),
    /// a `ret`, and an indirect jump.
    fn synth_elf() -> Vec<u8> {
        // Layout chosen so that every block is at least 5 bytes.
        //
        // The first version of this fixture had `je rel8` as the *only*
        // instruction of its block, making the block 2 bytes -- which is a real
        // case the pipeline must handle, but a poor thing to make the primary
        // fixture because it forces the shortest-block path on every test. The
        // short-block case has its own dedicated test below.
        let mut code: Vec<u8> = Vec::new();
        let push = |c: &mut Vec<u8>, b: &[u8]| c.extend_from_slice(b);

        // +0  mov eax, 0
        push(&mut code, &[0xb8, 0x00, 0x00, 0x00, 0x00]);
        // +5  je rel8 +2 -> +9   (2-byte branch, but the block is 7 bytes)
        push(&mut code, &[0x74, 0x02]);
        // +7  nop  (fallthrough)
        push(&mut code, &[0x90]);
        // +8  nop
        push(&mut code, &[0x90]);
        // +9  ret
        push(&mut code, &[0xc3]);
        // +10 mov ecx, 1
        push(&mut code, &[0xb9, 0x01, 0x00, 0x00, 0x00]);
        // +15 je rel32 +7 -> +28  (6-byte branch: patchable in place)
        push(&mut code, &[0x0f, 0x84, 0x07, 0x00, 0x00, 0x00]);
        // +21 nop
        push(&mut code, &[0x90]);
        // +22 nop
        push(&mut code, &[0x90]);
        // +23 nop
        push(&mut code, &[0x90]);
        // +24 nop
        push(&mut code, &[0x90]);
        // +25 nop
        push(&mut code, &[0x90]);
        // +26 nop
        push(&mut code, &[0x90]);
        // +27 nop
        push(&mut code, &[0x90]);
        // +28 mov rax, 0
        push(&mut code, &[0x48, 0xc7, 0xc0, 0x00, 0x00, 0x00, 0x00]);
        // +35 jmp rax  (indirect: recorded, not instrumented)
        push(&mut code, &[0xff, 0xe0]);

        let text_vaddr = 0x400000u64;
        // `p_offset` must be congruent to `p_vaddr` mod `p_align`, or the
        // kernel's loader rejects the file before any of our code runs. The
        // first version of this fixture used offset 0x100, which violates that
        // (0x100 % 0x1000 = 0x100, but 0x400000 % 0x1000 = 0) -- the input was
        // itself unloadable, and the test was asserting on garbage.
        let code_off = 0x1000usize;
        let file_len = 0x4000usize;
        let mut b = vec![0u8; file_len];
        b[0..4].copy_from_slice(b"\x7fELF");
        b[4] = 2; // ELFCLASS64
        b[5] = 1; // ELFDATA2LSB
        b[6] = 1;
        b[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        b[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
        b[20..24].copy_from_slice(&1u32.to_le_bytes());
        b[24..32].copy_from_slice(&text_vaddr.to_le_bytes());
        b[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
        b[40..48].copy_from_slice(&0u64.to_le_bytes());
        b[52..54].copy_from_slice(&64u16.to_le_bytes());
        b[54..56].copy_from_slice(&56u16.to_le_bytes());
        b[56..58].copy_from_slice(&1u16.to_le_bytes()); // e_phnum
        b[58..60].copy_from_slice(&64u16.to_le_bytes());
        b[60..62].copy_from_slice(&0u16.to_le_bytes()); // e_shnum

        // p_offset must point at the code: the pipeline slices
        // `bytes[p_offset .. p_offset + p_filesz]` and disassembles it starting
        // at p_vaddr, so an offset that disagrees with where the code sits makes
        // the sweep decode the ELF header as instructions.
        let p = suture_elf::ProgramHeader {
            p_type: suture_elf::PT_LOAD,
            p_flags: suture_elf::PF_R | suture_elf::PF_X,
            p_offset: code_off as u64,
            p_vaddr: text_vaddr,
            p_paddr: text_vaddr,
            p_filesz: 0x1000,
            p_memsz: 0x1000,
            p_align: 0x1000,
        };
        p.write(&mut b, 64);
        b[code_off..code_off + code.len()].copy_from_slice(&code);
        b
    }

    /// A unique directory per test. The pid alone is not enough: cargo runs
    /// tests in threads within one process, so two tests would share a path and
    /// one would delete the directory the other was still using.
    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir()
            .join(format!("suture-test-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn instruments_a_synthetic_binary_end_to_end() -> Result<()> {
        let d = tmpdir("e2e");
        let inp = d.join("in.elf");
        let outp = d.join("out.elf");
        std::fs::write(&inp, synth_elf())?;

        let rep = instrument_file(&inp, &outp)?;
        println!("{}", rep.summary());

        assert!(outp.exists(), "output must be written");
        assert!(rep.output_size > rep.input_size, "file must grow");
        assert!(rep.blocks_total > 0);
        // Every block must be accounted for by exactly one strategy. A block
        // that is silently dropped would make the coverage map claim edges that
        // are never recorded.
        assert_eq!(
            rep.blocks_total,
            rep.blocks_patched + rep.blocks_relocated + rep.blocks_skipped + rep.blocks_appended
        );
        assert!(rep.edges_total > 0);
        assert!(rep.edges_total as usize <= rep.map_size as usize);
        assert!(rep.arena_vaddr > 0);
        assert!(rep.arena_size > rep.map_size as u64);
        assert!(!rep.warnings.is_empty(), "the indirect jmp must be reported");
        std::fs::remove_dir_all(&d).ok();
        Ok(())
    }

    #[test]
    fn output_reparses_and_keeps_the_loader_invariants() -> Result<()> {
        let d = tmpdir("reparse");
        let inp = d.join("in2.elf");
        let outp = d.join("out2.elf");
        std::fs::write(&inp, synth_elf())?;
        instrument_file(&inp, &outp)?;

        let img = Elf64Image::from_path(&outp)?;
        assert_eq!(img.e_type, 2, "e_type preserved");
        assert_eq!(img.e_entry, 0x400000, "entry point preserved");
        // Three segments: the original plus suture's R|X code arena and R|W
        // coverage table.
        assert_eq!(img.phdrs.len(), 3, "both suture segments must be appended");
        assert_eq!(
            img.phdrs[1].p_flags & suture_elf::PF_X,
            suture_elf::PF_X,
            "the code arena must be executable"
        );
        assert_eq!(
            img.phdrs[1].p_flags & suture_elf::PF_W,
            0,
            "the code arena must not be writable"
        );
        assert_eq!(
            img.phdrs[2].p_flags & suture_elf::PF_W,
            suture_elf::PF_W,
            "the coverage table must be writable"
        );
        // The two suture segments must not overlap, or the table would clobber
        // the stubs at load time.
        assert!(
            img.phdrs[1].p_vaddr + img.phdrs[1].p_memsz <= img.phdrs[2].p_vaddr,
            "the arena and table mappings must not overlap"
        );

        // The congruence the kernel requires. Checked as equal *remainders* of
        // unsigned division, not as a subtraction: `p_offset` and `p_vaddr` are
        // both far above 2^31 here, and a signed `as i64` comparison of the
        // difference would report a spurious mismatch.
        for p in &img.phdrs {
            if p.p_align > 1 {
                assert_eq!(
                    p.p_offset % p.p_align,
                    p.p_vaddr % p.p_align,
                    "p_offset % p_align must equal p_vaddr % p_align for {:?}",
                    p
                );
            }
        }
        // The original mapping must be unchanged in virtual terms.
        let text = img.text_segment().unwrap();
        assert_eq!(text.p_vaddr, 0x400000);
        assert_eq!(text.p_filesz, 0x1000, "the segment's size must be preserved");

        let orig = synth_elf();
        // `text` comes from the *rebuilt* image, so its p_offset already
        // includes the rebuild shift. Adding delta again would look 4 KiB past
        // the code, into padding -- which reads as zeroes and makes every
        // byte-comparison assertion below fail for no real reason.
        let new_off = text.p_offset as usize;
        let orig_off = (text.p_offset - delta_of(&Elf64Image::from_path(&inp)?)) as usize;

        // The first block in the synthetic binary is
        //   +0  mov eax,0
        //   +5  je rel8        <- 2 bytes, cannot hold a 5-byte jmp
        // so it is *relocated*: the whole block is abandoned and replaced with a
        // jump to the arena copy. Overwriting the leading `mov` is therefore
        // correct here, not a bug.
        assert_eq!(
            img.bytes[new_off],
            0xE9,
            "a relocated block must be replaced by a jmp rel32 at its entry"
        );
        // The bytes the jump covers are dead, and must be nop padding rather
        // than leftover code that a wild jump could land in.
        for i in 5..7 {
            assert_eq!(
                img.bytes[new_off + i],
                0x90,
                "dead bytes after a relocated block's jump must be nop"
            );
        }

        // A block that was *not* relocated must be untouched. The `ret` at +9
        // is a terminator-less block reached by the branch, and nothing patches
        // it, so it must survive verbatim.
        assert_eq!(
            &img.bytes[new_off + 9..new_off + 10],
            &orig[orig_off + 9..orig_off + 10],
            "an uninstrumented block must survive byte for byte"
        );
        std::fs::remove_dir_all(&d).ok();
        Ok(())
    }

    #[test]
    fn in_place_patches_are_well_formed_jumps() -> Result<()> {
        let d = tmpdir("jumps");
        let inp = d.join("in3.elf");
        let outp = d.join("out3.elf");
        std::fs::write(&inp, synth_elf())?;
        let rep = instrument_file(&inp, &outp)?;
        let img = Elf64Image::from_path(&outp)?;
        let text = img.text_segment().unwrap();
        // `text` is from the rebuilt image, so p_offset already includes the
        // shift. The original file's offset is that minus delta.
        let delta = delta_of(&Elf64Image::from_path(&inp)?);
        let base = text.p_offset as usize;
        let orig_base = (text.p_offset - delta) as usize;

        let orig = synth_elf();
        // Inspect the whole code region, not a fixed 0x40 bytes. Block
        // boundaries moved when the sweep stopped splitting at `call`, so a
        // patch range can now extend further into the segment than before, and
        // a hard-coded window would index out of bounds rather than report it.
        const WINDOW: usize = 0x1000;
        let orig_code = &orig[orig_base..orig_base + WINDOW];
        let new_code = &img.bytes[base..base + WINDOW];

        // Every byte that changed must be inside a range suture reported patching.
        //
        // A patch that lands one byte off still yields a loadable binary that
        // still passes the congruence check, but it destroys a live instruction.
        // Comparing against the *reported* ranges (rather than re-deriving what
        // "should" have changed) is the stronger test: it catches both an
        // off-by-one and a range that was reported incorrectly.
        for i in 0..WINDOW as u64 {
            if new_code[i as usize] == orig_code[i as usize] {
                continue;
            }
            let vaddr = text.p_vaddr + i;
            let covered = rep
                .patched_ranges
                .iter()
                .any(|(start, len)| vaddr >= *start && vaddr < *start + *len as u64);
            assert!(
                covered,
                "byte {:#x} changed {:#x} -> {:#x} but no reported patch range covers it; \
                 reported ranges: {:?}",
                vaddr,
                orig_code[i as usize],
                new_code[i as usize],
                rep.patched_ranges
            );
        }

        // Every reported range must begin with a real `jmp rel32`, and its
        // padding must be `nop`. A range that does not is a mis-reported patch.
        for (start, len) in &rep.patched_ranges {
            let off = (*start - text.p_vaddr) as usize;
            assert!(
                off + *len as usize <= WINDOW,
                "reported range at {:#x} ({} bytes) runs past the inspected region",
                start,
                len
            );
            assert_eq!(
                new_code[off],
                0xE9,
                "reported range at {:#x} does not start with a jmp rel32",
                start
            );
            for k in 5..*len as usize {
                assert_eq!(
                    new_code[off + k],
                    0x90,
                    "padding at {:#x} is {:#x}, expected nop",
                    *start + k as u64,
                    new_code[off + k]
                );
            }
        }

        // And every jump we wrote must land inside the arena.
        let mut jumps = 0;
        for (i, &b) in new_code.iter().enumerate() {
            if b == 0xE9 && orig_code[i] != 0xE9 {
                jumps += 1;
                let rel = i32::from_le_bytes(new_code[i + 1..i + 5].try_into()?);
                let from = (text.p_vaddr + i as u64 + 5) as i64;
                let dest = (from + rel as i64) as u64;
                assert!(
                    (rep.arena_vaddr..rep.arena_vaddr + rep.arena_size).contains(&dest),
                    "jump at {:#x} must land in the arena {:#x}..{:#x}, went to {:#x}",
                    text.p_vaddr + i as u64,
                    rep.arena_vaddr,
                    rep.arena_vaddr + rep.arena_size,
                    dest
                );
            }
        }
        assert!(jumps > 0, "at least one jump must have been written into .text");
        std::fs::remove_dir_all(&d).ok();
        Ok(())
    }

    #[test]
    fn refuses_a_file_with_no_executable_segment() -> Result<()> {
        let d = tmpdir("noexec");
        let inp = d.join("data.elf");
        let mut b = synth_elf();
        // Clear PF_X on the only PT_LOAD.
        b[68..72].copy_from_slice(&suture_elf::PF_R.to_le_bytes());
        std::fs::write(&inp, &b)?;
        let err = instrument_file(&inp, &d.join("out4.elf")).unwrap_err();
        assert!(
            format!("{:#}", err).contains("executable"),
            "expected a clear error, got: {:#}",
            err
        );
        std::fs::remove_dir_all(&d).ok();
        Ok(())
    }

    #[test]
    fn rejects_non_elf_input() {
        let d = tmpdir("notelf");
        let inp = d.join("notelf.bin");
        std::fs::write(&inp, b"MZ\x90\x00 this is a PE file, not an ELF").unwrap();
        let err = instrument_file(&inp, &d.join("out5.elf")).unwrap_err();
        let msg = format!("{:#}", err);
        assert!(
            msg.contains("not an ELF") || msg.contains("too small for an ELF"),
            "expected a clear ELF complaint, got: {msg}"
        );
        std::fs::remove_dir_all(&d).ok();
    }
}
