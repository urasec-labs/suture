//! Static analysis of a binary *before* instrumenting it.
//!
//! Two questions this answers, both of which decide whether suture is worth
//! running at all:
//!
//! 1. **Is the exact-edge claim worth anything on this binary?** It depends
//!    entirely on how badly AFL's hashed map would collide on *this* program's
//!    control flow. A number, not an opinion.
//! 2. **What will instrumentation cost here?** Relocation ratio, arena size,
//!    code growth, and how many indirect branches will be missed. A 40%
//!    relocation ratio means the hybrid scheme is barely doing its job, and
//!    that is worth knowing before spending a day on a fork server.
//!
//! Both are pure computation over bytes: no execution, no Linux, no target
//! process. That is deliberate -- it means the thesis can be checked on any
//! machine in a second.

use anyhow::{bail, Context, Result};
use suture_coverage::measure_afl_collisions;
use suture_elf::Elf64Image;
use crate::{classify, cc_nibble, Strategy};
use serde::Serialize;
use std::path::Path;

/// Everything `suture analyze` reports.
#[derive(Debug, Clone, Serialize)]
pub struct AnalysisReport {
    pub path: String,
    pub file_size: u64,
    pub e_type: &'static str,
    pub is_pie: bool,
    pub text_vaddr: u64,
    pub text_size: u64,

    // --- what the sweep found ---
    pub blocks_total: u32,
    pub edges_total: u32,
    pub map_size: u32,
    /// Branches suture will not instrument (§4.3 of the design doc).
    pub indirect_branches: u32,
    pub indirect_pct: f64,
    /// Where the linear sweep stopped, and why. `Undecodable` is normal: real
    /// `.text` holds jump tables and string literals.
    pub sweep_stop: String,

    // --- the C1 claim, measured on this binary's real edge set ---
    /// Distinct edges the sweep found.
    pub distinct_edges: usize,
    /// Distinct AFL map slots those edges land on.
    pub afl_slots_touched: usize,
    /// Fraction of distinct edges AFL cannot distinguish from another.
    pub afl_collision_rate: f64,
    /// Edges AFL merges that suture keeps apart.
    pub afl_edges_merged: usize,
    /// suture's slots needed vs. AFL's fixed 16 KiB.
    pub graft_slots_needed: u32,

    // --- predicted cost of instrumenting ---
    /// Blocks that can be patched in place.
    pub blocks_patchable: u32,
    /// Blocks that must be relocated (their branch is too short).
    pub blocks_relocatable: u32,
    /// Blocks that will be skipped entirely.
    pub blocks_skipped: u32,
    pub relocation_ratio: f64,
    /// Rough arena size, from the stub and block sizes we can see statically.
    pub estimated_arena: u64,
    pub estimated_growth_ratio: f64,
    /// Blocks too short to hold even a 5-byte redirect.
    pub blocks_too_short: u32,
}

/// Analyse `path` without instrumenting it.
pub fn analyze_file(path: &Path) -> Result<AnalysisReport> {
    let img = Elf64Image::from_path(path)?;
    let text = img
        .text_segment()
        .with_context(|| format!("{} has no executable PT_LOAD", path.display()))?;

    let off = text.p_offset as usize;
    let end = off + text.p_filesz as usize;
    if end > img.bytes.len() {
        bail!("the executable segment extends past the end of the file");
    }
    let code = &img.bytes[off..end];

    let dis = suture_ir::Disassembler::new();
    let sweep = dis
        .sweep(code, text.p_vaddr)
        .with_context(|| format!("sweeping {} bytes of .text", code.len()))?;
    let (edges, _) = sweep.build_edges();
    let map_size = suture_ir::SweepResult::map_size(&edges) as u32;

    // --- the C1 measurement, on this binary's actual edge set ---
    let pairs: Vec<(u32, u32)> = edges.iter().map(|e| (e.from, e.to.unwrap_or(u32::MAX))).collect();
    let collision = measure_afl_collisions(&pairs)?;

    // --- predicted instrumentation cost ---
    let mut patchable = 0u32;
    let mut relocatable = 0u32;
    let mut skipped = 0u32;
    let mut too_short = 0u32;
    let mut arena_est = 0u64;

    for b in &sweep.blocks {
        let Some(t) = b.terminator else {
            skipped += 1;
            arena_est += b.size();
            continue;
        };
        let term = &b.instrs[t];
        match classify(term) {
            Strategy::PatchInPlace => {
                patchable += 1;
                // 5-byte jmp + one dispatch stub.
                arena_est += 5 + if cc_nibble(term.mnemonic()).is_some() { 19 } else { 11 };
            }
            Strategy::Relocate => {
                relocatable += 1;
                if b.size() < 5 {
                    too_short += 1;
                }
                // A copy of the body plus a trailing 5-byte jmp and a stub.
                arena_est += b.size() + 5 + 19;
            }
            Strategy::AppendTail => {
                skipped += 1;
                arena_est += b.size() + 5 + 11;
            }
            Strategy::Skip => skipped += 1,
        }
    }

    let indirect = sweep.skipped_indirect.len() as u32;
    let total_blocks = sweep.blocks.len() as u32;
    let file_size = img.bytes.len() as u64;

    Ok(AnalysisReport {
        path: path.display().to_string(),
        file_size,
        e_type: if img.e_type == 3 { "ET_DYN (PIE)" } else { "ET_EXEC" },
        is_pie: img.e_type == 3,
        text_vaddr: text.p_vaddr,
        text_size: text.p_filesz,

        blocks_total: total_blocks,
        edges_total: edges.len() as u32,
        map_size,
        indirect_branches: indirect,
        indirect_pct: if total_blocks == 0 { 0.0 } else { indirect as f64 * 100.0 / total_blocks as f64 },
        sweep_stop: format!("{:?}", sweep.stop),

        distinct_edges: collision.distinct_edges,
        afl_slots_touched: collision.afl_slots_touched,
        afl_collision_rate: collision.collision_rate,
        afl_edges_merged: collision.edges_afl_merges,
        graft_slots_needed: map_size,

        blocks_patchable: patchable,
        blocks_relocatable: relocatable,
        blocks_skipped: skipped,
        relocation_ratio: if total_blocks == 0 {
            0.0
        } else {
            relocatable as f64 / total_blocks as f64
        },
        estimated_arena: arena_est,
        estimated_growth_ratio: (file_size + arena_est) as f64 / file_size as f64,
        blocks_too_short: too_short,
    })
}

impl AnalysisReport {
    /// A human-readable summary, phrased so the C1 verdict is unmissable.
    pub fn summary(&self) -> String {
        let verdict = if self.afl_collision_rate > 0.5 {
            "STRONG -- exact edges are clearly worth having"
        } else if self.afl_collision_rate > 0.1 {
            "MODERATE -- a real but not dramatic difference"
        } else {
            "WEAK -- AFL's collisions are rare here; the exact-edge claim \
             matters much less than the no-TLS/no-relocation one"
        };

        format!(
            "{}\n  \
  type         {} ({} bytes, .text {:#x}..{:#x})\n  \
  sweep        {} blocks, {} edges, map {} KiB, stopped: {}\n  \
  indirect     {} branches ({:.1}%) will NOT be instrumented\n\
\n  \
  C1  exact edges vs AFL's hash, on this binary's real edge set:\n      \
  distinct edges      {}\n      \
  AFL slots touched   {} of 16384\n      \
  AFL collision rate  {:.1}%  <- edges AFL merges that we keep apart\n      \
  suture slots needed  {} ({:.1}x AFL's fixed 16 KiB)\n      \
  VERDICT: {}\n\
\n  \
  cost  {} patchable / {} relocated / {} skipped ({:.1}% relocation)\n      \
  arena estimate    {} bytes, growth {:.2}x\n      \
  too-short blocks  {} (cannot hold a 5-byte redirect)",
            self.path,
            self.e_type,
            self.file_size,
            self.text_vaddr,
            self.text_vaddr + self.text_size,
            self.blocks_total,
            self.edges_total,
            self.map_size / 1024,
            self.sweep_stop,
            self.indirect_branches,
            self.indirect_pct,
            self.distinct_edges,
            self.afl_slots_touched,
            self.afl_collision_rate * 100.0,
            self.graft_slots_needed,
            self.graft_slots_needed as f64 / 16384.0,
            verdict,
            self.blocks_patchable,
            self.blocks_relocatable,
            self.blocks_skipped,
            self.relocation_ratio * 100.0,
            self.estimated_arena,
            self.estimated_growth_ratio,
            self.blocks_too_short,
        )
    }
}
