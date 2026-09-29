//! Disassembly and basic-block recovery for x86-64.
//!
//! Built on `iced-x86` because §4.2 of `docs/DESIGN.md` requires an **encoder**:
//! relocating a basic block means re-emitting every instruction with corrected
//! RIP-relative displacements. A decoder-only library would force us to hand-roll
//! the encoder, which is where binary rewriters usually rot.
//!
//! Scope: static linear sweep over `.text`. No recursive descent, no data-flow
//! analysis, no function-boundary recovery. The edge map is a *conservative
//! over-approximation* of control-flow edges, which is what a coverage map
//! needs -- extra edges cost one byte each, missing edges cost bugs.

use anyhow::{bail, Result};
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
use std::collections::{HashMap, HashSet};

/// A run of instructions with a single entry point and a single exit.
#[derive(Debug, Clone)]
pub struct BasicBlock {
    /// Index into the sweep's block list. Also the coverage-map block id.
    pub id: u32,
    /// Virtual address of the first instruction. This is the anchor the
    /// instrumenter patches.
    pub vaddr: u64,
    pub instrs: Vec<Instruction>,
    /// Index (into `instrs`) of the terminating control transfer, if the block
    /// ends in a branch. `None` means implicit fallthrough.
    pub terminator: Option<usize>,
    /// True when control leaves the block somewhere other than the
    /// terminator's fallthrough: a return, an unconditional jump, an indirect
    /// transfer, or a trap.
    pub no_fallthrough: bool,
}

impl BasicBlock {
    pub fn size(&self) -> u64 {
        self.instrs.iter().map(|i| i.len() as u64).sum()
    }
    pub fn last(&self) -> Option<&Instruction> {
        self.instrs.last()
    }
    pub fn vaddr_end(&self) -> u64 {
        self.vaddr + self.size()
    }
    /// True when the block's first instruction is not its successor's, i.e. the
    /// block is a genuine branch target rather than a linear-scan artefact.
    pub fn ends_in(&self, m: Mnemonic) -> bool {
        self.last().map(|i| i.mnemonic() == m).unwrap_or(false)
    }
}

/// An edge: a control transfer from one block to another.
///
/// `id` is assigned statically during instrumentation. Unlike AFL's
/// `(prev>>1) ^ (cur>>1)` hashing this is injective, so two distinct edges can
/// never share a map slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Edge {
    pub id: u32,
    pub from: u32,
    /// `None` for a block's implicit exit (return, or fallthrough out of
    /// `.text`). Synthetic exits get ids too, so the map has no special cases.
    pub to: Option<u32>,
    pub taken: bool,
}

/// Why the disassembler stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SweepStop {
    EndOfSegment,
    /// Linear sweep ran past executable code into data. Expected for any real
    /// binary that embeds jump tables or string literals in `.text`.
    Undecodable(u64),
    /// Hit the per-function instruction budget. Prevents a mis-decode from
    /// turning into a multi-megabyte phantom function.
    BudgetExceeded,
}

#[derive(Debug)]
pub struct SweepResult {
    /// Blocks sorted by `vaddr`, densely numbered from 0.
    pub blocks: Vec<BasicBlock>,
    /// Sorted, de-duplicated block start addresses.
    pub block_starts: Vec<u64>,
    /// Branches we deliberately did not instrument (indirect transfers).
    /// Reported rather than hidden -- see §4.3 of the design doc.
    pub skipped_indirect: Vec<u64>,
    pub stop: SweepStop,
}

#[derive(Debug, Clone)]
pub struct Disassembler {
    /// Cap on instructions per run. Well above any real function, well below
    /// "this is a mis-decode" territory.
    /// Instructions the phase-1 linear scan will decode before giving up.
    ///
    /// This is the budget for the *whole segment* scan, not per function, so it
    /// is large: a 1 MB `.text` is roughly 250k instructions. Exceeding it means
    /// the input is not what we think it is, and stopping is better than
    /// allocating without limit.
    pub max_instrs_per_run: usize,
    /// Cap on total blocks, as a runaway backstop.
    pub max_blocks: usize,
}

impl Default for Disassembler {
    fn default() -> Self {
        Disassembler {
            // 8M instructions covers a ~30 MB `.text`, far past any binary we
            // would realistically instrument.
            max_instrs_per_run: 8 << 20,
            max_blocks: 1 << 22,
        }
    }
}

impl Disassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Decode one linear run starting at `start`, stopping *after* the
    /// instruction that ends a coverage block.
    ///
    /// The stop condition is [`splits_block`], **not** [`is_control_transfer`],
    /// and the two must agree. `is_control_transfer` includes `call` and
    /// `syscall`, which end a *decode* run; if this function stopped on them
    /// while `sweep` only created leaders for `splits_block` instructions, the
    /// instructions between the stop and the next leader would belong to no
    /// block and be silently dropped from the coverage map.
    pub fn decode_run(
        &self,
        code: &[u8],
        code_vaddr: u64,
        start: u64,
    ) -> Result<(Vec<Instruction>, SweepStop)> {
        if start < code_vaddr {
            bail!("start {:#x} is below the segment base {:#x}", start, code_vaddr);
        }
        let off = (start - code_vaddr) as usize;
        if off >= code.len() {
            return Ok((Vec::new(), SweepStop::EndOfSegment));
        }

        let mut decoder =
            Decoder::with_ip(64, &code[off..], start, DecoderOptions::NONE);
        let mut out = Vec::new();

        loop {
            if out.len() >= self.max_instrs_per_run {
                return Ok((out, SweepStop::BudgetExceeded));
            }
            if !decoder.can_decode() {
                return Ok((out, SweepStop::EndOfSegment));
            }
            let mut instr = Instruction::default();
            decoder.decode_out(&mut instr);
            if instr.mnemonic() == Mnemonic::INVALID {
                return Ok((out, SweepStop::Undecodable(instr.ip())));
            }
            out.push(instr);
            if splits_block(instr.mnemonic()) {
                return Ok((out, SweepStop::EndOfSegment));
            }
        }
    }

    /// Full sweep: find every basic block in the segment.
    ///
    /// Two phases, and the first one has to see the *whole* segment:
    ///
    /// 1. **Linear scan with resync.** Walk the segment decoding forward.
    ///    When an invalid byte is hit, skip it and carry on rather than
    ///    stopping, because real `.text` interleaves code with jump tables
    ///    and string literals. Collect a *leader* at the segment entry, at
    ///    every direct branch target, and after every control transfer.
    /// 2. **Re-decode per leader**, stopping at that block's terminator.
    ///
    /// Phase 1 deliberately does not stop at branches. An earlier version used
    /// `decode_run` (which halts at the first control transfer) to gather
    /// leaders, which meant it only ever saw the first handful of instructions
    /// of the binary: busybox's 1.1 MB of `.text` yielded 3 blocks. The bug was
    /// invisible on small synthetic fixtures and catastrophic on real input.
    /// `sweep_sees_the_whole_segment` is the regression test.
    pub fn sweep(&self, code: &[u8], code_vaddr: u64) -> Result<SweepResult> {
        let mut leaders: HashSet<u64> = HashSet::new();
        leaders.insert(code_vaddr);
        let mut skipped_indirect = Vec::new();

        // ---- Phase 1: linear scan with resync ----
        let mut decoder =
            Decoder::with_ip(64, code, code_vaddr, DecoderOptions::NONE);
        let mut instr = Instruction::default();
        let mut count = 0usize;
        let mut stop = SweepStop::EndOfSegment;
        // Where we resynchronised after hitting data. The next valid
        // instruction we decode starts a block: without this, everything after
        // a jump table in `.text` belonged to no block at all and was silently
        // excluded from the coverage map.
        let mut resync_at: Option<u64> = None;
        loop {
            if count >= self.max_instrs_per_run {
                stop = SweepStop::BudgetExceeded;
                break;
            }
            if !decoder.can_decode() {
                break;
            }
            decoder.decode_out(&mut instr);
            if instr.mnemonic() == Mnemonic::INVALID {
                // Resync: step over the bad byte and keep going. `.text`
                // contains data, and one data word must not end the sweep.
                let next = instr.ip() + 1;
                if next >= code_vaddr + code.len() as u64 {
                    stop = SweepStop::Undecodable(instr.ip());
                    break;
                }
                decoder = Decoder::with_ip(
                    64,
                    &code[(next - code_vaddr) as usize..],
                    next,
                    DecoderOptions::NONE,
                );
                resync_at = Some(next);
                continue;
            }
            count += 1;

            if let Some(_t) = resync_at.take() {
                // The first valid instruction after a data run is a leader.
                // Everything from here to the next branch is otherwise
                // unreachable from any leader, so the whole region would be
                // missing from the coverage map.
                if in_range(code_vaddr, code, instr.ip()) {
                    leaders.insert(instr.ip());
                }
            }

            let mn = instr.mnemonic();

            // Every direct branch *target* is a leader, including `call`
            // targets: a function body starts its own block even though the
            // call itself does not split the caller's flow.
            if let Some(t) = branch_target(&instr) {
                if in_range(code_vaddr, code, t) {
                    leaders.insert(t);
                }
            }

            if splits_block(mn) {
                // The instruction after a block boundary starts a new block.
                let next = instr.next_ip();
                if in_range(code_vaddr, code, next) {
                    leaders.insert(next);
                }
            }
            if is_indirect(mn) && !is_return(mn) {
                // `ret` is not an "uninstrumented branch" -- it is a normal
                // block end that suture simply does not patch. Counting it here
                // would inflate the reported coverage gap.
                skipped_indirect.push(instr.ip());
            }
        }

        let mut leaders: Vec<u64> = leaders.into_iter().collect();
        leaders.sort_unstable();

        // ---- Phase 2: decode each block from its leader ----
        let mut blocks: Vec<BasicBlock> = Vec::new();
        for (i, &start) in leaders.iter().enumerate() {
            if blocks.len() >= self.max_blocks {
                break;
            }
            let end = leaders.get(i + 1).copied().unwrap_or(u64::MAX);
            let (instrs, _) = self.decode_run(code, code_vaddr, start)?;
            // Trim anything that runs past the next leader.
            let mut instrs: Vec<Instruction> =
                instrs.into_iter().take_while(|ins| ins.ip() < end).collect();
            if instrs.is_empty() {
                continue;
            }

            // A terminator at or past the segment's end is not a real
            // terminator. `iced-x86` can report a final instruction whose `ip`
            // lands exactly on the boundary when the preceding one consumed the
            // last bytes; patching that address would write past `.text`.
            // Treat the block as terminator-less instead, which is what it is.
            let last = *instrs.last().unwrap();
            if last.ip() + last.len() as u64 > code_vaddr + code.len() as u64 {
                instrs.pop();
                if instrs.is_empty() {
                    continue;
                }
            }

            let last = *instrs.last().unwrap();
            let mn = last.mnemonic();
            let (terminator, no_fallthrough) = if splits_block(mn) {
                if is_conditional(mn) {
                    // jcc: the fallthrough is a real successor.
                    (Some(instrs.len() - 1), false)
                } else {
                    // jmp / ret / trap: control leaves, no fallthrough.
                    (Some(instrs.len() - 1), true)
                }
            } else {
                (None, false)
            };

            blocks.push(BasicBlock {
                id: blocks.len() as u32,
                vaddr: start,
                instrs,
                terminator,
                no_fallthrough,
            });
        }

        blocks.sort_by_key(|b| b.vaddr);
        for (i, b) in blocks.iter_mut().enumerate() {
            b.id = i as u32;
        }
        let block_starts: Vec<u64> = blocks.iter().map(|b| b.vaddr).collect();
        skipped_indirect.sort_unstable();
        skipped_indirect.dedup();

        Ok(SweepResult { blocks, block_starts, skipped_indirect, stop })
    }
}

impl SweepResult {
    /// Build the static edge list and assign dense edge ids.
    ///
    /// Every block contributes one edge per branch successor, plus a synthetic
    /// exit edge when it leaves without a branch. The synthetic edges matter:
    /// a uniform block shape means the instrumenter needs no special case for a
    /// block that happens to end in `ret`.
    pub fn build_edges(&self) -> (Vec<Edge>, HashMap<u64, u32>) {
        let index: HashMap<u64, u32> = self.blocks.iter().map(|b| (b.vaddr, b.id)).collect();
        let mut edges = Vec::new();
        let mut next_id: u32 = 0;

        for b in &self.blocks {
            let Some(last) = b.last() else {
                edges.push(Edge { id: next_id, from: b.id, to: None, taken: false });
                next_id += 1;
                continue;
            };
            let mn = last.mnemonic();
            if !is_control_transfer(mn) {
                let to = index.get(&last.next_ip()).copied();
                edges.push(Edge { id: next_id, from: b.id, to, taken: false });
                next_id += 1;
            } else if is_conditional(mn) {
                if let Some(t) = branch_target(last) {
                    let to = index.get(&t).copied();
                    edges.push(Edge { id: next_id, from: b.id, to, taken: true });
                    next_id += 1;
                }
                let to = index.get(&last.next_ip()).copied();
                edges.push(Edge { id: next_id, from: b.id, to, taken: false });
                next_id += 1;
            } else if let Some(t) = branch_target(last) {
                // A *direct* jump has exactly one successor. Dispatching on
                // `branch_target` rather than on the mnemonic is what makes
                // `jmp rax` fall through to the synthetic-exit arm below: an
                // indirect jump has no static target, and keying off the
                // mnemonic instead meant such blocks ended up with *zero*
                // edges and were silently absent from the coverage map.
                let to = index.get(&t).copied();
                edges.push(Edge { id: next_id, from: b.id, to, taken: false });
                next_id += 1;
            } else {
                // Return, indirect transfer, or trap: one synthetic exit edge.
                edges.push(Edge { id: next_id, from: b.id, to: None, taken: false });
                next_id += 1;
            }
        }
        (edges, index)
    }

    /// Total `u8` slots needed for a dense map over these edges.
    ///
    /// `next_power_of_two` is 1 for an empty edge set, so no `.max(1)` is
    /// needed -- and adding one would be a clamp-like pattern that suggests a
    /// bound it cannot provide.
    pub fn map_size(edges: &[Edge]) -> usize {
        // Capped at 64 KiB so the map stays L1/L2 resident; see DESIGN.md §4.4.
        edges.len().next_power_of_two().min(1 << 16)
    }

    /// AFL's hashed index, for the collision-rate measurement in
    /// `docs/EVALUATION.md` (claim C1).
    pub fn afl_index(prev: u32, cur: u32) -> usize {
        let prev = prev.wrapping_shl(1) ^ prev.wrapping_shr(31);
        let cur = cur.wrapping_shl(1) ^ cur.wrapping_shr(31);
        ((prev >> 1) ^ (cur >> 1) & 0xffff) as usize & 0xffff
    }
}

/// x86-64 `inc byte [rip+disp32]`: `FF 05 disp32` -- 6 bytes.
///
/// Lives here rather than in `suture-instrument` because both the arena builder
/// and the pipeline need the same encoding, and a second copy of a magic byte
/// sequence is how an instrumentation scheme ends up subtly self-inconsistent.
pub const INC_BYTE_RIP: [u8; 2] = [0xFF, 0x05];
/// `jmp rel32`: `E9 disp32` -- 5 bytes.
pub const JMP_REL32: [u8; 1] = [0xE9];

pub fn in_range(base: u64, code: &[u8], addr: u64) -> bool {
    addr >= base && (addr - base) < code.len() as u64
}

/// True for anything that ends a run: branches, calls, returns, traps.
///
/// This is the *decode* boundary. It is deliberately broader than
/// [`splits_block`]: a `call` ends a decode run but does not start a new
/// coverage block.
pub fn is_control_transfer(m: Mnemonic) -> bool {
    is_conditional(m)
        || is_unconditional(m)
        || matches!(
            m,
            Mnemonic::Ret
                | Mnemonic::Retf
                | Mnemonic::Iret
                | Mnemonic::Iretd
                | Mnemonic::Iretq
                | Mnemonic::Call
                | Mnemonic::Int
                | Mnemonic::Int1
                | Mnemonic::Int3
                | Mnemonic::Into
                | Mnemonic::Ud2
                | Mnemonic::Syscall
                | Mnemonic::Sysret
                | Mnemonic::Hlt
                | Mnemonic::Loop
                | Mnemonic::Loope
                | Mnemonic::Loopne
                | Mnemonic::Xbegin
        )
}

/// True for instructions that start a **new coverage block**.
///
/// The distinction from [`is_control_transfer`] is the single most important
/// decision in this module, and getting it wrong is expensive rather than
/// subtle.
///
/// A `call` transfers control, but it *returns*. For coverage purposes the
/// instruction after a `call` is reached by ordinary fallthrough, and AFL does
/// not treat the call as an edge. So splitting blocks at every call site
/// produces a graph with several times too many nodes: on busybox it inflated
/// the block count to 100k, forced 41.6% of blocks to be relocated, and grew
/// the output file 2.5x -- for edges a coverage map cannot distinguish anyway.
///
/// `jcc` genuinely has two successors, and an unconditional transfer or a
/// `return` genuinely ends the path. Those are the only block boundaries.
pub fn splits_block(m: Mnemonic) -> bool {
    is_conditional(m) || is_unconditional(m) || is_return(m)
}

pub fn is_return(m: Mnemonic) -> bool {
    matches!(
        m,
        Mnemonic::Ret | Mnemonic::Retf | Mnemonic::Iret | Mnemonic::Iretd | Mnemonic::Iretq
    )
}

pub fn is_conditional(m: Mnemonic) -> bool {
    condition_code(m).is_some()
}

pub fn is_unconditional(m: Mnemonic) -> bool {
    matches!(m, Mnemonic::Jmp | Mnemonic::Jmpe)
}

/// `jmp rax` / `call [rbx+8]` / `ret` -- control leaves via a register or
/// memory operand, so no static edge exists. See DESIGN.md §4.3.
pub fn is_indirect(m: Mnemonic) -> bool {
    matches!(
        m,
        Mnemonic::Jmp | Mnemonic::Jmpe | Mnemonic::Call | Mnemonic::Ret | Mnemonic::Retf
    )
}

/// The static displacement target of a direct branch, if any.
pub fn branch_target(instr: &Instruction) -> Option<u64> {
    if instr.op0_kind() == OpKind::NearBranch64 {
        return Some(instr.near_branch64());
    }
    None
}

/// The condition-code suffix, e.g. `Mnemonic::Je -> "e"`. Also the answer to
/// "can this be re-tested in a dispatch stub?" -- the flags are still live at
/// the branch.
fn condition_code(m: Mnemonic) -> Option<&'static str> {
    Some(match m {
        Mnemonic::Jo => "o",
        Mnemonic::Jno => "no",
        Mnemonic::Jb => "b",
        Mnemonic::Jae => "ae",
        Mnemonic::Je => "e",
        Mnemonic::Jne => "ne",
        Mnemonic::Jbe => "be",
        Mnemonic::Ja => "a",
        Mnemonic::Js => "s",
        Mnemonic::Jns => "ns",
        Mnemonic::Jp => "p",
        Mnemonic::Jnp => "np",
        Mnemonic::Jl => "l",
        Mnemonic::Jge => "ge",
        Mnemonic::Jle => "le",
        Mnemonic::Jg => "g",
        Mnemonic::Jcxz => "cxz",
        Mnemonic::Jecxz => "ecxz",
        Mnemonic::Jrcxz => "rcxz",
        _ => return None,
    })
}

/// True when an instruction's meaning depends on its own address and therefore
/// must have its displacement recomputed during relocation.
pub fn is_rip_relative(instr: &Instruction) -> bool {
    (0..instr.op_count())
        .any(|i| instr.op_kind(i) == OpKind::Memory && instr.memory_base() == Register::RIP)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: u64 = 0x1000;

    fn sweep(bytes: &[u8]) -> SweepResult {
        Disassembler::new().sweep(bytes, BASE).unwrap()
    }

    #[test]
    fn decodes_a_linear_run() {
        let b = [
            0xb8, 0x2a, 0x00, 0x00, 0x00, // mov eax,42
            0x48, 0x89, 0xc1, // mov rcx,rax
            0xc3, // ret
        ];
        let (instrs, stop) = Disassembler::new().decode_run(&b, BASE, BASE).unwrap();
        assert_eq!(instrs.len(), 3);
        assert_eq!(instrs[0].ip(), BASE);
        assert_eq!(instrs[2].ip(), BASE + 8);
        assert_eq!(stop, SweepStop::EndOfSegment);
    }

    #[test]
    fn stops_at_invalid_bytes() {
        // 0x06 (push es) is invalid in 64-bit mode.
        let b = [0x90u8, 0x06, 0x90];
        let (instrs, stop) = Disassembler::new().decode_run(&b, BASE, BASE).unwrap();
        assert_eq!(instrs.len(), 1);
        assert_eq!(stop, SweepStop::Undecodable(BASE + 1));
    }

    #[test]
    fn sweep_splits_at_branch_targets() {
        // mov eax,0 ; je +2 (to BASE+9) ; two skipped nops ; ret
        let b = [
            0xb8, 0x00, 0x00, 0x00, 0x00, // BASE+0  mov eax,0
            0x74, 0x02, //                     BASE+5  je BASE+9
            0x90, //                           BASE+7  fallthrough -> leader
            0x90, //                           BASE+8  dead, never reached
            0xc3, //                           BASE+9  ret
        ];
        let r = sweep(&b);
        let addrs: Vec<u64> = r.blocks.iter().map(|b| b.vaddr).collect();
        assert!(addrs.contains(&BASE), "entry must be a leader");
        assert!(addrs.contains(&(BASE + 9)), "branch target must be a leader");
        assert!(addrs.contains(&(BASE + 7)), "jcc fallthrough must be a leader");
        // BASE+8 is reachable from neither path, so it must not become a block.
        assert!(!addrs.contains(&(BASE + 8)), "unreachable nop became a block");
    }

    #[test]
    fn block_ids_are_dense_and_sorted() {
        let b = [
            0xb8, 0x00, 0x00, 0x00, 0x00, 0x74, 0x02, 0x90, 0x90, 0xc3, 0xeb, 0xfe,
        ];
        let r = sweep(&b);
        for (i, blk) in r.blocks.iter().enumerate() {
            assert_eq!(blk.id, i as u32, "block ids must be dense");
        }
        for w in r.blocks.windows(2) {
            assert!(w[0].vaddr < w[1].vaddr, "blocks must be sorted by vaddr");
        }
    }

    #[test]
    fn edges_are_injective_and_dense() {
        // The central claim of DESIGN.md §2: distinct edges get distinct ids,
        // and ids are 0..n with no holes. If this breaks, "exact edges" is a
        // lie and the whole C1 claim collapses.
        let b = [
            0xb8, 0x00, 0x00, 0x00, 0x00, 0x74, 0x03, 0x90, 0x90, 0xc3,
        ];
        let r = sweep(&b);
        let (edges, _) = r.build_edges();
        assert!(!edges.is_empty());
        for (i, e) in edges.iter().enumerate() {
            assert_eq!(e.id, i as u32, "edge ids must be dense and ordered");
        }
        let mut seen = HashSet::new();
        for e in &edges {
            let key = (e.from, e.to, e.taken);
            assert!(seen.insert(key), "duplicate edge {key:?}");
        }
    }

    #[test]
    fn conditional_block_gets_two_edges() {
        // A jcc is the one case with two successors. Getting this wrong
        // silently halves coverage on every branch.
        let b = [
            0xb8, 0x00, 0x00, 0x00, 0x00, 0x74, 0x03, 0x90, 0x90, 0xc3,
        ];
        let r = sweep(&b);
        let jcc_block = r
            .blocks
            .iter()
            .find(|b| b.last().map(|i| is_conditional(i.mnemonic())).unwrap_or(false))
            .expect("a block must end in the jcc");
        let (edges, _) = r.build_edges();
        let mine: Vec<_> = edges.iter().filter(|e| e.from == jcc_block.id).collect();
        assert_eq!(mine.len(), 2, "jcc must yield a taken and a not-taken edge");
        assert!(mine.iter().any(|e| e.taken));
        assert!(mine.iter().any(|e| !e.taken));
    }

    #[test]
    fn return_block_gets_one_exit_edge() {
        let b = [0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3];
        let r = sweep(&b);
        let (edges, _) = r.build_edges();
        assert!(
            edges.iter().any(|e| e.to.is_none()),
            "a ret must produce a synthetic exit edge"
        );
    }

    #[test]
    fn indirect_jumps_are_recorded_not_instrumented() {
        // ff e0 = jmp rax
        let b = [0x48, 0x89, 0xc0, 0xff, 0xe0, 0xc3];
        let r = sweep(&b);
        assert!(
            !r.skipped_indirect.is_empty(),
            "indirect jmp must appear in skipped_indirect, not vanish"
        );
    }

    #[test]
    fn rip_relative_detection() {
        // 48 8b 05 disp32 = mov rax, [rip+disp32]
        let b = [0x48, 0x8b, 0x05, 0x34, 0x12, 0x00, 0x00];
        let (instrs, _) = Disassembler::new().decode_run(&b, BASE, BASE).unwrap();
        assert!(is_rip_relative(&instrs[0]));

        // A register-only mov must not be flagged, or relocation would
        // needlessly rewrite it.
        let b2 = [0x48, 0x89, 0xc0];
        let (i2, _) = Disassembler::new().decode_run(&b2, BASE, BASE).unwrap();
        assert!(!is_rip_relative(&i2[0]));
    }

    #[test]
    fn all_sixteen_conditions_are_recognised() {
        // Every jcc must be classed as conditional, or the dispatch-stub scheme
        // in §4.1 would silently mis-handle it.
        for (bytes, expect_cc) in [
            (vec![0x70u8, 0x01], "o"),
            (vec![0x71, 0x01], "no"),
            (vec![0x72, 0x01], "b"),
            (vec![0x73, 0x01], "ae"),
            (vec![0x74, 0x01], "e"),
            (vec![0x75, 0x01], "ne"),
            (vec![0x76, 0x01], "be"),
            (vec![0x77, 0x01], "a"),
            (vec![0x78, 0x01], "s"),
            (vec![0x79, 0x01], "ns"),
            (vec![0x7a, 0x01], "p"),
            (vec![0x7b, 0x01], "np"),
            (vec![0x7c, 0x01], "l"),
            (vec![0x7d, 0x01], "ge"),
            (vec![0x7e, 0x01], "le"),
            (vec![0x7f, 0x01], "g"),
        ] {
            let (instrs, _) = Disassembler::new().decode_run(&bytes, BASE, BASE).unwrap();
            let m = instrs[0].mnemonic();
            assert!(is_conditional(m), "not recognised as conditional: {m:?}");
            assert_eq!(condition_code(m), Some(expect_cc));
            assert!(is_control_transfer(m));
            assert!(!is_unconditional(m), "{expect_cc} must not be unconditional");
        }
    }

    #[test]
    fn map_size_is_power_of_two_and_bounded() {
        let one = [Edge { id: 0, from: 0, to: None, taken: false }];
        assert_eq!(SweepResult::map_size(&[]), 1);
        assert_eq!(SweepResult::map_size(&one), 1);
        // Capped so the map stays cache-resident (DESIGN.md §4.4).
        let many: Vec<Edge> = (0..100_000)
            .map(|i| Edge { id: i, from: i, to: None, taken: false })
            .collect();
        assert_eq!(SweepResult::map_size(&many), 1 << 16);
    }

    #[test]
    fn afl_index_is_in_range() {
        // The collision metric needs AFL's index to be well-defined.
        for (p, c) in [(0u32, 0u32), (0x1234, 0x5678), (u32::MAX, 1), (7, 7)] {
            assert!(SweepResult::afl_index(p, c) < (1 << 16));
        }
    }

    #[test]
    fn empty_and_out_of_range_inputs() {
        let d = Disassembler::new();
        let (instrs, stop) = d.decode_run(&[], BASE, BASE).unwrap();
        assert!(instrs.is_empty());
        assert_eq!(stop, SweepStop::EndOfSegment);

        // A start past the end of the code is "no instructions", not an error:
        // the instrumenter probes addresses like this routinely.
        let (instrs, stop) = d.decode_run(&[0x90], BASE, BASE + 0x100).unwrap();
        assert!(instrs.is_empty());
        assert_eq!(stop, SweepStop::EndOfSegment);

        // A start *below* the segment base is a real error -- it would mean the
        // edge table and the code disagree about where the segment starts.
        assert!(d.decode_run(&[0x90], BASE, BASE - 1).is_err());
    }

    #[test]
    fn every_block_gets_at_least_one_edge() {
        // Regression test for a silent coverage bug.
        //
        // `build_edges` dispatched on the *mnemonic*: an unconditional branch
        // was assumed to be direct. `jmp rax` is unconditional but has no
        // static target, so it fell into an arm that pushed nothing, and every
        // block ending in an indirect jump ended up with **zero** edges. Those
        // blocks were then skipped by the planner and vanished from the
        // coverage map entirely -- no error, no warning, just missing coverage.
        //
        // The invariant is the one that matters: no block may be edge-less.
        let mut code = Vec::new();
        code.extend_from_slice(&[0x48, 0x89, 0xc0]); // 0:  mov rax, rax
        code.extend_from_slice(&[0xff, 0xe0]); // 3:  jmp rax      (indirect)
        code.extend_from_slice(&[0x48, 0x89, 0xc1]); // 5:  mov rcx, rax
        code.extend_from_slice(&[0xc3]); // 8:  ret
        code.extend_from_slice(&[0x48, 0x89, 0xc2]); // 9:  mov rdx, rax
        code.extend_from_slice(&[0xff, 0xe2]); // 12: jmp rdx      (indirect)
        code.extend_from_slice(&[0xc3]); // 14: ret

        let r = sweep(&code);
        assert!(r.blocks.len() >= 2, "expected several blocks, got {}", r.blocks.len());
        let (edges, _) = r.build_edges();
        for b in &r.blocks {
            let n = edges.iter().filter(|e| e.from == b.id).count();
            assert!(
                n >= 1,
                "block {:#x} (terminator {:?}) produced {} edges; every block must \
                 have at least one or it is missing from the coverage map",
                b.vaddr,
                b.instrs.last().map(|i| i.mnemonic()),
                n
            );
        }
    }

    #[test]
    fn sweep_sees_the_whole_segment() {
        // Regression test for the worst bug in the project's history.
        //
        // `sweep` originally discovered leaders by calling `decode_run`, which
        // halts at the first control transfer. So it only ever saw the handful
        // of instructions before the first branch: busybox's 1.1 MB of `.text`
        // produced 3 blocks and a 0% collision rate, which would have made the
        // entire exact-edge thesis look validated for the wrong reason.
        //
        // A long run of straight-line code followed by a branch at the very end
        // is the minimal reproduction.
        let mut code = Vec::new();
        code.extend(std::iter::repeat(0x90u8).take(500));
        code.extend_from_slice(&[0xc3]); // ret, at offset 500
        code.extend_from_slice(&[0x90]); // 501: something for the ret to fall into
        let r = sweep(&code);
        assert_eq!(
            r.blocks.len(),
            2,
            "a 500-byte straight-line run, a `ret`, and a trailing nop is two blocks"
        );
        assert_eq!(r.blocks[0].vaddr, BASE);
        assert!(
            r.blocks[0].instrs.len() > 400,
            "the first block must contain the whole straight-line run, got {} instrs",
            r.blocks[0].instrs.len()
        );
    }

    #[test]
    fn calls_do_not_split_coverage_blocks() {
        // The other costly mistake. Splitting at every `call` inflated busybox
        // to 100k blocks and 41.6% relocation for edges a coverage map cannot
        // tell apart. A `call` returns, so the next instruction is reached by
        // fallthrough.
        //
        // `call rel32` is 5 bytes at offset 2, so its next_ip is 7. The callee
        // sits at 18, which makes the displacement 11.
        let mut code = Vec::new();
        code.extend_from_slice(&[0x31, 0xc0]); // 0:  xor eax,eax
        code.extend_from_slice(&[0xe8, 0x0b, 0x00, 0x00, 0x00]); // 2: call +11 -> 18
        code.extend_from_slice(&[0x90]); // 7:  nop
        code.extend_from_slice(&[0xc3]); // 8:  ret
        code.extend(std::iter::repeat(0x90u8).take(9)); // 9..17
        code.extend_from_slice(&[0xc3]); // 18: the call target
        let r = sweep(&code);
        let entry = r.blocks.iter().find(|b| b.vaddr == BASE).unwrap();
        // The block must span the call *and* the nop after it.
        assert!(
            entry.instrs.iter().any(|i| i.ip() == BASE + 2),
            "the call must be inside the entry block"
        );
        assert!(
            entry.instrs.iter().any(|i| i.ip() == BASE + 7),
            "the instruction after the call must be in the same block, not a new one"
        );
        // The call target is still its own block, so the callee is entered.
        assert!(
            r.blocks.iter().any(|b| b.vaddr == BASE + 18),
            "the callee must still be a block"
        );
    }

    #[test]
    fn returns_are_not_counted_as_uninstrumented_branches() {
        // `ret` ends a block normally. Reporting it as a skipped branch would
        // inflate the documented coverage gap by the number of functions in the
        // binary, which is most of them.
        let code = [0xc3u8, 0xc3, 0xc3, 0xc3];
        let r = sweep(&code);
        assert!(
            r.skipped_indirect.is_empty(),
            "returns must not be reported as uninstrumented branches, got {:?}",
            r.skipped_indirect
        );
    }

    #[test]
    fn splits_block_distinguishes_calls_from_branches() {
        for m in [Mnemonic::Je, Mnemonic::Jne, Mnemonic::Jmp] {
            assert!(splits_block(m), "{m:?} must split a block");
        }
        for m in [Mnemonic::Ret, Mnemonic::Retf] {
            assert!(splits_block(m), "{m:?} must end a block");
        }
        for m in [Mnemonic::Call, Mnemonic::Mov, Mnemonic::Nop, Mnemonic::Test] {
            assert!(!splits_block(m), "{m:?} must not split a block");
        }
    }

    #[test]
    fn sweep_resynchronises_past_data_in_text() {
        // Real `.text` holds jump tables and string literals. One data word must
        // not end the sweep, or everything after it goes uninstrumented.
        let mut code = Vec::new();
        code.extend_from_slice(&[0xc3]); // ret
        code.extend_from_slice(&[0x06, 0x06, 0x06, 0x06]); // invalid opcodes
        code.extend_from_slice(&[0x90, 0xc3]); // a nop and a ret
        let r = sweep(&code);
        let addrs: Vec<u64> = r.blocks.iter().map(|b| b.vaddr).collect();
        assert!(
            addrs.iter().any(|&a| a > BASE + 1),
            "the sweep must continue past the invalid bytes, found blocks at {addrs:?}"
        );
    }

    #[test]
    fn budget_stops_a_runaway_decode() {
        // An infinite loop (`jmp $`) with a tiny budget must terminate the run
        // rather than spin.
        let d = Disassembler { max_instrs_per_run: 8, max_blocks: 16 };
        let b = [0xeb, 0xfe];
        let (instrs, _) = d.decode_run(&b, BASE, BASE).unwrap();
        assert!(instrs.len() <= 8);
    }
}
