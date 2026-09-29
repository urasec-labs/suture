# suture — Design Document

**Source-free edge-coverage instrumentation for x86-64 ELF binaries, by static rewriting.**

Status: draft · Last update: 2026-09-29

---

## 1. Problem statement

Coverage-guided fuzzers need **edge coverage** feedback from the target. The
standard way to get it is compile-time instrumentation (AFL's `afl-gcc` /
`afl-clang`, libFuzzer's `-fsanitize=fuzzer`). That requires **source code**,
a **supported compiler**, and the **willingness to rebuild**.

Three large classes of targets are therefore out of reach:

| Class | Example | Why it is excluded today |
|---|---|---|
| Closed-source binaries | `libxml2.so.2` from a distro, `.node` addons, proprietary `.so` | No source, no build |
| Stale build artefacts | Reproducing a 2017 build is often impossible | Wrong toolchain, missing deps |
| Instrumenting-unfriendly builds | `#pragma optimize`, asm, heavy LTO, no PIE | Cannot be recompiled faithfully |

Existing binary-only approaches each pay a different tax:

- **AFL++ QEMU mode** — re-raises IR from x86 on every block. Fast enough,
  but a large constant overhead and it also has to translate.
- **DrDynamic / DynamoRIO / Intel PT** — dynamic binary instrumentation.
  Per-execution cost is high (orders of magnitude vs. native).
- **static rewriters** (objcopy, `r2`, Ghidra scripts) — they patch or dump
  code, but they do **not** produce *executable, feedback-ready* binaries.

**Goal.** Produce, from a stripped `ET_EXEC`/`ET_DYN` x86-64 ELF and *nothing
else*, a new ELF that

1. executes with the original observable behaviour (same exit code, same
   stdout/stderr, same file side effects),
2. maintains an exact edge-coverage map in a known-location byte table,
3. does so with **no runtime relocation, no runtime shim library, and no
   thread-local state**,
4. can be driven by any existing coverage-guided fuzzer (including AFL++).

---

## 2. Core idea

AFL indexes its bitmap as

```
idx = (prev_loc >> 1) ^ (cur_loc >> 1)          # 16 KiB map
```

`prev_loc` is carried in **TLS** between executions, which means (a) a TLS
access on every basic-block entry, and (b) a **lossy** mapping — distinct
edges can collide onto the same map slot.

suture removes both problems by assigning every edge a **static integer ID at
rewrite time**. Because the ID is known when the code is emitted, the
instrumentation needs no runtime state at all:

```
taken_stub:
    inc byte [rip + disp32]     ; disp32 → table[edge_id]
    jmp  rel32                  ; → original successor
```

Three properties follow directly:

- **Exact edges.** No hash, no collisions. See §7 for the measurement.
- **No TLS.** No `prev_loc`, no `mov` from an FS-segment register on the hot path.
- **No relocation.** `disp32` is computed once, offline, so the binary needs
  no runtime fixup pass and no shim `.so`.

### 2.1 Load-address independence (PIE safety)

All stubs and the entire coverage table live in **one** `PT_LOAD` segment that
suture appends to the file. Since a stub's counter operand is RIP-relative and
the target is inside the *same* mapping, the encoding is valid at *any* load
address. `ET_DYN`/PIE binaries therefore need no special handling.

> **Design constraint (intentional).** The table must not be placed in a
> separate segment. Two separate mappings would be independently randomised
> relative to each other and the constant `disp32` would break. Cost: the
> table and code share a page boundary and cannot be `madvise`d apart —
> accepted deliberately.

---

## 3. Pipeline

```
input ELF
  │
  ├─ [1] parse          suture-elf      program headers, PT_LOAD, DT_*, sections
  │
  ├─ [2] disasm + CFG   suture-ir       iced-x86 linear sweep → basic blocks
  │
  ├─ [3] edge IDs        suture-ir       per-block ID, per-branch edge IDs
  │
  ├─ [4] classify        suture-instr    patchable-in-place vs must-relocate
  │
  ├─ [5] emit            suture-instr    arena: stubs, relocated blocks, table
  │
  ├─ [6] rewrite file    suture-elf      new phdr table, shifted p_offset,
  │                                    new PT_LOAD, patched .init_array
  │
  └─► instrumented ELF  (still a normal ELF — runnable by anything)
```

---

## 4. Instrumentation scheme

### 4.1 The patchable case (fast path)

For a conditional branch with a **32-bit displacement** (`jcc rel32`, 6 bytes):

```asm
; ---- original -----------------------------------
        cmp    eax, 0
        je     .L1                 ; 0F 84 rel32        (6 bytes)
        <fallthrough>
.L1:

; ---- instrumented --------------------------------
        cmp    eax, 0
        jmp    .dispatch           ; E9 rel32          (5 bytes)
        nop                         ; 90                (1 byte pad)
.dispatch:
        je     .nt
        inc    byte [rip + d_taken]
        jmp    .L1
.nt:
        inc    byte [rip + d_nt]
        <fallthrough, patched in place>
```

The `dispatch` stub **re-tests the same condition on the still-live flags**,
so the flags are consumed exactly once and semantics are preserved for
`jb/ja/jl/jg/jz/...` alike. Straight-line `jmp rel32` is instrumented the same
way minus the re-test.

### 4.2 The hard case: 2-byte `jcc rel8` — partial block relocation

This is the central difficulty of the project and the reason generic
"binary patchers" fail. A `jcc rel8` occupies **2 bytes**; a `jmp rel32`
needs **5**. There is no in-place encoding.

suture's answer: **hybrid patching with opportunistic block relocation.**

1. Try to patch in place (the 6-byte case above, and `jmp/call rel32`).
2. If the block does not fit, **relocate the whole basic block** into the
   arena and place `jmp rel32` + `nop` padding at the original site.

Relocation is not a byte copy — it is a re-emit:

- every instruction is **decoded and re-encoded** with the assembler
  (iced-x86 encoder), because
  - **RIP-relative operands** (`mov rax, [rip+X]`, `lea`, `jmp [rip+X]`) must
    have `disp32` recomputed against the new address, and
  - **relocated immediates** (32-bit displacements inside the instruction)
    must be re-derived from the decoded operand, not copied.

An *undecodable* instruction is a hard error: suture refuses to emit a binary
it cannot fully re-encode, rather than silently producing something subtly
broken. `suture-verify` (§6) exists to back this up empirically.

> **Metric to report.** `blocks_relocated / blocks_total`. This number is the
> honest cost of the approach and belongs in the paper.

### 4.3 Indirect branches

`jmp rax` / `call [rbx+8]` are **skipped in v1** and recorded. Two reasons:
they are rare in leaf-heavy parsers, and instrumenting them correctly needs
either a shadow stack or target resolution, which is a v3 project. suture
reports an `indirect_branch_count` so the coverage gap is always visible
rather than silent.

### 4.4 Counter map

- `u8` per edge, sized `next_pow2(total_edges)`, capped at 64 KiB so the
  table stays L1/L2-resident. This is the single most important performance
  property of AFL-style feedback and it is not negotiable.
- Wrap-around at 255 is intentional and matches AFL's `count_class`
  bucketing: a saturating counter would need a compare+branch on the hot path.

---

## 5. ELF file surgery

Adding a `PT_LOAD` means adding a program header entry, and there is normally
**no spare room** in the program header table. suture therefore rebuilds the
file:

```
out = [ e_ident | e_type..e_phnum=N+1 | phdr[0..N] | pad → 0x1000 ]
      [ original bytes from old_phdr_end, shifted by delta ]
      [ pad → 0x1000 ][ arena bytes ][ new PT_LOAD phdr → arena ]
```

**Alignment invariant.** The kernel requires
`p_offset ≡ p_vaddr (mod p_align)`. `delta` is chosen as a multiple of
`0x1000` and every existing `p_offset` is shifted by `delta` while `p_vaddr` is
left untouched, so the congruence is preserved. The arena is placed at
`align_up(max_vaddr_end, 0x1000) + GUARD`, where `GUARD` (default 64 KiB)
keeps the mapping clear of ASan shadow regions and the heap.

The arena layout is:

```
┌──────────────────────┬─────────────┬──────────────────────┐
│ stubs + relocated    │  pad        │ u8 coverage table    │
│ blocks               │             │ [n_edges → next_pow2]│
└──────────────────────┴─────────────┴──────────────────────┘
                    ^ same PT_LOAD, so disp32 is fixed
```

**`DT_INIT` / `.init_array` patch.** suture appends a constructor entry to
`.init_array` pointing at a bootstrap stub in the arena. The bootstrap reads
the table address from a **fixed known vaddr** — no relocation needed — and
starts the forkserver. Because the arena vaddr is known statically, this
works for PIE for free.

---

## 6. Correctness: `suture-verify`

The strongest criticism of any binary rewriter is *"how do you know the
output still does what the input did?"*. suture answers with an executable
argument rather than a claim.

1. **Differential execution.** Over a large input corpus (seed corpora plus
   fuzzed inputs), run original and instrumented; require identical exit
   status, stdout, stderr, and return value.
2. **Trace equivalence.** Under `ptrace(PTRACE_SINGLESTEP)`, step both
   binaries and compare the resulting RIP sequences **modulo** arena
   addresses. Every difference must be explainable as an arena stub.
   Slow, but it is an exhaustive per-path check.
3. **Idempotence / stability.** Re-instrumenting an instrumented binary must
   detect the arena and refuse, or produce a correct second-generation
   binary. Silent double-instrumentation is a real failure mode here.

Any divergence is a bug in the rewriter, and the corpus that triggered it
becomes a permanent regression test.

---

## 7. What we claim, and how it is measured

Nothing in §2 is a claim without a number attached. See
[`EVALUATION.md`](./EVALUATION.md) for the full protocol.

| # | Claim | Metric | Baseline |
|---|---|---|---|
| C1 | Exact edges beat hashed edges | distinct edges reachable per input; AFL bitmap collision rate on the same corpus | AFL++ |
| C2 | Our binary is better to fuzz | **edges / CPU-hour** | AFL++ QEMU mode (binary-only), AFL++ native |
| C3 | Static rewriting is cheap enough | wall-clock instrumentation time per binary | `afl-llvm-*` compile time |
| C4 | The instrumentation is not the bottleneck | exec/s of instrumented vs. `afl-clang`-built binary | compile-time instrumented build |
| C5 | It finds things | unique crashes, crashes AFL++ misses | AFL++ |

The headline number is **C2**, and the honest framing is *edges per CPU-hour*,
not exec/s. Exec/s is a micro-benchmark; coverage per unit of compute is what
decides whether a real bug is ever found.

**Known limitation to state up front.** suture does not claim to beat
`afl-clang`-instrumented binaries on exec/s. A compiler-instrumented build has
no rewriting overhead and no code growth. Claiming otherwise would be
dishonest and would not survive review.

---

## 8. Threat model / safety

Instrumenting arbitrary binaries means running untrusted code. suture does not
attempt to sandbox anything. It is a research tool that must run inside a
disposable VM or container. This is stated in the README, not buried.

---

## 9. Project layout

```
crates/
  suture-elf          ELF parse + file rebuild + PT_LOAD injection
  suture-ir           Zydis wrapper, linear sweep, basic blocks, edge IDs
  suture-instrument   classification, stub emission, block relocation
  suture-coverage     map, signatures, AFL-compatible sharing
  suture-exec         forkserver client, shmem, timeouts, crash capture
  suture-mutate       mutators (havoc, dict, splice, custom)
  suture-fuzz         corpus, scheduling, queue, triage
  suture-verify       differential + trace-equivalence harness
  suture-cli          `suture-instrument`, `suture-fuzz`, `suture-verify`
tools/bench          benchmark protocol, plotting, corpus fetch
prototypes/py-suture  Python design-validation prototype (throwaway)
```
