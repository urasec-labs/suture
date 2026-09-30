---
title: "Stitching Instrumentation Into a Binary You Can't Recompile"
subtitle: "How SUTURE gives closed-source x86-64 ELF binaries exact edge coverage — and what it cost"
tags: [security, binary-analysis, fuzzing, rust, x86-64, elf]
lang: en
---

# Stitching Instrumentation Into a Binary You Can't Recompile

*A working account of SUTURE: adding exact edge coverage to a stripped
x86-64 ELF with no source, no compiler, and no runtime shim — including the
three bugs that only appeared on a real 1.1 MB binary, and the 3.25× file
growth that the project has not yet solved.*

---

## The gap

Coverage-guided fuzzers get their feedback by *recompiling* the target.
`afl-clang`, `afl-llvm`, libFuzzer's `-fsanitize=fuzzer` — all of them need
source, a compiler, and a build that still works.

That excludes three large classes of target:

| Class | Example | Blocked by |
|---|---|---|
| Closed-source binaries | distro `libxml2.so.2`, proprietary `.so`, `.node` addons | no source |
| Stale artefacts | reproducing a 2017 build | wrong toolchain, missing deps |
| Instrumenting-hostile builds | `#pragma optimize`, inline asm, heavy LTO | rebuild is not faithful |

The binary-only alternatives each pay a different tax. **AFL++ QEMU mode**
re-raises IR from x86 on every block. **DrDynamic / DynamoRIO / Intel PT** are
dynamic binary instrumentation, costing orders of magnitude per execution. And
the static rewriters that do exist — `objcopy`, radare2 scripts, Ghidra
scripts — patch code, but they do not produce an *executable,
feedback-ready* binary.

SUTURE's goal: take an ELF and nothing else, and produce a new ELF that
behaves identically, reports exact edge coverage from a statically known
address, and needs no runtime cooperation.

---

## The idea

AFL indexes its coverage map like this:

```c
bitmap[(prev_loc >> 1) ^ (cur_loc >> 1)]     // 16 KiB
```

`prev_loc` is carried in **TLS**. That buys two problems at once:

1. A TLS load on every basic-block entry.
2. A **lossy hash** — distinct edges collide onto the same slot.

SUTURE removes both by assigning each edge a **static integer ID at rewrite
time**. The ID is known when the code is emitted, so the instrumentation
reduces to:

```asm
taken_stub:
    inc byte [rip + disp32]   ; → table[edge_id], displacement fixed offline
    jmp  rel32                ; → original successor
```

No hash, no TLS, no runtime relocation pass, no shim `.so`.

### Why the map must not live in a writable segment

The first design put every stub *and* the coverage table in one `R|W`
`PT_LOAD`. It is wrong, and obviously so in hindsight: a stub has to be
**executed**, the table has to be **written**, and on any system with NX
enforced a single writable segment faults the moment a stub runs. A single
executable one faults on the counter increment.

The fix is two segments — `R|X` for stubs, `R|W` for the table — which sounds
like it should break the whole scheme, because the stubs address the table.
It does not, and the reason is worth stating precisely:

> RIP-relative addressing is a signed 32-bit **relative** displacement. Both
> vaddrs are fixed at rewrite time, and neither is randomised independently of
> the other, so a displacement computed offline stays correct at any load
> address. PIE binaries just work.

The reasoning survived; only the conclusion about segment count was wrong.

---

## The hard part: `jcc rel8` does not fit

x86-64 variable-length instruction encoding is the entire difficulty.

| | bytes |
|---|---|
| `je rel8` | **2** |
| `je rel32` | **6** |
| `jmp rel32` — what we want to write | **5** |

A 2-byte `je rel8` cannot become a 5-byte jump in place. This is precisely why
generic "binary patchers" cannot produce a feedback-ready binary.

SUTURE's answer is **hybrid patching plus opportunistic basic-block
relocation**:

```
original block  --jmp rel32-->  arena copy  --jmp rel32-->  dispatch stub
```

The first hop is written at the **block's entry**, not over its terminator: the
bytes before the branch are the block's own body, and we are free to abandon
them because the copy lives in the arena. This requires the block to be at
least 5 bytes, which is what the 2-byte-with-empty-body case is about.

Relocation is not a `memcpy`. Every instruction must be **re-encoded**, because
a RIP-relative operand carries the displacement that made `[rip+d]` point
where it did in the *original* block; a raw byte copy computes the wrong
address at the new location. That requirement is the entire reason SUTURE uses
`iced-x86` — it ships an **encoder**, not just a decoder.

Blocks too short for even the entry jump are handled by redirecting them
through their *predecessor's* stub, which is already being redirected, so no
5-byte jump has to fit inside the short block at all.

---

## The measurement that decided whether this was worth building

The exact-edge claim is worth nothing if AFL's 16 KiB map does not actually
collide on real control flow. That is an empirical question, so it got measured.

`suture analyze` runs the sweep and the hash over a binary's real edge set — no
execution, no Linux, pure function of the bytes. On `busybox` 1.35.0 (static,
musl, 1.1 MB):

| | |
|---|---|
| distinct edges | 128,236 |
| AFL++ 16 KiB slots they touch | 13,643 of 16,384 |
| **AFL++ collision rate** | **89.4%** |
| SUTURE slots needed | 65,536 (4× AFL's fixed 16 KiB) |

**AFL++ merges 89.4% of distinct edges on real control flow.** The thesis is
not marginal, and the map being saturated rather than merely crowded is the
strong form of the result.

### A methodological trap worth naming

The obvious way to write this measurement is:

```rust
let edges: Vec<(u32, u32)> = (0..50_000).map(|i| (i, i + 1)).collect();
```

That fixture is **wrong**, and it was the first one written. For chained edges
`(i, i+1)`, AFL's index reduces to `i ^ (i+1)`, and `i ^ (i+1)` is always of the
form `2^k − 1`. So 50,000 distinct edges collapse into about **17 slots**, not
16 KiB.

A chained fixture would have *overstated* the collision rate — but the point is
that the number depends entirely on the edge distribution, and a plausible-looking
fixture measures the wrong function. The real generator is a fixed LCG, and the
chained behaviour is preserved as its own regression test with a comment
explaining why it is not the headline.

---

## Three bugs that only a real binary could find

Every test passed against hand-written 58-byte fixtures. All three of these
were invisible until `busybox` went through.

### 1. The sweep saw 3 blocks of a 1.1 MB binary

`sweep` discovered block leaders by calling `decode_run`, which stops at the
first control transfer. So it only ever saw the handful of instructions before
the first branch. busybox: **3 blocks, 0% collision rate.**

The worst part is not that it was wrong — it is that it made the thesis look
*validated for the wrong reason*. A 0% collision rate would have "confirmed"
exact edges, when in fact nothing had been measured.

The fix is a linear scan with resynchronisation: walk the whole segment, and
when an invalid byte appears, step over it and keep going, because real
`.text` interleaves code with jump tables and string literals.

### 2. Splitting at every `call` inflated everything

A `call` transfers control but it *returns*. For coverage purposes the next
instruction is reached by fallthrough, and AFL does not treat the call as an
edge. Splitting there produced a graph with several times too many nodes: 100k
blocks and 41.6% relocation, for edges the map cannot distinguish anyway.

The fix is to distinguish two things the code had conflated:
`is_control_transfer` (where a decode run ends) from `splits_block` (where a
coverage block begins). They must agree, and they did not.

### 3. Indirect jumps had **zero** edges

`build_edges` dispatched on the *mnemonic*: an unconditional branch was assumed
to be direct. `jmp rax` is unconditional but has no static target, so it fell
into an arm that pushed nothing. Every block ending in an indirect jump had
**no edges at all**, and was then skipped by the planner.

Those blocks were silently absent from the coverage map. No error, no warning —
just missing coverage, discovered later only because a block-accounting
assertion stopped adding up.

The invariant that now holds: **no block may have zero edges.**

Each of these has a regression test named after the failure, not the fix.

---

## What it costs, honestly

| | busybox 1.35.0 |
|---|---|
| relocation ratio | 51.6% |
| indirect branches not instrumented | 40.9% of blocks |
| output growth | **3.25×** (1.1 MB → 3.7 MB) |
| instrumentation time | 15.6 s |

**This is the part that decides whether the project is worth using.** A 3.25×
larger binary costs 3.25× the disk, 3.25× the page-cache pressure, and 3.25×
the load time. The idea is right and the implementation is currently too
expensive, and both halves of that sentence belong in the same breath.

The roadmap's first item is therefore not the fork server. It is making the
output affordable:

- **Stop emitting a 19-byte stub per block.** The stub is almost never shared,
  because its identity includes the target address and every block differs.
  For a relocated block the increments can be emitted inline, saving ~600 KB
  of the 2.5 MB arena.
- **Relocate per function, not per block.** A function is entered by a
  `call rel32` — always 5 bytes. Redirecting the call instead of the short
  `jcc` collapses N relocated blocks into one relocated function.

---

## What does not work yet

Stated plainly because a rewriter that hides its gaps is worse than one that
does not work.

**The coverage map cannot be read back.** A finished process's memory is gone,
so reading the map needs either a fork server (the target keeps the mapping
alive across executions) or a shared anonymous mapping the target writes into.

`SUTURE-exec` returns an **empty** map rather than a fabricated one.
`suture-fuzz` labels every run `plain-spawn` and warns that its exec/s numbers
measure process creation, not the fuzzer. **Do not report exec/s from the
current driver.**

Also not yet done: `ptrace` trace-equivalence verification, indirect-branch
instrumentation, and the AFL++ benchmark.

---

## Verification is not optional

The strongest objection to any binary rewriter is *"how do you know the output
still does what the input did?"*, and it deserves an executable answer rather
than a claim.

`suture verify` audits that **every byte of `.text` that changed lies inside a
range the instrumenter reported patching**. It needs no execution, so it runs
on any host, and it catches the failure mode that matters most: a patch that
landed one byte off. That produces a file which still loads, still passes the
loader's alignment congruence, and has quietly lost a live instruction.

The test suite deliberately corrupts a byte outside every reported range and
asserts that the audit notices.

A related bug: `orig_len` was originally a `u8`, so a block longer than 255
bytes produced a reported range *shorter* than what was actually overwritten —
and since the audit trusts those ranges, a truncated range is a false
all-clear on the very check meant to catch corruption.

---

## Tooling note: building on Windows without Visual Studio

Not the interesting part, but it cost a day and the answer is non-obvious.

rustup's `windows-gnu` toolchain ships `dlltool` but not the assembler
(`as.exe`) that `dlltool` shells out to, so it prints a `CreateProcess` error
and exits non-zero *after* writing a valid import library. rustc treats the
exit code as fatal, so the build dies on `windows-sys` — a crate with nothing
to do with this project.

The fix is upstream of that: turn off `clap`'s `color` and
`tracing-subscriber`'s `ansi`. Those are what pull in `windows-sys` at all,
and SUTURE's output is line-oriented and colourless by design. Plus a linker
path with no spaces in it, because `rustc` splits `-C linker=` on whitespace
and a space in `C:\Users\...` produces `multiple input filenames provided`.

The four core crates are cross-platform by design, so the rewriter — where all
the difficulty is — is developed and tested on Windows. The fuzzing driver is
not, and does not pretend to be.

---

## Where this goes

1. Make the output affordable (growth ≤ 1.3×).
2. Fork server, which gates every real benchmark.
3. Indirect branches — 40.9% of blocks is the largest coverage gap.
4. AFL++ benchmark: `afl-clang-fast` is the ceiling, **QEMU mode is the thing
   to beat**, and both numbers get reported.
5. Only then: publication.

The full reasoning, and why that order is not the order the features are most
interesting to build, is in [`docs/ROADMAP.md`](../docs/ROADMAP.md).

Source: [github.com/urasec-labs/suture](https://github.com/urasec-labs/suture)

---

*If you find a binary that breaks the rewriter, I would genuinely like to hear
about it — every bug in this post was found by trying it on a bigger binary
than the tests, and the next one is probably already sitting somewhere on your
disk.*
