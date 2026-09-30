# Suture — Technical Roadmap

Priority order below is **not** the order the features are most interesting to
build. It is the order that decides whether the project is worth anything.

The reason for the divergence is in §0.

---

## 0. The two numbers that decide everything

Measured on `busybox` 1.35.0 (static, musl, x86-64, 1.1 MB / 1.07 MB `.text`),
via `suture analyze` and `suture instrument`:

| | | verdict |
|---|---|---|
| AFL++ collision rate on real control flow | **89.4%** | the thesis is **confirmed** |
| output growth | **3.25×** (1.1 MB → 3.7 MB) | the thesis is **not yet practical** |

Read together, those say something precise:

> **The idea is right and the implementation is currently too expensive.**

A 3.25× larger binary is not a theoretical inconvenience. It is a binary that
costs 3.25× the disk, 3.25× the page-cache pressure, and — because the arena is
a second mapping the kernel must relocate — 3.25× the load time. Nobody ships
that. The collision rate being excellent is necessary but not sufficient.

So the roadmap is ordered by *"what makes this usable"*, not *"what is most fun
to implement"*.

---

## 1. P0 — Make the output affordable

**Target: growth ≤ 1.3×, relocation ≤ 20%** on Tier A binaries.
Without this, everything below is premature optimisation of something nobody
will use.

### 1a. Stop emitting a 19-byte dispatch stub per block

The single largest waste. Every relocated block currently costs
`body + 5 + 19` bytes, and the 19-byte stub is **almost never shared**, because
`StubKey` includes the target address and every block has a different one.

Fix: for a relocated block, the stub is redundant — emit the counter
increments *inline* at the end of the relocated body, then a single jump:

```
relocated:  [re-encoded body][inc taken][jmp target][inc not-taken]
```

Expected saving on busybox: ~600 KB of the 2.5 MB arena.

### 1b. Function-granularity relocation

Currently a block whose branch is a 2-byte `jcc rel8` must be moved, because
5 bytes cannot fit in 2. But the *enclosing function* is entered by a `call
rel32` — always 5 bytes. So:

- relocate the whole function once
- redirect the `call` (5 bytes available) instead of the `jcc`

This converts N relocated blocks into 1 relocated function. It is coarser, so
it over-instruments, but it collapses the relocation ratio structurally rather
than by micro-optimisation.

### 1c. Measure the ceiling honestly

Even after 1a and 1b, worst-case growth is bounded below by "the fraction of
functions containing a short branch", which is most of them. If the honest
floor is 1.8×, say so in the README rather than shipping 3.25× and hoping.

---

## 2. P0 — Fork server (gates every benchmark)

**Target: real exec/s.** The headline metric in
[`EVALUATION.md`](./EVALUATION.md) is *edges per CPU-hour*, and it is
unmeasurable without this. `suture-exec` currently returns an **empty** coverage
map rather than a fabricated one, and `suture-fuzz` labels every run
`plain-spawn` with a warning that its exec/s measures process creation, not the
fuzzer.

Implementation order:

1. Bootstrap in `.init_array` — **note this code path has never executed.** Every
   synthetic test fixture has `e_shoff = 0` and therefore no `.init_array`, so
   `patch_init_array` returns early in all 69 tests. The fork server's first
   task is to make that path run.
2. Arena is already at a **statically known vaddr**, so the bootstrap needs no
   relocation — this is the payoff for the whole design.
3. `fork()` per input, coverage map read from the child before `_exit`.
4. Then: shared testcase cache across workers, `jobs > 1`.

Until 2–4 land, **do not report exec/s from this project.**

---

## 3. P1 — Indirect branches (the largest coverage gap)

Measured: **40.9% of blocks on busybox** end in an indirect transfer, and
`DESIGN.md` §4.3 leaves them all uninstrumented. That is not a rounding error;
it is potentially the majority of the program's control flow.

Two approaches, in increasing honesty:

- **Target resolution** — statically resolve `jmp rax` when the register's
  value is provable. Cheap when it works, silently wrong when it does not.
- **Shadow stack** — record the taken targets at runtime. Correct, needs the
  fork server, costs a branch per indirect transfer.

Recommendation: do the measurement first. What fraction of the 40.9% are
switch tables with a statically enumerable target set? Those are the easy 90%
and they are the common case in parsers.

---

## 4. P1 — Complete the fuzzer

`suture-fuzz` has **0 tests** and a `jobs > 1` that returns an explicit error.
That is fine as a skeleton and not fine as a fuzzer.

1. Corpus scheduling worth the name — currently a round-robin. AFL's
   favoured/not-favoured split, or an age-based scheme.
2. Crash triage and dedup by stack hash.
3. Shared-memory testcase cache (this is what makes multi-core fuzzing scale,
   and it is why `Nyx` exists as a paper).
4. Timeout and RSS limits, recorded per run.

---

## 5. P2 — The benchmark, and only then the launch

`EVALUATION.md` §1 fixes the four baselines. Note the framing that must not
move: **B1 (`afl-clang-fast`) is the ceiling, B2 (AFL++ QEMU mode) is the
thing to beat.** Reporting a win against QEMU while ignoring B1's exec/s is the
failure mode this project has to avoid.

Order:
1. Fork server lands → exec/s is real
2. Tier A benchmarks, ≥5 repetitions, median + IQR
3. Fix the apples-to-apples problem: AFL reports hashed coverage, we report
   exact ids. Either compare on block sets, or build a B1 variant instrumented
   with *our* scheme at compile time so both speak the same map.
4. Publication. Not before.

---

## Explicitly out of scope

- **Non-x86-64.** The whole scheme is x86-64 encoding-specific. A second
  architecture doubles the relocation work for no new science.
- **Instrumenting ARM/Android.** Tempting (ModemPwn) but a different project.
- **Dynamic instrumentation.** SUTURE's claim is that *static* rewriting wins.
  Adding DBI would muddy the thesis rather than extend it.
