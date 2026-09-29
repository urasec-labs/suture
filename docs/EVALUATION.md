# Evaluation protocol

Status: draft

The claim under test is **"static rewriting of a source-free ELF yields a
binary that is better to fuzz than existing binary-only instrumentation"**.
Everything below exists to make that claim falsifiable.

---

## 1. Baselines

| ID | Tool | Why it is in the comparison |
|---|---|---|
| B1 | `afl-clang-fast` / `afl-llvm-lto` (AFL++ native) | Upper bound. Best possible instrumentation, requires source + build. **Not a target to beat on exec/s.** |
| B2 | **AFL++ QEMU mode** | The honest binary-only competitor. Same corpus, same seeds, same machine. |
| B3 | AFL++ with DrDynamic | Second binary-only data point. |
| B4 | Original binary, un-instrumented | Control: proves instrumentation is what produces the coverage. |

Rule: **B1 is the reference ceiling; B2 is the thing we must beat.** Reporting
a win against B2 while ignoring B1's exec/s is the failure mode to avoid.

## 2. Benchmark set

Targets must satisfy: x86-64 ELF, known historical crash, >20 KiB of
`.text`, no source rebuild needed for the comparison.

Tier A — with a documented CVE / OSS-Fuzz reproducer:
`libxml2`, `libpng`, `openssl` (subset), `busybox`, `xz`, `pcre2`, `json-c`,
`curl` (select harnesses), `sqlite3`

Tier B — AFL++ public benchmark set, used for a second, independent check so
the result is not an artefact of how Tier A was chosen.

Each target needs: build recipe, seed corpus, ground-truth crashing input.
`tools/bench/fetch.py` pulls and pins all of these by hash, so a result can be
reproduced months later.

## 3. Metrics

| Metric | Definition | Why |
|---|---|---|
| **edges / CPU-hour** | unique edge IDs hit across the whole run | primary metric |
| exec/s | executions per second, single core, forkserver on | measures instrumentation overhead (C4) |
| code growth | `size(instrumented) / size(original)` | cost of the scheme |
| instrumentation time | wall-clock, per binary | C3; if this is minutes, the tool is unusable in a pipeline |
| blocks relocated | §4.2 metric | honest cost of the hybrid scheme |
| unique crashes | deduped by stack hash | C5 |
| AFL collision rate | fraction of distinct edges mapping to the same 16 KiB slot, on the *same* corpus | quantifies the C1 claim directly |
| peak RSS | max resident set of instrumented target | catches pathological relocation |

## 4. Fairness controls

These are the things that make fuzzing comparisons worthless when omitted.

1. **Identical seed corpus** and identical seed count, per target.
2. **Identical core count and identical wall-clock budget**, run concurrently
   on the same machine to cancel thermal/noise drift. Run each configuration
   in **≥5 repetitions** and report median + IQR, not a single run.
3. **Same forkserver, same timeout (1000 ms), same RSS limit (2 GB)** for
   every fuzzer in the comparison.
4. **Coverage compared on equal footing.** B1/B2 report AFL-style hashed
   coverage. To compare suture's edge IDs against them we must map both to a
   common space. Two options, both to be reported:
   - map every edge to its **source block address** (available to all tools
     that report block coverage), and compare set-of-blocks; or
   - have B1 emit a suture-compatible map, by instrumenting with our own
     scheme at compile time instead of AFL's.
   Reporting only the first would silently flatter suture; the second is the
   correct apples-to-apples number and is worth the extra work.
5. **Record the full corpus** of each run so runs are inspectable, and
   publish a subset of interesting inputs (IP-permissive licensing permitting).

## 5. Expected results, stated in advance

Stating predictions before running them is what separates a result from a
rationalisation. Recorded here, before data:

- **C4 (exec/s): suture will lose to B1.** Expect roughly 1.3–2.5× slower than
  a compile-time-instrumented build on a tight loop, from code growth and
  extra taken branches per instrumented conditional. If suture *wins* here,
  the instrumentation is probably being optimised out — investigate before
  celebrating.
- **C1: AFL collision rate will be low (~1–5%) on a small corpus and will
  grow as the corpus does**, because collisions scale with the number of live
  edges. This is the number most likely to be *smaller than hoped*, and it
  should be reported as measured.
- **C2 is genuinely uncertain.** Competing with QEMU mode requires suture to
  win on scheduling and edge fidelity faster than it loses on exec/s. Realistic
  target: **parity to 1.5× on Tier A**, with the win concentrated on
  compute-heavy targets. If suture only ties, the honest result is still
  publishable — "static rewriting reaches QEMU-mode coverage at a fraction of
  the per-exec cost" is a real finding.

## 6. Correctness gate

No coverage number is reported unless `suture-verify` passes on that target:
identical exit status and output over the whole seed corpus plus every
fuzzed input, and a trace-equivalence pass on a bounded sample.

## 7. Reproducibility

- Every run writes a JSON result: tool, target, git SHA, seed corpus hash,
  core count, duration, all metrics.
- `tools/bench/plot.py` produces the figures from those JSONs.
- All results in the README/paper are regenerated by `make bench` on a
  documented machine spec.
