# urasec-labs

Low-level security research. Tooling for binary analysis and fuzzing.

---

## [SUTURE](https://github.com/urasec-labs/suture)

### Static Rewriting & Binary Instrumentation Framework

**Source-free exact edge coverage for x86-64 ELF binaries, by static rewriting.**

`Rust · x86-64 assembly · ELF architecture · binary rewriting · fuzzing · AFL++`

Coverage-guided fuzzers get their feedback by recompiling the target, which
excludes closed-source binaries, un-reproducible builds, and
instrumenting-hostile code. SUTURE takes an ELF and nothing else — no source,
no compiler, no build script, no runtime shim — and produces a new ELF that
reports **exact** edge coverage from a statically known address.

Where AFL++ indexes its map as `bitmap[(prev>>1) ^ (cur>>1)]` and carries
`prev` in TLS — a lossy hash costing a TLS load per basic block — SUTURE
assigns each edge a static integer ID at rewrite time. No hash, no TLS, no
relocation pass.

On `busybox` 1.35.0 (static, 1.1 MB), AFL++ merges **89.4%** of distinct edges
on real control flow. The cost is also stated: **3.25×** output growth, which is
the project's main unsolved problem.

```
suture analyze    <binary>                     # is it worth instrumenting?
suture instrument <in.elf> <out.elf> [--json]   # rewrite it
suture verify     <orig> <inst> <input>...     # prove it still behaves the same
```

[Repository](https://github.com/urasec-labs/suture) ·
[Deep dive (EN)](https://github.com/urasec-labs/suture/blob/main/blog/suture-deep-dive.en.md) ·
[Deep dive (TR)](https://github.com/urasec-labs/suture/blob/main/blog/suture-deep-dive.tr.md)

**Status:** research prototype. The rewriter is complete and measured on a real
binary; the fuzzing runtime is not. Do not report exec/s from the current
driver — it measures process creation, not the fuzzer.

**⚠️** SUTURE runs arbitrary binaries. It is not a sandbox. Use a disposable VM
or container.
