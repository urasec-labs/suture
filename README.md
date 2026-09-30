<div align="center">

# SUTURE

### Static Rewriting & Binary Instrumentation Framework

**Source-free exact edge coverage for x86-64 ELF binaries, by static rewriting.**

`Rust · x86-64 assembly · ELF architecture · binary rewriting · fuzzing · AFL++`

[🇹🇷 Türkçe](#türkçe) · [🇬🇧 English](#english) · [📄 Deep dive EN](blog/suture-deep-dive.en.md) · [📄 Deep dive TR](blog/suture-deep-dive.tr.md)

`status: research prototype — rewriter complete and measured on a real binary; fuzzing runtime not started`

</div>

---

## What this is, in one line

A binary rewriter that gives **closed-source** x86-64 ELF binaries exact edge
coverage — with no source code, no compiler, and no runtime shim — by
statically re-encoding instructions and relocating basic blocks.

## The two numbers

`busybox` 1.35.0 (static, musl, 1.1 MB). Both are re-measured in CI on every push,
so they cannot silently drift away from what the code does.

| claim | measured | |
|---|---|---|
| AFL++ merges distinct edges on real control flow | **89.4%** | ✅ confirmed |
| output growth | **3.25×** | ❌ **unsolved** |

They cancel into a single honest sentence:

> **The idea is right, and the implementation is currently too expensive.**

That is why [`docs/ROADMAP.md`](docs/ROADMAP.md) starts with making the output
affordable, not with the fork server.

| | busybox 1.35.0 |
|---|---|
| distinct edges found | 128,236 |
| AFL++ 16 KiB slots they touch | 13,643 of 16,384 |
| SUTURE slots needed | 65,536 (4× AFL's fixed 16 KiB) |
| blocks | 85,783 |
| relocation ratio | 51.6% |
| indirect branches not instrumented | 40.9% |
| instrumentation time | 15.6 s (release) |

## Why it exists

Coverage-guided fuzzers get their feedback by *recompiling* the target with
`afl-clang` or libFuzzer. That excludes three large classes:

| Class | Example | Blocked by |
|---|---|---|
| Closed-source binaries | distro `libxml2.so.2`, proprietary `.so`, `.node` | no source |
| Stale artefacts | reproducing a 2017 build | wrong toolchain |
| Instrumenting-hostile builds | `#pragma optimize`, inline asm, heavy LTO | rebuild is not faithful |

Existing binary-only tools each pay a different tax: **AFL++ QEMU mode**
re-raises IR from x86 per block; **DrDynamic / DynamoRIO / Intel PT** are DBI and
cost orders of magnitude per execution; and the static rewriters that do exist
(`objcopy`, radare2 scripts, Ghidra scripts) patch code without producing an
**executable, feedback-ready** binary.

SUTURE takes an ELF and nothing else.

## The core idea

AFL indexes its map as `bitmap[(prev>>1) ^ (cur>>1)]` and carries `prev` in
**TLS** — a lossy hash, costing a TLS load on every basic block. SUTURE assigns
each edge a **static integer ID at rewrite time**:

```asm
taken_stub:
    inc byte [rip + disp32]   ; → table[edge_id], displacement fixed offline
    jmp  rel32                ; → original successor
```

No hash, no TLS, no runtime relocation pass, no shim.

Stubs live in an `R|X` segment and the table in a separate `R|W` one — a stub
must be **executed** and the map must be **written**, and under NX one segment
cannot be both. The two need not be adjacent: RIP-relative addressing is a
signed 32-bit *relative* displacement, and with both addresses fixed at rewrite
time the encoding stays correct at any load address. **PIE binaries just work.**

The central difficulty: `jcc rel8` is **2** bytes, `jmp rel32` is **5**, so there
is no in-place encoding. SUTURE solves it with **hybrid patching plus
opportunistic basic-block relocation** into an arena, re-encoding RIP-relative
operands and relocated immediates. See [`docs/DESIGN.md` §4.2](docs/DESIGN.md).

## Three commands

```bash
suture analyze    <binary>                     # is it worth instrumenting?
suture instrument <in.elf> <out.elf> [--json]   # rewrite it
suture verify     <orig> <inst> <input>...     # prove it still behaves the same
```

`analyze` needs no execution and no Linux — a pure function of the bytes, so the
thesis can be checked on any machine in a second.

## Known limitations

Stated up front, because a rewriter that hides its gaps is worse than one that
does not work.

| Limitation | Cost on busybox |
|---|---|
| Output growth | **3.25×** — the main unsolved problem |
| Relocation ratio | 51.6% of blocks |
| Indirect branches not instrumented | 40.9% of blocks |
| **Coverage map cannot be read back** | **the fuzzer does not work** |

The last one is the blocker: a finished process's memory is gone, so reading the
map needs either a fork server or a shared anonymous mapping the target writes
into. `suture-exec` returns an **empty** map rather than a fabricated one, and
`suture-fuzz` labels every run `plain-spawn` with a warning that its exec/s
measures process creation, not the fuzzer. **Do not report exec/s from the
current driver.**

## Correctness is a separate crate, not an extra

The strongest objection to any binary rewriter is *"how do you know the output
still does what the input did?"*, so `suture verify` answers it executably:
every byte of `.text` that changed must lie inside a range the instrumenter
**reported patching**. It needs no execution, so it runs anywhere, and it catches
the failure mode that matters most — a patch that landed one byte off, which
yields a file that still loads, still passes the loader's alignment congruence,
and has quietly lost a live instruction.

## Status

69 unit tests, zero warnings, CI green.

| Component | State | Tests |
|---|---|---|
| `suture-elf` — parse, phdr rebuild, two-segment injection | **done** | 8 |
| `suture-ir` — sweep, basic blocks, edge-id assignment | **done** | 20 |
| `suture-coverage` — map, signatures, AFL collision measurement | **done** | 11 |
| `suture-instrument` — arena, stubs, relocation, pipeline, analyze | **done** | 14 |
| `suture-verify` — structural patch audit | **done** | 4 |
| `suture-mutate` — bit/byte, interesting-value, splice mutators | **done** | 10 |
| `suture-exec` — target execution | stub | 2 |
| `suture-fuzz` — corpus loop | **partial** | 0 |
| Fork server (fast execution backend) | **not started** | — |
| `ptrace` trace-equivalence check | **not started** | — |
| AFL++ benchmark (edges per CPU-hour) | **not started** | — |

## Building

Linux x86-64, Rust 1.75+:

```bash
sudo apt install build-essential
cargo test --workspace
cargo run -p suture-cli -- analyze <binary>
```

The four core crates are cross-platform and test on Windows without a Linux
host — see [`docs/BUILDING-ON-WINDOWS.md`](docs/BUILDING-ON-WINDOWS.md), which
also documents the two non-obvious rustup/Windows problems you will hit.

## ⚠️ Safety

SUTURE runs arbitrary binaries. It is **not** a sandbox. Run it inside a
disposable VM or container.

---

## Türkçe

### Tek cümlede

Kaynak kodu, derleyicisi ve runtime shim'i olmayan **kapalı kaynak** x86-64
ELF binary'lerine, talimatları statik olarak yeniden kodlayıp basic block'ları
taşıyarak tam kenar kapsama (exact edge coverage) kazandıran bir binary
rewriter.

### İki sayı

`busybox` 1.35.0 (static, musl, 1.1 MB) üzerinde; CI her push'ta yeniden ölçer:

| iddia | ölçülen | |
|---|---|---|
| AFL++ gerçek control flow'da benzersiz edge'leri birleştiriyor | **%89.4** | ✅ doğrulandı |
| çıktı büyümesi | **3.25×** | ❌ **çözülmedi** |

İkisi tek bir dürüst cümleye indirgeniyor: **fikir doğru, uygulama şu an pahalı.**
Roadmap'ın ilk maddesi bu yüzden fork server değil, çıktıyı ucuzlatmak.

### Neden var

Coverage-guided fuzzer'lar geri bildirimi hedefi yeniden derleyerek alır. Bu,
kapalı kaynak binary'leri, üretilemeyen build'leri ve enstrümantasyona dirençli
kodu dışarıda bırakır. Mevcut binary-only araçlar ya blok başına IR kaldırıyor
(QEMU mode), ya yürütme başına büyüklüklerinde maliyet getiriyor (DBI), ya da
**çalıştırılabilir ve geri bildirim alınabilir** binary üretmeden kodu yamıyor.

### Çekirdek fikir

AFL map'i `bitmap[(prev>>1) ^ (cur>>1)]` şeklinde indeksler ve `prev`'i **TLS**'te
taşır — kayıplı bir hash, her basic block'da TLS yüklemesi. SUTURE her kenara
**rewrite anında statik bir tamsayı ID** atar:

```asm
taken_stub:
    inc byte [rip + disp32]   ; → table[edge_id], displacement çevrimdışı sabit
    jmp  rel32                ; → orijinal successor
```

Hash yok, TLS yok, runtime relocation geçişi yok, shim yok.

Stub'lar `R|X`, tablo ayrı bir `R|W` segmentte: stub **çalıştırılmalı**, tablo
**yazılmalı**; NX altında tek segment ikisini birden yapamaz. İkisi bitişik olmak
zorunda değil — RIP-relative adresleme göreli bir displacement'tır ve iki adres de
rewrite anında sabitlendiği için PIE binary'ler kendiliğinden çalışır.

Zor kısım: `jcc rel8` **2** bayt, `jmp rel32` **5** bayt; yerine yazılamaz.
**Hibrit patch + fırsatçı basic-block relocation** ile çözülüyor: RIP-relative
operand'lar ve taşınan immediate'lar yeniden kodlanarak arena'ya kopyalanıyor.

### Bilinen sınırlar

| Sınır | busybox üzerindeki maliyeti |
|---|---|
| Çıktı büyümesi | **3.25×** — çözülmemiş ana problem |
| Relocation oranı | blokların %51.6'sı |
| Enstrümanlanmayan dolaylı dallar | blokların %40.9'u |
| **Coverage map geri okunamıyor** | **fuzzer çalışmıyor** |

Sonuncusu engel: bitmiş bir sürecin belleği gittiği için haritayı okumak fork
server gerektirir. `suture-exec` uydurma map yerine **boş** map döndürüyor ve
`suture-fuzz` her koşuyu `plain-spawn` etiketleyip exec/s'nin süreç oluşturmayı
ölçtüğünü uyarıyor. **Mevcut sürücüden exec/s raporlama.**

### Doğrulama

`suture verify` ayrı bir crate: değişen **her** `.text` baytı, enstrümanın
**raporladığı** patch aralığının içinde olmak zorunda. Execution gerektirmediği
için her yerde çalışır ve bir bayt kaymış patch'i yakalar — ki bu, dosyayı hâlâ
yüklenebilir, hâlâ hizalama kongrüansını geçer, ama sessizce canlı bir talimat
kaybetmiş bırakan hata sınıfıdır.

### Derleme

Linux x86-64, Rust 1.75+. Çekirdek dört crate platform-bağımsızdır ve Windows'ta
da test edilir — bkz. [`docs/BUILDING-ON-WINDOWS.md`](docs/BUILDING-ON-WINDOWS.md).

### ⚠️ Güvenlik

SUTURE keyfi binary'ler çalıştırır. **Sandbox değildir.** Yalnızca tekrar
kullanılabilir bir VM veya container içinde çalıştırılmalıdır.

---

## License

MIT · [LICENSE](LICENSE)
