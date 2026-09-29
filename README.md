<div align="center">

# suture

**Source-free edge-coverage instrumentation for x86-64 ELF binaries, by static rewriting.**

[🇹🇷 Türkçe](#türkçe) · [🇬🇧 English](#english)

`status: research prototype — design phase`

</div>

---

## English

### What it does

Coverage-guided fuzzers normally get their feedback by *recompiling* the
target with `afl-clang` or libFuzzer. That is impossible for closed-source
binaries, un-reproducible builds, and instrumenting-unfriendly code.

suture takes an x86-64 ELF and **nothing else** — no source, no compiler, no
build script — and produces a new ELF that:

- behaves identically to the original (same exit code, same output),
- maintains **exact edge coverage** in a byte table at a known address,
- requires **no runtime shim, no relocation pass, no thread-local state**,
- can be driven by any existing coverage-guided fuzzer, AFL++ included.

### Why it is different from AFL's

AFL indexes its map as `bitmap[(prev>>1) ^ (cur>>1)]` and carries `prev` in
**TLS**. That is a lossy hash, and it costs a TLS load on every basic block.

suture assigns each edge a **static integer ID at rewrite time**, so the
instrumentation is just:

```asm
taken_stub:
    inc byte [rip + disp32]   ; → table[edge_id], displacement fixed offline
    jmp  rel32                ; → original successor
```

All stubs and the table live in **one** appended `PT_LOAD`, so the
RIP-relative displacement stays valid at any load address — which is why PIE
binaries need no special handling.

The central technical problem is that `jcc rel8` occupies 2 bytes and
`jmp rel32` needs 5. suture solves it with **hybrid patching plus opportunistic
basic-block relocation** (re-emitting blocks into the arena, re-encoding
RIP-relative operands and relocated immediates). See
[`docs/DESIGN.md` §4.2](docs/DESIGN.md).

### Claims, and how they are measured

Stated in advance in [`docs/EVALUATION.md` §5](docs/EVALUATION.md), so the
results cannot be rationalised after the fact.

| Claim | Metric | Baseline we must beat |
|---|---|---|
| Exact edges > hashed edges | AFL bitmap collision rate, edges/input | AFL++ |
| Better to fuzz | **edges / CPU-hour** | AFL++ QEMU mode |
| Rewriting is cheap | instrumentation wall-clock per binary | `afl-llvm` compile time |
| Overhead is understood | exec/s vs compile-time-instrumented build | `afl-clang-fast` |
| It finds things | unique crashes, crashes AFL++ misses | AFL++ |

**We do not claim to beat `afl-clang` on exec/s.** A compile-time-instrumented
build has no rewriting overhead and no code growth. The claim is narrower and
defensible: *binary-only fuzzing at a fraction of QEMU mode's per-execution
cost.*

### Status

63 unit tests pass; the workspace builds with zero warnings.

| Component | State | Tests |
|---|---|---|
| `suture-elf` — parse, phdr rebuild, two-segment injection | **done** | 8 |
| `suture-ir` — linear sweep, basic blocks, edge-id assignment | **done** | 14 |
| `suture-coverage` — map, signatures, AFL collision measurement | **done** | 11 |
| `suture-instrument` — arena, dispatch stubs, relocation, pipeline | **done** | 14 |
| `suture-verify` — structural patch audit | **done** | 4 |
| `suture-mutate` — bit/byte, interesting-value, splice mutators | **done** | 10 |
| `suture-exec` — target execution | stub | 2 |
| `suture-fuzz` — corpus loop | **partial** | 0 |
| Fork server (fast execution backend) | **not started** | — |
| `ptrace` trace-equivalence check | **not started** | — |
| Benchmarks vs. AFL++ | **not started** | — |

**What works today.** `suture instrument` rewrites a real x86-64 ELF: it
disassembles `.text`, assigns dense edge ids, relocates blocks whose branch is
too short to hold a `jmp rel32`, and appends an R|X stub arena plus an R|W
coverage table. On the bundled smoke fixture it converts a 2-byte `je rel8`
block into a 5-byte jump into the arena and leaves every other byte untouched.
`suture verify` then proves that only the ranges suture reported were modified.

**What does not work yet.** The coverage map cannot be *read back* from a
finished process, because the process's memory is gone once it exits. Reading it
requires either a fork server (the target keeps the mapping alive across
executions) or a shared anonymous mapping the target writes into. `suture-exec`
returns an empty map rather than a fabricated one, and `suture-fuzz` labels every
run `plain-spawn` and warns that its exec/s numbers measure process creation
rather than the fuzzer. **Do not report exec/s from the current driver.**

### Requirements

Linux x86-64, Rust 1.75+. The four core crates are cross-platform and test on
Windows — see [`docs/BUILDING-ON-WINDOWS.md`](docs/BUILDING-ON-WINDOWS.md).

### ⚠️ Safety

suture runs arbitrary binaries. It is **not** a sandbox. Run it only inside a
disposable VM or container.

---

## Türkçe

### Ne yapıyor

Coverage-guided fuzzer'lar geri bildirimi hedefi **yeniden derleyerek**
alır (`afl-clang`, libFuzzer). Bu, kapalı kaynaklı binary'ler, yeniden
üretilemeyen build'ler ve enstrümantasyona uygun olmayan kod için imkânsızdır.

suture x86-64 ELF'i alır — kaynak kod, derleyici, build script **hiçbiri
gerekmez** — ve şunu üretir:

- orijinaliyle **aynı davranış** (aynı exit code, aynı çıktı),
- **tam (exact) edge coverage**'i bilinen adreste bir byte tablosunda,
- **runtime shim, relocation geçişi, thread-local durum olmadan**,
- mevcut her coverage-guided fuzzer tarafından sürülebilir — AFL++ dahil.

### AFL'den farkı

AFL map'i `bitmap[(prev>>1) ^ (cur>>1)]` şeklinde indeksler ve `prev`'i
**TLS**'te taşır. Bu kayıplı (lossy) bir hash'tir ve her basic block girişinde
TLS yüklemesine mal olur.

suture her kenara **rewrite anında statik bir tamsayı ID** atar:

```asm
taken_stub:
    inc byte [rip + disp32]   ; → table[edge_id], displacement çevrimdışı sabit
    jmp  rel32                ; → orijinal successor
```

Tüm stub'lar ve tablo **tek bir eklenen `PT_LOAD`** içindedir; RIP-relative
displacement her yükleme adresinde geçerli kalır — bu yüzden PIE binary'lere
özel işlem gerekmez.

Asıl teknik zorluk şu: `jcc rel8` **2** bayt yer kaplar, `jmp rel32` **5**
bayt ister. suture bunu **hibrit patch + fırsatçı basic-block relocation** ile
çözer: blokları arena'ya yeniden yazar, RIP-relative operand'ları ve
taşınan immediate'ları yeniden kodlar. Detay:
[`docs/DESIGN.md` §4.2](docs/DESIGN.md).

### İddialar ve nasıl ölçülecekleri

Sonuçlar sonradan gerekçelendirilmesin diye
[`docs/EVALUATION.md` §5](docs/EVALUATION.md) içinde **önceden** yazıldı.

| İddia | Metrik | Geçilmesi gereken rakip |
|---|---|---|
| Tam kenar > hash'lenmiş kenar | AFL bitmap çakışma oranı, input başına kenar | AFL++ |
| Daha iyi fuzz'lanabilir | **CPU-saati başına kapsanan kenar** | AFL++ QEMU mode |
| Rewrite ucuz | binary başına enstrümantasyon süresi | `afl-llvm` derleme süresi |
| Overhead anlaşıldı | exec/s, derleme-zamanı enstrümanl build'e karşı | `afl-clang-fast` |
| Gerçekten buluyor | benzersiz crash, AFL++'in bulamadıkları | AFL++ |

**`afl-clang`'i exec/s'de geçtiğimizi iddia etmiyoruz.** Derleme-zamanı
enstrümantasyonunda rewrite overhead'i ve kod büyümesi yoktur. İddiamız daha
dar ve savunulabilir: *QEMU mode'un yürütme başına maliyetinin küçük bir
kesriyle binary-only fuzzing.*

### Durum

63 birim testi geçiyor, workspace sıfır uyarıyla derleniyor.

| Bileşen | Durum | Test |
|---|---|---|
| `suture-elf` — parse, phdr rebuild, iki segment ekleme | **tamam** | 8 |
| `suture-ir` — linear sweep, basic block, edge-id ataması | **tamam** | 14 |
| `suture-coverage` — map, imza, AFL çakışma ölçümü | **tamam** | 11 |
| `suture-instrument` — arena, dispatch stub, relocation, pipeline | **tamam** | 14 |
| `suture-verify` — yapısal patch denetimi | **tamam** | 4 |
| `suture-mutate` — bit/byte, interesting-value, splice | **tamam** | 10 |
| `suture-exec` — hedef çalıştırma | iskelet | 2 |
| `suture-fuzz` — corpus döngüsü | **kısmi** | 0 |
| Fork server (hızlı yürütme backend'i) | **başlanmadı** | — |
| `ptrace` trace-equivalence kontrolü | **başlanmadı** | — |
| AFL++'e karşı benchmark | **başlanmadı** | — |

**Bugün çalışan.** `suture instrument` gerçek bir x86-64 ELF'i yeniden yazıyor:
`.text`'i disassemble ediyor, yoğun edge id atıyor, dalı `jmp rel32`'ye sığmayan
blokları arena'ya taşıyor, sonuna R|X stub arenası + R|W coverage tablosu
ekliyor. Smoke fixture'da 2-byte `je rel8` bloğunu arena'ya 5-byte jump ile
çeviriyor ve diğer tüm baytları olduğu gibi bırakıyor. `suture verify` sonra
suture'ın raporladığı aralıkların dışında hiçbir baytın değişmediğini kanıtlıyor.

**Henüz çalışmayan.** Coverage tablosu bitmiş bir süreçten **okunamıyor**,
çünkü süreç sonlandığında belleği kayboluyor. Okumak için ya fork server
(hedef eşlemeyi yürütmeler boyunca canlı tutar) ya da hedefin yazdığı paylaşımlı
anonim eşleme gerekiyor. `suture-exec` uydurma map yerine boş map döndürüyor ve
`suture-fuzz` her koşuyu `plain-spawn` olarak etiketleyip exec/s sayılarının
fuzzer'ı değil süreç oluşturmayı ölçtüğünü uyarıyor. **Mevcut sürücüden exec/s
raporlama.**

### Gereksinimler

Linux x86-64, Rust 1.75+. Çekirdek dört crate platform-bağımsız ve Windows'ta
da test ediliyor — bkz. [`docs/BUILDING-ON-WINDOWS.md`](docs/BUILDING-ON-WINDOWS.md).

### ⚠️ Güvenlik

suture keyfi binary'ler çalıştırır. **Sandbox değildir.** Yalnızca tekrar
kullanılabilir bir VM veya container içinde çalıştırılmalıdır.

---

## License

MIT OR Apache-2.0
