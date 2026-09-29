# Windows: building suture without Visual Studio

suture is a Linux tool, but its core crates (`suture-elf`, `suture-ir`,
`suture-coverage`, `suture-instrument`) are pure byte manipulation and are
deliberately kept cross-platform, so they can be developed and unit-tested on
Windows without a Linux machine or WSL.

## The problem

`rustup` installs two Windows toolchains:

| Toolchain | Linker | Works here? |
|---|---|---|
| `*-msvc` | `link.exe` from Visual Studio | No — no Visual Studio installed |
| `*-gnu` | MinGW `ld` | Partly — rustup's MinGW is incomplete |

The `msvc` toolchain is unusable without Build Tools. The `gnu` toolchain gets
further but hits two problems, both environmental rather than suture's fault.

### 1. `dlltool` needs an assembler that rustup does not ship

`windows-sys` (pulled in only by `clap` and `tracing-subscriber`) needs import
libraries. rustc invokes `dlltool` to build them, but rustup's bundle omits
`as.exe`, so `dlltool` prints a `CreateProcess` error and exits non-zero — even
though it has already written a valid import library. rustc treats the non-zero
exit as fatal and the build dies on a crate unrelated to suture.

suture avoids this at the source: `Cargo.toml` turns off `clap`'s `color` and
`tracing-subscriber`'s `ansi` features, which is what pulls in `windows-sys` in
the first place. suture's output is line-oriented and colourless by design, so
nothing is lost — and the whole workspace builds with no MinGW install, which
also keeps CI simple.

### 2. A space in the toolchain path breaks `rustc`

If the user profile contains a space (`C:\Users\Uras AKAS\...`), passing the
linker via `RUSTFLAGS=-C linker=<path>` fails with:

```
error: multiple input filenames provided (first two filenames are `-` and `AKAS\...`)
```

`rustc` splits the flag on whitespace rather than quoting it.

## The working setup

Use the `gnu` toolchain, with `rust-lld` as the linker, and with the bundled
toolchain files copied to a **space-free** path:

```powershell
# 1. Install the gnu toolchain (the msvc one is already present)
rustup toolchain install stable-x86_64-pc-windows-gnu --profile minimal

# 2. Copy the linker and the self-contained libs somewhere without spaces
$shim = "$env:TEMP\mingw"
New-Item -ItemType Directory -Force -Path $shim | Out-Null
$gnu = "$env:USERPROFILE\.rustup\toolchains\stable-x86_64-pc-windows-gnu"
Copy-Item "$gnu\lib\rustlib\x86_64-pc-windows-gnu\bin\self-contained\*" $shim -Force
Copy-Item "$gnu\lib\rustlib\x86_64-pc-windows-gnu\bin\rust-lld.exe" $shim -Force

# 3. Point the build at it
$env:RUSTUP_TOOLCHAIN = "stable-x86_64-pc-windows-gnu"
$lld = "$shim\rust-lld.exe"
$env:RUSTFLAGS = "-C linker=$lld -C link-self-contained=yes"
$env:PATH = "$shim;$env:USERPROFILE\.cargo\bin;$env:PATH"

cargo test --workspace
cargo run -p suture-cli -- instrument <in.elf> <out.elf>
```

`link-self-contained=yes` is what makes `crt2.o`, `libkernel32.a`,
`libmingw32.a` and friends visible; without it the linker reports
`cannot find crt2.o`.

## What is and is not testable on Windows

| Crate | Windows | Why |
|---|---|---|
| `suture-elf` | full | parses and rewrites ELF files; no execution needed |
| `suture-ir` | full | pure disassembly |
| `suture-coverage` | full | pure map arithmetic |
| `suture-instrument` | full | the rewriter itself, including relocation |
| `suture-verify` | **structural audit only** | differential *execution* needs Linux |
| `suture-exec` | minimal | cannot execute an ELF on Windows |
| `suture-fuzz` | none | needs the fork server, which needs Linux |

So on Windows you can develop and test the rewriter completely — which is where
all the difficulty is — but you cannot run the resulting binary or fuzz with it.
That last part needs WSL2 or a real Linux host.

## On Linux

None of this applies. A stock `rustup` + `build-essential` is enough:

```bash
sudo apt install build-essential
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
cargo test --workspace
```
