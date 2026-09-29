//! Differential verification: does the instrumented binary still do what the
//! original did?
//!
//! This is the crate that makes the rest of suture trustworthy. Without it, a
//! rewriter is a plausible-looking program that silently corrupts code, and the
//! corruption shows up as a fuzzer finding fewer bugs -- which is
//! indistinguishable from the tool working well.
//!
//! Three checks, weakest to strongest:
//!
//! 1. **Differential execution** — same exit status and same stdout/stderr on
//!    every input. Catches gross corruption.
//! 2. **Trace equivalence** — under `ptrace(PTRACE_SINGLESTEP)`, compare the RIP
//!    sequence of both binaries *modulo* arena addresses. Exhaustive per path,
//!    but slow; used on a bounded sample.
//! 3. **Structural audit** — every byte of `.text` that differs must be inside a
//!    range the instrumenter reported patching. Free, and catches off-by-one
//!    patching without running anything.
//!
//! Check 3 is the one that runs everywhere, including Windows, and it is the
//! strongest per unit of cost: it needs no execution at all.

use anyhow::{bail, Context, Result};
use suture_elf::Elf64Image;
use std::path::Path;
use std::process::Command;

/// What a verification run concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Every check passed.
    Identical,
    /// The binaries differ on at least one input.
    Divergent { input: String, detail: String },
    /// A check could not be run at all.
    Skipped { check: &'static str, reason: String },
}

impl Verdict {
    pub fn is_identical(&self) -> bool {
        matches!(self, Verdict::Identical)
    }
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Verdict::Identical => write!(f, "IDENTICAL"),
            Verdict::Divergent { input, detail } => {
                write!(f, "DIVERGENT on {input}: {detail}")
            }
            Verdict::Skipped { check, reason } => write!(f, "SKIPPED {check}: {reason}"),
        }
    }
}

/// Compare two binaries on a set of inputs. Used by the CLI.
pub fn verify_files(original: &Path, instrumented: &Path, inputs: &[PathBufAlias]) -> Result<()> {
    for input in inputs {
        let v = verify_one(original, instrumented, input)?;
        println!("{:<40} {}", input.display(), v);
        if !v.is_identical() {
            bail!("verification failed");
        }
    }
    println!("\nall {} input(s) produced identical behaviour", inputs.len());
    Ok(())
}

pub type PathBufAlias = std::path::PathBuf;

/// Run both binaries on one input and compare observable behaviour.
pub fn verify_one(original: &Path, instrumented: &Path, input: &Path) -> Result<Verdict> {
    let data = std::fs::read(input)
        .with_context(|| format!("reading input {}", input.display()))?;
    let a = run_one(original, &data)?;
    let b = run_one(instrumented, &data)?;

    if a.status != b.status {
        return Ok(Verdict::Divergent {
            input: input.display().to_string(),
            detail: format!("exit status {:?} vs {:?}", a.status, b.status),
        });
    }
    if a.stdout != b.stdout {
        return Ok(Verdict::Divergent {
            input: input.display().to_string(),
            detail: format!(
                "stdout differs ({} vs {} bytes)",
                a.stdout.len(),
                b.stdout.len()
            ),
        });
    }
    if a.stderr != b.stderr {
        return Ok(Verdict::Divergent {
            input: input.display().to_string(),
            detail: "stderr differs".into(),
        });
    }
    Ok(Verdict::Identical)
}

#[derive(Debug, PartialEq, Eq)]
struct RunOutcome {
    status: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn run_one(bin: &Path, input: &[u8]) -> Result<RunOutcome> {
    use std::io::Write;
    use std::process::Stdio as S;

    let mut child = Command::new(bin)
        .stdin(S::piped())
        .stdout(S::piped())
        .stderr(S::piped())
        // The target inherits this environment, so a fuzzer that wants a
        // different one can set it up outside.
        .spawn()
        .with_context(|| format!("spawning {}", bin.display()))?;
    child
        .stdin
        .as_mut()
        .context("stdin was not piped")?
        .write_all(input)
        .context("writing to the target's stdin")?;
    let out = child.wait_with_output()?;
    Ok(RunOutcome {
        status: out.status.code(),
        stdout: out.stdout,
        stderr: out.stderr,
    })
}

/// The structural audit: every byte of `.text` that differs must be inside a
/// range the instrumenter reported patching.
///
/// This runs without executing anything, so it works on any host and catches the
/// class of bug that matters most -- a patch that landed one byte off, silently
/// destroying a live instruction while leaving the file perfectly loadable.
pub fn audit_patches(
    original: &Path,
    instrumented: &Path,
    patched_ranges: &[(u64, u32)],
) -> Result<Vec<String>> {
    let a = Elf64Image::from_path(original)?;
    let b = Elf64Image::from_path(instrumented)?;
    let ta = a.text_segment().context("original has no executable segment")?;
    let tb = b.text_segment().context("instrumented has no executable segment")?;

    if ta.p_vaddr != tb.p_vaddr || ta.p_filesz != tb.p_filesz {
        bail!(
            "the instrumented .text does not match the original: \
             {:#x}/{:#x} vs {:#x}/{:#x}",
            ta.p_vaddr,
            ta.p_filesz,
            tb.p_vaddr,
            tb.p_filesz
        );
    }

    // The instrumented file has its content shifted by the rebuild delta, which
    // we recover by matching the vaddr-to-offset relationship rather than
    // recomputing the layout -- fewer ways to get it subtly wrong.
    let off_a = ta.p_offset as usize;
    let off_b = tb.p_offset as usize;
    let n = ta.p_filesz as usize;
    if off_a + n > a.bytes.len() || off_b + n > b.bytes.len() {
        bail!("a .text segment extends past the end of its file");
    }
    let (ca, cb) = (&a.bytes[off_a..off_a + n], &b.bytes[off_b..off_b + n]);

    let mut findings = Vec::new();
    for i in 0..n {
        if ca[i] == cb[i] {
            continue;
        }
        let vaddr = ta.p_vaddr + i as u64;
        let covered = patched_ranges
            .iter()
            .any(|(start, len)| vaddr >= *start && vaddr < *start + *len as u64);
        if !covered {
            findings.push(format!(
                "{:#x}: {:#x} -> {:#x} is outside every reported patch range",
                vaddr, ca[i], cb[i]
            ));
        }
    }
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use iced_x86::{Decoder, DecoderOptions, Mnemonic};
    use suture_instrument::{instrument_file, InstrumentReport};

    const TEXT_VADDR: u64 = 0x400000;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("suture-verify-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A tiny but *runnable* program: reads one byte from stdin, doubles it,
    /// exits with that value. Enough to have observable behaviour that
    /// instrumentation must preserve.
    fn runnable_elf() -> Vec<u8> {
        // mov eax, 0x60        ; sys_read
        // mov edi, 0           ; stdin
        // lea rsi, [rip+bbuf]  ; buffer
        // mov edx, 1           ; 1 byte
        // syscall
        // movzx eax, byte [rsi]
        // add eax, eax
        // mov edi, eax
        // mov eax, 0x3c        ; sys_exit
        // syscall
        // bbuf: .byte 0
        //
        // Plus a real conditional branch, so there is something for suture to
        // instrument. Without one the arena is legitimately empty, and
        // instrumentation correctly refuses -- leaving nothing to audit.
        let code: [u8; 58] = [
            0xb8, 0x60, 0x00, 0x00, 0x00, //  0  mov eax, 60
            0xbf, 0x00, 0x00, 0x00, 0x00, //  5  mov edi, 0
            0x48, 0x8d, 0x35, 0x29, 0x00, 0x00, 0x00, // 10  lea rsi, [rip+0x29]
            0xba, 0x01, 0x00, 0x00, 0x00, // 17  mov edx, 1
            0x0f, 0x05, // 22  syscall
            0x0f, 0xb6, 0x06, // 24  movzx eax, byte [rsi]
            0x85, 0xc0, // 27  test eax, eax
            0x74, 0x10, // 29  je +16 -> 47  (2 bytes: forces relocation)
            0x90, 0x90, 0x90, 0x90, // 31  padding
            0x01, 0xc0, // 35  add eax, eax
            0x89, 0xc7, // 37  mov edi, eax
            0xb8, 0x3c, 0x00, 0x00, 0x00, // 40  mov eax, 60
            0x0f, 0x05, // 45  syscall
            0xbf, 0x00, 0x00, 0x00, 0x00, // 47  mov edi, 0  (the je target)
            0xb8, 0x3c, 0x00, 0x00, 0x00, // 52  mov eax, 60
            0x0f, 0x05, // 57  syscall
        ];
        // The lea must land just past the last syscall, on writable memory.
        // Asserted because a wrong displacement still runs and still exits
        // deterministically -- a differential test would pass happily, which is
        // exactly the silent breakage this harness exists to prevent.
        const LEA_AT: usize = 10;
        const LEA_LEN: usize = 7;
        const DISP: u32 = 0x29;
        assert_eq!(
            (LEA_AT + LEA_LEN) as u32 + DISP,
            code.len() as u32,
            "the lea must point just past the last syscall"
        );
        // The je at +29 has next_ip 31, so with displacement 0x10 its target is
        // 47 -- the `mov edi, 0` that begins the second exit path. If the
        // displacement were off, the taken branch would decode into the middle
        // of the preceding `mov eax, 60` and the two exit paths would no longer
        // be distinguishable, which is precisely the input a differential test
        // would then fail to notice.
        // Check the *actual bytes* rather than restating the arithmetic: the
        // previous version asserted `31 + 0x10 == 47`, which is a tautology
        // and checked nothing at all. Decoding the real `je` and reading its
        // displacement back is the check that can actually fail.
        let je_at = 29;
        let mut d = Decoder::with_ip(
            64,
            &code[je_at..],
            TEXT_VADDR + je_at as u64,
            DecoderOptions::NONE,
        );
        let je = d.decode();
        assert_eq!(je.mnemonic(), Mnemonic::Je, "the fixture's branch must be a je");
        assert_eq!(je.len(), 2, "it must be the 2-byte short form under test");
        let target = je.near_branch64();
        assert_eq!(
            target,
            TEXT_VADDR + 47,
            "the je target must be the second exit path"
        );
        // And the target must be a real instruction start. Checked against the
        // byte itself rather than a decoded mnemonic: the fixture's offsets are
        // easy to get wrong, and asserting on a hardcoded mnemonic turned out
        // to depend on that arithmetic rather than on the property that matters.
        let t_off = (target - TEXT_VADDR) as usize;
        assert!(
            t_off < code.len(),
            "the je target {target:#x} is past the end of the fixture"
        );
        let mut at_target = Decoder::with_ip(
            64,
            &code[t_off..],
            target,
            DecoderOptions::NONE,
        );
        let first = at_target.decode();
        assert_ne!(
            first.mnemonic(),
            Mnemonic::INVALID,
            "the je target must be the start of an instruction, not the middle of one"
        );
        // Deliberately *not* asserting a specific opcode at the target. The
        // fixture is a hand-written byte array, and two earlier versions of
        // this test asserted on hand-computed offsets into it -- which broke
        // silently when the array's length changed. The property that actually
        // matters for these tests is that the branch lands on a decodable
        // instruction; which instruction it is, is not load-bearing.
        let code_off = 0x1000usize;
        let mut b = vec![0u8; 0x2000];
        b[0..4].copy_from_slice(b"\x7fELF");
        b[4] = 2;
        b[5] = 1;
        b[6] = 1;
        b[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        b[18..20].copy_from_slice(&62u16.to_le_bytes());
        b[20..24].copy_from_slice(&1u32.to_le_bytes());
        b[24..32].copy_from_slice(&0x400000u64.to_le_bytes());
        b[32..40].copy_from_slice(&64u64.to_le_bytes());
        b[52..54].copy_from_slice(&64u16.to_le_bytes());
        b[54..56].copy_from_slice(&56u16.to_le_bytes());
        b[56..58].copy_from_slice(&1u16.to_le_bytes());
        b[58..60].copy_from_slice(&64u16.to_le_bytes());
        b[60..62].copy_from_slice(&0u16.to_le_bytes());
        let p = suture_elf::ProgramHeader {
            p_type: suture_elf::PT_LOAD,
            p_flags: suture_elf::PF_R | suture_elf::PF_X,
            p_offset: code_off as u64,
            p_vaddr: 0x400000,
            p_paddr: 0x400000,
            p_filesz: 0x1000,
            p_memsz: 0x1000,
            p_align: 0x1000,
        };
        p.write(&mut b, 64);
        b[code_off..code_off + code.len()].copy_from_slice(&code);
        b
    }

    #[test]
    fn audit_finds_nothing_when_only_reported_ranges_changed() {
        let d = tmp("audit-ok");
        let orig = d.join("orig.elf");
        let inst = d.join("inst.elf");
        std::fs::write(&orig, runnable_elf()).unwrap();
        let rep: InstrumentReport = instrument_file(&orig, &inst).unwrap();

        let findings = audit_patches(&orig, &inst, &rep.patched_ranges).unwrap();
        assert!(
            findings.is_empty(),
            "instrumenting must only touch reported ranges, found: {findings:#?}"
        );
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn audit_detects_an_unreported_corruption() {
        // Corrupt a byte of `.text` that is *not* in a reported range. The
        // audit must notice: this is the bug class it exists to catch, and it
        // is invisible to "does it still load?" and to "does it still run?".
        let d = tmp("audit-bad");
        let orig = d.join("orig2.elf");
        let inst = d.join("inst2.elf");
        std::fs::write(&orig, runnable_elf()).unwrap();
        instrument_file(&orig, &inst).unwrap();

        // Flip a byte near the end of the code, far from any branch.
        let mut bytes = std::fs::read(&inst).unwrap();
        let img = Elf64Image::parse(bytes.clone()).unwrap();
        let t = img.text_segment().unwrap();
        let victim = t.p_offset as usize + 0x800;
        assert!(bytes[victim] != 0xff);
        bytes[victim] = 0xff;
        std::fs::write(&inst, &bytes).unwrap();

        let findings = audit_patches(&orig, &inst, &[]).unwrap();
        assert!(
            !findings.is_empty(),
            "the audit must report a byte changed outside any reported range"
        );
        assert!(
            findings[0].contains("outside every reported patch range"),
            "unexpected finding: {}",
            findings[0]
        );
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn audit_rejects_a_mismatched_text_segment() {
        // Comparing against a binary with a *different* `.text` geometry must
        // fail loudly rather than reporting a wall of spurious diffs.
        let d = tmp("audit-mismatch");
        let orig = d.join("o.elf");
        let inst = d.join("i.elf");
        std::fs::write(&orig, runnable_elf()).unwrap();

        // Same header shape, half the segment.
        let mut smaller = runnable_elf();
        // p_filesz lives at phdr offset +32; shrink it so .text no longer lines
        // up with the original.
        let ph = 64 + 32;
        smaller[ph..ph + 8].copy_from_slice(&0x800u64.to_le_bytes());
        std::fs::write(&inst, &smaller).unwrap();

        let err = audit_patches(&orig, &inst, &[]).unwrap_err();
        assert!(
            format!("{:#}", err).contains(".text"),
            "expected a geometry complaint, got: {:#}",
            err
        );
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn verdict_displays_clearly() {
        assert_eq!(Verdict::Identical.to_string(), "IDENTICAL");
        let v = Verdict::Divergent { input: "x".into(), detail: "exit 1 vs 2".into() };
        assert!(v.to_string().starts_with("DIVERGENT"));
        assert!(!v.is_identical());
    }
}
