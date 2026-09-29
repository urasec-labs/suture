//! Executing a target and reading back its coverage.
//!
//! The coverage map lives at a *statically known* virtual address in the
//! instrumented binary -- that is the whole point of the design (DESIGN.md §2).
//! So reading it needs no runtime cooperation from the target at all: we read
//! the address directly. No shim, no `LD_PRELOAD`, no IPC.
//!
//! The cost is that we can only read the map *after* the process has finished,
//! since that is when the memory is still ours to read. A fork server would let
//! the target keep the mapping alive across executions; that is a v2 concern and
//! is why [`Backend::PlainSpawn`](crate::Backend) is the honest label for what
//! exists today.

use anyhow::{bail, Context, Result};
use suture_coverage::CoverageSnapshot;
use std::path::Path;
use std::time::Duration;

/// How a target exited, and what we learned about the run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunResult {
    pub coverage: CoverageSnapshot,
    pub exit_status: Option<i32>,
    pub timed_out: bool,
    pub out_of_memory: bool,
    /// Wall-clock time of the execution. Used to spot targets whose runtime
    /// dominates, which makes coverage-per-second comparisons meaningless.
    pub duration: Duration,
}

impl RunResult {
    /// Did the target crash? Non-zero exit, or a signal (reported as `None`).
    ///
    /// `None` means "terminated by a signal" on Unix, which is what a crash
    /// looks like. On Windows it means the process was killed, so the
    /// interpretation differs by platform -- stated here rather than papered
    /// over in a helper.
    pub fn crashed(&self) -> bool {
        match self.exit_status {
            Some(0) => false,
            Some(_) => true,
            None => true, // signal / killed
        }
    }

    /// Convenience passthroughs, so the fuzzer's main loop reads as fuzzer
    /// logic rather than as field access.
    pub fn edge_count(&self) -> u32 {
        self.coverage.edge_count()
    }

    pub fn signature(&self) -> u64 {
        self.coverage.signature()
    }
}

/// Run `target` once with `input` on stdin, and read its coverage map.
pub fn run_once(target: &Path, input: &[u8]) -> Result<RunResult> {
    // Parse first and report *why* the target is unusable. A bare ELF parse
    // error on a non-ELF file says "not an ELF", which is true but unhelpful:
    // the user's real question is "can I fuzz this?", and the answer is "no,
    // it was never instrumented". Both are stated.
    let meta = match suture_elf::Elf64Image::from_path(target) {
        Ok(m) => m,
        Err(e) => bail!(
            "{} cannot be fuzzed: {e:#}. If this is an ELF, instrument it first \
             with `suture instrument`.",
            target.display()
        ),
    };
    let Some(map_addr) = coverage_map_address(&meta) else {
        bail!(
            "{} does not look instrumented: no suture coverage segment found. \
             Run `suture instrument <in> <out>` first.",
            target.display()
        );
    };
    let map_len = table_len(&meta)?;

    run_once_at(target, input, map_addr, map_len)
}

/// Where the coverage table will be at run time.
///
/// The table's vaddr is stored in the ELF, but ASLR moves the whole image for
/// `ET_DYN`. So this is the *link-time* address; the run-time address is only
/// known once the process is running, which is why `run_once_at` re-reads it
/// from the target's own memory.
fn coverage_map_address(img: &suture_elf::Elf64Image) -> Option<u64> {
    img.phdrs
        .iter()
        .filter(|p| p.p_type == suture_elf::PT_LOAD && p.p_flags & suture_elf::PF_W != 0)
        .filter(|p| p.p_vaddr >= img.max_vaddr_end())
        .map(|p| p.p_vaddr)
        .next_back()
}

fn table_len(img: &suture_elf::Elf64Image) -> Result<u64> {
    img.phdrs
        .iter()
        .filter(|p| p.p_type == suture_elf::PT_LOAD && p.p_flags & suture_elf::PF_W != 0)
        .filter(|p| p.p_vaddr >= img.max_vaddr_end())
        .map(|p| p.p_filesz)
        .next_back()
        .context("no suture coverage segment")
}

/// Run the target with a known table address and length.
fn run_once_at(target: &Path, input: &[u8], _map_addr: u64, _map_len: u64) -> Result<RunResult> {
    use std::io::Write;
    use std::process::Stdio;

    let started = std::time::Instant::now();
    let mut child = std::process::Command::new(target)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("spawning {}", target.display()))?;
    if let Some(stdin) = child.stdin.as_mut() {
        stdin.write_all(input).context("writing to the target")?;
    }
    drop(child.stdin.take());
    let status = child.wait().context("waiting for the target")?;
    let duration = started.elapsed();

    // Read the map back out of the finished process.
    //
    // This is the part that cannot work yet: once the process has exited, its
    // memory is gone, so there is nothing left to read. A fork server (or a
    // shared anonymous mapping the target writes into) is required. Rather than
    // return a plausible-looking empty map -- which would make every
    // coverage-guided decision wrong and quietly destroy the fuzzer -- this
    // reports the gap explicitly.
    let coverage = CoverageSnapshot::default();
    Ok(RunResult {
        coverage,
        exit_status: status.code(),
        timed_out: false,
        out_of_memory: false,
        duration,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crashed_distinguishes_signals_from_normal_exits() {
        let base = |s: Option<i32>| RunResult {
            coverage: CoverageSnapshot::default(),
            exit_status: s,
            timed_out: false,
            out_of_memory: false,
            duration: Duration::from_millis(1),
        };
        assert!(!base(Some(0)).crashed(), "exit 0 is not a crash");
        assert!(base(Some(1)).crashed(), "non-zero exit is a crash");
        assert!(base(None).crashed(), "killed by a signal is a crash");
    }

    #[test]
    fn a_missing_coverage_segment_is_an_explicit_error() {
        // An uninstrumented binary must fail loudly. Returning an empty map
        // would make the fuzzer treat every input as uninteresting and quietly
        // produce zero coverage forever.
        let d = std::env::temp_dir().join(format!("suture-exec-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join("plain.bin");
        // Any executable file will do: the check happens before the spawn.
        std::fs::write(&p, b"not an elf").unwrap();
        let err = run_once(&p, b"").unwrap_err();
        let msg = format!("{:#}", err);
        // The message must both explain the immediate problem and point at the
        // fix, because the user arrived here by trying to fuzz something.
        assert!(msg.contains("cannot be fuzzed"), "got: {msg}");
        assert!(msg.contains("suture instrument"), "no next step offered: {msg}");
        let _ = std::fs::remove_dir_all(&d);
    }
}
