//! The fuzzing driver.
//!
//! Two execution backends, chosen by whether the target is running on Linux:
//!
//! * **Fork server** — the fast path. The instrumented binary forks once and
//!   serves many inputs, so the per-execution cost is `fork` + a few
//!   microseconds instead of a full `execve`. This is where AFL's 10-100x
//!   advantage over naive `fork`-per-input comes from, and skipping it would
//!   make every measurement in EVALUATION.md meaningless.
//! * **Plain spawn** — portable fallback, used when the fork server is
//!   unavailable. Every run records which backend produced it, because numbers
//!   from the two are not comparable.
//!
//! The distinction is not an implementation detail; it is the difference between
//! measuring the fuzzer and measuring `execve`.

use anyhow::{bail, Context, Result};
use suture_coverage::Corpus;
use std::path::Path;
use std::time::{Duration, Instant};

/// How targets are executed. Recorded in every result so numbers stay honest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum Backend {
    /// The target's own fork server: one `exec`, then `fork` per input.
    ForkServer,
    /// `spawn` per input. Correct but dominated by process-creation cost.
    PlainSpawn,
}

impl std::fmt::Display for Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Backend::ForkServer => write!(f, "fork-server"),
            Backend::PlainSpawn => write!(f, "plain-spawn"),
        }
    }
}

/// Counters for a fuzzing run. These are the numbers that go in the paper.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct FuzzStats {
    pub backend: Option<Backend>,
    pub execs: u64,
    pub execs_per_sec: f64,
    pub corpus_entries: usize,
    pub crashes: usize,
    pub total_edges: u32,
    pub elapsed_secs: f64,
    /// Executions that hit the time or memory limit. A high rate here means the
    /// limits are shaping the results, so the measurement is not clean.
    pub timeouts: u64,
    pub ooms: u64,
}

/// Choose a backend for `target`.
///
/// The fork server needs a Linux target *and* the `GRAFT_FORKSERVER`
/// environment handshake, so the probe is cheap and the answer is recorded.
pub fn select_backend(target: &Path) -> Backend {
    if !cfg!(target_os = "linux") {
        return Backend::PlainSpawn;
    }
    // A real probe would handshake with the target. Until the fork server is
    // implemented we must not claim it: reporting `ForkServer` without one
    // would mean every published exec/s number was a lie.
    let _ = target;
    Backend::PlainSpawn
}

/// Run a fuzzing session.
pub fn run(
    target: &Path,
    seeds: &Path,
    out: &Path,
    duration: Option<u64>,
    jobs: usize,
) -> Result<()> {
    let backend = select_backend(target);
    std::fs::create_dir_all(out.join("queue"))
        .with_context(|| format!("creating {}", out.display()))?;
    std::fs::create_dir_all(out.join("crashes"))?;

    if backend == Backend::ForkServer {
        eprintln!(
            "warning: no fork server is available yet; running with {backend}.\n\
             \x20        exec/s from this run measures process creation, not the fuzzer.\n\
             \x20        Do not report these numbers."
        );
    }

    let mut corpus = Corpus::new();
    let mut inputs: Vec<Vec<u8>> = Vec::new();
    for entry in std::fs::read_dir(seeds).with_context(|| format!("reading {}", seeds.display()))? {
        let path = entry?.path();
        if path.is_file() {
            inputs.push(std::fs::read(&path)?);
        }
    }
    if inputs.is_empty() {
        bail!("no seed inputs in {}", seeds.display());
    }

    let started = Instant::now();
    // A deadline is an absolute instant, not a duration: comparing durations
    // against a duration that grows with `started.elapsed()` never terminates.
    let deadline = duration.map(|s| started + Duration::from_secs(s));
    let mut stats = FuzzStats {
        backend: Some(backend),
        ..Default::default()
    };

    // Seed pass: run every input once so the corpus reflects the starting point
    // before any mutation. Without this, the first mutations are spent
    // rediscovering the seeds.
    for input in &inputs {
        let snap = suture_exec::run_once(target, input)?;
        stats.execs += 1;
        stats.total_edges = stats.total_edges.max(snap.edge_count());
        if corpus.is_new(snap.signature()) {
            stats.corpus_entries += 1;
        }
    }

    let mut queue: Vec<Vec<u8>> = inputs;
    let mut i = 0usize;
    // `None` means "no deadline": run until the corpus is exhausted or the
    // caller interrupts. `Some(t)` is an absolute instant to stop at.
    while deadline.map_or(true, |t| Instant::now() < t) {
        if jobs > 1 {
            bail!("--jobs {jobs} is not implemented yet; the corpus is not thread-safe yet");
        }

        let parent = &queue[i % queue.len()];
        let child = suture_mutate::havoc(parent, 1 + (stats.execs as usize % 16));
        let snap = match suture_exec::run_once(target, &child) {
            Ok(s) => s,
            Err(_) => {
                i += 1;
                continue;
            }
        };
        stats.execs += 1;
        stats.total_edges = stats.total_edges.max(snap.edge_count());

        if snap.crashed() {
            let path = out.join("crashes").join(format!("id{:08}", stats.crashes));
            std::fs::write(&path, &child)?;
            stats.crashes += 1;
        }
        if corpus.is_new(snap.signature()) {
            let path = out.join("queue").join(format!("id{:08}", queue.len()));
            std::fs::write(&path, &child)?;
            queue.push(child);
            stats.corpus_entries += 1;
        }
        i += 1;
    }

    let elapsed = started.elapsed().as_secs_f64();
    stats.execs_per_sec = if elapsed > 0.0 { stats.execs as f64 / elapsed } else { 0.0 };
    stats.elapsed_secs = elapsed;

    std::fs::write(out.join("fuzz-stats.json"), serde_json::to_vec_pretty(&stats)?)?;
    println!("{}", serde_json::to_string_pretty(&stats)?);
    println!("\nresults in {}", out.display());
    Ok(())
}
