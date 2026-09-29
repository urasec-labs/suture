//! `suture` — the command-line entry point.
//!
//! Three subcommands, deliberately few:
//!
//! * `instrument` — the rewriter. ELF in, instrumented ELF out.
//! * `verify`     — the correctness gate from DESIGN.md §6.
//! * `fuzz`       — the driver (Linux only; needs a fork server).
//!
//! The verification gate is *not* optional and not a separate binary: a
//! researcher who runs `instrument` without ever running `verify` has a binary
//! they cannot trust, and the failure mode is silent. So `instrument` prints
//! the exact command that verifies its own output.

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "suture",
    about = "Source-free edge-coverage instrumentation for x86-64 ELF binaries",
    long_about = "suture rewrites a stripped x86-64 ELF so that it reports exact edge \
                  coverage through a byte table at a statically known address -- with no \
                  source code, no compiler, and no runtime relocation.\n\n\
                  \x20 WARNING: suture runs arbitrary binaries. It is not a sandbox. Run it \
                  inside a disposable VM or container."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
    /// Increase log verbosity. Repeat for more.
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,
}

#[derive(Subcommand)]
enum Command {
    /// Report what instrumentation would cost, and whether it is worth doing.
    ///
    /// Runs entirely on the bytes: no execution, no Linux, no target process.
    /// Answers the two questions that decide whether a binary is worth
    /// instrumenting -- how badly AFL's hashed map would collide on its real
    /// control flow, and how much of it must be relocated.
    Analyze {
        /// The ELF to analyse.
        input: PathBuf,
        /// Write the report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Rewrite an ELF to add exact edge-coverage instrumentation.
    Instrument {
        /// Input ELF (x86-64, ET_EXEC or ET_DYN).
        input: PathBuf,
        /// Output path for the instrumented ELF.
        output: PathBuf,
        /// Also write a JSON report next to the output.
        #[arg(long)]
        json: bool,
        /// Refuse to instrument when indirect branches were skipped.
        #[arg(long)]
        strict: bool,
    },
    /// Check that an instrumented binary still behaves like the original.
    Verify {
        /// The original ELF.
        original: PathBuf,
        /// The instrumented ELF.
        instrumented: PathBuf,
        /// Inputs to feed both binaries. Each file is passed on stdin.
        #[arg(required = true)]
        inputs: Vec<PathBuf>,
    },
    /// Fuzz an instrumented binary.
    Fuzz {
        /// The instrumented ELF.
        target: PathBuf,
        /// Directory of seed inputs.
        seeds: PathBuf,
        /// Where to write new inputs, crashes, and coverage.
        #[arg(short, long, default_value = "out")]
        out: PathBuf,
        /// Stop after this many seconds.
        #[arg(short, long)]
        duration: Option<u64>,
        /// Number of parallel workers.
        #[arg(short, long, default_value_t = 1)]
        jobs: usize,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing(cli.verbose);
    match run(cli.command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn init_tracing(verbosity: u8) {
    use tracing_subscriber::EnvFilter;
    let default = match verbosity {
        0 => "warn,suture=info",
        1 => "info",
        _ => "debug",
    };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}

fn run(cmd: Command) -> Result<()> {
    match cmd {
        Command::Analyze { input, json } => {
            let report = suture_instrument::analyze_file(&input)?;
            println!("{}", report.summary());
            if json {
                let path = input.with_extension("analysis.json");
                std::fs::write(&path, serde_json::to_vec_pretty(&report)?)?;
                println!("\nreport: {}", path.display());
            }
            Ok(())
        }

        Command::Instrument { input, output, json, strict } => {
            let report = suture_instrument::instrument_file(&input, &output)?;
            println!("{}", report.summary());

            for w in &report.warnings {
                eprintln!("warning: {w}");
            }
            if strict && report.skipped_indirect > 0 {
                bail!(
                    "--strict: {} indirect branches were not instrumented",
                    report.skipped_indirect
                );
            }

            if json {
                let path = output.with_extension("json");
                std::fs::write(&path, serde_json::to_vec_pretty(&report)?)?;
                println!("\nreport: {}", path.display());
            }

            // Print the verification command verbatim. Making the next step
            // copy-pasteable is the difference between "read the docs" and
            // "actually ran it".
            println!(
                "\nnext: verify this binary before trusting it\n  \
                 suture verify {} {} <input>...",
                input.display(),
                output.display()
            );
            Ok(())
        }

        Command::Verify { original, instrumented, inputs } => {
            suture_verify::verify_files(&original, &instrumented, &inputs)
        }

        Command::Fuzz { target, seeds, out, duration, jobs } => {
            suture_fuzz::run(&target, &seeds, &out, duration, jobs)
        }
    }
}
