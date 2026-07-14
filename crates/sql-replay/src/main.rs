use std::path::PathBuf;
use std::time::Instant;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use sql_replay::replay::{ReplayOptions, Speed};

#[derive(Parser)]
#[command(
    name = "sql-replay",
    version,
    about = "Capture MySQL slow query logs and replay them against a target server"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Parse a MySQL slow query log (legacy YYMMDD or modern RFC 3339
    /// dialect) into a compressed replay file
    Capture {
        /// Slow query log to parse (produce it with long_query_time=0)
        #[arg(long)]
        input: PathBuf,
        /// Output capture file (zstd-compressed JSONL)
        #[arg(long)]
        out: PathBuf,
        /// Override the auto-detected source dialect label (e.g. mysql-5.7)
        #[arg(long)]
        dialect: Option<String>,
    },
    /// Replay a capture file against a target MySQL server
    Replay {
        /// Capture file produced by `sql-replay capture`
        #[arg(long)]
        capture: PathBuf,
        /// Target server, e.g. mysql://user:pass@host:3306/db
        #[arg(long)]
        url: String,
        /// Maximum concurrent sessions/connections
        #[arg(long, default_value_t = 50)]
        max_connections: usize,
        /// Replay every event against this database instead of the captured
        /// per-session databases (captured USE statements are then skipped
        /// and counted)
        #[arg(long)]
        db_override: Option<String>,
        /// Execute non-read statements (INSERT/UPDATE/DDL/...). Without this
        /// flag they are always skipped and counted.
        #[arg(long)]
        allow_writes: bool,
        /// Skip non-read statements (this is already the default; the flag
        /// exists to make intent explicit and conflicts with --allow-writes)
        #[arg(long, conflicts_with = "allow_writes")]
        read_only: bool,
        /// Pacing: `max` (sessions fire each query as soon as the previous
        /// completes) or a positive factor honoring the capture's original
        /// timeline (`1.0` = real time, `2.0` = twice as fast, `0.5` = half
        /// speed); paced events never fire before their scheduled offset
        #[arg(long, default_value = "max", value_parser = Speed::parse)]
        speed: Speed,
        /// Write a machine-readable run report to this path
        #[arg(long)]
        out: Option<PathBuf>,
        /// How many fingerprints to show in the stdout summary table
        #[arg(long, default_value_t = 10)]
        top: usize,
    },
    /// Compare two `replay --out` run reports (baseline vs candidate) and
    /// rank per-fingerprint latency regressions. Exits 0 when no regression
    /// reaches the threshold, 2 when at least one does (1 = tool error), so
    /// CI can gate on it.
    Compare {
        /// Baseline run report (e.g. the MySQL 5.7 run.json)
        #[arg(long)]
        baseline: PathBuf,
        /// Candidate run report (e.g. the MySQL 8.0 run.json)
        #[arg(long)]
        candidate: PathBuf,
        /// Write a self-contained HTML report (inline CSS/JS, renders
        /// offline) to this path
        #[arg(long)]
        out: Option<PathBuf>,
        /// Write the machine-readable JSON report to this path
        #[arg(long)]
        json: Option<PathBuf>,
        /// Minimum executed count (in both runs) for a fingerprint to enter
        /// the headline ranking; below it it is listed as low-sample
        #[arg(long, default_value_t = 5)]
        min_count: u64,
        /// p95 latency change (percent) at/beyond which a fingerprint counts
        /// as regressed (or, mirrored, improved)
        #[arg(long, default_value_t = 20.0)]
        threshold_pct: f64,
        /// How many fingerprints to show per stdout section
        #[arg(long, default_value_t = 10)]
        top: usize,
    },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Capture {
            input,
            out,
            dialect,
        } => {
            let t0 = Instant::now();
            let summary = sql_replay::capture::run_capture(&input, &out, dialect.as_deref())?;
            println!(
                "captured {} events / {} sessions / {} fingerprints (dialect: {}, \
                 admin commands ignored: {}) in {:.2}s -> {}",
                summary.event_count,
                summary.session_count,
                summary.fingerprints.len(),
                summary.source_dialect,
                summary.admin_commands_ignored,
                t0.elapsed().as_secs_f64(),
                out.display(),
            );
        }
        Cmd::Replay {
            capture,
            url,
            max_connections,
            db_override,
            allow_writes,
            read_only,
            speed,
            out,
            top,
        } => {
            let options = ReplayOptions {
                url,
                max_connections,
                allow_writes,
                read_only,
                db_override,
                speed,
            };
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            let report = rt.block_on(sql_replay::replay::run_replay(&capture, options))?;
            print!("{}", report.render_table(top));
            if let Some(warning) = report.saturation_warning() {
                eprintln!("\n{warning}");
            }
            if let Some(path) = out {
                std::fs::write(&path, serde_json::to_string_pretty(&report)?)?;
                eprintln!("wrote run report to {}", path.display());
            }
        }
        Cmd::Compare {
            baseline,
            candidate,
            out,
            json,
            min_count,
            threshold_pct,
            top,
        } => {
            let load = |path: &PathBuf| -> Result<sql_replay::report::RunReport> {
                let text = std::fs::read_to_string(path)
                    .with_context(|| format!("cannot read run report {}", path.display()))?;
                serde_json::from_str(&text)
                    .with_context(|| format!("{} is not a sql-replay run report", path.display()))
            };
            let baseline_run = load(&baseline)?;
            let candidate_run = load(&candidate)?;
            let report = sql_replay::compare::compare_runs(
                &baseline.display().to_string(),
                &baseline_run,
                &candidate.display().to_string(),
                &candidate_run,
                sql_replay::compare::CompareOptions {
                    threshold_pct,
                    min_count,
                },
            );
            print!("{}", report.render_stdout(top));
            if let Some(path) = json {
                std::fs::write(&path, serde_json::to_string_pretty(&report)?)?;
                eprintln!("wrote JSON report to {}", path.display());
            }
            if let Some(path) = out {
                std::fs::write(&path, sql_replay::compare_html::render_html(&report))?;
                eprintln!("wrote HTML report to {}", path.display());
            }
            if report.regressed {
                eprintln!(
                    "FAIL: {} fingerprint(s) regressed >= {}% on p95 (exit code {})",
                    report.regressions.len(),
                    threshold_pct,
                    sql_replay::compare::EXIT_REGRESSED,
                );
                std::process::exit(sql_replay::compare::EXIT_REGRESSED);
            }
        }
    }
    Ok(())
}
