use std::path::PathBuf;
use std::time::Instant;

use anyhow::Result;
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
    /// Parse a MySQL slow query log (5.7 or 8.0 dialect) into a compressed
    /// replay file
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
        /// per-session databases
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
        /// Pacing mode (M1 supports only `max`: sessions fire each query as
        /// soon as the previous completes)
        #[arg(long, value_enum, default_value_t = Speed::Max)]
        speed: Speed,
        /// Write a machine-readable run report to this path
        #[arg(long)]
        out: Option<PathBuf>,
        /// How many fingerprints to show in the stdout summary table
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
    }
    Ok(())
}
