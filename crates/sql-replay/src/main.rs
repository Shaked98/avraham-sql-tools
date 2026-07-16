use std::path::PathBuf;
use std::time::Instant;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use sql_replay::replay::{ReplayOptions, Speed};
use sql_replay::spool::{Filters, TimeWindow};

#[derive(Parser)]
#[command(
    name = "sql-replay",
    version,
    about = "Capture MySQL load (slow query log or tcpdump pcap) and replay it against a target server"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Parse a MySQL slow query log (legacy YYMMDD or modern RFC 3339
    /// dialect) or a tcpdump pcap file into a compressed replay file
    Capture {
        /// Slow query log to parse (produce it with long_query_time=0), or
        /// a pcap/pcap-ng file recorded with tcpdump (auto-detected by
        /// magic bytes; see --format)
        #[arg(long)]
        input: PathBuf,
        /// Output capture file (zstd-compressed JSONL)
        #[arg(long)]
        out: PathBuf,
        /// Input format: `auto` detects pcap files by magic bytes and
        /// treats everything else as a slow log
        #[arg(long, default_value = "auto", value_parser = ["auto", "slowlog", "pcap"])]
        format: String,
        /// MySQL server port to decode in a pcap input (plaintext protocol
        /// only; TLS and compressed connections are skipped and counted)
        #[arg(long, default_value_t = sql_replay::pcap::DEFAULT_MYSQL_PORT)]
        port: u16,
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
        /// Write a machine-readable run report to this path. With
        /// --repeat N > 1, this receives the median-aggregated report and
        /// each pass lands next to it as <out>.passK.json
        #[arg(long)]
        out: Option<PathBuf>,
        /// How many fingerprints to show in the stdout summary table
        #[arg(long, default_value_t = 10)]
        top: usize,
        /// Run one unrecorded warmup pass (cache/buffer-pool warm-up)
        /// before the measured pass(es)
        #[arg(long)]
        warmup: bool,
        /// Number of measured passes; with N > 1 a median-aggregated
        /// report is emitted alongside the per-pass reports
        #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..))]
        repeat: u32,
        /// Replay only events captured against this default database
        /// (events without database metadata are excluded)
        #[arg(long)]
        filter_db: Option<String>,
        /// Replay only events captured for this user (events without user
        /// metadata are excluded)
        #[arg(long)]
        filter_user: Option<String>,
        /// Replay only events inside <start>..<end> (start-inclusive,
        /// end-exclusive; RFC 3339 timestamps or unix epoch seconds; either
        /// side may be omitted)
        #[arg(long, value_parser = TimeWindow::parse)]
        time_window: Option<TimeWindow>,
        /// Multiplex sessions over a bounded pool of this many connections
        /// (checked out per query) instead of one dedicated connection per
        /// session. Trades connection fidelity for feasibility when the
        /// capture has more sessions than the target can hold connections;
        /// captured USE statements are skipped (per-event db metadata
        /// drives database selection instead)
        #[arg(long, conflicts_with = "max_connections", value_parser = clap::value_parser!(u32).range(1..))]
        pool: Option<u32>,
        /// Directory for the replay spool file (roughly the uncompressed
        /// capture size; default: the system temp dir). On distros where
        /// the temp dir is tmpfs (RAM-backed), point this at real disk to
        /// keep replay memory bounded
        #[arg(long)]
        spool_dir: Option<PathBuf>,
        /// Record an order-insensitive result-set checksum per fingerprint
        /// (result-correctness diffing via `compare`). Reads every result
        /// row, so latencies are only comparable to another --checksum run
        #[arg(long)]
        checksum: bool,
    },
    /// Build a baseline run report from a capture's RECORDED production
    /// latencies (the slow log's Query_time values) instead of replaying —
    /// for migrations where the source server cannot be replayed against
    /// because it IS production. The report has the same shape as
    /// `replay --out` and feeds `compare` directly.
    Baseline {
        /// Capture file produced by `sql-replay capture`
        #[arg(long)]
        capture: PathBuf,
        /// Write the baseline run report (JSON) to this path
        #[arg(long)]
        out: PathBuf,
        /// Include only events captured against this default database
        /// (events without database metadata are excluded)
        #[arg(long)]
        filter_db: Option<String>,
        /// Include only events captured for this user (events without user
        /// metadata are excluded)
        #[arg(long)]
        filter_user: Option<String>,
        /// Include only events inside <start>..<end> (start-inclusive,
        /// end-exclusive; RFC 3339 timestamps or unix epoch seconds; either
        /// side may be omitted)
        #[arg(long, value_parser = TimeWindow::parse)]
        time_window: Option<TimeWindow>,
        /// How many fingerprints to show in the stdout summary table
        #[arg(long, default_value_t = 10)]
        top: usize,
    },
    /// Compare two run reports (baseline vs candidate; either side may come
    /// from `replay --out` or from `baseline`) and rank per-fingerprint
    /// latency regressions. Exits 0 when no regression reaches the
    /// threshold, 2 when at least one does (1 = tool error), so CI can gate
    /// on it.
    Compare {
        /// Baseline run report (e.g. the MySQL 5.7 run.json, or a recorded
        /// baseline from `sql-replay baseline`)
        #[arg(long)]
        baseline: PathBuf,
        /// Candidate run report (e.g. the MySQL 8.0 or MariaDB run.json)
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

/// `run.json` + pass 2 -> `run.pass2.json` (suffix lands before the
/// extension so the files sort and glob together).
fn pass_report_path(out: &std::path::Path, pass: usize) -> PathBuf {
    match out.extension().and_then(|e| e.to_str()) {
        Some(ext) => out.with_extension(format!("pass{pass}.{ext}")),
        None => out.with_extension(format!("pass{pass}")),
    }
}

fn main() -> Result<()> {
    // Before anything else: still single-threaded (it mutates the
    // environment) and no MySQL connection exists yet (mysql_async reads
    // its buffer-pool config from the environment exactly once).
    sql_replay::memtune::tune_process_memory();

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
            format,
            port,
            dialect,
        } => {
            let t0 = Instant::now();
            let is_pcap = match format.as_str() {
                "pcap" => true,
                "slowlog" => false,
                _ => sql_replay::pcap::looks_like_pcap(&input),
            };
            let summary = if is_pcap {
                sql_replay::capture::run_capture_pcap(&input, &out, port, dialect.as_deref())?
            } else {
                sql_replay::capture::run_capture(&input, &out, dialect.as_deref())?
            };
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
            if let Some(p) = &summary.pcap {
                println!(
                    "pcap: {} packets, {} connections ({} decoded, {} TLS-skipped, \
                     {} compressed-skipped, {} mid-stream-skipped, {} broken); \
                     prepared statements: {} expanded, {} inexpandable; \
                     {} responses missing; server version(s): {}",
                    p.packets,
                    p.connections,
                    p.connections_decoded,
                    p.connections_tls_skipped,
                    p.connections_compressed_skipped,
                    p.connections_midstream_skipped,
                    p.connections_broken,
                    p.statements_expanded,
                    p.statements_inexpandable,
                    p.responses_missing,
                    if p.server_versions.is_empty() {
                        "none seen".to_string()
                    } else {
                        p.server_versions.join(", ")
                    },
                );
            }
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
            warmup,
            repeat,
            filter_db,
            filter_user,
            time_window,
            pool,
            spool_dir,
            checksum,
        } => {
            let options = ReplayOptions {
                url,
                max_connections,
                allow_writes,
                read_only,
                db_override,
                speed,
                pool: pool.map(|n| n as usize),
                warmup,
                repeat: repeat as usize,
                filters: Filters {
                    db: filter_db,
                    user: filter_user,
                    window: time_window,
                },
                spool_dir,
                checksum,
            };
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            let outcome = rt.block_on(sql_replay::replay::run_replay(&capture, options))?;
            let primary = outcome.primary();
            print!("{}", primary.render_table(top));
            if let Some(warning) = primary.saturation_warning() {
                eprintln!("\n{warning}");
            }
            if let Some(path) = out {
                // Multi-pass runs also write each pass next to the
                // aggregated report.
                if outcome.aggregated.is_some() {
                    for (i, pass) in outcome.passes.iter().enumerate() {
                        let p = pass_report_path(&path, i + 1);
                        std::fs::write(&p, serde_json::to_string_pretty(pass)?)?;
                        eprintln!("wrote pass {} report to {}", i + 1, p.display());
                    }
                }
                std::fs::write(&path, serde_json::to_string_pretty(primary)?)?;
                eprintln!("wrote run report to {}", path.display());
            }
            if outcome.aborted() {
                eprintln!("replay aborted: the report(s) are partial");
                std::process::exit(130);
            }
        }
        Cmd::Baseline {
            capture,
            out,
            filter_db,
            filter_user,
            time_window,
            top,
        } => {
            let filters = Filters {
                db: filter_db,
                user: filter_user,
                window: time_window,
            };
            let report = sql_replay::baseline::build_baseline(&capture, &filters)?;
            print!("{}", report.render_table(top));
            std::fs::write(&out, serde_json::to_string_pretty(&report)?)?;
            eprintln!("wrote baseline report to {}", out.display());
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
            if report.correctness_failed {
                eprintln!(
                    "FAIL: {} fingerprint(s) returned different data (result checksum \
                     mismatch; exit code {})",
                    report
                        .correctness
                        .as_ref()
                        .map(|c| c.mismatches.len())
                        .unwrap_or(0),
                    sql_replay::compare::EXIT_REGRESSED,
                );
            }
            if report.regressed {
                eprintln!(
                    "FAIL: {} fingerprint(s) regressed >= {}% on p95 (exit code {})",
                    report.regressions.len(),
                    threshold_pct,
                    sql_replay::compare::EXIT_REGRESSED,
                );
            }
            if report.size_regressed {
                eprintln!(
                    "FAIL: {} result-size decade(s) regressed >= {}% on p95 inside \
                     otherwise-stable fingerprints (exit code {})",
                    report.size_regressions.len(),
                    threshold_pct,
                    sql_replay::compare::EXIT_REGRESSED,
                );
            }
            if report.regressed || report.size_regressed || report.correctness_failed {
                std::process::exit(sql_replay::compare::EXIT_REGRESSED);
            }
        }
    }
    Ok(())
}
