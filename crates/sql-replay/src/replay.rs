//! The `replay` subcommand: run a capture against a target MySQL server.
//!
//! Concurrency model: one lightweight tokio task per original session
//! (connection thread id). Each session executes its own queries strictly
//! in capture order on a dedicated connection; sessions run concurrently,
//! capped by a `--max-connections` semaphore (a permit is held for the
//! session's lifetime, mirroring one real client connection each).

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use hdrhistogram::Histogram;
use mysql_async::prelude::Queryable;
use mysql_async::{Conn, Opts, OptsBuilder};
use tokio::sync::Semaphore;

use crate::classify::{is_use_statement, should_execute};
use crate::format::{read_capture, Event};
use crate::report::{
    redact_url, FingerprintReport, ReportFlags, RunReport, SaturationReport, Totals,
};

/// Replay pacing mode. M1 only implements `max` (each session fires its next
/// query as soon as the previous one completes); faithful-timing pacing is a
/// planned M2 addition that slots into [`Pacer::pace`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Speed {
    Max,
}

impl Speed {
    pub fn as_str(self) -> &'static str {
        match self {
            Speed::Max => "max",
        }
    }
}

enum Pacer {
    Max,
}

impl Pacer {
    fn new(speed: Speed) -> Self {
        match speed {
            Speed::Max => Pacer::Max,
        }
    }

    /// Wait until `event` is due. `Speed::Max` never waits.
    async fn pace(&self, _event: &Event) {
        match self {
            Pacer::Max => {}
        }
    }
}

#[derive(Clone, Debug)]
pub struct ReplayOptions {
    pub url: String,
    pub max_connections: usize,
    pub allow_writes: bool,
    pub read_only: bool,
    pub db_override: Option<String>,
    pub speed: Speed,
}

struct FpAgg {
    hist: Histogram<u64>,
    executed: u64,
    errors: u64,
    first_error: Option<String>,
    skipped: u64,
    not_run: u64,
}

impl FpAgg {
    fn new() -> Self {
        FpAgg {
            hist: Histogram::new_with_bounds(1, 3_600_000_000, 3)
                .expect("static histogram bounds are valid"),
            executed: 0,
            errors: 0,
            first_error: None,
            skipped: 0,
            not_run: 0,
        }
    }
}

#[derive(Default)]
struct Metrics {
    per_fp: Mutex<HashMap<u32, FpAgg>>,
    executed: AtomicU64,
    skipped: AtomicU64,
    errors: AtomicU64,
    not_run: AtomicU64,
    connect_failures: AtomicU64,
}

impl Metrics {
    fn with_fp(&self, fp: u32, f: impl FnOnce(&mut FpAgg)) {
        let mut map = self.per_fp.lock().expect("metrics lock");
        f(map.entry(fp).or_insert_with(FpAgg::new));
    }

    fn record_ok(&self, fp: u32, micros: u64) {
        self.executed.fetch_add(1, Ordering::Relaxed);
        self.with_fp(fp, |agg| {
            agg.executed += 1;
            agg.hist.saturating_record(micros.max(1));
        });
    }

    fn record_err(&self, fp: u32, msg: &str) {
        self.errors.fetch_add(1, Ordering::Relaxed);
        let msg = truncate(msg, 300);
        self.with_fp(fp, |agg| {
            agg.errors += 1;
            if agg.first_error.is_none() {
                agg.first_error = Some(msg);
            }
        });
    }

    fn record_skip(&self, fp: u32) {
        self.skipped.fetch_add(1, Ordering::Relaxed);
        self.with_fp(fp, |agg| agg.skipped += 1);
    }

    fn record_not_run(&self, fp: u32) {
        self.not_run.fetch_add(1, Ordering::Relaxed);
        self.with_fp(fp, |agg| agg.not_run += 1);
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

/// Group events into per-session vectors, preserving capture order within
/// each session and first-appearance order between sessions.
fn group_sessions(events: Vec<Event>) -> Vec<Vec<Event>> {
    let mut order: Vec<u64> = Vec::new();
    let mut map: HashMap<u64, Vec<Event>> = HashMap::new();
    for e in events {
        let sid = e.session_id;
        match map.entry(sid) {
            std::collections::hash_map::Entry::Occupied(mut o) => o.get_mut().push(e),
            std::collections::hash_map::Entry::Vacant(v) => {
                order.push(sid);
                v.insert(vec![e]);
            }
        }
    }
    order
        .into_iter()
        .map(|sid| map.remove(&sid).expect("session recorded in order list"))
        .collect()
}

fn is_fatal(e: &mysql_async::Error) -> bool {
    matches!(e, mysql_async::Error::Io(_) | mysql_async::Error::Driver(_))
}

#[allow(clippy::too_many_arguments)]
async fn run_session(
    events: Vec<Event>,
    opts: Opts,
    sem: Arc<Semaphore>,
    waiters: Arc<AtomicU64>,
    metrics: Arc<Metrics>,
    allow_writes: bool,
    use_event_db: bool,
    pacer: Arc<Pacer>,
) {
    // SAFETY GATE: without --allow-writes, non-read statements are skipped
    // (and counted) before they can ever reach the wire.
    let session_id = events.first().map(|e| e.session_id).unwrap_or(0);
    if !events
        .iter()
        .any(|e| should_execute(&e.query, allow_writes))
    {
        for e in &events {
            metrics.record_skip(e.fingerprint_id);
        }
        return;
    }

    waiters.fetch_add(1, Ordering::SeqCst);
    let permit = sem
        .clone()
        .acquire_owned()
        .await
        .expect("replay semaphore is never closed");
    waiters.fetch_sub(1, Ordering::SeqCst);
    let _permit = permit;

    let mut conn = match Conn::new(opts).await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(session_id, error = %e, "session connect failed");
            metrics.connect_failures.fetch_add(1, Ordering::Relaxed);
            for e in &events {
                metrics.record_not_run(e.fingerprint_id);
            }
            return;
        }
    };

    let mut current_db: Option<String> = None;
    let mut it = events.into_iter();
    while let Some(ev) = it.next() {
        pacer.pace(&ev).await;

        if !should_execute(&ev.query, allow_writes) {
            metrics.record_skip(ev.fingerprint_id);
            continue;
        }

        // With --db-override every session is pinned to the override
        // database; a captured USE statement would silently unpin it, so
        // skip (and count) those instead of executing them.
        if !use_event_db && is_use_statement(&ev.query) {
            metrics.record_skip(ev.fingerprint_id);
            continue;
        }

        if use_event_db {
            if let Some(db) = ev.db.as_deref() {
                if current_db.as_deref() != Some(db) {
                    let stmt = format!("USE `{}`", db.replace('`', "``"));
                    match conn.query_drop(stmt).await {
                        Ok(()) => current_db = Some(db.to_string()),
                        Err(e) => {
                            metrics.record_err(ev.fingerprint_id, &format!("USE `{db}`: {e}"));
                            if is_fatal(&e) {
                                for rest in it.by_ref() {
                                    metrics.record_not_run(rest.fingerprint_id);
                                }
                                return;
                            }
                            // Running the query against the wrong db would
                            // skew results; skip this event instead.
                            continue;
                        }
                    }
                }
            }
        }

        let t0 = Instant::now();
        match conn.query_drop(ev.query.as_str()).await {
            Ok(()) => metrics.record_ok(ev.fingerprint_id, t0.elapsed().as_micros() as u64),
            Err(e) => {
                metrics.record_err(ev.fingerprint_id, &e.to_string());
                if is_fatal(&e) {
                    tracing::warn!(session_id, error = %e, "session connection lost");
                    for rest in it.by_ref() {
                        metrics.record_not_run(rest.fingerprint_id);
                    }
                    return;
                }
            }
        }
    }
    let _ = conn.disconnect().await;
}

pub async fn run_replay(capture_path: &Path, options: ReplayOptions) -> Result<RunReport> {
    let cap = read_capture(capture_path)?;

    let mut conn_opts = Opts::from_url(&options.url).context("invalid --url")?;
    let use_event_db = options.db_override.is_none();
    if let Some(db) = &options.db_override {
        conn_opts = OptsBuilder::from_opts(conn_opts)
            .db_name(Some(db.clone()))
            .into();
    }

    // Probe: validates connectivity and grabs the server version up front.
    let mut probe = Conn::new(conn_opts.clone())
        .await
        .with_context(|| format!("cannot connect to target {}", redact_url(&options.url)))?;
    let target_server_version: String = probe
        .query_first("SELECT VERSION()")
        .await?
        .unwrap_or_default();
    probe.disconnect().await?;

    let sessions = group_sessions(cap.events);
    let session_count = sessions.len() as u64;
    let event_count = cap.summary.event_count;

    let sem = Arc::new(Semaphore::new(options.max_connections.max(1)));
    let waiters = Arc::new(AtomicU64::new(0));
    let metrics = Arc::new(Metrics::default());
    let pacer = Arc::new(Pacer::new(options.speed));

    // Saturation sampler: counts intervals in which every permit was taken
    // while at least one session was waiting for one.
    let sat_samples = Arc::new(AtomicU64::new(0));
    let sat_hits = Arc::new(AtomicU64::new(0));
    let (stop_tx, mut stop_rx) = tokio::sync::watch::channel(false);
    let sampler = {
        let sem = sem.clone();
        let waiters = waiters.clone();
        let sat_samples = sat_samples.clone();
        let sat_hits = sat_hits.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_millis(50));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = tick.tick() => {
                        sat_samples.fetch_add(1, Ordering::Relaxed);
                        if sem.available_permits() == 0 && waiters.load(Ordering::SeqCst) > 0 {
                            sat_hits.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    _ = stop_rx.changed() => break,
                }
            }
        })
    };

    let started_at = time::OffsetDateTime::now_utc();
    let t0 = Instant::now();

    let mut tasks = tokio::task::JoinSet::new();
    for events in sessions {
        tasks.spawn(run_session(
            events,
            conn_opts.clone(),
            sem.clone(),
            waiters.clone(),
            metrics.clone(),
            options.allow_writes,
            use_event_db,
            pacer.clone(),
        ));
    }
    while let Some(res) = tasks.join_next().await {
        res.context("replay session task panicked")?;
    }

    let wall = t0.elapsed();
    let ended_at = time::OffsetDateTime::now_utc();
    let _ = stop_tx.send(true);
    let _ = sampler.await;

    let samples = sat_samples.load(Ordering::Relaxed);
    let hits = sat_hits.load(Ordering::Relaxed);
    let saturated_pct = if samples > 0 {
        hits as f64 * 100.0 / samples as f64
    } else {
        0.0
    };

    let executed = metrics.executed.load(Ordering::Relaxed);
    let fp_texts: HashMap<u32, &str> = cap
        .summary
        .fingerprints
        .iter()
        .map(|e| (e.id, e.text.as_str()))
        .collect();
    let per_fp = std::mem::take(&mut *metrics.per_fp.lock().expect("metrics lock"));
    let mut fingerprints: Vec<FingerprintReport> = per_fp
        .into_iter()
        .map(|(id, agg)| FingerprintReport {
            id,
            fingerprint: fp_texts
                .get(&id)
                .map(|t| t.to_string())
                .unwrap_or_else(|| format!("<unknown fingerprint {id}>")),
            count: agg.executed,
            errors: agg.errors,
            first_error: agg.first_error,
            skipped: agg.skipped,
            not_run: agg.not_run,
            p50_us: agg.hist.value_at_quantile(0.50),
            p95_us: agg.hist.value_at_quantile(0.95),
            p99_us: agg.hist.value_at_quantile(0.99),
            max_us: agg.hist.max(),
            mean_us: agg.hist.mean(),
        })
        .collect();
    fingerprints.sort_by(|a, b| b.p95_us.cmp(&a.p95_us).then(b.count.cmp(&a.count)));

    let wall_secs = wall.as_secs_f64();
    Ok(RunReport {
        tool: "sql-replay".to_string(),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        capture_file: capture_path.display().to_string(),
        capture_dialect: cap.summary.source_dialect.clone(),
        target_url: redact_url(&options.url),
        target_server_version,
        started_at: format_rfc3339(started_at),
        ended_at: format_rfc3339(ended_at),
        wall_secs,
        flags: ReportFlags {
            max_connections: options.max_connections,
            allow_writes: options.allow_writes,
            read_only: options.read_only,
            db_override: options.db_override.clone(),
            speed: options.speed.as_str().to_string(),
        },
        totals: Totals {
            events: event_count,
            sessions: session_count,
            executed,
            skipped: metrics.skipped.load(Ordering::Relaxed),
            errors: metrics.errors.load(Ordering::Relaxed),
            not_run: metrics.not_run.load(Ordering::Relaxed),
            connect_failures: metrics.connect_failures.load(Ordering::Relaxed),
            qps: if wall_secs > 0.0 {
                executed as f64 / wall_secs
            } else {
                0.0
            },
        },
        saturation: SaturationReport {
            samples,
            saturated_samples: hits,
            saturated_pct,
        },
        fingerprints,
    })
}

fn format_rfc3339(t: time::OffsetDateTime) -> String {
    t.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(session_id: u64, query: &str) -> Event {
        Event {
            ts_micros: 0,
            session_id,
            user: None,
            db: None,
            query: query.to_string(),
            orig_query_time_s: 0.0,
            fingerprint_id: 0,
        }
    }

    #[test]
    fn group_sessions_preserves_order() {
        let events = vec![
            ev(7, "a"),
            ev(3, "b"),
            ev(7, "c"),
            ev(9, "d"),
            ev(3, "e"),
            ev(7, "f"),
        ];
        let sessions = group_sessions(events);
        assert_eq!(sessions.len(), 3);
        // Sessions appear in first-seen order...
        assert_eq!(sessions[0][0].session_id, 7);
        assert_eq!(sessions[1][0].session_id, 3);
        assert_eq!(sessions[2][0].session_id, 9);
        // ...and each session keeps its capture-order query sequence.
        let s7: Vec<&str> = sessions[0].iter().map(|e| e.query.as_str()).collect();
        assert_eq!(s7, ["a", "c", "f"]);
        let s3: Vec<&str> = sessions[1].iter().map(|e| e.query.as_str()).collect();
        assert_eq!(s3, ["b", "e"]);
    }

    #[test]
    fn truncate_respects_char_boundaries() {
        assert_eq!(truncate("abc", 10), "abc");
        let t = truncate("aé日本語 long error text", 5);
        assert!(t.chars().count() <= 6);
    }
}
