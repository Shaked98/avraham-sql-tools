//! The `replay` subcommand: run a capture against a target MySQL server.
//!
//! Concurrency model: one lightweight tokio task per original session
//! (connection thread id). Each session executes its own queries strictly
//! in capture order, reading them one at a time from the on-disk spool
//! (see `spool.rs` — peak memory is independent of capture size). By
//! default each session runs on a dedicated connection; sessions run
//! concurrently, capped by a `--max-connections` semaphore (a permit is
//! held for the session's lifetime, mirroring one real client connection
//! each). With `--pool N`, sessions instead check a connection out of a
//! bounded pool per query — connection fidelity is traded away so captures
//! with more sessions than practical connections stay replayable.
//!
//! The execution layer is generic over [`Target`] so scheduling behavior
//! (pacing, permits, abort, 10k-session scale) is testable without MySQL.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use hdrhistogram::Histogram;
use mysql_async::prelude::Queryable;
use mysql_async::{Conn, Opts, OptsBuilder};
use tokio::sync::{watch, Semaphore};

use crate::aggregate::aggregate_median;
use crate::classify::{is_use_statement, should_execute};
use crate::format::Event;
use crate::report::{
    redact_url, FingerprintReport, PacingReport, ReportFlags, RunReport, SaturationReport, Totals,
};
use crate::spool::{Filters, Spool, SpoolCursor};
use crate::target::{MySqlTarget, Target, TargetConn};

/// Replay pacing mode: `max` (each session fires its next query as soon as
/// the previous one completes) or a positive speed factor honoring the
/// capture's original timeline (1.0 = real time, 2.0 = twice as fast).
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Speed {
    Max,
    Factor(f64),
}

impl Speed {
    pub fn parse(s: &str) -> Result<Speed, String> {
        if s.eq_ignore_ascii_case("max") {
            return Ok(Speed::Max);
        }
        let f: f64 = s
            .parse()
            .map_err(|_| format!("expected `max` or a positive number, got `{s}`"))?;
        if !f.is_finite() || f <= 0.0 {
            return Err(format!("speed factor must be a positive number, got `{s}`"));
        }
        Ok(Speed::Factor(f))
    }

    pub fn label(self) -> String {
        match self {
            Speed::Max => "max".to_string(),
            // Trim a trailing `.0` so `--speed 2` round-trips as "2".
            Speed::Factor(f) => {
                let s = format!("{f}");
                s.strip_suffix(".0").unwrap_or(&s).to_string()
            }
        }
    }
}

/// Pure schedule math: micros after replay start at which an event with
/// capture timestamp `ev_ts_micros` is due, given the capture-clock origin
/// (the earliest event timestamp) and the speed factor. Inter-event gaps
/// shrink by `speed`; timestamps at or before the origin are due at once.
fn due_offset_micros(ev_ts_micros: i64, base_ts_micros: i64, speed: f64) -> u64 {
    let gap = ev_ts_micros.saturating_sub(base_ts_micros).max(0) as f64;
    (gap / speed).round() as u64
}

/// Pacing-fidelity accumulator: how far behind its schedule each paced
/// event fired. A saturated target shows up here as growing lag instead of
/// silently reshaping the workload.
#[derive(Default)]
struct LagAgg {
    paced_events: AtomicU64,
    max_lag_us: AtomicU64,
    sum_lag_us: AtomicU64,
}

impl LagAgg {
    fn record(&self, lag: Duration) {
        let us = lag.as_micros() as u64;
        self.paced_events.fetch_add(1, Ordering::Relaxed);
        self.max_lag_us.fetch_max(us, Ordering::Relaxed);
        self.sum_lag_us.fetch_add(us, Ordering::Relaxed);
    }

    fn report(&self, speed: f64) -> PacingReport {
        let n = self.paced_events.load(Ordering::Relaxed);
        let sum = self.sum_lag_us.load(Ordering::Relaxed);
        PacingReport {
            speed,
            paced_events: n,
            max_lag_us: self.max_lag_us.load(Ordering::Relaxed),
            mean_lag_us: if n > 0 { sum as f64 / n as f64 } else { 0.0 },
        }
    }
}

enum Pacer {
    Max,
    Paced {
        speed: f64,
        base_ts_micros: i64,
        start: tokio::time::Instant,
        lag: LagAgg,
    },
}

impl Pacer {
    /// `base_ts_micros` is the capture-clock origin (earliest event
    /// timestamp); the pacer's own clock starts at construction time.
    fn new(speed: Speed, base_ts_micros: i64) -> Self {
        match speed {
            Speed::Max => Pacer::Max,
            Speed::Factor(f) => Pacer::Paced {
                speed: f,
                base_ts_micros,
                start: tokio::time::Instant::now(),
                lag: LagAgg::default(),
            },
        }
    }

    fn due(&self, event: &Event) -> Option<tokio::time::Instant> {
        match self {
            Pacer::Max => None,
            Pacer::Paced {
                speed,
                base_ts_micros,
                start,
                ..
            } => Some(
                *start
                    + Duration::from_micros(due_offset_micros(
                        event.ts_micros,
                        *base_ts_micros,
                        *speed,
                    )),
            ),
        }
    }

    /// Wait until `event` is due, then record how far behind schedule it
    /// fired (an event whose predecessor overran fires immediately; the
    /// lateness is what the lag metrics capture). `Speed::Max` never waits.
    async fn pace(&self, event: &Event) {
        let Some(due) = self.due(event) else { return };
        tokio::time::sleep_until(due).await;
        if let Pacer::Paced { lag, .. } = self {
            lag.record(tokio::time::Instant::now().saturating_duration_since(due));
        }
    }

    /// Wait until `event` is due without recording lag — used before a
    /// session claims its connection permit, so late-starting sessions don't
    /// pin idle connections (or skew lag stats when the same event is paced
    /// again inside the session loop).
    async fn wait_until_due(&self, event: &Event) {
        if let Some(due) = self.due(event) {
            tokio::time::sleep_until(due).await;
        }
    }

    fn report(&self) -> Option<PacingReport> {
        match self {
            Pacer::Max => None,
            Pacer::Paced { speed, lag, .. } => Some(lag.report(*speed)),
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
    /// Multiplex sessions over a bounded pool of this many connections
    /// (per-query checkout) instead of one dedicated connection per
    /// session. Trades connection fidelity for feasibility.
    pub pool: Option<usize>,
    /// Run one unrecorded pass before the measured pass(es).
    pub warmup: bool,
    /// Number of measured passes (>= 1). With N > 1 the outcome carries a
    /// median-aggregated report alongside the per-pass reports.
    pub repeat: usize,
    /// Replay-side event filters, applied while spooling.
    pub filters: Filters,
    /// Directory for the replay spool file (default: the system temp dir).
    pub spool_dir: Option<PathBuf>,
}

impl ReplayOptions {
    pub fn new(url: impl Into<String>) -> Self {
        ReplayOptions {
            url: url.into(),
            max_connections: 50,
            allow_writes: false,
            read_only: false,
            db_override: None,
            speed: Speed::Max,
            pool: None,
            warmup: false,
            repeat: 1,
            filters: Filters::default(),
            spool_dir: None,
        }
    }

    /// Connections the run can hold open at once.
    fn connection_cap(&self) -> usize {
        self.pool.unwrap_or(self.max_connections).max(1)
    }
}

/// Target identity recorded into each run report; probed from MySQL by
/// [`run_replay`], supplied by hand when driving a test target.
#[derive(Clone, Debug, Default)]
pub struct TargetInfo {
    pub server_version: String,
    pub settings: std::collections::BTreeMap<String, String>,
}

/// What a replay produced: one report per measured pass, plus the
/// median-aggregated report when `--repeat N > 1`.
#[derive(Debug)]
pub struct ReplayOutcome {
    pub passes: Vec<RunReport>,
    pub aggregated: Option<RunReport>,
}

impl ReplayOutcome {
    /// The headline report: the aggregate when present, else the single
    /// (or last partial) pass.
    pub fn primary(&self) -> &RunReport {
        self.aggregated
            .as_ref()
            .or_else(|| self.passes.last())
            .expect("a replay outcome always has at least one report")
    }

    pub fn aborted(&self) -> bool {
        self.passes.iter().any(|p| p.aborted)
    }
}

/// A session's events, delivered one at a time in capture order. The
/// production implementation is the spool cursor; a Vec-backed one exists
/// as the in-memory reference for equivalence tests.
pub trait EventStream: Send + 'static {
    fn next_event(&mut self) -> Result<Option<Event>>;
}

impl EventStream for SpoolCursor {
    fn next_event(&mut self) -> Result<Option<Event>> {
        SpoolCursor::next_event(self)
    }
}

/// In-memory event stream (reference path for equivalence testing).
pub struct VecEvents(std::vec::IntoIter<Event>);

impl EventStream for VecEvents {
    fn next_event(&mut self) -> Result<Option<Event>> {
        Ok(self.0.next())
    }
}

/// Per-session scheduling metadata precomputed at spool-build time.
#[derive(Clone, Debug)]
pub struct SessionMeta {
    pub session_id: u64,
    /// Whether any event passes the write gate; a session with none never
    /// paces or connects — its events are all recorded as skipped.
    pub has_executable: bool,
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
/// each session and first-appearance order between sessions (the in-memory
/// reference for what the spool does on disk).
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

/// Resolves when the shutdown flag flips to true; pends forever if the
/// sender is gone (no abort will ever come).
async fn wait_aborted(shutdown: &mut watch::Receiver<bool>) {
    if shutdown.wait_for(|aborted| *aborted).await.is_err() {
        std::future::pending::<()>().await;
    }
}

/// If a connect error looks like file-descriptor exhaustion, log an
/// actionable hint once.
fn hint_if_fd_exhausted(msg: &str) {
    if msg.contains("Too many open files") || msg.contains("os error 24") {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            tracing::error!(
                "the process ran out of file descriptors mid-run: raise the open-files \
                 limit (`ulimit -n`, or LimitNOFILE= under systemd) or lower \
                 --max-connections/--pool"
            );
        });
    }
}

/// Fail fast, with an actionable message, when the requested connection cap
/// cannot fit under the process's open-files limit.
pub fn check_fd_headroom(connections: usize, soft_limit: u64) -> Result<()> {
    // stdio + spool + tokio epoll/eventfd + a little slack for teardown.
    const MARGIN: u64 = 32;
    let needed = connections as u64 + MARGIN;
    if needed > soft_limit {
        bail!(
            "the requested connection cap ({connections}) needs ~{needed} file \
             descriptors but the open-files limit is {soft_limit}. Raise it \
             (`ulimit -n {suggest}` in this shell, or LimitNOFILE={suggest} in the \
             systemd unit) or lower --max-connections/--pool.",
            suggest = needed.div_ceil(1024) * 1024,
        );
    }
    Ok(())
}

fn nofile_soft_limit() -> Option<u64> {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes into the struct we hand it; no other state.
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) };
    (rc == 0).then_some(lim.rlim_cur)
}

/// Bounded connection pool for `--pool`: sessions check a connection out
/// per query. Capacity is enforced by the pass's semaphore (a checkout
/// happens only under a held permit), so `idle` is just the reuse shelf.
struct ConnPool<T: Target> {
    idle: Mutex<Vec<IdleConn<T>>>,
    /// The database new/idle connections start in (from the URL or
    /// --db-override), for per-query `USE` reconciliation.
    default_db: Option<String>,
}

struct IdleConn<T: Target> {
    conn: T::Conn,
    db: Option<String>,
}

impl<T: Target> ConnPool<T> {
    fn new(default_db: Option<String>) -> Self {
        ConnPool {
            idle: Mutex::new(Vec::new()),
            default_db,
        }
    }

    async fn checkout(&self, target: &T) -> Result<IdleConn<T>, crate::target::TargetError> {
        if let Some(idle) = self.idle.lock().expect("pool lock").pop() {
            return Ok(idle);
        }
        let conn = target.connect().await?;
        Ok(IdleConn {
            conn,
            db: self.default_db.clone(),
        })
    }

    fn checkin(&self, conn: IdleConn<T>) {
        self.idle.lock().expect("pool lock").push(conn);
    }

    async fn drain(&self) {
        let conns = std::mem::take(&mut *self.idle.lock().expect("pool lock"));
        for c in conns {
            c.conn.disconnect().await;
        }
    }
}

/// Everything a session task needs, shared across one pass.
struct PassCtx<T: Target> {
    target: T,
    sem: Arc<Semaphore>,
    waiters: AtomicU64,
    metrics: Metrics,
    pacer: Pacer,
    allow_writes: bool,
    use_event_db: bool,
    pool: Option<ConnPool<T>>,
    shutdown: watch::Receiver<bool>,
}

enum DrainAs {
    Skipped,
    NotRun,
}

/// Record every remaining event of a stream as skipped or not-run.
fn drain_recording(events: &mut impl EventStream, metrics: &Metrics, how: DrainAs) {
    loop {
        match events.next_event() {
            Ok(Some(e)) => match how {
                DrainAs::Skipped => metrics.record_skip(e.fingerprint_id),
                DrainAs::NotRun => metrics.record_not_run(e.fingerprint_id),
            },
            Ok(None) => return,
            Err(err) => {
                tracing::error!(error = %err, "spool read failed while draining a session");
                return;
            }
        }
    }
}

async fn run_session<T: Target, S: EventStream>(
    meta: SessionMeta,
    mut events: S,
    ctx: Arc<PassCtx<T>>,
) {
    // SAFETY GATE: without --allow-writes, a session whose statements are
    // all non-read never paces or connects — everything is skipped and
    // counted before it can ever reach the wire.
    if !meta.has_executable {
        drain_recording(&mut events, &ctx.metrics, DrainAs::Skipped);
        return;
    }
    if ctx.pool.is_some() {
        run_session_pooled(meta, events, ctx).await
    } else {
        run_session_dedicated(meta, events, ctx).await
    }
}

async fn run_session_dedicated<T: Target, S: EventStream>(
    meta: SessionMeta,
    mut events: S,
    ctx: Arc<PassCtx<T>>,
) {
    let session_id = meta.session_id;
    let mut shutdown = ctx.shutdown.clone();

    let first = match events.next_event() {
        Ok(Some(e)) => e,
        Ok(None) => return,
        Err(err) => {
            tracing::error!(session_id, error = %err, "spool read failed");
            return;
        }
    };

    // Don't claim a connection permit until the session's first event is
    // due — a session that starts late in the capture would otherwise pin
    // an idle connection for the whole lead-in.
    tokio::select! {
        biased;
        _ = wait_aborted(&mut shutdown) => {
            ctx.metrics.record_not_run(first.fingerprint_id);
            drain_recording(&mut events, &ctx.metrics, DrainAs::NotRun);
            return;
        }
        _ = ctx.pacer.wait_until_due(&first) => {}
    }

    ctx.waiters.fetch_add(1, Ordering::SeqCst);
    let permit = tokio::select! {
        biased;
        _ = wait_aborted(&mut shutdown) => {
            ctx.waiters.fetch_sub(1, Ordering::SeqCst);
            ctx.metrics.record_not_run(first.fingerprint_id);
            drain_recording(&mut events, &ctx.metrics, DrainAs::NotRun);
            return;
        }
        permit = ctx.sem.clone().acquire_owned() => {
            permit.expect("replay semaphore is never closed")
        }
    };
    ctx.waiters.fetch_sub(1, Ordering::SeqCst);
    let _permit = permit;

    let mut conn = match ctx.target.connect().await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(session_id, error = %e, "session connect failed");
            hint_if_fd_exhausted(&e.message);
            ctx.metrics.connect_failures.fetch_add(1, Ordering::Relaxed);
            ctx.metrics.record_not_run(first.fingerprint_id);
            drain_recording(&mut events, &ctx.metrics, DrainAs::NotRun);
            return;
        }
    };

    let mut current_db: Option<String> = None;
    let mut pending = Some(first);
    loop {
        let ev = match pending.take() {
            Some(e) => e,
            None => match events.next_event() {
                Ok(Some(e)) => e,
                Ok(None) => break,
                Err(err) => {
                    tracing::error!(session_id, error = %err, "spool read failed");
                    break;
                }
            },
        };

        if *shutdown.borrow() {
            ctx.metrics.record_not_run(ev.fingerprint_id);
            drain_recording(&mut events, &ctx.metrics, DrainAs::NotRun);
            break;
        }
        tokio::select! {
            biased;
            _ = wait_aborted(&mut shutdown) => {
                ctx.metrics.record_not_run(ev.fingerprint_id);
                drain_recording(&mut events, &ctx.metrics, DrainAs::NotRun);
                break;
            }
            _ = ctx.pacer.pace(&ev) => {}
        }

        if !should_execute(&ev.query, ctx.allow_writes) {
            ctx.metrics.record_skip(ev.fingerprint_id);
            continue;
        }

        // With --db-override every session is pinned to the override
        // database; a captured USE statement would silently unpin it, so
        // skip (and count) those instead of executing them.
        if !ctx.use_event_db && is_use_statement(&ev.query) {
            ctx.metrics.record_skip(ev.fingerprint_id);
            continue;
        }

        if ctx.use_event_db {
            if let Some(db) = ev.db.as_deref() {
                if current_db.as_deref() != Some(db) {
                    let stmt = format!("USE `{}`", db.replace('`', "``"));
                    match conn.query(&stmt).await {
                        Ok(()) => current_db = Some(db.to_string()),
                        Err(e) => {
                            ctx.metrics
                                .record_err(ev.fingerprint_id, &format!("USE `{db}`: {e}"));
                            if e.fatal {
                                drain_recording(&mut events, &ctx.metrics, DrainAs::NotRun);
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
        match conn.query(&ev.query).await {
            Ok(()) => ctx
                .metrics
                .record_ok(ev.fingerprint_id, t0.elapsed().as_micros() as u64),
            Err(e) => {
                ctx.metrics.record_err(ev.fingerprint_id, &e.message);
                if e.fatal {
                    tracing::warn!(session_id, error = %e, "session connection lost");
                    drain_recording(&mut events, &ctx.metrics, DrainAs::NotRun);
                    return;
                }
            }
        }
    }
    conn.disconnect().await;
}

async fn run_session_pooled<T: Target, S: EventStream>(
    meta: SessionMeta,
    mut events: S,
    ctx: Arc<PassCtx<T>>,
) {
    let session_id = meta.session_id;
    let mut shutdown = ctx.shutdown.clone();
    let pool = ctx.pool.as_ref().expect("pooled session has a pool");

    loop {
        let ev = match events.next_event() {
            Ok(Some(e)) => e,
            Ok(None) => return,
            Err(err) => {
                tracing::error!(session_id, error = %err, "spool read failed");
                return;
            }
        };

        if *shutdown.borrow() {
            ctx.metrics.record_not_run(ev.fingerprint_id);
            drain_recording(&mut events, &ctx.metrics, DrainAs::NotRun);
            return;
        }
        tokio::select! {
            biased;
            _ = wait_aborted(&mut shutdown) => {
                ctx.metrics.record_not_run(ev.fingerprint_id);
                drain_recording(&mut events, &ctx.metrics, DrainAs::NotRun);
                return;
            }
            _ = ctx.pacer.pace(&ev) => {}
        }

        if !should_execute(&ev.query, ctx.allow_writes) {
            ctx.metrics.record_skip(ev.fingerprint_id);
            continue;
        }
        // Pooled sessions have no sticky connection a USE could stick to;
        // the per-event db metadata drives USE reconciliation instead.
        if is_use_statement(&ev.query) {
            ctx.metrics.record_skip(ev.fingerprint_id);
            continue;
        }

        // One permit per query: the permit is the pool-capacity bound.
        ctx.waiters.fetch_add(1, Ordering::SeqCst);
        let permit = tokio::select! {
            biased;
            _ = wait_aborted(&mut shutdown) => {
                ctx.waiters.fetch_sub(1, Ordering::SeqCst);
                ctx.metrics.record_not_run(ev.fingerprint_id);
                drain_recording(&mut events, &ctx.metrics, DrainAs::NotRun);
                return;
            }
            permit = ctx.sem.clone().acquire_owned() => {
                permit.expect("replay semaphore is never closed")
            }
        };
        ctx.waiters.fetch_sub(1, Ordering::SeqCst);
        let _permit = permit;

        let mut pc = match pool.checkout(&ctx.target).await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(session_id, error = %e, "pooled connect failed");
                hint_if_fd_exhausted(&e.message);
                ctx.metrics.connect_failures.fetch_add(1, Ordering::Relaxed);
                ctx.metrics.record_not_run(ev.fingerprint_id);
                continue;
            }
        };

        // Reconcile the connection's current database with the event's.
        if ctx.use_event_db {
            if let Some(db) = ev.db.as_deref() {
                if pc.db.as_deref() != Some(db) {
                    let stmt = format!("USE `{}`", db.replace('`', "``"));
                    match pc.conn.query(&stmt).await {
                        Ok(()) => pc.db = Some(db.to_string()),
                        Err(e) => {
                            ctx.metrics
                                .record_err(ev.fingerprint_id, &format!("USE `{db}`: {e}"));
                            if !e.fatal {
                                pool.checkin(pc);
                            }
                            // A dead pooled connection doesn't kill the
                            // logical session; the next event gets a fresh
                            // checkout.
                            continue;
                        }
                    }
                }
            }
        }

        let t0 = Instant::now();
        match pc.conn.query(&ev.query).await {
            Ok(()) => {
                ctx.metrics
                    .record_ok(ev.fingerprint_id, t0.elapsed().as_micros() as u64);
                pool.checkin(pc);
            }
            Err(e) => {
                ctx.metrics.record_err(ev.fingerprint_id, &e.message);
                if !e.fatal {
                    pool.checkin(pc);
                }
            }
        }
    }
}

/// Static, per-run capture facts shared by every pass's report.
struct CaptureInfo {
    file: String,
    dialect: String,
    fp_texts: HashMap<u32, String>,
    /// Events included in the replay (post-filter).
    events: u64,
    filtered: u64,
    sessions: u64,
    base_ts_micros: i64,
}

async fn run_pass<T: Target, S: EventStream>(
    sessions: Vec<(SessionMeta, S)>,
    cap: &CaptureInfo,
    options: &ReplayOptions,
    target: &T,
    info: &TargetInfo,
    shutdown: watch::Receiver<bool>,
) -> Result<RunReport> {
    let use_event_db = options.db_override.is_none();
    let default_db = options.db_override.clone().or_else(|| {
        Opts::from_url(&options.url)
            .ok()
            .and_then(|o| o.db_name().map(str::to_string))
    });

    let ctx = Arc::new(PassCtx {
        target: target.clone(),
        sem: Arc::new(Semaphore::new(options.connection_cap())),
        waiters: AtomicU64::new(0),
        metrics: Metrics::default(),
        pacer: Pacer::new(options.speed, cap.base_ts_micros),
        allow_writes: options.allow_writes,
        use_event_db,
        pool: options.pool.map(|_| ConnPool::new(default_db)),
        shutdown: shutdown.clone(),
    });

    // Saturation sampler: counts intervals in which every permit was taken
    // while at least one session was waiting for one.
    let sat_samples = Arc::new(AtomicU64::new(0));
    let sat_hits = Arc::new(AtomicU64::new(0));
    let (stop_tx, mut stop_rx) = tokio::sync::watch::channel(false);
    let sampler = {
        let ctx = ctx.clone();
        let sat_samples = sat_samples.clone();
        let sat_hits = sat_hits.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_millis(50));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = tick.tick() => {
                        sat_samples.fetch_add(1, Ordering::Relaxed);
                        if ctx.sem.available_permits() == 0
                            && ctx.waiters.load(Ordering::SeqCst) > 0
                        {
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
    for (meta, events) in sessions {
        tasks.spawn(run_session(meta, events, ctx.clone()));
    }
    while let Some(res) = tasks.join_next().await {
        res.context("replay session task panicked")?;
    }

    if let Some(pool) = &ctx.pool {
        pool.drain().await;
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

    let metrics = &ctx.metrics;
    let executed = metrics.executed.load(Ordering::Relaxed);
    let per_fp = std::mem::take(&mut *metrics.per_fp.lock().expect("metrics lock"));
    let mut fingerprints: Vec<FingerprintReport> = per_fp
        .into_iter()
        .map(|(id, agg)| FingerprintReport {
            id,
            fingerprint: cap
                .fp_texts
                .get(&id)
                .cloned()
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
        capture_file: cap.file.clone(),
        capture_dialect: cap.dialect.clone(),
        target_url: redact_url(&options.url),
        target_server_version: info.server_version.clone(),
        started_at: format_rfc3339(started_at),
        ended_at: format_rfc3339(ended_at),
        wall_secs,
        aborted: *shutdown.borrow(),
        aggregation: None,
        flags: ReportFlags {
            max_connections: options.max_connections,
            allow_writes: options.allow_writes,
            read_only: options.read_only,
            db_override: options.db_override.clone(),
            speed: options.speed.label(),
            pool: options.pool,
            warmup: options.warmup,
            filter_db: options.filters.db.clone(),
            filter_user: options.filters.user.clone(),
            time_window: options.filters.window.as_ref().map(|w| w.raw.clone()),
        },
        totals: Totals {
            events: cap.events,
            sessions: cap.sessions,
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
            filtered: cap.filtered,
        },
        saturation: SaturationReport {
            samples,
            saturated_samples: hits,
            saturated_pct,
        },
        pacing: ctx.pacer.report(),
        target_settings: info.settings.clone(),
        fingerprints,
    })
}

/// Warmup + `--repeat N` pass loop over a session factory (each pass gets
/// fresh event streams).
async fn run_passes<T: Target, S: EventStream>(
    mk_sessions: impl Fn() -> Vec<(SessionMeta, S)>,
    cap: &CaptureInfo,
    options: &ReplayOptions,
    target: &T,
    info: &TargetInfo,
    shutdown: watch::Receiver<bool>,
) -> Result<ReplayOutcome> {
    let repeat = options.repeat.max(1);
    let mut passes: Vec<RunReport> = Vec::with_capacity(repeat);

    if options.warmup && !*shutdown.borrow() {
        tracing::info!("warmup pass (results discarded)");
        let report = run_pass(mk_sessions(), cap, options, target, info, shutdown.clone()).await?;
        if report.aborted {
            // Aborted during warmup: surface the partial warmup report
            // rather than nothing.
            return Ok(ReplayOutcome {
                passes: vec![report],
                aggregated: None,
            });
        }
    }

    for pass_no in 1..=repeat {
        if *shutdown.borrow() && !passes.is_empty() {
            break;
        }
        if repeat > 1 {
            tracing::info!(pass = pass_no, of = repeat, "measured pass");
        }
        let report = run_pass(mk_sessions(), cap, options, target, info, shutdown.clone()).await?;
        let aborted = report.aborted;
        passes.push(report);
        if aborted {
            break;
        }
    }

    let aggregated = (repeat > 1).then(|| aggregate_median(&passes));
    Ok(ReplayOutcome { passes, aggregated })
}

/// Replay via the bounded-memory spool (the production path), against any
/// [`Target`]. Public so scale/abort tests can drive it with a mock target.
pub async fn run_replay_with_target<T: Target>(
    capture_path: &Path,
    options: &ReplayOptions,
    target: T,
    info: TargetInfo,
    shutdown: watch::Receiver<bool>,
) -> Result<ReplayOutcome> {
    let spool = Spool::build(
        capture_path,
        options.spool_dir.as_deref(),
        &options.filters,
        options.allow_writes,
    )?;
    tracing::info!(
        events = spool.event_count,
        filtered = spool.filtered,
        sessions = spool.sessions.len(),
        spool_mb = spool.bytes / (1024 * 1024),
        "capture spooled for replay"
    );
    let cap = CaptureInfo {
        file: capture_path.display().to_string(),
        dialect: spool.summary.source_dialect.clone(),
        fp_texts: spool
            .summary
            .fingerprints
            .iter()
            .map(|e| (e.id, e.text.clone()))
            .collect(),
        events: spool.event_count,
        filtered: spool.filtered,
        sessions: spool.sessions.len() as u64,
        base_ts_micros: spool.base_ts_micros,
    };
    let mk_sessions = || {
        spool
            .sessions
            .iter()
            .map(|s| {
                (
                    SessionMeta {
                        session_id: s.session_id,
                        has_executable: s.has_executable,
                    },
                    spool.cursor(s),
                )
            })
            .collect::<Vec<_>>()
    };
    run_passes(mk_sessions, &cap, options, &target, &info, shutdown).await
}

/// Replay with fully in-memory ingestion. This is the reference
/// implementation the spool path is tested for equivalence against; the
/// production entry points always stream via the spool.
pub async fn run_replay_in_memory_with_target<T: Target>(
    capture_path: &Path,
    options: &ReplayOptions,
    target: T,
    info: TargetInfo,
    shutdown: watch::Receiver<bool>,
) -> Result<ReplayOutcome> {
    let capture = crate::format::read_capture(capture_path)?;
    let total = capture.events.len() as u64;
    let events: Vec<Event> = capture
        .events
        .into_iter()
        .filter(|e| options.filters.matches(e))
        .collect();
    let filtered = total - events.len() as u64;
    if events.is_empty() && filtered > 0 {
        bail!(
            "filters excluded all {filtered} events of {} — nothing to replay",
            capture_path.display()
        );
    }
    let base_ts_micros = events.iter().map(|e| e.ts_micros).min().unwrap_or(0);
    let grouped = group_sessions(events);
    let cap = CaptureInfo {
        file: capture_path.display().to_string(),
        dialect: capture.summary.source_dialect.clone(),
        fp_texts: capture
            .summary
            .fingerprints
            .iter()
            .map(|e| (e.id, e.text.clone()))
            .collect(),
        events: total - filtered,
        filtered,
        sessions: grouped.len() as u64,
        base_ts_micros,
    };
    let mk_sessions = || {
        grouped
            .iter()
            .map(|events| {
                (
                    SessionMeta {
                        session_id: events.first().map(|e| e.session_id).unwrap_or(0),
                        has_executable: events
                            .iter()
                            .any(|e| should_execute(&e.query, options.allow_writes)),
                    },
                    VecEvents(events.clone().into_iter()),
                )
            })
            .collect::<Vec<_>>()
    };
    run_passes(mk_sessions, &cap, options, &target, &info, shutdown).await
}

/// Replay against the MySQL target named by `options.url`, aborting
/// gracefully (partial report, `aborted: true`) when `shutdown` flips.
pub async fn run_replay_with_shutdown(
    capture_path: &Path,
    options: ReplayOptions,
    shutdown: watch::Receiver<bool>,
) -> Result<ReplayOutcome> {
    if let Some(limit) = nofile_soft_limit() {
        check_fd_headroom(options.connection_cap(), limit)?;
    }

    let mut conn_opts = Opts::from_url(&options.url).context("invalid --url")?;
    if let Some(db) = &options.db_override {
        conn_opts = OptsBuilder::from_opts(conn_opts)
            .db_name(Some(db.clone()))
            .into();
    }

    // Probe: validates connectivity and grabs the server version plus the
    // comparability-relevant settings up front.
    let mut probe = Conn::new(conn_opts.clone())
        .await
        .with_context(|| format!("cannot connect to target {}", redact_url(&options.url)))?;
    let target_server_version: String = probe
        .query_first("SELECT VERSION()")
        .await?
        .unwrap_or_default();
    let settings = collect_target_settings(&mut probe).await;
    probe.disconnect().await?;

    let info = TargetInfo {
        server_version: target_server_version,
        settings,
    };
    let target = MySqlTarget::new(conn_opts);
    run_replay_with_target(capture_path, &options, target, info, shutdown).await
}

/// Waits for Ctrl-C; never resolves if the handler cannot be installed.
async fn wait_ctrl_c() {
    if tokio::signal::ctrl_c().await.is_err() {
        std::future::pending::<()>().await;
    }
}

/// Waits for the next SIGTERM on an optional stream; never resolves if the
/// handler is absent or the stream ends.
async fn wait_sigterm(sig: &mut Option<tokio::signal::unix::Signal>) {
    if let Some(sig) = sig {
        if sig.recv().await.is_some() {
            return;
        }
    }
    std::future::pending::<()>().await;
}

/// Replay with Ctrl-C and SIGTERM wired to a graceful abort: in-flight
/// queries finish, everything else is recorded as not-run, and the
/// (partial) report is still produced with `aborted: true`. A second
/// Ctrl-C or SIGTERM exits immediately. SIGTERM matters because systemd
/// (the documented RHEL 8 deployment) stops units with it.
pub async fn run_replay(capture_path: &Path, options: ReplayOptions) -> Result<ReplayOutcome> {
    let (tx, rx) = watch::channel(false);
    tokio::spawn(async move {
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
        let received = tokio::select! {
            _ = wait_ctrl_c() => "Ctrl-C",
            _ = wait_sigterm(&mut sigterm) => "SIGTERM",
        };
        eprintln!(
            "\nreceived {received}: finishing in-flight queries and writing a partial \
             report (a second Ctrl-C or SIGTERM exits immediately)"
        );
        let _ = tx.send(true);
        tokio::select! {
            _ = wait_ctrl_c() => {},
            _ = wait_sigterm(&mut sigterm) => {},
        }
        std::process::exit(130);
    });
    run_replay_with_shutdown(capture_path, options, rx).await
}

/// Comparability-relevant target variables recorded into the run report so
/// `compare` can flag runs taken against differently-configured servers.
/// Read-only and tolerant of variables missing on either version
/// (`transaction_isolation` replaced `tx_isolation` across 5.7 → 8.0).
async fn collect_target_settings(conn: &mut Conn) -> std::collections::BTreeMap<String, String> {
    let mut out = std::collections::BTreeMap::new();
    let names = [
        "sql_mode",
        "character_set_server",
        "collation_server",
        "innodb_buffer_pool_size",
    ];
    for name in names {
        if let Some(v) = show_variable(conn, name).await {
            out.insert(name.to_string(), v);
        }
    }
    // Canonicalize the isolation level under one key: MySQL 8.0 only has
    // transaction_isolation, pre-5.7.20 only tx_isolation, 5.7.20+ has both.
    for name in ["transaction_isolation", "tx_isolation"] {
        if let Some(v) = show_variable(conn, name).await {
            out.insert("transaction_isolation".to_string(), v);
            break;
        }
    }
    out
}

async fn show_variable(conn: &mut Conn, name: &str) -> Option<String> {
    // SHOW VARIABLES LIKE returns no row (rather than an error) for
    // variables the server doesn't have, and always returns strings.
    let row: Option<(String, String)> = match conn
        .query_first(format!("SHOW VARIABLES LIKE '{name}'"))
        .await
    {
        Ok(row) => row,
        Err(e) => {
            tracing::warn!(variable = name, error = %e, "failed to read target variable");
            None
        }
    };
    row.map(|(_, v)| v)
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

    #[test]
    fn speed_parses_max_and_factors() {
        assert_eq!(Speed::parse("max").unwrap(), Speed::Max);
        assert_eq!(Speed::parse("MAX").unwrap(), Speed::Max);
        assert_eq!(Speed::parse("1.0").unwrap(), Speed::Factor(1.0));
        assert_eq!(Speed::parse("0.5").unwrap(), Speed::Factor(0.5));
        assert_eq!(Speed::parse("2").unwrap(), Speed::Factor(2.0));
        assert!(Speed::parse("0").is_err());
        assert!(Speed::parse("-1").is_err());
        assert!(Speed::parse("inf").is_err());
        assert!(Speed::parse("nan").is_err());
        assert!(Speed::parse("fast").is_err());
        assert_eq!(Speed::Max.label(), "max");
        assert_eq!(Speed::Factor(1.0).label(), "1");
        assert_eq!(Speed::Factor(2.5).label(), "2.5");
    }

    #[test]
    fn due_offset_scales_gaps_by_speed() {
        let base = 1_000_000;
        // At speed 1.0 the offset is the raw gap from the capture origin.
        assert_eq!(due_offset_micros(base, base, 1.0), 0);
        assert_eq!(due_offset_micros(base + 3_000_000, base, 1.0), 3_000_000);
        // Speed 2.0 halves every gap; 0.5 doubles it.
        assert_eq!(due_offset_micros(base + 3_000_000, base, 2.0), 1_500_000);
        assert_eq!(due_offset_micros(base + 3_000_000, base, 0.5), 6_000_000);
        // Timestamps at or before the origin are due immediately.
        assert_eq!(due_offset_micros(base - 500, base, 1.0), 0);
    }

    fn paced_ev(ts_micros: i64) -> Event {
        Event {
            ts_micros,
            ..ev(1, "SELECT 1")
        }
    }

    #[tokio::test(start_paused = true)]
    async fn pacer_sleeps_until_scheduled_offset() {
        let pacer = Pacer::new(Speed::Factor(2.0), 1_000_000);
        let t0 = tokio::time::Instant::now();
        // Due at +100ms of capture time -> +50ms of replay time at 2x.
        pacer.pace(&paced_ev(1_100_000)).await;
        assert_eq!((tokio::time::Instant::now() - t0).as_millis(), 50);
        let report = pacer.report().unwrap();
        assert_eq!(report.paced_events, 1);
        assert_eq!(report.max_lag_us, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn pacer_never_fires_early_and_records_lag_when_behind() {
        let pacer = Pacer::new(Speed::Factor(1.0), 0);
        let t0 = tokio::time::Instant::now();
        pacer.pace(&paced_ev(10_000)).await; // on time at +10ms
        assert_eq!((tokio::time::Instant::now() - t0).as_millis(), 10);

        // Simulate the predecessor overrunning by 40ms past the next event's
        // +20ms due time: the event fires immediately (order preserved, no
        // extra wait) and the 40ms lateness lands in the lag metrics.
        tokio::time::advance(Duration::from_millis(50)).await;
        let before = tokio::time::Instant::now();
        pacer.pace(&paced_ev(20_000)).await;
        assert_eq!(tokio::time::Instant::now(), before);

        let report = pacer.report().unwrap();
        assert_eq!(report.paced_events, 2);
        assert_eq!(report.max_lag_us, 40_000);
        assert_eq!(report.mean_lag_us, 20_000.0);
    }

    #[tokio::test(start_paused = true)]
    async fn max_pacer_never_waits_and_reports_no_pacing() {
        let pacer = Pacer::new(Speed::Max, 0);
        let t0 = tokio::time::Instant::now();
        pacer.pace(&paced_ev(60_000_000)).await;
        assert_eq!(tokio::time::Instant::now(), t0);
        assert!(pacer.report().is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn wait_until_due_does_not_record_lag() {
        let pacer = Pacer::new(Speed::Factor(1.0), 0);
        pacer.wait_until_due(&paced_ev(30_000)).await;
        let report = pacer.report().unwrap();
        assert_eq!(report.paced_events, 0);
    }

    #[test]
    fn fd_headroom_check_is_actionable() {
        assert!(check_fd_headroom(50, 1024).is_ok());
        assert!(check_fd_headroom(992, 1024).is_ok());
        let err = check_fd_headroom(10_000, 1024).unwrap_err().to_string();
        assert!(err.contains("10000"), "names the requested cap: {err}");
        assert!(err.contains("1024"), "names the current limit: {err}");
        assert!(err.contains("ulimit -n"), "suggests the fix: {err}");
        assert!(err.contains("LimitNOFILE"), "mentions systemd: {err}");
        // The suggested limit covers the need.
        assert!(check_fd_headroom(10_000, 10_240).is_ok());
    }

    #[test]
    fn nofile_soft_limit_is_readable() {
        let limit = nofile_soft_limit().expect("getrlimit works on linux");
        assert!(limit >= 64, "sane environment: {limit}");
    }
}
