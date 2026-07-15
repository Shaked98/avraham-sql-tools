//! Streaming-ingestion equivalence: the production spool path must produce
//! the same run.json results as the in-memory reference path, on the same
//! fixture, against the same (mock) target — plus behavior checks for the
//! M3 operational controls (filters, --repeat aggregation, --warmup,
//! --pool) at the whole-replay level.

mod common;

use std::sync::atomic::Ordering;
use std::time::Duration;

use common::{no_shutdown, temp_path, MockTarget};
use sql_replay::capture::run_capture;
use sql_replay::replay::{
    run_replay_in_memory_with_target, run_replay_with_target, ReplayOptions, ReplayOutcome, Speed,
    TargetInfo,
};
use sql_replay::report::RunReport;
use sql_replay::spool::{Filters, TimeWindow};

fn smoke_capture(name: &str) -> std::path::PathBuf {
    let fixture =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/replay_smoke.log");
    let out = temp_path(&format!("{name}.jsonl.zst"));
    let summary = run_capture(&fixture, &out, None).expect("capture fixture");
    assert_eq!(summary.event_count, 12);
    out
}

/// The deterministic (latency-independent) portion of a run report.
#[derive(Debug, PartialEq)]
struct Deterministic {
    events: u64,
    sessions: u64,
    executed: u64,
    skipped: u64,
    errors: u64,
    not_run: u64,
    connect_failures: u64,
    filtered: u64,
    aborted: bool,
    per_fp: Vec<(u32, String, u64, u64, u64, u64)>,
}

fn deterministic(r: &RunReport) -> Deterministic {
    let mut per_fp: Vec<_> = r
        .fingerprints
        .iter()
        .map(|f| {
            (
                f.id,
                f.fingerprint.clone(),
                f.count,
                f.errors,
                f.skipped,
                f.not_run,
            )
        })
        .collect();
    per_fp.sort();
    Deterministic {
        events: r.totals.events,
        sessions: r.totals.sessions,
        executed: r.totals.executed,
        skipped: r.totals.skipped,
        errors: r.totals.errors,
        not_run: r.totals.not_run,
        connect_failures: r.totals.connect_failures,
        filtered: r.totals.filtered,
        aborted: r.aborted,
        per_fp,
    }
}

async fn run_both(
    capture: &std::path::Path,
    options: &ReplayOptions,
) -> (ReplayOutcome, ReplayOutcome) {
    let (_tx1, rx1) = no_shutdown();
    let (_tx2, rx2) = no_shutdown();
    let spool = run_replay_with_target(
        capture,
        options,
        MockTarget::new(Duration::ZERO),
        TargetInfo::default(),
        rx1,
    )
    .await
    .expect("spool replay");
    let mem = run_replay_in_memory_with_target(
        capture,
        options,
        MockTarget::new(Duration::ZERO),
        TargetInfo::default(),
        rx2,
    )
    .await
    .expect("in-memory replay");
    (spool, mem)
}

#[tokio::test(flavor = "multi_thread")]
async fn spool_path_matches_in_memory_reference_on_the_fixture() {
    let capture = smoke_capture("equiv");
    let options = ReplayOptions {
        max_connections: 4,
        ..ReplayOptions::new("mysql://mock/")
    };
    let (spool, mem) = run_both(&capture, &options).await;

    let s = deterministic(spool.primary());
    let m = deterministic(mem.primary());
    assert_eq!(s, m, "spool vs in-memory results diverge");
    // And both match the fixture's known shape.
    assert_eq!(s.events, 12);
    assert_eq!(s.sessions, 3);
    assert_eq!(s.executed, 10, "write gate skips DROP + INSERT");
    assert_eq!(s.skipped, 2);
    assert_eq!(s.errors, 0);
    assert_eq!(s.not_run, 0);
    assert!(!s.aborted);
    std::fs::remove_file(&capture).ok();
}

#[tokio::test(flavor = "multi_thread")]
async fn spool_path_matches_in_memory_reference_with_filters_and_pacing() {
    let capture = smoke_capture("equiv-filtered");
    // Paced fast (capture spans 3s -> ~30ms) and time-narrowed: the two
    // ingestion paths must agree on what is filtered and what is paced.
    let options = ReplayOptions {
        max_connections: 4,
        speed: Speed::Factor(100.0),
        filters: Filters {
            window: Some(TimeWindow::parse("1693569602..1693569604").expect("window")),
            ..Filters::default()
        },
        ..ReplayOptions::new("mysql://mock/")
    };
    let (spool, mem) = run_both(&capture, &options).await;

    let s = deterministic(spool.primary());
    assert_eq!(s, deterministic(mem.primary()));
    assert_eq!(s.events, 6, "6 of 12 events fall in the window");
    assert_eq!(s.filtered, 6);
    let sp = spool.primary().pacing.as_ref().expect("paced run");
    let mp = mem.primary().pacing.as_ref().expect("paced run");
    assert_eq!(sp.paced_events, 6);
    assert_eq!(mp.paced_events, 6);
    std::fs::remove_file(&capture).ok();
}

#[tokio::test(flavor = "multi_thread")]
async fn user_filter_matches_across_paths() {
    let capture = smoke_capture("equiv-user");
    // Every fixture event is user `smoke`, so this filter keeps everything…
    let options = ReplayOptions {
        filters: Filters {
            user: Some("smoke".to_string()),
            ..Filters::default()
        },
        ..ReplayOptions::new("mysql://mock/")
    };
    let (spool, mem) = run_both(&capture, &options).await;
    let s = deterministic(spool.primary());
    assert_eq!(s, deterministic(mem.primary()));
    assert_eq!(s.events, 12);
    assert_eq!(s.filtered, 0);

    // …and a non-matching user filter refuses to replay nothing.
    let options = ReplayOptions {
        filters: Filters {
            user: Some("nobody".to_string()),
            ..Filters::default()
        },
        ..ReplayOptions::new("mysql://mock/")
    };
    let (_tx, rx) = no_shutdown();
    let err = match run_replay_with_target(
        &capture,
        &options,
        MockTarget::new(Duration::ZERO),
        TargetInfo::default(),
        rx,
    )
    .await
    {
        Err(e) => e.to_string(),
        Ok(_) => panic!("all-excluding filter must error"),
    };
    assert!(
        err.contains("filters excluded all 12 events"),
        "actionable error: {err}"
    );
    std::fs::remove_file(&capture).ok();
}

#[tokio::test(flavor = "multi_thread")]
async fn repeat_runs_n_passes_and_aggregates_the_median() {
    let capture = smoke_capture("repeat");
    let target = MockTarget::new(Duration::ZERO);
    let options = ReplayOptions {
        max_connections: 4,
        repeat: 3,
        ..ReplayOptions::new("mysql://mock/")
    };
    let (_tx, rx) = no_shutdown();
    let outcome = run_replay_with_target(
        &capture,
        &options,
        target.clone(),
        TargetInfo::default(),
        rx,
    )
    .await
    .expect("replay");
    assert_eq!(outcome.passes.len(), 3);
    for pass in &outcome.passes {
        assert_eq!(pass.totals.executed, 10);
        assert!(pass.aggregation.is_none());
    }
    let agg = outcome.aggregated.as_ref().expect("aggregate present");
    let info = agg.aggregation.as_ref().expect("aggregation info");
    assert_eq!(info.passes, 3);
    assert_eq!(info.method, "median");
    assert_eq!(agg.totals.executed, 10);
    assert_eq!(agg.totals.events, 12);
    // 3 sessions connect per pass; no warmup.
    assert_eq!(target.state.connects.load(Ordering::SeqCst), 9);
    std::fs::remove_file(&capture).ok();
}

#[tokio::test(flavor = "multi_thread")]
async fn warmup_runs_an_extra_unrecorded_pass() {
    let capture = smoke_capture("warmup");
    let target = MockTarget::new(Duration::ZERO);
    let options = ReplayOptions {
        max_connections: 4,
        warmup: true,
        ..ReplayOptions::new("mysql://mock/")
    };
    let (_tx, rx) = no_shutdown();
    let outcome = run_replay_with_target(
        &capture,
        &options,
        target.clone(),
        TargetInfo::default(),
        rx,
    )
    .await
    .expect("replay");
    // One recorded pass, but two full executions happened.
    assert_eq!(outcome.passes.len(), 1);
    assert!(outcome.aggregated.is_none());
    assert_eq!(outcome.primary().totals.executed, 10);
    assert!(outcome.primary().flags.warmup);
    assert_eq!(
        target.state.queries.load(Ordering::SeqCst),
        20,
        "warmup executed the workload once more"
    );
    assert_eq!(target.state.connects.load(Ordering::SeqCst), 6);
    std::fs::remove_file(&capture).ok();
}

#[tokio::test(flavor = "multi_thread")]
async fn pool_mode_bounds_connections_and_skips_captured_use() {
    let capture = smoke_capture("pool");
    let target = MockTarget::new(Duration::ZERO);
    let options = ReplayOptions {
        pool: Some(2),
        ..ReplayOptions::new("mysql://mock/")
    };
    let (_tx, rx) = no_shutdown();
    let outcome = run_replay_with_target(
        &capture,
        &options,
        target.clone(),
        TargetInfo::default(),
        rx,
    )
    .await
    .expect("replay");
    let r = outcome.primary();
    assert_eq!(r.totals.executed, 9, "captured USE is skipped in pool mode");
    assert_eq!(r.totals.skipped, 3, "2 write-gated + 1 USE");
    assert_eq!(r.totals.errors, 0);
    assert_eq!(r.flags.pool, Some(2));
    assert!(
        target.state.max_live.load(Ordering::SeqCst) <= 2,
        "pool cap respected"
    );
    assert!(
        target.state.connects.load(Ordering::SeqCst) <= 2,
        "pooled connections are reused"
    );
    std::fs::remove_file(&capture).ok();
}
