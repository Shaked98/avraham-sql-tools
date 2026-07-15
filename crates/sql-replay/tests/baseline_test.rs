//! End-to-end test of the production-recorded baseline workflow: parse the
//! smoke fixture slow log with `capture`, aggregate its recorded
//! `Query_time` latencies with `baseline`, and feed the result through
//! `compare` against a replayed-shape report.

use std::path::PathBuf;

use sql_replay::baseline::build_baseline;
use sql_replay::capture::run_capture;
use sql_replay::compare::{compare_runs, CompareOptions};
use sql_replay::report::RunReport;
use sql_replay::spool::Filters;

fn temp_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "sql-replay-baseline-e2e-{}-{name}",
        std::process::id()
    ))
}

fn smoke_baseline(name: &str) -> RunReport {
    let log = format!(
        "{}/tests/fixtures/replay_smoke.log",
        env!("CARGO_MANIFEST_DIR")
    );
    let cap = temp_path(name);
    run_capture(log.as_ref(), &cap, None).unwrap();
    let report = build_baseline(&cap, &Filters::default()).unwrap();
    std::fs::remove_file(&cap).unwrap();
    report
}

#[test]
fn smoke_fixture_baseline_aggregates_recorded_query_times() {
    let report = smoke_baseline("agg.jsonl.zst");

    assert_eq!(report.latency_source, "recorded-slow-log");
    assert_eq!(report.capture_dialect, "mysql-5.7-or-newer");
    assert_eq!(report.totals.events, 12);
    assert_eq!(report.totals.executed, 12);
    assert_eq!(report.totals.sessions, 3);
    assert_eq!(report.totals.errors, 0);
    assert_eq!(report.totals.skipped, 0);
    // Capture timeline: 1693569601..1693569604 → 3s wall, 4 QPS.
    assert_eq!(report.started_at, "2023-09-01T12:00:01Z");
    assert_eq!(report.ended_at, "2023-09-01T12:00:04Z");
    assert_eq!(report.wall_secs, 3.0);
    assert_eq!(report.totals.qps, 4.0);

    // Each statement is its own fingerprint (count 1), so per-fingerprint
    // percentiles equal the recorded Query_time up to the histogram's
    // 3-significant-digit bucketing (≤ 0.1% error). The slowest is
    // SELECT SLEEP(0.05) at 0.050000s.
    assert_eq!(report.fingerprints.len(), 12);
    let slowest = &report.fingerprints[0];
    assert!(
        slowest.fingerprint.contains("sleep"),
        "{}",
        slowest.fingerprint
    );
    let close = |got: u64, want: u64| (got as i64 - want as i64).unsigned_abs() * 1000 <= want;
    assert!(close(slowest.p50_us, 50_000), "{}", slowest.p50_us);
    assert!(close(slowest.p95_us, 50_000), "{}", slowest.p95_us);
    assert!(close(slowest.max_us, 50_000), "{}", slowest.max_us);
    // Writes are recorded too — production ran them (DROP at 0.01s).
    assert!(report
        .fingerprints
        .iter()
        .any(|f| f.fingerprint.starts_with("drop table") && close(f.p95_us, 10_000)));
}

#[test]
fn recorded_baseline_feeds_compare_against_a_replayed_run() {
    let baseline = smoke_baseline("compare.jsonl.zst");

    // Fake an 8.0 replay of the same capture: same fingerprint texts, all
    // latencies doubled (uniform 2x regression).
    let mut candidate = baseline.clone();
    candidate.latency_source = "replayed".to_string();
    candidate.target_url = "mysql://test-twin:3306/".to_string();
    candidate.target_server_version = "8.0.46".to_string();
    candidate.target_settings =
        std::collections::BTreeMap::from([("sql_mode".to_string(), "X".to_string())]);
    for fp in &mut candidate.fingerprints {
        fp.p50_us *= 2;
        fp.p95_us *= 2;
        fp.p99_us *= 2;
        fp.max_us *= 2;
        fp.mean_us *= 2.0;
    }

    let rep = compare_runs(
        "baseline.json",
        &baseline,
        "run-8.0.json",
        &candidate,
        CompareOptions {
            threshold_pct: 50.0,
            min_count: 1,
        },
    );

    // Delta math is source-agnostic: every fingerprint regressed +100%.
    assert_eq!(rep.regressions.len(), 12);
    assert!(rep.regressed);
    assert_eq!(rep.regressions[0].p95.delta_pct, Some(100.0));

    // The measurement-plane warning is prominent in both outputs.
    assert!(rep
        .comparability_warnings
        .iter()
        .any(|w| w.contains("MEASUREMENT PLANES DIFFER")));
    let stdout = rep.render_stdout(10);
    assert!(stdout.contains("MEASUREMENT PLANES DIFFER"));
    assert!(stdout.contains("recorded (slow log) latencies from capture"));
    let html = sql_replay::compare_html::render_html(&rep);
    assert!(html.contains("MEASUREMENT PLANES DIFFER"));
    assert!(html.contains("recorded (slow log)"));
    assert!(html.contains("recorded-slow-log"));
    // The settings diff is skipped with a note, and the recorded side's
    // empty version/url never render as blanks.
    assert!(html.contains("settings diff skipped"));
    assert!(html.contains("— (no target)"));
}
