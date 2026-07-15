//! Graceful-abort behavior: an aborted replay still yields a partial run
//! report, marked `aborted: true`, with never-attempted events counted as
//! `not_run`.

mod common;

use std::sync::atomic::Ordering;
use std::time::Duration;

use common::{temp_path, write_capture, MockTarget};
use sql_replay::format::Event;
use sql_replay::replay::{run_replay_with_target, ReplayOptions, TargetInfo};
use tokio::sync::watch;

fn sequential_capture(name: &str, n: u64) -> std::path::PathBuf {
    let events: Vec<Event> = (0..n)
        .map(|i| Event {
            ts_micros: 1_700_000_000_000_000 + i as i64,
            session_id: 1,
            user: Some("app".to_string()),
            db: None,
            query: format!("SELECT {i}"),
            orig_query_time_s: 0.0001,
            fingerprint_id: (i % 4) as u32,
        })
        .collect();
    let path = temp_path(&format!("{name}.jsonl.zst"));
    write_capture(&path, &events);
    path
}

#[tokio::test(flavor = "multi_thread")]
async fn abort_mid_run_writes_a_partial_report() {
    let capture = sequential_capture("abort-mid", 10);
    let target = MockTarget::new(Duration::ZERO);
    let (tx, rx) = watch::channel(false);
    // The mock flips the shutdown flag as query #3 starts; the single
    // session is strictly sequential, so exactly 3 queries complete.
    target.state.shutdown_after.store(3, Ordering::SeqCst);
    *target.state.shutdown_tx.lock().unwrap() = Some(tx);

    let options = ReplayOptions::new("mysql://mock/");
    let outcome = run_replay_with_target(&capture, &options, target, TargetInfo::default(), rx)
        .await
        .expect("aborted replay still returns a report");
    std::fs::remove_file(&capture).ok();

    assert!(outcome.aborted());
    let r = outcome.primary();
    assert!(r.aborted);
    let t = &r.totals;
    assert_eq!(t.events, 10);
    assert_eq!(t.executed, 3);
    assert_eq!(t.not_run, 7, "unattempted events are counted, not lost");
    assert_eq!(t.skipped, 0);
    assert_eq!(t.errors, 0);
    // The per-fingerprint accounting still adds up.
    let fp_not_run: u64 = r.fingerprints.iter().map(|f| f.not_run).sum();
    assert_eq!(fp_not_run, 7);
    // The partial report serializes with the aborted marker and the human
    // table says so loudly.
    let json = serde_json::to_string(r).expect("serializable");
    assert!(json.contains("\"aborted\": true") || json.contains("\"aborted\":true"));
    assert!(r.render_table(5).contains("ABORTED"));
}

#[tokio::test(flavor = "multi_thread")]
async fn abort_before_start_runs_nothing_but_reports_everything() {
    let capture = sequential_capture("abort-pre", 10);
    let target = MockTarget::new(Duration::ZERO);
    let (tx, rx) = watch::channel(false);
    tx.send(true).expect("receiver alive");

    let options = ReplayOptions::new("mysql://mock/");
    let outcome = run_replay_with_target(
        &capture,
        &options,
        target.clone(),
        TargetInfo::default(),
        rx,
    )
    .await
    .expect("report produced");
    std::fs::remove_file(&capture).ok();

    let r = outcome.primary();
    assert!(r.aborted);
    assert_eq!(r.totals.executed, 0);
    assert_eq!(r.totals.not_run, 10);
    assert_eq!(
        target.state.connects.load(Ordering::SeqCst),
        0,
        "no connection is opened for an already-aborted run"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn abort_during_repeat_stops_the_pass_loop() {
    let capture = sequential_capture("abort-repeat", 10);
    let target = MockTarget::new(Duration::ZERO);
    let (tx, rx) = watch::channel(false);
    // Pass 1 completes its 10 queries; the flag flips as query #12 (second
    // query of pass 2) starts.
    target.state.shutdown_after.store(12, Ordering::SeqCst);
    *target.state.shutdown_tx.lock().unwrap() = Some(tx);

    let options = ReplayOptions {
        repeat: 3,
        ..ReplayOptions::new("mysql://mock/")
    };
    let outcome = run_replay_with_target(&capture, &options, target, TargetInfo::default(), rx)
        .await
        .expect("report produced");
    std::fs::remove_file(&capture).ok();

    assert_eq!(outcome.passes.len(), 2, "third pass never starts");
    assert!(!outcome.passes[0].aborted);
    assert_eq!(outcome.passes[0].totals.executed, 10);
    assert!(outcome.passes[1].aborted);
    assert_eq!(outcome.passes[1].totals.executed, 2);
    assert_eq!(outcome.passes[1].totals.not_run, 8);
    let agg = outcome
        .aggregated
        .as_ref()
        .expect("aggregate still emitted");
    assert!(agg.aborted, "aggregate is marked partial");
}
