//! Thousands-of-sessions scheduling behavior, no database needed: 10k
//! concurrent session tasks must respect the connection cap (dedicated and
//! pooled modes) and complete without loss.

mod common;

use std::sync::atomic::Ordering;
use std::time::Duration;

use common::{generate_capture, no_shutdown, temp_path, MockTarget};
use sql_replay::replay::{run_replay_with_target, ReplayOptions, TargetInfo};

#[tokio::test(flavor = "multi_thread")]
async fn ten_thousand_sessions_respect_a_64_connection_cap() {
    let capture = temp_path("many-sessions.jsonl.zst");
    let total = generate_capture(&capture, 10_000, 2, 16);
    assert_eq!(total, 20_000);

    let target = MockTarget::new(Duration::ZERO);
    let options = ReplayOptions {
        max_connections: 64,
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
    std::fs::remove_file(&capture).ok();

    let t = &outcome.primary().totals;
    assert_eq!(t.events, 20_000);
    assert_eq!(t.sessions, 10_000);
    assert_eq!(t.executed, 20_000, "nothing lost at 10k sessions");
    assert_eq!(t.errors, 0);
    assert_eq!(t.not_run, 0);
    assert_eq!(t.connect_failures, 0);
    assert_eq!(
        target.state.connects.load(Ordering::SeqCst),
        10_000,
        "one dedicated connection per session"
    );
    assert!(
        target.state.max_live.load(Ordering::SeqCst) <= 64,
        "connection cap held: peak {}",
        target.state.max_live.load(Ordering::SeqCst)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn ten_thousand_sessions_multiplex_over_a_16_connection_pool() {
    let capture = temp_path("many-sessions-pool.jsonl.zst");
    generate_capture(&capture, 10_000, 2, 16);

    let target = MockTarget::new(Duration::ZERO);
    let options = ReplayOptions {
        pool: Some(16),
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
    std::fs::remove_file(&capture).ok();

    let t = &outcome.primary().totals;
    assert_eq!(t.executed, 20_000);
    assert_eq!(t.errors, 0);
    assert!(
        target.state.max_live.load(Ordering::SeqCst) <= 16,
        "pool cap held: peak {}",
        target.state.max_live.load(Ordering::SeqCst)
    );
    assert!(
        target.state.connects.load(Ordering::SeqCst) <= 16,
        "pooled connections are reused across 10k sessions: {} connects",
        target.state.connects.load(Ordering::SeqCst)
    );
}
