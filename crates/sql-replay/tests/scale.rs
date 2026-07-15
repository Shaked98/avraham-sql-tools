//! Bounded-memory evidence at production scale: replay a synthetic
//! million-event capture across thousands of sessions and assert the
//! process's peak RSS stays far below what materializing the capture would
//! require.
//!
//! Heavy, so `#[ignore]`d for plain `cargo test`; CI runs it in release
//! mode (`cargo test --release -p sql-replay --test scale -- --ignored`).
//! Event count is tunable via SQL_REPLAY_SCALE_EVENTS (default 1M; the
//! session count scales with it). This test must stay alone in its own
//! test binary — VmHWM is process-wide.

mod common;

use std::sync::atomic::Ordering;
use std::time::Duration;

use common::{generate_capture, no_shutdown, temp_path, MockTarget};
use sql_replay::replay::{run_replay_with_target, ReplayOptions, TargetInfo};

/// Peak resident set size of this process, in KiB (Linux).
fn vm_hwm_kib() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").expect("proc status");
    let line = status
        .lines()
        .find(|l| l.starts_with("VmHWM:"))
        .expect("VmHWM present");
    line.split_whitespace()
        .nth(1)
        .expect("VmHWM value")
        .parse()
        .expect("VmHWM is a number")
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "heavy: run in release mode with -- --ignored"]
async fn million_event_replay_memory_is_bounded() {
    let events_target: u64 = std::env::var("SQL_REPLAY_SCALE_EVENTS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1_000_000);
    let sessions = (events_target / 200).clamp(100, 20_000);
    let per_session = events_target / sessions;
    let total = sessions * per_session;

    let capture = temp_path("scale.jsonl.zst");
    let t0 = std::time::Instant::now();
    generate_capture(&capture, sessions, per_session, 32);
    let gen_secs = t0.elapsed().as_secs_f64();
    let baseline_kib = vm_hwm_kib();

    let target = MockTarget::new(Duration::ZERO);
    let options = ReplayOptions {
        max_connections: 256,
        ..ReplayOptions::new("mysql://mock/")
    };
    let (_tx, rx) = no_shutdown();
    let t0 = std::time::Instant::now();
    let outcome = run_replay_with_target(
        &capture,
        &options,
        target.clone(),
        TargetInfo::default(),
        rx,
    )
    .await
    .expect("replay");
    let replay_secs = t0.elapsed().as_secs_f64();
    std::fs::remove_file(&capture).ok();

    let t = &outcome.primary().totals;
    assert_eq!(t.events, total);
    assert_eq!(t.sessions, sessions);
    assert_eq!(t.executed, total, "every event executed");
    assert_eq!(t.errors, 0);
    assert_eq!(t.not_run, 0);
    assert!(
        target.state.max_live.load(Ordering::SeqCst) <= 256,
        "connection cap held"
    );

    // Memory evidence. Materializing the capture would need >= ~250 bytes
    // per event (Event struct + query string + grouping copies): ~250 MiB
    // at 1M events, growing linearly. The streaming path's peak must stay
    // an order of magnitude below that and, more importantly, must not
    // scale with the event count — the bound below stays flat whether
    // SQL_REPLAY_SCALE_EVENTS is 1M or 5M.
    let peak_kib = vm_hwm_kib();
    eprintln!(
        "scale evidence: {total} events / {sessions} sessions; generate {gen_secs:.1}s, \
         replay {replay_secs:.1}s ({:.0} qps); peak RSS {:.1} MiB (baseline before \
         replay {:.1} MiB)",
        t.qps,
        peak_kib as f64 / 1024.0,
        baseline_kib as f64 / 1024.0,
    );
    let bound_kib = 192 * 1024;
    assert!(
        peak_kib < bound_kib,
        "peak RSS {:.1} MiB exceeds the {:.0} MiB streaming bound — replay may be \
         materializing the capture again",
        peak_kib as f64 / 1024.0,
        bound_kib as f64 / 1024.0,
    );
}
