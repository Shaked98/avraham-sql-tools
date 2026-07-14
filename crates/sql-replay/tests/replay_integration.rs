//! Live replay integration test.
//!
//! Gated behind SQL_REPLAY_TEST_URL so plain `cargo test` passes without a
//! database. CI runs it against mysql:5.7 and mysql:8.0 service containers:
//!
//!   SQL_REPLAY_TEST_URL=mysql://root@127.0.0.1:3306/sqlreplay \
//!       cargo test -p sql-replay --test replay_integration

use std::path::Path;

use sql_replay::capture::run_capture;
use sql_replay::replay::{run_replay, ReplayOptions, Speed};

#[test]
fn replay_smoke_against_live_mysql() {
    let Ok(url) = std::env::var("SQL_REPLAY_TEST_URL") else {
        eprintln!("SQL_REPLAY_TEST_URL not set; skipping live replay integration test");
        return;
    };

    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/replay_smoke.log");
    let capture_path = std::env::temp_dir().join(format!(
        "sql-replay-integration-{}.jsonl.zst",
        std::process::id()
    ));
    let summary = run_capture(&fixture, &capture_path, None).expect("capture succeeds");
    assert_eq!(summary.event_count, 12);

    let options = ReplayOptions {
        url: url.clone(),
        max_connections: 4,
        allow_writes: false,
        read_only: false,
        db_override: None,
        speed: Speed::Max,
    };
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let report = rt
        .block_on(run_replay(&capture_path, options))
        .expect("replay succeeds");

    assert!(
        !report.target_server_version.is_empty(),
        "server version probed"
    );
    let t = &report.totals;
    assert_eq!(t.events, 12);
    assert_eq!(t.sessions, 3);
    assert_eq!(t.executed, 10, "all read statements execute: {report:#?}");
    assert_eq!(t.skipped, 2, "DROP and INSERT are write-gated");
    assert_eq!(
        t.errors, 0,
        "no errors expected: {:#?}",
        report.fingerprints
    );
    assert_eq!(t.not_run, 0);
    assert_eq!(t.connect_failures, 0);
    assert!(t.qps > 0.0);
    assert!(report.wall_secs > 0.0);

    assert_eq!(report.fingerprints.len(), 12);
    // Executed fingerprints have real latency data.
    for fp in report.fingerprints.iter().filter(|f| f.count > 0) {
        assert!(fp.p50_us >= 1, "p50 recorded for {}", fp.fingerprint);
        assert!(fp.max_us >= fp.p50_us);
    }
    // SELECT SLEEP(0.05) must show its intrinsic latency.
    let sleep_fp = report
        .fingerprints
        .iter()
        .find(|f| f.fingerprint.contains("sleep"))
        .expect("sleep fingerprint present");
    assert!(
        sleep_fp.p50_us >= 40_000,
        "sleep latency recorded: {} us",
        sleep_fp.p50_us
    );
    // The write-gated statements were never executed.
    for fp in report.fingerprints.iter().filter(|f| f.skipped > 0) {
        assert_eq!(fp.count, 0);
        assert_eq!(fp.errors, 0);
    }
    assert!(!report.flags.allow_writes);

    // Second run with --db-override: the captured USE statement is skipped
    // so sessions stay pinned to the override database. The override db is
    // the URL's path segment (e.g. `sqlreplay` in CI).
    let db = url
        .rsplit('/')
        .next()
        .map(|s| s.split('?').next().unwrap_or(""))
        .filter(|s| !s.is_empty() && !s.contains(':') && !s.contains('@'));
    let Some(db) = db else {
        std::fs::remove_file(&capture_path).ok();
        eprintln!("SQL_REPLAY_TEST_URL has no database path segment; skipping db-override leg");
        return;
    };
    let options = ReplayOptions {
        url: url.clone(),
        max_connections: 4,
        allow_writes: false,
        read_only: false,
        db_override: Some(db.to_string()),
        speed: Speed::Max,
    };
    let report = rt
        .block_on(run_replay(&capture_path, options))
        .expect("db-override replay succeeds");
    std::fs::remove_file(&capture_path).ok();

    let t = &report.totals;
    assert_eq!(t.events, 12);
    assert_eq!(
        t.executed, 9,
        "USE is skipped under --db-override: {report:#?}"
    );
    assert_eq!(t.skipped, 3, "2 write-gated + 1 USE under override");
    assert_eq!(t.errors, 0);
    assert_eq!(t.not_run, 0);
    assert_eq!(report.flags.db_override.as_deref(), Some(db));
}
