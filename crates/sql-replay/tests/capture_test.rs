//! End-to-end tests for `sql-replay capture` against both slow-log dialect
//! fixtures: parse -> compressed capture file -> read back -> assert.

use std::path::{Path, PathBuf};

use sql_replay::capture::run_capture;
use sql_replay::format::{read_capture, CaptureFile};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn capture_fixture(name: &str) -> CaptureFile {
    let out = std::env::temp_dir().join(format!(
        "sql-replay-capture-test-{}-{}.jsonl.zst",
        std::process::id(),
        name
    ));
    let summary = run_capture(&fixture(name), &out, None).expect("capture succeeds");
    let cap = read_capture(&out).expect("capture file reads back");
    std::fs::remove_file(&out).ok();
    assert_eq!(summary.event_count, cap.summary.event_count);
    cap
}

#[test]
fn captures_mysql57_dialect() {
    let cap = capture_fixture("mysql57.log");
    let s = &cap.summary;
    assert_eq!(s.source_dialect, "mysql-5.7");
    assert_eq!(s.event_count, 6);
    assert_eq!(s.session_count, 4); // thread ids 11, 12, 13, 14
    assert_eq!(s.admin_commands_ignored, 1);
    assert_eq!(s.server_restarts_seen, 1);
    // First and last SELECT share a fingerprint class.
    assert_eq!(s.fingerprints.len(), 5);

    let e = &cap.events;
    assert_eq!(e.len(), 6);

    assert_eq!(e[0].session_id, 11);
    assert_eq!(e[0].user.as_deref(), Some("appuser"));
    assert_eq!(e[0].db.as_deref(), Some("orders"));
    assert_eq!(e[0].ts_micros, 1_693_569_601_000_000);
    assert_eq!(e[0].query, "SELECT * FROM orders WHERE id = 12345");
    assert_eq!(e[0].orig_query_time_s, 0.000212);

    // Multi-line statement is preserved verbatim; db carries log-globally.
    assert_eq!(e[1].session_id, 12);
    assert_eq!(e[1].db.as_deref(), Some("orders"));
    assert!(e[1]
        .query
        .contains("JOIN order_items oi ON oi.order_id = o.id"));
    assert!(e[1].query.contains('\n'));

    // String literal containing `# ` header-lookalikes stays one statement.
    assert_eq!(e[2].session_id, 11);
    assert!(e[2].query.contains("# looks like a header: but is not"));
    assert!(e[2]
        .query
        .contains("# Time: 230901 99:99:99 also not a header"));
    assert!(e[2].query.ends_with("AND id = 7"));
    assert_eq!(e[2].ts_micros, 1_693_569_602_000_000);

    // Write statement and slow-admin statement are captured (replay gates them).
    assert_eq!(e[3].session_id, 13);
    assert_eq!(e[3].db.as_deref(), Some("analytics"));
    assert!(e[3].query.starts_with("INSERT INTO daily_rollup"));

    assert_eq!(e[4].session_id, 14);
    assert_eq!(e[4].user.as_deref(), Some("root"));
    assert_eq!(e[4].db.as_deref(), Some("analytics")); // log-global carry
    assert!(e[4].query.starts_with("ALTER TABLE orders"));
    assert_eq!(e[4].orig_query_time_s, 2.5);

    assert_eq!(e[5].session_id, 11);
    assert_eq!(e[5].db.as_deref(), Some("orders"));

    // Same class, different literals -> same fingerprint id.
    assert_eq!(e[0].fingerprint_id, e[5].fingerprint_id);
    assert_eq!(
        s.fingerprint_text(e[0].fingerprint_id).unwrap(),
        "select * from orders where id = ?"
    );
    // IN list collapsed in the fingerprint table.
    assert!(s
        .fingerprint_text(e[1].fingerprint_id)
        .unwrap()
        .contains("in (?+)"));
}

#[test]
fn captures_mysql80_dialect() {
    let cap = capture_fixture("mysql80.log");
    let s = &cap.summary;
    assert_eq!(s.source_dialect, "mysql-8.0");
    assert_eq!(s.event_count, 5);
    assert_eq!(s.session_count, 3); // thread ids 21, 22, 23
    assert_eq!(s.admin_commands_ignored, 1);
    assert_eq!(s.fingerprints.len(), 5);

    let e = &cap.events;
    assert_eq!(e.len(), 5);

    assert_eq!(e[0].session_id, 21);
    assert_eq!(e[0].db.as_deref(), Some("orders"));
    assert_eq!(e[0].ts_micros, 1_693_569_601_000_000);
    assert_eq!(e[0].query, "SELECT * FROM orders WHERE id = 777");

    // Strings spanning lines with header-lookalikes inside, plus a
    // double-quoted string with an escaped quote and a `#`.
    assert_eq!(e[1].session_id, 22);
    assert!(e[1]
        .query
        .contains("# User@Host: fake[fake] @ evil []  Id: 999"));
    assert!(e[1].query.contains(r#""double \" quoted # text""#));
    assert!(e[1].query.ends_with("LIMIT 3"));
    // The fake header inside the string must not pollute entry metadata.
    assert_eq!(e[1].ts_micros, 1_693_569_601_000_000);

    // No SET timestamp on this entry: falls back to the RFC3339 `# Time:`
    // with a +03:00 offset (12:00:02.5 UTC).
    assert_eq!(e[2].session_id, 23);
    assert_eq!(e[2].ts_micros, 1_693_569_602_500_000);
    assert!(e[2].query.starts_with("UPDATE orders"));

    assert_eq!(e[3].session_id, 21);
    assert!(e[3].query.starts_with("SHOW VARIABLES"));

    assert_eq!(e[4].session_id, 23);
    assert_eq!(e[4].db.as_deref(), Some("analytics"));
    assert!(s
        .fingerprint_text(e[4].fingerprint_id)
        .unwrap()
        .contains("kind in (?+)"));
}

#[test]
fn capture_of_smoke_fixture_matches_replay_expectations() {
    let cap = capture_fixture("replay_smoke.log");
    assert_eq!(cap.summary.event_count, 11);
    assert_eq!(cap.summary.session_count, 3);
    assert_eq!(cap.summary.fingerprints.len(), 11);
    let writes: Vec<&str> = cap
        .events
        .iter()
        .filter(|e| !sql_replay::classify::should_execute(&e.query, false))
        .map(|e| e.query.as_str())
        .collect();
    assert_eq!(
        writes.len(),
        2,
        "exactly the DROP and INSERT are gated: {writes:?}"
    );
}
