//! Expected-outcome tests for the nasty-log corpus in `tests/corpus/`.
//!
//! Each corpus file is an adversarial slow log distilled from a real-world
//! failure class (see `fuzz/README.md`). Every test pins the exact event
//! count — the parser must never panic on these inputs, and it must never
//! silently drop an entry either: whatever it cannot attribute must still
//! surface as an event. The corpus files double as seeds for the
//! `slowlog_parse` fuzz target.

use std::path::{Path, PathBuf};

use sql_replay::capture::run_capture;
use sql_replay::format::{read_capture, CaptureFile};

fn corpus(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/corpus")
        .join(name)
}

/// End to end: slow log -> capture file -> read back. Exercises the raw-byte
/// line reader (invalid UTF-8), the parser, and the capture roundtrip.
fn capture_log(input: &Path) -> CaptureFile {
    let out = std::env::temp_dir().join(format!(
        "sql-replay-corpus-test-{}-{}.jsonl.zst",
        std::process::id(),
        input.file_stem().unwrap().to_string_lossy(),
    ));
    let summary = run_capture(input, &out, None).expect("capture succeeds");
    let cap = read_capture(&out).expect("capture file reads back");
    std::fs::remove_file(&out).ok();
    assert_eq!(summary.event_count, cap.summary.event_count);
    cap
}

fn capture_corpus(name: &str) -> CaptureFile {
    capture_log(&corpus(name))
}

#[test]
fn giant_insert_batch_stays_one_event() {
    let cap = capture_corpus("giant_insert_batch.log");
    assert_eq!(cap.summary.event_count, 2);
    assert_eq!(cap.summary.session_count, 2);
    assert_eq!(cap.summary.source_dialect, "mysql-5.7-or-newer");

    let ins = &cap.events[0];
    assert!(ins.query.starts_with("INSERT INTO order_items"));
    // 1 header line + 500 value rows, all still one statement.
    assert_eq!(ins.query.lines().count(), 501);
    assert!(ins
        .query
        .contains("(500, 'SKU-0500', '# Time: 240301 00:00:00 lookalike inside row 500')"));
    assert!(ins
        .query
        .contains("escaped quote \\' and backslash \\\\ in row 73"));
    assert_eq!(ins.db.as_deref(), Some("shop"));
    assert_eq!(ins.session_id, 101);
    assert_eq!(ins.ts_micros, 1_709_251_200_000_000);
    assert_eq!(ins.orig_query_time_s, 4.5);

    let sel = &cap.events[1];
    assert_eq!(sel.query, "SELECT COUNT(*) FROM order_items");
    // No `use` line for the second entry: same db as the previous one.
    assert_eq!(sel.db.as_deref(), Some("shop"));
    assert_eq!(sel.session_id, 102);
}

#[test]
fn header_lookalikes_inside_literals_are_statement_text() {
    let cap = capture_corpus("string_literal_traps.log");
    assert_eq!(cap.summary.event_count, 3);
    assert_eq!(cap.summary.session_count, 3);

    // Entry 1: a literal spanning lines that look exactly like entry headers.
    let e = &cap.events[0];
    assert_eq!(e.session_id, 201);
    assert_eq!(e.ts_micros, 1_709_251_800_000_000);
    assert_eq!(e.orig_query_time_s, 0.1);
    assert!(e
        .query
        .contains("# User@Host: fake[fake] @ evil []  Id: 999"));
    assert!(e.query.contains("SET timestamp=1;"));
    assert!(e.query.ends_with("end of literal'"));

    // Entry 2: `--` and `#` comments hide unbalanced quotes; backtick
    // identifiers contain doubled backticks and a `#`.
    let e = &cap.events[1];
    assert_eq!(e.session_id, 202);
    // The fake `SET timestamp=1;` inside entry 1's literal must not leak.
    assert_eq!(e.ts_micros, 1_709_251_801_000_000);
    assert!(e
        .query
        .contains("-- line comment hides this unbalanced quote: '"));
    assert!(e
        .query
        .contains("# a real mysql # comment line with a stray \" quote"));
    assert!(e.query.contains("`back``tick # id`"));
    assert!(e.query.ends_with("AND y = 2"));

    // Entry 3 proves the parser state fully recovered.
    let e = &cap.events[2];
    assert_eq!(e.query, "SELECT 3");
    assert_eq!(e.session_id, 203);
}

#[test]
fn emoji_and_invalid_utf8_convert_lossily() {
    let cap = capture_corpus("emoji_invalid_utf8.log");
    assert_eq!(cap.summary.event_count, 2);

    let e = &cap.events[0];
    assert_eq!(e.session_id, 301);
    assert!(e.query.contains("héllo 🦀 emoji"));
    // The three raw non-UTF-8 bytes each become U+FFFD, nothing is lost
    // around them.
    assert!(e
        .query
        .contains("latin1 bytes: \u{FFFD}\u{FFFD}\u{FFFD} end"));
    assert!(e.query.contains("ステータス"));

    assert_eq!(cap.events[1].query, "SELECT '🎉'");
}

#[test]
fn rotation_seam_fragment_surfaces_as_event() {
    let cap = capture_corpus("rotation_seam.log");
    // The file starts mid-statement (previous log rotated away). The
    // fragment cannot be attributed, but it must surface as an event —
    // with zeroed metadata — rather than vanish.
    assert_eq!(cap.summary.event_count, 2);

    let frag = &cap.events[0];
    assert!(frag.query.contains("truncated by log rotation"));
    assert!(frag.query.ends_with("WHERE id IN (1, 2, 3)"));
    assert_eq!(frag.session_id, 0);
    assert_eq!(frag.ts_micros, 0);
    assert_eq!(frag.user, None);

    let e = &cap.events[1];
    assert_eq!(e.query, "SELECT 'first complete entry'");
    assert_eq!(e.session_id, 401);
    assert_eq!(e.ts_micros, 1_709_258_400_000_000);
}

#[test]
fn mixed_dialects_in_one_file() {
    let cap = capture_corpus("dialect_mix.log");
    assert_eq!(cap.summary.event_count, 3);
    assert_eq!(cap.summary.session_count, 3);
    assert_eq!(cap.summary.server_restarts_seen, 2);
    // The first restart banner's version is authoritative; the later 8.0
    // banner does not rewrite history.
    assert_eq!(cap.summary.source_dialect, "mysql-5.6-or-older");

    // Percona-style `# Thread_id: N Schema: db` entry.
    let e = &cap.events[0];
    assert_eq!(e.session_id, 501);
    assert_eq!(e.db.as_deref(), Some("percona_db"));
    assert_eq!(e.orig_query_time_s, 1.5);

    // Plain 5.6 entry: the Percona per-entry schema must not stick.
    let e = &cap.events[1];
    assert_eq!(e.session_id, 502);
    assert_eq!(e.db, None);
    assert_eq!(e.ts_micros, 1_709_262_005_000_000);

    // 8.0 log_slow_extra entry after the restart.
    let e = &cap.events[2];
    assert_eq!(e.session_id, 503);
    assert_eq!(e.user.as_deref(), Some("modern"));
    assert_eq!(e.orig_query_time_s, 0.000212);
}

#[test]
fn admin_commands_counted_but_not_replayed() {
    let cap = capture_corpus("admin_commands.log");
    // Ping/Quit produce no events; the slow ALTER (log_slow_admin_statements)
    // is an ordinary captured statement.
    assert_eq!(cap.summary.event_count, 1);
    assert_eq!(cap.summary.admin_commands_ignored, 2);
    assert_eq!(cap.summary.session_count, 1);

    let e = &cap.events[0];
    assert_eq!(e.query, "ALTER TABLE big ADD COLUMN c INT");
    // The Ping entry's SET timestamp must not leak into the ALTER.
    assert_eq!(e.ts_micros, 1_709_265_610_000_000);
    assert_eq!(e.orig_query_time_s, 12.5);
}

#[test]
fn windows_crlf_line_endings() {
    let cap = capture_corpus("crlf_windows.log");
    assert_eq!(cap.summary.event_count, 2);

    let e = &cap.events[0];
    assert_eq!(e.session_id, 651);
    assert!(e.query.contains("# Time: fake header inside CRLF literal"));
    assert!(e.query.ends_with("AND id = 7"));

    assert_eq!(cap.events[1].query, "SELECT 'second crlf entry'");
    for e in &cap.events {
        assert!(!e.query.contains('\r'), "CR leaked into query text");
    }
}

#[test]
fn reordered_and_duplicated_headers() {
    let cap = capture_corpus("headers_reordered.log");
    assert_eq!(cap.summary.event_count, 2);
    assert_eq!(cap.summary.source_dialect, "mysql-5.6-or-older");

    // Query_time before User@Host, and no SET timestamp at all: the entry
    // falls back to the carried-forward `# Time:` header.
    let e = &cap.events[0];
    assert_eq!(e.session_id, 701);
    assert_eq!(e.user.as_deref(), Some("u"));
    assert_eq!(e.ts_micros, 1_709_269_200_000_000);
    assert_eq!(e.orig_query_time_s, 0.3);
    assert_eq!(e.query, "SELECT reordered_headers");

    // Duplicated User@Host lines: the last one wins. Unknown `Key: value`
    // headers are ignored without complaint.
    let e = &cap.events[1];
    assert_eq!(e.session_id, 703);
    assert_eq!(e.user.as_deref(), Some("u2"));
    assert_eq!(e.ts_micros, 1_709_269_201_000_000);
    assert_eq!(e.orig_query_time_s, 0.4);
    assert_eq!(e.query, "SELECT duplicated_headers");
}

#[test]
fn eof_inside_open_string_literal() {
    let cap = capture_corpus("truncated_mid_statement.log");
    // Rotation cut the file inside a string literal. The partial statement
    // must still be emitted at EOF, not dropped.
    assert_eq!(cap.summary.event_count, 2);

    assert_eq!(cap.events[0].query, "SELECT ok_entry");

    let e = &cap.events[1];
    assert_eq!(e.session_id, 802);
    assert_eq!(e.ts_micros, 1_709_272_801_000_000);
    assert_eq!(
        e.query,
        "UPDATE t SET body = 'this literal is cut off by EOF"
    );
}

#[test]
fn mariadb_10_11_container_log() {
    // Verbatim slow log from a mariadb:10.11 container with
    // log_slow_verbosity=query_plan,explain: the restart banner names
    // MariaDB (dialect evidence), every entry carries the
    // `# Thread_id: N Schema: db QC_hit:` line, and the annotation lines
    // (`# Rows_affected:`, `# Full_scan:`, `# Tmp_tables:`, `# explain:`
    // with tab-separated plan columns, bare `#` separators) must be
    // consumed as headers without producing or dropping events.
    let cap = capture_corpus("mariadb-10.11.log");
    assert_eq!(cap.summary.event_count, 12);
    assert_eq!(cap.summary.session_count, 3);
    assert_eq!(cap.summary.source_dialect, "mariadb");

    let e = &cap.events[0];
    assert_eq!(e.session_id, 12);
    assert_eq!(e.db.as_deref(), Some("shop"));
    assert_eq!(e.ts_micros, 1_784_200_221_000_000);
    assert_eq!(e.orig_query_time_s, 0.000118);
    assert_eq!(
        e.query,
        "SELECT id, name, price, added, note FROM items WHERE id = 3"
    );

    // Every event belongs to one of the three client threads and none of
    // the annotation lines leaked into statement text.
    for e in &cap.events {
        assert!((12..=14).contains(&e.session_id), "{}", e.session_id);
        assert_eq!(e.db.as_deref(), Some("shop"));
        assert!(!e.query.contains("explain"), "{}", e.query);
        assert!(e.query.starts_with("SELECT"), "{}", e.query);
    }
}

#[test]
fn multi_megabyte_single_statement() {
    // Generated rather than committed: a multi-MB file has no place in git
    // history when 30 lines of code reproduce it deterministically.
    let dir = std::env::temp_dir();
    let log = dir.join(format!(
        "sql-replay-corpus-test-multimb-{}.log",
        std::process::id()
    ));
    {
        use std::io::Write;
        let mut f = std::io::BufWriter::new(std::fs::File::create(&log).unwrap());
        write!(
            f,
            "# Time: 2024-03-01T07:00:00.000000Z\n\
             # User@Host: bulk[bulk] @ h []  Id:   901\n\
             # Query_time: 30.000000  Lock_time: 1.000000 Rows_sent: 0  Rows_examined: 0\n\
             SET timestamp=1709276400;\n\
             INSERT INTO blobs (id, payload) VALUES\n"
        )
        .unwrap();
        // ~40k rows x ~90 bytes: a single statement well past 3 MiB.
        for i in 0..40_000 {
            let sep = if i == 39_999 { ";" } else { "," };
            writeln!(
                f,
                "({i}, 'payload-{i:05}-{}'){sep}",
                "x".repeat(64 + (i % 17))
            )
            .unwrap();
        }
        writeln!(
            f,
            "# User@Host: bulk[bulk] @ h []  Id:   902\n\
             # Query_time: 0.001000  Lock_time: 0.000000 Rows_sent: 1  Rows_examined: 1\n\
             SET timestamp=1709276460;\n\
             SELECT 'after the blob';"
        )
        .unwrap();
    }

    let cap = capture_log(&log);
    std::fs::remove_file(&log).ok();

    assert_eq!(cap.summary.event_count, 2);
    let e = &cap.events[0];
    assert_eq!(e.session_id, 901);
    assert!(
        e.query.len() > 3 * 1024 * 1024,
        "statement should exceed 3 MiB, got {}",
        e.query.len()
    );
    assert_eq!(e.query.lines().count(), 40_001);
    assert!(e.query.starts_with("INSERT INTO blobs"));
    assert!(e.query.contains("(39999, 'payload-39999-"));
    assert_eq!(cap.events[1].query, "SELECT 'after the blob'");
}
