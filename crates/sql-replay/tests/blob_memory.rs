//! Blob-heavy replay memory regression guard.
//!
//! Replays a workload of multi-MB LONGTEXT rows through the real binary
//! and asserts the child process's peak RSS stays bounded per
//! *connection* (packet buffer + one decoded row at a time), not per
//! result set. This is the guard against reintroducing whole-result-set
//! materialization (`collect()`-style handling in `target.rs`) or losing
//! the `memtune` retention fixes: a 32 MiB result set buffered per
//! connection would blow well past the bounds below.
//!
//! Needs a live server and measures process memory, so it is both gated
//! behind SQL_REPLAY_TEST_URL and `#[ignore]`d (bounds are calibrated
//! for release mode). CI runs it in the integration job:
//!
//!   SQL_REPLAY_TEST_URL=mysql://root@127.0.0.1:3306/sqlreplay \
//!       cargo test --release -p sql-replay --test blob_memory -- --ignored --nocapture
//!
//! It spawns the release binary (so `main`'s memtune tuning is part of
//! what is measured) and reads each child's peak RSS via `wait4(2)`.

use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

use mysql_async::prelude::Queryable;

const ROWS: usize = 8;
const ROW_BYTES: usize = 4 * 1024 * 1024; // per-row LONGTEXT payload
const SESSIONS: usize = 12;
const FETCHES_PER_SESSION: usize = 4;

/// Peak RSS bound for 12 dedicated concurrent sessions, in KiB.
///
/// Streaming floor: every session simultaneously mid-fetch costs
/// ~3x ROW_BYTES each (wire packet + decoded row + packet-buffer growth
/// transients) on top of a ~30 MiB base — ~170 MiB measured. Without the
/// `memtune` retention fixes the same leg measures ~320 MiB, and
/// buffering whole 32 MiB result sets per connection would add
/// >= 380 MiB more — both trip this bound.
const DEDICATED_BOUND_KIB: u64 = 256 * 1024;

/// Peak RSS bound for the same workload over `--pool 2`, in KiB.
///
/// Only 2 connections ever hold rows in flight: ~41 MiB measured.
/// This is the "memory bounded per connection, not per session" claim;
/// collecting result sets (>= 32 MiB per checked-out connection on top)
/// trips it.
const POOLED_BOUND_KIB: u64 = 96 * 1024;

/// Spawn and reap via wait4 so we get the child's peak RSS (KiB on
/// Linux) alongside its exit status.
// The child IS reaped — by wait4 below, which clippy cannot see.
#[allow(clippy::zombie_processes)]
fn run_measured(cmd: &mut Command) -> u64 {
    let child = cmd.spawn().expect("spawn sql-replay");
    let pid = child.id() as libc::pid_t;
    let mut status: libc::c_int = 0;
    // SAFETY: plain wait4 on a pid we own; rusage is a zeroed out-param.
    let mut rusage: libc::rusage = unsafe { std::mem::zeroed() };
    let reaped = unsafe { libc::wait4(pid, &mut status, 0, &mut rusage) };
    assert_eq!(reaped, pid, "wait4 reaps the child");
    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "sql-replay exited cleanly (status {status}): {cmd:?}"
    );
    rusage.ru_maxrss as u64
}

fn temp_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("sql-replay-blobmem-{}-{name}", std::process::id()))
}

/// A 5.7-dialect slow log: SESSIONS sessions, each full-scanning the
/// blob table FETCHES_PER_SESSION times. No `use` lines — events carry
/// no db metadata, so replay runs them against the URL's database.
fn write_slow_log(path: &PathBuf) {
    let mut f = std::fs::File::create(path).expect("create slow log");
    writeln!(
        f,
        "/usr/sbin/mysqld, Version: 5.7.44-log (MySQL Community Server (GPL)). started with:\n\
         Tcp port: 3306  Unix socket: /var/lib/mysql/mysql.sock\n\
         Time                 Id Command    Argument\n\
         # Time: 2026-07-16T12:00:00.000000Z"
    )
    .unwrap();
    for s in 0..SESSIONS {
        for _ in 0..FETCHES_PER_SESSION {
            writeln!(
                f,
                "# User@Host: blob[blob] @ localhost []  Id:    {}\n\
                 # Query_time: 0.010000  Lock_time: 0.000000 Rows_sent: {ROWS}  Rows_examined: {ROWS}\n\
                 SET timestamp=1784548800;\n\
                 SELECT id, body AS blob_scan FROM blob_mem_guard ORDER BY id;",
                101 + s,
            )
            .unwrap();
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a live server and release-calibrated memory bounds; run with -- --ignored"]
async fn blob_replay_memory_is_bounded_per_connection() {
    let Ok(url) = std::env::var("SQL_REPLAY_TEST_URL") else {
        eprintln!("SQL_REPLAY_TEST_URL not set; skipping blob memory guard");
        return;
    };

    // The server must allow ROW_BYTES-sized result packets (5.7 defaults
    // to 4 MiB). Raise the global for the duration; connections opened
    // after this (the loader below, the replay children) pick it up.
    let opts = mysql_async::Opts::from_url(&url).expect("parse url");
    let mut admin = mysql_async::Conn::new(opts.clone()).await.expect("connect");
    let old_packet: u64 = admin
        .query_first("SELECT @@GLOBAL.max_allowed_packet")
        .await
        .expect("read max_allowed_packet")
        .expect("row");
    let needed = (ROW_BYTES + 1024) as u64;
    if old_packet < needed {
        admin
            .query_drop("SET GLOBAL max_allowed_packet = 33554432")
            .await
            .expect("raise max_allowed_packet");
    }

    let mut conn = mysql_async::Conn::new(opts.clone()).await.expect("connect");
    conn.query_drop("DROP TABLE IF EXISTS blob_mem_guard")
        .await
        .unwrap();
    conn.query_drop(
        "CREATE TABLE blob_mem_guard (id INT NOT NULL PRIMARY KEY, body LONGTEXT NOT NULL) \
         ENGINE=InnoDB",
    )
    .await
    .unwrap();
    for i in 0..ROWS {
        // REPEAT generates the payload server-side; the statement itself
        // stays tiny.
        conn.query_drop(format!(
            "INSERT INTO blob_mem_guard VALUES ({i}, REPEAT(CHAR(97 + {i}), {ROW_BYTES}))"
        ))
        .await
        .expect("insert blob row");
    }
    let sizes: Vec<u64> = conn
        .query("SELECT LENGTH(body) FROM blob_mem_guard")
        .await
        .unwrap();
    assert_eq!(sizes.len(), ROWS);
    assert!(sizes.iter().all(|&s| s == ROW_BYTES as u64));

    let log = temp_path("blob.log");
    let capture = temp_path("blob.jsonl.zst");
    write_slow_log(&log);
    let bin = env!("CARGO_BIN_EXE_sql-replay");
    run_measured(
        Command::new(bin)
            .args(["capture", "--input"])
            .arg(&log)
            .arg("--out")
            .arg(&capture),
    );

    let replay = |extra: &[&str], out: &PathBuf| {
        let mut cmd = Command::new(bin);
        cmd.args(["replay", "--capture"])
            .arg(&capture)
            .args(["--url", &url])
            .args(extra)
            .arg("--out")
            .arg(out);
        cmd
    };

    // Leg 1: dedicated connections — memory scales with concurrent
    // connections, each bounded by a small multiple of the largest row.
    let out_dedicated = temp_path("run-dedicated.json");
    let peak = run_measured(&mut replay(&[], &out_dedicated));
    eprintln!(
        "dedicated ({SESSIONS} sessions): peak RSS {} MiB",
        peak / 1024
    );
    assert!(
        peak < DEDICATED_BOUND_KIB,
        "dedicated replay peak RSS {peak} KiB >= bound {DEDICATED_BOUND_KIB} KiB: \
         result rows are being buffered beyond one row per connection"
    );

    // Legs 2+3: --pool 2 with --checksum — in-flight rows are bounded by
    // the pool, and the checksum path must stream row-by-row too. Two
    // runs so the digests can be compared for determinism.
    let out_pool1 = temp_path("run-pool1.json");
    let out_pool2 = temp_path("run-pool2.json");
    for out in [&out_pool1, &out_pool2] {
        let peak = run_measured(&mut replay(&["--pool", "2", "--checksum"], out));
        eprintln!("--pool 2 --checksum: peak RSS {} MiB", peak / 1024);
        assert!(
            peak < POOLED_BOUND_KIB,
            "pooled replay peak RSS {peak} KiB >= bound {POOLED_BOUND_KIB} KiB: \
             replay memory is no longer bounded by the connection pool"
        );
    }

    let load = |p: &PathBuf| -> sql_replay::report::RunReport {
        serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
    };
    let (dedicated, pool1, pool2) = (load(&out_dedicated), load(&out_pool1), load(&out_pool2));
    let expected_events = (SESSIONS * FETCHES_PER_SESSION) as u64;
    for report in [&dedicated, &pool1, &pool2] {
        assert_eq!(report.totals.events, expected_events);
        assert_eq!(report.totals.executed, expected_events);
        assert_eq!(report.totals.errors, 0, "{:#?}", report.fingerprints);
    }
    // Identical data => identical order-insensitive digests, with every
    // row of every fetch accounted for.
    let checksum = |r: &sql_replay::report::RunReport| {
        let fp = &r.fingerprints[0];
        fp.checksum.clone().expect("checksum recorded")
    };
    let (cs1, cs2) = (checksum(&pool1), checksum(&pool2));
    assert_eq!(cs1.rows_total, expected_events * ROWS as u64);
    assert_eq!(cs1, cs2, "checksum digests differ between identical runs");

    conn.query_drop("DROP TABLE blob_mem_guard").await.unwrap();
    if old_packet < needed {
        admin
            .query_drop(format!("SET GLOBAL max_allowed_packet = {old_packet}"))
            .await
            .expect("restore max_allowed_packet");
    }
    for p in [log, capture, out_dedicated, out_pool1, out_pool2] {
        std::fs::remove_file(p).ok();
    }
}
