//! End-to-end result-set byte counting against the mock target: replay
//! measures per-fingerprint byte stats on the streaming path (plain and
//! `--checksum` alike), splits them by result-size decade, and leaves the
//! fields absent where nothing executed. The mock's `MOCK_BYTES=<n>`
//! marker rides in a comment so differently-sized events share one
//! fingerprint — the exact "one fingerprint hides a 150x payload spread"
//! shape the decade split exists for.

mod common;

use std::time::Duration;

use common::{mock_result_bytes, no_shutdown, temp_path, write_capture, MockTarget};
use sql_replay::format::Event;
use sql_replay::replay::{run_replay_with_target, ReplayOptions, TargetInfo};
use sql_replay::report::RunReport;

fn ev(session: u64, ts_ms: i64, fp: u32, query: &str) -> Event {
    Event {
        ts_micros: 1_700_000_000_000_000 + ts_ms * 1_000,
        session_id: session,
        user: Some("app".to_string()),
        db: None,
        query: query.to_string(),
        orig_query_time_s: 0.001,
        fingerprint_id: fp,
    }
}

const SMALL: u64 = 500; // <1KB decade
const BIG: u64 = 2 * 1024 * 1024; // 1MB-10MB decade

/// One mixed-size fingerprint (2 small + 2 big fetches), one write
/// (skipped), one always-failing statement.
fn mixed_capture(name: &str) -> std::path::PathBuf {
    let path = temp_path(&format!("result-bytes-{name}.jsonl.zst"));
    write_capture(
        &path,
        &[
            ev(
                1,
                0,
                0,
                "SELECT body FROM docs WHERE id = 1 /* MOCK_BYTES=500 */",
            ),
            ev(
                2,
                1,
                0,
                "SELECT body FROM docs WHERE id = 2 /* MOCK_BYTES=500 */",
            ),
            ev(
                1,
                2,
                0,
                "SELECT body FROM docs WHERE id = 3 /* MOCK_BYTES=2097152 */",
            ),
            ev(
                2,
                3,
                0,
                "SELECT body FROM docs WHERE id = 4 /* MOCK_BYTES=2097152 */",
            ),
            ev(1, 4, 1, "INSERT INTO docs VALUES (1)"),
            ev(2, 5, 2, "SELECT MOCK_FAIL FROM t"),
        ],
    );
    path
}

async fn replay(capture: &std::path::Path, checksum: bool) -> RunReport {
    let (_tx, rx) = no_shutdown();
    let options = ReplayOptions {
        checksum,
        ..ReplayOptions::new("mock://target")
    };
    let outcome = run_replay_with_target(
        capture,
        &options,
        MockTarget::new(Duration::ZERO),
        TargetInfo::default(),
        rx,
    )
    .await
    .expect("replay");
    outcome.primary().clone()
}

fn fp(r: &RunReport, id: u32) -> &sql_replay::report::FingerprintReport {
    r.fingerprints
        .iter()
        .find(|f| f.id == id)
        .expect("fingerprint present")
}

#[test]
fn mock_bytes_marker_overrides_the_text_length_fallback() {
    assert_eq!(mock_result_bytes("SELECT 1 /* MOCK_BYTES=12345 */"), 12345);
    assert_eq!(mock_result_bytes("SELECT 1"), "SELECT 1".len() as u64);
    assert_eq!(
        mock_result_bytes("MOCK_BYTES=x"),
        "MOCK_BYTES=x".len() as u64
    );
}

#[tokio::test]
async fn byte_stats_are_measured_per_fingerprint_and_split_by_decade() {
    let cap = mixed_capture("plain");
    let run = replay(&cap, false).await;
    std::fs::remove_file(&cap).ok();

    let docs = fp(&run, 0);
    assert_eq!(docs.count, 4);
    let bytes = docs.result_bytes.as_ref().expect("byte stats present");
    assert_eq!(bytes.total, 2 * SMALL + 2 * BIG);
    assert_eq!(bytes.min, SMALL);
    assert_eq!(bytes.max, BIG);
    assert_eq!(bytes.mean, (2 * SMALL + 2 * BIG) as f64 / 4.0);
    // Percentiles come from a 2-significant-digit histogram: p50 lands on
    // (a quantized neighbor of) the small size, p95 on the big one.
    assert!(bytes.p50 >= SMALL && bytes.p50 < 2 * SMALL, "{}", bytes.p50);
    let p95 = bytes.p95 as f64;
    assert!((p95 - BIG as f64).abs() / (BIG as f64) < 0.02, "{p95}");

    // Two decades, in decade order, counts and byte totals exact.
    let buckets = &docs.size_buckets;
    assert_eq!(buckets.len(), 2);
    assert_eq!(buckets[0].bucket, "<1KB");
    assert_eq!(buckets[0].count, 2);
    assert_eq!(buckets[0].bytes_total, 2 * SMALL);
    assert_eq!(buckets[1].bucket, "1MB-10MB");
    assert_eq!(buckets[1].count, 2);
    assert_eq!(buckets[1].bytes_total, 2 * BIG);
    assert!(buckets[1].p95_us > 0);

    // Skipped (write gate) and all-error fingerprints executed nothing:
    // no byte stats, no decades.
    let write = fp(&run, 1);
    assert_eq!(write.skipped, 1);
    assert!(write.result_bytes.is_none());
    assert!(write.size_buckets.is_empty());
    let failing = fp(&run, 2);
    assert_eq!(failing.errors, 1);
    assert!(failing.result_bytes.is_none());
    assert!(failing.size_buckets.is_empty());

    // The new fields round-trip through run.json.
    let json = serde_json::to_string(&run).expect("serialize");
    let back: RunReport = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(fp(&back, 0).result_bytes, docs.result_bytes);
    assert_eq!(fp(&back, 0).size_buckets, docs.size_buckets);
}

// New 0.4.x top decades: 10MB-100MB and the open-ended >=100MB. Blob/CLOB
// results used to all collapse into the former ">=10MB" bucket.
const MID: u64 = 50 * 1024 * 1024; // 10MB-100MB decade
const HUGE: u64 = 150 * 1024 * 1024; // >=100MB decade

#[tokio::test]
async fn big_blob_results_split_into_the_new_top_decades() {
    let path = temp_path("result-bytes-blob.jsonl.zst");
    write_capture(
        &path,
        &[
            ev(
                1,
                0,
                0,
                "SELECT blob FROM docs WHERE id = 1 /* MOCK_BYTES=52428800 */",
            ),
            ev(
                1,
                1,
                0,
                "SELECT blob FROM docs WHERE id = 2 /* MOCK_BYTES=157286400 */",
            ),
        ],
    );
    let run = replay(&path, false).await;
    std::fs::remove_file(&path).ok();

    let docs = fp(&run, 0);
    assert_eq!(docs.count, 2);
    let bytes = docs.result_bytes.as_ref().expect("byte stats present");
    assert_eq!(bytes.max, HUGE);

    // Two distinct top decades — no longer both in one ">=10MB" bucket.
    let buckets = &docs.size_buckets;
    assert_eq!(buckets.len(), 2);
    assert_eq!(buckets[0].bucket, "10MB-100MB");
    assert_eq!(buckets[0].count, 1);
    assert_eq!(buckets[0].bytes_total, MID);
    assert_eq!(buckets[1].bucket, ">=100MB");
    assert_eq!(buckets[1].count, 1);
    assert_eq!(buckets[1].bytes_total, HUGE);
}

#[tokio::test]
async fn checksum_path_counts_the_same_bytes_as_the_plain_path() {
    let cap = mixed_capture("checksum");
    let plain = replay(&cap, false).await;
    let checksummed = replay(&cap, true).await;
    std::fs::remove_file(&cap).ok();

    let (p, c) = (fp(&plain, 0), fp(&checksummed, 0));
    assert_eq!(p.result_bytes, c.result_bytes);
    // Bucket latencies are wall-clock (they differ run to run); the byte
    // shape must match exactly.
    let shape = |f: &sql_replay::report::FingerprintReport| {
        f.size_buckets
            .iter()
            .map(|b| (b.bucket.clone(), b.count, b.bytes_total))
            .collect::<Vec<_>>()
    };
    assert_eq!(shape(p), shape(c));
    // And the checksum aggregate agrees on the same totals.
    let cs = c.checksum.as_ref().expect("checksummed");
    assert_eq!(cs.rows_total, 4);
}

#[tokio::test]
async fn statements_without_result_sets_count_zero_bytes_into_the_smallest_decade() {
    let path = temp_path("result-bytes-noresult.jsonl.zst");
    write_capture(
        &path,
        &[ev(
            1,
            0,
            0,
            "SELECT MOCK_NO_RESULT FROM t /* MOCK_BYTES=0 */",
        )],
    );
    let run = replay(&path, true).await;
    std::fs::remove_file(&path).ok();

    let f = fp(&run, 0);
    let bytes = f.result_bytes.as_ref().expect("byte stats present");
    assert_eq!(bytes.total, 0);
    assert_eq!(bytes.min, 0);
    assert_eq!(bytes.max, 0);
    assert_eq!(f.size_buckets.len(), 1);
    assert_eq!(f.size_buckets[0].bucket, "<1KB");
    assert_eq!(f.size_buckets[0].bytes_total, 0);
}
