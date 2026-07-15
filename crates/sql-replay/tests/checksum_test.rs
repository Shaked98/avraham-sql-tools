//! End-to-end `--checksum` behavior against the mock target: identical
//! runs produce identical per-fingerprint digests, a planted data change
//! diverges them, `compare` classifies the divergence, and the checksum
//! machinery stays out of the way when the flag is off.

mod common;

use std::sync::atomic::Ordering;
use std::time::Duration;

use common::{no_shutdown, temp_path, write_capture, MockTarget};
use sql_replay::compare::{compare_runs, CompareOptions};
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

/// Two sessions, three fingerprints: a deterministic read (2 events), a
/// nondeterministic read, and a write (skipped without --allow-writes).
fn capture_path(name: &str) -> std::path::PathBuf {
    let path = temp_path(&format!("checksum-{name}.jsonl.zst"));
    write_capture(
        &path,
        &[
            ev(1, 0, 0, "SELECT v FROM t WHERE id = 1"),
            ev(2, 1, 0, "SELECT v FROM t WHERE id = 2"),
            ev(1, 2, 1, "SELECT id FROM t LIMIT 5"),
            ev(2, 3, 2, "INSERT INTO t VALUES (1)"),
        ],
    );
    path
}

async fn replay(capture: &std::path::Path, target: &MockTarget, checksum: bool) -> RunReport {
    let (_tx, rx) = no_shutdown();
    let options = ReplayOptions {
        checksum,
        ..ReplayOptions::new("mock://target")
    };
    let outcome =
        run_replay_with_target(capture, &options, target.clone(), TargetInfo::default(), rx)
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

#[tokio::test]
async fn checksums_are_stable_across_identical_runs_and_flag_off_means_none() {
    let cap = capture_path("stable");
    let target = MockTarget::new(Duration::ZERO);

    let run1 = replay(&cap, &target, true).await;
    let run2 = replay(&cap, &target, true).await;

    assert!(run1.flags.checksum);
    for id in [0u32, 1] {
        let (c1, c2) = (
            fp(&run1, id).checksum.as_ref().expect("checksummed"),
            fp(&run2, id).checksum.as_ref().expect("checksummed"),
        );
        assert_eq!(c1, c2, "identical runs must produce identical digests");
        assert_eq!(c1.rows_total, c1.events, "mock returns one row per query");
        assert_eq!(c1.columns, vec!["value".to_string()]);
        assert!(!c1.shape_varied);
    }
    // Two events of fingerprint 0 executed and were checksummed.
    assert_eq!(fp(&run1, 0).checksum.as_ref().unwrap().events, 2);
    // The nondeterminism classifier runs at report time: LIMIT without
    // ORDER BY is flagged, the plain lookup is not.
    assert!(!fp(&run1, 0).checksum.as_ref().unwrap().nondeterministic);
    assert!(fp(&run1, 1).checksum.as_ref().unwrap().nondeterministic);
    // The write was skipped by the gate: no checksum block at all.
    assert!(fp(&run1, 2).checksum.is_none());
    assert_eq!(fp(&run1, 2).skipped, 2 - 1); // 1 event, skipped

    // Flag off: no checksum blocks anywhere, flag recorded false.
    let plain = replay(&cap, &target, false).await;
    assert!(!plain.flags.checksum);
    assert!(plain.fingerprints.iter().all(|f| f.checksum.is_none()));
}

#[tokio::test]
async fn planted_data_change_diverges_digests_and_compare_flags_it() {
    let cap = capture_path("diverge");
    let target = MockTarget::new(Duration::ZERO);

    let baseline = replay(&cap, &target, true).await;
    // Plant a data change on the "candidate server".
    target.state.data_version.fetch_add(1, Ordering::SeqCst);
    let candidate = replay(&cap, &target, true).await;

    assert_ne!(
        fp(&baseline, 0).checksum.as_ref().unwrap().digest,
        fp(&candidate, 0).checksum.as_ref().unwrap().digest,
    );

    let rep = compare_runs(
        "baseline.json",
        &baseline,
        "candidate.json",
        &candidate,
        CompareOptions {
            threshold_pct: 20.0,
            min_count: 1,
        },
    );
    let corr = rep.correctness.as_ref().expect("correctness section");
    assert_eq!(corr.checked, 2);
    assert_eq!(corr.matched, 0);
    // The deterministic lookup is a hard mismatch; the LIMIT-without-
    // ORDER-BY fingerprint diverged too but is advisory.
    assert_eq!(corr.mismatches.len(), 1);
    assert!(corr.mismatches[0].fingerprint.contains("where id ="));
    assert_eq!(corr.advisory.len(), 1);
    assert!(corr.advisory[0].nondeterministic);
    assert!(rep.correctness_failed);

    // Identical data (same version): checked but silent.
    let candidate2 = replay(&cap, &target, true).await;
    let rep = compare_runs(
        "a.json",
        &candidate,
        "b.json",
        &candidate2,
        CompareOptions {
            threshold_pct: 20.0,
            min_count: 1,
        },
    );
    let corr = rep.correctness.as_ref().expect("correctness section");
    assert_eq!(corr.checked, 2);
    assert_eq!(corr.matched, 2);
    assert!(!rep.correctness_failed);
}
