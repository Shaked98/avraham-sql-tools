//! Fixture-driven tests for the `compare` subcommand logic: the fixture
//! pair encodes known regressions, an improvement, a low-sample mover,
//! only-in-one fingerprints, executed-count mismatches, an error-count
//! change, and a target-settings diff between a 5.7 and an 8.0 run.

use sql_replay::compare::{compare_runs, CompareOptions, CompareReport};
use sql_replay::compare_html::render_html;
use sql_replay::report::RunReport;

fn load(name: &str) -> RunReport {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn fixture_compare() -> CompareReport {
    compare_runs(
        "run-baseline.json",
        &load("run-baseline.json"),
        "run-candidate.json",
        &load("run-candidate.json"),
        CompareOptions {
            threshold_pct: 20.0,
            min_count: 5,
        },
    )
}

#[test]
fn fixture_pair_classifies_and_ranks_regressions() {
    let rep = fixture_compare();

    // Worst p95 regression first: orders +200%, audit +140%, users +30%.
    let regs: Vec<&str> = rep
        .regressions
        .iter()
        .map(|d| d.fingerprint.as_str())
        .collect();
    assert_eq!(
        regs,
        [
            "select * from orders where id = ?",
            "insert into audit values(?)",
            "select * from users where email = ?"
        ]
    );
    assert!(rep.regressed);
    assert_eq!(rep.regressions[0].p95.delta_pct, Some(200.0));
    assert_eq!(rep.regressions[0].p95.baseline_us, 10_000.0);
    assert_eq!(rep.regressions[0].p95.candidate_us, 30_000.0);
    assert_eq!(rep.regressions[0].p95.delta_us, 20_000.0);
    assert_eq!(rep.regressions[1].p95.delta_pct, Some(140.0));
    assert!(rep.regressions[1].count_mismatch);
    assert_eq!(rep.regressions[2].p95.delta_pct, Some(30.0));

    let imps: Vec<&str> = rep
        .improvements
        .iter()
        .map(|d| d.fingerprint.as_str())
        .collect();
    assert_eq!(imps, ["select count(*) from sessions"]);
    assert_eq!(rep.improvements[0].p95.delta_pct, Some(-50.0));

    // +5% and +10% movers stay within the 20% threshold.
    let stable: Vec<&str> = rep.stable.iter().map(|d| d.fingerprint.as_str()).collect();
    assert!(stable.contains(&"show variables like ?"));
    assert!(stable.contains(&"select json_extract(doc, ?) from docs"));

    // A 10x low-sample mover stays out of the headline ranking.
    let low: Vec<&str> = rep
        .low_sample
        .iter()
        .map(|d| d.fingerprint.as_str())
        .collect();
    assert_eq!(low, ["select * from rare_table"]);
}

#[test]
fn fixture_pair_flags_only_in_one_counts_errors_and_settings() {
    let rep = fixture_compare();

    assert_eq!(rep.only_in_baseline.len(), 1);
    assert_eq!(
        rep.only_in_baseline[0].fingerprint,
        "select * from legacy_view"
    );
    assert_eq!(rep.only_in_candidate.len(), 1);
    assert_eq!(
        rep.only_in_candidate[0].fingerprint,
        "select /* new */ ? from dual"
    );

    // audit (20 -> 10) and json_extract (30 -> 5) executed-count mismatches.
    assert_eq!(rep.count_mismatches, 2);
    let json_fp = rep
        .stable
        .iter()
        .find(|d| d.fingerprint.contains("json_extract"))
        .expect("json_extract fingerprint is matched and within threshold");
    assert!(json_fp.count_mismatch);
    assert_eq!(json_fp.error_delta, 25);

    // 5.7 vs 8.0 settings differences show up in the diff...
    let names: Vec<&str> = rep.settings_diff.iter().map(|d| d.name.as_str()).collect();
    assert_eq!(
        names,
        ["character_set_server", "collation_server", "sql_mode"]
    );
    // ...and comparability warnings cover settings, fingerprint-table shape,
    // count mismatches, and the differing --speed flag.
    let warns = rep.comparability_warnings.join("\n");
    assert!(warns.contains("target server settings differ"));
    assert!(warns.contains("only in the baseline"));
    assert!(warns.contains("different number of times"));
    assert!(warns.contains("--speed differs"));

    assert_eq!(rep.totals.error_delta, 25);
    assert_eq!(rep.totals.qps_delta_pct.map(f64::round), Some(-30.0));
    assert_eq!(rep.baseline.target_server_version, "5.7.42-log");
    assert_eq!(rep.candidate.target_server_version, "8.0.46");
    // The candidate run's pacing metadata survives into the compare report.
    assert_eq!(rep.candidate.pacing.as_ref().unwrap().max_lag_us, 1500);
}

#[test]
fn json_report_round_trips() {
    let rep = fixture_compare();
    let json = serde_json::to_string_pretty(&rep).unwrap();
    let back: CompareReport = serde_json::from_str(&json).unwrap();
    assert_eq!(back.regressions.len(), rep.regressions.len());
    assert_eq!(back.regressed, rep.regressed);
    assert_eq!(back.settings_diff.len(), rep.settings_diff.len());
}

#[test]
fn stdout_summary_covers_all_sections() {
    let rep = fixture_compare();
    let text = rep.render_stdout(10);
    assert!(text.contains("COMPARABILITY WARNINGS"));
    assert!(text.contains("5.7.42-log"));
    assert!(text.contains("8.0.46"));
    assert!(text.contains("Regressions"));
    assert!(text.contains("+200.0%"));
    assert!(text.contains("Improvements"));
    assert!(text.contains("-50.0%"));
    assert!(text.contains("Low-sample"));
    assert!(text.contains("Only in baseline"));
    assert!(text.contains("Only in candidate"));
    assert!(text.contains("error-count changes"));
    assert!(text.contains("character_set_server: latin1 -> utf8mb4"));
    assert!(text.contains("[count mismatch]"));
}

#[test]
fn html_report_is_self_contained_and_escaped() {
    let rep = fixture_compare();
    let html = render_html(&rep);

    assert!(html.starts_with("<!doctype html>"));
    assert!(html.contains("<script>"));
    assert!(html.contains("</html>"));

    // Zero network requests: nothing may reference an external resource.
    for needle in [
        "http://",
        "https://",
        "<link",
        "@import",
        "url(",
        "src=",
        "integrity=",
    ] {
        assert!(!html.contains(needle), "HTML must not contain {needle:?}");
    }

    // Content and prominent version display.
    assert!(html.contains("5.7.42-log"));
    assert!(html.contains("8.0.46"));
    assert!(html.contains("Comparability warnings"));
    assert!(html.contains("Target settings diff"));
    assert!(html.contains("select * from orders where id = ?"));
    assert!(html.contains("table class=\"sortable\""));
    assert!(html.contains("Only in baseline"));
    assert!(html.contains("select /* new */ ? from dual"));
    // The count-mismatch badge renders on the mismatched regression row.
    assert!(html.contains("count mismatch"));
}

#[test]
fn m1_run_report_without_new_fields_still_loads() {
    // Strip the M2-only fields to simulate an M1 run.json.
    let path = format!(
        "{}/tests/fixtures/run-baseline.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let obj = v.as_object_mut().unwrap();
    obj.remove("target_settings");
    obj.remove("pacing");
    let m1: RunReport = serde_json::from_value(v).unwrap();
    assert!(m1.pacing.is_none());
    assert!(m1.target_settings.is_empty());

    // Comparing an M1 baseline against an M2 candidate must still work; every
    // candidate setting then shows as one-sided in the diff.
    let rep = compare_runs(
        "m1.json",
        &m1,
        "run-candidate.json",
        &load("run-candidate.json"),
        CompareOptions {
            threshold_pct: 20.0,
            min_count: 5,
        },
    );
    assert!(rep.regressed);
    assert!(rep.settings_diff.iter().all(|d| d.baseline.is_none()));
}
