//! `--repeat N` aggregation: fold N per-pass run reports into one
//! median-aggregated report.
//!
//! Every numeric metric (totals, per-fingerprint latencies and counts,
//! pacing, saturation) is the per-field median across passes — for an even
//! number of passes, the mean of the two middle values (integer metrics
//! round down). Medians are taken field-by-field, so the aggregated report
//! is not any single pass; it is the "typical pass" per metric, robust to
//! one outlier pass. Identity fields (target, flags, capture) come from the
//! first pass; `started_at`/`ended_at` span first pass start to last pass
//! end; `aborted` is true if any pass aborted.

use std::collections::BTreeMap;

use crate::report::{
    AggregationInfo, FingerprintReport, PacingReport, RunReport, SaturationReport, Totals,
};

fn median_u64(mut v: Vec<u64>) -> u64 {
    assert!(!v.is_empty(), "median of empty set");
    v.sort_unstable();
    let n = v.len();
    if n % 2 == 1 {
        v[n / 2]
    } else {
        // Sums of u64 latencies can overflow in theory; use u128.
        ((v[n / 2 - 1] as u128 + v[n / 2] as u128) / 2) as u64
    }
}

fn median_f64(mut v: Vec<f64>) -> f64 {
    assert!(!v.is_empty(), "median of empty set");
    v.sort_unstable_by(|a, b| a.partial_cmp(b).expect("metric medians are never NaN"));
    let n = v.len();
    if n % 2 == 1 {
        v[n / 2]
    } else {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    }
}

/// Aggregate `passes` (at least one) into a median report.
pub fn aggregate_median(passes: &[RunReport]) -> RunReport {
    assert!(!passes.is_empty(), "aggregate_median needs at least one pass");

    let u = |f: &dyn Fn(&RunReport) -> u64| median_u64(passes.iter().map(f).collect());
    let fl = |f: &dyn Fn(&RunReport) -> f64| median_f64(passes.iter().map(f).collect());

    // Per-fingerprint: union of ids across passes (in practice identical —
    // every pass replays the same spool); each metric is the median over
    // the passes in which the fingerprint appears.
    let mut by_id: BTreeMap<u32, Vec<&FingerprintReport>> = BTreeMap::new();
    for pass in passes {
        for fp in &pass.fingerprints {
            by_id.entry(fp.id).or_default().push(fp);
        }
    }
    let mut fingerprints: Vec<FingerprintReport> = by_id
        .into_iter()
        .map(|(id, fps)| {
            let mu = |f: &dyn Fn(&FingerprintReport) -> u64| {
                median_u64(fps.iter().map(|fp| f(fp)).collect())
            };
            FingerprintReport {
                id,
                fingerprint: fps[0].fingerprint.clone(),
                count: mu(&|f| f.count),
                errors: mu(&|f| f.errors),
                first_error: fps.iter().find_map(|f| f.first_error.clone()),
                skipped: mu(&|f| f.skipped),
                not_run: mu(&|f| f.not_run),
                p50_us: mu(&|f| f.p50_us),
                p95_us: mu(&|f| f.p95_us),
                p99_us: mu(&|f| f.p99_us),
                max_us: mu(&|f| f.max_us),
                mean_us: median_f64(fps.iter().map(|f| f.mean_us).collect()),
            }
        })
        .collect();
    fingerprints.sort_by(|a, b| b.p95_us.cmp(&a.p95_us).then(b.count.cmp(&a.count)));

    let pacing = if passes.iter().all(|p| p.pacing.is_some()) {
        let pu = |f: &dyn Fn(&PacingReport) -> u64| {
            median_u64(passes.iter().map(|p| f(p.pacing.as_ref().unwrap())).collect())
        };
        Some(PacingReport {
            speed: passes[0].pacing.as_ref().unwrap().speed,
            paced_events: pu(&|p| p.paced_events),
            max_lag_us: pu(&|p| p.max_lag_us),
            mean_lag_us: median_f64(
                passes
                    .iter()
                    .map(|p| p.pacing.as_ref().unwrap().mean_lag_us)
                    .collect(),
            ),
        })
    } else {
        None
    };

    let first = &passes[0];
    RunReport {
        tool: first.tool.clone(),
        tool_version: first.tool_version.clone(),
        capture_file: first.capture_file.clone(),
        capture_dialect: first.capture_dialect.clone(),
        target_url: first.target_url.clone(),
        target_server_version: first.target_server_version.clone(),
        started_at: first.started_at.clone(),
        ended_at: passes.last().expect("non-empty").ended_at.clone(),
        wall_secs: fl(&|p| p.wall_secs),
        aborted: passes.iter().any(|p| p.aborted),
        aggregation: Some(AggregationInfo {
            passes: passes.len() as u64,
            method: "median".to_string(),
        }),
        flags: first.flags.clone(),
        totals: Totals {
            events: u(&|p| p.totals.events),
            sessions: u(&|p| p.totals.sessions),
            executed: u(&|p| p.totals.executed),
            skipped: u(&|p| p.totals.skipped),
            errors: u(&|p| p.totals.errors),
            not_run: u(&|p| p.totals.not_run),
            connect_failures: u(&|p| p.totals.connect_failures),
            qps: fl(&|p| p.totals.qps),
            filtered: u(&|p| p.totals.filtered),
        },
        saturation: SaturationReport {
            samples: u(&|p| p.saturation.samples),
            saturated_samples: u(&|p| p.saturation.saturated_samples),
            saturated_pct: fl(&|p| p.saturation.saturated_pct),
        },
        pacing,
        target_settings: first.target_settings.clone(),
        fingerprints,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::ReportFlags;

    fn fp(id: u32, p95_us: u64, count: u64) -> FingerprintReport {
        FingerprintReport {
            id,
            fingerprint: format!("select {id}"),
            count,
            errors: 0,
            first_error: None,
            skipped: 0,
            not_run: 0,
            p50_us: p95_us / 2,
            p95_us,
            p99_us: p95_us + 10,
            max_us: p95_us + 20,
            mean_us: p95_us as f64 / 2.0,
        }
    }

    fn pass(qps: f64, wall: f64, fps: Vec<FingerprintReport>) -> RunReport {
        RunReport {
            tool: "sql-replay".to_string(),
            tool_version: "test".to_string(),
            capture_file: "cap.zst".to_string(),
            capture_dialect: "mysql-5.7".to_string(),
            target_url: "mysql://h/".to_string(),
            target_server_version: "8.0.46".to_string(),
            started_at: "2026-01-01T00:00:00Z".to_string(),
            ended_at: "2026-01-01T00:01:00Z".to_string(),
            wall_secs: wall,
            aborted: false,
            aggregation: None,
            flags: ReportFlags {
                max_connections: 50,
                allow_writes: false,
                read_only: false,
                db_override: None,
                speed: "max".to_string(),
                pool: None,
                warmup: false,
                filter_db: None,
                filter_user: None,
                time_window: None,
            },
            totals: Totals {
                events: 100,
                sessions: 10,
                executed: 90,
                skipped: 10,
                errors: 0,
                not_run: 0,
                connect_failures: 0,
                qps,
                filtered: 0,
            },
            saturation: SaturationReport {
                samples: 10,
                saturated_samples: 0,
                saturated_pct: 0.0,
            },
            pacing: None,
            target_settings: BTreeMap::new(),
            fingerprints: fps,
        }
    }

    #[test]
    fn median_helpers() {
        assert_eq!(median_u64(vec![5]), 5);
        assert_eq!(median_u64(vec![3, 1, 2]), 2);
        assert_eq!(median_u64(vec![1, 2, 3, 10]), 2); // (2+3)/2 rounds down
        assert_eq!(median_u64(vec![u64::MAX, u64::MAX]), u64::MAX); // no overflow
        assert_eq!(median_f64(vec![3.0, 1.0, 2.0]), 2.0);
        assert_eq!(median_f64(vec![1.0, 2.0, 3.0, 4.0]), 2.5);
    }

    #[test]
    fn odd_pass_count_takes_the_middle_pass_per_metric() {
        let passes = vec![
            pass(100.0, 3.0, vec![fp(0, 900, 30)]),
            pass(300.0, 1.0, vec![fp(0, 500, 30)]),
            pass(200.0, 2.0, vec![fp(0, 700, 30)]),
        ];
        let agg = aggregate_median(&passes);
        assert_eq!(agg.totals.qps, 200.0);
        assert_eq!(agg.wall_secs, 2.0);
        assert_eq!(agg.fingerprints.len(), 1);
        assert_eq!(agg.fingerprints[0].p95_us, 700);
        assert_eq!(agg.fingerprints[0].count, 30);
        let info = agg.aggregation.expect("aggregation info");
        assert_eq!(info.passes, 3);
        assert_eq!(info.method, "median");
        assert!(!agg.aborted);
        // Identity comes from the first pass; end time from the last.
        assert_eq!(agg.started_at, "2026-01-01T00:00:00Z");
    }

    #[test]
    fn even_pass_count_averages_the_middle_two() {
        let passes = vec![
            pass(100.0, 4.0, vec![fp(0, 100, 5)]),
            pass(200.0, 2.0, vec![fp(0, 301, 5)]),
        ];
        let agg = aggregate_median(&passes);
        assert_eq!(agg.totals.qps, 150.0);
        assert_eq!(agg.wall_secs, 3.0);
        assert_eq!(agg.fingerprints[0].p95_us, 200); // (100+301)/2 = 200 (floor)
    }

    #[test]
    fn fingerprint_missing_from_a_pass_uses_the_passes_it_appears_in() {
        let passes = vec![
            pass(1.0, 1.0, vec![fp(0, 100, 5), fp(1, 9000, 2)]),
            pass(1.0, 1.0, vec![fp(0, 200, 5)]),
            pass(1.0, 1.0, vec![fp(0, 300, 5)]),
        ];
        let agg = aggregate_median(&passes);
        assert_eq!(agg.fingerprints.len(), 2);
        // Sorted by p95 desc: the sparse fingerprint ranks first.
        assert_eq!(agg.fingerprints[0].id, 1);
        assert_eq!(agg.fingerprints[0].p95_us, 9000);
        assert_eq!(agg.fingerprints[1].p95_us, 200);
    }

    #[test]
    fn aborted_pass_marks_the_aggregate() {
        let mut p2 = pass(1.0, 1.0, vec![]);
        p2.aborted = true;
        let agg = aggregate_median(&[pass(1.0, 1.0, vec![]), p2]);
        assert!(agg.aborted);
    }

    #[test]
    fn pacing_aggregates_only_when_every_pass_is_paced() {
        let mut p1 = pass(1.0, 1.0, vec![]);
        let mut p2 = pass(1.0, 1.0, vec![]);
        p1.pacing = Some(PacingReport {
            speed: 2.0,
            paced_events: 10,
            max_lag_us: 100,
            mean_lag_us: 50.0,
        });
        let agg = aggregate_median(&[p1.clone(), p2.clone()]);
        assert!(agg.pacing.is_none(), "one unpaced pass -> no pacing block");

        p2.pacing = Some(PacingReport {
            speed: 2.0,
            paced_events: 10,
            max_lag_us: 300,
            mean_lag_us: 150.0,
        });
        let agg = aggregate_median(&[p1, p2]);
        let pacing = agg.pacing.expect("pacing aggregated");
        assert_eq!(pacing.max_lag_us, 200);
        assert_eq!(pacing.mean_lag_us, 100.0);
        assert_eq!(pacing.speed, 2.0);
    }
}
