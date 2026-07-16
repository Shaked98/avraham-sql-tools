//! The `compare` subcommand: diff two `replay --out run.json` reports to
//! find per-fingerprint latency regressions (baseline vs candidate, e.g.
//! MySQL 5.7 vs 8.0, or cross-engine MySQL 5.7 vs MariaDB — see
//! [`server_family`]).
//!
//! Fingerprints are matched by normalized text (not id), so runs from
//! different captures still line up where the workload overlaps — with
//! loud comparability warnings when the runs don't look comparable.
//! Regression gate: a fingerprint counts as regressed when its p95 delta
//! is at least `threshold_pct` (or its baseline p95 is zero while the
//! candidate's is not — an unbounded regression with no percentage) and it
//! executed at least `min_count` times in both runs; `compare` exits with
//! code 2 when any exist (see [`EXIT_REGRESSED`]). The same threshold and
//! min-count rules also run per result-size decade (0.4.0), so a
//! regression confined to one size class of an otherwise-stable
//! fingerprint still gates — those findings land in the separate
//! `size_regressions` list and drive the same exit code.

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

use crate::report::{PacingReport, ReportFlags, RunReport, Totals};

/// Process exit code when regressions at/beyond the threshold exist, so CI
/// can gate on `sql-replay compare` (0 = no regression, 1 = tool error).
pub const EXIT_REGRESSED: i32 = 2;

#[derive(Clone, Copy, Debug)]
pub struct CompareOptions {
    /// p95 percentage change at/beyond which a fingerprint is regressed
    /// (or, negated, improved) rather than noise.
    pub threshold_pct: f64,
    /// Minimum executed count in *both* runs for a fingerprint to enter the
    /// headline ranking; below it the fingerprint is listed as low-sample.
    pub min_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompareReport {
    pub tool: String,
    pub tool_version: String,
    pub threshold_pct: f64,
    pub min_count: u64,
    pub baseline: RunMeta,
    pub candidate: RunMeta,
    /// Non-empty when the two runs don't look comparable (different capture
    /// file, dialect, flags, fingerprint tables, executed counts, target
    /// settings).
    pub comparability_warnings: Vec<String>,
    /// Target variables whose values differ between the runs (or exist on
    /// only one side). Empty (see `settings_note`) when a side records no
    /// settings at all.
    pub settings_diff: Vec<SettingDiff>,
    /// Present when the settings diff was skipped because at least one run
    /// records no target settings (a recorded slow-log baseline, or an old
    /// pre-M2 run.json).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings_note: Option<String>,
    pub totals: TotalsDelta,
    /// Matched fingerprints with p95 delta >= threshold — plus zero-baseline
    /// fingerprints whose candidate p95 is nonzero (`delta_pct` is null for
    /// those; they rank worst) — worst first.
    pub regressions: Vec<FpDelta>,
    /// Matched fingerprints with p95 delta <= -threshold, best first.
    pub improvements: Vec<FpDelta>,
    /// Matched fingerprints within the threshold (noise).
    pub stable: Vec<FpDelta>,
    /// Matched fingerprints executed fewer than `min_count` times in either
    /// run — excluded from the headline ranking, listed below the fold.
    pub low_sample: Vec<FpDelta>,
    pub only_in_baseline: Vec<OnlyIn>,
    pub only_in_candidate: Vec<OnlyIn>,
    /// Matched fingerprints whose executed counts differ between the runs.
    pub count_mismatches: u64,
    /// True when `regressions` is non-empty; drives the exit code.
    pub regressed: bool,
    /// Result-correctness diff, present when both runs recorded result
    /// checksums (`replay --checksum`); 0.3.0, serde-defaulted so older
    /// compare reports load.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correctness: Option<CorrectnessReport>,
    /// True when `correctness.mismatches` is non-empty — a deterministic
    /// query returned different data. Drives exit code 2 like `regressed`
    /// (a wrong answer is worse than a slow one).
    #[serde(default)]
    pub correctness_failed: bool,
    /// Result-size-decade regressions (0.4.0): matched fingerprints whose
    /// *decade sub-population* p95 regressed at/beyond the threshold while
    /// the fingerprint-wide p95 did not — the "regression only on big
    /// rows, averaged away by the mixed-size percentiles" case.
    /// Fingerprints already in `regressions` are not repeated here (their
    /// per-decade split is in the run reports' `size_buckets`). Worst
    /// first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub size_regressions: Vec<BucketDelta>,
    /// Matched (fingerprint, decade) pairs whose sub-populations were big
    /// enough to compare (count >= min_count in both runs).
    #[serde(default)]
    pub size_buckets_checked: u64,
    /// Present when the byte/size-decade comparison was skipped because at
    /// least one run records no result-set byte stats (a pre-0.4.0 report
    /// or a recorded baseline).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_note: Option<String>,
    /// True when `size_regressions` is non-empty. Drives exit code 2 like
    /// `regressed` (which stays fingerprint-level for compatibility with
    /// existing consumers).
    #[serde(default)]
    pub size_regressed: bool,
}

/// Result-correctness section: matched fingerprints whose result-set
/// checksums diverge between the runs. Only meaningful when both runs
/// executed against identical data — see `note`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrectnessReport {
    /// Matched fingerprints checksummed (with at least one result set) in
    /// both runs.
    pub checked: u64,
    /// ... of which the digests agree.
    pub matched: u64,
    /// Deterministic fingerprints with diverging results: hard failures.
    pub mismatches: Vec<ChecksumDelta>,
    /// Diverging fingerprints that are classified nondeterministic (or
    /// whose checksummed event counts differ, making the multisets
    /// incomparable): advisory only, not failures.
    pub advisory: Vec<ChecksumDelta>,
    pub note: String,
}

/// One fingerprint's checksum divergence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChecksumDelta {
    pub fingerprint: String,
    pub baseline_digest: String,
    pub candidate_digest: String,
    pub baseline_rows: u64,
    pub candidate_rows: u64,
    /// Checksummed events per side; unequal populations cannot be
    /// compared conclusively (the delta is then advisory).
    pub baseline_events: u64,
    pub candidate_events: u64,
    pub columns_differ: bool,
    pub nondeterministic: bool,
    pub events_differ: bool,
}

/// Per-run metadata carried into the compare report so both runs' context
/// (server version, flags, settings) is visible side by side.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunMeta {
    pub file: String,
    /// See [`RunReport::latency_source`]; defaults to replayed for
    /// pre-0.2.0 reports.
    #[serde(default = "crate::report::default_latency_source")]
    pub latency_source: String,
    /// Empty for recorded baselines — display via
    /// [`RunMeta::display_server_version`].
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub target_server_version: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub target_url: String,
    pub capture_file: String,
    pub capture_dialect: String,
    pub started_at: String,
    pub wall_secs: f64,
    pub flags: ReportFlags,
    pub totals: Totals,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pacing: Option<PacingReport>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub target_settings: BTreeMap<String, String>,
}

impl RunMeta {
    pub fn is_recorded(&self) -> bool {
        self.latency_source == crate::report::LATENCY_SOURCE_RECORDED
    }

    /// The server version for display: recorded baselines have none (the
    /// slow log doesn't know it), so show their provenance instead of a
    /// blank. MariaDB's replication-compat `5.5.5-` prefix (seen when the
    /// version string comes through a proxy that forwards the wire
    /// greeting) is stripped — `5.5.5-10.11.18-MariaDB` is not a version.
    pub fn display_server_version(&self) -> String {
        if !self.target_server_version.is_empty() {
            strip_maria_compat_prefix(&self.target_server_version).to_string()
        } else if self.is_recorded() {
            "recorded (slow log)".to_string()
        } else {
            "unknown".to_string()
        }
    }

    fn from_report(file: &str, r: &RunReport) -> Self {
        RunMeta {
            file: file.to_string(),
            latency_source: r.latency_source.clone(),
            target_server_version: r.target_server_version.clone(),
            target_url: r.target_url.clone(),
            capture_file: r.capture_file.clone(),
            capture_dialect: r.capture_dialect.clone(),
            started_at: r.started_at.clone(),
            wall_secs: r.wall_secs,
            flags: r.flags.clone(),
            totals: r.totals.clone(),
            pacing: r.pacing.clone(),
            target_settings: r.target_settings.clone(),
        }
    }
}

/// Engine family of a `SELECT VERSION()` string. MariaDB servers report
/// versions like `10.11.18-MariaDB-ubu2204`; anything else nonempty is
/// MySQL-family (Percona included — it tracks MySQL behavior). `None` for
/// the empty string (recorded baselines carry no version).
pub fn server_family(version: &str) -> Option<&'static str> {
    if version.is_empty() {
        None
    } else if version.contains("MariaDB") {
        Some("MariaDB")
    } else {
        Some("MySQL")
    }
}

/// Strip MariaDB's `5.5.5-` replication-compat prefix (prepended to the
/// wire-protocol greeting for old clients; a proxy can surface it in the
/// version string). Real versions never have it, so only strip when the
/// remainder names MariaDB.
fn strip_maria_compat_prefix(version: &str) -> &str {
    version
        .strip_prefix("5.5.5-")
        .filter(|rest| rest.contains("MariaDB"))
        .unwrap_or(version)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettingDiff {
    pub name: String,
    pub baseline: Option<String>,
    pub candidate: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotalsDelta {
    pub baseline_qps: f64,
    pub candidate_qps: f64,
    pub qps_delta_pct: Option<f64>,
    pub baseline_wall_secs: f64,
    pub candidate_wall_secs: f64,
    pub wall_delta_pct: Option<f64>,
    pub baseline_executed: u64,
    pub candidate_executed: u64,
    pub baseline_errors: u64,
    pub candidate_errors: u64,
    pub error_delta: i64,
}

/// One latency metric compared across the runs. `delta_pct` is `None` when
/// the baseline value is zero (no percentage is meaningful).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricDelta {
    pub baseline_us: f64,
    pub candidate_us: f64,
    pub delta_us: f64,
    pub delta_pct: Option<f64>,
}

impl MetricDelta {
    fn new(baseline_us: f64, candidate_us: f64) -> Self {
        MetricDelta {
            baseline_us,
            candidate_us,
            delta_us: candidate_us - baseline_us,
            delta_pct: pct_change(baseline_us, candidate_us),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FpDelta {
    pub fingerprint: String,
    pub baseline_count: u64,
    pub candidate_count: u64,
    /// The runs executed this fingerprint a different number of times, so
    /// its latency populations may not be comparable.
    pub count_mismatch: bool,
    pub baseline_errors: u64,
    pub candidate_errors: u64,
    pub error_delta: i64,
    pub p50: MetricDelta,
    pub p95: MetricDelta,
    pub p99: MetricDelta,
    pub mean: MetricDelta,
    /// Result-set bytes per executed statement, present when both runs
    /// record byte stats for this fingerprint (0.4.0). A large shift is
    /// itself a signal: the two targets returned differently-sized data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_bytes: Option<BytesDelta>,
}

/// Result-set byte stats of one fingerprint compared across the runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BytesDelta {
    pub baseline_mean: f64,
    pub candidate_mean: f64,
    /// `None` when the baseline mean is zero.
    pub mean_delta_pct: Option<f64>,
    pub baseline_total: u64,
    pub candidate_total: u64,
}

/// One regressed result-size decade of a matched fingerprint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BucketDelta {
    pub fingerprint: String,
    /// Decade label ([`crate::report::SIZE_BUCKET_LABELS`]).
    pub bucket: String,
    pub baseline_count: u64,
    pub candidate_count: u64,
    /// The decade's populations differ in size — result sizes shifted
    /// between the runs (or coverage differs), so the latency comparison
    /// is weaker.
    pub count_mismatch: bool,
    pub p50: MetricDelta,
    pub p95: MetricDelta,
    pub mean: MetricDelta,
    pub baseline_bytes_total: u64,
    pub candidate_bytes_total: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnlyIn {
    pub fingerprint: String,
    pub count: u64,
    pub errors: u64,
}

fn pct_change(base: f64, cand: f64) -> Option<f64> {
    if base > 0.0 {
        Some((cand - base) / base * 100.0)
    } else {
        None
    }
}

pub fn compare_runs(
    baseline_file: &str,
    baseline: &RunReport,
    candidate_file: &str,
    candidate: &RunReport,
    options: CompareOptions,
) -> CompareReport {
    let mut warnings = Vec::new();

    if baseline.capture_file != candidate.capture_file {
        warnings.push(format!(
            "the runs replayed different capture files ({} vs {}) — deltas may reflect \
             different workloads, not server behavior",
            baseline.capture_file, candidate.capture_file
        ));
    }
    if baseline.capture_dialect != candidate.capture_dialect {
        warnings.push(format!(
            "capture dialects differ ({} vs {})",
            baseline.capture_dialect, candidate.capture_dialect
        ));
    }
    // Cross-engine comparison (MySQL -> MariaDB migration validation) is a
    // supported workflow, but the reader should know the settings diff and
    // behavior deltas below span an engine boundary, not just a version
    // bump.
    if let (Some(bf), Some(cf)) = (
        server_family(&baseline.target_server_version),
        server_family(&candidate.target_server_version),
    ) {
        if bf != cf {
            warnings.push(format!(
                "target engine families differ: {bf} (baseline) vs {cf} (candidate) — \
                 engine defaults (sql_mode, collations, optimizer behavior) differ by \
                 design; entries in the settings diff may reflect differing engine \
                 defaults rather than misconfiguration, but they still change behavior \
                 and are worth reviewing for a migration"
            ));
        }
    }
    // One recorded side + one replayed side is the tool's intended
    // production-baseline workflow, but the measurement planes differ
    // systematically — say so up front, and loudly.
    let both_replayed = !baseline.is_recorded() && !candidate.is_recorded();
    if baseline.is_recorded() != candidate.is_recorded() {
        let (rec, rep) = if baseline.is_recorded() {
            ("baseline", "candidate")
        } else {
            ("candidate", "baseline")
        };
        warnings.push(format!(
            "MEASUREMENT PLANES DIFFER: the {rec} latencies were recorded in the source \
             capture — server-side slow-log Query_time (measured under live production \
             load, including lock waits and contention) or request→response wire time \
             for pcap captures (server plus the capture-point→server network path) — \
             while the {rep} latencies are client-side wall times measured by replay \
             from the test host (including network round-trip and driver overhead). \
             Deltas mix real server changes with this measurement gap — use a generous \
             --threshold-pct and treat small deltas as noise"
        ));
    }
    // Replay-execution knobs (speed, connection caps, write gate, ...) only
    // exist on replayed runs; comparing them against a recorded baseline
    // would be pure noise. Filter flags always matter — they change which
    // slice of the capture each report covers.
    for (name, b, c) in flag_diffs(&baseline.flags, &candidate.flags, both_replayed) {
        warnings.push(format!(
            "replay flag --{name} differs: {b} (baseline) vs {c} (candidate)"
        ));
    }
    for (label, run) in [("baseline", baseline), ("candidate", candidate)] {
        if run.aborted {
            warnings.push(format!(
                "the {label} run was aborted mid-replay — its latency populations are \
                 partial and may not be comparable"
            ));
        }
    }

    // A side with no recorded settings has nothing to diff against — skip
    // the section with a note instead of listing every other-side variable
    // as a spurious one-sided change.
    let no_settings_side = |r: &RunReport| {
        if r.is_recorded() {
            "records no target settings (recorded from the slow log)"
        } else {
            "records no target settings (older report)"
        }
    };
    let (settings_diff, settings_note) = match (
        baseline.target_settings.is_empty(),
        candidate.target_settings.is_empty(),
    ) {
        (false, false) => (
            settings_diff(&baseline.target_settings, &candidate.target_settings),
            None,
        ),
        (true, true) => (
            Vec::new(),
            Some("settings diff skipped: neither run records target settings".to_string()),
        ),
        (b_empty, _) => {
            let (side, run) = if b_empty {
                ("baseline", baseline)
            } else {
                ("candidate", candidate)
            };
            (
                Vec::new(),
                Some(format!(
                    "settings diff skipped: the {side} run {}",
                    no_settings_side(run)
                )),
            )
        }
    };
    if !settings_diff.is_empty() {
        let names: Vec<&str> = settings_diff.iter().map(|d| d.name.as_str()).collect();
        warnings.push(format!(
            "target server settings differ: {} (see settings diff)",
            names.join(", ")
        ));
    }

    // Match fingerprints by normalized text; ids are capture-local.
    let cand_by_text: HashMap<&str, &crate::report::FingerprintReport> = candidate
        .fingerprints
        .iter()
        .map(|f| (f.fingerprint.as_str(), f))
        .collect();
    let base_texts: std::collections::HashSet<&str> = baseline
        .fingerprints
        .iter()
        .map(|f| f.fingerprint.as_str())
        .collect();

    // Result-correctness diff: only when both runs recorded checksums.
    let both_checksummed = baseline.flags.checksum && candidate.flags.checksum;
    if baseline.flags.checksum != candidate.flags.checksum {
        let (with, without) = if baseline.flags.checksum {
            ("baseline", "candidate")
        } else {
            ("candidate", "baseline")
        };
        warnings.push(format!(
            "only the {with} run recorded result checksums (--checksum) — the \
             correctness diff is skipped, and the {with} run's latencies include \
             reading every result row, so they are not comparable to the {without} \
             run's"
        ));
    }
    let mut correctness = both_checksummed.then(|| CorrectnessReport {
        checked: 0,
        matched: 0,
        mismatches: Vec::new(),
        advisory: Vec::new(),
        note: "result checksums diverge meaningfully only when both runs executed \
               against identical data; nondeterministic queries (volatile functions, \
               LIMIT without ORDER BY, server-state reads) are listed as advisory"
            .to_string(),
    });

    // Result-set byte stats exist only on replayed 0.4.0+ reports; when a
    // side has none the byte columns show n/a and the decade comparison is
    // skipped with a note rather than a spurious verdict.
    let has_bytes = |r: &RunReport| r.fingerprints.iter().any(|f| f.result_bytes.is_some());
    let no_bytes_side = |r: &RunReport| {
        if r.is_recorded() {
            "records no result-set byte stats (recorded latencies — the capture \
             carries no result sizes)"
        } else {
            "records no result-set byte stats (pre-0.4.0 report)"
        }
    };
    let size_note = match (has_bytes(baseline), has_bytes(candidate)) {
        (true, true) => None,
        (false, false) => Some(
            "result-set byte and size-decade comparison skipped: neither run records \
             byte stats"
                .to_string(),
        ),
        (b_has, _) => {
            let (side, run) = if !b_has {
                ("baseline", baseline)
            } else {
                ("candidate", candidate)
            };
            Some(format!(
                "result-set byte and size-decade comparison skipped: the {side} run {}",
                no_bytes_side(run)
            ))
        }
    };

    let mut regressions = Vec::new();
    let mut improvements = Vec::new();
    let mut stable = Vec::new();
    let mut low_sample = Vec::new();
    let mut only_in_baseline = Vec::new();
    let mut count_mismatches = 0u64;
    let mut size_regressions: Vec<BucketDelta> = Vec::new();
    let mut size_buckets_checked = 0u64;

    for b in &baseline.fingerprints {
        let Some(c) = cand_by_text.get(b.fingerprint.as_str()) else {
            only_in_baseline.push(OnlyIn {
                fingerprint: b.fingerprint.clone(),
                count: b.count,
                errors: b.errors,
            });
            continue;
        };
        let count_mismatch = b.count != c.count;
        if count_mismatch {
            count_mismatches += 1;
        }
        if let Some(corr) = correctness.as_mut() {
            if let (Some(bc), Some(cc)) = (&b.checksum, &c.checksum) {
                if bc.events > 0 && cc.events > 0 {
                    corr.checked += 1;
                    if bc.digest == cc.digest {
                        corr.matched += 1;
                    } else {
                        let delta = ChecksumDelta {
                            fingerprint: b.fingerprint.clone(),
                            baseline_digest: bc.digest.clone(),
                            candidate_digest: cc.digest.clone(),
                            baseline_rows: bc.rows_total,
                            candidate_rows: cc.rows_total,
                            baseline_events: bc.events,
                            candidate_events: cc.events,
                            columns_differ: bc.columns != cc.columns,
                            nondeterministic: bc.nondeterministic || cc.nondeterministic,
                            events_differ: bc.events != cc.events,
                        };
                        if delta.nondeterministic || delta.events_differ {
                            corr.advisory.push(delta);
                        } else {
                            corr.mismatches.push(delta);
                        }
                    }
                }
            }
        }
        let delta = FpDelta {
            fingerprint: b.fingerprint.clone(),
            baseline_count: b.count,
            candidate_count: c.count,
            count_mismatch,
            baseline_errors: b.errors,
            candidate_errors: c.errors,
            error_delta: c.errors as i64 - b.errors as i64,
            p50: MetricDelta::new(b.p50_us as f64, c.p50_us as f64),
            p95: MetricDelta::new(b.p95_us as f64, c.p95_us as f64),
            p99: MetricDelta::new(b.p99_us as f64, c.p99_us as f64),
            mean: MetricDelta::new(b.mean_us, c.mean_us),
            result_bytes: match (&b.result_bytes, &c.result_bytes) {
                (Some(bb), Some(cb)) => Some(BytesDelta {
                    baseline_mean: bb.mean,
                    candidate_mean: cb.mean,
                    mean_delta_pct: pct_change(bb.mean, cb.mean),
                    baseline_total: bb.total,
                    candidate_total: cb.total,
                }),
                _ => None,
            },
        };
        // Zero-count sides carry no latency population, so they can never
        // enter the headline ranking regardless of --min-count.
        let mut fp_regressed = false;
        if b.count == 0
            || c.count == 0
            || b.count < options.min_count
            || c.count < options.min_count
        {
            low_sample.push(delta);
        } else {
            match delta.p95.delta_pct {
                Some(p) if p >= options.threshold_pct => {
                    fp_regressed = true;
                    regressions.push(delta);
                }
                Some(p) if p <= -options.threshold_pct => improvements.push(delta),
                // A zero baseline yields no percentage, but any nonzero
                // candidate is an unbounded regression, not noise.
                None if delta.p95.candidate_us > 0.0 => {
                    fp_regressed = true;
                    regressions.push(delta);
                }
                _ => stable.push(delta),
            }
        }

        // Size-decade sub-populations: the same threshold and min-count
        // rules, applied per decade, so a regression confined to one size
        // class can't hide inside a stable mixed-size percentile. A decade
        // present on only one side is skipped (its events moved decades —
        // the byte columns already surface that).
        let cand_buckets: HashMap<&str, &crate::report::SizeBucketReport> = c
            .size_buckets
            .iter()
            .map(|s| (s.bucket.as_str(), s))
            .collect();
        for bb in &b.size_buckets {
            let Some(cb) = cand_buckets.get(bb.bucket.as_str()) else {
                continue;
            };
            if bb.count == 0
                || cb.count == 0
                || bb.count < options.min_count
                || cb.count < options.min_count
            {
                continue;
            }
            size_buckets_checked += 1;
            if fp_regressed {
                // Already flagged at the fingerprint level; the per-decade
                // split lives in the run reports' size_buckets.
                continue;
            }
            let p95 = MetricDelta::new(bb.p95_us as f64, cb.p95_us as f64);
            let bucket_regressed = match p95.delta_pct {
                Some(p) => p >= options.threshold_pct,
                None => p95.candidate_us > 0.0,
            };
            if bucket_regressed {
                size_regressions.push(BucketDelta {
                    fingerprint: b.fingerprint.clone(),
                    bucket: bb.bucket.clone(),
                    baseline_count: bb.count,
                    candidate_count: cb.count,
                    count_mismatch: bb.count != cb.count,
                    p50: MetricDelta::new(bb.p50_us as f64, cb.p50_us as f64),
                    p95,
                    mean: MetricDelta::new(bb.mean_us, cb.mean_us),
                    baseline_bytes_total: bb.bytes_total,
                    candidate_bytes_total: cb.bytes_total,
                });
            }
        }
    }

    let mut only_in_candidate: Vec<OnlyIn> = candidate
        .fingerprints
        .iter()
        .filter(|c| !base_texts.contains(c.fingerprint.as_str()))
        .map(|c| OnlyIn {
            fingerprint: c.fingerprint.clone(),
            count: c.count,
            errors: c.errors,
        })
        .collect();

    // Rank: worst p95 regression first / best improvement first; ties by
    // absolute delta so big absolute movers outrank tiny ones.
    let pct = |d: &FpDelta| d.p95.delta_pct.unwrap_or(0.0);
    let reg_pct = |d: &FpDelta| d.p95.delta_pct.unwrap_or(f64::INFINITY);
    regressions.sort_by(|a, b| {
        reg_pct(b)
            .total_cmp(&reg_pct(a))
            .then(b.p95.delta_us.total_cmp(&a.p95.delta_us))
    });
    improvements.sort_by(|a, b| {
        pct(a)
            .total_cmp(&pct(b))
            .then(a.p95.delta_us.total_cmp(&b.p95.delta_us))
    });
    low_sample.sort_by(|a, b| pct(b).total_cmp(&pct(a)));
    let bucket_pct = |d: &BucketDelta| d.p95.delta_pct.unwrap_or(f64::INFINITY);
    size_regressions.sort_by(|a, b| {
        bucket_pct(b)
            .total_cmp(&bucket_pct(a))
            .then(b.p95.delta_us.total_cmp(&a.p95.delta_us))
    });
    only_in_baseline.sort_by_key(|o| std::cmp::Reverse(o.count));
    only_in_candidate.sort_by_key(|o| std::cmp::Reverse(o.count));

    if !only_in_baseline.is_empty() || !only_in_candidate.is_empty() {
        warnings.push(format!(
            "fingerprint tables differ: {} fingerprint(s) only in the baseline run, {} only \
             in the candidate run — the runs may not cover the same workload",
            only_in_baseline.len(),
            only_in_candidate.len()
        ));
    }
    if count_mismatches > 0 {
        warnings.push(format!(
            "{count_mismatches} matched fingerprint(s) executed a different number of times \
             in the two runs — their latency populations may not be comparable"
        ));
    }

    let correctness_failed = correctness
        .as_ref()
        .is_some_and(|c| !c.mismatches.is_empty());
    if let Some(corr) = &mut correctness {
        // Deterministic order: worst absolute row delta first.
        let rank =
            |d: &ChecksumDelta| std::cmp::Reverse(d.baseline_rows.abs_diff(d.candidate_rows));
        corr.mismatches.sort_by_key(rank);
        corr.advisory.sort_by_key(rank);
        if correctness_failed {
            warnings.push(format!(
                "RESULT MISMATCH: {} fingerprint(s) returned different data on the two \
                 targets (see the correctness section) — if both runs executed against \
                 identical data, the candidate server returns wrong answers",
                corr.mismatches.len()
            ));
        }
    }

    let bt = &baseline.totals;
    let ct = &candidate.totals;
    let regressed = !regressions.is_empty();
    let size_regressed = !size_regressions.is_empty();
    CompareReport {
        tool: "sql-replay".to_string(),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        threshold_pct: options.threshold_pct,
        min_count: options.min_count,
        baseline: RunMeta::from_report(baseline_file, baseline),
        candidate: RunMeta::from_report(candidate_file, candidate),
        comparability_warnings: warnings,
        settings_diff,
        settings_note,
        totals: TotalsDelta {
            baseline_qps: bt.qps,
            candidate_qps: ct.qps,
            qps_delta_pct: pct_change(bt.qps, ct.qps),
            baseline_wall_secs: baseline.wall_secs,
            candidate_wall_secs: candidate.wall_secs,
            wall_delta_pct: pct_change(baseline.wall_secs, candidate.wall_secs),
            baseline_executed: bt.executed,
            candidate_executed: ct.executed,
            baseline_errors: bt.errors,
            candidate_errors: ct.errors,
            error_delta: ct.errors as i64 - bt.errors as i64,
        },
        regressions,
        improvements,
        stable,
        low_sample,
        only_in_baseline,
        only_in_candidate,
        count_mismatches,
        regressed,
        correctness,
        correctness_failed,
        size_regressions,
        size_buckets_checked,
        size_note,
        size_regressed,
    }
}

fn flag_diffs(
    b: &ReportFlags,
    c: &ReportFlags,
    include_replay_knobs: bool,
) -> Vec<(&'static str, String, String)> {
    let mut out = Vec::new();
    if include_replay_knobs {
        if b.max_connections != c.max_connections {
            out.push((
                "max-connections",
                b.max_connections.to_string(),
                c.max_connections.to_string(),
            ));
        }
        if b.allow_writes != c.allow_writes {
            out.push((
                "allow-writes",
                b.allow_writes.to_string(),
                c.allow_writes.to_string(),
            ));
        }
        if b.db_override != c.db_override {
            let show = |v: &Option<String>| v.clone().unwrap_or_else(|| "<none>".to_string());
            out.push(("db-override", show(&b.db_override), show(&c.db_override)));
        }
        if b.speed != c.speed {
            out.push(("speed", b.speed.clone(), c.speed.clone()));
        }
        if b.pool != c.pool {
            let show = |v: &Option<usize>| {
                v.map(|n| n.to_string())
                    .unwrap_or_else(|| "<none>".to_string())
            };
            out.push(("pool", show(&b.pool), show(&c.pool)));
        }
        if b.warmup != c.warmup {
            out.push(("warmup", b.warmup.to_string(), c.warmup.to_string()));
        }
        if b.checksum != c.checksum {
            out.push(("checksum", b.checksum.to_string(), c.checksum.to_string()));
        }
    }
    let show = |v: &Option<String>| v.clone().unwrap_or_else(|| "<none>".to_string());
    if b.filter_db != c.filter_db {
        out.push(("filter-db", show(&b.filter_db), show(&c.filter_db)));
    }
    if b.filter_user != c.filter_user {
        out.push(("filter-user", show(&b.filter_user), show(&c.filter_user)));
    }
    if b.time_window != c.time_window {
        out.push(("time-window", show(&b.time_window), show(&c.time_window)));
    }
    out
}

fn settings_diff(b: &BTreeMap<String, String>, c: &BTreeMap<String, String>) -> Vec<SettingDiff> {
    let mut names: Vec<&String> = b.keys().chain(c.keys()).collect();
    names.sort();
    names.dedup();
    names
        .into_iter()
        .filter(|n| b.get(*n) != c.get(*n))
        .map(|n| SettingDiff {
            name: n.clone(),
            baseline: b.get(n).cloned(),
            candidate: c.get(n).cloned(),
        })
        .collect()
}

fn fmt_pct(p: Option<f64>) -> String {
    match p {
        Some(p) => format!("{p:+.1}%"),
        None => "n/a".to_string(),
    }
}

fn fmt_ms(us: f64) -> String {
    format!("{:.3}", us / 1000.0)
}

fn truncate_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let cut: String = s.chars().take(max).collect();
        format!("{cut}…")
    }
}

impl CompareReport {
    fn push_fp_table(out: &mut String, rows: &[FpDelta], top: usize) {
        out.push_str(&format!(
            "{:>12} {:>12} {:>9} {:>9} {:>11} {:>15}  {}\n",
            "p95 base(ms)",
            "p95 cand(ms)",
            "Δp95",
            "Δmean",
            "count b/c",
            "res/query b→c",
            "fingerprint"
        ));
        for d in rows.iter().take(top) {
            let bytes = match &d.result_bytes {
                Some(b) => format!(
                    "{}→{}",
                    crate::report::fmt_bytes(b.baseline_mean),
                    crate::report::fmt_bytes(b.candidate_mean)
                ),
                None => "n/a".to_string(),
            };
            out.push_str(&format!(
                "{:>12} {:>12} {:>9} {:>9} {:>11} {:>15}  {}{}\n",
                fmt_ms(d.p95.baseline_us),
                fmt_ms(d.p95.candidate_us),
                fmt_pct(d.p95.delta_pct),
                fmt_pct(d.mean.delta_pct),
                format!("{}/{}", d.baseline_count, d.candidate_count),
                bytes,
                truncate_chars(&d.fingerprint, 70),
                if d.count_mismatch {
                    "  [count mismatch]"
                } else {
                    ""
                },
            ));
        }
        if rows.len() > top {
            out.push_str(&format!("  … and {} more\n", rows.len() - top));
        }
    }

    pub fn render_stdout(&self, top: usize) -> String {
        let mut out = String::new();
        out.push_str("Comparing runs:\n");
        for (label, m) in [("baseline", &self.baseline), ("candidate", &self.candidate)] {
            if m.is_recorded() {
                out.push_str(&format!(
                    "  {label:>9}: {} — recorded (slow log) latencies from capture {}\n",
                    m.file, m.capture_file
                ));
            } else {
                out.push_str(&format!(
                    "  {label:>9}: {} — target {} ({})\n",
                    m.file,
                    m.display_server_version(),
                    m.target_url
                ));
            }
        }
        out.push('\n');

        if !self.comparability_warnings.is_empty() {
            out.push_str(
                "!!! COMPARABILITY WARNINGS — the runs may not be directly comparable !!!\n",
            );
            for w in &self.comparability_warnings {
                out.push_str(&format!("  - {w}\n"));
            }
            out.push('\n');
        }

        if let Some(note) = &self.settings_note {
            out.push_str(&format!("Target settings: {note}\n\n"));
        }
        if !self.settings_diff.is_empty() {
            out.push_str("Target settings diff (baseline -> candidate):\n");
            for d in &self.settings_diff {
                let show = |v: &Option<String>| v.clone().unwrap_or_else(|| "<absent>".to_string());
                out.push_str(&format!(
                    "  {}: {} -> {}\n",
                    d.name,
                    show(&d.baseline),
                    show(&d.candidate)
                ));
            }
            out.push('\n');
        }

        let t = &self.totals;
        out.push_str(&format!(
            "Totals: QPS {:.1} -> {:.1} ({}) | wall {:.2}s -> {:.2}s ({}) | executed {} -> {} | errors {} -> {} ({:+})\n",
            t.baseline_qps,
            t.candidate_qps,
            fmt_pct(t.qps_delta_pct),
            t.baseline_wall_secs,
            t.candidate_wall_secs,
            fmt_pct(t.wall_delta_pct),
            t.baseline_executed,
            t.candidate_executed,
            t.baseline_errors,
            t.candidate_errors,
            t.error_delta,
        ));
        let matched = self.regressions.len()
            + self.improvements.len()
            + self.stable.len()
            + self.low_sample.len();
        out.push_str(&format!(
            "Fingerprints: {} matched ({} within threshold), {} only in baseline, {} only in candidate, {} with executed-count mismatch\n\n",
            matched,
            self.stable.len(),
            self.only_in_baseline.len(),
            self.only_in_candidate.len(),
            self.count_mismatches,
        ));

        if let Some(corr) = &self.correctness {
            out.push_str(&format!(
                "Result correctness (--checksum): {} fingerprints checked, {} matched, \
                 {} MISMATCHED, {} advisory\n",
                corr.checked,
                corr.matched,
                corr.mismatches.len(),
                corr.advisory.len(),
            ));
            out.push_str(&format!("  note: {}\n", corr.note));
            for (label, list) in [
                ("MISMATCH (deterministic — wrong answers)", &corr.mismatches),
                (
                    "advisory (nondeterministic — diff advisory only)",
                    &corr.advisory,
                ),
            ] {
                if list.is_empty() {
                    continue;
                }
                out.push_str(&format!("  {label}:\n"));
                for d in list.iter().take(top) {
                    out.push_str(&format!(
                        "    digest {} -> {} | rows {} -> {} | events {}/{}{}{}  {}\n",
                        d.baseline_digest,
                        d.candidate_digest,
                        d.baseline_rows,
                        d.candidate_rows,
                        d.baseline_events,
                        d.candidate_events,
                        if d.columns_differ {
                            " | COLUMNS DIFFER"
                        } else {
                            ""
                        },
                        if d.events_differ {
                            " | event counts differ"
                        } else {
                            ""
                        },
                        truncate_chars(&d.fingerprint, 60),
                    ));
                }
                if list.len() > top {
                    out.push_str(&format!("    … and {} more\n", list.len() - top));
                }
            }
            out.push('\n');
        }

        out.push_str(&format!(
            "Regressions (p95 {:+.0}% or worse, count >= {} in both runs): {}\n",
            self.threshold_pct,
            self.min_count,
            self.regressions.len()
        ));
        if !self.regressions.is_empty() {
            Self::push_fp_table(&mut out, &self.regressions, top);
        }
        out.push('\n');

        if let Some(note) = &self.size_note {
            out.push_str(&format!("Result-size decades: {note}\n\n"));
        } else {
            out.push_str(&format!(
                "Result-size decade regressions (p95 {:+.0}% or worse inside one decade of a \
                 fingerprint the ranking above did not flag; {} decade pair(s) checked): {}\n",
                self.threshold_pct,
                self.size_buckets_checked,
                self.size_regressions.len()
            ));
            if !self.size_regressions.is_empty() {
                out.push_str(&format!(
                    "{:>10} {:>12} {:>12} {:>9} {:>11}  {}\n",
                    "decade", "p95 base(ms)", "p95 cand(ms)", "Δp95", "count b/c", "fingerprint"
                ));
                for d in self.size_regressions.iter().take(top) {
                    out.push_str(&format!(
                        "{:>10} {:>12} {:>12} {:>9} {:>11}  {}{}\n",
                        d.bucket,
                        fmt_ms(d.p95.baseline_us),
                        fmt_ms(d.p95.candidate_us),
                        fmt_pct(d.p95.delta_pct),
                        format!("{}/{}", d.baseline_count, d.candidate_count),
                        truncate_chars(&d.fingerprint, 60),
                        if d.count_mismatch {
                            "  [count mismatch]"
                        } else {
                            ""
                        },
                    ));
                }
                if self.size_regressions.len() > top {
                    out.push_str(&format!(
                        "  … and {} more\n",
                        self.size_regressions.len() - top
                    ));
                }
            }
        }
        out.push('\n');

        out.push_str(&format!(
            "Improvements (p95 -{:.0}% or better): {}\n",
            self.threshold_pct,
            self.improvements.len()
        ));
        if !self.improvements.is_empty() {
            Self::push_fp_table(&mut out, &self.improvements, top);
        }
        out.push('\n');

        if !self.low_sample.is_empty() {
            out.push_str(&format!(
                "Low-sample fingerprints (count < {} in either run, excluded from the ranking): {}\n",
                self.min_count,
                self.low_sample.len()
            ));
            Self::push_fp_table(&mut out, &self.low_sample, top);
            out.push('\n');
        }

        for (label, list) in [
            ("Only in baseline", &self.only_in_baseline),
            ("Only in candidate", &self.only_in_candidate),
        ] {
            if !list.is_empty() {
                out.push_str(&format!("{label}: {}\n", list.len()));
                for o in list.iter().take(top) {
                    out.push_str(&format!(
                        "  {:>6}x ({} errors)  {}\n",
                        o.count,
                        o.errors,
                        truncate_chars(&o.fingerprint, 70)
                    ));
                }
                if list.len() > top {
                    out.push_str(&format!("  … and {} more\n", list.len() - top));
                }
                out.push('\n');
            }
        }

        let error_changes: Vec<&FpDelta> = self
            .regressions
            .iter()
            .chain(&self.improvements)
            .chain(&self.stable)
            .chain(&self.low_sample)
            .filter(|d| d.error_delta != 0)
            .collect();
        if !error_changes.is_empty() {
            out.push_str(&format!(
                "Fingerprints with error-count changes: {}\n",
                error_changes.len()
            ));
            for d in error_changes.iter().take(top) {
                out.push_str(&format!(
                    "  {} -> {} errors ({:+})  {}\n",
                    d.baseline_errors,
                    d.candidate_errors,
                    d.error_delta,
                    truncate_chars(&d.fingerprint, 70)
                ));
            }
            if error_changes.len() > top {
                out.push_str(&format!("  … and {} more\n", error_changes.len() - top));
            }
            out.push('\n');
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{FingerprintReport, SaturationReport};

    fn fp(text: &str, count: u64, errors: u64, p95_us: u64) -> FingerprintReport {
        FingerprintReport {
            id: 0,
            fingerprint: text.to_string(),
            count,
            errors,
            first_error: None,
            skipped: 0,
            not_run: 0,
            p50_us: p95_us / 2,
            p95_us,
            p99_us: p95_us * 2,
            max_us: p95_us * 3,
            mean_us: p95_us as f64 / 2.0,
            checksum: None,
            result_bytes: None,
            size_buckets: Vec::new(),
        }
    }

    fn run(version: &str, fps: Vec<FingerprintReport>) -> RunReport {
        let executed: u64 = fps.iter().map(|f| f.count).sum();
        let errors: u64 = fps.iter().map(|f| f.errors).sum();
        RunReport {
            tool: "sql-replay".to_string(),
            tool_version: "test".to_string(),
            capture_file: "capture.jsonl.zst".to_string(),
            capture_dialect: "mysql-5.7".to_string(),
            latency_source: crate::report::LATENCY_SOURCE_REPLAYED.to_string(),
            target_url: "mysql://t/".to_string(),
            target_server_version: version.to_string(),
            started_at: String::new(),
            ended_at: String::new(),
            wall_secs: 10.0,
            aborted: false,
            aggregation: None,
            flags: ReportFlags {
                checksum: false,
                max_connections: 8,
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
                events: executed,
                sessions: 1,
                executed,
                skipped: 0,
                errors,
                not_run: 0,
                connect_failures: 0,
                qps: executed as f64 / 10.0,
                filtered: 0,
            },
            saturation: SaturationReport {
                samples: 0,
                saturated_samples: 0,
                saturated_pct: 0.0,
            },
            pacing: None,
            target_settings: BTreeMap::new(),
            fingerprints: fps,
        }
    }

    const OPTS: CompareOptions = CompareOptions {
        threshold_pct: 20.0,
        min_count: 5,
    };

    fn texts(list: &[FpDelta]) -> Vec<&str> {
        list.iter().map(|d| d.fingerprint.as_str()).collect()
    }

    #[test]
    fn classifies_and_ranks_by_p95_regression() {
        let base = run(
            "5.7.42",
            vec![
                fp("q_reg_small", 50, 0, 20_000),
                fp("q_reg_big", 100, 0, 10_000),
                fp("q_improved", 80, 0, 50_000),
                fp("q_stable", 40, 0, 1_000),
            ],
        );
        let cand = run(
            "8.0.46",
            vec![
                fp("q_reg_small", 50, 0, 26_000), // +30%
                fp("q_reg_big", 100, 0, 30_000),  // +200%
                fp("q_improved", 80, 0, 25_000),  // -50%
                fp("q_stable", 40, 0, 1_050),     // +5%
            ],
        );
        let rep = compare_runs("a.json", &base, "b.json", &cand, OPTS);
        assert_eq!(texts(&rep.regressions), ["q_reg_big", "q_reg_small"]);
        assert_eq!(texts(&rep.improvements), ["q_improved"]);
        assert_eq!(texts(&rep.stable), ["q_stable"]);
        assert!(rep.regressed);
        let worst = &rep.regressions[0];
        assert_eq!(worst.p95.delta_us, 20_000.0);
        assert_eq!(worst.p95.delta_pct, Some(200.0));
        // Boundary: exactly the threshold counts as regressed.
        let base = run("5.7", vec![fp("q", 10, 0, 10_000)]);
        let cand = run("8.0", vec![fp("q", 10, 0, 12_000)]);
        let rep = compare_runs("a", &base, "b", &cand, OPTS);
        assert_eq!(rep.regressions.len(), 1);
    }

    #[test]
    fn zero_baseline_with_nonzero_candidate_is_a_regression() {
        let base = run(
            "5.7.42",
            vec![
                fp("q_zero_big", 10, 0, 0),
                fp("q_zero_small", 10, 0, 0),
                fp("q_pct_reg", 10, 0, 10_000),
                fp("q_zero_both", 10, 0, 0),
            ],
        );
        let cand = run(
            "8.0.46",
            vec![
                fp("q_zero_big", 10, 0, 50_000),
                fp("q_zero_small", 10, 0, 5_000),
                fp("q_pct_reg", 10, 0, 30_000), // +200%
                fp("q_zero_both", 10, 0, 0),
            ],
        );
        let rep = compare_runs("a", &base, "b", &cand, OPTS);
        // Zero-baseline regressions rank worst (as if +inf), ordered among
        // themselves by absolute p95 delta; delta_pct stays None.
        assert_eq!(
            texts(&rep.regressions),
            ["q_zero_big", "q_zero_small", "q_pct_reg"]
        );
        assert!(rep.regressed);
        assert_eq!(rep.regressions[0].p95.delta_pct, None);
        assert_eq!(rep.regressions[0].p95.delta_us, 50_000.0);
        let json = serde_json::to_value(&rep.regressions[0]).unwrap();
        assert_eq!(json["p95"]["delta_pct"], serde_json::Value::Null);
        // 0 -> 0 stays stable.
        assert_eq!(texts(&rep.stable), ["q_zero_both"]);
    }

    #[test]
    fn low_sample_and_zero_count_stay_out_of_headline() {
        let base = run(
            "5.7.42",
            vec![fp("q_rare", 2, 0, 1_000), fp("q_never_ran", 0, 0, 0)],
        );
        let cand = run(
            "8.0.46",
            vec![fp("q_rare", 2, 0, 10_000), fp("q_never_ran", 0, 5, 0)],
        );
        let rep = compare_runs("a", &base, "b", &cand, OPTS);
        assert!(rep.regressions.is_empty());
        assert!(!rep.regressed);
        assert_eq!(texts(&rep.low_sample), ["q_rare", "q_never_ran"]);
        // Zero-count matches are low-sample even with --min-count 0.
        let rep = compare_runs(
            "a",
            &base,
            "b",
            &cand,
            CompareOptions {
                threshold_pct: 20.0,
                min_count: 0,
            },
        );
        assert!(texts(&rep.low_sample).contains(&"q_never_ran"));
        assert_eq!(texts(&rep.regressions), ["q_rare"]);
    }

    #[test]
    fn only_in_one_run_and_count_mismatches_warn() {
        let base = run(
            "5.7.42",
            vec![fp("q_common", 20, 0, 5_000), fp("q_old_only", 10, 0, 2_000)],
        );
        let cand = run(
            "8.0.46",
            vec![fp("q_common", 10, 0, 5_100), fp("q_new_only", 5, 1, 3_000)],
        );
        let rep = compare_runs("a", &base, "b", &cand, OPTS);
        assert_eq!(rep.only_in_baseline.len(), 1);
        assert_eq!(rep.only_in_baseline[0].fingerprint, "q_old_only");
        assert_eq!(rep.only_in_candidate.len(), 1);
        assert_eq!(rep.only_in_candidate[0].fingerprint, "q_new_only");
        assert_eq!(rep.count_mismatches, 1);
        assert!(rep.stable[0].count_mismatch);
        assert!(rep
            .comparability_warnings
            .iter()
            .any(|w| w.contains("only in the baseline")));
        assert!(rep
            .comparability_warnings
            .iter()
            .any(|w| w.contains("different number of times")));
    }

    #[test]
    fn capture_and_flag_differences_warn() {
        let base = run("5.7.42", vec![]);
        let mut cand = run("8.0.46", vec![]);
        cand.capture_file = "other.jsonl.zst".to_string();
        cand.flags.allow_writes = true;
        cand.flags.speed = "1".to_string();
        let rep = compare_runs("a", &base, "b", &cand, OPTS);
        assert!(rep
            .comparability_warnings
            .iter()
            .any(|w| w.contains("different capture files")));
        assert!(rep
            .comparability_warnings
            .iter()
            .any(|w| w.contains("--allow-writes differs")));
        assert!(rep
            .comparability_warnings
            .iter()
            .any(|w| w.contains("--speed differs")));
    }

    #[test]
    fn settings_diff_lists_changed_and_one_sided_variables() {
        let mut base = run("5.7.42", vec![]);
        let mut cand = run("8.0.46", vec![]);
        base.target_settings = BTreeMap::from([
            ("sql_mode".to_string(), "NO_ENGINE_SUBSTITUTION".to_string()),
            ("character_set_server".to_string(), "latin1".to_string()),
            (
                "collation_server".to_string(),
                "latin1_swedish_ci".to_string(),
            ),
        ]);
        cand.target_settings = BTreeMap::from([
            ("sql_mode".to_string(), "NO_ENGINE_SUBSTITUTION".to_string()),
            ("character_set_server".to_string(), "utf8mb4".to_string()),
            ("new_only".to_string(), "1".to_string()),
        ]);
        let rep = compare_runs("a", &base, "b", &cand, OPTS);
        let names: Vec<&str> = rep.settings_diff.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(
            names,
            ["character_set_server", "collation_server", "new_only"]
        );
        assert_eq!(rep.settings_diff[0].baseline.as_deref(), Some("latin1"));
        assert_eq!(rep.settings_diff[0].candidate.as_deref(), Some("utf8mb4"));
        assert_eq!(rep.settings_diff[1].candidate, None);
        assert!(rep
            .comparability_warnings
            .iter()
            .any(|w| w.contains("target server settings differ")));
        // Identical settings produce no diff and no warning.
        cand.target_settings = base.target_settings.clone();
        let rep = compare_runs("a", &base, "b", &cand, OPTS);
        assert!(rep.settings_diff.is_empty());
        assert!(rep.comparability_warnings.is_empty());
    }

    #[test]
    fn server_family_classifies_version_strings() {
        assert_eq!(server_family("5.7.44"), Some("MySQL"));
        assert_eq!(server_family("8.0.46"), Some("MySQL"));
        assert_eq!(server_family("5.7.44-48-log"), Some("MySQL")); // Percona
        assert_eq!(server_family("10.11.18-MariaDB-ubu2204"), Some("MariaDB"));
        assert_eq!(server_family("5.5.5-10.11.18-MariaDB"), Some("MariaDB"));
        assert_eq!(server_family("5.5.68-MariaDB"), Some("MariaDB"));
        assert_eq!(server_family(""), None);
    }

    #[test]
    fn display_version_strips_the_maria_compat_prefix_only() {
        let mut m = RunMeta::from_report("f", &run("5.5.5-10.11.18-MariaDB-log", vec![]));
        assert_eq!(m.display_server_version(), "10.11.18-MariaDB-log");
        // A genuine (ancient) MySQL 5.5.5 must not be mangled...
        m.target_server_version = "5.5.5-log".to_string();
        assert_eq!(m.display_server_version(), "5.5.5-log");
        // ...and the prefix-less MariaDB string passes through untouched.
        m.target_server_version = "10.11.18-MariaDB-ubu2204".to_string();
        assert_eq!(m.display_server_version(), "10.11.18-MariaDB-ubu2204");
    }

    #[test]
    fn cross_engine_targets_warn_same_engine_does_not() {
        let base = run("5.7.44", vec![fp("q", 10, 0, 10_000)]);
        let cand = run("10.11.18-MariaDB-ubu2204", vec![fp("q", 10, 0, 10_500)]);
        let rep = compare_runs("a", &base, "b", &cand, OPTS);
        let w = rep
            .comparability_warnings
            .iter()
            .find(|w| w.contains("engine families differ"))
            .expect("cross-engine warning present");
        assert!(w.contains("MySQL (baseline)"));
        assert!(w.contains("MariaDB (candidate)"));
        // The warning is informational: it must not gate the exit code.
        assert!(!rep.regressed);

        // Same family (a 5.7 -> 8.0 upgrade): no engine warning.
        let cand = run("8.0.46", vec![fp("q", 10, 0, 10_500)]);
        let rep = compare_runs("a", &base, "b", &cand, OPTS);
        assert!(!rep
            .comparability_warnings
            .iter()
            .any(|w| w.contains("engine families differ")));

        // A recorded baseline has no version — nothing to compare families
        // against, no warning.
        let base = recorded_run(vec![fp("q", 10, 0, 10_000)]);
        let cand = run("10.11.18-MariaDB-ubu2204", vec![fp("q", 10, 0, 10_500)]);
        let rep = compare_runs("a", &base, "b", &cand, OPTS);
        assert!(!rep
            .comparability_warnings
            .iter()
            .any(|w| w.contains("engine families differ")));
    }

    /// A `sql-replay baseline` report: recorded latencies, no target.
    fn recorded_run(fps: Vec<FingerprintReport>) -> RunReport {
        let mut r = run("", fps);
        r.latency_source = crate::report::LATENCY_SOURCE_RECORDED.to_string();
        r.target_url = String::new();
        r.flags.max_connections = 0;
        r.flags.speed = "recorded".to_string();
        r
    }

    #[test]
    fn recorded_vs_replayed_warns_about_measurement_planes() {
        let base = recorded_run(vec![fp("q", 10, 0, 10_000)]);
        let mut cand = run("8.0.46", vec![fp("q", 10, 0, 11_000)]);
        cand.target_settings = BTreeMap::from([("sql_mode".to_string(), "X".to_string())]);
        let rep = compare_runs("baseline.json", &base, "run-8.0.json", &cand, OPTS);

        // The measurement-plane warning is present and explains both sides.
        let plane = rep
            .comparability_warnings
            .iter()
            .find(|w| w.contains("MEASUREMENT PLANES DIFFER"))
            .expect("measurement-plane warning present");
        assert!(plane.contains("Query_time"));
        assert!(plane.contains("source capture"));
        assert!(plane.contains("pcap"));
        assert!(plane.contains("wall times"));
        assert!(plane.contains("--threshold-pct"));

        // Replay-knob flag diffs (speed "recorded" vs "max", max-connections
        // 0 vs 8) are suppressed — they'd be pure noise against a recorded
        // side.
        assert!(!rep
            .comparability_warnings
            .iter()
            .any(|w| w.contains("replay flag")));

        // The settings diff is skipped with a note, not filled with
        // one-sided entries; no "settings differ" warning either.
        assert!(rep.settings_diff.is_empty());
        let note = rep.settings_note.as_deref().expect("settings note");
        assert!(note.contains("baseline"), "{note}");
        assert!(note.contains("recorded from the slow log"), "{note}");
        assert!(!rep
            .comparability_warnings
            .iter()
            .any(|w| w.contains("target server settings differ")));

        // Delta math is unchanged: the fingerprints still match and rank.
        assert_eq!(rep.stable.len(), 1);
        assert_eq!(rep.stable[0].p95.delta_pct, Some(10.0));

        // Display: the recorded side shows its provenance in the version
        // slot rather than a blank.
        assert_eq!(rep.baseline.display_server_version(), "recorded (slow log)");
        assert_eq!(rep.candidate.display_server_version(), "8.0.46");
        assert!(rep.baseline.is_recorded());
        assert!(!rep.candidate.is_recorded());
        let text = rep.render_stdout(10);
        assert!(text.contains("recorded (slow log) latencies from capture"));
        assert!(text.contains("MEASUREMENT PLANES DIFFER"));
        assert!(text.contains("Target settings: settings diff skipped"));
    }

    /// Attach a checksum aggregate to a fingerprint report.
    fn with_cs(
        mut f: FingerprintReport,
        digest: &str,
        events: u64,
        rows: u64,
        nondet: bool,
    ) -> FingerprintReport {
        f.checksum = Some(crate::report::ChecksumReport {
            events,
            no_result: 0,
            rows_total: rows,
            digest: digest.to_string(),
            columns: vec!["id".to_string(), "v".to_string()],
            shape_varied: false,
            nondeterministic: nondet,
        });
        f
    }

    fn checksummed_run(version: &str, fps: Vec<FingerprintReport>) -> RunReport {
        let mut r = run(version, fps);
        r.flags.checksum = true;
        r
    }

    #[test]
    fn identical_checksums_pass_and_diverging_ones_fail() {
        let base = checksummed_run(
            "5.7.42",
            vec![
                with_cs(fp("q_same", 10, 0, 1_000), "aaaa", 10, 100, false),
                with_cs(fp("q_diff", 10, 0, 1_000), "bbbb", 10, 100, false),
                with_cs(fp("q_nondet", 10, 0, 1_000), "cccc", 10, 100, true),
                with_cs(fp("q_pop", 10, 0, 1_000), "dddd", 10, 100, false),
                fp("q_uncheck", 10, 0, 1_000), // executed but never checksummed
            ],
        );
        let cand = checksummed_run(
            "8.0.46",
            vec![
                with_cs(fp("q_same", 10, 0, 1_000), "aaaa", 10, 100, false),
                with_cs(fp("q_diff", 10, 0, 1_000), "eeee", 10, 90, false),
                with_cs(fp("q_nondet", 10, 0, 1_000), "ffff", 10, 100, false),
                with_cs(fp("q_pop", 10, 0, 1_000), "gggg", 7, 70, false),
                fp("q_uncheck", 10, 0, 1_000),
            ],
        );
        let rep = compare_runs("a", &base, "b", &cand, OPTS);
        let corr = rep.correctness.as_ref().expect("correctness section");
        assert_eq!(corr.checked, 4);
        assert_eq!(corr.matched, 1);
        // q_diff is a hard mismatch; q_nondet (flagged on either side) and
        // q_pop (unequal checksummed-event populations) are advisory.
        assert_eq!(corr.mismatches.len(), 1);
        assert_eq!(corr.mismatches[0].fingerprint, "q_diff");
        assert_eq!(corr.mismatches[0].baseline_rows, 100);
        assert_eq!(corr.mismatches[0].candidate_rows, 90);
        assert!(!corr.mismatches[0].events_differ);
        let advisory: Vec<&str> = corr
            .advisory
            .iter()
            .map(|d| d.fingerprint.as_str())
            .collect();
        assert_eq!(advisory.len(), 2);
        assert!(advisory.contains(&"q_nondet"));
        assert!(advisory.contains(&"q_pop"));
        assert!(rep.correctness_failed);
        assert!(rep
            .comparability_warnings
            .iter()
            .any(|w| w.contains("RESULT MISMATCH")));
        let text = rep.render_stdout(10);
        assert!(text.contains("Result correctness"));
        assert!(text.contains("q_diff"));
        assert!(text.contains("MISMATCH"));
        assert!(text.contains("advisory"));

        // Identical data: silent (no mismatches, no exit-2 driver).
        let rep = compare_runs("a", &base, "b", &base, OPTS);
        let corr = rep.correctness.as_ref().expect("correctness section");
        assert_eq!(corr.checked, 4);
        assert_eq!(corr.matched, 4);
        assert!(corr.mismatches.is_empty() && corr.advisory.is_empty());
        assert!(!rep.correctness_failed);
    }

    #[test]
    fn checksum_flag_mismatch_warns_and_skips_correctness() {
        let base = checksummed_run("5.7.42", vec![fp("q", 10, 0, 1_000)]);
        let cand = run("8.0.46", vec![fp("q", 10, 0, 1_000)]);
        let rep = compare_runs("a", &base, "b", &cand, OPTS);
        assert!(rep.correctness.is_none());
        assert!(!rep.correctness_failed);
        assert!(rep
            .comparability_warnings
            .iter()
            .any(|w| w.contains("only the baseline run recorded result checksums")));
        assert!(rep
            .comparability_warnings
            .iter()
            .any(|w| w.contains("--checksum differs")));
        // Neither run checksummed: no section, no warnings about it.
        let rep = compare_runs("a", &cand, "b", &cand, OPTS);
        assert!(rep.correctness.is_none());
        assert!(!rep
            .comparability_warnings
            .iter()
            .any(|w| w.contains("checksum")));
    }

    #[test]
    fn recorded_side_filter_flag_diffs_still_warn() {
        let mut base = recorded_run(vec![]);
        base.flags.filter_db = Some("shop".to_string());
        let cand = run("8.0.46", vec![]);
        let rep = compare_runs("a", &base, "b", &cand, OPTS);
        assert!(rep
            .comparability_warnings
            .iter()
            .any(|w| w.contains("--filter-db differs")));
    }

    #[test]
    fn two_replayed_runs_get_no_measurement_plane_warning() {
        let base = run("5.7.42", vec![fp("q", 10, 0, 10_000)]);
        let cand = run("8.0.46", vec![fp("q", 10, 0, 10_000)]);
        let rep = compare_runs("a", &base, "b", &cand, OPTS);
        assert!(!rep
            .comparability_warnings
            .iter()
            .any(|w| w.contains("MEASUREMENT PLANES")));
        // Both sides empty settings -> note, no spurious diff.
        assert!(rep.settings_diff.is_empty());
        assert_eq!(
            rep.settings_note.as_deref(),
            Some("settings diff skipped: neither run records target settings")
        );
    }

    /// Attach byte stats to a fingerprint: a mean plus per-decade
    /// (label, count, p95_us) sub-populations.
    fn with_bytes(
        mut f: FingerprintReport,
        mean: f64,
        buckets: &[(&str, u64, u64)],
    ) -> FingerprintReport {
        let total = (mean * f.count as f64) as u64;
        f.result_bytes = Some(crate::report::ResultBytesReport {
            total,
            min: 1,
            max: total,
            mean,
            p50: mean as u64,
            p95: total,
        });
        f.size_buckets = buckets
            .iter()
            .map(|(label, count, p95_us)| crate::report::SizeBucketReport {
                bucket: label.to_string(),
                count: *count,
                p50_us: p95_us / 2,
                p95_us: *p95_us,
                mean_us: *p95_us as f64 / 2.0,
                max_us: p95_us * 2,
                bytes_total: total,
            })
            .collect();
        f
    }

    #[test]
    fn size_decade_regression_is_flagged_even_when_the_fingerprint_is_stable() {
        // Fingerprint-wide p95 moves +5% (stable), but the >=10MB decade —
        // 10 of 40 events — regresses +150%: exactly the averaged-away case.
        let base = run(
            "5.7.42",
            vec![with_bytes(
                fp("q_docs", 40, 0, 10_000),
                1_000_000.0,
                &[("<1KB", 30, 500), (">=10MB", 10, 20_000)],
            )],
        );
        let cand = run(
            "8.0.46",
            vec![with_bytes(
                fp("q_docs", 40, 0, 10_500),
                1_000_000.0,
                &[("<1KB", 30, 510), (">=10MB", 10, 50_000)],
            )],
        );
        let rep = compare_runs("a", &base, "b", &cand, OPTS);
        assert!(!rep.regressed, "fingerprint-wide p95 is within threshold");
        assert!(rep.size_regressed);
        assert_eq!(rep.size_buckets_checked, 2);
        assert_eq!(rep.size_regressions.len(), 1);
        let d = &rep.size_regressions[0];
        assert_eq!(d.fingerprint, "q_docs");
        assert_eq!(d.bucket, ">=10MB");
        assert_eq!(d.p95.delta_pct, Some(150.0));
        assert!(!d.count_mismatch);
        assert!(rep.size_note.is_none());
        // Per-fingerprint byte columns are populated.
        let bytes = rep.stable[0].result_bytes.as_ref().expect("bytes delta");
        assert_eq!(bytes.baseline_mean, 1_000_000.0);
        assert_eq!(bytes.mean_delta_pct, Some(0.0));
        // Rendering mentions the section and the decade.
        let text = rep.render_stdout(10);
        assert!(text.contains("Result-size decade regressions"));
        assert!(text.contains(">=10MB"));
    }

    #[test]
    fn size_decades_skip_low_sample_buckets_and_already_regressed_fingerprints() {
        // q_reg regresses fingerprint-wide: its decades are not re-listed.
        // q_small's regressed decade has count 2 < min_count: not flagged.
        let base = run(
            "5.7.42",
            vec![
                with_bytes(fp("q_reg", 20, 0, 10_000), 100.0, &[("<1KB", 20, 10_000)]),
                with_bytes(
                    fp("q_small", 20, 0, 1_000),
                    100.0,
                    &[("<1KB", 18, 1_000), ("1KB-10KB", 2, 1_000)],
                ),
            ],
        );
        let cand = run(
            "8.0.46",
            vec![
                with_bytes(fp("q_reg", 20, 0, 30_000), 100.0, &[("<1KB", 20, 30_000)]),
                with_bytes(
                    fp("q_small", 20, 0, 1_010),
                    100.0,
                    &[("<1KB", 18, 1_010), ("1KB-10KB", 2, 9_000)],
                ),
            ],
        );
        let rep = compare_runs("a", &base, "b", &cand, OPTS);
        assert_eq!(rep.regressions.len(), 1);
        assert!(rep.size_regressions.is_empty());
        assert!(!rep.size_regressed);
        // q_reg's decade pair was population-eligible and counted; q_small's
        // small decade was not.
        assert_eq!(rep.size_buckets_checked, 2);
    }

    #[test]
    fn missing_byte_stats_degrade_to_notes_never_verdicts() {
        // The candidate regresses (+100%) so the regression table renders —
        // with an n/a bytes column, since the baseline records no bytes.
        let with = run(
            "8.0.46",
            vec![with_bytes(
                fp("q", 10, 0, 2_000),
                100.0,
                &[("<1KB", 10, 2_000)],
            )],
        );
        let without = run("5.7.42", vec![fp("q", 10, 0, 1_000)]);

        // Baseline lacks byte stats (older report): note names the side,
        // no decade verdict, per-fp bytes are None.
        let rep = compare_runs("old.json", &without, "new.json", &with, OPTS);
        assert!(!rep.size_regressed);
        assert!(rep.size_regressions.is_empty());
        let note = rep.size_note.as_deref().expect("size note");
        assert!(note.contains("baseline"), "{note}");
        assert!(note.contains("pre-0.4.0"), "{note}");
        assert!(rep.regressions[0].result_bytes.is_none());
        let text = rep.render_stdout(10);
        assert!(text.contains("Result-size decades:"));
        assert!(text.contains("n/a"));

        // Recorded baselines say so instead of claiming an old report.
        let recorded = recorded_run(vec![fp("q", 10, 0, 1_000)]);
        let rep = compare_runs("base.json", &recorded, "new.json", &with, OPTS);
        let note = rep.size_note.as_deref().expect("size note");
        assert!(note.contains("recorded"), "{note}");

        // Neither side records bytes: quiet note, nothing compared.
        let rep = compare_runs("a", &without, "b", &without, OPTS);
        let note = rep.size_note.as_deref().expect("size note");
        assert!(note.contains("neither run"), "{note}");
        assert_eq!(rep.size_buckets_checked, 0);
    }

    #[test]
    fn totals_deltas_and_pct_edge_cases() {
        let base = run("5.7.42", vec![fp("q", 100, 0, 1_000)]);
        let cand = run("8.0.46", vec![fp("q", 80, 20, 1_100)]);
        let rep = compare_runs("a", &base, "b", &cand, OPTS);
        assert_eq!(rep.totals.baseline_qps, 10.0);
        assert_eq!(rep.totals.candidate_qps, 8.0);
        assert_eq!(rep.totals.qps_delta_pct, Some(-20.0));
        assert_eq!(rep.totals.error_delta, 20);
        assert_eq!(pct_change(0.0, 5.0), None);
        assert_eq!(pct_change(10.0, 5.0), Some(-50.0));
    }

    #[test]
    fn stdout_rendering_mentions_key_sections() {
        let base = run(
            "5.7.42",
            vec![fp("q_reg", 10, 0, 10_000), fp("q_rare", 1, 0, 100)],
        );
        let mut cand = run(
            "8.0.46",
            vec![fp("q_reg", 10, 2, 30_000), fp("q_rare", 1, 0, 500)],
        );
        cand.capture_file = "other.zst".to_string();
        let rep = compare_runs("base.json", &base, "cand.json", &cand, OPTS);
        let text = rep.render_stdout(10);
        assert!(text.contains("COMPARABILITY WARNINGS"));
        assert!(text.contains("5.7.42"));
        assert!(text.contains("8.0.46"));
        assert!(text.contains("Regressions"));
        assert!(text.contains("q_reg"));
        assert!(text.contains("Low-sample"));
        assert!(text.contains("error-count changes"));
    }
}
