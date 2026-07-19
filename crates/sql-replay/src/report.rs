//! Machine-readable run report (`--out run.json`) and the human summary
//! table printed to stdout.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// [`RunReport::latency_source`] for reports produced by `replay`:
/// latencies are client-side wall times measured by this tool.
pub const LATENCY_SOURCE_REPLAYED: &str = "replayed";
/// [`RunReport::latency_source`] for reports produced by `baseline`:
/// latencies were recorded in the source capture (server-side `Query_time`
/// for slow logs, request→first-response wire time for pcap captures —
/// the value stays `recorded-slow-log` for format compatibility).
pub const LATENCY_SOURCE_RECORDED: &str = "recorded-slow-log";

pub(crate) fn default_latency_source() -> String {
    LATENCY_SOURCE_REPLAYED.to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunReport {
    pub tool: String,
    pub tool_version: String,
    pub capture_file: String,
    pub capture_dialect: String,
    /// Where the per-fingerprint latencies were measured:
    /// [`LATENCY_SOURCE_REPLAYED`] (client-side wall time observed by
    /// `sql-replay replay`) or [`LATENCY_SOURCE_RECORDED`] (the capture's
    /// recorded per-event latency aggregated by `sql-replay baseline`).
    /// Absent in pre-0.2.0 reports, which are all replayed (serde
    /// default).
    #[serde(default = "default_latency_source")]
    pub latency_source: String,
    /// Empty (and omitted from JSON) for recorded baselines, which have no
    /// target server.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub target_url: String,
    /// Empty (and omitted from JSON) for recorded baselines — there was no
    /// replay to observe the server version string.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub target_server_version: String,
    pub started_at: String,
    pub ended_at: String,
    pub wall_secs: f64,
    /// True when the run was interrupted (Ctrl-C/SIGTERM): the report is
    /// partial — events that never got to run are counted under `not_run`.
    #[serde(default)]
    pub aborted: bool,
    /// Present on the median-aggregated report of a `--repeat N` run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aggregation: Option<AggregationInfo>,
    pub flags: ReportFlags,
    pub totals: Totals,
    pub saturation: SaturationReport,
    /// Present only for paced runs (`--speed <factor>`); `--speed max` has
    /// no schedule to lag behind. Absent in M1 reports (serde default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pacing: Option<PacingReport>,
    /// Comparability-relevant target variables (sql_mode, charset/collation,
    /// buffer pool size, transaction isolation). Absent in M1 reports.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub target_settings: BTreeMap<String, String>,
    pub fingerprints: Vec<FingerprintReport>,
}

/// Pacing fidelity for paced replays: how far behind its schedule each
/// event fired. Large lag means the target (or the connection cap) could
/// not keep up with the captured timeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacingReport {
    pub speed: f64,
    pub paced_events: u64,
    pub max_lag_us: u64,
    pub mean_lag_us: f64,
}

/// How a multi-pass (`--repeat N`) report was aggregated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregationInfo {
    pub passes: u64,
    pub method: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportFlags {
    pub max_connections: usize,
    pub allow_writes: bool,
    pub read_only: bool,
    pub db_override: Option<String>,
    pub speed: String,
    /// Result-set checksums were recorded (`--checksum`, 0.3.0). Latencies
    /// of a checksummed run include reading every result row and are not
    /// comparable to a non-checksummed run's.
    #[serde(default)]
    pub checksum: bool,
    /// Sessions multiplexed over a bounded connection pool of this size
    /// instead of one dedicated connection per session (M3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pool: Option<usize>,
    /// An unrecorded warmup pass ran before the measured pass(es) (M3).
    #[serde(default)]
    pub warmup: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter_db: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter_user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_window: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Totals {
    pub events: u64,
    pub sessions: u64,
    pub executed: u64,
    pub skipped: u64,
    pub errors: u64,
    /// Events abandoned after a fatal connection error in their session,
    /// or never attempted because the run was aborted.
    pub not_run: u64,
    pub connect_failures: u64,
    pub qps: f64,
    /// Events excluded up front by --filter-db/--filter-user/--time-window
    /// (not part of `events`). Absent (0) in pre-M3 reports.
    #[serde(default)]
    pub filtered: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaturationReport {
    pub samples: u64,
    pub saturated_samples: u64,
    pub saturated_pct: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintReport {
    pub id: u32,
    pub fingerprint: String,
    /// Successfully executed instances (latency histogram population).
    pub count: u64,
    pub errors: u64,
    pub first_error: Option<String>,
    pub skipped: u64,
    pub not_run: u64,
    pub p50_us: u64,
    pub p95_us: u64,
    pub p99_us: u64,
    pub max_us: u64,
    pub mean_us: f64,
    /// Result-set checksum aggregate, present when the run used
    /// `--checksum` and this fingerprint executed read statements
    /// (0.3.0; serde default keeps older reports loading).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checksum: Option<ChecksumReport>,
    /// Result-set byte stats over the executed instances (0.4.0; serde
    /// default keeps older reports loading). Absent when nothing executed
    /// or the latencies are recorded rather than replayed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_bytes: Option<ResultBytesReport>,
    /// Latency stats split by result-size decade (0.4.0), non-empty
    /// decades only, in decade order. Absent under the same conditions as
    /// `result_bytes`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub size_buckets: Vec<SizeBucketReport>,
}

/// Result-size decade boundaries (binary units): a result set of `b` bytes
/// falls in the first decade whose bound exceeds it, or the last decade
/// (`>=100MB`) when none does. `<1KB` includes statements that returned no
/// result set (0 bytes).
///
/// 0.5.0 extends this past the former open-ended `>=10MB` top with two more
/// binary decades (`10MB-100MB`, `>=100MB`): blob/CLOB workloads pile every
/// large result into a single bucket, blinding the size-decade regression
/// gate exactly where big rows live. The six pre-existing decades keep
/// identical boundaries and semantics — only the former top decade is split.
pub const SIZE_BUCKET_BOUNDS: [u64; 6] =
    [1 << 10, 10 << 10, 100 << 10, 1 << 20, 10 << 20, 100 << 20];

/// Labels of the result-size decades, index-aligned with the decade order
/// (and with [`SIZE_BUCKET_BOUNDS`], which holds the upper bounds of all
/// but the open-ended last decade).
pub const SIZE_BUCKET_LABELS: [&str; 7] = [
    "<1KB",
    "1KB-10KB",
    "10KB-100KB",
    "100KB-1MB",
    "1MB-10MB",
    "10MB-100MB",
    ">=100MB",
];

/// Decade index (into [`SIZE_BUCKET_LABELS`]) of a result-set byte count.
pub fn size_bucket_index(bytes: u64) -> usize {
    SIZE_BUCKET_BOUNDS
        .iter()
        .position(|bound| bytes < *bound)
        .unwrap_or(SIZE_BUCKET_LABELS.len() - 1)
}

/// Human-readable byte count for report tables ("1.5KB", "12.3MB").
pub fn fmt_bytes(b: f64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = 1024.0 * 1024.0;
    const GB: f64 = 1024.0 * 1024.0 * 1024.0;
    if b < KB {
        format!("{b:.0}B")
    } else if b < MB {
        format!("{:.1}KB", b / KB)
    } else if b < GB {
        format!("{:.1}MB", b / MB)
    } else {
        format!("{:.1}GB", b / GB)
    }
}

/// Per-fingerprint result-set byte statistics (0.4.0), measured while
/// draining rows on the streaming replay path. Bytes are the canonical
/// decoded cell sizes (`target::value_bytes`) — payload, not wire framing —
/// so they are comparable only between runs of this tool. `total`, `min`,
/// `max`, and `mean` are exact; `p50`/`p95` come from a histogram with two
/// significant digits. Absent on recorded baselines (the capture carries no
/// result sizes) and on pre-0.4.0 reports.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResultBytesReport {
    pub total: u64,
    pub min: u64,
    pub max: u64,
    pub mean: f64,
    pub p50: u64,
    pub p95: u64,
}

/// Latency stats of one result-size decade of a fingerprint (0.4.0).
/// Fingerprinting collapses literals, so one fingerprint can mix result
/// sizes spanning orders of magnitude (a `WHERE id = ?` against a document
/// table fetches 100KB and 15MB rows alike); the per-decade split lets
/// `compare` flag a regression that only affects one size class instead of
/// averaging it away in the fingerprint-wide percentiles.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SizeBucketReport {
    /// Decade label, one of [`SIZE_BUCKET_LABELS`].
    pub bucket: String,
    /// Successfully executed instances whose result size fell in this
    /// decade (errors have no known result size and are not counted).
    pub count: u64,
    pub p50_us: u64,
    pub p95_us: u64,
    pub mean_us: f64,
    pub max_us: u64,
    pub bytes_total: u64,
}

/// Per-fingerprint result-set checksum aggregate (`replay --checksum`).
///
/// Per-event checksums would bloat run.json (a fingerprint can have
/// millions of events), so events collapse into one order-insensitive
/// digest: per-event result digests are combined with commutative
/// operations (wrapping sum + xor + count), making the aggregate a
/// multiset hash of the event checksums. Two runs over the same capture
/// and identical data produce the same multiset — regardless of session
/// interleaving — so equal digests mean no observed divergence, and any
/// changed result set changes the digest.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChecksumReport {
    /// Executed statements whose result set was checksummed.
    pub events: u64,
    /// Executed checksummed statements that returned no result set (OK
    /// packet only, e.g. SET) — nothing to diff.
    pub no_result: u64,
    /// Total rows read across all checksummed events.
    pub rows_total: u64,
    /// Combined order-insensitive digest (16 hex chars) over the
    /// per-event result checksums.
    pub digest: String,
    /// Column names of the first checksummed result set.
    pub columns: Vec<String>,
    /// Column names/count varied between events of this fingerprint.
    pub shape_varied: bool,
    /// The query looks nondeterministic (volatile functions, LIMIT
    /// without ORDER BY, server-state reads — see
    /// `classify::is_nondeterministic`), or its digest empirically varied
    /// across `--repeat` passes: checksum diffs are advisory, not hard
    /// mismatches.
    pub nondeterministic: bool,
}

impl RunReport {
    /// Above this, results are likely throttled by --max-connections rather
    /// than by the target server.
    pub const SATURATION_WARN_PCT: f64 = 20.0;

    /// True for reports whose latencies were recorded in the source
    /// capture (`sql-replay baseline`) rather than measured by a replay.
    pub fn is_recorded(&self) -> bool {
        self.latency_source == LATENCY_SOURCE_RECORDED
    }

    pub fn saturation_warning(&self) -> Option<String> {
        if self.saturation.saturated_pct >= Self::SATURATION_WARN_PCT {
            let (flag, cap) = match self.flags.pool {
                Some(n) => ("--pool", n),
                None => ("--max-connections", self.flags.max_connections),
            };
            Some(format!(
                "WARNING: the connection cap was saturated for {:.0}% of the run \
                 ({} of {} samples had all {} permits taken with sessions waiting). \
                 Latency and QPS results may be limited by {} \
                 rather than by the target server.",
                self.saturation.saturated_pct,
                self.saturation.saturated_samples,
                self.saturation.samples,
                cap,
                flag,
            ))
        } else {
            None
        }
    }

    pub fn render_table(&self, top: usize) -> String {
        let mut out = String::new();
        let t = &self.totals;
        if self.aborted {
            out.push_str("*** ABORTED: partial results — the run was interrupted ***\n");
        }
        if let Some(agg) = &self.aggregation {
            out.push_str(&format!(
                "Aggregated ({}) over {} measured passes\n",
                agg.method, agg.passes
            ));
        }
        let verb = if self.is_recorded() {
            "Recorded"
        } else {
            "Replayed"
        };
        out.push_str(&format!(
            "{verb} {} events across {} sessions in {:.2}s — {:.1} QPS\n",
            t.events, t.sessions, self.wall_secs, t.qps
        ));
        out.push_str(&format!(
            "  executed: {}  skipped: {}  errors: {}  not run: {}  connect failures: {}\n",
            t.executed, t.skipped, t.errors, t.not_run, t.connect_failures
        ));
        if t.filtered > 0 {
            out.push_str(&format!(
                "  filtered out before replay: {} events\n",
                t.filtered
            ));
        }
        if self.is_recorded() {
            out.push_str(
                "Latencies: recorded in the source capture (slow-log Query_time, or \
                 request→response wire time for pcap captures; no replay target — the \
                 capture carries no error information, so errors are 0 by definition)\n",
            );
        } else {
            out.push_str(&format!(
                "Target: {} ({})\n",
                self.target_server_version, self.target_url
            ));
        }
        if let Some(p) = &self.pacing {
            out.push_str(&format!(
                "Pacing: speed {}x over {} events — max lag {:.1} ms, mean lag {:.1} ms\n",
                p.speed,
                p.paced_events,
                p.max_lag_us as f64 / 1000.0,
                p.mean_lag_us / 1000.0,
            ));
        }
        out.push('\n');

        out.push_str(&format!("Top {top} fingerprints by p95 latency:\n"));
        out.push_str(&format!(
            "{:>8} {:>6} {:>10} {:>10} {:>10} {:>10} {:>9}  {}\n",
            "count", "errs", "p50(ms)", "p95(ms)", "p99(ms)", "max(ms)", "res/query", "fingerprint"
        ));
        for fp in self.fingerprints.iter().filter(|f| f.count > 0).take(top) {
            out.push_str(&format!(
                "{:>8} {:>6} {:>10.3} {:>10.3} {:>10.3} {:>10.3} {:>9}  {}\n",
                fp.count,
                fp.errors,
                fp.p50_us as f64 / 1000.0,
                fp.p95_us as f64 / 1000.0,
                fp.p99_us as f64 / 1000.0,
                fp.max_us as f64 / 1000.0,
                fp.result_bytes
                    .as_ref()
                    .map(|b| fmt_bytes(b.mean))
                    .unwrap_or_else(|| "-".to_string()),
                truncate_chars(&fp.fingerprint, 80),
            ));
        }

        let error_fps: Vec<&FingerprintReport> =
            self.fingerprints.iter().filter(|f| f.errors > 0).collect();
        if !error_fps.is_empty() {
            out.push_str("\nFingerprints with errors:\n");
            for fp in error_fps.iter().take(top) {
                out.push_str(&format!(
                    "  {:>6}x  {}\n          first error: {}\n",
                    fp.errors,
                    truncate_chars(&fp.fingerprint, 80),
                    fp.first_error.as_deref().unwrap_or("<none>"),
                ));
            }
        }
        out
    }
}

fn truncate_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let cut: String = s.chars().take(max).collect();
        format!("{cut}…")
    }
}

/// Strip the password (and anything else in userinfo after `:`) from a URL
/// so it is safe to embed in reports and logs.
pub fn redact_url(url: &str) -> String {
    let Some(scheme_end) = url.find("://") else {
        return url.to_string();
    };
    let rest = &url[scheme_end + 3..];
    let authority = &rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())];
    let Some(at) = authority.rfind('@') else {
        return url.to_string();
    };
    let userinfo = &authority[..at];
    match userinfo.find(':') {
        Some(colon) => format!(
            "{}://{}:***@{}",
            &url[..scheme_end],
            &userinfo[..colon],
            &rest[at + 1..]
        ),
        None => url.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_bucket_boundaries_are_half_open() {
        // Each decade is [lower, upper): the bound value itself belongs to
        // the next decade up.
        assert_eq!(size_bucket_index(0), 0); // no result set
        assert_eq!(size_bucket_index(1023), 0);
        assert_eq!(size_bucket_index(1024), 1);
        assert_eq!(size_bucket_index(10 * 1024 - 1), 1);
        assert_eq!(size_bucket_index(10 * 1024), 2);
        assert_eq!(size_bucket_index(100 * 1024 - 1), 2);
        assert_eq!(size_bucket_index(100 * 1024), 3);
        assert_eq!(size_bucket_index(1024 * 1024 - 1), 3);
        assert_eq!(size_bucket_index(1024 * 1024), 4);
        assert_eq!(size_bucket_index(10 * 1024 * 1024 - 1), 4);
        assert_eq!(size_bucket_index(10 * 1024 * 1024), 5);
        assert_eq!(size_bucket_index(100 * 1024 * 1024 - 1), 5);
        assert_eq!(size_bucket_index(100 * 1024 * 1024), 6);
        assert_eq!(size_bucket_index(u64::MAX), 6);
        // Labels and bounds stay index-aligned.
        assert_eq!(SIZE_BUCKET_LABELS.len(), SIZE_BUCKET_BOUNDS.len() + 1);
        assert_eq!(SIZE_BUCKET_LABELS[size_bucket_index(5 << 20)], "1MB-10MB");
        assert_eq!(
            SIZE_BUCKET_LABELS[size_bucket_index(50 << 20)],
            "10MB-100MB"
        );
        assert_eq!(SIZE_BUCKET_LABELS[size_bucket_index(500 << 20)], ">=100MB");
    }

    #[test]
    fn bytes_format_picks_the_readable_unit() {
        assert_eq!(fmt_bytes(0.0), "0B");
        assert_eq!(fmt_bytes(999.0), "999B");
        assert_eq!(fmt_bytes(1536.0), "1.5KB");
        assert_eq!(fmt_bytes(15.0 * 1024.0 * 1024.0), "15.0MB");
        assert_eq!(fmt_bytes(2.5 * 1024.0 * 1024.0 * 1024.0), "2.5GB");
    }

    #[test]
    fn redacts_password() {
        assert_eq!(
            redact_url("mysql://user:s3cr3t@db.example:3306/prod"),
            "mysql://user:***@db.example:3306/prod"
        );
        assert_eq!(
            redact_url("mysql://user@db.example:3306/"),
            "mysql://user@db.example:3306/"
        );
        assert_eq!(
            redact_url("mysql://db.example:3306/"),
            "mysql://db.example:3306/"
        );
        assert_eq!(
            redact_url("mysql://user:p@ss@db.example:3306/prod"),
            "mysql://user:***@db.example:3306/prod"
        );
        assert_eq!(
            redact_url("mysql://db.example:3306/db@name"),
            "mysql://db.example:3306/db@name"
        );
    }
}
