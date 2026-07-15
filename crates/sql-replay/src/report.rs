//! Machine-readable run report (`--out run.json`) and the human summary
//! table printed to stdout.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunReport {
    pub tool: String,
    pub tool_version: String,
    pub capture_file: String,
    pub capture_dialect: String,
    pub target_url: String,
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
}

impl RunReport {
    /// Above this, results are likely throttled by --max-connections rather
    /// than by the target server.
    pub const SATURATION_WARN_PCT: f64 = 20.0;

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
        out.push_str(&format!(
            "Replayed {} events across {} sessions in {:.2}s — {:.1} QPS\n",
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
        out.push_str(&format!(
            "Target: {} ({})\n",
            self.target_server_version, self.target_url
        ));
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
            "{:>8} {:>6} {:>10} {:>10} {:>10} {:>10}  {}\n",
            "count", "errs", "p50(ms)", "p95(ms)", "p99(ms)", "max(ms)", "fingerprint"
        ));
        for fp in self.fingerprints.iter().filter(|f| f.count > 0).take(top) {
            out.push_str(&format!(
                "{:>8} {:>6} {:>10.3} {:>10.3} {:>10.3} {:>10.3}  {}\n",
                fp.count,
                fp.errors,
                fp.p50_us as f64 / 1000.0,
                fp.p95_us as f64 / 1000.0,
                fp.p99_us as f64 / 1000.0,
                fp.max_us as f64 / 1000.0,
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
