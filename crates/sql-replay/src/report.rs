//! Machine-readable run report (`--out run.json`) and the human summary
//! table printed to stdout.

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
    pub flags: ReportFlags,
    pub totals: Totals,
    pub saturation: SaturationReport,
    pub fingerprints: Vec<FingerprintReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportFlags {
    pub max_connections: usize,
    pub allow_writes: bool,
    pub read_only: bool,
    pub db_override: Option<String>,
    pub speed: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Totals {
    pub events: u64,
    pub sessions: u64,
    pub executed: u64,
    pub skipped: u64,
    pub errors: u64,
    /// Events abandoned after a fatal connection error in their session.
    pub not_run: u64,
    pub connect_failures: u64,
    pub qps: f64,
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
            Some(format!(
                "WARNING: the connection cap was saturated for {:.0}% of the run \
                 ({} of {} samples had all {} permits taken with sessions waiting). \
                 Latency and QPS results may be limited by --max-connections \
                 rather than by the target server.",
                self.saturation.saturated_pct,
                self.saturation.saturated_samples,
                self.saturation.samples,
                self.flags.max_connections,
            ))
        } else {
            None
        }
    }

    pub fn render_table(&self, top: usize) -> String {
        let mut out = String::new();
        let t = &self.totals;
        out.push_str(&format!(
            "Replayed {} events across {} sessions in {:.2}s — {:.1} QPS\n",
            t.events, t.sessions, self.wall_secs, t.qps
        ));
        out.push_str(&format!(
            "  executed: {}  skipped: {}  errors: {}  not run: {}  connect failures: {}\n",
            t.executed, t.skipped, t.errors, t.not_run, t.connect_failures
        ));
        out.push_str(&format!(
            "Target: {} ({})\n\n",
            self.target_server_version, self.target_url
        ));

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
