//! The `baseline` subcommand: turn a capture file's *recorded* production
//! latencies (each event's slow-log `Query_time`) into a run report that
//! `compare` accepts.
//!
//! This exists for migrations where the source server can never be
//! replayed against because it IS production (e.g. a live MySQL 5.7
//! primary) and only the new-version twin host is replayable: capture on
//! production, build the baseline from the recorded latencies, replay the
//! twin, compare.
//!
//! The report has the same shape as `replay --out run.json`, but:
//! - `latency_source` is `"recorded-slow-log"`: latencies are server-side
//!   `Query_time` under live production load (including lock waits and
//!   contention), not client-side replay wall time. `compare` warns loudly
//!   when one side is recorded and the other replayed.
//! - There is no target: `target_url`, `target_server_version`, and
//!   `target_settings` are absent — the slow log does not know them.
//! - The timeline is the capture's own: `started_at`/`ended_at` are the
//!   first/last event timestamps, `wall_secs` their span, and QPS derives
//!   from them.
//! - `errors` is 0 by definition: the slow log records no statement
//!   errors, so a zero says nothing about how production behaved.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use anyhow::{bail, Result};
use hdrhistogram::Histogram;

use crate::format::stream_capture;
use crate::report::{
    FingerprintReport, ReportFlags, RunReport, SaturationReport, Totals, LATENCY_SOURCE_RECORDED,
};
use crate::spool::Filters;

struct FpAgg {
    hist: Histogram<u64>,
    count: u64,
}

impl FpAgg {
    fn new() -> Self {
        FpAgg {
            hist: Histogram::new_with_bounds(1, 3_600_000_000, 3)
                .expect("static histogram bounds are valid"),
            count: 0,
        }
    }
}

/// Stream `capture_path` and aggregate each event's recorded
/// `orig_query_time_s` per fingerprint into a [`RunReport`]. Filters mirror
/// replay's (`--filter-db`/`--filter-user`/`--time-window`); excluded
/// events land in `totals.filtered`.
pub fn build_baseline(capture_path: &Path, filters: &Filters) -> Result<RunReport> {
    let mut per_fp: HashMap<u32, FpAgg> = HashMap::new();
    let mut sessions: HashSet<u64> = HashSet::new();
    let mut events: u64 = 0;
    let mut total: u64 = 0;
    let mut min_ts = i64::MAX;
    let mut max_ts = i64::MIN;

    let (_, summary) = stream_capture(capture_path, |e| {
        total += 1;
        if !filters.matches(&e) {
            return Ok(());
        }
        events += 1;
        sessions.insert(e.session_id);
        min_ts = min_ts.min(e.ts_micros);
        max_ts = max_ts.max(e.ts_micros);
        let agg = per_fp.entry(e.fingerprint_id).or_insert_with(FpAgg::new);
        agg.count += 1;
        // Query_time is fractional seconds; the histogram (shared with
        // replay) stores whole microseconds, floored at 1.
        let micros = (e.orig_query_time_s * 1_000_000.0).round().max(0.0) as u64;
        agg.hist.saturating_record(micros.max(1));
        Ok(())
    })?;

    let filtered = total - events;
    if events == 0 {
        if filtered > 0 {
            bail!(
                "filters excluded all {filtered} events of {} — nothing to aggregate",
                capture_path.display()
            );
        }
        bail!("{} contains no events", capture_path.display());
    }

    let fp_texts: HashMap<u32, &str> = summary
        .fingerprints
        .iter()
        .map(|e| (e.id, e.text.as_str()))
        .collect();
    let mut fingerprints: Vec<FingerprintReport> = per_fp
        .into_iter()
        .map(|(id, agg)| FingerprintReport {
            id,
            fingerprint: fp_texts
                .get(&id)
                .map(|t| t.to_string())
                .unwrap_or_else(|| format!("<unknown fingerprint {id}>")),
            count: agg.count,
            errors: 0,
            first_error: None,
            skipped: 0,
            not_run: 0,
            p50_us: agg.hist.value_at_quantile(0.50),
            p95_us: agg.hist.value_at_quantile(0.95),
            p99_us: agg.hist.value_at_quantile(0.99),
            max_us: agg.hist.max(),
            mean_us: agg.hist.mean(),
        })
        .collect();
    fingerprints.sort_by(|a, b| b.p95_us.cmp(&a.p95_us).then(b.count.cmp(&a.count)));

    let wall_secs = (max_ts - min_ts) as f64 / 1_000_000.0;
    Ok(RunReport {
        tool: "sql-replay".to_string(),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        capture_file: capture_path.display().to_string(),
        capture_dialect: summary.source_dialect.clone(),
        latency_source: LATENCY_SOURCE_RECORDED.to_string(),
        target_url: String::new(),
        target_server_version: String::new(),
        started_at: format_ts_micros(min_ts),
        ended_at: format_ts_micros(max_ts),
        wall_secs,
        aborted: false,
        aggregation: None,
        flags: ReportFlags {
            max_connections: 0,
            allow_writes: false,
            read_only: false,
            db_override: None,
            speed: "recorded".to_string(),
            pool: None,
            warmup: false,
            filter_db: filters.db.clone(),
            filter_user: filters.user.clone(),
            time_window: filters.window.as_ref().map(|w| w.raw.clone()),
        },
        totals: Totals {
            events,
            sessions: sessions.len() as u64,
            // Everything in the log ran on production by definition.
            executed: events,
            skipped: 0,
            errors: 0,
            not_run: 0,
            connect_failures: 0,
            qps: if wall_secs > 0.0 {
                events as f64 / wall_secs
            } else {
                0.0
            },
            filtered,
        },
        saturation: SaturationReport {
            samples: 0,
            saturated_samples: 0,
            saturated_pct: 0.0,
        },
        pacing: None,
        target_settings: std::collections::BTreeMap::new(),
        fingerprints,
    })
}

fn format_ts_micros(ts_micros: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp_nanos(ts_micros as i128 * 1_000)
        .ok()
        .and_then(|t| {
            t.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::{CaptureWriter, Event, FingerprintEntry, Header, Record, Summary};
    use crate::spool::TimeWindow;
    use std::path::PathBuf;

    fn ev(session_id: u64, ts_micros: i64, fp: u32, query_time_s: f64) -> Event {
        Event {
            ts_micros,
            session_id,
            user: Some("app".to_string()),
            db: Some("shop".to_string()),
            query: format!("SELECT {fp}"),
            orig_query_time_s: query_time_s,
            fingerprint_id: fp,
        }
    }

    fn write_capture(path: &Path, events: &[Event]) {
        let mut w = CaptureWriter::create(path).unwrap();
        w.write(&Record::Header(Header {
            version: crate::format::FORMAT_VERSION,
            tool_version: "test".to_string(),
            created_at: "2023-09-01T00:00:00Z".to_string(),
        }))
        .unwrap();
        let mut sessions = HashSet::new();
        let mut fps = HashSet::new();
        for e in events {
            sessions.insert(e.session_id);
            fps.insert(e.fingerprint_id);
            w.write(&Record::Event(e.clone())).unwrap();
        }
        w.write(&Record::Summary(Summary {
            source_dialect: "mysql-5.7".to_string(),
            event_count: events.len() as u64,
            session_count: sessions.len() as u64,
            admin_commands_ignored: 0,
            server_restarts_seen: 0,
            pcap: None,
            fingerprints: fps
                .into_iter()
                .map(|id| FingerprintEntry {
                    id,
                    text: format!("select {id}"),
                })
                .collect(),
        }))
        .unwrap();
        w.finish().unwrap();
    }

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "sql-replay-baseline-test-{}-{name}",
            std::process::id()
        ))
    }

    #[test]
    fn aggregates_recorded_latencies_into_exact_percentiles() {
        // 100 events of one fingerprint at 1..=100 µs: all values are below
        // the histogram's exact-representation range, so the percentiles
        // are exact, not approximations.
        let events: Vec<Event> = (1..=100)
            .map(|i| ev(1, 1_000_000 * i, 7, i as f64 / 1_000_000.0))
            .collect();
        let cap = temp_path("percentiles.zst");
        write_capture(&cap, &events);
        let report = build_baseline(&cap, &Filters::default()).unwrap();
        std::fs::remove_file(&cap).unwrap();

        assert_eq!(report.fingerprints.len(), 1);
        let fp = &report.fingerprints[0];
        assert_eq!(fp.fingerprint, "select 7");
        assert_eq!(fp.count, 100);
        assert_eq!(fp.p50_us, 50);
        assert_eq!(fp.p95_us, 95);
        assert_eq!(fp.p99_us, 99);
        assert_eq!(fp.max_us, 100);
        assert_eq!(fp.mean_us, 50.5);
        assert_eq!(fp.errors, 0);
        assert_eq!(fp.skipped, 0);
    }

    #[test]
    fn report_carries_provenance_and_capture_timeline() {
        let events = vec![
            ev(1, 1_693_569_601_000_000, 0, 0.001),
            ev(2, 1_693_569_602_000_000, 1, 0.002),
            ev(1, 1_693_569_604_000_000, 0, 0.003),
        ];
        let cap = temp_path("timeline.zst");
        write_capture(&cap, &events);
        let report = build_baseline(&cap, &Filters::default()).unwrap();
        std::fs::remove_file(&cap).unwrap();

        assert_eq!(report.latency_source, LATENCY_SOURCE_RECORDED);
        assert!(report.is_recorded());
        assert_eq!(report.capture_dialect, "mysql-5.7");
        assert_eq!(report.started_at, "2023-09-01T12:00:01Z");
        assert_eq!(report.ended_at, "2023-09-01T12:00:04Z");
        assert_eq!(report.wall_secs, 3.0);
        assert_eq!(report.totals.events, 3);
        assert_eq!(report.totals.executed, 3);
        assert_eq!(report.totals.sessions, 2);
        assert_eq!(report.totals.errors, 0);
        assert_eq!(report.totals.qps, 1.0);
        assert!(!report.aborted);
        assert!(report.pacing.is_none());
        assert!(report.target_settings.is_empty());

        // No target: the JSON must omit target_url/target_server_version
        // and target_settings entirely.
        let json = serde_json::to_value(&report).unwrap();
        assert!(json.get("target_url").is_none());
        assert!(json.get("target_server_version").is_none());
        assert!(json.get("target_settings").is_none());
        assert_eq!(json["latency_source"], "recorded-slow-log");

        // The provenance marker round-trips...
        let back: RunReport = serde_json::from_value(json).unwrap();
        assert!(back.is_recorded());
        // ...and a report without one (any pre-0.2.0 run.json) defaults to
        // replayed.
        let mut old = serde_json::to_value(&report).unwrap();
        old.as_object_mut().unwrap().remove("latency_source");
        let old: RunReport = serde_json::from_value(old).unwrap();
        assert_eq!(old.latency_source, "replayed");
        assert!(!old.is_recorded());

        let table = report.render_table(10);
        assert!(table.contains("Recorded 3 events"));
        assert!(table.contains("recorded in the production slow log"));
    }

    #[test]
    fn filters_mirror_replay_and_land_in_filtered() {
        let mut events = vec![
            ev(1, 1_000_000, 0, 0.001),
            ev(1, 2_000_000, 0, 0.002),
            ev(2, 3_000_000, 1, 0.003),
        ];
        events[2].user = Some("batch".to_string());
        let cap = temp_path("filters.zst");
        write_capture(&cap, &events);

        let filters = Filters {
            user: Some("app".to_string()),
            ..Filters::default()
        };
        let report = build_baseline(&cap, &filters).unwrap();
        assert_eq!(report.totals.events, 2);
        assert_eq!(report.totals.filtered, 1);
        assert_eq!(report.totals.sessions, 1);
        assert_eq!(report.flags.filter_user.as_deref(), Some("app"));
        // The timeline reflects only the included events.
        assert_eq!(report.wall_secs, 1.0);

        let filters = Filters {
            window: Some(TimeWindow::parse("100..200").unwrap()),
            ..Filters::default()
        };
        let err = build_baseline(&cap, &filters).unwrap_err().to_string();
        assert!(err.contains("excluded all 3 events"), "{err}");
        std::fs::remove_file(&cap).unwrap();
    }

    #[test]
    fn sub_microsecond_and_zero_query_times_clamp_to_one_microsecond() {
        let events = vec![ev(1, 1_000_000, 0, 0.0), ev(1, 2_000_000, 0, 0.0000001)];
        let cap = temp_path("clamp.zst");
        write_capture(&cap, &events);
        let report = build_baseline(&cap, &Filters::default()).unwrap();
        std::fs::remove_file(&cap).unwrap();
        assert_eq!(report.fingerprints[0].p50_us, 1);
        assert_eq!(report.fingerprints[0].max_us, 1);
    }

    #[test]
    fn empty_capture_is_an_error() {
        let cap = temp_path("empty.zst");
        write_capture(&cap, &[]);
        let err = build_baseline(&cap, &Filters::default())
            .unwrap_err()
            .to_string();
        std::fs::remove_file(&cap).unwrap();
        assert!(err.contains("contains no events"), "{err}");
    }
}
