//! Bounded-memory replay ingestion: the on-disk session spool.
//!
//! Replay must not materialize the capture (M3 requirement: captures can
//! hold millions of events). Instead the capture is streamed twice into a
//! single unlinked temp file — the *spool* — laid out as one contiguous
//! region per session:
//!
//! - **Pass A** streams the capture to size each session's region (and to
//!   collect per-session metadata: event count, whether any event passes
//!   the write gate, plus the global pacing origin = earliest included
//!   timestamp).
//! - **Pass B** streams the capture again, writing each event's record
//!   (`u32` little-endian length prefix + the event as JSON) into its
//!   session's region via positioned writes.
//!
//! Each replay session then reads its own events through an independent
//! [`SpoolCursor`] (positioned reads on a shared `File`), so peak memory is
//! O(sessions) + one in-flight event per session — independent of capture
//! size — and no cross-session coordination exists that could deadlock or
//! head-of-line block. The spool file is unlinked right after creation, so
//! the OS reclaims it even on crash; disk usage is roughly the uncompressed
//! capture size for the duration of the replay.
//!
//! Replay-side filters (`--filter-db`, `--filter-user`, `--time-window`)
//! are applied here, during spooling. Filtering at replay rather than at
//! capture keeps the capture a complete, reusable artifact: capturing is
//! expensive and done on the production source, while re-slicing a capture
//! per replay run is cheap and repeatable.

use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{bail, Context, Result};

use crate::classify::should_execute;
use crate::format::{stream_capture, Event, Header, Summary};

/// Replay-side event filters, applied while building the spool.
#[derive(Clone, Debug, Default)]
pub struct Filters {
    /// Keep only events whose captured default database equals this.
    /// Events with no database metadata do not match.
    pub db: Option<String>,
    /// Keep only events whose captured user equals this. Events with no
    /// user metadata do not match.
    pub user: Option<String>,
    /// Keep only events whose timestamp falls in this window.
    pub window: Option<TimeWindow>,
}

impl Filters {
    pub fn is_active(&self) -> bool {
        self.db.is_some() || self.user.is_some() || self.window.is_some()
    }

    pub fn matches(&self, event: &Event) -> bool {
        if let Some(db) = &self.db {
            if event.db.as_deref() != Some(db.as_str()) {
                return false;
            }
        }
        if let Some(user) = &self.user {
            if event.user.as_deref() != Some(user.as_str()) {
                return false;
            }
        }
        if let Some(w) = &self.window {
            if !w.contains(event.ts_micros) {
                return false;
            }
        }
        true
    }
}

/// `--time-window <start>..<end>`: start-inclusive, end-exclusive. Either
/// side may be omitted for an open range. Bounds are RFC 3339 timestamps
/// (`2023-09-01T12:00:02Z`) or unix epoch seconds.
#[derive(Clone, Debug, PartialEq)]
pub struct TimeWindow {
    pub raw: String,
    pub start_micros: Option<i64>,
    pub end_micros: Option<i64>,
}

impl TimeWindow {
    pub fn parse(s: &str) -> Result<TimeWindow, String> {
        let Some((start, end)) = s.split_once("..") else {
            return Err(format!(
                "expected <start>..<end> (RFC 3339 or unix seconds, either side optional), \
                 got `{s}`"
            ));
        };
        let parse_bound = |b: &str| -> Result<Option<i64>, String> {
            if b.is_empty() {
                return Ok(None);
            }
            if let Ok(secs) = b.parse::<i64>() {
                return Ok(Some(secs.saturating_mul(1_000_000)));
            }
            time::OffsetDateTime::parse(b, &time::format_description::well_known::Rfc3339)
                .map(|t| {
                    Some(t.unix_timestamp().saturating_mul(1_000_000) + i64::from(t.microsecond()))
                })
                .map_err(|_| format!("`{b}` is not an RFC 3339 timestamp or unix epoch seconds"))
        };
        let win = TimeWindow {
            raw: s.to_string(),
            start_micros: parse_bound(start)?,
            end_micros: parse_bound(end)?,
        };
        if let (Some(a), Some(b)) = (win.start_micros, win.end_micros) {
            if a >= b {
                return Err(format!("time window start must precede end, got `{s}`"));
            }
        }
        if win.start_micros.is_none() && win.end_micros.is_none() {
            return Err("time window has neither a start nor an end".to_string());
        }
        Ok(win)
    }

    fn contains(&self, ts_micros: i64) -> bool {
        self.start_micros.is_none_or(|s| ts_micros >= s)
            && self.end_micros.is_none_or(|e| ts_micros < e)
    }
}

/// Per-session metadata gathered in pass A.
#[derive(Debug, Clone)]
pub struct SpoolSession {
    pub session_id: u64,
    /// Byte range of this session's contiguous region in the spool file.
    start: u64,
    end: u64,
    pub event_count: u64,
    /// Whether any event passes the write gate — a session with none never
    /// connects (its events are recorded as skipped without pacing).
    pub has_executable: bool,
}

/// The built spool: session index plus the shared (already unlinked)
/// backing file.
pub struct Spool {
    file: Arc<File>,
    pub sessions: Vec<SpoolSession>,
    pub header: Header,
    pub summary: Summary,
    /// Pacing origin: earliest timestamp among *included* events.
    pub base_ts_micros: i64,
    /// Events written to the spool (after filters).
    pub event_count: u64,
    /// Events excluded by filters.
    pub filtered: u64,
    /// Total spool file size in bytes.
    pub bytes: u64,
}

struct SessionBuild {
    session_id: u64,
    bytes: u64,
    event_count: u64,
    has_executable: bool,
    /// Set in the layout step; pass B advances it as the write cursor.
    write_pos: u64,
}

impl Spool {
    /// Build the spool from a capture. `allow_writes` feeds the pass-A
    /// write-gate precomputation (mirroring the per-event gate applied at
    /// execution time); `dir` overrides the spool's temp directory.
    pub fn build(
        capture_path: &Path,
        dir: Option<&Path>,
        filters: &Filters,
        allow_writes: bool,
    ) -> Result<Spool> {
        // Pass A: size each session's region and gather metadata.
        let mut order: Vec<u64> = Vec::new();
        let mut sessions: std::collections::HashMap<u64, SessionBuild> =
            std::collections::HashMap::new();
        let mut base_ts_micros = i64::MAX;
        let mut included: u64 = 0;
        let mut filtered: u64 = 0;
        let (header, summary) = stream_capture(capture_path, |event| {
            if !filters.matches(&event) {
                filtered += 1;
                return Ok(());
            }
            included += 1;
            base_ts_micros = base_ts_micros.min(event.ts_micros);
            let record_len = record_size(&event)?;
            let s = sessions.entry(event.session_id).or_insert_with(|| {
                order.push(event.session_id);
                SessionBuild {
                    session_id: event.session_id,
                    bytes: 0,
                    event_count: 0,
                    has_executable: false,
                    write_pos: 0,
                }
            });
            s.bytes += record_len;
            s.event_count += 1;
            s.has_executable |= should_execute(&event.query, allow_writes);
            Ok(())
        })?;

        if included == 0 && filtered > 0 {
            bail!(
                "filters excluded all {filtered} events of {} — nothing to replay",
                capture_path.display()
            );
        }

        // Layout: contiguous regions in first-appearance order (the same
        // session order the in-memory grouping used).
        let mut offset: u64 = 0;
        let mut index: Vec<SpoolSession> = Vec::with_capacity(order.len());
        for sid in &order {
            let s = sessions.get_mut(sid).expect("session recorded in order");
            s.write_pos = offset;
            index.push(SpoolSession {
                session_id: s.session_id,
                start: offset,
                end: offset + s.bytes,
                event_count: s.event_count,
                has_executable: s.has_executable,
            });
            offset += s.bytes;
        }

        let file = create_unlinked_temp(dir)?;
        file.set_len(offset)
            .context("cannot size the replay spool file (disk full?)")?;

        // Pass B: stream the capture again, writing each event into its
        // session's region.
        stream_capture(capture_path, |event| {
            if !filters.matches(&event) {
                return Ok(());
            }
            let Some(s) = sessions.get_mut(&event.session_id) else {
                bail!(
                    "capture {} changed while being spooled (session {} appeared \
                     between passes)",
                    capture_path.display(),
                    event.session_id
                );
            };
            let rec = encode_record(&event)?;
            file.write_all_at(&rec, s.write_pos)
                .context("cannot write to the replay spool file")?;
            s.write_pos += rec.len() as u64;
            Ok(())
        })?;

        // Every region must be exactly full, or the capture changed between
        // the two passes.
        for planned in &index {
            let s = sessions
                .get(&planned.session_id)
                .expect("indexed session was seen in pass A");
            if s.write_pos != planned.end {
                bail!(
                    "capture {} changed while being spooled (session {} wrote {} of {} bytes)",
                    capture_path.display(),
                    planned.session_id,
                    s.write_pos - planned.start,
                    planned.end - planned.start
                );
            }
        }

        Ok(Spool {
            file: Arc::new(file),
            sessions: index,
            header,
            summary,
            base_ts_micros: if included > 0 { base_ts_micros } else { 0 },
            event_count: included,
            filtered,
            bytes: offset,
        })
    }

    pub fn cursor(&self, session: &SpoolSession) -> SpoolCursor {
        SpoolCursor {
            file: self.file.clone(),
            pos: session.start,
            end: session.end,
        }
    }
}

/// Sequential reader over one session's spool region. Reading is two small
/// positioned reads per event (length prefix, then the record); the spool
/// is written once and read sequentially per region, so these are page
/// cache hits in practice.
pub struct SpoolCursor {
    file: Arc<File>,
    pos: u64,
    end: u64,
}

impl SpoolCursor {
    pub fn next_event(&mut self) -> Result<Option<Event>> {
        if self.pos >= self.end {
            return Ok(None);
        }
        let mut len_buf = [0u8; 4];
        self.file
            .read_exact_at(&mut len_buf, self.pos)
            .context("reading spool record length")?;
        let len = u32::from_le_bytes(len_buf) as u64;
        if self.pos + 4 + len > self.end {
            bail!("corrupt spool: record overruns its session region");
        }
        let mut buf = vec![0u8; len as usize];
        self.file
            .read_exact_at(&mut buf, self.pos + 4)
            .context("reading spool record")?;
        self.pos += 4 + len;
        let event: Event = serde_json::from_slice(&buf).context("corrupt spool record")?;
        Ok(Some(event))
    }
}

fn record_size(event: &Event) -> Result<u64> {
    // Sizing must agree byte-for-byte with encode_record; serde_json output
    // for the same value is deterministic.
    let body = serde_json::to_vec(event).context("serializing event")?;
    Ok(4 + body.len() as u64)
}

fn encode_record(event: &Event) -> Result<Vec<u8>> {
    let body = serde_json::to_vec(event).context("serializing event")?;
    let mut rec = Vec::with_capacity(4 + body.len());
    rec.extend_from_slice(&(body.len() as u32).to_le_bytes());
    rec.extend_from_slice(&body);
    Ok(rec)
}

/// Create the spool file and immediately unlink it: the kernel keeps the
/// data reachable through our handle and reclaims it when the last handle
/// closes, even if the process crashes.
fn create_unlinked_temp(dir: Option<&Path>) -> Result<File> {
    let dir: PathBuf = dir
        .map(Path::to_path_buf)
        .unwrap_or_else(std::env::temp_dir);
    let path = dir.join(format!(
        "sql-replay-spool-{}-{:x}.tmp",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .with_context(|| {
            format!(
                "cannot create replay spool file {} (use --spool-dir to pick a \
                 writable directory with enough space)",
                path.display()
            )
        })?;
    if let Err(e) = std::fs::remove_file(&path) {
        tracing::warn!(path = %path.display(), error = %e, "could not unlink spool file");
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::{CaptureWriter, FingerprintEntry, Record, FORMAT_VERSION};

    fn ev(session_id: u64, ts_micros: i64, query: &str) -> Event {
        Event {
            ts_micros,
            session_id,
            user: Some("app".to_string()),
            db: Some("shop".to_string()),
            query: query.to_string(),
            orig_query_time_s: 0.001,
            fingerprint_id: 0,
        }
    }

    fn write_capture(path: &Path, events: &[Event]) {
        let mut w = CaptureWriter::create(path).unwrap();
        w.write(&Record::Header(Header {
            version: FORMAT_VERSION,
            tool_version: "test".to_string(),
            created_at: "2023-09-01T00:00:00Z".to_string(),
        }))
        .unwrap();
        let mut sessions = std::collections::HashSet::new();
        for e in events {
            sessions.insert(e.session_id);
            w.write(&Record::Event(e.clone())).unwrap();
        }
        w.write(&Record::Summary(Summary {
            source_dialect: "test".to_string(),
            event_count: events.len() as u64,
            session_count: sessions.len() as u64,
            admin_commands_ignored: 0,
            server_restarts_seen: 0,
            fingerprints: vec![FingerprintEntry {
                id: 0,
                text: "select ?".to_string(),
            }],
        }))
        .unwrap();
        w.finish().unwrap();
    }

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "sql-replay-spool-test-{}-{name}",
            std::process::id()
        ))
    }

    #[test]
    fn spool_round_trips_sessions_in_first_seen_order() {
        let events = vec![
            ev(7, 1_000_000, "SELECT 1"),
            ev(3, 2_000_000, "SELECT 2"),
            ev(7, 3_000_000, "SELECT 3"),
            ev(9, 4_000_000, "INSERT INTO t VALUES (1)"),
            ev(3, 5_000_000, "SELECT 4"),
        ];
        let cap = temp_path("roundtrip.zst");
        write_capture(&cap, &events);
        let spool = Spool::build(&cap, None, &Filters::default(), false).unwrap();
        std::fs::remove_file(&cap).unwrap();

        assert_eq!(spool.event_count, 5);
        assert_eq!(spool.filtered, 0);
        assert_eq!(spool.base_ts_micros, 1_000_000);
        let ids: Vec<u64> = spool.sessions.iter().map(|s| s.session_id).collect();
        assert_eq!(ids, [7, 3, 9]);
        // Write-gated INSERT-only session has nothing executable.
        assert!(spool.sessions[0].has_executable);
        assert!(spool.sessions[1].has_executable);
        assert!(!spool.sessions[2].has_executable);

        let mut replayed: Vec<Event> = Vec::new();
        for s in &spool.sessions {
            let mut c = spool.cursor(s);
            let mut n = 0;
            while let Some(e) = c.next_event().unwrap() {
                assert_eq!(e.session_id, s.session_id);
                replayed.push(e);
                n += 1;
            }
            assert_eq!(n, s.event_count);
        }
        // Per-session order matches capture order.
        let s7: Vec<&str> = replayed
            .iter()
            .filter(|e| e.session_id == 7)
            .map(|e| e.query.as_str())
            .collect();
        assert_eq!(s7, ["SELECT 1", "SELECT 3"]);
    }

    #[test]
    fn filters_narrow_the_spool_and_move_the_pacing_origin() {
        let mut events = vec![
            ev(1, 1_000_000, "SELECT 'early'"),
            ev(1, 5_000_000, "SELECT 'kept'"),
            ev(2, 6_000_000, "SELECT 'kept too'"),
            ev(2, 9_000_000, "SELECT 'late'"),
        ];
        events[2].user = Some("other".to_string());
        let cap = temp_path("filters.zst");
        write_capture(&cap, &events);

        let filters = Filters {
            window: Some(TimeWindow::parse("2..9").unwrap()),
            ..Filters::default()
        };
        let spool = Spool::build(&cap, None, &filters, false).unwrap();
        assert_eq!(spool.event_count, 2);
        assert_eq!(spool.filtered, 2);
        // Pacing origin is the earliest *included* timestamp.
        assert_eq!(spool.base_ts_micros, 5_000_000);
        assert_eq!(spool.sessions.len(), 2);

        let filters = Filters {
            user: Some("app".to_string()),
            ..Filters::default()
        };
        let spool = Spool::build(&cap, None, &filters, false).unwrap();
        assert_eq!(spool.event_count, 3);
        assert_eq!(spool.filtered, 1);

        let filters = Filters {
            db: Some("nope".to_string()),
            ..Filters::default()
        };
        let Err(err) = Spool::build(&cap, None, &filters, false) else {
            panic!("all-excluding filters must fail the build");
        };
        assert!(err.to_string().contains("filters excluded all 4 events"));
        std::fs::remove_file(&cap).unwrap();
    }

    #[test]
    fn time_window_parses_rfc3339_and_unix_and_open_ends() {
        let w = TimeWindow::parse("1693569601..1693569603").unwrap();
        assert_eq!(w.start_micros, Some(1_693_569_601_000_000));
        assert_eq!(w.end_micros, Some(1_693_569_603_000_000));
        assert!(w.contains(1_693_569_601_000_000));
        assert!(w.contains(1_693_569_602_999_999));
        assert!(!w.contains(1_693_569_603_000_000)); // end-exclusive

        let w = TimeWindow::parse("2023-09-01T12:00:01Z..2023-09-01T12:00:03Z").unwrap();
        assert_eq!(w.start_micros, Some(1_693_569_601_000_000));
        assert_eq!(w.end_micros, Some(1_693_569_603_000_000));

        let w = TimeWindow::parse("100..").unwrap();
        assert_eq!(w.start_micros, Some(100_000_000));
        assert_eq!(w.end_micros, None);
        assert!(w.contains(i64::MAX));

        let w = TimeWindow::parse("..100").unwrap();
        assert_eq!(w.start_micros, None);
        assert!(w.contains(i64::MIN));

        assert!(TimeWindow::parse("100").is_err());
        assert!(TimeWindow::parse("..").is_err());
        assert!(TimeWindow::parse("5..3").is_err());
        assert!(TimeWindow::parse("yesterday..today").is_err());
    }

    #[test]
    fn db_filter_excludes_events_without_db_metadata() {
        let mut e = ev(1, 0, "SELECT 1");
        e.db = None;
        let f = Filters {
            db: Some("shop".to_string()),
            ..Filters::default()
        };
        assert!(!f.matches(&e));
        assert!(f.matches(&ev(1, 0, "SELECT 1")));
    }
}
