//! The `capture` subcommand: slow query log -> compressed replay file.

use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use anyhow::{Context, Result};
use time::format_description::well_known::Rfc3339;

use crate::fingerprint::FingerprintRegistry;
use crate::format::{
    CaptureWriter, Event, FingerprintEntry, Header, Record, Summary, FORMAT_VERSION,
};
use crate::slowlog::{ParsedQuery, SlowLogParser};

pub fn run_capture(input: &Path, out: &Path, dialect_override: Option<&str>) -> Result<Summary> {
    let file =
        File::open(input).with_context(|| format!("cannot open slow log {}", input.display()))?;
    let mut reader = BufReader::new(file);

    let mut parser = SlowLogParser::new();
    let mut registry = FingerprintRegistry::new();
    let mut writer = CaptureWriter::create(out)?;
    writer.write(&Record::Header(Header {
        version: FORMAT_VERSION,
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        created_at: time::OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_default(),
    }))?;

    let mut sessions: HashSet<u64> = HashSet::new();
    let mut event_count: u64 = 0;

    let mut emit = |writer: &mut CaptureWriter, pq: ParsedQuery| -> Result<()> {
        let fingerprint_id = registry.intern(&pq.query);
        sessions.insert(pq.thread_id);
        event_count += 1;
        writer.write(&Record::Event(Event {
            ts_micros: pq.ts_micros,
            session_id: pq.thread_id,
            user: pq.user,
            db: pq.db,
            query: pq.query,
            orig_query_time_s: pq.query_time_s,
            fingerprint_id,
        }))
    };

    // Slow logs may contain non-UTF-8 bytes inside query text, so read raw
    // lines and convert lossily instead of failing.
    let mut raw: Vec<u8> = Vec::new();
    loop {
        raw.clear();
        let n = reader
            .read_until(b'\n', &mut raw)
            .with_context(|| format!("reading {}", input.display()))?;
        if n == 0 {
            break;
        }
        let line = String::from_utf8_lossy(&raw);
        let line = line.trim_end_matches(['\n', '\r']);
        if let Some(pq) = parser.push_line(line) {
            emit(&mut writer, pq)?;
        }
    }
    if let Some(pq) = parser.finish() {
        emit(&mut writer, pq)?;
    }

    let source_dialect = dialect_override
        .map(str::to_string)
        .or_else(|| parser.dialect().map(|d| d.as_str().to_string()))
        .unwrap_or_else(|| "unknown".to_string());
    let summary = Summary {
        source_dialect,
        event_count,
        session_count: sessions.len() as u64,
        admin_commands_ignored: parser.stats().admin_commands,
        server_restarts_seen: parser.stats().restarts,
        fingerprints: registry
            .texts()
            .iter()
            .enumerate()
            .map(|(i, text)| FingerprintEntry {
                id: i as u32,
                text: text.clone(),
            })
            .collect(),
    };
    writer.write(&Record::Summary(summary.clone()))?;
    writer.finish()?;
    Ok(summary)
}
