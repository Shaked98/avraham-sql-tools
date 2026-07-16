//! The `capture` subcommand: slow query log OR pcap file -> compressed
//! replay file. Both sources emit the exact same capture format; replay,
//! baseline, and compare do not care where a capture came from.

use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use anyhow::{Context, Result};
use time::format_description::well_known::Rfc3339;

use crate::fingerprint::FingerprintRegistry;
use crate::format::{
    CaptureWriter, Event, FingerprintEntry, Header, PcapSummary, Record, Summary, FORMAT_VERSION,
};
use crate::slowlog::{ParsedQuery, SlowLogParser};

/// Shared event sink: fingerprints, counts, and writes each event.
struct EventEmitter {
    registry: FingerprintRegistry,
    writer: CaptureWriter,
    sessions: HashSet<u64>,
    event_count: u64,
}

impl EventEmitter {
    fn create(out: &Path) -> Result<Self> {
        let mut writer = CaptureWriter::create(out)?;
        writer.write(&Record::Header(Header {
            version: FORMAT_VERSION,
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            created_at: time::OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .unwrap_or_default(),
        }))?;
        Ok(EventEmitter {
            registry: FingerprintRegistry::new(),
            writer,
            sessions: HashSet::new(),
            event_count: 0,
        })
    }

    fn emit(&mut self, mut event: Event) -> Result<()> {
        event.fingerprint_id = self.registry.intern(&event.query);
        self.sessions.insert(event.session_id);
        self.event_count += 1;
        self.writer.write(&Record::Event(event))
    }

    /// Write the summary record and close the capture file.
    fn finish(mut self, mut summary: Summary) -> Result<Summary> {
        summary.event_count = self.event_count;
        summary.session_count = self.sessions.len() as u64;
        summary.fingerprints = self
            .registry
            .texts()
            .iter()
            .enumerate()
            .map(|(i, text)| FingerprintEntry {
                id: i as u32,
                text: text.clone(),
            })
            .collect();
        self.writer.write(&Record::Summary(summary.clone()))?;
        self.writer.finish()?;
        Ok(summary)
    }
}

pub fn run_capture(input: &Path, out: &Path, dialect_override: Option<&str>) -> Result<Summary> {
    let file =
        File::open(input).with_context(|| format!("cannot open slow log {}", input.display()))?;
    let mut reader = BufReader::new(file);

    let mut parser = SlowLogParser::new();
    let mut emitter = EventEmitter::create(out)?;

    let emit = |emitter: &mut EventEmitter, pq: ParsedQuery| -> Result<()> {
        emitter.emit(Event {
            ts_micros: pq.ts_micros,
            session_id: pq.thread_id,
            user: pq.user,
            db: pq.db,
            query: pq.query,
            orig_query_time_s: pq.query_time_s,
            fingerprint_id: 0, // interned by the emitter
        })
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
            emit(&mut emitter, pq)?;
        }
    }
    if let Some(pq) = parser.finish() {
        emit(&mut emitter, pq)?;
    }

    let source_dialect = dialect_override
        .map(str::to_string)
        .or_else(|| parser.dialect().map(|d| d.as_str().to_string()))
        .unwrap_or_else(|| "unknown".to_string());
    emitter.finish(Summary {
        source_dialect,
        event_count: 0,   // filled by finish()
        session_count: 0, // filled by finish()
        admin_commands_ignored: parser.stats().admin_commands,
        server_restarts_seen: parser.stats().restarts,
        pcap: None,
        fingerprints: Vec::new(), // filled by finish()
    })
}

/// Capture from a tcpdump pcap/pcap-ng file: decode MySQL traffic on
/// `port` into the same capture format the slow-log path emits. The
/// event's `orig_query_time_s` is the observed request→first-response
/// wall time (server + network as seen from the capture point).
pub fn run_capture_pcap(
    input: &Path,
    out: &Path,
    port: u16,
    dialect_override: Option<&str>,
) -> Result<Summary> {
    let mut emitter = EventEmitter::create(out)?;

    let stats = crate::pcap::scan_pcap_file(input, port, |session_id, ev| {
        emitter.emit(Event {
            ts_micros: ev.ts_micros,
            session_id,
            user: ev.user,
            db: ev.db,
            query: ev.query,
            orig_query_time_s: ev.latency_s,
            fingerprint_id: 0, // interned by the emitter
        })
    })?;

    for warning in stats.warnings() {
        tracing::warn!("pcap capture: {warning}");
    }

    // Label the dialect with the observed server version so `compare` can
    // flag cross-source comparisons.
    let source_dialect = dialect_override.map(str::to_string).unwrap_or_else(|| {
        match stats.server_versions.first() {
            Some(v) => format!("pcap:{v}"),
            None => "pcap".to_string(),
        }
    });

    emitter.finish(Summary {
        source_dialect,
        event_count: 0,   // filled by finish()
        session_count: 0, // filled by finish()
        // COM_PING/statistics/... mirror the slow log's "administrator
        // command" entries: commands that never become events.
        admin_commands_ignored: stats.commands_ignored,
        server_restarts_seen: 0,
        pcap: Some(PcapSummary {
            packets: stats.packets,
            truncated_packets: stats.truncated_packets,
            ip_fragments_skipped: stats.ip_fragments_skipped,
            connections: stats.connections,
            connections_decoded: stats.connections_decoded,
            connections_tls_skipped: stats.connections_tls_skipped,
            connections_compressed_skipped: stats.connections_compressed_skipped,
            connections_midstream_skipped: stats.connections_midstream_skipped,
            connections_broken: stats.connections_broken,
            statements_expanded: stats.statements_expanded,
            statements_inexpandable: stats.statements_inexpandable,
            responses_missing: stats.responses_missing,
            server_versions: stats.server_versions.clone(),
        }),
        fingerprints: Vec::new(), // filled by finish()
    })
}
