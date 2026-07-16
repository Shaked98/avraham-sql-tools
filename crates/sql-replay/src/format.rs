//! The capture file format: zstd-compressed JSONL.
//!
//! Line 1 is a `header` record, followed by one `event` record per query,
//! and a final `summary` record carrying the source dialect, event count,
//! and the fingerprint id -> normalized text table.

use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

pub const FORMAT_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Record {
    Header(Header),
    Event(Event),
    Summary(Summary),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header {
    pub version: u32,
    pub tool_version: String,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Event {
    pub ts_micros: i64,
    /// Original connection thread id; replay runs one session per id.
    pub session_id: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db: Option<String>,
    pub query: String,
    pub orig_query_time_s: f64,
    pub fingerprint_id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Summary {
    pub source_dialect: String,
    pub event_count: u64,
    pub session_count: u64,
    pub admin_commands_ignored: u64,
    pub server_restarts_seen: u64,
    /// Wire-decode counters, present only for captures built from a pcap
    /// file (0.3.0+; serde default keeps older captures loading).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pcap: Option<PcapSummary>,
    /// fingerprint_id -> normalized query text
    pub fingerprints: Vec<FingerprintEntry>,
}

/// pcap-source decode counters (mirrors `pcap::PcapStats`); everything the
/// wire decode skipped or lost is counted here so it is never silent.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PcapSummary {
    pub packets: u64,
    pub truncated_packets: u64,
    pub ip_fragments_skipped: u64,
    pub connections: u64,
    pub connections_decoded: u64,
    pub connections_tls_skipped: u64,
    pub connections_compressed_skipped: u64,
    pub connections_midstream_skipped: u64,
    pub connections_broken: u64,
    pub statements_expanded: u64,
    pub statements_inexpandable: u64,
    pub responses_missing: u64,
    pub server_versions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FingerprintEntry {
    pub id: u32,
    pub text: String,
}

impl Summary {
    pub fn fingerprint_text(&self, id: u32) -> Option<&str> {
        self.fingerprints
            .iter()
            .find(|e| e.id == id)
            .map(|e| e.text.as_str())
    }
}

pub struct CaptureWriter {
    enc: zstd::stream::write::Encoder<'static, BufWriter<File>>,
}

impl CaptureWriter {
    pub fn create(path: &Path) -> Result<Self> {
        let file = File::create(path)
            .with_context(|| format!("cannot create capture file {}", path.display()))?;
        let enc = zstd::stream::write::Encoder::new(BufWriter::new(file), 3)?;
        Ok(CaptureWriter { enc })
    }

    pub fn write(&mut self, rec: &Record) -> Result<()> {
        serde_json::to_writer(&mut self.enc, rec)?;
        self.enc.write_all(b"\n")?;
        Ok(())
    }

    pub fn finish(self) -> Result<()> {
        self.enc.finish()?.flush()?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct CaptureFile {
    pub header: Header,
    pub events: Vec<Event>,
    pub summary: Summary,
}

/// Stream every event of a capture through `on_event` without materializing
/// the file: peak memory is one record regardless of capture size. Returns
/// the header and summary after validating the format version and that the
/// summary's declared event count matches the events seen.
pub fn stream_capture(
    path: &Path,
    mut on_event: impl FnMut(Event) -> Result<()>,
) -> Result<(Header, Summary)> {
    let file =
        File::open(path).with_context(|| format!("cannot open capture file {}", path.display()))?;
    let dec = zstd::stream::read::Decoder::new(file)?;
    let reader = BufReader::new(dec);

    let mut header: Option<Header> = None;
    let mut summary: Option<Summary> = None;
    let mut event_count: u64 = 0;

    for (idx, line) in reader.lines().enumerate() {
        let line = line.with_context(|| format!("capture line {}", idx + 1))?;
        if line.trim().is_empty() {
            continue;
        }
        let rec: Record = serde_json::from_str(&line)
            .with_context(|| format!("malformed capture record on line {}", idx + 1))?;
        match rec {
            Record::Header(h) => {
                if h.version != FORMAT_VERSION {
                    bail!(
                        "unsupported capture format version {} (this build reads {})",
                        h.version,
                        FORMAT_VERSION
                    );
                }
                header = Some(h);
            }
            Record::Event(e) => {
                event_count += 1;
                on_event(e)?;
            }
            Record::Summary(s) => summary = Some(s),
        }
    }

    let header = header.context("capture file has no header record")?;
    let summary = summary.context("capture file has no summary record (truncated capture?)")?;
    if summary.event_count != event_count {
        bail!(
            "capture summary declares {} events but file contains {}",
            summary.event_count,
            event_count
        );
    }
    Ok((header, summary))
}

/// Read a whole capture into memory. Kept for tests and small captures;
/// replay streams via [`stream_capture`] so its memory stays bounded.
pub fn read_capture(path: &Path) -> Result<CaptureFile> {
    let mut events: Vec<Event> = Vec::new();
    let (header, summary) = stream_capture(path, |e| {
        events.push(e);
        Ok(())
    })?;
    Ok(CaptureFile {
        header,
        events,
        summary,
    })
}
