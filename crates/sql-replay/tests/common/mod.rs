//! Shared test helpers: a mock replay [`Target`] (so scheduling behavior —
//! permits, pacing, pooling, abort — is testable at scale without MySQL)
//! and synthetic capture generators.
//!
//! Each test binary compiles its own copy, and none of them uses every
//! helper — silence per-binary dead-code noise.
#![allow(dead_code)]

use std::path::Path;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sql_replay::format::{
    CaptureWriter, Event, FingerprintEntry, Header, Record, Summary, FORMAT_VERSION,
};
use sql_replay::target::{Target, TargetConn, TargetError};
use tokio::sync::watch;

#[derive(Default)]
pub struct MockState {
    pub connects: AtomicU64,
    pub live: AtomicI64,
    pub max_live: AtomicI64,
    pub queries: AtomicU64,
    /// When nonzero: flip `shutdown_tx` to true the moment this many
    /// queries have started (deterministic mid-run abort).
    pub shutdown_after: AtomicU64,
    pub shutdown_tx: Mutex<Option<watch::Sender<bool>>>,
}

/// Mock target: counts connections/queries, tracks peak concurrent
/// connections, optionally sleeps per query, optionally triggers a
/// shutdown after N queries. Queries containing `MOCK_FAIL` error
/// non-fatally; `MOCK_FATAL` errors fatally (connection considered dead).
#[derive(Clone)]
pub struct MockTarget {
    pub latency: Duration,
    pub state: Arc<MockState>,
}

impl MockTarget {
    pub fn new(latency: Duration) -> Self {
        MockTarget {
            latency,
            state: Arc::new(MockState::default()),
        }
    }
}

pub struct MockConn {
    state: Arc<MockState>,
    latency: Duration,
}

impl Drop for MockConn {
    fn drop(&mut self) {
        self.state.live.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Target for MockTarget {
    type Conn = MockConn;

    async fn connect(&self) -> Result<MockConn, TargetError> {
        self.state.connects.fetch_add(1, Ordering::SeqCst);
        let live = self.state.live.fetch_add(1, Ordering::SeqCst) + 1;
        self.state.max_live.fetch_max(live, Ordering::SeqCst);
        Ok(MockConn {
            state: self.state.clone(),
            latency: self.latency,
        })
    }
}

impl TargetConn for MockConn {
    async fn query(&mut self, sql: &str) -> Result<(), TargetError> {
        let n = self.state.queries.fetch_add(1, Ordering::SeqCst) + 1;
        let trigger = self.state.shutdown_after.load(Ordering::SeqCst);
        if trigger != 0 && n == trigger {
            if let Some(tx) = self.state.shutdown_tx.lock().unwrap().take() {
                let _ = tx.send(true);
            }
        }
        if !self.latency.is_zero() {
            tokio::time::sleep(self.latency).await;
        }
        if sql.contains("MOCK_FATAL") {
            return Err(TargetError {
                message: "mock fatal error".to_string(),
                fatal: true,
            });
        }
        if sql.contains("MOCK_FAIL") {
            return Err(TargetError {
                message: "mock error".to_string(),
                fatal: false,
            });
        }
        Ok(())
    }

    async fn disconnect(self) {}
}

/// Write a well-formed capture file from explicit events.
pub fn write_capture(path: &Path, events: &[Event]) {
    let mut w = CaptureWriter::create(path).expect("create capture");
    w.write(&Record::Header(Header {
        version: FORMAT_VERSION,
        tool_version: "test".to_string(),
        created_at: "2026-01-01T00:00:00Z".to_string(),
    }))
    .expect("write header");
    let mut sessions = std::collections::HashSet::new();
    let mut max_fp = 0;
    for e in events {
        sessions.insert(e.session_id);
        max_fp = max_fp.max(e.fingerprint_id);
        w.write(&Record::Event(e.clone())).expect("write event");
    }
    w.write(&Record::Summary(Summary {
        source_dialect: "test".to_string(),
        event_count: events.len() as u64,
        session_count: sessions.len() as u64,
        admin_commands_ignored: 0,
        server_restarts_seen: 0,
        fingerprints: (0..=max_fp)
            .map(|id| FingerprintEntry {
                id,
                text: format!("fingerprint {id}"),
            })
            .collect(),
    }))
    .expect("write summary");
    w.finish().expect("finish capture");
}

/// Stream a large synthetic capture to disk without materializing it:
/// `sessions` round-robin sessions, `events_per_session` events each,
/// timestamps advancing 1ms per event, `fp_count` fingerprint classes.
pub fn generate_capture(
    path: &Path,
    sessions: u64,
    events_per_session: u64,
    fp_count: u32,
) -> u64 {
    let total = sessions * events_per_session;
    let mut w = CaptureWriter::create(path).expect("create capture");
    w.write(&Record::Header(Header {
        version: FORMAT_VERSION,
        tool_version: "test".to_string(),
        created_at: "2026-01-01T00:00:00Z".to_string(),
    }))
    .expect("write header");
    for i in 0..total {
        let session_id = i % sessions + 1;
        let fp = (i % fp_count as u64) as u32;
        w.write(&Record::Event(Event {
            ts_micros: 1_700_000_000_000_000 + i as i64 * 1_000,
            session_id,
            user: Some("load".to_string()),
            db: Some("bench".to_string()),
            query: format!(
                "SELECT c1, c2, c3 FROM lineitem_{fp} WHERE order_id = {i} LIMIT 10"
            ),
            orig_query_time_s: 0.0001,
            fingerprint_id: fp,
        }))
        .expect("write event");
    }
    w.write(&Record::Summary(Summary {
        source_dialect: "test".to_string(),
        event_count: total,
        session_count: sessions,
        admin_commands_ignored: 0,
        server_restarts_seen: 0,
        fingerprints: (0..fp_count)
            .map(|id| FingerprintEntry {
                id,
                text: format!("select c?, c?, c? from lineitem_{id} where order_id = ? limit ?"),
            })
            .collect(),
    }))
    .expect("write summary");
    w.finish().expect("finish capture");
    total
}

/// A watch receiver that never fires (plus its kept-alive sender).
pub fn no_shutdown() -> (watch::Sender<bool>, watch::Receiver<bool>) {
    watch::channel(false)
}

pub fn temp_path(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("sql-replay-test-{}-{name}", std::process::id()))
}
