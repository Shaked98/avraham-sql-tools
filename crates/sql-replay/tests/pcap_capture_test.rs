//! End-to-end pcap ingestion: build deterministic .pcap files byte by
//! byte (no tcpdump needed), run them through `run_capture_pcap`, and
//! assert on the produced capture file — events, sessions, timestamps,
//! recorded latencies, and the honesty counters.

use std::path::Path;

use sql_replay::capture::run_capture_pcap;
use sql_replay::format::read_capture;

// ---- pcap file writer (legacy format, written by hand) ----

const MAGIC_MICROS: u32 = 0xa1b2_c3d4;
const MAGIC_NANOS: u32 = 0xa1b2_3c4d;
const LINKTYPE_ETHERNET: u32 = 1;

struct PcapWriter {
    bytes: Vec<u8>,
    nanos: bool,
}

impl PcapWriter {
    fn new(magic: u32, linktype: u32) -> Self {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&magic.to_le_bytes());
        bytes.extend_from_slice(&2u16.to_le_bytes()); // version major
        bytes.extend_from_slice(&4u16.to_le_bytes()); // version minor
        bytes.extend_from_slice(&0i32.to_le_bytes()); // thiszone
        bytes.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
        bytes.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
        bytes.extend_from_slice(&linktype.to_le_bytes());
        PcapWriter {
            bytes,
            nanos: magic == MAGIC_NANOS,
        }
    }

    fn packet(&mut self, ts_micros: i64, frame: &[u8]) {
        self.packet_truncated(ts_micros, frame, frame.len());
    }

    /// Write a record whose captured length is `caplen` (snaplen cut).
    fn packet_truncated(&mut self, ts_micros: i64, frame: &[u8], caplen: usize) {
        let sec = (ts_micros / 1_000_000) as u32;
        let sub = (ts_micros % 1_000_000) as u32;
        let sub = if self.nanos { sub * 1000 } else { sub };
        self.bytes.extend_from_slice(&sec.to_le_bytes());
        self.bytes.extend_from_slice(&sub.to_le_bytes());
        self.bytes.extend_from_slice(&(caplen as u32).to_le_bytes());
        self.bytes
            .extend_from_slice(&(frame.len() as u32).to_le_bytes());
        self.bytes.extend_from_slice(&frame[..caplen]);
    }

    fn write(&self, path: &Path) {
        std::fs::write(path, &self.bytes).expect("write pcap fixture");
    }
}

// ---- ethernet/IPv4/TCP frame builder ----

fn ipv4_tcp(
    src: [u8; 4],
    sport: u16,
    dst: [u8; 4],
    dport: u16,
    seq: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut tcp = Vec::new();
    tcp.extend_from_slice(&sport.to_be_bytes());
    tcp.extend_from_slice(&dport.to_be_bytes());
    tcp.extend_from_slice(&seq.to_be_bytes());
    tcp.extend_from_slice(&0u32.to_be_bytes());
    tcp.push(5 << 4);
    tcp.push(flags);
    tcp.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    tcp.extend_from_slice(payload);

    let total = 20 + tcp.len();
    let mut ip = Vec::new();
    ip.push(0x45);
    ip.push(0);
    ip.extend_from_slice(&(total as u16).to_be_bytes());
    ip.extend_from_slice(&[0, 0, 0, 0]);
    ip.push(64);
    ip.push(6);
    ip.extend_from_slice(&[0, 0]);
    ip.extend_from_slice(&src);
    ip.extend_from_slice(&dst);
    ip.extend_from_slice(&tcp);

    let mut eth = Vec::new();
    eth.extend_from_slice(&[0u8; 12]);
    eth.extend_from_slice(&0x0800u16.to_be_bytes());
    eth.extend_from_slice(&ip);
    eth
}

const SYN: u8 = 0x02;
const SYNACK: u8 = 0x12;
const ACK: u8 = 0x10;
const FINACK: u8 = 0x11;

// ---- MySQL wire bytes ----

fn mysql_packet(seq: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes()[..3]);
    out.push(seq);
    out.extend_from_slice(payload);
    out
}

fn greeting(version: &str, thread_id: u32) -> Vec<u8> {
    let mut p = vec![10u8];
    p.extend_from_slice(version.as_bytes());
    p.push(0);
    p.extend_from_slice(&thread_id.to_le_bytes());
    p.extend_from_slice(&[0u8; 30]);
    mysql_packet(0, &p)
}

fn login(user: &str, db: &str) -> Vec<u8> {
    // CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_CONNECT_WITH_DB
    let caps: u32 = 0x0200 | 0x8000 | 0x0008;
    let mut p = Vec::new();
    p.extend_from_slice(&caps.to_le_bytes());
    p.extend_from_slice(&0u32.to_le_bytes());
    p.push(33);
    p.extend_from_slice(&[0u8; 23]);
    p.extend_from_slice(user.as_bytes());
    p.push(0);
    p.push(0);
    p.extend_from_slice(db.as_bytes());
    p.push(0);
    mysql_packet(1, &p)
}

fn com_query(text: &str) -> Vec<u8> {
    let mut p = vec![0x03];
    p.extend_from_slice(text.as_bytes());
    mysql_packet(0, &p)
}

fn com_stmt_prepare(text: &str) -> Vec<u8> {
    let mut p = vec![0x16];
    p.extend_from_slice(text.as_bytes());
    mysql_packet(0, &p)
}

fn prepare_ok(stmt_id: u32, num_params: u16) -> Vec<u8> {
    let mut p = vec![0x00];
    p.extend_from_slice(&stmt_id.to_le_bytes());
    p.extend_from_slice(&0u16.to_le_bytes());
    p.extend_from_slice(&num_params.to_le_bytes());
    p.extend_from_slice(&[0, 0, 0]);
    mysql_packet(1, &p)
}

/// COM_STMT_EXECUTE with one i32 param (type LONG, new-params-bound).
fn com_stmt_execute_i32(stmt_id: u32, value: i32) -> Vec<u8> {
    let mut p = vec![0x17];
    p.extend_from_slice(&stmt_id.to_le_bytes());
    p.push(0);
    p.extend_from_slice(&1u32.to_le_bytes());
    p.push(0); // null bitmap (1 param)
    p.push(1); // new params bound
    p.push(0x03); // MYSQL_TYPE_LONG
    p.push(0);
    p.extend_from_slice(&value.to_le_bytes());
    mysql_packet(0, &p)
}

fn ok_packet(seq: u8) -> Vec<u8> {
    mysql_packet(seq, &[0x00, 0, 0, 0, 0, 0, 0])
}

const SERVER: [u8; 4] = [10, 0, 0, 2];

/// Scripts one client connection into pcap records.
struct Conn<'a> {
    w: &'a mut PcapWriter,
    client: [u8; 4],
    port: u16,
    c_seq: u32,
    s_seq: u32,
}

impl<'a> Conn<'a> {
    fn new(w: &'a mut PcapWriter, client_last_octet: u8, port: u16) -> Self {
        Conn {
            w,
            client: [10, 0, 0, client_last_octet],
            port,
            c_seq: 1_000,
            s_seq: 50_000,
        }
    }

    fn client_pkt(&mut self, ts: i64, flags: u8, payload: &[u8]) {
        let f = ipv4_tcp(
            self.client,
            self.port,
            SERVER,
            3306,
            self.c_seq,
            flags,
            payload,
        );
        self.c_seq += payload.len() as u32 + (flags & (SYN | 0x01) != 0) as u32;
        self.w.packet(ts, &f);
    }

    fn server_pkt(&mut self, ts: i64, flags: u8, payload: &[u8]) {
        let f = ipv4_tcp(
            SERVER,
            3306,
            self.client,
            self.port,
            self.s_seq,
            flags,
            payload,
        );
        self.s_seq += payload.len() as u32 + (flags & (SYN | 0x01) != 0) as u32;
        self.w.packet(ts, &f);
    }

    /// TCP + MySQL handshake, ending at `ts` (micros).
    fn handshake(&mut self, ts: i64, version: &str, thread_id: u32, user: &str, db: &str) {
        self.client_pkt(ts - 500, SYN, b"");
        self.server_pkt(ts - 400, SYNACK, b"");
        self.client_pkt(ts - 300, ACK, b"");
        let g = greeting(version, thread_id);
        self.server_pkt(ts - 200, ACK, &g);
        let l = login(user, db);
        self.client_pkt(ts - 100, ACK, &l);
        self.server_pkt(ts, ACK, &ok_packet(2));
    }

    fn close(&mut self, ts: i64) {
        self.client_pkt(ts, FINACK, b"");
        self.server_pkt(ts + 10, FINACK, b"");
    }
}

fn tmp(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join("sql-replay-pcap-tests");
    std::fs::create_dir_all(&dir).expect("mkdir");
    dir.join(format!("{}-{name}", std::process::id()))
}

/// Base capture timestamp: 2023-09-01 12:00:00 UTC in micros.
const T0: i64 = 1_693_569_600_000_000;

#[test]
fn pcap_file_to_capture_end_to_end() {
    let mut w = PcapWriter::new(MAGIC_MICROS, LINKTYPE_ETHERNET);

    // Session A: plain queries with known request→response latencies.
    let mut a = Conn::new(&mut w, 1, 40_001);
    a.handshake(T0, "8.0.36", 11, "app", "shop");
    a.client_pkt(T0 + 1_000_000, ACK, &com_query("SELECT 1"));
    a.server_pkt(T0 + 1_050_000, ACK, &ok_packet(1)); // 50ms
    a.client_pkt(
        T0 + 2_000_000,
        ACK,
        &com_query("SELECT * FROM t WHERE id = 7"),
    );
    a.server_pkt(T0 + 2_200_000, ACK, &ok_packet(1)); // 200ms
    a.close(T0 + 3_000_000);

    // Session B (interleaved in wire time): prepared statement, executed
    // twice with different parameter values.
    let mut b = Conn::new(&mut w, 2, 40_002);
    b.handshake(T0 + 500_000, "8.0.36", 12, "app", "shop");
    b.client_pkt(
        T0 + 1_500_000,
        ACK,
        &com_stmt_prepare("SELECT name FROM u WHERE id = ?"),
    );
    b.server_pkt(T0 + 1_510_000, ACK, &prepare_ok(1, 1));
    b.client_pkt(T0 + 1_600_000, ACK, &com_stmt_execute_i32(1, 42));
    b.server_pkt(T0 + 1_630_000, ACK, &ok_packet(1)); // 30ms
    b.client_pkt(T0 + 1_700_000, ACK, &com_stmt_execute_i32(1, -5));
    b.server_pkt(T0 + 1_740_000, ACK, &ok_packet(1)); // 40ms
    b.close(T0 + 2_500_000);

    let pcap_path = tmp("e2e.pcap");
    w.write(&pcap_path);
    let out = tmp("e2e.jsonl.zst");
    let summary = run_capture_pcap(&pcap_path, &out, 3306, None).expect("capture");

    assert_eq!(summary.event_count, 4);
    assert_eq!(summary.session_count, 2);
    assert_eq!(summary.source_dialect, "pcap:8.0.36");
    let p = summary.pcap.as_ref().expect("pcap summary present");
    assert_eq!(p.connections, 2);
    assert_eq!(p.connections_decoded, 2);
    assert_eq!(p.statements_expanded, 2);
    assert_eq!(p.statements_inexpandable, 0);
    assert_eq!(p.responses_missing, 0);
    assert_eq!(p.server_versions, vec!["8.0.36".to_string()]);

    let cap = read_capture(&out).expect("read capture back");
    let by_session = |sid: u64| -> Vec<&sql_replay::format::Event> {
        cap.events.iter().filter(|e| e.session_id == sid).collect()
    };

    let a_events = by_session(11);
    assert_eq!(a_events.len(), 2);
    assert_eq!(a_events[0].query, "SELECT 1");
    assert_eq!(a_events[0].ts_micros, T0 + 1_000_000);
    assert!((a_events[0].orig_query_time_s - 0.050).abs() < 1e-9);
    assert_eq!(a_events[1].query, "SELECT * FROM t WHERE id = 7");
    assert!((a_events[1].orig_query_time_s - 0.200).abs() < 1e-9);
    assert_eq!(a_events[0].db.as_deref(), Some("shop"));
    assert_eq!(a_events[0].user.as_deref(), Some("app"));

    let b_events = by_session(12);
    assert_eq!(b_events.len(), 2);
    assert_eq!(b_events[0].query, "SELECT name FROM u WHERE id = 42");
    assert_eq!(b_events[1].query, "SELECT name FROM u WHERE id = -5");
    assert!((b_events[0].orig_query_time_s - 0.030).abs() < 1e-9);
    // Both executes share one fingerprint.
    assert_eq!(b_events[0].fingerprint_id, b_events[1].fingerprint_id);
    assert_eq!(
        cap.summary.fingerprint_text(b_events[0].fingerprint_id),
        Some("select name from u where id = ?")
    );

    // The recorded latencies feed `baseline` directly.
    let report = sql_replay::baseline::build_baseline(&out, &Default::default())
        .expect("baseline from pcap capture");
    assert_eq!(report.totals.events, 4);
    assert_eq!(report.latency_source, "recorded-slow-log");
    let slow = report
        .fingerprints
        .iter()
        .find(|f| f.fingerprint.contains("from t"))
        .expect("SELECT * FROM t fingerprint");
    // hdrhistogram keeps 3 significant digits.
    assert!(
        (199_000..=201_000).contains(&slow.p95_us),
        "recorded 200ms latency lands in the baseline p95: {}",
        slow.p95_us
    );
}

#[test]
fn nanosecond_pcap_timestamps_convert() {
    let mut w = PcapWriter::new(MAGIC_NANOS, LINKTYPE_ETHERNET);
    let mut c = Conn::new(&mut w, 3, 40_003);
    c.handshake(T0, "5.7.44", 21, "app", "shop");
    c.client_pkt(T0 + 1_000_000, ACK, &com_query("SELECT 1"));
    c.server_pkt(T0 + 1_000_123, ACK, &ok_packet(1));
    let pcap_path = tmp("nanos.pcap");
    w.write(&pcap_path);
    let out = tmp("nanos.jsonl.zst");
    let summary = run_capture_pcap(&pcap_path, &out, 3306, None).expect("capture");
    assert_eq!(summary.event_count, 1);
    assert_eq!(summary.source_dialect, "pcap:5.7.44");
    let cap = read_capture(&out).expect("read");
    assert_eq!(cap.events[0].ts_micros, T0 + 1_000_000);
    assert!((cap.events[0].orig_query_time_s - 0.000123).abs() < 1e-9);
}

#[test]
fn truncated_pcap_file_keeps_decoded_prefix() {
    let mut w = PcapWriter::new(MAGIC_MICROS, LINKTYPE_ETHERNET);
    let mut c = Conn::new(&mut w, 4, 40_004);
    c.handshake(T0, "8.0.36", 31, "app", "shop");
    c.client_pkt(T0 + 1_000_000, ACK, &com_query("SELECT 1"));
    c.server_pkt(T0 + 1_010_000, ACK, &ok_packet(1));
    c.client_pkt(T0 + 2_000_000, ACK, &com_query("SELECT 2"));
    let full = w.bytes.clone();

    // Cut the file mid-record (the last packet's bytes are incomplete).
    let cut = full.len() - 10;
    let pcap_path = tmp("truncated.pcap");
    std::fs::write(&pcap_path, &full[..cut]).expect("write truncated");
    let out = tmp("truncated.jsonl.zst");
    let summary = run_capture_pcap(&pcap_path, &out, 3306, None).expect("capture survives");
    // SELECT 1 decoded; SELECT 2's packet was cut off entirely.
    assert_eq!(summary.event_count, 1);
    let cap = read_capture(&out).expect("read");
    assert_eq!(cap.events[0].query, "SELECT 1");
}

#[test]
fn snaplen_truncated_packets_are_counted_and_fail_soft() {
    let mut w = PcapWriter::new(MAGIC_MICROS, LINKTYPE_ETHERNET);
    let mut c = Conn::new(&mut w, 5, 40_005);
    c.handshake(T0, "8.0.36", 41, "app", "shop");
    // The query packet is snaplen-cut: only half its bytes captured.
    let q = com_query("SELECT 'a much longer query text here'");
    let f = ipv4_tcp(c.client, c.port, SERVER, 3306, c.c_seq, ACK, &q);
    c.w.packet_truncated(T0 + 1_000_000, &f, f.len() - 20);
    let pcap_path = tmp("snaplen.pcap");
    w.write(&pcap_path);
    let out = tmp("snaplen.jsonl.zst");
    let summary = run_capture_pcap(&pcap_path, &out, 3306, None).expect("capture");
    let p = summary.pcap.as_ref().expect("pcap summary");
    assert_eq!(p.truncated_packets, 1);
    // The half query never completes; no bogus event is emitted.
    assert_eq!(summary.event_count, 0);
}

#[test]
fn tls_connection_is_counted_in_summary() {
    let mut w = PcapWriter::new(MAGIC_MICROS, LINKTYPE_ETHERNET);
    let mut c = Conn::new(&mut w, 6, 40_006);
    c.client_pkt(T0, SYN, b"");
    c.server_pkt(T0 + 10, SYNACK, b"");
    let g = greeting("8.0.36", 51);
    c.server_pkt(T0 + 20, ACK, &g);
    // SSLRequest: caps only (PROTOCOL_41 | SSL).
    let caps: u32 = 0x0200 | 0x0800;
    let mut p = Vec::new();
    p.extend_from_slice(&caps.to_le_bytes());
    p.extend_from_slice(&0u32.to_le_bytes());
    p.push(33);
    p.extend_from_slice(&[0u8; 23]);
    let ssl_req = mysql_packet(1, &p);
    c.client_pkt(T0 + 30, ACK, &ssl_req);
    c.client_pkt(T0 + 40, ACK, b"\x16\x03\x01 opaque tls bytes");
    let pcap_path = tmp("tls.pcap");
    w.write(&pcap_path);
    let out = tmp("tls.jsonl.zst");
    let summary = run_capture_pcap(&pcap_path, &out, 3306, None).expect("capture");
    assert_eq!(summary.event_count, 0);
    let p = summary.pcap.as_ref().expect("pcap summary");
    assert_eq!(p.connections_tls_skipped, 1);
    assert_eq!(p.connections_decoded, 0);
}

#[test]
fn sink_error_stops_the_scan_and_propagates() {
    let mut w = PcapWriter::new(MAGIC_MICROS, LINKTYPE_ETHERNET);
    let mut c = Conn::new(&mut w, 9, 40_009);
    c.handshake(T0, "8.0.36", 71, "app", "shop");
    c.client_pkt(T0 + 1_000, ACK, &com_query("SELECT 1"));
    c.server_pkt(T0 + 2_000, ACK, &ok_packet(1));
    c.client_pkt(T0 + 3_000, ACK, &com_query("SELECT 2"));
    c.server_pkt(T0 + 4_000, ACK, &ok_packet(1));
    c.close(T0 + 5_000);
    let pcap_path = tmp("sink-err.pcap");
    w.write(&pcap_path);

    let mut calls = 0;
    let err = sql_replay::pcap::scan_pcap_file(&pcap_path, 3306, |_sid, _ev| {
        calls += 1;
        Err(anyhow::anyhow!("disk full"))
    })
    .expect_err("sink error must propagate");
    assert!(err.to_string().contains("disk full"));
    assert_eq!(calls, 1, "no events delivered after the sink failed");
}

#[test]
fn not_a_pcap_file_errors_and_slowlog_detection_works() {
    let path = tmp("not-a.pcap");
    std::fs::write(&path, b"# Time: 2023-09-01T12:00:00.000000Z\n").expect("write");
    assert!(!sql_replay::pcap::looks_like_pcap(&path));
    let out = tmp("not-a.jsonl.zst");
    assert!(run_capture_pcap(&path, &out, 3306, None).is_err());

    let mut w = PcapWriter::new(MAGIC_MICROS, LINKTYPE_ETHERNET);
    let mut c = Conn::new(&mut w, 7, 40_007);
    c.handshake(T0, "8.0.36", 61, "app", "shop");
    let pcap_path = tmp("magic.pcap");
    w.write(&pcap_path);
    assert!(sql_replay::pcap::looks_like_pcap(&pcap_path));
}
