//! pcap-file ingestion for `capture --input traffic.pcap`.
//!
//! Reads a tcpdump/wireshark capture FILE (legacy pcap — micro- or
//! nanosecond — and pcap-ng; pure Rust via `pcap-parser`, no libpcap),
//! reassembles per-connection TCP streams on the MySQL port, and feeds
//! each connection's bytes to [`crate::mysqlproto::ConnDecoder`]. Layer
//! split: this module owns pcap framing, link/IP/TCP parsing, and stream
//! reassembly; `mysqlproto` owns the MySQL protocol. There is no live
//! capture — production traffic is recorded with plain tcpdump (see the
//! README) and parsed offline.
//!
//! Fidelity properties:
//! - The event timestamp is the pcap timestamp of the TCP segment that
//!   carried the first byte of the request — true wire arrival time, so
//!   replay pacing reproduces real concurrency.
//! - Request→first-response wall time is recorded as the event's original
//!   latency (`orig_query_time_s`), so `baseline` works on pcap captures
//!   too. Unlike the slow log's server-side `Query_time`, this includes
//!   the network path between capture point and server.
//! - Sessions are TCP connections; the session id is the server-assigned
//!   connection thread id from the handshake greeting (like the slow-log
//!   path), so the same workload captured both ways lines up.
//!
//! Failure honesty: TLS and compressed connections (opaque above the
//! handshake), connections whose handshake wasn't captured (mid-stream
//! starts), broken/oversized streams, truncated snaplen packets, and IP
//! fragments are all *counted* and reported in the capture summary —
//! never silently dropped.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::File;
use std::path::Path;

use anyhow::{bail, Context, Result};
use pcap_parser::{Block, PcapBlockOwned, PcapError};

use crate::mysqlproto::{ConnDecoder, Dir, Disposition, ProtoEvent};

pub const DEFAULT_MYSQL_PORT: u16 = 3306;

/// Per-direction cap on buffered out-of-order TCP data before the
/// connection is declared broken (a gap that large means the capture lost
/// packets wholesale).
const MAX_PENDING_BYTES: usize = 8 * 1024 * 1024;

/// Linktypes we can strip (pcap `network` field / pcap-ng IDB linktype).
mod linktype {
    pub const NULL: i32 = 0; // BSD loopback: 4-byte AF
    pub const ETHERNET: i32 = 1;
    pub const RAW: i32 = 101; // raw IP
    pub const LOOP: i32 = 108; // OpenBSD loopback: 4-byte AF (network order)
    pub const LINUX_SLL: i32 = 113; // tcpdump -i any (libpcap < 1.10)
    pub const LINUX_SLL2: i32 = 276; // tcpdump -i any (libpcap >= 1.10)
}

/// Decode counters, aggregated over the whole file and reported in the
/// capture summary (see `format::PcapSummary`).
#[derive(Debug, Default, Clone)]
pub struct PcapStats {
    /// Packets on the MySQL port (after link/IP/TCP parsing).
    pub packets: u64,
    /// Packets whose captured length is shorter than their wire length
    /// (snaplen cut the payload; capture with `-s 0`). The affected
    /// connection usually ends up broken or with missing responses.
    pub truncated_packets: u64,
    /// Non-first IP fragments (and first fragments of fragmented
    /// datagrams) — IP reassembly is not implemented; rare for MySQL
    /// traffic (TCP negotiates MSS below the MTU).
    pub ip_fragments_skipped: u64,
    /// TCP connections seen on the MySQL port.
    pub connections: u64,
    /// Connections fully decoded (may still have missing responses).
    pub connections_decoded: u64,
    /// Connections that negotiated TLS: everything after the handshake is
    /// opaque, no events can be extracted.
    pub connections_tls_skipped: u64,
    /// Connections that negotiated the compressed protocol.
    pub connections_compressed_skipped: u64,
    /// Connections whose handshake wasn't captured (capture started
    /// mid-connection) or that don't speak MySQL.
    pub connections_midstream_skipped: u64,
    /// Connections whose stream broke: MySQL framing overrun, or more than
    /// [`MAX_PENDING_BYTES`] of out-of-order data (lost packets).
    pub connections_broken: u64,
    /// COM_STMT_EXECUTEs expanded into SQL text.
    pub statements_expanded: u64,
    /// COM_STMT_EXECUTEs that could not be expanded (statement prepared
    /// before the capture started, unsupported parameter type, ...).
    pub statements_inexpandable: u64,
    /// Client commands that produce no event (ping, statistics, ...).
    pub commands_ignored: u64,
    /// Events whose response was never captured (latency recorded as 0).
    pub responses_missing: u64,
    /// Server version strings seen in handshake greetings.
    pub server_versions: Vec<String>,
}

impl PcapStats {
    /// Human-readable warning lines for everything that was skipped or
    /// lossy — printed to stderr by `capture` so data loss is visible.
    pub fn warnings(&self) -> Vec<String> {
        let mut out = Vec::new();
        let mut push = |n: u64, msg: &str| {
            if n > 0 {
                out.push(format!("{n} {msg}"));
            }
        };
        push(
            self.connections_tls_skipped,
            "connection(s) negotiated TLS and were skipped (TLS traffic is opaque; \
             capture on a plaintext segment or disable TLS for the capture window)",
        );
        push(
            self.connections_compressed_skipped,
            "connection(s) negotiated the compressed protocol and were skipped",
        );
        push(
            self.connections_midstream_skipped,
            "connection(s) started before the capture (handshake not seen) and were skipped",
        );
        push(
            self.connections_broken,
            "connection(s) had broken/incomplete streams and were only partially decoded",
        );
        push(
            self.truncated_packets,
            "packet(s) were truncated by the capture snaplen — capture with `-s 0`",
        );
        push(self.ip_fragments_skipped, "IP fragment(s) were skipped");
        push(
            self.statements_inexpandable,
            "prepared-statement execution(s) could not be expanded into SQL text \
             (statement prepared before the capture started, or unsupported \
             parameter encoding) and were dropped",
        );
        push(
            self.responses_missing,
            "statement(s) never got a captured response; their recorded latency is 0",
        );
        out
    }
}

/// `(address, port)`; v4 addresses are mapped into the 16-byte form.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
struct Endpoint {
    addr: [u8; 16],
    port: u16,
}

/// A tracked connection, keyed client→server.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
struct FlowKey {
    client: Endpoint,
    server: Endpoint,
}

/// One direction's TCP stream reassembler. Sequence numbers are mapped to
/// a 64-bit relative offset (`rel`) so wraparound and >4 GiB streams are
/// handled uniformly; out-of-order segments are buffered until the gap
/// fills, retransmissions and overlaps are trimmed.
struct SeqStream {
    started: bool,
    isn: u32,
    /// Relative offset of the next expected byte.
    next_rel: u64,
    /// Out-of-order segments by relative offset.
    pending: BTreeMap<u64, (i64, Vec<u8>)>,
    pending_bytes: usize,
    /// Out-of-order buffer overran [`MAX_PENDING_BYTES`].
    overflow: bool,
}

impl SeqStream {
    fn new() -> Self {
        SeqStream {
            started: false,
            isn: 0,
            next_rel: 0,
            pending: BTreeMap::new(),
            pending_bytes: 0,
            overflow: false,
        }
    }

    fn on_syn(&mut self, seq: u32) {
        // SYN consumes one sequence number; data starts at seq+1.
        self.isn = seq.wrapping_add(1);
        self.started = true;
        self.next_rel = 0;
        self.pending.clear();
        self.pending_bytes = 0;
    }

    /// Map an absolute sequence number to the relative offset closest to
    /// the current stream position (handles seq wraparound).
    fn rel(&self, seq: u32) -> u64 {
        let low = seq.wrapping_sub(self.isn) as u64;
        let base = self.next_rel;
        let k = base >> 32;
        let mut best = (k << 32) | low;
        for kk in [k.wrapping_sub(1), k.wrapping_add(1)] {
            let cand = (kk << 32) | low;
            if cand.abs_diff(base) < best.abs_diff(base) {
                best = cand;
            }
        }
        best
    }

    fn on_data(
        &mut self,
        ts_micros: i64,
        seq: u32,
        payload: &[u8],
        deliver: &mut dyn FnMut(i64, &[u8]),
    ) {
        if payload.is_empty() || self.overflow {
            return;
        }
        if !self.started {
            // Mid-stream start: treat this byte as the stream origin.
            self.isn = seq;
            self.started = true;
        }
        let rel = self.rel(seq);
        let end = rel + payload.len() as u64;
        if end <= self.next_rel {
            return; // pure retransmission
        }
        if rel <= self.next_rel {
            let skip = (self.next_rel - rel) as usize;
            deliver(ts_micros, &payload[skip..]);
            self.next_rel = end;
            self.drain(deliver);
        } else {
            // Out of order: buffer until the gap fills.
            if self.pending_bytes + payload.len() > MAX_PENDING_BYTES {
                self.overflow = true;
                self.pending.clear();
                self.pending_bytes = 0;
                return;
            }
            if let std::collections::btree_map::Entry::Vacant(v) = self.pending.entry(rel) {
                self.pending_bytes += payload.len();
                v.insert((ts_micros, payload.to_vec()));
            }
        }
    }

    fn drain(&mut self, deliver: &mut dyn FnMut(i64, &[u8])) {
        while let Some((&rel, _)) = self.pending.first_key_value() {
            if rel > self.next_rel {
                break;
            }
            let (rel, (ts, data)) = self.pending.pop_first().expect("checked non-empty");
            self.pending_bytes -= data.len();
            let end = rel + data.len() as u64;
            if end <= self.next_rel {
                continue; // fully covered by data already delivered
            }
            let skip = (self.next_rel - rel) as usize;
            deliver(ts, &data[skip..]);
            self.next_rel = end;
        }
    }
}

struct ConnState {
    dec: ConnDecoder,
    c2s: SeqStream,
    s2c: SeqStream,
    session_id: Option<u64>,
    fin_client: bool,
    fin_server: bool,
    /// Finished (FIN/RST/replaced); kept as a tombstone so late
    /// retransmissions don't respawn a phantom mid-stream connection.
    finished: bool,
    version_recorded: bool,
}

impl ConnState {
    fn new() -> Self {
        ConnState {
            dec: ConnDecoder::new(),
            c2s: SeqStream::new(),
            s2c: SeqStream::new(),
            session_id: None,
            fin_client: false,
            fin_server: false,
            finished: false,
            version_recorded: false,
        }
    }
}

/// The packet-level engine: fed parsed link-layer frames (by
/// [`scan_pcap_file`] or directly by tests), it emits `(session_id,
/// ProtoEvent)` pairs through the sink passed to each call.
pub struct PcapEngine {
    port: u16,
    conns: HashMap<FlowKey, ConnState>,
    /// Session ids already assigned; a server restart inside one capture
    /// can reuse thread ids, which must not merge two connections into one
    /// replay session.
    used_session_ids: HashSet<u64>,
    synthetic_next: u64,
    pub stats: PcapStats,
    evbuf: Vec<ProtoEvent>,
}

pub type EventSink<'a> = &'a mut dyn FnMut(u64, ProtoEvent);

impl PcapEngine {
    pub fn new(port: u16) -> Self {
        PcapEngine {
            port,
            conns: HashMap::new(),
            used_session_ids: HashSet::new(),
            // High bit set: out of the range MySQL thread ids (u32) live in.
            synthetic_next: 1 << 48,
            stats: PcapStats::default(),
            evbuf: Vec::new(),
        }
    }

    /// Feed one captured frame. `truncated` = the capture's snaplen cut
    /// the frame short (caplen < wire length).
    pub fn on_packet(
        &mut self,
        ts_micros: i64,
        linktype: i32,
        frame: &[u8],
        truncated: bool,
        sink: EventSink,
    ) {
        let Some(ip) = strip_link(linktype, frame) else {
            return;
        };
        let Some(seg) = parse_ip_tcp(ip) else {
            if is_ip_fragment(ip) {
                self.stats.ip_fragments_skipped += 1;
            }
            return;
        };

        // Direction from the server port. (If both ports equal the MySQL
        // port the sender is taken to be the server; real client sockets
        // use ephemeral ports.)
        let (key, dir) = if seg.src.port == self.port {
            (
                FlowKey {
                    client: seg.dst,
                    server: seg.src,
                },
                Dir::Server,
            )
        } else if seg.dst.port == self.port {
            (
                FlowKey {
                    client: seg.src,
                    server: seg.dst,
                },
                Dir::Client,
            )
        } else {
            return;
        };

        self.stats.packets += 1;
        if truncated {
            self.stats.truncated_packets += 1;
        }

        // A fresh SYN on a finished (tombstoned) 4-tuple means the port
        // pair is being reused for a new connection.
        let fresh_syn = seg.syn && !seg.ack && dir == Dir::Client;
        if fresh_syn && self.conns.get(&key).is_some_and(|c| c.finished) {
            self.conns.remove(&key);
        }

        let conn = match self.conns.entry(key) {
            std::collections::hash_map::Entry::Occupied(o) => o.into_mut(),
            std::collections::hash_map::Entry::Vacant(v) => {
                self.stats.connections += 1;
                v.insert(ConnState::new())
            }
        };
        if conn.finished {
            return;
        }

        if seg.syn {
            match dir {
                Dir::Client => conn.c2s.on_syn(seg.seq),
                Dir::Server => conn.s2c.on_syn(seg.seq),
            }
        }

        // Deliver reassembled bytes into the MySQL decoder.
        {
            let evbuf = &mut self.evbuf;
            let dec = &mut conn.dec;
            let stream = match dir {
                Dir::Client => &mut conn.c2s,
                Dir::Server => &mut conn.s2c,
            };
            stream.on_data(ts_micros, seg.seq, seg.payload, &mut |ts, bytes| {
                dec.on_data(dir, ts, bytes, evbuf);
            });
        }

        if !conn.version_recorded {
            if let Some(v) = conn.dec.server_version() {
                let v = v.to_string();
                conn.version_recorded = true;
                if !self.stats.server_versions.contains(&v) && self.stats.server_versions.len() < 8
                {
                    self.stats.server_versions.push(v);
                }
            }
        }

        match dir {
            Dir::Client => conn.fin_client |= seg.fin,
            Dir::Server => conn.fin_server |= seg.fin,
        }
        let closed = seg.rst || (conn.fin_client && conn.fin_server);
        // A non-Active disposition means the decoder gave up on the rest
        // of the stream; a reassembly-buffer overflow means the capture
        // lost packets beyond repair. Either way: flush, count, tombstone.
        let done_decoding =
            conn.dec.disposition() != Disposition::Active || conn.c2s.overflow || conn.s2c.overflow;

        if closed || done_decoding {
            let mut c = self.conns.remove(&key).expect("conn present");
            self.finalize(&mut c, sink);
            self.conns.insert(key, c); // tombstone
        } else {
            self.drain_events_at(&key, sink);
        }
    }

    /// End of file: flush every connection still in flight.
    pub fn finish(&mut self, sink: EventSink) {
        let keys: Vec<FlowKey> = self.conns.keys().copied().collect();
        for key in keys {
            let mut c = self.conns.remove(&key).expect("key just listed");
            self.finalize(&mut c, sink);
        }
    }

    /// Flush pending decoder state, emit remaining events, fold the
    /// connection's counters into the file totals, and mark it finished.
    fn finalize(&mut self, conn: &mut ConnState, sink: EventSink) {
        if conn.finished {
            return;
        }
        conn.finished = true;
        conn.dec.finish(&mut self.evbuf);
        self.drain_events(conn, sink);
        let lost_packets = conn.c2s.overflow || conn.s2c.overflow;
        match conn.dec.disposition() {
            Disposition::Active if lost_packets => self.stats.connections_broken += 1,
            Disposition::Active => self.stats.connections_decoded += 1,
            Disposition::Tls => self.stats.connections_tls_skipped += 1,
            Disposition::Compressed => self.stats.connections_compressed_skipped += 1,
            Disposition::BadHandshake => self.stats.connections_midstream_skipped += 1,
            Disposition::Broken => self.stats.connections_broken += 1,
        }
        self.accumulate(conn);
    }

    fn accumulate(&mut self, conn: &ConnState) {
        let s = &conn.dec.stats;
        self.stats.statements_expanded += s.statements_expanded;
        self.stats.statements_inexpandable += s.statements_inexpandable;
        self.stats.commands_ignored += s.commands_ignored;
        self.stats.responses_missing += s.responses_missing;
    }

    fn drain_events_at(&mut self, key: &FlowKey, sink: EventSink) {
        if self.evbuf.is_empty() {
            return;
        }
        let mut conn = self.conns.remove(key).expect("conn present");
        self.drain_events(&mut conn, sink);
        self.conns.insert(*key, conn);
    }

    fn drain_events(&mut self, conn: &mut ConnState, sink: EventSink) {
        if self.evbuf.is_empty() {
            return;
        }
        let sid = *conn.session_id.get_or_insert_with(|| {
            // Prefer the server-assigned thread id (matches the slow-log
            // path); fall back to a synthetic id on reuse across a server
            // restart mid-capture.
            let preferred = conn.dec.thread_id().map(u64::from);
            let id = match preferred {
                Some(t) if !self.used_session_ids.contains(&t) => t,
                _ => {
                    let id = self.synthetic_next;
                    self.synthetic_next += 1;
                    id
                }
            };
            self.used_session_ids.insert(id);
            id
        });
        for ev in self.evbuf.drain(..) {
            sink(sid, ev);
        }
    }
}

struct TcpSegment<'a> {
    src: Endpoint,
    dst: Endpoint,
    seq: u32,
    syn: bool,
    fin: bool,
    ack: bool,
    rst: bool,
    payload: &'a [u8],
}

fn v4mapped(a: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[10] = 0xff;
    out[11] = 0xff;
    out[12..16].copy_from_slice(&a[..4]);
    out
}

/// Strip the link-layer header, returning the IP datagram.
fn strip_link(linktype: i32, frame: &[u8]) -> Option<&[u8]> {
    match linktype {
        linktype::ETHERNET => {
            if frame.len() < 14 {
                return None;
            }
            let mut off = 12;
            let mut ethertype = u16::from_be_bytes([frame[off], frame[off + 1]]);
            // 802.1Q / QinQ VLAN tags.
            while ethertype == 0x8100 || ethertype == 0x88a8 {
                off += 4;
                if frame.len() < off + 2 {
                    return None;
                }
                ethertype = u16::from_be_bytes([frame[off], frame[off + 1]]);
            }
            match ethertype {
                0x0800 | 0x86dd => Some(&frame[off + 2..]),
                _ => None,
            }
        }
        linktype::LINUX_SLL => {
            // 16-byte header; protocol (ethertype) at offset 14.
            if frame.len() < 16 {
                return None;
            }
            match u16::from_be_bytes([frame[14], frame[15]]) {
                0x0800 | 0x86dd => Some(&frame[16..]),
                _ => None,
            }
        }
        linktype::LINUX_SLL2 => {
            // 20-byte header; protocol (ethertype) at offset 0.
            if frame.len() < 20 {
                return None;
            }
            match u16::from_be_bytes([frame[0], frame[1]]) {
                0x0800 | 0x86dd => Some(&frame[20..]),
                _ => None,
            }
        }
        linktype::RAW => Some(frame),
        linktype::NULL | linktype::LOOP => {
            // 4-byte address family; byte order varies by writer, so accept
            // AF_INET/AF_INET6 spellings in either.
            if frame.len() < 4 {
                return None;
            }
            Some(&frame[4..])
        }
        _ => None,
    }
}

/// True when the datagram is an IPv4 fragment (offset != 0 or MF set) or
/// an IPv6 datagram with a fragment header.
fn is_ip_fragment(ip: &[u8]) -> bool {
    match ip.first().map(|b| b >> 4) {
        Some(4) if ip.len() >= 8 => {
            let frag = u16::from_be_bytes([ip[6], ip[7]]);
            frag & 0x3fff != 0 // MF flag or nonzero offset
        }
        Some(6) if ip.len() >= 40 => ip[6] == 44,
        _ => false,
    }
}

/// Parse an IP datagram down to a TCP segment on any port.
fn parse_ip_tcp(ip: &[u8]) -> Option<TcpSegment<'_>> {
    let version = ip.first()? >> 4;
    let (src, dst, tcp) = match version {
        4 => {
            if ip.len() < 20 {
                return None;
            }
            let ihl = (ip[0] & 0x0f) as usize * 4;
            if ihl < 20 || ip.len() < ihl {
                return None;
            }
            let frag = u16::from_be_bytes([ip[6], ip[7]]);
            if frag & 0x3fff != 0 {
                return None; // fragment (counted by the caller)
            }
            if ip[9] != 6 {
                return None; // not TCP
            }
            // Trust the IP total length when the capture carried it all
            // (frames can be padded to the ethernet minimum).
            let total = u16::from_be_bytes([ip[2], ip[3]]) as usize;
            let end = if total >= ihl && total <= ip.len() {
                total
            } else {
                ip.len()
            };
            (v4mapped(&ip[12..16]), v4mapped(&ip[16..20]), &ip[ihl..end])
        }
        6 => {
            if ip.len() < 40 {
                return None;
            }
            let mut next = ip[6];
            let mut off = 40usize;
            // Walk the extension-header chain to the TCP header.
            loop {
                match next {
                    6 => break,
                    0 | 43 | 60 => {
                        if ip.len() < off + 8 {
                            return None;
                        }
                        next = ip[off];
                        off += (ip[off + 1] as usize + 1) * 8;
                    }
                    _ => return None, // fragment (44), ESP, ICMPv6, ...
                }
                if ip.len() < off {
                    return None;
                }
            }
            let payload_len = u16::from_be_bytes([ip[4], ip[5]]) as usize;
            let end = (40 + payload_len).min(ip.len());
            if end < off {
                return None;
            }
            let mut src = [0u8; 16];
            src.copy_from_slice(&ip[8..24]);
            let mut dst = [0u8; 16];
            dst.copy_from_slice(&ip[24..40]);
            (src, dst, &ip[off..end])
        }
        _ => return None,
    };

    if tcp.len() < 20 {
        return None;
    }
    let doff = (tcp[12] >> 4) as usize * 4;
    if doff < 20 || tcp.len() < doff {
        return None;
    }
    let flags = tcp[13];
    Some(TcpSegment {
        src: Endpoint {
            addr: src,
            port: u16::from_be_bytes([tcp[0], tcp[1]]),
        },
        dst: Endpoint {
            addr: dst,
            port: u16::from_be_bytes([tcp[2], tcp[3]]),
        },
        seq: u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]),
        fin: flags & 0x01 != 0,
        syn: flags & 0x02 != 0,
        rst: flags & 0x04 != 0,
        ack: flags & 0x10 != 0,
        payload: &tcp[doff..],
    })
}

/// Stream every MySQL statement out of a pcap/pcap-ng file. `on_event`
/// receives `(session_id, event)` pairs in decode order (within a session:
/// capture order). Returns the aggregated stats.
pub fn scan_pcap_file(
    path: &Path,
    port: u16,
    mut on_event: impl FnMut(u64, ProtoEvent) -> Result<()>,
) -> Result<PcapStats> {
    let file =
        File::open(path).with_context(|| format!("cannot open pcap file {}", path.display()))?;
    let mut buffer_cap: usize = 1 << 20;
    let mut reader = pcap_parser::create_reader(buffer_cap, file)
        .map_err(|e| anyhow::anyhow!("not a pcap/pcap-ng file: {e:?}"))?;

    let mut engine = PcapEngine::new(port);
    // Legacy header state.
    let mut legacy_linktype: i32 = linktype::ETHERNET;
    let mut legacy_nanos = false;
    // pcap-ng per-interface state (reset per section): (linktype, units/s,
    // ts offset in seconds).
    let mut ng_ifaces: Vec<(i32, u64, i64)> = Vec::new();

    let mut sink_err: Option<anyhow::Error> = None;
    {
        let mut sink = |sid: u64, ev: ProtoEvent| {
            if sink_err.is_none() {
                if let Err(e) = on_event(sid, ev) {
                    sink_err = Some(e);
                }
            }
        };

        loop {
            match reader.next() {
                Ok((offset, block)) => {
                    match block {
                        PcapBlockOwned::LegacyHeader(h) => {
                            legacy_linktype = h.network.0;
                            legacy_nanos = h.is_nanosecond_precision();
                        }
                        PcapBlockOwned::Legacy(p) => {
                            let sub_micros = if legacy_nanos {
                                (p.ts_usec / 1000) as i64
                            } else {
                                p.ts_usec as i64
                            };
                            let ts = p.ts_sec as i64 * 1_000_000 + sub_micros;
                            let truncated = p.caplen < p.origlen;
                            engine.on_packet(ts, legacy_linktype, p.data, truncated, &mut sink);
                        }
                        PcapBlockOwned::NG(Block::SectionHeader(_)) => ng_ifaces.clear(),
                        PcapBlockOwned::NG(Block::InterfaceDescription(idb)) => {
                            ng_ifaces.push((
                                idb.linktype.0,
                                idb.ts_resolution().unwrap_or(1_000_000),
                                idb.if_tsoffset,
                            ));
                        }
                        PcapBlockOwned::NG(Block::EnhancedPacket(ep)) => {
                            let Some(&(lt, resol, tsoff)) = ng_ifaces.get(ep.if_id as usize) else {
                                reader.consume(offset);
                                continue;
                            };
                            let units = ((ep.ts_high as u64) << 32) | ep.ts_low as u64;
                            let ts = (units as u128 * 1_000_000 / resol.max(1) as u128) as i64
                                + tsoff * 1_000_000;
                            let data = &ep.data[..(ep.caplen as usize).min(ep.data.len())];
                            let truncated = ep.caplen < ep.origlen;
                            engine.on_packet(ts, lt, data, truncated, &mut sink);
                        }
                        // SimplePacket has no timestamp; tcpdump never
                        // writes it. Other NG blocks carry no packets.
                        PcapBlockOwned::NG(_) => {}
                    }
                    reader.consume(offset);
                }
                Err(PcapError::Eof) => break,
                Err(PcapError::UnexpectedEof) => {
                    // Truncated file (capture cut mid-packet): keep what
                    // decoded; the missing tail shows up in the
                    // responses-missing / broken counters.
                    tracing::warn!("pcap file ends mid-packet (truncated capture)");
                    break;
                }
                Err(PcapError::Incomplete(_)) => {
                    if reader.reader_exhausted() {
                        tracing::warn!("pcap file ends mid-packet (truncated capture)");
                        break;
                    }
                    reader
                        .refill()
                        .map_err(|e| anyhow::anyhow!("pcap read error: {e:?}"))?;
                }
                Err(PcapError::BufferTooSmall) => {
                    // A single record larger than the read buffer (jumbo
                    // frames captured with -s 0 can exceed the default).
                    buffer_cap *= 2;
                    if buffer_cap > 1 << 30 || !reader.grow(buffer_cap) {
                        bail!("pcap record larger than the 1 GiB read-buffer cap");
                    }
                }
                Err(e) => bail!("malformed pcap file {}: {e:?}", path.display()),
            }
        }
        engine.finish(&mut sink);
    }
    if let Some(e) = sink_err {
        return Err(e);
    }
    Ok(engine.stats)
}

/// True when the file starts with a pcap or pcap-ng magic number.
pub fn looks_like_pcap(path: &Path) -> bool {
    let Ok(mut f) = File::open(path) else {
        return false;
    };
    let mut magic = [0u8; 4];
    if std::io::Read::read_exact(&mut f, &mut magic).is_err() {
        return false;
    }
    matches!(
        magic,
        // Legacy pcap: micro/nanosecond, either byte order.
        [0xa1, 0xb2, 0xc3, 0xd4]
            | [0xd4, 0xc3, 0xb2, 0xa1]
            | [0xa1, 0xb2, 0x3c, 0x4d]
            | [0x4d, 0x3c, 0xb2, 0xa1]
            // pcap-ng section header block.
            | [0x0a, 0x0d, 0x0d, 0x0a]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- frame builders (hand-built fixtures) ----

    const CLIENT: [u8; 4] = [10, 0, 0, 1];
    const SERVER: [u8; 4] = [10, 0, 0, 2];
    const CLIENT_PORT: u16 = 43210;

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
        tcp.extend_from_slice(&0u32.to_be_bytes()); // ack
        tcp.push(5 << 4); // data offset 20
        tcp.push(flags);
        tcp.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // window, cksum, urg
        tcp.extend_from_slice(payload);

        let total = 20 + tcp.len();
        let mut ip = Vec::new();
        ip.push(0x45);
        ip.push(0);
        ip.extend_from_slice(&(total as u16).to_be_bytes());
        ip.extend_from_slice(&[0, 0, 0, 0]); // id, frag
        ip.push(64); // ttl
        ip.push(6); // TCP
        ip.extend_from_slice(&[0, 0]); // cksum
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
    const RSTACK: u8 = 0x14;

    /// A scripted connection: builds MySQL wire bytes with the mysqlproto
    /// test helpers re-created here (raw packet framing only).
    fn mysql_packet(seq: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + payload.len());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes()[..3]);
        out.push(seq);
        out.extend_from_slice(payload);
        out
    }

    fn greeting_payload(version: &str, thread_id: u32) -> Vec<u8> {
        let mut p = vec![10u8];
        p.extend_from_slice(version.as_bytes());
        p.push(0);
        p.extend_from_slice(&thread_id.to_le_bytes());
        p.extend_from_slice(&[0u8; 30]);
        mysql_packet(0, &p)
    }

    fn login_payload(user: &str, db: &str) -> Vec<u8> {
        // CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CONNECT_WITH_DB
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

    fn ok_packet(seq: u8) -> Vec<u8> {
        mysql_packet(seq, &[0x00, 0, 0, 0, 0, 0, 0])
    }

    /// Drives an engine with a per-call incrementing timestamp.
    struct Driver {
        engine: PcapEngine,
        events: Vec<(u64, ProtoEvent)>,
        ts: i64,
        client_port: u16,
        c_seq: u32,
        s_seq: u32,
    }

    impl Driver {
        fn new() -> Self {
            Driver::with_port(3306, CLIENT_PORT)
        }

        fn with_port(server_port: u16, client_port: u16) -> Self {
            Driver {
                engine: PcapEngine::new(server_port),
                events: Vec::new(),
                ts: 1_700_000_000_000_000,
                client_port,
                c_seq: 1000,
                s_seq: 5000,
            }
        }

        fn feed(&mut self, frame: &[u8]) {
            self.ts += 1000;
            let ts = self.ts;
            let events = &mut self.events;
            self.engine
                .on_packet(ts, linktype::ETHERNET, frame, false, &mut |sid, ev| {
                    events.push((sid, ev))
                });
        }

        fn server_port(&self) -> u16 {
            self.engine.port
        }

        fn client_pkt(&mut self, flags: u8, payload: &[u8]) {
            let f = ipv4_tcp(
                CLIENT,
                self.client_port,
                SERVER,
                self.server_port(),
                self.c_seq,
                flags,
                payload,
            );
            self.c_seq = self
                .c_seq
                .wrapping_add(payload.len() as u32)
                .wrapping_add((flags & (SYN | 0x01) != 0) as u32);
            self.feed(&f);
        }

        fn server_pkt(&mut self, flags: u8, payload: &[u8]) {
            let f = ipv4_tcp(
                SERVER,
                self.server_port(),
                CLIENT,
                self.client_port,
                self.s_seq,
                flags,
                payload,
            );
            self.s_seq = self
                .s_seq
                .wrapping_add(payload.len() as u32)
                .wrapping_add((flags & (SYN | 0x01) != 0) as u32);
            self.feed(&f);
        }

        fn handshake(&mut self) {
            self.client_pkt(SYN, b"");
            self.server_pkt(SYNACK, b"");
            self.client_pkt(ACK, b"");
            let g = greeting_payload("8.0.36", 77);
            self.server_pkt(ACK, &g);
            let l = login_payload("app", "shop");
            self.client_pkt(ACK, &l);
            self.server_pkt(ACK, &ok_packet(2));
        }

        fn finish(&mut self) {
            let events = &mut self.events;
            self.engine.finish(&mut |sid, ev| events.push((sid, ev)));
        }
    }

    #[test]
    fn full_connection_decodes_with_latency_and_thread_id_session() {
        let mut d = Driver::new();
        d.handshake();
        d.client_pkt(ACK, &com_query("SELECT 1"));
        let req_ts = d.ts;
        d.server_pkt(ACK, &ok_packet(1));
        let resp_ts = d.ts;
        d.client_pkt(ACK, &mysql_packet(0, &[0x01])); // COM_QUIT
        d.client_pkt(FINACK, b"");
        d.server_pkt(FINACK, b"");
        d.finish();

        assert_eq!(d.events.len(), 1);
        let (sid, ev) = &d.events[0];
        assert_eq!(*sid, 77, "session id is the server thread id");
        assert_eq!(ev.query, "SELECT 1");
        assert_eq!(ev.ts_micros, req_ts);
        assert!(ev.response_seen);
        let expect = (resp_ts - req_ts) as f64 / 1_000_000.0;
        assert!((ev.latency_s - expect).abs() < 1e-9);
        assert_eq!(ev.db.as_deref(), Some("shop"));
        assert_eq!(ev.user.as_deref(), Some("app"));

        let s = &d.engine.stats;
        assert_eq!(s.connections, 1);
        assert_eq!(s.connections_decoded, 1);
        assert_eq!(s.connections_midstream_skipped, 0);
        assert_eq!(s.server_versions, vec!["8.0.36".to_string()]);
        assert!(s.warnings().is_empty());
    }

    #[test]
    fn out_of_order_and_retransmitted_segments_reassemble() {
        let mut d = Driver::new();
        d.handshake();

        // Send a query split into two segments, delivered reversed, with
        // the first segment retransmitted afterwards.
        let q = com_query("SELECT 'out of order'");
        let (a, b) = q.split_at(9);
        let seq0 = d.c_seq;
        let f_a = ipv4_tcp(CLIENT, CLIENT_PORT, SERVER, 3306, seq0, ACK, a);
        let f_b = ipv4_tcp(
            CLIENT,
            CLIENT_PORT,
            SERVER,
            3306,
            seq0 + a.len() as u32,
            ACK,
            b,
        );
        d.feed(&f_b); // out of order: buffered
        d.feed(&f_a); // gap fills, both deliver
        d.feed(&f_a); // pure retransmission: ignored
        d.c_seq = seq0.wrapping_add(q.len() as u32);
        d.server_pkt(ACK, &ok_packet(1));
        d.finish();

        assert_eq!(d.events.len(), 1);
        assert_eq!(d.events[0].1.query, "SELECT 'out of order'");
    }

    #[test]
    fn midstream_connection_is_counted_and_skipped() {
        let mut d = Driver::new();
        // No handshake captured: first thing seen is a query.
        d.client_pkt(ACK, &com_query("SELECT 1"));
        d.server_pkt(ACK, &ok_packet(1));
        d.finish();
        assert!(d.events.is_empty());
        assert_eq!(d.engine.stats.connections, 1);
        assert_eq!(d.engine.stats.connections_midstream_skipped, 1);
        assert_eq!(d.engine.stats.connections_decoded, 0);
        let w = d.engine.stats.warnings();
        assert!(w.iter().any(|w| w.contains("before the capture")), "{w:?}");
    }

    #[test]
    fn tls_connection_is_counted_and_skipped() {
        let mut d = Driver::new();
        d.client_pkt(SYN, b"");
        d.server_pkt(SYNACK, b"");
        let g = greeting_payload("8.0.36", 5);
        d.server_pkt(ACK, &g);
        // SSLRequest: caps only (PROTOCOL_41 | SSL), no user.
        let caps: u32 = 0x0200 | 0x0800;
        let mut p = Vec::new();
        p.extend_from_slice(&caps.to_le_bytes());
        p.extend_from_slice(&0u32.to_le_bytes());
        p.push(33);
        p.extend_from_slice(&[0u8; 23]);
        let ssl_req = mysql_packet(1, &p);
        d.client_pkt(ACK, &ssl_req);
        d.client_pkt(ACK, b"\x16\x03\x01 tls garbage");
        d.finish();
        assert!(d.events.is_empty());
        assert_eq!(d.engine.stats.connections_tls_skipped, 1);
        assert!(d.engine.stats.warnings().iter().any(|w| w.contains("TLS")));
    }

    #[test]
    fn missing_response_at_eof_yields_zero_latency_event() {
        let mut d = Driver::new();
        d.handshake();
        d.client_pkt(ACK, &com_query("SELECT SLEEP(60)"));
        d.finish(); // capture ends before the response
        assert_eq!(d.events.len(), 1);
        assert!(!d.events[0].1.response_seen);
        assert_eq!(d.events[0].1.latency_s, 0.0);
        assert_eq!(d.engine.stats.responses_missing, 1);
    }

    #[test]
    fn rst_closes_and_port_reuse_starts_a_new_session() {
        let mut d = Driver::new();
        d.handshake();
        d.client_pkt(ACK, &com_query("SELECT 1"));
        d.server_pkt(ACK, &ok_packet(1));
        d.client_pkt(RSTACK, b"");

        // Same 4-tuple, new connection (new SYN, new ISNs).
        d.c_seq = 90_000;
        d.s_seq = 40_000;
        d.client_pkt(SYN, b"");
        d.server_pkt(SYNACK, b"");
        let g = greeting_payload("8.0.36", 78);
        d.server_pkt(ACK, &g);
        let l = login_payload("app", "shop");
        d.client_pkt(ACK, &l);
        d.server_pkt(ACK, &ok_packet(2));
        d.client_pkt(ACK, &com_query("SELECT 2"));
        d.server_pkt(ACK, &ok_packet(1));
        d.finish();

        assert_eq!(d.events.len(), 2);
        assert_eq!(d.events[0].0, 77);
        assert_eq!(d.events[1].0, 78);
        assert_eq!(d.engine.stats.connections, 2);
        assert_eq!(d.engine.stats.connections_decoded, 2);
    }

    #[test]
    fn thread_id_reuse_after_restart_gets_a_synthetic_session_id() {
        let mut d = Driver::new();
        d.handshake();
        d.client_pkt(ACK, &com_query("SELECT 1"));
        d.server_pkt(ACK, &ok_packet(1));
        d.client_pkt(FINACK, b"");
        d.server_pkt(FINACK, b"");

        // New connection reusing thread id 77 (server restarted).
        d.c_seq = 90_000;
        d.s_seq = 40_000;
        d.client_pkt(SYN, b"");
        d.server_pkt(SYNACK, b"");
        let g = greeting_payload("8.0.37", 77);
        d.server_pkt(ACK, &g);
        let l = login_payload("app", "shop");
        d.client_pkt(ACK, &l);
        d.server_pkt(ACK, &ok_packet(2));
        d.client_pkt(ACK, &com_query("SELECT 2"));
        d.server_pkt(ACK, &ok_packet(1));
        d.finish();

        assert_eq!(d.events.len(), 2);
        assert_eq!(d.events[0].0, 77);
        assert!(d.events[1].0 >= 1 << 48, "synthetic id: {}", d.events[1].0);
        assert_ne!(d.events[0].0, d.events[1].0);
    }

    #[test]
    fn non_default_port_and_other_traffic_is_filtered() {
        let mut d = Driver::with_port(3307, CLIENT_PORT);
        // Traffic on 3306 is invisible when capturing for 3307.
        let noise = ipv4_tcp(CLIENT, 5555, SERVER, 3306, 1, SYN, b"");
        d.feed(&noise);
        assert_eq!(d.engine.stats.packets, 0);

        d.handshake(); // on 3307 now
        d.client_pkt(ACK, &com_query("SELECT 1"));
        d.server_pkt(ACK, &ok_packet(1));
        d.finish();
        assert_eq!(d.events.len(), 1);
    }

    #[test]
    fn truncated_packets_are_counted() {
        let mut d = Driver::new();
        d.handshake();
        let q = com_query("SELECT 1");
        let seq = d.c_seq;
        let f = ipv4_tcp(CLIENT, CLIENT_PORT, SERVER, 3306, seq, ACK, &q[..4]);
        // Simulate snaplen truncation: caplen < wire length.
        let events = &mut d.events;
        d.ts += 1000;
        d.engine
            .on_packet(d.ts, linktype::ETHERNET, &f, true, &mut |sid, ev| {
                events.push((sid, ev))
            });
        assert_eq!(d.engine.stats.truncated_packets, 1);
    }

    #[test]
    fn sll_and_sll2_and_raw_frames_strip() {
        // SLL: 16-byte header, ethertype at 14.
        let ip = ipv4_tcp(CLIENT, 1, SERVER, 2, 0, SYN, b"")[14..].to_vec();
        let mut sll = vec![0u8; 14];
        sll.extend_from_slice(&0x0800u16.to_be_bytes());
        sll.extend_from_slice(&ip);
        assert_eq!(strip_link(linktype::LINUX_SLL, &sll), Some(&ip[..]));

        // SLL2: 20-byte header, ethertype at 0.
        let mut sll2 = Vec::new();
        sll2.extend_from_slice(&0x0800u16.to_be_bytes());
        sll2.extend_from_slice(&[0u8; 18]);
        sll2.extend_from_slice(&ip);
        assert_eq!(strip_link(linktype::LINUX_SLL2, &sll2), Some(&ip[..]));

        assert_eq!(strip_link(linktype::RAW, &ip), Some(&ip[..]));

        // VLAN-tagged ethernet.
        let mut eth = vec![0u8; 12];
        eth.extend_from_slice(&0x8100u16.to_be_bytes());
        eth.extend_from_slice(&[0, 5]); // VLAN id
        eth.extend_from_slice(&0x0800u16.to_be_bytes());
        eth.extend_from_slice(&ip);
        assert_eq!(strip_link(linktype::ETHERNET, &eth), Some(&ip[..]));

        // Unknown linktype: dropped, not misparsed.
        assert_eq!(strip_link(147, &sll), None);
    }

    #[test]
    fn ip_fragments_are_counted_and_skipped() {
        let mut d = Driver::new();
        let mut f = ipv4_tcp(CLIENT, CLIENT_PORT, SERVER, 3306, 1, ACK, b"data");
        // Set the more-fragments flag in the IP header (offset 6 in IP =
        // offset 20 in the ethernet frame).
        f[20] = 0x20;
        d.feed(&f);
        assert_eq!(d.engine.stats.ip_fragments_skipped, 1);
        assert_eq!(d.engine.stats.packets, 0);
    }

    #[test]
    fn seq_wraparound_is_handled() {
        let mut s = SeqStream::new();
        s.on_syn(u32::MAX - 2); // data starts at u32::MAX - 1
        let mut got = Vec::new();
        let mut deliver = |_ts: i64, b: &[u8]| got.extend_from_slice(b);
        s.on_data(0, u32::MAX - 1, b"ab", &mut deliver); // crosses the wrap
        s.on_data(0, 0, b"cd", &mut deliver); // post-wrap continuation
        assert_eq!(got, b"abcd");
        assert_eq!(s.next_rel, 4);
    }

    #[test]
    fn overlapping_segments_are_trimmed() {
        let mut s = SeqStream::new();
        s.on_syn(99); // data starts at 100
        let mut got = Vec::new();
        let mut deliver = |_ts: i64, b: &[u8]| got.extend_from_slice(b);
        s.on_data(0, 100, b"hello ", &mut deliver);
        // Overlapping retransmission carrying new data at the tail.
        s.on_data(0, 103, b"lo world", &mut deliver);
        assert_eq!(got, b"hello world");
    }

    #[test]
    fn pending_overflow_marks_stream_broken() {
        let mut s = SeqStream::new();
        s.on_syn(0);
        let mut deliver = |_ts: i64, _b: &[u8]| {};
        // Never send byte 1, buffer past the cap.
        let chunk = vec![0u8; 1024 * 1024];
        for i in 0..9u32 {
            s.on_data(0, 1000 + i * 1024 * 1024, &chunk, &mut deliver);
        }
        assert!(s.overflow);
    }
}
