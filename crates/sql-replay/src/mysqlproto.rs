//! MySQL client/server wire-protocol decoder for the pcap capture path.
//!
//! [`ConnDecoder`] is fed one connection's reassembled TCP payload bytes —
//! time-ordered chunks tagged with direction and the pcap timestamp of the
//! segment that carried them — and emits [`ProtoEvent`]s: one per client
//! statement, with the request packet's wire timestamp and the observed
//! request→first-response latency. It never sees pcap or TCP; `pcap.rs`
//! owns those layers, which keeps this module unit-testable against
//! hand-built packet bytes.
//!
//! Protocol facts this decoder is built on (its tests are the spec):
//!
//! - A MySQL packet is `3-byte LE length + 1-byte sequence id + payload`;
//!   a payload of 0xffffff bytes continues into the next packet.
//! - The sequence id resets to 0 for every client *command*, so in the
//!   command phase "client packet with seq 0" identifies a command and
//!   everything else from the client (auth continuations, LOCAL INFILE
//!   data) can be ignored. Mirrored on the server side: a response's
//!   first packet has seq 1, so "server packet with seq 1 that is not a
//!   continuation of the current response" starts a response — that
//!   timestamp closes the oldest in-flight request's latency window.
//! - The handshake is: server greeting (seq 0, protocol version 10, with
//!   the server version string and thread id), client handshake response
//!   (seq 1, capability flags + username + optional database), then an
//!   arbitrary auth exchange at higher seqs. TLS (`CLIENT_SSL`) and
//!   compression (`CLIENT_COMPRESS`/zstd) are negotiated via capability
//!   flags in the handshake response; both make everything after the
//!   handshake opaque to us, so such connections are skipped and counted.
//! - `COM_QUERY` carries plain text — unless `CLIENT_QUERY_ATTRIBUTES`
//!   was negotiated (mysql 8.x CLI does), in which case an attribute
//!   section precedes the text and must be skipped. Negotiated means set
//!   by *both* sides: the 8.x CLI sends the flag even to pre-8.0 servers
//!   whose greeting never advertised it, and then uses the plain form.
//! - `COM_STMT_PREPARE`'s response carries the statement id and parameter
//!   count; `COM_STMT_EXECUTE` carries binary-encoded parameter values,
//!   which are decoded and interpolated into the prepared SQL text
//!   (best-effort: statements with unknown ids, unsupported types, or
//!   placeholder mismatches are counted as inexpandable, never fatal).

use std::collections::{HashMap, VecDeque};

/// Client capability flags (subset we care about).
const CLIENT_CONNECT_WITH_DB: u32 = 0x0000_0008;
const CLIENT_COMPRESS: u32 = 0x0000_0020;
const CLIENT_PROTOCOL_41: u32 = 0x0000_0200;
const CLIENT_SSL: u32 = 0x0000_0800;
const CLIENT_SECURE_CONNECTION: u32 = 0x0000_8000;
const CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA: u32 = 1 << 21;
const CLIENT_ZSTD_COMPRESSION_ALGORITHM: u32 = 1 << 26;
const CLIENT_QUERY_ATTRIBUTES: u32 = 1 << 27;

/// COM_STMT_EXECUTE flag: a parameter count follows (8.0.23+, only with
/// CLIENT_QUERY_ATTRIBUTES).
const PARAMETER_COUNT_AVAILABLE: u8 = 0x08;

/// Command bytes.
const COM_QUIT: u8 = 0x01;
const COM_INIT_DB: u8 = 0x02;
const COM_QUERY: u8 = 0x03;
const COM_STMT_PREPARE: u8 = 0x16;
const COM_STMT_EXECUTE: u8 = 0x17;
const COM_STMT_SEND_LONG_DATA: u8 = 0x18;
const COM_STMT_CLOSE: u8 = 0x19;
const COM_STMT_RESET: u8 = 0x1a;

/// Hard cap on one logical packet's reassembled payload; beyond this the
/// connection is treated as broken rather than buffering unbounded data.
const MAX_LOGICAL_PACKET: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dir {
    Client,
    Server,
}

/// One decoded client statement.
#[derive(Debug, Clone)]
pub struct ProtoEvent {
    /// Wire timestamp of the request packet (its first TCP segment).
    pub ts_micros: i64,
    pub query: String,
    /// Request packet → first response packet, as observed on the wire
    /// (server processing + network). 0.0 when no response was captured.
    pub latency_s: f64,
    pub response_seen: bool,
    /// Default database at the time the statement was sent.
    pub db: Option<String>,
    pub user: Option<String>,
}

/// Why a connection stopped being decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Still decoding (or ended cleanly).
    Active,
    /// Client negotiated TLS: the rest of the stream is opaque.
    Tls,
    /// Client negotiated compression: the rest of the stream is opaque.
    Compressed,
    /// The handshake did not parse (e.g. capture started mid-connection,
    /// or the stream is not MySQL).
    BadHandshake,
    /// A logical packet overran [`MAX_LOGICAL_PACKET`] or framing broke.
    Broken,
}

/// Per-connection decode counters, aggregated into the capture summary.
#[derive(Debug, Default, Clone)]
pub struct ConnStats {
    /// COM_STMT_EXECUTEs successfully expanded into SQL text.
    pub statements_expanded: u64,
    /// COM_STMT_EXECUTEs dropped: unknown statement id (prepared before
    /// the capture started), unsupported parameter type, or a
    /// placeholder/parameter-count mismatch.
    pub statements_inexpandable: u64,
    /// Client commands that produce no event (ping, statistics, ...).
    pub commands_ignored: u64,
    /// Events whose response was never captured (latency recorded as 0).
    pub responses_missing: u64,
}

struct PreparedStmt {
    sql: String,
    num_params: u16,
    /// Parameter types from the last execute with new-params-bound = 1;
    /// later executes may reuse them (new-params-bound = 0).
    param_types: Option<Vec<(u8, u8)>>,
}

enum Pending {
    /// A statement event waiting for its first response packet.
    Event(ProtoEvent),
    /// COM_STMT_PREPARE waiting for the prepare-OK (stmt id, param count).
    Prepare { sql: String },
    /// A command with a response but no event (ping, reset, ...).
    Silent,
}

/// An in-flight request: the server's response to it starts at `resp_seq`
/// (the request's last packet seq + 1 — seq ids run per command/response
/// cycle, so this is usually 1 but higher after a multi-packet command).
struct InFlight {
    resp_seq: u8,
    pending: Pending,
}

#[derive(PartialEq)]
enum Phase {
    /// Waiting for the server greeting.
    Greeting,
    /// Waiting for the client handshake response.
    Login,
    /// Command phase (auth continuation packets are ignored by seq rule).
    Established,
}

/// Reassembles raw MySQL packets (and joins 0xffffff continuations) from
/// a stream of (timestamp, bytes) chunks. Each logical packet carries the
/// timestamp of the chunk that delivered its first byte.
struct PacketAssembler {
    buf: Vec<u8>,
    /// (stream offset, ts) marks for chunk starts; `consumed` is the
    /// stream offset of `buf[0]`.
    marks: VecDeque<(u64, i64)>,
    consumed: u64,
    /// In-progress multi-packet payload (previous fragment was 0xffffff).
    partial: Option<(u8, i64, Vec<u8>)>,
    broken: bool,
}

/// One logical (continuation-joined) MySQL packet.
struct LogicalPacket {
    first_seq: u8,
    last_seq: u8,
    ts_micros: i64,
    payload: Vec<u8>,
}

impl PacketAssembler {
    fn new() -> Self {
        PacketAssembler {
            buf: Vec::new(),
            marks: VecDeque::new(),
            consumed: 0,
            partial: None,
            broken: false,
        }
    }

    fn feed(&mut self, ts_micros: i64, data: &[u8], out: &mut Vec<LogicalPacket>) {
        if self.broken || data.is_empty() {
            return;
        }
        self.marks
            .push_back((self.consumed + self.buf.len() as u64, ts_micros));
        self.buf.extend_from_slice(data);

        let mut cursor = 0usize;
        loop {
            let rest = &self.buf[cursor..];
            if rest.len() < 4 {
                break;
            }
            let len = u32::from_le_bytes([rest[0], rest[1], rest[2], 0]) as usize;
            if rest.len() < 4 + len {
                break;
            }
            let seq = rest[3];
            let frag_offset = self.consumed + cursor as u64;
            let payload = &rest[4..4 + len];

            match self.partial.take() {
                Some((first_seq, ts, mut acc)) => {
                    if acc.len() + payload.len() > MAX_LOGICAL_PACKET {
                        self.broken = true;
                        return;
                    }
                    acc.extend_from_slice(payload);
                    if len == 0xff_ffff {
                        self.partial = Some((first_seq, ts, acc));
                    } else {
                        out.push(LogicalPacket {
                            first_seq,
                            last_seq: seq,
                            ts_micros: ts,
                            payload: acc,
                        });
                    }
                }
                None => {
                    let ts = self.ts_for(frag_offset);
                    if len == 0xff_ffff {
                        self.partial = Some((seq, ts, payload.to_vec()));
                    } else {
                        out.push(LogicalPacket {
                            first_seq: seq,
                            last_seq: seq,
                            ts_micros: ts,
                            payload: payload.to_vec(),
                        });
                    }
                }
            }
            cursor += 4 + len;
        }

        if cursor > 0 {
            self.buf.drain(..cursor);
            self.consumed += cursor as u64;
        }
        // Drop marks that no longer cover buffered bytes (keep the last
        // mark at or before the current front).
        while self.marks.len() > 1 && self.marks[1].0 <= self.consumed {
            self.marks.pop_front();
        }
        if self.buf.len() > MAX_LOGICAL_PACKET {
            self.broken = true;
        }
    }

    /// Timestamp of the chunk that delivered the byte at `offset`.
    fn ts_for(&self, offset: u64) -> i64 {
        let mut ts = 0;
        for &(o, t) in &self.marks {
            if o <= offset {
                ts = t;
            } else {
                break;
            }
        }
        ts
    }
}

pub struct ConnDecoder {
    phase: Phase,
    client: PacketAssembler,
    server: PacketAssembler,
    disposition: Disposition,
    /// Client capability flags from the handshake response.
    caps: u32,
    /// Server capability flags from the greeting.
    server_caps: u32,
    query_attrs: bool,
    user: Option<String>,
    db: Option<String>,
    server_version: Option<String>,
    thread_id: Option<u32>,
    stmts: HashMap<u32, PreparedStmt>,
    long_data: HashMap<(u32, u16), Vec<u8>>,
    pending: VecDeque<InFlight>,
    /// Expected seq of the next continuation packet of the current server
    /// response (handles seq wraparound in >255-packet responses).
    server_cont_seq: Option<u8>,
    pub stats: ConnStats,
    finished: bool,
}

impl ConnDecoder {
    pub fn new() -> Self {
        ConnDecoder {
            phase: Phase::Greeting,
            client: PacketAssembler::new(),
            server: PacketAssembler::new(),
            disposition: Disposition::Active,
            caps: 0,
            server_caps: 0,
            query_attrs: false,
            user: None,
            db: None,
            server_version: None,
            thread_id: None,
            stmts: HashMap::new(),
            long_data: HashMap::new(),
            pending: VecDeque::new(),
            server_cont_seq: None,
            stats: ConnStats::default(),
            finished: false,
        }
    }

    pub fn disposition(&self) -> Disposition {
        self.disposition
    }

    pub fn server_version(&self) -> Option<&str> {
        self.server_version.as_deref()
    }

    pub fn thread_id(&self) -> Option<u32> {
        self.thread_id
    }

    fn decoding(&self) -> bool {
        !self.finished && self.disposition == Disposition::Active
    }

    /// Feed one direction's reassembled bytes (in stream order; chunks
    /// across directions must arrive in wire-time order for latency to be
    /// meaningful). Decoded events are appended to `out`.
    pub fn on_data(&mut self, dir: Dir, ts_micros: i64, data: &[u8], out: &mut Vec<ProtoEvent>) {
        if !self.decoding() {
            return;
        }
        let mut packets = Vec::new();
        match dir {
            Dir::Client => self.client.feed(ts_micros, data, &mut packets),
            Dir::Server => self.server.feed(ts_micros, data, &mut packets),
        }
        if self.client.broken || self.server.broken {
            self.disposition = Disposition::Broken;
            return;
        }
        for pkt in packets {
            match dir {
                Dir::Client => self.on_client_packet(pkt),
                Dir::Server => self.on_server_packet(pkt, out),
            }
            if !self.decoding() {
                return;
            }
        }
    }

    /// The connection ended (FIN/RST/end of capture): flush in-flight
    /// requests as response-missing events.
    pub fn finish(&mut self, out: &mut Vec<ProtoEvent>) {
        if self.finished {
            return;
        }
        self.finished = true;
        for p in std::mem::take(&mut self.pending) {
            if let Pending::Event(mut ev) = p.pending {
                ev.response_seen = false;
                ev.latency_s = 0.0;
                self.stats.responses_missing += 1;
                out.push(ev);
            }
        }
    }

    fn on_server_packet(&mut self, pkt: LogicalPacket, out: &mut Vec<ProtoEvent>) {
        match self.phase {
            Phase::Greeting => {
                match parse_greeting(&pkt.payload) {
                    Some((version, thread_id, caps)) => {
                        self.server_version = Some(version);
                        self.thread_id = Some(thread_id);
                        self.server_caps = caps;
                        self.phase = Phase::Login;
                    }
                    None => self.disposition = Disposition::BadHandshake,
                };
            }
            Phase::Login => {
                // Server data before the client handshake response is out
                // of protocol order (or a mid-stream capture).
                self.disposition = Disposition::BadHandshake;
            }
            Phase::Established => {
                // Continuation of the current response? (Checked first so
                // a >255-packet response's wrapped seq is never mistaken
                // for a new response start.)
                if self.server_cont_seq == Some(pkt.first_seq) {
                    self.server_cont_seq = Some(pkt.last_seq.wrapping_add(1));
                    return;
                }
                if self
                    .pending
                    .front()
                    .is_none_or(|f| f.resp_seq != pkt.first_seq)
                {
                    // Auth-phase leftovers or a stray packet; not the
                    // start of the oldest in-flight request's response.
                    self.server_cont_seq = None;
                    return;
                }
                self.server_cont_seq = Some(pkt.last_seq.wrapping_add(1));
                let front = self.pending.pop_front().expect("checked above");
                match front.pending {
                    Pending::Event(mut ev) => {
                        ev.latency_s = ((pkt.ts_micros - ev.ts_micros).max(0)) as f64 / 1_000_000.0;
                        ev.response_seen = true;
                        out.push(ev);
                    }
                    Pending::Prepare { sql } => {
                        // Prepare-OK: status 0, stmt id, columns, params.
                        let p = &pkt.payload;
                        if p.len() >= 9 && p[0] == 0x00 {
                            let stmt_id = u32::from_le_bytes([p[1], p[2], p[3], p[4]]);
                            let num_params = u16::from_le_bytes([p[7], p[8]]);
                            self.stmts.insert(
                                stmt_id,
                                PreparedStmt {
                                    sql,
                                    num_params,
                                    param_types: None,
                                },
                            );
                        }
                        // ERR packet: the statement never existed; nothing
                        // to register.
                    }
                    Pending::Silent => {}
                }
            }
        }
    }

    fn on_client_packet(&mut self, pkt: LogicalPacket) {
        match self.phase {
            Phase::Greeting => {
                // Client data before any server greeting: mid-stream.
                self.disposition = Disposition::BadHandshake;
            }
            Phase::Login => self.on_login(&pkt),
            Phase::Established => {
                if pkt.first_seq != 0 {
                    // Auth continuation or LOCAL INFILE body.
                    return;
                }
                self.on_command(pkt);
            }
        }
    }

    fn on_login(&mut self, pkt: &LogicalPacket) {
        let p = &pkt.payload;
        if p.len() < 4 {
            self.disposition = Disposition::BadHandshake;
            return;
        }
        let caps = u32::from_le_bytes([p[0], p[1], p[2], p[3]]);
        if caps & CLIENT_PROTOCOL_41 == 0 {
            // Pre-4.1 handshake (or not a handshake at all).
            self.disposition = Disposition::BadHandshake;
            return;
        }
        if caps & CLIENT_SSL != 0 {
            self.disposition = Disposition::Tls;
            return;
        }
        if caps & (CLIENT_COMPRESS | CLIENT_ZSTD_COMPRESSION_ALGORITHM) != 0 {
            self.disposition = Disposition::Compressed;
            return;
        }
        self.caps = caps;
        // Effective capabilities are the intersection of both sides'.
        // The mysql 8.x CLI sends CLIENT_QUERY_ATTRIBUTES even to servers
        // that never advertised it (libmysqlclient only masks off
        // COMPRESS/SSL/PROTOCOL_41 against server caps) but then uses the
        // plain COM_QUERY form, so the client flag alone must not enable
        // attribute parsing.
        self.query_attrs = caps & self.server_caps & CLIENT_QUERY_ATTRIBUTES != 0;

        // Best-effort user/db extraction; failures leave them None but the
        // command phase still works.
        let mut r = Reader::new(p);
        r.skip(4 + 4 + 1 + 23); // caps, max packet, charset, filler
        if let Some(user) = r.cstring() {
            self.user = Some(String::from_utf8_lossy(user).into_owned());
            let auth_ok = if caps & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA != 0 {
                r.lenenc_bytes().is_some()
            } else if caps & CLIENT_SECURE_CONNECTION != 0 {
                r.u8().is_some_and(|n| r.take(n as usize).is_some())
            } else {
                r.cstring().is_some()
            };
            if auth_ok && caps & CLIENT_CONNECT_WITH_DB != 0 {
                if let Some(db) = r.cstring() {
                    if !db.is_empty() {
                        self.db = Some(String::from_utf8_lossy(db).into_owned());
                    }
                }
            }
        }
        self.phase = Phase::Established;
    }

    fn on_command(&mut self, pkt: LogicalPacket) {
        // A command with nothing in flight means the previous response is
        // over: drop its continuation seq, or a multi-packet command whose
        // resp_seq collides with it would have its response start swallowed
        // as a continuation.
        if self.pending.is_empty() {
            self.server_cont_seq = None;
        }
        // The response to this command starts at the command's last packet
        // seq + 1 (seq ids run per command/response cycle).
        let resp_seq = pkt.last_seq.wrapping_add(1);
        let p = &pkt.payload;
        let Some(&cmd) = p.first() else {
            return;
        };
        match cmd {
            COM_QUERY => match self.com_query_text(&p[1..]) {
                Some(text) => {
                    let query = String::from_utf8_lossy(&text).into_owned();
                    self.queue_event(resp_seq, pkt.ts_micros, query);
                }
                None => {
                    self.stats.commands_ignored += 1;
                    self.push_pending(resp_seq, Pending::Silent);
                }
            },
            COM_INIT_DB => {
                let db = String::from_utf8_lossy(&p[1..]).into_owned();
                let query = format!("USE `{}`", db.replace('`', "``"));
                self.db = Some(db);
                self.queue_event(resp_seq, pkt.ts_micros, query);
            }
            COM_STMT_PREPARE => {
                let sql = String::from_utf8_lossy(&p[1..]).into_owned();
                self.push_pending(resp_seq, Pending::Prepare { sql });
            }
            COM_STMT_EXECUTE => {
                match self.decode_execute(&p[1..]) {
                    Some(query) => {
                        self.stats.statements_expanded += 1;
                        self.queue_event(resp_seq, pkt.ts_micros, query);
                    }
                    None => {
                        self.stats.statements_inexpandable += 1;
                        // The server still responds; keep latency windows
                        // aligned.
                        self.push_pending(resp_seq, Pending::Silent);
                    }
                }
            }
            COM_STMT_SEND_LONG_DATA => {
                // stmt id (4), param id (2), data. No server response.
                if p.len() >= 7 {
                    let stmt_id = u32::from_le_bytes([p[1], p[2], p[3], p[4]]);
                    let param_id = u16::from_le_bytes([p[5], p[6]]);
                    self.long_data
                        .entry((stmt_id, param_id))
                        .or_default()
                        .extend_from_slice(&p[7..]);
                }
            }
            COM_STMT_CLOSE => {
                // No server response.
                if p.len() >= 5 {
                    let stmt_id = u32::from_le_bytes([p[1], p[2], p[3], p[4]]);
                    self.stmts.remove(&stmt_id);
                    self.long_data.retain(|(sid, _), _| *sid != stmt_id);
                }
            }
            COM_STMT_RESET => {
                if p.len() >= 5 {
                    let stmt_id = u32::from_le_bytes([p[1], p[2], p[3], p[4]]);
                    self.long_data.retain(|(sid, _), _| *sid != stmt_id);
                }
                self.push_pending(resp_seq, Pending::Silent);
            }
            COM_QUIT => {
                // Connection command; produces no event (mirrors the slow
                // log's `# administrator command: Quit`). No response.
                self.finished = true;
            }
            _ => {
                // Ping, statistics, field list, change user, ... — all
                // respond, none are statements.
                self.stats.commands_ignored += 1;
                self.push_pending(resp_seq, Pending::Silent);
            }
        }
    }

    fn push_pending(&mut self, resp_seq: u8, pending: Pending) {
        self.pending.push_back(InFlight { resp_seq, pending });
        // A new in-flight request means whatever response was streaming is
        // over as far as matching goes; matching keys off resp_seq anyway.
    }

    fn queue_event(&mut self, resp_seq: u8, ts_micros: i64, query: String) {
        // A client-issued USE also moves the session's default database
        // (mirroring the slow-log path, where it stays an event too).
        if let Some(db) = parse_use_target(&query) {
            self.db = Some(db);
        }
        self.push_pending(
            resp_seq,
            Pending::Event(ProtoEvent {
                ts_micros,
                query,
                latency_s: 0.0,
                response_seen: false,
                db: self.db.clone(),
                user: self.user.clone(),
            }),
        );
    }

    /// The SQL text of a COM_QUERY payload (command byte stripped),
    /// skipping the query-attribute section when the capability was
    /// negotiated. None when the attribute section fails to parse.
    fn com_query_text(&self, p: &[u8]) -> Option<Vec<u8>> {
        if !self.query_attrs {
            return Some(p.to_vec());
        }
        let mut r = Reader::new(p);
        let param_count = r.lenenc_int()? as usize;
        let _param_set_count = r.lenenc_int()?;
        if param_count > 0 {
            let null_bitmap = r.take(param_count.div_ceil(8))?.to_vec();
            let new_params_bound = r.u8()?;
            let mut types = Vec::with_capacity(param_count);
            if new_params_bound == 1 {
                for _ in 0..param_count {
                    let t = r.u8()?;
                    let f = r.u8()?;
                    // Attribute names are always present in this form.
                    let _name = r.lenenc_bytes()?;
                    types.push((t, f));
                }
            } else {
                // Attributes without types cannot be skipped reliably.
                return None;
            }
            for (i, &(t, f)) in types.iter().enumerate() {
                if null_bitmap[i / 8] & (1 << (i % 8)) != 0 {
                    continue;
                }
                decode_binary_value(&mut r, t, f)?;
            }
        }
        Some(r.rest().to_vec())
    }

    /// Expand a COM_STMT_EXECUTE payload (command byte stripped) into SQL
    /// text with parameter values interpolated. None = inexpandable.
    fn decode_execute(&mut self, p: &[u8]) -> Option<String> {
        let mut r = Reader::new(p);
        let stmt_id = u32::from_le_bytes(r.take(4)?.try_into().ok()?);
        let flags = r.u8()?;
        let _iterations = r.take(4)?;

        // Values must be decoded (and long data consumed) even if we end
        // up failing later, but failure only affects this statement.
        let stmt = self.stmts.get(&stmt_id)?;
        let num_params = stmt.num_params as usize;

        let mut param_count = num_params;
        if self.query_attrs && flags & PARAMETER_COUNT_AVAILABLE != 0 {
            param_count = r.lenenc_int()? as usize;
        }

        let mut values: Vec<String> = Vec::with_capacity(num_params);
        if param_count > 0 {
            let null_bitmap = r.take(param_count.div_ceil(8))?.to_vec();
            let new_params_bound = r.u8()?;
            let types: Vec<(u8, u8)> = if new_params_bound == 1 {
                let mut types = Vec::with_capacity(param_count);
                for i in 0..param_count {
                    let t = r.u8()?;
                    let f = r.u8()?;
                    if self.query_attrs && flags & PARAMETER_COUNT_AVAILABLE != 0 {
                        // Statement params have empty names; attributes
                        // (i >= num_params) carry theirs.
                        let _name = r.lenenc_bytes()?;
                    }
                    let _ = i;
                    types.push((t, f));
                }
                self.stmts
                    .get_mut(&stmt_id)
                    .expect("stmt looked up above")
                    .param_types = Some(types.clone());
                types
            } else {
                self.stmts.get(&stmt_id)?.param_types.clone()?
            };
            if types.len() < param_count {
                return None;
            }
            for (i, &(t, f)) in types.iter().enumerate().take(param_count) {
                if null_bitmap[i / 8] & (1 << (i % 8)) != 0 {
                    values.push("NULL".to_string());
                    continue;
                }
                if let Some(data) = self.long_data.get(&(stmt_id, i as u16)) {
                    // Sent via COM_STMT_SEND_LONG_DATA: the value is not
                    // in this packet.
                    values.push(bytes_literal(data));
                    continue;
                }
                values.push(decode_binary_value(&mut r, t, f)?);
            }
        }
        // Long data is consumed by execution.
        self.long_data.retain(|(sid, _), _| *sid != stmt_id);

        let stmt = self.stmts.get(&stmt_id)?;
        // Only the first num_params values are statement placeholders;
        // the rest (if any) are query attributes.
        interpolate(
            &stmt.sql,
            &values[..num_params.min(values.len())],
            num_params,
        )
    }
}

impl Default for ConnDecoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Server greeting: protocol version 10, server version (NUL-terminated),
/// thread id, and the server capability flags (best-effort: 0 bits for
/// anything past the end of a short greeting).
fn parse_greeting(p: &[u8]) -> Option<(String, u32, u32)> {
    if p.first() != Some(&10) {
        return None;
    }
    let mut r = Reader::new(&p[1..]);
    let version = r.cstring()?;
    let thread_id = u32::from_le_bytes(r.take(4)?.try_into().ok()?);
    // auth-plugin-data-part-1 (8) + filler (1), then the low capability
    // bytes; charset (1) + status (2) precede the high capability bytes.
    let mut caps = 0u32;
    r.skip(8 + 1);
    if let Some(low) = r.take(2) {
        caps |= u16::from_le_bytes(low.try_into().expect("2 bytes")) as u32;
        r.skip(1 + 2);
        if let Some(high) = r.take(2) {
            caps |= (u16::from_le_bytes(high.try_into().expect("2 bytes")) as u32) << 16;
        }
    }
    Some((
        String::from_utf8_lossy(version).into_owned(),
        thread_id,
        caps,
    ))
}

/// `USE dbname` / `USE \`dbname\`` → the database name.
fn parse_use_target(sql: &str) -> Option<String> {
    let rest = sql.trim().strip_suffix(';').unwrap_or(sql.trim()).trim();
    let (kw, target) = rest.split_once(char::is_whitespace)?;
    if !kw.eq_ignore_ascii_case("use") {
        return None;
    }
    let target = target.trim();
    let db = if let Some(inner) = target.strip_prefix('`') {
        inner.strip_suffix('`')?.replace("``", "`")
    } else {
        target.to_string()
    };
    (!db.is_empty()).then_some(db)
}

/// Little-endian byte reader with the MySQL length-encoded primitives.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }

    fn rest(&self) -> &'a [u8] {
        &self.data[self.pos..]
    }

    fn skip(&mut self, n: usize) {
        self.pos = (self.pos + n).min(self.data.len());
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.data.len() - self.pos < n {
            return None;
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Some(s)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|s| s[0])
    }

    fn cstring(&mut self) -> Option<&'a [u8]> {
        let rest = self.rest();
        let nul = rest.iter().position(|&b| b == 0)?;
        let s = &rest[..nul];
        self.pos += nul + 1;
        Some(s)
    }

    fn lenenc_int(&mut self) -> Option<u64> {
        match self.u8()? {
            n @ 0..=0xfa => Some(n as u64),
            0xfc => self
                .take(2)
                .map(|s| u16::from_le_bytes([s[0], s[1]]) as u64),
            0xfd => self
                .take(3)
                .map(|s| u32::from_le_bytes([s[0], s[1], s[2], 0]) as u64),
            0xfe => self
                .take(8)
                .map(|s| u64::from_le_bytes(s.try_into().expect("take(8)"))),
            _ => None, // 0xfb = NULL, 0xff = ERR: not an integer
        }
    }

    fn lenenc_bytes(&mut self) -> Option<&'a [u8]> {
        let n = self.lenenc_int()?;
        self.take(n as usize)
    }
}

/// MySQL binary-protocol field types (subset).
mod field_type {
    pub const DECIMAL: u8 = 0x00;
    pub const TINY: u8 = 0x01;
    pub const SHORT: u8 = 0x02;
    pub const LONG: u8 = 0x03;
    pub const FLOAT: u8 = 0x04;
    pub const DOUBLE: u8 = 0x05;
    pub const NULL: u8 = 0x06;
    pub const TIMESTAMP: u8 = 0x07;
    pub const LONGLONG: u8 = 0x08;
    pub const INT24: u8 = 0x09;
    pub const DATE: u8 = 0x0a;
    pub const TIME: u8 = 0x0b;
    pub const DATETIME: u8 = 0x0c;
    pub const YEAR: u8 = 0x0d;
    pub const VARCHAR: u8 = 0x0f;
    pub const BIT: u8 = 0x10;
    pub const JSON: u8 = 0xf5;
    pub const NEWDECIMAL: u8 = 0xf6;
    pub const ENUM: u8 = 0xf7;
    pub const SET: u8 = 0xf8;
    pub const TINY_BLOB: u8 = 0xf9;
    pub const MEDIUM_BLOB: u8 = 0xfa;
    pub const LONG_BLOB: u8 = 0xfb;
    pub const BLOB: u8 = 0xfc;
    pub const VAR_STRING: u8 = 0xfd;
    pub const STRING: u8 = 0xfe;
}

const UNSIGNED_FLAG: u8 = 0x80;

/// Decode one binary-protocol value into a SQL literal. None for types we
/// cannot render faithfully (the whole statement is then inexpandable).
fn decode_binary_value(r: &mut Reader<'_>, ftype: u8, flags: u8) -> Option<String> {
    use field_type as t;
    let unsigned = flags & UNSIGNED_FLAG != 0;
    match ftype {
        t::NULL => Some("NULL".to_string()),
        t::TINY => {
            let v = r.u8()?;
            Some(if unsigned {
                v.to_string()
            } else {
                (v as i8).to_string()
            })
        }
        t::SHORT | t::YEAR => {
            let b = r.take(2)?;
            let v = u16::from_le_bytes([b[0], b[1]]);
            Some(if unsigned {
                v.to_string()
            } else {
                (v as i16).to_string()
            })
        }
        t::LONG | t::INT24 => {
            let b = r.take(4)?;
            let v = u32::from_le_bytes(b.try_into().ok()?);
            Some(if unsigned {
                v.to_string()
            } else {
                (v as i32).to_string()
            })
        }
        t::LONGLONG => {
            let b = r.take(8)?;
            let v = u64::from_le_bytes(b.try_into().ok()?);
            Some(if unsigned {
                v.to_string()
            } else {
                (v as i64).to_string()
            })
        }
        t::FLOAT => {
            let b = r.take(4)?;
            let v = f32::from_le_bytes(b.try_into().ok()?);
            Some(float_literal(v as f64, v.to_string()))
        }
        t::DOUBLE => {
            let b = r.take(8)?;
            let v = f64::from_le_bytes(b.try_into().ok()?);
            Some(float_literal(v, v.to_string()))
        }
        t::DATE | t::DATETIME | t::TIMESTAMP => {
            let len = r.u8()? as usize;
            let b = r.take(len)?;
            match len {
                0 => Some("'0000-00-00 00:00:00'".to_string()),
                4 => Some(format!(
                    "'{:04}-{:02}-{:02}'",
                    u16::from_le_bytes([b[0], b[1]]),
                    b[2],
                    b[3]
                )),
                7 => Some(format!(
                    "'{:04}-{:02}-{:02} {:02}:{:02}:{:02}'",
                    u16::from_le_bytes([b[0], b[1]]),
                    b[2],
                    b[3],
                    b[4],
                    b[5],
                    b[6]
                )),
                11 => Some(format!(
                    "'{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:06}'",
                    u16::from_le_bytes([b[0], b[1]]),
                    b[2],
                    b[3],
                    b[4],
                    b[5],
                    b[6],
                    u32::from_le_bytes([b[7], b[8], b[9], b[10]])
                )),
                _ => None,
            }
        }
        t::TIME => {
            let len = r.u8()? as usize;
            let b = r.take(len)?;
            match len {
                0 => Some("'00:00:00'".to_string()),
                8 | 12 => {
                    let neg = if b[0] != 0 { "-" } else { "" };
                    let days = u32::from_le_bytes([b[1], b[2], b[3], b[4]]);
                    let hours = days * 24 + b[5] as u32;
                    let micros = if len == 12 {
                        format!(".{:06}", u32::from_le_bytes([b[8], b[9], b[10], b[11]]))
                    } else {
                        String::new()
                    };
                    Some(format!("'{neg}{hours:02}:{:02}:{:02}{micros}'", b[6], b[7]))
                }
                _ => None,
            }
        }
        t::DECIMAL | t::NEWDECIMAL => {
            let b = r.lenenc_bytes()?;
            let s = std::str::from_utf8(b).ok()?;
            // The wire value is a numeric string; emit it bare when it
            // looks like one, else fall back to a quoted literal.
            if !s.is_empty()
                && s.chars()
                    .all(|c| c.is_ascii_digit() || matches!(c, '-' | '+' | '.' | 'e' | 'E'))
            {
                Some(s.to_string())
            } else {
                Some(string_literal(s))
            }
        }
        t::BIT => {
            let b = r.lenenc_bytes()?;
            Some(format!("X'{}'", hex(b)))
        }
        t::VARCHAR
        | t::JSON
        | t::ENUM
        | t::SET
        | t::TINY_BLOB
        | t::MEDIUM_BLOB
        | t::LONG_BLOB
        | t::BLOB
        | t::VAR_STRING
        | t::STRING => {
            let b = r.lenenc_bytes()?;
            Some(bytes_literal(b))
        }
        _ => None, // GEOMETRY and anything unknown
    }
}

/// NaN/Infinity have no SQL literal; those statements are inexpandable.
fn float_literal(v: f64, formatted: String) -> String {
    if v.is_finite() {
        formatted
    } else {
        // Handled by the caller via placeholder-count mismatch? No: emit
        // NULL — MySQL cannot bind non-finite floats anyway, so this path
        // is unreachable from real captures; NULL keeps us total.
        "NULL".to_string()
    }
}

/// A byte value as a SQL literal: a quoted, escaped string when it is
/// valid UTF-8, else a hex literal (binary string).
fn bytes_literal(b: &[u8]) -> String {
    match std::str::from_utf8(b) {
        Ok(s) => string_literal(s),
        Err(_) => format!("X'{}'", hex(b)),
    }
}

fn string_literal(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        match c {
            '\'' => out.push_str("''"),
            '\\' => out.push_str("\\\\"),
            '\0' => out.push_str("\\0"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\x1a' => out.push_str("\\Z"),
            c => out.push(c),
        }
    }
    out.push('\'');
    out
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

/// Replace the `?` placeholders of `sql` (outside strings, comments, and
/// backtick identifiers) with `values`. None when the placeholder count
/// does not equal `expected` or values run short.
fn interpolate(sql: &str, values: &[String], expected: usize) -> Option<String> {
    let b = sql.as_bytes();
    let n = b.len();
    let mut out = String::with_capacity(sql.len() + values.iter().map(String::len).sum::<usize>());
    let mut i = 0;
    let mut used = 0;

    while i < n {
        match b[i] {
            q @ (b'\'' | b'"' | b'`') => {
                let start = i;
                i += 1;
                while i < n {
                    if b[i] == b'\\' && q != b'`' {
                        i = (i + 2).min(n);
                    } else if b[i] == q {
                        if i + 1 < n && b[i + 1] == q {
                            i += 2;
                        } else {
                            i += 1;
                            break;
                        }
                    } else {
                        i += 1;
                    }
                }
                out.push_str(&sql[start..i]);
            }
            b'-' if i + 1 < n
                && b[i + 1] == b'-'
                && (i + 2 >= n || b[i + 2].is_ascii_whitespace()) =>
            {
                let start = i;
                while i < n && b[i] != b'\n' {
                    i += 1;
                }
                out.push_str(&sql[start..i]);
            }
            b'#' => {
                let start = i;
                while i < n && b[i] != b'\n' {
                    i += 1;
                }
                out.push_str(&sql[start..i]);
            }
            b'/' if i + 1 < n && b[i + 1] == b'*' => {
                let start = i;
                i += 2;
                while i + 1 < n && !(b[i] == b'*' && b[i + 1] == b'/') {
                    i += 1;
                }
                i = (i + 2).min(n);
                out.push_str(&sql[start..i]);
            }
            b'?' => {
                out.push_str(values.get(used)?);
                used += 1;
                i += 1;
            }
            _ => {
                // Copy one whole UTF-8 sequence (lead byte + continuations).
                let start = i;
                i += 1;
                while i < n && b[i] & 0xc0 == 0x80 {
                    i += 1;
                }
                out.push_str(&sql[start..i]);
            }
        }
    }

    (used == expected).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- packet-building helpers (the hand-built fixtures) ----

    /// Raw MySQL packet: 3-byte LE length + seq + payload.
    fn packet(seq: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + payload.len());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes()[..3]);
        out.push(seq);
        out.extend_from_slice(payload);
        out
    }

    /// Greeting advertising every capability (a modern server); tests
    /// that negotiate a capability in `login` then get it end-to-end.
    fn greeting(version: &str, thread_id: u32) -> Vec<u8> {
        greeting_with_caps(version, thread_id, u32::MAX)
    }

    fn greeting_with_caps(version: &str, thread_id: u32, server_caps: u32) -> Vec<u8> {
        let mut p = vec![10u8];
        p.extend_from_slice(version.as_bytes());
        p.push(0);
        p.extend_from_slice(&thread_id.to_le_bytes());
        p.extend_from_slice(&[0u8; 8]); // auth-plugin-data-part-1
        p.push(0); // filler
        p.extend_from_slice(&(server_caps as u16).to_le_bytes());
        p.push(33); // charset
        p.extend_from_slice(&[0u8; 2]); // status flags
        p.extend_from_slice(&((server_caps >> 16) as u16).to_le_bytes());
        p.extend_from_slice(&[0u8; 11]); // auth data len + reserved
        packet(0, &p)
    }

    fn login(caps: u32, user: &str, db: Option<&str>) -> Vec<u8> {
        let mut caps = caps | CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION;
        if db.is_some() {
            caps |= CLIENT_CONNECT_WITH_DB;
        }
        let mut p = Vec::new();
        p.extend_from_slice(&caps.to_le_bytes());
        p.extend_from_slice(&0u32.to_le_bytes()); // max packet
        p.push(33); // charset
        p.extend_from_slice(&[0u8; 23]);
        p.extend_from_slice(user.as_bytes());
        p.push(0);
        p.push(0); // empty auth response (length-prefixed)
        if let Some(db) = db {
            p.extend_from_slice(db.as_bytes());
            p.push(0);
        }
        packet(1, &p)
    }

    fn com_query(text: &str) -> Vec<u8> {
        let mut p = vec![COM_QUERY];
        p.extend_from_slice(text.as_bytes());
        packet(0, &p)
    }

    /// COM_QUERY as sent when CLIENT_QUERY_ATTRIBUTES was negotiated with
    /// zero attributes (the mysql 8.x CLI form).
    fn com_query_attrs(text: &str) -> Vec<u8> {
        let mut p = vec![COM_QUERY, 0x00, 0x01];
        p.extend_from_slice(text.as_bytes());
        packet(0, &p)
    }

    fn ok_packet(seq: u8) -> Vec<u8> {
        packet(seq, &[0x00, 0, 0, 0, 0, 0, 0])
    }

    fn prepare_ok(stmt_id: u32, num_params: u16) -> Vec<u8> {
        let mut p = vec![0x00];
        p.extend_from_slice(&stmt_id.to_le_bytes());
        p.extend_from_slice(&0u16.to_le_bytes()); // num columns
        p.extend_from_slice(&num_params.to_le_bytes());
        p.extend_from_slice(&[0, 0, 0]); // filler + warnings
        packet(1, &p)
    }

    struct ExecBuilder {
        stmt_id: u32,
        types: Vec<(u8, u8)>,
        values: Vec<Vec<u8>>, // None encoded via null bitmap
        nulls: Vec<bool>,
    }

    impl ExecBuilder {
        fn new(stmt_id: u32) -> Self {
            ExecBuilder {
                stmt_id,
                types: Vec::new(),
                values: Vec::new(),
                nulls: Vec::new(),
            }
        }

        fn param(mut self, ftype: u8, flags: u8, bytes: &[u8]) -> Self {
            self.types.push((ftype, flags));
            self.values.push(bytes.to_vec());
            self.nulls.push(false);
            self
        }

        fn null_param(mut self, ftype: u8) -> Self {
            self.types.push((ftype, 0));
            self.values.push(Vec::new());
            self.nulls.push(true);
            self
        }

        fn build(self, new_params_bound: bool) -> Vec<u8> {
            let n = self.types.len();
            let mut p = vec![COM_STMT_EXECUTE];
            p.extend_from_slice(&self.stmt_id.to_le_bytes());
            p.push(0); // flags
            p.extend_from_slice(&1u32.to_le_bytes()); // iterations
            if n > 0 {
                let mut bitmap = vec![0u8; n.div_ceil(8)];
                for (i, &null) in self.nulls.iter().enumerate() {
                    if null {
                        bitmap[i / 8] |= 1 << (i % 8);
                    }
                }
                p.extend_from_slice(&bitmap);
                p.push(new_params_bound as u8);
                if new_params_bound {
                    for &(t, f) in &self.types {
                        p.push(t);
                        p.push(f);
                    }
                }
                for (i, v) in self.values.iter().enumerate() {
                    if !self.nulls[i] {
                        p.extend_from_slice(v);
                    }
                }
            }
            packet(0, &p)
        }
    }

    fn lenenc_str(s: &[u8]) -> Vec<u8> {
        assert!(s.len() < 251);
        let mut out = vec![s.len() as u8];
        out.extend_from_slice(s);
        out
    }

    // ---- a driver that mimics pcap.rs feeding the decoder ----

    struct Session {
        dec: ConnDecoder,
        events: Vec<ProtoEvent>,
        ts: i64,
    }

    impl Session {
        /// A connection already past greeting+login with the given caps.
        fn established(extra_caps: u32) -> Session {
            let mut s = Session {
                dec: ConnDecoder::new(),
                events: Vec::new(),
                ts: 1_000_000,
            };
            s.server(&greeting("8.0.36", 42));
            s.client(&login(extra_caps, "app", Some("shop")));
            s
        }

        fn client(&mut self, data: &[u8]) {
            self.ts += 1000;
            let ts = self.ts;
            self.dec.on_data(Dir::Client, ts, data, &mut self.events);
        }

        fn server(&mut self, data: &[u8]) {
            self.ts += 1000;
            let ts = self.ts;
            self.dec.on_data(Dir::Server, ts, data, &mut self.events);
        }

        fn finish(&mut self) {
            let mut out = std::mem::take(&mut self.events);
            self.dec.finish(&mut out);
            self.events = out;
        }
    }

    #[test]
    fn handshake_extracts_version_thread_user_and_db() {
        let s = Session::established(0);
        assert_eq!(s.dec.server_version(), Some("8.0.36"));
        assert_eq!(s.dec.thread_id(), Some(42));
        assert_eq!(s.dec.user.as_deref(), Some("app"));
        assert_eq!(s.dec.db.as_deref(), Some("shop"));
        assert_eq!(s.dec.disposition(), Disposition::Active);
    }

    #[test]
    fn com_query_roundtrip_with_latency() {
        let mut s = Session::established(0);
        s.client(&com_query("SELECT 1"));
        assert!(s.events.is_empty(), "no event until the response arrives");
        let req_ts = s.ts;
        s.server(&ok_packet(1));
        assert_eq!(s.events.len(), 1);
        let ev = &s.events[0];
        assert_eq!(ev.query, "SELECT 1");
        assert_eq!(ev.ts_micros, req_ts);
        assert!(ev.response_seen);
        // The driver advances 1000 µs per chunk.
        assert!((ev.latency_s - 0.001).abs() < 1e-9);
        assert_eq!(ev.db.as_deref(), Some("shop"));
        assert_eq!(ev.user.as_deref(), Some("app"));
    }

    #[test]
    fn query_attributes_form_is_stripped() {
        let mut s = Session::established(CLIENT_QUERY_ATTRIBUTES);
        s.client(&com_query_attrs("SELECT 2"));
        s.server(&ok_packet(1));
        assert_eq!(s.events[0].query, "SELECT 2");

        // With one attribute present: type LONG, name "a", value 7.
        let mut p = vec![COM_QUERY, 0x01, 0x01, 0x00, 0x01];
        p.push(field_type::LONG);
        p.push(0);
        p.extend_from_slice(&lenenc_str(b"a"));
        p.extend_from_slice(&7u32.to_le_bytes());
        p.extend_from_slice(b"SELECT 3");
        s.client(&packet(0, &p));
        s.server(&ok_packet(1));
        assert_eq!(s.events[1].query, "SELECT 3");
    }

    #[test]
    fn query_attrs_client_flag_without_server_support_stays_plain_text() {
        // The mysql 8.x CLI against a 5.7 server: the client's handshake
        // response still carries CLIENT_QUERY_ATTRIBUTES (libmysqlclient
        // doesn't mask it against server caps), but COM_QUERY uses the
        // plain form because the server never advertised the capability.
        let mut s = Session {
            dec: ConnDecoder::new(),
            events: Vec::new(),
            ts: 1_000_000,
        };
        s.server(&greeting_with_caps("5.7.44", 9, !CLIENT_QUERY_ATTRIBUTES));
        s.client(&login(CLIENT_QUERY_ATTRIBUTES, "root", None));
        // 5.7 also auth-switches this client to mysql_native_password;
        // with an empty password the switch response is a 0-byte packet.
        let mut switch = vec![0xfe];
        switch.extend_from_slice(b"mysql_native_password\0");
        switch.extend_from_slice(&[0u8; 21]);
        s.server(&packet(2, &switch));
        s.client(&packet(3, &[]));
        s.server(&ok_packet(4));
        s.client(&com_query("select @@version_comment limit 1"));
        s.server(&ok_packet(1));
        assert_eq!(s.dec.disposition(), Disposition::Active);
        assert_eq!(s.events.len(), 1);
        assert_eq!(s.events[0].query, "select @@version_comment limit 1");
        assert_eq!(s.dec.stats.commands_ignored, 0);
    }

    #[test]
    fn init_db_becomes_use_and_moves_the_default_db() {
        let mut s = Session::established(0);
        let mut p = vec![COM_INIT_DB];
        p.extend_from_slice(b"analytics");
        s.client(&packet(0, &p));
        s.server(&ok_packet(1));
        assert_eq!(s.events[0].query, "USE `analytics`");
        assert_eq!(s.events[0].db.as_deref(), Some("analytics"));
        // Later statements carry the new default db.
        s.client(&com_query("SELECT 1"));
        s.server(&ok_packet(1));
        assert_eq!(s.events[1].db.as_deref(), Some("analytics"));
    }

    #[test]
    fn client_use_statement_moves_the_default_db_too() {
        let mut s = Session::established(0);
        s.client(&com_query("USE `analytics`"));
        s.server(&ok_packet(1));
        s.client(&com_query("SELECT 1"));
        s.server(&ok_packet(1));
        assert_eq!(s.events[1].db.as_deref(), Some("analytics"));
    }

    #[test]
    fn prepare_execute_expands_typed_params() {
        let mut s = Session::established(0);
        s.client(&{
            let mut p = vec![COM_STMT_PREPARE];
            p.extend_from_slice(b"SELECT * FROM t WHERE a = ? AND b = ? AND c = ?");
            packet(0, &p)
        });
        s.server(&prepare_ok(5, 3));
        assert!(s.events.is_empty(), "prepare produces no event");

        let exec = ExecBuilder::new(5)
            .param(field_type::LONG, 0, &(-7i32).to_le_bytes())
            .param(field_type::VAR_STRING, 0, &lenenc_str(b"it's"))
            .param(field_type::DOUBLE, 0, &2.5f64.to_le_bytes())
            .build(true);
        s.client(&exec);
        s.server(&ok_packet(1));
        assert_eq!(
            s.events[0].query,
            "SELECT * FROM t WHERE a = -7 AND b = 'it''s' AND c = 2.5"
        );
        assert_eq!(s.dec.stats.statements_expanded, 1);

        // Second execute reuses the cached types (new_params_bound = 0).
        let exec = ExecBuilder::new(5)
            .param(field_type::LONG, 0, &12i32.to_le_bytes())
            .param(field_type::VAR_STRING, 0, &lenenc_str(b"x"))
            .param(field_type::DOUBLE, 0, &0.5f64.to_le_bytes())
            .build(false);
        s.client(&exec);
        s.server(&ok_packet(1));
        assert_eq!(
            s.events[1].query,
            "SELECT * FROM t WHERE a = 12 AND b = 'x' AND c = 0.5"
        );
    }

    #[test]
    fn execute_decodes_null_unsigned_temporal_decimal_and_binary() {
        let mut s = Session::established(0);
        s.client(&{
            let mut p = vec![COM_STMT_PREPARE];
            p.extend_from_slice(b"INSERT INTO t VALUES (?, ?, ?, ?, ?, ?)");
            packet(0, &p)
        });
        s.server(&prepare_ok(1, 6));

        let datetime7 = {
            let mut b = vec![7u8];
            b.extend_from_slice(&2024u16.to_le_bytes());
            b.extend_from_slice(&[3, 9, 14, 30, 5]);
            b
        };
        let time8 = {
            // -(1 day + 2:03:04)
            let mut b = vec![8u8, 1];
            b.extend_from_slice(&1u32.to_le_bytes());
            b.extend_from_slice(&[2, 3, 4]);
            b
        };
        let exec = ExecBuilder::new(1)
            .null_param(field_type::VAR_STRING)
            .param(field_type::LONGLONG, UNSIGNED_FLAG, &u64::MAX.to_le_bytes())
            .param(field_type::DATETIME, 0, &datetime7)
            .param(field_type::TIME, 0, &time8)
            .param(field_type::NEWDECIMAL, 0, &lenenc_str(b"12.34"))
            .param(field_type::BLOB, 0, &lenenc_str(&[0xff, 0x00, 0x7f]))
            .build(true);
        s.client(&exec);
        s.server(&ok_packet(1));
        assert_eq!(
            s.events[0].query,
            format!(
                "INSERT INTO t VALUES (NULL, {}, '2024-03-09 14:30:05', '-26:03:04', 12.34, X'FF007F')",
                u64::MAX
            )
        );
    }

    #[test]
    fn execute_of_unknown_stmt_is_counted_inexpandable() {
        let mut s = Session::established(0);
        // Statement id 99 was prepared before the capture started.
        let exec = ExecBuilder::new(99)
            .param(field_type::LONG, 0, &1i32.to_le_bytes())
            .build(true);
        s.client(&exec);
        s.server(&ok_packet(1));
        assert!(s.events.is_empty());
        assert_eq!(s.dec.stats.statements_inexpandable, 1);
        // Latency windows stay aligned for the next statement.
        s.client(&com_query("SELECT 1"));
        s.server(&ok_packet(1));
        assert_eq!(s.events.len(), 1);
        assert!(s.events[0].response_seen);
    }

    #[test]
    fn long_data_params_are_inlined() {
        let mut s = Session::established(0);
        s.client(&{
            let mut p = vec![COM_STMT_PREPARE];
            p.extend_from_slice(b"INSERT INTO t VALUES (?, ?)");
            packet(0, &p)
        });
        s.server(&prepare_ok(2, 2));
        // Param 1 arrives via COM_STMT_SEND_LONG_DATA in two chunks.
        let mut ld = vec![COM_STMT_SEND_LONG_DATA];
        ld.extend_from_slice(&2u32.to_le_bytes());
        ld.extend_from_slice(&1u16.to_le_bytes());
        ld.extend_from_slice(b"hello ");
        s.client(&packet(0, &ld));
        let mut ld = vec![COM_STMT_SEND_LONG_DATA];
        ld.extend_from_slice(&2u32.to_le_bytes());
        ld.extend_from_slice(&1u16.to_le_bytes());
        ld.extend_from_slice(b"world");
        s.client(&packet(0, &ld));

        let exec = ExecBuilder::new(2)
            .param(field_type::LONG, 0, &5i32.to_le_bytes())
            .param(field_type::LONG_BLOB, 0, &[]) // value came via long data
            .build(true);
        s.client(&exec);
        s.server(&ok_packet(1));
        assert_eq!(s.events[0].query, "INSERT INTO t VALUES (5, 'hello world')");
    }

    #[test]
    fn placeholders_inside_literals_are_not_substituted() {
        assert_eq!(
            interpolate("SELECT '?', `a?b`, ? -- ? trailing", &["1".into()], 1).unwrap(),
            "SELECT '?', `a?b`, 1 -- ? trailing"
        );
        assert_eq!(
            interpolate("SELECT /* ? */ ?", &["'x'".into()], 1).unwrap(),
            "SELECT /* ? */ 'x'"
        );
        // Placeholder-count mismatches are inexpandable, not misexpanded.
        assert!(interpolate("SELECT ?", &["1".into()], 2).is_none());
        assert!(interpolate("SELECT ?, ?", &["1".into()], 1).is_none());
        // Multi-byte text survives.
        assert_eq!(
            interpolate("SELECT ? /* 日本語 */", &["1".into()], 1).unwrap(),
            "SELECT 1 /* 日本語 */"
        );
    }

    #[test]
    fn tls_and_compressed_connections_are_skipped() {
        let mut s = Session {
            dec: ConnDecoder::new(),
            events: Vec::new(),
            ts: 0,
        };
        s.server(&greeting("8.0.36", 1));
        // SSLRequest: caps only, no user.
        let mut p = Vec::new();
        p.extend_from_slice(&(CLIENT_PROTOCOL_41 | CLIENT_SSL).to_le_bytes());
        p.extend_from_slice(&0u32.to_le_bytes());
        p.push(33);
        p.extend_from_slice(&[0u8; 23]);
        s.client(&packet(1, &p));
        assert_eq!(s.dec.disposition(), Disposition::Tls);
        // Everything after is ignored without panicking.
        s.client(b"\x16\x03\x01garbage tls bytes");
        assert!(s.events.is_empty());

        let mut s = Session::established(CLIENT_COMPRESS);
        assert_eq!(s.dec.disposition(), Disposition::Compressed);
        s.client(&com_query("SELECT 1"));
        assert!(s.events.is_empty());

        let s = Session::established(CLIENT_ZSTD_COMPRESSION_ALGORITHM);
        assert_eq!(s.dec.disposition(), Disposition::Compressed);
    }

    #[test]
    fn non_mysql_or_midstream_streams_are_bad_handshake() {
        let mut s = Session {
            dec: ConnDecoder::new(),
            events: Vec::new(),
            ts: 0,
        };
        // First server bytes are a result-set row, not a greeting.
        s.server(&packet(3, b"\x04abcd"));
        assert_eq!(s.dec.disposition(), Disposition::BadHandshake);

        // Client speaks before any server greeting (capture started after
        // the handshake).
        let mut s = Session {
            dec: ConnDecoder::new(),
            events: Vec::new(),
            ts: 0,
        };
        s.client(&com_query("SELECT 1"));
        assert_eq!(s.dec.disposition(), Disposition::BadHandshake);
    }

    #[test]
    fn quit_ends_the_session_without_an_event() {
        let mut s = Session::established(0);
        s.client(&com_query("SELECT 1"));
        s.server(&ok_packet(1));
        s.client(&packet(0, &[COM_QUIT]));
        s.client(&com_query("SELECT 2"));
        s.finish();
        assert_eq!(s.events.len(), 1);
    }

    #[test]
    fn missing_response_is_flushed_and_counted_on_finish() {
        let mut s = Session::established(0);
        s.client(&com_query("SELECT 1"));
        s.finish();
        assert_eq!(s.events.len(), 1);
        assert!(!s.events[0].response_seen);
        assert_eq!(s.events[0].latency_s, 0.0);
        assert_eq!(s.dec.stats.responses_missing, 1);
    }

    #[test]
    fn packets_split_and_merged_across_chunks_reassemble() {
        let mut s = Session::established(0);
        // One chunk carrying two commands back to back...
        let mut two = com_query("SELECT 'a'");
        two.extend_from_slice(&com_query("SELECT 'b'"));
        s.client(&two);
        s.server(&ok_packet(1));
        s.server(&ok_packet(1));
        // ...and one command split mid-header and mid-payload.
        let q = com_query("SELECT 'split'");
        let first_ts;
        {
            s.client(&q[..2]);
            first_ts = s.ts;
            s.client(&q[2..7]);
            s.client(&q[7..]);
        }
        s.server(&ok_packet(1));
        assert_eq!(s.events.len(), 3);
        assert_eq!(s.events[2].query, "SELECT 'split'");
        // The event timestamp is the chunk that carried the first byte.
        assert_eq!(s.events[2].ts_micros, first_ts);
    }

    /// A COM_QUERY whose logical payload is exactly 0xffffff + 10 bytes,
    /// split into two wire packets (seqs 0 and 1). Its response starts at
    /// seq 2.
    fn two_packet_com_query() -> Vec<u8> {
        let text_len = 0xff_ffff - 1 + 10; // minus command byte
        let mut text = b"SELECT '".to_vec();
        text.extend(std::iter::repeat_n(b'x', text_len - 9));
        text.push(b'\'');
        let mut payload = vec![COM_QUERY];
        payload.extend_from_slice(&text);
        assert_eq!(payload.len(), 0xff_ffff + 10);

        let mut wire = Vec::new();
        wire.extend_from_slice(&[0xff, 0xff, 0xff, 0]); // len, seq 0
        wire.extend_from_slice(&payload[..0xff_ffff]);
        wire.extend_from_slice(&[10, 0, 0, 1]); // len 10, seq 1
        wire.extend_from_slice(&payload[0xff_ffff..]);
        wire
    }

    #[test]
    fn multi_packet_payload_joins_continuations() {
        let mut s = Session::established(0);
        s.client(&two_packet_com_query());
        s.server(&ok_packet(2)); // response seq continues after seq 1
        assert_eq!(s.events.len(), 1);
        assert_eq!(s.events[0].query.len(), 0xff_ffff + 10 - 1);
        assert!(s.events[0].query.starts_with("SELECT 'xxx"));
    }

    #[test]
    fn multi_packet_command_after_completed_response() {
        let mut s = Session::established(0);
        s.client(&com_query("SELECT 1"));
        s.server(&ok_packet(1));
        assert_eq!(s.events.len(), 1);
        // The finished response's continuation seq would be 2 — exactly
        // where this two-packet command's response starts. It must be
        // matched as a response start, not swallowed as a continuation.
        s.client(&two_packet_com_query());
        s.server(&ok_packet(2));
        assert_eq!(s.events.len(), 2);
        assert!(s.events[1].response_seen);
        s.finish();
        assert_eq!(s.dec.stats.responses_missing, 0);
    }

    #[test]
    fn server_seq_wraparound_is_continuation_not_new_response() {
        let mut s = Session::established(0);
        s.client(&com_query("SELECT * FROM huge"));
        // Response of 300 packets: seqs 1..=255 then 0, 1, ...
        let mut wire = Vec::new();
        for i in 0..300u32 {
            wire.extend_from_slice(&packet((1 + i % 256) as u8, &[0x04, b'r']));
        }
        s.server(&wire);
        assert_eq!(s.events.len(), 1, "one response, despite wrapped seq 1s");
        s.client(&com_query("SELECT 1"));
        s.server(&ok_packet(1));
        assert_eq!(s.events.len(), 2);
    }

    #[test]
    fn pipelined_commands_resolve_in_order() {
        let mut s = Session::established(0);
        s.client(&com_query("SELECT 'a'"));
        s.client(&com_query("SELECT 'b'"));
        s.server(&ok_packet(1));
        s.server(&ok_packet(1));
        assert_eq!(s.events.len(), 2);
        assert_eq!(s.events[0].query, "SELECT 'a'");
        assert_eq!(s.events[1].query, "SELECT 'b'");
        assert!(s.events.iter().all(|e| e.response_seen));
    }

    #[test]
    fn oversized_logical_packet_marks_the_connection_broken() {
        let mut s = Session::established(0);
        // Five max-size continuation fragments join into one logical packet
        // of ~84 MiB, overrunning the 64 MiB cap (four land 4 bytes short).
        let frag = vec![0u8; 0xff_ffff];
        for seq in 0..5u8 {
            let mut wire = Vec::with_capacity(4 + frag.len());
            wire.extend_from_slice(&[0xff, 0xff, 0xff, seq]);
            wire.extend_from_slice(&frag);
            s.client(&wire);
        }
        assert_eq!(s.dec.disposition(), Disposition::Broken);
        assert!(s.events.is_empty());
    }

    #[test]
    fn parse_use_target_variants() {
        assert_eq!(parse_use_target("USE shop"), Some("shop".to_string()));
        assert_eq!(parse_use_target("use `a``b` ;"), Some("a`b".to_string()));
        assert_eq!(parse_use_target("SELECT 1"), None);
        assert_eq!(parse_use_target("USELESS x"), None);
        assert_eq!(parse_use_target("use"), None);
    }

    #[test]
    fn string_literals_escape_dangerous_bytes() {
        assert_eq!(string_literal("a'b\\c\nd"), "'a''b\\\\c\\nd'");
        // 0xde 0xad alone is (surprisingly) valid UTF-8; a lone continuation
        // byte is what forces the hex form.
        assert_eq!(bytes_literal(&[0xde, 0xad, 0xbe, 0xef]), "X'DEADBEEF'");
        assert_eq!(bytes_literal(b"plain"), "'plain'");
    }
}
