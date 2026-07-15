//! Structured slow-log mutations: assemble a log from realistic building
//! blocks (headers in any order, restart banners interleaved, statements
//! with fuzzed text), optionally truncate it at an arbitrary byte offset
//! (log-rotation seam), and parse it. Exercises header/state interactions
//! that pure byte fuzzing rarely reaches.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use sql_replay::slowlog::SlowLogParser;

#[derive(Arbitrary, Debug)]
enum Piece {
    TimeOld {
        ts: u32,
    },
    TimeRfc3339 {
        ts: u32,
        micros: u32,
    },
    TimeRaw {
        text: String,
    },
    UserHost {
        user: String,
        host: String,
        id: u64,
    },
    QueryTime {
        qt: f32,
        extra: bool,
        thread_id: u64,
    },
    PerconaThread {
        id: u64,
        schema: String,
    },
    UseDb {
        db: String,
    },
    SetTimestamp {
        ts: u32,
    },
    Statement {
        text: String,
        terminated: bool,
    },
    Banner {
        major: u8,
    },
    ColumnHeader,
    AdminCommand {
        cmd: String,
    },
    BlankLine,
    RawLine {
        text: String,
    },
}

#[derive(Arbitrary, Debug)]
struct Plan {
    pieces: Vec<Piece>,
    crlf: bool,
    truncate_at: Option<u32>,
}

fn render(plan: &Plan) -> Vec<u8> {
    let mut out = String::new();
    for p in &plan.pieces {
        match p {
            Piece::TimeOld { ts } => {
                // YYMMDD HH:MM:SS derived from fuzzed fields (may be invalid).
                out.push_str(&format!(
                    "# Time: {:02}{:02}{:02} {:2}:{:02}:{:02}\n",
                    ts % 100,
                    (ts >> 8) % 20,
                    (ts >> 16) % 40,
                    (ts >> 24) % 30,
                    ts % 61,
                    (ts >> 4) % 61,
                ));
            }
            Piece::TimeRfc3339 { ts, micros } => {
                out.push_str(&format!(
                    "# Time: 20{:02}-{:02}-{:02}T{:02}:{:02}:{:02}.{:06}Z\n",
                    ts % 100,
                    1 + (ts >> 8) % 12,
                    1 + (ts >> 16) % 31,
                    (ts >> 24) % 24,
                    ts % 60,
                    (ts >> 4) % 60,
                    micros % 1_000_000,
                ));
            }
            Piece::TimeRaw { text } => {
                out.push_str("# Time: ");
                out.push_str(text);
                out.push('\n');
            }
            Piece::UserHost { user, host, id } => {
                out.push_str(&format!(
                    "# User@Host: {user}[{user}] @ {host} []  Id: {id}\n"
                ));
            }
            Piece::QueryTime {
                qt,
                extra,
                thread_id,
            } => {
                if *extra {
                    out.push_str(&format!(
                        "# Query_time: {qt} Lock_time: 0.000045 Rows_sent: 1 Rows_examined: 1 Thread_id: {thread_id} Errno: 0 Killed: 0\n"
                    ));
                } else {
                    out.push_str(&format!(
                        "# Query_time: {qt}  Lock_time: 0.0 Rows_sent: 1  Rows_examined: 1\n"
                    ));
                }
            }
            Piece::PerconaThread { id, schema } => {
                out.push_str(&format!(
                    "# Thread_id: {id}  Schema: {schema}  QC_hit: No\n"
                ));
            }
            Piece::UseDb { db } => {
                out.push_str(&format!("use {db};\n"));
            }
            Piece::SetTimestamp { ts } => {
                out.push_str(&format!("SET timestamp={ts};\n"));
            }
            Piece::Statement { text, terminated } => {
                out.push_str(text);
                if *terminated {
                    out.push(';');
                }
                out.push('\n');
            }
            Piece::Banner { major } => {
                out.push_str(&format!(
                    "/usr/sbin/mysqld, Version: {}.0.42-log (MySQL Community Server (GPL)). started with:\n",
                    major % 12
                ));
            }
            Piece::ColumnHeader => {
                out.push_str("Tcp port: 3306  Unix socket: /var/lib/mysql/mysql.sock\n");
                out.push_str("Time                 Id Command    Argument\n");
            }
            Piece::AdminCommand { cmd } => {
                out.push_str(&format!("# administrator command: {cmd};\n"));
            }
            Piece::BlankLine => out.push('\n'),
            Piece::RawLine { text } => {
                out.push_str(text);
                out.push('\n');
            }
        }
    }
    let mut bytes = if plan.crlf {
        out.replace('\n', "\r\n").into_bytes()
    } else {
        out.into_bytes()
    };
    if let Some(cut) = plan.truncate_at {
        let cut = cut as usize;
        if cut < bytes.len() {
            bytes.truncate(cut);
        }
    }
    bytes
}

fuzz_target!(|plan: Plan| {
    let data = render(&plan);
    let mut parser = SlowLogParser::new();
    for raw in data.split_inclusive(|&b| b == b'\n') {
        let line = String::from_utf8_lossy(raw);
        let line = line.trim_end_matches(['\n', '\r']);
        if let Some(q) = parser.push_line(line) {
            assert!(!q.query.is_empty());
        }
    }
    if let Some(q) = parser.finish() {
        assert!(!q.query.is_empty());
    }
});
