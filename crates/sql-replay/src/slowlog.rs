//! Streaming parser for MySQL slow query logs.
//!
//! Handles both the 5.7 (`# Time: YYMMDD HH:MM:SS`) and 8.0
//! (`# Time: 2023-09-01T12:00:01.123456Z`, RFC 3339) header dialects, plus
//! Percona-style `# Thread_id: N Schema: db ...` lines and the 8.0
//! `log_slow_extra` fields.
//!
//! Notable behaviors:
//! - `use <db>;` metadata lines are **log-global**, not per-thread: the
//!   server prints one whenever the default db differs from the previous
//!   entry in the log. Events inherit the most recent `use` (or a
//!   per-entry `Schema:` field when present).
//! - `SET timestamp=N;` lines set the event timestamp and are not emitted
//!   as queries. `# Time:` is carried forward as a fallback (old servers
//!   only print it when the second changes).
//! - Multi-line statements are accumulated until the next entry header.
//!   Quote/comment state is tracked across lines so that header-looking
//!   text (`# Time: ...`) embedded inside string literals is not misparsed.
//! - Server restart banners, the `Time Id Command Argument` column header,
//!   and `# administrator command:` entries produce no events.

use std::fmt;

use time::format_description::well_known::Rfc3339;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dialect {
    Mysql57,
    Mysql80,
}

impl Dialect {
    pub fn as_str(self) -> &'static str {
        match self {
            Dialect::Mysql57 => "mysql-5.7",
            Dialect::Mysql80 => "mysql-8.0",
        }
    }
}

impl fmt::Display for Dialect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One query parsed out of the slow log.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedQuery {
    pub ts_micros: i64,
    pub thread_id: u64,
    pub user: Option<String>,
    pub db: Option<String>,
    pub query: String,
    pub query_time_s: f64,
}

#[derive(Debug, Default, Clone)]
pub struct ParserStats {
    pub admin_commands: u64,
    pub restarts: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SqlState {
    Normal,
    InString(u8),
    InComment,
}

pub struct SlowLogParser {
    dialect: Option<Dialect>,
    time_micros: Option<i64>,
    set_ts_micros: Option<i64>,
    user: Option<String>,
    thread_id: Option<u64>,
    schema: Option<String>,
    query_time_s: f64,
    current_db: Option<String>,
    buf: String,
    in_query: bool,
    sql_state: SqlState,
    stats: ParserStats,
}

impl Default for SlowLogParser {
    fn default() -> Self {
        Self::new()
    }
}

impl SlowLogParser {
    pub fn new() -> Self {
        SlowLogParser {
            dialect: None,
            time_micros: None,
            set_ts_micros: None,
            user: None,
            thread_id: None,
            schema: None,
            query_time_s: 0.0,
            current_db: None,
            buf: String::new(),
            in_query: false,
            sql_state: SqlState::Normal,
            stats: ParserStats::default(),
        }
    }

    pub fn dialect(&self) -> Option<Dialect> {
        self.dialect
    }

    pub fn stats(&self) -> &ParserStats {
        &self.stats
    }

    /// Feed one log line (without its trailing newline). Returns a completed
    /// query if this line terminated one.
    pub fn push_line(&mut self, line: &str) -> Option<ParsedQuery> {
        let line = line.strip_suffix('\r').unwrap_or(line);

        if self.in_query {
            // Inside a string or block comment, header-looking lines are
            // statement text, never headers.
            if self.sql_state == SqlState::Normal
                && (is_entry_header(line) || is_restart_banner(line))
            {
                let done = self.take_query();
                self.consume_meta_line(line);
                return done;
            }
            self.append_query_line(line);
            return None;
        }

        self.consume_meta_line(line);
        None
    }

    /// Signal end of input; returns the final query if one was pending.
    pub fn finish(&mut self) -> Option<ParsedQuery> {
        self.take_query()
    }

    /// Handle a line while outside of statement text.
    fn consume_meta_line(&mut self, line: &str) {
        if line.starts_with('#') {
            self.handle_header(line);
            return;
        }
        if self.handle_banner(line) {
            return;
        }
        let t = line.trim();
        if t.is_empty() {
            return;
        }
        if let Some(db) = parse_use_line(t) {
            self.current_db = Some(db);
            return;
        }
        if let Some(ts) = parse_set_timestamp(t) {
            self.set_ts_micros = Some(ts);
            return;
        }
        // Statement text begins.
        self.in_query = true;
        self.buf.clear();
        self.sql_state = SqlState::Normal;
        self.append_query_line(line);
    }

    fn handle_header(&mut self, line: &str) {
        if let Some(rest) = line.strip_prefix("# Time: ") {
            if let Some((micros, dialect)) = parse_time_value(rest.trim()) {
                self.time_micros = Some(micros);
                self.observe_dialect(dialect);
            }
        } else if let Some(rest) = line.strip_prefix("# User@Host: ") {
            self.handle_user_host(rest);
        } else if line.starts_with("# administrator command:") {
            self.stats.admin_commands += 1;
            self.reset_entry();
        } else {
            self.handle_kv_line(line);
        }
    }

    fn handle_user_host(&mut self, rest: &str) {
        // e.g. `appuser[appuser] @ app01 [10.0.0.5]  Id:    11`
        let before_at = rest.split('@').next().unwrap_or("").trim();
        let user = match before_at.find('[') {
            Some(0) => before_at
                .find(']')
                .map(|end| before_at[1..end].to_string())
                .unwrap_or_default(),
            Some(p) => before_at[..p].to_string(),
            None => before_at.to_string(),
        };
        if !user.is_empty() {
            self.user = Some(user);
        }
        if let Some(pos) = rest.rfind("Id:") {
            if let Some(tok) = rest[pos + 3..].split_whitespace().next() {
                if let Ok(id) = tok.parse() {
                    self.thread_id = Some(id);
                }
            }
        }
    }

    /// Parse `Key: value` pairs from `# Query_time: ...` style lines,
    /// including Percona `# Thread_id: N Schema: db ...` and the 8.0
    /// `log_slow_extra` fields.
    fn handle_kv_line(&mut self, line: &str) {
        let rest = line.trim_start_matches('#').trim_start();
        let toks: Vec<&str> = rest.split_whitespace().collect();
        let mut idx = 0;
        while idx < toks.len() {
            let Some(key) = toks[idx].strip_suffix(':') else {
                idx += 1;
                continue;
            };
            // A value is missing when the next token is itself a key
            // (e.g. Percona `Schema:  Last_errno: 0` with an empty schema).
            let val = toks.get(idx + 1).copied().filter(|v| !v.ends_with(':'));
            match (key, val) {
                ("Query_time", Some(v)) => {
                    if let Ok(f) = v.parse() {
                        self.query_time_s = f;
                    }
                }
                ("Thread_id", Some(v)) => {
                    if let Ok(id) = v.parse() {
                        self.thread_id = Some(id);
                    }
                }
                ("Schema", Some(v)) => {
                    self.schema = Some(v.to_string());
                }
                _ => {}
            }
            idx += if val.is_some() { 2 } else { 1 };
        }
    }

    /// Recognize server-restart banners and log column headers. Returns
    /// true when the line was consumed as one.
    fn handle_banner(&mut self, line: &str) -> bool {
        if is_restart_banner(line) {
            self.stats.restarts += 1;
            // A restarted server starts a fresh log stream.
            self.current_db = None;
            self.set_ts_micros = None;
            if let Some(pos) = line.find(", Version: ") {
                let ver = &line[pos + ", Version: ".len()..];
                if ver.starts_with('5') {
                    self.observe_dialect(Dialect::Mysql57);
                } else if ver.starts_with('8') {
                    self.observe_dialect(Dialect::Mysql80);
                }
            }
            return true;
        }
        if line.starts_with("Tcp port:") || line.starts_with("TCP Port:") {
            return true;
        }
        let t = line.trim_start();
        if t.starts_with("Time")
            && t.contains("Id")
            && t.contains("Command")
            && t.contains("Argument")
        {
            return true;
        }
        false
    }

    fn observe_dialect(&mut self, d: Dialect) {
        if self.dialect.is_none() {
            self.dialect = Some(d);
        }
    }

    fn append_query_line(&mut self, line: &str) {
        if !self.buf.is_empty() {
            self.buf.push('\n');
        }
        self.buf.push_str(line);
        self.sql_state = scan_sql_state(self.sql_state, line);
    }

    fn reset_entry(&mut self) {
        self.set_ts_micros = None;
        self.schema = None;
        self.query_time_s = 0.0;
    }

    fn take_query(&mut self) -> Option<ParsedQuery> {
        if !self.in_query {
            return None;
        }
        self.in_query = false;
        self.sql_state = SqlState::Normal;
        let mut q = std::mem::take(&mut self.buf);
        q.truncate(q.trim_end().len());
        if q.ends_with(';') {
            q.pop();
            q.truncate(q.trim_end().len());
        }
        let ts_micros = self.set_ts_micros.or(self.time_micros).unwrap_or(0);
        let thread_id = self.thread_id.unwrap_or(0);
        let db = self.schema.take().or_else(|| self.current_db.clone());
        let query_time_s = self.query_time_s;
        self.reset_entry();
        if q.is_empty() {
            return None;
        }
        Some(ParsedQuery {
            ts_micros,
            thread_id,
            user: self.user.clone(),
            db,
            query: q,
            query_time_s,
        })
    }
}

/// Headers that begin a new slow-log entry (and therefore terminate any
/// statement being accumulated).
fn is_entry_header(line: &str) -> bool {
    line.starts_with("# Time: ")
        || line.starts_with("# User@Host: ")
        || line.starts_with("# Query_time: ")
        || line.starts_with("# Thread_id: ")
        || line.starts_with("# administrator command:")
}

fn is_restart_banner(line: &str) -> bool {
    line.contains(", Version: ") && line.trim_end().ends_with("started with:")
}

/// Track string/comment state across the lines of a statement.
fn scan_sql_state(mut state: SqlState, line: &str) -> SqlState {
    let b = line.as_bytes();
    let n = b.len();
    let mut i = 0;
    while i < n {
        match state {
            SqlState::InString(q) => {
                if b[i] == b'\\' && q != b'`' {
                    i += 2;
                } else if b[i] == q {
                    if i + 1 < n && b[i + 1] == q {
                        i += 2;
                    } else {
                        state = SqlState::Normal;
                        i += 1;
                    }
                } else {
                    i += 1;
                }
            }
            SqlState::InComment => {
                if b[i] == b'*' && i + 1 < n && b[i + 1] == b'/' {
                    state = SqlState::Normal;
                    i += 2;
                } else {
                    i += 1;
                }
            }
            SqlState::Normal => match b[i] {
                b'\'' | b'"' | b'`' => {
                    state = SqlState::InString(b[i]);
                    i += 1;
                }
                b'/' if i + 1 < n && b[i + 1] == b'*' => {
                    state = SqlState::InComment;
                    i += 2;
                }
                b'-' if i + 1 < n
                    && b[i + 1] == b'-'
                    && (i + 2 >= n || b[i + 2].is_ascii_whitespace()) =>
                {
                    break; // rest of the line is a comment
                }
                b'#' => break,
                _ => i += 1,
            },
        }
    }
    state
}

/// Parse the value of a `# Time:` header in either dialect, returning
/// microseconds since the Unix epoch. The old `YYMMDD HH:MM:SS` format has
/// no zone information and is assumed to be UTC.
fn parse_time_value(s: &str) -> Option<(i64, Dialect)> {
    let s = s.trim();
    if s.contains('T') {
        let odt = time::OffsetDateTime::parse(s, &Rfc3339).ok()?;
        return Some(((odt.unix_timestamp_nanos() / 1000) as i64, Dialect::Mysql80));
    }
    let mut parts = s.split_whitespace();
    let date = parts.next()?;
    let tod = parts.next()?;
    if date.len() != 6 || !date.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let year = 2000 + date[0..2].parse::<i32>().ok()?;
    let month: u8 = date[2..4].parse().ok()?;
    let day: u8 = date[4..6].parse().ok()?;
    let mut hms = tod.split(':');
    let hour: u8 = hms.next()?.trim().parse().ok()?;
    let minute: u8 = hms.next()?.parse().ok()?;
    let second: u8 = hms.next()?.parse().ok()?;
    let d = time::Date::from_calendar_date(year, time::Month::try_from(month).ok()?, day).ok()?;
    let dt = d.with_hms(hour, minute, second).ok()?.assume_utc();
    Some(((dt.unix_timestamp_nanos() / 1000) as i64, Dialect::Mysql57))
}

/// Parse a `use <db>;` metadata line.
fn parse_use_line(t: &str) -> Option<String> {
    if t.len() < 5 || !t[..4].eq_ignore_ascii_case("use ") {
        return None;
    }
    let mut db = t[4..].trim().trim_end_matches(';').trim().to_string();
    if db.starts_with('`') && db.ends_with('`') && db.len() >= 2 {
        db = db[1..db.len() - 1].replace("``", "`");
    } else if db.is_empty() || db.contains(char::is_whitespace) {
        return None;
    }
    if db.is_empty() {
        return None;
    }
    Some(db)
}

/// Parse a `SET timestamp=N;` metadata line into epoch microseconds.
fn parse_set_timestamp(t: &str) -> Option<i64> {
    const PREFIX: &str = "set timestamp=";
    if t.len() <= PREFIX.len() || !t[..PREFIX.len()].eq_ignore_ascii_case(PREFIX) {
        return None;
    }
    let v = t[PREFIX.len()..].trim_end_matches(';').trim();
    let secs: f64 = v.parse().ok()?;
    Some((secs * 1_000_000.0).round() as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_all(input: &str) -> (Vec<ParsedQuery>, ParserStats, Option<Dialect>) {
        let mut p = SlowLogParser::new();
        let mut out = Vec::new();
        for line in input.lines() {
            if let Some(q) = p.push_line(line) {
                out.push(q);
            }
        }
        if let Some(q) = p.finish() {
            out.push(q);
        }
        let stats = p.stats().clone();
        (out, stats, p.dialect())
    }

    #[test]
    fn old_time_format_parses() {
        let (micros, dialect) = parse_time_value("230901 12:00:01").unwrap();
        assert_eq!(dialect, Dialect::Mysql57);
        assert_eq!(micros, 1_693_569_601_000_000);
        // Single-digit hour variant.
        let (micros, _) = parse_time_value("230901  1:02:03").unwrap();
        assert_eq!(micros, 1_693_530_123_000_000);
    }

    #[test]
    fn rfc3339_time_format_parses() {
        let (micros, dialect) = parse_time_value("2023-09-01T12:00:01.123456Z").unwrap();
        assert_eq!(dialect, Dialect::Mysql80);
        assert_eq!(micros, 1_693_569_601_123_456);
        let (micros, _) = parse_time_value("2023-09-01T15:00:01.500000+03:00").unwrap();
        assert_eq!(micros, 1_693_569_601_500_000);
    }

    #[test]
    fn set_timestamp_and_use_lines() {
        assert_eq!(
            parse_set_timestamp("SET timestamp=1693569601;"),
            Some(1_693_569_601_000_000)
        );
        assert_eq!(
            parse_set_timestamp("set timestamp=1693569601.250000;"),
            Some(1_693_569_601_250_000)
        );
        assert_eq!(parse_use_line("use orders;"), Some("orders".into()));
        assert_eq!(parse_use_line("USE `weird``db`;"), Some("weird`db".into()));
        assert_eq!(parse_use_line("user preferences"), None);
    }

    #[test]
    fn header_inside_string_is_not_misparsed() {
        let log = "\
# User@Host: u[u] @ h []  Id: 1
# Query_time: 0.1  Lock_time: 0.0 Rows_sent: 1  Rows_examined: 1
SET timestamp=100;
SELECT * FROM t WHERE body = 'line one
# Time: 230901 12:00:00
# User@Host: fake[fake] @ x []  Id: 99
still inside' AND id = 3;
# User@Host: u[u] @ h []  Id: 1
# Query_time: 0.2  Lock_time: 0.0 Rows_sent: 1  Rows_examined: 1
SET timestamp=101;
SELECT 2;
";
        let (qs, _, _) = parse_all(log);
        assert_eq!(qs.len(), 2);
        assert!(qs[0].query.contains("# Time: 230901 12:00:00"));
        assert!(qs[0].query.contains("# User@Host: fake"));
        assert!(qs[0].query.ends_with("AND id = 3"));
        assert_eq!(qs[0].thread_id, 1);
        assert_eq!(qs[1].query, "SELECT 2");
        // The embedded fake headers must not have leaked into parser state.
        assert_eq!(qs[1].thread_id, 1);
        assert_eq!(qs[1].ts_micros, 101_000_000);
    }

    #[test]
    fn hash_comment_line_inside_query_is_kept() {
        let log = "\
# User@Host: u[u] @ h []  Id: 7
# Query_time: 0.1  Lock_time: 0.0 Rows_sent: 1  Rows_examined: 1
SET timestamp=100;
SELECT a
# an inline mysql comment
FROM t;
";
        let (qs, _, _) = parse_all(log);
        assert_eq!(qs.len(), 1);
        assert!(qs[0].query.contains("# an inline mysql comment"));
    }

    #[test]
    fn admin_commands_are_counted_not_emitted() {
        let log = "\
# User@Host: u[u] @ h []  Id: 5
# Query_time: 0.0  Lock_time: 0.0 Rows_sent: 0  Rows_examined: 0
SET timestamp=100;
# administrator command: Quit;
# User@Host: u[u] @ h []  Id: 6
# Query_time: 0.0  Lock_time: 0.0 Rows_sent: 0  Rows_examined: 0
SET timestamp=101;
SELECT 1;
";
        let (qs, stats, _) = parse_all(log);
        assert_eq!(qs.len(), 1);
        assert_eq!(qs[0].thread_id, 6);
        assert_eq!(stats.admin_commands, 1);
    }

    #[test]
    fn log_global_use_carries_across_threads() {
        let log = "\
# User@Host: u[u] @ h []  Id: 1
# Query_time: 0.0  Lock_time: 0.0 Rows_sent: 0  Rows_examined: 0
use db_a;
SET timestamp=100;
SELECT 1;
# User@Host: u[u] @ h []  Id: 2
# Query_time: 0.0  Lock_time: 0.0 Rows_sent: 0  Rows_examined: 0
SET timestamp=101;
SELECT 2;
# User@Host: u[u] @ h []  Id: 1
# Query_time: 0.0  Lock_time: 0.0 Rows_sent: 0  Rows_examined: 0
use db_b;
SET timestamp=102;
SELECT 3;
";
        let (qs, _, _) = parse_all(log);
        assert_eq!(qs[0].db.as_deref(), Some("db_a"));
        // No `use` printed for thread 2 => same db as previous log entry.
        assert_eq!(qs[1].db.as_deref(), Some("db_a"));
        assert_eq!(qs[2].db.as_deref(), Some("db_b"));
    }

    #[test]
    fn percona_thread_id_and_schema_line() {
        let log = "\
# Time: 230901 12:00:01
# User@Host: u[u] @ h []
# Thread_id: 33  Schema: shop  QC_hit: No
# Query_time: 0.5  Lock_time: 0.0 Rows_sent: 1  Rows_examined: 10
SET timestamp=1693569601;
SELECT x FROM y;
";
        let (qs, _, dialect) = parse_all(log);
        assert_eq!(qs.len(), 1);
        assert_eq!(qs[0].thread_id, 33);
        assert_eq!(qs[0].db.as_deref(), Some("shop"));
        assert_eq!(qs[0].query_time_s, 0.5);
        assert_eq!(dialect, Some(Dialect::Mysql57));
    }

    #[test]
    fn log_slow_extra_thread_id_wins() {
        let log = "\
# Time: 2023-09-01T12:00:01.000000Z
# User@Host: u[u] @ h []  Id:    21
# Query_time: 0.000212 Lock_time: 0.000045 Rows_sent: 1 Rows_examined: 1 Thread_id: 21 Errno: 0 Killed: 0 Bytes_received: 96 Bytes_sent: 190 Start: 2023-09-01T12:00:00.999788Z End: 2023-09-01T12:00:01.000000Z
SET timestamp=1693569601;
SELECT 1;
";
        let (qs, _, dialect) = parse_all(log);
        assert_eq!(qs.len(), 1);
        assert_eq!(qs[0].thread_id, 21);
        assert_eq!(qs[0].query_time_s, 0.000212);
        assert_eq!(dialect, Some(Dialect::Mysql80));
    }

    #[test]
    fn time_header_carries_forward_when_set_timestamp_missing() {
        let log = "\
# Time: 230901 12:00:01
# User@Host: u[u] @ h []  Id: 1
# Query_time: 0.0  Lock_time: 0.0 Rows_sent: 0  Rows_examined: 0
SELECT 1;
# User@Host: u[u] @ h []  Id: 1
# Query_time: 0.0  Lock_time: 0.0 Rows_sent: 0  Rows_examined: 0
SELECT 2;
";
        let (qs, _, _) = parse_all(log);
        assert_eq!(qs[0].ts_micros, 1_693_569_601_000_000);
        assert_eq!(qs[1].ts_micros, 1_693_569_601_000_000);
    }

    #[test]
    fn restart_banner_is_ignored_and_sets_dialect() {
        let log = "\
/usr/sbin/mysqld, Version: 5.7.42-log (MySQL Community Server (GPL)). started with:
Tcp port: 3306  Unix socket: /var/lib/mysql/mysql.sock
Time                 Id Command    Argument
# User@Host: u[u] @ h []  Id: 1
# Query_time: 0.0  Lock_time: 0.0 Rows_sent: 0  Rows_examined: 0
SET timestamp=100;
SELECT 1;
";
        let (qs, stats, dialect) = parse_all(log);
        assert_eq!(qs.len(), 1);
        assert_eq!(stats.restarts, 1);
        assert_eq!(dialect, Some(Dialect::Mysql57));
    }
}
