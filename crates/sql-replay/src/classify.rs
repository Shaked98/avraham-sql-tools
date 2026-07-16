//! Statement classification for the replay safety gate, plus the
//! nondeterminism classifier used by `--checksum` result diffing.
//!
//! Anything not provably read-only is classified as a write and is only
//! executed when `--allow-writes` is passed.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueryClass {
    Read,
    Write,
}

/// Decide whether a statement may run without `--allow-writes`.
pub fn should_execute(query: &str, allow_writes: bool) -> bool {
    allow_writes || classify(query) == QueryClass::Read
}

/// True when the statement is a `USE <db>` database switch.
pub fn is_use_statement(sql: &str) -> bool {
    TokenScanner::new(sql).next_word().as_deref() == Some("use")
}

pub fn classify(sql: &str) -> QueryClass {
    // Multi-statement text can hide a write after a read (`SELECT 1; DROP
    // TABLE t`); the driver does not enable CLIENT_MULTI_STATEMENTS today,
    // but "not provably read-only" means such text is a write regardless.
    if has_trailing_statement(sql) {
        return QueryClass::Write;
    }
    let mut scan = TokenScanner::new(sql);
    let Some(first) = scan.next_word() else {
        return QueryClass::Write;
    };
    match first.as_str() {
        "select" => classify_select_tail(&mut scan),
        "show" | "use" | "help" => QueryClass::Read,
        // EXPLAIN ANALYZE (unlike plain EXPLAIN) executes the underlying
        // statement on MySQL 8.0, so DML under it is a write. DESCRIBE/DESC
        // are EXPLAIN synonyms.
        "explain" | "describe" | "desc" => match scan.next_word().as_deref() {
            Some("analyze") => classify_explain_analyze_tail(&mut scan),
            _ => QueryClass::Read,
        },
        // Session-level SET is required for faithful replay (SET NAMES,
        // SET @vars, ...), but SET GLOBAL/PERSIST mutate server state and
        // SET PASSWORD / SET DEFAULT ROLE mutate account data.
        "set" => match scan.next_word().as_deref() {
            Some("global") | Some("persist") | Some("persist_only") | Some("password")
            | Some("default") => QueryClass::Write,
            _ => QueryClass::Read,
        },
        "with" => classify_with_tail(&mut scan),
        _ => QueryClass::Write,
    }
}

/// Classify the remainder of a SELECT: `INTO OUTFILE`/`INTO DUMPFILE`
/// writes files on the target server even though the statement is a read.
fn classify_select_tail(scan: &mut TokenScanner) -> QueryClass {
    let mut after_into = false;
    while let Some(w) = scan.next_word() {
        match w.as_str() {
            "outfile" | "dumpfile" if after_into => return QueryClass::Write,
            _ => after_into = w == "into",
        }
    }
    QueryClass::Read
}

/// In 8.0, WITH can prefix UPDATE/DELETE as well as SELECT; the first
/// top-level verb after the CTE bodies decides.
fn classify_with_tail(scan: &mut TokenScanner) -> QueryClass {
    while let Some(w) = scan.next_word() {
        if scan.last_word_depth() == 0 {
            match w.as_str() {
                "select" => return classify_select_tail(scan),
                "insert" | "update" | "delete" | "replace" => return QueryClass::Write,
                _ => {}
            }
        }
    }
    QueryClass::Write
}

/// Classify the statement under `EXPLAIN ANALYZE [FORMAT = ...]`, which
/// MySQL executes for real.
fn classify_explain_analyze_tail(scan: &mut TokenScanner) -> QueryClass {
    while let Some(w) = scan.next_word() {
        match w.as_str() {
            "format" | "tree" | "json" => continue,
            "select" | "table" => return classify_select_tail(scan),
            "with" => return classify_with_tail(scan),
            _ => return QueryClass::Write,
        }
    }
    QueryClass::Write
}

/// Best-effort detector for queries whose result set can legitimately
/// differ between two runs against identical data. Used by `--checksum`
/// result diffing to demote such fingerprints to "advisory" instead of
/// hard mismatches. Operates on the normalized *fingerprint* text
/// (lowercased, literals collapsed to `?`, comments stripped).
///
/// Detected classes (the honest limits — this is a token scan, not a SQL
/// parser; a column actually named `now` etc. can false-positive, and
/// nondeterminism hidden in views or stored functions is invisible):
/// - volatile functions: NOW()/SYSDATE()/CURDATE()/RAND()/UUID()/
///   LAST_INSERT_ID()/CONNECTION_ID()/FOUND_ROWS()/... and the bare
///   CURRENT_TIMESTAMP/CURRENT_DATE/... forms, plus no-argument
///   UNIX_TIMESTAMP()
/// - `@@variable` reads and VERSION() (differ across servers by design)
/// - reads from information_schema / performance_schema (live server
///   state)
/// - LIMIT with no ORDER BY anywhere in the statement (which rows are
///   returned is storage-order dependent; an ORDER BY anywhere disarms
///   this heuristic even though only a top-level one truly fixes the
///   ambiguity)
pub fn is_nondeterministic(fingerprint: &str) -> bool {
    // Functions that are volatile only as calls: require a following `(`.
    const VOLATILE_FUNCS: &[&str] = &[
        "now",
        "sysdate",
        "curdate",
        "curtime",
        "rand",
        "uuid",
        "uuid_short",
        "last_insert_id",
        "connection_id",
        "found_rows",
        "row_count",
        "benchmark",
        "get_lock",
        "release_lock",
        "is_free_lock",
        "is_used_lock",
        "version",
        "sleep",
    ];
    // Keywords volatile even without parentheses.
    const VOLATILE_WORDS: &[&str] = &[
        "current_timestamp",
        "current_date",
        "current_time",
        "localtime",
        "localtimestamp",
        "utc_timestamp",
        "utc_date",
        "utc_time",
        "information_schema",
        "performance_schema",
    ];

    let b = fingerprint.as_bytes();
    let n = b.len();
    let mut i = 0;
    let mut has_limit = false;
    let mut has_order = false;
    while i < n {
        let c = b[i];
        match c {
            b'`' | b'\'' | b'"' => i = skip_quoted(b, i),
            b'@' if i + 1 < n && b[i + 1] == b'@' => return true,
            _ if c.is_ascii_alphabetic() || c == b'_' => {
                let start = i;
                while i < n && (b[i].is_ascii_alphanumeric() || b[i] == b'_' || b[i] == b'$') {
                    i += 1;
                }
                let word = &fingerprint[start..i];
                let mut j = i;
                while j < n && b[j].is_ascii_whitespace() {
                    j += 1;
                }
                let called = j < n && b[j] == b'(';
                if VOLATILE_WORDS.contains(&word) {
                    return true;
                }
                if called && VOLATILE_FUNCS.contains(&word) {
                    return true;
                }
                // UNIX_TIMESTAMP() without arguments is "now"; with an
                // argument it is a pure conversion.
                if called && word == "unix_timestamp" {
                    let mut k = j + 1;
                    while k < n && b[k].is_ascii_whitespace() {
                        k += 1;
                    }
                    if k < n && b[k] == b')' {
                        return true;
                    }
                }
                match word {
                    "limit" => has_limit = true,
                    "order" => has_order = true,
                    _ => {}
                }
            }
            _ => i += 1,
        }
    }
    has_limit && !has_order
}

/// True when a `;` outside strings/comments is followed by anything other
/// than whitespace and comments, i.e. the text is a multi-statement batch.
/// A single trailing `;` is harmless.
fn has_trailing_statement(sql: &str) -> bool {
    let b = sql.as_bytes();
    let n = b.len();
    let mut i = 0;
    let mut after_semicolon = false;
    while i < n {
        let c = b[i];
        if c == b'/' && i + 1 < n && b[i + 1] == b'*' {
            i += 2;
            while i + 1 < n && !(b[i] == b'*' && b[i + 1] == b'/') {
                i += 1;
            }
            i = (i + 2).min(n);
        } else if c == b'#'
            || (c == b'-'
                && i + 1 < n
                && b[i + 1] == b'-'
                && (i + 2 >= n || b[i + 2].is_ascii_whitespace()))
        {
            while i < n && b[i] != b'\n' {
                i += 1;
            }
        } else if c.is_ascii_whitespace() {
            i += 1;
        } else if c == b';' {
            after_semicolon = true;
            i += 1;
        } else if after_semicolon {
            return true;
        } else if c == b'\'' || c == b'"' || c == b'`' {
            i = skip_quoted(b, i);
        } else {
            i += 1;
        }
    }
    false
}

/// Yields lowercased word tokens, skipping strings, comments and literals,
/// tracking parenthesis depth.
struct TokenScanner<'a> {
    b: &'a [u8],
    i: usize,
    depth: i32,
    word_depth: i32,
}

impl<'a> TokenScanner<'a> {
    fn new(sql: &'a str) -> Self {
        TokenScanner {
            b: sql.as_bytes(),
            i: 0,
            depth: 0,
            word_depth: 0,
        }
    }

    /// Parenthesis depth at the start of the last yielded word.
    fn last_word_depth(&self) -> i32 {
        self.word_depth
    }

    fn next_word(&mut self) -> Option<String> {
        let b = self.b;
        let n = b.len();
        while self.i < n {
            let c = b[self.i];
            match c {
                b'(' => {
                    self.depth += 1;
                    self.i += 1;
                }
                b')' => {
                    self.depth -= 1;
                    self.i += 1;
                }
                b'\'' | b'"' | b'`' => {
                    self.i = skip_quoted(b, self.i);
                }
                b'/' if self.i + 1 < n && b[self.i + 1] == b'*' => {
                    self.i += 2;
                    while self.i + 1 < n && !(b[self.i] == b'*' && b[self.i + 1] == b'/') {
                        self.i += 1;
                    }
                    self.i = (self.i + 2).min(n);
                }
                b'-' if self.i + 1 < n
                    && b[self.i + 1] == b'-'
                    && (self.i + 2 >= n || b[self.i + 2].is_ascii_whitespace()) =>
                {
                    while self.i < n && b[self.i] != b'\n' {
                        self.i += 1;
                    }
                }
                b'#' => {
                    while self.i < n && b[self.i] != b'\n' {
                        self.i += 1;
                    }
                }
                _ if c.is_ascii_alphabetic() || c == b'_' => {
                    self.word_depth = self.depth;
                    let start = self.i;
                    while self.i < n
                        && (b[self.i].is_ascii_alphanumeric()
                            || b[self.i] == b'_'
                            || b[self.i] == b'$')
                    {
                        self.i += 1;
                    }
                    return Some(
                        std::str::from_utf8(&b[start..self.i])
                            .expect("ASCII word")
                            .to_ascii_lowercase(),
                    );
                }
                _ => self.i += 1,
            }
        }
        None
    }
}

fn skip_quoted(b: &[u8], mut i: usize) -> usize {
    let n = b.len();
    let quote = b[i];
    i += 1;
    while i < n {
        if b[i] == b'\\' && quote != b'`' {
            i += 2;
            continue;
        }
        if b[i] == quote {
            if i + 1 < n && b[i + 1] == quote {
                i += 2;
                continue;
            }
            return i + 1;
        }
        i += 1;
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_are_reads() {
        for q in [
            "SELECT 1",
            "  select * from t",
            "/* lead */ SELECT 1",
            "-- c\nSELECT 1",
            "(SELECT 1) UNION (SELECT 2)",
            "SHOW VARIABLES LIKE 'x%'",
            "EXPLAIN SELECT * FROM t",
            "EXPLAIN UPDATE t SET a = 1",
            "EXPLAIN ANALYZE SELECT * FROM t",
            "EXPLAIN ANALYZE FORMAT=TREE SELECT * FROM t",
            "EXPLAIN ANALYZE WITH q AS (SELECT 1) SELECT * FROM q",
            "DESCRIBE t",
            "DESC t",
            "SELECT 'into outfile' FROM t",
            "SELECT a INTO @v FROM t",
            "USE mydb",
            "SET NAMES utf8mb4",
            "SET @a = 1, @b = 2",
            "set session sort_buffer_size = 1000000",
            "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ",
            "SELECT 1;",
            "SELECT ';' AS s",
            "WITH q AS (SELECT 1) SELECT * FROM q",
            "WITH RECURSIVE q AS (SELECT 1) SELECT * FROM q",
        ] {
            assert_eq!(classify(q), QueryClass::Read, "misclassified: {q}");
        }
    }

    #[test]
    fn writes_are_writes() {
        for q in [
            "INSERT INTO t VALUES (1)",
            "UPDATE t SET a = 1",
            "DELETE FROM t",
            "REPLACE INTO t VALUES (1)",
            "CREATE TABLE t (a INT)",
            "ALTER TABLE t ADD COLUMN b INT",
            "DROP TABLE t",
            "TRUNCATE TABLE t",
            "CALL some_proc()",
            "LOCK TABLES t WRITE",
            "GRANT ALL ON *.* TO 'x'",
            "BEGIN",
            "COMMIT",
            "SET GLOBAL max_connections = 100",
            "SET PERSIST max_connections = 100",
            "SET PASSWORD = 'auth_string'",
            "SET PASSWORD FOR 'u'@'h' = 'auth_string'",
            "SET DEFAULT ROLE ALL TO 'u'@'h'",
            "SELECT 1; DROP TABLE t",
            "SELECT 1;\nDROP TABLE t",
            "WITH q AS (SELECT 1) UPDATE t SET a = 1 WHERE b IN (SELECT * FROM q)",
            "WITH q AS (SELECT 1) DELETE FROM t WHERE b IN (SELECT * FROM q)",
            "EXPLAIN ANALYZE UPDATE t SET a = 1",
            "EXPLAIN ANALYZE DELETE FROM t",
            "EXPLAIN ANALYZE FORMAT=TREE DELETE FROM t",
            "EXPLAIN ANALYZE WITH q AS (SELECT 1) DELETE FROM t WHERE b IN (SELECT * FROM q)",
            "SELECT * FROM t INTO OUTFILE '/tmp/x'",
            "SELECT a, b INTO DUMPFILE '/tmp/x' FROM t",
            "select * from t into outfile '/tmp/x'",
            "WITH q AS (SELECT 1) SELECT * FROM q INTO OUTFILE '/tmp/x'",
            "DO SLEEP(1)",
            "",
        ] {
            assert_eq!(classify(q), QueryClass::Write, "misclassified: {q}");
        }
    }

    #[test]
    fn use_statements_are_detected() {
        assert!(is_use_statement("USE mydb"));
        assert!(is_use_statement("use `my-db`;"));
        assert!(is_use_statement("  /* c */ Use mydb"));
        assert!(!is_use_statement("SELECT 'use mydb'"));
        assert!(!is_use_statement("SELECT used FROM t"));
        assert!(!is_use_statement("INSERT INTO uses VALUES (1)"));
    }

    #[test]
    fn nondeterministic_fingerprints_are_flagged() {
        for q in [
            "select now()",
            "select * from t where created_at > now() - interval ? day",
            "select current_timestamp",
            "select rand()",
            "select uuid()",
            "select last_insert_id()",
            "select sysdate()",
            "select unix_timestamp()",
            "select found_rows()",
            "select connection_id()",
            "select @@version_comment limit ?",
            "select version()",
            "select * from information_schema.tables",
            "select * from performance_schema.threads",
            // LIMIT with no ORDER BY: which rows come back is not defined.
            "select id from t limit ?",
            "select id from t where a = ? limit ?, ?",
        ] {
            assert!(is_nondeterministic(q), "should be nondeterministic: {q}");
        }
    }

    #[test]
    fn deterministic_fingerprints_are_not_flagged() {
        for q in [
            "select ? from t where id = ?",
            "select id from t order by id limit ?",
            // ORDER BY anywhere disarms the LIMIT heuristic (documented).
            "select * from (select a from t order by a) q limit ?",
            // Conversion form of unix_timestamp is pure.
            "select unix_timestamp(created_at) from t",
            "select unix_timestamp(?) from t",
            // Words that merely resemble volatile functions.
            "select `now` from t",
            "select nowhere from t",
            "select rand_score from t",
            "select * from randomizer",
            "select version_tag from releases",
            "select email from users where name = ?",
        ] {
            assert!(!is_nondeterministic(q), "should be deterministic: {q}");
        }
    }

    #[test]
    fn safety_gate_requires_allow_writes() {
        assert!(!should_execute("INSERT INTO t VALUES (1)", false));
        assert!(!should_execute("DROP TABLE t", false));
        assert!(should_execute("INSERT INTO t VALUES (1)", true));
        assert!(should_execute("SELECT 1", false));
    }
}
