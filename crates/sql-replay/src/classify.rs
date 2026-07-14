//! Statement classification for the replay safety gate.
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
    fn safety_gate_requires_allow_writes() {
        assert!(!should_execute("INSERT INTO t VALUES (1)", false));
        assert!(!should_execute("DROP TABLE t", false));
        assert!(should_execute("INSERT INTO t VALUES (1)", true));
        assert!(should_execute("SELECT 1", false));
    }
}
