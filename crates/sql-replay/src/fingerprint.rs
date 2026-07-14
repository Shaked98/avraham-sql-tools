//! pt-query-digest-style SQL fingerprinting.
//!
//! Collapses literals (numbers, quoted strings, `IN (...)` lists, `VALUES`
//! tuples), strips comments, and normalizes whitespace and case so that
//! millions of query instances group into a small number of comparable
//! classes.

use std::collections::HashMap;

/// Normalize a SQL statement into its fingerprint text.
pub fn fingerprint(query: &str) -> String {
    let b = query.as_bytes();
    let n = b.len();
    let mut out = String::with_capacity(query.len().min(1024));
    let mut i = 0;

    while i < n {
        let c = b[i];
        match c {
            b'\'' | b'"' => {
                i = skip_string(b, i);
                out.push('?');
            }
            b'`' => {
                out.push('`');
                i += 1;
                while i < n {
                    if b[i] == b'`' {
                        if i + 1 < n && b[i + 1] == b'`' {
                            out.push_str("``");
                            i += 2;
                            continue;
                        }
                        out.push('`');
                        i += 1;
                        break;
                    }
                    push_lossy_lower(&mut out, b, &mut i);
                }
            }
            b'/' if i + 1 < n && b[i + 1] == b'*' => {
                i += 2;
                while i + 1 < n && !(b[i] == b'*' && b[i + 1] == b'/') {
                    i += 1;
                }
                i = (i + 2).min(n);
                push_space(&mut out);
            }
            b'-' if i + 1 < n
                && b[i + 1] == b'-'
                && (i + 2 >= n || b[i + 2].is_ascii_whitespace()) =>
            {
                while i < n && b[i] != b'\n' {
                    i += 1;
                }
            }
            b'#' => {
                while i < n && b[i] != b'\n' {
                    i += 1;
                }
            }
            _ if c.is_ascii_whitespace() => {
                push_space(&mut out);
                i += 1;
            }
            _ if c.is_ascii_digit() || (c == b'.' && i + 1 < n && b[i + 1].is_ascii_digit()) => {
                if ends_with_ident_char(&out) {
                    // Digit inside an identifier such as `t1`.
                    out.push(c.to_ascii_lowercase() as char);
                    i += 1;
                } else {
                    i = skip_number(b, i);
                    fold_sign(&mut out);
                    out.push('?');
                }
            }
            _ => {
                push_lossy_lower(&mut out, b, &mut i);
            }
        }
    }

    let mut s = out.trim().to_string();
    while s.ends_with(';') {
        s.pop();
        s.truncate(s.trim_end().len());
    }
    let s = collapse_in_lists(&s);
    collapse_values_lists(&s)
}

/// Push the (possibly multi-byte) character at `b[*i]`, ASCII-lowercased.
fn push_lossy_lower(out: &mut String, b: &[u8], i: &mut usize) {
    let c = b[*i];
    if c.is_ascii() {
        out.push(c.to_ascii_lowercase() as char);
        *i += 1;
    } else {
        // Copy a whole UTF-8 sequence (or a replacement char for junk bytes).
        let s = &b[*i..];
        let len = utf8_len(c).min(s.len());
        match std::str::from_utf8(&s[..len]) {
            Ok(chunk) => {
                out.push_str(chunk);
                *i += len;
            }
            Err(_) => {
                out.push(char::REPLACEMENT_CHARACTER);
                *i += 1;
            }
        }
    }
}

fn utf8_len(first: u8) -> usize {
    match first {
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF7 => 4,
        _ => 1,
    }
}

fn is_ident_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_' || c == b'$'
}

fn ends_with_ident_char(out: &str) -> bool {
    out.chars()
        .next_back()
        .is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '$' || !ch.is_ascii())
}

fn push_space(out: &mut String) {
    if !out.is_empty() && !out.ends_with(' ') {
        out.push(' ');
    }
}

/// Skip a quoted string starting at `b[i]` (a `'` or `"`); returns the index
/// just past the closing quote. Handles backslash escapes and doubled quotes.
fn skip_string(b: &[u8], mut i: usize) -> usize {
    let n = b.len();
    let quote = b[i];
    i += 1;
    while i < n {
        if b[i] == b'\\' {
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

/// Skip a numeric literal (integer, decimal, exponent, or 0x hex).
fn skip_number(b: &[u8], mut i: usize) -> usize {
    let n = b.len();
    if b[i] == b'0' && i + 1 < n && (b[i + 1] | 0x20) == b'x' {
        i += 2;
        while i < n && b[i].is_ascii_hexdigit() {
            i += 1;
        }
        return i;
    }
    while i < n && b[i].is_ascii_digit() {
        i += 1;
    }
    if i < n && b[i] == b'.' {
        i += 1;
        while i < n && b[i].is_ascii_digit() {
            i += 1;
        }
    }
    if i < n && (b[i] | 0x20) == b'e' {
        let mut j = i + 1;
        if j < n && (b[j] == b'+' || b[j] == b'-') {
            j += 1;
        }
        if j < n && b[j].is_ascii_digit() {
            i = j;
            while i < n && b[i].is_ascii_digit() {
                i += 1;
            }
        }
    }
    i
}

/// Fold a unary sign preceding a number into the `?` placeholder, so that
/// `x = -5` and `x = 5` fingerprint identically. Only folds when the sign
/// cannot be a binary operator (i.e. it follows an operator, `(` or `,`).
fn fold_sign(out: &mut String) {
    let t = out.trim_end();
    let Some(last) = t.chars().next_back() else {
        return;
    };
    if last != '-' && last != '+' {
        return;
    }
    let fold = match t[..t.len() - 1].trim_end().chars().next_back() {
        None => true,
        Some(ch) => matches!(
            ch,
            '(' | ',' | '=' | '<' | '>' | '+' | '-' | '*' | '/' | '%'
        ),
    };
    if fold {
        out.truncate(t.len() - 1);
    }
}

/// Collapse `in (?, ?, ?)` (any spacing) into the canonical `in (?+)`.
fn collapse_in_lists(s: &str) -> String {
    let b = s.as_bytes();
    let n = b.len();
    let mut out: Vec<u8> = Vec::with_capacity(n);
    let mut i = 0;
    while i < n {
        if word_at(b, i, b"in") {
            let mut j = i + 2;
            while j < n && b[j] == b' ' {
                j += 1;
            }
            if j < n && b[j] == b'(' {
                if let Some(end) = placeholder_group_end(b, j) {
                    out.extend_from_slice(b"in (?+)");
                    i = end;
                    continue;
                }
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8(out).expect("collapse preserves UTF-8")
}

/// Collapse `values (?, ?), (?, ?), ...` into the canonical `values (?+)`.
fn collapse_values_lists(s: &str) -> String {
    let b = s.as_bytes();
    let n = b.len();
    let mut out: Vec<u8> = Vec::with_capacity(n);
    let mut i = 0;
    while i < n {
        if word_at(b, i, b"values") {
            let mut k = i + 6;
            let mut tuples = 0usize;
            loop {
                let mut m = k;
                while m < n && b[m] == b' ' {
                    m += 1;
                }
                if tuples > 0 && m < n && b[m] == b',' {
                    m += 1;
                    while m < n && b[m] == b' ' {
                        m += 1;
                    }
                }
                if m >= n || b[m] != b'(' {
                    break;
                }
                match placeholder_group_end(b, m) {
                    Some(end) => {
                        tuples += 1;
                        k = end;
                    }
                    None => break,
                }
            }
            if tuples > 0 {
                out.extend_from_slice(b"values (?+)");
                i = k;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8(out).expect("collapse preserves UTF-8")
}

/// If `b[open]` starts a parenthesized group containing only `?`, `,` and
/// spaces (with at least one `?`), return the index just past the `)`.
fn placeholder_group_end(b: &[u8], open: usize) -> Option<usize> {
    debug_assert_eq!(b[open], b'(');
    let n = b.len();
    let mut k = open + 1;
    let mut placeholders = 0usize;
    loop {
        if k >= n {
            return None;
        }
        match b[k] {
            b'?' => {
                placeholders += 1;
                k += 1;
            }
            b',' | b' ' => k += 1,
            b')' if placeholders > 0 => return Some(k + 1),
            _ => return None,
        }
    }
}

/// True when `word` occurs at `b[i]` with word boundaries on both sides.
fn word_at(b: &[u8], i: usize, word: &[u8]) -> bool {
    if i + word.len() > b.len() || &b[i..i + word.len()] != word {
        return false;
    }
    let before_ok = i == 0 || (!is_ident_byte(b[i - 1]) && b[i - 1] != b'`');
    let after = i + word.len();
    let after_ok = after >= b.len() || (!is_ident_byte(b[after]) && b[after] != b'`');
    before_ok && after_ok
}

/// Interns fingerprint texts, assigning stable sequential ids.
#[derive(Debug, Default)]
pub struct FingerprintRegistry {
    ids: HashMap<String, u32>,
    texts: Vec<String>,
}

impl FingerprintRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fingerprint `query` and return the id of its class.
    pub fn intern(&mut self, query: &str) -> u32 {
        let fp = fingerprint(query);
        if let Some(&id) = self.ids.get(&fp) {
            return id;
        }
        let id = self.texts.len() as u32;
        self.texts.push(fp.clone());
        self.ids.insert(fp, id);
        id
    }

    pub fn len(&self) -> usize {
        self.texts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.texts.is_empty()
    }

    /// Fingerprint texts in id order (index == id).
    pub fn texts(&self) -> &[String] {
        &self.texts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_collapse() {
        assert_eq!(
            fingerprint("SELECT * FROM Orders WHERE id = 12345"),
            "select * from orders where id = ?"
        );
        assert_eq!(fingerprint("LIMIT 10 OFFSET 20"), "limit ? offset ?");
        assert_eq!(fingerprint("WHERE h = 0xDEADbeef"), "where h = ?");
        assert_eq!(fingerprint("WHERE x = -5.5e3"), "where x = ?");
        assert_eq!(fingerprint("WHERE x = .5"), "where x = ?");
    }

    #[test]
    fn identifiers_with_digits_survive() {
        assert_eq!(fingerprint("SELECT a1 FROM t2"), "select a1 from t2");
        assert_eq!(
            fingerprint("SELECT `T1`.`Id` FROM `T1`"),
            "select `t1`.`id` from `t1`"
        );
    }

    #[test]
    fn strings_collapse() {
        assert_eq!(
            fingerprint("SELECT * FROM t WHERE name = 'O''Brien #1'"),
            "select * from t where name = ?"
        );
        assert_eq!(
            fingerprint(r#"SELECT * FROM t WHERE s = "a\"b # not comment""#),
            "select * from t where s = ?"
        );
        assert_eq!(
            fingerprint("SELECT 1 FROM t WHERE s = 'multi\nline'"),
            "select ? from t where s = ?"
        );
    }

    #[test]
    fn in_lists_collapse() {
        assert_eq!(
            fingerprint("SELECT id FROM t WHERE a IN (1, 2, 3)"),
            "select id from t where a in (?+)"
        );
        assert_eq!(
            fingerprint("SELECT id FROM t WHERE a IN(1,2)"),
            "select id from t where a in (?+)"
        );
        assert_eq!(
            fingerprint("SELECT id FROM t WHERE a IN ('x', 'y')"),
            "select id from t where a in (?+)"
        );
        // Subqueries must not collapse.
        assert_eq!(
            fingerprint("SELECT id FROM t WHERE a IN (SELECT b FROM u)"),
            "select id from t where a in (select b from u)"
        );
    }

    #[test]
    fn values_lists_collapse() {
        assert_eq!(
            fingerprint("INSERT INTO t (a, b) VALUES (1, 'x'), (2, 'y')"),
            "insert into t (a, b) values (?+)"
        );
        assert_eq!(
            fingerprint("INSERT INTO t VALUES(1,2)"),
            "insert into t values (?+)"
        );
        // Non-literal tuples must not collapse.
        assert_eq!(
            fingerprint("INSERT INTO t VALUES (1, NOW())"),
            "insert into t values (?, now())"
        );
    }

    #[test]
    fn whitespace_case_comments_normalize() {
        assert_eq!(
            fingerprint("SELECT  *\n\t FROM t\nWHERE a = 1"),
            "select * from t where a = ?"
        );
        assert_eq!(fingerprint("SELECT /* hint */ 1 -- tail"), "select ?");
        assert_eq!(fingerprint("SELECT 1 # trailing"), "select ?");
        assert_eq!(fingerprint("SELECT 1;"), "select ?");
    }

    #[test]
    fn registry_groups_instances() {
        let mut reg = FingerprintRegistry::new();
        let a = reg.intern("SELECT * FROM t WHERE id = 1");
        let b = reg.intern("select *  from t where id = 999");
        let c = reg.intern("SELECT * FROM t WHERE id IN (1,2)");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(reg.len(), 2);
        assert_eq!(reg.texts()[a as usize], "select * from t where id = ?");
    }
}
