//! Execution-target abstraction for replay.
//!
//! The replay scheduling layer (session tasks, pacing, connection permits,
//! pooling, abort) is generic over [`Target`], so it can be exercised at
//! scale in tests with a mock target — no MySQL needed. Production replay
//! uses [`MySqlTarget`]; test mocks live under `tests/`.
//!
//! # Memory: both query paths stream, per row
//!
//! Neither path ever materializes a whole result set: `query` drains via
//! `query_drop` (mysql_async reads, decodes, and drops one row at a
//! time — its public API has no decode-free drain, so each in-flight
//! row briefly exists as a wire packet plus a decoded `Row`), and
//! `query_checksum` folds rows into the O(1) [`ChecksumBuilder`] as they
//! arrive. Peak replay memory is therefore O(active connections x
//! largest row) — the retention that used to sit on top of that floor
//! is removed by [`crate::memtune`], and `tests/blob_memory.rs` is the
//! regression guard. Don't add `collect()`-style result handling here.

use std::future::Future;

use mysql_async::prelude::Queryable;
use mysql_async::{Conn, Opts, Value};
use xxhash_rust::xxh3::Xxh3;

/// A query-execution error, tagged with whether the connection is dead
/// (I/O or driver failure): a fatal error abandons the rest of a dedicated
/// session (or drops the pooled connection).
#[derive(Debug)]
pub struct TargetError {
    pub message: String,
    pub fatal: bool,
}

impl std::fmt::Display for TargetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

/// Checksum of one statement's full result set (`replay --checksum`).
///
/// Order-insensitive: the digest combines per-row hashes with commutative
/// operations (wrapping sum + xor + row count), so two runs that return
/// the same multiset of rows in different orders — the norm under
/// concurrent replay — hash identically, while any changed, missing,
/// duplicated, or extra row changes the digest. Memory is O(1) per
/// result set regardless of row count (the M3 bounded-memory invariant),
/// which is why this is a multiset hash rather than a sorted list of row
/// hashes. Column names participate in the digest so `SELECT a` vs
/// `SELECT a AS b` differ.
///
/// Digests are only comparable between runs made by this tool with the
/// same protocol (text) — the canonical cell encoding below is ours, not
/// the server's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResultChecksum {
    pub digest: u64,
    pub row_count: u64,
    /// Column names of the (first) result set.
    pub columns: Vec<String>,
}

/// Builds a [`ResultChecksum`] row by row.
#[derive(Debug, Default)]
pub struct ChecksumBuilder {
    columns: Vec<String>,
    sum: u64,
    xor: u64,
    rows: u64,
}

impl ChecksumBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record the result-set column names (first result set wins).
    pub fn set_columns(&mut self, names: impl IntoIterator<Item = String>) {
        if self.columns.is_empty() {
            self.columns = names.into_iter().collect();
        }
    }

    pub fn add_row_hash(&mut self, h: u64) {
        self.sum = self.sum.wrapping_add(h);
        self.xor ^= h;
        self.rows += 1;
    }

    pub fn finish(self) -> ResultChecksum {
        let mut h = Xxh3::new();
        for name in &self.columns {
            h.update(name.as_bytes());
            h.update(&[0]);
        }
        h.update(&self.sum.to_le_bytes());
        h.update(&self.xor.to_le_bytes());
        h.update(&self.rows.to_le_bytes());
        ResultChecksum {
            digest: h.digest(),
            row_count: self.rows,
            columns: self.columns,
        }
    }
}

/// Canonical hash of one result row: type-tagged cells so `NULL`, `0`,
/// and `"0"` all differ. Shared by the MySQL target and test mocks so
/// their digests are comparable.
pub struct RowHasher(Xxh3);

impl RowHasher {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        RowHasher(Xxh3::new())
    }

    pub fn cell_null(&mut self) {
        self.0.update(&[0]);
    }

    pub fn cell_bytes(&mut self, b: &[u8]) {
        self.0.update(&[1]);
        self.0.update(&(b.len() as u64).to_le_bytes());
        self.0.update(b);
    }

    pub fn cell_int(&mut self, v: i64) {
        self.0.update(&[2]);
        self.0.update(&v.to_le_bytes());
    }

    pub fn cell_uint(&mut self, v: u64) {
        self.0.update(&[3]);
        self.0.update(&v.to_le_bytes());
    }

    pub fn cell_float(&mut self, v: f64) {
        self.0.update(&[4]);
        self.0.update(&v.to_bits().to_le_bytes());
    }

    pub fn finish(self) -> u64 {
        self.0.digest()
    }
}

fn hash_row(row: mysql_async::Row) -> u64 {
    let mut h = RowHasher::new();
    for v in row.unwrap() {
        match v {
            Value::NULL => h.cell_null(),
            Value::Bytes(b) => h.cell_bytes(&b),
            Value::Int(i) => h.cell_int(i),
            Value::UInt(u) => h.cell_uint(u),
            Value::Float(f) => h.cell_float(f as f64),
            Value::Double(d) => h.cell_float(d),
            // The text protocol returns temporal values as Bytes; encode
            // the structured forms canonically anyway for completeness.
            Value::Date(y, mo, d, hh, mm, ss, us) => h.cell_bytes(
                format!("{y:04}-{mo:02}-{d:02} {hh:02}:{mm:02}:{ss:02}.{us:06}").as_bytes(),
            ),
            Value::Time(neg, days, hh, mm, ss, us) => h.cell_bytes(
                format!(
                    "{}{:02}:{mm:02}:{ss:02}.{us:06}",
                    if neg { "-" } else { "" },
                    days * 24 + hh as u32,
                )
                .as_bytes(),
            ),
        }
    }
    h.finish()
}

/// Connection factory for a replay target.
pub trait Target: Clone + Send + Sync + 'static {
    type Conn: TargetConn;

    fn connect(&self) -> impl Future<Output = Result<Self::Conn, TargetError>> + Send;
}

/// One live connection to the target.
pub trait TargetConn: Send + 'static {
    fn query(&mut self, sql: &str) -> impl Future<Output = Result<(), TargetError>> + Send;

    /// Execute `sql` and checksum its full result set (`--checksum`).
    /// `Ok(None)` = the statement succeeded but returned no result set
    /// (OK packet only). Reads every row, so the measured latency includes
    /// the full transfer — see the README's `--checksum` caveat.
    fn query_checksum(
        &mut self,
        sql: &str,
    ) -> impl Future<Output = Result<Option<ResultChecksum>, TargetError>> + Send;

    fn disconnect(self) -> impl Future<Output = ()> + Send;
}

#[derive(Clone)]
pub struct MySqlTarget {
    opts: Opts,
}

impl MySqlTarget {
    pub fn new(opts: Opts) -> Self {
        MySqlTarget { opts }
    }
}

fn is_fatal(e: &mysql_async::Error) -> bool {
    matches!(e, mysql_async::Error::Io(_) | mysql_async::Error::Driver(_))
}

fn target_err(e: mysql_async::Error) -> TargetError {
    TargetError {
        fatal: is_fatal(&e),
        message: e.to_string(),
    }
}

impl Target for MySqlTarget {
    type Conn = Conn;

    async fn connect(&self) -> Result<Conn, TargetError> {
        Conn::new(self.opts.clone()).await.map_err(|e| TargetError {
            message: e.to_string(),
            // A failed connect is always "fatal" for the attempt itself.
            fatal: true,
        })
    }
}

impl TargetConn for Conn {
    async fn query(&mut self, sql: &str) -> Result<(), TargetError> {
        self.query_drop(sql).await.map_err(target_err)
    }

    async fn query_checksum(&mut self, sql: &str) -> Result<Option<ResultChecksum>, TargetError> {
        let mut result = self.query_iter(sql).await.map_err(target_err)?;
        let mut builder = ChecksumBuilder::new();
        let mut saw_result_set = false;
        loop {
            if let Some(cols) = result.columns() {
                if !cols.is_empty() && !saw_result_set {
                    saw_result_set = true;
                    builder.set_columns(cols.iter().map(|c| c.name_str().into_owned()));
                }
            }
            // `next` yields the rows of the current result set and advances
            // to the following set (multi-set results hash as one stream).
            match result.next().await {
                Ok(Some(row)) => builder.add_row_hash(hash_row(row)),
                Ok(None) => {
                    if result.is_empty() {
                        break;
                    }
                }
                Err(e) => return Err(target_err(e)),
            }
        }
        Ok(saw_result_set.then(|| builder.finish()))
    }

    async fn disconnect(self) {
        let _ = Conn::disconnect(self).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row_hash(cells: &[&str]) -> u64 {
        let mut h = RowHasher::new();
        for c in cells {
            h.cell_bytes(c.as_bytes());
        }
        h.finish()
    }

    fn checksum(columns: &[&str], rows: &[&[&str]]) -> ResultChecksum {
        let mut b = ChecksumBuilder::new();
        b.set_columns(columns.iter().map(|s| s.to_string()));
        for r in rows {
            b.add_row_hash(row_hash(r));
        }
        b.finish()
    }

    #[test]
    fn checksum_is_order_insensitive_but_content_sensitive() {
        let a = checksum(&["id", "name"], &[&["1", "ann"], &["2", "bob"]]);
        let b = checksum(&["id", "name"], &[&["2", "bob"], &["1", "ann"]]);
        assert_eq!(a, b, "row order must not matter");
        assert_eq!(a.row_count, 2);

        let changed = checksum(&["id", "name"], &[&["1", "ann"], &["2", "bub"]]);
        assert_ne!(a.digest, changed.digest, "changed cell must matter");

        let fewer = checksum(&["id", "name"], &[&["1", "ann"]]);
        assert_ne!(a.digest, fewer.digest);
        assert_eq!(fewer.row_count, 1);

        // Duplicate rows do not cancel out (sum term catches what xor
        // would miss).
        let dup_a = checksum(&["v"], &[&["x"], &["x"]]);
        let dup_b = checksum(&["v"], &[&["y"], &["y"]]);
        assert_ne!(dup_a.digest, dup_b.digest);

        // Same data under different column names differs.
        let renamed = checksum(&["id", "alias"], &[&["1", "ann"], &["2", "bob"]]);
        assert_ne!(a.digest, renamed.digest);

        // The empty result set still has a digest (of its column shape).
        let empty = checksum(&["id"], &[]);
        assert_eq!(empty.row_count, 0);
        assert_ne!(empty.digest, checksum(&["other"], &[]).digest);
    }

    #[test]
    fn cell_types_are_distinguished() {
        let mut a = RowHasher::new();
        a.cell_null();
        let mut b = RowHasher::new();
        b.cell_bytes(b"");
        let mut c = RowHasher::new();
        c.cell_int(0);
        let mut d = RowHasher::new();
        d.cell_uint(0);
        let hashes = [a.finish(), b.finish(), c.finish(), d.finish()];
        for (i, x) in hashes.iter().enumerate() {
            for y in &hashes[i + 1..] {
                assert_ne!(x, y);
            }
        }
    }

    #[test]
    fn checksum_deterministic_across_builders() {
        let a = checksum(&["a"], &[&["1"], &["2"], &["3"]]);
        let b = checksum(&["a"], &[&["3"], &["1"], &["2"]]);
        assert_eq!(a, b);
        assert_eq!(a.columns, vec!["a".to_string()]);
    }
}
