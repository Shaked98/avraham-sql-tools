//! Execution-target abstraction for replay.
//!
//! The replay scheduling layer (session tasks, pacing, connection permits,
//! pooling, abort) is generic over [`Target`], so it can be exercised at
//! scale in tests with a mock target — no MySQL needed. Production replay
//! uses [`MySqlTarget`]; test mocks live under `tests/`.

use std::future::Future;

use mysql_async::prelude::Queryable;
use mysql_async::{Conn, Opts};

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

/// Connection factory for a replay target.
pub trait Target: Clone + Send + Sync + 'static {
    type Conn: TargetConn;

    fn connect(&self) -> impl Future<Output = Result<Self::Conn, TargetError>> + Send;
}

/// One live connection to the target.
pub trait TargetConn: Send + 'static {
    fn query(&mut self, sql: &str) -> impl Future<Output = Result<(), TargetError>> + Send;

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
        self.query_drop(sql).await.map_err(|e| TargetError {
            message: e.to_string(),
            fatal: is_fatal(&e),
        })
    }

    async fn disconnect(self) {
        let _ = Conn::disconnect(self).await;
    }
}
