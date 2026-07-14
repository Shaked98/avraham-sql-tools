//! sql-replay: capture MySQL slow query logs, replay them against a
//! target server, and compare run reports to find performance regressions.

pub mod capture;
pub mod classify;
pub mod compare;
pub mod compare_html;
pub mod fingerprint;
pub mod format;
pub mod replay;
pub mod report;
pub mod slowlog;
