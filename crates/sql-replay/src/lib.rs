//! sql-replay: capture MySQL load (slow query logs or tcpdump pcap
//! files), replay it against a target server (or build a baseline report
//! from the capture's recorded latencies), and compare run reports to
//! find performance and result-correctness regressions.

pub mod aggregate;
pub mod baseline;
pub mod capture;
pub mod classify;
pub mod compare;
pub mod compare_html;
pub mod fingerprint;
pub mod format;
pub mod memtune;
pub mod mysqlproto;
pub mod pcap;
pub mod replay;
pub mod report;
pub mod slowlog;
pub mod spool;
pub mod target;
