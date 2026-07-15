//! Scripted MySQL workload for CI's pcap capture leg.
//!
//! Drives real binary-protocol traffic (COM_STMT_PREPARE / COM_STMT_EXECUTE
//! with bound parameters — something the plain `mysql` CLI never sends)
//! plus text queries, over a few concurrent connections, so tcpdump has
//! genuine wire traffic for `capture --format pcap` to decode. Also sets
//! up the `pcap_smoke` table the CI checksum legs read and later mutate.
//!
//! Usage: wire_workload <mysql-url>

use mysql_async::prelude::*;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = std::env::args()
        .nth(1)
        .expect("usage: wire_workload <mysql-url>");
    let opts = mysql_async::Opts::from_url(&url)?;

    // Session 1: schema + deterministic data via prepared INSERTs.
    let mut setup = mysql_async::Conn::new(opts.clone()).await?;
    setup
        .query_drop(
            "CREATE TABLE IF NOT EXISTS pcap_smoke \
             (id INT PRIMARY KEY, v VARCHAR(50), score DOUBLE)",
        )
        .await?;
    setup.query_drop("DELETE FROM pcap_smoke").await?;
    setup
        .exec_batch(
            "INSERT INTO pcap_smoke (id, v, score) VALUES (?, ?, ?)",
            [
                (1, "alpha", 1.5),
                (2, "bravo", 2.5),
                (3, "it's charlie", 3.5),
            ],
        )
        .await?;

    // Two concurrent read sessions: prepared lookups with different bound
    // values (same fingerprint), a NULL-able param, and text queries.
    let opts2 = opts.clone();
    let reader = |opts: mysql_async::Opts, ids: Vec<i32>| async move {
        let mut conn = mysql_async::Conn::new(opts).await?;
        for id in ids {
            let _row: Option<(i32, String)> = conn
                .exec_first("SELECT id, v FROM pcap_smoke WHERE id = ?", (id,))
                .await?;
        }
        let _all: Vec<(i32, String)> = conn
            .query("SELECT id, v FROM pcap_smoke ORDER BY id")
            .await?;
        let _n: Option<i64> = conn.query_first("SELECT COUNT(*) FROM pcap_smoke").await?;
        conn.disconnect().await?;
        Ok::<_, mysql_async::Error>(())
    };
    let (a, b) = tokio::join!(reader(opts.clone(), vec![1, 2]), reader(opts2, vec![3, 1]));
    a?;
    b?;

    // A slow query so pcap-recorded latencies are visibly nonzero: the
    // request→response gap on the wire must be >= the sleep time.
    setup.query_drop("SELECT SLEEP(0.25)").await?;
    setup.disconnect().await?;

    println!("wire workload complete");
    Ok(())
}
