# sql-replay quick start: gating a MySQL 5.7 → 8.0 migration

This is the hands-on, ~15-minute version of the README's
[Quickstart](../README.md#quickstart): a complete capture → replay →
compare session you can run on any x86_64 Linux machine with Docker, to
evaluate sql-replay for a real 5.7 → 8.0 migration. Every command below
was executed exactly as shown, against the real v0.3.0 release binary and
throwaway MySQL containers; the outputs are real (a few long ones are
trimmed and marked). Exact latency numbers will differ on your machine —
the shapes and verdicts should not. For the big picture first, the
[architecture diagram](architecture.svg) shows the whole
capture → replay → compare pipeline this walkthrough drives end to end.

What you will do:

1. [Install sql-replay](#1-install-sql-replay) from the latest release.
2. [Stand up a toy "production" MySQL 5.7](#2-stand-up-a-toy-production-mysql-57)
   with a small shop schema and a concurrent workload.
3. [Capture that workload from the slow query log](#3-capture-the-workload-from-the-slow-log)
   (with a pointer to the pcap alternative).
4. [Stand up the MySQL 8.0 candidate](#4-stand-up-the-80-candidate--and-sabotage-it)
   — and plant a regression on it so there is something to find.
5. [Replay the capture against both servers](#5-replay-against-both-servers).
6. [Compare the runs](#6-compare-the-runs) and learn to read every part
   of the report: fingerprints, thresholds, exit codes, warnings, HTML.
7. [Build a recorded production baseline](#7-no-replayable-57-use-the-recorded-baseline)
   for when the 5.7 side *is* production and can't be replayed against.
8. [Check result correctness](#8-correctness-not-just-latency---checksum)
   with `--checksum`.
9. [Clean up](#9-clean-up), then read the
   [production notes](#10-taking-this-to-a-real-migration) and
   [troubleshooting box](#11-troubleshooting-first-run-gotchas) before
   pointing any of this at real infrastructure.

Prerequisites: Docker, `curl`, and ports 23306/23307 free on
127.0.0.1. Everything runs as an unprivileged user; total disk use is a
few hundred MB of Docker images.

```console
$ mkdir sql-replay-quickstart && cd sql-replay-quickstart
```

## 1. Install sql-replay

The release binary is fully static (musl) — one file, no runtime
dependencies, same install on a dev laptop or a RHEL 8 database host:

```console
$ VERSION=0.3.0   # the latest release tag, without the leading v
$ curl -LO https://github.com/Shaked98/avraham-sql-tools/releases/download/v$VERSION/sql-replay-$VERSION-x86_64-unknown-linux-musl.tar.gz
$ curl -LO https://github.com/Shaked98/avraham-sql-tools/releases/download/v$VERSION/SHA256SUMS
$ sha256sum --check --ignore-missing SHA256SUMS
sql-replay-0.3.0-x86_64-unknown-linux-musl.tar.gz: OK
$ tar xzf sql-replay-$VERSION-x86_64-unknown-linux-musl.tar.gz
$ sudo install -m755 sql-replay-$VERSION-x86_64-unknown-linux-musl/sql-replay /usr/local/bin/
```

(No sudo? Any directory on your `PATH` works — the binary is
self-contained: `install -m755 .../sql-replay ~/.local/bin/`.)

```console
$ sql-replay --version
sql-replay 0.3.0
```

## 2. Stand up a toy "production" MySQL 5.7

In a real migration this server is your production 5.7 (or its restored
twin). Here it's a container:

```console
$ docker run -d --name sqlreplay-demo-57 \
    -p 127.0.0.1:23306:3306 \
    -e MYSQL_ALLOW_EMPTY_PASSWORD=yes \
    mysql:5.7 --character-set-server=latin1 --collation-server=latin1_swedish_ci
$ until docker exec sqlreplay-demo-57 mysqladmin ping -h127.0.0.1 --silent 2>/dev/null; do sleep 2; done
mysqld is alive
```

Two things worth copying into real life:

- **The readiness loop matters.** The mysql images start a throwaway
  init-phase server first; connecting too early fails or hits the wrong
  instance. `mysqladmin ping` over TCP only succeeds once the real server
  is up.
- **The charset pin matters.** We'll start the 8.0 container with the
  same `--character-set-server`/`--collation-server` flags. Stock 8.0
  defaults to utf8mb4 while 5.7 defaults to latin1; tables created
  without an explicit charset inherit the server default, and an honest,
  unmodified 8.0 can then "regress" GROUP BYs on VARCHAR keys purely
  because its keys got 4x wider. Pin the charset (and other
  comparability-relevant settings) identically on both sides so `compare`
  measures the server, not your config drift — more in the
  [production notes](#10-taking-this-to-a-real-migration).

Now a small schema — a `shop` database with 1,000 customers and 100,000
orders, generated deterministically so both servers will hold
byte-identical data (that matters for `--checksum` later):

```console
$ cat > seed.sql <<'EOF'
CREATE DATABASE IF NOT EXISTS shop;
USE shop;

-- helper table for generating rows without stored procedures
CREATE TABLE digits (d INT PRIMARY KEY);
INSERT INTO digits VALUES (0),(1),(2),(3),(4),(5),(6),(7),(8),(9);

CREATE TABLE customers (
  id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(40) NOT NULL,
  email VARCHAR(60) NOT NULL,
  created_at DATE NOT NULL
) ENGINE=InnoDB;

-- 1,000 customers. The id is assigned explicitly (not left to
-- AUTO_INCREMENT): INSERT ... SELECT over a join returns rows in no
-- defined order, so auto-assigned ids would map to different names on
-- each server — a data difference --checksum would rightly flag.
INSERT INTO customers (id, name, email, created_at)
SELECT 1 + n, CONCAT('customer-', n), CONCAT('user', n, '@example.com'),
       DATE_ADD('2024-01-01', INTERVAL n % 365 DAY)
FROM (SELECT a.d*100 + b.d*10 + c.d AS n FROM digits a, digits b, digits c) seq;

CREATE TABLE orders (
  id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  customer_id INT NOT NULL,
  status VARCHAR(16) NOT NULL,
  order_date DATE NOT NULL,
  amount DECIMAL(10,2) NOT NULL,
  KEY idx_order_date (order_date),
  KEY idx_customer (customer_id)
) ENGINE=InnoDB;

-- 100,000 orders spread over 2025; every column derives from n, so both
-- servers hold identical data
INSERT INTO orders (id, customer_id, status, order_date, amount)
SELECT 1 + n, 1 + (n % 1000),
       ELT(1 + n % 3, 'new', 'shipped', 'returned'),
       DATE_ADD('2025-01-01', INTERVAL n % 365 DAY),
       10 + (n % 490) + (n % 100) / 100
FROM (
  SELECT a.d*10000 + b.d*1000 + c.d*100 + d.d*10 + e.d AS n
  FROM digits a, digits b, digits c, digits d, digits e
) seq;

ANALYZE TABLE customers, orders;
EOF
$ docker exec -i sqlreplay-demo-57 mysql -uroot < seed.sql
Table	Op	Msg_type	Msg_text
shop.customers	analyze	status	OK
shop.orders	analyze	status	OK
```

Finally, a dedicated application user. Running the workload as `app`
(never as root) lets replay cleanly separate application traffic from
admin noise later, with `--filter-user`:

```console
$ docker exec sqlreplay-demo-57 mysql -uroot -e \
    "CREATE USER 'app'@'%' IDENTIFIED BY 'app_pw'; GRANT SELECT, INSERT ON shop.* TO 'app'@'%';"
```

## 3. Capture the workload from the slow log

`capture` reads a slow query log that contains *every* statement, so
first turn that on (on a real 5.7, do this for a bounded window — the
log grows with query volume):

```console
$ docker exec sqlreplay-demo-57 mysql -uroot -e "
SET GLOBAL slow_query_log_file = '/var/lib/mysql/demo-slow.log';
SET GLOBAL log_output = 'FILE';
SET GLOBAL long_query_time = 0;
SET GLOBAL slow_query_log = ON;"
```

Now the workload: three concurrent client sessions, standing in for
three application connections. Session 1 does customer point lookups
plus a few INSERTs, session 2 runs a daily-revenue report that uses
`idx_order_date`, session 3 breaks down order status per customer
segment:

```console
$ # session 1: customer point lookups, plus a few writes
$ for i in $(seq 1 40); do
    echo "SELECT id, name, email FROM customers WHERE id = $(( (i * 37) % 1000 + 1 ));"
  done > session-1.sql
$ for i in $(seq 1 10); do
    echo "INSERT INTO orders (customer_id, status, order_date, amount) VALUES ($i, 'new', '2025-07-01', 99.90);"
  done >> session-1.sql

$ # session 2: daily-revenue report (uses idx_order_date today)
$ for i in $(seq 1 30); do
    d=$(printf '2025-%02d-%02d' $(( i % 12 + 1 )) $(( i % 28 + 1 )))
    echo "SELECT COUNT(*), SUM(amount) FROM orders WHERE order_date = '$d';"
  done > session-2.sql

$ # session 3: per-segment status breakdown
$ for i in $(seq 1 20); do
    lo=$(( (i * 41) % 900 + 1 ))
    echo "SELECT status, COUNT(*) AS cnt FROM orders WHERE customer_id BETWEEN $lo AND $(( lo + 100 )) GROUP BY status;"
  done > session-3.sql

$ # run all three sessions concurrently as the app user
$ for s in 1 2 3; do
    docker exec -i -e MYSQL_PWD=app_pw sqlreplay-demo-57 mysql -uapp shop < session-$s.sql > /dev/null &
  done; wait
```

Turn the log off and copy it out of the container:

```console
$ docker exec sqlreplay-demo-57 mysql -uroot -e \
    "SET GLOBAL slow_query_log = OFF; SET GLOBAL long_query_time = 10;"
$ docker cp sqlreplay-demo-57:/var/lib/mysql/demo-slow.log demo-slow.log
```

Convert it into a compressed, replayable capture file:

```console
$ sql-replay capture --input demo-slow.log --out capture.jsonl.zst
captured 104 events / 4 sessions / 5 fingerprints (dialect: mysql-5.7, admin commands ignored: 0) in 0.00s -> capture.jsonl.zst
```

Read that summary line carefully — it already teaches three things:

- **104 events, not 100.** We wrote 100 statements, but the mysql client
  sends `select @@version_comment limit 1` on every connection (3 more),
  and the root session that toggled the slow log got captured too. Slow
  logs record *everything* that ran, including your own admin traffic.
- **4 sessions, not 3.** That root admin session is the 4th. We'll
  exclude it at replay time with `--filter-user app` — captures stay
  complete artifacts; filtering happens on replay.
- **5 fingerprints.** A fingerprint is a normalized query class:
  literals are collapsed (`WHERE id = 38` and `WHERE id = 75` are the
  same fingerprint, `where id = ?`), whitespace/case normalized, IN/VALUES
  lists collapsed to `?+`. All latency stats and regression verdicts are
  per fingerprint.

> **Alternative: capture from the wire (pcap).** If you can't enable the
> slow log (managed instance, log-volume concerns), record the MySQL
> traffic with plain tcpdump instead —
> `sudo timeout 60 tcpdump -i any port 3306 -w traffic.pcap -s 0` — and
> feed `traffic.pcap` to the same `sql-replay capture` command; the
> output format is identical and everything below works unchanged. The
> wire also gives you true arrival timestamps (better `--speed 1.0`
> fidelity) and decodes prepared statements. Its hard limit: TLS
> connections are opaque (skipped and counted), so it needs a plaintext
> segment. This walkthrough doesn't exercise the pcap path; see
> ["Capturing from the wire instead"](../README.md#capturing-from-the-wire-instead-pcap)
> in the README before choosing it.

## 4. Stand up the 8.0 candidate — and sabotage it

The candidate gets the *same* pinned charset, plus `--disable-log-bin`:
8.0 enables the binlog by default and 5.7 doesn't, and that asymmetry
would tax every write on the candidate. Load the identical dataset:

```console
$ docker run -d --name sqlreplay-demo-80 \
    -p 127.0.0.1:23307:3306 \
    -e MYSQL_ALLOW_EMPTY_PASSWORD=yes \
    mysql:8.0 --character-set-server=latin1 --collation-server=latin1_swedish_ci --disable-log-bin
$ until docker exec sqlreplay-demo-80 mysqladmin ping -h127.0.0.1 --silent 2>/dev/null; do sleep 2; done
mysqld is alive
$ docker exec -i sqlreplay-demo-80 mysql -uroot < seed.sql
Table	Op	Msg_type	Msg_text
shop.customers	analyze	status	OK
shop.orders	analyze	status	OK
```

A faithful migration of this toy schema would show little movement, so
plant a regression to give `compare` something to catch — drop the index
the revenue report depends on, standing in for the real things you're
hunting (optimizer plan changes, config drift, a migration script that
missed an index):

```console
$ docker exec sqlreplay-demo-80 mysql -uroot -e \
    "ALTER TABLE shop.orders DROP INDEX idx_order_date;"
```

## 5. Replay against both servers

Replay the capture first against 5.7 (the baseline), then against 8.0
(the candidate). Same capture, same flags — only the URL differs:

```console
$ sql-replay replay --capture capture.jsonl.zst --url mysql://root@127.0.0.1:23306/ \
    --filter-user app --out run-5.7.json
2026-07-16T10:59:59.195139Z  INFO sql_replay::replay: capture spooled for replay events=103 filtered=1 sessions=3 spool_mb=0
Replayed 103 events across 3 sessions in 0.17s — 563.6 QPS
  executed: 93  skipped: 10  errors: 0  not run: 0  connect failures: 0
  filtered out before replay: 1 events
Target: 5.7.44 (mysql://root@127.0.0.1:23306/)

Top 10 fingerprints by p95 latency:
   count   errs    p50(ms)    p95(ms)    p99(ms)    max(ms)  fingerprint
      20      0      9.623      9.943     10.207     10.207  select status, count(*) as cnt from orders where customer_id between ? and ? gro…
      30      0      0.306      0.384      0.470      0.470  select count(*), sum(amount) from orders where order_date = ?
       3      0      0.138      0.168      0.168      0.168  select @@version_comment limit ?
      40      0      0.111      0.159      0.196      0.196  select id, name, email from customers where id = ?
wrote run report to run-5.7.json
```

The accounting line is the important part:

- **executed: 93** — replay runs one concurrent session per captured
  connection, preserving each session's query order.
- **skipped: 10** — the INSERTs. Replay is **read-only by default**:
  anything not provably a read is skipped and counted, and only runs if
  you pass `--allow-writes` (do that against disposable targets only —
  it mutates data as it goes).
- **filtered out before replay: 1** — the root admin session's event,
  excluded by `--filter-user app`.

Now the candidate:

```console
$ sql-replay replay --capture capture.jsonl.zst --url mysql://root@127.0.0.1:23307/ \
    --filter-user app --out run-8.0.json
2026-07-16T10:59:59.370705Z  INFO sql_replay::replay: capture spooled for replay events=103 filtered=1 sessions=3 spool_mb=0
Replayed 103 events across 3 sessions in 0.22s — 424.4 QPS
  executed: 93  skipped: 10  errors: 0  not run: 0  connect failures: 0
  filtered out before replay: 1 events
Target: 8.0.46 (mysql://root@127.0.0.1:23307/)

Top 10 fingerprints by p95 latency:
   count   errs    p50(ms)    p95(ms)    p99(ms)    max(ms)  fingerprint
      30      0      7.199      7.751      7.915      7.915  select count(*), sum(amount) from orders where order_date = ?
      20      0      6.391      7.359      8.359      8.359  select status, count(*) as cnt from orders where customer_id between ? and ? gro…
      40      0      0.112      0.196      0.255      0.255  select id, name, email from customers where id = ?
       3      0      0.119      0.156      0.156      0.156  select @@version_comment limit ?
wrote run report to run-8.0.json
```

The revenue report jumped from 0.38ms to 7.8ms p95 — the dropped index,
now scanning 100k rows per query. You could eyeball that here, with five
fingerprints. `compare` exists because you can't at five hundred.

By default replay runs at maximum pressure (each session fires its next
query as soon as the previous completes). `--speed 1.0` honors the
capture's original timeline instead, and `--warmup --repeat 3` runs an
unrecorded warm-up pass plus three measured passes with a median-
aggregated report — both worth using for real measurements; both omitted
here to keep the toy loop fast.

## 6. Compare the runs

```console
$ sql-replay compare --baseline run-5.7.json --candidate run-8.0.json \
    --json report.json --out report.html
Comparing runs:
   baseline: run-5.7.json — target 5.7.44 (mysql://root@127.0.0.1:23306/)
  candidate: run-8.0.json — target 8.0.46 (mysql://root@127.0.0.1:23307/)

!!! COMPARABILITY WARNINGS — the runs may not be directly comparable !!!
  - target server settings differ: sql_mode (see settings diff)

Target settings diff (baseline -> candidate):
  sql_mode: ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION -> ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION

Totals: QPS 563.6 -> 424.4 (-24.7%) | wall 0.17s -> 0.22s (+32.8%) | executed 93 -> 93 | errors 0 -> 0 (+0)
Fingerprints: 5 matched (0 within threshold), 0 only in baseline, 0 only in candidate, 0 with executed-count mismatch

Regressions (p95 +20% or worse, count >= 5 in both runs): 2
p95 base(ms) p95 cand(ms)      Δp95     Δmean   count b/c  fingerprint
       0.384        7.751  +1918.5%  +2165.0%       30/30  select count(*), sum(amount) from orders where order_date = ?
       0.159        0.196    +23.3%     -0.4%       40/40  select id, name, email from customers where id = ?

Improvements (p95 -20% or better): 1
p95 base(ms) p95 cand(ms)      Δp95     Δmean   count b/c  fingerprint
       9.943        7.359    -26.0%    -20.4%       20/20  select status, count(*) as cnt from orders where customer_id between ?…

Low-sample fingerprints (count < 5 in either run, excluded from the ranking): 2
p95 base(ms) p95 cand(ms)      Δp95     Δmean   count b/c  fingerprint
       0.000        0.000       n/a       n/a         0/0  insert into orders (customer_id, status, order_date, amount) values (?…
       0.168        0.156     -7.1%     -7.1%         3/3  select @@version_comment limit ?

wrote JSON report to report.json
wrote HTML report to report.html
FAIL: 2 fingerprint(s) regressed >= 20% on p95 (exit code 2)
$ echo $?
2
```

Walking through it, top to bottom:

- **Comparability warnings** come first because they change how much to
  trust everything below. Here `compare` noticed the two targets run
  different `sql_mode`s. This particular diff appears in *every* stock
  5.7-vs-8.0 pair — 8.0 removed `NO_AUTO_CREATE_USER` — and is benign;
  a diff in `character_set_server` or `innodb_buffer_pool_size` would
  not be. The warning block is also where aborted runs, capture
  mismatches, and executed-count mismatches get flagged.
- **Fingerprints are matched across runs by normalized query text**, so
  the comparison survives capture-local ids and literal churn.
- **Regressions** are ranked worst-Δp95 first, gated by two knobs:
  `--threshold-pct` (default 20 — the Δp95 a fingerprint must reach) and
  `--min-count` (default 5 — executions required *in both runs* to be
  ranked at all; below it a fingerprint drops to the low-sample section,
  which is why the 3-per-run `@@version_comment` and the never-executed
  INSERT class sit there).
- The planted regression is unmissable: **+1918.5%** on p95.
- The second "regression" is a lesson, not a bug: the point-lookup class
  "regressed" +23.3% on p95 — which is 37 *microseconds* — while its
  Δmean is **−0.4%**. Sub-millisecond fingerprints flap at a 20%
  threshold from scheduler noise alone (and 8.0's per-query overhead is
  genuinely a bit higher). When Δp95 and Δmean disagree wildly on a
  sub-ms class, suspect noise; gate on thresholds that represent real
  pain.
- **Improvements are ranked too** (the GROUP BY got 26% faster on 8.0) —
  a migration report is not only bad news.
- **Exit code 2** is the machine-readable verdict: `0` = no regression
  at/beyond the threshold, `2` = at least one (also used for correctness
  failures, below), `1` = tool error. CI can gate a migration on it
  directly.

Retuned for this workload — a 50% threshold and a slightly higher sample
floor — the gate flags exactly the planted regression and nothing else:

```console
$ sql-replay compare --baseline run-5.7.json --candidate run-8.0.json \
    --threshold-pct 50 --min-count 10 --json report.json --out report.html
```

```text
(same shape as above, trimmed to the verdict)
Regressions (p95 +50% or worse, count >= 10 in both runs): 1
p95 base(ms) p95 cand(ms)      Δp95     Δmean   count b/c  fingerprint
       0.384        7.751  +1918.5%  +2165.0%       30/30  select count(*), sum(amount) from orders where order_date = ?
...
FAIL: 1 fingerprint(s) regressed >= 50% on p95 (exit code 2)
```

`report.html` is the same data as a **self-contained HTML page** (inline
CSS/JS, renders offline — safe to email or attach to a ticket) with a
sortable per-fingerprint table and both runs' metadata side by side;
`report.json` is the same data for machines. One note on version drift:
v0.4.0 adds per-fingerprint result-set byte stats and per-size-decade
regression checks, which put a result-bytes column in every fingerprint
table in this walkthrough (`replay`, `baseline`, and `compare` — terminal
output and reports alike) and a size-decade section in `compare`'s
output; the v0.3.0 binary this walkthrough was executed against produces
output exactly as shown here.

## 7. No replayable 5.7? Use the recorded baseline

Replaying against production 5.7 is often off the table. The slow log
already recorded every statement's server-side `Query_time`, and the
capture carries it — so `baseline` builds the baseline report from the
capture alone, no 5.7 target needed:

```console
$ sql-replay baseline --capture capture.jsonl.zst --filter-user app --out baseline.json
Recorded 103 events across 3 sessions in 0.00s — 0.0 QPS
  executed: 103  skipped: 0  errors: 0  not run: 0  connect failures: 0
  filtered out before replay: 1 events
Latencies: recorded in the source capture (slow-log Query_time, or request→response wire time for pcap captures; no replay target — the capture carries no error information, so errors are 0 by definition)

Top 10 fingerprints by p95 latency:
   count   errs    p50(ms)    p95(ms)    p99(ms)    max(ms)  fingerprint
      20      0      9.327      9.671      9.711      9.711  select status, count(*) as cnt from orders where customer_id between ? and ? gro…
      30      0      0.349      1.021      1.181      1.181  select count(*), sum(amount) from orders where order_date = ?
      10      0      0.371      0.998      0.998      0.998  insert into orders (customer_id, status, order_date, amount) values (?+)
       3      0      0.057      0.063      0.063      0.063  select @@version_comment limit ?
      40      0      0.023      0.045      0.191      0.191  select id, name, email from customers where id = ?
wrote baseline report to baseline.json
```

(The `0.00s — 0.0 QPS` is a toy artifact: the report's timeline is the
capture's own first-to-last event span, and our whole workload fit
inside one second. A real capture shows production's span and QPS. Note
the INSERT class *is* included here — `baseline` executes nothing
against any server, so there is no write gate to skip it, and "executed"
means "aggregated from the recording". Errors are 0 by definition: the
slow log records none.)

Comparing recorded-vs-replayed prints the loudest warning in the tool:

```console
$ sql-replay compare --baseline baseline.json --candidate run-8.0.json \
    --threshold-pct 50 --min-count 10
Comparing runs:
   baseline: baseline.json — recorded (slow log) latencies from capture capture.jsonl.zst
  candidate: run-8.0.json — target 8.0.46 (mysql://root@127.0.0.1:23307/)

!!! COMPARABILITY WARNINGS — the runs may not be directly comparable !!!
  - MEASUREMENT PLANES DIFFER: the baseline latencies were recorded in the source capture — server-side slow-log Query_time (measured under live production load, including lock waits and contention) or request→response wire time for pcap captures (server plus the capture-point→server network path) — while the candidate latencies are client-side wall times measured by replay from the test host (including network round-trip and driver overhead). Deltas mix real server changes with this measurement gap — use a generous --threshold-pct and treat small deltas as noise
  - 1 matched fingerprint(s) executed a different number of times in the two runs — their latency populations may not be comparable

Target settings: settings diff skipped: the baseline run records no target settings (recorded from the slow log)

Totals: QPS 0.0 -> 424.4 (n/a) | wall 0.00s -> 0.22s (n/a) | executed 103 -> 93 | errors 0 -> 0 (+0)
Fingerprints: 5 matched (1 within threshold), 0 only in baseline, 0 only in candidate, 1 with executed-count mismatch

Regressions (p95 +50% or worse, count >= 10 in both runs): 2
p95 base(ms) p95 cand(ms)      Δp95     Δmean   count b/c  fingerprint
       1.021        7.751   +659.2%  +1645.0%       30/30  select count(*), sum(amount) from orders where order_date = ?
       0.045        0.196   +335.6%   +289.0%       40/40  select id, name, email from customers where id = ?

Improvements (p95 -50% or better): 0

Low-sample fingerprints (count < 10 in either run, excluded from the ranking): 2
p95 base(ms) p95 cand(ms)      Δp95     Δmean   count b/c  fingerprint
       0.063        0.156   +147.6%   +133.5%         3/3  select @@version_comment limit ?
       0.998        0.000   -100.0%   -100.0%        10/0  insert into orders (customer_id, status, order_date, amount) values (?…  [count mismatch]

FAIL: 2 fingerprint(s) regressed >= 50% on p95 (exit code 2)
```

This output *is* the lesson in comparing across measurement planes:

- The planted regression still screams (+659%) — real regressions
  survive the plane change.
- The point-lookup class shows +335%: recorded server-side time was
  45µs, replayed client-side wall time is 196µs — the difference is
  mostly network round-trip and driver overhead, not the server. This is
  exactly why the warning says to use a generous `--threshold-pct`
  (think 50+, sized so only real pain trips it) and treat small
  absolute deltas as noise.
- The INSERT class is flagged `[count mismatch]` — 10 recorded, 0
  replayed (write-gated) — and its populations aren't compared.

For a real recorded-baseline gate, also replay the twin with
`--speed 1.0` so it faces production's original concurrency, and use a
twin with hardware identical to production — a weaker test host shifts
every delta.

## 8. Correctness, not just latency: `--checksum`

A migration can return *wrong answers* long before it returns slow ones
(collation changes reorder comparisons, sql_mode changes alter implicit
casts, optimizer bugs drop rows). `replay --checksum` checksums every
read's full result set, order-insensitively, and `compare` diffs the
digests. Both runs need the flag, and both targets must hold identical
data:

```console
$ sql-replay replay --capture capture.jsonl.zst --url mysql://root@127.0.0.1:23306/ \
    --filter-user app --checksum --out run-5.7-checksum.json
$ sql-replay replay --capture capture.jsonl.zst --url mysql://root@127.0.0.1:23307/ \
    --filter-user app --checksum --out run-8.0-checksum.json
$ sql-replay compare --baseline run-5.7-checksum.json --candidate run-8.0-checksum.json \
    --threshold-pct 50 --min-count 10
```

```text
(trimmed to the correctness section)
Result correctness (--checksum): 4 fingerprints checked, 3 matched, 0 MISMATCHED, 1 advisory
  note: result checksums diverge meaningfully only when both runs executed against identical data; nondeterministic queries (volatile functions, LIMIT without ORDER BY, server-state reads) are listed as advisory
  advisory (nondeterministic — diff advisory only):
    digest 27738df92133d581 -> 7b8400631fd34a8a | rows 3 -> 3 | events 3/3  select @@version_comment limit ?
```

All three deterministic read classes returned identical data on both
servers. The one *advisory* divergence is genuine but expected:
`@@version_comment` really does return different strings on 5.7 and 8.0,
and the classifier demoted it because `@@variables` are server state,
not data. A divergence on a *deterministic* fingerprint would be listed
as `MISMATCH` and set exit code 2, same as a latency regression — a
wrong answer is worse than a slow one. Read the mismatch list as
"investigate", not "guaranteed bug" (the nondeterminism classifier is a
token scan; volatility hidden inside views is invisible to it).

One latency caveat: checksumming drains every result set fully, so a
`--checksum` run's latencies are not comparable to a plain run's
(`compare` warns if you mix them). For a real gate, run one plain pair
for latency and one checksummed pair for correctness.

## 9. Clean up

```console
$ docker rm -f sqlreplay-demo-57 sqlreplay-demo-80
```

The capture, run reports, and HTML/JSON reports are plain files in your
working directory — keep them; captures especially are complete,
reusable artifacts (filters like `--filter-user` and `--time-window`
re-slice them at replay time, no recapture needed).

## 10. Taking this to a real migration

Everything above scales to production captures with millions of events;
these are the knobs that start mattering:

- **`--filter-user`** — as seen in step 3, slow logs capture *everyone*:
  monitoring agents, backup jobs, your own admin session toggling the
  log. Run applications under dedicated MySQL users and filter replay to
  them, or the admin noise becomes replayed load.
- **`--max-connections`** — replay opens one concurrent connection per
  captured session. A production capture can hold tens of thousands of
  sessions; cap it (replay applies backpressure, and warns if the cap
  saturates enough to distort results — and fails up front if the cap
  can't fit under `ulimit -n`). For captures whose session counts exceed
  any practical cap, `--pool N` multiplexes instead, trading session
  fidelity for feasibility.
- **`--spool-dir`** — replay streams the capture into an on-disk spool
  roughly the size of the *uncompressed* capture, in the system temp dir
  by default. On many distros `/tmp` is tmpfs (RAM-backed): point
  `--spool-dir` at real disk or the spool silently becomes memory.
- **`max_allowed_packet`** — replayed statements are as long as
  production's were. Make the target's `max_allowed_packet` at least the
  source's, or the biggest INSERTs error only on the candidate and skew
  the comparison.
- **Pin comparability-relevant settings on both servers** — charset and
  collation above all, as in step 2. This repo's own verification rig
  additionally pins `tmp_table_size`/`max_heap_table_size` because
  stock 8.0 spills a GROUP BY temp table to disk that 5.7 keeps in
  memory under identical defaults; see
  ["Why the server config is pinned"](../verify/README.md#why-the-server-config-is-pinned-on-every-container)
  for the measurements — and the executed
  [benchmark writeups](benchmarks/2026-07-16-mysql80-general.md) for
  what stock defaults cost on a real workload (stock defaults made a
  GROUP BY class ~5x slower on 8.0 — the utf8mb4 default widening the
  grouping keys, compounded by 8.0's temp-table spill behavior).
  `compare`'s settings diff (it records `sql_mode`,
  charset/collation, buffer pool size, and transaction isolation from
  each target) is your safety net when something slips through — read
  it before trusting any verdict.

## 11. Troubleshooting: first-run gotchas

Every one of these was hit (or nearly hit) while building this guide:

- **`--checksum` flags a MISMATCH immediately, on a class that can't be
  wrong** — check how the two targets were loaded before blaming the
  server. Loading each side with a logical script whose
  `INSERT ... SELECT` has no defined order (or any `AUTO_INCREMENT`
  assignment that depends on it) produces *genuinely different data* per
  server; the checksum is telling the truth. Restore both targets from
  the same physical backup/snapshot, or make the load deterministic (the
  demo seed assigns ids explicitly for exactly this reason).
- **A sub-millisecond fingerprint "regresses" at the default threshold**
  — 20% of 150µs is scheduler noise, and 8.0's per-query overhead is
  genuinely a little higher than 5.7's. Compare Δp95 against Δmean
  (they'll disagree wildly on noise), and size `--threshold-pct`/
  `--min-count` so the gate only trips on real pain. The
  [benchmark writeups](benchmarks/2026-07-16-mysql80-hugetext.md) hit
  this repeatedly: every flagged sub-ms class was 0.05–0.8 ms absolute.
- **The capture contains sessions you never wrote** — client startup
  queries (`select @@version_comment limit 1` on every connection) and
  your own admin session. Expected; that's what `--filter-user` is for.
- **Connecting to a fresh mysql container fails or behaves oddly** — the
  official images run a temporary init server before the real one. Poll
  with `mysqladmin ping` (as in steps 2 and 4) before capturing or
  replaying.
- **The slow log is empty or missing** — check `log_output` is `FILE`
  (it can be `TABLE`, which `capture` doesn't read), confirm
  `slow_query_log_file`'s path, and remember `long_query_time = 0` is
  required to log every statement, not just slow ones.
- **The sql_mode warning shows up in every 5.7 → 8.0 compare** — stock
  8.0 dropped `NO_AUTO_CREATE_USER` from the default `sql_mode`, so this
  one diff is expected. Any *other* settings diff deserves a real look.
