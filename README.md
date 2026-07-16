# avraham-sql-tools

[![CI](https://github.com/Shaked98/avraham-sql-tools/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Shaked98/avraham-sql-tools/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Modern SQL tooling.

- **sql-replay** — multi-threaded MySQL query-replay benchmarking tool for
  5.7 → 8.0 migration testing (maintained successor to the abandoned Percona
  Playback; unlike pt-upgrade it replays at the original concurrency).

## sql-replay

Replay real production load captured on MySQL 5.7 against MySQL 8.0 (or any
other target) to find performance regressions before cutover.

### Installation

Prebuilt binaries are published on the
[GitHub releases page](https://github.com/Shaked98/avraham-sql-tools/releases).
Each release carries a fully static `x86_64-unknown-linux-musl` tarball
(runs on any x86_64 Linux — no glibc, OpenSSL, or other runtime
dependency), a prebuilt RPM for RHEL 8-family hosts, and a `SHA256SUMS`
file. This README documents the code on `main`; check a release's notes
for what its tag includes.

```console
$ VERSION=0.3.0   # the latest release tag, without the leading v
$ curl -LO https://github.com/Shaked98/avraham-sql-tools/releases/download/v$VERSION/sql-replay-$VERSION-x86_64-unknown-linux-musl.tar.gz
$ curl -LO https://github.com/Shaked98/avraham-sql-tools/releases/download/v$VERSION/SHA256SUMS
$ sha256sum --check --ignore-missing SHA256SUMS
$ tar xzf sql-replay-$VERSION-x86_64-unknown-linux-musl.tar.gz
$ sudo install -m755 sql-replay-$VERSION-x86_64-unknown-linux-musl/sql-replay /usr/local/bin/
```

On RHEL/Rocky/Alma/Oracle 8+ the RPM works too:

```console
$ sudo dnf install ./sql-replay-$VERSION-1.x86_64.rpm
```

To build from source instead, install stable Rust (plus a C compiler —
zstd is the tree's one C dependency) and run:

```console
$ cargo build --release          # binary at target/release/sql-replay
```

### Quickstart

Capture production load on the source server, replay it against the
migration target, and diff the two runs:

```console
$ # 1. convert a slow query log (or a tcpdump .pcap) into a capture file
$ sql-replay capture --input /var/lib/mysql/slow.log --out capture.jsonl.zst

$ # 2. replay the capture against each server
$ sql-replay replay --capture capture.jsonl.zst \
    --url mysql://bench@mysql57-host:3306/ --out run-5.7.json
$ sql-replay replay --capture capture.jsonl.zst \
    --url mysql://bench@mysql80-host:3306/ --out run-8.0.json

$ # 3. rank per-fingerprint latency regressions (exit code 2 = regression)
$ sql-replay compare --baseline run-5.7.json --candidate run-8.0.json \
    --out report.html
```

When the source server can't be replayed against (it *is* production),
`sql-replay baseline` builds the baseline report from the capture's
recorded latencies instead — see below. The rest of this document covers
each step in depth.

### Scope

M1 shipped `capture` and `replay`; M2 added faithful-timing pacing
(`--speed`) and the `compare` subcommand for run-to-run regression diffs.
M3 made replay production-scale (bounded memory independent of capture
size, thousands of concurrent sessions, warmup/repeat/filter/abort
controls, an optional connection pool) and deployable on RHEL 8 (static
musl binary, RPM spec, release workflow). 0.2.0 added `baseline`: build
the baseline report from the capture's *recorded* production latencies
when the source server cannot be replayed against. M4 (0.3.0, the final
planned milestone) added a second capture source — **pcap network
captures** recorded with plain tcpdump — and **result-correctness
diffing** (`replay --checksum` + a correctness section in `compare`).
0.4.0 added **result-set byte stats and size-decade splits** per
fingerprint, so `compare` can flag a regression that only affects big
rows instead of averaging it away inside a mixed-size fingerprint.

### Supported source and target servers

Capture reads MySQL-family slow logs (5.6/5.7/8.0, Percona, MariaDB) and
pcap captures of the MySQL wire protocol. Replay targets anything that
speaks the MySQL protocol; **MySQL 5.7, MySQL 8.0 and MariaDB (verified
against 10.11 LTS, the RHEL 8 AppStream migration candidate)** are
exercised by the test suite and the real-data verification rig — for
MariaDB that includes `--checksum` result-correctness diffing and the
planted-regression detection ground truth, cross-engine. The settings
snapshot tolerates engine differences (variables absent on one side are
simply not recorded; MariaDB's `tx_isolation` is canonicalized to
`transaction_isolation` like 5.7's), and `compare` labels a cross-engine
pair with a "target engine families differ" comparability warning so
settings deltas read as engine defaults to review, not noise.

### Capturing load on the source server

`capture` reads a MySQL **slow query log** that contains *every* query. On
the source (e.g. 5.7.42) enable:

```sql
SET GLOBAL slow_query_log = ON;
SET GLOBAL long_query_time = 0;          -- log every statement
SET GLOBAL log_slow_admin_statements = ON; -- include ALTER/ANALYZE/OPTIMIZE
-- optionally: SET GLOBAL log_timestamps = UTC;
```

Then convert the log into a compressed replay file:

```console
$ sql-replay capture --input /var/lib/mysql/slow.log --out capture.jsonl.zst
captured 6 events / 4 sessions / 5 fingerprints (dialect: mysql-5.7, admin commands ignored: 1) in 0.00s -> capture.jsonl.zst
```

Both the legacy (`# Time: YYMMDD HH:MM:SS`, written by MySQL 5.6/older and
MariaDB) and modern (RFC 3339 `# Time:`, written since MySQL 5.7.2, plus the
8.0 `log_slow_extra` fields) slow-log dialects are parsed, as are
Percona/MariaDB-style `# Thread_id: ... Schema: ...` lines and MariaDB's
`log_slow_verbosity` annotation lines (`# Rows_affected:`, `# Full_scan:`,
`# explain:`). The recorded dialect
label comes from the server-restart banner when the log contains one (a
banner naming MariaDB labels the log `mariadb`);
otherwise it is inferred from the timestamp format (`mysql-5.6-or-older` /
`mysql-5.7-or-newer`, refined to `mysql-8.0` when `log_slow_extra` fields
are present — MariaDB kept the legacy format, so a banner-less MariaDB
log honestly reports the `mysql-5.6-or-older` bound), and `--dialect`
overrides the label either way. The capture file is zstd-compressed
JSONL: a header record, one event per query
(`ts_micros`, `session_id`, `user`, `db`, `query`, `orig_query_time_s`,
`fingerprint_id`), and a summary record with the fingerprint table
(pt-query-digest-style normalized query classes).

### Capturing from the wire instead (pcap)

When the slow log can't be enabled (permissions, log-volume concerns, a
managed instance), `capture` can read a **tcpdump network capture** of the
MySQL traffic instead. Record on the database host (or anywhere on the
plaintext path between clients and server):

```console
$ # 60 seconds of production traffic, full packets (-s 0 is required —
$ # snaplen-truncated packets break statement decoding and are counted):
$ sudo timeout 60 tcpdump -i any port 3306 -w traffic.pcap -s 0
$ # or bound by file size instead: -C 1000 -W 1 caps it at ~1 GB
```

then convert it exactly like a slow log — pcap files are detected by
magic bytes (`--format pcap` forces it; `--port` for non-3306 servers):

```console
$ sql-replay capture --input traffic.pcap --out capture.jsonl.zst
captured 17 events / 4 sessions / 9 fingerprints (dialect: pcap:8.0.36, admin commands ignored: 0) in 0.01s -> capture.jsonl.zst
pcap: 196 packets, 4 connections (4 decoded, 0 TLS-skipped, 0 compressed-skipped, 0 mid-stream-skipped, 0 broken); prepared statements: 7 expanded, 0 inexpandable; 0 responses missing; server version(s): 8.0.36
```

The output is the *same* capture format the slow-log path emits — replay,
baseline, and compare don't care which source it came from. Legacy pcap
(micro- and nanosecond) and pcap-ng files both work, as do `-i any`
captures (Linux SLL/SLL2), VLAN-tagged ethernet, IPv6, out-of-order and
retransmitted segments.

What the wire gives you that the slow log can't:

- **True arrival timestamps.** Each event's timestamp is the request
  packet's pcap timestamp, so `--speed 1.0` replay reproduces the exact
  wire concurrency (slow logs only record query *completion* times).
- **Recorded latency for free:** the request→first-response gap is stored
  as the event's original latency, so `sql-replay baseline` works on pcap
  captures too. Note the measurement point: this is server processing
  *plus* the network path between capture point and server (capturing on
  the DB host itself makes that gap ≈ server time), whereas the slow
  log's `Query_time` is purely server-side.
- **Prepared statements** (binary protocol) are decoded and expanded into
  replayable SQL text with the bound parameter values interpolated —
  best-effort for standard types; executions that can't be expanded
  (statement prepared before the capture started, exotic parameter
  encodings) are counted and reported, never silently dropped.

Honest limits — every one of these is *counted* in the capture summary
(`summary.pcap` in the file, warnings on stderr), never silent:

- **TLS traffic is opaque and unsupported.** A connection that negotiates
  TLS is skipped and counted; capture on a plaintext segment or disable
  TLS for the capture window. Compressed-protocol connections are
  likewise skipped and counted.
- Connections whose handshake predates the capture start (mid-stream) are
  skipped and counted — the decoder can't join a binary stream midway.
  Statements still in flight when the capture ends get latency 0 and a
  `responses_missing` count.
- Overhead: tcpdump itself costs a few percent CPU under high packet
  rates, and the pcap file grows with *traffic volume* (result sets
  included), not query count — bound the capture with `timeout`/`-C`. The
  slow-log path costs the server less on busy read workloads; the pcap
  path costs zero server *configuration*.

### Replaying against the target

```console
$ sql-replay replay \
    --capture capture.jsonl.zst \
    --url mysql://user:pass@target-host:3306/ \
    --max-connections 50 \
    --out run.json
```

- One concurrent session per original connection (thread id), preserving
  per-session query order; `--max-connections` caps concurrency with
  backpressure. If the cap is saturated for a significant share of the run,
  a warning is printed (results would reflect the cap, not the server).
- **Memory is bounded and independent of capture size.** Replay never
  materializes the capture: it is streamed twice into an on-disk *spool*
  (one contiguous region per session, unlinked temp file, roughly the
  uncompressed capture size — `--spool-dir` picks where), and each session
  reads its own events one at a time. A 5M-event / 20k-session replay peaks
  around ~35 MiB of RSS; memory scales with session count, not event count.
  Note the default spool location is the system temp dir, which is tmpfs
  (RAM-backed) on some distros — point `--spool-dir` at real disk there,
  or the spool itself occupies memory.
- **Memory model on big rows:** result sets are never buffered — rows are
  read, processed, and dropped one at a time (also under `--checksum`) —
  but each *connection* mid-fetch briefly holds its current row about
  three times over (wire packet + decoded row + buffer-growth transients).
  Peak RSS is therefore roughly
  `base + concurrent connections x 3 x largest row`
  (measured: ~170 MiB for 12 sessions concurrently scanning 4 MiB-row
  result sets; `tests/blob_memory.rs` enforces the bound in CI). For
  blob-heavy captures with many sessions, **use `--pool N`**: in-flight
  rows are then bounded by the pool, not the session count (the same
  12-session workload over `--pool 2` peaks at ~41 MiB). The binary also
  pins allocator/driver buffer retention (`src/memtune.rs`) so freed
  multi-MB row buffers return to the OS instead of accumulating —
  overridable via the `MYSQL_ASYNC_BUFFER_SIZE_CAP` and
  `MALLOC_MMAP_THRESHOLD_` environment variables; the cost is a page-fault
  tax of roughly a millisecond per 15 MB row on fetches of multi-MB rows
  (identical on both sides of a `compare` pair, so ratios are unaffected).
- If the connection cap cannot fit under the process's open-files limit,
  replay fails up front with the `ulimit -n` / systemd `LimitNOFILE=` value
  to raise.
- **Safety:** non-read statements (anything but SELECT / SHOW / EXPLAIN /
  DESCRIBE / HELP / session-level SET / USE) are skipped and counted unless
  you explicitly pass `--allow-writes`.
  `SET GLOBAL`/`SET PERSIST`/`SET PASSWORD`/`SET DEFAULT ROLE`,
  `EXPLAIN ANALYZE` over DML (8.0 actually executes the statement),
  `SELECT ... INTO OUTFILE`/`DUMPFILE` (writes files on the server), and
  multi-statement text (a `;` followed by more SQL) also count as writes.
  MySQL executes the contents of `/*! ... */` version-conditional comments,
  so they are classified as real content (`/*!50700 UPDATE ... */` is a
  write); ordinary comments stay inert.
  `--read-only` makes the default explicit (and conflicts with
  `--allow-writes`). Replay against a disposable target when using
  `--allow-writes`.
- `--db-override <db>` replays everything against one database instead of
  the captured per-session databases; captured `USE` statements are then
  skipped (and counted as skipped) so sessions stay pinned to the override.
- `run.json` carries run metadata (target server version, flags, wall
  clock, QPS, saturation) plus per-fingerprint stats (count, errors with a
  first-error sample, skipped/not-run counts, p50/p95/p99/max/mean latency
  in µs, and the result-set byte stats described under "Result-set size
  stats" below); stdout
  gets a top-N slowest-fingerprints table (`--top`, default 10). It also
  records comparability-relevant target settings (`sql_mode`,
  `character_set_server`, `collation_server`, `innodb_buffer_pool_size`,
  and the transaction isolation level — read via `SHOW VARIABLES`, tolerant
  of the 5.7/8.0 `tx_isolation`/`transaction_isolation` rename) so
  `compare` can flag differently-configured targets.

### Pacing (`--speed`)

By default (`--speed max`) each session fires its next query as soon as the
previous one completes — maximum pressure, original per-session ordering.
`--speed <factor>` honors the capture's original timeline instead:

```console
$ sql-replay replay --capture capture.jsonl.zst --url mysql://... \
    --speed 1.0 --out run.json
```

- Every event is scheduled at its captured timestamp offset from replay
  start (one global capture clock), with all inter-event gaps divided by
  the factor: `1.0` = real time, `2.0` = twice as fast, `0.5` = half speed.
- An event never fires *before* its scheduled offset. Within a session,
  order is still strict: if a query overruns its successor's slot, the
  successor fires as soon as the query completes — late, and that lateness
  is recorded rather than silently reshaping the workload.
- Pacing fidelity lands in `run.json` (`pacing.max_lag_us`,
  `pacing.mean_lag_us`, `pacing.paced_events`) and on stdout, so a target
  that can't keep up with the captured timeline is visible.

### Operational controls (M3)

- `--warmup` runs the whole capture once, unrecorded (buffer pool / cache
  warm-up), before the measured pass(es).
- `--repeat N` runs N measured passes: each pass's report is written as
  `<out>.passK.json` and `--out` itself receives the median-aggregated
  report (every numeric metric is the per-field median across passes; the
  report carries `aggregation: {passes, method: "median"}`).
- **Filters** re-slice a capture at replay time (captures stay complete,
  reusable artifacts; filtering happens while building the spool):
  `--filter-db <db>` and `--filter-user <user>` match the captured
  metadata (events without that metadata are excluded);
  `--time-window <start>..<end>` takes RFC 3339 timestamps or unix epoch
  seconds, start-inclusive / end-exclusive, either side optional. Excluded
  events are counted in `totals.filtered`; the pacing origin becomes the
  earliest *included* timestamp. Filtering everything is an error.
- **Graceful abort:** on Ctrl-C or SIGTERM (what systemd sends on stop),
  in-flight queries finish, everything not yet attempted is counted as
  `not_run`, and the partial `run.json` is still written with
  `"aborted": true` (exit code 130; a second Ctrl-C or SIGTERM exits
  immediately). `compare` warns when fed an aborted run.
- `--pool N` multiplexes sessions over a bounded pool of N connections,
  checked out per query, for captures whose session counts exceed
  practical connection counts (conflicts with `--max-connections`). This
  **trades connection fidelity for feasibility**: sessions no longer hold
  a dedicated connection, so session state (temp tables, session
  variables, transactions) does not carry across a session's queries, and
  captured `USE` statements are skipped — the per-event database metadata
  drives `USE` reconciliation on checkout instead. Off by default. Also
  the recommended lever for blob-heavy captures: replay memory scales
  with connections holding rows in flight (see the memory-model bullet
  above), and `--pool N` caps that at N regardless of session count.

### Comparing runs (5.7 vs 8.0 regression gate)

Replay the same capture against both servers, then diff the two run
reports (either side may instead be a recorded production baseline from
`sql-replay baseline` — see the next section):

```console
$ sql-replay compare \
    --baseline run-5.7.json \
    --candidate run-8.0.json \
    --json report.json \
    --out report.html
```

- Fingerprints are matched across the runs by normalized query text;
  per-fingerprint deltas cover p50/p95/p99/mean (absolute µs and %) plus
  error-count changes. Executed-count mismatches are flagged — those
  latency populations may not be comparable.
- Ranking: regressions (worst p95 first) and improvements are listed
  separately. `--threshold-pct` (default 20) splits regressed/improved
  from noise; `--min-count` (default 5) keeps low-sample fingerprints out
  of the headline ranking (they are still listed below the fold).
- Outputs: a stdout summary (top regressions/improvements — capped per
  section by `--top`, default 10 — QPS/wall-clock deltas, error deltas,
  fingerprints only in one run), `--json` for
  machines, and `--out` for a self-contained HTML report (inline CSS/JS,
  renders offline with zero network requests) with a sortable table and
  both runs' metadata side by side.
- Comparability preflight: if the runs differ in capture file, capture
  dialect, replay flags, fingerprint-table shape, executed counts, or
  target settings, a
  loud warning block tops every output; both `target_server_version`s are
  always shown prominently, and a settings-diff section lists changed
  variables (e.g. `character_set_server: latin1 -> utf8mb4`).
- **Exit code**: `0` when no regression reaches the threshold, `2` when at
  least one fingerprint regressed at/beyond it (`1` = tool error), so CI
  can gate a migration:

```yaml
- run: sql-replay compare --baseline run-5.7.json --candidate run-8.0.json \
        --threshold-pct 25 --min-count 10 --json report.json
  # non-zero exit fails the job when p95 regressions >= 25% exist
```

### Result-set size stats and size-decade regressions (0.4.0)

Fingerprinting collapses literals, so one fingerprint can hide result
sizes spanning orders of magnitude — `SELECT body FROM docs WHERE id = ?`
against a document table fetches 100KB and 15MB rows under the same
fingerprint, and its p50/p95 mix a 150x payload spread. A regression that
only hits the big rows used to be averaged away. Replay therefore
measures result sizes as it drains rows (always on — no flag, no extra
buffering: rows were already read one at a time, counting their bytes is
free):

- Each fingerprint in `run.json` carries `result_bytes`
  (total/min/max/mean exact, p50/p95 from a 2-significant-digit
  histogram) and `size_buckets`: its latency stats split by
  **result-size decade** — `<1KB`, `1KB-10KB`, `10KB-100KB`, `100KB-1MB`,
  `1MB-10MB`, `>=10MB` (binary units, lower bound inclusive). Only
  non-empty decades are stored; the stdout table shows mean result bytes
  per query.
- **Bytes are decoded payload, not wire bytes**: the canonical cell sizes
  of every drained row (string/blob cells count their byte length,
  fixed-width numerics their binary width, NULLs zero) — comparable
  between runs of this tool, not to `Bytes_sent`.
- `compare` shows per-fingerprint byte columns (a large byte delta means
  the targets returned differently-sized data) and adds a **result-size
  decade regressions** section: the same `--threshold-pct` / `--min-count`
  rules applied per decade, catching a p95 regression confined to one
  size class of a fingerprint whose mixed-size p95 stayed within the
  threshold. Such a decade regression sets **exit code 2** exactly like a
  fingerprint-level one (fingerprints already flagged at the top level
  are not re-listed per decade). In the JSON report the decade findings
  are a separate `size_regressions` list and `size_regressed` flag;
  `regressed` keeps meaning fingerprint-level regressions.
- **Older reports and recorded baselines degrade gracefully**: a run
  without byte data (pre-0.4.0, or `sql-replay baseline` — the capture
  records latencies, not result sizes) compares fine; byte columns show
  n/a and the decade comparison is skipped with a note, never a spurious
  verdict.

### Result-correctness diffing (`--checksum`)

A migration can return *wrong answers* long before it returns slow ones —
collation changes reorder comparisons, sql_mode changes alter implicit
casts, optimizer bugs drop rows. `replay --checksum` catches that
(pt-upgrade's data-diff job, at replay concurrency):

```console
$ sql-replay replay --capture capture.jsonl.zst --url mysql://old:3306/ \
    --checksum --out run-old.json
$ sql-replay replay --capture capture.jsonl.zst --url mysql://new:3306/ \
    --checksum --out run-new.json
$ sql-replay compare --baseline run-old.json --candidate run-new.json
```

- Every executed **read** statement's full result set is checksummed:
  per-row hashes combined **order-insensitively** (a multiset hash — row
  order and session interleaving never matter; any changed, missing,
  extra, or duplicated row changes the digest), plus row counts and
  column names. Memory stays O(1) per result set.
- run.json stores one aggregate per fingerprint (per-event checksums
  would bloat reports with millions of events): the multiset hash of the
  per-event digests, total rows, and column names. Two runs over the same
  capture and identical data produce equal aggregates no matter how the
  scheduler interleaved them.
- `compare` gains a **Result correctness** section: matched fingerprints
  whose digests diverge are reported separately from latency, and a
  deterministic divergence sets **exit code 2** just like a latency
  regression — a wrong answer is worse than a slow one.
- **Nondeterminism handling:** fingerprints using volatile functions
  (`NOW()`, `RAND()`, `UUID()`, `LAST_INSERT_ID()`, …), `@@variables`,
  `information_schema`/`performance_schema` reads, or `LIMIT` with no
  `ORDER BY` are classified up front and their divergences listed as
  *advisory* instead of failures (so are fingerprints whose checksummed
  event counts differ between the runs — those multisets aren't
  conclusively comparable). The classifier is an honest token scan, not a
  SQL parser: a column literally named `now` can false-positive, and
  nondeterminism hidden inside views or stored functions is invisible —
  such a query can land in the mismatch list even though its data is
  fine. Read the mismatch list as "investigate", not "guaranteed bug".
- **Only meaningful against identical data.** Both targets must hold the
  same snapshot (and both runs must use `--checksum` — `compare` warns
  when only one side did). Replaying with `--allow-writes` mutates data
  as it goes; checksums then compare meaningfully only if both runs
  started from the same snapshot and executed the same writes.
- **Latency caveat:** checksumming reads every result row fully, so a
  `--checksum` run's latencies include the full transfer and are **not
  comparable to a non-checksum run's** (compare warns on that flag
  mismatch). For a migration gate, either run both sides with
  `--checksum`, or do two passes: one plain pair for latency, one
  checksummed pair for correctness.

### No 5.7 replay target? Use the production-recorded baseline

The classic workflow above replays the same capture against *both*
servers. Often the 5.7 side can't be replayed against at all — it **is**
production — and only the 8.0 twin host is replayable. `sql-replay
baseline` covers that: the slow log already recorded every statement's
server-side execution time (`Query_time`), and `capture` stores it per
event, so the production baseline can be built from the capture alone:

```console
$ # 1. capture on production (slow log with long_query_time=0)
$ sql-replay capture --input slow.log --out capture.jsonl.zst
$ # 2. baseline from the RECORDED production latencies — no replay, no target
$ sql-replay baseline --capture capture.jsonl.zst --out baseline.json
$ # 3. replay the 8.0 twin at the original pace
$ sql-replay replay --capture capture.jsonl.zst \
    --url mysql://bench@twin-80:3306/ --speed 1.0 --out run-8.0.json
$ # 4. gate
$ sql-replay compare --baseline baseline.json --candidate run-8.0.json \
    --threshold-pct 50 --min-count 10 --json report.json --out report.html
```

- The baseline report has the same shape as a replay `run.json` (same
  per-fingerprint count/p50/p95/p99/max/mean; stdout gets the same top-N
  slowest-fingerprints table, `--top`), with
  `latency_source: "recorded-slow-log"` marking its provenance (replayed
  reports say `"replayed"`). Its timeline is the capture's own:
  `started_at`/`ended_at` are the first/last event timestamps and QPS
  derives from them. It carries no `target_url`, server version, or
  target settings — the slow log doesn't know them; `compare` shows
  "recorded (slow log)" in the version slot and skips the settings diff
  with a note.
- `--filter-db`/`--filter-user`/`--time-window` work exactly as in
  `replay`, so the baseline can cover the same slice you replay.
- **Measurement planes differ — compare generously.** Recorded latencies
  are server-side `Query_time` under live production load (they include
  lock waits and contention from concurrent traffic); replayed latencies
  are client-side wall times measured from the test host (they include
  network round-trip and driver overhead). `compare` prints a loud
  warning for recorded-vs-replayed pairs; use a generous
  `--threshold-pct` (e.g. 50) and treat small deltas as noise. Replay the
  twin with `--speed 1.0` so it sees the original concurrency and think
  of the twin as ideally **identical hardware** to production — a weaker
  test host shifts every delta.
- **Errors are 0 by definition** in a recorded baseline: the slow log
  records no statement errors. A zero there says nothing about how many
  errors production actually had — only replayed runs measure errors.

### Deploying on RHEL 8

The release artifact is a **fully static** `x86_64-unknown-linux-musl`
binary: no glibc, OpenSSL, or any other runtime dependency, so the same
file runs on RHEL 8 (and Rocky/Alma/Oracle 8+) database hosts as-is.

- Grab `sql-replay-<version>-x86_64-unknown-linux-musl.tar.gz` (or the
  prebuilt `.rpm`) plus `SHA256SUMS` from the GitHub release; the tarball
  contains the binary, README, and licenses — `install -m755 sql-replay
  /usr/local/bin/` is a complete install.
- To build the RPM yourself on a RHEL 8 host:
  `rpmbuild -bb packaging/sql-replay.spec --define "_sourcedir <dir with
  the tarball>" --define "version <version>"`.
- Releases are cut by pushing a `v*` tag: `.github/workflows/release.yml`
  runs the test suite, builds the musl binary, verifies it is static,
  packages tarball + RPM, and attaches them with checksums.
- Operationally: the spool needs disk roughly the uncompressed capture
  size — use `--spool-dir` to place it, especially where the default
  system temp dir is tmpfs (RAM-backed) — and the connection cap must fit
  under `ulimit -n` (replay checks and tells you the value to raise it
  to). Under systemd, stopping the unit (SIGTERM) aborts gracefully and
  still writes the partial `run.json`.

### Building & testing

```console
$ cargo build --release          # binary at target/release/sql-replay
$ cargo test                     # unit + fixture tests, no database needed
$ SQL_REPLAY_TEST_URL=mysql://root@127.0.0.1:3306/test cargo test -p sql-replay --test replay_integration
$ cargo test --release -p sql-replay --test scale -- --ignored  # 1M-event memory-bound evidence
$ SQL_REPLAY_TEST_URL=... cargo test --release -p sql-replay --test blob_memory -- --ignored  # blob-row peak-RSS guard
$ cargo build --release --target x86_64-unknown-linux-musl -p sql-replay  # static binary (needs musl-gcc)
```

CI runs fmt/clippy/tests (including 10k-session scheduling tests against a
mock target and, in release mode, the million-event bounded-memory scale
test) plus a live replay of a fixture capture against `mysql:5.7` and
`mysql:8.0` service containers (max-speed, `--db-override`, paced
`--speed 20`, `--warmup --repeat 3`, filtered, and `--pool` runs), then
feeds run reports through `sql-replay compare` — including a recorded
`baseline` built from the fixture capture compared against the live 8.0
run — and asserts the report shape, the recorded-vs-replayed warning,
and gate exit codes. The integration job also tcpdumps a real scripted
workload (binary-protocol prepared statements included) and drives it
through the full pcap → capture → replay → baseline path, and exercises
`--checksum` end to end: two replays over identical data must compare
clean, and a planted `UPDATE` must be detected with exit code 2. It also
runs the blob-row memory guard (`tests/blob_memory.rs`, release mode):
replaying multi-MB LONGTEXT rows must keep the binary's peak RSS under
the per-connection bounds, dedicated and `--pool 2`. A
dedicated job builds the static musl binary, verifies it is statically
linked, and smoke-builds the RPM from `packaging/sql-replay.spec`.

Every external-input surface (slow-log parser, fingerprint normalizer,
write-gate classifier, capture reader) is also fuzzed: [`fuzz/`](fuzz/) is
a standalone cargo-fuzz workspace (nightly-only tooling, kept outside the
stable root workspace) with a weekly/manual `fuzz-smoke` CI workflow — see
[`fuzz/README.md`](fuzz/README.md). A committed corpus of adversarial slow
logs under `crates/sql-replay/tests/corpus/` (header lookalikes inside
string literals, invalid UTF-8, rotation seams, CRLF, dialect mixtures, …)
is pinned by expected-outcome tests in the normal `cargo test` run and
doubles as fuzz seeds.

### Real-data verification rig

Beyond the unit/CI suites, `verify/run.sh` is a single-command,
end-to-end **detection-quality** check on real data: it loads the
canonical [employees dataset](https://github.com/datacharmer/test_db)
into real `mysql:5.7`, `mysql:8.0` and `mariadb:10.11` containers, plants
two large regressions on each candidate only (a dropped secondary index
and a temp-table-to-disk spill — via `temptable_max_ram` on 8.0,
`tmp_table_size` on MariaDB), runs a seeded
concurrent workload through the full capture → replay → compare loop, and
asserts that `compare` flags exactly the two planted classes — on the
same-engine 5.7 → 8.0 pair and the cross-engine 5.7 → MariaDB pair —
while the untouched control classes (PK lookups, INSERTs, and
big-LONGTEXT `xmldata` point/`IN` fetches spanning five result-size
decades, which also pin the byte stats and size-decade buckets on real
big rows) stay clean. Runs locally on any
docker-equipped Linux machine (~20–30 min) or in CI via the
manually-triggered / weekly
`real-verify` workflow. See [`verify/README.md`](verify/README.md).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  <http://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
