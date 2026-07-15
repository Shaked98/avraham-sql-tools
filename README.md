# avraham-sql-tools

Modern SQL tooling.

- **sql-replay** — multi-threaded MySQL query-replay benchmarking tool for
  5.7 → 8.0 migration testing (maintained successor to the abandoned Percona
  Playback; unlike pt-upgrade it replays at the original concurrency).

## sql-replay

Replay real production load captured on MySQL 5.7 against MySQL 8.0 (or any
other target) to find performance regressions before cutover.

### Scope

M1 shipped `capture` and `replay`; M2 added faithful-timing pacing
(`--speed`) and the `compare` subcommand for run-to-run regression diffs.
M3 made replay production-scale (bounded memory independent of capture
size, thousands of concurrent sessions, warmup/repeat/filter/abort
controls, an optional connection pool) and deployable on RHEL 8 (static
musl binary, RPM spec, release workflow). 0.2.0 added `baseline`: build
the baseline report from the capture's *recorded* production latencies
when the source server cannot be replayed against. Planned next: pcap
capture (M4).

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
Percona-style `# Thread_id: ... Schema: ...` lines. The recorded dialect
label comes from the server-restart banner when the log contains one;
otherwise it is inferred from the timestamp format (`mysql-5.6-or-older` /
`mysql-5.7-or-newer`, refined to `mysql-8.0` when `log_slow_extra` fields
are present), and `--dialect` overrides the label either way. The capture file is zstd-compressed
JSONL: a header record, one event per query
(`ts_micros`, `session_id`, `user`, `db`, `query`, `orig_query_time_s`,
`fingerprint_id`), and a summary record with the fingerprint table
(pt-query-digest-style normalized query classes).

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
  in µs); stdout
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
  drives `USE` reconciliation on checkout instead. Off by default.

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
and gate exit codes. A dedicated job builds the static musl binary,
verifies it is statically linked, and smoke-builds the RPM from
`packaging/sql-replay.spec`.

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
into real `mysql:5.7` and `mysql:8.0` containers, plants two large
regressions on the 8.0 side only (a dropped secondary index and a
temp-table-to-disk spill via `temptable_max_ram`), runs a seeded
concurrent workload through the full capture → replay → compare loop, and
asserts that `compare` flags exactly the two planted classes while the
untouched control classes stay clean. Runs locally on any docker-equipped
Linux machine (~15–25 min) or in CI via the manually-triggered / weekly
`real-verify` workflow. See [`verify/README.md`](verify/README.md).
