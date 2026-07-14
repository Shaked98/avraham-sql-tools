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
Planned next: static packaging for RHEL 8 (M3) and pcap capture (M4).

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
- **Safety:** non-read statements (anything but SELECT / SHOW / EXPLAIN /
  DESCRIBE / HELP / session-level SET / USE) are skipped and counted unless
  you explicitly pass `--allow-writes`.
  `SET GLOBAL`/`SET PERSIST`/`SET PASSWORD`/`SET DEFAULT ROLE`,
  `EXPLAIN ANALYZE` over DML (8.0 actually executes the statement),
  `SELECT ... INTO OUTFILE`/`DUMPFILE` (writes files on the server), and
  multi-statement text (a `;` followed by more SQL) also count as writes.
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

### Comparing runs (5.7 vs 8.0 regression gate)

Replay the same capture against both servers, then diff the two run
reports:

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
- Outputs: a stdout summary (top regressions/improvements, QPS/wall-clock
  deltas, error deltas, fingerprints only in one run), `--json` for
  machines, and `--out` for a self-contained HTML report (inline CSS/JS,
  renders offline with zero network requests) with a sortable table and
  both runs' metadata side by side.
- Comparability preflight: if the runs differ in capture file, replay
  flags, fingerprint-table shape, executed counts, or target settings, a
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

### Building & testing

```console
$ cargo build --release          # binary at target/release/sql-replay
$ cargo test                     # unit + fixture tests, no database needed
$ SQL_REPLAY_TEST_URL=mysql://root@127.0.0.1:3306/test cargo test -p sql-replay --test replay_integration
```

CI runs fmt/clippy/tests plus a live replay of a fixture capture against
`mysql:5.7` and `mysql:8.0` service containers (max-speed, `--db-override`,
and paced `--speed 20` runs), then feeds both run reports through
`sql-replay compare` and asserts the report shape and gate exit codes.
