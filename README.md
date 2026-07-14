# avraham-sql-tools

Modern SQL tooling.

- **sql-replay** — multi-threaded MySQL query-replay benchmarking tool for
  5.7 → 8.0 migration testing (maintained successor to the abandoned Percona
  Playback; unlike pt-upgrade it replays at the original concurrency).

## sql-replay

Replay real production load captured on MySQL 5.7 against MySQL 8.0 (or any
other target) to find performance regressions before cutover.

### M1 scope

This milestone ships `capture` and `replay` with `--speed max` pacing
(each session fires its next query as soon as the previous one completes).
Planned next: faithful-timing pacing (M2), a `compare` subcommand for
run-to-run regression diffs, and static packaging for RHEL 8 (M3).

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

Both the 5.7 (`# Time: YYMMDD HH:MM:SS`) and 8.0 (RFC 3339 `# Time:`,
`log_slow_extra`) slow-log dialects are auto-detected, as are Percona-style
`# Thread_id: ... Schema: ...` lines. The capture file is zstd-compressed
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
  DESCRIBE / session-level SET / USE) are skipped and counted unless you
  explicitly pass `--allow-writes`. `SET GLOBAL`/`SET PERSIST` also count
  as writes. Replay against a disposable target when using
  `--allow-writes`.
- `--db-override <db>` replays everything against one database instead of
  the captured per-session databases.
- `run.json` carries run metadata (target server version, flags, wall
  clock, QPS, saturation) plus per-fingerprint stats (count, errors with a
  first-error sample, skipped, p50/p95/p99/max/mean latency in µs); stdout
  gets a top-N slowest-fingerprints table.

### Building & testing

```console
$ cargo build --release          # binary at target/release/sql-replay
$ cargo test                     # unit + fixture tests, no database needed
$ SQL_REPLAY_TEST_URL=mysql://root@127.0.0.1:3306/test cargo test -p sql-replay --test replay_integration
```

CI runs fmt/clippy/tests plus a live replay of a fixture capture against
`mysql:5.7` and `mysql:8.0` service containers.
