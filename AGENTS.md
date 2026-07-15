# avraham-sql-tools — agent notes

Cargo workspace of SQL tooling. First (and so far only) crate:
`crates/sql-replay`, a MySQL slow-log capture + replay benchmarking tool
with a `compare` regression gate. See `README.md` for user-facing usage
and milestone scope (M1 capture/replay, M2 pacing + compare).

## Build / test

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test                # unit + fixture tests; no database required
cargo build --release
# live replay test (CI runs it against mysql:5.7 and mysql:8.0 services):
SQL_REPLAY_TEST_URL=mysql://root@127.0.0.1:3306/test cargo test -p sql-replay --test replay_integration
```

CI (`.github/workflows/ci.yml`) is the authoritative home of the MySQL
integration job — don't expect docker locally.

## This dev host has no C toolchain

`gcc`/`cc` and glibc dev files (`crt1.o`) are absent and there is no sudo.
Rust is installed user-level via rustup, and linking + `cc`-built crates
(zstd-sys) work through a `zig cc` wrapper:

- `~/.local/opt/zig/` — zig toolchain; `~/.local/bin/zigcc` — wrapper that
  rewrites `--target=x86_64-unknown-linux-gnu` to zig's triple spelling.
- `~/.cargo/config.toml` sets `linker = "zigcc"` for the gnu target and
  `CC=zigcc`. This is host config, deliberately NOT committed; CI uses
  plain gcc on ubuntu-latest.

If a build fails with `linker \`cc\` not found`, that setup is missing —
recreate it rather than adding repo-level workarounds.

## Dependency constraints

- `mysql_async` uses `default-features = false` with only the
  `minimal-rust` and `time` features so the dependency tree stays pure-Rust
  (no OpenSSL/system libs; TLS is not needed for M1). Don't re-enable
  default features casually.
- `hdrhistogram` has default features off (serialization deps not needed).
- Stable Rust only; no nightly features.

## MySQL slow-log dialect gotchas (learned building the parser)

All handled in `crates/sql-replay/src/slowlog.rs` (see its module docs and
tests, which are the executable spec):

- `# Time:` is `YYMMDD HH:MM:SS` on MySQL 5.6/older and MariaDB, RFC 3339
  since MySQL 5.7.2 (so real 5.7 logs use RFC 3339) — and old servers only
  print it **when the second changes**, so it must be carried forward.
  `SET timestamp=N;` (per entry) is the primary event timestamp. The
  dialect label prefers the restart banner's version; the time format only
  bounds it (`mysql-5.6-or-older`/`mysql-5.7-or-newer`, refined to
  `mysql-8.0` by `log_slow_extra` fields).
- `use <db>;` metadata lines are **log-global**, not per-thread: absence of
  a `use` line means "same db as the previous entry in the log", even for a
  different connection. They only count as metadata before the entry's
  `SET timestamp=N;`; a `use ...;` line after it is a client-issued USE
  statement and becomes an event.
- Thread id comes from `Id:` on the `User@Host` line (5.6+), from
  `Thread_id:` in 8.0 `log_slow_extra` Query_time lines, or from Percona's
  `# Thread_id: N Schema: db` line (which also carries a per-entry schema).
- Statement text can span lines and contain `# ...` lines inside string
  literals; quote/comment state must be tracked across lines before
  treating a `# ` line as a header. Real `#` SQL comments at line start
  inside a statement are also legal — only known header prefixes terminate
  an entry.
- `# administrator command: Quit;` entries (connection commands) produce no
  events; "admin statements" in `log_slow_admin_statements` (ALTER etc.)
  are ordinary captured statements.
- Slow logs can contain invalid UTF-8 inside queries — capture reads raw
  bytes and converts lossily.

## Replay write gate

`crates/sql-replay/src/classify.rs` (its tests are the spec): anything not
provably read-only is a write and only runs with `--allow-writes`.
Non-obvious cases handled there: `SET GLOBAL`/`PERSIST`/`SET PASSWORD`/
`SET DEFAULT ROLE` are writes while session-level `SET` is a read;
`EXPLAIN ANALYZE` executes the underlying statement on 8.0, so DML under it
is a write (plain `EXPLAIN`/`DESCRIBE` stay reads); `SELECT ... INTO
OUTFILE`/`DUMPFILE` writes files on the server; `WITH` is classified by the
first top-level verb after the CTEs; multi-statement text (a top-level `;`
followed by more content) is always a write.

## Pacing (`--speed`)

`crates/sql-replay/src/replay.rs`, `Pacer` (tests are the spec). Schedule =
capture-clock offset from the earliest event timestamp, gaps divided by the
factor; events never fire early, an overrun predecessor just makes the
successor late and the lateness lands in `run.json` `pacing` lag metrics
(`--speed max` ⇒ no `pacing` block). Skipped events are still paced, so
`paced_events` counts every event that reached a session loop, not just
executed ones. Sessions wait for their first event's due time *before*
claiming a `--max-connections` permit (late sessions must not pin idle
connections). Pacing tests use `#[tokio::test(start_paused = true)]` —
that's why tokio's `test-util` feature is a dev-dependency.

## compare subcommand

`crates/sql-replay/src/compare.rs` (logic; its tests + fixture pair
`tests/fixtures/run-{baseline,candidate}.json` are the spec) and
`compare_html.rs` (self-contained HTML — inline CSS/JS only, no external
refs; the fixture test greps for `http://` etc. to enforce it).
Fingerprints match by normalized *text*, not id (ids are capture-local).
Exit codes: 0 no regression, 2 regression ≥ threshold (`EXIT_REGRESSED`),
1 tool error — CI gates on this. M1 run.json files (no `pacing`/
`target_settings`) still load: the new `RunReport` fields are
`#[serde(default)]`, keep them that way. Target settings are read with
`SHOW VARIABLES LIKE` (returns no row instead of erroring on unknown
variables); the 5.7 `tx_isolation` / 8.0 `transaction_isolation` rename is
canonicalized to `transaction_isolation`.

## Capture format

zstd JSONL: header record, event records, summary record (dialect, counts,
fingerprint table as `[{id, text}]`). Note: the fingerprint table is a
*list*, not a JSON map — integer-keyed maps don't round-trip through
serde's internally-tagged enums.

## Maintaining this file

Keep this file current as the project evolves; it is the shared memory
across agent sessions. Record durable, project-intrinsic knowledge (build
commands, invariants, gotchas) — not session-specific state. When a fact
here becomes stale, fix or delete it in the same change that made it stale.
Prefer pointers to authoritative files over copied detail.
