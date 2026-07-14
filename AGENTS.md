# avraham-sql-tools — agent notes

Cargo workspace of SQL tooling. First (and so far only) crate:
`crates/sql-replay`, a MySQL slow-log capture + replay benchmarking tool.
See `README.md` for user-facing usage and the M1 scope.

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

- `mysql_async` uses `default-features = false, features = ["minimal-rust"]`
  so the dependency tree stays pure-Rust (no OpenSSL/system libs; TLS is not
  needed for M1). Don't re-enable default features casually.
- `hdrhistogram` has default features off (serialization deps not needed).
- Stable Rust only; no nightly features.

## MySQL slow-log dialect gotchas (learned building the parser)

All handled in `crates/sql-replay/src/slowlog.rs` (see its module docs and
tests, which are the executable spec):

- `# Time:` is `YYMMDD HH:MM:SS` on old servers, RFC 3339 on 8.0 — and old
  servers only print it **when the second changes**, so it must be carried
  forward. `SET timestamp=N;` (per entry) is the primary event timestamp.
- `use <db>;` metadata lines are **log-global**, not per-thread: absence of
  a `use` line means "same db as the previous entry in the log", even for a
  different connection.
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
