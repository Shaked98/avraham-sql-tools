# avraham-sql-tools — agent notes

Cargo workspace of SQL tooling. First (and so far only) crate:
`crates/sql-replay`, a MySQL slow-log/pcap capture + replay benchmarking
tool with a `compare` regression gate. See `README.md` for user-facing
usage and milestone scope (M1 capture/replay, M2 pacing + compare, M3
scale hardening + RHEL 8 packaging, M4 pcap capture + result-correctness
diffing — the final planned milestone).

`docs/quickstart.md` is an *executed* walkthrough: every shown output
came from really running the commands against the pinned release binary
(v0.4.0) and toy mysql:5.7/8.0 containers. If tool output or flags
change, re-execute the walkthrough (and bump the pinned version when a
new release ships) instead of hand-editing the outputs. When
re-executing: §6's noise lesson needs the sub-ms point-lookup class's
Δp95 to land between the default (20%) and tuned (50%) thresholds, and
on this host it swings roughly −11%..+72% run to run — re-run the two
replay commands (real filenames, keep transcripts) until a pair lands
in band.

`docs/architecture.svg` is a hand-written, self-contained SVG workflow
diagram (Cantrill-style: white canvas rect, soft-fill rounded boxes,
dashed zone containers) embedded near the top of the README and linked
from the quickstart. No external refs/fonts — keep it that way so GitHub
renders it in both themes; update it when subcommands, artifacts, or the
pipeline shape change.

`docs/benchmarks/` holds three *executed* benchmark writeups (5.7 vs
8.0 general + huge-text, 5.7 vs MariaDB 10.11) feeding the README
"Benchmarks" cross-engine table. Every number came from a real run —
never hand-edit them; a new benchmark run gets a new dated file (and
the README table updated to match). The README table's footnotes
(baseline charset labeling, cross-tool-version MB/s caveat) are
load-bearing — keep them when editing the section.

## Build / test

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test                # unit + fixture tests; no database required
cargo build --release
# live replay test (CI runs it against mysql:5.7 and mysql:8.0 services):
SQL_REPLAY_TEST_URL=mysql://root@127.0.0.1:3306/test cargo test -p sql-replay --test replay_integration
# heavy 1M-event bounded-memory test (CI runs it in the check job):
cargo test --release -p sql-replay --test scale -- --ignored --nocapture
# blob-row peak-RSS guard (needs a live server; CI runs it in the integration job):
SQL_REPLAY_TEST_URL=mysql://root@127.0.0.1:3306/test cargo test --release -p sql-replay --test blob_memory -- --ignored --nocapture
```

CI (`.github/workflows/ci.yml`) is the authoritative home of the MySQL
integration job — don't expect docker locally. `release.yml` cuts GitHub
releases from `v*` tags (musl tarball + RPM + checksums); never create
tags/releases from an agent session.

## This dev host has no C toolchain

`gcc`/`cc` and glibc dev files (`crt1.o`) are absent and there is no sudo.
Rust is installed user-level via rustup, and linking + `cc`-built crates
(zstd-sys) work through a `zig cc` wrapper:

- `~/.local/opt/zig/` — zig toolchain; `~/.local/bin/zigcc` — wrapper that
  rewrites `--target=x86_64-unknown-linux-gnu` to zig's triple spelling
  (`zigcxx` is the same for `zig c++`, needed as `CXX` by cargo-fuzz's
  libFuzzer runtime).
- `~/.cargo/config.toml` sets `linker = "zigcc"` for the gnu target and
  `CC=zigcc`. This is host config, deliberately NOT committed; CI uses
  plain gcc on ubuntu-latest.

If a build fails with `linker \`cc\` not found`, that setup is missing —
recreate it rather than adding repo-level workarounds.

To smoke the static musl build locally (CI's musl job uses musl-gcc and is
authoritative): `~/.local/bin/zigcc-musl` pins zig to the musl triple
(rustc invokes the linker without `--target`), and rustc's self-contained
crt objects must be disabled or they collide with zig's:

```sh
RUSTFLAGS="-C link-self-contained=no" \
CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=zigcc-musl \
CC_x86_64_unknown_linux_musl=zigcc-musl \
cargo build --release --target x86_64-unknown-linux-musl -p sql-replay
```

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
- The `mariadb` dialect label comes ONLY from a restart banner naming
  MariaDB: banner-less MariaDB logs are not reliably distinguishable from
  Percona/old-MySQL (legacy `# Time:`, shared `# Thread_id: .. Schema: ..
  QC_hit:` line) and honestly stay `mysql-5.6-or-older`. MariaDB's
  `log_slow_verbosity` annotation lines (`# Rows_affected:`,
  `# Full_scan:`, `# explain:` with tab-separated plan rows, bare `#`)
  are ignored header lines; `tests/corpus/mariadb-10.11.log` is a
  verbatim container log pinning all of this.

## pcap capture source (M4)

Two-module split, deliberately: `crates/sql-replay/src/mysqlproto.rs` is
the MySQL wire-protocol decoder (packet framing, handshake, COM_QUERY,
COM_STMT_PREPARE/EXECUTE expansion with bound-parameter interpolation) and
never sees pcap or TCP; `crates/sql-replay/src/pcap.rs` owns pcap-file
reading (pure-Rust `pcap-parser`, no libpcap), link/IP parsing, and
per-4-tuple TCP reassembly. Module docs + tests of both are the spec;
`tests/pcap_capture_test.rs` builds .pcap files byte-by-byte (never
requires tcpdump locally). Non-obvious facts baked in:

- Seq-id rule: in the command phase, "client packet with seq 0" is a
  command; the response to it starts at the command's *last* packet seq +
  1. Server seq wraparound in >255-packet responses must be treated as
  continuation, not a new response (that's what `server_cont_seq` does).
- TLS (CLIENT_SSL) and compression (CLIENT_COMPRESS/zstd) are negotiated
  in the client handshake response — from then on the stream is opaque;
  such connections are skipped and *counted* (`Disposition`), as are
  mid-stream starts (no greeting seen ⇒ BadHandshake). Nothing is ever
  silently dropped; every loss class lands in `summary.pcap` (a
  serde-defaulted `format::PcapSummary`) and stderr warnings.
- The mysql 8.x CLI negotiates CLIENT_QUERY_ATTRIBUTES: COM_QUERY then
  carries an attribute section before the SQL text that must be skipped.
  But it sends that flag even to pre-8.0 servers that never advertised
  the capability (and then uses plain COM_QUERY), so the decoder ANDs
  client and server (greeting) capability flags before trusting it.
- TCP reassembly maps seqs to u64 relative offsets (wraparound and >4 GiB
  streams); out-of-order data buffers up to 8 MiB per direction, beyond
  that the connection counts as broken. Session id = server thread id
  from the greeting (matches the slow-log path); reused thread ids
  (server restart mid-capture) get synthetic ids ≥ 1<<48.
- Event latency = request packet → first response packet on the wire
  (recorded into `orig_query_time_s`, so `baseline` works on pcap
  captures; it includes the capture-point→server network path, unlike
  slow-log Query_time — README documents this).
- CI's pcap leg tcpdumps `-i lo` (docker-proxy publishes the service
  container port on loopback) and uses `--ssl-mode=DISABLED` on the mysql
  CLI — without it the connection negotiates TLS and decodes to nothing.
  `examples/wire_workload.rs` generates the binary-protocol prepared
  statements (the CLI's text PREPARE never sends COM_STMT_PREPARE).

## Result-correctness diffing (M4)

`replay --checksum` + the `compare` correctness section. Design decisions
(docs in `target.rs`/`report.rs`/`compare.rs`, tests are the spec;
`tests/checksum_test.rs` is the mock-target E2E):

- Checksums are **multiset hashes** at two levels: per-row xxh3 hashes
  combined with commutative sum+xor+count into a per-event digest
  (`target::ChecksumBuilder`), per-event digests combined the same way
  into one per-fingerprint aggregate in run.json. Order-insensitive by
  construction (session interleaving differs between runs) and O(1)
  memory (the M3 bounded-memory invariant) — that's why it is not a
  sorted list of row hashes. Duplicate rows don't cancel (sum term).
- Digests are only comparable between runs of this tool over the text
  protocol; the canonical cell encoding (`RowHasher`, type-tagged) is
  ours. The mock target in `tests/common/mod.rs` shares it, with a
  `data_version` knob to plant a data change.
- `classify::is_nondeterministic` (fingerprint-text token scan) demotes
  volatile-function/`@@var`/info-schema/LIMIT-without-ORDER fingerprints to
  advisory; `--repeat` pass disagreement also marks nondeterministic
  (aggregate.rs). Deterministic digest divergence sets
  `correctness_failed` ⇒ exit 2 (same code as latency regressions).
- A `--checksum` run's latencies include full result reads — compare
  warns on checksum-flag mismatch and skips the correctness diff.

## Result-set byte stats + size-decade split (0.4.0)

`replay` measures per-fingerprint result-set bytes on the streaming drain
(`target.rs` `value_bytes` is the canonical cell-size definition — decoded
payload, NOT wire bytes; `TargetConn::query` returns the drained byte
count, `ResultChecksum` carries `bytes_total` *outside* the digest so
0.3.0 digests stay comparable). Always on: `FingerprintReport.result_bytes`
plus `size_buckets` (latency stats per result-size decade,
`report::SIZE_BUCKET_LABELS`/`size_bucket_index`, binary units,
half-open). `compare` applies the same threshold/min-count rules per
decade so a regression confined to big rows can't be averaged away —
findings land in `size_regressions`/`size_regressed` (exit 2), kept
*separate* from `regressions`/`regressed` deliberately: the verify rig
asserts `.regressions | length == 2` and single-decade fingerprints would
double-report (fingerprints already regressed at top level are excluded
from the decade list). Runs without byte data (pre-0.4.0, recorded
baselines) degrade to a `size_note` + n/a columns.
`tests/result_bytes_test.rs` is the mock E2E (the mock honors a
`MOCK_BYTES=<n>` marker); the fixture pair plants a decade-only
regression in `show variables like ?`.

## Replay write gate

`crates/sql-replay/src/classify.rs` (its tests are the spec): anything not
provably read-only is a write and only runs with `--allow-writes`.
Non-obvious cases handled there: `SET GLOBAL`/`PERSIST`/`SET PASSWORD`/
`SET DEFAULT ROLE` are writes while session-level `SET` is a read;
`EXPLAIN ANALYZE` executes the underlying statement on 8.0, so DML under it
is a write (plain `EXPLAIN`/`DESCRIBE` stay reads); `SELECT ... INTO
OUTFILE`/`DUMPFILE` writes files on the server; `WITH` is classified by the
first top-level verb after the CTEs; multi-statement text (a top-level `;`
followed by more content) is always a write; MySQL executes
`/*! ... */` version-conditional comments, so their contents are
classified as real content (only ordinary comments are inert).

## Blob-row memory model (post-M4 hardening)

`crates/sql-replay/src/memtune.rs` + `tests/blob_memory.rs` (docs there
are the spec; README "Memory model on big rows" is the user story).
Replay peak RSS ≈ base + connections × ~3× largest result row (packet
buf + decoded Row + growth transients — mysql_async has no decode-free
drain; both `query` and `query_checksum` already stream per-row, never
per-result-set). Two retention mechanisms used to add ~50 MB/session on
15 MB rows: mysql_async's global buffer pool (128 bufs shrunk only to
`MYSQL_ASYNC_BUFFER_SIZE_CAP`, default 4 MiB) and glibc's dynamic mmap
threshold. `memtune::tune_process_memory()` (called first thing in
`main`, must precede threads and the first connection) defaults both to
128 KiB, respecting env overrides; musl needs no mallopt (gated out).
Cost: ~1 ms page-fault tax per 15 MB row. `--pool N` is the documented
lever for blob-heavy captures (bounds in-flight rows to N). CI's
integration job runs the guard (`--test blob_memory -- --ignored`,
release mode — bounds are release-calibrated; it must stay alone in its
binary and drives the real binary via `CARGO_BIN_EXE` + `wait4` maxrss).

## Replay ingestion is streamed — keep it that way (M3)

`crates/sql-replay/src/spool.rs` (module docs + tests are the spec):
replay never materializes the capture. Two streaming passes build an
unlinked on-disk spool with one contiguous byte region per session; each
session task reads its events via positioned reads. Peak memory is
O(sessions), independent of event count (~35 MiB at 5M events / 20k
sessions — `tests/scale.rs` asserts a 192 MiB bound and is the evidence
run; it must stay alone in its binary because VmHWM is process-wide).
The contiguous-region design exists because per-session queues fed by a
live dispatcher can deadlock: with all permits held by sessions idling for
their next event and the dispatcher blocked on a full queue of a
permit-waiting session, nothing progresses. Pre-building the spool gives
every session an independent cursor and removes cross-session coupling.
`replay.rs` keeps an in-memory reference path
(`run_replay_in_memory_with_target`) purely so
`tests/streaming_equivalence.rs` can prove the spool path yields identical
run.json results — don't ship features that exist in only one path.

The execution layer is generic over `target::Target` (mysql impl +
`tests/common/mod.rs` mock), which is how abort/pool/10k-session behavior
is tested without a database. Replay-side filters (`--filter-db/user`,
`--time-window`) are applied at spool build — deliberately not at capture,
so captures stay complete reusable artifacts. `--pool N` checks
connections out per query (session state fidelity is documented as lost;
captured USE is skipped, per-event db metadata reconciles instead).
Graceful abort is a `watch::Receiver<bool>` threaded through sessions
(SIGINT and SIGTERM both trigger it — systemd stops units with SIGTERM);
`--warmup`/`--repeat` rerun passes over the same spool and
`aggregate.rs` does the median math.

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

## baseline subcommand (0.2.0)

`crates/sql-replay/src/baseline.rs` (module docs + tests are the spec;
`tests/baseline_test.rs` is the capture→baseline→compare E2E): streams a
capture and aggregates each event's recorded slow-log `Query_time`
(`orig_query_time_s`) into a `RunReport`-shaped baseline — for the case
where the 5.7 side IS production and can't be replayed against.
Provenance is `RunReport::latency_source` (`"recorded-slow-log"` vs
`"replayed"`, serde-defaulted to replayed so pre-0.2.0 run.json loads);
recorded reports have empty `target_url`/`target_server_version`
(skip-serialized) and no settings. `compare` handles mixed pairs: a loud
MEASUREMENT PLANES DIFFER warning (recorded latencies — server-side
slow-log Query_time or pcap request→response wire time — vs client-side
replay wall time), replay-knob flag diffs suppressed
(filter flags still compared — they change the workload slice), settings
diff skipped with `settings_note`, "recorded (slow log)" in the version
slot. Baseline errors are 0 by definition (the slow log records none) —
documented in the README so nobody reads it as "production had no
errors".

## compare subcommand

`crates/sql-replay/src/compare.rs` (logic; its tests + fixture pair
`tests/fixtures/run-{baseline,candidate}.json` are the spec) and
`compare_html.rs` (self-contained HTML — inline CSS/JS only, no external
refs; the fixture test greps for `http://` etc. to enforce it).
Fingerprints match by normalized *text*, not id (ids are capture-local).
Exit codes: 0 no regression, 2 regression ≥ threshold (`EXIT_REGRESSED`),
1 tool error — CI gates on this. Older run.json files still load: every
field added after M1 (`pacing`, `target_settings`, the M3 `aborted`/
`aggregation`/`filtered`/flag fields, the 0.2.0 `latency_source`/
`settings_note`, the 0.3.0 checksum fields — `flags.checksum`,
per-fingerprint `checksum`, compare's `correctness`/`correctness_failed` —
the 0.4.0 byte-stat fields — per-fingerprint `result_bytes`/
`size_buckets`, compare's `size_regressions`/`size_buckets_checked`/
`size_note`/`size_regressed` — plus the capture summary's `pcap` block)
is `#[serde(default)]`, keep it that way. An aborted (Ctrl-C/SIGTERM) replay exits 130 after writing partial
reports; `compare` warns when an input run is `aborted`. Target settings are read with
`SHOW VARIABLES LIKE` (returns no row instead of erroring on unknown
variables); the 5.7 `tx_isolation` / 8.0 `transaction_isolation` rename is
canonicalized to `transaction_isolation` (this also covers MariaDB 10.11,
which has only `tx_isolation` — `transaction_isolation` arrived in 11.1).

MariaDB targets are first-class: `compare::server_family()` classifies
`target_server_version` (contains "MariaDB" ⇒ MariaDB, else MySQL; the
`5.5.5-` wire-compat prefix is stripped for display only), and a
cross-engine pair adds a "target engine families differ" comparability
warning — informational, never gates the exit code. The settings snapshot
and `--checksum` digests are engine-agnostic by construction (proven by a
live 5.7→10.11 run and the rig's MariaDB leg). MariaDB's sql_mode default
differs from 5.7's (no ONLY_FULL_GROUP_BY etc.) — that diff is honest,
don't suppress it.

## Capture format

zstd JSONL: header record, event records, summary record (dialect, counts,
fingerprint table as `[{id, text}]`). Note: the fingerprint table is a
*list*, not a JSON map — integer-keyed maps don't round-trip through
serde's internally-tagged enums.

## Packaging (M3)

`packaging/sql-replay.spec` builds the RHEL 8 RPM from the release tarball
of the static musl binary (AutoReqProv off, debuginfo/build-id disabled —
the binary is prebuilt and static). Its `%global version` default must
match the crate version (CI's musl job asserts this). `release.yml`
publishes tarball + RPM + SHA256SUMS on `v*` tags after the full test
suite; the tag must equal the crate version. CI's musl job also rebuilds
the static binary and rpmbuilds the spec on every PR so neither rots.
Keep the dep tree free of OpenSSL/system libs or the static build breaks
(zstd-sys is the one C dependency, compiled by musl-gcc in CI).

## Real-data verification rig (`verify/`)

`verify/run.sh` + `verify/workload.sh` + `.github/workflows/real-verify.yml`
(docs: `verify/README.md`): ground-truth detection-quality check on the
real employees dataset against mysql:5.7/8.0 and mariadb:10.11 containers
— plants the same two big regressions on each candidate (8.0 AND MariaDB;
never the 5.7 baseline), asserts `compare` flags exactly those and
no control class, per candidate. Manual/weekly CI job, deliberately
not per-PR.
Gotchas baked into it (relearn them from its comments before changing it):

- The mysql client sends `select @@version_comment limit 1` on EVERY
  connection, batch mode included — one extra captured event per session.
- Sub-millisecond control queries' p95 is scheduler noise when heavy
  queries run concurrently on a small runner, and the noise is worse on
  the deliberately slower candidate — a false-positive machine. The rig
  parks planted-class sessions behind a `SELECT SLEEP(n)` first event so
  controls run on a quiet box; keep that property when adding classes.
- `workflow_dispatch` cannot target a workflow file that is not yet on
  the default branch; iterate on a rig branch with a temporary
  `push:` trigger instead.
- Replay-side `--filter-user` on a dedicated workload MySQL user is how
  the rig keeps its own admin statements out of the replayed event set.
- Both containers pin `character_set_server=latin1` (the employees DDL
  pins no charset, so stock 8.0's utf8mb4 default widens the GROUP BY
  keys 4x) AND `tmp_table_size`/`max_heap_table_size=128M` (8.0's
  optimizer over-estimates the gb temp table past the 16M default and
  creates it directly on disk — the larger effect). Without the pins an
  honest, unsabotaged 8.0 regresses the join+GROUP BY class past the 100%
  threshold, making the compare-level temptable-plant assertion vacuous.
  Rationale + measurements in verify/README.md ("Why the server config is
  pinned"). The pins apply to the MariaDB container too (MariaDB 10.6+
  also defaults to utf8mb4).
- MariaDB has no TempTable engine / `temptable_max_ram`: its temp-table
  plant floors `tmp_table_size=1K` + `max_heap_table_size=16K` instead
  (spills to on-disk Aria; measured ~9x on the gb probe). The mariadb
  image keeps `mysql`/`mysqladmin` shims, so `mrun`/`wait_ready` work
  unchanged; the empty-root-password env var is
  `MARIADB_ALLOW_EMPTY_ROOT_PASSWORD`.

## Fuzzing (`fuzz/`)

`fuzz/README.md` is the authoritative doc. cargo-fuzz targets (nightly,
standalone workspace — deliberately outside the stable root workspace)
cover every external-input surface: slow-log parser (raw bytes +
structured mutations), fingerprint normalizer, classify write gate
(with gate invariants asserted, e.g. appended top-level `;DROP …` must
classify Write), and the zstd-JSONL capture reader.
`crates/sql-replay/tests/corpus/` holds the committed nasty-log corpus;
every file there is pinned by `tests/corpus_test.rs` (exact event counts —
no panics, no silently dropped entries) and doubles as fuzz seeds.
`.github/workflows/fuzz-smoke.yml` runs 60 s/target weekly/manual.
Before shipping parser changes, run a longer local campaign per
`fuzz/README.md` (on this host: `CXX=zigcxx`).

## Maintaining this file

Keep this file current as the project evolves; it is the shared memory
across agent sessions. Record durable, project-intrinsic knowledge (build
commands, invariants, gotchas) — not session-specific state. When a fact
here becomes stale, fix or delete it in the same change that made it stale.
Prefer pointers to authoritative files over copied detail.
