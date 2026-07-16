# Fuzzing sql-replay's input-parsing surfaces

The slow-log parser is the first thing that touches a user's production
data, so everything that parses external input is fuzzed: it must never
panic, hang, or silently drop events, whatever bytes it is fed.

This directory is a standalone cargo-fuzz workspace (nightly-only tooling;
the crate itself stays on stable and never depends on it).

## Targets

| target | surface | what is asserted beyond "no panic/hang" |
|---|---|---|
| `slowlog_parse` | `slowlog::SlowLogParser`, fed arbitrary bytes exactly the way `capture::run_capture` feeds it | emitted queries are never empty; `finish()` never emits twice |
| `slowlog_structured` | same parser, but inputs are assembled from realistic building blocks (headers in any order, restart banners, fuzzed statements, CRLF, truncation at an arbitrary byte = rotation seam) | reaches header/state interactions raw bytes rarely hit |
| `fingerprint` | `fingerprint::fingerprint` on arbitrary SQL-ish strings | metamorphic: ASCII case and leading/trailing whitespace never change the class |
| `classify` | `classify::classify` (the `--allow-writes` gate) on arbitrary statements | appending `;DROP TABLE …` at top level must classify Write (checked against an independently written lexer); inert comment/whitespace prefixes never flip the gate (non-empty `/*! … */` prefixes are excluded — MySQL executes their contents, so they legitimately change the class) |
| `capture_reader` | `format::stream_capture` on corrupted zstd-JSONL (both raw bytes and valid-zstd-wrapped fuzzed JSONL) | every failure is an `Err`, never a panic |

## Running

Nightly is required for libFuzzer instrumentation:

```sh
rustup toolchain install nightly
cargo install cargo-fuzz --locked
```

On this dev host (no C toolchain — see the AGENTS.md toolchain section)
libFuzzer's C++ runtime needs the zig wrapper: `export CXX=zigcxx`.
On a normal box with gcc/clang, no env is needed.

```sh
cd fuzz
# one target, bounded (corpus dirs are created on demand and gitignored):
cargo +nightly fuzz run slowlog_parse corpus/slowlog_parse seeds/slowlog_parse -- \
  -max_total_time=900 -timeout=20 -rss_limit_mb=3072
# list targets:
cargo +nightly fuzz list
```

A crash writes a reproducer under `fuzz/artifacts/<target>/`; replay it
with `cargo +nightly fuzz run <target> artifacts/<target>/crash-…` and
keep the minimized input as a regression test or seed once fixed.

## Seeds and corpora

- `seeds/<target>/` — small, committed, curated starting points. Add a
  seed when a bug is fixed (its reproducer) or when a new input shape is
  under-covered (e.g. a new slow-log header dialect). Keep seeds minimal:
  libFuzzer explores better from many small inputs than one big one.
- `corpus/<target>/` — the evolving corpus libFuzzer accumulates; local
  state, gitignored. Delete it to start exploration from the seeds again.
- `../crates/sql-replay/tests/corpus/` — the nasty-log corpus. Every file
  there is pinned by an expected-outcome test in
  `crates/sql-replay/tests/corpus_test.rs` (event counts and metadata, so
  nothing is silently dropped), and the files double as `slowlog_parse`
  seeds in the smoke workflow. New adversarial log shapes belong there,
  *with* a test; fuzz-only seeds belong in `seeds/`. Corpus files are
  byte-exact (some deliberately carry CRLF or invalid UTF-8); the
  directory's `.gitattributes` marks `*.log -text` so git never
  normalizes them.

## CI

`.github/workflows/fuzz-smoke.yml` runs every target for 60 s on a weekly
schedule and on manual dispatch — a regression tripwire, not exploration.
Longer campaigns (10–15 min per target) are run locally before parser
changes ship; record target/duration/execs/findings in the PR body.
