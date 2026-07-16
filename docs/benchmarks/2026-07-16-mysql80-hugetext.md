# Huge-text payload benchmark — MySQL 5.7 vs 8.0 fetching 100KB–15MB XML documents

**Date:** 2026-07-16 · **Host:** i7-13700KF (24 threads, hybrid P/E cores), WSL2 capped at 15 GB RAM, consumer NVMe, Docker 29.4.3
**sql-replay:** 0.2.0, built `--release` from commit `8aa0c49` (same binary/method as the [prior general-workload head-to-head](2026-07-16-mysql80-general.md))
**Servers:** mysql:5.7 → **5.7.44**, mysql:8.0 → **8.0.46**, run **sequentially** (never simultaneous), data on ext4 via Docker's default volume storage — never /mnt/c. The box was shared with other workloads, but they were idle during the runs.

> One of three executed benchmark writeups behind the cross-engine table
> in the main [README](../../README.md#benchmarks-where-a-57-workload-regresses-on-80-vs-mariadb-1011).
> Companions: [5.7 vs 8.0, general workload](2026-07-16-mysql80-general.md) ·
> [5.7 vs MariaDB 10.11, both workloads](2026-07-16-mariadb.md).

Motivating question: *what happens when the workload fetches huge XML text — 5 MB documents and larger?* Extends the prior head-to-head, this time with the charset confound **removed** (pinned identically on both, see below).

## Verdict

1. **On huge-text fetch, 8.0 is at par with 5.7 — actually slightly faster.** For every multi-MB class (1MB / 5MB / 15MB full-row fetches) at every concurrency (1, 4, 12 parallel fetchers), 8.0's mean latency is 2–17% *lower* and effective MB/s 3–16% *higher* than 5.7's. There is no payload-size cliff up to 15MB: latency scales linearly with document size on both engines (single-stream: ~0.4ms/1MB, ~2.3ms/5MB, ~8ms/15MB), and both sustain ~1.8–2.5 GB/s single-stream and ~4.3–4.6 GB/s aggregate at 12 fetchers over loopback. **The prior run's big 8.0 loss (group-by, ~5x) does not generalize to payload transfer** — with the charset pinned identically, blob/text fetch is one of the areas where 8.0 is fine.
2. **Where 8.0 does lose is fixed per-statement overhead, not transfer.** The only classes `compare` flagged as regressed (exit 2 at all three concurrencies) are sub-millisecond ones: `SUBSTRING(body,1,1024)` on the 100KB class (p95 +24…+44%) and the 100KB full fetch at 12 fetchers (p95 +34%). These are 0.2–0.8ms absolute — the same "8.0 costs a bit more per statement" signal the prior report saw on point lookups, amplified by compare's 20% default threshold in scheduler-noise territory. At ≥1MB payloads, transfer time swamps this overhead and the deltas flip in 8.0's favor.
3. **Partial fetch (`SUBSTRING(body,1,1024)`) proves the cost is payload handling, not row-locating — and 8.0 handles big blobs server-side *better*.** Fetching 1KB out of a 15MB document still costs 1.3ms single-stream (vs 0.12ms for a 100KB doc) because the server must read the full off-page blob to substring it; the wire transfer of the remaining ~15MB adds only ~6.7ms more. At 12 fetchers, 8.0 is 20–29% *faster* than 5.7 at this server-side blob read on the 5MB/15MB classes.
4. **No protocol drama on either engine:** `max_allowed_packet=64M` was never hit (15MB rows fit comfortably), zero errors, zero aborted clients, no packet/net-buffer warnings in either error log across ~6.5 GB sent per leg. Server peak memory: 1.02 GiB (5.7) vs 1.19 GiB (8.0) for the whole leg — payload buffering on the server side is per-connection send-buffer sized, not payload×connections.
5. **Tool dogfood (KEY for M4): sql-replay survived multi-MB result sets correctly, but its memory is O(sessions × largest row), not bounded.** Replay RSS: 85 MB at 1 session → 270–340 MB at 4 → 650–720 MB at 12 (vs ~26 MB in the prior small-row run). That's ~50 MB per session against 15MB rows (~3.5x the max row, mysql_async buffers whole rows plus allocator retention). No blowup, no timeout, identical results across passes — but extrapolate to a production-shaped capture (hundreds of sessions × multi-MB rows) and replay would need many GB. The M3 "peak memory is O(sessions)" invariant silently acquires a large constant when rows are huge. Recommendation below.

---

## Method

Same rig shape as the prior report (sequential containers, identical my.cnf, `--warmup --repeat 3`, median-aggregated reports), with this run's additions:

**Everything pinned in `my.cnf`** (identical file mounted into both containers; all verified applied via `SHOW VARIABLES`, values in evidence below):

```ini
[mysqld]
innodb_buffer_pool_size = 4G
innodb_flush_log_at_trx_commit = 2
skip-log-bin
# blob-run additions:
max_allowed_packet = 64M              # verified 67108864 on both
character_set_server = utf8mb4        # pinned on BOTH (prior run showed stock defaults differ)
collation_server = utf8mb4_general_ci # pinned on BOTH (8.0's stock utf8mb4_0900_ai_ci doesn't exist on 5.7)
```

Plus explicit DDL charset so nothing inherits anything: `CREATE DATABASE docsdb CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci` and `CREATE TABLE docs (id INT NOT NULL PRIMARY KEY, size_class VARCHAR(16) NOT NULL, body LONGTEXT NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci`. The only settings diff `compare` reported was `sql_mode` losing `NO_AUTO_CREATE_USER` (removed in 8.0; irrelevant to reads).

**Data:** deterministic seeded (seed 42) XML-like documents (`<doc>` of `<item n=..>sha256hex</item>` elements, pure ASCII), byte-exact sizes, identical bytes on both legs: 40×100KB, 20×1MB, 10×5MB, 4×15MB (~134 MB table). Row counts and `MIN/MAX(LENGTH(body))` verified identical on both servers.

**Workload:** per concurrency level C ∈ {1, 4, 12}, C parallel mysql-client sessions splitting a fixed seeded fetch plan: full fetches `SELECT body AS body_<class> FROM docs WHERE id=?` (96/48/24/24 per pass for 100KB/1MB/5MB/15MB — ~537 MB per pass) plus a partial-fetch class `SELECT SUBSTRING(body,1,1024) AS sub_<class> ...` (24 per size). The per-class alias is what keeps size classes as distinct fingerprints — sql-replay fingerprinting collapses literals, so `WHERE size_class='c5m'` would have merged all classes into one bucket.

**Pipeline (the preferred sql-replay path — it worked, no fallback needed):** 5.7 up → load → slow-log capture of the live workload per concurrency (`long_query_time=0`, one log per level; `sql-replay capture` parsed all three cleanly, dialect `mysql-5.7`) → replay each capture against 5.7 (`--warmup --repeat 3`, `--filter-user blob` to exclude admin sessions, `--max-connections 24`, `--spool-dir` on real disk since /tmp is tmpfs) → tear down → 8.0 up → identical load → replay the **same** captures → tear down → `compare` per concurrency. Memory kept far under the 10 GB budget (worst case: ~1.2 GiB server + 0.7 GiB tool).

## Results — per-class latency and throughput (median of 3 measured passes, client-side wall time)

Latencies are per-query; "per-stream MB/s" = document size / mean latency (aggregate ≈ ×C for the concurrent runs, since all C sessions work the same class phase).

### Single stream (C=1) — pass wall 0.36s → 0.33s, QPS 803 → 869, errors 0/0

| class | count | p50 5.7 (ms) | p50 8.0 (ms) | Δp50 | p95 5.7 (ms) | p95 8.0 (ms) | Δp95 | MB/s 5.7 | MB/s 8.0 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| full fetch 100KB | 96 | 0.14 | 0.12 | −15% | 0.22 | 0.18 | −16% | 665 | 789 |
| full fetch 1MB | 48 | 0.44 | 0.39 | −13% | 0.52 | 0.55 | +5% | 2213 | 2488 |
| full fetch 5MB | 24 | 2.31 | 2.23 | −3% | 3.14 | 2.58 | −18% | 2044 | 2078 |
| full fetch 15MB | 24 | 8.04 | 7.51 | −7% | 10.49 | 10.89 | +4% | 1780 | 1900 |
| SUBSTRING 1KB of 100KB | 24 | 0.12 | 0.13 | +11% | 0.16 | 0.20 | **+24%** | — | — |
| SUBSTRING 1KB of 1MB | 24 | 0.19 | 0.18 | −4% | 0.25 | 0.21 | −14% | — | — |
| SUBSTRING 1KB of 5MB | 24 | 0.43 | 0.47 | +10% | 0.48 | 0.64 | **+32%** | — | — |
| SUBSTRING 1KB of 15MB | 24 | 1.26 | 1.25 | −0% | 1.86 | 1.61 | −14% | — | — |

### 4 parallel fetchers — pass wall 0.18s → 0.17s, QPS 1618 → 1713, errors 0/0

| class | count | p50 5.7 (ms) | p50 8.0 (ms) | Δp50 | p95 5.7 (ms) | p95 8.0 (ms) | Δp95 | MB/s 5.7 | MB/s 8.0 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| full fetch 100KB | 96 | 0.17 | 0.18 | +1% | 0.32 | 0.27 | −17% | 525 | 543 |
| full fetch 1MB | 48 | 0.63 | 0.55 | −13% | 0.93 | 0.84 | −10% | 1530 | 1712 |
| full fetch 5MB | 24 | 5.33 | 5.22 | −2% | 8.21 | 6.48 | −21% | 890 | 940 |
| full fetch 15MB | 24 | 16.40 | 15.46 | −6% | 22.06 | 20.11 | −9% | 906 | 944 |
| SUBSTRING 1KB of 100KB | 24 | 0.17 | 0.17 | +3% | 0.20 | 0.27 | **+35%** | — | — |
| SUBSTRING 1KB of 1MB | 24 | 0.22 | 0.23 | +7% | 0.30 | 0.29 | −3% | — | — |
| SUBSTRING 1KB of 5MB | 24 | 0.67 | 0.80 | +19% | 0.97 | 0.89 | −9% | — | — |
| SUBSTRING 1KB of 15MB | 24 | 2.78 | 2.41 | −13% | 3.11 | 2.61 | −16% | — | — |

### 12 parallel fetchers — pass wall 0.17s → 0.15s, QPS 1786 → 1940, errors 0/0

| class | count | p50 5.7 (ms) | p50 8.0 (ms) | Δp50 | p95 5.7 (ms) | p95 8.0 (ms) | Δp95 | MB/s 5.7 | MB/s 8.0 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| full fetch 100KB | 96 | 0.39 | 0.42 | +7% | 0.60 | 0.81 | **+34%** | 247 | 212 |
| full fetch 1MB | 48 | 1.90 | 1.58 | −17% | 3.80 | 3.60 | −5% | 449 | 520 |
| full fetch 5MB | 24 | 15.47 | 14.49 | −6% | 25.07 | 22.82 | −9% | 293 | 323 |
| full fetch 15MB | 24 | 40.22 | 38.17 | −5% | 59.07 | 53.47 | −9% | 361 | 381 |
| SUBSTRING 1KB of 100KB | 24 | 0.25 | 0.31 | +23% | 0.36 | 0.52 | **+44%** | — | — |
| SUBSTRING 1KB of 1MB | 24 | 0.44 | 0.50 | +14% | 0.81 | 0.96 | +18% | — | — |
| SUBSTRING 1KB of 5MB | 24 | 2.33 | 1.65 | **−29%** | 4.33 | 3.62 | −16% | — | — |
| SUBSTRING 1KB of 15MB | 24 | 7.16 | 5.09 | **−29%** | 9.81 | 7.86 | −20% | — | — |

**compare verdicts** (defaults: p95 +20%, min-count 5): exit 2 at every concurrency, but every flagged regression is a sub-millisecond class (sub_c100k at all three; sub_c5m at C=1; full c100k at C=12). Every ≥1MB full-fetch class was within threshold or an *improvement* (c5m at C=4: −21% p95, flagged as improvement). 9 fingerprints matched at every level, 0 count mismatches, 0 errors either side.

### Reading the split (plain language)

- **Row-locate cost is trivial and flat** (~0.12ms — see 100KB SUBSTRING ≈ 100KB full fetch ≈ PK lookups from the prior run).
- **Server-side blob read scales with document size even when you fetch 1KB of it** (SUBSTRING of 15MB doc: ~1.3ms single-stream, ~5–7ms at 12 fetchers). If an app only needs a prefix/fragment of big XML, `SUBSTRING` saves the wire time (6.7ms of the 8ms for 15MB) but not the server's blob read. 8.0 does this blob read faster under concurrency (−20…−29%).
- **Wire transfer dominates ≥1MB** and both engines move it at effectively the same (high) rate; 8.0 consistently a few percent better.
- **Concurrency divides per-stream bandwidth, sub-linearly:** aggregate throughput on the 15MB class rises from ~1.8→~4.3 GB/s (5.7) and ~1.9→~4.6 GB/s (8.0) going 1→12 fetchers; per-stream drops ~5x. Latency SLOs for huge-payload fetch should be modeled as bandwidth-shared, not per-query-constant — on both engines equally.

## Server-side observations

| metric | 5.7 leg | 8.0 leg |
|---|---|---|
| container peak memory (1s `docker stats` sampling, whole leg) | 1.02 GiB | 1.19 GiB |
| Bytes_sent over leg | 8.07 GB (incl. 3 capture passes) | 6.45 GB (replays only) |
| Aborted_clients / Aborted_connects | 0 / 0 | 0 / 0 |
| Max_used_connections | 12 | 12 |
| max_allowed_packet / net-buffer warnings in error log | none | none |
| other warnings | startup boilerplate only | + transient `innodb_redo_log_capacity` pressure warnings **during the 134MB bulk load only** (default 100MB redo capacity; none during replay) |

The 4G buffer pool is a ceiling, not a working set (134 MB table, fully cached after warmup — this benchmark deliberately measures fetch/transfer, not disk).

## Tool dogfood — sql-replay on multi-MB result sets (feeds M4)

The preferred path worked end-to-end; no fallback to direct scripting was needed:

- **Capture:** slow-log parsing of the payload workload was instant and correct (290/294/302 events; the extra per-session `select @@version_comment limit 1` from the mysql client and root admin sessions appeared exactly as the verify-rig notes predict; `--filter-user blob` excluded the admin sessions at replay).
- **Replay:** all passes executed 100% of events with 0 errors, including 24-in-flight 15MB fetches; `mysql_async` (minimal-rust features) handled >16MB-capable packets fine under `max_allowed_packet=64M`. Results were reproducible run-to-run (c15m p50 within 6% across two full 5.7 legs).
- **Limitation found (the M4-relevant one): replay RSS grows with sessions × row size.** MaxRSS across the three concurrency levels: **85 MB (1 session) → 270–340 MB (4) → 650–720 MB (12)**, vs ~26 MB on the prior small-row workload. That's roughly 50 MB per session when rows are 15MB — whole-row buffering in mysql_async plus allocator retention, ~3.5× the largest row per session. The M3 bounded-memory invariant ("peak is O(sessions), independent of event count") still holds, but the per-session constant is now the row size, not a few KB. A realistic production capture (say 300 sessions touching multi-MB rows) extrapolates to **~15 GB RSS**. Suggested M4 work: drain rows without materializing (mysql_async `ResultSet` streaming / `reduce`), or document a `--pool` recommendation for blob-heavy captures (pool N bounds in-flight rows to N, not sessions).
- **Minor sharp edge:** per-size-class results required aliasing tricks (`SELECT body AS body_c5m`) because fingerprinting collapses all literals — a real workload's `WHERE id=?` against a docs table would merge 100KB and 15MB fetches into one fingerprint whose p50/p95 mixes size classes. For M4 result-correctness diffing, consider optional bucketing by result-set size decade alongside the text fingerprint.
- `compare`'s default 20% p95 threshold again flagged only sub-ms noise classes on a virtualized box (all three exits were 2) — same caveat as the prior report; the multi-MB signal classes were clean.

## Exact commands

Scratch scripts only (gen.py / leg.sh / analyze.py, kept out of the repo); no project source modified. The meat:

```sh
# identical my.cnf (above) mounted into both containers, sequentially:
docker run -d --name sqlt-blob -p 127.0.0.1:13310:3306 -e MYSQL_ALLOW_EMPTY_PASSWORD=yes \
  -v my.cnf:/etc/mysql/conf.d/zz-blob.cnf:ro mysql:5.7    # then mysql:8.0
# per leg: CREATE DATABASE docsdb CHARSET utf8mb4 COLLATE utf8mb4_general_ci;
#          load seeded docs.sql (134MB, seed 42); ANALYZE TABLE docs; verify LENGTH(body) per class
# 5.7 leg only, per concurrency C in 1 4 12:
#   SET GLOBAL slow_query_log_file='/var/lib/mysql/blob-cC.log'; long_query_time=0; slow_query_log=ON;
#   C parallel `mysql -ublob docsdb < sess_cC_sK.sql`; slow_query_log=OFF; docker cp the log
target/release/sql-replay capture --input blob-cC.log --out capture-cC.jsonl.zst
# both legs, per concurrency:
/usr/bin/time -v target/release/sql-replay replay --capture capture-cC.jsonl.zst \
  --url mysql://root@127.0.0.1:13310/docsdb --db-override docsdb --filter-user blob \
  --max-connections 24 --spool-dir <real-disk> --warmup --repeat 3 --out run-{57,80}-cC.json
target/release/sql-replay compare --baseline run-57-cC.json --candidate run-80-cC.json \
  --top 12 --json compare-cC.json --out compare-cC.html    # exit 2 at all three levels (sub-ms classes only)
```

## Caveats

- **Same box caveats as the prior report:** WSL2 virtualization, 15 GB cap, hybrid cores, loopback through docker-proxy — ratios between the two engines measured back-to-back are the meaningful output; absolute MB/s and milliseconds are not production predictions. Wire numbers are loopback (memcpy-bound); a real network would flatten the engine difference on big payloads even further.
- **Sub-millisecond classes are scheduler-noise territory** (the flagged +24…+44% p95s are 0.05–0.2ms absolute). Directionally consistent with 8.0's known higher per-statement overhead, but magnitudes untrustworthy — same caveat and same mechanism as the prior report's insert class.
- p95 on 24-sample classes is effectively "2nd worst of 24"; medians and means are the stabler columns (they agree with the p95 story everywhere except the noise classes).
- 15MB max tested (fits 64M packet with room); this says nothing about payloads near/over `max_allowed_packet`, compressed protocol, TLS, or `LONGBLOB` binary (utf8mb4 LONGTEXT with ASCII content transfers byte-identical, so binary should match).
- Server "peak memory" is 1s-interval `docker stats` sampling (cgroup `memory.peak` unavailable on this WSL2 host) — could miss a sub-second spike; both legs measured identically.
- Docs are ASCII inside utf8mb4 columns — a worst-case multibyte corpus would stress charset conversion more; here the client charset matched so no conversion happened on either engine.

## Recommendations

1. **For migration planning:** huge-XML fetch is not a 5.7→8.0 risk area on its own — plan capacity around *concurrency × payload bandwidth-sharing* (identical on both engines), and around 8.0's fixed per-statement overhead if the workload is many small fetches rather than few big ones. Pin the charset during migration (as here) so blob classes don't inherit the group-by-style utf8mb4 confound.
2. **For M4 (ship-worthy):** add a blob-heavy scale test and make replay memory bounded per *connection*, not per session-row (stream/drain rows instead of materializing whole 15MB rows per session, or document `--pool` as the blob-workload mode). Evidence: 85→720 MB RSS scaling measured above.
   *Update: shipped post-M4 — the `memtune` buffer/allocator caps roughly halved replay RSS on this exact workload shape (650–720 MB → 324–340 MB at C=12, measured in the [MariaDB writeup](2026-07-16-mariadb.md)), CI gained a blob-row peak-RSS guard (`tests/blob_memory.rs`), and `--pool N` is documented as the blob-heavy lever.*
3. **For M4 fingerprinting:** consider result-size-aware bucketing (or at least surfacing result-set byte counts per fingerprint in run.json) — today a single `WHERE id=?` fingerprint hides a 150x payload spread, and `compare` would average away a regression that only affects big rows. `Bytes_sent`-style per-query counters exist in 8.0 `log_slow_extra` captures already.
   *Update: shipped in 0.4.0 — per-fingerprint result-set byte stats plus a size-decade regression gate, exercised end-to-end in the [MariaDB writeup](2026-07-16-mariadb.md).*
