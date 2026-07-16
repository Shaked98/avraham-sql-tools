# Local MySQL benchmark — sql-replay detection proof + honest 5.7 vs 8.0 head-to-head

**Date:** 2026-07-16 · **Host:** i7-13700KF (24 threads, hybrid P/E cores), WSL2 capped at 15 GB RAM, consumer NVMe, Docker 29.4.3
**sql-replay:** 0.2.0, built `--release` from commit `8aa0c49` ("test(verify): real-data detection-quality rig for sql-replay (#5)")
**Servers:** mysql:5.7 → **5.7.44**, mysql:8.0 → **8.0.46** (official Docker images, data on ext4 via Docker's default volume storage — never /mnt/c)

> One of three executed benchmark writeups behind the cross-engine table
> in the main [README](../../README.md#benchmarks-where-a-57-workload-regresses-on-80-vs-mariadb-1011).
> Companions: [5.7 vs 8.0 on huge-text payloads](2026-07-16-mysql80-hugetext.md) ·
> [5.7 vs MariaDB 10.11, both workloads](2026-07-16-mariadb.md).

## Verdict

1. **Detection works.** The shipped rig (`verify/run.sh`, unmodified) passed end-to-end: exit 0, all 11 ground-truth checks ok, wall clock 6m02s. `compare` flagged **exactly** the two planted regressions (index drop +1731% p95, temp-table spill +603% p95) and neither control class.
2. **On an honest head-to-head (identical 4G-buffer-pool config, no sabotage), MySQL 8.0 loses badly on the join+GROUP BY class and is roughly at par everywhere else on this box.** The group-by aggregate is **~5x slower on 8.0** (p95 202 ms → 1145 ms). Point lookups, secondary-index lookups, and inserts stay sub-millisecond with single-digit-to-~25% deltas. Overall workload QPS dropped 60% (92 → 37), almost entirely due to the group-by class.
3. **The group-by slowdown is largely a charset default, not (only) an engine defect.** The employees dataset DDL pins no charset, so tables inherit the server default: latin1 on 5.7, utf8mb4 (`utf8mb4_0900_ai_ci`) on 8.0. The GROUP BY keys are two VARCHARs, so 8.0 groups on 4x-wider keys with a costlier collation. `compare` itself surfaced this in its comparability warning (`character_set_server: latin1 -> utf8mb4`). This is what a naive 5.7→8.0 migration actually experiences, so it's an honest result — but it means the number measures "stock 8.0 defaults", not isolated optimizer/engine changes.
4. **Rig observation worth acting on (see Recommendations):** the honest, unsabotaged 8.0 already regresses the group-by class by +465% p95 — above the rig's 100% detection threshold. Run 1's temp-table plant only added ~25% on top (1145 ms honest → 1431 ms sabotaged). So the rig's *compare-level* assertion for the gb class would pass even if the temptable plant silently stopped working (the plant is only truly verified by the rig's separate disk-spill probe). The index-drop plant, by contrast, is cleanly isolated (honest hire-date class: −6% p95; sabotaged: +1731%).

---

## Run 1 — detection proof (shipped rig, unmodified)

- Command: `cargo build --release && verify/run.sh` (defaults: seed 42, 12 sessions, `--warmup --repeat 3`, compare threshold 100% p95, min-count 50).
- **Exit status: 0 (PASS)** · wall clock **6m02.20s** (`/usr/bin/time -v`).
- Both containers ran simultaneously (rig design), 512M buffer pool each, `innodb_flush_log_at_trx_commit=2`, binlog off on 8.0; dataset row counts verified canonical on both; both plant-effectiveness probes passed before replay.
- Compare gate fired as intended: `FAIL: 2 fingerprint(s) regressed >= 100% on p95 (exit code 2)` — exit 2 is the rig's *expected* outcome and part of the pass condition.

Regression list (compare stdout, threshold +100% p95, count ≥ 50):

| class | p95 5.7 (ms) | p95 8.0-sabotaged (ms) | Δp95 | Δmean | verdict |
|---|---:|---:|---:|---:|---|
| hire-date lookup (idx_hire_date dropped) | 1.52 | 27.89 | **+1731%** | +2705% | REGRESSED (planted) |
| join+GROUP BY (temptable_max_ram=2MiB, mmap off) | 203.52 | 1430.53 | **+603%** | +595% | REGRESSED (planted) |
| pk-lookup (control) | 0.20 | 0.22 | +11% | — | stable ✓ |
| insert (control) | 0.20 | 0.25 | +21% | — | stable ✓ |

Ground truth: all 11 checks ok — regressions list is exactly the two planted classes; both controls present with full samples and clean; low-sample bucket holds only the mysql-client startup query and the SLEEP gate; no fingerprint set or count mismatches. Totals: QPS 91.6 → 29.5, wall 18.56s → 57.57s, 1700/1700 events executed, 0 errors on both sides.

## Run 2 — clean head-to-head (no sabotage)

Sequential, never simultaneous: 5.7 up → load → capture workload → replay vs 5.7 → tear down → 8.0 up → load identically → replay same capture → tear down → compare. Total wall 5m18s (5.7 leg ~1m53s, 8.0 leg ~3m25s). Driven by a scratch script calling the binary and `docker` directly; no project source modified.

**Every server setting I set** (identical `my.cnf` mounted into both containers; everything else stock image defaults):

```ini
[mysqld]
innodb_buffer_pool_size = 4G          # verified applied on both (4294967296)
innodb_flush_log_at_trx_commit = 2    # rig-standard: fsync-per-commit off
skip-log-bin                          # rig-standard: binlog off on both (log_bin=OFF verified)
```

Plus, capture side only (5.7, disabled again before any replay measurement): `slow_query_log=ON`, `long_query_time=0`, `log_output=FILE`, `log_slow_admin_statements=ON`. Schema setup on both was the rig's standard: `ADD INDEX idx_hire_date`, `verify_audit` table, `ANALYZE TABLE employees, salaries`.

Notable **unset** difference (stock defaults, surfaced by compare's warning): `character_set_server latin1 → utf8mb4`, `collation_server latin1_swedish_ci → utf8mb4_0900_ai_ci`, `sql_mode` loses `NO_AUTO_CREATE_USER`. Tables inherit the charset, so this is a real workload difference on the VARCHAR GROUP BY keys — see verdict #3.

Workload: `verify/workload.sh` defaults (seed 42, 12 sessions, 1701 captured events, 6 fingerprints, dialect `mysql-5.7`). Replay: `--warmup --repeat 3` (median-aggregated reports), `--max-connections 24`, `--allow-writes --db-override employees --filter-user verify` — note the capture has 12 sessions, so effective concurrency is 12; 24 is the ceiling asked for.

### Per-class latency, 5.7 vs 8.0 (median-of-3 reports, client-side wall time)

| class | count | p50 5.7 (ms) | p50 8.0 (ms) | Δp50 | p95 5.7 (ms) | p95 8.0 (ms) | Δp95 | compare verdict |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| join+GROUP BY (30k groups over ~330k joined rows) | 200 | 138.88 | 699.39 | **+404%** | 202.50 | 1144.83 | **+465%** | **REGRESSED** |
| insert (short audit-row INSERT) | 480 | 0.128 | 0.150 | +17% | 0.175 | 0.218 | +25% | REGRESSED (barely; see caveats) |
| hire-date secondary-index lookup | 360 | 0.273 | 0.443 | +62% | 1.394 | 1.306 | −6% | stable |
| pk point lookup | 640 | 0.134 | 0.143 | +7% | 0.179 | 0.194 | +8% | stable |

Compare (default threshold 20% p95, min-count 5): **exit 2**, 2 regressions (group-by, insert), 0 improvements, 6/6 fingerprints matched, 0 count mismatches, 0 errors either side.

Throughput: QPS 92.2 → 36.7 (−60%), wall 18.45s → 46.30s per measured pass. Caveat: every pass includes a fixed 12s `SELECT SLEEP(12)` gate (workload design), so compute-time is roughly 6.5s vs 34.3s — the honest ratio is worse than raw QPS suggests, and both are dominated by the group-by class.

Cross-validation: the 5.7 leg reproduced Run 1's 5.7 numbers almost exactly (gb p95 202.5 vs 203.5 ms; pk/insert within hundredths of a ms), so the sequential rerun and 4G pool didn't shift the baseline, and the 9–12s dataset loads (fast NVMe + relaxed fsync; `data_load_time_diff 00:00:08` in the load log) produced the same behavior as Run 1's canonically row-count-verified load.

Peak container memory observed: 777 MiB (5.7) / 1.16 GiB (8.0), replay tool RSS ~26 MB — far under the 10 GB budget (4G buffer pool is a ceiling, not a working set, for this 160 MB dataset).

### What 8.0 does to each class on this box (plain language)

- **Join+GROUP BY over VARCHAR keys: much slower (~5x).** Driven by utf8mb4 default charset/collation on the grouping keys plus 8.0's TempTable engine; no disk spill was planted here — this is stock behavior.
- **Point lookups (PK): par.** +7–8%, sub-millisecond.
- **Secondary-index lookups: par at the tail** (p95 −6%), noticeably slower at the median (+62%) but still sub-half-millisecond — consistent with 8.0's higher fixed per-statement overhead.
- **Short inserts: slightly slower** (+17% p50 / +25% p95), sub-millisecond; flagged only because the default 20% threshold is tight for sub-ms classes.

## Exact commands

```sh
# Run 1 (from a checkout of commit 8aa0c49)
cargo build --release
/usr/bin/time -v verify/run.sh          # exit 0, 6m02s

# Run 2 (scratch script; the meat of it)
# identical my.cnf above mounted at /etc/mysql/conf.d/zz-bench.cnf in both containers
docker run -d --name sqlt-bench -p 127.0.0.1:13310:3306 -e MYSQL_ALLOW_EMPTY_PASSWORD=yes \
  -v <dataset>:/test_db:ro -v <my.cnf>:/etc/mysql/conf.d/zz-bench.cnf:ro mysql:5.7   # then mysql:8.0, sequentially
# per leg: load employees.sql; ADD INDEX idx_hire_date; CREATE TABLE verify_audit; ANALYZE
# 5.7 leg only: create 'verify' user; slow log on; verify/workload.sh all; slow log off
target/release/sql-replay capture --input bench-slow.log --out capture.jsonl.zst
target/release/sql-replay replay --capture capture.jsonl.zst \
  --url mysql://root@127.0.0.1:13310/employees --max-connections 24 \
  --allow-writes --db-override employees --filter-user verify \
  --warmup --repeat 3 --out run-{57,80}.json
target/release/sql-replay compare --baseline run-57.json --candidate run-80.json \
  --top 20 --json report.json --out report.html    # defaults: threshold 20% p95, min-count 5 → exit 2
```

## Caveats

- **WSL2 virtualization + 15 GB host cap + hybrid P/E cores + consumer NVMe: all numbers are directional/relative, not absolute predictions** for production hardware. Latency ratios (5.7 vs 8.0 on the same box, back-to-back) are the meaningful output; absolute milliseconds are not.
- **Sub-millisecond classes (pk, insert, hire p50) sit in scheduler-noise territory.** The insert "+25% p95" regression flag is real overhead directionally (mean +7%) but the magnitude is not trustworthy at 0.2 ms scale; the rig itself uses a 100% threshold + SLEEP gates for exactly this reason. At compare's default 20% threshold, expect sub-ms false-ish positives on shared/virtualized boxes.
- **The 8.0 numbers include the utf8mb4 default-charset effect** (see verdict #3) — deliberate ("honest defaults"), but a migration that pins `character_set_server=latin1` (or converts schemas deliberately) would see a smaller group-by gap.
- Single seeded workload (seed 42), 12 sessions, one dataset — one workload shape, not a general 8.0 verdict.
- QPS totals include the 12s SLEEP gates (see throughput note).
- Minor asymmetry: 5.7's `verify_audit` had ~1.9k workload rows before replay while 8.0's started empty (same asymmetry exists in the shipped rig); negligible at this table size. Run 2 skipped the rig's canonical row-count assertion, mitigated by the 5.7-leg cross-validation above.
- The box was shared with other workloads, but they were idle during the runs; containers ran sequentially in Run 2, simultaneously in Run 1 (rig design).

## Recommendations

1. **Ship-worthy rig improvement:** pin the charset/collation in the rig (e.g. `character_set_server=latin1` on both containers, or explicit DDL charset) so the gb class regresses *only* when the temptable plant is active. Today the compare-level "temp-table-spill class regressed" assertion (verify/run.sh:380) would keep passing even if the plant broke, because stock 8.0 already regresses that class +465% — beyond the 100% threshold. The disk-spill probe (verify/run.sh:271-284) is currently the only assertion that actually isolates the plant. Alternatively, assert a higher gb threshold that honest 8.0 can't reach (fragile), or record the honest-8.0 delta as a third "known-difference" class. The index-drop plant needs no change — it's cleanly isolated (−6% honest vs +1731% planted).
   *Update: shipped — the rig now pins `character_set_server=latin1` on both containers, plus `tmp_table_size`/`max_heap_table_size`; see ["Why the server config is pinned"](../../verify/README.md#why-the-server-config-is-pinned-on-every-container) in the verify README.*
2. For real 5.7→8.0 migration assessments with this tool, run compare twice: once on stock defaults (what you'll get) and once with charset pinned (what the engine change alone costs). The comparability-warning block already gives the operator the cue.
