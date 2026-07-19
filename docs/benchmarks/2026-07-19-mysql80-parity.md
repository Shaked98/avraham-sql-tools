# Local MySQL benchmark — 5.7 vs parity-pinned 8.0: what the engine alone costs

**Date:** 2026-07-19 · **Host:** i7-13700KF (24 threads, hybrid P/E cores), WSL2 capped at 15 GB RAM, consumer NVMe, Docker 29.4.3
**sql-replay:** 0.5.0, built `--release` from commit `c7df136` ("chore(sql-replay): bump version to 0.5.0 and sync release docs (#20)")
**Servers:** mysql:5.7 → **5.7.44**, mysql:8.0 → **8.0.46** (official Docker images, data on ext4 via Docker's default volume storage — never /mnt/c)

> The parity-pinned twin of the stock-defaults head-to-head
> ([5.7 vs 8.0, general workload](2026-07-16-mysql80-general.md), Run 2):
> same workload, same seed, same sequential discipline, one experimental
> delta — the 8.0 candidate additionally gets the
> [`parity-57.cnf` fragment](../parity-5.7-to-8.0.md) (PR #21), which
> pins every still-settable drifted 8.0 default back to its stock-5.7
> value. The question this answers: **with the same parameters, is 8.0
> slower or faster?**

## Verdict

1. **With the same parameters, 8.0 is at par with 5.7 on this workload —
   modestly slower everywhere, catastrophically slower nowhere.** The
   join+GROUP BY class that lost **+465% p95 on stock defaults comes back
   to +8% p95** (206.1 → 221.8 ms) with the parity fragment applied.
   Overall workload QPS drops 2.6% (91.3 → 88.9) versus −60% on stock
   defaults.
2. **The parity pins recover ~98% of the stock GROUP BY regression.**
   Stock 8.0 ran the class at 1144.8 ms p95; parity-pinned 8.0 runs it at
   221.8 ms — 5.2x faster than stock 8.0 on the same box, same workload,
   same 4G buffer pool. What looked like an engine cliff was almost
   entirely two drifted defaults (utf8mb4 `character_set_server` widening
   the VARCHAR grouping keys 4x, and the TempTable engine's
   estimate-driven spill behavior — `internal_tmp_mem_storage_engine=MEMORY`
   restores 5.7 semantics).
3. **The residual engine delta is a consistent single-digit-to-~25%
   per-statement overhead.** Sub-millisecond classes: pk lookups +9% p95,
   short INSERTs +28% p95, both directionally consistent with the stock
   run (+8%, +25%) — this is 8.0's higher fixed per-statement cost, not a
   config artifact, and the absolute magnitudes (0.02–0.06 ms) are
   scheduler-noise territory on this box. The heavy gb class's +8% p95 is
   the cleanest engine-only number this workload produces.
4. **`compare` still exits 2** — it flags the two sub-ms control classes
   (INSERT +28%, hire-date +102% p95) plus the 12-sample mysql-client
   startup query at the default 20% threshold. All three are sub-ms
   noise-band findings (see caveats; the hire-date class's p95 swung
   0.41–0.85 ms between 5.7 passes alone, and the same class measured
   **−6%** in the stock run). The settings snapshot is clean: the only
   surviving comparability warning is the un-pinnable `sql_mode`
   residue (8.0 removed `NO_AUTO_CREATE_USER`).

---

## Method — one delta vs the stock-defaults run

Identical to [Run 2 of the general benchmark](2026-07-16-mysql80-general.md#run-2--clean-head-to-head-no-sabotage),
sequential and never simultaneous: 5.7 up → load → capture workload →
replay vs 5.7 → tear down → 8.0 up → load identically → replay same
capture → tear down → compare. Total wall 3m32s (5.7 leg 1m54s, 8.0 leg
1m38s). Driven by a scratch script calling the binary and `docker`
directly; no project source modified.

Both containers get the identical shared `my.cnf` (verbatim Run 2):

```ini
[mysqld]
innodb_buffer_pool_size = 4G          # verified applied on both (4294967296)
innodb_flush_log_at_trx_commit = 2    # rig-standard: fsync-per-commit off
skip-log-bin                          # rig-standard: binlog off on both
```

**The delta:** the 8.0 container additionally mounts the full
[`parity-57.cnf` fragment](../parity-5.7-to-8.0.md) (§7 of the parity
guide, taken verbatim from PR #21) as `/etc/mysql/conf.d/parity.cnf`.
conf.d files load alphabetically, so the shared `zz-bench.cnf` loads
last and its resource settings win on overlap — the only overlap is
`skip-log-bin`, which both set identically (Run 2 already had binlog off
on 8.0; the parity pin coincides). Net effect: the parity fragment pins
only stock-5.7 defaults the shared config never touched (charset,
temp-table engine, redo capacity, auth plugin, flushing knobs,
statement/cache limits — 23 settings), while the deliberate shared
resource settings stay identical on both sides.

Capture side only (5.7, disabled before any replay measurement):
`slow_query_log=ON`, `long_query_time=0`, `log_output=FILE`,
`log_slow_admin_statements=ON`. Schema setup on both was Run 2's
rig-standard: `ADD INDEX idx_hire_date`, `verify_audit` table,
`ANALYZE TABLE employees, salaries`. Dataset row counts verified
canonical on both sides (300024 employees / 2844047 salaries / …).

Workload: `verify/workload.sh` as of Run 2's commit `8aa0c49` (seed 42,
12 sessions, 4 classes + SLEEP gates). Capture: **1701 events / 6
fingerprints, dialect `mysql-5.7`** — byte-for-byte the same shape as
Run 2. Replay: `--warmup --repeat 3` (median-aggregated),
`--max-connections 24`, `--allow-writes --db-override employees
--filter-user verify`.

### Effective final variable set — verified, not assumed

`SHOW GLOBAL VARIABLES` on both servers immediately before replay, for
every headline pin (5.7 left, parity-8.0 right):

```
character_set_server             latin1        latin1
collation_server                 latin1_swedish_ci  latin1_swedish_ci
log_bin                          OFF           OFF
innodb_buffer_pool_size          4294967296    4294967296
innodb_flush_log_at_trx_commit   2             2
tmp_table_size                   16777216      16777216
max_heap_table_size              16777216      16777216
internal_tmp_mem_storage_engine  (n/a on 5.7)  MEMORY
innodb_redo_log_capacity         (n/a on 5.7)  100663296   # = 5.7's 48M x 2 files
information_schema_stats_expiry  (n/a on 5.7)  0
default_authentication_plugin    mysql_native_password  mysql_native_password
innodb_autoinc_lock_mode         1             1
innodb_flush_neighbors           1             1
innodb_max_dirty_pages_pct       75            75
innodb_max_dirty_pages_pct_lwm   0             0
innodb_undo_log_truncate         OFF           OFF
explicit_defaults_for_timestamp  OFF           OFF
local_infile                     ON            ON
event_scheduler                  OFF           OFF
max_allowed_packet               4194304       4194304
max_length_for_sort_data         1024          1024
max_error_count                  64            64
back_log                         80            80
table_open_cache                 2000          2000
table_definition_cache           1400          1400
innodb_open_files                2000          2000
```

The full headline snapshots differ **only** in the three 8.0-only
variables (each pinned to the 5.7-equivalent value shown above) and the
un-pinnable `sql_mode` (8.0 removed `NO_AUTO_CREATE_USER`) — exactly the
residue the [parity guide](../parity-5.7-to-8.0.md) §4 predicts.

## Per-class latency, 5.7 vs parity-pinned 8.0 (median of 3 passes, client-side wall time)

| class | count | p50 5.7 (ms) | p50 8.0 (ms) | Δp50 | p95 5.7 (ms) | p95 8.0 (ms) | Δp95 | compare verdict |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| join+GROUP BY (30k groups over ~330k joined rows) | 200 | 140.80 | 155.90 | +11% | 206.08 | 221.82 | +8% | stable |
| pk point lookup | 640 | 0.139 | 0.151 | +9% | 0.195 | 0.212 | +9% | stable |
| insert (short audit-row INSERT) | 480 | 0.135 | 0.162 | +20% | 0.190 | 0.243 | +28% | REGRESSED (sub-ms; see caveats) |
| hire-date secondary-index lookup | 360 | 0.294 | 0.464 | +58% | 0.607 | 1.226 | +102% | REGRESSED (sub-ms; see caveats) |

Compare (default threshold 20% p95, min-count 5): **exit 2**, 3
regressions (insert, hire-date, plus the 12-sample `select
@@version_comment` client-startup query at +24%), 0 improvements, 6/6
fingerprints matched, 0 count mismatches, 0 errors either side.

Throughput: QPS 91.3 → 88.9 (−2.6%), wall 18.61s → 19.11s (+2.7%) per
measured pass. Excluding the fixed 12s `SELECT SLEEP(12)` gate each pass
carries, compute time is roughly 6.6s vs 7.1s (+8%) — consistent with
the gb class's +8% and no longer dominated by it.

Per-pass stability of the headline class (p95, ms): 5.7 {213.8, 205.4,
206.1} vs parity-8.0 {220.5, 225.8, 221.8} — non-overlapping, tight, a
real but small gap. The flagged hire-date class by contrast: 5.7 {0.61,
0.85, 0.41} vs 8.0 {0.51, 1.49, 1.23} — overlapping pass ranges on a
0.5 ms scale.

Compare transcript (headline excerpt):

```
!!! COMPARABILITY WARNINGS — the runs may not be directly comparable !!!
  - target server settings differ: sql_mode (see settings diff)

Target settings diff (baseline -> candidate):
  sql_mode: ...,ERROR_FOR_DIVISION_BY_ZERO,NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION -> ...,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION

Totals: QPS 91.3 -> 88.9 (-2.6%) | wall 18.61s -> 19.11s (+2.7%) | executed 1700 -> 1700 | errors 0 -> 0 (+0)
Fingerprints: 6 matched (3 within threshold), 0 only in baseline, 0 only in candidate, 0 with executed-count mismatch

Regressions (p95 +20% or worse, count >= 5 in both runs): 3
p95 base(ms) p95 cand(ms)      Δp95     Δmean   count b/c   res/query b→c  fingerprint
       0.607        1.226   +102.0%    +66.0%     360/360         13B→13B  select count(*), min(emp_no), max(emp_no) from employees where hire_da…
       0.190        0.243    +27.9%    +19.5%     480/480           0B→0B  insert into verify_audit (actor, action, note) values (?+)
       0.281        0.348    +23.8%    +33.6%       12/12         28B→28B  select @@version_comment limit ?

Result-size decade regressions (... 6 decade pair(s) checked): 0
Improvements (p95 -20% or better): 0
FAIL: 3 fingerprint(s) regressed >= 20% on p95 (exit code 2)
```

Note the contrast with the stock run's warning block: there, `compare`
led with `character_set_server: latin1 -> utf8mb4` and
`collation_server` drift. Here the snapshot is clean except for the
`sql_mode` token 8.0 physically cannot accept.

## This run vs the stock-defaults run — what the pins recover, per class

Same workload, same seed, same box, same shared config; the only
difference between the two candidate columns is the parity fragment.
Stock numbers from [Run 2](2026-07-16-mysql80-general.md#per-class-latency-57-vs-80-median-of-3-reports-client-side-wall-time).

| class | Δp95, stock 8.0 | Δp95, parity 8.0 | p95 stock → parity (ms) | recovered |
|---|---:|---:|---:|---|
| join+GROUP BY | **+465%** | +8% | 1144.8 → 221.8 | **98% of the regression; parity-8.0 is 5.2x faster than stock 8.0** |
| pk point lookup | +8% | +9% | 0.194 → 0.212 | nothing to recover — this was engine overhead all along |
| insert | **+25%** | **+28%** | 0.218 → 0.243 | nothing recovered — per-statement overhead, not config |
| hire-date lookup | −6% | **+102%** | 1.306 → 1.226 | candidate-side p95 essentially unchanged (1.31 → 1.23 ms); the sign flip is baseline noise — this run's 5.7 tail landed at 0.61 ms vs Run 2's 1.39 ms |

Reading per class, answering the captain's question directly:

- **join+GROUP BY: 8.0 is at par (mildly slower, +8–11%).** The +465%
  was ~98% drifted defaults — utf8mb4 grouping keys and TempTable's
  estimate-driven on-disk spill — and ~2% engine. The residual +8% is
  reproducible across passes and is the honest engine cost on this
  class.
- **pk point lookup: at par (+9%),** identical verdict with and without
  pins.
- **short INSERT: slightly slower (+20% p50 / +28% p95 at 0.16–0.24 ms
  absolute),** consistent across both runs — 8.0's fixed per-statement
  overhead, real in direction, noise-scale in magnitude.
- **hire-date secondary-index lookup: at par on the tail** (candidate
  p95 ~1.2–1.3 ms in both runs); the flagged +102% is a
  baseline-tail-landed-low artifact, not an 8.0 change (see caveats).
- **Aggregate: −2.6% QPS.** With the same parameters, 8.0 is *slightly
  slower*, not dramatically slower — and nothing in this workload gets
  faster on 8.0.

## Exact commands

```sh
# shared zz-bench.cnf (above) mounted at /etc/mysql/conf.d/zz-bench.cnf in BOTH containers;
# parity-57.cnf (verbatim from docs/parity-5.7-to-8.0.md §7) additionally mounted
# at /etc/mysql/conf.d/parity.cnf in the 8.0 container ONLY
docker run -d --name sqlt-parity-57 -p 127.0.0.1:13310:3306 -e MYSQL_ALLOW_EMPTY_PASSWORD=yes \
  -v <dataset>:/test_db:ro -v <zz-bench.cnf>:/etc/mysql/conf.d/zz-bench.cnf:ro mysql:5.7
# ... load employees.sql; verify canonical row counts; ADD INDEX idx_hire_date;
#     CREATE TABLE verify_audit; ANALYZE; create 'verify' user; slow log on;
#     workload.sh (commit 8aa0c49) all; slow log off
target/release/sql-replay capture --input verify-slow.log --out capture.jsonl.zst
target/release/sql-replay replay --capture capture.jsonl.zst \
  --url mysql://root@127.0.0.1:13310/employees --max-connections 24 \
  --allow-writes --db-override employees --filter-user verify \
  --warmup --repeat 3 --out run-57.json
docker rm -f sqlt-parity-57      # STRICTLY sequential: 8.0 starts only after this

docker run -d --name sqlt-parity-80 -p 127.0.0.1:13310:3306 -e MYSQL_ALLOW_EMPTY_PASSWORD=yes \
  -v <dataset>:/test_db:ro -v <zz-bench.cnf>:/etc/mysql/conf.d/zz-bench.cnf:ro \
  -v <parity-57.cnf>:/etc/mysql/conf.d/parity.cnf:ro mysql:8.0
# ... load identically; verify canonical row counts; same schema setup; replay the SAME capture
target/release/sql-replay replay --capture capture.jsonl.zst ... --out run-80-parity.json
docker rm -f sqlt-parity-80

target/release/sql-replay compare --baseline run-57.json --candidate run-80-parity.json \
  --top 20 --json report.json --out report.html    # defaults: threshold 20% p95, min-count 5 → exit 2
```

## Cross-validation

- The 5.7 leg reproduced Run 2's 5.7 baseline: gb p95 206.1 vs 202.5 ms
  (+1.8%), pk p95 0.195 vs 0.179, insert p95 0.190 vs 0.175 — despite
  the tool moving from 0.2.0 to 0.5.0 between the runs (same client-side
  measurement plane). The one outlier is the hire-date tail (0.61 vs
  1.39 ms) — a sub-ms class, and sub-ms p95s on this host swing tens of
  percent between identical runs (the
  [quickstart's compare walkthrough](../quickstart.md#6-compare-the-runs)
  teaches the same scheduler-noise lesson; this run's own passes ranged
  0.41–0.85 ms on the 5.7 side).
- The capture matched Run 2's shape exactly: 1701 events, 6
  fingerprints, 12 replayed sessions, dialect `mysql-5.7`.
- Peak container memory: 808 MiB (5.7) / 1.01 GiB (8.0), both far under
  budget (the 4G pool is a ceiling, not a working set, for this 160 MB
  dataset).

## Caveats

- **WSL2 virtualization + hybrid P/E cores + consumer NVMe: all numbers
  are directional/relative, not absolute predictions.** The meaningful
  outputs are same-box back-to-back ratios.
- **Sub-millisecond classes are scheduler-noise territory** at compare's
  default 20% threshold (the repo's writeups and the verify rig say the
  same). This run's three flagged regressions are all sub-ms: the
  insert delta is directionally real (consistent +17–28% across both
  runs), the hire-date +102% is a low-landing baseline tail (candidate
  absolute p95 matches Run 2's within 6%), and `@@version_comment` has
  12 samples.
- **The parity fragment targets *stock* 5.7.** A production 5.7 with
  binlog on, a raised `max_allowed_packet`, or the query cache enabled
  needs the fragment's values substituted per the
  [parity guide](../parity-5.7-to-8.0.md) (§3 caveats, §4 query-cache
  note) — this run measures the stock-to-stock engine delta only.
- **Un-pinnable differences ride along**: `sql_mode` loses
  `NO_AUTO_CREATE_USER`, the new data dictionary, undo tablespaces
  layout, and 8.0's new optimizer switches (deliberately left on — they
  are the engine under test). See the parity guide §§4–5.
- Single seeded workload (seed 42), 12 sessions, one dataset — one
  workload shape, not a general 8.0 verdict. In particular this workload
  has no DDL, no I_S traffic, and its statements fit well under 4M
  `max_allowed_packet`.
- Tool version differs from Run 2 (0.5.0 here vs 0.2.0): cross-run
  comparisons lean on the 5.7-leg cross-validation above; within-run
  deltas are unaffected.
- Same minor asymmetry as Run 2 (and the shipped rig): 5.7's
  `verify_audit` held ~1.9k workload rows before replay while 8.0's
  started empty; negligible at this table size.
- The box was shared with other workloads but idle during the runs;
  containers ran strictly sequentially.
