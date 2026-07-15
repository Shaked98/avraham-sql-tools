# sql-replay real-data verification rig

Ground-truth test of **detection quality**, not another unit suite: it
proves on real data and real MySQL servers that the
`capture -> replay -> compare` loop flags regressions that are actually
there and stays quiet about queries that did not change.

## What it does

1. Starts `mysql:5.7` (baseline) and `mysql:8.0` (candidate) containers and
   loads both with the identical, canonical
   [employees test dataset](https://github.com/datacharmer/test_db)
   (v1.0.7, ~300k employees / 2.8M salary rows, row counts verified against
   the dataset's published checksums table).
2. Sets up identical schema extras on both: a secondary index
   `idx_hire_date` on `employees(hire_date)` and an audit-style
   `verify_audit` table.
3. **Plants two large regressions on the 8.0 candidate only:**
   - drops `idx_hire_date`, so one query class degrades from an index
     lookup to a 300k-row table scan (expected 10x+ on p95);
   - sets `temptable_max_ram` to its 2 MiB floor and disables mmap
     overflow (`temptable_max_mmap=0`), so the join + GROUP BY class —
     whose internal temp table is several MiB — spills to on-disk InnoDB
     temp tables.
   The PK-lookup and INSERT classes are left untouched as the
   **no-false-positive control group**.
4. Runs a deterministic, seeded 12-session concurrent workload
   (`verify/workload.sh`) against 5.7 with the slow log capturing
   (`long_query_time=0`), >= 200 executions per class.
5. `sql-replay capture` the slow log, `replay --warmup --repeat 3` against
   **both** servers (baseline first, sequentially, so the runs never share
   CPU), then `compare` the median reports with `--threshold-pct 100
   --min-count 50`.
6. **Asserts the ground truth** and exits non-zero on any violation:
   - `compare` exits 2 (the regression gate fired);
   - the regressions list is *exactly* the two planted classes;
   - both control classes are present with their full sample and are
     *stable or improved* — never regressed, never low-sample;
   - every stage that could silently produce nothing is checked (dataset
     row counts, non-empty slow log, exact capture/replay event counts,
     zero replay errors).

A PASS/FAIL verdict per class, with the measured p95s, is printed at the
end; `verify/out/report.html` / `report.json` carry the full compare
output.

## Robustness against noisy runners

Detection must be reliable, so every lever pushes the same way: seeded
workload and fixed dataset (bit-identical runs), 512 MiB buffer pools so
data stays cached, `innodb_flush_log_at_trx_commit=2` on both servers and
binlog off on 8.0 (fsync noise would poison the INSERT control), a warmup
pass before measuring, medians over 3 passes, planted effects sized 10x+,
and a 100% p95 threshold. The planted classes run in dedicated sessions
that open with a `SELECT SLEEP(...)` gate: at `--speed max` that parks
the heavy sessions (identical near-zero cost on both servers) while the
control sessions finish on a quiet box — without it, the planted classes'
CPU burn inflates the sub-ms controls' p95 through scheduler contention,
measurably worse on the deliberately slower candidate (a false-positive
machine; run 2 of this rig measured the PK control at +127% p95 from
contention alone). Before the long replay, cheap probe batches
verify each plant actually bites (index gone from
`information_schema.statistics`, probe timing ratios) so a misconfigured
plant fails fast with a clear message instead of a mysterious compare
verdict. If a class ever proves noisy in practice, add executions
(`WORKLOAD_*` volumes) rather than loosening assertions.

## Running it

In CI: manually via
`gh workflow run real-verify.yml` (plus a weekly scheduled run); reports
are uploaded as artifacts. It is deliberately not a per-PR job.

Locally, on any docker-equipped machine:

```console
$ verify/run.sh
```

Requirements: `docker`, `jq`, `curl`, and either a prebuilt
`target/release/sql-replay` or `cargo` to build one. Expected runtime:
**~15–25 minutes** (dataset load and the deliberately slow candidate
replay dominate); ~35 MB download on first run (cached in
`verify/.cache/`), ~2 GB of docker disk. Ports 13306/13307 must be free
(override with `VERIFY_PORT_57` / `VERIFY_PORT_80`; `VERIFY_SEED`,
`VERIFY_SESSIONS`, `VERIFY_REPEAT`, `VERIFY_THRESHOLD_PCT` are also
overridable). Set `KEEP_CONTAINERS=1` to leave the two MySQL servers up
for post-mortem poking.

## Reading a failure

- **`plant '...' looks ineffective`** — the sabotage didn't produce the
  expected slowdown on the candidate before replay even started; nothing
  is wrong with sql-replay itself. Check the probe timings printed just
  above, and whether the MySQL images changed behavior.
- **`FAIL planted ... class regressed`** — the whole point: sql-replay
  failed to detect a regression that is really there. Open
  `verify/out/report.json` and find the class's fingerprint under
  `stable`/`improvements` to see the measured p95s.
- **`FAIL control ... is NOT a regression`** — a false positive on an
  untouched query class. Look at the class's p95s in the report; if the
  candidate really was 2x slower, suspect environmental asymmetry
  (fsync/binlog settings, cold caches) before suspecting compare.
- **Exact-count assertion failures** (`expected N executed events`, row
  counts, empty slow log) — a rig stage silently under-produced; the
  message names the stage. `verify/out/` keeps every intermediate
  (session SQL files and their outputs, slow log, capture, per-pass run
  reports) for inspection.

The four query classes live in `verify/workload.sh` (SQL text) and
`verify/run.sh` (`FP_*` fingerprint constants); they must stay in sync —
the run.json per-fingerprint count assertions catch drift loudly.
