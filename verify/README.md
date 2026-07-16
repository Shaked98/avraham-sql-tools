# sql-replay real-data verification rig

Ground-truth test of **detection quality**, not another unit suite: it
proves on real data and real MySQL servers that the
`capture -> replay -> compare` loop flags regressions that are actually
there and stays quiet about queries that did not change.

## What it does

1. Starts `mysql:5.7` (baseline), `mysql:8.0` (candidate) and
   `mariadb:10.11` (cross-engine candidate — the 5.7 → MariaDB migration
   path) containers — all with the server charset and in-memory
   temp-table limits pinned identically (see "Why the server config is
   pinned" below) — and loads each with the identical, canonical
   [employees test dataset](https://github.com/datacharmer/test_db)
   (v1.0.7, ~300k employees / 2.8M salary rows, row counts verified against
   the dataset's published checksums table).
2. Sets up identical schema extras on all servers: a secondary index
   `idx_hire_date` on `employees(hire_date)` and an audit-style
   `verify_audit` table.
3. **Plants two large regressions on each candidate only** (the 5.7
   baseline is never touched):
   - drops `idx_hire_date`, so one query class degrades from an index
     lookup to a 300k-row table scan (expected 10x+ on p95);
   - forces the join + GROUP BY class — whose internal temp table is
     several MiB — to spill to on-disk temp tables. On 8.0:
     `temptable_max_ram` at its 2 MiB floor with mmap overflow disabled
     (`temptable_max_mmap=0`) → on-disk InnoDB temp tables. On MariaDB
     (no TempTable engine, no `temptable_max_ram`): `tmp_table_size=1K` /
     `max_heap_table_size=16K` (the variables' floors) → on-disk Aria
     temp tables.
   The PK-lookup and INSERT classes are left untouched as the
   **no-false-positive control group**.
4. Runs a deterministic, seeded 12-session concurrent workload
   (`verify/workload.sh`) against 5.7 with the slow log capturing
   (`long_query_time=0`), >= 200 executions per class.
5. `sql-replay capture` the slow log, `replay --warmup --repeat 3` against
   **all three** servers (baseline first, sequentially, so the runs never
   share CPU), then `compare` each candidate's median report against the
   baseline's with `--threshold-pct 100 --min-count 50`.
6. **Asserts the ground truth, per candidate,** and exits non-zero on any
   violation:
   - `compare` exits 2 (the regression gate fired);
   - the regressions list is *exactly* the two planted classes;
   - both control classes are present with their full sample and are
     *stable or improved* — never regressed, never low-sample;
   - the cross-engine pair (and only it) carries compare's
     "target engine families differ" warning, and the MariaDB candidate's
     server version is reported first-class;
   - every stage that could silently produce nothing is checked (dataset
     row counts, non-empty slow log, exact capture/replay event counts,
     zero replay errors).

A PASS/FAIL verdict per class and per candidate, with the measured p95s,
is printed at the end; `verify/out/report{,-maria}.html` /
`report{,-maria}.json` carry the full compare output.

## Robustness against noisy runners

Detection must be reliable, so every lever pushes the same way: seeded
workload and fixed dataset (bit-identical runs), 512 MiB buffer pools so
data stays cached, `innodb_flush_log_at_trx_commit=2` on every server and
binlog off on the candidates (fsync noise would poison the INSERT
control; MariaDB's is off by default), a warmup
pass before measuring, medians over 3 passes, planted effects sized 10x+,
and a 100% p95 threshold. The planted classes run in dedicated sessions
that open with a `SELECT SLEEP(...)` gate: at `--speed max` that parks
the heavy sessions (identical near-zero cost on both servers) while the
control sessions finish on a quiet box — without it, the planted classes'
CPU burn inflates the sub-ms controls' p95 through scheduler contention,
measurably worse on the deliberately slower candidate (a false-positive
machine; run 2 of this rig measured the PK control at +127% p95 from
contention alone). Before the long replay, cheap probes
verify each plant actually bites (index gone from
`information_schema.statistics`, probe batch timing ratios, and
`Created_tmp_disk_tables` deltas — the GROUP BY probe must spill on every
candidate and must NOT spill on the 5.7 baseline) so a misconfigured plant fails
fast with a clear message instead of a mysterious compare verdict. If a
class ever proves noisy in practice, add executions
(`WORKLOAD_*` volumes) rather than loosening assertions.

## Why the server config is pinned on both containers

On *stock defaults*, an honest, unsabotaged 8.0 already regresses the
join+GROUP BY class ~5x p95 on real hardware — past the rig's 100%
detection threshold. That would make the compare-level "planted
temp-table-spill class regressed" assertion vacuous: it would keep passing
even with the temptable plant silently broken, leaving the pre-replay
disk-spill probe as the only real check on that plant. Two stock-default
differences drive it, so the rig pins both identically on every container
(and assert-checks the pins before the dataset loads):

- **`character_set_server=latin1` / `collation_server=latin1_swedish_ci`**
  (5.7's stock defaults). Stock 8.0 defaults to
  `utf8mb4`/`utf8mb4_0900_ai_ci` (MariaDB 10.6+ likewise defaults to
  `utf8mb4`, with `utf8mb4_general_ci`), and the employees dataset DDL
  pins no charset, so without the pin the same `CREATE TABLE` produces
  latin1 tables on 5.7 and utf8mb4 tables on the candidates — and the gb
  class groups on two VARCHAR name columns, 4x wider under utf8mb4 (on
  8.0 with a costlier collation on top).
- **`tmp_table_size` / `max_heap_table_size = 128M`** (defaults: 16M).
  This is the *larger* effect, and it is easy to misattribute to the
  charset: MySQL creates an internal temp table directly **on disk** when
  the optimizer's size estimate exceeds the in-memory limit, and 8.0's
  ~888k-row estimate for the gb aggregation (actual: ~50k groups) blows
  the 16M default — so honest 8.0 pays an on-disk InnoDB temp table on
  every gb query (~4.4x slower), while 5.7 keeps the same aggregation in a
  MEMORY table under identical settings. Raising the limit keeps honest
  8.0's aggregation in RAM. The plant still bites regardless, because
  `temptable_max_ram` caps the TempTable engine's RAM budget independently
  of `tmp_table_size`.

Measured on the rig box (i7-13700KF/WSL2, honest 8.0, same replay): stock
defaults +465% p95; charset pinned alone still +341%; both pinned ~+35% —
comfortably inside the threshold, so the gb class regresses only when the
plant is active and every planted assertion again isolates its plant.

This is a property of the *rig* (its job is isolating planted effects),
not advice to hide those costs: a real stock-defaults 5.7→8.0 migration
genuinely pays both, and `compare` surfaces the cue in its comparability
warning (`character_set_server: latin1 -> utf8mb4`). For a real migration
assessment, run the comparison twice — once on stock defaults (what you
will get) and once with the charset and temp-table limits pinned or
schemas converted deliberately (what the engine change alone costs).

## Running it

In CI: manually via
`gh workflow run real-verify.yml` (plus a weekly scheduled run); reports
are uploaded as artifacts. It is deliberately not a per-PR job.

Locally, on any docker-equipped Linux machine:

```console
$ verify/run.sh
```

Requirements: a Linux host (the scripts use GNU `date +%s%N` and
`sha256sum`, absent on stock macOS), `docker`, `jq`, `curl`, `tar`, and
either a prebuilt `target/release/sql-replay` (point `SQL_REPLAY_BIN` at
another binary) or `cargo` to build one. Expected runtime:
**~20–30 minutes** (dataset loads and the deliberately slow candidate
replays dominate); ~35 MB download on first run (cached in
`verify/.cache/`, override with `VERIFY_CACHE`), ~3 GB of docker disk.
Ports 13306/13307/13308 must be free
(override with `VERIFY_PORT_57` / `VERIFY_PORT_80` / `VERIFY_PORT_MARIA`;
`VERIFY_SEED`, `VERIFY_SESSIONS`, `VERIFY_REPEAT`, `VERIFY_THRESHOLD_PCT`
and `VERIFY_MIN_COUNT` are also
overridable). Set `KEEP_CONTAINERS=1` to leave the three servers up
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
