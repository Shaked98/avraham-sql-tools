#!/usr/bin/env bash
# Real-data verification rig for sql-replay: prove, on the real employees
# dataset against real MySQL 5.7/8.0 and MariaDB servers, that the
# capture -> replay -> compare loop DETECTS deliberately planted
# regressions and does NOT flag untouched control queries. Ground truth,
# not another unit suite.
#
#   baseline  mysql:5.7      loaded with github.com/datacharmer/test_db,
#                            plus a secondary index on employees(hire_date)
#   candidate mysql:8.0      loaded identically, then sabotaged:
#               (a) idx_hire_date dropped        -> index lookups scan 300k rows
#               (b) temptable_max_ram=2MiB (min) -> the join+GROUP BY class
#                   + temptable_max_mmap=0          spills to on-disk temp tables
#   candidate mariadb:10.11  loaded identically, then sabotaged the same
#             way modulo engine differences (MariaDB has no TempTable
#             engine, so the temp-table plant floors tmp_table_size /
#             max_heap_table_size instead):
#               (a) idx_hire_date dropped        -> same 300k-row scans
#               (b) tmp_table_size=1K (floor)    -> the join+GROUP BY class
#                   + max_heap_table_size=16K       spills to on-disk Aria
#                                                   temp tables
#             On every candidate the PK-lookup and INSERT classes stay
#             untouched as the no-false-positive control group. The MariaDB
#             leg proves cross-engine detection for the 5.7 -> MariaDB
#             migration path.
#
# A seeded 12-session workload (verify/workload.sh) runs against 5.7 with
# the slow log capturing; the log is captured, replayed with
# --warmup --repeat 3 against ALL servers, and each candidate's median
# report is compared against the 5.7 one. The rig exits non-zero unless,
# for EVERY candidate: compare exits 2, exactly the two planted classes are
# in the regressions list, and both control classes are present and clean.
#
# Requirements: docker, jq, curl, tar, and the sql-replay binary (built
# from this checkout with `cargo build --release` if missing). Runtime on a
# 4-core GitHub runner: ~15-25 minutes, most of it dataset load and the
# deliberately slow candidate replay. verify/out/ is wiped at the start of
# each run; the ~35 MB dataset tarball is cached in verify/.cache/.
set -euo pipefail
cd "$(dirname "$0")/.."

# ---------------------------------------------------------------- knobs
SEED=${VERIFY_SEED:-42}
SESSIONS=${VERIFY_SESSIONS:-12}
REPEAT=${VERIFY_REPEAT:-3}
THRESHOLD_PCT=${VERIFY_THRESHOLD_PCT:-100} # compare gate: p95 must double
MIN_COUNT=${VERIFY_MIN_COUNT:-50}
PORT57=${VERIFY_PORT_57:-13306}
PORT80=${VERIFY_PORT_80:-13307}
PORTMD=${VERIFY_PORT_MARIA:-13308}
C57=sql-replay-verify-57
C80=sql-replay-verify-80
CMARIA=sql-replay-verify-maria
OUT=verify/out
CACHE=${VERIFY_CACHE:-verify/.cache}
BIN=${SQL_REPLAY_BIN:-target/release/sql-replay}
DATASET_URL=https://github.com/datacharmer/test_db/releases/download/v1.0.7/test_db-1.0.7.tar.gz
DATASET_SHA256=c44c140f352f35d47fdb65df60f52b779ef552822fad6c4efcfa7b134c3faf84

# Session roles and per-session class volumes (see verify/workload.sh:
# planted classes get dedicated SLEEP-gated sessions so the control
# classes run on a quiet box; the rest are fast control sessions).
GB_SESSIONS=4
HIRE_SESSIONS=4
HEAVY_SESSIONS=$((GB_SESSIONS + HIRE_SESSIONS))
FAST_SESSIONS=$((SESSIONS - HEAVY_SESSIONS))
PK_PER_SESSION=160 HIRE_PER_SESSION=90 GB_PER_SESSION=50 INS_PER_SESSION=120
TOTAL_PK=$((PK_PER_SESSION * FAST_SESSIONS))
TOTAL_HIRE=$((HIRE_PER_SESSION * HIRE_SESSIONS))
TOTAL_GB=$((GB_PER_SESSION * GB_SESSIONS))
TOTAL_INS=$((INS_PER_SESSION * FAST_SESSIONS))
TOTAL_EVENTS=$((TOTAL_PK + TOTAL_HIRE + TOTAL_GB + TOTAL_INS))
# Beyond the generated statements, every session's mysql client sends
# `select @@version_comment limit 1` on connect (batch mode included), and
# every heavy session opens with its SELECT SLEEP gate event.
TOTAL_EXECUTED=$((TOTAL_EVENTS + SESSIONS + HEAVY_SESSIONS))
((FAST_SESSIONS >= 1)) || {
  printf '\nFAIL: VERIFY_SESSIONS=%s leaves no control sessions: the %s heavy planted-class sessions are fixed, so it must be at least %s\n' \
    "$SESSIONS" "$HEAVY_SESSIONS" "$((HEAVY_SESSIONS + 1))" >&2
  exit 1
}
((SESSIONS < MIN_COUNT)) || {
  printf '\nFAIL: VERIFY_SESSIONS=%s must stay below VERIFY_MIN_COUNT=%s, or the per-session client startup query reaches --min-count and breaks the low-sample exact-set assertion\n' \
    "$SESSIONS" "$MIN_COUNT" >&2
  exit 1
}

# The workload classes as sql-replay fingerprints (normalized text, matched
# exactly against compare's report.json). Must stay in sync with the SQL
# emitted by verify/workload.sh.
FP_PK='select emp_no, first_name, last_name, gender from employees where emp_no = ?'
FP_HIRE='select count(*), min(emp_no), max(emp_no) from employees where hire_date = ?'
FP_GB='select e.first_name, e.last_name, count(*) as cnt, avg(s.salary) as avg_sal from employees e join salaries s on s.emp_no = e.emp_no where e.emp_no between ? and ? group by e.first_name, e.last_name order by avg_sal desc limit ?'
FP_INS='insert into verify_audit (actor, action, note) values (?+)'
# Incidental fingerprints, both deliberately below --min-count so they
# land in the report's low_sample bucket, never the ranking: the mysql
# client's own startup query and the heavy sessions' SLEEP gate.
FP_VER='select @@version_comment limit ?'
FP_SLEEP='select sleep(?)'

# ---------------------------------------------------------------- helpers
stage() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
die() {
  printf '\nFAIL: %s\n' "$*" >&2
  exit 1
}

# mrun <container> <sql> [db] — run SQL as root inside a server container.
mrun() {
  docker exec "$1" mysql -uroot -N -B ${3:+--database="$3"} -e "$2"
}

# timed_batch <container> <sql-file> — wall-clock ms for one mysql client
# running the whole file.
timed_batch() {
  local t0 t1
  t0=$(date +%s%N)
  docker exec -i "$1" mysql -uroot -N -B employees <"$2" >/dev/null
  t1=$(date +%s%N)
  echo $(((t1 - t0) / 1000000))
}

cleanup() {
  if [[ "${KEEP_CONTAINERS:-0}" != 1 ]]; then
    docker rm -f "$C57" "$C80" "$CMARIA" >/dev/null 2>&1 || true
  else
    echo "KEEP_CONTAINERS=1: leaving $C57 (:$PORT57), $C80 (:$PORT80) and $CMARIA (:$PORTMD) running"
  fi
}
trap cleanup EXIT

wait_ready() { # wait_ready <container>
  local i
  for ((i = 0; i < 120; i++)); do
    # TCP ping: the image's init-phase temp server is socket-only, so this
    # only succeeds once the real server is up.
    if docker exec "$1" mysqladmin ping -h127.0.0.1 --silent >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  echo "--- docker logs $1 (tail) ---" >&2
  docker logs "$1" 2>&1 | tail -30 >&2
  die "$1 did not become ready within 240s"
}

# ---------------------------------------------------------------- stages
stage "preflight"
command -v docker >/dev/null || die "docker is required"
command -v jq >/dev/null || die "jq is required"
command -v curl >/dev/null || die "curl is required"
if [[ ! -x "$BIN" ]]; then
  command -v cargo >/dev/null || die "no $BIN and no cargo to build it"
  echo "building $BIN"
  cargo build --release -p sql-replay
fi
"$BIN" --version
rm -rf "$OUT"
mkdir -p "$OUT" "$CACHE"

stage "dataset: employees test_db v1.0.7 (~35 MB download, cached)"
if [[ ! -f "$CACHE/test_db/employees.sql" ]]; then
  curl -fsSL --retry 3 -o "$CACHE/test_db.tar.gz" "$DATASET_URL"
  echo "$DATASET_SHA256  $CACHE/test_db.tar.gz" | sha256sum -c - ||
    die "dataset tarball checksum mismatch"
  tar -xzf "$CACHE/test_db.tar.gz" -C "$CACHE"
  [[ -f "$CACHE/test_db/employees.sql" ]] || die "dataset tarball layout unexpected"
else
  echo "using cached dataset in $CACHE/test_db"
fi
DATASET_DIR=$(cd "$CACHE/test_db" && pwd)

stage "start mysql:5.7 (baseline, :$PORT57), mysql:8.0 (candidate, :$PORT80) and mariadb:10.11 (candidate, :$PORTMD)"
docker rm -f "$C57" "$C80" "$CMARIA" >/dev/null 2>&1 || true
# Identical config apart from version quirks: 512M buffer pool so the
# dataset stays cached (stable latencies); binlog off on 8.0 to match
# 5.7's default (sync_binlog=1 would otherwise slow every replayed INSERT
# on the candidate and poison the control group).
#
# Two further settings are pinned identically on BOTH servers because with
# the stock defaults an HONEST, unsabotaged 8.0 already regresses the
# join+GROUP BY class past the 100% threshold — which would make the
# compare-level "temptable plant detected" assertion vacuous (it would keep
# passing with the plant broken):
#   - character_set_server=latin1 + collation_server=latin1_swedish_ci
#     (5.7's stock defaults). The employees DDL pins no charset, so tables
#     inherit the server default — latin1 on 5.7 but utf8mb4 with the
#     costlier utf8mb4_0900_ai_ci on stock 8.0, and the gb class groups on
#     two VARCHAR name keys, 4x wider under utf8mb4.
#   - tmp_table_size/max_heap_table_size=128M (defaults: 16M). 8.0 creates
#     an internal temp table directly ON DISK when the optimizer's estimate
#     of its size exceeds the in-memory limit; its ~888k-row estimate for
#     the gb aggregation (actual: ~50k groups) blows the 16M default, so
#     honest 8.0 pays an on-disk InnoDB temp table on every gb query —
#     ~4.4x slower than 5.7, which keeps the same aggregation in a MEMORY
#     table under identical settings. This, not the charset, is the larger
#     effect. 128M keeps honest 8.0's aggregation in RAM; the plant still
#     bites because temptable_max_ram caps TempTable's RAM budget
#     regardless of tmp_table_size.
# With both pinned, the gb class regresses only when the temptable plant is
# active (see verify/README.md, "Why the server config is pinned").
PINS=(--character-set-server=latin1 --collation-server=latin1_swedish_ci
  --tmp-table-size=134217728 --max-heap-table-size=134217728)
docker run -d --name "$C57" -p "127.0.0.1:$PORT57:3306" \
  -e MYSQL_ALLOW_EMPTY_PASSWORD=yes \
  -v "$DATASET_DIR:/test_db:ro" \
  mysql:5.7 --innodb-buffer-pool-size=512M "${PINS[@]}" >/dev/null
docker run -d --name "$C80" -p "127.0.0.1:$PORT80:3306" \
  -e MYSQL_ALLOW_EMPTY_PASSWORD=yes \
  -v "$DATASET_DIR:/test_db:ro" \
  mysql:8.0 --innodb-buffer-pool-size=512M --disable-log-bin "${PINS[@]}" >/dev/null
# The mariadb image keeps mysql/mysqladmin compat shims, so mrun/wait_ready
# work unchanged. Binlog is already off by default; the same charset and
# temp-table pins matter doubly here because MariaDB 10.6+ also defaults
# character_set_server to utf8mb4.
docker run -d --name "$CMARIA" -p "127.0.0.1:$PORTMD:3306" \
  -e MARIADB_ALLOW_EMPTY_ROOT_PASSWORD=yes \
  -v "$DATASET_DIR:/test_db:ro" \
  mariadb:10.11 --innodb-buffer-pool-size=512M "${PINS[@]}" >/dev/null
wait_ready "$C57"
wait_ready "$C80"
wait_ready "$CMARIA"
# Cut fsync-per-commit out of all servers identically: INSERT latencies on
# shared CI runners are hopeless otherwise.
mrun "$C57" "SET GLOBAL innodb_flush_log_at_trx_commit = 2"
mrun "$C80" "SET GLOBAL innodb_flush_log_at_trx_commit = 2"
mrun "$CMARIA" "SET GLOBAL innodb_flush_log_at_trx_commit = 2"
# Fail fast if a future image stops honoring the pins: the dataset has not
# been loaded yet (tables inherit the charset at CREATE time), and a
# silently ignored temp-table limit would quietly re-weaken the gb ground
# truth.
for c in "$C57" "$C80" "$CMARIA"; do
  got=$(mrun "$c" "SELECT @@character_set_server, @@collation_server,
                   @@tmp_table_size, @@max_heap_table_size")
  [[ "$got" == $'latin1\tlatin1_swedish_ci\t134217728\t134217728' ]] ||
    die "server config pins did not apply on $c (got: $got); the gb ground truth needs them identical on both servers"
done

stage "load the employees dataset into all servers (parallel, ~2-5 min)"
load() { # load <container> <logfile>
  docker exec -i -w /test_db "$1" sh -c 'mysql -uroot <employees.sql' >"$2" 2>&1
}
load "$C57" "$OUT/load-57.log" &
P57=$!
load "$C80" "$OUT/load-80.log" &
P80=$!
load "$CMARIA" "$OUT/load-maria.log" &
PMD=$!
wait $P57 || {
  tail -20 "$OUT/load-57.log" >&2
  die "dataset load failed on 5.7"
}
wait $P80 || {
  tail -20 "$OUT/load-80.log" >&2
  die "dataset load failed on 8.0"
}
wait $PMD || {
  tail -20 "$OUT/load-maria.log" >&2
  die "dataset load failed on mariadb"
}

stage "verify all servers hold the identical canonical dataset"
COUNTS_SQL="SELECT 'employees', COUNT(*) FROM employees
UNION ALL SELECT 'departments', COUNT(*) FROM departments
UNION ALL SELECT 'dept_manager', COUNT(*) FROM dept_manager
UNION ALL SELECT 'dept_emp', COUNT(*) FROM dept_emp
UNION ALL SELECT 'titles', COUNT(*) FROM titles
UNION ALL SELECT 'salaries', COUNT(*) FROM salaries"
CANONICAL=$'employees\t300024\ndepartments\t9\ndept_manager\t24\ndept_emp\t331603\ntitles\t443308\nsalaries\t2844047'
for c in "$C57" "$C80" "$CMARIA"; do
  got=$(mrun "$c" "$COUNTS_SQL" employees)
  [[ "$got" == "$CANONICAL" ]] || {
    printf 'expected:\n%s\ngot from %s:\n%s\n' "$CANONICAL" "$c" "$got" >&2
    die "dataset row counts wrong on $c"
  }
done
echo "row counts match the canonical employees dataset on all servers"

stage "common setup on all servers (index, audit table, ANALYZE)"
SETUP_SQL="ALTER TABLE employees ADD INDEX idx_hire_date (hire_date);
CREATE TABLE verify_audit (
  id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  actor VARCHAR(32) NOT NULL,
  action VARCHAR(16) NOT NULL,
  note VARCHAR(64) NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;
ANALYZE TABLE employees, salaries;"
mrun "$C57" "$SETUP_SQL" employees >/dev/null
mrun "$C80" "$SETUP_SQL" employees >/dev/null
mrun "$CMARIA" "$SETUP_SQL" employees >/dev/null
# Dedicated workload user on the capture side, so replay can --filter-user
# and the rig's own admin statements never become replayed events.
mrun "$C57" "CREATE USER 'verify'@'%' IDENTIFIED BY 'verify';
GRANT SELECT, INSERT ON employees.* TO 'verify'@'%';"

stage "plant regressions on the candidates ONLY (never the 5.7 baseline)"
mrun "$C80" "ALTER TABLE employees DROP INDEX idx_hire_date" employees
# 2 MiB is temptable_max_ram's floor; with mmap overflow disabled, any
# internal temp table above it becomes an on-disk InnoDB temp table.
mrun "$C80" "SET GLOBAL temptable_max_ram = 2097152"
mrun "$C80" "SET GLOBAL temptable_max_mmap = 0"
echo "planted on 8.0: idx_hire_date dropped; temptable_max_ram=2MiB, mmap overflow off"
mrun "$CMARIA" "ALTER TABLE employees DROP INDEX idx_hire_date" employees
# MariaDB has no TempTable engine (and no temptable_max_ram): the
# equivalent plant floors the classic MEMORY-engine limits, so the gb
# class's several-MiB internal temp table converts to an on-disk Aria
# table on every query. 1K/16K are the variables' documented minimums;
# SET GLOBAL affects new connections, and replay connects fresh.
mrun "$CMARIA" "SET GLOBAL tmp_table_size = 1024"
mrun "$CMARIA" "SET GLOBAL max_heap_table_size = 16384"
echo "planted on mariadb: idx_hire_date dropped; tmp_table_size=1K, max_heap_table_size=16K"

stage "verify the plants actually bite (probe timings, min work before the long replay)"
have_idx() { # have_idx <container> -> row count of the index in i_s
  mrun "$1" "SELECT COUNT(*) FROM information_schema.statistics
             WHERE table_schema='employees' AND table_name='employees'
             AND index_name='idx_hire_date'"
}
[[ "$(have_idx "$C57")" == 1 ]] || die "idx_hire_date missing on the 5.7 baseline"
[[ "$(have_idx "$C80")" == 0 ]] || die "idx_hire_date still present on the 8.0 candidate"
[[ "$(have_idx "$CMARIA")" == 0 ]] || die "idx_hire_date still present on the mariadb candidate"

# 20 index-class lookups per batch: client startup cost amortizes away.
for i in $(seq 1 20); do
  echo "SELECT COUNT(*), MIN(emp_no), MAX(emp_no) FROM employees WHERE hire_date = '1992-06-15';"
done >"$OUT/probe-hire.sql"
# 3 group-by-class aggregates per batch (they are ~100x slower each).
for i in 1 2 3; do
  echo "SELECT e.first_name, e.last_name, COUNT(*) AS cnt, AVG(s.salary) AS avg_sal FROM employees e JOIN salaries s ON s.emp_no = e.emp_no WHERE e.emp_no BETWEEN 200000 AND 249999 GROUP BY e.first_name, e.last_name ORDER BY avg_sal DESC LIMIT 10;"
done >"$OUT/probe-gb.sql"

probe_ratio() { # probe_ratio <candidate-container> <cand-label> <file> <label> <min-ratio>
  local cand=$1 cand_label=$2 file=$3 label=$4 min=$5 ms57 msc
  # First run doubles as cache warm-up on both sides; measure the second.
  timed_batch "$C57" "$file" >/dev/null
  ms57=$(timed_batch "$C57" "$file")
  timed_batch "$cand" "$file" >/dev/null
  msc=$(timed_batch "$cand" "$file")
  echo "probe $label: 5.7=${ms57}ms $cand_label=${msc}ms (batch)" >&2
  [[ "$ms57" -gt 0 ]] || ms57=1
  if ((msc < min * ms57)); then
    die "plant '$label' looks ineffective: $cand_label batch ${msc}ms vs 5.7 ${ms57}ms (need ${min}x); tune the plant/workload before trusting compare"
  fi
}
tmp_disk_delta() { # Created_tmp_disk_tables delta for one gb-class query
  local c=$1 before after
  before=$(mrun "$c" "SHOW GLOBAL STATUS LIKE 'Created_tmp_disk_tables'" | cut -f2)
  head -1 "$OUT/probe-gb.sql" | docker exec -i "$c" mysql -uroot -N -B employees >/dev/null
  after=$(mrun "$c" "SHOW GLOBAL STATUS LIKE 'Created_tmp_disk_tables'" | cut -f2)
  echo $((after - before))
}
SPILL57=$(tmp_disk_delta "$C57")
SPILL80=$(tmp_disk_delta "$C80")
SPILLMD=$(tmp_disk_delta "$CMARIA")
echo "gb probe on-disk temp tables created: 5.7=$SPILL57 8.0=$SPILL80 mariadb=$SPILLMD"
[[ "$SPILL57" == 0 ]] ||
  die "gb class spills to disk on the 5.7 BASELINE too (delta $SPILL57) — the planted contrast is gone; shrink the group count"
[[ "$SPILL80" -ge 1 ]] ||
  die "gb class did not spill to disk on the 8.0 candidate — temptable plant ineffective; grow the group count"
[[ "$SPILLMD" -ge 1 ]] ||
  die "gb class did not spill to disk on the mariadb candidate — tmp_table_size plant ineffective; grow the group count"
probe_ratio "$C80" "8.0" "$OUT/probe-hire.sql" "hire_date index drop (8.0)" 3
probe_ratio "$C80" "8.0" "$OUT/probe-gb.sql" "temptable disk spill (8.0)" 2
probe_ratio "$CMARIA" "mariadb" "$OUT/probe-hire.sql" "hire_date index drop (mariadb)" 3
probe_ratio "$CMARIA" "mariadb" "$OUT/probe-gb.sql" "tmp-table disk spill (mariadb)" 2

stage "run the seeded workload against 5.7 with the slow log capturing"
mrun "$C57" "SET GLOBAL slow_query_log_file = '/var/lib/mysql/verify-slow.log';
SET GLOBAL log_output = 'FILE';
SET GLOBAL log_slow_admin_statements = ON;
SET GLOBAL long_query_time = 0;
SET GLOBAL slow_query_log = ON;"
WORKLOAD_OUT="$OUT" WORKLOAD_SEED="$SEED" WORKLOAD_SESSIONS="$SESSIONS" \
  WORKLOAD_GB_SESSIONS="$GB_SESSIONS" WORKLOAD_HIRE_SESSIONS="$HIRE_SESSIONS" \
  WORKLOAD_PK="$PK_PER_SESSION" WORKLOAD_HIRE="$HIRE_PER_SESSION" \
  WORKLOAD_GB="$GB_PER_SESSION" WORKLOAD_INS="$INS_PER_SESSION" \
  WORKLOAD_CONTAINER="$C57" verify/workload.sh all
mrun "$C57" "SET GLOBAL slow_query_log = OFF; SET GLOBAL long_query_time = 10;"
docker cp "$C57:/var/lib/mysql/verify-slow.log" "$OUT/verify-slow.log"
[[ -s "$OUT/verify-slow.log" ]] || die "slow log is empty — capture produced nothing"
echo "slow log: $(wc -c <"$OUT/verify-slow.log") bytes"

stage "sql-replay capture"
"$BIN" capture --input "$OUT/verify-slow.log" --out "$OUT/capture.jsonl.zst" |
  tee "$OUT/capture-summary.txt"
CAPTURED=$(sed -n 's/^captured \([0-9]\+\) events.*/\1/p' "$OUT/capture-summary.txt")
[[ -n "$CAPTURED" && "$CAPTURED" -ge "$TOTAL_EXECUTED" ]] ||
  die "capture holds ${CAPTURED:-0} events, expected >= $TOTAL_EXECUTED"

stage "replay (--warmup --repeat $REPEAT) against all servers, baseline first"
replay() { # replay <url> <run.json>
  "$BIN" replay \
    --capture "$OUT/capture.jsonl.zst" \
    --url "$1" \
    --max-connections $((SESSIONS + 4)) \
    --allow-writes \
    --db-override employees \
    --filter-user verify \
    --warmup --repeat "$REPEAT" \
    --out "$2"
}
assert_run() { # assert_run <run.json>
  jq -e --argjson n "$TOTAL_EXECUTED" '.totals.executed == $n' "$1" >/dev/null ||
    die "$1: expected $TOTAL_EXECUTED executed events, got $(jq '.totals.executed' "$1")"
  jq -e '.totals.errors == 0' "$1" >/dev/null ||
    die "$1: replay hit SQL errors: $(jq -r '[.fingerprints[] | select(.errors > 0) | .first_error][0]' "$1")"
  jq -e '.aborted == false' "$1" >/dev/null || die "$1: replay was aborted"
  jq -e --argjson s "$SESSIONS" '.totals.sessions == $s' "$1" >/dev/null ||
    die "$1: expected $SESSIONS sessions, got $(jq '.totals.sessions' "$1")"
  local fp want
  for spec in "$FP_PK|$TOTAL_PK" "$FP_HIRE|$TOTAL_HIRE" "$FP_GB|$TOTAL_GB" \
    "$FP_INS|$TOTAL_INS" "$FP_VER|$SESSIONS" "$FP_SLEEP|$HEAVY_SESSIONS"; do
    fp=${spec%|*} want=${spec##*|}
    jq -e --arg fp "$fp" --argjson want "$want" \
      '[.fingerprints[] | select(.fingerprint == $fp) | .count] == [$want]' "$1" >/dev/null ||
      die "$1: fingerprint '$fp' does not have exactly $want executions"
  done
}
replay "mysql://root@127.0.0.1:$PORT57/employees" "$OUT/run-baseline-57.json"
assert_run "$OUT/run-baseline-57.json"
replay "mysql://root@127.0.0.1:$PORT80/employees" "$OUT/run-candidate-80.json"
assert_run "$OUT/run-candidate-80.json"
replay "mysql://root@127.0.0.1:$PORTMD/employees" "$OUT/run-candidate-maria.json"
assert_run "$OUT/run-candidate-maria.json"

# compare_candidate <run.json> <report-basename> <stdout-file> — exit code
# lands in COMPARE_EXIT.
compare_candidate() {
  set +e
  "$BIN" compare \
    --baseline "$OUT/run-baseline-57.json" \
    --candidate "$1" \
    --threshold-pct "$THRESHOLD_PCT" \
    --min-count "$MIN_COUNT" \
    --top 20 \
    --json "$OUT/$2.json" \
    --out "$OUT/$2.html" | tee "$OUT/$3"
  COMPARE_EXIT=${PIPESTATUS[0]}
  set -e
  [[ -s "$OUT/$2.json" ]] || die "compare produced no $2.json"
}

FAILURES=0
check() { # check <description> <jq filter> [extra jq args...]
  local desc=$1 filter=$2
  shift 2
  if jq -e "$@" "$filter" "$REPORT" >/dev/null; then
    echo "  ok   $desc"
  else
    echo "  FAIL $desc"
    FAILURES=$((FAILURES + 1))
  fi
}

# ground_truth <report.json> <compare-exit> — the detection-quality
# assertions, identical for every candidate: exactly the two planted
# classes regress, both controls stay clean.
ground_truth() {
  REPORT=$1
  local compare_exit=$2
  if [[ "$compare_exit" == 2 ]]; then
    echo "  ok   compare exited 2 (regression gate fired)"
  else
    echo "  FAIL compare exited $compare_exit, want 2"
    FAILURES=$((FAILURES + 1))
  fi
  check "planted index-drop class regressed" \
    '[.regressions[].fingerprint] | index($fp) != null' --arg fp "$FP_HIRE"
  check "planted temp-table-spill class regressed" \
    '[.regressions[].fingerprint] | index($fp) != null' --arg fp "$FP_GB"
  check "regressions list is EXACTLY the two planted classes" \
    '.regressions | length == 2'
  check "control pk-lookup class is NOT a regression" \
    '[.regressions[].fingerprint] | index($fp) == null' --arg fp "$FP_PK"
  check "control insert class is NOT a regression" \
    '[.regressions[].fingerprint] | index($fp) == null' --arg fp "$FP_INS"
  check "control pk-lookup class present with a full sample (stable or improved)" \
    '[(.stable + .improvements)[].fingerprint] | index($fp) != null' --arg fp "$FP_PK"
  check "control insert class present with a full sample (stable or improved)" \
    '[(.stable + .improvements)[].fingerprint] | index($fp) != null' --arg fp "$FP_INS"
  check "low-sample bucket holds only the client startup query and the SLEEP gate" \
    '([.low_sample[].fingerprint] | sort) == ([$fpver, $fpsleep] | sort)' \
    --arg fpver "$FP_VER" --arg fpsleep "$FP_SLEEP"
  check "no fingerprints exclusive to one run" \
    '(.only_in_baseline | length == 0) and (.only_in_candidate | length == 0)'
  check "no executed-count mismatches" '.count_mismatches == 0'
}

verdicts() { # verdicts <report.json> <candidate-label>
  REPORT=$1
  printf '%-28s %-11s %13s %13s %11s\n' class verdict "p95 5.7 (ms)" "p95 $2 (ms)" "delta"
  row() { # row <label> <fp>
    jq -r --arg fp "$2" --arg label "$1" '
      def loc: if ([.regressions[].fingerprint] | index($fp)) != null then "REGRESSED"
        elif ([.improvements[].fingerprint] | index($fp)) != null then "improved"
        elif ([.stable[].fingerprint] | index($fp)) != null then "stable"
        elif ([.low_sample[].fingerprint] | index($fp)) != null then "low-sample"
        else "MISSING" end;
      ((.regressions + .improvements + .stable + .low_sample)[] | select(.fingerprint == $fp)) as $d |
      [$label, loc,
       ($d.p95.baseline_us / 1000 | tostring),
       ($d.p95.candidate_us / 1000 | tostring),
       (if $d.p95.delta_pct == null then "n/a" else ($d.p95.delta_pct | round | tostring) + "%" end)]
      | @tsv' "$REPORT" 2>/dev/null |
      awk -F'\t' '{printf "%-28s %-11s %13.2f %13.2f %11s\n", $1, $2, $3, $4, $5}'
  }
  row "hire-date (index dropped)" "$FP_HIRE"
  row "group-by (temptable spill)" "$FP_GB"
  row "pk-lookup (control)" "$FP_PK"
  row "insert (control)" "$FP_INS"
}

stage "compare 5.7 -> 8.0 (threshold ${THRESHOLD_PCT}% p95, min-count $MIN_COUNT) — expecting exit 2"
compare_candidate "$OUT/run-candidate-80.json" report compare-stdout.txt
COMPARE_EXIT_80=$COMPARE_EXIT

stage "compare 5.7 -> mariadb (threshold ${THRESHOLD_PCT}% p95, min-count $MIN_COUNT) — expecting exit 2"
compare_candidate "$OUT/run-candidate-maria.json" report-maria compare-stdout-maria.txt
COMPARE_EXIT_MD=$COMPARE_EXIT

stage "ground truth: 5.7 -> 8.0"
ground_truth "$OUT/report.json" "$COMPARE_EXIT_80"
# Same-engine pair: the cross-engine warning must not fire here.
check "no engine-family warning on the same-engine pair" \
  '[.comparability_warnings[] | select(contains("engine families differ"))] | length == 0'

stage "ground truth: 5.7 -> mariadb (cross-engine)"
ground_truth "$OUT/report-maria.json" "$COMPARE_EXIT_MD"
# The cross-engine pair must be labeled as such, and the MariaDB target's
# version must be reported first-class.
check "engine-family warning present on the cross-engine pair" \
  '[.comparability_warnings[] | select(contains("engine families differ"))] | length == 1'
check "candidate server version reports as MariaDB" \
  '.candidate.target_server_version | contains("MariaDB")'

stage "per-class verdicts: 5.7 -> 8.0"
verdicts "$OUT/report.json" "8.0"
stage "per-class verdicts: 5.7 -> mariadb"
verdicts "$OUT/report-maria.json" "maria"

echo
if [[ "$FAILURES" -eq 0 ]]; then
  echo "PASS: both planted regressions detected on every candidate, all controls clean."
  echo "reports: $OUT/report.html, $OUT/report.json, $OUT/report-maria.html, $OUT/report-maria.json"
else
  die "$FAILURES ground-truth assertion(s) failed (see above; reports in $OUT)"
fi
