#!/usr/bin/env bash
# Deterministic seeded workload for the sql-replay real-data verification
# rig (see verify/run.sh and verify/README.md).
#
# Generates one SQL file per client session from a seeded Lehmer LCG (fully
# reproducible for a given WORKLOAD_SEED), then plays every session file
# concurrently against the capture-side MySQL container as the dedicated
# `verify` user (one mysql client process = one connection = one slow-log
# thread id = one replay session).
#
# The four query classes (their fingerprints are the rig's ground truth —
# keep the SQL text in sync with the FP_* constants in verify/run.sh):
#   pk    control  : PK point lookup on employees
#   hire  planted  : secondary-index lookup on employees(hire_date); the rig
#                    drops idx_hire_date on the candidate server only
#   gb    planted  : join + GROUP BY big enough to need an internal temp
#                    table (> 2 MiB); the rig strangles temptable_max_ram on
#                    the candidate server so it spills to disk
#   ins   control  : short INSERT stream into an audit-style table
#
# Usage: workload.sh gen|run|all   (env-driven; see the variables below)
set -euo pipefail

OUT_DIR=${WORKLOAD_OUT:?set WORKLOAD_OUT to the output directory}
SEED=${WORKLOAD_SEED:-42}
SESSIONS=${WORKLOAD_SESSIONS:-12}
# Executions per session per class (x SESSIONS = per-fingerprint sample
# size; keep every class >= ~200 total for stable p95s).
PK_PER_SESSION=${WORKLOAD_PK:-40}
HIRE_PER_SESSION=${WORKLOAD_HIRE:-30}
GB_PER_SESSION=${WORKLOAD_GB:-18}
INS_PER_SESSION=${WORKLOAD_INS:-30}
# Only needed for `run`:
CONTAINER=${WORKLOAD_CONTAINER:-}
MYSQL_USER=${WORKLOAD_MYSQL_USER:-verify}
MYSQL_PASSWORD=${WORKLOAD_MYSQL_PASSWORD:-verify}

# --- deterministic PRNG: Lehmer/Park-Miller MINSTD. The 48271 multiplier
# keeps every product below 2^47, so plain 64-bit bash arithmetic is exact
# and the stream is identical on any bash. `rnd N` leaves 0..N-1 in $R —
# NOT a command substitution, which would run in a subshell and lose the
# state advance.
RSTATE=$(((SEED % 2147483646) + 1))
R=0
rnd() { # rnd N -> R in 0..N-1
  RSTATE=$(((RSTATE * 48271) % 2147483647))
  R=$((RSTATE % $1))
}

# --- query generators (one statement per line; params from the PRNG)
gen_pk() {
  rnd 489999
  echo "SELECT emp_no, first_name, last_name, gender FROM employees WHERE emp_no = $((10001 + R));"
}

gen_hire() {
  # employees.hire_date spans 1985..2000; day capped at 28 so every date is
  # valid without calendar math.
  local y m d
  rnd 15
  y=$((1985 + R))
  rnd 12
  m=$((1 + R))
  rnd 28
  d=$((1 + R))
  printf 'SELECT COUNT(*), MIN(emp_no), MAX(emp_no) FROM employees WHERE hire_date = '\''%04d-%02d-%02d'\'';\n' "$y" "$m" "$d"
}

gen_gb() {
  # emp_no 200000..499999 is a dense block; a 60000-wide slice joins to
  # ~400k salary rows and produces ~35-40k (first_name, last_name) groups —
  # a several-MiB internal temp table, comfortably above the 2 MiB
  # temptable_max_ram planted on the candidate yet far below the 16 MiB
  # MEMORY-engine ceiling on the 5.7 baseline.
  local a
  rnd 230001
  a=$((200000 + R))
  echo "SELECT e.first_name, e.last_name, COUNT(*) AS cnt, AVG(s.salary) AS avg_sal FROM employees e JOIN salaries s ON s.emp_no = e.emp_no WHERE e.emp_no BETWEEN ${a} AND $((a + 59999)) GROUP BY e.first_name, e.last_name ORDER BY avg_sal DESC LIMIT 10;"
}

gen_ins() {
  local actions=(login logout view update) actor act note
  rnd 100
  actor=$R
  rnd 4
  act=${actions[$R]}
  rnd 100000
  note=$R
  echo "INSERT INTO verify_audit (actor, action, note) VALUES ('actor-${actor}', '${act}', 'seed-${SEED}-note-${note}');"
}

generate() {
  mkdir -p "$OUT_DIR/sessions"
  local s i j t
  for ((s = 1; s <= SESSIONS; s++)); do
    # Build the class mix, then Fisher-Yates shuffle it so classes
    # interleave within the session (still fully seeded).
    local mix=()
    for ((i = 0; i < PK_PER_SESSION; i++)); do mix+=(pk); done
    for ((i = 0; i < HIRE_PER_SESSION; i++)); do mix+=(hire); done
    for ((i = 0; i < GB_PER_SESSION; i++)); do mix+=(gb); done
    for ((i = 0; i < INS_PER_SESSION; i++)); do mix+=(ins); done
    for ((i = ${#mix[@]} - 1; i > 0; i--)); do
      rnd $((i + 1))
      j=$R
      t=${mix[i]}
      mix[i]=${mix[j]}
      mix[j]=$t
    done
    local file
    file=$(printf '%s/sessions/session-%02d.sql' "$OUT_DIR" "$s")
    {
      for c in "${mix[@]}"; do "gen_$c"; done
    } >"$file"
  done
  echo "generated $SESSIONS session files under $OUT_DIR/sessions (seed $SEED," \
    "$((SESSIONS * (PK_PER_SESSION + HIRE_PER_SESSION + GB_PER_SESSION + INS_PER_SESSION))) statements total)"
}

run() {
  [[ -n "$CONTAINER" ]] || {
    echo "workload.sh run: set WORKLOAD_CONTAINER" >&2
    exit 1
  }
  local pids=() files=() s file
  for ((s = 1; s <= SESSIONS; s++)); do
    file=$(printf '%s/sessions/session-%02d.sql' "$OUT_DIR" "$s")
    [[ -s "$file" ]] || {
      echo "workload.sh run: missing or empty $file (run gen first)" >&2
      exit 1
    }
    docker exec -i -e MYSQL_PWD="$MYSQL_PASSWORD" "$CONTAINER" \
      mysql -u"$MYSQL_USER" --batch employees <"$file" >"$file.out" 2>&1 &
    pids+=($!)
    files+=("$file")
  done
  local rc=0 k
  for k in "${!pids[@]}"; do
    if ! wait "${pids[k]}"; then
      echo "workload session ${files[k]} FAILED:" >&2
      cat "${files[k]}.out" >&2
      rc=1
    fi
  done
  [[ $rc -eq 0 ]] || exit $rc
  echo "workload complete: $SESSIONS concurrent sessions finished cleanly"
}

case "${1:-all}" in
gen) generate ;;
run) run ;;
all)
  generate
  run
  ;;
*)
  echo "usage: workload.sh gen|run|all" >&2
  exit 1
  ;;
esac
