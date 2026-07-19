# Configuring a MySQL 8.0 candidate for 1:1 parity with stock MySQL 5.7

You are gating a real 5.7.4x → 8.0.4x migration with
`sql-replay compare`, and you want the comparison to measure **the
engine**, not five years of drifted defaults. Stock 8.0 differs from
stock 5.7 in dozens of behavior-relevant defaults — charset, binlog,
temp-table engine, flushing policy, auth plugin — and every one of them
shows up in your latency deltas as a phantom "regression" (or masks a
real one). This document classifies **every** global-variable difference
between the two versions and delivers a ready-to-use `my.cnf` fragment
that pins the 8.0 candidate back to stock-5.7 behavior everywhere that
is physically possible, plus an honest list of what cannot be pinned.

Like [the quickstart](quickstart.md), this is an *executed* document:
every command below was really run (2026-07-19, `mysql:5.7` = 5.7.44 and
`mysql:8.0` = 8.0.46 official Docker images, sql-replay 0.4.0), and
every output is the verbatim product of those runs — a few long ones are
trimmed and marked. If your production 5.7 is not stock, the *method*
transfers: diff your server's variables instead and substitute its
values into the fragment.

Why the headline pins matter is already measured elsewhere in this repo
— this document doesn't repeat the numbers:

- charset drift (utf8mb4 vs latin1) made a join+GROUP BY class **+465%**
  on an unpinned 8.0 in the
  [general-workload benchmark](benchmarks/2026-07-16-mysql80-general.md)
  (summarized in the
  [README benchmarks table](../README.md#benchmarks-where-a-57-workload-regresses-on-80-vs-mariadb-1011));
- temp-table engine/spill drift is why the verification rig pins
  `tmp_table_size`/`max_heap_table_size` on every container — see
  ["Why the server config is pinned"](../verify/README.md#why-the-server-config-is-pinned-on-every-container).

## 1. Two stock servers, side by side

Deliberately **no** configuration flags — the whole point is to see what
the defaults do:

```console
$ docker run -d --name parity-57 -p 127.0.0.1:23310:3306 \
    -e MYSQL_ALLOW_EMPTY_PASSWORD=yes mysql:5.7
$ docker run -d --name parity-80-stock -p 127.0.0.1:23311:3306 \
    -e MYSQL_ALLOW_EMPTY_PASSWORD=yes mysql:8.0
$ until docker exec parity-57 mysqladmin ping -h127.0.0.1 --silent 2>/dev/null; do sleep 2; done
mysqld is alive
$ until docker exec parity-80-stock mysqladmin ping -h127.0.0.1 --silent 2>/dev/null; do sleep 2; done
mysqld is alive
$ docker exec parity-57 mysql -uroot -N -e "SELECT VERSION();"
5.7.44
$ docker exec parity-80-stock mysql -uroot -N -e "SELECT VERSION();"
8.0.46
```

## 2. The full variables diff

Dump `SHOW GLOBAL VARIABLES` from both and split the diff three ways:
variables present on both sides with different values, variables 5.7 has
that 8.0 removed, and variables new in 8.0:

```console
$ docker exec parity-57 mysql -uroot -N -B -e "SHOW GLOBAL VARIABLES" > vars-57.tsv
$ docker exec parity-80-stock mysql -uroot -N -B -e "SHOW GLOBAL VARIABLES" > vars-80.tsv
$ wc -l vars-57.tsv vars-80.tsv
  505 vars-57.tsv
  631 vars-80.tsv
 1136 total
$ join -t$'\t' <(sort vars-57.tsv) <(sort vars-80.tsv) -o 1.1,1.2,2.2 \
    | awk -F'\t' '$2 != $3' > diff-common.tsv
$ comm -23 <(cut -f1 vars-57.tsv | sort) <(cut -f1 vars-80.tsv | sort) > only-57.txt
$ comm -13 <(cut -f1 vars-57.tsv | sort) <(cut -f1 vars-80.tsv | sort) > only-80.txt
$ wc -l diff-common.tsv only-57.txt only-80.txt
  68 diff-common.tsv
  38 only-57.txt
 164 only-80.txt
 270 total
```

So a "same version, different major" pair really disagrees on **68
shared defaults**, has lost 38 variables and gained 164. Sections 3–6
classify all of them; the classes are:

- **Pin it** — changes measured behavior, and 8.0 still has the knob:
  goes into the `my.cnf` fragment (§7).
- **Cannot pin** — behavior removed or restructured with no 8.0
  equivalent: honest measurement caveats (§4).
- **Engine-intrinsic** — new engine features you *should not* pin away,
  because they are the thing under test (§5).
- **Replication-inert / noise** — knobs that only matter on a
  replicating server, plus version strings, paths, and instrumentation
  sizing with no query-path effect (§6).

## 3. Pin it — drifted defaults 8.0 can still be set back to

Every row below is in the fragment in §7 (values are the stock 5.7.44
defaults from `vars-57.tsv`).

| variable | 5.7 | stock 8.0 | why it moves measurements |
|---|---|---|---|
| `character_set_server` | `latin1` | `utf8mb4` | tables created without an explicit charset inherit it; utf8mb4 keys are 4x wider — the biggest single confounder ([measured](../README.md#benchmarks-where-a-57-workload-regresses-on-80-vs-mariadb-1011)) |
| `collation_server` | `latin1_swedish_ci` | `utf8mb4_0900_ai_ci` | comparison/sort rules follow the charset |
| `log_bin` | `OFF` | `ON` | 8.0 binlogs every write by default (plus a `sync_binlog=1` fsync); a per-write cost the 5.7 baseline never paid |
| `internal_tmp_mem_storage_engine` (new in 8.0) | — (5.7 used MEMORY) | `TempTable` | in-memory temp-table engine for GROUP BY/derived tables; different allocation and spill behavior. `tmp_table_size`/`max_heap_table_size` are 16M on both, but the engine differs — `MEMORY` restores 5.7 semantics ([why this matters](../verify/README.md#why-the-server-config-is-pinned-on-every-container)) |
| `innodb_redo_log_capacity` (new in 8.0) | — (48M × 2 files = 96M) | `104857600` (100M) | replaces `innodb_log_file_size` × `innodb_log_files_in_group`; pin to 100663296 = 5.7's exact 96M total |
| `innodb_flush_neighbors` | `1` | `0` | 5.7 flushed adjacent pages (HDD assumption); 8.0 doesn't (SSD assumption) — changes write I/O patterns |
| `innodb_max_dirty_pages_pct` | `75` | `90` | how much dirty data may accumulate before aggressive flushing |
| `innodb_max_dirty_pages_pct_lwm` | `0` | `10` | when pre-flushing starts |
| `innodb_undo_log_truncate` | `OFF` | `ON` | background undo truncation runs on stock 8.0 only |
| `innodb_autoinc_lock_mode` | `1` | `2` | consecutive vs interleaved auto-inc allocation — insert-path locking behavior |
| `default_authentication_plugin` | `mysql_native_password` | `caching_sha2_password` | changes the connection handshake (extra round trip / RSA on first contact); replay opens one connection per captured session, so per-connection cost counts |
| `explicit_defaults_for_timestamp` | `OFF` | `ON` | TIMESTAMP NULL/DEFAULT column semantics — a correctness difference, not just latency |
| `local_infile` | `ON` | `OFF` | `LOAD DATA LOCAL` allowed vs refused |
| `information_schema_stats_expiry` (new in 8.0) | — (always fresh) | `86400` | 8.0 serves I_S table statistics from a 24 h cache; `0` restores 5.7's always-fresh reads |
| `event_scheduler` | `OFF` | `ON` | scheduler background thread running vs not |
| `mysqlx` (new in 8.0) | — (plugin not loaded) | `ON` | 8.0 ships the X Plugin listening on port 33060 (29 `mysqlx_*` variables); 5.7 doesn't load it |
| `max_allowed_packet` | `4194304` | `67108864` | largest statement/row accepted — an oversized INSERT errors on one side only |
| `max_length_for_sort_data` | `1024` | `4096` | filesort payload strategy threshold |
| `max_error_count` | `64` | `1024` | per-statement warning retention |
| `back_log` | `80` | `151` | pending-connection queue depth |
| `table_open_cache` | `2000` | `4000` | table cache capacity |
| `table_definition_cache` | `1400` | `2000` | definition cache capacity |
| `innodb_open_files` | `2000` | `4000` | InnoDB file-handle cap |

Pinning `character_set_server`/`collation_server` also collapses the six
derived diffs (`character_set_client`/`_connection`/`_database`/
`_results`, `collation_connection`/`_database`), and `skip-log-bin`
collapses `log_bin_basename`/`log_bin_index`/`log_slave_updates` — all
verified in the §8 re-diff.

Two pins deserve an explicit caveat:

- **`skip-log-bin` matches stock 5.7**, which is what this document
  targets. If your production 5.7 runs with the binlog *enabled*, match
  that instead: leave the binlog on on both sides and carry over
  `sync_binlog`, `binlog_format`, and the retention setting
  (5.7 `expire_logs_days` → 8.0 `binlog_expire_logs_seconds`).
- **`max_allowed_packet = 4M`** is the stock value. If production raised
  it, use production's value — replayed statements are as long as
  production's were, and the [quickstart's production
  notes](quickstart.md#10-taking-this-to-a-real-migration) already warn
  about the failure mode.

## 4. Cannot pin — honest measurement caveats

These differences ride along in every 5.7 → 8.0 comparison no matter
what you configure. Know them before attributing a delta to "the
engine".

**The query cache is gone.** 8.0 removed it entirely — `have_query_cache`
is the only trace left, and the five `query_cache_*` variables are among
the 38 removed (this section's transcripts run against
`parity-80-pinned`, the pinned container stood up in §8 — execution
order differs from presentation order here):

```console
$ docker exec parity-80-pinned mysql -uroot -e "SHOW GLOBAL VARIABLES LIKE 'query_cache%';"
$ docker exec parity-57 mysql -uroot -B -e "SHOW GLOBAL VARIABLES LIKE 'query_cache_type';"
Variable_name	Value
query_cache_type	OFF
```

(No rows at all on 8.0.) The important nuance: **stock 5.7 ships with
the query cache OFF** (`query_cache_type=OFF`, as shown), so for a
stock-vs-stock comparison its removal is a non-event. But if your
production 5.7 has `query_cache_type=1`, part of your read traffic is
served from a cache that has no 8.0 equivalent whatsoever — replay the
5.7 baseline with the cache off (`query_cache_type=0`) or accept that
cache-hit classes will read as regressions.

**`sql_mode` cannot be made byte-identical.** 8.0 removed
`NO_AUTO_CREATE_USER` (user creation via bare `GRANT` is simply gone as
a behavior) and rejects the flag outright:

```console
$ docker exec parity-80-pinned mysql -uroot -e "SET GLOBAL sql_mode='ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION';"
ERROR 1231 (42000) at line 1: Variable 'sql_mode' can't be set to the value of 'NO_AUTO_CREATE_USER'
```

The remaining six default flags are identical on both sides, so this
diff is expected residue in every stock 5.7 → 8.0 `compare` (the
[quickstart's troubleshooting box](quickstart.md#11-troubleshooting-first-run-gotchas)
says the same) — you'll see it survive in §9.

**The rest of the cannot-pin list:**

- **New data dictionary, atomic DDL, no `.frm` files** (`sync_frm` is
  among the removed variables). DDL latency and crash semantics differ
  by construction; `information_schema` is now views over the dictionary
  with its own latency profile. If your capture contains DDL or heavy
  I_S traffic, those classes compare across different machinery.
- **`innodb_undo_tablespaces`: 0 → 2.** 5.7 kept undo logs in the system
  tablespace; 8.0 requires at least two dedicated undo tablespaces — the
  storage layout cannot be reverted (the settable-but-ON-by-default
  truncation behavior *is* pinned in §3).
- **`utf8` naming and collations.** `character_set_system` reads
  `utf8` vs `utf8mb3` — same encoding, new honest name (display-only
  here, since the system charset isn't configurable). The 0900 collation
  family (`utf8mb4_0900_ai_ci` etc.) exists only on 8.0; irrelevant once
  the server charset is pinned to latin1, but a real constraint if your
  schema pins per-table utf8mb4 collations.
- **`thread_stack`: 262144 → 1048576.** Technically settable, but 8.0
  genuinely needs deeper thread stacks; lowering it invites stack
  overruns for zero measurement value. Left unpinned on purpose (it is
  per-thread memory, not query behavior).
- **`tls_version`: TLSv1/TLSv1.1 were removed** in 8.0.28+. Only matters
  for TLS clients (sql-replay's M1..M4 replay path doesn't use TLS).
- **Removed no-ops and legacy toggles** (the rest of the 38): the
  `query_cache_*` five and `sync_frm` above, plus `date_format`,
  `datetime_format`, `time_format`, `have_crypt`,
  `ignore_builtin_innodb`, `ignore_db_dirs`, `innodb_checksums`
  (superseded by `innodb_checksum_algorithm`, `crc32` on both sides),
  `innodb_file_format`/`_check`/`_max` and `innodb_large_prefix`
  (Barracuda is the only format now), `innodb_locks_unsafe_for_binlog`,
  `innodb_numa_interleave`, `innodb_stats_sample_pages` (deprecated
  alias), `innodb_support_xa` (always ON, matching 5.7's default),
  `innodb_undo_logs` (rollback segments now fixed),
  `internal_tmp_disk_storage_engine` (on-disk temp tables are always
  InnoDB in 8.0; 5.7's default was InnoDB too),
  `log_builtin_as_identified_by_password`, the four `log_syslog*`
  variables (superseded by `log_error_services`), `log_warnings`
  (superseded by `log_error_verbosity`), `max_tmp_tables`,
  `metadata_locks_cache_size`/`_hash_instances`, `multi_range_count`,
  `old_passwords`, `secure_auth`, `show_compatibility_56` — all either
  never had an effect or their 8.0 fixed behavior equals the 5.7
  default. Two are pure renames `compare` already canonicalizes:
  `tx_isolation` → `transaction_isolation` (both `REPEATABLE-READ`) and
  `tx_read_only` → `transaction_read_only`.
- **XA semantics:** new-in-8.0 `xa_detach_on_prepare` defaults ON
  (prepared XA transactions detach from the session); only XA workloads
  notice.

## 5. Engine-intrinsic — do NOT pin these away

The point of the gate is to measure MySQL 8.0 as you would actually run
it. Some diffs *are* the new engine, and "pinning" them would mean
benchmarking a deliberately crippled 8.0:

- **`optimizer_switch`.** Every flag 5.7 has, 8.0 has with the same
  value; the diff is purely 8.0's new flags
  (`use_invisible_indexes=off`, `skip_scan=on`, `hash_join=on`,
  `subquery_to_derived=off`, `hypergraph_optimizer=off`,
  `derived_condition_pushdown=on`). New access methods are the engine
  under test — leave them. When `compare` flags a class and you suspect
  a plan change, bisect per-session
  (`SET optimizer_switch='skip_scan=off'; EXPLAIN ...`) rather than
  globally. (Note MySQL's documented gotcha: from 8.0.20 the `hash_join`
  flag is a no-op — hash join usage is governed by the
  `block_nested_loop` flag.)
- **`innodb_parallel_read_threads` (new, 4)** — parallel clustered-index
  scans; **`innodb_log_writer_threads` (new, ON)** — the rewritten redo
  pipeline; the doublewrite layout (`innodb_doublewrite_files`/`_pages`,
  same `ON` semantics). All engine architecture, not config drift.

If a regression traces to one of these, that's a *finding about 8.0*,
and per-class bisection (not a global pin) is how to attribute it.

## 6. Replication-inert and noise

**Replication-inert** — differ on paper, do nothing on a replay target
that isn't replicating: `gtid_executed_compression_period`,
`master_info_repository`/`relay_log_info_repository` (FILE → TABLE; 8.0
manages replication metadata transactionally), `server_id`,
`slave_allow_batching`, `slave_parallel_type`, `slave_parallel_workers`,
`slave_pending_jobs_size_max`, `slave_preserve_commit_order`,
`slave_rows_search_algorithms`, `transaction_write_set_extraction`. If
your candidate *will* replicate in production, benchmark that topology
deliberately — as its own experiment, not as silent drift. The same
applies to 8.0's new `replica_*`/`source_*` variables (25 of the 164 —
terminology aliases of the `slave_*`/`master_*` set) and the new
`binlog_*` knobs (9 — inert under `skip-log-bin`).

**Noise** — no query-path effect, safely ignored: version strings
(`version`, `version_comment`, `innodb_version`), instance identity and
paths (`hostname`, `server_uuid`, `general_log_file`,
`slow_query_log_file`, `relay_log*`, `character_sets_dir`,
`lc_messages_dir`), `innodb_flush_method` (`''` vs `fsync` — the same
default, 8.0 just spells it out), `character_set_system`
(`utf8`→`utf8mb3` rename, §4), the seven `performance_schema_max_*`
instrumentation-sizing values, `log_error_verbosity` (error-log wording
only; pin it too if you want identical logs), and
`optimizer_trace_max_mem_size` (only read when tracing is on). Among
the new-in-8.0 set: the `admin_*` interface (11, not enabled),
`caching_sha2_password_*` (4, inert once the default auth plugin is
pinned), and the new opt-in features that default to
5.7-compatible behavior (`partial_revokes`, `password_history`,
`sql_require_primary_key`, `sql_generate_invisible_primary_key`,
`default_table_encryption`, `mandatory_roles`, connection-memory
tracking, histogram and regexp limits, `select_into_*`,
`cte_max_recursion_depth`, `explain_format`,
`terminology_use_previous`, …).

## 7. The deliverable: `parity-57.cnf`

Everything from §3 in one `[mysqld]` fragment. Drop it into
`/etc/mysql/conf.d/` (or merge into `my.cnf`) on the 8.0 candidate:

```ini
# parity-5.7-to-8.0.cnf — pin a stock MySQL 8.0 candidate to stock MySQL
# 5.7 (5.7.44) behavior wherever 8.0 still has the knob, so a
# `sql-replay compare` between the two measures the engine, not drifted
# defaults. Every value below is the stock 5.7.44 default (or the closest
# 8.0 equivalent of 5.7's behavior, where marked). If your production 5.7
# is not stock, substitute its values — the method is what matters.

[mysqld]

# --- character set / collation: the single biggest silent drift.
# Tables created without an explicit charset inherit these; utf8mb4 keys
# are 4x wider than latin1 and measurably regress GROUP BY / sorts.
character_set_server            = latin1
collation_server                = latin1_swedish_ci

# --- binary log: ON by default in 8.0, OFF in 5.7. A real per-write
# cost (binlog write + sync_binlog=1 fsync) the baseline never paid.
skip-log-bin

# --- in-memory temp-table engine: 8.0 defaults to TempTable, 5.7 used
# MEMORY. tmp_table_size/max_heap_table_size are 16M on both by default,
# but TempTable allocates/spills differently. MEMORY restores 5.7's
# engine and its spill thresholds. (If your 5.7 raised tmp_table_size /
# max_heap_table_size, carry those values over here too.)
internal_tmp_mem_storage_engine = MEMORY

# --- redo log capacity: 5.7 = innodb_log_file_size(48M) x
# innodb_log_files_in_group(2) = 96M; 8.0's replacement variable
# defaults to 100M. Pin to exactly 96M.
innodb_redo_log_capacity        = 100663296

# --- InnoDB flushing/background behavior: 8.0 retuned for SSDs.
innodb_flush_neighbors          = 1     # 8.0: 0 (SSD assumption)
innodb_max_dirty_pages_pct      = 75    # 8.0: 90
innodb_max_dirty_pages_pct_lwm  = 0     # 8.0: 10
innodb_undo_log_truncate        = OFF   # 8.0: ON (background truncation)

# --- insert-path locking: 8.0 defaults to interleaved (2) because
# row-format binlog made it safe; 5.7 used consecutive (1).
innodb_autoinc_lock_mode        = 1

# --- authentication: caching_sha2_password changes the connection
# handshake (extra round trips / RSA on first contact). Per-connection
# cost counts when replay opens one connection per captured session.
default_authentication_plugin   = mysql_native_password

# --- semantics changes (correctness, not latency):
explicit_defaults_for_timestamp = OFF   # 8.0: ON — TIMESTAMP NULL/DEFAULT DDL semantics
local_infile                    = ON    # 8.0: OFF — LOAD DATA LOCAL refused vs allowed
information_schema_stats_expiry = 0     # 8.0: 86400 — I_S table stats served from a
                                        # 24h cache; 0 = always fresh, like 5.7

# --- background/servicing parity:
event_scheduler                 = OFF   # 8.0: ON — scheduler thread running vs not
mysqlx                          = OFF   # 8.0 ships the X Plugin listening on 33060;
                                        # 5.7 does not load it by default

# --- statement/session limits and caches (5.7 stock sizes):
max_allowed_packet              = 4194304   # 8.0: 64M — biggest statement accepted
max_length_for_sort_data        = 1024      # 8.0: 4096 — filesort payload strategy
max_error_count                 = 64        # 8.0: 1024 — per-stmt warning retention
back_log                        = 80        # 8.0: 151 — pending-connect queue
table_open_cache                = 2000      # 8.0: 4000
table_definition_cache          = 1400      # 8.0: 2000
innodb_open_files               = 2000      # 8.0: 4000
```

## 8. Verify the pins took

A third container, stock 8.0 image plus only the fragment:

```console
$ docker run -d --name parity-80-pinned -p 127.0.0.1:23312:3306 \
    -e MYSQL_ALLOW_EMPTY_PASSWORD=yes \
    -v $PWD/parity-57.cnf:/etc/mysql/conf.d/parity.cnf:ro mysql:8.0
$ until docker exec parity-80-pinned mysqladmin ping -h127.0.0.1 --silent 2>/dev/null; do sleep 2; done
mysqld is alive
$ docker exec parity-80-pinned mysql -uroot -N -B -e "SHOW GLOBAL VARIABLES WHERE Variable_name IN
    ('character_set_server','collation_server','log_bin','internal_tmp_mem_storage_engine',
     'innodb_redo_log_capacity','default_authentication_plugin','max_allowed_packet')"
character_set_server	latin1
collation_server	latin1_swedish_ci
default_authentication_plugin	mysql_native_password
innodb_redo_log_capacity	100663296
internal_tmp_mem_storage_engine	MEMORY
log_bin	OFF
max_allowed_packet	4194304
```

Re-running the §2 diff against the pinned server shrinks it from **68
differing shared variables to 40**, and from 164 new variables to 135
(`mysqlx=OFF` removes all 29 `mysqlx_*`):

```console
$ docker exec parity-80-pinned mysql -uroot -N -B -e "SHOW GLOBAL VARIABLES" > vars-80-pinned.tsv
$ join -t$'\t' <(sort vars-57.tsv) <(sort vars-80-pinned.tsv) -o 1.1,1.2,2.2 \
    | awk -F'\t' '$2 != $3' | wc -l
40
$ comm -13 <(cut -f1 vars-57.tsv | sort) <(cut -f1 vars-80-pinned.tsv | sort) | wc -l
135
```

Every one of the 40 survivors is accounted for above: `sql_mode` and the
rest of §4's cannot-pin list, §5's engine-intrinsic diffs
(`optimizer_switch`), and §6's replication-inert/noise sets. Nothing
behavior-relevant and pinnable is left.

The mechanism the charset pin exists for, made visible — the same
`CREATE TABLE` (no explicit charset, the
[quickstart's seed](quickstart.md#2-stand-up-a-toy-production-mysql-57))
run on all three servers (the `shop` schema was seeded on each of them
for §9's workload):

```console
$ for c in parity-57 parity-80-stock parity-80-pinned; do
    docker exec $c mysql -uroot -N -e "SHOW CREATE TABLE shop.orders\G" | tail -1
  done
) ENGINE=InnoDB AUTO_INCREMENT=100001 DEFAULT CHARSET=latin1
) ENGINE=InnoDB AUTO_INCREMENT=100001 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci
) ENGINE=InnoDB AUTO_INCREMENT=100001 DEFAULT CHARSET=latin1
```

Stock 8.0 silently gave the "same" migration utf8mb4 tables; pinned 8.0
reproduced 5.7's latin1 exactly.

## 9. Prove it with the tool: `compare` before vs after

The point of all of the above, seen through sql-replay itself. Seed all
three servers with the quickstart's deterministic `shop` schema, then run
a reads-only variant of the quickstart's three-session workload on 5.7
with the slow log on — session 1 issues only its point lookups, with the
10 INSERTs omitted — capture, and replay the same capture against each
server. The schema and slow-log mechanics are the quickstart's
([quickstart](quickstart.md), §§2–5); omitting the INSERTs is why this
capture shows 94 events / 4 fingerprints / 1 admin command ignored where
the quickstart's shows 104 / 5 / 3:

```console
$ sql-replay capture --input parity-slow.log --out capture.jsonl.zst
captured 94 events / 4 sessions / 4 fingerprints (dialect: mysql-5.7, admin commands ignored: 1) in 0.00s -> capture.jsonl.zst
$ sql-replay replay --capture capture.jsonl.zst --url mysql://root@127.0.0.1:23310/ \
    --filter-user app --out run-5.7.json
$ sql-replay replay --capture capture.jsonl.zst --url mysql://root@127.0.0.1:23311/ \
    --filter-user app --out run-8.0-stock.json
$ sql-replay replay --capture capture.jsonl.zst --url mysql://root@127.0.0.1:23312/ \
    --filter-user app --out run-8.0-pinned.json
```

**Before** — 5.7 baseline vs *stock* 8.0. `compare`'s settings snapshot
catches the drift it tracks and warns before showing a single latency
number:

```console
$ sql-replay compare --baseline run-5.7.json --candidate run-8.0-stock.json \
    --threshold-pct 50 --min-count 10
Comparing runs:
   baseline: run-5.7.json — target 5.7.44 (mysql://root@127.0.0.1:23310/)
  candidate: run-8.0-stock.json — target 8.0.46 (mysql://root@127.0.0.1:23311/)

!!! COMPARABILITY WARNINGS — the runs may not be directly comparable !!!
  - target server settings differ: character_set_server, collation_server, sql_mode (see settings diff)

Target settings diff (baseline -> candidate):
  character_set_server: latin1 -> utf8mb4
  collation_server: latin1_swedish_ci -> utf8mb4_0900_ai_ci
  sql_mode: ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION -> ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION
...
```

**After** — the same baseline vs *pinned* 8.0. The drift is gone; the
only surviving diff is §4's un-pinnable `sql_mode` residue, now carrying
real information ("these really are different major versions") instead
of config noise:

```console
$ sql-replay compare --baseline run-5.7.json --candidate run-8.0-pinned.json \
    --threshold-pct 50 --min-count 10
Comparing runs:
   baseline: run-5.7.json — target 5.7.44 (mysql://root@127.0.0.1:23310/)
  candidate: run-8.0-pinned.json — target 8.0.46 (mysql://root@127.0.0.1:23312/)

!!! COMPARABILITY WARNINGS — the runs may not be directly comparable !!!
  - target server settings differ: sql_mode (see settings diff)

Target settings diff (baseline -> candidate):
  sql_mode: ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION -> ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION
...
```

(Both transcripts are trimmed after the settings diff, which is the
section under test here: this toy workload's classes are all
sub-millisecond-to-10ms and its latency verdicts are the scheduler-noise
lesson the [quickstart's §6](quickstart.md#6-compare-the-runs) already
teaches — on both candidates the gate behaved identically, flagging the
same single sub-ms class at the same generous threshold.)

One scope note: `compare`'s settings snapshot deliberately records only
the highest-signal variables (`sql_mode`, charset/collation, buffer pool
size, transaction isolation — canonicalized across the
`tx_isolation`/`transaction_isolation` rename). It is a safety net, not
a full config audit; the §2 diff *is* the full audit, and this
document's fragment is how the other 60-odd drifted defaults get pinned
before the snapshot ever sees them.

## 10. Clean up

```console
$ docker rm -f parity-57 parity-80-stock parity-80-pinned
```

If a future MySQL 8.0.x image or sql-replay release changes any output
shown here, re-execute this document against it rather than hand-editing
— same law as the quickstart.
