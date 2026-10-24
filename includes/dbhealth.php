<?php
/**
 * includes/dbhealth.php - GENERAL MySQL/MariaDB slowness & health diagnostic.
 *
 * Portable across ANY WHM/cPanel server: it reads the LOCAL MySQL/MariaDB as root
 * (--defaults-extra-file=/root/.my.cnf), gathers SHOW GLOBAL STATUS / VARIABLES,
 * information_schema.PROCESSLIST and InnoDB counters, and derives uptime-normalized,
 * server-agnostic findings - temp-tables spilling to disk, unindexed full joins,
 * slow-query-log visibility, connection saturation, InnoDB buffer-pool efficiency,
 * table-cache overflow, lock waits, and the queries that are slow RIGHT NOW.
 *
 * Nothing here is tied to one server or one workload: every threshold is a ratio or a
 * per-time rate, computed from that server's own counters and hardware. The gather is
 * strictly READ-ONLY and every query is `timeout`-bounded so it stays fast even on a
 * heavily-loaded box. The ONLY writes are explicit, POST+CSRF+root-gated, reversible
 * dynamic tunables (SET GLOBAL) and a guarded "kill this stuck query".
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

/* ---------------- root MySQL access (self-contained; own prefix to avoid clashes) ---------------- */
function smpro_dbh_cli() {
    foreach (['/usr/bin/mariadb', '/usr/bin/mysql', '/usr/local/bin/mysql'] as $b) { if (@is_executable($b)) return $b; }
    $w = trim((string)@shell_exec('command -v mariadb 2>/dev/null; command -v mysql 2>/dev/null'));
    if ($w !== '') { $w = strtok($w, "\n"); return $w; }
    return 'mysql';
}
function smpro_dbh_defaults() { return is_readable('/root/.my.cnf') ? ' --defaults-extra-file=/root/.my.cnf' : ''; }
/** Run a read-only statement as root; return raw TSV stdout (errors suppressed, time-bounded). */
function smpro_dbh_q($sql, $t = 15) {
    return (string)@shell_exec('timeout ' . (int)$t . ' ' . smpro_dbh_cmd($sql) . ' 2>/dev/null');
}
/** The bare client command for a read-only statement (what smpro_dbh_q runs; also what a memo refresher re-runs). */
function smpro_dbh_cmd($sql) {
    return smpro_dbh_cli() . smpro_dbh_defaults() . ' --connect-timeout=5 -N --batch -e ' . escapeshellarg($sql);
}
/** Run SQL and return the server's ERROR text (STDERR) if it rejected the statement; '' on success.
 *  Used for writes (SET GLOBAL ...) so the real rejection reason is surfaced instead of a generic failure. */
function smpro_dbh_q_err($sql, $t = 15) {
    $err = (string)@shell_exec('timeout ' . (int)$t . ' ' . smpro_dbh_cli() . smpro_dbh_defaults()
        . ' --connect-timeout=5 -N --batch -e ' . escapeshellarg($sql) . ' 2>&1 1>/dev/null');   // capture STDERR, drop STDOUT
    return trim($err);
}
/** key\tvalue rows -> assoc array. */
function smpro_dbh_kv($sql, $t = 12) {
    $out = [];
    foreach (explode("\n", smpro_dbh_q($sql, $t)) as $l) {
        if ($l === '') continue; $p = explode("\t", $l, 2);
        if (count($p) === 2) $out[$p[0]] = $p[1];
    }
    return $out;
}
/** Is a local MySQL/MariaDB present AND answering as root? Distinguishes the two failure modes. */
function smpro_dbh_state() {
    static $st = null; if ($st !== null) return $st;
    $running = trim((string)@shell_exec('pgrep -x mysqld 2>/dev/null; pgrep -x mariadbd 2>/dev/null; pgrep -x mysqld_safe 2>/dev/null')) !== '';
    $ping = trim(smpro_dbh_q('SELECT 1', 6)) === '1';
    if ($ping)   return $st = ['ok' => true,  'reason' => ''];
    if ($running) return $st = ['ok' => false, 'reason' => 'auth', 'msg' => 'A local MySQL/MariaDB is running, but SM Pro could not authenticate as root (/root/.my.cnf missing or invalid). Fix root access and reload.'];
    return $st = ['ok' => false, 'reason' => 'absent', 'msg' => 'No local MySQL/MariaDB server was detected on this machine. This diagnostic checks the database engine running on THIS server.'];
}
function smpro_dbh_available() { $s = smpro_dbh_state(); return !empty($s['ok']); }

function smpro_dbh_status() { static $c = null; if ($c === null) $c = smpro_dbh_kv('SHOW GLOBAL STATUS'); return $c; }
function smpro_dbh_vars()   { static $c = null; if ($c === null) $c = smpro_dbh_kv('SHOW GLOBAL VARIABLES'); return $c; }

/* ---------------- small helpers ---------------- */
function smpro_dbh_n($a, $k)   { return isset($a[$k]) ? (float)$a[$k] : 0.0; }               // numeric status/var
function smpro_dbh_rate($v, $up) { return $up > 0 ? ($v / $up) : 0.0; }                       // per-second
function smpro_dbh_bytes_h($b) {
    $b = (float)$b; $u = ['B','KB','MB','GB','TB']; $i = 0;
    while ($b >= 1024 && $i < 4) { $b /= 1024; $i++; }
    return ($i === 0 ? (int)$b : round($b, $b < 10 ? 1 : 0)) . ' ' . $u[$i];
}
function smpro_dbh_dur_h($s) {
    $s = (int)$s; if ($s < 60) return $s . 's';
    $m = intdiv($s, 60); if ($m < 60) return $m . 'm ' . ($s % 60) . 's';
    $h = intdiv($m, 60); if ($h < 24) return $h . 'h ' . ($m % 60) . 'm';
    $d = intdiv($h, 24); return $d . 'd ' . ($h % 24) . 'h';
}
/** Collapse literal values so a query SHAPE can be shown without leaking row data. */
function smpro_dbh_redact_sql($q) {
    $q = trim((string)$q);
    if ($q === '' || strcasecmp($q, 'NULL') === 0) return '';
    $q = preg_replace("/'(?:[^'\\\\]|\\\\.)*'/", "'?'", $q);   // single-quoted strings → '?'
    $q = preg_replace('/"(?:[^"\\\\]|\\\\.)*"/', '"?"', $q);   // double-quoted strings → "?"
    $q = preg_replace('/\b\d{4,}\b/', '?', $q);                // long numeric literals (ids/phones) -> ?
    $q = preg_replace('/\s+/', ' ', $q);
    return function_exists('mb_substr') ? mb_substr($q, 0, 240) : substr($q, 0, 240);
}

/* ---------------- server identity ---------------- */
function smpro_dbh_server() {
    $v = smpro_dbh_vars(); $s = smpro_dbh_status();
    $ver = $v['version'] ?? trim(smpro_dbh_q('SELECT VERSION()', 6));
    $flavor = (stripos($ver, 'mariadb') !== false || stripos(($v['version_comment'] ?? ''), 'mariadb') !== false) ? 'MariaDB' : 'MySQL';
    return [
        'flavor'    => $flavor,
        'version'   => $ver,
        'uptime'    => (int)smpro_dbh_n($s, 'Uptime'),
        'datadir'   => $v['datadir'] ?? '',
        'max_conn'  => (int)smpro_dbh_n($v, 'max_connections'),
        'buffer_pool' => (int)smpro_dbh_n($v, 'innodb_buffer_pool_size'),
        'ram_bytes' => (function () { $m = (int)trim((string)@shell_exec("awk '/MemTotal/{print \$2*1024}' /proc/meminfo 2>/dev/null")); return $m; })(),
        'cores'     => function_exists('smpro_cpu_cores') ? (int)smpro_cpu_cores() : max(1, (int)trim((string)@shell_exec('nproc 2>/dev/null'))),
    ];
}

/* ---------------- live processlist (structured + redacted) ---------------- */
function smpro_dbh_processlist() {
    $sql = "SELECT ID,USER,HOST,DB,COMMAND,TIME,STATE,LEFT(INFO,400) "
         . "FROM information_schema.PROCESSLIST ORDER BY TIME DESC";
    $rows = [];
    foreach (explode("\n", smpro_dbh_q($sql, 10)) as $l) {
        if ($l === '') continue; $p = explode("\t", $l, 8);
        if (count($p) < 7) continue;
        if (stripos((string)($p[7] ?? ''), 'FROM information_schema.PROCESSLIST') !== false) continue;   // hide our own live-poll probe
        $rows[] = [
            'id'      => (int)$p[0],
            'user'    => $p[1],
            'host'    => preg_replace('/:\d+$/', '', (string)$p[2]),   // drop ephemeral source port
            'db'      => ($p[3] === 'NULL') ? '' : $p[3],
            'command' => $p[4],
            'time'    => (int)$p[5],
            'state'   => ($p[6] === 'NULL') ? '' : $p[6],
            'info'    => smpro_dbh_redact_sql($p[7] ?? ''),
        ];
    }
    return $rows;
}
/** Threads that are actually DOING work right now (not idle Sleep, not the plugin's own probe). */
function smpro_dbh_active(array $pl) {
    $act = [];
    foreach ($pl as $r) {
        if (strcasecmp($r['command'], 'Sleep') === 0) continue;
        if ($r['info'] === '' && strcasecmp($r['command'], 'Query') !== 0) continue;    // Daemon/Binlog etc. with no statement
        if (stripos($r['info'], 'information_schema.PROCESSLIST') !== false) continue;   // our own probe
        $act[] = $r;
    }
    return $act;
}

/* ---------------- the analysis: portable, uptime-normalized findings ---------------- */
function smpro_dbh_analyze() {
    $s  = smpro_dbh_status();
    $v  = smpro_dbh_vars();
    $srv = smpro_dbh_server();
    $up = max(1, $srv['uptime']);
    $cores = max(1, (int)$srv['cores']);
    $pl = smpro_dbh_processlist();
    $active = smpro_dbh_active($pl);

    $F = [];
    $add = function ($sev, $id, $title, $evidence, $detail, $rec, $fix = null) use (&$F) {
        // Written out key by key on purpose. compact() names its variables in STRINGS, and the obfuscator that
        // builds every release renames the variables without touching those strings - so compact() looked up
        // names that no longer existed and returned an empty array. Findings then rendered as blank rows: the
        // page counted five problems and described none of them. Nothing reported the mismatch, and the test
        // suite runs on the source, where it works.
        $F[] = ['sev' => $sev, 'id' => $id, 'title' => $title, 'evidence' => $evidence,
                'detail' => $detail, 'rec' => $rec, 'fix' => $fix];
    };
    $perHr = function ($v) use ($up) { return round(smpro_dbh_rate($v, $up) * 3600, 1); };

    // 0) warm-up note - some ratios need a running-in period to be meaningful.
    $warm = $up < 3600;

    // 1) TEMP TABLES SPILLING TO DISK - the classic "queries suddenly slow" signal.
    $tmp   = smpro_dbh_n($s, 'Created_tmp_tables');
    $tmpD  = smpro_dbh_n($s, 'Created_tmp_disk_tables');
    if ($tmp > 200 && $tmpD > 0) {
        $ratio = $tmpD / max(1, $tmp);
        $tmpSz = (int)smpro_dbh_n($v, 'tmp_table_size');
        $heapSz = (int)smpro_dbh_n($v, 'max_heap_table_size');
        $eff = min($tmpSz, $heapSz);
        if ($ratio >= 0.25) {
            $sev = $ratio >= 0.50 ? 'high' : 'medium';
            $canBump = $eff < 64 * 1024 * 1024;
            $add($sev, 'tmp_disk',
                round($ratio * 100) . '% of temp tables go to DISK',
                round($ratio * 100) . '% of internal temp tables spill to disk (' . number_format($tmpD) . ' of ' . number_format($tmp) . '; ~' . $perHr($tmpD) . '/hr). In-memory limit: ' . smpro_dbh_bytes_h($eff) . ' (tmp_table_size ' . smpro_dbh_bytes_h($tmpSz) . ' / max_heap_table_size ' . smpro_dbh_bytes_h($heapSz) . ').',
                'When a GROUP BY / ORDER BY / DISTINCT / UNION builds a temp table larger than the in-memory limit — or uses a BLOB/TEXT column — MySQL writes it to disk, which is far slower and hammers I/O. A high disk ratio is one of the most common causes of a database that "suddenly got slow".',
                'Raise tmp_table_size and max_heap_table_size together (they must match) so more temp tables stay in RAM, AND fix the queries that build big temp tables (add indexes for their GROUP BY/ORDER BY, avoid SELECT *, and move BLOB/TEXT out of sorted result sets).',
                $canBump ? ['action' => 'bump_tmp', 'label' => 'Raise temp-table size to 64M (live)'] : null);
        } elseif ($tmpD >= 500000 && smpro_dbh_rate($tmpD, $up) * 3600 >= 60) {
            // Lesson from a real production box: 1,273,812 on-disk temp tables. Even when the on-disk
            // SHARE stays under 25%, that absolute volume is constant disk I/O that RAM would absorb.
            $canBump = $eff < 64 * 1024 * 1024;
            $add('medium', 'tmp_disk_vol',
                number_format($tmpD) . ' temp tables written to DISK (' . round($ratio * 100, 1) . '% of all temp tables)',
                'Created_tmp_disk_tables=' . number_format($tmpD) . ' of Created_tmp_tables=' . number_format($tmp) . ' (' . round($ratio * 100, 1) . '% on disk, ~' . $perHr($tmpD) . '/hr). In-memory limit: ' . smpro_dbh_bytes_h($eff) . ' (tmp_table_size ' . smpro_dbh_bytes_h($tmpSz) . ' / max_heap_table_size ' . smpro_dbh_bytes_h($heapSz) . ').',
                'The on-disk share is below the 25% warning line, but the sheer number of temp tables hitting disk is large enough to generate constant I/O. Each one is a GROUP BY / ORDER BY / DISTINCT / UNION intermediate result that outgrew the in-memory limit (or contains BLOB/TEXT columns) and was written to disk instead of RAM.',
                'Raise tmp_table_size and max_heap_table_size together (they must be equal to take effect) so more of these stay in RAM, and review the heavy GROUP BY / ORDER BY queries that create them — the slow-query log will name them.',
                $canBump ? ['action' => 'bump_tmp', 'label' => 'Raise temp-table size to 64M (live)'] : null);
        }
    }

    // 2) UNINDEXED JOINS / FULL SCANS - joins with no usable index are pathologically slow.
    $fullJoin = smpro_dbh_n($s, 'Select_full_join');
    $rangeChk = smpro_dbh_n($s, 'Select_range_check');
    $scan     = smpro_dbh_n($s, 'Select_scan');
    if (!$warm && $fullJoin > 0 && smpro_dbh_rate($fullJoin, $up) * 60 >= 1) {
        $add('high', 'full_join',
            number_format($fullJoin) . ' joins with NO index (~' . $perHr($fullJoin) . '/hr)',
            'Select_full_join=' . number_format($fullJoin) . ' (~' . $perHr($fullJoin) . '/hr), Select_range_check=' . number_format($rangeChk) . ', Select_scan=' . number_format($scan) . '.',
            'Select_full_join counts joins that could not use ANY index on the joined table — every such query re-reads the whole table for each row of the other, so cost explodes as tables grow. This is almost always a missing index on a JOIN/WHERE column.',
            'Turn on the slow-query log, capture the offending statements, and add the missing indexes (pt-query-digest or EXPLAIN will point at the un-indexed join column). This is the single highest-leverage fix for a slow database.',
            (($v['slow_query_log'] ?? 'OFF') !== 'ON') ? ['action' => 'enable_slowlog', 'label' => 'Enable slow-query log to capture them'] : null);
    }

    // 3) SLOW-QUERY LOG - visibility. If off, DB slowness is invisible.
    $slowOn = (($v['slow_query_log'] ?? 'OFF') === 'ON');
    $slowQ  = smpro_dbh_n($s, 'Slow_queries');
    $lqt    = (float)($v['long_query_time'] ?? 10);
    if (!$slowOn) {
        $add('medium', 'slowlog_off',
            'Slow-query log is OFF',
            'slow_query_log=OFF — genuinely slow statements are not being recorded anywhere.',
            'Without the slow-query log you are flying blind: you can see that the server is slow but not WHICH queries are responsible. Enabling it is the first step of every real MySQL performance investigation.',
            'Enable the slow-query log with long_query_time=2s, let it run through a slow period, then review it (or run pt-query-digest) to find the exact queries to optimize.',
            ['action' => 'enable_slowlog', 'label' => 'Enable slow-query log (live)']);
    } elseif ($slowQ > 0 && smpro_dbh_rate($slowQ, $up) * 60 >= 1) {
        $add('medium', 'slow_queries',
            number_format($slowQ) . ' slow queries logged (~' . $perHr($slowQ) . '/hr)',
            'Slow_queries=' . number_format($slowQ) . ' (~' . $perHr($slowQ) . '/hr) with long_query_time=' . $lqt . 's. Log: ' . ($v['slow_query_log_file'] ?? '(server default)') . '.',
            'The server is logging queries that exceed ' . $lqt . 's at a meaningful rate — these are the statements users feel as "the site is slow".',
            'Review the slow log (or run: pt-query-digest ' . ($v['slow_query_log_file'] ?? '/var/lib/mysql/*-slow.log') . '), then index/rewrite the top offenders.', null);
    }

    // 4) CONNECTION SATURATION - pileups + rejected connections.
    $maxConn   = max(1, (int)smpro_dbh_n($v, 'max_connections'));
    $connd     = (int)smpro_dbh_n($s, 'Threads_connected');
    $maxUsed   = (int)smpro_dbh_n($s, 'Max_used_connections');
    $running   = (int)smpro_dbh_n($s, 'Threads_running');
    $rejected  = smpro_dbh_n($s, 'Connection_errors_max_connections');
    if ($rejected > 0) {
        $add('high', 'conn_rejected',
            number_format($rejected) . ' connections REJECTED (max_connections hit)',
            'Connection_errors_max_connections=' . number_format($rejected) . '; max_connections=' . $maxConn . ', peak used=' . $maxUsed . '.',
            'The server has already refused connections because it reached max_connections — visitors get "Too many connections" and the site errors out. Usually caused by slow queries holding threads (pileup) or a connection leak in an app.',
            'Fix the root cause first (the slow/locking queries that make threads pile up — see the temp-table / full-join / lock findings). Only raise max_connections after that, and only if RAM allows (each thread costs memory).', null);
    } elseif ($maxUsed / $maxConn >= 0.85) {
        $add('medium', 'conn_peak',
            'Peak connections reached ' . round($maxUsed / $maxConn * 100) . '% of the limit',
            'Max_used_connections=' . $maxUsed . ' of max_connections=' . $maxConn . ' (' . round($maxUsed / $maxConn * 100) . '%). Currently connected: ' . $connd . '.',
            'Connection usage has peaked close to the ceiling. If it reaches 100% the server starts rejecting connections and sites error out.',
            'Investigate what holds connections open (slow queries, an app not closing connections). Consider a modest max_connections increase only if you have RAM headroom.', null);
    }
    // running threads vs cores - live contention signal
    if ($running > max(4, $cores * 2)) {
        $add('high', 'threads_running',
            $running . ' queries running at once (server has ' . $cores . ' cores)',
            'Threads_running=' . $running . ' vs ' . $cores . ' CPU cores. Active (non-idle) threads now: ' . count($active) . '.',
            'Far more queries are executing simultaneously than the CPU can run in parallel — they queue behind each other, and each one gets slower. A running-thread spike well above core count is the live signature of a query pileup (often triggered by one slow/locking query).',
            'Look at "Queries running now" below for the long-running / locking statement at the head of the pileup and address it (index it, or kill it if it is stuck).', null);
    }

    // 5) InnoDB BUFFER POOL - is hot data served from RAM or re-read from disk?
    $reads    = smpro_dbh_n($s, 'Innodb_buffer_pool_reads');           // physical reads (missed cache)
    $reqs     = smpro_dbh_n($s, 'Innodb_buffer_pool_read_requests');   // logical reads
    $bp       = (int)smpro_dbh_n($v, 'innodb_buffer_pool_size');
    if ($reqs > 100000) {
        $missPct = $reads / max(1, $reqs) * 100;
        if ($missPct >= 1.0 && $reads > 100000) {
            $sev = $missPct >= 5.0 ? 'high' : 'medium';
            $dataMb = smpro_dbh_datasize_mb();   // cached ~1h: the information_schema aggregate is the one costly query
            $dataNote = $dataMb > 0 ? ' InnoDB data+indexes ≈ ' . smpro_dbh_bytes_h($dataMb * 1048576) . ' vs buffer pool ' . smpro_dbh_bytes_h($bp) . '.' : ' Buffer pool: ' . smpro_dbh_bytes_h($bp) . '.';
            $add($sev, 'innodb_bp',
                'InnoDB buffer pool miss rate ' . round($missPct, 1) . '% — hot data read from disk',
                'Innodb_buffer_pool_reads=' . number_format($reads) . ' of ' . number_format($reqs) . ' requests (' . round($missPct, 2) . '% missed the cache).' . $dataNote,
                'The InnoDB buffer pool caches table + index pages in RAM. A high miss rate means frequently-used data does not fit and is being re-read from disk on every access — slow, and it saturates disk I/O.',
                'Increase innodb_buffer_pool_size so the working set fits in RAM (a common target is up to ~50–70% of server RAM on a dedicated DB box, less on a shared cPanel box). On MySQL 5.7+/MariaDB 10.2+ it can be resized live; make it persistent in my.cnf.', null);
        }
    }

    // 5b) BUFFER POOL UNDERSIZED FOR THIS MACHINE - the "shipped default on a big server" trap.
    // Lesson from a real production box: a 124 GB server was running the 128 MB compiled-in default -
    // the single biggest missed performance win. Config-vs-hardware check, so it needs no warm-up.
    $ramB = (float)$srv['ram_bytes'];
    if ($bp > 0 && $ramB >= 4 * 1073741824) {                                  // need a believable RAM reading on a real server
        $tinyAbs = $bp <= 256 * 1048576;                                       // at or near the shipped 128 MB default
        $tinyRel = ($ramB >= 8 * 1073741824) && ($bp < $ramB * 0.20);          // under 20% of RAM on an 8 GB+ box
        if ($tinyAbs || $tinyRel) {
            $sugg = smpro_dbh_round_mb(min(24 * 1073741824, $ramB * 0.5), 128); // conservative shared-cPanel cap: min(24 GB, 50% RAM)
            $bpPct = round($bp / $ramB * 100, 1);
            $hasLiveRec = false;                                                // only offer the button when the guarded rec path will accept it
            foreach (smpro_dbh_recommend() as $r0) if (($r0['key'] ?? '') === 'innodb_buffer_pool_size' && !empty($r0['dynamic'])) { $hasLiveRec = true; break; }
            $add('high', 'bp_undersized',
                'InnoDB buffer pool is only ' . smpro_dbh_bytes_h($bp) . ' on a ' . round($ramB / 1073741824) . ' GB server',
                'innodb_buffer_pool_size=' . smpro_dbh_bytes_h($bp) . ' — ' . $bpPct . '% of ' . smpro_dbh_bytes_h($ramB) . ' system RAM.' . ($tinyAbs ? ' This is at or near the shipped 128 MB default, which is almost never right for a production server.' : ''),
                'The buffer pool is the RAM cache for every InnoDB table and index page. When it is this small relative to the machine, hot data is re-read from disk continuously and every query pays for it — leaving the default pool on a large server is one of the most common and biggest missed MySQL performance wins.',
                'Suggestion to review — not to apply blindly: raise innodb_buffer_pool_size to around ' . smpro_dbh_bytes_h($sugg) . ' (a conservative shared-cPanel starting point of min(24 GB, 50% of RAM); a dedicated database server can go to ~50-70% of RAM). Weigh it against everything else this box runs (Apache/PHP/mail) and current free memory first. "Ways to improve" above computes a value fitted to this server\'s actual data size; a permanent change belongs in my.cnf (SET GLOBAL resizes online on MySQL 5.7+/MariaDB 10.2+ but reverts on restart).',
                $hasLiveRec ? ['action' => 'grow_buffer_pool', 'label' => 'Apply recommended pool size (live)'] : null);
        }
    }

    // 6) TABLE CACHE OVERFLOW - reopening tables constantly is pure overhead.
    $toc_of = smpro_dbh_n($s, 'Table_open_cache_overflows');
    $opened = smpro_dbh_n($s, 'Opened_tables');
    $toc    = (int)smpro_dbh_n($v, 'table_open_cache');
    if (($toc_of > 0 && smpro_dbh_rate($toc_of, $up) * 60 >= 1) || ($toc_of == 0 && $opened > 0 && smpro_dbh_rate($opened, $up) * 60 >= 30)) {
        $add('medium', 'table_cache',
            'Table-cache is overflowing — tables reopened constantly',
            ($toc_of > 0 ? 'Table_open_cache_overflows=' . number_format($toc_of) . ' (~' . $perHr($toc_of) . '/hr)' : 'Opened_tables=' . number_format($opened) . ' (~' . $perHr($opened) . '/hr)') . ' with table_open_cache=' . number_format($toc) . '.',
            'table_open_cache limits how many table handles stay open. When it overflows, MySQL closes and reopens table files on almost every query — extra filesystem work that shows up as latency, especially with many small tables or high concurrency.',
            'Raise table_open_cache so the working set of tables stays open. (And keep the total number of tables reasonable.)',
            ['action' => 'bump_table_cache', 'label' => 'Raise table_open_cache (live)']);
    }

    // 7) MyISAM TABLE-LEVEL LOCK WAITS - one write blocks all readers.
    $lkWait = smpro_dbh_n($s, 'Table_locks_waited');
    $lkImm  = smpro_dbh_n($s, 'Table_locks_immediate');
    if ($lkWait > 50 && ($lkWait / max(1, $lkImm + $lkWait)) >= 0.01) {
        $add('medium', 'myisam_locks',
            'Table-level lock contention (' . round($lkWait / max(1, $lkImm + $lkWait) * 100, 1) . '% of locks waited)',
            'Table_locks_waited=' . number_format($lkWait) . ' vs immediate=' . number_format($lkImm) . '.',
            'Table-level lock waits are almost always MyISAM tables: a single INSERT/UPDATE locks the WHOLE table, so every reader stalls behind it. This serializes traffic and feels like random slowness under load.',
            'Convert the hot MyISAM tables to InnoDB (row-level locking): ALTER TABLE <t> ENGINE=InnoDB. Check with: SELECT table_schema,table_name FROM information_schema.tables WHERE engine=\'MyISAM\' AND table_schema NOT IN (\'mysql\',\'information_schema\',\'performance_schema\').', null);
    }

    // 8) InnoDB ROW-LOCK CONTENTION - long transactions blocking each other.
    $rlWaits = smpro_dbh_n($s, 'Innodb_row_lock_waits');
    $rlAvg   = smpro_dbh_n($s, 'Innodb_row_lock_time_avg');   // ms
    if ($rlWaits > 100 && $rlAvg >= 200) {
        $add('medium', 'innodb_rowlock',
            'InnoDB row-lock waits averaging ' . round($rlAvg) . 'ms',
            'Innodb_row_lock_waits=' . number_format($rlWaits) . ', avg wait=' . round($rlAvg) . 'ms, current waiters=' . (int)smpro_dbh_n($s, 'Innodb_row_lock_current_waits') . '.',
            'Transactions are frequently waiting on rows locked by other transactions. Long-held locks (a transaction left open, or a slow UPDATE inside a transaction) block everyone touching the same rows.',
            'Keep transactions short, commit promptly, and index the WHERE columns of UPDATE/DELETE so they lock few rows. Look for an app that opens a transaction and does slow work before COMMIT.', null);
    }

    // 9) InnoDB LOG BUFFER - waits mean the redo log buffer is too small.
    if (smpro_dbh_n($s, 'Innodb_log_waits') > 0) {
        $add('low', 'innodb_logwaits',
            'InnoDB redo-log buffer waits',
            'Innodb_log_waits=' . number_format(smpro_dbh_n($s, 'Innodb_log_waits')) . ' (innodb_log_buffer_size=' . smpro_dbh_bytes_h(smpro_dbh_n($v, 'innodb_log_buffer_size')) . ').',
            'Write bursts had to wait for the redo-log buffer to flush because it is too small — adds latency to writes.',
            'Increase innodb_log_buffer_size (e.g. 16–64M) in my.cnf.', null);
    }

    // 10) SORT MERGE PASSES - big sorts spilling because of a small sort buffer / missing index.
    $smp = smpro_dbh_n($s, 'Sort_merge_passes');
    if (!$warm && $smp > 0 && smpro_dbh_rate($smp, $up) * 60 >= 1) {
        $add('low', 'sort_merge',
            'Sorts spilling to multiple merge passes (~' . $perHr($smp) . '/hr)',
            'Sort_merge_passes=' . number_format($smp) . ' (sort_buffer_size=' . smpro_dbh_bytes_h(smpro_dbh_n($v, 'sort_buffer_size')) . ').',
            'Large ORDER BY sorts did not fit in the sort buffer and needed multiple disk merge passes. Usually the real fix is an index that satisfies the ORDER BY so no big sort is needed.',
            'Add indexes matching the heavy ORDER BY clauses; only raise sort_buffer_size modestly if genuinely needed (it is per-connection, so large values waste RAM).', null);
    }

    // 11) QUERY CACHE (MariaDB / MySQL 5.7) - a scalability bottleneck under concurrency.
    if (($v['query_cache_type'] ?? 'OFF') !== 'OFF' && (int)smpro_dbh_n($v, 'query_cache_size') > 0) {
        $prunes = smpro_dbh_n($s, 'Qcache_lowmem_prunes');
        $sev = ($prunes > 0 && smpro_dbh_rate($prunes, $up) * 60 >= 1) ? 'medium' : 'low';
        $add($sev, 'query_cache',
            'Query cache is ON — a known concurrency bottleneck',
            'query_cache_type=' . ($v['query_cache_type'] ?? '') . ', query_cache_size=' . smpro_dbh_bytes_h(smpro_dbh_n($v, 'query_cache_size')) . ', Qcache_lowmem_prunes=' . number_format($prunes) . '.',
            'The query cache takes a global lock on every read AND every write to the same tables, so on a busy multi-core server it often SLOWS things down rather than speeding them up (this is why MySQL 8 removed it entirely).',
            'On a busy server, set query_cache_type=OFF and query_cache_size=0 and rely on the InnoDB buffer pool + application caching instead.', null);
    }

    // 12) ABORTED CONNECTIONS - auth/network churn.
    $abConn = smpro_dbh_n($s, 'Aborted_connects');
    if ($abConn > 100 && smpro_dbh_rate($abConn, $up) * 3600 >= 10) {
        $add('low', 'aborted_conn',
            number_format($abConn) . ' aborted connections (~' . $perHr($abConn) . '/hr)',
            'Aborted_connects=' . number_format($abConn) . ' (~' . $perHr($abConn) . '/hr).',
            'Connections that failed before authenticating — usually wrong credentials (a mis-configured app), a scanner probing 3306, or network timeouts. High rates waste resources and can hint at a brute-force on the DB port.',
            'Check which app/host is failing to authenticate; ensure MySQL is not exposed to the internet on 3306 (bind-address / firewall).', null);
    }

    // 13) QUERIES SLOW RIGHT NOW - the live smoking gun.
    $longNow = [];
    foreach ($active as $r) if ($r['time'] >= 15 && strcasecmp($r['command'], 'Sleep') !== 0) $longNow[] = $r;
    if ($longNow) {
        $top = $longNow[0];
        $add(($top['time'] >= 60 ? 'high' : 'medium'), 'long_running',
            count($longNow) . ' quer' . (count($longNow) === 1 ? 'y' : 'ies') . ' running longer than 15s RIGHT NOW',
            'Longest: thread ' . $top['id'] . ' (' . $top['user'] . ($top['db'] !== '' ? '/' . $top['db'] : '') . ') running ' . smpro_dbh_dur_h($top['time']) . ' — ' . $top['command'] . ($top['state'] !== '' ? ' · ' . $top['state'] : '') . '.',
            'These queries are executing at this moment and have been for a while — on a slow server they are frequently the direct cause (or a symptom of locking). A single long query can pile every other request up behind it.',
            'Review "Queries running now" below. If a query is genuinely stuck (e.g. "Waiting for table metadata lock", or a runaway SELECT with no index), you can kill just that statement from there. Then fix its root cause (index / rewrite / long transaction).', null);
    }

    // stable severity sort (critical->high->medium->low)
    $rank = ['critical' => 0, 'high' => 1, 'medium' => 2, 'low' => 3];
    usort($F, function ($a, $b) use ($rank) { return ($rank[$a['sev']] ?? 9) <=> ($rank[$b['sev']] ?? 9); });
    return ['findings' => $F, 'warm' => $warm, 'active' => $active, 'proc' => $pl, 'server' => $srv, 'status' => $s, 'vars' => $v];
}

/* ---------------- headline KPIs + overall verdict ---------------- */
function smpro_dbh_report() {
    $A = smpro_dbh_analyze();
    $s = $A['status']; $v = $A['vars']; $srv = $A['server'];
    $up = max(1, $srv['uptime']);

    $questions = smpro_dbh_n($s, 'Questions');
    $qps = round(smpro_dbh_rate($questions, $up), 1);
    $connd = (int)smpro_dbh_n($s, 'Threads_connected');
    $running = (int)smpro_dbh_n($s, 'Threads_running');
    $maxConn = max(1, (int)smpro_dbh_n($v, 'max_connections'));
    $tmp = smpro_dbh_n($s, 'Created_tmp_tables'); $tmpD = smpro_dbh_n($s, 'Created_tmp_disk_tables');
    $reads = smpro_dbh_n($s, 'Innodb_buffer_pool_reads'); $reqs = smpro_dbh_n($s, 'Innodb_buffer_pool_read_requests');
    $slowQ = smpro_dbh_n($s, 'Slow_queries');

    $kpis = [
        'qps'          => $qps,
        'connected'    => $connd,
        'running'      => $running,
        'max_conn'     => $maxConn,
        'conn_pct'     => round($connd / $maxConn * 100),
        'tmp_disk_pct' => $tmp > 0 ? round($tmpD / $tmp * 100) : 0,
        'bp_hit_pct'   => $reqs > 0 ? round((1 - $reads / $reqs) * 100, 2) : 100,
        'slow_per_hr'  => round(smpro_dbh_rate($slowQ, $up) * 3600, 1),
        'slow_on'      => (($v['slow_query_log'] ?? 'OFF') === 'ON'),
        'buffer_pool'  => (int)$srv['buffer_pool'],
        'uptime_h'     => smpro_dbh_dur_h($up),
    ];

    // score: 100 minus weighted findings
    $w = ['critical' => 45, 'high' => 22, 'medium' => 11, 'low' => 4];
    $score = 100; foreach ($A['findings'] as $f) $score -= ($w[$f['sev']] ?? 0);
    $score = max(0, min(100, $score));
    $verdict = $score >= 90 ? ['Healthy', 'good'] : ($score >= 70 ? ['Watch', 'warn'] : ($score >= 45 ? ['Degraded', 'warn'] : ['Critical', 'dang']));

    $counts = ['high' => 0, 'medium' => 0, 'low' => 0, 'critical' => 0];
    foreach ($A['findings'] as $f) $counts[$f['sev']] = ($counts[$f['sev']] ?? 0) + 1;

    return [
        'server'   => $srv,
        'kpis'     => $kpis,
        'config'   => smpro_dbh_config(),
        'findings' => $A['findings'],
        'active'   => $A['active'],
        'proc'     => $A['proc'],
        'warm'     => $A['warm'],
        'score'    => $score,
        'verdict'  => $verdict[0],
        'verdict_cls' => $verdict[1],
        'counts'   => $counts,
        'ts'       => date('H:i:s'),
    ];
}

/* ---------------- shared HTML renderers (ONE source of truth for the page render AND the live refresh) ---------------- */
function smpro_dbh_pcls($p, $warn, $dang) { return $p >= $dang ? 'red' : ($p >= $warn ? 'orange' : 'green'); }
function smpro_dbh_kpis_html(array $R) {
    $k = $R['kpis'];
    $h  = '<div class="card"><div class="lbl">Queries / sec</div><div class="val">' . smpro_h($k['qps']) . '</div><div class="meta">how busy the DB is now</div></div>';
    $h .= '<div class="card"><div class="lbl">Running / Connected</div><div class="val">' . (int)$k['running'] . ' / ' . (int)$k['connected'] . '</div>'
        . '<div class="meta"><span class="b ' . smpro_dbh_pcls($k['conn_pct'], 70, 90) . '">' . (int)$k['conn_pct'] . '%</span> of ' . (int)$k['max_conn'] . ' allowed · <span class="dbh-target">ideal &lt; 70%</span></div></div>';
    $h .= '<div class="card"><div class="lbl">Temp tables on disk</div><div class="val"><span class="b ' . smpro_dbh_pcls($k['tmp_disk_pct'], 25, 50) . '">' . (int)$k['tmp_disk_pct'] . '%</span></div>'
        . '<div class="meta"><span class="dbh-target">ideal &lt; 25%</span> · lower is better</div></div>';
    $bh = (float)$k['bp_hit_pct'];
    $h .= '<div class="card"><div class="lbl">Buffer-pool hit</div><div class="val"><span class="b ' . ($bh >= 99 ? 'green' : ($bh >= 95 ? 'orange' : 'red')) . '">' . number_format($bh, 2) . '%</span></div>'
        . '<div class="meta">data served from RAM · <span class="dbh-target">ideal &ge; 99%</span></div></div>';
    $h .= '<div class="card"><div class="lbl">Slow queries / hr</div><div class="val">' . smpro_h($k['slow_per_hr']) . '</div>'
        . '<div class="meta">' . ($k['slow_on'] ? 'slow log ON' : '<span style="color:var(--warn)">slow log OFF</span>') . ' · <span class="dbh-target">ideal: log ON, few slow</span></div></div>';
    return $h;
}
function smpro_dbh_config_html(array $R) {
    $h = '<table class="smpro-table dbh-cfg"><thead><tr><th>Setting</th><th>Now (used)</th><th>Ideal</th><th>Status</th><th>What it does</th></tr></thead><tbody>';
    foreach ($R['config'] as $c) {
        $stCls = ['good' => 'green', 'watch' => 'orange', 'bad' => 'red'][$c['status']] ?? 'gray';
        $stTxt = ['good' => 'Good', 'watch' => 'Could improve', 'bad' => 'Needs attention'][$c['status']] ?? '';
        $bar = ($c['used_pct'] !== null)
            ? '<div class="dbh-bar"><span class="' . ($c['used_pct'] >= 85 ? 'red' : ($c['used_pct'] >= 70 ? 'orange' : 'green')) . '" style="width:' . min(100, max(2, (int)$c['used_pct'])) . '%"></span></div>' : '';
        $h .= '<tr><td><b>' . smpro_h($c['label']) . '</b></td><td class="mono">' . smpro_h($c['now']) . $bar . '</td>'
            . '<td class="dbh-ideal">' . smpro_h($c['ideal']) . '</td><td><span class="b ' . $stCls . '">' . $stTxt . '</span></td>'
            . '<td class="dbh-what">' . smpro_h($c['what']) . '</td></tr>';
    }
    return $h . '</tbody></table>';
}
function smpro_dbh_findings_html(array $R) {
    $sevCls = ['critical' => 'red', 'high' => 'red', 'medium' => 'orange', 'low' => 'blue'];
    $sevLbl = ['critical' => 'CRITICAL', 'high' => 'HIGH', 'medium' => 'MEDIUM', 'low' => 'LOW'];
    if (!$R['findings'])
        return '<div style="padding:22px 16px;text-align:center;color:var(--good)"><b>&#10003; No slowness signals detected.</b>'
             . '<div class="sub" style="margin-top:4px">MySQL\'s counters look healthy on this server right now.</div></div>';
    $h = '<div class="dbh-findings">';
    foreach ($R['findings'] as $f) {
        $c = $sevCls[$f['sev']] ?? 'blue';
        $btn = !empty($f['fix'])
            ? '<button class="tp-btn dbh-fix" type="button" data-fix="' . smpro_h($f['fix']['action']) . '">' . smpro_h($f['fix']['label']) . '</button>' : '';
        $h .= '<div class="dbh-f dbh-' . $c . '"><div class="dbh-frow"><span class="b ' . $c . ' dbh-sev">' . ($sevLbl[$f['sev']] ?? 'INFO') . '</span>'
            . '<b class="dbh-ftitle">' . smpro_h($f['title']) . '</b>' . $btn . '</div>'
            . '<div class="dbh-eqv">' . smpro_h($f['evidence']) . '</div>'
            . '<div class="dbh-detail">' . smpro_h($f['detail']) . '</div>'
            . '<div class="dbh-rec"><span>&#128161; Fix</span> ' . smpro_h($f['rec']) . '</div></div>';
    }
    return $h . '</div>';
}
function smpro_dbh_recommend_html(array $rows) {
    if (!$rows)
        return '<div style="padding:20px 16px;text-align:center;color:var(--good)"><b>&#10003; Nothing to tune.</b>'
             . '<div class="sub" style="margin-top:4px">The key MySQL settings already match what this server\'s RAM, cores and data size call for.</div></div>';
    $gainLbl = ['high' => ['red', 'Big win'], 'medium' => ['orange', 'Worth doing'], 'low' => ['blue', 'Minor']];
    $h = '<div class="smpro-tablewrap"><table class="smpro-table dbh-rectbl"><thead><tr><th>Setting</th><th>Now</th><th>Recommended</th><th>Impact</th><th>Why this value</th><th></th></tr></thead><tbody>';
    foreach ($rows as $r) {
        $g = $gainLbl[$r['gain']] ?? ['gray', ''];
        $act = !empty($r['dynamic'])
            ? '<button class="tp-btn dbh-recapply" type="button" data-key="' . smpro_h($r['key']) . '">Apply live</button>'
            : '<span class="meta">needs restart</span>';
        $h .= '<tr><td><b>' . smpro_h($r['label']) . '</b><div class="meta mono">' . smpro_h($r['key']) . '</div></td>'
            . '<td class="mono">' . smpro_h($r['cur']) . '</td>'
            . '<td class="mono"><b class="dbh-target">' . smpro_h($r['rec']) . '</b></td>'
            . '<td><span class="b ' . $g[0] . '">' . $g[1] . '</span></td>'
            . '<td class="dbh-what">' . smpro_h($r['why']) . '</td>'
            . '<td>' . $act . '</td></tr>';
    }
    $h .= '</tbody></table></div>';
    $snip = smpro_dbh_mycnf_snippet($rows);
    if ($snip !== '') $h .= '<div class="dbh-snip"><div class="dbh-sniphd">&#128196; Make it permanent — add this under <span class="mono">[mysqld]</span> in my.cnf, then restart MySQL in a quiet window:</div><pre>' . smpro_h($snip) . '</pre></div>';
    return $h;
}

/* ---------------- live poll payload (cheap, fresh; $full also re-renders the whole page) ---------------- */
function smpro_dbh_live($full = false) {
    $st = smpro_dbh_state();
    if (empty($st['ok'])) return ['db_ok' => false, 'reason' => $st['reason'] ?? '', 'msg' => $st['msg'] ?? ''];
    $t = smpro_dbh_kv("SHOW GLOBAL STATUS WHERE Variable_name IN ('Threads_running','Threads_connected','Threads_created','Queries')", 8);
    $pl = smpro_dbh_processlist();
    $active = smpro_dbh_active($pl);
    $longest = 0; foreach ($active as $r) if ($r['time'] > $longest) $longest = $r['time'];
    $out = [
        'db_ok'            => true,
        'threads_running'  => (int)($t['Threads_running'] ?? 0),
        'threads_connected' => (int)($t['Threads_connected'] ?? 0),
        'active'           => count($active),
        'longest'          => $longest,
        'proc'             => $pl,
        'ts'               => date('H:i:s'),
    ];
    if ($full) {                                   // whole page re-rendered server-side -> one source of truth
        $R   = smpro_dbh_report();
        $rec = smpro_dbh_recommend();
        $out['score']       = $R['score'];
        $out['verdict']     = $R['verdict'];
        $out['verdict_cls'] = $R['verdict_cls'];
        $out['counts']      = $R['counts'];
        $out['rec_count']   = count($rec);
        $out['fcount']      = count($R['findings']);
        $out['html'] = [
            'kpis'     => smpro_dbh_kpis_html($R),
            'config'   => smpro_dbh_config_html($R),
            'findings' => smpro_dbh_findings_html($R),
            'rec'      => smpro_dbh_recommend_html($rec),
        ];
    }
    return $out;
}

/* ---------------- InnoDB data size (cached - the information_schema aggregate is the one expensive query) ---------------- */
function smpro_dbh_datasize_mb($ttl = 3600) {
    $f = SMPRO_VARLIB . '/dbh_datasize.json';
    $d = @is_file($f) ? json_decode((string)@file_get_contents($f), true) : null;
    if (is_array($d) && (time() - (int)($d['ts'] ?? 0)) < $ttl) return (int)$d['mb'];
    $sqlSz = "SELECT ROUND(SUM(data_length+index_length)/1048576) FROM information_schema.tables WHERE engine='InnoDB'";
    $raw = function_exists('smpro_memo_cmd') ? smpro_memo_cmd('dbh_datasize', (int)$ttl, smpro_dbh_cmd($sqlSz), 60, 604800, true) : smpro_dbh_q($sqlSz, 8);   // 13 s on a large server: never inline, computed behind the page
    if (trim($raw) === '') return 0;   // not known yet (first open, or the scan is running): callers treat 0 as "unknown"; nothing is cached
    $mb = (int)trim($raw);
    @is_dir(dirname($f)) || @mkdir(dirname($f), 0700, true);
    if (@file_put_contents($f, json_encode(['ts' => time(), 'mb' => $mb]), LOCK_EX) !== false) @chmod($f, 0600);
    return $mb;
}

/* ---------------- MyISAM hot tables (cached ~1h) - names the tables behind the myisam_locks finding ---------------- */
/** Read-only list of the biggest user MyISAM tables (each is a table-lock candidate to convert to InnoDB). */
function smpro_dbh_myisam_tables($ttl = 3600) {
    $f = SMPRO_VARLIB . '/dbh_myisam.json';
    $d = @is_file($f) ? json_decode((string)@file_get_contents($f), true) : null;
    if (is_array($d) && isset($d['rows']) && is_array($d['rows']) && (time() - (int)($d['ts'] ?? 0)) < $ttl) return $d['rows'];
    $sql = "SELECT table_schema, table_name, ROUND(data_length/1048576,1) AS mb "
         . "FROM information_schema.tables "
         . "WHERE engine='MyISAM' AND table_schema NOT IN ('mysql','information_schema','performance_schema','sys') "
         . "ORDER BY data_length DESC LIMIT 40";
    $rows = [];
    $rawM = function_exists('smpro_memo_cmd') ? smpro_memo_cmd('dbh_myisam', (int)$ttl, smpro_dbh_cmd($sql), 60, 604800, true) : smpro_dbh_q($sql, 12);
    if (trim($rawM) === '') return [];   // not known yet: an empty list, and nothing cached as if it were final
    foreach (explode("\n", $rawM) as $l) {
        if ($l === '') continue; $p = explode("\t", $l, 3);
        if (count($p) < 3) continue;
        $rows[] = ['schema' => $p[0], 'table' => $p[1], 'mb' => (float)$p[2]];
    }
    @is_dir(dirname($f)) || @mkdir(dirname($f), 0700, true);
    if (@file_put_contents($f, json_encode(['ts' => time(), 'rows' => $rows], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE), LOCK_EX) !== false) @chmod($f, 0600);
    return $rows;
}

/* ---------------- WAYS TO IMPROVE: values tuned to THIS server's RAM / cores / data size ---------------- */
function smpro_dbh_round_mb($bytes, $stepMb = 64) {
    $step = $stepMb * 1048576;
    return (int)max($step, round($bytes / $step) * $step);
}
/**
 * Compute the recommended value for each key knob from this machine's real resources.
 * Deliberately conservative: a cPanel box also runs Apache/PHP/mail, so MySQL never gets the
 * "dedicated DB server" 70-80% of RAM.
 */
function smpro_dbh_recommend() {
    $v = smpro_dbh_vars(); $s = smpro_dbh_status(); $srv = smpro_dbh_server();
    $ram = (float)$srv['ram_bytes']; $cores = max(1, (int)$srv['cores']);
    $dataMb = smpro_dbh_datasize_mb();
    $rows = [];

    // 1) InnoDB buffer pool - big enough for the hot data, capped at 50% RAM on a shared cPanel box.
    $bpCur = (int)smpro_dbh_n($v, 'innodb_buffer_pool_size');
    if ($ram > 0) {
        $want = $dataMb > 0 ? ($dataMb * 1048576 * 1.2) : ($ram * 0.25);   // fit data+indexes with 20% headroom
        $bpWant = smpro_dbh_round_mb(min($want, $ram * 0.5), 128);
        $bpWant = max($bpWant, 256 * 1048576);
        if ($bpWant > $bpCur * 1.25) {
            $rows[] = ['key' => 'innodb_buffer_pool_size', 'label' => 'InnoDB buffer pool',
                'cur' => smpro_dbh_bytes_h($bpCur), 'rec' => smpro_dbh_bytes_h($bpWant), 'rec_raw' => $bpWant,
                'dynamic' => true, 'gain' => 'high',
                'why' => $dataMb > 0
                    ? 'Your InnoDB data + indexes are about ' . smpro_dbh_bytes_h($dataMb * 1048576) . '. A pool of ' . smpro_dbh_bytes_h($bpWant) . ' lets the hot part live in RAM instead of being re-read from disk on every query — usually the single biggest MySQL speed win.'
                    : 'A larger pool keeps hot table + index pages in RAM instead of re-reading them from disk. Capped at 50% of RAM because this server also runs the web/mail stack.'];
        }
    }
    // 2) temp table limits
    $tt = (int)smpro_dbh_n($v, 'tmp_table_size'); $mh = (int)smpro_dbh_n($v, 'max_heap_table_size'); $eff = min($tt, $mh);
    $ttWant = ($ram >= 8 * 1073741824) ? 128 * 1048576 : 64 * 1048576;
    if ($eff < $ttWant || $tt !== $mh) {
        $rows[] = ['key' => 'tmp_table_size', 'label' => 'In-memory temp-table limit',
            'cur' => smpro_dbh_bytes_h($eff) . ($tt !== $mh ? ' (mismatched)' : ''), 'rec' => smpro_dbh_bytes_h($ttWant), 'rec_raw' => $ttWant,
            'dynamic' => true, 'gain' => (smpro_dbh_n($s, 'Created_tmp_disk_tables') > 0 ? 'high' : 'medium'),
            'why' => 'Temp tables bigger than this are written to disk instead of RAM. Raising it (both values must match) keeps GROUP BY / ORDER BY / DISTINCT work in memory.'];
    }
    // 3) table_open_cache
    $toc = (int)smpro_dbh_n($v, 'table_open_cache');
    $tocWant = smpro_dbh_n($s, 'Table_open_cache_overflows') > 0 ? min(16000, max($toc * 2, 4000)) : 0;
    if ($tocWant > $toc) {
        $rows[] = ['key' => 'table_open_cache', 'label' => 'Table-open cache',
            'cur' => number_format($toc), 'rec' => number_format($tocWant), 'rec_raw' => $tocWant,
            'dynamic' => true, 'gain' => 'medium',
            'why' => 'The cache is overflowing, so MySQL keeps closing and reopening table files. A bigger cache removes that per-query overhead.'];
    }
    // 4) slow query log
    if (($v['slow_query_log'] ?? 'OFF') !== 'ON') {
        $rows[] = ['key' => 'slow_query_log', 'label' => 'Slow-query log',
            'cur' => 'OFF', 'rec' => 'ON (2s)', 'rec_raw' => 1, 'dynamic' => true, 'gain' => 'high',
            'why' => 'Without it you cannot see WHICH queries are slow. Turn it on, let it collect during a busy period, then optimise the queries it names — that is where the real wins are.'];
    }
    // 5) query cache (legacy, hurts concurrency)
    if (isset($v['query_cache_type']) && $v['query_cache_type'] !== 'OFF' && (int)smpro_dbh_n($v, 'query_cache_size') > 0) {
        $rows[] = ['key' => 'query_cache_type', 'label' => 'Query cache',
            'cur' => 'ON · ' . smpro_dbh_bytes_h(smpro_dbh_n($v, 'query_cache_size')), 'rec' => 'OFF', 'rec_raw' => 0,
            'dynamic' => false, 'gain' => 'medium',
            'why' => 'On a busy multi-core server the query cache serialises reads and writes on the same table and costs more than it saves (MySQL 8 removed it). Turning it off usually increases throughput.'];
    }
    // 6) buffer pool instances (only meaningful once the pool is large)
    $bpNow = $bpCur; $inst = (int)smpro_dbh_n($v, 'innodb_buffer_pool_instances');
    if ($bpNow >= 1073741824 && $inst > 0 && $inst < min(8, $cores)) {
        $rows[] = ['key' => 'innodb_buffer_pool_instances', 'label' => 'Buffer-pool instances',
            'cur' => (string)$inst, 'rec' => (string)min(8, $cores), 'rec_raw' => min(8, $cores),
            'dynamic' => false, 'gain' => 'low',
            'why' => 'With a pool of 1 GB or more, splitting it into several instances reduces internal lock contention between concurrent queries. Needs a restart.'];
    }
    return $rows;
}
/** Copy-ready my.cnf block for the recommendations (the permanent version of the live fixes). */
function smpro_dbh_mycnf_snippet(array $rows) {
    if (!$rows) return '';
    $out = "[mysqld]\n";
    foreach ($rows as $r) {
        $k = $r['key'];
        if ($k === 'slow_query_log')      { $out .= "slow_query_log = 1\nlong_query_time = 2\n"; continue; }
        if ($k === 'query_cache_type')    { $out .= "query_cache_type = 0\nquery_cache_size = 0\n"; continue; }
        if ($k === 'tmp_table_size')      { $out .= 'tmp_table_size = ' . (int)($r['rec_raw'] / 1048576) . "M\n"
                                                 . 'max_heap_table_size = ' . (int)($r['rec_raw'] / 1048576) . "M\n"; continue; }
        if ($k === 'innodb_buffer_pool_size') { $out .= 'innodb_buffer_pool_size = ' . (int)($r['rec_raw'] / 1048576) . "M\n"; continue; }
        $out .= $k . ' = ' . $r['rec_raw'] . "\n";
    }
    return $out;
}
/** Apply ONE recommendation live (dynamic keys only), recording the previous value for Undo. */
function smpro_dbh_apply_rec($key) {
    if (!smpro_dbh_available()) return ['ok' => false, 'msg' => 'No local MySQL/MariaDB is reachable.'];
    $rec = null;
    foreach (smpro_dbh_recommend() as $r) if ($r['key'] === $key) { $rec = $r; break; }
    if (!$rec) return ['ok' => false, 'msg' => 'That recommendation no longer applies — reload the page.'];
    if (empty($rec['dynamic'])) return ['ok' => false, 'msg' => 'This one needs a MySQL restart, so it cannot be applied live. Add the my.cnf line shown below and restart MySQL during a quiet window.'];
    $v = smpro_dbh_vars();
    if ($key === 'slow_query_log') return smpro_dbh_apply('enable_slowlog');
    if ($key === 'tmp_table_size') {
        $to = (int)$rec['rec_raw'];
        smpro_dbh_prev_write('rec:tmp_table_size', ['tmp_table_size' => (int)smpro_dbh_n($v, 'tmp_table_size'), 'max_heap_table_size' => (int)smpro_dbh_n($v, 'max_heap_table_size')]);
        smpro_dbh_q('SET GLOBAL tmp_table_size=' . $to, 8);
        smpro_dbh_q('SET GLOBAL max_heap_table_size=' . $to, 8);
        $a = (int)trim(smpro_dbh_q('SELECT @@global.tmp_table_size', 6));
        $ok = $a >= $to;
        if (function_exists('smpro_audit')) smpro_audit('dbhealth_rec', ['key' => $key, 'to' => $to, 'ok' => $ok]);
        return ['ok' => $ok, 'undo' => $ok ? 'rec:tmp_table_size' : '', 'from' => $rec['cur'], 'to' => $rec['rec'],
            'msg' => $ok ? '✅ Temp-table limit raised to ' . $rec['rec'] . " (new connections).\n\nIt is a size limit, not data — nothing deleted, nothing to back up. Add the my.cnf lines below to keep it after a restart, or press Undo." : 'A hard-coded my.cnf value may be capping this.'];
    }
    if ($key === 'table_open_cache') {
        $to = (int)$rec['rec_raw'];
        smpro_dbh_prev_write('rec:table_open_cache', ['table_open_cache' => (int)smpro_dbh_n($v, 'table_open_cache')]);
        smpro_dbh_q('SET GLOBAL table_open_cache=' . $to, 8);
        $now = (int)trim(smpro_dbh_q('SELECT @@global.table_open_cache', 6));
        $ok = $now >= $to;
        if (function_exists('smpro_audit')) smpro_audit('dbhealth_rec', ['key' => $key, 'to' => $to, 'ok' => $ok]);
        return ['ok' => $ok, 'undo' => $ok ? 'rec:table_open_cache' : '', 'from' => $rec['cur'], 'to' => $rec['rec'],
            'msg' => $ok ? '✅ Table-open cache raised to ' . number_format($now) . ".\n\nA cache size, not data — nothing deleted, nothing to back up. Add the my.cnf line below to persist, or press Undo." : 'Could not raise table_open_cache.'];
    }
    if ($key === 'innodb_buffer_pool_size') {
        $to = (int)$rec['rec_raw']; $from = (int)smpro_dbh_n($v, 'innodb_buffer_pool_size');
        // Resizing the pool is online on MySQL 5.7+/MariaDB 10.2+, but it is real memory - refuse if the box lacks free RAM.
        $freeB = (float)((int)trim((string)@shell_exec("awk '/MemAvailable/{print \$2*1024}' /proc/meminfo 2>/dev/null")));
        if ($freeB > 0 && ($to - $from) > $freeB * 0.7)
            return ['ok' => false, 'msg' => 'Refused: growing the pool by ' . smpro_dbh_bytes_h($to - $from) . ' would use most of the ' . smpro_dbh_bytes_h($freeB) . ' currently available RAM. Free memory first, or apply it in my.cnf and restart during a quiet window.'];
        // Align the target UP to the engine's resize granularity (chunk_size x instances) so the server accepts the
        // exact size instead of silently rounding DOWN below our tolerance. These vars are ABSENT on MariaDB 10.11+
        // (single instant resize) -> the queries return '' and we skip alignment.
        $chunk = (int)trim(smpro_dbh_q('SELECT @@global.innodb_buffer_pool_chunk_size', 6));
        $inst  = (int)trim(smpro_dbh_q('SELECT @@global.innodb_buffer_pool_instances', 6));
        $gran  = $chunk > 0 ? $chunk * max(1, $inst) : 0;
        if ($gran > 0) $to = max($gran, (int)(ceil($to / $gran) * $gran));
        smpro_dbh_prev_write('rec:innodb_buffer_pool_size', ['innodb_buffer_pool_size' => $from]);
        // Capture STDERR so a rejection (read-only var on an old build, size cap, permissions) is reported with the
        // real reason instead of the generic "did not accept".
        $setErr = smpro_dbh_q_err('SET GLOBAL innodb_buffer_pool_size=' . $to, 20);
        // The resize can be asynchronous (MySQL runs it in a background thread) - poll the read-back briefly.
        $now = $from;
        for ($i = 0; $i < 6; $i++) {
            $now = (int)trim(smpro_dbh_q('SELECT @@global.innodb_buffer_pool_size', 8));
            if ($now >= $to * 0.98 || $now > $from) break;
            usleep(400000);
        }
        $ok = ($setErr === '') && ($now >= $to * 0.9 || ($to > $from && $now > $from));
        if (function_exists('smpro_audit')) smpro_audit('dbhealth_rec', ['key' => $key, 'from' => $from, 'to' => $to, 'now' => $now, 'ok' => $ok, 'err' => $setErr]);
        if ($ok) {
            return ['ok' => true, 'undo' => 'rec:innodb_buffer_pool_size', 'from' => smpro_dbh_bytes_h($from), 'to' => smpro_dbh_bytes_h($now),
                'msg' => '✅ InnoDB buffer pool resized from ' . smpro_dbh_bytes_h($from) . ' to ' . smpro_dbh_bytes_h($now) . " online — no restart, no data touched, nothing to back up.\n\nMySQL warms the new pool up gradually, so the benefit builds over the next few minutes. Add the my.cnf line below to keep it after a restart, or press Undo."];
        }
        if ($setErr !== '') {
            // Extract just the "ERROR nnnn (SQLSTATE): message" text (the CLI may prepend a statement banner).
            if (preg_match('/ERROR\s+\d+\s+\([0-9A-Za-z]+\)(?:\s+at line \d+)?:\s*(.+)$/im', $setErr, $em)) $r = trim($em[1]);
            else $r = trim(preg_replace('/\s+/', ' ', $setErr));
            $reason = "\n\nServer said: " . mb_substr($r, 0, 240);
        } else {
            $reason = ' — the command was accepted without error but the pool size did not change (it may still be applying in the background, or this build only honours innodb_buffer_pool_size from my.cnf).';
        }
        return ['ok' => false, 'from' => smpro_dbh_bytes_h($from), 'to' => smpro_dbh_bytes_h($now),
            'msg' => 'The server did not apply the live resize' . $reason . "\n\nApply it permanently instead: add the my.cnf line below (innodb_buffer_pool_size) and restart MySQL during a quiet window — that always works, even without online resize."];
    }
    return ['ok' => false, 'msg' => 'Unknown recommendation.'];
}

/* ---------------- utilization & configuration table (what's used vs its capacity, and the ideal) ---------------- */
function smpro_dbh_config() {
    $s = smpro_dbh_status(); $v = smpro_dbh_vars(); $srv = smpro_dbh_server();
    $ram = (float)$srv['ram_bytes'];
    $rows = [];

    $maxc = max(1, (int)smpro_dbh_n($v, 'max_connections'));
    $peak = (int)smpro_dbh_n($s, 'Max_used_connections');
    $pp = $peak / $maxc;
    $rows[] = ['label' => 'Client connections', 'now' => $peak . ' peak used / ' . $maxc . ' allowed',
        'used_pct' => round($pp * 100), 'ideal' => 'peak stays under ~80% of the limit',
        'status' => $pp >= 0.85 ? 'bad' : ($pp >= 0.70 ? 'watch' : 'good'),
        'what' => 'Simultaneous connections MySQL will accept. If peak reaches the limit, new visitors get "Too many connections".'];

    $bp = (int)smpro_dbh_n($v, 'innodb_buffer_pool_size');
    $bpPct = $ram > 0 ? round($bp / $ram * 100) : 0;
    $rows[] = ['label' => 'InnoDB buffer pool (RAM cache)', 'now' => smpro_dbh_bytes_h($bp) . ($ram > 0 ? ' — ' . $bpPct . '% of ' . smpro_dbh_bytes_h($ram) . ' RAM' : ''),
        'used_pct' => $bpPct, 'ideal' => 'big enough to hold the hot data (≈25–70% of RAM on a DB-dedicated box; less on shared cPanel)',
        'status' => $bp < 128 * 1024 * 1024 ? 'watch' : 'good',
        'what' => 'RAM cache for table + index pages. Too small ⇒ hot data is re-read from disk on every query.'];

    $tt = (int)smpro_dbh_n($v, 'tmp_table_size'); $mh = (int)smpro_dbh_n($v, 'max_heap_table_size'); $eff = min($tt, $mh);
    $rows[] = ['label' => 'In-memory temp-table limit', 'now' => smpro_dbh_bytes_h($eff) . ($tt !== $mh ? ' (the two values don\'t match!)' : ''),
        'used_pct' => null, 'ideal' => '≥ 64M, and tmp_table_size = max_heap_table_size',
        'status' => ($eff < 32 * 1024 * 1024 || $tt !== $mh) ? 'watch' : 'good',
        'what' => 'Biggest temp table kept in RAM. Above this, a query\'s temp table spills to disk (much slower).'];

    $toc = (int)smpro_dbh_n($v, 'table_open_cache'); $of = smpro_dbh_n($s, 'Table_open_cache_overflows');
    $rows[] = ['label' => 'Table-open cache', 'now' => number_format($toc) . ($of > 0 ? ' — overflowing' : ''),
        'used_pct' => null, 'ideal' => 'high enough that it does not overflow',
        'status' => $of > 0 ? 'watch' : 'good',
        'what' => 'How many table handles stay open. Overflow ⇒ table files are closed and reopened on almost every query.'];

    $slow = (($v['slow_query_log'] ?? 'OFF') === 'ON');
    $rows[] = ['label' => 'Slow-query log', 'now' => $slow ? 'ON (> ' . rtrim(rtrim((string)($v['long_query_time'] ?? '?'), '0'), '.') . 's)' : 'OFF',
        'used_pct' => null, 'ideal' => 'ON, threshold 1–2s',
        'status' => $slow ? 'good' : 'watch',
        'what' => 'Records statements slower than the threshold so you can find and fix them. Off ⇒ slowness is invisible.'];

    if (isset($v['query_cache_type'])) {
        $qc = ($v['query_cache_type'] !== 'OFF' && (int)smpro_dbh_n($v, 'query_cache_size') > 0);
        $rows[] = ['label' => 'Query cache', 'now' => $qc ? 'ON · ' . smpro_dbh_bytes_h(smpro_dbh_n($v, 'query_cache_size')) : 'OFF',
            'used_pct' => null, 'ideal' => 'OFF on a busy multi-core server',
            'status' => $qc ? 'watch' : 'good',
            'what' => 'Legacy result cache; it locks the table on every read AND write, so it usually slows a busy server (MySQL 8 removed it).'];
    }
    return $rows;
}

/* ---------------- writes: reversible dynamic tunables + guarded kill ---------------- */
/* Previous-value store so every dynamic fix has a real one-click UNDO (nothing here is destructive, but this makes "reversible" literal). */
function smpro_dbh_prev_file() { return SMPRO_VARLIB . '/dbh_tuning_prev.json'; }
function smpro_dbh_prev_read() { $d = @is_file(smpro_dbh_prev_file()) ? json_decode((string)@file_get_contents(smpro_dbh_prev_file()), true) : []; return is_array($d) ? $d : []; }
function smpro_dbh_prev_write($k, $val) {
    $d = smpro_dbh_prev_read(); $d[$k] = $val; $f = smpro_dbh_prev_file();
    @is_dir(dirname($f)) || @mkdir(dirname($f), 0700, true);
    if (@file_put_contents($f, json_encode($d, JSON_UNESCAPED_SLASHES), LOCK_EX) !== false) @chmod($f, 0600);
}
/** Restore a previously-applied dynamic fix to the exact value it had before. */
function smpro_dbh_revert($which) {
    if (!smpro_dbh_available()) return ['ok' => false, 'msg' => 'No local MySQL/MariaDB is reachable.'];
    $p = smpro_dbh_prev_read();
    if (empty($p[$which])) return ['ok' => false, 'msg' => 'Nothing recorded to undo for this setting.'];
    $pp = $p[$which];
    if ($which === 'enable_slowlog') {
        $on = (strtoupper((string)($pp['slow_query_log'] ?? 'OFF')) === 'ON' || (string)($pp['slow_query_log'] ?? '') === '1');
        smpro_dbh_q('SET GLOBAL slow_query_log=' . ($on ? 'ON' : 'OFF'), 8);
        if (isset($pp['long_query_time'])) smpro_dbh_q('SET GLOBAL long_query_time=' . (float)$pp['long_query_time'], 8);
        $msg = '↩ Restored the slow-query log to its previous state (' . ($on ? 'ON' : 'OFF') . ').';
    } elseif ($which === 'bump_tmp') {
        smpro_dbh_q('SET GLOBAL tmp_table_size=' . (int)$pp['tmp_table_size'], 8);
        smpro_dbh_q('SET GLOBAL max_heap_table_size=' . (int)$pp['max_heap_table_size'], 8);
        $msg = '↩ Restored temp-table sizes to ' . smpro_dbh_bytes_h(min((int)$pp['tmp_table_size'], (int)$pp['max_heap_table_size'])) . '.';
    } elseif ($which === 'bump_table_cache' || $which === 'rec:table_open_cache') {
        smpro_dbh_q('SET GLOBAL table_open_cache=' . (int)$pp['table_open_cache'], 8);
        $msg = '↩ Restored table_open_cache to ' . number_format((int)$pp['table_open_cache']) . '.';
    } elseif ($which === 'rec:tmp_table_size') {
        smpro_dbh_q('SET GLOBAL tmp_table_size=' . (int)$pp['tmp_table_size'], 8);
        smpro_dbh_q('SET GLOBAL max_heap_table_size=' . (int)$pp['max_heap_table_size'], 8);
        $msg = '↩ Restored temp-table sizes to ' . smpro_dbh_bytes_h(min((int)$pp['tmp_table_size'], (int)$pp['max_heap_table_size'])) . '.';
    } elseif ($which === 'rec:innodb_buffer_pool_size') {
        smpro_dbh_q('SET GLOBAL innodb_buffer_pool_size=' . (int)$pp['innodb_buffer_pool_size'], 20);
        $msg = '↩ Restored the InnoDB buffer pool to ' . smpro_dbh_bytes_h((int)$pp['innodb_buffer_pool_size']) . '.';
    } else {
        return ['ok' => false, 'msg' => 'Unknown setting.'];
    }
    if (function_exists('smpro_audit')) smpro_audit('dbhealth_revert', ['which' => $which]);
    return ['ok' => true, 'msg' => $msg];
}

/** Apply a SAFE, reversible, dynamic (no-restart) tunable. Returns {ok,msg}. */
function smpro_dbh_apply($action) {
    if (!smpro_dbh_available()) return ['ok' => false, 'msg' => 'No local MySQL/MariaDB is reachable.'];
    $v = smpro_dbh_vars();
    if ($action === 'enable_slowlog') {
        smpro_dbh_prev_write('enable_slowlog', ['slow_query_log' => ($v['slow_query_log'] ?? 'OFF'), 'long_query_time' => ($v['long_query_time'] ?? '10')]);
        smpro_dbh_q('SET GLOBAL slow_query_log=ON', 8);
        $lqt = (float)($v['long_query_time'] ?? 10);
        if ($lqt >= 10 || $lqt <= 0) smpro_dbh_q('SET GLOBAL long_query_time=2', 8);
        $now = strtoupper(trim(smpro_dbh_q('SELECT @@global.slow_query_log', 6)));
        $ok = ($now === '1' || $now === 'ON');
        if (function_exists('smpro_audit')) smpro_audit('dbhealth_fix', ['action' => $action, 'ok' => $ok]);
        $file = trim(smpro_dbh_q('SELECT @@global.slow_query_log_file', 6));
        return ['ok' => $ok, 'undo' => $ok ? 'enable_slowlog' : '', 'from' => 'OFF', 'to' => 'ON (2s)', 'msg' => $ok
            ? '✅ Slow-query log enabled (records queries slower than 2s). Log file: ' . ($file ?: '(server default)') . '.'
            . "\n\nWhat changed: slow_query_log OFF → ON, long_query_time → 2s. Nothing was deleted and no data was touched, so there is no backup to make — it is a live tuning switch. To make it permanent add \"slow_query_log=1\" and \"long_query_time=2\" under [mysqld] in my.cnf; otherwise it reverts on the next MySQL restart, or press Undo."
            : 'Could not enable the slow-query log (permission or read-only variable).'];
    }
    if ($action === 'bump_tmp') {
        $fromA = (int)smpro_dbh_n($v, 'tmp_table_size'); $fromB = (int)smpro_dbh_n($v, 'max_heap_table_size');
        smpro_dbh_prev_write('bump_tmp', ['tmp_table_size' => $fromA, 'max_heap_table_size' => $fromB]);
        $target = 64 * 1024 * 1024;
        smpro_dbh_q('SET GLOBAL tmp_table_size=' . $target, 8);
        smpro_dbh_q('SET GLOBAL max_heap_table_size=' . $target, 8);
        $a = (int)trim(smpro_dbh_q('SELECT @@global.tmp_table_size', 6));
        $b = (int)trim(smpro_dbh_q('SELECT @@global.max_heap_table_size', 6));
        $ok = ($a >= $target && $b >= $target);
        if (function_exists('smpro_audit')) smpro_audit('dbhealth_fix', ['action' => $action, 'ok' => $ok, 'tmp' => $a, 'heap' => $b]);
        return ['ok' => $ok, 'undo' => $ok ? 'bump_tmp' : '', 'from' => smpro_dbh_bytes_h(min($fromA, $fromB)), 'to' => '64M', 'msg' => $ok
            ? '✅ In-memory temp-table limit raised to 64M so fewer temp tables spill to disk (applies to NEW connections).'
            . "\n\nWhat changed: tmp_table_size & max_heap_table_size " . smpro_dbh_bytes_h(min($fromA, $fromB)) . ' → 64M. These are size limits, not data — nothing was deleted, so there is no backup to make. Persist with "tmp_table_size=64M" and "max_heap_table_size=64M" under [mysqld] in my.cnf; otherwise it reverts on restart, or press Undo.'
            : 'Set was accepted but read back lower than expected — a hard-coded my.cnf value may cap it.'];
    }
    if ($action === 'bump_table_cache') {
        $cur = (int)smpro_dbh_n($v, 'table_open_cache');
        smpro_dbh_prev_write('bump_table_cache', ['table_open_cache' => $cur]);
        $target = min(16000, max($cur * 2, 4000));
        smpro_dbh_q('SET GLOBAL table_open_cache=' . $target, 8);
        $now = (int)trim(smpro_dbh_q('SELECT @@global.table_open_cache', 6));
        $ok = ($now >= $target);
        if (function_exists('smpro_audit')) smpro_audit('dbhealth_fix', ['action' => $action, 'ok' => $ok, 'from' => $cur, 'to' => $now]);
        return ['ok' => $ok, 'undo' => $ok ? 'bump_table_cache' : '', 'from' => number_format($cur), 'to' => number_format($now), 'msg' => $ok
            ? '✅ Table-open cache raised so tables stay open instead of being reopened constantly.'
            . "\n\nWhat changed: table_open_cache " . number_format($cur) . ' → ' . number_format($now) . ". It is a cache size, not data — nothing was deleted, so there is no backup to make. Persist with \"table_open_cache=" . $target . '" under [mysqld] in my.cnf; otherwise it reverts on restart, or press Undo.'
            : 'Could not raise table_open_cache.'];
    }
    if ($action === 'grow_buffer_pool') {
        // Findings-card entry point for the undersized-pool finding. Delegates to the existing guarded
        // recommendation path (mirror of apply_rec's 'slow_query_log' delegation): same free-RAM refusal,
        // same prev-value Undo ('rec:innodb_buffer_pool_size'), same audit - no new write path.
        return smpro_dbh_apply_rec('innodb_buffer_pool_size');
    }
    return ['ok' => false, 'msg' => 'Unknown action.'];
}

/** Kill just the running STATEMENT on a thread (KILL QUERY keeps the session). Refuses internal/replication threads. */
function smpro_dbh_kill_query($id) {
    $id = (int)$id;
    if ($id < 1) return ['ok' => false, 'msg' => 'Invalid thread id.'];
    if (!smpro_dbh_available()) return ['ok' => false, 'msg' => 'No local MySQL/MariaDB is reachable.'];
    $t = null; foreach (smpro_dbh_processlist() as $r) if ($r['id'] === $id) { $t = $r; break; }
    if (!$t) return ['ok' => false, 'msg' => 'Thread not found (it may have finished already).'];
    $u = strtolower(trim($t['user']));
    if (in_array($u, ['system user', 'event_scheduler', 'unauthenticated user', ''], true))
        return ['ok' => false, 'msg' => 'Refused: internal MySQL thread (' . ($t['user'] ?: 'system') . ') is never killed.'];
    if (strcasecmp($t['command'], 'Binlog Dump') === 0 || stripos($t['state'], 'master') !== false || stripos($t['state'], 'slave') !== false || stripos($t['state'], 'replica') !== false)
        return ['ok' => false, 'msg' => 'Refused: replication thread.'];
    if (strcasecmp($t['command'], 'Sleep') === 0)
        return ['ok' => false, 'msg' => 'That thread is idle (Sleep) — there is no running query to kill.'];
    smpro_dbh_q('KILL QUERY ' . $id, 6);
    usleep(350000);
    $still = false;
    foreach (smpro_dbh_processlist() as $r) if ($r['id'] === $id && strcasecmp($r['command'], 'Sleep') !== 0 && $r['info'] !== '' && $r['time'] >= 1) { $still = true; break; }
    if (function_exists('smpro_audit')) smpro_audit('dbhealth_kill_query', ['id' => $id, 'user' => $t['user'], 'db' => $t['db'], 'time' => $t['time'], 'killed' => !$still]);
    return ['ok' => !$still, 'msg' => $still
        ? 'Sent KILL QUERY to thread ' . $id . ', but it is still running (it may be in an un-interruptible phase, e.g. rollback).'
        : '✅ Killed the running query on thread ' . $id . '. The connection stayed open.'];
}
