<?php
/**
 * modules/database-cleanup.php — Database Injection Cleanup.
 *
 * Imunify360 DETECTS malicious content injected into databases (wp_posts,
 * wp_options, etc.) but often cannot precisely clean it without risking the
 * legitimate content. This tool lists those DB injections, lets you INSPECT the
 * exact row value (binary-safe via HEX), shows the malicious snippets it would
 * strip, and applies a precise clean — backing up the original value first
 * (restorable). Every mutation is POST + CSRF + root + audit. Read-only on GET.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

define('SMPRO_DBC_BACKUP', '/home/backup/detections/db');
define('SMPRO_DBC_REPORTS', SMPRO_VARLIB . '/reports/db_cleanup');
define('SMPRO_DBC_STATUS',  SMPRO_VARLIB . '/cache/db_status.json');

/* ---------------- persisted row statuses (so a re-check / clean survives reloads) ---------------- */
function smpro_db_status_load() {
    $j = is_file(SMPRO_DBC_STATUS) ? json_decode((string)@file_get_contents(SMPRO_DBC_STATUS), true) : null;
    return is_array($j) ? $j : [];
}
function smpro_db_status_save($map) {
    @is_dir(dirname(SMPRO_DBC_STATUS)) || @mkdir(dirname(SMPRO_DBC_STATUS), 0700, true);
    @file_put_contents(SMPRO_DBC_STATUS, json_encode($map, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE), LOCK_EX);
    @chmod(SMPRO_DBC_STATUS, 0600);
}
/** Merge classification/clean results into the cache (key => [state,snips,ts]). */
function smpro_db_status_merge(array $entries) {
    $m = smpro_db_status_load();
    foreach ($entries as $key => $e) $m[$key] = ['state' => $e['state'], 'snips' => (int)($e['snips'] ?? 0), 'ts' => time()];
    smpro_db_status_save($m);
}

/* ---------------- ignored findings (hidden from the list; persisted so they never re-appear) ---------------- */
function smpro_db_ignore_file() { return SMPRO_VARLIB . '/reports/db_ignored.json'; }
/** Map of ignored row-keys ("db|table|field|row" => 1). */
function smpro_db_ignored() {
    $d = @is_file(smpro_db_ignore_file()) ? json_decode((string)@file_get_contents(smpro_db_ignore_file()), true) : null;
    return (is_array($d) && isset($d['keys']) && is_array($d['keys'])) ? array_fill_keys(array_map('strval', $d['keys']), 1) : [];
}
function smpro_db_set_ignore($key, $ignore) {
    $key = (string)$key;
    if (!preg_match('#^[A-Za-z0-9_]+\|[A-Za-z0-9_]+\|[A-Za-z0-9_]+\|\d+$#', $key)) return false;   // db|table|field|row
    $ig = array_keys(smpro_db_ignored());
    if ($ignore) { if (!in_array($key, $ig, true)) $ig[] = $key; } else $ig = array_values(array_diff($ig, [$key]));
    $f = smpro_db_ignore_file(); @is_dir(dirname($f)) || @mkdir(dirname($f), 0700, true);
    $t = $f . '.tmp';
    if (@file_put_contents($t, json_encode(['keys' => array_values($ig)], JSON_PRETTY_PRINT), LOCK_EX) === false) return false;
    @chmod($t, 0600); return @rename($t, $f);
}

/* ---------------- file/code analysis: is the linked file a web-shell, or a legit file with a vuln? ---------------- */
/** Turn a smpro_fx_deepfile() result into a plain verdict: MALICIOUS shell vs a legitimate (possibly vulnerable) file. */
function smpro_db_file_verdict(array $deep) {
    if (empty($deep['exists'])) return ['label' => 'File not found', 'cls' => 'gray', 'text' => 'The file no longer exists on disk — it may already have been removed or was in a temporary path.'];
    if (!empty($deep['is_link'])) return ['label' => 'Symlink — not followed', 'cls' => 'warn', 'text' => 'This path is a symbolic link (→ ' . ($deep['link_target'] ?: '?') . '). On shared hosting a symlink into another account is itself an attack; do not follow it blindly.'];
    $band = (string)($deep['band'] ?? 'clean');
    $fams = (array)($deep['families_seen'] ?? []);
    $obf  = in_array('obfusc', $fams, true); $exec = in_array('exec', $fams, true);
    if (in_array($band, ['high', 'critical'], true))
        return ['label' => 'Likely a WEB-SHELL / BACKDOOR', 'cls' => 'danger',
                'text' => 'The code shows backdoor characteristics (' . implode(', ', array_slice((array)($deep['contributing_signals'] ?? []), 0, 6)) . '). Treat this file as malicious: quarantine it, then clean the DB injection it produced.'];
    if ($band === 'medium')
        return ['label' => 'SUSPICIOUS — review the code', 'cls' => 'warn',
                'text' => 'Some risky signals (' . implode(', ', array_slice((array)($deep['contributing_signals'] ?? []), 0, 6)) . ') but not conclusive. Open the file and read the flagged sections before deciding.'];
    if ($exec && !$obf)
        return ['label' => 'Looks LEGITIMATE — a normal application file', 'cls' => 'good',
                'text' => 'No backdoor or obfuscation signatures — this reads as a real application file (framework-like code). If a DB injection came through it, the app (plugin/theme/CMS) most likely has a VULNERABILITY that was exploited — update/patch it. The file itself is not a shell, so do not delete it blindly.'];
    return ['label' => 'No malware signatures found', 'cls' => 'good', 'text' => 'No web-shell characteristics were detected in this file.'];
}

/** Server-side status badge (mirrors the JS statusBadge). */
function smpro_db_status_badge($st, $snips = 0) {
    switch ($st) {
        case 'live':    return '<span class="b red">&#128308; Live — ' . (int)$snips . ' spam snippet' . ($snips == 1 ? '' : 's') . '</span>';
        case 'spam':    return '<span class="b amber">&#128465; Spam post — whole page</span>';
        case 'clean':   return '<span class="b green">&#9989; Clean (stale entry)</span>';
        case 'cleaned': return '<span class="b green">&#9989; Cleaned</span>';
        case 'deleted': return '<span class="b gray">&#9898; Row removed</span>';
        case 'gone':    return '<span class="b gray">cleared</span>';
        default:        return '<span class="b gray">— not checked</span>';
    }
}

/* ---------------- mysql access (root via /root/.my.cnf) ---------------- */
function smpro_db_cli() { foreach (['/usr/bin/mariadb', '/usr/bin/mysql', 'mysql'] as $b) if (is_executable($b) || $b === 'mysql') return $b; return 'mysql'; }
/**
 * Root auth flag. The WHM CGI does not run with HOME=/root, so the mysql client
 * cannot find /root/.my.cnf on its own — we point it there explicitly so DB
 * access works regardless of the environment. Must be the FIRST client option.
 */
function smpro_db_defaults() { return is_readable('/root/.my.cnf') ? ' --defaults-extra-file=/root/.my.cnf' : ''; }
function smpro_db_ident($s) { return (bool)preg_match('/^[A-Za-z0-9_]+$/', (string)$s); }
/** Run a SQL statement as root, return raw stdout (errors suppressed). */
function smpro_db_q($sql, $t = 20) {
    return (string)@shell_exec('timeout ' . (int)$t . ' ' . smpro_db_cli() . smpro_db_defaults() . ' -N --batch -e ' . escapeshellarg($sql) . ' 2>/dev/null');
}
/** Primary-key column of a table (cached). Falls back to a common id column. */
function smpro_db_pk($db, $table) {
    static $c = [];
    if (!smpro_db_ident($db) || !smpro_db_ident($table)) return '';
    $k = "$db.$table"; if (isset($c[$k])) return $c[$k];
    $out = trim(smpro_db_q("SELECT COLUMN_NAME FROM information_schema.STATISTICS WHERE TABLE_SCHEMA='$db' AND TABLE_NAME='$table' AND INDEX_NAME='PRIMARY' ORDER BY SEQ_IN_INDEX LIMIT 1"));
    if (smpro_db_ident($out)) return $c[$k] = $out;
    // fallback: pick a common single-column id if it exists (covers cases where PRIMARY lookup is blocked/empty)
    $cols = array_filter(array_map('trim', explode("\n", smpro_db_q("SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='$db' AND TABLE_NAME='$table'"))));
    $lc = array_change_key_case(array_flip($cols), CASE_LOWER);
    foreach (['id', 'option_id', 'meta_id', 'comment_id', 'term_id', 'umeta_id'] as $cand) {
        if (isset($lc[$cand])) { foreach ($cols as $col) if (strtolower($col) === $cand) return $c[$k] = $col; }
    }
    return $c[$k] = '';
}
/** Read a single column value (binary-safe via HEX). Returns string|null. */
function smpro_db_read($db, $table, $field, $pk, $row) {
    if (!smpro_db_ident($db) || !smpro_db_ident($table) || !smpro_db_ident($field) || !smpro_db_ident($pk)) return null;
    $row = (int)$row;
    $hex = trim(smpro_db_q("SELECT HEX(`$field`) FROM `$db`.`$table` WHERE `$pk`=$row LIMIT 1", 25));
    if ($hex === '' || !preg_match('/^[0-9A-Fa-f]*$/', $hex)) return null;
    return @hex2bin($hex);
}

/* ---------------- injection list (from Imunify history) ---------------- */
function smpro_db_bin() { return is_executable('/usr/bin/imunify360-agent') ? '/usr/bin/imunify360-agent' : (is_executable('/usr/local/bin/imunify360-agent') ? '/usr/local/bin/imunify360-agent' : ''); }
function smpro_db_family($sig) { if (preg_match('/SMW-[A-Z]+-\d+-(.+?)-\d+$/', (string)$sig, $m)) return $m[1]; return (string)$sig; }
/** Current DB injections Imunify flagged as still present (event=found), deduped. Cached per request. */
function smpro_db_injections($scope = '') {
    static $cache = [];
    if (array_key_exists($scope, $cache)) return $cache[$scope];
    $rows = [];
    $bin = smpro_db_bin();
    if ($bin !== '') {                                  // Level 1 — Imunify malware history (if Imunify is installed)
        // The Imunify malware list is expensive — cache the raw JSON for 90s so navigating
        // to/within this page doesn't re-run a slow query each time (was a 60s page hang).
        // Root-only 0700 cache dir (NOT world-writable /tmp) — prevents a local user pre-planting a symlink
        // that the root file_put_contents would follow (CWE-59). Matches analytics-reports.php.
        $cf = (defined('SMPRO_CACHE') ? SMPRO_CACHE : (SMPRO_VARLIB . '/cache')) . '/dbinj.json';
        @is_dir(dirname($cf)) || @mkdir(dirname($cf), 0700, true);
        $raw = (is_file($cf) && (time() - (int)@filemtime($cf)) < 90) ? (string)@file_get_contents($cf) : '';
        if ($raw === '') {
            $raw = (string)@shell_exec('timeout 30 ' . escapeshellarg($bin) . ' malware history list --limit 4000 --json 2>/dev/null');
            if (trim($raw) !== '') { @file_put_contents($cf, $raw, LOCK_EX); @chmod($cf, 0600); }
        }
        $j = json_decode($raw, true); $items = is_array($j) ? ($j['items'] ?? []) : [];
        $byKey = [];
        foreach ($items as $r) {
            if (($r['resource_type'] ?? '') !== 'db') continue;
            $acct = (string)($r['file_user'] ?? $r['file_owner'] ?? '');
            if ($scope !== '' && $acct !== $scope) continue;
            $db = (string)($r['db_name'] ?? ''); $tbl = (string)($r['table_name'] ?? ''); $fld = (string)($r['table_field'] ?? ''); $rid = (int)($r['table_row_inf'] ?? 0);
            if ($db === '' || $tbl === '' || $fld === '') continue;
            $key = "$db|$tbl|$fld|$rid";
            $ct = (int)($r['ctime'] ?? 0);
            if (!isset($byKey[$key]) || $ct >= $byKey[$key]['ctime']) {
                $byKey[$key] = ['db'=>$db,'table'=>$tbl,'field'=>$fld,'row'=>$rid,'account'=>$acct,
                    'app'=>(string)($r['app_name'] ?? ''), 'path'=>(string)($r['path'] ?? ''),
                    'family'=>smpro_db_family($r['signature_id'] ?? ''), 'event'=>(string)($r['event'] ?? ''), 'ctime'=>$ct, 'source'=>'imunify'];
            }
        }
        $rows = array_values(array_filter($byKey, fn($r) => $r['event'] === 'found'));
    }
    // Level 2 — merge findings from the plugin's own deep scan (works with OR without Imunify), deduped by key.
    $seen = []; foreach ($rows as $r0) $seen[$r0['db'].'|'.$r0['table'].'|'.$r0['field'].'|'.(int)$r0['row']] = 1;
    foreach (smpro_db_native_load() as $nr) {
        if ($scope !== '' && (string)($nr['account'] ?? '') !== $scope) continue;
        $k = $nr['db'].'|'.$nr['table'].'|'.$nr['field'].'|'.(int)$nr['row'];
        if (isset($seen[$k])) continue; $seen[$k] = 1;
        $rows[] = $nr;
    }
    usort($rows, fn($a, $b) => ($b['ctime'] ?? 0) <=> ($a['ctime'] ?? 0));
    return $cache[$scope] = $rows;
}

/* ---------------- Level 2: plugin-native deep scan (independent of Imunify) ---------------- */
function smpro_db_native_file() { return SMPRO_VARLIB . '/reports/db_native.json'; }
/** Load persisted native-scan findings (validated to the injection-row shape). */
function smpro_db_native_load() {
    $d = @is_file(smpro_db_native_file()) ? json_decode((string)@file_get_contents(smpro_db_native_file()), true) : null;
    $rows = (is_array($d) && isset($d['rows']) && is_array($d['rows'])) ? $d['rows'] : [];
    $out = [];
    foreach ($rows as $r) {
        if (empty($r['db']) || empty($r['table']) || empty($r['field'])) continue;
        if (!smpro_db_ident($r['db']) || !smpro_db_ident($r['table']) || !smpro_db_ident($r['field'])) continue;
        $out[] = ['db'=>(string)$r['db'],'table'=>(string)$r['table'],'field'=>(string)$r['field'],'row'=>(int)($r['row'] ?? 0),
                  'account'=>(string)($r['account'] ?? ''),'app'=>'', 'path'=>'', 'family'=>(string)($r['family'] ?? 'native'),
                  'event'=>'found','ctime'=>(int)($r['ctime'] ?? 0),'source'=>'native'];
    }
    return $out;
}
function smpro_db_native_save($rows, $meta = []) {
    $f = smpro_db_native_file(); @is_dir(dirname($f)) || @mkdir(dirname($f), 0700, true);
    $t = $f . '.tmp';
    if (@file_put_contents($t, json_encode(['meta'=>$meta, 'rows'=>array_values($rows)], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE), LOCK_EX) !== false) { @chmod($t, 0600); @rename($t, $f); }
}
/** Drop remediated rows (keys "db|table|field|row") from the deep-scan cache so they don't re-appear on reload. */
function smpro_db_native_remove(array $keys) {
    if (!$keys || !@is_file(smpro_db_native_file())) return;
    $drop = array_fill_keys(array_map('strval', $keys), 1);
    $kept = [];
    foreach (smpro_db_native_load() as $r) {
        $k = $r['db'] . '|' . $r['table'] . '|' . $r['field'] . '|' . (int)$r['row'];
        if (!isset($drop[$k])) $kept[] = ['db'=>$r['db'],'table'=>$r['table'],'field'=>$r['field'],'row'=>(int)$r['row'],'account'=>$r['account'],'family'=>$r['family'],'ctime'=>(int)$r['ctime']];
    }
    $d = json_decode((string)@file_get_contents(smpro_db_native_file()), true);
    smpro_db_native_save($kept, is_array($d) ? ($d['meta'] ?? []) : []);
}
/** System schemas we never scan/clean. */
function smpro_db_is_system_schema($db) { return in_array(strtolower((string)$db), ['information_schema','mysql','performance_schema','sys','phpmyadmin','roundcube','horde','modsec','cphulkd','eximstats','leechprotect','whmxfer'], true); }
/** All non-system databases on the server. */
function smpro_db_all_databases() {
    $out = []; foreach (array_filter(array_map('trim', explode("\n", smpro_db_q("SHOW DATABASES", 30)))) as $db) if ($db !== '' && smpro_db_ident($db) && !smpro_db_is_system_schema($db)) $out[] = $db; return $out;
}
/** cPanel system users (for DB→owner resolution). */
function smpro_db_cpanel_users() { static $u = null; if ($u !== null) return $u; $u = []; foreach (glob('/var/cpanel/users/*') ?: [] as $f) { $b = basename($f); if ($b !== '' && $b[0] !== '.') $u[$b] = 1; } return $u; }
/** Owner of a cPanel DB — the longest cPanel username that prefixes "<user>_". '' if unknown. */
function smpro_db_owner($db) {
    $users = smpro_db_cpanel_users(); $best = '';
    foreach (array_keys($users) as $u) { if (strpos($db, $u . '_') === 0 && strlen($u) > strlen($best)) $best = $u; }
    return $best;
}
/** Databases owned by one cPanel account (name prefixed with "<acct>_", plus an exact match). */
function smpro_db_user_databases($acct) {
    if (!preg_match('/^[A-Za-z0-9._-]+$/', (string)$acct)) return [];
    $out = []; foreach (smpro_db_all_databases() as $db) if ($db === $acct || strpos($db, $acct . '_') === 0) $out[] = $db; return $out;
}
/** Text-ish columns of a table + the table's single-column primary key. Returns [pk, [cols...]]. */
function smpro_db_scan_columns($db, $table) {
    $pk = smpro_db_pk($db, $table); if ($pk === '') return ['', []];
    $cols = [];
    $rows = array_filter(array_map('trim', explode("\n", smpro_db_q(
        "SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='$db' AND TABLE_NAME='$table' "
      . "AND DATA_TYPE IN ('text','mediumtext','longtext','tinytext','varchar','char')", 20))));
    foreach ($rows as $c) if (smpro_db_ident($c)) $cols[] = $c;
    return [$pk, $cols];
}
/**
 * Deep native scan: find injected rows directly in MySQL (server-wide, or one account's DBs). Bounded + read-only.
 * Candidate rows are pre-filtered in SQL by backdoor markers, then confirmed with smpro_db_analyze(). Persists the
 * findings so the SAME clean/backup/restore pipeline (via smpro_db_injections) can act on them. Returns a summary.
 */
function smpro_db_native_scan($scope) {
    $deadline = time() + 55; $CAP = 3000;
    $acct = '';
    if (strpos((string)$scope, 'user:') === 0) $acct = substr($scope, 5);
    $dbs = $acct !== '' ? smpro_db_user_databases($acct) : smpro_db_all_databases();
    $markers = ['<script', '<iframe', '<?php', '<?=', 'eval('];      // high-signal backdoor pre-filter (analyzer confirms)
    $findings = []; $scannedDbs = 0; $scannedTables = 0; $ownCache = [];
    foreach ($dbs as $db) {
        if (time() > $deadline || count($findings) >= $CAP) break;
        $owner = $acct !== '' ? $acct : smpro_db_owner($db);
        $ownDomains = $ownCache[$owner] ?? ($ownCache[$owner] = smpro_db_account_domains($owner));
        $scannedDbs++;
        $tables = array_filter(array_map('trim', explode("\n", smpro_db_q("SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA='$db' AND TABLE_TYPE='BASE TABLE'", 20))));
        foreach ($tables as $table) {
            if (time() > $deadline || count($findings) >= $CAP) break;
            if (!smpro_db_ident($table)) continue;
            [$pk, $cols] = smpro_db_scan_columns($db, $table);
            if ($pk === '' || !$cols) continue;
            $scannedTables++;
            // WordPress posts table: never re-flag posts that are already TRASHED (remediated) — otherwise a
            // trashed spam post keeps re-appearing on every scan because its content is unchanged.
            $hasStatus = false; foreach ($cols as $cc) if (strcasecmp($cc, 'post_status') === 0) { $hasStatus = true; break; }
            $extra = (preg_match('/_?posts$/i', $table) && $hasStatus) ? " AND post_status <> 'trash'" : '';
            foreach ($cols as $col) {
                if (time() > $deadline || count($findings) >= $CAP) break;
                $where = [];
                foreach ($markers as $mk) $where[] = "`$col` LIKE " . "'%" . str_replace(['\\','%','_','\''], ['\\\\','\\%','\\_','\\\''], $mk) . "%'";
                $sql = "SELECT `$pk`,LEFT(`$col`,200000) FROM `$db`.`$table` WHERE (" . implode(' OR ', $where) . ")" . $extra . " LIMIT 300";
                // read raw (tab-separated pk<TAB>value); values may contain newlines — use a sentinel-free bounded read
                $raw = smpro_db_q($sql, 25);
                if ($raw === '') continue;
                foreach (explode("\n", $raw) as $line) {
                    $tab = strpos($line, "\t"); if ($tab === false) continue;
                    $rid = (int)substr($line, 0, $tab); $val = substr($line, $tab + 1);
                    if ($val === '') continue;
                    $a = smpro_db_analyze($val, $ownDomains);
                    if (empty($a['changed'])) continue;                 // only confirmed backdoor/script/iframe/eval snippets
                    $findings[] = ['db'=>$db,'table'=>$table,'field'=>$col,'row'=>$rid,'account'=>$owner,'family'=>$a['snippets'][0]['type'] ?? 'native','ctime'=>time()];
                    if (count($findings) >= $CAP) break;
                }
            }
        }
    }
    // de-dupe by key (a row can match on multiple columns only once per column; keys already unique per col)
    $uniq = []; foreach ($findings as $f) $uniq[$f['db'].'|'.$f['table'].'|'.$f['field'].'|'.$f['row']] = $f;
    $rows = array_values($uniq);
    smpro_db_native_save($rows, ['scope'=>$scope, 'at'=>time(), 'dbs'=>$scannedDbs, 'tables'=>$scannedTables, 'found'=>count($rows),
        'partial'=>(time() > $deadline || count($findings) >= $CAP)]);
    return ['ok'=>true, 'dbs'=>$scannedDbs, 'tables'=>$scannedTables, 'found'=>count($rows),
        'partial'=>(time() > $deadline || count($findings) >= $CAP), 'scope'=>$acct !== '' ? ('account ' . $acct) : 'whole server'];
}
/** Verify a target (db,table,field,row) is in the current injection list — safety gate (uses the cached full list). */
function smpro_db_is_flagged($db, $table, $field, $row) {
    static $idx = null;
    if ($idx === null) { $idx = []; foreach (smpro_db_injections() as $r) $idx[$r['db'].'|'.$r['table'].'|'.$r['field'].'|'.(int)$r['row']] = $r; }
    return $idx[$db.'|'.$table.'|'.$field.'|'.(int)$row] ?? null;
}

/* ---------------- account → own domains (for external-link detection) ---------------- */
/** Domains owned by an account (from /etc/userdomains), incl. bare + www stripped. */
function smpro_db_account_domains($account) {
    static $cache = [];
    $account = (string)$account;
    if ($account === '') return [];
    if (isset($cache[$account])) return $cache[$account];
    $out = [];
    foreach (@file('/etc/userdomains', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $line) {
        $p = strrpos($line, ':'); if ($p === false) continue;
        $dom = strtolower(trim(substr($line, 0, $p))); $usr = trim(substr($line, $p + 1));
        if ($usr !== $account || $dom === '' || $dom === '*') continue;
        $dom = preg_replace('/^www\./', '', $dom);
        $out[$dom] = 1;
    }
    return $cache[$account] = array_keys($out);
}
/** True when $host belongs to the account (its own domain or a subdomain of it). */
function smpro_db_host_is_own($host, $ownDomains) {
    $host = strtolower(preg_replace('/^www\./', '', (string)$host));
    if ($host === '') return true;                       // relative/anchor → treat as own
    foreach ($ownDomains as $d) { if ($host === $d || str_ends_with($host, '.' . $d)) return true; }
    return false;
}
/** Hosts we never treat as injected spam (common, benign embeds/CDNs). */
function smpro_db_host_is_safe($host) {
    $host = strtolower((string)$host);
    static $safe = ['w.org','wordpress.org','gmpg.org','schema.org','gravatar.com','googleapis.com',
        'gstatic.com','google.com','youtube.com','youtu.be','youtube-nocookie.com','vimeo.com',
        'facebook.com','twitter.com','x.com','instagram.com','linkedin.com','wp.com','wp.me',
        'cloudflare.com','jquery.com','bootstrapcdn.com','fontawesome.com','jsdelivr.net','unpkg.com'];
    foreach ($safe as $s) { if ($host === $s || str_ends_with($host, '.' . $s)) return true; }
    return false;
}

/* ---------------- spam-content detector (whole-page SEO spam, not a strippable snippet) ---------------- */
/** Multilingual SEO-spam keywords (casino / pharma / adult / finance / replica). */
function smpro_db_spam_terms() {
    static $t = ['casino','casinos','kasyno','kasyna','kasino','sazka','slot machine','slots','sloty','roulette','ruletka',
        'blackjack','baccarat','poker','jackpot','betting','bet365','bookmaker','bukmacher','gambling','hazard','zakłady bukmacherskie',
        'kryptowaluty','crypto casino','online casino','best casino','mostbet','1xbet','parimatch','pin-up','vulkan',
        'viagra','cialis','levitra','tadalafil','sildenafil','kamagra','pharmacy','farmacia','canadian pharmacy',
        'payday loan','quick loan','escort','escorts','call girl','porn','porno','xxx','sex video','replica watch','rolex replica',
        'казино','ставки','букмекер','порно','виагра'];
    return $t;
}
/** Score how spammy a value's text is: distinct terms + total occurrences. */
function smpro_db_spam_score($val) {
    $v = mb_strtolower((string)$val);
    // De-overlap the term list ONCE: drop any term that CONTAINS a shorter listed term (e.g. "casinos"
    // contains "casino", "porno" contains "porn") — the shorter term already matches the same text, so
    // keeping both double-counted one word as 2 distinct hits. Keeps detection, fixes the inflated score.
    static $terms = null;
    if ($terms === null) {
        $all = smpro_db_spam_terms();
        $terms = [];
        foreach ($all as $t) {
            $redundant = false;
            foreach ($all as $o) { if ($o !== '' && $o !== $t && mb_strpos($t, $o) !== false) { $redundant = true; break; } }
            if (!$redundant) $terms[] = $t;
        }
    }
    $hits = 0; $distinct = 0; $found = [];
    foreach ($terms as $t) {
        $c = substr_count($v, $t);
        if ($c > 0) { $distinct++; $hits += $c; if (count($found) < 6) $found[] = $t; }
    }
    return ['hits' => $hits, 'distinct' => $distinct, 'terms' => $found];
}
/** True when the value reads as a whole-page SEO-spam post (many spam terms, repeated). */
function smpro_db_is_spam_content($val) {
    $s = smpro_db_spam_score($val);
    return $s['distinct'] >= 2 && $s['hits'] >= 3;
}

/* ---------------- malicious-snippet analyzer ---------------- */
/**
 * Analyze a row value for injected malware. Detects:
 *   - backdoors:  <script>…</script>, lone <script…>, <iframe>…</iframe>, <?php…?>, eval(base64_decode/atob(…))
 *   - hidden spam blocks (display:none / off-screen divs)
 *   - external SEO-spam anchors  <a href="http(s)://EXTERNAL-HOST">…</a>  (host not owned by the account & not safe-listed)
 * Returns offset-anchored snippets so cleaning can remove EXACTLY the selected ones (precise, reversible).
 *   ['snippets'=>[ ['i'=>int,'type'=>str,'host'=>str,'off'=>int,'len'=>int,'text'=>str], … ], 'changed'=>bool, 'hash'=>md5]
 */
function smpro_db_analyze($val, $ownDomains = []) {
    $val = (string)$val;
    $hits = [];   // [off, len, type, host, text]
    $add = function ($off, $len, $type, $host = '') use (&$hits, $val) {
        if ($len <= 0) return;
        $hits[] = ['off' => $off, 'len' => $len, 'type' => $type, 'host' => $host, 'text' => substr($val, $off, $len)];
    };
    // 1) backdoor / scripting patterns — always malicious in stored content
    $backdoor = [
        ['script', '/<script\b[^>]*>.*?<\/script\s*>/is'],
        ['script', '/<script\b[^>]*\/?>/is'],
        ['iframe', '/<iframe\b[^>]*>.*?<\/iframe\s*>/is'],
        ['php',    '/<\?php\b.*?\?>/is'],
        ['php',    '/<\?=.*?\?>/is'],
        ['hidden', '/<div[^>]*style\s*=\s*("|\')[^"\']*(display\s*:\s*none|visibility\s*:\s*hidden|position\s*:\s*absolute[^"\']*(left|top)\s*:\s*-\d)[^"\']*\1[^>]*>.*?<\/div\s*>/is'],
        ['eval',   '/eval\s*\(\s*(?:base64_decode|atob)\s*\([^)]*\)\s*\)/is'],
    ];
    foreach ($backdoor as [$type, $re]) {
        if (preg_match_all($re, $val, $m, PREG_OFFSET_CAPTURE) && !empty($m[0])) {
            foreach ($m[0] as $hit) $add($hit[1], strlen($hit[0]), $type);
        }
    }
    // 2) external SEO-spam anchors — host not owned by the account and not safe-listed
    if (preg_match_all('/<a\b[^>]*\bhref\s*=\s*("|\')(.*?)\1[^>]*>.*?<\/a\s*>/is', $val, $m, PREG_OFFSET_CAPTURE)) {
        foreach ($m[0] as $idx => $hit) {
            $href = html_entity_decode($m[2][$idx][0] ?? '', ENT_QUOTES);
            if (!preg_match('#^(?:https?:)?//#i', $href)) continue;          // only absolute external URLs
            $host = strtolower((string)parse_url(preg_replace('#^//#', 'http://', $href), PHP_URL_HOST));
            if ($host === '' || smpro_db_host_is_own($host, $ownDomains) || smpro_db_host_is_safe($host)) continue;
            $add($hit[1], strlen($hit[0]), 'extlink', $host);
        }
    }
    // de-overlap: sort by offset, drop snippets contained within an earlier one
    usort($hits, fn($a, $b) => $a['off'] <=> $b['off'] ?: $b['len'] <=> $a['len']);
    $snips = []; $coverEnd = -1; $i = 0;
    foreach ($hits as $h) {
        if ($h['off'] < $coverEnd) continue;            // nested inside a prior snippet
        $coverEnd = $h['off'] + $h['len'];
        $snips[] = ['i' => $i++, 'type' => $h['type'], 'host' => $h['host'], 'off' => $h['off'], 'len' => $h['len'], 'text' => $h['text']];
    }
    return ['snippets' => $snips, 'changed' => !empty($snips), 'hash' => md5($val)];
}
/** Remove the selected snippets (by index) from the original value — exact, offset-based. */
function smpro_db_strip($val, $snippets, $selected) {
    $val = (string)$val;
    $sel = array_filter($snippets, fn($s) => in_array($s['i'], $selected, true));
    usort($sel, fn($a, $b) => $b['off'] <=> $a['off']);  // remove back-to-front so offsets stay valid
    foreach ($sel as $s) {
        if ($s['off'] >= 0 && $s['off'] + $s['len'] <= strlen($val) && substr($val, $s['off'], $s['len']) === $s['text']) {
            $val = substr_replace($val, '', $s['off'], $s['len']);
        }
    }
    return $val;
}

/* ---------------- backup + report + clean ---------------- */
function smpro_db_report($d) {
    @is_dir(SMPRO_DBC_REPORTS) || @mkdir(SMPRO_DBC_REPORTS, 0700, true);
    $id = date('Ymd_His') . '_' . substr(hash('sha256', json_encode($d) . uniqid('', true)), 0, 8);
    $d['id'] = $id; $d['at'] = date('c'); $d['ts'] = time();
    @file_put_contents(SMPRO_DBC_REPORTS . '/' . $id . '.json', json_encode($d, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE), LOCK_EX);
    @chmod(SMPRO_DBC_REPORTS . '/' . $id . '.json', 0600);
    return $id;
}
function smpro_db_reports($limit = 40) {
    $rows = [];
    foreach (glob(SMPRO_DBC_REPORTS . '/*.json') ?: [] as $f) { $j = json_decode((string)@file_get_contents($f), true); if (is_array($j)) $rows[] = $j; }
    usort($rows, fn($a, $b) => ($b['ts'] ?? 0) <=> ($a['ts'] ?? 0));
    return array_slice($rows, 0, $limit);
}

/* ---------------- restore index: every clean/trash logs enough to UNDO it with one click ---------------- */
function smpro_db_restore_file() { return SMPRO_VARLIB . '/reports/db_restore.json'; }
/** Append a restore entry. Filenames alone can't be parsed (db/table names contain '_'), so we store the exact
 *  db/table/field/pk/row + the backup file path here. Keeps the most recent 500. */
function smpro_db_restore_log(array $e) {
    $f = smpro_db_restore_file(); @is_dir(dirname($f)) || @mkdir(dirname($f), 0700, true);
    $d = @is_file($f) ? json_decode((string)@file_get_contents($f), true) : null;
    $list = (is_array($d) && isset($d['items']) && is_array($d['items'])) ? $d['items'] : [];
    $e['id'] = date('Ymd_His') . '_' . substr(hash('sha256', json_encode($e) . uniqid('', true)), 0, 8);
    $e['ts'] = time();
    array_unshift($list, $e); $list = array_slice($list, 0, 500);
    $t = $f . '.tmp';
    if (@file_put_contents($t, json_encode(['items' => $list], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE), LOCK_EX) !== false) { @chmod($t, 0600); @rename($t, $f); }
    return $e['id'];
}
function smpro_db_restore_list($limit = 60) {
    $f = smpro_db_restore_file();
    $d = @is_file($f) ? json_decode((string)@file_get_contents($f), true) : null;
    $list = (is_array($d) && isset($d['items']) && is_array($d['items'])) ? $d['items'] : [];
    foreach ($list as &$e) { $e['backup_exists'] = !empty($e['backup']) && @is_file($e['backup']); } unset($e);
    return array_slice($list, 0, $limit);
}
/** Look up one restore entry by id. */
function smpro_db_restore_get($id) { foreach (smpro_db_restore_list(500) as $e) if (($e['id'] ?? '') === $id) return $e; return null; }
/** UNDO a clean/trash from its backup. Verifies the write took effect (re-read). Returns ['ok','msg']. */
function smpro_db_restore_apply($id) {
    $e = smpro_db_restore_get($id);
    if (!$e) return ['ok' => false, 'msg' => 'Restore entry not found.'];
    $db = (string)($e['db'] ?? ''); $table = (string)($e['table'] ?? ''); $pk = (string)($e['pk'] ?? ''); $row = (int)($e['row'] ?? 0);
    if (!smpro_db_ident($db) || !smpro_db_ident($table) || !smpro_db_ident($pk)) return ['ok' => false, 'msg' => 'Invalid identifiers in the restore entry.'];
    $kind = (string)($e['kind'] ?? 'clean');
    if ($kind === 'trash') {
        $prev = (string)($e['prev_status'] ?? 'publish');
        if (!preg_match('/^[a-z0-9_-]{1,32}$/i', $prev)) $prev = 'publish';
        $sql = "UPDATE `$db`.`$table` SET post_status='" . $prev . "' WHERE `$pk`=$row LIMIT 1";
        @shell_exec('timeout 30 ' . smpro_db_cli() . smpro_db_defaults() . ' -e ' . escapeshellarg($sql) . ' 2>&1');
        $now = trim(smpro_db_q("SELECT post_status FROM `$db`.`$table` WHERE `$pk`=$row LIMIT 1"));
        $ok = ($now === $prev);
        $key = $db . '|' . $table . '|' . (string)($e['field'] ?? 'post_content') . '|' . $row;
        if ($ok) { smpro_db_status_merge([$key => ['state' => 'live', 'snips' => 0]]); smpro_audit('db_restore', ['kind' => 'trash', 'db' => $db, 'table' => $table, 'row' => $row]); }
        return ['ok' => $ok, 'msg' => $ok ? ('Restored post status to "' . $prev . '" — the post is live again.') : ('Restore did not take effect (status is now "' . $now . '").')];
    }
    // clean: write the backed-up ORIGINAL value back into the column
    $field = (string)($e['field'] ?? '');
    if (!smpro_db_ident($field)) return ['ok' => false, 'msg' => 'Invalid column in the restore entry.'];
    $bak = (string)($e['backup'] ?? '');
    if (strpos($bak, SMPRO_DBC_BACKUP . '/') !== 0 || !@is_file($bak)) return ['ok' => false, 'msg' => 'The backup file is missing — cannot restore this one.'];
    $orig = (string)@file_get_contents($bak);
    $hex = bin2hex($orig);
    $sql = "UPDATE `$db`.`$table` SET `$field`=UNHEX('" . $hex . "') WHERE `$pk`=$row LIMIT 1";
    @shell_exec('timeout 30 ' . smpro_db_cli() . smpro_db_defaults() . ' -e ' . escapeshellarg($sql) . ' 2>&1');
    $after = smpro_db_read($db, $table, $field, $pk, $row);
    $ok = ($after !== null && $after === $orig);
    if ($ok) {
        $key = $db . '|' . $table . '|' . $field . '|' . $row;
        smpro_db_status_merge([$key => ['state' => 'live', 'snips' => 0]]);   // show it as a finding again (it's the original injected value)
        smpro_audit('db_restore', ['kind' => 'clean', 'db' => $db, 'table' => $table, 'field' => $field, 'row' => $row, 'bytes' => strlen($orig)]);
    }
    return ['ok' => $ok, 'msg' => $ok ? ('Restored the original ' . strlen($orig) . '-byte value back into the row. Note: this brings back the ORIGINAL (injected) content — re-clean it if that was not intended.') : 'Restore did not take effect (the row did not change).'];
}
/** Show WHAT WAS REMOVED for a restore-log entry: reads the backed-up original value and, for a clean, re-runs the
 *  analyzer to list the exact malicious snippets that were stripped (+ a preview). For a trash, shows the backed-up
 *  post content + the status it had. Read-only — never changes the database. */
function smpro_db_restore_view($id) {
    $e = smpro_db_restore_get($id);
    if (!$e) return ['ok' => false, 'msg' => 'Restore entry not found.'];
    $bak = (string)($e['backup'] ?? '');
    if (strpos($bak, SMPRO_DBC_BACKUP . '/') !== 0 || !@is_file($bak)) return ['ok' => false, 'msg' => 'The backup file for this action is missing — cannot show what was removed.'];
    $raw = (string)@file_get_contents($bak);
    $loc = ($e['db'] ?? '') . ' › ' . ($e['table'] ?? '') . ' › ' . ($e['field'] ?? '') . ' #' . (int)($e['row'] ?? 0);
    $cut = fn($s, $n) => mb_strlen($s, '8bit') > $n ? mb_strcut($s, 0, $n) . ' …(+' . (strlen($s) - $n) . ' B more)' : $s;
    $when = date('Y-m-d H:i', (int)($e['ts'] ?? 0));
    if (($e['kind'] ?? '') === 'trash') {
        // the trash backup file is: "original post_status=<status>\n\n<content>"
        $body = $raw; $prev = (string)($e['prev_status'] ?? 'publish');
        if (preg_match('/^original post_status=(\S+)\r?\n\r?\n(.*)$/s', $raw, $m)) { $prev = $m[1]; $body = $m[2]; }
        return ['ok' => true, 'kind' => 'trash', 'when' => $when, 'location' => $loc, 'account' => (string)($e['account'] ?? ''),
                'prev_status' => $prev, 'len' => strlen($body), 'preview' => $cut($body, 8000)];
    }
    // clean: re-analyze the ORIGINAL (backed-up) value → the snippets it lists ARE what was stripped
    $own   = function_exists('smpro_db_account_domains') ? smpro_db_account_domains((string)($e['account'] ?? '')) : [];
    $a     = smpro_db_analyze($raw, $own);
    $clean = smpro_db_strip($raw, $a['snippets'], array_map(fn($s) => $s['i'], $a['snippets']));
    $snips = array_map(fn($s) => ['type' => $s['type'], 'host' => $s['host'], 'len' => $s['len'], 'text' => $cut($s['text'], 1600)], $a['snippets']);
    return ['ok' => true, 'kind' => 'clean', 'when' => $when, 'location' => $loc, 'account' => (string)($e['account'] ?? ''),
            'orig_len' => (int)($e['orig_len'] ?? strlen($raw)), 'clean_len' => (int)($e['clean_len'] ?? strlen($clean)),
            'removed_bytes' => max(0, ((int)($e['orig_len'] ?? strlen($raw))) - ((int)($e['clean_len'] ?? strlen($clean)))),
            'snippets' => $snips, 'snippet_count' => count($snips), 'orig_preview' => $cut($raw, 8000)];
}

/** Core: back up the original value to a file + UPDATE the row. No report (used by batches). */
function smpro_db_clean_row_core($db, $table, $field, $pk, $row, $orig, $clean, $account) {
    if (!smpro_db_ident($db) || !smpro_db_ident($table) || !smpro_db_ident($field) || !smpro_db_ident($pk)) return ['ok'=>false,'msg'=>'Invalid identifier.','backup'=>''];
    $row = (int)$row;
    $dir = SMPRO_DBC_BACKUP . '/' . preg_replace('/[^a-zA-Z0-9._-]/', '', $account);
    @is_dir($dir) || @mkdir($dir, 0700, true); @chmod(SMPRO_DBC_BACKUP, 0700);
    $bak = $dir . '/' . date('Ymd_His') . '_' . $db . '_' . $table . '_' . $field . '_' . $row . '.txt';
    @file_put_contents($bak, $orig, LOCK_EX); @chmod($bak, 0600);
    $hex = bin2hex($clean);
    $sql = "UPDATE `$db`.`$table` SET `$field`=UNHEX('" . $hex . "') WHERE `$pk`=$row LIMIT 1";
    $out = (string)@shell_exec('timeout 30 ' . smpro_db_cli() . smpro_db_defaults() . ' -e ' . escapeshellarg($sql) . ' 2>&1');
    // VERIFY the write actually took effect — re-read the row and confirm it now equals the cleaned value.
    // ("no 'error' in output" is NOT proof: a write that matches 0 rows, or a read-only grant, prints nothing.)
    $after = smpro_db_read($db, $table, $field, $pk, $row);
    $ok = ($after !== null && $after === $clean);
    $err = $ok ? '' : (trim(mb_substr($out, 0, 160)) ?: 'the row did not change after the UPDATE (0 rows affected or the write was blocked)');
    if ($ok) smpro_db_restore_log(['kind'=>'clean','account'=>$account,'db'=>$db,'table'=>$table,'field'=>$field,'pk'=>$pk,'row'=>$row,'backup'=>$bak,'orig_len'=>strlen($orig),'clean_len'=>strlen($clean)]);
    else @unlink($bak);   // failed clean → the backup is a no-op, don't clutter the restore list
    return ['ok'=>$ok,'backup'=>$bak,'removed'=>strlen($orig)-strlen($clean),'err'=>$err];
}
/** Single-row clean WITH a report (used by the per-row "Remove selected & clean" button). */
function smpro_db_clean_apply($db, $table, $field, $pk, $row, $orig, $clean, $account, $nsnip = 0) {
    $c = smpro_db_clean_row_core($db, $table, $field, $pk, $row, $orig, $clean, $account);
    if (isset($c['msg'])) return ['ok'=>false,'msg'=>$c['msg']];
    $ok = $c['ok'];
    $rid = smpro_db_report(['action'=>'db_clean','account'=>$account,'db'=>$db,'table'=>$table,'field'=>$field,'pk'=>$pk,'row'=>$row,
        'orig_len'=>strlen($orig),'clean_len'=>strlen($clean),'removed_bytes'=>strlen($orig)-strlen($clean),'snippets'=>(int)$nsnip,'backup'=>$c['backup'],'ok'=>$ok,
        'actor'=>function_exists('smpro_current_actor')?smpro_current_actor():'root']);
    smpro_audit('db_clean', ['account'=>$account,'db'=>$db,'table'=>$table,'row'=>$row,'ok'=>$ok,'snippets'=>(int)$nsnip,'removed'=>strlen($orig)-strlen($clean)]);
    return ['ok'=>$ok,'msg'=>$ok?('Cleaned. Removed '.(strlen($orig)-strlen($clean)).' bytes · backup kept · report #'.$rid):'UPDATE failed: '.$c['err'],'report'=>$rid,'backup'=>$c['backup']];
}
/** Clean ONE batch of row-keys ("db|table|field|row"). No reports. Returns running counts. */
function smpro_db_clean_batch(array $keys) {
    $cleaned = 0; $skipped = 0; $bytes = 0; $stat = [];
    foreach ($keys as $key) {
        $p = explode('|', (string)$key);
        if (count($p) !== 4) { $skipped++; continue; }
        [$db, $table, $field, $row] = $p; $row = (int)$row;
        $flag = smpro_db_is_flagged($db, $table, $field, $row);
        if (!$flag) { $skipped++; continue; }
        $pk = smpro_db_pk($db, $table);
        $val = $pk !== '' ? smpro_db_read($db, $table, $field, $pk, $row) : null;
        if ($val === null) { $skipped++; continue; }
        $a = smpro_db_analyze($val, smpro_db_account_domains($flag['account']));
        if (!$a['changed']) { $skipped++; continue; }
        $clean = smpro_db_strip($val, $a['snippets'], array_map(fn($s) => $s['i'], $a['snippets']));
        if ($clean === $val) { $skipped++; continue; }
        $c = smpro_db_clean_row_core($db, $table, $field, $pk, $row, $val, $clean, $flag['account']);
        if (!empty($c['ok'])) { $cleaned++; $bytes += strlen($val) - strlen($clean); $stat[$key] = ['state'=>'cleaned']; } else $skipped++;
    }
    if ($stat) { smpro_db_status_merge($stat); smpro_db_native_remove(array_keys($stat)); }   // remember + drop cleaned rows from the deep-scan cache
    return ['cleaned'=>$cleaned, 'skipped'=>$skipped, 'removed_bytes'=>$bytes];
}

/* ---------------- trash spam POSTS (whole-page SEO spam) — reversible ---------------- */
/** Set a spam post's status to 'trash' (WordPress-reversible). Backs up its content + original status. */
function smpro_db_trash_post($db, $table, $pk, $row, $account) {
    if (!smpro_db_ident($db) || !smpro_db_ident($table) || !smpro_db_ident($pk)) return ['ok'=>false,'msg'=>'Invalid identifier.'];
    if (!preg_match('/_?posts$/i', $table)) return ['ok'=>false,'msg'=>'Not a posts table — cannot trash.'];
    $row = (int)$row;
    $cur = trim(smpro_db_q("SELECT post_status FROM `$db`.`$table` WHERE `$pk`=$row LIMIT 1"));
    if ($cur === '') return ['ok'=>false,'msg'=>'Post no longer exists.'];
    if ($cur === 'trash') return ['ok'=>true,'msg'=>'Already trashed.','prev'=>'trash'];
    // back up the full content + original status so it can be restored
    $val = smpro_db_read($db, $table, 'post_content', $pk, $row);
    $dir = SMPRO_DBC_BACKUP . '/' . preg_replace('/[^a-zA-Z0-9._-]/', '', $account);
    @is_dir($dir) || @mkdir($dir, 0700, true); @chmod(SMPRO_DBC_BACKUP, 0700);
    $bak = $dir . '/' . date('Ymd_His') . "_{$db}_{$table}_TRASH_{$row}.txt";
    @file_put_contents($bak, "original post_status={$cur}\n\n" . (string)$val, LOCK_EX); @chmod($bak, 0600);
    $sql = "UPDATE `$db`.`$table` SET post_status='trash' WHERE `$pk`=$row LIMIT 1";
    $out = (string)@shell_exec('timeout 30 ' . smpro_db_cli() . smpro_db_defaults() . ' -e ' . escapeshellarg($sql) . ' 2>&1');
    // VERIFY: re-read post_status — it must now be 'trash' (a silent 0-row / blocked write must NOT report success).
    $now = trim(smpro_db_q("SELECT post_status FROM `$db`.`$table` WHERE `$pk`=$row LIMIT 1"));
    $ok = ($now === 'trash');
    if ($ok) smpro_db_restore_log(['kind'=>'trash','account'=>$account,'db'=>$db,'table'=>$table,'field'=>'post_content','pk'=>$pk,'row'=>$row,'backup'=>$bak,'prev_status'=>$cur]);
    return ['ok'=>$ok,'prev'=>$cur,'msg'=>$ok?'Trashed (restorable from WP trash / backup).':('UPDATE did not take effect (status still "'.$now.'"): '.trim(mb_substr($out,0,140)))];
}
/** Trash a batch of selected spam posts. Only acts on rows that are flagged AND spam content AND a posts table. */
function smpro_db_trash_batch(array $keys) {
    $trashed = 0; $skipped = 0; $done = [];
    foreach ($keys as $key) {
        $p = explode('|', (string)$key);
        if (count($p) !== 4) { $skipped++; continue; }
        [$db, $table, $field, $row] = $p; $row = (int)$row;
        if (!preg_match('/_?posts$/i', $table)) { $skipped++; continue; }
        $flag = smpro_db_is_flagged($db, $table, $field, $row);
        if (!$flag) { $skipped++; continue; }
        $pk = smpro_db_pk($db, $table);
        $val = $pk !== '' ? smpro_db_read($db, $table, $field, $pk, $row) : null;
        if ($val === null) { $skipped++; continue; }
        if (!smpro_db_is_spam_content($val)) { $skipped++; continue; }   // safety: only trash confirmed-spam content
        $r = smpro_db_trash_post($db, $table, $pk, $row, $flag['account']);
        if (!empty($r['ok'])) { $trashed++; $done[] = $key; } else $skipped++;
    }
    if ($done) { smpro_db_status_merge(array_fill_keys($done, ['state'=>'deleted'])); smpro_db_native_remove($done); }   // trashed → won't re-appear
    return ['trashed'=>$trashed, 'skipped'=>$skipped];
}

/* ---------------- full-database backup (into the client's home) + bulk fix ---------------- */
/** Resolve an account's home directory (getent → /home/<acct> fallback). */
function smpro_db_account_home($account) {
    if (!preg_match('/^[a-z0-9._-]+$/i', (string)$account)) return '';
    $h = trim((string)@shell_exec('getent passwd ' . escapeshellarg($account) . ' 2>/dev/null | cut -d: -f6'));
    if ($h !== '' && is_dir($h)) return $h;
    return is_dir(smpro_user_home($account)) ? smpro_user_home($account) : '';
}
/** mysqldump a whole database into the client's home folder (owned by the client, 0600). Returns [ok,path,bytes,msg]. */
function smpro_db_dump_to_home($db, $account) {
    if (!smpro_db_ident($db)) return ['ok'=>false,'msg'=>'Invalid database name.'];
    $home = smpro_db_account_home($account);
    if ($home === '') return ['ok'=>false,'msg'=>"Could not locate the home folder for '$account'."];
    $dir = $home . '/smpro_db_backups';
    @is_dir($dir) || @mkdir($dir, 0700, true);
    $path = $dir . '/' . $db . '_' . date('Ymd_His') . '.sql.gz';
    $dump = is_executable('/usr/bin/mysqldump') ? '/usr/bin/mysqldump' : 'mysqldump';
    $cmd = 'timeout 600 ' . $dump . smpro_db_defaults() . ' --single-transaction --quick --skip-lock-tables --default-character-set=binary '
         . escapeshellarg($db) . ' 2>/dev/null | gzip -c > ' . escapeshellarg($path) . ' 2>/dev/null';
    @shell_exec($cmd);
    $bytes = (int)@filesize($path);
    if ($bytes < 40) { @unlink($path); return ['ok'=>false,'msg'=>'mysqldump produced no output (DB empty or dump failed).']; }
    // hand ownership to the account so it lives in their space, lock down perms
    @chmod($path, 0600);
    @shell_exec('chown ' . escapeshellarg($account . ':' . $account) . ' ' . escapeshellarg($path) . ' 2>/dev/null');
    return ['ok'=>true,'path'=>$path,'bytes'=>$bytes,'msg'=>'Backup saved'];
}
/**
 * Fix one database: full mysqldump backup into the client's home, then auto-clean
 * EVERY flagged row in that DB (strip all detected snippets). Writes one report.
 */
function smpro_db_fix_database($db, $account) {
    $rows = array_values(array_filter(smpro_db_injections($account), fn($r) => $r['db'] === $db));
    if (!$rows) return ['ok'=>false,'msg'=>'No flagged rows for this database (re-scan).'];
    $dump = smpro_db_dump_to_home($db, $account);
    if (!$dump['ok']) return ['ok'=>false,'msg'=>'Aborted — backup failed: ' . $dump['msg']];
    $own = smpro_db_account_domains($account);
    $cleaned = 0; $skipped = 0; $snips = 0; $bytes = 0; $details = [];
    foreach ($rows as $r) {
        $pk = smpro_db_pk($r['db'], $r['table']);
        $val = $pk !== '' ? smpro_db_read($r['db'], $r['table'], $r['field'], $pk, $r['row']) : null;
        if ($val === null) { $skipped++; continue; }
        $a = smpro_db_analyze($val, $own);
        if (!$a['changed']) { $skipped++; continue; }
        $clean = smpro_db_strip($val, $a['snippets'], array_map(fn($s) => $s['i'], $a['snippets']));
        if ($clean === $val) { $skipped++; continue; }
        $hex = bin2hex($clean);
        $sql = "UPDATE `{$r['db']}`.`{$r['table']}` SET `{$r['field']}`=UNHEX('$hex') WHERE `$pk`=" . (int)$r['row'] . " LIMIT 1";
        $out = (string)@shell_exec('timeout 30 ' . smpro_db_cli() . smpro_db_defaults() . ' -e ' . escapeshellarg($sql) . ' 2>&1');
        if (stripos($out, 'error') !== false) { $skipped++; continue; }
        $cleaned++; $snips += count($a['snippets']); $bytes += strlen($val) - strlen($clean);
        if (count($details) < 200) $details[] = $r['table'] . '.' . $r['field'] . '#' . $r['row'];
    }
    $rid = smpro_db_report(['action'=>'db_fix','account'=>$account,'db'=>$db,'rows_flagged'=>count($rows),
        'rows_cleaned'=>$cleaned,'rows_skipped'=>$skipped,'snippets'=>$snips,'removed_bytes'=>$bytes,
        'backup'=>$dump['path'],'backup_bytes'=>$dump['bytes'],'locations'=>$details,'ok'=>$cleaned>0,
        'actor'=>function_exists('smpro_current_actor')?smpro_current_actor():'root']);
    smpro_audit('db_fix', ['account'=>$account,'db'=>$db,'cleaned'=>$cleaned,'skipped'=>$skipped,'removed'=>$bytes,'backup'=>basename($dump['path'])]);
    return ['ok'=>$cleaned>0,'cleaned'=>$cleaned,'skipped'=>$skipped,'snippets'=>$snips,'removed_bytes'=>$bytes,
        'backup'=>basename($dump['path']),'backup_bytes'=>$dump['bytes'],'report'=>$rid,
        'msg'=>($cleaned>0?"Backed up DB ($db) to the client's home, then cleaned $cleaned row(s)":'Backup saved, but nothing needed cleaning')
            . ($skipped?" · $skipped skipped":'') . ' · report #' . $rid];
}

/* =====================================================================
 * CONTROLLER
 * ===================================================================== */
$reqMethod = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? getenv('REQUEST_METHOD') ?: 'GET'));

/* ---- POST: Level 2 — run the plugin-native deep scan (server-wide or one account); READ-ONLY ---- */
if ($reqMethod === 'POST' && ($_POST['dbc_action'] ?? '') === 'deep_scan') {
    smpro_require_valid_csrf('dbc_act'); smpro_require_root();
    header('Content-Type: application/json');
    @set_time_limit(120); @ignore_user_abort(true);
    $mode = ($_POST['scan_scope'] ?? 'server') === 'account' ? 'account' : 'server';
    $acct = strtolower(trim((string)($_POST['account'] ?? '')));
    if ($mode === 'account') {
        if (!preg_match('/^[a-z0-9._-]{1,32}$/', $acct) || !is_file('/var/cpanel/users/' . $acct)) { echo json_encode(['ok'=>false,'msg'=>'Enter a valid cPanel account to scan.']); exit; }
        $scope = 'user:' . $acct;
    } else { $scope = ''; }
    $r = smpro_db_native_scan($scope);
    smpro_audit('db_deep_scan', ['scope'=>$scope, 'dbs'=>$r['dbs'], 'tables'=>$r['tables'], 'found'=>$r['found']]);
    $msg = 'Scanned ' . (int)$r['dbs'] . ' database(s) / ' . (int)$r['tables'] . ' table(s) across ' . $r['scope'] . ' — found ' . (int)$r['found'] . ' injected row(s)'
         . (!empty($r['partial']) ? ' (hit the time/size limit — run again to continue)' : '') . '. They now appear in the list below tagged NATIVE; inspect and clean them with the same backup-first tools.';
    echo json_encode(['ok'=>true, 'found'=>(int)$r['found'], 'partial'=>!empty($r['partial']), 'msg'=>$msg], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit;
}

/* ---- POST: clear the stored native-scan findings ---- */
if ($reqMethod === 'POST' && ($_POST['dbc_action'] ?? '') === 'deep_scan_clear') {
    smpro_require_valid_csrf('dbc_act'); smpro_require_root();
    header('Content-Type: application/json');
    @is_file(smpro_db_native_file()) && @unlink(smpro_db_native_file());
    smpro_audit('db_deep_scan_clear', []);
    echo json_encode(['ok'=>true, 'msg'=>'Cleared the deep-scan results.'], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit;
}

/* ---- POST: ignore / restore a finding so it does not show again (persisted) ---- */
if ($reqMethod === 'POST' && in_array(($_POST['dbc_action'] ?? ''), ['ignore', 'unignore'], true)) {
    smpro_require_valid_csrf('dbc_act'); smpro_require_root();
    header('Content-Type: application/json');
    $key = (string)($_POST['key'] ?? '');
    $ok  = smpro_db_set_ignore($key, $_POST['dbc_action'] === 'ignore');
    smpro_audit('db_' . $_POST['dbc_action'], ['key' => $key, 'ok' => $ok]);
    echo json_encode(['ok' => $ok, 'msg' => $ok ? ($_POST['dbc_action'] === 'ignore' ? 'Hidden — this finding will not show again.' : 'Restored.') : 'Could not update (invalid key).'], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit;
}

/* ---- POST: analyze a FILE's code — is it a web-shell/backdoor, or a legit file with a vulnerability? (read-only) ---- */
if ($reqMethod === 'POST' && ($_POST['dbc_action'] ?? '') === 'analyze_file') {
    smpro_require_valid_csrf('dbc_act'); smpro_require_root();
    header('Content-Type: application/json');
    if (!function_exists('smpro_fx_deepfile') || !function_exists('smpro_fx_scope')) { echo json_encode(['ok' => false, 'msg' => 'File-analysis engine unavailable.']); exit; }
    $path = trim((string)($_POST['path'] ?? ''));
    if (!preg_match('#^/home/([^/]+)/.+#', $path, $m) || strpos($path, '/..') !== false) { echo json_encode(['ok' => false, 'msg' => 'Refused: only a real file under /home/<account>/ can be analyzed.']); exit; }
    $acct = $m[1];
    if (!@is_file($path) && !@is_link($path)) { echo json_encode(['ok' => false, 'msg' => 'File not found: ' . $path]); exit; }
    $scope = smpro_fx_scope($acct);
    if (!$scope) { echo json_encode(['ok' => false, 'msg' => 'Could not resolve the cPanel account for this path.']); exit; }
    $deep = smpro_fx_deepfile($path, $scope);
    $verdict = smpro_db_file_verdict($deep);
    smpro_audit('db_analyze_file', ['path' => $path, 'band' => $deep['band'] ?? '', 'acct' => $acct]);
    echo json_encode(['ok' => true, 'path' => $path, 'verdict' => $verdict, 'deep' => [
        'band' => $deep['band'], 'score' => $deep['score'], 'size' => (int)$deep['size'], 'owner_ok' => $deep['owner_ok'],
        'entropy' => round((float)$deep['entropy'], 2), 'families' => array_values((array)$deep['families_seen']),
        'tokens' => array_slice((array)$deep['tokens'], 0, 12), 'nested_chain' => (bool)$deep['nested_chain'],
        'timestomp' => $deep['timestomp'], 'in_webroot' => (bool)$deep['in_webroot'],
        'mtime' => $deep['mtime'] ? date('Y-m-d H:i', (int)$deep['mtime']) : '', 'signals' => array_values((array)$deep['contributing_signals']),
        'sha256' => substr((string)$deep['sha256'], 0, 16),
    ]], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit;
}

/* ---- POST: RESTORE a clean/trash from its backup (undo an accidental action) ---- */
if ($reqMethod === 'POST' && ($_POST['dbc_action'] ?? '') === 'restore') {
    smpro_require_valid_csrf('dbc_act'); smpro_require_root();
    header('Content-Type: application/json');
    $id = preg_replace('/[^0-9A-Za-z_]/', '', (string)($_POST['id'] ?? ''));
    if ($id === '') { echo json_encode(['ok' => false, 'msg' => 'No restore id.']); exit; }
    echo json_encode(smpro_db_restore_apply($id), JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit;
}

/* ---- POST: VIEW what was removed for a restore-log entry (read-only) ---- */
if ($reqMethod === 'POST' && ($_POST['dbc_action'] ?? '') === 'restore_view') {
    smpro_require_valid_csrf('dbc_act'); smpro_require_root();
    header('Content-Type: application/json');
    $id = preg_replace('/[^0-9A-Za-z_]/', '', (string)($_POST['id'] ?? ''));
    if ($id === '') { echo json_encode(['ok' => false, 'msg' => 'No id.']); exit; }
    smpro_audit('db_restore_view', ['id' => $id]);
    echo json_encode(smpro_db_restore_view($id), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit;
}

/* ---- POST: inspect a flagged row (read-only, returns snippet analysis) ---- */
if ($reqMethod === 'POST' && ($_POST['dbc_action'] ?? '') === 'inspect') {
    smpro_require_valid_csrf('dbc_act'); smpro_require_root();
    header('Content-Type: application/json');
    $db = (string)($_POST['db'] ?? ''); $table = (string)($_POST['table'] ?? ''); $field = (string)($_POST['field'] ?? ''); $row = (int)($_POST['row'] ?? 0);
    $flag = smpro_db_is_flagged($db, $table, $field, $row);
    if (!$flag) { echo json_encode(['ok'=>false,'msg'=>'This row is not in the current Imunify injection list (re-scan).']); exit; }
    $pk = smpro_db_pk($db, $table);
    if ($pk === '') { echo json_encode(['ok'=>false,'msg'=>'Could not resolve the table primary key.']); exit; }
    $val = smpro_db_read($db, $table, $field, $pk, $row);
    if ($val === null) { echo json_encode(['ok'=>false,'msg'=>'Could not read the row (already cleaned/removed, or DB inaccessible).']); exit; }
    $own = smpro_db_account_domains($flag['account']);
    $a = smpro_db_analyze($val, $own);
    $cut = fn($s, $n) => mb_strlen($s, '8bit') > $n ? mb_strcut($s, 0, $n) . ' …(+' . (strlen($s) - $n) . ' B more)' : $s;
    $clean = smpro_db_strip($val, $a['snippets'], array_map(fn($s) => $s['i'], $a['snippets']));
    $snips = array_map(fn($s) => ['i'=>$s['i'],'type'=>$s['type'],'host'=>$s['host'],'len'=>$s['len'],'text'=>$cut($s['text'],1400)], $a['snippets']);
    $sp = smpro_db_spam_score($val);
    $isSpamPost = !$a['changed'] && $sp['distinct'] >= 2 && $sp['hits'] >= 3;
    // remember the status for the list (so it survives reload)
    smpro_db_status_merge([$db.'|'.$table.'|'.$field.'|'.$row => ['state' => $a['changed'] ? 'live' : ($isSpamPost ? 'spam' : 'clean'), 'snips' => count($a['snippets'])]]);
    smpro_audit('db_inspect', ['db'=>$db,'table'=>$table,'row'=>$row,'snippets'=>count($snips)]);
    echo json_encode(['ok'=>true,'pk'=>$pk,'len'=>strlen($val),'clean_len'=>strlen($clean),'changed'=>$a['changed'],
        'hash'=>$a['hash'],'own_domains'=>$own,'snippets'=>$snips,'snippet_count'=>count($a['snippets']),
        'spam_post'=>$isSpamPost,'spam_terms'=>$sp['terms'],'is_post'=>(bool)preg_match('/_?posts$/i',$table),
        'preview'=>$cut($val,6000)], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit;
}

/* ---- POST: clean a flagged row (backup + UPDATE only the SELECTED snippets) ---- */
if ($reqMethod === 'POST' && ($_POST['dbc_action'] ?? '') === 'clean') {
    smpro_require_valid_csrf('dbc_act'); smpro_require_root();
    header('Content-Type: application/json');
    $db = (string)($_POST['db'] ?? ''); $table = (string)($_POST['table'] ?? ''); $field = (string)($_POST['field'] ?? ''); $row = (int)($_POST['row'] ?? 0);
    $expectHash = (string)($_POST['hash'] ?? '');
    $sel = array_values(array_filter(array_map('intval', explode(',', (string)($_POST['sel'] ?? ''))), fn($x) => $x >= 0 || $x === 0));
    if ((string)($_POST['sel'] ?? '') === '' || $sel === []) { echo json_encode(['ok'=>false,'msg'=>'No snippets selected to remove.']); exit; }
    $flag = smpro_db_is_flagged($db, $table, $field, $row);
    if (!$flag) { echo json_encode(['ok'=>false,'msg'=>'Row not in the injection list (re-scan).']); exit; }
    $pk = smpro_db_pk($db, $table);
    $val = $pk !== '' ? smpro_db_read($db, $table, $field, $pk, $row) : null;
    if ($val === null) { echo json_encode(['ok'=>false,'msg'=>'Could not read the row to clean.']); exit; }
    // guard: row must be unchanged since inspection (offsets are valid only for that exact value)
    if ($expectHash !== '' && md5($val) !== $expectHash) { echo json_encode(['ok'=>false,'msg'=>'The row changed since you inspected it. Re-inspect and try again.']); exit; }
    $own = smpro_db_account_domains($flag['account']);
    $a = smpro_db_analyze($val, $own);
    if (!$a['changed']) { echo json_encode(['ok'=>false,'msg'=>'Nothing matched the malware patterns in this row — it may already be clean. Use “Remove from list” in Imunify if it is a leftover entry.']); exit; }
    $clean = smpro_db_strip($val, $a['snippets'], $sel);
    if ($clean === $val) { echo json_encode(['ok'=>false,'msg'=>'Selected snippets no longer match the current row content. Re-inspect.']); exit; }
    echo json_encode(smpro_db_clean_apply($db, $table, $field, $pk, $row, $val, $clean, $flag['account'], count($sel)), JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit;
}

/* ---- POST: clean ONE batch of rows (chunked bulk cleaning, drives the progress bar) ---- */
if ($reqMethod === 'POST' && ($_POST['dbc_action'] ?? '') === 'clean_batch') {
    smpro_require_valid_csrf('dbc_act'); smpro_require_root();
    header('Content-Type: application/json');
    $keys = array_slice(array_filter(array_map('trim', explode("\n", (string)($_POST['rows'] ?? '')))), 0, 50);
    if (!$keys) { echo json_encode(['ok'=>false,'msg'=>'Empty batch.']); exit; }
    echo json_encode(['ok'=>true] + smpro_db_clean_batch($keys), JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit;
}

/* ---- POST: trash ONE batch of selected SPAM POSTS (reversible, chunked) ---- */
if ($reqMethod === 'POST' && ($_POST['dbc_action'] ?? '') === 'trash_batch') {
    smpro_require_valid_csrf('dbc_act'); smpro_require_root();
    header('Content-Type: application/json');
    $keys = array_slice(array_filter(array_map('trim', explode("\n", (string)($_POST['rows'] ?? '')))), 0, 50);
    if (!$keys) { echo json_encode(['ok'=>false,'msg'=>'Empty batch.']); exit; }
    $r = smpro_db_trash_batch($keys);
    smpro_audit('db_trash', ['trashed'=>$r['trashed'],'skipped'=>$r['skipped']]);
    echo json_encode(['ok'=>true] + $r, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit;
}

/* ---- POST: classify a batch of rows (status only, NO mutation) — drives the Status column ---- */
if ($reqMethod === 'POST' && ($_POST['dbc_action'] ?? '') === 'classify_batch') {
    smpro_require_valid_csrf('dbc_act'); smpro_require_root();
    header('Content-Type: application/json');
    $keys = array_slice(array_filter(array_map('trim', explode("\n", (string)($_POST['rows'] ?? '')))), 0, 40);
    if (!$keys) { echo json_encode(['ok'=>false,'msg'=>'Empty batch.']); exit; }
    $out = [];
    foreach ($keys as $key) {
        $p = explode('|', $key);
        if (count($p) !== 4) { $out[$key] = ['state'=>'unknown','snips'=>0]; continue; }
        [$db, $table, $field, $row] = $p; $row = (int)$row;
        $flag = smpro_db_is_flagged($db, $table, $field, $row);
        if (!$flag) { $out[$key] = ['state'=>'gone','snips'=>0]; continue; }       // no longer in Imunify list
        $pk = smpro_db_pk($db, $table);
        if ($pk === '') { $out[$key] = ['state'=>'unknown','snips'=>0]; continue; }
        $val = smpro_db_read($db, $table, $field, $pk, $row);
        if ($val === null) { $out[$key] = ['state'=>'deleted','snips'=>0]; continue; } // row no longer exists
        $a = smpro_db_analyze($val, smpro_db_account_domains($flag['account']));
        if ($a['changed']) { $out[$key] = ['state'=>'live','snips'=>count($a['snippets'])]; continue; }
        $sp = smpro_db_spam_score($val);
        if ($sp['distinct'] >= 2 && $sp['hits'] >= 3) {                                  // whole-page spam, no strippable snippet
            $out[$key] = ['state'=>'spam','snips'=>0,'terms'=>$sp['terms'],'is_post'=>(bool)preg_match('/_?posts$/i',$table)];
        } else {
            $out[$key] = ['state'=>'clean','snips'=>0];
        }
    }
    smpro_db_status_merge($out);   // persist so a reload shows the same statuses
    echo json_encode(['ok'=>true,'statuses'=>$out], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit;
}

/* ---- POST: FIX a DB, phase 1 — mysqldump backup into the client's home, return the row list to clean ---- */
if ($reqMethod === 'POST' && ($_POST['dbc_action'] ?? '') === 'fixdb_backup') {
    smpro_require_valid_csrf('dbc_act'); smpro_require_root();
    header('Content-Type: application/json');
    $db = (string)($_POST['db'] ?? ''); $account = (string)($_POST['account'] ?? '');
    if (!smpro_db_ident($db)) { echo json_encode(['ok'=>false,'msg'=>'Invalid database name.']); exit; }
    $rows = array_values(array_filter(smpro_db_injections($account), fn($r) => $r['db'] === $db));
    if (!$rows) { echo json_encode(['ok'=>false,'msg'=>'This database has no flagged rows in scope (re-scan).']); exit; }
    $dump = smpro_db_dump_to_home($db, $account);
    if (!$dump['ok']) { echo json_encode(['ok'=>false,'msg'=>'Backup failed: ' . $dump['msg']]); exit; }
    smpro_audit('db_fix_backup', ['account'=>$account,'db'=>$db,'rows'=>count($rows),'backup'=>basename($dump['path'])]);
    $keys = array_map(fn($r) => $r['db'] . '|' . $r['table'] . '|' . $r['field'] . '|' . $r['row'], $rows);
    echo json_encode(['ok'=>true,'backup'=>$dump['path'],'backup_name'=>basename($dump['path']),'backup_bytes'=>$dump['bytes'],'rows'=>$keys], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit;
}

/* ---- POST: write ONE summary report at the end of a bulk operation ---- */
if ($reqMethod === 'POST' && ($_POST['dbc_action'] ?? '') === 'bulk_report') {
    smpro_require_valid_csrf('dbc_act'); smpro_require_root();
    header('Content-Type: application/json');
    $kind = (string)($_POST['kind'] ?? '');
    $action = in_array($kind, ['db_fix','db_trash','db_clean_bulk'], true) ? $kind : 'db_clean_bulk';
    $rid = smpro_db_report([
        'action'       => $action,
        'account'      => (string)($_POST['account'] ?? ''),
        'db'           => (string)($_POST['db'] ?? ''),
        'rows_flagged' => (int)($_POST['flagged'] ?? 0),
        'rows_cleaned' => (int)($_POST['cleaned'] ?? 0),
        'rows_skipped' => (int)($_POST['skipped'] ?? 0),
        'removed_bytes'=> (int)($_POST['removed_bytes'] ?? 0),
        'backup'       => (string)($_POST['backup'] ?? ''),
        'backup_bytes' => (int)($_POST['backup_bytes'] ?? 0),
        'ok'           => (int)($_POST['cleaned'] ?? 0) > 0,
        'actor'        => function_exists('smpro_current_actor') ? smpro_current_actor() : 'root',
    ]);
    smpro_audit($action, ['account'=>(string)($_POST['account'] ?? ''),'db'=>(string)($_POST['db'] ?? ''),'cleaned'=>(int)($_POST['cleaned'] ?? 0)]);
    echo json_encode(['ok'=>true,'report'=>$rid], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit;
}

/* ---- render ---- */
$scope = preg_replace('/[^a-zA-Z0-9._-]/', '', (string)($_GET['user'] ?? ''));
$csrf = smpro_csrf_generate('dbc_act');

// Render the page chrome FIRST so the page appears instantly, THEN run the (cached) Imunify
// query — previously the whole page waited up to 60s for Imunify before any HTML was sent.
smpro_layout_header('DB Cleanup');
?>
<div class="svc-kicker">Malware</div>
<h1 class="h" style="margin:2px 0 4px">Database Injection Cleanup</h1>
<p class="sub">Finds malware injected into your databases (posts, options…) on <b>two levels — Level 1: Imunify360</b> (if installed) and <b>Level 2: SM Pro's own deep scan</b> that searches the databases directly, server-wide or for one account, even without Imunify. For any finding you <b>inspect</b> the exact row, see what would be stripped, and apply a <b>precise clean</b> — the original value is backed up first and is fully restorable.</p>

<script>var DBC_CSRF=<?= json_encode($csrf) ?>;</script>
<?php
@ob_flush(); @flush();   // push the chrome to the browser before the (possibly slow) first Imunify query
$inj = smpro_db_injections($scope);
$reports = smpro_db_reports(20);
$restores = smpro_db_restore_list(60);
$byAcct = []; foreach ($inj as $r) { $byAcct[$r['account']] = ($byAcct[$r['account']] ?? 0) + 1; } arsort($byAcct);
$byTable = []; foreach ($inj as $r) { $k = $r['table'] . '.' . $r['field']; $byTable[$k] = ($byTable[$k] ?? 0) + 1; } arsort($byTable);
smpro_audit('db_cleanup_view', ['injections' => count($inj)]);
?>

<div class="db-progress-overlay" id="dbProgress" style="display:none">
  <div class="db-progress-box">
    <div class="db-progress-title" id="dbpTitle">Cleaning…</div>
    <div class="db-progress-track"><div class="db-progress-fill" id="dbpFill"></div></div>
    <div class="db-progress-meta"><span id="dbpPct">0%</span><span id="dbpCounts">0 / 0</span></div>
    <div class="db-progress-sub" id="dbpSub">Working in batches — please keep this tab open…</div>
    <button type="button" class="tp-btn db-progress-cancel" id="dbpCancel">Stop after current batch</button>
  </div>
</div>

<?php
// ---- the overview: one clickable tile per number, read from the same arrays the cards below use
$dbOv = [
  ['id' => 'db-inj', 'l' => 'DB injections (found)', 'v' => number_format(count($inj)), 'cls' => count($inj) ? 'dang' : 'good', 's' => count($inj) ? 'grouped by account below' : 'nothing flagged in scope'],
  ['id' => 'db-inj', 'l' => 'Accounts affected', 'v' => number_format(count($byAcct)), 'cls' => count($byAcct) ? 'warn' : 'muted', 's' => $scope !== '' ? ('scope: ' . $scope) : 'all accounts'],
  ['id' => 'db-inj', 'l' => 'Table.column targets', 'v' => number_format(count($byTable)), 'cls' => count($byTable) ? 'brand' : 'muted', 's' => $byTable ? ('most hit: ' . (string)array_key_first($byTable)) : '—'],
  ['id' => 'db-reports', 'l' => 'Cleans recorded', 'v' => (string)count($reports), 'cls' => 'brand', 's' => 'backups in /home/backup/detections/db'],
  ['id' => 'db-restore', 'l' => 'Restorable', 'v' => (string)count($restores), 'cls' => count($restores) ? 'good' : 'muted', 's' => count($restores) ? 'cleans / trashes you can undo' : 'nothing to undo yet'],
];
$dbOvNav = [['db-deep', '&#128269; Deep scan'], ['db-analyze', '&#128300; Analyze a file'], ['db-inj', '&#128137; Injections'], ['db-ignored', '&#128683; Ignored'], ['db-restore', '&#8634; Restore'], ['db-reports', '&#128203; Reports']];
?>
<div class="fw-kpis">
  <?php foreach ($dbOv as $k): ?>
  <a class="fw-kpi <?= $k['cls'] ?>" href="#<?= $k['id'] ?>" data-go="<?= $k['id'] ?>"><div class="l"><?= $k['l'] ?></div><div class="v"><?= smpro_h($k['v']) ?></div><div class="s"><?= smpro_h($k['s']) ?></div></a>
  <?php endforeach; ?>
</div>
<nav class="fw-nav" id="dbNav"><?php foreach ($dbOvNav as [$id, $lbl]): ?><a href="#<?= $id ?>" data-go="<?= $id ?>"><?= $lbl ?></a><?php endforeach; ?><span class="sp"></span><button type="button" class="fw-navx" id="dbOpenAll">expand all</button><button type="button" class="fw-navx" id="dbCloseAll">collapse all</button></nav>

<form method="get" action="index.cgi" class="card db-bar">
  <input type="hidden" name="page" value="database-cleanup">
  <label class="db-fld">Account filter<input class="tp-in" name="user" value="<?= smpro_h($scope) ?>" placeholder="all accounts" data-ac="accounts" autocomplete="off"></label>
  <button class="tp-btn primary" type="submit">Filter</button>
  <a class="tp-btn" href="index.cgi?page=imunify360-reports">Imunify360 Reports →</a>
</form>

<?php
$nativeMeta = null; { $nf = smpro_db_native_file(); if (@is_file($nf)) { $nd = json_decode((string)@file_get_contents($nf), true); $nativeMeta = is_array($nd) ? ($nd['meta'] ?? null) : null; } }
$nativeCount = count(array_filter($inj, fn($r) => ($r['source'] ?? '') === 'native'));
$imunifyOn = smpro_db_bin() !== '';
?>
<div class="card db-l2" id="db-deep">
  <div class="db-l2-hd"><b>&#128269; Level 2 — Deep native scan</b>
    <span class="meta"> — searches your databases directly for injected &lt;script&gt; / &lt;iframe&gt; / eval / PHP backdoors. <?= $imunifyOn ? 'Complements Imunify (Level 1) above.' : 'Works even though Imunify is not installed on this server.' ?></span>
  </div>
  <div class="db-l2-body">
    <div class="db-l2-row">
      <label class="db-l2-opt"><input type="radio" name="dbScanScope" value="server" checked> Whole server (all accounts)</label>
      <label class="db-l2-opt"><input type="radio" name="dbScanScope" value="account"> One account: <input class="tp-in" id="dbScanAcct" placeholder="cPanel user" data-ac="accounts" autocomplete="off" style="width:150px"></label>
      <button class="tp-btn primary" id="dbScanBtn" type="button">&#128269; Scan now</button>
      <?php if ($nativeCount || $nativeMeta): ?><button class="tp-btn" id="dbScanClear" type="button">Clear results</button><?php endif; ?>
    </div>
    <div class="db-l2-note">Read-only. Findings appear in the list below tagged <span class="db-tag-native">NATIVE</span> and use the same inspect &rarr; backup &rarr; precise-clean tools as Imunify findings. On a large server the scan is time-bounded — run it again to continue where it stopped.</div>
    <?php if ($nativeMeta): ?><div class="meta db-l2-last">Last deep scan: <?= smpro_h(date('M j, H:i', (int)($nativeMeta['at'] ?? 0))) ?> — <?= (int)($nativeMeta['found'] ?? 0) ?> found across <?= (int)($nativeMeta['dbs'] ?? 0) ?> database(s)<?= !empty($nativeMeta['partial']) ? ' · partial (hit the time/size limit)' : '' ?>.</div><?php endif; ?>
    <div id="dbScanMsg" class="db-l2-msg"></div>
  </div>
</div>
<script>
(function(){
  var b=document.getElementById('dbScanBtn'); if(!b)return;
  function msg(t,ok){var m=document.getElementById('dbScanMsg');if(m){m.textContent=t;m.style.color=ok?'var(--good)':'var(--dang)';}}
  b.addEventListener('click',function(){
    var scope=(document.querySelector('input[name=dbScanScope]:checked')||{}).value||'server';
    var acct=((document.getElementById('dbScanAcct')||{}).value||'').trim();
    if(scope==='account'&&!acct){msg('Enter a cPanel account, or choose Whole server.',false);return;}
    if(!confirm('Run a deep native scan of '+(scope==='account'?('account "'+acct+'"'):'ALL databases on the server')+'?\n\nRead-only — it only finds injected rows, it does not change anything. On a big server this can take up to a minute.'))return;
    var o=b.innerHTML;b.disabled=true;b.innerHTML='… scanning';msg('Scanning databases — keep this tab open…',true);
    var fd=new URLSearchParams();fd.set('dbc_action','deep_scan');fd.set('smpro_csrf',DBC_CSRF);fd.set('scan_scope',scope);fd.set('account',acct);
    fetch('index.cgi?page=database-cleanup',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'})
      .then(function(r){return r.json();}).then(function(j){b.disabled=false;b.innerHTML=o;msg((j&&j.msg)||'Done',j&&j.ok);if(j&&j.ok&&j.found>0){setTimeout(function(){location.reload();},1900);}})
      .catch(function(){b.disabled=false;b.innerHTML=o;msg('Scan request failed.',false);});
  });
  var c=document.getElementById('dbScanClear');
  if(c)c.addEventListener('click',function(){if(!confirm('Clear the stored deep-scan findings from the list below?'))return;
    var fd=new URLSearchParams();fd.set('dbc_action','deep_scan_clear');fd.set('smpro_csrf',DBC_CSRF);
    fetch('index.cgi?page=database-cleanup',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'}).then(function(r){return r.json();}).then(function(j){if(j&&j.ok)location.reload();});
  });
})();
</script>
<style>
.db-l2{margin:12px 0;border-left:4px solid var(--brand)}
.db-l2-hd{margin-bottom:10px}
.db-l2-row{display:flex;align-items:center;gap:14px;flex-wrap:wrap;margin-bottom:8px}
.db-l2-opt{display:flex;align-items:center;gap:6px;font-size:13px}
.db-l2-note{font-size:12px;color:var(--muted);line-height:1.5}
.db-l2-last{margin-top:6px;font-size:11.5px}
.db-l2-msg{margin-top:6px;font-size:12.5px;min-height:16px}
.db-tag-native{display:inline-block;background:var(--brand-bg);color:var(--brand);font-size:10px;font-weight:800;padding:1px 6px;border-radius:10px}
.db-tag-imun{display:inline-block;background:var(--card);color:var(--muted);border:1px solid var(--line);font-size:10px;font-weight:700;padding:1px 6px;border-radius:10px}
.db-path{font-size:11px;color:#7c5cff;margin-top:3px;max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.db-af{margin:12px 0;border-left:4px solid #7c3aed}
.db-af-hd{margin-bottom:10px}
.db-af-row{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:6px}
.db-af-note{font-size:11.5px;color:var(--muted)}
.db-af-result{margin-top:10px}
.db-af-verdict{border:1px solid var(--line);border-radius:12px;padding:14px 16px}
.db-af-vt{font-size:15px;font-weight:800;margin-bottom:4px}
.db-af-vx{font-size:12.5px;line-height:1.55}
.db-af-path{font-size:11.5px;color:var(--muted);margin-top:8px;word-break:break-all}
.db-af-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:8px 14px;margin-top:12px}
.db-af-grid>div{display:flex;flex-direction:column}
.db-af-grid span{font-size:10px;text-transform:uppercase;color:var(--muted);letter-spacing:.04em}
.db-af-grid b{font-size:12.5px}
.db-af-k{margin-top:10px;font-size:11.5px}.db-af-k>span{color:var(--muted);text-transform:uppercase;font-size:10px;letter-spacing:.04em}
.db-af-chip{display:inline-block;background:var(--card);border:1px solid var(--line);border-radius:20px;font-size:10.5px;padding:1px 8px;margin:2px 2px 0 0}
.db-loc-t{font-size:9px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);font-weight:700}
.db-loc-a{color:var(--muted)}
.db-loc .mono{font-size:12px}
.db-nofile{font-size:11px;color:var(--muted);margin-top:3px;font-style:italic}
</style>

<!-- ===== Analyze a file: web-shell / backdoor vs a legit file with a vulnerability ===== -->
<div class="card db-af" id="db-analyze">
  <div class="db-af-hd"><b>&#128300; Analyze a file (code)</b>
    <span class="meta"> — is a file a real web-shell/backdoor, or a legitimate file that just has a vulnerability? Paste a path, or click &#128300; Analyze on any finding that has a file.</span>
  </div>
  <div class="db-af-body">
    <div class="db-af-row">
      <input class="tp-in" id="dbAfPath" placeholder="/home/<account>/public_html/…/suspect.php" spellcheck="false" autocomplete="off" style="flex:1;min-width:260px;font-family:ui-monospace,monospace">
      <button class="tp-btn primary" id="dbAfBtn" type="button">&#128300; Analyze file</button>
    </div>
    <div class="db-af-note">Read-only — it never changes the file. Only paths under <span class="mono">/home/&lt;account&gt;/</span> are allowed.</div>
    <div id="dbAfResult" class="db-af-result"></div>
  </div>
</div>

<?php
// group injections by account → list of rows; track each account's databases
$groups = [];
$statusMap = smpro_db_status_load();   // last-known per-row statuses (persisted)
$dbIgnored = smpro_db_ignored(); $dbHidden = []; $dbFixed = 0;
foreach (array_slice($inj, 0, 1000) as $r) {
    $rk = $r['db'] . '|' . $r['table'] . '|' . $r['field'] . '|' . (int)$r['row'];
    if (isset($dbIgnored[$rk])) { if (count($dbHidden) < 300) $dbHidden[] = $r; continue; }   // ignored → hidden from the list
    // Already remediated by us (cleaned/trashed) and NOT re-detected since — hide it so Imunify's still-listed
    // history (or a stale cache) doesn't keep showing a row we already fixed. A genuinely NEW detection
    // (ctime newer than when we acted) still shows.
    $st = $statusMap[$rk] ?? null;
    if ($st && in_array($st['state'] ?? '', ['cleaned', 'deleted'], true) && (int)($st['ts'] ?? 0) >= (int)($r['ctime'] ?? 0)) { $dbFixed++; continue; }
    $groups[$r['account']][] = $r;
}
?>
<div class="card" id="db-inj" style="padding:0;overflow:hidden">
  <div class="im-head"><b>&#128137; Database injections</b><span class="meta"><?= count($inj) ?> row(s) flagged<?= $nativeCount ? (' (' . (int)$nativeCount . ' by the deep scan)') : '' ?> · grouped by account · inspect &amp; clean precisely</span></div>
  <?php if (!$inj): ?><div class="im-empty" style="color:var(--good)">&#10003; No active database injections in scope.</div>
  <?php else: ?>
  <div class="db-toolbar">
    <label class="db-allwrap"><input type="checkbox" id="dbMasterAll"> <b>Select all</b></label>
    <span class="db-selcount" id="dbSelCount">0 selected</span>
    <button class="tp-btn db-checkall" id="dbCheckAll" type="button">&#128269; Check statuses</button>
    <button class="tp-btn db-selectlive" id="dbSelectLive" type="button" style="display:none">&#9889; Select live only</button>
    <button class="tp-btn db-selectspam" id="dbSelectSpam" type="button" style="display:none">&#128465; Select spam posts</button>
    <?php /* NOT `primary`: this rewrites customer database rows in bulk. Primary-blue is reserved for safe
             actions like "Scan now" / "Analyze file", so a data-changing button must not look identical to
             them. It IS reversible (every original value is backed up and restorable), so amber rather than
             red — matching its sibling "Trash selected posts". */ ?>
    <button class="tp-btn db-cleansel" id="dbCleanSel" type="button" disabled>&#129529; Clean selected rows</button>
    <button class="tp-btn db-trashsel" id="dbTrashSel" type="button" disabled>&#128465; Trash selected posts</button>
    <span class="db-statussum" id="dbStatusSum"></span>
  </div>
  <div class="fw-pg" id="dbGrpBar"><input type="search" id="dbGrpFind" placeholder="Filter by account, database, table, column, family&hellip;"><span class="sp"></span><span class="n" id="dbGrpInfo"></span></div>
  <div class="db-tablewrap">
    <table class="smpro-table dbtbl"><thead><tr>
      <th class="db-cbcol"><input type="checkbox" id="dbHeadAll" title="select all"></th>
      <th>Location</th><th>Database</th><th>Status</th><th>Family</th><th>Detected</th><th>Action</th>
    </tr></thead><tbody>
      <?php foreach ($groups as $acct => $rows): $dbs = array_values(array_unique(array_map(fn($x)=>$x['db'], $rows))); $gid = 'g_'.substr(md5($acct),0,8); ?>
        <tr class="db-grouprow" data-gid="<?= $gid ?>">
          <td class="db-cbcol"><input type="checkbox" class="db-groupall" data-gid="<?= $gid ?>" title="select all of this account's rows"></td>
          <td colspan="6" class="db-grouphd">
            <div class="db-gh">
              <button type="button" class="db-toggle" data-gid="<?= $gid ?>" title="collapse / expand">&#9662;</button>
              <span class="db-gh-ava"><?= smpro_h(strtoupper(substr((string)($acct ?: '?'), 0, 1))) ?></span>
              <div class="db-gh-main">
                <div class="db-gh-top">
                  <b class="db-gh-name"><?= smpro_h($acct ?: '(unknown account)') ?></b>
                  <span class="db-gh-count"><?= count($rows) ?> injection<?= count($rows) == 1 ? '' : 's' ?></span>
                  <span class="db-glive" data-gid="<?= $gid ?>"></span>
                </div>
                <div class="db-gh-dbs">
                  <?php foreach (array_slice($dbs, 0, 6) as $dbn): ?><span class="db-gh-db">&#128190; <?= smpro_h($dbn) ?></span><?php endforeach; ?>
                  <?php if (count($dbs) > 6): ?><span class="db-gh-db">+<?= count($dbs) - 6 ?> more</span><?php endif; ?>
                </div>
              </div>
              <div class="db-gh-act">
                <?php foreach ($dbs as $dbn): ?><button class="db-mini fixdb" type="button" data-db="<?= smpro_h($dbn) ?>" data-account="<?= smpro_h($acct) ?>" title="Full mysqldump of <?= smpro_h($dbn) ?> into the client's home, then auto-clean every flagged row in it">&#128737; Backup &amp; clean<?= count($dbs) > 1 ? ' &middot; ' . smpro_h($dbn) : '' ?></button><?php endforeach; ?>
              </div>
            </div>
          </td>
        </tr>
        <?php foreach ($rows as $r): $rkey = $r['db'].'|'.$r['table'].'|'.$r['field'].'|'.(int)$r['row']; $cst = $statusMap[$rkey] ?? null; ?>
        <tr class="db-row <?= $gid ?>" data-gid="<?= $gid ?>" data-status="<?= $cst ? smpro_h($cst['state']) : '' ?>" data-db="<?= smpro_h($r['db']) ?>" data-table="<?= smpro_h($r['table']) ?>" data-field="<?= smpro_h($r['field']) ?>" data-row="<?= (int)$r['row'] ?>">
          <td class="db-cbcol"><input type="checkbox" class="db-pickrow" data-gid="<?= $gid ?>"></td>
          <td class="db-loc" title="This is a location INSIDE a database (a table row) — not a file on disk"><span class="db-loc-t">table</span> <span class="mono"><?= smpro_h($r['table']) ?></span> <span class="db-loc-a">›</span> <span class="db-loc-t">column</span> <span class="mono"><b><?= smpro_h($r['field']) ?></b></span> <span class="db-loc-t">row</span> <span class="mono">#<?= (int)$r['row'] ?></span></td>
          <td class="mono"><?= smpro_h($r['db']) ?><?php if (!empty($r['app'])): ?><div class="meta" style="font-size:11px"><?= smpro_h($r['app']) ?></div><?php endif; ?><?php if (!empty($r['path'])): ?><div class="db-path" title="<?= smpro_h($r['path']) ?>">&#128193; <?= smpro_h($r['path']) ?></div><?php elseif (($r['source'] ?? '') === 'native'): ?><div class="db-nofile" title="The injection lives in this database row. The code that wrote it is a file in the account's site — locate &amp; analyze it below.">&#8505;&#65039; injected in the database — no source file</div><?php endif; ?></td>
          <td class="db-status"><?= $cst ? smpro_db_status_badge($cst['state'], $cst['snips'] ?? 0) : '<span class="b gray">— not checked</span>' ?></td>
          <td><span class="b red"><?= smpro_h($r['family'] ?: 'malware') ?></span> <?php if (($r['source'] ?? '') === 'native'): ?><span class="db-tag-native" title="Found by SM Pro's deep native scan">NATIVE</span><?php else: ?><span class="db-tag-imun" title="Found by Imunify360">IMUNIFY</span><?php endif; ?></td>
          <td class="mono" style="font-size:11px"><?= $r['ctime']?smpro_h(date('Y-m-d H:i',(int)$r['ctime'])):'—' ?></td>
          <td class="db-act"><button class="db-mini insp" type="button">&#128269; Inspect</button> <?php if (!empty($r['path'])): ?><button class="db-mini dbAnalyze" type="button" data-path="<?= smpro_h($r['path']) ?>" title="Analyze this file's code — web-shell/backdoor or a legit file with a vulnerability?">&#128300; Analyze file</button> <?php else: ?><button class="db-mini dbFindFile" type="button" data-acct="<?= smpro_h($r['account']) ?>" title="This DB injection has no file recorded. Jump to the file analyzer to locate &amp; scan the file in the site that wrote it.">&#128300; Analyze a file</button> <?php endif; ?><button class="db-mini dbIgnore" type="button" title="Hide this finding — it will not show again (restorable below)">&#128683; Ignore</button></td>
        </tr>
        <tr class="db-insprow <?= $gid ?>" style="display:none"><td colspan="7" class="db-inspcell"></td></tr>
        <?php endforeach; ?>
      <?php endforeach; ?>
    </tbody></table>
  </div>
  <div class="im-note">&#128737; <b>Backup &amp; clean</b> saves a full <code>mysqldump</code> of the database into the client's home (<code>~/smpro_db_backups</code>) first, then removes every detected injection. Per-row cleans back up the original value to <code>/home/backup/detections/db</code>. Both are restorable.</div>
  <?php endif; ?>
</div>

<?php if ($dbHidden): ?>
<div class="card" id="db-ignored" style="margin-top:14px">
  <details><summary class="db-ignsum">&#128683; Ignored findings (<?= count($dbHidden) ?>) — show</summary>
    <div class="fa-tablewrap" style="max-height:300px;margin-top:10px"><table class="smpro-table"><thead><tr><th>Account</th><th>Database</th><th>Table.column</th><th class="num">Row</th><th>Source</th><th></th></tr></thead><tbody>
      <?php foreach ($dbHidden as $r): $rk = $r['db'].'|'.$r['table'].'|'.$r['field'].'|'.(int)$r['row']; ?>
        <tr>
          <td class="mono"><?= smpro_h($r['account'] ?: '—') ?></td>
          <td class="mono"><?= smpro_h($r['db']) ?></td>
          <td class="mono"><?= smpro_h($r['table'] . '.' . $r['field']) ?></td>
          <td class="num"><?= (int)$r['row'] ?></td>
          <td><?php if (($r['source'] ?? '') === 'native'): ?><span class="db-tag-native">NATIVE</span><?php else: ?><span class="db-tag-imun">IMUNIFY</span><?php endif; ?></td>
          <td><button class="db-mini dbUnignore" type="button" data-key="<?= smpro_h($rk) ?>">&#8634; Restore</button></td>
        </tr>
      <?php endforeach; ?>
    </tbody></table></div>
  </details>
</div>
<?php endif; ?>

<?php if ($restores): ?>
<div class="card" id="db-restore" style="padding:0;overflow:hidden;margin-top:14px;border-top:3px solid var(--good)">
  <div class="im-head"><b>&#8634; Restore (undo a clean / trash)</b><span class="meta">every clean and trash is backed up first — click <b>View</b> to see exactly what was removed, or Restore to undo it</span></div>
  <div class="db-tablewrap" style="max-height:380px"><table class="smpro-table"><thead><tr><th>When</th><th>Action</th><th>Account</th><th>Location</th><th class="num">Removed</th><th>Backup</th><th>What was removed</th><th>Restore</th></tr></thead><tbody>
    <?php foreach ($restores as $e): $rvid = smpro_h($e['id'] ?? ''); $rvHas = !empty($e['backup_exists']);
          $rmBytes = isset($e['orig_len'], $e['clean_len']) ? max(0, (int)$e['orig_len'] - (int)$e['clean_len']) : null; ?>
      <tr data-row>
        <td class="mono" style="font-size:11px"><?= smpro_h(date('Y-m-d H:i', (int)($e['ts'] ?? 0))) ?></td>
        <td><?php if (($e['kind'] ?? '') === 'trash'): ?><span class="b" style="background:var(--warn-bg);color:#92400e">trashed post</span><?php else: ?><span class="b" style="background:var(--good-bg);color:#15803d">cleaned row</span><?php endif; ?></td>
        <td class="mono"><?= smpro_h($e['account'] ?? '—') ?></td>
        <td class="mono" style="font-size:11px"><?= smpro_h(($e['db'] ?? '') . ' › ' . ($e['table'] ?? '') . ' › ' . ($e['field'] ?? '') . ' #' . (int)($e['row'] ?? 0)) ?></td>
        <td class="num mono" style="font-size:11px"><?= $rmBytes !== null ? number_format($rmBytes) . ' B' : (($e['kind'] ?? '') === 'trash' ? 'post' : '—') ?></td>
        <td class="mono" style="font-size:10.5px"><?= $rvHas ? '&#10003; kept' : '<span style="color:var(--dang)">&#10007; missing</span>' ?></td>
        <td><?php if ($rvHas): ?><button class="db-mini dbRvView" type="button" data-id="<?= $rvid ?>">&#128065;&#65039; View</button><?php else: ?><span class="meta">backup gone</span><?php endif; ?></td>
        <td><?php if ($rvHas || ($e['kind'] ?? '') === 'trash'): ?><button class="db-mini dbRestore" type="button" data-id="<?= $rvid ?>" data-kind="<?= smpro_h($e['kind'] ?? '') ?>">&#8634; Restore</button><?php else: ?><span class="meta">—</span><?php endif; ?></td>
      </tr>
      <tr class="db-rvrow" data-for="<?= $rvid ?>" style="display:none"><td colspan="8" class="db-inspcell db-rvcell"></td></tr>
    <?php endforeach; ?>
  </tbody></table></div>
  <div class="im-note" style="background:var(--brand-bg);color:#26408b"><b>View</b> shows the exact injected snippets that were stripped from each row (from the backup taken before cleaning) — nothing is changed. Restoring a <b>cleaned</b> row puts the ORIGINAL value back (that includes the injected content — re-clean if you didn't mean to). Restoring a <b>trashed</b> post sets its status back to what it was (it becomes live again). Every restore is verified against the database.</div>
</div>
<?php endif; ?>

<?php if ($reports): ?>
<div class="card" id="db-reports" style="padding:0;overflow:hidden;margin-top:14px">
  <div class="im-head"><b>&#128203; Cleanup action reports</b><span class="meta"><?= count($reports) ?> · backups in /home/backup/detections/db</span></div>
  <div class="db-tablewrap" style="max-height:300px"><table class="smpro-table"><thead><tr><th>When</th><th>Type</th><th>Account</th><th>What was cleaned</th><th class="num">Removed</th><th>Backup</th></tr></thead><tbody>
    <?php foreach ($reports as $d): $act = $d['action'] ?? 'db_clean';
        $label = ['db_fix'=>['amber','DB backup+clean'],'db_clean_bulk'=>['amber','bulk clean'],'db_trash'=>['amber','trash spam posts'],'db_clean'=>['gray','row clean']][$act] ?? ['gray',$act]; ?><tr data-row>
      <td class="mono" style="font-size:11px"><?= smpro_h(isset($d['ts'])?date('Y-m-d H:i',(int)$d['ts']):'') ?></td>
      <td><span class="b <?= $label[0] ?>"><?= $label[1] ?></span></td>
      <td class="mono"><?= smpro_h($d['account'] ?? '') ?></td>
      <td class="mono" style="font-size:11.5px">
        <?php if ($act === 'db_fix'): ?>
          <b><?= smpro_h($d['db'] ?? '') ?></b> — cleaned <b><?= (int)($d['rows_cleaned']??0) ?></b> of <?= (int)($d['rows_flagged']??0) ?> flagged row(s)<?= !empty($d['rows_skipped'])?' · '.(int)$d['rows_skipped'].' skipped':'' ?>
        <?php elseif ($act === 'db_trash'): ?>
          trashed <b><?= (int)($d['rows_cleaned']??0) ?></b> spam post(s)<?= !empty($d['rows_skipped'])?' · '.(int)$d['rows_skipped'].' skipped':'' ?>
        <?php elseif ($act === 'db_clean_bulk'): ?>
          cleaned <b><?= (int)($d['rows_cleaned']??0) ?></b> selected row(s)<?= !empty($d['rows_skipped'])?' · '.(int)$d['rows_skipped'].' skipped/clean':'' ?>
        <?php else: ?>
          <?= smpro_h(($d['db']??'').'.'.($d['table']??'').'.'.($d['field']??'')) ?> #<?= (int)($d['row']??0) ?><?= !empty($d['snippets'])?' · '.(int)$d['snippets'].' snippet(s)':'' ?>
        <?php endif; ?>
      </td>
      <td class="num"><?= number_format((int)($d['removed_bytes']??0)) ?> B</td>
      <td class="mono" style="font-size:11px"><?= smpro_h(basename($d['backup'] ?? '')) ?><?= $act==='db_fix' && !empty($d['backup_bytes'])?'<div class="meta">'.smpro_h(smpro_bytes((int)$d['backup_bytes'])).'</div>':'' ?></td>
    </tr><?php endforeach; ?>
  </tbody></table></div>
</div>
<?php endif; ?>

<style>
.svc-kicker{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--brand);font-weight:800}
.db-kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:14px 0}@media(max-width:760px){.db-kpis{grid-template-columns:1fr 1fr}}
.db-kpi{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px;text-align:center}.db-kpi.crit{border-top:3px solid var(--dang)}.db-kpi.good{border-top:3px solid var(--good)}
.db-kpi .n{font-size:23px;font-weight:800}.db-kpi.crit .n{color:var(--dang)}.db-kpi .l{font-size:11px;text-transform:uppercase;color:var(--muted);font-weight:700;margin-top:4px}
.db-bar{display:flex;gap:12px;align-items:flex-end;flex-wrap:wrap;margin:14px 0;padding:14px 16px}
.db-fld{display:flex;flex-direction:column;gap:5px;font-size:11px;text-transform:uppercase;color:var(--muted);font-weight:700}
.tp-in,.tp-sel{border:1px solid var(--line);border-radius:9px;padding:9px 12px;font-size:13px}
.tp-btn{border:1px solid var(--line);border-radius:9px;padding:9px 15px;font-size:13px;font-weight:600;cursor:pointer;text-decoration:none;color:var(--ink);background:var(--card)}.tp-btn.primary{background:var(--brand);color:#fff;border-color:var(--brand)}
.im-head{padding:12px 16px;border-bottom:1px solid var(--line);font-weight:700;font-size:14px;display:flex;align-items:center;gap:10px}.im-head .meta{margin-left:auto;color:var(--muted);font-size:12px}
.im-note{padding:10px 16px;background:var(--warn-bg);color:#8a6516;font-size:12px;border-top:1px solid var(--line)}.im-empty{padding:18px;text-align:center;color:var(--muted)}
.db-tablewrap{overflow:auto;max-height:520px}.db-tablewrap thead th{position:sticky;top:0;background:var(--card);z-index:1;box-shadow:inset 0 -1px 0 var(--line)}
.smpro-table{width:100%;border-collapse:collapse;font-size:12.5px}.smpro-table th,.smpro-table td{padding:8px 12px;text-align:left;border-bottom:1px solid var(--line);white-space:nowrap;vertical-align:top}
.smpro-table th{font-size:11px;text-transform:uppercase;color:var(--muted)}.smpro-table td.num,.smpro-table th.num{text-align:right}
.mono{font-family:ui-monospace,Consolas,monospace}.meta{color:var(--muted)}
.b{display:inline-block;font-size:11px;font-weight:700;padding:2px 8px;border-radius:20px}.b.red{background:var(--dang-bg);color:var(--dang)}.b.green{background:var(--good-bg);color:var(--good)}.b.gray{background:var(--card);color:#475569}
.db-toolbar{display:flex;align-items:center;gap:10px;flex-wrap:wrap;padding:10px 16px;border-bottom:1px solid var(--line);background:var(--card)}
.db-allwrap{font-size:13px;cursor:pointer;display:flex;align-items:center;gap:6px}
.db-selcount{font-size:12px;color:var(--muted);font-weight:700}
.db-statussum{font-size:12px;color:var(--muted);font-weight:700;margin-left:auto}
.db-checkall{border-color:#c7d2fe !important;background:var(--brand-bg) !important;color:#3730a3 !important}
.db-selectlive{border-color:#fca5a5 !important;background:var(--dang-bg) !important;color:var(--dang) !important}
.db-selectspam,.db-trashsel,.db-cleansel{border-color:#fcd34d !important;background:var(--warn-bg) !important;color:#92400e !important}
.db-trashsel:disabled,.db-cleansel:disabled{opacity:.5;cursor:not-allowed}
.db-status .b{white-space:nowrap}
.db-groupact{text-align:right}
.db-cbcol{width:34px;text-align:center !important}
.db-grouprow{background:linear-gradient(180deg,rgba(100,116,139,.07),transparent)}.db-grouprow td{border-top:1px solid var(--line);border-bottom:1px solid var(--line);vertical-align:middle}
html[data-theme=dark] .db-grouprow{background:linear-gradient(180deg,rgba(255,255,255,.04),transparent)}
.db-grouphd{padding:0 !important}
.db-gh{display:flex;align-items:center;gap:13px;padding:12px 14px;flex-wrap:wrap}
.db-gh-ava{width:34px;height:34px;flex:none;border-radius:10px;background:var(--brand);color:#fff;font-weight:800;font-size:15px;display:flex;align-items:center;justify-content:center}
.db-gh-main{display:flex;flex-direction:column;gap:5px;min-width:0}
.db-gh-top{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.db-gh-name{font-size:14.5px;font-weight:800;letter-spacing:.01em}
.db-gh-count{font-size:11px;font-weight:800;background:var(--dang-bg);color:var(--dang);padding:2px 10px;border-radius:20px;white-space:nowrap}
.db-gh-dbs{display:flex;gap:6px;flex-wrap:wrap}
.db-gh-db{font-size:10.5px;color:var(--muted);background:var(--card);border:1px solid var(--line);border-radius:7px;padding:2px 8px;white-space:nowrap}
.db-gh-act{margin-left:auto;display:flex;gap:6px;flex-wrap:wrap;justify-content:flex-end}
.db-toggle{border:none;background:transparent;cursor:pointer;font-size:14px;color:var(--muted);padding:0;flex:none;transition:transform .15s}.db-toggle.collapsed{transform:rotate(-90deg)}
.db-row td{white-space:nowrap}
.amber{background:var(--warn-bg);color:#92400e}
.db-mini{font-size:11px;font-weight:700;border:1px solid var(--line);background:var(--card);border-radius:7px;padding:4px 10px;cursor:pointer;margin:1px}
.db-mini.fixdb{border-color:#fcd34d;background:var(--warn-bg);color:#92400e}
.db-mini.trash1{border-color:#fcd34d;background:var(--warn-bg);color:#92400e;margin-top:8px}
.db-box-spam{margin:6px 0;padding:9px 12px;background:var(--warn-bg);border:1px solid #fde68a;border-radius:9px;font-size:12.5px;color:#7c5e16}
.db-mini.insp{border-color:#c7d2fe;background:var(--brand-bg);color:#3730a3}
.db-mini.dbIgnore{border-color:var(--line);background:var(--card);color:var(--muted)}
.db-mini.dbIgnore:hover{background:var(--muted);color:#fff}
.db-ignsum{cursor:pointer;font-weight:700;color:var(--muted);display:inline-block}
.db-mini.clean{border-color:#bbf7d0;background:var(--good-bg);color:#15803d}
.db-inspcell{background:var(--card);padding:12px 16px !important;white-space:normal}
.db-box{font-size:12px}.db-box h4{margin:0 0 6px;font-size:12px}
.db-snip{display:block;font-family:ui-monospace,Consolas,monospace;font-size:11px;background:#2b1414;color:#ffb3b3;border-radius:8px;padding:8px 10px;margin:6px 0;white-space:pre-wrap;word-break:break-all;max-height:150px;overflow:auto}
.db-selbar{margin:6px 0;font-size:12px}.db-selbar label{cursor:pointer;font-weight:600}
.db-snipwrap{display:block;border:1px solid var(--line);border-radius:9px;padding:8px 10px;margin:7px 0;background:var(--card);cursor:pointer}
.db-snipwrap>input{margin-right:6px;vertical-align:middle}
.db-sniphd{display:inline-flex;gap:8px;align-items:center;font-size:11px}
.db-host{font-family:ui-monospace,Consolas,monospace;font-weight:700;color:var(--dang)}
.db-prev{font-family:ui-monospace,Consolas,monospace;font-size:11px;background:#0f172a;color:#cbd5e1;border-radius:8px;padding:8px 10px;white-space:pre-wrap;word-break:break-all;max-height:200px;overflow:auto;margin:6px 0}
.db-stat{display:flex;gap:14px;flex-wrap:wrap;font-size:12px;margin:6px 0}.db-stat b{color:var(--ink)}
.db-progress-overlay{position:fixed;inset:0;background:rgba(15,23,42,.55);z-index:9999;display:flex;align-items:center;justify-content:center;backdrop-filter:blur(2px)}
.db-progress-box{background:var(--card);border-radius:16px;padding:26px 28px;width:min(460px,92vw);box-shadow:0 20px 60px rgba(0,0,0,.35);text-align:center}
.db-progress-title{font-size:16px;font-weight:800;margin-bottom:16px}
.db-progress-track{height:14px;background:var(--card);border-radius:20px;overflow:hidden}
.db-progress-fill{height:100%;width:0;background:linear-gradient(90deg,var(--brand),#6366f1);border-radius:20px;transition:width .3s ease}
.db-progress-meta{display:flex;justify-content:space-between;font-size:13px;font-weight:700;margin-top:8px}
.db-progress-sub{font-size:12px;color:var(--muted);margin-top:6px;min-height:16px}
.db-progress-cancel{margin-top:16px}
.db-progress-box.done .db-progress-fill{background:var(--good)}
</style>
<script>
(function(){
  function post(fd){fd.set('smpro_csrf',DBC_CSRF);return fetch('index.cgi?page=database-cleanup',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'}).then(function(r){return r.json();});}
  function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
  function rowData(tr){return {db:tr.getAttribute('data-db'),table:tr.getAttribute('data-table'),field:tr.getAttribute('data-field'),row:tr.getAttribute('data-row')};}
  var TYPE_LABEL={extlink:'External spam link',script:'Injected &lt;script&gt;',iframe:'Hidden &lt;iframe&gt;',php:'Injected PHP',eval:'Obfuscated eval()',hidden:'Hidden spam block'};
  // ---- Ignore / Restore a finding (persisted; it will not show again) ----
  document.addEventListener('click',function(e){
    var ig=e.target.closest('.dbIgnore');
    if(ig){ var tr=ig.closest('tr'),d=rowData(tr),key=d.db+'|'+d.table+'|'+d.field+'|'+d.row;
      if(!confirm('Hide this finding so it does not show again?\n\n'+d.db+'.'+d.table+'.'+d.field+' (row '+d.row+')\n\nYou can restore it later from "Ignored findings".'))return;
      ig.disabled=true;var fd=new URLSearchParams();fd.set('dbc_action','ignore');fd.set('key',key);
      post(fd).then(function(j){ if(j&&j.ok){ var ir=tr.nextElementSibling; tr.parentNode.removeChild(tr); if(ir&&ir.classList&&ir.classList.contains('db-insprow')&&ir.parentNode)ir.parentNode.removeChild(ir); } else { ig.disabled=false; alert((j&&j.msg)||'Failed'); } }).catch(function(){ig.disabled=false;alert('Request failed.');});
      return; }
    var un=e.target.closest('.dbUnignore');
    if(un){ un.disabled=true;var fd2=new URLSearchParams();fd2.set('dbc_action','unignore');fd2.set('key',un.getAttribute('data-key'));
      post(fd2).then(function(j){ if(j&&j.ok){location.reload();} else {un.disabled=false;alert((j&&j.msg)||'Failed');} }).catch(function(){un.disabled=false;alert('Request failed.');});
      return; }
  });
  // ---- Analyze a file (web-shell vs legit-with-vuln) ----
  var VCLS={danger:'var(--dang)',warn:'var(--warn)',good:'var(--good)',gray:'var(--muted)'};
  var VBG={danger:'var(--dang-bg)',warn:'var(--warn-bg)',good:'var(--good-bg)',gray:'var(--card)'};
  function chips(a,lbl){ if(!a||!a.length)return ''; return '<div class="db-af-k"><span>'+lbl+'</span> '+a.map(function(x){return '<span class="db-af-chip">'+esc(x)+'</span>';}).join(' ')+'</div>'; }
  function analyzeFile(path,btn){
    var box=document.getElementById('dbAfResult'); if(box)box.innerHTML='<div class="meta">⏳ Analyzing '+esc(path)+' …</div>';
    var o; if(btn){o=btn.innerHTML;btn.disabled=true;btn.innerHTML='…';}
    var fd=new URLSearchParams();fd.set('dbc_action','analyze_file');fd.set('path',path);
    post(fd).then(function(j){ if(btn){btn.disabled=false;btn.innerHTML=o;}
      if(!j||!j.ok){ if(box)box.innerHTML='<div style="color:var(--dang)">✗ '+esc((j&&j.msg)||'Analysis failed')+'</div>'; return; }
      var v=j.verdict||{},d=j.deep||{},c=v.cls||'gray';
      var h='<div class="db-af-verdict" style="border-color:'+(VCLS[c]||'var(--line)')+';background:'+(VBG[c]||'var(--card)')+'">'
        +'<div class="db-af-vt" style="color:'+(VCLS[c]||'inherit')+'">'+esc(v.label||'')+'</div>'
        +'<div class="db-af-vx">'+esc(v.text||'')+'</div>'
        +'<div class="mono db-af-path">'+esc(j.path||path)+'</div>'
        +'<div class="db-af-grid">'
        +'<div><span>Risk band</span><b style="color:'+(VCLS[c]||"inherit")+'">'+esc((d.band||"").toUpperCase())+'</b></div>'
        +'<div><span>Entropy</span><b>'+esc(d.entropy)+'</b></div>'
        +'<div><span>Owner OK</span><b>'+esc(d.owner_ok)+'</b></div>'
        +'<div><span>In webroot</span><b>'+(d.in_webroot?'yes':'no')+'</b></div>'
        +'<div><span>Nested decode→eval</span><b>'+(d.nested_chain?'YES':'no')+'</b></div>'
        +'<div><span>Timestomp</span><b>'+esc(d.timestomp)+'</b></div>'
        +'<div><span>Modified</span><b>'+esc(d.mtime||'—')+'</b></div>'
        +'<div><span>SHA256</span><b class="mono">'+esc(d.sha256)+'…</b></div>'
        +'</div>'
        +chips(d.families,'Families:')+chips(d.tokens,'Tokens:')+chips(d.signals,'Signals:')
        +'</div>';
      if(box)box.innerHTML=h;
    }).catch(function(){ if(btn){btn.disabled=false;btn.innerHTML=o;} if(box)box.innerHTML='<div style="color:var(--dang)">✗ Request failed.</div>'; });
  }
  var afBtn=document.getElementById('dbAfBtn'),afIn=document.getElementById('dbAfPath');
  if(afBtn)afBtn.addEventListener('click',function(){var p=(afIn&&afIn.value||'').trim();if(!p){if(afIn)afIn.focus();return;}analyzeFile(p,afBtn);});
  if(afIn)afIn.addEventListener('keydown',function(e){if(e.key==='Enter'){e.preventDefault();if(afBtn)afBtn.click();}});
  document.addEventListener('click',function(e){
    var a=e.target.closest('.dbAnalyze'); if(!a)return;
    var p=a.getAttribute('data-path'); if(afIn)afIn.value=p;
    var panel=document.querySelector('.db-af'); if(panel)panel.scrollIntoView({behavior:'smooth',block:'center'});
    analyzeFile(p,a);
  });
  // Native DB finding has no file recorded — jump to the analyzer, prefill the account webroot so the admin
  // can complete the path to the suspected file (a vulnerable extension or a web-shell) and analyze it.
  document.addEventListener('click',function(e){
    var f=e.target.closest('.dbFindFile'); if(!f)return;
    var acct=f.getAttribute('data-acct')||'';
    if(afIn){afIn.value='/home/'+acct+'/public_html/'; afIn.focus(); try{afIn.setSelectionRange(afIn.value.length,afIn.value.length);}catch(_){}}
    var panel=document.querySelector('.db-af'); if(panel)panel.scrollIntoView({behavior:'smooth',block:'center'});
    var box=document.getElementById('dbAfResult'); if(box)box.innerHTML='<div class="meta">This injection is stored in the database (no file was recorded for it). The code that wrote it is a file in <b>'+esc(acct)+'</b>’s site — finish the path above to the suspected file (e.g. a recently-changed .php in an extension/theme, or an uploaded shell) and press <b>Analyze file</b>. Tip: OpenCart/WordPress DB injections usually come from a vulnerable extension or an uploaded web-shell under this webroot.</div>';
  });
  // Restore (undo a clean/trash) from its backup
  document.addEventListener('click',function(e){
    var r=e.target.closest('.dbRestore'); if(!r)return;
    var kind=r.getAttribute('data-kind')||'';
    var warn=kind==='trash'?'This will set the post status back to what it was (the post becomes live again).':'This will put the ORIGINAL value back into the row — that INCLUDES the injected content. Only do this if the clean was a mistake.';
    if(!confirm('Restore this '+(kind==='trash'?'trashed post':'cleaned row')+' from its backup?\n\n'+warn))return;
    var o=r.innerHTML;r.disabled=true;r.innerHTML='…';
    var fd=new URLSearchParams();fd.set('dbc_action','restore');fd.set('id',r.getAttribute('data-id'));
    post(fd).then(function(j){ alert((j&&j.ok?'✓ ':'✗ ')+((j&&j.msg)||'Failed'));
      if(j&&j.ok){var tr=r.closest('tr');if(tr)tr.style.opacity=.5;r.outerHTML='<span class="b green">✓ restored</span>';setTimeout(function(){location.reload();},1400);}
      else{r.disabled=false;r.innerHTML=o;} }).catch(function(){r.disabled=false;r.innerHTML=o;alert('Request failed.');});
  });
  // View exactly what was removed for a restore-log entry (toggle an inline detail row) — read-only
  document.addEventListener('click',function(e){
    var b=e.target.closest('.dbRvView'); if(!b)return;
    var id=b.getAttribute('data-id'), tr=b.closest('tr'), drow=tr.nextElementSibling;
    if(!drow||!drow.classList.contains('db-rvrow')){return;}
    if(drow.style.display!=='none'){drow.style.display='none';b.innerHTML='&#128065;&#65039; View';return;}  // toggle closed
    var cell=drow.querySelector('.db-rvcell');
    drow.style.display='';b.innerHTML='&#128065;&#65039; Hide';cell.innerHTML='<div class="meta">⏳ Reading the backup…</div>';
    var fd=new URLSearchParams();fd.set('dbc_action','restore_view');fd.set('id',id);
    post(fd).then(function(j){
      if(!j||!j.ok){cell.innerHTML='<div class="db-box" style="color:var(--dang)">⚠ '+esc((j&&j.msg)||'Could not read the backup.')+'</div>';return;}
      var h='<div class="db-box">';
      h+='<div class="db-stat"><span>location: <b>'+esc(j.location)+'</b></span><span>when: <b>'+esc(j.when)+'</b></span>'+(j.account?'<span>account: <b>'+esc(j.account)+'</b></span>':'')+'</div>';
      if(j.kind==='trash'){
        h+='<h4>&#128465; This was a spam POST that was trashed (not stripped). Its status was <b>'+esc(j.prev_status)+'</b>; restoring sets it back.</h4>';
        h+='<h4 style="margin-top:8px">Backed-up post content ('+(+j.len||0)+' B):</h4><div class="db-prev">'+esc(j.preview)+'</div>';
      } else {
        h+='<div class="db-stat"><span>original: <b>'+(+j.orig_len||0)+'</b> B</span><span>after clean: <b>'+(+j.clean_len||0)+'</b> B</span><span>removed: <b style="color:var(--dang)">'+(+j.removed_bytes||0)+'</b> B</span><span><b>'+(+j.snippet_count||0)+'</b> malicious snippet(s) stripped</span></div>';
        if(j.snippets&&j.snippets.length){
          h+='<h4 style="margin-top:8px">&#9888; Exactly what was removed from this row:</h4>';
          j.snippets.forEach(function(s){
            var lbl=TYPE_LABEL[s.type]||esc(s.type);
            h+='<div class="db-snipwrap" style="cursor:default">'
              +'<span class="db-sniphd"><span class="b red">'+lbl+'</span>'+(s.host?' <span class="db-host">'+esc(s.host)+'</span>':'')+' <span class="meta">'+(+s.len||0)+' B</span></span>'
              +'<span class="db-snip">'+esc(s.text)+'</span></div>';
          });
        } else {
          h+='<div class="b green" style="margin:6px 0">The backed-up value had no strippable snippet on re-analysis (it may have been whole-content spam or already partially cleaned). Full backup shown below.</div>';
        }
        h+='<h4 style="margin-top:10px">Backed-up ORIGINAL value (first 8 KB — includes the injected content):</h4><div class="db-prev">'+esc(j.orig_preview)+'</div>';
      }
      h+='</div>';cell.innerHTML=h;
    }).catch(function(){cell.innerHTML='<div class="db-box" style="color:var(--dang)">Request failed.</div>';});
  });
  document.addEventListener('click',function(e){
    var b=e.target.closest('.db-mini.insp'); if(!b)return;
    var tr=b.closest('tr'),cell=tr.nextElementSibling.querySelector('.db-inspcell'),crow=tr.nextElementSibling;
    crow.style.display=''; cell.innerHTML='<div class="meta">⏳ Reading the row from the database…</div>'; b.disabled=true;
    var d=rowData(tr),fd=new URLSearchParams();fd.set('dbc_action','inspect');fd.set('db',d.db);fd.set('table',d.table);fd.set('field',d.field);fd.set('row',d.row);
    post(fd).then(function(j){ b.disabled=false;
      if(!j.ok){cell.innerHTML='<div class="db-box" style="color:var(--dang)">⚠ '+esc(j.msg)+'</div>';return;}
      var h='<div class="db-box" data-hash="'+esc(j.hash)+'"><div class="db-stat"><span>value length: <b>'+j.len+'</b> B</span><span>after removing all: <b>'+j.clean_len+'</b> B</span><span>found <b>'+j.snippet_count+'</b> malicious snippet(s)</span>'+(j.own_domains&&j.own_domains.length?'<span>own domain(s): <b>'+esc(j.own_domains.join(', '))+'</b></span>':'')+'</div>';
      if(j.changed && j.snippets.length){
        h+='<h4>&#9888; Select the snippets to remove (the rest of the row is kept):</h4>';
        h+='<div class="db-selbar"><label><input type="checkbox" class="db-all" checked> select all</label></div>';
        j.snippets.forEach(function(s){
          var lbl=TYPE_LABEL[s.type]||s.type;
          h+='<label class="db-snipwrap"><input type="checkbox" class="db-pick" value="'+s.i+'" checked>'
            +'<span class="db-sniphd"><span class="b red">'+lbl+'</span>'+(s.host?' <span class="db-host">'+esc(s.host)+'</span>':'')+' <span class="meta">'+s.len+' B</span></span>'
            +'<span class="db-snip">'+esc(s.text)+'</span></label>';
        });
        h+='<button class="db-mini clean" type="button" data-db="'+esc(d.db)+'" data-table="'+esc(d.table)+'" data-field="'+esc(d.field)+'" data-row="'+esc(d.row)+'" data-hash="'+esc(j.hash)+'">&#129529; Remove selected &amp; clean (backup first)</button>';
      } else if(j.spam_post){
        var terms=(j.spam_terms||[]).slice(0,6).map(esc).join(', ');
        h+='<div class="db-box-spam">&#128465; <b>This is a spam '+(j.is_post?'post':'record')+'</b> — the whole content is SEO spam'+(terms?' (terms: '+terms+')':'')+', not an injected snippet, so there is nothing to "strip". '
          +(j.is_post?'Remove it with <b>Trash this post</b> below — it is hidden from the site and recoverable from WordPress trash.':'Review the value and remove the record manually.')+'</div>';
        if(j.is_post){
          tr.setAttribute('data-status','spam');
          h+='<button class="db-mini trash1" type="button" data-db="'+esc(d.db)+'" data-table="'+esc(d.table)+'" data-field="'+esc(d.field)+'" data-row="'+esc(d.row)+'">&#128465; Trash this post (reversible)</button>';
        }
      } else {
        h+='<div class="b green" style="margin:4px 0">&#10003; No injected script / iframe / PHP / external-spam link or spam content is present in the current row. This Imunify detection is most likely <b>stale</b> — already cleaned. It will clear on Imunify’s next database rescan.</div>';
      }
      h+='<h4 style="margin-top:10px">Current value (first 6 KB):</h4><div class="db-prev">'+esc(j.preview)+'</div></div>';
      cell.innerHTML=h;
    }).catch(function(){b.disabled=false;cell.innerHTML='<div style="color:var(--dang)">Request failed.</div>';});
  });
  // single spam-post trash (from the Inspect panel)
  document.addEventListener('click',function(e){
    var b=e.target.closest('.db-mini.trash1'); if(!b)return;
    if(!confirm('Trash this spam post?\n\n'+b.getAttribute('data-db')+'.'+b.getAttribute('data-table')+' #'+b.getAttribute('data-row')+'\n\nIts status is set to "trash" (hidden from the site, recoverable from WordPress trash; content also backed up).'))return;
    b.disabled=true;b.textContent='⏳ Trashing…';
    var key=[b.getAttribute('data-db'),b.getAttribute('data-table'),b.getAttribute('data-field'),b.getAttribute('data-row')].join('|');
    var fd=new URLSearchParams();fd.set('dbc_action','trash_batch');fd.set('rows',key);
    post(fd).then(function(j){ alert((j&&j.trashed?'✅ ':'⚠ ')+'Trashed '+((j&&j.trashed)||0)+' post(s)'+((j&&j.skipped)?' · '+j.skipped+' skipped':'')); if(j&&j.trashed){b.outerHTML='<span class="b green">✓ trashed</span>';}else{b.disabled=false;b.innerHTML='&#128465; Trash this post (reversible)';} }).catch(function(){b.disabled=false;b.textContent='Trash';alert('Request failed.');});
  });
  // select-all toggle
  document.addEventListener('change',function(e){
    var a=e.target.closest('.db-all'); if(!a)return;
    var box=a.closest('.db-box'); box.querySelectorAll('.db-pick').forEach(function(c){c.checked=a.checked;});
  });
  document.addEventListener('click',function(e){
    var b=e.target.closest('.db-mini.clean'); if(!b)return;
    var box=b.closest('.db-box');
    var sel=Array.prototype.slice.call(box.querySelectorAll('.db-pick:checked')).map(function(c){return c.value;});
    if(!sel.length){alert('Select at least one snippet to remove.');return;}
    if(!confirm('Remove '+sel.length+' selected snippet(s) from\n\n'+b.getAttribute('data-db')+'.'+b.getAttribute('data-table')+'.'+b.getAttribute('data-field')+' #'+b.getAttribute('data-row')+'\n\nThe original value is backed up first and is fully restorable. Only the snippets you selected are removed; the rest of the content is kept.'))return;
    b.disabled=true;b.textContent='⏳ Cleaning…';
    var fd=new URLSearchParams();fd.set('dbc_action','clean');fd.set('db',b.getAttribute('data-db'));fd.set('table',b.getAttribute('data-table'));fd.set('field',b.getAttribute('data-field'));fd.set('row',b.getAttribute('data-row'));fd.set('hash',b.getAttribute('data-hash'));fd.set('sel',sel.join(','));
    post(fd).then(function(j){ alert((j&&j.ok?'✅ ':'⚠ ')+((j&&j.msg)||'Done')); if(j&&j.ok){b.outerHTML='<span class="b green">✓ cleaned — '+sel.length+' snippet(s) removed</span>';} else {b.disabled=false;b.innerHTML='&#129529; Remove selected &amp; clean (backup first)';} }).catch(function(){b.disabled=false;b.textContent='Clean';alert('Request failed.');});
  });

  /* ---------- selection (master / header / group / row) + bulk clean ---------- */
  var pickRows=function(){return Array.prototype.slice.call(document.querySelectorAll('.db-pickrow'));};
  function refreshSel(){
    var checked=pickRows().filter(function(c){return c.checked;});
    var cnt=checked.length, el=document.getElementById('dbSelCount'), btn=document.getElementById('dbCleanSel');
    if(el)el.textContent=cnt+' selected'; if(btn)btn.disabled=cnt===0;
    // enable Trash only when selection includes spam-post rows
    var spamSel=checked.filter(function(c){var tr=c.closest('tr');return tr.getAttribute('data-status')==='spam'&&/_?posts$/i.test(tr.getAttribute('data-table')||'');}).length;
    var tb=document.getElementById('dbTrashSel'); if(tb)tb.disabled=spamSel===0;
    var all=pickRows().length, m=document.getElementById('dbMasterAll'), hh=document.getElementById('dbHeadAll');
    [m,hh].forEach(function(x){if(x){x.checked=cnt>0&&cnt===all;x.indeterminate=cnt>0&&cnt<all;}});
    // group checkbox state
    document.querySelectorAll('.db-groupall').forEach(function(g){
      var gid=g.getAttribute('data-gid');
      var rows=pickRows().filter(function(c){return c.getAttribute('data-gid')===gid;});
      var on=rows.filter(function(c){return c.checked;}).length;
      g.checked=on>0&&on===rows.length; g.indeterminate=on>0&&on<rows.length;
    });
  }
  function setAll(on){pickRows().forEach(function(c){c.checked=on;});refreshSel();}
  document.addEventListener('change',function(e){
    if(e.target.id==='dbMasterAll'||e.target.id==='dbHeadAll'){setAll(e.target.checked);return;}
    if(e.target.classList.contains('db-groupall')){var gid=e.target.getAttribute('data-gid');
      pickRows().filter(function(c){return c.getAttribute('data-gid')===gid;}).forEach(function(c){c.checked=e.target.checked;});refreshSel();return;}
    if(e.target.classList.contains('db-pickrow')){refreshSel();return;}
  });
  // collapse/expand a group
  document.addEventListener('click',function(e){
    var t=e.target.closest('.db-toggle'); if(!t)return;
    var gid=t.getAttribute('data-gid'); t.classList.toggle('collapsed');
    var hide=t.classList.contains('collapsed');
    document.querySelectorAll('tr.'+gid).forEach(function(tr){ if(tr.classList.contains('db-insprow'))return; tr.style.display=hide?'none':''; });
  });
  /* ---------- progress bar controller ---------- */
  var CHUNK=25, cancelFlag=false, reloadOnClose=true;
  var ov=document.getElementById('dbProgress'),pBox=ov?ov.querySelector('.db-progress-box'):null;
  var pTitle=document.getElementById('dbpTitle'),pFill=document.getElementById('dbpFill'),pPct=document.getElementById('dbpPct'),pCounts=document.getElementById('dbpCounts'),pSub=document.getElementById('dbpSub'),pCancel=document.getElementById('dbpCancel');
  function progShow(title,reload){cancelFlag=false;reloadOnClose=reload!==false;if(pBox)pBox.classList.remove('done');pTitle.textContent=title;pFill.style.width='0%';pPct.textContent='0%';pCounts.textContent='0 / 0';pSub.textContent='Working in batches — please keep this tab open…';pCancel.style.display='';pCancel.disabled=false;pCancel.textContent='Stop after current batch';ov.style.display='flex';}
  function progUpd(done,total,cleaned,skipped){var pct=total?Math.round(done/total*100):0;pFill.style.width=pct+'%';pPct.textContent=pct+'%';pCounts.textContent=done+' / '+total;pSub.textContent='Cleaned '+cleaned+(skipped?' · '+skipped+' skipped/clean':'')+' — '+(total-done)+' remaining';}
  function progDone(msg){if(pBox)pBox.classList.add('done');pFill.style.width='100%';pPct.textContent='100%';pSub.textContent=msg;pCancel.textContent='Close';pCancel.disabled=false;}
  if(pCancel)pCancel.addEventListener('click',function(){ if(pBox&&pBox.classList.contains('done')){ov.style.display='none';if(reloadOnClose)location.reload();return;} cancelFlag=true;pCancel.disabled=true;pCancel.textContent='Stopping…';});
  /* ---------- status classification (no mutation) ---------- */
  function rowKey(tr){return [tr.getAttribute('data-db'),tr.getAttribute('data-table'),tr.getAttribute('data-field'),tr.getAttribute('data-row')].join('|');}
  function statusBadge(st,snips,isPost){
    if(st==='live')return '<span class="b red">&#128308; Live — '+snips+' spam snippet'+(snips==1?'':'s')+'</span>';
    if(st==='spam')return '<span class="b amber">&#128465; Spam '+(isPost?'post':'content')+' — whole page</span>';
    if(st==='clean')return '<span class="b green">&#9989; Clean (stale entry)</span>';
    if(st==='deleted')return '<span class="b gray">&#9898; Row removed</span>';
    if(st==='gone')return '<span class="b gray">cleared</span>';
    return '<span class="b amber">unknown</span>';
  }
  function updateGroupLive(){
    document.querySelectorAll('.db-glive').forEach(function(sp){
      var gid=sp.getAttribute('data-gid');
      var rows=Array.prototype.slice.call(document.querySelectorAll('tr.db-row.'+gid));
      var live=rows.filter(function(tr){return tr.getAttribute('data-status')==='live';}).length;
      var spam=rows.filter(function(tr){return tr.getAttribute('data-status')==='spam';}).length;
      sp.innerHTML=(live>0?'<span class="b red" style="margin-right:6px">&#128308; '+live+' live</span>':'')+(spam>0?'<span class="b amber" style="margin-right:6px">&#128465; '+spam+' spam</span>':'');
    });
  }
  document.addEventListener('click',function(e){
    var b=e.target.closest('#dbCheckAll'); if(!b)return;
    var trs=Array.prototype.slice.call(document.querySelectorAll('tr.db-row'));
    if(!trs.length)return;
    var keys=trs.map(rowKey),cellOf={};
    trs.forEach(function(tr){cellOf[rowKey(tr)]=tr;});
    progShow('Checking '+keys.length+' row status(es)…',false);
    var counts={live:0,spam:0,clean:0,deleted:0,gone:0,unknown:0},done=0,i=0;
    function setProg(){var pct=keys.length?Math.round(done/keys.length*100):0;pFill.style.width=pct+'%';pPct.textContent=pct+'%';pCounts.textContent=done+' / '+keys.length;pSub.textContent='🔴 '+counts.live+' live · 🗑 '+counts.spam+' spam · ✅ '+counts.clean+' clean · ⚪ '+counts.deleted+' removed';}
    function finish(){
      updateGroupLive();
      var sum=document.getElementById('dbStatusSum');if(sum)sum.innerHTML='<b style="color:var(--dang)">'+counts.live+' live</b> · <b style="color:#b45309">'+counts.spam+' spam</b> · '+counts.clean+' clean · '+counts.deleted+' removed';
      var sl=document.getElementById('dbSelectLive');if(sl)sl.style.display=counts.live>0?'':'none';
      var ss=document.getElementById('dbSelectSpam');if(ss)ss.style.display=counts.spam>0?'':'none';
      progDone((cancelFlag?'Stopped. ':'Done. ')+'🔴 '+counts.live+' live · 🗑 '+counts.spam+' spam post(s) · ✅ '+counts.clean+' clean · ⚪ '+counts.deleted+' removed.');
    }
    function next(){
      if(cancelFlag||i>=keys.length){finish();return;}
      var batch=keys.slice(i,i+CHUNK);i+=CHUNK;
      var fd=new URLSearchParams();fd.set('dbc_action','classify_batch');fd.set('rows',batch.join('\n'));
      post(fd).then(function(j){
        if(j&&j.ok&&j.statuses){Object.keys(j.statuses).forEach(function(k){var s=j.statuses[k],tr=cellOf[k];if(!tr)return;tr.setAttribute('data-status',s.state);var c=tr.querySelector('.db-status');if(c)c.innerHTML=statusBadge(s.state,s.snips,s.is_post);counts[s.state]=(counts[s.state]||0)+1;});}
        done+=batch.length;setProg();setTimeout(next,0);
      }).catch(function(){done+=batch.length;setProg();setTimeout(next,0);});
    }
    setProg();next();
  });
  // select only rows classified as live
  document.addEventListener('click',function(e){
    var b=e.target.closest('#dbSelectLive'); if(!b)return;
    pickRows().forEach(function(c){var tr=c.closest('tr');c.checked=tr.getAttribute('data-status')==='live';});
    refreshSel();
  });
  // select only spam-post rows
  document.addEventListener('click',function(e){
    var b=e.target.closest('#dbSelectSpam'); if(!b)return;
    pickRows().forEach(function(c){var tr=c.closest('tr');c.checked=tr.getAttribute('data-status')==='spam'&&/_?posts$/i.test(tr.getAttribute('data-table')||'');});
    refreshSel();
  });
  // trash selected spam posts (chunked, reversible)
  document.addEventListener('click',function(e){
    var b=e.target.closest('#dbTrashSel'); if(!b)return;
    var rows=pickRows().filter(function(c){var tr=c.closest('tr');return c.checked&&tr.getAttribute('data-status')==='spam'&&/_?posts$/i.test(tr.getAttribute('data-table')||'');}).map(function(c){var tr=c.closest('tr');return [tr.getAttribute('data-db'),tr.getAttribute('data-table'),tr.getAttribute('data-field'),tr.getAttribute('data-row')].join('|');});
    if(!rows.length){alert('Select spam posts first (use “Check statuses” then “Select spam posts”).');return;}
    if(!confirm('Trash '+rows.length+' spam post(s)?\n\nEach post’s status is set to “trash” (it disappears from the site but is recoverable from WordPress trash; its content is also backed up). Continue?'))return;
    progShow('Trashing '+rows.length+' spam post(s)…');
    var total=rows.length,done=0,trashed=0,skipped=0,i=0;
    function up(){var pct=total?Math.round(done/total*100):0;pFill.style.width=pct+'%';pPct.textContent=pct+'%';pCounts.textContent=done+' / '+total;pSub.textContent='Trashed '+trashed+(skipped?' · '+skipped+' skipped':'')+' — '+(total-done)+' remaining';}
    function next(){
      if(cancelFlag||i>=rows.length){
        var fr=new URLSearchParams();fr.set('dbc_action','bulk_report');fr.set('kind','db_trash');fr.set('flagged',total);fr.set('cleaned',trashed);fr.set('skipped',skipped);
        post(fr).then(function(){progDone((cancelFlag?'Stopped. ':'Done. ')+'Trashed '+trashed+' spam post(s)'+(skipped?' · '+skipped+' skipped':'')+'. They are now removed from the list and skipped by future scans.');if(trashed)setTimeout(function(){location.reload();},2600);});
        return;
      }
      var batch=rows.slice(i,i+CHUNK);i+=CHUNK;
      var fd=new URLSearchParams();fd.set('dbc_action','trash_batch');fd.set('rows',batch.join('\n'));
      post(fd).then(function(j){if(j&&j.ok){trashed+=j.trashed||0;skipped+=j.skipped||0;}else skipped+=batch.length;done+=batch.length;up();setTimeout(next,0);}).catch(function(){skipped+=batch.length;done+=batch.length;up();setTimeout(next,0);});
    }
    up();next();
  });
  // run keys through clean_batch in chunks, updating the bar; returns totals
  function runChunks(keys,onProgress){
    var total=keys.length,done=0,cleaned=0,skipped=0,bytes=0,i=0;
    return new Promise(function(resolve){
      function next(){
        if(cancelFlag||i>=keys.length){resolve({done:done,total:total,cleaned:cleaned,skipped:skipped,bytes:bytes,cancelled:cancelFlag&&i<keys.length});return;}
        var batch=keys.slice(i,i+CHUNK);i+=CHUNK;
        var fd=new URLSearchParams();fd.set('dbc_action','clean_batch');fd.set('rows',batch.join('\n'));
        post(fd).then(function(j){
          if(j&&j.ok){cleaned+=j.cleaned||0;skipped+=j.skipped||0;bytes+=j.removed_bytes||0;}
          else{skipped+=batch.length;}
          done+=batch.length;onProgress(done,total,cleaned,skipped);
          setTimeout(next,0);
        }).catch(function(){skipped+=batch.length;done+=batch.length;onProgress(done,total,cleaned,skipped);setTimeout(next,0);});
      }
      onProgress(0,total,0,0);next();
    });
  }
  // bulk clean selected rows (chunked + progress)
  document.addEventListener('click',function(e){
    var b=e.target.closest('#dbCleanSel'); if(!b)return;
    var rows=pickRows().filter(function(c){return c.checked;}).map(function(c){var tr=c.closest('tr');return [tr.getAttribute('data-db'),tr.getAttribute('data-table'),tr.getAttribute('data-field'),tr.getAttribute('data-row')].join('|');});
    if(!rows.length)return;
    if(!confirm('Clean '+rows.length+' selected row(s)?\n\nEvery detected injection snippet is removed and each original value is backed up first (restorable).'))return;
    progShow('Cleaning '+rows.length+' row(s)…');
    runChunks(rows,progUpd).then(function(r){
      var fd=new URLSearchParams();fd.set('dbc_action','bulk_report');fd.set('kind','db_clean_bulk');fd.set('flagged',r.total);fd.set('cleaned',r.cleaned);fd.set('skipped',r.skipped);fd.set('removed_bytes',r.bytes);
      post(fd).then(function(){progDone((r.cancelled?'Stopped. ':'Done. ')+'Cleaned '+r.cleaned+' row(s)'+(r.skipped?' · '+r.skipped+' skipped':'')+'.'+((r.cleaned===0&&r.skipped>0)?'  These are likely whole-page spam POSTS with no strippable snippet — use “🗑 Trash selected posts” for those.':'  Cleaned rows are removed from the list.'));setTimeout(function(){location.reload();},2600);});
    });
  });
  // Fix whole database: phase 1 backup (mysqldump) → phase 2 chunked clean → summary report
  document.addEventListener('click',function(e){
    var b=e.target.closest('.db-mini.fixdb'); if(!b)return;
    var db=b.getAttribute('data-db'),acct=b.getAttribute('data-account');
    if(!confirm('Backup & clean database "'+db+'" (account: '+acct+')?\n\n1) A full mysqldump of the database is saved into the client\'s home (~/smpro_db_backups) first.\n2) Every Imunify-flagged injection in this database is then removed automatically.\n\nThis is restorable from the backup. Continue?'))return;
    progShow('Backing up database '+db+'…');
    pSub.textContent='Running mysqldump into the client\'s home — this can take a moment…';pCancel.style.display='none';
    var fb=new URLSearchParams();fb.set('dbc_action','fixdb_backup');fb.set('db',db);fb.set('account',acct);
    post(fb).then(function(j){
      if(!j||!j.ok){progDone('⚠ '+((j&&j.msg)||'Backup failed — nothing was changed.'));return;}
      pCancel.style.display='';pTitle.textContent='Cleaning '+db+' — '+j.rows.length+' row(s)…';
      var backup=j.backup,backupName=j.backup_name,backupBytes=j.backup_bytes,flagged=j.rows.length;
      runChunks(j.rows,progUpd).then(function(r){
        var fd=new URLSearchParams();fd.set('dbc_action','bulk_report');fd.set('kind','db_fix');fd.set('account',acct);fd.set('db',db);fd.set('flagged',flagged);fd.set('cleaned',r.cleaned);fd.set('skipped',r.skipped);fd.set('removed_bytes',r.bytes);fd.set('backup',backup);fd.set('backup_bytes',backupBytes);
        post(fd).then(function(){progDone((r.cancelled?'Stopped. ':'Done. ')+'Backed up to '+backupName+' · cleaned '+r.cleaned+' row(s)'+(r.skipped?' · '+r.skipped+' skipped/already-clean':'')+'.');});
      });
    }).catch(function(){progDone('⚠ Backup request failed — nothing was changed.');});
  });
  refreshSel();
})();
</script>
<style>
/* ---- overview strip + sticky navigator + collapsible cards + folds + pager (pattern: firewall-status.php) ---- */
.fw-kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:12px 0}
@media(max-width:640px){.fw-kpis{grid-template-columns:repeat(2,1fr)}}
.fw-nav{position:sticky;top:calc(var(--toph,52px) + 6px);z-index:5;display:flex;gap:6px;flex-wrap:wrap;align-items:center;padding:8px 10px;margin:0 0 14px;background:var(--card);border:1px solid var(--line);border-radius:12px;box-shadow:0 2px 10px rgba(0,0,0,.05)}
.fw-nav a{font-size:12px;font-weight:700;text-decoration:none;color:var(--ink);padding:4px 10px;border-radius:20px;border:1px solid var(--line);white-space:nowrap}
.fw-toggle{cursor:pointer;user-select:none}.fw-toggle:hover{background:var(--bg)}
.gl-fold{margin:6px 0}.gl-fold>summary{cursor:pointer;list-style:none;font-size:12.5px;font-weight:700;color:var(--brand);display:flex;align-items:center;gap:6px}
.gl-fold>summary::-webkit-details-marker{display:none}
.gl-fold>summary .gl-chev{display:inline-block;transition:transform .15s;font-weight:800}.gl-fold[open]>summary .gl-chev{transform:rotate(90deg)}
.fw-pg{display:flex;gap:8px;align-items:center;flex-wrap:wrap;padding:8px 16px;border-bottom:1px solid var(--line);font-size:12px;color:var(--muted)}
.fw-pg input{border:1px solid var(--line);border-radius:8px;padding:5px 9px;font-size:12.5px;min-width:180px;background:var(--card);color:inherit}
.fw-pg .sp{flex:1}.fw-pg button{font-size:11.5px;font-weight:700;border:1px solid var(--line);border-radius:7px;padding:3px 9px;cursor:pointer;background:var(--card);color:var(--ink)}
.fw-pg button:disabled{opacity:.45;cursor:default}.fw-pg .n{font-variant-numeric:tabular-nums}
tr.fw-pghide{display:none !important}
</style>
<script>
(function(){
  // make every section card collapsible — click its header to open/close; the choice is remembered per section
  var KEY='smpro:database-cleanup:open', SEL='.card > .im-head, .card > .db-l2-hd, .card > .db-af-hd', EXTRA='';
  var open={};
  try{ open=JSON.parse(localStorage.getItem(KEY)||'{}')||{}; }catch(err){ open={}; }
  function remember(){ try{ localStorage.setItem(KEY, JSON.stringify(open)); }catch(err){} }
  function toggleOf(card){ for(var i=0;i<card.children.length;i++){ var c=card.children[i]; if(c.classList&&c.classList.contains('fw-toggle')) return c; } return null; }
  function openCard(id, scroll){
    var el=document.getElementById(id); if(!el) return;
    var node=el;
    while(node && node!==document.body){
      if(node.classList && node.classList.contains('card')){ var th=toggleOf(node); if(th && !node.classList.contains('fw-open')){ node.classList.add('fw-open'); th.setAttribute('aria-expanded','true'); open[th.getAttribute('data-fold')]=true; remember(); } }
      if(node.tagName==='DETAILS' && !node.open) node.open=true;
      node=node.parentElement;
    }
    if(el.tagName!=='DETAILS' && el.classList.contains('card') && !toggleOf(el)){ var d=el.querySelector('details'); if(d && !d.open) d.open=true; }
    if(scroll){ el.style.scrollMarginTop='120px'; try{ el.scrollIntoView({behavior:'smooth',block:'start'}); }catch(e2){ el.scrollIntoView(); } }   // the page scrolls inside .smpro-main
  }
  var gos=document.querySelectorAll('[data-go]');
  for(var g=0;g<gos.length;g++){ (function(a){
    var tid=a.getAttribute('data-go');
    if(!document.getElementById(tid)){ if(a.parentElement && a.parentElement.classList.contains('fw-nav')) a.style.display='none'; return; }   // chip for a section this page does not have
    a.addEventListener('click',function(e){ e.preventDefault(); openCard(tid,true); var xs=document.querySelectorAll('.fw-nav a'); for(var i=0;i<xs.length;i++){ xs[i].classList.toggle('on', xs[i].getAttribute('data-go')===tid); } try{ history.replaceState(null,'','#'+tid); }catch(err){} });
  })(gos[g]); }
  function setAll(on){
    var cards=document.querySelectorAll('.smpro-main .card');
    for(var i=0;i<cards.length;i++){ var th=toggleOf(cards[i]); if(!th) continue; cards[i].classList.toggle('fw-open',on); th.setAttribute('aria-expanded',on?'true':'false'); open[th.getAttribute('data-fold')]=on; }
    if(EXTRA){ var ds=document.querySelectorAll(EXTRA); for(var k=0;k<ds.length;k++){ ds[k].open=on; } }
    remember();
  }
  var oa=document.getElementById('dbOpenAll'), ca=document.getElementById('dbCloseAll');
  if(oa) oa.addEventListener('click',function(){ setAll(true); });
  if(ca) ca.addEventListener('click',function(){ setAll(false); });
  var ths=document.querySelectorAll(SEL);
  for(var t=0;t<ths.length;t++){ (function(th, n){
    var card=th.parentElement; if(!card||!card.classList.contains('card')) return;
    var body=document.createElement('div'); body.className='fw-collapse';
    while(th.nextSibling){ body.appendChild(th.nextSibling); }
    card.appendChild(body);
    th.classList.add('fw-toggle');
    if(!th.querySelector('.fw-chev')) th.insertAdjacentHTML('afterbegin','<span class="fw-chev">&#9656;</span> ');
    // A stable name for this section: its own heading text (position would move every remembered state when a section is added above it).
    var id=(th.textContent||'').replace(/\s+/g,' ').trim().slice(0,60) || ('card'+n);
    th.setAttribute('data-fold', id);
    var closedByDefault=card.hasAttribute('data-fold-closed');
    var isOpen=Object.prototype.hasOwnProperty.call(open,id) ? !!open[id] : !closedByDefault;
    card.classList.toggle('fw-open', isOpen);
    th.setAttribute('role','button'); th.setAttribute('tabindex','0'); th.style.cursor='pointer'; th.setAttribute('aria-expanded', isOpen?'true':'false');
    function toggle(){ var now=card.classList.toggle('fw-open'); th.setAttribute('aria-expanded', now?'true':'false'); open[id]=now; remember(); }
    th.addEventListener('click',function(e){ if(e.target.closest('a,button,input,select,label,textarea,summary')) return; toggle(); });   // header controls keep working
    th.addEventListener('keydown',function(e){ if(e.key===' '||e.key==='Enter'||e.key==='Spacebar'){ e.preventDefault(); toggle(); } });
  })(ths[t], t); }
  if(location.hash && document.getElementById(location.hash.slice(1))) setTimeout(function(){ openCard(location.hash.slice(1), true); }, 150);
  window.smproOpenCard=openCard;

  // client-side filter + paging (50/page) for a PHP-rendered table: rows carry data-row, hidden rows get .fw-pghide
  function smproPager(tbl, opt){
    opt=opt||{}; var per=opt.per||50; if(!tbl||!tbl.tBodies||!tbl.tBodies[0]) return null;
    var tb=tbl.tBodies[0], rows=[], i;
    for(i=0;i<tb.rows.length;i++){ if(tb.rows[i].hasAttribute('data-row')) rows.push(tb.rows[i]); }
    if(rows.length<(opt.min||12)) return null;
    var wrap=tbl.parentElement, bar=document.createElement('div'); bar.className='fw-pg';
    bar.innerHTML=(opt.nofilter?'':'<input type="search" placeholder="'+(opt.ph||'Filter rows\u2026')+'">')+'<span class="sp"></span><span class="n fw-pginfo"></span><button type="button" class="fw-pgprev">&#8249; prev</button><span class="n fw-pgpos"></span><button type="button" class="fw-pgnext">next &#8250;</button>';
    wrap.parentElement.insertBefore(bar, wrap);
    var inp=bar.querySelector('input'), info=bar.querySelector('.fw-pginfo'), pos=bar.querySelector('.fw-pgpos'), prev=bar.querySelector('.fw-pgprev'), next=bar.querySelector('.fw-pgnext');
    var q='', page=0;
    function textOf(tr){ return (tr.getAttribute('data-search')||tr.textContent||'').replace(/\s+/g,' ').toLowerCase(); }
    function hide(tr,h){ tr.classList.toggle('fw-pghide',h); if(opt.follow){ var nx=tr.nextElementSibling; if(nx&&nx.classList.contains(opt.follow)) nx.classList.toggle('fw-pghide',h); } }
    function draw(){
      var view=[]; for(var k=0;k<rows.length;k++){ var tr=rows[k]; var ok=(!q||textOf(tr).indexOf(q)!==-1) && !(opt.skip&&opt.skip(tr)); if(ok) view.push(tr); else hide(tr,true); }
      var pages=Math.max(1,Math.ceil(view.length/per)); if(page>=pages) page=pages-1; if(page<0) page=0;
      for(var j=0;j<view.length;j++){ hide(view[j], j<page*per || j>=(page+1)*per); }
      var a=view.length?page*per+1:0, b=Math.min((page+1)*per,view.length);
      info.textContent=(view.length>per?('showing '+a+'\u2013'+b+' of '):'')+view.length+' of '+rows.length+' rows';
      pos.textContent=(page+1)+' / '+pages; prev.disabled=page<=0; next.disabled=page>=pages-1;
      var ctrl=rows.length>per?'':'none'; prev.style.display=ctrl; next.style.display=ctrl; pos.style.display=ctrl;
    }
    if(inp) inp.addEventListener('input',function(){ q=inp.value.trim().toLowerCase(); page=0; draw(); });
    prev.addEventListener('click',function(){ if(page>0){ page--; draw(); } });
    next.addEventListener('click',function(){ page++; draw(); });
    draw(); return {draw:draw};
  }
  window.smproPager=smproPager;

  // Injections: the rows carry bulk checkboxes driven by the page's own JS, so they are never paged — the filter only
  // hides whole account GROUPS (header row + its rows) that do not match, and says how many are left.
  (function(){
    var inp=document.getElementById('dbGrpFind'), info=document.getElementById('dbGrpInfo'); if(!inp) return;
    var heads=document.querySelectorAll('tr.db-grouprow'); if(!heads.length){ inp.parentElement.style.display='none'; return; }
    function txt(el){ return (el.textContent||'').replace(/\s+/g,' ').toLowerCase(); }
    function apply(){
      var q=inp.value.trim().toLowerCase(), shown=0;
      for(var i=0;i<heads.length;i++){
        var gid=heads[i].getAttribute('data-gid'), rows=document.querySelectorAll('tr.'+gid), s=txt(heads[i]), r;
        for(r=0;r<rows.length;r++){ if(!rows[r].classList.contains('db-insprow')) s+=' '+txt(rows[r]); }
        var hideIt=!!q && s.indexOf(q)===-1;
        heads[i].classList.toggle('fw-pghide',hideIt);
        for(r=0;r<rows.length;r++){ rows[r].classList.toggle('fw-pghide',hideIt); }
        if(!hideIt) shown++;
      }
      info.textContent=shown+' of '+heads.length+' account(s)'+(q?' match':'');
    }
    inp.addEventListener('input',apply); apply();
  })();
  // "Analyze" on a finding scrolls to the analyzer card — make sure that card is open when it does
  document.addEventListener('click',function(e){ if(e.target.closest && e.target.closest('.dbAnalyze,.dbFindFile')) openCard('db-analyze',false); });
  var rs=document.getElementById('db-restore'); if(rs) smproPager(rs.querySelector('table.smpro-table'), {follow:'db-rvrow', ph:'Filter restores (account, database, table)\u2026'});
  var rp=document.getElementById('db-reports'); if(rp) smproPager(rp.querySelector('table.smpro-table'), {ph:'Filter reports (account, database, type)\u2026'});
})();
</script>

<?php
smpro_layout_footer();
