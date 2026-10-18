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
    @file_put_contents(SMPRO_DBC_STATUS, json_encode($map, JSON_UNESCAPED_SLASHES), LOCK_EX);
    @chmod(SMPRO_DBC_STATUS, 0600);
}
/** Merge classification/clean results into the cache (key => [state,snips,ts]). */
function smpro_db_status_merge(array $entries) {
    $m = smpro_db_status_load();
    foreach ($entries as $key => $e) $m[$key] = ['state' => $e['state'], 'snips' => (int)($e['snips'] ?? 0), 'ts' => time()];
    smpro_db_status_save($m);
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
    $bin = smpro_db_bin(); if ($bin === '') return $cache[$scope] = [];
    // The Imunify malware list is expensive — cache the raw JSON for 90s so navigating
    // to/within this page doesn't re-run a slow query each time (was a 60s page hang).
    $cf = sys_get_temp_dir() . '/smpro_dbinj.json';
    $raw = (is_file($cf) && (time() - (int)@filemtime($cf)) < 90) ? (string)@file_get_contents($cf) : '';
    if ($raw === '') {
        $raw = (string)@shell_exec('timeout 30 ' . escapeshellarg($bin) . ' malware history list --limit 4000 --json 2>/dev/null');
        if (trim($raw) !== '') { @file_put_contents($cf, $raw, LOCK_EX); @chmod($cf, 0600); }
    }
    $j = json_decode($raw, true); $items = is_array($j) ? ($j['items'] ?? []) : [];
    // latest event per (db,table,field,row); keep only those whose latest is 'found'
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
                'family'=>smpro_db_family($r['signature_id'] ?? ''), 'event'=>(string)($r['event'] ?? ''), 'ctime'=>$ct];
        }
    }
    $rows = array_values(array_filter($byKey, fn($r) => $r['event'] === 'found'));
    usort($rows, fn($a, $b) => $b['ctime'] <=> $a['ctime']);
    return $cache[$scope] = $rows;
}
/** Verify a target (db,table,field,row) is in the current injection list — safety gate (uses the cached full list). */
function smpro_db_is_flagged($db, $table, $field, $row) {
    static $idx = null;
    if ($idx === null) { $idx = []; foreach (smpro_db_injections() as $r) $idx[$r['db'].'|'.$r['table'].'|'.$r['field'].'|'.(int)$r['row']] = $r; }
    return $idx[$db.'|'.$table.'|'.$field.'|'.(int)$row] ?? null;
    return null;
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
    $hits = 0; $distinct = 0; $found = [];
    foreach (smpro_db_spam_terms() as $t) {
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
    @file_put_contents(SMPRO_DBC_REPORTS . '/' . $id . '.json', json_encode($d, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), LOCK_EX);
    @chmod(SMPRO_DBC_REPORTS . '/' . $id . '.json', 0600);
    return $id;
}
function smpro_db_reports($limit = 40) {
    $rows = [];
    foreach (glob(SMPRO_DBC_REPORTS . '/*.json') ?: [] as $f) { $j = json_decode((string)@file_get_contents($f), true); if (is_array($j)) $rows[] = $j; }
    usort($rows, fn($a, $b) => ($b['ts'] ?? 0) <=> ($a['ts'] ?? 0));
    return array_slice($rows, 0, $limit);
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
    $ok = stripos($out, 'error') === false;
    return ['ok'=>$ok,'backup'=>$bak,'removed'=>strlen($orig)-strlen($clean),'err'=>$ok?'':trim(mb_substr($out,0,160))];
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
    if ($stat) smpro_db_status_merge($stat);   // remember cleaned rows across reloads
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
    @file_put_contents($dir . '/' . date('Ymd_His') . "_{$db}_{$table}_TRASH_{$row}.txt", "original post_status={$cur}\n\n" . (string)$val, LOCK_EX);
    $sql = "UPDATE `$db`.`$table` SET post_status='trash' WHERE `$pk`=$row LIMIT 1";
    $out = (string)@shell_exec('timeout 30 ' . smpro_db_cli() . smpro_db_defaults() . ' -e ' . escapeshellarg($sql) . ' 2>&1');
    $ok = stripos($out, 'error') === false;
    return ['ok'=>$ok,'prev'=>$cur,'msg'=>$ok?'Trashed (restorable from WP trash / backup).':'UPDATE failed: '.trim(mb_substr($out,0,160))];
}
/** Trash a batch of selected spam posts. Only acts on rows that are flagged AND spam content AND a posts table. */
function smpro_db_trash_batch(array $keys) {
    $trashed = 0; $skipped = 0;
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
        if (!empty($r['ok'])) $trashed++; else $skipped++;
    }
    return ['trashed'=>$trashed, 'skipped'=>$skipped];
}

/* ---------------- full-database backup (into the client's home) + bulk fix ---------------- */
/** Resolve an account's home directory (getent → /home/<acct> fallback). */
function smpro_db_account_home($account) {
    if (!preg_match('/^[a-z0-9._-]+$/i', (string)$account)) return '';
    $h = trim((string)@shell_exec('getent passwd ' . escapeshellarg($account) . ' 2>/dev/null | cut -d: -f6'));
    if ($h !== '' && is_dir($h)) return $h;
    return is_dir('/home/' . $account) ? '/home/' . $account : '';
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
        'preview'=>$cut($val,6000)], JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE); exit;
}

/* ---- POST: clean a flagged row (backup + UPDATE only the SELECTED snippets) ---- */
if ($reqMethod === 'POST' && ($_POST['dbc_action'] ?? '') === 'clean') {
    smpro_require_valid_csrf('dbc_act'); smpro_require_root();
    header('Content-Type: application/json');
    $db = (string)($_POST['db'] ?? ''); $table = (string)($_POST['table'] ?? ''); $field = (string)($_POST['field'] ?? ''); $row = (int)($_POST['row'] ?? 0);
    $expectHash = (string)($_POST['hash'] ?? '');
    $sel = array_values(array_filter(array_map('intval', explode(',', (string)($_POST['sel'] ?? ''))), fn($x) => $x >= 0 || $x === 0));
    if ($_POST['sel'] === '' || $sel === []) { echo json_encode(['ok'=>false,'msg'=>'No snippets selected to remove.']); exit; }
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
    echo json_encode(smpro_db_clean_apply($db, $table, $field, $pk, $row, $val, $clean, $flag['account'], count($sel)), JSON_UNESCAPED_SLASHES); exit;
}

/* ---- POST: clean ONE batch of rows (chunked bulk cleaning, drives the progress bar) ---- */
if ($reqMethod === 'POST' && ($_POST['dbc_action'] ?? '') === 'clean_batch') {
    smpro_require_valid_csrf('dbc_act'); smpro_require_root();
    header('Content-Type: application/json');
    $keys = array_slice(array_filter(array_map('trim', explode("\n", (string)($_POST['rows'] ?? '')))), 0, 50);
    if (!$keys) { echo json_encode(['ok'=>false,'msg'=>'Empty batch.']); exit; }
    echo json_encode(['ok'=>true] + smpro_db_clean_batch($keys), JSON_UNESCAPED_SLASHES); exit;
}

/* ---- POST: trash ONE batch of selected SPAM POSTS (reversible, chunked) ---- */
if ($reqMethod === 'POST' && ($_POST['dbc_action'] ?? '') === 'trash_batch') {
    smpro_require_valid_csrf('dbc_act'); smpro_require_root();
    header('Content-Type: application/json');
    $keys = array_slice(array_filter(array_map('trim', explode("\n", (string)($_POST['rows'] ?? '')))), 0, 50);
    if (!$keys) { echo json_encode(['ok'=>false,'msg'=>'Empty batch.']); exit; }
    $r = smpro_db_trash_batch($keys);
    smpro_audit('db_trash', ['trashed'=>$r['trashed'],'skipped'=>$r['skipped']]);
    echo json_encode(['ok'=>true] + $r, JSON_UNESCAPED_SLASHES); exit;
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
    echo json_encode(['ok'=>true,'statuses'=>$out], JSON_UNESCAPED_SLASHES); exit;
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
    echo json_encode(['ok'=>true,'backup'=>$dump['path'],'backup_name'=>basename($dump['path']),'backup_bytes'=>$dump['bytes'],'rows'=>$keys], JSON_UNESCAPED_SLASHES); exit;
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
    echo json_encode(['ok'=>true,'report'=>$rid], JSON_UNESCAPED_SLASHES); exit;
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
<p class="sub">Imunify360 detects malware injected into databases (posts, options…) but can't always clean it precisely. Here you <b>inspect</b> the exact row, see what would be stripped, and apply a <b>precise clean</b> — the original value is backed up first and is fully restorable.</p>

<script>var DBC_CSRF=<?= json_encode($csrf) ?>;</script>
<?php
@ob_flush(); @flush();   // push the chrome to the browser before the (possibly slow) first Imunify query
$inj = smpro_db_injections($scope);
$reports = smpro_db_reports(20);
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

<div class="db-kpis">
  <div class="db-kpi <?= count($inj)?'crit':'good' ?>"><div class="n"><?= number_format(count($inj)) ?></div><div class="l">DB injections (found)</div></div>
  <div class="db-kpi"><div class="n"><?= number_format(count($byAcct)) ?></div><div class="l">Accounts affected</div></div>
  <div class="db-kpi"><div class="n"><?= number_format(count($byTable)) ?></div><div class="l">Table.column targets</div></div>
  <div class="db-kpi"><div class="n"><?= count($reports) ?></div><div class="l">Cleans recorded</div></div>
</div>

<form method="get" action="index.cgi" class="card db-bar">
  <input type="hidden" name="page" value="database-cleanup">
  <label class="db-fld">Account filter<input class="tp-in" name="user" value="<?= smpro_h($scope) ?>" placeholder="all accounts" data-ac="accounts" autocomplete="off"></label>
  <button class="tp-btn primary" type="submit">Filter</button>
  <a class="tp-btn" href="index.cgi?page=imunify360-reports">Imunify360 Reports →</a>
</form>

<?php
// group injections by account → list of rows; track each account's databases
$groups = [];
foreach (array_slice($inj, 0, 1000) as $r) { $groups[$r['account']][] = $r; }
$statusMap = smpro_db_status_load();   // last-known per-row statuses (persisted)
?>
<div class="card" style="padding:0;overflow:hidden">
  <div class="im-head"><b>&#128137; Database injections</b><span class="meta"><?= count($inj) ?> row(s) flagged by Imunify · grouped by account · inspect &amp; clean precisely</span></div>
  <?php if (!$inj): ?><div class="im-empty" style="color:var(--good)">&#10003; No active database injections in scope.</div>
  <?php else: ?>
  <div class="db-toolbar">
    <label class="db-allwrap"><input type="checkbox" id="dbMasterAll"> <b>Select all</b></label>
    <span class="db-selcount" id="dbSelCount">0 selected</span>
    <button class="tp-btn db-checkall" id="dbCheckAll" type="button">&#128269; Check statuses</button>
    <button class="tp-btn db-selectlive" id="dbSelectLive" type="button" style="display:none">&#9889; Select live only</button>
    <button class="tp-btn db-selectspam" id="dbSelectSpam" type="button" style="display:none">&#128465; Select spam posts</button>
    <button class="tp-btn primary db-cleansel" id="dbCleanSel" type="button" disabled>&#129529; Clean selected rows</button>
    <button class="tp-btn db-trashsel" id="dbTrashSel" type="button" disabled>&#128465; Trash selected posts</button>
    <span class="db-statussum" id="dbStatusSum"></span>
  </div>
  <div class="db-tablewrap">
    <table class="smpro-table dbtbl"><thead><tr>
      <th class="db-cbcol"><input type="checkbox" id="dbHeadAll" title="select all"></th>
      <th>Location</th><th>Database</th><th>Status</th><th>Family</th><th>Detected</th><th>Action</th>
    </tr></thead><tbody>
      <?php foreach ($groups as $acct => $rows): $dbs = array_values(array_unique(array_map(fn($x)=>$x['db'], $rows))); $gid = 'g_'.substr(md5($acct),0,8); ?>
        <tr class="db-grouprow" data-gid="<?= $gid ?>">
          <td class="db-cbcol"><input type="checkbox" class="db-groupall" data-gid="<?= $gid ?>" title="select this account"></td>
          <td colspan="3">
            <button type="button" class="db-toggle" data-gid="<?= $gid ?>">&#9662;</button>
            <b class="mono"><?= smpro_h($acct ?: '(unknown)') ?></b>
            <span class="b gray"><?= count($rows) ?> injection(s)</span>
            <span class="meta" style="font-size:11px"><?= smpro_h(implode(', ', array_slice($dbs,0,4))) . (count($dbs)>4?' +'.(count($dbs)-4):'') ?></span>
          </td>
          <td colspan="3" class="db-act db-groupact">
            <span class="db-glive" data-gid="<?= $gid ?>"></span>
            <?php foreach ($dbs as $dbn): ?>
              <button class="db-mini fixdb" type="button" data-db="<?= smpro_h($dbn) ?>" data-account="<?= smpro_h($acct) ?>" title="Full mysqldump into the client's home, then auto-clean every flagged row in this database">&#128737; Backup &amp; clean <?= smpro_h($dbn) ?></button>
            <?php endforeach; ?>
          </td>
        </tr>
        <?php foreach ($rows as $r): $rkey = $r['db'].'|'.$r['table'].'|'.$r['field'].'|'.(int)$r['row']; $cst = $statusMap[$rkey] ?? null; ?>
        <tr class="db-row <?= $gid ?>" data-gid="<?= $gid ?>" data-status="<?= $cst ? smpro_h($cst['state']) : '' ?>" data-db="<?= smpro_h($r['db']) ?>" data-table="<?= smpro_h($r['table']) ?>" data-field="<?= smpro_h($r['field']) ?>" data-row="<?= (int)$r['row'] ?>">
          <td class="db-cbcol"><input type="checkbox" class="db-pickrow" data-gid="<?= $gid ?>"></td>
          <td class="mono"><?= smpro_h($r['table']) ?>.<b><?= smpro_h($r['field']) ?></b> <span class="meta">#<?= (int)$r['row'] ?></span></td>
          <td class="mono"><?= smpro_h($r['db']) ?><div class="meta" style="font-size:11px"><?= smpro_h($r['app']) ?></div></td>
          <td class="db-status"><?= $cst ? smpro_db_status_badge($cst['state'], $cst['snips'] ?? 0) : '<span class="b gray">— not checked</span>' ?></td>
          <td><span class="b red"><?= smpro_h($r['family'] ?: 'malware') ?></span></td>
          <td class="mono" style="font-size:11px"><?= $r['ctime']?smpro_h(date('Y-m-d H:i',(int)$r['ctime'])):'—' ?></td>
          <td class="db-act"><button class="db-mini insp" type="button">&#128269; Inspect</button></td>
        </tr>
        <tr class="db-insprow <?= $gid ?>" style="display:none"><td colspan="7" class="db-inspcell"></td></tr>
        <?php endforeach; ?>
      <?php endforeach; ?>
    </tbody></table>
  </div>
  <div class="im-note">&#128737; <b>Backup &amp; clean</b> saves a full <code>mysqldump</code> of the database into the client's home (<code>~/smpro_db_backups</code>) first, then removes every detected injection. Per-row cleans back up the original value to <code>/home/backup/detections/db</code>. Both are restorable; only Imunify-flagged rows are touched.</div>
  <?php endif; ?>
</div>

<?php if ($reports): ?>
<div class="card" style="padding:0;overflow:hidden;margin-top:14px">
  <div class="im-head"><b>&#128203; Cleanup action reports</b><span class="meta"><?= count($reports) ?> · backups in /home/backup/detections/db</span></div>
  <div class="db-tablewrap" style="max-height:300px"><table class="smpro-table"><thead><tr><th>When</th><th>Type</th><th>Account</th><th>What was cleaned</th><th class="num">Removed</th><th>Backup</th></tr></thead><tbody>
    <?php foreach ($reports as $d): $act = $d['action'] ?? 'db_clean';
        $label = ['db_fix'=>['amber','DB backup+clean'],'db_clean_bulk'=>['amber','bulk clean'],'db_trash'=>['amber','trash spam posts'],'db_clean'=>['gray','row clean']][$act] ?? ['gray',$act]; ?><tr>
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
.db-kpi{background:#fff;border:1px solid var(--line);border-radius:12px;padding:14px;text-align:center}.db-kpi.crit{border-top:3px solid var(--dang)}.db-kpi.good{border-top:3px solid var(--good)}
.db-kpi .n{font-size:23px;font-weight:800}.db-kpi.crit .n{color:var(--dang)}.db-kpi .l{font-size:11px;text-transform:uppercase;color:var(--muted);font-weight:700;margin-top:4px}
.db-bar{display:flex;gap:12px;align-items:flex-end;flex-wrap:wrap;margin:14px 0;padding:14px 16px}
.db-fld{display:flex;flex-direction:column;gap:5px;font-size:11px;text-transform:uppercase;color:var(--muted);font-weight:700}
.tp-in,.tp-sel{border:1px solid var(--line);border-radius:9px;padding:9px 12px;font-size:13px}
.tp-btn{border:1px solid var(--line);border-radius:9px;padding:9px 15px;font-size:13px;font-weight:600;cursor:pointer;text-decoration:none;color:var(--ink);background:#fff}.tp-btn.primary{background:var(--brand);color:#fff;border-color:var(--brand)}
.im-head{padding:12px 16px;border-bottom:1px solid var(--line);font-weight:700;font-size:14px;display:flex;align-items:center;gap:10px}.im-head .meta{margin-left:auto;color:var(--muted);font-size:12px}
.im-note{padding:10px 16px;background:var(--warn-bg);color:#8a6516;font-size:12px;border-top:1px solid var(--line)}.im-empty{padding:18px;text-align:center;color:var(--muted)}
.db-tablewrap{overflow:auto;max-height:520px}.db-tablewrap thead th{position:sticky;top:0;background:#fafbfe;z-index:1;box-shadow:inset 0 -1px 0 var(--line)}
.smpro-table{width:100%;border-collapse:collapse;font-size:12.5px}.smpro-table th,.smpro-table td{padding:8px 12px;text-align:left;border-bottom:1px solid var(--line);white-space:nowrap;vertical-align:top}
.smpro-table th{font-size:11px;text-transform:uppercase;color:var(--muted)}.smpro-table td.num,.smpro-table th.num{text-align:right}
.mono{font-family:ui-monospace,Consolas,monospace}.meta{color:var(--muted)}
.b{display:inline-block;font-size:11px;font-weight:700;padding:2px 8px;border-radius:20px}.b.red{background:var(--dang-bg);color:var(--dang)}.b.green{background:var(--good-bg);color:var(--good)}.b.gray{background:#f1f5f9;color:#475569}
.db-toolbar{display:flex;align-items:center;gap:10px;flex-wrap:wrap;padding:10px 16px;border-bottom:1px solid var(--line);background:#fafbfe}
.db-allwrap{font-size:13px;cursor:pointer;display:flex;align-items:center;gap:6px}
.db-selcount{font-size:12px;color:var(--muted);font-weight:700}
.db-statussum{font-size:12px;color:var(--muted);font-weight:700;margin-left:auto}
.db-checkall{border-color:#c7d2fe !important;background:#eef2ff !important;color:#3730a3 !important}
.db-selectlive{border-color:#fca5a5 !important;background:#fef2f2 !important;color:var(--dang) !important}
.db-selectspam,.db-trashsel{border-color:#fcd34d !important;background:#fffbeb !important;color:#92400e !important}
.db-trashsel:disabled{opacity:.5;cursor:not-allowed}
.db-status .b{white-space:nowrap}
.db-groupact{text-align:right}
.db-cbcol{width:34px;text-align:center !important}
.db-grouprow{background:#f3f6ff}.db-grouprow td{border-bottom:1px solid var(--line);vertical-align:middle}
.db-grouprow .b.gray{margin:0 6px}
.db-toggle{border:none;background:transparent;cursor:pointer;font-size:13px;color:var(--muted);padding:0 6px;transition:transform .15s}.db-toggle.collapsed{transform:rotate(-90deg)}
.db-row td{white-space:nowrap}
.amber{background:#fef3c7;color:#92400e}
.db-mini{font-size:11px;font-weight:700;border:1px solid var(--line);background:#fff;border-radius:7px;padding:4px 10px;cursor:pointer;margin:1px}
.db-mini.fixdb{border-color:#fcd34d;background:#fffbeb;color:#92400e}
.db-mini.trash1{border-color:#fcd34d;background:#fffbeb;color:#92400e;margin-top:8px}
.db-box-spam{margin:6px 0;padding:9px 12px;background:#fffbeb;border:1px solid #fde68a;border-radius:9px;font-size:12.5px;color:#7c5e16}
.db-mini.insp{border-color:#c7d2fe;background:#eef2ff;color:#3730a3}
.db-mini.clean{border-color:#bbf7d0;background:#f0fdf4;color:#15803d}
.db-inspcell{background:#fbfcff;padding:12px 16px !important;white-space:normal}
.db-box{font-size:12px}.db-box h4{margin:0 0 6px;font-size:12px}
.db-snip{display:block;font-family:ui-monospace,Consolas,monospace;font-size:11px;background:#2b1414;color:#ffb3b3;border-radius:8px;padding:8px 10px;margin:6px 0;white-space:pre-wrap;word-break:break-all;max-height:150px;overflow:auto}
.db-selbar{margin:6px 0;font-size:12px}.db-selbar label{cursor:pointer;font-weight:600}
.db-snipwrap{display:block;border:1px solid var(--line);border-radius:9px;padding:8px 10px;margin:7px 0;background:#fff;cursor:pointer}
.db-snipwrap>input{margin-right:6px;vertical-align:middle}
.db-sniphd{display:inline-flex;gap:8px;align-items:center;font-size:11px}
.db-host{font-family:ui-monospace,Consolas,monospace;font-weight:700;color:var(--dang)}
.db-prev{font-family:ui-monospace,Consolas,monospace;font-size:11px;background:#0f172a;color:#cbd5e1;border-radius:8px;padding:8px 10px;white-space:pre-wrap;word-break:break-all;max-height:200px;overflow:auto;margin:6px 0}
.db-stat{display:flex;gap:14px;flex-wrap:wrap;font-size:12px;margin:6px 0}.db-stat b{color:var(--ink)}
.db-progress-overlay{position:fixed;inset:0;background:rgba(15,23,42,.55);z-index:9999;display:flex;align-items:center;justify-content:center;backdrop-filter:blur(2px)}
.db-progress-box{background:#fff;border-radius:16px;padding:26px 28px;width:min(460px,92vw);box-shadow:0 20px 60px rgba(0,0,0,.35);text-align:center}
.db-progress-title{font-size:16px;font-weight:800;margin-bottom:16px}
.db-progress-track{height:14px;background:#eef2f7;border-radius:20px;overflow:hidden}
.db-progress-fill{height:100%;width:0;background:linear-gradient(90deg,var(--brand),#6366f1);border-radius:20px;transition:width .3s ease}
.db-progress-meta{display:flex;justify-content:space-between;font-size:13px;font-weight:700;margin-top:8px}
.db-progress-sub{font-size:12px;color:var(--muted);margin-top:6px;min-height:16px}
.db-progress-cancel{margin-top:16px}
.db-progress-box.done .db-progress-fill{background:var(--good)}
</style>
<script>
(function(){
  function post(fd){fd.set('smpro_csrf',DBC_CSRF);return fetch('index.cgi?page=database-cleanup',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'}).then(function(r){return r.json();});}
  function esc(s){return String(s==null?'':s).replace(/[<>&]/g,function(c){return{'<':'&lt;','>':'&gt;','&':'&amp;'}[c];});}
  function rowData(tr){return {db:tr.getAttribute('data-db'),table:tr.getAttribute('data-table'),field:tr.getAttribute('data-field'),row:tr.getAttribute('data-row')};}
  var TYPE_LABEL={extlink:'External spam link',script:'Injected &lt;script&gt;',iframe:'Hidden &lt;iframe&gt;',php:'Injected PHP',eval:'Obfuscated eval()',hidden:'Hidden spam block'};
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
        post(fr).then(function(){progDone((cancelFlag?'Stopped. ':'Done. ')+'Trashed '+trashed+' spam post(s)'+(skipped?' · '+skipped+' skipped':'')+'.');});
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
      post(fd).then(function(){progDone((r.cancelled?'Stopped. ':'Done. ')+'Cleaned '+r.cleaned+' row(s)'+(r.skipped?' · '+r.skipped+' skipped/already-clean':'')+'.');});
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
<?php
smpro_layout_footer();
