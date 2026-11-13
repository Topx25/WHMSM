<?php
/**
 * includes/sitewatch.php - Site Watch: what happened to each site, who did it, and fix / lock it down.
 *
 * Per site, on a schedule (or on demand):
 *   - files: a fingerprint of the site's code files (php, .htaccess, js, html, ini) compared with the last check ->
 *     new / changed / deleted, with the dangerous ones flagged (PHP inside uploads, hidden PHP, .htaccess);
 *   - who: each flagged change is matched to the file-change journal (File Manager / FTP / SSH, login, address) or,
 *     when the site itself wrote it, to the web request that did (POST in the same seconds);
 *   - ran: requests to a flagged file in the site's access logs (how often, from which addresses);
 *   - database (WordPress): administrators, siteurl/home, active plugins, injected script in posts/options, compared
 *     with the last snapshot;
 *   - checks: files reachable from the web that must not be (.env, .git, dumps, backups), PHP allowed in uploads.
 * Events go to the site's history, to the report rules (which sites -> which numbers, from which level, when), and,
 * for the sites the operator selected for automatic protection, the safe steps run at once (quarantine, block the
 * addresses that ran the file, deny PHP in uploads). Every change is backed up and recorded for undo.
 * Database edits (removing an administrator) only ever run when a person presses the button.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

if (!defined('SMPRO_SW_DIR')) define('SMPRO_SW_DIR', SMPRO_VARLIB . '/sitewatch');
require_once __DIR__ . '/swdeep.php';   // deep checks: core checksums, cloaking, shell locks, file-manager plugins

/* ============================ storage ============================ */
function smpro_sw_path(string $f): string { $p = SMPRO_SW_DIR . '/' . $f; @is_dir(dirname($p)) || @mkdir(dirname($p), 0700, true); return $p; }
function smpro_sw_load(string $f, array $def = []): array { $p = smpro_sw_path($f); $j = @is_file($p) ? json_decode((string)@file_get_contents($p), true) : null; return is_array($j) ? $j : $def; }
function smpro_sw_save(string $f, array $d): bool {
    $p = smpro_sw_path($f); $t = $p . '.tmp.' . getmypid();
    if (@file_put_contents($t, json_encode($d, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE), LOCK_EX) === false) return false;
    @chmod($t, 0600); return @rename($t, $p);
}
function smpro_sw_key(string $dom): string { return preg_replace('/[^a-z0-9.-]/', '', strtolower($dom)); }

function smpro_sw_cfg(): array {
    $c = smpro_sw_load('cfg.json') + ['auto' => false, 'scope' => 'all', 'sites' => [], 'files_min' => 60, 'db_min' => 1440, 'keep_days' => 90,
        'protect' => [], 'alerts' => [], 'rules' => []];
    $c['alerts'] += ['upload_php' => true, 'shell_run' => true, 'new_admin' => true, 'db_inject' => true, 'htaccess' => false, 'new_ip' => false];
    return $c;
}
function smpro_sw_cfg_save(array $patch): array {
    $c = array_replace(smpro_sw_cfg(), $patch);
    $c['auto'] = !empty($c['auto']); $c['scope'] = in_array($c['scope'], ['all', 'list'], true) ? $c['scope'] : 'all';
    $clean = fn($a) => array_values(array_unique(array_filter(array_map('smpro_sw_key', (array)$a))));
    $c['sites'] = $clean($c['sites']); $c['protect'] = $clean($c['protect']);
    $c['files_min'] = max(15, min(1440, (int)$c['files_min'])); $c['db_min'] = max(60, min(10080, (int)$c['db_min'])); $c['keep_days'] = max(7, min(365, (int)$c['keep_days']));
    smpro_sw_save('cfg.json', $c); smpro_sw_cron_sync();
    return $c;
}
/** The sites being watched: [domain => target]. */
function smpro_sw_targets(): array {
    $all = function_exists('smpro_sdb_targets') ? smpro_sdb_targets() : [];
    $c = smpro_sw_cfg();
    return $c['scope'] === 'list' ? array_intersect_key($all, array_flip($c['sites'])) : $all;
}

/* ============================ severity ============================ */
function smpro_sw_rank(string $sev): int { return ['info' => 1, 'warning' => 2, 'critical' => 3][$sev] ?? 0; }

/* ============================ files ============================ */
/** Fingerprint of the code files under a web root: [relpath => "size|mtime"]. Null when it cannot look. */
/** The real web root, only when it sits inside the account's own home (a docroot symlinked into another account is refused). */
function smpro_sw_doc_ok(string $doc, string $user): bool {
    $r = @realpath($doc); $pw = function_exists('posix_getpwnam') && $user !== '' ? @posix_getpwnam($user) : null;
    $home = $pw ? (string)@realpath((string)$pw['dir']) : '';
    return $r !== false && $home !== '' && strpos($r . '/', rtrim($home, '/') . '/') === 0;
}
function smpro_sw_scan_files(string $doc): ?array {
    if (!@is_dir($doc) || strpos((string)@realpath($doc), '/home') !== 0) return null;
    $cmd = 'timeout 120 find ' . escapeshellarg($doc) . ' -xdev \( -path "*/cache/*" -o -path "*/node_modules/*" -o -path "*/.git/objects/*" -o -name "*.smpro-*" \) -prune -o -type f'
         . ' \( -iname "*.php" -o -iname "*.php[0-9]" -o -iname "*.phtml" -o -iname "*.phar" -o -name ".htaccess" -o -name ".user.ini" -o -iname "*.js" -o -iname "*.html" -o -iname "*.htm" -o -iname "*.cgi" -o -iname "*.pl" -o -iname "*.sh" \)'
         . ' -printf "%P\t%s\t%T@\n" 2>/dev/null; echo "__SMPRO_RC=$?"';
    $raw = (string)@shell_exec($cmd);
    // a listing cut by the time limit (rc 124) or that never ran is not a fingerprint: comparing with it would report
    // every missing file as deleted now and as new next time
    if (!preg_match('/__SMPRO_RC=(\d+)\s*$/', $raw, $m) || (int)$m[1] === 124 || (int)$m[1] === 137) return null;
    $out = [];
    foreach (explode("\n", $raw) as $l) { $p = explode("\t", $l); if (count($p) === 3 && $p[0] !== '') $out[$p[0]] = $p[1] . '|' . (int)$p[2]; if (count($out) > 400000) return null; }
    return $out;
}
function smpro_sw_is_php(string $rel): bool { return (bool)preg_match('/\.(php\d?|phtml|phar)$/i', $rel); }
/** How dangerous a new or changed file is, by where it is and what it is called. [sev, why] or null when ordinary. */
function smpro_sw_classify_file(string $rel, bool $isNew, int $size = -1): ?array {
    $b = basename($rel);
    // Uploads = WordPress' uploads folder, or an uploads/images folder at the top of the web root. NOT any folder that
    // happens to be called "files" or "img" inside a plugin, a theme or WordPress itself (wp-includes/.../Files/,
    // plugins/x/assets/img/index.php): those are the software's own code and flagged thousands of false alarms.
    if (smpro_sw_is_php($rel) && !preg_match('#^(wp-includes|wp-admin)/#', $rel) && !preg_match('#(^|/)wp-content/(plugins|themes|mu-plugins)/#', $rel)
        && preg_match('#^(wp-content/uploads|uploads|images|img|upload|media)/#i', $rel)) {
        if ($b === 'index.php' && $size >= 0 && $size <= 200) return null;   // the "silence is golden" placeholder
        return ['critical', 'PHP file in an uploads/images folder'];
    }
    if (smpro_sw_is_php($rel) && preg_match('#(^|/)\.[^/]+#', $rel)) return ['critical', 'PHP file that is hidden or in a hidden folder'];
    if (smpro_sw_is_php($rel) && preg_match('/\.(jpe?g|png|gif|ico|txt)\.php$|^[a-f0-9]{8,}\.php$/i', $b)) return ['critical', 'PHP file with a disguised name'];
    if ($b === '.htaccess' || $b === '.user.ini') return ['warning', $b . ' ' . ($isNew ? 'created' : 'changed')];
    if (!$isNew && in_array($b, ['index.php', 'wp-config.php', 'wp-load.php', 'wp-settings.php', 'functions.php'], true)) return ['warning', $b . ' changed'];
    if ($isNew && preg_match('/\.(cgi|pl|sh|phar)$/i', $b)) return ['warning', 'New script file'];
    return null;
}

/* ============================ who + ran ============================ */
/** The access log files of a domain (both schemes). */
function smpro_sw_domlogs(string $dom): array {
    $out = [];
    foreach (['/etc/apache2/logs/domlogs', '/usr/local/apache/domlogs', '/var/log/apache2/domlogs'] as $d) foreach ([$dom, $dom . '-ssl_log'] as $n) {
        if (@is_file("$d/$n")) $out[] = "$d/$n";
        foreach ((array)@glob("$d/*/$n") as $f) if (@is_file($f)) $out[] = $f;
    }
    return array_values(array_unique($out));
}
/** The last lines of a domain's access logs, parsed: [ts, ip, method, path, code]. */
function smpro_sw_access(string $dom, int $lines = 40000): array {
    $out = [];
    foreach (smpro_sw_domlogs($dom) as $f) {
        foreach (explode("\n", (string)@shell_exec('tail -n ' . (int)$lines . ' ' . escapeshellarg($f) . ' 2>/dev/null')) as $l) {
            if (!preg_match('#^(\S+) \S+ \S+ \[([^\]]+)\] "(GET|POST|PUT|HEAD|OPTIONS|DELETE|PATCH) (\S+)[^"]*" (\d{3})#', $l, $m)) continue;
            $ts = strtotime($m[2]); if (!$ts) continue;
            $out[] = [$ts, $m[1], $m[3], (string)parse_url($m[4], PHP_URL_PATH), (int)$m[5]];
        }
    }
    return $out;
}
/** Who put a file there: the file-change journal first, then a web request of the site itself in the same seconds. */
function smpro_sw_who(string $user, string $abs, int $mtime, array $access, string $urlBase): array {
    if (function_exists('smpro_fa_events')) {
        $ev = smpro_fa_events($user, $mtime - 180, $mtime + 180, 3000);
        foreach ((array)($ev['events'] ?? []) as $r) if (($r['path'] ?? '') === $abs || (($r['path2'] ?? '') === $abs))
            return ['door' => (string)($r['door'] ?? ''), 'ip' => (string)($r['ip'] ?? ''), 'login' => (string)($r['login'] ?? ($r['user'] ?? '')), 'how' => 'file-change journal'];
    }
    $best = null;
    foreach ($access as [$ts, $ip, $meth, $path, $code]) if ($meth === 'POST' && abs($ts - $mtime) <= 5 && $code < 400) { $best = [$ts, $ip, $path]; if ($ts <= $mtime) break; }
    if ($best) return ['door' => 'web', 'ip' => $best[1], 'login' => '', 'how' => 'POST ' . $best[2] . ' in the same seconds'];
    return ['door' => 'unknown', 'ip' => '', 'login' => '', 'how' => 'not in the file-change journal and no web request at that moment'];
}
/** Requests to a file from the web: count, addresses (max 10), first and last. */
function smpro_sw_ran(string $rel, array $access, string $sub): array {
    $want = '/' . ltrim(($sub !== '' ? rtrim($sub, '/') . '/' : '') . $rel, '/');
    $n = 0; $ips = []; $first = 0; $last = 0;
    foreach ($access as [$ts, $ip, $meth, $path, $code]) if ($path === $want && $code >= 200 && $code < 400) { $n++; $ips[$ip] = 1; $first = $first ? min($first, $ts) : $ts; $last = max($last, $ts); }
    return ['runs' => $n, 'ips' => array_slice(array_keys($ips), 0, 10), 'first' => $first, 'last' => $last];
}

/* ============================ database (WordPress) ============================ */
function smpro_sw_db_conn(string $doc) {
    if (!function_exists('smpro_inv_wp_db') || !function_exists('mysqli_connect')) return [null, null];
    $db = smpro_inv_wp_db($doc); if (!$db || $db['name'] === '') return [null, null];
    $host = $db['host']; $port = 0; $sock = null; if (strpos($host, ':') !== false) { [$host, $p] = explode(':', $host, 2); if (is_numeric($p)) $port = (int)$p; else $sock = $p; }
    mysqli_report(MYSQLI_REPORT_OFF);
    $my = @mysqli_connect($host, $db['user'], $db['pass'], $db['name'], $port ?: 0, $sock);
    return [$my ?: null, preg_replace('/[^A-Za-z0-9_]/', '', (string)$db['prefix'])];
}
/** What matters for security in a WordPress database, as a comparable snapshot. Null for a non-WordPress site. */
function smpro_sw_db_snapshot(string $doc): ?array {
    [$my, $p] = smpro_sw_db_conn($doc); if (!$my) return null;
    $q = function ($sql) use ($my) { $r = @mysqli_query($my, $sql); $o = []; if ($r instanceof mysqli_result) { while ($x = mysqli_fetch_assoc($r)) $o[] = $x; } return $o; };
    $admins = [];
    foreach ($q("SELECT u.ID,u.user_login,u.user_email,u.user_registered FROM `{$p}users` u JOIN `{$p}usermeta` m ON m.user_id=u.ID WHERE m.meta_key='{$p}capabilities' AND m.meta_value LIKE '%administrator%' LIMIT 200") as $r)
        $admins[(string)$r['user_login']] = ['id' => (int)$r['ID'], 'email' => (string)$r['user_email'], 'registered' => (string)$r['user_registered']];
    $opt = []; foreach ($q("SELECT option_name,option_value FROM `{$p}options` WHERE option_name IN ('siteurl','home','active_plugins','admin_email','users_can_register','default_role')") as $r) $opt[$r['option_name']] = (string)$r['option_value'];
    $inj = "(post_content LIKE '%<script%src=%' OR post_content LIKE '%eval(%' OR post_content LIKE '%String.fromCharCode%' OR post_content LIKE '%atob(%')";
    $posts = array_map(fn($r) => (int)$r['ID'], $q("SELECT ID FROM `{$p}posts` WHERE $inj AND post_status IN ('publish','draft','private') LIMIT 50"));
    $optInj = array_map(fn($r) => (string)$r['option_name'], $q("SELECT option_name FROM `{$p}options` WHERE (option_value LIKE '%<script%src=%' OR option_value LIKE '%eval(base64%' OR option_value LIKE '%String.fromCharCode%') AND option_name NOT LIKE '\\_transient%' LIMIT 50"));
    @mysqli_close($my);
    return ['ts' => time(), 'admins' => $admins, 'options' => $opt, 'inj_posts' => $posts, 'inj_options' => $optInj];
}
/** Events from two snapshots. */
function smpro_sw_db_diff(array $old, array $new): array {
    $ev = [];
    foreach (array_diff_key($new['admins'], $old['admins']) as $login => $a) $ev[] = ['critical', 'new_admin', 'New administrator in the database: ' . $login, ['login' => $login, 'email' => $a['email'], 'registered' => $a['registered'], 'id' => $a['id']]];
    foreach (['siteurl', 'home'] as $k) if (($old['options'][$k] ?? '') !== '' && ($new['options'][$k] ?? '') !== ($old['options'][$k] ?? '')) $ev[] = ['critical', 'db_url', $k . ' changed: ' . ($old['options'][$k] ?? '') . ' -> ' . ($new['options'][$k] ?? ''), []];
    if (($new['options']['users_can_register'] ?? '0') === '1' && ($new['options']['default_role'] ?? '') === 'administrator') $ev[] = ['critical', 'db_register', 'Anyone can register and becomes an administrator (users_can_register + default_role)', []];
    $np = array_diff($new['inj_posts'], $old['inj_posts']); if ($np) $ev[] = ['critical', 'db_inject', 'Script injected in ' . count($np) . ' post(s)', ['posts' => array_values($np)]];
    $no = array_diff($new['inj_options'], $old['inj_options']); if ($no) $ev[] = ['critical', 'db_inject', 'Script injected in option(s): ' . implode(', ', $no), ['options' => array_values($no)]];
    if (($old['options']['active_plugins'] ?? '') !== '' && ($new['options']['active_plugins'] ?? '') !== ($old['options']['active_plugins'] ?? '')) $ev[] = ['info', 'db_plugins', 'The list of active plugins changed', []];
    return $ev;
}

/* ============================ checks ============================ */
function smpro_sw_checks(string $doc): array {
    $c = [];
    $exp = [];
    foreach (['.env', '.git/config', 'wp-config.php.bak', 'wp-config.php~', 'wp-config.bak', '.env.bak', 'database.sql', 'dump.sql', 'backup.sql', 'backup.zip', 'site.zip', 'public_html.zip', 'www.zip', 'backup.tar.gz'] as $f) if (@is_file($doc . '/' . $f)) $exp[] = $f;
    foreach ((array)@glob($doc . '/*.sql') as $f) $exp[] = basename($f);
    $exp = array_values(array_unique($exp));
    $c[] = $exp ? ['fail', 'Files that must not be reachable from the web: ' . implode(', ', array_slice($exp, 0, 8)), 'exposed', $exp] : ['ok', 'No .env / .git / dump / backup files in the web root', 'exposed', []];
    $up = $doc . '/wp-content/uploads';
    if (@is_dir($up)) { $uh = $up . '/.htaccess'; $h = (@is_file($uh) && !@is_link($uh)) ? (string)@file_get_contents($uh, false, null, 0, 262144) : '';   // a pipe or a link here would hang or mislead the round
        $c[] = preg_match('/(Require all denied|Deny from all|php_flag\s+engine\s+off|SetHandler\s+none)/i', $h) ? ['ok', 'PHP cannot run inside uploads', 'uploads', []] : ['warn', 'PHP can run inside uploads', 'uploads', []]; }
    if (@is_file($doc . '/wp-includes/version.php') && preg_match("/wp_version\s*=\s*'([0-9.]+)'/", (string)@file_get_contents($doc . '/wp-includes/version.php'), $m)) $c[] = ['info', 'WordPress ' . $m[1], 'wpver', [$m[1]]];
    if (@is_file($doc . '/wp-config.php') && ((@fileperms($doc . '/wp-config.php') & 0004) !== 0)) $c[] = ['warn', 'wp-config.php is readable by every account on the server (mode ' . substr(sprintf('%o', @fileperms($doc . '/wp-config.php')), -3) . ')', 'cfgperm', []];
    return $c;
}

/* ============================ events ============================ */
/** An event still counts: not resolved, and (for a flagged file) the file would still be flagged by today's rules -
 *  events recorded by the first release, which flagged plugin/WordPress folders named img/files, no longer count. */
function smpro_sw_event_live(array $e): bool {
    if (!empty($e['resolved'])) return false;
    if (in_array($e['kind'] ?? '', ['upload_php', 'shell_run'], true) && !empty($e['data']['path'])) return smpro_sw_classify_file((string)$e['data']['path'], true)[0] ?? '' ? true : false;
    return true;
}
function smpro_sw_event_add(string $dom, array &$batch, string $sev, string $kind, string $title, array $data): void {
    // the id names THIS occurrence: the same file uploaded again (new mtime) or the same login re-created (new id) is a
    // new event, not a duplicate of the one already resolved
    $id = substr(sha1($dom . '|' . $kind . '|' . $title . '|' . json_encode([$data['path'] ?? ($data['login'] ?? ''), $data['mtime'] ?? '', $data['id'] ?? '', $data['registered'] ?? '', $data['files'] ?? ''])), 0, 16);
    $batch[] = ['id' => $id, 'ts' => time(), 'domain' => $dom, 'sev' => $sev, 'kind' => $kind, 'title' => $title, 'data' => $data];
}
function smpro_sw_events(string $dom, int $limit = 300): array {
    $f = smpro_sw_path('sites/' . smpro_sw_key($dom) . '/events.jsonl'); if (!@is_file($f)) return [];
    $o = []; foreach (array_reverse(file($f, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: []) as $l) { $j = json_decode($l, true); if (is_array($j)) $o[] = $j; if (count($o) >= $limit) break; }
    return $o;
}
function smpro_sw_events_write(string $dom, array $batch): void {
    if (!$batch) return;
    $f = smpro_sw_path('sites/' . smpro_sw_key($dom) . '/events.jsonl'); $s = '';
    foreach ($batch as $e) $s .= json_encode($e, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE) . "\n";
    $lk = smpro_sw_evlock($dom); @file_put_contents($f, $s, FILE_APPEND | LOCK_EX); @chmod($f, 0600); smpro_sw_evunlock($lk);
}
/** Read-modify-write of an events file and appends share one lock, so neither loses the other's lines. */
function smpro_sw_evlock(string $dom) { $h = @fopen(smpro_sw_path('sites/' . smpro_sw_key($dom) . '/events.lock'), 'c'); if ($h) @flock($h, LOCK_EX); return $h; }
function smpro_sw_evunlock($h): void { if ($h) { @flock($h, LOCK_UN); @fclose($h); } }
function smpro_sw_prune(): void {
    $keep = time() - smpro_sw_cfg()['keep_days'] * 86400;
    foreach ((array)@glob(SMPRO_SW_DIR . '/sites/*/events.jsonl') as $f) {
        $lk = smpro_sw_evlock(basename(dirname($f)));
        $ls = file($f, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: []; $k = array_filter($ls, fn($l) => (int)(json_decode($l, true)['ts'] ?? 0) >= $keep);
        if (count($k) < count($ls)) @file_put_contents($f, $k ? implode("\n", $k) . "\n" : '', LOCK_EX);
        smpro_sw_evunlock($lk);
    }
}

/* ============================ check one site ============================ */
function smpro_sw_check_site(string $dom, bool $withDb): array {
    $dom = smpro_sw_key($dom);
    $r = function_exists('smpro_inv_resolve') ? smpro_inv_resolve($dom) : null;
    if (!$r) return ['ok' => false, 'msg' => 'unresolved site'];
    $doc = rtrim((string)$r['docroot'], '/'); $user = (string)$r['user']; $sub = (string)($r['urlpath'] ?? '');
    if (!smpro_sw_doc_ok($doc, $user)) return ['ok' => false, 'msg' => 'the web root is not inside the account home - not checked'];
    $st = smpro_sw_load('sites/' . $dom . '/state.json'); $batch = [];
    $files = smpro_sw_scan_files($doc);
    $access = null; $coreTouched = false;
    if ($files !== null) {
        $prevF = smpro_sw_load('sites/' . $dom . '/files.json');
        $first = !$prevF;
        $new = array_diff_key($files, $prevF); $chg = []; foreach (array_intersect_key($files, $prevF) as $k => $v) if ($prevF[$k] !== $v) $chg[$k] = $v;
        $del = $first ? [] : array_diff_key($prevF, $files);
        foreach (array_keys($new + $chg) as $rel) if (preg_match('#^(wp-includes/|wp-admin/|[^/]+\.php$)#', (string)$rel)) { $coreTouched = true; break; }
        $flag = [];
        foreach ([[$new, true], [$chg, false]] as [$set, $isNew]) foreach ($set as $rel => $v) { $c = smpro_sw_classify_file((string)$rel, $isNew, (int)explode('|', $v)[0]); if ($c) $flag[$rel] = [$c[0], $c[1], $isNew, (int)explode('|', $v)[1]]; }
        if ($first) { $flag = array_filter($flag, fn($x) => $x[0] === 'critical'); }   // first look: only what is dangerous already
        if ($flag) $access = smpro_sw_access($dom);
        $i = 0;
        foreach ($flag as $rel => [$sev, $why, $isNew, $mt]) {
            if (++$i > 60) { unset($files[$rel]); continue; }   // over the per-round limit: left out of the baseline, so the next round reports it
            $abs = $doc . '/' . $rel;
            $who = $first ? ['door' => 'before Site Watch', 'ip' => '', 'login' => '', 'how' => 'found on the first check'] : smpro_sw_who($user, $abs, $mt, $access, $sub);
            $ran = smpro_sw_is_php($rel) ? smpro_sw_ran($rel, $access, $sub) : ['runs' => 0, 'ips' => []];
            $kind = $sev === 'critical' ? 'upload_php' : ((basename($rel) === '.htaccess') ? 'htaccess' : 'file');
            smpro_sw_event_add($dom, $batch, $sev, $kind, $why . ': ' . $rel, ['path' => $rel, 'new' => $isNew, 'mtime' => $mt, 'who' => $who, 'ran' => $ran]);
            if ($ran['runs'] > 0 && $sev === 'critical') smpro_sw_event_add($dom, $batch, 'critical', 'shell_run', 'Injected file run from the web ' . $ran['runs'] . 'x: ' . $rel, ['path' => $rel, 'ips' => $ran['ips'], 'first' => $ran['first'], 'last' => $ran['last']]);
        }
        if (!$first) {
            $np = count(array_filter(array_keys($new), 'smpro_sw_is_php')) - count(array_filter(array_keys($flag), fn($k) => isset($new[$k])));
            if ($np > 0 || count($chg) || count($del)) smpro_sw_event_add($dom, $batch, 'info', 'files', count($new) . ' new, ' . count($chg) . ' changed, ' . count($del) . ' deleted code file(s)', ['path' => 'summary-' . date('YmdH'), 'new' => array_slice(array_keys($new), 0, 200), 'changed' => array_slice(array_keys($chg), 0, 200), 'deleted' => array_slice(array_keys($del), 0, 100)]);
        }
        smpro_sw_save('sites/' . $dom . '/files.json', $files);
        $st['files_at'] = time(); $st['files_n'] = count($files); $st['new24'] = $first ? [] : array_slice(array_keys($new), 0, 300);   // the first look sets the baseline: nothing in it is "new"
    }
    if ($withDb) {
        $snap = smpro_sw_db_snapshot($doc);
        if ($snap !== null) {
            $old = smpro_sw_load('sites/' . $dom . '/db.json');
            if ($old) foreach (smpro_sw_db_diff($old, $snap) as [$sev, $kind, $title, $data]) smpro_sw_event_add($dom, $batch, $sev, $kind, $title, $data);
            elseif ($snap['inj_posts'] || $snap['inj_options']) smpro_sw_event_add($dom, $batch, 'critical', 'db_inject', 'Injected script found on the first database check', ['posts' => $snap['inj_posts'], 'options' => $snap['inj_options']]);
            smpro_sw_save('sites/' . $dom . '/db.json', $snap); $st['db_at'] = time(); $st['admins'] = array_keys($snap['admins']);
        }
    }
    $prevChecks = (array)($st['checks'] ?? []);
    $coreDue = $withDb || $coreTouched || !array_filter($prevChecks, fn($c) => ($c[2] ?? '') === 'core' && ($c[0] ?? '') !== 'info');   // a real verdict, not a "not verified" note
    $st['checks'] = array_merge(smpro_sw_checks($doc), smpro_swd_run($dom, $doc, $user, $coreDue, $batch, $prevChecks));
    foreach ($st['checks'] as $c) if ($c[2] === 'exposed') {
        $now = $c[0] === 'fail' ? (array)$c[3] : []; sort($now);
        if ($now && $now !== (array)($st['exposed_told'] ?? [])) smpro_sw_event_add($dom, $batch, 'critical', 'exposed', $c[1], ['path' => 'exposed', 'files' => $now]);
        $st['exposed_told'] = $now;
    }
    // the same event (same id) is recorded once
    // ...unless it was closed because it was no longer found: the same thing coming back is a new event
    $seen = array_flip(array_column(array_filter(smpro_sw_events($dom, 500), fn($e) => ($e['resolved_by'] ?? '') !== 'no longer found'), 'id'));
    $batch = array_values(array_filter($batch, fn($e) => !isset($seen[$e['id']])));
    smpro_sw_events_write($dom, $batch);
    $st['user'] = $user; $st['docroot'] = $doc; $st['checked_at'] = time();
    $evs = smpro_sw_events($dom, 200); $cut = time() - 86400; $risk = 'clean';
    foreach ($evs as $e) if ($e['ts'] >= $cut && smpro_sw_event_live($e)) { if ($e['sev'] === 'critical') { $risk = 'critical'; break; } if ($e['sev'] === 'warning') $risk = 'warning'; }
    foreach ($st['checks'] as $c) if ($c[0] === 'fail') $risk = 'critical'; elseif ($c[0] === 'warn' && $risk === 'clean') $risk = 'warning';
    $st['risk'] = $risk;
    smpro_sw_save('sites/' . $dom . '/state.json', $st);
    if ($batch) { smpro_sw_dispatch($dom, $batch); if (in_array($dom, smpro_sw_cfg()['protect'], true) && array_filter($batch, fn($e) => $e['sev'] === 'critical')) smpro_sw_fix_safe($dom, 'auto'); }
    return ['ok' => true, 'events' => count($batch), 'risk' => $risk];
}

/* ============================ reports ============================ */
/** A rule matches a site when its sites are "*" or list the site. */
function smpro_sw_rule_match(array $rule, string $dom): bool { $s = $rule['sites'] ?? '*'; return $s === '*' || in_array($dom, (array)$s, true); }
function smpro_sw_message(string $dom, array $e): string {
    $icon = ['critical' => "\u{1F534}", 'warning' => "\u{1F7E0}", 'info' => "\u{1F535}"][$e['sev']] ?? '';
    $m = $icon . ' ' . $dom . ' - ' . $e['title'] . "\n";
    $d = $e['data'] ?? [];
    if (!empty($d['who']['door'])) $m .= 'By: ' . $d['who']['door'] . ($d['who']['login'] ? ' (' . $d['who']['login'] . ')' : '') . ($d['who']['ip'] ? ' from ' . $d['who']['ip'] : '') . "\n";
    if (!empty($d['ran']['runs'])) $m .= 'Run ' . $d['ran']['runs'] . 'x from ' . implode(', ', array_slice($d['ran']['ips'], 0, 5)) . "\n";
    if (!empty($d['ips'])) $m .= 'From: ' . implode(', ', array_slice($d['ips'], 0, 5)) . "\n";
    return $m . date('Y-m-d H:i', (int)$e['ts']);
}
/** Send to one recipient over one channel. [ok, detail]. */
function smpro_sw_send(string $channel, string $to, string $subject, string $text): array {
    if (!function_exists('smpro_ntf_load')) return [false, 'notifications not loaded'];
    $cfg = smpro_ntf_load();
    if ($channel === 'whatsapp') { $cfg['whatsapp']['chat_id'] = preg_replace('/[^0-9@a-z.]/i', '', $to); return smpro_ntf_send_whatsapp($cfg, $text); }
    if ($channel === 'telegram') return smpro_ntf_send_telegram((string)($cfg['telegram']['token'] ?? ''), $to, htmlspecialchars($text));
    if ($channel === 'email') return smpro_ntf_send_email([$to], (string)($cfg['email']['from'] ?? ''), '[Site Watch] ' . $subject, $text);
    return [false, 'unknown channel'];
}
/** Instant events go out now; daily/weekly ones are queued for the digest. Never the same event twice to one recipient. */
function smpro_sw_dispatch(string $dom, array $batch): void {
    $c = smpro_sw_cfg(); $sent = smpro_sw_load('sent.json'); $queue = smpro_sw_load('digest.json');
    $alertOn = fn($e) => !isset($c['alerts'][$e['kind']]) || !empty($c['alerts'][$e['kind']]);
    foreach ($c['rules'] as $ri => $rule) {
        if (!smpro_sw_rule_match($rule, $dom)) continue;
        $min = smpro_sw_rank((string)($rule['level'] ?? 'critical'));
        foreach ($batch as $e) {
            if (smpro_sw_rank($e['sev']) < $min || !$alertOn($e)) continue;
            foreach ((array)$rule['to'] as $to) foreach ((array)$rule['channels'] as $ch) {
                $k = $e['id'] . '|' . $ch . '|' . $to; if (isset($sent[$k])) continue;
                if (in_array($rule['when'] ?? 'instant', ['instant', 'instant_daily'], true)) { smpro_sw_send($ch, $to, $dom . ': ' . $e['title'], smpro_sw_message($dom, $e)); $sent[$k] = time(); }
                if (in_array($rule['when'] ?? 'instant', ['daily', 'weekly', 'instant_daily'], true)) $queue[$ri][$ch . '|' . $to][] = $dom . ' - [' . strtoupper($e['sev']) . '] ' . $e['title'];
            }
        }
    }
    $cut = time() - 120 * 86400; $sent = array_filter($sent, fn($t) => $t > $cut);
    smpro_sw_save('sent.json', $sent); smpro_sw_save('digest.json', $queue);
}
/** Daily summaries at 09:00, weekly on Monday 09:00. */
function smpro_sw_digest(): void {
    $c = smpro_sw_cfg(); $queue = smpro_sw_load('digest.json'); if (!$queue) return;
    $st = smpro_sw_load('digest_state.json'); $today = date('Y-m-d');
    if ((int)date('G') < 9 || ($st['day'] ?? '') === $today) return;
    foreach ($queue as $ri => $byTo) {
        $when = $c['rules'][$ri]['when'] ?? 'daily';
        if ($when === 'weekly' && date('N') !== '1') continue;
        foreach ($byTo as $chTo => $lines) { [$ch, $to] = explode('|', $chTo, 2); smpro_sw_send($ch, $to, 'Site Watch summary', "Site Watch - " . ($when === 'weekly' ? 'weekly' : 'daily') . " summary\n\n" . implode("\n", array_slice(array_unique($lines), 0, 60))); }
        unset($queue[$ri]);
    }
    smpro_sw_save('digest.json', $queue); smpro_sw_save('digest_state.json', ['day' => $today]);
}

/* ============================ fix & protect ============================ */
/** The steps that would fix / protect a site now. safe=true steps may run automatically. */
function smpro_sw_plan(string $dom): array {
    $dom = smpro_sw_key($dom); $st = smpro_sw_load('sites/' . $dom . '/state.json'); $doc = (string)($st['docroot'] ?? '');
    if ($doc === '') return [];
    $steps = []; $ips = []; $seen = [];
    foreach (smpro_sw_events($dom, 300) as $e) {
        if (!smpro_sw_event_live($e)) continue;
        $d = $e['data'] ?? [];
        if (in_array($e['kind'], ['upload_php', 'shell_run'], true) && !empty($d['path']) && !isset($seen['q' . $d['path']]) && @is_file($doc . '/' . $d['path'])) {
            $seen['q' . $d['path']] = 1; $steps[] = ['action' => 'quarantine', 'arg' => $d['path'], 'label' => 'Move ' . $d['path'] . ' to quarantine (original kept)', 'safe' => true, 'event' => $e['id']];
        }
        foreach (array_merge((array)($d['ips'] ?? []), (array)($d['ran']['ips'] ?? [])) as $ip) if ($e['sev'] === 'critical' && filter_var($ip, FILTER_VALIDATE_IP)) $ips[$ip] = 1;
        if ($e['kind'] === 'new_admin' && !empty($d['login']) && !isset($seen['a' . $d['login']])) { $seen['a' . $d['login']] = 1; $steps[] = ['action' => 'remove_admin', 'arg' => (string)$d['login'], 'label' => 'Remove administrator ' . $d['login'] . ' (database backed up first)', 'safe' => false, 'event' => $e['id']]; }
    }
    $own = function_exists('smpro_gw_always') ? array_flip(array_map('strval', (array)smpro_gw_always(''))) : [];
    foreach (array_keys($ips) as $ip) if (!isset($own[$ip])) $steps[] = ['action' => 'block_ip', 'arg' => $ip, 'label' => 'Block ' . $ip . ' in the firewall (it ran an injected file)', 'safe' => true, 'event' => ''];
    foreach ((array)($st['checks'] ?? []) as $c) {
        if ($c[2] === 'uploads' && $c[0] === 'warn') $steps[] = ['action' => 'protect_uploads', 'arg' => '', 'label' => 'Protect: stop PHP from running inside uploads', 'safe' => true, 'event' => ''];
        if ($c[2] === 'exposed' && $c[0] === 'fail') foreach ((array)$c[3] as $f) $steps[] = ['action' => 'quarantine', 'arg' => $f, 'label' => 'Move ' . $f . ' out of the web root (original kept)', 'safe' => false, 'event' => ''];
        if ($c[2] === 'cfgperm') $steps[] = ['action' => 'cfg_perm', 'arg' => '', 'label' => 'Protect: make wp-config.php readable by its own account only (600) - only where PHP runs as the account (PHP-FPM / suPHP)', 'safe' => false, 'event' => ''];
    }
    foreach (smpro_swd_plan($dom, smpro_sw_events($dom, 300), $doc, (string)($st['user'] ?? '')) as $s) if ($s['action'] !== 'quarantine' || !isset($seen['q' . $s['arg']])) $steps[] = $s;
    if (array_filter(smpro_sw_events($dom, 300), fn($e) => $e['kind'] === 'shell_run' && empty($e['resolved'])))
        $steps[] = ['action' => 'advice', 'arg' => '', 'label' => 'By hand: an injected file ran - change the database password and the WordPress salts in wp-config.php', 'safe' => false, 'event' => ''];
    return $steps;
}
/** Run one step. Every change is backed up and recorded for undo in the Site Doctor manifest. */
function smpro_sw_fix(string $dom, string $action, string $arg): array {
    $dom = smpro_sw_key($dom); $st = smpro_sw_load('sites/' . $dom . '/state.json'); $doc = (string)($st['docroot'] ?? ''); $user = (string)($st['user'] ?? '');
    if ($doc === '' || !smpro_sw_doc_ok($doc, $user)) return ['ok' => false, 'msg' => 'check the site first (or its web root is outside the account home)'];
    $res = ['ok' => false, 'msg' => 'unknown step'];
    if ($action === 'quarantine') {
        $abs = $doc . '/' . ltrim($arg, '/'); $real = @realpath($abs);
        if ($real === false || strpos($real, rtrim((string)@realpath($doc), '/') . '/') !== 0 || is_link($abs) || !is_file($real)) return ['ok' => false, 'msg' => 'refused: not a file inside the site'];
        $qd = SMPRO_VARLIB . '/quarantine/sitewatch/' . date('Ymd_His') . '_' . substr(sha1($real), 0, 8); @mkdir($qd, 0700, true);
        $to = $qd . '/' . basename($real);
        $imm = function_exists('smpro_inv_imm') && smpro_inv_imm($real); if ($imm) @shell_exec('chattr -i ' . escapeshellarg($real) . ' 2>/dev/null');
        if (!@rename($real, $to)) { if (!(@copy($real, $to) && @unlink($real))) return ['ok' => false, 'msg' => 'could not move the file']; }
        $id = smpro_inv_manifest_add(['user' => $user, 'domain' => $dom, 'action' => 'sw_quarantine', 'from' => $real, 'to' => $to]);
        $res = ['ok' => true, 'msg' => 'Moved to quarantine: ' . $arg . ' (kept at ' . $to . ')', 'undo_id' => $id];
    } elseif ($action === 'block_ip') {
        if (!filter_var($arg, FILTER_VALIDATE_IP) || !function_exists('smpro_fw_block_ip')) return ['ok' => false, 'msg' => 'bad address'];
        // the same refusals as every automatic block: never this server, never a private/local address, never in dry-run
        if (function_exists('smpro_is_server_ip') && smpro_is_server_ip($arg)) return ['ok' => false, 'msg' => 'refused: the address of this server'];
        if (function_exists('smpro_ip_is_external') && !smpro_ip_is_external($arg)) return ['ok' => false, 'msg' => 'refused: private/local address'];
        if (function_exists('smpro_ctl_dry_run') && smpro_ctl_dry_run()) return ['ok' => false, 'msg' => 'dry-run mode: ' . $arg . ' was not blocked'];
        // only through the one guarded block function (allow-list, Cloudflare edge, own addresses). Without it: no block.
        if (!function_exists('smpro_im_block_ip')) return ['ok' => false, 'msg' => 'not blocked: the block guards are not loaded here - block ' . $arg . ' from the Firewall page'];
        $r = smpro_im_block_ip($arg, 'Site Watch: ran an injected file on ' . $dom);
        $ok = is_array($r) ? !empty($r['ok']) : (bool)$r;
        $res = ['ok' => $ok, 'msg' => ($ok ? 'Blocked ' : 'Could not block ') . $arg . (is_array($r) && !empty($r['msg']) ? ' - ' . $r['msg'] : '')];
    } elseif ($action === 'protect_uploads') {
        $up = $doc . '/wp-content/uploads'; if (!is_dir($up) || is_link($up)) return ['ok' => false, 'msg' => 'no uploads folder'];
        $f = $up . '/.htaccess'; if (is_link($f)) return ['ok' => false, 'msg' => 'refused: .htaccess is a link'];
        $old = is_file($f) ? (string)@file_get_contents($f) : null;
        $add = "\n# Safety Monitor Pro Site Watch: no PHP inside uploads\n<FilesMatch \"\\.(php[0-9]?|phtml|phar)$\">\n  Require all denied\n</FilesMatch>\n";
        if ($old !== null) {
            $bak = '.htaccess.smpro-bak-' . date('Ymd_His');
            if (!smpro_sdb_safe_write($up, $bak, $old) || !smpro_sdb_safe_write($up, '.htaccess', rtrim($old) . "\n" . $add)) return ['ok' => false, 'msg' => 'could not write uploads/.htaccess'];
            $id = smpro_inv_manifest_add(['user' => $user, 'domain' => $dom, 'action' => 'sw_protect_uploads', 'kind' => 'file', 'from' => $f, 'backup' => $up . '/' . $bak]);
        } else {
            if (!smpro_sdb_safe_write($up, '.htaccess', ltrim($add))) return ['ok' => false, 'msg' => 'could not write uploads/.htaccess'];
            $id = smpro_inv_manifest_add(['user' => $user, 'domain' => $dom, 'action' => 'sw_protect_uploads', 'kind' => 'created', 'from' => $up . '/index.php', 'to' => $f]);
        }
        $res = ['ok' => true, 'msg' => 'PHP can no longer run inside uploads' . ($old !== null ? ' (old .htaccess backed up)' : ''), 'undo_id' => $id];
    } elseif ($action === 'cfg_perm') {
        $f = $doc . '/wp-config.php'; if (is_link($f) || !is_file($f)) return ['ok' => false, 'msg' => 'no wp-config.php'];
        // as the account, never as root: root's chmod follows a link the account could swap in at this moment
        $mode = @fileperms($f) & 0777;
        @shell_exec('timeout 20 su -s /bin/sh ' . escapeshellarg($user) . ' -c ' . escapeshellarg('cd ' . escapeshellarg($doc) . ' && chmod 600 -- wp-config.php') . ' 2>/dev/null');
        clearstatcache(); $ok = (@fileperms($f) & 0777) === 0600;
        $res = ['ok' => $ok, 'msg' => $ok ? 'wp-config.php is now 600 (was ' . sprintf('%o', $mode) . ')' : 'chmod failed'];
    } elseif ($action === 'remove_admin') {
        [$my, $p] = smpro_sw_db_conn($doc); if (!$my) return ['ok' => false, 'msg' => 'cannot reach the database'];
        $l = mysqli_real_escape_string($my, $arg);
        $q = @mysqli_query($my, "SELECT * FROM `{$p}users` WHERE user_login='$l' LIMIT 1"); $u = $q instanceof mysqli_result ? (mysqli_fetch_assoc($q) ?: null) : null;
        if (!$u) { @mysqli_close($my); return ['ok' => false, 'msg' => 'user not found']; }
        $meta = []; $r = @mysqli_query($my, "SELECT * FROM `{$p}usermeta` WHERE user_id=" . (int)$u['ID']); if ($r) while ($x = mysqli_fetch_assoc($r)) $meta[] = $x;
        $bak = smpro_sw_path('backups/' . $dom . '-user-' . preg_replace('/[^a-z0-9_.-]/i', '', $arg) . '-' . date('Ymd_His') . '.json');
        if (@file_put_contents($bak, json_encode(['user' => $u, 'meta' => $meta, 'prefix' => $p])) === false) { @mysqli_close($my); return ['ok' => false, 'msg' => 'could not back up the user - nothing changed']; }
        @chmod($bak, 0600);
        @mysqli_query($my, "DELETE FROM `{$p}usermeta` WHERE user_id=" . (int)$u['ID']); @mysqli_query($my, "DELETE FROM `{$p}users` WHERE ID=" . (int)$u['ID']);
        @mysqli_close($my);
        $res = ['ok' => true, 'msg' => 'Administrator ' . $arg . ' removed; the user and its settings are backed up in ' . $bak];
    } elseif ($action === 'advice') {
        return ['ok' => false, 'msg' => 'This step is done by hand.'];
    } elseif (($deep = smpro_swd_fix($dom, $doc, $user, $action, $arg)) !== null) {
        $res = $deep;
    }
    if (!empty($res['ok'])) {
        // the events the step answered are marked resolved
        $lk = smpro_sw_evlock($dom);
        $f = smpro_sw_path('sites/' . $dom . '/events.jsonl'); $ls = @file($f, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: []; $ch = false;
        foreach ($ls as &$l) { $e = json_decode($l, true); if (!is_array($e) || !empty($e['resolved'])) continue; $d = $e['data'] ?? [];
            if (($action === 'quarantine' && ($d['path'] ?? '') === $arg) || ($action === 'remove_admin' && ($d['login'] ?? '') === $arg)) { $e['resolved'] = time(); $l = json_encode($e, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE); $ch = true; } }
        unset($l); if ($ch) @file_put_contents($f, implode("\n", $ls) . "\n", LOCK_EX);
        smpro_sw_evunlock($lk);
        $log = smpro_sw_load('sites/' . $dom . '/fixes.json'); array_unshift($log, ['ts' => time(), 'action' => $action, 'arg' => $arg, 'msg' => $res['msg'], 'undo_id' => $res['undo_id'] ?? '']); smpro_sw_save('sites/' . $dom . '/fixes.json', array_slice($log, 0, 200));
    }
    if (function_exists('smpro_audit')) smpro_audit('sitewatch_fix', ['domain' => $dom, 'action' => $action, 'ok' => !empty($res['ok'])]);
    return $res;
}
/** Run every safe step (automatic protection, or "Fix all safe steps"), then report to the site's recipients. */
function smpro_sw_fix_safe(string $dom, string $mode = 'manual'): array {
    $done = [];
    foreach (smpro_sw_plan($dom) as $s) if ($s['safe']) { $r = smpro_sw_fix($dom, $s['action'], $s['arg']); $done[] = (!empty($r['ok']) ? 'Done: ' : 'Failed: ') . $s['label'] . ' - ' . $r['msg']; }
    if ($done) {
        $left = array_filter(smpro_sw_plan($dom), fn($s) => !$s['safe']);
        $e = ['id' => 'fix' . time(), 'ts' => time(), 'domain' => $dom, 'sev' => 'info', 'kind' => 'fixed', 'title' => ($mode === 'auto' ? 'Automatic protection ran' : 'Safe fixes applied') . ' (' . count($done) . ' step(s))' . ($left ? '; ' . count($left) . ' step(s) wait for you' : ''), 'data' => ['steps' => $done, 'left' => array_column($left, 'label')]];
        smpro_sw_events_write($dom, [$e]);
        $c = smpro_sw_cfg();
        foreach ($c['rules'] as $rule) if (smpro_sw_rule_match($rule, $dom)) foreach ((array)$rule['to'] as $to) foreach ((array)$rule['channels'] as $ch)
            smpro_sw_send($ch, $to, $dom . ': fixed', "\u{1F6E1} " . $dom . ' - ' . $e['title'] . "\n" . implode("\n", $done) . ($left ? "\nWaiting for you:\n" . implode("\n", array_column($left, 'label')) : ''));
    }
    return ['ok' => true, 'steps' => $done];
}

/* ============================ jobs + cron ============================ */
function smpro_sw_job(): array {
    $j = smpro_sw_load('job.json'); if (empty($j['running'])) return $j;
    $pid = (int)($j['pid'] ?? 0);
    if (($pid > 0 && !@file_exists('/proc/' . $pid)) || ($pid === 0 && (int)($j['started'] ?? 0) < time() - 90) || max((int)($j['beat'] ?? 0), (int)($j['started'] ?? 0)) < time() - 900) { $j['running'] = false; $j['stopped'] = true; smpro_sw_save('job.json', $j); }
    return $j;
}
function smpro_sw_start(array $domains, bool $withDb = true): array {
    if (!empty(smpro_sw_job()['running'])) return ['ok' => false, 'msg' => 'A check is already running.'];
    $domains = array_values(array_filter(array_map('smpro_sw_key', $domains)));
    if (!$domains) $domains = array_keys(smpro_sw_targets());
    smpro_sw_save('job.json', ['running' => true, 'started' => time(), 'beat' => time(), 'pid' => 0, 'domains' => $domains, 'db' => $withDb, 'done' => 0, 'total' => count($domains), 'current' => '']);
    $php = function_exists('smpro_php_cli_bin') ? smpro_php_cli_bin() : 'php';
    @shell_exec('nohup timeout 7200 nice -n 10 ' . escapeshellarg($php) . ' ' . escapeshellarg(SMPRO_BASE . '/bin/sitewatch.php') . ' job >/dev/null 2>&1 </dev/null &');
    return ['ok' => true, 'msg' => 'Checking ' . count($domains) . ' site(s) in the background - you can close this page.'];
}
function smpro_sw_run_job(): void {
    $j = smpro_sw_load('job.json'); $j['pid'] = getmypid(); $j['running'] = true; smpro_sw_save('job.json', $j);
    foreach ((array)$j['domains'] as $d) {
        $j['current'] = $d; $j['beat'] = time(); smpro_sw_save('job.json', $j);
        try { smpro_sw_check_site((string)$d, !empty($j['db'])); } catch (\Throwable $e) { if (function_exists('smpro_audit')) @smpro_audit('sitewatch_check_failed', ['domain' => (string)$d, 'msg' => $e->getMessage()]); }
        $j['done']++; $j['beat'] = time(); smpro_sw_save('job.json', $j);
    }
    $j['running'] = false; $j['current'] = ''; $j['finished'] = time(); smpro_sw_save('job.json', $j);
}
/** The cron tick (every 15 minutes): start what is due, send digests, prune. */
function smpro_sw_tick(): void {
    $c = smpro_sw_cfg(); smpro_sw_digest();
    $st = smpro_sw_load('sched.json');
    if (($st['pruned'] ?? '') !== date('Y-m-d')) { smpro_sw_prune(); $st['pruned'] = date('Y-m-d'); smpro_sw_save('sched.json', $st); }
    if (!$c['auto'] || !empty(smpro_sw_job()['running'])) return;
    $filesDue = (int)($st['files'] ?? 0) <= time() - $c['files_min'] * 60; $dbDue = (int)($st['db'] ?? 0) <= time() - $c['db_min'] * 60;
    if (!$filesDue && !$dbDue) return;
    $st['files'] = time(); if ($dbDue) $st['db'] = time(); smpro_sw_save('sched.json', $st);
    smpro_sw_save('job.json', ['running' => true, 'started' => time(), 'beat' => time(), 'pid' => getmypid(), 'domains' => array_keys(smpro_sw_targets()), 'db' => $dbDue, 'done' => 0, 'total' => count(smpro_sw_targets()), 'current' => '']);
    smpro_sw_run_job();
}
function smpro_sw_cron_sync(): bool {
    if (defined('SMPRO_TEST_SRC')) return true;
    $f = '/etc/cron.d/smpro-sitewatch'; $c = smpro_sw_cfg();
    $hasRules = !empty($c['rules']);
    if (!$c['auto'] && !$hasRules) { if (@is_file($f)) @unlink($f); return true; }
    $php = function_exists('smpro_php_cli_bin') ? smpro_php_cli_bin() : 'php';
    $want = "# Safety Monitor Pro - Site Watch: scheduled checks, report digests\n*/15 * * * * root /usr/bin/flock -n " . SMPRO_LOCKS . "/sitewatch.lock timeout 7000 nice -n 10 $php " . SMPRO_BASE . "/bin/sitewatch.php tick >/dev/null 2>&1\n";
    if (@is_file($f) && (string)@file_get_contents($f) === $want) return true;
    return function_exists('smpro_cron_install') ? smpro_cron_install($f, $want) : false;
}
