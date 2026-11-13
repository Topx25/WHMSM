<?php
/**
 * includes/sdbulk.php - Site Doctor for every site at once.
 *
 * The single-site engine (includes/investigate.php) already diagnoses a site, knows its platform, proposes fixes and
 * applies them backup-first with an undo record. This file is the layer above it:
 *   - scan: probe every domain, sub-domain and add-on from THIS server (so a CDN in front cannot hide the result) and
 *     diagnose the ones that fail with the single-site engine;
 *   - fix: for the sites the operator ticks, or for every failing site when the automatic switch is on, apply the
 *     engine's fixes one at a time and stop at the first that brings the site back, verifying after each;
 *   - report: what was wrong, why, what was changed (files and their backups), and the result before and after;
 *   - retention: backups of edited files are removed after 7 days (the undo for those edits ends with them).
 *
 * The automatic switch never changes a PHP version, never edits a database, never restarts a shared service, and never
 * touches a site whose files are locked: those always wait for the operator to tick the site.
 * Work runs in a detached worker (bin/sitedoctor_bulk.php) so it finishes even when the page is closed.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

if (!defined('SMPRO_SDB_DIR')) define('SMPRO_SDB_DIR', SMPRO_VARLIB . '/sitedoctor');
define('SMPRO_SDB_KEEP_DAYS', 7);

function smpro_sdb_path(string $f): string { @is_dir(SMPRO_SDB_DIR) || @mkdir(SMPRO_SDB_DIR, 0700, true); return SMPRO_SDB_DIR . '/' . $f; }
function smpro_sdb_load(string $f, array $def = []): array { $j = @is_file(smpro_sdb_path($f)) ? json_decode((string)@file_get_contents(smpro_sdb_path($f)), true) : null; return is_array($j) ? $j : $def; }
function smpro_sdb_save(string $f, array $d): bool {
    $p = smpro_sdb_path($f); $t = $p . '.tmp.' . getmypid();
    if (@file_put_contents($t, json_encode($d, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE), LOCK_EX) === false) return false;
    @chmod($t, 0600); return @rename($t, $p);
}
function smpro_sdb_cfg(): array { return smpro_sdb_load('bulk.json') + ['auto' => false, 'scan_daily' => true]; }
function smpro_sdb_cfg_save(array $patch): array { $c = array_replace(smpro_sdb_cfg(), $patch); $c['auto'] = !empty($c['auto']); $c['scan_daily'] = !empty($c['scan_daily']); smpro_sdb_save('bulk.json', $c); if (function_exists('smpro_sdb_cron_sync')) smpro_sdb_cron_sync(); return $c; }

/** Fixes the automatic switch may apply on its own. Everything else waits for a person to tick the site. */
function smpro_sdb_auto_allowed(string $action, string $path = ''): bool {
    // fix_wp_url edits the database; restart_phpfpm restarts a PHP pool other sites share; unharden is handled by the
    // lock rule below (a locked site is never touched automatically); restore_wp_core replaces code files.
    if (in_array($action, ['fix_wp_url', 'restart_phpfpm', 'unharden', 'restore_wp_core'], true)) return false;
    // The site's security plugin (WP Guard) is never switched off by a machine, even when it is the one failing.
    if (preg_match('#/plugins/wp-guard$#', rtrim($path, '/'))) return false;
    return true;
}

/**
 * Scenarios the single-site engine has no fix for, found in the bulk scan on real servers:
 *   - a plugin/theme throws an uncaught error (not a missing file / parse error)  -> disable it (renamed, reversible)
 *   - a WordPress core file is missing (wp-includes / wp-admin / wp-*.php)         -> restore the core files (by hand)
 *   - PHP warnings / deprecations printed to visitors                              -> display_errors off in .user.ini
 * Returns fixes in the engine's shape, not already in $res['fixes'].
 */
function smpro_sdb_extra_fixes(array $res, string $kind): array {
    $out = []; $have = array_column((array)($res['fixes'] ?? []), 'path');
    $doc = rtrim((string)($res['docroot'] ?? ''), '/'); if ($doc === '') return [];
    foreach ((array)($res['fatals'] ?? []) as $f) {
        $msg = (string)($f['msg'] ?? '');
        if (preg_match('#wp-content/(plugins|themes)/([A-Za-z0-9._-]+)#', $msg, $m) && preg_match('/Uncaught (Error|TypeError|ArgumentCountError|ValueError|DivisionByZeroError)/', $msg)) {
            $p = $doc . '/wp-content/' . $m[1] . '/' . $m[2];
            if (is_dir($p) && !in_array($p, $have, true)) { $have[] = $p; $out[] = ['action' => $m[1] === 'plugins' ? 'disable_plugin' : 'disable_theme', 'path' => $p, 'label' => 'Disable ' . $m[2] . ' (it crashes the site)', 'why' => 'Uncaught error inside ' . $m[2]]; }
        }
        if (preg_match("#Failed opening required '" . preg_quote($doc, '#') . "/(wp-includes/|wp-admin/|wp-[a-z-]+\.php)#", $msg) && !in_array('restore_wp_core', array_column($out, 'action'), true))
            $out[] = ['action' => 'restore_wp_core', 'path' => $doc, 'label' => 'Restore the WordPress core files (wp-admin, wp-includes, root files)', 'why' => 'A WordPress core file is missing - often removed by a malware clean-up or a broken update. Content, uploads and wp-config.php are not touched.'];
    }
    if (in_array($kind, ['php_warning', 'php_deprecated'], true))
        $out[] = ['action' => 'hide_php_errors', 'path' => $doc, 'label' => 'Stop printing PHP warnings to visitors (display_errors off)', 'why' => 'Warnings are shown on the page; they stay in the error log.'];
    return $out;
}

/** Why a 403 / listing / default page: the web root has no index page. '' when it has one. */
function smpro_sdb_noindex_cause(string $doc): string {
    if ($doc === '' || !is_dir($doc)) return '';
    foreach (['index.php', 'index.html', 'index.htm', 'default.html', 'index.shtml'] as $i) if (file_exists($doc . '/' . $i)) return '';
    $n = count(array_diff((array)@scandir($doc), ['.', '..', 'cgi-bin', '.well-known', '.htaccess']));
    return $n === 0 ? 'The web root is empty: the site has no content (upload it, or remove the domain).' : 'The web root has no index page (index.php / index.html), so the server refuses to list it.';
}

/** Run one fix: the bulk-only actions here, everything else through the single-site engine. */
function smpro_sdb_fix_one(string $action, string $domain, string $path): array {
    if ($action === 'hide_php_errors') return smpro_sdb_fix_hide_errors($domain);
    if ($action === 'restore_wp_core') return smpro_sdb_fix_wp_core($domain);
    return smpro_inv_fix($action, $domain, $path);
}
/** Write a file inside the account's web root as root without following a planted link; owner = the web root's owner. */
function smpro_sdb_safe_write(string $dir, string $name, string $content): bool {
    $d = @realpath($dir); if ($d === false || strpos($d, '/home') !== 0 || is_link($dir . '/' . $name)) return false;
    $tmp = $d . '/.' . $name . '.smpro-tmp-' . bin2hex(random_bytes(4));
    $h = @fopen($tmp, 'xb'); if (!$h) return false; $ok = @fwrite($h, $content) !== false; @fclose($h);
    if ($ok) { @chmod($tmp, 0644); $st = @stat($d); if ($st) { @chown($tmp, $st['uid']); @chgrp($tmp, $st['gid']); } $ok = @rename($tmp, $d . '/' . $name); }
    if (!$ok) @unlink($tmp);
    return $ok;
}
function smpro_sdb_fix_hide_errors(string $domain): array {
    $r = smpro_inv_resolve($domain); if (!$r) return ['ok' => false, 'msg' => 'unresolved target'];
    $doc = rtrim($r['docroot'], '/'); $f = $doc . '/.user.ini';
    if (is_link($f)) return ['ok' => false, 'msg' => 'refused: .user.ini is a link'];
    $old = null;
    if (file_exists($f)) {
        // read without following a link the account could swap in after the check above (root would copy the target)
        $st0 = @lstat($f); $h = ($st0 && ($st0['mode'] & 0170000) === 0100000 && $st0['nlink'] === 1) ? @fopen($f, 'rb') : false;
        $st1 = $h ? @fstat($h) : null;
        if (!$h || !$st1 || $st1['ino'] !== $st0['ino'] || $st1['dev'] !== $st0['dev'] || $st1['size'] > 65536) { if ($h) @fclose($h); return ['ok' => false, 'msg' => 'refused: .user.ini is not a plain file of the site']; }
        $old = (string)stream_get_contents($h); @fclose($h);
    }
    if ($old !== null && preg_match('/^\s*display_errors\s*=\s*(off|0)\s*$/mi', $old)) return ['ok' => false, 'msg' => 'display_errors is already off in .user.ini (the warnings come from code that turns it on - see Diagnose).'];
    $new = ($old === null ? '' : rtrim(preg_replace('/^\s*display_errors\s*=.*$/mi', '', $old)) . "\n") . "; Safety Monitor Pro Site Doctor: warnings go to the error log, not to visitors\ndisplay_errors = Off\n";
    if ($old !== null) {
        $bak = $f . '.smpro-bak-' . date('Ymd_His');
        if (!smpro_sdb_safe_write($doc, basename($bak), $old)) return ['ok' => false, 'msg' => 'could not back up .user.ini - nothing changed'];
        if (!smpro_sdb_safe_write($doc, '.user.ini', $new)) return ['ok' => false, 'msg' => 'could not write .user.ini'];
        $id = smpro_inv_manifest_add(['user' => $r['user'], 'domain' => $r['domain'], 'action' => 'hide_php_errors', 'kind' => 'file', 'from' => $f, 'backup' => $bak]);
    } else {
        if (!smpro_sdb_safe_write($doc, '.user.ini', $new)) return ['ok' => false, 'msg' => 'could not write .user.ini'];
        $id = smpro_inv_manifest_add(['user' => $r['user'], 'domain' => $r['domain'], 'action' => 'hide_php_errors', 'kind' => 'created', 'from' => $doc . '/index.php', 'to' => $f]);
    }
    smpro_audit('sitedoctor_fix', ['action' => 'hide_php_errors', 'user' => $r['user'], 'ok' => true]);
    return ['ok' => true, 'msg' => 'display_errors = Off written to .user.ini' . ($old !== null ? ' (old file backed up)' : ' (new file)') . '. PHP re-reads it within 5 minutes.', 'undo_id' => $id, 'delayed' => true];
}
/**
 * Missing WordPress core files: back up wp-admin, wp-includes and the root *.php (not wp-config.php) to a tarball in
 * the account's home, then let wp-cli, run AS THE ACCOUNT, download the same version's core over them. wp-content and
 * wp-config.php are never touched. Undo = unpack the tarball as the account.
 */
function smpro_sdb_fix_wp_core(string $domain): array {
    $r = smpro_inv_resolve($domain); if (!$r) return ['ok' => false, 'msg' => 'unresolved target'];
    $doc = rtrim($r['docroot'], '/'); $user = (string)$r['user']; $home = rtrim((string)$r['home'], '/');
    $wp = ''; foreach (['/usr/local/bin/wp', '/usr/bin/wp', '/usr/local/cpanel/3rdparty/bin/wp'] as $c) if (is_executable($c)) { $wp = $c; break; }
    if ($wp === '') return ['ok' => false, 'msg' => 'wp-cli is not installed on this server - restore the core files from a backup.'];
    if (!is_file($doc . '/wp-config.php') || !preg_match('/^[a-z0-9_-]+$/i', $user)) return ['ok' => false, 'msg' => 'not a WordPress web root'];
    $ver = '';
    if (is_file($doc . '/wp-includes/version.php') && preg_match("/wp_version\s*=\s*'([0-9.]+)'/", (string)@file_get_contents($doc . '/wp-includes/version.php'), $m)) $ver = $m[1];
    if ($ver === '') return ['ok' => false, 'msg' => 'the installed WordPress version could not be read - not replacing the core with a different version'];
    $bak = $home . '/.smpro-bak-wpcore-' . date('Ymd_His') . '.tar.gz';
    $items = array_values(array_filter(array_merge(['wp-admin', 'wp-includes'], array_map('basename', (array)glob($doc . '/*.php'))), fn($x) => $x !== 'wp-config.php' && file_exists($doc . '/' . $x)));
    $as = function (string $cmd) use ($user) { return (string)@shell_exec('timeout 300 su -s /bin/bash ' . escapeshellarg($user) . ' -c ' . escapeshellarg($cmd) . ' 2>&1'); };
    if ($items) { $as('umask 077; tar czf ' . escapeshellarg($bak) . ' -C ' . escapeshellarg($doc) . ' ' . implode(' ', array_map('escapeshellarg', $items)));
        if (!is_file($bak) || filesize($bak) < 1000) return ['ok' => false, 'msg' => 'could not back up the current core files - nothing changed']; }
    $o = $as('cd / && WP_CLI_CONFIG_PATH=/dev/null WP_CLI_PACKAGES_DIR=/nonexistent ' . escapeshellarg($wp) . ' core download --skip-content --force' . ($ver !== '' ? ' --version=' . escapeshellarg($ver) : '') . ' --path=' . escapeshellarg($doc));
    $ok = (bool)preg_match('/^Success:/m', $o);   // the tool's own result line, not the word anywhere in its output
    $id = $items ? smpro_inv_manifest_add(['user' => $user, 'domain' => $r['domain'], 'action' => 'restore_wp_core', 'kind' => 'tar', 'from' => $doc, 'backup' => $bak]) : '';
    smpro_audit('sitedoctor_fix', ['action' => 'restore_wp_core', 'user' => $user, 'version' => $ver ?: 'latest', 'ok' => $ok]);
    return ['ok' => $ok, 'msg' => $ok ? ('WordPress core ' . ($ver ?: '(latest)') . ' restored; wp-content and wp-config.php untouched. Previous core files backed up to ' . $bak . '.') : ('wp-cli failed: ' . substr(trim($o), -300)), 'undo_id' => $id];
}

/* ============================ discovery + probe ============================ */
/** Every site on the server: [domain => [domain, user, type, ip]]. */
function smpro_sdb_targets(): array {
    if (!function_exists('smpro_dom_list')) { $f = __DIR__ . '/domains.php'; if (is_file($f)) require_once $f; }
    $out = [];
    foreach ((function_exists('smpro_dom_list') ? smpro_dom_list() : []) as $d) {
        $dom = strtolower((string)($d['domain'] ?? '')); if ($dom === '' || ($d['user'] ?? '') === '') continue;
        if (in_array((string)($d['type'] ?? ''), ['parked'], true)) continue;   // an alias shows the same site as its main domain
        $out[$dom] = ['domain' => $dom, 'user' => (string)$d['user'], 'type' => (string)($d['type'] ?? 'main'), 'ip' => (string)($d['conf_ip'] ?? '')];
    }
    ksort($out);
    return $out;
}

/**
 * What a visitor would see, judged without the single-site engine. Pure (the caller fetches): returns
 * ['state' => ok|problem, 'kind' => short code, 'text' => human sentence].
 */
function smpro_sdb_classify(int $code, string $body, int $ms): array {
    $b = substr($body, 0, 6000);
    $marks = [
        ['Resource Limit Is Reached', 'limit_508', 'The account hit its resource limit (508).'],
        ['Error establishing a database connection', 'db_connect', 'WordPress cannot reach its database.'],
        ['SQLSTATE[', 'db_error', 'The site shows a database error to visitors.'],
        ['Fatal error</b>', 'php_fatal', 'A PHP fatal error is printed on the page.'],
        ['Parse error</b>', 'php_parse', 'A PHP parse error is printed on the page.'],
        ['Briefly unavailable for scheduled maintenance', 'wp_maintenance', 'WordPress is stuck in maintenance mode.'],
        ['Deprecated</b>', 'php_deprecated', 'PHP deprecation notices are printed to visitors (the code is older than the PHP version).'],
        ['Warning</b>:', 'php_warning', 'PHP warnings are printed to visitors.'],
        ['<title>Index of /', 'dir_listing', 'The web root shows a bare directory listing (no index page).'],
        ['defaultwebpage.cgi', 'default_page', 'The cPanel default page is shown (no site content in the web root).'],
    ];
    foreach ($marks as [$needle, $kind, $text]) if (stripos($b, $needle) !== false) return ['state' => 'problem', 'kind' => $kind, 'text' => $text];
    if ($code === 0) return ['state' => 'problem', 'kind' => 'no_answer', 'text' => 'No answer within the time limit (hung PHP, a blocked outbound call, or a dead backend).'];
    if ($code === 508) return ['state' => 'problem', 'kind' => 'limit_508', 'text' => 'The account hit its resource limit (508).'];
    if ($code >= 500) return ['state' => 'problem', 'kind' => 'http_' . $code, 'text' => 'The server answers ' . $code . '.'];
    if ($code === 403 || $code === 404) return ['state' => 'problem', 'kind' => 'http_' . $code, 'text' => 'The home page answers ' . $code . '.'];
    if ($code >= 200 && $code < 400 && strlen(trim($body)) < 20) return ['state' => 'problem', 'kind' => 'blank', 'text' => 'The page is blank.'];
    if ($code >= 200 && $code < 400) return ['state' => 'ok', 'kind' => $ms > 8000 ? 'slow' : 'ok', 'text' => $ms > 8000 ? 'Up, but slow (' . round($ms / 1000, 1) . ' s).' : 'Up.'];
    return ['state' => 'problem', 'kind' => 'http_' . $code, 'text' => 'Unexpected answer ' . $code . '.'];
}

/** Fetch the home page from this server (the site's own IP, so a CDN in front is skipped), following redirects. */
function smpro_sdb_probe(string $domain, string $ip): array {
    $ip = preg_replace('/:.*$/', '', $ip); if (!filter_var($ip, FILTER_VALIDATE_IP)) $ip = '127.0.0.1';
    $tmp = smpro_sdb_path('probe.' . getmypid() . '.body');
    $cmd = 'timeout 20 curl -ksSL --max-redirs 6 -m 15 -A ' . escapeshellarg('SafetyMonitorPro/sitedoctor') . ' -o ' . escapeshellarg($tmp)
         . ' -w ' . escapeshellarg('%{http_code}|%{time_total}|%{num_redirects}')
         . ' --resolve ' . escapeshellarg($domain . ':443:' . $ip) . ' --resolve ' . escapeshellarg($domain . ':80:' . $ip)
         . ' ' . escapeshellarg('https://' . $domain . '/') . ' 2>/dev/null';
    $w = explode('|', trim((string)@shell_exec($cmd)));
    $body = (string)@file_get_contents($tmp, false, null, 0, 65536); @unlink($tmp);
    $code = (int)($w[0] ?? 0); $ms = (int)round(((float)($w[1] ?? 0)) * 1000);
    if ((int)($w[2] ?? 0) >= 6) return ['code' => $code, 'ms' => $ms, 'state' => 'problem', 'kind' => 'redirect_loop', 'text' => 'The page redirects in a loop.'];
    return ['code' => $code, 'ms' => $ms] + smpro_sdb_classify($code, $body, $ms);
}

/* ============================ scan ============================ */
/** Probe every site (or the given ones); diagnose the failing ones with the single-site engine. Time-bounded. */
function smpro_sdb_scan(array $only = [], int $budget = 3300, bool $resume = false): array {
    $t0 = time(); $all = smpro_sdb_targets();
    if ($only) $all = array_intersect_key($all, array_flip(array_map('strtolower', $only)));
    $scan = smpro_sdb_load('scan.json', ['results' => []]);
    // Resume: an unfinished scan keeps its start time and skips every site already checked since then.
    $resume = $resume && !$only && empty($scan['finished']) && !empty($scan['started']);
    if (!$resume) $scan['started'] = $t0;
    $scan['finished'] = 0; $scan['total'] = count($all); $scan['current'] = ''; $scan['beat'] = time(); unset($scan['partial']);
    $scan['done'] = $resume ? count(array_filter((array)$scan['results'], fn($r) => (int)($r['checked_at'] ?? 0) >= (int)$scan['started'])) : 0;
    if (!$only) $scan['results'] = array_intersect_key((array)$scan['results'], $all);   // forget sites that no longer exist
    smpro_sdb_save('scan.json', $scan);
    foreach ($all as $dom => $t) {
        if (time() - $t0 > $budget) { $scan['partial'] = true; break; }
        if ($resume && (int)($scan['results'][$dom]['checked_at'] ?? 0) >= (int)$scan['started']) continue;
        $scan['current'] = $dom; $scan['beat'] = time(); smpro_sdb_save('scan.json', $scan);   // the page shows which site is being checked
        $p = smpro_sdb_probe($dom, $t['ip']);
        $row = ['domain' => $dom, 'user' => $t['user'], 'type' => $t['type'], 'checked_at' => time()] + $p;
        if ($p['state'] === 'problem' && function_exists('smpro_inv_run')) {
            $res = smpro_inv_run($dom);
            if (!empty($res['ok'])) {
                $row['platform'] = (string)($res['detect']['platform'] ?? '');
                $row['php'] = (string)($res['phpver'] ?? '');
                $row['cause'] = (string)($res['live_cause']['msg'] ?? ($res['fatals'][0]['msg'] ?? ''));
                $row['locked'] = count((array)($res['hardened'] ?? [])) > 0;
                $all_f = array_merge((array)($res['fixes'] ?? []), smpro_sdb_extra_fixes($res, (string)$p['kind']));
                $row['fixes'] = array_values(array_map(fn($f) => ['action' => (string)($f['action'] ?? ''), 'label' => (string)($f['label'] ?? ''), 'path' => (string)($f['path'] ?? ''), 'auto' => smpro_sdb_auto_allowed((string)($f['action'] ?? ''), (string)($f['path'] ?? ''))], $all_f));
                if ($row['cause'] === '' && in_array($p['kind'], ['http_403', 'dir_listing', 'default_page'], true)) $row['cause'] = smpro_sdb_noindex_cause((string)($res['docroot'] ?? ''));
            }
            // A site that was fixed before and fails again: say so (something put the fault back - an update, a
            // self-healing plugin, a restore), instead of showing it as a new problem.
            $prev = smpro_sdb_reports($dom, 1)[0] ?? null;
            if ($prev && !empty($prev['ok']) && !empty($prev['changed'])) $row['again'] = (int)$prev['ts'];
        }
        $scan['results'][$dom] = $row; $scan['done']++; $scan['beat'] = time();
        smpro_sdb_save('scan.json', $scan);   // progress after every site
    }
    $scan['current'] = '';
    if (empty($scan['partial'])) $scan['finished'] = time();   // a scan cut by its time limit stays resumable
    smpro_sdb_save('scan.json', $scan);
    if (function_exists('smpro_audit')) @smpro_audit('sitedoctor_bulk_scan', ['sites' => $scan['done'], 'problems' => count(array_filter($scan['results'], fn($r) => ($r['state'] ?? '') === 'problem'))]);
    return $scan;
}

/* ============================ fix ============================ */
/**
 * Fix one site. $auto = the switch is doing it (only fixes smpro_sdb_auto_allowed() approves; locked sites skipped).
 * Fixes run one at a time, the site is re-checked after each, and the run stops at the first that brings it back.
 * Every file the engine edits is backed up by the engine itself (.smpro-bak-*) and recorded for undo.
 */
function smpro_sdb_fix_site(string $domain, bool $auto): array {
    $rep = ['ts' => time(), 'domain' => $domain, 'mode' => $auto ? 'auto' : 'manual', 'steps' => [], 'changed' => [], 'undo' => [], 'ok' => false];
    if (!function_exists('smpro_inv_run')) { $rep['steps'][] = 'Site Doctor engine not loaded.'; return smpro_sdb_report_add($rep); }
    $t = smpro_sdb_targets()[$domain] ?? null; $ip = (string)($t['ip'] ?? '');
    $before = smpro_sdb_probe($domain, $ip);
    $rep['before'] = ['code' => $before['code'], 'ms' => $before['ms'], 'text' => $before['text']];
    $res = smpro_inv_run($domain);
    if (empty($res['ok'])) { $rep['steps'][] = 'Could not resolve the site: ' . (string)($res['msg'] ?? ''); return smpro_sdb_report_add($rep); }
    $rep['user'] = (string)$res['user']; $rep['platform'] = (string)($res['detect']['platform'] ?? ''); $rep['php'] = (string)($res['phpver'] ?? '');
    $rep['problem'] = $before['text']; $rep['cause'] = (string)($res['live_cause']['msg'] ?? ($res['fatals'][0]['msg'] ?? ''));
    if ($before['state'] === 'ok') { $rep['ok'] = true; $rep['steps'][] = 'The site already answers correctly; nothing was changed.'; $rep['after'] = $rep['before']; return smpro_sdb_report_add($rep); }
    $fixes = array_merge((array)($res['fixes'] ?? []), smpro_sdb_extra_fixes($res, (string)$before['kind']));
    if ($rep['cause'] === '' && in_array($before['kind'], ['http_403', 'dir_listing', 'default_page'], true)) $rep['cause'] = smpro_sdb_noindex_cause((string)($res['docroot'] ?? ''));
    if ($auto) {
        if (!empty($res['hardened'])) { $rep['steps'][] = 'Skipped by the automatic switch: some of this site\'s files are locked (PHP Harden / WP Guard). Tick the site to fix it by hand.'; return smpro_sdb_report_add($rep); }
        $held = array_filter($fixes, fn($f) => !smpro_sdb_auto_allowed((string)($f['action'] ?? ''), (string)($f['path'] ?? '')));
        foreach ($held as $f) $rep['steps'][] = 'Left for you (not done automatically): ' . (string)($f['label'] ?? $f['action']);
        $fixes = array_values(array_filter($fixes, fn($f) => smpro_sdb_auto_allowed((string)($f['action'] ?? ''), (string)($f['path'] ?? ''))));
    } elseif (function_exists('smpro_inv_unharden_base')) {
        $n = smpro_inv_unharden_base($res); if ($n) $rep['steps'][] = 'Cleared the immutable flag on ' . $n . ' file(s) to be edited (each is recorded for undo).';
    }
    if (!$fixes) { $rep['steps'][] = 'No known fix matches this problem on this platform' . ($rep['platform'] !== '' ? ' (' . $rep['platform'] . ')' : '') . '. Use Diagnose on the site for the full evidence.'; $rep['after'] = $rep['before']; return smpro_sdb_report_add($rep); }
    $ids0 = array_column(smpro_inv_manifest_load(), 'id');
    $after = $before;
    foreach ($fixes as $f) {
        $x = smpro_sdb_fix_one((string)$f['action'], $domain, (string)($f['path'] ?? ''));
        $rep['steps'][] = (!empty($x['ok']) ? 'Done: ' : 'Failed: ') . (string)($f['label'] ?? $f['action']) . ' - ' . (string)($x['msg'] ?? '');
        if (!empty($x['delayed'])) $rep['delayed'] = true;
        if (!empty($x['ok'])) { $after = smpro_sdb_probe($domain, $ip); if ($after['state'] === 'ok') break; }
    }
    foreach (smpro_inv_manifest_load() as $e) if (!in_array($e['id'] ?? '', $ids0, true) && ($e['domain'] ?? '') === $domain) {
        $rep['undo'][] = (string)$e['id'];
        $rep['changed'][] = ['what' => (string)($e['action'] ?? ''), 'file' => (string)($e['from'] ?? ''), 'backup' => (string)($e['backup'] ?? ($e['to'] ?? ''))];
    }
    $rep['after'] = ['code' => $after['code'], 'ms' => $after['ms'], 'text' => $after['text']];
    $rep['ok'] = $after['state'] === 'ok';
    if (!$rep['ok'] && !empty($rep['delayed']) && $after['code'] === $before['code']) $rep['steps'][] = 'PHP picks up .user.ini within 5 minutes; scan the site again after that to confirm.';
    // a fix that made the answer worse is taken back at once
    if (!$rep['ok'] && $before['code'] >= 200 && $before['code'] < 500 && ($after['code'] === 0 || $after['code'] >= 500) && $rep['undo'] && function_exists('smpro_inv_undo')) {
        foreach (array_reverse($rep['undo']) as $uid) smpro_inv_undo($uid);
        $rep['steps'][] = 'The site got worse (' . $before['code'] . ' -> ' . $after['code'] . '), so every change above was undone.';
        $rep['rolled_back'] = true;
    }
    return smpro_sdb_report_add($rep);
}
/** Append a report (bounded) and refresh the site's row in the scan. */
function smpro_sdb_report_add(array $rep): array {
    $f = smpro_sdb_path('reports.jsonl');
    @file_put_contents($f, json_encode($rep, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE) . "\n", FILE_APPEND | LOCK_EX); @chmod($f, 0600);
    clearstatcache(); if (@filesize($f) > 4000000) { $ls = file($f, FILE_IGNORE_NEW_LINES) ?: []; if (count($ls) > 4000) @file_put_contents($f . '.tmp', implode("\n", array_slice($ls, -2000)) . "\n", LOCK_EX) && @rename($f . '.tmp', $f); }
    $scan = smpro_sdb_load('scan.json', ['results' => []]);
    if (isset($scan['results'][$rep['domain']]) && isset($rep['after'])) {
        $scan['results'][$rep['domain']]['code'] = $rep['after']['code']; $scan['results'][$rep['domain']]['text'] = $rep['after']['text'];
        $scan['results'][$rep['domain']]['state'] = !empty($rep['ok']) ? 'ok' : 'problem'; $scan['results'][$rep['domain']]['last_fix'] = $rep['ts'];
        smpro_sdb_save('scan.json', $scan);
    }
    if (function_exists('smpro_audit')) @smpro_audit('sitedoctor_bulk_fix', ['domain' => $rep['domain'], 'mode' => $rep['mode'], 'ok' => !empty($rep['ok']), 'changed' => count($rep['changed'])]);
    return $rep;
}
/** Newest report per domain (or the newest $limit overall). */
function smpro_sdb_reports(string $domain = '', int $limit = 50): array {
    $f = smpro_sdb_path('reports.jsonl'); if (!@is_file($f)) return [];
    $out = []; foreach (array_reverse(file($f, FILE_IGNORE_NEW_LINES) ?: []) as $l) { $j = json_decode($l, true); if (!is_array($j)) continue; if ($domain !== '' && ($j['domain'] ?? '') !== $domain) continue; $out[] = $j; if (count($out) >= $limit) break; }
    return $out;
}

/* ============================ retention ============================ */
/**
 * Backups of edited files older than SMPRO_SDB_KEEP_DAYS are removed and their undo records closed ("expired").
 * Only real backup copies are removed (.smpro-bak-* / .smpro-optbak-* inside /home). A plugin or theme the doctor
 * disabled by renaming it (.smpro-disabled-*) is the customer's own code, not a backup: it is never deleted here.
 */
function smpro_sdb_purge(int $days = SMPRO_SDB_KEEP_DAYS): array {
    if (!function_exists('smpro_inv_manifest_path')) return ['removed' => 0];
    $cut = time() - $days * 86400; $removed = 0; $closed = 0;
    @is_dir(SMPRO_LOCKS) || @mkdir(SMPRO_LOCKS, 0700, true);
    $lk = @fopen(SMPRO_LOCKS . '/sitedoctor-manifest.lock', 'c'); if ($lk) @flock($lk, LOCK_EX);
    $m = smpro_inv_manifest_load(); $dirty = false;
    foreach ($m as &$e) {
        if (($e['status'] ?? '') !== 'applied' || (int)($e['ts'] ?? 0) > $cut) continue;
        $b = (string)($e['backup'] ?? '');
        if ($b === '' || !preg_match('/\.smpro-(bak|optbak)-/', basename($b))) continue;
        $real = @realpath($b);
        $u = preg_quote((string)($e['user'] ?? ''), '#');
        if ($real !== false && $u !== '' && preg_match('#^/home[^/]*/' . $u . '/#', $real) && !is_link($b) && @is_file($real) && @unlink($real)) $removed++;
        $e['status'] = 'expired'; $e['expired_at'] = time(); $closed++; $dirty = true;
    }
    unset($e);
    if ($dirty) { $p = smpro_inv_manifest_path(); @file_put_contents($p . '.tmp', json_encode($m, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), LOCK_EX); @chmod($p . '.tmp', 0600); @rename($p . '.tmp', $p); }
    if ($lk) { @flock($lk, LOCK_UN); @fclose($lk); }
    if (($removed || $closed) && function_exists('smpro_audit')) @smpro_audit('sitedoctor_backup_purge', ['removed' => $removed, 'closed' => $closed, 'days' => $days]);
    return ['removed' => $removed, 'closed' => $closed];
}

/* ============================ jobs + cron ============================ */
/** The job as the page sees it. A worker that died, never started, or stopped moving for 15 minutes is not "running". */
function smpro_sdb_job(): array {
    $j = smpro_sdb_load('job.json'); if (empty($j['running'])) return $j;
    $pid = (int)($j['pid'] ?? 0); $beat = (int)(smpro_sdb_load('scan.json')['beat'] ?? 0);
    $dead = ($pid > 0 && !@file_exists('/proc/' . $pid)) || ($pid === 0 && (int)($j['started'] ?? 0) < time() - 90)
         || (($j['kind'] ?? '') !== 'fix' && max($beat, (int)($j['started'] ?? 0)) < time() - 900);
    if ($dead) { $j['running'] = false; $j['stopped'] = true; smpro_sdb_save('job.json', $j); }
    return $j;
}
/** Start the detached worker: kind scan|fix, with the sites to fix. Refuses while one is running. */
function smpro_sdb_start(string $kind, array $domains = []): array {
    $j = smpro_sdb_job(); if (!empty($j['running'])) return ['ok' => false, 'msg' => 'A ' . (string)$j['kind'] . ' is already running (' . (int)($j['done'] ?? 0) . ' of ' . (int)($j['total'] ?? 0) . ').'];
    $domains = array_values(array_unique(array_filter(array_map(fn($d) => strtolower(preg_replace('/[^A-Za-z0-9.-]/', '', (string)$d)), $domains))));
    if ($kind === 'fix' && !$domains) return ['ok' => false, 'msg' => 'No site was selected.'];
    if (!in_array($kind, ['scan', 'resume', 'fix'], true)) return ['ok' => false, 'msg' => 'Unknown job.'];
    smpro_sdb_save('job.json', ['kind' => $kind, 'domains' => $domains, 'running' => true, 'started' => time(), 'done' => 0, 'total' => $kind === 'fix' ? count($domains) : 0, 'pid' => 0]);
    $php = function_exists('smpro_php_cli_bin') ? smpro_php_cli_bin() : 'php';
    $bin = SMPRO_BASE . '/bin/sitedoctor_bulk.php';
    @shell_exec('nohup timeout 3600 nice -n 10 ' . escapeshellarg($php) . ' ' . escapeshellarg($bin) . ' ' . escapeshellarg($kind) . ' >/dev/null 2>&1 </dev/null &');
    return ['ok' => true, 'msg' => $kind === 'fix' ? ('Fixing ' . count($domains) . ' site(s) in the background - you can close this page.') : ($kind === 'resume' ? 'Continuing the scan where it stopped - you can close this page.' : 'Scanning every site in the background - you can close this page.')];
}
/** The worker body. */
function smpro_sdb_run_job(string $kind): void {
    $j = smpro_sdb_load('job.json'); $j['pid'] = getmypid(); $j['running'] = true; smpro_sdb_save('job.json', $j);
    if ($kind === 'fix') {
        foreach ((array)$j['domains'] as $d) { smpro_sdb_fix_site((string)$d, false); $j['done'] = (int)$j['done'] + 1; smpro_sdb_save('job.json', $j); }
    } else {
        smpro_sdb_scan([], 3300, $kind === 'resume');
        $cfg = smpro_sdb_cfg();
        if ($kind === 'daily' && $cfg['auto']) {
            $scan = smpro_sdb_load('scan.json', ['results' => []]);
            foreach ($scan['results'] as $dom => $r) if (($r['state'] ?? '') === 'problem' && !empty($r['fixes'])) {
                smpro_sdb_fix_site((string)$dom, true);
                $sc = smpro_sdb_load('scan.json'); $sc['beat'] = time(); $sc['current'] = 'fixing ' . $dom; smpro_sdb_save('scan.json', $sc);   // still alive
            }
        }
        smpro_sdb_purge();
    }
    $j['running'] = false; $j['finished'] = time(); smpro_sdb_save('job.json', $j);
}
/** Daily scan (and, with the switch on, automatic fixes) at 05:30; the purge runs with it. */
function smpro_sdb_cron_sync(): bool {
    if (defined('SMPRO_TEST_SRC')) return true;
    $f = '/etc/cron.d/smpro-sitedoctor'; $cfg = smpro_sdb_cfg();
    if (!$cfg['scan_daily'] && !$cfg['auto']) { if (@is_file($f)) @unlink($f); return true; }
    $php = function_exists('smpro_php_cli_bin') ? smpro_php_cli_bin() : 'php';
    $want = "# Safety Monitor Pro - Site Doctor: daily scan of every site, automatic fixes when switched on, 7-day backup purge\n"
          . "30 5 * * * root timeout 3600 nice -n 10 $php " . SMPRO_BASE . "/bin/sitedoctor_bulk.php daily >/dev/null 2>&1\n";
    if (@is_file($f) && (string)@file_get_contents($f) === $want) return true;
    return function_exists('smpro_cron_install') ? smpro_cron_install($f, $want) : false;
}
