<?php
/**
 * includes/secreport.php - the Daily Security Report: one day of the server, from every record this product and
 * the server keep, as one page an operator can read top to bottom, download, print to PDF, and receive on a channel.
 *
 * Sections, in the order a person decides: score and headline numbers; the executive summary in sentences; the
 * alerts that went out (channel, delivered); the alerts that did NOT go out and why (switched off, snoozed, no
 * channel, unchanged, held for the digest) - "not sent" is never allowed to look like "nothing happened"; sign-ins
 * and access; web attacks and the WAF; malware, integrity and Learned Defense; crawlers, mail, resources, updates;
 * recommendations ordered by risk, each with why and how; per-domain details (attacks, served, malware, resources,
 * vulnerabilities) for every domain that had anything; delivery and schedule.
 *
 * Every number is read for the day's window from the server's own logs and this product's own stores. A source that
 * could not be read is reported as "not checked", never as zero. Nothing here changes the server.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

define('SMPRO_SR_DIR', SMPRO_VARLIB . '/reports/security');
define('SMPRO_SR_CFG', SMPRO_VARLIB . '/reports/security.json');
define('SMPRO_SR_KEEP_DAYS', 90);

function smpro_sr_dir(): string { @is_dir(SMPRO_SR_DIR) || @mkdir(SMPRO_SR_DIR, 0700, true); return SMPRO_SR_DIR; }
function smpro_sr_cfg(): array {
    $d = @is_file(SMPRO_SR_CFG) ? json_decode((string)@file_get_contents(SMPRO_SR_CFG), true) : null;
    $d = is_array($d) ? $d : [];
    $d += ['enabled' => false, 'hour' => 6, 'minute' => 0, 'tz' => '', 'last_run' => 0, 'last_id' => '', 'last_day' => ''];
    $d['minute'] = max(0, min(59, (int)$d['minute'])); $d['tz'] = in_array((string)$d['tz'], DateTimeZone::listIdentifiers(), true) ? (string)$d['tz'] : '';
    $d['channels'] = ($d['channels'] ?? []) + ['panel' => true, 'email' => false, 'telegram' => false, 'whatsapp' => false];
    $d['hour'] = max(0, min(23, (int)$d['hour']));
    return $d;
}
/** The clock the schedule and the report's day follow: the chosen zone, or the server's when none is chosen. */
function smpro_sr_tz(): string { $t = smpro_sr_cfg()['tz']; return $t !== '' ? $t : date_default_timezone_get(); }
function smpro_sr_now(): DateTime { return new DateTime('now', new DateTimeZone(smpro_sr_tz())); }
function smpro_sr_cfg_save(array $c): void { smpro_sr_dir(); $t = SMPRO_SR_CFG . '.tmp'; @file_put_contents($t, json_encode($c, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), LOCK_EX); @chmod($t, 0600); @rename($t, SMPRO_SR_CFG); }

/* ---------------- small readers (each says when it could not look) ---------------- */
function smpro_sr_nc(string $why): array { return ['checked' => false, 'why' => $why]; }
/** The engines the report reads; the panel loads most of them, the cron tick and a CLI load none, so each is asked for by name. */
function smpro_sr_need(): void {
    foreach (['mmdb', 'netkind', 'geologin', 'loginfeed', 'breakin', 'intrusion', 'learn', 'lvelimits', 'sysupd', 'geoset', 'geowall', 'geohulk', 'trustfeed', 'botguard', 'crawlers', 'integrity', 'notify', 'digest'] as $m) {
        $f = __DIR__ . '/' . $m . '.php'; if (is_file($f)) require_once $f;
    }
}
function smpro_sr_userdomains(): array {
    static $m = null; if ($m !== null) return $m;
    $m = [];
    foreach ((array)@file('/etc/userdomains', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $l) if (preg_match('/^([^:\s]+):\s*(\S+)/', $l, $x) && $x[1] !== '*') $m[strtolower($x[1])] = $x[2];
    return $m;
}
function smpro_sr_account_of(string $domain): string {
    $ud = smpro_sr_userdomains(); $d = strtolower($domain);
    if (isset($ud[$d])) return $ud[$d];
    while (($p = strpos($d, '.')) !== false) { $d = substr($d, $p + 1); if (isset($ud[$d])) return $ud[$d]; }
    return '';
}
function smpro_sr_docroot_of(string $domain): string {
    if (!function_exists('smpro_lr_docroots')) { $lf = __DIR__ . '/learn.php'; if (is_file($lf)) require_once $lf; }
    if (!function_exists('smpro_lr_docroots')) return '';
    $acct = smpro_sr_account_of($domain); $want = strtolower($domain);
    foreach (smpro_lr_docroots() as $root => $u) { if ($u !== $acct) continue; $ud = "/var/cpanel/userdata/$u/$want"; if (is_file($ud) && preg_match('/^[ \t]*documentroot:[ \t]*(\S+)/m', (string)@file_get_contents($ud, false, null, 0, 16384), $x) && rtrim((string)@realpath($x[1]), '/') === $root) return $root; }
    return '';
}

/* ---------------- the collectors ---------------- */
function smpro_sr_collect_alerts(int $from, int $to): array {
    if (!function_exists('smpro_ntf_sent_between')) return ['sent' => smpro_sr_nc('notifier not loaded'), 'held' => smpro_sr_nc('notifier not loaded')];
    $sent = []; foreach (smpro_ntf_sent_between($from, $to) as $r) {
        $ok = []; $fail = [];
        foreach ((array)($r['results'] ?? []) as $ch => $res) { if (!empty($res['ok'])) $ok[] = $ch; else $fail[] = $ch . ' (' . (string)($res['detail'] ?? 'failed') . ')'; }
        $sent[] = ['ts' => (int)$r['ts'], 'type' => (string)$r['type'], 'subject' => (string)$r['subject'], 'delivered' => $ok, 'failed' => $fail];
    }
    $held = []; $byKey = [];
    foreach (smpro_ntf_held_between($from, $to) as $r) {
        // the same alert held for the same reason many times (every tick) is one row with a count and a span
        $k = $r['type'] . '|' . $r['subject'] . '|' . $r['why'];
        if (!isset($byKey[$k])) { $byKey[$k] = ['ts' => (int)$r['ts'], 'last' => (int)$r['ts'], 'type' => (string)$r['type'], 'subject' => (string)$r['subject'], 'why' => (string)$r['why'], 'times' => 0]; }
        $byKey[$k]['times']++; $byKey[$k]['last'] = max($byKey[$k]['last'], (int)$r['ts']); $byKey[$k]['ts'] = min($byKey[$k]['ts'], (int)$r['ts']);
    }
    $held = array_values($byKey);
    usort($sent, fn($a, $b) => $a['ts'] <=> $b['ts']); usort($held, fn($a, $b) => $a['ts'] <=> $b['ts']);
    $chan = []; foreach ($sent as $x) foreach ($x['delivered'] as $c) $chan[$c] = ($chan[$c] ?? 0) + 1;
    return ['sent' => ['checked' => true, 'rows' => $sent, 'by_channel' => $chan], 'held' => ['checked' => true, 'rows' => $held]];
}
function smpro_sr_collect_access(int $from, int $to, array $allowedCc): array {
    $o = [];
    if (!function_exists('smpro_lf_success')) { $lf = __DIR__ . '/loginfeed.php'; if (is_file($lf)) require_once $lf; }
    if (!function_exists('smpro_lf_success')) return smpro_sr_nc('login feed not available');
    $feed = smpro_lf_success($from, 60000, ['password', 'operator', 'api', 'unknown', 'other']);
    if (empty($feed['ok'])) return smpro_sr_nc((string)($feed['msg'] ?? 'session_log / login_log could not be read'));
    $ok = 0; $foreign = []; $byUser = []; $byDomain = [];
    foreach ((array)$feed['events'] as $e) {
        $ts = (int)$e['ts']; if ($ts < $from || $ts > $to) continue;
        if (in_array((string)$e['kind'], ['operator', 'api'], true)) continue;
        $ok++; $ip = (string)$e['ip']; $cc = (function_exists('smpro_gl_country') && filter_var($ip, FILTER_VALIDATE_IP) && $ip !== '127.0.0.1') ? strtoupper((string)smpro_gl_country($ip)) : '';
        $u = (string)$e['user']; $byUser[$u] = ($byUser[$u] ?? 0) + 1;
        if ($cc !== '' && $allowedCc && !in_array($cc, $allowedCc, true)) $foreign[] = ['ts' => $ts, 'user' => $u, 'ip' => $ip, 'cc' => $cc, 'service' => (string)$e['service']];
    }
    $failed = null; $bf = null;
    if (!function_exists('smpro_aa_collect')) { $bk = __DIR__ . '/breakin.php'; if (is_file($bk)) require_once $bk; }
    if (function_exists('smpro_aa_collect')) {
        [$ev, $hid] = smpro_aa_collect('', 'failed_login', 200000, $from, $to, '');
        $failed = count($ev); $ips = []; foreach ($ev as $x) { $ip = (string)($x['ip'] ?? ''); if ($ip !== '' && $ip !== '127.0.0.1') $ips[$ip] = ($ips[$ip] ?? 0) + 1; }
        arsort($ips); $bf = ['addresses' => count($ips), 'top' => array_slice($ips, 0, 5, true)];
        if (!empty($GLOBALS['smpro_aa_unread'])) $o['unread'] = $GLOBALS['smpro_aa_unread'];
    }
    $blockedGeo = function_exists('smpro_gs_active') ? count(smpro_gs_active(false, 5000)) : null;
    $gw = function_exists('smpro_gw_cfg') ? smpro_gw_cfg() : null; $gwLive = function_exists('smpro_gw_live') ? smpro_gw_live() : null;
    $gh = function_exists('smpro_gh_status') ? smpro_gh_status() : null;
    return $o + ['checked' => true, 'ok' => $ok, 'foreign' => $foreign, 'failed' => $failed, 'bruteforce' => $bf, 'users' => count($byUser), 'geo_blocked' => $blockedGeo,
                 'wall' => $gw ? ['enabled' => !empty($gw['enabled']), 'live' => (bool)$gwLive, 'countries' => (array)$gw['countries'], 'set' => function_exists('smpro_gw_set_size') ? smpro_gw_set_size() : null, 'built' => (int)($gw['set_size'] ?? 0), 'hook' => function_exists('smpro_gw_hook_present') ? smpro_gw_hook_present() : null] : null,
                 'cphulk_lock' => $gh ? ['enabled' => !empty($gh['cfg']['enabled']), 'state' => (string)($gh['state'] ?? '')] : null];
}
function smpro_sr_collect_attacks(int $from, int $to): array {
    if (!function_exists('smpro_in_history')) return smpro_sr_nc('intrusion index not loaded');
    $rows = smpro_in_history($from, 100000); $rows = array_values(array_filter($rows, fn($r) => (int)$r['ts'] <= $to));
    $total = count($rows); $served = []; $byDom = []; $byAsn = []; $kinds = []; $hours = array_fill(0, 24, 0); $ips = [];
    foreach ($rows as $r) {
        $dom = (string)($r['domain'] ?? '') ?: '(no host)'; $code = (string)($r['code'] ?? ''); $kind = (string)($r['kind'] ?? '');
        $byDom[$dom] = $byDom[$dom] ?? ['total' => 0, 'served' => 0, 'ips' => [], 'kinds' => [], 'served_rows' => []];
        $byDom[$dom]['total']++; $byDom[$dom]['ips'][(string)$r['ip']] = 1; $byDom[$dom]['kinds'][$kind] = ($byDom[$dom]['kinds'][$kind] ?? 0) + 1;
        $kinds[$kind] = ($kinds[$kind] ?? 0) + 1; $ips[(string)$r['ip']] = ($ips[(string)$r['ip']] ?? 0) + 1;
        $hours[(int)date('G', (int)$r['ts'])]++;
        if ($code !== '' && $code[0] === '2') { $byDom[$dom]['served']++; if (count($byDom[$dom]['served_rows']) < 5) $byDom[$dom]['served_rows'][] = ['ts' => (int)$r['ts'], 'ip' => (string)$r['ip'], 'uri' => (string)($r['uri'] ?? ''), 'rule' => (string)($r['rule'] ?? '')]; $served[] = $dom; }
    }
    arsort($ips); $topIps = array_slice($ips, 0, 8, true); $topNets = [];
    foreach ($topIps as $ip => $n) { $in = function_exists('smpro_ip_intel') ? smpro_ip_intel($ip, false) : []; $k = (string)(($in['asn'] ?? '') ?: ($in['provider'] ?? 'unknown')) . ' (' . strtoupper((string)($in['country'] ?? '?')) . ')'; $topNets[$k] = ($topNets[$k] ?? 0) + $n; }
    arsort($topNets);
    foreach ($byDom as $d => &$g) { $g['uniq_ips'] = count($g['ips']); unset($g['ips']); arsort($g['kinds']); } unset($g);
    uasort($byDom, fn($a, $b) => ($b['served'] <=> $a['served']) ?: ($b['total'] <=> $a['total']));
    $blocked = 0; if (function_exists('smpro_in_state')) { $st = smpro_in_state(); foreach ((array)($st['autoblocked'] ?? []) as $ip => $v) { $t = is_array($v) ? (int)($v['ts'] ?? $v['at'] ?? 0) : (int)$v; if ($t >= $from && $t <= $to) $blocked++; } }
    return ['checked' => true, 'total' => $total, 'served' => count($served), 'served_domains' => array_values(array_unique($served)), 'domains' => count($byDom), 'by_domain' => $byDom, 'kinds' => $kinds, 'hours' => $hours, 'top_nets' => array_slice($topNets, 0, 5, true), 'autoblocked' => $blocked];
}
function smpro_sr_collect_malware(int $from, int $to): array {
    $o = ['checked' => true];
    $bin = is_executable('/usr/bin/imunify360-agent') ? '/usr/bin/imunify360-agent' : '';
    if ($bin === '') $o['imunify'] = smpro_sr_nc('Imunify360 is not installed');
    else {
        $raw = (string)@shell_exec('timeout 40 ' . $bin . ' malware malicious list --limit 500 --json 2>/dev/null'); $j = json_decode($raw, true);
        if (!is_array($j)) $o['imunify'] = smpro_sr_nc('Imunify360 did not answer');
        else { $live = []; $today = 0; foreach ((array)($j['items'] ?? []) as $it) { $f = (string)($it['file'] ?? ''); $ts = (int)($it['created'] ?? $it['timestamp'] ?? 0); if ($f !== '' && strpos($f, '/home') === 0 && !@file_exists($f)) { if ($ts >= $from && $ts <= $to) $today++; continue; } $live[] = ['file' => $f, 'user' => (string)($it['username'] ?? ''), 'ts' => $ts, 'status' => (string)($it['status'] ?? '')]; }
               $o['imunify'] = ['checked' => true, 'active' => count($live), 'rows' => array_slice($live, 0, 50), 'handled_today' => $today]; }
    }
    if (function_exists('smpro_lr_load')) {
        $F = smpro_lr_load('findings'); $fs = (array)($F['findings'] ?? []); $Q = function_exists('smpro_lr_quarantined') ? smpro_lr_quarantined(1000) : [];
        $qToday = 0; $qHeld = 0; $qBad = 0; foreach ($Q as $q) { if (empty($q['restored'])) { $qHeld++; $v = function_exists('smpro_lr_verdict_of') ? smpro_lr_verdict_of($q) : null; if ($v && $v['verdict'] === 'malicious') $qBad++; } if ((int)$q['at'] >= $from && (int)$q['at'] <= $to) $qToday++; }
        $P = smpro_lr_load('procs');
        $o['learn'] = ['checked' => true, 'findings' => count($fs), 'findings_by_user' => array_count_values(array_map(fn($f) => (string)$f['user'], $fs)), 'quarantined_today' => $qToday, 'store_held' => $qHeld, 'store_malicious' => $qBad, 'hidden_procs' => count((array)($P['rows'] ?? [])), 'rows' => array_slice(array_map(fn($f) => ['path' => (string)$f['path'], 'user' => (string)$f['user'], 'why' => implode('; ', (array)$f['why'])], $fs), 0, 40)];
    } else $o['learn'] = smpro_sr_nc('Learned Defense not loaded');
    $o['integrity'] = function_exists('smpro_integrity_check') ? ['checked' => true, 'ok' => (bool)(smpro_integrity_check()['ok'] ?? true)] : smpro_sr_nc('integrity check not loaded');
    return $o;
}
function smpro_sr_collect_resources(int $from, int $to): array {
    $o = ['checked' => true];
    if (function_exists('smpro_lv_present') && smpro_lv_present()) {
        $f = smpro_lv_faults('24h'); $o['lve'] = $f['ok'] ? ['checked' => true, 'rows' => array_slice(array_values(array_filter($f['rows'], fn($r) => (int)($r['faults'] ?? 0) > 0)), 0, 30)] : smpro_sr_nc((string)$f['why']);
        $lifts = @is_file(SMPRO_LV_LIFTS) ? json_decode((string)@file_get_contents(SMPRO_LV_LIFTS), true) : []; $lt = 0; foreach ((array)$lifts as $u => $l) { $t = (int)($l['at'] ?? $l['since'] ?? 0); if ($t >= $from && $t <= $to) $lt++; } $o['lifts_today'] = $lt;
    } else $o['lve'] = smpro_sr_nc('CloudLinux LVE is not on this server');
    $df = (string)@shell_exec('timeout 10 df -P -x tmpfs -x devtmpfs 2>/dev/null | awk "NR>1{print \\$6\\" \\"\\$5}"'); $disk = [];
    foreach (explode("\n", trim($df)) as $l) if (preg_match('/^(\S+) (\d+)%$/', trim($l), $m)) $disk[$m[1]] = (int)$m[2];
    $o['disk'] = $disk ? ['checked' => true, 'mounts' => $disk, 'worst' => max($disk)] : smpro_sr_nc('df gave no answer');
    $load = (float)(explode(' ', (string)@file_get_contents('/proc/loadavg'))[0] ?? 0); $cores = function_exists('smpro_cpu_cores') ? max(1, (int)smpro_cpu_cores()) : max(1, (int)@shell_exec('nproc 2>/dev/null'));
    $o['load'] = ['now' => $load, 'cores' => $cores];
    $q = trim((string)@shell_exec('timeout 15 /usr/sbin/exim -bpc 2>/dev/null')); $o['mail_queue'] = ctype_digit($q) ? (int)$q : null;
    return $o;
}
function smpro_sr_collect_updates(): array {
    $o = ['checked' => true];
    if (function_exists('smpro_su_state')) { $st = smpro_su_state(); $o['packages_pending'] = count((array)($st['pending'] ?? [])); $o['security_pending'] = count(array_filter((array)($st['pending'] ?? []), fn($p) => in_array((string)($p['kind'] ?? ''), ['security', 'kernel'], true))); $k = (array)($st['kernel'] ?? []); $o['kernel'] = ['running' => (string)($k['running'] ?? ''), 'installed' => (string)($k['installed'] ?? ''), 'reboot' => !empty($k['reboot_pending']) || (!empty($k['running']) && !empty($k['installed']) && $k['running'] !== $k['installed'])]; $o['last_check'] = (int)($st['last_check'] ?? 0); }
    else $o['packages'] = smpro_sr_nc('System updates not loaded');
    // PHP builds: end-of-life versions still selectable per domain
    $eol = ['ea-php54', 'ea-php55', 'ea-php56', 'ea-php70', 'ea-php71', 'ea-php72', 'ea-php73', 'ea-php74', 'ea-php80', 'ea-php81'];
    $w = '/usr/local/cpanel/bin/whmapi1'; $vh = is_executable($w) ? json_decode((string)@shell_exec('timeout 60 ' . $w . ' php_get_vhost_versions --output=json 2>/dev/null'), true) : null;
    $perDomain = []; $eolDomains = 0;
    foreach ((array)($vh['data']['versions'] ?? []) as $v) { $d = strtolower((string)($v['vhost'] ?? '')); $ver = (string)($v['version'] ?? ''); if ($d === '') continue; $perDomain[$d] = $ver; if (in_array($ver, $eol, true)) $eolDomains++; }
    $o['php'] = $vh ? ['checked' => true, 'eol_domains' => $eolDomains, 'per_domain' => $perDomain, 'eol_list' => $eol] : smpro_sr_nc('whmapi1 php_get_vhost_versions did not answer');
    return $o;
}
/** Vulnerability signs per site that need no feed: CMS core version vs the vendor's latest, EOL PHP, readable config, debug on. */
function smpro_sr_site_vulns(string $domain, string $docroot, array $phpPer, array $eol, ?string $wpLatest): array {
    $v = [];
    $php = $phpPer[strtolower($domain)] ?? ''; if ($php !== '' && in_array($php, $eol, true)) $v[] = ['sev' => 'high', 'what' => str_replace('ea-php', 'PHP ', $php) . ' (end of life) selected for this domain'];
    if ($docroot === '' || !is_dir($docroot)) return $v;
    $wpv = $docroot . '/wp-includes/version.php';
    if (is_file($wpv) && preg_match('/\$wp_version\s*=\s*[\'"]([^\'"]+)/', (string)@file_get_contents($wpv, false, null, 0, 4096), $m)) {
        $cur = $m[1]; if ($wpLatest && version_compare($cur, $wpLatest, '<')) $v[] = ['sev' => version_compare($cur, $wpLatest, '<') && (int)explode('.', $cur)[0] < (int)explode('.', $wpLatest)[0] ? 'high' : 'medium', 'what' => 'WordPress ' . $cur . ' (current ' . $wpLatest . ')'];
        $cfg = $docroot . '/wp-config.php'; if (is_file($cfg) && (@fileperms($cfg) & 0004)) $v[] = ['sev' => 'medium', 'what' => 'wp-config.php is readable by everyone (mode ' . substr(sprintf('%o', fileperms($cfg)), -3) . ')'];
        if (is_file($cfg) && preg_match('/define\(\s*[\'"]WP_DEBUG[\'"]\s*,\s*true/i', (string)@file_get_contents($cfg, false, null, 0, 65536))) $v[] = ['sev' => 'low', 'what' => 'WP_DEBUG is on'];
        $plug = $docroot . '/wp-content/plugins'; if (is_dir($plug)) { $n = count(glob($plug . '/*', GLOB_ONLYDIR) ?: []); if ($n > 40) $v[] = ['sev' => 'low', 'what' => $n . ' plugins installed (large attack surface)']; }
    }
    $env = $docroot . '/.env'; $envUp = dirname($docroot) . '/.env';
    foreach ([$env, $envUp] as $e) if (is_file($e) && preg_match('/^APP_DEBUG\s*=\s*true/mi', (string)@file_get_contents($e, false, null, 0, 16384))) { $v[] = ['sev' => 'high', 'what' => 'APP_DEBUG=true in .env (stack traces and secrets shown to visitors)']; break; }
    if (is_file($docroot . '/.git/HEAD')) $v[] = ['sev' => 'high', 'what' => 'a .git folder inside the web root (source and history downloadable)'];
    if (is_file($docroot . '/config.php') && is_dir($docroot . '/admin') && is_file($docroot . '/admin/index.php') && is_dir($docroot . '/system')) $v[] = ['sev' => 'low', 'what' => 'OpenCart admin at the default path /admin'];
    return $v;
}
function smpro_sr_wp_latest(): ?string {
    $f = smpro_sr_dir() . '/wp_latest.json'; $j = @is_file($f) ? json_decode((string)@file_get_contents($f), true) : null;
    if (is_array($j) && time() - (int)($j['at'] ?? 0) < 86400) return (string)($j['v'] ?? '') ?: null;
    $raw = function_exists('smpro_http') ? (string)(smpro_http('https://api.wordpress.org/core/version-check/1.7/', ['timeout' => 15])['body'] ?? '') : '';
    $d = json_decode($raw, true); $v = (string)($d['offers'][0]['version'] ?? '');
    if ($v !== '') @file_put_contents($f, json_encode(['at' => time(), 'v' => $v]));
    return $v !== '' ? $v : (is_array($j) ? ((string)($j['v'] ?? '') ?: null) : null);
}
function smpro_sr_collect_crawlers(): array {
    if (!function_exists('smpro_cr_stats')) return smpro_sr_nc('Crawler Control not loaded');
    $s = smpro_cr_stats('24h'); $fams = function_exists('smpro_cr_families') ? smpro_cr_families() : []; $tot = 0; $ai = 0; $top = [];
    foreach ($s as $k => $x) { $tot += (int)$x['hits']; if (in_array((string)($fams[$k]['category'] ?? ''), ['ai_crawler', 'ai_assistant', 'ai_search'], true)) $ai += (int)$x['hits']; $top[(string)($fams[$k]['name'] ?? $k)] = (int)$x['hits']; }
    arsort($top);
    return ['checked' => true, 'total' => $tot, 'ai' => $ai, 'top' => array_slice($top, 0, 5, true), 'refused' => function_exists('smpro_cr_blocked') ? smpro_cr_blocked() : []];
}

/* ---------------- score + recommendations ---------------- */
function smpro_sr_score(array $r): array {
    $s = 100; $why = [];
    $at = $r['attacks']; $ac = $r['access']; $mw = $r['malware']; $up = $r['updates']; $rs = $r['resources'];
    if (!empty($at['checked'])) { if ($at['served'] > 0) { $s -= min(30, 15 * $at['served']); $why[] = $at['served'] . ' exploit request(s) served 2xx'; } }
    if (!empty($ac['checked'])) { $n = count($ac['foreign']); if ($n) { $s -= min(20, 8 * $n); $why[] = $n . ' sign-in(s) from outside the allowed countries'; } if (!empty($ac['wall']) && $ac['wall']['enabled'] && !$ac['wall']['live']) { $s -= 10; $why[] = 'the country wall is enabled but not live'; } }
    if (!empty($mw['imunify']['checked']) && $mw['imunify']['active'] > 0) { $s -= min(25, 10 * $mw['imunify']['active']); $why[] = $mw['imunify']['active'] . ' active malicious file(s)'; }
    if (!empty($mw['learn']['checked']) && $mw['learn']['hidden_procs'] > 0) { $s -= 20; $why[] = 'hidden processes are running'; }
    if (!empty($mw['learn']['checked']) && $mw['learn']['findings'] > 0) { $s -= min(10, $mw['learn']['findings']); $why[] = $mw['learn']['findings'] . ' Learned Defense finding(s) awaiting a decision'; }
    if (!empty($mw['integrity']['checked']) && empty($mw['integrity']['ok'])) { $s -= 25; $why[] = 'plugin integrity failed'; }
    if (!empty($up['kernel']['reboot'])) { $s -= 8; $why[] = 'a kernel reboot is pending'; }
    if (!empty($up['security_pending'])) { $s -= min(10, 2 * $up['security_pending']); $why[] = $up['security_pending'] . ' security update(s) pending'; }
    if (!empty($up['php']['checked']) && $up['php']['eol_domains'] > 0) { $s -= min(8, (int)ceil($up['php']['eol_domains'] / 10)); $why[] = $up['php']['eol_domains'] . ' domain(s) on end-of-life PHP'; }
    if (!empty($rs['disk']['checked']) && $rs['disk']['worst'] >= 90) { $s -= 8; $why[] = 'a disk is ' . $rs['disk']['worst'] . '% full'; }
    return ['score' => max(0, min(100, $s)), 'why' => $why];
}
function smpro_sr_recommend(array $r): array {
    $out = [];
    $at = $r['attacks']; $ac = $r['access']; $mw = $r['malware']; $up = $r['updates']; $rs = $r['resources']; $cr = $r['crawlers']; $al = $r['alerts'];
    if (!empty($at['checked'])) foreach ($at['by_domain'] as $d => $g) if ($g['served'] > 0) { $x = $g['served_rows'][0] ?? null; $out[] = ['p' => 'high', 'title' => 'Review the ' . $g['served'] . ' exploit request(s) served 2xx on ' . $d, 'why' => 'A served exploit is the one event that can mean a foothold' . ($x ? ' (first at ' . date('H:i', $x['ts']) . ' from ' . $x['ip'] . ')' : '') . '.', 'how' => 'Open Forensics / Audit for ' . $d . ' at that minute, compare the changed files with the last clean copy, quarantine what changed.']; break; }
    if (!empty($mw['imunify']['checked']) && $mw['imunify']['active'] > 0) $out[] = ['p' => 'high', 'title' => 'Clean the ' . $mw['imunify']['active'] . ' active malicious file(s)', 'why' => 'Imunify360 still lists them on disk.', 'how' => 'Imunify360 Reports > Clean / Delete, or let the product hand them to Imunify cleanup.'];
    if (!empty($mw['learn']['checked']) && $mw['learn']['hidden_procs'] > 0) $out[] = ['p' => 'high', 'title' => 'Stop the ' . $mw['learn']['hidden_procs'] . ' hidden process(es)', 'why' => 'A program running from memory or under a false name is what a file scan cannot see.', 'how' => 'Learned Defense > Processes > Stop; what it was is kept as evidence.'];
    if (!empty($up['kernel']['reboot'])) $out[] = ['p' => 'high', 'title' => 'Reboot for the installed kernel (' . $up['kernel']['installed'] . ')', 'why' => 'The running kernel is ' . $up['kernel']['running'] . '; the fixes in the installed one are not active.', 'how' => 'System updates > reboot window. The country wall and the Login Lock come back by themselves after boot.'];
    if (!empty($ac['checked'])) { $n = count($ac['foreign']); if ($n) $out[] = ['p' => 'high', 'title' => 'Check the ' . $n . ' sign-in(s) from outside the allowed countries', 'why' => 'Each is a real accepted password from a country you do not allow; Country Login Lock blocked the addresses afterwards.', 'how' => 'Account Audit > Successful logins > country = foreign; reset the password if the owner did not travel.']; }
    if (!empty($ac['wall']) && !$ac['wall']['enabled']) $out[] = ['p' => 'medium', 'title' => 'The country wall is off', 'why' => 'Only the after-the-fact lock protects the login ports.', 'how' => 'Firewall Status > Country wall > arm (the pre-arm check now proves recent sign-ins are covered).'];
    if (!empty($al['held']['checked'])) { foreach ($al['held']['rows'] as $h) if (strpos($h['why'], 'no channel') === 0 || strpos($h['why'], 'switched off') !== false) { $out[] = ['p' => 'medium', 'title' => 'An alert type has no way to reach you: ' . $h['type'], 'why' => $h['subject'] . ' was evaluated ' . $h['times'] . ' time(s) and never sent (' . $h['why'] . ').', 'how' => 'Notifications > enable the type and at least one channel.']; break; } }
    if (!empty($up['security_pending'])) $out[] = ['p' => 'medium', 'title' => 'Install the ' . $up['security_pending'] . ' pending security update(s)', 'why' => 'Security and kernel packages are waiting.', 'how' => 'System updates > apply (a PHP-version photograph is taken first).'];
    if (!empty($up['php']['checked']) && $up['php']['eol_domains'] > 0) $out[] = ['p' => 'medium', 'title' => 'Move ' . $up['php']['eol_domains'] . ' domain(s) off end-of-life PHP', 'why' => 'EOL PHP gets no security fixes; the php2shell class of bugs lands there first.', 'how' => 'WHM > MultiPHP Manager; the per-domain section below names them.'];
    if (!empty($cr['checked']) && $cr['ai'] > 500 && !$cr['refused']) $out[] = ['p' => 'low', 'title' => 'Decide on the AI crawlers (' . number_format($cr['ai']) . ' requests in 24 h)', 'why' => 'They read your customers\' shops at bulk and return nothing; none is refused.', 'how' => 'Bot Guard > Crawlers > "Refuse all AI crawlers" (search engines are never touched).'];
    if (!empty($rs['disk']['checked']) && $rs['disk']['worst'] >= 85) $out[] = ['p' => 'medium', 'title' => 'A disk is ' . $rs['disk']['worst'] . '% full', 'why' => 'Logs and backups stop silently at 100%.', 'how' => 'Disk / Storage > largest accounts, caches, old backups.'];
    if (!empty($rs['lve']['checked']) && count($rs['lve']['rows']) >= 3) $out[] = ['p' => 'low', 'title' => count($rs['lve']['rows']) . ' accounts hit their resource limits', 'why' => 'Repeated 508s are usually a stuck wp-cron or a cache job, not traffic.', 'how' => 'Resource Limit Reached > each account says what to do; the stuck-cron detector repairs the common case.'];
    $rank = ['high' => 0, 'medium' => 1, 'low' => 2]; usort($out, fn($a, $b) => $rank[$a['p']] <=> $rank[$b['p']]);
    return array_slice($out, 0, 10);
}
/* ---------------- per-domain ---------------- */
function smpro_sr_domains(array $r, int $from, int $to): array {
    $d = [];
    $touch = function (string $dom) use (&$d) { $dom = strtolower($dom); if (!isset($d[$dom])) $d[$dom] = ['domain' => $dom, 'account' => smpro_sr_account_of($dom), 'attacks' => 0, 'served' => 0, 'served_rows' => [], 'kinds' => [], 'uniq_ips' => 0, 'malware' => [], 'resources' => [], 'vulns' => [], 'foreign' => [], 'risk' => 0]; return $dom; };
    if (!empty($r['attacks']['checked'])) foreach ($r['attacks']['by_domain'] as $dom => $g) { if ($dom === '(no host)') continue; $k = $touch($dom); $d[$k]['attacks'] = $g['total']; $d[$k]['served'] = $g['served']; $d[$k]['served_rows'] = $g['served_rows']; $d[$k]['kinds'] = $g['kinds']; $d[$k]['uniq_ips'] = $g['uniq_ips']; }
    if (!empty($r['malware']['imunify']['checked'])) foreach ($r['malware']['imunify']['rows'] as $row) { $dom = smpro_sr_domain_of_path((string)$row['file']); if ($dom === '') continue; $k = $touch($dom); $d[$k]['malware'][] = 'Imunify360: ' . $row['file'] . ' (' . $row['status'] . ')'; }
    if (!empty($r['malware']['learn']['checked'])) foreach ($r['malware']['learn']['rows'] as $row) { $dom = smpro_sr_domain_of_path((string)$row['path']); if ($dom === '') continue; $k = $touch($dom); $d[$k]['malware'][] = 'Learned Defense: ' . $row['path'] . ' - ' . $row['why']; }
    if (!empty($r['access']['checked'])) foreach ($r['access']['foreign'] as $f) { $u = (string)$f['user']; $dom = strpos($u, '@') !== false ? substr($u, strpos($u, '@') + 1) : ''; if ($dom === '') { foreach (smpro_sr_userdomains() as $dd => $acc) if ($acc === $u) { $dom = $dd; break; } } if ($dom === '') continue; $k = $touch($dom); $d[$k]['foreign'][] = date('H:i', $f['ts']) . ' ' . $u . ' from ' . $f['ip'] . ' (' . $f['cc'] . ')'; }
    if (!empty($r['resources']['lve']['checked'])) foreach ($r['resources']['lve']['rows'] as $row) { $u = (string)($row['user'] ?? $row['id'] ?? ''); if ($u === '') continue; foreach (smpro_sr_userdomains() as $dd => $acc) if ($acc === $u) { $k = $touch($dd); $d[$k]['resources'][] = 'LVE: ' . (int)$row['faults'] . ' limit hit(s) in 24 h' . (!empty($row['cpu_f']) ? ', CPU' : '') . (!empty($row['pmem_f']) ? ', memory' : '') . (!empty($row['ep_f']) ? ', entry processes' : ''); break; } }
    $php = $r['updates']['php']['checked'] ?? false ? $r['updates']['php']['per_domain'] : []; $eol = $r['updates']['php']['eol_list'] ?? []; $wpLatest = smpro_sr_wp_latest();
    // vulnerabilities: every domain already in the table, plus every main domain with a docroot (bounded)
    $cands = array_keys($d); $n = 0; foreach (smpro_sr_userdomains() as $dom => $acc) { if (!isset($d[$dom]) && $n < 400) { $cands[] = $dom; $n++; } }
    $t0 = microtime(true);
    foreach ($cands as $dom) { if (microtime(true) - $t0 > 60) break; $root = smpro_sr_docroot_of($dom); $v = smpro_sr_site_vulns($dom, $root, $php, $eol, $wpLatest); if ($v) { $k = $touch($dom); $d[$k]['vulns'] = $v; } }
    foreach ($d as &$x) { $risk = 0; $risk += $x['served'] * 40 + min(20, (int)($x['attacks'] / 100)); $risk += count($x['malware']) * 30; $risk += count($x['foreign']) * 25; foreach ($x['vulns'] as $v) $risk += ['high' => 15, 'medium' => 7, 'low' => 2][$v['sev']] ?? 2; $risk += count($x['resources']) * 5; $x['risk'] = $risk; $x['level'] = $risk >= 60 ? 'critical' : ($risk >= 25 ? 'high' : ($risk > 0 ? 'medium' : 'clean')); } unset($x);
    uasort($d, fn($a, $b) => $b['risk'] <=> $a['risk']);
    return $d;
}
function smpro_sr_domain_of_path(string $path): string {
    if (!function_exists('smpro_lr_owner_root')) { $lf = __DIR__ . '/learn.php'; if (is_file($lf)) require_once $lf; }
    if (function_exists('smpro_lr_owner_root')) { [$root, $user] = smpro_lr_owner_root($path); if ($root !== '') { $acct = $user; foreach (glob("/var/cpanel/userdata/$acct/*") ?: [] as $f) { $b = basename($f); if ($b === 'main' || strpos($b, '_SSL') !== false || strpos($b, '.') === false || preg_match('/\.(cache|json|yaml|db)$/', $b)) continue; if (preg_match('/^[ \t]*documentroot:[ \t]*(\S+)/m', (string)@file_get_contents($f, false, null, 0, 16384), $x) && rtrim((string)@realpath($x[1]), '/') === $root) return strtolower($b); } } }
    if (preg_match('#^/home[0-9]*/([^/]+)/#', $path, $m)) { foreach (smpro_sr_userdomains() as $dom => $acc) if ($acc === $m[1]) return $dom; }
    return '';
}

/* ---------------- build / store / render ---------------- */
function smpro_sr_build(int $dayStart = 0): array {
    smpro_sr_need();
    if (smpro_sr_cfg()['tz'] !== '') @date_default_timezone_set(smpro_sr_tz());   // the day's edges and every printed time follow the chosen clock
    $dayStart = $dayStart ?: strtotime('yesterday 00:00:00'); $from = $dayStart; $to = $dayStart + 86399;
    $allowed = function_exists('smpro_gl_cfg') ? array_map('strtoupper', (array)(smpro_gl_cfg()['countries'] ?? [])) : [];
    $r = ['id' => date('Ymd', $from), 'day' => date('Y-m-d', $from), 'from' => $from, 'to' => $to, 'generated' => time(), 'host' => (string)gethostname(), 'version' => defined('SMPRO_VERSION') ? SMPRO_VERSION : '', 'allowed_cc' => $allowed];
    $r['alerts'] = smpro_sr_collect_alerts($from, $to);
    $r['access'] = smpro_sr_collect_access($from, $to, $allowed);
    $r['attacks'] = smpro_sr_collect_attacks($from, $to);
    $r['malware'] = smpro_sr_collect_malware($from, $to);
    $r['resources'] = smpro_sr_collect_resources($from, $to);
    $r['updates'] = smpro_sr_collect_updates();
    $r['crawlers'] = smpro_sr_collect_crawlers();
    $r['domains'] = smpro_sr_domains($r, $from, $to);
    $r['score'] = smpro_sr_score($r);
    $prev = smpro_sr_get(date('Ymd', $from - 86400)); $r['score']['prev'] = $prev ? (int)($prev['score']['score'] ?? 0) : null;
    $r['recommendations'] = smpro_sr_recommend($r);
    $r['summary'] = smpro_sr_summary($r);
    return $r;
}
function smpro_sr_summary(array $r): string {
    $at = $r['attacks']; $ac = $r['access']; $mw = $r['malware']; $al = $r['alerts']; $up = $r['updates'];
    $p = [];
    if (!empty($at['checked'])) { $p[] = 'The server saw ' . number_format($at['total']) . ' attack request' . ($at['total'] === 1 ? '' : 's') . ' across ' . $at['domains'] . ' domain' . ($at['domains'] === 1 ? '' : 's') . ($at['served'] ? '; ' . $at['served'] . ' of them were SERVED a 2xx on ' . implode(', ', array_slice($at['served_domains'], 0, 3)) . ' and are the first thing to look at' : '; none was served, the WAF refused them all') . '.'; } else $p[] = 'The attack index could not be read (' . $at['why'] . ').';
    if (!empty($ac['checked'])) { $n = count($ac['foreign']); $p[] = number_format($ac['ok']) . ' successful sign-ins; ' . ($n ? $n . ' from outside the allowed countries (' . implode(', ', array_unique(array_map(fn($f) => $f['user'] . ' from ' . $f['cc'], $ac['foreign']))) . ')' : 'all from allowed countries') . '.' . ($ac['failed'] !== null ? ' ' . number_format($ac['failed']) . ' failed attempts from ' . (int)($ac['bruteforce']['addresses'] ?? 0) . ' addresses.' : ''); } else $p[] = 'Sign-ins could not be read (' . $ac['why'] . ').';
    if (!empty($mw['imunify']['checked'])) $p[] = ($mw['imunify']['active'] ? $mw['imunify']['active'] . ' malicious file(s) are still active' : 'No active malware') . ($mw['learn']['checked'] ?? false ? '; Learned Defense holds ' . $mw['learn']['store_held'] . ' file(s) in the store (' . $mw['learn']['store_malicious'] . ' judged malicious) and has ' . $mw['learn']['findings'] . ' finding(s) awaiting a decision' : '') . '.';
    if (!empty($al['sent']['checked'])) { $hn = count($al['held']['rows'] ?? []); $p[] = count($al['sent']['rows']) . ' alert(s) went out (' . (implode(', ', array_map(fn($k, $v) => "$k $v", array_keys($al['sent']['by_channel']), $al['sent']['by_channel'])) ?: 'no channel') . ')' . ($hn ? '; ' . $hn . ' were evaluated and not sent - the reasons are in section 3' : '') . '.'; }
    if (!empty($up['kernel']['reboot'])) $p[] = 'A kernel reboot is still pending.';
    return implode(' ', $p);
}
function smpro_sr_save(array $r): void { smpro_sr_dir(); @file_put_contents(smpro_sr_dir() . '/' . $r['id'] . '.json', json_encode($r, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE), LOCK_EX); @chmod(smpro_sr_dir() . '/' . $r['id'] . '.json', 0600);
    foreach (glob(smpro_sr_dir() . '/2*.json') ?: [] as $f) if ((int)@filemtime($f) < time() - SMPRO_SR_KEEP_DAYS * 86400) @unlink($f); }
function smpro_sr_get(string $id): ?array { $id = preg_replace('/[^0-9]/', '', $id); $f = smpro_sr_dir() . '/' . $id . '.json'; if (!is_file($f)) return null; $j = json_decode((string)@file_get_contents($f), true); return is_array($j) ? $j : null; }
function smpro_sr_list(int $limit = 90): array { $out = []; foreach (array_reverse(glob(smpro_sr_dir() . '/2*.json') ?: []) as $f) { $j = json_decode((string)@file_get_contents($f), true); if (is_array($j)) $out[] = ['id' => $j['id'], 'day' => $j['day'], 'score' => (int)($j['score']['score'] ?? 0), 'served' => (int)($j['attacks']['served'] ?? 0), 'foreign' => count($j['access']['foreign'] ?? []), 'sent' => count($j['alerts']['sent']['rows'] ?? []), 'held' => count($j['alerts']['held']['rows'] ?? []), 'generated' => (int)$j['generated']]; if (count($out) >= $limit) break; } return $out; }

function smpro_sr_h($v): string { return htmlspecialchars((string)$v, ENT_QUOTES, 'UTF-8'); }
/** The report as one self-contained page (download, print to PDF, email attachment). $full = every domain row. */
function smpro_sr_render_html(array $r, bool $full = true, bool $embed = false): string {
    $h = 'smpro_sr_h'; $sc = (int)$r['score']['score']; $prev = $r['score']['prev'];
    $ago = fn($t) => date('H:i', (int)$t);
    $css = '*{box-sizing:border-box}body{margin:0;background:#f6f8fa;color:#17202a;font:14px/1.55 "Segoe UI",system-ui,-apple-system,sans-serif}.page{max-width:1040px;margin:0 auto;padding:24px 16px 60px}.hdr{background:#fff;border:1px solid #e3e8ee;border-radius:14px;padding:20px 24px;display:grid;grid-template-columns:1fr auto;gap:16px;align-items:center}.hdr h1{margin:0 0 4px;font-size:22px}.meta{color:#5f6b7a;font-size:13px}.score{text-align:center;padding:8px 18px;border-radius:12px;background:#e9f0fa;min-width:150px}.score b{display:block;font-size:34px;line-height:1;color:#1f4e8c}.score span{font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:#5f6b7a}.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:14px 0 18px}.kpi{background:#fff;border:1px solid #e3e8ee;border-radius:12px;padding:12px 14px;border-top:3px solid #e3e8ee}.kpi .l{font-size:10.5px;letter-spacing:.06em;text-transform:uppercase;color:#5f6b7a;font-weight:700}.kpi .v{font-size:22px;font-weight:800;margin-top:4px}.kpi .s{font-size:11.5px;color:#5f6b7a}.kpi.good{border-top-color:#1a7f4b}.kpi.good .v{color:#1a7f4b}.kpi.warn{border-top-color:#9a5b00}.kpi.warn .v{color:#9a5b00}.kpi.dang{border-top-color:#b3261e}.kpi.dang .v{color:#b3261e}.kpi.brand{border-top-color:#1f4e8c}.sec{background:#fff;border:1px solid #e3e8ee;border-radius:14px;margin:0 0 16px;overflow:hidden;break-inside:avoid}.sec>h2{margin:0;padding:12px 18px;font-size:15px;border-bottom:1px solid #e3e8ee;display:flex;gap:10px;align-items:center}.sec>h2 .n{margin-left:auto;font-size:12px;color:#5f6b7a;font-weight:500}.body{padding:14px 18px}.pill{display:inline-block;font-size:11px;font-weight:800;padding:2px 9px;border-radius:999px}.pill.good{background:#e6f5ec;color:#1a7f4b}.pill.warn{background:#fff4e0;color:#9a5b00}.pill.dang{background:#fbe9e7;color:#b3261e}.pill.brand{background:#e9f0fa;color:#1f4e8c}.pill.gray{background:#f6f8fa;color:#5f6b7a;border:1px solid #e3e8ee}table{width:100%;border-collapse:collapse;font-size:13px}th{text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:#5f6b7a;padding:8px;border-bottom:1px solid #e3e8ee}td{padding:8px;border-bottom:1px solid #e3e8ee;vertical-align:top}tr:last-child td{border-bottom:0}.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;word-break:break-all}.two{display:grid;grid-template-columns:1fr 1fr;gap:16px}@media(max-width:860px){.two{grid-template-columns:1fr}}.sum{font-size:14px;line-height:1.75}.rec{display:grid;grid-template-columns:28px 1fr;gap:10px;padding:10px 0;border-bottom:1px dashed #e3e8ee}.rec:last-child{border-bottom:0}.rec .p{width:28px;height:28px;border-radius:8px;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:12px}.rec .p.high{background:#fbe9e7;color:#b3261e}.rec .p.medium{background:#fff4e0;color:#9a5b00}.rec .p.low{background:#e9f0fa;color:#1f4e8c}.rec b{display:block}.rec .why{color:#5f6b7a;font-size:12.5px}.rec .how{font-size:12.5px;margin-top:2px}.small{font-size:12px;color:#5f6b7a}.nc{color:#9a5b00;font-size:12.5px}details.dom{border:1px solid #e3e8ee;border-radius:10px;margin:8px 0;background:#f6f8fa}details.dom>summary{list-style:none;cursor:pointer;padding:10px 12px;display:grid;grid-template-columns:minmax(180px,1.4fr) repeat(5,minmax(70px,1fr)) 90px;gap:8px;align-items:center;font-size:13px}details.dom>summary::-webkit-details-marker{display:none}details.dom>summary .d{font-weight:700;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px}details.dom>summary .c{text-align:right;font-variant-numeric:tabular-nums}details.dom[open]>summary{border-bottom:1px solid #e3e8ee}details.dom .in{padding:10px 14px 12px;display:grid;grid-template-columns:1fr 1fr;gap:12px 24px;font-size:12.5px;background:#fff}details.dom .in h4{margin:0 0 4px;font-size:12px;letter-spacing:.05em;text-transform:uppercase;color:#5f6b7a}details.dom .in ul{margin:0;padding-left:16px}.domhead{display:grid;grid-template-columns:minmax(180px,1.4fr) repeat(5,minmax(70px,1fr)) 90px;gap:8px;padding:4px 12px;font-size:10.5px;text-transform:uppercase;letter-spacing:.05em;color:#5f6b7a;font-weight:700}.domhead .c{text-align:right}.spark{display:flex;align-items:flex-end;gap:3px;height:38px}.spark i{flex:1;background:#1f4e8c;opacity:.65;border-radius:2px 2px 0 0}@media print{.noprint{display:none}.page{padding:0}details.dom{break-inside:avoid}details.dom .in{display:grid!important}}';
    $o = $embed ? '<style>' . $css . '</style><div class="page">' : '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Daily Security Report ' . $h($r['day']) . ' - ' . $h($r['host']) . '</title><style>' . $css . '</style></head><body><div class="page">';
    $at = $r['attacks']; $ac = $r['access']; $mw = $r['malware']; $rs = $r['resources']; $up = $r['updates']; $cr = $r['crawlers']; $al = $r['alerts'];
    $crit = ($at['served'] ?? 0) + count($ac['foreign'] ?? []) + (int)($mw['imunify']['active'] ?? 0) + (int)($mw['learn']['hidden_procs'] ?? 0);
    $warnN = count($r['recommendations']);
    $o .= '<div class="hdr"><div><h1>Daily Security Report - ' . $h($r['host']) . '</h1><div class="meta">' . $h(date('l Y-m-d', $r['from'])) . ', 00:00 to 23:59 (' . $h(date_default_timezone_get()) . ') · generated ' . $h(date('Y-m-d H:i', $r['generated'])) . ' · Safety Monitor Pro ' . $h($r['version']) . ($prev !== null ? ' · compared with the previous day' : '') . '</div>'
        . '<div style="margin-top:8px"><span class="pill dang">' . (int)$crit . ' critical</span> <span class="pill warn">' . $warnN . ' recommendation' . ($warnN === 1 ? '' : 's') . '</span> <span class="pill gray">' . count($al['held']['rows'] ?? []) . ' alert(s) not sent - see why</span></div></div>'
        . '<div class="score"><span>Security score</span><b>' . $sc . '</b><span>' . ($prev !== null ? 'yesterday ' . (int)$prev . ' · ' . ($sc - $prev >= 0 ? '+' : '') . ($sc - $prev) : 'first report') . '</span></div></div>';
    $k = function ($cls, $l, $v, $s) use ($h) { return '<div class="kpi ' . $cls . '"><div class="l">' . $h($l) . '</div><div class="v">' . $h($v) . '</div><div class="s">' . $h($s) . '</div></div>'; };
    $fn = count($ac['foreign'] ?? []);
    $o .= '<div class="kpis">' . $k($fn ? 'dang' : 'good', 'Foreign sign-ins', $ac['checked'] ? $fn : '?', $ac['checked'] ? ($fn ? implode(', ', array_unique(array_column($ac['foreign'], 'cc'))) . ' - blocked afterwards' : 'all from allowed countries') : 'not checked')
        . $k(($at['served'] ?? 0) ? 'dang' : (($at['total'] ?? 0) > 1000 ? 'warn' : 'good'), 'Web attacks', $at['checked'] ? number_format($at['total']) : '?', $at['checked'] ? ($at['total'] ? round(100 - $at['served'] / max(1, $at['total']) * 100, 1) . '% refused · ' . $at['served'] . ' served' : 'none') : 'not checked')
        . $k(!empty($mw['imunify']['checked']) ? ($mw['imunify']['active'] ? 'dang' : 'good') : 'warn', 'Malware active', !empty($mw['imunify']['checked']) ? $mw['imunify']['active'] : '?', !empty($mw['learn']['checked']) ? $mw['learn']['store_held'] . ' in the store · ' . $mw['learn']['findings'] . ' findings' : 'not checked')
        . $k(!empty($rs['lve']['checked']) ? (count($rs['lve']['rows']) ? 'warn' : 'good') : 'brand', 'Accounts over limits', !empty($rs['lve']['checked']) ? count($rs['lve']['rows']) : '-', !empty($rs['lve']['checked']) ? 'LVE 24 h · ' . (int)($rs['lifts_today'] ?? 0) . ' lifted' : (string)($rs['lve']['why'] ?? ''))
        . $k(!empty($up['kernel']['reboot']) ? 'warn' : ((int)($up['security_pending'] ?? 0) ? 'warn' : 'good'), 'Updates pending', (int)($up['packages_pending'] ?? 0), (!empty($up['kernel']['reboot']) ? 'kernel reboot pending' : 'kernel current') . ' · ' . (int)($up['php']['eol_domains'] ?? 0) . ' EOL-PHP domains')
        . $k('brand', 'Alerts sent / held', count($al['sent']['rows'] ?? []) . ' / ' . count($al['held']['rows'] ?? []), implode(' · ', array_map(fn($c, $n) => ucfirst($c) . ' ' . $n, array_keys($al['sent']['by_channel'] ?? []), $al['sent']['by_channel'] ?? [])) ?: 'no channel delivered') . '</div>';
    $o .= '<div class="sec"><h2>1 · Executive summary</h2><div class="body sum">' . $h($r['summary']) . '</div></div>';
    // 2 sent
    $o .= '<div class="sec"><h2>2 · Alerts sent <span class="n">' . count($al['sent']['rows'] ?? []) . ' alert(s)</span></h2><div class="body">';
    if (empty($al['sent']['checked'])) $o .= '<div class="nc">not checked: ' . $h($al['sent']['why']) . '</div>';
    elseif (!$al['sent']['rows']) $o .= '<div class="small">No alert was sent on this day.</div>';
    else { $o .= '<table><thead><tr><th>Time</th><th>Alert</th><th>Type</th><th>Delivered</th><th>Failed</th></tr></thead><tbody>'; foreach ($al['sent']['rows'] as $x) $o .= '<tr><td class="mono">' . $ago($x['ts']) . '</td><td>' . $h($x['subject']) . '</td><td class="small">' . $h($x['type']) . '</td><td>' . ($x['delivered'] ? '<span class="pill good">' . $h(implode(', ', $x['delivered'])) . '</span>' : '<span class="pill dang">none</span>') . '</td><td class="small">' . $h(implode('; ', $x['failed'])) . '</td></tr>'; $o .= '</tbody></table>'; }
    $o .= '</div></div>';
    // 3 held
    $o .= '<div class="sec"><h2>3 · Alerts NOT sent - and why <span class="n">' . count($al['held']['rows'] ?? []) . ' distinct · every evaluated alert that did not go out</span></h2><div class="body">';
    if (empty($al['held']['checked'])) $o .= '<div class="nc">not checked: ' . $h($al['held']['why']) . '</div>';
    elseif (!$al['held']['rows']) $o .= '<div class="small">Nothing was held back on this day (the record starts with this version; earlier days have none).</div>';
    else { $o .= '<table><thead><tr><th>First / last</th><th>Alert</th><th>Type</th><th>Why it was not sent</th><th class="num">Times</th></tr></thead><tbody>'; foreach ($al['held']['rows'] as $x) { $bad = strpos($x['why'], 'no channel') === 0 || strpos($x['why'], 'switched off') !== false; $o .= '<tr><td class="mono">' . $ago($x['ts']) . ($x['last'] !== $x['ts'] ? ' - ' . $ago($x['last']) : '') . '</td><td>' . $h($x['subject']) . '</td><td class="small">' . $h($x['type']) . '</td><td>' . ($bad ? '<span class="pill warn">check</span> ' : '') . $h($x['why']) . '</td><td class="num">' . (int)$x['times'] . '</td></tr>'; } $o .= '</tbody></table>'; }
    $o .= '<p class="small" style="margin:10px 0 0">"Not sent" never means "nothing happened": a rule silenced it, or no channel could carry it. Rows marked <b>check</b> are the ones to look at.</p></div></div>';
    // 4 + 5
    $o .= '<div class="two"><div class="sec"><h2>4 · Sign-ins and access</h2><div class="body">';
    if (empty($ac['checked'])) $o .= '<div class="nc">not checked: ' . $h($ac['why']) . '</div>';
    else { $w = $ac['wall']; $o .= '<table><tbody><tr><td>Successful sign-ins (cPanel/WHM/webmail)</td><td class="num">' . number_format($ac['ok']) . '</td></tr><tr><td>From outside the allowed countries' . ($r['allowed_cc'] ? ' (' . $h(implode(', ', $r['allowed_cc'])) . ')' : '') . '</td><td class="num">' . ($fn ? '<span class="pill dang">' . $fn . '</span>' : '0') . '</td></tr><tr><td>Failed sign-ins</td><td class="num">' . ($ac['failed'] === null ? 'not checked' : number_format($ac['failed']) . ' from ' . (int)$ac['bruteforce']['addresses'] . ' addresses') . '</td></tr><tr><td>Addresses held by Country Login Lock</td><td class="num">' . ($ac['geo_blocked'] === null ? '-' : number_format($ac['geo_blocked'])) . '</td></tr>'
             . '<tr><td>Country wall</td><td class="num">' . ($w ? ($w['live'] ? '<span class="pill good">UP</span> set ' . number_format((int)$w['set']) . ' of ' . number_format($w['built']) . ' · hook ' . ($w['hook'] ? 'ok' : 'missing') : ($w['enabled'] ? '<span class="pill dang">enabled, NOT live</span>' : '<span class="pill gray">off</span>')) : '-') . '</td></tr><tr><td>cPHulk country lock</td><td class="num">' . ($ac['cphulk_lock'] ? ($ac['cphulk_lock']['enabled'] ? '<span class="pill good">on</span> ' . $h($ac['cphulk_lock']['state']) : '<span class="pill gray">off</span>') : '-') . '</td></tr></tbody></table>';
        if ($fn) { $o .= '<table style="margin-top:10px"><thead><tr><th>Time</th><th>Account</th><th>From</th><th>Service</th></tr></thead><tbody>'; foreach ($ac['foreign'] as $f) $o .= '<tr><td class="mono">' . $ago($f['ts']) . '</td><td>' . $h($f['user']) . '</td><td class="mono">' . $h($f['ip']) . ' (' . $h($f['cc']) . ')</td><td>' . $h($f['service']) . '</td></tr>'; $o .= '</tbody></table>'; }
        if (!empty($ac['unread'])) $o .= '<div class="nc" style="margin-top:8px">Could not read: ' . $h(implode(', ', $ac['unread'])) . ' - those counts are "not seen", not zero.</div>'; }
    $o .= '</div></div><div class="sec"><h2>5 · Web attacks and WAF</h2><div class="body">';
    if (empty($at['checked'])) $o .= '<div class="nc">not checked: ' . $h($at['why']) . '</div>';
    else { $mx = max(1, max($at['hours'])); $o .= '<div class="spark">'; for ($i = 0; $i < 24; $i += 2) { $v = $at['hours'][$i] + $at['hours'][$i + 1]; $o .= '<i style="height:' . max(3, round($v / max(1, $mx * 2) * 100)) . '%" title="' . $i . ':00 ' . $v . '"></i>'; } $o .= '</div><div class="small" style="margin:4px 0 10px">attack requests per 2-hour slot</div>';
        $o .= '<table><tbody><tr><td>Attack requests</td><td class="num">' . number_format($at['total']) . '</td></tr><tr><td>Served 2xx (possible success)</td><td class="num">' . ($at['served'] ? '<span class="pill dang">' . $at['served'] . '</span> ' . $h(implode(', ', array_slice($at['served_domains'], 0, 3))) : '0') . '</td></tr><tr><td>Domains touched</td><td class="num">' . (int)$at['domains'] . '</td></tr><tr><td>Top attacking networks</td><td class="num small">' . $h(implode(' · ', array_map(fn($k, $v) => "$k $v", array_keys($at['top_nets']), $at['top_nets']))) . '</td></tr><tr><td>Kinds</td><td class="num small">' . $h(implode(' · ', array_map(fn($k, $v) => "$k $v", array_keys(array_slice($at['kinds'], 0, 5, true)), array_slice($at['kinds'], 0, 5, true)))) . '</td></tr><tr><td>Attacker addresses auto-blocked today</td><td class="num">' . (int)$at['autoblocked'] . '</td></tr></tbody></table>'; }
    $o .= '</div></div></div>';
    // 6 + 7
    $o .= '<div class="two"><div class="sec"><h2>6 · Malware, integrity, Learned Defense</h2><div class="body"><table><tbody>';
    $o .= '<tr><td>Imunify360 active malicious files</td><td class="num">' . (!empty($mw['imunify']['checked']) ? ($mw['imunify']['active'] ? '<span class="pill dang">' . $mw['imunify']['active'] . '</span>' : '<span class="pill good">0</span>') : '<span class="nc">' . $h($mw['imunify']['why']) . '</span>') . '</td></tr>';
    if (!empty($mw['learn']['checked'])) $o .= '<tr><td>Learned Defense findings awaiting a decision</td><td class="num">' . (int)$mw['learn']['findings'] . '</td></tr><tr><td>Quarantined today</td><td class="num">' . (int)$mw['learn']['quarantined_today'] . '</td></tr><tr><td>Store: held / judged malicious</td><td class="num">' . (int)$mw['learn']['store_held'] . ' / ' . (int)$mw['learn']['store_malicious'] . '</td></tr><tr><td>Hidden processes</td><td class="num">' . ($mw['learn']['hidden_procs'] ? '<span class="pill dang">' . (int)$mw['learn']['hidden_procs'] . '</span>' : '<span class="pill good">0</span>') . '</td></tr>';
    $o .= '<tr><td>Plugin integrity</td><td class="num">' . (!empty($mw['integrity']['checked']) ? ($mw['integrity']['ok'] ? '<span class="pill good">intact</span>' : '<span class="pill dang">FAILED</span>') : '<span class="nc">' . $h($mw['integrity']['why']) . '</span>') . '</td></tr></tbody></table></div></div>';
    $o .= '<div class="sec"><h2>7 · Crawlers, mail, resources, updates</h2><div class="body"><table><tbody>';
    $o .= '<tr><td>Crawler requests (24 h)</td><td class="num">' . (!empty($cr['checked']) ? number_format($cr['total']) . ' · AI ' . number_format($cr['ai']) : '<span class="nc">' . $h($cr['why']) . '</span>') . '</td></tr>';
    if (!empty($cr['checked'])) $o .= '<tr><td>Refused crawler families</td><td class="num">' . count($cr['refused']) . '</td></tr>';
    $o .= '<tr><td>Mail queue</td><td class="num">' . ($rs['mail_queue'] === null ? 'not checked' : number_format($rs['mail_queue'])) . '</td></tr><tr><td>Accounts at resource limit (24 h)</td><td class="num">' . (!empty($rs['lve']['checked']) ? count($rs['lve']['rows']) . ' · ' . (int)$rs['lifts_today'] . ' lifted' : '<span class="nc">' . $h($rs['lve']['why']) . '</span>') . '</td></tr><tr><td>Load now</td><td class="num">' . $h($rs['load']['now']) . ' on ' . (int)$rs['load']['cores'] . ' cores</td></tr><tr><td>Disk (worst mount)</td><td class="num">' . (!empty($rs['disk']['checked']) ? (int)$rs['disk']['worst'] . '%' : 'not checked') . '</td></tr><tr><td>Packages pending / security</td><td class="num">' . (int)($up['packages_pending'] ?? 0) . ' / ' . (int)($up['security_pending'] ?? 0) . '</td></tr><tr><td>Kernel</td><td class="num">' . (!empty($up['kernel']['reboot']) ? '<span class="pill warn">reboot pending</span> ' . $h($up['kernel']['running']) : '<span class="pill good">current</span>') . '</td></tr><tr><td>Domains on end-of-life PHP</td><td class="num">' . (!empty($up['php']['checked']) ? (int)$up['php']['eol_domains'] : 'not checked') . '</td></tr></tbody></table></div></div></div>';
    // 8 recommendations
    $o .= '<div class="sec"><h2>8 · Recommendations <span class="n">ordered by risk · each says why and how</span></h2><div class="body">';
    if (!$r['recommendations']) $o .= '<div class="small">Nothing to recommend today.</div>';
    foreach ($r['recommendations'] as $i => $rc) $o .= '<div class="rec"><div class="p ' . $rc['p'] . '">' . ($i + 1) . '</div><div><b>' . $h($rc['title']) . '</b><div class="why">' . $h($rc['why']) . '</div><div class="how">' . $h($rc['how']) . '</div></div></div>';
    $o .= '</div></div>';
    // 9 per-domain
    $doms = $r['domains']; $shown = $full ? $doms : array_slice($doms, 0, 15, true);
    $o .= '<div class="sec" id="domains"><h2>9 · Per-domain details <span class="n">' . count($doms) . ' domain(s) with something to report · worst first</span></h2><div class="body">';
    if (!$doms) $o .= '<div class="small">No domain had an attack, a malware find, a resource problem or a vulnerability sign on this day.</div>';
    else { $o .= '<div class="domhead"><span>Domain · account</span><span class="c">Attacks</span><span class="c">Served 2xx</span><span class="c">Malware</span><span class="c">Resources</span><span class="c">Vulnerabilities</span><span class="c">Risk</span></div>';
        $i = 0; foreach ($shown as $dom => $x) { $lv = $x['level']; $cls = $lv === 'critical' ? 'dang' : ($lv === 'high' ? 'warn' : 'brand');
            $o .= '<details class="dom"' . ($i++ === 0 ? ' open' : '') . '><summary><span class="d">' . $h($dom) . ' <span class="small">· ' . $h($x['account']) . '</span></span><span class="c">' . number_format($x['attacks']) . '</span><span class="c"' . ($x['served'] ? ' style="color:#b3261e;font-weight:800"' : '') . '>' . (int)$x['served'] . '</span><span class="c">' . count($x['malware']) . '</span><span class="c">' . ($x['resources'] ? count($x['resources']) : '-') . '</span><span class="c">' . count($x['vulns']) . '</span><span class="c"><span class="pill ' . $cls . '">' . $h($lv) . '</span></span></summary><div class="in">';
            $o .= '<div><h4>Attacks (' . number_format($x['attacks']) . ($x['served'] ? ' · ' . $x['served'] . ' served' : '') . ')</h4><ul>'; if (!$x['attacks']) $o .= '<li>none</li>'; foreach ($x['served_rows'] as $sr) $o .= '<li><b>served 2xx</b> ' . $ago($sr['ts']) . ' from ' . $h($sr['ip']) . ': <span class="mono">' . $h(substr($sr['uri'], 0, 120)) . '</span>' . ($sr['rule'] !== '' ? ' (' . $h($sr['rule']) . ')' : '') . '</li>'; if ($x['attacks']) $o .= '<li>kinds: ' . $h(implode(' · ', array_map(fn($k, $v) => "$k $v", array_keys(array_slice($x['kinds'], 0, 4, true)), array_slice($x['kinds'], 0, 4, true)))) . ' · from ' . (int)$x['uniq_ips'] . ' address(es)</li>'; $o .= '</ul></div>';
            $o .= '<div><h4>Malware · integrity (' . count($x['malware']) . ')</h4><ul>' . ($x['malware'] ? implode('', array_map(fn($m) => '<li class="mono">' . $h($m) . '</li>', $x['malware'])) : '<li>none</li>') . '</ul></div>';
            $o .= '<div><h4>Resources · memory</h4><ul>' . ($x['resources'] ? implode('', array_map(fn($m) => '<li>' . $h($m) . '</li>', $x['resources'])) : '<li>none</li>') . '</ul></div>';
            $o .= '<div><h4>Vulnerabilities (' . count($x['vulns']) . ')</h4><ul>' . ($x['vulns'] ? implode('', array_map(fn($v) => '<li><span class="pill ' . ($v['sev'] === 'high' ? 'dang' : ($v['sev'] === 'medium' ? 'warn' : 'brand')) . '">' . $h($v['sev']) . '</span> ' . $h($v['what']) . '</li>', $x['vulns'])) : '<li>none found by the checks that need no feed (CMS core version, EOL PHP, readable config, debug, exposed .git)</li>') . '</ul></div>';
            if ($x['foreign']) $o .= '<div><h4>Foreign sign-ins</h4><ul>' . implode('', array_map(fn($m) => '<li>' . $h($m) . '</li>', $x['foreign'])) . '</ul></div>';
            $o .= '</div></details>'; }
        if (!$full && count($doms) > 15) $o .= '<p class="small">' . (count($doms) - 15) . ' more domain(s) in the full report (download).</p>'; }
    $o .= '<p class="small" style="margin:10px 0 0">Columns: Attacks = requests the WAF or this product classified as attacks · Served 2xx = attack requests the site answered successfully · Malware = active files + Learned Defense findings · Resources = LVE limit hits · Vulnerabilities = outdated CMS core, end-of-life PHP, readable config, debug modes, exposed .git. Plugin-level CVE matching needs a feed and is not part of this report yet.</p></div></div>';
    $o .= '<p class="small">Every number is read for this day from the server\'s own logs and this product\'s own records; a check that could not run is shown as "not checked", never as zero.</p></div>' . ($embed ? '' : '</body></html>');
    return $o;
}
function smpro_sr_render_text(array $r): string {
    $l = []; $l[] = 'Daily Security Report - ' . $r['host'] . ' - ' . $r['day'] . ' - score ' . (int)$r['score']['score'] . ($r['score']['prev'] !== null ? ' (yesterday ' . (int)$r['score']['prev'] . ')' : '');
    $l[] = ''; $l[] = $r['summary']; $l[] = '';
    if ($r['recommendations']) { $l[] = 'Recommendations:'; foreach ($r['recommendations'] as $i => $rc) $l[] = ($i + 1) . '. [' . strtoupper($rc['p']) . '] ' . $rc['title'] . ' - ' . $rc['how']; }
    $held = count($r['alerts']['held']['rows'] ?? []); if ($held) $l[] = ''; if ($held) $l[] = $held . ' alert(s) were evaluated and not sent (reasons in the full report).';
    return implode("\n", $l);
}

/* ---------------- delivery ---------------- */
function smpro_sr_pdf(string $html, string $outPdf): bool {
    foreach (['wkhtmltopdf', 'chromium', 'chromium-browser', 'google-chrome'] as $b) {
        $bin = trim((string)@shell_exec('command -v ' . $b . ' 2>/dev/null')); if ($bin === '') continue;
        $tmp = $outPdf . '.html'; @file_put_contents($tmp, $html);
        if ($b === 'wkhtmltopdf') @shell_exec('timeout 120 ' . escapeshellarg($bin) . ' -q ' . escapeshellarg($tmp) . ' ' . escapeshellarg($outPdf) . ' 2>/dev/null');
        else @shell_exec('timeout 120 ' . escapeshellarg($bin) . ' --headless --disable-gpu --no-sandbox --print-to-pdf=' . escapeshellarg($outPdf) . ' ' . escapeshellarg('file://' . $tmp) . ' 2>/dev/null');
        @unlink($tmp); if (@is_file($outPdf) && @filesize($outPdf) > 1000) return true;
    }
    return false;
}
/** Email with the report attached (PDF when a renderer exists, else the HTML file). Sendmail MIME; SMTP falls back to the text body. */
function smpro_sr_email(array $to, string $from, string $subject, string $text, array $attach): array {
    $cfg = function_exists('smpro_ntf_load') ? smpro_ntf_load() : [];
    $to = array_values(array_filter(array_map('trim', $to), fn($a) => filter_var($a, FILTER_VALIDATE_EMAIL))); if (!$to) return [false, 'no valid recipient'];
    $from = filter_var($from, FILTER_VALIDATE_EMAIL) ? $from : ('safety-monitor@' . gethostname());
    $sendmail = is_executable('/usr/sbin/sendmail') ? '/usr/sbin/sendmail' : (is_executable('/usr/lib/sendmail') ? '/usr/lib/sendmail' : '');
    if (($cfg['email']['method'] ?? 'sendmail') === 'smtp' || $sendmail === '') { if (function_exists('smpro_ntf_send_email')) return smpro_ntf_send_email($to, $from, $subject, $text . "\n\n(The attachment needs the sendmail method; open the report in the panel.)"); return [false, 'no sendmail']; }
    $b = 'smpro-' . bin2hex(random_bytes(8));
    $msg = "From: Safety Monitor Pro <$from>\r\nTo: " . implode(', ', $to) . "\r\nSubject: " . mb_encode_mimeheader($subject, 'UTF-8') . "\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"$b\"\r\n\r\n";
    $msg .= "--$b\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n" . $text . "\r\n";
    foreach ($attach as $name => $spec) { [$mime, $data] = $spec; $msg .= "--$b\r\nContent-Type: $mime; name=\"$name\"\r\nContent-Disposition: attachment; filename=\"$name\"\r\nContent-Transfer-Encoding: base64\r\n\r\n" . chunk_split(base64_encode($data)) . "\r\n"; }
    $msg .= "--$b--\r\n";
    $h = @popen($sendmail . ' -t -i -f ' . escapeshellarg($from), 'w'); if (!$h) return [false, 'sendmail could not be started'];
    fwrite($h, $msg); $rc = pclose($h); return [$rc === 0, 'sendmail rc=' . $rc];
}
function smpro_sr_deliver(array $r, array $channels): array {
    $done = []; $html = smpro_sr_render_html($r, true); $text = smpro_sr_render_text($r);
    $subject = 'Daily Security Report - ' . $r['host'] . ' - ' . $r['day'] . ' - score ' . (int)$r['score']['score'];
    $ntf = function_exists('smpro_ntf_load') ? smpro_ntf_load() : [];
    $pdfPath = smpro_sr_dir() . '/' . $r['id'] . '.pdf'; $hasPdf = @is_file($pdfPath) || smpro_sr_pdf($html, $pdfPath);
    if (!empty($channels['email'])) { $to = (array)($ntf['email']['to'] ?? []); if ($to) { $att = $hasPdf ? ['security-report-' . $r['day'] . '.pdf' => ['application/pdf', (string)@file_get_contents($pdfPath)]] : ['security-report-' . $r['day'] . '.html' => ['text/html; charset=UTF-8', $html]]; [$ok, $d] = smpro_sr_email($to, (string)($ntf['email']['from'] ?? ''), $subject, $text, $att); $done['email'] = ['ok' => $ok, 'detail' => $d]; } else $done['email'] = ['ok' => false, 'detail' => 'no recipient set in Notifications']; }
    if (!empty($channels['telegram']) && function_exists('smpro_ntf_send_telegram')) { $tk = (string)($ntf['telegram']['token'] ?? ''); $cid = (string)($ntf['telegram']['chat_id'] ?? ''); if ($tk !== '' && $cid !== '') { [$ok] = smpro_ntf_send_telegram($tk, $cid, '<b>' . htmlspecialchars($subject) . "</b>\n<pre>" . htmlspecialchars(mb_substr($text, 0, 3500)) . '</pre>'); $done['telegram'] = ['ok' => $ok, 'detail' => $ok ? 'sent' : 'failed']; } else $done['telegram'] = ['ok' => false, 'detail' => 'not configured']; }
    if (!empty($channels['whatsapp']) && function_exists('smpro_ntf_send_whatsapp')) { if (!empty($ntf['whatsapp']['base_url']) && !empty($ntf['whatsapp']['chat_id'])) { [$ok] = smpro_ntf_send_whatsapp($ntf, '*' . $subject . "*\n" . mb_substr($text, 0, 3000) . "\n\nFull report: Reports Center > Daily security report > " . $r['day']); $done['whatsapp'] = ['ok' => $ok, 'detail' => $ok ? 'sent' : 'failed']; } else $done['whatsapp'] = ['ok' => false, 'detail' => 'not configured']; }
    if (function_exists('smpro_ntf_log')) smpro_ntf_log('daily_security_report', $subject, array_keys($done), $done);
    return $done;
}
function smpro_sr_run(bool $force = false, int $dayStart = 0): array {
    $cfg = smpro_sr_cfg();
    $now = smpro_sr_now(); $today = $now->format('Ymd'); $mins = (int)$now->format('G') * 60 + (int)$now->format('i');
    if (!$force && (!$cfg['enabled'] || $mins < $cfg['hour'] * 60 + $cfg['minute'] || $cfg['last_day'] === $today)) return ['ok' => false, 'skipped' => 'not due'];
    @set_time_limit(600);
    $r = smpro_sr_build($dayStart); smpro_sr_save($r);
    $d = $force ? [] : smpro_sr_deliver($r, $cfg['channels']);
    if (!$force) { $cfg['last_run'] = time(); $cfg['last_day'] = $today; $cfg['last_id'] = $r['id']; smpro_sr_cfg_save($cfg); }
    if (function_exists('smpro_audit')) smpro_audit('daily_security_report', ['id' => $r['id'], 'score' => (int)$r['score']['score'], 'delivered' => array_keys(array_filter($d, fn($x) => !empty($x['ok'])))]);
    return ['ok' => true, 'id' => $r['id'], 'score' => (int)$r['score']['score'], 'delivered' => $d];
}
function smpro_sr_cron_sync(): bool {
    if (defined('SMPRO_TEST_SRC')) return true;
    $f = '/etc/cron.d/smpro-secreport'; $cfg = smpro_sr_cfg();
    if (empty($cfg['enabled'])) { if (@is_file($f)) @unlink($f); return true; }
    $bin = SMPRO_BASE . '/bin/secreport_tick.php'; if (!@is_file($bin)) return false;
    $php = function_exists('smpro_php_cli_bin') ? smpro_php_cli_bin() : (is_executable('/usr/local/cpanel/3rdparty/bin/php') ? '/usr/local/cpanel/3rdparty/bin/php' : 'php');
    $lockDir = defined('SMPRO_LOCKS') ? SMPRO_LOCKS : (SMPRO_VARLIB . '/locks'); @is_dir($lockDir) || @mkdir($lockDir, 0700, true);
    $flock = is_executable('/usr/bin/flock') ? '/usr/bin/flock' : 'flock';
    // every ten minutes: the tick itself decides when the chosen time in the chosen zone has passed, so the hour holds across daylight-saving changes
    $desired = "# Safety Monitor Pro - Daily Security Report: built for the previous day and delivered once a day, at the chosen time in the chosen time zone\n"
             . '*/10 * * * * root ' . $flock . ' -n ' . $lockDir . '/secreport.lock timeout 900 nice -n 10 ' . $php . ' ' . $bin . ' >/dev/null 2>&1' . "\n";
    return function_exists('smpro_cron_install') ? smpro_cron_install($f, $desired) : (@file_put_contents($f, $desired) !== false && @chmod($f, 0644));
}
