<?php
/**
 * includes/frontlogs.php - what stands in front of cPanel and the sites, and where it writes, DISCOVERED on the
 * server it runs on. Nothing here names a path or a vendor layout as a fact: every location is read from the
 * running configuration of the program that writes it, so a server laid out differently is read correctly, and a
 * program that is not installed contributes nothing.
 *
 *   Imunify360 WebShield  owns cPanel's ports and hands cpsrvd every connection from 127.0.0.1; its access_log is
 *                         the only place a cPanel visitor's address survives. Read from its own config.
 *   nginx (ea-nginx)      per-domain logs written by a piped logger (`pipelog ... splitlogs --dir=<dir>`); the
 *                         service subdomains (cpanel.*, webmail.*, whm.*) are files in that dir. Read from `nginx -T`.
 *   Apache                same piped logger in CustomLog. Read from the Apache configuration `httpd -V` names.
 *
 * And the one setting that decides whether those logs hold a visitor or a Cloudflare edge: nginx restoring the
 * real client address from Cloudflare at http level. cPanel ships the ranges file and keeps it current, but only
 * includes it in the server blocks of accounts that switched Cloudflare on - every other site, and cpanel.*
 * itself, logged and firewalled Cloudflare edges. smpro_cf_realip_sync() closes that, server by server.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

function smpro_fl_bin(string $name): string {
    $p = trim((string)@shell_exec('command -v ' . escapeshellarg($name) . ' 2>/dev/null'));
    return ($p !== '' && @is_executable($p)) ? $p : '';
}
/** `nginx -T` once per process ('' when nginx is absent or the dump fails). */
function smpro_fl_nginx_dump(): string {
    static $d = null; if ($d !== null) return $d;
    $bin = smpro_fl_bin('nginx'); if ($bin === '') return $d = '';
    return $d = (string)@shell_exec('timeout 20 ' . escapeshellarg($bin) . ' -T 2>/dev/null');
}
/** Directories a cPanel piped logger writes per-domain files into, from a config text. */
function smpro_fl_splitlog_dirs(string $conf): array {
    $out = [];
    if (preg_match_all('/splitlogs\s+[^"\n]*--dir=([^\s"]+)/', $conf, $m)) foreach ($m[1] as $d) if (@is_dir($d)) $out[$d] = 1;
    return array_keys($out);
}
/** Plain access_log targets (not "off", not variables) from a config text. */
function smpro_fl_access_logs(string $conf): array {
    $out = [];
    if (preg_match_all('/^\s*access_log\s+([^\s;]+)/m', $conf, $m)) foreach ($m[1] as $p) if ($p !== 'off' && strpos($p, '$') === false && @is_file($p) && @is_readable($p)) $out[$p] = 1;
    return array_keys($out);
}
/** WebShield's config text: every *.conf under the directory its installed binary/package declares. */
function smpro_fl_webshield_conf(): string {
    $dirs = [];
    // the package lists its own config files; no package manager answer -> nothing is assumed
    foreach (['rpm -qc imunify360-webshield-bundle 2>/dev/null', 'rpm -qc imunify360-webshield 2>/dev/null', 'dpkg -L imunify360-webshield-bundle 2>/dev/null'] as $q) {
        foreach (explode("\n", (string)@shell_exec('timeout 10 ' . $q)) as $f) { $f = trim($f); if (substr($f, -5) === '.conf') $dirs[dirname($f)] = 1; }
        if ($dirs) break;
    }
    $txt = '';
    foreach (array_keys($dirs) as $d) foreach (glob($d . '/*.conf') ?: [] as $f) if (@is_readable($f)) $txt .= "\n" . (string)@file_get_contents($f);
    return $txt;
}
/** Apache's main config, as `httpd -V` reports it. */
function smpro_fl_apache_conf(): string {
    foreach (['httpd', 'apache2', 'apachectl'] as $b) {
        $bin = smpro_fl_bin($b); if ($bin === '') continue;
        $v = (string)@shell_exec('timeout 10 ' . escapeshellarg($bin) . ' -V 2>/dev/null');
        $root = preg_match('/HTTPD_ROOT="([^"]+)"/', $v, $m) ? $m[1] : '';
        $cf   = preg_match('/SERVER_CONFIG_FILE="([^"]+)"/', $v, $m) ? $m[1] : '';
        if ($cf === '') continue;
        $path = $cf[0] === '/' ? $cf : rtrim($root, '/') . '/' . $cf;
        if (@is_readable($path)) return (string)@file_get_contents($path);
    }
    return '';
}
/**
 * The logs that saw a cPanel / webmail visitor BEFORE cpsrvd did, discovered. Memoised for ten minutes.
 * ['webshield' => [...], 'service' => [...per-domain logs of cpanel./webmail./whm. vhosts...], 'main' => [...]]
 */
function smpro_front_logs(bool $fresh = false): array {
    $build = function (): array {
        $r = ['webshield' => [], 'service' => [], 'main' => []];
        $r['webshield'] = smpro_fl_access_logs(smpro_fl_webshield_conf());
        $dirs = array_merge(smpro_fl_splitlog_dirs(smpro_fl_nginx_dump()), smpro_fl_splitlog_dirs(smpro_fl_apache_conf()));
        foreach (array_unique($dirs) as $d) {
            foreach (['cpanel.*', 'webmail.*', 'whm.*', 'proxy-subdomains-vhost.*'] as $g)
                foreach (glob($d . '/' . $g) ?: [] as $f) if (substr($f, -10) !== '-bytes_log' && @is_readable($f)) $r['service'][] = $f;
        }
        if (preg_match_all('/splitlogs\s+[^"\n]*--mainout=([^\s"]+)/', smpro_fl_nginx_dump(), $m)) foreach ($m[1] as $f) if (@is_readable($f)) $r['main'][] = $f;
        foreach ($r as $k => $v) $r[$k] = array_values(array_unique($v));
        return $r;
    };
    if (!$fresh && function_exists('smpro_memo')) return (array)smpro_memo('front_logs', 600, $build);
    return $build();
}
/** Every discovered front log, flat. */
function smpro_front_logs_all(): array {
    $l = smpro_front_logs(); return array_values(array_unique(array_merge($l['webshield'] ?? [], $l['service'] ?? [], $l['main'] ?? [])));
}

/* ---------------- Cloudflare real visitor address, server-wide ---------------- */
/** Where nginx keeps its config, from the binary itself (`nginx -V` --conf-path). */
function smpro_fl_nginx_confdir(): string {
    $bin = smpro_fl_bin('nginx'); if ($bin === '') return '';
    $v = (string)@shell_exec('timeout 10 ' . escapeshellarg($bin) . ' -V 2>&1');
    $cp = preg_match('/--conf-path=(\S+)/', $v, $m) ? $m[1] : '';
    return $cp !== '' ? dirname($cp) : '';
}
/** The Cloudflare ranges file cPanel generates, found by its content in the running config, not by its name. */
function smpro_fl_cf_ranges_file(): string {
    $dump = smpro_fl_nginx_dump(); if ($dump === '') return '';
    // nginx -T prints "# configuration file <path>:" before each file's text
    if (!preg_match_all('/^# configuration file (\S+):\n((?:(?!^# configuration file ).*\n?)*)/m', $dump, $m, PREG_SET_ORDER)) return '';
    foreach ($m as $f) if (strpos($f[2], 'set_real_ip_from') !== false && preg_match('/real_ip_header\s+CF-Connecting-IP/i', $f[2])) return $f[1];
    return '';
}
/** The state: 'on' (restored at http level), 'partial' (only in some server blocks), 'none', or 'n/a' (no nginx). */
function smpro_cf_realip_state(): array {
    $dump = smpro_fl_nginx_dump(); if ($dump === '') return ['state' => 'n/a', 'why' => 'nginx is not running here'];
    $ranges = smpro_fl_cf_ranges_file();
    if ($ranges === '') return ['state' => 'none', 'why' => 'no Cloudflare ranges file in the nginx configuration'];
    $confdir = smpro_fl_nginx_confdir();
    $mine = $confdir !== '' ? $confdir . '/conf.d/smpro-cloudflare-realip.conf' : '';
    if ($mine !== '' && @is_file($mine)) return ['state' => 'on', 'why' => 'restored for every site', 'file' => $mine, 'ranges' => $ranges];
    // http-level include by anyone else = a top-level conf.d file that includes the ranges file outside a server block
    foreach (glob($confdir . '/conf.d/*.conf') ?: [] as $f) {
        $txt = (string)@file_get_contents($f);
        if (strpos($txt, basename($ranges)) !== false && !preg_match('/^\s*server\s*\{/m', $txt)) return ['state' => 'on', 'why' => 'restored for every site (' . basename($f) . ')', 'ranges' => $ranges];
    }
    return ['state' => 'partial', 'why' => 'only accounts with Cloudflare switched on get the real visitor; every other site and cpanel.* log Cloudflare edges', 'ranges' => $ranges, 'confdir' => $confdir];
}
/**
 * Make it 'on': one include at http level, tested by nginx before it is kept, reverted if the test fails. The
 * ranges file stays cPanel's (it refreshes it); this only decides where it applies. Disabled / Dry-Run: report only.
 */
function smpro_cf_realip_sync(): bool {
    if (defined('SMPRO_TEST_SRC')) return true;
    $s = smpro_cf_realip_state();
    if ($s['state'] !== 'partial') return true;
    if ((function_exists('smpro_ctl_disabled') && smpro_ctl_disabled()) || (function_exists('smpro_ctl_dry_run') && smpro_ctl_dry_run())) return true;
    if (@is_file(SMPRO_VARLIB . '/cf_realip_off')) return true;   // the operator switched it off
    $bin = smpro_fl_bin('nginx'); $confdir = (string)($s['confdir'] ?? ''); if ($bin === '' || $confdir === '') return false;
    $rel = ltrim(substr((string)$s['ranges'], strlen($confdir)), '/');
    $inc = ($rel !== '' && strpos((string)$s['ranges'], $confdir . '/') === 0) ? $rel : (string)$s['ranges'];
    $f = $confdir . '/conf.d/smpro-cloudflare-realip.conf';
    $txt = "# Safety Monitor Pro: the real visitor behind Cloudflare, for every site and the cPanel/webmail service subdomains.\n"
         . "# The ranges file is cPanel's own and is kept current by cPanel. Remove this file (and create " . SMPRO_VARLIB . "/cf_realip_off) to opt out.\n"
         . 'include ' . $inc . ";\n";
    if (@file_put_contents($f, $txt, LOCK_EX) === false) return false;
    @chmod($f, 0644);
    $test = (string)@shell_exec('timeout 30 ' . escapeshellarg($bin) . ' -t 2>&1');
    if (stripos($test, 'test is successful') === false) {
        @unlink($f);
        if (function_exists('smpro_audit')) smpro_audit('cf_realip_refused', ['test' => substr($test, 0, 300)]);
        return false;
    }
    @shell_exec('timeout 30 ' . escapeshellarg($bin) . ' -s reload 2>&1');
    if (function_exists('smpro_audit')) smpro_audit('cf_realip_enabled', ['file' => $f, 'ranges' => $s['ranges']]);
    return true;
}
