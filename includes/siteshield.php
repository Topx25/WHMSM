<?php
/**
 * includes/siteshield.php — Site Shield: one domain, closed to hosting / cloud / VPN networks, scanner tools and
 * secret-file probes, open to everybody else.
 *
 * WHY. A server carried a hundred old store copies under one development hostname. Not one customer visited them;
 * what did, every day, was cloud-hosted scanners probing /.env, /.git, each store's admin - and in 2022 one of them
 * found a way in. The owner wanted the paths to keep working (they are shown to clients) and the scanners gone.
 * An address list in .htaccess would have shut the clients out too; a country lock would not have stopped a cloud
 * box in the right country. What tells a scanner from a client is the network it comes from: people browse from
 * homes and phones, scanners run on rented machines. The plugin already keeps those prefix lists for the Country
 * Login Lock (includes/netkind.php); this puts the same knowledge in front of one web site.
 *
 * HOW. A cPanel "userdata" include for the domain's vhosts (std + ssl) - the supported place for per-vhost
 * configuration, kept across every rebuild - with three refusals, 403 each:
 *   1. the request comes from a hosting / cloud or VPN prefix (Require not ip, from the plugin's lists);
 *   2. the User-Agent is a known attack / scanner tool (the Bot Guard pattern, the same source);
 *   3. the path is a secret-file or admin-tool probe (the Bot Guard pattern).
 * The operator's own addresses (the plugin's self-allow and the firewall allow-list) pass regardless.
 * Apache sees the real client address behind cPanel's nginx through mod_remoteip, so the network test is honest.
 *
 * Every change is: write, rebuild httpd.conf, configtest, graceful reload - and on any refusal the files are
 * removed and the configuration rebuilt again, so a shield that could not be installed is not half-installed.
 * The status shown is read from the generated httpd.conf, never from what this file remembers writing.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit; }
if (!function_exists('smpro_bg_scanner_ua')) { $bgf = __DIR__ . '/botguard.php'; if (is_file($bgf)) require_once $bgf; }
if (!function_exists('smpro_nk_file'))       { $nkf = __DIR__ . '/netkind.php';  if (is_file($nkf)) require_once $nkf; }

define('SMPRO_SS_CFG',  SMPRO_VARLIB . '/siteshield.json');
define('SMPRO_SS_UD',   '/etc/apache2/conf.d/userdata');
define('SMPRO_SS_FILE', 'smpro-siteshield.conf');
define('SMPRO_SS_HTTPD', '/etc/apache2/conf/httpd.conf');

function smpro_ss_cfg(): array { $d = @is_file(SMPRO_SS_CFG) ? json_decode((string)@file_get_contents(SMPRO_SS_CFG), true) : null; return is_array($d) ? $d : ['domains' => []]; }
function smpro_ss_cfg_save(array $c): void { smpro_json_save(SMPRO_SS_CFG, $c); }

/** Every domain that has a vhost of its own, from cPanel's record: domain => [user, type, docroot]. Parked names alias
 *  another vhost and have no include of their own, so they are left out. */
function smpro_ss_domains(): array {
    $out = [];
    foreach (@file('/etc/userdatadomains', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $l) {
        if (!preg_match('/^([a-z0-9.-]+):\s*([a-z0-9_.-]+)==[^=]*==(main|addon|sub)==[^=]*==(\/[^=]*)==/i', $l, $m)) continue;
        if ($m[1][0] === '*' || strpos($m[1], '_wildcard_') !== false) continue;
        $out[strtolower($m[1])] = ['user' => $m[2], 'type' => $m[3], 'docroot' => $m[4]];
    }
    ksort($out);
    return $out;
}
function smpro_ss_domain_ok(string $d): bool { return (bool)preg_match('/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i', $d); }

/** The operator's own addresses: the plugin's self-allow record and the firewall allow-list. IPv4 only (the lists
 *  are IPv4; an IPv6 visitor is never in them and so never refused by the network test). */
function smpro_ss_operator_ips(): array {
    $ips = [];
    if (function_exists('smpro_fw_self_state')) foreach (array_keys(smpro_fw_self_state()) as $ip) $ips[(string)$ip] = true;
    if (function_exists('smpro_fw_live_list')) foreach ((array)smpro_fw_live_list() as $ip) $ips[(string)$ip] = true;
    return array_values(array_filter(array_keys($ips), fn($ip) => filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false));
}
/** The prefix lists as Apache will read them: one valid IPv4 CIDR per entry, nothing else. */
function smpro_ss_prefixes(): array {
    $out = [];
    foreach (['vpn', 'hosting'] as $k) {
        $f = function_exists('smpro_nk_file') ? smpro_nk_file($k) : '';
        if ($f === '' || !is_file($f)) continue;
        foreach (@file($f, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $l) {
            $l = trim($l);
            if (preg_match('/^((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})\/([0-9]|[12][0-9]|3[0-2])$/', $l)) $out[] = $l;
        }
    }
    return array_values(array_unique($out));
}
/** A PCRE pattern as an Apache argument: double-quoted, with the quote itself escaped. */
function smpro_ss_q(string $re): string { return '"' . str_replace('"', '\\"', $re) . '"'; }

/** The include for one domain. Pure: nothing read but the lists and the operator addresses; nothing written. */
function smpro_ss_render(string $domain, ?array $prefixes = null, ?array $operator = null): string {
    $prefixes = $prefixes ?? smpro_ss_prefixes(); $operator = $operator ?? smpro_ss_operator_ips();
    $ua = function_exists('smpro_bg_scanner_ua_re') ? smpro_bg_scanner_ua_re() : '';
    $probe = function_exists('smpro_bg_probe_re') ? smpro_bg_probe_re() : '';
    $o = "# Safety Monitor Pro - Site Shield for " . $domain . "\n"
       . "# Generated " . date('c') . "; edits are overwritten. Turn the shield off on the Bot Guard page to remove this file.\n"
       . "# Refuses: hosting / cloud / VPN networks (" . count($prefixes) . " prefixes), known scanner tools, secret-file probes.\n";
    if ($ua !== '') $o .= "<IfModule mod_setenvif.c>\n    SetEnvIfNoCase User-Agent " . smpro_ss_q($ua) . " smpro_ss_tool\n</IfModule>\n";
    if ($probe !== '') $o .= "<IfModule mod_rewrite.c>\n    RewriteEngine On\n    RewriteCond %{REQUEST_URI} " . smpro_ss_q($probe) . " [NC]\n    RewriteRule .* - [F,L]\n</IfModule>\n";
    $o .= "<Location \"/\">\n    <RequireAny>\n";
    foreach ($operator as $ip) $o .= "        Require ip " . $ip . "\n";
    $o .= "        <RequireAll>\n            Require all granted\n";
    if ($ua !== '') $o .= "            Require not env smpro_ss_tool\n";
    foreach ($prefixes as $p) $o .= "            Require not ip " . $p . "\n";
    $o .= "        </RequireAll>\n    </RequireAny>\n</Location>\n";
    return $o;
}
function smpro_ss_paths(string $domain, string $user): array {
    return [SMPRO_SS_UD . '/std/2_4/' . $user . '/' . $domain . '/' . SMPRO_SS_FILE, SMPRO_SS_UD . '/ssl/2_4/' . $user . '/' . $domain . '/' . SMPRO_SS_FILE];
}
/** Written AND live: the generated httpd.conf carries the (uncommented) Include for this domain's userdata folder. */
function smpro_ss_live(string $domain, string $user): bool {
    $conf = (string)@file_get_contents(SMPRO_SS_HTTPD);
    $std = SMPRO_SS_UD . '/std/2_4/' . $user . '/' . $domain . '/*.conf';
    return (bool)preg_match('#^\s*Include\s+"?' . preg_quote($std, '#') . '"?#m', $conf) && is_file(smpro_ss_paths($domain, $user)[0]);
}
function smpro_ss_run(string $cmd, int $t = 180): array { $out = (string)@shell_exec('timeout ' . $t . ' ' . $cmd . ' 2>&1; echo "__rc=$?"'); preg_match('/__rc=(\d+)\s*$/', $out, $m); return [(int)($m[1] ?? 1), trim((string)preg_replace('/__rc=\d+\s*$/', '', $out))]; }
/** Rebuild + test + reload. [ok, msg]. On a failed test the caller has already put the files back the way they were. */
function smpro_ss_reload(bool $rebuild): array {
    if ($rebuild) { [$rc, $o] = smpro_ss_run('/scripts/rebuildhttpdconf'); if ($rc !== 0) return [false, 'rebuildhttpdconf refused: ' . substr($o, -300)]; }
    [$rc, $o] = smpro_ss_run('/usr/sbin/apachectl configtest', 60);
    if ($rc !== 0 || stripos($o, 'Syntax OK') === false) return [false, 'Apache configtest refused: ' . substr($o, -300)];
    [$rc, $o] = smpro_ss_run('/usr/sbin/apachectl graceful', 60);
    return [$rc === 0, $rc === 0 ? 'ok' : 'graceful reload failed: ' . substr($o, -300)];
}
/** Turn the shield on for one domain. [ok, msg]. */
function smpro_ss_enable(string $domain): array {
    $domain = strtolower(trim($domain));
    if (!smpro_ss_domain_ok($domain)) return [false, 'Not a valid domain name.'];
    $all = smpro_ss_domains(); if (!isset($all[$domain])) return [false, 'This domain has no vhost of its own on this server (a parked name follows the domain it is parked on).'];
    if (function_exists('smpro_ctl_dry_run') && smpro_ctl_dry_run()) return [false, 'Dry-Run is on: the shield was not installed (it would refuse ' . count(smpro_ss_prefixes()) . ' network prefixes, scanner tools and secret-file probes for ' . $domain . ').'];
    if (!function_exists('smpro_nk_ready') || !smpro_nk_ready()) return [false, 'The hosting / VPN network lists are not on this server yet (the Country Login Lock worker fetches them); without them the shield would refuse nothing, so it is not installed.'];
    if (!is_dir(SMPRO_SS_UD)) return [false, 'This does not look like a cPanel/EA4 server (' . SMPRO_SS_UD . ' is missing).'];
    $user = $all[$domain]['user']; $content = smpro_ss_render($domain);
    $paths = smpro_ss_paths($domain, $user); $existed = [];
    foreach ($paths as $p) { $existed[$p] = is_file($p); @mkdir(dirname($p), 0755, true); if (@file_put_contents($p, $content) === false) { foreach ($paths as $q) if (empty($existed[$q])) @unlink($q); return [false, 'Cannot write ' . $p]; } @chmod($p, 0644); }
    [$ok, $msg] = smpro_ss_reload(true);
    if (!$ok) { foreach ($paths as $p) @unlink($p); smpro_ss_reload(true); return [false, 'Not installed, everything put back: ' . $msg]; }
    $c = smpro_ss_cfg(); $c['domains'][$domain] = ['user' => $user, 'since' => time(), 'prefixes' => count(smpro_ss_prefixes()), 'hash' => sha1($content)]; smpro_ss_cfg_save($c);
    if (function_exists('smpro_audit')) smpro_audit('siteshield_on', ['domain' => $domain, 'prefixes' => $c['domains'][$domain]['prefixes']]);
    return [true, 'Shield is live for ' . $domain . ': ' . $c['domains'][$domain]['prefixes'] . ' hosting / VPN prefixes, scanner tools and secret-file probes are refused; everybody else passes.'];
}
function smpro_ss_disable(string $domain): array {
    $domain = strtolower(trim($domain)); $c = smpro_ss_cfg();
    $user = (string)($c['domains'][$domain]['user'] ?? (smpro_ss_domains()[$domain]['user'] ?? ''));
    if ($user === '' || !smpro_ss_domain_ok($domain)) return [false, 'Unknown domain.'];
    foreach (smpro_ss_paths($domain, $user) as $p) @unlink($p);
    unset($c['domains'][$domain]); smpro_ss_cfg_save($c);
    [$ok, $msg] = smpro_ss_reload(true);
    if (function_exists('smpro_audit')) smpro_audit('siteshield_off', ['domain' => $domain, 'ok' => $ok ? 1 : 0]);
    return [$ok, $ok ? 'Shield removed from ' . $domain . '.' : 'Files removed, but the reload said: ' . $msg];
}
/** Status of every shielded domain, read from the generated configuration. */
function smpro_ss_status(): array {
    $out = [];
    foreach (smpro_ss_cfg()['domains'] as $d => $r) $out[$d] = ['user' => (string)$r['user'], 'since' => (int)$r['since'], 'prefixes' => (int)$r['prefixes'], 'live' => smpro_ss_live($d, (string)$r['user'])];
    return $out;
}
/** Called by the worker after the network lists refresh: when the rendered include would differ (new prefixes, a new
 *  operator address), the files are rewritten and Apache reloaded gracefully - at most one reload for all domains. */
function smpro_ss_refresh(): array {
    $c = smpro_ss_cfg(); if (empty($c['domains'])) return ['changed' => 0];
    if (function_exists('smpro_ctl_dry_run') && smpro_ctl_dry_run()) return ['changed' => 0, 'why' => 'dry-run'];
    $prefixes = smpro_ss_prefixes(); if (count($prefixes) < 500) return ['changed' => 0, 'why' => 'lists not usable'];
    $operator = smpro_ss_operator_ips(); $changed = 0;
    foreach ($c['domains'] as $d => &$r) {
        $content = smpro_ss_render($d, $prefixes, $operator); $h = sha1($content);
        if ($h === (string)($r['hash'] ?? '') && smpro_ss_live($d, (string)$r['user'])) continue;
        foreach (smpro_ss_paths($d, (string)$r['user']) as $p) { @mkdir(dirname($p), 0755, true); @file_put_contents($p, $content); @chmod($p, 0644); }
        $r['hash'] = $h; $r['prefixes'] = count($prefixes); $changed++;
    } unset($r);
    if ($changed === 0) return ['changed' => 0];
    smpro_ss_cfg_save($c);
    [$ok, $msg] = smpro_ss_reload(false);
    if (!$ok && function_exists('smpro_audit')) smpro_audit('siteshield_refresh_failed', ['msg' => $msg]);
    return ['changed' => $changed, 'ok' => $ok, 'msg' => $msg];
}
