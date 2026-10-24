<?php
/**
 * includes/netkind.php - what kind of network an address belongs to: a VPN exit, a hosting / cloud range, or
 * neither (an ordinary ISP or mobile network, where real people sign in from).
 *
 * WHY. A correct password used from a VPN or a rented server is the signature of a stolen one: a customer signs in
 * from home or a phone, an attacker from a tunnel or a box they rent. Country alone cannot see it - a VPN exit in
 * an allowed country looks like a customer. On a production server the mass sign-in into fifty accounts came
 * through a VPN provider's ranges, three addresses per account so that no single one was ever blocked.
 *
 * HOW. Two published prefix lists (VPN exits, hosting/datacenter ranges), fetched like the GeoIP databases are -
 * from more than one source, validated line by line, kept only when they parse, refreshed daily. They live in
 * two kernel sets for an O(1) membership test and in plain files for a pure-PHP fallback. Nothing in this file
 * names a provider: the lists do, and they are data that updates.
 *
 * The verdict is advisory to the features that use it; this file blocks nothing by itself.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

function smpro_nk_dir(): string { $d = SMPRO_VARLIB . '/netkind'; if (!is_dir($d)) @mkdir($d, 0700, true); return $d; }
function smpro_nk_kinds(): array { return ['vpn' => 'a VPN exit', 'hosting' => 'a hosting / cloud network']; }
/** Published sources per kind, tried in order (a mirror of the same list second). */
function smpro_nk_sources(string $kind): array {
    $path = $kind === 'vpn' ? 'vpn' : 'datacenter';
    return [
        'https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/' . $path . '/ipv4.txt',
        'https://cdn.jsdelivr.net/gh/X4BNet/lists_vpn@main/output/' . $path . '/ipv4.txt',
    ];
}
function smpro_nk_file(string $kind): string { return smpro_nk_dir() . '/' . $kind . '.txt'; }
function smpro_nk_meta(): array { $m = json_decode((string)@file_get_contents(smpro_nk_dir() . '/meta.json'), true); return is_array($m) ? $m : []; }
function smpro_nk_meta_save(array $m): void { @file_put_contents(smpro_nk_dir() . '/meta.json', json_encode($m), LOCK_EX); @chmod(smpro_nk_dir() . '/meta.json', 0600); }
function smpro_nk_set(string $kind): string { return 'smpro_nk_' . ($kind === 'vpn' ? 'vpn' : 'dc'); }
function smpro_nk_ipset(): string { static $b = null; if ($b !== null) return $b; $b = ''; foreach (['/usr/sbin/ipset', '/sbin/ipset', '/usr/bin/ipset'] as $c) if (@is_executable($c)) { $b = $c; break; } return $b; }

/** Every line must be an IPv4 prefix; a list that does not parse, or is implausibly short, is refused whole. */
function smpro_nk_validate(string $body): ?array {
    $out = []; $n = 0;
    foreach (preg_split('/\r?\n/', $body) as $l) {
        $l = trim($l); if ($l === '' || $l[0] === '#') continue;
        if (!preg_match('#^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:/(\d{1,2}))?$#', $l, $m)) return null;
        for ($i = 1; $i <= 4; $i++) if ((int)$m[$i] > 255) return null;
        $bits = isset($m[5]) && $m[5] !== '' ? (int)$m[5] : 32; if ($bits > 32) return null;
        $out[] = $m[1] . '.' . $m[2] . '.' . $m[3] . '.' . $m[4] . '/' . $bits; $n++;
        if ($n > 500000) return null;
    }
    return $n >= 500 ? $out : null;   // a real list has thousands of prefixes; a stub page or an error body does not
}
/** Fetch one kind from the first source that yields a valid list. Returns [ok, lines, source|error]. */
function smpro_nk_fetch(string $kind): array {
    foreach (smpro_nk_sources($kind) as $u) {
        $body = (string)@shell_exec('timeout 40 curl -sSL -m 35 -A ' . escapeshellarg('SafetyMonitorPro/netkind') . ' ' . escapeshellarg($u) . ' 2>/dev/null');
        if ($body === '') continue;
        $lines = smpro_nk_validate($body);
        if ($lines === null) continue;
        return [true, $lines, $u];
    }
    return [false, [], 'no source gave a valid list'];
}
/** Refresh both lists when missing or older than a day; keep the old file when a fetch fails. */
function smpro_nk_update(bool $force = false): array {
    $meta = smpro_nk_meta(); $res = [];
    foreach (array_keys(smpro_nk_kinds()) as $kind) {
        $f = smpro_nk_file($kind); $age = time() - (int)($meta[$kind]['at'] ?? 0);
        if (!$force && is_file($f) && $age < 86400) { $res[$kind] = 'fresh'; continue; }
        [$ok, $lines, $src] = smpro_nk_fetch($kind);
        if (!$ok) { $meta[$kind]['error'] = $src; $meta[$kind]['tried'] = time(); $res[$kind] = 'kept old list: ' . $src; continue; }
        $t = $f . '.tmp'; @file_put_contents($t, implode("\n", $lines) . "\n", LOCK_EX); @chmod($t, 0600); @rename($t, $f);
        $meta[$kind] = ['at' => time(), 'lines' => count($lines), 'source' => $src, 'error' => ''];
        $res[$kind] = count($lines) . ' prefixes';
        if (function_exists('smpro_audit')) @smpro_audit('netkind_update', ['kind' => $kind, 'lines' => count($lines), 'source' => $src]);
    }
    smpro_nk_meta_save($meta);
    smpro_nk_ensure_sets();
    return $res;
}
/** Load each list into its kernel set (atomic swap), when ipset is here. Cheap when the sets already hold the lists. */
function smpro_nk_ensure_sets(bool $force = false): bool {
    $ips = smpro_nk_ipset(); if ($ips === '' || (defined('SMPRO_TEST_SRC') && !defined('SMPRO_GS_TEST_LIVE'))) return false;
    $meta = smpro_nk_meta(); $ok = true;
    foreach (array_keys(smpro_nk_kinds()) as $kind) {
        $f = smpro_nk_file($kind); if (!is_file($f)) continue;
        $set = smpro_nk_set($kind); $want = (int)($meta[$kind]['lines'] ?? 0);
        $have = (int)trim((string)@shell_exec('timeout 10 ' . escapeshellarg($ips) . ' list ' . escapeshellarg($set) . ' 2>/dev/null | grep -c "^[0-9]"'));
        if (!$force && $have > 0 && $have === $want) continue;
        $tmp = $set . '_new'; $bf = smpro_nk_dir() . '/' . $kind . '.restore';
        $lines = ["create $tmp hash:net family inet maxelem 262144 -exist"];
        foreach ((array)@file($f, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $p) $lines[] = "add $tmp $p -exist";
        @file_put_contents($bf, implode("\n", $lines) . "\n", LOCK_EX); @chmod($bf, 0600);
        @shell_exec('timeout 10 ' . escapeshellarg($ips) . ' destroy ' . escapeshellarg($tmp) . ' 2>/dev/null');
        @shell_exec('timeout 60 ' . escapeshellarg($ips) . ' restore < ' . escapeshellarg($bf) . ' 2>/dev/null');
        $n = (int)trim((string)@shell_exec('timeout 10 ' . escapeshellarg($ips) . ' list ' . escapeshellarg($tmp) . ' 2>/dev/null | grep -c "^[0-9]"'));
        if ($n < 500) { @shell_exec('timeout 10 ' . escapeshellarg($ips) . ' destroy ' . escapeshellarg($tmp) . ' 2>/dev/null'); $ok = false; continue; }
        @shell_exec('timeout 10 ' . escapeshellarg($ips) . ' create ' . escapeshellarg($set) . ' hash:net family inet maxelem 262144 -exist 2>/dev/null');
        @shell_exec('timeout 10 ' . escapeshellarg($ips) . ' swap ' . escapeshellarg($tmp) . ' ' . escapeshellarg($set) . ' 2>/dev/null');
        @shell_exec('timeout 10 ' . escapeshellarg($ips) . ' destroy ' . escapeshellarg($tmp) . ' 2>/dev/null');
        @unlink($bf);
    }
    return $ok;
}
function smpro_nk_sets_live(): bool {
    $ips = smpro_nk_ipset(); if ($ips === '') return false;
    foreach (array_keys(smpro_nk_kinds()) as $kind) { $n = (int)trim((string)@shell_exec('timeout 10 ' . escapeshellarg($ips) . ' list ' . escapeshellarg(smpro_nk_set($kind)) . ' 2>/dev/null | grep -c "^[0-9]"')); if ($n < 500) return false; }
    return true;
}
/** Pure-PHP membership: sorted [start, end] ranges per kind, built once per process from the files. */
function smpro_nk_ranges(string $kind): array {
    static $c = [];
    if (isset($c[$kind])) return $c[$kind];
    $r = [];
    foreach ((array)@file(smpro_nk_file($kind), FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $p) {
        [$net, $bits] = explode('/', $p . '/32', 2); $n = ip2long($net); if ($n === false) continue;
        $bits = (int)$bits; $mask = $bits === 0 ? 0 : ((-1 << (32 - $bits)) & 0xFFFFFFFF);
        $s = $n & $mask; $r[] = [$s, $s | (~$mask & 0xFFFFFFFF)];
    }
    usort($r, fn($a, $b) => $a[0] <=> $b[0]);
    return ($c[$kind] = $r);
}
function smpro_nk_in(string $kind, string $ip): bool {
    $n = ip2long($ip); if ($n === false) return false;
    $r = smpro_nk_ranges($kind); $lo = 0; $hi = count($r) - 1;
    while ($lo <= $hi) { $mid = intdiv($lo + $hi, 2); if ($r[$mid][0] > $n) $hi = $mid - 1; elseif ($r[$mid][1] < $n) $lo = $mid + 1; else return true; }
    return false;
}
/** The kind of network an IPv4 address is in: 'vpn', 'hosting' or '' (unknown kind, or no list on this server yet). */
function smpro_nk_kind(string $ip): string {
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) return '';
    static $live = null; if ($live === null) $live = smpro_nk_sets_live();
    foreach (array_keys(smpro_nk_kinds()) as $kind) {
        if ($live) { $o = []; $rc = 1; @exec('timeout 5 ' . escapeshellarg(smpro_nk_ipset()) . ' test ' . escapeshellarg(smpro_nk_set($kind)) . ' ' . escapeshellarg($ip) . ' 2>&1', $o, $rc); if ($rc === 0) return $kind; }
        elseif (is_file(smpro_nk_file($kind)) && smpro_nk_in($kind, $ip)) return $kind;
    }
    return '';
}
/** Do the lists exist here at all? Features must say "could not tell" rather than "not a VPN" when they do not. */
function smpro_nk_ready(): bool { foreach (array_keys(smpro_nk_kinds()) as $k) if (!is_file(smpro_nk_file($k))) return false; return true; }
function smpro_nk_status(): array {
    $m = smpro_nk_meta(); $out = ['ready' => smpro_nk_ready(), 'sets' => smpro_nk_sets_live(), 'kinds' => []];
    foreach (smpro_nk_kinds() as $k => $label) $out['kinds'][$k] = ['label' => $label, 'lines' => (int)($m[$k]['lines'] ?? 0), 'at' => (int)($m[$k]['at'] ?? 0), 'error' => (string)($m[$k]['error'] ?? '')];
    return $out;
}
