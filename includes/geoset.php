<?php
/**
 * includes/geoset.php — the firewall side of the Country Login Lock, as ONE kernel set instead of csf.deny lines.
 *
 * WHY. The lock closes the login ports (never 80/443) for an address, which csf.deny can only express as one line
 * per port: 15 ports × 296 addresses was 4,434 lines on a production server - csf.deny at its 5,000 limit, every
 * new block from any other feature evicting an old one, and 4,434 separate iptables rules. The limit had already
 * been raised once (200 → 5,000) for the same symptom; raising it again only moves the day.
 *
 * NOW. One ipset per address family holds the addresses, with the kernel's own expiry on each entry, and one
 * iptables rule per 15 login ports matches that set. The rule sits in CSF's LOCALINPUT chain right AFTER the
 * ALLOWIN jump, so csf.allow still wins, and before DENYIN. Nothing is written to csf.deny. The set survives
 * `csf -r` and reboots because the lock's own worker puts it back every minute from its state file, and
 * csfpost.sh asks for the same restore right after CSF reloads.
 *
 * A server without ipset/iptables keeps the old csf.deny path (includes/geologin.php); this file reports
 * "not available" and nothing here runs.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

if (!defined('SMPRO_GS_STATE')) define('SMPRO_GS_STATE', SMPRO_VARLIB . '/geolock_set.json');
if (!defined('SMPRO_GS_SET'))   define('SMPRO_GS_SET',   'smpro_geo');
if (!defined('SMPRO_GS_TAG'))   define('SMPRO_GS_TAG',   'smpro-geologin');
if (!defined('SMPRO_GS_TMAX'))  define('SMPRO_GS_TMAX',  2147483);   // ipset's largest timeout (~24.8 days); longer lives are renewed by restore()

function smpro_gs_x(string $cmd, int $t = 15): array { $o = []; $rc = 1; @exec('timeout ' . $t . ' ' . $cmd . ' 2>&1', $o, $rc); return [$rc, trim(implode("\n", $o))]; }
function smpro_gs_ipset(): string { static $b = null; if ($b !== null) return $b; $b = ''; foreach (['/usr/sbin/ipset', '/sbin/ipset', '/usr/bin/ipset'] as $c) if (@is_executable($c)) { $b = $c; break; } if ($b === '') { $c = trim((string)@shell_exec('command -v ipset 2>/dev/null')); if ($c !== '') $b = $c; } return $b; }
/** The iptables binary CSF actually drives (the one whose rules hold LOCALINPUT), else the first present. */
function smpro_gs_ipt(bool $v6): string {
    static $m = [];
    $k = $v6 ? '6' : '4'; if (isset($m[$k])) return $m[$k];
    $bins = function_exists('smpro_fw_ipt_bins') ? smpro_fw_ipt_bins($v6) : ($v6 ? ['/usr/sbin/ip6tables'] : ['/usr/sbin/iptables']);
    $first = ''; $m[$k] = '';
    foreach ($bins as $b) { if (!@is_executable($b)) continue; if ($first === '') $first = $b; [$rc] = smpro_gs_x(escapeshellarg($b) . ' -S LOCALINPUT', 10); if ($rc === 0) { $m[$k] = $b; break; } }
    if ($m[$k] === '') $m[$k] = $first;
    return $m[$k];
}
/** Can this server keep the lock in a kernel set at all? Probed once per process. */
function smpro_gs_available(): bool {
    static $ok = null; if ($ok !== null) return $ok;
    if (defined('SMPRO_TEST_SRC') && !defined('SMPRO_GS_TEST_LIVE')) return ($ok = false);   // a test that loads only this file must not touch the kernel
    $ok = smpro_gs_ipset() !== '' && smpro_gs_ipt(false) !== '';
    if ($ok) { [$rc, $o] = smpro_gs_x(escapeshellarg(smpro_gs_ipset()) . ' list -n', 10); $ok = ($rc === 0); }
    return $ok;
}
function smpro_gs_setname(bool $v6): string { return SMPRO_GS_SET . ($v6 ? '6' : ''); }
function smpro_gs_is6(string $ip): bool { return strpos($ip, ':') !== false; }

/* ---------------- state: why each address is in the set (the kernel keeps only the address and its time left) ---------------- */
function smpro_gs_state(): array { $d = @is_file(SMPRO_GS_STATE) ? json_decode((string)@file_get_contents(SMPRO_GS_STATE), true) : null; return is_array($d) ? $d : []; }
function smpro_gs_state_save(array $s): void {
    @is_dir(dirname(SMPRO_GS_STATE)) || @mkdir(dirname(SMPRO_GS_STATE), 0700, true);
    $t = SMPRO_GS_STATE . '.' . getmypid() . '.tmp';
    if (@file_put_contents($t, json_encode($s, JSON_UNESCAPED_SLASHES), LOCK_EX) !== false) { @chmod($t, 0600); @rename($t, SMPRO_GS_STATE); }
}

/* ---------------- the set and the rule ---------------- */
/** Login ports in groups iptables' multiport accepts (15 per rule); 80 and 443 can never be in a group. */
function smpro_gs_port_groups(array $ports): array {
    $p = []; foreach ($ports as $x) { $x = (int)$x; if ($x > 0 && $x < 65536 && $x !== 80 && $x !== 443) $p[$x] = 1; }
    $p = array_keys($p); sort($p);
    return array_chunk($p, 15);
}
/** The rules this feature owns in one family, as "-A CHAIN ..." lines. */
function smpro_gs_rules_present(bool $v6): array {
    $b = smpro_gs_ipt($v6); if ($b === '') return [];
    $out = [];
    foreach (['LOCALINPUT', 'INPUT'] as $ch) { [$rc, $o] = smpro_gs_x(escapeshellarg($b) . ' -S ' . $ch, 10); if ($rc !== 0) continue; foreach (explode("\n", $o) as $l) if (strpos($l, '--comment ' . SMPRO_GS_TAG) !== false || strpos($l, '--comment "' . SMPRO_GS_TAG) !== false) $out[] = $l; }
    return $out;
}
/** Make sure the set exists and the rules match the wanted ports, in the right place. Returns what it did. */
function smpro_gs_ensure(array $ports, bool $v6 = false): array {
    if (!smpro_gs_available()) return ['ok' => false, 'msg' => 'ipset/iptables not available'];
    $set = smpro_gs_setname($v6); $ips = smpro_gs_ipset(); $ipt = smpro_gs_ipt($v6);
    if ($ipt === '') return ['ok' => false, 'msg' => ($v6 ? 'ip6tables' : 'iptables') . ' not available'];
    $did = [];
    [$rc] = smpro_gs_x(escapeshellarg($ips) . ' list -n ' . escapeshellarg($set), 10);
    if ($rc !== 0) {
        [$rc2, $o] = smpro_gs_x(escapeshellarg($ips) . ' create ' . escapeshellarg($set) . ' hash:ip family ' . ($v6 ? 'inet6' : 'inet') . ' timeout ' . SMPRO_GS_TMAX . ' hashsize 1024 maxelem 262144', 10);
        if ($rc2 !== 0) return ['ok' => false, 'msg' => 'could not create set: ' . $o];
        $did[] = 'set created';
    }
    $groups = smpro_gs_port_groups($ports);
    $want = []; foreach ($groups as $g) $want[] = '-p tcp -m multiport --dports ' . implode(',', $g) . ' -m set --match-set ' . $set . ' src -m comment --comment ' . SMPRO_GS_TAG . ' -j DROP';
    $have = smpro_gs_rules_present($v6);
    $same = count($have) === count($want);
    if ($same) foreach ($want as $w) { $hit = false; foreach ($have as $h) if (strpos(str_replace('"', '', $h), $w) !== false) $hit = true; if (!$hit) { $same = false; break; } }
    if ($same && !$groups) return ['ok' => true, 'msg' => 'no login ports selected', 'did' => $did];
    if ($same) return ['ok' => true, 'msg' => 'in place', 'did' => $did];
    // rebuild: remove ours, then insert right after CSF's ALLOWIN jump (so csf.allow still wins), else at the top of INPUT
    foreach ($have as $h) { $d = preg_replace('/^-A /', '-D ', $h); smpro_gs_x(escapeshellarg($ipt) . ' ' . $d, 10); }
    [$rc, $o] = smpro_gs_x(escapeshellarg($ipt) . ' -S LOCALINPUT', 10);
    $chain = 'INPUT'; $pos = 1;
    if ($rc === 0) { $chain = 'LOCALINPUT'; $n = 0; foreach (explode("\n", $o) as $l) { if (strpos($l, '-A LOCALINPUT') === 0) { $n++; if (strpos($l, '-j ALLOWIN') !== false) { $pos = $n + 1; break; } } } }
    $bad = '';
    foreach (array_reverse($want) as $w) { [$rc3, $o3] = smpro_gs_x(escapeshellarg($ipt) . ' -I ' . $chain . ' ' . $pos . ' ' . $w, 10); if ($rc3 !== 0) $bad = $o3; }
    if ($bad !== '') return ['ok' => false, 'msg' => 'could not install the rule: ' . $bad, 'did' => $did];
    $did[] = count($want) . ' rule(s) in ' . $chain;
    if (function_exists('smpro_audit')) @smpro_audit('geologin_set_rules', ['family' => $v6 ? 6 : 4, 'rules' => count($want), 'chain' => $chain]);
    return ['ok' => true, 'msg' => implode(', ', $did), 'did' => $did];
}
function smpro_gs_rule_live(bool $v6 = false): bool { return smpro_gs_available() && count(smpro_gs_rules_present($v6)) > 0; }
function smpro_gs_has(string $ip): bool {
    if (!smpro_gs_available()) return false;
    [$rc] = smpro_gs_x(escapeshellarg(smpro_gs_ipset()) . ' test ' . escapeshellarg(smpro_gs_setname(smpro_gs_is6($ip))) . ' ' . escapeshellarg($ip), 5);
    return $rc === 0;
}
/** Put one address in the set for $ttl seconds (renewed if already there) and remember why. */
function smpro_gs_add(string $ip, int $ttl, string $cc, string $account, string $why, array $ports): array {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return ['ok' => false, 'msg' => 'not an address'];
    $v6 = smpro_gs_is6($ip);
    $e = smpro_gs_ensure($ports, $v6); if (empty($e['ok'])) return $e;
    $ttl = max(60, $ttl);
    [$rc, $o] = smpro_gs_x(escapeshellarg(smpro_gs_ipset()) . ' add -exist ' . escapeshellarg(smpro_gs_setname($v6)) . ' ' . escapeshellarg($ip) . ' timeout ' . min($ttl, SMPRO_GS_TMAX), 5);
    if ($rc !== 0) return ['ok' => false, 'msg' => 'could not add to the set: ' . $o];
    $s = smpro_gs_state();
    $s[$ip] = ['ip' => $ip, 'cc' => $cc, 'account' => $account, 'why' => $why, 'since' => (int)($s[$ip]['since'] ?? time()), 'until' => time() + $ttl, 'ports' => array_values($ports)];
    smpro_gs_state_save($s);
    return ['ok' => true, 'msg' => count($ports) . ' login port(s) closed for ' . $ip . ' (kernel set)'];
}
function smpro_gs_del(string $ip = ''): int {
    $s = smpro_gs_state(); $n = 0;
    foreach ($s as $k => $e) {
        if ($ip !== '' && $k !== $ip) continue;
        if (smpro_gs_available()) smpro_gs_x(escapeshellarg(smpro_gs_ipset()) . ' del -exist ' . escapeshellarg(smpro_gs_setname(smpro_gs_is6($k))) . ' ' . escapeshellarg($k), 5);
        unset($s[$k]); $n++;
    }
    smpro_gs_state_save($s);
    return $n;
}
/** Every address the lock holds, from the state file (with whether the kernel really has it). */
function smpro_gs_active(bool $checkLive = true, int $max = 500): array {
    $out = []; $n = 0; $now = time();
    foreach (smpro_gs_state() as $ip => $e) {
        if ((int)($e['until'] ?? 0) <= $now) continue;
        $r = ['ip' => $ip, 'ports' => (array)($e['ports'] ?? []), 'why' => (string)($e['why'] ?? ''), 'until' => (int)$e['until'], 'since' => (int)($e['since'] ?? 0), 'backend' => 'set'];
        $r['live'] = $checkLive ? (($n++ < $max) ? (smpro_gs_has($ip) && smpro_gs_rule_live(smpro_gs_is6($ip))) : null) : null;
        $out[] = $r;
    }
    return $out;
}
/** Drop expired state (the kernel already dropped the entry). */
function smpro_gs_expire(): int {
    $s = smpro_gs_state(); $now = time(); $n = 0;
    foreach ($s as $ip => $e) if ((int)($e['until'] ?? 0) <= $now) { unset($s[$ip]); $n++; }
    if ($n) smpro_gs_state_save($s);
    return $n;
}
/**
 * After `csf -r` or a reboot the kernel forgot everything: put the sets, the rules and every unexpired address
 * back from the state file. Cheap when all is in place (one `ipset list -n`, one chain read per family), so the
 * worker calls it every minute.
 */
function smpro_gs_restore(array $ports): array {
    if (!smpro_gs_available()) return ['ok' => false, 'msg' => 'not available', 'readded' => 0];
    $s = smpro_gs_state(); $now = time(); $re = 0; $fam = [];
    foreach ($s as $ip => $e) { if ((int)($e['until'] ?? 0) <= $now) continue; $fam[smpro_gs_is6($ip) ? 6 : 4] = true; }
    if (!$fam) $fam[4] = true;
    $msgs = [];
    foreach (array_keys($fam) as $f) { $r = smpro_gs_ensure($ports, $f === 6); $msgs[] = ($f === 6 ? 'v6: ' : 'v4: ') . (string)$r['msg']; if (empty($r['ok'])) return ['ok' => false, 'msg' => implode('; ', $msgs), 'readded' => 0]; }
    foreach ($s as $ip => $e) {
        $left = (int)($e['until'] ?? 0) - $now; if ($left <= 0) continue;
        if (smpro_gs_has($ip)) continue;
        [$rc] = smpro_gs_x(escapeshellarg(smpro_gs_ipset()) . ' add -exist ' . escapeshellarg(smpro_gs_setname(smpro_gs_is6($ip))) . ' ' . escapeshellarg($ip) . ' timeout ' . min($left, SMPRO_GS_TMAX), 5);
        if ($rc === 0) $re++;
    }
    if ($re && function_exists('smpro_audit')) @smpro_audit('geologin_set_restored', ['readded' => $re]);
    return ['ok' => true, 'msg' => implode('; ', $msgs) . ($re ? "; $re address(es) put back" : ''), 'readded' => $re];
}

/* ---------------- moving the old csf.deny lines into the set ---------------- */
/** One legacy line → [ip, date] or null. */
function smpro_gs_parse_legacy(string $line): ?array {
    if (strpos($line, SMPRO_GS_TAG) === false || !preg_match('/s=([0-9a-fA-F:.]+)/', $line, $m)) return null;
    $d = preg_match('/(\d{4}-\d{2}-\d{2})\s*$/', $line, $dm) ? $dm[1] : date('Y-m-d');
    $why = preg_match('/# ' . preg_quote(SMPRO_GS_TAG, '/') . '\s+(.*)$/', $line, $wm) ? trim($wm[1]) : '';
    return ['ip' => $m[1], 'date' => $d, 'why' => $why];
}
/** How many of the lock's old csf.deny lines are still there (one cheap read; 0 when the file is missing). */
function smpro_gs_legacy_count(string $denyFile): int {
    if (!@is_file($denyFile)) return 0;
    $n = 0; foreach ((array)@file($denyFile, FILE_IGNORE_NEW_LINES) as $l) if (strpos((string)$l, SMPRO_GS_TAG) !== false && strpos((string)$l, 's=') !== false) $n++;
    return $n;
}
/** Convert every legacy line in csf.deny to a set entry with its remaining life, remove the lines, reload CSF once. */
function smpro_gs_migrate(string $denyFile, int $ttlDays, array $ports): array {
    if (!smpro_gs_available() || !@is_file($denyFile) || !@is_writable($denyFile)) return ['ok' => false, 'moved' => 0, 'dropped' => 0, 'msg' => 'nothing to do'];
    $dl = function_exists('smpro_csf_deny_lock') ? smpro_csf_deny_lock() : null;   // held across read -> rewrite
    $lines = (array)@file($denyFile, FILE_IGNORE_NEW_LINES);
    $keep = []; $ips = []; $removed = 0;
    foreach ($lines as $l) { $p = smpro_gs_parse_legacy((string)$l); if ($p === null) { $keep[] = $l; continue; } $removed++; if (!isset($ips[$p['ip']]) || $ips[$p['ip']]['date'] < $p['date']) $ips[$p['ip']] = $p; }
    if (!$removed) { if (function_exists('smpro_csf_deny_unlock')) smpro_csf_deny_unlock($dl); return ['ok' => true, 'moved' => 0, 'dropped' => 0, 'msg' => 'no legacy lines']; }
    $moved = 0; $dropped = 0; $now = time();
    foreach ($ips as $ip => $p) {
        $left = max(1, $ttlDays) * 86400 - ($now - (int)strtotime($p['date'] . ' 12:00:00'));
        if ($left <= 0) { $dropped++; continue; }
        $r = smpro_gs_add($ip, $left, '', '', $p['why'], $ports); if (!empty($r['ok'])) $moved++; else $keep[] = 'tcp|in|d=' . (int)($ports[0] ?? 2083) . '|s=' . $ip . ' # ' . SMPRO_GS_TAG . ' ' . $p['why'];
    }
    @file_put_contents($denyFile . '.smpro.tmp', implode("\n", $keep) . "\n", LOCK_EX); @chmod($denyFile . '.smpro.tmp', 0600);
    if (!@rename($denyFile . '.smpro.tmp', $denyFile)) @file_put_contents($denyFile, implode("\n", $keep) . "\n", LOCK_EX);
    if (function_exists('smpro_csf_deny_unlock')) smpro_csf_deny_unlock($dl);
    $csf = function_exists('smpro_csf_bin') ? smpro_csf_bin() : '';
    if ($csf !== '') @shell_exec('timeout 120 ' . escapeshellarg($csf) . ' -r >/dev/null 2>&1');
    smpro_gs_restore($ports);   // csf -r just flushed the chains: put our rule back at once
    if (function_exists('smpro_audit')) @smpro_audit('geologin_set_migrated', ['lines' => $removed, 'addresses' => $moved, 'expired' => $dropped]);
    return ['ok' => true, 'moved' => $moved, 'dropped' => $dropped, 'lines' => $removed, 'msg' => "$removed csf.deny line(s) became $moved set entr" . ($moved === 1 ? 'y' : 'ies') . ($dropped ? ", $dropped already past their life" : '')];
}

/* ---------------- CSF hook: restore right after CSF reloads (the worker covers the gap otherwise) ---------------- */
function smpro_gs_hook_install(): bool {
    if (defined('SMPRO_TEST_SRC')) return true;
    if (!is_dir('/etc/csf')) return false;
    // The file CSF actually runs, in CSF's own order of preference: /usr/local/csf/bin/csfpost.sh wins over
    // /etc/csf/csfpost.sh when both exist. A production server had both, our line sat in the one CSF never ran, and
    // every reload emptied the set until the worker's next minute.
    $f = is_file('/usr/local/csf/bin/csfpost.sh') ? '/usr/local/csf/bin/csfpost.sh' : '/etc/csf/csfpost.sh';
    $php = function_exists('smpro_php_cli_bin') ? smpro_php_cli_bin() : '/usr/local/cpanel/3rdparty/bin/php';
    $block = "\n# " . SMPRO_GS_TAG . " set restore (Safety Monitor Pro): put the Country Login Lock back after CSF reloaded its rules\n"
           . "timeout 60 $php " . SMPRO_BASE . "/bin/geologin_tick.php --restore >/dev/null 2>&1 || true\n";
    $cur = @is_file($f) ? (string)@file_get_contents($f) : "#!/usr/bin/env bash\n";
    // Right after the shebang, not at the end: another product's csfpost.sh on a server with nftables ended with
    // `exit 0` before our appended lines ever ran, and the lock stayed down until the worker's next minute.
    $lines = explode("\n", $cur); $out = []; $i = 0; $had = false;
    while ($i < count($lines)) { if (strpos($lines[$i], '# ' . SMPRO_GS_TAG . ' set restore') === 0) { $had = true; $i += 2; continue; } $out[] = $lines[$i]; $i++; }
    $atTop = $had && isset($lines[1]) && strpos($lines[1], '# ' . SMPRO_GS_TAG . ' set restore') === 0;
    if ($atTop) return true;
    $first = ($out && strpos($out[0], '#!') === 0) ? array_shift($out) : '#!/usr/bin/env bash';
    $new = $first . "\n" . trim($block) . "\n" . ltrim(implode("\n", $out), "\n");
    if (@file_put_contents($f, rtrim($new, "\n") . "\n", LOCK_EX) === false) return false;   // the other product's lines stay as they are, below ours
    @chmod($f, 0700);
    return true;
}
