<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
require_once SMPRO_BASE . '/includes/fwallow.php';
// a test-only set, tag and state file, so a live run never touches a real lock on the host
define('SMPRO_GS_SET', 'smpro_geo_t134'); define('SMPRO_GS_TAG', 'smpro-geologin-t134'); define('SMPRO_GS_STATE', SMPRO_VARLIB . '/t134_state.json');
$liveOk = function_exists('posix_geteuid') && posix_geteuid() === 0 && PHP_OS_FAMILY === 'Linux' && trim((string)@shell_exec('command -v ipset 2>/dev/null')) !== '';
if ($liveOk) define('SMPRO_GS_TEST_LIVE', 1);
require_once SMPRO_BASE . '/includes/geoset.php';
require_once SMPRO_BASE . '/includes/geologin.php';
/** t134 - the Country Login Lock keeps its addresses in ONE kernel set with per-entry expiry and one rule per 15 login
 *  ports, writes nothing to csf.deny, moves old lines over, survives a CSF reload, and still reads liveness back. */
$src = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/geoset.php'));
$gl  = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/geologin.php'));

/* ---- pure: port groups, legacy parsing, never 80/443 ---- */
is_eq(smpro_gs_port_groups([2083, 22, 80, 443, 2083, 0, 70000]), [[22, 2083]], 'P1: ports are deduplicated and sorted, 80/443 and garbage can never be in a group');
$g = smpro_gs_port_groups(range(1000, 1032));
is_eq([count($g), count($g[0]), count($g[2])], [3, 15, 3], 'P2: at most 15 ports per rule (multiport\'s limit), the rest in further rules');
$p = smpro_gs_parse_legacy('tcp|in|d=2083|s=203.0.113.9 # smpro-geologin-t134 login from US not allowed for acct 2026-10-15');
is_eq([$p['ip'], $p['date']], ['203.0.113.9', '2026-10-15'], 'P3: a legacy csf.deny line gives its address and the day it was written');
is_eq(smpro_gs_parse_legacy('tcp|in|d=2083|s=203.0.113.9 # somebody else'), null, 'P3: a line that is not ours is not touched');
is_eq(smpro_gs_parse_legacy('203.0.113.9 # smpro-geologin-t134 x 2026-10-15'), null, 'P3: nor a whole-address line (the lock never wrote one)');

/* ---- wiring: the lock prefers the set, reads liveness from set + rule, and still has the csf.deny fallback ---- */
has($gl, "if (smpro_gl_use_set()) {\n        \$why = 'login from '", 'W1: block() takes the set path first');
has($gl, "if (smpro_gl_use_set()) return smpro_gs_has(\$ip, \$refresh) && smpro_gs_rule_live(smpro_gs_is6(\$ip), \$refresh);", 'W2: live = the kernel holds the address AND the rule is in place (one snapshot per request since beta363)');
has($gl, "smpro_gl_ensure_deny_limit(); @file_put_contents(SMPRO_GL_DENY", 'W3: the csf.deny fallback is still there for a server without ipset');
has($gl, "if (smpro_gl_use_set()) smpro_gl_set_up(\$c);", 'W4: arming makes the set, the hook and the migration');
has($src, "-m comment --comment ' . SMPRO_GS_TAG . ' -j DROP", 'W5: every rule carries the tag, so it can be found and removed exactly');
has($src, "if (strpos(\$l, '-j ALLOWIN') !== false) { \$pos = \$n + 1; break; }", 'W6: the rule goes right after CSF\'s ALLOWIN jump, so csf.allow still wins');
has($src, "\$dl = function_exists('smpro_csf_deny_lock') ? smpro_csf_deny_lock() : null;", 'W7: the migration rewrites csf.deny under the shared lock');
hasnt($src, "'80'", 'W8: no port number is written in the backend; the lock\'s own port list decides, and 80/443 are stripped from any group');
has($src, "if (defined('SMPRO_TEST_SRC') && !defined('SMPRO_GS_TEST_LIVE')) return (\$ok = false);", 'W9: a test never touches the kernel unless it says so');
has($src, "\$f = is_file('/usr/local/csf/bin/csfpost.sh') ? '/usr/local/csf/bin/csfpost.sh' : '/etc/csf/csfpost.sh';", 'W13: the hook goes into the csfpost.sh CSF actually runs (its own order of preference)');
has($src, "\$new = \$first . \"\\n\" . trim(\$block) . \"\\n\" . ltrim(implode(\"\\n\", \$out), \"\\n\");", 'W13: and at the top, above another product\'s early exit');
$tick = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/bin/geologin_tick.php'));
has($tick, "smpro_gs_restore(smpro_gl_ports_for(\$cfg))", 'W10: the worker puts the set and rule back every minute');
has($tick, "if (in_array('--restore', (array)(\$argv ?? []), true)) exit;", 'W10: and csfpost.sh can ask for just that');
has($tick, "if (smpro_gs_legacy_count(SMPRO_GL_DENY) > 0) smpro_gl_set_up(\$cfg);", 'W12: a lock armed before the set existed is moved over by the worker itself - nobody has to press Save');
is_eq(smpro_gs_legacy_count(SMPRO_VARLIB . '/no-such-file'), 0, 'W12: a missing csf.deny counts as nothing to move');
$page = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/firewall-status.php'));
has($page, 'nothing is written to csf.deny, so this lock cannot fill it', 'W11: the page says where the addresses are held');
has($page, "\$glDenyLines >= \$glDenyLimit && !\$glUseSet", 'W11: and the limit warning is only for the csf.deny fallback');

/* ---- live (root on Linux with ipset): set, rule, membership, restore after a flush, migration, removal ---- */
if (!$liveOk) { echo "# live part skipped (needs root on Linux with ipset)\n"; }
else {
    $ips = smpro_gs_ipset(); $ipt = smpro_gs_ipt(false);
    $cleanup = function () use ($ips, $ipt) {
        foreach (smpro_gs_rules_present(false) as $h) { $d = preg_replace('/^-A /', '-D ', $h); smpro_gs_x(escapeshellarg($ipt) . ' ' . $d, 10); }
        smpro_gs_x(escapeshellarg($ips) . ' destroy ' . escapeshellarg(SMPRO_GS_SET), 10);
        @unlink(SMPRO_GS_STATE);
    };
    $cleanup();
    $ports = [2083, 2087, 22];
    $r = smpro_gs_add('203.0.113.77', 3600, 'XX', 't134acct', 'test', $ports);
    ok(!empty($r['ok']), 'L1: an address goes into the set: ' . $r['msg']);
    ok(smpro_gs_has('203.0.113.77'), 'L1: and the kernel says it is there');
    ok(smpro_gs_rule_live(false), 'L1: and the rule is in place');
    $rules = smpro_gs_rules_present(false);
    is_eq(count($rules), 1, 'L2: three ports are one rule');
    ok(strpos($rules[0], '--dports 22,2083,2087') !== false && strpos($rules[0], 'match-set ' . SMPRO_GS_SET . ' src') !== false, 'L2: multiport + the set as source: ' . $rules[0]);
    ok(strpos($rules[0], ',80') === false && strpos($rules[0], ',443') === false, 'L2: no web port in the rule');
    [$rc, $o] = smpro_gs_x(escapeshellarg($ips) . ' list ' . escapeshellarg(SMPRO_GS_SET), 10);
    ok(preg_match('/203\.0\.113\.77 timeout (\d+)/', $o, $tm) && (int)$tm[1] > 3000 && (int)$tm[1] <= 3600, 'L3: the kernel entry carries its own expiry (' . ($tm[1] ?? '?') . ' s)');
    $before = (string)@file_get_contents('/etc/csf/csf.deny');
    // a CSF reload flushes the chains: restore() must put the rule back and re-add what the kernel forgot
    foreach ($rules as $h) smpro_gs_x(escapeshellarg($ipt) . ' ' . preg_replace('/^-A /', '-D ', $h), 10);
    smpro_gs_x(escapeshellarg($ips) . ' flush ' . escapeshellarg(SMPRO_GS_SET), 10);
    ok(!smpro_gs_rule_live(false) && !smpro_gs_has('203.0.113.77'), 'L4: after a flush the kernel has nothing');
    $rs = smpro_gs_restore($ports);
    ok(!empty($rs['ok']) && $rs['readded'] === 1 && smpro_gs_has('203.0.113.77') && smpro_gs_rule_live(false), 'L4: restore() puts the rule and the address back: ' . $rs['msg']);
    // the port list changed: the rule is rebuilt, not duplicated
    smpro_gs_ensure([2083, 2087, 22, 21], false);
    $rules = smpro_gs_rules_present(false);
    ok(count($rules) === 1 && strpos($rules[0], '--dports 21,22,2083,2087') !== false, 'L5: a new port list rebuilds the one rule');
    // migration from legacy lines in a scratch "csf.deny"
    $deny = SMPRO_VARLIB . '/t134_csf.deny';
    file_put_contents($deny, "1.2.3.4 # somebody else\ntcp|in|d=2083|s=203.0.113.88 # " . SMPRO_GS_TAG . " login from ZZ not allowed for a " . date('Y-m-d', time() - 2 * 86400) . "\ntcp|in|d=22|s=203.0.113.88 # " . SMPRO_GS_TAG . " login from ZZ not allowed for a " . date('Y-m-d', time() - 2 * 86400) . "\ntcp|in|d=22|s=203.0.113.99 # " . SMPRO_GS_TAG . " old 2020-01-01\n");
    $m = smpro_gs_migrate($deny, 30, $ports);
    is_eq([$m['moved'], $m['dropped'], $m['lines']], [1, 1, 3], 'L6: two lines of one address became one entry, a line past its life was dropped, all three left the file');
    is_eq(trim((string)file_get_contents($deny)), '1.2.3.4 # somebody else', 'L6: the line that is not ours is untouched');
    ok(smpro_gs_has('203.0.113.88') && !smpro_gs_has('203.0.113.99'), 'L6: the kernel has the live one, not the expired one');
    [$rc, $o] = smpro_gs_x(escapeshellarg($ips) . ' list ' . escapeshellarg(SMPRO_GS_SET), 10);
    // 28 days remain, which is more than ipset can hold (~24.8 days): the kernel gets the cap and the state keeps the
    // true "until", so restore() renews the entry before it lapses. A fresh block would also carry the cap - the state
    // is what tells them apart.
    ok(preg_match('/203\.0\.113\.88 timeout (\d+)/', $o, $tm) && (int)$tm[1] <= SMPRO_GS_TMAX && (int)$tm[1] > SMPRO_GS_TMAX - 120, 'L6: the kernel holds the entry for its maximum (' . ($tm[1] ?? '?') . ' s of ' . SMPRO_GS_TMAX . ')');
    $st = null; foreach (smpro_gs_active(false) as $e) if ($e['ip'] === '203.0.113.88') $st = $e;
    ok($st !== null && $st['until'] - time() > 27 * 86400 && $st['until'] - time() < 29 * 86400, 'L6: and the state keeps the real remaining life (' . ($st ? round(($st['until'] - time()) / 86400, 1) : '?') . ' days), which restore() renews from');
    is_eq((string)@file_get_contents('/etc/csf/csf.deny'), $before, 'L7: the real csf.deny was never touched');
    $n = smpro_gs_del('203.0.113.77');
    ok($n === 1 && !smpro_gs_has('203.0.113.77') && smpro_gs_has('203.0.113.88'), 'L8: removing one address leaves the other');
    is_eq(count(smpro_gs_active(true)), 1, 'L8: and the state agrees');
    $cleanup();
    ok(!smpro_gs_rule_live(false), 'L9: cleanup left no rule behind');
    @unlink($deny);
}
