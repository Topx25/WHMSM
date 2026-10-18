<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/geologin.php';
require_once SMPRO_BASE . '/includes/geowall.php';

/**
 * t67_geowall.php — the country wall: a login door a disallowed country cannot reach at all.
 *
 * This is the only feature in the product that can make the server unreachable to its own operator — panel and
 * SSH at the same time, with no way back except the hosting provider's console. So almost everything asserted
 * here is a refusal, and the few assertions that are not are about the wall taking ITSELF down.
 */

/* ---------- U1: the web is never walled ---------- */
$cfg = smpro_gw_defaults();
$cfg['doors'] = array_keys(smpro_gw_doors());
$ports = smpro_gw_ports($cfg);
ok($ports, 'U1: with every door selected there are ports to cover');
nok(in_array(80, $ports, true),  'U1: port 80 is never covered — a shop stays readable from every country');
nok(in_array(443, $ports, true), 'U1: nor is 443');
ok(in_array(22, $ports, true),   'U1: SSH is covered');
ok(in_array(21, $ports, true),   'U1: and FTP, because uploads were the point');

// even a tampered stored config cannot add them
$cfg2 = smpro_gw_defaults(); $cfg2['doors'] = ['cpanel', 'web', 'http'];
$p2 = smpro_gw_ports($cfg2);
nok(in_array(80, $p2, true) || in_array(443, $p2, true), 'U1: an unknown door name cannot smuggle 80/443 in');

/* ---------- U2: the membership test is right, because a wrong one locks somebody out ---------- */
ok(smpro_gw_ip_in('192.0.2.7',   ['192.0.2.0/24']),  'U2: an address inside a /24 is inside');
nok(smpro_gw_ip_in('192.0.3.7',  ['192.0.2.0/24']),  'U2: one outside it is not');
ok(smpro_gw_ip_in('10.1.2.3',    ['10.0.0.0/8']),    'U2: a /8 works');
nok(smpro_gw_ip_in('11.1.2.3',   ['10.0.0.0/8']),    'U2: and does not over-reach');
ok(smpro_gw_ip_in('203.0.113.9', ['203.0.113.9']),   'U2: a bare address matches itself');
nok(smpro_gw_ip_in('203.0.113.9', []),               'U2: an EMPTY set matches nothing — the case that denies the world');
nok(smpro_gw_ip_in('not-an-ip',  ['0.0.0.0/0']),     'U2: rubbish is not a member of anything');
ok(smpro_gw_ip_in('1.2.3.4',     ['0.0.0.0/0']),     'U2: /0 does contain everything, and is handled without a shift bug');

/* ---------- U3: arming is refused unless the operator is provably inside ---------- */
$c = smpro_gw_defaults();
$c['countries'] = []; $c['doors'] = ['ssh'];
$chk = smpro_gw_arm_check($c, '192.0.2.7');
nok($chk['ok'], 'U3: no countries allowed = refused, not "deny everyone"');

$c['countries'] = ['ZZ'];                       // a code with certainly no range data
$chk = smpro_gw_arm_check($c, '192.0.2.7');
nok($chk['ok'], 'U3: refused while the firewall has no ranges for a chosen country');
ok((bool)array_filter($chk['problems'], fn($p) => strpos($p, 'no address ranges') !== false),
   'U3: and says the ranges are missing rather than arming an empty wall');

$c['doors'] = [];
$chk = smpro_gw_arm_check($c, '192.0.2.7');
ok((bool)array_filter($chk['problems'], fn($p) => strpos($p, 'No door') !== false), 'U3: no doors = refused');

$c['doors'] = ['ssh']; $c['countries'] = ['ZZ'];
$chk = smpro_gw_arm_check($c, '');
ok((bool)array_filter($chk['problems'], fn($p) => strpos($p, 'own address could not be determined') !== false),
   'U3: an unknown operator address is refused — it cannot be proven to survive');

/* ---------- U4: applying refuses before it writes ---------- */
$r = smpro_gw_apply($c, '192.0.2.7', true);
nok($r['ok'], 'U4: a dry run of an unarmed-able config still refuses');
isnt_eq(trim((string)$r['msg']), '', 'U4: with a reason');

/* ---------- U5: the rule is built in exactly one place ---------- */
$args = smpro_gw_rule_args([22, 2087]);
has($args, '--dports 22,2087', 'U5: the ports are in the rule');
has($args, '! --match-set ' . SMPRO_GW_SET, 'U5: it is default-DENY — anything NOT in the set is dropped');
has($args, '-j DROP', 'U5: and the action is drop');
has($args, SMPRO_GW_MARK, 'U5: it carries a marker, so removal takes out exactly what this added');
$many = smpro_gw_rule_args(range(1000, 1030));
is_eq(substr_count(explode('--dports ', $many)[1], ',') + 1, 15, 'U5: never more than 15 ports — multiport\'s limit, applied not discovered');

/* ---------- U6: the safety that makes it usable at all ---------- */
$src = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/geowall.php'));
has($src, 'function smpro_gw_deadman', 'U6: there is a dead man\'s switch');
has($src, "\$cfg['enabled'] = false;", 'U6: and it switches the wall off, not just removes the rule');
has($src, 'function smpro_gw_cron_sync', 'U6: with a schedule, so it runs when nobody is watching');
ok(strpos($src, 'ipset swap') !== false, 'U6: the set is swapped in atomically, never filled live under the rule');
$iSet = strpos($src, 'ipset swap');
$iRule = strpos($src, 'iptables -I INPUT 1');
ok($iSet !== false && $iRule !== false && $iSet < $iRule,
   'U6: the set is in place BEFORE the rule — the other order denies the world for a moment, including the operator');

$tick = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/bin/geowall_tick.php'));
has($tick, 'smpro_gw_remove()', 'U6: if the watcher itself fails, the wall comes down');
// The word appears in the comment explaining WHY the gate is absent; what must not appear is the gate call
// itself. A needle that matches an explanation is a test that fails for the wrong reason.
hasnt($tick, "if (function_exists(" . chr(39) . "smpro_ctl_disabled" . chr(39) . ") && smpro_ctl_disabled()) exit;",
      'U6: and disabling the plugin does not strand a live DROP rule with nothing watching it');
has($tick, 'deliberately NOT gated', 'U6: with the reason written where the next reader will look');

/* ---------- U7: a reboot re-assert has a proven address to check against ---------- */
has($src, "'armed_from' => ''", 'U7: the address the wall was armed from is stored');
has($src, 'if ($myIp === \'\') $myIp = (string)($cfg[\'armed_from\'] ?? \'\');',
    'U7: and cron re-asserts against it instead of skipping the check');

/* ---------- U8: the panel and its endpoint ---------- */
$fw = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/firewall-status.php'));
has($fw, "'gw_save', 'gw_fetch', 'gw_preview', 'gw_apply', 'gw_remove', 'gw_beat'", 'U8: the endpoint exists');
has($fw, "\$cfg['enabled'] = false;                       // saving settings never arms",
    'U8: saving settings never arms — arming is its own deliberate press');
has($fw, 'id="gw"', 'U8: the panel is on the page');
has($fw, 'gwDoor', 'U8: with the doors as checkboxes');
has($fw, 'Ports 80 and 443 are never included and cannot be added', 'U8: and says plainly what is never walled');

// The heartbeat has to come from a browser. A worker feeding it proves nothing: from inside the server, a
// locked-out operator and a healthy one look exactly the same.
has($fw, "fd.set('fw_action','gw_beat')", 'U8: the dead man\'s switch is fed from the browser');
has($fw, 'setInterval(gwBeat', 'U8: and keeps being fed while the page is open');
hasnt(str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/bin/geowall_tick.php')), 'smpro_gw_heartbeat',
      'U8: the worker never feeds it — that would defeat the whole guard');

// A throw mid-apply must not leave a DROP rule nobody is managing.
has($fw, 'if (function_exists(\'smpro_gw_remove\')) @smpro_gw_remove();',
    'U8: an error during apply takes the wall down rather than leaving it half-applied');

/* ---------- U9: a test can never install a live cron ---------- */
// /etc/cron.d is an absolute path with no sandbox equivalent, so a test that saved any feature's settings was
// writing a real scheduled job onto whatever machine ran the suite. The lab noticed, restored the file, and the
// build went red at random — a flake with a real cause.
$hp = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/helpers.php'));
has($hp, "if (defined('SMPRO_TEST_SRC')) return true;", 'U9: the shared cron writer refuses to write during a test');
$i = strpos($hp, 'function smpro_cron_install');
$j = strpos($hp, "if (defined('SMPRO_TEST_SRC')) return true;", $i);
$k = strpos($hp, '@file_put_contents($path, $content', $i);
ok($i !== false && $j !== false && $k !== false && $j < $k, 'U9: and refuses BEFORE it writes, not after');

/* ---------- U10: THE SERVER MUST BE ABLE TO REACH ITSELF ---------- */
// This is the assertion that was missing, and its absence took a live server's services out. Armed with a
// country list, the drop rule cut the machine's traffic to its OWN address and to loopback: cPanel talking to
// its services, AutoSSL, mail handed between local daemons. The operator reported "the services fell over".
// The services were running. The server had been told to refuse itself.
$always = smpro_gw_always('198.51.100.9');
ok(smpro_gw_ip_in('127.0.0.1', $always), 'U10: loopback always gets through');
ok(smpro_gw_ip_in('127.0.0.53', $always), 'U10: the whole 127/8 range, not just one address');
ok(in_array('198.51.100.9', $always, true), 'U10: and so does the operator');

$gwSrc = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/geowall.php'));
has($gwSrc, "'127.0.0.0/8' => 1", 'U10: loopback is the FIRST thing in the always-allow list, not an afterthought');
has($gwSrc, 'hostname -I', 'U10: the machine\'s own addresses are collected');
has($gwSrc, 'ip -4 -o addr show scope global', 'U10: from two sources, because one can come back empty');
has($gwSrc, 'told to refuse itself', 'U10: with the incident that caused it written down');

/* ---------- U11: traffic already in flight is not cut ---------- */
$pre = smpro_gw_pre_rules([22, 2083]);
is_eq(count($pre), 2, 'U11: two rules stand in front of the drop');
ok((bool)array_filter($pre, fn($r) => strpos($r, 'ESTABLISHED,RELATED') !== false && strpos($r, '-j ACCEPT') !== false),
   'U11: established and related connections are accepted — a country rule decides who may START a connection');
ok((bool)array_filter($pre, fn($r) => strpos($r, '-i lo') !== false && strpos($r, '-j ACCEPT') !== false),
   'U11: and loopback is accepted at the rule level too, not only via the set');
foreach ($pre as $r) has($r, SMPRO_GW_MARK, 'U11: each carries the marker so removal takes them out as well');
has($gwSrc, 'array_reverse(smpro_gw_pre_rules($ports))',
    'U11: they are inserted so they end up ABOVE the drop — the wrong order is what cut live sessions');

/* ---------- U12: the address a wall was proven from survives a save ---------- */
has($gwSrc, "\$c['armed_from'] = filter_var(", 'U12: armed_from is carried explicitly through a save');
$fwSrc = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/firewall-status.php'));
has($fwSrc, '$fresh = smpro_gw_cfg();', 'U12: the endpoint re-reads before saving instead of writing a stale copy back');
hasnt($fwSrc, "if (!empty(\$r['ok'])) { smpro_gw_save(\$cfg); if (function_exists('smpro_gw_cron_sync')) smpro_gw_cron_sync(); }",
      'U12: and no longer writes the pre-apply copy over it');

/* ---------- U13: a first arming cannot leave the operator out for a working day ---------- */
has($gwSrc, '$firstTime = ((string)($c[\'armed_from\'] ?? \'\') === \'\');',
    'U13: the first arming is recognised');
has($gwSrc, 'max(5, min($firstTime ? 60 : 10080, (int)$c[\'deadman_minutes\']))',
    'U13: and capped at an hour — 24 hours locked out is not something to find out by choosing it from a menu');

/* ---------- U12: fetching actually fetches, and a delay is not called a network fault ---------- */
// `csf -r` reloads rules; it does NOT download a country's ranges — that is lfd's scheduled job. Declaring the
// country and reloading left the zone file absent for up to a day while the button reported failure, and the
// failure it reported was "check outbound access" on a server whose outbound access was fine. An operator sent
// to hunt a network problem that does not exist stops believing the next message too.
$gw = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/geowall.php'));
has($gw, 'restart lfd',                  'U12: the download is actually triggered, not just declared');
has($gw, 'does NOT download',            'U12: with the reason csf -r was not enough written down');
has($gw, 'could not reach the range source', 'U12: a real outbound failure still says so');
has($gw, 'fetches ranges in its own scheduled job', 'U12: and a scheduling delay is reported as a delay');
ok(function_exists('smpro_gw_source_reachable'), 'U12: reachability can be tested rather than assumed');
is_eq(smpro_gw_zone_has('zz'), false,    'U12: a country with no range file has no ranges');
is_eq(smpro_gw_zones_missing(['zz']), true, 'U12: and that is reported as missing');
// null, never false, when the question could not be asked: "we could not check" must not pass for "it is down".
$reach = smpro_gw_source_reachable();
ok($reach === true || $reach === false || $reach === null, 'U12: reachability answers true, false or "could not ask"');
