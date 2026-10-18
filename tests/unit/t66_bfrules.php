<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/breakin.php';   // the verdict now lives here, not in the page module
require_once SMPRO_BASE . '/includes/bfrules.php';

/**
 * t66_bfrules.php — the rules that block a break-in network without a person present.
 *
 * The danger of an automatic block is not that it misses an attacker; it is that it blocks the wrong thing and
 * nobody is watching. So most of what is asserted here is what the rules REFUSE to do.
 */

/* A network shaped like the examples the operator gave. */
$net = function (array $o = []) {
    $n = array_replace([
        'provider' => 'Example Networks', 'asn' => 'AS64500', 'cc' => 'XX', 'bot' => false,
        'fails' => 100, 'first' => 1000, 'last' => 1000 + 3600,
        'ips' => [['ip' => '203.0.113.10', 'n' => 100]],
        'users' => ['root' => 60, 'admin' => 40],
        'services' => ['cpaneld' => 1],
    ], $o);
    return $n;
};
$spray = $net(['users' => array_fill_keys(array_map(fn($i) => 'u' . $i, range(1, 141)), 1), 'fails' => 141]);
$brute = $net(['users' => ['root' => 79], 'fails' => 79]);

/* ---------- U1: defaults are safe ---------- */
$d = smpro_bfr_defaults();
nok($d['enabled'], 'U1: off by default — a rule set that arms on save cannot be tried safely on a live server');
ok($d['dryrun'], 'U1: and dry run by default');

/* ---------- U2: a rule can ask for MORE evidence, never less ---------- */
$pats = smpro_bfr_patterns();
foreach ($pats as $k => $p) {
    ok($p['default_min'] >= $p['floor'], 'U2: default for "' . $k . '" is at or above the report threshold');
}
$saved = smpro_bfr_save(['enabled' => 1, 'dryrun' => 1, 'rules' => ['Brute force' => ['enabled' => 1, 'min' => 1]]]);
ok($saved, 'U2: a config with an under-floor threshold still saves');
$c = smpro_bfr_cfg();
is_eq($c['rules']['Brute force']['min'], $pats['Brute force']['floor'],
      'U2: ...but it is raised to the floor — below it the report does not call it an attack at all');

/* ---------- U3: only "block" is ever actioned ---------- */
$cfg = smpro_bfr_defaults();
$cfg['enabled'] = true;
foreach (['watch', 'normal'] as $v) {
    $m = smpro_bfr_match(['verdict' => $v, 'what' => 'Brute force', 'users' => 9, 'per_ip' => 900, 'rate' => 99, 'why' => []], $brute, $cfg);
    nok($m['match'], 'U3: a "' . $v . '" verdict is never blocked, however big the numbers');
    isnt_eq($m['skip'], '', 'U3: and it says why');
}

/* ---------- U4: the pattern must be one a rule covers ---------- */
$m = smpro_bfr_match(['verdict' => 'block', 'what' => 'Something New', 'users' => 99, 'per_ip' => 99, 'rate' => 9, 'why' => []], $brute, $cfg);
nok($m['match'], 'U4: an unknown pattern is not blocked — a new verdict is silence, not a surprise block');

/* ---------- U5: it matches the real assessment of a real shape ---------- */
$as = smpro_aa_bf_assess($spray);
is_eq($as['what'], 'Password spraying', 'U5: 141 accounts is read as password spraying');
is_eq($as['verdict'], 'block', 'U5: and as an attack');
$cfg['rules']['Password spraying'] = ['enabled' => true, 'min' => 10];
$m = smpro_bfr_match($as, $spray, $cfg);
ok($m['match'], 'U5: the rule matches it');
has($m['why'], 'Password spraying', 'U5: and the recorded reason names the pattern');
has($m['why'], 'password spraying', 'U5: carrying the page\'s OWN sentence, not a restatement of it');

/* ---------- U6: the threshold is honoured ---------- */
$cfg['rules']['Password spraying']['min'] = 500;
$m = smpro_bfr_match($as, $spray, $cfg);
nok($m['match'], 'U6: under the operator threshold it is not blocked');
has($m['skip'], 'rule needs 500', 'U6: and the reason says what was needed');

/* ---------- U7: a disabled rule does nothing ---------- */
$cfg['rules']['Password spraying'] = ['enabled' => false, 'min' => 5];
$m = smpro_bfr_match($as, $spray, $cfg);
nok($m['match'], 'U7: a rule that is off does not block');
has($m['skip'], 'is off', 'U7: and says so rather than looking like no match');

/* ---------- U8: arming is refused if it would catch the operator ---------- */
$cfg = smpro_bfr_defaults(); $cfg['enabled'] = true; $cfg['dryrun'] = false;
$cfg['rules']['Password spraying'] = ['enabled' => true, 'min' => 10];
$chk = smpro_bfr_arm_check($cfg, '203.0.113.10', [$spray]);
nok($chk['ok'], 'U8: arming is REFUSED when the operator\'s own address is in a network the rules would block');
has($chk['msg'], 'lock you out', 'U8: and the refusal says why in plain words');

$chk2 = smpro_bfr_arm_check($cfg, '198.51.100.7', [$spray]);
ok($chk2['ok'], 'U8: an operator outside those networks can arm');

/* ---------- U9: a run with the rules off looks at nothing, and says so ---------- */
$off = smpro_bfr_defaults();
$r = smpro_bfr_run([$spray], $off, null, 'test');
nok($r['ok'], 'U9: with the rules off nothing runs');
has($r['msg'], 'Nothing was looked at', 'U9: stated as "not checked", never as "nothing found"');

/* ---------- U10: dry run changes nothing and still shows the work ---------- */
$on = smpro_bfr_defaults(); $on['enabled'] = true;
$on['rules']['Password spraying'] = ['enabled' => true, 'min' => 10];
$r = smpro_bfr_run([$spray], $on, true, 'test');
ok($r['dryrun'], 'U10: dry run is reported as such');
is_eq(count($r['blocked']), 0, 'U10: and blocks nothing');
ok(count($r['would']) >= 1, 'U10: while still naming what it would block');
has($r['msg'], 'Nothing was changed', 'U10: and saying plainly that nothing changed');

/* ---------- U11: the near-misses are reported too ---------- */
$quiet = $net(['users' => ['bob' => 3], 'fails' => 3, 'ips' => [['ip' => '203.0.113.99', 'n' => 3]]]);
$r = smpro_bfr_run([$quiet], $on, true, 'test');
ok(count($r['skipped']) >= 1, 'U11: a network that was passed over is listed');
isnt_eq((string)($r['skipped'][0]['why'] ?? ''), '',
        'U11: with the reason — a rule that quietly does nothing looks exactly like one that is working');

/* ---------- U12: the judgement is reachable outside a browser ---------- */
// This is the whole point of the rules. It lived inside modules/account-audit.php, and a page module executes a
// router at include time — so nothing in cron could ever require it. The rules could be pressed by a person and
// could not run while nobody was looking, which is exactly when an attack starts.
ok(is_file(SMPRO_BASE . '/includes/breakin.php'), 'U12: the break-in judgement lives in includes/, not in a page module');
$bi = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/breakin.php'));
has($bi, 'function smpro_bi_networks', 'U12: and there is a builder a worker can call');
has($bi, 'function smpro_aa_bf_assess', 'U12: with the SAME verdict function the page uses — one opinion, not two');
$aaMod = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/account-audit.php'));
is_eq(substr_count($aaMod, 'function smpro_aa_bf_assess'), 0, 'U12: the page no longer carries its own copy');
is_eq(substr_count($aaMod, 'function smpro_aa_collect'), 0, 'U12: nor its own collector');

ok(is_file(SMPRO_BASE . '/bin/bfrules_tick.php'), 'U12: there is a worker');
$tick = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/bin/bfrules_tick.php'));
hasnt($tick, "modules/", 'U12: and it never loads a page module');
has($tick, "smpro_bi_networks()", 'U12: it rebuilds the networks from this server\'s own logs');
has($tick, "could not read the logs", 'U12: a night it could not look is recorded, not silently treated as quiet');
has($bi, 'function smpro_bi_networks', 'U12: builder present');

/* ---------- U13: the cron follows the setting, both ways ---------- */
$bfr = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/bfrules.php'));
has($bfr, 'function smpro_bfr_cron_sync', 'U13: there is a cron sync');
has($bfr, "if (empty(\$cfg['enabled'])) { if (@is_file(\$f)) @unlink(\$f); return true; }",
    'U13: turning the rules off REMOVES the cron — a cron that exists but does nothing outlives the feature');
$i = strpos($bfr, '$ok = @rename($tmp, SMPRO_BFR_CFG);');
$j = strpos($bfr, 'smpro_bfr_cron_sync();');
ok($i !== false && $j !== false && $j > $i, 'U13: and it runs on save, so "on" takes effect immediately');

/* ---------- U14: allow-listed addresses never reach a rule at all ---------- */
has($bi, 'smpro_fw_allow_covers_name', 'U14: the builder drops allow-listed addresses before anything can act on them');
has($bi, 'smpro_aa_bf_ign_all', 'U14: and honours the networks the operator marked as ignored');
