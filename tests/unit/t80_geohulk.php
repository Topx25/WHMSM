<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/geologin.php';
require_once SMPRO_BASE . '/includes/geohulk.php';
/**
 * t80_geohulk.php — the door wall refuses sign-ins from countries nobody is allowed from, BEFORE the password,
 * through cPHulk's country blacklist - and never through a packet drop.
 *
 * Locked here with cPHulk mocked: the blacklist is "every known code minus everyone's allowances", an empty
 * allowance refuses to arm, the operator's own address is whitelisted BEFORE anything else is changed, cPHulk is
 * only enabled if it was off, sync is a no-op when the list is unchanged and re-applies when it drifts, disarm
 * restores exactly the previous list and the previous on/off, and status never says "armed" when cPHulk is off.
 */
$calls = []; $HULK = ['enabled' => false, 'blacklist' => '', 'white' => []];
$GLOBALS['smpro_gh_api'] = function (string $fn, array $args) use (&$calls, &$HULK) {
    $calls[] = [$fn, $args];
    switch ($fn) {
        case 'cphulk_status': return ['metadata' => ['result' => 1], 'data' => ['is_enabled' => $HULK['enabled'] ? 1 : 0]];
        case 'enable_cphulk': $HULK['enabled'] = true; return ['metadata' => ['result' => 1]];
        case 'disable_cphulk': $HULK['enabled'] = false; return ['metadata' => ['result' => 1]];
        case 'create_cphulk_record': $HULK['white'][] = $args['ip']; return ['metadata' => ['result' => 1]];
        case 'set_cphulk_config_key': if ($args['key'] === 'country_blacklist') $HULK['blacklist'] = $args['value']; return ['metadata' => ['result' => 1]];
        case 'get_countries_with_known_ip_ranges':
            $c = [['code' => 'EG', 'name' => 'EG'], ['code' => 'AU', 'name' => 'AU']];   // + 156 synthetic codes (SA is among them) = 158
            foreach (range('A', 'Z') as $x) foreach (range('A', 'F') as $y) $c[] = ['code' => $x . $y, 'name' => $x . $y];
            return ['metadata' => ['result' => 1], 'data' => ['countries' => $c]];
        case 'queue:update_country_ips': return ['metadata' => ['result' => 1]];
        case 'conf:country_blacklist': return ['metadata' => ['result' => 1], 'data' => ['value' => $HULK['blacklist'], 'ranges' => $HULK['blacklist'] === '' ? 0 : 48]];
    }
    return null;
};
@unlink(SMPRO_VARLIB . '/geohulk_codes.json'); @unlink(SMPRO_GH_CFG);
smpro_gl_cfg_save(['countries' => ['EG', 'SA'], 'per_account' => ['shopone' => ['AU']]]);

/* ---------- U1: the list ---------- */
$allowed = smpro_gh_allowed();
ok(in_array('EG', $allowed, true) && in_array('SA', $allowed, true) && in_array('AU', $allowed, true), 'U1: allowed = the lock list + every per-account exception (' . implode(',', $allowed) . ')');
$bl = smpro_gh_blacklist(['EG', 'SA', 'AU', 'PL', 'US', 'de'], ['EG', 'SA', 'AU']);
is_eq($bl, 'DE,PL,US', 'U1: blacklist = every known code minus the allowed ones, upper-cased and sorted');
is_eq(smpro_gh_blacklist(['EG'], ['EG']), '', 'U1: nothing left to refuse when everything is allowed');
is_eq(count(smpro_gh_all_codes()), 158, 'U1: the code list comes from cPanel\'s own range database');

/* ---------- U2: refuses to arm when it would refuse everyone ---------- */
smpro_gl_cfg_save(['countries' => [], 'per_account' => []]);
$c = smpro_gh_arm_check('203.0.113.7');
ok(!$c['ok'], 'U2: no allowed country anywhere -> not armable');
smpro_gl_cfg_save(['countries' => ['EG', 'SA'], 'per_account' => ['shopone' => ['AU']]]);
$c = smpro_gh_arm_check('');
ok(!$c['ok'], 'U2: an operator address that cannot be established -> not armable (nothing to whitelist first)');

/* ---------- U3: arming - order of operations ---------- */
$calls = [];
$r = smpro_gh_arm('203.0.113.7', 'tester');
ok($r['ok'], 'U3: armed (' . $r['msg'] . ')');
$names = array_column($calls, 0);
$iWhite = array_search('create_cphulk_record', $names, true); $iOn = array_search('enable_cphulk', $names, true); $iSet = array_search('set_cphulk_config_key', $names, true);
ok($iWhite !== false && $iOn !== false && $iSet !== false && $iWhite < $iOn && $iOn < $iSet, 'U3: whitelist the operator FIRST, then enable cPHulk, then set the list');
is_eq($HULK['white'], ['203.0.113.7'], 'U3: the operator\'s address is on cPHulk\'s whitelist');
ok($HULK['enabled'], 'U3: cPHulk is on');
ok(strpos($HULK['blacklist'], 'EG') === false && strpos($HULK['blacklist'], 'SA') === false && strpos($HULK['blacklist'], 'AU') === false, 'U3: no allowed country is in the blacklist');
is_eq(substr_count($HULK['blacklist'], ',') + 1, 158 - 3, 'U3: every other known code is');
ok(in_array('queue:update_country_ips', $names, true), 'U3: cPHulk was asked to expand the list now');
$cfg = smpro_gh_cfg();
is_eq($cfg['prev_hulk_enabled'], false, 'U3: remembered that cPHulk was OFF before');

/* ---------- U4: sync is a no-op when unchanged, re-applies when the list or cPHulk drifts ---------- */
$calls = [];
$s = smpro_gh_sync();
ok($s['ok'] && !$s['changed'], 'U4: nothing changed -> nothing written');
ok(!in_array('set_cphulk_config_key', array_column($calls, 0), true), 'U4: and cPHulk was not touched');
smpro_gl_cfg_save(['countries' => ['EG', 'SA', 'DE'], 'per_account' => ['shopone' => ['AU']]]);   // operator allows DE
$s = smpro_gh_sync();
ok($s['changed'] && strpos($HULK['blacklist'], 'DE') === false, 'U4: allowing a new country removes it from the blacklist within a sync');
$HULK['enabled'] = false; $calls = [];
$s = smpro_gh_sync();
ok($HULK['enabled'], 'U4: cPHulk switched off underneath the wall is switched back on by the sync');
$HULK['blacklist'] = 'ZZ'; $calls = [];
$s = smpro_gh_sync();
ok($s['changed'] && $HULK['blacklist'] !== 'ZZ', 'U4: a list edited elsewhere is put back');

/* ---------- U5: status never lies ---------- */
$st = smpro_gh_status();
ok(in_array($st['state'], ['armed', 'unexpanded'], true), 'U5: armed (or waiting for cPHulk\'s expansion) - ' . $st['state']);
$HULK['enabled'] = false;
$st = smpro_gh_status();
is_eq($st['state'], 'hulk_off', 'U5: with cPHulk off the wall says so, not "armed"');
$HULK['enabled'] = true;

/* ---------- U6: disarm restores what was there ---------- */
$r = smpro_gh_disarm('tester');
ok($r['ok'], 'U6: disarmed');
is_eq($HULK['blacklist'], '', 'U6: cPHulk\'s country list is back to what it was (empty)');
ok(!$HULK['enabled'], 'U6: cPHulk is off again because it was off before the wall');
is_eq(smpro_gh_status()['state'], 'off', 'U6: status is off');

/* ---------- U7: it is a login refusal, never the firewall ---------- */
$src = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/geohulk.php'));
hasnt($src, 'ipset', 'U7: no ipset');
hasnt($src, 'iptables -', 'U7: no iptables');
hasnt($src, 'csf -d', 'U7: no csf deny');
has($src, "'country_blacklist'", 'U7: cPHulk\'s own country blacklist is the mechanism');
$tick = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/bin/geologin_tick.php'));
has($tick, 'smpro_gh_sync()', 'U7: the lock\'s tick keeps the wall in step');
has($tick, '$pass < 3', 'U7: and the tick now passes three times a minute');
$gl = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/geologin.php'));
has($gl, '"* * * * * root $flock', 'U7: the lock runs every minute, not every two');
unset($GLOBALS['smpro_gh_api']);
