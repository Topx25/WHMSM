<?php
/**
 * t54_breakin_assess.php — the per-network verdict on the Break-in Report (smpro_aa_bf_assess), pure fixtures.
 *   V1 password spraying (many accounts) → block
 *   V2 many addresses from one network → block
 *   V3 hammering (attempts per address) → block
 *   V4 cloud/hosting network with few attempts → block, and says crawlers never log in
 *   V5 one address, one account, few attempts, residential → normal ("wrong saved password")
 *   V6 small residential probe → watch
 *   V7 rate / burst / targets / door lines appear when the data supports them
 *   V8 rank order block < watch < normal
 */
require __DIR__ . '/../support/bootstrap.php';
require SMPRO_BASE . '/tests/support/plugin_funcs.php';
smpro_plugin_funcs('includes/helpers.php');
// The collector, the grouping and the verdict moved to includes/breakin.php so they could be reached from
// cron - a page module executes a router at include time and can never be required outside a browser.
// Both are loaded here: the page still owns the rendering, breakin.php now owns the judgement.
smpro_plugin_funcs('includes/breakin.php');
smpro_plugin_funcs('modules/account-audit.php');
ok(function_exists('smpro_aa_bf_assess'), 'V0: assess loaded router-free');

$net = function (int $ips, int $fails, array $users, bool $bot = false, int $span = 0, array $svc = ['cpaneld']) {
    $list = []; for ($i = 0; $i < $ips; $i++) $list[] = ['ip' => '203.0.113.' . ($i + 1), 'n' => intdiv($fails, $ips)];
    $u = []; foreach ($users as $x) $u[$x] = 1;
    return ['asn' => 'AS64500', 'provider' => 'Example', 'cc' => 'DE', 'ips' => $list, 'fails' => $fails, 'users' => $u, 'first' => 1000, 'last' => 1000 + $span, 'bot' => $bot, 'services' => array_fill_keys($svc, 1)];
};
$a = smpro_aa_bf_assess($net(2, 40, ['a', 'b', 'c', 'd', 'e', 'f']));
is_eq($a['verdict'], 'block', 'V1: 6 accounts → block'); is_eq($a['what'], 'Password spraying', 'V1: named'); ok((bool)array_filter($a['why'], fn($w) => strpos($w, 'password spraying') !== false), 'V1: reason');
$a = smpro_aa_bf_assess($net(15, 419, ['a']));
is_eq($a['verdict'], 'block', 'V2: 15 addresses → block'); is_eq($a['what'], 'Many-address run', 'V2: named'); ok((bool)array_filter($a['why'], fn($w) => strpos($w, 'one actor renting many addresses') !== false), 'V2: reason');
$a = smpro_aa_bf_assess($net(1, 120, ['a']));
is_eq($a['verdict'], 'block', 'V3: 120 attempts from one address → block'); is_eq($a['what'], 'Brute force', 'V3: named'); is_eq($a['per_ip'], 120.0, 'V3: per-address figure');
$a = smpro_aa_bf_assess($net(1, 6, ['a'], true));
is_eq($a['verdict'], 'block', 'V4: cloud network → block even when small'); is_eq($a['what'], 'Automated scanner', 'V4: named');
ok((bool)array_filter($a['why'], fn($w) => strpos($w, 'crawlers never attempt a login') !== false), 'V4: says it is not a crawler');
$a = smpro_aa_bf_assess($net(1, 6, ['a']));
is_eq($a['verdict'], 'normal', 'V5: one address, one account, 6 attempts, residential → normal'); is_eq($a['what'], 'Wrong saved password', 'V5: named');
is_eq($a['label'], 'Probably not an attack', 'V5: label');
$a = smpro_aa_bf_assess($net(2, 20, ['a', 'b']));
is_eq($a['verdict'], 'watch', 'V6: 2 addresses, 20 attempts, 2 accounts → look first'); is_eq($a['what'], 'Small probe', 'V6: named');
$a = smpro_aa_bf_assess($net(1, 60, ['a', 'b'], false, 600, ['cpaneld', 'webmaild']));
ok((bool)array_filter($a['why'], fn($w) => strpos($w, 'attempts/min') !== false), 'V7: rate line when span known'); is_eq($a['rate'], 6.0, 'V7: 60 attempts in 10 min = 6/min');
ok((bool)array_filter($a['why'], fn($w) => strpos($w, 'targets: a, b') !== false), 'V7: targets named');
ok((bool)array_filter($a['why'], fn($w) => strpos($w, 'door: cPanel, webmail') !== false), 'V7: doors translated');
$a = smpro_aa_bf_assess($net(1, 40, ['a'], false, 90));
ok((bool)array_filter($a['why'], fn($w) => strpos($w, 'inside two minutes') !== false), 'V7: burst line');
$a = smpro_aa_bf_assess($net(3, 30, ['a', 'b', 'c', 'd']));
ok(in_array('… (+1)', array_map(fn($w) => substr($w, -7), $a['why']), true) || (bool)array_filter($a['why'], fn($w) => strpos($w, '(+1)') !== false), 'V7: more than 3 targets is counted');
ok(smpro_aa_bf_rank('block') < smpro_aa_bf_rank('watch') && smpro_aa_bf_rank('watch') < smpro_aa_bf_rank('normal'), 'V8: rank order');
is_eq(smpro_aa_bf_rank('bogus'), 1, 'V8: unknown verdict ranks as watch');
$a = smpro_aa_bf_assess(['asn' => '', 'provider' => '', 'cc' => '', 'ips' => [], 'fails' => 0]);
ok(in_array($a['verdict'], ['block', 'watch', 'normal'], true) && $a['why'] !== [], 'V8: an empty row never throws and still explains');
