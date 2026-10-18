<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/uistory.php';
/**
 * t77_story.php — the investigation told in plain words says only what the rows say, and says it about people.
 *
 * THE ASK. The page showed 2,039 rows and six counters, and an operator could not tell from it what had
 * happened: who came, from where, what they did, whether it mattered. The story groups the same rows by
 * address into episodes and writes one sentence per episode. Locked here: the grouping, the classes, that
 * blocked-only noise is folded into one paragraph, that a person's session outranks it, that nothing is
 * invented for an address the rows do not carry, and that "could not look" survives into the story.
 */
$t0 = 1789900000;
$ev = [];
// a password holder: signs in, runs panel ops, two hours later comes back (same address, gap > 30 min = new episode)
$ev[] = ['ts' => $t0,        'source' => 'login',        'actor_ip' => '203.0.113.5', 'action' => 'Successful login', 'target' => 'cpaneld', 'severity' => 'info'];
$ev[] = ['ts' => $t0 + 60,   'source' => 'cpanel_panel', 'actor_ip' => '203.0.113.5', 'action' => 'POST Fileman::upload_files', 'target' => '/execute/Fileman/upload_files', 'severity' => 'low'];
$ev[] = ['ts' => $t0 + 90,   'source' => 'cpanel_panel', 'actor_ip' => '203.0.113.5', 'action' => 'POST Email::add_pop', 'target' => '/execute/Email/add_pop', 'severity' => 'low'];
$ev[] = ['ts' => $t0 + 7200, 'source' => 'cpanel_panel', 'actor_ip' => '203.0.113.5', 'action' => 'GET Themes::list', 'target' => '/execute/Themes/list', 'severity' => 'info'];
// a brute-forcer
for ($i = 0; $i < 12; $i++) $ev[] = ['ts' => $t0 + $i * 10, 'source' => 'login', 'actor_ip' => '198.51.100.9', 'action' => 'Failed login', 'target' => 'FAILED LOGIN', 'severity' => 'medium'];
// blocked attack noise from three addresses
foreach (['192.0.2.1', '192.0.2.2', '192.0.2.3'] as $ip) for ($i = 0; $i < 20; $i++)
    $ev[] = ['ts' => $t0 + $i * 300, 'source' => 'web_attack', 'actor_ip' => $ip, 'action' => 'Sensitive File Access (403)', 'target' => '/.env', 'severity' => 'critical', 'fx' => ['outcome' => 'blocked']];
// one attack that reached the app
$ev[] = ['ts' => $t0 + 500, 'source' => 'web_attack', 'actor_ip' => '192.0.2.77', 'action' => 'Command Injection / RCE (200)', 'target' => '/wp-content/x.php', 'severity' => 'critical', 'fx' => ['outcome' => 'reached']];
// file changes: the password holder through File Manager, and PHP deleting a cache file with no address
$fa = ['ok' => true, 'why' => '', 'partial' => false, 'covered_from' => $t0 - 86400, 'events' => [
    ['ts' => $t0 + 70,  'door' => 'cpanel', 'actor' => 'acct', 'ip' => '203.0.113.5', 'op' => 'created', 'path' => '/home/acct/public_html/new.php'],
    ['ts' => $t0 + 510, 'door' => 'web',    'actor' => 'acct', 'ip' => '',            'op' => 'deleted', 'path' => '/home/acct/public_html/wp-content/uploads/x.txt'],
]];

$s = smpro_ui_story($ev, $fa, $t0 - 100, $t0 + 9000);

/* ---------- U1: episodes are per address, split at silence ---------- */
$byIp = [];
foreach ($s['episodes'] as $ep) $byIp[$ep['ip']][] = $ep;
is_eq(count($byIp['203.0.113.5'] ?? []), 2, 'U1: the password holder has two episodes - the second visit was over 30 minutes later');
is_eq(count($byIp['198.51.100.9'] ?? []), 1, 'U1: the brute-forcer has one');
ok(!isset($byIp['192.0.2.1']), 'U1: blocked-only addresses are not episodes of their own');

/* ---------- U2: classes ---------- */
$owner = $byIp['203.0.113.5'][0]['class'] === 'owner' ? $byIp['203.0.113.5'][0] : $byIp['203.0.113.5'][1];
is_eq($owner['class'], 'owner', 'U2: a successful password sign-in makes the episode a password holder');
is_eq($byIp['198.51.100.9'][0]['class'], 'bruteforce', 'U2: twelve failed sign-ins is password guessing');
is_eq($byIp['192.0.2.77'][0]['class'], 'reached', 'U2: an attack that reached the app is its own class');
is_eq($byIp[''][0]['class'], 'machine', 'U2: a file change with no address is the site\'s own code');

/* ---------- U3: the sentence says what the rows say ---------- */
has($owner['sentence'], 'signed in with the account password', 'U3: the sign-in is in the sentence');
has($owner['sentence'], 'ran 2 panel operations (Fileman, Email)', 'U3: the panel operations are counted and named by module');
has($owner['sentence'], 'changed 1 file through File Manager (1 created)', 'U3: the file change is attributed to the same episode by address');
has($owner['sentence'], '203.0.113.5', 'U3: the address is in the sentence');
has($byIp['192.0.2.77'][0]['sentence'], 'REACHED the site', 'U3: a reached attack is shouted');
is_eq($byIp[''][0]['c']['file'], 1, 'U3: the addressless change stays addressless - nothing is invented');

/* ---------- U4: ranking - what matters comes first ---------- */
is_eq($s['episodes'][0]['class'], 'reached', 'U4: the attack that got through is episode 1');
ok($s['episodes'][1]['class'] === 'owner' || $s['episodes'][1]['class'] === 'bruteforce', 'U4: then the people and the guessing');
$last = end($s['episodes']);
ok($last['weight'] <= $s['episodes'][0]['weight'], 'U4: sorted by weight, descending');

/* ---------- U5: blocked noise is one paragraph with real numbers ---------- */
is_eq($s['blocked']['n'], 60, 'U5: 60 blocked requests folded into one paragraph');
is_eq(count($s['blocked']['ips']), 3, 'U5: from three addresses');
is_eq(array_key_first($s['blocked']['targets']), 'Sensitive File Access', 'U5: with the status code stripped from the label');

/* ---------- U6: the bottom line ---------- */
is_eq($s['bottom']['people'], 2, 'U6: two person sessions (the same address, twice)');
is_eq($s['bottom']['addrs'], 1, 'U6: from one address');
is_eq($s['bottom']['reached'], 1, 'U6: one attack reached');
is_eq($s['bottom']['failed'], 12, 'U6: twelve failed sign-ins');
is_eq($s['bottom']['files'], 2, 'U6: two file changes in the episodes');

/* ---------- U7: could-not-look survives into the story ---------- */
$blind = smpro_ui_story($ev, ['ok' => false, 'why' => 'auditd is not installed', 'events' => [], 'partial' => false, 'covered_from' => 0], $t0, $t0 + 9000);
ok(count($blind['blind']) === 1 && strpos($blind['blind'][0], 'auditd is not installed') !== false, 'U7: a blind file-change source is named, not shown as zero changes');
$partial = smpro_ui_story($ev, ['ok' => true, 'why' => '', 'events' => [], 'partial' => true, 'covered_from' => $t0 + 100], $t0, $t0 + 9000);
ok(count($partial['blind']) === 1 && strpos($partial['blind'][0], 'only recorded from') !== false, 'U7: a window that starts before recording says so');
$big = $ev; for ($i = 0; $i < 2000; $i++) $big[] = ['ts' => $t0 + $i, 'source' => 'web_attack', 'actor_ip' => '192.0.2.9', 'action' => 'WAF Block (other) (403)', 'target' => '/', 'severity' => 'notice', 'fx' => ['outcome' => 'blocked']];
$capped = smpro_ui_story($big, null, $t0, $t0 + 9000);
ok(!empty($capped['capped']), 'U7: a window at the 2,000-row cap is marked as a floor, not printed as a total');

/* ---------- U8: the text report carries the same facts ---------- */
$txt = smpro_ui_story_text('acct', $t0, $t0 + 9000, $s);
has($txt, 'BOTTOM LINE', 'U8: has a bottom line');
has($txt, '2 person session(s) from 1 address(es)', 'U8: with the people count');
has($txt, 'REACHED the site', 'U8: and the reached attack');
has($txt, 'BLOCKED ATTACK TRAFFIC: 60 request(s) from 3 address(es)', 'U8: and the folded noise');
has($txt, 'file: /home/acct/public_html/new.php', 'U8: and the changed file');

/* ---------- U9: the page wires it ---------- */
$mod = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/user-investigation.php'));
has($mod, 'What happened', 'U9: the story section is on the page');
has($mod, 'Download report (.txt)', 'U9: with the text report');
has($mod, 'data-go="<?= smpro_h($go) ?>"', 'U9: every KPI card is a control');
has($mod, "'src:cpanel_panel'", 'U9: Panel actions filters to the panel rows - the number that had no way to see its rows');
has($mod, "'jump:uiSignins'", 'U9: and sign-ins have their own card, which jumps to who-got-in');
has($mod, 'IDX.map(function(i){return EV[i];})', 'U9: the grouped view honours the filter too');

/* ---------- U10: who got in, and everything each address did ---------- */
// The narrower question: only the successful sign-ins, and for each address that got in, ALL of its actions in the
// window - not the 30-minute episode. An address that never signed in is not listed, whatever else it did.
$si = $s['signins'];
is_eq(count($si), 1, 'U10: one address signed in');
is_eq($si[0]['ip'], '203.0.113.5', 'U10: the password holder');
is_eq(count($si[0]['logins']), 1, 'U10: with its sign-in');
is_eq(count($si[0]['panel']), 3, 'U10: and ALL its panel operations, including the one two hours later that was a separate episode');
is_eq(count($si[0]['files']), 1, 'U10: and its file change');
is_eq($si[0]['modules'], ['Fileman' => 1, 'Email' => 1, 'Themes' => 1], 'U10: panel operations summarised by module');
foreach ($si as $x) ok($x['ip'] !== '198.51.100.9' && $x['ip'] !== '192.0.2.77', 'U10: the brute-forcer and the attacker are not here - they never got in');
has($txt = smpro_ui_story_text('acct', $t0, $t0 + 9000, $s), 'WHO SIGNED IN, AND EVERYTHING EACH ADDRESS DID', 'U10: the text report has the section');
has($txt, '203.0.113.5 - 1 sign-in(s), 3 panel operation(s), 1 file change(s)', 'U10: with the counts');
has($mod, 'id="uiSignins"', 'U10: the page has the section');
has($mod, "'jump:uiSignins'", 'U10: and the Sign-ins card jumps to it');
