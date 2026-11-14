<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
require_once SMPRO_BASE . '/includes/botguard.php';
/**
 * t176 - round 428: the Telegram bot cannot be kept busy by strangers, a hole in the file-change evidence is said,
 * the Service Monitor never takes CSF out of TESTING, and Bot Guard blocks on a count only when that count is
 * something the address itself must have produced.
 */
$src = fn($p) => str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/' . $p));

$tg = $src('includes/tgbot.php');
$i = strpos($tg, "if (!\$authorized) {");
$blk = $i !== false ? substr($tg, $i, 1600) : '';
ok($i !== false, 'T0: the unauthorized branch is there');
$a = strpos($blk, "smpro_tg_state_save(['offset' => \$offset]); \$cfg['offset'] = \$offset;");
$b = strpos($blk, "smpro_tg_send(\$cfg['token'], \$chat,");
ok($a !== false && $b !== false && $a < $b, 'T1: the position is saved before a stranger is answered');
has($blk, "if (\$tnow - (int)(\$den[\$dk] ?? 0) >= 3600) {", 'T2: a stranger gets one answer an hour');
has($blk, "if (count(\$den) > 500) \$den = array_slice(\$den, -500, 500, true);", 'T3: the list of strangers is bounded');
is_eq(substr_count($blk, "smpro_tg_send(\$cfg['token'], \$chat, '"), 1, 'T4: and there is no second, unconditional answer');

$fa = $src('includes/fileaudit.php');
has($fa, "if (!\$files) {", 'G1: a rotated log that is gone is noticed');
has($fa, "smpro_audit('fileaudit_gap'", 'G2: ...written to the audit trail');
has($fa, "\$st['blind'] = \$blind !== '' ? \$blind : (string)(\$gap ?? '');", 'G3: ...and shown as a blind period');

$sv = $src('includes/svcmon.php');
ok(strpos($sv, "@file_put_contents('/etc/csf/csf.conf'") === false, 'C1: the Service Monitor never rewrites csf.conf');
has($sv, "'cause' => 'CSF is in TESTING mode, and lfd does not run in it. Not changed:", 'C2: TESTING mode is reported with what to do');

/* ---------- Bot Guard: what a count is made of ---------- */
$chrome = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36';
$req = fn(string $ip, string $m, string $uri, int $st, string $ua, int $ts) => ['ip' => $ip, 'ts' => $ts, 'method' => $m, 'uri' => $uri, 'status' => $st, 'ua' => $ua];
$now = time(); $ips = [];
smpro_bg_aggregate($ips, $req('203.0.113.30', 'GET', '/xmlrpc.php', 405, $chrome, $now), 'a.test', 0);
ok(!isset($ips['203.0.113.30']), 'X1: a GET to xmlrpc.php is nothing');
for ($k = 0; $k < 40; $k++) smpro_bg_aggregate($ips, $req('203.0.113.31', 'POST', '/xmlrpc.php', 200, 'Jetpack by WordPress.com', $now), 'a.test', 0);
is_eq((int)$ips['203.0.113.31']['attacks'], 0, 'X2: forty POSTs from a client that names itself Jetpack are not forty guesses');
for ($k = 0; $k < 270; $k++) smpro_bg_aggregate($ips, $req('203.0.113.31', 'POST', '/xmlrpc.php', 200, 'Jetpack by WordPress.com', $now), 'a.test', 0);
is_eq((int)$ips['203.0.113.31']['attacks'], 10, 'X3: past 300 the name stops helping');
smpro_bg_aggregate($ips, $req('203.0.113.32', 'POST', '/xmlrpc.php', 200, $chrome, $now), 'a.test', 0);
is_eq((int)$ips['203.0.113.32']['attacks'], 1, 'X4: a POST to xmlrpc.php from anything else is a guess');
is_eq((int)$ips['203.0.113.32']['atk_nonget'], 1, 'X5: ...and is remembered as a POST');

$cfg = ['gray_threshold' => 25, 'window_hours' => 24]; $cat = smpro_bg_catalog();
$mk = function (string $ua, array $over = []) use ($req, $now) {
    $ips = [];
    for ($k = 0; $k < 30; $k++) smpro_bg_aggregate($ips, $req('203.0.113.40', 'GET', '/.env?' . $k, 404, $ua, $now), 'a.test', 0);
    return array_merge($ips['203.0.113.40'], $over);
};
$a1 = $mk($chrome);
ok(smpro_bg_hold_reason($a1, ['attacks' => 30], '', $cat, $cfg) !== '', 'H1: thirty GETs with a browser signature on one site in one hour are held, not blocked');
is_eq(smpro_bg_hold_reason($mk($chrome, ['atk_domains' => ['a.test' => 1, 'b.test' => 1, 'c.test' => 1]]), ['attacks' => 30], '', $cat, $cfg), '', 'H2: the same over three sites is a sweep - blocked');
is_eq(smpro_bg_hold_reason($mk($chrome, ['atk_hours' => [1 => 1, 2 => 1, 3 => 1]]), ['attacks' => 30], '', $cat, $cfg), '', 'H3: ...or over three hours - blocked');
is_eq(smpro_bg_hold_reason($mk($chrome, ['atk_nonget' => 1]), ['attacks' => 30], '', $cat, $cfg), '', 'H4: one POST among them - blocked');
is_eq(smpro_bg_hold_reason($mk('curl/8.4.0'), ['attacks' => 30], '', $cat, $cfg), '', 'H5: a script by its own signature - blocked');
is_eq(smpro_bg_hold_reason($mk(''), ['attacks' => 30], '', $cat, $cfg), '', 'H6: no User-Agent at all - blocked');
$tgUa = 'TelegramBot (like TwitterBot)';
ok(smpro_bg_hold_reason($mk($tgUa), ['attacks' => 30, 'verified' => false], 'telegram', $cat, $cfg) !== '', 'H7: a link-preview service over the threshold is held');
is_eq(smpro_bg_hold_reason($mk($tgUa), ['attacks' => 100, 'verified' => false], 'telegram', $cat, $cfg), '', 'H8: ...up to four times the threshold, then blocked (the name can be faked)');
$old = $a1; unset($old['atk_nonget']);
is_eq(smpro_bg_hold_reason($old, ['attacks' => 30], '', $cat, $cfg), '', 'H9: a record without the detail is decided as before');
is_eq(smpro_bg_hold_reason(array_merge($a1, ['cats' => ['probe' => 29, 'waf' => 1]]), ['attacks' => 30], '', $cat, $cfg), '', 'H10: an event from the server rule engine - blocked');

// the whole decision
$scan = ['ips' => ['203.0.113.40' => $a1, '203.0.113.41' => array_merge($mk('curl/8.4.0'), ['ip' => '203.0.113.41'])], 'files' => 1, 'lines' => 60, 'waf' => 0];
$full = ['gray_threshold' => 25, 'window_hours' => 24, 'allow_verified' => true, 'auto_block' => true];
$d = smpro_bg_decide($scan, $full + (function_exists('smpro_bg_cfg') ? smpro_bg_cfg() : []), ['bots' => []], fn($ip, $f) => ['verified' => false, 'how' => '', 'host' => '', 'why' => ''], $now);
ok(!isset($d['to_block']['203.0.113.40']) && ($d['state']['bots']['203.0.113.40']['status'] ?? '') === 'gray', 'D1: the browser-signature address goes to the gray list with the reason');
ok(isset($d['to_block']['203.0.113.41']), 'D2: the script is blocked as before');
ok(in_array('203.0.113.40', $d['new_gray'], true), 'D3: and the operator is told about the held one');
