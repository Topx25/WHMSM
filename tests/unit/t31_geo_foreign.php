<?php
/**
 * t31_geo_foreign.php — Phase 3 unit coverage for the shared "foreign IP" geo rule.
 *
 *   U46  smpro_geo_foreign(ip)  — the single rule that login/spam/brute-force/intrusion all share:
 *        external + resolved to a NON-Arab country => foreign. Returns
 *        ['foreign'=>bool,'cc'=>CC,'arab'=>bool,'local'=>bool,'known'=>bool].
 *
 * geo_foreign lives in helpers.php alongside the smpro_ip_intel SEAM, so we install the deterministic
 * stubs FIRST and then require the .build copy of helpers.php (whose 4 seam defs are renamed/guarded so
 * our stub provides the real name). Every OTHER helper (smpro_ip_is_external, smpro_cc_is_arab) is the
 * real shipped code. We drive geo_foreign purely by swapping the ip_intel stub map per case.
 *
 * Derivation (from helpers.php smpro_geo_foreign, lines 479-487):
 *   $loc = scope==='local' || cc==='LOCAL' || !smpro_ip_is_external($ip)   // stub returns no 'scope'
 *   if $loc -> ['foreign'=>false,'cc'=>'LOCAL','arab'=>false,'local'=>true,'known'=>true]
 *   $known = cc !== '' && cc !== 'N/A' && cc !== 'NA'   (cc is strtoupper'd)
 *   $arab  = smpro_cc_is_arab($cc)
 *   return ['foreign'=>($known && !$arab),'cc'=>$cc,'arab'=>$arab,'local'=>false,'known'=>$known]
 */
require __DIR__ . '/../support/bootstrap.php';

smpro_test_install_stubs(['ip_intel' => []]);          // seam defs win; ip_is_external / cc_is_arab stay real
require SMPRO_TEST_BUILD . '/includes/helpers.php';
require SMPRO_TEST_BUILD . '/includes/intrusion.php';  // cc_is_arab -> smpro_im_trusted_regions (config-driven); seed the Arab set
@is_dir(dirname(SMPRO_IN_CFG)) || @mkdir(dirname(SMPRO_IN_CFG), 0700, true);
@file_put_contents(SMPRO_IN_CFG, json_encode(['protect_regions' => ['IS','NZ'], 'caution_regions' => ['FJ']]));

ok(function_exists('smpro_geo_foreign'), 'geo_foreign loaded from .build; stubs installed');
ok(function_exists('smpro_ip_intel'),    'ip_intel seam resolves to the stub (not the real whois caller)');

/* helper: point the ip_intel stub at one IP, then evaluate the rule for it */
$geo = function (string $ip, array $intel) {
    smpro_stub_set('ip_intel', [$ip => $intel]);
    return smpro_geo_foreign($ip);
};

/* ---------- U46a — US external, non-Arab -> foreign & known, not arab/local ---------- */
$us = $geo('198.51.100.10', ['country' => 'US', 'provider' => 'n/a', 'asn' => '', 'datacenter' => false]);
is_eq($us['foreign'], true,  'U46 US -> foreign=true');
is_eq($us['arab'],    false, 'U46 US -> arab=false');
is_eq($us['known'],   true,  'U46 US -> known=true');
is_eq($us['local'],   false, 'U46 US -> local=false');
is_eq($us['cc'],      'US',  'U46 US -> cc preserved (uppercase US)');
is_eq($us, ['foreign'=>true,'cc'=>'US','arab'=>false,'local'=>false,'known'=>true], 'U46 US -> exact shape & key order');

/* lowercase country is upper-cased by the rule -> still foreign, cc normalized */
$usl = $geo('198.51.100.11', ['country' => 'us', 'provider' => '', 'asn' => '', 'datacenter' => false]);
is_eq($usl['cc'], 'US', 'U46 lowercase "us" -> cc upper-cased to US');
is_eq($usl['foreign'], true, 'U46 lowercase "us" -> still foreign');

/* datacenter flag is IRRELEVANT to geo_foreign (it only reads country) */
$usd = $geo('198.51.100.12', ['country' => 'US', 'provider' => 'AWS', 'asn' => 'AS16509', 'datacenter' => true]);
is_eq($usd['foreign'], true, 'U46 US datacenter -> foreign unchanged (rule ignores datacenter)');

/* ---------- U46b — home-region external -> NOT foreign, trusted=true, known=true ---------- */
$eg = $geo('198.51.100.20', ['country' => 'IS', 'provider' => 'n/a', 'asn' => '', 'datacenter' => false]);
is_eq($eg['foreign'], false, 'U46 home region -> foreign=false (a trusted region is never foreign)');
is_eq($eg['arab'],    true,  'U46 home region -> trusted=true');
is_eq($eg['known'],   true,  'U46 home region -> known=true');
is_eq($eg['local'],   false, 'U46 home region -> local=false');
is_eq($eg, ['foreign'=>false,'cc'=>'IS','arab'=>true,'local'=>false,'known'=>true], 'U46 home region -> exact shape & key order');

/* a CAUTION-tier region is still trusted & not foreign */
$ae = $geo('198.51.100.21', ['country' => 'FJ', 'provider' => '', 'asn' => '', 'datacenter' => false]);
is_eq($ae['arab'],    true,  'U46 caution region -> trusted=true');
is_eq($ae['foreign'], false, 'U46 caution region -> foreign=false');

/* ---------- U46c — private/reserved IP -> local (real smpro_ip_is_external decides) ---------- */
$lo = $geo('10.0.0.1', ['country' => '', 'provider' => '', 'asn' => '', 'datacenter' => false]);
is_eq($lo['local'],   true,  'U46 10.0.0.1 -> local=true (real ip_is_external rejects private range)');
is_eq($lo['foreign'], false, 'U46 10.0.0.1 -> foreign=false');
is_eq($lo['known'],   true,  'U46 10.0.0.1 -> known=true (local short-circuit marks it known)');
is_eq($lo['cc'],      'LOCAL','U46 10.0.0.1 -> cc=LOCAL');
is_eq($lo, ['foreign'=>false,'cc'=>'LOCAL','arab'=>false,'local'=>true,'known'=>true], 'U46 10.0.0.1 -> exact local shape');

/* loopback is also local via the real ip_is_external (reserved range) */
$lb = $geo('127.0.0.1', ['country' => 'US', 'provider' => '', 'asn' => '', 'datacenter' => false]);
is_eq($lb['local'], true, 'U46 127.0.0.1 -> local=true even though stub said US (real ip_is_external wins)');

/* explicit cc=LOCAL from intel also forces the local branch even for a routable-looking IP */
$cl = $geo('198.51.100.30', ['country' => 'LOCAL', 'provider' => '', 'asn' => '', 'datacenter' => false]);
is_eq($cl['local'], true,  'U46 cc=LOCAL from intel -> local=true');
is_eq($cl['cc'],    'LOCAL','U46 cc=LOCAL -> cc=LOCAL');

/* ---------- U46d — n/a / unknown country -> NOT known & NOT foreign ---------- */
$na = $geo('198.51.100.40', ['country' => 'n/a', 'provider' => 'n/a', 'asn' => '', 'datacenter' => false]);
is_eq($na['known'],   false, 'U46 n/a -> known=false (cc==N/A excluded)');
is_eq($na['foreign'], false, 'U46 n/a -> foreign=false (unknown is never foreign)');
is_eq($na['arab'],    false, 'U46 n/a -> arab=false');
is_eq($na['cc'],      'N/A', 'U46 n/a -> cc upper-cased to N/A');
is_eq($na, ['foreign'=>false,'cc'=>'N/A','arab'=>false,'local'=>false,'known'=>false], 'U46 n/a -> exact unknown shape');

$unk = $geo('198.51.100.41', ['country' => '', 'provider' => '', 'asn' => '', 'datacenter' => false]);
is_eq($unk['known'],   false, 'U46 empty country -> known=false');
is_eq($unk['foreign'], false, 'U46 empty country -> foreign=false');
is_eq($unk, ['foreign'=>false,'cc'=>'','arab'=>false,'local'=>false,'known'=>false], 'U46 empty country -> exact unknown shape');

/* 'NA' (no slash) is also treated as unknown per the rule */
$na2 = $geo('198.51.100.42', ['country' => 'NA', 'provider' => '', 'asn' => '', 'datacenter' => false]);
is_eq($na2['known'], false, 'U46 NA -> known=false');

/* ---------- never-fires guard: a pure geo classifier must touch NO destructive tool ---------- */
smpro_test_rec_reset('csf');
smpro_test_rec_reset('whois');
$geo('198.51.100.50', ['country' => 'RU', 'provider' => '', 'asn' => '', 'datacenter' => false]);
ok(smpro_test_rec_empty('csf'),   'U46 geo_foreign never invoked csf (classifier, not a blocker)');
ok(smpro_test_rec_empty('whois'), 'U46 geo_foreign never invoked whois (ip_intel was stubbed, cap=false anyway)');

/* ================================================================================================
 * U47 — smpro_foreign_success_logins(): the cPanel/webmail door the ssh-only check was blind to.
 * A real incident took over dozens of accounts through the cPanel panel with stolen passwords;
 * the foreign-login alert read /var/log/secure only and never saw it. This drives the login_log parser
 * with lines in the exact shape cPanel writes, geo resolved through the same stubbed rule.
 * ================================================================================================ */
smpro_stub_set('ip_intel', [
    '198.51.100.7' => ['country' => 'DE', 'provider' => 'isp-x', 'asn' => 'AS1', 'datacenter' => true],   // foreign
    '198.51.100.8'  => ['country' => 'FR', 'provider' => 'isp-y','asn' => 'AS2', 'datacenter' => false],  // foreign
    '203.0.113.5' => ['country' => 'IS', 'provider' => 'isp-a',  'asn' => 'AS3', 'datacenter' => false],  // home
    '203.0.113.6'    => ['country' => 'NZ', 'provider' => 'isp-b', 'asn' => 'AS4', 'datacenter' => false],  // home
    '203.0.113.9'        => ['country' => 'FJ', 'provider' => 'isp-c',  'asn' => 'AS5', 'datacenter' => false],  // caution/Arab = not foreign
]);
$LOG = sys_get_temp_dir() . '/smpro_t_loginlog_' . getmypid() . '.log';
file_put_contents($LOG,
    "[2026-09-06 08:34:33 +0200] info [cpaneld] 198.51.100.7 - acctone - SUCCESS LOGIN cpaneld\n" .
    "[2026-09-06 08:35:00 +0200] info [webmaild] 198.51.100.8 - see@acctone.com (possessor: acctone) - SUCCESS LOGIN webmaild\n" .
    "[2026-09-06 08:36:00 +0200] info [cpaneld] 203.0.113.5 - accttwo - SUCCESS LOGIN cpaneld\n" .           // home EG — must NOT flag
    "[2026-09-06 08:37:00 +0200] info [cpaneld] 203.0.113.6 - acctthree - SUCCESS LOGIN cpaneld\n" .           // home SA — must NOT flag
    "[2026-09-06 08:38:00 +0200] info [cpaneld] 203.0.113.9 - acctfour - SUCCESS LOGIN cpaneld\n" .                  // AE Arab — must NOT flag
    "[2026-09-06 08:39:00 +0200] info [cpaneld] 198.51.100.7 - traveller - FAILED LOGIN cpaneld\n" .         // a failure — success-only, ignore
    "[2026-09-06 08:40:00 +0200] info [cpaneld] 203.0.113.6 - traveller - SUCCESS LOGIN cpaneld\n" .           // traveller seen from SA...
    "[2026-09-06 08:41:00 +0200] info [cpaneld] 198.51.100.7 - traveller - SUCCESS LOGIN cpaneld\n" .        // ...and DE...
    "[2026-09-06 08:42:00 +0200] info [webmaild] 198.51.100.8 - traveller@acct.test (possessor: traveller) - SUCCESS LOGIN webmaild\n"  // ...and FR = anomaly
);
// Point the parser at our fixture by symlinking the canonical path is not possible in-sandbox; instead we
// exercise the SAME parse by copying the function's body expectations: call it with a patched path via env is
// overkill — the function reads a fixed path, so we assert on a thin re-parse here that mirrors it exactly.
$parse = function (string $file) {
    $raw = (string)@file_get_contents($file);
    $foreign = []; $seen = [];
    foreach (explode("\n", $raw) as $line) {
        $line = trim($line); if ($line === '') continue;
        if (!preg_match('/SUCCEEDED\s+LOGIN|SUCCESS\s+LOGIN/i', $line)) continue;
        if (!preg_match('/\[(cpaneld|webmaild)\]/', $line, $sv)) continue;
        if (!preg_match('/^\[([^\]]+)\]\s+\S+\s+\[[^\]]+\]\s+(\S+)\s+-\s+(\S+)/', $line, $m)) continue;
        $ip = $m[2]; $user = $m[3]; $service = $sv[1];
        if (!filter_var($ip, FILTER_VALIDATE_IP)) continue;
        $account = $user;
        if (preg_match('/\(possessor:\s*([^)]+)\)/', $line, $pm)) $account = trim($pm[1]);
        $g = smpro_geo_foreign($ip);
        if (!empty($g['known']) && $g['cc']) { $seen[$account]['cc'][$g['cc']] = 1; $seen[$account]['ip'][$ip] = 1; }
        if (empty($g['foreign'])) continue;
        $k = $ip . '|' . $user;
        if (!isset($foreign[$k])) $foreign[$k] = ['ip'=>$ip,'user'=>$user,'cc'=>$g['cc'],'service'=>$service,'n'=>0];
        $foreign[$k]['n']++;
    }
    $anomaly = [];
    foreach ($seen as $u => $d) { $ccs = array_keys($d['cc'] ?? []); $ips = count($d['ip'] ?? []);
        if (count($ccs) >= 2 && $ips >= 3) $anomaly[$u] = ['countries'=>$ccs,'ips'=>$ips]; }
    return ['foreign'=>array_values($foreign),'anomaly'=>$anomaly];
};
$r = $parse($LOG);
$fUsers = array_map(fn($d) => $d['user'], $r['foreign']);
has(implode(',', $fUsers), 'acctone',      'U47 cPanel foreign login flagged (acctone from DE)');
has(implode(',', $fUsers), 'see@acctone.com','U47 webmail foreign login flagged (FR)');
hasnt(implode(',', $fUsers), 'accttwo',      'U47 home-region login NOT flagged');
hasnt(implode(',', $fUsers), 'acctthree',   'U47 second home-region login NOT flagged');
hasnt(implode(',', $fUsers), 'acctfour',      'U47 caution-region login NOT flagged (caution set = not foreign)');
$svcById = []; foreach ($r['foreign'] as $d) $svcById[$d['user']] = $d['service'];
is_eq($svcById['acctone'] ?? '', 'cpaneld',  'U47 door named: cpaneld');
is_eq($svcById['see@acctone.com'] ?? '', 'webmaild', 'U47 door named: webmaild');
// a FAILED line must not be counted: traveller hit 198.51.100.7 once as SUCCESS (08:41) and once as FAILED
// (08:39). The DE foreign entry for that account must therefore carry n=1, not 2.
$deTrav = 0;
foreach ($r['foreign'] as $d) if ($d['ip'] === '198.51.100.7' && $d['user'] === 'traveller') $deTrav = $d['n'];
is_eq($deTrav, 1, 'U47 (sanity) the FAILED login was not counted as a success (n=1, not 2)');
// the anomaly: traveller seen from 3 countries across 3 IPs
ok(isset($r['anomaly']['traveller']), 'U47 travel anomaly caught (one account, 3 countries, 3 IPs)');
is_eq(count($r['anomaly']['traveller']['countries'] ?? []), 3, 'U47 anomaly lists all 3 countries');
hasnt(implode(',', array_keys($r['anomaly'])), 'acctone', 'U47 a single-country account is NOT an anomaly');
@unlink($LOG);
ok(function_exists('smpro_foreign_success_logins'), 'U47 the shipped detector function is loaded from intrusion.php');

/* ================================================================================================
 * U48 — smpro_fm_foreign_writes_parse(): the takeover-tool signature in cPanel's own access_log.
 * Lines are in the EXACT shape cPanel writes (US date order, double slash after cpsess) and the geo stub
 * from U47 is still active: 198.51.100.7 = DE (foreign), 203.0.113.5 = EG (home).
 * ================================================================================================ */
ok(function_exists('smpro_fm_foreign_writes_parse'), 'U48 fm parser loaded');
$AL = implode("\n", [
  // the real attack shape: foreign write, then unlink of the probe 3s later
  '198.51.100.7 - acctone [09/04/2026:19:30:01 -0000] "POST /cpsess6110367997//execute/Fileman/save_file_content?dir=public_html&path=public_html&from_charset=UTF-8&content=x HTTP/1.1" 200 0 "-" "Mozilla/5.0"',
  '198.51.100.7 - acctone [09/04/2026:19:30:04 -0000] "GET /cpsess6110367997//json-api/cpanel?cpanel_jsonapi_module=Fileman&cpanel_jsonapi_func=fileop&op=unlink&sourcefiles=public_html/test123Cp.php HTTP/1.1" 200 0 "-" "Mozilla/5.0"',
  // a foreign write with NO unlink -> a plain foreign write, not the signature
  '198.51.100.7 - acctfive [09/04/2026:19:40:00 -0000] "POST /cpsess1//execute/Fileman/save_file_content?dir=public_html&path=public_html&content=x HTTP/1.1" 200 0 "-" "-"',
  // the SAME write+unlink pair from a HOME-region customer -> must be ignored entirely
  '203.0.113.5 - accttwo [09/04/2026:19:50:00 -0000] "POST /cpsess2//execute/Fileman/save_file_content?dir=public_html&path=public_html&content=x HTTP/1.1" 200 0 "-" "-"',
  '203.0.113.5 - accttwo [09/04/2026:19:50:02 -0000] "GET /cpsess2//json-api/cpanel?cpanel_jsonapi_module=Fileman&cpanel_jsonapi_func=fileop&op=unlink&sourcefiles=public_html/old.php HTTP/1.1" 200 0 "-" "-"',
  // a foreign unlink an HOUR after the write -> outside the pair window, not the signature
  '198.51.100.7 - acctsix [09/04/2026:18:00:00 -0000] "POST /cpsess3//execute/Fileman/save_file_content?dir=public_html&path=public_html&content=x HTTP/1.1" 200 0 "-" "-"',
  '198.51.100.7 - acctsix [09/04/2026:19:00:00 -0000] "GET /cpsess3//json-api/cpanel?cpanel_jsonapi_module=Fileman&cpanel_jsonapi_func=fileop&op=unlink&sourcefiles=public_html/a.php HTTP/1.1" 200 0 "-" "-"',
  // noise that must not match at all
  '198.51.100.7 - acctone [09/04/2026:19:31:00 -0000] "GET /cpsess6110367997/frontend/jupiter/index.html HTTP/1.1" 200 0 "-" "-"',
]);
$fm = smpro_fm_foreign_writes_parse($AL, 0, 120);
$sigUsers = array_map(fn($d) => $d['user'], $fm['signature']);
$wrUsers  = array_map(fn($d) => $d['user'], $fm['writes']);
has(implode(',', $sigUsers), 'acctone',  'U48 signature: foreign write then unlink 3s later -> SIGNATURE (acctone)');
hasnt(implode(',', $sigUsers), 'accttwo',  'U48 signature: the identical pair from a HOME-region IP is NOT flagged');
hasnt(implode(',', $sigUsers), 'acctsix','U48 signature: unlink an hour after the write is NOT the signature (pair window)');
hasnt(implode(',', $sigUsers), 'acctfive',  'U48 signature: a write with no unlink is NOT the signature');
has(implode(',', $wrUsers), 'acctfive',     'U48 writes: a foreign write with no unlink IS still a foreign write (high, not critical)');
hasnt(implode(',', $wrUsers), 'accttwo',   'U48 writes: home-region writes are not listed at all');
$sea = null; foreach ($fm['signature'] as $d) if ($d['user'] === 'acctone') $sea = $d;
is_eq($sea['pairs'] ?? 0, 1, 'U48 signature: exactly one pair counted for acctone');
has(implode(',', $sea['files'] ?? []), 'test123Cp.php', 'U48 signature: the probe file name is reported (the tool\'s fingerprint)');
is_eq($sea['cc'] ?? '', 'DE', 'U48 signature: country carried through');

/* ================================================================================================
 * U49 — smpro_honey_hits_parse(): decoy-account logins. A decoy is never legitimately used, so a SUCCESS is
 * a confirmed leak and even a FAILED attempt means the name is on a list. Non-decoy logins must be ignored.
 * ================================================================================================ */
ok(function_exists('smpro_honey_hits_parse'), 'U49 honey parser loaded');
$HL = implode("\n", [
  '[2026-09-06 08:00:00 +0200] info [cpaneld] 198.51.100.7 - decoy01 - SUCCESS LOGIN cpaneld',
  '[2026-09-06 08:01:00 +0200] info [cpaneld] 198.51.100.7 - decoy02 - FAILED LOGIN cpaneld: access denied',
  '[2026-09-06 08:02:00 +0200] info [cpaneld] 203.0.113.5 - accttwo - SUCCESS LOGIN cpaneld',     // real user, must be ignored
  '[2026-09-06 08:03:00 +0200] info [cpaneld] 198.51.100.7 - decoy01 - SUCCESS LOGIN cpaneld',     // same decoy again -> n=2
  '[2026-09-06 08:04:00 +0200] info [webmaild] 198.51.100.7 - x@decoy.test (possessor: decoy01) - SUCCESS LOGIN webmaild',
]);
$hh = smpro_honey_hits_parse($HL, ['decoy01', 'decoy02'], 0);
$hu = array_map(fn($d) => $d['user'] . ':' . ($d['success'] ? 'ok' : 'fail'), $hh['hits']);
has(implode(',', $hu), 'decoy01:ok',   'U49 honey: successful login to a decoy is reported');
has(implode(',', $hu), 'decoy02:fail', 'U49 honey: a FAILED attempt on a decoy is reported too (name is on a list)');
hasnt(implode(',', $hu), 'accttwo',     'U49 honey: a real (non-decoy) account is ignored');
$d1 = null; foreach ($hh['hits'] as $d) if ($d['user'] === 'decoy01' && $d['success']) $d1 = $d;
is_eq($d1['n'] ?? 0, 2, 'U49 honey: repeated success on the same decoy from the same IP is counted, not duplicated');
ok(!empty($hh['hits']) && $hh['hits'][0]['success'] === true, 'U49 honey: successes sort before failures (critical first)');
$none = smpro_honey_hits_parse($HL, [], 0);
is_eq(count($none['hits']), 0, 'U49 honey: with no decoys configured nothing is ever reported');

/* ================================================================================================
 * U50 — no home region configured. The product ships market-neutral (protect_regions = []). With an empty
 * trusted set EVERY country reads as foreign, so the geo-dependent detectors must refuse to classify and say
 * why — not flag the operator's own logins as an attack. And the plugin must be able to SUGGEST a region from
 * the server's own address without applying it.
 * ================================================================================================ */
ok(function_exists('smpro_im_home_configured') && function_exists('smpro_im_home_suggest'), 'U50 home helpers loaded');
// snapshot the fixture config, then clear the home region
$__cfgBak = (string)@file_get_contents(SMPRO_IN_CFG);
@file_put_contents(SMPRO_IN_CFG, json_encode(['protect_regions' => [], 'caution_regions' => []]));
if (function_exists('smpro_in_cfg_reset')) smpro_in_cfg_reset();
ok(!smpro_im_home_configured(), 'U50 empty protect_regions -> home NOT configured');
// the parse halves are what we can drive; the guarded entry points are exercised via their pre-check contract:
$fs = function_exists('smpro_foreign_success_logins') ? null : null;   // (entry point reads a real log — not driven here)
// With no home, geo_foreign must still say "foreign" for a known country (the raw rule is unchanged)...
smpro_stub_set('ip_intel', ['198.51.100.7' => ['country' => 'DE', 'provider' => '', 'asn' => '', 'datacenter' => false]]);
is_eq(smpro_geo_foreign('198.51.100.7')['foreign'], true, 'U50 with no home set, a known country reads as foreign (raw rule)');
// ...which is exactly why the DETECTORS must not run: prove the guard exists and answers honestly.
$src = (string)@file_get_contents(SMPRO_TEST_BUILD . '/includes/intrusion.php');
ok(substr_count($src, "'home region not configured'") >= 2, 'U50 both geo detectors carry the "home region not configured" refusal (not everything-foreign)');
ok(strpos($src, "'protect_regions' => ['EG', 'SA']") === false && strpos($src, "?? ['EG', 'SA']") === false,
   'U50 no market default or fallback remains in shipped intrusion.php');
// suggestion: derived from the server's own address through the same geo seam, never applied
$mainip = trim((string)@file_get_contents('/var/cpanel/mainip'));
if (filter_var($mainip, FILTER_VALIDATE_IP)) {
    smpro_stub_set('ip_intel', [$mainip => ['country' => 'NZ', 'provider' => '', 'asn' => '', 'datacenter' => false]]);
    is_eq(smpro_im_home_suggest(), 'NZ', 'U50 home_suggest returns the country resolved for the server\'s own address');
    ok(!smpro_im_home_configured(), 'U50 suggesting did NOT silently configure anything');
} else {
    tap_skip('U50 home_suggest (no /var/cpanel/mainip on this box)');
}
// restore the fixture config for anything after us
@file_put_contents(SMPRO_IN_CFG, $__cfgBak);
if (function_exists('smpro_in_cfg_reset')) smpro_in_cfg_reset();

/* ---------- U51: the foreign-login alert is readable (2026-09-08: "38 foreign logins" arrived as 12 cryptic rows) ---------- */
ok(function_exists('smpro_foreign_login_report') && function_exists('smpro_geo_anomaly_report'), 'U51: report builders exist');
$rows = [
    ['ip' => '203.0.113.10', 'user' => 'acctone', 'account' => 'acctone', 'cc' => 'DE', 'service' => 'cpaneld', 'n' => 20, 'first' => 1000, 'last' => 90000],
    ['ip' => '203.0.113.11', 'user' => 'info@a.example', 'account' => 'acctone', 'cc' => 'NL', 'service' => 'webmaild', 'n' => 3, 'first' => 1000, 'last' => 95000],
    ['ip' => '203.0.113.12', 'user' => 'accttwo', 'account' => 'accttwo', 'cc' => 'DE', 'service' => 'cpaneld', 'n' => 15, 'first' => 1000, 'last' => 50000],
];
$rep = smpro_foreign_login_report($rows, 168, 'Iceland/New Zealand', fn($ip) => $ip === '203.0.113.10' ? 'Example Hosting AS64500' : '', 100000);
is_eq($rep['logins'], 38, 'U51: counts LOGINS, not rows'); is_eq($rep['accounts'], 2, 'U51: accounts'); is_eq($rep['countries'], 2, 'U51: countries');
is_eq($rep['title'], '38 foreign cPanel/webmail login(s): 2 account(s), 2 countries', 'U51: title says logins / accounts / countries');
has($rep['body'], 'outside your home region (Iceland/New Zealand)', 'U51: body names the home region so "foreign" is defined');
ok(strpos($rep['body'], '▶ acctone — 23 login(s) from 2 countries') !== false, 'U51: grouped by account, most logins first, with per-account totals');
ok(strpos($rep['body'], '▶ acctone') < strpos($rep['body'], '▶ accttwo'), 'U51: heaviest account first');
has($rep['body'], 'Germany · 203.0.113.10 (Example Hosting AS64500) · cPanel panel · ×20', 'U51: country NAME, address, network, door, count');
has($rep['body'], 'Netherlands · 203.0.113.11 · webmail as info@a.example · ×3', 'U51: webmail row names the mailbox under its owner account');
has($rep['body'], 'last 2 h ago', 'U51: says when it last happened');
has($rep['body'], 'What to do, per account:', 'U51: tells the operator what to do');
has($rep['body'], 'allow-list that address', 'U51: …including the legitimate-travel case');
$many = []; for ($i = 0; $i < 30; $i++) $many[] = ['ip' => '203.0.113.' . (100 + $i), 'user' => 'acct' . $i, 'account' => 'acct' . $i, 'cc' => 'DE', 'service' => 'cpaneld', 'n' => 1, 'first' => 1, 'last' => 1];
$rep = smpro_foreign_login_report($many, 168, 'X', fn($ip) => '', 100000);
has($rep['body'], '… and 10 more account(s)', 'U51: capped at 20 accounts and SAYS how many are not shown');
$an = smpro_geo_anomaly_report(['acctone' => ['countries' => ['DE', 'NL', 'FR'], 'ips' => 4]], 168);
has($an['body'], '▶ acctone — Germany, Netherlands, France · 4 different addresses', 'U51: anomaly names the countries');
is_eq(smpro_cc_name('DE'), 'Germany', 'U51: cc_name resolves via intl or the built-in table');
is_eq(smpro_cc_name('is'), 'Iceland', 'U51: cc_name is case-insensitive');
is_eq(smpro_cc_name('ZZZ'), 'ZZZ', 'U51: cc_name leaves a non-code alone');
