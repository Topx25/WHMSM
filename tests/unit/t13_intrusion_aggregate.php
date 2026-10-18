<?php
require __DIR__ . '/../support/bootstrap.php';
/**
 * t13_intrusion_aggregate.php — array-aggregation helpers in includes/intrusion.php
 *   U36 smpro_im_by_domain        — group events by domain: total / uniq_ips / cats / sev label / sort desc
 *   U37 smpro_im_attack_analysis  — paths / attackers / campaigns(/24>=3) / rotators(ua>=4) / phases
 *   U38 smpro_im_campaigns        — distributed (IP -> >=thr_ip_domains domains) vs targeted (domain -> >=5 IPs)
 *
 * intrusion.php loads standalone (only function/const defs after the SMPRO_BOOT guard).
 * These targets are pure array->array transforms. They read /etc/userdomains via
 * smpro_im_account_for() (-> '' on the test box) and smpro_in_cfg() (sandbox defaults),
 * which are deterministic here. No exec/network/CSF on the tested paths.
 *
 * NOTE on fixtures: smpro_im_by_domain reads $e['domain'|'ip'|'kind'|'severity'|'ts']
 * WITHOUT ?? guards, so every fixture row must define all five keys (else PHP notices).
 * smpro_im_campaigns reads $e['ip'|'domain']; smpro_im_attack_analysis guards with ??.
 */
require SMPRO_BASE . '/includes/intrusion.php';

/* row builder guaranteeing all keys by_domain/campaigns read directly (no notices) */
function t13_row($a = []) {
    return $a + ['ts'=>0,'ip'=>'','domain'=>'','method'=>'','uri'=>'','code'=>'',
                 'rule'=>'','msg'=>'','tag'=>'','severity'=>'','kind'=>'','ua'=>''];
}

/* ===================== U36 smpro_im_by_domain ===================== */
$ev = [
    t13_row(['domain'=>'a.com','ip'=>'1.1.1.1','kind'=>'XSS','severity'=>'warning','ts'=>100]),
    t13_row(['domain'=>'a.com','ip'=>'1.1.1.1','kind'=>'XSS','severity'=>'critical','ts'=>200]),
    t13_row(['domain'=>'a.com','ip'=>'2.2.2.2','kind'=>'SQL Injection','severity'=>'error','ts'=>50]),
    t13_row(['domain'=>'b.com','ip'=>'3.3.3.3','kind'=>'Scanner / Recon','severity'=>'info','ts'=>300]),
    t13_row(['domain'=>'',     'ip'=>'',       'kind'=>'XSS','severity'=>'notice','ts'=>0]),
];
$by = smpro_im_by_domain($ev);

// keys + sort order: total desc; ties keep insertion order (uasort stable in PHP8)
is_eq(array_keys($by), ['a.com','b.com','(no host)'],
      'by_domain: keyed by domain, sorted total desc (a.com 3 > b.com 1 = (no host) 1, stable)');

// --- a.com group ---
$g = $by['a.com'];
is_eq($g['domain'], 'a.com',           'by_domain a.com: domain field');
is_eq($g['account'], '',               'by_domain a.com: account empty (no /etc/userdomains on test box)');
is_eq($g['total'], 3,                  'by_domain a.com: total counts every event');
is_eq($g['uniq_ips'], 2,              'by_domain a.com: uniq_ips = distinct non-empty IPs');
is_eq($g['ips'], ['1.1.1.1'=>2,'2.2.2.2'=>1], 'by_domain a.com: ips per-IP counts arsorted desc');
is_eq($g['cats'], ['XSS'=>2,'SQL Injection'=>1], 'by_domain a.com: cats per-kind counts arsorted desc');
is_eq($g['top_cat'], 'XSS',            'by_domain a.com: top_cat = most frequent kind');
is_eq($g['sev'], 5,                    'by_domain a.com: sev = MAX severity rank (critical=5)');
is_eq($g['sevlabel'], 'critical',     'by_domain a.com: sevlabel = label of the max-rank event');
is_eq($g['first'], 50,                 'by_domain a.com: first = min ts');
is_eq($g['last'], 200,                 'by_domain a.com: last = max ts');

// --- b.com group ---
$b = $by['b.com'];
is_eq($b['total'], 1,                  'by_domain b.com: total 1');
is_eq($b['uniq_ips'], 1,               'by_domain b.com: uniq_ips 1');
is_eq($b['top_cat'], 'Scanner / Recon','by_domain b.com: top_cat');
is_eq($b['sev'], 1,                    'by_domain b.com: sev info=1');
is_eq($b['sevlabel'], 'info',          'by_domain b.com: sevlabel info');
is_eq($b['first'], 300,                'by_domain b.com: first==last single ts');
is_eq($b['last'], 300,                 'by_domain b.com: last single ts');

// --- empty-host group: placeholder + empty-ip handling + ts=0 -> first reset to 0 ---
$nh = $by['(no host)'];
is_eq($nh['domain'], '(no host)',      'by_domain: empty domain -> "(no host)" placeholder');
is_eq($nh['total'], 1,                 'by_domain (no host): total 1');
is_eq($nh['ips'], [],                  'by_domain (no host): empty IP not recorded');
is_eq($nh['uniq_ips'], 0,              'by_domain (no host): uniq_ips 0 (security: blank IP not counted)');
is_eq($nh['sev'], 2,                   'by_domain (no host): notice rank 2');
is_eq($nh['first'], 0,                 'by_domain (no host): ts=0 -> first stays PHP_INT_MAX then reset to 0');
is_eq($nh['last'], 0,                  'by_domain (no host): last 0');

// empty input -> empty array
is_eq(smpro_im_by_domain([]), [],      'by_domain: empty events -> []');

// two empty-domain rows collapse into one "(no host)" bucket
$by2 = smpro_im_by_domain([
    t13_row(['domain'=>'','ip'=>'9.9.9.9','kind'=>'XSS','severity'=>'info','ts'=>1]),
    t13_row(['domain'=>'','ip'=>'9.9.9.9','kind'=>'XSS','severity'=>'info','ts'=>2]),
]);
is_eq(array_keys($by2), ['(no host)'],         'by_domain: multiple empty-host rows share one bucket');
is_eq($by2['(no host)']['total'], 2,           'by_domain: empty-host bucket aggregates total');
is_eq($by2['(no host)']['uniq_ips'], 1,        'by_domain: empty-host bucket uniq_ips');

/* ===================== U38 smpro_im_campaigns ===================== */
// distributed: IP hitting >= thr_ip_domains (default 12) distinct domains.
// targeted: domain hit by >= 5 distinct IPs (hardcoded 5).
// Build a distributed scanner spanning 12 domains + a targeted domain with 5 IPs.
$cev = [];
for ($i = 0; $i < 12; $i++) {                                   // scanner 7.7.7.7 over 12 domains
    $cev[] = t13_row(['ip'=>'7.7.7.7','domain'=>'d'.$i.'.com','kind'=>'Scanner / Recon']);
}
for ($i = 0; $i < 5; $i++) {                                    // 5 distinct IPs all hit victim.com
    $cev[] = t13_row(['ip'=>'8.8.8.'.$i,'domain'=>'victim.com','kind'=>'SQL Injection']);
}
$cev[] = t13_row(['ip'=>'','domain'=>'skip.com','kind'=>'XSS']); // empty IP -> skipped entirely
$camp = smpro_im_campaigns($cev);

is_eq(array_keys($camp), ['distributed','targeted'], 'campaigns: returns distributed + targeted keys');
is_eq(count($camp['distributed']), 1,        'campaigns: one distributed offender (>=12 domains)');
is_eq($camp['distributed'][0]['ip'], '7.7.7.7','campaigns: distributed offender IP');
is_eq($camp['distributed'][0]['domains'], 12, 'campaigns: distributed domain count');
is_eq($camp['distributed'][0]['hits'], 12,    'campaigns: distributed total hits');
is_eq(count($camp['targeted']), 1,            'campaigns: one targeted domain (>=5 IPs)');
is_eq($camp['targeted'][0]['domain'], 'victim.com','campaigns: targeted domain');
is_eq($camp['targeted'][0]['ips'], 5,         'campaigns: targeted distinct-IP count');

// boundary: IP at 11 domains is BELOW default thr 12 -> not distributed; domain at 4 IPs below 5 -> not targeted
$cev2 = [];
for ($i = 0; $i < 11; $i++) $cev2[] = t13_row(['ip'=>'6.6.6.6','domain'=>'e'.$i.'.com','kind'=>'XSS']);
for ($i = 0; $i < 4; $i++)  $cev2[] = t13_row(['ip'=>'5.5.5.'.$i,'domain'=>'near.com','kind'=>'XSS']);
$camp2 = smpro_im_campaigns($cev2);
is_eq($camp2['distributed'], [], 'campaigns: 11 domains < thr 12 -> not distributed (boundary)');
is_eq($camp2['targeted'], [],    'campaigns: 4 IPs < 5 -> not targeted (boundary)');

// empty input
$campE = smpro_im_campaigns([]);
is_eq($campE['distributed'], [], 'campaigns: empty -> no distributed');
is_eq($campE['targeted'], [],    'campaigns: empty -> no targeted');

/* ===================== U37 smpro_im_attack_analysis ===================== */
// Build: one /24 botnet (3 distinct IPs -> campaign), one UA-rotator (4 UAs -> rotator),
// plus phase-classification coverage.
$aev = [
    // /24 botnet: 1.2.3.{10,11,12} share 1.2.3.0/24 (>=3 -> campaign)
    t13_row(['ip'=>'1.2.3.10','domain'=>'x.com','uri'=>'/a','kind'=>'XSS','method'=>'GET','code'=>'403']),
    t13_row(['ip'=>'1.2.3.11','domain'=>'x.com','uri'=>'/a','kind'=>'XSS','method'=>'GET','code'=>'403']),
    t13_row(['ip'=>'1.2.3.12','domain'=>'x.com','uri'=>'/a','kind'=>'XSS','method'=>'GET','code'=>'403']),
    // UA-rotator: one IP cycling 4 distinct User-Agents (>=4 -> rotator)
    t13_row(['ip'=>'9.0.0.1','uri'=>'/b','kind'=>'XSS','ua'=>'UA1']),
    t13_row(['ip'=>'9.0.0.1','uri'=>'/b','kind'=>'XSS','ua'=>'UA2']),
    t13_row(['ip'=>'9.0.0.1','uri'=>'/b','kind'=>'XSS','ua'=>'UA3']),
    t13_row(['ip'=>'9.0.0.1','uri'=>'/b','kind'=>'XSS','ua'=>'UA4']),
    // phase rows use DISTINCT /24s (one IP each) so they never form a second campaign
    // phase: xmlrpc -> Remote exploit
    t13_row(['ip'=>'10.1.0.1','uri'=>'/xmlrpc.php','kind'=>'WAF Block (other)']),
    // phase: wp-login -> Brute force
    t13_row(['ip'=>'10.2.0.1','uri'=>'/wp-login.php','kind'=>'WAF Block (other)']),
    // phase: exploit kind -> Exploit (SQLi/RCE/LFI)
    t13_row(['ip'=>'10.3.0.1','uri'=>'/q','kind'=>'SQL Injection']),
    // phase: Spam / content (POST 2xx) — method POST + 2xx code, no other category match
    t13_row(['ip'=>'10.4.0.1','uri'=>'/post','kind'=>'WAF Block (other)','method'=>'POST','code'=>'200']),
    // phase: Other WAF blocks — nothing matches
    t13_row(['ip'=>'10.5.0.1','uri'=>'/misc','kind'=>'WAF Block (other)','method'=>'GET','code'=>'403']),
];
$an = smpro_im_attack_analysis($aev);

is_eq($an['total'], 12,                'attack_analysis: total = event count');

// campaign: the 1.2.3.0/24 subnet with 3 unique IPs
is_eq(count($an['campaigns']), 1,      'attack_analysis: one /24 campaign (>=3 IPs)');
is_eq($an['campaigns'][0]['subnet'], '1.2.3.0/24', 'attack_analysis: campaign subnet label');
is_eq($an['campaigns'][0]['uniq_ips'], 3,          'attack_analysis: campaign uniq_ips');
is_eq($an['campaigns'][0]['n'], 3,                 'attack_analysis: campaign total hits');

// rotator: 9.0.0.1 with 4 distinct UAs
is_eq(count($an['rotators']), 1,       'attack_analysis: one UA-rotator (>=4 UAs)');
is_eq($an['rotators'][0]['ip'], '9.0.0.1',   'attack_analysis: rotator IP');
is_eq($an['rotators'][0]['ua_count'], 4,     'attack_analysis: rotator distinct-UA count');
is_eq($an['rotators'][0]['top_path'], '/b',  'attack_analysis: rotator top_path');
// internal sets are stripped from output
ok(!isset($an['rotators'][0]['uas']),  'attack_analysis: raw "uas" set removed from attacker output');

// top path: /b has n=4 (rotator), /a has n=3 (botnet) -> /b ranks first
is_eq($an['paths'][0]['path'], '/b',   'attack_analysis: most-hit path first (/b n=4)');
is_eq($an['paths'][0]['n'], 4,         'attack_analysis: top path hit count');
is_eq($an['paths'][0]['uniq_ips'], 1,  'attack_analysis: /b hit by single IP -> uniq_ips 1');
ok(!isset($an['paths'][0]['ips']),     'attack_analysis: raw path "ips" set removed from output');

// /a aggregated across the 3 botnet IPs
$paA = null; foreach ($an['paths'] as $p) if ($p['path'] === '/a') { $paA = $p; break; }
ok($paA !== null,                      'attack_analysis: /a path present');
is_eq($paA['n'], 3,                    'attack_analysis: /a hit count 3');
is_eq($paA['uniq_ips'], 3,             'attack_analysis: /a uniq_ips = 3 distinct botnet IPs');

// attackers: top attacker is 9.0.0.1 (n=4)
is_eq($an['attackers'][0]['ip'], '9.0.0.1', 'attack_analysis: top attacker by hits');
is_eq($an['attackers'][0]['n'], 4,          'attack_analysis: top attacker hit count');

// phases: array_filter drops zero buckets; verify each non-zero phase counted once
is_eq($an['phases']['Remote exploit (xmlrpc/RPC)'], 1, 'attack_analysis phase: xmlrpc -> remote exploit');
is_eq($an['phases']['Brute force (login)'], 1,         'attack_analysis phase: wp-login -> brute force');
is_eq($an['phases']['Exploit (SQLi/RCE/LFI)'], 1,      'attack_analysis phase: SQLi kind -> exploit');
is_eq($an['phases']['Spam / content (POST 2xx)'], 1,   'attack_analysis phase: POST 2xx -> spam/content');
// Other WAF blocks: the 3 botnet XSS GET/403 + rotator 4 XSS + the /misc row = 8 land in "Other".
// (XSS is NOT an exploit_kind, no path/kind triggers an earlier branch, GET so not spam.)
is_eq($an['phases']['Other WAF blocks'], 8,            'attack_analysis phase: non-matching events -> Other (8)');
// Sensitive / Scanner phases never triggered -> array_filter removed them
ok(!isset($an['phases']['Sensitive-file probing']),   'attack_analysis: zero phase pruned by array_filter (Sensitive)');
ok(!isset($an['phases']['Scanner / recon']),          'attack_analysis: zero phase pruned by array_filter (Scanner)');

// empty input -> total 0, empty collections, phases fully pruned to []
$anE = smpro_im_attack_analysis([]);
is_eq($anE['total'], 0,           'attack_analysis: empty -> total 0');
is_eq($anE['paths'], [],          'attack_analysis: empty -> no paths');
is_eq($anE['attackers'], [],      'attack_analysis: empty -> no attackers');
is_eq($anE['campaigns'], [],      'attack_analysis: empty -> no campaigns');
is_eq($anE['rotators'], [],       'attack_analysis: empty -> no rotators');
is_eq($anE['phases'], [],         'attack_analysis: empty -> phases all-zero pruned to []');

/* ---- intentionally NOT tested here (need stubs / side effects; Phase 3) ---- */
tap_skip('smpro_im_breaches — needs stub (Phase 3)', 'shells out: find/grep docroots + smpro_im_account_for mapping');
tap_skip('smpro_im_offenders — needs stub (Phase 3)', 'calls smpro_ip_intel / smpro_ip_is_datacenter for geo enrichment');
