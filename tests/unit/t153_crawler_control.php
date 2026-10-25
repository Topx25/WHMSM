<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
if (!defined('SMPRO_VARLIB')) define('SMPRO_VARLIB', sys_get_temp_dir() . '/t153_varlib_' . getmypid());
require_once SMPRO_BASE . '/includes/botguard.php';
require_once SMPRO_BASE . '/includes/crawlers.php';
/** t153 - beta378: Crawler Control - every family listed with honest counts, one switch per family, search engines
 *  protected, the Apache rule rendered from the catalogue patterns, the worker counting from byte cursors. */
$cr = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/crawlers.php'));
$pg = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/bot-guard.php'));
$ix = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/index.php'));
$cs = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/bin/cron_sync.php'));

// A. the catalogue as categories
$F = smpro_cr_families();
ok(count($F) >= 40, 'A1: every catalogue family is listed (' . count($F) . ')');
is_eq($F['openai']['category'], 'ai_crawler', 'A2: GPTBot is an AI crawler');
is_eq($F['googlebot']['category'], 'search', 'A3: Googlebot is a search engine');
is_eq($F['facebook']['category'], 'social', 'A4: Meta preview is social');
is_eq($F['bytedance']['vendor'], 'ByteDance', 'A5: the vendor is named');
ok(smpro_cr_protected('googlebot') && !smpro_cr_protected('openai'), 'A6: only search engines are protected');

// B. counting: synthetic lines into hourly buckets, summed by window
$line = fn($ua, $st, $b, $t) => '1.2.3.4 - - [' . gmdate('d/M/Y:H:i:s', $t) . ' +0000] "GET /x HTTP/1.1" ' . $st . ' ' . $b . ' "-" "' . $ua . '"';
$B = []; $memo = []; $now = time();
foreach ([['Mozilla/5.0 (compatible; GPTBot/1.0)', 200, 5000, $now - 60], ['Mozilla/5.0 (compatible; GPTBot/1.0)', 403, 300, $now - 120], ['Mozilla/5.0 (compatible; Googlebot/2.1)', 200, 800, $now - 200], ['Mozilla/5.0 Chrome/120', 200, 100, $now - 10]] as $x) {
    $r = smpro_cr_parse($line($x[0], $x[1], $x[2], $x[3])); ok($r !== null, 'B0: a combined log line parses');
    $fam = smpro_cr_family_of($r['ua'], $memo); if ($fam !== '') smpro_cr_bucket($B, $fam, 'shop.example', $r);
}
smpro_cr_bucket_merge($B);
$S = smpro_cr_stats('24h');
is_eq([$S['openai']['hits'], $S['openai']['bytes'], $S['openai']['served'], $S['openai']['refused']], [2, 5300, 1, 1], 'B1: GPTBot: 2 requests, 5300 bytes, 1 served, 1 refused');
is_eq($S['googlebot']['hits'], 1, 'B2: Googlebot: 1');
ok(!isset($S['']), 'B3: a browser is not a family and is not counted');
is_eq($S['openai']['domain_count'], 1, 'B4: the sites touched are counted');
$rows = smpro_cr_rows('7d');
ok(isset($rows['anthropic']) && $rows['anthropic']['hits'] === 0, 'B5: a family that was not seen is still listed, with zeros');
is_eq(array_key_first($rows), 'openai', 'B6: rows are sorted by requests');

// C. policy + the Apache rule (no Apache in a test: apply says so and the policy still records the decision)
$r = smpro_cr_set('googlebot', true, 'test');
ok(!$r['ok'] && !empty($r['needs_confirm']), 'C1: a search engine is refused without the second confirmation');
$r = smpro_cr_set('openai', true, 'test');
ok($r['ok'], 'C2: an AI crawler is refused at once (' . $r['msg'] . ')');
ok(in_array('openai', smpro_cr_blocked(), true), 'C3: ...and recorded');
$conf = smpro_cr_render(['openai', 'bytedance'], smpro_cr_families());
has($conf, '<If "%{HTTP_USER_AGENT} =~ m#', 'C4: the rule tests the User-Agent');
has($conf, 'Require all denied', 'C5: ...and denies');
has($conf, 'GPTBot|ChatGPT-User|OAI-SearchBot', 'C6: the catalogue pattern, not a guess');
has($conf, '# Families: openai, bytedance', 'C7: the file names what it refuses (read back as the live state)');
is_eq(smpro_cr_render([], smpro_cr_families()), "# Safety Monitor Pro - Crawler Control: crawler families the operator refused on every site of this server.\n# Generated; do not edit. Change it on the Bot Guard page (Crawlers). Removed when nothing is refused.\n# (nothing refused)\n", 'C8: nothing refused = no rule');
$r = smpro_cr_set_category('ai_crawler', true, 'test');
ok($r['ok'] && count(array_intersect(['openai', 'anthropic', 'bytedance', 'commoncrawl'], smpro_cr_blocked())) === 4, 'C9: the category switch refuses every AI crawler');
$r = smpro_cr_set_category('search', true, 'test');
ok(!in_array('googlebot', smpro_cr_blocked(), true), 'C10: ...and never a search engine');
smpro_cr_set_category('ai_crawler', false, 'test');
is_eq(array_values(array_intersect(['openai', 'anthropic'], smpro_cr_blocked())), [], 'C11: allowed again');
has($cr, "if (\$prev === null) @unlink(SMPRO_CR_HTTPD); else @file_put_contents(SMPRO_CR_HTTPD, \$prev, LOCK_EX);", 'C12: a refused configtest leaves Apache as it was');
has($cr, "if (!\$a['ok']) {", 'C13: a rule that did not go live is not claimed by the policy');

// D. the worker and its cursors
has($cr, "\$off = (\$c && (int)\$c[0] === \$ino && (int)\$c[1] <= \$size) ? (int)\$c[1] : 0;", 'D1: a rotated or truncated log starts over');
has($cr, "if (\$c === null) \$off = max(0, \$size - 2 * 1024 * 1024);", 'D2: a file never seen starts from its last 2 MB, not its history');
has($cr, "\$res['unreadable']++;", 'D4: an unopenable log is counted as not seen');
has($cr, "'*/10 * * * * root '", 'D5: every ten minutes');
has($ix, "require __DIR__ . '/includes/crawlers.php';", 'D6: loaded by the plugin');
has($cs, "'crawler control'    => 'smpro_cr_cron_sync',", 'D7: cron sync keeps the tick');

// E. the page
has($pg, "elseif (\$act === 'cr_set')", 'E1: the switch action');
has($pg, "elseif (\$act === 'cr_category')", 'E2: the category action');
has($pg, 'id="bg-crawlers"', 'E3: the card');
has($pg, 'Refuse all AI crawlers', 'E4: the one-press AI switch');
has($pg, "is a SEARCH ENGINE. Refusing it removes your customers", 'E5: the second confirmation for a search engine');
has($pg, 'data-go="bg-crawlers"', 'E6: in the navigator');
