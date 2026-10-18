<?php
/**
 * r19_breakin_report.php — the brute-force networks live on a report page with a decision per network.
 *
 * 2026-09-08: the Account Audit results page opened with a wall of "Block all N" cards (394 addresses, 113
 * networks) above the events the operator searched for. Now: a one-line alert with a link, and a Break-in Report
 * tab that lists every network (residential/business vs cloud/hosting, allow-listed addresses left out) with
 * Block all / Allow-list / Ignore per network. Ignore is reversible and visible ("Ignored networks").
 *
 *   B1 ignore store: add / list / remove; keys are sanitised
 *   B2 the results page shows the compact alert + link and no longer the inline Block-all cards
 *   B3 the report tab exists, is dispatched, and offers the three decisions
 *   B4 the handlers are CSRF + root gated; allow-list goes through smpro_csf_allow_add
 *   B5 "Arab" wording is gone from the page (the rule is the configured home region)
 */
require __DIR__ . '/../support/bootstrap.php';
require SMPRO_BASE . '/tests/support/plugin_funcs.php';
smpro_plugin_funcs('includes/helpers.php');
// The collector, the grouping and the verdict moved to includes/breakin.php so they could be reached from
// cron - a page module executes a router at include time and can never be required outside a browser.
// Both are loaded here: the page still owns the rendering, breakin.php now owns the judgement.
smpro_plugin_funcs('includes/breakin.php');
smpro_plugin_funcs('modules/account-audit.php');

ok(function_exists('smpro_aa_bf_ign_add') && function_exists('smpro_aa_bf_render'), 'B0: report functions loaded router-free');
@unlink(SMPRO_AA_BFIGN);
ok(smpro_aa_bf_ign_add('AS64500', 'Example Cloud', 'root'), 'B1: ignore a network');
ok(smpro_aa_bf_ign_add('cc:ZZ', 'unidentified', 'root'), 'B1: ignore a country-keyed group');
ok(!smpro_aa_bf_ign_add('', 'x', 'root'), 'B1: empty key refused');
$all = smpro_aa_bf_ign_all();
is_eq(array_keys($all), ['AS64500', 'cc:ZZ'], 'B1: both stored');
is_eq($all['AS64500']['label'], 'Example Cloud', 'B1: label kept'); is_eq($all['AS64500']['by'], 'root', 'B1: actor kept');
ok(smpro_aa_bf_ign_add('AS1; rm -rf /', 'x', 'root'), 'B1: a hostile key is accepted only after sanitising');
ok(isset(smpro_aa_bf_ign_all()['AS1rm-rf']), 'B1: ...stored sanitised');
smpro_aa_bf_ign_remove('AS64500'); ok(!isset(smpro_aa_bf_ign_all()['AS64500']), 'B1: remove works');
is_eq(smpro_aa_bf_key(['asn' => 'AS1', 'cc' => 'DE']), 'AS1', 'B1: key is the ASN when known');
is_eq(smpro_aa_bf_key(['asn' => '', 'cc' => 'DE']), 'cc:DE', 'B1: ...else the country');
@unlink(SMPRO_AA_BFIGN);

$src = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/account-audit.php'));   // the module is CRLF on disk
has($src, 'Open the break-in report &rarr;', 'B2: results page carries the alert link');
is_eq(substr_count($src, 'class="tp-btn danger aaBlockNet"'), 1, 'B2: the Block-all card renders only inside the report (not on the results page)');
has($src, "'bruteforce', 'overview'", 'B3: tab registered');
has($src, "if (\$aaTab === 'bruteforce'): smpro_aa_bf_render(", 'B3: tab dispatched to the renderer');
foreach (['aaBfAllow', 'aaBfIgnore', 'aaBfUnignore'] as $b) has($src, 'class="tp-btn ' . ($b === 'aaBfAllow' ? 'aaBfAllow' : $b) . '"', "B3: $b button");
has($src, 'Ignored networks', 'B3: ignored section is visible, so the decision is reversible');
has($src, "in_array((string)(\$_POST['aa_action'] ?? ''), ['bf_allow', 'bf_ignore', 'bf_unignore'], true)) {\n    smpro_require_valid_csrf('aa_delete'); smpro_require_root();", 'B4: handlers gated');
has($src, "smpro_csf_allow_add(\$one, 'Account Audit allow-list by ' . \$by)", 'B4: allow-list uses the shared csf.allow helper');
has($src, "if (\$aaTab === 'audit' || \$aaTab === 'bruteforce') {", 'B4: the report computes from the same collection as the audit');
has($src, "=== 'search' && \$aaTab === 'audit') {", 'B4: opening the report never saves a report');
ok(!preg_match('/Arab/', preg_replace('/\/\/.*$/m', '', preg_replace('#/\*.*?\*/#s', '', $src))), 'B5: no "Arab" wording in code or markup');
has($src, 'array $trusted, string $back, $totalIps', 'B6: the back link is a string (beta184 declared it array and the tab died with a TypeError)');

/* ---------- B7: the "addresses tried to break in" figure (independent review, 2026-09-09) ---------- */
// $aaBrute keeps every address, including those in networks the operator later chose to ignore; the ignored
// networks are only removed from $aaNets. Adding their address count to count($aaBrute) counted them twice, so
// ignoring a network INFLATED the headline figure — the opposite of what the operator just asked for.
has($src, "array_sum(array_map(fn(\$n) => count(\$n['ips']), (\$aaNets ?? []) + (\$aaNetsIgnored ?? [])))", 'B7: addresses are the same disjoint sum as attempts');
hasnt($src, "count(\$aaBrute ?? []) + array_sum(", 'B7: the double-counting form is gone');
