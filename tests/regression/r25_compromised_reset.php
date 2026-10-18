<?php
require __DIR__ . '/../support/bootstrap.php';
/**
 * r25_compromised_reset.php — the bulk password reset must be able to find a compromised account, the break-in
 * statement must stay on its own tab, and neither screen may grow a second copy of a handler.
 *
 * Three separate failures are pinned here, all seen for real:
 *
 *  1. The reset offered ZERO accounts during a live incident. Its only source asked "did anyone sign in from a
 *     country outside the list?", which is silent until a country list exists and blind to the ordinary case —
 *     the correct password used from an ordinary country, which is what a stolen password looks like. Malware
 *     inside the account is now a source too.
 *
 *  2. The button was DISABLED without a country list, so the one screen that could act on an incident could not
 *     be pressed at all.
 *
 *  3. Patching the page by text splice duplicated a whole <script> block, binding two click handlers to the
 *     reset button. One press would have reset every ticked password twice — the second pass invalidating the
 *     export from the first, handing the operator a file of passwords that no longer work.
 */

$fw = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/firewall-status.php'));
$aa = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/account-audit.php'));
$gr = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/georeport.php'));

/* ---------- R1: evidence beyond the one blind source ---------- */
has($gr, 'function smpro_gr_compromised', 'R1: there is a compromised-accounts source');
has($gr, 'function smpro_gr_malware_accounts', 'R1: malware inside the account is one of its inputs');
has($fw, 'smpro_gr_compromised(', 'R1: the reset endpoint actually calls it');
has($gr, 'not "clean"', 'R1: a source that cannot run says so rather than reporting zero');
has($gr, '$out[\'state\'] = \'absent\';', 'R1: "no scanner installed" is its own state, not an empty result');

require_once SMPRO_BASE . '/includes/georeport.php';
ok(function_exists('smpro_gr_compromised'), 'R1: the function loads');
$c = smpro_gr_malware_accounts(30);
ok(is_array($c) && array_key_exists('ok', $c) && array_key_exists('accounts', $c), 'R1: it returns the three-state shape');
ok($c['ok'] === false || is_array($c['accounts']), 'R1: either it could look, or it says it could not');
if ($c['ok'] === false) isnt_eq(trim((string)$c["msg"]), "", 'R1: and when it could not look it explains why');

/* ---------- R2: the operator can press the button ---------- */
hasnt($fw, "id=\"grScan\" type=\"button\"<?= \$grReady ? '' : ' disabled",
      'R2: the report button is no longer disabled when no country list is set');
has($fw, 'Malware evidence does not need a country list', 'R2: and the page says why it still works');

/* ---------- R3: exactly one of each handler, on both screens ---------- */
foreach ([
    "document.getElementById('grOut')" => 'the report renderer',
    "document.getElementById('grScan')" => 'the scan button binding',
    'function doReset'                  => 'the reset function',
    "document.getElementById('glOut')"  => 'the country-lock renderer',
] as $needle => $what) {
    is_eq(substr_count($fw, $needle), 1, 'R3: exactly one ' . $what . ' — a second one resets every password twice');
}
is_eq(substr_count($fw, '/* Foreign sign-in report + bulk password reset.'), 1,
      'R3: the reset script block appears once');

/* ---------- R4: the break-in statement lives on its own tab ---------- */
has($aa, "!empty(\$aaBrute) && \$aaTab === 'audit'",
    'R4: the break-in banner is scoped to one tab instead of every tab');
has($aa, "tab=bruteforce", 'R4: the dedicated tab still exists to send people to');

/* ---------- R5: one reset, linked to — not a second implementation ---------- */
has($aa, 'page=firewall-status#gr', 'R5: Account Audit links to the one reset');
is_eq(substr_count($aa, 'smpro_gr_reset_bulk'), 0, 'R5: and does not carry its own copy of it');
has($fw, 'id="gr"', 'R5: the link has something to land on');
