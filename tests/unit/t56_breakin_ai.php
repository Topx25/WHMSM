<?php
/**
 * t56_breakin_ai.php — the AI second opinion on the Break-in Report.
 *
 * Two promises this file exists to keep:
 *   1. Nothing identifying leaves the server. The AI is asked to judge a SHAPE — counts, a provider name, a country
 *      code, a time span. No IP address, no account name, no log line is ever in the payload, so there is nothing
 *      to redact and nothing to leak to a third-party endpoint.
 *   2. It recommends, it never acts. No block, allow-list or ignore can originate from an AI answer, and an answer
 *      that is short, malformed or hostile degrades to the verdict the rules already produced.
 */
require __DIR__ . '/../support/bootstrap.php';
require SMPRO_BASE . '/tests/support/plugin_funcs.php';
smpro_plugin_funcs('includes/helpers.php');
// The collector, the grouping and the verdict moved to includes/breakin.php so they could be reached from
// cron - a page module executes a router at include time and can never be required outside a browser.
// Both are loaded here: the page still owns the rendering, breakin.php now owns the judgement.
smpro_plugin_funcs('includes/breakin.php');
smpro_plugin_funcs('modules/account-audit.php');

ok(function_exists('smpro_aa_bf_facts'), 'A0: the facts extractor exists');
ok(function_exists('smpro_aa_bf_ai_review'), 'A0: the review exists');

/* ---------- A1: what goes out is numbers, not people ---------- */
$nv = [
    'provider' => 'Example Telecom', 'asn' => 'AS64500', 'cc' => 'DE', 'bot' => false,
    'ips'   => [['ip' => '203.0.113.9', 'n' => 40, 'user' => 'admin'], ['ip' => '203.0.113.10', 'n' => 12, 'user' => 'info']],
    'fails' => 52, 'users' => ['admin' => 40, 'info' => 12], 'services' => ['cpaneld' => 1],
    'first' => 1000, 'last' => 1000 + 3600,
];
$f = smpro_aa_bf_facts($nv);
$blob = json_encode($f);
foreach (['203.0.113.9', '203.0.113.10', 'admin', 'info'] as $secret)
    ok(strpos($blob, $secret) === false, 'A1: "' . $secret . '" is NOT in what would be sent to the AI');
is_eq($f['addresses'], 2, 'A1: the count of addresses goes, the addresses do not');
is_eq($f['accounts'], 2, 'A1: the count of accounts goes, the names do not');
is_eq($f['attempts'], 52, 'A1: attempts');
is_eq($f['span_min'], 60, 'A1: the span in minutes');
is_eq($f['key'], 'AS64500', 'A1: keyed by the network, the same key the card and the ignore list use');
is_eq($f['rules_say'], smpro_aa_bf_assess($nv)['verdict'], 'A1: the rules verdict travels too, so the AI can be seen to disagree');

/* ---------- A2: anything coming back from the page is normalised before it reaches a prompt ---------- */
$c = smpro_aa_bf_facts_clean(['key' => "AS64500\n; rm -rf /", 'provider' => str_repeat('x', 400),
    'country' => '<script>', 'addresses' => '9e9', 'attempts' => -5, 'accounts' => 'abc',
    'services' => ['cpaneld', '$(id)', 'a', 'b', 'c', 'd', 'e', 'f'], 'span_min' => 1e9, 'rules_say' => 'delete_everything']);
is_eq($c['key'], 'AS64500rm-rf', 'A2: the key is stripped to the character set the ignore list uses');
is_eq(strlen($c['provider']), 80, 'A2: a provider name cannot grow the prompt without bound');
is_eq($c['country'], 'SCRIPT', 'A2: a country is letters only');
is_eq($c['attempts'], 0, 'A2: a negative count becomes zero');
is_eq($c['accounts'], 0, 'A2: a non-numeric count becomes zero');
is_eq($c['addresses'], 100000, 'A2: an absurd count is capped, not passed through');
is_eq($c['span_min'], 525600, 'A2: ...and so is an absurd span');
is_eq(count($c['services']), 6, 'A2: at most six doors');
ok(!in_array('$(id)', $c['services'], true), 'A2: a shell-shaped service name does not survive');
is_eq($c['rules_say'], 'watch', 'A2: an unknown verdict falls back to "look first", never to an action');
ok(smpro_aa_bf_facts_clean(['key' => '!!!']) === null, 'A2: a row with no usable key is dropped entirely');
ok(smpro_aa_bf_facts_clean('not an array') === null, 'A2: ...and so is anything that is not a row');

/* ---------- A3: with no provider configured it says so, and does not pretend to have reviewed ---------- */
if (!function_exists('smpro_ai_available')) {
    $r = smpro_aa_bf_ai_review([$f]);
    ok($r['ok'] === false, 'A3: no AI layer -> not ok');
    is_eq($r['rows'], [], 'A3: ...and no rows, so the page cannot show a verdict nobody gave');
    has($r['error'], 'AI provider', 'A3: ...with an error that says what to do about it');
} else {
    ok(true, 'A3: (skipped — an AI layer is loaded in this sandbox)');
}
is_eq(smpro_aa_bf_ai_review([])['rows'] ?? null, [], 'A3: nothing to review is not an error');

/* ---------- A4: the wiring in the page ---------- */
$src = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/account-audit.php'));
has($src, "smpro_require_valid_csrf('aa_delete'); smpro_require_root();\n    header('Content-Type: application/json');\n    // The page sends back",
    'A4: the endpoint is root-only and CSRF-checked, like every other action on this page');
has($src, "smpro_audit('account_audit_breakin_ai'", 'A4: every review is recorded in the audit log');
has($src, 'mislead nobody but its own sender', 'A4: the endpoint states that its input drives no action');
hasnt($src, "'bf_ai'\n    smpro_csf_block", 'A4: no blocking path leads out of the AI endpoint');
has($src, "if (\$k === '' || !isset(\$byKey[\$k]) || isset(\$rows[\$k])) continue;",
    'A4: a verdict for a network nobody asked about, or a repeat, is discarded');
has($src, "if (!in_array(\$d, ['block', 'watch', 'keep'], true)) \$d = 'watch';",
    'A4: an invented decision becomes "look first"');
has($src, 'A recommendation only — nothing was blocked, allow-listed or ignored.', 'A4: and the operator is told so on screen');
has($src, 'AI review — no provider configured', 'A4: with no provider the button is replaced by the reason, not hidden silently');
