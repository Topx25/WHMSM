<?php
/**
 * t36_ai_region.php — AI region home-protection safety net + the pure region classifier.
 *
 * TARGETS
 *   S16  smpro_im_ai_block_decide  (includes/intrusion.php) — the in-code safety net that
 *        OVERRIDES whatever the model returns: when the model says {block:[EG-residential,
 *        weak-Arab-residential, US-datacenter]} the code DOWNGRADES the EG entry to "review",
 *        downgrades the weak-Arab entry to "review" (not clear & repeated), and KEEPS the
 *        US-datacenter entry in "block". Non-IP / bogus block entries are filtered out by
 *        filter_var(FILTER_VALIDATE_IP). This is the anti-collateral-damage heart of the WAF.
 *   U35* smpro_im_region_status     (includes/intrusion.php) — the pure region classifier the
 *        safety net leans on (core_protected / arab_caution / normal). (Listed in the brief as
 *        the region seam that the AI path consumes.)
 *
 * MECHANISM
 *   smpro_im_ai_block_decide calls smpro_ai_available() and smpro_ai_chat_json() by those exact
 *   names (no seam indirection). Neither lives in intrusion.php, so this test DEFINES both as
 *   deterministic stubs BEFORE requiring intrusion.php — our stubs are then the ONLY definitions
 *   and fully control the "model" reply with NO network call. The geo seam (smpro_ip_intel /
 *   smpro_ip_is_datacenter) is provided by smpro_test_install_stubs() and required from the
 *   .build copy of helpers.php (whose seam defs are renamed so our stubs win).
 *
 * NOTE on U78 (smpro_ai_decide_kind / smpro_ai_decide_exec): those live in includes/ai.php,
 *   which defines smpro_ai_chat_json() and smpro_ai_available() WITHOUT a function_exists guard.
 *   Requiring ai.php in this process would fatally redeclare the very stubs S16 depends on, and
 *   those two callees are NOT in the seam-stub set, so they cannot be controlled while ai.php is
 *   loaded. U78 is therefore tap_skip'd here (deferred — needs its own file that loads ai.php
 *   instead of stubbing the AI layer, or spy infra for the AI seam).
 */
require __DIR__ . '/../support/bootstrap.php';

/* ---- deterministic geo/identity seams (stubs win over the renamed .build defs) ---- */
smpro_test_install_stubs(['server_ips' => ['203.0.113.50' => 1]]);

/* ---- AI layer stubs: the ONLY definitions of these names in this process ----
 * smpro_ai_available() -> always "ready" so smpro_im_ai_block_decide does not bail early.
 * smpro_ai_chat_json($sys,$usr,$opts) -> returns ['ok'=>true,'data'=>$GLOBALS[...]] so the
 * model's block/keep/review lists are whatever the test sets. NO network is ever touched. */
if (!function_exists('smpro_ai_available')) {
    function smpro_ai_available(): bool { return (bool)($GLOBALS['__ai_ready'] ?? true); }
}
if (!function_exists('smpro_ai_chat_json')) {
    function smpro_ai_chat_json(string $sys, string $usr, array $opts = []): array {
        $GLOBALS['__ai_chat_calls'] = ($GLOBALS['__ai_chat_calls'] ?? 0) + 1;
        $m = $GLOBALS['__ai_reply'] ?? ['ok' => true, 'data' => ['block' => [], 'keep' => [], 'review' => [], 'reason' => 'stub']];
        return $m;
    }
}

require SMPRO_TEST_BUILD . '/includes/helpers.php';     // seams renamed -> our stubs win
require SMPRO_BASE . '/includes/intrusion.php';         // region_status + ai_block_decide (real code)

// caution_regions ships empty now; set the Arab list so the caution tier is exercised via the configurable path.
@is_dir(dirname(SMPRO_IN_CFG)) || @mkdir(dirname(SMPRO_IN_CFG), 0700, true);
@file_put_contents(SMPRO_IN_CFG, json_encode(['protect_regions' => ['EG','SA'], 'caution_regions' => ['AE','KW','QA','BH','OM','JO','LB','SY','IQ','YE','PS','DZ','MA','TN','LY','SD','MR','SO','DJ','KM']]));

ok(function_exists('smpro_im_ai_block_decide'), 'ai_block_decide loaded; AI + geo stubs installed');
ok(function_exists('smpro_im_region_status'), 'region_status loaded');

/* TEST-NET IPs only (RFC 5737). Geo intel keyed by IP via the ip_intel stub. */
$EG_RES = '198.51.100.10';   // EG residential   -> core_protected -> model "block" must become review
$AE_RES = '198.51.100.11';   // AE residential   -> arab_caution   -> weak attack -> review
$AE_HOT = '198.51.100.12';   // AE residential   -> arab_caution   -> clear&repeated -> stays block
$US_DC  = '203.0.113.20';    // US datacenter    -> normal         -> stays block
$US_RES = '198.51.100.13';   // US residential   -> normal         -> stays block

smpro_stub_set('ip_intel', [
    $EG_RES => ['country' => 'EG', 'provider' => 'TE Data',   'datacenter' => false],
    $AE_RES => ['country' => 'AE', 'provider' => 'Etisalat',  'datacenter' => false],
    $AE_HOT => ['country' => 'AE', 'provider' => 'Etisalat',  'datacenter' => false],
    $US_DC  => ['country' => 'US', 'provider' => 'DigitalOcean', 'datacenter' => true],
    $US_RES => ['country' => 'US', 'provider' => 'Comcast',   'datacenter' => false],
]);

/* ---------- U35* region classifier the safety net consumes ---------- */
is_eq(smpro_im_region_status($EG_RES), 'core_protected', 'U35* EG residential -> core_protected');
is_eq(smpro_im_region_status($AE_RES), 'arab_caution',   'U35* AE residential -> arab_caution');
is_eq(smpro_im_region_status($US_DC),  'normal',         'U35* US datacenter -> normal (hosting is fair game)');
is_eq(smpro_im_region_status($US_RES), 'normal',         'U35* US residential -> normal');

/* ---------- S16 — the downgrade safety net ----------
 * offenders carry ip/hits/cats(array); the safety net reads hits + count(cats) for arab_caution.
 *   EG_RES: model blocks -> code forces to review (core_protected)
 *   AE_RES: model blocks, hits=2 cats=1 (not clear&repeated: hits<5 AND cats<2) -> forced to review
 *   AE_HOT: model blocks, hits=40 cats=3 (clear & repeated)                      -> stays block
 *   US_DC : model blocks, datacenter                                            -> stays block
 *   bogus : a non-IP entry in the model's block list                            -> filtered out
 */
$offenders = [
    ['ip' => $EG_RES, 'hits' => 99, 'domains' => 5, 'cats' => ['sqli', 'lfi', 'rce'], 'country' => 'EG', 'provider' => 'TE Data', 'bot' => 0],
    ['ip' => $AE_RES, 'hits' => 2,  'domains' => 1, 'cats' => ['sqli'],                'country' => 'AE', 'provider' => 'Etisalat', 'bot' => 0],
    ['ip' => $AE_HOT, 'hits' => 40, 'domains' => 8, 'cats' => ['sqli', 'lfi', 'rce'], 'country' => 'AE', 'provider' => 'Etisalat', 'bot' => 0],
    ['ip' => $US_DC,  'hits' => 30, 'domains' => 9, 'cats' => ['scan'],               'country' => 'US', 'provider' => 'DigitalOcean', 'bot' => 1],
];
$GLOBALS['__ai_ready'] = true;
$GLOBALS['__ai_reply'] = ['ok' => true, 'data' => [
    'block'  => [$EG_RES, $AE_RES, $AE_HOT, $US_DC, 'not-an-ip', '999.1.2.3'],
    'keep'   => [$US_RES],
    'review' => [],
    'reason' => 'model picks',
]];
$GLOBALS['__ai_chat_calls'] = 0;

$res = smpro_im_ai_block_decide($offenders);

ok(!empty($res['ok']), 'S16 ai_block_decide returns ok');
is_eq($GLOBALS['__ai_chat_calls'], 1, 'S16 the AI was consulted exactly once (stub, no network)');

/* what survives in BLOCK */
ok(in_array($US_DC, $res['block'], true),  'S16 US datacenter STAYS in block (hosting attacks normally)');
ok(in_array($AE_HOT, $res['block'], true), 'S16 weak-Arab residential with clear&repeated attack STAYS in block');
nok(in_array($EG_RES, $res['block'], true),  'S16 EG residential DOWNGRADED out of block (never auto-block home region)');
nok(in_array($AE_RES, $res['block'], true),  'S16 weak-Arab residential (not clear&repeated) DOWNGRADED out of block');
nok(in_array('not-an-ip', $res['block'], true), 'S16 non-IP block entry filtered out (FILTER_VALIDATE_IP)');
nok(in_array('999.1.2.3', $res['block'], true), 'S16 bogus IP block entry filtered out');
is_eq(count($res['block']), 2, 'S16 exactly two IPs survive to block (US-dc + clear-Arab)');

/* what lands in REVIEW (the downgrades) */
ok(in_array($EG_RES, $res['review'], true), 'S16 EG residential routed to review');
ok(in_array($AE_RES, $res['review'], true), 'S16 weak-Arab residential routed to review');
nok(in_array($US_DC, $res['review'], true), 'S16 US datacenter NOT in review');
nok(in_array($AE_HOT, $res['review'], true), 'S16 clear-attack Arab IP NOT in review');

/* keep list passes through from the model — but is now IP-SANITIZED (the lab-found fix) */
ok(in_array($US_RES, $res['keep'], true), 'S16 model keep list (valid IPs) passes through');
$GLOBALS['__ai_reply'] = ['ok' => true, 'data' => ['block' => [], 'keep' => [$US_RES, 'not-an-ip', '; rm -rf /', ''], 'review' => [], 'reason' => 'x']];
$resK = smpro_im_ai_block_decide($offenders);
ok(in_array($US_RES, $resK['keep'], true), 'S16 keep: valid IP retained after sanitization');
nok(in_array('not-an-ip', $resK['keep'], true), 'S16 keep: non-IP "not-an-ip" filtered out (fix: FILTER_VALIDATE_IP)');
nok(in_array('; rm -rf /', $resK['keep'], true), 'S16 keep: injection-y non-IP filtered out (model output never echoed raw)');
is_eq(count($resK['keep']), 1, 'S16 keep: only the single valid IP survives sanitization');

/* dedupe: an IP the model lists in BOTH block and review must not be double-counted in review */
$GLOBALS['__ai_reply'] = ['ok' => true, 'data' => [
    'block'  => [$EG_RES],
    'keep'   => [],
    'review' => [$EG_RES],          // model also already put it in review
    'reason' => 'dup',
]];
$res2 = smpro_im_ai_block_decide([$offenders[0]]);
is_eq(count(array_keys($res2['review'], $EG_RES, true)), 1, 'S16 EG IP appears once in review (array_unique dedupe)');
is_eq(count($res2['block']), 0, 'S16 EG-only block downgrades to empty block');

/* AI unavailable -> early, honest failure, no review/block invented */
$GLOBALS['__ai_ready'] = false;
$res3 = smpro_im_ai_block_decide($offenders);
is_eq($res3['ok'], false, 'S16 no AI provider -> ok=false');
is_eq($res3['block'], [],  'S16 no AI provider -> empty block');
has($res3['reason'], 'No AI provider', 'S16 no AI provider -> honest reason');
$GLOBALS['__ai_ready'] = true;

/* no offenders -> ok with empty plan, model never consulted */
$GLOBALS['__ai_chat_calls'] = 0;
$res4 = smpro_im_ai_block_decide([]);
is_eq($res4['ok'], true, 'S16 no offenders -> ok=true');
is_eq($res4['block'], [], 'S16 no offenders -> empty block');
is_eq($GLOBALS['__ai_chat_calls'], 0, 'S16 no offenders -> AI NOT consulted (short-circuit)');

/* model returns unparseable / non-array data -> honest failure, nothing blocked */
$GLOBALS['__ai_reply'] = ['ok' => true, 'data' => null];
$res5 = smpro_im_ai_block_decide($offenders);
is_eq($res5['ok'], false, 'S16 model returned no usable JSON -> ok=false');
is_eq($res5['block'], [], 'S16 unparseable reply -> empty block (never block on garbage)');

/* U78 (decide_kind / decide_exec) is now covered in its own file: tests/unit/t42_ai_decide.php
 * (those functions are pure — they only needed a file without the S16 AI stubs). */
