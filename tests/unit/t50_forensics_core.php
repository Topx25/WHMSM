<?php
/**
 * t50_forensics_core.php — the malware-detection core had NO tests at all (audit 2026-09-06: forensics-engine,
 * forensics-webattack, forensics-upload-breach — 0 references under tests/). That is the code that decides whether a
 * file is a web shell. The compact() defect that blanked Database Health could not have been caught here even in
 * principle, because nothing exercised these functions. This drives the pure, deterministic parts against REAL
 * files written to the sandbox — a genuine obfuscated shell, a clean file, an empty file — not mocks, so a
 * regression in the token table, the entropy math, or the verdict thresholds fails here first.
 *
 *   U60 smpro_fx_entropy      — Shannon entropy of a file (0 for empty/missing, high for base64 blobs)
 *   U61 smpro_fx_tokenscan    — dangerous-function families + nested decode→eval chain detection
 *   U62 smpro_fx_verdict      — band from signals (a clean file must NOT be called critical; a shell must)
 *   U63 smpro_fx_band_to_sev / smpro_fx_sev_word — the two mappings must round-trip consistently
 *   U64 smpro_fw_classify_req — web-attack request classification (WEBSHELL / WRITE_CANDIDATE / CONTEXT)
 */
require __DIR__ . '/../support/bootstrap.php';
require SMPRO_BASE . '/tests/support/plugin_funcs.php';
smpro_plugin_funcs('includes/helpers.php');
smpro_plugin_funcs('includes/forensics-engine.php');
smpro_plugin_funcs('includes/forensics-webattack.php');

ok(function_exists('smpro_fx_entropy') && function_exists('smpro_fx_tokenscan') && function_exists('smpro_fx_verdict'),
   'forensics core: engine functions loaded router-free');
ok(function_exists('smpro_fw_classify_req'), 'forensics core: web-attack classifier loaded');

$T = sys_get_temp_dir() . '/smpro_t_fx_' . getmypid();
@mkdir($T, 0700, true);

/* ---------- fixtures: real bytes on disk ---------- */
// A plausible obfuscated web shell: decode chain feeding eval, plus exec-family calls.
$shell = "<?php\n\$k='" . base64_encode('system') . "';\n"
       . "eval(base64_decode(gzinflate(base64_decode('" . str_repeat('QUFBQUFBQUFBQUFBQUFB', 20) . "'))));\n"
       . "\$f=base64_decode(\$k); \$f(\$_GET['cmd']); passthru(\$_POST['c']); assert(\$_REQUEST['x']);\n";
file_put_contents("$T/shell.php", $shell);
// A clean, ordinary PHP file — a small template with no dangerous calls.
file_put_contents("$T/clean.php", "<?php\n// site footer\necho '<footer>&copy; ' . date('Y') . ' Example</footer>';\n");
// Empty file.
file_put_contents("$T/empty.php", '');
// A high-entropy blob (random bytes) — what a packed payload looks like to the entropy check.
file_put_contents("$T/blob.bin", random_bytes(65536));

/* ---------- U60 entropy ---------- */
is_eq(smpro_fx_entropy("$T/empty.php"), 0.0, 'U60 entropy: empty file -> 0.0 (nothing to measure, not "suspicious")');
is_eq(smpro_fx_entropy("$T/does-not-exist.php"), 0.0, 'U60 entropy: missing file -> 0.0, no warning, no crash');
$eClean = smpro_fx_entropy("$T/clean.php");
$eBlob  = smpro_fx_entropy("$T/blob.bin");
ok($eClean > 0 && $eClean < 6.0, 'U60 entropy: plain PHP source is moderate (' . round($eClean, 2) . ' bits/byte)');
ok($eBlob > 7.5, 'U60 entropy: random bytes read as near-maximal (' . round($eBlob, 2) . ' bits/byte)');
ok($eBlob > $eClean, 'U60 entropy: a packed blob scores higher than source text (the ordering the verdict relies on)');

/* ---------- U61 token scan ---------- */
$ts = smpro_fx_tokenscan("$T/shell.php");
ok(is_array($ts) && isset($ts['families_seen'], $ts['token_score'], $ts['nested_chain']),
   'U61 tokenscan: returns the documented shape (families_seen/token_score/nested_chain)');
has(implode(',', $ts['families_seen']), 'exec',   'U61 tokenscan: shell -> exec family seen (system/passthru)');
has(implode(',', $ts['families_seen']), 'obfusc', 'U61 tokenscan: shell -> obfuscation family seen (base64_decode/gzinflate)');
ok($ts['nested_chain'] === true, 'U61 tokenscan: decode->decode->eval is recognised as a NESTED chain');
ok((int)$ts['token_score'] > 0, 'U61 tokenscan: shell carries a positive token score (' . (int)$ts['token_score'] . ')');

$tc = smpro_fx_tokenscan("$T/clean.php");
ok(empty($tc['families_seen']), 'U61 tokenscan: clean file -> NO dangerous families (no false positive on echo/date)');
ok($tc['nested_chain'] === false, 'U61 tokenscan: clean file -> no nested chain');
is_eq((int)$tc['token_score'], 0, 'U61 tokenscan: clean file -> token score 0');

$te = smpro_fx_tokenscan("$T/empty.php");
ok(empty($te['families_seen']) && (int)$te['token_score'] === 0, 'U61 tokenscan: empty file -> nothing, not an error');
$tm = smpro_fx_tokenscan("$T/does-not-exist.php");
ok(is_array($tm) && empty($tm['families_seen']), 'U61 tokenscan: missing file -> empty result shape, not a crash');

/* ---------- U62 verdict ---------- */
// Build the deep-scan signal set the way the engine would for each file, then ask for the band.
$mkSignals = function (array $ts, float $ent, array $extra = []) {
    return $extra + ['families_seen' => $ts['families_seen'], 'token_score' => $ts['token_score'],
                     'nested_chain' => $ts['nested_chain'], 'entropy' => $ent];
};
$vShell = smpro_fx_verdict($mkSignals($ts, smpro_fx_entropy("$T/shell.php")));
$vClean = smpro_fx_verdict($mkSignals($tc, $eClean));
ok(is_array($vShell) && isset($vShell['band'], $vShell['score'], $vShell['contributing_signals']),
   'U62 verdict: returns band/score/contributing_signals');
ok(in_array($vShell['band'], ['high', 'critical'], true), 'U62 verdict: obfuscated exec chain -> high/critical (got ' . $vShell['band'] . ')');
ok((int)$vShell['score'] >= 60, 'U62 verdict: shell score >= 60 (' . (int)$vShell['score'] . ')');
ok(!empty($vShell['contributing_signals']), 'U62 verdict: the shell verdict NAMES its signals (explainable, not a bare number)');
ok(in_array($vClean['band'], ['clean', 'info', 'low'], true), 'U62 verdict: clean file -> clean/info/low, never a scare (got ' . $vClean['band'] . ')');
ok((int)$vClean['score'] < 30, 'U62 verdict: clean file score < 30 (' . (int)$vClean['score'] . ')');
ok((int)$vShell['score'] > (int)$vClean['score'], 'U62 verdict: shell outranks clean (the one ordering that must never invert)');

/* ---------- U63 band <-> sev mappings ---------- */
is_eq(smpro_fx_band_to_sev('clean'),    0,  'U63 band_to_sev: clean -> 0');
is_eq(smpro_fx_band_to_sev('critical'), 92, 'U63 band_to_sev: critical -> 92');
is_eq(smpro_fx_band_to_sev('CRITICAL'), 92, 'U63 band_to_sev: case-insensitive');
is_eq(smpro_fx_band_to_sev('nonsense'), 0,  'U63 band_to_sev: unknown band -> 0, not a notice');
is_eq(smpro_fx_sev_word(92), 'critical', 'U63 sev_word: 92 -> critical');
is_eq(smpro_fx_sev_word(75), 'high',     'U63 sev_word: 75 -> high');
is_eq(smpro_fx_sev_word(45), 'medium',   'U63 sev_word: 45 -> medium');
is_eq(smpro_fx_sev_word(0),  'info',     'U63 sev_word: 0 -> info');
// round-trip: every named band maps to a sev whose word is at least as severe as itself
foreach (['medium' => 'medium', 'high' => 'high', 'critical' => 'critical'] as $band => $word)
    is_eq(smpro_fx_sev_word(smpro_fx_band_to_sev($band)), $word, "U63 round-trip: $band -> sev -> $word");

/* ---------- U64 web-attack request classification ---------- */
$req = function ($method, $uri) { return ['method' => $method, 'uri' => $uri]; };
is_eq(smpro_fw_classify_req($req('GET', '/wp-content/uploads/x.php?cmd=id'), '/home/u/public_html/wp-content/uploads', 'x.php'),
      'WEBSHELL', 'U64 classify: ?cmd= on a php -> WEBSHELL');
is_eq(smpro_fw_classify_req($req('GET', '/a.php?x=' . str_repeat('QUFB', 80)), '/home/u/public_html', 'a.php'),
      'WEBSHELL', 'U64 classify: long base64 blob in the query -> WEBSHELL');
is_eq(smpro_fw_classify_req($req('POST', '/wp-admin/admin-ajax.php'), '/home/u/public_html/wp-admin', 'admin-ajax.php'),
      'WRITE_CANDIDATE', 'U64 classify: POST to an upload/admin-ajax endpoint -> WRITE_CANDIDATE');
is_eq(smpro_fw_classify_req($req('POST', '/wp-content/uploads/x.php'), '/home/u/public_html/wp-content/uploads', 'x.php'),
      'WRITE_CANDIDATE', 'U64 classify: POST to the flagged file itself -> WRITE_CANDIDATE');
$ordinary = smpro_fw_classify_req($req('GET', '/about-us/'), '/home/u/public_html', 'x.php');
ok(!in_array($ordinary, ['WEBSHELL', 'WRITE_CANDIDATE'], true), 'U64 classify: an ordinary page view is neither WEBSHELL nor WRITE_CANDIDATE (got ' . $ordinary . ')');

/* cleanup */
foreach (glob("$T/*") ?: [] as $f) @unlink($f); @rmdir($T);
