<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
require_once SMPRO_BASE . '/includes/integrity.php';
require_once SMPRO_BASE . '/includes/license.php';
/**
 * t167 - the licence stop clock and the gates around it.
 * The 48h after which background functions go quiet used to hang on one unsigned file: removing it every day kept
 * an expired install working for ever. The clock is now read from signed data when there is any, and the local
 * marker lives in two places with the earliest winning.
 */
@mkdir(SMPRO_LIC_DIR, 0700, true);
$f = smpro_lic_dormant_file(); @unlink($f); @unlink(SMPRO_LIC_STATE);
$fresh = function () { unset($GLOBALS['_smpro_lic_state']); };   // the state is cached per request; a hand-written file needs a new one

$t0 = time();
$s1 = smpro_lic_invalid_since();
ok($s1 >= $t0 && $s1 <= time() + 1, 'D1: with nothing recorded the clock starts now');
ok(is_file($f) && (int)trim((string)file_get_contents($f)) === $s1, 'D2: ...and is written down');

// an activated install (key present, no signed verdict left) whose marker is 3 days old
$past = time() - 3 * 86400;
file_put_contents(SMPRO_LIC_STATE, json_encode(['key' => 'TEST-KEY', 'ok' => false, 'status' => 'expired'])); $fresh();
file_put_contents($f, (string)$past);
is_eq(smpro_lic_invalid_since(), $past, 'D3: an existing marker is kept');
is_eq((int)(json_decode((string)file_get_contents(SMPRO_LIC_STATE), true)['inv_since'] ?? 0), $past, 'D4: the marker is mirrored inside the licence state');
unlink($f);
is_eq(smpro_lic_invalid_since(), $past, 'D5: removing the marker file does not restart the clock');
ok(is_file($f) && (int)trim((string)file_get_contents($f)) === $past, 'D6: ...the file comes back with the original moment');
$d = json_decode((string)file_get_contents(SMPRO_LIC_STATE), true); unset($d['inv_since']); file_put_contents(SMPRO_LIC_STATE, json_encode($d)); $fresh();
is_eq(smpro_lic_invalid_since(), $past, 'D7: removing the mirror alone does not restart it either');
file_put_contents($f, (string)(time() + 999999));
is_eq(smpro_lic_invalid_since(), $past, 'D8: a marker set in the future is ignored (the earliest real moment wins)');
if (defined('SMPRO_LIC_ENFORCE') && SMPRO_LIC_ENFORCE) {
    ok(smpro_lic_dormant() === true, 'D9: 48h after the licence stopped, background functions are off');
    file_put_contents($f, (string)(time() - 3600)); $d = json_decode((string)file_get_contents(SMPRO_LIC_STATE), true); $d['inv_since'] = time() - 3600; file_put_contents(SMPRO_LIC_STATE, json_encode($d)); $fresh();
    ok(smpro_lic_dormant() === false, 'D10: inside the 48h they keep running');
} else { tap_skip('D9-D10: dormancy verdict', 'licence enforcement is off in this run'); }
smpro_lic_dormant_clear();
ok(!is_file($f) && !isset(json_decode((string)file_get_contents(SMPRO_LIC_STATE), true)['inv_since']), 'D11: a valid licence clears both copies');
@unlink(SMPRO_LIC_STATE);

$src = fn($p) => str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/' . $p));
$lic = $src('includes/license.php');
has($lic, "if (\$valid && (time() - (int)(\$s['last_ok'] ?? 0)) < 3 * \$grace) {", 'G1: an action rides the cached verdict only after a real answer (last_ok), never after a mere attempt');
ok(strpos($lic, "(time() - (int)(\$s['last_check'] ?? 0)) < \$grace") === false, 'G2: the last-attempt clock no longer opens actions');

$in = $src('includes/integrity.php');
has($in, "if (!is_file(SMPRO_INTEG_MANIFEST)) return \$packaged ? ['ok' => false, 'reason' => 'integrity manifest missing', 'critical' => true] : ['skip' => 'no_manifest'];", 'I1: a packaged copy without its manifest is a failure, not a skip');
has($in, "return \$packaged ? ['ok' => false, 'reason' => 'integrity manifest unreadable', 'critical' => true] : ['skip' => 'blank_manifest'];", 'I2: ...and so is an emptied manifest');
has($src('includes/defines.php'), "define('SMPRO_PACKAGED',    false);", 'I3: the source tree is not a packaged copy');
$b = is_file(SMPRO_BASE . '/build/obfuscate-and-package.sh') ? $src('build/obfuscate-and-package.sh') : '';
if ($b === '') tap_skip('I4: the release build marks its staged copy', 'the build script is not part of this tree');
else ok(strpos($b, "define('SMPRO_PACKAGED',    true);") !== false && strpos($b, 'could not mark the staged copy as packaged') !== false, 'I4: the release build marks its staged copy and stops if it could not');
$r = smpro_integrity_check(['index.php']);
ok(!empty($r['skip']) || !empty($r['ok']), 'I5: a source checkout (no manifest) still skips');

$up = $src('includes/update.php');
has($up, "@openssl_verify('smpro-upd-force|' . \$fv, \$fs, \$fpk, OPENSSL_ALGO_SHA256) === 1", 'U1: a forced apply needs a signature by the release key over the directive');
has($up, "if (\$fok && \$fv !== (string)(\$c['upd_force_done'] ?? '')) {", 'U2: without it nothing is forced');

// Safety Lock: where the account signed in from
$isLogin = fn(string $line) => (bool)preg_match('/\bSUCCESS\b/i', (string)preg_replace('/"[^"]*"/', '""', $line)) && !preg_match('/\bFAILED\b/i', $line);
ok($isLogin('[2026-01-01 10:00:00 +0000] info [cpaneld] 192.0.2.10 - bob "POST /login/ HTTP/1.1" SUCCESS LOGIN cpaneld'), 'S1: a real login line counts');
ok(!$isLogin('[2026-01-01 10:00:00 +0000] info [cpaneld] 192.0.2.66 - bob "POST /login/?login_only=1&x=success HTTP/1.1" FAILED LOGIN cpaneld: wrong password'), 'S2: a failed attempt with the word in its URL does not');
has($src('includes/sprules.php'), "preg_replace('/\"[^\"]*\"/', '\"\"', \$line)", 'S3: the rule reads the result outside the quoted request');

ok(strpos($src('includes/sdbulk.php'), "stripos(\$o, 'Success')") === false && strpos($src('includes/sdbulk.php'), 'WP_CLI_CONFIG_PATH=/dev/null WP_CLI_PACKAGES_DIR=/nonexistent') !== false, 'C1: core restore ignores the account tool config and reads the real result line');
ok(strpos($src('includes/investigate.php') . $src('includes/sitewatch.php'), '@mysqli_connect(') === false, 'C2: site databases are reached through the guarded connect');
ok(function_exists('smpro_mysqli_connect') && is_string(smpro_detect_backup_root()) && smpro_detect_backup_root() !== '', 'C3: helpers present');
has($src('includes/fwblock.php'), "if (is_array(\$r) && is_array(\$r[1] ?? null)) \$docs[] = \$r[1];", 'C4: the shared list reads the decoded reply, not the transport tuple');
has($src('includes/investigate.php'), "if (isset(\$held[rtrim(\$t, '/')])) continue;", 'C5: Site Doctor leaves a lock another product holds');

// signed refusals
ok(smpro_lic_neg_ok(null, 'K') === false && smpro_lic_neg_ok(['payload' => ['kind' => 'negative', 'license_key' => 'K', 'fingerprint' => smpro_lic_fingerprint(), 'status' => 'suspended'], 'signature' => base64_encode('x')], 'K') === false, 'N1: a refusal without a valid signature of the licence server is not accepted as signed');
has($lic, "if (\$auth && empty(\$j['ok']) && !smpro_lic_neg_ok(\$j['verdict'] ?? null, \$key, \$j['status'] ?? '')", 'N2: an unsigned refusal is weighed against what the server said about itself');
has($lic, "&& smpro_lic_signed_field(smpro_lic_state(), 'signs_negative', false) === true) \$auth = false;", 'N3: ...only a server that signs its refusals makes an unsigned one count as "not reached"');
has($lic, "if ((string)(\$p['kind'] ?? '') !== 'negative') return false;", 'N4: a signed verdict of another kind is not a refusal');
has($lic, "\$nt = (int)@strtotime((string)(\$s['neg_first']['payload']['issued_at'] ?? '')); if (\$nt > 0 && \$nt <= \$now) \$c[] = \$nt;", 'N5: the stop clock reads the signed time of the first refusal');
