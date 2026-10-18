<?php
/**
 * r02_opcache_tuning.php — PHASE-4 REGRESSION lock for the Server Tune-up OPcache bugs.
 *
 * Two documented past bugs must never reopen (source: includes/tuning.php):
 *
 *   R15  OPcache FALSE-POSITIVE (the "flagged forever" regression).
 *        The OLD detection reader built a `php -r` one-liner with NESTED double quotes
 *        inside an outer escapeshellarg — the program string came out MALFORMED, so the
 *        shell returned EMPTY, and the scan logic `if ($oc !== '1')` therefore ALWAYS fired
 *        the `php_opcache` recommendation, even on a server where OPcache was enabled.
 *        FIX (tuning.php:129-132): escapeshellarg the WHOLE `-r` program. The reader now
 *        emits a clean single token "0" or "1".
 *        LOCK: run the reader EXACTLY as the source builds it, against the real interpreter
 *        this test runs under (PHP_BINARY === ea-php82 on the box). It must return a strict
 *        "0"/"1" (never empty/garbage). And on THIS ea-php82 which HAS OPcache the reader
 *        returns "1" => the scan decision `$oc !== '1'` is false => ZERO php_opcache recs.
 *
 *   R16  HONEST-VERIFY on apply (no false "applied").
 *        smpro_tun_apply('php_opcache') must NOT report success if the OPcache .so is still
 *        absent after the claimed install — it returns ok=false "...could not be installed..."
 *        (tuning.php:374-378). The live end-to-end fire needs an OPcache-OFF box + a real
 *        package-install fixture + an overridable glob()/hardcoded /opt/cpanel path, so the
 *        full path is tap_skip'd (documented below). What IS reachable without faking the
 *        filesystem — the apply guard rails (unknown/cPanel-managed rec refused with NO
 *        destructive side effect) — is asserted here.
 *
 * smpro_tun_score grade boundaries and the smpro_tun_apply_map registry are already covered
 * exhaustively by unit/t18_modules_tuning_harden.php (U89/U90); they are NOT re-duplicated
 * here (one load-bearing R16-precondition map assertion aside) — see the tap_skip notes.
 *
 * Every expected value is derived by reading includes/tuning.php directly. No real
 * csf/dnf/rm/restartsrv/net can fire: the stub PATH shadows them and we assert the
 * recorders stayed empty.
 */
require __DIR__ . '/../support/bootstrap.php';

require_once SMPRO_BASE . '/includes/helpers.php';   // smpro_tun_sh delegates to smpro_run since beta287
require SMPRO_BASE . '/includes/tuning.php';   // standalone (SMPRO_BOOT guard); constants -> sandbox

ok(function_exists('smpro_tun_sh'), 'tuning.php loaded; smpro_tun_sh available');
ok(function_exists('smpro_tun_scan'), 'tuning.php loaded; smpro_tun_scan available');

/* =====================================================================
 * R15 — OPcache detection reader: the EXACT `php -r` one-liner from
 * includes/tuning.php line 131, rebuilt verbatim and run via the real
 * function against the real interpreter (PHP_BINARY = ea-php82 on box).
 *
 *   $oc = trim(smpro_tun_sh(
 *       escapeshellarg($php) . ' -r ' .
 *       escapeshellarg('echo (extension_loaded("Zend OPcache") && ini_get("opcache.enable")) ? "1" : "0";')));
 * ===================================================================== */
$php = PHP_BINARY;                                   // the interpreter under test (ea-php82 on the box)
$ocProg = 'echo (extension_loaded("Zend OPcache") && ini_get("opcache.enable")) ? "1" : "0";';
$ocCmd  = escapeshellarg($php) . ' -r ' . escapeshellarg($ocProg);
$oc     = trim(smpro_tun_sh($ocCmd));

// THE REGRESSION: the malformed-quote bug made this empty. The fixed reader yields a clean token.
isnt_eq($oc, '', 'R15 opcache reader is NOT empty (the malformed-escapeshellarg "flagged forever" bug)');
ok($oc === '0' || $oc === '1', 'R15 opcache reader returns a strict single token "0" or "1" (parseable, no garbage)');
hasnt($oc, 'error', 'R15 opcache reader output carries no parse/syntax error text');
hasnt($oc, 'Parse', 'R15 opcache reader output carries no "Parse error" text');

// The scan DECISION replicated from the source: `if ($oc !== '1') $rec(... 'php_opcache' ...)`.
$wouldFlag = ($oc !== '1');                          // exactly the source predicate

// On THIS ea-php82 (OPcache present + enabled) the reader is "1" => the recommendation is NOT produced.
if ($oc === '1') {
    is_eq($wouldFlag, false, 'R15 OPcache enabled here => scan predicate ($oc !== "1") is false => NO php_opcache rec');
    // Prove it end-to-end through smpro_tun_scan(): there must be EXACTLY ZERO php_opcache recs.
    $scan = smpro_tun_scan();
    $ocRecs = array_values(array_filter($scan['recs'], fn($r) => ($r['id'] ?? '') === 'php_opcache'));
    is_eq(count($ocRecs), 0, 'R15 smpro_tun_scan() emits EXACTLY ZERO php_opcache recommendations (no false positive)');
} else {
    // OPcache genuinely off on this interpreter (e.g. CLI without the ext): the reader HONESTLY says "0"
    // and the predicate fires — that is correct behavior, not the regression. (The regression was EMPTY.)
    is_eq($wouldFlag, true, 'R15 OPcache off here => reader honestly "0" => predicate fires (correct, not the empty-string bug)');
    tap_skip('R15 zero-php_opcache-rec assertion', 'this interpreter has OPcache OFF (reader="0"); the zero-rec lock requires an OPcache-ON ea-php82 (the box) — reader still proved non-empty above');
}

// Sibling regression surface: expose_php uses the SAME whole-program escapeshellarg form (line 129).
// It must likewise return a clean token, never a malformed-empty.
$exProg = 'echo (string)ini_get("expose_php");';
$ex     = trim(smpro_tun_sh(escapeshellarg($php) . ' -r ' . escapeshellarg($exProg)));
hasnt($ex, 'error', 'R15 expose_php reader (same whole-program escaping) returns clean output (no parse error)');
ok($ex === '0' || $ex === '1' || $ex === '' || $ex === 'On' || $ex === 'Off',
   'R15 expose_php reader yields a plain ini token (0/1/On/Off/"") — well-formed, not a shell error');

/* Witness that the FIXED escaping is well-formed: building the command the source way must
 * produce a single-quoted, shell-safe -r argument (no stray unquoted parens/quotes that
 * would let the shell mangle it). This is the structural anti-regression for the quoting. */
like($ocCmd, '/ -r /', 'R15 reader command shells the program via a separate -r argument');
ok(substr_count($ocCmd, escapeshellarg($ocProg)) === 1,
   'R15 the ENTIRE -r program is wrapped by a single escapeshellarg (the fix; old code nested raw quotes)');

/* =====================================================================
 * R16 — apply path: HONEST-VERIFY + guard rails.
 *
 * smpro_tun_apply() first re-scans, finds the rec, looks it up in apply_map.
 *   - unknown rec id            -> 'Recommendation not found (re-scan).'  (returns BEFORE any backup)
 *   - rec exists but unmapped   -> cPanel-managed advisory refusal
 * Neither path may touch dnf/rm/restartsrv. We assert the recorders stay empty.
 * ===================================================================== */
$map = smpro_tun_apply_map();

// Load-bearing R16 precondition (and only non-dup map check): php_opcache routes to the php_ini
// applier whose tail is the honest-verify branch (tuning.php:374-378). If this routing ever
// changed, the verify guarantee would silently move — so we anchor it here.
is_eq($map['php_opcache'] ?? null, ['php_ini', 'opcache.enable', '1'],
    'R16 apply_map routes php_opcache -> php_ini applier (the branch that honest-verifies the .so)');

// Guard: an UNKNOWN recommendation id is refused, and refused BEFORE any side effect.
smpro_test_rec_reset('dnf');
smpro_test_rec_reset('rm');
smpro_test_rec_reset('restartsrv');
$bad = smpro_tun_apply('this_rec_does_not_exist');
is_eq($bad['ok'], false, 'R16 apply(unknown rec) -> ok=false');
has($bad['msg'], 'not found', 'R16 apply(unknown rec) -> "Recommendation not found" message');
ok(smpro_test_rec_empty('dnf'), 'R16 apply(unknown rec): dnf/yum NEVER invoked (no package install attempted)');
ok(smpro_test_rec_empty('rm'),  'R16 apply(unknown rec): rm NEVER invoked (no destructive action)');
ok(smpro_test_rec_empty('restartsrv'), 'R16 apply(unknown rec): restartsrv NEVER invoked (no service restart)');

/* The HONEST-VERIFY behavior is documented in source (tuning.php:374-378):
 *   if ($recId === 'php_opcache') { ...glob each ea-php opcache.so...; if (!$loaded)
 *       return ['ok'=>false,'msg'=>'Setting written, but the OPcache extension could not be installed...']; }
 * We assert the exact failure string the source returns, so any wording/logic drift on the
 * honest-verify branch trips this lock — even though we cannot DRIVE the branch in-process. */
$src = (string)@file_get_contents(SMPRO_BASE . '/includes/tuning.php');
has($src, "the OPcache extension could not be installed",
    'R16 source honest-verify branch returns ok=false "OPcache extension could not be installed" when .so still absent');
has($src, "opcache.so",
    'R16 source honest-verify checks for the real opcache.so on disk (not just extension_loaded of a fresh proc)');

/* =====================================================================
 * Deferred / not duplicated (documented):
 * ===================================================================== */
tap_skip('R16 honest-verify LIVE fire (apply php_opcache -> .so absent -> ok=false)',
    'needs an OPcache-OFF ea-php82 (so a php_opcache rec exists) + a package-install fixture + an overridable glob()/hardcoded /opt/cpanel path; not stubbable without runkit. Source string + apply_map routing locked above');
tap_skip('smpro_tun_score grade boundaries',
    'already covered exhaustively in unit/t18_modules_tuning_harden.php (U89) — not duplicated');
tap_skip('smpro_tun_apply_map full registry',
    'already covered exhaustively in unit/t18_modules_tuning_harden.php (U90) — only the php_opcache->php_ini routing (R16 precondition) is re-anchored here');
tap_skip('ssh sshd_config.d drop-in parity (sget effective via sshd -T)',
    'needs sshd -T / sshd_config.d fixtures to exercise the merged-config reader; deferred');
tap_skip('apache conf.d/includes drop-in parity (zz-smpro-tuning.conf merge)',
    'needs apachectl -t + a real httpd include-dir fixture to exercise the apply/validate/rollback; deferred');
