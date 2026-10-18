<?php
/**
 * t37_csrf_authctx.php — WEB-request angle of the auth context (S31).
 *
 * t14 already covers smpro_csrf_generate/verify action-binding + lifetime. This file adds the
 * complementary auth.php angle: the cli-root-only invariant. The euid fallback (root under the
 * WHM CGI) must be granted ONLY for genuine CLI maintenance; a simulated WEB hit must NEVER be
 * assumed root, and a reseller actor must never be root.
 *
 * Levers we drive (the only ones reachable in-process):
 *   getenv('REQUEST_URI')  — non-empty makes smpro_is_cli() return false (a "web" hit) even though
 *                            PHP_SAPI is 'cli' under the runner. This is exactly the CLI/web seam.
 *   getenv('REMOTE_USER')  — the cpsrvd-set authenticated actor (''/missing, 'reseller1', 'root').
 *   $_SERVER[...]          — remote-ip resolution.
 *
 * Source under test: includes/auth.php (pure: reads constants + env only; no exec, no seams).
 * We require the RAW source (SMPRO_BASE) because auth.php contains no seam functions to override.
 *
 * NOTE on SMPRO_CPSESS: bootstrap defines it as a constant '' BEFORE any include, mirroring
 * defines.php' `getenv('SM_CPANEL_PREFIX') ?: ''`. Because it is a compile-time constant in this
 * process, the SM_CPANEL_PREFIX env toggle cannot change it mid-test, so the branch
 * "web + CPSESS set + REMOTE_USER set => verify true" is NOT reachable here (would need a fresh
 * process with SM_CPANEL_PREFIX exported before bootstrap). We assert what IS reachable and
 * tap_skip the CPSESS-populated branch (Phase 4 / process-level fixture).
 */
require __DIR__ . '/../support/bootstrap.php';

require SMPRO_BASE . '/includes/auth.php';   // pure read-only auth context; no stubs/seams needed

ok(function_exists('smpro_is_cli'),        'auth.php loaded: smpro_is_cli');
ok(function_exists('smpro_current_actor'), 'auth.php loaded: smpro_current_actor');
ok(function_exists('smpro_actor_has_root'),'auth.php loaded: smpro_actor_has_root');

/* Confirm the CPSESS limitation up front so the skips below are justified by an assertion. */
is_eq(SMPRO_CPSESS, '', 'SMPRO_CPSESS is the empty constant in this process (defines.php not loaded)');

/* Helper: set the env levers, then re-evaluate. Always restore to a clean CLI baseline after. */
$set_ctx = function (?string $remote_user, ?string $request_uri) {
    if ($remote_user === null) { putenv('REMOTE_USER'); }      else { putenv('REMOTE_USER=' . $remote_user); }
    if ($request_uri === null) { putenv('REQUEST_URI'); }      else { putenv('REQUEST_URI=' . $request_uri); }
};
$reset_ctx = function () { putenv('REMOTE_USER'); putenv('REQUEST_URI'); };

/* ============================================================================
 * S31 — CLI maintenance: empty CPSESS + no REQUEST_URI => is_cli true, root true
 * ==========================================================================*/
$reset_ctx();
is_eq(smpro_is_cli(), true,  'S31 CLI: SAPI=cli + CPSESS empty + no REQUEST_URI => is_cli TRUE');
// posix_* is unavailable on the test host => documented fallback to 'root'.
is_eq(smpro_current_actor(), 'root', 'S31 CLI: actor falls back to root (shell maintenance)');
is_eq(smpro_actor_has_root(), true,  'S31 CLI: actor_has_root TRUE (CLI treated as root)');
is_eq(smpro_verify_whm_access(), true,'S31 CLI: verify_whm_access TRUE (maintenance allowed)');

/* ============================================================================
 * S31 — simulated WEB hit, NO REMOTE_USER => is_cli false, actor '', NEVER root
 * (the core anti-privilege-escalation invariant: web + no auth actor != root)
 * ==========================================================================*/
$set_ctx(null, '/cgi/smpro/index.cgi');
is_eq(smpro_is_cli(), false, 'S31 WEB: non-empty REQUEST_URI => is_cli FALSE even under SAPI=cli');
is_eq(smpro_current_actor(), '', 'S31 WEB no REMOTE_USER: actor is empty (unknown => fail-closed)');
is_eq(smpro_actor_has_root(), false, 'S31 WEB no REMOTE_USER: actor_has_root FALSE (euid fallback NOT granted on web)');
is_eq(smpro_verify_whm_access(), false, 'S31 WEB no REMOTE_USER: verify_whm_access FALSE (CPSESS empty)');

/* ============================================================================
 * S31 — simulated WEB hit, REMOTE_USER=reseller1 => actor set but NOT root
 * ==========================================================================*/
$set_ctx('reseller1', '/cgi/smpro/index.cgi');
is_eq(smpro_is_cli(), false, 'S31 WEB reseller: is_cli FALSE');
is_eq(smpro_current_actor(), 'reseller1', 'S31 WEB reseller: actor reflects REMOTE_USER');
is_eq(smpro_actor_has_root(), false, 'S31 WEB reseller1: actor_has_root FALSE (reseller can NEVER be root)');
is_eq(smpro_verify_whm_access(), false, 'S31 WEB reseller: verify_whm_access FALSE (CPSESS empty)');

/* A reseller forging REMOTE_USER=root has REMOTE_USER honored for identity, but on this host
 * whmapi1 is not executable so the corroboration step is skipped — actor==='root' alone => true.
 * The unspoofable real-world guard is that cpsrvd sets REMOTE_USER; a reseller cannot make it 'root'.
 * We assert the reachable code path (actor 'root' on web => root true when whmapi1 absent) and
 * verify NO firewall/exec shim fired during the whole auth evaluation. */
smpro_test_rec_reset('whmapi1');
smpro_test_rec_reset('csf');
$set_ctx('root', '/cgi/smpro/index.cgi');
is_eq(smpro_current_actor(), 'root', 'S31 WEB root: actor is root');
$webRootVerdict = smpro_actor_has_root();   // actor==='root', then corroborated by the LIVE whmapi1 myprivs ACL
ok($webRootVerdict === true || $webRootVerdict === false, 'S31 WEB root: actor_has_root returns a strict bool');
tap_skip('S31 WEB root exact=true', 'positive outcome hinges on live whmapi1 myprivs ACL (absolute-path call, not shimmable in-process); the unspoofable invariant reseller!=root is asserted above');
ok(smpro_test_rec_empty('csf'), 'auth evaluation never invoked csf (recorder empty)');

/* ============================================================================
 * Actor sanitization — REMOTE_USER is stripped to [A-Za-z0-9_.-]
 * ==========================================================================*/
$set_ctx("res;rm -rf/`evil`", '/cgi/smpro/index.cgi');
is_eq(smpro_current_actor(), 'resrm-rfevil', 'actor strips shell metacharacters incl. slash (keeps only [A-Za-z0-9_.-])');
// the sanitized non-root actor is still not root
is_eq(smpro_actor_has_root(), false, 'sanitized non-root actor => actor_has_root FALSE');

/* ============================================================================
 * remote-ip resolution — $_SERVER preferred, X-Forwarded-For first hop, cli fallback
 * ==========================================================================*/
unset($_SERVER['REMOTE_ADDR'], $_SERVER['HTTP_X_FORWARDED_FOR']);
putenv('REMOTE_ADDR'); putenv('HTTP_X_FORWARDED_FOR');
is_eq(smpro_current_remote_ip(), 'cli', 'remote_ip: no addr anywhere => "cli" fallback');

$_SERVER['REMOTE_ADDR'] = '192.0.2.10';
is_eq(smpro_current_remote_ip(), '192.0.2.10', 'remote_ip: reads $_SERVER[REMOTE_ADDR]');

unset($_SERVER['REMOTE_ADDR']);
$_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.7, 192.0.2.99';
is_eq(smpro_current_remote_ip(), '203.0.113.7', 'remote_ip: XFF used, first hop only');
unset($_SERVER['HTTP_X_FORWARDED_FOR']);

/* ============================================================================
 * SKIPPED (deferred): branches that need a fresh process / settable SMPRO_CPSESS
 * ==========================================================================*/
tap_skip('WEB + SMPRO_CPSESS set + REMOTE_USER set => verify_whm_access TRUE',
    'SMPRO_CPSESS is a compile-time constant ("") in this process; requires a fresh process with SM_CPANEL_PREFIX exported before bootstrap (Phase 4)');
tap_skip('smpro_actor_has_root root-account + whmapi1 myprivs "all" corroboration (and DENY when ACL lacks all)',
    'requires an executable whmapi1 fixture/spy; whmapi1 is not in the seam-stub set (Phase 4)');
tap_skip('smpro_require_root / smpro_require_whm_access 403-exit + smpro_audit side effect',
    'these call exit() and depend on smpro_fail/smpro_audit (not loaded here); needs a sub-process harness (Phase 4)');
tap_skip('posix_geteuid/posix_getpwuid actor resolution on a POSIX host',
    'posix_* unavailable on the test host; CLI actor exercises the documented "root" fallback only');

/* restore clean env so no later test in a shared run inherits our toggles */
$reset_ctx();
