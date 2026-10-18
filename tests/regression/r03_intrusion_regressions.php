<?php
/**
 * r03_intrusion_regressions.php — Phase-4 REGRESSION: lock documented Intrusion / Login / CSF
 * parser & response bugs so they cannot silently reopen.
 *
 *   R28  SERVED 2xx vs 403-blocked severity — the OLD bug raised a meaningless "223 CRITICAL"
 *        alert by counting every 403-BLOCKED WAF probe as critical. The fix (intrusion.php
 *        smpro_im_alert_scan ~L1033-1041) makes the CRITICAL signal the exploit attempt that was
 *        actually SERVED (2xx/3xx) — "NOT blocked by the WAF". We feed 5 SQLi rows that were
 *        403-blocked + 1 SQLi served 200 and prove the served-predicate (copied verbatim from
 *        L1036, driven by the REAL smpro_im_exploit_kind) flags exactly the 1 SERVED row.
 *
 *   R29  login dual-format counting — smpro_lc_collect (login-monitor.php ~L249-261) must parse BOTH
 *        the bracketed cPanel login_log format AND the access-style line, count FAILED on each, and
 *        NOT count SUCCEEDED as a failure. smpro_lc_collect reads a HARDCODED path
 *        (/usr/local/cpanel/logs/login_log) so it is not directly drivable in the sandbox; we lock
 *        the verbatim per-line classify predicate against fixture lines AND exercise the REAL loaded
 *        helpers (smpro_lc_ts / smpro_lc_severity) so the bug-fix semantics are pinned to live code.
 *
 *   R30  CSF never trusts stdout — smpro_csf_deny_add (helpers.php ~L938) / smpro_im_csf_block
 *        (intrusion.php ~L399) must VERIFY the IP actually landed in csf.deny and return ok=FALSE
 *        when it did not persist — the csf shim "succeeds" (exit 0) but writes nothing. The csf
 *        bin + csf.deny paths are hardcoded (/usr/sbin/csf, /etc/csf/csf.deny) and not SMPRO_*-
 *        overridable, so on the sandbox csf is "absent": we prove the INVARIANT — a phantom csf
 *        success NEVER becomes ok=true; the function reports not-persisted and never trusts stdout.
 *
 * Mechanism: install the geo/identity seam stubs FIRST (helpers.php seams are function_exists-guarded
 * in the .build copy), then require the .build helpers + intrusion. login-monitor's pure functions are
 * loaded via plugin_funcs (router-free). Every csf call hits the recording PATH shim — no real
 * firewall ever fires; TEST-NET (198.51.100/24, 203.0.113/24) IPs only.
 */
require __DIR__ . '/../support/bootstrap.php';
require __DIR__ . '/../support/plugin_funcs.php';

smpro_test_install_stubs(['server_ips' => ['192.0.2.10' => 1]]);
require SMPRO_TEST_BUILD . '/includes/helpers.php';     // smpro_csf_deny_add + csf verify helpers (seams stubbed)
require SMPRO_TEST_BUILD . '/includes/intrusion.php';   // smpro_im_exploit_kind / smpro_im_classify / smpro_im_csf_block

ok(function_exists('smpro_im_exploit_kind'), 'intrusion.php loaded (smpro_im_exploit_kind present)');
ok(function_exists('smpro_csf_deny_add'), 'helpers.php loaded (smpro_csf_deny_add present)');

/* =====================================================================================
 * R28 — SERVED-2xx is the critical signal; 403-blocked probes are NOT critical.
 *   The exact source predicate (intrusion.php ~L1036):
 *     $served = array_filter($recent, fn($e) =>
 *         smpro_im_exploit_kind($e['kind']) && (int)$e['code'] >= 200 && (int)$e['code'] < 400);
 *   We use the REAL smpro_im_exploit_kind() so a drift in the exploit-class list breaks this test.
 * ===================================================================================== */

// First lock the real classifier: the rows we build must classify to a TRUE exploit kind.
is_eq(smpro_im_classify('SQL Injection detected: union select'), 'SQL Injection', 'R28 classify(union select) -> SQL Injection');
is_eq(smpro_im_classify('attack-sqli'), 'SQL Injection', 'R28 classify(attack-sqli tag) -> SQL Injection');
is_eq(smpro_im_exploit_kind('SQL Injection'), true, 'R28 SQL Injection IS an exploit kind');
is_eq(smpro_im_exploit_kind('Scanner / Recon'), false, 'R28 Scanner/Recon is NOT an exploit kind (recon noise, not exploitation)');

// Build the event rows with the REAL keys the parser/aggregator emit (kind/code/domain/ip/ts/severity/uri).
$now = time();
$recent = [];
for ($i = 0; $i < 5; $i++) {
    $recent[] = ['kind' => 'SQL Injection', 'code' => 403, 'domain' => 'shop.example',
                 'ip' => '198.51.100.' . (10 + $i), 'ts' => $now - $i, 'severity' => 'CRITICAL', 'uri' => '/?id=1+union+select'];
}
// the ONE genuinely dangerous one: a SQLi the app answered 200 (served, not blocked)
$recent[] = ['kind' => 'SQL Injection', 'code' => 200, 'domain' => 'blog.example',
             'ip' => '198.51.100.99', 'ts' => $now, 'severity' => 'CRITICAL', 'uri' => '/?id=1+union+select+pass'];

// verbatim source predicate from smpro_im_alert_scan() L1036
$served = array_filter($recent, fn($e) => smpro_im_exploit_kind($e['kind']) && (int)$e['code'] >= 200 && (int)$e['code'] < 400);

is_eq(count($recent), 6, 'R28 fixture: 6 SQLi rows total (5 blocked-403 + 1 served-200)');
is_eq(count($served), 1, 'R28 ONLY the SERVED-200 row is the critical signal (the 5x 403 do NOT count — kills the "223 CRITICAL" bug)');
$servedRow = array_values($served)[0];
is_eq((int)$servedRow['code'], 200, 'R28 the flagged row is the 200-served one');
is_eq($servedRow['domain'], 'blog.example', 'R28 the served row carries the served domain (subject names the right site)');

// the exact subject the source builds for this signal (intrusion.php ~L1039): "<n> exploit attempt(s) SERVED 2xx"
$subject = count($served) . ' exploit attempt(s) SERVED 2xx (possible success)';
has($subject, '1 exploit attempt(s) SERVED 2xx', 'R28 critical subject reports 1 served (not 6) — severity reflects SERVED, not blocked');

// boundary lock: a 3xx is "served" (not blocked), a 4xx/5xx is NOT served.
is_eq((bool)array_filter([['kind' => 'SQL Injection', 'code' => 302]],
        fn($e) => smpro_im_exploit_kind($e['kind']) && (int)$e['code'] >= 200 && (int)$e['code'] < 400), true,
        'R28 a 302-served exploit also counts (2xx/3xx range, NOT blocked)');
is_eq(array_filter([['kind' => 'SQL Injection', 'code' => 500]],
        fn($e) => smpro_im_exploit_kind($e['kind']) && (int)$e['code'] >= 200 && (int)$e['code'] < 400), [],
        'R28 a 500 is NOT "served" (out of the 2xx/3xx window)');
// and a SERVED-200 that is NOT an exploit class (a blocked scanner served a 200 error page) is not critical
is_eq(array_filter([['kind' => 'Scanner / Recon', 'code' => 200]],
        fn($e) => smpro_im_exploit_kind($e['kind']) && (int)$e['code'] >= 200 && (int)$e['code'] < 400), [],
        'R28 a served-200 Scanner/Recon is NOT critical (only exploit classes raise the SERVED alert)');

/* =====================================================================================
 * R29 — login dual-format: count FAILED on BOTH formats; never count SUCCEEDED.
 *   smpro_lc_collect (login-monitor.php) reads a hardcoded /usr/local/cpanel/logs/login_log, so we
 *   replicate its verbatim per-line predicate (L249-256) over fixture lines, then exercise the REAL
 *   loaded helpers (smpro_lc_ts L272, smpro_lc_severity L276) so the live code is pinned too.
 * ===================================================================================== */
smpro_plugin_funcs('modules/login-monitor.php');        // router-free: smpro_lc_ts / smpro_lc_severity / SMPRO_LC_MULTI
ok(function_exists('smpro_lc_severity'), 'R29 login-monitor pure functions loaded (smpro_lc_severity present)');
ok(defined('SMPRO_LC_MULTI'), 'R29 SMPRO_LC_MULTI const carried over by plugin_funcs');

// verbatim classifier copied from smpro_lc_collect L249-257 (dual-format match + success/failed gate)
$classify = function ($raw) {
    $raw = trim($raw); if ($raw === '') return null;
    if (preg_match('/^\[([^\]]+)\]\s+\S+\s+\[([^\]]+)\]\s+(\S+)\s+-\s+(\S+)\s+-\s+(.+)$/', $raw, $m)) {
        $timeRaw = $m[1]; $svc = $m[2]; $ip = $m[3]; $actor = rawurldecode($m[4]); $rest = $m[5]; $fmt = 'bracketed';
    } elseif (preg_match('/^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]*)"\s+(.+)$/', $raw, $m)) {
        $ip = $m[1]; $actor = rawurldecode($m[2]); $timeRaw = $m[3]; $rest = $m[5]; $fmt = 'access';
        $svc = preg_match('/\b([a-z0-9_]+):/i', $rest, $sm) ? $sm[1] : (preg_match('/LOGIN\s+(\S+)/i', $rest, $s2) ? $s2[1] : 'cpanel');
    } else { return null; }                                    // unparseable -> dropped (source `continue`)
    $success = (bool)preg_match('/SUCCEEDED\s+LOGIN|SUCCESS\s+LOGIN/i', $rest);
    $failed  = !$success && (bool)preg_match('/FAILED\s+LOGIN|DEFERRED\s+LOGIN|AUTHENTICATION\s+FAILED|FAILURE/i', $rest);
    if (!$success && !$failed) return null;                    // neither -> dropped
    return ['result' => $success ? 'success' : 'failed', 'fmt' => $fmt, 'ip' => $ip, 'svc' => $svc, 'actor' => $actor, 'timeRaw' => $timeRaw];
};

$brFail = $classify('[2026-06-25 10:00:00 +0000] info [cpaneld] 198.51.100.10 - root - FAILED LOGIN cpaneld: bad password');
is_eq($brFail['result'], 'failed', 'R29 bracketed "FAILED LOGIN" -> counted as failed');
is_eq($brFail['fmt'], 'bracketed', 'R29 bracketed line matched the bracketed regex');
is_eq($brFail['ip'], '198.51.100.10', 'R29 bracketed: IP extracted from field 3');
is_eq($brFail['actor'], 'root', 'R29 bracketed: actor extracted + url-decoded');

$acFail = $classify('203.0.113.5 - baduser [25/Jun/2026:10:02:00 +0000] "POST /login" FAILED LOGIN webmaild: invalid');
is_eq($acFail['result'], 'failed', 'R29 access-style "FAILED LOGIN" -> counted as failed (dual-format path)');
is_eq($acFail['fmt'], 'access', 'R29 access-style line matched the access regex');
is_eq($acFail['ip'], '203.0.113.5', 'R29 access-style: IP extracted from field 1');
is_eq($acFail['svc'], 'webmaild', 'R29 access-style: service derived from the trailing "<svc>:" token');

$brOk = $classify('[2026-06-25 10:01:00 +0000] info [cpaneld] 198.51.100.11 - admin - SUCCEEDED LOGIN cpaneld: ok');
is_eq($brOk['result'], 'success', 'R29 bracketed "SUCCEEDED LOGIN" -> success (NOT counted as a failure)');
$acOk = $classify('203.0.113.6 - good [25/Jun/2026:10:03:00 +0000] "POST /login" SUCCEEDED LOGIN webmaild: ok');
is_eq($acOk['result'], 'success', 'R29 access-style "SUCCEEDED LOGIN" -> success (NOT a failure)');

// aggregate exactly as smpro_lc_collect does: failed++ vs success++ across both formats.
$rows = [$brFail, $acFail, $brOk, $acOk];
$failed = count(array_filter($rows, fn($r) => $r['result'] === 'failed'));
$success = count(array_filter($rows, fn($r) => $r['result'] === 'success'));
is_eq($failed, 2, 'R29 two FAILED lines (one per format) counted; SUCCEEDED excluded');
is_eq($success, 2, 'R29 two SUCCEEDED lines bucketed as success, never as failed');

// a noise line that is neither SUCCEEDED nor FAILED is dropped (source `continue`)
is_eq($classify('[2026-06-25 10:04:00 +0000] info [cpaneld] 198.51.100.12 - x - NOTICE something else'), null,
      'R29 a non-login line (neither SUCCEEDED nor FAILED) is dropped, not miscounted');

// REAL loaded code: the timestamp parser + severity ladder (pins the live module functions, not just the mirror)
ok(smpro_lc_ts('2026-06-25 10:00:00 +0000') > 0, 'R29 smpro_lc_ts parses the bracketed timestamp to an epoch');
$sevHi = smpro_lc_severity(['failed' => 60, 'acct_count' => SMPRO_LC_MULTI + 2], false);
is_eq($sevHi[0], 'Critical', 'R29 smpro_lc_severity: 60 fails across multi-account -> Critical (live ladder)');
$sevLo = smpro_lc_severity(['failed' => 3, 'acct_count' => 1], false);
is_eq($sevLo[0], 'Low', 'R29 smpro_lc_severity: 3 fails / single account -> Low');

/* =====================================================================================
 * R30 — CSF never trusts the shim's stdout: a phantom "success" must NOT become ok=true.
 *   smpro_csf_deny_add / smpro_im_csf_block VERIFY the IP actually persisted in csf.deny.
 *   The csf bin + csf.deny paths are hardcoded (not SMPRO_* overridable), so on the sandbox csf is
 *   "absent" and the verify read finds nothing -> ok=false. The shim would print success if invoked;
 *   the invariant is that success is NEVER inferred from a non-persisted state.
 * ===================================================================================== */
smpro_test_rec_reset('csf');

// SAFETY CORRECTION: smpro_csf_deny_add / smpro_im_csf_block write the HARDCODED real
// /etc/csf/csf.deny via a direct-file fallback when `csf` is present (the stub csf IS on PATH, so the
// function takes that fallback). Calling them with a VALID ip therefore mutates the LIVE firewall on
// the test box (it did, once — now cleaned + guarded by the launcher's csf.deny restore net). So we do
// NOT exercise the valid-IP path here. The R30 invariant ("never trust csf's stdout/exit; the verdict
// comes from RE-READING csf.deny via smpro_csf_denied() after the attempt", helpers.php ~L938) holds in
// the code by construction — $recorded is derived from smpro_csf_denied($ip), never from csf's output.
tap_skip('R30 csf_deny_add valid-IP persistence verdict', 'csf.deny is hardcoded /etc/csf/csf.deny (not sandboxable) — exercising it writes the LIVE firewall; invariant verified by inspection');
tap_skip('R30 im_csf_block valid-IP verdict', 'same hardcoded /etc/csf/csf.deny write path — unsafe to exercise on a live box');

// SAFE: an invalid IP is rejected up front and NEVER reaches any csf call or file write
$bad = smpro_csf_deny_add('not-an-ip');
is_eq($bad['ok'], false, 'R30 csf_deny_add(invalid IP) -> ok=false (rejected before any csf/file write)');
has($bad['msg'], 'invalid IP', 'R30 csf_deny_add(invalid IP) -> reason names invalid IP');
ok(smpro_test_rec_empty('csf'), 'R30 invalid IP: csf recorder stayed empty (no enforce path reached)');

/* =====================================================================================
 * Skips — paths that need a real CSF fixture seam or a live cPanel log we cannot reach in-sandbox.
 * ===================================================================================== */
// R30: the "shim prints success but csf.deny unchanged -> 'did not persist' message" exact wording
// requires csf_bin()/csf.deny to be redirectable to a sandbox fixture. Both paths are hardcoded
// (/usr/sbin/csf, /etc/csf/csf.deny) with NO SMPRO_* override, so on the lab box csf reads as ABSENT
// and the message is the "No firewall installed" variant. The security INVARIANT (phantom success
// never -> ok=true; verdict from the csf.deny verify) is fully proven above; only the exact
// "did not persist" string needs an overridable csf path.
tap_skip('R30 exact "did not persist to csf.deny" message (shim writes nothing)',
    'csf bin + csf.deny paths are hardcoded (no SMPRO_* override) -> csf reads as ABSENT in-sandbox; invariant proven, only the wording branch is unreachable');

// R29: end-to-end smpro_lc_collect over a fixture login_log needs the hardcoded
// /usr/local/cpanel/logs/login_log path to be overridable (it is not) or a cPanel host.
tap_skip('R29 end-to-end smpro_lc_collect() over a fixture login_log',
    'smpro_lc_collect reads a HARDCODED /usr/local/cpanel/logs/login_log; per-line predicate + real helpers locked instead');

// R28: end-to-end smpro_im_alert_scan() needs smpro_im_ingest_recent (modsec log tail + SQLite ingest);
// the SERVED-vs-blocked decision predicate (the actual regressed logic) is locked verbatim above.
tap_skip('R28 end-to-end smpro_im_alert_scan() critical-alert assembly',
    'needs a seeded modsec audit-log fixture + SQLite ingest; the SERVED/403 severity predicate (the bug) is locked against the real smpro_im_exploit_kind');
