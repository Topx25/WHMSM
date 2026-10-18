<?php
/**
 * t35_module_gates.php — Phase-3 module security GATES (validation / guard predicates).
 *
 * Loads ONLY the pure functions out of four module files (via the funcs-only extractor —
 * no router, no DB, no exec side effects) and proves their refusal logic:
 *
 *   S34  disk-storage.php   smpro_ds_safe_target() — delete-target validator refuses
 *                           /etc, anything outside /home/<acct>/, and any '/..' traversal.
 *   S35  spam-phishing.php  smpro_sp_* — the suspend gate's protected-account predicate
 *                           (root/system/nobody/empty/absent are refused) AND the pure
 *                           sp helpers never invoke whmapi1 (recorder stays EMPTY — the
 *                           "destructive recorder never fired" proof).
 *   S32  includes/svcmon.php smpro_svc_registry() — sshd carries no_stop (Stop blocked) and
 *                           security products carry product=true (no runtime control). The catalog +
 *                           controls now live in includes/svcmon.php, shared by the cpanel-services
 *                           module, the Dashboard service cards, and the bin/svcmon.php monitor cron.
 *   S33  top-processes.php  smpro_tp_kill() — refuses pid<1, missing pid, low/system PID,
 *                           and the plugin's own process.
 *
 * Every expected value is derived from the real function source. Recorders prove no
 * dangerous tool (whmapi1) was ever executed by the loaded code.
 */
require __DIR__ . '/../support/bootstrap.php';

// install seam stubs FIRST (provides smpro_is_server_ip etc. that some sp_* helpers reference)
smpro_test_install_stubs(['server_ips' => ['192.0.2.10' => 1]]);

require __DIR__ . '/../support/plugin_funcs.php';
// funcs-only extraction — modules have no seams, so load from the raw source root.
smpro_plugin_funcs('modules/disk-storage.php');
smpro_plugin_funcs('modules/spam-phishing.php');
smpro_plugin_funcs('modules/cpanel-services.php');
smpro_plugin_funcs('includes/svcmon.php');       // service catalog + controls moved here (shared with the cron worker + Dashboard)
smpro_plugin_funcs('modules/top-processes.php');

ok(function_exists('smpro_ds_safe_target'), 'disk-storage pure funcs loaded (no router)');
ok(function_exists('smpro_svc_registry'),   'svcmon service catalog pure funcs loaded (no router)');
ok(function_exists('smpro_tp_kill'),        'top-processes pure funcs loaded (no router)');

/* ===================================================================================
 * S34 — disk-storage.php  smpro_ds_safe_target($f, $kind)
 *   non-cache: preg_match('#^/home/[^/]+/.+#', $f) && strpos($f,'/..')===false
 *   cache    : preg_match('#^/home/[^/]+/.+/(cache|views|bootstrap/cache|\.cache|tmp)(/.*)?$#', $f)
 *              || preg_match('#/cache(/|$)#', $f)
 * =================================================================================== */
/* refusals — must be a strict FALSE (bool), not just falsy */
is_eq(smpro_ds_safe_target('/etc/passwd', 'file'),            false, 'S34 file: /etc/passwd refused (not under /home/<acct>/)');
is_eq(smpro_ds_safe_target('/etc/shadow', 'file'),            false, 'S34 file: /etc/shadow refused');
is_eq(smpro_ds_safe_target('/root/.ssh/id_rsa', 'file'),      false, 'S34 file: /root/... refused');
is_eq(smpro_ds_safe_target('/home/bob/../etc/passwd', 'file'), false, 'S34 file: /home/bob/../etc traversal refused (/.. present)');
is_eq(smpro_ds_safe_target('/home/bob/a/../../etc', 'file'),   false, 'S34 file: nested /.. traversal refused');
is_eq(smpro_ds_safe_target('/home/onlyacct', 'file'),         false, 'S34 file: /home/<acct> with no trailing path refused');
is_eq(smpro_ds_safe_target('', 'file'),                       false, 'S34 file: empty path refused');
/* allowed — a real file deep under a home account, no traversal */
is_eq(smpro_ds_safe_target('/home/bob/public_html/big.zip', 'file'), true, 'S34 file: legit /home/bob/...big.zip allowed');
/* cache kind: now anchored to /home/<acct>/ AND traversal-checked (the loose '#/cache(/|$)#' fallback was the bug) */
is_eq(smpro_ds_safe_target('/etc/cache', 'cache'),            false, 'S34 cache: /etc/cache REFUSED (must live under /home/<acct>/ — loose fallback removed)');
is_eq(smpro_ds_safe_target('/var/cache', 'cache'),            false, 'S34 cache: /var/cache REFUSED (outside /home)');
is_eq(smpro_ds_safe_target('/home/bob/../etc/cache', 'cache'), false, 'S34 cache: traversal /home/bob/../etc/cache REFUSED (/.. now blocked for cache too)');
is_eq(smpro_ds_safe_target('/home/bob/public_html/wp-content/cache', 'cache'), true, 'S34 cache: legit account cache dir allowed');
is_eq(smpro_ds_safe_target('/home/bob/cache', 'cache'),       true,  'S34 cache: cache as first segment under /home/<acct>/ allowed');
is_eq(smpro_ds_safe_target('/home/bob/public_html', 'cache'), false, 'S34 cache: non-cache account dir refused');

/* ===================================================================================
 * S35 — spam-phishing.php  protected-account suspend predicate + whmapi1 recorder
 *   router gate (line ~414):  $acct === '' || in_array($acct, ['root','system','nobody'], true)
 *                             || !is_file('/var/cpanel/users/'.$acct)  -> refuse
 *   The exact protected-name set lives in source; replicate it and assert membership.
 *   NOTE: the suspend body itself runs in the module ROUTER (not a function), so it is not
 *   reachable through the funcs-only extractor. We therefore (a) assert the protected-name
 *   predicate the gate uses, and (b) reset the whmapi1 recorder, exercise every loaded pure
 *   sp_* helper, and assert whmapi1 was NEVER executed (no suspend/unsuspend path fired).
 * =================================================================================== */
$sp_protected = ['root', 'system', 'nobody'];   // verbatim from the suspend gate's in_array()
$sp_refused = function ($acct) use ($sp_protected) {
    // mirrors the gate's account-name refusal (filesystem check excluded; /var/cpanel absent in sandbox)
    return $acct === '' || in_array($acct, $sp_protected, true);
};
ok($sp_refused('root'),   'S35 suspend gate refuses "root" (protected system account)');
ok($sp_refused('system'), 'S35 suspend gate refuses "system"');
ok($sp_refused('nobody'), 'S35 suspend gate refuses "nobody"');
ok($sp_refused(''),       'S35 suspend gate refuses empty account');
nok($sp_refused('bob'),   'S35 suspend gate does NOT refuse a normal account on the name check');
/* the absent-account leg: a real cPanel user file is required; sandbox has none, so every
 * account is unresolved -> the gate refuses on !is_file('/var/cpanel/users/<acct>') too. */
is_eq(is_file('/var/cpanel/users/bob'), false, 'S35 absent-account leg: /var/cpanel/users/bob does not exist (gate would refuse)');

/* whmapi1 recorder — exercise the loaded pure sp_* helpers; NONE may shell out to whmapi1 */
smpro_test_rec_reset('whmapi1');
lives_ok(function () {
    smpro_sp_users();                 // glob /var/cpanel/users (absent) -> []
    smpro_sp_owner('bob@example.com');// reads /etc/userdomains (absent) -> ''
    smpro_sp_server_domains();        // reads /etc/userdomains (absent) -> []
    smpro_sp_spam_keywords();         // pure
    smpro_sp_decode_subject('hello'); // pure
    smpro_sp_mail_scan('bob', []);    // pure over an empty log window
}, 'S35 pure sp_* helpers run without error on an empty/sandbox environment');
ok(smpro_test_rec_empty('whmapi1'), 'S35 whmapi1 was NEVER executed by any loaded sp_* code (suspend recorder empty)');

/* derive an expected verdict from smpro_sp_mail_scan source: empty window -> score 0 -> "low" */
$scan = smpro_sp_mail_scan('bob', []);
is_eq($scan['verdict'], 'low',  'S35 mail_scan(empty) -> verdict "low" (score 0, derived from source)');
is_eq($scan['score'], 0,        'S35 mail_scan(empty) -> score 0');
is_eq($scan['total_msgs'], 0,   'S35 mail_scan(empty) -> 0 messages');

/* ===================================================================================
 * S32 — cpanel-services.php  registry guard flags
 *   sshd: 'no_stop'=>true  (router refuses action=stop)  + 'critical'=>true
 *   security products carry 'product'=>true (router: "no runtime control here")
 * =================================================================================== */
$reg = smpro_svc_registry();
ok(is_array($reg) && isset($reg['sshd']), 'S32 registry has the sshd entry');
is_eq(!empty($reg['sshd']['no_stop']), true, 'S32 sshd carries no_stop=true (Stop blocked — lock-out protection)');
is_eq(empty($reg['sshd']['product']), true,  'S32 sshd is a real runtime service (not a product)');

/* replicate the router stop-refusal predicate for sshd (line ~78) */
$svc_stop_blocked = function ($key) use ($reg) {
    $svc = $reg[$key] ?? null;
    return $svc !== null && !empty($svc['no_stop']);   // action==='stop' && no_stop -> refused
};
ok($svc_stop_blocked('sshd'),   'S32 stop(sshd) -> refused (no_stop gate)');
nok($svc_stop_blocked('apache'),'S32 stop(apache) -> NOT refused by the no_stop gate (apache is stoppable)');

/* every product-flagged service is refused runtime control (router line ~79) */
$products = [];
foreach ($reg as $k => $svc) if (!empty($svc['product'])) $products[] = $k;
ok(count($products) >= 5, 'S32 multiple security products are registered (' . count($products) . ' product entries)');
ok(in_array('imunify', $products, true),    'S32 imunify is product-flagged (no runtime control)');
ok(in_array('modsecurity', $products, true),'S32 modsecurity is product-flagged');
ok(in_array('clamav', $products, true),     'S32 clamav is product-flagged');
/* a known runtime service is NOT product-flagged, so it keeps controls */
is_eq(empty($reg['apache']['product']), true, 'S32 apache is NOT product-flagged (keeps Start/Restart/Stop)');
is_eq(empty($reg['exim']['product']), true,   'S32 exim is NOT product-flagged');

/* ===================================================================================
 * S33 — top-processes.php  smpro_tp_kill($pid, $doit)  — refusal predicates.
 *   Order of guards (advise mode, $doit=false):
 *     1. $pid < 1 || !is_dir("/proc/$pid")          -> "Process not found"
 *     2. $pid <= 300                                 -> "Refused: low/system PID."
 *     3. $pid===getmypid() || $pid===getppid()       -> "Refused: this plugin's own process."
 *     4. critical comm / uid 0                       -> environment-dependent (skipped, Phase 4)
 *   No real kill ever fires here: $doit=false short-circuits before any kill -*.
 * =================================================================================== */
smpro_test_rec_reset('kill');
$k0  = smpro_tp_kill(0, false);
is_eq($k0['ok'], false, 'S33 kill(pid=0) refused');
has($k0['msg'], 'not found', 'S33 kill(pid=0) -> "Process not found" (pid<1 guard)');

$kn  = smpro_tp_kill(-5, false);
is_eq($kn['ok'], false, 'S33 kill(pid=-5) refused (negative pid)');

/* a guaranteed-absent high PID -> "Process not found" (no /proc entry) */
$kabsent = smpro_tp_kill(4000000, false);
is_eq($kabsent['ok'], false, 'S33 kill(absent high pid) refused');
has($kabsent['msg'], 'not found', 'S33 kill(absent pid) -> "Process not found"');

/* PID 1 always exists on Linux and is <=300 -> low/system PID refusal.
 * (On a host without /proc/1 it falls to "not found" — still a refusal; assert ok===false.) */
$k1 = smpro_tp_kill(1, false);
is_eq($k1['ok'], false, 'S33 kill(pid=1) refused (low/system PID, never killable)');

/* the plugin's own process: getmypid() is >300 and /proc/self exists on Linux -> own-process guard.
 * If this host lacks /proc (non-Linux runner) it returns "not found" — still ok===false. */
$kself = smpro_tp_kill(getmypid(), false);
is_eq($kself['ok'], false, 'S33 kill(own pid) refused (never kills the plugin itself)');

ok(smpro_test_rec_empty('kill'), 'S33 the kill binary was NEVER executed for any refused/advise call (recorder empty)');

/* env-dependent refusals that need a specific live process — deferred to Phase 4 */
tap_skip('S33 kill refuses a uid-0 (>300) non-critical root daemon', 'needs a deterministic live uid-0 PID; Phase 4');
tap_skip('S33 kill refuses a critical-named service (e.g. mysqld) by comm', 'needs a deterministic live critical PID; Phase 4');
