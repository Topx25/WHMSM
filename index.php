<?php
/**
 * Safety Monitor Pro (smpro) — front controller / router.
 * GET = read-only. State-changing actions (later) = POST + CSRF.
 * Routes + sidebar are generated from a single registry: includes/menu.php
 */
define('SMPRO_BOOT', 1);
// Dev-mode bypass — honored ONLY with a valid OFFLINE-SIGNED token bound to THIS machine (machine-id|hostname),
// verified here with the embedded offline public key. It is UNFORGEABLE without the offline private key, so a
// stray file, a copied token, or a spoofed /var/cpanel/mainip can NOT enable it (the old public-IP marker could).
// Fail-closed everywhere else: no token / bad signature => SMPRO_LIC_ENFORCE defaults to true (hard-gate).
if (is_file('/var/lib/smpro/.dev_mode') && function_exists('openssl_verify')) {
    $__dmSig = base64_decode(trim((string)@file_get_contents('/var/lib/smpro/.dev_mode')), true);
    $__dmMid = '';
    foreach (['/etc/machine-id', '/var/lib/dbus/machine-id'] as $__dmF) { if (is_readable($__dmF)) { $__dmMid = trim((string)@file_get_contents($__dmF)); if ($__dmMid !== '') break; } }
    $__dmPk = @openssl_pkey_get_public(
        "-----BEGIN PUBLIC KEY-----\n"
      . "MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA2OKZTIB4S7cqRnoTj0q0\n"
      . "rPGhqSOKT0lDggnza7QYhP0qFe1lH7s3j16varPsiFjBSBY9brHG5GGoS90PnwHx\n"
      . "YzNfOXZEIw3UCClaq6roveRN8w9du5egyb1ElXkpV2OXj42WKdMZ8tdA8hm/Q7jY\n"
      . "GmmS6+VObnLHrMJyfb03Hxn0G4ximuO77vmttKAkayIbc44e4rLgv3RRAfXNgBSr\n"
      . "XnFstDDrr7WbuSdscOnixKyK7DFezt5VL4atnxfj1RlDxgszpPyDC0+Z/Zb5iwr2\n"
      . "h5c3EWMAKejoYI30RtACMtJbSWAGBAQEgh55ZJb/DbysFlXPZlm3l0WUw3cccjc8\n"
      . "coHVj1G2csGsrURvRGUi4a3p6KsplGyfqDEZaF061LU1C9zS/+oxC5PhDseOs64G\n"
      . "SiCA+iSJKm9mwTIQvnxHOcgShwGUF07DsL2a1xsGdaHlWd1GBAOtnqMXwsYC5ChF\n"
      . "IO1aoVYQjV9psv6/7kHz/ZcAHvWQU/lolYWcMsEyQHmTAgMBAAE=\n"
      . "-----END PUBLIC KEY-----\n");
    if ($__dmPk && $__dmSig !== false && @openssl_verify('smpro-dev|' . $__dmMid . '|' . php_uname('n'), $__dmSig, $__dmPk, OPENSSL_ALGO_SHA256) === 1) {
        define('SMPRO_LIC_ENFORCE', false);
    }
}

require __DIR__ . '/includes/defines.php';
require __DIR__ . '/includes/env.php';
require __DIR__ . '/includes/mmdb.php';
require __DIR__ . '/includes/helpers.php';
smpro_page_fatal_guard();   // a fatal renders a box + a log line, never a blank page
require __DIR__ . '/includes/pkg.php';
require __DIR__ . '/includes/secret.php';
require __DIR__ . '/includes/license.php';
require __DIR__ . '/includes/loginfeed.php';
require __DIR__ . '/includes/evidence.php';           // the local evidence journal (keeps what the logs rotate away)          // where a SUCCESSFUL sign-in is really recorded (session_log)
require __DIR__ . '/includes/evship.php';             // and move it off the server, over the hub's encrypted relay
require __DIR__ . '/includes/geowall.php';            // country wall: the ipset rule that actually PREVENTS
                                                     // a login, as opposed to closing the door afterwards
require __DIR__ . '/includes/breakin.php';           // failed-login collection + network grouping + the verdict
                                                     // (was inside modules/account-audit.php, so nothing outside a
                                                     //  browser could reach it - see the header of that file)
require __DIR__ . '/includes/intrusion.php';
require __DIR__ . '/includes/forensics-engine.php';        // §3.0-3.2 + unified whitelist (consulted by the intrusion tick below)
require __DIR__ . '/includes/forensics-webattack.php';     // §3.3 web-attack + §3.4 auth correlation
require __DIR__ . '/includes/forensics-upload-breach.php'; // one-click upload-breach collector (smpro_ub_*) + cluster alert
require __DIR__ . '/includes/auth.php';
require __DIR__ . '/includes/csrf.php';
require __DIR__ . '/includes/ai.php';
require __DIR__ . '/includes/notify.php';
require __DIR__ . '/includes/profiles.php';
require __DIR__ . '/includes/update.php';
require __DIR__ . '/includes/integrity.php';
require __DIR__ . '/includes/reports.php';
require __DIR__ . '/includes/investigate.php';
require __DIR__ . '/includes/digest.php';
require __DIR__ . '/includes/tuning.php';
require __DIR__ . '/includes/domains.php';
require __DIR__ . '/includes/tgbot.php';
require __DIR__ . '/includes/cooler.php';
require __DIR__ . '/includes/load_investigate.php';
require __DIR__ . '/includes/mailblock.php';
require __DIR__ . '/includes/uinvestigate.php';
require __DIR__ . '/includes/maintenance.php';   // A1 swap-expand + A3 auto-purge scheduler (owns shared smpro_mnt_* helpers)
require __DIR__ . '/includes/disk_tmp.php';       // A2 /tmp-expand (uses smpro_mnt_*; MUST be required after maintenance.php)
require __DIR__ . '/includes/disk_home.php';      // A2b move-account-home-to-another-partition (uses smpro_mnt_* + smpro_dom_*; background worker in bin/home_move.php)
require __DIR__ . '/includes/disk_scan.php';      // A2c per-account cleanup scan helpers + background job (worker: bin/cleanscan.php)
require __DIR__ . '/includes/clearcache.php';     // B  Site Doctor platform-aware cache clear (uses smpro_inv_*)
require __DIR__ . '/includes/phstack.php';    // which app is in a web root + which files matter — shared with the account-side plugin
require __DIR__ . '/includes/phlock.php';     // the ROOT-only half: read and set the immutable bit (cron needs it too)
require __DIR__ . '/includes/ph_ignore.php';   // accounts force-unprotected on purpose — read by the intrusion cron tick, not only by the page
require __DIR__ . '/includes/spqueue.php';     // Safety Lock: the accounts' release requests, decided on the PHP Harden page
require __DIR__ . '/includes/sprules.php';     // and the operator's automatic-approval rules for them
// Without these two the PHP Harden page silently rendered without its pending-requests panel: the panel is
// guarded by function_exists(), so a missing include looked exactly like "no requests" - and every release
// request on a production server waited for ever.
require __DIR__ . '/includes/geohulk.php';
require __DIR__ . '/includes/loadhist.php';
require __DIR__ . '/includes/backupmon.php';   // backup auto-retry cron (cron_sync-able)     // 24 h load ring (cron-fed)
require __DIR__ . '/includes/ccfix.php';       // Compromise Check fixes + scheduled scan
require __DIR__ . '/includes/fwallow.php';        // Firewall recommended allow-lists + live fetch + auto-update (uses smpro_csf_allowlisted)
require __DIR__ . '/includes/svcmon.php';         // Service catalog + controls + background service monitor (auto-restart + notify; uses smpro_notify)
require __DIR__ . '/includes/migrate.php';
require __DIR__ . '/includes/migrate_da.php';
require __DIR__ . '/includes/migrate_da_convert.php';
require __DIR__ . '/includes/migrate_da_home.php';        // the bulk half: content, mail, dumps, packaging   // DirectAdmin -> cpmove translation   // DirectAdmin archive reader (stage one of that route)      // Restore & Migrate — drives cPanel's own transfer engine
require __DIR__ . '/includes/spincheck.php';        // processes holding a core while doing nothing
require __DIR__ . '/includes/croncheck.php';       // stuck scheduled jobs — the usual cause of high load with idle CPUs
require __DIR__ . '/includes/croncheck_fix.php';   // repairing one, with a verified copy first
require __DIR__ . '/includes/wpcron_fix.php';      // switching off WordPress's visitor-triggered cron
require __DIR__ . '/includes/insight.php';        // Dashboard "Daily insight" — rotating tip + live server-specific warnings
require __DIR__ . '/includes/phishscan.php';      // Spam & Phishing background phishing scan (detached worker + result polling)
require __DIR__ . '/includes/reboot.php';         // Reboot readiness checks + scheduled auto-reboot (re-verifies safety at fire time)
require __DIR__ . '/includes/diskio.php';         // Live per-disk I/O + temperature (shared by the Disk/Storage card's live poll)
require __DIR__ . '/includes/benchmark.php';      // Hardware benchmark (CPU/RAM/disk) inventory + detached-worker engine
require __DIR__ . '/includes/dbhealth.php';       // General MySQL/MariaDB slowness & health diagnostic (read-only gather + reversible dynamic fixes)
require __DIR__ . '/includes/benchdiag.php';      // Benchmark & Diagnostics hub: software/PHP + MySQL benchmarks, kernel/software troubleshooting, run history
require __DIR__ . '/includes/hub.php';
require __DIR__ . '/includes/legal.php';
require __DIR__ . '/includes/menu.php';
require __DIR__ . '/includes/shortcuts.php';
require __DIR__ . '/includes/layout.php';

// Boot self-heal: re-assert our /etc/cron.d files (they self-heal after a cPanel upcp wipe) + the /tmp watchdog.
// These are pure redundancy (each feature's own Save already writes its cron), so they do NOT need to run on every
// request. Skipping them on the dashboard's 2s live-poll (and other lightweight JSON/hub endpoints) and throttling
// them to ~once every 3 min keeps page loads and navigation snappy on busy servers. A full page load ≥3 min apart
// runs the whole set; upcp never wipes cron more often than that, so self-heal coverage is unchanged.
$__liteReq   = (($_GET['format'] ?? '') === 'json') || !empty($_GET['metric']) || !empty($_GET['hub_ajax']) || !empty($_GET['hub_render']) || !empty($_GET['tuning']) || !empty($_GET['domchk']) || !empty($_GET['live']);
$__selfhealF = (defined('SMPRO_VARLIB') ? SMPRO_VARLIB : '/var/lib/smpro') . '/.selfheal';
$__selfhealDue = !@is_file($__selfhealF) || (time() - (int)@filemtime($__selfhealF)) > 180;
if (!$__liteReq && $__selfhealDue) {
    @touch($__selfhealF);
    if (function_exists('smpro_upd_install_cron'))   { try { smpro_upd_install_cron(); }   catch (\Throwable $e) { if (function_exists('smpro_soft_fail')) smpro_soft_fail(basename(__FILE__) . ':' . __LINE__, $e); } }
    if (function_exists('smpro_hub_install_cron'))    { try { smpro_hub_install_cron(); }    catch (\Throwable $e) { if (function_exists('smpro_soft_fail')) smpro_soft_fail(basename(__FILE__) . ':' . __LINE__, $e); } }
    if (function_exists('smpro_ntf_cron_sync'))       { try { smpro_ntf_cron_sync(); }       catch (\Throwable $e) { if (function_exists('smpro_soft_fail')) smpro_soft_fail(basename(__FILE__) . ':' . __LINE__, $e); } }  // intrusion auto-response/auto-block scanner cron (when Emergency/auto-block is ON)
    if (function_exists('smpro_mnt_cron_sync'))       { try { smpro_mnt_cron_sync(); }       catch (\Throwable $e) { if (function_exists('smpro_soft_fail')) smpro_soft_fail(basename(__FILE__) . ':' . __LINE__, $e); } }  // auto-purge scheduler
    if (function_exists('smpro_ds_tmp_watchdog'))     { try { smpro_ds_tmp_watchdog(); }     catch (\Throwable $e) { if (function_exists('smpro_soft_fail')) smpro_soft_fail(basename(__FILE__) . ':' . __LINE__, $e); } }  // /tmp-expand crash watchdog
    if (function_exists('smpro_fw_allow_cron_sync'))  { try { smpro_fw_allow_cron_sync(); }  catch (\Throwable $e) { if (function_exists('smpro_soft_fail')) smpro_soft_fail(basename(__FILE__) . ':' . __LINE__, $e); } }  // firewall allow-list auto-update cron self-heal
    if (function_exists('smpro_svcmon_cron_sync'))    { try { smpro_svcmon_cron_sync(); }    catch (\Throwable $e) { if (function_exists('smpro_soft_fail')) smpro_soft_fail(basename(__FILE__) . ':' . __LINE__, $e); } }  // service-monitor cron self-heal (auto-restart + notify)
    if (function_exists('smpro_swapcycle_cron_sync')) { try { smpro_swapcycle_cron_sync(); } catch (\Throwable $e) { if (function_exists('smpro_soft_fail')) smpro_soft_fail(basename(__FILE__) . ':' . __LINE__, $e); } }  // auto swap-cycle cron self-heal (OOM-safe)
    if (function_exists('smpro_fw_live_apply_all'))   { try { smpro_fw_live_apply_all(); }   catch (\Throwable $e) { if (function_exists('smpro_soft_fail')) smpro_soft_fail(basename(__FILE__) . ':' . __LINE__, $e); } }  // re-insert admin live-allow IPs into iptables (survive reboot/firewall flush; works with no CSF)
    if (function_exists('smpro_reboot_cron_sync'))    { try { smpro_reboot_cron_sync(); }    catch (\Throwable $e) { if (function_exists('smpro_soft_fail')) smpro_soft_fail(basename(__FILE__) . ':' . __LINE__, $e); } }  // scheduled-reboot cron self-heal (re-assert or clear the one-shot)
    if (function_exists('smpro_bd_sample_cron_sync')) { try { smpro_bd_sample_cron_sync(); } catch (\Throwable $e) { if (function_exists('smpro_soft_fail')) smpro_soft_fail(basename(__FILE__) . ':' . __LINE__, $e); } }  // hardware workload sampler (5-min peaks → the 7-day hardware-fit report)
    if (function_exists('smpro_login_guard_install_cron')) { try { smpro_login_guard_install_cron(); } catch (\Throwable $e) { if (function_exists('smpro_soft_fail')) smpro_soft_fail('login_guard_cron', $e); } }   // was run on EVERY request, including the 2-second poll
    if (function_exists('smpro_ds_home_cron_sync'))   { try { smpro_ds_home_cron_sync(); }   catch (\Throwable $e) { if (function_exists('smpro_soft_fail')) smpro_soft_fail(basename(__FILE__) . ':' . __LINE__, $e); } }  // account-move resume watchdog (installed only while a move is unfinished)
}

// index.cgi invokes PHP as CLI, which does NOT auto-populate superglobals from
// the CGI environment. Rebuild $_GET (and $_POST for forms later) ourselves.
// parse_str() is NOT bounded by max_input_vars/post_max_size (those only cap the normal SAPI), so cap the raw
// input first — keeps the CLI-rebuilt superglobals within the same envelope a normal PHP SAPI would enforce.
if (empty($_GET) && ($qs = getenv('QUERY_STRING'))) {
    parse_str(substr((string)$qs, 0, 131072), $_GET);                 // 128KB query string ceiling
    if (count($_GET, COUNT_RECURSIVE) > 2000) $_GET = [];             // param-flood guard (CLI SAPI drops max_input_vars)
}
if (($_SERVER['REQUEST_METHOD'] ?? getenv('REQUEST_METHOD')) === 'POST' && empty($_POST)) {
    $__raw = (string)stream_get_contents(fopen('php://stdin', 'r'), 4194304);             // 4MB POST body ceiling
    // parse_str understands ONE encoding: application/x-www-form-urlencoded. Handed a multipart body it does not
    // fail — it quietly yields nothing usable, so every field is missing, the handler that was addressed never
    // runs, and the caller receives the whole page instead of its answer. That took a long time to find, because
    // the symptom (a dialog saying it could not load) looks like anything except an encoding mismatch. Nothing
    // here can read multipart, so a request that sends it is a bug at the caller and is now told so on arrival
    // rather than being answered with a page that nothing will parse.
    $__ct = (string)($_SERVER['CONTENT_TYPE'] ?? (getenv('CONTENT_TYPE') ?: ''));
    if (stripos($__ct, 'multipart/form-data') !== false) {
        http_response_code(415);
        header('Content-Type: application/json');
        echo json_encode(['ok' => false, 'msg' => 'This endpoint reads url-encoded form data; the request sent multipart, so none of its fields arrived.'], JSON_UNESCAPED_SLASHES);
        exit;
    }
    parse_str($__raw, $_POST);
    if (count($_POST, COUNT_RECURSIVE) > 2000) $_POST = [];           // param-flood guard (byte cap doesn't bound var count)
}

// RULE: a state-changing action, once started on the server, must RUN TO COMPLETION even if the admin closes the
// tab / navigates away mid-request. ignore_user_abort keeps the PHP process alive past a client disconnect for POST
// actions (the truly long jobs — scans, /tmp expand, DB deep-scan — additionally run as detached workers). The
// results are then waiting when the admin re-opens the page. A companion hint is shown on every page (layout.php).
if (strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? getenv('REQUEST_METHOD') ?: 'GET')) === 'POST') {
    @ignore_user_abort(true);
}

// Defense-in-depth gate: every request must come from a WHM session (or CLI).
smpro_require_whm_access();

// Anti-tamper gate: if a protected file was modified (e.g. patching out the licence gate), lock down.
if (function_exists('smpro_integrity_gate')) { try { smpro_integrity_gate(); } catch (\Throwable $e) { if (function_exists('smpro_soft_fail')) smpro_soft_fail(basename(__FILE__) . ':' . __LINE__, $e); } }


// ---- LICENSE GATE: when enforcement is on and the license is not valid, NOTHING in the
// plugin opens. License activation traffic is always allowed; everything else is blocked
// (JSON endpoints → error, page requests → forced to the License page + auto-redirect). ----
$SMPRO_LIC_GATE = false;
if (SMPRO_LIC_ENFORCE && function_exists('smpro_lic_is_valid')) {
    smpro_lic_ensure_fresh();   // warm async, or block-check if past the 10-min hard window
    $licReqPage = isset($_GET['page']) && in_array(strtolower((string)$_GET['page']), ['license', 'licence', 'licensing', 'activation'], true);
    $licReqApi  = ($_GET['license'] ?? '') !== '';                 // activate/check/deactivate endpoint
    if (function_exists('smpro_lic_kill_tick')) smpro_lic_kill_tick();   // confirmed-tamper >48h → self-uninstall (no-op otherwise)
    if (!smpro_lic_is_valid() && !$licReqPage && !$licReqApi) {
        // Tamper is handled SILENTLY — no countdown / no "auto-remove" warning is ever shown to the customer
        // (the only alert goes to the admin via the license server). A tampered box just sees the neutral
        // "license could not be verified" message, exactly like a transport outage.
        $unreachable = function_exists('smpro_lic_is_unreachable') && smpro_lic_is_unreachable();
        $msg = $unreachable ? smpro_lic_support_message() : ('License required — activate ' . SMPRO_NAME . ' to use this.');
        if (($_GET['format'] ?? '') === 'json' || ($_GET['ai_assist'] ?? '') === '1' || ($_GET['env_install'] ?? '') !== '') {
            header('Content-Type: application/json');
            echo json_encode(['ok' => false, 'error' => $msg, 'license_required' => true, 'support' => $unreachable], JSON_UNESCAPED_UNICODE);
            exit;
        }
        $_GET['page'] = 'license';   // force the router to render ONLY the License page
        $SMPRO_LIC_GATE = true;      // layout adds a client-side redirect so the URL becomes ?page=license
        $GLOBALS['SMPRO_LIC_UNREACHABLE'] = $unreachable;
    }
    // Fast, non-blocking endpoint-redirect check on page load (no network on web) — flips to full-stop instantly
    // the moment the panel is opened on a blackholed box, instead of waiting for the next cron.
    if (function_exists('smpro_lic_tlm_sync')) { try { smpro_lic_tlm_sync(); } catch (\Throwable $e) { if (function_exists('smpro_soft_fail')) smpro_soft_fail(basename(__FILE__) . ':' . __LINE__, $e); } }
    // Connection-loss ladder: advance the accumulator on page load too (read-only — no network/notify on web).
    if (function_exists('smpro_lic_sync_tick')) { try { smpro_lic_sync_tick(); } catch (\Throwable $e) { if (function_exists('smpro_soft_fail')) smpro_soft_fail(basename(__FILE__) . ':' . __LINE__, $e); } }
}

// --- Multi-Server: if a Hub manages this server, pull & run its plugin-scoped commands
//     (throttled ~90s, granted-permission gated). Skipped on JSON/live endpoints to stay fast. ---
if (($_GET['format'] ?? '') !== 'json' && empty($_GET['metric']) && empty($_GET['hub_ajax']) && empty($_GET['hub_render']) && empty($_GET['live'])
    && function_exists('smpro_hub_member_tick') && function_exists('smpro_hub_active') && smpro_hub_active()) {
    try { smpro_hub_member_tick(); } catch (\Throwable $e) { if (function_exists('smpro_soft_fail')) smpro_soft_fail(basename(__FILE__) . ':' . __LINE__, $e); }
}

// --- Multi-Server Hub actions (pair / manage / member-approve). POST + CSRF + root. JSON. ---
if (($_GET['hub_ajax'] ?? '') !== '') {
    header('Content-Type: application/json');
    if (strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? getenv('REQUEST_METHOD') ?: 'GET')) !== 'POST') { echo json_encode(['ok'=>false,'msg'=>'POST required']); exit; }
    smpro_require_valid_csrf('hub'); smpro_require_root();
    if (!function_exists('smpro_hub_enabled') || !smpro_hub_enabled()) { echo json_encode(['ok'=>false,'msg'=>'Multi-Server is an Ultra feature.']); exit; }
    $act = preg_replace('/[^a-z_]/', '', strtolower((string)($_POST['hub_action'] ?? '')));
    $perms = array_map('strval', (array)($_POST['perms'] ?? []));
    $lid = (int)($_POST['link_id'] ?? 0);
    $resp = ['ok'=>false,'msg'=>'unknown action'];
    // PAIRING REQUIRES a control password to EXIST first. The password derives the E2E secret the relay never
    // sees (sha256('smpro-e2e|'+pw)); without it the ECDH handshake has no relay-invisible binding and a hostile
    // relay could MITM the key exchange. So refuse to pair on a server with no control password set.
    if (in_array($act, ['init','approve'], true) && function_exists('smpro_hub_cpass_isset') && !smpro_hub_cpass_isset()) {
        echo json_encode(['ok'=>false,'msg'=>'Set a control password first (Multi-Server → control password) — it secures the end-to-end channel between paired servers. Use the SAME password on both servers.']); exit;
    }
    // independent control password: gate PAIRING (init/approve) + actions (push) — the token alone is not enough
    if (in_array($act, ['push','init','approve'], true) && function_exists('smpro_hub_cpass_isset') && smpro_hub_cpass_isset()) {
        if (!smpro_hub_cpass_unlocked()) { echo json_encode(['ok'=>false,'locked'=>true,'msg'=>'Enter the control password to pair or manage servers.']); exit; }
        smpro_hub_cpass_unlock();   // SLIDING idle timeout: refresh on each action so active work is never interrupted (re-locks after 15 min idle)
    }
    // step-up authorization: performing an ACTION on a member requires proving the member's control password —
    // first time, then again only when an UNDISCLOSED security rule fires (see smpro_hub_needs_verify). The UI
    // is never told WHICH rule triggered (just needverify) so the rule-set stays opaque to anyone watching.
    // ONLY actions (push) are gated — read-only viewing (render/proxy/live) is open so the panel always opens,
    // and by the time the operator acts the member is already live, so the verify round-trip completes fast.
    if ($act === 'push' && function_exists('smpro_hub_needs_verify')) {
        $vsnap = null;
        if (function_exists('smpro_hub_fleet_cached')) foreach (smpro_hub_fleet_cached() as $F) {
            if ((int)($F['link']['link_id'] ?? 0) === $lid) { $vsnap = is_array($F['snap'] ?? null) ? $F['snap'] : []; $vsnap['_mip'] = (string)($F['link']['member_ip'] ?? ''); break; }
        }
        if (smpro_hub_needs_verify($lid, (string)($_POST['cmd'] ?? ''), $vsnap) !== '') {
            echo json_encode(['ok'=>false,'needverify'=>true,'msg'=>'Security check — enter the managed server\'s control password to continue.']); exit;
        }
    }
    switch ($act) {
        case 'verify': {
            $mip = '';
            if (function_exists('smpro_hub_fleet_cached')) foreach (smpro_hub_fleet_cached() as $F) { if ((int)($F['link']['link_id'] ?? 0) === $lid) { $mip = (string)($F['link']['member_ip'] ?? ''); break; } }
            $v = smpro_hub_verify_link($lid, (string)($_POST['pw'] ?? ''), $mip);
            $resp = ['ok'=>!empty($v['ok'])] + (array)$v;
            if (empty($v['ok'])) {
                if (!empty($v['locked'])) {
                    $resp['msg'] = 'Remote control is locked after too many wrong control-password attempts'
                        . (!empty($v['until']) ? ' (until ' . date('Y-m-d H:i', (int)$v['until']) . ')' : '')
                        . '. Wait it out, or reset the lock (allowed once per 24h) from the managed server or here. '
                        . 'If this was not you, change the server root password, change the control password, and re-create the pairing token.';
                } else {
                    $resp['msg'] = !empty($v['nopass']) ? 'The managed server has no control password set — set one there first.'
                        : (!empty($v['notready']) ? 'Secure channel not ready yet (still establishing the encrypted link). Wait ~60s and try again.'
                        : (!empty($v['timeout']) ? 'The managed server did not answer yet (it comes online within ~60s). Try again.' : 'Wrong password.'));
                }
            }
            break;
        }
        case 'cpass_set': {
            smpro_require_root();
            // The control password is the step-up credential that is INDEPENDENT of the root session (and half of the
            // fleet channel key). Replacing or removing it must prove the current one, else a hijacked session resets
            // it in one request and then drives every managed server. Five tries per five minutes, like the member side.
            if (function_exists('smpro_ratelimit') && !smpro_ratelimit('hub_cpass', 5, 300)) { $resp = ['ok'=>false, 'msg'=>'Too many attempts — try again in a few minutes.']; break; }
            if (smpro_hub_cpass_isset() && !smpro_hub_cpass_verify((string)($_POST['old_pw'] ?? ''))) { $resp = ['ok'=>false, 'msg'=>'The current control password is required to change or remove it.', 'need_old'=>1]; break; }
            $resp = ['ok'=>smpro_hub_cpass_set((string)($_POST['pw'] ?? '')), 'isset'=>smpro_hub_cpass_isset()]; break;
        }
        case 'cpass_unlock':
            if (function_exists('smpro_ratelimit') && !smpro_ratelimit('hub_cpass', 5, 300)) { $resp = ['ok'=>false, 'msg'=>'Too many attempts — try again in a few minutes.']; break; }
            $ok = smpro_hub_cpass_verify((string)($_POST['pw'] ?? '')); if ($ok) smpro_hub_cpass_unlock(); $resp = ['ok'=>$ok, 'msg'=>$ok?'unlocked':'wrong password']; break;
        case 'reset_lock':     smpro_require_root(); $resp = smpro_hub_lock_reset('local'); break;          // MEMBER: clear OUR own brute-force lock (once/24h)
        case 'hub_reset_lock': smpro_require_root(); $resp = smpro_hub_reset_lock_request($lid); break;      // HUB master: ask the managed server to reset its lock
        case 'init':    [$ok,$d] = smpro_hub_init((string)($_POST['label'] ?? ''), $perms, (string)($_POST['target'] ?? ''), (string)($_POST['mode'] ?? 'control')); $resp = ['ok'=>$ok] + (array)$d; break;
        case 'invites': $resp = ['ok'=>true,'invites'=>smpro_hub_invites()]; break;
        case 'links':   $lk = smpro_hub_links((string)($_POST['role'] ?? 'hub')); foreach ($lk as &$_L) { if (is_array($_L)) unset($_L['pair_code']); } unset($_L); $resp = ['ok'=>true,'links'=>$lk]; break;   // never expose the secret token to the browser
        case 'revoke':  [$ok,$d] = smpro_hub_revoke($lid); $resp = ['ok'=>$ok] + (array)$d; break;
        case 'push':    [$ok,$d] = smpro_hub_push_cmd($lid, (string)($_POST['cmd'] ?? ''), (array)($_POST['args'] ?? [])); $resp = ['ok'=>$ok] + (array)$d; break;
        case 'pull':    $resp = ['ok'=>true,'items'=>smpro_hub_pull($lid, (string)($_POST['dir'] ?? 'status'))]; break;
        case 'lookup':  [$ok,$d] = smpro_hub_lookup((string)($_POST['code'] ?? '')); $resp = ['ok'=>$ok] + (array)$d; break;
        case 'approve': [$ok,$d] = smpro_hub_approve((string)($_POST['code'] ?? ''), $perms); $resp = ['ok'=>$ok] + (array)$d; break;
        case 'tick':    $resp = ['ok'=>true,'tick'=>smpro_hub_member_tick(true)]; break;
        case 'snapshot':$resp = ['ok'=>true,'snapshot'=>smpro_hub_status_snapshot()]; break;
        case 'set_enabled': smpro_hub_set_disabled(empty($_POST['on'])); $resp = ['ok'=>true,'disabled'=>smpro_hub_locally_disabled()]; break;
        case 'live':    [$ok,$d] = smpro_hub_live($lid); $resp = ['ok'=>$ok] + (array)$d; break;
        case 'render':  [$ok,$html] = smpro_hub_render_request($lid, (string)($_POST['rpage'] ?? 'dashboard')); $resp = ['ok'=>$ok,'html'=>$html]; break;
        case 'proxy':   [$ok,$html] = smpro_hub_proxy_request($lid, (string)($_POST['q'] ?? 'page=dashboard')); $resp = ['ok'=>$ok,'html'=>$html]; break;
    }
    echo json_encode($resp, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit;
}

// --- Install a missing optional component via the OS package manager. POST+CSRF+root. JSON. ---
if (($_GET['env_install'] ?? '') !== '') {
    $reqM = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? getenv('REQUEST_METHOD') ?: 'GET'));
    header('Content-Type: application/json');
    if ($reqM !== 'POST') { echo json_encode(['ok' => false, 'msg' => 'POST required']); exit; }
    smpro_require_valid_csrf('env_install'); smpro_require_root();
    $key = preg_replace('/[^a-z0-9_]/', '', strtolower((string)($_POST['component'] ?? '')));
    [$ok, $detail] = smpro_env_install($key);
    echo json_encode(['ok' => $ok, 'msg' => $detail], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit;
}

// --- Accept the Terms & Legal (first-run acceptance gate). POST + CSRF + root. JSON. ---
if (($_GET['legal_accept'] ?? '') !== '') {
    header('Content-Type: application/json');
    if (strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? getenv('REQUEST_METHOD') ?: 'GET')) !== 'POST') { echo json_encode(['ok' => false, 'msg' => 'POST required']); exit; }
    smpro_require_valid_csrf('legal'); smpro_require_root();
    echo json_encode(['ok' => function_exists('smpro_legal_accept') ? smpro_legal_accept() : false]); exit;
}

// --- Self allow-list: add THIS admin's IP to csf.allow (full, never block). POST + CSRF + root. JSON. ---
if (($_GET['fw_self'] ?? '') !== '') {
    header('Content-Type: application/json');
    if (strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? getenv('REQUEST_METHOD') ?: 'GET')) !== 'POST') { echo json_encode(['ok'=>false,'msg'=>'POST required']); exit; }
    smpro_require_valid_csrf('fw_self'); smpro_require_root();
    $ip = function_exists('smpro_admin_ip') ? smpro_admin_ip() : '';
    if (!filter_var($ip, FILTER_VALIDATE_IP)) { echo json_encode(['ok'=>false,'msg'=>'No detectable admin IP']); exit; }
    $st = smpro_fw_self_state();
    if ((string)($_GET['fw_self']) === 'dismiss') {
        $st[$ip] = ['d'=>'dismissed','ts'=>time()]; smpro_fw_self_state_save($st);
        smpro_audit('firewall_self_allow', ['ip'=>$ip,'decision'=>'dismissed']);
        echo json_encode(['ok'=>true,'dismissed'=>true]); exit;
    }
    $r = smpro_csf_allow_add($ip, 'admin IP (self) - never block');
    if (!empty($r['ok'])) { $st[$ip] = ['d'=>'added','ts'=>time()]; smpro_fw_self_state_save($st); }
    smpro_audit('firewall_self_allow', ['ip'=>$ip,'decision'=>'added','ok'=>!empty($r['ok'])]);
    echo json_encode(['ok'=>!empty($r['ok']),'ip'=>$ip,'msg'=>(string)$r['msg']], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit;
}

// --- License actions (activate / re-check / deactivate). POST + CSRF + root. JSON. ---
if (($_GET['license'] ?? '') !== '') {
    $reqM = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? getenv('REQUEST_METHOD') ?: 'GET'));
    header('Content-Type: application/json');
    if ($reqM !== 'POST') { echo json_encode(['ok' => false, 'msg' => 'POST required']); exit; }
    smpro_require_valid_csrf('license'); smpro_require_root();
    $act = preg_replace('/[^a-z]/', '', strtolower((string)($_POST['lic_action'] ?? '')));
    if ($act === 'activate') {
        if (function_exists('smpro_ratelimit') && !smpro_ratelimit('lic_activate', 10, 60)) { echo json_encode(['ok' => false, 'msg' => 'Too many attempts — wait a minute and try again.']); exit; }
        $key = trim((string)($_POST['key'] ?? ''));
        if ($key === '') { echo json_encode(['ok' => false, 'msg' => 'Enter a license key.']); exit; }
        $st = smpro_lic_activate($key);
    } elseif ($act === 'check') {
        $st = smpro_lic_check();
    } elseif ($act === 'deactivate') {
        smpro_lic_deactivate(); echo json_encode(['ok' => true, 'msg' => 'License removed from this server.']); exit;
    } else { echo json_encode(['ok' => false, 'msg' => 'Unknown action.']); exit; }
    echo json_encode([
        'ok'      => !empty($st['ok']),
        'status'  => $st['status'] ?? '',
        'message' => $st['message'] ?? '',
        'expiry'  => $st['expiry'] ?? '',
        'plan'    => $st['plan'] ?? '',
        'http'    => $st['http'] ?? 0,
        'valid'   => smpro_lic_is_valid(),
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}

// --- Update endpoint (check / apply / auto-toggle). POST + CSRF + root. JSON. ---
if (($_GET['update'] ?? '') !== '') {
    $reqM = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? getenv('REQUEST_METHOD') ?: 'GET'));
    header('Content-Type: application/json');
    if ($reqM !== 'POST') { echo json_encode(['ok' => false, 'msg' => 'POST required']); exit; }
    smpro_require_valid_csrf('update'); smpro_require_root();
    $act = preg_replace('/[^a-z]/', '', strtolower((string)($_POST['upd_action'] ?? '')));
    if ($act === 'check') { echo json_encode(smpro_upd_check(), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit; }
    if ($act === 'apply') { smpro_audit('self_update_manual', []); echo json_encode(smpro_upd_apply(), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit; }
    // FORCE: re-apply the current channel's latest signed build immediately, bypassing ONLY the version_compare
    // downgrade guard ($force=true) — the RSA package signature is STILL enforced, so it can only ever install a
    // genuinely-signed build the channel serves, never unsigned/forged code. Used to recover a broken/partial
    // install, re-pull a re-published build, or move a server off an out-of-order version string. Backup + reversible.
    if ($act === 'force') { smpro_audit('self_update_force', []); echo json_encode(smpro_upd_apply('', true), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit; }
    if ($act === 'auto')  { $c = smpro_upd_cfg(); $c['auto'] = !empty($_POST['on']); smpro_upd_cfg_save($c); smpro_audit('self_update_auto', ['on' => $c['auto']]); echo json_encode(['ok' => true, 'auto' => $c['auto']]); exit; }
    if ($act === 'channel') { $ch = (($_POST['channel'] ?? '') === 'beta') ? 'beta' : 'stable'; $c = smpro_upd_cfg(); $c['channel'] = $ch; smpro_upd_cfg_save($c); smpro_audit('self_update_channel', ['channel' => $ch]); echo json_encode(['ok' => true, 'channel' => $ch]); exit; }
    echo json_encode(['ok' => false, 'msg' => 'unknown action']); exit;
}

// --- Automatic reports endpoint (save schedule / generate now). POST + CSRF + root. JSON. ---
if (($_GET['autoreport'] ?? '') !== '') {
    $reqM = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? getenv('REQUEST_METHOD') ?: 'GET'));
    header('Content-Type: application/json');
    if ($reqM !== 'POST') { echo json_encode(['ok' => false, 'msg' => 'POST required']); exit; }
    smpro_require_valid_csrf('autoreport'); smpro_require_root();
    $act = preg_replace('/[^a-z]/', '', strtolower((string)($_POST['ar_action'] ?? '')));
    if ($act === 'save') {
        $cfg = smpro_rep_cfg();
        $cfg['enabled']     = !empty($_POST['enabled']);
        $iv = (string)($_POST['interval'] ?? 'weekly'); if (!in_array($iv, ['daily', '3days', 'weekly', 'monthly', 'custom'], true)) $iv = 'weekly';
        $cfg['interval']    = $iv;
        $cfg['custom_days'] = max(1, min(365, (int)($_POST['custom_days'] ?? 7)));
        $cfg['channels']    = ['panel' => !empty($_POST['ch_panel']), 'email' => !empty($_POST['ch_email']), 'telegram' => !empty($_POST['ch_telegram']), 'whatsapp' => !empty($_POST['ch_whatsapp'])];
        smpro_rep_cfg_save($cfg);
        smpro_audit('auto_report_cfg', ['interval' => $iv, 'enabled' => $cfg['enabled']]);
        echo json_encode(['ok' => true, 'next_days' => smpro_rep_days($cfg)]); exit;
    }
    if ($act === 'generate') { echo json_encode(smpro_rep_run(true), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit; }
    // --- grouped-alerts / quiet digest ---
    if ($act === 'dgsave' && function_exists('smpro_dg_cfg_save')) {
        $cfg = smpro_dg_cfg();
        $cfg['enabled']        = !empty($_POST['dg_enabled']);
        $cfg['interval_hours'] = max(1, min(168, (int)($_POST['dg_hours'] ?? 6)));
        smpro_dg_cfg_save($cfg);
        smpro_audit('digest_cfg', ['enabled' => $cfg['enabled'], 'hours' => $cfg['interval_hours']]);
        echo json_encode(['ok' => true, 'cfg' => $cfg]); exit;
    }
    if ($act === 'dgclassify' && function_exists('smpro_dg_ai_classify')) { echo json_encode(smpro_dg_ai_classify(), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit; }
    if ($act === 'dgflush'    && function_exists('smpro_dg_flush'))        { echo json_encode(smpro_dg_flush(true), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit; }
    echo json_encode(['ok' => false, 'msg' => 'unknown action']); exit;
}

// --- Telegram control bot: enable / disable / test. POST + CSRF + root. JSON. ---
if (($_GET['tgbot'] ?? '') !== '') {
    $reqM = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? getenv('REQUEST_METHOD') ?: 'GET'));
    header('Content-Type: application/json');
    if ($reqM !== 'POST') { echo json_encode(['ok' => false, 'msg' => 'POST required']); exit; }
    smpro_require_valid_csrf('tgbot'); smpro_require_root();
    $act = preg_replace('/[^a-z]/', '', strtolower((string)($_POST['tgb_action'] ?? '')));
    if ($act === 'enable')  { echo json_encode(smpro_tg_enable(true),  JSON_UNESCAPED_SLASHES); exit; }
    if ($act === 'disable') { echo json_encode(smpro_tg_enable(false), JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit; }
    if ($act === 'test')    { echo json_encode(smpro_tg_test(),        JSON_UNESCAPED_SLASHES); exit; }
    echo json_encode(['ok' => false, 'msg' => 'unknown action']); exit;
}

// --- Cooler mode: detect load source / throttle it for a duration / stop. POST+CSRF+root, except GET status. JSON. ---
if (($_GET['cooler'] ?? '') !== '') {
    header('Content-Type: application/json');
    if (!empty($SMPRO_LIC_GATE)) { echo json_encode(['ok' => false, 'error' => 'License required', 'license_required' => true], JSON_UNESCAPED_UNICODE); exit; }   // even the read-only status/sources/report GETs must not serve on an unlicensed/tampered box
    smpro_require_root();                                // status/sources expose the top-CPU process/PID list — root-only
    $reqM = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? getenv('REQUEST_METHOD') ?: 'GET'));
    // read from $_POST first (the CGI populates $_POST/$_GET manually — $_REQUEST may be unreliable here)
    $act  = preg_replace('/[^a-z]/', '', strtolower((string)($_POST['cool_action'] ?? $_GET['cool_action'] ?? 'status')));
    if ($act === 'status')  { echo json_encode(smpro_cool_status(), JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit; }
    if ($act === 'sources') { echo json_encode(['ok' => true] + smpro_cool_sources(8), JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit; }
    if ($act === 'investigate') { $ev = smpro_load_evidence(); echo json_encode(['ok' => true, 'ev' => $ev, 'diag' => smpro_load_diagnose($ev)], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit; }
    if ($act === 'autoplan')    { $ev = smpro_load_evidence(); echo json_encode(smpro_load_auto_plan($ev, smpro_load_diagnose($ev)), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit; }
    if ($act === 'report')      { echo json_encode(['ok' => true, 'rows' => array_reverse(smpro_load_overload_read())], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit; }
    if ($reqM !== 'POST') { echo json_encode(['ok' => false, 'msg' => 'POST required']); exit; }
    smpro_require_valid_csrf('cooler'); smpro_require_root();
    if ($act === 'start') {
        $pids = array_filter(array_map('intval', preg_split('/[,\s]+/', (string)($_POST['pids'] ?? ''))));
        $pct  = (int)($_POST['percent'] ?? 0); $min = (int)($_POST['minutes'] ?? 15);
        echo json_encode(smpro_cool_start($pids, $pct, $min), JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit;
    }
    if ($act === 'auto')  { echo json_encode(smpro_cool_auto((int)($_POST['minutes'] ?? 15), (int)($_POST['percent'] ?? 50)), JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit; }
    if ($act === 'guard') { $smGr = smpro_cool_guard_save([
        'enabled' => !empty($_POST['enabled']), 'ceiling' => (float)($_POST['ceiling'] ?? 20),
        'percent' => (int)($_POST['percent'] ?? 50), 'minutes' => (int)($_POST['minutes'] ?? 15),
        'topk' => (int)($_POST['topk'] ?? 3), 'min_cpu' => (int)($_POST['min_cpu'] ?? 25),
    ]); if (is_array($smGr)) $smGr['_via'] = 'guardsave'; echo json_encode($smGr, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit; }
    if ($act === 'stop')  { echo json_encode(smpro_cool_stop(), JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit; }
    if ($act === 'aidiagnose') { echo json_encode(smpro_load_ai_diagnose(smpro_load_evidence()), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit; }
    if ($act === 'cooluser')   { echo json_encode(smpro_load_cool_user((string)($_POST['user'] ?? ''), (string)($_POST['comm'] ?? ''), (int)($_POST['percent'] ?? 20), (int)($_POST['minutes'] ?? 15)), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit; }
    echo json_encode(['ok' => false, 'msg' => 'unknown action']); exit;
}

// --- Helper-tool one-click install (cpulimit / lm-sensors / whois / curl / e2fsprogs). POST + CSRF + root. JSON. ---
if (($_GET['pkg'] ?? '') !== '') {
    header('Content-Type: application/json');
    $reqM = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? getenv('REQUEST_METHOD') ?: 'GET'));
    if ($reqM !== 'POST') { echo json_encode(['ok' => false, 'msg' => 'POST required']); exit; }
    smpro_require_valid_csrf('pkg'); smpro_require_root();
    $tool = preg_replace('/[^a-z0-9_-]/', '', strtolower((string)($_POST['tool'] ?? '')));
    echo json_encode(smpro_pkg_install($tool), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit;
}

// --- Server Tune-up: backup configs / apply a recommendation. POST + CSRF + root. JSON. ---
if (($_GET['tuning'] ?? '') !== '') {
    $reqM = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? getenv('REQUEST_METHOD') ?: 'GET'));
    header('Content-Type: application/json');
    if ($reqM !== 'POST') { echo json_encode(['ok' => false, 'msg' => 'POST required']); exit; }
    smpro_require_valid_csrf('tuning'); smpro_require_root();
    $act = preg_replace('/[^a-z]/', '', strtolower((string)($_POST['tun_action'] ?? '')));
    // Any config-changing action makes the cached posture stale → bust it so the next render recomputes fresh.
    if (function_exists('smpro_cache_bust') && in_array($act, ['restore', 'apply', 'install', 'aioptimize', 'aiapplyall', 'secadvisorapply'], true)) smpro_cache_bust('tun_scan');
    if ($act === 'backup')  { $b = smpro_tun_backup_all(); echo json_encode(['ok' => true, 'id' => $b['id'], 'files' => count($b['files'])]); exit; }
    if ($act === 'restore') { $id = preg_replace('/[^0-9_a-z]/', '', (string)($_POST['bk_id'] ?? '')); echo json_encode(smpro_tun_restore($id), JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit; }
    if ($act === 'apply')   { $rid = preg_replace('/[^a-z0-9_]/', '', (string)($_POST['rec'] ?? '')); echo json_encode(smpro_tun_apply($rid), JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit; }
    if ($act === 'install') {
        $tgt = preg_replace('/[^a-z0-9_]/', '', strtolower((string)($_POST['target'] ?? '')));
        if ($tgt === 'csf' && function_exists('smpro_tun_install_csf')) { echo json_encode(smpro_tun_install_csf(), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit; }
        echo json_encode(['ok' => false, 'msg' => 'unsupported install target']); exit;
    }
    if ($act === 'aioptimize' && function_exists('smpro_tun_ai_optimize')) {
        $targets = array_filter(array_map(fn($t) => preg_replace('/[^a-z]/', '', strtolower($t)), preg_split('/[,\s]+/', (string)($_POST['targets'] ?? ''))));
        echo json_encode(smpro_tun_ai_optimize($targets), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit;
    }
    if ($act === 'secadvisor' && function_exists('smpro_tun_secadvisor')) {
        echo json_encode(smpro_tun_secadvisor(), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit;
    }
    // --- background variants: start a detached scan / poll its state (keeps running if the page is closed) ---
    if ($act === 'aioptimizestart' && function_exists('smpro_tun_job_start')) {
        $targets = array_values(array_filter(array_map(fn($t) => preg_replace('/[^a-z]/', '', strtolower($t)), preg_split('/[,\s]+/', (string)($_POST['targets'] ?? '')))));
        echo json_encode(smpro_tun_job_start('aioptimize', ['targets' => $targets]), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit;
    }
    if ($act === 'aioptimizestatus' && function_exists('smpro_tun_job_read')) { echo json_encode(smpro_tun_job_read('aioptimize'), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit; }
    if ($act === 'secadvisorstart' && function_exists('smpro_tun_job_start')) { echo json_encode(smpro_tun_job_start('secadvisor', []), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit; }
    if ($act === 'secadvisorstatus' && function_exists('smpro_tun_job_read')) { echo json_encode(smpro_tun_job_read('secadvisor'), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit; }
    if ($act === 'aiapplyall' && function_exists('smpro_tun_ai_apply_all')) {   // bulk-apply the AI suggestions that map to safe appliers (auto-backup first) — synchronous
        $ids = array_values(array_filter(array_map(fn($t) => preg_replace('/[^a-z0-9_]/', '', strtolower($t)), preg_split('/[,\s]+/', (string)($_POST['ids'] ?? '')))));
        echo json_encode(smpro_tun_ai_apply_all($ids), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit;
    }
    // background variant: start apply-all detached (keeps running if the page is closed) + poll its progress/result
    if ($act === 'applyallstart' && function_exists('smpro_tun_job_start')) {
        $ids = array_values(array_filter(array_map(fn($t) => preg_replace('/[^a-z0-9_]/', '', strtolower($t)), preg_split('/[,\s]+/', (string)($_POST['ids'] ?? '')))));
        echo json_encode(smpro_tun_job_start('applyall', ['ids' => $ids]), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit;
    }
    if ($act === 'applyallstatus' && function_exists('smpro_tun_job_read')) { echo json_encode(smpro_tun_job_read('applyall'), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit; }
    if ($act === 'secadvisorapply' && function_exists('smpro_tun_sa_apply')) {
        $saId = mb_substr(preg_replace('/[^A-Za-z0-9_:\-]/', '', (string)($_POST['sa_id'] ?? '')), 0, 120);
        if ($saId === '') { echo json_encode(['ok' => false, 'msg' => 'sa_id required']); exit; }
        echo json_encode(smpro_tun_sa_apply($saId), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit;
    }
    echo json_encode(['ok' => false, 'msg' => 'unknown action']); exit;
}

// --- Domain Checker: deep-check a domain (DNS+WHOIS) / suspend / terminate. POST + CSRF + root. JSON. ---
if (($_GET['domchk'] ?? '') !== '') {
    $reqM = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? getenv('REQUEST_METHOD') ?: 'GET'));
    header('Content-Type: application/json');
    if ($reqM !== 'POST') { echo json_encode(['ok' => false, 'msg' => 'POST required']); exit; }
    smpro_require_valid_csrf('domchk'); smpro_require_root();
    $act = preg_replace('/[^a-z]/', '', strtolower((string)($_POST['dc_action'] ?? '')));
    if ($act === 'check' && function_exists('smpro_dom_check')) {
        $dom = mb_substr(preg_replace('/[^a-z0-9.\-]/i', '', (string)($_POST['domain'] ?? '')), 0, 253);
        echo json_encode(smpro_dom_check($dom, !empty($_POST['fresh'])), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit;
    }
    if ($act === 'suspend' && function_exists('smpro_dom_suspend')) {
        $user = preg_replace('/[^A-Za-z0-9_]/', '', (string)($_POST['user'] ?? ''));
        echo json_encode(smpro_dom_suspend($user, (string)($_POST['reason'] ?? '')), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit;
    }
    if ($act === 'terminate' && function_exists('smpro_dom_terminate')) {
        // extra safety: require an explicit confirm token in the POST
        if ((string)($_POST['confirm'] ?? '') !== 'TERMINATE') { echo json_encode(['ok' => false, 'msg' => 'Confirmation token required.']); exit; }
        $user = preg_replace('/[^A-Za-z0-9_]/', '', (string)($_POST['user'] ?? ''));
        echo json_encode(smpro_dom_terminate($user, !empty($_POST['backup'])), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit;
    }
    if ($act === 'backup' && function_exists('smpro_dom_backup')) {
        $user = preg_replace('/[^A-Za-z0-9_]/', '', (string)($_POST['user'] ?? ''));
        echo json_encode(smpro_dom_backup($user), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit;
    }
    if ($act === 'terminatebg' && function_exists('smpro_dom_terminate_bg')) {
        if ((string)($_POST['confirm'] ?? '') !== 'TERMINATE') { echo json_encode(['ok' => false, 'msg' => 'Confirmation token required.']); exit; }
        $user = preg_replace('/[^A-Za-z0-9_]/', '', (string)($_POST['user'] ?? ''));
        echo json_encode(smpro_dom_terminate_bg($user, !empty($_POST['backup'])), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit;
    }
    if ($act === 'jobstatus' && function_exists('smpro_dom_job')) {
        echo json_encode(smpro_dom_job((string)($_POST['job'] ?? '')), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit;
    }
    if ($act === 'bgscan' && function_exists('smpro_dom_bgscan_start')) {
        echo json_encode(smpro_dom_bgscan_start(function_exists('smpro_dom_list') ? smpro_dom_list() : []), JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit;
    }
    if ($act === 'scanstatus' && function_exists('smpro_dom_scan_status')) {
        $sid = preg_replace('/[^0-9A-Za-z_]/', '', (string)($_POST['scan_id'] ?? ''));
        echo json_encode(smpro_dom_scan_status($sid, max(0, (int)($_POST['since'] ?? 0))), JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit;
    }
    echo json_encode(['ok' => false, 'msg' => 'unknown action']); exit;
}

// --- Save dashboard shortcut pins. POST + CSRF + root. JSON. ---
if (($_GET['shortcuts'] ?? '') !== '') {
    $reqM = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? getenv('REQUEST_METHOD') ?: 'GET'));
    header('Content-Type: application/json');
    if ($reqM !== 'POST') { echo json_encode(['ok' => false, 'msg' => 'POST required']); exit; }
    smpro_require_valid_csrf('shortcuts'); smpro_require_root();
    $pins = smpro_sc_save_pins((array)($_POST['pin'] ?? []));
    echo json_encode(['ok' => true, 'pins' => $pins], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit;
}

// --- Save/activate an AI provider from the catalog. POST + CSRF + root. JSON. ---
if (($_GET['aiprov'] ?? '') !== '') {
    $reqM = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? getenv('REQUEST_METHOD') ?: 'GET'));
    header('Content-Type: application/json');
    if ($reqM !== 'POST') { echo json_encode(['ok' => false, 'msg' => 'POST required']); exit; }
    smpro_require_valid_csrf('aiprov'); smpro_require_root();
    $pid = preg_replace('/[^a-z0-9_]/', '', strtolower((string)($_POST['provider'] ?? '')));
    $act = preg_replace('/[^a-z]/', '', strtolower((string)($_POST['ar_action'] ?? 'save')));
    $r = ['ok' => false, 'msg' => 'unavailable'];
    if      ($act === 'save'     && function_exists('smpro_ai_provider_save'))     $r = smpro_ai_provider_save($pid, trim((string)($_POST['key'] ?? '')));
    elseif  ($act === 'toggle'   && function_exists('smpro_ai_provider_toggle'))   $r = smpro_ai_provider_toggle($pid, !empty($_POST['on']));
    elseif  ($act === 'setmodel' && function_exists('smpro_ai_provider_setmodel')) $r = smpro_ai_provider_setmodel($pid, trim((string)($_POST['model'] ?? '')));
    elseif  ($act === 'setmodels' && function_exists('smpro_ai_provider_setmodels')) $r = smpro_ai_provider_setmodels($pid, (array)($_POST['models'] ?? []));
    elseif  ($act === 'models'   && function_exists('smpro_ai_provider_models'))   $r = smpro_ai_provider_models($pid);
    elseif  ($act === 'execmode' && function_exists('smpro_ai_set_exec_mode'))     $r = smpro_ai_set_exec_mode(strtolower((string)($_POST['mode'] ?? 'series')));
    elseif  ($act === 'allfree'  && function_exists('smpro_ai_enable_all_free'))   $r = smpro_ai_enable_all_free();
    elseif  ($act === 'verify'   && function_exists('smpro_ai_provider_verify'))   $r = smpro_ai_provider_verify($pid);
    elseif  ($act === 'test'     && function_exists('smpro_ai_provider_test'))     $r = smpro_ai_provider_test($pid, trim((string)($_POST['model'] ?? '')));
    elseif  ($act === 'autoprune' && function_exists('smpro_ai_autoprune'))        $r = smpro_ai_autoprune(true);   // manual "Check now" (force)
    smpro_audit('ai_provider_' . $act, ['provider' => $pid, 'ok' => !empty($r['ok'])]);
    echo json_encode($r, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit;
}

// --- Global AI assistant endpoint (section-aware). POST + CSRF + root. JSON. ---
if (($_GET['ai_assist'] ?? '') === '1') {
    $reqM = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? getenv('REQUEST_METHOD') ?: 'GET'));
    if ($reqM !== 'POST') { echo json_encode(['ok' => false, 'error' => 'POST required']); exit; }
    smpro_require_valid_csrf('ai_assist'); smpro_require_root();
    if (function_exists('smpro_ratelimit') && !smpro_ratelimit('ai_assist', 20, 60)) { echo json_encode(['ok' => false, 'error' => 'Too many AI requests — slow down and try again in a minute.']); exit; }
    if (!function_exists('smpro_ai_available') || !smpro_ai_available()) { echo json_encode(['ok' => false, 'error' => 'No AI provider configured. Open AI Providers and save a key.']); exit; }
    $ctx = preg_replace('/[^a-z0-9_\-]/', '', strtolower((string)($_POST['ctx'] ?? 'dashboard')));
    // Executable decision plan: returns named action buttons wired to real endpoints.
    if (($_POST['mode'] ?? '') === 'decide') {
        $plan = smpro_ai_decide_plan($ctx);
        smpro_audit('ai_decide', ['ctx' => $ctx, 'ok' => $plan['ok'] ?? false, 'n' => count($plan['decisions'] ?? [])]);
        echo json_encode($plan, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit;
    }
    $q = trim((string)($_POST['q'] ?? ''));
    if ($q === '') { echo json_encode(['ok' => false, 'error' => 'Empty question.']); exit; }
    $sys = "You are the built-in AI assistant of Safety Monitor Pro, a WHM/cPanel shared-hosting security & monitoring plugin. The admin is viewing the '" . $ctx . "' section. Give practical, accurate, concise guidance for cPanel/WHM/CSF/LFD/Imunify360/Linux server security and operations. When asked about data you cannot directly see, tell the admin exactly what command or page to check. Prefer safe, reversible actions. Use short markdown.";
    $r = smpro_ai_chat($sys, smpro_ai_redact($q), ['max_tokens' => 950, 'context' => 'assist_' . $ctx]);
    smpro_audit('ai_assist', ['ctx' => $ctx, 'ok' => $r['ok'], 'provider' => $r['provider'] ?? '']);
    echo json_encode(['ok' => $r['ok'], 'text' => $r['text'] ?? '', 'error' => $r['error'] ?? '', 'provider' => $r['provider'] ?? '', 'model' => $r['model'] ?? ''], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}

// --- Live JSON API (polled by the page for real-time updates) ---
// GET only, read-only. Returns pure JSON; index.cgi serves it as application/json.
if (($_GET['format'] ?? '') === 'json') {
    smpro_require_root();                                // metrics/process list are root-only (parity with the page itself)
    $metric = preg_replace('/[^a-z0-9_\-]/', '', strtolower($_GET['metric'] ?? 'server'));
    $out = ['ok' => true];
    if ($metric === 'server' || $metric === '') {
        $out['data'] = smpro_collect_metrics();
        if (function_exists('smpro_dash_attention')) $out['attention'] = smpro_dash_attention($out['data']);
    } elseif ($metric === 'processes') {
        $limit = (int)($_GET['limit'] ?? 25);
        $out['data'] = smpro_top_processes($limit);
    } elseif ($metric === 'serverhealth') {
        $out['data'] = smpro_sv_snapshot();
    } elseif ($metric === 'diskio' && function_exists('smpro_ds_diskio_payload')) {
        $out += smpro_ds_diskio_payload(smpro_ds_diskio());          // live read/write + busy% + temperature (no page refresh)
    } elseif ($metric === 'benchmark' && function_exists('smpro_bm_state')) {
        $out['bench'] = smpro_bm_state();                            // hardware-benchmark progress/results (polled while running)
        if (function_exists('smpro_bm_inventory')) $out['inv'] = smpro_bm_inventory(true);   // compute+cache the static hardware inventory here (NOT on the page render, so the page stays fast)
    } elseif ($metric === 'dbhealth' && function_exists('smpro_dbh_live')) {
        $out += smpro_dbh_live(($_GET['full'] ?? '') === '1');       // live MySQL processlist + threads; full=1 also re-renders KPIs/config/findings/recommendations
    } elseif ($metric === 'connsrc' && function_exists('smpro_im_conn_sources')) {
        // On-demand: which live sockets (and therefore which process/account) involve a flagged IP.
        $cip = preg_replace('/[^0-9a-fA-F:.]/', '', (string)($_GET['ip'] ?? ''));
        $out += smpro_im_conn_sources($cip);
    } elseif ($metric === 'benchdiag' && function_exists('smpro_bd_live_payload')) {
        $out += smpro_bd_live_payload();                             // LIVE hardware gauges + per-disk I/O/temps + inventory + run state + cached hw-health/diagnostics
    } else {
        $out = ['ok' => false, 'error' => 'unknown metric'];
    }
    echo json_encode($out, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);   // SUBSTITUTE: a single process with a non-UTF-8 cmdline must not make the whole live-metric response empty (which would freeze the poll)
    exit;
}

// --- Resolve requested page (alias-aware, whitelist via registry) ---
$page = isset($_GET['page']) ? preg_replace('/[^a-z0-9_\-]/', '', strtolower($_GET['page'])) : 'dashboard';
$item = smpro_menu_resolve($page);

if ($item === null) {
    // Unknown route → safe fallback to dashboard.
    $item = smpro_menu_resolve('dashboard');
    $page = 'dashboard';
}

// First-run acceptance: the Terms & Conditions / Privacy / Refund must be accepted before any page is used.
// (JSON/metric/AJAX endpoints and the accept POST already returned above, so only full page renders are gated.)
if (function_exists('smpro_legal_accepted') && !smpro_legal_accepted()) {
    smpro_legal_render_gate();
    exit;
}

// Feature gate: when licensed, a section whose required feature is not in the license is locked.
// (License itself is never gated — it's the way back in.)
if (SMPRO_LIC_ENFORCE && $page !== 'license' && function_exists('smpro_lic_section_allowed')
    && !smpro_lic_section_allowed($item['feature'] ?? '')) {
    smpro_render_locked($item);
    exit;
}

// Master switch: when the plugin is DISABLED, every page shows a notice.
// A NORMAL admin-disable leaves Plugin Control + License open as the way back. A confirmed TAMPER (endpoint
// redirect / forged state) gets NO escape hatch — EVERY page is locked and no re-enable control is offered, since
// only a server-side reset can clear it (local re-enable is a no-op anyway while the marker is set).
$smTamperLock = (function_exists('smpro_lic_tlm_at') && smpro_lic_tlm_at() > 0)
             || (function_exists('smpro_lic_tamper_at') && smpro_lic_tamper_at() > 0);
// B2 FIX — the License page is ALWAYS a way back in (read-only status + support info + the surface a server-side
// reset reaches), even under a tamper lock. Locking it made a false tamper flag unrecoverable in-panel. Plugin
// Control stays a recovery page only for a NORMAL admin-disable, not under tamper (its re-enable is a no-op then).
$smRecoveryPage = ($page === 'license') || (!$smTamperLock && $page === 'plugin-control');
if (function_exists('smpro_ctl_disabled') && smpro_ctl_disabled() && !$smRecoveryPage) {
    $ctl = smpro_ctl_get();
    // Connection-loss SOFT stop wears a different, reversible face: "could not connect to the main server" + Retry.
    $smSyncStop = !$smTamperLock && ((function_exists('smpro_lic_sync_disabled') && smpro_lic_sync_disabled())
                                  || (function_exists('smpro_lic_pair_stopped') && smpro_lic_pair_stopped()));   // pairing stop = reversible soft face
    smpro_layout_header('Plugin Disabled');
    if ($smSyncStop) {
        echo '<div class="card" style="max-width:620px;margin:30px auto;text-align:center;padding:32px 26px">'
           . '<div style="font-size:42px;line-height:1">&#128246;</div>'
           . '<h1 class="h" style="justify-content:center;margin:8px 0">Could not connect to the main server</h1>'
           . '<p class="sub">The plugin is paused until it can reach the license server again. Please contact technical support or verify license integrity. It resumes automatically the moment the connection is restored.</p>'
           . '<div style="margin-top:14px"><a class="btn" href="index.cgi?page=license" style="background:var(--brand);color:#fff">&#8635; Retry / open License</a></div></div>';
    } else {
        echo '<div class="card" style="max-width:620px;margin:30px auto;text-align:center;padding:32px 26px">'
           . '<div style="font-size:42px;line-height:1">&#9940;</div>'
           . '<h1 class="h" style="justify-content:center;margin:8px 0">' . smpro_h(SMPRO_NAME) . ' is disabled</h1>'
           . '<p class="sub">Monitoring and automatic protection are stopped.'
           . (!$smTamperLock && (int)$ctl['reenable_at'] > 0 ? ' It will turn back on automatically at <b>' . smpro_h(date('Y-m-d H:i', (int)$ctl['reenable_at'])) . '</b>.' : '')
           . '</p>'
           . ($smTamperLock ? '' : '<div style="margin-top:14px"><a class="btn" href="index.cgi?page=plugin-control" style="background:var(--brand);color:#fff">&#9211; Open Plugin Control</a></div>')
           . '</div>';
    }
    smpro_layout_footer();
    exit;
}

// Defense-in-depth (#3): an INDEPENDENT last-line guard right before a module renders — re-derives the verdict
// from the signed tamper marker + the integrity check DIRECTLY (not via smpro_ctl_disabled / smpro_lic_is_valid),
// so patching the central boolean alone does not let a module render on a tampered box.
// B2 FIX — never lock the License page itself; it is the guaranteed recovery/status surface (see master switch above).
if ($page !== 'license'
    && ((function_exists('smpro_lic_tlm_at') && smpro_lic_tlm_at() > 0)
    || (function_exists('smpro_lic_integrity_ok') && !smpro_lic_integrity_ok()))) {
    smpro_layout_header('Plugin Disabled');
    echo '<div class="card" style="max-width:620px;margin:30px auto;text-align:center;padding:32px 26px">'
       . '<div style="font-size:42px;line-height:1">&#9940;</div>'
       . '<h1 class="h" style="justify-content:center;margin:8px 0">' . smpro_h(SMPRO_NAME) . ' is disabled</h1>'
       . '<p class="sub">Monitoring and automatic protection are stopped.</p></div>';
    smpro_layout_footer();
    exit;
}

// Built modules load their file; unbuilt ones render the shared placeholder.
$modulePath = SMPRO_MODULES . '/' . $item['id'] . '.php';

// track most-used pages (for Dashboard shortcuts) — GET page views only, cheap json bump
if (function_exists('smpro_sc_track') && strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? 'GET')) === 'GET') smpro_sc_track($item['id'] ?? $page);

if (!empty($item['built']) && is_file($modulePath)) {
    // Buffer the module render so an uncaught Throwable can't leave a truncated, header-only page with no footer
    // and no diagnostic (display_errors is off + stderr is swallowed by index.cgi). On success flush as-is; on
    // error discard the partial output, log it to the audit trail, and render a complete error page with chrome.
    ob_start();
    try {
        require $modulePath;
        echo ob_get_clean();
    } catch (\Throwable $e) {
        ob_get_clean();
        if (function_exists('smpro_audit')) smpro_audit('module_fatal', ['page' => (string)($_GET['page'] ?? $page), 'err' => $e->getMessage(), 'file' => basename($e->getFile()), 'line' => $e->getLine()]);
        smpro_layout_header('Section error');
        echo '<div class="card" style="max-width:620px;margin:24px auto;padding:26px;text-align:center">'
           . '<div style="font-size:38px;line-height:1">&#9888;</div>'
           . '<h2 class="h" style="justify-content:center;margin:8px 0">This section hit an internal error</h2>'
           . '<p class="sub">The problem was logged for support. Try another section, or reload the page.</p></div>';
        smpro_layout_footer();
    }
} else {
    smpro_render_placeholder($item);
}
