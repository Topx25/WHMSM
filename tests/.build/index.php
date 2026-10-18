<?php
/**
 * Safety Monitor Pro (smpro) — front controller / router.
 * GET = read-only. State-changing actions (later) = POST + CSRF.
 * Routes + sidebar are generated from a single registry: includes/menu.php
 */
define('SMPRO_BOOT', 1);
// Dev-mode bypass: ONLY honored on the single designated test box (bound to its cPanel main IP), and
// fail-closed everywhere else — a stray .dev_mode file on a production server can NOT disable the license
// gate. The IP is matched against /var/cpanel/mainip (root-owned); no file or a different IP = enforced.
if (is_file('/var/lib/smpro/.dev_mode') && trim((string)@file_get_contents('/var/cpanel/mainip')) === '167.233.29.168') define('SMPRO_LIC_ENFORCE', false);

require __DIR__ . '/includes/defines.php';
require __DIR__ . '/includes/env.php';
require __DIR__ . '/includes/mmdb.php';
require __DIR__ . '/includes/helpers.php';
require __DIR__ . '/includes/secret.php';
require __DIR__ . '/includes/license.php';
require __DIR__ . '/includes/intrusion.php';
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
require __DIR__ . '/includes/tgbot.php';
require __DIR__ . '/includes/cooler.php';
require __DIR__ . '/includes/hub.php';
require __DIR__ . '/includes/legal.php';
require __DIR__ . '/includes/menu.php';
require __DIR__ . '/includes/shortcuts.php';
require __DIR__ . '/includes/layout.php';

// Ensure the daily update-check cron exists on every server (idempotent — only writes if missing/changed),
// so the auto-update worker runs even if the admin never opens the Updates page.
if (function_exists('smpro_upd_install_cron')) { try { smpro_upd_install_cron(); } catch (\Throwable $e) {} }
if (function_exists('smpro_hub_install_cron')) { try { smpro_hub_install_cron(); } catch (\Throwable $e) {} }
// Ensure the intrusion auto-response/auto-block scanner cron exists whenever Emergency/auto-block is ON
// (its scan runs on the notify worker, which otherwise only existed if "Auto-check" was toggled on).
if (function_exists('smpro_ntf_cron_sync')) { try { smpro_ntf_cron_sync(); } catch (\Throwable $e) {} }

// index.cgi invokes PHP as CLI, which does NOT auto-populate superglobals from
// the CGI environment. Rebuild $_GET (and $_POST for forms later) ourselves.
// parse_str() is NOT bounded by max_input_vars/post_max_size (those only cap the normal SAPI), so cap the raw
// input first — keeps the CLI-rebuilt superglobals within the same envelope a normal PHP SAPI would enforce.
if (empty($_GET) && ($qs = getenv('QUERY_STRING'))) {
    parse_str(substr((string)$qs, 0, 131072), $_GET);                 // 128KB query string ceiling
}
if (($_SERVER['REQUEST_METHOD'] ?? getenv('REQUEST_METHOD')) === 'POST' && empty($_POST)) {
    parse_str((string)stream_get_contents(fopen('php://stdin', 'r'), 4194304), $_POST);   // 4MB POST body ceiling
}

// Defense-in-depth gate: every request must come from a WHM session (or CLI).
smpro_require_whm_access();

// Anti-tamper gate: if a protected file was modified (e.g. patching out the licence gate), lock down.
if (function_exists('smpro_integrity_gate')) { try { smpro_integrity_gate(); } catch (\Throwable $e) {} }

// Ensure the 24/7 foreign login brute-force guard cron is installed (idempotent, cheap).
if (function_exists('smpro_login_guard_install_cron')) { try { smpro_login_guard_install_cron(); } catch (\Throwable $e) {} }

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
    if (function_exists('smpro_lic_tlm_sync')) { try { smpro_lic_tlm_sync(); } catch (\Throwable $e) {} }
    // Connection-loss ladder: advance the accumulator on page load too (read-only — no network/notify on web).
    if (function_exists('smpro_lic_sync_tick')) { try { smpro_lic_sync_tick(); } catch (\Throwable $e) {} }
}

// --- Multi-Server: if a Hub manages this server, pull & run its plugin-scoped commands
//     (throttled ~90s, granted-permission gated). Skipped on JSON/live endpoints to stay fast. ---
if (($_GET['format'] ?? '') !== 'json' && empty($_GET['metric']) && empty($_GET['hub_ajax']) && empty($_GET['hub_render'])
    && function_exists('smpro_hub_member_tick') && function_exists('smpro_hub_active') && smpro_hub_active()) {
    try { smpro_hub_member_tick(); } catch (\Throwable $e) {}
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
        case 'cpass_set':    smpro_require_root(); $resp = ['ok'=>smpro_hub_cpass_set((string)($_POST['pw'] ?? '')), 'isset'=>smpro_hub_cpass_isset()]; break;
        case 'cpass_unlock': $ok = smpro_hub_cpass_verify((string)($_POST['pw'] ?? '')); if ($ok) smpro_hub_cpass_unlock(); $resp = ['ok'=>$ok, 'msg'=>$ok?'unlocked':'wrong password']; break;
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
    echo json_encode($resp, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE); exit;
}

// --- Install a missing optional component via the OS package manager. POST+CSRF+root. JSON. ---
if (($_GET['env_install'] ?? '') !== '') {
    $reqM = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? getenv('REQUEST_METHOD') ?: 'GET'));
    header('Content-Type: application/json');
    if ($reqM !== 'POST') { echo json_encode(['ok' => false, 'msg' => 'POST required']); exit; }
    smpro_require_valid_csrf('env_install'); smpro_require_root();
    $key = preg_replace('/[^a-z0-9_]/', '', strtolower((string)($_POST['component'] ?? '')));
    [$ok, $detail] = smpro_env_install($key);
    echo json_encode(['ok' => $ok, 'msg' => $detail], JSON_UNESCAPED_SLASHES); exit;
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
    echo json_encode(['ok'=>!empty($r['ok']),'ip'=>$ip,'msg'=>(string)$r['msg']], JSON_UNESCAPED_SLASHES); exit;
}

// --- License actions (activate / re-check / deactivate). POST + CSRF + root. JSON. ---
if (($_GET['license'] ?? '') !== '') {
    $reqM = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? getenv('REQUEST_METHOD') ?: 'GET'));
    header('Content-Type: application/json');
    if ($reqM !== 'POST') { echo json_encode(['ok' => false, 'msg' => 'POST required']); exit; }
    smpro_require_valid_csrf('license'); smpro_require_root();
    $act = preg_replace('/[^a-z]/', '', strtolower((string)($_POST['lic_action'] ?? '')));
    if ($act === 'activate') {
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
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

// --- Update endpoint (check / apply / auto-toggle). POST + CSRF + root. JSON. ---
if (($_GET['update'] ?? '') !== '') {
    $reqM = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? getenv('REQUEST_METHOD') ?: 'GET'));
    header('Content-Type: application/json');
    if ($reqM !== 'POST') { echo json_encode(['ok' => false, 'msg' => 'POST required']); exit; }
    smpro_require_valid_csrf('update'); smpro_require_root();
    $act = preg_replace('/[^a-z]/', '', strtolower((string)($_POST['upd_action'] ?? '')));
    if ($act === 'check') { echo json_encode(smpro_upd_check(), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE); exit; }
    if ($act === 'apply') { smpro_audit('self_update_manual', []); echo json_encode(smpro_upd_apply(), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE); exit; }
    if ($act === 'auto')  { $c = smpro_upd_cfg(); $c['auto'] = !empty($_POST['on']); smpro_upd_cfg_save($c); smpro_audit('self_update_auto', ['on' => $c['auto']]); echo json_encode(['ok' => true, 'auto' => $c['auto']]); exit; }
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
    if ($act === 'generate') { echo json_encode(smpro_rep_run(true), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE); exit; }
    // --- grouped-alerts / quiet digest ---
    if ($act === 'dgsave' && function_exists('smpro_dg_cfg_save')) {
        $cfg = smpro_dg_cfg();
        $cfg['enabled']        = !empty($_POST['dg_enabled']);
        $cfg['interval_hours'] = max(1, min(168, (int)($_POST['dg_hours'] ?? 6)));
        smpro_dg_cfg_save($cfg);
        smpro_audit('digest_cfg', ['enabled' => $cfg['enabled'], 'hours' => $cfg['interval_hours']]);
        echo json_encode(['ok' => true, 'cfg' => $cfg]); exit;
    }
    if ($act === 'dgclassify' && function_exists('smpro_dg_ai_classify')) { echo json_encode(smpro_dg_ai_classify(), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE); exit; }
    if ($act === 'dgflush'    && function_exists('smpro_dg_flush'))        { echo json_encode(smpro_dg_flush(true), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE); exit; }
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
    if ($act === 'disable') { echo json_encode(smpro_tg_enable(false), JSON_UNESCAPED_SLASHES); exit; }
    if ($act === 'test')    { echo json_encode(smpro_tg_test(),        JSON_UNESCAPED_SLASHES); exit; }
    echo json_encode(['ok' => false, 'msg' => 'unknown action']); exit;
}

// --- Cooler mode: detect load source / throttle it for a duration / stop. POST+CSRF+root, except GET status. JSON. ---
if (($_GET['cooler'] ?? '') !== '') {
    header('Content-Type: application/json');
    smpro_require_root();                                // status/sources expose the top-CPU process/PID list — root-only
    $reqM = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? getenv('REQUEST_METHOD') ?: 'GET'));
    // read from $_POST first (the CGI populates $_POST/$_GET manually — $_REQUEST may be unreliable here)
    $act  = preg_replace('/[^a-z]/', '', strtolower((string)($_POST['cool_action'] ?? $_GET['cool_action'] ?? 'status')));
    if ($act === 'status')  { echo json_encode(smpro_cool_status(), JSON_UNESCAPED_SLASHES); exit; }
    if ($act === 'sources') { echo json_encode(['ok' => true] + smpro_cool_sources(8), JSON_UNESCAPED_SLASHES); exit; }
    if ($reqM !== 'POST') { echo json_encode(['ok' => false, 'msg' => 'POST required']); exit; }
    smpro_require_valid_csrf('cooler'); smpro_require_root();
    if ($act === 'start') {
        $pids = array_filter(array_map('intval', preg_split('/[,\s]+/', (string)($_POST['pids'] ?? ''))));
        $pct  = (int)($_POST['percent'] ?? 0); $min = (int)($_POST['minutes'] ?? 15);
        echo json_encode(smpro_cool_start($pids, $pct, $min), JSON_UNESCAPED_SLASHES); exit;
    }
    if ($act === 'auto')  { echo json_encode(smpro_cool_auto((int)($_POST['minutes'] ?? 15), (int)($_POST['percent'] ?? 50)), JSON_UNESCAPED_SLASHES); exit; }
    if ($act === 'guard') { $smGr = smpro_cool_guard_save([
        'enabled' => !empty($_POST['enabled']), 'ceiling' => (float)($_POST['ceiling'] ?? 20),
        'percent' => (int)($_POST['percent'] ?? 50), 'minutes' => (int)($_POST['minutes'] ?? 15),
        'topk' => (int)($_POST['topk'] ?? 3), 'min_cpu' => (int)($_POST['min_cpu'] ?? 25),
    ]); if (is_array($smGr)) $smGr['_via'] = 'guardsave'; echo json_encode($smGr, JSON_UNESCAPED_SLASHES); exit; }
    if ($act === 'stop')  { echo json_encode(smpro_cool_stop(), JSON_UNESCAPED_SLASHES); exit; }
    echo json_encode(['ok' => false, 'msg' => 'unknown action']); exit;
}

// --- Server Tune-up: backup configs / apply a recommendation. POST + CSRF + root. JSON. ---
if (($_GET['tuning'] ?? '') !== '') {
    $reqM = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? getenv('REQUEST_METHOD') ?: 'GET'));
    header('Content-Type: application/json');
    if ($reqM !== 'POST') { echo json_encode(['ok' => false, 'msg' => 'POST required']); exit; }
    smpro_require_valid_csrf('tuning'); smpro_require_root();
    $act = preg_replace('/[^a-z]/', '', strtolower((string)($_POST['tun_action'] ?? '')));
    if ($act === 'backup') { $b = smpro_tun_backup_all(); echo json_encode(['ok' => true, 'id' => $b['id'], 'files' => count($b['files'])]); exit; }
    if ($act === 'apply')  { $rid = preg_replace('/[^a-z0-9_]/', '', (string)($_POST['rec'] ?? '')); echo json_encode(smpro_tun_apply($rid), JSON_UNESCAPED_SLASHES); exit; }
    if ($act === 'install') {
        $tgt = preg_replace('/[^a-z0-9_]/', '', strtolower((string)($_POST['target'] ?? '')));
        if ($tgt === 'csf' && function_exists('smpro_tun_install_csf')) { echo json_encode(smpro_tun_install_csf(), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE); exit; }
        echo json_encode(['ok' => false, 'msg' => 'unsupported install target']); exit;
    }
    if ($act === 'aioptimize' && function_exists('smpro_tun_ai_optimize')) {
        $targets = array_filter(array_map(fn($t) => preg_replace('/[^a-z]/', '', strtolower($t)), preg_split('/[,\s]+/', (string)($_POST['targets'] ?? ''))));
        echo json_encode(smpro_tun_ai_optimize($targets), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE); exit;
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
    echo json_encode(['ok' => true, 'pins' => $pins], JSON_UNESCAPED_SLASHES); exit;
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
    echo json_encode($r, JSON_UNESCAPED_SLASHES); exit;
}

// --- Global AI assistant endpoint (section-aware). POST + CSRF + root. JSON. ---
if (($_GET['ai_assist'] ?? '') === '1') {
    $reqM = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? getenv('REQUEST_METHOD') ?: 'GET'));
    if ($reqM !== 'POST') { echo json_encode(['ok' => false, 'error' => 'POST required']); exit; }
    smpro_require_valid_csrf('ai_assist'); smpro_require_root();
    if (!function_exists('smpro_ai_available') || !smpro_ai_available()) { echo json_encode(['ok' => false, 'error' => 'No AI provider configured. Open AI Providers and save a key.']); exit; }
    $ctx = preg_replace('/[^a-z0-9_\-]/', '', strtolower((string)($_POST['ctx'] ?? 'dashboard')));
    // Executable decision plan: returns named action buttons wired to real endpoints.
    if (($_POST['mode'] ?? '') === 'decide') {
        $plan = smpro_ai_decide_plan($ctx);
        smpro_audit('ai_decide', ['ctx' => $ctx, 'ok' => $plan['ok'] ?? false, 'n' => count($plan['decisions'] ?? [])]);
        echo json_encode($plan, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE); exit;
    }
    $q = trim((string)($_POST['q'] ?? ''));
    if ($q === '') { echo json_encode(['ok' => false, 'error' => 'Empty question.']); exit; }
    $sys = "You are the built-in AI assistant of Safety Monitor Pro, a WHM/cPanel shared-hosting security & monitoring plugin. The admin is viewing the '" . $ctx . "' section. Give practical, accurate, concise guidance for cPanel/WHM/CSF/LFD/Imunify360/Linux server security and operations. When asked about data you cannot directly see, tell the admin exactly what command or page to check. Prefer safe, reversible actions. Use short markdown.";
    $r = smpro_ai_chat($sys, smpro_ai_redact($q), ['max_tokens' => 950, 'context' => 'assist_' . $ctx]);
    smpro_audit('ai_assist', ['ctx' => $ctx, 'ok' => $r['ok'], 'provider' => $r['provider'] ?? '']);
    echo json_encode(['ok' => $r['ok'], 'text' => $r['text'] ?? '', 'error' => $r['error'] ?? '', 'provider' => $r['provider'] ?? '', 'model' => $r['model'] ?? ''], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
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
    } else {
        $out = ['ok' => false, 'error' => 'unknown metric'];
    }
    echo json_encode($out, JSON_UNESCAPED_SLASHES);
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
    require $modulePath;
} else {
    smpro_render_placeholder($item);
}
