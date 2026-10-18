<?php
/**
 * hub.php — Multi-Server "Hub" client (plugin side) for Safety Monitor Pro.
 *
 * Gated behind the `multi_server` feature (Ultra plan). A server can act as:
 *   - HUB    (controller): pairs with the customer's OTHER servers and manages their PLUGIN
 *            resources (block IP, apply profile, restart a service via the plugin, push update,
 *            view metrics/incidents) — never anything outside the plugin.
 *   - MEMBER (managed): approves a pairing, GRANTS a granular permission set, then pulls the
 *            hub's commands and executes them LOCALLY under exactly those permissions.
 *
 * Transport: the license server acts as an authenticated RELAY (see server/hub_ext.php) because
 * WHM addon CGIs cannot accept direct inbound calls. Every relay call is authenticated by this
 * server's license_key + bound fingerprint (same trust as /api/check). Commands are executed only
 * by the Member, only within granted permissions, and every action is audited on BOTH sides.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

/** Permission catalog the Hub may request and the Member may grant. 'view' is always implied. */
function smpro_hub_perms_all() {
    return [
        'view'     => 'View metrics, incidents & security status',
        'firewall' => 'Block / unblock IPs (CSF firewall)',
        'profiles' => 'Apply a Protection Profile',
        'services' => 'Restart a service via the plugin',
        'updates'  => 'Trigger a plugin update',
    ];
}
/** Which granted permission an inbound action requires. */
function smpro_hub_action_perm($action) {
    $map = ['ping'=>'view','status'=>'view','incidents'=>'view',
            'block_ip'=>'firewall','unblock_ip'=>'firewall',
            'apply_profile'=>'profiles','restart_service'=>'services','update'=>'updates'];
    return $map[$action] ?? 'view';
}

/** Is multi-server in this license? (Ultra plan feature) */
function smpro_hub_enabled() {
    $f = smpro_lic_state()['features'] ?? [];
    return is_array($f) && in_array('multi_server', $f, true);
}
/** Admin turned the Hub OFF on THIS server (an option, separate from the license). */
function smpro_hub_locally_disabled() { return is_file(SMPRO_VARLIB . '/hub/disabled'); }
function smpro_hub_set_disabled($off) {
    $f = SMPRO_VARLIB . '/hub/disabled'; @mkdir(dirname($f), 0700, true);
    if ($off) @file_put_contents($f, (string)time()); else @unlink($f);
}
/** Hub is usable here = licensed (Ultra) AND not locally turned off. */
function smpro_hub_active() { return smpro_hub_enabled() && !smpro_hub_locally_disabled(); }

/* ---- Independent control password (separate from root) — gates actions on remote servers ---- */
function smpro_hub_cpass_file()   { return SMPRO_VARLIB . '/hub/control_pass'; }
function smpro_hub_cpass_isset()  { return is_file(smpro_hub_cpass_file()); }
function smpro_hub_cpass_set($pw) {
    @mkdir(SMPRO_VARLIB . '/hub', 0700, true);
    if ((string)$pw === '') {
        @unlink(smpro_hub_cpass_file()); @unlink(SMPRO_VARLIB . '/hub/.cpass_unlock');
        @unlink(smpro_hub_e2e_pass_file());                                  // (see below) clear the derived channel key too
        return true;
    }
    $ok = (bool)@file_put_contents(smpro_hub_cpass_file(), password_hash((string)$pw, PASSWORD_DEFAULT));
    @chmod(smpro_hub_cpass_file(), 0600);
    // The control password ALSO derives the end-to-end channel key (the same value on two paired servers seals
    // all traffic with a secret the relay never sees). Stored as a deterministic hash — never the raw password.
    @file_put_contents(smpro_hub_e2e_pass_file(), hash('sha256', 'smpro-e2e|' . (string)$pw));
    @chmod(smpro_hub_e2e_pass_file(), 0600);
    return $ok;
}
function smpro_hub_cpass_verify($pw) {
    if (!smpro_hub_cpass_isset()) return true;
    return password_verify((string)$pw, (string)@file_get_contents(smpro_hub_cpass_file()));
}
function smpro_hub_cpass_unlock()   { @file_put_contents(SMPRO_VARLIB . '/hub/.cpass_unlock', (string)time()); }
/** Unlocked = no password set, OR active within the last 60s (sliding idle window — refreshed on each action). */
function smpro_hub_cpass_unlocked() {
    if (!smpro_hub_cpass_isset()) return true;
    $f = SMPRO_VARLIB . '/hub/.cpass_unlock';
    return is_file($f) && (time() - (int)@filemtime($f)) < 60;
}

/* ---- step-up brute-force lock: a real 24h lock + once-per-24h reset (member-local OR hub-master) ---- */
function smpro_hub_lock_file()  { return SMPRO_VARLIB . '/hub/.verify_lock'; }
function smpro_hub_fails_file() { return SMPRO_VARLIB . '/hub/.verify_fails'; }
function smpro_hub_reset_file() { return SMPRO_VARLIB . '/hub/.lock_reset'; }
/** Active lock record (['locked_at','until']) or [] when not locked. Expired locks self-clear. */
function smpro_hub_lock_state() {
    $f = smpro_hub_lock_file();
    $d = is_file($f) ? (json_decode((string)@file_get_contents($f), true) ?: []) : [];
    if (!empty($d['until']) && time() < (int)$d['until']) return $d;
    if ($d) @unlink($f);                                                            // expired → clear
    return [];
}
function smpro_hub_is_locked() { return !empty(smpro_hub_lock_state()['until']); }
/** The (internal) remediation guidance shown on suspected brute force. */
function smpro_hub_breach_advice() {
    return 'If this was not you: change the server ROOT password, change the plugin CONTROL password (Multi-Server page), and re-create the pairing TOKEN (remove the pairing and pair again).';
}
/** MEMBER (cron): report a failed/locked verify to the local admin AND to the license server. Never throws. */
function smpro_hub_report_fail($lid, $n, $locked = false) {
    if (function_exists('smpro_audit')) smpro_audit($locked ? 'hub_bruteforce_lock' : 'hub_verify_fail', ['link' => (int)$lid, 'n' => (int)$n]);
    // notify the local admin — FORCE only the early warning (first attempt) and the lock, so a burst of wrong
    // tries can't spam alerts; the middle attempts go through the normal (batched/toggle-respecting) path.
    if (function_exists('smpro_notify')) {
        $sub  = $locked ? 'Remote control LOCKED (brute force)' : 'Failed remote-control attempt';
        $body = ($locked ? 'Too many wrong control-password attempts from a hub — remote control is locked for 24h. ' : ('A hub made a wrong control-password attempt (#' . (int)$n . '). ')) . smpro_hub_breach_advice();
        @smpro_notify('hub_bruteforce_lock', $sub, $body, ['severity' => $locked ? 'critical' : 'warning'], $locked || (int)$n === 1);
    }
    if (function_exists('smpro_hub_api')) @smpro_hub_api('event', ['link_id' => (int)$lid, 'kind' => $locked ? 'verify_lock' : 'verify_fail', 'n' => (int)$n], 8);
}
/** MEMBER/HUB: reset the lock — allowed ONCE per 24h (shared gate covers both the local and the hub-master path). */
function smpro_hub_lock_reset($by = 'local') {
    if (!smpro_hub_is_locked()) { @unlink(smpro_hub_fails_file()); return ['ok' => true, 'was_locked' => false, 'msg' => 'No active lock.']; }
    $rf = smpro_hub_reset_file();
    $last = is_file($rf) ? (int)trim((string)@file_get_contents($rf)) : 0;
    if ($last && time() - $last < 86400)
        return ['ok' => false, 'cooldown' => true, 'next' => $last + 86400, 'msg' => 'A lock reset was already used in the last 24h. Next reset allowed after ' . date('Y-m-d H:i', $last + 86400) . '.'];
    @unlink(smpro_hub_lock_file()); @unlink(smpro_hub_fails_file());
    @file_put_contents($rf, (string)time()); @chmod($rf, 0600);
    if (function_exists('smpro_audit'))  smpro_audit('hub_lock_reset', ['by' => $by]);
    if (function_exists('smpro_notify')) @smpro_notify('hub_bruteforce_lock', 'Remote-control lock reset', 'The remote-control brute-force lock was reset (' . $by . ').', ['severity' => 'warning'], true);
    return ['ok' => true, 'was_locked' => true, 'msg' => 'Lock reset.'];
}

/** MEMBER: verify a control-password attempt sent (E2E) by a hub. Hard 24h lock after repeated failures;
 *  while locked, a correct password does NOT bypass — only a once/24h reset or expiry clears it. */
function smpro_hub_member_verify_pass($pw, $lid = 0) {
    if (!smpro_hub_cpass_isset()) return ['ok' => true, 'nopass' => true, 'locked' => false];   // no password set here → nothing to prove
    $ls = smpro_hub_lock_state();
    if (!empty($ls['until'])) return ['ok' => false, 'nopass' => false, 'locked' => true, 'until' => (int)$ls['until']];   // hard lock
    $lf = smpro_hub_fails_file(); $now = time();
    $all = is_file($lf) ? (json_decode((string)@file_get_contents($lf), true) ?: []) : [];
    $all = array_values(array_filter(array_map('intval', $all), fn($t) => $now - $t < 86400));   // keep a 24h failure history
    if (smpro_hub_cpass_verify((string)$pw)) { @unlink($lf); return ['ok' => true, 'nopass' => false, 'locked' => false]; }
    $all[] = $now; @file_put_contents($lf, json_encode($all)); @chmod($lf, 0600);
    $burst = count(array_filter($all, fn($t) => $now - $t < 1800));                  // last 30 min (fast brute-force)
    $day   = count($all);                                                            // last 24 h (low-and-slow brute-force)
    if ($burst >= 5 || $day >= 15) {                                                 // EITHER pattern → 24h lock
        $until = $now + 86400;
        @file_put_contents(smpro_hub_lock_file(), json_encode(['locked_at' => $now, 'until' => $until])); @chmod(smpro_hub_lock_file(), 0600);
        smpro_hub_report_fail($lid, max($burst, $day), true);
        return ['ok' => false, 'nopass' => false, 'locked' => true, 'until' => $until];
    }
    smpro_hub_report_fail($lid, $burst, false);
    return ['ok' => false, 'nopass' => false, 'locked' => false];
}

/* ---- HUB: link verification state + undisclosed step-up rules ---- */
function smpro_hub_boot_ts() { return (int)trim((string)@shell_exec('date -d "$(uptime -s 2>/dev/null)" +%s 2>/dev/null')); }
function smpro_hub_vstate_file($lid) { $d = SMPRO_VARLIB . '/hub/verified'; @mkdir($d, 0700, true); return $d . '/' . (int)$lid . '.json'; }
function smpro_hub_vstate($lid) { $f = smpro_hub_vstate_file($lid); return is_file($f) ? (json_decode((string)@file_get_contents($f), true) ?: []) : []; }
function smpro_hub_set_verified($lid, $mip) { @file_put_contents(smpro_hub_vstate_file($lid), json_encode(['ts' => time(), 'mip' => (string)$mip, 'hb' => smpro_hub_boot_ts()])); }
function smpro_hub_clear_verified($lid) { @unlink(smpro_hub_vstate_file($lid)); }

/** HUB: prove knowledge of the member's control password (sent E2E-encrypted); on success record verified. */
function smpro_hub_verify_link($lid, $pw, $mip = '') {
    $lid = (int)$lid; $rid = bin2hex(random_bytes(6));
    // The control password may ONLY be sent over an E2E-sealed channel. If the ECDH secret isn't derived yet
    // (the window right after pairing), force derivation from any freshly-arrived member_pub; if still not ready,
    // bail — NEVER let smpro_hub_seal drop it as '' or (pre-fix) leak it as plaintext through the relay.
    if (smpro_hub_enckey($lid) === '') { smpro_hub_ensure_secrets(smpro_hub_links('hub')); }
    if (smpro_hub_enckey($lid) === '') return ['ok' => false, 'notready' => true];
    smpro_hub_api('live', ['link_id' => $lid]);
    smpro_hub_api('send', ['link_id' => $lid, 'dir' => 'cmd', 'body' => smpro_hub_seal($lid, ['action' => 'verify_pass', 'pw' => (string)$pw, 'req' => $rid])]);
    // patient: a freshly-paired member only checks in on its ~60s cron tick, so allow up to ~70s for the first
    // reply (when the panel is already open the member is live and this returns in seconds).
    $deadline = time() + 70;
    while (time() < $deadline) {
        usleep(800000);
        [$ok, $d] = smpro_hub_api('fetch', ['link_id' => $lid, 'dir' => 'result', 'max' => 25], 8);
        if ($ok) foreach ((array)($d['items'] ?? []) as $it) {
            $b = smpro_hub_open($lid, (string)($it['body'] ?? ''));
            if (is_array($b) && ($b['req'] ?? '') === $rid) {
                if (!empty($b['vok'])) smpro_hub_set_verified($lid, $mip);
                return ['ok' => !empty($b['vok']), 'nopass' => !empty($b['nopass']), 'locked' => !empty($b['locked']), 'until' => (int)($b['until'] ?? 0)];
            }
        }
    }
    return ['ok' => false, 'timeout' => true];
}

/** HUB master: ask a managed server to reset its brute-force lock (once/24h enforced member-side). E2E-sealed. */
function smpro_hub_reset_lock_request($lid) {
    $lid = (int)$lid; $rid = bin2hex(random_bytes(6));
    smpro_hub_api('live', ['link_id' => $lid]);
    smpro_hub_api('send', ['link_id' => $lid, 'dir' => 'cmd', 'body' => smpro_hub_seal($lid, ['action' => 'reset_lock', 'req' => $rid])]);
    $deadline = time() + 70;
    while (time() < $deadline) {
        usleep(800000);
        [$ok, $d] = smpro_hub_api('fetch', ['link_id' => $lid, 'dir' => 'result', 'max' => 25], 8);
        if ($ok) foreach ((array)($d['items'] ?? []) as $it) {
            $b = smpro_hub_open($lid, (string)($it['body'] ?? ''));
            if (is_array($b) && ($b['req'] ?? '') === $rid) {
                if (function_exists('smpro_audit')) smpro_audit('hub_lock_reset', ['link' => $lid, 'by' => 'hub', 'ok' => !empty($b['rok'])]);
                if (!empty($b['rok']))      return ['ok' => true, 'msg' => 'Lock reset on the managed server.'];
                if (!empty($b['cooldown'])) return ['ok' => false, 'cooldown' => true, 'next' => (int)($b['next'] ?? 0), 'msg' => 'A reset was already used there in the last 24h' . (!empty($b['next']) ? ' (next: ' . date('Y-m-d H:i', (int)$b['next']) . ')' : '') . '.'];
                return ['ok' => false, 'msg' => 'No active lock on the managed server.'];
            }
        }
    }
    return ['ok' => false, 'timeout' => true, 'msg' => 'The managed server did not answer yet (it comes online within ~60s). Try again.'];
}

/** HUB: UNDISCLOSED step-up rules — returns a (non-UI) reason to (re)ask for the member's password, or '' if fine. */
function smpro_hub_needs_verify($lid, $action = '', $snap = null) {
    $st = smpro_hub_vstate($lid); $now = time();
    if (!$st || empty($st['ts']))                                            return 'first';            // R7 never verified
    if ($now - (int)$st['ts'] > 86400)                                       return 'periodic';         // R8 24h max
    if (in_array($action, ['revoke', 'update', 'restart_service', 'apply_profile', 'bulk'], true)) return 'sensitive_action'; // R2
    if ($now - (int)$st['ts'] > 1800)                                        return 'idle';             // R1 30-min idle
    if (smpro_hub_boot_ts() > (int)$st['ts'] && smpro_hub_boot_ts() > 0)     return 'hub_restarted';    // R5
    if (is_array($snap)) {
        if (!empty($snap['_mip']) && !empty($st['mip']) && $snap['_mip'] !== $st['mip']) return 'member_ip_changed';          // R3
        if (!empty($snap['rebooted']) && strtotime((string)$snap['rebooted']) > (int)$st['ts']) return 'member_rebooted';     // R4
    }
    return '';
}

/* ===== Per-link end-to-end authentication: ECDH shared secret + per-request HMAC token =====
 * Each pairing exchanges ECDH public keys (relay carries them but, being passive, never learns the
 * derived secret). Every message then carries a per-request token: nonce + timestamp + HMAC over the
 * body, signed with the shared secret. The receiver verifies signature + freshness + nonce (anti-replay)
 * and audits every check — so a compromised relay can neither forge nor replay commands. */
function smpro_hub_dh_keypair() {
    $k = @openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
    if (!$k) return ['', ''];
    $priv = ''; openssl_pkey_export($k, $priv); $d = openssl_pkey_get_details($k);
    return [(string)$priv, (string)($d['key'] ?? '')];
}
function smpro_hub_dh_secret($privPem, $peerPub) {
    if (!function_exists('openssl_pkey_derive') || $privPem === '' || trim((string)$peerPub) === '') return '';
    $a = @openssl_pkey_get_private($privPem); $b = @openssl_pkey_get_public((string)$peerPub);
    if (!$a || !$b) return '';
    $raw = @openssl_pkey_derive($b, $a, 32);
    return $raw ? hash('sha256', $raw) : '';
}
function smpro_hub_sec_dir() { $d = SMPRO_VARLIB . '/hub/sec'; @mkdir($d, 0700, true); return $d; }
function smpro_hub_secret($lid) { $f = smpro_hub_sec_dir() . '/' . (int)$lid . '.key'; return is_file($f) ? trim((string)@file_get_contents($f)) : ''; }
/** Store the ECDH secret + the link context used to bind the encryption key (token + identity). */
function smpro_hub_set_secret($lid, $s, array $ctx = []) {
    if ((string)$s === '') return;
    $f = smpro_hub_sec_dir() . '/' . (int)$lid . '.key'; @file_put_contents($f, $s); @chmod($f, 0600);
    if ($ctx) { $cf = smpro_hub_sec_dir() . '/' . (int)$lid . '.ctx'; @file_put_contents($cf, json_encode($ctx, JSON_UNESCAPED_SLASHES)); @chmod($cf, 0600); }
}
function smpro_hub_priv_path($code) { $d = SMPRO_VARLIB . '/hub/dh'; @mkdir($d, 0700, true); return $d . '/' . preg_replace('/[^A-F0-9-]/', '', strtoupper((string)$code)) . '.pem'; }

/** Optional SHARED end-to-end passphrase — set the SAME value on both servers to "seal" the channel with
 *  a secret the relay never sees. Stored as a deterministic hash so both sides derive the identical key. */
function smpro_hub_e2e_pass_file() { return SMPRO_VARLIB . '/hub/e2e_pass'; }
function smpro_hub_e2e_pass_isset() { return is_file(smpro_hub_e2e_pass_file()); }
function smpro_hub_e2e_pass_set($pw) {
    @mkdir(SMPRO_VARLIB . '/hub', 0700, true); $f = smpro_hub_e2e_pass_file();
    if ((string)$pw === '') { @unlink($f); return true; }
    @file_put_contents($f, hash('sha256', 'smpro-e2e|' . $pw)); @chmod($f, 0600); return true;   // deterministic (NOT password_hash) so both sides match
}
function smpro_hub_e2e_pass() { $f = smpro_hub_e2e_pass_file(); return is_file($f) ? trim((string)@file_get_contents($f)) : ''; }

/** Derive the AES-256 key for a link = SHA256( ECDH-secret | pair_code(token) | member key | host | IP | shared-passphrase ).
 *  Binds confidentiality to the token + both endpoints' identity + (optionally) a password the relay never sees. */
function smpro_hub_enckey($lid) {
    $sec = smpro_hub_secret($lid); if ($sec === '') return '';
    $cf = smpro_hub_sec_dir() . '/' . (int)$lid . '.ctx';
    $c = is_file($cf) ? (json_decode((string)@file_get_contents($cf), true) ?: []) : [];
    $material = $sec . '|' . ($c['code'] ?? '') . '|' . ($c['mkey'] ?? '') . '|' . ($c['mhost'] ?? '') . '|' . ($c['mip'] ?? '') . '|' . smpro_hub_e2e_pass();
    return hash('sha256', $material, true);   // 32 raw bytes
}

function smpro_hub_seal($lid, array $payload) {
    $body = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    $key = smpro_hub_enckey($lid);
    if ($key === '') {                                              // no shared E2E key yet → NEVER ship plaintext through the
        if (function_exists('smpro_audit')) smpro_audit('hub_seal_nokey', ['link' => (int)$lid]);   // (untrusted) relay. The
        return '';                                                 // receiver rejects keyless links anyway; sealing would only
    }                                                              // risk leaking the control password before ECDH is derived.
    $n = bin2hex(random_bytes(8)); $t = time(); $iv = random_bytes(12); $tag = '';
    $ct = openssl_encrypt($body, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, (int)$lid . '|' . $n . '|' . $t);
    if ($ct === false) {                                            // a key EXISTS but encryption failed — NEVER fall back to
        if (function_exists('smpro_audit')) smpro_audit('hub_seal_fail', ['link' => (int)$lid]);   // plaintext (would expose the
        return '';                                                  // control password to the relay). Drop the message instead.
    }
    return json_encode(['c' => base64_encode($iv . $tag . $ct), 'n' => $n, 't' => $t], JSON_UNESCAPED_SLASHES);   // encrypted + authenticated (GCM)
}
function smpro_hub_open($lid, $raw) {
    $e = json_decode((string)$raw, true); if (!is_array($e)) return null;
    $key = smpro_hub_enckey($lid);
    if (isset($e['c'], $e['n'], $e['t'])) {                         // encrypted envelope
        if ($key === '') return null;
        $blob = base64_decode((string)$e['c'], true); if ($blob === false || strlen($blob) < 29) return null;
        $iv = substr($blob, 0, 12); $tag = substr($blob, 12, 16); $ct = substr($blob, 28);
        $body = openssl_decrypt($ct, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, (int)$lid . '|' . $e['n'] . '|' . $e['t']);
        if ($body === false)                            { if (function_exists('smpro_audit')) smpro_audit('hub_auth_reject', ['link' => (int)$lid, 'why' => 'bad_decrypt']); return null; }
        if (abs(time() - (int)$e['t']) > 300)           { if (function_exists('smpro_audit')) smpro_audit('hub_auth_reject', ['link' => (int)$lid, 'why' => 'stale']); return null; }
        if (!smpro_hub_nonce_ok($lid, (string)$e['n'])) { if (function_exists('smpro_audit')) smpro_audit('hub_auth_reject', ['link' => (int)$lid, 'why' => 'replay']); return null; }
        $p = json_decode((string)$body, true); return is_array($p) ? $p : null;
    }
    // raw legacy payload — accepted ONLY when no key exists on this link; with a key set, a raw message is a
    // downgrade/forgery attempt and is rejected.
    if ($key !== '') { if (function_exists('smpro_audit')) smpro_audit('hub_auth_reject', ['link' => (int)$lid, 'why' => 'downgrade']); return null; }
    return $e;
}
function smpro_hub_nonce_ok($lid, $n) {
    $f = SMPRO_VARLIB . '/hub/nonce/' . (int)$lid . '.json'; @mkdir(dirname($f), 0700, true);
    // hold an exclusive lock across the whole read-check-write so two concurrent deliveries (cron tick +
    // live-loop) of the SAME nonce can't both pass — that would be a replay window.
    $fh = @fopen($f, 'c+'); if (!$fh) return false;
    if (!@flock($fh, LOCK_EX)) { fclose($fh); return false; }
    $raw = stream_get_contents($fh); $seen = $raw !== '' ? (json_decode($raw, true) ?: []) : [];
    $now = time(); foreach ($seen as $k => $ts) if ($now - (int)$ts > 600) unset($seen[$k]);
    $ok = !isset($seen[$n]);
    if ($ok) {
        $seen[$n] = $now;
        @ftruncate($fh, 0); @rewind($fh); @fwrite($fh, json_encode($seen, JSON_UNESCAPED_SLASHES));
    }
    @flock($fh, LOCK_UN); @fclose($fh); @chmod($f, 0600);
    return $ok;
}
/** HUB: derive+store the shared secret for any active link that now has the member's public key. */
function smpro_hub_ensure_secrets(array $links) {
    foreach ($links as $L) {
        if (($L['status'] ?? '') !== 'active') continue;
        $lid = (int)$L['link_id']; if (smpro_hub_secret($lid) !== '') continue;
        $mpub = (string)($L['member_pub'] ?? ''); if (trim($mpub) === '') continue;
        $pf = smpro_hub_priv_path($L['pair_code'] ?? ''); if (!is_file($pf)) continue;
        $sec = smpro_hub_dh_secret((string)@file_get_contents($pf), $mpub);
        if ($sec !== '') {
            $ctx = ['code' => (string)($L['pair_code'] ?? ''), 'mkey' => (string)($L['member_key'] ?? ''), 'mhost' => (string)($L['member_host'] ?? ''), 'mip' => (string)($L['member_ip'] ?? '')];
            smpro_hub_set_secret($lid, $sec, $ctx); @unlink($pf);
            if (function_exists('smpro_audit')) smpro_audit('hub_secret_established', ['link' => $lid, 'role' => 'hub']);
        }
    }
}

/** Install the per-minute member worker cron (idempotent) so members respond + see invites
 *  even when no admin is browsing. The worker itself exits instantly when not an active member. */
function smpro_hub_install_cron() {
    $cron = '/etc/cron.d/smpro-hub';
    $worker = SMPRO_BASE . '/bin/hub_worker.php';
    if (!is_file($worker)) return;
    $php = is_executable('/usr/local/cpanel/3rdparty/bin/php') ? '/usr/local/cpanel/3rdparty/bin/php' : (trim((string)@shell_exec('command -v php')) ?: 'php');
    $want = "# Safety Monitor Pro — multi-server member worker\n* * * * * root " . $php . ' ' . $worker . " >/dev/null 2>&1\n";
    $cur = is_file($cron) ? (string)@file_get_contents($cron) : '';
    if (trim($cur) !== trim($want)) @file_put_contents($cron, $want);
}

/** License key currently activated on this server. */
function smpro_hub_key() {
    return trim((string)(smpro_lic_state()['key'] ?? smpro_lic_state()['license_key'] ?? ''));
}

/** Identity fields every relay call carries (authenticated server-side). */
function smpro_hub_identity() {
    return [
        'license_key' => smpro_hub_key(),
        'fingerprint' => function_exists('smpro_lic_fingerprint') ? smpro_lic_fingerprint() : '',
        'server_ip'   => function_exists('smpro_lic_server_ip') ? smpro_lic_server_ip() : '',
        'hostname'    => php_uname('n'),
    ];
}

/** POST to a /api/hub/* relay endpoint. Returns [ok(bool), data(array), http(int)]. */
function smpro_hub_api($path, array $fields = [], $timeout = 20) {
    if (!function_exists('smpro_lic_api')) return [false, ['message' => 'license transport unavailable'], 0];
    $body = array_merge(smpro_hub_identity(), $fields);
    [$code, $json, $raw] = smpro_lic_api('/api/hub/' . ltrim($path, '/'), $body, $timeout);
    $ok = is_array($json) && !empty($json['ok']);
    return [$ok, is_array($json) ? $json : ['message' => 'no response', 'raw' => substr((string)$raw, 0, 300)], (int)$code];
}

/* ---------------------------------------------------------------- HUB role */

function smpro_hub_init($label, array $perms, $targetKey = '', $mode = 'control') {
    // a Slave (managed by a hub) cannot become a Master
    foreach (smpro_hub_links('member') as $L) if (($L['status'] ?? '') === 'active')
        return [false, ['message' => 'This server is managed by a hub — remove that pairing first before it can manage others.']];
    $mode  = $mode === 'monitor' ? 'monitor' : 'control';
    $perms = $mode === 'monitor' ? ['view'] : array_values(array_intersect($perms, array_keys(smpro_hub_perms_all())));
    if (!in_array('view', $perms, true)) array_unshift($perms, 'view');
    [$priv, $pub] = smpro_hub_dh_keypair();
    [$ok, $d] = smpro_hub_api('init', ['hub_label' => (string)$label, 'perms_req' => $perms, 'target_member_key' => strtoupper(trim((string)$targetKey)), 'mode' => $mode, 'hub_pub' => $pub]);
    if ($ok && !empty($d['pair_code']) && $priv !== '') { @file_put_contents(smpro_hub_priv_path($d['pair_code']), $priv); @chmod(smpro_hub_priv_path($d['pair_code']), 0600); }
    if ($ok && function_exists('smpro_audit')) smpro_audit('hub_pair_init', ['code' => true, 'mode' => $mode, 'perms' => $perms, 'target' => $targetKey]);   // never log the raw pairing token
    return [$ok, $d];
}
/** HUB: fleet overview — latest vital snapshot for every active member (cached so it's never blank). */
function smpro_hub_fleet() {
    $cf = SMPRO_VARLIB . '/hub/fleet.json'; @mkdir(dirname($cf), 0700, true);
    $prev = is_file($cf) ? (json_decode((string)@file_get_contents($cf), true) ?: []) : [];
    $cache = is_array($prev['snaps'] ?? null) ? $prev['snaps'] : [];
    $links = smpro_hub_links('hub');
    // prune cached snaps for links that are no longer active (revoked/removed) so the Dashboard never shows a ghost
    $activeIds = [];
    foreach ($links as $L) if (($L['status'] ?? '') === 'active') $activeIds[(string)$L['link_id']] = true;
    foreach (array_keys($cache) as $k) if (empty($activeIds[$k])) unset($cache[$k]);
    foreach ($links as $L) {
        if (($L['status'] ?? '') !== 'active') continue;
        $items = smpro_hub_pull((int)$L['link_id'], 'status');           // newest last (consumes; cache keeps last-known)
        if ($items) $cache[(string)$L['link_id']] = $items[count($items) - 1];
    }
    $out = [];
    foreach ($links as $L) {
        if (($L['status'] ?? '') !== 'active') continue;
        $out[] = ['link' => $L, 'snap' => $cache[(string)$L['link_id']] ?? null];
    }
    // atomic write (tmp + rename) so the cron worker and a web request never leave a half-written fleet.json
    $tmp = $cf . '.tmp.' . getmypid();
    if (@file_put_contents($tmp, json_encode(['ts' => time(), 'snaps' => $cache, 'fleet' => $out], JSON_UNESCAPED_SLASHES), LOCK_EX) !== false) { @chmod($tmp, 0600); @rename($tmp, $cf); }
    return $out;
}

/** HUB: fleet from the local cache only (ZERO relay calls) — fast, for the Dashboard. Cron keeps it fresh. */
function smpro_hub_fleet_cached() {
    $cf = SMPRO_VARLIB . '/hub/fleet.json';
    $d = is_file($cf) ? (json_decode((string)@file_get_contents($cf), true) ?: []) : [];
    return is_array($d['fleet'] ?? null) ? $d['fleet'] : [];
}

/** Classify a member's snapshot → list of human problem strings (empty = healthy). For hub alerts. */
function smpro_hub_snap_issues($s) {
    if (!is_array($s) || empty($s)) return ['not reporting yet'];
    $i = [];
    if (!empty($s['rebooted']))                                   $i[] = 'rebooted';
    if (!empty($s['svc_failed']))                                 $i[] = (int)$s['svc_failed'] . ' failed service' . ((int)$s['svc_failed'] > 1 ? 's' : '');
    if (isset($s['csf_on']) && !$s['csf_on'])                     $i[] = 'firewall OFF';
    if (isset($s['disk']) && $s['disk'] !== null && (float)$s['disk'] >= 90) $i[] = 'disk ' . round((float)$s['disk']) . '%';
    if (isset($s['mem'])  && $s['mem']  !== null && (float)$s['mem']  >= 92) $i[] = 'RAM ' . round((float)$s['mem']) . '%';
    if (!empty($s['ctl_locked']))                                 $i[] = 'remote-control LOCKED';
    if (!empty($s['ts']) && (time() - (int)$s['ts']) > 360)       $i[] = 'stale (not reporting)';
    return $i;
}

/** Recent Hub-related actions from THIS server's audit log (for the activity panel). */
function smpro_hub_history($n = 40) {
    if (!defined('SMPRO_AUDIT_LOG') || !is_readable(SMPRO_AUDIT_LOG)) return [];
    $out = [];
    foreach (array_reverse(explode("\n", (string)@shell_exec('tail -n 800 ' . escapeshellarg(SMPRO_AUDIT_LOG) . ' 2>/dev/null'))) as $l) {
        $j = json_decode(trim($l), true); if (!is_array($j)) continue;
        $a = (string)($j['action'] ?? ''); if (strncmp($a, 'hub_', 4) !== 0) continue;
        $out[] = ['t' => (string)($j['timestamp'] ?? ''), 'action' => $a, 'actor' => (string)($j['actor'] ?? ''), 'details' => $j['details'] ?? []];
        if (count($out) >= $n) break;
    }
    return $out;
}

/** MEMBER: invitations addressed to THIS server (live from the relay). */
function smpro_hub_invites() {
    [$ok, $d] = smpro_hub_api('invites', []);
    return $ok ? (array)($d['invites'] ?? []) : [];
}
/** Cheap, no-network read of the cached pending invitations (for the cross-plugin banner). */
function smpro_hub_invites_cached() {
    $f = SMPRO_VARLIB . '/hub/invites.json';
    if (!is_file($f) || (time() - (int)@filemtime($f)) > 600) return [];
    $d = json_decode((string)@file_get_contents($f), true);
    return is_array($d) ? $d : [];
}
function smpro_hub_links($role = 'hub') {
    [$ok, $d] = smpro_hub_api('links', ['role' => $role === 'member' ? 'member' : 'hub']);
    $links = $ok ? (array)($d['links'] ?? []) : [];
    if ($role !== 'member' && $links) smpro_hub_ensure_secrets($links);   // hub: derive shared secrets once member_pub is in
    return $links;
}
function smpro_hub_revoke($linkId) {
    [$ok, $d] = smpro_hub_api('revoke', ['link_id' => (int)$linkId]);
    if ($ok) {
        smpro_hub_link_forget((int)$linkId);                                 // drop it from the Dashboard fleet + wipe per-link secrets NOW
        if (function_exists('smpro_audit')) smpro_audit('hub_revoke', ['link' => (int)$linkId]);
    }
    return [$ok, $d];
}
/** Remove all local trace of a link after revoke: the cached fleet entry (so the Dashboard updates instantly)
 *  plus its E2E secret/ctx/nonce/verified state (so a future re-pair starts clean). */
function smpro_hub_link_forget($linkId) {
    $lid = (int)$linkId; $k = (string)$lid;
    $cf = SMPRO_VARLIB . '/hub/fleet.json';
    if (is_file($cf)) {
        $d = json_decode((string)@file_get_contents($cf), true) ?: [];
        if (isset($d['snaps'][$k])) unset($d['snaps'][$k]);
        if (is_array($d['fleet'] ?? null)) $d['fleet'] = array_values(array_filter($d['fleet'], fn($e) => (string)(int)($e['link']['link_id'] ?? 0) !== $k));
        @file_put_contents($cf, json_encode($d, JSON_UNESCAPED_SLASHES));
    }
    @unlink(smpro_hub_sec_dir() . '/' . $lid . '.key');
    @unlink(smpro_hub_sec_dir() . '/' . $lid . '.ctx');
    @unlink(SMPRO_VARLIB . '/hub/nonce/' . $lid . '.json');
    if (function_exists('smpro_hub_vstate_file')) @unlink(smpro_hub_vstate_file($lid));
}
/** HUB → queue a plugin-scoped command for a member link. */
function smpro_hub_push_cmd($linkId, $action, array $args = []) {
    $payload = smpro_hub_seal((int)$linkId, ['action' => (string)$action, 'args' => $args, 'ts' => time()]);
    [$ok, $d] = smpro_hub_api('send', ['link_id' => (int)$linkId, 'dir' => 'cmd', 'body' => $payload]);
    if ($ok && function_exists('smpro_audit')) smpro_audit('hub_push_cmd', ['link' => (int)$linkId, 'action' => $action]);
    return [$ok, $d];
}
/** HUB → pull the latest status/results a member posted. Returns decoded items (newest last). */
function smpro_hub_pull($linkId, $dir = 'status') {
    [$ok, $d] = smpro_hub_api('fetch', ['link_id' => (int)$linkId, 'dir' => $dir, 'max' => 20]);
    if (!$ok) return [];
    $out = [];
    foreach ((array)($d['items'] ?? []) as $it) {
        $b = smpro_hub_open((int)$linkId, (string)($it['body'] ?? ''));
        if (is_array($b)) { $b['_at'] = $it['created_at'] ?? ''; $out[] = $b; }
    }
    return $out;
}

/* ------------------------------------------------------------- MEMBER role */

function smpro_hub_lookup($code) {
    [$ok, $d] = smpro_hub_api('lookup', ['pair_code' => strtoupper(trim((string)$code))]);
    return [$ok, $d];
}
function smpro_hub_approve($code, array $perms) {
    // a Master (already managing others) cannot become a Slave
    foreach (smpro_hub_links('hub') as $L) if (in_array(($L['status'] ?? ''), ['active','pending'], true))
        return [false, ['message' => 'This server is a Hub (manages other servers) — remove its paired servers first before another hub can manage it.']];
    // a server can be managed by ONLY ONE hub at a time
    foreach (smpro_hub_links('member') as $L) if (($L['status'] ?? '') === 'active')
        return [false, ['message' => 'This server is already managed by a hub. Remove that pairing first — a server can only be managed by one hub.']];
    $perms = array_values(array_intersect($perms, array_keys(smpro_hub_perms_all())));
    if (!in_array('view', $perms, true)) array_unshift($perms, 'view');
    // fetch the hub's public key, generate ours, derive the shared secret
    [$lok, $linfo] = smpro_hub_lookup($code);
    $hubPub = $lok ? (string)($linfo['hub_pub'] ?? '') : '';
    [$priv, $pub] = smpro_hub_dh_keypair();
    [$ok, $d] = smpro_hub_api('approve', ['pair_code' => strtoupper(trim((string)$code)), 'perms_grant' => $perms, 'member_pub' => $pub]);
    if ($ok && !empty($d['link_id']) && $priv !== '' && $hubPub !== '') {
        $sec = smpro_hub_dh_secret($priv, $hubPub);
        if ($sec !== '') {
            $ctx = ['code' => strtoupper(trim((string)$code)), 'mkey' => smpro_hub_key(), 'mhost' => php_uname('n'), 'mip' => (function_exists('smpro_lic_server_ip') ? smpro_lic_server_ip() : '')];
            smpro_hub_set_secret((int)$d['link_id'], $sec, $ctx);
            if (function_exists('smpro_audit')) smpro_audit('hub_secret_established', ['link' => (int)$d['link_id'], 'role' => 'member']);
        }
    }
    if ($ok && function_exists('smpro_audit')) smpro_audit('hub_pair_approve', ['code' => strtoupper(trim((string)$code)), 'granted' => $perms]);
    return [$ok, $d];
}

/** A read-only snapshot a Member reports up to its Hub(s). Plugin-scoped, no secrets. */
function smpro_hub_status_snapshot() {
    $m = function_exists('smpro_collect_metrics') ? smpro_collect_metrics() : [];
    $s = smpro_lic_state();
    $snap = [
        'hostname' => php_uname('n'),
        'version'  => defined('SMPRO_VERSION') ? SMPRO_VERSION : '',
        'plan'     => (string)($s['plan'] ?? ''),
        'load'     => $m['load'] ?? null,
        'cpu'      => $m['cpu']['pct'] ?? null,
        'mem'      => $m['ram']['pct'] ?? null,
        'disk'     => $m['disk']['pct'] ?? null,
        'uptime'   => $m['uptime'] ?? null,
        'ts'       => time(),
    ];
    if (function_exists('smpro_csf_blocked_set')) { $b = smpro_csf_blocked_set(); $snap['blocked'] = is_array($b) ? count($b) : null; }
    // --- drill-down extras (cheap shell reads) ---
    $snap['svc_failed'] = (int)trim((string)@shell_exec('systemctl --failed --no-legend 2>/dev/null | wc -l'));
    $csf = @shell_exec('systemctl is-active csf lfd 2>/dev/null'); $snap['csf_on'] = (stripos((string)$csf, 'active') !== false);
    $top = [];
    foreach (array_filter(array_map('trim', explode("\n", (string)@shell_exec("ps -eo pcpu,comm --sort=-pcpu 2>/dev/null | sed 1d | head -4")))) as $l) {
        if (preg_match('/^([\d.]+)\s+(.+)$/', $l, $m) && (float)$m[1] > 0) $top[] = ['cpu' => (float)$m[1], 'cmd' => mb_substr($m[2], 0, 24)];
    }
    $snap['top'] = $top;
    // recent reboot (so the hub sees crashes on members)
    $bts = (int)trim((string)@shell_exec('date -d "$(uptime -s 2>/dev/null)" +%s 2>/dev/null'));
    if ($bts && (time() - $bts) < 86400) $snap['rebooted'] = date('Y-m-d H:i', $bts);
    // step-up brute-force lock state (so the master sees a member that locked itself after wrong attempts)
    if (function_exists('smpro_hub_lock_state')) { $ls = smpro_hub_lock_state(); if (!empty($ls['until'])) { $snap['ctl_locked'] = true; $snap['ctl_lock_until'] = (int)$ls['until']; } }
    return $snap;
}

/** Execute ONE plugin-scoped command on the Member, enforcing granted permissions. [ok,msg]. */
function smpro_hub_exec($action, array $args, array $granted) {
    $action = preg_replace('/[^a-z_]/', '', strtolower((string)$action));
    $need = smpro_hub_action_perm($action);
    if (!in_array($need, $granted, true)) return [false, "permission '$need' not granted"];

    // Honor the local master switch / dry-run, same as every other automated action.
    if (function_exists('smpro_ctl_disabled') && smpro_ctl_disabled()) return [false, 'plugin disabled on this server'];
    $dry = function_exists('smpro_ctl_dry_run') && smpro_ctl_dry_run();

    switch ($action) {
        case 'ping':   return [true, 'pong'];
        case 'status': return [true, 'status reported'];

        case 'block_ip': {
            $ip = trim((string)($args['ip'] ?? ''));
            if (!filter_var($ip, FILTER_VALIDATE_IP)) return [false, 'invalid IP'];
            if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) return [false, 'refusing local/private IP'];
            if (function_exists('smpro_admin_ip') && $ip === smpro_admin_ip()) return [false, 'refusing the admin IP'];
            if ($dry) return [true, "[dry-run] would block $ip"];
            @shell_exec('csf -d ' . escapeshellarg($ip) . ' ' . escapeshellarg('SM Hub block') . ' 2>/dev/null');
            return [true, "block requested for $ip"];
        }
        case 'unblock_ip': {
            $ip = trim((string)($args['ip'] ?? ''));
            if (!filter_var($ip, FILTER_VALIDATE_IP)) return [false, 'invalid IP'];
            if ($dry) return [true, "[dry-run] would unblock $ip"];
            @shell_exec('csf -dr ' . escapeshellarg($ip) . ' 2>/dev/null');
            return [true, "unblock requested for $ip"];
        }
        case 'apply_profile': {
            $p = preg_replace('/[^a-z0-9_]/', '', strtolower((string)($args['profile'] ?? '')));
            if ($p === '' || !function_exists('smpro_prof_apply')) return [false, 'no profile / unsupported'];
            if ($dry) return [true, "[dry-run] would apply profile $p"];
            $r = smpro_prof_apply($p, 'via Hub');
            return [is_array($r) ? !empty($r['ok']) : (bool)$r, "profile $p applied"];
        }
        case 'restart_service': {
            $svc = preg_replace('/[^a-z0-9_\-]/', '', strtolower((string)($args['service'] ?? '')));
            $script = '/scripts/restartsrv_' . $svc;
            if ($svc === '' || !is_executable($script)) return [false, 'unknown/unsupported service'];
            if ($dry) return [true, "[dry-run] would restart $svc"];
            @shell_exec(escapeshellarg($script) . ' 2>/dev/null');
            return [true, "restart requested: $svc"];
        }
        case 'update': {
            if (!function_exists('smpro_upd_apply')) return [false, 'update unsupported'];
            if ($dry) return [true, '[dry-run] would update'];
            $ver = preg_replace('/[^0-9.]/', '', (string)($args['version'] ?? ''));
            $r = smpro_upd_apply($ver, true);
            return [is_array($r) ? !empty($r['ok']) : (bool)$r, 'update triggered' . ($ver ? " ($ver)" : '')];
        }
    }
    return [false, "unknown action: $action"];
}

/** MEMBER: render one of THIS server's plugin pages to HTML (read-only) for a hub's remote panel.
 *  Runs the real index.php in a fresh GET process so the output is byte-identical to a browser view. */
function smpro_hub_render($page) {
    $page = preg_replace('/[^a-z0-9_\-]/', '', strtolower((string)$page)); if ($page === '') $page = 'dashboard';
    if (function_exists('smpro_menu_resolve') && !smpro_menu_resolve($page)) return '';   // whitelist via the menu registry
    $idx = SMPRO_BASE . '/index.php';
    $php = is_executable('/usr/local/cpanel/3rdparty/bin/php') ? '/usr/local/cpanel/3rdparty/bin/php' : (defined('PHP_BINARY') && PHP_BINARY ? PHP_BINARY : 'php');
    // env vars MUST come before `timeout` (a leading `timeout VAR=x` treats the assignment as its command)
    $cmd = 'REQUEST_METHOD=GET QUERY_STRING=' . escapeshellarg('page=' . $page . '&hub_render=1') . ' REMOTE_USER=root '
         . 'timeout 20 ' . escapeshellarg($php) . ' ' . escapeshellarg($idx);
    return (string)@shell_exec($cmd . ' 2>/dev/null');
}

/** MEMBER: proxy a READ-ONLY (GET) request to this server's plugin and return the output (HTML or JSON).
 *  GET-only by design (the plugin's convention: GET = read-only), so it can never change state — that
 *  keeps the remote panel's live views/reports working without granting action power beyond the toolbar. */
function smpro_hub_proxy($query) {
    $query = ltrim((string)$query, '?');
    if ($query === '' || strlen($query) > 4000) $query = 'page=dashboard';
    parse_str($query, $q);
    // STRICT PARAMETER ALLOWLIST (replaces the old deny-list): every key must be a known READ-ONLY view/filter
    // param. Anything else — incl. any future state-changing GET trigger we forget to deny — blocks the whole
    // request. This is in addition to GET-forcing below (REQUEST_METHOD=GET = the structural read-only guarantee).
    static $proxy_allow = [
        'page','format','metric','limit','mins','win','days','range','from','to','o_date','o_from','o_to',
        'tab','cat','country','ip','view','p','o','q','sort','dir','type','user','audit_user','phuser','bip',
        'loglines','weblines','showlocal','show_hidden','saved','report','im_export','im_live','im_attack',
        'rc_export','rc_live','hub_render',
    ];
    foreach ($q as $k => $v) if (!in_array(strtolower((string)$k), $proxy_allow, true)) return '';   // unknown/action key → refuse
    // ALLOWLIST: must target a real menu page, OR be a pure live-metric poll (format=json&metric=…)
    $page = preg_replace('/[^a-z0-9_\-]/', '', strtolower((string)($q['page'] ?? '')));
    $isMetric = isset($q['metric']) || (($q['format'] ?? '') === 'json');
    if ($page !== '' && function_exists('smpro_menu_resolve') && !smpro_menu_resolve($page)) return '';
    if ($page === '' && !$isMetric) return '';
    $idx = SMPRO_BASE . '/index.php';
    $php = is_executable('/usr/local/cpanel/3rdparty/bin/php') ? '/usr/local/cpanel/3rdparty/bin/php' : (defined('PHP_BINARY') && PHP_BINARY ? PHP_BINARY : 'php');
    $cmd = 'REQUEST_METHOD=GET QUERY_STRING=' . escapeshellarg($query . '&hub_render=1') . ' REMOTE_USER=root '
         . 'timeout 20 ' . escapeshellarg($php) . ' ' . escapeshellarg($idx);
    return (string)@shell_exec($cmd . ' 2>/dev/null');
}

/** MEMBER: process all pending commands for ONE link (exec actions or render pages), post results. */
function smpro_hub_process_link($lid, array $granted) {
    $lid = (int)$lid; $done = 0; $errs = 0;
    // HARD REQUIREMENT: never process commands on a link with no established E2E secret. Otherwise smpro_hub_open
    // would fall back to accepting RAW (unauthenticated) payloads, letting the untrusted relay inject commands.
    // Commands are never part of the key-establishment handshake, so a keyless link must run nothing.
    if (smpro_hub_enckey($lid) === '') {
        if (function_exists('smpro_audit')) smpro_audit('hub_auth_reject', ['link' => $lid, 'why' => 'no_secret']);
        return [0, 0];
    }
    [$ok, $d] = smpro_hub_api('fetch', ['link_id' => $lid, 'dir' => 'cmd', 'max' => 20], 8);
    if (!$ok) return [0, 0];
    foreach ((array)($d['items'] ?? []) as $it) {
        $cmd = smpro_hub_open($lid, (string)($it['body'] ?? ''));    // decode + verify per-request token (E2E enforced — see guard above)
        if (!is_array($cmd)) { $errs++; continue; }                  // unverified/forged/replayed → dropped (audited)
        $action = (string)($cmd['action'] ?? '');
        if ($action === 'verify_pass') {                            // hub proves it knows THIS server's control password
            $res = smpro_hub_member_verify_pass((string)($cmd['pw'] ?? ''), $lid);
            smpro_hub_api('send', ['link_id' => $lid, 'dir' => 'result', 'body' => smpro_hub_seal($lid, ['req' => (string)($cmd['req'] ?? ''), 'vok' => $res['ok'], 'nopass' => $res['nopass'], 'locked' => $res['locked'], 'until' => (int)($res['until'] ?? 0), 'ts' => time()])]);
            if (function_exists('smpro_audit')) smpro_audit('hub_verify_pass', ['link' => $lid, 'ok' => $res['ok'], 'locked' => $res['locked']]);
            $done++; continue;
        }
        if ($action === 'reset_lock') {                             // hub master asks us to clear our brute-force lock (once/24h)
            $r = smpro_hub_lock_reset('hub');
            smpro_hub_api('send', ['link_id' => $lid, 'dir' => 'result', 'body' => smpro_hub_seal($lid, ['req' => (string)($cmd['req'] ?? ''), 'rok' => !empty($r['ok']) && !empty($r['was_locked']), 'cooldown' => !empty($r['cooldown']), 'next' => (int)($r['next'] ?? 0), 'ts' => time()])]);
            $done++; continue;
        }
        if ($action === 'render') {                                  // remote-panel page view (needs 'view')
            $html = in_array('view', $granted, true) ? smpro_hub_render((string)($cmd['page'] ?? 'dashboard')) : '';
            smpro_hub_api('send', ['link_id' => $lid, 'dir' => 'result',
                'body' => smpro_hub_seal($lid, ['req' => (string)($cmd['req'] ?? ''), 'page' => (string)($cmd['page'] ?? ''), 'html' => $html, 'ts' => time()])]);
            $done++; continue;
        }
        if ($action === 'proxy') {                                   // read-only (GET) sub-request from the panel
            $body = in_array('view', $granted, true) ? smpro_hub_proxy((string)($cmd['query'] ?? '')) : '';
            smpro_hub_api('send', ['link_id' => $lid, 'dir' => 'result',
                'body' => smpro_hub_seal($lid, ['req' => (string)($cmd['req'] ?? ''), 'html' => $body, 'ts' => time()])]);
            $done++; continue;
        }
        [$rok, $msg] = smpro_hub_exec($action, (array)($cmd['args'] ?? []), $granted);
        $rok ? $done++ : $errs++;
        if (function_exists('smpro_audit')) smpro_audit('hub_member_exec', ['link' => $lid, 'action' => $action, 'ok' => $rok, 'msg' => $msg]);
        smpro_hub_api('send', ['link_id' => $lid, 'dir' => 'result',
            'body' => smpro_hub_seal($lid, ['req' => (string)($cmd['req'] ?? ''), 'action' => $action, 'ok' => $rok, 'msg' => $msg, 'ts' => time()])]);
    }
    return [$done, $errs];
}

/** MEMBER tick: process pending commands for every active link + post a status snapshot. Throttled. */
function smpro_hub_member_tick($force = false) {
    if (!smpro_hub_active()) return ['ran' => false, 'reason' => 'inactive'];
    $stamp = SMPRO_VARLIB . '/hub/.member_tick';
    @mkdir(dirname($stamp), 0700, true);
    if (!$force && is_file($stamp) && (time() - (int)@filemtime($stamp)) < 30) return ['ran' => false, 'reason' => 'throttled'];
    @touch($stamp);
    @file_put_contents(SMPRO_VARLIB . '/hub/invites.json', json_encode(smpro_hub_invites(), JSON_UNESCAPED_SLASHES));
    $links = smpro_hub_links('member'); $done = 0; $errs = 0; $live = false;
    foreach ($links as $L) {
        if (($L['status'] ?? '') !== 'active') continue;
        $lid = (int)$L['link_id']; $granted = (array)($L['perms_grant'] ?? []);
        [$dn, $er] = smpro_hub_process_link($lid, $granted); $done += $dn; $errs += $er;
        smpro_hub_api('send', ['link_id' => $lid, 'dir' => 'status', 'body' => smpro_hub_seal($lid, smpro_hub_status_snapshot())]);
        if ((int)($L['live_until'] ?? 0) > time()) $live = true;
    }
    return ['ran' => true, 'links' => count($links), 'done' => $done, 'errs' => $errs, 'live' => $live];
}

/** MEMBER: while a hub is actively viewing (live_until set), fast-poll for ~50s so the remote panel
 *  feels live (~2s). Called from the per-minute cron worker. Single-flight via a lock. */
function smpro_hub_live_loop() {
    if (!smpro_hub_active()) return;
    $lock = SMPRO_VARLIB . '/hub/.live_lock';
    // atomic single-flight: a non-blocking exclusive lock prevents two cron ticks arriving in the same second
    // from both entering the loop (the old is_file()+mtime check was TOCTOU-racy → duplicate relay traffic).
    $fh = @fopen($lock, 'c'); if (!$fh) return;
    if (!@flock($fh, LOCK_EX | LOCK_NB)) { fclose($fh); return; }   // a loop is already running
    @chmod($lock, 0600);
    $end = time() + 50;
    while (time() < $end) {
        $live = false;
        foreach (smpro_hub_links('member') as $L) {
            if (($L['status'] ?? '') !== 'active') continue;
            if ((int)($L['live_until'] ?? 0) <= time()) continue;
            $live = true;
            smpro_hub_process_link((int)$L['link_id'], (array)($L['perms_grant'] ?? []));
        }
        if (!$live) break;                 // no hub viewing → stop early
        usleep(1800000);                   // ~1.8s
    }
    @flock($fh, LOCK_UN); @fclose($fh); @unlink($lock);
}

/* ---- HUB side: live session + remote render request ---- */
function smpro_hub_live($lid) {
    [$ok, $d] = smpro_hub_api('live', ['link_id' => (int)$lid]);
    return [$ok, $d];
}
/** HUB: proxy a read-only (GET) sub-request (live polling / reports search / nav) to the member. */
function smpro_hub_proxy_request($lid, $query) {
    $lid = (int)$lid; $rid = bin2hex(random_bytes(6));
    smpro_hub_api('live', ['link_id' => $lid]);
    smpro_hub_api('send', ['link_id' => $lid, 'dir' => 'cmd', 'body' => smpro_hub_seal($lid, ['action' => 'proxy', 'query' => (string)$query, 'req' => $rid])]);
    $deadline = time() + 14;
    while (time() < $deadline) {
        usleep(800000);
        [$ok, $d] = smpro_hub_api('fetch', ['link_id' => $lid, 'dir' => 'result', 'max' => 25], 8);
        if ($ok) foreach ((array)($d['items'] ?? []) as $it) {
            $b = smpro_hub_open($lid, (string)($it['body'] ?? ''));
            if (is_array($b) && ($b['req'] ?? '') === $rid && isset($b['html'])) return [true, (string)$b['html']];
        }
    }
    return [false, ''];
}

/** HUB: request a remote page render and wait (briefly) for the member to return its HTML. */
function smpro_hub_render_request($lid, $page) {
    $lid = (int)$lid; $rid = bin2hex(random_bytes(6));
    $page = preg_replace('/[^a-z0-9_\-]/', '', strtolower((string)$page));
    smpro_hub_api('live', ['link_id' => $lid]);   // keep the member fast-polling
    smpro_hub_api('send', ['link_id' => $lid, 'dir' => 'cmd', 'body' => smpro_hub_seal($lid, ['action' => 'render', 'page' => $page, 'req' => $rid])]);
    $deadline = time() + 14;
    while (time() < $deadline) {
        usleep(900000);
        [$ok, $d] = smpro_hub_api('fetch', ['link_id' => $lid, 'dir' => 'result', 'max' => 25], 8);
        if ($ok) foreach ((array)($d['items'] ?? []) as $it) {
            $b = smpro_hub_open($lid, (string)($it['body'] ?? ''));
            if (is_array($b) && ($b['req'] ?? '') === $rid && isset($b['html'])) return [true, (string)$b['html']];
        }
    }
    return [false, ''];
}
