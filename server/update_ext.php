<?php
/**
 * update_ext.php — /api/version + /api/update : in-plugin update channel for Safety Monitor Pro.
 *
 *   POST /api/version  {license_key, fingerprint?}                       -> {ok, version, sha256, size, notes}
 *   POST /api/update   {license_key, server_ip, hostname, fingerprint}   -> streams the latest package
 *
 * Unlike /api/download (the one-time INITIAL install), /api/update is for an ALREADY-licensed +
 * bound server pulling a newer build: it requires the request fingerprint to MATCH the license's
 * bound fingerprint, is NOT subject to the single-download limit, and never (re)binds a new machine.
 * Reuses the app's license_find / license_expired / log_event / json_response / db / normalize_*.
 */
if (!function_exists('db')) { return; }

function smpro_rel_dir(): string { return '/opt/aitech-license-server/releases'; }
function smpro_rel_file(): string { return smpro_rel_dir() . '/smpro-latest.tar.gz'; }
function smpro_rel_version(): string { $f = smpro_rel_dir() . '/VERSION'; return is_readable($f) ? trim((string)@file_get_contents($f)) : ''; }
function smpro_rel_notes(): string { $f = smpro_rel_dir() . '/NOTES.txt'; return is_readable($f) ? substr((string)@file_get_contents($f), 0, 4000) : ''; }
/** Base64 RSA-SHA256 signature of the release tarball, produced OFFLINE at publish time with the
 *  private key (which never lives on this server). The plugin verifies it against its embedded public
 *  key before applying — so even a fully compromised license server cannot push a malicious update. */
function smpro_rel_sig(): string { $f = smpro_rel_file() . '.sig'; return is_readable($f) ? trim((string)@file_get_contents($f)) : ''; }

/** Light-gated: a valid (non-suspended/expired/tampered) key may query the latest version. */
function api_version(): never {
    $data = json_input();
    $licenseKey = strtoupper(trim((string)($data['license_key'] ?? '')));
    if ($licenseKey === '') json_response(['ok' => false, 'status' => 'bad_request', 'message' => 'license_key required'], 400);
    $lic = license_find($licenseKey);
    if (!$lic)                                                  json_response(['ok' => false, 'status' => 'invalid',   'message' => 'Invalid license key'], 404);
    if (!empty($lic['tamper_status']) && $lic['tamper_status'] === 'blocked') json_response(['ok' => false, 'status' => 'tampered', 'message' => 'Blocked'], 403);
    if (($lic['status'] ?? '') === 'suspended')                json_response(['ok' => false, 'status' => 'suspended', 'message' => 'License suspended'], 403);
    if (license_expired($lic))                                 json_response(['ok' => false, 'status' => 'expired',   'message' => 'License expired'], 403);

    // Per-server commands: surface ALL pending commands (update / restart / revoke) for this license so the
    // plugin pulls + executes + acks each. Also keep pushed_version (first update) for back-compat.
    $commands = []; $pushedVer = ''; $pushedId = 0;
    if ($q = db()->prepare("SELECT id, command, args FROM license_commands WHERE license_key=? AND status='pending' ORDER BY id ASC")) {
        $q->bind_param('s', $licenseKey); $q->execute(); $rs = $q->get_result();
        while ($row = $rs->fetch_assoc()) {
            $cid = (int)$row['id']; $cmd = (string)$row['command']; $args = (string)$row['args'];
            $commands[] = ['id' => $cid, 'command' => $cmd, 'args' => $args];
            if ($cmd === 'update' && $pushedId === 0) { $pushedVer = preg_replace('/[^0-9.]/', '', $args); $pushedId = $cid; }
            db()->query("UPDATE license_commands SET status='sent', sent_at=NOW() WHERE id=" . $cid);
        }
    }

    $file = smpro_rel_file();
    json_response([
        'ok'      => true,
        'version' => smpro_rel_version(),
        'sha256'  => is_readable($file) ? hash_file('sha256', $file) : '',
        'sig'     => smpro_rel_sig(),
        'size'    => is_readable($file) ? (int)filesize($file) : 0,
        'notes'   => smpro_rel_notes(),
        'pushed_version' => $pushedVer,   // a specific build the operator pushed to THIS server (or '')
        'pushed_id'      => $pushedId,     // license_commands row id to ack after applying
        'commands'       => $commands,     // ALL pending commands [{id,command,args}] for this server
    ]);
}

/** Plugin acknowledges a pushed command result → mark it done/failed in license_commands. */
function api_command_ack(): never {
    $d   = json_input();
    $key = strtoupper(trim((string)($d['license_key'] ?? '')));
    $id  = (int)($d['id'] ?? 0);
    $ok  = !empty($d['ok']);
    $res = substr(strip_tags((string)($d['result'] ?? '')), 0, 400);   // plugins never send markup — strip tags (defence-in-depth vs panel XSS)
    if ($key === '' || $id <= 0) json_response(['ok' => false, 'status' => 'bad_request', 'message' => 'license_key and id required'], 400);
    if (!license_find($key))     json_response(['ok' => false, 'status' => 'invalid', 'message' => 'Invalid license key'], 404);
    $st = $ok ? 'done' : 'failed';
    if ($q = db()->prepare("UPDATE license_commands SET status=?, result=?, done_at=NOW() WHERE id=? AND license_key=? AND status IN ('sent','pending')")) {
        $q->bind_param('ssis', $st, $res, $id, $key); $q->execute();
    }
    if (function_exists('log_event')) log_event($key, 'command_ack', $ok ? 'ok' : 'fail', 'cmd#' . $id . ' ' . $res, []);
    json_response(['ok' => true, 'status' => $st]);
}

/** Streams the latest package to an already-licensed + fingerprint-bound server. No download-limit. */
function api_update(): never {
    $data        = json_input();
    $licenseKey  = strtoupper(trim((string)($data['license_key'] ?? '')));
    $serverIp    = normalize_ip((string)($data['server_ip'] ?? request_ip()));
    $hostname    = substr(trim((string)($data['hostname'] ?? '')), 0, 255);
    $fingerprint = normalize_fingerprint((string)($data['fingerprint'] ?? ''));
    $ctx = ['server_ip' => $serverIp, 'hostname' => $hostname, 'fingerprint' => $fingerprint];

    if ($licenseKey === '' || $fingerprint === '') json_response(['ok' => false, 'status' => 'bad_request', 'message' => 'license_key and fingerprint are required'], 400);

    $lic = license_find($licenseKey);
    if (!$lic) { log_event($licenseKey, 'update', 'invalid', 'Invalid key', $ctx); json_response(['ok' => false, 'status' => 'invalid', 'message' => 'Invalid license key'], 404); }
    $id = (int)$lic['id'];

    if (!empty($lic['tamper_status']) && $lic['tamper_status'] === 'blocked') { log_event($licenseKey, 'update', 'tampered', '', $ctx); json_response(['ok' => false, 'status' => 'tampered', 'message' => 'Blocked. Contact support.'], 403); }
    if (license_expired($lic))  { db()->query("UPDATE licenses SET status='expired' WHERE id=" . $id); log_event($licenseKey, 'update', 'expired', '', $ctx); json_response(['ok' => false, 'status' => 'expired', 'message' => 'License expired'], 403); }
    if (($lic['status'] ?? '') === 'suspended') { log_event($licenseKey, 'update', 'suspended', '', $ctx); json_response(['ok' => false, 'status' => 'suspended', 'message' => 'License suspended'], 403); }

    // updates are ONLY for an already-activated + bound license
    if (empty($lic['bound_fingerprint'])) { log_event($licenseKey, 'update', 'not_activated', 'Not installed yet', $ctx); json_response(['ok' => false, 'status' => 'not_activated', 'message' => 'License not activated — install first.'], 403); }
    if (!hash_equals((string)$lic['bound_fingerprint'], $fingerprint)) { log_event($licenseKey, 'update', 'binding_mismatch', 'Different machine', $ctx); json_response(['ok' => false, 'status' => 'binding_mismatch', 'message' => 'License is bound to a different machine.'], 403); }
    // same machine, origin IP/hostname may have changed — keep it current
    if (!hash_equals((string)$lic['bound_ip'], $serverIp) || !hash_equals((string)($lic['bound_hostname'] ?? ''), $hostname)) {
        $rs = db()->prepare("UPDATE licenses SET bound_ip=?, bound_hostname=? WHERE id=?");
        $rs->bind_param('ssi', $serverIp, $hostname, $id); $rs->execute();
    }

    // IGNORE the request 'version' — it is the plugin's CURRENT (telemetry) version, not a build
    // request. Older plugins overload this field; trusting it handed a stuck client its OWN version
    // back forever (never upgrading). Always serve the LATEST; the plugin's downgrade guard prevents
    // regressions. (Stage a specific build by swapping smpro-latest if ever needed.)
    $reqVer = '';
    if ($reqVer !== '') {
        $vf = smpro_rel_dir() . '/smpro-' . $reqVer . '.tar.gz';
        if (!is_readable($vf)) { log_event($licenseKey, 'update', 'no_release', 'requested ' . $reqVer, $ctx); json_response(['ok' => false, 'status' => 'no_release', 'message' => 'Requested version not available'], 404); }
        $file = $vf; $ver = $reqVer; $sig = is_readable($vf . '.sig') ? trim((string)@file_get_contents($vf . '.sig')) : '';
    } else {
        $file = smpro_rel_file(); $ver = smpro_rel_version(); $sig = smpro_rel_sig();
    }
    if (!is_readable($file)) { log_event($licenseKey, 'update', 'no_release', '', $ctx); json_response(['ok' => false, 'status' => 'no_release', 'message' => 'No release available'], 503); }

    db()->query("UPDATE licenses SET last_check_at=NOW() WHERE id=" . $id);
    $size = (int)filesize($file); $sha = @hash_file('sha256', $file);
    while (ob_get_level() > 0) { ob_end_clean(); }
    ignore_user_abort(true);
    header('Content-Type: application/gzip');
    header('Content-Disposition: attachment; filename="smpro.tar.gz"');
    header('Content-Length: ' . $size);
    if ($ver !== '') header('X-Smpro-Version: ' . $ver);
    if ($sha)        header('X-Smpro-SHA256: ' . $sha);
    if ($sig !== '') header('X-Smpro-Sig: ' . $sig);   // offline RSA-SHA256 signature (base64) the plugin verifies
    header('Cache-Control: no-store');
    $sent = @readfile($file);
    log_event($licenseKey, 'update', ($sent !== false && (int)$sent === $size && !connection_aborted()) ? 'ok' : 'incomplete', 'Served update ' . $ver . ' (' . $size . ' bytes)', $ctx);
    exit;
}
