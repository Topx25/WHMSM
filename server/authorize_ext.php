<?php
/**
 * authorize_ext.php — /api/authorize : per-action, replay-proof authorization for
 * Safety Monitor Pro (smprov1). Reuses the server's existing license_find() +
 * sign_payload() (same RSA key as /api/check), and ECHOES the client nonce so a
 * captured response cannot be replayed. Additive: does not touch existing routes.
 */
function api_authorize(): never {
    $data        = json_input();
    $licenseKey  = strtoupper(trim((string)($data['license_key'] ?? '')));
    $serverIp    = normalize_ip((string)($data['server_ip'] ?? request_ip()));
    $fingerprint = normalize_fingerprint((string)($data['fingerprint'] ?? ''));
    $hostname    = substr(trim((string)($data['hostname'] ?? '')), 0, 255);
    $action      = normalize_action_name((string)($data['action'] ?? ''));
    $nonce       = substr(preg_replace('/[^a-fA-F0-9]/', '', (string)($data['nonce'] ?? '')), 0, 64);

    $ctx = ['server_ip' => $serverIp, 'hostname' => $hostname, 'fingerprint' => $fingerprint];

    if ($licenseKey === '' || $serverIp === '' || $fingerprint === '' || $action === '' || $nonce === '') {
        log_event($licenseKey ?: null, 'authorize:' . ($action ?: '-'), 'bad_request', 'missing required fields', $ctx);
        json_response(['ok' => false, 'status' => 'bad_request', 'message' => 'license_key, server_ip, fingerprint, action and nonce are required'], 400);
    }

    $lic = license_find($licenseKey);
    if (!$lic) {
        log_event($licenseKey, 'authorize:' . $action, 'invalid', 'Invalid license key', $ctx);
        json_response(['ok' => false, 'status' => 'invalid', 'message' => 'Invalid license key'], 404);
    }
    $id = (int)$lic['id'];

    if (!empty($lic['tamper_status']) && $lic['tamper_status'] === 'blocked') {
        log_event($licenseKey, 'authorize:' . $action, 'tampered', 'Previously blocked', $ctx);
        json_response(['ok' => false, 'status' => 'tampered', 'message' => 'Plugin integrity blocked. Contact support.'], 403);
    }
    if (license_expired($lic)) {
        db()->query("UPDATE licenses SET status='expired' WHERE id=" . $id);
        log_event($licenseKey, 'authorize:' . $action, 'expired', 'License expired', $ctx);
        json_response(['ok' => false, 'status' => 'expired', 'message' => 'License expired'], 403);
    }
    if (($lic['status'] ?? '') === 'suspended') {
        json_response(['ok' => false, 'status' => 'suspended', 'message' => 'License suspended'], 403);
    }
    if (($lic['status'] ?? '') === 'new') {
        json_response(['ok' => false, 'status' => 'not_activated', 'message' => 'License not activated'], 403);
    }
    // Fingerprint (hardware identity) is the AUTHORITATIVE binding — stable even when the
    // server sits behind Cloudflare or its origin IP changes. The IP is informational and
    // auto-rebinds when the fingerprint still matches. Only a DIFFERENT machine is rejected.
    if (!hash_equals((string)$lic['bound_fingerprint'], $fingerprint)) {
        log_event($licenseKey, 'authorize:' . $action, 'binding_mismatch', 'Fingerprint mismatch (different machine)', $ctx);
        json_response(['ok' => false, 'status' => 'binding_mismatch', 'message' => 'License is bound to a different machine. Contact support.'], 403);
    }
    if (!hash_equals((string)$lic['bound_ip'], $serverIp) || !hash_equals((string)($lic['bound_hostname'] ?? ''), $hostname)) {
        $rs = db()->prepare("UPDATE licenses SET bound_ip=?, bound_hostname=? WHERE id=?");
        $rs->bind_param('ssi', $serverIp, $hostname, $id); $rs->execute();
        log_event($licenseKey, 'authorize:' . $action, 'ip_rebind', 'Origin IP/hostname updated for same fingerprint (Cloudflare/IP change): ' . $lic['bound_ip'] . ' -> ' . $serverIp, $ctx);
        $lic['bound_ip'] = $serverIp; $lic['bound_hostname'] = $hostname;
    }

    // Signed, server-bound, nonce-bound, action-bound, short-lived authorization.
    $payload = [
        'status'         => 'active',
        'action'         => $action,
        'nonce'          => $nonce,                       // ECHO — defeats replay
        'bound_ip'       => $serverIp,
        'fingerprint'    => $fingerprint,
        'bound_hostname' => (string)($lic['bound_hostname'] ?? $hostname),
        'plan'           => (string)($lic['plan'] ?? ''),
        'product'        => function_exists('license_product_v2') ? license_product_v2($lic) : (string)($lic['product_code'] ?? ''),
        'client_name'    => (string)($lic['client_name'] ?? ''),
        'expires_at'     => (string)($lic['expires_at'] ?? ''),
        'issued_at'      => date('c'),
        'ttl'            => 120,
    ];
    $signed = sign_payload($payload);

    $stmt = db()->prepare("UPDATE licenses SET last_action_at=NOW(), last_check_at=NOW() WHERE id=?");
    $stmt->bind_param('i', $id);
    $stmt->execute();

    log_event($licenseKey, 'authorize:' . $action, 'ok', 'Action authorized', $ctx);
    json_response([
        'ok'      => true,
        'status'  => 'active',
        'license' => ['payload' => $signed['payload'], 'signature' => $signed['signature']],
    ]);
}
