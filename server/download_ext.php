<?php
/**
 * download_ext.php — /api/download : license-GATED plugin download for Safety Monitor Pro (smprov1).
 *
 * The plugin tarball is stored OUTSIDE the web root (/opt/aitech-license-server/releases/), so it can
 * never be fetched as a static URL. The ONLY way to get the bytes is to pass the same activation +
 * hardware-fingerprint binding check used by /api/check:
 *   - the license must exist, not be expired / suspended / tamper-blocked,
 *   - a fresh (unbound) valid key binds to the FIRST machine that downloads (that download IS the
 *     activation — status -> active, bound to this ip+hostname+fingerprint),
 *   - any OTHER machine (different fingerprint) is then refused (binding_mismatch),
 *   - IP / hostname auto-rebind when the same fingerprint reports a new origin (Cloudflare / IP change).
 *
 * Reuses the server's existing helpers (license_find/sign-free, log_event, json_response, db,
 * normalize_*). Additive: does not touch any existing route. Mirrors authorize_ext.php's style.
 */
function api_download(): never {
    $data        = json_input();
    $licenseKey  = strtoupper(trim((string)($data['license_key'] ?? '')));
    $serverIp    = normalize_ip((string)($data['server_ip'] ?? request_ip()));
    $hostname    = substr(trim((string)($data['hostname'] ?? '')), 0, 255);
    $fingerprint = normalize_fingerprint((string)($data['fingerprint'] ?? ''));

    $ctx = ['server_ip' => $serverIp, 'hostname' => $hostname, 'fingerprint' => $fingerprint];

    if ($licenseKey === '' || $serverIp === '' || $fingerprint === '') {
        log_event($licenseKey ?: null, 'download', 'bad_request', 'missing required fields', $ctx);
        json_response(['ok' => false, 'status' => 'bad_request', 'message' => 'license_key, server_ip and fingerprint are required'], 400);
    }

    $lic = license_find($licenseKey);
    if (!$lic) {
        log_event($licenseKey, 'download', 'invalid', 'Invalid license key', $ctx);
        json_response(['ok' => false, 'status' => 'invalid', 'message' => 'Invalid license key'], 404);
    }
    $id = (int)$lic['id'];

    if (!empty($lic['tamper_status']) && $lic['tamper_status'] === 'blocked') {
        log_event($licenseKey, 'download', 'tampered', 'Previously blocked', $ctx);
        json_response(['ok' => false, 'status' => 'tampered', 'message' => 'Plugin integrity blocked. Contact support.'], 403);
    }
    if (license_expired($lic)) {
        db()->query("UPDATE licenses SET status='expired' WHERE id=" . $id);
        log_event($licenseKey, 'download', 'expired', 'License expired', $ctx);
        json_response(['ok' => false, 'status' => 'expired', 'message' => 'License expired'], 403);
    }
    if (($lic['status'] ?? '') === 'suspended') {
        log_event($licenseKey, 'download', 'suspended', 'License suspended', $ctx);
        json_response(['ok' => false, 'status' => 'suspended', 'message' => 'License suspended'], 403);
    }

    // Bind on first download (this is the activation), else verify the existing binding.
    $notBound = empty($lic['bound_ip']) && empty($lic['bound_fingerprint']);
    if ($notBound) {
        $st = db()->prepare("UPDATE licenses SET status='active', bound_ip=?, bound_hostname=?, bound_fingerprint=?, activated_at=COALESCE(activated_at, NOW()), last_check_at=NOW() WHERE id=?");
        $st->bind_param('sssi', $serverIp, $hostname, $fingerprint, $id);
        $st->execute();
        $lic = license_find($licenseKey);
        log_event($licenseKey, 'download', 'activated', 'License activated and bound on first download', $ctx);
    }
    if (($lic['status'] ?? '') === 'new') {
        log_event($licenseKey, 'download', 'not_activated', 'License is not activated yet', $ctx);
        json_response(['ok' => false, 'status' => 'not_activated', 'message' => 'License not activated'], 403);
    }
    // Fingerprint (hardware identity) is the AUTHORITATIVE binding — only a DIFFERENT machine is refused.
    if (!hash_equals((string)$lic['bound_fingerprint'], $fingerprint)) {
        log_event($licenseKey, 'download', 'binding_mismatch', 'Fingerprint mismatch (different machine)', $ctx);
        json_response(['ok' => false, 'status' => 'binding_mismatch', 'message' => 'License is bound to a different machine. Contact support.'], 403);   // do NOT echo bound_ip (another tenant's IP)
    }
    if (!hash_equals((string)$lic['bound_ip'], $serverIp) || !hash_equals((string)($lic['bound_hostname'] ?? ''), $hostname)) {
        $rs = db()->prepare("UPDATE licenses SET bound_ip=?, bound_hostname=? WHERE id=?");
        $rs->bind_param('ssi', $serverIp, $hostname, $id);
        $rs->execute();
        log_event($licenseKey, 'download', 'ip_rebind', 'Origin IP/hostname updated for same fingerprint: ' . $lic['bound_ip'] . ' -> ' . $serverIp, $ctx);
    }

    // ---- single-download limit: each license may be downloaded ONCE only ----
    // The count is the number of prior SUCCESSFUL ('ok') download events already recorded in
    // license_logs for this key. No schema change needed; logs ARE the per-license counter.
    // (Reset = delete this key's ok-download rows from license_logs.)
    $downloadCount = 0;
    if ($q = db()->prepare("SELECT COUNT(*) FROM license_logs WHERE license_key=? AND action='download' AND result='ok'")) {
        $q->bind_param('s', $licenseKey);
        $q->execute();
        $q->bind_result($downloadCount);
        $q->fetch();
        $q->close();
        $downloadCount = (int)$downloadCount;
    }
    if ($downloadCount >= 1) {
        log_event($licenseKey, 'download', 'limit_reached', 'Single-download limit already used (' . $downloadCount . ')', $ctx);
        json_response([
            'ok'       => false,
            'status'   => 'download_limit',
            'message'  => 'This license has already been downloaded once. For a re-download (e.g. server rebuild), contact support.',
            'downloads' => $downloadCount,
        ], 403);
    }
    // ATOMIC single-use reserve — closes the TOCTOU where N concurrent first-downloads all read count=0 and all
    // get the tarball. Whoever flips download_used 0→1 wins; the losers are refused. (One-time column add.)
    @db()->query("ALTER TABLE licenses ADD COLUMN download_used TINYINT NOT NULL DEFAULT 0");   // idempotent (dup-column error ignored)
    $reserved = false;
    if ($rsv = db()->prepare("UPDATE licenses SET download_used=1 WHERE id=? AND download_used=0")) {
        $rsv->bind_param('i', $id); $rsv->execute(); $reserved = (db()->affected_rows === 1); $rsv->close();
    }
    if (!$reserved) {
        log_event($licenseKey, 'download', 'limit_reached', 'Concurrent/duplicate download reserve refused', $ctx);
        json_response(['ok' => false, 'status' => 'download_limit', 'message' => 'This license has already been downloaded. For a re-download, contact support.'], 403);
    }

    // Passed the gate — stream the protected release.
    $relDir = '/opt/aitech-license-server/releases';
    $file   = $relDir . '/smpro-latest.tar.gz';
    if (!is_readable($file)) {
        log_event($licenseKey, 'download', 'error', 'release file missing: ' . $file, $ctx);
        json_response(['ok' => false, 'status' => 'unavailable', 'message' => 'Release temporarily unavailable. Contact support.'], 503);
    }

    db()->query("UPDATE licenses SET last_check_at=NOW() WHERE id=" . $id);

    $ver  = is_readable($relDir . '/VERSION') ? trim((string)file_get_contents($relDir . '/VERSION')) : '';
    $size = (int)filesize($file);
    $sha  = @hash_file('sha256', $file);
    $sig  = is_readable($file . '.sig') ? trim((string)file_get_contents($file . '.sig')) : '';  // offline RSA sig (base64)
    while (ob_get_level() > 0) { ob_end_clean(); }
    ignore_user_abort(true);                         // keep running after the stream so we can log the outcome
    header('Content-Type: application/gzip');
    header('Content-Disposition: attachment; filename="smprov1.tar.gz"');
    header('Content-Length: ' . $size);
    if ($ver !== '') header('X-Smpro-Version: ' . $ver);
    if ($sha)        header('X-Smpro-SHA256: ' . $sha);
    if ($sig !== '') header('X-Smpro-Sig: ' . $sig);
    header('Cache-Control: no-store');

    $sent = @readfile($file);
    // Consume the single-download allowance ONLY when the whole file was emitted AND the client did not
    // abort — so a failed / interrupted first download does NOT lock the customer out of their one download.
    if ($sent !== false && (int)$sent === $size && !connection_aborted()) {
        log_event($licenseKey, 'download', 'ok', 'Served ' . basename($file) . ' (' . $size . ' bytes)', $ctx);
    } else {
        // stream failed/aborted → release the reservation so the customer isn't locked out of their one download
        @db()->query("UPDATE licenses SET download_used=0 WHERE id=" . $id);
        log_event($licenseKey, 'download', 'incomplete', 'Stream not completed (sent=' . var_export($sent, true) . ', aborted=' . (int)connection_aborted() . ') — reservation released', $ctx);
    }
    exit;
}
