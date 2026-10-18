<?php
/**
 * provision_ext.php — payment-driven license provisioning API for the sales website.
 * Server-to-server, authenticated with a shared secret (storage/provision.key, outside webroot).
 * Endpoints (POST JSON, base https://dl.iptvpro.org):
 *   /api/provision       {product, plan, client_name, client_email, order_id} -> issues a license (idempotent on order_id)
 *   /api/renew           {order_id|license_key, extend_days|expires_at}        -> extends expiry (reactivates if suspended)
 *   /api/revoke          {order_id|license_key}                                -> suspends the license (locks on next check-in)
 *   /api/license-status  {order_id|license_key}                                -> returns current license state
 * Reuses: db(), json_response(), splan_all()/splan_keygen() (plans_ext, required just before), log_event().
 */
if (!function_exists('db')) return;

function prov_key(): string {
    $f = __DIR__ . '/../storage/provision.key';
    return is_file($f) ? trim((string)@file_get_contents($f)) : '';
}

function prov_auth(): bool {
    $k = prov_key();
    if ($k === '') return false;
    $h = (string)($_SERVER['HTTP_X_PROVISION_KEY'] ?? '');
    if ($h === '' && !empty($_SERVER['HTTP_AUTHORIZATION']) && preg_match('/Bearer\s+(.+)/i', $_SERVER['HTTP_AUTHORIZATION'], $m)) $h = trim($m[1]);
    return $h !== '' && hash_equals($k, $h);
}

function prov_body(): array {
    $j = json_decode((string)@file_get_contents('php://input'), true);
    return is_array($j) ? $j : (is_array($_POST) ? $_POST : []);
}

function prov_migrate(): void {
    $flag = __DIR__ . '/../storage/.prov_migrated';
    if (is_file($flag)) return;
    try {
        @db()->query("ALTER TABLE licenses ADD COLUMN order_ref VARCHAR(120) NULL");
        @db()->query("ALTER TABLE licenses ADD INDEX idx_order_ref (order_ref)");
        @file_put_contents($flag, date('c'));
    } catch (\Throwable $e) {}
}

function prov_find_by_order(string $ref) {
    if ($ref === '') return null;
    $st = db()->prepare("SELECT * FROM licenses WHERE order_ref=? LIMIT 1");
    if (!$st) return null;
    $st->bind_param('s', $ref); $st->execute();
    return $st->get_result()->fetch_assoc() ?: null;
}

/** Resolve the target license from order_id (preferred) or license_key. */
function prov_target(array $b) {
    $order = trim((string)($b['order_id'] ?? $b['order_ref'] ?? ''));
    if ($order !== '' && ($l = prov_find_by_order($order))) return $l;
    $key = trim((string)($b['license_key'] ?? ''));
    if ($key !== '') {
        $st = db()->prepare("SELECT * FROM licenses WHERE license_key=? LIMIT 1");
        if ($st) { $st->bind_param('s', $key); $st->execute(); return $st->get_result()->fetch_assoc() ?: null; }
    }
    return null;
}

function prov_public(array $lic): array {
    return [
        'license_key'  => $lic['license_key'],
        'product'      => $lic['product_code'] ?? '',
        'plan'         => $lic['plan'],
        'status'       => $lic['status'],
        'client_name'  => $lic['client_name'],
        'client_email' => $lic['client_email'],
        'expires_at'   => $lic['expires_at'],
        'order_ref'    => $lic['order_ref'] ?? '',
        'bound_ip'     => $lic['bound_ip'] ?? null,
    ];
}

/* ---- per-IP brute-force guard on the shared secret (the API is grey-cloud / CF-bypassable) ---- */
/** Trust CF-Connecting-IP ONLY when REMOTE_ADDR is a Cloudflare edge; on the direct origin these headers are
 *  attacker-supplied. (Reuses authotp_ip_is_cf when loaded; else fails closed to REMOTE_ADDR.) */
function prov_client_ip(): string {
    $remote = trim((string)($_SERVER['REMOTE_ADDR'] ?? ''));
    if ($remote !== '' && function_exists('authotp_ip_is_cf') && authotp_ip_is_cf($remote)) {
        $cf = trim((string)($_SERVER['HTTP_CF_CONNECTING_IP'] ?? ''));
        if ($cf !== '' && filter_var($cf, FILTER_VALIDATE_IP)) return $cf;
    }
    return ($remote !== '' && filter_var($remote, FILTER_VALIDATE_IP)) ? $remote : '';
}
function prov_guard_migrate(): void {
    static $d = false; if ($d) return; $d = true;
    db()->query("CREATE TABLE IF NOT EXISTS prov_guard (ip VARCHAR(45) NOT NULL PRIMARY KEY, fails INT NOT NULL DEFAULT 0,
        blocked_until DATETIME NULL, updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
}
function prov_blocked(string $ip): bool {
    if ($ip === '') return false;
    $st = db()->prepare("SELECT blocked_until FROM prov_guard WHERE ip=? LIMIT 1"); $st->bind_param('s', $ip); $st->execute();
    $r = $st->get_result()->fetch_assoc();
    return $r && !empty($r['blocked_until']) && strtotime((string)$r['blocked_until']) > time();
}
function prov_fail(string $ip): void {
    if ($ip === '') return;
    $st = db()->prepare("SELECT fails, updated_at FROM prov_guard WHERE ip=? LIMIT 1"); $st->bind_param('s', $ip); $st->execute();
    $r = $st->get_result()->fetch_assoc();
    $f = ($r && (time() - strtotime((string)$r['updated_at']) < 1800)) ? (int)$r['fails'] : 0;   // 30-min window
    $f++; $until = $f >= 8 ? date('Y-m-d H:i:s', time() + 3600) : null;                            // 8 fails → block 1h
    $st = db()->prepare("INSERT INTO prov_guard (ip,fails,blocked_until) VALUES (?,?,?) ON DUPLICATE KEY UPDATE fails=VALUES(fails), blocked_until=VALUES(blocked_until), updated_at=NOW()");
    $st->bind_param('sis', $ip, $f, $until); $st->execute();
    if (function_exists('log_event')) { try { log_event('provision_guard', 'auth_fail', $until ? 'blocked' : 'fail', $ip . ' (' . $f . '/8)', []); } catch (\Throwable $e) {} }
}
function prov_clear(string $ip): void { if ($ip === '') return; $st = db()->prepare("DELETE FROM prov_guard WHERE ip=?"); $st->bind_param('s', $ip); $st->execute(); }

function prov_route(string $path): bool {
    if (!in_array($path, ['/api/provision', '/api/revoke', '/api/renew', '/api/license-status', '/api/ping'], true)) return false;
    // /api/ping is a connectivity + auth test (GET or POST); the rest require POST.
    if ($path !== '/api/ping' && ($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST')
        json_response(['ok' => false, 'status' => 'method_not_allowed', 'message' => 'POST required'], 405);
    prov_guard_migrate();
    $ip = prov_client_ip();
    if (prov_blocked($ip)) json_response(['ok' => false, 'status' => 'rate_limited', 'message' => 'Too many failed attempts — try again later.'], 429);
    if (!prov_auth()) { prov_fail($ip); json_response(['ok' => false, 'status' => 'unauthorized', 'message' => 'Invalid or missing API key'], 401); }
    prov_clear($ip);   // authenticated → reset this IP's strike counter
    if ($path === '/api/ping')
        json_response(['ok' => true, 'status' => 'pong', 'message' => 'Provisioning API reachable and authenticated',
                       'products' => array_keys(splan_products())]);
    prov_migrate();
    $b = prov_body();
    if ($path === '/api/provision')      prov_do_provision($b);
    if ($path === '/api/revoke')         prov_do_revoke($b);
    if ($path === '/api/renew')          prov_do_renew($b);
    if ($path === '/api/license-status') prov_do_status($b);
    return true;
}

function prov_do_provision(array $b): void {
    $product  = preg_replace('/[^a-z0-9_]/', '', strtolower((string)($b['product'] ?? 'safety_monitor')));
    $planCode = preg_replace('/[^a-z0-9_]/', '', strtolower((string)($b['plan'] ?? '')));
    $name     = trim((string)($b['client_name'] ?? ''));
    $email    = trim(str_replace(["\r", "\n", "\0"], '', (string)($b['client_email'] ?? '')));  // strip CR/LF at ingest — no injecting recipient stored (delivery also FILTER_VALIDATE_EMAILs it)
    $order    = trim((string)($b['order_id'] ?? $b['order_ref'] ?? ''));
    if ($planCode === '' || $email === '') json_response(['ok' => false, 'status' => 'bad_request', 'message' => 'plan and client_email are required'], 400);

    if ($order !== '' && ($ex = prov_find_by_order($order)))
        json_response(['ok' => true, 'status' => 'exists', 'message' => 'Order already provisioned', 'license' => prov_public($ex)]);

    $plan = null;
    foreach (splan_all($product) as $p) if ($p['code'] === $planCode) { $plan = $p; break; }
    if (!$plan) json_response(['ok' => false, 'status' => 'invalid_plan', 'message' => 'Unknown product/plan'], 404);

    $key = function_exists('splan_keygen') ? splan_keygen($product, $planCode) : ('LIC-' . date('Y') . '-' . strtoupper(bin2hex(random_bytes(4))));
    $exp = trim((string)($b['expires_at'] ?? ''));
    if ($exp === '') {
        if ((int)$plan['trial_days'] > 0) $exp = date('Y-m-d H:i:s', time() + (int)$plan['trial_days'] * 86400);
        elseif ($plan['cycle'] === 'yearly') $exp = date('Y-m-d H:i:s', time() + 365 * 86400);
        elseif ($plan['cycle'] === 'monthly') $exp = date('Y-m-d H:i:s', time() + 31 * 86400);
        else $exp = null;
    } else $exp = date('Y-m-d H:i:s', strtotime($exp) ?: time());

    $fj = json_encode(array_values((array)$plan['features']));
    $maxs = (int)$plan['max_servers'];
    $orderv = $order !== '' ? $order : null;
    $st = db()->prepare("INSERT INTO licenses (license_key,client_name,client_email,status,plan,product_code,features,max_servers,expires_at,order_ref)
        VALUES (?,?,?, 'active', ?,?,?,?,?,?)");
    if (!$st) json_response(['ok' => false, 'status' => 'error', 'message' => 'DB prepare failed'], 500);
    $st->bind_param('ssssssiss', $key, $name, $email, $planCode, $product, $fj, $maxs, $exp, $orderv);
    if (!$st->execute()) {
        if (function_exists('log_event')) log_event($key, 'provision', 'fail', db()->error, []);
        json_response(['ok' => false, 'status' => 'error', 'message' => 'Could not create license'], 500);
    }
    if (function_exists('log_event')) log_event($key, 'provision', 'ok', $product . '/' . $planCode . ' order=' . $order, []);
    // Build the response from local values (do NOT re-query via insert_id — log_event
    // above changes mysqli->insert_id to the log row's id).
    $lic = ['license_key' => $key, 'product_code' => $product, 'plan' => $planCode, 'status' => 'active',
            'client_name' => $name, 'client_email' => $email, 'expires_at' => $exp, 'order_ref' => $orderv, 'bound_ip' => null];
    json_response(['ok' => true, 'status' => 'provisioned', 'license' => prov_public($lic)]);
}

function prov_do_revoke(array $b): void {
    $lic = prov_target($b);
    if (!$lic) json_response(['ok' => false, 'status' => 'not_found', 'message' => 'License not found'], 404);
    db()->query("UPDATE licenses SET status='suspended' WHERE id=" . (int)$lic['id']);
    if (function_exists('log_event')) log_event($lic['license_key'], 'revoke', 'ok', 'via provisioning API', []);
    json_response(['ok' => true, 'status' => 'suspended', 'license_key' => $lic['license_key']]);
}

function prov_do_renew(array $b): void {
    $lic = prov_target($b);
    if (!$lic) json_response(['ok' => false, 'status' => 'not_found', 'message' => 'License not found'], 404);
    $exp = trim((string)($b['expires_at'] ?? ''));
    if ($exp !== '') {
        $new = date('Y-m-d H:i:s', strtotime($exp) ?: time());
    } else {
        $days = (int)($b['extend_days'] ?? 0);
        if ($days <= 0) $days = 31;
        $base = (!empty($lic['expires_at']) && strtotime($lic['expires_at']) > time()) ? strtotime($lic['expires_at']) : time();
        $new = date('Y-m-d H:i:s', $base + $days * 86400);
    }
    $st = db()->prepare("UPDATE licenses SET expires_at=?, status=IF(status IN ('suspended','expired'),'active',status) WHERE id=?");
    $id = (int)$lic['id']; $st->bind_param('si', $new, $id); $st->execute();
    if (function_exists('log_event')) log_event($lic['license_key'], 'renew', 'ok', 'new expiry ' . $new, []);
    $fresh = db()->query("SELECT * FROM licenses WHERE id=" . $id)->fetch_assoc();
    json_response(['ok' => true, 'status' => 'renewed', 'license' => prov_public($fresh)]);
}

function prov_do_status(array $b): void {
    $lic = prov_target($b);
    if (!$lic) json_response(['ok' => false, 'status' => 'not_found', 'message' => 'License not found'], 404);
    json_response(['ok' => true, 'status' => 'ok', 'license' => prov_public($lic)]);
}
