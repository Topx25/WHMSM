<?php
declare(strict_types=1);

ini_set('display_errors', '0');
ini_set('log_errors', '1');
ini_set('error_log', '/var/log/aitech-license-server-php.log');
error_reporting(E_ALL);

const CONFIG_FILE = '/etc/aitech-license-server.env';

function envv(string $key, string $default = ''): string {
    static $env = null;
    if ($env === null) {
        $env = is_file(CONFIG_FILE) ? parse_ini_file(CONFIG_FILE, false, INI_SCANNER_RAW) : [];
        if (!is_array($env)) $env = [];
    }
    return (string)($env[$key] ?? $default);
}

function db(): mysqli {
    static $db = null;
    if ($db instanceof mysqli) return $db;

    mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
    $db = new mysqli(
        envv('DB_HOST', 'localhost'),
        envv('DB_USER'),
        envv('DB_PASS'),
        envv('DB_NAME')
    );
    $db->set_charset('utf8mb4');
    return $db;
}

function h($v): string {
    return htmlspecialchars((string)$v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function now(): string {
    return date('Y-m-d H:i:s');
}

function path_only(): string {
    return parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
}

function request_ip(): string {
    return $_SERVER['REMOTE_ADDR'] ?? '';
}

function json_input(): array {
    $raw = file_get_contents('php://input') ?: '';
    $data = json_decode($raw, true);
    return is_array($data) ? $data : [];
}

function json_response(array $data, int $code = 200): never {
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    header('X-Content-Type-Options: nosniff');
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
    exit;
}

function redirect(string $to): never {
    header('Location: ' . $to);
    exit;
}

function csrf_token(): string {
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf'];
}

function require_csrf(): void {
    $token = $_POST['csrf'] ?? '';
    if (!hash_equals($_SESSION['csrf'] ?? '', (string)$token)) {
        http_response_code(403);
        exit('CSRF validation failed');
    }
}

function is_admin(): bool {
    return !empty($_SESSION['admin_id']);
}

function require_admin(): void {
    if (!is_admin()) {
        redirect('/login');
    }
}

function log_event(?string $licenseKey, string $action, string $result, string $message = '', array $ctx = []): void {
    $stmt = db()->prepare("
        INSERT INTO license_logs
        (license_key, action, request_ip, server_ip, hostname, fingerprint, result, message)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ");

    $requestIp = request_ip();
    $serverIp = (string)($ctx['server_ip'] ?? '');
    $hostname = (string)($ctx['hostname'] ?? '');
    $fingerprint = (string)($ctx['fingerprint'] ?? '');

    $stmt->bind_param(
        'ssssssss',
        $licenseKey,
        $action,
        $requestIp,
        $serverIp,
        $hostname,
        $fingerprint,
        $result,
        $message
    );
    $stmt->execute();
}

/**
 * Clone / license-sharing detection. The plugin auto-rebinds bound_ip when the SAME fingerprint reports a new
 * origin IP (legit for Cloudflare / dynamic IPs). But a customer running ONE key on N servers — with a forged,
 * identical machine-id+hostname fingerprint (which is fully root-forgeable, per the audit) — makes bound_ip
 * THRASH between those servers. We flag a license whose bound IP has bounced across >=3 distinct origin IPs in
 * 24h. FLAG-ONLY (log + dated note in the panel) — never auto-suspend, so legit IP changes / failover are not
 * punished; the operator reviews flagged licenses. This check lives on the license server (operator-controlled),
 * so a customer with root on their own box cannot patch it out — unlike any client-side enforcement.
 */
function flag_clone_if_thrashing(string $licenseKey, int $licId, array $ctx = []): void {
    $n = 0;
    if ($q = db()->prepare("SELECT COUNT(DISTINCT server_ip) FROM license_logs WHERE license_key=? AND result='ip_rebind' AND server_ip<>'' AND created_at >= (NOW() - INTERVAL 24 HOUR)")) {
        $q->bind_param('s', $licenseKey); $q->execute(); $q->bind_result($n); $q->fetch(); $q->close();
    }
    if ((int)$n < 3) return;                                 // threshold: >=3 distinct origin IPs in 24h = sharing signal
    log_event($licenseKey, 'check', 'clone_suspected', 'License IP thrashing across ' . (int)$n . ' distinct origin IPs in 24h — possible license sharing / clones (same fingerprint on multiple servers).', $ctx);
    $mark = '[clone? ' . date('Y-m-d') . ' ' . (int)$n . ' IPs/24h]';   // idempotent per day
    if ($u = db()->prepare("UPDATE licenses SET notes = TRIM(CONCAT_WS(' ', COALESCE(NULLIF(notes,''),''), ?)) WHERE id=? AND (notes IS NULL OR notes NOT LIKE ?)")) {
        $like = '%' . $mark . '%';
        $u->bind_param('sis', $mark, $licId, $like); $u->execute(); $u->close();
    }
}

/**
 * Plugin-reported deliberate endpoint redirect (license host pinned in /etc/hosts to a non-license IP, confirmed
 * by a check that returned no valid RSA signature). The plugin has already stopped itself locally and started its
 * 24h→uninstall countdown; here we (1) flag the license, (2) alert the admin via WhatsApp + email so they can
 * investigate and either send a Reset or let it lapse. Best-effort: a fully blackholed host can't reach us — the
 * dead-man sweep (stale check-in) is the backstop alert for that case.
 */
function api_report_tamper(): never {
    $d   = json_input();
    $key = strtoupper(trim((string)($d['license_key'] ?? '')));
    $fp  = (string)($d['fingerprint'] ?? '');
    $ev  = substr(strip_tags((string)($d['meta'] ?? $d['evidence'] ?? '')), 0, 300);
    $ctx = ['server_ip' => (string)($d['server_ip'] ?? ''), 'hostname' => (string)($d['hostname'] ?? ''), 'fingerprint' => $fp];
    if ($key === '') json_response(['ok' => false, 'status' => 'bad_request', 'message' => 'license_key required'], 400);
    $lic = license_find($key);
    if (!$lic) json_response(['ok' => false, 'status' => 'invalid', 'message' => 'Invalid license key'], 404);

    log_event($key, 'check', 'env_tamper', 'Plugin reported a deliberate license-endpoint redirect: ' . $ev, $ctx);
    // flag the license (idempotent dated note) so it stands out in the panel for investigation
    $mark = '[TAMPER ' . date('Y-m-d H:i') . ' ' . substr($ev, 0, 80) . ']';
    if ($u = db()->prepare("UPDATE licenses SET notes = TRIM(CONCAT_WS(' ', COALESCE(NULLIF(notes,''),''), ?)), updated_at=NOW() WHERE id=? AND (notes IS NULL OR notes NOT LIKE '%[TAMPER %')")) {
        $like = $mark; $id = (int)$lic['id']; $u->bind_param('si', $like, $id); $u->execute();
    }
    // alert the admin — WhatsApp (global recipient) + email (every admin)
    $who  = (string)($lic['client_name'] ?? '') . ' / ' . (string)($lic['client_email'] ?? '');
    $host = (string)($d['hostname'] ?? '') ?: (string)($d['server_ip'] ?? '');
    $msg  = "⚠️ Safety Monitor Pro — license tamper detected\nLicense: $key\nClient: $who\nServer: $host\nEvidence: $ev\nThe plugin stopped itself and will self-remove in 24h unless you send a Reset from the panel after investigation.";
    if (function_exists('wa_send'))     { $e = ''; @wa_send($msg, $e); }
    if (function_exists('mailer_send')) {
        if ($rs = @db()->query("SELECT email FROM admins WHERE email IS NOT NULL AND email<>''")) {
            while ($a = $rs->fetch_assoc()) { $e = ''; @mailer_send((string)$a['email'], 'Safety Monitor Pro — license tamper detected', nl2br(h($msg)), $e); }
        }
    }
    json_response(['ok' => true, 'status' => 'recorded']);
}

/**
 * Dead-man sweep (CLI cron). Finds licenses that were active and checking in but have gone SILENT past the
 * threshold — the reliable signal for a hosts/DNS blackhole of the license endpoint, where the plugin's own
 * /api/report-tamper can't reach us. Alerts the admin (WhatsApp + email) ONCE per silence episode: a 'silent'
 * row is written to license_logs, and the NOT EXISTS guard suppresses re-alerts until the plugin resumes
 * (last_check_at advances past that log), which self-resets the episode. No schema changes, no notes pollution.
 */
function deadman_sweep(): void {
    $hours = 6;                                          // brief outages are fine; >6h silent = genuinely gone
    $rows = [];
    $sql = "SELECT id, license_key, client_name, client_email, bound_hostname, bound_ip, last_check_at
            FROM licenses
            WHERE status='active' AND last_check_at IS NOT NULL
              AND last_check_at < (NOW() - INTERVAL ? HOUR)
              AND NOT EXISTS (SELECT 1 FROM license_logs l
                              WHERE l.license_key = licenses.license_key AND l.result='silent'
                                AND l.created_at > licenses.last_check_at)";
    if ($q = db()->prepare($sql)) { $q->bind_param('i', $hours); $q->execute(); $r = $q->get_result(); while ($row = $r->fetch_assoc()) $rows[] = $row; }
    foreach ($rows as $row) {
        $key  = (string)$row['license_key'];
        log_event($key, 'deadman', 'silent', 'No check-in for >' . $hours . 'h (last ' . (string)$row['last_check_at'] . ') — possible license-endpoint blackhole/tamper.', []);
        $who  = (string)$row['client_name'] . ' / ' . (string)$row['client_email'];
        $host = (string)($row['bound_hostname'] ?: $row['bound_ip']);
        $msg  = "🔇 Safety Monitor Pro — a licensed server went SILENT\nLicense: $key\nClient: $who\nServer: $host\nLast check-in: " . (string)$row['last_check_at'] . "\nThe plugin stopped reporting (possible license-endpoint blackhole / tamper). Investigate — a confirmed tamper self-removes the plugin 24h after detection.";
        if (function_exists('wa_send'))     { $e = ''; @wa_send($msg, $e); }
        if (function_exists('mailer_send')) {
            if ($rs = @db()->query("SELECT email FROM admins WHERE email IS NOT NULL AND email<>''")) {
                while ($a = $rs->fetch_assoc()) { $e = ''; @mailer_send((string)$a['email'], 'Safety Monitor Pro — a licensed server went silent', nl2br(h($msg)), $e); }
            }
        }
    }
    if (PHP_SAPI === 'cli') fwrite(STDOUT, 'deadman: ' . count($rows) . " alert(s)\n");
}

function feature_list(string $plan, ?string $featuresJson): array {
    if ($featuresJson) {
        $decoded = json_decode($featuresJson, true);
        if (is_array($decoded)) return array_values(array_unique(array_map('strval', $decoded)));
    }

    return match ($plan) {
        'basic' => ['scan', 'reports'],
        'enterprise' => ['scan', 'reports', 'telegram', 'cleanup', 'smart_engine', 'multi_server'],
        default => ['scan', 'reports', 'telegram', 'cleanup', 'smart_engine'],
    };
}

function resolve_features(array $lic): array {
    $product = (string)($lic['product_code'] ?? 'safety_monitor'); if ($product === '') $product = 'safety_monitor';
    $plan = (string)($lic['plan'] ?? '');
    if ($plan !== '' && function_exists('splan_all')) {
        foreach (splan_all($product) as $p) if (($p['code'] ?? '') === $plan) return array_values(array_map('strval', (array)($p['features'] ?? [])));
    }
    return feature_list($plan, $lic['features'] ?? null);   // legacy fallback when the plan row is gone
}

function license_key_generate(): string {
    $parts = [];
    for ($i = 0; $i < 4; $i++) {
        $parts[] = strtoupper(bin2hex(random_bytes(2)));
    }
    return 'SM-' . date('Y') . '-' . implode('-', $parts);
}

function normalize_ip(string $ip): string {
    $ip = trim($ip);
    return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '';
}

function normalize_fingerprint(string $fp): string {
    $fp = strtolower(trim($fp));
    return preg_match('/^[a-f0-9]{64}$/', $fp) ? $fp : '';
}

function license_find(string $key): ?array {
    $stmt = db()->prepare("SELECT * FROM licenses WHERE license_key = ? LIMIT 1");
    $stmt->bind_param('s', $key);
    $stmt->execute();
    $res = $stmt->get_result();
    $row = $res->fetch_assoc();
    return $row ?: null;
}

function license_expired(array $lic): bool {
    if (empty($lic['expires_at'])) return false;
    return strtotime((string)$lic['expires_at']) < time();
}

/** Per-license feature key — HMAC of (license_key|fingerprint) under a secret derived from the OFFLINE private key
 *  (server-only). Stable per license+box, unguessable without the private key. Emitted only inside a signed verdict. */
function smlic_feat_key(string $key, string $fp): string {
    static $secret = null;
    if ($secret === null) {
        $pk = @file_get_contents((string)envv('PRIVATE_KEY'));
        $secret = $pk ? hash('sha256', $pk) : ((string)envv('FEAT_SECRET') ?: 'smpro-feat-fallback');
    }
    return hash_hmac('sha256', strtoupper(trim($key)) . '|' . strtolower(trim($fp)), $secret);
}
/* PAIR (Stage 0) — per-license base secret S (server-only master) + derived pairing key K.
 * S is 32 random bytes (hex), generated lazily once per license and stored server-side; it is the "master key
 * generated with the license". K = HMAC(sha256(private_key), "smp|"+KEY+"|"+S) is the value DELIVERED to the plugin
 * (inside the RSA-signed verdict, like feat_key) — raw S never travels on the wire. The plugin will later compute a
 * rolling code keyed by K; verifying it proves possession of K (=> a genuine, server-issued, not-cross-copied license).
 * Stage 0 is INERT: K/pair_id ride in the verdict but nothing enforces yet (older plugins ignore unknown fields). */
function smlic_pair_secret(array $lic): string {
    $s = trim((string)($lic['pair_secret'] ?? ''));
    if ($s !== '') return $s;
    $id = (int)($lic['id'] ?? 0);
    if ($id <= 0) return '';
    try {
        $s = bin2hex(random_bytes(32));
        if ($q = db()->prepare("UPDATE licenses SET pair_secret=? WHERE id=? AND (pair_secret IS NULL OR pair_secret='')")) { $q->bind_param('si', $s, $id); $q->execute(); }
    } catch (\Throwable $e) { return ''; }
    return $s;
}
function smlic_pair_key(string $key, string $s): string {
    $s = trim($s); if ($s === '') return '';
    static $secret = null;
    if ($secret === null) { $pk = @file_get_contents((string)envv('PRIVATE_KEY')); $secret = $pk ? hash('sha256', $pk) : ((string)envv('FEAT_SECRET') ?: 'smpro-feat-fallback'); }
    return hash_hmac('sha256', 'smp|' . strtoupper(trim($key)) . '|' . $s, $secret);
}
/** Public, non-secret short label for a license's pairing identity (safe to show anywhere; reveals nothing about S). */
function smlic_pair_id(string $s): string { $s = trim($s); return $s === '' ? '' : substr(hash('sha256', 'pid|' . $s), 0, 10); }
/* PAIR (Stage 2, REPORT-ONLY) — recompute the rolling beacon over the CLIENT-REPORTED identity (echo-back: never
 * compares against stored MAC/IP/Host, so a benign change can't false-fail) for T,T±1 and classify the result.
 * NOTHING is stopped here — it only logs an audit row (action='pair') the admin can see in /logs + the server card.
 * States: ok | miss (wrong/absent key, or identity/clock) | bootstrap (no S yet) | nobeacon (older plugin). The
 * reversible stop + push-alert come in Stage 3; Stage 2 just surfaces the signal. */
function smlic_pair_verify(array $lic, array $data, string $serverIp = '', string $hostname = '', string $fingerprint = ''): array {
    $key = (string)($lic['license_key'] ?? '');
    if ($key === '') return ['state' => 'skip', 'reason' => 'no key'];
    $S   = trim((string)($lic['pair_secret'] ?? ''));
    $tel = (is_array($data['telemetry'] ?? null)) ? $data['telemetry'] : $data;
    $msig = strtolower(trim((string)($tel['m_sig'] ?? '')));
    $mac  = (string)($tel['mac'] ?? '');
    $host = $hostname !== '' ? $hostname : (string)($data['hostname'] ?? '');
    if ($S === '')        { $state = 'bootstrap'; $reason = 'no base secret yet (grace)'; }
    elseif ($msig === '') { $state = 'nobeacon';  $reason = 'no beacon (older plugin or not sending yet)'; }
    else {
        $K = smlic_pair_key($key, $S);
        $ctx = hash('sha256', strtolower(trim($mac)) . '|' . strtolower(trim($host)));
        $t0 = (int)floor(time() / 3600); $ok = false;
        for ($t = $t0 - 2; $t <= $t0 + 2; $t++) { if (hash_equals(substr(hash_hmac('sha256', 'beat|' . $t . '|' . $ctx, $K), 0, 20), $msig)) { $ok = true; break; } }   // ±2h: absorbs NTP slop + the plugin's monotonic-clock lead (review minor)
        $state  = $ok ? 'ok' : 'miss';
        $reason = $ok ? 'beacon valid' : 'beacon mismatch — wrong/absent pairing key, identity change, or clock skew';
    }
    // Stage 3 — ENFORCEMENT, OPT-IN (pair_enforce=1), default OFF → fully report-only otherwise. The stop is REVERSIBLE
    // (a signed pair_stop the plugin honours as a soft stop — License/Plugin-Control reachable, NEVER destructive) and
    // self-heals: a single valid beacon clears the flag. A real pirate (no valid K) never sends 'ok' → stays stopped.
    if ((int)($lic['pair_enforce'] ?? 0) === 1) {
        $id = (int)($lic['id'] ?? 0);
        if ($state === 'ok' && (int)($lic['pair_flagged'] ?? 0) === 1 && $id > 0) {
            try { db()->query("UPDATE licenses SET pair_flagged=0 WHERE id=" . $id); } catch (\Throwable $e) {}   // self-heal on a valid beacon
        } elseif ($state === 'miss' && $id > 0 && (int)($lic['pair_flagged'] ?? 0) !== 1) {
            $streak = 1;   // consecutive prior 'miss' since the last NON-miss marker (current miss not logged yet). MAJOR
            // review fix: any non-miss row (ok / bootstrap / nobeacon / pair_resume / rotated / enforce_on|off / flagged)
            // ENDS the run — so an operator Rotate/enforce-toggle truly resets the episode (no looking through it to old misses).
            try { if ($q = db()->prepare("SELECT result FROM license_logs WHERE license_key=? AND action='pair' ORDER BY id DESC LIMIT 12")) { $q->bind_param('s', $key); $q->execute(); $r = $q->get_result(); while ($x = $r->fetch_assoc()) { if ((string)$x['result'] !== 'miss') break; $streak++; } } } catch (\Throwable $e) {}
            if ($streak >= 3) {
                try { db()->query("UPDATE licenses SET pair_flagged=1 WHERE id=" . $id); } catch (\Throwable $e) {}
                $alert = 'Pairing enforcement: ' . $key . ' flagged after ' . $streak . ' consecutive beacon misses — ' . $reason . '. REVERSIBLE: review (legit change?) then Re-pair in the Servers tab.';
                if (function_exists('wa_send'))     { try { @wa_send($alert); } catch (\Throwable $e) {} }
                if (function_exists('mailer_send')) { try { @mailer_send('Pairing alert', $alert); } catch (\Throwable $e) {} }
                if (function_exists('log_event'))   { try { log_event($key, 'pair', 'flagged', $alert, []); } catch (\Throwable $e) {} }
            }
        }
    }
    if (function_exists('log_event')) { try { log_event($key, 'pair', $state, $reason, ['server_ip' => $serverIp, 'hostname' => $host, 'fingerprint' => $fingerprint]); } catch (\Throwable $e) {} }
    return ['state' => $state, 'reason' => $reason];
}
/** Latest pairing result for a license (for the admin card). Returns [state, reason, at] or null. */
function smlic_pair_last(string $key): ?array {
    if ($key === '') return null;
    try {
        $st = db()->prepare("SELECT result, message, created_at FROM license_logs WHERE license_key=? AND action='pair' AND result IN ('ok','miss','bootstrap','nobeacon') ORDER BY id DESC LIMIT 1");
        if (!$st) return null;
        $st->bind_param('s', $key); $st->execute(); $r = $st->get_result()->fetch_assoc();
        return $r ? ['state' => (string)$r['result'], 'reason' => (string)$r['message'], 'at' => (string)$r['created_at']] : null;
    } catch (\Throwable $e) { return null; }
}
/* TEMP-DIAG (license-protection tokens) — shows the per-license enforcement tokens (feat_key, the signed-verdict
 * gates, the sync policy) + the LAST EXCHANGE timestamps. Shown in the Servers card + License edit/list while we run
 * the enforcement experiments. require_admin() gates every caller. REMOVE this block + its 3 call sites after testing.
 * $r must carry: license_key, bound_fingerprint, status, expires_at, last_check_at, sync_enabled, sync_purge,
 * directive, pin_version, tamper_status, pair_secret, and (optional) last_heartbeat_at / last_action_at. */
function smlic_protection_block(array $r, bool $compact = false): string {
    return '';   // PRODUCTION: TEMP-DIAG disabled — never display license-protection secrets (S/K/feat_key) in the panel. (Re-enable for dev by removing this line.)
    $key  = (string)($r['license_key'] ?? '');
    $fp   = (string)($r['bound_fingerprint'] ?? '');
    $feat = ($key !== '' && $fp !== '' && function_exists('smlic_feat_key')) ? smlic_feat_key($key, $fp) : '';
    $ago = function ($dt) {
        if (!$dt) return 'never';
        $ts = is_numeric($dt) ? (int)$dt : strtotime((string)$dt);
        if (!$ts) return h((string)$dt);
        $s = time() - $ts;
        if ($s < 0)     return 'in future';
        if ($s < 60)    return $s . 's ago';
        if ($s < 3600)  return floor($s / 60) . 'm ago';
        if ($s < 86400) return floor($s / 3600) . 'h ago';
        return floor($s / 86400) . 'd ago';
    };
    $lastChk = (string)($r['last_check_at'] ?? '');
    $sync  = (int)($r['sync_enabled'] ?? 0);
    $purge = (int)($r['sync_purge'] ?? 0);
    $dir   = (string)($r['directive'] ?? 'normal');
    $pin   = (string)($r['pin_version'] ?? '');
    $tamp  = (string)($r['tamper_status'] ?? 'none');
    $S      = (string)($r['pair_secret'] ?? '');                                 // Stage 0: per-license base secret (master)
    $pairId = ($S !== '' && function_exists('smlic_pair_id'))  ? smlic_pair_id($S)        : '';
    $pairK  = ($S !== '' && $key !== '' && function_exists('smlic_pair_key')) ? smlic_pair_key($key, $S) : '';
    $stale = $lastChk !== '' && (time() - (int)strtotime($lastChk)) > 86400;   // >24h since last exchange = at risk
    if ($compact) {
        return '<div style="font-size:11px;color:#64748b;margin-top:4px;line-height:1.5">'
             . '&#128273; last exchange: <b style="color:' . ($stale ? '#b91c1c' : '#0f1b33') . '">' . h($lastChk ?: 'never') . '</b> (' . $ago($lastChk) . ')'
             . ' &middot; sync ' . ($sync ? '<b style="color:#1f9d55">ON</b>' : 'off') . ($purge ? ' &middot; <b style="color:#b91c1c">purge</b>' : '')
             . ($tamp !== 'none' ? ' &middot; <b style="color:#b91c1c">tamper:' . h($tamp) . '</b>' : '')
             . ($feat !== '' ? ' &middot; feat <code>' . h(substr($feat, 0, 12)) . '&hellip;</code>' : ' &middot; <span style="color:#b91c1c">no feat_key (unbound)</span>')
             . ($pairId !== '' ? ' &middot; pair <code>' . h($pairId) . '</code>' : '')
             . '</div>';
    }
    $row = fn($k, $v) => '<div style="display:flex;gap:10px;padding:3px 0;font-size:12px;align-items:baseline"><span style="min-width:148px;color:var(--sm-faint,#94a3b8);flex-shrink:0">' . h($k) . '</span><span style="color:var(--sm-text,#1f2733);word-break:break-all">' . $v . '</span></div>';
    $o  = '<div style="margin-top:10px;border:1px dashed var(--sm-line,#c4b5e8);background:var(--sm-surface2,#faf7ff);border-radius:9px;padding:11px 13px">';
    $o .= '<div style="font-size:12px;font-weight:800;color:var(--sm-accent,#6b3fa0);margin-bottom:7px">License-protection tokens <span style="font-weight:600;color:var(--sm-faint,#a99bc9)">&middot; temporary, shown during enforcement testing</span></div>';
    $o .= $row('feat_key', $feat !== '' ? '<code class="copykey" data-k="' . h($feat) . '" title="Click to copy" style="cursor:pointer">' . h($feat) . '</code>' : '<span style="color:#b91c1c">&mdash; needs a bound fingerprint (not downloaded/activated yet)</span>');
    $o .= $row('base secret (S)', $S !== '' ? '<code class="copykey" data-k="' . h($S) . '" title="Click to copy" style="cursor:pointer">' . h($S) . '</code> <span style="color:#a99bc9;font-size:11px">master &middot; server-only, never sent raw</span>' : '<span style="color:#94a3b8">&mdash; not generated yet (no check-in)</span>');
    $o .= $row('pair key (K)', $pairK !== '' ? '<code class="copykey" data-k="' . h($pairK) . '" title="Click to copy" style="cursor:pointer">' . h($pairK) . '</code> <span style="color:#a99bc9;font-size:11px">delivered to plugin (in signed verdict)</span>' : '<span style="color:#94a3b8">&mdash;</span>');
    $o .= $row('pair id', $pairId !== '' ? '<code>' . h($pairId) . '</code>' : '<span style="color:#94a3b8">&mdash;</span>');
    $pl = function_exists('smlic_pair_last') ? smlic_pair_last($key) : null;
    if ($pl) { $pc = $pl['state'] === 'ok' ? '#1f9d55' : ($pl['state'] === 'miss' ? '#b91c1c' : '#94a3b8'); $o .= $row('pairing (beacon)', '<b style="color:' . $pc . '">' . h($pl['state']) . '</b> <span style="color:#94a3b8">' . h($pl['reason']) . ' &middot; ' . h($pl['at']) . '</span>'); }
    else { $o .= $row('pairing (beacon)', '<span style="color:#94a3b8">&mdash; no beacon logged yet (report-only)</span>'); }
    $pe = (int)($r['pair_enforce'] ?? 0); $pfl = (int)($r['pair_flagged'] ?? 0);
    $o .= $row('pair enforce', $pe ? ('<b style="color:#1f9d55">ON</b>' . ($pfl ? ' &middot; <b style="color:#b91c1c">FLAGGED — reversible stop active (Re-pair to clear)</b>' : ' &middot; clear')) : '<span style="color:#94a3b8">off (report-only)</span>');
    $o .= $row('bound fingerprint', $fp !== '' ? '<code>' . h($fp) . '</code>' : '<span style="color:#94a3b8">&mdash; unbound</span>');
    $o .= $row('signed verdict', 'status=<b>' . h((string)($r['status'] ?? '')) . '</b> &middot; expires=' . ($r['expires_at'] ?? '' ? h((string)$r['expires_at']) : '&mdash;') . ($pin !== '' ? ' &middot; pin=<b>' . h($pin) . '</b>' : ''));
    $o .= $row('sync policy', 'escalation=' . ($sync ? '<b style="color:#1f9d55">ON</b>' : 'off') . ' &middot; purge=' . ($purge ? '<b style="color:#b91c1c">ON</b>' : 'off') . ' &middot; directive=<b>' . h($dir) . '</b>');
    $o .= $row('tamper status', $tamp !== 'none' ? '<b style="color:#b91c1c">' . h($tamp) . '</b>' : 'none');
    $o .= $row('last exchange', '<b style="color:' . ($stale ? '#b91c1c' : '#1f9d55') . '">' . h($lastChk ?: 'never') . '</b> <span style="color:#94a3b8">(' . $ago($lastChk) . ')</span>' . ($stale ? ' <span style="color:#b91c1c;font-size:11px">&#9888; &gt;24h &mdash; license at risk</span>' : ''));
    if (array_key_exists('last_heartbeat_at', $r)) $o .= $row('last heartbeat', ($r['last_heartbeat_at'] ? h((string)$r['last_heartbeat_at']) : '&mdash;') . ' <span style="color:#94a3b8">(' . $ago((string)($r['last_heartbeat_at'] ?? '')) . ')</span>');
    if (array_key_exists('last_action_at', $r))    $o .= $row('last action', ($r['last_action_at'] ? h((string)$r['last_action_at']) : '&mdash;') . ' <span style="color:#94a3b8">(' . $ago((string)($r['last_action_at'] ?? '')) . ')</span>');
    $o .= '</div>';
    return $o;
}
function sign_payload(array $payload): array {
    $privatePath = envv('PRIVATE_KEY');
    $privateKey = is_file($privatePath) ? file_get_contents($privatePath) : '';
    if (!$privateKey) {
        throw new RuntimeException('Private key not found');
    }

    $data = json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    $pkey = openssl_pkey_get_private($privateKey);
    if (!$pkey) {
        throw new RuntimeException('Invalid private key');
    }

    $signature = '';
    $ok = openssl_sign($data, $signature, $pkey, OPENSSL_ALGO_SHA256);
    if (!$ok) {
        throw new RuntimeException('Signing failed');
    }

    return [
        'payload' => $payload,
        'signature_alg' => 'RSA-SHA256',
        'signature' => base64_encode($signature),
    ];
}

function license_payload(array $lic, string $serverIp, string $hostname, string $fingerprint): array {
    $pairSecret = smlic_pair_secret($lic);   // Stage 0: ensure/generate the per-license base secret S (server-only)
    return [
        'product' => envv('PRODUCT_CODE', 'guirkhunter'),
        'client_name' => $lic['client_name'] ?? '',
        'client_email' => $lic['client_email'] ?? '',
        'license_key' => $lic['license_key'],
        'status' => $lic['status'],
        'plan' => $lic['plan'],
        'features' => resolve_features($lic),
        'bound_ip' => $lic['bound_ip'],
        'bound_hostname' => $lic['bound_hostname'],
        'fingerprint' => $lic['bound_fingerprint'],
        'request_server_ip' => $serverIp,
        'request_hostname' => $hostname,
        'request_fingerprint' => $fingerprint,
        'expires_at' => $lic['expires_at'],
        'issued_at' => date('c'),
        'next_check_after' => date('c', time() + 21600),
        'grace_hours' => (int)envv('DEFAULT_GRACE_HOURS', '72'),
        // ── connection-loss escalation directives (SIGNED; client trusts only these) ──
        'sync_enabled' => (int)($lic['sync_enabled'] ?? 0) === 1,                              // opt this license into the escalation ladder
        'sync_purge'   => (int)($lic['sync_purge'] ?? 0) === 1,                                // suspected-pirate: allow 48h-silence delete
        'sync_stop'    => in_array(($lic['directive'] ?? 'normal'), ['normal', 'hold', 'permstop'], true) ? ($lic['directive'] ?? 'normal') : 'normal',
        // server-gated VALUE: a per-license secret (HMAC under the server's offline private key, bound to the
        // fingerprint) delivered ONLY inside this RSA-signed verdict for a valid license. Features can encrypt
        // their server-delivered data with it — a patched-gate pirate without a valid verdict can't derive it.
        'feat_key'     => smlic_feat_key((string)$lic['license_key'], (string)($lic['bound_fingerprint'] ?? '')),
        // PAIR (Stage 0, INERT): derived pairing key K delivered to the plugin (raw S never sent) + a public pair_id.
        'pair_key'     => smlic_pair_key((string)$lic['license_key'], $pairSecret),
        'pair_id'      => smlic_pair_id($pairSecret),
        'pair_stop'    => ((int)($lic['pair_enforce'] ?? 0) === 1 && (int)($lic['pair_flagged'] ?? 0) === 1),   // Stage 3: signed REVERSIBLE stop (opt-in; default off → always false)
    ];
}


function normalize_action_name(string $action): string {
    $action = strtolower(trim($action));
    return preg_match('/^[a-z0-9_:-]{1,60}$/', $action) ? $action : '';
}

function normalize_integrity_hash(string $hash): string {
    $hash = strtolower(trim($hash));
    return preg_match('/^[a-f0-9]{64}$/', $hash) ? $hash : '';
}

function action_required_feature(string $action): string {
    $map = [
        'scan' => 'scan',
        'clean' => 'scan',
        'pause' => 'scan',
        'resume' => 'scan',
        'stop' => 'scan',
        'update' => 'scan',

        'make_report' => 'reports',
        'open_report' => 'reports',
        'delete_report' => 'reports',

        'telegram' => 'telegram',
        'save_telegram' => 'telegram',
        'test_alert' => 'telegram',

        'alerts' => 'telegram',
        'save_alert_settings' => 'telegram',

        'cleanup' => 'cleanup',
        'cleanup_now' => 'cleanup',

        'smart_results' => 'smart_engine',
        'scanning_review' => 'smart_engine',
        'smart_engine' => 'smart_engine',
    ];

    return $map[$action] ?? $action;
}

function action_check_fail(string $licenseKey, string $action, string $status, string $message, array $ctx = [], int $code = 403): never {
    log_event($licenseKey ?: null, 'action-check:' . ($action ?: '-'), $status, $message, $ctx);

    json_response([
        'ok' => false,
        'allow' => false,
        'status' => $status,
        'message' => $message,
    ], $code);
}

function license_update_tamper(int $id, string $status): void {
    $stmt = db()->prepare("UPDATE licenses SET tamper_status=?, status=IF(?='blocked','suspended',status), updated_at=NOW() WHERE id=?");
    $stmt->bind_param('ssi', $status, $status, $id);
    $stmt->execute();
}

function license_set_expected_integrity(int $id, string $integrityHash): void {
    $stmt = db()->prepare("UPDATE licenses SET expected_integrity_hash=?, updated_at=NOW() WHERE id=? AND expected_integrity_hash IS NULL");
    $stmt->bind_param('si', $integrityHash, $id);
    $stmt->execute();
}

function api_action_check(): never {
    $data = json_input();

    $licenseKey = strtoupper(trim((string)($data['license_key'] ?? '')));
    $serverIp = normalize_ip((string)($data['server_ip'] ?? request_ip()));
    $hostname = substr(trim((string)($data['hostname'] ?? '')), 0, 255);
    $fingerprint = normalize_fingerprint((string)($data['fingerprint'] ?? ''));
    $pluginVersion = substr(trim((string)($data['plugin_version'] ?? '')), 0, 40);
    $action = normalize_action_name((string)($data['action'] ?? ''));
    $integrityHash = normalize_integrity_hash((string)($data['integrity_hash'] ?? ''));

    $ctx = [
        'server_ip' => $serverIp,
        'hostname' => $hostname,
        'fingerprint' => $fingerprint,
        'plugin_version' => $pluginVersion,
    ];

    if ($licenseKey === '' || $serverIp === '' || $fingerprint === '' || $action === '') {
        action_check_fail($licenseKey, $action, 'bad_request', 'license_key, server_ip, fingerprint and action are required', $ctx, 400);
    }

    $lic = license_find($licenseKey);

    if (!$lic) {
        action_check_fail($licenseKey, $action, 'invalid', 'Invalid license key', $ctx, 404);
    }

    $id = (int)$lic['id'];

    if (!empty($lic['tamper_status']) && $lic['tamper_status'] === 'blocked') {
        action_check_fail($licenseKey, $action, 'tampered', 'Plugin integrity was previously blocked. Contact support.', $ctx, 403);
    }

    if (license_expired($lic)) {
        db()->query("UPDATE licenses SET status='expired' WHERE id=" . $id);
        action_check_fail($licenseKey, $action, 'expired', 'License expired', $ctx, 403);
    }

    if ($lic['status'] === 'suspended') {
        action_check_fail($licenseKey, $action, 'suspended', 'License suspended', $ctx, 403);
    }

    if ($lic['status'] === 'new') {
        action_check_fail($licenseKey, $action, 'not_activated', 'License not activated', $ctx, 403);
    }

    $ipMatches = hash_equals((string)$lic['bound_ip'], $serverIp);
    $fpMatches = hash_equals((string)$lic['bound_fingerprint'], $fingerprint);

    if (!$ipMatches || !$fpMatches) {
        action_check_fail($licenseKey, $action, 'binding_mismatch', 'IP or fingerprint mismatch. Contact support.', $ctx, 403);
    }

    if ($integrityHash === '') {
        action_check_fail($licenseKey, $action, 'missing_integrity', 'Missing plugin integrity hash', $ctx, 403);
    }

    if (empty($lic['expected_integrity_hash'])) {
        license_set_expected_integrity($id, $integrityHash);
        $lic['expected_integrity_hash'] = $integrityHash;
        log_event($licenseKey, 'integrity-register', 'ok', 'Initial integrity hash registered', $ctx);
    }

    if (!hash_equals((string)$lic['expected_integrity_hash'], $integrityHash)) {
        license_update_tamper($id, 'blocked');
        action_check_fail($licenseKey, $action, 'tampered', 'Plugin integrity hash mismatch. Plugin locked.', $ctx, 403);
    }

    $features = resolve_features($lic);
    $requiredFeature = action_required_feature($action);

    if (!in_array($requiredFeature, $features, true)) {
        action_check_fail($licenseKey, $action, 'feature_denied', 'This action requires feature: ' . $requiredFeature, $ctx, 403);
    }

    $stmt = db()->prepare("UPDATE licenses SET last_action_at=NOW(), last_check_at=NOW() WHERE id=?");
    $stmt->bind_param('i', $id);
    $stmt->execute();

    $payload = [
        'product' => envv('PRODUCT_CODE', 'guirkhunter'),
        'client_name' => $lic['client_name'] ?? '',
        'client_email' => $lic['client_email'] ?? '',
        'license_key' => $licenseKey,
        'action' => $action,
        'required_feature' => $requiredFeature,
        'server_ip' => $serverIp,
        'hostname' => $hostname,
        'fingerprint' => $fingerprint,
        'integrity_hash' => $integrityHash,
        'plugin_version' => $pluginVersion,
        'allow' => true,
        'status' => 'active',
        'issued_at' => date('c'),
        'expires_at' => date('c', time() + 120),
        'nonce' => bin2hex(random_bytes(16)),
    ];

    $signed = sign_payload($payload);

    log_event($licenseKey, 'action-check:' . $action, 'ok', 'Action allowed', $ctx);

    json_response([
        'ok' => true,
        'allow' => true,
        'status' => 'active',
        'action' => $action,
        'required_feature' => $requiredFeature,
        'features' => $features,
        'action_token' => $signed,
        'message' => 'Action allowed',
    ]);
}


function api_activate_or_check(string $mode): never {
    $data = json_input();

    $licenseKey = strtoupper(trim((string)($data['license_key'] ?? '')));
    $serverIp = normalize_ip((string)($data['server_ip'] ?? request_ip()));
    $hostname = substr(trim((string)($data['hostname'] ?? '')), 0, 255);
    $fingerprint = normalize_fingerprint((string)($data['fingerprint'] ?? ''));
    $pluginVersion = substr(trim((string)($data['plugin_version'] ?? '')), 0, 40);

    $ctx = [
        'server_ip' => $serverIp,
        'hostname' => $hostname,
        'fingerprint' => $fingerprint,
        'plugin_version' => $pluginVersion,
    ];

    if ($licenseKey === '' || $serverIp === '' || $fingerprint === '') {
        log_event($licenseKey, $mode, 'bad_request', 'Missing license_key/server_ip/fingerprint', $ctx);
        json_response([
            'ok' => false,
            'status' => 'bad_request',
            'message' => 'license_key, server_ip and fingerprint are required'
        ], 400);
    }

    $lic = license_find($licenseKey);

    if (!$lic) {
        log_event($licenseKey, $mode, 'invalid', 'License not found', $ctx);
        json_response(['ok' => false, 'status' => 'invalid', 'message' => 'Invalid license key'], 404);
    }

    if (license_expired($lic)) {
        db()->query("UPDATE licenses SET status='expired' WHERE id=" . (int)$lic['id']);
        log_event($licenseKey, $mode, 'expired', 'License expired', $ctx);
        json_response(['ok' => false, 'status' => 'expired', 'message' => 'License expired'], 403);
    }

    if ($lic['status'] === 'suspended') {
        log_event($licenseKey, $mode, 'suspended', 'License suspended', $ctx);
        json_response(['ok' => false, 'status' => 'suspended', 'message' => 'License suspended'], 403);
    }

    if ($mode === 'activate') {
        $notBound = empty($lic['bound_ip']) && empty($lic['bound_fingerprint']);

        if ($notBound) {
            if (function_exists('smlic_server_taken') && ($smOther = smlic_server_taken($licenseKey, $serverIp, $hostname, $fingerprint))) {
                log_event($licenseKey, $mode, 'dup_binding', 'Server already bound to ' . $smOther, $ctx);
                json_response(['ok' => false, 'status' => 'dup_binding', 'message' => 'This server (IP + hostname) is already licensed under another serial. One license per server.'], 409);
            }
            $stmt = db()->prepare("
                UPDATE licenses
                SET status='active',
                    bound_ip=?,
                    bound_hostname=?,
                    bound_fingerprint=?,
                    activated_at=COALESCE(activated_at, NOW()),
                    last_check_at=NOW()
                WHERE id=?
            ");
            $id = (int)$lic['id'];
            $stmt->bind_param('sssi', $serverIp, $hostname, $fingerprint, $id);
            $stmt->execute();
            $lic = license_find($licenseKey);
            log_event($licenseKey, 'activate', 'activated', 'License activated and bound', $ctx);
        }
    }

    if ($lic['status'] === 'new') {
        log_event($licenseKey, $mode, 'not_activated', 'License is not activated yet', $ctx);
        json_response(['ok' => false, 'status' => 'not_activated', 'message' => 'License not activated'], 403);
    }

    // Fingerprint = authoritative binding (stable behind Cloudflare / on IP change).
    // IP auto-rebinds when the same machine reports a new origin IP. Only a DIFFERENT machine is rejected.
    if (!hash_equals((string)$lic['bound_fingerprint'], $fingerprint)) {
        log_event($licenseKey, $mode, 'binding_mismatch', 'Fingerprint mismatch (different machine)', $ctx);
        json_response([
            'ok' => false,
            'status' => 'binding_mismatch',
            'message' => 'License is bound to a different machine. Contact support.',
            'bound_ip' => $lic['bound_ip'],
        ], 403);
    }
    if (!hash_equals((string)$lic['bound_ip'], $serverIp) || !hash_equals((string)($lic['bound_hostname'] ?? ''), $hostname)) {
        $rid = (int)$lic['id'];
        $rs = db()->prepare("UPDATE licenses SET bound_ip=?, bound_hostname=? WHERE id=?");
        $rs->bind_param('ssi', $serverIp, $hostname, $rid); $rs->execute();
        log_event($licenseKey, $mode, 'ip_rebind', 'Origin IP/hostname updated for same fingerprint (Cloudflare/IP change): ' . $lic['bound_ip'] . ' -> ' . $serverIp, $ctx);
        $lic = license_find($licenseKey);
        flag_clone_if_thrashing($licenseKey, (int)$lic['id'], $ctx);   // operator-side clone/sharing detection (flag only)
    }

    $pluginEnabled = isset($data['plugin_enabled']) ? ((string)$data['plugin_enabled'] === '0' ? 0 : 1) : 1;
    // /api/check IS the plugin's heartbeat (smpro_lic_heartbeat → /api/check), so stamp last_heartbeat_at too —
    // otherwise that column stays NULL forever and the panel shows "last heartbeat — never".
    $stmt = db()->prepare("UPDATE licenses SET last_check_at=NOW(), last_heartbeat_at=NOW(), plugin_enabled=? WHERE id=?");
    $id = (int)$lic['id'];
    $stmt->bind_param('ii', $pluginEnabled, $id);
    $stmt->execute();

    $lic = license_find($licenseKey);
    $payload = license_payload($lic, $serverIp, $hostname, $fingerprint);
    $signed = sign_payload($payload);

    log_event($licenseKey, $mode, 'ok', 'License valid', $ctx);

    if (function_exists('smlic_telemetry_ingest')) smlic_telemetry_ingest($licenseKey, $data, $serverIp, $hostname);
    if (function_exists('smlic_pair_verify')) smlic_pair_verify($lic, $data, $serverIp, $hostname, $fingerprint);   // Stage 2: report-only beacon check (logs only, never stops)
    $smResp = ['ok' => true, 'status' => 'active', 'license' => $signed];
    if (function_exists('smlic_command_pop')) { $smCmd = smlic_command_pop($licenseKey); if ($smCmd) $smResp['command'] = $smCmd; }
    json_response($smResp);
}

/** Real-time warnings the license server can detect (tamper / expiry / technical) for the header bell. Each query is guarded so a missing column never 500s the panel. */
function sm_header_alerts(): array {
    $al = [];
    $cnt = function (string $sql): int {
        try { $r = db()->query($sql); if ($r) { $row = $r->fetch_assoc(); return (int)($row['c'] ?? 0); } } catch (\Throwable $e) {}
        return 0;
    };
    $n = $cnt("SELECT COUNT(*) c FROM licenses WHERE status='active' AND expires_at IS NOT NULL AND expires_at < NOW()");
    if ($n > 0) $al[] = ['lvl' => 'crit', 't' => $n . ' active license' . ($n > 1 ? 's' : '') . ' past expiry', 'h' => '/licenses'];
    $n = $cnt("SELECT COUNT(*) c FROM licenses WHERE (tamper_status IS NOT NULL AND tamper_status NOT IN ('','none','ok')) OR pair_flagged=1");
    if ($n > 0) $al[] = ['lvl' => 'crit', 't' => $n . ' tamper / pairing flag' . ($n > 1 ? 's' : ''), 'h' => '/servers'];
    $n = $cnt("SELECT COUNT(DISTINCT license_key) c FROM license_logs WHERE result='clone_suspected' AND created_at > NOW() - INTERVAL 7 DAY");
    if ($n > 0) $al[] = ['lvl' => 'crit', 't' => $n . ' clone-suspected server' . ($n > 1 ? 's' : ''), 'h' => '/logs'];
    $n = $cnt("SELECT COUNT(*) c FROM licenses WHERE status='active' AND expires_at IS NOT NULL AND expires_at >= NOW() AND expires_at < NOW() + INTERVAL 7 DAY");
    if ($n > 0) $al[] = ['lvl' => 'warn', 't' => $n . ' license' . ($n > 1 ? 's' : '') . ' expiring within 7 days', 'h' => '/licenses'];
    $n = $cnt("SELECT COUNT(*) c FROM licenses WHERE status='active' AND last_check_at IS NOT NULL AND last_check_at < NOW() - INTERVAL 24 HOUR");
    if ($n > 0) $al[] = ['lvl' => 'warn', 't' => $n . ' server' . ($n > 1 ? 's' : '') . ' silent over 24h', 'h' => '/servers'];
    return $al;
}

/** Header alert bell + dropdown (admins only). */
function sm_header_bell(): string {
    if (!function_exists('is_admin') || !is_admin()) return '';
    $al = sm_header_alerts();
    $crit = 0; foreach ($al as $x) if ($x['lvl'] === 'crit') $crit++;
    $cnt = count($al);
    $cls = $cnt ? ($crit ? ' has-crit' : ' has-warn') : '';
    $o = '<div id="smBell" class="smbell' . $cls . '"><button type="button" class="smbell-btn" aria-label="Alerts" onclick="smTglBell(event)">'
       . '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8a6 6 0 0 0-12 0c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.7 21a2 2 0 0 1-3.4 0"/></svg>'
       . ($cnt ? '<span class="smbell-badge">' . ($cnt > 9 ? '9+' : $cnt) . '</span>' : '')
       . '</button><div class="smbell-menu"><div class="smbell-h">Server alerts</div>';
    if (!$al) $o .= '<div class="smbell-empty">&#10003; All clear — no issues detected.</div>';
    else foreach ($al as $x) $o .= '<a class="smbell-row ' . h($x['lvl']) . '" href="' . h($x['h']) . '"><span class="smbell-dot"></span><span class="smbell-t">' . h($x['t']) . '</span><span class="smbell-go">&#8594;</span></a>';
    $o .= '</div></div>';
    return $o;
}

function layout_start(string $title = 'AiTech License Server'): void {
    if (!headers_sent()) { header('Cache-Control: no-store, no-cache, must-revalidate, private'); header('Pragma: no-cache'); }
    echo '<!doctype html><html><head><meta charset="utf-8">';
    echo '<meta name="viewport" content="width=device-width, initial-scale=1">';
    echo '<title>' . h($title) . '</title>';
    echo '<script>try{document.documentElement.setAttribute("data-smtheme",localStorage.getItem("smtheme")||"slate");}catch(e){document.documentElement.setAttribute("data-smtheme","slate");}</script>';
    echo '<style>/* SMPRO-REDESIGN */
*{box-sizing:border-box}
body{margin:0;font:14px/1.6 -apple-system,Segoe UI,Roboto,Arial,sans-serif;background:#f4f6fb;color:#1f2733}
a{color:#3b5bdb;text-decoration:none}
h1,h2,h3{color:#0f1b33}
.nav{position:fixed;top:0;left:0;width:236px;height:100vh;background:#10182b;display:flex;flex-direction:column;gap:2px;padding:62px 12px 16px;overflow:auto;z-index:30}
.nav::before{content:"AiTech \00B7 Licensing";position:fixed;top:0;left:0;width:236px;height:50px;display:flex;align-items:center;padding:0 16px;font-weight:800;color:#fff;background:#0c1322;font-size:14px;border-bottom:1px solid #1d2740}
.nav a{color:#cfd8ef;padding:9px 12px;border-radius:9px;font-size:13.5px;font-weight:600;border-left:3px solid transparent}
.nav a:hover{background:#1a2740;color:#fff}
.nav a[href="/logout"]{margin-top:auto;color:#f3a9a9}
.nav a[href="/public.pem"]{color:#9fb0d6}
.wrap{margin-left:236px;padding:22px 28px;max-width:1500px}
.hero{background:#fff;border:1px solid #e6eaf1;border-radius:14px;padding:18px 22px;margin-bottom:18px}
.hero h1{margin:0;font-size:22px;font-weight:800}
.hero p{margin:4px 0 0;color:#6b7686;font-size:13px}
.card{background:#fff;border:1px solid #e6eaf1;border-radius:14px;padding:18px 20px;margin-bottom:16px;box-shadow:0 6px 20px rgba(15,23,42,.05)}
.card h2{margin:0 0 14px;font-size:16px;font-weight:800}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.03em;color:#6b7686;font-weight:700;padding:9px 10px;border-bottom:2px solid #eef1f6}
td{padding:10px;border-bottom:1px solid #eef1f6;vertical-align:top}
tr:hover td{background:#fafbff}
button,.btn{display:inline-flex;align-items:center;gap:6px;background:#3b5bdb;color:#fff;border:0;border-radius:9px;padding:8px 13px;font-size:13px;font-weight:700;cursor:pointer;text-decoration:none}
button:hover,.btn:hover{background:#2f49b0}
button.danger,.btn.danger{background:#d93b3b}button.danger:hover{background:#b91c1c}
button.ok,.btn.ok{background:#1f9d55}
label{display:block;font-weight:700;color:#0f2657;font-size:13px;margin-bottom:4px}
input,select,textarea{padding:9px 12px;border:1px solid #d8dee9;border-radius:9px;font-size:14px;background:#fff;color:#1f2733;width:100%}
.form-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.badge{display:inline-block;font-size:11px;font-weight:700;padding:2px 9px;border-radius:20px;background:#eef2f7;color:#475569}
.badge.active{background:#e9f8ef;color:#1f9d55}.badge.suspended{background:#fdecec;color:#d93b3b}.badge.expired{background:#fdf6e7;color:#c47f17}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px;margin-bottom:16px}
.stat{background:#fff;border:1px solid #e6eaf1;border-radius:14px;padding:16px 18px}
.stat .num{font-size:30px;font-weight:800}
.stat .label{color:#6b7686;font-size:12px;margin-top:2px}
code{background:#f1f5f9;padding:1px 6px;border-radius:6px;font-size:12px}
small{color:#6b7686}
@media(max-width:860px){.nav{position:static;width:auto;height:auto;flex-direction:row;flex-wrap:wrap;padding:8px}.nav::before{display:none}.wrap{margin-left:0;padding:14px}}
</style>';
    echo '</head><body><div class="wrap">';
    echo '<header class="topbar"><div class="tb-left"><svg class="tb-lock" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg><span class="tb-mut">Licensing</span><span class="tb-sep">/</span><span class="tb-cur">' . h($title) . '</span></div>'
       . '<div class="tb-right">' . sm_header_bell() . '<div class="tb-user"><span class="tb-ini">A</span><span class="tb-who">Admin<small>Operator</small></span></div></div></header>';
    if (is_admin()) {
        echo '<nav class="nav">';
        echo '<a href="/">Dashboard</a>';
        echo '<a href="/licenses">Licenses</a>';
        echo '<a href="/licenses/new">Create License</a>';
        echo '<a href="/plans">Plans</a>';
        echo '<a href="/servers">Servers</a>';
        echo '<a href="/releases">Releases</a>';
        echo '<a href="/logs">Logs</a>';
        echo '<a href="/settings/smtp">Settings</a>';
        echo '<a href="/logout">Logout</a>';
        echo '</nav>';
    }
}

function layout_end(): void {
    // footer removed per request
    echo '<style>/* SMPRO-GUI-POLISH */.nav a{transition:background .12s,border-color .12s}.nav a.active{background:#1a2740;color:#fff;border-left-color:#3b5bdb}.nav a i,.nav a svg{margin-right:2px}.hero{display:flex;align-items:center;justify-content:space-between;gap:14px;flex-wrap:wrap}.card{transition:box-shadow .15s}.card:hover{box-shadow:0 10px 28px rgba(15,23,42,.08)}td small{display:block;color:#94a3b8;font-size:11px;margin-top:2px}table{border-radius:10px;overflow:hidden}.wrap>.card:last-child{background:transparent;border:0;box-shadow:none;color:#94a3b8;font-size:12px;padding:8px}::-webkit-scrollbar{width:9px;height:9px}::-webkit-scrollbar-thumb{background:#c7d0e0;border-radius:6px}.nav::-webkit-scrollbar-thumb{background:#2a3a5c}/* LICENSES-ACTIONS-INLINE */td.actions{min-width:360px}td.actions form{display:inline-flex;flex-wrap:wrap;gap:4px;align-items:center;vertical-align:middle;margin:0}td.actions>a.btn{vertical-align:middle;margin:0 4px 0 0}td.actions button,td.actions .btn{width:auto;margin:0;padding:6px 9px;font-size:12px;white-space:nowrap}</style>'; echo '<script>(function(){var p=location.pathname.replace(/\/+$/,"")||"/";var best=null,bl=-1;document.querySelectorAll(".nav a").forEach(function(a){var h=(a.getAttribute("href")||"").replace(/\/+$/,"")||"/";if(h===p||(h!=="/"&&p.indexOf(h)===0)){if(h.length>bl){bl=h.length;best=a;}}});if(best)best.classList.add("active");})();</script>';
    echo '<script>/* COPYKEY-GLOBAL */document.addEventListener("click",function(e){var c=e.target.closest(".copykey");if(!c)return;var t=c.getAttribute("data-k")||c.textContent;if(navigator.clipboard)navigator.clipboard.writeText(t);var o=c.textContent;c.textContent="\u2713 copied";c.style.color="#16a34a";setTimeout(function(){c.textContent=o;c.style.color="";},1000);});</script>';
    echo "<style>/* SMPRO-GUI2 */
body{background:#eef1f7}
.wrap{padding:24px 30px}
.card{border-radius:16px;border-color:#e8ecf3}
th{background:#fbfcfe}
tr:hover td{background:#f6f8ff}
button,.btn{border-radius:10px}
.btn-ghost{background:#eef1f6;color:#475569}.btn-ghost:hover{background:#e2e7f0}
.lic-stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(118px,1fr));gap:10px;margin-bottom:14px}
.lic-stat{background:#f7f9fc;border:1px solid #eef1f6;border-radius:12px;padding:11px 14px}
.lic-stat .n{font-size:22px;font-weight:800;line-height:1}.lic-stat .l{font-size:11px;color:#6b7686;margin-top:4px}
.lic-toolbar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;background:#f7f9fc;border:1px solid #eef1f6;border-radius:12px;padding:10px 12px;margin-bottom:14px}
.lic-toolbar select,.lic-toolbar input{width:auto;padding:8px 10px;font-size:12.5px;margin:0}
.lic-toolbar input[name=q]{flex:1;min-width:170px}
.chip{display:inline-block;font-size:11px;font-weight:700;padding:2px 9px;border-radius:7px;background:#eef2ff;color:#3b5bdb;white-space:nowrap}
.chip.alt{background:#fdf6e7;color:#c47f17}
.pdot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:7px;vertical-align:middle}
.pdot.ok{background:#1f9d55}.pdot.miss{background:#d97706}.pdot.none{background:#cbd5e1}
.rowmenu{position:relative;display:inline-block}
.rowmenu .dots{cursor:pointer;font-weight:800;color:#94a3b8;padding:2px 9px;border-radius:7px;font-size:18px;line-height:1;display:inline-block}
.rowmenu .dots:hover{background:#eef1f6;color:#3b5bdb}
.rowmenu .menu{position:absolute;right:0;top:calc(100% + 4px);z-index:50;min-width:184px;background:#fff;border:1px solid #e2e7f0;border-radius:11px;box-shadow:0 12px 34px rgba(15,23,42,.17);padding:5px;display:none;text-align:left}
.rowmenu.open .menu{display:block}
.rowmenu .menu form{margin:0;display:block}
.rowmenu .menu button{display:block;width:100%;background:none;color:#1f2733;border:0;border-radius:7px;padding:9px 11px;font-size:12.5px;font-weight:600;text-align:left;cursor:pointer}
.rowmenu .menu button:hover{background:#f1f5f9}
.rowmenu .menu button.danger{color:#d93b3b;background:none}.rowmenu .menu button.danger:hover{background:#fdecec}
.rowmenu .menu hr{border:0;border-top:1px solid #eef1f6;margin:4px 3px}
.appftr{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-top:22px;padding:16px 6px 6px;border-top:1px solid #e6eaf1;color:#94a3b8;font-size:12.5px}
.appftr-l{display:flex;align-items:center;gap:7px;flex-wrap:wrap}
.appftr-brand{font-weight:800;color:#475569;letter-spacing:.01em}
.appftr-sep{color:#cbd5e1}
.appftr-r{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.appftr-by{font-weight:700;color:#475569}
.appftr-wa{display:inline-flex;align-items:center;gap:5px;background:#e9f8ef;color:#1f9d55;border:1px solid #cdebd6;border-radius:999px;padding:4px 11px;font-weight:700;font-size:12px;text-decoration:none;transition:background .12s}
.appftr-wa:hover{background:#d7f0e0}
@media(max-width:680px){.appftr{justify-content:center;text-align:center}}
</style>";
    echo "<script>/* ROWMENU */document.addEventListener('click',function(e){var t=e.target.closest('.rowmenu .dots');document.querySelectorAll('.rowmenu.open').forEach(function(m){if(!t||m!==t.closest('.rowmenu'))m.classList.remove('open');});if(t){t.closest('.rowmenu').classList.toggle('open');e.stopPropagation();}});</script>";
    // ===== SMPRO theme system (switchable skins + readability) =====
    echo '<style>/* SMPRO-THEMES */
html[data-smtheme="slate"]{--sm-bg:#eef1f7;--sm-surface:#ffffff;--sm-surface2:#f7f9fc;--sm-sidebar:#10182b;--sm-brand-bg:#0c1322;--sm-sfg:#cfd8ef;--sm-text:#1b2330;--sm-muted:#46536b;--sm-faint:#647288;--sm-line:#e6eaf1;--sm-accent:#3b5bdb;--sm-accent-fg:#ffffff;--sm-accent-soft:#eef2ff}
html[data-smtheme="aurora"]{--sm-bg:#f6f7fb;--sm-surface:#ffffff;--sm-surface2:#f1f2fb;--sm-sidebar:#ffffff;--sm-brand-bg:#ffffff;--sm-brand-fg:#1b1e2b;--sm-sfg:#5b6276;--sm-text:#1b1e2b;--sm-muted:#515873;--sm-faint:#7c828f;--sm-line:#e6e7f1;--sm-accent:#5b5bf0;--sm-accent-fg:#ffffff;--sm-accent-soft:#eeeefd}
html[data-smtheme="midnight"]{--sm-bg:#0a0e16;--sm-surface:#111722;--sm-surface2:#0e141f;--sm-sidebar:#0c1019;--sm-brand-bg:#0a0e16;--sm-sfg:#aab6c9;--sm-text:#e9eef6;--sm-muted:#b6c0d0;--sm-faint:#8a97ab;--sm-line:#222c3d;--sm-accent:#00e5c4;--sm-accent-fg:#04121a;--sm-accent-soft:rgba(0,229,196,.12)}
html[data-smtheme]{--sm-brand-fg:#ffffff}
html[data-smtheme="aurora"]{--sm-brand-fg:#1b1e2b}
/* base: larger + stronger text across all themes */
html[data-smtheme] body{background:var(--sm-bg);color:var(--sm-text);font-size:14.5px}
html[data-smtheme] .hero,html[data-smtheme] .card{background:var(--sm-surface);border-color:var(--sm-line);color:var(--sm-text)}
html[data-smtheme] h1,html[data-smtheme] h2,html[data-smtheme] h3,html[data-smtheme] .hero h1{color:var(--sm-text)}
html[data-smtheme] .hero p{color:var(--sm-muted);font-size:13.5px}
html[data-smtheme] small,html[data-smtheme] .muted{color:var(--sm-muted)}
html[data-smtheme] a{color:var(--sm-accent)}
html[data-smtheme] code{background:var(--sm-surface2);color:var(--sm-muted)}
html[data-smtheme] table th{color:var(--sm-muted);background:var(--sm-surface2);border-color:var(--sm-line);font-size:12px}
html[data-smtheme] table td{border-color:var(--sm-line);color:var(--sm-text)}
html[data-smtheme] tr:hover td{background:var(--sm-surface2)}
html[data-smtheme] button,html[data-smtheme] .btn{background:var(--sm-accent);color:var(--sm-accent-fg)}
html[data-smtheme] .btn-ghost{background:var(--sm-surface2);color:var(--sm-muted)}
html[data-smtheme] input,html[data-smtheme] select,html[data-smtheme] textarea{background:var(--sm-surface);border-color:var(--sm-line);color:var(--sm-text)}
html[data-smtheme] label{color:var(--sm-text)}
html[data-smtheme] .nav{background:var(--sm-sidebar);border-right:1px solid var(--sm-line)}
html[data-smtheme] .nav::before{background:var(--sm-brand-bg);color:var(--sm-brand-fg);border-color:var(--sm-line)}
html[data-smtheme] .nav a{color:var(--sm-sfg)}
html[data-smtheme] .nav a:hover{background:var(--sm-surface2);color:var(--sm-text)}
html[data-smtheme] .nav a.active{background:var(--sm-accent);color:#fff;border-left-color:var(--sm-accent)}
html[data-smtheme] .lic-stat{background:var(--sm-surface2);border-color:var(--sm-line)}
html[data-smtheme] .lic-stat .n{color:var(--sm-text)}html[data-smtheme] .lic-stat .l{color:var(--sm-muted);font-size:12px}
html[data-smtheme] .lic-toolbar{background:var(--sm-surface2);border-color:var(--sm-line)}
html[data-smtheme] .chip{background:var(--sm-accent-soft);color:var(--sm-accent)}
html[data-smtheme] .rowmenu .menu{background:var(--sm-surface);border-color:var(--sm-line)}
html[data-smtheme] .rowmenu .menu button{color:var(--sm-text)}
html[data-smtheme] .rowmenu .menu button:hover{background:var(--sm-surface2)}
html[data-smtheme] .kpi{background:var(--sm-surface);border-color:var(--sm-line)}
html[data-smtheme] .kpi-n{color:var(--sm-text)}html[data-smtheme] .kpi-l{color:var(--sm-muted);font-size:12.5px}
html[data-smtheme] .dash2 .card{background:var(--sm-surface)}
html[data-smtheme] .act .time,html[data-smtheme] .act .when{color:var(--sm-faint)}
html[data-smtheme] .srv-kpi .c{background:var(--sm-surface);border-color:var(--sm-line)}
html[data-smtheme] .srv-kpi .c .n{color:var(--sm-text)}html[data-smtheme] .srv-kpi .c .l{color:var(--sm-muted)}
html[data-smtheme] .srv-tbl thead th{background:var(--sm-surface2);border-bottom:1px solid var(--sm-line)}
html[data-smtheme] .srv-row{border-color:var(--sm-line)}html[data-smtheme] .srv-row td{color:var(--sm-text)}
html[data-smtheme] .srv-row:hover{background:var(--sm-surface2)}
html[data-smtheme] .srv-host{color:var(--sm-text)}html[data-smtheme] .srv-ip{color:var(--sm-faint)}
html[data-smtheme] .srv-search{background:var(--sm-surface);border-color:var(--sm-line);color:var(--sm-text)}
html[data-smtheme] .srv-chip{background:var(--sm-surface);border-color:var(--sm-line);color:var(--sm-muted)}
html[data-smtheme] .srv-chip.on{background:var(--sm-accent);border-color:var(--sm-accent);color:#fff}
html[data-smtheme] .srv-grid{background:var(--sm-line)}html[data-smtheme] .srv-f{background:var(--sm-surface)}html[data-smtheme] .srv-f b{color:var(--sm-text)}
html[data-smtheme] .srv-prod{background:var(--sm-surface);border-color:var(--sm-line)}
html[data-smtheme] .srv-prod-top b{color:var(--sm-text)}
html[data-smtheme] .srv-tag{background:var(--sm-surface2);color:var(--sm-muted)}
html[data-smtheme] .srv-prod-key{color:var(--sm-faint)}
html[data-smtheme] .srv-pol{border-color:var(--sm-line)}
html[data-smtheme] .srv-pol-h{color:var(--sm-muted)}
html[data-smtheme] .srv-pol-dir{color:var(--sm-faint)}
html[data-smtheme] .srv-pol .pol{background:var(--sm-surface);border-color:var(--sm-line);color:var(--sm-text)}
html[data-smtheme] .srv-viol{border-color:var(--sm-line)}
html[data-smtheme] .srv-vrow{background:var(--sm-surface);border-color:var(--sm-line)}
html[data-smtheme] .srv-vk{color:var(--sm-text)}
html[data-smtheme] .srv-vm,html[data-smtheme] .srv-vt{color:var(--sm-faint)}
html[data-smtheme] .srv-detin,html[data-smtheme] .srv-det>td{background:var(--sm-surface)}
html[data-smtheme] .srv-prog{background:var(--sm-surface2);border-color:var(--sm-line)}
html[data-smtheme] .plan-card{background:var(--sm-surface);border-color:var(--sm-line)}
html[data-smtheme] .plan-name,html[data-smtheme] .plan-price{color:var(--sm-text)}
html[data-smtheme] .pedit{border-color:var(--sm-line)}html[data-smtheme] .pedit>summary{background:var(--sm-surface)}
html[data-smtheme] .cmp th,html[data-smtheme] .cmp td{border-color:var(--sm-line)}
html[data-smtheme] .cl-h{color:var(--sm-faint)}
html[data-smtheme] .cl-fg label{color:var(--sm-text)}
html[data-smtheme] .cl-fg input,html[data-smtheme] .cl-fg select{background:var(--sm-surface);border-color:var(--sm-line);color:var(--sm-text)}
html[data-smtheme] .cust-box{border-color:var(--sm-line)}
html[data-smtheme] .appftr{border-color:var(--sm-line);color:var(--sm-faint)}
html[data-smtheme] .appftr-brand,html[data-smtheme] .appftr-by{color:var(--sm-muted)}
/* dark theme: rescue dark inline text so nothing goes dark-on-dark */
html[data-smtheme="midnight"] [style*="color:#0f1b33"],html[data-smtheme="midnight"] [style*="color:#0f2657"],html[data-smtheme="midnight"] [style*="color:#1f2733"],html[data-smtheme="midnight"] [style*="color:#0f172a"],html[data-smtheme="midnight"] [style*="color:#1e293b"],html[data-smtheme="midnight"] [style*="color:#1b2330"]{color:var(--sm-text)!important}
html[data-smtheme="midnight"] .card[style*="background:#fff"],html[data-smtheme="midnight"] [style*="background:#ffffff"],html[data-smtheme="midnight"] [style*="background:#fff "]{background:var(--sm-surface)!important}
/* theme switcher (floating) */
.smfab{position:fixed;right:18px;bottom:18px;z-index:9999;font-family:inherit}
.smfab-btn{width:46px;height:46px;border-radius:50%;background:var(--sm-accent,#3b5bdb);color:var(--sm-accent-fg,#fff);border:0;box-shadow:0 8px 22px rgba(15,23,42,.28);cursor:pointer;display:flex;align-items:center;justify-content:center}
.smfab-btn:hover{filter:brightness(1.06)}
.smfab-menu{position:absolute;right:0;bottom:56px;background:var(--sm-surface,#fff);border:1px solid var(--sm-line,#e2e8f0);border-radius:12px;box-shadow:0 16px 40px rgba(15,23,42,.25);padding:6px;display:none;min-width:182px}
.smfab.open .smfab-menu{display:block}
.smfab-menu .ttl{font-size:10.5px;text-transform:uppercase;letter-spacing:.06em;color:var(--sm-faint,#94a3b8);padding:6px 10px 5px;font-weight:700}
.smfab-menu button{display:flex;align-items:center;gap:10px;width:100%;background:none;border:0;color:var(--sm-text,#1e293b);padding:9px 11px;border-radius:8px;font-size:13.5px;font-weight:600;cursor:pointer;text-align:left}
.smfab-menu button:hover{background:var(--sm-surface2,#f1f5f9)}
.smfab-menu button .sw{width:15px;height:15px;border-radius:5px;flex:none;border:1px solid rgba(0,0,0,.12)}
.smfab-menu button.on{color:var(--sm-accent,#3b5bdb)}
.smfab-menu button .ck{margin-left:auto;opacity:0;font-weight:800}
.smfab-menu button.on .ck{opacity:1}
</style>';
    echo '<div id="smThemeFab" class="smfab">'
       . '<div class="smfab-menu"><div class="ttl">Theme</div>'
       . '<button type="button" data-t="slate"><span class="sw" style="background:#3b5bdb"></span>Slate Pro<span class="ck">&#10003;</span></button>'
       . '<button type="button" data-t="aurora"><span class="sw" style="background:linear-gradient(135deg,#5b5bf0,#9a5bf0)"></span>Aurora<span class="ck">&#10003;</span></button>'
       . '<button type="button" data-t="midnight"><span class="sw" style="background:#00e5c4"></span>Midnight<span class="ck">&#10003;</span></button>'
       . '</div>'
       . '<button class="smfab-btn" type="button" aria-label="Change theme" onclick="smTglTheme(event)"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="13.5" cy="6.5" r=".6" fill="currentColor" stroke="none"/><circle cx="17.5" cy="10.5" r=".6" fill="currentColor" stroke="none"/><circle cx="8.5" cy="7.5" r=".6" fill="currentColor" stroke="none"/><circle cx="6.5" cy="12.5" r=".6" fill="currentColor" stroke="none"/><path d="M12 2C6.5 2 2 6.5 2 12s4.5 10 10 10c.93 0 1.7-.77 1.7-1.7 0-.43-.17-.82-.43-1.11-.27-.3-.44-.7-.44-1.12 0-.93.77-1.7 1.7-1.7H16c3.3 0 6-2.7 6-6 0-4.7-4.5-8.5-10-8.5z"/></svg></button>'
       . '</div>';
    echo '<script>(function(){function set(t){document.documentElement.setAttribute("data-smtheme",t);try{localStorage.setItem("smtheme",t);}catch(e){}var m=document.querySelectorAll("#smThemeFab .smfab-menu button");for(var i=0;i<m.length;i++){m[i].classList.toggle("on",m[i].getAttribute("data-t")===t);}}window.smTglTheme=function(e){e.stopPropagation();var f=document.getElementById("smThemeFab");if(f)f.classList.toggle("open");};var b=document.querySelectorAll("#smThemeFab .smfab-menu button");for(var i=0;i<b.length;i++){(function(x){x.addEventListener("click",function(){set(x.getAttribute("data-t"));var f=document.getElementById("smThemeFab");if(f)f.classList.remove("open");});})(b[i]);}document.addEventListener("click",function(e){var f=document.getElementById("smThemeFab");if(f&&!f.contains(e.target))f.classList.remove("open");});set(document.documentElement.getAttribute("data-smtheme")||"slate");})();</script>';
    // ===== header alert bell (styles + behavior) =====
    echo '<style>/* SMPRO-BELL */
.hero{gap:14px}
.smbell{position:relative;flex:0 0 auto}
.smbell-btn{position:relative;width:38px;height:38px;border-radius:10px;border:1px solid var(--sm-line,#e6eaf1);background:var(--sm-surface,#fff);color:var(--sm-muted,#475569);display:flex;align-items:center;justify-content:center;cursor:pointer}
.smbell-btn:hover{color:var(--sm-accent,#3b5bdb);border-color:var(--sm-accent,#3b5bdb)}
.smbell-badge{position:absolute;top:-6px;right:-6px;min-width:18px;height:18px;padding:0 5px;border-radius:9px;background:#94a3b8;color:#fff;font-size:11px;font-weight:800;display:flex;align-items:center;justify-content:center;border:2px solid var(--sm-surface,#fff)}
.smbell.has-warn .smbell-badge{background:#d97706}
.smbell.has-crit .smbell-badge{background:#dc2626}
.smbell.has-crit .smbell-btn,.smbell.has-warn .smbell-btn{color:var(--sm-text,#1b2330);border-color:var(--sm-line,#e6eaf1)}
.smbell-menu{position:absolute;right:0;top:46px;z-index:9998;width:308px;max-width:82vw;background:var(--sm-surface,#fff);border:1px solid var(--sm-line,#e6eaf1);border-radius:12px;box-shadow:0 18px 44px rgba(15,23,42,.22);padding:6px;display:none;text-align:left}
.smbell.open .smbell-menu{display:block}
.smbell-h{font-size:10.5px;text-transform:uppercase;letter-spacing:.06em;color:var(--sm-faint,#94a3b8);font-weight:700;padding:8px 10px 6px}
.smbell-empty{padding:14px 12px;color:var(--sm-muted,#475569);font-size:13px}
.smbell-row{display:flex;align-items:center;gap:10px;padding:10px 11px;border-radius:9px;color:var(--sm-text,#1b2330);text-decoration:none;font-size:13px}
.smbell-row:hover{background:var(--sm-surface2,#f7f9fc)}
.smbell-row .smbell-dot{width:9px;height:9px;border-radius:50%;flex:none;background:#94a3b8}
.smbell-row.crit .smbell-dot{background:#dc2626}
.smbell-row.warn .smbell-dot{background:#d97706}
.smbell-row .smbell-t{flex:1;line-height:1.35}
.smbell-row .smbell-go{color:var(--sm-faint,#94a3b8);font-weight:800}
</style>';
    echo '<script>(function(){window.smTglBell=function(e){e.stopPropagation();var b=document.getElementById("smBell");if(b)b.classList.toggle("open");};document.addEventListener("click",function(e){var b=document.getElementById("smBell");if(b&&!b.contains(e.target))b.classList.remove("open");});})();</script>';
    echo '<style>/* SMPRO-FIX */
html[data-smtheme="slate"]{--sm-faint:#566070}
html[data-smtheme="aurora"]{--sm-faint:#5d6470}
.topbar{display:flex;align-items:center;justify-content:space-between;gap:14px;min-height:54px;padding:10px 22px;margin:-24px -30px 18px;background:var(--sm-surface,#fff);border-bottom:1px solid var(--sm-line,#e6eaf1)}
.tb-left{display:flex;align-items:center;gap:8px;font-size:13px;min-width:0}
.tb-lock{color:var(--sm-accent,#3b5bdb);flex:none}
.tb-mut{color:var(--sm-faint,#647288)}
.tb-sep{color:var(--sm-line,#cbd5e1)}
.tb-cur{color:var(--sm-text,#1b2330);font-weight:700;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.tb-right{display:flex;align-items:center;gap:12px;flex:none}
.tb-user{display:flex;align-items:center;gap:8px}
.tb-ini{width:30px;height:30px;border-radius:8px;background:var(--sm-accent,#3b5bdb);color:var(--sm-accent-fg,#fff);display:flex;align-items:center;justify-content:center;font-weight:700;font-size:13px}
.tb-who{font-size:12px;font-weight:600;color:var(--sm-text,#1b2330);line-height:1.1}.tb-who small{display:block;font-size:10.5px;color:var(--sm-faint,#647288);font-weight:500}
@media(max-width:860px){.topbar{margin:-14px -14px 14px;padding:10px 14px}.tb-who{display:none}}
html[data-smtheme] .srv-hostc b,html[data-smtheme] .srv-host{color:var(--sm-text)}
html[data-smtheme] .srv-pcount{background:var(--sm-accent-soft);color:var(--sm-accent)}
html[data-smtheme] .plan-cyc{color:var(--sm-faint)}
html[data-smtheme] .plan-desc{color:var(--sm-muted)}
html[data-smtheme] .pe-name{color:var(--sm-text)}html[data-smtheme] .pe-price{color:var(--sm-accent)}
html[data-smtheme] .pe-tag,html[data-smtheme] .pe-srv{color:var(--sm-faint)}
html[data-smtheme] .cmp thead th{background:var(--sm-surface2);color:var(--sm-text)}html[data-smtheme] .cmp td,html[data-smtheme] .cmp th{border-color:var(--sm-line);color:var(--sm-text)}
html[data-smtheme] .chip{background:var(--sm-accent-soft);color:var(--sm-accent)}
html[data-smtheme] .plan-view{background:var(--sm-surface2);border-color:var(--sm-line)}
html[data-smtheme] .plan-view .pill{background:var(--sm-accent);color:var(--sm-accent-fg)}
html[data-smtheme] .plan-view .pv-head b{color:var(--sm-text)}
html[data-smtheme] .plan-view .pv-meta,html[data-smtheme] .plan-view .pv-sub{color:var(--sm-muted)}
html[data-smtheme] .plan-view ul.pv-feats li{color:var(--sm-text)}html[data-smtheme] .plan-view ul.pv-feats li.muted{color:var(--sm-faint)}
html[data-smtheme] .cust-box{border-color:var(--sm-line)}html[data-smtheme] .cust-sub{color:var(--sm-text)}html[data-smtheme] .cust-f{color:var(--sm-text)}
</style>';
    echo '</div></body></html>';
}

function page_login(): void {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        require_csrf();
        $username = trim((string)($_POST['username'] ?? ''));
        $password = (string)($_POST['password'] ?? '');

        $stmt = db()->prepare("SELECT * FROM admins WHERE username=? LIMIT 1");
        $stmt->bind_param('s', $username);
        $stmt->execute();
        $admin = $stmt->get_result()->fetch_assoc();

        if ($admin && password_verify($password, $admin['password_hash'])) {
            $_SESSION['admin_id'] = (int)$admin['id'];
            $_SESSION['admin_user'] = $admin['username'];
            redirect('/');
        }

        $error = 'Invalid username or password';
    }

    layout_start('Login');
    echo '<div class="card" style="max-width:430px;margin:24px auto">';
    echo '<h2>Admin Login</h2>';
    if (!empty($error)) echo '<p style="color:#b91c1c;font-weight:900">' . h($error) . '</p>';
    echo '<form method="post">';
    echo '<input type="hidden" name="csrf" value="' . h(csrf_token()) . '">';
    echo '<p><label>Username</label><input name="username" required></p>';
    echo '<p><label>Password</label><input name="password" type="password" required></p>';
    echo '<button class="btn" type="submit">Login</button>';
    echo '</form></div>';
    layout_end();
}

function page_dashboard(): void {
    require_admin();

    $stats = ['new'=>0,'active'=>0,'suspended'=>0,'expired'=>0];
    if ($cr = db()->query("SELECT status, COUNT(*) c FROM licenses GROUP BY status")) while ($x = $cr->fetch_assoc()) { $s = (string)$x['status']; if (isset($stats[$s])) $stats[$s] = (int)$x['c']; }
    $total = array_sum($stats);
    $servers = ($q=@db()->query("SELECT COUNT(*) c FROM license_telemetry")) ? (int)$q->fetch_assoc()['c'] : 0;
    $trials  = ($q=@db()->query("SELECT COUNT(*) c FROM licenses WHERE plan='free_trial'")) ? (int)$q->fetch_assoc()['c'] : 0;
    $logs = db()->query("SELECT * FROM license_logs ORDER BY id DESC LIMIT 8")->fetch_all(MYSQLI_ASSOC);
    $byprod = []; if ($pr=@db()->query("SELECT product_code, COUNT(*) c FROM licenses GROUP BY product_code ORDER BY c DESC LIMIT 6")) while ($x=$pr->fetch_assoc()) $byprod[(string)$x['product_code']] = (int)$x['c'];
    $prodName = function ($pc) { $pc=(string)$pc; if ($pc==='') return 'Unspecified'; if (stripos($pc,'safety')!==false) return 'Safety Monitor'; if (stripos($pc,'mail')!==false) return 'MailShield'; return $pc; };
    $ago = function ($dt) { if (!$dt) return '-'; $t = strtotime((string)$dt); if (!$t) return h((string)$dt); $s = time() - $t; if ($s<60) return $s.'s'; if ($s<3600) return floor($s/60).'m'; if ($s<86400) return floor($s/3600).'h'; return floor($s/86400).'d'; };
    $pct = fn($n) => $total > 0 ? max(2, (int)round($n * 100 / $total)) : 0;

    $sI = fn($p) => '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">'.$p.'</svg>';
    $aico = function (string $a): string {
        $a = strtolower($a);
        $p = '<path d="M3 12h4l2 6 4-14 2 8h6"/>';
        if (strpos($a,'pair')!==false) $p='<path d="M9 7H6a3 3 0 0 0 0 6h3M15 17h3a3 3 0 0 0 0-6h-3M8 10h8"/>';
        elseif (strpos($a,'check')!==false||strpos($a,'verify')!==false) $p='<path d="M20 6 9 17l-5-5"/>';
        elseif (strpos($a,'activate')!==false) $p='<circle cx="12" cy="12" r="9"/><path d="m8.5 12 2.5 2.5 4.5-5"/>';
        elseif (strpos($a,'download')!==false||strpos($a,'deliver')!==false) $p='<path d="M12 3v12m0 0 4-4m-4 4-4-4"/><path d="M4 17v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2"/>';
        elseif (strpos($a,'revoke')!==false||strpos($a,'suspend')!==false) $p='<circle cx="12" cy="12" r="9"/><path d="m15 9-6 6M9 9l6 6"/>';
        elseif (strpos($a,'create')!==false) $p='<path d="M12 5v14M5 12h14"/>';
        elseif (strpos($a,'telemetry')!==false||strpos($a,'sync')!==false) $p='<path d="M4 11a9 9 0 0 1 9 9M4 4a16 16 0 0 1 16 16"/><circle cx="5" cy="19" r="1.5"/>';
        return '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">'.$p.'</svg>';
    };
    $pctTot = fn($n) => $total > 0 ? (int)round($n * 100 / $total) : 0;

    layout_start('Dashboard');
    echo '<div class="dhead"><div><div class="dt">Dashboard</div><div class="ds">License activity, server health and account distribution at a glance.</div></div>'
       . '<div class="da"><a class="btn" href="/licenses/new">&#43; Create license</a><a class="btn btn-ghost" href="/servers">Servers</a><a class="btn btn-ghost" href="/logs">Logs</a></div></div>';

    echo '<div class="dkpis">';
    echo '<div class="dkpi"><div class="dkpi-ic" style="background:var(--sm-accent-soft);color:var(--sm-accent)">'.$sI('<path d="M15 7a4 4 0 1 0-3.9 5H14l1.5 1.5L17 12l1.5 1.5L21 11l-2-2z"/><circle cx="9" cy="9" r="1"/>').'</div><div class="dkpi-n">'.$total.'</div><div class="dkpi-l">Total licenses</div><div class="dkpi-s">across all products</div></div>';
    echo '<div class="dkpi"><div class="dkpi-ic" style="background:rgba(31,157,85,.14);color:#1f9d55">'.$sI('<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><path d="m9 11 3 3L22 4"/>').'</div><div class="dkpi-n">'.$stats['active'].'</div><div class="dkpi-l">Active</div><div class="dkpi-s">'.$pctTot($stats['active']).'% of total</div></div>';
    echo '<div class="dkpi"><div class="dkpi-ic" style="background:rgba(226,87,76,.14);color:#e2574c">'.$sI('<circle cx="12" cy="12" r="9"/><path d="M9 9h2v6H9zM13 9h2v6h-2z"/>').'</div><div class="dkpi-n">'.$stats['suspended'].'</div><div class="dkpi-l">Suspended</div><div class="dkpi-s">'.$pctTot($stats['suspended']).'% of total</div></div>';
    echo '<div class="dkpi"><div class="dkpi-ic" style="background:rgba(14,165,183,.14);color:#0ea5b7">'.$sI('<rect x="3" y="4" width="18" height="7" rx="1.5"/><rect x="3" y="13" width="18" height="7" rx="1.5"/><path d="M7 7.5h.01M7 16.5h.01"/>').'</div><div class="dkpi-n">'.$servers.'</div><div class="dkpi-l">Reporting servers</div><div class="dkpi-s">telemetry live</div></div>';
    echo '<div class="dkpi"><div class="dkpi-ic" style="background:rgba(124,92,255,.14);color:#7c5cff">'.$sI('<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>').'</div><div class="dkpi-n">'.$trials.'</div><div class="dkpi-l">Trials</div><div class="dkpi-s">free plan</div></div>';
    echo '</div>';

    echo '<div class="dgrid">';
    echo '<div class="card"><div class="dch"><h2>Recent activity</h2><a class="btn btn-ghost" href="/logs">View all &rarr;</a></div>';
    if (!$logs) echo '<p style="color:var(--sm-faint,#94a3b8);margin:8px 0 0">No activity yet.</p>';
    foreach ($logs as $l) {
        $res = (string)$l['result'];
        $okk = in_array($res, ['ok','active','valid','done','paired'], true);
        $err = in_array($res, ['fail','invalid','expired','suspended','binding_mismatch','bad_request','tampered','tamper','miss','blocked','clone_suspected','revoke'], true);
        $col = $okk ? '#1f9d55' : ($err ? '#e2574c' : 'var(--sm-accent)');
        $bbg = $okk ? 'rgba(31,157,85,.15)' : ($err ? 'rgba(226,87,76,.15)' : 'var(--sm-accent-soft)');
        $tgt = trim((string)($l['hostname'] ?? '')) ?: (trim((string)($l['license_key'] ?? '')) ?: (string)($l['server_ip'] ?? ''));
        $act = ucfirst(str_replace('_',' ', (string)$l['action']));
        echo '<div class="drow"><span class="dsd" style="background:'.$col.'"></span>'
           . '<span class="drico" style="color:'.$col.'">'.$aico((string)$l['action']).'</span>'
           . '<div class="drb"><div class="dract">'.h($act).'</div><div class="drtgt">'.h($tgt!==''?$tgt:'—').'</div></div>'
           . '<span class="dbdg" style="background:'.$bbg.';color:'.$col.'">'.h(mb_substr($res,0,14)).'</span>'
           . '<span class="drtime" title="'.h($l['created_at']).'">'.$ago($l['created_at']).'</span></div>';
    }
    echo '</div>';

    echo '<div style="display:flex;flex-direction:column;gap:13px">';
    echo '<div class="card"><div class="dch"><h2>Licenses by status</h2></div>';
    $bar = fn($label,$n,$color) => '<div class="dst"><div class="dstl"><span class="dleg" style="background:'.$color.'"></span>'.$label.'</div><div class="dstv"><b>'.$n.'</b> &middot; '.$pctTot($n).'%</div></div><div class="dbar"><div class="dbf" style="width:'.max(2,$pctTot($n)).'%;background:'.$color.'"></div></div>';
    echo $bar('Active',$stats['active'],'#1f9d55').$bar('Expired',$stats['expired'],'#d3920f').$bar('New',$stats['new'],'#6979f8').$bar('Suspended',$stats['suspended'],'#e2574c');
    echo '</div>';
    if ($byprod) {
        echo '<div class="card"><div class="dch"><h2>By product</h2></div>';
        foreach ($byprod as $pc => $c) {
            $isMail = stripos((string)$pc,'mail')!==false;
            $isSafe = stripos((string)$pc,'safety')!==false;
            $pi  = $isMail ? '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="m3 7 9 6 9-6"/>' : '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>';
            $pbg = $isMail ? 'rgba(31,157,85,.14)' : 'var(--sm-accent-soft)';
            $pfg = $isMail ? '#1f9d55' : 'var(--sm-accent)';
            $sub = $isMail ? 'Mail security suite' : ($isSafe ? 'WHM protection plugin' : 'Licenses');
            echo '<div class="dpr"><div class="dpic" style="background:'.$pbg.';color:'.$pfg.'">'.$sI($pi).'</div><div class="dpb"><div class="dpn">'.h($prodName($pc)).'</div><div class="dps">'.h($sub).'</div></div><div class="dpc">'.$c.'</div></div>';
        }
        echo '</div>';
    }
    echo '</div></div>';

    echo '<style>'
       . '.dhead{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;margin-bottom:18px;flex-wrap:wrap}'
       . '.dhead .dt{font-size:21px;font-weight:800;letter-spacing:-.3px;color:var(--sm-text,#0f1b33)}'
       . '.dhead .ds{font-size:12.5px;color:var(--sm-muted,#6b7686);margin-top:3px}'
       . '.dhead .da{display:flex;gap:8px;flex-wrap:wrap}'
       . '.dkpis{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:16px}'
       . '@media(max-width:900px){.dkpis{grid-template-columns:repeat(2,1fr)}}'
       . '.dkpi{background:var(--sm-surface,#fff);border:1px solid var(--sm-line,#e8ecf3);border-radius:14px;padding:15px;transition:box-shadow .12s}'
       . '.dkpi:hover{box-shadow:0 6px 18px rgba(15,23,42,.07)}'
       . '.dkpi-ic{width:34px;height:34px;border-radius:10px;display:flex;align-items:center;justify-content:center;margin-bottom:11px}'
       . '.dkpi-n{font-size:27px;font-weight:800;letter-spacing:-.6px;line-height:1;color:var(--sm-text,#0f1b33)}'
       . '.dkpi-l{font-size:12px;color:var(--sm-muted,#6b7686);margin-top:5px;font-weight:600}'
       . '.dkpi-s{font-size:11px;color:var(--sm-faint,#94a3b8);margin-top:7px}'
       . '.dgrid{display:grid;grid-template-columns:1.55fr 1fr;gap:13px;align-items:start}@media(max-width:900px){.dgrid{grid-template-columns:1fr}}'
       . '.dch{display:flex;align-items:center;justify-content:space-between;margin-bottom:8px}'
       . '.dch h2{margin:0;font-size:15px;font-weight:800;color:var(--sm-text,#0f1b33)}'
       . '.drow{display:flex;align-items:center;gap:11px;padding:9px 0;border-bottom:1px solid var(--sm-line,#f1f4f9)}.drow:last-child{border-bottom:0}'
       . '.dsd{width:8px;height:8px;border-radius:50%;flex:none}'
       . '.drico{width:28px;height:28px;border-radius:8px;background:var(--sm-surface2,#f7f9fc);display:flex;align-items:center;justify-content:center;flex:none}'
       . '.drb{flex:1;min-width:0}.dract{font-size:12.5px;font-weight:600;color:var(--sm-text,#1f2733)}'
       . '.drtgt{font-size:11px;color:var(--sm-faint,#94a3b8);font-family:ui-monospace,Menlo,Consolas,monospace;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}'
       . '.dbdg{font-size:10px;font-weight:700;padding:2.5px 8px;border-radius:20px;white-space:nowrap;flex:none}'
       . '.drtime{font-size:11px;color:var(--sm-faint,#94a3b8);width:32px;text-align:right;flex:none;font-variant-numeric:tabular-nums}'
       . '.dst{display:flex;align-items:center;justify-content:space-between;font-size:12px;margin-bottom:6px;margin-top:12px}'
       . '.dstl{display:flex;align-items:center;gap:7px;font-weight:600;color:var(--sm-text,#334155)}'
       . '.dleg{width:9px;height:9px;border-radius:3px}'
       . '.dstv{color:var(--sm-muted,#64748b);font-variant-numeric:tabular-nums}.dstv b{color:var(--sm-text,#0f1b33)}'
       . '.dbar{height:8px;border-radius:6px;background:var(--sm-surface2,#eef1f6);overflow:hidden}.dbf{height:100%;border-radius:6px}'
       . '.dpr{display:flex;align-items:center;gap:11px;padding:10px 0;border-bottom:1px solid var(--sm-line,#f1f4f9)}.dpr:last-child{border-bottom:0}'
       . '.dpic{width:32px;height:32px;border-radius:9px;display:flex;align-items:center;justify-content:center;flex:none}'
       . '.dpb{flex:1;min-width:0}.dpn{font-size:12.5px;font-weight:700;color:var(--sm-text,#0f1b33)}.dps{font-size:11px;color:var(--sm-faint,#94a3b8)}'
       . '.dpc{margin-left:auto;font-size:18px;font-weight:800;color:var(--sm-text,#0f1b33);font-variant-numeric:tabular-nums}'
       . '</style>';
    layout_end();
}

function page_licenses(): void {
    require_admin();

    // ---- filters (server-side, parameterized) ----
    $fProduct = trim((string)($_GET['product'] ?? ''));
    $fStatus  = trim((string)($_GET['status'] ?? ''));
    $fPlan    = trim((string)($_GET['plan'] ?? ''));
    $q        = trim((string)($_GET['q'] ?? ''));
    $where = []; $types = ''; $args = [];
    if ($fProduct !== '' && $fProduct !== 'all') { $where[] = 'l.product_code = ?'; $types .= 's'; $args[] = $fProduct; }
    if ($fStatus  !== '' && $fStatus  !== 'all') { $where[] = 'l.status = ?';       $types .= 's'; $args[] = $fStatus; }
    if ($fPlan    !== '' && $fPlan    !== 'all') { $where[] = 'l.plan = ?';         $types .= 's'; $args[] = $fPlan; }
    if ($q !== '') { $where[] = '(l.license_key LIKE ? OR l.client_name LIKE ? OR l.client_email LIKE ? OR l.bound_hostname LIKE ?)'; $types .= 'ssss'; $like = '%' . $q . '%'; array_push($args, $like, $like, $like, $like); }
    $wsql = $where ? (' WHERE ' . implode(' AND ', $where)) : '';

    // ---- sorting (column whitelist → no injection) ----
    $sortable = ['id'=>'l.id','client'=>'l.client_name','status'=>'l.status','plan'=>'l.plan','product'=>'l.product_code','expires'=>'l.expires_at','created'=>'l.created_at'];
    $sort = (string)($_GET['sort'] ?? 'id'); if (!isset($sortable[$sort])) $sort = 'id';
    $dir  = strtolower((string)($_GET['dir'] ?? 'desc')) === 'asc' ? 'ASC' : 'DESC';
    $orderby = ' ORDER BY ' . $sortable[$sort] . ' ' . $dir;

    $sql = "SELECT l.*, (SELECT COUNT(*) FROM license_logs g WHERE g.license_key=l.license_key AND g.action='download' AND g.result='ok') AS download_count FROM licenses l" . $wsql . $orderby . " LIMIT 500";
    $rows = [];
    if ($st = db()->prepare($sql)) { if ($types !== '') $st->bind_param($types, ...$args); $st->execute(); $rows = $st->get_result()->fetch_all(MYSQLI_ASSOC); }

    // distinct products + plans for the dropdowns
    $prods = []; if ($pr = db()->query("SELECT DISTINCT product_code FROM licenses WHERE product_code IS NOT NULL AND product_code<>'' ORDER BY product_code")) while ($x = $pr->fetch_row()) $prods[] = (string)$x[0];
    $plansF = []; if ($pl = db()->query("SELECT DISTINCT plan FROM licenses WHERE plan IS NOT NULL AND plan<>'' ORDER BY plan")) while ($x = $pl->fetch_row()) $plansF[] = (string)$x[0];
    $prodName = function ($pc) { $pc = (string)$pc; if ($pc === '') return '-'; if (stripos($pc, 'safety') !== false) return 'Safety Monitor Pro'; if (stripos($pc, 'mail') !== false) return 'MailShield OSM Pro'; return $pc; };

    // querystring preserving filters/sort, overriding given keys
    $qs = function (array $over = []) use ($fProduct, $fStatus, $fPlan, $q, $sort, $dir) {
        $p = array_merge(['product'=>$fProduct,'status'=>$fStatus,'plan'=>$fPlan,'q'=>$q,'sort'=>$sort,'dir'=>strtolower($dir)], $over);
        return '/licenses?' . http_build_query(array_filter($p, fn($v) => $v !== '' && $v !== 'all'));
    };
    $sh = function ($key, $label) use ($sort, $dir, $qs) { $nd = ($sort === $key && $dir === 'ASC') ? 'desc' : 'asc'; $ar = $sort === $key ? ($dir === 'ASC' ? ' &#9650;' : ' &#9660;') : ''; return '<th><a href="' . h($qs(['sort'=>$key,'dir'=>$nd])) . '" style="color:inherit;text-decoration:none">' . h($label) . $ar . '</a></th>'; };
    $optsel = fn($v, $cur) => ($v === $cur ? ' selected' : '');

    // accurate status counts (unfiltered totals) for the stat chips
    $cnt = ['total'=>0,'new'=>0,'active'=>0,'suspended'=>0,'expired'=>0];
    if ($cr = db()->query("SELECT status, COUNT(*) c FROM licenses GROUP BY status")) while ($x = $cr->fetch_assoc()) { $s = (string)$x['status']; $c = (int)$x['c']; $cnt['total'] += $c; if (isset($cnt[$s])) $cnt[$s] = $c; }
    // batched latest pairing state per license (ONE query → a status dot per row, no N+1)
    $pairMap = [];
    if ($pmr = db()->query("SELECT t.license_key, t.result FROM license_logs t INNER JOIN (SELECT license_key, MAX(id) mid FROM license_logs WHERE action='pair' AND result IN ('ok','miss','bootstrap','nobeacon') GROUP BY license_key) m ON t.id=m.mid")) while ($x = $pmr->fetch_assoc()) $pairMap[(string)$x['license_key']] = (string)$x['result'];

    layout_start('Licenses');
    echo '<div class="card">';
    echo '<div style="display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:14px"><h2 style="margin:0">Licenses</h2><a class="btn" href="/licenses/new">&#43; Create license</a></div>';
    echo '<div class="lic-stats">'
       . '<div class="lic-stat"><div class="n">' . $cnt['total'] . '</div><div class="l">Total</div></div>'
       . '<div class="lic-stat"><div class="n" style="color:#1f9d55">' . $cnt['active'] . '</div><div class="l">Active</div></div>'
       . '<div class="lic-stat"><div class="n" style="color:#d93b3b">' . $cnt['suspended'] . '</div><div class="l">Suspended</div></div>'
       . '<div class="lic-stat"><div class="n" style="color:#c47f17">' . $cnt['expired'] . '</div><div class="l">Expired</div></div>'
       . '<div class="lic-stat"><div class="n" style="color:#6b7686">' . $cnt['new'] . '</div><div class="l">New</div></div></div>';
    echo '<form method="get" action="/licenses" class="lic-toolbar">';
    echo '<select name="product"><option value="all">Product: all</option>';
    foreach ($prods as $pc) echo '<option value="' . h($pc) . '"' . $optsel($pc, $fProduct) . '>' . h($prodName($pc)) . '</option>';
    echo '</select>';
    echo '<select name="status"><option value="all">Status: all</option>';
    foreach (['new','active','suspended','expired'] as $sv) echo '<option value="' . $sv . '"' . $optsel($sv, $fStatus) . '>' . ucfirst($sv) . '</option>';
    echo '</select>';
    echo '<select name="plan"><option value="all">Plan: all</option>';
    foreach ($plansF as $pv) echo '<option value="' . h($pv) . '"' . $optsel($pv, $fPlan) . '>' . h($pv) . '</option>';
    echo '</select>';
    echo '<input name="q" value="' . h($q) . '" placeholder="Search key / client / email / host">';
    echo '<input type="hidden" name="sort" value="' . h($sort) . '"><input type="hidden" name="dir" value="' . h(strtolower($dir)) . '">';
    echo '<button type="submit">&#128269; Filter</button> <a class="btn btn-ghost" href="/licenses">Reset</a>';
    echo '</form>';
    echo '<p style="color:#94a3b8;font-size:11.5px;margin:0 2px 10px"><b>' . count($rows) . '</b> shown' . ($wsql ? ' (filtered)' : '') . (count($rows) >= 500 ? ' — first 500; narrow the filter' : '') . ' &middot; <span style="color:#1f9d55">&#9679;</span> paired &nbsp;<span style="color:#d97706">&#9679;</span> miss &nbsp;<span style="color:#cbd5e1">&#9679;</span> none</p>';
    echo '<table>';
    echo '<tr>' . $sh('id', 'ID') . '<th>License</th>' . $sh('client', 'Client') . $sh('product', 'Product') . $sh('plan', 'Plan') . $sh('status', 'Status') . '<th>Bound IP</th>' . $sh('expires', 'Expires') . '<th>DL</th><th style="text-align:right">Actions</th></tr>';

    foreach ($rows as $r) {
        $pst = $pairMap[(string)$r['license_key']] ?? '';
        $dotc = $pst === 'ok' ? 'ok' : ($pst === 'miss' ? 'miss' : 'none');
        $pcode = (string)($r['product_code'] ?? '');
        $chipAlt = (stripos($pcode, 'mail') !== false) ? ' alt' : '';
        echo '<tr>';
        echo '<td>' . (int)$r['id'] . '</td>';
        echo '<td><span class="pdot ' . $dotc . '" title="pairing: ' . h($pst ?: 'none') . '"></span><code class="copykey" style="cursor:pointer" title="Click to copy">' . h($r['license_key']) . '</code></td>';
        echo '<td>' . h($r['client_name'] ?: '-') . ($r['client_email'] ? '<br><small>' . h($r['client_email']) . '</small>' : '') . '</td>';
        echo '<td><span class="chip' . $chipAlt . '" title="' . h($pcode) . '">' . h($prodName($pcode)) . '</span></td>';
        echo '<td>' . h($r['plan'] ?: '-') . '</td>';
        echo '<td><span class="badge ' . h($r['status']) . '">' . h($r['status']) . '</span></td>';
        echo '<td>' . h($r['bound_ip'] ?: '-') . '</td>';
        echo '<td>' . h($r['expires_at'] ? substr((string)$r['expires_at'], 0, 10) : '-') . '</td>';
        $dlc = (int)($r['download_count'] ?? 0);
        echo '<td>' . $dlc . '/1' . ($dlc >= 1 ? ' <span class="badge suspended">used</span>' : '') . '</td>';
        echo '<td style="text-align:right;white-space:nowrap">';
        echo '<a class="btn" href="/licenses/edit?id=' . (int)$r['id'] . '">Edit</a> ';
        echo '<span class="rowmenu"><span class="dots" title="More actions">&#8943;</span><div class="menu">';
        echo '<form method="post" action="/licenses/action"><input type="hidden" name="csrf" value="' . h(csrf_token()) . '"><input type="hidden" name="id" value="' . (int)$r['id'] . '">';
        echo '<button name="do" value="activate">&#10003; Activate</button>';
        echo '<button name="do" value="suspend">&#9209; Suspend</button>';
        echo '<button name="do" value="reset">&#8635; Reset IP binding</button>';
        echo '<button name="do" value="reset_download" onclick="return confirm(\'Allow this license to be downloaded again?\')">&#11015; Reset download</button>';
        echo '<button name="do" value="notify" onclick="return confirm(\'Send the license + install to the customer now?\')">&#9993; Resend to customer</button>';
        echo '<hr>';
        echo '<button name="do" value="delete" class="danger" onclick="return confirm(\'Delete license? This cannot be undone.\')">&#128465; Delete</button>';
        echo '</form></div></span>';
        echo '</td></tr>';
    }

    echo '</table></div>';
    layout_end();
}

function page_license_create(): void {
    require_admin();

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        require_csrf();

        $key = strtoupper(trim((string)($_POST['license_key'] ?? '')));
        if ($key === '') $key = license_key_generate();

        $clientName = trim((string)($_POST['client_name'] ?? ''));
        $clientEmail = trim((string)($_POST['client_email'] ?? ''));
        $plan = in_array($_POST['plan'] ?? 'pro', ['basic','pro','enterprise'], true) ? $_POST['plan'] : 'pro';
        $status = in_array($_POST['status'] ?? 'new', ['new','active','suspended','expired'], true) ? $_POST['status'] : 'new';
        $expiresAt = trim((string)($_POST['expires_at'] ?? ''));
        $notes = trim((string)($_POST['notes'] ?? ''));

        $features = $_POST['features'] ?? [];
        if (!is_array($features)) $features = [];
        $features = array_values(array_intersect($features, ['scan','reports','telegram','cleanup','smart_engine','multi_server']));
        $featuresJson = json_encode($features, JSON_UNESCAPED_UNICODE);

        $stmt = db()->prepare("
            INSERT INTO licenses
            (license_key, client_name, client_email, status, plan, features, expires_at, notes)
            VALUES (?, ?, ?, ?, ?, ?, NULLIF(?, ''), ?)
        ");
        $stmt->bind_param('ssssssss', $key, $clientName, $clientEmail, $status, $plan, $featuresJson, $expiresAt, $notes);
        $stmt->execute();

        redirect('/licenses');
    }

    $generated = license_key_generate();

    layout_start('Create License');
    echo '<div class="card"><h2>Create License</h2>';
    echo '<form method="post">';
    echo '<input type="hidden" name="csrf" value="' . h(csrf_token()) . '">';
    echo '<div class="form-grid">';
    echo '<p><label>License Key</label><input name="license_key" value="' . h($generated) . '"></p>';
    echo '<p><label>Client Name</label><input name="client_name"></p>';
    echo '<p><label>Client Email</label><input name="client_email" type="email"></p>';
    echo '<p><label>Expires At</label><input name="expires_at" type="datetime-local"></p>';
    echo '<p><label>Plan</label><select name="plan"><option>basic</option><option selected>pro</option><option>enterprise</option></select></p>';
    echo '<p><label>Status</label><select name="status"><option selected>new</option><option>active</option><option>suspended</option><option>expired</option></select></p>';
    echo '</div>';
    echo '<div class="card"><b>Features</b><br>';
    foreach (['scan','reports','telegram','cleanup','smart_engine','multi_server'] as $f) {
        $checked = in_array($f, ['scan','reports','telegram','cleanup','smart_engine'], true) ? 'checked' : '';
        echo '<label style="display:inline-flex;gap:6px;margin:8px 12px 0 0"><input type="checkbox" name="features[]" value="' . h($f) . '" ' . $checked . '> ' . h($f) . '</label>';
    }
    echo '</div>';
    echo '<p><label>Notes</label><textarea name="notes" rows="4"></textarea></p>';
    echo '<button type="submit">Create License</button>';
    echo '</form></div>';
    layout_end();
}

function page_license_action(): void {
    require_admin();
    require_csrf();

    $id = (int)($_POST['id'] ?? 0);
    $do = (string)($_POST['do'] ?? '');

    if ($id <= 0) redirect('/licenses');

    if ($do === 'activate') {
        db()->query("UPDATE licenses SET status='active' WHERE id=$id");
    } elseif ($do === 'suspend') {
        db()->query("UPDATE licenses SET status='suspended' WHERE id=$id");
    } elseif ($do === 'reset') {
        db()->query("UPDATE licenses SET bound_ip=NULL, bound_hostname=NULL, bound_fingerprint=NULL, activated_at=NULL, status='new' WHERE id=$id");
    } elseif ($do === 'reset_download') {
        $kr = db()->query("SELECT license_key FROM licenses WHERE id=$id");
        $key = $kr ? (string)($kr->fetch_row()[0] ?? '') : '';
        if ($key !== '') {
            $st = db()->prepare("DELETE FROM license_logs WHERE license_key=? AND action='download' AND result='ok'");
            $st->bind_param('s', $key); $st->execute();
            log_event($key, 'reset_download', 'ok', 'Admin reset the single-download allowance', []);
        }
    } elseif ($do === 'delete') {
        db()->query("DELETE FROM licenses WHERE id=$id");
    } elseif ($do === 'notify') {
        // resend the license key + install command to the customer (email +WhatsApp) — reuses the create-time delivery
        if (function_exists('smlic_deliver_license')) {
            $lr = db()->query("SELECT * FROM licenses WHERE id=$id");
            $lic = $lr ? $lr->fetch_assoc() : null;
            if (is_array($lic)) { $sum = ''; smlic_deliver_license($lic, $sum); }
        }
    }

    redirect('/licenses');
}

function page_logs(): void {
    require_admin();

    $rows = db()->query("SELECT * FROM license_logs ORDER BY id DESC LIMIT 1000")->fetch_all(MYSQLI_ASSOC);

    layout_start('Logs');
    echo '<div class="card"><h2>License Logs</h2><table>';
    echo '<tr><th>Date</th><th>License</th><th>Action</th><th>Result</th><th>Request IP</th><th>Server IP</th><th>Hostname</th><th>Fingerprint</th><th>Message</th></tr>';
    foreach ($rows as $r) {
        echo '<tr>';
        echo '<td>' . h($r['created_at']) . '</td>';
        echo '<td>' . h($r['license_key']) . '</td>';
        echo '<td>' . h($r['action']) . '</td>';
        echo '<td>' . h($r['result']) . '</td>';
        echo '<td>' . h($r['request_ip']) . '</td>';
        echo '<td>' . h($r['server_ip']) . '</td>';
        echo '<td>' . h($r['hostname']) . '</td>';
        echo '<td><small>' . h($r['fingerprint']) . '</small></td>';
        echo '<td>' . h($r['message']) . '</td>';
        echo '</tr>';
    }
    echo '</table></div>';
    layout_end();
}


/* AITECH_LICENSE_SERVER_V2_MULTI_PRODUCT_API */

function normalize_product_code_v2(string $product): string {
    $product = strtolower(trim($product));
    return preg_match('/^[a-z0-9_:-]{2,40}$/', $product) ? $product : '';
}

function normalize_edition_v2(string $edition): string {
    $edition = strtolower(trim($edition));
    return in_array($edition, ['free','basic','pro','enterprise','ultimate'], true) ? $edition : '';
}

function license_product_v2(array $lic): string {
    $p = normalize_product_code_v2((string)($lic['product_code'] ?? ''));
    return $p !== '' ? $p : 'guirkhunter';
}

function license_edition_v2(array $lic): string {
    $e = normalize_edition_v2((string)($lic['edition'] ?? ''));
    if ($e !== '') return $e;

    $plan = strtolower((string)($lic['plan'] ?? 'pro'));
    return normalize_edition_v2($plan) ?: 'pro';
}

function default_features_v2(string $product, string $edition): array {
    $product = normalize_product_code_v2($product) ?: 'guirkhunter';
    $edition = normalize_edition_v2($edition) ?: 'pro';

    if ($product === 'safety_monitor') {
        $free = [
            'dashboard',
            'service_health',
            'load_monitor',
            'top_processes',
            'firewall_status',
            'login_monitor',
            'disk_monitor',
            'email_queue_summary',
            'license',
        ];

        $pro = array_values(array_unique(array_merge($free, [
            'advanced_load_monitor',
            'user_abuse_monitor',
            'process_scanner',
            'email_queue_monitor',
            'web_attack_monitor',
            'suspicious_files',
            'htaccess_watcher',
            'suspended_accounts',
            'telegram_alerts',
            'optional_actions',
        ])));

        $enterprise = array_values(array_unique(array_merge($pro, [
            'automation_rules',
            'attack_timeline',
            'ssl_monitor',
            'risk_score_engine',
            'ai_incident_summary',
        ])));

        $ultimate = array_values(array_unique(array_merge($enterprise, [
            'multi_server_fleet',
            'central_command',
            'cloudflare_sync',
            'fleet_analytics',
            'executive_reports',
        ])));

        return match ($edition) {
            'free', 'basic' => $free,
            'pro' => $pro,
            'enterprise' => $enterprise,
            'ultimate' => $ultimate,
            default => $pro,
        };
    }

    // Backward-compatible GUI RKHunter features.
    return match ($edition) {
        'basic', 'free' => ['scan', 'reports'],
        'enterprise', 'ultimate' => ['scan', 'reports', 'telegram', 'cleanup', 'smart_engine', 'multi_server'],
        default => ['scan', 'reports', 'telegram', 'cleanup', 'smart_engine'],
    };
}

function feature_list_v2(string $product, string $edition, ?string $featuresJson): array {
    if ($featuresJson) {
        $decoded = json_decode($featuresJson, true);
        if (is_array($decoded)) {
            if (array_is_list($decoded)) {
                return array_values(array_unique(array_map('strval', $decoded)));
            }

            if (isset($decoded[$product]) && is_array($decoded[$product])) {
                return array_values(array_unique(array_map('strval', $decoded[$product])));
            }

            if (isset($decoded['features']) && is_array($decoded['features'])) {
                return array_values(array_unique(array_map('strval', $decoded['features'])));
            }
        }
    }

    return default_features_v2($product, $edition);
}

function action_required_feature_v2(string $product, string $action): string {
    $product = normalize_product_code_v2($product) ?: 'guirkhunter';
    $action = normalize_action_name($action);

    if ($product === 'safety_monitor') {
        $map = [
            'dashboard' => 'dashboard',
            'service_health' => 'service_health',
            'load_monitor' => 'load_monitor',
            'advanced_load_monitor' => 'advanced_load_monitor',
            'top_processes' => 'top_processes',
            'top_users' => 'user_abuse_monitor',
            'user_abuse' => 'user_abuse_monitor',
            'process_scanner' => 'process_scanner',
            'firewall_status' => 'firewall_status',
            'login_monitor' => 'login_monitor',
            'email_queue' => 'email_queue_monitor',
            'email_queue_summary' => 'email_queue_summary',
            'web_attack_monitor' => 'web_attack_monitor',
            'suspicious_files' => 'suspicious_files',
            'htaccess_watcher' => 'htaccess_watcher',
            'suspended_accounts' => 'suspended_accounts',
            'telegram_alerts' => 'telegram_alerts',
            'save_telegram' => 'telegram_alerts',
            'test_alert' => 'telegram_alerts',
            'disk_monitor' => 'disk_monitor',
            'ssl_monitor' => 'ssl_monitor',
            'attack_timeline' => 'attack_timeline',
            'automation_rules' => 'automation_rules',
            'ai_incident_summary' => 'ai_incident_summary',
            'risk_score' => 'risk_score_engine',
            'multi_server_fleet' => 'multi_server_fleet',
            'central_command' => 'central_command',
            'cloudflare_sync' => 'cloudflare_sync',

            // Optional response actions.
            'kill_abusive_process' => 'optional_actions',
            'kill_process' => 'optional_actions',
            'restart_failed_service' => 'optional_actions',
            'restart_service' => 'optional_actions',
            'temporary_block_ip' => 'optional_actions',
            'block_ip' => 'optional_actions',
            'delete_suspicious_uploaded_file' => 'suspicious_files',
            'delete_suspicious_file' => 'suspicious_files',
            'quarantine_suspicious_uploaded_file' => 'suspicious_files',
            'quarantine_suspicious_file' => 'suspicious_files',
        ];

        return $map[$action] ?? $action;
    }

    return action_required_feature($action);
}

function license_payload_v2(array $lic, string $product, string $serverIp, string $hostname, string $fingerprint): array {
    $edition = license_edition_v2($lic);
    $features = resolve_features($lic);
    $pairSecret = smlic_pair_secret($lic);   // Stage 0: ensure/generate the per-license base secret S (server-only)

    return [
        'product' => $product,
        'product_code' => $product,
        'license_key' => $lic['license_key'],
        'status' => $lic['status'],
        'plan' => $lic['plan'],
        'edition' => $edition,
        'features' => $features,
        'max_servers' => (int)($lic['max_servers'] ?? 1),
        'bound_ip' => $lic['bound_ip'],
        'bound_hostname' => $lic['bound_hostname'],
        'fingerprint' => $lic['bound_fingerprint'],
        'request_server_ip' => $serverIp,
        'request_hostname' => $hostname,
        'request_fingerprint' => $fingerprint,
        'expires_at' => $lic['expires_at'],
        'issued_at' => date('c'),
        'next_check_after' => date('c', time() + 21600),
        'grace_hours' => (int)envv('DEFAULT_GRACE_HOURS', '72'),
        // ── connection-loss escalation directives (SIGNED; client trusts only these) ──
        'sync_enabled' => (int)($lic['sync_enabled'] ?? 0) === 1,                              // opt this license into the escalation ladder
        'sync_purge'   => (int)($lic['sync_purge'] ?? 0) === 1,                                // suspected-pirate: allow 48h-silence delete
        'sync_stop'    => in_array(($lic['directive'] ?? 'normal'), ['normal', 'hold', 'permstop'], true) ? ($lic['directive'] ?? 'normal') : 'normal',
        // server-gated VALUE: a per-license secret (HMAC under the server's offline private key, bound to the
        // fingerprint) delivered ONLY inside this RSA-signed verdict for a valid license. Features can encrypt
        // their server-delivered data with it — a patched-gate pirate without a valid verdict can't derive it.
        'feat_key'     => smlic_feat_key((string)$lic['license_key'], (string)($lic['bound_fingerprint'] ?? '')),
        // PAIR (Stage 0, INERT): derived pairing key K delivered to the plugin (raw S never sent) + a public pair_id.
        'pair_key'     => smlic_pair_key((string)$lic['license_key'], $pairSecret),
        'pair_id'      => smlic_pair_id($pairSecret),
        // NOTE: NO pair_stop here — the v2 path never runs smlic_pair_verify, so it could neither set nor SELF-HEAL the
        // flag (review minor). Pairing enforcement is v1/SM-only; v2 clients are pairing-exempt.
    ];
}

function api_license_check_v2(): never {
    $data = json_input();

    $licenseKey = strtoupper(trim((string)($data['license_key'] ?? '')));
    $product = normalize_product_code_v2((string)($data['product_code'] ?? $data['product'] ?? 'guirkhunter'));
    $serverIp = normalize_ip((string)($data['server_ip'] ?? request_ip()));
    $hostname = substr(trim((string)($data['hostname'] ?? '')), 0, 255);
    $fingerprint = normalize_fingerprint((string)($data['fingerprint'] ?? ''));
    $pluginVersion = substr(trim((string)($data['plugin_version'] ?? '')), 0, 40);

    $ctx = [
        'server_ip' => $serverIp,
        'hostname' => $hostname,
        'fingerprint' => $fingerprint,
        'plugin_version' => $pluginVersion,
    ];

    if ($licenseKey === '' || $product === '' || $serverIp === '' || $fingerprint === '') {
        log_event($licenseKey ?: null, 'license-check', 'bad_request', 'license_key, product_code, server_ip and fingerprint are required', $ctx);
        json_response([
            'ok' => false,
            'status' => 'bad_request',
            'message' => 'license_key, product_code, server_ip and fingerprint are required',
        ], 400);
    }

    $lic = license_find($licenseKey);

    if (!$lic) {
        log_event($licenseKey, 'license-check', 'invalid', 'Invalid license key', $ctx);
        json_response(['ok' => false, 'status' => 'invalid', 'message' => 'Invalid license key'], 404);
    }

    $licenseProduct = license_product_v2($lic);
    if (!hash_equals($licenseProduct, $product)) {
        log_event($licenseKey, 'license-check', 'product_mismatch', 'License product mismatch', $ctx);
        json_response([
            'ok' => false,
            'status' => 'product_mismatch',
            'message' => 'License is not valid for this product',
            'license_product' => $licenseProduct,
            'requested_product' => $product,
        ], 403);
    }

    $id = (int)$lic['id'];

    if (!empty($lic['tamper_status']) && $lic['tamper_status'] === 'blocked') {
        log_event($licenseKey, 'license-check', 'tampered', 'Plugin integrity was previously blocked', $ctx);
        json_response(['ok' => false, 'status' => 'tampered', 'message' => 'Plugin integrity was previously blocked. Contact support.'], 403);
    }

    if (license_expired($lic)) {
        db()->query("UPDATE licenses SET status='expired' WHERE id=" . $id);
        log_event($licenseKey, 'license-check', 'expired', 'License expired', $ctx);
        json_response(['ok' => false, 'status' => 'expired', 'message' => 'License expired'], 403);
    }

    if ($lic['status'] === 'suspended') {
        log_event($licenseKey, 'license-check', 'suspended', 'License suspended', $ctx);
        json_response(['ok' => false, 'status' => 'suspended', 'message' => 'License suspended'], 403);
    }

    $notBound = empty($lic['bound_ip']) && empty($lic['bound_fingerprint']);
    if ($notBound) {
        $stmt = db()->prepare("
            UPDATE licenses
            SET status='active',
                bound_ip=?,
                bound_hostname=?,
                bound_fingerprint=?,
                activated_at=COALESCE(activated_at, NOW()),
                last_check_at=NOW()
            WHERE id=?
        ");
        $stmt->bind_param('sssi', $serverIp, $hostname, $fingerprint, $id);
        $stmt->execute();
        $lic = license_find($licenseKey);
        log_event($licenseKey, 'license-check', 'activated', 'License activated and bound', $ctx);
    }

    if ($lic['status'] === 'new') {
        log_event($licenseKey, 'license-check', 'not_activated', 'License is not activated yet', $ctx);
        json_response(['ok' => false, 'status' => 'not_activated', 'message' => 'License not activated'], 403);
    }

    $ipMatches = hash_equals((string)$lic['bound_ip'], $serverIp);
    $fpMatches = hash_equals((string)$lic['bound_fingerprint'], $fingerprint);

    if (!$ipMatches || !$fpMatches) {
        log_event($licenseKey, 'license-check', 'binding_mismatch', 'IP or fingerprint mismatch', $ctx);
        json_response([
            'ok' => false,
            'status' => 'binding_mismatch',
            'message' => 'License is already bound to another server. Contact support.',
            'bound_ip' => $lic['bound_ip'],
        ], 403);
    }

    $stmt = db()->prepare("UPDATE licenses SET last_check_at=NOW() WHERE id=?");
    $stmt->bind_param('i', $id);
    $stmt->execute();

    $lic = license_find($licenseKey);
    $payload = license_payload_v2($lic, $product, $serverIp, $hostname, $fingerprint);
    $signed = sign_payload($payload);

    log_event($licenseKey, 'license-check', 'ok', 'License valid', $ctx);

    json_response([
        'ok' => true,
        'status' => 'active',
        'product_code' => $product,
        'edition' => $payload['edition'],
        'features' => $payload['features'],
        'license' => $signed,
    ]);
}

function api_action_check_v2(): never {
    $data = json_input();

    $licenseKey = strtoupper(trim((string)($data['license_key'] ?? '')));
    $product = normalize_product_code_v2((string)($data['product_code'] ?? $data['product'] ?? 'guirkhunter'));
    $serverIp = normalize_ip((string)($data['server_ip'] ?? request_ip()));
    $hostname = substr(trim((string)($data['hostname'] ?? '')), 0, 255);
    $fingerprint = normalize_fingerprint((string)($data['fingerprint'] ?? ''));
    $pluginVersion = substr(trim((string)($data['plugin_version'] ?? '')), 0, 40);
    $action = normalize_action_name((string)($data['action'] ?? ''));
    $integrityHash = normalize_integrity_hash((string)($data['integrity_hash'] ?? ''));

    $ctx = [
        'server_ip' => $serverIp,
        'hostname' => $hostname,
        'fingerprint' => $fingerprint,
        'plugin_version' => $pluginVersion,
    ];

    if ($licenseKey === '' || $product === '' || $serverIp === '' || $fingerprint === '' || $action === '') {
        action_check_fail($licenseKey, $action, 'bad_request', 'license_key, product_code, server_ip, fingerprint and action are required', $ctx, 400);
    }

    $lic = license_find($licenseKey);

    if (!$lic) {
        action_check_fail($licenseKey, $action, 'invalid', 'Invalid license key', $ctx, 404);
    }

    $licenseProduct = license_product_v2($lic);
    if (!hash_equals($licenseProduct, $product)) {
        action_check_fail($licenseKey, $action, 'product_mismatch', 'License is not valid for this product', $ctx, 403);
    }

    $id = (int)$lic['id'];

    if (!empty($lic['tamper_status']) && $lic['tamper_status'] === 'blocked') {
        action_check_fail($licenseKey, $action, 'tampered', 'Plugin integrity was previously blocked. Contact support.', $ctx, 403);
    }

    if (license_expired($lic)) {
        db()->query("UPDATE licenses SET status='expired' WHERE id=" . $id);
        action_check_fail($licenseKey, $action, 'expired', 'License expired', $ctx, 403);
    }

    if ($lic['status'] === 'suspended') {
        action_check_fail($licenseKey, $action, 'suspended', 'License suspended', $ctx, 403);
    }

    if ($lic['status'] === 'new') {
        action_check_fail($licenseKey, $action, 'not_activated', 'License not activated', $ctx, 403);
    }

    $ipMatches = hash_equals((string)$lic['bound_ip'], $serverIp);
    $fpMatches = hash_equals((string)$lic['bound_fingerprint'], $fingerprint);

    if (!$ipMatches || !$fpMatches) {
        action_check_fail($licenseKey, $action, 'binding_mismatch', 'IP or fingerprint mismatch. Contact support.', $ctx, 403);
    }

    if ($integrityHash === '') {
        action_check_fail($licenseKey, $action, 'missing_integrity', 'Missing plugin integrity hash', $ctx, 403);
    }

    if (empty($lic['expected_integrity_hash'])) {
        license_set_expected_integrity($id, $integrityHash);
        $lic['expected_integrity_hash'] = $integrityHash;
        log_event($licenseKey, 'integrity-register', 'ok', 'Initial integrity hash registered', $ctx);
    }

    if (!hash_equals((string)$lic['expected_integrity_hash'], $integrityHash)) {
        license_update_tamper($id, 'blocked');
        action_check_fail($licenseKey, $action, 'tampered', 'Plugin integrity hash mismatch. Plugin locked.', $ctx, 403);
    }

    $edition = license_edition_v2($lic);
    $features = resolve_features($lic);
    $requiredFeature = action_required_feature_v2($product, $action);

    if (!in_array($requiredFeature, $features, true)) {
        action_check_fail($licenseKey, $action, 'feature_denied', 'This action requires feature: ' . $requiredFeature, $ctx, 403);
    }

    $stmt = db()->prepare("UPDATE licenses SET last_action_at=NOW(), last_check_at=NOW() WHERE id=?");
    $stmt->bind_param('i', $id);
    $stmt->execute();

    $payload = [
        'product' => $product,
        'product_code' => $product,
        'license_key' => $licenseKey,
        'edition' => $edition,
        'action' => $action,
        'required_feature' => $requiredFeature,
        'server_ip' => $serverIp,
        'hostname' => $hostname,
        'fingerprint' => $fingerprint,
        'integrity_hash' => $integrityHash,
        'plugin_version' => $pluginVersion,
        'allow' => true,
        'status' => 'active',
        'issued_at' => date('c'),
        'expires_at' => date('c', time() + 120),
        'nonce' => bin2hex(random_bytes(16)),
    ];

    $signed = sign_payload($payload);

    log_event($licenseKey, 'action-check:' . $action, 'ok', 'Action allowed', $ctx);

    json_response([
        'ok' => true,
        'allow' => true,
        'status' => 'active',
        'product_code' => $product,
        'edition' => $edition,
        'action' => $action,
        'required_feature' => $requiredFeature,
        'features' => $features,
        'action_token' => $signed,
        'message' => 'Action allowed',
    ]);
}

function api_heartbeat_v2(): never {
    $data = json_input();

    $licenseKey = strtoupper(trim((string)($data['license_key'] ?? '')));
    $product = normalize_product_code_v2((string)($data['product_code'] ?? $data['product'] ?? 'guirkhunter'));
    $serverIp = normalize_ip((string)($data['server_ip'] ?? request_ip()));
    $hostname = substr(trim((string)($data['hostname'] ?? '')), 0, 255);
    $fingerprint = normalize_fingerprint((string)($data['fingerprint'] ?? ''));

    $ctx = [
        'server_ip' => $serverIp,
        'hostname' => $hostname,
        'fingerprint' => $fingerprint,
    ];

    if ($licenseKey === '' || $product === '' || $serverIp === '' || $fingerprint === '') {
        log_event($licenseKey ?: null, 'heartbeat', 'bad_request', 'license_key, product_code, server_ip and fingerprint are required', $ctx);
        json_response(['ok' => false, 'status' => 'bad_request', 'message' => 'license_key, product_code, server_ip and fingerprint are required'], 400);
    }

    $lic = license_find($licenseKey);
    if (!$lic) {
        log_event($licenseKey, 'heartbeat', 'invalid', 'Invalid license key', $ctx);
        json_response(['ok' => false, 'status' => 'invalid', 'message' => 'Invalid license key'], 404);
    }

    $licenseProduct = license_product_v2($lic);
    if (!hash_equals($licenseProduct, $product)) {
        log_event($licenseKey, 'heartbeat', 'product_mismatch', 'License product mismatch', $ctx);
        json_response(['ok' => false, 'status' => 'product_mismatch', 'message' => 'License is not valid for this product'], 403);
    }

    if (license_expired($lic)) {
        db()->query("UPDATE licenses SET status='expired' WHERE id=" . (int)$lic['id']);
        log_event($licenseKey, 'heartbeat', 'expired', 'License expired', $ctx);
        json_response(['ok' => false, 'status' => 'expired', 'message' => 'License expired'], 403);
    }

    if ($lic['status'] !== 'active') {
        log_event($licenseKey, 'heartbeat', (string)$lic['status'], 'License is not active', $ctx);
        json_response(['ok' => false, 'status' => $lic['status'], 'message' => 'License is not active'], 403);
    }

    $ipMatches = hash_equals((string)$lic['bound_ip'], $serverIp);
    $fpMatches = hash_equals((string)$lic['bound_fingerprint'], $fingerprint);

    if (!$ipMatches || !$fpMatches) {
        log_event($licenseKey, 'heartbeat', 'binding_mismatch', 'IP or fingerprint mismatch', $ctx);
        json_response(['ok' => false, 'status' => 'binding_mismatch', 'message' => 'IP or fingerprint mismatch'], 403);
    }

    $stmt = db()->prepare("UPDATE licenses SET last_heartbeat_at=NOW(), last_check_at=NOW() WHERE id=?");
    $id = (int)$lic['id'];
    $stmt->bind_param('i', $id);
    $stmt->execute();

    log_event($licenseKey, 'heartbeat', 'ok', 'Heartbeat accepted', $ctx);

    json_response([
        'ok' => true,
        'status' => 'active',
        'product_code' => $product,
        'edition' => license_edition_v2($lic),
        'server_time' => date('c'),
        'next_heartbeat_after' => date('c', time() + 3600),
    ]);
}

function serve_public_key_v2(): never {
    $paths = array_values(array_unique(array_filter([
        envv('PUBLIC_KEY'),
        '/opt/aitech-license-server/keys/public.pem',
        '/opt/aitech-license-server/public/public.pem',
    ])));

    $pem = '';
    foreach ($paths as $path) {
        if (is_file($path) && is_readable($path)) {
            $pem = (string)file_get_contents($path);
            if (trim($pem) !== '') break;
        }
    }

    if (trim($pem) === '') {
        http_response_code(500);
        header('Content-Type: text/plain; charset=utf-8');
        echo "public key not readable";
        exit;
    }

    header('Content-Type: text/plain; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate');
    header('X-Content-Type-Options: nosniff');
    echo $pem;
    exit;
}


session_name('AITECH_LICENSE_ADMIN');
session_start([
    'cookie_httponly' => true,
    'cookie_samesite' => 'Strict',
]);

// CLI cron: `SMPRO_CRON=deadman php index.php` (or `php index.php deadman`) runs the dead-man sweep and exits,
// BEFORE any web routing/panel gate. getenv is the primary trigger (works even when register_argc_argv is off).
if (PHP_SAPI === 'cli') {
    $cliArgs = $_SERVER['argv'] ?? [];
    if (getenv('SMPRO_CRON') === 'deadman' || in_array('deadman', $cliArgs, true)) {
        $__m = __DIR__ . '/mailer.php'; if (is_file($__m)) require_once $__m;   // load wa_send/mailer_send for the alert
        deadman_sweep();
        exit;
    }
}
$path = path_only();

/* ---- SMPRO ADMIN GATE: hide the admin panel from the public; /api/* stays open for customer plugins ---- */
if (strpos($path, '/api/') !== 0) {
    $smGateFile = __DIR__ . '/../storage/.gate';
    $smGateSecret = is_file($smGateFile) ? trim((string)@file_get_contents($smGateFile)) : '';
    if ($smGateSecret !== '') {
        $smGateExpect = hash_hmac('sha256', 'smgate-v1', $smGateSecret);
        if (!hash_equals($smGateExpect, (string)($_COOKIE['smgate'] ?? ''))) {
            $smKnock = (string)($_GET['k'] ?? '');
            if ($smKnock !== '' && hash_equals($smGateSecret, $smKnock)) {
                setcookie('smgate', $smGateExpect, ['expires' => time() + 60*86400, 'path' => '/', 'secure' => true, 'httponly' => true, 'samesite' => 'Lax']);
                header('Location: /login'); exit;
            }
            // DYNAMIC one-time links (issued via WhatsApp): accept a fresh single-use token
            $smOtl = __DIR__ . '/../storage/.gate_otl';
            if ($smKnock !== '' && is_file($smOtl)) {
                $smList = json_decode((string)@file_get_contents($smOtl), true) ?: [];
                $smNow = time(); $smKeep = []; $smHit = false;
                foreach ($smList as $smIt) {
                    if (!is_array($smIt) || (int)($smIt['exp'] ?? 0) < $smNow) continue;   // drop expired
                    $smKeep[] = $smIt;                                                       // keep (time-limited, survives link-preview prefetch)
                    if (hash_equals((string)($smIt['h'] ?? ''), hash('sha256', $smKnock))) $smHit = true;
                }
                if ($smHit) {
                    if (count($smKeep) !== count($smList)) @file_put_contents($smOtl, json_encode($smKeep), LOCK_EX);
                    setcookie('smgate', $smGateExpect, ['expires' => time() + 60*86400, 'path' => '/', 'secure' => true, 'httponly' => true, 'samesite' => 'Lax']);
                    header('Location: /login'); exit;
                }
            }
            http_response_code(404);
            header('Content-Type: text/html; charset=utf-8');
            echo "<!doctype html><html><head><title>404 Not Found</title></head><body style=\"font:15px sans-serif;padding:60px;text-align:center;color:#555\"><h1>404 Not Found</h1></body></html>";
            exit;
        }
    }
}



/* SM_ACTIVATE_INCLUDE */
$__activateSm = __DIR__ . "/activate_sm.php";
if (is_file($__activateSm)) { require_once $__activateSm;
  if (function_exists("sm_activate_route") && sm_activate_route($path)) { exit; } }

/* PANEL_EXT_INCLUDE */
$__panelExt = __DIR__ . '/panel_ext.php';
if (is_file($__panelExt)) {
    require_once $__panelExt;
    require_once __DIR__ . '/servers_ext.php';
    require_once __DIR__ . '/plans_ext.php';
    require_once __DIR__ . '/releases_ext.php';
    if (function_exists('splan_migrate')) splan_migrate();
    if (function_exists('srv_route') && srv_route($path)) { exit; }
    if (function_exists('splan_route') && splan_route($path)) { exit; }
    if (function_exists('rel_route') && rel_route($path)) { exit; }
    if (function_exists('pext_route') && pext_route($path)) { exit; }
}

$__mailer = __DIR__ . '/mailer.php';
if (is_file($__mailer)) {
    require_once $__mailer;
    if (function_exists('mailer_route') && mailer_route($path)) { exit; }
}

$__waLink = __DIR__ . '/wa_link.php';
if (is_file($__waLink)) {
    require_once $__waLink;
    if (function_exists('wa_link_route') && wa_link_route($path)) { exit; }
}

$__authOtp = __DIR__ . '/auth_otp.php';
if (is_file($__authOtp)) {
    require_once $__authOtp;
    if (function_exists('authotp_route') && authotp_route($path)) { exit; }
}
/* AITECH_CREATE_SAFETY_SERIAL_V2_INCLUDE */
$__createSafetySerialV2 = __DIR__ . '/create_safety_serial_v2.php';
if (is_file($__createSafetySerialV2)) {
    require_once $__createSafetySerialV2;
    if (function_exists('sm_serial_v2_route') && sm_serial_v2_route($path)) {
        exit;
    }
}




/* AITECH_SAFETY_PLANS_V2_INCLUDE */
$__safetyPlansV2 = __DIR__ . '/safety_plans_v2.php';
if (is_file($__safetyPlansV2)) {
    require_once $__safetyPlansV2;
    if (function_exists('safety_plans_v2_route') && safety_plans_v2_route($path)) {
        exit;
    }
}




/* AITECH_PLANS_V7_INCLUDE */
$__plansV7 = __DIR__ . '/plans_v7.php';
if (is_file($__plansV7)) {
    require_once $__plansV7;
    if (function_exists('route_plans_v7') && route_plans_v7($path)) {
        exit;
    }
}




/* AITECH_LICENSE_SERVER_V2_ROUTES */

if ($path === '/api/public-key') {
    serve_public_key_v2();
}

if ($path === '/api/license-check' && ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    api_license_check_v2();
}

if ($path === '/api/license-check' && ($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    json_response([
        'ok' => false,
        'status' => 'method_not_allowed',
        'message' => 'Use POST with JSON body for this API endpoint'
    ], 405);
}

if ($path === '/api/heartbeat' && ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    api_heartbeat_v2();
}

if ($path === '/api/heartbeat' && ($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    json_response([
        'ok' => false,
        'status' => 'method_not_allowed',
        'message' => 'Use POST with JSON body for this API endpoint'
    ], 405);
}




if ($path === '/health') {
    try {
        $okDb = false;
        $dbName = envv('DB_NAME');
        $dbUser = envv('DB_USER');
        $dbPass = envv('DB_PASS');
        $cfgReadable = is_readable(CONFIG_FILE);
        $privateReadable = is_readable(envv('PRIVATE_KEY'));
        $publicReadable = is_readable(envv('PUBLIC_KEY'));

        if ($cfgReadable && $dbName !== '' && $dbUser !== '') {
            $mysqli = new mysqli(envv('DB_HOST', 'localhost'), $dbUser, $dbPass, $dbName);
            $mysqli->set_charset('utf8mb4');
            $okDb = true;
            $mysqli->close();
        }

        json_response([
            'ok' => $cfgReadable && $okDb && $privateReadable && $publicReadable,
            'config_readable' => $cfgReadable,
            'db_ok' => $okDb,
            'private_key_readable' => $privateReadable,
            'public_key_readable' => $publicReadable,
            'php_user' => get_current_user(),
            'time' => date('c'),
        ]);
    } catch (Throwable $e) {
        error_log('health error: ' . $e->getMessage());
        json_response([
            'ok' => false,
            'error' => $e->getMessage(),
        ], 500);
    }
}

// telemetry helpers must load BEFORE the /api/check dispatch (handler exits via json_response)
require_once __DIR__ . '/telemetry_ext.php';
require_once __DIR__ . '/plans_ext.php'; /* PLANS_EARLY_SEED */ if (function_exists('splan_migrate')) splan_migrate();
require_once __DIR__ . '/provision_ext.php'; if (function_exists('prov_route') && prov_route($path)) { exit; }
require_once __DIR__ . '/hub_ext.php'; if (function_exists('hub_route') && hub_route($path)) { exit; }
if (in_array($path, ['/api/activate', '/api/check'], true) && ($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    json_response([
        'ok' => false,
        'status' => 'method_not_allowed',
        'message' => 'Use POST with JSON body for this API endpoint'
    ], 405);
}


if ($path === '/api/action-check' && ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    api_action_check_v2();
}

if ($path === '/api/action-check' && ($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    json_response([
        'ok' => false,
        'status' => 'method_not_allowed',
        'message' => 'Use POST with JSON body for this API endpoint'
    ], 405);
}




if ($path === '/public.pem') {
    $pem = @file_get_contents('/opt/aitech-license-server/keys/public.pem');
    if ($pem === false || trim($pem) === '') {
        http_response_code(500);
        header('Content-Type: text/plain; charset=utf-8');
        echo "public key not readable";
        exit;
    }
    header('Content-Type: text/plain; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate');
    header('X-Content-Type-Options: nosniff');
    echo $pem;
    exit;
}

if ($path === '/api/activate' && ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    api_activate_or_check('activate');
}

if ($path === '/api/check' && ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    api_activate_or_check('check');
}

if (in_array($path, ['/api/telemetry', '/api/report-tamper'], true) && ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    api_report_tamper();
}

require_once __DIR__ . '/authorize_ext.php';
require_once __DIR__ . '/telemetry_ext.php';
if ($path === '/api/authorize' && ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    api_authorize();
}

require_once __DIR__ . '/download_ext.php';
require_once __DIR__ . '/update_ext.php';
if ($path === '/api/version' && ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') { api_version(); }
if ($path === '/api/update'  && ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') { api_update(); }
if ($path === '/api/command-ack' && ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') { api_command_ack(); }
if ($path === '/api/download' && ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    api_download();
}




if ($path === '/login') {
    page_login();
    exit;
}

if ($path === '/logout') {
    session_destroy();
    redirect('/login');
}

if ($path === '/') {
    page_dashboard();
    exit;
}

if ($path === '/licenses') {
    page_licenses();
    exit;
}

if ($path === '/licenses/create') {
    page_license_create();
    exit;
}

if ($path === '/licenses/action' && ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    page_license_action();
    exit;
}

if ($path === '/logs') {
    page_logs();
    exit;
}

http_response_code(404);
layout_start('404');
echo '<div class="card"><h2>404</h2><p>Page not found.</p></div>';
layout_end();
