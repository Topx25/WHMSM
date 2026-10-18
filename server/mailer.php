<?php
/**
 * mailer.php — admin-configurable SMTP (additive, self-contained). Provides:
 *   • a key/value app_settings store + AES-encrypted SMTP password at rest
 *   • mailer_send() — sends via the admin's SMTP (if enabled) else falls back to local mail()
 *   • a minimal SMTP client (STARTTLS / implicit-SSL / AUTH LOGIN, no external libs)
 *   • /settings/smtp — admin page to enter host/port/security/user/pass/from + send a test
 * Reuses the host app: db(), h(), csrf_token(), require_admin(), require_csrf(), redirect(),
 * layout_start()/layout_end().
 */
if (!function_exists('db')) { return; }

/* ---------------- settings store ---------------- */
function settings_migrate(): void {
    static $done = false; if ($done) return; $done = true;
    db()->query("CREATE TABLE IF NOT EXISTS app_settings (
        k VARCHAR(64) NOT NULL PRIMARY KEY,
        v TEXT NULL,
        updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
}
function settings_get(string $k, string $default = ''): string {
    settings_migrate();
    $st = db()->prepare("SELECT v FROM app_settings WHERE k=? LIMIT 1");
    $st->bind_param('s', $k); $st->execute(); $st->bind_result($v);
    $has = $st->fetch(); $st->close();
    return ($has && $v !== null) ? (string)$v : $default;
}
function settings_set(string $k, string $v): void {
    settings_migrate();
    $st = db()->prepare("INSERT INTO app_settings (k, v) VALUES (?, ?) ON DUPLICATE KEY UPDATE v=VALUES(v)");
    $st->bind_param('ss', $k, $v); $st->execute();
}

/* ---------------- password encryption at rest ---------------- */
function app_key(): string {
    $f = '/opt/aitech-license-server/storage/.appkey';
    if (is_readable($f)) { $k = base64_decode((string)@file_get_contents($f)); if (strlen($k) === 32) return $k; }
    $k = random_bytes(32);
    @file_put_contents($f, base64_encode($k)); @chmod($f, 0600);
    return $k;
}
function smtp_pass_set(string $plain): void {
    if ($plain === '') return;                                   // empty submit = keep existing
    $iv = random_bytes(16);
    $ct = openssl_encrypt($plain, 'aes-256-cbc', app_key(), OPENSSL_RAW_DATA, $iv);
    settings_set('smtp_pass_enc', base64_encode($iv . $ct));
}
function smtp_pass_get(): string {
    $blob = base64_decode(settings_get('smtp_pass_enc')); if (strlen($blob) < 17) return '';
    $p = openssl_decrypt(substr($blob, 16), 'aes-256-cbc', app_key(), OPENSSL_RAW_DATA, substr($blob, 0, 16));
    return $p === false ? '' : $p;
}

/* ---------------- send ---------------- */
function mailer_hdr_encode(string $s): string {
    return preg_match('/[^\x20-\x7E]/', $s) ? '=?UTF-8?B?' . base64_encode($s) . '?=' : $s;
}
function mailer_send(string $to, string $subject, string $body, string &$err = ''): bool {
    $to = trim(str_replace(["\r", "\n", "\0"], '', $to));   // strip CR/LF → no SMTP header/command or extra-recipient injection via a crafted client_email
    if ($to === '' || !filter_var($to, FILTER_VALIDATE_EMAIL)) { $err = 'Invalid recipient email.'; return false; }
    $subject = str_replace(["\r", "\n"], ' ', $subject);   // header line — never allow a newline
    $fromEmail = settings_get('smtp_from_email') ?: 'no-reply@plugins.iptvpro.org';
    $fromName  = settings_get('smtp_from_name')  ?: 'Safety Monitor Pro';
    if (settings_get('smtp_enabled') === '1' && settings_get('smtp_host') !== '') {
        return smtp_send_raw([
            'host'   => settings_get('smtp_host'),
            'port'   => (int)(settings_get('smtp_port') ?: 587),
            'secure' => settings_get('smtp_secure') ?: 'tls',
            'user'   => settings_get('smtp_user'),
            'pass'   => smtp_pass_get(),
        ], $to, $subject, $body, $fromEmail, $fromName, $err);
    }
    // fallback: local postfix
    $headers = 'From: ' . mailer_hdr_encode($fromName) . ' <' . $fromEmail . ">\r\n"
             . 'Reply-To: ' . $fromEmail . "\r\n"
             . "Content-Type: text/plain; charset=utf-8";
    $ok = @mail($to, $subject, $body, $headers, '-f ' . $fromEmail);
    if (!$ok) $err = 'Local mail() failed (no SMTP configured and postfix delivery failed).';
    return $ok;
}

/** Minimal SMTP client. Returns true on a 250 after end-of-DATA; $err carries the server reply on failure. */
function smtp_send_raw(array $cfg, string $to, string $subject, string $body, string $fromEmail, string $fromName, string &$err): bool {
    // Self-defend: strip CR/LF from every value that enters an SMTP command or header line, regardless of caller,
    // so no header/command/extra-recipient injection is possible even if a future path skips mailer_send's guard.
    $to        = str_replace(["\r", "\n", "\0"], '', $to);
    $fromEmail = str_replace(["\r", "\n", "\0"], '', $fromEmail);
    $fromName  = str_replace(["\r", "\n"], ' ', $fromName);
    $subject   = str_replace(["\r", "\n"], ' ', $subject);
    $host = (string)$cfg['host']; $port = (int)$cfg['port']; $secure = (string)$cfg['secure'];
    $user = (string)$cfg['user']; $pass = (string)$cfg['pass']; $timeout = 20;
    $dsn = ($secure === 'ssl' ? 'ssl://' : '') . $host . ':' . $port;
    $ctx = stream_context_create(['ssl' => ['verify_peer' => true, 'verify_peer_name' => true, 'SNI_enabled' => true]]);
    $fp = @stream_socket_client($dsn, $errno, $errstr, $timeout, STREAM_CLIENT_CONNECT, $ctx);
    if (!$fp) { $err = "connect failed: $errstr ($errno)"; return false; }
    stream_set_timeout($fp, $timeout);
    $read = function () use ($fp) {
        $data = '';
        while (($line = fgets($fp, 600)) !== false) { $data .= $line; if (strlen($line) < 4 || $line[3] === ' ') break; }
        return $data;
    };
    $put  = function (string $c) use ($fp) { fwrite($fp, $c . "\r\n"); };
    $ok   = function (string $resp, array $codes) use (&$err) { $c = (int)substr($resp, 0, 3); if (in_array($c, $codes, true)) return true; $err = trim($resp); return false; };
    $ehlo = 'EHLO ' . (gethostname() ?: 'localhost');
    try {
        if (!$ok($read(), [220])) { fclose($fp); return false; }
        $put($ehlo); if (!$ok($read(), [250])) { fclose($fp); return false; }
        if ($secure === 'tls') {
            $put('STARTTLS'); if (!$ok($read(), [220])) { fclose($fp); return false; }
            $crypto = STREAM_CRYPTO_METHOD_TLS_CLIENT;
            if (defined('STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT')) $crypto |= STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT;
            if (defined('STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT')) $crypto |= STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT;
            if (!@stream_socket_enable_crypto($fp, true, $crypto)) { $err = 'STARTTLS negotiation failed'; fclose($fp); return false; }
            $put($ehlo); if (!$ok($read(), [250])) { fclose($fp); return false; }
        }
        if ($user !== '') {
            $put('AUTH LOGIN');         if (!$ok($read(), [334])) { fclose($fp); return false; }
            $put(base64_encode($user)); if (!$ok($read(), [334])) { fclose($fp); return false; }
            $put(base64_encode($pass)); if (!$ok($read(), [235])) { fclose($fp); return false; }
        }
        $put('MAIL FROM:<' . $fromEmail . '>'); if (!$ok($read(), [250])) { fclose($fp); return false; }
        $put('RCPT TO:<' . $to . '>');          if (!$ok($read(), [250, 251])) { fclose($fp); return false; }
        $put('DATA');                           if (!$ok($read(), [354])) { fclose($fp); return false; }
        $domain  = substr(strrchr($fromEmail, '@') ?: '@localhost', 1);
        $headers = 'From: ' . mailer_hdr_encode($fromName) . ' <' . $fromEmail . ">\r\n"
                 . 'To: <' . $to . ">\r\n"
                 . 'Subject: ' . mailer_hdr_encode($subject) . "\r\n"
                 . 'MIME-Version: 1.0' . "\r\n"
                 . 'Content-Type: text/plain; charset=utf-8' . "\r\n"
                 . 'Date: ' . date('r') . "\r\n"
                 . 'Message-ID: <' . bin2hex(random_bytes(8)) . '@' . $domain . ">\r\n";
        $data = preg_replace('/^\./m', '..', $body);            // dot-stuffing
        $put($headers . "\r\n" . $data . "\r\n.");
        if (!$ok($read(), [250])) { fclose($fp); return false; }
        $put('QUIT'); fclose($fp);
        return true;
    } catch (\Throwable $e) { $err = 'SMTP error: ' . $e->getMessage(); if (is_resource($fp)) fclose($fp); return false; }
}

/* ---------------- WhatsApp gateway (same WAHA/OpenWA contract smprov1 uses) ---------------- */
function wa_key_set(string $plain): void {
    if ($plain === '') return;
    $iv = random_bytes(16);
    settings_set('wa_api_key_enc', base64_encode($iv . openssl_encrypt($plain, 'aes-256-cbc', app_key(), OPENSSL_RAW_DATA, $iv)));
}
function wa_key_get(): string {
    $blob = base64_decode(settings_get('wa_api_key_enc')); if (strlen($blob) < 17) return '';
    $p = openssl_decrypt(substr($blob, 16), 'aes-256-cbc', app_key(), OPENSSL_RAW_DATA, substr($blob, 0, 16));
    return $p === false ? '' : $p;
}
function wa_chat(string $v): string {                              // digits → "<digits>@c.us"
    $v = trim($v);
    if ($v === '' || strpos($v, '@') !== false) return $v;
    $d = preg_replace('/[^0-9]/', '', $v);
    return $d !== '' ? $d . '@c.us' : '';
}
function wa_request(string $base, string $key, string $method, string $path, $body = null, int $timeout = 15): array {
    $base = rtrim(trim($base), '/'); if ($base === '') return [0, null];
    $headers = ['X-API-Key: ' . trim($key), 'Accept: application/json'];
    $opts = ['http' => ['method' => $method, 'timeout' => $timeout, 'ignore_errors' => true],
             'ssl'  => ['verify_peer' => false, 'verify_peer_name' => false]];   // gateways are often self-hosted / self-signed
    if ($body !== null) { $headers[] = 'Content-Type: application/json'; $opts['http']['content'] = json_encode($body, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES); }
    $opts['http']['header'] = implode("\r\n", $headers);
    $raw = @file_get_contents($base . $path, false, stream_context_create($opts));
    $code = 0;
    if (isset($http_response_header) && is_array($http_response_header))
        foreach ($http_response_header as $h) if (preg_match('#^HTTP/\S+\s+(\d{3})#', $h, $m)) $code = (int)$m[1];
    return [$code, json_decode((string)$raw, true)];
}
function wa_resolve_session(string $base, string $key, string $ref): string {
    $ref = trim($ref);
    [$c, $j] = wa_request($base, $key, 'GET', '/api/sessions', null, 10);
    if (!is_array($j) || !$j) return $ref;
    foreach ($j as $s) { if (($s['id'] ?? '') === $ref || strcasecmp((string)($s['name'] ?? ''), $ref) === 0) return (string)($s['id'] ?? $ref); }
    foreach ($j as $s) { if (in_array(strtolower((string)($s['status'] ?? '')), ['connected', 'working', 'ready', 'authenticated'], true)) return (string)($s['id'] ?? $ref); }
    if (count($j) === 1) return (string)($j[0]['id'] ?? $ref);
    return $ref;
}
function wa_enabled(): bool {
    return settings_get('wa_enabled') === '1' && settings_get('wa_base_url') !== '' && settings_get('wa_chat_id') !== '';
}
/** A session can send when its status is one of these. */
function wa_session_ready(string $status): bool {
    return in_array(strtolower($status), ['ready', 'working', 'connected', 'authenticated'], true);
}
/** List gateway sessions as [id,name,status,phone,pushName,ready]. */
function wa_sessions_detailed(string $base, string $key): array {
    [$c, $j] = wa_request($base, $key, 'GET', '/api/sessions', null, 10);
    $out = [];
    if (is_array($j)) foreach ($j as $s) {
        if (!is_array($s)) continue;
        $phone = (string)($s['phone'] ?? (isset($s['me']['id']) ? preg_replace('/\D+/', '', (string)$s['me']['id']) : ''));
        $st = (string)($s['status'] ?? '');
        $out[] = [
            'id' => (string)($s['id'] ?? ''), 'name' => (string)($s['name'] ?? ''),
            'status' => $st, 'phone' => $phone,
            'pushName' => (string)($s['pushName'] ?? ($s['me']['pushName'] ?? '')),
            'ready' => wa_session_ready($st),
        ];
    }
    return $out;
}
/**
 * Send text via WhatsApp with automatic FAILOVER: try the configured default session
 * first, then every other READY session in turn until one accepts the message.  // WA-FAILOVER
 * On success $err = "sent via <name> (<phone>)"; on total failure it lists each attempt.
 */
function wa_send(string $text, string &$err = ''): bool {
    $base = settings_get('wa_base_url'); $chat = wa_chat(settings_get('wa_chat_id'));
    if ($base === '' || $chat === '') { $err = 'WhatsApp gateway/recipient not configured'; return false; }
    $key = wa_key_get();
    $ready = array_values(array_filter(wa_sessions_detailed($base, $key), fn($s) => $s['ready']));
    if (!$ready) { $err = 'no ready WhatsApp session on the gateway'; return false; }
    // configured default first (match by id or name), then the rest as fallbacks
    $pref = trim(settings_get('wa_session'));
    usort($ready, function ($a, $b) use ($pref) {
        $am = ($a['id'] === $pref || strcasecmp($a['name'], $pref) === 0) ? 0 : 1;
        $bm = ($b['id'] === $pref || strcasecmp($b['name'], $pref) === 0) ? 0 : 1;
        return $am <=> $bm;
    });
    $errors = [];
    foreach ($ready as $s) {
        $sid = $s['id'] !== '' ? $s['id'] : $s['name'];
        if ($sid === '') continue;
        // short per-attempt timeout so a dead/stuck session fails over fast (instead of hanging ~15s)
        [$code, $j] = wa_request($base, $key, 'POST', '/api/sessions/' . rawurlencode($sid) . '/messages/send-text', ['chatId' => $chat, 'text' => mb_substr($text, 0, 4096)], 9);
        if ($code >= 200 && $code < 300) {
            $err = 'sent via ' . ($s['name'] ?: $sid) . ($s['phone'] ? ' (+' . $s['phone'] . ')' : '');
            return true;
        }
        $m = (is_array($j) && isset($j['message'])) ? (is_array($j['message']) ? implode('; ', $j['message']) : $j['message']) : '';
        $errors[] = ($s['name'] ?: $sid) . ': HTTP ' . $code . ($m ? ' ' . $m : '');
    }
    $err = 'all sessions failed — ' . implode(' | ', $errors);
    return false;
}

/** Send a WhatsApp text to a SPECIFIC chat id (e.g. a customer number). Same gateway/session selection as wa_send,
 *  but targets the given chatId instead of the configured admin recipient. $chatId may be a raw phone (wa_chat-formatted). */
function wa_send_to(string $chatId, string $text, string &$err = ''): bool {
    $base = settings_get('wa_base_url'); $chat = wa_chat($chatId);
    if ($base === '' || $chat === '') { $err = 'WhatsApp gateway not configured or empty recipient'; return false; }
    $key = wa_key_get();
    $ready = array_values(array_filter(wa_sessions_detailed($base, $key), fn($s) => $s['ready']));
    if (!$ready) { $err = 'no ready WhatsApp session on the gateway'; return false; }
    $pref = trim(settings_get('wa_session'));
    usort($ready, function ($a, $b) use ($pref) {
        $am = ($a['id'] === $pref || strcasecmp($a['name'], $pref) === 0) ? 0 : 1;
        $bm = ($b['id'] === $pref || strcasecmp($b['name'], $pref) === 0) ? 0 : 1;
        return $am <=> $bm;
    });
    $errors = [];
    foreach ($ready as $s) {
        $sid = $s['id'] !== '' ? $s['id'] : $s['name']; if ($sid === '') continue;
        [$code, $j] = wa_request($base, $key, 'POST', '/api/sessions/' . rawurlencode($sid) . '/messages/send-text', ['chatId' => $chat, 'text' => mb_substr($text, 0, 4096)], 9);
        if ($code >= 200 && $code < 300) { $err = 'sent'; return true; }
        $m = (is_array($j) && isset($j['message'])) ? (is_array($j['message']) ? implode('; ', $j['message']) : $j['message']) : '';
        $errors[] = ($s['name'] ?: $sid) . ': HTTP ' . $code . ($m ? ' ' . $m : '');
    }
    $err = 'all sessions failed — ' . implode(' | ', $errors);
    return false;
}

/** Deliver a license to the customer on creation (or resend): emails the key + plan + install one-liner, and (if a
 *  phone is set) sends a shorter WhatsApp. English only. Best-effort + logged. Returns ['emailed','wa','summary']. */
function smlic_deliver_license(array $lic, string &$summary = ''): array {
    $key   = (string)($lic['license_key'] ?? '');
    $email = trim((string)($lic['client_email'] ?? ''));
    $phone = trim((string)($lic['client_phone'] ?? ''));
    $name  = trim((string)($lic['client_name'] ?? '')) ?: 'there';
    $plan  = (string)($lic['plan'] ?? '');
    $exp   = trim((string)($lic['expires_at'] ?? ''));
    $maxs  = (int)($lic['max_servers'] ?? 1);
    $prod  = (string)($lic['product_code'] ?? '');
    $expTxt   = $exp !== '' ? substr($exp, 0, 10) : 'no expiry';
    $prodName = (stripos($prod, 'safety') !== false) ? 'Safety Monitor Pro' : (stripos($prod, 'mail') !== false ? 'MailShield OSM Pro' : ($prod !== '' ? $prod : 'your plugin'));
    $ua      = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 SafetyMonitorPro/installer';
    $install = 'curl -fsSL -A "' . $ua . '" https://plugins.iptvpro.org/install.sh | bash -s -- ' . $key;

    $subject = 'Your ' . $prodName . ' license & installation';
    $body  = "Hello " . $name . ",\n\n";
    $body .= "Thank you for your purchase. Here are your " . $prodName . " license details:\n\n";
    $body .= "  License key : " . $key . "\n";
    $body .= "  Plan        : " . ($plan !== '' ? $plan : '-') . "\n";
    $body .= "  Servers     : up to " . $maxs . "\n";
    $body .= "  Expires     : " . $expTxt . "\n\n";
    $body .= "INSTALL — run this as root on your WHM/cPanel server:\n\n";
    $body .= $install . "\n\n";
    $body .= "Notes:\n";
    $body .= "  - Keep your license key private. It binds to the first server that installs it.\n";
    $body .= "  - After install, open WHM > Plugins > " . $prodName . ".\n";
    $body .= "  - Need help? Just reply to this email.\n";

    $wa  = "*" . $prodName . "* — license & install\n\n";
    $wa .= "License: " . $key . "\n";
    $wa .= "Plan: " . ($plan !== '' ? $plan : '-') . "  |  Servers: " . $maxs . "  |  Expires: " . $expTxt . "\n\n";
    $wa .= "Install (run as root on your WHM/cPanel server):\n" . $install . "\n\n";
    $wa .= "Keep this key private.";

    $emailed = false; $waed = false; $parts = [];
    if ($email !== '') { $e = ''; $emailed = function_exists('mailer_send') ? mailer_send($email, $subject, $body, $e) : false; $parts[] = 'email→' . $email . ':' . ($emailed ? 'ok' : ('fail ' . $e)); }
    else { $parts[] = 'email:no-address'; }
    if ($phone !== '') { $e = ''; $waed = function_exists('wa_send_to') ? wa_send_to($phone, $wa, $e) : false; $parts[] = 'wa→' . $phone . ':' . ($waed ? 'ok' : ('fail ' . $e)); }
    else { $parts[] = 'wa:no-phone'; }
    $summary = implode(' | ', $parts);
    if (function_exists('log_event')) { try { log_event($key, 'deliver', ($emailed || $waed) ? 'ok' : 'fail', $summary, []); } catch (\Throwable $e) {} }
    return ['emailed' => $emailed, 'wa' => $waed, 'summary' => $summary];
}

/* ---------------- /settings/smtp admin page ---------------- */
function mailer_route(string $path): bool {
    if (!in_array(rtrim($path, '/'), ['/settings', '/settings/smtp'], true)) return false;   // /settings, /settings/, /settings/smtp
    require_admin();
    $msg = ''; $err = '';
    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
        require_csrf();
        settings_set('smtp_enabled', !empty($_POST['smtp_enabled']) ? '1' : '0');
        settings_set('smtp_host', trim((string)($_POST['smtp_host'] ?? '')));
        settings_set('smtp_port', (string)max(1, min(65535, (int)($_POST['smtp_port'] ?? 587))));
        $sec = (string)($_POST['smtp_secure'] ?? 'tls'); if (!in_array($sec, ['none', 'tls', 'ssl'], true)) $sec = 'tls';
        settings_set('smtp_secure', $sec);
        settings_set('smtp_user', trim((string)($_POST['smtp_user'] ?? '')));
        smtp_pass_set((string)($_POST['smtp_pass'] ?? ''));
        settings_set('smtp_from_email', trim((string)($_POST['smtp_from_email'] ?? '')));
        settings_set('smtp_from_name', trim((string)($_POST['smtp_from_name'] ?? '')));
        // WhatsApp (same WAHA gateway settings as smprov1)
        settings_set('wa_enabled', !empty($_POST['wa_enabled']) ? '1' : '0');
        settings_set('wa_base_url', rtrim(trim((string)($_POST['wa_base_url'] ?? '')), '/'));
        wa_key_set((string)($_POST['wa_api_key'] ?? ''));
        settings_set('wa_session', trim((string)($_POST['wa_session'] ?? '')) ?: 'default');
        settings_set('wa_chat_id', trim((string)($_POST['wa_chat_id'] ?? '')));
        // Cloudflare Turnstile (login CAPTCHA)
        settings_set('ts_enabled', !empty($_POST['ts_enabled']) ? '1' : '0');
        settings_set('ts_site_key', trim((string)($_POST['ts_site_key'] ?? '')));
        if (function_exists('turnstile_secret_set')) turnstile_secret_set((string)($_POST['ts_secret'] ?? ''));
        // Login security (per-IP brute-force guard) — blank/0 = use built-in defaults
        if (isset($_POST['lg_max']))          settings_set('lg_max', (string)max(0, min(50, (int)$_POST['lg_max'])));
        if (isset($_POST['lg_cooldown_min'])) settings_set('lg_cooldown_min', (string)max(0, min(10080, (int)$_POST['lg_cooldown_min'])));
        if (isset($_POST['lg_window_min']))   settings_set('lg_window_min', (string)max(0, min(1440, (int)$_POST['lg_window_min'])));
        $msg = 'Settings saved.';
        $do = (string)($_POST['do'] ?? '');
        if ($do === 'test') {
            $to = trim((string)($_POST['test_to'] ?? '')) ?: settings_get('smtp_from_email');
            if ($to === '' || !filter_var($to, FILTER_VALIDATE_EMAIL)) { $err = 'Enter a valid test-recipient email.'; }
            else {
                $e = '';
                $ok = mailer_send($to, 'Safety Monitor Pro - SMTP test', "This is a test message confirming your SMTP settings work.\r\n", $e);
                $ok ? ($msg = 'Settings saved. Test email sent to ' . $to . ' — check the inbox.') : ($err = 'Saved, but the test email FAILED: ' . $e);
            }
        } elseif ($do === 'test_wa') {
            $e = '';
            $ok = wa_send('Safety Monitor Pro - WhatsApp test. Your gateway works ✅', $e);
            $ok ? ($msg = 'Settings saved. WhatsApp test ' . h($e) . ' to ' . h(settings_get('wa_chat_id')) . ' — check WhatsApp.') : ($err = 'Saved, but the WhatsApp test FAILED: ' . $e);
        }
    }
    mailer_settings_page($msg, $err);
    return true;
}

function mailer_settings_page(string $msg = '', string $err = ''): void {
    $en   = settings_get('smtp_enabled') === '1';
    $host = settings_get('smtp_host');
    $port = settings_get('smtp_port') ?: '587';
    $sec  = settings_get('smtp_secure') ?: 'tls';
    $user = settings_get('smtp_user');
    $hasPass = settings_get('smtp_pass_enc') !== '';
    $fromE = settings_get('smtp_from_email');
    $fromN = settings_get('smtp_from_name') ?: 'Safety Monitor Pro';
    $opt = function ($v, $cur, $label) { return '<option value="' . $v . '"' . ($v === $cur ? ' selected' : '') . '>' . $label . '</option>'; };
    layout_start('Settings');
    echo '<div class="card" style="max-width:680px">';
    echo '<h1 style="margin:0 0 2px">&#9881; Settings</h1>';
    echo '<p style="color:#64748b;margin:0 0 12px;font-size:13px">Server configuration — login-code delivery, login protection. One <b>Save</b> persists everything.</p>';
    echo '<div class="set-nav" style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:16px">'
       . '<a class="set-tab" href="#s-email">&#9993; Email / SMTP</a>'
       . '<a class="set-tab" href="#s-wa">&#128241; WhatsApp OTP</a>'
       . '<a class="set-tab" href="#s-captcha">&#128737; Login CAPTCHA</a>'
       . '<a class="set-tab" href="#s-login">&#128274; Login Security</a></div>';
    echo '<style>.set-tab{padding:7px 14px;border:1px solid #d6dcea;border-radius:999px;font-size:13px;font-weight:700;color:#3b5bdb;background:#eef2ff;text-decoration:none}.set-tab:hover{background:#3b5bdb;color:#fff}</style>';
    if ($msg !== '') echo '<p style="color:#047857;font-weight:800">' . h($msg) . '</p>';
    if ($err !== '') echo '<p style="color:#b91c1c;font-weight:900">' . h($err) . '</p>';
    echo '<form method="post" action="/settings/smtp"><input type="hidden" name="csrf" value="' . h(csrf_token()) . '">';
    echo '<h2 id="s-email">&#9993; Email / SMTP</h2>';
    echo '<p style="color:#475569">Sends admin login codes. With SMTP enabled, mail relays through your provider (recommended — avoids spam/SPF issues). If disabled, the server uses local mail (postfix).</p>';
    echo '<p><label><input type="checkbox" name="smtp_enabled" value="1"' . ($en ? ' checked' : '') . '> <b>Enable SMTP sending</b></label></p>';
    echo '<div class="pext-grid" style="display:grid;grid-template-columns:repeat(2,1fr);gap:12px">';
    echo '<label>SMTP host<input name="smtp_host" value="' . h($host) . '" placeholder="smtp.gmail.com"></label>';
    echo '<label>Port<input name="smtp_port" type="number" value="' . h($port) . '" placeholder="587"></label>';
    echo '<label>Security<select name="smtp_secure">' . $opt('tls', $sec, 'STARTTLS (587)') . $opt('ssl', $sec, 'SSL/TLS (465)') . $opt('none', $sec, 'None (25)') . '</select></label>';
    echo '<label>Username<input name="smtp_user" value="' . h($user) . '" placeholder="you@gmail.com" autocomplete="off"></label>';
    echo '<label>Password' . ($hasPass ? ' <small style="color:#047857">(saved — leave blank to keep)</small>' : '') . '<input name="smtp_pass" type="password" value="" autocomplete="new-password" placeholder="' . ($hasPass ? '••••••••' : 'app password') . '"></label>';
    echo '<label>From email<input name="smtp_from_email" value="' . h($fromE) . '" placeholder="you@gmail.com"></label>';
    echo '<label>From name<input name="smtp_from_name" value="' . h($fromN) . '"></label>';
    echo '<label>Send test to<input name="test_to" type="email" placeholder="topx1.host@gmail.com"></label>';
    echo '</div>';
    echo '<div style="margin-top:14px"><button class="btn" type="submit" name="do" value="save" style="background:#16a34a;color:#fff">&#128190; Save</button> ';
    echo '<button class="btn" type="submit" name="do" value="test">&#9993; Save &amp; send email test</button></div>';

    // ---- WhatsApp card (same form so one Save persists both) ----
    $waEn   = settings_get('wa_enabled') === '1';
    $waBase = settings_get('wa_base_url');
    $waSess = settings_get('wa_session') ?: 'default';
    $waChat = settings_get('wa_chat_id');
    $waHasKey = settings_get('wa_api_key_enc') !== '';
    echo '<hr style="margin:18px 0;border:none;border-top:1px solid rgba(148,163,184,.35)">';
    echo '<h2 id="s-wa" style="margin-top:0">&#128241; WhatsApp OTP (login code via WhatsApp)</h2>';
    echo '<p style="color:#475569">Optional alternative to email — uses the same WAHA/OpenWA gateway as the Safety Monitor Pro plugin. When enabled, the login code is also sent to your WhatsApp.</p>';

    // ---- live sessions: show active numbers, pick the default sender (with auto-failover) ----
    $waSessList = ($waBase !== '') ? wa_sessions_detailed($waBase, wa_key_get()) : [];
    $waReady = array_values(array_filter($waSessList, fn($s) => $s['ready']));
    if ($waSessList) {
        echo '<div style="margin:6px 0 10px;overflow:auto"><table style="width:100%;border-collapse:collapse;font-size:13px">';
        echo '<thead><tr>'
           . '<th style="text-align:center;padding:6px 8px">Default</th>'
           . '<th style="text-align:left;padding:6px 8px">Session</th>'
           . '<th style="text-align:left;padding:6px 8px">Number</th>'
           . '<th style="text-align:left;padding:6px 8px">Account</th>'
           . '<th style="text-align:left;padding:6px 8px">Status</th></tr></thead><tbody>';
        $anyChecked = false;
        foreach ($waSessList as $i => $s) {
            $isDef = ($s['id'] === $waSess || strcasecmp($s['name'], $waSess) === 0);
            if ($isDef && $s['ready']) $anyChecked = true;
            echo '<tr style="border-top:1px solid rgba(148,163,184,.25)">';
            echo '<td style="padding:6px 8px;text-align:center">' . ($s['ready']
                ? '<input type="radio" name="wa_session" value="' . h($s['id'] ?: $s['name']) . '"' . ($isDef ? ' checked' : '') . '>'
                : '<span style="color:#94a3b8">—</span>') . '</td>';
            echo '<td style="padding:6px 8px"><b>' . h($s['name'] ?: $s['id']) . '</b></td>';
            echo '<td style="padding:6px 8px">' . ($s['phone'] ? '+' . h($s['phone']) : '<span style="color:#94a3b8">—</span>') . '</td>';
            echo '<td style="padding:6px 8px">' . h($s['pushName']) . '</td>';
            echo '<td style="padding:6px 8px">' . ($s['ready']
                ? '<span style="color:#16a34a;font-weight:800">&#9679; ' . h($s['status']) . '</span>'
                : '<span style="color:#b91c1c;font-weight:700">&#9679; ' . h($s['status']) . '</span>') . '</td>';
            echo '</tr>';
        }
        echo '</tbody></table></div>';
        // if no ready session is the saved default, pre-check the first ready one
        if (!$anyChecked && $waReady) {
            echo '<script>(function(){var r=document.querySelector(\'input[name=wa_session]\');if(r&&!document.querySelector(\'input[name=wa_session]:checked\'))r.checked=true;})();</script>';
        }
        echo '<p style="color:#64748b;font-size:12px;margin:2px 0 10px">Choose the <b>default sender</b> (radio). If a code fails to send on it, the server <b>automatically retries the other ready sessions</b>. <b>' . count($waReady) . '</b> of ' . count($waSessList) . ' session(s) ready now. <a href="/settings/smtp">&#8635; Refresh</a></p>';
    } elseif ($waBase !== '') {
        echo '<p style="color:#b91c1c;font-size:13px">Could not load sessions from the gateway (check base URL / API key). You can still type a session name below.</p>';
    }

    echo '<div class="pext-grid" style="display:grid;grid-template-columns:repeat(2,1fr);gap:12px">';
    echo '<label>Gateway base URL<input name="wa_base_url" value="' . h($waBase) . '" placeholder="https://wa.example.com:3000"></label>';
    echo '<label>API key (X-API-Key)' . ($waHasKey ? ' <small style="color:#047857">(saved — blank=keep)</small>' : '') . '<input name="wa_api_key" type="password" value="" autocomplete="new-password" placeholder="' . ($waHasKey ? '••••••••' : 'gateway key') . '"></label>';
    if (!$waSessList) echo '<label>Session<input name="wa_session" value="' . h($waSess) . '" placeholder="default"></label>';
    echo '<label>Recipient number<input name="wa_chat_id" value="' . h($waChat) . '" placeholder="2010xxxxxxxx (country code, no +)"></label>';
    echo '</div>';
    echo '<p style="margin-top:8px"><label><input type="checkbox" name="wa_enabled" value="1"' . ($waEn ? ' checked' : '') . '> <b>Enable WhatsApp delivery</b></label></p>';
    echo '<div style="margin-top:6px"><button class="btn" type="submit" name="do" value="test_wa">&#128241; Save &amp; send WhatsApp test</button></div>';
    // ---- Cloudflare Turnstile (login CAPTCHA) ----
    $tsEn = settings_get('ts_enabled') === '1'; $tsSite = settings_get('ts_site_key'); $tsHasSecret = settings_get('ts_secret_enc') !== '';
    echo '<hr style="border:0;border-top:1px solid #e2e8f0;margin:18px 0">';
    echo '<h2 id="s-captcha" style="margin:0 0 6px">&#128737; Login CAPTCHA — Cloudflare Turnstile</h2>';
    echo '<p style="color:#475569;font-size:13px">Adds a Cloudflare Turnstile challenge to the admin login (<code>/login</code> + <code>/login-pw</code>) to stop bots &amp; brute-force. Create a FREE widget at <b>Cloudflare dashboard → Turnstile → Add widget</b> (add the domains <code>plugins.iptvpro.org</code> + <code>dl.iptvpro.org</code>), then paste its <b>Site key</b> + <b>Secret key</b> below.</p>';
    echo '<div class="pext-grid" style="display:grid;grid-template-columns:repeat(2,1fr);gap:12px">';
    echo '<label>Site key<input name="ts_site_key" value="' . h($tsSite) . '" placeholder="0x4AAAAA..."></label>';
    echo '<label>Secret key' . ($tsHasSecret ? ' <small style="color:#047857">(saved — blank=keep)</small>' : '') . '<input name="ts_secret" type="password" value="" autocomplete="new-password" placeholder="' . ($tsHasSecret ? '••••••••' : '0x4AAAAA...') . '"></label>';
    echo '</div>';
    echo '<p style="margin-top:8px"><label><input type="checkbox" name="ts_enabled" value="1"' . ($tsEn ? ' checked' : '') . '> <b>Enable login CAPTCHA</b></label> <small style="color:#64748b">(takes effect only once BOTH keys are set)</small></p>';
    // ---- Login Security (per-IP brute-force guard) ----
    $lgMax = (int)settings_get('lg_max'); $lgCd = (int)settings_get('lg_cooldown_min'); $lgWin = (int)settings_get('lg_window_min');
    echo '<hr style="border:0;border-top:1px solid #e2e8f0;margin:18px 0">';
    echo '<h2 id="s-login" style="margin:0 0 6px">&#128274; Login Security (brute-force guard)</h2>';
    echo '<p style="color:#475569;font-size:13px">After too many failed login attempts (wrong email / wrong code / wrong password) from one IP, that IP is temporarily blocked from <code>/login</code> + <code>/login-pw</code>. The real client IP is read from Cloudflare. Leave a field at <b>0</b> to use the built-in default.</p>';
    echo '<div class="pext-grid" style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px">';
    echo '<label>Max failed attempts<input name="lg_max" type="number" min="0" max="50" value="' . $lgMax . '" placeholder="3 (default)"></label>';
    echo '<label>Block duration (min)<input name="lg_cooldown_min" type="number" min="0" max="10080" value="' . $lgCd . '" placeholder="60 (default)"></label>';
    echo '<label>Counting window (min)<input name="lg_window_min" type="number" min="0" max="1440" value="' . $lgWin . '" placeholder="30 (default)"></label>';
    echo '</div>';
    echo '<p style="color:#64748b;font-size:12px;margin-top:6px">Defaults: 3 attempts within 30 min → blocked for 60 min.</p>';
    echo '<div style="margin-top:14px"><button class="btn" type="submit" style="background:#16a34a;color:#fff">&#128190; Save all settings</button></div>';
    echo '</form>';
    echo '<p style="color:#64748b;margin-top:12px;font-size:13px">Copy the gateway URL, API key, session &amp; your number from the plugin&#39;s WhatsApp settings. Gmail SMTP: host <code>smtp.gmail.com</code>, port <code>587</code>, STARTTLS, password = 16-char <b>App Password</b>. If both email and WhatsApp are enabled, the code is sent via both.</p>';
    echo '</div>';
    layout_end();
}
