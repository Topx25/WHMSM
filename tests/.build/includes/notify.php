<?php
/**
 * includes/notify.php — central Notifications layer for Safety Monitor Pro.
 *
 * One API — smpro_notify($type, $subject, $body, $meta) — that every module can
 * call. The admin configures, in Notifications:
 *   • channels   : Email (sendmail) and/or Telegram (bot token + chat id)
 *   • event types: which alerts are on, and which channel(s) each one uses
 * A built-in checker (smpro_notify_run_checks) evaluates live server state and
 * fires notifications only when a condition is NEW/changed (deduped via a state
 * file), so it can run from the page button or a cron without spamming.
 *
 * Config + state + log live under /var/lib/smpro/notifications (root-only, 0600).
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

define('SMPRO_NTF_DIR',   SMPRO_VARLIB . '/notifications');
define('SMPRO_NTF_CONF',  SMPRO_VARLIB . '/notifications/config.json');
define('SMPRO_NTF_STATE', SMPRO_VARLIB . '/notifications/state.json');
define('SMPRO_NTF_LOG',   SMPRO_VARLIB . '/notifications/log.jsonl');

/** Catalogue of notification types: key => [label, description, severity]. */
function smpro_ntf_types() {
    return [
        'malware_active'   => ['Active malware detected', 'Imunify360 reports one or more currently-malicious files.', 'critical'],
        'db_injection'     => ['Database injection detected', 'Imunify360 flagged malicious content injected into a database (spam links, scripts, backdoors).', 'critical'],
        'login_bruteforce' => ['Login brute-force / spike', 'A source IP crossed the failed-login threshold in the window.', 'high'],
        'account_suspended'=> ['Account suspended', 'A cPanel account became suspended.', 'high'],
        'backup_failed'    => ['Backup failed', 'A JetBackup job failed or did not complete.', 'high'],
        'disk_high'        => ['Disk usage high', 'A filesystem crossed the disk-usage threshold.', 'high'],
        'load_high'        => ['Server load high', 'Load average crossed the threshold.', 'medium'],
        'harden_drift'     => ['PHP Harden drift', 'A file that PHP Harden locked is no longer immutable (possible tamper).', 'high'],
        'spam_outbreak'    => ['Outbound spam spike', 'An account sent an unusually high volume of outbound mail (over the per-hour or per-12h threshold).', 'high'],
        'inbound_spam'     => ['Inbound spam detected', 'Incoming emails were scored/marked as spam (SpamAssassin) or rejected as spam. Re-checked at least every 6 hours.', 'medium'],
        'integrity_tamper' => ['Plugin integrity / tamper', 'A protected plugin file was modified or the signed integrity manifest is invalid — the plugin entered Protected Mode. Always sent.', 'critical'],
        'intrusion_attack' => ['Web-attack activity', 'Real-time WAF attacks: critical rules, a domain under heavy attack, or one IP scanning many domains.', 'high'],
        'intrusion_breach' => ['Possible compromise', 'An exploit-class attack was served 2xx/3xx AND the domain has freshly-changed PHP files (likely successful breach).', 'critical'],
        'intrusion_autoblock' => ['Attacker auto-blocked', 'The Intrusion Monitor auto-blocked one or more attacker IPs (CSF / Cloudflare).', 'high'],
        'intrusion_emergency' => ['Emergency actions', 'EMERGENCY auto-response fired: an attacked site whose files changed was hardened and any web-shells quarantined.', 'critical'],
        'hub_bruteforce_lock' => ['Remote-control attempts / lock', 'Wrong control-password attempts from a managing hub, or the resulting 24h lock/reset on remote control.', 'critical'],
        'license_expiry'   => ['License expiry / renewal', 'Mandatory reminders before the license expires (2 days, 1 day, then at expiry). Always sent — cannot be turned off.', 'critical'],
        'sync_loss'        => ['License server unreachable', 'This server could not reach the main license server for several hours — sent so you can restore connectivity or contact support before the plugin stops.', 'critical'],
        'test'             => ['Test message', 'Manual test from the Notifications page.', 'info'],
    ];
}

/* ---------------- config ---------------- */
function smpro_ntf_default_config() {
    $types = [];
    foreach (smpro_ntf_types() as $k => $_) $types[$k] = ['on' => $k !== 'load_high', 'email' => true, 'telegram' => true, 'pushbullet' => true, 'whatsapp' => true];
    return [
        'email'    => ['enabled' => false, 'method' => 'sendmail', 'to' => [], 'from' => 'safety-monitor@' . gethostname(),
                       'smtp' => ['host' => '', 'port' => 587, 'secure' => 'tls', 'user' => '', 'pass' => '']],
        'telegram' => ['enabled' => false, 'token' => '', 'chat_id' => ''],
        'pushbullet' => ['enabled' => false, 'token' => ''],
        'whatsapp' => ['enabled' => false, 'base_url' => '', 'api_key' => '', 'session' => 'default', 'chat_id' => ''],
        'types'    => $types,
        'thresholds' => ['disk_pct' => 90, 'load' => 20, 'failed_logins' => 60, 'spam_events' => 300, 'db_injections' => 1, 'remind_hours' => 12,
                         // Outbound bulk-mail: "large volume" = more than mail_out_hour emails in one hour,
                         // OR at least mail_out_12h emails over 12 hours. Below both → treated as normal (not spam),
                         // unless the Spam & Phishing content scan flags the messages as actual spam.
                         'mail_out_hour' => 100, 'mail_out_12h' => 300,
                         // Inbound spam: alert when at least this many incoming spam-scored/rejected mails are seen;
                         // re-alerted at most every inbound_spam_remind_hours (default 6h).
                         'inbound_spam_min' => 1, 'inbound_spam_remind_hours' => 6],
        'updated_at' => '',
    ];
}
/** Config fields that hold secrets and must be encrypted at rest. */
function smpro_ntf_secret_paths() { return [['telegram', 'token'], ['whatsapp', 'api_key'], ['pushbullet', 'token'], ['email', 'smtp', 'pass']]; }
function smpro_ntf_load() {
    $d = is_file(SMPRO_NTF_CONF) ? json_decode((string)@file_get_contents(SMPRO_NTF_CONF), true) : null;
    $cfg = is_array($d) ? $d : [];
    $cfg = array_replace_recursive(smpro_ntf_default_config(), $cfg);
    if (function_exists('smpro_secret_dec')) {                            // decrypt secrets for callers; migrate legacy plaintext
        $migrate = false;
        foreach (smpro_ntf_secret_paths() as $p) {
            $v = smpro_secret_get($cfg, $p);
            if (is_string($v) && $v !== '') { if (!smpro_secret_is_enc($v)) $migrate = true; smpro_secret_set($cfg, $p, smpro_secret_dec($v)); }
        }
        if ($migrate) smpro_ntf_save($cfg);                              // re-store with the secrets encrypted
    }
    return $cfg;
}
function smpro_ntf_save($cfg) {
    @is_dir(SMPRO_NTF_DIR) || @mkdir(SMPRO_NTF_DIR, 0700, true);
    $cfg['updated_at'] = date('c');
    if (function_exists('smpro_secret_enc')) {                            // encrypt secrets before writing to disk
        foreach (smpro_ntf_secret_paths() as $p) {
            $v = smpro_secret_get($cfg, $p);
            if (is_string($v) && $v !== '') smpro_secret_set($cfg, $p, smpro_secret_enc($v));
        }
    }
    $tmp = SMPRO_NTF_CONF . '.tmp';
    if (@file_put_contents($tmp, json_encode($cfg, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), LOCK_EX) === false) return false;
    @chmod($tmp, 0600);
    return @rename($tmp, SMPRO_NTF_CONF);
}

/* ---------------- channel senders ---------------- */
/** Send via the configured method (sendmail or SMTP). Returns [ok, detail]. */
function smpro_ntf_send_email(array $to, $from, $subject, $body) {
    $cfg = smpro_ntf_load();
    $to = array_values(array_filter(array_map('trim', $to), fn($a) => filter_var($a, FILTER_VALIDATE_EMAIL)));
    if (!$to) return [false, 'no valid recipient'];
    $from = filter_var($from, FILTER_VALIDATE_EMAIL) ? $from : ('safety-monitor@' . gethostname());
    if (($cfg['email']['method'] ?? 'sendmail') === 'smtp') return smpro_ntf_send_smtp($cfg['email']['smtp'] ?? [], $from, $to, $subject, $body);
    // sendmail
    $sendmail = is_executable('/usr/sbin/sendmail') ? '/usr/sbin/sendmail' : (is_executable('/usr/lib/sendmail') ? '/usr/lib/sendmail' : '');
    $headers = "From: Safety Monitor Pro <$from>\r\n"
             . 'To: ' . implode(', ', $to) . "\r\n"
             . 'Subject: ' . mb_encode_mimeheader($subject, 'UTF-8') . "\r\n"
             . "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\n";
    $msg = $headers . "\r\n" . $body . "\r\n";
    if ($sendmail !== '') {
        $h = @popen($sendmail . ' -t -i -f ' . escapeshellarg($from), 'w');
        if ($h) { fwrite($h, $msg); $rc = pclose($h); return [$rc === 0, 'sendmail rc=' . $rc]; }
    }
    $ok = @mail(implode(',', $to), $subject, $body, "From: Safety Monitor Pro <$from>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8");
    return [(bool)$ok, $ok ? 'php mail()' : 'mail() failed'];
}
/** Minimal SMTP client (fsockopen + STARTTLS/SSL + AUTH LOGIN). Returns [ok, detail]. */
function smpro_ntf_smtp_cmd($fp, $cmd) {
    if ($cmd !== null) fputs($fp, $cmd . "\r\n");
    $resp = '';
    while (($line = fgets($fp, 600)) !== false) { $resp .= $line; if (strlen($line) < 4 || $line[3] === ' ') break; }
    return [(int)substr($resp, 0, 3), trim($resp)];
}
function smpro_ntf_send_smtp($smtp, $from, array $to, $subject, $body) {
    $host = trim((string)($smtp['host'] ?? '')); $port = (int)($smtp['port'] ?? 587); $secure = (string)($smtp['secure'] ?? 'tls');
    if ($host === '') return [false, 'SMTP host not configured'];
    $he = gethostname();
    $target = ($secure === 'ssl' ? 'ssl://' : '') . $host . ':' . $port;
    // Verify the SMTP server's TLS certificate by default (prevents a network MITM from stealing the AUTH LOGIN
    // credentials). Admins on a self-signed internal relay can opt out with verify_tls=false.
    $verify = !isset($smtp['verify_tls']) || (bool)$smtp['verify_tls'];
    $ctx = stream_context_create(['ssl' => [
        'verify_peer'       => $verify,
        'verify_peer_name'  => $verify,
        'allow_self_signed' => !$verify,
        'peer_name'         => $host,
        'SNI_enabled'       => true,
    ]]);
    $tlsm = STREAM_CRYPTO_METHOD_TLS_CLIENT;          // negotiate TLS 1.2/1.3 (best available); never SSLv3
    if (defined('STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT')) $tlsm = STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT
        | (defined('STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT') ? STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT : 0);
    $fp = @stream_socket_client($target, $en, $es, 15, STREAM_CLIENT_CONNECT, $ctx);
    if (!$fp) return [false, "connect failed ($es)"];
    stream_set_timeout($fp, 15);
    [$c] = smpro_ntf_smtp_cmd($fp, null); if ($c !== 220) { fclose($fp); return [false, 'no 220 greeting']; }
    smpro_ntf_smtp_cmd($fp, 'EHLO ' . $he);
    if ($secure === 'tls') {
        [$c] = smpro_ntf_smtp_cmd($fp, 'STARTTLS'); if ($c !== 220) { fclose($fp); return [false, 'STARTTLS not accepted']; }
        if (!@stream_socket_enable_crypto($fp, true, $tlsm)) { fclose($fp); return [false, 'TLS negotiation failed (certificate not trusted? set verify_tls off for a self-signed relay)']; }
        smpro_ntf_smtp_cmd($fp, 'EHLO ' . $he);
    }
    if (trim((string)($smtp['user'] ?? '')) !== '') {
        smpro_ntf_smtp_cmd($fp, 'AUTH LOGIN');
        smpro_ntf_smtp_cmd($fp, base64_encode((string)$smtp['user']));
        [$c, $r] = smpro_ntf_smtp_cmd($fp, base64_encode((string)($smtp['pass'] ?? '')));
        if ($c !== 235) { fclose($fp); return [false, 'auth failed: ' . $r]; }
    }
    [$c, $r] = smpro_ntf_smtp_cmd($fp, 'MAIL FROM:<' . $from . '>'); if ($c !== 250) { fclose($fp); return [false, 'MAIL FROM rejected: ' . $r]; }
    foreach ($to as $rcpt) { [$c, $r] = smpro_ntf_smtp_cmd($fp, 'RCPT TO:<' . $rcpt . '>'); if ($c !== 250 && $c !== 251) { fclose($fp); return [false, 'RCPT rejected: ' . $r]; } }
    [$c] = smpro_ntf_smtp_cmd($fp, 'DATA'); if ($c !== 354) { fclose($fp); return [false, 'DATA not accepted']; }
    $headers = 'From: Safety Monitor Pro <' . $from . ">\r\n" . 'To: ' . implode(', ', $to) . "\r\n"
             . 'Subject: ' . mb_encode_mimeheader($subject, 'UTF-8') . "\r\n" . "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n";
    $payload = $headers . preg_replace('/^\./m', '..', $body) . "\r\n.";
    [$c, $r] = smpro_ntf_smtp_cmd($fp, $payload);
    smpro_ntf_smtp_cmd($fp, 'QUIT'); fclose($fp);
    return [$c === 250, $c === 250 ? 'sent via SMTP' : 'send failed: ' . $r];
}
/** Pushbullet push (note). Returns [ok, detail]. */
function smpro_ntf_send_pushbullet($token, $title, $body) {
    $token = trim((string)$token);
    if ($token === '') return [false, 'access token missing'];
    $payload = json_encode(['type' => 'note', 'title' => mb_substr($title, 0, 250), 'body' => mb_substr($body, 0, 2000)], JSON_UNESCAPED_UNICODE);
    $res = smpro_http('https://api.pushbullet.com/v2/pushes', ['method' => 'POST', 'timeout' => 15, 'body' => $payload,
        'headers' => ['Access-Token: ' . $token, 'Content-Type: application/json']]);   // token stays in-process (not in argv)
    $j = json_decode($res['body'], true);
    if (is_array($j) && isset($j['iden'])) return [true, 'sent'];
    return [false, is_array($j) ? (string)($j['error']['message'] ?? ($j['error_code'] ?? 'pushbullet error')) : 'no response from Pushbullet'];
}
/* ---------------- WhatsApp gateway (OpenWA-style: X-API-Key, multi-session) ---------------- */
/** SSRF guard: an admin-set base URL must be http(s) and must NOT point at loopback, private, link-local,
 *  or cloud-metadata addresses (else a tampered config could make this root process hit internal services
 *  e.g. 169.254.169.254 or 127.0.0.1:2087 with the API key attached). Returns '' if safe, else a reason. */
function smpro_ntf_url_unsafe($url) {
    $p = @parse_url($url); if (!is_array($p) || empty($p['scheme']) || empty($p['host'])) return 'malformed URL';
    if (!in_array(strtolower($p['scheme']), ['http', 'https'], true)) return 'scheme must be http(s)';
    $host = $p['host']; $ips = [];
    if (filter_var($host, FILTER_VALIDATE_IP)) $ips[] = $host;
    else { $r = @gethostbynamel($host); if (is_array($r)) $ips = $r; }     // resolve names too (DNS-rebind defence is best-effort)
    foreach ($ips as $ip) {
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE))
            return 'resolves to a private/reserved address (' . $ip . ')';
        if (strpos($ip, '169.254.') === 0 || strpos($ip, '127.') === 0 || $ip === '::1') return 'loopback/link-local not allowed';
    }
    return '';
}
/** Generic call to the WhatsApp API. Returns [http_code, decoded_json|null, raw]. */
function smpro_ntf_wa_request($base, $key, $method, $path, $body = null, $timeout = 15) {
    $base = rtrim(trim((string)$base), '/');
    if ($base === '') return [0, null, 'base URL not set'];
    if ($why = smpro_ntf_url_unsafe($base)) return [0, null, 'WhatsApp base URL rejected: ' . $why];
    $headers = ['X-API-Key: ' . trim((string)$key), 'Accept: application/json'];   // API key stays in-process (not in argv)
    $payload = null;
    if ($body !== null) { $headers[] = 'Content-Type: application/json'; $payload = json_encode($body, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES); }
    $res = smpro_http($base . $path, ['method' => $method, 'timeout' => (int)$timeout, 'headers' => $headers, 'body' => $payload]);
    return [$res['code'], json_decode($res['body'], true), $res['body']];
}
/** Normalise a recipient to a WhatsApp chat id: digits → "<digits>@c.us". */
function smpro_ntf_wa_chat($v) {
    $v = trim((string)$v);
    if ($v === '' || strpos($v, '@') !== false) return $v;
    $d = preg_replace('/[^0-9]/', '', $v);
    return $d !== '' ? $d . '@c.us' : '';
}
/** Resolve a session reference (friendly name OR id) to the gateway's session id. */
function smpro_ntf_wa_resolve_session($base, $key, $ref) {
    $ref = trim((string)$ref);
    [$c, $j] = smpro_ntf_wa_request($base, $key, 'GET', '/api/sessions', null, 10);
    if (!is_array($j) || !$j) return $ref;
    foreach ($j as $s) { if (($s['id'] ?? '') === $ref || strcasecmp((string)($s['name'] ?? ''), $ref) === 0) return (string)($s['id'] ?? $ref); }
    // prefer a connected/ready session (gateway uses 'ready'/'working'/'connected'/'authenticated')
    foreach ($j as $s) { if (in_array(strtolower((string)($s['status'] ?? '')), ['connected', 'working', 'ready', 'authenticated'], true)) return (string)($s['id'] ?? $ref); }
    // else if there is exactly one session, use it
    if (count($j) === 1) return (string)($j[0]['id'] ?? $ref);
    return $ref;
}
/** A gateway session can send when its status is one of these. */
function smpro_ntf_wa_ready($status) {
    return in_array(strtolower((string)$status), ['ready', 'working', 'connected', 'authenticated'], true);
}
/** List gateway sessions as [id,name,status,phone,pushName,ready]. */
function smpro_ntf_wa_sessions($base, $key) {
    [$c, $j] = smpro_ntf_wa_request($base, $key, 'GET', '/api/sessions', null, 10);
    $out = [];
    if (is_array($j)) foreach ($j as $s) {
        if (!is_array($s)) continue;
        $st = (string)($s['status'] ?? '');
        $out[] = [
            'id' => (string)($s['id'] ?? ''), 'name' => (string)($s['name'] ?? ''),
            'status' => $st,
            'phone' => (string)($s['phone'] ?? (isset($s['me']['id']) ? preg_replace('/\D+/', '', (string)$s['me']['id']) : '')),
            'pushName' => (string)($s['pushName'] ?? ($s['me']['pushName'] ?? '')),
            'ready' => smpro_ntf_wa_ready($st),
        ];
    }
    return $out;
}
/**
 * Send a WhatsApp text with automatic FAILOVER: try the configured default session first,
 * then every other READY session until one accepts the message. Returns [ok, detail].
 * detail = "sent via <name> (+phone)" on success, or the list of failed attempts.
 */
function smpro_ntf_send_whatsapp($cfg, $text) {
    $w = $cfg['whatsapp'] ?? [];
    $base = $w['base_url'] ?? ''; $key = $w['api_key'] ?? ''; $chat = smpro_ntf_wa_chat($w['chat_id'] ?? '');
    if ($base === '' || $chat === '') return [false, 'WhatsApp gateway / recipient not configured'];
    $ready = array_values(array_filter(smpro_ntf_wa_sessions($base, $key), function ($s) { return $s['ready']; }));
    if (!$ready) return [false, 'No ready WhatsApp session — create & link one in the WhatsApp section'];
    $pref = trim((string)($w['session'] ?? ''));
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
        [$code, $j] = smpro_ntf_wa_request($base, $key, 'POST', '/api/sessions/' . rawurlencode($sid) . '/messages/send-text', ['chatId' => $chat, 'text' => mb_substr($text, 0, 4096)], 9);
        if ($code >= 200 && $code < 300) return [true, 'sent via ' . ($s['name'] ?: $sid) . ($s['phone'] ? ' (+' . $s['phone'] . ')' : '')];
        $m = (is_array($j) && isset($j['message'])) ? (is_array($j['message']) ? implode('; ', $j['message']) : $j['message']) : '';
        $errors[] = ($s['name'] ?: $sid) . ': HTTP ' . $code . ($m ? ' ' . $m : '');
    }
    return [false, 'all sessions failed — ' . implode(' | ', $errors)];
}
/** Send via Telegram Bot API. Returns [ok, detail]. */
function smpro_ntf_send_telegram($token, $chatId, $text) {
    $token = trim((string)$token); $chatId = trim((string)$chatId);
    if ($token === '' || $chatId === '') return [false, 'token/chat_id missing'];
    if (!preg_match('#^\d+:[\w-]+$#', $token)) return [false, 'invalid bot token format'];
    $url = 'https://api.telegram.org/bot' . $token . '/sendMessage';
    $payload = http_build_query(['chat_id' => $chatId, 'text' => mb_substr($text, 0, 4000), 'parse_mode' => 'HTML', 'disable_web_page_preview' => 'true']);
    $res = smpro_http($url, ['method' => 'POST', 'timeout' => 15, 'body' => $payload]);   // bot token (in URL) stays in-process, not in argv
    $j = json_decode($res['body'], true);
    if (is_array($j)) return [!empty($j['ok']), !empty($j['ok']) ? 'sent' : (string)($j['description'] ?? 'telegram error')];
    return [false, 'no response from Telegram'];
}
/** Telegram helper: discover chat id(s) from recent getUpdates (after the user messages the bot). */
function smpro_ntf_telegram_chats($token) {
    $token = trim((string)$token);
    if (!preg_match('#^\d+:[\w-]+$#', $token)) return [];
    $url = 'https://api.telegram.org/bot' . $token . '/getUpdates';
    $res = smpro_http($url, ['timeout' => 15]);   // bot token (in URL) stays in-process, not in argv
    $j = json_decode($res['body'], true);
    $chats = [];
    if (is_array($j) && !empty($j['ok'])) foreach ($j['result'] ?? [] as $up) {
        $c = $up['message']['chat'] ?? $up['channel_post']['chat'] ?? null;
        if ($c && isset($c['id'])) $chats[(string)$c['id']] = trim(($c['title'] ?? '') . ' ' . ($c['first_name'] ?? '') . ' ' . ($c['username'] ? '@' . $c['username'] : '')) ?: ('chat ' . $c['id']);
    }
    return $chats;
}

/* ---------------- log ---------------- */
function smpro_ntf_log($type, $subject, $channels, $results) {
    @is_dir(SMPRO_NTF_DIR) || @mkdir(SMPRO_NTF_DIR, 0700, true);
    $row = ['ts' => time(), 'at' => date('c'), 'type' => $type, 'subject' => $subject, 'channels' => $channels, 'results' => $results];
    @file_put_contents(SMPRO_NTF_LOG, json_encode($row, JSON_UNESCAPED_SLASHES) . "\n", FILE_APPEND | LOCK_EX);
    // keep the log bounded
    if (@filesize(SMPRO_NTF_LOG) > 512 * 1024) { $lines = @file(SMPRO_NTF_LOG, FILE_IGNORE_NEW_LINES) ?: []; @file_put_contents(SMPRO_NTF_LOG, implode("\n", array_slice($lines, -400)) . "\n", LOCK_EX); }
}
function smpro_ntf_recent($limit = 40) {
    if (!is_file(SMPRO_NTF_LOG)) return [];
    $lines = []; @exec('tail -n ' . (int)($limit + 20) . ' ' . escapeshellarg(SMPRO_NTF_LOG) . ' 2>/dev/null', $lines);
    $rows = [];
    foreach (array_reverse($lines) as $l) { $j = json_decode($l, true); if (is_array($j)) $rows[] = $j; }
    return array_slice($rows, 0, $limit);
}

/* ---------------- the public API ---------------- */
/**
 * Dispatch a notification of $type. Honours the admin's per-type channel choices.
 * $force=true ignores the per-type "on" toggle (used by the Test button).
 * @return array per-channel results.
 */
function smpro_notify($type, $subject, $body, array $meta = [], $force = false) {
    $cfg = smpro_ntf_load();
    $t = $cfg['types'][$type] ?? ['on' => true, 'email' => true, 'telegram' => true];
    if (!$force && empty($t['on'])) return ['skipped' => 'type disabled'];
    // Quiet / grouped-alerts mode: batch routine alerts into a periodic digest. Load + AI-flagged
    // maximum-danger events bypass this and send immediately (see digest.php).
    if (!$force && function_exists('smpro_dg_hold') && smpro_dg_hold($type, $meta)) {
        smpro_dg_queue($type, $subject, $body, $meta);
        return ['queued' => 'digest'];
    }
    $host = gethostname();
    $tag = strtoupper(($meta['severity'] ?? (smpro_ntf_types()[$type][2] ?? 'info')));
    $full = "[$tag] $subject\n\n$body\n\n— Safety Monitor Pro on $host\n" . date('Y-m-d H:i:s T');
    $channels = []; $results = [];
    if (!empty($cfg['email']['enabled']) && !empty($t['email'])) {
        [$ok, $d] = smpro_ntf_send_email($cfg['email']['to'] ?? [], $cfg['email']['from'] ?? '', '[SMPro] ' . $subject, $full);
        $channels[] = 'email'; $results['email'] = ['ok' => $ok, 'detail' => $d];
    }
    if (!empty($cfg['telegram']['enabled']) && !empty($t['telegram'])) {
        $html = '<b>' . htmlspecialchars($tag . ': ' . $subject) . '</b>' . "\n" . htmlspecialchars($body) . "\n\n<i>" . htmlspecialchars($host) . ' · ' . date('Y-m-d H:i') . '</i>';
        [$ok, $d] = smpro_ntf_send_telegram($cfg['telegram']['token'] ?? '', $cfg['telegram']['chat_id'] ?? '', $html);
        $channels[] = 'telegram'; $results['telegram'] = ['ok' => $ok, 'detail' => $d];
    }
    if (!empty($cfg['pushbullet']['enabled']) && !empty($t['pushbullet'])) {
        [$ok, $d] = smpro_ntf_send_pushbullet($cfg['pushbullet']['token'] ?? '', '[' . $tag . '] ' . $subject, $body . "\n\n" . $host . ' · ' . date('Y-m-d H:i'));
        $channels[] = 'pushbullet'; $results['pushbullet'] = ['ok' => $ok, 'detail' => $d];
    }
    if (!empty($cfg['whatsapp']['enabled']) && !empty($t['whatsapp'])) {
        [$ok, $d] = smpro_ntf_send_whatsapp($cfg, "*[$tag] $subject*\n" . $body . "\n\n" . $host . ' · ' . date('Y-m-d H:i'));
        $channels[] = 'whatsapp'; $results['whatsapp'] = ['ok' => $ok, 'detail' => $d];
    }
    if ($channels) smpro_ntf_log($type, $subject, $channels, $results);
    if (function_exists('smpro_audit')) smpro_audit('notify', ['type' => $type, 'channels' => implode(',', $channels)]);
    return $results ?: ['skipped' => 'no channel enabled for this type'];
}

/* Self-heal an older notify cron that was installed WITHOUT flock/timeout (pre-1.0.57). Without a lock a
 * long run + the next 15-min tick overlap and pile up → resource exhaustion. Rewrites the line once to add
 * `flock -n` (skip tick if a run is still going) + an outer `timeout`. Safe no-op if already healed/absent. */
/** INSTALL the periodic checker cron (every 15 min). This worker runs BOTH the notification checks AND the
 *  Intrusion-Monitor scan + emergency auto-block, so it must exist whenever auto-checks OR emergency/auto-block
 *  is enabled — not only when the admin flips "Auto-checks" on the Notifications page. Idempotent. */
function smpro_ntf_cron_install() {
    $f = '/etc/cron.d/smpro-notify';
    $bin = SMPRO_BASE . '/bin/notify_check.php';
    if (!is_file($bin)) return false;
    $php = is_executable('/usr/local/cpanel/3rdparty/bin/php') ? '/usr/local/cpanel/3rdparty/bin/php' : (trim((string)@shell_exec('command -v php')) ?: 'php');
    $lock = SMPRO_VARLIB . '/locks/notify.lock';
    @is_dir(dirname($lock)) || @mkdir(dirname($lock), 0700, true);
    $flock = is_executable('/usr/bin/flock') ? '/usr/bin/flock' : 'flock';
    $desired = "# Safety Monitor Pro — notifications + intrusion auto-response (every 15 min; flock = no overlap)\n"
             . "*/15 * * * * root $flock -n $lock timeout 600 $php $bin >/dev/null 2>&1\n";
    if (is_file($f) && (string)@file_get_contents($f) === $desired) return true;
    @file_put_contents($f, $desired); @chmod($f, 0644);
    return true;
}
/** True if the Intrusion Monitor needs the periodic checker (emergency auto-response or auto-block enabled).
 *  Notifications "Auto-check" manages the cron file directly; this covers the intrusion auto-response case
 *  that previously had NO scheduler at all. */
function smpro_ntf_cron_wanted() {
    if (function_exists('smpro_in_cfg')) { $in = smpro_in_cfg(); if (!empty($in['emergency']) || !empty($in['auto_block'])) return true; }
    return false;
}
/** Boot-time self-heal: make sure the checker cron EXISTS whenever it's wanted (so emergency auto-block runs
 *  even if the admin never opened the Notifications page). Never removes it here — that's the toggle's job. */
function smpro_ntf_cron_sync() {
    if (smpro_ntf_cron_wanted() && !is_file('/etc/cron.d/smpro-notify')) smpro_ntf_cron_install();
    else smpro_ntf_cron_heal();
}
function smpro_ntf_cron_heal() {
    $f = '/etc/cron.d/smpro-notify';
    if (!is_file($f)) return;                                   // auto-checks not enabled → nothing to heal
    $cur = (string)@file_get_contents($f);
    if (strpos($cur, 'flock') !== false) return;                // already has a lock → done
    $php = is_executable('/usr/local/cpanel/3rdparty/bin/php') ? '/usr/local/cpanel/3rdparty/bin/php' : (trim((string)@shell_exec('command -v php')) ?: 'php');
    $bin = SMPRO_BASE . '/bin/notify_check.php';
    $lock = SMPRO_VARLIB . '/locks/notify.lock';
    @is_dir(dirname($lock)) || @mkdir(dirname($lock), 0700, true);
    $flock = is_executable('/usr/bin/flock') ? '/usr/bin/flock' : 'flock';
    $line = "*/15 * * * * root $flock -n $lock timeout 600 $php $bin >/dev/null 2>&1\n";
    @file_put_contents($f, "# Safety Monitor Pro — notification checker (every 15 min; flock = no overlap)\n" . $line);
    @chmod($f, 0644);
}

/* ---------------- live event checker (deduped) ---------------- */
function smpro_ntf_state_load() { $d = is_file(SMPRO_NTF_STATE) ? json_decode((string)@file_get_contents(SMPRO_NTF_STATE), true) : null; return is_array($d) ? $d : []; }
function smpro_ntf_state_save($s) { @is_dir(SMPRO_NTF_DIR) || @mkdir(SMPRO_NTF_DIR, 0700, true); $t = SMPRO_NTF_STATE . '.tmp'; @file_put_contents($t, json_encode($s, JSON_UNESCAPED_SLASHES), LOCK_EX); @chmod($t, 0600); @rename($t, SMPRO_NTF_STATE); }

/**
 * Time-windowed mail analysis from exim logs (read-only, bounded).
 * OUTBOUND: count locally-originated messages (script `cwd=/home/<acct>` or authenticated `A=<id>`)
 *           per account in the last 1 hour and last 12 hours — so "bulk" is judged by real rate, not a
 *           fixed log-line count. INBOUND SPAM: count incoming mail that SpamAssassin scored as spam or
 *           that exim rejected as spam/RBL within the given lookback window.
 * Returns: ['out_hour'=>[acct=>n], 'out_12h'=>[acct=>n], 'inbound_spam'=>n, 'inbound_samples'=>[...]].
 */
function smpro_ntf_mail_scan(int $inboundLookbackSecs = 21600): array {
    $out = ['out_hour' => [], 'out_12h' => [], 'inbound_spam' => 0, 'inbound_samples' => [], 'inbound_recips' => [], 'inbound_senders' => []];
    $log = '/var/log/exim_mainlog';
    $now = time(); $cut1h = $now - 3600; $cut12h = $now - 43200; $cutIn = $now - max(3600, $inboundLookbackSecs);

    // --- outbound: count locally-originated messages by account, time-windowed ---
    // cPanel/exim logs TWO distinct line types for local origin:
    //   • script sends → a standalone line  "<ts> cwd=/home/<acct> N args: /usr/sbin/sendmail …"  (P=local)
    //   • authenticated (webmail/SMTP AUTH) → an arrival line  "<ts> … <= … A=dovecot_login:<user> …"
    // These are disjoint (a script send is P=local, not A=), so counting both does not double-count.
    if (is_readable($log)) {
        $raw = (string)@shell_exec("timeout 30 tail -n 300000 " . escapeshellarg($log)
             . " 2>/dev/null | grep -aE 'cwd=/home/| <= .* A=' | tail -n 80000");
        foreach (explode("\n", $raw) as $l) {
            if ($l === '') continue;
            $ts = strtotime(substr($l, 0, 19));
            if (!$ts || $ts < $cut12h) continue;                      // older than 12h → ignore
            if (preg_match('#cwd=/home/([^/ ]+)#', $l, $m)) {
                $acct = $m[1];                                         // script-sent: home account that ran it
            } elseif (strpos($l, ' <= ') !== false && preg_match('#\bA=[^\s:]+:([^\s]+)#', $l, $m)) {
                $acct = $m[1];                                         // authenticated: the mailbox id after the colon
            } elseif (strpos($l, ' <= ') !== false && preg_match('#\bA=([^\s]+)#', $l, $m)) {
                $acct = $m[1];                                         // authenticated (no colon form)
            } else continue;
            $out['out_12h'][$acct] = ($out['out_12h'][$acct] ?? 0) + 1;
            if ($ts >= $cut1h) $out['out_hour'][$acct] = ($out['out_hour'][$acct] ?? 0) + 1;
        }
        arsort($out['out_12h']); arsort($out['out_hour']);
    }

    // --- inbound spam: SpamAssassin score lines in mainlog + exim_rejectlog spam/RBL rejects ---
    $spamLines = [];
    if (is_readable($log)) {
        // cPanel/exim logs a spam verdict as e.g. "... spam acl ... score=12.3" / "X-Spam-..." / "Apache SpamAssassin"
        $rawS = (string)@shell_exec("timeout 25 tail -n 200000 " . escapeshellarg($log)
              . " 2>/dev/null | grep -aiE 'spam( |-|=)|sa score|spamassassin|x-spam' | tail -n 5000");
        foreach (explode("\n", $rawS) as $l) if ($l !== '') $spamLines[] = $l;
    }
    foreach (['/var/log/exim_rejectlog'] as $rl) {
        if (!is_readable($rl)) continue;
        $rawR = (string)@shell_exec("timeout 20 tail -n 50000 " . escapeshellarg($rl)
              . " 2>/dev/null | grep -aiE 'spam|spamhaus|rbl|blacklist|blocked using' | tail -n 5000");
        foreach (explode("\n", $rawR) as $l) if ($l !== '') $spamLines[] = $l;
    }
    $ids = [];
    foreach ($spamLines as $l) {
        $ts = strtotime(substr($l, 0, 19));
        if (!$ts || $ts < $cutIn) continue;                           // only within the lookback window
        $out['inbound_spam']++;
        if (count($out['inbound_samples']) < 5) $out['inbound_samples'][] = trim(mb_substr($l, 20, 180));
        // WHO was it from / to? (so the admin can warn the targeted local mailbox)
        if (preg_match('/\bF=<([^>]+)>/', $l, $m)) { $s = strtolower($m[1]); $out['inbound_senders'][$s] = ($out['inbound_senders'][$s] ?? 0) + 1; }
        if (preg_match('/\b(?:for|=>|->)\s+<?([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})/', $l, $m)) { $r = strtolower(rtrim($m[1], '>')); $out['inbound_recips'][$r] = ($out['inbound_recips'][$r] ?? 0) + 1; }
        if (preg_match('/\b([0-9A-Za-z]{6}-[0-9A-Za-z]{6}-[0-9A-Za-z]{2})\b/', $l, $m)) $ids[$m[1]] = 1;   // exim message id → resolve recipient below
    }
    // Resolve the local RECIPIENT for spam message-ids that had none on the matched line — exim's arrival line
    // ("<id> <= <sender> ... for <rcpt>") carries it. One bounded grep over the mainlog tail.
    $need = array_slice(array_keys($ids), 0, 60);
    if ($need && is_readable($log)) {
        $pat = implode('|', array_map(fn($x) => preg_quote($x, '/'), $need));
        $rawF = (string)@shell_exec("timeout 15 tail -n 200000 " . escapeshellarg($log)
              . " 2>/dev/null | grep -aE " . escapeshellarg($pat)
              . " | grep -aoE 'for [A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+' | sort | uniq -c | sort -rn | head -20");
        foreach (explode("\n", trim($rawF)) as $line) {
            if (preg_match('/^\s*(\d+)\s+for\s+(\S+@\S+)/', $line, $m)) { $r = strtolower($m[2]); $out['inbound_recips'][$r] = ($out['inbound_recips'][$r] ?? 0) + (int)$m[1]; }
        }
    }
    arsort($out['inbound_recips']); arsort($out['inbound_senders']);
    return $out;
}

/**
 * Evaluate live conditions; notify only when a condition's signature changed
 * since the last run. Returns a summary array of what fired / what was checked.
 */
function smpro_notify_run_checks($verbose = false) {
    $cfg = smpro_ntf_load();
    $st = smpro_ntf_state_load();
    $fired = []; $checked = [];
    $thr = $cfg['thresholds'] ?? [];

    // Which channels will actually deliver this type right now? Signature of that set
    // is tracked so that enabling a NEW channel (e.g. WhatsApp) re-fires a still-true
    // condition that already alerted on the old channels.
    $chanSig = function ($type) use ($cfg) {
        $t = $cfg['types'][$type] ?? [];
        $on = '';
        if (!empty($cfg['email']['enabled'])     && !empty($t['email']))     $on .= 'e';
        if (!empty($cfg['telegram']['enabled'])  && !empty($t['telegram']))  $on .= 't';
        if (!empty($cfg['pushbullet']['enabled']) && !empty($t['pushbullet'])) $on .= 'p';
        if (!empty($cfg['whatsapp']['enabled'])  && !empty($t['whatsapp']))  $on .= 'w';
        return $on;
    };
    $remindSecs = max(1, (int)($thr['remind_hours'] ?? 12)) * 3600;  // re-alert a persistent condition this often
    $now = time();
    // $remindOverride (seconds) lets a specific check re-alert on its own cadence (e.g. inbound spam every 6h)
    // instead of the global remind window.
    $maybe = function ($type, $sig, $subject, $body, $meta = [], $remindOverride = 0) use (&$st, &$fired, $cfg, $chanSig, $remindSecs, $now) {
        if (empty($cfg['types'][$type]['on'])) return;
        $prev = $st[$type] ?? null;
        if (is_string($prev)) $prev = ['sig' => $prev, 'ch' => '', 'ts' => 0];   // migrate legacy state
        if ($sig === 'clear') { $st[$type] = ['sig' => 'clear', 'ch' => '', 'ts' => $now]; return; }
        $ch = $chanSig($type);
        if ($ch === '') return;                                   // no channel yet → keep pending, fire when one turns on
        $window   = $remindOverride > 0 ? $remindOverride : $remindSecs;
        $sameSig  = $prev && ($prev['sig'] ?? null) === $sig;
        $sameChan = $prev && ($prev['ch']  ?? '')   === $ch;
        $fresh    = $prev && (int)($prev['ts'] ?? 0) > 0 && ($now - (int)$prev['ts']) < $window;
        if ($sameSig && $sameChan && $fresh) return;              // unchanged, same channels, still within remind window
        $st[$type] = ['sig' => $sig, 'ch' => $ch, 'ts' => $now];
        smpro_notify($type, $subject, $body, $meta);
        $fired[] = $type;
    };

    // 1) active malware (Imunify)
    $bin = is_executable('/usr/bin/imunify360-agent') ? '/usr/bin/imunify360-agent' : '';
    if ($bin) {
        $checked[] = 'malware_active';
        $raw = (string)@shell_exec('timeout 40 ' . $bin . ' malware malicious list --limit 500 --json 2>/dev/null');
        $j = json_decode($raw, true); $items = is_array($j) ? ($j['items'] ?? []) : [];
        $n = count($items);
        if ($n > 0) {
            $accts = array_values(array_unique(array_map(fn($r) => $r['username'] ?? '', $items)));
            $maybe('malware_active', 'mal:' . $n, "$n currently-malicious file(s) detected",
                "Accounts: " . implode(', ', array_slice($accts, 0, 8)) . "\nOpen Forensics / Imunify360 Reports to clean or delete.", ['severity' => 'critical']);
        } else $maybe('malware_active', 'clear', '', '');

        // 1b) database injections (Imunify flagged malicious DB content)
        $checked[] = 'db_injection';
        $rawd = (string)@shell_exec('timeout 60 ' . $bin . ' malware history list --limit 8000 --json 2>/dev/null');
        $jd = json_decode($rawd, true); $itemsd = is_array($jd) ? ($jd['items'] ?? []) : [];
        $dbKeys = [];   // latest event per (db|table|field|row); keep only 'found'
        foreach ($itemsd as $r) {
            if (($r['resource_type'] ?? '') !== 'db') continue;
            $k = ($r['db_name'] ?? '') . '|' . ($r['table_name'] ?? '') . '|' . ($r['table_field'] ?? '') . '|' . ($r['table_row_inf'] ?? '');
            $ct = (int)($r['ctime'] ?? 0);
            if (!isset($dbKeys[$k]) || $ct >= $dbKeys[$k]['ct']) $dbKeys[$k] = ['ct' => $ct, 'ev' => (string)($r['event'] ?? ''), 'u' => (string)($r['file_user'] ?? '')];
        }
        $found = array_filter($dbKeys, fn($x) => $x['ev'] === 'found');
        $thrDb = (int)($thr['db_injections'] ?? 1);
        if (count($found) >= max(1, $thrDb)) {
            $accts = array_values(array_unique(array_filter(array_map(fn($x) => $x['u'], $found))));
            $maybe('db_injection', 'dbinj:' . count($found), count($found) . ' database injection(s) flagged by Imunify',
                'Affected accounts: ' . implode(', ', array_slice($accts, 0, 10)) . (count($accts) > 10 ? ' +' . (count($accts) - 10) : '')
                . "\nOpen DB Cleanup to back up & clean the affected databases.", ['severity' => 'critical']);
        } else $maybe('db_injection', 'clear', '', '');
    }

    // 2) suspended accounts (whmapi1)
    if (is_executable('/usr/local/cpanel/bin/whmapi1')) {
        $checked[] = 'account_suspended';
        $raw = (string)@shell_exec('timeout 25 /usr/local/cpanel/bin/whmapi1 --output=json listsuspended 2>/dev/null');
        $j = json_decode($raw, true); $list = $j['data']['accts'] ?? [];
        $names = array_values(array_filter(array_map(fn($r) => is_array($r) ? ($r['user'] ?? '') : (string)$r, $list)));
        sort($names);
        if ($names) $maybe('account_suspended', 'susp:' . md5(implode(',', $names)), count($names) . ' suspended account(s)',
            "Suspended: " . implode(', ', array_slice($names, 0, 15)), ['severity' => 'high']);
        else $maybe('account_suspended', 'clear', '', '');
    }

    // 3) disk usage
    $checked[] = 'disk_high';
    $dfRaw = (string)@shell_exec("df -P -x tmpfs -x devtmpfs 2>/dev/null | awk 'NR>1{gsub(\"%\",\"\",$5); print $6\" \"$5}'");
    $over = [];
    foreach (explode("\n", trim($dfRaw)) as $line) { if (!preg_match('/^(\S+)\s+(\d+)$/', trim($line), $m)) continue; if ((int)$m[2] >= (int)($thr['disk_pct'] ?? 90)) $over[] = $m[1] . ' ' . $m[2] . '%'; }
    if ($over) $maybe('disk_high', 'disk:' . md5(implode(',', $over)), 'Disk usage high', implode("\n", $over), ['severity' => 'high']);
    else $maybe('disk_high', 'clear', '', '');

    // 4) load average
    $checked[] = 'load_high';
    $load = (float)(explode(' ', (string)@file_get_contents('/proc/loadavg'))[0] ?? 0);
    if ($load >= (float)($thr['load'] ?? 20)) {
        $cause = trim((string)@shell_exec("ps -eo pcpu,user,comm --sort=-pcpu --no-headers 2>/dev/null | head -6 | awk '{printf \"• %s%% %s (%s)\\n\", \$1, \$3, \$2}'"));
        $cores = (int)@shell_exec('nproc 2>/dev/null'); $pct = $cores > 0 ? round($load / $cores * 100) : 0;
        $maybe('load_high', 'load:' . round($load), 'Server load high', '1-min load average: ' . $load . ($cores ? ' (' . $pct . '% of ' . $cores . ' cores)' : '') . "\n\nTop CPU consumers (cause):\n" . ($cause ?: 'n/a'), ['severity' => 'medium']);
    } else $maybe('load_high', 'clear', '', '');

    // 5) real-time intrusion / web-attack alerts (engine in includes/intrusion.php)
    if (function_exists('smpro_im_alert_scan') && function_exists('smpro_im_modsec_log') && smpro_im_modsec_log() !== '') {
        $checked[] = 'intrusion';
        $al = smpro_im_alert_scan();
        $parts = []; $sig = [];
        foreach (['selfattack', 'critical', 'spike', 'distributed'] as $k) if (isset($al[$k])) { $parts[] = $al[$k]['subject'] . "\n" . $al[$k]['body']; $sig[] = $al[$k]['sig']; }
        if ($parts) $maybe('intrusion_attack', 'atk:' . md5(implode('|', $sig)), 'Web-attack activity detected', implode("\n\n", $parts), ['severity' => (isset($al['critical']) || isset($al['selfattack'])) ? 'critical' : 'high']);
        else $maybe('intrusion_attack', 'clear', '', '');
        if (isset($al['breach']))    $maybe('intrusion_breach', $al['breach']['sig'], $al['breach']['subject'], $al['breach']['body'], ['severity' => 'critical']);
        else $maybe('intrusion_breach', 'clear', '', '');
        if (isset($al['autoblock'])) $maybe('intrusion_autoblock', $al['autoblock']['sig'], $al['autoblock']['subject'], $al['autoblock']['body'], ['severity' => 'high']);
        if (isset($al['emergency'])) $maybe('intrusion_emergency', $al['emergency']['sig'], $al['emergency']['subject'], $al['emergency']['body'], ['severity' => 'critical']);
        // routine scanner auto-blocks → low-urgency grouped digest via the Auto-block type (INFO, not CRITICAL)
        if (isset($al['emergency_blocks'])) $maybe('intrusion_autoblock', $al['emergency_blocks']['sig'], $al['emergency_blocks']['subject'], $al['emergency_blocks']['body'], ['severity' => 'info']);
    }

    // 5) PHP Harden drift (locked files that lost immutability) — self-contained lsattr check
    if (is_dir(SMPRO_VARLIB . '/php_harden')) {
        $checked[] = 'harden_drift';
        $isLocked = function ($p) {
            $out = (string)@shell_exec('lsattr -d ' . escapeshellarg($p) . ' 2>/dev/null');
            $flags = preg_split('/\s+/', trim($out))[0] ?? '';
            return strpos($flags, 'i') !== false;
        };
        $drift = [];
        foreach (glob(SMPRO_VARLIB . '/php_harden/*.json') ?: [] as $mf) {
            $m = json_decode((string)@file_get_contents($mf), true);
            if (!is_array($m) || ($m['status'] ?? '') !== 'locked') continue;
            foreach (($m['protected_files'] ?? []) as $f) {
                $p = $f['path'] ?? ''; if ($p && is_file($p) && !$isLocked($p)) $drift[] = ($m['user'] ?? '?') . ': ' . basename($p);
            }
        }
        if ($drift) $maybe('harden_drift', 'drift:' . md5(implode(',', $drift)), count($drift) . ' protected file(s) no longer locked', implode("\n", array_slice($drift, 0, 12)), ['severity' => 'high']);
        else $maybe('harden_drift', 'clear', '', '');
    }

    // 6) outbound bulk mail + inbound spam (time-windowed exim analysis)
    if (is_readable('/var/log/exim_mainlog')) {
        $inboundRemind = max(1, (int)($thr['inbound_spam_remind_hours'] ?? 6)) * 3600;
        $scan = smpro_ntf_mail_scan($inboundRemind);

        // 6a) OUTBOUND bulk: flag an account that sent > mail_out_hour in the last hour, OR >= mail_out_12h over 12h.
        //     Below both → not treated as spam here (volume is normal); the Spam & Phishing AI scan judges content.
        $checked[] = 'spam_outbreak';
        $perHour = max(1, (int)($thr['mail_out_hour'] ?? 100));
        $per12h  = max(1, (int)($thr['mail_out_12h'] ?? ($thr['spam_events'] ?? 300)));
        $hot = [];   // acct => "reason" line
        foreach ($scan['out_12h'] as $a => $n12) {
            $n1 = (int)($scan['out_hour'][$a] ?? 0);
            if ($n1 > $perHour)      $hot[$a] = "$a: $n1/hour (12h: $n12) — over " . $perHour . "/hour";
            elseif ($n12 >= $per12h) $hot[$a] = "$a: $n12 in 12h (now " . $n1 . "/hour) — over " . $per12h . "/12h";
        }
        if ($hot) {
            $maybe('spam_outbreak', 'spam:' . md5(implode(',', array_keys($hot))) . ':' . count($hot),
                count($hot) . ' account(s) sending bulk outbound mail',
                implode("\n", array_slice($hot, 0, 8)) . "\n\nThreshold: > $perHour/hour or ≥ $per12h/12h (editable in Notifications)."
                . "\nOpen Spam & Phishing to scan content / suspend / block outgoing.", ['severity' => 'high']);
        } else $maybe('spam_outbreak', 'clear', '', '');

        // 6b) INBOUND spam: any spam-scored / spam-rejected incoming mail in the window → alert at least every 6h.
        $checked[] = 'inbound_spam';
        $minIn = max(1, (int)($thr['inbound_spam_min'] ?? 1));
        if ((int)$scan['inbound_spam'] >= $minIn) {
            $hrs = max(1, (int)($thr['inbound_spam_remind_hours'] ?? 6));
            $body = $scan['inbound_spam'] . " incoming message(s) scored/marked as spam in the last $hrs h.";
            if (!empty($scan['inbound_recips'])) {
                $rl = []; foreach (array_slice($scan['inbound_recips'], 0, 10, true) as $r => $n) $rl[] = $r . ' (' . $n . ')';
                $body .= "\n\n📥 Local recipient(s) targeted — warn them:\n• " . implode("\n• ", $rl);
            }
            if (!empty($scan['inbound_senders'])) {
                $sl = []; foreach (array_slice($scan['inbound_senders'], 0, 6, true) as $s => $n) $sl[] = $s . ' (' . $n . ')';
                $body .= "\n\n📤 Top sender(s) (often spoofed): " . implode(', ', $sl);
            }
            if (!empty($scan['inbound_samples'])) $body .= "\n\nSamples:\n• " . implode("\n• ", $scan['inbound_samples']);
            $body .= "\n\nReview Spam & Phishing / mailbox filters. (Re-alerted at most every $hrs h.)";
            // signature is bucketed by remind window so it re-fires every ~6h while spam keeps arriving
            $bucket = (int)floor($now / $inboundRemind);
            $maybe('inbound_spam', 'inspam:' . $bucket, 'Inbound spam detected', $body, ['severity' => 'medium'], $inboundRemind);
        } else $maybe('inbound_spam', 'clear', '', '');
    }

    // 7) backup failed (JetBackup5 — a job whose last run did not complete)
    if (is_executable('/usr/bin/jetbackup5api')) {
        $checked[] = 'backup_failed';
        $api = function ($func, $data = '') {
            $out = (string)@shell_exec('timeout 60 /usr/bin/jetbackup5api -F ' . escapeshellarg($func) . ' -O json' . ($data !== '' ? ' -D ' . escapeshellarg($data) : '') . ' 2>/dev/null');
            $j = json_decode($out, true); return is_array($j) ? $j : [];
        };
        $list = $api('listBackupJobs');
        $jobs = $list['data']['jobs'] ?? $list['data'] ?? [];
        $failed = [];
        if (is_array($jobs)) foreach ($jobs as $j) {
            $id = (string)($j['_id'] ?? ''); if ($id === '') continue;
            $full = $api('getBackupJob', '_id=' . $id)['data'] ?? $j;
            if (!empty($full['running'])) continue;
            $lr = strtotime((string)($full['last_run'] ?? '')) ?: 0;
            $lc = strtotime((string)($full['last_completed'] ?? '')) ?: 0;
            if ($lr > 0 && $lc < $lr) $failed[] = (string)($full['name'] ?? $id);
        }
        if ($failed) $maybe('backup_failed', 'bk:' . md5(implode(',', $failed)), count($failed) . ' backup job(s) failed / incomplete',
            "Jobs: " . implode(', ', array_slice($failed, 0, 12)) . "\nOpen Backup Monitor to re-run them.", ['severity' => 'high']);
        else $maybe('backup_failed', 'clear', '', '');
    }

    // 8) license expiry — MANDATORY reminders (2 days, 1 day, then at expiry). Force-sent,
    //    bypasses the per-type on/off toggle. Each threshold fires once per license/expiry.
    if (function_exists('smpro_lic_state')) {
        $checked[] = 'license_expiry';
        $ls  = smpro_lic_state();
        $key = (string)($ls['key'] ?? '');
        $exp = trim((string)($ls['expiry'] ?? ''));
        $expTs = $exp !== '' ? (is_numeric($exp) ? (int)$exp : strtotime($exp)) : 0;
        if ($key !== '' && $expTs) {
            $rem = $expTs - time();
            $bucket = null; $subject = ''; $sev = 'high';
            if ($rem <= 0)            { $bucket = 'expired'; $subject = 'License has EXPIRED — renew now'; $sev = 'critical'; }
            elseif ($rem <= 86400)    { $bucket = '1day';    $subject = 'License expires in ~1 day — renew now'; $sev = 'critical'; }
            elseif ($rem <= 172800)   { $bucket = '2days';   $subject = 'License expires in ~2 days — renew soon'; }
            $prev = $st['license_expiry'] ?? null;
            $prev = is_array($prev) ? ($prev['sig'] ?? '') : (string)$prev;
            if ($bucket !== null) {
                $sig = 'licexp:' . $bucket . ':' . md5($key . '|' . $exp);
                if ($prev !== $sig) {
                    $body = 'License key: ' . substr($key, 0, 8) . "…\nExpires: " . $exp
                          . ($rem > 0 ? "\nTime left: ~" . max(1, (int)ceil($rem / 3600)) . ' hour(s).' : "\nThe license has expired — the plugin is now locked until you re-activate.")
                          . "\n\nRenew the license, then open the License page in the plugin and re-activate this server.";
                    smpro_notify('license_expiry', $subject, $body, ['severity' => $sev], true);  // force = mandatory
                    $st['license_expiry'] = $sig;
                    $fired[] = 'license_expiry';
                }
            } else {
                $st['license_expiry'] = 'clear';   // > 2 days away → reset so the cycle re-fires next renewal period
            }
        }
    }

    smpro_ntf_state_save($st);
    return ['fired' => $fired, 'checked' => $checked, 'at' => date('Y-m-d H:i:s')];
}
