<?php
/**
 * includes/notify.php - central Notifications layer for Safety Monitor Pro.
 *
 * One API - smpro_notify($type, $subject, $body, $meta) - that every module can
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
define('SMPRO_NTF_HELD',  SMPRO_VARLIB . '/notifications/held.jsonl');   // every alert evaluated and NOT sent, with the reason

/** Catalogue of notification types: key => [label, description, severity]. */
function smpro_ntf_types() {
    return [
        'malware_active'   => ['Active malware detected', 'Imunify360 reports one or more currently-malicious files.', 'critical'],
        'sysupd_new'       => ['System updates available', 'New package updates (kernel, PHP, web, mail, security) or a newer cPanel build appeared; the message says what and whether they will be applied automatically.', 'medium'],
        'sysupd_result'    => ['System update applied', 'An automatic update finished: how many packages, and the service check afterwards.', 'info'],
        'sysupd_problem'   => ['System update problem', 'A check or download broke, or a service needed attention after an update: the diagnosis, the repair attempted, and what is left for a person.', 'high'],
        'compromise_check' => ['Compromise Check (scheduled scan)', 'The scheduled Compromise Check finished: server checks that are not OK and accounts that gained a door.', 'high'],
        'db_injection'     => ['Database injection detected', 'Imunify360 flagged malicious content injected into a database (spam links, scripts, backdoors).', 'critical'],
        'login_bruteforce' => ['Login brute-force / spike', 'A source IP crossed the failed-login threshold in the window.', 'high'],
        'account_suspended'=> ['Account suspended', 'A cPanel account became suspended.', 'high'],
        'backup_failed'    => ['Backup failed', 'A JetBackup job failed or did not complete.', 'high'],
        'disk_high'        => ['Disk usage high', 'A filesystem crossed the disk-usage threshold.', 'high'],
        'load_high'        => ['Server load high', 'Load average crossed the threshold.', 'medium'],
        'service_down'     => ['Service down', 'The Service Monitor found a watched service (Apache, MySQL, Exim, LFD, …) stopped. Includes whether auto-restart was attempted.', 'high'],
        'service_up'       => ['Service recovered', 'A watched service that was down is running again (recovered on its own or restarted by SM Pro).', 'info'],
        'service_repaired' => ['Service repaired', 'A watched service was down for a reason a plain restart cannot clear (a stale PHP-FPM socket, flushed firewall rules, a broken pool file). SM Pro found the cause, fixed it, and names it.', 'high'],
        'harden_drift'     => ['PHP Harden drift', 'A file that PHP Harden locked is no longer immutable (possible tamper).', 'high'],
        'spam_outbreak'    => ['Outbound spam spike', 'An account sent an unusually high volume of outbound mail (over the per-hour or per-12h threshold).', 'high'],
        'inbound_spam'     => ['Inbound spam detected', 'Incoming emails were scored/marked as spam (SpamAssassin) or rejected as spam. Re-checked at least every 6 hours.', 'medium'],
        'integrity_tamper' => ['Plugin integrity / tamper', 'A protected plugin file was modified or the signed integrity manifest is invalid — the plugin entered Protected Mode. Always sent.', 'critical'],
        'intrusion_attack' => ['Web-attack activity', 'Real-time WAF attacks: critical rules, a domain under heavy attack, or one IP scanning many domains.', 'high'],
        'intrusion_breach' => ['Possible compromise', 'An exploit-class attack was served 2xx/3xx AND the domain has freshly-changed PHP files (likely successful breach).', 'critical'],
        'intrusion_upload_cluster' => ['Malicious upload cluster', 'Many malicious-upload requests were ACCEPTED (2xx) on one upload endpoint from multiple IPs in a short window — the app is accepting attacker files even if no .php file changed. Includes a content scan of the upload dirs to say whether a web-shell landed.', 'critical'],
        'intrusion_autoblock' => ['Attacker auto-blocked', 'The Intrusion Monitor auto-blocked one or more attacker IPs (CSF / Cloudflare).', 'high'],
        'intrusion_emergency' => ['Emergency actions', 'EMERGENCY auto-response fired: an attacked site whose files changed was hardened and any web-shells quarantined.', 'critical'],
        'hub_bruteforce_lock' => ['Remote-control attempts / lock', 'Wrong control-password attempts from a managing hub, or the resulting 24h lock/reset on remote control.', 'critical'],
        'license_expiry'   => ['License expiry / renewal', 'Mandatory reminders before the license expires (2 days, 1 day, then at expiry). Always sent — cannot be turned off.', 'critical'],
        'sync_loss'        => ['License server unreachable', 'This server could not reach the main license server for several hours — sent so you can restore connectivity or contact support before the plugin stops.', 'critical'],
        'server_reboot'    => ['Server reboot', 'The server rebooted — classifies it as a clean/administrative reboot or an unexpected crash / power loss (no clean shutdown recorded).', 'high'],
        'foreign_login'    => ['Foreign successful login', 'A successful login from an IP OUTSIDE your home region — over SSH, or through the cPanel panel or webmail, which is the door most account takeovers use. A strong compromise signal if it was not you.', 'high'],
        'home_region_unset' => ['Home region not set', 'No home region is configured, so every location-based check (foreign logins, File Manager writes from abroad, residential auto-block protection) is switched off rather than guessing. Set it once in Intrusion Monitor — the plugin suggests the country this server is in.', 'high'],
        'fm_foreign_write' => ['File Manager write from outside your region', 'A cPanel account wrote files through File Manager from an address OUTSIDE your home region — and, at critical severity, wrote a file and deleted it seconds later, which is the fingerprint of an automated account-takeover tool testing the account before dropping a phishing kit. A stolen password never fails a login, so this is the earliest signal there is.', 'critical'],
        'honeytoken_login' => ['Decoy account login', 'Someone signed in to (or tried) a decoy cPanel account that exists for no customer and is never used. That cannot be legitimate: a success is a confirmed leaked-credential list with no false-positive possibility; a failed attempt means the account name is already on somebody\'s list.', 'critical'],
        'login_geo_anomaly' => ['Account signed in from several countries', 'One cPanel/webmail account was signed into successfully from several different countries within a week — the shape of a stolen password, even when each individual login looks ordinary.', 'high'],
        'bot_autoblock'    => ['Bot Guard auto-block', 'A gray-listed automated client crossed the attack-signature threshold inside the window and was blocked (CSF / Cloudflare per Intrusion settings). Lists each address and why.', 'high'],
        'bot_pending'      => ['Bots awaiting your decision', 'New automated clients that could not be verified as official crawlers are waiting in Bot Guard for allow / block / ignore. At most one notice per 6 hours.', 'medium'],
        'mem_pressure'     => ['Memory / swap pressure', 'Available RAM is nearly exhausted and swap is filling — the kernel may start killing processes (OOM).', 'high'],
        'lve_resource'     => ['CloudLinux account resource limits', 'Accounts repeatedly hitting their CloudLinux LVE limits (CPU / IO / entry-processes / processes) — the per-tenant caps that actually slow customer sites on shared hosting.', 'medium'],
        'plugin_mode_change' => ['Protection mode changed', 'Someone switched the plugin master mode (Enabled / Dry-Run / Disabled) — so a guard being stood down is never silent.', 'high'],
        'profile_apply'    => ['Protection profile applied', 'A Server Tuning / protection profile was applied, changing the server\'s security posture.', 'medium'],
        'update_available' => ['Plugin update available', 'A newer SM Pro build is available on your channel while auto-update is off — sent once per version so you can review and install it.', 'info'],
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
                         // OR at least mail_out_12h emails over 12 hours. Below both -> treated as normal (not spam),
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

/** Ensure the WhatsApp gateway's IP(s) are in the firewall allowlist so our own auto-block / CSF never
 *  blocks the gateway host - which would silently break WhatsApp alerts. Resolves a hostname to its IPs,
 *  is idempotent, and degrades safely if CSF is absent (plugin allowlist only). Returns the IPs allow-listed. */
function smpro_ntf_wa_allowlist($baseUrl) {
    $baseUrl = trim((string)$baseUrl);
    if ($baseUrl === '' || !function_exists('smpro_im_allow_ip')) return [];
    $host = parse_url($baseUrl, PHP_URL_HOST);
    if (!$host) $host = parse_url('http://' . preg_replace('#^/*#', '', $baseUrl), PHP_URL_HOST);   // tolerate a scheme-less value
    if (!$host) return [];
    $ips = [];
    if (filter_var($host, FILTER_VALIDATE_IP)) $ips[] = $host;
    else { $r = @gethostbynamel($host); if (is_array($r)) $ips = $r; }
    $done = [];
    foreach (array_slice(array_values(array_unique($ips)), 0, 4) as $ip) {
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) { $done[] = $ip; continue; }   // private/reserved are never auto-blocked - count as covered, no CSF churn
        $res = smpro_im_allow_ip($ip); if (!empty($res['ok'])) $done[] = $ip;
    }
    if ($done && function_exists('smpro_audit')) smpro_audit('whatsapp_gateway_allowlist', ['host' => $host, 'ips' => $done]);
    return $done;
}
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
    // smpro_host_port() brackets an IPv6 literal - an admin who enters a bare v6 SMTP address would
    // otherwise get "connection failed" with no hint that the address itself was mis-parsed.
    $target = ($secure === 'ssl' ? 'ssl://' : '')
            . (function_exists('smpro_host_port') ? smpro_host_port((string)$host, (int)$port) : $host . ':' . $port);
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
/** Block an IPv6 literal that the IPv4-oriented reserved-range filter misses: loopback (::1), unspecified (::),
 *  link-local (fe80::/10), unique-local/ULA (fc00::/7), and IPv4-mapped (::ffff:a.b.c.d) forms whose embedded
 *  IPv4 is itself private/reserved (PHP's NO_RES_RANGE does not catch the mapped form). $ip is an
 *  already-FILTER_VALIDATE_IP-valid address. Returns a reason string, or '' if the address is allowed. */
function smpro_ntf_ip6_unsafe($ip) {
    if (strpos($ip, ':') === false) return '';                    // IPv4 - handled by the caller's own checks
    $b = @inet_pton($ip);
    if ($b === false || strlen($b) !== 16) return '';             // not a 16-byte IPv6 address
    if ($b === str_repeat("\0", 15) . "\x01") return 'IPv6 loopback (::1) not allowed';
    if ($b === str_repeat("\0", 16))          return 'IPv6 unspecified (::) not allowed';
    $o = function ($i) use ($b) { return ord($b[$i]); };
    if ($o(0) === 0xfe && ($o(1) & 0xc0) === 0x80) return 'IPv6 link-local (fe80::/10) not allowed';
    if (($o(0) & 0xfe) === 0xfc)                   return 'IPv6 unique-local (fc00::/7) not allowed';
    // IPv4-mapped ::ffff:a.b.c.d - re-validate the embedded IPv4 against the private/reserved ranges.
    if (substr($b, 0, 10) === str_repeat("\0", 10) && $o(10) === 0xff && $o(11) === 0xff) {
        $v4 = $o(12) . '.' . $o(13) . '.' . $o(14) . '.' . $o(15);
        if (!filter_var($v4, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)
            || strpos($v4, '169.254.') === 0 || strpos($v4, '127.') === 0)
            return 'IPv4-mapped IPv6 to a private/reserved address (' . $v4 . ')';
    }
    return '';
}
/** SSRF guard: an admin-set base URL must be http(s) and must NOT point at loopback, private, link-local,
 *  or cloud-metadata addresses (else a tampered config could make this root process hit internal services
 *  e.g. 169.254.169.254 or 127.0.0.1:2087 with the API key attached). Returns '' if safe, else a reason. */
function smpro_ntf_url_unsafe($url) {
    $p = @parse_url($url); if (!is_array($p) || empty($p['scheme']) || empty($p['host'])) return 'malformed URL';
    if (!in_array(strtolower($p['scheme']), ['http', 'https'], true)) return 'scheme must be http(s)';
    // parse_url() keeps the brackets on an IPv6 literal ("http://[::1]/" -> host "[::1]"); strip them so the
    // literal validates as an IP. WITHOUT this, "[::1]" fails FILTER_VALIDATE_IP, falls through to
    // gethostbynamel("[::1]") (-> false), $ips stays empty, and every check below is skipped -> SSRF bypass.
    $host = trim((string)$p['host'], '[]'); $ips = [];
    if (filter_var($host, FILTER_VALIDATE_IP)) $ips[] = $host;
    else { $r = @gethostbynamel($host); if (is_array($r)) $ips = $r; }     // resolve names too (DNS-rebind defence is best-effort)
    foreach ($ips as $ip) {
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE))
            return 'resolves to a private/reserved address (' . $ip . ')';
        if (strpos($ip, '169.254.') === 0 || strpos($ip, '127.') === 0 || $ip === '::1') return 'loopback/link-local not allowed';
        // FILTER_FLAG_NO_RES_RANGE does NOT reject an IPv4-mapped IPv6 literal (e.g. ::ffff:127.0.0.1), so
        // re-check IPv6 forms explicitly for loopback / link-local / ULA / mapped-internal targets.
        if ($why6 = smpro_ntf_ip6_unsafe($ip)) return $why6;
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
/** Normalise a recipient to a WhatsApp chat id: digits -> "<digits>@c.us". */
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
    $url = 'https://api.telegram.org/bot' . $token . '/sendMessage';   // bot token (in URL) stays in-process, not in argv
    $send = function ($body, $html) use ($url, $chatId) {
        $p = ['chat_id' => $chatId, 'text' => $body, 'disable_web_page_preview' => 'true'];
        if ($html) $p['parse_mode'] = 'HTML';
        $res = smpro_http($url, ['method' => 'POST', 'timeout' => 15, 'body' => http_build_query($p)]);
        $j = json_decode($res['body'] ?? '', true);
        if (is_array($j)) return [!empty($j['ok']), !empty($j['ok']) ? 'sent' : (string)($j['description'] ?? 'telegram error')];
        return [false, 'no response from Telegram'];
    };
    // Telegram hard-limits a message to 4096 chars. Truncating AFTER HTML assembly (the old code) cut
    // mid-tag/entity -> Telegram rejected the whole message ("can't parse entities") and the alert was
    // silently dropped - precisely the biggest digests. Truncate the source well under the limit, add a
    // marker, and close any left-open <pre> so the HTML stays valid.
    $limit = 3900;
    $html = mb_substr($text, 0, $limit);
    if (mb_strlen($text) > $limit) $html .= "\n…(truncated)";
    if (substr_count($html, '<pre>') > substr_count($html, '</pre>')) $html .= '</pre>';
    [$ok, $msg] = $send($html, true);
    if (!$ok && stripos($msg, 'parse') !== false) {          // HTML parse failure -> resend as plain text
        $plain = trim(html_entity_decode(strip_tags($text), ENT_QUOTES | ENT_HTML5, 'UTF-8'));
        [$ok, $msg] = $send(mb_substr($plain, 0, $limit), false);
    }
    return [$ok, $msg];
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
/** An alert the engine evaluated and did not send: the daily report lists these next to the ones that went out. */
function smpro_ntf_held($type, $subject, $why, $sig = '') {
    @is_dir(SMPRO_NTF_DIR) || @mkdir(SMPRO_NTF_DIR, 0700, true);
    $row = ['ts' => time(), 'at' => date('c'), 'type' => (string)$type, 'subject' => (string)$subject, 'why' => (string)$why, 'sig' => (string)$sig];
    @file_put_contents(SMPRO_NTF_HELD, json_encode($row, JSON_UNESCAPED_SLASHES) . "\n", FILE_APPEND | LOCK_EX);
    if (@filesize(SMPRO_NTF_HELD) > 1024 * 1024) { $lines = @file(SMPRO_NTF_HELD, FILE_IGNORE_NEW_LINES) ?: []; @file_put_contents(SMPRO_NTF_HELD, implode("\n", array_slice($lines, -6000)) . "\n", LOCK_EX); }
}
function smpro_ntf_held_between($from, $to) {
    if (!is_file(SMPRO_NTF_HELD)) return [];
    $out = [];
    foreach (@file(SMPRO_NTF_HELD, FILE_IGNORE_NEW_LINES) ?: [] as $l) { $j = json_decode($l, true); if (is_array($j) && (int)$j['ts'] >= $from && (int)$j['ts'] <= $to) $out[] = $j; }
    return $out;
}
function smpro_ntf_sent_between($from, $to) {
    if (!is_file(SMPRO_NTF_LOG)) return [];
    $out = [];
    foreach (@file(SMPRO_NTF_LOG, FILE_IGNORE_NEW_LINES) ?: [] as $l) { $j = json_decode($l, true); if (is_array($j) && (int)$j['ts'] >= $from && (int)$j['ts'] <= $to) $out[] = $j; }
    return $out;
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
    smpro_ntf_undelivered_note($type, $subject, $channels);
    if (function_exists('smpro_audit')) smpro_audit('notify', ['type' => $type, 'channels' => implode(',', $channels)]);
    return $results ?: ['skipped' => 'no channel enabled for this type'];
}

/* Self-heal an older notify cron that was installed WITHOUT flock/timeout (pre-1.0.57). Without a lock a
 * long run + the next 15-min tick overlap and pile up -> resource exhaustion. Rewrites the line once to add
 * `flock -n` (skip tick if a run is still going) + an outer `timeout`. Safe no-op if already healed/absent. */
/** INSTALL the periodic checker cron (every 15 min). This worker runs BOTH the notification checks AND the
 *  Intrusion-Monitor scan + emergency auto-block, so it must exist whenever auto-checks OR emergency/auto-block
 *  is enabled - not only when the admin flips "Auto-checks" on the Notifications page. Idempotent. */
/**
 * The book of alerts that went NOWHERE. A server with no channel switched on fired hundreds of auto-block notices
 * into the void and the operator learned of a blocked editor from the editor. Every page shows a red bar while
 * this file exists; a delivery through any channel clears it.
 */
function smpro_ntf_undelivered_file(): string { return SMPRO_VARLIB . '/notify_undelivered.json'; }
function smpro_ntf_undelivered_note(string $type, string $subject, array $channels): void {
    $f = smpro_ntf_undelivered_file();
    if ($channels) { if (@is_file($f)) @unlink($f); return; }
    $d = @is_file($f) ? json_decode((string)@file_get_contents($f), true) : null; if (!is_array($d)) $d = ['count' => 0, 'since' => time(), 'types' => []];
    $d['count'] = (int)$d['count'] + 1; $d['last_ts'] = time(); $d['last_type'] = $type; $d['last_subject'] = mb_substr($subject, 0, 120);
    $d['types'][$type] = (int)($d['types'][$type] ?? 0) + 1;
    @is_dir(SMPRO_VARLIB) || @mkdir(SMPRO_VARLIB, 0700, true);
    @file_put_contents($f . '.tmp', json_encode($d, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE), LOCK_EX); @chmod($f . '.tmp', 0600); @rename($f . '.tmp', $f);
}
function smpro_ntf_undelivered(): ?array {
    $f = smpro_ntf_undelivered_file(); if (!@is_file($f)) return null;
    $d = json_decode((string)@file_get_contents($f), true); return is_array($d) && (int)($d['count'] ?? 0) > 0 ? $d : null;
}
function smpro_ntf_cron_install() {
    $f = '/etc/cron.d/smpro-notify';
    $bin = SMPRO_BASE . '/bin/notify_check.php';
    if (!is_file($bin)) return false;
    $php = smpro_php_cli_bin();   // canonical: cron's PATH may not resolve a bare `php`
    $lock = SMPRO_VARLIB . '/locks/notify.lock';
    @is_dir(dirname($lock)) || @mkdir(dirname($lock), 0700, true);
    $flock = is_executable('/usr/bin/flock') ? '/usr/bin/flock' : 'flock';
    $desired = "# Safety Monitor Pro — notifications + intrusion auto-response (every 5 min; flock = no overlap)\n"
             . "*/5 * * * * root $flock -n $lock timeout 600 $php $bin >/dev/null 2>&1\n";
    if (is_file($f) && (string)@file_get_contents($f) === $desired) return true;
    smpro_cron_install($f, $desired);   // verified write: 0644 + trailing newline, or it reports failure
    return true;
}
/** True if the Intrusion Monitor needs the periodic checker (emergency auto-response or auto-block enabled).
 *  Notifications "Auto-check" manages the cron file directly; this covers the intrusion auto-response case
 *  that previously had NO scheduler at all. */
function smpro_ntf_cron_wanted() {
    // ALWAYS. This worker is not "the notifier" - it is the detection engine: foreign logins, File Manager writes
    // from abroad, decoy logins, breaches, upload clusters, service-down, disk, backups all run inside it. It used to
    // be scheduled only when the admin had toggled "Auto-checks" on the Notifications page or enabled intrusion
    // auto-block; on a production server neither had ever been touched, so an account takeover through
    // File Manager from a foreign address - exactly the case the detector exists for - was never even looked at,
    // and every page read as clean. Detection must not depend on an optional toggle. Delivery is still governed by
    // the channels (email/Telegram/...), and Plugin Control -> Disabled stops the worker itself.
    return !(function_exists('smpro_ctl_disabled') && smpro_ctl_disabled());
}
/** Boot-time self-heal: make sure the checker cron EXISTS whenever it's wanted (so emergency auto-block runs
 *  even if the admin never opened the Notifications page). Never removes it here - that's the toggle's job. */
function smpro_ntf_cron_sync() {
    // A test must never install a live cron. The shared writer refuses too, but a test that loads only
    // this file has no shared writer to refuse - function_exists() is false and the fallback writes
    // /etc/cron.d directly. The lab caught exactly that, restored the file, and went red at random.
    if (defined('SMPRO_TEST_SRC')) return true;
    if (smpro_ntf_cron_wanted() && (!is_file('/etc/cron.d/smpro-notify') || (strpos((string)@file_get_contents('/etc/cron.d/smpro-notify'), '*/5 * * * *') === false || strpos((string)@file_get_contents('/etc/cron.d/smpro-notify'), 'timeout 280') !== false))) smpro_ntf_cron_install();   // missing, or still on the old 15-minute cadence
    else smpro_ntf_cron_heal();
}
function smpro_ntf_cron_heal() {
    $f = '/etc/cron.d/smpro-notify';
    if (!is_file($f)) return;                                   // auto-checks not enabled -> nothing to heal
    $cur = (string)@file_get_contents($f);
    if (strpos($cur, 'flock') !== false) return;                // already has a lock -> done
    $php = smpro_php_cli_bin();   // canonical: cron's PATH may not resolve a bare `php`
    $bin = SMPRO_BASE . '/bin/notify_check.php';
    $lock = SMPRO_VARLIB . '/locks/notify.lock';
    @is_dir(dirname($lock)) || @mkdir(dirname($lock), 0700, true);
    $flock = is_executable('/usr/bin/flock') ? '/usr/bin/flock' : 'flock';
    $line = "*/5 * * * * root $flock -n $lock timeout 600 $php $bin >/dev/null 2>&1\n";
    $want = "# Safety Monitor Pro — notifications + intrusion auto-response (every 5 min; flock = no overlap)\n" . $line;
    if (function_exists('smpro_cron_install')) smpro_cron_install($f, $want); else { @file_put_contents($f, $want); @chmod($f, 0644); }   // through the verified installer, like every other cron
}

/* ---------------- live event checker (deduped) ---------------- */
function smpro_ntf_state_load() { $d = is_file(SMPRO_NTF_STATE) ? json_decode((string)@file_get_contents(SMPRO_NTF_STATE), true) : null; return is_array($d) ? $d : []; }
function smpro_ntf_state_save($s) { @is_dir(SMPRO_NTF_DIR) || @mkdir(SMPRO_NTF_DIR, 0700, true);
    $lk = @fopen(SMPRO_NTF_STATE . '.lock', 'c'); if ($lk) @flock($lk, LOCK_EX);   // merged under a lock (page "Run checks" vs the cron): a lost remind-window re-sent alerts
    $disk = is_file(SMPRO_NTF_STATE) ? json_decode((string)@file_get_contents(SMPRO_NTF_STATE), true) : null; if (is_array($disk) && is_array($s)) $s = array_merge($disk, $s);
    $t = SMPRO_NTF_STATE . '.' . getmypid() . '.tmp'; @file_put_contents($t, json_encode($s, JSON_UNESCAPED_SLASHES), LOCK_EX); @chmod($t, 0600); @rename($t, SMPRO_NTF_STATE);
    if ($lk) { @flock($lk, LOCK_UN); @fclose($lk); }   // released NOW: held to process exit, a second save in the same run waited on itself forever
}

/**
 * Time-windowed mail analysis from exim logs (read-only, bounded).
 * OUTBOUND: count locally-originated messages (script `cwd=/home/<acct>` or authenticated `A=<id>`)
 *           per account in the last 1 hour and last 12 hours - so "bulk" is judged by real rate, not a
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
    //   • script sends -> a standalone line  "<ts> cwd=/home/<acct> N args: /usr/sbin/sendmail ..."  (P=local)
    //   • authenticated (webmail/SMTP AUTH) -> an arrival line  "<ts> ... <= ... A=dovecot_login:<user> ..."
    // These are disjoint (a script send is P=local, not A=), so counting both does not double-count.
    if (is_readable($log)) {
        // Streamed: this runs in the notify worker under cPanel's 128M CLI cap, and 80k exim lines held as string+array
        // is enough to kill it silently (the same failure that once blanked Account Audit).
        $it = function_exists('smpro_run_lines') ? smpro_run_lines("sh -c " . escapeshellarg("tail -n 300000 " . escapeshellarg($log) . " 2>/dev/null | grep -aE 'cwd=/home[0-9]*/| <= .* A=' | tail -n 80000"), 30) : [];
        foreach ($it as $l) {
            if ($l === '') continue;
            $ts = strtotime(substr($l, 0, 19));
            if (!$ts || $ts < $cut12h) continue;                      // older than 12h -> ignore
            if (preg_match('#cwd=/home[0-9]*/([^/ ]+)#', $l, $m)) {
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
        // \b only anchors 'for' (word char); '=>'/'->' start with non-word chars so they need no boundary - keep them literal
        if (preg_match('/(?:\bfor|=>|->)\s+<?([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})/', $l, $m)) { $r = strtolower(rtrim($m[1], '>')); $out['inbound_recips'][$r] = ($out['inbound_recips'][$r] ?? 0) + 1; }
        if (preg_match('/\b([0-9A-Za-z]{6}-[0-9A-Za-z]{6}-[0-9A-Za-z]{2})\b/', $l, $m)) $ids[$m[1]] = 1;   // exim message id -> resolve recipient below
    }
    // Resolve the local RECIPIENT for spam message-ids that had none on the matched line - exim's arrival line
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

/** Human-readable label for an outbound "sender" identity + whether it's the SERVER (not a customer).
 *  cPanel authenticates its own notification/service mail as __cpanel__service__auth__<svc>__... - that is
 *  the server sending, not a customer, so we show a plain label instead of the raw token. Returns [label, isSystem]. */
function smpro_ntf_friendly_sender(string $acct): array {
    if (strpos($acct, '__cpanel__service__auth__icontact') === 0) return ['Server notifications (cPanel iContact)', true];
    if (strpos($acct, '__cpanel__service__auth__') === 0) {
        $svc = preg_replace('/__.*$/', '', substr($acct, strlen('__cpanel__service__auth__')));
        return ['Server service' . ($svc !== '' ? " ({$svc})" : '') . ' (cPanel)', true];
    }
    if (in_array(strtolower($acct), ['mailnull', 'nobody', 'root', 'cpanel', 'mail', 'daemon'], true)) return [ucfirst($acct) . ' (system)', true];
    if (strpos($acct, ':') !== false) { $p = explode(':', $acct, 2); return [(($p[1] ?? '') !== '' ? $p[1] : $acct) . ' (webmail/SMTP login)', false]; }
    return [$acct, false];   // a real cPanel account username
}

/**
 * Evaluate live conditions; notify only when a condition's signature changed
 * since the last run. Returns a summary array of what fired / what was checked.
 */
/**
 * Map an LVE id to a REAL cPanel account name, or '' if it isn't one. lveinfo reports reserved/system LVE
 * contexts too (e.g. id 255 = a non-account context that showed 5,491 IO faults on a live box) - those are
 * not customer accounts, can't be acted on ("raise the plan"), and must be filtered out of tenant alerts.
 */
function smpro_ntf_lve_acct($uid) {
    $n = function_exists('posix_getpwuid') ? (string)(posix_getpwuid((int)$uid)['name'] ?? '') : '';
    return ($n !== '' && preg_match('/^[a-z0-9._-]+$/i', $n) && @is_file('/var/cpanel/users/' . $n)) ? $n : '';
}
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
    // The identity of a foreign-login row for the "did it change?" question. NOT the bare address: relay
    // networks (Cloudflare WARP, Apple Private Relay, Google One VPN) hand the same person a different exit
    // address every session, so one mailbox read through WARP produced a "new" report every few hours - three
    // addresses in a day, all Cloudflare, all the same story. A row is the same row while it is the same
    // account from the same country through the same network (ASN); a genuinely new place or network still changes it.
    $rowId = function (array $d): string {
        $ip = (string)($d['ip'] ?? ''); $cc = (string)($d['cc'] ?? '');
        $asn = '';
        if ($ip !== '' && function_exists('smpro_ip_intel')) { $i = (array)smpro_ip_intel($ip, false); $asn = (string)($i['asn'] ?? ''); if ($cc === '') $cc = (string)($i['country'] ?? ''); }
        return (string)($d['user'] ?? '') . '|' . $cc . '|' . ($asn !== '' ? $asn : $ip);
    };
    $maybe = function ($type, $sig, $subject, $body, $meta = [], $remindOverride = 0) use (&$st, &$fired, $cfg, $chanSig, $remindSecs, $now) {
        $isClear = ($sig === 'clear' || strpos($sig, 'clear:') === 0);
        if (empty($cfg['types'][$type]['on'])) { if (!$isClear && $subject !== '') smpro_ntf_held($type, $subject, 'this alert type is switched off in Notifications', $sig); return; }
        if ((int)($cfg['types'][$type]['mute_until'] ?? 0) > $now) { if (!$isClear && $subject !== '') smpro_ntf_held($type, $subject, 'snoozed until ' . date('Y-m-d H:i', (int)$cfg['types'][$type]['mute_until']), $sig); return; }   // snoozed -> suppress; state is left untouched so it re-evaluates (and fires once if still active) when the snooze expires
        /*
         * One alert TYPE can be fed by several independent checks (foreign_login: the SSH scan and the
         * cPanel/webmail scan; mem_pressure: the host and the CloudLinux tenants). They used to share ONE state
         * slot, so the SSH scan's "clear" (no foreign SSH login this run) wiped the webmail scan's signature on
         * every run, and the webmail alert was re-sent at every cron tick with "only when it changes" switched
         * on - the operator did everything the alert asked and kept receiving it. Each signature prefix (the part
         * before the first colon) now owns its own slot: 'flogin:' and 'cplogin:' never touch each other. A bare
         * 'clear' resets every slot of the type (one-check types), 'clear:<prefix>' resets that slot alone.
         */
        $pfx = (strpos($sig, ':') !== false) ? substr($sig, 0, strpos($sig, ':')) : '';
        if ($pfx === 'clear') { $slot = $type . '#' . substr($sig, 6); $st[$slot] = ['sig' => 'clear', 'ch' => '', 'ts' => $now]; return; }
        if ($sig === 'clear') { foreach (array_keys($st) as $k) if ($k === $type || strpos($k, $type . '#') === 0) $st[$k] = ['sig' => 'clear', 'ch' => '', 'ts' => $now]; return; }
        $slot = $pfx !== '' ? $type . '#' . $pfx : $type;
        $prev = $st[$slot] ?? ($st[$type] ?? null);   // the legacy shared slot answers once, so the upgrade itself re-sends nothing
        if (is_string($prev)) $prev = ['sig' => $prev, 'ch' => '', 'ts' => 0];   // migrate legacy state
        $ch = $chanSig($type);
        if ($ch === '') { smpro_ntf_held($type, $subject, 'no channel is enabled for this alert type', $sig); return; }   // no channel yet -> keep pending, fire when one turns on
        $window   = $remindOverride > 0 ? $remindOverride : $remindSecs;
        $sameSig  = $prev && ($prev['sig'] ?? null) === $sig;
        $sameChan = $prev && ($prev['ch']  ?? '')   === $ch;
        $fresh    = $prev && (int)($prev['ts'] ?? 0) > 0 && ($now - (int)$prev['ts']) < $window;
        // "Only when it changes": the operator has read this report and does not want it again every remind
        // window. It is sent again the moment its signature changes - a new account, a new address, a new
        // finding for the same account - because the signature is built from exactly those.
        $onlyChanges = !empty($cfg['types'][$type]['only_changes']);
        if ($sameSig && $sameChan && ($fresh || $onlyChanges)) { smpro_ntf_held($type, $subject, $onlyChanges ? 'unchanged since it was last sent ("only when it changes" is on)' : 'unchanged and still inside the reminder window', $sig); return; }   // unchanged: within the remind window, or muted until it changes
        $st[$slot] = ['sig' => $sig, 'ch' => $ch, 'ts' => $now];
        smpro_ntf_state_save([$slot => $st[$slot]]);   // recorded the moment it is sent: the full save waits for the END of the run, and a run killed before it re-sent every alert next time
        smpro_notify($type, $subject, $body, $meta);
        $fired[] = $type;
    };

    // 1) active malware (Imunify)
    $bin = is_executable('/usr/bin/imunify360-agent') ? '/usr/bin/imunify360-agent' : '';
    if ($bin) {
        $checked[] = 'malware_active';
        $raw = (string)@shell_exec('timeout 40 ' . $bin . ' malware malicious list --limit 500 --json 2>/dev/null');
        $j = json_decode($raw, true); $items = is_array($j) ? ($j['items'] ?? []) : [];
        // Only count files that are STILL malicious RIGHT NOW. Imunify keeps a record in its "malicious
        // list" even after the file has been cleaned/quarantined/deleted from disk, so counting the raw
        // list produces a STALE "currently-malicious" alert naming already-cleaned accounts. Mirror the
        // Reports module's staleness test (imunify360-reports.php): a file resource still under /home
        // whose path no longer exists on disk was already handled - drop it. (DB injections are covered
        // by the separate db_injection check below, so they don't belong in the file count.)
        // Files Imunify left as "found" (on-demand / rescan finds are never auto-cleaned by Imunify) are handed to
        // Imunify's own cleanup when the operator chose cleanup there (includes/imclean.php); they leave the count.
        if (!function_exists('smpro_imc_auto')) { $ic = __DIR__ . '/imclean.php'; if (is_file($ic)) require_once $ic; }
        $imc = function_exists('smpro_imc_auto') ? smpro_imc_auto($items) : ['ran' => false, 'files' => [], 'why' => ''];
        $imcSent = array_flip($imc['files']);
        $live = [];
        foreach ($items as $r) {
            if (isset($imcSent[(string)($r['file'] ?? '')])) continue;
            if (($r['resource_type'] ?? '') === 'db') continue;
            $p = (string)($r['file'] ?? '');
            if (($r['status'] ?? 'found') !== 'found') continue;                   // cleanup_done / cleanup_removed: Imunify already cleaned it (the file may remain, emptied or clean)
            if ($p !== '' && !@is_file($p)) continue;                               // already cleaned/gone -> stale (any home root, not only /home)
            if ($p !== '' && function_exists('smpro_wpguard_trusted') && smpro_wpguard_trusted($p)) continue;   // WP Guard's own / already-neutralized file -> not a "possible compromise"
            $live[] = $r;
        }
        $n = count($live);
        if ($n > 0) {
            $accts = array_values(array_filter(array_unique(array_map(fn($r) => $r['username'] ?? '', $live))));
            $maybe('malware_active', 'mal:' . $n . ':' . substr(md5(implode(',', $accts)), 0, 8), "$n currently-malicious file(s) detected",
                "Accounts: " . implode(', ', array_slice($accts, 0, 8))
                . ($imc['ran'] ? "\nImunify360 was asked to clean " . count($imc['files']) . " other file(s) it had left as found." : '')
                . "\nThese still need you: open Imunify360 Reports and use Clean with Imunify (keeps the original) or Delete.", ['severity' => 'critical']);
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
        $j = json_decode($raw, true); $list = $j['data']['account'] ?? $j['data']['accts'] ?? [];   // whmapi1 returns data.account (singular)
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
    // A fixed number is not a load line: 20 on a 96-thread server is a fifth busy. The configured threshold is
    // read as "at least half the cores", so the same setting means the same thing on every box, and the
    // Notifications page says what it comes to here. (Same rule as the automatic load guard.)
    $cores = function_exists('smpro_cpu_cores') ? max(1, (int)smpro_cpu_cores()) : max(1, (int)@shell_exec('nproc 2>/dev/null'));
    $loadThr = max((float)($thr['load'] ?? 20), $cores / 2);
    if ($load >= $loadThr) {
        $cause = trim((string)@shell_exec("ps -eo pcpu,user,comm --sort=-pcpu --no-headers 2>/dev/null | head -6 | awk '{printf \"• %s%% %s (%s)\\n\", \$1, \$3, \$2}'"));
        $pct = $cores > 0 ? round($load / $cores * 100) : 0;
        // the signature is the load BAND (steps of a quarter of the cores), not the exact number: a load that
        // hovers around the line must not re-send every run
        $maybe('load_high', 'load:' . (int)floor($load / max(1, $cores / 4)), 'Server load high', '1-min load average: ' . $load . ($cores ? ' (' . $pct . '% of ' . $cores . ' cores)' : '') . "\n\nTop CPU consumers (cause):\n" . ($cause ?: 'n/a'), ['severity' => 'medium']);
    } else $maybe('load_high', 'clear', '', '');

    // 5) real-time intrusion / web-attack alerts (engine in includes/intrusion.php)
    if (function_exists('smpro_im_alert_scan') && function_exists('smpro_im_modsec_log') && smpro_im_modsec_log() !== '') {
        $checked[] = 'intrusion';
        $al = smpro_im_alert_scan();
        $parts = []; $sig = [];
        foreach (['selfattack', 'critical', 'spike', 'distributed'] as $k) if (isset($al[$k])) { $parts[] = $al[$k]['subject'] . "\n" . $al[$k]['body']; $sig[] = $al[$k]['sig']; }
        if ($parts) $maybe('intrusion_attack', 'atk:' . md5(implode('|', $sig)), 'Web-attack activity detected', implode("\n\n", $parts), ['severity' => (isset($al['critical']) || isset($al['selfattack'])) ? 'critical' : 'high']);
        // An attack that dips under the line for one window and comes back is the same attack: the slot is
        // cleared only after thirty quiet minutes, so a flicker around the threshold does not re-send the alert.
        elseif ((int)(($st['intrusion_attack#atk']['ts'] ?? 0)) < $now - 1800) $maybe('intrusion_attack', 'clear', '', '');
        if (isset($al['breach']))    $maybe('intrusion_breach', $al['breach']['sig'], $al['breach']['subject'], $al['breach']['body'], ['severity' => 'critical']);
        else $maybe('intrusion_breach', 'clear', '', '');
        if (isset($al['upload_cluster'])) $maybe('intrusion_upload_cluster', $al['upload_cluster']['sig'], $al['upload_cluster']['subject'], $al['upload_cluster']['body'], $al['upload_cluster']['meta']);
        else $maybe('intrusion_upload_cluster', 'clear', '', '');
        if (isset($al['autoblock'])) $maybe('intrusion_autoblock', $al['autoblock']['sig'], $al['autoblock']['subject'], $al['autoblock']['body'], ['severity' => 'high']);
        if (isset($al['emergency'])) $maybe('intrusion_emergency', $al['emergency']['sig'], $al['emergency']['subject'], $al['emergency']['body'], ['severity' => 'critical']);
        // routine scanner auto-blocks -> low-urgency grouped digest via the Auto-block type (INFO, not CRITICAL)
        if (isset($al['emergency_blocks'])) $maybe('intrusion_autoblock', $al['emergency_blocks']['sig'], $al['emergency_blocks']['subject'], $al['emergency_blocks']['body'], ['severity' => 'info']);
    }

    // 5) PHP Harden drift (locked files that lost immutability) - self-contained lsattr check
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
        if ($drift) {
            $body = implode("\n", array_slice($drift, 0, 12))
                . "\n\nThese files were locked by PHP Harden (made immutable with chattr +i) and are writable again now."
                . "\nMost common cause: a WordPress / plugin / core UPDATE replaced the file — that's benign, just re-lock it."
                . "\nIf no update was expected, treat it as possible tampering: inspect the file's contents in Forensics / Audit and the account's recent activity in User Investigation before re-locking."
                . "\nRe-apply protection in PHP Harden: scan the account, then Lock.";
            $maybe('harden_drift', 'drift:' . md5(implode(',', $drift)), count($drift) . ' protected file(s) no longer locked', $body, ['severity' => 'high']);
        } else $maybe('harden_drift', 'clear', '', '');
    }

    // 6) outbound bulk mail + inbound spam (time-windowed exim analysis)
    if (is_readable('/var/log/exim_mainlog')) {
        $inboundRemind = max(1, (int)($thr['inbound_spam_remind_hours'] ?? 6)) * 3600;
        $scan = smpro_ntf_mail_scan($inboundRemind);

        // 6a) OUTBOUND bulk: flag an account that sent > mail_out_hour in the last hour, OR >= mail_out_12h over 12h.
        //     Below both -> not treated as spam here (volume is normal); the Spam & Phishing AI scan judges content.
        $checked[] = 'spam_outbreak';
        $perHour = max(1, (int)($thr['mail_out_hour'] ?? 100));
        $per12h  = max(1, (int)($thr['mail_out_12h'] ?? ($thr['spam_events'] ?? 300)));
        $hot = []; $custN = 0; $sysN = 0;   // acct => friendly reason line
        foreach ($scan['out_12h'] as $a => $n12) {
            $n1 = (int)($scan['out_hour'][$a] ?? 0);
            if ($n1 > $perHour)      $reason = "$n1/hour (12h: $n12) — over " . $perHour . "/hour";
            elseif ($n12 >= $per12h) $reason = "$n12 in 12h (now " . $n1 . "/hour) — over " . $per12h . "/12h";
            else continue;
            [$label, $isSys] = smpro_ntf_friendly_sender((string)$a);
            $hot[$a] = ($isSys ? '⚙ ' : '') . $label . ': ' . $reason;
            if ($isSys) $sysN++; else $custN++;
        }
        if ($hot) {
            $title = $custN > 0
                ? ($custN . ' customer account(s) sending bulk outbound mail')
                : 'High server-notification volume (no customer account)';
            $body  = implode("\n", array_slice($hot, 0, 8)) . "\n\nThreshold: > $perHour/hour or ≥ $per12h/12h (editable in Notifications).";
            if ($custN > 0) $body .= "\nOpen Spam & Phishing to scan the account's mail; if it's spam, block its outgoing or suspend it.";
            if ($sysN > 0)  $body .= "\n\n⚙ = the SERVER's own notification emails (cPanel iContact / services), NOT a customer — do not suspend. A spike here is usually a symptom, e.g. an account hit its hourly mail limit so cPanel sent many \"limit exceeded\" notices. Check /var/log/exim_mainlog for the subjects.";
            $maybe('spam_outbreak', 'spam:' . md5(implode(',', array_keys($hot))) . ':' . count($hot),
                $title, $body, ['severity' => $custN > 0 ? 'high' : 'medium']);
        } else $maybe('spam_outbreak', 'clear', '', '');

        // 6b) INBOUND spam: any spam-scored / spam-rejected incoming mail in the window -> alert at least every 6h.
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

    // 7) backup failed (JetBackup5 - a job whose last run did not complete)
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
            // 'disabled', NOT 'state' - a live enabled job reports state:0, so keying off state silenced the
            // backup alert for EVERY job (same misread as the retry worker had).
            if (!empty($full['disabled'])) continue;   // job intentionally disabled - the retry worker skips it too, so don't alert on its last failure
            $lr = (is_numeric($full['last_run'] ?? '') ? (int)($full['last_run'] ?? 0) : (strtotime((string)($full['last_run'] ?? '')) ?: 0));
            $lc = (is_numeric($full['last_completed'] ?? '') ? (int)($full['last_completed'] ?? 0) : (strtotime((string)($full['last_completed'] ?? '')) ?: 0));
            if ($lr > 0 && $lc < $lr) $failed[] = (string)($full['name'] ?? $id);
        }
        if ($failed) $maybe('backup_failed', 'bk:' . md5(implode(',', $failed)), count($failed) . ' backup job(s) failed / incomplete',
            "Jobs: " . implode(', ', array_slice($failed, 0, 12)) . "\nOpen Backup Monitor to re-run them.", ['severity' => 'high']);
        else $maybe('backup_failed', 'clear', '', '');
    }

    // 7b) server reboot - alert once per boot; classify clean/administrative vs unexpected (crash/power loss).
    $checked[] = 'server_reboot';
    $bootTs = strtotime(trim((string)@shell_exec('uptime -s 2>/dev/null'))) ?: 0;
    if ($bootTs > 0) {
        $prevBoot = (int)($st['_last_boot'] ?? 0);
        if ($prevBoot === 0) {
            $st['_last_boot'] = $bootTs;                       // first run ever: record the baseline, don't alert
        } elseif ($bootTs > $prevBoot + 60) {                 // a genuinely newer boot (60s guard against clock jitter)
            $prevLog = (string)@shell_exec('journalctl -b -1 -n 40 --no-pager 2>/dev/null');
            $wtmp = trim((string)@shell_exec('last -x -n 6 reboot shutdown 2>/dev/null | head -6'));
            $journalClean = $prevLog !== '' && stripos($prevLog, 'Reached target') !== false
                     && (stripos($prevLog, 'Shutdown') !== false || stripos($prevLog, 'Power-Off') !== false || stripos($prevLog, 'Reboot') !== false || stripos($prevLog, 'Halt') !== false);
            // Fall back to wtmp when journald isn't persistent (no prior boot in the journal): a recorded
            // "shutdown" line means the previous boot ended cleanly, so don't cry "crash" on those boxes.
            $clean = $journalClean || ($prevLog === '' && stripos($wtmp, 'shutdown') !== false);
            $body = ($clean ? 'Clean / administrative reboot.' : 'UNEXPECTED reboot — no clean shutdown was recorded (crash, kernel panic, or power loss).')
                  . "\nBooted: " . date('Y-m-d H:i', $bootTs) . ' (up ' . smpro_dur(max(0, $now - $bootTs)) . ').'
                  . ($wtmp ? "\n\nRecent reboot/shutdown records:\n" . $wtmp : '')
                  . "\n\nIf this was not expected, check Reports Center › Reboots and hardware health (Benchmark › Drive lifetime).";
            $maybe('server_reboot', 'boot:' . $bootTs, $clean ? 'Server rebooted' : 'Server rebooted UNEXPECTEDLY', $body, ['severity' => $clean ? 'info' : 'high']);
            $st['_last_boot'] = $bootTs;
        }
    }

    // 7c) foreign successful login - a successful SSH login from OUTSIDE the home region (compromise signal).
    if (function_exists('smpro_geo_foreign')) {
        $sec = is_readable('/var/log/secure') ? '/var/log/secure' : (is_readable('/var/log/auth.log') ? '/var/log/auth.log' : '');
        if ($sec !== '') {
            $checked[] = 'foreign_login';
            $raw = (string)@shell_exec('grep -aE "Accepted (password|publickey|keyboard-interactive)" ' . escapeshellarg($sec) . ' 2>/dev/null | tail -120');
            // A deployment pipeline (GitHub Actions, Bitbucket Pipelines, GitLab CI) logs in with a KEY from a range
            // its provider publishes, once per run, from a different runner each time. Read as "foreign logins" that
            // is nine addresses, one login each, all [HIGH] - and the operator is told to rotate keys over a git push.
            // The method and the provider are read here so a deployment is reported as a deployment.
            if (!function_exists('smpro_deploy_classify')) { $dp = __DIR__ . '/deployer.php'; if (@is_file($dp)) require_once $dp; }
            if (function_exists('smpro_deploy_refresh')) { try { smpro_deploy_refresh(); } catch (\Throwable $e) { if (function_exists('smpro_soft_fail')) smpro_soft_fail('deploy_refresh', $e); } }   // TTL-guarded: a fetch once a week, nothing otherwise
            $foreign = []; $deploys = [];
            foreach (explode("\n", $raw) as $l) {
                if (!preg_match('/Accepted (\S+) for (\S+) from ([0-9a-fA-F:.]+)/', $l, $mm)) continue;
                $method = $mm[1]; $user = $mm[2]; $ip = $mm[3];
                if (function_exists('smpro_is_server_ip') && smpro_is_server_ip($ip)) continue;
                $g = smpro_geo_foreign($ip);
                if (empty($g['foreign'])) continue;            // local / home-region / unknown -> not flagged
                $cl = function_exists('smpro_deploy_classify') ? smpro_deploy_classify($ip, $method) : ['class' => ($method === 'publickey' ? 'key' : 'password'), 'provider' => ''];
                if ($cl['class'] === 'deploy') {
                    $k = $user . '|' . $cl['provider'];
                    if (!isset($deploys[$k])) $deploys[$k] = ['user' => $user, 'provider' => $cl['provider'], 'n' => 0, 'ips' => []];
                    $deploys[$k]['n']++; $deploys[$k]['ips'][$ip] = 1;
                    continue;
                }
                if (!isset($foreign[$ip])) $foreign[$ip] = ['user' => $user, 'cc' => $g['cc'], 'n' => 0, 'class' => $cl['class']];
                $foreign[$ip]['n']++;
                if ($cl['class'] === 'password') $foreign[$ip]['class'] = 'password';   // a password outranks a key from the same address
            }
            if ($foreign) {
                $lines = []; $anyPassword = false;
                foreach (array_slice($foreign, 0, 10, true) as $ip => $d) {
                    $lines[] = $d['user'] . ' @ ' . $ip . ' (' . $d['cc'] . ') ×' . $d['n'] . ($d['class'] === 'key' ? ' — by KEY' : ' — by password');
                    if ($d['class'] === 'password') $anyPassword = true;
                }
                $body = "Successful SSH login(s) from outside your home region:\n" . implode("\n", $lines)
                      . "\n\nBy password: if this is not you, the password is known to someone else - change it and review Login Monitor + User Investigation."
                      . "\nBy KEY: a key in that account's ~/.ssh/authorized_keys was used from an address no deployment provider publishes. Check whose key it is; remove any you do not recognise."
                      . (function_exists('smpro_deploy_classify') ? '' : "\n(Deployment-provider ranges are not available on this build, so a CI pipeline would appear here as a key login.)");
                $maybe('foreign_login', 'flogin:' . md5(implode(',', array_keys($foreign))), count($foreign) . ' foreign successful login(s)', $body,
                       ['severity' => $anyPassword ? 'high' : 'medium']);
            } else $maybe('foreign_login', 'clear:flogin', '', '');   // the SSH scan clears ITS slot only; the webmail scan below owns 'cplogin'
            // Deployments are told apart and told ONCE per account+provider: a customer who wires up GitHub Actions
            // hears about it the first time, and never again for every push.
            if ($deploys) {
                $lines = [];
                foreach ($deploys as $d) $lines[] = $d['user'] . ' — ' . $d['provider'] . ' (key) ×' . $d['n'] . ' from ' . count($d['ips']) . ' runner address(es)';
                $body = "SSH deployments by key from a published CI provider range - a pipeline, not a person:\n" . implode("\n", $lines)
                      . "\n\nNothing to do if that account deploys from there. If it should not, remove the deploy key from its ~/.ssh/authorized_keys.";
                $maybe('deploy_login', 'deploy:' . md5(implode(',', array_keys($deploys))), count($deploys) . ' CI deployment login(s) by key', $body, ['severity' => 'info']);
            }
        }
    }

    // 7c-a) A setup gap is a finding too. The product ships with NO home region (it is sold into any market), and
    // until one is set the location-based checks below deliberately classify nothing - silence there would look
    // like "no foreign logins" when the truth is "nothing was checked". So say it, once, with the suggestion.
    if (function_exists('smpro_im_home_configured') && !smpro_im_home_configured()) {
        $checked[] = 'home_region_unset';
        $sug = function_exists('smpro_im_home_suggest') ? smpro_im_home_suggest() : '';
        $body = "No home region is configured, so these checks are currently OFF: foreign successful logins (cPanel/webmail/SSH), File Manager writes from outside your region, and the residential-IP protection in auto-block.\n\n"
              . ($sug !== '' ? "This server appears to be in $sug. If that is where your customers are, set the home region to $sug in Intrusion Monitor › Settings. If your customers are elsewhere (a business in one country on a server in another), set THEIR country instead."
                              : "Set the home region in Intrusion Monitor › Settings to the country your customers are in.");
        $maybe('home_region_unset', 'unset:' . ($sug !== '' ? $sug : 'x'), 'Home region not set — location checks are off', $body, ['severity' => 'high']);
    } elseif (function_exists('smpro_im_home_configured')) $maybe('home_region_unset', 'clear', '', '');

    // 7d) login brute-force. The type existed in the catalogue (and on the Notifications page, with a threshold)
    //     since the first release, and NO check ever evaluated it: 18,000 failed attempts from 200 addresses sat on
    //     the Account Audit page and nothing was sent. The same grouping the Break-in report shows - networks, not
    //     addresses - over the last 24 h; a network the operator ignored on the report is not counted; an
    //     allow-listed provider (a crawler, the CDN) is not an attacker. Sent when the attacking networks together
    //     cross the "Failed logins" threshold; its signature is the set of networks, so a new network re-sends it
    //     and the same campaign does not.
    if (!empty($cfg['types']['login_bruteforce']['on']) && function_exists('smpro_aa_collect') && function_exists('smpro_aa_bf_networks')) {
        $checked[] = 'login_bruteforce';
        try {
            $bfEvents = smpro_aa_collect('', 'failed_login', 60000, $now - 86400, $now);   // '' = every account (the page's own 'all')
            $bfEvents = is_array($bfEvents[0] ?? null) ? $bfEvents[0] : (array)$bfEvents;
            $bfN = smpro_aa_bf_networks($bfEvents);
            $bfThr = max(1, (int)($cfg['thresholds']['failed_logins'] ?? 60));
            $attack = [];
            foreach ($bfN['nets'] as $k => $nv) { $as = smpro_aa_bf_assess($nv); if (($as['verdict'] ?? '') === 'block') { $nv['assess'] = $as; $attack[$k] = $nv; } }
            $fails = array_sum(array_map(fn($n) => (int)$n['fails'], $attack));
            if ($attack && $fails >= $bfThr) {
                $keys = array_keys($attack); sort($keys);
                $addrs = array_sum(array_map(fn($n) => count($n['ips']), $attack));
                $lines = []; $i = 0;
                foreach ($attack as $k => $nv) {
                    if (++$i > 10) { $lines[] = '    … and ' . (count($attack) - 10) . ' more network(s) on the report'; break; }
                    $users = (array)$nv['users']; arsort($users); $tu = array_slice(array_keys($users), 0, 3);
                    $lines[] = '▶ ' . $nv['provider'] . ($nv['asn'] !== '' ? ' (' . $nv['asn'] . ')' : '') . ($nv['cc'] !== '' ? ' · ' . (function_exists('smpro_cc_name') ? smpro_cc_name($nv['cc']) : $nv['cc']) : '')
                             . ($nv['bot'] ? ' · cloud/hosting' : ' · residential/business') . ' — ' . count($nv['ips']) . ' address(es), ' . (int)$nv['fails'] . ' failed attempt(s)'
                             . ($tu ? ' · targets: ' . implode(', ', $tu) . (count($users) > 3 ? ' +' . (count($users) - 3) : '') : '')
                             . ($nv['services'] ? ' · door: ' . implode(', ', array_map(fn($x) => str_replace(['cpaneld', 'webmaild', 'whostmgrd'], ['cPanel', 'webmail', 'WHM'], $x), array_keys((array)$nv['services']))) : '');
                    $why = (array)($nv['assess']['why'] ?? []); if ($why) $lines[] = '    ' . $why[0];
                    $lines[] = '    e.g. ' . implode(', ', array_slice(array_map(fn($x) => $x['ip'] . ' ×' . (int)$x['n'], $nv['ips']), 0, 3));
                }
                $body = count($attack) . ' network(s) are brute-forcing cPanel / webmail / WHM / SSH logins: ' . number_format($fails) . ' failed attempts from ' . $addrs . ' address(es) in the last 24 h'
                      . ' (threshold ' . $bfThr . '). No password was accepted by these; a successful foreign login is a separate alert.' . "\n\n"
                      . implode("\n", $lines) . "\n\n"
                      . 'What to do: open Account Audit → Break-in report and decide PER NETWORK — Block (closes the login ports for every address of that network), '
                      . 'Allow-list (a provider you trust), or Ignore (it stops being counted here). Nothing is blocked automatically by this alert.'
                      . (count($bfN['ignored']) ? "\n" . count($bfN['ignored']) . ' network(s) you ignored are not counted.' : '')
                      . (count($bfN['trusted']) ? "\n" . count($bfN['trusted']) . ' allow-listed address(es) with failed logins are listed on the report as trusted, not as attackers.' : '')
                      . "\nThis notice is sent again only when a new attacking network appears.";
                $maybe('login_bruteforce', 'bf:' . md5(implode(',', $keys)), count($attack) . ' network(s) brute-forcing logins: ' . number_format($fails) . ' failed attempts', $body, ['severity' => 'high']);
            } else $maybe('login_bruteforce', 'clear:bf', '', '');
        } catch (\Throwable $e) { if (function_exists('smpro_soft_fail')) smpro_soft_fail('login_bruteforce', $e); }
    }

    // 7c-bis) foreign successful logins through the cPanel panel / webmail, and per-account travel anomalies.
    // The ssh scan above only sees /var/log/secure; the panel and webmail are where stolen cPanel passwords are
    // actually used, and they log elsewhere. Both feed the SAME foreign_login alert so the operator has one place
    // to look, with the door named. Reported the same aggregated, deduped way - one line per source, never a flood.
    if (function_exists('smpro_foreign_success_logins')) {
        $checked[] = 'login_geo_anomaly';
        $r = smpro_foreign_success_logins(168, 2, 3);
        if (!empty($r['ok'])) {
            $fp = $r['foreign'] ?? [];
            if ($fp) {
                $ids = array_unique(array_map($rowId, $fp)); sort($ids);
                $key  = 'cplogin:' . md5(implode(',', $ids));
                $home = function_exists('smpro_im_home_regions_label') ? smpro_im_home_regions_label(true) : 'your home region';   // home + the lock's countries: the set the rows were judged against
                $rep  = smpro_foreign_login_report($fp, 168, $home);
                $maybe('foreign_login', $key, $rep['title'], $rep['body'], ['severity' => 'high']);
            }
            $an = $r['anomaly'] ?? [];
            if ($an) {
                $key = 'geoanom:' . md5(implode(',', array_keys($an)));
                $rep = smpro_geo_anomaly_report($an, 168);
                $maybe('login_geo_anomaly', $key, $rep['title'], $rep['body'], ['severity' => 'high']);
            } else $maybe('login_geo_anomaly', 'clear', '', '');
        }
    }

    // 7c-ter) File Manager writes from outside the home region + the takeover-tool signature, and decoy logins.
    // Both come from the incident that took 31 accounts with stolen passwords: the panel's own access log held the
    // fingerprint the whole time (foreign write, then delete seconds later), and nothing read it.
    if (function_exists('smpro_fm_foreign_writes')) {
        $checked[] = 'fm_foreign_write';
        $r = smpro_fm_foreign_writes(24, 120);
        if (!empty($r['ok'])) {
            $sig = $r['signature'] ?? []; $wr = $r['writes'] ?? [];
            if ($sig) {
                $lines = [];
                foreach (array_slice($sig, 0, 10) as $d)
                    $lines[] = $d['user'] . ' @ ' . $d['ip'] . ' (' . $d['cc'] . ') — ' . $d['pairs'] . ' write→delete pair(s)' . ($d['files'] ? ' [' . implode(', ', $d['files']) . ']' : '');
                $key = 'fmsig:' . md5(implode(',', array_map(fn($d) => $d['ip'] . $d['user'], $sig)));
                $body = "TAKEOVER-TOOL SIGNATURE — an outside address wrote a file through File Manager and deleted it seconds later:\n" . implode("\n", $lines)
                      . "\n\nThis is what an automated tool does with a freshly bought password: it probes the account, then drops its kit. Treat these accounts as compromised NOW — reset the password, end every session, then look for what was written (Account Audit → File Manager activity).";
                $maybe('fm_foreign_write', $key, count($sig) . ' account(s) show the takeover-tool signature', $body, ['severity' => 'critical']);
            } elseif ($wr) {
                usort($wr, fn($a, $b) => $b['n'] <=> $a['n']);
                $lines = [];
                foreach (array_slice($wr, 0, 10) as $d) $lines[] = $d['user'] . ' @ ' . $d['ip'] . ' (' . $d['cc'] . ') ×' . $d['n'];
                $key = 'fmwr:' . md5(implode(',', array_map(fn($d) => $d['ip'] . $d['user'], $wr)));
                $body = "File Manager write(s) from outside your home region in the last 24h:\n" . implode("\n", $lines)
                      . "\n\nA customer editing their site from abroad is possible; a stolen password being used is more common. If the account owner is not travelling, reset the password and review what changed.";
                $maybe('fm_foreign_write', $key, count($wr) . ' foreign File Manager write(s)', $body, ['severity' => 'high']);
            } else $maybe('fm_foreign_write', 'clear', '', '');
        }
    }
    if (function_exists('smpro_honey_hits')) {
        $r = smpro_honey_hits(168);
        if (!empty($r['ok']) && (int)($r['configured'] ?? 0) > 0) {
            $checked[] = 'honeytoken_login';
            $h = $r['hits'] ?? [];
            if ($h) {
                $lines = [];
                foreach (array_slice($h, 0, 10) as $d) $lines[] = ($d['success'] ? 'SIGNED IN' : 'attempted') . ': ' . $d['user'] . ' @ ' . $d['ip'] . ' (' . $d['cc'] . ', ' . $d['service'] . ') ×' . $d['n'];
                $anyOk = (bool)array_filter($h, fn($d) => $d['success']);
                $key = 'honey:' . md5(implode(',', array_map(fn($d) => $d['user'] . $d['ip'] . ($d['success'] ? 1 : 0), $h)));
                $body = "Decoy account activity:\n" . implode("\n", $lines)
                      . "\n\nA decoy is never used by anyone, so this cannot be a customer. " . ($anyOk
                          ? "A SUCCESSFUL sign-in means a list containing your accounts' passwords is being used against this server right now — assume other accounts on it are exposed too."
                          : "Attempts mean the decoy's name is on a credential list; watch the other accounts.");
                $maybe('honeytoken_login', $key, count($h) . ' decoy-account login event(s)', $body, ['severity' => $anyOk ? 'critical' : 'high']);
            } else $maybe('honeytoken_login', 'clear', '', '');
        }
    }

    // 7d) memory / swap pressure - available RAM nearly gone AND swap filling -> OOM risk.
    $checked[] = 'mem_pressure';
    $mi = (string)@file_get_contents('/proc/meminfo');
    if ($mi !== '') {
        $mv = fn($k) => preg_match('/^' . $k . ':\s+(\d+)/m', $mi, $m) ? (int)$m[1] : 0;   // kB
        $memTotal = $mv('MemTotal'); $memAvail = $mv('MemAvailable'); $swapTotal = $mv('SwapTotal'); $swapFree = $mv('SwapFree');
        if ($memTotal > 0) {
            $availPct    = (int)round($memAvail / $memTotal * 100);
            $swapUsedPct = $swapTotal > 0 ? (int)round(($swapTotal - $swapFree) / $swapTotal * 100) : 0;
            $memThr  = (int)($thr['mem_avail_pct'] ?? 8);      // alert when available RAM drops below this %
            $swapThr = (int)($thr['swap_used_pct'] ?? 75);
            if ($availPct <= $memThr && ($swapTotal === 0 || $swapUsedPct >= $swapThr)) {
                $cause = trim((string)@shell_exec("ps -eo pmem,user,comm --sort=-rss --no-headers 2>/dev/null | head -6 | awk '{printf \"• %s%% %s (%s)\\n\", \$1, \$3, \$2}'"));
                $body = 'Available RAM is only ' . $availPct . '% of ' . round($memTotal / 1048576, 1) . ' GB'
                      . ($swapTotal > 0 ? ('; swap is ' . $swapUsedPct . '% used.') : '; NO swap is configured (a spike will trigger the OOM killer immediately).')
                      . "\n\nTop memory consumers:\n" . ($cause ?: 'n/a')
                      . "\n\nThe kernel may start killing processes (OOM). Add RAM/swap (Disk & Storage › Swap) or stop a runaway in Top Processes.";
                // coarse signature so it fires once then respects the remind window instead of churning on every %
                $maybe('mem_pressure', 'mem:crit', 'Memory pressure — OOM risk', $body, ['severity' => 'high']);
            } else {
                // On CloudLinux, HOST RAM is usually healthy while individual accounts hit their per-tenant LVE
                // memory limit (OOM is per-tenant, not global) - a global reading alone is misleading. When the host
                // looks fine, surface accounts hitting LVE memory faults instead (probed only here, off the hot path).
                $lve = is_executable('/usr/sbin/lveinfo') ? '/usr/sbin/lveinfo' : (is_executable('/usr/bin/lveinfo') ? '/usr/bin/lveinfo' : '');
                $faults = [];   // uid => memory faults (PMemF + VMemF) in the last hour
                if ($lve !== '') {
                    // lveinfo prints a box-drawing table; ID is the numeric LVE id (= uid). Columns PMemF/VMemF are the
                    // physical/virtual memory-limit fault counts.
                    $raw = (string)@shell_exec('timeout 20 ' . escapeshellarg($lve) . ' --period=1h --limit 200 --show-columns=id,PMemF,VMemF 2>/dev/null');
                    foreach (explode("\n", $raw) as $l) {
                        // id, PMemF, VMemF - \D*$ swallows the trailing box-drawing "│" (multibyte) so the anchor
                        // holds without the /u flag; header rows (ID/PMemF/VMemF text) have no 3-number pattern.
                        if (preg_match('/(\d+)\D+(\d+)\D+(\d+)\D*$/', trim($l), $m)) {
                            $f = (int)$m[2] + (int)$m[3];
                            if ($f > 0 && smpro_ntf_lve_acct((int)$m[1]) !== '') $faults[(int)$m[1]] = $f;   // real cPanel accounts only
                        }
                    }
                }
                arsort($faults);
                // Threshold so this is a MONITOR, not noise: a big shared box always has a couple of accounts
                // brushing their default 1 GB limit in brief bursts - that is normal background, not an incident.
                // Alert only on a real pattern: many accounts faulting at once, OR one account faulting heavily
                // (sustained per-tenant pressure = a likely leak/runaway). Both tunable in Notifications thresholds.
                $accThr = (int)($thr['lve_mem_accounts'] ?? 5);
                $oneThr = (int)($thr['lve_mem_faults'] ?? 60);
                $maxFaults = $faults ? (int)reset($faults) : 0;
                $tenants = [];
                if (count($faults) >= $accThr || $maxFaults >= $oneThr) {
                    foreach (array_slice($faults, 0, 8, true) as $uid => $f) {
                        $name = function_exists('posix_getpwuid') ? (posix_getpwuid($uid)['name'] ?? (string)$uid) : (string)$uid;
                        $tenants[] = $name . ' (' . $f . ' mem faults/h)';
                    }
                }
                if ($tenants) {
                    $body = count($tenants) . ' account(s) are hitting their CloudLinux LVE memory limit (per-tenant OOM) in the last hour, while host RAM is healthy (' . $availPct . '% free):'
                          . "\n• " . implode("\n• ", $tenants)
                          . "\n\nRaise the affected accounts' Physical Memory LVE limit, or investigate a runaway/leak in those accounts. This is NOT a host-wide memory problem.";
                    $maybe('mem_pressure', 'lvemem:' . md5(implode(',', $tenants)), 'CloudLinux tenants hitting LVE memory limits', $body, ['severity' => 'medium']);
                } else $maybe('mem_pressure', 'clear:lvemem', '', '');   // the tenants scan clears its slot; 'mem:crit' is the host's
            }
        }
    }

    // 7e) CloudLinux LVE resource faults (CPU / IO / entry-processes / processes). Real-world lesson from a
    //     live 1,845-account box: the per-tenant limits accounts ACTUALLY hit are IO-throttle and CPU-throttle
    //     (far more than memory OOM) - this is what "my site is slow" usually is on shared hosting. Surface which
    //     accounts are constrained and on what, so the host can raise a plan or spot an abuser. (Memory faults are
    //     covered by mem_pressure above.) Thresholds keep it a monitor, not noise.
    $lvebin = is_executable('/usr/sbin/lveinfo') ? '/usr/sbin/lveinfo' : (is_executable('/usr/bin/lveinfo') ? '/usr/bin/lveinfo' : '');
    if ($lvebin !== '') {
        $checked[] = 'lve_resource';
        $raw = (string)@shell_exec('timeout 25 ' . escapeshellarg($lvebin) . ' --period=1h --limit 5000 --show-columns=id,CPUf,EPf,NprocF,IOf 2>/dev/null');
        $cat = ['CPU' => [], 'IO' => [], 'entry-process' => [], 'processes' => []];
        foreach (explode("\n", $raw) as $l) {
            // split on the box-drawing separators (│ U+2502, ┆ U+2506) and the ASCII pipe; cells: ''|id|CPUf|EPf|NprocF|IOf
            $c = preg_split('/[\x{2502}\x{2506}|]/u', $l) ?: [];
            $c = array_map('trim', $c);
            if (count($c) < 6 || !ctype_digit($c[1])) continue;   // skip header/border rows
            $uid = (int)$c[1];
            if (smpro_ntf_lve_acct($uid) === '') continue;        // real cPanel accounts only (skip reserved/system LVE ids like 255)
            if ((int)$c[2] > 0) $cat['CPU'][$uid] = (int)$c[2];
            if ((int)$c[3] > 0) $cat['entry-process'][$uid] = (int)$c[3];
            if ((int)$c[4] > 0) $cat['processes'][$uid] = (int)$c[4];
            if ((int)$c[5] > 0) $cat['IO'][$uid] = (int)$c[5];
        }
        $manyThr = (int)($thr['lve_accounts'] ?? 8);    // alert when this many accounts hit ONE limit type in the hour
        $oneThr  = (int)($thr['lve_faults'] ?? 200);    // ...or a single account hitting a limit this hard (abuse / struggling site)
        $lines = [];
        foreach ($cat as $type => $map) {
            if (!$map) continue;
            arsort($map);
            $top = (int)reset($map);
            if (count($map) >= $manyThr || $top >= $oneThr) {
                $names = [];
                foreach (array_slice($map, 0, 5, true) as $uid => $f) {
                    $nm = function_exists('posix_getpwuid') ? (posix_getpwuid($uid)['name'] ?? (string)$uid) : (string)$uid;
                    $names[] = $nm . ' (' . $f . ')';
                }
                $lines[] = strtoupper($type) . ' limit: ' . count($map) . ' account(s) — top: ' . implode(', ', $names);
            }
        }
        if ($lines) {
            $body = "Accounts are repeatedly hitting their CloudLinux LVE resource limits in the last hour (the per-tenant caps that slow customer sites):\n• "
                  . implode("\n• ", $lines)
                  . "\n\nFor a persistently-throttled account: raise its LVE limit / move it to a bigger package, or investigate abuse (a heavy plugin, bad cron, or attack traffic). IO-throttling usually means slow queries or heavy file activity.";
            $maybe('lve_resource', 'lveres:' . md5(implode('|', $lines)), 'CloudLinux accounts hitting LVE resource limits', $body, ['severity' => 'medium']);
        } else $maybe('lve_resource', 'clear', '', '');
    }

    // 8) license expiry - MANDATORY reminders (2 days, 1 day, then at expiry). Force-sent,
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
                $st['license_expiry'] = 'clear';   // > 2 days away -> reset so the cycle re-fires next renewal period
            }
        }
    }

    smpro_ntf_state_save($st);
    return ['fired' => $fired, 'checked' => $checked, 'at' => date('Y-m-d H:i:s')];
}
