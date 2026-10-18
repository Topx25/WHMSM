<?php
/**
 * auth_otp.php — email one-time-code admin login (additive, self-contained).
 *   • /login      — step 1: enter admin email → a 6-digit code is emailed; step 2: enter code → signed in.
 *   • /login-pw   — emergency fallback: the original username/password login (so you can never be locked out).
 *   • /logout     — handled by the core (session_destroy).
 * Codes: 6 digits, 3-minute expiry, single-use, hashed at rest, 5-attempt cap, 60s resend throttle.
 * Authorized emails live in admin_auth(email → admin_id). Reuses the host app: db(), h(), csrf_token(),
 * require_csrf(), redirect(), layout_start()/layout_end().
 */
if (!function_exists('db')) { return; }

const AUTHOTP_TTL         = 180;     // code lifetime (seconds) = 3 minutes
const AUTHOTP_RESEND      = 60;      // min seconds between code sends
const AUTHOTP_MAXATTEMPTS = 5;       // wrong-code attempts before the code is locked
const AUTHOTP_FROM        = 'no-reply@plugins.iptvpro.org';
// --- per-IP brute-force guard (app-level block on the login surface) ---
const AUTHOTP_GUARD_MAX      = 3;      // failed attempts (wrong email / wrong code / wrong password) before an IP block
const AUTHOTP_GUARD_COOLDOWN = 3600;   // how long a blocked IP stays blocked (seconds) = 1 hour
const AUTHOTP_GUARD_WINDOW   = 1800;   // rolling window — fails older than this are forgiven (30 min)
// admin-tunable overrides (Settings → Login Security); fall back to the consts above when unset
function authotp_guard_max(): int      { $v = (int)settings_get('lg_max');          return $v > 0 ? $v : AUTHOTP_GUARD_MAX; }
function authotp_guard_cooldown(): int  { $v = (int)settings_get('lg_cooldown_min');  return $v > 0 ? $v * 60 : AUTHOTP_GUARD_COOLDOWN; }
function authotp_guard_window(): int    { $v = (int)settings_get('lg_window_min');    return $v > 0 ? $v * 60 : AUTHOTP_GUARD_WINDOW; }

/** Idempotent: create the table and make sure the admin email is registered for OTP login. */
function authotp_migrate(): void {
    static $done = false; if ($done) return; $done = true;
    db()->query("CREATE TABLE IF NOT EXISTS admin_auth (
        email VARCHAR(190) NOT NULL PRIMARY KEY,
        admin_id INT NOT NULL,
        code_hash VARCHAR(255) NULL,
        expires_at DATETIME NULL,
        attempts INT NOT NULL DEFAULT 0,
        last_sent_at DATETIME NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    authotp_register_admin('topx1.host@gmail.com');
}

/** Ensure an admins row exists for $email (OTP-only, random password) and link it in admin_auth. */
function authotp_register_admin(string $email): void {
    $email = strtolower(trim($email));
    if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) return;
    $rnd = password_hash(bin2hex(random_bytes(18)), PASSWORD_DEFAULT);     // unusable password (OTP-only)
    $st = db()->prepare("INSERT IGNORE INTO admins (username, password_hash) VALUES (?, ?)");
    $st->bind_param('ss', $email, $rnd); $st->execute();
    $aid = 0;
    $st = db()->prepare("SELECT id FROM admins WHERE username=? LIMIT 1");
    $st->bind_param('s', $email); $st->execute(); $st->bind_result($aid); $st->fetch(); $st->close();
    if (!$aid) return;
    $st = db()->prepare("INSERT IGNORE INTO admin_auth (email, admin_id) VALUES (?, ?)");
    $st->bind_param('si', $email, $aid); $st->execute();
}

function authotp_lookup(string $email): ?array {
    $email = strtolower(trim($email));
    $st = db()->prepare("SELECT email, admin_id, code_hash, expires_at, attempts, last_sent_at FROM admin_auth WHERE email=? LIMIT 1");
    $st->bind_param('s', $email); $st->execute();
    $r = $st->get_result()->fetch_assoc();
    return $r ?: null;
}

/** Generate, store (hashed) and email a fresh code. Returns [bool ok, string status]. */
function authotp_send(string $email): array {
    $row = authotp_lookup($email);
    // HARD allowlist: a login code is ONLY ever generated/sent for an email registered in admin_auth.
    // No code, no message, and nothing written to disk for any other address.
    if (!$row) return [false, 'not_registered'];
    if (!empty($row['last_sent_at']) && (time() - strtotime((string)$row['last_sent_at'])) < AUTHOTP_RESEND)
        return [false, 'too_soon'];
    $code = str_pad((string)random_int(0, 999999), 6, '0', STR_PAD_LEFT);
    $hash = password_hash($code, PASSWORD_DEFAULT);
    $exp  = date('Y-m-d H:i:s', time() + AUTHOTP_TTL);
    $st = db()->prepare("UPDATE admin_auth SET code_hash=?, expires_at=?, attempts=0, last_sent_at=NOW() WHERE email=?");
    $st->bind_param('sss', $hash, $exp, $email); $st->execute();
    // Codes are NEVER written to disk — they are delivered only to the registered admin (email / WhatsApp).
    return [authotp_mail($email, $code) ? true : false, 'sent'];
}

function authotp_mail(string $email, string $code): bool {
    // Code FIRST in the subject → it shows in the phone's notification preview WITHOUT opening the email; and ALONE
    // on the first body line → the preview text is just the code and a triple-tap / line-select copies only it.
    $subj = $code . ' is your Safety Monitor Pro login code';
    $body = $code . "\r\n\r\n"
          . "This is your Safety Monitor Pro admin login code (valid 3 minutes, single use).\r\n"
          . "If you did not request it, you can ignore this email.\r\n";
    $any = false;
    // WhatsApp delivery — TWO messages: (1) the CODE on its own FIRST (long-press → Copy grabs just the number on
    // mobile), then (2) the descriptive message (this format shows the hover/Copy on desktop) as the latest message.
    if (function_exists('wa_enabled') && wa_enabled()) {
        $we = ''; $we2 = '';
        wa_send($code, $we);
        if (wa_send("*Safety Monitor Pro*\nAdmin login code: *" . $code . "*\nValid 3 minutes, single use.", $we2)) $any = true;
    }
    // Email delivery (admin-configured SMTP, else local postfix).
    if (function_exists('mailer_send')) { $ee = ''; if (mailer_send($email, $subj, $body, $ee)) $any = true; }
    else {
        $headers = 'From: Safety Monitor Pro <' . AUTHOTP_FROM . ">\r\n" . 'Reply-To: ' . AUTHOTP_FROM . "\r\n"
                 . "Content-Type: text/plain; charset=utf-8\r\n" . 'X-Auto-Response-Suppress: All';
        if (@mail($email, $subj, $body, $headers, '-f ' . AUTHOTP_FROM)) $any = true;
    }
    return $any;
}

/** Verify a submitted code; on success set the admin session. */
function authotp_verify(string $email, string $code): bool {
    $row = authotp_lookup($email);
    if (!$row || empty($row['code_hash']) || empty($row['expires_at'])) return false;
    if ((int)$row['attempts'] >= AUTHOTP_MAXATTEMPTS) return false;
    if (strtotime((string)$row['expires_at']) < time()) return false;
    $st = db()->prepare("UPDATE admin_auth SET attempts=attempts+1 WHERE email=?");
    $st->bind_param('s', $email); $st->execute();
    if (!password_verify($code, (string)$row['code_hash'])) return false;
    $st = db()->prepare("UPDATE admin_auth SET code_hash=NULL, expires_at=NULL, attempts=0 WHERE email=?");
    $st->bind_param('s', $email); $st->execute();
    $_SESSION['admin_id']   = (int)$row['admin_id'];
    $_SESSION['admin_user'] = $email;
    return true;
}

function authotp_page(string $step, string $email = '', string $error = '', string $note = ''): void {
    layout_start('Admin Login');
    echo '<div class="card" style="max-width:440px;margin:24px auto">';
    echo '<h2>&#128274; Admin Login</h2>';
    if ($error !== '') echo '<p style="color:#b91c1c;font-weight:900">' . h($error) . '</p>';
    if ($note  !== '') echo '<p style="color:#047857;font-weight:800">' . h($note) . '</p>';
    if ($step === 'code') {
        echo '<p style="color:#475569">Enter the 6-digit code sent to <b>' . h($email) . '</b> (valid 3 minutes).</p>';
        echo '<form method="post" action="/login">';
        echo '<input type="hidden" name="csrf" value="' . h(csrf_token()) . '">';
        echo '<input type="hidden" name="email" value="' . h($email) . '">';
        echo '<p><label>Login code</label><input name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]*" maxlength="6" required autofocus></p>';
        echo turnstile_widget();
        echo '<button class="btn" type="submit" name="step" value="verify">Verify &amp; sign in</button> ';
        echo '<button class="btn" type="submit" name="step" value="send" formnovalidate style="background:#64748b">Resend code</button>';
        echo '</form>';
    } else {
        echo '<form method="post" action="/login">';
        echo '<input type="hidden" name="csrf" value="' . h(csrf_token()) . '">';
        echo '<p><label>Admin email</label><input name="email" type="email" required autofocus placeholder="you@example.com"></p>';
        echo turnstile_widget();
        echo '<button class="btn" type="submit" name="step" value="send">Send login code</button>';
        echo '</form>';
    }
    echo '</div>';
    layout_end();
}

/** Strong 14-char password: upper+lower+digits+symbols (unambiguous). */
function authotp_genpw(): string {
    $U='ABCDEFGHJKLMNPQRSTUVWXYZ'; $L='abcdefghijkmnpqrstuvwxyz'; $D='23456789'; $S='!@#$%&*-_+=?';
    $pick = fn($s) => $s[random_int(0, strlen($s) - 1)];
    $c = [$pick($U),$pick($U),$pick($L),$pick($L),$pick($L),$pick($D),$pick($D),$pick($S),$pick($S)];
    $all = $U.$L.$D.$S; while (count($c) < 14) $c[] = $pick($all);
    for ($i = count($c) - 1; $i > 0; $i--) { $j = random_int(0, $i); [$c[$i],$c[$j]] = [$c[$j],$c[$i]]; }
    return implode('', $c);
}

function authotp_pw_page(string $ip = ''): void {
    $error = ''; $note = '';
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        require_csrf();
        if (($_POST['pw_action'] ?? '') === 'sendpw') {
            // Enter email → generate a fresh password, set it, and deliver via the enabled channel(s).
            $email = strtolower(trim((string)($_POST['email'] ?? '')));
            $note  = 'If that email is registered, a new login password was sent to the enabled channel(s) (WhatsApp / email). Check your phone / inbox.';
            $last  = function_exists('settings_get') ? (float)settings_get('pwsend_last') : 0;
            if ($email !== '' && filter_var($email, FILTER_VALIDATE_EMAIL) && (time() - $last) >= 60) {
                $st = db()->prepare("SELECT id FROM admins WHERE username=? LIMIT 1");
                $st->bind_param('s', $email); $st->execute(); $st->bind_result($aid); $found = $st->fetch(); $st->close();
                if ($found && $aid) {
                    $pw = authotp_genpw(); $hash = password_hash($pw, PASSWORD_DEFAULT);
                    $st = db()->prepare("UPDATE admins SET password_hash=? WHERE id=?"); $st->bind_param('si', $hash, $aid); $st->execute();
                    if (function_exists('settings_set')) settings_set('pwsend_last', (string)time());
                    $body = "Safety Monitor Pro — admin login\nUsername: $email\nPassword: $pw\n\nSign in: https://plugins.iptvpro.org/login-pw";
                    if (function_exists('wa_enabled') && wa_enabled()) { $e = ''; @wa_send("🔐 *Safety Monitor Pro* — admin login\nUser: " . $email . "\nPassword: *" . $pw . "*\nSign in at /login-pw", $e); }
                    if (function_exists('mailer_send')) { $ee = ''; @mailer_send($email, 'Safety Monitor Pro — your login password', $body, $ee); }
                }
            }
        } elseif (turnstile_enabled() && !turnstile_verify((string)($_POST['cf-turnstile-response'] ?? ''), $ip)) {
            $error = 'Please complete the CAPTCHA and try again.';
        } else {
            $u = trim((string)($_POST['username'] ?? '')); $p = (string)($_POST['password'] ?? '');
            $st = db()->prepare("SELECT * FROM admins WHERE username=? LIMIT 1");
            $st->bind_param('s', $u); $st->execute(); $a = $st->get_result()->fetch_assoc();
            if ($a && password_verify($p, (string)$a['password_hash'])) {
                if (function_exists('authotp_guard_clear')) authotp_guard_clear($ip);   // success → reset strikes
                session_regenerate_id(true);
                $_SESSION['admin_id'] = (int)$a['id']; $_SESSION['admin_user'] = $a['username'];
                redirect('/licenses');
            }
            if (function_exists('authotp_guard_fail') && authotp_guard_fail($ip, 'pw')) { authotp_guard_blocked_page($ip); return; }   // wrong password → strike
            $error = 'Invalid username or password';
        }
    }
    layout_start('Admin Login');
    echo '<div class="card" style="max-width:440px;margin:24px auto"><h2>&#128274; Admin Login</h2>';
    if ($error !== '') echo '<p style="color:#b91c1c;font-weight:900">' . h($error) . '</p>';
    if ($note  !== '') echo '<p style="color:#047857;font-weight:800">' . h($note) . '</p>';
    echo '<form method="post" action="/login-pw"><input type="hidden" name="csrf" value="' . h(csrf_token()) . '">';
    echo '<p><label>Username</label><input name="username" required></p>';
    echo '<p><label>Password</label><input name="password" type="password" required></p>';
    echo turnstile_widget();
    echo '<button class="btn" type="submit">Login</button></form>';
    echo '<div style="border-top:1px solid #e2e8f0;margin:14px 0;padding-top:12px">';
    echo '<p style="font-weight:700;margin:0 0 6px">Get a new password sent to you</p>';
    echo '<form method="post" action="/login-pw"><input type="hidden" name="csrf" value="' . h(csrf_token()) . '"><input type="hidden" name="pw_action" value="sendpw">';
    echo '<p><label>Admin email</label><input name="email" type="email" required placeholder="you@example.com"></p>';
    echo '<button class="btn" type="submit" formnovalidate style="background:#16a34a">&#128241; Send password (WhatsApp / email)</button></form></div>';
    echo '<p style="margin-top:10px"><a href="/login">&#8592; Use email code login</a></p>';
    echo '</div>'; layout_end();
}

/* ============================ per-IP login brute-force guard ============================ */
/** Real client IP — the server sits behind Cloudflare/nginx, so REMOTE_ADDR is the proxy. Trust
 *  CF-Connecting-IP (set by Cloudflare) first, then the first X-Forwarded-For hop, then REMOTE_ADDR.
 *  Blocking the proxy IP would lock out everyone, so we must resolve the true client here. */
function authotp_client_ip(): string {
    foreach (['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR'] as $k) {
        $v = (string)($_SERVER[$k] ?? ''); if ($v === '') continue;
        $v = trim(explode(',', $v)[0]);
        if (filter_var($v, FILTER_VALIDATE_IP)) return $v;
    }
    return '';
}
function authotp_guard_migrate(): void {
    static $done = false; if ($done) return; $done = true;
    db()->query("CREATE TABLE IF NOT EXISTS login_guard (
        ip VARCHAR(45) NOT NULL PRIMARY KEY,
        fails INT NOT NULL DEFAULT 0,
        blocked_until DATETIME NULL,
        updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
}
/** unix ts the IP is blocked until (0 if not blocked). */
function authotp_guard_until(string $ip): int {
    if ($ip === '') return 0;
    $st = db()->prepare("SELECT blocked_until FROM login_guard WHERE ip=? LIMIT 1");
    $st->bind_param('s', $ip); $st->execute(); $r = $st->get_result()->fetch_assoc();
    if (!$r || empty($r['blocked_until'])) return 0;
    $u = strtotime((string)$r['blocked_until']); return $u > time() ? $u : 0;
}
function authotp_guard_blocked(string $ip): bool { return authotp_guard_until($ip) > 0; }
/** Record a failed login attempt for this IP; block it once it crosses the threshold. Returns true if now blocked. */
function authotp_guard_fail(string $ip, string $kind): bool {
    if ($ip === '') return false;
    $st = db()->prepare("SELECT fails, updated_at FROM login_guard WHERE ip=? LIMIT 1");
    $st->bind_param('s', $ip); $st->execute(); $r = $st->get_result()->fetch_assoc();
    // rolling window: forgive old failures so a legit admin isn't punished for a slip-up hours ago
    $fails = ($r && (time() - strtotime((string)$r['updated_at']) < authotp_guard_window())) ? (int)$r['fails'] : 0;
    $fails++;
    $max     = authotp_guard_max();
    $blocked = $fails >= $max;
    $until   = $blocked ? date('Y-m-d H:i:s', time() + authotp_guard_cooldown()) : null;
    $st = db()->prepare("INSERT INTO login_guard (ip, fails, blocked_until) VALUES (?,?,?)
        ON DUPLICATE KEY UPDATE fails=VALUES(fails), blocked_until=VALUES(blocked_until), updated_at=NOW()");
    $st->bind_param('sis', $ip, $fails, $until); $st->execute();
    if (function_exists('log_event')) { try { log_event('login_guard', 'login_fail_' . $kind, $blocked ? 'blocked' : 'fail', $ip . ' (' . $fails . '/' . $max . ')', []); } catch (\Throwable $e) {} }
    return $blocked;
}
/** Clear an IP's failure record (called on a successful sign-in). */
function authotp_guard_clear(string $ip): void {
    if ($ip === '') return;
    $st = db()->prepare("DELETE FROM login_guard WHERE ip=?"); $st->bind_param('s', $ip); $st->execute();
}
function authotp_guard_blocked_page(string $ip): void {
    http_response_code(429);
    $mins = max(1, (int)ceil((authotp_guard_until($ip) - time()) / 60));
    layout_start('Blocked');
    echo '<div class="card" style="max-width:440px;margin:24px auto">';
    echo '<h2>&#9940; Too many attempts</h2>';
    echo '<p style="color:#b91c1c;font-weight:800">This IP is temporarily blocked after too many failed login attempts.</p>';
    echo '<p style="color:#475569">Please try again in about <b>' . $mins . ' minute' . ($mins > 1 ? 's' : '') . '</b>.</p>';
    echo '</div>'; layout_end();
}

/* ============================ Cloudflare Turnstile (login CAPTCHA) ============================ */
function turnstile_site_key(): string { return settings_get('ts_site_key'); }
function turnstile_secret_set(string $p): void {
    if ($p === '') return;                                            // empty submit = keep existing
    $iv = random_bytes(16); $ct = openssl_encrypt($p, 'aes-256-cbc', app_key(), OPENSSL_RAW_DATA, $iv);
    settings_set('ts_secret_enc', base64_encode($iv . $ct));
}
function turnstile_secret(): string {
    $b = base64_decode(settings_get('ts_secret_enc')); if (strlen($b) < 17) return '';
    $p = openssl_decrypt(substr($b, 16), 'aes-256-cbc', app_key(), OPENSSL_RAW_DATA, substr($b, 0, 16));
    return $p === false ? '' : $p;
}
function turnstile_enabled(): bool { return settings_get('ts_enabled') === '1' && turnstile_site_key() !== '' && turnstile_secret() !== ''; }
function turnstile_widget(): string {
    if (!turnstile_enabled()) return '';
    return '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>'
         . '<div class="cf-turnstile" data-sitekey="' . h(turnstile_site_key()) . '" style="margin:12px 0"></div>';
}
/** Verify the Turnstile token with Cloudflare. Returns true when disabled (don't lock out login if unconfigured). */
function turnstile_verify(string $token, string $ip): bool {
    if (!turnstile_enabled()) return true;
    if ($token === '') return false;
    $post = http_build_query(['secret' => turnstile_secret(), 'response' => $token, 'remoteip' => $ip]);
    $out = '';
    if (function_exists('curl_init')) {
        $ch = curl_init('https://challenges.cloudflare.com/turnstile/v0/siteverify');
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_POST => true, CURLOPT_POSTFIELDS => $post,
            CURLOPT_TIMEOUT => 10, CURLOPT_SSL_VERIFYPEER => true, CURLOPT_SSL_VERIFYHOST => 2]);
        $out = (string)curl_exec($ch); curl_close($ch);
    } else {
        $ctx = stream_context_create(['http' => ['method' => 'POST', 'header' => 'Content-Type: application/x-www-form-urlencoded', 'content' => $post, 'timeout' => 10]]);
        $out = (string)@file_get_contents('https://challenges.cloudflare.com/turnstile/v0/siteverify', false, $ctx);
    }
    $j = json_decode($out, true);
    return is_array($j) && !empty($j['success']);
}

function authotp_route(string $path): bool {
    if ($path !== '/login' && $path !== '/login-pw') return false;   // /logout etc. fall through to the core
    authotp_migrate(); authotp_guard_migrate();
    $ip = authotp_client_ip();
    // HARD STOP: a blocked IP cannot even load the login form (covers /login and /login-pw, GET + POST)
    if (authotp_guard_blocked($ip)) { authotp_guard_blocked_page($ip); return true; }

    if ($path === '/login-pw') { authotp_pw_page($ip); return true; }

    // /login (email one-time-code flow)
    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
        require_csrf();
        $email = strtolower(trim((string)($_POST['email'] ?? '')));
        $step  = (string)($_POST['step'] ?? 'send');
        if (turnstile_enabled() && !turnstile_verify((string)($_POST['cf-turnstile-response'] ?? ''), $ip)) {
            authotp_page($step === 'verify' ? 'code' : 'email', $email, 'Please complete the CAPTCHA and try again.');
            return true;
        }
        if ($step === 'verify') {
            $code = preg_replace('/\D+/', '', (string)($_POST['code'] ?? ''));
            if ($email !== '' && $code !== '' && authotp_verify($email, $code)) {
                authotp_guard_clear($ip);                                   // success → reset the IP's strikes
                session_regenerate_id(true);
                redirect('/licenses');
            }
            $blocked = authotp_guard_fail($ip, 'code');                     // wrong/expired code → strike
            if ($blocked) { authotp_guard_blocked_page($ip); return true; }
            authotp_page('code', $email, 'Invalid or expired code — try again, or resend a new one.');
            return true;
        }
        // send / resend
        [$ok, $status] = authotp_send($email);
        // OTP-HARD-REJECT: an unregistered/unauthorized email is REJECTED on the email step — it never advances to
        // the code step and no code is generated/sent. (Also counts a brute-force strike for the IP guard.)
        if ($status === 'not_registered') {
            if (authotp_guard_fail($ip, 'email')) { authotp_guard_blocked_page($ip); return true; }
            authotp_page('email', $email, 'This email address is not authorized to sign in.');
            return true;
        }
        $err = ''; $note = 'A login code has been sent to your email / WhatsApp. Check your inbox (and spam).';
        if ($status === 'too_soon')   { $err = 'A code was just sent — please wait up to a minute before requesting another.'; $note = ''; }
        elseif ($status === 'sent' && !$ok) { $err = 'The email could not be sent right now. Please try again shortly.'; $note = ''; }
        authotp_page('code', $email, $err, $note);
        return true;
    }
    authotp_page('email');
    return true;
}
