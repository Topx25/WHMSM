<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
require_once SMPRO_BASE . '/includes/botguard.php';
require_once SMPRO_BASE . '/includes/fileaudit.php';
/**
 * t175 - review round 427: Safety Lock requests, the hub member's own lock, the automatic workers.
 */
$src = fn($p) => str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/' . $p));

/* ---------- Bot Guard: what is counted as an attack ---------- */
$ips = [];
$line = fn(string $ip, string $req, int $st, string $ref, string $ua) => $ip . ' - - [' . date('d/M/Y:H:i:s O') . '] "' . $req . '" ' . $st . ' 512 "' . $ref . '" "' . $ua . '"';
$chrome = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36';
$p = smpro_bg_parse_line($line('203.0.113.9', 'GET /.env HTTP/1.1', 404, 'http://a\\"b', $chrome));
ok(is_array($p) && $p['uri'] === '/.env' && $p['status'] === 404, 'B1: a quote in the Referer no longer hides the request');
$p2 = smpro_bg_parse_line($line('203.0.113.9', 'GET /x HTTP/1.1', 200, '-', 'a \\"quoted\\" agent'));
ok(is_array($p2) && strpos($p2['ua'], 'quoted') !== false, 'B2: ...nor one in the User-Agent');
smpro_bg_aggregate($ips, smpro_bg_parse_line($line('203.0.113.10', 'POST /wp-login.php HTTP/1.1', 302, '-', $chrome)), 'example.test', 0);
ok(!isset($ips['203.0.113.10']), 'B3: a WordPress sign-in that worked (redirect) is not a password guess');
smpro_bg_aggregate($ips, smpro_bg_parse_line($line('203.0.113.11', 'POST /wp-login.php HTTP/1.1', 200, '-', $chrome)), 'example.test', 0);
is_eq((int)($ips['203.0.113.11']['attacks'] ?? 0), 1, 'B4: a wrong password (the form again) still is');
is_eq(smpro_bg_classify_req('GET', '/api/orders', 'python-requests/2.31.0'), '', 'B5: a plain library client fetching an ordinary URL is not a scanner');
is_eq(smpro_bg_classify_req('POST', '/webhook', 'Go-http-client/1.1'), '', 'B6: ...nor is a webhook sender');
is_eq(smpro_bg_classify_req('GET', '/.env', 'python-requests/2.31.0'), 'probe', 'B7: the same client fetching a secret file is counted');
is_eq(smpro_bg_classify_req('GET', '/', 'sqlmap/1.7'), 'scanner', 'B8: a named attack tool still is a scanner');
$bg = $src('includes/botguard.php');
has($bg, "if (\$vN >= 40 || microtime(true) - \$vT0 > 90) {", 'B9: name lookups in one pass are bounded in number and in time');

/* ---------- file audit: names as the audit log writes them ---------- */
is_eq(smpro_fa_field('type=PATH msg=audit(1.1:2): item=1 name="/home/u/a.php" inode=1', 'name'), '/home/u/a.php', 'F1: a quoted name is read as it is');
is_eq(smpro_fa_field('type=PATH msg=audit(1.1:2): item=1 name=' . strtoupper(bin2hex('/home/u/my file.php')) . ' inode=1', 'name'), '/home/u/my file.php', 'F2: a hex-written name (it has a space) is decoded');
is_eq(smpro_fa_field('type=PATH msg=audit(1.1:2): item=0 name=(null) inode=1', 'name'), '(null)', 'F3: (null) stays (null)');
is_eq(smpro_fa_norm('/home/./u/public_html/../public_html/index.php'), '/home/u/public_html/index.php', 'F4: dot parts are worked out');
is_eq(smpro_fa_account_of('/home/./u/x'), '', 'F5: "." is never an account');
is_eq(smpro_fa_account_of('/home/../x'), '', 'F6: nor is ".."');
is_eq(smpro_fa_account_of(smpro_fa_norm('/home/./u/x')), 'u', 'F7: the worked-out path belongs to its real account');

/* ---------- source: the rest of the round ---------- */
$sv = $src('includes/svcmon.php');
has($sv, "if (!\$active && \$units && \$noAns >= count(\$units) && empty(\$s['product'])) \$state = 'unknown';", 'S1: no answer from the service manager is unknown, not down');
has($sv, "if ((\$row['state'] ?? '') === 'unknown') continue;", 'S2: and the monitor does not act on unknown');
$i = strpos($sv, "\$s['restarts'][] = \$now; \$acted++; \$state[\$key] = \$s; smpro_svcmon_state_save(\$state);");
$j = strpos($sv, "\$r = smpro_svcmon_control(\$key, smpro_svc_restartsrv(\$svc) !== '' ? 'restart' : 'start');");
ok($i !== false && $j !== false && $i < $j, 'S3: an attempt is counted and saved before it starts');
has($sv, "\$state[\$key] = ['restarts' => \$s['restarts']]; continue;", 'S4: a restart that worked keeps the count of the hour');

has($src('includes/evidence.php'), "\$cur = smpro_ev_state(); foreach (['head', 'day', 'seq'] as \$ck) \$s[\$ck] = \$cur[\$ck];", 'E1: the run keeps the chain head its own records moved');

$q = $src('includes/spqueue.php');
has($q, "['unlock_permanent', 'unlock_selected', 'unlock_hour', 'ignore', 'relock']", 'Q1: a one-hour request for chosen files is stored as what it is');
ok(strpos($q, 'foreach (scandir($dir) ?: [] as $e) {') === false, 'Q2: the queue folder is not read whole into memory');
has($q, "if (\$now - (int)@strtotime((string)(\$ask['at'] ?? '')) > 7200) continue;", 'Q3: an old request is not retried for automatic approval');
has($q, "\$relist = !empty(\$row['paths']) ? array_map('strval', (array)\$row['paths']) : smpro_spq_targets(\$user);", 'Q4: what was released is what is locked again');
$r = $src('includes/sprules.php');
has($r, "if (strpos(\$line, 'method=handle_form_login') === false) continue;", 'R1: only a sign-in through the form counts as the account signing in');
has($r, "(\$askAt < \$loginAt || \$askAt - \$loginAt > 3600)", 'R2: and the request must follow it within the hour');
has($src('includes/phlock.php'), "smpro_audit('safetylock_lock_escaped'", 'P1: a lock that landed outside the account is taken off and recorded');
has($src('includes/hub.php'), "smpro_hub_is_locked() && !in_array(\$action, ['ping', 'status'], true)", 'H1: a locked member runs nothing that changes it');
$im = $src('includes/intrusion.php');
has($im, "smpro_audit('login_guard_block_failed'", 'L1: a Login Guard block that did not take is recorded as failed');
has($src('includes/geologin.php'), "smpro_audit(\$took ? 'geologin_block' : 'geologin_block_failed'", 'L2: and so is a country-lock block');
has($src('includes/maintenance.php'), "if (\$n0 > 5000) {", 'M1: the purge breaker counts real candidates per account');
