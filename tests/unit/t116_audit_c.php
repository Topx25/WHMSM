<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
/** t116 - web-layer audit: control password needs the current one, secret-bearing calls never follow redirects, no package without a signed manifest, session-bound CSRF, REMOTE_ADDR-first lockout guards, exact format match in index.cgi. */
$ix = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/index.php'));
has($ix, "if (smpro_hub_cpass_isset() && !smpro_hub_cpass_verify((string)(\$_POST['old_pw'] ?? '')))", 'M1: replacing the control password proves the current one');
is_eq(substr_count($ix, "smpro_ratelimit('hub_cpass', 5, 300)"), 2, 'L2: set and unlock are rate-limited');
ok(smpro_http_has_secret_header(['X-API-Key: abc']), 'M2: an API-key header is a secret');
ok(smpro_http_has_secret_header(['Key: abc', 'Accept: application/json']), 'M2: AbuseIPDB style key too');
ok(!smpro_http_has_secret_header(['Accept: application/json']), 'M2: plain headers are not');
$h = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/helpers.php'));
has($h, "CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS,", 'M2: redirects may not leave https');
has($h, "&& !smpro_http_has_secret_header(\$headers),", 'M2: a secret-bearing call never follows a redirect');
$u = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/update.php'));
has($u, "Package carries no signed version manifest", 'M3: a package without a signed manifest is refused');
$hub = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/hub.php'));
has($hub, "\$r = smpro_upd_apply(\$ver, false);", 'M3: the hub never forces past the downgrade guard');
$cs = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/csrf.php'));
ok(substr_count($cs, "(defined('SMPRO_CPSESS') ? (string)SMPRO_CPSESS : '')") >= 2, 'L1: the CSRF HMAC is bound to the WHM session');
foreach (['modules/firewall-status.php', 'includes/bfrules.php', 'modules/account-audit.php'] as $f) {
    $s = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/' . $f));
    hasnt($s, "['HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'REMOTE_ADDR']", 'L3: ' . $f . ' no longer trusts a forwarded header first');
}
$cgi = (string)file_get_contents(SMPRO_BASE . '/index.cgi');
has($cgi, 'case "&${QUERY_STRING:-}&" in', 'L4: the format switch matches whole parameters');
has($cgi, '*"&format=pdf&"*)', 'L4: ...pdf exactly');
ok(substr_count($cgi, "Content-Security-Policy:") >= 2, 'L4: the print branch carries the CSP too');
$lay = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/layout.php'));
hasnt($lay, "'<div class=\"sm-aierr\">'+((j&&j.error)||'AI request failed')+'</div>'", 'L7: provider error text is escaped before innerHTML');
