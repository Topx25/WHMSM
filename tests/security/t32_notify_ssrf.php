<?php
/**
 * t32_notify_ssrf.php — Phase-3 security coverage for the Notifications + Telegram-bot layer.
 * Every assertion exercises a VALIDATION / EARLY-RETURN / DISABLED path, so NOTHING is ever
 * sent: the sendmail recorder and the curl recorder must both stay EMPTY, and the one place a
 * socket could open (SMTP) is pointed at a dead port (127.0.0.1:1) so it fails fast.
 *
 *   S26  smpro_ntf_url_unsafe       — SSRF guard: reject loopback/private/link-local/metadata + bad scheme/host
 *   ----  smpro_ntf_send_email      — validation-only: empty/invalid recipient -> [false,'no valid recipient'] (no send)
 *   S30  smpro_ntf_send_smtp        — host-not-configured early return; TLS-default-on context (verify_tls unset => verify_peer)
 *   S29  smpro_ntf_send_telegram    — bad bot-token format -> [false,'invalid bot token format'] (no net)
 *   I12  smpro_notify               — ALL channels disabled (default config) -> ['skipped'=>...] (no send at all)
 *   ----  tgbot smpro_tg_api/enable — empty-token API returns []; enable refused when unconfigured (no send)
 *
 * notify.php + tgbot.php have NO seam callees, so we require them RAW from SMPRO_BASE.
 * smpro_ntf_load() decrypts secrets only `if(function_exists('smpro_secret_dec'))`; we do NOT
 * require helpers.php, so that branch is skipped and the fresh-sandbox default config loads.
 */
require __DIR__ . '/../support/bootstrap.php';

require SMPRO_BASE . '/includes/notify.php';   // notify layer (no seams; raw source)
require SMPRO_BASE . '/includes/tgbot.php';    // telegram control bot (no seams; raw source)

// Any accidental real send would hit one of these recorders — start them clean and prove empty.
smpro_test_rec_reset('sendmail');
smpro_test_rec_reset('curl');

ok(function_exists('smpro_ntf_url_unsafe'), 'notify.php + tgbot.php loaded raw');

/* ---------- S26 — smpro_ntf_url_unsafe (SSRF guard). '' = SAFE, non-empty = reason ---------- */
// Literal IPs: filter_var validates locally (no DNS), so these are deterministic offline.
// NB derived from source: the FILTER_FLAG_NO_PRIV_RANGE|NO_RES_RANGE check runs FIRST, so 127.x and
// 169.254.x are caught as "private/reserved" — the later explicit loopback/link-local branch only
// fires for an IP the reserved filter let through (it never does for these), so we assert what the
// code ACTUALLY returns, not the by-name reason.
has(smpro_ntf_url_unsafe('https://127.0.0.1:2087'), 'private/reserved', 'S26 loopback 127.0.0.1 rejected (caught by reserved-range filter first)');
has(smpro_ntf_url_unsafe('http://169.254.169.254/latest/meta-data/'), 'private/reserved', 'S26 cloud-metadata 169.254.x rejected (reserved range)');
has(smpro_ntf_url_unsafe('http://10.0.0.5/api'),  'private/reserved', 'S26 private 10.x rejected (private/reserved)');
has(smpro_ntf_url_unsafe('http://192.168.1.1/'),  'private/reserved', 'S26 private 192.168.x rejected');
is_eq(smpro_ntf_url_unsafe('ftp://example.com/x'), 'scheme must be http(s)', 'S26 non-http(s) scheme rejected');
is_eq(smpro_ntf_url_unsafe('notaurl'),             'malformed URL', 'S26 malformed URL (no scheme/host) rejected');
is_eq(smpro_ntf_url_unsafe(''),                    'malformed URL', 'S26 empty URL rejected');
is_eq(smpro_ntf_url_unsafe('https://203.0.113.10:3000'), '', 'S26 public TEST-NET literal IP -> safe (empty reason)');
// IPv6 literals in bracket URL form (task_49e96efd, FIXED): parse_url() keeps the host as "[::1]"; the guard
// now strips the surrounding brackets BEFORE the IP checks, so loopback / ULA / link-local / IPv4-mapped-internal
// IPv6 targets are all rejected. (filter_var with NO_PRIV_RANGE|NO_RES_RANGE catches ::1, fc00::/7 and fe80::/10
// directly; the explicit smpro_ntf_ip6_unsafe() check additionally catches the IPv4-mapped ::ffff:a.b.c.d form,
// which those flags miss.) A regression that re-opens the bracket bypass turns these RED.
$u6 = smpro_ntf_url_unsafe('http://[::1]:8080/');
ok($u6 !== '', 'S26 IPv6 loopback [::1] now REJECTED (non-empty reason — bracket-host SSRF hole closed)');
has($u6, 'private/reserved', 'S26 [::1] -> "resolves to a private/reserved address" (brackets stripped, ::1 caught)');
has(smpro_ntf_url_unsafe('http://[fc00::1]/'), 'private/reserved', 'S26 IPv6 ULA [fc00::1] rejected (fc00::/7)');
has(smpro_ntf_url_unsafe('http://[fe80::1]/'), 'private/reserved', 'S26 IPv6 link-local [fe80::1] rejected (fe80::/10)');
has(smpro_ntf_url_unsafe('http://[::ffff:127.0.0.1]/'), 'private/reserved', 'S26 IPv4-mapped IPv6 [::ffff:127.0.0.1] rejected (filter flags miss it; explicit IPv6 check catches it)');
is_eq(smpro_ntf_url_unsafe('http://[2001:4860:4860::8888]/'), '', 'S26 public IPv6 literal [2001:4860:4860::8888] -> safe (fix does not over-block global IPv6)');

/* ---------- smpro_ntf_send_email — validation-only, NEVER sends ---------- */
$e1 = smpro_ntf_send_email([], 'from@example.com', 'subj', 'body');
is_eq($e1[0], false, 'send_email([]) -> false (no recipient)');
is_eq($e1[1], 'no valid recipient', 'send_email([]) -> "no valid recipient"');

$e2 = smpro_ntf_send_email(['not-an-email', '  '], 'from@example.com', 'subj', 'body');
is_eq($e2[0], false, 'send_email(invalid addrs) -> false');
is_eq($e2[1], 'no valid recipient', 'send_email(invalid addrs) -> filtered to none -> no valid recipient');

/* ---------- S30 — smpro_ntf_send_smtp: host-not-configured early return ---------- */
$s0 = smpro_ntf_send_smtp([], 'from@example.com', ['to@example.com'], 'subj', 'body');
is_eq($s0[0], false, 'send_smtp(no host) -> false');
is_eq($s0[1], 'SMTP host not configured', 'send_smtp(no host) -> "SMTP host not configured" (returns before any socket)');

/* ---------- S30 — TLS verify defaults ON: verify_tls unset => verify_peer true ---------- */
// Force a DEAD endpoint (127.0.0.1:1) so the connect fails fast; we assert the validation-shape
// of the return and that no recorder fired. (Source builds the ssl ctx with verify_peer = !isset
// (verify_tls) || (bool)verify_tls, i.e. ON by default — proven by reading notify.php; the connect
// to a dead port returns "connect failed (...)" without negotiating, which is the safe outcome.)
$dead = ['host' => '127.0.0.1', 'port' => 1];                 // verify_tls UNSET => verify defaults ON
$sd   = smpro_ntf_send_smtp($dead, 'from@example.com', ['to@example.com'], 'subj', 'body');
is_eq($sd[0], false, 'S30 send_smtp(dead 127.0.0.1:1) -> false (no SMTP server)');
has($sd[1], 'connect failed', 'S30 dead port -> "connect failed (...)" (failed before sending any data)');

/* ---------- S29 — smpro_ntf_send_telegram: bad token format, NO network ---------- */
$t0 = smpro_ntf_send_telegram('', 'chat', 'hi');
is_eq($t0, [false, 'token/chat_id missing'], 'S29 telegram empty token -> token/chat_id missing');
$tm = smpro_ntf_send_telegram('123:abc', '', 'hi');
is_eq($tm, [false, 'token/chat_id missing'], 'S29 telegram empty chat_id -> token/chat_id missing');
$tb = smpro_ntf_send_telegram('not-a-valid-token', '12345', 'hi');
is_eq($tb, [false, 'invalid bot token format'], 'S29 telegram bad-token format rejected before smpro_http (no net)');
// telegram_chats: bad token -> [] before any smpro_http call
is_eq(smpro_ntf_telegram_chats('garbage'), [], 'S29 telegram_chats(bad token) -> [] (no getUpdates call)');

/* ---------- I12 — smpro_notify with ALL channels disabled (default config) -> skipped ---------- */
// Fresh sandbox => no config.json => default config (email/telegram/pushbullet/whatsapp all enabled=false).
// 'test' type is on=true, so we pass the per-type "on" gate and reach the no-channel branch.
$r = smpro_notify('test', 'hello', 'world');
is_eq($r, ['skipped' => 'no channel enabled for this type'], 'I12 all channels disabled -> ["skipped"=>"no channel enabled for this type"]');
// 'load_high' is the only default-OFF type -> type-disabled short circuit (still no send).
$r2 = smpro_notify('load_high', 'x', 'y');
is_eq($r2, ['skipped' => 'type disabled'], 'I12 default-off type -> ["skipped"=>"type disabled"]');

/* ---------- tgbot — empty-token API + unconfigured enable, NO send ---------- */
// smpro_tg_cfg() reads notify config: telegram disabled + empty token/chat_id by default.
$cfg = smpro_tg_cfg();
is_eq($cfg['enabled'], false, 'tgbot disabled by default (no state file)');
is_eq($cfg['token'], '', 'tgbot token empty by default');
is_eq($cfg['allowed'], [], 'tgbot has no allowed chats by default');
// smpro_tg_api with empty token returns [] before constructing any URL / calling smpro_http.
is_eq(smpro_tg_api('', 'getUpdates'), [], 'tgbot_api(empty token) -> [] (no smpro_http / no net)');
// enable(true) must REFUSE when token+admin unconfigured -> no welcome message is sent.
$en = smpro_tg_enable(true);
is_eq($en['ok'], false, 'tg_enable(true) refused when unconfigured');
has($en['msg'], 'Configure the Telegram token', 'tg_enable(true) -> asks admin to configure first (no send)');
// smpro_tg_poll: not enabled -> returns immediately (no getUpdates, no lock churn).
lives_ok('smpro_tg_poll', 'tg_poll() no-ops when disabled (no exception, no net)');

/* ---------- the "never sent" proof: both recorders stayed EMPTY across the whole file ---------- */
ok(smpro_test_rec_empty('sendmail'), 'sendmail was NEVER invoked (recorder empty — no mail left the box)');
ok(smpro_test_rec_empty('curl'),     'curl was NEVER invoked (recorder empty — no HTTP left the box)');

/* ---------- deferred to Phase 4 (need a SPY on a destructive/network callee, not in seam set) ---------- */
tap_skip('smpro_ntf_send_smtp full TLS handshake (needs a fake STARTTLS server / socket spy)', 'Phase 4: socket-server fixture');
tap_skip('smpro_ntf_send_whatsapp failover (needs smpro_http spy to assert session order without net)', 'Phase 4: smpro_http spy');
