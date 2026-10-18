<?php
require __DIR__ . '/../support/bootstrap.php';

/**
 * t16_notify_ai_hub — pure, no-network helpers from the Notifications, AI, Hub
 * and Reports includes. Every expected value below is derived by READING the
 * source (includes/notify.php, ai.php, hub.php, reports.php).
 *
 * Targets:
 *   U70  smpro_ntf_url_unsafe        (SSRF guard — '' for a literal public IP/url, reason otherwise)
 *   U71  smpro_ntf_wa_chat           (recipient → "<digits>@c.us" normalisation)
 *        smpro_ntf_wa_ready          (ready-status set membership)
 *        smpro_ntf_send_telegram     (invalid-token → [false,'invalid bot token format'], NO network)
 *   U76  smpro_ai_redact             (api_key/cpsess/PEM/ssh-rsa/$6$ redaction)
 *   U77  smpro_ai_json               (clean / fenced / prose-wrapped / trailing-comma / 'no json'→null)
 *   U79  smpro_hub_action_perm       (action → required perm; unknown/default → 'view')
 *        smpro_hub_perms_all         (permission catalog shape)
 *   U73  smpro_rep_render_html/text  (HTML render escapes a '<b>x' XSS field; text render does not)
 *
 * NON-NETWORK NOTE: all unsafe-URL cases use LITERAL IPs so nothing resolves via DNS;
 * the telegram bad-token case returns at the regex check BEFORE smpro_http() is ever called.
 */
require SMPRO_BASE . '/includes/notify.php';
require SMPRO_BASE . '/includes/ai.php';
require SMPRO_BASE . '/includes/hub.php';
require SMPRO_BASE . '/includes/reports.php';

/* ============================================================ *
 *  U70 — smpro_ntf_url_unsafe (SSRF guard)
 *  '' = safe; a non-empty string = the rejection reason.
 * ============================================================ */

// --- SAFE: a literal PUBLIC IP (no DNS lookup happens for a literal IP) ---
is_eq(smpro_ntf_url_unsafe('http://8.8.8.8/'), '', 'url_unsafe: http + public IP 8.8.8.8 is safe ("")');
is_eq(smpro_ntf_url_unsafe('https://1.1.1.1:3000/api/sessions'), '', 'url_unsafe: https + public IP with port/path is safe');

// --- malformed / scheme branch ---
is_eq(smpro_ntf_url_unsafe(''), 'malformed URL', 'url_unsafe: empty string → "malformed URL"');
is_eq(smpro_ntf_url_unsafe('8.8.8.8'), 'malformed URL', 'url_unsafe: bare host (no scheme) → "malformed URL"');
is_eq(smpro_ntf_url_unsafe('ftp://8.8.8.8/'), 'scheme must be http(s)', 'url_unsafe: ftp scheme → "scheme must be http(s)"');

// --- loopback / link-local: caught by the NO_PRIV/NO_RES filter first (returns the private/reserved reason) ---
is_eq(smpro_ntf_url_unsafe('http://127.0.0.1:2087/'),
      'resolves to a private/reserved address (127.0.0.1)',
      'url_unsafe: loopback 127.0.0.1 → private/reserved reason');
is_eq(smpro_ntf_url_unsafe('http://169.254.169.254/latest/meta-data'),
      'resolves to a private/reserved address (169.254.169.254)',
      'url_unsafe: cloud-metadata 169.254.169.254 → private/reserved reason');

// --- private RFC1918 ranges ---
is_eq(smpro_ntf_url_unsafe('http://10.0.0.1/'),
      'resolves to a private/reserved address (10.0.0.1)',
      'url_unsafe: 10.0.0.1 → private/reserved reason');
is_eq(smpro_ntf_url_unsafe('https://192.168.1.50:9000/'),
      'resolves to a private/reserved address (192.168.1.50)',
      'url_unsafe: 192.168.1.50 → private/reserved reason');

// the reason is non-empty for every unsafe input (truthy contract used by callers)
ok(smpro_ntf_url_unsafe('http://10.0.0.1/') !== '', 'url_unsafe: a rejected URL yields a NON-empty (truthy) reason');

/* ============================================================ *
 *  U71 — smpro_ntf_wa_chat (recipient → chat id normalisation)
 * ============================================================ */

is_eq(smpro_ntf_wa_chat('+1 (555) 123-4567'), '15551234567@c.us', 'wa_chat: punctuation/spaces stripped → digits@c.us');
is_eq(smpro_ntf_wa_chat('15551234567'), '15551234567@c.us', 'wa_chat: bare digits → digits@c.us');
is_eq(smpro_ntf_wa_chat('15551234567@c.us'), '15551234567@c.us', 'wa_chat: already has @ → returned unchanged');
is_eq(smpro_ntf_wa_chat('120363000@g.us'), '120363000@g.us', 'wa_chat: a group jid (@g.us) is left as-is');
is_eq(smpro_ntf_wa_chat(''), '', 'wa_chat: empty input → ""');
is_eq(smpro_ntf_wa_chat('   '), '', 'wa_chat: whitespace-only input → "" (trimmed)');
is_eq(smpro_ntf_wa_chat('abc'), '', 'wa_chat: no digits and no @ → "" (digits empty)');

/* ============================================================ *
 *  U71 — smpro_ntf_wa_ready (sendable status set)
 *  ready set = ['ready','working','connected','authenticated'] (case-insensitive)
 * ============================================================ */

ok(smpro_ntf_wa_ready('ready'),         'wa_ready: "ready" is ready');
ok(smpro_ntf_wa_ready('working'),       'wa_ready: "working" is ready');
ok(smpro_ntf_wa_ready('connected'),     'wa_ready: "connected" is ready');
ok(smpro_ntf_wa_ready('authenticated'), 'wa_ready: "authenticated" is ready');
ok(smpro_ntf_wa_ready('READY'),         'wa_ready: case-insensitive ("READY")');
ok(smpro_ntf_wa_ready('Connected'),     'wa_ready: case-insensitive ("Connected")');
nok(smpro_ntf_wa_ready('disconnected'), 'wa_ready: "disconnected" is NOT ready');
nok(smpro_ntf_wa_ready('starting'),     'wa_ready: "starting" is NOT ready');
nok(smpro_ntf_wa_ready(''),             'wa_ready: empty status is NOT ready');

/* ============================================================ *
 *  U71 — smpro_ntf_send_telegram invalid-token guard (NO network)
 *  Order of guards: (1) token/chat_id empty → 'token/chat_id missing'
 *                   (2) token fails /^\d+:[\w-]+$/ → 'invalid bot token format'
 *  Both return BEFORE smpro_http() is called, so no network.
 * ============================================================ */

$r = smpro_ntf_send_telegram('not-a-valid-token', '123456', 'hi');
is_eq($r[0], false, 'send_telegram: invalid-format token → ok=false');
is_eq($r[1], 'invalid bot token format', 'send_telegram: invalid-format token → exact "invalid bot token format" reason');

$r2 = smpro_ntf_send_telegram('123456:no spaces allowed here', '123456', 'hi');  // colon present but space breaks [\w-]+
is_eq($r2[1], 'invalid bot token format', 'send_telegram: token with a space after colon → invalid format');

$r3 = smpro_ntf_send_telegram('', '123456', 'hi');
is_eq($r3[1], 'token/chat_id missing', 'send_telegram: empty token → "token/chat_id missing" (empty guard wins first)');

$r4 = smpro_ntf_send_telegram('123456:ABCdef', '', 'hi');
is_eq($r4[1], 'token/chat_id missing', 'send_telegram: empty chat_id → "token/chat_id missing"');

/* ============================================================ *
 *  U76 — smpro_ai_redact (strip secrets before sending to a 3rd-party model)
 * ============================================================ */

// api_key=… / token=… / password=… → "<name>=REDACTED" (note: regex uppercases nothing; keeps the matched key)
has(smpro_ai_redact('api_key=sk-supersecretvalue123'), 'api_key=REDACTED', 'redact: api_key=… → api_key=REDACTED');
hasnt(smpro_ai_redact('api_key=sk-supersecretvalue123'), 'sk-supersecretvalue123', 'redact: the api key VALUE is gone');
has(smpro_ai_redact('password: hunter2hunter2'), 'password=REDACTED', 'redact: "password: x" → password=REDACTED');
has(smpro_ai_redact('Authorization: Bearer abc.def.ghi'), 'Authorization=REDACTED', 'redact: Authorization header value redacted');
// the Bearer TOKEN itself must be gone, not just the word "Bearer" (the leak the lab found, now fixed)
hasnt(smpro_ai_redact('Authorization: Bearer abc.def.ghi'), 'abc.def.ghi', 'redact: the Bearer token VALUE is removed (not left exposed)');
$jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJyb290In0.s3cr3t-signature_value';
hasnt(smpro_ai_redact('ctx: ' . $jwt), 'eyJzdWIiOiJyb290In0', 'redact: a raw JWT anywhere is removed before reaching the AI');
hasnt(smpro_ai_redact('Authorization: Bearer ' . $jwt), $jwt, 'redact: Authorization: Bearer <jwt> fully redacts the JWT');

// cpsess token → cpsessXXXX
$cp = smpro_ai_redact('open /cpsess1234567890/frontend/jupiter/');
has($cp, 'cpsessXXXX', 'redact: cpsess<digits> → cpsessXXXX');
hasnt($cp, 'cpsess1234567890', 'redact: the original cpsess digits are gone');

// PEM private key block → [REDACTED PRIVATE KEY]
$pemTag = '-----' . 'BEGIN RSA ' . 'PRIVATE KEY' . '-----';   // split so repository scanners do not read it as a real key
$pem = "before\n" . $pemTag . "\nMIIBOwIBAAJB\nAKj...\n" . str_replace('BEGIN', 'END', $pemTag) . "\nafter";
$pemR = smpro_ai_redact($pem);
has($pemR, '[REDACTED PRIVATE KEY]', 'redact: PEM PRIVATE KEY block → [REDACTED PRIVATE KEY]');
hasnt($pemR, 'MIIBOwIBAAJB', 'redact: PEM body bytes are gone');

// ssh-rsa public key line → [REDACTED SSH KEY]
$ssh = 'ssh-rsa ' . str_repeat('A', 60) . ' user@host';
$sshR = smpro_ai_redact($ssh);
has($sshR, '[REDACTED SSH KEY]', 'redact: ssh-rsa <base64> → [REDACTED SSH KEY]');
hasnt($sshR, str_repeat('A', 60), 'redact: the ssh key blob is gone');

// /etc/shadow style $6$ hash → [REDACTED HASH]
$sh = 'root:$6$abcd1234$LongHashValueHereThatIsManyChars:19000:0:99999:7:::';
$shR = smpro_ai_redact($sh);
has($shR, '[REDACTED HASH]', 'redact: $6$… shadow hash → [REDACTED HASH]');

// benign text is untouched
is_eq(smpro_ai_redact('just a normal sentence about IP 8.8.8.8'),
      'just a normal sentence about IP 8.8.8.8',
      'redact: ordinary text passes through unchanged');

/* ============================================================ *
 *  U77 — smpro_ai_json (robust JSON extraction)
 * ============================================================ */

// clean JSON object
is_eq(smpro_ai_json('{"a":1,"b":"x"}'), ['a' => 1, 'b' => 'x'], 'ai_json: clean JSON object parses to the array');
// clean JSON array
is_eq(smpro_ai_json('[1,2,3]'), [1, 2, 3], 'ai_json: clean JSON array parses');

// ```json fenced block
is_eq(smpro_ai_json("```json\n{\"ok\":true}\n```"), ['ok' => true], 'ai_json: ```json fenced block is unwrapped + parsed');
// bare ``` fence (no language)
is_eq(smpro_ai_json("```\n{\"n\":5}\n```"), ['n' => 5], 'ai_json: bare ``` fence is unwrapped + parsed');

// prose-wrapped object (balanced-brace scan)
is_eq(smpro_ai_json('Sure! Here is the plan: {"action":"block","id":"ip0"} — done.'),
      ['action' => 'block', 'id' => 'ip0'],
      'ai_json: object embedded in prose is extracted');
// prose-wrapped array
is_eq(smpro_ai_json('result => [10,20] thanks'), [10, 20], 'ai_json: array embedded in prose is extracted');

// trailing comma (last-resort regex strips it)
is_eq(smpro_ai_json('{"a":1,"b":2,}'), ['a' => 1, 'b' => 2], 'ai_json: trailing comma before } is tolerated');

// braces inside a string must not fool the balanced scan
is_eq(smpro_ai_json('text {"msg":"a } b","k":2} tail'),
      ['msg' => 'a } b', 'k' => 2],
      'ai_json: a } inside a JSON string does not terminate the scan early');

// no JSON at all → null
is_eq(smpro_ai_json('no json here, just words'), null, 'ai_json: text with no JSON → null');
is_eq(smpro_ai_json(''), null, 'ai_json: empty string → null');
is_eq(smpro_ai_json('   '), null, 'ai_json: whitespace-only → null (trimmed to "")');
// a JSON scalar (not array/object) is rejected (json_decode→int, not array)
is_eq(smpro_ai_json('42'), null, 'ai_json: a bare scalar (42) → null (only arrays/objects accepted)');

/* ============================================================ *
 *  U79 — smpro_hub_action_perm (action → required permission)
 * ============================================================ */

is_eq(smpro_hub_action_perm('ping'),            'view',     'action_perm: ping → view');
is_eq(smpro_hub_action_perm('status'),          'view',     'action_perm: status → view');
is_eq(smpro_hub_action_perm('incidents'),       'view',     'action_perm: incidents → view');
is_eq(smpro_hub_action_perm('block_ip'),        'firewall', 'action_perm: block_ip → firewall');
is_eq(smpro_hub_action_perm('unblock_ip'),      'firewall', 'action_perm: unblock_ip → firewall');
is_eq(smpro_hub_action_perm('apply_profile'),   'profiles', 'action_perm: apply_profile → profiles');
is_eq(smpro_hub_action_perm('restart_service'), 'services', 'action_perm: restart_service → services');
is_eq(smpro_hub_action_perm('update'),          'updates',  'action_perm: update → updates');
// unknown / empty default to the least-privilege 'view'
is_eq(smpro_hub_action_perm('totally_unknown'), 'view', 'action_perm: unknown action defaults to view');
is_eq(smpro_hub_action_perm(''),                'view', 'action_perm: empty action defaults to view');

/* ============================================================ *
 *  U79 — smpro_hub_perms_all (permission catalog)
 * ============================================================ */

$perms = smpro_hub_perms_all();
ok(is_array($perms), 'perms_all: returns an array');
is_eq(array_keys($perms), ['view', 'firewall', 'profiles', 'services', 'updates', 'evidence'],
      'perms_all: exact key set (view, firewall, profiles, services, updates, evidence)');
ok(isset($perms['view']) && $perms['view'] !== '', 'perms_all: "view" has a non-empty description');
// every action_perm output must be a real catalog key (or "view") — invariant the exec layer relies on
foreach (['ping', 'block_ip', 'apply_profile', 'restart_service', 'update', 'unknown_x'] as $a) {
    ok(array_key_exists(smpro_hub_action_perm($a), $perms),
       "perms_all: action_perm('$a') maps to a real catalog permission");
}

/* ============================================================ *
 *  U73 — smpro_rep render escaping (XSS)
 *  HTML render escapes user-influenced fields (top_domains/top_ips via $esc);
 *  the TEXT render does NOT escape (plain text — no markup context).
 * ============================================================ */

$xss = '<b>x</b>"\'';
$rep = [
    'period_days'   => 7,
    'from'          => 1000000000,
    'to'            => 1000600000,
    'metrics'       => [],          // guarded: no load/ram/disk keys → those <li>s are skipped
    'security'      => [
        'total'       => 0,
        'ips'         => 0,
        'domains'     => 0,
        'top_domains' => [['domain' => $xss, 'c' => 3]],
        'top_ips'     => [['ip' => '203.0.113.9<script>', 'c' => 2]],
    ],
    'blocked_total' => 0,
];

$html = smpro_rep_render_html($rep);
// the raw XSS payload must NOT appear verbatim
hasnt($html, '<b>x</b>', 'rep_render_html: raw "<b>x</b>" attacker domain is NOT emitted verbatim');
hasnt($html, '<script>', 'rep_render_html: raw "<script>" in attacker IP is NOT emitted verbatim');
// the escaped form must appear (htmlspecialchars ENT_QUOTES)
has($html, '&lt;b&gt;x&lt;/b&gt;', 'rep_render_html: the attacker domain is HTML-escaped');
has($html, '&lt;script&gt;', 'rep_render_html: the attacker IP markup is HTML-escaped');
// ENT_QUOTES also escapes the double-quote in the domain field
has($html, '&quot;', 'rep_render_html: ENT_QUOTES escapes the double-quote too');
// the legitimate report chrome (a <b> the TEMPLATE itself wrote) is still present
has($html, '<li><b>', 'rep_render_html: template-authored <b> markup is preserved (only data is escaped)');

// TEXT render: plain text, no escaping — the value appears as-is (documents the no-markup contract)
$text = smpro_rep_render_text($rep);
has($text, '<b>x</b>', 'rep_render_text: plain-text render emits the value unescaped (no markup context)');

/* ============================================================ *
 *  Targets intentionally SKIPPED in Phase 1 (need stubs/fixtures)
 * ============================================================ */
tap_skip('smpro_hub_seal / smpro_hub_open — needs key fixture (Phase 2)',
         'smpro_hub_enckey() returns "" with no ECDH secret/ctx files, so seal returns "" — needs a planted key fixture to test GCM round-trip');
tap_skip('smpro_hub_enckey — needs key fixture (Phase 2)',
         'reads per-link secret + ctx files under SMPRO_VARLIB/hub/sec that do not exist in a fresh sandbox');
tap_skip('smpro_ai_decide / smpro_ai_decide_plan — needs csrf/exec + AI stub (Phase 3)',
         'smpro_ai_decide_pack shells out (imunify/exim/csf) and smpro_ai_chat hits the network');
tap_skip('smpro_ntf_send_whatsapp / smpro_ntf_wa_request — needs HTTP stub (Phase 3)',
         'calls smpro_http() to the gateway once the base URL passes the SSRF guard');
tap_skip('smpro_ntf_send_email / smpro_ntf_send_smtp — needs sendmail/socket stub (Phase 3)',
         'popen(sendmail) / fsockopen to an SMTP relay');
