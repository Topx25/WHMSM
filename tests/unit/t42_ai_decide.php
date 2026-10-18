<?php
/**
 * t42_ai_decide.php — closes the t36 U78 skip. smpro_ai_decide_kind / smpro_ai_decide_exec are PURE
 * (no network / no AI call) — t36 only skipped them because that file had the AI seam stubbed for S16,
 * which collides with requiring ai.php. In a fresh file we just require ai.php (+ csrf.php for the token)
 * and test the ctx->kind map + the action builder's kind/action gating. Expected values from ai.php.
 */
require __DIR__ . '/../support/bootstrap.php';
require SMPRO_BASE . '/includes/auth.php';   // smpro_current_actor() — csrf.php depends on it
require SMPRO_BASE . '/includes/csrf.php';   // so decide_exec emits a real smpro_csrf token
require SMPRO_BASE . '/includes/ai.php';

ok(function_exists('smpro_ai_decide_kind') && function_exists('smpro_ai_decide_exec'), 'ai.php loaded: decide_kind + decide_exec');

/* ---------- U78a — ctx -> kind map ---------- */
is_eq(smpro_ai_decide_kind('forensics-audit'),    'malware',   'decide_kind: forensics-audit -> malware');
is_eq(smpro_ai_decide_kind('imunify360'),         'malware',   'decide_kind: imunify360 -> malware');
is_eq(smpro_ai_decide_kind('login-monitor'),      'login',     'decide_kind: login-monitor -> login');
is_eq(smpro_ai_decide_kind('firewall-status'),    'login',     'decide_kind: firewall-status -> login');
is_eq(smpro_ai_decide_kind('account-audit'),      'login',     'decide_kind: account-audit -> login');
is_eq(smpro_ai_decide_kind('spam-phishing'),      'spam',      'decide_kind: spam-phishing -> spam');
is_eq(smpro_ai_decide_kind('phishing'),           'spam',      'decide_kind: phishing -> spam');
is_eq(smpro_ai_decide_kind('intrusion-monitor'),  'intrusion', 'decide_kind: intrusion-monitor -> intrusion');
is_eq(smpro_ai_decide_kind('nope'),               '',          'decide_kind: unknown ctx -> "" (no AI action)');
is_eq(smpro_ai_decide_kind(''),                   '',          'decide_kind: empty ctx -> ""');

/* ---------- U78b — decide_exec: action requires the matching kind + required field, else null ---------- */
$del = smpro_ai_decide_exec(['kind' => 'malware', 'file' => '/home/bob/x.php'], 'delete');
is_eq($del['fields']['im_action'] ?? null, 'delete_file', 'decide_exec delete(malware,file): builds im_action=delete_file');
is_eq($del['fields']['file'] ?? null, '/home/bob/x.php', 'decide_exec delete: carries the file');
is_eq($del['cls'] ?? null, 'danger', 'decide_exec delete: danger class');
ok(!empty($del['fields']['smpro_csrf']), 'decide_exec delete: emits a CSRF token (action can never be forged)');
has((string)($del['confirm'] ?? ''), '/home/bob/x.php', 'decide_exec delete: confirm names the file');

is_eq(smpro_ai_decide_exec(['kind' => 'login', 'file' => '/x'], 'delete'), null, 'decide_exec delete: wrong kind (login) -> null (AI cannot delete a non-malware item)');
is_eq(smpro_ai_decide_exec(['kind' => 'malware'], 'delete'), null, 'decide_exec delete: no file -> null');

$blk = smpro_ai_decide_exec(['kind' => 'ip', 'ip' => '203.0.113.7'], 'block');
is_eq($blk['fields']['la_action'] ?? null, 'block', 'decide_exec block(ip): la_action=block');
is_eq($blk['fields']['ips'] ?? null, '203.0.113.7', 'decide_exec block: carries the ip');
is_eq(smpro_ai_decide_exec(['kind' => 'malware', 'ip' => '203.0.113.7'], 'block'), null, 'decide_exec block: wrong kind -> null');
is_eq(smpro_ai_decide_exec(['kind' => 'ip'], 'block'), null, 'decide_exec block: no ip -> null');

is_eq(smpro_ai_decide_exec(['kind' => 'ip', 'ip' => '203.0.113.7'], 'allow')['fields']['la_action'] ?? null, 'allow', 'decide_exec allow(ip): la_action=allow');

$sus = smpro_ai_decide_exec(['account' => 'bob'], 'suspend');
is_eq($sus['fields']['fa_action'] ?? null, 'suspend', 'decide_exec suspend(account): fa_action=suspend');
is_eq($sus['fields']['account'] ?? null, 'bob', 'decide_exec suspend: carries the account');
is_eq(smpro_ai_decide_exec([], 'suspend'), null, 'decide_exec suspend: no account -> null');

$inv = smpro_ai_decide_exec(['ip' => '203.0.113.7'], 'investigate');
ok(!empty($inv['nav']), 'decide_exec investigate: returns a nav target');

is_eq(smpro_ai_decide_exec(['kind' => 'malware', 'file' => '/x'], 'frobnicate'), null, 'decide_exec: unknown action -> null (AI can only pick from the allowed verbs)');
