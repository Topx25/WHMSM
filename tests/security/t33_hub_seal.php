<?php
/**
 * t33_hub_seal.php — Phase-3: the Hub end-to-end sealed channel (hub.php).
 *
 * The Hub relays commands through the (UNTRUSTED) license server. The ONLY thing keeping a
 * compromised relay from forging/replaying control commands is the per-link AES-256-GCM seal
 * keyed by an ECDH secret the relay never sees. These tests prove the seal's security contract:
 *
 *   U81  smpro_hub_enckey      — 32 raw key bytes WHEN a secret exists; '' when no secret (never a usable key)
 *   U80  smpro_hub_seal/open   — roundtrip == payload; tamper -> null; replay(nonce) -> null; stale(t) -> null;
 *                                NO key -> seal returns '' (NEVER plaintext); keyed link rejects RAW (downgrade)
 *   U79/S25 action_perm/perms_all/needs_verify — the permission map + step-up verify gate
 *   S27  smpro_hub_proxy       — STRICT param allowlist refuses any unknown/state-changing key (no shell ever runs)
 *
 * Mechanism: hub.php's seams (smpro_audit/smpro_notify/smpro_hub_api/smpro_menu_resolve) are all
 * function_exists()-guarded, so we require the RAW source and simply DON'T define them — the guards
 * skip cleanly (no warnings). We seed the sandbox secret file to mint a real enckey, then exercise the
 * crypto. The csf/etc PATH shims would record any exec the proxy attempts — we prove it NEVER execs.
 */
require __DIR__ . '/../support/bootstrap.php';

require SMPRO_BASE . '/includes/hub.php';   // raw source; hub seams are function_exists-guarded (audit/api/menu absent here)

ok(function_exists('smpro_hub_enckey'), 'hub.php loaded (enckey/seal/open present)');

$LID = 7;

/* ---------- U81 — enckey: NO secret -> '' (no usable key ever) ---------- */
is_eq(smpro_hub_secret($LID), '', 'U81 no secret file yet -> smpro_hub_secret == ""');
is_eq(smpro_hub_enckey($LID), '', 'U81 enckey with NO secret -> "" (cannot mint a key)');

/* seed the sandbox secret so a real 32-byte key can be derived (mirrors smpro_hub_set_secret) */
$secdir = smpro_hub_sec_dir();
is_eq(strpos($secdir, SMPRO_VARLIB), 0, 'U81 sec_dir lives under the sandbox VARLIB (no /var/lib write)');
file_put_contents($secdir . '/' . $LID . '.key', str_repeat('S', 64));   // any non-empty ECDH-secret stand-in
file_put_contents($secdir . '/' . $LID . '.ctx', json_encode(['code' => 'ABC', 'mkey' => 'K', 'mhost' => 'm.example', 'mip' => '192.0.2.20']));

$key = smpro_hub_enckey($LID);
is_eq(strlen($key), 32, 'U81 enckey WITH secret -> exactly 32 raw bytes (aes-256 keylen)');
isnt_eq($key, str_repeat('S', 64), 'U81 enckey is a HASH of the material, not the raw secret');
// determinism: same inputs -> same key (so both endpoints derive identically)
is_eq(smpro_hub_enckey($LID), $key, 'U81 enckey is deterministic for identical secret+ctx');
// ctx is folded in: changing ctx changes the key
file_put_contents($secdir . '/' . $LID . '.ctx', json_encode(['code' => 'ABC', 'mkey' => 'K', 'mhost' => 'm.example', 'mip' => '203.0.113.99']));
isnt_eq(smpro_hub_enckey($LID), $key, 'U81 enckey is bound to ctx (mip change -> different key)');
file_put_contents($secdir . '/' . $LID . '.ctx', json_encode(['code' => 'ABC', 'mkey' => 'K', 'mhost' => 'm.example', 'mip' => '192.0.2.20'])); // restore
is_eq(smpro_hub_enckey($LID), $key, 'U81 enckey restored after ctx restore (key is a pure function of inputs)');

/* ---------- U80 — seal: NO key -> '' (NEVER plaintext through the relay) ---------- */
$NOKEY = 99;
is_eq(smpro_hub_enckey($NOKEY), '', 'U80 link with no secret -> enckey ""');
$sealNoKey = smpro_hub_seal($NOKEY, ['action' => 'block_ip', 'pw' => 'topsecret']);
is_eq($sealNoKey, '', 'U80 seal on keyless link -> "" (drops msg; control password never leaks to relay)');
hasnt($sealNoKey, 'topsecret', 'U80 keyless seal output never contains the plaintext payload');
hasnt($sealNoKey, 'block_ip', 'U80 keyless seal output never contains the plaintext action');

/* ---------- U80 — seal/open roundtrip == payload ---------- */
$payload = ['action' => 'status', 'req' => 'r1', 'n' => 5, 'ok' => true, 'unicode' => 'café', 'slash' => 'a/b'];
$sealed = smpro_hub_seal($LID, $payload);
isnt_eq($sealed, '', 'U80 seal on keyed link -> non-empty envelope');
$env = json_decode($sealed, true);
ok(is_array($env) && isset($env['c'], $env['n'], $env['t']), 'U80 envelope is JSON with c/n/t (ciphertext+nonce+ts)');
// the envelope must be opaque: no field of the plaintext appears in the wire bytes
hasnt($sealed, 'café', 'U80 sealed wire bytes contain no plaintext (unicode value hidden)');
hasnt($sealed, '"action"', 'U80 sealed wire bytes contain no plaintext keys');

$opened = smpro_hub_open($LID, $sealed);
is_eq($opened, $payload, 'U80 open(seal(payload)) === payload (full roundtrip, deep-equal)');

/* ---------- U80 — tamper -> null (GCM auth fails) ---------- */
$bad = $env;
$raw = base64_decode($env['c'], true);
$raw[strlen($raw) - 1] = ($raw[strlen($raw) - 1] === 'A') ? 'B' : 'A';   // flip last ciphertext byte
$bad['c'] = base64_encode($raw);
is_eq(smpro_hub_open($LID, json_encode($bad)), null, 'U80 tampered ciphertext -> null (GCM tag rejects)');

$badAad = $env; $badAad['n'] = bin2hex(random_bytes(8));   // nonce is part of the GCM AAD -> decrypt fails
is_eq(smpro_hub_open($LID, json_encode($badAad)), null, 'U80 swapped nonce (AAD mismatch) -> null');

$wrongKey = smpro_hub_open($LID + 1, $sealed);             // different lid -> different key + AAD -> fail
is_eq($wrongKey, null, 'U80 open with the WRONG link key -> null');

is_eq(smpro_hub_open($LID, 'not json'), null, 'U80 non-JSON envelope -> null');
is_eq(smpro_hub_open($LID, json_encode(['c' => 'zzz', 'n' => 'x', 't' => time()])), null, 'U80 short/garbage ciphertext -> null');

/* ---------- U80 — replay (same nonce twice) -> null ---------- */
$fresh = smpro_hub_seal($LID, ['action' => 'ping', 'req' => 'rep']);
$first = smpro_hub_open($LID, $fresh);
ok(is_array($first), 'U80 first delivery of a nonce opens OK');
is_eq(smpro_hub_open($LID, $fresh), null, 'U80 SECOND delivery of the same nonce -> null (anti-replay)');

/* ---------- U80 — stale t (> 300s) -> null ---------- */
/* Build a validly-encrypted envelope with an OLD timestamp (AAD includes t, so we must encrypt with it). */
$oldT = time() - 1000;
$oldN = bin2hex(random_bytes(8));
$iv = random_bytes(12); $tag = '';
$body = json_encode(['action' => 'ping', 'req' => 'stale'], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
$ct = openssl_encrypt($body, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, $LID . '|' . $oldN . '|' . $oldT);
$staleEnv = json_encode(['c' => base64_encode($iv . $tag . $ct), 'n' => $oldN, 't' => $oldT], JSON_UNESCAPED_SLASHES);
is_eq(smpro_hub_open($LID, $staleEnv), null, 'U80 stale timestamp (>300s old, but auth-valid) -> null');

/* ---------- U80 — keyed link rejects a RAW (legacy/unsealed) payload (downgrade attack) ---------- */
$rawLegacy = json_encode(['action' => 'block_ip', 'args' => ['ip' => '198.51.100.7']]);   // no c/n/t -> "raw" branch
is_eq(smpro_hub_open($LID, $rawLegacy), null, 'U80 keyed link rejects a RAW unsealed payload (downgrade -> null)');
/* but a KEYLESS link DOES accept raw (handshake window) — proves the branch is key-gated, not always-deny */
is_eq(smpro_hub_open($NOKEY, $rawLegacy), ['action' => 'block_ip', 'args' => ['ip' => '198.51.100.7']],
    'U80 keyless link accepts raw payload (key-gated downgrade rule, not blanket)');

/* ---------- U79 — perms_all catalog ---------- */
$all = smpro_hub_perms_all();
// Locked on purpose: a new permission is a new thing a hub may do to a member, so it must be a deliberate
// change with a test edit beside it, never something that arrives with a refactor. 'evidence' is the odd
// one out and the reason it is listed last: it is the only permission where the MEMBER sends, rather than
// the hub acting on it.
is_eq(array_keys($all), ['view', 'firewall', 'profiles', 'services', 'updates', 'evidence'], 'U79 perms_all has exactly the 6 known permissions');
ok(isset($all['firewall']) && is_string($all['firewall']), 'U79 each permission has a human label');

/* ---------- U79/S25 — action_perm map (which grant each inbound action needs) ---------- */
is_eq(smpro_hub_action_perm('ping'),            'view',     'S25 ping -> view');
is_eq(smpro_hub_action_perm('status'),          'view',     'S25 status -> view');
is_eq(smpro_hub_action_perm('incidents'),       'view',     'S25 incidents -> view');
is_eq(smpro_hub_action_perm('block_ip'),        'firewall', 'S25 block_ip -> firewall');
is_eq(smpro_hub_action_perm('unblock_ip'),      'firewall', 'S25 unblock_ip -> firewall');
is_eq(smpro_hub_action_perm('apply_profile'),   'profiles', 'S25 apply_profile -> profiles');
is_eq(smpro_hub_action_perm('restart_service'), 'services', 'S25 restart_service -> services');
is_eq(smpro_hub_action_perm('update'),          'updates',  'S25 update -> updates');
// SECURITY: an UNKNOWN action must fall back to the LEAST privilege ('view'), never to a powerful grant
is_eq(smpro_hub_action_perm('rm_rf_everything'), 'view',    'S25 unknown action -> "view" (least-privilege default, no escalation)');
is_eq(smpro_hub_action_perm(''),                 'view',    'S25 empty action -> view (least privilege)');
// every action_perm value must be a REAL permission key (no typo grants a bypass)
foreach (['ping','block_ip','apply_profile','restart_service','update'] as $a)
    ok(array_key_exists(smpro_hub_action_perm($a), $all), "S25 action_perm('$a') maps to a real perms_all key");

/* ---------- S25 — needs_verify step-up gate ---------- */
$VL = 11;
$vfile = smpro_hub_vstate_file($VL);
@mkdir(dirname($vfile), 0700, true);
// never verified -> 'first'
@unlink($vfile);
is_eq(smpro_hub_needs_verify($VL, 'status'), 'first', 'S25 needs_verify: never verified -> "first"');
// freshly verified (now) + harmless action -> '' (no re-verify needed)
file_put_contents($vfile, json_encode(['ts' => time(), 'mip' => '192.0.2.20']));
is_eq(smpro_hub_needs_verify($VL, 'status'), '', 'S25 needs_verify: fresh verify + read action -> "" (allowed)');
// a SENSITIVE action always re-verifies even when fresh
is_eq(smpro_hub_needs_verify($VL, 'update'), 'sensitive_action', 'S25 needs_verify: update (sensitive) -> step-up even when fresh');
is_eq(smpro_hub_needs_verify($VL, 'restart_service'), 'sensitive_action', 'S25 needs_verify: restart_service -> sensitive_action');
is_eq(smpro_hub_needs_verify($VL, 'apply_profile'), 'sensitive_action', 'S25 needs_verify: apply_profile -> sensitive_action');
// idle > 30min (but < 24h) on a NON-sensitive action -> 'idle'
file_put_contents($vfile, json_encode(['ts' => time() - 2000, 'mip' => '192.0.2.20']));
is_eq(smpro_hub_needs_verify($VL, 'status'), 'idle', 'S25 needs_verify: >30min idle -> "idle"');
// stale > 24h -> 'periodic' (checked before idle/sensitive)
file_put_contents($vfile, json_encode(['ts' => time() - 90000, 'mip' => '192.0.2.20']));
is_eq(smpro_hub_needs_verify($VL, 'status'), 'periodic', 'S25 needs_verify: >24h -> "periodic"');
// member IP changed (snap) on a fresh verify -> 'member_ip_changed'
file_put_contents($vfile, json_encode(['ts' => time(), 'mip' => '192.0.2.20']));
is_eq(smpro_hub_needs_verify($VL, 'status', ['_mip' => '203.0.113.5']), 'member_ip_changed',
    'S25 needs_verify: member IP changed -> "member_ip_changed"');
is_eq(smpro_hub_needs_verify($VL, 'status', ['_mip' => '192.0.2.20']), '',
    'S25 needs_verify: same member IP -> "" (no spurious step-up)');
@unlink($vfile);

/* ---------- S27 — proxy STRICT allowlist: unknown/state-changing key -> "" and NO shell exec ---------- */
smpro_test_rec_reset('csf'); smpro_test_rec_reset('curl'); smpro_test_rec_reset('systemctl');
// an unknown key (e.g. a future state-changing GET trigger) blocks the WHOLE request
is_eq(smpro_hub_proxy('page=dashboard&do_uninstall=1'), '', 'S27 proxy: unknown key (do_uninstall) -> "" (whole request refused)');
is_eq(smpro_hub_proxy('action=block&ip=1.2.3.4'),       '', 'S27 proxy: "action" not on allowlist -> ""');
is_eq(smpro_hub_proxy('page=dashboard&cmd=rm'),         '', 'S27 proxy: "cmd" not on allowlist -> ""');
// no page and not a metric poll -> ""
is_eq(smpro_hub_proxy('format=html'),                   '', 'S27 proxy: no page + not a json metric -> ""');
// a single state-changing key with NO page still refuses on the allowlist before any page/shell logic
is_eq(smpro_hub_proxy('restart=service&page=dashboard'), '', 'S27 proxy: "restart" not on allowlist -> "" (refused pre-shell)');
is_eq(smpro_hub_proxy('page=dashboard&token=evil'),      '', 'S27 proxy: "token" not on allowlist -> ""');
// CRITICAL: none of the refused requests ever reached a real command shim
ok(smpro_test_rec_empty('csf') && smpro_test_rec_empty('curl') && smpro_test_rec_empty('systemctl'),
    'S27 proxy refusals NEVER invoked csf/curl/systemctl (recorders empty — no shell side effect)');
