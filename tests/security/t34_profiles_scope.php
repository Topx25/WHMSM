<?php
/**
 * t34_profiles_scope.php — Phase-3 WRITE-SCOPE proof for the Protection Profiles engine.
 *
 *   I11  smpro_prof_apply write-scope — the patch a profile applies is a SUBSET of
 *        keys_intrusion ∪ keys_notify_thr. Applying a built-in profile must NEVER touch
 *        Cloudflare/AbuseIPDB secrets, the IP allowlist, breach-exclude paths, or any
 *        other live-config key outside that set.
 *
 * Mechanism: smpro_prof_apply does NOT return its patch — it WRITES via smpro_in_cfg_save()
 * (intrusion.json) and smpro_ntf_save() (notifications/config.json). So we use the REAL
 * intrusion + notify config layer (writing into the sandbox SMPRO_VARLIB), pre-seed sentinel
 * secret / allowlist / breach values, apply a built-in profile, then READ THE CFG FILES BACK
 * and assert the scope: every key that changed is inside the allowed set, and every
 * out-of-scope sentinel is byte-for-byte intact.
 *
 * Determinism: secret.php is NOT required, so smpro_secret_enc/dec are absent and the config
 * layer reads/writes plaintext (function_exists guards). The four env helpers used by
 * smpro_prof_env() are stubbed BEFORE any include so adaptation is deterministic and no real
 * binary/AI is probed. No csf/kill/mail/network can fire (no such call path here; PATH shims
 * back-stop anyway).
 */
require __DIR__ . '/../support/bootstrap.php';

/* ---- deterministic env stubs (smpro_prof_env reads these via function_exists) ---- */
if (!function_exists('smpro_audit'))       { function smpro_audit($a, array $d = []) { $GLOBALS['__rec_audit'][] = [$a, $d]; } }
if (!function_exists('smpro_cpu_cores'))    { function smpro_cpu_cores() { return 4; } }
if (!function_exists('smpro_memory'))       { function smpro_memory() { return ['total_mb' => 8192]; } }
if (!function_exists('smpro_has_bin'))      { function smpro_has_bin($n) { return false; } }   // no imunify
if (!function_exists('smpro_ai_available')) { function smpro_ai_available(): bool { return false; } }  // no AI provider

require SMPRO_BASE . '/includes/intrusion.php';   // real smpro_in_cfg / _save / _write (sandbox file)
require SMPRO_BASE . '/includes/notify.php';      // real smpro_ntf_load / _save (sandbox file)
require SMPRO_BASE . '/includes/profiles.php';    // function-under-test: smpro_prof_apply

ok(function_exists('smpro_prof_apply'), 'profiles engine loaded; env stubbed, real cfg layer in sandbox');

$KEYS_INTR = smpro_prof_keys_intrusion();
$KEYS_THR  = smpro_prof_keys_notify_thr();

/* keys a profile is allowed to write into the INTRUSION config, and the out-of-scope keys
   that MUST survive untouched (secrets + allowlist + breach paths + unrelated tunables). */
$FORBIDDEN_CFG = ['cf_token','cf_account','abuseipdb_key','allowlist','breach_exclude',
                  'auto_block_threshold','protect_arab','protect_regions','login_guard',
                  'login_guard_threshold','protect_arab_threshold'];

/* ---- sentinel seed: write intrusion.json + notifications/config.json BEFORE any prof call
        (smpro_in_cfg() caches statically on first read, so seed must land on disk first). ---- */
@mkdir(SMPRO_VARLIB, 0700, true);
$seedCfg = [
    'cf_token'             => 'SENTINEL-CF-TOKEN',
    'cf_account'           => 'SENTINEL-CF-ACCT',
    'abuseipdb_key'        => 'SENTINEL-ABUSE-KEY',
    'allowlist'            => ['203.0.113.7', '198.51.100.0/24'],
    'breach_exclude'       => ['/custom/path/', 'sentinel-marker'],
    'auto_block_threshold' => 99,
    'protect_arab'         => false,
    'protect_regions'      => ['EG', 'SA', 'AE'],
    'login_guard'          => false,
    'login_guard_threshold'=> 7,
    'protect_arab_threshold' => 3,
];
file_put_contents(SMPRO_IN_CFG, json_encode($seedCfg, JSON_UNESCAPED_SLASHES));

@mkdir(SMPRO_NTF_DIR, 0700, true);
$seedNtf = smpro_ntf_default_config();
$seedNtf['telegram']['enabled'] = true;
$seedNtf['telegram']['token']   = 'SENTINEL-TG-TOKEN';
$seedNtf['telegram']['chat_id'] = 'SENTINEL-CHAT';
$seedNtf['whatsapp']['api_key'] = 'SENTINEL-WA-KEY';
$seedNtf['email']['smtp']['pass'] = 'SENTINEL-SMTP-PASS';
$seedNtf['types']['intrusion_attack']['on'] = false;   // profile must FLIP this back on
file_put_contents(SMPRO_NTF_CONF, json_encode($seedNtf, JSON_UNESCAPED_SLASHES));

/* snapshot of the seed exactly as it will be on disk (cfg layer reads file each call after
   cache busts; we read fresh by decoding the file directly to avoid the static cache). */
$readCfg = function () { $d = json_decode((string)@file_get_contents(SMPRO_IN_CFG), true); return is_array($d) ? $d : []; };
$readNtf = function () { $d = json_decode((string)@file_get_contents(SMPRO_NTF_CONF), true); return is_array($d) ? $d : []; };

/* Materialize the cfg layer's own DEFAULT backfill once (empty patch) so the baseline already
   contains every default key. Otherwise the first real save would "change" keys that the cfg
   layer back-fills from defaults (emergency_batch, login_guard_window, ...) — those are NOT the
   profile's patch and would pollute the scope diff. After this, any diff is purely the patch. */
smpro_in_cfg_save([]);

$cfgBefore = $readCfg();
$ntfBefore = $readNtf();

/* sanity: the seed is on disk as written (full-fidelity, no encryption mangling) */
is_eq($cfgBefore['cf_token'], 'SENTINEL-CF-TOKEN', 'seed: cf_token persisted plaintext (no secret.php loaded)');
is_eq($cfgBefore['allowlist'], ['203.0.113.7', '198.51.100.0/24'], 'seed: allowlist persisted (TEST-NET IPs)');

/* =================== I11 — apply "maximum" and assert WRITE SCOPE =================== */
$res = smpro_prof_apply('maximum');
is_eq($res['ok'], true, 'I11 apply(maximum) -> ok (patch written to cfg + ntf)');
is_eq($res['active'], 'maximum', 'I11 apply(maximum) -> active=maximum');

$cfgAfter = $readCfg();
$ntfAfter = $readNtf();

/* (a) every INTRUSION-config key that CHANGED must be inside keys_intrusion */
$changed = [];
foreach ($cfgAfter as $k => $v) {
    $was = $cfgBefore[$k] ?? '__ABSENT__';
    if ($was !== $v) $changed[] = $k;
}
foreach ($cfgBefore as $k => $v) {                         // (also catch any key that disappeared)
    if (!array_key_exists($k, $cfgAfter)) $changed[] = $k;
}
$changed = array_values(array_unique($changed));
$outOfScope = array_values(array_diff($changed, $KEYS_INTR));
is_eq($outOfScope, [], 'I11 every changed intrusion-cfg key is within keys_intrusion (no scope escape): ' . implode(',', $changed));

/* (b) the explicit forbidden keys are byte-for-byte intact */
foreach ($FORBIDDEN_CFG as $fk) {
    is_eq($cfgAfter[$fk] ?? '__MISSING__', $cfgBefore[$fk] ?? '__MISSING__', "I11 forbidden cfg key untouched: $fk");
}

/* (c) the profile DID write the in-scope intrusion keys it controls (proves apply actually ran) */
$bMax = smpro_prof_builtin()['maximum']['intrusion'];
is_eq($cfgAfter['auto_block_dryrun'], false, 'I11 maximum wrote auto_block_dryrun=false (enforced, in scope)');
is_eq($cfgAfter['emergency'], true,          'I11 maximum wrote emergency=true (in scope)');
is_eq($cfgAfter['alert_window_min'], 10,     'I11 maximum wrote alert_window_min=10 (in scope)');
/* use_cloudflare stays true: the seed carries cf_token+cf_account, so smpro_cf_configured() is
   true and adapt does NOT force it off. (Still an in-scope key either way.) */
is_eq($cfgAfter['use_cloudflare'], true,     'I11 maximum use_cloudflare stays true (cf IS configured via seed) — in scope');
/* ai_block adapted to false because smpro_ai_available() stub returns false */
is_eq($cfgAfter['ai_block'], false,          'I11 maximum ai_block adapted to false (no AI provider) — still in scope');

/* (d) NOTIFY config: only keys under thresholds[] (within keys_notify_thr) may change in the
       thresholds map; secrets + channels stay intact; security alert types get flipped on. */
$thrChanged = [];
foreach ($ntfAfter['thresholds'] as $k => $v) {
    if (($ntfBefore['thresholds'][$k] ?? '__A__') !== $v) $thrChanged[] = $k;
}
$thrOutOfScope = array_values(array_diff($thrChanged, $KEYS_THR));
is_eq($thrOutOfScope, [], 'I11 every changed notify threshold is within keys_notify_thr: ' . implode(',', $thrChanged));

/* secrets / channel config in notify untouched */
is_eq($ntfAfter['telegram']['token'],     'SENTINEL-TG-TOKEN',  'I11 notify telegram token untouched');
is_eq($ntfAfter['telegram']['chat_id'],   'SENTINEL-CHAT',      'I11 notify telegram chat_id untouched');
is_eq($ntfAfter['whatsapp']['api_key'],   'SENTINEL-WA-KEY',    'I11 notify whatsapp api_key untouched');
is_eq($ntfAfter['email']['smtp']['pass'], 'SENTINEL-SMTP-PASS', 'I11 notify smtp pass untouched');
is_eq($ntfAfter['telegram']['enabled'],   true,                 'I11 notify telegram enabled flag untouched');

/* extra-threshold keys NOT in keys_notify_thr stay put (mail_out_hour, inbound_spam_min, ...) */
is_eq($ntfAfter['thresholds']['mail_out_hour'],   $ntfBefore['thresholds']['mail_out_hour'],   'I11 out-of-scope threshold mail_out_hour untouched');
is_eq($ntfAfter['thresholds']['inbound_spam_min'],$ntfBefore['thresholds']['inbound_spam_min'],'I11 out-of-scope threshold inbound_spam_min untouched');

/* the profile DID write the in-scope thresholds + flipped security alert types on */
is_eq($ntfAfter['thresholds']['disk_pct'], 85, 'I11 maximum wrote disk_pct=85 (in scope)');
is_eq($ntfAfter['types']['intrusion_attack']['on'], true, 'I11 maximum forced intrusion_attack alert type ON');

/* =================== second apply ("medium") — same scope guarantee ===================
   smpro_in_cfg() caches statically, so the file on disk is the live state; we baseline off it
   directly (no re-seed — a direct file rewrite would be ignored by the static cache). */
$cfg2Before = $readCfg();
$res2 = smpro_prof_apply('medium');
is_eq($res2['ok'], true, 'I11 apply(medium) -> ok');
$cfg2After = $readCfg();

$changed2 = [];
foreach ($cfg2After as $k => $v) if (($cfg2Before[$k] ?? '__A__') !== $v) $changed2[] = $k;
foreach ($cfg2Before as $k => $v) if (!array_key_exists($k, $cfg2After)) $changed2[] = $k;
$changed2 = array_values(array_unique($changed2));
is_eq(array_values(array_diff($changed2, $KEYS_INTR)), [], 'I11 medium: every changed intrusion-cfg key within keys_intrusion: ' . implode(',', $changed2));
is_eq($cfg2After['cf_token'],  'SENTINEL-CF-TOKEN', 'I11 medium: cf_token still untouched');
is_eq($cfg2After['allowlist'], ['203.0.113.7', '198.51.100.0/24'], 'I11 medium: allowlist still untouched');
is_eq($cfg2After['auto_block_dryrun'], true, 'I11 medium wrote auto_block_dryrun=true (safe dry-run, in scope)');

/* =================== unknown / empty profile is a no-op (refused, no writes) =================== */
$cfg3Before = $readCfg();
$bad = smpro_prof_apply('does-not-exist');
is_eq($bad['ok'], false, 'I11 apply(unknown) -> refused');
has($bad['msg'], 'Unknown or empty', 'I11 apply(unknown) -> reason names unknown/empty');
is_eq($readCfg(), $cfg3Before, 'I11 apply(unknown) wrote NOTHING to intrusion cfg (no-op on refusal)');

/* =================== pure scope contract on the key sets themselves =================== */
$overlap = array_intersect($KEYS_INTR, $KEYS_THR);
is_eq($overlap, [], 'keys_intrusion and keys_notify_thr are disjoint (no ambiguous key)');
foreach (['cf_token','cf_account','abuseipdb_key','allowlist','breach_exclude'] as $secret) {
    nok(in_array($secret, $KEYS_INTR, true), "secret/allowlist key NOT declared writable by a profile: $secret");
}

/* NOTE (Phase 4, skipped here): smpro_prof_ai_generate() writes a profile from a live AI
   round-trip (smpro_ai_chat) — verifying its sanitiser needs an AI spy not in the seam set. */
tap_skip('I11 smpro_prof_ai_generate sanitiser scope', 'needs smpro_ai_chat spy (not in seam-stub set) — deferred to Phase 4');
