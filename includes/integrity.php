<?php
/**
 * integrity.php - signed file-integrity manifest + Protected Mode (anti-tamper).
 *
 * Goal: make the easiest crack - editing a shipped file (e.g. forcing the licence gate to return true) -
 * SELF-EVIDENT. At build time every shipped file is hashed and the hash map is signed with the OFFLINE
 * private key (the same key used for update signing). The plugin verifies, with its embedded PUBLIC key:
 *   1) the manifest signature  -> a tamperer can't regenerate a valid manifest (no private key), and
 *   2) each file's SHA-256      -> a patched file no longer matches.
 * Either failure on a CRITICAL file puts the plugin into Protected Mode (locked, alerted). Drift on a
 * non-critical file only raises an alert. This cannot make PHP "uncrackable" (a determined root user can
 * patch the verifier itself) - it raises the bar and gives real tamper-evidence, integrating with the
 * existing licence kill-switch philosophy. It is FAIL-OPEN: a missing/blank manifest is skipped (older
 * builds / partial deploys are never bricked).
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

define('SMPRO_INTEG_MANIFEST', SMPRO_BASE . '/integrity.json');
define('SMPRO_INTEG_STATE',    SMPRO_VARLIB . '/integrity_state.json');
define('SMPRO_INTEG_TTL',      120);   // re-run the per-request critical check at most this often (seconds)

/** Files whose modification = a real attack on the gate. Mismatch here -> Protected Mode (lock). */
function smpro_integrity_critical_files() {
    return ['index.php', 'includes/defines.php', 'includes/license.php', 'includes/auth.php', 'includes/integrity.php'];
}

/** Load + signature-verify the manifest. Returns [ok,bool 'files'=>map] or ['skip'=>reason] when absent/blank. */
function smpro_integrity_load() {
    if (!is_file(SMPRO_INTEG_MANIFEST)) return ['skip' => 'no_manifest'];
    $j = json_decode((string)@file_get_contents(SMPRO_INTEG_MANIFEST), true);
    if (!is_array($j) || empty($j['files']) || empty($j['sig'])) return ['skip' => 'blank_manifest'];
    if (!function_exists('openssl_verify') || !defined('SMPRO_UPD_PUBKEY')) return ['skip' => 'no_openssl'];
    $files = $j['files']; ksort($files);                           // canonical order must match the builder
    $canon = json_encode($files, JSON_UNESCAPED_SLASHES);
    $pk = @openssl_pkey_get_public(SMPRO_UPD_PUBKEY);
    $sig = base64_decode((string)$j['sig'], true);
    if (!$pk || $sig === false || @openssl_verify($canon, $sig, $pk, OPENSSL_ALGO_SHA256) !== 1) {
        return ['ok' => false, 'reason' => 'manifest signature invalid', 'critical' => true];
    }
    return ['ok' => true, 'files' => $files];
}

/** Check a subset (or all) of the manifest's files against their on-disk SHA-256. */
function smpro_integrity_check(array $only = []) {
    $m = smpro_integrity_load();
    if (isset($m['skip'])) return ['ok' => true, 'skip' => $m['skip']];
    if (empty($m['ok']))   return $m;                              // manifest signature already failed (critical)
    $files = $m['files'];
    $list  = $only ?: array_keys($files);
    foreach ($list as $rel) {
        if (!isset($files[$rel])) continue;
        $p = SMPRO_BASE . '/' . $rel;
        if (!is_file($p) || !hash_equals($files[$rel], (string)@hash_file('sha256', $p))) {
            return ['ok' => false, 'reason' => 'modified file: ' . $rel, 'file' => $rel,
                    'critical' => in_array($rel, smpro_integrity_critical_files(), true)];
        }
    }
    return ['ok' => true, 'checked' => count($list)];
}

/** Enter Protected Mode: log + alert (deduped) + lock the request. Reversible by restoring clean files. */
function smpro_protected_mode($reason) {
    if (function_exists('smpro_audit')) smpro_audit('integrity_tamper', ['reason' => $reason]);
    // notify at most once per distinct reason (avoid per-request spam)
    $st = is_file(SMPRO_INTEG_STATE) ? (array)json_decode((string)@file_get_contents(SMPRO_INTEG_STATE), true) : [];
    if (function_exists('smpro_notify') && (($st['alerted'] ?? '') !== $reason)) {
        @smpro_notify('integrity_tamper', 'Plugin integrity check FAILED — Protected Mode',
            "A protected file was modified or the integrity manifest is invalid.\nDetail: " . $reason
            . "\n\nThe plugin is locked until the original files are restored (re-install / re-update).",
            ['severity' => 'critical'], true);
        $st['alerted'] = $reason; $st['at'] = time(); @smpro_integrity_state_save($st);
    }
    if (PHP_SAPI === 'cli') return;                               // cron/CLI: just log+alert, don't exit the worker
    http_response_code(403);
    header('Content-Type: text/html; charset=utf-8');
    echo '<!doctype html><meta charset="utf-8"><title>Protected Mode</title>'
       . '<div style="font:14px sans-serif;padding:40px;max-width:560px;margin:auto">'
       . '<h2 style="color:#b91c1c">&#128274; Protected Mode</h2>'
       . '<p>Safety Monitor Pro detected that one of its protected files was modified. For your safety the '
       . 'plugin is locked.</p><p>Restore the original files (re-install or re-run the update) to unlock.</p>'
       . '<p style="color:#888;font-size:12px">code SMPRO-INTEGRITY-403</p></div>';
    exit;
}

function smpro_integrity_state_save(array $s) {
    @is_dir(dirname(SMPRO_INTEG_STATE)) || @mkdir(dirname(SMPRO_INTEG_STATE), 0700, true);
    @file_put_contents(SMPRO_INTEG_STATE, json_encode($s, JSON_UNESCAPED_SLASHES), LOCK_EX); @chmod(SMPRO_INTEG_STATE, 0600);
}

/**
 * Per-request gate (called from index.php). Cheap: re-checks only the CRITICAL files, cached for TTL so the
 * 2s live-poll endpoint doesn't re-hash every call. A critical mismatch -> Protected Mode immediately.
 */
function smpro_integrity_gate() {
    $st = is_file(SMPRO_INTEG_STATE) ? (array)json_decode((string)@file_get_contents(SMPRO_INTEG_STATE), true) : [];
    if (!empty($st['locked'])) smpro_protected_mode((string)($st['reason'] ?? 'integrity'));   // stay locked until cleared
    if (isset($st['ok_at']) && (time() - (int)$st['ok_at']) < SMPRO_INTEG_TTL) return;          // recently verified -> skip
    $r = smpro_integrity_check(smpro_integrity_critical_files());
    if (!empty($r['ok']) || !empty($r['skip'])) {
        $st['ok_at'] = time(); unset($st['locked'], $st['reason']); @smpro_integrity_state_save($st);
        return;
    }
    // critical failure -> lock
    $st['locked'] = true; $st['reason'] = (string)($r['reason'] ?? 'integrity'); @smpro_integrity_state_save($st);
    smpro_protected_mode($st['reason']);
}

/**
 * Full sweep (called from cron). Verifies EVERY file. A critical mismatch locks; non-critical drift only
 * alerts (so benign edits to a non-gate file don't brick the UI, but you still hear about them).
 */
function smpro_integrity_full() {
    $r = smpro_integrity_check();
    if (!empty($r['ok']) || !empty($r['skip'])) {
        $st = is_file(SMPRO_INTEG_STATE) ? (array)json_decode((string)@file_get_contents(SMPRO_INTEG_STATE), true) : [];
        $st['ok_at'] = time(); unset($st['locked'], $st['reason']); @smpro_integrity_state_save($st);
        return $r;
    }
    if (!empty($r['critical'])) {
        $st = is_file(SMPRO_INTEG_STATE) ? (array)json_decode((string)@file_get_contents(SMPRO_INTEG_STATE), true) : [];
        $st['locked'] = true; $st['reason'] = (string)($r['reason'] ?? 'integrity'); @smpro_integrity_state_save($st);
        smpro_protected_mode($st['reason']);                       // CLI -> log+alert only
    } else {
        // non-critical drift: alert but keep running
        if (function_exists('smpro_notify')) @smpro_notify('integrity_tamper', 'Plugin file changed (non-critical)',
            'A non-gate plugin file no longer matches the signed manifest: ' . (string)($r['reason'] ?? '?'), ['severity' => 'high']);
    }
    return $r;
}
