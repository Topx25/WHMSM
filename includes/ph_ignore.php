<?php
/**
 * Safety Monitor Pro - accounts that must be left unprotected.
 *
 * Some accounts cannot take file hardening. A site with a self-updating installer, a deploy pipeline that writes
 * its own wp-config, a customer who edits core files by hand - for these, locking files is not protection, it is
 * an outage. Force-unprotect exists for that case, and this is the list that makes the decision stick: without it
 * the next automatic pass simply locks the account again and the operator is back where they started, wondering
 * why the protection they removed keeps coming back.
 *
 * It lives in includes/ rather than beside the rest of PHP Harden because the code that must OBEY it does not run
 * on the page. Emergency response runs from the intrusion tick, which is a cron worker, and page modules are not
 * loaded there - a list only the page can read would be a list that automation silently ignores.
 *
 * An entry is deliberately never anonymous: it records who added it, when, and why, and nothing prunes it on a
 * timer. An account that stops being protected should stay visible as a decision someone made, not decay into an
 * unexplained gap.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

function smpro_ph_ign_path() { return SMPRO_VARLIB . '/php_harden/ignore.json'; }

/** The whole list, keyed by account: [user => ['user','reason','by','at','scope']]. */
function smpro_ph_ign_all() {
    $j = json_decode((string)@file_get_contents(smpro_ph_ign_path()), true);
    if (!is_array($j)) return [];
    $out = [];
    foreach ($j as $k => $row) {
        if (!is_array($row)) continue;
        $u = (string)($row['user'] ?? $k);
        if ($u === '' || !preg_match('/^[a-zA-Z0-9._-]{1,64}$/', $u)) continue;
        $out[$u] = ['user' => $u, 'reason' => (string)($row['reason'] ?? ''), 'by' => (string)($row['by'] ?? ''),
                    'at' => (string)($row['at'] ?? ''), 'scope' => (string)($row['scope'] ?? 'all')];
    }
    ksort($out);
    return $out;
}

/**
 * Is this account on the list?
 *
 * $scope is what the CALLER is about to do - 'auto' for an unattended pass (emergency response, auto re-lock),
 * 'manual' for an operator pressing Apply on the page. An entry may exclude only automation, so that an admin who
 * deliberately opens the page and applies protection is not silently refused; the default entry excludes both.
 */
function smpro_ph_ign_has($u, $scope = 'auto') {
    $row = smpro_ph_ign_all()[(string)$u] ?? null;
    if (!$row) return false;
    return ($row['scope'] === 'all') || ($row['scope'] === 'auto' && $scope === 'auto');
}

/** The stored entry for an account, or null. */
function smpro_ph_ign_get($u) { return smpro_ph_ign_all()[(string)$u] ?? null; }

function smpro_ph_ign_save(array $list) {
    $dir = dirname(smpro_ph_ign_path());
    @is_dir($dir) || @mkdir($dir, 0700, true);
    $tmp = smpro_ph_ign_path() . '.tmp';
    if (@file_put_contents($tmp, json_encode($list, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), LOCK_EX) === false) return false;
    @chmod($tmp, 0600);
    return @rename($tmp, smpro_ph_ign_path());
}

/** Add (or update) an account. Returns false only if the list could not be written. */
function smpro_ph_ign_add($u, $reason = '', $by = '', $scope = 'all') {
    $u = (string)$u;
    if (!preg_match('/^[a-zA-Z0-9._-]{1,64}$/', $u)) return false;
    if ($scope !== 'auto') $scope = 'all';
    $list = smpro_ph_ign_all();
    $list[$u] = ['user' => $u, 'reason' => trim((string)$reason), 'by' => (string)$by, 'at' => date('c'), 'scope' => $scope];
    return smpro_ph_ign_save($list);
}

/** Remove an account. Returns true only if it was there AND the list was written. */
function smpro_ph_ign_remove($u) {
    $list = smpro_ph_ign_all();
    if (!isset($list[(string)$u])) return false;
    unset($list[(string)$u]);
    return smpro_ph_ign_save($list);
}

/** Where the permanent-unlock list lives. One JSON object: path => ['by' => who, 'at' => when]. */
function smpro_ph_perm_path(): string { return SMPRO_VARLIB . '/php_harden/perm_unlock.json'; }

/** Every path the operator has permanently released from locking. Was called everywhere and defined nowhere. */
function smpro_ph_perm_all(): array {
    $j = json_decode((string)@file_get_contents(smpro_ph_perm_path()), true);
    return is_array($j) ? $j : [];
}

function smpro_ph_perm_add(string $path, string $by = ''): bool {
    $all = smpro_ph_perm_all(); $all[$path] = ['by' => $by, 'at' => time()];
    @is_dir(dirname(smpro_ph_perm_path())) || @mkdir(dirname(smpro_ph_perm_path()), 0700, true);
    return @file_put_contents(smpro_ph_perm_path(), json_encode($all, JSON_UNESCAPED_SLASHES), LOCK_EX) !== false;
}

function smpro_ph_perm_remove(string $path): bool {
    $all = smpro_ph_perm_all(); unset($all[$path]); $r = realpath($path); if ($r !== false) unset($all[$r]);
    return @file_put_contents(smpro_ph_perm_path(), json_encode($all, JSON_UNESCAPED_SLASHES), LOCK_EX) !== false;
}

/** Is this exact path permanently unlocked? */
function smpro_ph_perm_has($path) {
    $p = (string)$path;
    if ($p === '') return false;
    $real = realpath($p);
    $all  = smpro_ph_perm_all();
    // Match the stored name AND the resolved one: a path can be recorded before a
    // symlink in its parent changes, and re-locking the same file under another
    // spelling would defeat the whole entry.
    return isset($all[$p]) || ($real !== false && isset($all[$real]));
}
