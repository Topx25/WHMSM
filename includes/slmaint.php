<?php
/**
 * includes/slmaint.php - Safety Lock and the panel's own maintenance.
 *
 * WHY. Safety Lock keeps an account's .htaccess and the other files a break-in rewrites immutable (chattr +i), which
 * root itself cannot write through. cPanel's PHP update hook (009-phpconf.pl, run by dnf for every PHP package) and
 * its MultiPHP tooling REWRITE those .htaccess files to carry the account's PHP handler. On a production server the
 * two met: every PHP package update ended in "failed to lock the immutable (+i) file ... Operation not permitted"
 * for hundreds of accounts, and the 1,176-package PHP update had to be postponed. Neither side was wrong - the
 * protection is wanted, the update is wanted - they had simply never been told about each other.
 *
 * WHAT. Two tiny hooks in the same cPanel hook folders, sorted before and after cPanel's own:
 *   005-smpro-safetylock-release   lifts +i from every file Safety Lock locked, and RECORDS the list
 *   995-smpro-safetylock-relock    puts +i back on exactly that list
 * plus the same pair around cPanel's updater (/scripts/preupcp, /scripts/postupcp). A release is never open-ended:
 * the Site Protection worker (every minute) re-locks a release older than two hours whether or not the relock hook
 * ran - a crashed update must not leave a server unlocked. Files the operator permanently unlocked are left alone.
 * A lock set by ANOTHER product is not touched: it is reported by name so the operator lifts it where it was set.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit; }

define('SMPRO_SLM_REC',   SMPRO_VARLIB . '/php_harden/maint_release.json');
define('SMPRO_SLM_MARK',  '#smpro-safetylock');
define('SMPRO_SLM_MAXAGE', 7200);

function smpro_slm_rec(): array { $d = @is_file(SMPRO_SLM_REC) ? json_decode((string)@file_get_contents(SMPRO_SLM_REC), true) : null; return is_array($d) ? $d : []; }
function smpro_slm_rec_save(array $r): void { @is_dir(dirname(SMPRO_SLM_REC)) || @mkdir(dirname(SMPRO_SLM_REC), 0700, true); smpro_json_save(SMPRO_SLM_REC, $r); }

/** Every file Safety Lock would lock on this server, that is locked right now and not permanently unlocked. */
function smpro_slm_locked_files(): array {
    if (!function_exists('smpro_spq_targets') || !function_exists('smpro_ph_locked_map')) return [];
    $all = [];
    foreach (array_keys(function_exists('smpro_cc_accounts') ? smpro_cc_accounts() : []) as $u) {
        foreach (smpro_spq_targets($u) as $p) { if (function_exists('smpro_ph_perm_has') && smpro_ph_perm_has($p)) continue; $all[] = $p; }
    }
    if (!$all) return [];
    $out = [];
    foreach (array_chunk($all, 500) as $chunk) foreach (smpro_ph_locked_map($chunk) as $p => $locked) if ($locked) $out[] = $p;
    return $out;
}
/** Lift the locks for maintenance and record exactly what was lifted. Idempotent: a second call during the same
 *  maintenance extends the record rather than losing the first list. */
function smpro_slm_release(string $why = 'maintenance'): array {
    if (!function_exists('smpro_ph_chattr_many')) return ['ok' => false, 'released' => 0, 'msg' => 'the file-lock helpers are not loaded'];
    $files = smpro_slm_locked_files();
    $rec = smpro_slm_rec();
    if (!$files) { if (!$rec) return ['ok' => true, 'released' => 0, 'msg' => 'nothing is locked']; $files = []; }
    $r = smpro_ph_chattr_many('-i', $files);
    $list = array_values(array_unique(array_merge((array)($rec['files'] ?? []), $files)));
    smpro_slm_rec_save(['at' => (int)($rec['at'] ?? time()), 'why' => $why, 'files' => $list]);
    if (function_exists('smpro_audit')) smpro_audit('safetylock_maint_release', ['why' => $why, 'released' => (int)$r['done'], 'total' => count($list)]);
    return ['ok' => (bool)$r['ok'], 'released' => (int)$r['done'], 'msg' => (int)$r['done'] . ' file(s) unlocked for ' . $why . ' (' . count($list) . ' recorded); they are locked again by the relock hook, or by the worker after ' . (SMPRO_SLM_MAXAGE / 3600) . ' hours at the latest'];
}
/** Put the locks back on exactly the recorded list and clear the record. */
function smpro_slm_relock(string $why = 'maintenance'): array {
    $rec = smpro_slm_rec();
    if (!$rec) return ['ok' => true, 'relocked' => 0, 'msg' => 'nothing was released'];
    $again = [];
    foreach ((array)($rec['files'] ?? []) as $p) { if (function_exists('smpro_ph_perm_has') && smpro_ph_perm_has($p)) continue; if (is_file($p) && !is_link($p)) $again[] = $p; }
    $r = function_exists('smpro_ph_chattr_many') ? smpro_ph_chattr_many('+i', $again) : ['ok' => false, 'done' => 0, 'failed' => []];
    @unlink(SMPRO_SLM_REC);
    if (function_exists('smpro_audit')) smpro_audit('safetylock_maint_relock', ['why' => $why, 'relocked' => (int)$r['done'], 'failed' => count((array)$r['failed'])]);
    return ['ok' => (bool)$r['ok'], 'relocked' => (int)$r['done'], 'msg' => (int)$r['done'] . ' file(s) locked again after ' . $why . (count((array)$r['failed']) ? '; ' . count((array)$r['failed']) . ' could not be locked' : '')];
}
/** The worker calls this every minute: a release older than the limit is closed whether or not the relock ran. */
function smpro_slm_deadman(): int {
    $rec = smpro_slm_rec(); if (!$rec) return 0;
    if (time() - (int)($rec['at'] ?? 0) < SMPRO_SLM_MAXAGE) return 0;
    $r = smpro_slm_relock('the time limit (the relock hook never ran)');
    if (function_exists('smpro_notify')) @smpro_notify('harden_drift', 'Safety Lock: locks put back by the time limit', 'A maintenance release of ' . count((array)($rec['files'] ?? [])) . ' file(s) was never closed by the relock hook (an update that crashed or was interrupted). The worker locked them again: ' . $r['msg']);
    return (int)$r['relocked'];
}

/* ---------------- the hooks cPanel runs ---------------- */
function smpro_slm_hook_body(string $verb): string {
    $php = function_exists('smpro_php_cli_bin') ? smpro_php_cli_bin() : '/usr/local/cpanel/3rdparty/bin/php';
    return "#!/bin/bash\n" . SMPRO_SLM_MARK . " - Safety Monitor Pro: lift Safety Lock's immutable bits for this maintenance and put them back after it\n"
         . "exec timeout 300 " . $php . " " . SMPRO_BASE . "/bin/sl_maint.php " . $verb . " >/dev/null 2>&1\n";
}
/** Where cPanel runs its PHP-package hooks: every transaction folder that carries its own 009-phpconf.pl. */
function smpro_slm_hook_dirs(): array {
    $out = [];
    foreach (['/etc/dnf/universal-hooks', '/etc/yum/universal-hooks'] as $base) foreach (glob($base . '/multi_pkgs/transaction/*/009-phpconf.pl') ?: [] as $f) $out[] = dirname($f);
    return $out;
}
/** Install (or refresh) the hooks; remove them when Safety Lock's worker is not shipped. Idempotent, quiet. */
function smpro_slm_hooks_sync(): array {
    if (defined('SMPRO_TEST_SRC')) return ['ok' => true, 'msg' => 'test: hooks are never installed'];
    $ship = is_file(SMPRO_BASE . '/bin/sl_maint.php'); $n = 0;
    foreach (smpro_slm_hook_dirs() as $d) {
        foreach (['005-smpro-safetylock-release' => 'release', '995-smpro-safetylock-relock' => 'relock'] as $name => $verb) {
            $f = $d . '/' . $name;
            if (!$ship) { if (is_file($f)) @unlink($f); continue; }
            $want = smpro_slm_hook_body($verb);
            if ((string)@file_get_contents($f) !== $want) { @file_put_contents($f, $want); @chmod($f, 0755); $n++; }
        }
    }
    // cPanel's own updater: /scripts/preupcp and /scripts/postupcp are run when present; other products append lines
    // to them too, so one marked line is added or removed, never the file rewritten.
    foreach (['/scripts/preupcp' => 'release', '/scripts/postupcp' => 'relock'] as $f => $verb) {
        $php = function_exists('smpro_php_cli_bin') ? smpro_php_cli_bin() : '/usr/local/cpanel/3rdparty/bin/php';
        $line = 'timeout 300 ' . $php . ' ' . SMPRO_BASE . '/bin/sl_maint.php ' . $verb . ' >/dev/null 2>&1   ' . SMPRO_SLM_MARK;
        $cur = is_file($f) ? (string)@file_get_contents($f) : '';
        $has = strpos($cur, SMPRO_SLM_MARK) !== false;
        if (!$ship) { if ($has) { @file_put_contents($f, preg_replace('/^.*' . preg_quote(SMPRO_SLM_MARK, '/') . '.*\n?/m', '', $cur)); } continue; }
        if ($has && strpos($cur, $line) !== false) continue;
        if ($has) $cur = preg_replace('/^.*' . preg_quote(SMPRO_SLM_MARK, '/') . '.*\n?/m', '', $cur);
        if ($cur === '') $cur = "#!/bin/bash\n";
        if (!is_dir('/scripts')) continue;
        @file_put_contents($f, rtrim($cur, "\n") . "\n" . $line . "\n"); @chmod($f, 0755); $n++;
    }
    return ['ok' => true, 'msg' => $n . ' hook file(s) written'];
}
/** Is anything released for maintenance right now? For the pages. */
function smpro_slm_status(): array { $r = smpro_slm_rec(); return ['released' => $r ? count((array)($r['files'] ?? [])) : 0, 'since' => (int)($r['at'] ?? 0), 'why' => (string)($r['why'] ?? ''), 'hooks' => count(smpro_slm_hook_dirs())]; }
