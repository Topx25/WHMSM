<?php
/**
 * includes/imclean.php - hand stuck "found" malware to Imunify360's own cleanup.
 *
 * Imunify cleans automatically only what its background scan finds. Files found by an on-demand scan or a
 * rescan stay "found" forever even when the operator set default_action = cleanup - a production server had
 * 262 of them while SM Pro kept alerting. SM Pro never deletes here: it asks Imunify to run ITS cleanup on those
 * files, which keeps the original (restore-original) for the period set in Imunify.
 *
 * Automatic mode follows the operator's own Imunify choice: it acts only when default_action is "cleanup",
 * only on files that have waited at least an hour (so Imunify's own pass goes first), at most once an hour,
 * and reports only in Dry-Run / Disabled.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

function smpro_imc_bin(): string {
    foreach (['/usr/bin/imunify360-agent', '/usr/sbin/imunify360-agent'] as $b) if (@is_executable($b)) return $b;
    return '';
}
function smpro_imc_cfg_file(): string { return SMPRO_VARLIB . '/imclean.json'; }
function smpro_imc_cfg(): array {
    $c = json_decode((string)@file_get_contents(smpro_imc_cfg_file()), true);
    $c = is_array($c) ? $c : [];
    $c += ['auto' => 'follow', 'last_run' => 0, 'last' => []];
    if (!in_array($c['auto'], ['follow', 'off'], true)) $c['auto'] = 'follow';
    return $c;
}
function smpro_imc_cfg_save(array $c): void {
    $f = smpro_imc_cfg_file(); $t = $f . '.tmp';
    if (@file_put_contents($t, json_encode($c, JSON_UNESCAPED_SLASHES)) !== false) { @chmod($t, 0600); @rename($t, $f); }
}
/** Imunify's own default action for detected malware ('cleanup', 'notify', ...); '' when it cannot be read. */
function smpro_imc_default_action(): string {
    $b = smpro_imc_bin(); if ($b === '') return '';
    $j = json_decode((string)@shell_exec('timeout 40 ' . escapeshellarg($b) . ' config show --json 2>/dev/null'), true);
    return (string)($j['items']['MALWARE_SCANNING']['default_action'] ?? '');
}
/** Rows of `malware malicious list` that Imunify left as found: a file still on disk, inside its owner's home,
 *  not WP Guard's own, detected at least $minAge seconds ago. Returns [file => [ids...]]. */
function smpro_imc_stuck(array $items, int $minAge = 3600): array {
    $out = []; $now = time(); $homes = [];
    foreach ($items as $r) {
        if (($r['status'] ?? '') !== 'found' || ($r['resource_type'] ?? '') === 'db') continue;
        $p = (string)($r['file'] ?? ''); $u = (string)($r['username'] ?? ''); $id = (int)($r['id'] ?? 0);
        if ($p === '' || $u === '' || $id <= 0 || $now - (int)($r['detected'] ?? $r['created'] ?? $now) < $minAge) continue;
        if (function_exists('smpro_wpguard_trusted') && smpro_wpguard_trusted($p)) continue;
        if (!isset($homes[$u])) { $h = function_exists('smpro_user_home') ? (string)smpro_user_home($u) : ''; $homes[$u] = $h !== '' ? (string)@realpath($h) : ''; }
        $rp = (string)@realpath($p);
        if ($homes[$u] === '' || $rp === '' || !is_file($rp) || strpos($rp, $homes[$u] . '/') !== 0) continue;
        $out[$p][] = $id;
    }
    return $out;
}
/** Ask Imunify to clean these item ids (chunked). Returns [ok, number of ids accepted, message]. */
function smpro_imc_clean(array $ids, array $files = []): array {
    $b = smpro_imc_bin(); if ($b === '') return [false, 0, 'Imunify360 agent not available'];
    $ids = array_values(array_unique(array_filter(array_map('intval', $ids), fn($i) => $i > 0)));
    if (!$ids) return [true, 0, 'nothing to clean'];
    // Learned Defense reads each file before Imunify changes it; $files is [path, ...] when the caller knows them
    if ($files && !function_exists('smpro_lr_learn_file')) { $lf = __DIR__ . '/learn.php'; if (is_file($lf)) require_once $lf; }
    if ($files && function_exists('smpro_lr_learn_file')) foreach (array_slice($files, 0, 300) as $p) {
        // a lesson that cannot be read must never stop the cleanup itself: logged, not thrown
        try { smpro_lr_learn_file($p, $p, 'imunify cleanup'); } catch (\Throwable $e) { if (function_exists('smpro_soft_fail')) smpro_soft_fail('imclean:learn', $e); }
    }
    $n = 0; $err = '';
    foreach (array_chunk($ids, 100) as $chunk) {
        $o = []; $rc = 1;
        @exec('timeout 120 ' . escapeshellarg($b) . ' malware malicious cleanup --items ' . implode(' ', $chunk) . ' --json 2>&1', $o, $rc);
        if ($rc === 0) $n += count($chunk); else $err = substr(trim(implode(' ', $o)), 0, 200);
    }
    return [$err === '', $n, $err === '' ? "Imunify360 is cleaning $n item(s)" : "Imunify360 refused part of the cleanup: $err"];
}
/** Automatic pass, called from the alert cycle with the list it already read. Returns
 *  ['ran' => bool, 'files' => [paths sent], 'why' => text]. */
function smpro_imc_auto(array $items): array {
    $c = smpro_imc_cfg();
    if ($c['auto'] !== 'follow') return ['ran' => false, 'files' => [], 'why' => 'automatic cleanup is off'];
    if (time() - (int)$c['last_run'] < 3600) return ['ran' => false, 'files' => [], 'why' => 'ran within the hour'];
    $stuck = smpro_imc_stuck($items);
    if (!$stuck) return ['ran' => false, 'files' => [], 'why' => 'nothing waiting'];
    $act = smpro_imc_default_action();
    if ($act !== 'cleanup') return ['ran' => false, 'files' => [], 'why' => 'Imunify default action is ' . ($act === '' ? 'unknown' : $act) . ', not cleanup'];
    $c['last_run'] = time();
    $dry = (function_exists('smpro_ctl_dry_run') && smpro_ctl_dry_run()) || (function_exists('smpro_ctl_get') && smpro_ctl_get()['mode'] === 'disabled');
    if ($dry) { $c['last'] = ['at' => time(), 'files' => count($stuck), 'dry' => true]; smpro_imc_cfg_save($c); return ['ran' => false, 'files' => [], 'why' => 'Dry-Run: would ask Imunify to clean ' . count($stuck) . ' file(s)']; }
    $ids = []; foreach ($stuck as $l) $ids = array_merge($ids, $l);
    [$ok, $n, $msg] = smpro_imc_clean($ids, array_keys($stuck));
    $c['last'] = ['at' => time(), 'files' => count($stuck), 'ok' => $ok, 'msg' => $msg];
    smpro_imc_cfg_save($c);
    if (function_exists('smpro_audit')) smpro_audit('im_auto_cleanup', ['files' => count($stuck), 'ids' => $n, 'ok' => $ok]);
    return ['ran' => $n > 0, 'files' => $ok ? array_keys($stuck) : [], 'why' => $msg];
}
