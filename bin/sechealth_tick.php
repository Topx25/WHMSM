<?php
/**
 * bin/sechealth_tick.php - the Security Health page had NO automatic scan: it ran its ~50 checks only when an
 * operator opened it, so an end-of-life PHP branch, a newly world-exposed port, or a protection that switched off
 * sat unseen until someone happened to look. This worker runs the SAME checks on a schedule (the cron below), keeps
 * a snapshot, and raises ONE alert for a NEW critical/warning finding since the last run - so the server tells you
 * when its security posture gets worse instead of waiting to be asked.
 *
 * It runs the page's own smpro_sh_all() in a CLI process (the module is page code; this is the one place a worker
 * loads it, the same way the Site Doctor worker loads its scan). Nothing on the page changes; this only reads.
 *
 *   php bin/sechealth_tick.php         - run if the schedule is due
 *   php bin/sechealth_tick.php --now   - run now whatever the schedule says
 */
define('SMPRO_BOOT', 1);
$base = dirname(__DIR__);
foreach (['defines', 'env', 'mmdb', 'helpers', 'secret', 'license', 'notify', 'mailblock', 'trustfeed', 'vulnfeed', 'shharden', 'sechealth'] as $m) {
    $f = $base . '/includes/' . $m . '.php';
    if (is_file($f)) require_once $f;
}
if (PHP_SAPI !== 'cli') exit;
$now = in_array('--now', $argv ?? [], true);

try {
    if (function_exists('smpro_ctl_disabled') && smpro_ctl_disabled()) exit(0);

    $stateFile = SMPRO_VARLIB . '/sechealth_auto.json';
    $st = @is_file($stateFile) ? (array)json_decode((string)@file_get_contents($stateFile), true) : [];
    $cfg = is_array($st['cfg'] ?? null) ? $st['cfg'] : [];
    $every = max(3600, (int)($cfg['every'] ?? 86400));                 // daily by default, at least hourly
    if (!$now && (time() - (int)($st['last_run'] ?? 0)) < $every) exit(0);

    // The checks live in includes/sechealth.php (moved out of the page module exactly so a worker can run them).
    if (!function_exists('smpro_sh_all')) { $sh = $base . '/includes/sechealth.php'; if (is_file($sh)) require_once $sh; }
    if (!function_exists('smpro_sh_all')) { if (function_exists('smpro_soft_fail')) smpro_soft_fail('sechealth_tick', new \RuntimeException('smpro_sh_all not available')); exit(1); }

    // smpro_sh_all() returns [category => [check, check, ...]]; flatten to the individual checks.
    $cats = (array)smpro_sh_all();
    $items = [];
    foreach ($cats as $catChecks) foreach ((array)$catChecks as $it) if (is_array($it)) $items[] = $it;

    // Reduce to a stable map: title => status, keeping only the ones that are a real problem.
    $cur = [];
    foreach ($items as $it) {
        $title = (string)($it['title'] ?? ''); $status = strtolower((string)($it['status'] ?? ''));
        if ($title === '' || !in_array($status, ['critical', 'warning'], true)) continue;
        $cur[$title] = ['status' => $status, 'finding' => (string)($it['finding'] ?? '')];
    }
    $prev = is_array($st['findings'] ?? null) ? $st['findings'] : [];

    // NEW or WORSENED since last run: a title that was absent, or moved warning -> critical.
    $rank = ['warning' => 1, 'critical' => 2];
    $new = [];
    foreach ($cur as $title => $c) {
        $was = $prev[$title]['status'] ?? '';
        if ($was === '' || ($rank[$c['status']] ?? 0) > ($rank[$was] ?? 0)) $new[$title] = $c;
    }

    $critN = 0; foreach ($cur as $c) if ($c['status'] === 'critical') $critN++;
    $st['cfg'] = $cfg; $st['last_run'] = time(); $st['findings'] = $cur;
    $st['counts'] = ['critical' => $critN, 'warning' => count($cur) - $critN];
    smpro_json_save($stateFile, $st);

    if ($new && function_exists('smpro_notify')) {
        $critNew = array_filter($new, fn($c) => $c['status'] === 'critical');
        $sev = $critNew ? 'critical' : 'warning';
        $lines = [];
        foreach ($new as $title => $c) $lines[] = strtoupper($c['status']) . ' — ' . $title . ($c['finding'] !== '' ? ': ' . mb_substr($c['finding'], 0, 160) : '');
        $body = "The scheduled Security Health scan found " . count($new) . " new or worsened issue(s) since the last run:\n\n"
              . implode("\n", array_map(fn($l) => '• ' . $l, $lines))
              . "\n\nOpen Security Health for the full list and the one-click fixes.";
        smpro_notify('sechealth_auto', count($new) . ' new security-health issue(s)', $body, ['severity' => $sev], true);
        if (function_exists('smpro_audit')) @smpro_audit('sechealth_auto', ['new' => array_keys($new), 'critical_total' => $critN]);
    }
    fwrite(STDOUT, 'sechealth: ' . count($cur) . " issue(s), " . count($new) . " new\n");
} catch (\Throwable $e) {
    if (function_exists('smpro_soft_fail')) smpro_soft_fail('sechealth_tick', $e);
}
exit(0);
