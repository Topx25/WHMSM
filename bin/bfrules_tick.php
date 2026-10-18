<?php
/**
 * bin/bfrules_tick.php — Break-in rules worker.
 *
 * Installed as /etc/cron.d/smpro-bfrules while the rules are enabled, removed when they are turned off. This is
 * the whole point of the rules: an attack that starts at 3am is blocked at 3am, not when somebody next opens the
 * Break-in Report.
 *
 * It rebuilds the networks from this server's own logs through includes/breakin.php — the same code the page
 * uses — so the worker and the page can never hold two different opinions about what an attack is. Nothing here
 * takes a number from anywhere else.
 *
 * A run that could not read the logs exits without blocking and says so in the record. "Could not look" is not
 * "nothing found", and a worker that silently treats them the same is the failure this project keeps removing.
 */
define('SMPRO_BOOT', 1);
@ini_set('memory_limit', '512M');   // a 200k-line login window materialises ~300 MB; the CLI default (128M) died silently while the page said ARMED
$base = dirname(__DIR__);
foreach (['defines', 'mmdb', 'helpers', 'secret', 'license', 'fwallow', 'botguard', 'breakin', 'bfrules'] as $m) {
    $f = $base . '/includes/' . $m . '.php';
    if (is_file($f)) require_once $f;
}

if (function_exists('smpro_lic_heartbeat')) { @smpro_lic_heartbeat(); }
if (function_exists('smpro_ctl_disabled') && smpro_ctl_disabled()) exit;

if (!function_exists('smpro_bfr_cfg') || !function_exists('smpro_bi_networks')) exit;
$cfg = smpro_bfr_cfg();
if (empty($cfg['enabled'])) exit;                       // the cron should already be gone, but never act if it is not

try {
    $b = smpro_bi_networks();
    if (empty($b['ok'])) {
        // Recorded rather than swallowed: a night where the rules could not read the log must be visible the
        // next morning, not indistinguishable from a quiet night.
        if (function_exists('smpro_bfr_record')) smpro_bfr_record('-', 'run', 'could not read the logs: ' . (string)$b['msg'], 'cron', false, (string)$b['msg']);
        exit;
    }
    if (!$b['nets']) exit;                              // genuinely nothing to judge
    $gdry = function_exists('smpro_ctl_dry_run') && smpro_ctl_dry_run();   // global Dry-Run = judge, report, never act
    smpro_bfr_run($b['nets'], $cfg, $gdry ? true : null, 'cron');
} catch (\Throwable $e) {
    if (function_exists('smpro_worker_fatal')) smpro_worker_fatal('bfrules_tick', $e);
    elseif (function_exists('smpro_soft_fail')) smpro_soft_fail('bfrules_tick', $e);
}
