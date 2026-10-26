<?php
/**
 * bin/secreport_tick.php - build yesterday's Daily Security Report and deliver it (see includes/secreport.php).
 * With --now the report is built at once whatever the schedule says (kept in the panel, not delivered).
 */
define('SMPRO_BOOT', 1);
$base = dirname(__DIR__);
foreach (['defines', 'env', 'mmdb', 'helpers', 'secret', 'license', 'netkind', 'geologin', 'loginfeed', 'breakin', 'intrusion', 'learn', 'lvelimits', 'sysupd', 'geoset', 'geowall', 'geohulk', 'trustfeed', 'botguard', 'crawlers', 'notify', 'digest', 'secreport'] as $m) {
    $f = $base . '/includes/' . $m . '.php';
    if (is_file($f)) require_once $f;
}
try {
    if (function_exists('smpro_ctl_disabled') && smpro_ctl_disabled()) exit(0);
    if (function_exists('smpro_sr_run')) { $r = smpro_sr_run(in_array('--now', $argv ?? [], true)); fwrite(STDOUT, (!empty($r['ok']) ? 'built ' . $r['id'] . ' score ' . $r['score'] : 'skipped: ' . (string)($r['skipped'] ?? '')) . "\n"); }
} catch (\Throwable $e) {
    if (function_exists('smpro_soft_fail')) smpro_soft_fail('secreport_tick', $e);
}
exit(0);
