<?php
/**
 * bin/crawlers_tick.php - count crawler traffic since the last pass (see includes/crawlers.php). Exit 0 always.
 */
define('SMPRO_BOOT', 1);
$base = dirname(__DIR__);
foreach (['defines', 'env', 'mmdb', 'helpers', 'secret', 'license', 'trustfeed', 'botguard', 'crawlers'] as $m) {
    $f = $base . '/includes/' . $m . '.php';
    if (is_file($f)) require_once $f;
}
try {
    if (function_exists('smpro_ctl_disabled') && smpro_ctl_disabled()) exit(0);
    if (function_exists('smpro_cr_robots_apply') && function_exists('smpro_cr_robots_families') && smpro_cr_robots_families() && (int)date('G') === 4 && (int)date('i') < 10) smpro_cr_robots_apply();   // once a day: new sites, files put back by a restore
    if (function_exists('smpro_cr_collect')) { $r = smpro_cr_collect(); fwrite(STDOUT, ($r['ok'] ? 'ok: ' : 'skipped: ') . $r['files'] . ' file(s), ' . $r['lines'] . ' line(s)' . ($r['partial'] ? ', partial' : '') . ($r['why'] !== '' ? ' - ' . $r['why'] : '') . "\n"); }
} catch (\Throwable $e) {
    if (function_exists('smpro_soft_fail')) smpro_soft_fail('crawlers_tick', $e);
}
exit(0);
