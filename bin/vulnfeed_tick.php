<?php
/**
 * bin/vulnfeed_tick.php - pull the signed service-vulnerability advisory list from the licence server
 * (see includes/vulnfeed.php). Exit 0 always; a failed pull leaves the previous verified list in place.
 */
define('SMPRO_BOOT', 1);
$base = dirname(__DIR__);
foreach (['defines', 'env', 'mmdb', 'helpers', 'secret', 'license', 'trustfeed', 'vulnfeed'] as $m) {
    $f = $base . '/includes/' . $m . '.php';
    if (is_file($f)) require_once $f;
}
try {
    if (function_exists('smpro_ctl_disabled') && smpro_ctl_disabled()) exit(0);
    if (function_exists('smpro_vf_fetch')) { $r = smpro_vf_fetch(); fwrite(STDOUT, ($r['ok'] ? 'ok: ' : 'kept previous: ') . $r['msg'] . "\n"); }
} catch (\Throwable $e) {
    if (function_exists('smpro_soft_fail')) smpro_soft_fail('vulnfeed_tick', $e);
}
exit(0);
