<?php
/**
 * bin/trustfeed_tick.php — pull the signed trusted-bots list from the licence server (see includes/trustfeed.php).
 * Exit 0 always; a failed pull leaves the previous list in place.
 */
define('SMPRO_BOOT', 1);
$base = dirname(__DIR__);
foreach (['defines', 'env', 'mmdb', 'helpers', 'secret', 'license', 'trustfeed'] as $m) {
    $f = $base . '/includes/' . $m . '.php';
    if (is_file($f)) require_once $f;
}
try {
    if (function_exists('smpro_ctl_disabled') && smpro_ctl_disabled()) exit(0);
    if (function_exists('smpro_tf_fetch')) { $r = smpro_tf_fetch(); fwrite(STDOUT, ($r['ok'] ? 'ok: ' : 'kept previous: ') . $r['msg'] . "\n"); }
} catch (\Throwable $e) {
    if (function_exists('smpro_soft_fail')) smpro_soft_fail('trustfeed_tick', $e);
}
exit(0);
