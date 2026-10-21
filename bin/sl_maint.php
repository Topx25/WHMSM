<?php
/**
 * bin/sl_maint.php release|relock — run by cPanel's own hooks around PHP package updates and upcp, and by the
 * System updates page around its own dnf run. Lifts Safety Lock's immutable bits for the maintenance and puts them
 * back after it (see includes/slmaint.php). Exit code 0 always: a hook that fails must never stop cPanel's update.
 */
define('SMPRO_BOOT', 1);
$base = dirname(__DIR__);
foreach (['defines', 'env', 'mmdb', 'helpers', 'secret', 'license', 'notify', 'phlock', 'phstack', 'ph_ignore', 'compcheck', 'spqueue', 'slmaint'] as $m) {
    $f = $base . '/includes/' . $m . '.php';
    if (is_file($f)) require_once $f;
}
$verb = (string)($argv[1] ?? '');
try {
    if ($verb === 'release' && function_exists('smpro_slm_release')) { $r = smpro_slm_release('cPanel maintenance'); fwrite(STDOUT, $r['msg'] . "\n"); }
    elseif ($verb === 'relock' && function_exists('smpro_slm_relock')) { $r = smpro_slm_relock('cPanel maintenance'); fwrite(STDOUT, $r['msg'] . "\n"); }
    else fwrite(STDERR, "usage: sl_maint.php release|relock\n");
} catch (\Throwable $e) {
    if (function_exists('smpro_soft_fail')) smpro_soft_fail('sl_maint', $e);
}
exit(0);
