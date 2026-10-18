<?php
/**
 * bin/lic_refresh.php — detached background license re-check.
 * Spawned (non-blocking) from a page load when the cached verdict is getting stale,
 * so active browsing keeps the license "seen" within the 10-min window WITHOUT adding
 * latency to the page. Does one /api/check and persists the fresh signed verdict.
 */
define('SMPRO_BOOT', 1);
$base = dirname(__DIR__);
require $base . '/includes/defines.php';
require $base . '/includes/helpers.php';
require $base . '/includes/license.php';
if (function_exists('smpro_lic_check')) { @smpro_lic_check(); }
$lock = SMPRO_LIC_DIR . '/.refresh.lock';
if (is_file($lock)) @unlink($lock);
