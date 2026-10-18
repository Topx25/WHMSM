<?php
/**
 * bin/loadsample.php — every minute: one load sample into the 24-hour ring (includes/loadhist.php).
 * Read-only, sub-millisecond; NOT gated on the plugin being switched off, because the history of a quiet
 * hour is exactly what the next investigation asks for.
 */
define('SMPRO_BOOT', 1);
$base = dirname(__DIR__);
foreach (['defines', 'helpers', 'loadhist'] as $m) { $f = $base . '/includes/' . $m . '.php'; if (is_file($f)) require_once $f; }
if (!function_exists('smpro_lo_hist_tick')) exit;
try { smpro_lo_hist_tick(smpro_lo_load1()); } catch (\Throwable $e) { @error_log('smpro loadsample: ' . $e->getMessage()); }
