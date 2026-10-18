<?php
/**
 * bin/update_check.php — dedicated daily cron worker for the in-plugin updater.
 * Always refreshes the "latest available" version (so the UI/dashboard can show it),
 * and auto-applies the new build only when auto-update is enabled.
 * Installed via /etc/cron.d/smpro-update (once per day) by smpro_upd_install_cron().
 */
define('SMPRO_BOOT', 1);
$base = dirname(__DIR__);
require $base . '/includes/defines.php';
require $base . '/includes/env.php';
require $base . '/includes/mmdb.php';
require $base . '/includes/helpers.php';
require $base . '/includes/secret.php';
require $base . '/includes/license.php';
require $base . '/includes/intrusion.php';
require $base . '/includes/update.php';
// keep the license verdict fresh FIRST — this is the always-installed daily cron, so it guarantees the plugin
// wakes from dormancy after a renewal even if no other worker is scheduled.
if (function_exists('smpro_lic_heartbeat')) { @smpro_lic_heartbeat(); }
// disabled / license-dormant (>48h stopped) → do nothing further (the heartbeat above still detects renewal)
if (function_exists('smpro_ctl_disabled') && smpro_ctl_disabled()) exit;
// ensure required tooling (mmdblookup) + a fresh offline GeoIP DB are present (self-provision on every box)
if (function_exists('smpro_deps_ensure'))      { try { smpro_deps_ensure(); } catch (\Throwable $e) { if (function_exists('smpro_worker_fatal')) smpro_worker_fatal(__FILE__, $e); else @error_log('smpro worker fatal in ' . basename(__FILE__) . ': ' . $e->getMessage()); } }
if (function_exists('smpro_geoip_auto_update')) { try { smpro_geoip_auto_update(); } catch (\Throwable $e) { if (function_exists('smpro_worker_fatal')) smpro_worker_fatal(__FILE__, $e); else @error_log('smpro worker fatal in ' . basename(__FILE__) . ': ' . $e->getMessage()); } }
if (function_exists('smpro_upd_auto')) { try { smpro_upd_auto(); } catch (\Throwable $e) { if (function_exists('smpro_worker_fatal')) smpro_worker_fatal(__FILE__, $e); else @error_log('smpro worker fatal in ' . basename(__FILE__) . ': ' . $e->getMessage()); } }
