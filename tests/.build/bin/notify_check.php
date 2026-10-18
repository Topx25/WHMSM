<?php
/**
 * bin/notify_check.php — cron worker for the Notifications checker.
 * Runs the deduped live event checks and dispatches any new alerts.
 * Installed via /etc/cron.d/smpro-notify (every 15 min) from the UI.
 */
define('SMPRO_BOOT', 1);
$base = dirname(__DIR__);
require $base . '/includes/defines.php';
require $base . '/includes/mmdb.php';
require $base . '/includes/helpers.php';
require $base . '/includes/secret.php';
require $base . '/includes/license.php';
require $base . '/includes/intrusion.php';
require $base . '/includes/notify.php';
require $base . '/includes/update.php';
require $base . '/includes/reports.php';
require $base . '/includes/digest.php';
require $base . '/includes/ai.php';   // pulls in ai_catalog.php (require_once) → smpro_ai_autoprune()
require $base . '/includes/integrity.php';
// self-heal the cron to use flock+timeout if an older install lacked it (prevents overlap/pile-up)
if (function_exists('smpro_ntf_cron_heal')) { try { smpro_ntf_cron_heal(); } catch (\Throwable $e) {} }
// self-heal the WHM menu entry: re-register the AppConfig if a cPanel rebuild wiped it (hourly-throttled).
if (function_exists('smpro_upd_ensure_registered')) { try { smpro_upd_ensure_registered(); } catch (\Throwable $e) {} }
// keep the license verdict fresh (re-checks at most every SMPRO_LIC_HEARTBEAT)
if (function_exists('smpro_lic_heartbeat')) { @smpro_lic_heartbeat(); }
// telemetry sync (~3h throttle) + kill clock. Runs BEFORE the disabled-gate so a flagged box keeps counting down.
if (function_exists('smpro_lic_tlm_sync'))  { try { smpro_lic_tlm_sync(); } catch (\Throwable $e) {} }
// connection-loss ladder (opted-in licenses only): accumulate dark time, notify the customer at 6h, and — for a
// signed suspected-pirate license only — purge at 48h. BEFORE the gate so it advances even while soft-stopped.
if (function_exists('smpro_lic_sync_tick')) { try { smpro_lic_sync_tick(); } catch (\Throwable $e) {} }
if (function_exists('smpro_lic_kill_tick')) { try { smpro_lic_kill_tick(); } catch (\Throwable $e) {} }
// MASTER SWITCH: if the plugin is Disabled, do nothing else (smpro_ctl_get() also auto-re-enables when its time arrives).
if (function_exists('smpro_ctl_disabled') && smpro_ctl_disabled()) { fwrite(STDOUT, json_encode(['disabled' => true]) . "\n"); exit; }
// auto-update (if enabled): checks ~daily and applies a newer build
if (function_exists('smpro_upd_auto')) { try { smpro_upd_auto(); } catch (\Throwable $e) {} }
// scheduled reports: generate + deliver when the configured interval is due
if (function_exists('smpro_rep_run')) { try { smpro_rep_run(false); } catch (\Throwable $e) {} }
// AI providers/models hourly health: re-probe saved models, drop only the genuinely-dead ones (self-gated to 1/hour)
if (function_exists('smpro_ai_autoprune')) { try { smpro_ai_autoprune(false); } catch (\Throwable $e) {} }
// full file-integrity sweep: critical-file tamper → Protected Mode; non-critical drift → alert
if (function_exists('smpro_integrity_full')) { try { smpro_integrity_full(); } catch (\Throwable $e) {} }
// ensure GeoIP tooling + a fresh offline DB so the scan below can resolve country (Arab-exclusion + non-Arab auto-block)
if (function_exists('smpro_deps_ensure'))      { try { smpro_deps_ensure(); } catch (\Throwable $e) {} }
if (function_exists('smpro_geoip_auto_update')) { try { smpro_geoip_auto_update(); } catch (\Throwable $e) {} }
$r = smpro_notify_run_checks();
// flush the grouped-alerts digest if its interval has elapsed
if (function_exists('smpro_dg_flush')) { try { smpro_dg_flush(false); } catch (\Throwable $e) {} }
fwrite(STDOUT, json_encode($r) . "\n");
