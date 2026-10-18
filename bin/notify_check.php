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
foreach (['fwallow', 'breakin'] as $m) { $f = $base . '/includes/' . $m . '.php'; if (is_file($f)) require_once $f; }   // the brute-force alert groups failed logins by network like the Break-in report
require $base . '/includes/analytics.php';   // smpro_ar_prewarm: keeps the Analytics counts warm across the day roll
// self-heal the cron to use flock+timeout if an older install lacked it (prevents overlap/pile-up)
if (function_exists('smpro_ntf_cron_heal')) { try { smpro_ntf_cron_heal(); } catch (\Throwable $e) { if (function_exists('smpro_worker_fatal')) smpro_worker_fatal(__FILE__, $e); else @error_log('smpro worker fatal in ' . basename(__FILE__) . ': ' . $e->getMessage()); } }
// self-heal the WHM menu entry: re-register the AppConfig if a cPanel rebuild wiped it (hourly-throttled).
if (function_exists('smpro_upd_ensure_registered')) { try { smpro_upd_ensure_registered(); } catch (\Throwable $e) { if (function_exists('smpro_worker_fatal')) smpro_worker_fatal(__FILE__, $e); else @error_log('smpro worker fatal in ' . basename(__FILE__) . ': ' . $e->getMessage()); } }
// Analytics counts: warm the default window so the page never pays the 4 s scan itself (new keys at midnight).
if (function_exists('smpro_ar_prewarm') && !(function_exists('smpro_ctl_disabled') && smpro_ctl_disabled())) { try { smpro_ar_prewarm(); } catch (\Throwable $e) { if (function_exists('smpro_soft_fail')) smpro_soft_fail('ar_prewarm', $e); } }
// predecessor-product crons (old Safety Monitor / Safety Lock) still installed: retire them, once an hour at most
if (function_exists('smpro_upd_retire_legacy_crons')) { $lcf = SMPRO_VARLIB . '/legacy_cron_check'; if (!@is_file($lcf) || time() - (int)@filemtime($lcf) > 3600) { @touch($lcf); try { smpro_upd_retire_legacy_crons(); } catch (\Throwable $e) { if (function_exists('smpro_soft_fail')) smpro_soft_fail('legacy_crons', $e); } } }
// keep the license verdict fresh (re-checks at most every SMPRO_LIC_HEARTBEAT)
if (function_exists('smpro_lic_heartbeat')) { @smpro_lic_heartbeat(); }
// telemetry sync (~3h throttle) + kill clock. Runs BEFORE the disabled-gate so a flagged box keeps counting down.
if (function_exists('smpro_lic_tlm_sync'))  { try { smpro_lic_tlm_sync(); } catch (\Throwable $e) { if (function_exists('smpro_worker_fatal')) smpro_worker_fatal(__FILE__, $e); else @error_log('smpro worker fatal in ' . basename(__FILE__) . ': ' . $e->getMessage()); } }
// connection-loss ladder (opted-in licenses only): accumulate dark time, notify the customer at 6h, and — for a
// signed suspected-pirate license only — purge at 48h. BEFORE the gate so it advances even while soft-stopped.
if (function_exists('smpro_lic_sync_tick')) { try { smpro_lic_sync_tick(); } catch (\Throwable $e) { if (function_exists('smpro_worker_fatal')) smpro_worker_fatal(__FILE__, $e); else @error_log('smpro worker fatal in ' . basename(__FILE__) . ': ' . $e->getMessage()); } }
if (function_exists('smpro_lic_kill_tick')) { try { smpro_lic_kill_tick(); } catch (\Throwable $e) { if (function_exists('smpro_worker_fatal')) smpro_worker_fatal(__FILE__, $e); else @error_log('smpro worker fatal in ' . basename(__FILE__) . ': ' . $e->getMessage()); } }
// MASTER SWITCH: if the plugin is Disabled, do nothing else (smpro_ctl_get() also auto-re-enables when its time arrives).
if (function_exists('smpro_ctl_disabled') && smpro_ctl_disabled()) { fwrite(STDOUT, json_encode(['disabled' => true]) . "\n"); exit; }
// auto-update (if enabled): checks ~daily and applies a newer build
if (function_exists('smpro_upd_auto')) { try { smpro_upd_auto(); } catch (\Throwable $e) { if (function_exists('smpro_worker_fatal')) smpro_worker_fatal(__FILE__, $e); else @error_log('smpro worker fatal in ' . basename(__FILE__) . ': ' . $e->getMessage()); } }
// scheduled reports: generate + deliver when the configured interval is due
if (function_exists('smpro_rep_run')) { try { smpro_rep_run(false); } catch (\Throwable $e) { if (function_exists('smpro_worker_fatal')) smpro_worker_fatal(__FILE__, $e); else @error_log('smpro worker fatal in ' . basename(__FILE__) . ': ' . $e->getMessage()); } }
// AI providers/models hourly health: re-probe saved models, drop only the genuinely-dead ones (self-gated to 1/hour)
if (function_exists('smpro_ai_autoprune')) { try { smpro_ai_autoprune(false); } catch (\Throwable $e) { if (function_exists('smpro_worker_fatal')) smpro_worker_fatal(__FILE__, $e); else @error_log('smpro worker fatal in ' . basename(__FILE__) . ': ' . $e->getMessage()); } }
// full file-integrity sweep: critical-file tamper → Protected Mode; non-critical drift → alert
if (function_exists('smpro_integrity_full')) { try { smpro_integrity_full(); } catch (\Throwable $e) { if (function_exists('smpro_worker_fatal')) smpro_worker_fatal(__FILE__, $e); else @error_log('smpro worker fatal in ' . basename(__FILE__) . ': ' . $e->getMessage()); } }
// ensure GeoIP tooling + a fresh offline DB so the scan below can resolve country (Arab-exclusion + non-Arab auto-block)
if (function_exists('smpro_deps_ensure'))      { try { smpro_deps_ensure(); } catch (\Throwable $e) { if (function_exists('smpro_worker_fatal')) smpro_worker_fatal(__FILE__, $e); else @error_log('smpro worker fatal in ' . basename(__FILE__) . ': ' . $e->getMessage()); } }
if (function_exists('smpro_geoip_auto_update')) { try { smpro_geoip_auto_update(); } catch (\Throwable $e) { if (function_exists('smpro_worker_fatal')) smpro_worker_fatal(__FILE__, $e); else @error_log('smpro worker fatal in ' . basename(__FILE__) . ': ' . $e->getMessage()); } }
$r = smpro_notify_run_checks();
// flush the grouped-alerts digest if its interval has elapsed
if (function_exists('smpro_dg_flush')) { try { smpro_dg_flush(false); } catch (\Throwable $e) { if (function_exists('smpro_worker_fatal')) smpro_worker_fatal(__FILE__, $e); else @error_log('smpro worker fatal in ' . basename(__FILE__) . ': ' . $e->getMessage()); } }
fwrite(STDOUT, json_encode($r) . "\n");
// weekly upkeep of the attack index (vacuum) - a worker's job, never a page's
if (function_exists('smpro_in_maintain')) { try { smpro_in_maintain(); } catch (\Throwable $e) { if (function_exists('smpro_soft_fail')) smpro_soft_fail('intrusion_vacuum', $e); } }
