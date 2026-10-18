<?php
/**
 * bin/svcmon.php — background worker for the SERVICE MONITOR. Installed as /etc/cron.d/smpro-svcmon ONLY while
 * monitoring is enabled with at least one watched service. Refreshes the service-scan snapshot and, for each
 * watched service that is down, auto-restarts it (rate-limited) and/or notifies through the configured channels.
 */
define('SMPRO_BOOT', 1);
$base = dirname(__DIR__);
foreach (['defines', 'helpers', 'secret', 'license', 'notify', 'svcmon'] as $m) { $f = $base . '/includes/' . $m . '.php'; if (is_file($f)) require $f; }
// GLOBAL GATE: admin-disabled / tamper-lock / license-dormant => do nothing (parity with the other workers).
if (function_exists('smpro_ctl_disabled') && smpro_ctl_disabled()) exit;
if (function_exists('smpro_ctl_dry_run') && smpro_ctl_dry_run()) exit;   // global Dry-Run: this worker only acts, so it stays home
@ignore_user_abort(true); @set_time_limit(115);
if (function_exists('smpro_svcmon_run')) { try { smpro_svcmon_run(); } catch (\Throwable $e) { if (function_exists('smpro_worker_fatal')) smpro_worker_fatal(__FILE__, $e); else @error_log('smpro worker fatal in ' . basename(__FILE__) . ': ' . $e->getMessage()); } }
