<?php
/**
 * bin/fw_allow_sync.php - background worker for the firewall allow-list AUTO-UPDATE. Installed as
 * /etc/cron.d/smpro-fwallow ONLY while at least one provider has auto-update enabled. For each such provider it
 * fetches the current IP ranges from the provider feed and reconciles csf.allow (adds new, drops our-tagged stale).
 */
define('SMPRO_BOOT', 1);
$base = dirname(__DIR__);
foreach (['defines', 'helpers', 'secret', 'license', 'fwallow'] as $m) { $f = $base . '/includes/' . $m . '.php'; if (is_file($f)) require $f; }
// GLOBAL GATE: admin-disabled / tamper-lock / license-dormant => do nothing (parity with the other workers).
if (function_exists('smpro_ctl_disabled') && smpro_ctl_disabled()) exit;
if (function_exists('smpro_ctl_dry_run') && smpro_ctl_dry_run()) exit;   // global Dry-Run: this worker only acts, so it stays home
@ignore_user_abort(true); @set_time_limit(280);
if (function_exists('smpro_fw_allow_autoupdate_run')) { try { smpro_fw_allow_autoupdate_run(); } catch (\Throwable $e) { if (function_exists('smpro_worker_fatal')) smpro_worker_fatal(__FILE__, $e); else @error_log('smpro worker fatal in ' . basename(__FILE__) . ': ' . $e->getMessage()); } }
// Deployment-provider ranges (GitHub Actions, Bitbucket Pipelines) ride along: classification only, never allow-listed.
if (function_exists('smpro_fw_deploy_refresh_hook')) { @smpro_fw_deploy_refresh_hook(); }
