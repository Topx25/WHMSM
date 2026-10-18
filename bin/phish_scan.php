<?php
/**
 * bin/phish_scan.php — detached background worker for the Spam & Phishing per-account phishing scan.
 * Launched by smpro_ps_start() with the account name as argv[1]; runs the scan and writes the result file,
 * so the scan finishes even if the admin closed the page. Root already (invoked from the root CGI).
 */
define('SMPRO_BOOT', 1);
$base = dirname(__DIR__);
foreach (['defines', 'helpers', 'secret', 'license', 'phishscan'] as $m) { $f = $base . '/includes/' . $m . '.php'; if (is_file($f)) require $f; }
if (function_exists('smpro_ctl_disabled') && smpro_ctl_disabled()) exit;   // global gate parity
@ignore_user_abort(true); @set_time_limit(320);
$acct = isset($argv[1]) ? (string)$argv[1] : '';
if ($acct !== '' && function_exists('smpro_ps_run')) { try { smpro_ps_run($acct); } catch (\Throwable $e) { if (function_exists('smpro_worker_fatal')) smpro_worker_fatal(__FILE__, $e); else @error_log('smpro worker fatal in ' . basename(__FILE__) . ': ' . $e->getMessage()); } }
