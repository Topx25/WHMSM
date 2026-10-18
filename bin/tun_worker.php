<?php
/**
 * bin/tun_worker.php — background worker for Server Tune-up long jobs (AI optimization / Security Advisor).
 * Spawned detached by smpro_tun_job_start(); runs the scan and writes the result + timestamp to the job
 * state file so the result survives the user closing the page. Usage: php tun_worker.php <job> <base64-json-args>
 */
define('SMPRO_BOOT', 1);
$base = dirname(__DIR__);
require $base . '/includes/defines.php';
require $base . '/includes/helpers.php';
require $base . '/includes/secret.php';
require $base . '/includes/license.php';
require $base . '/includes/ai.php';        // pulls ai_catalog.php (require_once); smpro_ai_available/generate
require $base . '/includes/tuning.php';

$job  = preg_replace('/[^a-z]/', '', (string)($argv[1] ?? ''));
$args = isset($argv[2]) ? json_decode(base64_decode((string)$argv[2]), true) : [];
if ($job === '' || !function_exists('smpro_tun_job_run')) exit(1);
@ignore_user_abort(true);
@set_time_limit(180);
smpro_tun_job_run($job, is_array($args) ? $args : []);
