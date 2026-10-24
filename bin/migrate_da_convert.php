<?php
/**
 * bin/migrate_da_convert.php - detached worker: DirectAdmin archive -> cpmove archive.
 *
 * The whole pipeline in one job, because every stage of it is measured in minutes on a real backup and none of
 * it belongs in a page request. It refuses before it starts if the disk cannot hold the result, writes progress
 * as it goes, and leaves a cpmove archive for cPanel's own restore to take from there.
 *
 * Usage: migrate_da_convert.php --archive=/path/to/user.admin.name.tar.gz [--work=/path]
 */
define('SMPRO_BOOT', 1);   // MUST precede the requires - every include exits('forbidden') without it

$base = dirname(__DIR__);
require $base . '/includes/defines.php';
require $base . '/includes/env.php';
require $base . '/includes/helpers.php';
require $base . '/includes/migrate_da.php';
require $base . '/includes/migrate_da_convert.php';
require $base . '/includes/migrate_da_home.php';

define('SMPRO_MIG_CONV_JOB', SMPRO_VARLIB . '/migrate_da_convert.json');

$archive = ''; $work = '';
foreach ($argv as $a) {
    if (strpos($a, '--archive=') === 0) $archive = substr($a, 10);
    if (strpos($a, '--work=') === 0)    $work    = substr($a, 7);
}
if ($archive === '') { fwrite(STDERR, "--archive is required\n"); exit(2); }
if ($work === '')    $work = SMPRO_VARLIB . '/migrate_work/' . substr(sha1($archive), 0, 12);

$JOB = ['done' => false, 'ok' => false, 'archive' => $archive, 'phase' => 'starting',
        'steps' => [], 'warnings' => [], 'started' => time(), 'heartbeat' => time()];
function jsave() { global $JOB; $JOB['heartbeat'] = time();
    $t = SMPRO_MIG_CONV_JOB . '.tmp';
    if (@file_put_contents($t, json_encode($JOB, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)) !== false) { @chmod($t, 0600); @rename($t, SMPRO_MIG_CONV_JOB); } }
function jstep($m) { global $JOB; $JOB['steps'][] = ['t' => date('H:i:s'), 'msg' => $m]; $JOB['phase'] = $m; jsave(); }
function jfail($m) { global $JOB; $JOB['done'] = true; $JOB['ok'] = false; $JOB['error'] = $m; $JOB['finished'] = time(); jsave(); exit(1); }

$lockDir = SMPRO_VARLIB . '/locks';
if (!is_dir($lockDir)) @mkdir($lockDir, 0700, true);
$lock = @fopen($lockDir . '/migrate_da_convert.lock', 'c');
if (!$lock || !@flock($lock, LOCK_EX | LOCK_NB)) jfail('Another conversion is already running. Wait for it to finish.');

jsave();

/* 1. Refuse before touching anything if the result cannot fit. */
jstep('Checking there is room to do this');
$sp = smpro_mig_da_space_check($archive, dirname($work));
if (empty($sp['ok'])) jfail($sp['why']);

/* 2. Identify it - a converter pointed at the wrong format must stop, not improvise. */
jstep('Identifying the archive');
$det = smpro_mig_detect($archive);
if ($det['format'] !== 'directadmin') jfail($det['why']);

/* 2b. A backup handed over by a departing customer is untrusted input. */
jstep('Checking the archive cannot write outside its own folder');
$pc = smpro_mig_da_path_check($archive);
if (empty($pc['ok'])) jfail($pc['why']);

/* 3. Metadata out, then translated. */
jstep('Reading the account definition');
$x = smpro_mig_da_extract_meta($archive, $work, 3600);
if (empty($x['ok'])) jfail($x['error']);

jstep('Translating settings, DNS, certificates and database grants');
$conv = smpro_mig_da_build_meta($work, $work . '/out');
if (empty($conv['ok'])) jfail($conv['error']);
$JOB['user'] = $conv['user']; $JOB['main_domain'] = $conv['main_domain'];
$JOB['warnings'] = array_merge($JOB['warnings'], $conv['warnings']);
jsave();

/* 4. The content. */
$home = smpro_mig_da_build_home($archive, $conv['dest'], $conv['user'], $conv['main_domain'], 'jstep');
if (empty($home['ok'])) jfail($home['error']);
$JOB['warnings'] = array_merge($JOB['warnings'], $home['warnings']);
$JOB['sites'] = $home['sites']; $JOB['mailboxes'] = $home['mailboxes']; $JOB['databases'] = $home['databases'];
jsave();

/* 5. Package it for cPanel's restore. */
jstep('Packaging it for cPanel to restore');
$pack = smpro_mig_da_pack($conv['dest']);
if (empty($pack['ok'])) jfail($pack['error']);

// The converted tree is large and its contents are now inside the archive; leaving both doubles the footprint.
smpro_run('rm -rf ' . escapeshellarg($conv['dest']), 1800, ['stderr' => 'discard']);

$JOB['done'] = true; $JOB['ok'] = true;
$JOB['cpmove'] = $pack['archive'];
$JOB['bytes']  = $pack['bytes'];
$JOB['finished'] = time();
$JOB['seconds']  = time() - $JOB['started'];
$JOB['phase'] = 'ready to restore';
$JOB['msg'] = 'Converted in ' . $JOB['seconds'] . 's. Nothing has been restored yet — the account is packaged and '
            . 'waiting, so you can review the notes below before letting cPanel put it on this server.';
jsave();

if (function_exists('smpro_audit')) {
    smpro_audit('migrate_da_convert', ['archive' => $archive, 'user' => $conv['user'],
        'cpmove' => $pack['archive'], 'seconds' => $JOB['seconds'], 'warnings' => count($JOB['warnings'])]);
}
exit(0);
