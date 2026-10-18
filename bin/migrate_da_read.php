<?php
/**
 * bin/migrate_da_read.php — detached worker that reads a DirectAdmin archive.
 *
 * Reading one is not a page-request job: tar is sequential, so describing a 9.7 GB archive meant decompressing
 * the whole stream — 183 seconds on the reference sample, for 36 MB of metadata. It runs here so the operator
 * can close the page and find the answer waiting, which is the rule for every started action in this plugin.
 *
 * Usage: migrate_da_read.php --archive=/path/to/user.admin.name.tar.gz
 */
define('SMPRO_BOOT', 1);   // MUST precede the requires — every include exits('forbidden') without it

$base = dirname(__DIR__);
require $base . '/includes/defines.php';
require $base . '/includes/env.php';
require $base . '/includes/helpers.php';
require $base . '/includes/migrate_da.php';

define('SMPRO_MIG_DA_JOB', SMPRO_VARLIB . '/migrate_da_job.json');

$archive = '';
foreach ($argv as $a) if (strpos($a, '--archive=') === 0) $archive = substr($a, 10);
if ($archive === '') { fwrite(STDERR, "--archive is required\n"); exit(2); }

function smpro_mig_da_job_write(array $j): void {
    $t = SMPRO_MIG_DA_JOB . '.tmp';
    if (@file_put_contents($t, json_encode($j, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)) === false) return;
    @chmod($t, 0600);
    @rename($t, SMPRO_MIG_DA_JOB);
}

// Single-flight: two readers on one archive would extract over each other's working directory.
$lockDir = SMPRO_VARLIB . '/locks';
if (!is_dir($lockDir)) @mkdir($lockDir, 0700, true);
$lock = @fopen($lockDir . '/migrate_da.lock', 'c');
if (!$lock || !@flock($lock, LOCK_EX | LOCK_NB)) {
    smpro_mig_da_job_write(['done' => true, 'ok' => false, 'archive' => $archive,
        'error' => 'Another archive is already being read. Wait for it to finish.', 'heartbeat' => time()]);
    exit(0);
}

$started = time();
smpro_mig_da_job_write(['done' => false, 'ok' => false, 'archive' => $archive, 'phase' => 'reading',
    'msg' => 'Reading the archive. On a large backup this takes a few minutes — the whole file has to be '
           . 'decompressed to reach the parts that describe the account.',
    'started' => $started, 'heartbeat' => $started]);

$r = smpro_mig_da_read($archive);
$r['done']      = true;
$r['archive']   = $archive;
$r['started']   = $started;
$r['finished']  = time();
$r['seconds']   = time() - $started;
$r['heartbeat'] = time();
if (empty($r['ok'])) $r['msg'] = 'The archive could not be read.';
else $r['msg'] = 'Read in ' . $r['seconds'] . 's. Nothing has been restored — this is a description only.';
smpro_mig_da_job_write($r);

if (function_exists('smpro_audit')) {
    smpro_audit('migrate_da_read', ['archive' => $archive, 'ok' => !empty($r['ok']), 'seconds' => $r['seconds']]);
}
exit(0);
