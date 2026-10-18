<?php
/**
 * includes/backupmon.php — the backup auto-retry cron, owned here so cron_sync can put it back after an update.
 * The page used to write /etc/cron.d directly (bypassing the shared installer and its test guard) and nothing
 * re-created it; the on/off state is now a flag file, and the cron line is derived from it.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }
if (!defined('SMPRO_BM_CRON'))   define('SMPRO_BM_CRON',   '/etc/cron.d/smpro-backup-retry');
if (!defined('SMPRO_BM_SCRIPT')) define('SMPRO_BM_SCRIPT', SMPRO_BASE . '/bin/backup_retry.php');
if (!defined('SMPRO_BM_FLAG'))   define('SMPRO_BM_FLAG',   SMPRO_VARLIB . '/backup_retry.enabled');

function smpro_bm_autoretry_on(): bool { return @is_file(SMPRO_BM_FLAG) || @is_file(SMPRO_BM_CRON); }   // the cron file counts for installs made before the flag existed

function smpro_bm_autoretry_set(bool $on): bool {
    if ($on) { @is_dir(SMPRO_VARLIB) || @mkdir(SMPRO_VARLIB, 0700, true); @file_put_contents(SMPRO_BM_FLAG, date('c') . "\n"); @chmod(SMPRO_BM_FLAG, 0600); }
    else @unlink(SMPRO_BM_FLAG);
    return smpro_bm_cron_sync();
}

/** cron_sync entry: present while on, absent while off. */
function smpro_bm_cron_sync(): bool {
    if (defined('SMPRO_TEST_SRC')) return true;   // a test never installs a live cron
    if (!smpro_bm_autoretry_on() || !@is_file(SMPRO_BM_FLAG)) { if (@is_file(SMPRO_BM_CRON) && !@is_file(SMPRO_BM_FLAG)) { /* legacy install without a flag: adopt it */ @touch(SMPRO_BM_FLAG); } else { if (@is_file(SMPRO_BM_CRON)) @unlink(SMPRO_BM_CRON); return true; } }
    $lockDir = defined('SMPRO_LOCKS') ? SMPRO_LOCKS : (SMPRO_VARLIB . '/locks'); @is_dir($lockDir) || @mkdir($lockDir, 0700, true);
    $script = realpath(SMPRO_BM_SCRIPT) ?: SMPRO_BM_SCRIPT;
    $php = function_exists('smpro_php_cli_bin') ? smpro_php_cli_bin() : '/usr/local/cpanel/3rdparty/bin/php';
    $flock = is_executable('/usr/bin/flock') ? '/usr/bin/flock' : 'flock';
    $cron = "# Safety Monitor Pro — auto-retry failed JetBackup jobs until they complete (bounded)\n"
          . "*/20 * * * * root $flock -n $lockDir/backup_retry.lock timeout 600 $php $script >/dev/null 2>&1\n";
    return function_exists('smpro_cron_install') ? smpro_cron_install(SMPRO_BM_CRON, $cron) : (@file_put_contents(SMPRO_BM_CRON, $cron) !== false && @chmod(SMPRO_BM_CRON, 0644));
}
