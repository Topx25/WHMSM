<?php
/**
 * Safety Monitor Pro - repairing a schedule that keeps producing stuck jobs.
 *
 * Separate from croncheck.php on purpose: that file only reads. This one WRITES to a customer's crontab, which
 * is one of the few places where a mistake is both silent and expensive - a schedule that stops running takes
 * days to be noticed, and by then whatever it was doing has quietly not happened.
 *
 * So every change here:
 *   • copies the whole crontab first, and refuses to continue if that copy cannot be verified afterwards;
 *   • touches ONLY the entries that run the one script it was asked about, and leaves every other line -
 *     comments, blank lines, unrelated jobs, MAILTO and PATH - exactly as it found them;
 *   • reads the result back and compares it against what it meant to write, rather than trusting the write;
 *   • puts the account back the way it was if that comparison fails;
 *   • can be undone from the copy at any time.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

/** Where the copies live. Dated per task, so what was changed and when is readable from the filenames alone. */
function smpro_ccf_backup_dir(string $user): string {
    return SMPRO_VARLIB . '/cron_backups/' . preg_replace('/[^a-z0-9_-]/i', '', $user);
}

/** Every line of a crontab, comments and blanks included - this is what gets restored, so nothing may be dropped. */
function smpro_ccf_read_raw(string $user): array {
    if (!preg_match('/^[a-z0-9][a-z0-9_-]{0,31}$/i', $user)) return ['ok' => false, 'lines' => [], 'error' => 'Not a valid account name.'];
    [$rc, $out] = smpro_run_rc('crontab -l -u ' . escapeshellarg($user), 15, ['stderr' => 'discard']);
    if ($rc !== 0 && trim($out) === '') return ['ok' => false, 'lines' => [], 'error' => 'That account has no crontab, or it could not be read.'];
    return ['ok' => true, 'lines' => explode("\n", rtrim($out, "\n")), 'error' => ''];
}

/** Copy the crontab before changing it. Returns the path, or '' when the copy could not be made AND verified. */
function smpro_ccf_backup(string $user, string $task): string {
    $r = smpro_ccf_read_raw($user);
    if (empty($r['ok'])) return '';
    $dir = smpro_ccf_backup_dir($user);
    if (!is_dir($dir) && !@mkdir($dir, 0700, true)) return '';
    $path = $dir . '/' . date('Ymd_His') . '_' . preg_replace('/[^a-z0-9_-]/i', '', $task) . '.cron';
    $body = implode("\n", $r['lines']) . "\n";
    if (@file_put_contents($path, $body) === false) return '';
    @chmod($path, 0600);
    // Verified, not assumed: a copy that was not actually written is the same as no copy at all, and finding
    // that out during a restore is finding out too late.
    clearstatcache();
    if (!is_file($path) || (string)@file_get_contents($path) !== $body) { @unlink($path); return ''; }
    return $path;
}

/** Install a set of lines as the account's crontab. Returns [ok, error]. */
function smpro_ccf_write(string $user, array $lines): array {
    if (!preg_match('/^[a-z0-9][a-z0-9_-]{0,31}$/i', $user)) return ['ok' => false, 'error' => 'Not a valid account name.'];
    $tmp = SMPRO_VARLIB . '/cron_backups/.write_' . getmypid() . '.tmp';
    if (!is_dir(dirname($tmp))) @mkdir(dirname($tmp), 0700, true);
    if (@file_put_contents($tmp, implode("\n", $lines) . "\n") === false) return ['ok' => false, 'error' => 'Could not stage the new schedule.'];
    @chmod($tmp, 0600);
    [$rc, $out] = smpro_run_rc('crontab -u ' . escapeshellarg($user) . ' ' . escapeshellarg($tmp), 20, ['stderr' => 'merge']);
    @unlink($tmp);
    if ($rc !== 0) return ['ok' => false, 'error' => 'cron refused the new schedule: ' . trim($out)];
    return ['ok' => true, 'error' => ''];
}

/**
 * Give one script a single, locked, time-limited entry.
 *
 * $script is the resolved path of the job to repair; every existing entry that runs THAT file is replaced by one
 * line, and nothing else in the crontab is touched. Returns what it did, what it kept, and where the copy is.
 */
function smpro_ccf_repair(string $user, string $script, int $everyMin = 10, int $maxSecs = 300, bool $dryRun = false): array {
    $r = smpro_ccf_read_raw($user);
    if (empty($r['ok'])) return ['ok' => false, 'error' => $r['error']];
    $lines = $r['lines'];

    $job = function_exists('smpro_cc_job_name') ? smpro_cc_job_name($script) : basename($script);
    if ($job === '') $job = basename($script);

    // Which lines run THIS file. Resolved the same way the detector resolves them, so a relative path written
    // after a cd is recognised as the same job as an absolute one - that pair is the usual cause of the problem
    // and matching on the text alone would leave one of the two behind.
    $targets = []; $kept = [];
    foreach ($lines as $i => $line) {
        $t = trim($line);
        if ($t === '' || $t[0] === '#') { $kept[$i] = $line; continue; }
        if ((function_exists('smpro_cc_job_name') ? smpro_cc_job_name($line) : '') === '') { $kept[$i] = $line; continue; }
        if (preg_match('#(/[^\s;&|]*' . preg_quote($job, '#') . ')#i', $line, $m))      $path = $m[1];
        elseif (preg_match('#\bcd\s+(/[^\s;&|]+)#i', $line, $m))                        $path = rtrim($m[1], '/') . '/' . $job;
        else                                                                            $path = $job;
        if ($path === $script) $targets[$i] = $line; else $kept[$i] = $line;
    }
    if (!$targets) return ['ok' => false, 'error' => 'No entry in that account runs ' . $script . ', so there is nothing to repair.'];

    $newLine = function_exists('smpro_cc_recommend')
        ? smpro_cc_recommend($user, $script, $everyMin, $maxSecs)
        : ('*/' . $everyMin . ' * * * * flock -n /var/lock/smpro-cron-' . $user . '.lock timeout ' . $maxSecs . ' /usr/local/bin/php ' . $script);

    // Rebuild in the original order: the first target position becomes the single new entry, the rest disappear.
    $first = array_key_first($targets);
    $out = [];
    foreach ($lines as $i => $line) {
        if ($i === $first) { $out[] = '# schedule repaired by ' . SMPRO_NAME . ' on ' . date('Y-m-d H:i') . ' — was ' . count($targets) . ' entr' . (count($targets) === 1 ? 'y' : 'ies'); $out[] = $newLine; continue; }
        if (isset($targets[$i])) continue;
        $out[] = $line;
    }

    if ($dryRun) {
        return ['ok' => true, 'dry_run' => true, 'replaced' => count($targets), 'removed' => $targets,
                'new_line' => $newLine, 'kept' => count($kept), 'preview' => $out, 'error' => ''];
    }

    $backup = smpro_ccf_backup($user, 'cron_repair');
    if ($backup === '') return ['ok' => false, 'error' => 'The account\'s schedule could not be copied, so nothing was changed.'];

    $w = smpro_ccf_write($user, $out);
    if (empty($w['ok'])) return ['ok' => false, 'error' => $w['error'], 'backup' => $backup];

    // Read it back. A write that reported success but did not land, or landed differently, is exactly the kind of
    // failure that is only discovered days later when the job has not been running.
    $after = smpro_ccf_read_raw($user);
    $ok = !empty($after['ok']) && in_array($newLine, $after['lines'], true);
    $stillDupe = 0;
    foreach (($after['lines'] ?? []) as $l) if (trim($l) !== '' && $l !== $newLine && stripos($l, $job) !== false) $stillDupe++;
    if (!$ok || $stillDupe > 0) {
        $restore = smpro_ccf_write($user, explode("\n", rtrim((string)@file_get_contents($backup), "\n")));
        return ['ok' => false, 'backup' => $backup,
                'error' => 'The new schedule did not read back as written, so the account was put back the way it was'
                         . (empty($restore['ok']) ? ' — AND THE RESTORE ALSO FAILED. Restore by hand from ' . $backup . '.' : '.')];
    }

    if (function_exists('smpro_audit')) smpro_audit('cron_repair', ['user' => $user, 'script' => $script,
        'replaced' => count($targets), 'backup' => $backup]);
    return ['ok' => true, 'replaced' => count($targets), 'removed' => array_values($targets),
            'new_line' => $newLine, 'backup' => $backup, 'error' => ''];
}

/** The copies taken for an account, newest first. */
function smpro_ccf_backups(string $user): array {
    $out = [];
    foreach (glob(smpro_ccf_backup_dir($user) . '/*.cron') ?: [] as $f) {
        $out[] = ['path' => $f, 'when' => (int)@filemtime($f), 'bytes' => (int)@filesize($f),
                  'lines' => count(array_filter(explode("\n", (string)@file_get_contents($f)), fn($l) => trim($l) !== ''))];
    }
    usort($out, fn($a, $b) => $b['when'] <=> $a['when']);
    return $out;
}

/** Put an account's schedule back from one of the copies. */
function smpro_ccf_undo(string $user, string $backupPath): array {
    $dir = smpro_ccf_backup_dir($user);
    $real = @realpath($backupPath);
    // Only ever restore from this account's own copies - a path from elsewhere would install someone else's
    // schedule under this account, which is worse than the problem being fixed.
    // Suffix compared by its own length, never a hand-written number - see the note on the same check in
    // wpcron_fix.php, where a wrong count silently refused every restore.
    $suffix = '.cron';
    $dirReal = @realpath($dir);
    if ($real === false || $dirReal === false || strpos($real, $dirReal . '/') !== 0
        || substr($real, -strlen($suffix)) !== $suffix) {
        return ['ok' => false, 'error' => 'That is not one of this account\'s saved schedules.'];
    }
    $body = (string)@file_get_contents($real);
    if (trim($body) === '') return ['ok' => false, 'error' => 'That saved schedule is empty; it is not being installed.'];
    $safety = smpro_ccf_backup($user, 'before_undo');
    $w = smpro_ccf_write($user, explode("\n", rtrim($body, "\n")));
    if (empty($w['ok'])) return ['ok' => false, 'error' => $w['error']];
    if (function_exists('smpro_audit')) smpro_audit('cron_undo', ['user' => $user, 'from' => $real, 'safety' => $safety]);
    return ['ok' => true, 'restored_from' => $real, 'safety_copy' => $safety, 'error' => ''];
}
