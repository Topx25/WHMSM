<?php
/**
 * Safety Monitor Pro - stuck scheduled jobs.
 *
 * A load average that stays high while the processors sit idle is usually not work - it is a queue. The most
 * common source on a shared server is a site's own scheduled job that never finishes: each run adds a process,
 * nothing ever removes one, and where per-account CPU is capped (CloudLinux LVE) they pile up runnable but
 * throttled. Load counts a process waiting for its turn exactly like one doing work, so the number climbs while
 * the machine has nothing to do. Measured on a live server: 282 such processes across five accounts, some more
 * than ten days old, load ~60 on 96 cores with 78-90% of the processors idle.
 *
 * WordPress is the usual source because it is the common case, not the only one - anything scheduled that can
 * outlive its interval behaves the same way, so the scan is by AGE and OWNERSHIP first and by name second.
 *
 * Three things keep it happening, and all three are visible from here:
 *   1. the same script scheduled twice at different intervals, so the runs interleave;
 *   2. no lock and no time limit, so a slow run is joined by the next one instead of being skipped;
 *   3. WordPress's own web-triggered cron left enabled alongside the real one, so visitors start it too.
 *
 * Everything in this file READS. Nothing here kills a process or edits a schedule.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

/** Scripts that are scheduled work rather than a request being served. */
function smpro_cc_job_patterns(): array {
    return ['wp-cron.php', 'cron.php', 'artisan schedule:run', 'cron.sh', 'scheduled-tasks.php', 'cronjob.php'];
}

/** Which scheduled script a command line is running, or '' when it is not one. */
function smpro_cc_job_name(string $args): string {
    foreach (smpro_cc_job_patterns() as $p) if (stripos($args, $p) !== false) return $p;
    return '';
}

/**
 * Account-owned scheduled jobs still running after $minMinutes.
 * Returns ['ok','total','oldest_min','accounts'=>[user=>['n','oldest_min','script','pids'=>[[pid,min]]]]].
 * A job older than its own schedule can never be healthy - by then the next run has already started.
 */
function smpro_cc_stuck(int $minMinutes = 60): array {
    // Its OWN ps, not the shared top-N list. That list is ordered by CPU and truncated, and a job stuck behind a
    // per-account CPU cap uses almost none - exactly the processes this looks for are the ones a "top consumers"
    // view drops. Under-counting here would understate the problem while looking like an answer.
    $pat = implode('|', array_map(fn($p) => preg_quote($p, '/'), smpro_cc_job_patterns()));
    $raw = smpro_run("ps -eo user:32=,pid=,etimes=,args= 2>/dev/null | grep -Ei "
        . escapeshellarg($pat) . " | grep -v grep", 25, ['stderr' => 'discard']);
    if (trim($raw) === '') {
        return ['ok' => true, 'total' => 0, 'oldest_min' => 0, 'accounts' => [], 'scanned' => 0, 'why' => ''];
    }
    $out = []; $total = 0; $oldest = 0; $scanned = 0;
    foreach (preg_split('/
?
/', $raw) as $line) {
        $line = trim($line); if ($line === '') continue;
        $p = preg_split('/\s+/', $line, 4);
        if (!$p || count($p) < 4) continue;
        $scanned++;
        $user = $p[0]; $pid = (int)$p[1]; $secs = (int)$p[2]; $args = (string)$p[3];
        if (!function_exists('smpro_is_cpanel_user') || !smpro_is_cpanel_user($user)) continue;   // customers only
        $job = smpro_cc_job_name($args); if ($job === '') continue;
        $min = (int)floor($secs / 60);
        if ($min < $minMinutes) continue;
        if (!isset($out[$user])) $out[$user] = ['n' => 0, 'oldest_min' => 0, 'script' => $job, 'pids' => []];
        $out[$user]['n']++;
        $out[$user]['pids'][] = ['pid' => $pid, 'min' => $min];
        if ($min > $out[$user]['oldest_min']) $out[$user]['oldest_min'] = $min;
        if ($min > $oldest) $oldest = $min;
        $total++;
    }
    uasort($out, fn($a, $b) => $b['n'] <=> $a['n']);
    foreach ($out as &$_a) { usort($_a['pids'], fn($x, $y) => $y['min'] <=> $x['min']); }
    unset($_a);
    return ['ok' => true, 'total' => $total, 'oldest_min' => $oldest, 'accounts' => $out,
            'scanned' => $scanned, 'why' => ''];
}

/** An account's crontab lines (comments and blanks dropped). */
function smpro_cc_crontab(string $user): array {
    if (!preg_match('/^[a-z0-9][a-z0-9_-]{0,31}$/i', $user)) return [];
    $raw = smpro_run('crontab -l -u ' . escapeshellarg($user), 15, ['stderr' => 'discard']);
    $out = [];
    foreach (explode("\n", $raw) as $l) {
        $l = rtrim($l);
        if (trim($l) === '' || ltrim($l)[0] === '#') continue;
        $out[] = $l;
    }
    return $out;
}

/**
 * Entries in one crontab that run the SAME script.
 * Two schedules for one job is the quiet half of this problem: each looks reasonable alone, and together they
 * guarantee overlap. Returns [script => [lines...]] for scripts scheduled more than once.
 */
function smpro_cc_duplicates(string $user): array {
    $byScript = [];
    foreach (smpro_cc_crontab($user) as $line) {
        $job = smpro_cc_job_name($line);
        if ($job === '') continue;
        // Resolve to the actual FILE, because the same job is almost never written the same way twice. The real
        // pair this was built from was "cd /home/u/public_html; php -q wp-cron.php" alongside
        // "php /home/u/public_html/wp-cron.php" - one relative, one absolute, the same file, and grouping on the
        // text alone reported no duplication for the very case that caused the pile-up.
        if (preg_match('#(/[^\s;&|]*' . preg_quote($job, '#') . ')#i', $line, $m)) {
            $path = $m[1];
        } elseif (preg_match('#\bcd\s+(/[^\s;&|]+)#i', $line, $m)) {
            $path = rtrim($m[1], '/') . '/' . $job;          // relative script, resolved against the cd target
        } else {
            $path = $job;
        }
        $byScript[$path][] = trim($line);
    }
    return array_filter($byScript, fn($v) => count($v) > 1);
}

/** Whether a crontab line already protects itself with a lock and a time limit. */
function smpro_cc_line_guarded(string $line): array {
    return ['lock' => (stripos($line, 'flock') !== false),
            'limit' => (stripos($line, 'timeout ') !== false)];
}

/**
 * Is WordPress's web-triggered cron switched off for this docroot?
 * Returns true (off, correct when a real schedule exists), false (on), or null (no wp-config.php to read).
 * Left on alongside a real cron entry, every visitor can start another run.
 */
function smpro_cc_wp_cron_disabled(string $docroot) {
    $f = rtrim($docroot, '/') . '/wp-config.php';
    if (!@is_file($f) || !@is_readable($f)) return null;
    $s = (string)@file_get_contents($f, false, null, 0, 262144);
    if ($s === '') return null;
    if (preg_match("/define\s*\(\s*['\"]DISABLE_WP_CRON['\"]\s*,\s*(true|1)\s*\)/i", $s)) return true;
    return false;
}

/** The schedule this job should have: one entry, locked, and unable to outlive its own interval. */
function smpro_cc_recommend(string $user, string $script, int $everyMin = 10, int $maxSecs = 300): string {
    $lock = '/var/lock/smpro-cron-' . preg_replace('/[^a-z0-9]/i', '', $user) . '.lock';
    $php  = function_exists('smpro_php_cli_bin') ? smpro_php_cli_bin() : '/usr/local/bin/php';
    return '*/' . max(1, $everyMin) . ' * * * * flock -n ' . $lock
         . ' timeout ' . max(30, $maxSecs) . ' ' . $php . ' ' . $script;
}

/**
 * The whole picture for one account: how many of its jobs are stuck, whether it schedules the same one twice,
 * whether the entries protect themselves, and whether WordPress is also starting the job from the web.
 */
function smpro_cc_account_report(string $user, array $stuckEntry = []): array {
    $lines = smpro_cc_crontab($user);
    $jobLines = [];
    foreach ($lines as $l) if (smpro_cc_job_name($l) !== '') $jobLines[] = $l;
    $unguarded = [];
    foreach ($jobLines as $l) {
        $g = smpro_cc_line_guarded($l);
        if (!$g['lock'] || !$g['limit']) $unguarded[] = ['line' => $l] + $g;
    }
    $docroot = smpro_user_home($user) . '/public_html';
    $wpOff   = smpro_cc_wp_cron_disabled($docroot);
    $script  = '';
    foreach ($jobLines as $l) {
        if (preg_match('#(/[^\s;&|]*wp-cron\.php)#i', $l, $m)) { $script = $m[1]; break; }
    }
    if ($script === '') $script = $docroot . '/wp-cron.php';
    return [
        'user'        => $user,
        'stuck'       => (int)($stuckEntry['n'] ?? 0),
        'oldest_min'  => (int)($stuckEntry['oldest_min'] ?? 0),
        'pids'        => (array)($stuckEntry['pids'] ?? []),
        'job_lines'   => $jobLines,
        'duplicates'  => smpro_cc_duplicates($user),
        'unguarded'   => $unguarded,
        'wp_cron_web' => ($wpOff === null ? null : !$wpOff),   // true = visitors can also start it
        'recommend'   => smpro_cc_recommend($user, $script),
    ];
}
