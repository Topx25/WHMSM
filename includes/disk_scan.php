<?php
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }
/**
 * disk_scan.php — per-account disk-cleanup scan, run as a BACKGROUND job.
 *
 * Standing rule: an action the admin starts must finish even if the page is closed, and the result must be
 * waiting when they come back. The only thing that stops it is the admin explicitly cancelling. The scan used
 * to run inline in the page request (the UI even claimed "runs in the background"), so closing the tab killed
 * it and threw the work away. It now runs in a detached worker (bin/cleanscan.php) that persists its result.
 *
 * These scan helpers live in includes/ (not the module) so the detached worker can load them without
 * executing the page.
 */

function smpro_ds_wrap($c, $t = 110) { return 'timeout ' . $t . ' nice -n ' . SMPRO_SCAN_NICE . ' ionice -c3 ' . $c; }
function smpro_ds_humb($b) { if ($b >= 1073741824) return round($b/1073741824,2).' GB'; if ($b >= 1048576) return round($b/1048576,1).' MB'; if ($b >= 1024) return round($b/1024,1).' KB'; return (int)$b.' B'; }

/** Per-account disk cleanup scan: large files, archives/backups, cache dirs, big logs. */
function smpro_ds_cleanscan($acct) {
    if ($acct === '' || !preg_match('/^[a-zA-Z0-9._-]+$/', $acct) || !is_dir(smpro_user_home($acct))) return ['err'=>'Invalid account.'];
    $home = smpro_user_home($acct);
    // NEVER offer to delete mail, sessions or the off-site backup dir
    $excl = " -not -path '*/.snapshots/*' -not -ipath '*/mail/*' -not -path '/home/backup/*' -not -ipath '*/.trash/*'";
    $out = ['large'=>[], 'arch'=>[], 'logs'=>[], 'cache'=>[], 'mail'=>0];
    // large files (>40MB) — mail excluded (deleting customer mail = data loss)
    foreach (explode("\n", (string)@shell_exec(smpro_ds_wrap("find " . escapeshellarg($home) . " -type f -size +40M" . $excl . " -printf '%s\\t%TY-%Tm-%Td\\t%p\\n' 2>/dev/null | sort -rn | head -40"))) as $l) {
        if (trim($l)==='') continue; $p = explode("\t",$l,3); if (count($p)<3) continue; $out['large'][] = ['size'=>(int)$p[0],'mtime'=>$p[1],'file'=>$p[2]];
    }
    // mail storage size (info only — managed via webmail/account, never bulk-deleted here)
    if (is_dir($home . '/mail')) $out['mail'] = (int)trim((string)@shell_exec(smpro_ds_wrap('du -sb ' . escapeshellarg($home . '/mail') . " 2>/dev/null | cut -f1", 50)));
    // archives / DB dumps / backups (>5MB)
    foreach (explode("\n", (string)@shell_exec(smpro_ds_wrap("find " . escapeshellarg($home) . " -type f \\( -iname '*.zip' -o -iname '*.tar' -o -iname '*.tar.gz' -o -iname '*.tgz' -o -iname '*.gz' -o -iname '*.sql' -o -iname '*.bak' -o -iname '*.old' -o -iname '*.7z' -o -iname '*.rar' \\) -size +5M" . $excl . " -printf '%s\\t%TY-%Tm-%Td\\t%p\\n' 2>/dev/null | sort -rn | head -40"))) as $l) {
        if (trim($l)==='') continue; $p = explode("\t",$l,3); if (count($p)<3) continue; $out['arch'][] = ['size'=>(int)$p[0],'mtime'=>$p[1],'file'=>$p[2]];
    }
    // big logs (>10MB)
    foreach (explode("\n", (string)@shell_exec(smpro_ds_wrap("find " . escapeshellarg($home) . " -type f \\( -iname '*.log' -o -iname 'error_log' -o -iname 'access-*.log' \\) -size +10M" . $excl . " -printf '%s\\t%TY-%Tm-%Td\\t%p\\n' 2>/dev/null | sort -rn | head -30"))) as $l) {
        if (trim($l)==='') continue; $p = explode("\t",$l,3); if (count($p)<3) continue; $out['logs'][] = ['size'=>(int)$p[0],'mtime'=>$p[1],'file'=>$p[2]];
    }
    // cache directories (safe to clear)
    foreach (['public_html/wp-content/cache','public_html/storage/framework/cache','public_html/storage/framework/views','public_html/bootstrap/cache','public_html/cache','.cache','tmp','public_html/wp-content/cache/wp-rocket'] as $cd) {
        $p = $home . '/' . $cd; if (!is_dir($p)) continue;
        $sz = (int)trim((string)@shell_exec(smpro_ds_wrap('du -sb ' . escapeshellarg($p) . " 2>/dev/null | cut -f1", 40)));
        if ($sz > 1048576) $out['cache'][] = ['dir'=>$p,'size'=>$sz];
    }
    usort($out['cache'], fn($a,$b)=>$b['size']<=>$a['size']);
    return $out;
}

/* ---------------- background job storage ---------------- */
function smpro_ds_scan_dir(): string { $d = SMPRO_VARLIB . '/cleanscan'; @is_dir($d) || @mkdir($d, 0700, true); return $d; }
function smpro_ds_scan_safe_acct($a): string { return preg_replace('/[^a-zA-Z0-9._-]/', '', (string)$a); }
function smpro_ds_scan_job_path($acct): string { return smpro_ds_scan_dir() . '/' . smpro_ds_scan_safe_acct($acct) . '.json'; }
function smpro_ds_scan_read($acct): array { $j = smpro_mnt_jread(smpro_ds_scan_job_path($acct)); return is_array($j) ? $j : []; }
function smpro_ds_scan_write($acct, array $j): void { $j['updated_at'] = time(); smpro_mnt_jwrite(smpro_ds_scan_job_path($acct), $j); }

/** Every account that currently has a scan on file (running or finished) — used to restore the panel on return. */
function smpro_ds_scan_all(): array {
    $rows = [];
    foreach (glob(smpro_ds_scan_dir() . '/*.json') ?: [] as $f) {
        $j = smpro_mnt_jread($f);
        if (!is_array($j) || empty($j['account'])) continue;
        $rows[] = ['account' => (string)$j['account'], 'phase' => (string)($j['phase'] ?? ''), 'done' => !empty($j['done']),
                   'started_at' => (int)($j['started_at'] ?? 0), 'finished_at' => (int)($j['finished_at'] ?? 0),
                   'stale' => empty($j['done']) && (time() - (int)($j['heartbeat'] ?? 0)) > 900];
    }
    usort($rows, fn($a, $b) => ($b['started_at'] <=> $a['started_at']));
    return $rows;
}

/** Launch the detached scan worker for one account. Survives the page closing. */
function smpro_ds_scan_launch($acct): array {
    $acct = smpro_ds_scan_safe_acct($acct);
    if ($acct === '' || !is_dir(smpro_user_home($acct))) return ['ok' => false, 'msg' => 'Invalid account.'];
    $cur = smpro_ds_scan_read($acct);
    if (!empty($cur) && empty($cur['done']) && (time() - (int)($cur['heartbeat'] ?? 0)) < 900) {
        return ['ok' => true, 'msg' => 'A scan for this account is already running.', 'already' => 1];
    }
    $worker = (defined('SMPRO_BASE') ? SMPRO_BASE : dirname(__DIR__)) . '/bin/cleanscan.php';
    if (!@is_file($worker)) return ['ok' => false, 'msg' => 'Scan worker not found (bin/cleanscan.php).'];
    $php = function_exists('smpro_ds_home_php_bin') ? smpro_ds_home_php_bin() : (is_executable('/usr/local/cpanel/3rdparty/bin/php') ? '/usr/local/cpanel/3rdparty/bin/php' : 'php');
    $hasSetsid = trim((string)@shell_exec('command -v setsid 2>/dev/null')) !== '';
    smpro_ds_scan_write($acct, ['account' => $acct, 'phase' => 'queued', 'done' => false, 'cancelled' => false,
        'msg' => 'Starting the scan…', 'started_at' => time(), 'heartbeat' => 0]);
    $cmd = ($hasSetsid ? 'setsid ' : 'nohup ') . escapeshellarg($php) . ' ' . escapeshellarg($worker)
         . ' ' . escapeshellarg('--user=' . $acct) . ' >/dev/null 2>&1 </dev/null &';
    @shell_exec('PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin ' . $cmd);
    for ($i = 0; $i < 20; $i++) {
        usleep(400000);
        $j = smpro_ds_scan_read($acct);
        if (!empty($j['heartbeat']) || !empty($j['done'])) return ['ok' => true, 'msg' => 'Scan started.'];
    }
    return ['ok' => false, 'msg' => 'The scan worker did not start. Check that PHP CLI is available.'];
}

/** Explicit admin cancel — the ONLY thing that stops a started scan. */
function smpro_ds_scan_cancel($acct): array {
    $acct = smpro_ds_scan_safe_acct($acct);
    $j = smpro_ds_scan_read($acct);
    if (!$j) return ['ok' => false, 'msg' => 'No scan to cancel.'];
    $j['cancelled'] = true; $j['done'] = true; $j['phase'] = 'cancelled';
    $j['msg'] = 'Cancelled by the administrator.'; $j['finished_at'] = time();
    smpro_ds_scan_write($acct, $j);
    if (function_exists('smpro_audit')) smpro_audit('disk_cleanscan_cancel', ['account' => $acct]);
    return ['ok' => true, 'msg' => 'Scan cancelled.'];
}
function smpro_ds_scan_forget($acct): array {
    @unlink(smpro_ds_scan_job_path($acct));
    return ['ok' => true, 'msg' => 'Report cleared.'];
}
