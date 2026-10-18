<?php
/**
 * bin/home_move_batch.php — supervises a MULTI-ACCOUNT home move.
 *
 * Keeps at most N account-moves running at once (N is capped by smpro_ds_home_capacity(), which is derived
 * from the server's cores, whether the target disk is spinning, and the load already on the box) so a bulk
 * move never saturates the disk and starve customer sites. Each account is moved by the normal single-account
 * worker, so every safety property of a single move still applies (preflight, catch-up sync, rollback).
 *
 * Runs detached — it finishes even if the admin closes the page. The only thing that stops it is an explicit
 * cancel from the UI, which sets cancelled=1 in batch.json; already-running accounts finish their current move
 * (stopping mid-copy would leave a half-copied account), and nothing further is started.
 */
define('SMPRO_BOOT', 1);
$root = dirname(__DIR__);
foreach (['defines', 'helpers', 'maintenance', 'domains', 'disk_home'] as $m) {
    $f = $root . '/includes/' . $m . '.php';
    if (is_file($f)) require $f;
}
@ignore_user_abort(true);
@set_time_limit(0);

$lockDir = defined('SMPRO_LOCKS') ? SMPRO_LOCKS : (SMPRO_VARLIB . '/locks');
@is_dir($lockDir) || @mkdir($lockDir, 0700, true);
$lf = @fopen($lockDir . '/home_move_batch.lock', 'c');
if ($lf && !@flock($lf, LOCK_EX | LOCK_NB)) exit(0);          // another supervisor already owns this batch

function hb_save(array $b) { smpro_ds_home_batch_write($b); }
function hb_acct_done(string $u): array {
    // Outcome of one account, read from that account's own job file.
    $j = smpro_ds_home_job_read($u);
    if (empty($j)) return ['done' => false, 'ok' => false, 'msg' => ''];
    return ['done' => !empty($j['done']), 'ok' => !empty($j['result']['ok']), 'msg' => (string)($j['msg'] ?? ''),
            'pct' => (int)($j['pct'] ?? 0), 'phase' => (string)($j['phase'] ?? ''), 'heartbeat' => (int)($j['heartbeat'] ?? 0)];
}

$b = smpro_ds_home_batch_read();
if (empty($b['accounts']) || !is_array($b['accounts'])) exit(0);

/*
 * A supervisor is a long-lived process running the code it started with. One started on 27 July with a build
 * that had no stall guard, the plugin was updated eleven times underneath it, and it looped for 58 days over two
 * slots whose workers had long finished - writing a warning into cPanel's error log on every pass, 1.27 million
 * lines. Two rules end that class of zombie: the supervisor stops when the plugin on disk is no longer the build
 * it started as (the update installs a fresh one), and no slot or batch outlives an absolute deadline.
 */
$bootVersion = defined('SMPRO_VERSION') ? SMPRO_VERSION : '';
function hb_disk_version(): string {
    $f = dirname(__DIR__) . '/includes/defines.php';
    $s = (string)@file_get_contents($f);
    return preg_match("/define\\('SMPRO_VERSION',\\s*'([^']+)'\\)/", $s, $m) ? $m[1] : '';
}
const HB_SLOT_MAX_SEC  = 48 * 3600;      // no single account move runs two days
const HB_BATCH_MAX_SEC = 7 * 86400;      // no batch runs a week

$cap     = smpro_ds_home_capacity((string)($b['target'] ?? '/home'));
$threads = max(1, min((int)($b['threads'] ?? 1), (int)$cap['max']));    // never exceed what the server can take
$b['threads_effective'] = $threads;
$b['capacity'] = $cap;
$b['phase'] = 'running';
$b['started_at'] = (int)($b['started_at'] ?? time());
$b['heartbeat'] = time();
hb_save($b);

$php    = smpro_ds_home_php_bin();
$worker = $root . '/bin/home_move.php';
$setsid = trim((string)@shell_exec('command -v setsid 2>/dev/null')) !== '' ? 'setsid ' : 'nohup ';

while (true) {
    $b = smpro_ds_home_batch_read();
    if (empty($b['accounts'])) break;
    $b['heartbeat'] = time();
    $running = 0; $pending = 0;

    // The build changed under this process: stop cleanly and say so. In-flight account workers are separate
    // processes and finish on their own; their outcome stays in their job files for the next supervisor.
    $dv = hb_disk_version();
    if ($bootVersion !== '' && $dv !== '' && $dv !== $bootVersion) {
        foreach ($b['accounts'] as $i => $a) if (in_array(($a['status'] ?? ''), ['queued', 'running'], true)) {
            $b['accounts'][$i]['status'] = ($a['status'] === 'running') ? 'failed' : 'skipped';
            $b['accounts'][$i]['msg']    = 'The plugin was updated (' . $bootVersion . ' -> ' . $dv . ') while this batch ran. Start the batch again; accounts already moved are in the history.';
            $b['accounts'][$i]['ended']  = time();
        }
        $b['phase'] = 'stopped'; $b['done'] = true; $b['finished_at'] = time(); hb_save($b);
        if (function_exists('smpro_audit')) @smpro_audit('home_move_batch_stopped', ['why' => 'plugin updated', 'from' => $bootVersion, 'to' => $dv]);
        break;
    }
    if (!empty($b['started_at']) && time() - (int)$b['started_at'] > HB_BATCH_MAX_SEC) {
        foreach ($b['accounts'] as $i => $a) if (in_array(($a['status'] ?? ''), ['queued', 'running'], true)) {
            $b['accounts'][$i]['status'] = 'failed'; $b['accounts'][$i]['ended'] = time();
            $b['accounts'][$i]['msg']    = 'The batch passed its one-week deadline. Check the history for what was moved and start again for the rest.';
        }
        $b['phase'] = 'stopped'; $b['done'] = true; $b['finished_at'] = time(); hb_save($b);
        if (function_exists('smpro_audit')) @smpro_audit('home_move_batch_stopped', ['why' => 'deadline', 'days' => 7]);
        break;
    }

    foreach ($b['accounts'] as $i => $a) {
        $u  = (string)($a['user'] ?? ''); if ($u === '') continue;
        $st = (string)($a['status'] ?? 'queued');
        if ($st === 'running') {
            $d = hb_acct_done($u);
            // Same race as below: this file belongs to another process and is read while it is being written,
            // so every key is treated as possibly-not-there-yet. An absent 'done' means "not finished", which is
            // the safe reading — the opposite would finalise an account that is still being copied.
            if (!empty($d['done'])) {
                $b['accounts'][$i]['status'] = !empty($d['ok']) ? 'moved' : 'failed';
                $b['accounts'][$i]['msg']    = (string)($d['msg'] ?? '');
                $b['accounts'][$i]['ended']  = time();
            } else {
                // A worker that never produced a heartbeat at all (require/exec failure) would otherwise keep
                // the slot 'running' for ever and the supervisor would loop indefinitely — so a slot that has
                // been started for over two minutes with NO heartbeat is treated as failed too.
                $startedAgo = time() - (int)($a['started'] ?? 0);
                if (empty($d['heartbeat']) && !empty($a['started']) && $startedAgo > 120) {
                    $b['accounts'][$i]['status'] = 'failed';
                    $b['accounts'][$i]['msg']    = 'The worker never started — nothing was changed for this account.';
                    $b['accounts'][$i]['ended']  = time();
                }
                // a slot that has run longer than any move can take, whatever its heartbeat says
                elseif (!empty($a['started']) && $startedAgo > HB_SLOT_MAX_SEC) {
                    $b['accounts'][$i]['status'] = 'failed';
                    $b['accounts'][$i]['msg']    = 'This move ran for over two days and was stopped by the supervisor. Check the history and the account\'s home before trying again.';
                    $b['accounts'][$i]['ended']  = time();
                }
                // a worker that vanished mid-run (reboot/OOM) — mark it so the admin sees it
                elseif (!empty($d['heartbeat']) && (time() - $d['heartbeat']) > 900) {
                    $b['accounts'][$i]['status'] = 'failed';
                    $b['accounts'][$i]['msg']    = 'The worker stopped responding — nothing was finalised for this account.';
                    $b['accounts'][$i]['ended']  = time();
                } else {
                    // The worker writes its progress file the moment it starts and fills these in a tick later,
                    // so between those two moments they are simply absent. Reading them blind warned on EVERY
                    // supervisor pass — once every five seconds, into the server's cPanel error log, for as long
                    // as any move was running. Keep whatever was last known rather than overwriting it with
                    // nothing: a progress bar that drops to zero because one poll arrived early is a worse lie
                    // than one that pauses.
                    if (isset($d['pct']))   $b['accounts'][$i]['pct']   = $d['pct'];
                    if (isset($d['phase'])) $b['accounts'][$i]['phase'] = $d['phase'];
                    $b['accounts'][$i]['pct']   = $b['accounts'][$i]['pct']   ?? 0;
                    $b['accounts'][$i]['phase'] = $b['accounts'][$i]['phase'] ?? 'starting';
                    $running++;
                }
            }
        } elseif ($st === 'queued') { $pending++; }
    }

    if (!empty($b['cancelled'])) {                                       // explicit admin stop
        foreach ($b['accounts'] as $i => $a) if (($a['status'] ?? '') === 'queued') {
            $b['accounts'][$i]['status'] = 'skipped';
            $b['accounts'][$i]['msg']    = 'Cancelled before this account started.';
        }
        if ($running === 0) { $b['phase'] = 'cancelled'; $b['done'] = true; $b['finished_at'] = time(); hb_save($b); break; }
        hb_save($b); sleep(5); continue;                                 // let in-flight accounts finish cleanly
    }

    // Fill free slots up to the cap.
    if ($running < $threads && $pending > 0) {
        foreach ($b['accounts'] as $i => $a) {
            if ($running >= $threads) break;
            if (($a['status'] ?? '') !== 'queued') continue;
            $u = (string)$a['user'];
            @unlink(smpro_ds_home_job_path($u));                          // clean slate for this account
            $cmd = $setsid . escapeshellarg($php) . ' ' . escapeshellarg($worker)
                 . ' ' . escapeshellarg('--mode=move') . ' ' . escapeshellarg('--user=' . $u)
                 . ' ' . escapeshellarg('--target=' . (string)$b['target'])
                 . ' ' . escapeshellarg('--job=' . $u)
                 . ' >/dev/null 2>&1 </dev/null &';
            @shell_exec('PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin ' . $cmd);
            $b['accounts'][$i]['status']  = 'running';
            $b['accounts'][$i]['started'] = time();
            $running++;
            sleep(2);                                                     // stagger starts so N rsyncs don't all hit the disk at once
        }
    }

    $left = 0;
    foreach ($b['accounts'] as $a) if (in_array(($a['status'] ?? ''), ['queued', 'running'], true)) $left++;
    if ($left === 0) {
        $b['phase'] = 'done'; $b['done'] = true; $b['finished_at'] = time();
        $ok = 0; $bad = 0;
        foreach ($b['accounts'] as $a) { if (($a['status'] ?? '') === 'moved') $ok++; elseif (($a['status'] ?? '') === 'failed') $bad++; }
        $b['summary'] = ['moved' => $ok, 'failed' => $bad, 'total' => count($b['accounts'])];
        hb_save($b);
        if (function_exists('smpro_audit')) smpro_audit('disk_home_batch_done', $b['summary']);
        break;
    }
    hb_save($b);
    sleep(5);
}
