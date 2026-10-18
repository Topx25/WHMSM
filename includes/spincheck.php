<?php
/**
 * Safety Monitor Pro — processes that are spinning rather than working.
 *
 * A process can hold a core at full speed for weeks without doing anything. It happens when an event loop is
 * woken by a descriptor that is never cleared, so it wakes, finds nothing, and immediately wakes again. From
 * outside it looks exactly like hard work, and every tool that ranks by CPU puts it at the top and leaves the
 * reader to assume it is busy.
 *
 * The difference is not the amount of CPU — it is the SHAPE. Real work varies: it responds to traffic, it pauses
 * on I/O, it finishes. A loop does not. So this samples the same process several times and looks for a reading
 * that never moves, on something that has been running far longer than its job should take.
 *
 * Found on a live mail server: dovecot's anvil at 99% of a core, identical across every sample, state R with
 * nothing waited on in the kernel, for 29.7 days, on a server with 185 mail connections. Nothing in the plugin
 * would have said a word about it; it simply sat at the top of the process list looking busy.
 *
 * This only reads and reports. Ending such a process is a judgement about a running service and belongs to the
 * operator, not to a scan.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

/** CPU time (user+system) a pid has consumed, in clock ticks. -1 when it cannot be read. */
function smpro_spin_ticks(int $pid): int {
    $s = @file_get_contents("/proc/$pid/stat");
    if ($s === false || $s === '') return -1;
    // The command field can contain spaces and brackets, so everything is counted from the closing bracket.
    $p = strrpos($s, ')');
    if ($p === false) return -1;
    $f = preg_split('/\s+/', trim(substr($s, $p + 1)));
    // After the ')' the fields are: state, ppid, pgrp, session, tty, tpgid, flags, minflt, cminflt, majflt,
    // cmajflt, utime, stime — utime and stime are the 12th and 13th here.
    if (!isset($f[12])) return -1;
    return (int)$f[11] + (int)$f[12];
}

/** Single-character process state, or '' — 'R' means runnable, never sleeping. */
function smpro_spin_state(int $pid): string {
    $s = @file_get_contents("/proc/$pid/stat");
    if ($s === false) return '';
    $p = strrpos($s, ')');
    if ($p === false) return '';
    $f = preg_split('/\s+/', trim(substr($s, $p + 1)));
    return (string)($f[0] ?? '');
}

/**
 * Processes that look like a loop rather than work.
 *
 * $minHours — how long it must have been running. A loop is only interesting once it has outlived any plausible
 *             piece of work; a backup or a malware scan is meant to sit at full speed for a while.
 * $minPct   — how much of a core it must hold in EVERY sample.
 * $maxSpread— how much the readings may differ between samples before this is treated as varying, and therefore
 *             as real work. This is the check that does the actual separating.
 *
 * Returns ['ok','checked','found'=>[[pid,comm,user,pct,days,state,rss_kb,samples]],'why'].
 */
function smpro_spin_scan(int $minHours = 24, int $minPct = 80, int $maxSpread = 8, int $samples = 3, int $gapMs = 1200): array {
    $hz = 100;
    $g = trim((string)@shell_exec('getconf CLK_TCK 2>/dev/null'));
    if (ctype_digit($g) && (int)$g > 0) $hz = (int)$g;

    // Candidates first, from one cheap listing: long-lived and currently hot. Sampling every process would cost
    // more than the answer is worth on a busy server.
    $raw = smpro_run("ps -eo pid=,etimes=,pcpu=,user:32=,comm= --sort=-pcpu 2>/dev/null | head -n 40", 20, ['stderr' => 'discard']);
    if (trim($raw) === '') return ['ok' => false, 'checked' => 0, 'found' => [], 'why' => 'The process list could not be read, so nothing is being claimed.'];

    $cand = [];
    foreach (preg_split('/\r?\n/', $raw) as $line) {
        $line = trim($line); if ($line === '') continue;
        $p = preg_split('/\s+/', $line, 5);
        if (!$p || count($p) < 5) continue;
        $pid = (int)$p[0]; $secs = (int)$p[1]; $pct = (float)$p[2];
        if ($pid < 2 || $secs < $minHours * 3600 || $pct < $minPct) continue;
        $cand[$pid] = ['pid' => $pid, 'secs' => $secs, 'user' => $p[3], 'comm' => trim($p[4])];
    }
    if (!$cand) return ['ok' => true, 'checked' => 0, 'found' => [], 'why' => ''];

    // Measure each candidate over several intervals. One reading cannot tell a loop from a busy moment.
    $reads = [];
    $prev = [];
    foreach (array_keys($cand) as $pid) $prev[$pid] = smpro_spin_ticks($pid);
    for ($i = 0; $i < max(2, $samples); $i++) {
        usleep(max(300, $gapMs) * 1000);
        foreach (array_keys($cand) as $pid) {
            $now = smpro_spin_ticks($pid);
            if ($now < 0 || $prev[$pid] < 0) { $reads[$pid][] = -1; $prev[$pid] = $now; continue; }
            $pct = (int)round((($now - $prev[$pid]) / $hz) / (max(300, $gapMs) / 1000) * 100);
            $reads[$pid][] = $pct;
            $prev[$pid] = $now;
        }
    }

    $found = [];
    foreach ($cand as $pid => $c) {
        $r = array_values(array_filter($reads[$pid] ?? [], fn($x) => $x >= 0));
        if (count($r) < 2) continue;
        $min = min($r); $max = max($r);
        // Every reading high, and barely any difference between them. A process doing real work moves.
        if ($min < $minPct || ($max - $min) > $maxSpread) continue;
        $st = smpro_spin_state($pid);
        $rss = 0;
        if (preg_match('/VmRSS:\s+(\d+)/', (string)@file_get_contents("/proc/$pid/status"), $m)) $rss = (int)$m[1];
        $found[] = ['pid' => $pid, 'comm' => $c['comm'], 'user' => $c['user'],
                    'pct' => (int)round(array_sum($r) / count($r)), 'days' => round($c['secs'] / 86400, 1),
                    'state' => $st, 'rss_kb' => $rss, 'samples' => $r];
    }
    usort($found, fn($a, $b) => $b['days'] <=> $a['days']);
    return ['ok' => true, 'checked' => count($cand), 'found' => $found, 'why' => ''];
}

/** One readable line about a spinning process — what was seen, and why that means a loop. */
function smpro_spin_describe(array $f): string {
    return $f['comm'] . ' (pid ' . $f['pid'] . ', ' . $f['user'] . ') has held about ' . $f['pct']
         . '% of one core for ' . $f['days'] . ' day(s), and the reading does not move between samples ('
         . implode('%, ', $f['samples']) . '%). Work varies and finishes; a reading that never changes over that '
         . 'long is a loop. It is using a core to do nothing.';
}
