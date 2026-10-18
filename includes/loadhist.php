<?php
/**
 * includes/loadhist.php — the 24-hour ring of 1-minute load samples behind "Load — last 24 hours".
 *
 * It used to be fed ONLY by the Load Monitor page's own poll (every 3 s while somebody had the page open), so
 * "the last 24 hours" was really "the last 1,440 moments somebody was looking": on a production server the
 * 1,440 samples spanned 760 hours. Now bin/loadsample.php feeds it every minute from cron whether anyone looks
 * or not, the page's poll only tops it up, and the ring is bounded by TIME (24 h) as well as by count.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }
if (!defined('SMPRO_LO_HIST')) define('SMPRO_LO_HIST', SMPRO_VARLIB . '/load_hist.json');

function smpro_lo_hist_read(): array {
    $j = @is_file(SMPRO_LO_HIST) ? json_decode((string)@file_get_contents(SMPRO_LO_HIST), true) : [];
    return is_array($j) ? array_values($j) : [];
}

/** Append one sample, throttled to ~1/min; keep 24 h. Returns the ring. */
function smpro_lo_hist_tick($load1): array {
    $h = smpro_lo_hist_read();
    $now = time();
    if ($h && ($now - (int)($h[count($h) - 1][0] ?? 0)) < 55) return $h;
    $h[] = [$now, round((float)$load1, 2)];
    $cut = $now - 86400;
    $h = array_values(array_filter($h, fn($p) => is_array($p) && (int)($p[0] ?? 0) >= $cut));   // 24 h by time, not by count
    if (count($h) > 1500) $h = array_slice($h, -1500);
    @is_dir(dirname(SMPRO_LO_HIST)) || @mkdir(dirname(SMPRO_LO_HIST), 0700, true);
    $t = SMPRO_LO_HIST . '.tmp';
    if (@file_put_contents($t, json_encode($h), LOCK_EX) !== false) { @chmod($t, 0600); @rename($t, SMPRO_LO_HIST); }
    return $h;
}

/** The 1-minute load average as the kernel reports it. */
function smpro_lo_load1(): float {
    $l = function_exists('sys_getloadavg') ? sys_getloadavg() : null;
    if (is_array($l) && isset($l[0])) return (float)$l[0];
    $s = (string)@file_get_contents('/proc/loadavg');
    return (float)strtok($s, ' ');
}

/** The product provisions its own cron: one sample a minute, regardless of who is looking. */
function smpro_lo_cron_sync(): bool {
    if (defined('SMPRO_TEST_SRC')) return true;   // a test never installs a live cron
    $f = '/etc/cron.d/smpro-loadsample';
    $php = function_exists('smpro_php_cli_bin') ? smpro_php_cli_bin() : '/usr/local/cpanel/3rdparty/bin/php';
    $lockDir = defined('SMPRO_LOCKS') ? SMPRO_LOCKS : (SMPRO_VARLIB . '/locks'); @is_dir($lockDir) || @mkdir($lockDir, 0700, true);
    $flock = is_executable('/usr/bin/flock') ? '/usr/bin/flock' : 'flock';
    $line = "# Safety Monitor Pro - one load sample a minute for the 24-hour chart\n* * * * * root " . $flock . ' -n ' . $lockDir . '/loadsample.lock timeout 50 ' . $php . ' ' . SMPRO_BASE . "/bin/loadsample.php >/dev/null 2>&1\n";
    return function_exists('smpro_cron_install') ? smpro_cron_install($f, $line) : (@file_put_contents($f, $line) !== false && @chmod($f, 0644));
}
