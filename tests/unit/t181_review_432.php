<?php
require __DIR__ . '/../support/bootstrap.php';
/**
 * t181 - round 432. On a real server the scheduled reboot ran at its minute, announced "rebooting now" and the
 * server never restarted: the restart command was a bare name, cron's search path does not hold the folder it
 * lives in, and the output was thrown away. And Site Watch called a file "reachable from the web" because it
 * was in the web root, when every one of 17 such files answered 403/404 from outside.
 */
$src = fn($p) => str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/' . $p));

$rb = $src('includes/reboot.php');
ok(strpos($rb, "@shell_exec('shutdown -r +1") === false, 'R1: the restart command is no longer a bare name');
has($rb, "foreach (['/usr/sbin/shutdown', '/sbin/shutdown', '/usr/bin/shutdown'] as \$cand) if (@is_executable(\$cand)) { \$sd = \$cand; break; }", 'R2: it is found by its full path');
has($rb, "\$started = \$sd !== '' && (bool)preg_match('/__SMRC__=0\\s*\$/', \$out);", 'R3: and its result is read');
has($rb, "'Scheduled reboot could NOT be started'", 'R4: a restart that did not take is said');
has($rb, "smpro_audit('reboot_started', ['ok' => \$started ? 1 : 0, 'via' => \$sd]);", 'R5: ...and written down either way');
$i = strpos($rb, "'Scheduled reboot could NOT be started'"); $j = strpos($rb, "unset(\$su['reboot_reason'], \$su['reboot_planned_at']); smpro_su_state_save(\$su);", (int)$i);
ok($i !== false && $j !== false, 'R6: and an automatic reboot may then be planned again');

$df = $src('includes/defines.php');
has($df, "foreach (['/usr/local/sbin', '/usr/local/bin', '/usr/sbin', '/usr/bin', '/sbin', '/bin'] as \$smproDir)", 'P1: a worker run from cron gets the system tool folders on its search path');
// the way a worker really starts: a fresh process, cron's search path, the defines file loaded first
if (PHP_SAPI === 'cli' && stripos(PHP_OS, 'WIN') !== 0 && is_executable('/usr/bin/env')) {
    $code = 'define("SMPRO_BOOT", 1); require ' . var_export(SMPRO_BASE . '/includes/defines.php', true) . '; echo "PATH=", getenv("PATH"), "|", trim((string)shell_exec("command -v shutdown 2>/dev/null"));';
    $out = (string)shell_exec('/usr/bin/env -i PATH=/usr/bin:/bin ' . escapeshellarg(PHP_BINARY) . ' -r ' . escapeshellarg($code) . ' 2>&1');
    ok(strpos($out, ':/usr/sbin') !== false && strpos($out, ':/sbin') !== false, 'P2: a process started with cron\'s search path ends up with the tool folders (' . substr($out, 0, 120) . ')');
    if (is_executable('/usr/sbin/shutdown')) ok((bool)preg_match('#\|/\S*shutdown$#', trim($out)), 'P3: and then finds the restart command by its bare name too');
    else tap_skip('P3: bare-name lookup', 'no shutdown command on this system');
} else {
    tap_skip('P2-P3: the search path of a worker', 'needs the command line on Linux');
}

$sw = $src('includes/sitewatch.php');
has($sw, "['warn', 'Sensitive files inside the web root (only a deny rule keeps them from being served): '", 'E1: a file in the web root is reported as what it is');
ok(strpos($sw, "'Files that must not be reachable from the web: '") === false, 'E2: ...not as "reachable"');
has($sw, "smpro_sw_event_add(\$dom, \$batch, 'warning', 'exposed', \$c[1], ['path' => 'exposed', 'files' => \$now]);", 'E3: as a warning, not a critical finding');
has($sw, "\$now = \$c[0] !== 'ok' ? (array)\$c[3] : []; sort(\$now);", 'E4: and it is still told once');
