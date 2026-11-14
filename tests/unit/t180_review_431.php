<?php
require __DIR__ . '/../support/bootstrap.php';
/**
 * t180 - round 431: a scheduled reboot waits for work that must not be cut, a cancelled one is said, the swap
 * cycle cannot end with swap off, and an alert check that could not ask does not report "all clear".
 */
$src = fn($p) => str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/' . $p));

$rb = $src('includes/reboot.php');
has($rb, "function smpro_reboot_busy(): array {", 'B1: work in progress is looked for before a reboot');
has($rb, '\'-f "[s]cripts/upcp"\'', 'B2: the patterns cannot match the shell that carries them');
$i = strpos($rb, '$busy = smpro_reboot_busy();'); $j = strpos($rb, "@shell_exec('shutdown -r +1");
ok($i !== false && $j !== false && $i < $j, 'B3: ...and it is looked for before the shutdown command');
has($rb, "\$again = smpro_reboot_sched_save(['enabled' => true, 'at' => time() + 600, 'target' => \$s['target']]);", 'B4: the reboot waits ten minutes and tries again');
has($rb, "if (time() - \$first < 7200) {", 'B5: for two hours at most');
has($rb, "'Scheduled reboot NOT performed (work in progress)'", 'B6: then it is given up and said');
has($rb, "unset(\$su['reboot_reason'], \$su['reboot_planned_at']); smpro_su_state_save(\$su);", 'B7: and an automatic one may be planned again');

$br = $src('bin/reboot.php');
has($br, "'Scheduled reboot NOT performed'", 'S1: a reboot that a switched-off or Dry-Run plugin will not do is said');
has($br, "if (function_exists('smpro_reboot_clear')) smpro_reboot_clear();", 'S2: and its schedule is cleared');
ok(strpos($br, "if (function_exists('smpro_ctl_disabled') && smpro_ctl_disabled()) exit;") === false, 'S3: no silent exit is left');

$mn = $src('includes/maintenance.php');
has($mn, "escapeshellarg('timeout 900 ' . \$swoff . ' -a; ' . \$swon . ' -a' . \$re)", 'W1: the time limit is on swapoff alone, swapon always follows');
ok(strpos($mn, "'timeout 900 sh -c ' . escapeshellarg(\$swoff") === false, 'W2: the limit no longer wraps the pair');

has($src('includes/sysupd.php'), '/sysupd.lock timeout 14000 "', 'U1: the update worker is not killed before the work it started ends');

$nt = $src('includes/notify.php');
has($nt, "} elseif (\$imAsked) \$maybe('malware_active', 'clear', '', '');", 'N1: a scanner that did not answer is not "clean"');
has($nt, "elseif (is_array(\$j) && !empty(\$j['metadata']['result'])) \$maybe('account_suspended', 'clear', '', '');", 'N2: an API that did not answer is not "none suspended"');
has($nt, "elseif (\$list) \$maybe('backup_failed', 'clear', '', '');", 'N3: a backup service that did not answer is not "all jobs fine"');
