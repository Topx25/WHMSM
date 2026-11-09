<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/sysupd.php';
/** t164 - a reboot owed by an update is placed inside the window, in Egypt time. */
$cfg = ['reboot_tz' => 'Africa/Cairo', 'reboot_from' => 1, 'reboot_to' => 3];
$tz = new DateTimeZone('Africa/Cairo');
foreach (['2026-11-09 12:00', '2026-11-09 00:30', '2026-11-09 01:20', '2026-11-09 02:55', '2026-11-09 23:59'] as $t) {
    $now = (new DateTime($t, $tz))->getTimestamp();
    $at = smpro_su_reboot_slot($cfg, $now); $h = (int)(new DateTime('@' . $at))->setTimezone($tz)->format('G'); $m = (int)(new DateTime('@' . $at))->setTimezone($tz)->format('i');
    ok($at >= $now + 600 && $h >= 1 && ($h < 2 || ($h === 2 && $m <= 45)), 'W: from ' . $t . ' Cairo -> ' . (new DateTime('@' . $at))->setTimezone($tz)->format('Y-m-d H:i') . ' (inside 01:00-02:45, 10+ min ahead)');
}
$c = smpro_su_cfg(); ok($c['auto_reboot'] === false, 'D1: off unless the operator turns it on');
$src = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/sysupd.php'));
has($src, "\$r = smpro_reboot_sched_save(['enabled' => true, 'at' => \$at, 'target' => 'next']);", 'D2: the reboot goes through Scheduled Reboot (safety re-check at the minute)');
has($src, "if (!empty(\$cur['enabled']) && \$cur['at'] > time()) return ['planned' => false", 'D3: never replaces a reboot the operator scheduled');
