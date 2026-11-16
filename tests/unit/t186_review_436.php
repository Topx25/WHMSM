<?php
require __DIR__ . '/../support/bootstrap.php';
/**
 * t186 - round 436: settings written to the system by Server Tuning, alert signatures, the stale package lock.
 */
$src = fn($p) => str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/' . $p));

$tu = $src('includes/tuning.php');
has($tu, "\$bpMb = max(128, (int)floor((int)\$scan['ram_mb'] * 0.5)); \$val = \$bpMb >= 2048 ? intdiv(\$bpMb, 1024) . 'G' : \$bpMb . 'M';", 'M1: the buffer pool is half the RAM, in megabytes when it is small');
ok(strpos($tu, "max(1, (int)round(\$scan['ram_mb'] * 0.5 / 1024)) . 'G'") === false, 'M2: no more "at least 1G" on a 1 GB server');
foreach ([[1024, '512M'], [2048, '1024M'], [3072, '1536M'], [8192, '4G'], [65536, '32G'], [200, '128M']] as [$ram, $want]) {
    $bpMb = max(128, (int)floor($ram * 0.5)); $val = $bpMb >= 2048 ? intdiv($bpMb, 1024) . 'G' : $bpMb . 'M';
    is_eq($val, $want, 'M3: ' . $ram . ' MB of RAM gives ' . $want);
}
is_eq(substr_count($tu, "if (\$sshBad) {"), 2, 'S1: the SSH config test is judged by its exit code (both appliers)');
ok(strpos($tu, "stripos(\$t, 'warning') === false") === false, 'S2: not by whether its output holds the word "warning"');
has($tu, "function smpro_tun_root_has_key(): bool {", 'S3: there is a check for a usable key for root');
is_eq(substr_count($tu, "Switching password sign-in off now would lock you out of SSH."), 2, 'S4: password sign-in is not switched off without one (both appliers)');
if (function_exists('smpro_tun_root_has_key') || @include_once SMPRO_BASE . '/includes/helpers.php') {
    if (!function_exists('smpro_tun_root_has_key')) @include_once SMPRO_BASE . '/includes/tuning.php';
}
$line = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGst2cLpgiUO0ahttdjPY7bIgp9SAZowhQhsQCrjIyfnAAAAAAAAAAAA someone';
ok((bool)preg_match('/(?:^|\s)(ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-\S+|sk-\S+)\s+[A-Za-z0-9+\/]{60,}/', $line), 'S5: a key line is recognised');
ok((bool)preg_match('/(?:^|\s)(ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-\S+|sk-\S+)\s+[A-Za-z0-9+\/]{60,}/', 'from="10.0.0.1",no-pty ' . $line), 'S6: ...with options in front too');
ok(!preg_match('/(?:^|\s)(ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-\S+|sk-\S+)\s+[A-Za-z0-9+\/]{60,}/', '# ssh-ed25519 short'), 'S7: a stub is not a key');

$nt = $src('includes/notify.php');
has($nt, "'dbinj:' . count(\$found) . '.' . substr(md5(implode(',', array_keys(\$found))), 0, 8)", 'A1: the database-injection alert knows WHICH rows, not only how many');
has($nt, "\$overSig[] = \$m[1] . ':' . intdiv((int)\$m[2], 5);", 'A2: the disk alert moves in steps of 5%, not on every percent');
has($nt, "\$maybe('mem_pressure', 'clear:mem', '', '');", 'A3: the host memory alert is cleared when memory is fine again');
has($nt, "} else \$maybe('foreign_login', 'clear:cplogin', '', '');", 'A4: so is the panel foreign-login alert');
has($nt, "\$chOn && \$ticked && !array_intersect(\$ticked, \$chOn)", 'A5: an alert is re-routed only when its chosen channels are all off');

$su = $src('includes/sysupd.php');
has($su, "if (!preg_match('/^(dnf|yum|rpm|microdnf|packagekit|python)/i', \$comm)) \$alive = false;", 'L1: a process number taken by another program is not a package manager');
has($su, "else \$age = max(0, time() - (int)@filemtime('/proc/' . \$pid));", 'L2: the age is the process\'s own, not the lock file\'s');
