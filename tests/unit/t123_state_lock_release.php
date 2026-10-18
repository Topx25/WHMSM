<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
require_once SMPRO_BASE . '/includes/notify.php';
/** t123 - the state books release their lock right after writing (two saves in one run never deadlock), an alert's slot is saved the moment it is sent, the worker has its full time. */
$r = fn($f) => str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/' . $f));
$t0 = microtime(true);
smpro_ntf_state_save(['t123a' => ['sig' => 'x', 'ch' => '', 'ts' => 1]]);
smpro_ntf_state_save(['t123b' => ['sig' => 'y', 'ch' => '', 'ts' => 2]]);
ok(microtime(true) - $t0 < 5, 'U1: two saves in one process do not wait on each other');
$s = smpro_ntf_state_load();
ok(isset($s['t123a'], $s['t123b']), 'U1: ...and both keys are kept (merge)');
$n = $r('includes/notify.php');
hasnt($n, "register_shutdown_function(function () use (\$lk) { if (\$lk) { @flock(\$lk, LOCK_UN); @fclose(\$lk); } });\n    \$t = SMPRO_NTF_STATE", 'U2: the notify lock is not held to process exit');
has($n, "smpro_ntf_state_save([\$slot => \$st[\$slot]]);", 'U3: an alert slot is recorded the moment it is sent');
is_eq(substr_count($n, 'timeout 600 $php $bin'), 2, 'U4: the worker has its full time again');
$i = $r('includes/intrusion.php');
has($i, "if (\$lk) { @flock(\$lk, LOCK_UN); @fclose(\$lk); }   /* released now", 'U5: the intrusion state lock is released after the write too');
