<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
require_once SMPRO_BASE . '/includes/cooler.php';
/** t110 - the unattended load guard never throttles a cPanel session child, and a ceiling below half the cores is not an overload line. */
ok(smpro_cool_is_critical('cpsrvd (SSL) - serving someuser'), 'U1: a renamed cpsrvd session child is protected by prefix');
ok(smpro_cool_is_critical('cpsrvd'), 'U1: plain cpsrvd too');
ok(smpro_cool_is_critical('sshd: user [priv]'), 'U1: an sshd session too');
ok(!smpro_cool_is_critical('ffmpeg'), 'U1: an ordinary runaway is still a target');
$src = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/cooler.php'));
has($src, "readlink('/proc/' . \$pid . '/exe')", 'U2: the executable behind the name is checked as well');
has($src, "if (\$ceil < \$cores / 2) {", 'U3: a ceiling under half the cores is lifted to half the cores');
has($src, "smpro_audit('cooler_ceiling_raised'", 'U3: ...and the operator is told once per run');
