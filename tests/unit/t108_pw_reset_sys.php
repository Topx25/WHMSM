<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
require_once SMPRO_BASE . '/includes/intrusion.php';
/** t108 - a password changed in WHM / cPanel / by the customer clears a foreign-login alert like one made from the Threat Report: the system shadow files are the proof. */
ok(function_exists('smpro_pw_reset_sys'), 'U1: helper exists');
is_eq(smpro_pw_reset_sys('nosuchacct', 'nosuchacct'), 0, 'U2: an unknown account has no change date');
is_eq(smpro_pw_reset_sys('nosuchacct', 'box@nosuch.example'), 0, 'U2: an unknown mailbox has no change date');
$src = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/intrusion.php'));
has($src, "smpro_pw_reset_sys((string)\$account, (string)\$user) > \$ts)) continue;", 'U3: the foreign-login scan skips logins older than the system-recorded change');
has($src, "\$home . '/etc/' . \$dom . '/shadow'", 'U4: a mailbox is read from the domain mail shadow file');
has($src, "\$lastchg('/etc/shadow'", 'U4: a cPanel account from /etc/shadow');
has($src, "return \$memo[\$key] = \$day > 0 ? (\$day + 1) * 86400 : 0;", 'U5: day granularity, read as the end of that day');
