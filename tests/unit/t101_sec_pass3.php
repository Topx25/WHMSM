<?php
require __DIR__ . '/../support/bootstrap.php';
/** t101 - security pass 3: harden undo restores the real backup, secret key born 0600, PHP Harden roots confined, optimizers never run as root. */
$im = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/intrusion.php'));
has($im, "'bak' => (!\$dryrun && !empty(\$bakPath)) ? \$bakPath : ''", 'U1: the harden manifest records the backup name');
has($im, "glob(\$p . '.smprobak-*')", 'U1: undo finds the random-suffixed backup of older manifests');
hasnt($im, "is_file(\$p . '.smprobak')) { @rename(\$p . '.smprobak', \$p); }", 'U1: the fixed-name restore (which never matched) is gone');
$sc = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/secret.php'));
has($sc, 'umask(077); @file_put_contents($f, base64_encode($k), LOCK_EX); umask($um)', 'U2: the key file is written under umask 077');
$ph = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/phlock.php'));
has($ph, "!smpro_ph_inside(\$u, \$real)) continue;", 'U3: a userdatadomains docroot outside the home is skipped');
$iv = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/investigate.php'));
hasnt($iv, "@shell_exec('timeout ' . \$t . ' /bin/sh -c ' . escapeshellarg(\$bounded)", 'U4: no root fallback for asset optimizers');
has($iv, "su -s /bin/sh ' . escapeshellarg(\$user)", 'U4: the fallback drops to the account with su');
has($iv, "|| \$user === 'root') return;", 'U4: an invalid or root user means the tool does not run');
