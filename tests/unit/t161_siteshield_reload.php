<?php
require __DIR__ . '/../support/bootstrap.php';
/** t161 - Site Shield reloads Apache through cPanel's restart script and backs off after a refused reload. */
$s = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/siteshield.php'));
has($s, "\$rs = '/usr/local/cpanel/scripts/restartsrv_httpd';", 'R1: cPanel restart script, not apachectl');
has($s, "if ((int)(\$c['reload_failed_at'] ?? 0) > time() - 1800) return ['changed' => 0, 'why' => 'backing off after a failed reload'];", 'R2: 30-minute back-off after a refused reload');
has($s, "\$c['reload_failed_at'] = \$ok ? 0 : time();", 'R3: the failure time is recorded');
