<?php
require __DIR__ . '/../support/bootstrap.php';
/** t158 - Security Health: a stuck malware scan, an own server in a ban list, and a low SSH flood limit are reported. */
$sh = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/security-health.php'));
has($sh, "function smpro_sh_scan_own_checks() {", 'S1: the checks exist');
has($sh, "\$C['Scanning & own servers'] = smpro_sh_scan_own_checks();", 'S2: ...and are listed');
has($sh, "&& \$started > 0 && \$started < time() - 172800)", 'S3: a scan running or queued for more than 2 days is stuck');
has($sh, "nft list set inet filter cphulk-TempBan", 'S4: cPHulk bans live in nftables and are read there');
has($sh, "(int)\$q[0] === 22 && (int)\$q[2] < 40", 'S5: an SSH PORTFLOOD below 40 per window is flagged');
$lv = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/lvelimits.php'));
has($lv, "\$kind = preg_match('/rc -75|quota -22/', \$o) ? 'value' :", 'L1: a refused limit value is told apart from a half-loaded module');
has($lv, "a reboot does not clear this; open a CloudLinux support ticket", 'L2: ...and points to the ticket, not a reboot');
