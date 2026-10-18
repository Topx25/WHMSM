<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/intrusion.php';
/**
 * t88_pw_native_reset.php — a password reset done outside this product clears the foreign-login alert too.
 *
 * The alert dropped events older than the newest reset in the product's own log. An operator who reset the
 * password in WHM, or whose customer changed it in cPanel, left no line there, and the alert came back the next
 * morning naming an account already dealt with. cPanel's own evidence is read now: the session purge it writes
 * at a password change, and the shadow record's last-change day.
 */
$src = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/intrusion.php'));
has($src, "return max((int)(\$map[\$u] ?? 0), smpro_pw_native_reset_at(\$u));", 'U1: the per-account watermark is the later of the product log and cPanel\'s own evidence');
has($src, "' PURGE ' . \$identity . ':'", 'U2: session_log PURGE lines are matched on the exact identity');
has($src, "grep -a -F password_change", 'U2: and only the password_change purge counts');
has($src, "getent shadow", 'U3: an account\'s shadow last-change day counts');
has($src, "/etc/' . strtolower(\$dom) . '/shadow'", 'U3: and a mailbox\'s, from its domain\'s own shadow under the owner\'s home');
has($src, "(int)\$f[2] * 86400", 'U3: day precision is taken as the start of that day');
is_eq(smpro_pw_native_reset_at(''), 0, 'U4: nothing resolves to nothing');
is_eq(smpro_pw_native_reset_at('no such; rm -rf /'), 0, 'U4: an identity that is not an identity is refused before any command');
has($src, "all count", 'U5: the alert tells the operator that ordinary resets count');
