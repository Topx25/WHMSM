<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
/** t98 - fixes from the 2026-10-01 security audit: every one is pinned here so it cannot drift back. */
require_once SMPRO_BASE . '/includes/migrate_da_convert.php';
ok(smpro_mig_da_hostname_ok('example.com'), 'U1: a hostname passes');
ok(smpro_mig_da_hostname_ok('a-b.c-d.co.uk'), 'U1: hyphens and several labels pass');
ok(!smpro_mig_da_hostname_ok('../../../root/.ssh/authorized_keys'), 'U1: a path is not a hostname');
ok(!smpro_mig_da_hostname_ok('evil/x.com'), 'U1: a slash is refused'); ok(!smpro_mig_da_hostname_ok('localhost'), 'U1: a single label is refused (a domain has a dot)');
$mc = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/migrate_da_convert.php'));
has($mc, "if (\$rel === '' || \$rel[0] === '/' || strpos(\$rel, '..') !== false", 'U1: and the writer itself refuses to leave its root');
/* the worker's helpers exist in includes/ now */
require_once SMPRO_BASE . '/includes/phstack.php'; require_once SMPRO_BASE . '/includes/phlock.php'; require_once SMPRO_BASE . '/includes/ph_ignore.php';
ok(function_exists('smpro_ph_inside'), 'U2: smpro_ph_inside is an include-level function (the cron worker can call it)');
ok(function_exists('smpro_ph_perm_all'), 'U2: smpro_ph_perm_all exists');
is_eq(smpro_ph_perm_all(), [], 'U2: ...and is empty until something is added');
ok(smpro_ph_perm_add('/home/x/public_html/a.php', 'test'), 'U2: add'); ok(smpro_ph_perm_has('/home/x/public_html/a.php'), 'U2: has'); ok(smpro_ph_perm_remove('/home/x/public_html/a.php') && !smpro_ph_perm_has('/home/x/public_html/a.php'), 'U2: remove');
$mod = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/php-harden.php'));
hasnt($mod, 'function smpro_ph_inside(', 'U2: the module no longer carries its own copy (a second definition would be a fatal)');
$sq = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/bin/sp_queue.php'));
has($sq, "!function_exists('smpro_ph_inside') || !function_exists('smpro_ph_perm_all')", 'U2: the worker refuses to run without them instead of throwing on every request');
$im = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/intrusion.php'));
has($im, "if (is_link(\$f) || !is_file(\$f)) continue;\n            \$st = @lstat(\$f); if (!is_array(\$st) || (int)\$st['uid'] === 0) continue;", 'U3: emergency harden never chmods through a link or touches a root-owned file');
has($im, "if (\$a['type'] === 'lock' && \$p) { if (is_link(\$p)) continue;", 'U3: ...nor does its undo');
$tu = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/tuning.php'));
has($tu, "escapeshellarg(\"SHOW GRANTS FOR 'root'@'\" . \$esc(\$h) . \"';\")", 'U4: the grants query is one shell argument');
$hb = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/hub.php'));
hasnt($hb, "smpro_audit('hub_pair_approve', ['code' => strtoupper", 'U5: the pairing code is not written to the audit log');
$cf = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/croncheck_fix.php'));
has($cf, "\$dirReal === false || strpos(\$real, \$dirReal . '/') !== 0", 'U6: cron undo is confined even when the backup dir is missing');
$wc = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/wpcron_fix.php'));
has($wc, "is_link(\$file) || \$real === false || \$homeReal === false || strpos(\$real, \$homeReal . '/') !== 0", 'U7: wp-config edits refuse links and anything outside the account');
$iv = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/investigate.php'));
has($iv, "basename(\$cacheReal) !== 'cache' || basename(dirname(\$cacheReal)) !== 'bootstrap'", 'U8: the Laravel cache fix is confined to bootstrap/cache inside the account');
is_eq(substr_count($iv, "refused: a symlink in the path"), 2, 'U8: chattr fixes refuse a symlinked path');
$rs = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/bin/register.sh'));
hasnt($rs, '${DEST}', 'U9: register.sh no longer dies on an unbound DEST before the cron re-sync');
