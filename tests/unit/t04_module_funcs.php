<?php
/**
 * t04_module_funcs.php — proves the funcs-only extractor (plugin_funcs.php) loads a MODULE's
 * pure functions WITHOUT executing its router, and tests two security-relevant identifier/path
 * gates (catalog U59 smpro_db_ident, U60 smpro_ds_safe_target). Expected values derived from:
 *   database-cleanup.php: smpro_db_ident = (bool)preg_match('/^[A-Za-z0-9_]+$/', $s)
 *   disk-storage.php:     smpro_ds_safe_target (see regexes in source)
 * If extraction leaked router code, the auto "no warnings" / "no fatal" guards would fail.
 */
require __DIR__ . '/../support/bootstrap.php';
require __DIR__ . '/../support/plugin_funcs.php';

smpro_plugin_funcs('modules/database-cleanup.php');
smpro_plugin_funcs('modules/disk-storage.php');

ok(function_exists('smpro_db_ident'), 'extractor loaded smpro_db_ident (no router executed)');
ok(function_exists('smpro_ds_safe_target'), 'extractor loaded smpro_ds_safe_target');

/* U59 — SQL identifier gate (security: blocks injection via table/field names) */
is_eq(smpro_db_ident('wp_posts'), true,  'db_ident: wp_posts -> true');
is_eq(smpro_db_ident('wp-posts'), false, 'db_ident: hyphen -> false');
is_eq(smpro_db_ident('1;DROP TABLE x'), false, 'db_ident: SQL injection -> false');
is_eq(smpro_db_ident(''), false, 'db_ident: empty -> false');
is_eq(smpro_db_ident('a b'), false, 'db_ident: space -> false');

/* U60 — deletion target must live under a real /home/<acct>/ tree, no traversal */
is_eq(smpro_ds_safe_target('/home/bob/public_html/backup.tar.gz', 'file'), true,  'ds_safe_target: /home file -> true');
is_eq(smpro_ds_safe_target('/etc/passwd', 'file'), false, 'ds_safe_target: /etc/passwd -> false');
is_eq(smpro_ds_safe_target('/home/bob/../../etc/x', 'file'), false, 'ds_safe_target: /.. traversal -> false');
is_eq(smpro_ds_safe_target('/home/bob/app/storage/cache', 'cache'), true, 'ds_safe_target: cache path -> true');
