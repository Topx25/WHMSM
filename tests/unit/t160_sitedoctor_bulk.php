<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/investigate.php';
require_once SMPRO_BASE . '/includes/sdbulk.php';
/** t160 - Site Doctor for all sites: classification, the automatic switch's limits, the 7-day purge. */
is_eq(smpro_sdb_classify(200, '<html>Hello world, a real page here</html>', 300)['state'], 'ok', 'C1: a normal page is up');
is_eq(smpro_sdb_classify(200, 'x<b>Fatal error</b>: Uncaught', 300)['kind'], 'php_fatal', 'C2: a fatal printed on a 200 page is a problem');
is_eq(smpro_sdb_classify(500, '', 300)['kind'], 'http_500', 'C3: 500');
is_eq(smpro_sdb_classify(0, '', 15000)['kind'], 'no_answer', 'C4: no answer');
is_eq(smpro_sdb_classify(200, '<title>Index of /</title>', 100)['kind'], 'dir_listing', 'C5: directory listing');
is_eq(smpro_sdb_classify(508, '', 100)['kind'], 'limit_508', 'C6: resource limit');
is_eq(smpro_sdb_classify(200, ' ', 100)['kind'], 'blank', 'C7: blank page');
ok(!smpro_sdb_auto_allowed('fix_wp_url'), 'A1: the switch never edits a database');
ok(!smpro_sdb_auto_allowed('restart_phpfpm'), 'A2: never restarts a shared service');
ok(!smpro_sdb_auto_allowed('unharden'), 'A3: never unlocks a locked site');
ok(smpro_sdb_auto_allowed('fix_htaccess') && smpro_sdb_auto_allowed('disable_plugin'), 'A4: file fixes with a backup are allowed');
$src = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/sdbulk.php'));
has($src, "Skipped by the automatic switch: some of this site", 'A5: a locked site is skipped by the switch');
has($src, "preg_match('/\\.smpro-(bak|optbak)-/', basename(", 'P1: only real backup copies are purged');
has($src, "preg_match('#^/home[^/]*/' . \$u . '/#', \$real) && !is_link(\$b)", 'P2: only inside the backup own account home, never through a link');
$mf = smpro_inv_manifest_path(); @mkdir(dirname($mf), 0700, true); $keep = @file_get_contents($mf);
file_put_contents($mf, json_encode([
    ['id' => 'x1', 'status' => 'applied', 'ts' => time() - 8 * 86400, 'backup' => '/nonexistent/.htaccess.smpro-bak-1'],
    ['id' => 'x2', 'status' => 'applied', 'ts' => time(), 'backup' => '/nonexistent/.htaccess.smpro-bak-2'],
    ['id' => 'x3', 'status' => 'applied', 'ts' => time() - 9 * 86400, 'to' => '/x/plugins/a.smpro-disabled-1']]));
smpro_sdb_purge(7); $m = smpro_inv_manifest_load();
is_eq($m[0]['status'], 'expired', 'P4: an 8-day-old backup record is closed');
is_eq($m[1]['status'], 'applied', 'P5: a fresh one is kept');
is_eq($m[2]['status'], 'applied', 'P6: a disabled plugin (the site own code) is never purged');
if ($keep !== false) file_put_contents($mf, $keep); else @unlink($mf);
$sd = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/site-doctor.php'));
has($sd, "['bulk_scan', 'bulk_resume', 'bulk_fix', 'bulk_cfg'], true) && function_exists('smpro_sdb_start')) {\n    smpro_require_valid_csrf('sd_action'); smpro_require_root();", 'S1: bulk actions need CSRF + root');
has($sd, "|| isset(\$_GET['sd_bulk'])) {\n    smpro_require_root();", 'S2: the state endpoint is root only');
$cs = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/bin/cron_sync.php'));
has($cs, "'site doctor bulk'   => 'smpro_sdb_cron_sync',", 'S3: the daily cron is kept in step by cron_sync');
has($src, "smpro_sdb_save('scan.json', \$scan);   // progress after every site", 'R1: progress saved after every site');
has($src, "if (\$resume && (int)(\$scan['results'][\$dom]['checked_at'] ?? 0) >= (int)\$scan['started']) continue;", 'R2: a resumed scan skips sites already checked');
has($src, "if (\$dead) { \$j['running'] = false; \$j['stopped'] = true;", 'R3: a dead or stuck worker is not shown as running');
has($sd, "if (\$act === 'bulk_resume') { echo json_encode(smpro_sdb_start('resume')", 'R4: Continue scan button');
ok(!smpro_sdb_auto_allowed('disable_plugin', '/home/u/public_html/wp-content/plugins/wp-guard'), 'X1: the switch never disables the security plugin');
ok(!smpro_sdb_auto_allowed('restore_wp_core'), 'X2: core restore is by hand only');
$d = sys_get_temp_dir() . '/sdb' . getmypid(); @mkdir($d . '/wp-content/plugins/badp', 0700, true);
$x = smpro_sdb_extra_fixes(['docroot' => $d, 'fixes' => [], 'fatals' => [
    ['msg' => "PHP Fatal error:  Uncaught Error: Call to a member function get_row() on null in $d/wp-content/plugins/badp/x.php:50"],
    ['msg' => "PHP Fatal error: Uncaught Error: Failed opening required '$d/wp-includes/version.php' (include_path='.')"]]], 'php_warning');
is_eq(array_column($x, 'action'), ['disable_plugin', 'restore_wp_core', 'hide_php_errors'], 'X3: crash in a plugin, missing core file, printed warnings each get a fix');
is_eq(smpro_sdb_noindex_cause($d), 'The web root has no index page (index.php / index.html), so the server refuses to list it.', 'X4: 403 cause = no index page');
@rmdir($d . '/wp-content/plugins/badp'); @rmdir($d . '/wp-content/plugins'); @rmdir($d . '/wp-content');
is_eq(smpro_sdb_noindex_cause($d), 'The web root is empty: the site has no content (upload it, or remove the domain).', 'X5: empty web root');
@rmdir($d);
$inv = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/investigate.php'));
has($inv, "if ((\$e['kind'] ?? '') === 'tar') {   // restored WordPress core", 'X6: the core restore can be undone');
