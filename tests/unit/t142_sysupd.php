<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
if (!defined('SMPRO_VARLIB')) define('SMPRO_VARLIB', sys_get_temp_dir() . '/t142_varlib_' . getmypid());
require_once SMPRO_BASE . '/includes/sysupd.php';
/** t142 - System updates: a check that could not run is never "nothing pending"; the kind of a package is read from
 *  its name; a broken download is diagnosed from the tool's own words and only the safe kinds are repaired by the
 *  product; nothing here ever reboots; the schedule is always on; the mode only decides who presses the button. */
$src = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/sysupd.php'));
$pg  = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/system-updates.php'));
foreach (["run('reboot", "exec('reboot", "run('shutdown", "exec('shutdown", 'systemctl reboot', "run('/sbin/reboot", "run('/usr/sbin/reboot"] as $bad) hasnt($src, $bad, 'N1: the engine never runs a reboot (' . $bad . ')');
hasnt($src, 'shutdown', 'N1: nor a shutdown');
hasnt($src, '/home/', 'N2: no path from any server in the code');
hasnt($src, 'efadh', 'N2: no customer name');
has($src, "if (\$rc !== 0 && \$rc !== 100) return ['ok' => false, 'err' => 'check-update failed (rc ' . \$rc . '): '", 'N3: dnf rc 100 = updates, 0 = none, anything else = could not check');
has($pg, "'could not check'", 'N4: the page shows "could not check" as its own state, never as zero pending');
has($src, "if (function_exists('smpro_ctl_dry_run') && smpro_ctl_dry_run()) { \$rec['msg'] = 'Dry-Run is on: nothing was applied", 'N5: Dry-Run applies nothing and says what it would have done');
has($src, "if (defined('SMPRO_TEST_SRC')) return true;", 'N6: a test never installs a live cron');
has($src, "*/30 * * * * root ", 'N7: the worker is scheduled every 30 minutes whatever the mode');
has($src, "if (\$cfg['mode'] === 'auto' && \$s['pending'] && (int)date('G') === \$cfg['hour']", 'N8: automatic apply only in auto mode, at the chosen hour');
has($src, "if (date('Y-m-d', (int)(\$la['at'] ?? 0)) !== date('Y-m-d'))", 'N9: and at most once a day');

// kinds
is_eq(smpro_su_kind('kernel-core'), 'kernel', 'K1: kernel');
is_eq(smpro_su_kind('ea-php84-php-cli'), 'php', 'K1: php');
is_eq(smpro_su_kind('ea-nginx'), 'web', 'K1: web');
is_eq(smpro_su_kind('exim'), 'mail', 'K1: mail');
is_eq(smpro_su_kind('MariaDB-server'), 'db', 'K1: db');
is_eq(smpro_su_kind('imunify360-firewall'), 'security', 'K1: security');
is_eq(smpro_su_kind('glibc'), 'base', 'K1: base');
is_eq(smpro_su_kind('emacs-filesystem'), 'other', 'K1: other');

// diagnosis from the tool's own words
$d = smpro_su_diagnose("Error: Failed to download metadata for repo 'EA4-c9': Cannot download repomd.xml: Cannot download repodata/repomd.xml: All mirrors were tried");
ok($d !== null && $d['kind'] === 'repo' && $d['repo'] === 'EA4-c9' && !empty($d['auto']), 'D1: a repository whose metadata will not download is named, and is repairable');
$d = smpro_su_diagnose("Another app is currently holding the yum lock; waiting for it to exit...\n  The other application is: dnf\n    Memory :  60 M RSS (1.2 GB VSZ)\n    Started: Tue Oct 21 10:00:00 2026 - 00:40 ago\n    State  : Sleeping, pid: 12345\nWaiting for process with pid 12345 to finish.");
ok($d !== null && $d['kind'] === 'lock' && (int)$d['pid'] === 12345, 'D2: a held lock is diagnosed with its pid');
$d = smpro_su_diagnose("error: rpmdb: BDB0113 Thread/process 1234/5678 failed: BDB1507 Thread died in Berkeley DB library\nerror: db5 error(-30973) from dbenv->failchk: BDB0087 DB_RUNRECOVERY: Fatal error, run database recovery");
ok($d !== null && $d['kind'] === 'rpmdb' && !empty($d['auto']), 'D3: a damaged rpm database is diagnosed and repairable');
$d = smpro_su_diagnose("Error: Transaction test error:\n  installing package foo-1.0 needs 2GB on the / filesystem\nError Summary\n-------------\nDisk Requirements:\n   At least 2048MB more space needed on the / filesystem.");
ok($d !== null && $d['kind'] === 'disk' && empty($d['auto']), 'D4: a full disk is reported, never "repaired"');
$d = smpro_su_diagnose("Error: \n Problem 1: package a-1 requires b = 2, but none of the providers can be installed\n  - conflicting requests");
ok($d !== null && $d['kind'] === 'depsolve' && empty($d['auto']), 'D5: a dependency conflict is reported for a person, not auto-repaired');
$d = smpro_su_diagnose("Public key for foo-1.2.rpm is not installed. Failing package is: foo-1.2.x86_64\n GPG Keys are configured as: file:///etc/pki/rpm-gpg/RPM-GPG-KEY");
ok($d !== null && $d['kind'] === 'gpg', 'D6: a signature problem is named');
is_eq(smpro_su_diagnose('Complete!'), null, 'D7: a clean run has no diagnosis');
has($src, "if (\$alive && \$age < 1800) return [false, 'a package-manager process (pid ' . \$pid . ') is really running", 'D8: a lock whose process is alive and recent is never removed');
has($src, "smpro_su_run('cp -a /var/lib/rpm ' . escapeshellarg(\$bk) . '/', 120);", 'D9: the rpm database is copied before it is rebuilt');
has($src, "default:\n            return [false, 'no automatic repair for this kind (' . \$d['kind'] . '): ' . \$d['what']];", 'D10: an unknown kind is refused, not guessed at');

// after an apply, the services, and the operator is told
has($src, "\$rec['services'] = smpro_su_service_check();", 'S1: services are checked after every apply');
has($src, "smpro_su_run('systemctl restart ' . \$s, 120);", 'S2: a stopped service is restarted once');
has($src, "@smpro_notify('sysupd_problem'", 'S3: a failure or a service that needed attention is told as a problem');
has($src, "@smpro_notify('sysupd_result'", 'S4: a clean automatic apply is told as a result');
has($src, "@smpro_notify('sysupd_new'", 'S5: new updates are told when they appear');
has($src, "\$sig = sha1(", 'S6: and only once per new set, not every check');
$nt = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/notify.php'));
foreach (['sysupd_new', 'sysupd_result', 'sysupd_problem'] as $t) has($nt, "'" . $t . "'", 'S7: notification type ' . $t . ' is in the catalog');
$cs = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/bin/cron_sync.php'));
has($cs, "'system updates'     => 'smpro_su_cron_sync'", 'S8: cron sync installs the worker');
$mn = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/menu.php'));
has($mn, "['id' => 'system-updates'", 'S9: the page is in the menu');
// config round trip
$c = smpro_su_cfg_save(['mode' => 'auto', 'hour' => 99, 'check_hours' => 0]);
is_eq([$c['mode'], $c['hour'], $c['check_hours']], ['auto', 23, 1], 'C1: settings are clamped to sane values');
$c = smpro_su_cfg_save(['mode' => 'weird']);
is_eq($c['mode'], 'manual', 'C2: an unknown mode falls back to manual');
@exec('rm -rf ' . escapeshellarg(SMPRO_VARLIB));

// the PHP version of every domain, photographed and compared (a production domain came out of an update on a PHP
// four major versions older than its code, FPM pointed at a service that did not exist)
$src2 = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/sysupd.php'));
$before = ['a.example' => ['v' => 'ea-php84', 'fpm' => 1, 'u' => 'a'], 'b.example' => ['v' => 'ea-php82', 'fpm' => 0, 'u' => 'b'], 'c.example' => ['v' => 'ea-php82', 'fpm' => 0, 'u' => 'c']];
$after  = ['a.example' => ['v' => 'alt-php56', 'fpm' => 1, 'u' => 'a'], 'b.example' => ['v' => 'ea-php82', 'fpm' => 1, 'u' => 'b'], 'c.example' => ['v' => 'ea-php82', 'fpm' => 0, 'u' => 'c'], 'd.example' => ['v' => 'ea-php83', 'fpm' => 0, 'u' => 'd']];
$d = smpro_su_php_diff($before, $after);
is_eq(array_keys($d), ['a.example', 'b.example'], 'V1: a changed version and a changed FPM setting are both changes; a new domain is not');
is_eq($d['a.example']['before']['v'] . '>' . $d['a.example']['after']['v'], 'ea-php84>alt-php56', 'V2: before and after are kept');
is_eq(smpro_su_php_putback('../x', 'ea-php84', 0)[0], false, 'V3: a domain is a name, never a path');
is_eq(smpro_su_php_putback('a.example', 'php84', 0)[0], false, 'V3: a version is an ea-/alt- build name');
has($src2, "\$s0 = smpro_su_state(); smpro_su_php_watch(\$s0, 'before the update', false);", 'V4: photographed before the update');
has($src2, "\$rec['php_changed'] = smpro_su_php_watch(\$s1, 'the system update', true);", 'V5: compared after it, and said');
has($src2, "smpro_su_php_watch(\$s, 'since the last look', \$notify);", 'V6: and at every check, because the panel changes versions on its own too');
has($src2, "if (!\$now || \$now['v'] !== \$version || \$now['fpm'] !== (\$fpm ? 1 : 0)) return [false, 'cPanel answered OK but the domain still reads '", 'V7: put back is read back from cPanel, never assumed');
