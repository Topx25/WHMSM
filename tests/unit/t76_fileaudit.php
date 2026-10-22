<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/fileaudit.php';
/**
 * t76_fileaudit.php — who changed a file, through which door, from which address, when.
 *
 * THE GAP. An operator asked the investigation page who deleted or changed an account's files and it could not
 * say: the File Manager's deletes travel in a POST body the access log does not record, FTP never writes a DELE
 * anywhere and its transfer log is destroyed within minutes, SSH leaves nothing. So the evidence is made by the
 * kernel (auditd) and collected every minute into the plugin's own store, with the address joined from the log
 * that knows it. These records are REAL ones, copied from a production server and a lab box.
 */

/* ---------- fixtures: real audit events ---------- */
$evShellDelete = [
    'type=SYSCALL msg=audit(1789909178.966:1468783): arch=c000003e syscall=263 success=yes exit=0 a0=ffffff9c a1=5622060a4630 a2=0 a3=100 items=2 ppid=2335887 pid=2335888 auid=0 uid=1005 gid=1006 euid=1005 suid=1005 fsuid=1005 egid=1006 sgid=1006 fsgid=1006 tty=(none) ses=145117 comm="rm" exe="/usr/bin/rm" key="smpro_files_del"ARCH=x86_64 SYSCALL=unlinkat AUID="root" UID="accttwo" GID="accttwo" EUID="accttwo" SUID="accttwo" FSUID="accttwo" EGID="accttwo" SGID="accttwo" FSGID="accttwo"',
    'type=CWD msg=audit(1789909178.966:1468783): cwd="/root"',
    'type=PATH msg=audit(1789909178.966:1468783): item=0 name="/home/accttwo/public_html/smpro_t/" inode=653919 dev=08:01 mode=040755 ouid=1005 ogid=1006 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0OUID="accttwo" OGID="accttwo"',
    'type=PATH msg=audit(1789909178.966:1468783): item=1 name="/home/accttwo/public_html/smpro_t/b.txt" inode=664192 dev=08:01 mode=0100644 ouid=1005 ogid=1006 rdev=00:00 nametype=DELETE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0OUID="accttwo" OGID="accttwo"',
    'type=PROCTITLE msg=audit(1789909178.966:1468783): proctitle=726D002F686F6D65',
];
// proftpd under DefaultRoot: the kernel saw cwd "/" and a jail-relative name. auid unset, uid = the account.
$evFtpDelete = [
    'type=SYSCALL msg=audit(1789909878.787:412652712): arch=c000003e syscall=87 success=yes exit=0 a0=559beeba10f8 a1=559bedc928f4 a2=5 a3=a items=2 ppid=928847 pid=3232781 auid=4294967295 uid=1110 gid=1114 euid=1110 suid=1110 fsuid=1110 egid=1114 sgid=1114 fsgid=1114 tty=(none) ses=4294967295 comm="proftpd" exe="/usr/sbin/proftpd" subj=kernel key="smpro_files_del"ARCH=x86_64 SYSCALL=unlink AUID="unset" UID="acctone" GID="acctone" EUID="acctone" SUID="acctone" FSUID="acctone" EGID="acctone" SGID="acctone" FSGID="acctone"',
    'type=CWD msg=audit(1789909878.787:412652712): cwd="/"',
    'type=PATH msg=audit(1789909878.787:412652712): item=0 name="/" inode=2 dev=09:05 mode=040755 ouid=1110 ogid=1114 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0OUID="acctone" OGID="acctone"',
    'type=PATH msg=audit(1789909878.787:412652712): item=1 name="fa_up.txt" inode=1234 dev=09:05 mode=0100644 ouid=1110 ogid=1114 rdev=00:00 nametype=DELETE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0OUID="acctone" OGID="acctone"',
];
$evCpanelRename = [
    'type=SYSCALL msg=audit(1789909637.100:412640001): arch=c000003e syscall=82 success=yes exit=0 a0=1 a1=2 a2=5 a3=10 items=4 ppid=928979 pid=3220001 auid=4294967295 uid=1110 gid=1114 euid=1110 suid=1110 fsuid=1110 egid=1114 sgid=1114 fsgid=1114 tty=(none) ses=4294967295 comm="cpanel" exe="/usr/local/cpanel/cpanel" subj=kernel key="smpro_files_door"ARCH=x86_64 SYSCALL=rename AUID="unset" UID="acctone"',
    'type=CWD msg=audit(1789909637.100:412640001): cwd="/home2/acctone/public_html/smpro_t"',
    'type=PATH msg=audit(1789909637.100:412640001): item=0 name="/home2/acctone/public_html/smpro_t/" inode=1 dev=09:05 mode=040755 ouid=1110 ogid=1114 rdev=00:00 nametype=PARENT',
    'type=PATH msg=audit(1789909637.100:412640001): item=1 name="/home2/acctone/public_html/smpro_t/" inode=1 dev=09:05 mode=040755 ouid=1110 ogid=1114 rdev=00:00 nametype=PARENT',
    'type=PATH msg=audit(1789909637.100:412640001): item=2 name=".tmp.14fd3.edited.txt" inode=2 dev=09:05 mode=0100644 ouid=1110 ogid=1114 rdev=00:00 nametype=DELETE',
    'type=PATH msg=audit(1789909637.100:412640001): item=3 name="edited.txt" inode=2 dev=09:05 mode=0100644 ouid=1110 ogid=1114 rdev=00:00 nametype=CREATE',
];
$evFailed = [str_replace('success=yes', 'success=no', $evShellDelete[0]), $evShellDelete[1], $evShellDelete[2], $evShellDelete[3]];
$evWebDelete = [
    'type=SYSCALL msg=audit(1789909700.000:412641000): arch=c000003e syscall=87 success=yes exit=0 a0=1 a1=2 a2=5 a3=a items=2 ppid=1 pid=3220100 auid=4294967295 uid=1110 gid=1114 euid=1110 suid=1110 fsuid=1110 egid=1114 sgid=1114 fsgid=1114 tty=(none) ses=4294967295 comm="php-fpm" exe="/opt/cpanel/ea-php82/root/usr/sbin/php-fpm" subj=kernel key="smpro_files_del"ARCH=x86_64 SYSCALL=unlink AUID="unset" UID="acctone"',
    'type=CWD msg=audit(1789909700.000:412641000): cwd="/home2/acctone/public_html"',
    'type=PATH msg=audit(1789909700.000:412641000): item=1 name="/home2/acctone/public_html/wp-config.php" inode=3 dev=09:05 mode=0100644 ouid=1110 ogid=1114 rdev=00:00 nametype=DELETE',
];

/* ---------- U1: a shell delete is read whole: who, what, where, session ---------- */
$r = smpro_fa_parse_event($evShellDelete);
ok(is_array($r), 'U1: the event parses');
is_eq($r['op'], 'deleted', 'U1: unlinkat + nametype=DELETE is a deletion');
is_eq($r['path'], '/home/accttwo/public_html/smpro_t/b.txt', 'U1: the deleted path');
is_eq($r['account'], 'accttwo', 'U1: the account is the owner of the home the path is in');
is_eq($r['actor'], 'accttwo', 'U1: the actor is the uid that did it (interpreted by auditd)');
is_eq($r['login'], 'root', 'U1: the login it happened under (auid) is kept - root su-ing to the account is root');
is_eq($r['door'], 'shell', 'U1: a login session is the shell door');
is_eq($r['ses'], '145117', 'U1: the session id is kept for the address join');
is_eq($r['ts'], 1789909178, 'U1: the time is the kernel\'s, to the second');

/* ---------- U2: a failed attempt changed nothing and is not a record ---------- */
ok(smpro_fa_parse_event($evFailed) === null, 'U2: success=no is dropped - an attempt is not a change');

/* ---------- U3: FTP is jailed; the record still finds its account ---------- */
// THIS IS THE ONE THAT FAILED FIRST. proftpd reports cwd "/" and "fa_up.txt"; the built path "/fa_up.txt" was
// nobody's, the record was dropped, and four real FTP operations on a production server collected as nothing.
if (function_exists('posix_getpwuid')) {
    $r = smpro_fa_parse_event($evFtpDelete);
    ok(is_array($r), 'U3: the jailed event parses');
    is_eq($r['door'], 'ftp', 'U3: proftpd is the FTP door');
    // uid 1110 is not an account on the test box, so the fallback cannot name it here. What is locked: the jailed
    // name is never attributed to a WRONG account, and when the uid IS an account the record is flagged as jailed
    // so the join can put the login's home back in front of the path.
    is_eq($r['path'], '/fa_up.txt', 'U3: the jail-relative name is kept as the kernel gave it, for the join to complete');
    ok($r['account'] === '' || !empty($r['chroot']), 'U3: either unattributed (dropped later) or attributed by uid AND flagged as jailed - never a guess');
} else {
    ok(true, 'U3: (posix unavailable here - the lab gate runs this)');
}
$src = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/fileaudit.php'));
has($src, "@is_file('/var/cpanel/users/' . \$n)", 'U3: the account is taken from the uid when the path is jailed');
has($src, 'USER ([^\\s:]+): Login successful', 'U3: the FTP login name comes from proftpd\'s own login line, by pid');
has($src, "rtrim(\$home, '/') . \$rec['path']", 'U3: and the jail is put back in front of the path');

/* ---------- U4: the File Manager editor: a save is a rename from its temp file ---------- */
$r = smpro_fa_parse_event($evCpanelRename);
is_eq($r['door'], 'cpanel', 'U4: /usr/local/cpanel/cpanel with no login session is the File Manager door');
is_eq($r['op'], 'renamed', 'U4: rename + CREATE is a rename');
is_eq($r['path'], '/home2/acctone/public_html/smpro_t/edited.txt', 'U4: the file that now exists');
is_eq($r['from'], '/home2/acctone/public_html/smpro_t/.tmp.14fd3.edited.txt', 'U4: and what it was renamed from (relative names resolved against cwd)');
is_eq($r['account'], 'acctone', 'U4: on /home2, not a guessed /home');

/* ---------- U5: a web delete is recorded with its door and no invented address ---------- */
$r = smpro_fa_parse_event($evWebDelete);
is_eq($r['door'], 'web', 'U5: php-fpm is the web door');
is_eq($r['op'], 'deleted', 'U5: and the delete is kept - it is the one that matters for "who removed my files"');
is_eq($r['ip'], '', 'U5: with no address invented for it');

/* ---------- U6: the door is decided by the login state before the binary ---------- */
is_eq(smpro_fa_door('/usr/local/cpanel/uapi', 'uapi', '0', '1'), 'shell', 'U6: `uapi` typed by root over ssh is a shell action, not the File Manager');
is_eq(smpro_fa_door('/usr/local/cpanel/cpanel', 'cpanel', 'unset', '1'), 'cpanel', 'U6: the cpanel binary with no login session is the File Manager');
is_eq(smpro_fa_door('/usr/libexec/openssh/sftp-server', 'sftp-server', '1005', '1'), 'sftp', 'U6: sftp-server is SFTP even inside a session');
is_eq(smpro_fa_door('/usr/sbin/proftpd', 'proftpd', 'unset', '1'), 'ftp', 'U6: proftpd is FTP');
is_eq(smpro_fa_door('/usr/sbin/exim', 'exim', 'unset', '1'), 'system', 'U6: the mail server is system machinery');

/* ---------- U7: noise is machinery, not a person ---------- */
ok(smpro_fa_is_noise('/home2/x/public_html/wp-content/cache/page.html'), 'U7: a cache file is noise');
ok(smpro_fa_is_noise('/home2/x/public_html/edited.txt.lock-1e9781effe1b6-1b73b8a5f-79bcef'), 'U7: the editor\'s lock file is noise');
ok(smpro_fa_is_noise('/home2/x/mail/new/1234.mail'), 'U7: mail delivery is noise');
ok(!smpro_fa_is_noise('/home2/x/public_html/wp-config.php'), 'U7: wp-config.php is not');
ok(!smpro_fa_is_noise('/home2/x/public_html/index.php'), 'U7: index.php is not');

/* ---------- U8: the rules are built from the server, not from memory ---------- */
$rules = smpro_fa_rules_text(['/home', '/home2'], ['ftp' => ['/usr/sbin/proftpd'], 'cpanel' => ['/usr/local/cpanel/cpanel']], true);
has($rules, '-F dir=/home2 -k smpro_files_del', 'U8: every home root gets the delete rule');
has($rules, '-F dir=/home -F perm=w -F auid!=unset -k smpro_files_ses', 'U8: writes from a login session');
has($rules, '-F exe=/usr/sbin/proftpd -k smpro_files_door', 'U8: writes by the FTP daemon, by its executable');
hasnt($rules, 'php-fpm', 'U8: web writes are deliberately not watched - a busy site would rotate the log in minutes');
$noWrites = smpro_fa_rules_text(['/home'], ['ftp' => ['/usr/sbin/proftpd']], false);
hasnt($noWrites, 'perm=w', 'U8: with writes off only deletes are watched');
is_eq(smpro_fa_rules_text(['/home'], ['x' => ['/a']], true), smpro_fa_rules_text(['/home'], ['x' => ['/a']], true), 'U8: deterministic, so an unchanged rule set is never rewritten');
hasnt($rules, 'efadh', 'U8: no customer name in the rules text');

/* ---------- U9: could-not-look is a result, never an empty table ---------- */
$st = smpro_fa_status();
ok(isset($st['ok'], $st['why'], $st['state']), 'U9: status always says ok/why/state');
if (!$st['ok']) ok($st['why'] !== '', 'U9: and a "no" always carries its reason (' . $st['why'] . ')');
else ok(true, 'U9: (auditd fully working on the test host)');
$ev = smpro_fa_events('nobody_' . uniqid(), time() - 3600, time());
is_eq($ev['events'], [], 'U9: an unknown account has no records');
ok(isset($ev['ok']) && isset($ev['why']), 'U9: but the answer still says whether it could look');
$mod = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/user-investigation.php'));
has($mod, 'Could not look.', 'U9: the page shows the blind state as a banner');
has($mod, "This is not \"no changes\".", 'U9: and says explicitly that blind is not empty');
has($mod, 'Recording began', 'U9: and a window that starts before recording did is said to be partial');

/* ---------- U10: the collector is a worker that is scheduled and not gated on the plugin switch ---------- */
$tick = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/bin/fileaudit_tick.php'));
hasnt($tick, 'smpro_ctl_disabled()) exit', 'U10: the tick keeps collecting when the plugin is switched off - that history is the one that gets asked for');
$cs = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/bin/cron_sync.php'));
has($cs, "'file changes'       => 'smpro_fa_cron_sync'", 'U10: cron sync installs it');
has($cs, "'evship', 'fileaudit', 'learn', 'sysupd', 'slmaint', 'lvelimits']", 'U10: and loads the module so the function exists when it looks');
