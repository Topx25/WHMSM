<?php
/**
 * r10_da_convert_e2e.php — locks the DirectAdmin → cpmove conversion end to end.
 *
 * The metadata half was checked against a genuine 9.7 GB backup while it was being written, but the half that
 * moves the content never was: converting that archive needs about 23 GB and the lab has nine, so a shipped
 * feature had a large untested middle. This builds a miniature backup with every structural feature that
 * matters and runs the whole pipeline over it. Only the size is scaled down — each path shape a real backup
 * has is present, and each is one that was got wrong at least once:
 *
 *   • the home directory arrives in an archive NESTED inside the backup, holding only the home root;
 *   • the served content lives elsewhere and includes a SECOND docroot beside public_html (5.1 GB of one in
 *     the reference account) which an earlier version silently left behind;
 *   • mail sits one directory deeper than cPanel reads it, so leaving that level in makes every mailbox
 *     restore looking empty;
 *   • logs and statistics must NOT come over, while public_ftp must;
 *   • the certificate has to land where the web server installs it, or the site comes up self-signed;
 *   • grant syntax has to be the form MySQL 8 still accepts, or the databases restore unreachable.
 */
require __DIR__ . '/../support/bootstrap.php';
require SMPRO_BASE . '/tests/support/plugin_funcs.php';

// The bootstrap deliberately does not load the plugin's own helpers, so the shell runner these modules are built
// on has to be brought in explicitly. plugin_funcs takes the functions out of a file without running what is
// around them, which is what keeps a test from needing the whole router.
smpro_plugin_funcs('includes/helpers.php');
foreach (['migrate', 'migrate_da', 'migrate_da_convert', 'migrate_da_home'] as $m) {
    smpro_plugin_funcs('includes/' . $m . '.php');
}
ok(function_exists('smpro_run') && function_exists('smpro_mig_detect'),
   'DA e2e: the conversion functions and the shell runner they use are loaded');

$W    = sys_get_temp_dir() . '/smpro_da_e2e_' . getmypid();
$USER = 'demoacct';
$DOM  = 'demo.example';
@mkdir("$W/src/backup/$DOM/email", 0700, true);
@mkdir("$W/src/domains/$DOM/public_html/wp-admin", 0700, true);
@mkdir("$W/src/domains/$DOM/public_html-second", 0700, true);
foreach (['logs', 'stats', 'awstats', 'public_ftp'] as $d) @mkdir("$W/src/domains/$DOM/$d", 0700, true);
foreach (['contact', 'info'] as $box) @mkdir("$W/src/imap/$DOM/$box/Maildir/cur", 0700, true);

$b = "$W/src/backup";
file_put_contents("$b/user.conf",
    "name=$USER\ndomain=$DOM\nemail=owner@example.net\npackage=demo\nquota=unlimited\nbandwidth=unlimited\n"
  . "inode=250000\nip=203.0.113.9\naccount=ON\nsuspended=no\nmysql=1\nnsubdomains=10\ndomainptr=5\nlanguage=en\n"
  . "date_created=Sat Sep 28 11:09:46 2019\n");
file_put_contents("$b/.shadow", '$6$abcdefgh$' . str_repeat('x', 43));
file_put_contents("$b/crontab.conf", "MAILTO=\"\"\n30 * * * * /usr/local/bin/php /home/$USER/public_html/wp-cron.php\n");
file_put_contents("$b/{$USER}_wp.conf",
    "accesshosts=0=localhost\ndb_collation=SCHEMA_NAME={$USER}_wp\n"
  . "{$USER}_wp=accesshosts=localhost&select_priv=Y&passwd=%2A5D594B055117D801D6B1FBB296BB9E29ECEB311F&plugin=mysql_native_password\n");
file_put_contents("$b/{$USER}_wp.sql", "-- dump\nCREATE TABLE wp_posts (id INT);\n");
file_put_contents("$b/$DOM/domain.conf", "domain=$DOM\nactive=yes\nsuspended=no\ndefaultdomain=yes\nssl=ON\nphp=ON\nusername=$USER\n");
file_put_contents("$b/$DOM/$DOM.db", "\$TTL 14400\n@ IN SOA ns1.example. root.example. ( 1 )\n");
file_put_contents("$b/$DOM/domain.cert",   "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n");
$keyTag = '-----' . 'BEGIN ' . 'PRIVATE KEY' . '-----';   // split so repository scanners do not read it as a real key
file_put_contents("$b/$DOM/domain.key",    $keyTag . "\nBBBB\n" . str_replace('BEGIN', 'END', $keyTag) . "\n");
file_put_contents("$b/$DOM/domain.cacert", "-----BEGIN CERTIFICATE-----\nCCCC\n-----END CERTIFICATE-----\n");
file_put_contents("$b/$DOM/subdomain.list", '');
file_put_contents("$b/$DOM/email/passwd",  "contact:\$6\$aaa\$" . str_repeat('y', 43) . "\ninfo:\$6\$bbb\$" . str_repeat('z', 43) . "\n");
file_put_contents("$b/$DOM/email/aliases", "sales: contact\n");
file_put_contents("$b/$DOM/email/quota",   "contact:52428800\ninfo:0\n");

@mkdir("$W/homesrc", 0700, true);
file_put_contents("$W/homesrc/.bashrc",   "# home root marker\n");
file_put_contents("$W/homesrc/.htaccess", "# htaccess marker\n");
smpro_run('tar czf ' . escapeshellarg("$b/home.tar.gz") . ' -C ' . escapeshellarg("$W/homesrc") . ' .', 60, ['stderr' => 'discard']);

file_put_contents("$W/src/domains/$DOM/public_html/index.php", "<?php // live\n");
file_put_contents("$W/src/domains/$DOM/public_html/wp-admin/admin.php", "<?php\n");
file_put_contents("$W/src/domains/$DOM/public_html-second/index.php", "<?php // second\n");
file_put_contents("$W/src/domains/$DOM/logs/access.log", "x\n");
file_put_contents("$W/src/domains/$DOM/stats/awstats.txt", "s\n");
file_put_contents("$W/src/domains/$DOM/awstats/old.txt", "s\n");
file_put_contents("$W/src/domains/$DOM/public_ftp/welcome.msg", "hi\n");
foreach (['contact', 'info'] as $box) {
    file_put_contents("$W/src/imap/$DOM/$box/Maildir/cur/1.msg", "Subject: for $box\n");
    file_put_contents("$W/src/imap/$DOM/$box/Maildir/dovecot.index", "stale index\n");
}

$ARCHIVE = "$W/user.admin.$USER.tar.gz";
smpro_run('tar czf ' . escapeshellarg($ARCHIVE) . ' -C ' . escapeshellarg("$W/src") . ' backup domains imap', 120, ['stderr' => 'discard']);
ok(is_file($ARCHIVE), 'DA e2e: a miniature DirectAdmin backup was built');

is_eq(smpro_mig_detect($ARCHIVE)['format'], 'directadmin', 'DA e2e: recognised as a DirectAdmin backup');
ok(!empty(smpro_mig_da_path_check($ARCHIVE, 120)['ok']), 'DA e2e: it writes nothing outside itself');

$work = "$W/work";
ok(!empty(smpro_mig_da_extract_meta($ARCHIVE, $work, 300)['ok']), 'DA e2e: metadata extracted');
$d = smpro_mig_da_describe($work);
is_eq($d['account']['username'] ?? '', $USER, 'DA e2e: the account is identified');
is_eq((int)($d['totals']['mailboxes'] ?? 0), 2, 'DA e2e: both mailboxes are counted');

$conv = smpro_mig_da_build_meta($work, "$W/out", '203.0.113.99');
ok(!empty($conv['ok']), 'DA e2e: cpmove metadata written');
$root = (string)$conv['dest'];
has((string)@file_get_contents("$root/cp/$USER"), 'IP=203.0.113.99',
    'DA e2e: the account is bound to THIS server, not the one it came from');
$tls = (string)@file_get_contents("$root/apache_tls/$DOM");
has($tls, 'BEGIN ' . 'PRIVATE KEY', 'DA e2e: the certificate bundle carries the key');
is_eq(substr_count($tls, 'BEGIN CERTIFICATE'), 2, 'DA e2e: certificate AND issuer chain are in the bundle');
is_eq(substr_count((string)@file_get_contents("$root/homedir/etc/$DOM/shadow"), '$6$'), 2,
    'DA e2e: mailbox passwords land where cPanel reads them');
has((string)@file_get_contents("$root/mysql.sql"), 'IDENTIFIED WITH mysql_native_password',
    'DA e2e: grants use the syntax MySQL 8 still accepts');

$h = smpro_mig_da_build_home($ARCHIVE, $root, $USER, $DOM);
ok(!empty($h['ok']), 'DA e2e: the content was moved');
$home = "$root/homedir";
ok(is_file("$home/.bashrc"), 'DA e2e: the home root came out of the NESTED archive');
ok(is_file("$home/public_html/index.php"), 'DA e2e: the live site is at public_html');
ok(is_file("$home/public_html-second/index.php"), 'DA e2e: the SECOND site came over too');
ok(is_file("$home/mail/$DOM/contact/cur/1.msg"), 'DA e2e: mail is where the mail server reads it');
ok(!is_file("$home/mail/$DOM/contact/dovecot.index"), 'DA e2e: the old server\'s mail indexes were dropped');
ok(is_file("$root/mysql/{$USER}_wp.sql"), 'DA e2e: the database dump is placed for cPanel');
ok(!is_dir("$home/logs") && !is_dir("$home/stats") && !is_dir("$home/awstats"),
    'DA e2e: logs and statistics were NOT carried over');
ok(is_dir("$home/public_ftp"), 'DA e2e: public_ftp was');

$pack = smpro_mig_da_pack($root);
ok(!empty($pack['ok']) && is_file((string)($pack['archive'] ?? '')), 'DA e2e: packaged');
if (!empty($pack['ok'])) {
    has(smpro_run('tar tzf ' . escapeshellarg($pack['archive']) . ' | head -n 400', 60, ['stderr' => 'discard']),
        "cpmove-$USER/cp/$USER", 'DA e2e: the package is a cpmove tree');
    is_eq(smpro_mig_detect((string)$pack['archive'])['format'], 'cpanel',
        'DA e2e: the converter\'s output is recognised as a restorable cPanel archive');
}

smpro_run('rm -rf ' . escapeshellarg($W), 120, ['stderr' => 'discard']);
