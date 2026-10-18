<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/georeport.php';
/**
 * t84_gr_counter.php — the threat report says which countries the password WORKED from, and its counter can be
 * reset only after the report is archived; the logs are never touched.
 */
@unlink(smpro_gr_counter_file());
foreach (glob(smpro_gr_archive_dir() . '/*') ?: [] as $f) @unlink($f);
$src = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/georeport.php'));
has($src, "\$acc[\$u][\$ok ? 'ccs_ok' : 'ccs_failed'][\$cc]", 'U1: accepted and failed countries are counted apart');
is_eq(smpro_gr_counter_since(), 0, 'U2: no counter reset yet');
$rep = ['days' => 7, 'allowed' => ['EG'], 'accounts' => [
    ['user' => 'acctone', 'ok' => 2, 'failed' => 5, 'ccs_ok' => ['US' => 2], 'ccs_failed' => ['US' => 4, 'CA' => 1], 'ips' => [['ip' => '203.0.113.9', 'cc' => 'US', 'n' => 6]], 'last' => time()],
]];
$r = smpro_gr_counter_reset($rep, 'tester');
ok($r['ok'], 'U3: reset succeeds when the archive was written (' . $r['msg'] . ')');
$since = smpro_gr_counter_since();
ok($since > 0 && time() - $since < 5, 'U3: the counter now starts from now');
$list = smpro_gr_archives();
is_eq(count($list), 1, 'U3: one archive exists');
is_eq($list[0]['accounts'], 1, 'U3: with the account');
is_eq($list[0]['signed_in'], 1, 'U3: and it is counted as signed in');
$got = smpro_gr_archive_get($list[0]['id']);
is_eq($got['accounts'][0]['user'], 'acctone', 'U3: the archive holds the report as it stood');
$txt = smpro_gr_archive_text($got);
has($txt, 'US (2)', 'U3: the text render lists the country the password worked from');
has($txt, '203.0.113.9 (US) x6', 'U3: and the addresses');
ok(is_file(smpro_gr_archive_dir() . '/' . $list[0]['id'] . '.txt'), 'U3: a text copy sits beside the JSON');
is_eq(smpro_gr_archive_get('../etc/passwd'), null, 'U4: an archive id is digits and underscores only');
hasnt($src, 'unlink(', 'U5: nothing in the report code deletes a file');
hasnt($src, 'login_log\', \'w', 'U5: nothing writes the login log');
$page = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/firewall-status.php'));
has($page, "accepted</b> from '+ccList(a.ccs_ok,4)+'", 'U6: the table names the countries the password worked from');
has($page, "fd.set('fw_action','gr_counter_reset')", 'U6: the counter button posts the current report to be archived first');
has($page, 'No log file is deleted or changed', 'U6: and says so');
