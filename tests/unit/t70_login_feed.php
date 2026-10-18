<?php
/**
 * t70_login_feed.php — where a SUCCESSFUL sign-in is actually recorded.
 *
 * Every login check in this plugin read /usr/local/cpanel/logs/login_log and looked for "SUCCEEDED LOGIN".
 * Current cPanel never writes that string: login_log carries FAILED and DEFERRED lines, and a session that is
 * granted becomes a NEW line in session_log. Account Audit therefore said "0 successful logins", the foreign
 * sign-in report found nobody, and Country Login Lock scanned and matched nothing — on servers that were being
 * signed into all day. Three all-clears that none of them had any way to earn.
 */
$tmpDir = sys_get_temp_dir();
define('SMPRO_LF_SESSION_LOG', $tmpDir . '/smpro_t70_session_' . getmypid());
define('SMPRO_LF_LOGIN_LOG',   $tmpDir . '/smpro_t70_login_'   . getmypid());

require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/loginfeed.php';

$sess = SMPRO_LF_SESSION_LOG;
$logn = SMPRO_LF_LOGIN_LOG;
$now  = time();
$T    = function ($ago) use ($now) { return date('Y-m-d H:i:s O', $now - $ago); };

file_put_contents($sess, implode("\n", [
    '[' . $T(600) . '] info [cpaneld] 216.189.152.132 NEW shopone:Mz5iDI7Es0LJa2NI address=216.189.152.132,app=cpaneld,creator=shopone,method=handle_form_login,path=form,possessed=0',
    '[' . $T(500) . '] info [whostmgrd] 197.35.200.168 NEW exclusive:LyYk8_IoznHjOTG9 address=197.35.200.168,app=cpaneld,creator=root,method=handle_auth_transfer,path=xfercpanel',
    '[' . $T(400) . '] info [xml-api] internal NEW root:D4Og9KsZnaM3Nhu1:create_user_session address=,app=Whostmgr::API::1::Session,creator=root,method=create_user_session',
    '[' . $T(300) . '] info [whostmgrd] 41.47.38.151 PURGE root:7y3Bo2IAzHhOocwZ tokendenied [Too many token failures (3/3)]',
    '[' . $T(200) . '] info [webmaild] 8.8.4.4 NEW sales:aaaaBBBBccccDDDD address=8.8.4.4,app=webmaild,creator=sales,method=handle_form_login,path=form,possessed=0',
    '[' . date('Y-m-d H:i:s O', $now - 9 * 86400) . '] info [cpaneld] 5.5.5.5 NEW olduser:zzzz address=5.5.5.5,app=cpaneld,creator=olduser,method=handle_form_login,path=form,possessed=0',
]) . "\n");
file_put_contents($logn, implode("\n", [
    '[' . $T(700) . '] info [whostmgrd] 79.110.54.94 - root "POST /login/?login_only=1 HTTP/1.1" FAILED LOGIN whostmgrd: user password incorrect',
    '[' . $T(650) . '] info [cpaneld] 1.2.3.4 - legacy "POST /login/ HTTP/1.1" SUCCEEDED LOGIN cpaneld',
]) . "\n");

/* ---------- U1: a NEW line is read as the login it is ---------- */
$e = smpro_lf_parse_session('[' . $T(600) . '] info [cpaneld] 216.189.152.132 NEW shopone:tok address=216.189.152.132,app=cpaneld,creator=shopone,method=handle_form_login,path=form,possessed=0');
is_eq($e['user'] ?? '',    'shopone',         'U1: the account is read from the NEW line');
is_eq($e['ip'] ?? '',      '216.189.152.132', 'U1: with the address the session was opened from');
is_eq($e['kind'] ?? '',    'password',        'U1: handle_form_login means a password was accepted');
is_eq($e['service'] ?? '', 'cpaneld',         'U1: named by the session created, not the daemon that wrote the line');

/* ---------- U2: a session ending is not a session beginning ---------- */
is_eq(smpro_lf_parse_session('[' . $T(300) . '] info [whostmgrd] 1.1.1.1 PURGE root:x expire'), [], 'U2: a PURGE is not a login');
is_eq(smpro_lf_parse_session('hello'), [], 'U2: an unrelated line is not a login');

/* ---------- U3: the operator is not the customer ---------- */
// If "root opened this customer's cPanel from WHM" counted as a sign-in, the plugin would report the reseller
// to themselves as a compromise every working day, and the real ones would be lost in it.
$op = smpro_lf_parse_session('[' . $T(500) . '] info [whostmgrd] 197.35.200.168 NEW exclusive:t address=197.35.200.168,app=cpaneld,creator=root,method=handle_auth_transfer,path=xfercpanel');
is_eq($op['kind'] ?? '', 'operator', 'U3: WHM "Log in as User" is the operator, no account password used');
$api = smpro_lf_parse_session('[' . $T(400) . '] info [xml-api] internal NEW root:t:create_user_session address=,app=Whostmgr::API::1::Session,creator=root,method=create_user_session');
is_eq($api['kind'] ?? '', 'api', 'U3: an API-minted session is neither');
is_eq($api['ip'] ?? 'x',  '',    'U3: "internal" is not an address — nobody came over the network');
$poss = smpro_lf_parse_session('[' . $T(400) . '] info [cpaneld] 9.9.9.9 NEW bob:t address=9.9.9.9,app=cpaneld,creator=root,method=handle_form_login,possessed=1');
is_eq($poss['kind'] ?? '', 'operator', 'U3: possessed=1 is the operator whatever the method claims');

/* ---------- U4: the older format still works ---------- */
$old = smpro_lf_parse_login('[' . $T(650) . '] info [cpaneld] 1.2.3.4 - legacy "POST /login/ HTTP/1.1" SUCCEEDED LOGIN cpaneld');
is_eq($old['user'] ?? '', 'legacy', 'U4: a login_log success is still read, for cPanel versions that write one');
is_eq(smpro_lf_parse_login('[' . $T(700) . '] info [whostmgrd] 79.110.54.94 - root "POST /x HTTP/1.1" FAILED LOGIN whostmgrd: user password incorrect'),
      [], 'U4: a refusal is not a success');

/* ---------- U5: the feed, both files at once ---------- */
$f = smpro_lf_success($now - 3600);
ok(!empty($f['ok']), 'U5: the feed reads');
$users = array_column($f['events'], 'user');
ok(in_array('shopone', $users, true), 'U5: the cPanel password login is found');
ok(in_array('sales', $users, true),   'U5: the webmail password login is found');
ok(in_array('legacy', $users, true),  'U5: and the legacy login_log one, from the same call');
ok(!in_array('exclusive', $users, true), 'U5: the operator jump is not counted as a customer sign-in');
ok(!in_array('olduser', $users, true),   'U5: nothing older than the window asked for');
$sorted = $f['events'];
usort($sorted, function ($a, $b) { return $a['ts'] <=> $b['ts']; });
is_eq($f['events'], $sorted, 'U5: events come back in time order');

$all = smpro_lf_success($now - 3600, 20000, []);
ok(in_array('exclusive', array_column($all['events'], 'user'), true), 'U5: asking for every kind does include the operator');

/* ---------- U6: could not look is not nothing happened ---------- */
@unlink($sess); @unlink($logn);
$g = smpro_lf_success($now - 3600);
ok(empty($g['ok']), 'U6: with neither log present the feed does NOT report an all-clear');
has((string)$g['msg'], 'not seen', 'U6: and says in words that nothing was checked');
is_eq($g['events'], [], 'U6: no events, and no claim that there were none');

/* ---------- U7: the method alone does not make it a password login ---------- */
// cPanel reuses handle_form_login for sessions DERIVED from an authentication that already happened. Counted by
// method, one live server reported 68 of those as "the account password was accepted" — among them "aaefadh <-
// root" (the operator opening an account) and a dozen mailboxes opened by their own cPanel account. With Country
// Login Lock armed that is an operator blocked and evicted for doing their job.
$mk = function ($method, $path, $creator, $user, $poss = '0') use ($T) {
    return '[' . $T(100) . '] info [cpaneld] 9.9.9.9 NEW ' . $user . ':tok address=9.9.9.9,app=cpaneld,creator='
         . $creator . ',method=' . $method . ',path=' . $path . ',possessed=' . $poss;
};
is_eq(smpro_lf_parse_session($mk('handle_form_login', 'form', 'bob', 'bob'))['kind'],
      'password', 'U7: the login FORM, by the account itself, is a password login');
is_eq(smpro_lf_parse_session($mk('handle_form_login', 'loadsession:bob:x', 'root', 'bob'))['kind'],
      'operator', 'U7: root opening an account is NOT the account password');
is_eq(smpro_lf_parse_session($mk('handle_form_login', 'loadsession:x', 'shop', 'info@shop.com'))['kind'],
      'operator', 'U7: an account opening its own mailbox is NOT the mailbox password');
is_eq(smpro_lf_parse_session($mk('handle_form_login', 'loadsession:bob:x', 'bob', 'bob'))['kind'],
      'restored', 'U7: a session restored for the same identity is not a fresh sign-in');
is_eq(smpro_lf_parse_session($mk('handle_auth_transfer', 'xfercpanel', 'root', 'bob'))['kind'],
      'operator', 'U7: and "Log in as User" stays the operator');

/* ---------- U8: webmail must never be the kind that is silently dropped ---------- */
// It is the commonest compromise route on shared hosting. These methods fell through to 'other', which the
// feed's default filter discards — so a webmail sign-in was collected and then thrown away.
is_eq(smpro_lf_parse_session($mk('CREATE_WEBMAIL_SESSION_FOR_SELF', '-', 'info@shop.com', 'info@shop.com'))['kind'],
      'password', 'U8: a mailbox opening its own webmail IS a password login');
is_eq(smpro_lf_parse_session($mk('CREATE_WEBMAIL_SESSION_FOR_MAIL_USER', '-', 'shop', 'info@shop.com'))['kind'],
      'operator', 'U8: a mailbox opened FOR it by its account is not');
// and the default filter now carries it
file_put_contents(SMPRO_LF_SESSION_LOG, $mk('CREATE_WEBMAIL_SESSION_FOR_SELF', '-', 'boxy@d.com', 'boxy@d.com') . "\n");
file_put_contents(SMPRO_LF_LOGIN_LOG, '');
ok(in_array('boxy@d.com', array_column(smpro_lf_success($now - 3600)['events'], 'user'), true),
   'U8: and the default feed returns it instead of discarding it');
@unlink(SMPRO_LF_SESSION_LOG); @unlink(SMPRO_LF_LOGIN_LOG);
