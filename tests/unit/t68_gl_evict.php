<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/geologin.php';
/**
 * t68_gl_evict.php — a correct password used from a country you do not allow means somebody is inside NOW.
 *
 * The lock wrote a firewall rule and stopped there. That closes the door for the NEXT connection and leaves the
 * attacker on the current one, working, for as long as they care to stay. Three separate things have to end,
 * because "a session" is three different objects on a cPanel server, and killing one leaves the others alive.
 */

/* ---------- U1: all three, and the reason each exists ---------- */
foreach ([
    'smpro_gl_kill_sockets'        => 'the TCP connections',
    'smpro_gl_kill_panel_sessions' => 'the cPanel/WHM session tokens',
    'smpro_gl_kill_procs'          => 'the processes still serving it',
    'smpro_gl_evict'               => 'the whole response, in order',
] as $fn => $what) {
    ok(function_exists($fn), 'U1: ' . $what . ' can be ended (' . $fn . ')');
}

$src = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/geologin.php'));
has($src, 'A panel session survives a dropped socket',
    'U1: with the reason the socket alone is not enough written down');

/* ---------- U2: the door is closed BEFORE the socket is dropped ---------- */
// The other order leaves a gap between the connection dying and the rule existing, and a script reconnects
// inside it every time.
$iBlock = strpos($src, '$b = smpro_gl_block($ip, $cc, $account, $cfg);');
$iKill  = strpos($src, "\$res['sockets'] = smpro_gl_kill_sockets(\$ip);");
ok($iBlock !== false && $iKill !== false && $iBlock < $iKill,
   'U2: blocked first, evicted second — a script wins the race the other way round');

/* ---------- U3: nothing is killed on a guess ---------- */
foreach (['', 'not-an-ip', '999.1.1.1'] as $bad) {
    $r = smpro_gl_kill_sockets($bad);
    nok($r['ok'], 'U3: sockets are not touched for "' . ($bad === '' ? '(empty)' : $bad) . '"');
    $r2 = smpro_gl_kill_panel_sessions($bad);
    nok($r2['ok'], 'U3: nor are panel sessions');
    $r3 = smpro_gl_kill_procs($bad);
    nok($r3['ok'], 'U3: nor are processes');
}
$r = smpro_gl_evict('not-an-ip', 'XX', 'someone', smpro_gl_defaults());
nok($r['ok'], 'U3: and the whole eviction refuses an address it cannot validate');

/* ---------- U4: a process is not killed just because it talks to that address ---------- */
// A database, a backup agent or a monitoring probe can hold a connection to the same address. Only the daemons
// that actually serve a login session are candidates.
has($src, "in_array(\$base, ['sshd', 'pure-ftpd', 'proftpd', 'vsftpd', 'cpsrvd'",
    'U4: only session-serving daemons are candidates');
// The needle stays inside ONE line: the sentence wraps in the source, and a needle that spans the wrap
// fails for a formatting reason rather than a real one.
has($src, 'is not a licence to kill an', 'U4: with the reason recorded');
has($src, 'unset($pids[$me], $pids[1]);', 'U4: and never this process or init');

/* ---------- U5: the session store is matched on the RIGHT field ---------- */
// Session files record both the client's address and the SERVER's. Matching the server's would sign every user
// on the box out at once.
has($src, "preg_match('/^ip_address=(\S+)/m'", 'U5: the client address is read as a field');
has($src, "matching that would\n            // sign every single user out", 'U5: with the trap that avoids named');

/* ---------- U6: "could not" is never reported as "did" ---------- */
// ss -K needs a kernel built with INET_DIAG_DESTROY. Where it is missing the connection stays up, and saying
// the session was ended would be a lie told at the worst possible moment.
has($src, 'no INET_DIAG_DESTROY', 'U6: an unsupported kernel is detected');
has($src, 'the connection was NOT dropped', 'U6: and said plainly');
has($src, "'socket_msg'", 'U6: and recorded, so a night it could not act is visible afterwards');

/* ---------- U7: it is the default, and it is reachable from the page ---------- */
$d = smpro_gl_defaults();
ok(!empty($d['evict']), 'U7: ending the session is the default response to a successful foreign sign-in');
$fw = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/firewall-status.php'));
has($fw, 'glEvict', 'U7: the operator can turn it off');
has($fw, "'evict'      => !empty(\$_POST['evict'])", 'U7: and the choice is stored');

/* ---------- U8: only a SUCCESSFUL sign-in evicts ---------- */
// A wrong password from a country not allowed is noise. Ending sessions over it would let anyone disconnect an
// account by failing to log into it from abroad.
has($src, "if (!empty(\$cfg['evict']) && \$ok) {", 'U8: eviction requires the password to have been accepted');

/* ---------- U9: a session file this build cannot read is not an empty session store ---------- */
// cPanel changed the session file from key=value lines to a single JSON object. Reading only the old shape meant
// eviction ended 0 sessions on a current server and reported that as success: the block went up and whoever was
// already signed in stayed signed in behind it, on the one session that mattered.
has($src, "json_decode(\$body, true)",       'U9: the JSON session format is read');
has($src, "preg_match('/^ip_address=(\S+)/m'", 'U9: and the older key=value one still is');
has($src, 'none of the',                     'U9: "0 ended" says so when NOTHING could be understood');
has($src, "isset(\$j['ip_address'])",        'U9: matched on the client address field, never a substring search');
hasnt($src, "strpos(\$body, \$ip)",          'U9: and never by searching the file for the address');
