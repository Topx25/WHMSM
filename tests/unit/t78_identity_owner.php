<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/georeport.php';
/**
 * t78_identity_owner.php — a mailbox is an identity; its owner is the account. Neither is ever mangled.
 *
 * THE INCIDENT. Country Login Lock's report showed "yousefexample.com IN - 12 accepted" and the bulk reset
 * answered "yousefexample.com - not a cPanel account on this server". The identity was yousef@example.com: a
 * mailbox that signed in through webmail from a country outside the list, twelve times, with the right
 * password. Seven cleaners in the report code stripped the "@" - so the page showed a name that exists nowhere,
 * and the reset refused it - and the sign-ins that most needed a reset were exactly the ones it skipped.
 */

/* ---------- U1: '@' survives every cleaner in the report code ---------- */
$src = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/georeport.php'));
hasnt($src, "preg_replace('/[^a-zA-Z0-9._-]/', ''", 'U1: no cleaner in georeport.php strips @ any more');
ok(substr_count($src, "preg_replace('/[^a-zA-Z0-9._@-]/', ''") >= 7, 'U1: the seven that did now keep it');

/* ---------- U2: an identity resolves to the account that owns it ---------- */
$map = SMPRO_VARLIB . '/t78_userdatadomains';
@is_dir(SMPRO_VARLIB) || @mkdir(SMPRO_VARLIB, 0700, true);
file_put_contents($map, implode("\n", [
    'example.com: shopone==root==main==example.com==203.0.113.10:80==203.0.113.10:443',
    'mail.example.com: shopone==root==sub==example.com==203.0.113.10:80==',
    'other.test: shoptwo==root==main==other.test==203.0.113.11:80==',
]) . "\n");
// smpro_is_cpanel_user is not loaded here (helpers not required), so the resolver trusts the map
$r = smpro_gr_owner_of('yousef@example.com', $map);
is_eq($r['account'], 'shopone', 'U2: a mailbox resolves to the account that owns its domain');
is_eq($r['mailbox'], 'yousef@example.com', 'U2: and keeps its own name, @ and all');
$r = smpro_gr_owner_of('Info@Example.COM', $map);
is_eq($r['account'], 'shopone', 'U2: case does not matter for the domain');
$r = smpro_gr_owner_of('nobody@unknown.test', $map);
is_eq($r['account'], '', 'U2: a mailbox on a domain nobody here owns resolves to no account');
is_eq($r['mailbox'], 'nobody@unknown.test', 'U2: but is still named as a mailbox, so the message can say why');
$r = smpro_gr_owner_of('shoptwo', $map);
is_eq($r['account'], 'shoptwo', 'U2: an account name is its own owner');
is_eq($r['mailbox'], '', 'U2: and is not a mailbox');
is_eq(smpro_gr_owner_of('', $map)['account'], '', 'U2: nothing resolves to nothing');
@unlink($map);

/* ---------- U3: the bulk reset goes through the resolver, and says so ---------- */
has($src, '$o = smpro_gr_owner_of($u);', 'U3: every identity handed to the reset is resolved first');
has($src, "\$res['plan'] = \$plan;", 'U3: and the exact plan (identity, kind, owner) is returned to the page');
has($src, "no account on this server owns that mailbox\\'s domain", 'U3: a mailbox nobody owns gets a message that says mailbox, not "not an account"');
$page = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/firewall-status.php'));
has($page, "<b>Changed ('+j.done.length+'):</b>", 'U3: the page lists exactly what changed');
