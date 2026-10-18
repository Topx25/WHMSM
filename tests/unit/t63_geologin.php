<?php
/**
 * t63_geologin.php — Country Login Lock: it must close login doors without ever closing a website.
 *
 * The attack it stops is a CORRECT password used by the wrong person: no failed attempts, no brute force, nothing
 * for any other rule to catch. The only thing wrong is where it came from.
 *
 * The danger it must not become is the one this estate already lived through: CSF's CC_ALLOW_FILTER country
 * filter took sites down and killed every WhatsApp webhook. So the assertions below are mostly about restraint —
 * ports 80 and 443 unreachable by any setting, no country denied in advance, and a refusal to arm when arming
 * would lock the operator out of their own panel.
 */
require __DIR__ . '/../support/bootstrap.php';
require SMPRO_BASE . '/tests/support/plugin_funcs.php';
smpro_plugin_funcs('includes/geologin.php');

$src = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/geologin.php'));
// The card lives on the Firewall page: a country rule is a firewall rule, and an operator looking for one
// looks there. It was briefly on the account-protection page, which is where the per-account file locks live.
$pg  = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/firewall-status.php'));

/* ---------- G1: a website is never affected. This is the whole safety case ---------- */
$all = smpro_gl_services();
$ports = [];
foreach ($all as $s) foreach ($s['ports'] as $p) $ports[] = (int)$p;
ok(!in_array(80, $ports, true),  'G1: port 80 is not in the catalogue of doors this can close');
ok(!in_array(443, $ports, true), 'G1: nor is 443');
// And not merely absent from the list — unreachable even if the stored config were edited by hand.
$evil = smpro_gl_ports_for(['services' => array_keys($all) + ['x' => 'http', 'y' => 'https']]);
ok(!in_array(80, $evil, true) && !in_array(443, $evil, true),
   'G1: a tampered service list still cannot produce 80 or 443 — they are stripped after the lookup');
has($src, 'unset($ports[80], $ports[443]);', 'G1: stripped explicitly, as a second line of defence');
has($src, 'there is no setting that can add them', 'G1: and the reason is written where the list is');
ok(smpro_gl_ports_for(['services' => []]) === [], 'G1: no service selected means no port at all');

/* ---------- G2: the rule is port-scoped, so it cannot become a whole-address block ---------- */
$lines = smpro_gl_rule_lines('203.0.113.9', [2083, 22], 'why');
is_eq(count($lines), 2, 'G2: one rule line per port, not one blanket rule');
has($lines[0], 'tcp|in|d=2083|s=203.0.113.9', 'G2: CSF advanced syntax — this port, from this address');
has($lines[0], SMPRO_GL_MARK, 'G2: every line carries our marker so it can be removed exactly');
foreach ($lines as $l) ok(strpos($l, 'd=80|') === false && strpos($l, 'd=443|') === false, 'G2: no web port in a rule line');

/* ---------- G3: it refuses to lock its owner out ---------- */
$base = smpro_gl_defaults();
$none = smpro_gl_arm_check(array_replace($base, ['countries' => [], 'services' => ['cpanel']]), '203.0.113.5');
ok(!$none['ok'], 'G3: an empty country list refuses to arm');
has(implode(' ', $none['problems']), 'nobody at all may sign in', 'G3: ...because it would mean exactly that');

$nosvc = smpro_gl_arm_check(array_replace($base, ['countries' => ['EG'], 'services' => []]), '');
ok(!$nosvc['ok'], 'G3: no service selected refuses too — a lock that does nothing is a lie');

has($src, 'Arming this would lock you out of WHM', 'G3: an operator in a country not on the list is refused, by name');
has($src, "\$problems[] = 'This server cannot tell which country you are connecting from",
    'G3: and so is an operator whose own country cannot be determined — it cannot promise not to lock them out');
has($pg, "if (\$wantOn && !\$chk['ok']) {", 'G3: the check runs BEFORE saving');
has($pg, 'A refusal here leaves the previous state', 'G3: ...so a refusal changes nothing at all');

/* ---------- G4: "unknown" is never treated as "not allowed" ---------- */
has($src, "if (\$cc === '') { \$res['skipped'][] = ['ip' => \$ip, 'why' => 'country unknown — never treated as not allowed']; continue; }",
    'G4: an address whose country is unknown is skipped, not blocked');
has($src, 'Geo data is wrong often enough', 'G4: with the reason stated');
is_eq(smpro_gl_country('not-an-ip'), '', 'G4: junk resolves to unknown rather than to a country');

/* ---------- G5: nothing acts on the server itself, or on anything already trusted ---------- */
is_eq(smpro_gl_exempt('127.0.0.1'), 'private or local', 'G5: loopback is exempt');
is_eq(smpro_gl_exempt('10.0.0.5'), 'private or local', 'G5: private ranges are exempt');
is_eq(smpro_gl_exempt('nonsense'), 'not an address', 'G5: junk is exempt');
has($src, "if (isset(\$mine[\$ip])) return 'this server\\'s own address';", 'G5: the server\'s own addresses are exempt');
has($src, 'a cPanel login proxied through the machine itself arrives FROM',
    'G5: ...and why — that one would take the panel down for everyone at once');
has($src, "smpro_fw_allow_covers(\$ip) !== '') return 'on the firewall allow-list';", 'G5: the firewall allow-list is honoured');
has($src, "smpro_bg_crawler_shield(\$ip); if (!empty(\$cs['crawler']))", 'G5: and a verified crawler is never touched');

/* ---------- G6: off, and report-only, until somebody says otherwise ---------- */
is_eq($base['enabled'], false, 'G6: it ships off');
is_eq($base['dryrun'], true,  'G6: and report-only even once armed');
is_eq($base['countries'], [], 'G6: with no country assumed on anybody\'s behalf');
ok(!in_array('mail', $base['services'], true), 'G6: mail is off by default — phones roam and mail clients retry silently');
$off = smpro_gl_run(true);
is_eq($off['enabled'], false, 'G6: with the feature off, a run does nothing');
has($off['msg'], 'is off', 'G6: ...and says so');

/* ---------- G7: a correct password from a country not allowed is an incident, not noise ---------- */
is_eq($base['on_success'], 'block',  'G7: an accepted password from there is acted on');
is_eq($base['on_failed'],  'ignore', 'G7: a rejected one is not — that is ordinary background noise');
has($src, 'The password for ', 'G7: the alert says the password itself is compromised');
has($src, 'the password is already known to somebody: change it', 'G7: ...and what to do about it');
has($pg, 'ACCEPTED — this password is already known to somebody', 'G7: and the check screen says it too');

/* ---------- G8: reversible, exactly, and it forgets ---------- */
has($src, "\$isOurs = strpos(\$l, SMPRO_GL_MARK) !== false;", 'G8: undo removes only lines this feature wrote');
has($src, 'Nothing else is touched.', 'G8: stated where the code is');
ok(function_exists('smpro_gl_expire'), 'G8: rules expire on their own');
is_eq($base['ttl_days'], 30, 'G8: after 30 days by default');
has($pg, 'One trip abroad should not lock an address out forever', 'G8: which is why');

/* ---------- G9: per-account lists, since one account is not the server ---------- */
$cfg = array_replace($base, ['countries' => ['EG'], 'per_account' => ['shopuser' => ['DE', 'NL']]]);
is_eq(smpro_gl_allowed_for('shopuser', $cfg), ['DE', 'NL'], 'G9: an account with its own list uses it');
is_eq(smpro_gl_allowed_for('otheruser', $cfg), ['EG'], 'G9: everyone else uses the server list');
is_eq(smpro_gl_clean_cc(['eg', ' SA ', 'x', '', 'USA', '12']), ['EG', 'SA'], 'G9: only real two-letter codes survive');

/* ---------- G10: gated and recorded like every other action ---------- */
has($pg, "smpro_require_valid_csrf('fw_csf'); smpro_require_root();", 'G10: root-only and CSRF-checked');
has($pg, "smpro_audit('geologin_settings'", 'G10: settings changes are recorded');
has($src, "smpro_audit('geologin_block'", 'G10: so is every block');
has($pg, "smpro_audit('geologin_unblock'", 'G10: and every unblock, with the actor');
has($pg, "fd.set('dryrun','1');   // a check never writes", 'G10: the "check" button can never write a rule');
