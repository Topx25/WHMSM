<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/geologin.php';
/**
 * t82_gl_custom_ports.php — the lock closes the operator's OWN login ports too.
 *
 * A server had SSH moved off 22 and an SMTP submission port that was not 465/587. The lock knew six standard
 * doors and closed those; the two the server actually used stayed open to the address it had just "blocked".
 */
is_eq(smpro_gl_clean_ports('2200, 2525'), [2200, 2525], 'U1: typed ports are parsed');
is_eq(smpro_gl_clean_ports(' 2525;2200 2200 '), [2200, 2525], 'U1: any separator, deduplicated, sorted');
is_eq(smpro_gl_clean_ports('80, 443, 2200'), [2200], 'U1: the web ports are refused even when typed');
is_eq(smpro_gl_clean_ports('0, 70000, abc, -1'), [], 'U1: garbage is dropped');
$cfg = array_replace(smpro_gl_defaults(), ['services' => ['ssh'], 'custom_ports' => [2200, 2525, 443]]);
$ports = smpro_gl_ports_for($cfg);
ok(in_array(22, $ports, true) && in_array(2200, $ports, true) && in_array(2525, $ports, true), 'U2: the rule set is the doors plus the custom ports');
ok(!in_array(443, $ports, true) && !in_array(80, $ports, true), 'U2: and never the web ports');
$saved = smpro_gl_cfg_save(['custom_ports' => smpro_gl_clean_ports('2200')]);
is_eq($saved['custom_ports'], [2200], 'U3: the setting round-trips through the config');
$page = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/firewall-status.php'));
has($page, "'custom_ports' => smpro_gl_clean_ports((string)(\$_POST['custom_ports'] ?? ''))", 'U4: the page saves it through the cleaner');
has($page, 'id="glPorts"', 'U4: and has the field');
has($page, "fd.set('custom_ports',gp.value)", 'U4: and sends it');
