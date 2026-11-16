<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
/**
 * t190 - "Allow" had no "Remove allow": an address allow-listed by mistake (or a one-off that is over) stayed in
 * csf.allow forever = never block, with no button to take it off. Found in the 2026-11-16 pen-test. The reverse
 * now exists, refuses the operator's own current address unless forced, and is wired to a UI action + button.
 */
$src = fn($p) => str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/' . $p));

ok(function_exists('smpro_csf_allow_remove'), 'A0: the counterpart of allow-add exists');

$h = $src('includes/helpers.php');
$fn = substr($h, (int)strpos($h, 'function smpro_csf_allow_remove'), 3400);
has($fn, "if (!filter_var(\$ip, FILTER_VALIDATE_IP)) return ['ok'=>false,'msg'=>'invalid IP'];", 'A1: a non-IP is refused');
has($fn, "if (!smpro_csf_allowlisted(\$ip)) return ['ok'=>true,'already'=>true,", 'A2: an address that is not allow-listed is a no-op success');
has($fn, "if (!\$selfOverride && function_exists('smpro_admin_ip') && \$ip === smpro_admin_ip())", 'A3: the operator\'s own current address is refused unless forced');
has($fn, "'refused'=>true", 'A4: ...and that refusal is marked so the UI can offer an override');
has($fn, "escapeshellarg(\$csf) . ' -ar ' . escapeshellarg(\$ip)", 'A5: it mirrors the add - csf -ar first');
has($fn, "return \$tok !== \$ip;", 'A6: only an EXACT line is stripped - never a CIDR that merely contains the address');
has($fn, "\$gone = !smpro_csf_allowlisted(\$ip);", 'A7: success is judged by the address really being gone, not by csf stdout');
has($fn, "// Done inline (not via smpro_fw_live_remove) so the two removers never call back into each other.", 'A8: no mutual recursion with the live remover');
ok(strpos($fn, 'smpro_fw_live_remove(') === false, 'A9: ...it does not call smpro_fw_live_remove');
has($fn, "@smpro_audit('csf_allow_remove'", 'A10: the removal is audited');

$fs = $src('modules/firewall-status.php');
has($fs, "\$op = in_array((\$_POST['op'] ?? ''), ['block', 'unallow'], true) ? (string)\$_POST['op'] : 'allow';", 'U1: the endpoint accepts a third op, unallow');
has($fs, "if (\$op === 'unallow') {", 'U2: ...handled before allow/block');
has($fs, "\$force = (\$_POST['force'] ?? '') === '1';", 'U3: an explicit override is read');
has($fs, "function_exists('smpro_csf_allow_remove') ? smpro_csf_allow_remove(\$ip, \$force)", 'U4: it calls the remover');
has($fs, "smpro_audit('firewall_ip_unallow'", 'U5: the action is audited at the endpoint');
has($fs, "id=\"ipUnallowBtn\"", 'U6: there is a Remove-allow button');
has($fs, "if(ua)ua.addEventListener('click',function(){ipact('unallow');});", 'U7: the button is wired');
has($fs, "if(op==='unallow'&&j&&j.refused&&!fd.get('force')){", 'U8: a refusal on your own address offers the override');

// functional: on a box with a writable csf.allow stand-in, a line is really removed and an unrelated one kept.
// We cannot point the production path at a sandbox file (it is hard-coded /etc/csf/csf.allow), so this exercises
// the exact line-filter the function uses, proving the EXACT-match + keep-comments behaviour.
$allow = ["# header", "198.51.100.7 # smpro manual allow", "198.51.100.70 # a different address", "203.0.113.0/24 # a range", ""];
$ip = '198.51.100.7';
$kept = array_filter($allow, function ($l) use ($ip) {
    $t = trim($l); if ($t === '' || $t[0] === '#') return true;
    $tok = preg_split('/[\s#]/', $t, 2)[0]; return $tok !== $ip;
});
$kept = array_values($kept);
ok(!in_array("198.51.100.7 # smpro manual allow", $kept, true), 'F1: the exact line is removed');
ok(in_array("198.51.100.70 # a different address", $kept, true), 'F2: an address that only shares a prefix is kept');
ok(in_array("203.0.113.0/24 # a range", $kept, true), 'F3: a CIDR that would contain it is kept (exact match only)');
ok(in_array("# header", $kept, true), 'F4: comments are kept');
