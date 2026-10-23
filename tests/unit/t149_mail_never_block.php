<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
if (!defined('SMPRO_VARLIB')) define('SMPRO_VARLIB', sys_get_temp_dir() . '/t149_varlib_' . getmypid());
require_once SMPRO_BASE . '/includes/intrusion.php';
require_once SMPRO_BASE . '/includes/fwallow.php';
/** t149 - beta367: Google's and Microsoft's mail-sending ranges (as published in SPF) are never blocked - not by a
 *  button, not by an automatic response, not with force - and the SPF resolver follows include/redirect safely. */
$fa = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/fwallow.php'));
$hp = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/helpers.php'));
$P = smpro_fw_allow_providers();
ok(isset($P['google_mail']) && !empty($P['google_mail']['never_block']), 'A1: Google mail provider, never-block');
ok(isset($P['microsoft_mail']) && !empty($P['microsoft_mail']['never_block']), 'A2: Microsoft mail provider, never-block');
ok(in_array('_spf.google.com', $P['google_mail']['fetch_spf'], true), 'A3: Google ranges come from its SPF record');
ok(in_array('spf.protection.outlook.com', $P['microsoft_mail']['fetch_spf'], true), 'A4: Microsoft ranges come from its SPF record');
ok(count($P['google_mail']['ranges']) >= 20 && count($P['microsoft_mail']['ranges']) >= 6, 'A5: seeds ship, so the shield works before the first DNS refresh');
foreach ($P as $k => $pv) if (!in_array($k, ['google_mail', 'microsoft_mail'], true)) ok(empty($pv['never_block']), 'A6: ' . $k . ' is NOT never-block (crawlers and Cloudflare keep their own rules)');

// B. the SPF resolver: ip4/ip6, include:, redirect=, loops, depth, bare addresses
$txt = function (string $h): array { return ['_spf.test' => ['v=spf1 include:_nb.test ip4:1.2.3.0/24 ~all'], '_nb.test' => ['v=spf1 ip4:5.6.7.8 ip6:2001:db8::/32 redirect=_loop.test', 'not an spf record'], '_loop.test' => ['v=spf1 include:_spf.test -all']][$h] ?? []; };
$seen = []; $r = smpro_fw_spf_ranges('_spf.test', 0, $seen, $txt); sort($r);
is_eq($r, ['1.2.3.0/24', '2001:db8::/32', '5.6.7.8/32'], 'B1: ip4, ip6, include, redirect, a bare address as /32, a loop ends');
$seen = []; is_eq(smpro_fw_spf_ranges('bad host!', 0, $seen, $txt), [], 'B2: a host name that is not one is refused');
$seen = []; is_eq(smpro_fw_spf_ranges('_none.test', 0, $seen, $txt), [], 'B3: no record -> nothing, never an error');

// C. the guard answers from the seeds (no network) and names the provider
is_eq(smpro_fw_never_block('74.125.1.1'), $P['google_mail']['name'], 'C1: a Google mail address is shielded');
is_eq(smpro_fw_never_block('209.85.200.1'), $P['google_mail']['name'], 'C2: ...another Google block');
is_eq(smpro_fw_never_block('40.107.1.1'), $P['microsoft_mail']['name'], 'C3: a Microsoft 365 address is shielded');
is_eq(smpro_fw_never_block('2a01:111:f400::1'), $P['microsoft_mail']['name'], 'C4: ...IPv6 too');
is_eq(smpro_fw_never_block('8.8.8.8'), '', 'C5: an unrelated address is not');
is_eq(smpro_fw_never_block('66.249.66.1'), '', 'C6: Googlebot is a crawler, handled by the crawler shield, not this one');
is_eq(smpro_fw_never_block('not-an-ip'), '', 'C7: garbage -> empty');

// D. every block path refuses, even with force
$r = smpro_fw_block_ip('74.125.1.1', 'test', true);
ok(empty($r['ok']) && strpos((string)$r['msg'], 'bounce your customers') !== false, 'D1: the central block function refuses (force ignored)');
$r = smpro_fw_live_block('40.107.1.1');
ok(empty($r['ok']) && strpos((string)$r['msg'], 'Refused') === 0, 'D2: the live iptables block refuses');
$r = smpro_imunify_block_ip('209.85.200.1', 'test');
ok(empty($r['ok']) && strpos((string)$r['msg'], 'refused') === 0, 'D3: the Imunify block refuses');
has($hp, "smpro_audit('firewall_block_refused_mail'", 'D4: a refusal is audited');
has($fa, "if (\$r && !empty(\$pv['never_block'])) foreach ((array)\$pv['ranges'] as \$seed) if (!in_array(\$seed, \$r, true)) \$r[] = \$seed;", 'D5: a DNS refresh can only ADD to a never-block list, never drop a published block');
