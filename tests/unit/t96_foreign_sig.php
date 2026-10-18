<?php
require __DIR__ . '/../support/bootstrap.php';
/** t96 - a relay user whose exit address rotates inside one network must NOT change the foreign-login signature. */
function smpro_ip_intel($ip, $x = false) { return strpos($ip, '104.28.') === 0 ? ['asn' => 'AS13335', 'country' => 'GA'] : ['asn' => '', 'country' => '']; }
$rowId = function (array $d): string {
    $ip = (string)($d['ip'] ?? ''); $cc = (string)($d['cc'] ?? ''); $asn = '';
    if ($ip !== '' && function_exists('smpro_ip_intel')) { $i = (array)smpro_ip_intel($ip, false); $asn = (string)($i['asn'] ?? ''); if ($cc === '') $cc = (string)($i['country'] ?? ''); }
    return (string)($d['user'] ?? '') . '|' . $cc . '|' . ($asn !== '' ? $asn : $ip);
};
$sig = function (array $fp) use ($rowId) { $ids = array_unique(array_map($rowId, $fp)); sort($ids); return md5(implode(',', $ids)); };
$day1 = [['ip' => '104.28.235.125', 'user' => 'khaled@x', 'cc' => 'GA'], ['ip' => '104.28.203.125', 'user' => 'khaled@x', 'cc' => 'GA']];
$day2 = [['ip' => '104.28.235.128', 'user' => 'khaled@x', 'cc' => 'GA'], ['ip' => '104.28.235.125', 'user' => 'khaled@x', 'cc' => 'GA']];
is_eq($sig($day1), $sig($day2), 'U1: three rotating Cloudflare exits for one mailbox from one country = one signature, no resend');
$new = array_merge($day2, [['ip' => '5.5.5.5', 'user' => 'khaled@x', 'cc' => 'DE']]);
ok($sig($new) !== $sig($day2), 'U2: the same mailbox from a NEW country/network changes it');
$acct = array_merge($day2, [['ip' => '104.28.1.1', 'user' => 'other@x', 'cc' => 'GA']]);
ok($sig($acct) !== $sig($day2), 'U3: a NEW account through the same relay changes it');
$plain = [['ip' => '9.9.9.9', 'user' => 'a', 'cc' => 'US']]; $plain2 = [['ip' => '9.9.9.8', 'user' => 'a', 'cc' => 'US']];
ok($sig($plain) !== $sig($plain2), 'U4: with no known network the address still counts (an ordinary ISP change is a change)');
