<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/geologin.php';
require_once SMPRO_BASE . '/includes/geohulk.php';
/** t163 - cloud mail providers pass the country lock: names, ranges, and the bot command. */
is_eq(smpro_gh_mail_provider_key('Outlook'), 'microsoft', 'C1: "Outlook" is Microsoft');
is_eq(smpro_gh_mail_provider_key('office 365'), 'microsoft', 'C2: "office 365" is Microsoft');
is_eq(smpro_gh_mail_provider_key('Gmail'), 'google', 'C3: Gmail is Google');
is_eq(smpro_gh_mail_provider_key('nothing'), '', 'C4: unknown names are refused');
ok(smpro_gh_in_cidr('40.104.246.173', '40.104.0.0/15') && smpro_gh_in_cidr('52.96.179.21', '52.96.0.0/14') && !smpro_gh_in_cidr('41.1.1.1', '40.96.0.0/13'), 'C5: range matching');
$ms = smpro_gh_mail_providers()['microsoft'][1];
ok(in_array('40.96.0.0/13', $ms, true) && in_array('40.104.0.0/15', $ms, true) && in_array('52.96.0.0/14', $ms, true), 'C6: the Exchange Online ranges seen in the field are covered');
$src = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/geohulk.php'));
has($src, "\$on = isset(\$c['cloud_mail']) ? (array)\$c['cloud_mail'] : ['microsoft'];", 'C7: Microsoft is allowed by default');
has($src, "smpro_gh_cloudmail_apply(\$force);     // cloud mail providers", 'C8: every sync keeps them allowed');
has($src, "@shell_exec('timeout 10 nft delete element inet filter ' . \$set", 'C9: bans already placed are lifted one address at a time');
$tg = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/tgbot.php'));
has($tg, "case 'mailallow': case 'cloudmail':", 'C10: the Telegram bot takes /mailallow <provider>');
