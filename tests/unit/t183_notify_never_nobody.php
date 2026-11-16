<?php
require __DIR__ . '/../support/bootstrap.php';
/**
 * t183 - an alert must not be sent to nobody. On two real servers that use WhatsApp alone, "Reboot scheduled",
 * "Server rebooting now" and "the country wall took itself down" reached no channel: a type the saved settings
 * did not know defaulted to e-mail and Telegram only. One of those walls stayed down for two weeks unnoticed.
 */
$nt = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/notify.php'));
has($nt, "\$t = \$cfg['types'][\$type] ?? ['on' => true, 'email' => true, 'telegram' => true, 'pushbullet' => true, 'whatsapp' => true];", 'N1: a type the saved settings do not know goes to every channel');
ok(strpos($nt, "?? ['on' => true, 'email' => true, 'telegram' => true];") === false, 'N2: the e-mail-and-Telegram-only default is gone');
has($nt, "if (in_array(\$tag, ['CRITICAL', 'HIGH', 'WARNING'], true) && \$chOn && \$ticked && !array_intersect(\$ticked, \$chOn)) {", 'N3: a warning or worse whose chosen channels are all off uses the channels that are on');
has($nt, "A type with NO channel ticked at all is the operator's choice", 'N3b: a type with nothing ticked stays log-only');
has($nt, "so it was sent through the ones that are on", 'N4: and the message says why it arrived there');
$i = strpos($nt, "if (!\$force && empty(\$t['on'])) return ['skipped' => 'type disabled'];"); $j = strpos($nt, "in_array(\$tag, ['CRITICAL', 'HIGH', 'WARNING'], true)");
ok($i !== false && $j !== false && $i < $j, 'N5: a type the operator switched off stays off');
