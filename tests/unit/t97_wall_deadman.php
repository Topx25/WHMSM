<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
require_once SMPRO_BASE . '/includes/geowall.php';
/** t97 - the wall's dead man's switch is fed by WHM sign-ins from outside and by any product page, not only the Firewall page. */
$g = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/geowall.php'));
has($g, 'function smpro_gw_reachability_proof(int $since): int', 'U1: the proof reader exists');
has($g, "strpos(\$l, 'app=whostmgrd') === false || strpos(\$l, 'method=handle_form_login') === false", 'U1: only a WHM form sign-in counts');
has($g, "if (\$ip === '127.0.0.1' || \$ip === '::1' || \$ip === '') continue;", 'U1: a session minted on the box is not proof');
has($g, "if (\$proof > (int)\$cfg['last_seen']) { smpro_gw_heartbeat(\$proof);", 'U1: the dead man reads it before judging silence');
has($g, "max(5, min(10080, (int)(\$j['deadman_minutes'] ?? 60)))", 'U2: up to 7 days');
has($g, "min(\$firstTime ? 60 : 10080,", 'U2: ...but the first arming is still capped at an hour');
$l = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/layout.php'));
has($l, "if (!empty(\$gwc['enabled']) && time() - (int)\$gwc['last_seen'] >= 60) @smpro_gw_heartbeat();", 'U3: every rendered page from a remote address is a heartbeat, once a minute');
$f = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/firewall-status.php'));
has($f, "4320 => '3 days', 10080 => '7 days'", 'U4: the page offers 3 and 7 days');
/* the heartbeat never moves time backwards */
$c = smpro_gw_cfg(); $c['last_seen'] = 1000; smpro_gw_save($c);
smpro_gw_heartbeat(500); is_eq((int)smpro_gw_cfg()['last_seen'], 1000, 'U5: an older proof does not rewind last_seen');
smpro_gw_heartbeat(2000); is_eq((int)smpro_gw_cfg()['last_seen'], 2000, 'U5: a newer proof advances it');
