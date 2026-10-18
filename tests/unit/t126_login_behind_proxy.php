<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
require_once SMPRO_BASE . '/includes/loginfeed.php';
/** t126 - a cPanel login that cPanel recorded as 127.0.0.1 (Imunify WebShield / service-subdomain proxy in front) gets the visitor's address from the front proxy log. */
$src = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/loginfeed.php'));
has($src, "\$logs = function_exists('smpro_front_logs_all') ? smpro_front_logs_all() : [];", 'U1: the logs are discovered from the running configuration');
has($src, "if (\$m[3] !== '200' && \$m[3] !== '401') continue;", 'U1: only an accepted (200) or refused (401) login is indexed, each with its outcome');
has($src, "if (count(\$cand) === 1) return [(string)array_key_first(\$cand),", 'U2: one address in the window is a join');
has($src, "'one of ' . implode(', ', array_keys(\$cand)) . ' (several logins in the same second)'", 'U3: several are candidates, never a guess');
has($src, "\$e['ip_local'] = \$e['ip'];", 'U4: the loopback address is kept beside the real one');
is_eq(smpro_lf_real_login_ip(0), ['', ''], 'U5: no time, no answer');
$fa = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/fileaudit.php'));
hasnt($fa, "/var/log/imunify360-webshield/access.log", 'U6: no log path is written in the file evidence');
