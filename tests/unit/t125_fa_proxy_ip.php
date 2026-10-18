<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
require_once SMPRO_BASE . '/includes/fileaudit.php';
/** t125 - a File Manager change made through the cPanel service-subdomain proxy is attributed to the real address, joined by the session token in the proxy log. */
$src = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/fileaudit.php'));
has($src, "if (preg_match('#^/(cpsess\\d{6,12})/#', \$m[9], \$tk)) \$tokens[\$tk[1]] = 1;", 'U1: the session token is taken from the cPanel request line');
has($src, "[\$rip, \$rhow] = smpro_fa_proxy_ip_for_token(\$tok);", 'U2: a loopback address is resolved through the proxy log');
has($src, "\$logs = function_exists('smpro_front_logs_all') ? smpro_front_logs_all() : [];", 'U3: the logs are discovered, none named');
has($src, "'Cloudflare edge for cpanel session '", 'U4: a Cloudflare edge is labelled as such, never passed off as the visitor');
is_eq(smpro_fa_proxy_ip_for_token('not-a-token; rm -rf /'), ['', ''], 'U5: anything but a cpsess token is refused before any shell');
