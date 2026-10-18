<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
require_once SMPRO_BASE . '/includes/breakin.php';
/** t111 - the "Login brute-force" alert is evaluated (it was declared for a year and never checked), grouped by network like the Break-in report. */
$n = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/notify.php'));
has($n, "\$maybe('login_bruteforce', 'bf:' . md5(implode(',', \$keys))", 'U1: the alert is sent with a network-set signature');
has($n, "\$maybe('login_bruteforce', 'clear:bf', '', '');", 'U1: ...and cleared in its own slot when quiet');
has($n, "\$bfThr = max(1, (int)(\$cfg['thresholds']['failed_logins'] ?? 60));", 'U2: the Notifications page threshold is what fires it');
has($n, "if ((\$as['verdict'] ?? '') === 'block')", 'U3: only networks the report would call an attack count');
ok(function_exists('smpro_aa_bf_networks'), 'U4: the grouping is a pure include function');
$r = smpro_aa_bf_networks([]);
is_eq(array_keys($r), ['nets', 'ignored', 'trusted', 'brute'], 'U4: shape');
is_eq($r['nets'], [], 'U4: no events, no networks');
$nc = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/bin/notify_check.php'));
has($nc, "foreach (['fwallow', 'breakin'] as \$m)", 'U5: the worker loads the grouping and the allow-list helpers');
