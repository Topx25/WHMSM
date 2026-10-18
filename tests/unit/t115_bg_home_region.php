<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
require_once SMPRO_BASE . '/includes/notify.php';
/** t115 - Bot Guard never auto-blocks a home-region residential / allow-listed address; an alert with no channel is recorded and shown. */
$bg = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/botguard.php'));
has($bg, "function smpro_bg_never_autoblock(string \$ip): bool {", 'U1: the guard exists');
has($bg, "smpro_im_region_status(\$ip) === 'core_protected'", 'U1: ...home-region residential (the Intrusion Monitor rule)');
has($bg, "smpro_im_allowlisted(\$ip)", 'U1: ...and the allow-list');
has($bg, "} elseif (\$b['attacks'] >= \$cfg['gray_threshold'] && smpro_bg_never_autoblock(\$ip)) {", 'U2: checked before the block branch');
has($bg, "'review' => \$review]", 'U2: such addresses are reported for review');
has($bg, "home-region address(es) over the Bot Guard threshold — NOT blocked, your decision", 'U3: ...and the operator is told');
$k = SMPRO_VARLIB . '/notify_undelivered.json'; @unlink($k);
smpro_ntf_undelivered_note('test', 'first', []);
smpro_ntf_undelivered_note('test', 'second', []);
$d = smpro_ntf_undelivered();
is_eq((int)($d['count'] ?? 0), 2, 'U4: two alerts with no channel are counted');
is_eq($d['last_subject'] ?? '', 'second', 'U4: the last one is remembered');
smpro_ntf_undelivered_note('test', 'delivered', ['telegram']);
ok(smpro_ntf_undelivered() === null, 'U4: a delivery through any channel clears the record');
$lay = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/layout.php'));
has($lay, 'Alerts are going nowhere:', 'U5: every page shows the bar while alerts have no channel');
