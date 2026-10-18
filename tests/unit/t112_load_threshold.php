<?php
require __DIR__ . '/../support/bootstrap.php';
/** t112 - the "load high" alert line is at least half the cores, its signature is a band, and the page says the effective value. */
$n = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/notify.php'));
has($n, "\$loadThr = max((float)(\$thr['load'] ?? 20), \$cores / 2);", 'U1: threshold = max(configured, cores/2)');
has($n, "if (\$load >= \$loadThr) {", 'U1: ...and that is what is compared');
has($n, "'load:' . (int)floor(\$load / max(1, \$cores / 4))", 'U2: the signature is a band, not the exact load');
$m = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/notifications.php'));
has($m, 'so the alert fires at <?= (int)$ntEff ?>', 'U3: the page states the effective line');
