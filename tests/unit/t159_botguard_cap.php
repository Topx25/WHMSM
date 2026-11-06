<?php
require __DIR__ . '/../support/bootstrap.php';
/** t159 - Bot Guard state stays bounded and its worker has the headroom to shrink an oversized file. */
$bg = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/botguard.php'));
$tk = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/bin/botguard_tick.php'));
has($bg, "\$cap = 12000;", 'B1: a hard cap on tracked addresses');
has($bg, "&& (\$b['status'] ?? '') !== 'blocked') \$cand[\$ip] = (int)(\$b['seen'] ?? 0);", 'B2: only undecided, unblocked entries are dropped, least recently seen first');
has($tk, "@ini_set('memory_limit', '768M');", 'B3: the worker can load an oversized state once to shrink it');
