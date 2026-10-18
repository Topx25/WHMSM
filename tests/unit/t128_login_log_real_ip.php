<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
require_once SMPRO_BASE . '/includes/loginfeed.php';
/** t128 - a login_log line recorded as 127.0.0.1 carries the visitor the front proxy saw, matched by second AND outcome; every reader uses it. */
$plain = '[2026-10-11 13:15:35 +0200] info [cpaneld] 203.0.113.9 - efadh "POST /login/?login_only=1 HTTP/1.1" FAILED LOGIN cpaneld: access denied';
is_eq(smpro_login_line_real($plain), $plain, 'U1: a line that already has a real address is untouched');
$noOutcome = '[2026-10-11 13:15:35 +0200] info [cpaneld] 127.0.0.1 - efadh "GET /" something else';
is_eq(smpro_login_line_real($noOutcome), $noOutcome, 'U2: a line with no outcome is untouched (never guessed)');
$src = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/loginfeed.php'));
has($src, "\$idx[\$ts][\$m[3]][\$ip] = 1;", 'U3: the front index keeps the outcome (200 accepted / 401 refused)');
has($src, "foreach (array_keys(\$idx[\$ts + \$d][\$status] ?? []) as \$ip)", 'U3: a refusal is matched only to a refusal');
foreach (['includes/intrusion.php' => 'smpro_login_log_resolve($raw)', 'includes/geologin.php' => 'smpro_login_log_resolve($raw)', 'includes/georeport.php' => 'smpro_login_log_resolve($raw)',
          'includes/breakin.php' => 'smpro_login_line_real($raw)', 'modules/login-monitor.php' => 'smpro_login_line_real((string)$raw)', 'includes/ai.php' => 'smpro_login_line_real((string)$line)'] as $f => $call)
    has(str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/' . $f)), $call, 'U4: ' . $f . ' reads the resolved line');
is_eq(substr_count(str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/intrusion.php')), 'smpro_login_log_resolve($raw)'), 3, 'U4: all three intrusion readers (decoys, foreign, login guard)');
