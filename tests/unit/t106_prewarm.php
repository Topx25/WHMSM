<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
/** t106 - analytics counts live in includes/analytics.php and are kept warm by the notify worker; information_schema scans never block a page. */
require_once SMPRO_BASE . '/includes/analytics.php';
ok(function_exists('smpro_ar_reports') && function_exists('smpro_ar_prewarm') && function_exists('smpro_ar_sh'), 'U1: the counts are an include now');
$mod = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/analytics-reports.php'));
hasnt($mod, 'function smpro_ar_reports(', 'U1: ...not a module-local function');
has($mod, "require_once SMPRO_BASE . '/includes/analytics.php';", 'U1: ...and the module loads it');
$nc = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/bin/notify_check.php'));
has($nc, "smpro_ar_prewarm();", 'U2: the notify worker keeps the default window warm');
has($nc, "require \$base . '/includes/analytics.php';", 'U2: ...and loads the include');
$db = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/dbhealth.php'));
has($db, "smpro_memo_cmd('dbh_datasize', (int)\$ttl, smpro_dbh_cmd(\$sqlSz), 60, 604800, true)", 'U3: the data-size scan is background-on-miss');
has($db, "if (trim(\$raw) === '') return 0;", 'U3: ...and an unknown size is 0, never cached as final');
has($db, "if (trim(\$rawM) === '') return [];", 'U3: same for the MyISAM list');
// background-on-miss returns '' and (outside the lab) hands off; inside the lab it still computes inline so nothing spawns
$k = 'test_bgmiss_' . getmypid(); @unlink(SMPRO_CACHE . '/memo_' . $k . '.json');
is_eq(trim(smpro_memo_cmd($k, 60, 'echo five', 5, 604800, true)), 'five', 'U4: inside the lab the miss computes inline (no background process from a test)');
@unlink(SMPRO_CACHE . '/memo_' . $k . '.json');
