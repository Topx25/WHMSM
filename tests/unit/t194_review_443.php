<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
require_once SMPRO_BASE . '/includes/shharden.php';
require_once SMPRO_BASE . '/includes/sechealth.php';
/**
 * t194 - the Security Health page ran its checks only when opened: no scheduled scan, so a posture that got worse
 * (an EOL PHP branch, a newly exposed port, a protection switched off) sat unseen until someone looked. The checks
 * were moved out of the page module into includes/sechealth.php so a worker can run the SAME checks on a schedule
 * and alert on a new/worsened finding.
 */
$src = fn($p) => str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/' . $p));

// 1) the checks are now in the include, loadable without the page/render
ok(function_exists('smpro_sh_all'), 'M1: the checks are available from the include (no page needed)');
ok(function_exists('smpro_sh_mk') && function_exists('smpro_sh_scan_own_checks'), 'M2: their helpers moved too');
$inc = $src('includes/sechealth.php');
ok(strpos($inc, 'smpro_layout_header') === false, 'M3: the include carries NO render code (layout stays on the page)');
has($inc, 'function smpro_sh_all()', 'M4: smpro_sh_all lives in the include');
has($inc, 'function smpro_sh_cron_sync()', 'M5: ...and the scheduler for it');

// the page module now requires the include and keeps only render + POST
$mod = $src('modules/security-health.php');
has($mod, "require_once __DIR__ . '/../includes/sechealth.php';", 'P1: the page pulls the checks from the include');
ok(strpos($mod, 'function smpro_sh_all()') === false, 'P2: the page no longer defines the checks (no double definition)');
has($mod, 'function smpro_sh_badge', 'P3: the render-only badge helper stays on the page');
has($mod, "\$_POST['sh_apply']", 'P4: the POST fix handling stays on the page');

// smpro_sh_all runs from the include and returns [category => [check,...]]; flatten and check the shape
$cats = smpro_sh_all();
ok(is_array($cats) && count($cats) > 0, 'R1: smpro_sh_all runs standalone and returns categories (' . count($cats) . ')');
$flat = []; foreach ($cats as $cc) foreach ((array)$cc as $it) if (is_array($it)) $flat[] = $it;
ok(count($flat) > 0, 'R2: the categories hold individual checks (' . count($flat) . ')');
$shape = true; foreach ($flat as $it) { if (!isset($it['title']) || !isset($it['status'])) { $shape = false; break; } }
ok($shape, 'R3: every check has a title and a status');

// 2) the worker exists, loads the include (not the page), and alerts only on NEW/worsened findings
ok(is_file(SMPRO_BASE . '/bin/sechealth_tick.php'), 'W0: the scheduled worker exists');
$w = $src('bin/sechealth_tick.php');
has($w, "\$sh = \$base . '/includes/sechealth.php'; if (is_file(\$sh)) require_once \$sh;", 'W1: the worker loads the include, not the page module');
has($w, 'foreach ((array)$catChecks as $it) if (is_array($it)) $items[] = $it;', 'W1b: the worker flattens the category structure first');
has($w, "in_array(\$status, ['critical', 'warning'], true)", 'W2: only real problems (critical/warning) are tracked');
has($w, "if (\$was === '' || (\$rank[\$c['status']] ?? 0) > (\$rank[\$was] ?? 0)) \$new[\$title] = \$c;", 'W3: alert only on a NEW finding or a warning that became critical');
has($w, "smpro_notify('sechealth_auto'", 'W4: a worsened posture raises an alert');
has($w, "smpro_json_save(\$stateFile, \$st);", 'W5: the snapshot is saved so the next run compares against it');

// the new/worsened logic, exercised directly
$rank = ['warning' => 1, 'critical' => 2];
$prev = ['A' => ['status' => 'warning'], 'B' => ['status' => 'critical']];
$cur  = ['A' => ['status' => 'critical'], 'B' => ['status' => 'critical'], 'C' => ['status' => 'warning']];
$new = [];
foreach ($cur as $t => $c) { $was = $prev[$t]['status'] ?? ''; if ($was === '' || ($rank[$c['status']] ?? 0) > ($rank[$was] ?? 0)) $new[$t] = $c; }
is_eq(array_keys($new), ['A', 'C'], 'N1: A (warning->critical) and C (new) alert; B (unchanged critical) does not');

// the cron is scheduled from index.php
has($src('index.php'), "if (function_exists('smpro_sh_cron_sync'))", 'C1: the automatic scan is scheduled from the boot path');
has($src('includes/sechealth.php'), "'/etc/cron.d/smpro-sechealth'", 'C2: via its own cron file (removed by the glob uninstall)');
