<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
if (!defined('SMPRO_VARLIB')) define('SMPRO_VARLIB', sys_get_temp_dir() . '/t145_varlib_' . getmypid());
require_once SMPRO_BASE . '/includes/lvelimits.php';
/** t145 - beta352: "Resource Limit Is Reached" page. The parsers are pure and are fed the exact shapes CloudLinux
 *  prints (lveinfo JSON, /proc/lve/list, lvectl list-user, ps); the actions back up first and are journalled. */
$lv = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/lvelimits.php'));
$pg = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/resource-limits.php'));
$mn = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/menu.php'));
$cs = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/bin/cron_sync.php'));
hasnt($lv, '/home/', 'N1: no path from any server');
hasnt($lv . $pg, 'efadh', 'N2: no customer name');

// A. lveinfo JSON (shape printed by lve-stats 5): reserved numeric IDs are skipped, bytes become MB
$json = '{"data":[{"EPf":0,"ID":255,"NprocF":0,"PMemF":0,"VMemF":0,"aCPU":8,"aEP":1,"lCPU":34,"lEP":0,"mEP":2,"mPMem":36717641728,"lPMem":0},'
      . '{"EPf":12,"ID":"alpha","NprocF":1,"PMemF":3,"VMemF":0,"aCPU":6.9,"mCPU":44.7,"lCPU":100,"aEP":0,"mEP":20,"lEP":20,"mPMem":58408960,"lPMem":1073741824,"mNproc":4,"lNproc":100,"IOf":5},'
      . '{"EPf":0,"ID":"beta","NprocF":0,"PMemF":0,"VMemF":0,"aCPU":1,"mCPU":99.5,"lCPU":100,"mEP":0,"lEP":20,"mPMem":1000,"lPMem":1073741824,"mNproc":1,"lNproc":100}],"success":1}';
$f = smpro_lv_parse_faults($json);
is_eq(array_keys($f), ['alpha'], 'A1: reserved LVE 255 skipped; a row with nothing counted is dropped (beta)');
is_eq($f['alpha']['ep_f'], 12, 'A2: entry-process faults');
is_eq($f['alpha']['pmem_max'], 56, 'A3: bytes -> MB');
is_eq($f['alpha']['pmem_lim'], 1024, 'A4: limit bytes -> MB');
is_eq($f['alpha']['faults'], 21, 'A5: faults summed across kinds (12+1+3+5)');
is_eq($f['alpha']['cpu_f'], 0, 'A6: a column lveinfo does not print reads 0, never an error');
has($lv, "--show-columns=ID,aCPU,mCPU,lCPU,CPUf,aEP,mEP,lEP,EPf,aPMem,mPMem,lPMem,PMemF,VMemF,mNproc,lNproc,NprocF,IOf,IOPSf", 'A8: CPU / IO / IOPS fault columns are asked for by name - lveinfo omits them by default');
is_eq(smpro_lv_parse_faults('{"data":[{"ID":"gamma","CPUf":6,"IOf":2,"IOPSf":1}],"success":1}')['gamma']['faults'], 9, 'A9: CPU + IO + IOPS faults count');
is_eq(smpro_lv_parse_faults('garbage'), [], 'A7: not JSON -> empty');

// B. /proc/lve/list, header-driven; MEMPHY is in 4K pages; uid 0 and the 4294967295 pseudo-LVE are skipped
$pl = "10:LVE\tlCPU\tlCPUW\tnCPU\tlEP\tlNPROC\tlMEM\tlMEMPHY\tlIO\tlIOPS\tlNETO\tlNETI\tEP\tCPU\tMEM\tIO\tfMEM\tfEP\tMEMPHY\tfMEMPHY\tNPROC\tfNPROC\tIOPS\tNETO\tNETI\n"
    . "0,0\t\t10000\t100\t1\t20\t100\t0\t262144\t1024\t1024\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\n"
    . "0,2318\t10000\t100\t1\t20\t100\t0\t262144\t1024\t1024\t0\t0\t20\t5\t0\t0\t0\t7\t51200\t2\t24\t0\t0\t0\t0\n"
    . "0,4294967295\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t1\t1\t0\t0\t0\t0\t9245055\t16788\t39\t0\t0\t4\t6\n";
$n = smpro_lv_parse_proclist($pl);
is_eq(array_keys($n), [2318], 'B1: only real uids');
is_eq($n[2318]['ep'], 20, 'B2: EP now');
is_eq($n[2318]['lep'], 20, 'B3: EP limit');
is_eq($n[2318]['fep'], 7, 'B4: EP faults since boot');
is_eq($n[2318]['memphy_mb'], 200, 'B5: 51200 pages = 200 MB');
is_eq($n[2318]['lmemphy_mb'], 1024, 'B6: 262144 pages = 1 GB');
is_eq($n[2318]['fmemphy'], 2, 'B7: memory faults since boot');
is_eq(smpro_lv_parse_proclist("10:LVE\tlCPU\n"), [], 'B8: header only -> empty');

// C. lvectl list-user
$lu = "                                ID   SPEED    PMEM    VMEM      EP   NPROC      IO    IOPS\n"
    . "                           default     100   1024M      0K      20     100    1024    1024\n"
    . "                               255      34      0K      0K       0       0    2048    2048\n"
    . "                             alpha     200    2.0G      0K      40     200    1024    1024\n";
$L = smpro_lv_parse_limits($lu);
is_eq($L['default']['pmem_mb'], 1024, 'C1: 1024M -> MB');
is_eq($L['alpha']['pmem_mb'], 2048, 'C2: 2.0G -> MB');
is_eq($L['alpha']['ep'], 40, 'C3: EP');
is_eq($L['alpha']['speed'], 200, 'C4: SPEED');
is_eq(smpro_lv_limits_of('nobody_here', $L), $L['default'], 'C5: an account without its own row rides on the defaults');
is_eq(smpro_lv_lifted(['ep' => 20, 'pmem_mb' => 1024, 'nproc' => 100, 'speed' => 100]), ['ep' => 40, 'pmem_mb' => 2048, 'nproc' => 200, 'speed' => 200], 'C6: a lift doubles');
is_eq(smpro_lv_lifted(['ep' => 5, 'pmem_mb' => 256, 'nproc' => 50, 'speed' => 300]), ['ep' => 40, 'pmem_mb' => 2048, 'nproc' => 200, 'speed' => 400], 'C7: floors on ep/mem/nproc, ceiling on CPU');

// D. ps rows: PHP and cron are the kinds that may be ended; oldest first
$ps = " 1234 7200 0.5 102400 /opt/cpanel/ea-php81/root/usr/bin/php-cgi /home/x/public_html/index.php\n"
    . " 1235 30 12.0 20480 lsphp:/home/x/public_html/wp-admin/admin-ajax.php\n"
    . " 1236 400 0.0 1024 /bin/sh -c wget -q -O - https://example.net/wp-cron.php\n"
    . " 1237 9000 0.0 2048 -bash\n";
$p = smpro_lv_parse_ps($ps);
is_eq($p[0]['pid'], 1237, 'D1: sorted by age, oldest first');
is_eq($p[0]['kind'], 'other', 'D2: a shell is never a victim');
is_eq($p[1]['kind'], 'php', 'D3: php-cgi is PHP');
is_eq($p[1]['rss_mb'], 100, 'D4: rss KB -> MB');
$k = array_column($p, 'kind', 'pid');
is_eq($k[1235], 'php', 'D5: lsphp is PHP');
is_eq($k[1236], 'cron', 'D6: a wp-cron fetch is cron');

// E. the explanation names the limit and the usual cause
$why = smpro_lv_explain($f['alpha'], ['ep' => 20, 'lep' => 20]);
ok(strpos($why, 'entry processes 20 of 20') !== false, 'E1: entry processes with the numbers');
ok(strpos($why, 'more memory than its limit (peak 56 of 1024 MB)') !== false, 'E2: memory with the numbers');
ok(strpos($why, 'more processes than allowed') !== false, 'E3: nproc');
ok(strpos($why, 'disk I/O throttled') !== false, 'E4: io');
$why = smpro_lv_explain(['cpu_f' => 3, 'cpu_max' => 99.5, 'cpu_lim' => 100], []);
ok(strpos($why, 'CPU at its ceiling 3 time(s)') !== false && strpos($why, 'entry') === false, 'E5: CPU only, says throttled not refused');
is_eq(smpro_lv_explain([], []), 'no limit was hit in this period.', 'E6: nothing');

// F. actions: argument gate, backup before change, journal, automatic put-back, no cron in tests
$ops = smpro_lv_ops();
is_eq(array_keys($ops), ['kill_hung', 'lift', 'putback', 'reset'], 'F1: four actions');
is_eq(smpro_lv_apply('lift', ['user' => 'x; rm', 'minutes' => '60'])['ok'], false, 'F2: a bad user name is refused before anything runs');
is_eq(smpro_lv_apply('lift', ['user' => 'alpha', 'minutes' => '7'])['ok'], false, 'F3: only 15/60/240 minutes');
is_eq(smpro_lv_apply('nope', [])['msg'], 'unknown action', 'F4: unknown op');
has($lv, "\$bk = smpro_lv_backup_cfg(); if (\$bk === '') { \$r = ['ok' => false, 'msg' => 'could not back up ' . SMPRO_LV_VECFG . ' - nothing changed']; break; }", 'F5: no backup, no lift');
has($lv, "\$prev = isset(\$lifts[\$user]['prev']) ? \$lifts[\$user]['prev'] : smpro_lv_limits_of(\$user);", 'F6: a second lift keeps the ORIGINAL limits to put back');
has($lv, "? \$ctl . ' set-user ' . escapeshellarg(\$user) . ' --maxEntryProcs=' . (int)\$p['ep']", 'F7: put-back restores the own values when the account had them');
has($lv, ": \$ctl . ' delete-user ' . escapeshellarg(\$user) . ' 2>&1';", 'F8: ...and returns to the package when it had none');
has($lv, "if ((int)(\$L['until'] ?? 0) <= \$now) \$out[\$user] = smpro_lv_putback((string)\$user, 'cron', 'time was up');", 'F9: the tick expires lifts');
has($lv, "if (!smpro_lv_lifts()) { if (@is_file(\$f)) @unlink(\$f); return true; }", 'F10: no lift, no cron');
has($lv, "if (defined('SMPRO_TEST_SRC')) return true;", 'F11: a test never installs a cron');
has($lv, "if (!is_array(\$pw) || (int)\$pw['uid'] < 1000) return ['ok' => false, 'msg' => 'refused: not a hosting account'];", 'F12: system users are never touched');
has($lv, "if ((\$p['kind'] === 'php' || \$p['kind'] === 'cron') && \$p['secs'] >= \$min) \$victims[] = \$p;", 'F13: only PHP/cron older than the floor are ended');
has($lv, "foreach (\$pids as \$pid) @posix_kill(\$pid, 15);", 'F14: TERM first');
is_eq(smpro_lv_tick(0), [], 'F15: nothing journalled -> nothing expired');

// G. the page and the menu
has($pg, "smpro_require_valid_csrf('lv_fix');", 'G1: CSRF on the action');
has($pg, "var fd = new URLSearchParams(); fd.append('lv_action','fix')", 'G2: url-encoded, never multipart');
has($pg, 'This server has no CloudLinux LVE', 'G3: a server without LVE is told so, not shown an empty table');
has($pg, "History could not be read:", 'G4: a read that could not run is said, never shown as no faults');
has($pg, "\$expired = smpro_lv_tick();", 'G5: expired lifts go back when the page is drawn too');
has($mn, "['id' => 'resource-limits','label' => 'Resource Limit Reached'", 'G6: in the menu');
has($mn, "'resource-limits'    => '1.1.10-beta353',", 'G7: NEW badge');
has($cs, "'lve lifts'          => 'smpro_lv_cron_sync',", 'G8: cron sync knows the tick');
has($cs, "'slmaint', 'lvelimits'] as \$m) {", 'G9: cron sync loads the engine');
