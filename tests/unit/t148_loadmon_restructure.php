<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
/** t148 - beta363: Server Health & System has ONE fold engine and ONE poller, keeps its sections open on the first
 *  visit, its tables stay in their card; the Firewall page reads the country-lock set once per request. */
$lm = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/load-monitor.php'));
$ly = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/layout.php'));
$gs = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/geoset.php'));
$gl = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/geologin.php'));
$ds = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/disk-storage.php'));

// A. one fold engine
hasnt($lm, "localStorage.getItem('smpro_lm_folds')", 'A1: the page\'s own fold script is gone');
has($lm, "var KEY='smpro:load-monitor:open'", 'A2: the shared card engine remains');
is_eq(substr_count($lm, "chev.textContent='▾ '"), 0, 'A3: no second chevron is drawn');
// B. one poller
has($lm, "'health' => \$health], JSON_UNESCAPED_SLASHES", 'B1: the live JSON carries the health snapshot');
has($lm, "if(j.health&&window.loApplyHealth)window.loApplyHealth(j.health);", 'B2: the live tick feeds the health ring');
has($lm, "window.loApplyHealth=apply;", 'B3: the health script exposes apply instead of polling');
hasnt($lm, "fetch('index.cgi?format=json&metric=serverhealth'", 'B4: no second 3-second poll');
is_eq(substr_count($lm, 'setInterval(tick,3000)'), 1, 'B5: exactly one 3-second interval');
// C. first visit shows the graphs
has($lm, '<nav class="fw-nav" id="loNav" data-keep-open="1">', 'C1: the navigator opts out of close-all');
has($ly, "if(nav.getAttribute('data-keep-open')!=='1') closeAll(nav);", 'C2: the layout honours it, every other page unchanged');
// D. tables and tiles
has($lm, ".lo-kv{width:100%;table-layout:fixed}.lo-kv td{word-break:break-word}", 'D1: key/value tables stay in the card');
has($lm, ".fw-kpi.lo-vs .v{font-size:15px;white-space:normal;line-height:1.3}", 'D2: the Platform tile wraps');
has($lm, "trim(\$hw['virt'] . ' · up ' . smpro_lo_dur(\$L['uptime']), ' ·'), 'lo-vs'],", 'D3: ...and only that tile');
has($ds, ".hm-batch table{width:100%;table-layout:fixed}.hm-batch td{word-break:break-word}", 'D4: the batch-move table stays in its box');
// E. firewall page: one read per request
has($gs, 'function smpro_gs_members(bool $v6 = false, bool $fresh = false): array {', 'E1: members snapshot');
has($gs, "function smpro_gs_rule_live(bool \$v6 = false, bool \$fresh = false): bool {", 'E2: rule presence memoised per family');
has($gs, "if (!preg_match('/ (list|-S|test|-C) /', ' ' . \$cmd . ' ')) \$GLOBALS['smpro_gs_cache'] = ['members' => [], 'rules' => []];", 'E2b: any command that changes the set or the rules drops the snapshots, so a read right after a change is true');
has($gs, "function smpro_gs_has(string \$ip, bool \$fresh = false): bool {", 'E3: has() takes a fresh flag');
has($gs, "return isset(smpro_gs_members(smpro_gs_is6(\$ip))[strtolower(\$ip)]);", 'E4: ...and answers from the snapshot');
has($gs, "if (\$fresh) { [\$rc] = smpro_gs_x(escapeshellarg(smpro_gs_ipset()) . ' test '", 'E5: a fresh read still asks the kernel');
has($gl, "return smpro_gs_has(\$ip, \$refresh) && smpro_gs_rule_live(smpro_gs_is6(\$ip), \$refresh);", 'E6: the caller passes refresh through');
