<?php
/**
 * r18_panel_actions.php — Account Audit lists the panel actions of a searched address/account.
 *
 * 2026-09-08: an account was taken over with a stolen cPanel password; the attacker used File Manager through the
 * cpanel.<domain> proxy to plant a Google verification file and replace index.php. login_log had NO success line
 * for the account, and Account Audit searched for the attacker's address returned "0 matched": the page kept only
 * login / password-change lines from access_log and dropped every json-api Fileman call — the only trace there was.
 *
 *   P1 a search by address yields panel_action events with Module::func + the directory
 *   P2 a search by account yields the same
 *   P3 the unfiltered "all" view does NOT include panel actions (no flood)
 *   P4 event_type=panel_action lists them without a search text
 *   P5 the status is carried, the evidence line is redacted through smpro_redact_sensitive
 */
require __DIR__ . '/../support/bootstrap.php';
require SMPRO_BASE . '/tests/support/plugin_funcs.php';
smpro_plugin_funcs('includes/helpers.php');

$T = sys_get_temp_dir() . '/smpro_r18_' . getmypid(); @mkdir($T, 0700, true);
$acc = "$T/access_log"; $lg = "$T/login_log";
$d = gmdate('m/d/Y', time() - 3600);
file_put_contents($acc, implode("\n", [
    "203.0.113.9 proxy acctone [$d:12:21:19 -0000] \"GET /cpsess8253890742/json-api/cpanel?cpanel_jsonapi_module=Fileman&cpanel_jsonapi_func=listfiles&cpanel_jsonapi_apiversion=2&dir=%2fhome%2facctone%2fpublic_html&showdotfiles=1 HTTP/1.1\" 200 0 \"https://cpanel.a.example/cpsess8253890742/frontend/jupiter/filemanager/index.html\" \"Mozilla/5.0\" \"s\" \"X-Forwarded-For: 203.0.113.9\" 443",
    "203.0.113.9 proxy acctone [$d:12:22:02 -0000] \"POST /cpsess8253890742/execute/Fileman/save_file_content HTTP/1.1\" 200 0 \"-\" \"Mozilla/5.0\" \"s\" \"X-Forwarded-For: 203.0.113.9\" 443",
    "203.0.113.9 proxy acctone [$d:12:23:00 -0000] \"GET /cpsess8253890742/frontend/jupiter/filemanager/index.html?dir=%2Fhome%2Facctone HTTP/1.1\" 200 0 \"-\" \"Mozilla/5.0\" \"s\" \"X-Forwarded-For: 203.0.113.9\" 443",
    "203.0.113.9 proxy acctone [$d:12:23:05 -0000] \"GET /cpsess8253890742/frontend/jupiter/js/app.js HTTP/1.1\" 200 0 \"-\" \"Mozilla/5.0\" \"s\" \"X-Forwarded-For: 203.0.113.9\" 443",
    "198.51.100.7 - accttwo [$d:13:00:00 -0000] \"GET /login/?login_only=1&user=accttwo&pass=__HIDDEN__ HTTP/1.1\" 301 0 \"-\" \"Mozilla/5.0\" \"s\" \"-\" 2083",
]) . "\n");
file_put_contents($lg, "[" . gmdate('Y-m-d H:i:s', time() - 3600) . " +0000] info [cpaneld] 198.51.100.7 - accttwo \"GET /login/?login_only=1 HTTP/1.1\" SUCCESS LOGIN cpaneld\n");
define('SMPRO_AA_ACCESS_LOG', $acc); define('SMPRO_AA_LOGIN_LOG', $lg);
putenv('SMPRO_FIX_TAIL=' . $acc);   // the lab stubs `tail` on PATH; the stub prints this file instead
// The collector, the grouping and the verdict moved to includes/breakin.php so they could be reached from
// cron - a page module executes a router at include time and can never be required outside a browser.
// Both are loaded here: the page still owns the rendering, breakin.php now owns the judgement.
smpro_plugin_funcs('includes/breakin.php');
smpro_plugin_funcs('modules/account-audit.php');
ok(function_exists('smpro_aa_collect'), 'P0: collector loaded router-free');
if (DIRECTORY_SEPARATOR !== '/') { ok(true, 'P1-P5: (the collector streams through coreutils `timeout`, absent on Windows — exercised on the gate host)'); $src = (string)file_get_contents(SMPRO_BASE . '/modules/account-audit.php'); has($src, "'panel_action'=>'Panel actions (API / File Manager)'", 'P6: the type is selectable on the page'); @unlink($acc); @unlink($lg); return; }

$kinds = fn(array $ev) => array_values(array_unique(array_column($ev, 'kind')));
[$ev] = smpro_aa_collect('', 'all', 1000, 0, time() + 86400, '203.0.113.9');
$panel = array_values(array_filter($ev, fn($e) => $e['kind'] === 'panel_action'));
ok(count($panel) >= 2, 'P1: searching the address lists its panel actions (' . count($panel) . ')');
$ops = array_column($panel, 'action');
ok((bool)array_filter($ops, fn($o) => strpos($o, 'Fileman::listfiles /home/acctone/public_html') === 0), 'P1: json-api call is named Module::func + directory');
ok(in_array('Fileman::save_file_content', $ops, true), 'P1: UAPI execute call is named Module::func');
ok(!(bool)array_filter($ops, fn($o) => strpos($o, 'app.js') !== false), 'P1: static assets are not events');
foreach ($panel as $e) { is_eq($e['ip'], '203.0.113.9', 'P1: ip'); is_eq($e['account'], 'acctone', 'P1: account resolved from the actor'); is_eq($e['type'], 'Panel Action', 'P1: type label'); }

[$ev2] = smpro_aa_collect('acctone', 'all', 1000, 0, time() + 86400, '');
ok(count(array_filter($ev2, fn($e) => $e['kind'] === 'panel_action')) >= 2, 'P2: auditing the account lists its panel actions too');

[$ev3] = smpro_aa_collect('', 'all', 1000, 0, time() + 86400, '');
ok(!in_array('panel_action', $kinds($ev3), true), 'P3: the unfiltered view carries no panel actions (no flood)');

[$ev4] = smpro_aa_collect('', 'panel_action', 1000, 0, time() + 86400, '');
ok(count($ev4) >= 2 && $kinds($ev4) === ['panel_action'], 'P4: event_type=panel_action lists only panel actions, no search text needed');

$e = $panel[0];
is_eq($e['status'], '200', 'P5: HTTP status carried'); has($e['result'], 'HTTP 200', 'P5: result text');
hasnt($e['evidence'], 'pass=', 'P5: evidence never carries a password field');
ok((bool)array_filter($panel, fn($x) => strpos($x['evidence'], 'json-api') !== false), 'P5: evidence keeps the request line (events are newest-first, so check the set)');

$src = (string)file_get_contents(SMPRO_BASE . '/modules/account-audit.php');
has($src, "'panel_action'=>'Panel actions (API / File Manager)'", 'P6: the type is selectable on the page');
has($src, "'panel_action'=>['blue','Panel Action']", 'P6: badge for the new kind');
@unlink($acc); @unlink($lg);
