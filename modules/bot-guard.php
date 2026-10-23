<?php
/**
 * modules/bot-guard.php — Bot Guard page.
 *   Verified official crawlers → allowed · unverified bots → the admin decides · bots sending attack-signature
 *   requests → gray list · past the threshold → auto-blocked. Core logic: includes/botguard.php (shared with the
 *   worker bin/botguard_tick.php). This file is routing + rendering only.
 *   Every row carries a verdict (what it is, why, what blocking would cost), its impact on the sites (requests/hour,
 *   bad-request share, domains, last URLs), a live "Verify now", bulk actions with a filter, a 7-day summary, and CSV /
 *   print export.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }
require_once SMPRO_INCLUDES . '/botguard.php';
require_once SMPRO_INCLUDES . '/siteshield.php';
if (!function_exists('smpro_fw_allow_covers')) { $__fw = SMPRO_INCLUDES . '/fwallow.php'; if (is_file($__fw)) require_once $__fw; }

$reqMethod = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? getenv('REQUEST_METHOD') ?: 'GET'));
if ($reqMethod === 'POST' && isset($_POST['bg_action'])) {
    smpro_require_valid_csrf('bg_action'); smpro_require_root();
    header('Content-Type: application/json');
    $act = (string)$_POST['bg_action']; $by = function_exists('smpro_current_actor') ? smpro_current_actor() : 'root';
    $out = ['ok' => false, 'msg' => 'Unknown action.'];
    if ($act === 'rows') { $bgRowsReq = true; }   // one page of one list: answered below, once the lists exist
    elseif ($act === 'tf_refresh') { $r = function_exists('smpro_tf_fetch') ? smpro_tf_fetch() : ['ok' => false, 'msg' => 'not available in this build']; echo json_encode(['ok' => (bool)$r['ok'], 'msg' => (string)$r['msg']]); exit; }
    elseif ($act === 'settings') {
        $patch = [
            'enabled' => !empty($_POST['enabled']), 'auto_block' => !empty($_POST['auto_block']), 'allow_verified' => !empty($_POST['allow_verified']),
            'firewall_allow_verified' => !empty($_POST['firewall_allow_verified']),
            'gray_threshold' => (int)($_POST['gray_threshold'] ?? 25), 'window_hours' => (int)($_POST['window_hours'] ?? 24),
            'tail_lines' => (int)($_POST['tail_lines'] ?? 20000), 'max_logs' => (int)($_POST['max_logs'] ?? 150), 'scan_minutes' => (int)($_POST['scan_minutes'] ?? 15),
            'ignore_ips' => array_values(array_filter(array_map('trim', preg_split('/[\s,]+/', (string)($_POST['ignore_ips'] ?? ''))), fn($x) => $x !== '' && (function_exists('smpro_fw_cidr_valid') ? smpro_fw_cidr_valid($x) : filter_var($x, FILTER_VALIDATE_IP)))),
        ];
        // Operator-defined crawlers, one per line: key | Display name | kind | UA fragment | suffix[,suffix…]
        // Anything malformed is dropped by smpro_bg_catalog_custom rather than saved as a rule that looks applied
        // and is not — the same reasoning as the ignore list above.
        $custom = [];
        foreach (preg_split('/\r?\n/', (string)($_POST['custom_bots'] ?? '')) as $line) {
            $line = trim($line); if ($line === '' || $line[0] === '#') continue;
            $f = array_map('trim', explode('|', $line));
            if (count($f) < 5) continue;
            $custom[] = ['key' => $f[0], 'name' => $f[1], 'kind' => $f[2], 'ua' => $f[3],
                         'rdns' => array_filter(array_map('trim', explode(',', $f[4])))];
        }
        $patch['custom_bots'] = $custom;
        $cfg = smpro_bg_cfg_save($patch);
        $accepted = smpro_bg_catalog_custom($cfg);
        $cron = smpro_bg_cron_sync();
        smpro_audit('botguard_settings', ['custom_bots' => count($accepted), 'custom_sent' => count($custom), 'enabled' => $cfg['enabled'] ? 1 : 0, 'auto_block' => $cfg['auto_block'] ? 1 : 0, 'threshold' => $cfg['gray_threshold'], 'window_h' => $cfg['window_hours'], 'cron' => $cron ? 1 : 0, 'by' => $by]);
        $out = ['ok' => true, 'msg' => 'Saved. ' . ($cfg['enabled'] ? ($cron ? 'Worker scheduled every ' . $cfg['scan_minutes'] . ' min.' : 'WARNING: the cron entry could not be written — the worker will NOT run. Check /etc/cron.d is writable.') : 'Bot Guard is off — no worker scheduled; "Scan now" still works.'), 'custom_bots' => count($accepted), 'cfg' => $cfg];
    } elseif ($act === 'detail') {
        // Row details (User-Agent, cost/advice, last requests) are fetched on demand: with hundreds of bots the page
        // would otherwise carry a megabyte of text that is read for a handful of rows.
        $dst = smpro_bg_state(); $dcfg = smpro_bg_cfg(); $dip = (string)($_POST['ip'] ?? '');
        if (isset($dst['bots'][$dip])) {
            $db = $dst['bots'][$dip]; $das = smpro_bg_assess($db, $dcfg);
            $out = ['ok' => true, 'ua' => (string)($db['ua'] ?? ''), 'cost' => (string)($das['cost'] ?? ''), 'advice' => (string)($das['advice'] ?? ''),
                    'urls' => array_values((array)($db['urls'] ?? [])), 'sample' => (string)($db['sample'] ?? ''), 'note' => (string)($db['note'] ?? '')];
        } else $out = ['ok' => false, 'msg' => 'Unknown address.'];
    } elseif ($act === 'shield_on' || $act === 'shield_off') {
        [$sok, $smsg] = $act === 'shield_on' ? smpro_ss_enable((string)($_POST['domain'] ?? '')) : smpro_ss_disable((string)($_POST['domain'] ?? ''));
        $out = ['ok' => $sok, 'msg' => $smsg];
    } elseif ($act === 'scan') {
        $out = smpro_bg_run(true);
    } elseif ($act === 'bulk') {
        $bact = (string)($_POST['act'] ?? '');
        if (in_array($bact, ['allow', 'block', 'ignore', 'deny', 'unblock', 'reset', 'verify'], true))
            $out = smpro_bg_bulk($bact, explode(',', (string)($_POST['ips'] ?? '')), $by, ['firewall' => !empty($_POST['firewall'])]);
    } elseif (in_array($act, ['allow', 'block', 'ignore', 'deny', 'unblock', 'reset', 'verify'], true)) {
        $out = smpro_bg_action($act, (string)($_POST['ip'] ?? ''), $by, ['firewall' => !empty($_POST['firewall'])]);
    }
    if (empty($bgRowsReq)) { echo json_encode($out, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit; }
}

$cfg = smpro_bg_cfg(); $st = smpro_bg_state(); $csrf = smpro_csrf_generate('bg_action');
$bots = $st['bots'];
foreach ($bots as $ip => &$b) { $b['assess'] = smpro_bg_assess($b, $cfg); } unset($b);

/* ---------- export (GET, read-only) ---------- */
$export = (string)($_GET['export'] ?? '');
if ($export === 'csv') {
    smpro_audit('botguard_export', ['fmt' => 'csv', 'rows' => count($bots)]);
    header('Content-Type: text/csv; charset=utf-8'); header('Content-Disposition: attachment; filename="bot-guard-' . date('Ymd-Hi') . '.csv"');
    $fh = fopen('php://output', 'w'); fwrite($fh, "\xEF\xBB\xBF");
    foreach (smpro_bg_export_rows($st, $cfg) as $r) { if (function_exists('smpro_fputcsv')) smpro_fputcsv($fh, $r); else fputcsv($fh, $r); }
    fclose($fh); exit;
}

uasort($bots, fn($a, $b) => (smpro_bg_rank($a['assess']['verdict']) <=> smpro_bg_rank($b['assess']['verdict'])) ?: (($b['attacks'] <=> $a['attacks']) ?: ($b['last'] <=> $a['last'])));
$groups = ['allowed' => [], 'pending' => [], 'gray' => [], 'blocked' => [], 'ignored' => [], 'denied' => []];
foreach ($bots as $ip => $b) { $s = $b['status'] ?? 'pending'; if ($s === 'block') $s = 'gray'; if (!isset($groups[$s])) $s = 'pending'; $groups[$s][$ip] = $b; }
$dry = function_exists('smpro_ctl_dry_run') && smpro_ctl_dry_run();
$domBase = smpro_bg_domlogs_base();
$cronOk = !$cfg['enabled'] || is_file('/etc/cron.d/smpro-botguard');
$lastScan = (int)($st['last_scan'] ?? 0);
$catalog = smpro_bg_catalog();
$hist = is_array($st['history'] ?? null) ? $st['history'] : [];
$days7 = []; for ($i = 6; $i >= 0; $i--) { $d = date('Y-m-d', time() - $i * 86400); $days7[$d] = $hist[$d] ?? ['tracked' => 0, 'new_pending' => 0, 'autoblocked' => 0, 'manual_blocked' => 0, 'allowed' => 0, 'top' => []]; }
$sum7 = ['new_pending' => 0, 'autoblocked' => 0, 'manual_blocked' => 0, 'top' => []];
foreach ($days7 as $r) { foreach (['new_pending', 'autoblocked', 'manual_blocked'] as $k) $sum7[$k] += (int)$r[$k]; foreach ((array)$r['top'] as $ip => $n) $sum7['top'][$ip] = max((int)($sum7['top'][$ip] ?? 0), (int)$n); }
arsort($sum7['top']); $sum7['top'] = array_slice($sum7['top'], 0, 5, true);
$maxTracked = max(1, max(array_map(fn($r) => (int)$r['tracked'], $days7)));
$print = $export === 'html';

$ago = function ($ts) { $ts = (int)$ts; if ($ts <= 0) return '—'; $d = time() - $ts; if ($d < 60) return $d . 's ago'; if ($d < 3600) return intdiv($d, 60) . 'm ago'; if ($d < 86400) return intdiv($d, 3600) . 'h ago'; return intdiv($d, 86400) . 'd ago'; };
$catsTxt = function (array $c) { arsort($c); $o = []; foreach ($c as $k => $n) $o[] = smpro_h($k) . ' ×' . (int)$n; return implode(', ', $o); };
$ccName = fn($cc) => $cc !== '' ? (function_exists('smpro_cc_name') ? smpro_cc_name($cc) : $cc) : '';
$needleOf = function ($ip, array $b) use ($ccName) { $as = $b['assess']; return strtolower($ip . ' ' . ($b['name'] ?? '') . ' ' . ($b['kind'] ?? '') . ' ' . ($b['country'] ?? '') . ' ' . $ccName((string)($b['country'] ?? '')) . ' ' . ($b['provider'] ?? '') . ' ' . $as['verdict'] . ' ' . $as['label'] . ' ' . implode(' ', array_keys((array)($b['domains_top'] ?? []))) . ' ' . ($b['ua'] ?? '') . ' ' . ($b['host'] ?? '')); };
/* Rows of one list as HTML (no table around them): the page renders the first 50 of each list this way, and the
   'rows' action below renders any later page or a filtered page on demand - a server with thousands of tracked
   clients used to ship every row (3.8 MB) on each open. */
$rowHtml = function (array $rows, string $mode) use ($ago, $catsTxt, $ccName, $needleOf, $print) {
    ob_start();
    foreach ($rows as $ip => $b) {
        $as = $b['assess']; $ipH = smpro_h($ip); $cats = (array)($b['cats'] ?? []);
        $needle = $needleOf($ip, $b);
        echo '<tr data-row="1" data-ip="' . $ipH . '" data-v="' . smpro_h($as['verdict']) . '" data-k="' . smpro_h(($b['kind'] ?? '') !== '' ? $b['kind'] : '-') . '" data-s="' . smpro_h($needle) . '">';
        if (!$print) echo '<td><input type="checkbox" class="bgSel" value="' . $ipH . '"></td>';
        echo '<td><span class="bg-ip">' . $ipH . '</span><div class="bg-note">' . smpro_h(trim($ccName((string)($b['country'] ?? '')) . ' · ' . ($b['provider'] ?? ''), ' ·')) . '</div>'
           . (($b['host'] ?? '') !== '' ? '<div class="bg-note">rDNS: ' . smpro_h($b['host']) . '</div>' : '')
           . '<div class="bg-note">first ' . smpro_h($ago($b['first'] ?? 0)) . ' · last ' . smpro_h($ago($b['last'] ?? 0)) . '</div></td>';
        echo '<td><span class="bg-pill bg-v-' . smpro_h($as['verdict']) . '">' . smpro_h($as['label']) . '</span>';
        if (($b['name'] ?? '') !== '') echo '<span class="bg-pill k">' . smpro_h(smpro_bg_kind_label((string)($b['kind'] ?? ''))) . '</span>' . (!empty($b['verified']) ? '<span class="bg-pill v">verified · ' . smpro_h((string)($b['how'] ?? '')) . '</span>' : '<span class="bg-pill u">not verified</span>');
        echo '<div><b>' . smpro_h($as['what']) . '</b></div><div class="bg-why">' . smpro_h(implode(' · ', $as['why'])) . '</div>';
        $uaTxt = ($b['ua'] ?? '') !== '' ? $b['ua'] : '(no User-Agent)';
        if ($print) {
            if ($as['cost'] !== '') echo '<div class="bg-cost"><b>If blocked:</b> ' . smpro_h($as['cost']) . '. <b>Advice:</b> ' . smpro_h($as['advice']) . '.</div>';
            echo '<div class="bg-ua">' . smpro_h($uaTxt) . '</div>';
        } else {
            echo '<details class="bg-more bg-lazy"><summary>' . ($as['cost'] !== '' ? 'if blocked · advice · ' : '') . 'User-Agent · last requests</summary><div class="bg-lazybody meta">loading…</div></details>';
        }
        if (($b['note'] ?? '') !== '') echo '<div class="bg-note">' . smpro_h($b['note']) . '</div>';
        if (($b['decided_by'] ?? '') !== '') echo '<div class="bg-note">decided by ' . smpro_h($b['decided_by']) . '</div>';
        echo '</td>';
        $tops = (array)($b['domains_top'] ?? []); $topTxt = []; foreach ($tops as $dn => $n) $topTxt[] = smpro_h($dn) . ' (' . (int)$n . ')';
        $codes = (array)($b['statuses'] ?? []); arsort($codes); $codeTxt = []; foreach (array_slice($codes, 0, 4, true) as $c => $n) $codeTxt[] = (int)$c . '×' . (int)$n;
        echo '<td class="bg-imp"><div><b>' . (int)($b['hits'] ?? 0) . '</b> requests · <b>' . smpro_h((string)($b['hits_per_hour'] ?? 0)) . '/h</b> · <b style="color:' . ((int)($b['attacks'] ?? 0) > 0 ? '#dc2626' : '#16a34a') . '">' . (int)($b['attacks'] ?? 0) . ' bad (' . (int)($b['bad_ratio'] ?? 0) . '%)</b></div>'
           . '<div>' . (int)($b['domains'] ?? 0) . ' domain(s)' . ($topTxt ? ': ' . implode(', ', $topTxt) : '') . '</div>'
           . ($codeTxt ? '<div class="bg-note">HTTP ' . smpro_h(implode(' ', $codeTxt)) . '</div>' : '')
           . ($cats ? '<div class="bg-note">' . $catsTxt($cats) . '</div>' : '')
           . ($print ? (!empty($b['urls']) ? '<div class="bg-urls">' . smpro_h(implode("
", (array)$b['urls'])) . '</div>' : (($b['sample'] ?? '') !== '' ? '<div class="bg-urls">' . smpro_h($b['sample']) . '</div>' : '')) : '')   // on screen the requests come with the on-demand details
           . '</td>';
        if (!$print) {
            echo '<td class="bg-actc"><div class="bg-acts">';
            if (($b['family'] ?? '') !== '' || smpro_bg_family((string)($b['ua'] ?? '')) !== '') echo '<button type="button" class="bg-act" data-act="verify">&#8635; Verify now</button>';
            if ($mode !== 'allowed')  echo '<button type="button" class="bg-act ok" data-act="allow">&#10003; Allow</button>';
            if ($mode === 'allowed')  echo '<button type="button" class="bg-act ok" data-act="allow" data-fw="1">&#10003; Allow in firewall too</button>';
            if ($mode !== 'blocked')  echo '<button type="button" class="bg-act bad" data-act="block">&#10006; Block</button>';
            if ($mode === 'blocked')  echo '<button type="button" class="bg-act" data-act="unblock">Unblock</button>';
            if ($mode === 'pending')  echo '<button type="button" class="bg-act" data-act="deny">Not legitimate</button><button type="button" class="bg-act" data-act="ignore">Ignore</button>';
            if ($mode === 'gray')     echo '<button type="button" class="bg-act" data-act="ignore">Ignore</button>';
            if (in_array($mode, ['ignored', 'denied', 'allowed'], true)) echo '<button type="button" class="bg-act" data-act="reset">Reset</button>';
            echo '</div></td>';
        }
        echo '</tr>';
    }
    return (string)ob_get_clean();
};
/* Server-side filter: the same needle the rows carry, plus verdict and kind. */
$bgFilter = function (array $rows, string $q, string $v, string $k) use ($needleOf) {
    $q = strtolower(trim($q)); if ($q === '' && $v === '' && $k === '') return $rows;
    $out = [];
    foreach ($rows as $ip => $b) {
        if ($v !== '' && (string)$b['assess']['verdict'] !== $v) continue;
        if ($k !== '' && ((($b['kind'] ?? '') !== '' ? (string)$b['kind'] : '-') !== $k)) continue;
        if ($q !== '' && strpos($needleOf($ip, $b), $q) === false) continue;
        $out[$ip] = $b;
    }
    return $out;
};
/* Grouping: a crawler family (Googlebot, Facebook, Bytespider...) or, for anonymous clients, the verdict + the
   network they come from. Thousands of addresses collapse into a few dozen identities; each group row carries
   totals, the countries, and the same actions, applied to every address in it. */
$groupKeyOf = function ($ip, array $b) {
    if (($b['name'] ?? '') !== '') return 'n:' . strtolower((string)$b['name']);
    $prov = strtolower(trim((string)($b['provider'] ?? '')));
    $prov = preg_replace('/\s*(as\d+|inc\.?|ltd\.?|llc|gmbh|s\.a\.|co\.|corp\.?|,.*)$/i', '', $prov);
    return 'v:' . (string)$b['assess']['verdict'] . '|' . ($prov !== '' ? $prov : '-');
};
$groupsOf = function (array $rows) use ($groupKeyOf, $ccName) {
    $g = [];
    foreach ($rows as $ip => $b) {
        $k = $groupKeyOf($ip, $b);
        if (!isset($g[$k])) {
            $g[$k] = ['key' => $k, 'label' => ($b['name'] ?? '') !== '' ? (string)$b['name'] : (string)$b['assess']['label'],
                      'sub' => ($b['name'] ?? '') !== '' ? smpro_bg_kind_label((string)($b['kind'] ?? '')) : trim((string)($b['provider'] ?? '')),
                      'verdict' => (string)$b['assess']['verdict'], 'vlabel' => (string)$b['assess']['label'], 'what' => (string)$b['assess']['what'],
                      'n' => 0, 'verified' => 0, 'hits' => 0, 'attacks' => 0, 'domains' => 0, 'cc' => [], 'ips' => [], 'first' => 0, 'last' => 0, 'family' => ($b['family'] ?? '') !== '' || smpro_bg_family((string)($b['ua'] ?? '')) !== '',
                      'prov' => trim((string)($b['provider'] ?? '')), 'advice' => (string)($b['assess']['advice'] ?? '')];
        }
        $e = &$g[$k]; $e['n']++; if (!empty($b['verified'])) $e['verified']++;
        $e['hits'] += (int)($b['hits'] ?? 0); $e['attacks'] += (int)($b['attacks'] ?? 0); $e['domains'] = max($e['domains'], (int)($b['domains'] ?? 0));
        $cc = (string)($b['country'] ?? ''); if ($cc !== '') $e['cc'][$cc] = ($e['cc'][$cc] ?? 0) + 1;
        $e['ips'][] = $ip; $f = (int)($b['first'] ?? 0); $l = (int)($b['last'] ?? 0);
        if ($f && (!$e['first'] || $f < $e['first'])) $e['first'] = $f; if ($l > $e['last']) $e['last'] = $l; unset($e);
    }
    // what the NETWORK is (rented servers vs. a home line) - the verdict alone left the operator guessing whether
    // "Google LLC" meant Googlebot or a box rented in Google's cloud
    foreach ($g as $k => $e) $g[$k]['net'] = function_exists('smpro_bg_net_kind') ? smpro_bg_net_kind($e['ips'], $e['prov'], (bool)$e['family']) : ['kind' => 'unknown', 'text' => ''];
    uasort($g, fn($a, $b) => ($b['n'] <=> $a['n']) ?: ($b['attacks'] <=> $a['attacks']));
    return $g;
};
/* the advice in the words of the buttons on the row */
$adviceOf = function (array $e, string $mode): string {
    $v = $e['verdict'];
    if ($v === 'trusted') return 'nothing - keep it allowed; blocking costs search traffic or link previews';
    if ($v === 'impersonator' || $v === 'attacker') return $mode === 'blocked' ? 'nothing - it is blocked; "Unblock all" only if you are sure it is a customer\'s own tool' : 'press "Block all" - no visitor is lost' . ($e['net']['kind'] === 'hosting' ? ' (rented servers, not people)' : '');
    if ($v === 'suspicious') return 'watch it; "Block all" if the bad requests continue (auto-block takes over past the threshold)';
    if ($v === 'scraper') return 'your policy: "Allow all" if you want the sites read by it, "Block all" if not - no visitor is lost either way';
    if ($v === 'harmless') return '"Ignore all" - a light tool with nothing bad';
    return 'open the group (the small arrow) and look at the domains and URLs it touches; "Verify all" re-checks a claimed crawler; then "Allow all" or "Block all"';
};
$groupHtml = function (array $groups, string $mode) use ($ago, $ccName, $adviceOf) {
    ob_start();
    foreach ($groups as $e) {
        arsort($e['cc']); $ccs = []; foreach (array_slice($e['cc'], 0, 4, true) as $cc => $n) $ccs[] = smpro_h($ccName((string)$cc)) . ' ×' . (int)$n;
        $more = count($e['cc']) > 4 ? ' +' . (count($e['cc']) - 4) . ' more' : '';
        echo '<tr class="bg-grp" data-g="' . smpro_h($e['key']) . '" data-ips="' . smpro_h(implode(',', $e['ips'])) . '">';
        echo '<td><input type="checkbox" class="bgGrpSel" value="' . smpro_h(implode(',', $e['ips'])) . '" title="select every address in this group"></td>';
        echo '<td><span class="bg-gx" title="show the addresses">&#9656;</span> <b>' . smpro_h($e['label']) . '</b>' . ($e['sub'] !== '' ? ' <span class="bg-note" style="display:inline">' . smpro_h($e['sub']) . '</span>' : '')
           . '<div class="bg-note">' . (int)$e['n'] . ' address' . ($e['n'] === 1 ? '' : 'es') . ($ccs ? ' · ' . implode(', ', $ccs) . $more : '') . '</div>'
           . '<div class="bg-note">first ' . smpro_h($ago($e['first'])) . ' · last ' . smpro_h($ago($e['last'])) . '</div></td>';
        echo '<td><span class="bg-pill bg-v-' . smpro_h($e['verdict']) . '">' . smpro_h($e['vlabel']) . '</span>'
           . ($e['verified'] ? '<span class="bg-pill v">' . (int)$e['verified'] . ' verified</span>' : '') . ($e['n'] - $e['verified'] > 0 && $e['verified'] ? '<span class="bg-pill u">' . (int)($e['n'] - $e['verified']) . ' not</span>' : '')
           . '<div class="bg-why">' . smpro_h($e['what']) . '</div>'
           . (($e['net']['text'] ?? '') !== '' ? '<div class="bg-net ' . smpro_h($e['net']['kind']) . '"><b>What it is:</b> ' . smpro_h($e['net']['text']) . '</div>' : '')
           . '<div class="bg-todo"><b>What to do:</b> ' . smpro_h($adviceOf($e, $mode)) . '</div></td>';
        echo '<td class="bg-imp"><div><b>' . (int)$e['hits'] . '</b> requests · <b style="color:' . ($e['attacks'] > 0 ? '#dc2626' : '#16a34a') . '">' . (int)$e['attacks'] . ' bad</b></div><div>up to ' . (int)$e['domains'] . ' domain(s) per address</div></td>';
        echo '<td class="bg-actc"><div class="bg-acts">';
        if ($e['family']) echo '<button type="button" class="bg-act" data-gact="verify">&#8635; Verify all</button>';
        if ($mode !== 'allowed') echo '<button type="button" class="bg-act ok" data-gact="allow">&#10003; Allow all</button>';
        if ($mode !== 'blocked') echo '<button type="button" class="bg-act bad" data-gact="block">&#10006; Block all</button>';
        if ($mode === 'blocked') echo '<button type="button" class="bg-act" data-gact="unblock">Unblock all</button>';
        if ($mode === 'pending') echo '<button type="button" class="bg-act" data-gact="deny">Not legitimate</button><button type="button" class="bg-act" data-gact="ignore">Ignore all</button>';
        if ($mode === 'gray') echo '<button type="button" class="bg-act" data-gact="ignore">Ignore all</button>';
        if (in_array($mode, ['ignored', 'denied', 'allowed'], true)) echo '<button type="button" class="bg-act" data-gact="reset">Reset all</button>';
        echo '</div></td></tr>';
    }
    return (string)ob_get_clean();
};
$bgGrouped = !$print;   // the screen groups by identity; print lists every address
$renderRows = function (array $rows, string $mode) use ($rowHtml, $print, $groupsOf, $groupHtml, $bgGrouped) {
    if (!$rows) { echo '<div class="bg-empty">Nothing here.</div>'; return; }
    if ($bgGrouped) { $gs = $groupsOf($rows); $total = count($gs); $page = array_slice($gs, 0, 50, true); }
    else { $total = count($rows); $page = $print ? $rows : array_slice($rows, 0, 50, true); }
    echo '<div class="smpro-tablewrap" data-nopage="1"><table class="bg-tbl" id="bgTbl-' . smpro_h($mode) . '" data-mode="' . smpro_h($mode) . '" data-total="' . $total . '" data-addresses="' . count($rows) . '" data-grouped="' . ($bgGrouped ? 1 : 0) . '"><thead><tr>' . ($print ? '' : '<th><input type="checkbox" class="bgAll" title="select all in this list"></th>') . '<th>Address</th><th>Verdict &amp; identity</th><th>Impact on the sites</th>' . ($print ? '' : '<th>Actions</th>') . '</tr></thead><tbody>';
    echo $bgGrouped ? $groupHtml($page, $mode) : $rowHtml($page, $mode);
    echo '</tbody></table></div>';
    if (!$print && $total > 50) {
        $pages = (int)ceil($total / 50);
        echo '<div class="fw-pgbar bg-pg" data-mode="' . smpro_h($mode) . '"><span class="fw-pginfo">Showing 1&ndash;50 of ' . $total . '</span><span class="sp"></span>'
           . '<button type="button" class="fw-pgbtn" data-d="-1" disabled>&#8249; prev</button><span class="fw-pgnum">1 / ' . $pages . '</span><button type="button" class="fw-pgbtn" data-d="1">next &#8250;</button></div>';
    }
};
if (!empty($bgRowsReq)) {   // one page of one list, filtered on the server (answers the deferred POST before any HTML)
    $mode = preg_replace('/[^a-z]/', '', (string)($_POST['mode'] ?? '')); $off = max(0, (int)($_POST['offset'] ?? 0));
    $src = $mode === 'ignored' ? ($groups['ignored'] + $groups['denied']) : ($groups[$mode] ?? null);
    if ($src === null) { echo json_encode(['ok' => false, 'msg' => 'Unknown list.']); exit; }
    $f = $bgFilter($src, (string)($_POST['q'] ?? ''), preg_replace('/[^a-z]/', '', (string)($_POST['v'] ?? '')), preg_replace('/[^a-z-]/', '', (string)($_POST['k'] ?? '')));
    $grp = (string)($_POST['grp'] ?? '');
    if ($grp !== '') {   // the addresses behind one group row (expand)
        $in = []; foreach ($f as $ip => $b) { if ($groupKeyOf($ip, $b) === $grp) { $in[$ip] = $b; if (count($in) >= 500) break; } }
        echo json_encode(['ok' => true, 'count' => count($in), 'html' => $rowHtml($in, $mode)], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit;
    }
    if ((string)($_POST['g'] ?? '1') === '1') { $gs = $groupsOf($f); $total = count($gs); $page = array_slice($gs, $off, 50, true); $html = $groupHtml($page, $mode); }
    else { $total = count($f); $page = array_slice($f, $off, 50, true); $html = $rowHtml($page, $mode); }
    echo json_encode(['ok' => true, 'total' => $total, 'addresses' => count($f), 'offset' => $off, 'count' => count($page), 'html' => $html], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit;
}
smpro_audit('botguard_view', ['pending' => count($groups['pending']), 'gray' => count($groups['gray']), 'print' => $print ? 1 : 0]);
smpro_layout_header('Bot Guard');
?>
<script>var BG_CSRF=<?= json_encode($csrf) ?>;
document.addEventListener('DOMContentLoaded',function(){var b=document.getElementById('bgTfRefresh');if(!b)return;b.addEventListener('click',function(){b.disabled=true;var m=document.getElementById('bgTfMsg');m.textContent='pulling…';var fd=new URLSearchParams();fd.set('bg_action','tf_refresh');fd.set('smpro_csrf',BG_CSRF);
  fetch('index.cgi?page=bot-guard',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'}).then(function(r){return r.json();}).then(function(j){m.textContent=(j.ok?'done: ':'not updated: ')+(j.msg||'');if(j.ok)setTimeout(function(){location.reload();},1500);else b.disabled=false;}).catch(function(){m.textContent='the request did not complete';b.disabled=false;});});});</script>
<style>
/* .fw-kpis / .fw-nav / .fw-collapse / pager styles: shared, in includes/layout.php */
.bg-hd{display:flex;align-items:center;gap:10px;flex-wrap:wrap;padding:12px 16px;border-bottom:1px solid var(--line,#e5e7eb)}
.bg-hd b{font-size:15px}.bg-hd .meta{font-size:12.5px;opacity:.75}.bg-hd .bg-n{font-size:11.5px;font-weight:800;padding:1px 8px;border-radius:999px;background:var(--brand-bg,rgba(37,99,235,.1));color:var(--brand,#2563eb)}
.card.bg-c{padding:0!important}.card.bg-c>.fw-collapse{padding:4px 8px}.card.bg-c>.fw-collapse.pad{padding:14px 18px}
.bg-ua{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:420px}
.bg-more{margin-top:3px}.bg-more>summary{cursor:pointer;font-size:11.5px;opacity:.7;list-style:none}.bg-more>summary::-webkit-details-marker{display:none}.bg-more[open]>summary{opacity:1}.bg-more[open] .bg-ua{white-space:normal;word-break:break-all}.bg-lazybody.meta{font-size:11.5px;opacity:.7}
.bg-grp td{background:var(--brand-bg,rgba(37,99,235,.05))}.bg-gx{display:inline-block;cursor:pointer;color:var(--brand,#2563eb);font-weight:800;transition:transform .15s;margin-right:2px}.bg-grp.open .bg-gx{transform:rotate(90deg)}.bg-sub td:first-child{padding-left:26px}.bg-sub .bg-ip{font-weight:600}
td.bg-actc{white-space:nowrap}td.bg-actc .bg-acts{display:grid;grid-template-columns:auto auto;gap:3px;justify-content:start}
.bg-tbl .bg-act{padding:3px 8px;font-size:11.5px;margin:0}
.bg-stale{display:inline-block;font-size:11px;font-weight:700;color:var(--warn,#b45309);margin-left:8px}
@media print{.fw-nav,.fw-pgbar{display:none!important}}
.bg-kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:14px 0 18px}
.bg-kpi{background:var(--card,#fff);border:1px solid var(--line,#e5e7eb);border-radius:10px;padding:12px 14px}
.bg-kpi .n{font-size:26px;font-weight:800;line-height:1.1}.bg-kpi .l{font-size:12px;opacity:.75;margin-top:4px}
.bg-kpi.ok .n{color:#16a34a}.bg-kpi.warn .n{color:#b45309}.bg-kpi.gray .n{color:#6b7280}.bg-kpi.bad .n{color:#dc2626}
.bg-sec{margin:22px 0 8px;display:flex;align-items:baseline;gap:10px;flex-wrap:wrap}.bg-sec h2{margin:0;font-size:17px}.bg-sec .meta{font-size:12.5px;opacity:.75}
.bg-tbl{width:100%;border-collapse:collapse;font-size:13px}.bg-tbl th{text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.04em;opacity:.7;padding:8px 8px;border-bottom:1px solid var(--line,#e5e7eb)}
.bg-tbl td{padding:8px;border-bottom:1px solid var(--line,#e5e7eb);vertical-align:top}.bg-tbl tr:last-child td{border-bottom:0}.bg-tbl tr.hide{display:none}
.bg-ua{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:11.5px;opacity:.85;word-break:break-all;max-width:380px}
.bg-ip{font-family:ui-monospace,Menlo,Consolas,monospace;font-weight:700}
.bg-pill{display:inline-block;font-size:10.5px;font-weight:800;padding:2px 7px;border-radius:999px;letter-spacing:.03em;text-transform:uppercase;margin-right:4px}
.bg-pill.v{background:rgba(22,163,74,.12);color:#16a34a}.bg-pill.u{background:rgba(107,114,128,.14);color:#4b5563}.bg-pill.g{background:rgba(180,83,9,.14);color:#b45309}.bg-pill.b{background:rgba(220,38,38,.12);color:#dc2626}.bg-pill.k{background:rgba(37,99,235,.12);color:#2563eb}.bg-pill.p{background:rgba(147,51,234,.14);color:#7e22ce}
.bg-v-trusted{background:rgba(22,163,74,.12);color:#16a34a}.bg-v-impersonator{background:rgba(147,51,234,.14);color:#7e22ce}.bg-v-attacker{background:rgba(220,38,38,.12);color:#dc2626}.bg-v-suspicious{background:rgba(180,83,9,.14);color:#b45309}.bg-v-scraper{background:rgba(37,99,235,.12);color:#2563eb}.bg-v-harmless{background:rgba(107,114,128,.14);color:#4b5563}.bg-v-unknown{background:rgba(107,114,128,.14);color:#4b5563}
.bg-why{font-size:12.3px;line-height:1.55;opacity:.92;margin-top:3px}
.bg-net,.bg-todo{font-size:11.8px;line-height:1.5;margin-top:4px;padding-left:7px;border-left:2px solid var(--line,#e5e7eb)}.bg-net b,.bg-todo b{opacity:1}
.bg-net.hosting{border-left-color:#dc2626}.bg-net.home{border-left-color:#16a34a}.bg-todo{border-left-color:var(--brand,#2563eb)}.bg-cost{font-size:11.5px;opacity:.75;margin-top:2px}.bg-cost b{opacity:1}
.bg-act{display:inline-block;border:1px solid var(--line,#d1d5db);background:var(--card,#fff);border-radius:7px;padding:4px 9px;font-size:12px;cursor:pointer;margin:1px 2px 1px 0}
.bg-act.ok{border-color:#16a34a;color:#16a34a}.bg-act.bad{border-color:#dc2626;color:#dc2626}.bg-act.pri{background:#2563eb;border-color:#2563eb;color:#fff;font-weight:700;padding:7px 14px;font-size:13px}.bg-act:disabled{opacity:.5;cursor:default}
.bg-empty{opacity:.7;padding:14px 8px;font-size:13px}
.bg-form{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px 18px}.bg-form label{display:flex;flex-direction:column;gap:4px;font-size:12.5px}
.bg-form label.cb{flex-direction:row;align-items:center;gap:8px}.bg-form input[type=number],.bg-form input[type=text],.bg-filter input,.bg-filter select{padding:6px 8px;border:1px solid var(--line,#d1d5db);border-radius:6px;font-size:13px}
.bg-msg{margin-top:8px;font-size:13px;min-height:18px}
.bg-warn{background:rgba(180,83,9,.08);border:1px solid rgba(180,83,9,.35);border-radius:8px;padding:10px 14px;margin:10px 0;font-size:13px}
.bg-note{font-size:11.5px;opacity:.75;margin-top:3px}
.bg-cat{font-size:12px;opacity:.85;line-height:1.7;columns:3;column-gap:24px}@media(max-width:900px){.bg-cat{columns:1}}
.bg-filter{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:8px 0 10px}.bg-filter .cnt{font-size:12px;opacity:.7}
.bg-bulk{position:sticky;top:0;z-index:5;display:none;align-items:center;gap:8px;flex-wrap:wrap;background:#1f2937;color:#fff;padding:8px 12px;border-radius:8px;margin:8px 0}.bg-bulk.on{display:flex}.bg-bulk b{margin-right:6px}
.bg-imp{font-size:12px;line-height:1.55}.bg-imp b{font-weight:700}.bg-urls{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:11px;opacity:.85;white-space:pre-wrap;word-break:break-all;margin-top:3px}
.bg-hist{display:grid;grid-template-columns:2fr 1fr;gap:14px}@media(max-width:900px){.bg-hist{grid-template-columns:1fr}}
.bg-bars{display:flex;align-items:flex-end;gap:8px;height:90px;padding:6px 4px 0}.bg-bar{flex:1;display:flex;flex-direction:column;align-items:center;gap:3px;font-size:10.5px;opacity:.85}.bg-bar i{display:block;width:100%;background:#2563eb;border-radius:4px 4px 0 0;min-height:2px}.bg-bar i.r{background:#dc2626}
.bg-toplist{font-size:12.5px;line-height:1.8}.bg-toplist .bg-ip{font-weight:600}
@media print{.bg-act,.bg-bulk,.bg-filter,#bgForm,.svc-kicker,.bg-cat,input[type=checkbox]{display:none!important}.bg-tbl td,.bg-tbl th{padding:4px 6px;font-size:11px}}
</style>
<div class="svc-kicker">Security &amp; Access</div>
<h1 class="h" style="margin:2px 0 4px">&#129302; Bot Guard</h1>
<p class="sub">Every automated client seen in the web logs, sorted into four buckets: <b>official crawlers</b> are verified the way their publishers document (forward-confirmed reverse DNS or published IP ranges) and allowed; <b>unverified bots</b> wait for your decision; a bot that sends attack-signature requests goes to the <b>gray list</b>; past the threshold it is <b>blocked automatically</b> through the same guarded path the Intrusion Monitor uses. Each row says what the client is, why, what it does to the sites, and what blocking it would cost.</p>

<?php if ($domBase === ''): ?><div class="bg-warn">&#9888; No Apache domlogs directory was found on this server, so Bot Guard can only see WAF (ModSecurity) events — it cannot recognise crawlers by User-Agent here.</div><?php endif; ?>
<?php if ($dry): ?><div class="bg-warn">&#9888; The plugin is in <b>Dry-Run</b>: gray-listed addresses past the threshold are recorded as "would block" and nothing is blocked.</div><?php endif; ?>
<?php if (!$cronOk): ?><div class="bg-warn">&#9888; Bot Guard is enabled but its cron entry is missing — the worker is not running. Save the settings again to reinstall it.</div><?php endif; ?>

<?php
$bgIgnN  = count($groups['ignored']) + count($groups['denied']);
$bgStale = !$lastScan ? 'dang' : ($lastScan < time() - max(3600, 2 * (int)$cfg['scan_minutes'] * 60) ? 'warn' : 'good');
$bgScanS = ($lastScan ? (int)($st['last_files'] ?? 0) . ' logs, ' . number_format((int)($st['last_lines'] ?? 0)) . ' lines' : 'no scan recorded') . ' · worker ' . ($cfg['enabled'] ? 'every ' . (int)$cfg['scan_minutes'] . ' min' : 'OFF');
if (!$print): ?>
<div class="fw-kpis">
  <a class="fw-kpi good" href="#bg-allowed" data-go="bg-allowed"><div class="l">Allowed</div><div class="v"><?= count($groups['allowed']) ?></div><div class="s">verified crawlers + your allows</div></a>
  <a class="fw-kpi <?= count($groups['pending']) ? 'warn' : 'muted' ?>" href="#bg-pending" data-go="bg-pending"><div class="l">Awaiting decision</div><div class="v"><?= count($groups['pending']) ?></div><div class="s">unverified, no bad request yet</div></a>
  <a class="fw-kpi <?= count($groups['gray']) ? 'warn' : 'muted' ?>" href="#bg-gray" data-go="bg-gray"><div class="l">Gray list</div><div class="v"><?= count($groups['gray']) ?></div><div class="s">attacking, under threshold <?= (int)$cfg['gray_threshold'] ?></div></a>
  <a class="fw-kpi <?= count($groups['blocked']) ? 'dang' : 'muted' ?>" href="#bg-blocked" data-go="bg-blocked"><div class="l">Blocked</div><div class="v"><?= count($groups['blocked']) ?></div><div class="s">by Bot Guard or by you</div></a>
  <a class="fw-kpi muted" href="#bg-ignored" data-go="bg-ignored"><div class="l">Ignored / not legit</div><div class="v"><?= (int)$bgIgnN ?></div><div class="s">kept out of the queue</div></a>
  <a class="fw-kpi <?= $bgStale ?>" href="#bg-scan" data-go="bg-scan"><div class="l">Last scan</div><div class="v"><?= $lastScan ? smpro_h($ago($lastScan)) : 'never' ?></div><div class="s"><?= smpro_h($bgScanS) ?></div></a>
</div>
<nav class="fw-nav" id="bgNav"><a href="#bg-scan" data-go="bg-scan">&#128269; Scan</a><a href="#bg-hist" data-go="bg-hist">&#128197; Last 7 days</a><a href="#bg-pending" data-go="bg-pending">&#9203; Pending</a><a href="#bg-gray" data-go="bg-gray">&#9888; Gray</a><a href="#bg-blocked" data-go="bg-blocked">&#10006; Blocked</a><a href="#bg-allowed" data-go="bg-allowed">&#10003; Allowed</a><a href="#bg-ignored" data-go="bg-ignored">Ignored</a><a href="#bg-settings" data-go="bg-settings">&#9881; Settings</a><a href="#bg-cat" data-go="bg-cat">Families</a><span class="sp"></span><button type="button" class="fw-navx" id="bgOpenAll">expand all</button><button type="button" class="fw-navx" id="bgCloseAll">collapse all</button></nav>
<?php endif; ?>

<div class="card bg-c" id="bg-scan"><div class="bg-hd"><b>&#128269; Scan &amp; export</b><span class="meta">reads the newest logs now; the worker does the same on its schedule</span></div><div class="pad">
  <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">
    <button class="bg-act pri" type="button" id="bgScan">&#128269; Scan now</button>
    <a class="bg-act" href="index.cgi?page=bot-guard&amp;export=csv">&#11015; Export CSV</a>
    <a class="bg-act" href="index.cgi?page=bot-guard&amp;export=html" target="_blank">&#128424; Print / PDF</a>
    <span class="meta">Reads the newest <?= (int)$cfg['max_logs'] ?> domlogs (last <?= (int)$cfg['tail_lines'] ?> lines each, streamed) plus the WAF index for the last <?= (int)$cfg['window_hours'] ?>h. Worker: <?= $cfg['enabled'] ? 'every ' . (int)$cfg['scan_minutes'] . ' min' : '<b>off</b>' ?>.</span>
  </div>
  <div class="bg-msg" id="bgScanMsg"></div>
</div></div>

<div class="card bg-c" id="bg-hist"><div class="bg-hd"><b>&#128197; Last 7 days</b><span class="meta">what the worker saw and did, per day</span></div><div class="pad">
  <div class="bg-kpis" style="margin:0 0 12px">
    <div class="bg-kpi warn"><div class="n"><?= (int)$sum7['new_pending'] ?></div><div class="l">new bots queued for you</div></div>
    <div class="bg-kpi bad"><div class="n"><?= (int)$sum7['autoblocked'] ?></div><div class="l">auto-blocked (threshold)</div></div>
    <div class="bg-kpi"><div class="n"><?= (int)$sum7['manual_blocked'] ?></div><div class="l">blocked by you</div></div>
    <div class="bg-kpi"><div class="n"><?= (int)($days7[date('Y-m-d')]['tracked'] ?? 0) ?></div><div class="l">automated clients tracked today</div></div>
  </div>
  <div class="bg-hist">
    <div>
      <div class="bg-note">tracked automated clients per day (blue) · auto-blocks (red)<?php if (!array_sum(array_map(fn($r) => (int)$r['tracked'], $days7))): ?><span class="bg-stale">&#9888; nothing recorded in 7 days — <?= $cfg['enabled'] ? 'the worker has not reported' : 'the worker is OFF (Settings)' ?></span><?php endif; ?></div>
      <div class="bg-bars">
        <?php foreach ($days7 as $d => $r): $h = (int)round(60 * (int)$r['tracked'] / $maxTracked); $hb = (int)min(60, 4 * (int)$r['autoblocked']); ?>
        <div class="bg-bar" title="<?= smpro_h($d) ?>: <?= (int)$r['tracked'] ?> tracked, <?= (int)$r['autoblocked'] ?> auto-blocked, <?= (int)$r['new_pending'] ?> new"><i style="height:<?= $h ?>px"></i><?php if ($hb): ?><i class="r" style="height:<?= $hb ?>px"></i><?php endif; ?><span><?= smpro_h(date('D', strtotime($d))) ?></span></div>
        <?php endforeach; ?>
      </div>
    </div>
    <div>
      <div class="bg-note">top attackers this week (attack-signature requests)</div>
      <div class="bg-toplist"><?php if ($sum7['top']) foreach ($sum7['top'] as $ip => $n): ?><div><span class="bg-ip"><?= smpro_h($ip) ?></span> · <?= (int)$n ?> · <?= smpro_h($ccName((string)($bots[$ip]['country'] ?? ''))) ?> <?= isset($bots[$ip]) ? '<span class="bg-pill bg-v-' . smpro_h($bots[$ip]['assess']['verdict']) . '">' . smpro_h($bots[$ip]['assess']['label']) . '</span>' : '' ?></div><?php endforeach; else echo '<div class="bg-empty">none yet</div>'; ?></div>
    </div>
  </div>
</div></div>

<?php if (!$print): $ssSt = smpro_ss_status(); $ssAll = smpro_ss_domains(); $ssNk = function_exists('smpro_nk_status') ? smpro_nk_status() : ['ready' => false, 'kinds' => []]; ?>
<div class="card" id="siteshield" style="margin:10px 0 12px">
  <div class="fa-head"><b>&#128737; Site Shield</b> <span class="meta">- one domain closed to hosting / cloud / VPN networks, scanner tools and secret-file probes; people on home and mobile networks pass, your own addresses always pass</span></div>
  <div style="padding:12px 16px">
    <div class="meta" style="margin-bottom:8px">Lists on this server: <?= $ssNk['ready'] ? (int)($ssNk['kinds']['vpn']['lines'] ?? 0) . ' VPN + ' . (int)($ssNk['kinds']['hosting']['lines'] ?? 0) . ' hosting prefixes (refreshed daily; the shield follows them)' : 'not fetched yet - the Country Login Lock worker brings them; until then a shield cannot be installed' ?>. Applied as a cPanel per-vhost include (kept across rebuilds), tested with configtest before the graceful reload, removed again if the test refuses.</div>
    <?php if ($ssSt): ?><table class="smpro-table" style="margin:0 0 10px"><thead><tr><th>Domain</th><th>Account</th><th>Since</th><th>Prefixes</th><th>Status</th><th></th></tr></thead><tbody>
      <?php foreach ($ssSt as $d => $r): ?><tr><td class="mono"><?= smpro_h($d) ?></td><td><?= smpro_h($r['user']) ?></td><td><?= smpro_h(date('Y-m-d H:i', $r['since'])) ?></td><td><?= (int)$r['prefixes'] ?></td><td><span class="b <?= $r['live'] ? 'green' : 'red' ?>"><?= $r['live'] ? 'live in httpd.conf' : 'NOT in httpd.conf - press Remove, then Shield again' ?></span></td><td><button class="fa-lnk ssOff" type="button" data-d="<?= smpro_h($d) ?>">Remove</button></td></tr><?php endforeach; ?>
    </tbody></table><?php endif; ?>
    <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
      <select id="ssDomain" class="tp-in" style="min-width:260px"><option value="">choose a domain…</option><?php foreach ($ssAll as $d => $i): if (isset($ssSt[$d])) continue; ?><option value="<?= smpro_h($d) ?>"><?= smpro_h($d) ?> (<?= smpro_h($i['user']) ?>, <?= smpro_h($i['type']) ?>)</option><?php endforeach; ?></select>
      <button class="tp-btn primary" id="ssOn" type="button"<?= $ssNk['ready'] ? '' : ' disabled' ?>>&#128737; Shield this domain</button>
      <span class="meta" id="ssMsg"></span>
    </div>
  </div>
</div>
<details class="gl-fold" style="margin:4px 0 10px"><summary><span class="gl-chev">&#9656;</span> What the verdicts mean, and what to do</summary>
<table class="bg-tbl" style="margin-top:6px"><thead><tr><th>Verdict</th><th>Meaning</th><th>Proof used</th><th>What to do</th></tr></thead><tbody>
<tr><td><span class="bg-pill bg-v-trusted">Verified crawler</span></td><td>Really is the search engine / social network / tool it claims to be.</td><td>Forward-confirmed reverse DNS, or the publisher's published IP ranges.</td><td>Allow. Blocking it costs you search traffic or link previews.</td></tr>
<tr><td><span class="bg-pill bg-v-impersonator">Impersonating a crawler</span></td><td>The User-Agent says Googlebot / Facebook / GPTBot, but the address fails that publisher's own check. A fake identity used to slip past robots.txt and rate limits.</td><td>Reverse DNS not under the publisher's domain, or address outside its ranges.</td><td>Block. The real crawler is unaffected: it comes from verified addresses.</td></tr>
<tr><td><span class="bg-pill bg-v-attacker">Attacker</span></td><td>Sent attack-signature requests past the threshold (WAF hits, probes for shells, logins, config files).</td><td>The web and WAF logs.</td><td>Block (done automatically when auto-block is on).</td></tr>
<tr><td><span class="bg-pill bg-v-suspicious">Suspicious</span></td><td>Some bad requests, still under the threshold.</td><td>The web and WAF logs.</td><td>Watch; block if it continues. It sits in the gray list.</td></tr>
<tr><td><span class="bg-pill bg-v-scraper">Scraper</span></td><td>A known AI / SEO crawler that offers no way to verify it, or a very heavy tool with no bad requests.</td><td>User-Agent and request rate.</td><td>Your policy: allow (it may bring mentions), or block (it brings no visitors).</td></tr>
<tr><td><span class="bg-pill bg-v-harmless">Harmless</span></td><td>A script or tool with a handful of requests and nothing bad: a checker, a feed reader, a one-off fetch.</td><td>Request count.</td><td>Ignore.</td></tr>
<tr><td><span class="bg-pill bg-v-unknown">Unknown</span></td><td>An automated client with no identity and no bad requests, or a claimed crawler not checked yet.</td><td>Nothing yet.</td><td>Open the group, look at the domains and URLs, then decide. "Verify all" re-checks claimed crawlers.</td></tr>
</tbody></table>
<div class="meta" style="margin-top:6px">A group row is one identity (a crawler family, or a verdict + network). The name on the row is what the client <i>claims</i>; the verdict is what the check found.</div>
</details>
<div class="bg-filter">
  <input type="text" id="bgQ" placeholder="filter: address, name, country, provider, verdict, domain…" style="min-width:320px">
  <select id="bgV"><option value="">every verdict</option><?php foreach (['impersonator' => 'Impersonating a crawler', 'attacker' => 'Attacker', 'suspicious' => 'Suspicious', 'scraper' => 'Scraper', 'unknown' => 'Unknown', 'harmless' => 'Harmless', 'trusted' => 'Verified crawler'] as $k => $v): ?><option value="<?= $k ?>"><?= $v ?></option><?php endforeach; ?></select>
  <select id="bgK"><option value="">every kind</option><?php foreach (['search' => 'Search engine', 'social' => 'Social preview', 'seo' => 'SEO tool', 'monitor' => 'Uptime monitor', 'ai' => 'AI crawler', 'archive' => 'Archive', '-' => 'unknown bot'] as $k => $v): ?><option value="<?= $k ?>"><?= $v ?></option><?php endforeach; ?></select>
  <select id="bgG" title="how the lists are shown"><option value="1">grouped by identity</option><option value="0">every address</option></select>
  <span class="cnt" id="bgCnt"></span>
</div>
<div class="meta" style="font-size:11.5px;margin:0 0 6px">Row actions: <b>Verify now</b> resolves reverse DNS / published ranges right now · <b>Not legitimate</b> gray-lists the bot on its first bad request · <b>Reset</b> forgets the decision so the next scan judges it afresh · <b>Allow in firewall too</b> also writes the IP to csf.allow.</div>
<div class="bg-bulk" id="bgBulk"><b><span id="bgSel">0</span> selected</b>
  <button type="button" class="bg-act ok" data-bulk="allow">&#10003; Allow</button><button type="button" class="bg-act bad" data-bulk="block">&#10006; Block</button><button type="button" class="bg-act" data-bulk="ignore">Ignore</button><button type="button" class="bg-act" data-bulk="deny">Not legitimate</button><button type="button" class="bg-act" data-bulk="verify">Verify now</button><button type="button" class="bg-act" data-bulk="unblock">Unblock</button><button type="button" class="bg-act" data-bulk="reset">Reset</button>
  <button type="button" class="bg-act" id="bgClear" style="margin-left:auto">clear</button></div>
<?php endif; ?>


<div class="card bg-c" id="bg-pending"><div class="bg-hd"><b>&#9203; Awaiting your decision</b><span class="bg-n"><?= count($groups['pending']) ?></span><span class="meta">automated clients that could not be verified as an official crawler and have sent no bad request — allow, block, or ignore</span></div><div><?php $renderRows($groups['pending'], 'pending'); ?></div></div>

<div class="card bg-c" id="bg-gray"><div class="bg-hd"><b>&#9888; Gray list</b><span class="bg-n"><?= count($groups['gray']) ?></span><span class="meta">sent attack-signature requests in the last <?= (int)$cfg['window_hours'] ?>h · auto-block at <?= (int)$cfg['gray_threshold'] ?><?= $cfg['auto_block'] ? '' : ' (auto-block is OFF)' ?></span></div><div><?php $renderRows($groups['gray'], 'gray'); ?></div></div>

<div class="card bg-c" id="bg-blocked"><div class="bg-hd"><b>&#10006; Blocked</b><span class="bg-n"><?= count($groups['blocked']) ?></span><span class="meta">blocked by Bot Guard (automatic or by you) — CSF and, when configured, Cloudflare</span></div><div><?php $renderRows($groups['blocked'], 'blocked'); ?></div></div>

<div class="card bg-c" id="bg-allowed"><div class="bg-hd"><b>&#10003; Allowed</b><span class="bg-n"><?= count($groups['allowed']) ?></span><span class="meta">verified official crawlers, and anything you allowed — exempt from Bot Guard actions and from the plugin's automatic blocks</span></div><div><?php $renderRows($groups['allowed'], 'allowed'); ?></div></div>

<div class="card bg-c" id="bg-ignored"><div class="bg-hd"><b>Ignored / not legitimate</b><span class="bg-n"><?= (int)$bgIgnN ?></span><span class="meta">decisions that keep an address out of the pending queue</span></div><div><?php $renderRows($groups['ignored'] + $groups['denied'], 'ignored'); ?></div></div>

<?php if ($print): smpro_layout_footer(); return; endif; ?>

<div class="card bg-c" id="bg-settings"><div class="bg-hd"><b>&#9881; Settings</b></div><div class="pad">
  <form id="bgForm" onsubmit="return false">
  <div class="bg-form">
    <label class="cb"><input type="checkbox" name="enabled" <?= $cfg['enabled'] ? 'checked' : '' ?>> <b>Bot Guard on</b> (schedules the worker)</label>
    <label class="cb"><input type="checkbox" name="auto_block" <?= $cfg['auto_block'] ? 'checked' : '' ?>> Auto-block gray list past the threshold</label>
    <label class="cb"><input type="checkbox" name="allow_verified" <?= $cfg['allow_verified'] ? 'checked' : '' ?>> Allow verified official crawlers automatically</label>
    <label class="cb"><input type="checkbox" name="firewall_allow_verified" <?= $cfg['firewall_allow_verified'] ? 'checked' : '' ?>> Also add verified crawler IPs to csf.allow <span class="bg-note">(off by default — the Firewall allow-list feature covers Googlebot/Bingbot by published ranges, which is cleaner than per-IP lines)</span></label>
    <label>Gray-list threshold (attack-signature requests per window)<input type="number" name="gray_threshold" min="3" max="5000" value="<?= (int)$cfg['gray_threshold'] ?>"></label>
    <label>Window (hours)<input type="number" name="window_hours" min="1" max="168" value="<?= (int)$cfg['window_hours'] ?>"></label>
    <label>Scan every (minutes)<input type="number" name="scan_minutes" min="5" max="240" value="<?= (int)$cfg['scan_minutes'] ?>"></label>
    <label>Lines per domlog (newest)<input type="number" name="tail_lines" min="1000" max="200000" step="1000" value="<?= (int)$cfg['tail_lines'] ?>"></label>
    <label>Domlogs per scan (newest-modified)<input type="number" name="max_logs" min="5" max="2000" value="<?= (int)$cfg['max_logs'] ?>"></label>
    <label>Never track these IPs/CIDRs<input type="text" name="ignore_ips" placeholder="one per line or comma-separated" value="<?= smpro_h(implode(', ', $cfg['ignore_ips'])) ?>"></label>
    <?php
    // What the server actually accepted, not what was typed: a line with a suffix like "com" is dropped, and the
    // box has to show that it was, or the operator walks away believing a rule is in force that is not.
    $bgCustom = function_exists('smpro_bg_catalog_custom') ? smpro_bg_catalog_custom($cfg) : [];
    $bgLines = [];
    foreach ((array)($cfg['custom_bots'] ?? []) as $r) {
        if (!is_array($r)) continue;
        $bgLines[] = implode(' | ', [(string)($r['key'] ?? ''), (string)($r['name'] ?? ''), (string)($r['kind'] ?? 'search'),
                                     (string)($r['ua'] ?? ''), implode(',', (array)($r['rdns'] ?? []))]);
    }
    $bgSent = count($bgLines); $bgOk = count($bgCustom);
    ?>
    <label style="grid-column:1/-1">Crawlers of your own
      <span class="meta" style="display:block;font-weight:400;margin:2px 0 4px">
        One per line: <code>key | Display name | kind | UA fragment | rdns-suffix[,suffix]</code> &mdash; kind is one of
        search, social, seo, monitor, ai, archive. Example:
        <code>examplebot | ExampleBot | search | ExampleBot | crawl.example.com</code>.
        These are <b>added to</b> the built-in list, never replacing it, and they are verified exactly the same way:
        a suffix buys a name, never an exemption &mdash; the address still has to resolve to a host under that suffix
        <i>and</i> resolve back again. A bare public suffix (<code>com</code>, <code>co.uk</code>) is refused, because
        it would shield every host on earth ending that way.
        <?php if ($bgSent): ?>
          <b style="color:<?= $bgOk === $bgSent ? '#059669' : '#b45309' ?>"><?= (int)$bgOk ?> of <?= (int)$bgSent ?> line(s) in force<?= $bgOk === $bgSent ? '' : ' — the rest were dropped as unusable' ?>.</b>
        <?php endif; ?>
      </span>
      <textarea name="custom_bots" rows="4" placeholder="examplebot | ExampleBot | search | ExampleBot | crawl.example.com" style="width:100%;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px"><?= smpro_h(implode("\n", $bgLines)) ?></textarea>
    </label>
  </div>
  <div style="margin-top:12px"><button class="bg-act pri" type="button" id="bgSave">Save settings</button><span class="bg-msg" id="bgSaveMsg" style="margin-left:10px"></span></div>
  </form>
</div></div>

<?php $tf = function_exists('smpro_tf_status') ? smpro_tf_status() : ['have' => false, 'why' => 'not available in this build', 'sources' => [], 'ranges' => 0, 'families' => 0, 'generated' => 0, 'fetched' => 0]; ?>
<div class="card bg-c" id="bg-trusted"><div class="bg-hd"><b>&#10004; Trusted bots list</b><span class="bg-n"><?= $tf['have'] ? count($tf['sources']) : 0 ?></span><span class="meta">the official crawler and mail-server ranges, fetched and checked on the licence server from each publisher's own feed, signed, and pulled here every six hours - one verified list for every installation</span></div><div class="pad">
  <?php if ($tf['have']): ?>
  <div class="meta" style="margin-bottom:8px">List built <b><?= smpro_h(date('Y-m-d H:i', $tf['generated'])) ?></b> on the licence server &middot; pulled here <b><?= $tf['fetched'] ? smpro_h(date('Y-m-d H:i', $tf['fetched'])) : '-' ?></b> &middot; <b><?= (int)$tf['ranges'] ?></b> ranges in <b><?= count($tf['sources']) ?></b> sources &middot; signature verified against the pinned licence key &middot; <?= (int)$tf['families'] ?> crawler famil<?= $tf['families'] === 1 ? 'y' : 'ies' ?> added to the catalogue below</div>
  <div class="smpro-tablewrap"><table class="bg-tbl" data-nopage="1"><thead><tr><th>Source</th><th>Kind</th><th>Ranges</th><th>Publisher's copy fetched</th><th>Standing</th></tr></thead><tbody>
  <?php foreach ($tf['sources'] as $k => $s): ?><tr><td><b><?= smpro_h($s['name']) ?></b><div class="bg-note"><?= smpro_h($k) ?></div></td><td><?= smpro_h($s['kind']) ?></td><td><?= (int)$s['count'] ?></td><td><?= $s['fetched_at'] ? smpro_h(date('Y-m-d H:i', $s['fetched_at'])) : '-' ?></td><td><?= $s['stale'] !== '' ? '<span class="bg-pill bg-v-suspicious">last good copy kept</span> <span class="bg-note" style="display:inline">' . smpro_h($s['stale']) . '</span>' : '<span class="bg-pill bg-v-trusted">fresh</span>' ?><?= $s['never_block'] ? ' <span class="bg-pill v">never blocked</span>' : '' ?></td></tr><?php endforeach; ?>
  </tbody></table></div>
  <?php else: ?>
  <div class="bg-warn">&#9888; No verified list is held yet (<?= smpro_h($tf['why']) ?>). The allow-list providers use their shipped seeds and the publishers' own feeds until the first pull succeeds.</div>
  <?php endif; ?>
  <div style="margin-top:8px;display:flex;gap:8px;align-items:center"><button type="button" class="bg-act" id="bgTfRefresh">&#8635; Pull the list now</button><span class="meta" id="bgTfMsg">next automatic pull within six hours</span></div>
</div></div>
<div class="card bg-c" id="bg-cat"><div class="bg-hd"><b>Recognised crawler families</b><span class="meta">how each one is verified — a User-Agent string alone proves nothing, anyone can send "Googlebot"</span></div><div class="pad">
<?php foreach ($catalog as $k => $f): ?>
  <div><b><?= smpro_h($f['name']) ?></b> <span class="bg-pill k"><?= smpro_h(smpro_bg_kind_label($f['kind'])) ?></span> — <?= $f['rdns'] ? 'rDNS under ' . smpro_h(implode(', ', $f['rdns'])) : ($f['ranges'] !== '' ? 'published IP ranges' : '<i>no publisher verification → always pending</i>') ?><?= $f['rdns'] && $f['ranges'] !== '' ? ' or published IP ranges' : '' ?></div>
<?php endforeach; ?>
</div></div></div>

<script>(function(){
  /* collapsible section cards + sticky navigator (pattern: modules/firewall-status.php). The header of every
     card is a real toggle (role=button, keyboard), the open/closed choice is remembered per section. */
  var KEY='smpro:bot-guard:open', HSEL='.card > .bg-hd', PFX='bg', open={};
  try{ open=JSON.parse(localStorage.getItem(KEY)||'{}')||{}; }catch(err){ open={}; }
  function remember(){ try{ localStorage.setItem(KEY, JSON.stringify(open)); }catch(err){} }
  function toggleOf(card){ for(var i=0;i<card.children.length;i++){ if(card.children[i].classList.contains('fw-toggle')) return card.children[i]; } return null; }
  function setOpen(card,on){ var th=toggleOf(card); if(!th) return; card.classList.toggle('fw-open',on); th.setAttribute('aria-expanded',on?'true':'false'); open[th.getAttribute('data-fold')]=on; }
  function openCard(id,scroll){ var card=document.getElementById(id); if(!card) return;
    if(toggleOf(card)&&!card.classList.contains('fw-open')){ setOpen(card,true); remember(); }
    if(scroll){ card.style.scrollMarginTop='120px'; card.scrollIntoView({behavior:'smooth',block:'start'}); } }
  function init(){
    if(!document.getElementById(PFX+'Nav')) return;   /* only on a page that carries this navigator */
    var heads=document.querySelectorAll(HSEL), i;
    for(i=0;i<heads.length;i++){ (function(th,idx){
      var card=th.parentElement; if(!card||th.classList.contains('fw-toggle')) return;
      var body=document.createElement('div'); body.className='fw-collapse';
      while(th.nextSibling){ body.appendChild(th.nextSibling); }
      card.appendChild(body);
      th.classList.add('fw-toggle');
      if(!th.querySelector('.fw-chev')) th.insertAdjacentHTML('afterbegin','<span class="fw-chev">&#9656;</span> ');
      var lab=th.querySelector('b');
      var id=((lab?lab.textContent:th.textContent)||'').replace(/\s+/g,' ').replace(/^\s+|\s+$/g,'').slice(0,60) || ('card'+idx);
      th.setAttribute('data-fold',id);
      var isOpen=Object.prototype.hasOwnProperty.call(open,id)?!!open[id]:true;
      card.classList.toggle('fw-open',isOpen);
      th.setAttribute('role','button'); th.setAttribute('tabindex','0'); th.style.cursor='pointer'; th.setAttribute('aria-expanded',isOpen?'true':'false');
      function toggle(){ setOpen(card,!card.classList.contains('fw-open')); remember(); }
      th.addEventListener('click',function(e){ if(e.target.closest('a,button,input,select,label,textarea,details,summary')) return; toggle(); });
      th.addEventListener('keydown',function(e){ if(e.target!==th) return; if(e.key===' '||e.key==='Enter'||e.key==='Spacebar'){ e.preventDefault(); toggle(); } });
    })(heads[i],i); }
    var gos=document.querySelectorAll('.fw-nav [data-go], .fw-kpis [data-go]');
    for(i=0;i<gos.length;i++){ (function(a){ a.addEventListener('click',function(e){ e.preventDefault(); var id=a.getAttribute('data-go'); openCard(id,true);
      var ch=document.querySelectorAll('.fw-nav a'); for(var j=0;j<ch.length;j++) ch[j].classList.toggle('on', ch[j].getAttribute('data-go')===id);
      try{ history.replaceState(null,'','#'+id); }catch(err){} }); })(gos[i]); }
    function all(on){ var cs=document.querySelectorAll('.smpro-main .card'); for(var j=0;j<cs.length;j++){ if(toggleOf(cs[j])) setOpen(cs[j],on); } remember(); }
    var oa=document.getElementById(PFX+'OpenAll'), ca=document.getElementById(PFX+'CloseAll');
    if(oa) oa.addEventListener('click',function(){ all(true); });
    if(ca) ca.addEventListener('click',function(){ all(false); });
    if(location.hash && document.getElementById(location.hash.slice(1))) setTimeout(function(){ openCard(location.hash.slice(1), true); },150);
    /* row actions must not land on a collapsed card after reload: nothing to do, cards default open */
  }
  window[PFX+'OpenCard']=openCard;
  if(document.readyState==='loading') document.addEventListener('DOMContentLoaded',init); else init();
})();
</script>
<script>(function(){
  var ssOn=document.getElementById('ssOn'); if(ssOn) ssOn.onclick=function(){var d=document.getElementById('ssDomain').value; if(!d) return; var m=document.getElementById('ssMsg'); m.textContent='Installing (rebuild + configtest + graceful reload)…'; ssOn.disabled=true; var fd=new URLSearchParams(); fd.set('act','shield_on'); fd.set('domain',d); post(fd,function(r){m.textContent=r.msg||''; if(r.ok) setTimeout(function(){location.reload();},1200); else ssOn.disabled=false;});};
  document.querySelectorAll('.ssOff').forEach(function(b){b.onclick=function(){if(!confirm('Remove the shield from '+b.dataset.d+'?')) return; var fd=new URLSearchParams(); fd.set('act','shield_off'); fd.set('domain',b.dataset.d); post(fd,function(r){document.getElementById('ssMsg').textContent=r.msg||''; if(r.ok) setTimeout(function(){location.reload();},1000);});};});
  function post(fd,cb){fd.set('smpro_csrf',BG_CSRF);fetch('index.cgi?page=bot-guard',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'}).then(function(r){return r.json();}).then(cb).catch(function(){cb({ok:false,msg:'Request failed'});});}
  var sb=document.getElementById('bgScan');sb.addEventListener('click',function(){var o=sb.innerHTML;sb.disabled=true;sb.innerHTML='Scanning… (streams the logs; up to a few minutes on a busy server)';var m=document.getElementById('bgScanMsg');m.textContent='';var fd=new URLSearchParams();fd.set('bg_action','scan');
    post(fd,function(j){sb.disabled=false;sb.innerHTML=o;m.style.color=j&&j.ok?'#16a34a':'#dc2626';m.textContent=(j&&j.ok?'✅ ':'⚠ ')+((j&&j.msg)||'Failed');if(j&&j.ok)setTimeout(function(){location.reload();},1200);});});
  // per-row actions
  document.addEventListener('click',function(ev){var b=ev.target.closest('.bg-tbl button[data-act]');if(!b)return;var tr=b.closest('tr'),ip=tr.getAttribute('data-ip'),act=b.getAttribute('data-act');
    if(act==='block'&&!confirm('Block '+ip+' in the firewall now?'))return; if(act==='reset'&&!confirm('Forget the decision for '+ip+'?'))return;
    var o=b.innerHTML;b.disabled=true;b.innerHTML='…';var fd=new URLSearchParams();fd.set('bg_action',act);fd.set('ip',ip);if(b.getAttribute('data-fw'))fd.set('firewall','1');
    post(fd,function(j){if(j&&j.ok){if(act==='verify'){b.innerHTML=o;b.disabled=false;alert(j.msg||'');setTimeout(function(){location.reload();},400);return;}tr.style.opacity='.45';b.innerHTML='✓';setTimeout(function(){location.reload();},700);}else{b.disabled=false;b.innerHTML=o;alert('⚠ '+((j&&j.msg)||'Failed'));}});});
  // row details on demand (one request per row, on first open)
  function esc(s){return String(s).replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
  document.addEventListener('toggle',function(e){var d=e.target;if(!d.classList||!d.classList.contains('bg-lazy')||!d.open||d.getAttribute('data-loaded'))return;d.setAttribute('data-loaded','1');
    var tr=d.closest('tr'),box=d.querySelector('.bg-lazybody'),fd=new URLSearchParams();fd.set('bg_action','detail');fd.set('ip',tr.getAttribute('data-ip'));
    post(fd,function(j){if(!j||!j.ok){box.textContent=(j&&j.msg)||'Could not load.';return;}var h='';
      if(j.cost)h+='<div class="bg-cost"><b>If blocked:</b> '+esc(j.cost)+'. <b>Advice:</b> '+esc(j.advice)+'.</div>';
      h+='<div class="bg-ua">'+esc(j.ua||'(no User-Agent)')+'</div>';
      if(j.urls&&j.urls.length)h+='<div class="bg-note" style="margin-top:4px">last requests</div><div class="bg-urls">'+esc(j.urls.join('\n'))+'</div>';else if(j.sample)h+='<div class="bg-urls">'+esc(j.sample)+'</div>';
      box.className='bg-lazybody';box.innerHTML=h;});},true);
  // filter + paging: both on the server. Each list shows 50 rows; prev/next or a filter change asks for one page.
  var q=document.getElementById('bgQ'),v=document.getElementById('bgV'),k=document.getElementById('bgK'),cnt=document.getElementById('bgCnt'),bgState={};
  var g=document.getElementById('bgG');try{var gv=localStorage.getItem('smpro:bg:view');if(gv==='0'||gv==='1')g.value=gv;}catch(err){}
  function updCnt(){var s=0,tt=0,aa=0,m;for(m in bgState){s+=bgState[m].count;tt+=bgState[m].total;aa+=bgState[m].addresses||0;}cnt.textContent=(g.value==='1')?(s+' of '+tt+' groups shown · '+aa+' addresses'):(s+' of '+tt+' addresses shown');}
  function paint(mode,j){var bar=document.querySelector('.bg-pg[data-mode="'+mode+'"]');if(!bar)return;var pages=Math.max(1,Math.ceil(j.total/50)),p=Math.floor(j.offset/50);
    bar.querySelector('.fw-pginfo').textContent=j.total?('Showing '+(j.offset+1)+'\u2013'+(j.offset+j.count)+' of '+j.total):'No rows match';bar.querySelector('.fw-pgnum').textContent=(p+1)+' / '+pages;
    var bt=bar.querySelectorAll('.fw-pgbtn');bt[0].disabled=p<=0;bt[1].disabled=p>=pages-1;bar.style.display=(j.total>50||q.value||v.value||k.value)?'':'none';}
  function loadList(mode,off){var tbl=document.getElementById('bgTbl-'+mode);if(!tbl)return;var fd=new URLSearchParams();fd.set('bg_action','rows');fd.set('mode',mode);fd.set('offset',off);fd.set('q',q.value||'');fd.set('v',v.value);fd.set('k',k.value);fd.set('g',g.value);
    post(fd,function(j){if(!j||!j.ok)return;tbl.tBodies[0].innerHTML=j.html;bgState[mode]={off:j.offset,total:j.total,count:j.count,addresses:j.addresses||0};paint(mode,j);refreshBulk();updCnt();});}
  // a group row expands to its addresses (fetched once); group buttons act on every address in the group
  document.addEventListener('click',function(ev){var x=ev.target.closest('.bg-gx');if(!x)return;var tr=x.closest('tr.bg-grp'),tbl=tr.closest('table'),key=tr.getAttribute('data-g');
    if(tr.getAttribute('data-loaded')){var open=!tr.classList.contains('open');tr.classList.toggle('open',open);var n=tr.nextElementSibling;while(n&&n.classList.contains('bg-sub')){n.style.display=open?'':'none';n=n.nextElementSibling;}return;}
    tr.setAttribute('data-loaded','1');tr.classList.add('open');var fd=new URLSearchParams();fd.set('bg_action','rows');fd.set('mode',tbl.getAttribute('data-mode'));fd.set('grp',key);fd.set('q',q.value||'');fd.set('v',v.value);fd.set('k',k.value);
    post(fd,function(j){if(!j||!j.ok)return;var tmp=document.createElement('tbody');tmp.innerHTML=j.html;var ref=tr,r;while((r=tmp.firstElementChild)){r.classList.add('bg-sub');ref.parentNode.insertBefore(r,ref.nextSibling);ref=r;}});});
  document.addEventListener('click',function(ev){var b=ev.target.closest('.bg-grp button[data-gact]');if(!b)return;var tr=b.closest('tr'),ips=(tr.getAttribute('data-ips')||'').split(',').filter(Boolean),act=b.getAttribute('data-gact');if(!ips.length)return;
    if((act==='block'||act==='reset')&&!confirm(act.charAt(0).toUpperCase()+act.slice(1)+' all '+ips.length+' address(es) in this group?'))return;
    var o=b.innerHTML;b.disabled=true;b.innerHTML='…';var fd=new URLSearchParams();fd.set('bg_action','bulk');fd.set('act',act);fd.set('ips',ips.join(','));
    post(fd,function(j){b.disabled=false;b.innerHTML=o;alert((j&&j.msg)||'Failed');if(j&&j.ok)location.reload();});});
  document.querySelectorAll('.bg-tbl').forEach(function(tb){var m=tb.getAttribute('data-mode');bgState[m]={off:0,total:parseInt(tb.getAttribute('data-total'),10)||0,count:tb.tBodies[0]?tb.tBodies[0].rows.length:0,addresses:parseInt(tb.getAttribute('data-addresses'),10)||0};});updCnt();
  if(g.value!=='1')reloadAll();   // the page renders grouped; a remembered flat view is fetched
  g.addEventListener('change',function(){try{localStorage.setItem('smpro:bg:view',g.value);}catch(err){}reloadAll();});
  document.querySelectorAll('.bg-pg').forEach(function(bar){bar.addEventListener('click',function(e){var b=e.target.closest('.fw-pgbtn');if(!b||b.disabled)return;var m=bar.getAttribute('data-mode'),st=bgState[m]||{off:0};loadList(m,Math.max(0,st.off+50*parseInt(b.getAttribute('data-d'),10)));});});
  var bgTmr=null;function reloadAll(){clearTimeout(bgTmr);bgTmr=setTimeout(function(){['pending','gray','blocked','allowed','ignored'].forEach(function(m){loadList(m,0);});},250);}
  q.addEventListener('input',reloadAll);v.addEventListener('change',reloadAll);k.addEventListener('change',reloadAll);
  // bulk
  var bulk=document.getElementById('bgBulk'),sel=document.getElementById('bgSel');
  function selected(){var out={},i;Array.prototype.slice.call(document.querySelectorAll('.bgSel:checked, .bgGrpSel:checked')).forEach(function(c){c.value.split(',').forEach(function(ip){if(ip)out[ip]=1;});});var a=[];for(i in out)a.push(i);return a;}
  function refreshBulk(){var n=selected().length;sel.textContent=n;bulk.classList.toggle('on',n>0);}
  document.addEventListener('change',function(e){if(e.target.classList.contains('bgSel')||e.target.classList.contains('bgGrpSel'))refreshBulk();if(e.target.classList.contains('bgAll')){var on=e.target.checked;e.target.closest('table').querySelectorAll('tbody .bgSel, tbody .bgGrpSel').forEach(function(c){c.checked=on;});refreshBulk();}});
  document.getElementById('bgClear').addEventListener('click',function(){document.querySelectorAll('.bgSel,.bgGrpSel,.bgAll').forEach(function(c){c.checked=false;});refreshBulk();});
  bulk.querySelectorAll('button[data-bulk]').forEach(function(b){b.addEventListener('click',function(){var ips=selected();if(!ips.length)return;var act=b.getAttribute('data-bulk');
    if((act==='block'||act==='reset')&&!confirm(act.charAt(0).toUpperCase()+act.slice(1)+' '+ips.length+' address(es)?'))return;
    var o=b.innerHTML;b.disabled=true;b.innerHTML='…';var fd=new URLSearchParams();fd.set('bg_action','bulk');fd.set('act',act);fd.set('ips',ips.join(','));
    post(fd,function(j){b.disabled=false;b.innerHTML=o;alert((j&&j.msg)||'Failed');if(j&&j.ok)location.reload();});});});
  document.getElementById('bgSave').addEventListener('click',function(){var f=document.getElementById('bgForm'),fd=new URLSearchParams();fd.set('bg_action','settings');
    ['enabled','auto_block','allow_verified','firewall_allow_verified'].forEach(function(n){if(f.elements[n].checked)fd.set(n,'1');});
    ['gray_threshold','window_hours','scan_minutes','tail_lines','max_logs','ignore_ips','custom_bots'].forEach(function(n){fd.set(n,f.elements[n].value);});
    var m=document.getElementById('bgSaveMsg');m.textContent='Saving…';post(fd,function(j){m.style.color=j&&j.ok?'#16a34a':'#dc2626';m.textContent=(j&&j.ok?'✅ ':'⚠ ')+((j&&j.msg)||'Failed');if(j&&j.ok)setTimeout(function(){location.reload();},1200);});});
})();</script>
<?php
smpro_layout_footer();
