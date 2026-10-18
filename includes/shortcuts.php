<?php
/**
 * shortcuts.php — Dashboard widgets:
 *   1) smpro_dash_attention()  — cheaply detect the conditions that matter RIGHT NOW (critical load,
 *      full disk/RAM, active emergency blocks, etc.) so the main Dashboard surfaces them up top and
 *      links straight to the page that fixes each. No heavy scans — reads live metrics + cached state.
 *   2) Shortcuts — a quick-launch row on the Dashboard combining the user's PINNED pages and the
 *      auto-tracked MOST-USED pages. Usage is counted per page view; pins are saved by the admin.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

define('SMPRO_SC_USAGE', SMPRO_VARLIB . '/usage.json');
define('SMPRO_SC_PINS',  SMPRO_VARLIB . '/shortcuts.json');

/* ---------------- critical detection ---------------- */
function smpro_dash_attention($m = null) {
    if (!is_array($m)) $m = function_exists('smpro_collect_metrics') ? smpro_collect_metrics() : [];
    $a = [];
    $push = function ($sev, $icon, $title, $detail, $page, $noscore = false) use (&$a) {
        $a[] = ['sev' => $sev, 'icon' => $icon, 'title' => $title, 'detail' => $detail, 'page' => $page, 'noscore' => $noscore];
    };
    $pf = (float)($m['pressure'] ?? 0);
    $health = (string)($m['health'] ?? '');
    if ($health === 'crit' || $pf >= 100)
        $push('critical', '&#128293;', 'Server load critical', $pf . '% load pressure on ' . (int)($m['cores'] ?? 0) . ' cores (1m load ' . ($m['load']['1m'] ?? '?') . ')', 'load-monitor');
    elseif ($health === 'warn' || $pf >= 80)
        $push('warn', '&#9888;&#65039;', 'Server load high', $pf . '% load pressure — watch the top processes', 'load-monitor');

    $ram = (float)($m['ram']['pct'] ?? 0);
    if ($ram >= 95) $push('critical', '&#129518;', 'RAM almost exhausted', $ram . '% used (' . ($m['ram']['used'] ?? '?') . '/' . ($m['ram']['total'] ?? '?') . ')', 'load-monitor');
    elseif ($ram >= 90) $push('warn', '&#129518;', 'RAM usage high', $ram . '% used', 'load-monitor');

    $disk = (float)($m['disk']['pct'] ?? 0);
    if ($disk >= 95) $push('critical', '&#128190;', 'Disk almost full', $disk . '% used on / — free space now', 'disk-storage');
    elseif ($disk >= 90) $push('warn', '&#128190;', 'Disk filling up', $disk . '% used on /', 'disk-storage');

    $swap = (float)($m['swap']['pct'] ?? 0);
    if ($swap >= 60) $push('warn', '&#128260;', 'Heavy swap usage', $swap . '% of swap in use (memory pressure)', 'load-monitor');

    // security — cheap cached intrusion state (no scan)
    if (function_exists('smpro_in_state')) {
        $s = smpro_in_state();
        $emb = count($s['emergency_blocked'] ?? []);
        $ab  = count($s['autoblocked'] ?? []);
        // protective actions — the system DEFENDED the server. Shown as info notices, never as a score penalty.
        if ($emb > 0) $push('info', '&#128737;&#65039;', 'Emergency response blocked attackers', $emb . ' attacker IP(s) auto-blocked under emergency — protection working; click to review', 'intrusion-monitor', true);
        elseif ($ab > 0) $push('info', '&#128737;&#65039;', 'Attackers auto-blocked', $ab . ' attacker IP(s) blocked recently — protection working', 'intrusion-monitor', true);
    }
    // service down — start from the cheap cached watcher state, but LIVE-reconfirm with smart unit
    // discovery so a non-existent unit (e.g. named on a PowerDNS server) is never reported as down.
    if (function_exists('smpro_tg_state') && function_exists('smpro_tg_services') && function_exists('smpro_tg_pick_unit')) {
        $prev = (array)(smpro_tg_state()['svc_state'] ?? []);
        $services = smpro_tg_services();
        $down = [];
        foreach ($prev as $name => $st) {
            if (!in_array($st, ['failed', 'inactive', 'deactivating'], true)) continue;   // only re-check ones flagged down
            if (!isset($services[$name])) continue;                                        // stale name from an old map → ignore
            $unit = smpro_tg_pick_unit($services[$name]);                                   // smart: the ACTIVE candidate (pdns vs named)
            if ($unit === '') continue;                                                     // role not installed at all → not "down"
            if (in_array(smpro_tg_unit_active($unit), ['failed', 'inactive', 'deactivating'], true)) $down[] = $name;
        }
        if ($down) $push('critical', '&#128308;', 'Service down', implode(', ', array_slice($down, 0, 4)) . ' not running', 'cpanel-services');
    }
    return $a;
}

/* ---------------- section summary cards ----------------
 * One card per major section with a cheap at-a-glance summary pulled from inside it. Computed once
 * per page render (not on the 2s poll) — light reads only (cached state, one COUNT, exim -bpc). */
function smpro_dash_sections($m = null) {
    if (!is_array($m)) $m = function_exists('smpro_collect_metrics') ? smpro_collect_metrics() : [];
    $cards = [];
    $add = function ($page, $icon, $label, $stat, $sub, $tone = '') use (&$cards) {
        $cards[] = ['page' => $page, 'icon' => $icon, 'label' => $label, 'stat' => $stat, 'sub' => $sub, 'tone' => $tone];
    };
    // Intrusion Monitor — attacks (24h) + blocked IPs
    $blocked = 0; $att24 = 0;
    if (function_exists('smpro_in_state')) { $s = smpro_in_state(); $blocked = count($s['autoblocked'] ?? []) + count($s['emergency_blocked'] ?? []); }
    if (function_exists('smpro_in_db')) { try { $db = smpro_in_db(); if ($db) { $st = $db->prepare('SELECT COUNT(*) FROM attacks WHERE ts>=?'); $st->execute([time() - 86400]); $att24 = (int)$st->fetchColumn(); } } catch (\Throwable $e) { if (function_exists('smpro_soft_fail')) smpro_soft_fail(basename(__FILE__) . ':' . __LINE__, $e); } }
    $add('intrusion-monitor', '&#128680;', 'Intrusion Monitor', $att24 . ' attacks / 24h', $blocked . ' IP(s) blocked', $att24 > 200 ? 'warn' : 'good');
    // Firewall
    $csf = is_file('/etc/csf/csf.conf') || (function_exists('smpro_has_bin') && smpro_has_bin('csf'));
    $add('firewall-status', '&#9873;', 'Firewall', $csf ? 'CSF present' : 'no firewall', $csf ? $blocked . ' blocked' : 'install CSF', $csf ? 'good' : 'warn');
    // Disk / Storage (from live metrics)
    $dp = (float)($m['disk']['pct'] ?? 0);
    $add('disk-storage', '&#128202;', 'Disk / Storage', $dp . '% used', ($m['disk']['free'] ?? '?') . ' free', $dp >= 90 ? 'crit' : ($dp >= 80 ? 'warn' : 'good'));
    // Top Processes (cheap top CPU)
    $top = trim((string)@shell_exec("timeout 4 ps -eo pcpu,comm --sort=-pcpu --no-headers 2>/dev/null | awk 'NR==2{print $2\" \"$1\"%\"}'"));
    $add('top-processes', '&#9881;', 'Top Processes', (int)($m['procs'] ?? 0) . ' running', $top !== '' ? ('top: ' . smpro_h($top)) : 'by CPU / RAM', '');
    // Spam & mail queue (exim -bpc is cheap)
    if (function_exists('smpro_has_bin') && smpro_has_bin('exim')) {
        $q = (int)trim((string)@shell_exec('timeout 5 exim -bpc 2>/dev/null'));
        $add('spam-phishing', '&#128231;', 'Spam &amp; Phishing', $q . ' in mail queue', 'outbound mail', $q > 1000 ? 'warn' : 'good');
    }
    // Imunify / Forensics
    if (function_exists('smpro_has_bin') && smpro_has_bin('imunify360-agent'))
        $add('forensics-audit', '&#9670;', 'Forensics / Audit', 'Imunify on', 'malware &amp; breach hunt', 'good');
    else
        $add('forensics-audit', '&#9670;', 'Forensics / Audit', 'scan', 'compromise hunt', '');
    // Backups
    $add('backup-monitor', '&#128190;', 'Backup Monitor', function_exists('smpro_has_bin') && smpro_has_bin('jetbackup5api') ? 'JetBackup' : 'backups', 'jobs &amp; retention', '');
    // Reports
    if (function_exists('smpro_rep_list')) { $rl = smpro_rep_list(); $add('auto-reports', '&#128202;', 'Reports', count($rl) . ' saved', 'security + health digests', ''); }
    // Server Tune-up
    $add('server-tuning', '&#128295;', 'Server Tune-up', 'optimize', 'perf &amp; security · AI', '');
    return $cards;
}

/* ---------------- usage tracking ---------------- */
function smpro_sc_track($page) {
    $page = preg_replace('/[^a-z0-9_\-]/', '', strtolower((string)$page));
    if ($page === '' || $page === 'dashboard') return;                 // don't count the dashboard itself
    $u = is_file(SMPRO_SC_USAGE) ? json_decode((string)@file_get_contents(SMPRO_SC_USAGE), true) : [];
    if (!is_array($u)) $u = [];
    $u[$page] = (int)($u[$page] ?? 0) + 1;
    if (($u['_n'] ?? 0) > 5000) { foreach ($u as $k => $v) if ($k[0] !== '_') $u[$k] = (int)floor($v / 2); $u['_n'] = 0; }  // halve to age old usage
    $u['_n'] = (int)($u['_n'] ?? 0) + 1;
    @is_dir(dirname(SMPRO_SC_USAGE)) || @mkdir(dirname(SMPRO_SC_USAGE), 0700, true);
    @file_put_contents(SMPRO_SC_USAGE . '.tmp', json_encode($u, JSON_UNESCAPED_SLASHES), LOCK_EX); @chmod(SMPRO_SC_USAGE . '.tmp', 0600); @rename(SMPRO_SC_USAGE . '.tmp', SMPRO_SC_USAGE);
}
function smpro_sc_top($n = 6) {
    $u = is_file(SMPRO_SC_USAGE) ? json_decode((string)@file_get_contents(SMPRO_SC_USAGE), true) : [];
    if (!is_array($u)) return [];
    unset($u['_n']); arsort($u);
    return array_slice(array_keys($u), 0, $n);
}
function smpro_sc_pins() {
    $d = is_file(SMPRO_SC_PINS) ? json_decode((string)@file_get_contents(SMPRO_SC_PINS), true) : null;
    return is_array($d) ? array_values(array_filter(array_map('strval', $d))) : [];
}
function smpro_sc_save_pins(array $pins) {
    $valid = array_keys(smpro_sc_pagemap());
    $clean = array_values(array_unique(array_filter(array_map(fn($p) => preg_replace('/[^a-z0-9_\-]/', '', strtolower($p)), $pins), fn($p) => in_array($p, $valid, true))));
    @is_dir(dirname(SMPRO_SC_PINS)) || @mkdir(dirname(SMPRO_SC_PINS), 0700, true);
    @file_put_contents(SMPRO_SC_PINS . '.tmp', json_encode(array_slice($clean, 0, 12), JSON_UNESCAPED_SLASHES), LOCK_EX); @chmod(SMPRO_SC_PINS . '.tmp', 0600); @rename(SMPRO_SC_PINS . '.tmp', SMPRO_SC_PINS);
    if (function_exists('smpro_audit')) smpro_audit('shortcuts_save', ['n' => count($clean)]);
    return $clean;
}
/* page id => [label, icon] from the menu registry (built pages only, excluding the dashboard). */
function smpro_sc_pagemap() {
    static $map = null; if ($map !== null) return $map;
    $map = [];
    if (function_exists('smpro_menu')) foreach (smpro_menu() as $group) foreach ($group as $it) {
        if (empty($it['built']) || ($it['id'] ?? '') === 'dashboard') continue;
        $map[$it['id']] = [$it['label'] ?? $it['id'], $it['icon'] ?? '&#9679;'];
    }
    return $map;
}

/* ---------------- render the shortcuts card ---------------- */
function smpro_sc_render() {
    $map  = smpro_sc_pagemap();
    $pins = array_values(array_filter(smpro_sc_pins(), fn($p) => isset($map[$p])));
    $top  = array_values(array_filter(smpro_sc_top(8), fn($p) => isset($map[$p]) && !in_array($p, $pins, true)));
    $show = array_slice(array_merge($pins, $top), 0, 8);
    if (!$show) $show = array_slice(array_keys($map), 0, 6);            // fresh install: sensible defaults
    $csrf = function_exists('smpro_csrf_generate') ? smpro_csrf_generate('shortcuts') : '';

    echo '<div class="card sc-card" style="margin-bottom:14px"><div style="display:flex;align-items:center;gap:10px;margin-bottom:10px">';
    echo '<div class="lbl" style="margin:0">&#9889; Shortcuts</div><span class="meta" style="font-size:11.5px">pinned + most-used</span>';
    echo '<span style="flex:1"></span><button class="btn" id="scEdit" style="padding:4px 10px;font-size:12px">&#9881;&#65039; Customize</button></div>';
    echo '<div class="sc-row">';
    foreach ($show as $p) {
        [$label, $icon] = $map[$p];
        $pin = in_array($p, $pins, true) ? ' <span title="pinned" style="color:#f59e0b">&#128204;</span>' : '';
        echo '<a class="sc-chip" href="index.cgi?page=' . smpro_h($p) . '"><span class="sc-ic">' . $icon . '</span><span>' . smpro_h($label) . $pin . '</span></a>';
    }
    echo '</div>';

    // customize panel (pin/unpin any page)
    echo '<div id="scEditBox" hidden style="margin-top:12px;border-top:1px solid var(--line);padding-top:10px">';
    echo '<p class="meta" style="margin:0 0 8px">Pick the pages to pin as shortcuts (the rest auto-fill from your most-used):</p><div class="sc-pick">';
    foreach ($map as $id => $info) {
        $ck = in_array($id, $pins, true) ? ' checked' : '';
        echo '<label class="sc-pk"><input type="checkbox" class="scChk" value="' . smpro_h($id) . '"' . $ck . '> ' . $info[1] . ' ' . smpro_h($info[0]) . '</label>';
    }
    echo '</div><div style="margin-top:10px"><button class="btn" id="scSave" style="background:#16a34a;color:#fff">Save shortcuts</button><span id="scMsg" class="meta" style="margin-left:10px"></span></div></div>';
    echo '</div>';

    echo '<style>.sc-row{display:flex;gap:8px;flex-wrap:wrap}.sc-chip{display:inline-flex;align-items:center;gap:7px;background:#fff;border:1px solid var(--line);border-radius:10px;padding:8px 12px;font-size:13px;font-weight:600;color:var(--ink);text-decoration:none;transition:.15s}.sc-chip:hover{border-color:var(--brand);box-shadow:0 2px 10px rgba(124,58,237,.12);transform:translateY(-1px)}.sc-ic{font-size:15px}.sc-pick{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:6px}.sc-pk{display:flex;align-items:center;gap:7px;font-size:12.5px;background:#f7f9fc;border:1px solid var(--line);border-radius:8px;padding:6px 9px;cursor:pointer}</style>';
    echo '<script>(function(){var T=' . json_encode($csrf) . ';function P(i){return document.getElementById(i);}
      var e=P("scEdit"),b=P("scEditBox");if(e)e.addEventListener("click",function(){b.hidden=!b.hidden;});
      var s=P("scSave");if(s)s.addEventListener("click",function(){var pins=[].slice.call(document.querySelectorAll(".scChk:checked")).map(function(c){return c.value;});
        var fd=new URLSearchParams();fd.set("smpro_csrf",T);pins.forEach(function(p,i){fd.set("pin["+i+"]",p);});
        s.disabled=true;fetch("index.cgi?shortcuts=1",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:fd.toString(),cache:"no-store"}).then(function(r){return r.json();}).then(function(j){s.disabled=false;
          if(j&&j.ok){P("scMsg").textContent="✓ Saved — reloading…";P("scMsg").style.color="#047857";setTimeout(function(){location.reload();},600);}else{P("scMsg").textContent="✗ "+((j&&j.msg)||"failed");P("scMsg").style.color="#b91c1c";}}).catch(function(){s.disabled=false;P("scMsg").textContent="Request failed";});});
    })();</script>';
}

/* ---------------- Security & Health Score ----------------
 * A single 0–100 posture number for the whole server, computed from signals we ALREADY collect:
 *   - acute conditions surfaced by smpro_dash_attention() (load / RAM / disk / swap / intrusion /
 *     service-down) — these are pre-validated, so we never double-implement the detection here;
 *   - cheap security-posture checks (firewall present, malware scanner present).
 * Pure function (no side effects) so it can be reused by notifications / digests. */
function smpro_security_score($m = null, $attn = null) {
    if (!is_array($m))    $m    = function_exists('smpro_collect_metrics') ? smpro_collect_metrics() : [];
    if (!is_array($attn)) $attn = function_exists('smpro_dash_attention')  ? smpro_dash_attention($m) : [];

    $score = 100; $factors = [];
    $hit = function ($pts, $label, $page, $sev) use (&$score, &$factors) {
        $score -= $pts;
        $factors[] = ['pts' => $pts, 'label' => $label, 'page' => $page, 'sev' => $sev];
    };

    // acute issues — weight by the severity attention already assigned
    $sevPts = ['critical' => 14, 'warn' => 7, 'info' => 3];
    foreach ($attn as $x) {
        if (!empty($x['noscore'])) continue;                    // protective/positive notices (e.g. attackers blocked) never lower posture
        $sev = (string)($x['sev'] ?? 'warn');
        $hit($sevPts[$sev] ?? 7, (string)($x['title'] ?? 'Issue'), (string)($x['page'] ?? 'dashboard'), $sev === 'critical' ? 'crit' : ($sev === 'info' ? 'info' : 'warn'));
    }

    // posture — cheap presence checks (no scans)
    $csf = is_file('/etc/csf/csf.conf') || (function_exists('smpro_has_bin') && smpro_has_bin('csf'));
    if (!$csf) $hit(15, 'No firewall (CSF) detected', 'firewall-status', 'crit');
    $imun = function_exists('smpro_has_bin') && smpro_has_bin('imunify360-agent');
    if (!$imun) $hit(8, 'No malware scanner (Imunify) detected', 'forensics-audit', 'warn');

    // Open Server Tune-up hardening findings (SSH/Apache/MySQL/CSF/symlink/jail/…). Read a CACHED summary only —
    // the dashboard never runs the heavy tune-up scan itself; Server Tune-up + a throttled background job keep it fresh.
    $pd = function_exists('smpro_tun_posture_read') ? smpro_tun_posture_read() : [];
    if (is_array($pd) && !empty($pd['count']) && (time() - (int)($pd['ts'] ?? 0)) < 7 * 86400) {
        $ppts = min(40, (int)($pd['pts'] ?? 0));
        if ($ppts > 0) { $n = (int)$pd['count']; $hit($ppts, $n . ' server hardening item' . ($n > 1 ? 's' : '') . ' open in Server Tune-up', 'server-tuning', 'warn'); }
    }

    if ($score < 0)   $score = 0;
    if ($score > 100) $score = 100;
    $label = $score >= 85 ? 'Excellent' : ($score >= 70 ? 'Good' : ($score >= 50 ? 'Fair' : 'At risk'));
    $tone  = $score >= 70 ? 'good' : ($score >= 50 ? 'warn' : 'crit');
    return ['score' => (int)$score, 'label' => $label, 'tone' => $tone, 'issues' => count($factors), 'factors' => $factors];
}

/* Record today's score (one sample/day, 30-day ring) and return the previous day's score for the trend. */
function smpro_score_hist_record($score) {
    $f = SMPRO_VARLIB . '/score_hist.json';
    $h = is_file($f) ? json_decode((string)@file_get_contents($f), true) : [];
    if (!is_array($h)) $h = [];
    $today = date('Y-m-d');
    krsort($h);
    $prev = null;
    foreach ($h as $d => $v) { if ($d !== $today) { $prev = (int)$v; break; } }
    $h[$today] = (int)$score;
    ksort($h);
    if (count($h) > 30) $h = array_slice($h, -30, null, true);
    @is_dir(dirname($f)) || @mkdir(dirname($f), 0700, true);
    @file_put_contents($f . '.tmp', json_encode($h, JSON_UNESCAPED_SLASHES), LOCK_EX);
    @chmod($f . '.tmp', 0600); @rename($f . '.tmp', $f);
    return $prev;
}

/* Render the hero score card (semicircle gauge + label + trend + clickable issue chips). */
function smpro_score_render($m = null, $attn = null) {
    $r     = smpro_security_score($m, $attn);
    $sc    = (int)$r['score'];
    $tone  = $r['tone'];
    $prev  = smpro_score_hist_record($sc);
    $trend = ($prev === null) ? null : ($sc - $prev);

    $col = $tone === 'good' ? '#1f9d55' : ($tone === 'warn' ? '#c47f17' : '#d93b3b');
    $cbg = $tone === 'good' ? 'var(--good-bg)' : ($tone === 'warn' ? 'var(--warn-bg)' : 'var(--dang-bg)');
    $R = 72; $cx = 92; $cy = 92; $x0 = $cx - $R; $x1 = $cx + $R;
    $len = M_PI * $R;
    $off = $len * (1 - $sc / 100);
    $path = "M{$x0},{$cy} A{$R},{$R} 0 0,1 {$x1},{$cy}";
    ob_start(); ?>
  <div class="card score-hero" style="margin:6px 0 14px">
    <div class="sh-gauge">
      <svg viewBox="0 0 184 108" width="184" height="108" aria-hidden="true">
        <path d="<?= $path ?>" fill="none" style="stroke:var(--line)" stroke-width="13" stroke-linecap="round"/>
        <path d="<?= $path ?>" fill="none" stroke="<?= $col ?>" stroke-width="13" stroke-linecap="round"
              stroke-dasharray="<?= round($len, 1) ?>" stroke-dashoffset="<?= round($off, 1) ?>"/>
        <text x="92" y="84" text-anchor="middle" font-size="40" font-weight="800" style="fill:var(--ink)"><?= $sc ?></text>
        <text x="92" y="102" text-anchor="middle" font-size="12" style="fill:var(--muted)">out of 100</text>
      </svg>
    </div>
    <div class="sh-body">
      <div class="sh-top">
        <span class="sh-label" style="color:<?= $col ?>;background:<?= $cbg ?>"><?= smpro_h($r['label']) ?></span>
        <span class="sh-title">Security &amp; Health Score</span>
        <?php if ($trend !== null && $trend > 0): ?>
          <span class="sh-trend up">&#9650; +<?= $trend ?> since yesterday</span>
        <?php elseif ($trend !== null && $trend < 0): ?>
          <span class="sh-trend down">&#9660; <?= $trend ?> since yesterday</span>
        <?php elseif ($trend === 0): ?>
          <span class="sh-trend flat">&#8212; no change since yesterday</span>
        <?php endif; ?>
      </div>
      <?php if ($r['issues'] > 0): ?>
        <div class="sh-issues"><b><?= (int)$r['issues'] ?></b> issue<?= $r['issues'] > 1 ? 's' : '' ?> lowering your score — click any to fix:</div>
        <div class="sh-factors">
          <?php foreach (array_slice($r['factors'], 0, 6) as $f): ?>
            <a class="sh-fac sh-<?= smpro_h($f['sev']) ?>" href="index.cgi?page=<?= smpro_h($f['page']) ?>">
              <span><?= smpro_h($f['label']) ?></span><em>&minus;<?= (int)$f['pts'] ?></em>
            </a>
          <?php endforeach; ?>
        </div>
      <?php else: ?>
        <div class="sh-allclear">&#10003; No active issues detected — all monitored areas are healthy.</div>
      <?php endif; ?>
    </div>
  </div>
  <style>
  .score-hero{display:flex;align-items:center;gap:24px;flex-wrap:wrap}
  .sh-gauge{flex:0 0 auto}
  .sh-body{flex:1;min-width:240px}
  .sh-top{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:8px}
  .sh-label{font-size:12px;font-weight:800;padding:3px 11px;border-radius:20px;text-transform:uppercase;letter-spacing:.04em}
  .sh-title{font-size:16px;font-weight:800}
  .sh-trend{font-size:11.5px;font-weight:700;padding:2px 9px;border-radius:20px}
  .sh-trend.up{color:var(--good);background:var(--good-bg)}
  .sh-trend.down{color:var(--dang);background:var(--dang-bg)}
  .sh-trend.flat{color:var(--muted);background:#eef1f6}
  .sh-issues{font-size:12.5px;color:var(--muted);margin-bottom:8px}
  .sh-issues b{color:var(--ink)}
  .sh-factors{display:flex;gap:7px;flex-wrap:wrap}
  .sh-fac{display:inline-flex;align-items:center;gap:8px;text-decoration:none;font-size:12px;font-weight:600;padding:5px 10px;border-radius:9px;border:1px solid var(--line);background:var(--card);color:var(--ink);transition:.15s}
  .sh-fac:hover{transform:translateY(-1px);box-shadow:0 3px 12px rgba(0,0,0,.08)}
  .sh-fac em{font-style:normal;font-weight:800;font-size:11px;color:var(--dang)}
  .sh-fac.sh-crit{border-left:4px solid #dc2626}.sh-fac.sh-warn{border-left:4px solid #f59e0b}.sh-fac.sh-info{border-left:4px solid #0ea5e9}
  .sh-allclear{font-size:13px;color:var(--good);font-weight:700;background:var(--good-bg);display:inline-block;padding:7px 13px;border-radius:10px}
  </style>
  <?php
    echo ob_get_clean();
}
