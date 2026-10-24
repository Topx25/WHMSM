<?php
/**
 * modules/network.php - Network Traffic (live + historical totals).
 * Live upload/download rate per interface (sampled from /proc/net/dev), total
 * traffic since boot, and historical upload/download totals per period
 * (this hour / today / last 24h / this month / last 30 days / all-time) read
 * from vnStat when installed. Read-only; self-contained live JSON endpoint.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

/* ---------------- /proc/net/dev sampling ---------------- */
function smpro_net_dev() {
    $r = [];
    foreach (file('/proc/net/dev') ?: [] as $l) {
        if (!preg_match('/^\s*([\w.@-]+):\s*(.+)$/', $l, $m)) continue;
        $if = $m[1]; if ($if === 'lo') continue;
        $f = preg_split('/\s+/', trim($m[2]));
        if (count($f) >= 9) $r[$if] = ['rx' => (int)$f[0], 'tx' => (int)$f[8]];
    }
    return $r;
}
function smpro_net_default_iface() {
    $o = trim((string)@shell_exec("ip route 2>/dev/null | awk '/^default/{print \$5; exit}'"));
    return $o !== '' ? $o : '';
}
function smpro_net_conns() {
    $s = (string)@shell_exec('timeout 8 ss -s 2>/dev/null');
    return [
        'total' => preg_match('/Total:\s*(\d+)/', $s, $m) ? (int)$m[1] : 0,
        'estab' => preg_match('/estab\s+(\d+)/', $s, $m) ? (int)$m[1] : 0,
        'tw'    => preg_match('/timewait\s+(\d+)/', $s, $m) ? (int)$m[1] : 0,
    ];
}
function smpro_net_live() {
    $a = smpro_net_dev(); usleep(500000); $b = smpro_net_dev();
    $ifaces = []; $sumRx = 0; $sumTx = 0; $totRx = 0; $totTx = 0;
    foreach ($b as $if => $v) {
        if (!isset($a[$if])) continue;
        $rxRate = max(0, ($v['rx'] - $a[$if]['rx']) / 0.5);
        $txRate = max(0, ($v['tx'] - $a[$if]['tx']) / 0.5);
        // skip dead interfaces with no traffic at all
        if (($v['rx'] + $v['tx']) === 0 && $rxRate < 1 && $txRate < 1) continue;
        $ifaces[] = ['name' => $if, 'rx' => $rxRate, 'tx' => $txRate, 'rx_total' => $v['rx'], 'tx_total' => $v['tx']];
        $sumRx += $rxRate; $sumTx += $txRate; $totRx += $v['rx']; $totTx += $v['tx'];
    }
    usort($ifaces, fn($x, $y) => ($y['rx'] + $y['tx']) <=> ($x['rx'] + $x['tx']));
    return ['ts' => date('H:i:s'), 'ifaces' => $ifaces, 'rate' => ['rx' => $sumRx, 'tx' => $sumTx], 'boot' => ['rx' => $totRx, 'tx' => $totTx], 'conns' => smpro_net_conns()];
}
/** Per-account bandwidth this month (whmapi1 showbw). Returns null off cPanel. */
function smpro_net_bandwidth($n = 25) {
    if (!is_executable('/usr/local/cpanel/bin/whmapi1')) return null;
    $j = json_decode((string)@shell_exec('timeout 25 /usr/local/cpanel/bin/whmapi1 --output=json showbw 2>/dev/null'), true);
    $acct = $j['data']['acct'] ?? null; if (!is_array($acct)) return null;
    $rows = [];
    foreach ($acct as $a) {
        $used = (int)($a['totalbytes'] ?? 0); $limit = (int)($a['limit'] ?? 0);
        $rows[] = ['user' => (string)($a['user'] ?? ''), 'domain' => (string)($a['maindomain'] ?? ''), 'used' => $used,
                   'limit' => $limit, 'pct' => $limit > 0 ? round($used / $limit * 100, 1) : 0, 'limited' => !empty($a['bwlimited'])];
    }
    usort($rows, fn($x, $y) => $y['used'] <=> $x['used']);
    return ['rows' => array_slice($rows, 0, $n), 'count' => count($rows), 'total' => array_sum(array_column($rows, 'used'))];
}

/* ---------------- vnStat historical totals ---------------- */
function smpro_net_vnstat($iface = '') {
    if (!smpro_has_bin('vnstat')) return null;
    $cmd = 'timeout 15 vnstat --json' . ($iface !== '' ? ' -i ' . escapeshellarg($iface) : '') . ' 2>/dev/null';
    $j = json_decode((string)@shell_exec($cmd), true);
    if (!is_array($j) || empty($j['interfaces'])) return null;
    $best = null;
    if ($iface !== '') foreach ($j['interfaces'] as $i) if (($i['name'] ?? '') === $iface) { $best = $i; break; }
    if (!$best) { usort($j['interfaces'], fn($a, $b) => (($b['traffic']['total']['rx'] ?? 0) + ($b['traffic']['total']['tx'] ?? 0)) <=> (($a['traffic']['total']['rx'] ?? 0) + ($a['traffic']['total']['tx'] ?? 0))); $best = $j['interfaces'][0]; }
    $t = $best['traffic'] ?? [];
    $sumLast = function ($arr, $n) { $arr = array_slice((array)$arr, -$n); $rx = 0; $tx = 0; foreach ($arr as $r) { $rx += $r['rx'] ?? 0; $tx += $r['tx'] ?? 0; } return ['rx' => $rx, 'tx' => $tx]; };
    $lastOr = function ($arr) { $r = is_array($arr) && $arr ? end($arr) : []; return ['rx' => $r['rx'] ?? 0, 'tx' => $r['tx'] ?? 0]; };
    return [
        'iface' => $best['name'] ?? $iface,
        'periods' => [
            'hour'  => $lastOr($t['hour'] ?? []),
            'today' => $lastOr($t['day'] ?? []),
            'h24'   => $sumLast($t['hour'] ?? [], 24),
            'month' => $lastOr($t['month'] ?? []),
            'd30'   => $sumLast($t['day'] ?? [], 30),
            'total' => ['rx' => $t['total']['rx'] ?? 0, 'tx' => $t['total']['tx'] ?? 0],
        ],
    ];
}
function smpro_net_human($b) { $b = (float)$b; $u = ['B','KB','MB','GB','TB','PB']; $i = 0; while ($b >= 1024 && $i < 5) { $b /= 1024; $i++; } return ($i ? round($b, 2) : (int)$b) . ' ' . $u[$i]; }

/** Split an `ss` address field into [ip, port]; handles IPv6 "[::1]:22" and IPv4 "1.2.3.4:80". */
function smpro_net_split_addr($a) {
    if ($a === '' ) return ['', ''];
    if ($a[0] === '[' && ($p = strpos($a, ']:')) !== false) return [substr($a, 1, $p - 1), substr($a, $p + 2)];
    $p = strrpos($a, ':');
    return $p === false ? [$a, ''] : [substr($a, 0, $p), substr($a, $p + 1)];
}
/**
 * Who is connected to this server RIGHT NOW, grouped by remote IP - the "who is hammering the box"
 * view. One `ss` call, aggregated in PHP. Country is resolved only for the few rows we display and
 * only from the local/offline DB ($cap=false), so a big box with thousands of connections stays fast.
 */
function smpro_net_talkers($limit = 15) {
    $raw = (string)@shell_exec('timeout 12 ss -tnp state established 2>/dev/null');
    if (trim($raw) === '') {
        // A live server with ZERO established sockets is not a state that happens; an empty answer here means
        // ss is missing or timed out. Say so instead of drawing an empty, reassuring table.
        $hasSs = trim((string)@shell_exec('command -v ss 2>/dev/null')) !== '';
        return ['rows' => [], 'total' => 0, 'unique' => 0,
                'error' => $hasSs ? 'ss returned nothing (timed out?) — connections could not be read' : 'ss is not installed — connections cannot be read'];
    }
    $agg = []; $total = 0;
    foreach (explode("\n", $raw) as $i => $ln) {
        $ln = trim($ln);
        if ($ln === '' || stripos($ln, 'Recv-Q') === 0) continue;
        $c = preg_split('/\s+/', $ln);
        if (count($c) < 4) continue;
        // `ss -tn state established` drops the State column: Recv-Q Send-Q Local Peer [users:(...)]
        [$lip, $lport] = smpro_net_split_addr($c[2]);
        [$rip, $rport] = smpro_net_split_addr($c[3]);
        if ($rip === '' || $rip === '127.0.0.1' || $rip === '::1' || strpos($rip, '127.') === 0) continue;   // loopback = not a visitor
        $total++;
        $proc = preg_match('/users:\(\("([^"]+)"/', $ln, $pm) ? $pm[1] : '';
        if (!isset($agg[$rip])) $agg[$rip] = ['ip' => $rip, 'conns' => 0, 'ports' => [], 'procs' => []];
        $agg[$rip]['conns']++;
        if ($lport !== '') $agg[$rip]['ports'][$lport] = ($agg[$rip]['ports'][$lport] ?? 0) + 1;
        if ($proc !== '') $agg[$rip]['procs'][$proc] = true;
    }
    $unique = count($agg);
    usort($agg, fn($a, $b) => $b['conns'] <=> $a['conns']);
    $rows = array_slice(array_values($agg), 0, max(1, (int)$limit));
    foreach ($rows as &$r) {
        arsort($r['ports']);
        $r['top_ports'] = implode(', ', array_slice(array_keys($r['ports']), 0, 4));
        $r['service']   = implode(', ', array_slice(array_keys($r['procs']), 0, 3));
        $r['country']   = function_exists('smpro_geoip_cc') ? (string)smpro_geoip_cc($r['ip']) : '';
        $r['is_server'] = function_exists('smpro_is_server_ip') && smpro_is_server_ip($r['ip']);
        unset($r['ports'], $r['procs']);
    }
    unset($r);
    return ['rows' => $rows, 'total' => $total, 'unique' => $unique];
}

/* ---------------- live JSON endpoint ---------------- */
if (isset($_GET['live'])) { header('Content-Type: application/json'); echo json_encode(['ok' => true, 'live' => smpro_net_live()], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit; }

/* ---------------- render ---------------- */
$L = smpro_net_live();
$defIf = smpro_net_default_iface();
// vnstat + per-account bandwidth are heavy root-CLI probes (walks every account's bw DB) - keep them OFF
// every render via a read-through cache so a page view costs at most one probe per TTL window.
$vn = smpro_cache_through('net_vnstat_' . preg_replace('/[^a-z0-9]/i', '', $defIf), 300, fn() => smpro_net_vnstat($defIf));
$bw = smpro_cache_through('net_bw', 300, fn() => smpro_net_bandwidth(30));
// live connection picture - cheap (one ss call), but cache briefly so rapid reloads don't re-probe
$talk = smpro_cache_through('net_talkers', 20, fn() => smpro_net_talkers(15));
$periods = [
    'hour'  => ['This hour', '&#8986;'],
    'today' => ['Today', '&#128197;'],
    'h24'   => ['Last 24 h', '&#128336;'],
    'month' => ['This month', '&#128198;'],
    'd30'   => ['Last 30 days', '&#128467;'],
    'total' => ['All-time', '&#931;'],
];
smpro_audit('network_view', ['vnstat' => $vn ? 1 : 0]);
smpro_layout_header('Network Traffic');
?>
<div class="svc-kicker">Server Monitoring</div>
<div style="display:flex;justify-content:space-between;align-items:flex-start;gap:14px;flex-wrap:wrap">
  <div><h1 class="h" style="margin:2px 0 4px">Network Traffic <span class="nt-live" id="ntLive">&#9679; LIVE</span></h1>
    <p class="sub">Live upload &amp; download rate per interface, total since boot, and historical totals per time period.</p></div>
  <label class="nt-pause"><input type="checkbox" id="ntPause"> Pause</label>
</div>

<!-- live KPIs -->
<div class="nt-kpis">
  <div class="nt-kpi dn"><div class="nt-ic">&#8595;</div><div><div class="nt-kl">Download (live)</div><div class="nt-kv" id="kRxRate"><?= smpro_net_human($L['rate']['rx']) ?>/s</div></div></div>
  <div class="nt-kpi up"><div class="nt-ic">&#8593;</div><div><div class="nt-kl">Upload (live)</div><div class="nt-kv" id="kTxRate"><?= smpro_net_human($L['rate']['tx']) ?>/s</div></div></div>
  <div class="nt-kpi"><div class="nt-ic">&#8595;</div><div><div class="nt-kl">Total down (since boot)</div><div class="nt-kv" id="kRxTot"><?= smpro_net_human($L['boot']['rx']) ?></div></div></div>
  <div class="nt-kpi"><div class="nt-ic">&#8593;</div><div><div class="nt-kl">Total up (since boot)</div><div class="nt-kv" id="kTxTot"><?= smpro_net_human($L['boot']['tx']) ?></div></div></div>
</div>

<!-- period totals -->
<div class="card" style="padding:0;overflow:hidden;margin-bottom:14px">
  <div class="tp-th"><b>&#128202; Traffic by period</b>
    <?php if ($vn): ?><span class="meta">vnStat · interface <?= smpro_h($vn['iface']) ?></span><?php else: ?><span class="meta">vnStat not installed</span><?php endif; ?></div>
  <?php if ($vn): ?>
  <div class="nt-periods">
    <?php foreach ($periods as $k => $p): $d = $vn['periods'][$k]; $tot = ($d['rx'] ?? 0) + ($d['tx'] ?? 0); ?>
      <div class="nt-per">
        <div class="nt-per-h"><?= $p[1] ?> <?= smpro_h($p[0]) ?></div>
        <div class="nt-per-tot"><?= smpro_net_human($tot) ?></div>
        <div class="nt-per-sub"><span class="dn">&#8595; <?= smpro_net_human($d['rx'] ?? 0) ?></span> · <span class="up">&#8593; <?= smpro_net_human($d['tx'] ?? 0) ?></span></div>
      </div>
    <?php endforeach; ?>
  </div>
  <?php else: ?>
  <div class="nt-novn">vnStat gives accurate per-hour / per-day / per-month upload &amp; download totals. Install it from the warning banner at the top (or <code>apt/dnf install vnstat</code>), then this fills in. Live rates and since-boot totals work without it.</div>
  <?php endif; ?>
</div>

<!-- live traffic chart + connections -->
<div class="nt-graphrow">
  <div class="card" style="padding:0;overflow:hidden">
    <div class="tp-th"><b>&#128200; Live traffic</b><span class="meta"><span class="dn">&#8595; download</span> · <span class="up">&#8593; upload</span> · last ~3 min</span></div>
    <div style="padding:12px 14px">
      <svg id="ntChart" viewBox="0 0 600 150" preserveAspectRatio="none" class="nt-chart">
        <polyline id="ntRx" fill="rgba(31,157,85,.12)" stroke="var(--good)" stroke-width="2" points=""></polyline>
        <polyline id="ntTx" fill="none" stroke="var(--brand)" stroke-width="2" points=""></polyline>
      </svg>
      <div class="nt-chart-now"><span class="dn" id="ntChR">↓ —</span><span class="up" id="ntChT">↑ —</span><span class="meta" id="ntChPk"></span></div>
    </div>
  </div>
  <div class="card nt-conns">
    <div class="tp-th"><b>&#128279; Connections</b></div>
    <div class="nt-conn-grid">
      <div class="nt-cc"><div class="n" id="cEstab"><?= number_format($L['conns']['estab']) ?></div><div class="l">Established</div></div>
      <div class="nt-cc"><div class="n" id="cTotal"><?= number_format($L['conns']['total']) ?></div><div class="l">Total sockets</div></div>
      <div class="nt-cc"><div class="n" id="cTw"><?= number_format($L['conns']['tw']) ?></div><div class="l">Time-wait</div></div>
    </div>
  </div>
</div>

<!-- who is connected right now (top talkers) -->
<div class="card" style="padding:0;overflow:hidden;margin-bottom:14px">
  <div class="tp-th"><b>&#127760; Who is connected right now</b>
    <span class="meta"><?= number_format((int)$talk['total']) ?> established connection(s) from <?= number_format((int)$talk['unique']) ?> remote IP(s)</span></div>
  <?php if (!$talk['rows']): ?>
    <?php if (!empty($talk['error'])): ?>
    <div style="padding:14px 16px;color:var(--dang);font-size:13px">&#9888; <?= smpro_h($talk['error']) ?> &mdash; this is a failed read, not an empty server.</div>
    <?php else: ?>
    <div style="padding:14px 16px;color:var(--muted);font-size:13px">No external connections are established at this moment.</div>
    <?php endif; ?>
  <?php else: $tkMax = max(1, (int)$talk['rows'][0]['conns']); ?>
  <div class="nt-tw" style="max-height:420px"><table class="smpro-table"><thead><tr><th>Remote IP</th><th>Country</th><th class="num">Connections</th><th style="width:170px">Share</th><th>Reaching</th><th>Service</th><th></th></tr></thead><tbody>
    <?php foreach ($talk['rows'] as $t): $sh = round((int)$t['conns'] / $tkMax * 100); ?>
      <tr>
        <td class="mono"><b><?= smpro_h($t['ip']) ?></b><?= !empty($t['is_server']) ? ' <span class="b">this server</span>' : '' ?></td>
        <td><?= $t['country'] !== '' ? smpro_h($t['country']) : '<span class="meta">—</span>' ?></td>
        <td class="num mono"><?= (int)$t['conns'] ?></td>
        <td><div class="nt-bwbar"><i style="width:<?= max(2, $sh) ?>%;background:<?= $sh >= 70 ? 'var(--warn)' : 'var(--brand)' ?>"></i></div></td>
        <td class="mono"><?= smpro_h($t['top_ports']) ?></td>
        <td class="mono"><?= $t['service'] !== '' ? smpro_h($t['service']) : '<span class="meta">—</span>' ?></td>
        <td><?php if (empty($t['is_server'])): ?><a class="fa-lnk" href="index.cgi?page=reports-center&amp;ip=<?= urlencode($t['ip']) ?>">Investigate &#8594;</a><?php endif; ?></td>
      </tr>
    <?php endforeach; ?>
  </tbody></table></div>
  <div style="padding:9px 16px;border-top:1px solid var(--line);color:var(--muted);font-size:11.5px">A snapshot of established TCP connections, grouped by remote IP. Many connections from one IP to the same port can be normal (a busy visitor or a proxy) — use <b>Investigate</b> to see what that IP is actually doing before acting on it.</div>
  <?php endif; ?>
</div>

<!-- top accounts by bandwidth -->
<?php if ($bw && $bw['rows']): $bwMax = max(1, $bw['rows'][0]['used']); ?>
<div class="card" style="padding:0;overflow:hidden;margin-bottom:14px">
  <div class="tp-th"><b>&#128100; Top accounts by bandwidth</b><span class="meta"><?= number_format($bw['count']) ?> accounts · <?= smpro_net_human($bw['total']) ?> total this month</span></div>
  <div class="nt-tw" style="max-height:460px"><table class="smpro-table"><thead><tr><th>Account</th><th>Main domain</th><th class="num">Used (month)</th><th class="num">Limit</th><th style="width:200px">Share</th><th></th></tr></thead><tbody>
    <?php foreach ($bw['rows'] as $r): $share = round($r['used'] / $bwMax * 100); $limTxt = $r['limit'] > 0 ? smpro_net_human($r['limit']) : '∞'; ?>
      <tr>
        <td class="mono"><b><?= smpro_h($r['user']) ?></b><?= $r['limited']?' <span class="b red">limited</span>':'' ?></td>
        <td class="mono meta"><?= smpro_h($r['domain']) ?></td>
        <td class="num"><b><?= smpro_net_human($r['used']) ?></b></td>
        <td class="num meta"><?= $limTxt ?><?= $r['pct']?' · '.$r['pct'].'%':'' ?></td>
        <td><div class="nt-bwbar"><i style="width:<?= max(2,$share) ?>%;background:<?= $r['pct']>=90?'var(--dang)':($r['pct']>=70?'var(--warn)':'var(--brand)') ?>"></i></div></td>
        <td style="white-space:nowrap"><a class="fa-lnk" href="index.cgi?page=account-audit&tab=webact&audit_user=<?= urlencode($r['user']) ?>">Web activity</a></td>
      </tr>
    <?php endforeach; ?>
  </tbody></table></div>
</div>
<?php elseif ($bw === null): ?>
<div class="card" style="color:var(--muted);font-size:13px;margin-bottom:14px">Per-account bandwidth needs cPanel/WHM (whmapi1 showbw). Not available on this host.</div>
<?php endif; ?>

<!-- per-interface live -->
<div class="card" style="padding:0;overflow:hidden">
  <div class="tp-th"><b>Interfaces</b><span class="meta">live rate &amp; cumulative since boot</span></div>
  <div class="nt-tw"><table class="smpro-table"><thead><tr><th>Interface</th><th class="num">&#8595; Down rate</th><th class="num">&#8593; Up rate</th><th class="num">Total down</th><th class="num">Total up</th></tr></thead><tbody id="ntIf">
    <?php foreach ($L['ifaces'] as $n): ?><tr data-if="<?= smpro_h($n['name']) ?>"><td class="mono"><?= smpro_h($n['name']) ?><?= $n['name']===$defIf?' <span class="b blue">default</span>':'' ?></td><td class="num rx"><?= smpro_net_human($n['rx']) ?>/s</td><td class="num tx"><?= smpro_net_human($n['tx']) ?>/s</td><td class="num meta rxt"><?= smpro_net_human($n['rx_total']) ?></td><td class="num meta txt"><?= smpro_net_human($n['tx_total']) ?></td></tr><?php endforeach; ?>
  </tbody></table></div>
</div>

<style>
.svc-kicker{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--brand);font-weight:800}
.nt-live{font-size:11px;font-weight:800;color:var(--good);vertical-align:middle;margin-left:6px}.nt-live.off{color:var(--muted)}
.nt-pause{font-size:13px;display:flex;align-items:center;gap:6px;font-weight:600;color:var(--muted)}
.nt-kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:14px 0}@media(max-width:820px){.nt-kpis{grid-template-columns:1fr 1fr}}
.nt-kpi{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:14px 16px;display:flex;align-items:center;gap:12px}
.nt-kpi.dn{border-left:4px solid var(--good)}.nt-kpi.up{border-left:4px solid var(--brand)}
.nt-ic{font-size:20px;font-weight:800;color:var(--muted)}.nt-kpi.dn .nt-ic{color:var(--good)}.nt-kpi.up .nt-ic{color:var(--brand)}
.nt-kl{font-size:11px;text-transform:uppercase;color:var(--muted);font-weight:700}
.nt-kv{font-size:19px;font-weight:800;margin-top:2px}
.tp-th{display:flex;align-items:center;gap:10px;padding:12px 16px;border-bottom:1px solid var(--line);font-weight:700;font-size:14px}.tp-th .meta{margin-left:auto;color:var(--muted);font-size:12px}
.nt-periods{display:grid;grid-template-columns:repeat(6,1fr);gap:1px;background:var(--line)}@media(max-width:1000px){.nt-periods{grid-template-columns:repeat(3,1fr)}}@media(max-width:560px){.nt-periods{grid-template-columns:1fr 1fr}}
.nt-per{background:var(--card);padding:14px 16px;text-align:center}
.nt-per-h{font-size:11px;text-transform:uppercase;color:var(--muted);font-weight:700}
.nt-per-tot{font-size:20px;font-weight:800;margin:6px 0 3px}
.nt-per-sub{font-size:11.5px}.nt-per-sub .dn{color:var(--good)}.nt-per-sub .up{color:var(--brand)}
.nt-novn{padding:16px;font-size:13px;color:#8a6516;background:var(--warn-bg);line-height:1.6}
.nt-tw{overflow:auto}.smpro-table{width:100%;border-collapse:collapse;font-size:12.5px}
.smpro-table th,.smpro-table td{padding:9px 12px;text-align:left;border-bottom:1px solid var(--line);white-space:nowrap}
.smpro-table th{font-size:11px;text-transform:uppercase;color:var(--muted)}.smpro-table td.num,.smpro-table th.num{text-align:right}
.smpro-table td.rx{color:var(--good);font-weight:700}.smpro-table td.tx{color:var(--brand);font-weight:700}
.mono{font-family:ui-monospace,Consolas,monospace}.meta{color:var(--muted)}
.b{display:inline-block;font-size:11px;font-weight:700;padding:2px 8px;border-radius:20px}.b.blue{background:var(--brand-bg);color:var(--brand)}.b.red{background:var(--dang-bg);color:var(--dang)}
.nt-graphrow{display:grid;grid-template-columns:2fr 1fr;gap:14px;margin-bottom:14px}@media(max-width:820px){.nt-graphrow{grid-template-columns:1fr}}
.nt-chart{width:100%;height:150px;background:var(--card);border:1px solid var(--line);border-radius:10px}
.nt-chart-now{display:flex;gap:16px;margin-top:8px;font-size:13px;font-weight:700}.nt-chart-now .dn{color:var(--good)}.nt-chart-now .up{color:var(--brand)}.nt-chart-now .meta{margin-left:auto;font-weight:400}
.nt-conn-grid{display:flex;flex-direction:column;gap:10px;padding:14px 16px}
.nt-cc{display:flex;justify-content:space-between;align-items:baseline;border-bottom:1px dashed var(--line);padding-bottom:8px}.nt-cc:last-child{border-bottom:0}
.nt-cc .n{font-size:24px;font-weight:800}.nt-cc .l{font-size:12px;color:var(--muted);text-transform:uppercase;font-weight:700}
.dn{color:var(--good)}.up{color:var(--brand)}
.nt-bwbar{height:9px;border-radius:8px;background:var(--card);overflow:hidden}.nt-bwbar>i{display:block;height:100%;border-radius:8px}
.fa-lnk{color:var(--brand);text-decoration:none;font-size:11px;border:1px solid var(--line);padding:2px 8px;border-radius:6px}.fa-lnk:hover{background:var(--brand-bg)}
</style>
<script>
(function(){
  function human(b){b=+b||0;var u=['B','KB','MB','GB','TB','PB'],i=0;while(b>=1024&&i<5){b/=1024;i++;}return (i?b.toFixed(2):b)+' '+u[i];}
  var paused=false;var pz=document.getElementById('ntPause');if(pz)pz.addEventListener('change',function(){paused=this.checked;var lb=document.getElementById('ntLive');if(lb){lb.classList.toggle('off',paused);lb.innerHTML=paused?'&#9679; PAUSED':'&#9679; LIVE';}});
  var hRx=[],hTx=[];
  function chart(){
    var n=Math.max(hRx.length,1);var mx=1;for(var i=0;i<hRx.length;i++){mx=Math.max(mx,hRx[i],hTx[i]);}
    function pts(arr){return arr.map(function(v,i){return ((i/Math.max(1,arr.length-1))*600).toFixed(1)+','+(150-(v/mx)*140).toFixed(1);}).join(' ');}
    var rx=document.getElementById('ntRx'),tx=document.getElementById('ntTx');
    if(rx)rx.setAttribute('points',pts(hRx)+(hRx.length?' 600,150 0,150':''));
    if(tx)tx.setAttribute('points',pts(hTx));
    var r=document.getElementById('ntChR'),t=document.getElementById('ntChT'),pk=document.getElementById('ntChPk');
    if(r)r.textContent='↓ '+human(hRx[hRx.length-1]||0)+'/s';if(t)t.textContent='↑ '+human(hTx[hTx.length-1]||0)+'/s';
    if(pk)pk.textContent='peak '+human(mx)+'/s';
  }
  function apply(L){
    document.getElementById('kRxRate').textContent=human(L.rate.rx)+'/s';
    document.getElementById('kTxRate').textContent=human(L.rate.tx)+'/s';
    document.getElementById('kRxTot').textContent=human(L.boot.rx);
    document.getElementById('kTxTot').textContent=human(L.boot.tx);
    if(L.conns){var e=function(id,v){var x=document.getElementById(id);if(x)x.textContent=(v||0).toLocaleString();};e('cEstab',L.conns.estab);e('cTotal',L.conns.total);e('cTw',L.conns.tw);}
    hRx.push(L.rate.rx);hTx.push(L.rate.tx);if(hRx.length>60){hRx.shift();hTx.shift();}chart();
    var tb=document.getElementById('ntIf');
    (L.ifaces||[]).forEach(function(n){var r=tb.querySelector('[data-if="'+CSS.escape(n.name)+'"]');
      if(!r){r=document.createElement('tr');r.setAttribute('data-if',n.name);r.innerHTML='<td class="mono">'+n.name+'</td><td class="num rx"></td><td class="num tx"></td><td class="num meta rxt"></td><td class="num meta txt"></td>';tb.appendChild(r);}
      r.querySelector('.rx').textContent=human(n.rx)+'/s';r.querySelector('.tx').textContent=human(n.tx)+'/s';r.querySelector('.rxt').textContent=human(n.rx_total);r.querySelector('.txt').textContent=human(n.tx_total);});
  }
  function tick(){if(paused)return;fetch('index.cgi?page=network&live=1',{cache:'no-store'}).then(function(r){return r.json();}).then(function(j){if(j&&j.ok)apply(j.live);}).catch(function(){});}
  setInterval(tick,3000);
})();
</script>
<?php
smpro_layout_footer();
