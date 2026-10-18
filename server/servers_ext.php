<?php
/**
 * servers_ext.php — "Servers / Installations" admin tab.
 * TABLE of physical servers (one ROW per server, grouped by bound_hostname+ip). Clicking a row opens the
 * full detail page: hardware facts, per-product licenses with remote actions (push/restart/revoke/reset/
 * full-stop/edit), security policy flags, and recent violations from license_logs.
 * Reuses panel helpers: db(), h(), csrf_token(), require_admin(), require_csrf(), redirect(), layout_start/end().
 */
if (!function_exists('db')) return;

function srv_route(string $path): bool {
    $m = $_SERVER['REQUEST_METHOD'] ?? 'GET';
    if ($path === '/servers' && $m === 'GET')            { srv_page(); return true; }
    if ($path === '/servers/view' && $m === 'GET')       { srv_view_page(); return true; }
    if ($path === '/servers/cmd' && $m === 'POST')       { srv_cmd(); return true; }
    if ($path === '/servers/cmd-status' && $m === 'GET') { srv_cmd_status(); return true; }
    return false;
}

/** Live status of a queued command (for the push progress bar). */
function srv_cmd_status(): void {
    require_admin();
    header('Content-Type: application/json');
    $id = (int)($_GET['id'] ?? 0);
    if ($id <= 0) { echo json_encode(['ok' => false]); exit; }
    $r = null;
    if ($q = db()->prepare("SELECT command, status, result, sent_at, done_at FROM license_commands WHERE id=? LIMIT 1")) {
        $q->bind_param('i', $id); $q->execute(); $r = $q->get_result()->fetch_assoc();
    }
    if (!$r) { echo json_encode(['ok' => true, 'status' => 'gone']); exit; }
    echo json_encode(['ok' => true, 'command' => $r['command'], 'status' => $r['status'], 'result' => (string)$r['result']]);
    exit;
}

function srv_human_uptime($s) { $s = (int)$s; if ($s <= 0) return '—'; $d = floor($s / 86400); $h = floor(($s % 86400) / 3600); return $d > 0 ? ($d . 'd ' . $h . 'h') : ($h . 'h'); }
function srv_ago($dt) { if (!$dt) return '—'; $ts = strtotime($dt); if (!$ts) return h($dt); $s = time() - $ts; if ($s < 60) return $s . 's ago'; if ($s < 3600) return floor($s / 60) . 'm ago'; if ($s < 86400) return floor($s / 3600) . 'h ago'; return floor($s / 86400) . 'd ago'; }

function srv_cmd(): void {
    require_admin(); require_csrf();
    $ajax = ($_POST['ajax'] ?? '') === '1';
    $key  = trim((string)($_POST['license_key'] ?? ''));
    $cmd  = (string)($_POST['cmd'] ?? '');
    $id   = 0;
    if ($key !== '' && in_array($cmd, ['update', 'restart', 'revoke', 'reset', 'disable', 'enable'], true)) {
        $args = $cmd === 'update' ? preg_replace('/[^0-9.]/', '', (string)($_POST['args'] ?? '')) : '';
        // supersede any earlier pending command of the same type
        if ($c = db()->prepare("DELETE FROM license_commands WHERE license_key=? AND command=? AND status='pending'")) {
            $c->bind_param('ss', $key, $cmd); $c->execute();
        }
        if ($st = db()->prepare("INSERT INTO license_commands (license_key, command, args, status) VALUES (?,?,?, 'pending')")) {
            $st->bind_param('sss', $key, $cmd, $args); $st->execute(); $id = (int)db()->insert_id;
        }
        if ($cmd === 'revoke') {
            if ($u = db()->prepare("UPDATE licenses SET status='suspended', updated_at=NOW() WHERE license_key=?")) { $u->bind_param('s', $key); $u->execute(); }
            if ($d = db()->prepare("DELETE FROM license_telemetry WHERE license_key=?")) { $d->bind_param('s', $key); $d->execute(); }
        }
        // RESET: admin investigated a flag — re-activate, clear TAMPER notes, cancel destructive sync flags.
        if ($cmd === 'reset') {
            if ($u = db()->prepare("UPDATE licenses SET status='active', directive='normal', sync_purge=0, notes=TRIM(CONCAT_WS(' ', COALESCE(NULLIF(notes,''),''), ?)), updated_at=NOW() WHERE license_key=?")) {
                $note = '[reset ' . date('Y-m-d H:i') . ']'; $u->bind_param('ss', $note, $key); $u->execute();
            }
        }
        if (function_exists('log_event')) log_event($key, $cmd === 'revoke' ? 'revoke' : 'queue_command', 'ok', $cmd . ($args !== '' ? ' ' . $args : ''), []);
    // ── per-license security policy flags (written to the licenses row, delivered SIGNED on next /api/check)
    } elseif ($key !== '' && in_array($cmd, ['sync_on', 'sync_off', 'purge_on', 'purge_off', 'permstop', 'hold', 'normal'], true)) {
        $map = [
            'sync_on'   => "UPDATE licenses SET sync_enabled=1 WHERE license_key=?",
            'sync_off'  => "UPDATE licenses SET sync_enabled=0, sync_purge=0 WHERE license_key=?",
            'purge_on'  => "UPDATE licenses SET sync_purge=1, sync_enabled=1 WHERE license_key=?",
            'purge_off' => "UPDATE licenses SET sync_purge=0 WHERE license_key=?",
            'permstop'  => "UPDATE licenses SET directive='permstop' WHERE license_key=?",
            'hold'      => "UPDATE licenses SET directive='hold' WHERE license_key=?",
            'normal'    => "UPDATE licenses SET directive='normal' WHERE license_key=?",
        ];
        if ($u = db()->prepare($map[$cmd])) { $u->bind_param('s', $key); $u->execute(); $id = 1; }
        if (function_exists('log_event')) log_event($key, 'policy', $cmd, 'security policy: ' . $cmd, []);
    // ── PAIR controls (Stage 3) — all REVERSIBLE/non-destructive
    } elseif ($key !== '' && in_array($cmd, ['pair_resume', 'pair_enforce_on', 'pair_enforce_off', 'pair_rotate'], true)) {
        if ($cmd === 'pair_resume') {
            if ($u = db()->prepare("UPDATE licenses SET pair_flagged=0 WHERE license_key=?")) { $u->bind_param('s', $key); $u->execute(); }
            if (function_exists('log_event')) log_event($key, 'pair', 'pair_resume', 'operator cleared pairing flag (reviewed)', []);
        } elseif ($cmd === 'pair_enforce_on') {
            if ($u = db()->prepare("UPDATE licenses SET pair_enforce=1 WHERE license_key=?")) { $u->bind_param('s', $key); $u->execute(); }
            if (function_exists('log_event')) log_event($key, 'pair', 'enforce_on', 'pairing enforcement enabled (reversible stop)', []);
        } elseif ($cmd === 'pair_enforce_off') {
            if ($u = db()->prepare("UPDATE licenses SET pair_enforce=0, pair_flagged=0 WHERE license_key=?")) { $u->bind_param('s', $key); $u->execute(); }
            if (function_exists('log_event')) log_event($key, 'pair', 'enforce_off', 'pairing enforcement disabled (back to report-only)', []);
        } elseif ($cmd === 'pair_rotate') {
            $news = bin2hex(random_bytes(32));
            if ($u = db()->prepare("UPDATE licenses SET pair_secret=?, pair_flagged=0 WHERE license_key=?")) { $u->bind_param('ss', $news, $key); $u->execute(); }
            if (function_exists('log_event')) log_event($key, 'pair', 'rotated', 'base secret rotated (invalidates any extracted key; forces re-pair)', []);
        }
        $id = 1;
    }
    if ($ajax) { header('Content-Type: application/json'); echo json_encode(['ok' => $id > 0, 'id' => $id, 'cmd' => $cmd]); exit; }
    redirect('/servers');
}

/** Group key = the physical server. Bound host+ip is shared by every product on a box;
 *  unbound licenses fall back to their own key so each still gets a row. */
function srv_group_key(array $r): string {
    $host = strtolower(trim((string)($r['bound_hostname'] ?: $r['hostname'] ?: '')));
    $ip   = strtolower(trim((string)($r['bound_ip'] ?: $r['server_ip'] ?: '')));
    if ($host !== '' || $ip !== '') return 'hi:' . $host . '|' . $ip;
    $mac = strtolower(trim((string)($r['mac'] ?? '')));
    if ($mac !== '') return 'mac:' . $mac;
    return 'lk:' . (string)$r['license_key'];
}

/** Available smpro release versions (newest first) for the per-server "push version" picker. */
function srv_versions(): array {
    $out = [];
    foreach (glob('/opt/aitech-license-server/releases/smpro-*.tar.gz') ?: [] as $f)
        if (preg_match('/smpro-([0-9][0-9.]*)\.tar\.gz$/', basename($f), $m)) $out[$m[1]] = 1;
    $out = array_keys($out);
    usort($out, fn($a, $b) => version_compare($b, $a));
    return $out;
}

/** Recent VIOLATIONS (tamper / clone / silent / binding / ip_rebind / revoke) per license_key, newest first. */
function srv_violations_map(array $keys): array {
    $keys = array_values(array_unique(array_filter(array_map('strval', $keys))));
    if (!$keys) return [];
    $in  = implode(',', array_fill(0, count($keys), '?'));
    $sql = "SELECT license_key, result, message, created_at, server_ip FROM license_logs
            WHERE license_key IN ($in)
              AND result IN ('env_tamper','clone_suspected','silent','binding_mismatch','tampered','ip_rebind','revoke')
            ORDER BY created_at DESC LIMIT 400";
    $out = [];
    try {
        $st = db()->prepare($sql); if (!$st) return [];
        $st->bind_param(str_repeat('s', count($keys)), ...$keys);
        $st->execute(); $rs = $st->get_result();
        while ($r = $rs->fetch_assoc()) { $k = (string)$r['license_key']; if (count($out[$k] ?? []) >= 8) continue; $out[$k][] = $r; }
    } catch (\Throwable $e) {}
    return $out;
}

/* ═══════════════════════════════════════════════════════════════════════════
   LIST PAGE
   ═══════════════════════════════════════════════════════════════════════════ */
function srv_page(): void {
    require_admin();
    layout_start('Servers');

    $rows = [];
    if ($res = @db()->query(
        "SELECT l.id, l.license_key, l.client_name, l.status, l.plan, l.bound_ip, l.bound_hostname,
                l.bound_fingerprint, l.expires_at, l.last_check_at, l.plugin_enabled, l.sync_enabled,
                l.sync_purge, l.directive,
                t.hostname, t.server_ip, t.mac, t.os, t.panel, t.cpu_cores, t.ram_mb,
                t.uptime_sec, t.load1, t.load15, t.version, t.accounts, t.reported_at
         FROM licenses l LEFT JOIN license_telemetry t ON t.license_key = l.license_key
         WHERE l.status <> 'suspended'
         ORDER BY (t.reported_at IS NULL), t.reported_at DESC LIMIT 500"
    )) { while ($r = $res->fetch_assoc()) $rows[] = $r; }

    $pending = [];
    if ($pc = @db()->query("SELECT license_key, command FROM license_commands WHERE status='pending'"))
        while ($p = $pc->fetch_assoc()) $pending[$p['license_key']][] = $p['command'];

    $groups = [];
    foreach ($rows as $r) $groups[srv_group_key($r)][] = $r;

    $serverCount  = count($groups);
    $licenseCount = count($rows);
    $online = 0; $totalUsers = 0;
    foreach ($groups as $g) {
        $fresh = false; $gu = 0;
        foreach ($g as $r) {
            if (!empty($r['reported_at']) && (time() - strtotime($r['reported_at'])) < 1800) $fresh = true;
            $gu = max($gu, (int)($r['accounts'] ?? 0));
        }
        if ($fresh) $online++;
        $totalUsers += $gu;
    }
    $viol = srv_violations_map(array_map(fn($r) => (string)$r['license_key'], $rows));

    // ── Hero ─────────────────────────────────────────────────────────────────
    echo '<section class="hero"><div>'
       . '<h1>&#128421; Servers &amp; Installations</h1>'
       . '<p>Monitor and manage all registered plugin installations. Click any row for full details and remote actions.</p>'
       . '</div></section>';

    // ── KPI Cards ─────────────────────────────────────────────────────────────
    echo '<div class="srv-kpi">'
       . '<div class="srv-kc"><div class="srv-kn">' . $serverCount . '</div><div class="srv-kl">Servers</div></div>'
       . '<div class="srv-kc"><div class="srv-kn">' . $licenseCount . '</div><div class="srv-kl">Product licenses</div></div>'
       . '<div class="srv-kc"><div class="srv-kn srv-kn-gr">' . $online . '</div><div class="srv-kl">Online <small>&lt;30m</small></div></div>'
       . '<div class="srv-kc"><div class="srv-kn">' . number_format($totalUsers) . '</div><div class="srv-kl">Hosting accounts</div></div>'
       . '</div>';

    if (!$rows) {
        echo '<div class="card" style="text-align:center;padding:48px 20px;color:#94a3b8">'
           . '<div style="font-size:40px;margin-bottom:14px;opacity:.35">&#128421;</div>'
           . '<p style="font-size:15px;margin:0">No active licenses yet.</p></div>';
        echo srv_css();
        layout_end();
        return;
    }

    // ── Filter toolbar ────────────────────────────────────────────────────────
    echo '<div class="srv-toolbar">'
       . '<div class="srv-search-wrap">'
       .   '<span class="srv-search-icon">&#128269;</span>'
       .   '<input id="srvFilter" class="srv-search" placeholder="Filter by host, IP or client…" oninput="srvApplyFilter()">'
       . '</div>'
       . '<div class="srv-chips">'
       .   '<button type="button" class="srv-chip on" data-st="all" onclick="srvChip(this)">All</button>'
       .   '<button type="button" class="srv-chip" data-st="online" onclick="srvChip(this)"><span class="srv-chip-dot" style="background:#16a34a"></span>Online</button>'
       .   '<button type="button" class="srv-chip" data-st="idle" onclick="srvChip(this)"><span class="srv-chip-dot" style="background:#d97706"></span>Idle</button>'
       .   '<button type="button" class="srv-chip" data-st="offline" onclick="srvChip(this)"><span class="srv-chip-dot" style="background:#94a3b8"></span>Offline</button>'
       . '</div>'
       . '</div>';

    // ── Server cards ──────────────────────────────────────────────────────────
    echo '<div class="srv-cards" id="srvCards">';

    foreach ($groups as $gid => $g) {
        $info = $g[0];
        foreach ($g as $r)
            if (!empty($r['reported_at']) && (empty($info['reported_at']) || strtotime($r['reported_at']) > strtotime($info['reported_at'])))
                $info = $r;

        $host     = (string)($info['hostname'] ?: $info['bound_hostname'] ?: '—');
        $ip       = (string)($info['bound_ip'] ?: $info['server_ip'] ?: '');
        $reported = !empty($info['reported_at']);
        $age      = $reported ? (time() - strtotime($info['reported_at'])) : PHP_INT_MAX;
        if (!$reported || $age >= 86400) { $sst = 'offline'; $slabel = 'Offline'; $sdot = '#94a3b8'; $spill = 'srv-pill-offline'; $pulse = ''; }
        elseif ($age < 1800)             { $sst = 'online';  $slabel = 'Online';  $sdot = '#16a34a'; $spill = 'srv-pill-online';  $pulse = ' srv-pdot-pulse'; }
        else                             { $sst = 'idle';    $slabel = 'Idle';    $sdot = '#d97706'; $spill = 'srv-pill-idle';    $pulse = ''; }

        $users   = 0; foreach ($g as $r) $users = max($users, (int)($r['accounts'] ?? 0));
        $clients = implode(', ', array_values(array_unique(array_filter(array_map(fn($r) => (string)$r['client_name'], $g))))) ?: '—';
        $vers    = implode(' / ', array_values(array_unique(array_filter(array_map(fn($r) => (string)$r['version'], $g)))));
        $gv      = []; foreach ($g as $r) foreach (($viol[(string)$r['license_key']] ?? []) as $v) $gv[] = $v;
        $vcount  = count($gv);
        $ago     = srv_ago($info['reported_at'] ?: ($info['last_check_at'] ?? null));
        $search  = strtolower($host . ' ' . $ip . ' ' . $clients);

        echo '<div class="srv-card is-' . $sst . '" data-st="' . $sst . '" data-search="' . h($search) . '" onclick="location.href=\'/servers/view?id=' . (int)$g[0]['id'] . '\'">'
           . '<div class="srv-card-head">'
           .   '<div class="srv-pill ' . $spill . '"><span class="srv-pdot' . $pulse . '" style="background:' . $sdot . '"></span>' . $slabel . '</div>'
           .   '<span class="srv-card-spacer"></span>'
           .   ($vcount ? '<span class="srv-vbadge">&#9888; ' . $vcount . '</span>' : '')
           .   '<span class="srv-card-ago ' . $sst . '">' . h($ago) . '</span>'
           . '</div>'
           . '<div class="srv-card-hostname" title="' . h($host) . '">' . h($host) . '</div>'
           . '<div class="srv-card-ip">' . ($ip !== '' ? h($ip) : '&nbsp;') . '</div>'
           . '<div class="srv-card-client" title="' . h($clients) . '"><span class="srv-card-cico">&#128100;</span><span class="srv-card-ctxt">' . h($clients) . '</span></div>'
           . '<div class="srv-card-stats">'
           .   '<div class="srv-card-stat"><b>' . count($g) . '</b><span>Products</span></div>'
           .   '<div class="srv-card-stat"><b>' . ($users ? number_format($users) : '—') . '</b><span>Accounts</span></div>'
           .   '<div class="srv-card-stat"><b class="srv-card-verv" title="' . h($vers ?: '—') . '">' . ($vers !== '' ? h($vers) : '—') . '</b><span>Version</span></div>'
           . '</div>'
           . '<div class="srv-card-go">View details &#8594;</div>'
           . '</div>';
    }

    echo '</div>'
       . '<div id="srvEmpty" class="srv-empty" style="display:none">'
       .   '<div class="srv-empty-ico">&#128269;</div>'
       .   '<p>No servers match your filter.</p>'
       . '</div>';

    echo srv_css();
    echo '<script>(function(){'
       . 'var st="all";'
       . 'window.srvChip=function(b){st=b.getAttribute("data-st");document.querySelectorAll(".srv-chip").forEach(function(c){c.classList.toggle("on",c===b)});srvApplyFilter()};'
       . 'window.srvApplyFilter=function(){'
       .   'var q=(document.getElementById("srvFilter").value||"").toLowerCase().trim();var n=0;'
       .   'document.querySelectorAll("#srvCards .srv-card").forEach(function(r){'
       .     'var ok=(st==="all"||r.getAttribute("data-st")===st)&&(!q||(r.getAttribute("data-search")||"").indexOf(q)>=0);'
       .     'r.style.display=ok?"":"none";if(ok)n++'
       .   '});'
       .   'var e=document.getElementById("srvEmpty");if(e)e.style.display=n?"none":""'
       . '};'
       . '})();</script>';
    echo '<p class="srv-footer-note">Telemetry reported by plugin v1.0.96+. Click any server row for full details, remote actions, and security controls.</p>';
    layout_end();
}

/* ═══════════════════════════════════════════════════════════════════════════
   SHARED CSS  (list page + detail page)
   ═══════════════════════════════════════════════════════════════════════════ */
function srv_css(): string {
    return '<style>'
       /* KPI strip */
       . '.srv-kpi{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:18px}'
       . '.srv-kc{background:#fff;border:1px solid #e2e8f0;border-radius:14px;padding:16px 18px;text-align:center}'
       . '.srv-kn{font-size:26px;font-weight:800;color:#0f172a;font-variant-numeric:tabular-nums;line-height:1.1}'
       . '.srv-kn-gr{color:#15803d}'
       . '.srv-kl{font-size:11px;color:#94a3b8;margin-top:4px;font-weight:600;letter-spacing:.03em;text-transform:uppercase}'
       . '.srv-kl small{font-size:10px;text-transform:none;letter-spacing:0;opacity:.8}'
       /* Toolbar */
       . '.srv-toolbar{display:flex;gap:8px;align-items:center;margin-bottom:14px;flex-wrap:wrap}'
       . '.srv-search-wrap{position:relative;flex:1;min-width:200px}'
       . '.srv-search-icon{position:absolute;left:11px;top:50%;transform:translateY(-50%);color:#94a3b8;pointer-events:none;font-size:14px;line-height:1}'
       . '.srv-search{width:100%;padding:9px 12px 9px 34px;border:1px solid #e2e8f0;border-radius:10px;font-size:13px;background:#fff;color:#0f172a;outline:none;transition:border-color .15s,box-shadow .15s}'
       . '.srv-search:focus{border-color:#3b5bdb;box-shadow:0 0 0 3px rgba(59,91,219,.1)}'
       . '.srv-chips{display:flex;gap:5px;flex-wrap:wrap}'
       . '.srv-chip{background:#f1f5f9;border:0;color:#64748b;border-radius:8px;padding:7px 14px;font-size:12px;font-weight:600;cursor:pointer;display:inline-flex;align-items:center;gap:6px;transition:all .12s}'
       . '.srv-chip:hover{background:#e2e8f0;color:#1e293b}'
       . '.srv-chip.on{background:#0f172a;color:#fff}'
       . '.srv-chip-dot{width:7px;height:7px;border-radius:50%;flex-shrink:0}'
       /* Status pill */
       . '.srv-pill{display:inline-flex;align-items:center;gap:6px;border-radius:999px;padding:4px 10px 4px 7px;font-size:11.5px;font-weight:700;white-space:nowrap}'
       . '.srv-pill-online{background:#dcfce7;color:#15803d}'
       . '.srv-pill-idle{background:#fef3c7;color:#b45309}'
       . '.srv-pill-offline{background:#f1f5f9;color:#64748b}'
       . '.srv-pdot{width:7px;height:7px;border-radius:50%;flex-shrink:0}'
       . '@keyframes srvpulse{0%,100%{opacity:1}50%{opacity:.35}}.srv-pdot-pulse{animation:srvpulse 2s ease-in-out infinite}'
       /* Cells */
       . '.srv-host-name{font-weight:700;color:#0f172a;font-size:13px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}'
       . '.srv-host-ip{font-size:11.5px;color:#94a3b8;font-family:monospace;margin-top:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}'
       . '.srv-col-client{color:#475569;font-size:12.5px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}'
       . '.srv-prod-badge{display:inline-block;background:#eef2ff;color:#3b5bdb;border-radius:6px;padding:2px 9px;font-size:12.5px;font-weight:700}'
       . '.srv-ver-badge{display:inline-block;background:#f1f5f9;color:#475569;border-radius:6px;padding:2px 7px;font-size:12px;font-family:monospace;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;vertical-align:middle}'
       . '.srv-dim{color:#cbd5e1;font-size:12px}'
       . '.srv-ago-cell{color:#64748b;font-size:12.5px}'
       . '.srv-ago-cell.online{color:#16a34a;font-weight:600}'
       . '.srv-ago-cell.idle{color:#b45309}'
       . '.srv-row-act{text-align:right;white-space:nowrap}'
       . '.srv-vbadge{display:inline-flex;align-items:center;gap:3px;font-size:11px;font-weight:700;color:#b91c1c;background:#fef2f2;border:1px solid #fecaca;border-radius:999px;padding:2px 8px;margin-right:5px}'
       . '.srv-caret{color:#d1d8e4;font-size:12px;transition:color .12s}'
       . '.srv-row:hover .srv-caret{color:#3b5bdb}'
       /* Empty / footer */
       . '.srv-empty{text-align:center;padding:48px 20px;color:#94a3b8}'
       . '.srv-empty-ico{font-size:36px;margin-bottom:12px;opacity:.3}'
       . '.srv-empty p{font-size:13.5px;margin:0}'
       . '.srv-footer-note{color:#94a3b8;font-size:12px;margin-top:10px}'
       /* Detail: back */
       . '.srv-back{margin:0 0 14px}'
       . '.srv-back a{color:#64748b;text-decoration:none;font-size:13px;font-weight:600;display:inline-flex;align-items:center;gap:5px}'
       . '.srv-back a:hover{color:#3b5bdb}'
       /* Detail: hero */
       . '.srv-server-hero{position:relative;background:linear-gradient(135deg,#ffffff,#f7f9fc);border:1px solid #e2e8f0;border-radius:16px;padding:20px 24px 20px 28px;display:flex;align-items:center;gap:16px;margin-bottom:16px;box-shadow:0 1px 3px rgba(15,23,42,.04),0 14px 30px rgba(15,23,42,.05);overflow:hidden}'
       . '.srv-server-hero:before{content:"";position:absolute;left:0;top:0;bottom:0;width:5px;background:var(--srv-accent,#22c55e)}'
       . '.srv-server-hero-dot{width:12px;height:12px;border-radius:50%;flex-shrink:0;box-shadow:0 0 0 4px rgba(148,163,184,.18)}'
       . '.srv-server-hero-main{flex:1;min-width:0}'
       . '.srv-server-hero-main h2{margin:0;font-size:21px;font-weight:800;color:#0f172a;letter-spacing:-.01em}'
       . '.srv-server-hero-meta{display:flex;align-items:center;gap:8px;margin-top:5px;flex-wrap:wrap;font-size:12.5px;color:#64748b}'
       . '.srv-server-hero-meta code{font-size:12px;background:#f1f5f9;padding:1px 6px;border-radius:5px;color:#475569}'
       . '.srv-server-hero-sep{color:#d1d8e4}'
       . '.srv-server-hero-ago{font-size:13px;color:#94a3b8;white-space:nowrap;flex-shrink:0}'
       /* Detail: hardware grid */
       . '.srv-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(132px,1fr));gap:10px}'
       . '.srv-f{background:#f8fafc;border:1px solid #eef2f7;border-radius:12px;padding:12px 14px;transition:border-color .15s,background .15s,transform .15s}'
       . '.srv-f:hover{background:#fff;border-color:#dbe3ee;transform:translateY(-1px)}'
       . '.srv-f span{display:block;font-size:9.5px;text-transform:uppercase;letter-spacing:.07em;color:#94a3b8;font-weight:800}'
       . '.srv-f b{font-size:14px;color:#0f172a;display:block;margin-top:5px;font-weight:800;line-height:1.35}'
       /* Detail: product cards */
       . '.srv-prods{display:flex;flex-direction:column;gap:12px}'
       . '.srv-prod{position:relative;border:1px solid #e2e8f0;border-radius:14px;padding:16px 18px 16px 22px;background:#fff;transition:box-shadow .16s,border-color .16s;overflow:hidden}'
       . '.srv-prod:hover{box-shadow:0 4px 18px rgba(15,23,42,.07);border-color:#dbe3ee}'
       . '.srv-prod:before{content:"";position:absolute;left:0;top:0;bottom:0;width:4px;background:var(--p-accent,#94a3b8)}'
       . '.srv-prod-top{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:10px}'
       . '.srv-prod-top b{font-size:14px;color:#0f172a;font-weight:800}'
       . '.srv-tag{font-size:11px;color:#64748b;background:#f1f5f9;border-radius:7px;padding:3px 8px;font-weight:600}'
       . '.srv-prod-key{font-size:11.5px;color:#94a3b8;margin-bottom:12px;font-family:ui-monospace,Menlo,Consolas,monospace}'
       . '.srv-prod-act{display:flex;gap:6px;flex-wrap:wrap;align-items:center}'
       . '.srv-prod-act button,.srv-prod-act .btn{font-size:12px;padding:6px 12px;border-radius:9px;border:1px solid #e2e8f0;background:#fff;cursor:pointer;text-decoration:none;color:#475569;font-weight:600;transition:all .13s;display:inline-flex;align-items:center;gap:5px;width:auto}'
       . '.srv-prod-act button:hover{background:#f8fafc;border-color:#cbd5e1;color:#1e293b;transform:translateY(-1px)}'
       . '.srv-prod-act button.danger{border-color:#fecaca;background:#fff;color:#dc2626}'
       . '.srv-prod-act button.danger:hover{background:#fef2f2;border-color:#f87171}'
       . '.srv-prod-act .btn{background:#3b5bdb;color:#fff;border-color:#3b5bdb;box-shadow:0 1px 4px rgba(59,91,219,.28)}'
       . '.srv-prod-act .btn:hover{background:#2f49b0!important;border-color:#2f49b0;transform:translateY(-1px)}'
       /* Detail: security policy */
       . '.srv-pol{margin-top:10px;padding-top:10px;border-top:1px solid #f1f5f9;display:flex;align-items:flex-start;gap:7px;flex-wrap:wrap}'
       . '.srv-pol-h{color:#94a3b8;font-weight:800;font-size:11px;text-transform:uppercase;letter-spacing:.04em;padding:5px 0;white-space:nowrap}'
       . '.srv-pol-dir{display:flex;align-items:center;gap:4px;flex-wrap:wrap}'
       . '.srv-pol .pol{font-size:11.5px;padding:4px 9px;border-radius:7px;border:1px solid #e2e8f0;background:#f8fafc;cursor:pointer;color:#475569;font-weight:600;transition:all .12s}'
       . '.srv-pol .pol:hover{background:#fff;border-color:#cbd5e1;color:#1e293b}'
       . '.srv-pol .pol.on{background:#eef2ff;border-color:#3b5bdb;color:#3b5bdb;font-weight:700}'
       . '.srv-pol .pol.danger{border-color:#fecaca;background:#fff5f5;color:#b91c1c}'
       . '.srv-pol .pol.danger.on{background:#fef2f2;border-color:#dc2626;color:#dc2626}'
       . '.srv-pol .pol.mini{padding:3px 7px;font-size:11px}'
       /* Detail: violations */
       . '.srv-vrow{display:flex;gap:12px;font-size:12px;padding:9px 12px;border-radius:10px;margin-bottom:6px;border:1px solid #f1f5f9;background:#fff;transition:background .12s}'
       . '.srv-vrow:hover{background:#fafbfc}'
       . '.srv-vrow.crit{border-left:3px solid #dc2626;background:#fff7f7}'
       . '.srv-vrow.warn{border-left:3px solid #d97706;background:#fffcf5}'
       . '.srv-vrow.info{border-left:3px solid #e2e8f0}'
       . '.srv-vt{color:#94a3b8;white-space:nowrap;font-variant-numeric:tabular-nums;min-width:112px;font-weight:600}'
       . '.srv-vk{font-weight:800;color:#0f172a;white-space:nowrap}'
       . '.srv-vm{color:#64748b;overflow:hidden;text-overflow:ellipsis}'
       /* Push progress */
       . '.srv-prog{margin-top:8px;border:1px solid #e2e8f0;border-radius:9px;padding:9px 12px;background:#f8fafc}'
       . '.srv-prog .sp-row{display:flex;align-items:center;gap:8px;font-size:12.5px;font-weight:700}'
       . '.srv-prog .sp-bar{height:5px;border-radius:4px;background:#e2e8f0;overflow:hidden;margin-top:7px}'
       . '.srv-prog .sp-fill{height:100%;width:0;border-radius:4px;background:#3b5bdb;transition:width .5s ease}'
       . '.srv-prog.ok .sp-fill{background:#16a34a}.srv-prog.fail .sp-fill{background:#dc2626}'
       . '.srv-prog .sp-sub{font-size:11px;color:#94a3b8;margin-top:5px}'
       . '.srv-prog .sp-spin{width:12px;height:12px;border:2px solid #e2e8f0;border-top-color:#3b5bdb;border-radius:50%;animation:spspin .8s linear infinite;flex-shrink:0}'
       . '@keyframes spspin{to{transform:rotate(360deg)}}'
       /* Server cards (list page) */
       . '.srv-cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:14px}'
       . '.srv-card{position:relative;background:#fff;border:1px solid #e2e8f0;border-radius:16px;padding:15px 17px 14px;cursor:pointer;overflow:hidden;transition:box-shadow .15s,border-color .15s,transform .1s}'
       . '.srv-card::before{content:"";position:absolute;left:0;top:0;bottom:0;width:4px;background:#cbd5e1}'
       . '.srv-card.is-online::before{background:#16a34a}'
       . '.srv-card.is-idle::before{background:#d97706}'
       . '.srv-card.is-offline::before{background:#cbd5e1}'
       . '.srv-card:hover{border-color:#cbd5e1;box-shadow:0 10px 26px rgba(15,23,42,.09);transform:translateY(-2px)}'
       . '.srv-card-head{display:flex;align-items:center;gap:8px;margin-bottom:11px}'
       . '.srv-card-spacer{flex:1}'
       . '.srv-card-ago{font-size:12px;color:#94a3b8;white-space:nowrap;font-weight:600}'
       . '.srv-card-ago.online{color:#16a34a}.srv-card-ago.idle{color:#b45309}'
       . '.srv-card-hostname{font-weight:800;font-size:15.5px;color:#0f172a;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;line-height:1.25}'
       . '.srv-card-ip{font-size:12px;color:#94a3b8;font-family:monospace;margin-top:2px;min-height:16px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}'
       . '.srv-card-client{display:flex;align-items:center;gap:6px;margin:11px 0 13px;font-size:12.5px;color:#475569;min-width:0}'
       . '.srv-card-cico{flex-shrink:0;opacity:.55;font-size:12px}'
       . '.srv-card-ctxt{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}'
       . '.srv-card-stats{display:grid;grid-template-columns:repeat(3,1fr);gap:8px}'
       . '.srv-card-stat{background:#f8fafc;border:1px solid #f1f5f9;border-radius:10px;padding:9px 8px;text-align:center;min-width:0}'
       . '.srv-card-stat b{display:block;font-size:16px;font-weight:800;color:#0f172a;font-variant-numeric:tabular-nums;line-height:1.15;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}'
       . '.srv-card-stat .srv-card-verv{font-size:12.5px;font-family:monospace;font-weight:700}'
       . '.srv-card-stat span{display:block;font-size:9px;text-transform:uppercase;letter-spacing:.05em;color:#94a3b8;font-weight:700;margin-top:4px}'
       . '.srv-card-go{margin-top:12px;font-size:12px;font-weight:700;color:#cbd5e1;text-align:right;transition:color .12s}'
       . '.srv-card:hover .srv-card-go{color:#3b5bdb}'
       /* Responsive */
       . '@media(max-width:900px){.srv-kpi{grid-template-columns:repeat(2,1fr)}}'
       . '@media(max-width:560px){.srv-cards{grid-template-columns:1fr}}'
       . '</style>';
}

/* ═══════════════════════════════════════════════════════════════════════════
   SHARED JS  (detail page: command actions + security-policy flags)
   ═══════════════════════════════════════════════════════════════════════════ */
function srv_js(): string {
    return '<script>var SRV_CSRF=' . json_encode(csrf_token()) . ';(function(){'
       . 'function setp(pid,pct,label,sub,cls,spin){var b=document.getElementById("prog_"+pid);if(!b)return;b.style.display="";b.className="srv-prog"+(cls?" "+cls:"");'
       . 'b.innerHTML=\'<div class="sp-row">\'+(spin?\'<span class="sp-spin"></span>\':(cls==="ok"?"✅ ":(cls==="fail"?"⚠ ":"")))+\'<span class="sp-label"></span></div><div class="sp-bar"><div class="sp-fill"></div></div><div class="sp-sub"></div>\';'
       . 'var lb=b.querySelector(".sp-label");if(lb)lb.textContent=label||"";'
       . 'var fl=b.querySelector(".sp-fill");if(fl)fl.style.width=(pct|0)+"%";'
       . 'var sb=b.querySelector(".sp-sub");if(sb){if(sub){sb.textContent=sub;}else{sb.style.display="none";}}}'
       . 'function poll(pid,id,tries,doneLabel){'
       . 'fetch("/servers/cmd-status?id="+id,{cache:"no-store"}).then(function(r){return r.json();}).then(function(j){'
       . 'var s=(j&&j.status)||"";'
       . 'if(s==="done"){setp(pid,100,doneLabel||"Done",(j.result||"Applied on the server."),"ok",false);return;}'
       . 'if(s==="failed"){setp(pid,100,"Failed",(j.result||"The server reported an error."),"fail",false);return;}'
       . 'if(s==="gone"){setp(pid,100,"Superseded","Replaced by a newer command.","",false);return;}'
       . 'if(s==="sent"){setp(pid,70,"Delivered — applying…","The server pulled the command and is applying it.","",true);}'
       . 'else{setp(pid,30,"Queued — waiting for the server","The server checks in every ~15 min; it runs then.",null,true);}'
       . 'if(tries>0)setTimeout(function(){poll(pid,id,tries-1,doneLabel);},5000);'
       . 'else setp(pid,s==="sent"?70:30,"Still working…","Taking longer than usual — it will finish on the next check-in.",null,true);'
       . '}).catch(function(){if(tries>0)setTimeout(function(){poll(pid,id,tries-1,doneLabel);},5000);});}'
       . 'function send(btn,cmd,ver,confirmMsg,sending,doneLabel,reloadOnOk){'
       . 'if(confirmMsg&&!confirm(confirmMsg))return;'
       . 'var pid=btn.getAttribute("data-pid");var form=btn.closest("form");'
       . 'btn.disabled=true;setp(pid,15,sending,"",null,true);'
       . 'var fd=new URLSearchParams();fd.set("csrf",SRV_CSRF);fd.set("ajax","1");fd.set("license_key",form.querySelector("input[name=license_key]").value);fd.set("cmd",cmd);fd.set("args",ver||"");'
       . 'fetch("/servers/cmd",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:fd.toString(),cache:"no-store"}).then(function(r){return r.json();}).then(function(j){'
       . 'btn.disabled=false;'
       . 'if(j&&j.ok){if(reloadOnOk){setp(pid,100,doneLabel,"","ok",false);setTimeout(function(){location.reload();},1500);}else if(j.id){setp(pid,30,"Queued — waiting for the server","The server checks in every ~15 min; it runs then.",null,true);poll(pid,j.id,60,doneLabel);}else{setp(pid,100,doneLabel,"","ok",false);}}'
       . 'else{setp(pid,100,"Could not queue the command","","fail",false);}'
       . '}).catch(function(){btn.disabled=false;setp(pid,100,"Request failed","","fail",false);});}'
       . 'document.querySelectorAll(".srv-push").forEach(function(btn){btn.addEventListener("click",function(){var sel=btn.closest("form").querySelector("select[name=args]");var ver=sel?sel.value:"";send(btn,"update",ver,"Push "+(ver?("version "+ver):"the latest version")+" to this server? It installs on the next check-in (~15 min).","Sending push…","Installed on the server",false);});});'
       . 'document.querySelectorAll(".srv-restart").forEach(function(btn){btn.addEventListener("click",function(){send(btn,"restart","","Restart (re-activate) this server\'s plugin on its next check-in?","Sending restart…","Restarted (re-registered)",false);});});'
       . 'document.querySelectorAll(".srv-revoke").forEach(function(btn){btn.addEventListener("click",function(){send(btn,"revoke","","Revoke this license? It is suspended immediately and the plugin locks on its next check-in.","Revoking…","Revoked — license suspended",true);});});'
       . 'document.querySelectorAll(".srv-reset").forEach(function(btn){btn.addEventListener("click",function(){send(btn,"reset","","Reset this license after investigating a tamper flag? It re-activates and cancels the auto-uninstall on next check-in.","Sending reset…","Reset — license re-activated",true);});});'
       . 'document.querySelectorAll(".srv-stop").forEach(function(btn){btn.addEventListener("click",function(){send(btn,"disable","","Force a FULL STOP of the plugin on this server? All functions stop on next check-in. Reversible with Restart/Reset.","Stopping…","Full stop queued",true);});});'
       . 'var POLMSG={purge_on:"Mark this license as SUSPECTED PIRATE? It will auto-DELETE after 48h of no connection. Only do this for a confirmed pirate — honest customers must NOT be flagged.",permstop:"OPERATOR-ORDERED DELETE: the plugin will remove itself the next time this box reaches the server. Continue?"};'
       . 'document.querySelectorAll(".srv-pol .pol").forEach(function(btn){btn.addEventListener("click",function(){'
       . 'var cmd=btn.getAttribute("data-cmd");var wrap=btn.closest(".srv-pol");var lk=wrap.querySelector("input[name=license_key]").value;'
       . 'if(POLMSG[cmd]&&!confirm(POLMSG[cmd]))return;'
       . 'btn.disabled=true;var fd=new URLSearchParams();fd.set("csrf",SRV_CSRF);fd.set("ajax","1");fd.set("license_key",lk);fd.set("cmd",cmd);'
       . 'fetch("/servers/cmd",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:fd.toString(),cache:"no-store"}).then(function(r){return r.json();}).then(function(j){location.reload();}).catch(function(){btn.disabled=false;alert("Request failed");});});});'
       . '})();</script>';
}

/* ═══════════════════════════════════════════════════════════════════════════
   PRODUCT CARD  (shared by the detail page)
   ═══════════════════════════════════════════════════════════════════════════ */
function srv_render_product(array $r, array $pending, string $verOpts): string {
    $key     = (string)$r['license_key'];
    $short   = substr($key, 0, 17) . '…' . substr($key, -4);
    $stcls   = $r['status'] === 'active' ? 'active' : ($r['status'] === 'suspended' ? 'suspended' : ($r['status'] === 'expired' ? 'expired' : ''));
    $paccent = $r['status'] === 'active' ? '#22c55e' : ($r['status'] === 'suspended' ? '#f59e0b' : ($r['status'] === 'expired' ? '#ef4444' : '#94a3b8'));
    $pend    = !empty($pending[$key]) ? '<span class="badge" style="background:#fdf6e7;color:#c47f17">queued: ' . h(implode(',', $pending[$key])) . '</span>' : '';
    $label   = $r['client_name'] ?: 'license';
    $peb     = (!isset($r['plugin_enabled']) || $r['plugin_enabled']) ? '<span class="badge active">plugin on</span>' : '<span class="badge suspended">plugin OFF</span>';
    $pid     = preg_replace('/[^A-Za-z0-9]/', '', $key);
    $syncOn  = (int)($r['sync_enabled'] ?? 0) === 1;
    $purgeOn = (int)($r['sync_purge'] ?? 0) === 1;
    $dir     = (string)($r['directive'] ?? 'normal');
    $pairEnf = (int)($r['pair_enforce'] ?? 0) === 1;

    $o  = '<div class="srv-prod" style="--p-accent:' . $paccent . '">';
    $o .= '<div class="srv-prod-top">'
        . '<span class="badge ' . $stcls . '">' . h($r['status']) . '</span>' . $peb
        . '<b>' . h($label) . '</b>'
        . ($r['plan']       ? '<span class="srv-tag">plan: ' . h($r['plan']) . '</span>' : '')
        . ($r['version']    ? '<span class="srv-tag">v' . h($r['version']) . '</span>' : '')
        . ($r['expires_at'] ? '<span class="srv-tag">exp ' . h(substr($r['expires_at'], 0, 10)) . '</span>' : '')
        . '</div>';
    $o .= '<div class="srv-prod-key"><code>' . h($short) . '</code>'
        . ($r['bound_fingerprint'] ? ' · fp ' . h(substr($r['bound_fingerprint'], 0, 12)) . '…' : '')
        . '</div>';
    $o .= '<form method="post" action="/servers/cmd" class="srv-prod-act" data-pid="' . $pid . '">'
        . '<input type="hidden" name="csrf" value="' . h(csrf_token()) . '">'
        . '<input type="hidden" name="license_key" value="' . h($key) . '">'
        . '<select name="args" style="padding:4px 6px;font-size:12px;border-radius:7px;border:1px solid #d8dee9;background:#fff" title="Version to push (blank = latest)">' . $verOpts . '</select>'
        . '<button type="button" class="srv-push" data-pid="' . $pid . '" title="Push the selected version (next check-in)">&#11014; Push</button>'
        . '<button type="button" class="srv-restart" data-pid="' . $pid . '" title="Force re-activation (next check-in)">&#8635; Restart</button>'
        . '<button type="button" class="srv-revoke danger" data-pid="' . $pid . '" title="Suspend this license">&#9940; Revoke</button>'
        . '<button type="button" class="srv-reset" data-pid="' . $pid . '" title="Clear a tamper/sync flag and resume">&#10227; Reset</button>'
        . '<button type="button" class="srv-stop danger" data-pid="' . $pid . '" title="Force a full stop (reversible)">&#9209; Full stop</button>'
        . '<a class="btn" href="/licenses/edit?id=' . (int)$r['id'] . '" style="background:#fff;color:#3b5bdb;border:1px solid #d8dee9">&#9998; Edit</a>'
        . '</form>'
        . '<div id="prog_' . $pid . '" class="srv-prog" style="display:none"></div>'
        . ($pend ? '<div style="margin-top:6px">' . $pend . '</div>' : '');

    $o .= '<div class="srv-pol" data-pid="' . $pid . '">'
        . '<span class="srv-pol-h">Security policy:</span>'
        . '<input type="hidden" name="license_key" value="' . h($key) . '">'
        . '<button type="button" class="pol ' . ($syncOn ? 'on' : '') . '" data-cmd="' . ($syncOn ? 'sync_off' : 'sync_on') . '" title="Opt into the connection-loss escalation ladder (1h/3h warn, 6h notify, 24h reversible stop)">'
        .   ($syncOn ? '&#9745;' : '&#9744;') . ' Escalation'
        . '</button>'
        . '<button type="button" class="pol danger ' . ($purgeOn ? 'on' : '') . '" data-cmd="' . ($purgeOn ? 'purge_off' : 'purge_on') . '" title="SUSPECTED PIRATE: allow auto-DELETE after 48h of silence (this license only)">'
        .   ($purgeOn ? '&#9888; Pirate-purge ON' : 'Mark suspected-pirate')
        . '</button>'
        . '<span class="srv-pol-dir">directive: '
        .   '<button type="button" class="pol mini ' . ($dir === 'normal' ? 'on' : '') . '" data-cmd="normal">normal</button>'
        .   '<button type="button" class="pol mini ' . ($dir === 'hold' ? 'on' : '') . '" data-cmd="hold" title="Freeze escalation during maintenance">hold</button>'
        .   '<button type="button" class="pol mini danger ' . ($dir === 'permstop' ? 'on' : '') . '" data-cmd="permstop" title="OPERATOR-ORDERED DELETE on next contact">permstop</button>'
        . '</span>'
        . '<button type="button" class="pol mini" data-cmd="pair_resume" title="Reviewed a pairing flag (e.g. a legit IP/host/MAC change) — clear it and re-pair">&#10227; Re-pair</button>'
        . '<button type="button" class="pol mini ' . ($pairEnf ? 'on' : '') . '" data-cmd="' . ($pairEnf ? 'pair_enforce_off' : 'pair_enforce_on') . '" title="Opt into the REVERSIBLE pairing stop (default off = report-only).">'
        .   ($pairEnf ? '&#9745;' : '&#9744;') . ' Pair-enforce'
        . '</button>'
        . '<button type="button" class="pol mini danger" data-cmd="pair_rotate" title="Rotate the per-license base secret — invalidates any extracted pairing key and forces a clean re-pair.">&#8635; Rotate secret</button>'
        . '</div>';

    if (function_exists('smlic_protection_block')) $o .= smlic_protection_block($r);
    $o .= '</div>';
    return $o;
}

/* ═══════════════════════════════════════════════════════════════════════════
   DETAIL PAGE
   ═══════════════════════════════════════════════════════════════════════════ */
function srv_view_page(): void {
    require_admin();
    // SECURITY: address servers by internal numeric id — keys must not appear in URLs/logs/Referer.
    $id = (int)($_GET['id'] ?? 0);
    if ($id <= 0) { redirect('/servers'); }

    $rows = [];
    if ($res = @db()->query(
        "SELECT l.id, l.license_key, l.client_name, l.status, l.plan, l.bound_ip, l.bound_hostname,
                l.bound_fingerprint, l.expires_at, l.last_check_at, l.plugin_enabled, l.sync_enabled,
                l.sync_purge, l.directive, l.pin_version, l.tamper_status, l.last_heartbeat_at,
                l.last_action_at, l.pair_secret, l.pair_enforce, l.pair_flagged,
                t.hostname, t.server_ip, t.mac, t.os, t.panel, t.cpu_cores, t.ram_mb,
                t.uptime_sec, t.load1, t.load15, t.version, t.accounts, t.reported_at
         FROM licenses l LEFT JOIN license_telemetry t ON t.license_key = l.license_key
         WHERE l.status <> 'suspended' LIMIT 500"
    )) { while ($r = $res->fetch_assoc()) $rows[] = $r; }

    $target = null;
    foreach ($rows as $r) if ((int)$r['id'] === $id) { $target = $r; break; }
    if (!$target) {
        layout_start('Server');
        echo '<div class="card" style="padding:32px;text-align:center;color:#94a3b8">'
           . '<div style="font-size:32px;margin-bottom:12px">&#128421;</div>'
           . '<p style="margin:0 0 14px">Server not found or its license is suspended.</p>'
           . '<a href="/servers" style="color:#3b5bdb;font-weight:600">&#8592; All servers</a>'
           . '</div>';
        echo srv_css();
        layout_end();
        return;
    }

    $gkey = srv_group_key($target);
    $g    = array_values(array_filter($rows, fn($r) => srv_group_key($r) === $gkey));

    $pending = [];
    if ($pc = @db()->query("SELECT license_key, command FROM license_commands WHERE status='pending'"))
        while ($p = $pc->fetch_assoc()) $pending[$p['license_key']][] = $p['command'];

    $viol = srv_violations_map(array_map(fn($r) => (string)$r['license_key'], $g));
    $gv   = [];
    foreach ($g as $r) foreach (($viol[(string)$r['license_key']] ?? []) as $v) $gv[] = $v;
    usort($gv, fn($a, $b) => strcmp((string)$b['created_at'], (string)$a['created_at']));

    $info  = $g[0];
    foreach ($g as $r)
        if (!empty($r['reported_at']) && (empty($info['reported_at']) || strtotime($r['reported_at']) > strtotime($info['reported_at'])))
            $info = $r;

    $users = 0; foreach ($g as $r) $users = max($users, (int)($r['accounts'] ?? 0));
    $host  = (string)($info['hostname'] ?: $info['bound_hostname'] ?: '—');
    $ip    = (string)($info['bound_ip'] ?: $info['server_ip'] ?: '');
    $fresh = !empty($info['reported_at']) && (time() - strtotime($info['reported_at'])) < 1800;
    $sst   = empty($info['reported_at']) ? 'offline' : ($fresh ? 'online' : 'idle');
    $dot   = $sst === 'online' ? '#16a34a' : ($sst === 'idle' ? '#d97706' : '#94a3b8');
    $pulse = $sst === 'online' ? ' srv-pdot-pulse' : '';

    $verOpts = '<option value="">Latest</option>'
             . implode('', array_map(fn($v) => '<option value="' . h($v) . '">v' . h($v) . '</option>', srv_versions()));
    $fact    = fn($k, $v) => '<div class="srv-f"><span>' . h($k) . '</span><b>' . ($v === '' || $v === null ? '—' : h($v)) . '</b></div>';

    layout_start('Server — ' . $host);

    // Back link
    echo '<div class="srv-back"><a href="/servers">&#8592; All servers</a></div>';

    // Server hero card
    echo '<div class="srv-server-hero" style="--srv-accent:' . $dot . '">'
       . '<span class="srv-server-hero-dot' . $pulse . '" style="background:' . $dot . '"></span>'
       . '<div class="srv-server-hero-main">'
       .   '<h2>' . h($host) . '</h2>'
       .   '<div class="srv-server-hero-meta">'
       .     ($ip !== '' ? '<code>' . h($ip) . '</code><span class="srv-server-hero-sep">·</span>' : '')
       .     count($g) . ' product' . (count($g) !== 1 ? 's' : '')
       .     '<span class="srv-server-hero-sep">·</span>'
       .     number_format($users) . ' hosting accounts'
       .   '</div>'
       . '</div>'
       . '<div class="srv-server-hero-ago">Last seen: <strong>' . h(srv_ago($info['reported_at'] ?: $info['last_check_at'])) . '</strong></div>'
       . '</div>';

    // Hardware facts
    echo '<div class="card"><h3 style="margin:0 0 12px;font-size:15px">&#128187; Server details</h3>'
       . '<div class="srv-grid">'
       . $fact('IP (reported)', $info['server_ip'] ?: $info['bound_ip'])
       . $fact('MAC', $info['mac'])
       . $fact('OS', $info['os'])
       . $fact('Panel', $info['panel'])
       . $fact('CPU cores', $info['cpu_cores'] ? (int)$info['cpu_cores'] : '')
       . $fact('RAM', $info['ram_mb'] ? round($info['ram_mb'] / 1024, 1) . ' GB' : '')
       . $fact('Hosting accounts', $users ?: '')
       . $fact('Load (1 / 15m)', $info['load1'] !== null ? ($info['load1'] . ' / ' . $info['load15']) : '')
       . $fact('Uptime', $info['uptime_sec'] ? srv_human_uptime($info['uptime_sec']) : '')
       . $fact('Last seen', srv_ago($info['reported_at'] ?: $info['last_check_at']))
       . '</div></div>';

    // Products & actions
    echo '<div class="card"><h3 style="margin:0 0 12px;font-size:15px">&#128273; Products &amp; actions</h3>'
       . '<div class="srv-prods">';
    foreach ($g as $r) echo srv_render_product($r, $pending, $verOpts);
    echo '</div></div>';

    // Violations
    if ($gv) {
        echo '<div class="card">'
           . '<h3 style="margin:0 0 10px;color:#b91c1c;font-size:15px">&#9888; Violations &amp; security events (' . count($gv) . ')</h3>'
           . '<div class="srv-viol" style="margin:0;border:0;padding:0">';
        foreach (array_slice($gv, 0, 25) as $v) {
            $rcls = in_array($v['result'], ['env_tamper', 'tampered', 'clone_suspected'], true) ? 'crit'
                  : (in_array($v['result'], ['silent', 'binding_mismatch'], true) ? 'warn' : 'info');
            echo '<div class="srv-vrow ' . $rcls . '">'
               . '<span class="srv-vt">' . h(substr((string)$v['created_at'], 0, 16)) . '</span>'
               . '<span class="srv-vk">' . h($v['result']) . '</span>'
               . '<span class="srv-vm">' . h((string)($v['message'] ?? '')) . '</span>'
               . '</div>';
        }
        echo '</div></div>';
    }

    echo srv_css();
    echo srv_js();
    layout_end();
}
