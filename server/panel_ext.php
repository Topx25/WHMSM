<?php
/**
 * panel_ext.php — AiTech License Server admin extensions (additive, self-contained).
 *   • /licenses/edit        — edit a license (admin only, CSRF)
 *   • /logs                 — redesigned + filterable (period / action / result / key)
 *   • /logs/export          — CSV export of the current filter
 *   • /logs/delete          — delete the current filter (or all)
 * Reuses the host app's helpers: db(), h(), csrf_token(), require_admin(),
 * require_csrf(), layout_start(), layout_end(), redirect().
 */
if (!function_exists('db')) { return; }

/* ---------------- helpers ---------------- */
function pext_in(string $k, string $d = ''): string { return trim((string)($_GET[$k] ?? $_POST[$k] ?? $d)); }
function pext_log_columns(): array {
    return ['id','created_at','license_key','action','result','request_ip','server_ip','hostname','fingerprint','message'];
}
/** Build a WHERE clause + bound params from the current log filters. */
function pext_log_filter(): array {
    $where = []; $types = ''; $args = [];
    $from = pext_in('from'); $to = pext_in('to');
    $action = pext_in('action'); $result = pext_in('result'); $q = pext_in('q');
    if ($from !== '') { $where[] = 'created_at >= ?'; $types .= 's'; $args[] = $from . ' 00:00:00'; }
    if ($to   !== '') { $where[] = 'created_at <= ?'; $types .= 's'; $args[] = $to . ' 23:59:59'; }
    if ($action !== '' && $action !== 'all') { $where[] = 'action = ?'; $types .= 's'; $args[] = $action; }
    if ($result !== '' && $result !== 'all') { $where[] = 'result = ?'; $types .= 's'; $args[] = $result; }
    if ($q !== '') { $where[] = 'license_key LIKE ?'; $types .= 's'; $args[] = '%' . $q . '%'; }
    $sql = $where ? (' WHERE ' . implode(' AND ', $where)) : '';
    return [$sql, $types, $args];
}
function pext_distinct(string $col): array {
    $col = preg_match('/^[a-z_]+$/', $col) ? $col : 'action';
    $out = []; $res = db()->query("SELECT DISTINCT $col FROM license_logs WHERE $col IS NOT NULL AND $col<>'' ORDER BY $col LIMIT 100");
    if ($res) while ($r = $res->fetch_row()) $out[] = (string)$r[0];
    return $out;
}

/* ---------------- canonical plugin sections (license features) ---------------- */
/** The Safety Monitor Pro modules a license can grant. code => label. */
function pext_section_catalog(): array {
    return [
        'dashboard'           => 'Dashboard',
        'service_health'      => 'Server Health',
        'load_monitor'        => 'Load Monitor',
        'top_processes'       => 'Top Processes',
        'firewall_status'     => 'Firewall Status',
        'login_monitor'       => 'Account Audit',
        'disk_monitor'        => 'Disk / Storage',
        'suspicious_files'    => 'Forensics / Audit',
        'htaccess_watcher'    => 'PHP Harden',
        'email_queue_monitor' => 'Spam & Phishing',
        'web_attack_monitor'  => 'Imunify360 Reports',
        'telegram_alerts'     => 'Notifications / WhatsApp',
        'analytics_reports'   => 'Analytics Reports',
        'security_health'     => 'Security Health',
        'database_cleanup'    => 'DB Cleanup',
        'network_traffic'     => 'Network Traffic',
        'hardware_platform'   => 'Hardware & Platform',
        'cpanel_services'     => 'cPanel Services',
        'backup_monitor'      => 'Backup Monitor',
        'ai_providers'        => 'AI Providers',
    ];
}

/* ---------------- /licenses/edit ---------------- */
function pext_license_edit(): void {
    require_admin();
    $id = (int)pext_in('id');
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        require_csrf();
        $clientName  = trim((string)($_POST['client_name'] ?? ''));
        $clientEmail = trim((string)($_POST['client_email'] ?? ''));
        $clientPhone = trim((string)($_POST['client_phone'] ?? ''));
        $plan        = trim((string)($_POST['plan'] ?? 'pro'));
        $edition     = trim((string)($_POST['edition'] ?? ''));
        $product     = trim((string)($_POST['product_code'] ?? ''));
        $status      = in_array($_POST['status'] ?? 'new', ['new','active','suspended','expired'], true) ? $_POST['status'] : 'new';
        $maxServers  = max(1, (int)($_POST['max_servers'] ?? 1));
        $expiresAt   = trim((string)($_POST['expires_at'] ?? ''));
        $notes       = trim((string)($_POST['notes'] ?? ''));
        $expiresAt   = $expiresAt === '' ? null : (date('Y-m-d H:i:s', strtotime($expiresAt) ?: time()));
        // sections (features) — only codes from this product's catalog are accepted
        $feats = $_POST['features'] ?? [];
        if (!is_array($feats)) $feats = [];
        $allowedFeats = function_exists('splan_catalog') ? array_keys(splan_catalog($product)) : array_keys(pext_section_catalog());
        $feats = array_values(array_intersect(array_map('strval', $feats), $allowedFeats));
        $featuresJson = json_encode($feats, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        $bIp  = trim((string)($_POST['bound_ip'] ?? ''));          $bIp   = $bIp   === '' ? null : $bIp;
        $bHost = trim((string)($_POST['bound_hostname'] ?? ''));    $bHost = $bHost === '' ? null : $bHost;
        $bFp  = trim((string)($_POST['bound_fingerprint'] ?? ''));  $bFp   = $bFp   === '' ? null : $bFp;
        $stmt = db()->prepare("UPDATE licenses SET client_name=?, client_email=?, client_phone=?, plan=?, edition=?, product_code=?, status=?, max_servers=?, expires_at=?, notes=?, features=?, bound_ip=?, bound_hostname=?, bound_fingerprint=? WHERE id=?");
        $stmt->bind_param('sssssssissssssi', $clientName, $clientEmail, $clientPhone, $plan, $edition, $product, $status, $maxServers, $expiresAt, $notes, $featuresJson, $bIp, $bHost, $bFp, $id);
        $stmt->execute();
        redirect('/licenses');
    }
    $stmt = db()->prepare("SELECT * FROM licenses WHERE id=? LIMIT 1");
    $stmt->bind_param('i', $id); $stmt->execute();
    $lic = $stmt->get_result()->fetch_assoc();
    layout_start('Edit License');
    if (!$lic) { echo '<div class="card"><h2>Edit License</h2><p>License not found.</p><a class="btn" href="/licenses">Back</a></div>'; layout_end(); return; }
    $v = fn($k) => h((string)($lic[$k] ?? ''));
    $statusOpts = ''; foreach (['new','active','suspended','expired'] as $o) $statusOpts .= '<option value="' . $o . '"' . (($lic['status'] ?? '') === $o ? ' selected' : '') . '>' . $o . '</option>';
    echo '<div class="card"><h2>&#9998; Edit License</h2>';
    echo '<p style="color:#64748b;font-weight:800">Key <code class="copykey" data-k="' . h((string)$lic['license_key']) . '" title="Click to copy" style="cursor:pointer">' . h((string)$lic['license_key']) . '</code> <span style="font-size:11px;color:#94a3b8;font-weight:400">click to copy</span></p>';
    $dlc = 0;
    if ($dq = db()->prepare("SELECT COUNT(*) FROM license_logs WHERE license_key=? AND action='download' AND result='ok'")) {
        $dq->bind_param('s', $lic['license_key']); $dq->execute(); $dq->bind_result($dlc); $dq->fetch(); $dq->close(); $dlc = (int)$dlc;
    }
    echo '<p style="color:#0f2657;font-weight:800;margin:-4px 0 6px">Downloads: <b>' . $dlc . ' / 1</b> ' . ($dlc >= 1 ? '<span class="badge suspended">used</span>' : '<span class="badge active">available</span>') . '</p>';
    if (function_exists('smlic_protection_block')) echo smlic_protection_block($lic);   // TEMP-DIAG protection tokens
    echo '<form method="post" action="/licenses/action" style="margin:0 0 12px"><input type="hidden" name="csrf" value="' . h(csrf_token()) . '"><input type="hidden" name="id" value="' . (int)$lic['id'] . '">';
    echo '<button name="do" value="reset_download"' . ($dlc >= 1 ? '' : ' disabled') . ' onclick="return confirm(\'Allow this license to be downloaded again?\')">&#8635; Reset download allowance</button> ';
    $hasContact = trim((string)($lic['client_email'] ?? '')) !== '' || trim((string)($lic['client_phone'] ?? '')) !== '';
    echo '<button name="do" value="notify"' . ($hasContact ? '' : ' disabled title="No email/phone on file"') . ' onclick="return confirm(\'Send the license key + install command to the customer now?\')">&#9993;&#65039; Resend to customer</button></form>';
    echo '<form method="post" action="/licenses/edit"><input type="hidden" name="csrf" value="' . h(csrf_token()) . '"><input type="hidden" name="id" value="' . (int)$lic['id'] . '">';
    $edProduct = (string)($lic['product_code'] ?? 'safety_monitor');
    $edPlans = function_exists('splan_all') ? splan_all($edProduct) : [];
    $planOpts = ''; $haveCur = false;
    foreach ($edPlans as $ep) { $s = ((string)($lic['plan'] ?? '') === $ep['code']) ? ' selected' : ''; if ($s) $haveCur = true; $planOpts .= '<option value="' . h($ep['code']) . '"' . $s . '>' . h($ep['name']) . '</option>'; }
    if (!$haveCur && ($lic['plan'] ?? '') !== '') $planOpts = '<option selected value="' . $v('plan') . '">' . $v('plan') . ' (current)</option>' . $planOpts;
    echo '<div class="pext-grid">';
    echo '<label>Client name<input name="client_name" value="' . $v('client_name') . '"></label>';
    echo '<label>Client email<input name="client_email" value="' . $v('client_email') . '"></label>';
    echo '<label>Client phone / WhatsApp <span style="color:#94a3b8;font-weight:400">(intl format)</span><input name="client_phone" value="' . $v('client_phone') . '" placeholder="+201234567890"></label>';
    echo '<label>Plan <span style="color:#94a3b8;font-weight:400">(sets features automatically)</span><select name="plan" id="edPlan">' . $planOpts . '</select></label>';
    echo '<label>Edition <span style="color:#94a3b8;font-weight:400">(auto)</span><input name="edition" id="edEdition" value="' . $v('edition') . '" readonly style="background:#f1f5f9"></label>';
    echo '<label>Product code <span style="color:#94a3b8;font-weight:400">(auto)</span><input name="product_code" value="' . $v('product_code') . '" readonly style="background:#f1f5f9"></label>';
    echo '<label>Status<select name="status">' . $statusOpts . '</select></label>';
    echo '<label>Max servers<input name="max_servers" type="number" min="1" value="' . h((string)($lic['max_servers'] ?? 1)) . '"></label>';
    echo '<label>Expires at<input name="expires_at" value="' . $v('expires_at') . '" placeholder="YYYY-MM-DD HH:MM:SS"></label>';
    echo '</div>';
    echo '<label style="display:block;margin-top:10px">Notes<textarea name="notes" rows="2" style="width:100%">' . $v('notes') . '</textarea></label>';
    // sections (features) the license grants — catalog is product-specific
    $curFeats = json_decode((string)($lic['features'] ?? '[]'), true); if (!is_array($curFeats)) $curFeats = [];
    $featCatalog = function_exists('splan_catalog') ? splan_catalog($edProduct) : pext_section_catalog();
    echo '<div class="pext-sections"><div class="pext-sechd"><b>&#129518; Sections enabled by this license</b> '
       . '<a href="#" onclick="document.querySelectorAll(\'.pext-secchk\').forEach(c=>c.checked=true);return false;">all</a> · '
       . '<a href="#" onclick="document.querySelectorAll(\'.pext-secchk\').forEach(c=>c.checked=false);return false;">none</a></div>';
    echo '<div class="pext-secgrid">';
    foreach ($featCatalog as $code => $label) {
        $on = in_array($code, $curFeats, true) ? ' checked' : '';
        echo '<label class="pext-sec"><input type="checkbox" class="pext-secchk" name="features[]" value="' . h($code) . '"' . $on . '> ' . h($label) . '</label>';
    }
    echo '</div></div>';
    echo '<div class="pext-sections"><div class="pext-sechd"><b>&#128279; Server binding (who may download / run)</b></div>';
    echo '<p style="color:#475569;font-size:13px;margin:4px 0 8px">Auto by default: the FIRST download from the licensed server binds it to that server&#39;s IP + hostname + hardware fingerprint (the fingerprint is the real lock). Set these only to move/correct a binding. To let a NEW server download, <b>clear all three</b> (or use Reset IP) and it re-binds on next download. An IP without a fingerprint will NOT allow download.</p>';
    echo '<div class="pext-grid" style="display:grid;grid-template-columns:repeat(2,1fr);gap:12px">';
    echo '<label>Bound IP<input name="bound_ip" value="' . $v('bound_ip') . '" placeholder="(auto on first download)"></label>';
    echo '<label>Bound hostname<input name="bound_hostname" value="' . $v('bound_hostname') . '"></label>';
    echo '<label style="grid-column:1/-1">Bound fingerprint (sha256)<input name="bound_fingerprint" value="' . $v('bound_fingerprint') . '" placeholder="(auto on first download)"></label>';
    echo '</div>';
    echo '<p style="color:#64748b;font-size:12.5px;margin-top:6px">Status: <b>' . $v('status') . '</b> &middot; Activated: ' . ($v('activated_at') ?: '&mdash;') . '</p>';
    echo '</div>';
    echo '<div style="margin-top:14px"><button type="submit" class="ok">&#128190; Save changes</button> <a class="btn" href="/licenses">Cancel</a></div>';
    echo '</form></div>';
    echo '<style>.pext-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:12px}.pext-grid label,form label{display:flex;flex-direction:column;gap:5px;font-weight:800;color:#0f2657;font-size:13px}.pext-grid input,.pext-grid select,form input,form select,form textarea{padding:9px 12px;border-radius:12px;border:1px solid rgba(148,163,184,.5);font-size:14px}button.ok{background:#16a34a;color:#fff}'
       . '.pext-sections{margin-top:14px;border-top:1px solid rgba(148,163,184,.3);padding-top:12px}.pext-sechd{font-size:13px;color:#0f2657;margin-bottom:8px}.pext-sechd a{font-weight:800;color:#08a8c5}'
       . '.pext-secgrid{display:grid;grid-template-columns:repeat(3,1fr);gap:6px}@media(max-width:760px){.pext-secgrid{grid-template-columns:1fr 1fr}}'
       . '.pext-sec{flex-direction:row !important;align-items:center;gap:7px !important;font-weight:600 !important;font-size:13px;background:rgba(255,255,255,.5);padding:7px 10px;border-radius:10px;cursor:pointer}.pext-sec input{padding:0 !important}</style>';
    // auto-fill features/edition/max-servers from the selected plan + click-to-copy
    $pj = json_encode(array_map(fn($p) => ['code'=>$p['code'],'edition'=>$p['code'],'max_servers'=>$p['max_servers'],'features'=>array_values((array)$p['features'])], $edPlans), JSON_UNESCAPED_SLASHES);
    echo '<script>(function(){var P=' . $pj . ';var sel=document.getElementById("edPlan");
function apply(c){var p=null;for(var i=0;i<P.length;i++)if(P[i].code===c)p=P[i];if(!p)return;
  var ed=document.getElementById("edEdition");if(ed)ed.value=p.edition;
  var ms=document.querySelector("[name=max_servers]");if(ms)ms.value=p.max_servers;
  document.querySelectorAll(".pext-secchk").forEach(function(cb){cb.checked=(p.features||[]).indexOf(cb.value)>=0;});}
if(sel)sel.addEventListener("change",function(){apply(sel.value);});})();
document.addEventListener("click",function(e){var c=e.target.closest(".copykey");if(!c)return;var t=c.getAttribute("data-k")||c.textContent;if(navigator.clipboard)navigator.clipboard.writeText(t);var o=c.textContent;c.textContent="✓ copied";setTimeout(function(){c.textContent=o;},1000);});</script>';
    layout_end();
}

/* ---------------- /logs (redesigned + filterable) ---------------- */
function pext_logs(): void {
    require_admin();
    [$wsql, $types, $args] = pext_log_filter();
    $stmt = db()->prepare("SELECT * FROM license_logs" . $wsql . " ORDER BY id DESC LIMIT 1000");
    if ($types !== '') $stmt->bind_param($types, ...$args);
    $stmt->execute();
    $rows = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
    $cntStmt = db()->prepare("SELECT COUNT(*) FROM license_logs" . $wsql);
    if ($types !== '') $cntStmt->bind_param($types, ...$args);
    $cntStmt->execute(); $total = (int)($cntStmt->get_result()->fetch_row()[0] ?? 0);
    $qs = http_build_query(array_filter(['from'=>pext_in('from'),'to'=>pext_in('to'),'action'=>pext_in('action'),'result'=>pext_in('result'),'q'=>pext_in('q')]));

    layout_start('Logs');
    echo '<div class="card"><h2>&#128203; License Logs</h2>';
    // filter bar
    echo '<form method="get" action="/logs" class="pext-filter">';
    echo '<label>From<input type="date" name="from" value="' . h(pext_in('from')) . '"></label>';
    echo '<label>To<input type="date" name="to" value="' . h(pext_in('to')) . '"></label>';
    $opt = function($name,$vals,$cur){ $s='<option value="all">all</option>'; foreach($vals as $vv){ $s.='<option value="'.h($vv).'"'.($cur===$vv?' selected':'').'>'.h($vv).'</option>'; } return $s; };
    echo '<label>Action<select name="action">' . $opt('action', pext_distinct('action'), pext_in('action')) . '</select></label>';
    echo '<label>Result / validity<select name="result">' . $opt('result', pext_distinct('result'), pext_in('result')) . '</select></label>';
    echo '<label>License key<input name="q" value="' . h(pext_in('q')) . '" placeholder="search…"></label>';
    echo '<div class="pext-fbtns"><button type="submit">&#128269; Filter</button> <a class="btn" href="/logs">Reset</a></div>';
    echo '</form>';
    // toolbar: count + export + delete
    echo '<div class="pext-toolbar"><span><b>' . number_format($total) . '</b> matching log(s)' . ($qs ? ' (filtered)' : '') . '</span>';
    echo '<span class="pext-sp"></span>';
    echo '<a class="btn ok" href="/logs/export' . ($qs ? '?' . h($qs) : '') . '">&#11015; Export CSV</a> ';
    echo '<form method="post" action="/logs/delete" style="display:inline" onsubmit="return confirm(\'Delete the matching log(s)? This cannot be undone.\');">';
    echo '<input type="hidden" name="csrf" value="' . h(csrf_token()) . '">';
    foreach (['from','to','action','result','q'] as $k) { $val = pext_in($k); if ($val !== '') echo '<input type="hidden" name="' . $k . '" value="' . h($val) . '">'; }
    echo '<button class="danger" name="scope" value="' . ($qs ? 'filter' : 'all') . '">&#128465; Delete ' . ($qs ? 'filtered' : 'all') . '</button>';
    echo '</form></div>';
    // table
    echo '<div class="pext-tablewrap"><table><tr><th>Date</th><th>License</th><th>Action</th><th>Result</th><th>Req IP</th><th>Server IP</th><th>Hostname</th><th>Message</th></tr>';
    foreach ($rows as $r) {
        $rc = in_array(($r['result'] ?? ''), ['ok','active','valid'], true) ? 'ok' : (in_array(($r['result'] ?? ''), ['bad_request','binding_mismatch','invalid','expired','suspended'], true) ? 'danger' : '');
        echo '<tr>';
        echo '<td>' . h($r['created_at']) . '</td>';
        echo '<td><code class="copykey" data-k="' . h($r['license_key']) . '" title="Click to copy" style="cursor:pointer">' . h($r['license_key']) . '</code></td>';
        echo '<td>' . h($r['action']) . '</td>';
        echo '<td><span class="badge ' . $rc . '">' . h($r['result']) . '</span></td>';
        echo '<td>' . h($r['request_ip']) . '</td>';
        echo '<td>' . h($r['server_ip']) . '</td>';
        echo '<td>' . h($r['hostname']) . '</td>';
        echo '<td><small>' . h($r['message']) . '</small></td>';
        echo '</tr>';
    }
    echo '</table></div></div>';
    echo '<style>'
       . '.pext-filter{display:flex;flex-wrap:wrap;gap:10px;align-items:flex-end;margin-bottom:14px}'
       . '.pext-filter label{display:flex;flex-direction:column;gap:4px;font-size:12px;font-weight:800;color:#0f2657}'
       . '.pext-filter input,.pext-filter select{padding:8px 10px;border-radius:12px;border:1px solid rgba(148,163,184,.5)}'
       . '.pext-fbtns{display:flex;gap:8px}'
       . '.pext-toolbar{display:flex;align-items:center;gap:10px;margin-bottom:12px;flex-wrap:wrap}.pext-sp{flex:1}'
       . '.pext-tablewrap{overflow:auto;max-height:62vh;border-radius:14px}'
       . '.badge.ok{background:#dcfce7;color:#166534}.badge.danger{background:#fee2e2;color:#991b1b}'
       . 'a.btn.ok{background:#16a34a;color:#fff}button.danger{background:#dc2626;color:#fff}'
       . '</style>';
    layout_end();
}

/* ---------------- /logs/export (CSV) ---------------- */
function pext_logs_export(): void {
    require_admin();
    [$wsql, $types, $args] = pext_log_filter();
    $stmt = db()->prepare("SELECT " . implode(',', pext_log_columns()) . " FROM license_logs" . $wsql . " ORDER BY id DESC LIMIT 100000");
    if ($types !== '') $stmt->bind_param($types, ...$args);
    $stmt->execute();
    $res = $stmt->get_result();
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="license_logs_' . date('Ymd_His') . '.csv"');
    $out = fopen('php://output', 'w');
    fputcsv($out, pext_log_columns());
    while ($row = $res->fetch_assoc()) fputcsv($out, $row);
    fclose($out);
    exit;
}

/* ---------------- /logs/delete ---------------- */
function pext_logs_delete(): void {
    require_admin();
    require_csrf();
    $scope = pext_in('scope');
    if ($scope === 'all') {
        db()->query('DELETE FROM license_logs');
    } else {
        [$wsql, $types, $args] = pext_log_filter();
        $stmt = db()->prepare("DELETE FROM license_logs" . $wsql);
        if ($types !== '') $stmt->bind_param($types, ...$args);
        $stmt->execute();
    }
    redirect('/logs');
}

/* ---------------- router ---------------- */
function pext_route(string $path): bool {
    $m = $_SERVER['REQUEST_METHOD'] ?? 'GET';
    if ($path === '/licenses/edit') { pext_license_edit(); return true; }
    if ($path === '/logs/export')   { pext_logs_export();  return true; }
    if ($path === '/logs/delete' && $m === 'POST') { pext_logs_delete(); return true; }
    if ($path === '/logs')          { pext_logs();         return true; }
    return false;
}
