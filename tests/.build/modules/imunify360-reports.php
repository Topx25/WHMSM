<?php
/**
 * modules/imunify360-reports.php — Imunify360 malware reports (read-only).
 * Reads Imunify360's own scan results via imunify360-agent (zero scan overhead —
 * Imunify already scans continuously). Shows currently-malicious files, detection
 * history, infected accounts and malware families. Filterable + CSV export.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

function smpro_im_bin() { return is_executable('/usr/bin/imunify360-agent') ? '/usr/bin/imunify360-agent' : (is_executable('/usr/local/bin/imunify360-agent') ? '/usr/local/bin/imunify360-agent' : ''); }
function smpro_im_json($args, $t = 45) {
    $bin = smpro_im_bin(); if ($bin === '') return null;
    $raw = (string)@shell_exec('timeout ' . $t . ' ' . escapeshellarg($bin) . ' ' . $args . ' --json 2>/dev/null');
    $j = json_decode($raw, true); return is_array($j) ? $j : null;
}
/** Malware family from a signature id: SMW-INJ-2037296-php.bkdr.drpr-0 -> php.bkdr.drpr */
function smpro_im_family($sig) {
    if (!$sig) return ''; if (preg_match('/SMW-[A-Z]+-\d+-(.+?)-\d+$/', $sig, $m)) return $m[1];
    if (preg_match('/SMW-[A-Z]+-\d+-(.+)$/', $sig, $m)) return $m[1]; return $sig;
}

$installed = smpro_im_bin() !== '';

/* ---------- params ---------- */
$user = preg_replace('/[^a-zA-Z0-9._-]/', '', (string)($_GET['user'] ?? ''));
$days = (int)($_GET['days'] ?? 30); if (!in_array($days, [1,7,30,90,365], true)) $days = 30;
$fromTs = time() - $days * 86400;
$fmt = (string)($_GET['format'] ?? '');
$reqMethod = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? getenv('REQUEST_METHOD') ?: 'GET'));

/* ===================================================================
 * Action engine — server-wide hash hunt + REAL file deletion (backed up
 * outside the account, with a per-action report). Reuses the same backup
 * location & report schema as Forensics so deletions show up there too.
 * =================================================================== */
define('SMPRO_IM_REPDIR', SMPRO_VARLIB . '/reports/detections');

/** Write a per-action detection report (JSON) — same schema Forensics uses. */
function smpro_im_report_write($d) {
    @is_dir(SMPRO_IM_REPDIR) || @mkdir(SMPRO_IM_REPDIR, 0700, true);
    $id = date('Ymd_His') . '_' . substr(hash('sha256', json_encode($d) . uniqid('', true)), 0, 8);
    $d['id'] = $id; $d['at'] = date('c'); $d['ts'] = time();
    @file_put_contents(SMPRO_IM_REPDIR . '/' . $id . '.json', json_encode($d, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), LOCK_EX);
    @chmod(SMPRO_IM_REPDIR . '/' . $id . '.json', 0600);
    return $id;
}
function smpro_im_report_load($id) {
    $id = preg_replace('/[^a-zA-Z0-9_]/', '', (string)$id); if ($id === '') return null;
    $f = SMPRO_IM_REPDIR . '/' . $id . '.json'; if (!is_file($f)) return null;
    $j = json_decode((string)@file_get_contents($f), true); return is_array($j) ? $j : null;
}
function smpro_im_acct_of($file) { return preg_match('#^/home/([^/]+)/#', (string)$file, $m) ? $m[1] : 'system'; }

/** REAL deletion: back up OUTSIDE the account, then unlink, then write a report. */
function smpro_im_delete_file($file) {
    if (!preg_match('#^/home/([^/]+)/.+#', $file, $m))
        return ['ok'=>false,'msg'=>'Refused: only files under /home/<account>/ can be deleted.'];
    if (!is_file($file))
        return ['ok'=>false,'gone'=>true,'msg'=>'File is no longer on disk — Imunify already cleaned or quarantined it. Use “Clear from list” to remove this stale entry.'];
    $acct = $m[1];
    $bdir = '/home/backup/detections/' . $acct;
    @is_dir($bdir) || @mkdir($bdir, 0700, true); @chmod('/home/backup/detections', 0700);
    $sha  = @hash_file('sha256', $file) ?: '';
    $size = (int)@filesize($file);
    $bak  = $bdir . '/' . date('Ymd_His') . '_' . preg_replace('/[^a-zA-Z0-9._-]/', '_', basename($file));
    if (!@copy($file, $bak)) return ['ok'=>false,'msg'=>'Could not back up the file — aborting (nothing deleted).'];
    @chmod($bak, 0600);
    if (!@unlink($file)) return ['ok'=>false,'msg'=>'Backup saved but DELETE failed (permissions?). Backup: ' . basename($bak)];
    $rid = smpro_im_report_write(['action'=>'delete_malware','source'=>'imunify360-reports','account'=>$acct,'file'=>$file,'sha256'=>$sha,'size'=>$size,'backup'=>$bak,'actor'=>function_exists('smpro_current_actor')?smpro_current_actor():'root']);
    smpro_audit('im_delete_malware', ['account'=>$acct,'file'=>$file,'sha256'=>$sha,'backup'=>$bak,'report'=>$rid]);
    return ['ok'=>true,'msg'=>'File DELETED. Backed up outside the account (restorable from Forensics).','account'=>$acct,'file'=>$file,'sha256'=>$sha,'size'=>$size,'backup'=>$bak,'report'=>$rid,
            'report_url'=>'index.cgi?page=imunify360-reports&report=' . $rid . '&format=html'];
}

/** Standalone HTML deletion report (served via CGI format=html → download). */
function smpro_im_report_html($id) {
    $d = smpro_im_report_load($id);
    $h = fn($s) => htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');
    if (!$d) return '<!doctype html><meta charset=utf-8><body style="font-family:system-ui;padding:40px"><h2>Report not found</h2></body>';
    $kb = isset($d['size']) ? number_format($d['size']/1024, 1) . ' KB' : '—';
    return '<!doctype html><html><head><meta charset="utf-8"><title>Malware Deletion Report ' . $h($d['id']) . '</title>'
      . '<style>body{font-family:system-ui,Segoe UI,Arial;margin:0;background:#f4f6fb;color:#1a2233}'
      . '.wrap{max-width:760px;margin:30px auto;background:#fff;border:1px solid #e4e8f0;border-radius:14px;overflow:hidden}'
      . '.hd{background:#b42318;color:#fff;padding:22px 26px}.hd h1{margin:0;font-size:20px}.hd .s{opacity:.85;font-size:13px;margin-top:4px}'
      . 'table{width:100%;border-collapse:collapse;font-size:14px}td,th{padding:11px 26px;border-bottom:1px solid #eef1f6;text-align:left;vertical-align:top}'
      . 'th{width:170px;color:#667;font-weight:600;background:#fafbfe}.mono{font-family:ui-monospace,Consolas,monospace;word-break:break-all}'
      . '.tag{display:inline-block;background:#fde8e6;color:#b42318;font-weight:700;font-size:12px;padding:3px 10px;border-radius:20px}'
      . '.ft{padding:16px 26px;color:#889;font-size:12px}</style></head><body><div class="wrap">'
      . '<div class="hd"><h1>&#128737; Malware Deletion Report</h1><div class="s">Safety Monitor Pro · Imunify360 Reports · report #' . $h($d['id']) . '</div></div>'
      . '<table>'
      . '<tr><th>Action</th><td><span class="tag">DELETED (real)</span></td></tr>'
      . '<tr><th>When</th><td>' . $h($d['at'] ?? '') . '</td></tr>'
      . '<tr><th>Account</th><td class="mono">' . $h($d['account'] ?? '') . '</td></tr>'
      . '<tr><th>File</th><td class="mono">' . $h($d['file'] ?? '') . '</td></tr>'
      . '<tr><th>Size</th><td>' . $kb . '</td></tr>'
      . '<tr><th>SHA-256</th><td class="mono">' . $h($d['sha256'] ?? '') . '</td></tr>'
      . '<tr><th>Backup copy</th><td class="mono">' . $h($d['backup'] ?? '') . '</td></tr>'
      . '<tr><th>Performed by</th><td>' . $h($d['actor'] ?? 'root') . '</td></tr>'
      . '</table>'
      . '<div class="ft">The file was backed up OUTSIDE the customer account before removal and can be restored from Forensics &rarr; Remediation history. This report is retained for 90 days.</div>'
      . '</div></body></html>';
}

/* ---- GET: serve a standalone HTML deletion report (download via CGI format=html) ---- */
if ($fmt === 'html' && isset($_GET['report'])) { echo smpro_im_report_html($_GET['report']); exit; }

/* ---- POST: server-wide hash hunt (find other files with the SAME SHA-256) ---- */
if ($reqMethod === 'POST' && ($_POST['im_action'] ?? '') === 'hash_search') {
    smpro_require_valid_csrf('im_remediate'); smpro_require_root();
    header('Content-Type: application/json');
    $sha  = strtolower(preg_replace('/[^a-fA-F0-9]/', '', (string)($_POST['sha'] ?? '')));
    $size = (int)($_POST['size'] ?? 0);
    if (strlen($sha) !== 64) { echo json_encode(['ok'=>false,'msg'=>'No usable SHA-256 for this file (Imunify did not provide a hash).']); exit; }
    if ($size <= 0)          { echo json_encode(['ok'=>false,'msg'=>'No file size to anchor the hunt — refusing a full /home hash sweep (too heavy).']); exit; }
    // Bounded + throttled: prefilter by EXACT byte size (a same-payload file is byte-identical),
    // skip mail/backup/trash/vendor trees, then verify by hashing only the size matches.
    $prune = "\\( -path /home/backup -o -ipath '*/mail' -o -ipath '*/.trash*' -o -ipath '*/node_modules' -o -ipath '*/vendor' -o -ipath '*/.snapshots*' -o -ipath '*/.git' \\) -prune";
    $cmd = "timeout 110 nice -n19 ionice -c3 find /home -maxdepth 8 $prune -o -type f -size {$size}c -print 2>/dev/null | head -4000";
    $cand = array_filter(explode("\n", (string)@shell_exec($cmd)));
    $matches = []; $checked = 0;
    foreach ($cand as $p) {
        if ($checked++ > 4000) break;
        if (!is_file($p)) continue;
        if (@hash_file('sha256', $p) !== $sha) continue;
        $matches[] = ['path'=>$p, 'account'=>smpro_im_acct_of($p), 'size'=>(int)@filesize($p), 'mtime'=>(int)@filemtime($p)];
        if (count($matches) >= 500) break;
    }
    usort($matches, fn($a,$b)=>strcmp($a['path'],$b['path']));
    smpro_audit('im_hash_search', ['sha256'=>$sha,'size'=>$size,'candidates'=>count($cand),'matches'=>count($matches)]);
    echo json_encode(['ok'=>true,'sha'=>$sha,'size'=>$size,'candidates'=>count($cand),'matches'=>$matches], JSON_UNESCAPED_SLASHES); exit;
}

/* ---- POST: REAL deletion of a malicious file (+ report) ---- */
if ($reqMethod === 'POST' && ($_POST['im_action'] ?? '') === 'delete_file') {
    smpro_require_valid_csrf('im_remediate'); smpro_require_root();
    header('Content-Type: application/json');
    echo json_encode(smpro_im_delete_file((string)($_POST['file'] ?? '')), JSON_UNESCAPED_SLASHES); exit;
}

/* ---- POST: clear a STALE malicious-list entry (file already gone) from Imunify ---- */
if ($reqMethod === 'POST' && ($_POST['im_action'] ?? '') === 'clear_list') {
    smpro_require_valid_csrf('im_remediate'); smpro_require_root();
    header('Content-Type: application/json');
    $id = preg_replace('/[^0-9]/', '', (string)($_POST['imid'] ?? ''));
    $bin = smpro_im_bin();
    if ($bin === '') { echo json_encode(['ok'=>false,'msg'=>'Imunify360 agent not available.']); exit; }
    if ($id === '') { echo json_encode(['ok'=>false,'msg'=>'Missing Imunify item id for this entry.']); exit; }
    $out = (string)@shell_exec('timeout 60 ' . escapeshellarg($bin) . ' malware malicious remove-from-list --items ' . $id . ' --json 2>&1');
    $j = json_decode($out, true);
    $ok = is_array($j) ? (($j['success'] ?? null) !== false) : (stripos($out, 'error') === false && trim($out) !== '');
    smpro_audit('im_clear_list', ['imid'=>$id, 'ok'=>$ok]);
    echo json_encode(['ok'=>$ok, 'msg'=>$ok ? 'Stale entry cleared from Imunify360 list (file was already gone). Reloading…' : ('Failed to clear: ' . mb_substr(trim($out), 0, 160))], JSON_UNESCAPED_SLASHES); exit;
}

/* ---------- fetch (read-only) ---------- */
$malicious = []; $history = []; $accounts = 0; $totalHist = 0; $ver = ''; $strategy = '';
if ($installed) {
    $mj = smpro_im_json('malware malicious list --limit 2000', 40);
    if (is_array($mj)) { $malicious = $mj['items'] ?? []; }
    $hj = smpro_im_json('malware history list --limit 3000', 50);
    if (is_array($hj)) { $history = $hj['items'] ?? []; $totalHist = (int)($hj['max_count'] ?? count($history)); $ver = (string)($hj['version'] ?? ''); $strategy = (string)($hj['strategy'] ?? ''); $accounts = (int)($hj['license']['user_count'] ?? 0); }
    // newest first
    usort($history, fn($a, $b) => (int)($b['ctime'] ?? 0) <=> (int)($a['ctime'] ?? 0));
    usort($malicious, fn($a, $b) => (int)($b['created'] ?? 0) <=> (int)($a['created'] ?? 0));
}

/* filter helpers */
$mFilter = function ($r) use ($user) { return $user === '' || ($r['username'] ?? '') === $user; };
$hFilter = function ($r) use ($user, $fromTs) { if ($user !== '' && ($r['file_user'] ?? $r['file_owner'] ?? '') !== $user) return false; return (int)($r['ctime'] ?? 0) >= $fromTs; };
$malF = array_values(array_filter($malicious, $mFilter));
$histF = array_values(array_filter($history, $hFilter));

/* ---------- export ---------- */
if ($fmt === 'csv') {
    $fh = fopen('php://output', 'w');
    fputcsv($fh, ['type','account','path','malware_family','signature','size','sha256','detected','status']);
    foreach ($malF as $r) fputcsv($fh, ['active', $r['username'] ?? '', $r['file'] ?? '', smpro_im_family($r['type'] ?? ''), $r['type'] ?? '', $r['size'] ?? '', $r['hash'] ?? '', date('Y-m-d H:i', (int)($r['created'] ?? 0)), $r['status'] ?? '']);
    foreach ($histF as $r) fputcsv($fh, ['history', $r['file_user'] ?? $r['file_owner'] ?? '', $r['path'] ?? '', smpro_im_family($r['signature_id'] ?? ''), $r['signature_id'] ?? '', '', '', date('Y-m-d H:i', (int)($r['ctime'] ?? 0)), $r['event'] ?? '']);
    fclose($fh);
    exit;
}

/* ---------- aggregates ---------- */
$infectedAccts = []; foreach ($malF as $r) { $u = $r['username'] ?? ''; if ($u !== '') $infectedAccts[$u] = ($infectedAccts[$u] ?? 0) + 1; }
arsort($infectedAccts);
$families = []; foreach ($malF as $r) { $f = smpro_im_family($r['type'] ?? ''); if ($f !== '') $families[$f] = ($families[$f] ?? 0) + 1; }
foreach ($histF as $r) { $f = smpro_im_family($r['signature_id'] ?? ''); if ($f !== '') $families[$f] = ($families[$f] ?? 0) + 1; }
arsort($families);
$dbThreats = count(array_filter($malF, fn($r) => ($r['resource_type'] ?? '') === 'db'));
$userOptions = array_keys(array_merge(array_flip(array_map(fn($r)=>$r['username']??'', $malicious)), array_flip(array_map(fn($r)=>$r['file_user']??$r['file_owner']??'', $history))));
$userOptions = array_values(array_filter(array_unique($userOptions))); sort($userOptions);

smpro_audit('imunify360_reports_view', ['active'=>count($malF),'history'=>count($histF)]);
smpro_layout_header('Imunify360 Reports');
$exp = 'index.cgi?page=imunify360-reports&format=csv&user=' . urlencode($user) . '&days=' . $days;
$csrfIm = smpro_csrf_generate('im_remediate');
?>
<div class="svc-kicker">Malware</div>
<h1 class="h" style="margin:2px 0 4px">Imunify360 Reports</h1>
<p class="sub">Read directly from Imunify360's continuous scans — zero extra load on the server. Currently-infected files, detection history, accounts &amp; malware families.</p>

<?php if (!$installed): ?>
<div class="card im-missing">&#9888; Imunify360 is not installed or its agent was not detected. Install Imunify360/ImunifyAV for continuous malware scanning, then this report will populate automatically.</div>
<?php else: ?>

<form method="get" action="index.cgi" class="im-bar">
  <input type="hidden" name="page" value="imunify360-reports">
  <label class="im-fld">Account<select class="tp-sel" name="user"><option value="">All accounts</option>
    <?php foreach ($userOptions as $u): ?><option value="<?= smpro_h($u) ?>"<?= $user===$u?' selected':'' ?>><?= smpro_h($u) ?></option><?php endforeach; ?>
  </select></label>
  <label class="im-fld">History range<select class="tp-sel" name="days"><?php foreach ([1=>'24 hours',7=>'7 days',30=>'30 days',90=>'90 days',365=>'1 year'] as $k=>$v): ?><option value="<?= $k ?>"<?= $days===$k?' selected':'' ?>><?= $v ?></option><?php endforeach; ?></select></label>
  <button class="tp-btn primary" type="submit">Apply</button>
  <a class="tp-btn green" href="<?= smpro_h($exp) ?>">Export CSV</a>
  <?php $imUrl = rtrim((string)SMPRO_CPSESS, '/') . '/cgi/imunify/handlers/index.cgi'; ?>
  <a class="tp-btn" style="background:#0e7c4a;color:#fff;border-color:#0e7c4a" href="<?= smpro_h($imUrl) ?>" target="_blank" title="Open the Imunify360 plugin to clean, ignore or restore — actions run inside Imunify">&#128737; Open Imunify360 to take action &#8599;</a>
</form>
<p class="sub" style="margin:-2px 0 12px;font-size:12px">Cleanup / ignore / restore actions are performed inside Imunify360 itself (it owns the quarantine &amp; backups). The button above opens it; file-level actions are also available from <a href="index.cgi?page=forensics-audit">Forensics</a> (Clean / Delete with external backup).</p>

<div class="im-cards">
  <div class="card im-c <?= count($malF)?'danger':'good' ?>"><div class="lbl">Active threats</div><div class="v" style="color:<?= count($malF)?'var(--dang)':'var(--good)' ?>"><?= count($malF) ?></div><div class="meta">currently malicious files</div></div>
  <div class="card im-c"><div class="lbl">Infected accounts</div><div class="v" style="color:<?= count($infectedAccts)?'var(--dang)':'var(--good)' ?>"><?= count($infectedAccts) ?></div></div>
  <div class="card im-c"><div class="lbl">DB injections</div><div class="v"><?= (int)$dbThreats ?></div></div>
  <div class="card im-c"><div class="lbl">Total detections</div><div class="v"><?= (int)$totalHist ?></div><div class="meta">all-time history</div></div>
  <div class="card im-c"><div class="lbl">Accounts protected</div><div class="v" style="color:var(--good)"><?= (int)$accounts ?></div></div>
  <div class="card im-c"><div class="lbl">Imunify360</div><div class="v" style="font-size:15px"><?= smpro_h($ver?:'active') ?></div><div class="meta"><?= smpro_h($strategy) ?></div></div>
</div>

<div class="card" style="padding:0;overflow:hidden;margin-bottom:14px">
  <div class="im-head"><b>&#9888; Currently Malicious Files</b><span class="meta"><?= count($malF) ?> active · need cleanup</span>
    <?php if ($malF): ?><span style="flex:1"></span>
    <label class="im-selall"><input type="checkbox" id="imAll"> select all on-disk</label>
    <button class="im-mini del" id="imDelSel" type="button" disabled>&#128465; Delete selected (<b id="imN">0</b>)</button><?php endif; ?>
  </div>
  <?php if (!$malF): ?><div class="im-empty" style="color:var(--good)">&#10003; No active malware. Imunify reports the selected scope clean.</div>
  <?php else: ?>
  <div class="im-tablewrap" style="max-height:460px">
    <table class="smpro-table"><thead><tr><th style="width:26px"></th><th>Account</th><th>File</th><th>Malware</th><th class="num">Size</th><th>SHA-256</th><th>Detected</th><th>Actions</th></tr></thead><tbody>
      <?php foreach (array_slice($malF, 0, 500) as $r): $fam = smpro_im_family($r['type'] ?? '');
        $isFile = ($r['resource_type'] ?? '') !== 'db'; $path = (string)($r['file'] ?? ''); $hash = (string)($r['hash'] ?? ''); $sz = (int)($r['size'] ?? 0);
        $imid = (string)($r['id'] ?? ''); $exists = $isFile && strpos($path,'/home/')===0 && @is_file($path); ?>
        <tr>
          <td style="width:26px"><?php if ($exists): ?><input type="checkbox" class="imChk" data-path="<?= smpro_h($path) ?>"><?php endif; ?></td>
          <td class="mono"><b><?= smpro_h($r['username'] ?? '') ?></b></td>
          <td class="mono im-file"><?= $isFile?'':'<span class="b orange">DB</span> ' ?><?= smpro_h($r['file'] ?? $r['db_name'] ?? '—') ?><?= ($isFile && !$exists && strpos($path,'/home/')===0)?' <span class="b gray" title="No longer on disk — Imunify already cleaned/quarantined it">stale</span>':'' ?></td>
          <td><span class="b red"><?= smpro_h($fam ?: 'malware') ?></span></td>
          <td class="num"><?= $sz?smpro_h(number_format($sz/1024,1)).' KB':'—' ?></td>
          <td class="mono im-hash" title="<?= smpro_h($hash) ?>"><?= $hash?smpro_h(substr($hash,0,16)).'…':'—' ?></td>
          <td class="mono"><?= isset($r['created'])?smpro_h(date('Y-m-d H:i', (int)$r['created'])):'—' ?></td>
          <td class="im-act">
            <?php if ($isFile && strpos($path,'/home/')===0): ?>
              <button class="im-mini hunt" type="button" data-sha="<?= smpro_h($hash) ?>" data-size="<?= $sz ?>" data-path="<?= smpro_h($path) ?>" <?= ($hash&&$sz)?'':'disabled title="No hash/size from Imunify"' ?>>&#128269; Hunt hash</button>
              <?php if ($exists): ?>
                <button class="im-mini del" type="button" data-path="<?= smpro_h($path) ?>">&#128465; Delete</button>
              <?php else: ?>
                <button class="im-mini clear" type="button" data-imid="<?= smpro_h($imid) ?>" title="The file is already gone; remove this stale entry from Imunify's list">&#129529; Clear stale</button>
              <?php endif; ?>
            <?php else: ?><span class="meta">Imunify / DB</span><?php endif; ?>
          </td>
        </tr>
        <tr class="im-huntrow" style="display:none"><td></td><td colspan="7" class="im-huntcell"></td></tr>
      <?php endforeach; ?>
    </tbody></table>
  </div>
  <div class="im-note"><b>Hunt hash</b> searches the whole server for other files with the same SHA-256 (same payload on other accounts) — bounded &amp; throttled, prefiltered by exact size. <b>Delete</b> removes the file for real: it is backed up OUTSIDE the account in <code>/home/backup/detections</code> first, an action report is written (downloadable, restorable from Forensics), then the file is unlinked.</div>
  <?php endif; ?>
</div>

<div class="ar-two">
  <div class="card" style="padding:0;overflow:hidden">
    <div class="im-head"><b>Top Infected Accounts</b></div>
    <div class="im-tablewrap" style="max-height:300px"><table class="smpro-table"><thead><tr><th>Account</th><th class="num">Active threats</th><th>Investigate</th></tr></thead><tbody>
      <?php if (!$infectedAccts): ?><tr><td colspan="3" class="im-empty">No infected accounts.</td></tr>
      <?php else: foreach (array_slice($infectedAccts, 0, 20, true) as $u=>$n): ?>
        <tr><td class="mono"><b><?= smpro_h($u) ?></b></td><td class="num"><span class="b red"><?= (int)$n ?></span></td><td><a class="fa-lnk" href="index.cgi?page=imunify360-reports&user=<?= urlencode($u) ?>&days=<?= $days ?>">Filter</a> <a class="fa-lnk" href="index.cgi?page=account-audit&audit_user=<?= urlencode($u) ?>">Audit</a></td></tr>
      <?php endforeach; endif; ?>
    </tbody></table></div>
  </div>
  <div class="card" style="padding:0;overflow:hidden">
    <div class="im-head"><b>Malware Families</b><span class="meta">signature types</span></div>
    <div class="im-tablewrap" style="max-height:300px"><table class="smpro-table"><tbody>
      <?php if (!$families): ?><tr><td class="im-empty">No malware families in range.</td></tr>
      <?php else: $fmx=max($families); foreach (array_slice($families,0,15,true) as $f=>$n): ?>
        <tr><td style="width:62%"><span class="mono"><?= smpro_h($f) ?></span><div class="bar" style="margin-top:5px"><i style="width:<?= max(3,round($n/$fmx*100)) ?>%;background:var(--dang)"></i></div></td><td class="num"><b><?= (int)$n ?></b></td></tr>
      <?php endforeach; endif; ?>
    </tbody></table></div>
  </div>
</div>

<div class="card" style="padding:0;overflow:hidden;margin-top:14px">
  <div class="im-head"><b>Detection History</b><span class="meta"><?= count($histF) ?> events · last <?= (int)$days ?>d<?= $user!==''?' · '.smpro_h($user):'' ?></span></div>
  <div class="im-tablewrap" style="max-height:460px">
    <table class="smpro-table"><thead><tr><th>Time</th><th>Account</th><th>Type</th><th>Path / DB</th><th>Malware</th><th>Event</th></tr></thead><tbody>
      <?php if (!$histF): ?><tr><td colspan="6" class="im-empty">No detection events in this range.</td></tr>
      <?php else: foreach (array_slice($histF, 0, 400) as $r): $ev = $r['event'] ?? ''; $fam = smpro_im_family($r['signature_id'] ?? ''); ?>
        <tr>
          <td class="mono"><?= smpro_h(date('Y-m-d H:i', (int)($r['ctime'] ?? 0))) ?></td>
          <td class="mono"><?= smpro_h($r['file_user'] ?? $r['file_owner'] ?? '—') ?></td>
          <td><?= ($r['resource_type'] ?? '')==='db'?'<span class="b orange">DB</span>':'<span class="b gray">file</span>' ?></td>
          <td class="mono im-file"><?= smpro_h($r['path'] ?? ($r['db_name'] ?? '—')) ?></td>
          <td><?= $fam?'<span class="b red">'.smpro_h($fam).'</span>':'<span class="meta">—</span>' ?></td>
          <td><?= $ev==='found'?'<span class="b red">found</span>':(strpos($ev,'cleanup')!==false||strpos($ev,'removed')!==false?'<span class="b green">cleaned</span>':'<span class="b gray">'.smpro_h($ev).'</span>') ?></td>
        </tr>
      <?php endforeach; endif; ?>
    </tbody></table>
  </div>
</div>

<script>
(function(){
  var CSRF = <?= json_encode($csrfIm) ?>;
  function post(body){ return fetch(location.pathname+location.search,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:body}).then(function(r){return r.json();}); }
  function humb(b){ b=+b||0; var u=['B','KB','MB','GB']; var i=0; while(b>=1024&&i<3){b/=1024;i++;} return (i?b.toFixed(1):b)+' '+u[i]; }
  function esc(s){ return String(s==null?'':s).replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];}); }

  // ---- multi-select bulk delete ----
  function imChecked(){ return Array.prototype.slice.call(document.querySelectorAll('.imChk')).filter(function(c){return c.checked;}); }
  function imRefresh(){ var n=imChecked().length; var nE=document.getElementById('imN'); if(nE)nE.textContent=n; var b=document.getElementById('imDelSel'); if(b)b.disabled=n===0; }
  document.addEventListener('change',function(e){
    if(e.target.classList&&e.target.classList.contains('imChk'))imRefresh();
    if(e.target.id==='imAll'){var on=e.target.checked;document.querySelectorAll('.imChk').forEach(function(c){c.checked=on;});imRefresh();}
  });
  var imDel=document.getElementById('imDelSel');
  if(imDel)imDel.addEventListener('click',function(){
    var sel=imChecked(); if(!sel.length)return;
    var files=sel.map(function(c){return c.getAttribute('data-path');});
    if(!confirm('DELETE '+files.length+' selected malware file(s) for real?\n\n'+files.slice(0,8).join('\n')+(files.length>8?'\n…(+'+(files.length-8)+' more)':'')+'\n\nEach is backed up OUTSIDE the account first; reports written; restorable from Forensics.'))return;
    imDel.disabled=true; var i=0,ok=0;
    (function next(){
      if(i>=files.length){ imDel.innerHTML='&#128465; Delete selected (<b id="imN">0</b>)'; alert('Deleted '+ok+'/'+files.length+' file(s).'); setTimeout(function(){location.reload();},800); return; }
      var f=files[i++]; imDel.textContent='Deleting '+i+'/'+files.length+'…';
      var fd=new URLSearchParams(); fd.set('im_action','delete_file'); fd.set('smpro_csrf',CSRF); fd.set('file',f);
      post(fd.toString()).then(function(j){ if(j&&j.ok){ ok++; sel.forEach(function(c){if(c.getAttribute('data-path')===f){var tr=c.closest('tr');if(tr)tr.style.opacity='.5';c.checked=false;c.disabled=true;}}); } next(); }).catch(next);
    })();
  });

  // ---- Hunt the same hash across the server ----
  document.addEventListener('click', function(e){
    var b = e.target.closest('.im-mini.hunt'); if(!b) return;
    var tr = b.closest('tr'); var cell = tr.nextElementSibling.querySelector('.im-huntcell');
    var row = tr.nextElementSibling; row.style.display='';
    cell.innerHTML = '<div class="im-hbox">&#9203; Hunting the server for files with this SHA-256… (bounded &amp; throttled, may take up to ~1 min)</div>';
    b.disabled = true;
    var fd = new URLSearchParams(); fd.set('im_action','hash_search'); fd.set('smpro_csrf',CSRF);
    fd.set('sha', b.getAttribute('data-sha')); fd.set('size', b.getAttribute('data-size'));
    post(fd.toString()).then(function(j){
      b.disabled = false;
      if(!j.ok){ cell.innerHTML='<div class="im-hbox err">'+esc(j.msg||'Hunt failed.')+'</div>'; return; }
      if(!j.matches.length){ cell.innerHTML='<div class="im-hbox ok">&#10003; No other file on the server matches this hash (scanned '+j.candidates+' same-size candidate(s)).</div>'; return; }
      var h = '<div class="im-hbox warn">&#9888; '+j.matches.length+' file(s) on the server share this exact payload (SHA-256 match). Delete each below — real removal, backed up first.</div>';
      h += '<table class="im-htab"><thead><tr><th>Account</th><th>Path</th><th class="num">Size</th><th>Modified</th><th>Action</th></tr></thead><tbody>';
      j.matches.forEach(function(m){
        h += '<tr><td class="mono"><b>'+esc(m.account)+'</b></td><td class="mono im-file">'+esc(m.path)+'</td><td class="num">'+humb(m.size)+'</td><td class="mono">'+(m.mtime?new Date(m.mtime*1000).toISOString().slice(0,16).replace('T',' '):'—')+'</td>'
          + '<td><button class="im-mini del" type="button" data-path="'+esc(m.path)+'">&#128465; Delete</button></td></tr>';
      });
      h += '</tbody></table>';
      cell.innerHTML = h;
    }).catch(function(){ b.disabled=false; cell.innerHTML='<div class="im-hbox err">Hunt request failed.</div>'; });
  });

  // ---- REAL delete (+ report shown during deletion) ----
  document.addEventListener('click', function(e){
    var b = e.target.closest('.im-mini.del'); if(!b) return;
    var path = b.getAttribute('data-path')||'';
    if(path.indexOf('/home/')!==0){ alert('Only files under /home/<account>/ can be deleted.'); return; }
    if(!confirm('DELETE this file for real?\n\n'+path+'\n\nIt is backed up OUTSIDE the account (/home/backup/detections) first, an action report is written, and it is restorable from Forensics.')) return;
    var old = b.innerHTML; b.disabled=true; b.innerHTML='&#9203; Deleting…';
    var fd = new URLSearchParams(); fd.set('im_action','delete_file'); fd.set('smpro_csrf',CSRF); fd.set('file',path);
    post(fd.toString()).then(function(j){
      var host = b.closest('tr');
      if(!j.ok){ b.disabled=false; b.innerHTML=old; alert('Delete failed: '+(j.msg||'unknown')); return; }
      // mark the row done + show the deletion report inline
      var rep = '<div class="im-rep">&#9989; <b>Deleted.</b> '+esc(j.file)
        + '<div class="im-rep-g"><span>Account: <b>'+esc(j.account)+'</b></span><span>Size: <b>'+humb(j.size)+'</b></span>'
        + '<span class="mono">SHA-256: '+esc((j.sha256||'').slice(0,24))+'…</span></div>'
        + '<div class="im-rep-g"><span class="mono">Backup: '+esc(j.backup)+'</span></div>'
        + '<a class="im-mini" style="display:inline-block;margin-top:6px;text-decoration:none" href="'+esc(j.report_url)+'" target="_blank">&#128196; Download HTML report (#'+esc(j.report)+')</a></div>';
      // if the delete came from a hunt sub-row, strike that line; otherwise replace the malicious row's action cell
      var actCell = host.querySelector('.im-act') || b.parentNode;
      host.style.opacity='.6';
      if(host.classList.contains('im-huntrow')||host.parentNode.closest('.im-huntcell')){ b.outerHTML='<span class="b green">deleted</span>'; }
      else { actCell.innerHTML='<span class="b green">deleted</span>'; }
      // append the report under the row
      var holder = host.classList.contains('im-act')? host : host;
      var note = document.createElement('div'); note.innerHTML = rep;
      // place report into nearest hunt cell if present, else after the file cell
      var fileCell = host.querySelector('.im-file') || host;
      fileCell.appendChild(note);
    }).catch(function(){ b.disabled=false; b.innerHTML=old; alert('Delete request failed.'); });
  });

  // ---- Clear a STALE entry (file already gone) from Imunify's list ----
  document.addEventListener('click', function(e){
    var b = e.target.closest('.im-mini.clear'); if(!b) return;
    var imid = b.getAttribute('data-imid')||'';
    if(!confirm('Remove this STALE entry from Imunify\'s malicious list?\n\nThe file is already gone from disk (Imunify cleaned/quarantined it). This only clears the leftover list entry — nothing on disk is touched.')) return;
    var old=b.innerHTML; b.disabled=true; b.innerHTML='&#9203; Clearing…';
    var fd=new URLSearchParams(); fd.set('im_action','clear_list'); fd.set('smpro_csrf',CSRF); fd.set('imid',imid);
    post(fd.toString()).then(function(j){
      if(!j.ok){ b.disabled=false; b.innerHTML=old; alert('Clear failed: '+(j.msg||'unknown')); return; }
      b.outerHTML='<span class="b green">cleared</span>';
      setTimeout(function(){ location.reload(); }, 900);
    }).catch(function(){ b.disabled=false; b.innerHTML=old; alert('Clear request failed.'); });
  });
})();
</script>
<?php endif; ?>

<style>
.im-act{white-space:nowrap}
.im-mini{font-size:11px;font-weight:700;border:1px solid var(--line);background:#fff;color:var(--ink);border-radius:7px;padding:4px 9px;cursor:pointer;margin:1px}
.im-mini.hunt{border-color:#c7d2fe;background:#eef2ff;color:#3730a3}
.im-mini.del{border-color:#fecaca;background:#fef2f2;color:#b42318}
.im-mini.clear{border-color:#cdd9fb;background:#eef3ff;color:#3056b8}
.im-selall{display:flex;align-items:center;gap:6px;font-size:12px;font-weight:600;color:#475569;cursor:pointer}
#imDelSel[disabled]{opacity:.45;cursor:not-allowed}
.im-mini:disabled{opacity:.5;cursor:not-allowed}
.im-hbox{padding:9px 12px;border-radius:9px;font-size:12px;margin:6px 0;background:#f1f5f9;color:#334155}
.im-hbox.ok{background:var(--good-bg);color:#0e7c4a}.im-hbox.warn{background:var(--warn-bg);color:#8a6516}.im-hbox.err{background:var(--dang-bg);color:var(--dang)}
.im-htab{width:100%;border-collapse:collapse;font-size:12px;margin-bottom:8px}
.im-htab th,.im-htab td{padding:6px 10px;border-bottom:1px solid var(--line);text-align:left}.im-htab th{font-size:10px;text-transform:uppercase;color:var(--muted)}.im-htab td.num,.im-htab th.num{text-align:right}
.im-huntcell{background:#fbfcff;padding:6px 14px !important}
.im-rep{margin:6px 0;padding:9px 12px;border-radius:9px;background:var(--good-bg);border:1px solid #bbf7d0;font-size:12px;color:#14532d}
.im-rep-g{display:flex;gap:14px;flex-wrap:wrap;margin-top:4px}.im-rep-g span{color:#3f6b4e}
<?php /* original styles continue below */ ?>
.svc-kicker{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--brand);font-weight:800}
.im-missing{background:var(--warn-bg);color:#8a6516;border-left:4px solid var(--warn);font-size:13px;margin:14px 0}
.im-bar{display:flex;gap:12px;align-items:flex-end;flex-wrap:wrap;margin:14px 0;background:#fff;border:1px solid var(--line);border-radius:14px;padding:14px 16px}
.im-fld{display:flex;flex-direction:column;gap:4px;font-size:11px;text-transform:uppercase;color:var(--muted);font-weight:700}
.tp-sel,.tp-in{border:1px solid var(--line);border-radius:9px;padding:8px 11px;font-size:13px}
.tp-btn{border:1px solid var(--line);border-radius:9px;padding:9px 16px;font-size:13px;font-weight:600;cursor:pointer;text-decoration:none;color:var(--ink)}.tp-btn.primary{background:var(--brand);color:#fff;border-color:var(--brand)}.tp-btn.green{background:var(--good);color:#fff;border-color:var(--good)}
.im-cards{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin:14px 0}
@media(max-width:1100px){.im-cards{grid-template-columns:repeat(3,1fr)}}@media(max-width:600px){.im-cards{grid-template-columns:repeat(2,1fr)}}
.im-c{padding:14px 16px}.im-c.danger{border-top:3px solid var(--dang)}.im-c.good{border-top:3px solid var(--good)}
.im-c .lbl{font-size:11px;color:var(--muted);text-transform:uppercase;font-weight:700}.im-c .v{font-size:23px;font-weight:800;margin-top:4px}.im-c .meta{font-size:11px;color:var(--muted)}
.im-head{padding:12px 16px;border-bottom:1px solid var(--line);font-weight:700;font-size:14px;display:flex;align-items:center;gap:10px;flex-wrap:wrap}.im-head .meta{margin-left:auto;color:var(--muted);font-size:12px}
.im-note{padding:10px 16px;background:var(--brand-bg);color:#26408b;font-size:12px;border-top:1px solid var(--line)}
.im-empty{padding:18px;color:var(--muted);text-align:center}
.im-tablewrap{overflow:auto}.im-tablewrap thead th{position:sticky;top:0;background:#fafbfe;z-index:1;box-shadow:inset 0 -1px 0 var(--line)}
.smpro-table{width:100%;border-collapse:collapse;font-size:12px}
.smpro-table th,.smpro-table td{padding:7px 12px;text-align:left;border-bottom:1px solid var(--line);white-space:nowrap}
.smpro-table th{font-size:11px;text-transform:uppercase;color:var(--muted)}.smpro-table td.num,.smpro-table th.num{text-align:right}
.mono{font-family:ui-monospace,Consolas,monospace}.im-file{white-space:normal;word-break:break-all;max-width:380px}.im-hash{color:var(--muted)}
.bar{height:7px;border-radius:8px;background:#eef1f6;overflow:hidden}.bar>i{display:block;height:100%;border-radius:8px}
.fa-lnk{color:var(--brand);text-decoration:none;font-size:11px;border:1px solid var(--line);padding:1px 6px;border-radius:6px}
.ar-two{display:grid;grid-template-columns:1fr 1fr;gap:14px}@media(max-width:900px){.ar-two{grid-template-columns:1fr}}
.b{display:inline-block;font-size:11px;font-weight:700;padding:2px 8px;border-radius:20px}
.b.red{background:var(--dang-bg);color:var(--dang)}.b.green{background:var(--good-bg);color:var(--good)}.b.orange{background:var(--warn-bg);color:var(--warn)}.b.gray{background:#f1f5f9;color:#475569}
.meta{color:var(--muted)}
</style>
<?php
smpro_layout_footer();
