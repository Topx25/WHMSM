<?php
/**
 * modules/backup-monitor.php - JetBackup monitoring + auto-retry on failure.
 *
 * Reads JetBackup5 jobs (jetbackup5api) and computes each job's last-run status
 * from last_run vs last_completed (completed ⇒ last_completed ≥ last_run).
 * Shows the schedule, last result and recent alerts. Failed jobs can be re-run
 * on demand (runBackupJobManually), and an "auto-retry" cron re-runs failed
 * jobs until they complete (bounded). Read-only by default; actions are
 * POST+CSRF+root+audit.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

define('SMPRO_BM_BIN', '/usr/bin/jetbackup5api');
require_once SMPRO_INCLUDES . '/backupmon.php';   // SMPRO_BM_* + the cron installer live there so cron_sync can re-create the cron
define('SMPRO_BM_STATE', SMPRO_VARLIB . '/state/backup_retry.json');

function smpro_bm_available() { return is_executable(SMPRO_BM_BIN); }
/** Last JetBackup API failure text (licence expired, API disabled, daemon down...). Set-only - never cleared by a
 *  later success, so one broken call still surfaces even if other calls on the page succeed. */
function smpro_bm_err(?string $set = null): string { static $e = ''; if ($set !== null && $e === '') $e = $set; return $e; }

function smpro_bm_api($func, $data = '') {
    $out = (string)@shell_exec('timeout 60 ' . SMPRO_BM_BIN . ' -F ' . escapeshellarg($func) . ' -O json' . ($data !== '' ? ' -D ' . escapeshellarg($data) : '') . ' 2>/dev/null');
    $j = json_decode($out, true);
    if (!is_array($j)) { smpro_bm_err('JetBackup returned no readable response for "' . $func . '" (API disabled, or jetbackup5api failed to run).'); return []; }
    // JetBackup 5 wraps every reply: success=1 + data, or success=0 + message. On an expired licence / disabled API
    // the reply is success=0 with 'data' holding error text - reading 'data' regardless made a hard failure look
    // like a healthy "no jobs configured" page with green KPIs.
    if (array_key_exists('success', $j) && (int)$j['success'] !== 1) {
        $m = trim((string)($j['message'] ?? $j['error'] ?? ''));
        if ($m === '' && isset($j['data']) && is_string($j['data'])) $m = trim($j['data']);
        smpro_bm_err($m !== '' ? $m : 'JetBackup API call "' . $func . '" failed.');
        return [];
    }
    return $j;
}
function smpro_bm_type($t) { return [1=>'Accounts',2=>'Accounts',3=>'JetBackup config',4=>'Directories',5=>'Databases',6=>'Databases'][(int)$t] ?? ('Type ' . (int)$t); }

/** Jobs with computed last-run status. */
function smpro_bm_jobs() {
    $list = smpro_bm_api('listBackupJobs');
    $jobs = $list['data']['jobs'] ?? $list['data'] ?? [];
    if (!is_array($jobs)) return [];
    $out = [];
    foreach ($jobs as $j) {
        $id = (string)($j['_id'] ?? ''); if ($id === '') continue;
        $full = smpro_bm_api('getBackupJob', '_id=' . $id)['data'] ?? $j;
        $lr = (is_numeric($full['last_run'] ?? '') ? (int)($full['last_run'] ?? 0) : (strtotime((string)($full['last_run'] ?? '')) ?: 0));
        $lc = (is_numeric($full['last_completed'] ?? '') ? (int)($full['last_completed'] ?? 0) : (strtotime((string)($full['last_completed'] ?? '')) ?: 0));
        $running = !empty($full['running']);
        if ($running)            $status = 'running';
        elseif ($lr === 0)       $status = 'never';
        elseif ($lc >= $lr)      $status = 'completed';
        else                     $status = 'failed';
        $out[] = [
            'id'=>$id, 'name'=>(string)($full['name'] ?? $id), 'type'=>(int)($full['type'] ?? 0),
            'enabled'=>empty($full['disabled']), 'running'=>$running,   // 'state' is not the enabled flag on JetBackup 5
            'last_run'=>$lr, 'last_completed'=>$lc, 'next_run'=>strtotime((string)($full['next_run'] ?? '')) ?: 0,
            'retry_failed'=>!empty($full['retry_failed']), 'status'=>$status,
        ];
    }
    return $out;
}
function smpro_bm_alerts($limit = 14) {
    $j = smpro_bm_api('listAlerts', 'limit=' . (int)$limit);
    $a = $j['data']['alerts'] ?? $j['data'] ?? [];
    $rows = [];
    foreach ((array)$a as $x) {
        $msg = (string)($x['title'] ?? $x['message'] ?? $x['name'] ?? '');
        if ($msg === '') continue;
        // Severity: prefer JetBackup's own field over guessing from the (possibly reworded/localised) message.
        // We do NOT assume the numeric scale of a `level` int - that is exactly the vendor-format guess that has
        // burned this codebase before - so a numeric level is only SURFACED, not interpreted. A STRING severity
        // (unambiguous) is trusted, and the message-text heuristic is kept as a never-miss safety net: a row is a
        // failure if EITHER signal fires, so a real backup failure is never hidden by wording. Erring toward
        // flagging is the safe direction for a monitor.
        $sevRaw   = $x['level'] ?? $x['severity'] ?? $x['type'] ?? null;
        $sevFail  = is_string($sevRaw) && preg_match('/warn|error|crit|fail|danger|severe/i', $sevRaw);
        $textFail = (bool)preg_match('/fail|error|unable|warning|did not|incomplete/i', $msg);
        $rows[] = ['msg'=>$msg, 'fail'=>($sevFail || $textFail),
                   'level'=>(is_scalar($sevRaw) ? (string)$sevRaw : ''),
                   'created'=>strtotime((string)($x['created'] ?? '')) ?: 0];
    }
    usort($rows, fn($a,$b)=>$b['created']<=>$a['created']);
    return array_slice($rows, 0, $limit);
}

/* ---------- actions ---------- */
$reqMethod = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? getenv('REQUEST_METHOD') ?: 'GET'));
if ($reqMethod === 'POST' && ($_POST['bm_action'] ?? '') === 'retry') {
    smpro_require_valid_csrf('bm'); smpro_require_root();
    header('Content-Type: application/json');
    $id = preg_replace('/[^a-f0-9]/', '', (string)($_POST['id'] ?? ''));
    if ($id === '') { echo json_encode(['ok'=>false,'msg'=>'Bad job id.']); exit; }
    $r = smpro_bm_api('runBackupJobManually', '_id=' . $id);
    $ok = (int)($r['success'] ?? 0) === 1;
    if ($ok) { smpro_cache_bust('bm_jobs2'); smpro_cache_bust('bm_alerts2'); }   // MUST match the render cache keys (...2) or the stale failed state persists for the full TTL
    smpro_audit('backup_retry', ['id'=>$id,'ok'=>$ok]);
    echo json_encode(['ok'=>$ok,'msg'=>$ok ? 'Backup job started — it will run now.' : ('JetBackup error: ' . (string)($r['message'] ?? 'failed'))], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit;
}
if ($reqMethod === 'POST' && ($_POST['bm_action'] ?? '') === 'autoretry') {
    smpro_require_valid_csrf('bm'); smpro_require_root();
    header('Content-Type: application/json');
    $on = ($_POST['enable'] ?? '') === '1';
    $ok = smpro_bm_autoretry_set($on);
    smpro_audit('backup_autoretry', ['enable'=>$on,'ok'=>$ok]);
    echo json_encode(['ok'=>$ok,'on'=>smpro_bm_autoretry_on()], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit;
}

$avail = smpro_bm_available();
// JetBackup API is N+2 shell calls (listBackupJobs + getBackupJob per job + listAlerts), each up to 60s.
// Cache so a render costs at most one sweep per TTL; the retry cron and manual re-run keep it moving.
// The API error has to travel WITH the cached value - a cache hit never re-runs the closure, so a static
// error holder alone would go quiet on the second render and the page would go back to looking healthy.
// Cache keys are versioned (...2): the previous release cached a bare jobs array under 'bm_jobs', and a stale
// hit in the old shape would read as "no jobs" for a full TTL right after the upgrade.
$jobsC = $avail ? smpro_cache_through('bm_jobs2', 120, fn() => ['jobs' => smpro_bm_jobs(), 'err' => smpro_bm_err()]) : ['jobs'=>[], 'err'=>''];
$jobs  = (array)($jobsC['jobs'] ?? []);
$apiErr = trim((string)($jobsC['err'] ?? ''));
$alertsC = $avail ? smpro_cache_through('bm_alerts2', 120, fn() => ['alerts' => smpro_bm_alerts(), 'err' => smpro_bm_err()]) : ['alerts'=>[], 'err'=>''];
$alerts  = (array)($alertsC['alerts'] ?? []);
if ($apiErr === '') $apiErr = trim((string)($alertsC['err'] ?? ''));
$autoOn = smpro_bm_autoretry_on();
$nFail = 0; $nRun = 0; foreach ($jobs as $j) { if ($j['status']==='failed') $nFail++; if ($j['status']==='running') $nRun++; }
$retryState = is_file(SMPRO_BM_STATE) ? (json_decode((string)@file_get_contents(SMPRO_BM_STATE), true) ?: []) : [];
$csrf = smpro_csrf_generate('bm');

smpro_audit('backup_monitor_view', ['jobs'=>count($jobs),'failed'=>$nFail]);
smpro_layout_header('Backup Monitor');
$badge = ['completed'=>['good','&#10003; Completed'],'failed'=>['red','&#10007; Failed / incomplete'],'running'=>['blue','&#9889; Running'],'never'=>['gray','never run']];
?>
<div class="svc-kicker">Backups</div>
<h1 class="h" style="margin:2px 0 4px">Backup Monitor</h1>
<p class="sub">JetBackup job status with auto-retry on failure. A run is <b>Completed</b> when its finish time catches the start time; otherwise it is <b>Failed/incomplete</b> and can be re-run until it finishes.</p>

<?php if (!$avail): ?>
<div class="card" style="padding:18px;color:var(--muted)">JetBackup5 (<span class="mono">jetbackup5api</span>) was not found on this server. This page activates automatically once JetBackup is installed.</div>
<?php else: ?>

<?php if ($apiErr !== ''): ?>
<div class="card" style="padding:14px 16px;margin:12px 0;border-left:4px solid var(--dang)">
  <b style="color:var(--dang)">&#9888; JetBackup is installed but its API is not answering</b>
  <div class="meta" style="margin-top:6px">JetBackup said: <span class="mono"><?= smpro_h(mb_substr($apiErr, 0, 300)) ?></span></div>
  <div class="meta" style="margin-top:6px">The figures below are <b>not</b> a statement that your backups are fine — nothing could be read. This is usually an expired JetBackup licence or a disabled API. Check JetBackup &rsaquo; Settings, then reload this page.</div>
</div>
<?php endif; ?>

<div class="bm-kpis">
  <div class="kpi <?= $apiErr!==''?'crit':'' ?>"><div class="kn"><?= $apiErr!=='' ? '?' : count($jobs) ?></div><div class="kl">Backup jobs</div></div>
  <div class="kpi <?= $nRun?'blue':'' ?>"><div class="kn"><?= $nRun ?></div><div class="kl">Running now</div></div>
  <div class="kpi <?= $nFail?'crit':'' ?>"><div class="kn"><?= $nFail ?></div><div class="kl">Failed / incomplete</div></div>
  <div class="kpi <?= $autoOn?'good':'' ?>"><div class="kn" style="font-size:18px"><?= $autoOn?'ON':'OFF' ?></div><div class="kl">Auto-retry</div></div>
</div>

<div class="bm-auto">
  <div>
    <b>&#128260; Auto-retry failed backups</b>
    <div class="meta" style="font-size:12px">When ON, a cron every 20 min re-runs any failed job (up to 5 attempts per failure) until it completes. Uses JetBackup’s own <span class="mono">runBackupJobManually</span>.</div>
  </div>
  <label class="bm-switch"><input type="checkbox" id="bmAuto" <?= $autoOn?'checked':'' ?>><span>auto-retry</span></label>
</div>

<div class="card" style="padding:0;overflow:hidden;margin:14px 0;border-top:3px solid <?= ($nFail||$apiErr!=='')?'var(--dang)':'var(--good)' ?>">
  <div class="bm-head"><b>Backup jobs</b><span class="meta">status from last_run vs last_completed</span></div>
  <div class="bm-tablewrap"><table class="smpro-table"><thead><tr><th>Job</th><th>Type</th><th>Last run</th><th>Last completed</th><th>Next run</th><th>Status</th><th>Action</th></tr></thead><tbody>
    <?php if (!$jobs && $apiErr !== ''): ?><tr><td colspan="7" class="bm-empty">Could not read the job list — the JetBackup API returned an error (see above).</td></tr>
    <?php elseif (!$jobs): ?><tr><td colspan="7" class="bm-empty">No backup jobs found.</td></tr>
    <?php else: foreach ($jobs as $j): [$bc,$bl] = $badge[$j['status']] ?? ['gray',$j['status']]; $att = (int)($retryState[$j['id']]['attempts'] ?? 0); ?>
      <tr class="<?= $j['status']==='failed'?'bm-fail':'' ?>">
        <td><b><?= smpro_h($j['name']) ?></b><?= $j['retry_failed']?' <span class="b gray" title="JetBackup retries failed items">retry-items</span>':'' ?></td>
        <td class="mono"><?= smpro_h(smpro_bm_type($j['type'])) ?></td>
        <td class="mono"><?= $j['last_run']?smpro_h(date('Y-m-d H:i',$j['last_run'])):'—' ?></td>
        <td class="mono"><?= $j['last_completed']?smpro_h(date('Y-m-d H:i',$j['last_completed'])):'—' ?></td>
        <td class="mono"><?= $j['next_run']?smpro_h(date('Y-m-d H:i',$j['next_run'])):'—' ?></td>
        <td><span class="b <?= smpro_h($bc) ?>"><?= smpro_h($bl) ?></span><?php if($att>0):?><div class="meta" style="font-size:10px">auto-retried <?= $att ?>×</div><?php endif;?></td>
        <td><button class="fa-lnk bmRetry" data-id="<?= smpro_h($j['id']) ?>" data-name="<?= smpro_h($j['name']) ?>" type="button"><?= $j['status']==='failed'?'&#128260; Retry now':'&#9654; Run now' ?></button></td>
      </tr>
    <?php endforeach; endif; ?>
  </tbody></table></div>
</div>

<div class="card" style="padding:0;overflow:hidden;margin:14px 0">
  <div class="bm-head"><b>Recent backup events (JetBackup alerts)</b></div>
  <div class="bm-tablewrap" style="max-height:340px"><table class="smpro-table"><tbody>
    <?php if (!$alerts): ?><tr><td class="bm-empty">No recent alerts.</td></tr>
    <?php else: foreach ($alerts as $a): ?><tr><td style="white-space:nowrap"><span class="b <?= $a['fail']?'red':'green' ?>"><?= $a['fail']?'issue':'ok' ?></span></td><td class="mono"><?= $a['created']?smpro_h(date('Y-m-d H:i',$a['created'])):'' ?></td><td><?= smpro_h($a['msg']) ?></td></tr><?php endforeach; endif; ?>
  </tbody></table></div>
</div>
<?php endif; ?>

<style>
.svc-kicker{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--brand);font-weight:800}
.bm-kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:14px 0}@media(max-width:720px){.bm-kpis{grid-template-columns:1fr 1fr}}
.kpi{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px;text-align:center}
.kpi .kn{font-size:24px;font-weight:800;line-height:1}.kpi .kl{font-size:11px;text-transform:uppercase;color:var(--muted);margin-top:6px}
.kpi.crit{border-color:#f3c9c9;background:var(--dang-bg)}.kpi.crit .kn{color:var(--dang)}.kpi.good{border-color:#bfe6cd;background:var(--card)}.kpi.good .kn{color:var(--good)}.kpi.blue{border-color:#cdd9fb;background:var(--card)}.kpi.blue .kn{color:var(--brand)}
.bm-auto{display:flex;align-items:center;gap:14px;justify-content:space-between;flex-wrap:wrap;background:var(--card);border:1px solid var(--line);border-radius:14px;padding:14px 16px;margin:14px 0}
.bm-switch{display:inline-flex;align-items:center;gap:8px;cursor:pointer;font-size:12px;font-weight:700;color:var(--muted)}
.bm-switch input{width:18px;height:18px}
.bm-head{padding:12px 16px;border-bottom:1px solid var(--line);font-weight:700;font-size:14px;display:flex;gap:10px;align-items:center}.bm-head .meta{margin-left:auto;color:var(--muted);font-size:12px}
.bm-tablewrap{overflow:auto}.bm-tablewrap thead th{position:sticky;top:0;background:var(--card);box-shadow:inset 0 -1px 0 var(--line)}
.smpro-table{width:100%;border-collapse:collapse;font-size:12px}.smpro-table th,.smpro-table td{padding:8px 12px;text-align:left;border-bottom:1px solid var(--line);white-space:nowrap;vertical-align:top}
.smpro-table th{font-size:11px;text-transform:uppercase;color:var(--muted)}
.bm-fail td{background:var(--dang-bg)}.mono{font-family:ui-monospace,Consolas,monospace}.bm-empty{padding:18px;color:var(--muted);text-align:center}
.fa-lnk{color:var(--brand);text-decoration:none;font-size:11px;border:1px solid var(--line);padding:2px 9px;border-radius:6px;background:var(--card);cursor:pointer;font-weight:700}.fa-lnk:hover{background:var(--brand-bg)}
.b{display:inline-block;font-size:11px;font-weight:700;padding:2px 8px;border-radius:20px}.b.good,.b.green{background:var(--good-bg);color:var(--good)}.b.red{background:var(--dang-bg);color:var(--dang)}.b.blue{background:var(--brand-bg);color:var(--brand)}.b.gray{background:var(--card);color:#475569}
.meta{color:var(--muted)}
</style>
<script>
(function(){
  var CSRF=<?= json_encode($csrf) ?>;
  function post(b){return fetch(location.pathname+location.search,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:b});}
  document.addEventListener('click',function(e){
    var b=e.target.closest&&e.target.closest('.bmRetry'); if(!b)return;
    if(!confirm('Run the backup job "'+(b.getAttribute('data-name')||'')+'" now?'))return;
    var lbl=b.innerHTML;b.disabled=true;b.textContent='…';
    var fd=new URLSearchParams();fd.set('bm_action','retry');fd.set('smpro_csrf',CSRF);fd.set('id',b.getAttribute('data-id'));
    post(fd.toString()).then(function(r){return r.json();}).then(function(j){
      if(j&&j.ok){b.textContent='✓ started';b.style.color='var(--good)';}else{b.disabled=false;b.innerHTML=lbl;alert((j&&j.msg)||'Failed');}
    }).catch(function(){b.disabled=false;b.innerHTML=lbl;alert('Request failed');});
  });
  var auto=document.getElementById('bmAuto');
  if(auto)auto.addEventListener('change',function(){
    var on=auto.checked;auto.disabled=true;
    var fd=new URLSearchParams();fd.set('bm_action','autoretry');fd.set('smpro_csrf',CSRF);fd.set('enable',on?'1':'0');
    post(fd.toString()).then(function(r){return r.json();}).then(function(j){auto.disabled=false;if(!j||!j.ok){auto.checked=!on;alert('Could not change auto-retry.');}else{auto.checked=j.on;}}).catch(function(){auto.disabled=false;auto.checked=!on;alert('Request failed');});
  });
})();
</script>
<?php
smpro_layout_footer();
