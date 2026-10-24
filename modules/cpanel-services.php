<?php
/**
 * modules/cpanel-services.php - Service Manager: live Running/Down summary, one-click Fix/Start on stopped
 * services, and the Service Monitor (auto-restart + notifications). The catalog, status, controls and the
 * monitor all live in includes/svcmon.php (shared with the cron worker bin/svcmon.php and the Dashboard cards).
 * Controls and the monitor config are POST + CSRF + root + confirmation + audit.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

$reqMethod = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? getenv('REQUEST_METHOD') ?: 'GET'));

/* ---------- POST: uninstall an installed add-on (CSF / Imunify / ...) ---------- */
if ($reqMethod === 'POST' && ($_POST['svc_action'] ?? '') === 'uninstall') {
    smpro_require_valid_csrf('svc_ctl'); smpro_require_root();
    header('Content-Type: application/json');
    $key = preg_replace('/[^a-z0-9_]/', '', (string)($_POST['svc'] ?? ''));
    $r = function_exists('smpro_svc_uninstall') ? smpro_svc_uninstall($key) : ['ok'=>false,'msg'=>'unavailable'];
    smpro_audit('cpanel_service_uninstall', ['svc'=>$key, 'ok'=>!empty($r['ok']), 'gone'=>!empty($r['gone']), 'actor'=>smpro_current_actor()]);
    echo json_encode(['ok'=>!empty($r['ok']), 'gone'=>!empty($r['gone']), 'manual'=>!empty($r['manual']), 'msg'=>$r['msg'] ?? ''], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}

/* ---------- POST: service control (start/restart/stop) ---------- */
if ($reqMethod === 'POST' && ($_POST['svc_action'] ?? '') !== '') {
    smpro_require_valid_csrf('svc_ctl'); smpro_require_root();
    $action = preg_replace('/[^a-z]/', '', (string)$_POST['svc_action']);
    $key = preg_replace('/[^a-z0-9_]/', '', (string)($_POST['svc'] ?? ''));
    $r = smpro_svcmon_control($key, $action);
    smpro_audit('cpanel_service_' . $action, ['svc'=>$key, 'ok'=>!empty($r['ok']), 'actor'=>smpro_current_actor()]);
    echo json_encode(['ok'=>!empty($r['ok']), 'refused'=>!empty($r['refused']), 'active'=>$r['active'] ?? null, 'state_label'=>$r['state_label'] ?? '', 'cls'=>$r['cls'] ?? '', 'msg'=>$r['msg'] ?? ''], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}

/* ---------- POST: ignore / un-ignore (mute) a service ---------- */
if ($reqMethod === 'POST' && ($_POST['svc_ignore'] ?? '') !== '') {
    smpro_require_valid_csrf('svc_ctl'); smpro_require_root();
    $key = preg_replace('/[^a-z0-9_]/', '', (string)($_POST['svc'] ?? ''));
    $on  = ((string)$_POST['svc_ignore'] === 'on');
    $ok  = smpro_svc_set_ignore($key, $on);
    smpro_audit('svc_ignore', ['svc'=>$key, 'on'=>$on?1:0, 'ok'=>$ok, 'actor'=>smpro_current_actor()]);
    echo json_encode(['ok'=>$ok, 'msg'=>$ok ? ($on ? 'Muted — this service will no longer be flagged as down or alerted.' : 'Un-muted — it will be flagged again if stopped.') : 'Could not save.'], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}

/* ---------- POST: save Service Monitor configuration ---------- */
if ($reqMethod === 'POST' && ($_POST['svc_mon'] ?? '') === 'save') {
    smpro_require_valid_csrf('svc_ctl'); smpro_require_root();
    $mon = array_map(fn($x)=>preg_replace('/[^a-z0-9_]/', '', (string)$x), (array)($_POST['monitor'] ?? []));
    $ok = smpro_svcmon_cfg_save([
        'enabled'     => ($_POST['enabled'] ?? '') === '1',
        'monitor'     => $mon,
        'autorestart' => ($_POST['autorestart'] ?? '') === '1',
        'notify'      => ($_POST['notify'] ?? '') === '1',
        'recovery'    => ($_POST['recovery'] ?? '') === '1',
    ]);
    $cfg = smpro_svcmon_cfg();
    smpro_audit('svcmon_cfg', ['enabled'=>$cfg['enabled'], 'watch'=>count($cfg['monitor']), 'autorestart'=>$cfg['autorestart'], 'notify'=>$cfg['notify']]);
    echo json_encode(['ok'=>$ok, 'enabled'=>$cfg['enabled'], 'watch'=>count($cfg['monitor']),
        'msg'=>$ok ? ($cfg['enabled'] ? ('Service Monitor is ON — watching ' . count($cfg['monitor']) . ' service(s), checking every 3 min.') : 'Service Monitor is OFF.') : 'Could not save.'], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}

/* ---------- POST: schedule / cancel an automatic reboot (re-verified for safety at fire time) ---------- */
if ($reqMethod === 'POST' && ($_POST['reboot_action'] ?? '') !== '') {
    smpro_require_valid_csrf('svc_ctl'); smpro_require_root();
    header('Content-Type: application/json');
    $act = preg_replace('/[^a-z]/', '', (string)$_POST['reboot_action']);
    if ($act === 'cancel') { smpro_reboot_clear(); smpro_audit('reboot_cancel', ['actor'=>smpro_current_actor()]); echo json_encode(['ok'=>true, 'msg'=>'Scheduled reboot cancelled.']); exit; }
    if ($act === 'fixfstabtmp' && function_exists('smpro_reboot_fix_fstab_tmp')) { echo json_encode(smpro_reboot_fix_fstab_tmp(), JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit; }
    if ($act === 'schedule') {
        // Interpret the picked time in the SERVER's timezone (strtotime uses it) to match the "server time"
        // label. The browser used to convert to its OWN local epoch, so an admin in a different timezone
        // scheduled the reboot off by their UTC offset. Fall back to a raw epoch for older clients.
        $when = trim((string)($_POST['when'] ?? ''));
        $at = $when !== '' ? (int)strtotime($when) : (int)($_POST['at'] ?? 0);
        if ($at < time() + 60) { echo json_encode(['ok'=>false, 'msg'=>'Pick a time at least a minute in the future (server time).']); exit; }
        $target = (($_POST['target'] ?? '') === 'current') ? 'current' : 'next';
        $r = smpro_reboot_sched_save(['enabled'=>true, 'at'=>$at, 'target'=>$target]);
        echo json_encode($r, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit;
    }
    if ($act === 'readiness') { echo json_encode(['ok'=>true, 'r'=>smpro_reboot_readiness()], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit; }
    echo json_encode(['ok'=>false, 'msg'=>'unknown action']); exit;
}

/* ---------- gather ---------- */
// Render reads the CRON-refreshed cached scan (45s) instead of a fresh ~40-shell-call probe on every load.
// smpro_svc_scan_cached() returns a TUPLE [rows, ts, wasCached] - it must be destructured, not wrapped in
// array_values(). Wrapping it produced a 3-element array (rows-array, int, bool) whose members have no
// 'installed'/'active' keys, so every count came out 0 and the whole page rendered empty. Dashboard and
// insight.php always destructured it correctly; this page was the only one that did not.
[$rows, $svcScanTs, $svcScanCached] = function_exists('smpro_svc_scan_cached')
    ? smpro_svc_scan_cached(45)
    : [smpro_svc_scan(), time(), false];
$rows = array_values(is_array($rows) ? $rows : []);
$instN = count(array_filter($rows, fn($r)=>$r['installed']));
$actN  = count(array_filter($rows, fn($r)=>$r['active']));
$downRows = array_values(array_filter($rows, fn($r)=>$r['down']));           // controllable + installed + not running (muted excluded)
$downN = count($downRows);
// Muted = admin ignored a service that is genuinely stopped - listed separately so it can be un-muted.
$mutedRows = array_values(array_filter($rows, fn($r)=>!empty($r['ignored']) && $r['runtime'] && $r['installed'] && !$r['active']));
$attnN = count(array_filter($rows, fn($r)=>$r['cls']==='danger'));
$cfg = smpro_svcmon_cfg();
$monSet = array_fill_keys($cfg['monitor'], true);
$monerable = smpro_svc_monitorable();
// The silent failure: a service is DOWN and nothing is set to bring it back - Service Monitor is either off
// entirely, or this service is not on its watch list. WHM shows "stopped" and "monitored" as two unrelated
// columns, so it is easy to miss that a stopped service is ALSO unwatched: it just stays down and nobody is
// told. Security services in that state are the worst case, so they are called out first.
$unwatched = [];
foreach ($rows as $r) {
    if (empty($r['down'])) continue;                                      // genuinely stopped, controllable, not muted
    if (!empty($cfg['enabled']) && isset($monSet[$r['key']])) continue;   // something WILL restart it
    $unwatched[] = $r;
}
usort($unwatched, fn($a, $b) => (int)!empty($b['critical']) <=> (int)!empty($a['critical']));
$unwatchedCrit = array_values(array_filter($unwatched, fn($r) => !empty($r['critical'])));
$notifyLink = 'index.cgi?page=notifications';
$rbReady = function_exists('smpro_reboot_readiness') ? smpro_cache_through('svc_rbready', 120, fn() => smpro_reboot_readiness()) : null;   // pre-reboot safety check (cached - grubby/modinfo/df probes)
$rbSched = function_exists('smpro_reboot_sched') ? smpro_reboot_sched() : ['enabled'=>false,'at'=>0,'target'=>'next'];

smpro_audit('cpanel_services_view', ['installed'=>$instN,'active'=>$actN,'down'=>$downN]);
smpro_layout_header('Service Manager');
?>
<div style="display:flex;justify-content:space-between;align-items:flex-start;gap:14px;flex-wrap:wrap">
  <div>
    <div class="svc-kicker">Service Manager</div>
    <h1 class="h" style="margin:2px 0 4px">Services &amp; Auto-Monitor</h1>
    <p class="sub">See what is running and what stopped, fix a stopped service in one click, and let SM Pro watch your services and restart them automatically if they go down.</p>
  </div>
  <div style="display:flex;gap:8px;align-items:center">
    <a class="svc-top" href="index.cgi?page=load-monitor">Server Health</a>
    <a class="svc-top" href="index.cgi?page=firewall-status">Firewall</a>
  </div>
</div>

<script>var SVC_CSRF=<?= json_encode(smpro_csrf_generate('svc_ctl')) ?>;</script>

<?php if ($unwatched): ?>
<div class="svc-gap <?= $unwatchedCrit ? 'crit' : '' ?>">
  <div class="svc-gap-ic"><?= $unwatchedCrit ? '&#9888;&#65039;' : '&#128064;' ?></div>
  <div class="svc-gap-b">
    <div class="svc-gap-t">
      <?= count($unwatched) ?> stopped service<?= count($unwatched) > 1 ? 's are' : ' is' ?> not being watched &mdash; nothing will restart <?= count($unwatched) > 1 ? 'them' : 'it' ?>
    </div>
    <div class="svc-gap-d">
      <?php if ($unwatchedCrit): ?>
        <b><?= smpro_h(implode(', ', array_map(fn($r) => $r['label'], array_slice($unwatchedCrit, 0, 3)))) ?></b>
        <?= count($unwatchedCrit) > 3 ? ' and ' . (count($unwatchedCrit) - 3) . ' more' : '' ?>
        <?= count($unwatchedCrit) > 1 ? 'are' : 'is' ?> a protection service. While it is down your server is unprotected in that area, and because it is unwatched it will stay down until someone notices.
      <?php else: ?>
        These are stopped and not on the Service Monitor watch list, so they will stay down until someone notices.
      <?php endif; ?>
      <?php if (empty($cfg['enabled'])): ?>
        <b>Service Monitor is currently off</b>, so nothing is watching any service.
      <?php endif; ?>
    </div>
    <div class="svc-gap-list">
      <?php foreach (array_slice($unwatched, 0, 6) as $r): ?>
        <span class="svc-gap-chip <?= !empty($r['critical']) ? 'crit' : '' ?>"><?= smpro_h($r['label']) ?></span>
      <?php endforeach; ?>
      <?= count($unwatched) > 6 ? '<span class="svc-gap-chip">+' . (count($unwatched) - 6) . ' more</span>' : '' ?>
    </div>
    <div class="svc-gap-a">
      <button type="button" class="tp-btn primary" id="svcGapFix">&#9889; Start <?= count($unwatched) > 1 ? 'them' : 'it' ?> and watch from now on</button>
      <a class="svc-top" href="#svcMon">Open Service Monitor</a>
    </div>
  </div>
</div>
<?php endif; ?>

<!-- ===== two headline cards: Running vs Down ===== -->
<div class="svc-two">
  <div class="svc-big good">
    <div class="svc-big-ic">&#10003;</div>
    <div class="svc-big-body">
      <div class="svc-big-n"><?= (int)$actN ?></div>
      <div class="svc-big-l">Services running</div>
      <div class="svc-big-s">of <?= (int)$instN ?> installed &middot; <?= count($rows) ?> known</div>
    </div>
  </div>
  <button type="button" class="svc-big <?= $downN ? 'bad' : 'good' ?>" id="svcDownCard" <?= $downN ? '' : 'disabled' ?> title="<?= $downN ? 'Show the stopped services' : 'Everything is running' ?>">
    <div class="svc-big-ic"><?= $downN ? '&#9888;' : '&#10003;' ?></div>
    <div class="svc-big-body">
      <div class="svc-big-n"><?= (int)$downN ?></div>
      <div class="svc-big-l"><?= $downN ? 'Services down' : 'None down' ?></div>
      <div class="svc-big-s"><?= $downN ? 'Click to view &amp; fix &rarr;' : 'All monitored services are up' ?></div>
    </div>
  </button>
</div>

<!-- ===== drill-in: the stopped services, each with a contextual action + Ignore ===== -->
<div class="card svc-downwrap" id="svcDown" <?= $downN ? '' : 'hidden' ?>>
  <div class="svc-downhd">&#9888; Stopped services <span class="meta">— fix each one, or ignore it to stop the alerts</span></div>
  <div class="svc-downlist">
    <?php foreach ($downRows as $r): $reg = smpro_svc_registry()[$r['key']] ?? []; $act = smpro_svc_fix_action($r, $reg); ?>
      <div class="svc-downrow" data-svc="<?= smpro_h($r['key']) ?>" data-label="<?= smpro_h($r['label']) ?>">
        <div class="svc-downinfo">
          <b><?= smpro_h($r['label']) ?></b>
          <span class="svc-state danger" data-state><?= smpro_h($r['state_label']) ?></span>
          <?php if ($r['critical']): ?><span class="svc-crit">critical</span><?php endif; ?>
          <div class="meta"><?= smpro_h($r['category']) ?> &middot; unit <?= smpro_h($r['unit']) ?> &middot; <?= smpro_h($r['state']) ?><?= strtolower($r['enabled'])==='disabled' ? ' &middot; disabled at boot' : '' ?></div>
        </div>
        <div class="svc-downact" data-ctl>
          <button class="svc-btn <?= $act['cls'] ?>" data-a="<?= $act['a'] ?>"><?= $act['icon'] ?> <?= smpro_h($act['label']) ?></button>
          <button class="svc-igbtn" data-ig="on" title="Stop flagging this service as down and mute its alerts (auto-restart &amp; notifications skip it). Reversible.">&#128263; Ignore</button>
        </div>
      </div>
    <?php endforeach; ?>
  </div>
</div>

<?php if ($mutedRows): ?>
<!-- ===== muted services: ignored & still stopped — un-mute here ===== -->
<div class="card svc-mutewrap" id="svcMuted">
  <div class="svc-mutehd">&#128263; Muted services <span class="meta">— ignored while stopped; they are not flagged or alerted. Un-mute to watch again.</span></div>
  <div class="svc-mutelist">
    <?php foreach ($mutedRows as $r): ?>
      <div class="svc-muterow" data-svc="<?= smpro_h($r['key']) ?>" data-label="<?= smpro_h($r['label']) ?>">
        <div class="svc-muteinfo">
          <b><?= smpro_h($r['label']) ?></b>
          <span class="meta"><?= smpro_h($r['category']) ?> &middot; unit <?= smpro_h($r['unit']) ?> &middot; currently <?= smpro_h($r['state']) ?></span>
        </div>
        <button class="svc-igbtn unmute" data-ig="off" title="Watch this service again — it will be flagged if it stays stopped">&#128276; Un-mute</button>
      </div>
    <?php endforeach; ?>
  </div>
</div>
<?php endif; ?>

<!-- ===== Service Monitor control panel ===== -->
<div class="card svcm" id="svcMon">
  <div class="svcm-hd">
    <div>
      <div class="svc-kicker">Automatic monitoring</div>
      <h2 class="svcm-title">&#128737; Service Monitor</h2>
      <p class="svcm-sub">SM Pro checks your chosen services every 3 minutes. If one stops, it can restart it automatically and/or alert you — with no need to keep this page open.</p>
    </div>
    <label class="svcm-master">
      <input type="checkbox" id="svcmEnabled" <?= $cfg['enabled'] ? 'checked' : '' ?>>
      <span class="svcm-switch"></span>
      <span class="svcm-master-l"><?= $cfg['enabled'] ? 'Monitoring ON' : 'Monitoring OFF' ?></span>
    </label>
  </div>

  <div class="svcm-opts">
    <label class="svcm-opt">
      <input type="checkbox" id="svcmAuto" <?= $cfg['autorestart'] ? 'checked' : '' ?>>
      <span><b>Auto-restart stopped services</b><em>Bring a stopped service back automatically (rate-limited to 4 tries/hour to avoid a crash-loop).</em></span>
    </label>
    <label class="svcm-opt">
      <input type="checkbox" id="svcmNotify" <?= $cfg['notify'] ? 'checked' : '' ?>>
      <span><b>Notify me on incidents</b><em>Send an alert when a watched service goes down. Delivered through your <a href="<?= $notifyLink ?>">Notifications</a> channels (Email / Telegram / WhatsApp / Pushbullet).</em></span>
    </label>
    <label class="svcm-opt">
      <input type="checkbox" id="svcmRecovery" <?= $cfg['recovery'] ? 'checked' : '' ?>>
      <span><b>Also notify on recovery</b><em>Send a follow-up when a service comes back up.</em></span>
    </label>
  </div>

  <div class="svcm-pick">
    <div class="svcm-pick-hd">
      <b>Watch these services</b>
      <span class="svcm-pick-tools">
        <button type="button" class="fa-lnk" id="svcmAll">Select all</button>
        <button type="button" class="fa-lnk" id="svcmCrit">Critical only</button>
        <button type="button" class="fa-lnk" id="svcmNone">Clear</button>
      </span>
    </div>
    <div class="svcm-grid">
      <?php foreach ($monerable as $k): $reg = smpro_svc_registry()[$k] ?? []; $row = null; foreach ($rows as $rr) if ($rr['key']===$k) { $row = $rr; break; } if (!$row) continue;
        $caution = smpro_svc_monitor_caution($k, $row); $rec = smpro_svc_monitor_recommended($k); ?>
        <label class="svcm-chip <?= $row['active'] ? 'up' : ($row['installed'] ? 'down' : 'absent') ?><?= $caution ? ' has-caution' : '' ?>">
          <input type="checkbox" class="svcmChk" value="<?= smpro_h($k) ?>" <?= isset($monSet[$k]) ? 'checked' : '' ?>>
          <span class="svcm-chip-b">
            <span class="svcm-chip-t"><?= smpro_h($reg['label'] ?? $k) ?><?php if ($rec): ?> <i class="svcm-star" title="recommended to monitor">&#9733;</i><?php else: ?> <i class="svcm-warn" title="not a core service">&#9888;</i><?php endif; ?></span>
            <span class="svcm-chip-s"><?= $row['active'] ? '&#9679; running' : ($row['installed'] ? '&#9679; stopped' : 'not installed') ?></span>
            <?php if ($caution): ?><span class="svcm-chip-c"><?= smpro_h($caution) ?></span><?php endif; ?>
          </span>
        </label>
      <?php endforeach; ?>
    </div>
    <div class="svcm-legend"><i class="svcm-star">&#9733;</i> recommended to monitor &nbsp;·&nbsp; <i class="svcm-warn">&#9888;</i> optional — read the note before watching</div>
  </div>

  <div class="svcm-foot">
    <span class="svcm-autonote">&#128190; Changes save automatically — no button, no page reload.</span>
    <span id="svcmMsg" class="svcm-msg"></span>
  </div>
</div>

<!-- ===== Reboot readiness + scheduled reboot ===== -->
<?php if ($rbReady): $rv = $rbReady['verdict']; $rbAccent = $rv==='blocked'?'var(--dang)':($rv==='caution'?'#c2710c':'var(--good)'); ?>
<div class="card rb-card" style="padding:0;overflow:hidden;margin:16px 0;border-top:3px solid <?= $rbAccent ?>">
  <div style="padding:14px 16px 0">
    <div class="svc-kicker">Server control</div>
    <h2 class="svcm-title">&#128260; Reboot readiness &amp; scheduled reboot</h2>
    <p class="svcm-sub">Before any reboot SM Pro verifies the server will come back up cleanly — the next-boot kernel has its CloudLinux LVE module (kmodlve), boot images + the network driver exist, RAID is healthy, and a fallback kernel is available. You can schedule an automatic reboot; it re-runs these checks at that exact moment and <b>aborts (with an alert) if anything critical fails</b> — so it can never boot the box into a broken kernel.</p>
  </div>
  <div style="padding:8px 16px 14px">
    <div class="rb-verdict <?= $rv ?>">
      <?php if ($rv==='blocked'): ?>&#128308; <b>NOT safe to reboot yet</b> — <?= (int)$rbReady['fail'] ?> critical check(s) failed. Fix them, or choose “pin current kernel”, first.
      <?php elseif ($rv==='caution'): ?>&#128992; <b>Safe to reboot</b>, with <?= (int)$rbReady['warn'] ?> caution(s) noted below.
      <?php else: ?>&#128994; <b>Ready</b> — all pre-reboot checks pass. <?= $rbReady['kernel_change'] ? 'Next boot: new kernel '.smpro_h($rbReady['next']).'.' : 'The same kernel ('.smpro_h($rbReady['current']).') will boot.' ?>
      <?php endif; ?>
    </div>
    <div class="rb-checks">
      <?php foreach ($rbReady['checks'] as $c): $ci = $c['status']==='fail'?'&#10007;':($c['status']==='warn'?'&#9888;&#65039;':'&#10003;'); ?>
        <div class="rb-chk <?= smpro_h($c['status']) ?>"><span class="rb-ci"><?= $ci ?></span><span class="rb-cl"><?= smpro_h($c['label']) ?></span><span class="rb-cd"><?= smpro_h($c['detail']) ?></span><?php if (!empty($c['fix'])): ?><button class="svc-btn restart rb-fix" type="button" data-fix="<?= smpro_h($c['fix']) ?>">&#128295; Fix</button><?php endif; ?></div>
      <?php endforeach; ?>
    </div>
    <?php if (!empty($rbSched['enabled']) && (int)$rbSched['at'] > time()): ?>
      <div class="rb-active">&#9200; Reboot scheduled for <b><?= smpro_h(date('Y-m-d H:i', (int)$rbSched['at'])) ?></b> (server time) · boot target: <b><?= $rbSched['target']==='current'?'current kernel (pinned)':'next kernel' ?></b>. Safety is re-checked at that moment.
        <button class="svc-btn stop" id="rbCancel" type="button">Cancel scheduled reboot</button></div>
    <?php else: ?>
      <div class="rb-form">
        <div class="rb-form-t"><b>&#128197; Schedule an automatic reboot</b> <span class="meta">server time now: <?= date('Y-m-d H:i') ?></span></div>
        <div class="rb-frow">
          <label>When <input type="datetime-local" id="rbWhen" class="tp-in"></label>
          <label class="rb-tgt"><input type="radio" name="rbTarget" value="next" checked> Boot the next kernel<?= $rbReady['kernel_change']?' ('.smpro_h($rbReady['next']).')':'' ?></label>
          <label class="rb-tgt"><input type="radio" name="rbTarget" value="current"> Pin current kernel (conservative)</label>
          <button class="svc-btn restart" id="rbSchedule" type="button">&#128260; Schedule reboot</button>
        </div>
        <div class="rb-note">Pick a maintenance window. SM Pro re-checks safety at that moment and will NOT reboot if a critical check fails; you get a notification when it runs (or aborts). Times are in the SERVER's timezone.</div>
      </div>
    <?php endif; ?>
    <div id="rbMsg" class="svcm-msg" style="margin-top:8px"></div>
  </div>
</div>
<style>
.rb-verdict{font-size:13px;border-radius:10px;padding:9px 12px;margin-bottom:10px}
.rb-verdict.ready{background:var(--good-bg);color:#15803d}.rb-verdict.caution{background:var(--warn-bg);color:#b45309}.rb-verdict.blocked{background:var(--dang-bg);color:var(--dang)}
.rb-checks{display:flex;flex-direction:column;gap:5px;margin-bottom:12px}
.rb-chk{display:flex;gap:9px;align-items:baseline;font-size:12.5px;padding:6px 9px;border:1px solid var(--line);border-radius:9px;background:var(--card)}
.rb-chk.fail{border-color:#f3c4c4;background:var(--dang-bg)}.rb-chk.warn{border-color:#f0d8b8;background:var(--warn-bg)}
.rb-ci{flex:none;width:16px;text-align:center}.rb-chk.ok .rb-ci{color:var(--good)}.rb-chk.warn .rb-ci{color:#c2710c}.rb-chk.fail .rb-ci{color:var(--dang)}
.rb-cl{font-weight:700;min-width:210px}.rb-cd{color:var(--muted);flex:1;min-width:180px}
.rb-fix{margin-left:auto;padding:3px 11px;font-size:11px;white-space:nowrap;flex:none}
@media(max-width:600px){.rb-cl{min-width:0}}
.rb-active{display:flex;gap:12px;align-items:center;flex-wrap:wrap;font-size:13px;background:var(--brand-bg);border:1px solid #cdd9fb;border-radius:10px;padding:10px 12px}
.rb-form{border:1px solid var(--line);border-radius:11px;padding:12px;background:var(--card)}
.rb-form-t{display:flex;gap:10px;align-items:center;justify-content:space-between;flex-wrap:wrap;margin-bottom:9px}
.rb-frow{display:flex;gap:14px;align-items:center;flex-wrap:wrap}
.rb-frow label{font-size:12.5px;display:inline-flex;gap:6px;align-items:center}
.rb-tgt{border:1px solid var(--line);border-radius:9px;padding:6px 10px}
.rb-note{font-size:11.5px;color:var(--muted);margin-top:9px;line-height:1.5}
.rb-card .tp-in{padding:7px 10px;border:1px solid var(--line);border-radius:8px;font-size:13px;background:var(--card);color:var(--ink)}
</style>
<script>(function(){
  var CSRF=window.SVC_CSRF||'';
  function e2(s){var d=document.createElement('div');d.textContent=(s==null?'':String(s));return d.innerHTML;}
  function rbmsg(t,ok){var m=document.getElementById('rbMsg');if(m){m.innerHTML=e2(t);m.style.color=ok?'var(--good)':'var(--dang)';}}
  function rbpost(p){var fd=new URLSearchParams();fd.set('smpro_csrf',CSRF);for(var k in p)fd.set(k,p[k]);
    return fetch('index.cgi?page=cpanel-services',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'}).then(function(r){return r.json();});}
  var sb=document.getElementById('rbSchedule');
  if(sb)sb.addEventListener('click',function(){
    var w=(document.getElementById('rbWhen')||{}).value||''; if(!w){rbmsg('Pick a date & time first.',false);return;}
    var at=Math.floor(new Date(w).getTime()/1000);
    if(!at||at*1000<Date.now()+120000){rbmsg('Pick a time at least 2 minutes in the future.',false);return;}
    var tgt=(document.querySelector('input[name=rbTarget]:checked')||{}).value||'next';
    var blocked=<?= ($rbReady && $rbReady['verdict']==='blocked')?'true':'false' ?>;
    var msg='Schedule an automatic reboot of THIS server at '+w+' (server time)?\n\nBoot target: '+tgt+'. SM Pro re-checks safety at that moment and aborts if a critical check fails.';
    if(blocked)msg='WARNING: pre-reboot checks currently FAIL. If they still fail at the scheduled time the reboot will be ABORTED (safe). Schedule anyway?\n\n'+msg;
    if(!confirm(msg))return;
    if(!confirm('Final confirmation — schedule the reboot now?'))return;
    sb.disabled=true;var o=sb.innerHTML;sb.textContent='…';
    rbpost({reboot_action:'schedule',when:w,target:tgt}).then(function(j){sb.disabled=false;sb.innerHTML=o;rbmsg((j&&j.ok?'✓ ':'✗ ')+((j&&j.msg)||'Failed'),j&&j.ok);if(j&&j.ok)setTimeout(function(){location.reload();},1800);}).catch(function(){sb.disabled=false;sb.innerHTML=o;rbmsg('Request failed.',false);});
  });
  var cb=document.getElementById('rbCancel');
  if(cb)cb.addEventListener('click',function(){if(!confirm('Cancel the scheduled reboot?'))return;cb.disabled=true;rbpost({reboot_action:'cancel'}).then(function(j){rbmsg((j&&j.ok?'✓ ':'✗ ')+((j&&j.msg)||'Failed'),j&&j.ok);if(j&&j.ok)setTimeout(function(){location.reload();},1200);}).catch(function(){cb.disabled=false;rbmsg('Request failed.',false);});});
  document.addEventListener('click',function(e){
    var b=e.target.closest('.rb-fix'); if(!b)return;
    if(!confirm('Fix this now?\n\nSM Pro backs up /etc/fstab first, then aligns the /tmp entry to the actual filesystem type. Safe and reversible; no remount.'))return;
    b.disabled=true;var o=b.innerHTML;b.innerHTML='…';
    rbpost({reboot_action:'fixfstabtmp'}).then(function(j){rbmsg((j&&j.ok?'✓ ':'✗ ')+((j&&j.msg)||'Failed'),j&&j.ok);if(j&&j.ok)setTimeout(function(){location.reload();},1800);else{b.disabled=false;b.innerHTML=o;}}).catch(function(){b.disabled=false;b.innerHTML=o;rbmsg('Request failed.',false);});
  });
})();</script>
<?php endif; ?>

<!-- ===== full catalog ===== -->
<div class="lbl" style="margin:20px 0 8px">All services <span class="meta" style="font-weight:400">— every known service on this server, with controls</span></div>
<div class="svc-grid">
  <?php foreach ($rows as $r): $key=$r['key']; $s=smpro_svc_registry()[$key] ?? []; $cls=$r['cls']; $reg=$s;
    $runtime = $r['runtime']; $u = !empty($s['units']);
    // A service switched off through cPanel/CSF cannot be started from here - the daemon refuses and systemd
    // reports a confusing protocol failure. Do not offer the action at all; the card says where to re-enable it.
    $offReason = (string)($r['off_reason'] ?? '');
    $showStart = $runtime && $r['installed'] && !$r['active'] && $u && $offReason === '';
    $showRestart = $runtime && $r['installed'] && $r['active'] && ($u || smpro_svc_restartsrv($s)!=='');
    $showStop = $runtime && $r['installed'] && $r['active'] && empty($s['no_stop']) && $u;
    [$stateLabel,$c2,$recLevel,$recText] = smpro_svc_assess($s, ['installed'=>$r['installed'],'active'=>$r['active'],'state'=>$r['state'],'enabled'=>$r['enabled'],'unit'=>$r['unit'],'off_reason'=>$offReason]);
  ?>
  <article class="svc-card <?= $cls ?>" data-svc="<?= smpro_h($key) ?>" data-warn="<?= smpro_h($s['description'] ?? '') ?>" data-label="<?= smpro_h($r['label']) ?>">
    <div class="svc-cardtop">
      <div><span class="svc-cat"><?= smpro_h($r['category']) ?></span><h3><?= smpro_h($r['label']) ?></h3></div>
      <div style="display:flex;gap:5px;align-items:center;flex-wrap:wrap;justify-content:flex-end">
        <?php if (!empty($r['ignored'])): ?><span class="svc-mutedpill" title="Muted — not flagged as down or alerted">&#128263; muted</span><?php endif; ?>
        <span class="svc-state <?= $cls ?>" data-state><?= smpro_h($stateLabel) ?></span>
      </div>
    </div>
    <p class="svc-desc"><?= smpro_h($s['description'] ?? '') ?></p>
    <div class="svc-facts">
      <div><span>Installed</span><b><?= $r['installed']?'Yes':'No' ?></b></div>
      <div><span>State</span><b><?= smpro_h($r['state']) ?></b></div>
      <div><span>Enabled</span><b><?= smpro_h($r['enabled']) ?></b></div>
      <div><span>Unit</span><b><?= smpro_h($r['unit']) ?></b></div>
    </div>
    <div class="svc-rec <?= $recLevel ?>"><?= smpro_h($recText) ?></div>
    <div class="svc-ctl" data-ctl>
      <?php if ($showStart && strtolower($r['enabled'])==='disabled'): ?><button class="svc-btn enable" data-a="enable">Enable</button><?php endif; ?>
      <?php if ($showStart): ?><button class="svc-btn start" data-a="start">Start</button><?php endif; ?>
      <?php if ($showRestart): ?><button class="svc-btn restart" data-a="restart">Restart</button><?php endif; ?>
      <?php if ($showStop): ?><button class="svc-btn stop" data-a="stop">Stop</button><?php endif; ?>
      <?php if ($runtime && $r['installed'] && !$r['active']): ?>
        <?php if (!empty($r['ignored'])): ?><button class="svc-igbtn unmute" data-ig="off" title="Watch this service again">&#128276; Un-mute</button>
        <?php else: ?><button class="svc-igbtn" data-ig="on" title="Stop flagging this service as down and mute its alerts. Reversible.">&#128263; Ignore</button><?php endif; ?>
      <?php endif; ?>
      <?php if (!empty($s['no_stop']) && $r['active']): ?><span class="svc-blocked">Stop blocked</span><?php endif; ?>
      <?php if (!$runtime): ?><span class="svc-note">Detected by presence — no runtime control here.</span><?php endif; ?>
      <?php if (!$r['installed']): ?><span class="svc-note">Install: <?= smpro_h($s['install'] ?? '—') ?> (manual)</span><?php endif; ?>
      <?php if ($r['installed'] && (!$runtime || $key === 'lfd')): $uplan = smpro_svc_uninstall_plan($key); ?>
        <button class="svc-unbtn<?= ($uplan['risk'] ?? '') === 'high' ? ' high' : '' ?>" data-a="uninstall" data-label="<?= smpro_h($r['label']) ?>" data-risk="<?= smpro_h($uplan['risk'] ?? 'normal') ?>" data-note="<?= smpro_h($uplan['note'] ?? '') ?>" title="Uninstall this add-on from the server (the plugin runs the removal)">&#128465;&#65039; Uninstall</button>
      <?php endif; ?>
    </div>
    <?php if ($runtime && $r['installed'] && !$r['active']): ?>
      <details class="svc-unins"><summary>Installed but inactive — activate or remove?</summary>
        <div class="svc-unins-b">Use <b>Start</b> above to activate it now. If you don't need it, it's safe to leave stopped; to stop it launching on boot run <span class="mono">systemctl disable <?= smpro_h($r['unit']) ?></span>, or uninstall it with your OS package manager / WHM &rsaquo; EasyApache&nbsp;4 where applicable. SM Pro never auto-removes system packages.</div>
      </details>
    <?php endif; ?>
  </article>
  <?php endforeach; ?>
</div>

<style>
.svc-kicker{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--brand);font-weight:800}
.svc-top{font-size:13px;color:var(--brand);text-decoration:none;border:1px solid var(--line);padding:6px 12px;border-radius:8px}.svc-top:hover{background:var(--brand-bg)}
/* two headline cards */
.svc-two{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin:16px 0}
@media(max-width:600px){.svc-two{grid-template-columns:1fr}}
.svc-big{display:flex;align-items:center;gap:16px;text-align:left;border:1px solid var(--line);border-radius:16px;padding:18px 20px;background:var(--card);font:inherit;cursor:default}
.svc-big.good{border-left:5px solid var(--good)}
.svc-big.bad{border-left:5px solid var(--dang);cursor:pointer}
button.svc-big{width:100%}
button.svc-big.bad:hover{box-shadow:0 6px 20px rgba(220,38,38,.16);transform:translateY(-1px)}
button.svc-big:disabled{cursor:default}
.svc-big-ic{font-size:30px;width:56px;height:56px;flex:none;display:flex;align-items:center;justify-content:center;border-radius:14px}
.svc-big.good .svc-big-ic{background:var(--good-bg);color:var(--good)}
.svc-big.bad .svc-big-ic{background:var(--dang-bg);color:var(--dang)}
.svc-big-n{font-size:34px;font-weight:800;line-height:1}
.svc-big-l{font-weight:700;margin-top:2px}
.svc-big-s{font-size:12px;color:var(--muted);margin-top:2px}
/* down drill-in */
.svc-downwrap{margin-bottom:16px;border-left:4px solid var(--dang)}
.svc-downhd{font-weight:800;color:var(--dang);margin-bottom:10px}
.svc-downlist{display:flex;flex-direction:column;gap:8px}
.svc-downrow{display:flex;align-items:center;gap:12px;flex-wrap:wrap;border:1px solid var(--line);border-radius:11px;padding:11px 13px;background:var(--card)}
.svc-downinfo{flex:1;min-width:180px;display:flex;flex-direction:column;gap:3px}
.svc-downinfo b{font-size:14px}
.svc-crit{font-size:10px;font-weight:800;color:var(--dang);background:var(--dang-bg);padding:1px 7px;border-radius:20px;margin-left:2px}
.svc-downact{display:flex;gap:8px;align-items:center}
/* ignore / mute controls */
.svc-igbtn{font-size:12px;font-weight:600;border:1px solid var(--line);background:var(--card);color:var(--muted);border-radius:8px;padding:5px 12px;cursor:pointer;white-space:nowrap}
.svc-igbtn:hover{border-color:#94a3b8;color:#334155;background:#f1f5f9}
.svc-igbtn.unmute{color:var(--brand);border-color:#c9d4ff}.svc-igbtn.unmute:hover{background:var(--brand);color:#fff}
.svc-igbtn:disabled{opacity:.4;cursor:not-allowed}
.svc-unbtn{font-size:12px;font-weight:700;border:1px solid #f3c4c4;background:var(--card);color:var(--dang);border-radius:8px;padding:5px 12px;cursor:pointer;white-space:nowrap}
.svc-unbtn:hover{background:var(--dang);color:#fff}.svc-unbtn:disabled{opacity:.5;cursor:not-allowed}
.svc-unbtn.high{border-color:var(--dang);background:var(--dang-bg)}
.svc-mutedpill{font-size:10px;font-weight:800;color:#475569;background:#eef2f7;border:1px solid var(--line);padding:2px 8px;border-radius:20px;white-space:nowrap}
.svc-mutewrap{margin-bottom:16px;border-left:4px solid #94a3b8}
.svc-mutehd{font-weight:800;color:#475569;margin-bottom:10px}
.svc-mutelist{display:flex;flex-direction:column;gap:8px}
.svc-muterow{display:flex;align-items:center;gap:12px;flex-wrap:wrap;border:1px solid var(--line);border-radius:11px;padding:10px 13px;background:var(--card)}
.svc-muteinfo{flex:1;min-width:180px;display:flex;flex-direction:column;gap:2px}
.svc-muteinfo b{font-size:13.5px}
/* monitor panel */
.svcm{margin-bottom:16px}
.svcm-hd{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;flex-wrap:wrap}
/* stopped-and-unwatched gap banner */
.svc-gap{display:flex;gap:13px;align-items:flex-start;padding:13px 16px;border-radius:12px;margin:0 0 14px;
         background:var(--warn-bg);border:1px solid #f0d8b8}
.svc-gap.crit{background:var(--dang-bg);border-color:#f3c9c9}
.svc-gap-ic{font-size:19px;line-height:1.15}
.svc-gap-b{flex:1;min-width:0}
.svc-gap-t{font-weight:800;font-size:14px}
.svc-gap-d{font-size:12.5px;color:var(--muted);margin-top:3px;line-height:1.55}
.svc-gap-list{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}
.svc-gap-chip{font-size:11px;font-weight:700;padding:2px 9px;border-radius:20px;background:var(--card);border:1px solid var(--line);color:var(--muted)}
.svc-gap-chip.crit{color:var(--dang);border-color:#f3c9c9}
.svc-gap-a{display:flex;gap:9px;align-items:center;flex-wrap:wrap;margin-top:10px}
.svcm-title{font-size:18px;margin:2px 0 4px}
.svcm-sub{font-size:12.5px;color:var(--muted);margin:0;max-width:640px;line-height:1.55}
.svcm-master{display:flex;align-items:center;gap:9px;cursor:pointer;white-space:nowrap}
.svcm-master input{position:absolute;opacity:0;width:0;height:0}
.svcm-switch{width:44px;height:25px;border-radius:20px;background:var(--line);position:relative;transition:.2s;flex:none}
.svcm-switch::after{content:"";position:absolute;top:3px;left:3px;width:19px;height:19px;border-radius:50%;background:#fff;transition:.2s;box-shadow:0 1px 3px rgba(0,0,0,.3)}
.svcm-master input:checked + .svcm-switch{background:var(--good)}
.svcm-master input:checked + .svcm-switch::after{transform:translateX(19px)}
.svcm-master-l{font-weight:800;font-size:13px}
.svcm-opts{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin:16px 0 4px}
@media(max-width:720px){.svcm-opts{grid-template-columns:1fr}}
.svcm-opt{display:flex;gap:10px;align-items:flex-start;border:1px solid var(--line);border-radius:11px;padding:11px 13px;cursor:pointer;background:var(--card)}
.svcm-opt input{margin-top:2px;width:16px;height:16px;flex:none;accent-color:var(--brand)}
.svcm-opt b{font-size:13px;display:block}
.svcm-opt em{font-style:normal;font-size:11.5px;color:var(--muted);display:block;margin-top:2px;line-height:1.5}
.svcm-opt a{color:var(--brand)}
.svcm-pick{margin-top:12px;border-top:1px dashed var(--line);padding-top:12px}
.svcm-pick-hd{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:9px;flex-wrap:wrap}
.svcm-pick-tools{display:flex;gap:12px}
.fa-lnk{background:none;border:none;color:var(--brand);cursor:pointer;font-size:12px;padding:0;text-decoration:underline}
.svcm-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:8px}
.svcm-chip{display:flex;align-items:center;gap:9px;border:1px solid var(--line);border-radius:11px;padding:9px 11px;cursor:pointer;background:var(--card);transition:.12s}
.svcm-chip:hover{border-color:var(--brand)}
.svcm-chip input{width:16px;height:16px;flex:none;accent-color:var(--brand)}
.svcm-chip-b{display:flex;flex-direction:column;line-height:1.25;min-width:0}
.svcm-chip-t{font-size:12.5px;font-weight:700}
.svcm-star{color:#f59e0b;font-style:normal;font-size:11px}
.svcm-warn{color:#e0a106;font-style:normal;font-size:11px}
.svcm-chip-s{font-size:10.5px;color:var(--muted)}
.svcm-chip-c{font-size:10.5px;color:#a16207;margin-top:3px;line-height:1.35;white-space:normal}
.svcm-chip.up .svcm-chip-s{color:var(--good)}
.svcm-chip.down{border-color:#f3c4c4}.svcm-chip.down .svcm-chip-s{color:var(--dang)}
.svcm-chip.has-caution{border-color:#f0d9a8;background:#fffdf6}
.svcm-chip.absent{opacity:.55}
.svcm-legend{font-size:11px;color:var(--muted);margin-top:10px}
.svcm-foot{display:flex;align-items:center;gap:14px;margin-top:16px;flex-wrap:wrap}
.svcm-autonote{font-size:12px;color:var(--muted)}
.svcm-msg{font-size:12.5px}
/* catalog grid (unchanged look) */
.svc-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(330px,1fr));gap:14px}
.svc-card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:16px;border-top:4px solid var(--line);display:flex;flex-direction:column}
.svc-card.good{border-top-color:var(--good)}.svc-card.danger{border-top-color:var(--dang)}.svc-card.ok{border-top-color:var(--good)}.svc-card.muted{border-top-color:#cbd5e1}
.svc-cardtop{display:flex;justify-content:space-between;align-items:flex-start;gap:10px}
.svc-cat{font-size:10px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);font-weight:700}
.svc-cardtop h3{margin:3px 0 0;font-size:15px}
.svc-state{font-size:10px;font-weight:800;padding:3px 9px;border-radius:20px;white-space:nowrap}
.svc-state.good,.svc-state.ok{background:var(--good-bg);color:var(--good)}.svc-state.danger{background:var(--dang-bg);color:var(--dang)}.svc-state.muted{background:var(--card);color:#475569}
.svc-desc{font-size:12px;color:var(--muted);margin:10px 0;line-height:1.5;flex:1}
.svc-facts{display:grid;grid-template-columns:1fr 1fr;gap:6px 12px;font-size:12px;margin-bottom:10px}
.svc-facts span{color:var(--muted);font-size:10px;text-transform:uppercase;display:block}.svc-facts b{font-weight:700}
.svc-rec{font-size:12px;border-radius:8px;padding:8px 10px;line-height:1.5;margin-bottom:10px}
.svc-rec.good{background:var(--good-bg);color:#15803d}.svc-rec.info{background:var(--brand-bg);color:#26408b}.svc-rec.warning{background:var(--warn-bg);color:var(--warn)}.svc-rec.danger{background:var(--dang-bg);color:var(--dang)}
.svc-ctl{display:flex;gap:6px;align-items:center;flex-wrap:wrap}
.svc-btn{font-size:12px;font-weight:600;border:1px solid var(--line);background:var(--card);border-radius:8px;padding:5px 14px;cursor:pointer}
.svc-btn.restart{color:var(--brand);border-color:#c9d4ff}.svc-btn.restart:hover{background:var(--brand);color:#fff}
.svc-btn.start{color:var(--good);border-color:#bfe6cd}.svc-btn.start:hover{background:var(--good);color:#fff}
.svc-btn.enable{color:#0369a1;border-color:#bae0f5}.svc-btn.enable:hover{background:#0284c7;color:#fff}
.svc-btn.stop{color:var(--dang);border-color:#f3c4c4}.svc-btn.stop:hover{background:var(--dang);color:#fff}
.svc-btn:disabled{opacity:.4;cursor:not-allowed}
.svc-blocked,.svc-note{font-size:11px;color:var(--muted)}
.svc-unins{margin-top:9px}
.svc-unins summary{cursor:pointer;font-size:11.5px;color:var(--brand)}
.svc-unins-b{font-size:11.5px;color:var(--muted);line-height:1.5;margin-top:6px;background:var(--card);border:1px solid var(--line);border-radius:8px;padding:8px 10px}
.meta{color:var(--muted)}
</style>
<script>
(function(){
  function esc(s){var e=document.createElement('div');e.textContent=(s==null?'':String(s));return e.innerHTML;}
  function monMsg(t,ok){var m=document.getElementById('svcmMsg');if(m){m.innerHTML=esc(t);m.style.color=ok?'var(--good)':'var(--dang)';}}
  /* ---- uninstall an installed add-on - the PLUGIN runs the removal (multi-strategy + trace purge) ---- */
  document.addEventListener('click',function(e){
    var b=e.target.closest('.svc-unbtn');if(!b||b.disabled)return;
    var host=b.closest('[data-svc]');if(!host)return;
    var svc=host.getAttribute('data-svc'),label=b.getAttribute('data-label')||svc,risk=b.getAttribute('data-risk')||'normal',note=b.getAttribute('data-note')||'';
    if(!confirm('UNINSTALL '+label+' from this server?\n\n'+note+'\n\nThe plugin runs the removal (vendor uninstaller → package manager → cleanup) until it is gone, and this is logged.'))return;
    if(risk==='high'&&!confirm('⚠ HIGH RISK: '+label+' is a base OS layer. Removing it can break the server and may need a reboot into a stock kernel.\n\nType-check: only proceed if you are sure. Continue?'))return;
    if(!confirm('Final confirmation — uninstall '+label+' now?'))return;
    b.disabled=true;var o=b.innerHTML;b.innerHTML='⏳ Uninstalling…';
    var fd=new URLSearchParams();fd.set('svc_action','uninstall');fd.set('svc',svc);fd.set('smpro_csrf',SVC_CSRF);
    fetch('index.cgi?page=cpanel-services',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'})
      .then(function(r){return r.json();}).then(function(j){
        var m=(j&&j.msg)||'Done';
        if(j&&j.log&&j.log.length)m+='\n\nSteps:\n• '+j.log.join('\n• ');
        alert((j&&j.ok?(j.gone?'✅ ':'⚠ '):'⚠ ')+m);
        if(j&&j.ok&&j.gone){setTimeout(function(){location.reload();},1600);}else{b.disabled=false;b.innerHTML=o;}
      }).catch(function(){b.disabled=false;b.innerHTML=o;alert('Request failed (it may still be running in the background).');});
  });
  /* ---- service control (start/restart/stop) - catalog cards AND the down-list; NO page reload ---- */
  document.addEventListener('click',function(e){
    var b=e.target.closest('.svc-btn');if(!b||b.disabled)return;
    var host=b.closest('[data-svc]');if(!host)return;
    var svc=host.getAttribute('data-svc'),action=b.getAttribute('data-a'),label=host.getAttribute('data-label')||svc,warn=host.getAttribute('data-warn')||'';
    if(!confirm(action.toUpperCase()+' '+label+'?\n\n'+(warn?warn+'\n\n':'')+'Runs the real control command and is logged. Continue?'))return;
    host.querySelectorAll('.svc-btn').forEach(function(x){x.disabled=true;});var o=b.textContent;b.textContent='…';
    var fd=new URLSearchParams();fd.set('svc_action',action);fd.set('svc',svc);fd.set('smpro_csrf',SVC_CSRF);
    fetch('index.cgi?page=cpanel-services',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'})
      .then(function(r){return r.json();}).then(function(j){
        var s=host.querySelector('[data-state]');if(j&&j.state_label&&s){s.textContent=j.state_label;s.className='svc-state '+(j.cls||'');}
        var card=host.classList.contains('svc-card')?host:null;if(card&&j&&j.cls)card.className='svc-card '+j.cls;
        if(j&&j.ok&&host.classList.contains('svc-downrow')){                 // in-place: drop the fixed row + update counts, no reload
          host.style.transition='opacity .4s';host.style.opacity=0;
          setTimeout(function(){if(host.parentNode)host.parentNode.removeChild(host);dropDown(label,true);},420);return;
        }
        host.querySelectorAll('.svc-btn').forEach(function(x){x.disabled=false;});b.textContent=o;
        // A refusal is not a failed action - the server never tried, because the service is switched off on
        // purpose. Say that, instead of "<action> did not confirm", which reads as a malfunction.
        if(j&&j.refused){alert((j.msg||'This service is disabled on this server.').trim());}
        else if(!(j&&j.ok))alert((action+' did not confirm. '+((j&&j.msg)||'')).trim());
      }).catch(function(){host.querySelectorAll('.svc-btn').forEach(function(x){x.disabled=false;});b.textContent=o;alert('Failed (network/permission). If you restarted cpsrvd, just reload.');});
  });
  /* Drop a row from the "down" list and refresh the headline counts. started=true when it was brought up
     (also bump "running"); started=false when it was merely muted (down count falls, running unchanged). */
  function dropDown(label,started){
    var card=document.getElementById('svcDownCard');var nEl=card&&card.querySelector('.svc-big-n');
    if(nEl){var n=Math.max(0,(parseInt(nEl.textContent,10)||1)-1);nEl.textContent=n;
      if(started){var runEl=document.querySelector('.svc-big.good .svc-big-n');if(runEl)runEl.textContent=(parseInt(runEl.textContent,10)||0)+1;}
      if(n===0){var d=document.getElementById('svcDown');if(d)d.hidden=true;var l=card.querySelector('.svc-big-l');if(l)l.textContent='None down';var ic=card.querySelector('.svc-big-ic');if(ic)ic.innerHTML='&#10003;';card.classList.remove('bad');card.classList.add('good');card.disabled=true;}}
    monMsg(started?('✓ '+label+' started.'):('🔕 '+label+' muted — it will no longer be flagged.'),true);
  }
  /* ---- ignore / un-ignore (mute) - down-list rows, muted-list rows, and catalog cards ---- */
  document.addEventListener('click',function(e){
    var b=e.target.closest('.svc-igbtn');if(!b||b.disabled)return;
    var host=b.closest('[data-svc]');if(!host)return;
    var svc=host.getAttribute('data-svc'),label=host.getAttribute('data-label')||svc,on=b.getAttribute('data-ig')==='on';
    if(on&&!confirm('Ignore '+label+'?\n\nSM Pro will stop flagging this service as “down” and will NOT alert you about it — the Service Monitor’s auto-restart and notifications skip it. Use this for a service you turned off on purpose. You can un-mute it any time. Continue?'))return;
    b.disabled=true;var o=b.innerHTML;b.innerHTML='…';
    var fd=new URLSearchParams();fd.set('svc_ignore',on?'on':'off');fd.set('svc',svc);fd.set('smpro_csrf',SVC_CSRF);
    fetch('index.cgi?page=cpanel-services',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'})
      .then(function(r){return r.json();}).then(function(j){
        if(j&&j.ok&&on&&host.classList.contains('svc-downrow')){            // muted from the down-list: drop the row, decrement down count
          host.style.transition='opacity .4s';host.style.opacity=0;
          setTimeout(function(){if(host.parentNode)host.parentNode.removeChild(host);dropDown(label,false);},420);return;
        }
        if(j&&j.ok&&!on){location.reload();return;}                        // un-muted: reload so it returns to the down list
        if(j&&j.ok){location.reload();return;}                             // muted from a catalog card: reload to reflect the badge/list
        b.disabled=false;b.innerHTML=o;alert((j&&j.msg)||'Failed.');
      }).catch(function(){b.disabled=false;b.innerHTML=o;alert('Failed (network).');});
  });
  /* ---- Down card -> reveal + scroll to the stopped-services list ---- */
  var dc=document.getElementById('svcDownCard');
  if(dc)dc.addEventListener('click',function(){var d=document.getElementById('svcDown');if(d){d.hidden=false;d.scrollIntoView({behavior:'smooth',block:'start'});}});
  /* ---- Service Monitor: AUTOSAVE on any change - no Save button, no page reload ---- */
  var chks=function(){return Array.prototype.slice.call(document.querySelectorAll('.svcmChk'));};
  var elAll=document.getElementById('svcmAll'),elNone=document.getElementById('svcmNone'),elCrit=document.getElementById('svcmCrit');
  if(elAll)elAll.addEventListener('click',function(){chks().forEach(function(c){c.checked=true;});saveMon();});
  if(elNone)elNone.addEventListener('click',function(){chks().forEach(function(c){c.checked=false;});saveMon();});
  if(elCrit)elCrit.addEventListener('click',function(){chks().forEach(function(c){c.checked=!!c.parentNode.querySelector('.svcm-star');});saveMon();});
  /* "Start them and watch from now on" - close the gap in one press: start each stopped-and-unwatched
     service, tick it on the Service Monitor list, make sure the monitor itself is on, then save. */
  var gapFix=document.getElementById('svcGapFix');
  if(gapFix)gapFix.addEventListener('click',function(){
    var keys=<?= json_encode(array_values(array_map(fn($r) => $r['key'], $unwatched ?? [])), JSON_UNESCAPED_SLASHES) ?>;
    if(!keys.length)return;
    if(!confirm('Start '+keys.length+' stopped service(s) and add them to the Service Monitor?\n\nService Monitor will then check every 3 minutes and restart them if they stop again.'))return;
    var b=this,o=b.innerHTML;b.disabled=true;
    var i=0,started=0,failed=[];
    (function next(){
      if(i>=keys.length){
        // tick them on the watch list, turn the monitor on, and save
        var en=document.getElementById('svcmEnabled'); if(en&&!en.checked)en.checked=true;
        chks().forEach(function(c){ if(keys.indexOf(c.value)!==-1)c.checked=true; });
        doSaveMon();
        b.innerHTML='✓ '+started+' started'+(failed.length?(' · '+failed.length+' failed'):'')+' — now watched';
        setTimeout(function(){location.reload();},1600);
        return;
      }
      var k=keys[i++]; b.innerHTML='Starting… '+i+'/'+keys.length;
      var fd=new URLSearchParams();fd.set('svc_action','start');fd.set('svc',k);fd.set('smpro_csrf',SVC_CSRF);
      fetch(location.pathname+location.search,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'})
        .then(function(r){return r.json();}).then(function(j){ if(j&&j.ok)started++;else failed.push(k); next(); })
        .catch(function(){failed.push(k);next();});
    })();
  });
  var saveT=null;
  function saveMon(){if(saveT)clearTimeout(saveT);saveT=setTimeout(doSaveMon,350);}
  function doSaveMon(){
    var en=document.getElementById('svcmEnabled');
    var l=document.querySelector('.svcm-master-l');if(l)l.textContent=(en&&en.checked)?'Monitoring ON':'Monitoring OFF';
    monMsg('Saving…',true);
    var fd=new URLSearchParams();fd.set('svc_mon','save');fd.set('smpro_csrf',SVC_CSRF);
    fd.set('enabled',(en&&en.checked)?'1':'0');
    fd.set('autorestart',document.getElementById('svcmAuto').checked?'1':'0');
    fd.set('notify',document.getElementById('svcmNotify').checked?'1':'0');
    fd.set('recovery',document.getElementById('svcmRecovery').checked?'1':'0');
    chks().forEach(function(c){if(c.checked)fd.append('monitor[]',c.value);});
    fetch('index.cgi?page=cpanel-services',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'})
      .then(function(r){return r.json();}).then(function(j){monMsg((j&&j.ok?'✓ ':'✗ ')+((j&&j.msg)||'Failed'),j&&j.ok);})
      .catch(function(){monMsg('✗ Save failed (network).',false);});
  }
  ['svcmEnabled','svcmAuto','svcmNotify','svcmRecovery'].forEach(function(id){var el=document.getElementById(id);if(el)el.addEventListener('change',saveMon);});
  document.addEventListener('change',function(e){if(e.target.closest&&e.target.closest('.svcmChk'))saveMon();});
})();
</script>
<?php
smpro_layout_footer();
