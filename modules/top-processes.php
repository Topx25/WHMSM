<?php
/**
 * modules/top-processes.php — LIVE process monitor (read-only, plan §38).
 * Full depth (full usernames, per-user groups, command rollup, raw table) PLUS
 * an interactive relations layer:
 *   - click a user  → filter its processes
 *   - click a command → filter processes by that command
 *   - process Details → parent (PPID) + children (PID) relations, clickable
 * No kill / renice / env exposure. Command lines redacted.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

$limit = (int)($_GET['limit'] ?? 100);
if (!in_array($limit, [60, 100, 150, 300], true)) $limit = 100;

/**
 * MANUAL, AI-assisted kill of a runaway process. Safe by design: refuses critical services, root-owned
 * daemons, low/system PIDs and the plugin's own process; only account/user-space runaways are killable.
 * mode 'advise' returns the AI verdict + safety; mode 'kill' actually terminates (TERM then KILL).
 */
function smpro_tp_kill($pid, $doit) {
    $pid = (int)$pid;
    if ($pid < 1 || !is_dir("/proc/$pid"))                 return ['ok'=>false,'msg'=>'Process not found (already gone?).'];
    if ($pid <= 300)                                       return ['ok'=>false,'msg'=>'Refused: low/system PID.'];
    if ($pid === getmypid() || (function_exists('posix_getppid') && $pid === posix_getppid())) return ['ok'=>false,'msg'=>'Refused: this plugin\'s own process.'];
    $comm = trim((string)@file_get_contents("/proc/$pid/comm"));
    $st = @stat("/proc/$pid"); $uid = (int)($st['uid'] ?? 0);
    $crit = ['systemd','init','httpd','apache','nginx','lshttpd','litespeed','mysqld','mariadbd','mysqld_safe','named','exim','dovecot','sshd','lfd','csf','cpsrvd','cphulkd','tailwatchd','queueprocd','pure-ftpd','proftpd','crond','rsyslogd','journal','dbus','chronyd','imunify','defence360','clamd','spamd'];
    foreach ($crit as $c) if ($comm !== '' && stripos($comm, $c) !== false) return ['ok'=>false,'msg'=>'Refused: critical service "' . $comm . '" is never killed.'];
    if (function_exists('smpro_is_trusted_system_proc') && smpro_is_trusted_system_proc($comm)) return ['ok'=>false,'msg'=>'Refused: "' . $comm . '" is a trusted security/hosting daemon (e.g. Imunify/CloudLinux) — never killed.'];
    if ($uid === 0)                                        return ['ok'=>false,'msg'=>'Refused: root-owned process "' . $comm . '" — kill from shell if you are certain.'];
    $owner = function_exists('posix_getpwuid') ? (posix_getpwuid($uid)['name'] ?? (string)$uid) : (string)$uid;
    $ai = '';
    if (function_exists('smpro_ai_available') && smpro_ai_available()) {
        $cl = trim(str_replace("\0", ' ', (string)@file_get_contents("/proc/$pid/cmdline")));
        $sys = "You are a Linux/cPanel sysadmin. In ONE short line say whether killing this process is SAFE (stuck/runaway user process) or RISKY (may disrupt a customer site/job), then a brief why.";
        $r = smpro_ai_chat($sys, function_exists('smpro_ai_redact') ? smpro_ai_redact("PID $pid comm=$comm owner=$owner cmd=" . mb_substr($cl, 0, 200)) : "PID $pid comm=$comm owner=$owner", ['max_tokens'=>120,'context'=>'kill_advise']);
        if (!empty($r['ok'])) $ai = trim((string)$r['text']);
    }
    if (!$doit) return ['ok'=>true,'advise'=>1,'comm'=>$comm,'owner'=>$owner,'ai'=>$ai];
    @shell_exec('kill -TERM ' . $pid . ' 2>/dev/null'); usleep(350000);
    if (is_dir("/proc/$pid")) @shell_exec('kill -KILL ' . $pid . ' 2>/dev/null');
    $gone = !is_dir("/proc/$pid");
    if (function_exists('smpro_audit')) smpro_audit('top_process_kill', ['pid'=>$pid,'comm'=>$comm,'owner'=>$owner,'killed'=>$gone]);
    return ['ok'=>$gone,'comm'=>$comm,'msg'=>$gone ? ('✅ Killed ' . $comm . ' (PID ' . $pid . ', ' . $owner . ').') : 'Signal sent but the process is still present.'];
}
$reqMethod = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? getenv('REQUEST_METHOD') ?: 'GET'));
if ($reqMethod === 'POST' && in_array(($_POST['tp_action'] ?? ''), ['kill_advise', 'kill'], true)) {
    $GLOBALS['SMPRO_FORCE_JSON'] = 1;           // ensure CSRF/license/root failures return JSON, not an HTML page (CLI SAPI ignores header())
    header('Content-Type: application/json');
    smpro_require_valid_csrf('tp_action'); smpro_require_root();
    echo json_encode(smpro_tp_kill((int)($_POST['pid'] ?? 0), ($_POST['tp_action'] === 'kill')), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit;
}

// CSV export of the current process snapshot (GET, read-only). Still behind the page's normal
// WHM/root access; require root explicitly for defense in depth. index.cgi sets text/csv +
// Content-Disposition when it sees format=csv. smpro_fputcsv() neutralizes formula injection.
if (($_GET['export'] ?? '') === 'csv') {
    smpro_require_root();
    $snap = smpro_top_processes($limit);
    $fh = fopen('php://output', 'w');
    smpro_fputcsv($fh, ['user', 'pid', 'ppid', 'process', 'cpu', 'mem', 'stat', 'etime', 'args']);
    foreach (($snap['rows'] ?? []) as $r) {
        smpro_fputcsv($fh, [$r['user'], $r['pid'], $r['ppid'], $r['process'], $r['cpu'], $r['mem'], $r['stat'], $r['etime'], $r['args']]);
    }
    fclose($fh);
    exit;
}

$d = smpro_top_processes($limit);
smpro_audit('top_processes_view', ['limit' => $limit, 'rows' => $d['total']]);

smpro_layout_header('Top Processes');
?>
<div style="display:flex;justify-content:space-between;align-items:flex-start;gap:14px;flex-wrap:wrap">
  <div>
    <h1 class="h">Top Processes
      <span class="live" id="smLive"><i></i> LIVE <span id="smClock"><?= smpro_h($d['ts']) ?></span></span>
    </h1>
    <p class="sub">Full usernames, per-user grouping, command rollup, and process relations. Args redacted. <b>⚡ Kill (AI)</b> is available on user-owned runaways only — root-owned and critical services are never killable.</p>
  </div>
  <div class="tp-controls">
    <button class="tp-btn" id="smRefresh" type="button">Refresh</button>
    <select class="tp-sel" id="smInterval">
      <option value="2000">2s</option>
      <option value="3000" selected>3s</option>
      <option value="5000">5s</option>
      <option value="10000">10s</option>
    </select>
    <select class="tp-sel" id="smLimit">
      <?php foreach ([60,100,150,300] as $n): ?>
        <option value="<?= $n ?>"<?= $n === $limit ? ' selected' : '' ?>><?= $n ?> rows</option>
      <?php endforeach; ?>
    </select>
    <button class="tp-btn" id="smPause" type="button">Pause</button>
    <a class="tp-btn" style="text-decoration:none;display:inline-flex;align-items:center" href="index.cgi?page=top-processes&format=csv&export=csv">&#11015; Export CSV</a>
  </div>
</div>

<div class="grid" style="margin-bottom:14px">
  <?php /* The load average is deliberately NOT repeated here — it is already in the header chip on every page,
           on the Dashboard, and in full on Server Health & System. This page is about PROCESSES; duplicating the
           same figure in a fourth place only invites them to disagree. The chip links straight to the load page. */ ?>
  <div class="card"><div class="lbl">Top User</div><div class="val" id="smTopUser" style="font-size:18px"><?= $d['top_user'] ? smpro_h($d['top_user']['user']) : '-' ?></div><div class="meta" id="smTopUserMeta"><?= $d['top_user'] ? smpro_h($d['top_user']['cpu']) . '% CPU · ' . (int)$d['top_user']['processes'] . ' proc' : '' ?></div></div>
  <div class="card"><div class="lbl">CPU in use</div><div class="val" id="smCpuUse" style="font-size:18px"><?= (int)round(array_sum(array_column($d['rows'] ?? [], 'cpu'))) ?>%</div><div class="meta">across <span id="smCores"><?= (int)$d['cores'] ?></span> cores · <a class="lnk" href="index.cgi?page=load-monitor">load &amp; history &#8594;</a></div></div>
  <div class="card"><div class="lbl">Users</div><div class="val" id="smUsers"><?= (int)$d['users_count'] ?></div><div class="meta">distinct owners</div></div>
  <div class="card"><div class="lbl">Processes shown</div><div class="val" id="smTotal"><?= (int)$d['total'] ?></div><div class="meta">hidden noise <span id="smHidden"><?= (int)$d['hidden_self'] ?></span></div></div>
</div>

<div class="card" style="margin-bottom:14px">
  <div class="tp-filters">
    <input id="smSearch" class="tp-in" placeholder="Search user, process, PID, args…">
    <select id="smType" class="tp-sel">
      <option value="all">All users</option>
      <option value="cpanel">cPanel users only</option>
      <option value="system">System/root only</option>
    </select>
    <select id="smRisk" class="tp-sel">
      <option value="all">All risk</option>
      <option value="DANGER">DANGER</option>
      <option value="WARNING">WARNING</option>
      <option value="GOOD">GOOD</option>
    </select>
    <input id="smMinCpu" class="tp-in" type="number" min="0" step="1" placeholder="Min CPU %" style="max-width:120px">
    <button class="tp-btn" id="smClear" type="button">Clear</button>
  </div>
  <div id="smChips" class="tp-chips"></div>
</div>

<div class="card" style="padding:0;overflow:hidden;margin-bottom:14px">
  <div class="tp-th"><b>Top Users by CPU</b><span class="meta">click a username to filter its processes below · cPanel users get investigation links</span></div>
  <div class="smpro-tablewrap">
    <table class="smpro-table" id="smUsersTable">
      <thead><tr>
        <th data-us="user">User</th><th data-us="type">Type</th>
        <th data-us="cpu" class="num sorted-desc">Total CPU</th><th data-us="pressure" class="num">Pressure</th>
        <th data-us="mem" class="num">MEM</th><th data-us="processes" class="num">Procs</th>
        <th data-us="top_command_group">Top Command</th><th data-us="risk">Risk</th><th>Actions</th>
      </tr></thead>
      <tbody id="smUsersBody"></tbody>
    </table>
  </div>
</div>

<div class="card" style="padding:0;overflow:hidden;margin-bottom:14px">
  <div class="tp-th"><b>Top Commands</b><span class="meta">click a command to filter the processes table</span></div>
  <div class="smpro-tablewrap">
    <table class="smpro-table" id="smCmdTable">
      <thead><tr><th data-cs="command">Command</th><th data-cs="cpu" class="num sorted-desc">Total CPU</th><th data-cs="count" class="num">Count</th></tr></thead>
      <tbody id="smCmdBody"></tbody>
    </table>
  </div>
</div>

<div class="card" style="padding:0;overflow:hidden">
  <div class="tp-th"><b>Top Processes by CPU</b><span class="meta">raw table · click Details for parent/children relations</span></div>
  <div class="smpro-tablewrap">
    <table class="smpro-table" id="smRowsTable">
      <thead><tr>
        <th data-rs="user">User</th><th data-rs="pid" class="num">PID</th><th data-rs="ppid" class="num">PPID</th>
        <th data-rs="process">Process</th><th data-rs="cpu" class="num sorted-desc">CPU%</th><th data-rs="mem" class="num">MEM%</th>
        <th data-rs="stat">STAT</th><th data-rs="etime">ETIME</th><th data-rs="args">Args</th><th>Details</th>
      </tr></thead>
      <tbody id="smRowsBody"></tbody>
    </table>
  </div>
</div>

<style>
.tp-controls,.tp-filters{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.tp-btn,.tp-sel,.tp-in{border:1px solid var(--line);background:var(--card);color:var(--ink);border-radius:9px;padding:8px 12px;font-size:13px}
.tp-btn{cursor:pointer;font-weight:600}.tp-btn:hover{background:var(--brand-bg)}
.tp-acts{white-space:nowrap}
.tp-kill{border-color:#f3c4c4!important;color:#b91c1c;background:var(--dang-bg)}
.tp-kill:hover{background:var(--dang-bg)}
.tp-kill:disabled{opacity:.7;cursor:default}
.tp-cool{border-color:#bae6fd!important;color:#0369a1;background:#e0f2fe}
.tp-cool:hover{background:#e0f2fe}
.tp-cool:disabled{opacity:.7;cursor:default}
.tp-in{min-width:240px}
.tp-th{display:flex;align-items:center;gap:10px;padding:12px 16px;border-bottom:1px solid var(--line);flex-wrap:wrap}
.tp-th .meta{color:var(--muted);font-size:12px}
.smpro-tablewrap{overflow-x:auto}
.smpro-table{width:100%;border-collapse:collapse;font-size:13px}
.smpro-table th,.smpro-table td{padding:9px 12px;text-align:left;border-bottom:1px solid var(--line);white-space:nowrap}
.smpro-table th{font-size:11px;text-transform:uppercase;letter-spacing:.03em;color:var(--muted);cursor:pointer;user-select:none}
.smpro-table th.num,.smpro-table td.num{text-align:right;font-variant-numeric:tabular-nums}
.smpro-table th.sorted-desc::after{content:" ▼";font-size:9px}.smpro-table th.sorted-asc::after{content:" ▲";font-size:9px}
.smpro-table tbody tr:hover{background:var(--card)}
.smpro-table td.args{max-width:520px;overflow:hidden;text-overflow:ellipsis;color:var(--muted);font-family:ui-monospace,Consolas,monospace;font-size:12px}
.uname{font-family:ui-monospace,Consolas,monospace;font-weight:600}
.b{display:inline-block;font-size:11px;font-weight:700;padding:2px 8px;border-radius:20px}
.b.red{background:var(--dang-bg);color:var(--dang)}.b.orange{background:var(--warn-bg);color:var(--warn)}.b.green{background:var(--good-bg);color:var(--good)}
.b.blue{background:var(--brand-bg);color:var(--brand)}.b.gray{background:var(--card);color:#475569}
.tp-act a{font-size:11px;padding:4px 8px;margin-right:4px;border:1px solid var(--line);border-radius:7px;text-decoration:none;color:var(--brand)}
.tp-act a:hover{background:var(--brand-bg)}
.tp-chips{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}
.tp-chips:empty{display:none}
.tp-chip{display:inline-flex;align-items:center;gap:6px;font-size:12px;background:var(--brand-bg);color:var(--brand);border:1px solid #c9d4ff;padding:4px 10px;border-radius:20px}
.tp-chip b{font-weight:700}
.tp-chip .x{cursor:pointer;font-weight:700;opacity:.7}.tp-chip .x:hover{opacity:1}
.lnk{color:var(--brand);cursor:pointer;text-decoration:underline dotted}
.lnk:hover{text-decoration:underline}
.rel{color:var(--muted)}.rel b{color:#e5e7eb}
.kid{color:#9fc1ff;cursor:pointer}.kid:hover{text-decoration:underline}
tr.hl td{background:var(--warn-bg) !important}
.tp-details{display:none;background:#0f172a;color:#e5e7eb;border-radius:10px;padding:12px;white-space:pre-wrap;word-break:break-word;font-family:ui-monospace,Consolas,monospace;font-size:12px;margin:4px 0}
tr.open + tr .tp-details{display:block}
.live.stale{color:var(--muted);background:var(--card)}.live.stale i{background:var(--muted);animation:none}
</style>
<script>
(function(){
  var initial = <?= json_encode($d, JSON_UNESCAPED_SLASHES|JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT|JSON_INVALID_UTF8_SUBSTITUTE) ?>;   /* HEX flags escape script-closing sequences in attacker-influenced args/comm; SUBSTITUTE keeps a non-UTF-8 cmdline from making json_encode() return false (which would blank this line and break every card) */
  var TP_CSRF = <?= json_encode(smpro_csrf_generate('tp_action'), JSON_UNESCAPED_SLASHES) ?>;
  var COOL_CSRF = <?= json_encode(smpro_csrf_generate('cooler'), JSON_UNESCAPED_SLASHES) ?>;
  var limit = <?= $limit ?>, paused = false, timer = null, lastData = null;
  var uSort={k:'cpu',d:'desc'}, cSort={k:'cpu',d:'desc'}, rSort={k:'cpu',d:'desc'};
  var relUser=null, relCmd=null;          // active relation filters
  var pidIndex={};                         // pid -> row (rebuilt each render)
  var live=document.getElementById('smLive');
  function $(id){return document.getElementById(id);}
  function esc(s){return String(s==null?'':s).replace(/[&<>"]/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
  function riskRank(r){return r==='DANGER'?3:r==='WARNING'?2:r==='GOOD'?1:0;}
  function riskCls(r){return r==='DANGER'?'red':r==='WARNING'?'orange':'green';}
  function cpuCls(v){v=+v||0;return v>=100?'red':v>=35?'orange':'green';}
  function gv(o,k){if(k==='type')return o.is_cpanel?'cpanel':'system';if(k==='risk')return riskRank(o.risk);return o[k];}
  function cmp(a,b,k,d){var x=gv(a,k),y=gv(b,k);if(typeof x==='string')x=x.toLowerCase();if(typeof y==='string')y=y.toLowerCase();if(x<y)return d==='asc'?-1:1;if(x>y)return d==='asc'?1:-1;return 0;}
  function toggle(s,k,strKeys){if(s.k===k){s.d=s.d==='asc'?'desc':'asc';}else{s.k=k;s.d=strKeys.indexOf(k)>=0?'asc':'desc';}}
  function q(){return ($('smSearch').value||'').toLowerCase().trim();}

  // ---- relation filters ----
  function setUser(u){relUser=(relUser===u)?null:u;relCmd=null;if(lastData)render(lastData);scrollRows();}
  function setCmd(c){relCmd=(relCmd===c)?null:c;if(lastData)render(lastData);scrollRows();}
  function scrollRows(){var el=$('smRowsTable');if(el)el.scrollIntoView({behavior:'smooth',block:'start'});}
  function renderChips(){
    var html='';
    if(relUser)html+='<span class="tp-chip">user <b>'+esc(relUser)+'</b><span class="x" data-clr="user">✕</span></span>';
    if(relCmd)html+='<span class="tp-chip">command <b>'+esc(relCmd)+'</b><span class="x" data-clr="cmd">✕</span></span>';
    var box=$('smChips');box.innerHTML=html;
    box.querySelectorAll('.x').forEach(function(x){x.addEventListener('click',function(){
      if(this.getAttribute('data-clr')==='user')relUser=null;else relCmd=null;
      if(lastData)render(lastData);
    });});
  }

  function passCommon(o,isGroup){
    var t=$('smType').value,risk=$('smRisk').value,minc=+($('smMinCpu').value||0);
    if(t==='cpanel'&&!o.is_cpanel)return false;
    if(t==='system'&&o.is_cpanel)return false;
    if(isGroup&&risk!=='all'&&o.risk!==risk)return false;
    if((+o.cpu||0)<minc)return false;
    var s=q();if(s&&JSON.stringify(o).toLowerCase().indexOf(s)<0)return false;
    return true;
  }
  function passRow(r){
    if(!passCommon(r,false))return false;
    if(relUser&&r.user!==relUser)return false;
    if(relCmd&&r.process!==relCmd)return false;
    return true;
  }

  function renderUsers(data){
    var arr=(data.groups||[]).filter(function(g){return passCommon(g,true);});
    arr.sort(function(a,b){return cmp(a,b,uSort.k,uSort.d);});
    $('smUsersBody').innerHTML=arr.map(function(g){
      var type=g.is_cpanel?'<span class="b blue">cPanel</span>':'<span class="b gray">system</span>';
      var act=g.is_cpanel
        ?'<div class="tp-act"><a href="index.cgi?page=account-audit&audit_user='+encodeURIComponent(g.user)+'">Audit</a>'
         +'<a href="index.cgi?page=php-harden&phuser='+encodeURIComponent(g.user)+'">Harden</a>'
         +'<a href="index.cgi?page=load-monitor">Load</a></div>'
        :'<span class="meta">system user</span>';
      var sel=(relUser===g.user)?' style="background:var(--warn-bg)"':'';
      return '<tr'+sel+'><td><span class="uname lnk" data-user="'+esc(g.user)+'" title="filter this user’s processes">'+esc(g.user)+'</span></td>'
        +'<td>'+type+'</td>'
        +'<td class="num"><span class="b '+cpuCls(g.cpu)+'">'+g.cpu+'%</span></td>'
        +'<td class="num">'+g.pressure+'%</td><td class="num">'+g.mem+'%</td><td class="num">'+g.processes+'</td>'
        +'<td>'+esc(g.top_command_group||g.top_process||'')+'</td>'
        +'<td><span class="b '+riskCls(g.risk)+'">'+esc(g.risk)+'</span></td>'
        +'<td>'+act+'</td></tr>';
    }).join('');
    $('smUsersBody').querySelectorAll('.lnk[data-user]').forEach(function(el){
      el.addEventListener('click',function(){setUser(this.getAttribute('data-user'));});
    });
  }
  function renderCmds(data){
    var arr=(data.commands||[]).filter(function(c){var s=q();return !s||JSON.stringify(c).toLowerCase().indexOf(s)>=0;});
    arr.sort(function(a,b){return cmp(a,b,cSort.k,cSort.d);});
    $('smCmdBody').innerHTML=arr.map(function(c){
      var sel=(relCmd===c.command)?' style="background:var(--warn-bg)"':'';
      return '<tr'+sel+'><td><b class="lnk" data-cmd="'+esc(c.command)+'" title="filter processes by this command">'+esc(c.command)+'</b></td>'
        +'<td class="num"><span class="b '+cpuCls(c.cpu)+'">'+c.cpu+'%</span></td><td class="num">'+c.count+'</td></tr>';
    }).join('');
    $('smCmdBody').querySelectorAll('.lnk[data-cmd]').forEach(function(el){
      el.addEventListener('click',function(){setCmd(this.getAttribute('data-cmd'));});
    });
  }
  function relationsBlock(r){
    var parent=pidIndex[r.ppid];
    var kids=(lastData.rows||[]).filter(function(x){return x.ppid===r.pid;});
    var pTxt=parent?('<span class="rel">parent PPID '+r.ppid+' → <b>'+esc(parent.process)+'</b> ('+esc(parent.user)+')</span>')
                   :('<span class="rel">parent PPID '+r.ppid+' (not in current list)</span>');
    var kTxt='<span class="rel">children: '+(kids.length?kids.map(function(k){return '<span class="kid" data-jump="'+k.pid+'">'+k.pid+' '+esc(k.process)+'</span>';}).join(', '):'none in list')+'</span>';
    return pTxt+'\n'+kTxt;
  }
  // System accounts that own genuine service daemons — Kill is not offered for these (the
  // backend refuses them anyway). Everything else that is a cPanel account or a non-root user
  // is a user-owned runaway and CAN be offered a kill. (Prior logic had `!r.is_cpanel`, which
  // wrongly HID the button for cPanel accounts — the exact target — and showed it for daemons.)
  var TP_SYSUSER={root:1,mysql:1,mysqld:1,named:1,nobody:1,dovecot:1,dovenull:1,mailnull:1,mail:1,cpanel:1,cpaneleximscanner:1,cpaneleximfilter:1,mailman:1,nscd:1,redis:1,memcached:1,clamav:1,clam:1,postgres:1,dbus:1,polkitd:1,chrony:1,rpc:1,rpcuser:1,sshd:1,ntp:1,'systemd-network':1,'systemd-resolve':1,'systemd-timesync':1};
  function renderRows(data){
    pidIndex={};(data.rows||[]).forEach(function(r){pidIndex[r.pid]=r;});
    var arr=(data.rows||[]).filter(passRow);
    arr.sort(function(a,b){return cmp(a,b,rSort.k,rSort.d);});
    var html='';
    arr.forEach(function(r,i){
      var canKill=(r.is_cpanel || (r.user && r.user!=='root' && !TP_SYSUSER[r.user]));
      html+='<tr data-pidrow="'+r.pid+'"><td><span class="uname lnk" data-user="'+esc(r.user)+'">'+esc(r.user)+'</span>'+(r.is_cpanel?' <span class="b blue">cP</span>':'')+'</td>'
        +'<td class="num">'+r.pid+'</td><td class="num">'+r.ppid+'</td>'
        +'<td><span class="lnk" data-cmd="'+esc(r.process)+'">'+esc(r.process)+'</span></td>'
        +'<td class="num"><span class="b '+cpuCls(r.cpu)+'">'+r.cpu+'</span></td><td class="num">'+r.mem+'</td>'
        +'<td>'+esc(r.stat)+'</td><td>'+esc(r.etime)+'</td>'
        +'<td class="args" title="'+esc(r.args)+'">'+esc(r.args)+'</td>'
        +'<td class="tp-acts"><button class="tp-btn" type="button" data-det="'+i+'">Details</button>'
        +(canKill?' <button class="tp-btn tp-kill" type="button" data-kill="'+r.pid+'" data-comm="'+esc(r.process)+'" data-owner="'+esc(r.user)+'" data-cpu="'+r.cpu+'">⚡ Kill (AI)</button>':'')
        +(canKill?' <button class="tp-btn tp-cool" type="button" data-cool="'+r.pid+'" data-comm="'+esc(r.process)+'">&#10052;&#65039; Cool 15m</button>':'')
        +'</td></tr>';
      html+='<tr><td colspan="10"><div class="tp-details">User: '+esc(r.user)+'   PID: '+r.pid+'   PPID: '+r.ppid
        +'\nProcess: '+esc(r.process)+'   CPU: '+r.cpu+'%   MEM: '+r.mem+'%   STAT: '+esc(r.stat)+'   Elapsed: '+esc(r.etime)
        +'\n'+relationsBlock(r)
        +'\nArgs:\n'+esc(r.args)+'</div></td></tr>';
    });
    var tb=$('smRowsBody');tb.innerHTML=html;
    tb.querySelectorAll('button[data-det]').forEach(function(b){
      b.addEventListener('click',function(){this.closest('tr').classList.toggle('open');});
    });
    tb.querySelectorAll('button[data-kill]').forEach(function(b){
      b.addEventListener('click',function(){killProc(this);});
    });
    tb.querySelectorAll('button[data-cool]').forEach(function(b){
      b.addEventListener('click',function(){coolProc(this);});
    });
    tb.querySelectorAll('.lnk[data-user]').forEach(function(el){el.addEventListener('click',function(){setUser(this.getAttribute('data-user'));});});
    tb.querySelectorAll('.lnk[data-cmd]').forEach(function(el){el.addEventListener('click',function(){setCmd(this.getAttribute('data-cmd'));});});
    tb.querySelectorAll('.kid[data-jump]').forEach(function(el){el.addEventListener('click',function(){jumpToPid(+this.getAttribute('data-jump'));});});
  }
  function jumpToPid(pid){
    relUser=null;relCmd=null;render(lastData);
    var row=$('smRowsBody').querySelector('tr[data-pidrow="'+pid+'"]');
    if(row){row.classList.add('hl');row.scrollIntoView({behavior:'smooth',block:'center'});setTimeout(function(){row.classList.remove('hl');},2000);}
  }
  function render(data){
    if(!data)return;
    lastData=data;
    /* the load figure lives in the header chip / Server Health — here we keep the CPU-in-use total fresh instead */
    (function(){var _e=$('smCpuUse');if(!_e)return;var s=0;(data.rows||[]).forEach(function(r){s+=parseFloat(r.cpu)||0;});_e.textContent=Math.round(s)+'%';})();
    $('smCores').textContent=data.cores||'';
    $('smUsers').textContent=data.users_count||0;
    $('smTotal').textContent=data.total||0;
    $('smHidden').textContent=data.hidden_self||0;
    if(data.top_user){$('smTopUser').textContent=data.top_user.user;$('smTopUserMeta').textContent=data.top_user.cpu+'% CPU · '+data.top_user.processes+' proc';}
    var c=$('smClock');if(c)c.textContent=data.ts;
    if(live)live.classList.remove('stale');
    renderChips();renderUsers(data);renderCmds(data);renderRows(data);
  }
  function killProc(btn){
    var pid=btn.getAttribute('data-kill'), comm=btn.getAttribute('data-comm'), owner=btn.getAttribute('data-owner');
    if(btn.dataset.busy)return; btn.dataset.busy='1'; var orig=btn.innerHTML;
    btn.innerHTML='🤖 asking AI…'; btn.disabled=true;
    var body='tp_action=kill_advise&smpro_csrf='+encodeURIComponent(TP_CSRF)+'&pid='+encodeURIComponent(pid);
    fetch('index.cgi?page=top-processes',{method:'POST',cache:'no-store',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:body})
      .then(function(r){return r.json();})
      .then(function(j){
        btn.innerHTML=orig; btn.disabled=false; delete btn.dataset.busy;
        if(!j||!j.ok){alert('⚠ '+((j&&j.msg)||'Cannot kill this process.'));return;}
        var verdict=j.ai?('\n\n🤖 AI: '+j.ai):'\n\n(AI verdict unavailable — proceed only if you are sure.)';
        if(!confirm('Kill process?\n\nPID '+pid+'  ·  '+comm+'  ·  owner '+owner+verdict+'\n\nThis terminates the process immediately. Continue?'))return;
        btn.innerHTML='⏳ killing…'; btn.disabled=true; btn.dataset.busy='1';
        var b2='tp_action=kill&smpro_csrf='+encodeURIComponent(TP_CSRF)+'&pid='+encodeURIComponent(pid);
        fetch('index.cgi?page=top-processes',{method:'POST',cache:'no-store',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:b2})
          .then(function(r){return r.json();})
          .then(function(k){
            delete btn.dataset.busy;
            if(k&&k.ok){var tr=btn.closest('tr');if(tr){tr.style.transition='opacity .4s';tr.style.opacity='.35';}btn.innerHTML='✅ killed';tick();}
            else{btn.innerHTML=orig;btn.disabled=false;alert('⚠ '+((k&&k.msg)||'Kill failed.'));}
          })
          .catch(function(){delete btn.dataset.busy;btn.innerHTML=orig;btn.disabled=false;alert('⚠ Network error.');});
      })
      .catch(function(){btn.innerHTML=orig;btn.disabled=false;delete btn.dataset.busy;alert('⚠ Network error.');});
  }
  // ❄ Cool — reversible alternative to Kill: throttle a runaway to 30% CPU for 15 min via the
  // existing cooler engine (index.cgi?cooler=1, POST + 'cooler' CSRF + root). No new backend.
  function coolProc(btn){
    var pid=btn.getAttribute('data-cool'), comm=btn.getAttribute('data-comm');
    if(btn.dataset.busy)return;
    if(!confirm('Cool this process?\n\nPID '+pid+'  ·  '+comm+'\n\nThrottles it to 30% CPU for 15 minutes, then automatically restores it. Fully reversible — nothing is killed. Continue?'))return;
    btn.dataset.busy='1'; var orig=btn.innerHTML;
    btn.innerHTML='❄ cooling…'; btn.disabled=true;
    var body='cool_action=start&smpro_csrf='+encodeURIComponent(COOL_CSRF)+'&pids='+encodeURIComponent(pid)+'&percent=30&minutes=15';
    fetch('index.cgi?cooler=1',{method:'POST',cache:'no-store',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:body})
      .then(function(r){return r.json();})
      .then(function(j){
        delete btn.dataset.busy;
        if(j&&j.ok){btn.innerHTML='✅ '+((j&&j.msg)?'cooled':'cooled 15m');setTimeout(function(){btn.innerHTML=orig;btn.disabled=false;},4000);}
        else{btn.innerHTML=orig;btn.disabled=false;alert('⚠ '+((j&&j.msg)||'Cannot cool this process.'));}
      })
      .catch(function(){delete btn.dataset.busy;btn.innerHTML=orig;btn.disabled=false;alert('⚠ Network error.');});
  }
  function tick(){
    if(paused||document.hidden)return;
    fetch('index.cgi?page=top-processes&format=json&metric=processes&limit='+limit,{cache:'no-store'})
      .then(function(r){return r.json();})
      .then(function(j){if(j&&j.ok&&j.data)render(j.data);})
      .catch(function(){if(live)live.classList.add('stale');});
  }
  function schedule(){if(timer)clearInterval(timer);timer=setInterval(tick,+$('smInterval').value||3000);}
  $('smRefresh').addEventListener('click',tick);
  $('smInterval').addEventListener('change',schedule);
  $('smLimit').addEventListener('change',function(){limit=parseInt(this.value,10)||100;tick();});
  ['smSearch','smType','smRisk','smMinCpu'].forEach(function(id){
    $(id).addEventListener('input',function(){if(lastData)render(lastData);});
    $(id).addEventListener('change',function(){if(lastData)render(lastData);});
  });
  $('smClear').addEventListener('click',function(){$('smSearch').value='';$('smType').value='all';$('smRisk').value='all';$('smMinCpu').value='';relUser=null;relCmd=null;if(lastData)render(lastData);});
  document.querySelectorAll('#smUsersTable th[data-us]').forEach(function(th){th.addEventListener('click',function(){toggle(uSort,th.getAttribute('data-us'),['user','type','top_command_group']);markSort('#smUsersTable',th,uSort);if(lastData)render(lastData);});});
  document.querySelectorAll('#smCmdTable th[data-cs]').forEach(function(th){th.addEventListener('click',function(){toggle(cSort,th.getAttribute('data-cs'),['command']);markSort('#smCmdTable',th,cSort);if(lastData)render(lastData);});});
  document.querySelectorAll('#smRowsTable th[data-rs]').forEach(function(th){th.addEventListener('click',function(){toggle(rSort,th.getAttribute('data-rs'),['user','process','args','stat','etime']);markSort('#smRowsTable',th,rSort);if(lastData)render(lastData);});});
  function markSort(sel,th,s){document.querySelectorAll(sel+' th').forEach(function(h){h.classList.remove('sorted-asc','sorted-desc');});th.classList.add(s.d==='asc'?'sorted-asc':'sorted-desc');}
  $('smPause').addEventListener('click',function(){paused=!paused;this.textContent=paused?'Resume':'Pause';if(live)live.classList.toggle('stale',paused);if(!paused)tick();});
  document.addEventListener('visibilitychange',function(){if(!document.hidden)tick();});
  render(initial);schedule();
})();
</script>
<style>
.tp-toggle{cursor:pointer}.tp-toggle:hover{background:var(--card)}
.tp-chev{display:inline-block;transition:transform .15s;color:var(--brand);font-weight:800;margin-right:4px;font-size:15px}
.card.tp-open>.tp-toggle .tp-chev{transform:rotate(45deg)}
.tp-collapse{display:none}.card.tp-open>.tp-collapse{display:block}
</style>
<script>
(function(){
  // Collapsible section cards — start CLOSED, open by clicking the title (or +).
  document.querySelectorAll('.smpro-main .card > .tp-th').forEach(function(th){
    var card=th.parentElement;
    var body=document.createElement('div'); body.className='tp-collapse';
    while(th.nextSibling){ body.appendChild(th.nextSibling); }
    card.appendChild(body);
    th.classList.add('tp-toggle');
    if(!th.querySelector('.tp-chev')) th.insertAdjacentHTML('afterbegin','<span class="tp-chev">&#65291;</span> ');
    // start collapsed (no tp-open class)
    th.addEventListener('click',function(e){
      if(e.target.closest('a,button,input,select,label'))return;   // ignore header controls
      card.classList.toggle('tp-open');
    });
  });
})();
</script>
<?php
smpro_layout_footer();
