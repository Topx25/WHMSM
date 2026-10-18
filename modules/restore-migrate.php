<?php
/**
 * modules/restore-migrate.php — Restore & Migrate: bring accounts in from another server.
 * Engine: includes/migrate.php. Every route drives cPanel's own transfer engine rather than reimplementing
 * a restore, so an account that lands here was rebuilt by the same code cPanel uses for its own migrations.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

$reqMethod = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? getenv('REQUEST_METHOD') ?: 'GET'));

/* ---- live progress poll (GET JSON) ---- */
if (($_GET['mig_progress'] ?? '') === '1') {
    smpro_require_root();
    header('Content-Type: application/json');
    $st = smpro_mig_state();
    $sid = (string)($st['session'] ?? '');
    echo json_encode($sid === '' ? ['ok' => true, 'idle' => true] : (smpro_mig_progress($sid) + ['job' => $st]),
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit;
}

/* ---- DirectAdmin read job poll (GET JSON) ---- */
if (($_GET['mig_da_job'] ?? '') === '1') {
    smpro_require_root();
    header('Content-Type: application/json');
    $j = json_decode((string)@file_get_contents(SMPRO_VARLIB . '/migrate_da_job.json'), true);
    echo json_encode(is_array($j) ? $j : ['idle' => true], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit;
}

/* ---- conversion job poll (GET JSON) ---- */
if (($_GET['mig_conv_job'] ?? '') === '1') {
    smpro_require_root();
    header('Content-Type: application/json');
    $j = json_decode((string)@file_get_contents(SMPRO_VARLIB . '/migrate_da_convert.json'), true);
    echo json_encode(is_array($j) ? $j : ['idle' => true], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit;
}

/* ---- everything that changes the server: POST + CSRF + root ---- */
if ($reqMethod === 'POST' && isset($_POST['mig_action'])) {
    $GLOBALS['SMPRO_FORCE_JSON'] = 1;
    header('Content-Type: application/json');
    smpro_require_valid_csrf('mig_action'); smpro_require_root();
    $act = (string)$_POST['mig_action'];
    $st  = smpro_mig_state();
    $sid = (string)($st['session'] ?? '');
    $out = ['ok' => false, 'error' => 'Unknown action.'];

    if ($act === 'connect') {
        $out = smpro_mig_connect(
            (string)($_POST['type'] ?? ''), trim((string)($_POST['host'] ?? '')),
            (int)($_POST['port'] ?? 22), trim((string)($_POST['user'] ?? 'root')),
            (string)($_POST['auth'] ?? 'password'), (string)($_POST['secret'] ?? ''));
    } elseif ($act === 'analyze' && $sid !== '') {
        $out = smpro_mig_analyze($sid);
    } elseif ($act === 'enqueue' && $sid !== '') {
        $users = array_values(array_filter(array_map('trim', explode(',', (string)($_POST['users'] ?? '')))));
        $opt = []; foreach (['skiphomedir','skipbwdata','skipsubdomains','overwrite_all_dbusers'] as $k) if (!empty($_POST[$k])) $opt[$k] = 1;
        $done = 0; $errs = [];
        foreach ($users as $u) { $r = smpro_mig_enqueue($sid, $u, '', $opt); if ($r['ok']) $done++; else $errs[] = $u . ': ' . $r['error']; }
        $out = ['ok' => $done > 0, 'queued' => $done, 'error' => implode(' · ', $errs)];
    } elseif ($act === 'start' && $sid !== '') {
        $out = smpro_mig_start($sid);
    } elseif ($act === 'abort' && $sid !== '') {
        $out = smpro_mig_abort($sid);
    } elseif ($act === 'detect') {
        $out = ['ok' => true, 'detected' => smpro_mig_detect((string)($_POST['path'] ?? ''))];
    } elseif ($act === 'da_inspect') {
        // Detached: reading a multi-GB archive takes minutes, so the answer must survive closing the page.
        $p = (string)($_POST['path'] ?? '');
        $d = smpro_mig_detect($p);
        if ($d['format'] !== 'directadmin') {
            $out = ['ok' => false, 'error' => 'That file is not a DirectAdmin backup.'];
        } else {
            @unlink(SMPRO_VARLIB . '/migrate_da_job.json');
            $php  = smpro_php_cli_bin();
            $self = SMPRO_BASE . '/bin/migrate_da_read.php';
            $pre  = trim((string)@shell_exec('command -v setsid 2>/dev/null')) !== '' ? 'setsid ' : 'nohup ';
            @shell_exec('PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin ' . $pre
                . escapeshellarg($php) . ' ' . escapeshellarg($self) . ' ' . escapeshellarg('--archive=' . $p)
                . ' >/dev/null 2>&1 </dev/null &');
            smpro_audit('migrate_da_inspect', ['archive' => $p]);
            $out = ['ok' => true, 'started' => true];
        }
    } elseif ($act === 'da_convert') {
        $p = (string)($_POST['path'] ?? '');
        $d = smpro_mig_detect($p);
        if ($d['format'] !== 'directadmin') {
            $out = ['ok' => false, 'error' => 'That file is not a DirectAdmin backup.'];
        } else {
            // Say no here rather than after twenty minutes of extraction: filling the disk part-way through
            // takes every site on the server down, not just this migration.
            $sp = smpro_mig_da_space_check($p, SMPRO_VARLIB);
            if (empty($sp['ok'])) {
                $out = ['ok' => false, 'error' => $sp['why']];
            } else {
                @unlink(SMPRO_VARLIB . '/migrate_da_convert.json');
                $php  = smpro_php_cli_bin();
                $self = SMPRO_BASE . '/bin/migrate_da_convert.php';
                $pre  = trim((string)@shell_exec('command -v setsid 2>/dev/null')) !== '' ? 'setsid ' : 'nohup ';
                @shell_exec('PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin ' . $pre
                    . escapeshellarg($php) . ' ' . escapeshellarg($self) . ' ' . escapeshellarg('--archive=' . $p)
                    . ' >/dev/null 2>&1 </dev/null &');
                smpro_audit('migrate_da_convert_start', ['archive' => $p]);
                $out = ['ok' => true, 'started' => true];
            }
        }
    } elseif ($act === 'local_restore') {
        $out = smpro_mig_local_restore((string)($_POST['path'] ?? ''));
    }
    echo json_encode($out, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit;
}

smpro_layout_header('Restore & Migrate');
$job = smpro_mig_state();
$tok = smpro_csrf_generate('mig_action');
?>
<style>
.mg-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:14px}
.mg-f{display:flex;flex-direction:column;gap:5px;margin-bottom:11px}
.mg-f label{font-size:12px;opacity:.75}
.mg-f input,.mg-f select{padding:7px 9px;border:1px solid #d5d9e0;border-radius:6px;font:inherit;font-size:13px}
.mg-note{font-size:12px;opacity:.7;line-height:1.6;margin:6px 0 0}
.mg-res{margin-top:12px;padding:11px 13px;border-radius:7px;font-size:13px;line-height:1.6;display:none}
.mg-res.ok{background:#eaf7ef;border:1px solid #b7e3c7}
.mg-res.bad{background:#fdeeee;border:1px solid #f2c2c2}
.mg-res.warn{background:#fff7e6;border:1px solid #f3dca7}
.mg-acct{max-height:280px;overflow:auto;border:1px solid #e2e5ea;border-radius:7px;padding:9px;margin-top:10px;display:none}
.mg-acct label{display:block;padding:4px 2px;font-size:13px}
.mg-bar{height:7px;background:#e8ebef;border-radius:4px;overflow:hidden;margin:9px 0}
.mg-bar i{display:block;height:100%;background:#3d7dd6;width:0%}
</style>

<div class="card">
  <h2 style="margin:0 0 4px">Bring accounts in from another server</h2>
  <p class="mg-note" style="margin-bottom:0">Every route here hands the account to cPanel's own transfer engine — the same
  code WHM uses for its own migrations — so nothing about the rebuild is reimplemented. A running transfer keeps going if
  you close this page; come back and the progress is still here.</p>
</div>

<div class="mg-grid">

  <div class="card">
    <h3 style="margin-top:0">From a live server</h3>
    <p class="mg-note">cPanel connects over SSH, converts the account on the source, and pulls it across. This is the
    only route that works for a non-cPanel panel today.</p>
    <div class="mg-f"><label>Source panel</label><select id="mgType">
      <?php foreach (smpro_mig_sources() as $k => $v): ?>
        <option value="<?= htmlspecialchars($k) ?>" title="<?= htmlspecialchars($v['note']) ?>"><?= htmlspecialchars($v['label']) ?></option>
      <?php endforeach; ?>
    </select></div>
    <div class="mg-f"><label>Host or IP</label><input id="mgHost" placeholder="203.0.113.10" autocomplete="off"></div>
    <div class="mg-f"><label>SSH port</label><input id="mgPort" value="22" inputmode="numeric"></div>
    <div class="mg-f"><label>SSH user</label><input id="mgUser" value="root" autocomplete="off"></div>
    <div class="mg-f"><label>Authenticate with</label><select id="mgAuth">
      <option value="password">Password</option><option value="sshkey">Key already trusted by the source</option>
    </select></div>
    <div class="mg-f"><label id="mgSecLbl">Password</label><input id="mgSecret" type="password" autocomplete="new-password"></div>
    <button class="btn btn-primary" id="mgConnect">Connect and list accounts</button>
    <div class="mg-res" id="mgConnRes"></div>
    <div class="mg-acct" id="mgAccts"></div>
    <div id="mgQueueBox" style="display:none;margin-top:11px">
      <label style="font-size:12px"><input type="checkbox" id="mgSkipHome"> Skip files (settings, mail and databases only)</label><br>
      <label style="font-size:12px"><input type="checkbox" id="mgSkipBw"> Skip bandwidth history</label>
      <div style="margin-top:9px"><button class="btn btn-primary" id="mgQueue">Queue selected and start</button></div>
    </div>
  </div>

  <div class="card">
    <h3 style="margin-top:0">From an archive file</h3>
    <p class="mg-note">Give the full path to an archive already on this server. It is identified before anything is
    restored — an archive whose format cannot be confirmed is refused rather than restored on a guess.</p>
    <div class="mg-f"><label>Path on this server</label><input id="mgPath" placeholder="/home/cpmove-alice.tar.gz" autocomplete="off"></div>
    <button class="btn" id="mgDetect">Identify this archive</button>
    <button class="btn btn-primary" id="mgRestore" style="display:none">Restore it</button>
    <button class="btn" id="mgInspect" style="display:none">Read what is inside</button>
    <button class="btn btn-primary" id="mgConvert" style="display:none">Convert it for cPanel</button>
    <div class="mg-res" id="mgConvRes"></div>
    <div class="mg-res" id="mgDaRes"></div>
    <div class="mg-res" id="mgFileRes"></div>
  </div>

</div>

<div class="card" id="mgJobCard" style="<?= empty($job['session']) ? 'display:none' : '' ?>">
  <h3 style="margin-top:0">Transfer in progress</h3>
  <div id="mgJobMeta" class="mg-note"></div>
  <div class="mg-bar"><i id="mgBar"></i></div>
  <div id="mgJobState" style="font-size:13px"></div>
  <div style="margin-top:10px"><button class="btn btn-danger" id="mgAbort">Stop this transfer</button></div>
</div>

<script>
(function(){
  var TOK = <?= json_encode($tok) ?>;
  function post(action, extra, cb){
    var b = new URLSearchParams(); b.set('mig_action', action); b.set('smpro_csrf', TOK);
    Object.keys(extra||{}).forEach(function(k){ b.set(k, extra[k]); });
    fetch('index.cgi?page=restore-migrate', {method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body:b.toString()})
      .then(function(r){ return r.json(); }).then(cb).catch(function(e){ cb({ok:false, error:String(e)}); });
  }
  function show(el, cls, html){ var n=document.getElementById(el); n.className='mg-res '+cls; n.innerHTML=html; n.style.display='block'; }
  function esc(s){ return String(s==null?'':s).replace(/[&<>"]/g, function(c){ return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]; }); }

  document.getElementById('mgAuth').onchange = function(){
    document.getElementById('mgSecLbl').textContent = this.value === 'sshkey' ? 'Key passphrase (blank if none)' : 'Password';
  };

  document.getElementById('mgConnect').onclick = function(){
    var btn=this; btn.disabled=true; show('mgConnRes','warn','Connecting to the source server…');
    post('connect', {type:document.getElementById('mgType').value, host:document.getElementById('mgHost').value,
      port:document.getElementById('mgPort').value, user:document.getElementById('mgUser').value,
      auth:document.getElementById('mgAuth').value, secret:document.getElementById('mgSecret').value}, function(r){
      if(!r.ok){ btn.disabled=false; return show('mgConnRes','bad', esc(r.error||'Could not connect.')); }
      document.getElementById('mgSecret').value='';
      show('mgConnRes','warn','Connected. Asking the source which accounts it holds — this can take a few minutes on a busy server…');
      post('analyze', {}, function(a){
        btn.disabled=false;
        if(!a.ok) return show('mgConnRes','bad', esc(a.error||'The source could not be listed.'));
        var users = Object.keys(a.accounts||{});
        if(!users.length) return show('mgConnRes','warn','Connected, but the source reported no accounts. That is not the same as an empty server — check the SSH user can read the panel there.');
        show('mgConnRes','ok','Found '+users.length+' account'+(users.length===1?'':'s')+' on the source.');
        var box=document.getElementById('mgAccts'); box.innerHTML='';
        users.forEach(function(u){ box.insertAdjacentHTML('beforeend','<label><input type="checkbox" class="mgU" value="'+esc(u)+'"> '+esc(u)+'</label>'); });
        box.style.display='block'; document.getElementById('mgQueueBox').style.display='block';
      });
    });
  };

  document.getElementById('mgQueue').onclick = function(){
    var sel=[].slice.call(document.querySelectorAll('.mgU:checked')).map(function(c){ return c.value; });
    if(!sel.length) return show('mgConnRes','bad','Pick at least one account first.');
    var btn=this; btn.disabled=true; show('mgConnRes','warn','Queueing '+sel.length+' account(s)…');
    post('enqueue', {users:sel.join(','), skiphomedir:document.getElementById('mgSkipHome').checked?1:'',
      skipbwdata:document.getElementById('mgSkipBw').checked?1:''}, function(r){
      if(!r.ok){ btn.disabled=false; return show('mgConnRes','bad', esc(r.error||'Nothing could be queued.')); }
      post('start', {}, function(s){
        btn.disabled=false;
        if(!s.ok) return show('mgConnRes','bad', esc(s.error||'Queued, but the transfer would not start.'));
        show('mgConnRes','ok','Transfer started for '+r.queued+' account(s). You can close this page — it keeps running.');
        document.getElementById('mgJobCard').style.display=''; poll();
      });
    });
  };

  var detected=null;
  document.getElementById('mgDetect').onclick = function(){
    var p=document.getElementById('mgPath').value.trim();
    if(!p) return show('mgFileRes','bad','Enter the full path to the archive.');
    show('mgFileRes','warn','Reading the archive…');
    document.getElementById('mgRestore').style.display='none';
    post('detect', {path:p}, function(r){
      var d=(r&&r.detected)||{}; detected=d;
      var names={cpanel:'cPanel',directadmin:'DirectAdmin',plesk:'Plesk',unknown:'not identified'};
      show('mgFileRes', d.restorable?'ok':'warn',
        '<strong>'+esc(names[d.format]||d.format)+'</strong>'+(d.confidence&&d.confidence!=='none'?' · '+esc(d.confidence):'')+'<br>'+esc(d.why||''));
      if(d.restorable) document.getElementById('mgRestore').style.display='';
      document.getElementById('mgInspect').style.display = (d.format==='directadmin') ? '' : 'none';
      document.getElementById('mgConvert').style.display = (d.format==='directadmin') ? '' : 'none';
    });
  };

  document.getElementById('mgRestore').onclick = function(){
    if(!detected||!detected.restorable) return;
    if(!confirm('Restore this archive onto this server?\n\nAn account with the same name is overwritten.')) return;
    var btn=this; btn.disabled=true; show('mgFileRes','warn','Restoring…');
    post('local_restore', {path:document.getElementById('mgPath').value.trim()}, function(r){
      btn.disabled=false;
      show('mgFileRes', r.ok?'ok':'bad', r.ok ? 'Restore started. Progress appears below.' : esc(r.error||'The restore did not start.'));
      if(r.ok){ document.getElementById('mgJobCard').style.display=''; poll(); }
    });
  };

  var daTimer=null;
  document.getElementById('mgInspect').onclick = function(){
    var p=document.getElementById('mgPath').value.trim();
    show('mgDaRes','warn','Reading the archive. A large backup takes a few minutes — the whole file has to be decompressed to reach the parts that describe the account. You can close this page.');
    post('da_inspect', {path:p}, function(r){
      if(!r.ok) return show('mgDaRes','bad', esc(r.error||'Could not start reading.'));
      if(!daTimer) daTimer=setInterval(daPoll, 6000);
      daPoll();
    });
  };
  function daPoll(){
    fetch('index.cgi?page=restore-migrate&mig_da_job=1').then(function(r){ return r.json(); }).then(function(j){
      if(j.idle) return;
      if(!j.done) return show('mgDaRes','warn', esc(j.msg||'Reading…'));
      if(daTimer){ clearInterval(daTimer); daTimer=null; }
      if(!j.ok) return show('mgDaRes','bad', esc(j.error||'The archive could not be read.'));
      var a=j.account||{}, t=j.totals||{};
      var h='<strong>'+esc(a.username||'?')+'</strong> &middot; '+esc(a.main_domain||'')+'<br>'
        +'Package '+esc(a.package||'?')+' &middot; created '+esc(a.created||'?')+(a.suspended?' &middot; <strong>suspended</strong>':'')+'<br>'
        +t.domains+' domain(s), '+t.subdomains+' subdomain(s), '+t.databases+' database(s), '
        +t.mailboxes+' mailbox(es), '+t.forwarders+' forwarder(s)<br>'
        +'Account password '+(a.has_shadow?'is in the archive':'is <strong>not</strong> in the archive')+'.';
      if((j.warnings||[]).length){
        h+='<br><br><strong>What could not be read:</strong><ul style="margin:5px 0 0 16px;padding:0">';
        j.warnings.forEach(function(w){ h+='<li>'+esc(w)+'</li>'; });
        h+='</ul>';
      }
      h+='<br><em>Nothing has been restored. Converting a DirectAdmin backup to cPanel format is still being built.</em>';
      show('mgDaRes', (j.warnings||[]).length?'warn':'ok', h);
    }).catch(function(){});
  }

  var cvTimer=null;
  document.getElementById('mgConvert').onclick = function(){
    var p=document.getElementById('mgPath').value.trim();
    if(!confirm('Convert this DirectAdmin backup into cPanel format?\n\nNothing is restored by this step — it produces an archive you can review first. It reads and repacks the whole backup, so it takes a while on a large one.')) return;
    show('mgConvRes','warn','Starting…');
    post('da_convert', {path:p}, function(r){
      if(!r.ok) return show('mgConvRes','bad', esc(r.error||'Could not start.'));
      if(!cvTimer) cvTimer=setInterval(cvPoll, 6000);
      cvPoll();
    });
  };
  function cvPoll(){
    fetch('index.cgi?page=restore-migrate&mig_conv_job=1').then(function(r){ return r.json(); }).then(function(j){
      if(j.idle) return;
      if(!j.done){
        var last=(j.steps&&j.steps.length)?j.steps[j.steps.length-1]:null;
        return show('mgConvRes','warn', esc(j.phase||'Working…')+(last?(' &middot; since '+esc(last.t)):'')+'<br><span style="opacity:.7">You can close this page; it keeps going.</span>');
      }
      if(cvTimer){ clearInterval(cvTimer); cvTimer=null; }
      if(!j.ok) return show('mgConvRes','bad', esc(j.error||'The conversion did not finish.'));
      var h='<strong>'+esc(j.user||'')+'</strong> is converted and packaged.<br>'
        +(j.sites||0)+' site(s), '+(j.mailboxes||0)+' mailbox(es), '+(j.databases||0)+' database dump(s).<br>'
        +'<code>'+esc(j.cpmove||'')+'</code><br>'+esc(j.msg||'');
      if((j.warnings||[]).length){
        h+='<br><br><strong>Read these before restoring:</strong><ul style="margin:5px 0 0 16px;padding:0">';
        j.warnings.forEach(function(w){ h+='<li>'+esc(w)+'</li>'; });
        h+='</ul>';
      }
      h+='<br><button class="btn btn-primary" id="mgRestoreConv" style="margin-top:8px">Restore it now</button>';
      show('mgConvRes',(j.warnings||[]).length?'warn':'ok', h);
      var b=document.getElementById('mgRestoreConv');
      if(b) b.onclick=function(){
        if(!confirm('Let cPanel restore this account onto this server?')) return;
        b.disabled=true;
        post('local_restore', {path:j.cpmove}, function(r){
          show('mgConvRes', r.ok?'ok':'bad', r.ok?'Restore started. Progress appears below.':esc(r.error||'The restore did not start.'));
          if(r.ok){ document.getElementById('mgJobCard').style.display=''; poll(); }
        });
      };
    }).catch(function(){});
  }

  document.getElementById('mgAbort').onclick = function(){
    if(!confirm('Stop the running transfer?\n\nAccounts already brought across stay; the rest are not started.')) return;
    post('abort', {}, function(r){ show('mgConnRes', r.ok?'ok':'bad', r.ok?'Transfer stopped.':esc(r.error||'Could not stop it.')); });
  };

  var timer=null;
  function poll(){
    fetch('index.cgi?page=restore-migrate&mig_progress=1').then(function(r){ return r.json(); }).then(function(r){
      if(r.idle){ document.getElementById('mgJobCard').style.display='none'; return; }
      var st=r.state||{}, job=r.job||{};
      document.getElementById('mgJobMeta').textContent =
        (job.type?('Source: '+job.type+(job.host?(' · '+job.host):'')):'Local archive restore');
      var total=Number(st.total_items||0), done=Number(st.completed_items||0);
      document.getElementById('mgBar').style.width = (total>0 ? Math.round(done/total*100) : 0)+'%';
      document.getElementById('mgJobState').textContent =
        (st.state||st.status||'running') + (total>0 ? (' — '+done+' of '+total+' done') : '');
      document.getElementById('mgJobCard').style.display='';
      if(!timer) timer=setInterval(poll, 5000);
    }).catch(function(){});
  }
  <?php if (!empty($job['session'])): ?>poll();<?php endif; ?>
})();
</script>
<?php
smpro_layout_footer();
