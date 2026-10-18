<?php
/**
 * modules/whatsapp.php — WhatsApp gateway integration.
 * Connects to an OpenWA-style HTTP API (X-API-Key, multi-session). Manage the
 * connection, create/start/stop sessions, link a phone by scanning the QR code,
 * and send messages. The same connection feeds the WhatsApp notification channel
 * (config shared with Notifications). Read-only on GET; all changes POST+CSRF+root.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

$reqMethod = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? getenv('REQUEST_METHOD') ?: 'GET'));

/* ---------------- POST actions (AJAX JSON) ---------------- */
if ($reqMethod === 'POST' && ($_POST['wa_action'] ?? '') !== '') {
    smpro_require_valid_csrf('wa_act'); smpro_require_root();
    header('Content-Type: application/json');
    $cfg = smpro_ntf_load();
    $w = $cfg['whatsapp'];
    $act = $_POST['wa_action'];

    if ($act === 'save') {
        // Keep existing values when a field is submitted blank (so saving from the
        // Notifications card or here never wipes the other's values).
        $w['enabled']  = !empty($_POST['wa_enabled']);
        $b = rtrim(trim((string)($_POST['base_url'] ?? '')), '/');                       if ($b !== '') $w['base_url'] = $b;
        $k = trim((string)($_POST['api_key'] ?? ''));                                    if ($k !== '') $w['api_key'] = $k;
        $s = preg_replace('/[^a-zA-Z0-9._-]/', '', (string)($_POST['session'] ?? ''));   if ($s !== '') $w['session'] = $s;
        $c = trim((string)($_POST['chat_id'] ?? ''));                                    if ($c !== '') $w['chat_id'] = $c;
        $cfg['whatsapp'] = $w; smpro_ntf_save($cfg);
        smpro_audit('whatsapp_save', ['enabled' => $w['enabled'], 'base' => $w['base_url']]);
        echo json_encode(['ok' => true, 'msg' => 'WhatsApp settings saved.']); exit;
    }
    if ($base = $w['base_url']) { /* below actions need a configured base */ }
    if ($w['base_url'] === '') { echo json_encode(['ok' => false, 'msg' => 'Set the gateway URL and Save first.']); exit; }
    $base = $w['base_url']; $key = $w['api_key'];

    if ($act === 'health') {
        [$c, $j] = smpro_ntf_wa_request($base, $key, 'GET', '/api/health', null, 10);
        echo json_encode(['ok' => $c >= 200 && $c < 300, 'code' => $c, 'data' => $j, 'msg' => ($c >= 200 && $c < 300) ? 'Gateway reachable.' : 'Gateway returned HTTP ' . $c]); exit;
    }
    if ($act === 'sessions') {
        [$c, $j] = smpro_ntf_wa_request($base, $key, 'GET', '/api/sessions', null, 12);
        echo json_encode(['ok' => $c >= 200 && $c < 300, 'code' => $c, 'sessions' => is_array($j) ? $j : []]); exit;
    }
    if ($act === 'create') {
        $name = preg_replace('/[^a-zA-Z0-9._-]/', '', (string)($_POST['name'] ?? '')) ?: $w['session'];
        [$c, $j] = smpro_ntf_wa_request($base, $key, 'POST', '/api/sessions', ['name' => $name], 20);
        smpro_audit('whatsapp_create', ['name' => $name, 'code' => $c]);
        echo json_encode(['ok' => $c >= 200 && $c < 300, 'code' => $c, 'data' => $j, 'msg' => ($c >= 200 && $c < 300) ? ('Session "' . $name . '" created.') : ('Failed (HTTP ' . $c . ')')]); exit;
    }
    if (in_array($act, ['start', 'stop'], true)) {
        $id = preg_replace('/[^a-zA-Z0-9._-]/', '', (string)($_POST['id'] ?? ''));
        [$c, $j] = smpro_ntf_wa_request($base, $key, 'POST', '/api/sessions/' . rawurlencode($id) . '/' . $act, null, 20);
        smpro_audit('whatsapp_' . $act, ['id' => $id, 'code' => $c]);
        echo json_encode(['ok' => $c >= 200 && $c < 300, 'code' => $c, 'msg' => ($c >= 200 && $c < 300) ? ('Session ' . $act . 'ed.') : ('Failed (HTTP ' . $c . ')')]); exit;
    }
    if ($act === 'qr') {
        $id = preg_replace('/[^a-zA-Z0-9._-]/', '', (string)($_POST['id'] ?? ''));
        [$c, $j] = smpro_ntf_wa_request($base, $key, 'GET', '/api/sessions/' . rawurlencode($id) . '/qr', null, 15);
        $qr = is_array($j) ? (string)($j['qrCode'] ?? '') : '';
        $gw = is_array($j) ? (string)($j['message'] ?? '') : '';
        $linked = stripos($gw, 'connected') !== false || stripos($gw, 'already') !== false || stripos($gw, 'authenticated') !== false;
        $notReady = !$linked && (stripos($gw, 'not ready') !== false || stripos($gw, 'wait') !== false || ($c === 400 && $qr === '' && $gw === ''));
        echo json_encode(['ok' => $qr !== '', 'code' => $c, 'qr' => $qr, 'status' => is_array($j) ? ($j['status'] ?? '') : '', 'pending' => $qr === '' && $notReady, 'linked' => $linked,
            'msg' => $qr === '' ? ($linked ? 'This session is already linked — no QR needed.' : ($gw ?: 'No QR (HTTP ' . $c . ')')) : '']); exit;
    }
    if ($act === 'send') {
        $chat = smpro_ntf_wa_chat((string)($_POST['chat_id'] ?? $w['chat_id']));
        $text = (string)($_POST['text'] ?? 'Test message from Safety Monitor Pro.');
        if ($chat === '') { echo json_encode(['ok' => false, 'msg' => 'Enter a recipient number.']); exit; }
        $sess = smpro_ntf_wa_resolve_session($base, $key, $w['session']);
        [$c, $j] = smpro_ntf_wa_request($base, $key, 'POST', '/api/sessions/' . rawurlencode($sess) . '/messages/send-text', ['chatId' => $chat, 'text' => $text], 20);
        $ok = $c >= 200 && $c < 300;
        smpro_audit('whatsapp_send', ['chat' => $chat, 'code' => $c]);
        echo json_encode(['ok' => $ok, 'code' => $c, 'msg' => $ok ? ('Message sent to ' . $chat) : ('Failed (HTTP ' . $c . ')' . (is_array($j) && isset($j['message']) ? ': ' . (is_array($j['message']) ? implode('; ', $j['message']) : $j['message']) : ''))]); exit;
    }
    echo json_encode(['ok' => false, 'msg' => 'Unknown action.']); exit;
}

/* ---------------- render ---------------- */
$cfg = smpro_ntf_load(); $w = $cfg['whatsapp'];
$csrf = smpro_csrf_generate('wa_act');
smpro_audit('whatsapp_view', []);
smpro_layout_header('WhatsApp');
?>
<div class="svc-kicker">Messaging</div>
<h1 class="h" style="margin:2px 0 4px">WhatsApp Gateway</h1>
<p class="sub">Connect Safety Monitor Pro to your WhatsApp HTTP gateway (OpenWA-style API). Link a phone by scanning the QR, then send alerts to WhatsApp. This connection also powers the WhatsApp channel in <a href="index.cgi?page=notifications">Notifications</a>.</p>

<script>var WA_CSRF=<?= json_encode($csrf) ?>;</script>

<!-- connection settings -->
<div class="card wa-card">
  <div class="wa-h"><span class="wa-ic">&#128241;</span><b>Connection</b>
    <label class="nt-sw" style="margin-left:auto"><input type="checkbox" id="waEnabled" <?= !empty($w['enabled'])?'checked':'' ?>><span></span></label>
    <span class="wa-state" id="waState">&#9679; unknown</span>
  </div>
  <div class="wa-grid">
    <label class="wa-l" style="flex:2">Gateway URL<input class="tp-in mono" id="waBase" value="<?= smpro_h($w['base_url']) ?>" placeholder="http://46.224.174.88:2785"></label>
    <label class="wa-l" style="flex:2">API key (X-API-Key)<input class="tp-in mono" id="waKey" value="<?= smpro_h($w['api_key']) ?>" placeholder="your api key" autocomplete="off"></label>
  </div>
  <div class="wa-grid">
    <label class="wa-l" style="flex:1">Session name<input class="tp-in mono" id="waSession" value="<?= smpro_h($w['session'] ?: 'default') ?>" placeholder="default"></label>
    <label class="wa-l" style="flex:2">Default recipient (number)<input class="tp-in mono" id="waChat" value="<?= smpro_h($w['chat_id']) ?>" placeholder="201234567890  (digits, country code, no +)"></label>
  </div>
  <div class="wa-bar">
    <button class="tp-btn primary" type="button" id="waSave">&#128190; Save</button>
    <button class="tp-btn" type="button" id="waHealth">&#128268; Test connection</button>
    <span class="nt-res" id="waConnRes"></span>
  </div>
</div>

<div class="wa-two">
  <!-- sessions -->
  <div class="card" style="padding:0;overflow:hidden">
    <div class="wa-ch"><b>Sessions</b>
      <input class="tp-in mono" id="waNewName" placeholder="new session name" style="margin-left:auto;max-width:150px;padding:6px 9px">
      <button class="tp-btn" type="button" id="waCreate">+ Create</button>
      <button class="tp-btn" type="button" id="waReload">&#8635;</button>
    </div>
    <div class="wa-tablewrap"><table class="smpro-table"><thead><tr><th>Session</th><th>Status</th><th>Phone</th><th>Actions</th></tr></thead><tbody id="waSessions">
      <tr><td colspan="4" style="text-align:center;padding:16px;color:var(--muted)">Click &#8635; or Test connection to load sessions.</td></tr>
    </tbody></table></div>
  </div>
  <!-- QR + send -->
  <div class="card" style="padding:0;overflow:hidden">
    <div class="wa-ch"><b>Link a phone (QR)</b><span class="meta">scan from WhatsApp → Linked devices</span></div>
    <div id="waQrBox" class="wa-qr"><div class="meta">Click <b>Show QR</b> on a session to display its pairing code.</div></div>
    <div class="wa-ch" style="border-top:1px solid var(--line)"><b>Send a message</b></div>
    <div style="padding:12px 16px;display:flex;flex-direction:column;gap:8px">
      <input class="tp-in mono" id="waSendTo" placeholder="recipient number (blank = default)">
      <textarea class="tp-in" id="waSendText" rows="2" placeholder="Message…">Test message from Safety Monitor Pro ✅</textarea>
      <button class="tp-btn primary" type="button" id="waSend" style="align-self:flex-start">&#9993; Send</button>
      <div class="nt-res" id="waSendRes"></div>
    </div>
  </div>
</div>

<style>
.svc-kicker{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--brand);font-weight:800}
.wa-card{display:flex;flex-direction:column;gap:12px;margin-top:14px}
.wa-h{display:flex;align-items:center;gap:10px;font-size:15px}.wa-h b{font-size:15px}.wa-ic{font-size:18px}
.wa-state{font-size:12px;font-weight:700;color:var(--muted)}.wa-state.on{color:var(--good)}.wa-state.off{color:var(--dang)}
.wa-grid{display:flex;gap:12px;flex-wrap:wrap}
.wa-l{display:flex;flex-direction:column;gap:5px;font-size:12px;font-weight:700;color:var(--muted);min-width:160px}
.tp-in,.tp-sel{border:1px solid var(--line);border-radius:9px;padding:9px 12px;font-size:13px;font-weight:400;color:var(--ink);width:100%}
textarea.tp-in{font-family:inherit;resize:vertical}
.tp-btn{border:1px solid var(--line);border-radius:9px;padding:9px 14px;font-size:13px;font-weight:600;cursor:pointer;background:#fff;color:var(--ink)}
.tp-btn.primary{background:var(--brand);color:#fff;border-color:var(--brand)}
.wa-bar{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.nt-sw{position:relative;display:inline-block;width:42px;height:24px}.nt-sw input{opacity:0;width:0;height:0}
.nt-sw span{position:absolute;inset:0;background:#cbd5e1;border-radius:20px;transition:.2s;cursor:pointer}
.nt-sw span:before{content:"";position:absolute;height:18px;width:18px;left:3px;top:3px;background:#fff;border-radius:50%;transition:.2s}
.nt-sw input:checked+span{background:var(--good)}.nt-sw input:checked+span:before{transform:translateX(18px)}
.nt-res{font-size:12px}.nt-res.ok{color:var(--good)}.nt-res.err{color:var(--dang)}
.wa-two{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:14px}@media(max-width:900px){.wa-two{grid-template-columns:1fr}}
.wa-ch{padding:12px 16px;border-bottom:1px solid var(--line);font-weight:700;font-size:14px;display:flex;align-items:center;gap:10px}.wa-ch .meta{margin-left:auto;font-size:12px}
.wa-tablewrap{overflow:auto;max-height:340px}
.smpro-table{width:100%;border-collapse:collapse;font-size:12.5px}
.smpro-table th,.smpro-table td{padding:9px 12px;text-align:left;border-bottom:1px solid var(--line)}
.smpro-table th{font-size:11px;text-transform:uppercase;color:var(--muted)}
.wa-qr{padding:18px;text-align:center;min-height:160px;display:flex;align-items:center;justify-content:center;flex-direction:column;gap:10px}
.wa-qr img{width:230px;height:230px;border:1px solid var(--line);border-radius:10px;background:#fff;padding:6px}
.mono{font-family:ui-monospace,Consolas,monospace}.meta{color:var(--muted)}
.b{display:inline-block;font-size:11px;font-weight:700;padding:2px 8px;border-radius:20px}
.b.green{background:var(--good-bg);color:var(--good)}.b.orange{background:var(--warn-bg);color:var(--warn)}.b.gray{background:#f1f5f9;color:#475569}.b.red{background:var(--dang-bg);color:var(--dang)}
.wa-mini{font-size:11px;font-weight:600;border:1px solid var(--line);background:#fff;border-radius:7px;padding:3px 9px;cursor:pointer;margin:1px}
</style>
<script>
(function(){
  function post(fd){fd.set('smpro_csrf',WA_CSRF);return fetch('index.cgi?page=whatsapp',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'}).then(function(r){return r.json();});}
  function res(el,j){if(!el)return;el.className='nt-res '+(j&&j.ok?'ok':'err');el.textContent=(j&&j.ok?'✅ ':'⚠ ')+((j&&j.msg)||'');}
  function esc(s){return String(s==null?'':s).replace(/[<>&"]/g,function(c){return{'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;'}[c];});}
  function gather(){var fd=new URLSearchParams();fd.set('wa_action','save');if(document.getElementById('waEnabled').checked)fd.set('wa_enabled','1');
    fd.set('base_url',document.getElementById('waBase').value);fd.set('api_key',document.getElementById('waKey').value);
    fd.set('session',document.getElementById('waSession').value);fd.set('chat_id',document.getElementById('waChat').value);return fd;}
  document.getElementById('waSave').addEventListener('click',function(){post(gather()).then(function(j){res(document.getElementById('waConnRes'),j);});});

  var stateEl=document.getElementById('waState');
  function setState(ok,txt){stateEl.className='wa-state '+(ok?'on':'off');stateEl.innerHTML='&#9679; '+txt;}
  document.getElementById('waHealth').addEventListener('click',function(){
    post(gather()).then(function(){var fd=new URLSearchParams();fd.set('wa_action','health');return post(fd);}).then(function(j){res(document.getElementById('waConnRes'),j);setState(j&&j.ok,j&&j.ok?'reachable':'unreachable');loadSessions();});
  });

  function isLinked(st){st=(st||'').toLowerCase();return st==='connected'||st==='working'||st==='ready'||st==='authenticated';}
  function actBtns(s){var id=esc(s.id||s.name);var linked=isLinked(s.status);
    var b='';
    if(linked){b+='<button class="wa-mini" data-wa="qr" data-id="'+id+'">QR</button>';}
    else{b+='<button class="wa-mini" data-wa="start" data-id="'+id+'">Start</button>';b+='<button class="wa-mini" data-wa="qr" data-id="'+id+'">Show QR</button>';}
    b+='<button class="wa-mini" data-wa="stop" data-id="'+id+'">Stop</button>';
    return b;
  }
  function stBadge(st){st=(st||'').toLowerCase();var c=isLinked(st)?'green':(st.indexOf('qr')>=0||st==='scan_qr'||st==='starting'||st==='initializing'?'orange':'gray');return '<span class="b '+c+'">'+esc(st||'—')+'</span>';}
  function loadSessions(){
    var fd=new URLSearchParams();fd.set('wa_action','sessions');
    post(fd).then(function(j){var tb=document.getElementById('waSessions');
      if(!j.ok){tb.innerHTML='<tr><td colspan="4" style="color:var(--dang);padding:14px">Could not load sessions (HTTP '+(j.code||0)+').</td></tr>';return;}
      var ss=j.sessions||[];if(!ss.length){tb.innerHTML='<tr><td colspan="4" style="padding:14px;color:var(--muted)">No sessions yet — create one above, Start it, then Show QR to link your phone.</td></tr>';return;}
      tb.innerHTML=ss.map(function(s){return '<tr><td class="mono"><b>'+esc(s.name||s.id)+'</b></td><td>'+stBadge(s.status)+'</td><td class="mono">'+esc(s.phone||'—')+(s.pushName?' <span class="meta">('+esc(s.pushName)+')</span>':'')+'</td><td>'+actBtns(s)+'</td></tr>';}).join('');
      var conn=ss.some(function(s){return isLinked(s.status);});setState(conn,conn?'linked':'not linked');
    });
  }
  document.getElementById('waReload').addEventListener('click',loadSessions);
  document.getElementById('waCreate').addEventListener('click',function(){
    var nm=document.getElementById('waNewName').value||document.getElementById('waSession').value;
    var fd=new URLSearchParams();fd.set('wa_action','create');fd.set('name',nm);
    post(fd).then(function(j){res(document.getElementById('waConnRes'),j);loadSessions();});
  });
  var qrTimer=null;
  function showQr(id, tries){
    tries=tries||0;
    if(qrTimer){clearTimeout(qrTimer);qrTimer=null;}
    var box=document.getElementById('waQrBox');
    if(tries===0)box.innerHTML='<div class="meta">⏳ Fetching QR for '+esc(id)+'…</div>';
    var fd=new URLSearchParams();fd.set('wa_action','qr');fd.set('id',id);
    post(fd).then(function(j){
      if(j.ok&&j.qr){
        var q=j.qr,src=q.indexOf('data:image')===0?q:(/^[A-Za-z0-9+/=]+$/.test(q)&&q.length>120?('data:image/png;base64,'+q):'');
        box.innerHTML=src?('<img src="'+src+'" alt="QR">'+'<div class="meta">Open WhatsApp → <b>Linked devices</b> → <b>Link a device</b>, then scan. Status: '+esc(j.status||'qr')+'</div>'):('<div class="meta" style="word-break:break-all">QR string: <code>'+esc(q.slice(0,80))+'…</code></div>');
        return;
      }
      if(j.pending&&tries<15){
        box.innerHTML='<div class="meta">⏳ Generating QR… (the session is starting, attempt '+(tries+1)+'/15)</div>';
        qrTimer=setTimeout(function(){showQr(id,tries+1);},2500);
        return;
      }
      box.innerHTML='<div class="nt-res err">⚠ '+esc(j.msg||'No QR')+'</div>'+(j.pending?'<div class="meta" style="margin-top:6px">Click <b>Start</b> on the session, then <b>Show QR</b> again.</div>':'');
    });
  }
  document.getElementById('waSessions').addEventListener('click',function(e){var b=e.target.closest('.wa-mini');if(!b)return;
    var act=b.getAttribute('data-wa'),id=b.getAttribute('data-id');
    if(act==='qr'){showQr(id);return;}
    if(!confirm(act.toUpperCase()+' session "'+id+'"?'))return;
    var fd=new URLSearchParams();fd.set('wa_action',act);fd.set('id',id);
    b.disabled=true;post(fd).then(function(j){res(document.getElementById('waConnRes'),j);setTimeout(loadSessions,800);if(act==='start')setTimeout(function(){showQr(id);},1200);});
  });
  document.getElementById('waSend').addEventListener('click',function(){
    post(gather()).then(function(){var fd=new URLSearchParams();fd.set('wa_action','send');fd.set('chat_id',document.getElementById('waSendTo').value);fd.set('text',document.getElementById('waSendText').value);return post(fd);}).then(function(j){res(document.getElementById('waSendRes'),j);});
  });
})();
</script>
<?php
smpro_layout_footer();
