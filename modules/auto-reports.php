<?php
/**
 * modules/auto-reports.php — schedule periodic security+health reports and pick delivery channels.
 * Config + "Generate now" go through the ?autoreport=1 endpoint (POST + CSRF + root).
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

$cfg  = smpro_rep_cfg();
$csrf = smpro_csrf_generate('autoreport');
$ch   = $cfg['channels'];

// view a single saved report
$viewId = isset($_GET['view']) ? preg_replace('/[^0-9_]/', '', (string)$_GET['view']) : '';
if ($viewId !== '') {
    $rep = smpro_rep_get($viewId);
    smpro_layout_header('Report ' . $viewId);
    echo '<p><a class="btn" href="index.cgi?page=auto-reports">&#8592; Back to Automatic Reports</a></p>';
    echo '<div class="card">' . ($rep ? smpro_rep_render_html($rep) : '<p>Report not found.</p>') . '</div>';
    smpro_layout_footer();
    return;
}

$ntf = function_exists('smpro_ntf_load') ? smpro_ntf_load() : [];
$chOk = [
    'email'    => !empty($ntf['email']['to']),
    'telegram' => !empty($ntf['telegram']['token']) && !empty($ntf['telegram']['chat_id']),
    'whatsapp' => !empty($ntf['whatsapp']['base_url']) && !empty($ntf['whatsapp']['chat_id']),
];
$ivOpt = ['daily' => 'Every day', '3days' => 'Every 3 days', 'weekly' => 'Every week', 'monthly' => 'Every month', 'custom' => 'Custom (days)'];
smpro_audit('auto_reports_view', ['enabled' => !empty($cfg['enabled'])]);
smpro_layout_header('Automatic Reports');
?>
<script>var AR_CSRF=<?= json_encode($csrf) ?>;</script>
<div class="svc-kicker">Settings</div>
<h1 class="h" style="margin:2px 0 4px">&#128202; Automatic Reports</h1>
<p class="sub">Generate a security &amp; health digest on a schedule and receive it where you want — in the panel, by email, Telegram or WhatsApp.</p>

<div class="card" style="max-width:720px">
  <label class="sw" style="display:inline-flex;margin-bottom:14px">
    <input type="checkbox" id="arEnabled" <?= !empty($cfg['enabled']) ? 'checked' : '' ?>>
    <span class="track"></span><span class="lbl"><b>Enable automatic reports</b></span><span class="st"></span>
  </label>

  <p style="font-weight:800;color:#0f2657;margin:6px 0 4px">How often</p>
  <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center">
    <select id="arInterval">
      <?php foreach ($ivOpt as $v => $lbl) echo '<option value="' . $v . '"' . (($cfg['interval'] ?? 'weekly') === $v ? ' selected' : '') . '>' . smpro_h($lbl) . '</option>'; ?>
    </select>
    <span id="arCustomWrap" style="<?= ($cfg['interval'] ?? '') === 'custom' ? '' : 'display:none' ?>">
      every <input type="number" id="arCustomDays" min="1" max="365" value="<?= (int)($cfg['custom_days'] ?? 7) ?>" style="width:72px"> day(s)
    </span>
  </div>

  <p style="font-weight:800;color:#0f2657;margin:16px 0 4px">Deliver to</p>
  <div style="display:grid;grid-template-columns:repeat(2,1fr);gap:8px;max-width:520px">
    <label class="lm-chkl"><input type="checkbox" id="arPanel" <?= !empty($ch['panel']) ? 'checked' : '' ?>> View in panel (saved here)</label>
    <label class="lm-chkl"><input type="checkbox" id="arEmail" <?= !empty($ch['email']) ? 'checked' : '' ?>> Email <?= $chOk['email'] ? '' : '<small style="color:#b45309">(set recipient in Notifications)</small>' ?></label>
    <label class="lm-chkl"><input type="checkbox" id="arTelegram" <?= !empty($ch['telegram']) ? 'checked' : '' ?>> Telegram <?= $chOk['telegram'] ? '' : '<small style="color:#b45309">(configure in Notifications)</small>' ?></label>
    <label class="lm-chkl"><input type="checkbox" id="arWhatsapp" <?= !empty($ch['whatsapp']) ? 'checked' : '' ?>> WhatsApp <?= $chOk['whatsapp'] ? '' : '<small style="color:#b45309">(configure in WhatsApp Gateway)</small>' ?></label>
  </div>

  <div id="arMsg" class="meta" style="margin:14px 0;min-height:18px"></div>
  <div style="display:flex;gap:10px;flex-wrap:wrap">
    <button class="btn" id="arSave" style="background:#16a34a;color:#fff">&#128190; Save schedule</button>
    <button class="btn" id="arGen">&#9889; Generate &amp; send now</button>
  </div>
  <p style="color:#64748b;font-size:12.5px;margin-top:10px">Reports run from the background worker (every 15&nbsp;min it checks whether the chosen interval has elapsed). Email/Telegram/WhatsApp reuse the credentials from the Notifications &amp; WhatsApp pages.</p>
</div>

<?php
$dg = function_exists('smpro_dg_cfg') ? smpro_dg_cfg() : ['enabled'=>false,'interval_hours'=>6,'ai_critical'=>null];
$tt = function_exists('smpro_ntf_types') ? smpro_ntf_types() : [];
$always = function_exists('smpro_dg_always_immediate') ? smpro_dg_always_immediate() : ['load_high'];
$critSet = function_exists('smpro_dg_critical_types') ? smpro_dg_critical_types() : [];
$qN = function_exists('smpro_dg_queue_count') ? smpro_dg_queue_count() : 0;
?>
<div class="card" style="max-width:720px;margin-top:14px">
  <h3 style="margin:0 0 4px">&#128276; Grouped alerts (quiet mode)</h3>
  <p class="sub" style="margin:0 0 10px">Instead of a message for every event (noise), routine alerts are <b>collected and sent as one digest</b> every interval you pick. <b>Server load</b> and the <b>maximum-danger indicators the AI selects</b> still alert you <b>immediately</b>.</p>

  <label class="sw" style="display:inline-flex;margin-bottom:12px">
    <input type="checkbox" id="dgEnabled" <?= !empty($dg['enabled']) ? 'checked' : '' ?>>
    <span class="track"></span><span class="lbl"><b>Batch routine alerts into a periodic digest</b></span><span class="st"></span>
  </label>

  <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:6px">
    <span style="font-weight:700;color:#0f2657;font-size:13px">Send the digest every</span>
    <input type="number" id="dgHours" min="1" max="168" value="<?= (int)($dg['interval_hours'] ?? 6) ?>" style="width:72px"> hour(s)
    <button class="btn" id="dgSave" style="background:#16a34a;color:#fff">Save</button>
    <button class="btn" id="dgFlush">Send digest now<?= $qN ? ' ('.$qN.' queued)' : '' ?></button>
  </div>

  <div style="margin-top:12px;background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px 12px">
    <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap">
      <b style="font-size:13px">Which indicators are "maximum danger" (sent immediately)?</b>
      <button class="btn" id="dgAi" style="padding:4px 10px;font-size:12px;background:var(--brand);color:#fff" <?= function_exists('smpro_ai_available') && smpro_ai_available() ? '' : 'disabled title="Configure an AI provider first"' ?>>&#129518; Let AI decide</button>
    </div>
    <div id="dgLists" style="margin-top:8px;font-size:12.5px;line-height:1.7">
      <div><span style="color:#b91c1c;font-weight:800">&#9889; Immediate:</span> <span id="dgImm"><?php
        $immLabels = [];
        foreach (array_unique(array_merge($always, $critSet)) as $k) $immLabels[] = smpro_h($tt[$k][0] ?? $k);
        echo implode(' · ', $immLabels);
      ?></span></div>
      <div style="color:#64748b;margin-top:3px"><span style="font-weight:800">&#128238; Batched into digest:</span> everything else. <span style="color:#16a34a">Server load is always immediate.</span></div>
      <div id="dgAiMsg" class="meta" style="margin-top:6px"></div>
    </div>
  </div>
</div>

<div class="card" style="max-width:720px;margin-top:14px">
  <h3 style="margin:0 0 8px">Generated reports</h3>
  <?php $list = smpro_rep_list(); if (!$list): ?>
    <p class="meta">No reports yet. Set a schedule, or click “Generate &amp; send now”.</p>
  <?php else: ?>
    <table style="width:100%"><tr><th style="text-align:left">When</th><th style="text-align:left">Period</th><th style="text-align:left">Attacks</th><th></th></tr>
    <?php foreach ($list as $r): ?>
      <tr><td><?= smpro_h(date('Y-m-d H:i', (int)$r['generated'])) ?></td><td><?= (int)$r['days'] ?>d</td><td><?= (int)$r['attacks'] ?></td>
      <td style="text-align:right"><a class="btn" href="index.cgi?page=auto-reports&view=<?= smpro_h($r['id']) ?>">View</a></td></tr>
    <?php endforeach; ?>
    </table>
  <?php endif; ?>
</div>

<script>(function(){
  function P(id){return document.getElementById(id);}
  P('arInterval').addEventListener('change',function(){P('arCustomWrap').style.display=this.value==='custom'?'':'none';});
  function post(action){var fd=new URLSearchParams();fd.set('smpro_csrf',AR_CSRF);fd.set('ar_action',action);
    fd.set('enabled',P('arEnabled').checked?'1':'');fd.set('interval',P('arInterval').value);fd.set('custom_days',P('arCustomDays').value);
    fd.set('ch_panel',P('arPanel').checked?'1':'');fd.set('ch_email',P('arEmail').checked?'1':'');fd.set('ch_telegram',P('arTelegram').checked?'1':'');fd.set('ch_whatsapp',P('arWhatsapp').checked?'1':'');
    return fetch('index.cgi?autoreport=1',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'}).then(function(r){return r.json();});}
  function msg(t,c){var m=P('arMsg');m.innerHTML=t;m.style.color=c||'#475569';}
  P('arSave').addEventListener('click',function(){var b=this;b.disabled=true;post('save').then(function(j){b.disabled=false;msg(j&&j.ok?'&#10003; Saved. Next report runs after the chosen interval.':'Save failed','#047857');}).catch(function(){b.disabled=false;msg('Save failed','#b91c1c');});});
  P('arGen').addEventListener('click',function(){var b=this;b.disabled=true;var o=b.innerHTML;b.innerHTML='Generating…';msg('Generating + delivering…');
    post('save').then(function(){return post('generate');}).then(function(j){b.disabled=false;b.innerHTML=o;
      if(j&&j.ok){msg('&#10003; Report generated and delivered via: '+((j.delivered||[]).join(', ')||'—')+'. Reload to see it listed.','#047857');}
      else{msg('&#10007; '+((j&&(j.message||j.skipped))||'Failed'),'#b91c1c');}
    }).catch(function(){b.disabled=false;b.innerHTML=o;msg('Request failed','#b91c1c');});});

  // --- grouped alerts / quiet digest ---
  function dgPost(action,extra){var fd=new URLSearchParams();fd.set('smpro_csrf',AR_CSRF);fd.set('ar_action',action);
    if(extra)Object.keys(extra).forEach(function(k){fd.set(k,extra[k]);});
    return fetch('index.cgi?autoreport=1',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'}).then(function(r){return r.json();});}
  function dgMsg(t,c){var m=P('dgAiMsg');if(m){m.innerHTML=t;m.style.color=c||'#475569';}}
  if(P('dgSave'))P('dgSave').addEventListener('click',function(){var b=this;b.disabled=true;
    dgPost('dgsave',{dg_enabled:P('dgEnabled').checked?'1':'',dg_hours:P('dgHours').value}).then(function(j){b.disabled=false;dgMsg(j&&j.ok?'&#10003; Saved.':'Save failed',j&&j.ok?'#047857':'#b91c1c');}).catch(function(){b.disabled=false;dgMsg('Save failed','#b91c1c');});});
  if(P('dgFlush'))P('dgFlush').addEventListener('click',function(){var b=this;b.disabled=true;var o=b.innerHTML;b.innerHTML='Sending…';
    dgPost('dgflush').then(function(j){b.disabled=false;b.innerHTML=o;
      if(j&&j.ok)dgMsg('&#10003; Digest sent ('+j.count+' event(s)) via: '+((j.channels||[]).join(', ')||'—'),'#047857');
      else dgMsg(j&&j.skip==='empty'?'Nothing queued right now.':('Nothing sent ('+((j&&j.skip)||'—')+')'),'#64748b');}).catch(function(){b.disabled=false;b.innerHTML=o;dgMsg('Request failed','#b91c1c');});});
  if(P('dgAi'))P('dgAi').addEventListener('click',function(){var b=this;b.disabled=true;var o=b.innerHTML;b.innerHTML='&#129518; Classifying…';dgMsg('AI is triaging the alert types…');
    dgPost('dgclassify').then(function(j){b.disabled=false;b.innerHTML=o;
      if(j&&j.ok){var names=(j.immediate||[]);dgMsg('&#10003; AI set '+names.length+' indicator(s) as maximum-danger (immediate)'+(j.provider?' · '+j.provider:'')+'. Reload to see the updated list.','#047857');}
      else dgMsg('&#10007; '+String((j&&j.msg)||'AI failed').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'),'#b91c1c');}).catch(function(){b.disabled=false;b.innerHTML=o;dgMsg('Request failed','#b91c1c');});});
})();</script>
<?php
smpro_layout_footer();
