<?php
/** includes/sdbulk_ui.php - the "All sites" card on the Site Doctor page (engine: includes/sdbulk.php). */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }
?>
<div class="card sdb" id="sdBulk">
  <div class="sdb-head">
    <div><h2 class="h" style="margin:0;font-size:17px" data-i18n>All sites</h2>
      <p class="sub" style="margin:2px 0 0" data-i18n>Check every domain, sub-domain and add-on on this server, see which ones fail and why, then fix the ones you tick. Every edited file is backed up first; backups are removed after 7 days.</p></div>
    <div class="sdb-ctl">
      <button class="sd-go" id="sdbScan" type="button" data-i18n>Scan all sites</button>
      <label class="sdb-sw" title="Once a day, failing sites get the safe fixes automatically. Never changes a PHP version, a database, a shared service or a locked site."><input type="checkbox" id="sdbAuto"> <span data-i18n>Automatic fixing</span></label>
    </div>
  </div>
  <div id="sdbJob" class="sdb-job"></div>
  <div class="sdb-bar">
    <select id="sdbFilter"><option value="problem">Failing only</option><option value="all">All sites</option><option value="fixed">Fixed</option></select>
    <input type="text" id="sdbFind" placeholder="Filter by domain or account" autocomplete="off">
    <button class="sd-go sd-auto" id="sdbFix" type="button" disabled>Fix selected</button>
  </div>
  <div style="overflow-x:auto"><table class="tbl sdb-tbl"><thead><tr><th><input type="checkbox" id="sdbAll"></th><th>Site</th><th>Account</th><th>Platform</th><th>Answer</th><th>Problem / cause</th><th>Fix</th><th></th></tr></thead><tbody id="sdbRows"></tbody></table></div>
  <div id="sdbRep" class="sdb-rep"></div>
</div>
<style>
.sdb{margin-top:18px;padding:16px}.sdb-head{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;align-items:flex-start}
.sdb-ctl{display:flex;gap:10px;align-items:center}.sdb-sw{font-size:13px;font-weight:700;display:flex;gap:6px;align-items:center;cursor:pointer}
.sdb-job{margin:10px 0;font-size:13px}.sdb-bar{display:flex;gap:8px;margin:8px 0;flex-wrap:wrap}.sdb-bar input,.sdb-bar select{border:1px solid var(--line);border-radius:9px;padding:8px 10px}
.sdb-tbl td{font-size:13px;vertical-align:top}.sdb-pill{display:inline-block;border-radius:20px;padding:1px 8px;font-size:12px;font-weight:700}
.sdb-ok{background:#dcfce7;color:#166534}.sdb-bad{background:#fee2e2;color:#991b1b}.sdb-rep{margin-top:12px}.sdb-rep pre{white-space:pre-wrap;font-size:12px}
</style>
<script>
(function(){
  var st=null,timer=null,$=function(i){return document.getElementById(i);};
  function e(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
  function post(d){var f=new URLSearchParams();f.set('smpro_csrf',SD_CSRF);Object.keys(d).forEach(function(k){f.set(k,d[k]);});
    return fetch('index.cgi?page=site-doctor',{method:'POST',body:f,credentials:'same-origin'}).then(function(r){return r.json();});}
  function load(){fetch('index.cgi?page=site-doctor&sd_bulk=1',{cache:'no-store',credentials:'same-origin'}).then(function(r){return r.json();}).then(function(j){st=j;draw();clearTimeout(timer);if(j.job&&j.job.running)timer=setTimeout(load,4000);}).catch(function(){});}
  function vals(o){return Object.keys(o||{}).map(function(k){return o[k];});}
  function draw(){
    $('sdbAuto').checked=!!st.cfg.auto;
    var jb=st.job||{},sc=st.scan||{},rs=vals(sc.results),msg;
    if(jb.running)msg=(jb.kind==='fix'?'Fixing '+(jb.done||0)+' of '+(jb.total||0)+' site(s)…':'Scanning '+(sc.done||0)+' of '+(sc.total||'?')+' sites…')+' You can close this page; it keeps running.';
    else if(sc.finished)msg='Last scan: '+new Date(sc.finished*1000).toLocaleString()+' — '+rs.length+' sites, '+rs.filter(function(r){return r.state==='problem';}).length+' failing.';
    else msg='No scan yet. Press "Scan all sites".';
    $('sdbJob').textContent=msg; $('sdbScan').disabled=!!jb.running;
    var f=$('sdbFilter').value,q=$('sdbFind').value.toLowerCase(),h='';
    rs.forEach(function(r){
      var rp=(st.reports||{})[r.domain];
      if(f==='problem'&&r.state!=='problem')return;
      if(f==='fixed'&&!(rp&&rp.ok&&rp.changed&&rp.changed.length))return;
      if(q&&(r.domain+' '+r.user).toLowerCase().indexOf(q)<0)return;
      var fx=(r.fixes||[]).map(function(x){return e(x.label)+(x.auto?'':' <small>(by hand only)</small>');}).join('<br>')||(r.state==='problem'?'<small>none known — open the site</small>':'');
      h+='<tr><td>'+(r.state==='problem'?'<input type="checkbox" class="sdbChk" value="'+e(r.domain)+'">':'')+'</td>'
        +'<td><a href="#" class="sdbOne" data-d="'+e(r.domain)+'">'+e(r.domain)+'</a></td><td>'+e(r.user)+'</td>'
        +'<td>'+e(r.platform||'')+(r.php?' <small>PHP '+e(r.php)+'</small>':'')+'</td>'
        +'<td><span class="sdb-pill '+(r.state==='ok'?'sdb-ok':'sdb-bad')+'">'+e(r.code||'—')+'</span></td>'
        +'<td>'+e(r.text)+(r.cause?'<br><small>'+e(r.cause)+'</small>':'')+(r.locked?'<br><small>files locked</small>':'')+'</td><td>'+fx+'</td>'
        +'<td>'+(rp?'<a href="#" class="sdbRep" data-d="'+e(r.domain)+'">report</a>':'')+'</td></tr>';
    });
    $('sdbRows').innerHTML=h||'<tr><td colspan="8"><small>Nothing to show.</small></td></tr>';
    sel();
  }
  function sel(){var n=document.querySelectorAll('.sdbChk:checked').length,b=$('sdbFix');b.disabled=!n||!!(st&&st.job&&st.job.running);b.textContent=n?'Fix selected ('+n+')':'Fix selected';}
  function report(d){var r=(st.reports||{})[d];if(!r)return;var NL='\n';
    var t='Site: '+r.domain+'   ('+r.mode+', '+new Date(r.ts*1000).toLocaleString()+')'+NL
      +'Platform: '+(r.platform||'?')+(r.php?'   PHP '+r.php:'')+NL+'Problem: '+(r.problem||'')+NL+'Cause: '+(r.cause||'not determined')+NL+NL
      +'What was done:'+NL+'  '+(r.steps||[]).join(NL+'  ')+NL+NL
      +'Files changed (backup kept '+(st.keep_days||7)+' days):'+NL+'  '+((r.changed||[]).map(function(c){return c.what+': '+c.file+(c.backup?'  -> backup '+c.backup:'');}).join(NL+'  ')||'none')+NL+NL
      +'Before: '+(r.before?r.before.code+' '+r.before.text:'')+NL+'After:  '+(r.after?r.after.code+' '+r.after.text:'')+NL
      +'Result: '+(r.ok?'FIXED':'NOT FIXED')+(r.rolled_back?' (changes undone)':'')+NL+'Undo ids: '+((r.undo||[]).join(', ')||'none');
    $('sdbRep').innerHTML='<h3 class="h" style="font-size:15px">Report — '+e(d)+'</h3><pre>'+e(t)+'</pre>';$('sdbRep').scrollIntoView({behavior:'smooth'});}
  $('sdbScan').onclick=function(){post({sd_action:'bulk_scan'}).then(function(j){$('sdbJob').textContent=j.msg||'';setTimeout(load,1500);});};
  $('sdbFix').onclick=function(){var d=[].map.call(document.querySelectorAll('.sdbChk:checked'),function(c){return c.value;});
    if(!d.length||!confirm('Fix '+d.length+' site(s)? Every file changed is backed up first and can be undone for 7 days.'))return;
    post({sd_action:'bulk_fix',domains:d.join(',')}).then(function(j){$('sdbJob').textContent=j.msg||'';setTimeout(load,1500);});};
  $('sdbAuto').onchange=function(){var on=this.checked;
    if(on&&!confirm('Turn on automatic fixing? Once a day the safe fixes are applied to failing sites (backup first, 7-day undo). PHP versions, databases, shared services and locked sites are never touched automatically.')){this.checked=false;return;}
    post({sd_action:'bulk_cfg',auto:on?'1':'0',scan_daily:'1'}).then(function(j){$('sdbJob').textContent=j.msg||'';load();});};
  $('sdbFilter').onchange=draw; $('sdbFind').oninput=draw;
  $('sdbAll').onchange=function(){var on=this.checked;[].forEach.call(document.querySelectorAll('.sdbChk'),function(c){c.checked=on;});sel();};
  $('sdbRows').addEventListener('change',sel);
  $('sdbRows').addEventListener('click',function(ev){var a=ev.target.closest('a');if(!a)return;ev.preventDefault();
    if(a.className==='sdbRep')report(a.dataset.d);else{var i=$('sdTarget');i.value=a.dataset.d;window.scrollTo({top:0,behavior:'smooth'});$('sdGo').click();}});
  load();
})();
</script>
