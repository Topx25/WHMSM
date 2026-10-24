<?php
/**
 * modules/site-doctor.php - Site Doctor: diagnose WHY a site is failing (500/blank/down) and
 * apply a SAFE, REVERSIBLE fix (incl. AI-driven). Engine: includes/investigate.php.
 * Every fix is backup-first (rename, never delete), path-whitelisted to the account docroot,
 * hardening-aware (clears chattr +i, re-locks after), and one-click undoable.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

$reqMethod = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? getenv('REQUEST_METHOD') ?: 'GET'));

/* ---- all JSON endpoints below run privileged engines on arbitrary targets - root only ---- */
if (isset($_GET['sd_investigate']) || isset($_GET['sd_speed']) || isset($_GET['sd_optimize']) || isset($_GET['sd_clearcache_preview'])) {
    smpro_require_root();
}

/* ---- diagnose (GET JSON) ---- */
if (($_GET['sd_investigate'] ?? '') === '1') {
    header('Content-Type: application/json');
    $r = smpro_inv_run((string)($_GET['target'] ?? ''));
    smpro_audit('sitedoctor_investigate', ['target'=>(string)($_GET['target'] ?? ''),'ok'=>!empty($r['ok'])]);
    echo json_encode($r, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit;
}
/* ---- speed diagnosis (GET JSON) ---- */
if (($_GET['sd_speed'] ?? '') === '1') {
    header('Content-Type: application/json');
    $r = function_exists('smpro_inv_speed') ? smpro_inv_speed((string)($_GET['target'] ?? '')) : ['ok'=>false,'msg'=>'Speed engine unavailable.'];
    echo json_encode($r, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit;
}
/* ---- optimize scan (GET JSON, read-only) ---- */
if (($_GET['sd_optimize'] ?? '') === '1') {
    header('Content-Type: application/json');
    $r = function_exists('smpro_inv_optimize_scan') ? smpro_inv_optimize_scan((string)($_GET['target'] ?? '')) : ['ok'=>false,'msg'=>'Optimize engine unavailable.'];
    echo json_encode($r, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit;
}
/* ---- clear-cache dry-run (GET JSON, read-only) ---- */
if (($_GET['sd_clearcache_preview'] ?? '') === '1') {
    header('Content-Type: application/json');
    echo json_encode(function_exists('smpro_inv_clearcache_plan') ? smpro_inv_clearcache_plan((string)($_GET['target'] ?? '')) : ['ok'=>false,'msg'=>'Cache engine unavailable.'], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit;
}
/* ---- fix / undo / ai-fix / ai-verdict / optimize / clearcache (POST + CSRF + root) ---- */
if ($reqMethod === 'POST' && in_array(($_POST['sd_action'] ?? ''), ['fix','undo','fixit','ai_fix','ai','optimize','optimize_install','optimize_server','undo_run','clearcache'], true)) {
    smpro_require_valid_csrf('sd_action'); smpro_require_root();
    header('Content-Type: application/json');
    $act = $_POST['sd_action'];
    if ($act === 'fix')      { echo json_encode(smpro_inv_fix((string)($_POST['act'] ?? ''), (string)($_POST['target'] ?? ''), (string)($_POST['path'] ?? '')), JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit; }
    if ($act === 'undo')     { echo json_encode(smpro_inv_undo((string)($_POST['id'] ?? '')), JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit; }
    if ($act === 'optimize') { echo json_encode(function_exists('smpro_inv_optimize_apply') ? smpro_inv_optimize_apply((string)($_POST['target'] ?? ''), (string)($_POST['id'] ?? ''), (string)($_POST['run'] ?? '')) : ['ok'=>false,'msg'=>'Optimize engine unavailable.'], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit; }
    if ($act === 'optimize_install') { echo json_encode(function_exists('smpro_pkg_install_group') ? smpro_pkg_install_group((string)($_POST['group'] ?? '')) : ['ok'=>false,'msg'=>'Installer unavailable.'], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit; }
    if ($act === 'optimize_server') { echo json_encode(function_exists('smpro_inv_optimize_apply_server') ? smpro_inv_optimize_apply_server((string)($_POST['rec'] ?? '')) : ['ok'=>false,'msg'=>'Server tune-up unavailable.'], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit; }
    if ($act === 'undo_run') { echo json_encode(function_exists('smpro_inv_optimize_undo_run') ? smpro_inv_optimize_undo_run((string)($_POST['run'] ?? '')) : ['ok'=>false,'msg'=>'Undo unavailable.'], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit; }
    if ($act === 'fixit')    { echo json_encode(smpro_inv_fixit((string)($_POST['target'] ?? '')), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit; }   // deterministic
    if ($act === 'ai_fix')   { echo json_encode(smpro_inv_ai_plan((string)($_POST['target'] ?? '')), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit; }  // AI takes over + executes
    if ($act === 'clearcache') {   // platform-aware, drop-to-user cache clear; CageFS remount is opt-in via remount_cagefs=1
        $doRemount = ((string)($_POST['remount_cagefs'] ?? '') === '1');
        echo json_encode(function_exists('smpro_inv_clearcache') ? smpro_inv_clearcache((string)($_POST['target'] ?? ''), $doRemount) : ['ok'=>false,'msg'=>'Cache engine unavailable.'], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit;
    }
    if ($act === 'ai') {
        if (!function_exists('smpro_ai_available') || !smpro_ai_available()) { echo json_encode(['ok'=>false,'error'=>'No AI provider configured.']); exit; }
        $res = smpro_inv_run((string)($_POST['target'] ?? '')); if (empty($res['ok'])) { echo json_encode(['ok'=>false,'error'=>$res['msg'] ?? 'resolve failed']); exit; }
        $ev = "Site: " . $res['domain'] . " (account " . $res['user'] . ", PHP " . ($res['phpver'] ?: '?') . ", HTTP " . $res['http']['code'] . ")\n";
        foreach ($res['fatals'] as $f) $ev .= "FATAL: " . $f['msg'] . "\n";
        if (!empty($res['recent'])) { $ev .= "Recently changed:\n"; foreach (array_slice($res['recent'], 0, 10) as $c) $ev .= "  " . $c['time'] . " " . $c['path'] . "\n"; }
        $sys = "You are a senior cPanel/WHM hosting support engineer. Given diagnostic evidence for a failing website, state the SINGLE most likely root cause in one sentence, then numbered concrete fix steps (safest first). Be specific and short.";
        $r = smpro_ai_chat($sys, function_exists('smpro_ai_redact') ? smpro_ai_redact($ev) : $ev, ['max_tokens'=>600,'context'=>'sitedoctor']);
        echo json_encode(['ok'=>!empty($r['ok']),'text'=>$r['text'] ?? '','error'=>$r['error'] ?? '','provider'=>$r['provider'] ?? ''], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit;
    }
}

$csrf = smpro_csrf_generate('sd_action');
$aiReady = function_exists('smpro_ai_available') && smpro_ai_available();
$qtarget = smpro_h($_GET['target'] ?? '');
smpro_audit('sitedoctor_view', []);
smpro_layout_header('Site Doctor');
?>
<script>var SD_CSRF=<?= json_encode($csrf) ?>;</script>
<div class="svc-kicker">Diagnose &amp; fix</div>
<h1 class="h" style="margin:2px 0 4px">&#129658; Site Doctor</h1>
<p class="sub" data-i18n>Find out why a site is failing — 500 / blank page / errors — and fix it safely. Enter a domain or cPanel account; every fix is reversible.</p>

<div class="sd-search">
  <form id="sdForm" onsubmit="return false">
    <input type="text" id="sdTarget" class="sd-in" value="<?= $qtarget ?>" placeholder="domain.com  or  cPanel account…" autocomplete="off" autofocus>
    <button class="sd-go" id="sdGo" type="submit">&#128270; Diagnose</button>
    <button class="sd-go sd-speed" id="sdSpeed" type="button" title="Measure why the site is slow">&#9889; Diagnose speed</button>
    <button class="sd-go sd-opt" id="sdOpt" type="button" title="Find & apply speed optimizations">&#128640; Optimize</button>
    <button class="sd-go sd-auto" id="sdAuto" type="button" title="Install tools if needed, then apply every safe reversible optimization">&#9889; Auto-optimize</button>
  </form>
</div>
<div id="sdOut" class="sd-out"></div>

<style>
.svc-kicker{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--brand);font-weight:800}
.sd-search{margin:14px 0 6px}.sd-search form{display:flex;gap:8px;max-width:560px}
.sd-in{flex:1;border:1px solid var(--line);border-radius:11px;padding:12px 15px;font-size:15px}
.sd-go{border:none;background:var(--brand);color:#fff;border-radius:11px;padding:12px 20px;font-size:14px;font-weight:700;cursor:pointer;white-space:nowrap}
.sd-go:disabled{opacity:.6}
.sd-go.sd-speed{background:#7c3aed}
.sd-go.sd-opt{background:#0891b2}
.sd-go.sd-auto{background:#059669}
.sd-out{margin-top:16px;width:100%}
/* optimize layer */
.sd-ostack{display:flex;flex-wrap:wrap;gap:8px;padding:16px 20px;border-bottom:1px solid var(--line);align-items:center}
.sd-ochip{font-size:12px;color:#475569;background:var(--card);border:1px solid var(--line);border-radius:8px;padding:4px 11px}
.sd-ochip b{color:var(--ink)}
.sd-ochip.good{border-color:var(--good);color:var(--good)}.sd-ochip.warn{border-color:#f59e0b;color:#b45309}
.sd-osum{display:flex;flex-wrap:wrap;gap:10px;padding:14px 20px;border-bottom:1px solid var(--line)}
.sd-ometric{flex:1;min-width:120px;background:var(--card);border:1px solid var(--line);border-radius:11px;padding:11px 14px}
.sd-ometric .n{font-size:22px;font-weight:800;line-height:1}.sd-ometric .l{font-size:11px;text-transform:uppercase;letter-spacing:.03em;color:var(--muted);margin-top:3px}
.sd-ogrp{padding:14px 20px 4px}.sd-ogrp h4{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);margin:0 0 10px;display:flex;align-items:center;gap:8px}
.sd-ocard{border:1px solid var(--line);border-radius:13px;margin-bottom:12px;overflow:hidden}
.sd-ocard.safe{border-left:4px solid var(--good)}.sd-ocard.appr{border-left:4px solid #0891b2}.sd-ocard.adv{border-left:4px solid #94a3b8}
.sd-ochd{display:flex;gap:12px;align-items:flex-start;padding:13px 16px;cursor:pointer;user-select:none}
.sd-ochd .ic{font-size:20px;line-height:1;flex-shrink:0}
.sd-ochd .tt{flex:1;min-width:0}.sd-ochd .tt b{display:block;font-size:14.5px;margin-bottom:2px}
.sd-ochd .tt .d{font-size:12.5px;color:var(--muted);line-height:1.5}
.sd-otag{font-size:9.5px;font-weight:800;padding:3px 8px;border-radius:7px;text-transform:uppercase;flex-shrink:0;white-space:nowrap}
.sd-otag.safe{background:var(--good-bg);color:var(--good)}.sd-otag.appr{background:#cffafe;color:#0e7490}.sd-otag.adv{background:var(--card);color:#475569;border:1px solid var(--line)}
.sd-otag.imp{background:var(--dang-bg);color:#b91c1c;margin-left:6px}
.sd-obody{padding:0 16px 14px;border-top:1px solid var(--line)}
.sd-ocard.collapsed .sd-obody{display:none}
.sd-ochd::after{content:"\25B8";margin-left:auto;color:var(--muted);font-size:11px;align-self:center;transition:transform .15s}
.sd-ocard:not(.collapsed) .sd-ochd::after{transform:rotate(90deg)}
.sd-ometh{font-size:12.5px;color:var(--ink);background:var(--bg);border-radius:9px;padding:9px 12px;margin:12px 0}
.sd-ofiles{width:100%;border-collapse:collapse;font-size:12px;margin-top:4px}
.sd-ofiles th,.sd-ofiles td{padding:7px 10px;text-align:left;border-bottom:1px solid var(--line)}
.sd-ofiles th{font-size:10px;text-transform:uppercase;color:var(--muted)}
.sd-ofiles td.sz{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.sd-ofiles tr.rej{opacity:.4;text-decoration:line-through}
.sd-ofiles tr.done td{color:var(--good)}
.sd-ofsel{display:flex;gap:6px}
.sd-fbtn{border:1px solid var(--line);background:var(--card);border-radius:7px;padding:3px 9px;font-size:11px;cursor:pointer;font-weight:700}
.sd-fbtn.on{background:var(--good);color:#fff;border-color:var(--good)}
.sd-fbtn.rejon{background:var(--dang);color:#fff;border-color:var(--dang)}
.sd-oact{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-top:13px}
.sd-obtn{border:none;border-radius:10px;padding:9px 16px;font-size:13px;font-weight:700;cursor:pointer;color:#fff}
.sd-obtn.safe{background:var(--good)}.sd-obtn.appr{background:#0891b2}.sd-obtn:disabled{opacity:.55;cursor:default}
.sd-onote{font-size:11.5px;color:var(--muted)}
.sd-oinstall{font-family:ui-monospace,Consolas,monospace;font-size:11.5px;background:#0f172a;color:#e2e8f0;border-radius:7px;padding:3px 8px}
.sd-odeep{display:inline-block;margin-top:8px;font-size:12px;font-weight:700;color:var(--brand);text-decoration:none;border:1px solid var(--line);border-radius:8px;padding:4px 11px}
.sd-oskip{font-size:12px;color:var(--good);padding:2px 0}
/* speed diagnosis */
.sd-spdhero{display:flex;align-items:center;gap:18px;padding:18px 20px;border-bottom:1px solid var(--line);flex-wrap:wrap}
.sd-spdnum{min-width:120px}.sd-spdnum .n{font-size:34px;font-weight:800;line-height:1}.sd-spdnum .n small{font-size:14px;font-weight:700;color:var(--muted)}
.sd-spdnum .l{font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);margin-top:2px}
.sd-vbadge{display:inline-block;font-size:12px;font-weight:800;padding:3px 12px;border-radius:20px;text-transform:uppercase;letter-spacing:.03em}
.sd-vbadge.fast{background:var(--good-bg);color:var(--good)}.sd-vbadge.okay{background:var(--card);color:#475569;border:1px solid var(--line)}
.sd-vbadge.slow{background:var(--warn-bg);color:#b45309}.sd-vbadge.very_slow{background:var(--dang-bg);color:#b91c1c}
.sd-tbwrap{flex:1;min-width:260px}
.sd-tbar{display:flex;height:26px;border-radius:8px;overflow:hidden;border:1px solid var(--line)}
.sd-tseg{height:100%;min-width:2px}.sd-tseg.dns{background:#94a3b8}.sd-tseg.connect{background:#38bdf8}.sd-tseg.tls{background:#6366f1}.sd-tseg.think{background:#f59e0b}.sd-tseg.download{background:#10b981}
.sd-tlegend{display:flex;flex-wrap:wrap;gap:4px 14px;margin-top:9px;font-size:11.5px;color:var(--muted)}
.sd-tlegend span{display:inline-flex;align-items:center;gap:5px}.sd-tlegend i{width:10px;height:10px;border-radius:3px;display:inline-block}
.sd-tchips{display:flex;flex-wrap:wrap;gap:6px;padding:12px 20px;border-bottom:1px solid var(--line)}
.sd-tchip{font-size:11.5px;color:#475569;background:var(--card);border:1px solid var(--line);border-radius:8px;padding:3px 10px}
.sd-tchip b{color:var(--ink)}.sd-tchip.warn{border-color:#f59e0b;color:#b45309}
.sd-cz{padding:14px 20px 6px}.sd-cz h4{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);margin:0 0 10px}
.sd-czrow{display:flex;gap:12px;padding:12px 0;border-bottom:1px solid var(--line);align-items:flex-start}.sd-czrow:last-child{border-bottom:0}
.sd-czsev{font-size:10px;font-weight:800;padding:3px 8px;border-radius:7px;text-transform:uppercase;flex-shrink:0;margin-top:1px}
.sd-czsev.high{background:var(--dang-bg);color:#b91c1c}.sd-czsev.medium{background:var(--warn-bg);color:#b45309}.sd-czsev.low{background:var(--card);color:#475569;border:1px solid var(--line)}
.sd-czmain{flex:1;min-width:0}.sd-czmain b{display:block;font-size:14px;margin-bottom:2px}
.sd-czev{font-size:12.5px;color:var(--muted);margin-bottom:5px}.sd-czfix{font-size:13px;color:var(--ink)}
.sd-czact{display:inline-block;margin-top:6px;font-size:12px;font-weight:700;color:var(--brand);text-decoration:none;border:1px solid var(--line);border-radius:8px;padding:4px 11px}
.sd-czact:hover{border-color:var(--brand)}
.sd-card{background:var(--card);border:1px solid var(--line);border-radius:16px;overflow:hidden;box-shadow:0 8px 28px rgba(15,23,42,.06)}
.sd-hero{display:flex;align-items:center;gap:16px;padding:18px 20px;border-bottom:1px solid var(--line)}
.sd-http{width:72px;height:72px;border-radius:16px;display:flex;flex-direction:column;align-items:center;justify-content:center;font-size:22px;font-weight:800;flex-shrink:0;color:#fff;line-height:1}
.sd-http small{font-size:9px;font-weight:600;opacity:.85;margin-top:2px;text-transform:uppercase}
.sd-http.ok{background:var(--good)}.sd-http.bad{background:var(--dang)}.sd-http.warn{background:#d97706}.sd-http.na{background:#94a3b8}
.sd-hmeta{flex:1;min-width:0}.sd-dom{font-size:20px;font-weight:800;word-break:break-all}.sd-facts{color:var(--muted);font-size:13px;margin-top:4px}
.sd-facts .chip{display:inline-block;background:var(--card);border-radius:8px;padding:2px 9px;margin:2px 4px 0 0;font-size:12px;color:#475569}
.sd-cause{padding:16px 20px;display:flex;gap:14px;align-items:flex-start}
.sd-cause.bad{background:var(--dang-bg)}.sd-cause.good{background:var(--good-bg)}
.sd-cause .ci{font-size:24px;line-height:1}.sd-cause .ct{flex:1}.sd-cause b{display:block;margin-bottom:4px;font-size:15px}
/* clean diagnosis card (DNS / redirect-loop) */
.sd-card2{border:1px solid var(--line);border-left:4px solid var(--dang);border-radius:12px;overflow:hidden;margin:2px 0}
.sd-card2.bad{border-left-color:var(--dang)}
.sd-card2 .c2h{display:flex;gap:13px;align-items:flex-start;padding:15px 18px;background:var(--dang-bg)}
.sd-card2 .c2ic{font-size:26px;line-height:1;flex-shrink:0}
.sd-card2 .c2t{flex:1;min-width:0}.sd-card2 .c2t b{display:block;font-size:15px;color:#1d2327;margin-bottom:3px}
.sd-card2 .c2sub{font-size:12.5px;color:var(--muted);line-height:1.5}
.sd-card2 .c2body{padding:14px 18px;background:var(--card)}
.sd-card2 .c2plan-t{font-size:12px;font-weight:700;color:#64748b;text-transform:uppercase;letter-spacing:.03em;margin-bottom:8px}
.sd-plan{margin:0;padding:0;list-style:none;counter-reset:sp}
.sd-plan li{counter-increment:sp;position:relative;padding:7px 0 7px 32px;font-size:13.5px;color:var(--ink);border-bottom:1px dashed var(--line)}
.sd-plan li:last-child{border-bottom:0}
.sd-plan li::before{content:counter(sp);position:absolute;left:0;top:6px;width:21px;height:21px;border-radius:50%;background:var(--brand);color:#fff;font-size:11px;font-weight:700;display:flex;align-items:center;justify-content:center}
.sd-plan li b{font-weight:700}.sd-plan .sd-plan-w{display:block;font-size:11.5px;color:var(--muted);margin-top:1px}
.sd-card2 .c2note{margin-top:10px;font-size:12px;color:var(--muted);background:var(--bg);border-radius:8px;padding:8px 11px}
.sd-card2 code{background:var(--bg);padding:1px 6px;border-radius:5px;font-size:12px}
.sd-fixrow{display:flex;gap:10px;flex-wrap:wrap;margin-top:12px}
.sd-fixbtn{border:none;border-radius:10px;padding:10px 16px;font-size:13px;font-weight:700;cursor:pointer;color:#fff}
.sd-fixbtn.go{background:var(--good)}.sd-fixbtn.ai{background:var(--brand)}.sd-fixbtn:disabled{opacity:.6}
.sd-sec{padding:15px 20px;border-top:1px solid var(--line)}.sd-sec h4{margin:0;font-size:13px;display:flex;align-items:center;gap:7px;cursor:pointer;user-select:none}
.sd-sec h4::before{content:"\25B8";font-size:11px;color:var(--muted);transition:transform .15s;display:inline-block}
.sd-sec:not(.collapsed) h4{margin-bottom:9px}
.sd-sec:not(.collapsed) h4::before{transform:rotate(90deg)}
.sd-sec.collapsed > :not(h4){display:none}
.sd-scroll{max-height:240px;overflow:auto;border:1px solid var(--line);border-radius:10px}
.sd-tbl{width:100%;border-collapse:collapse;font-size:12px}.sd-tbl th,.sd-tbl td{padding:8px 11px;text-align:left;border-bottom:1px solid var(--line)}
.sd-tbl th{font-size:10.5px;text-transform:uppercase;color:var(--muted);background:var(--card);position:sticky;top:0}
.sd-tbl tr:last-child td{border-bottom:none}
.sd-mono{font-family:ui-monospace,Consolas,monospace;font-size:11px;word-break:break-all}
.sd-pre{background:#0f172a;color:#e2e8f0;padding:11px;border-radius:9px;overflow:auto;max-height:180px;font-size:11px;margin:0}
.sd-code{background:var(--card);border:1px solid var(--line);border-radius:9px;padding:11px 13px;font-family:ui-monospace,Consolas,monospace;font-size:11.5px;line-height:1.6;color:#334155;max-height:200px;overflow:auto;white-space:nowrap}
.sd-disk{max-width:420px}
.sd-bar{height:10px;border-radius:6px;background:var(--card);overflow:hidden}
.sd-fill{display:block;height:100%;border-radius:6px;background:var(--good)}.sd-fill.warn{background:#d97706}.sd-fill.bad{background:var(--dang)}
.sd-diskmeta{font-size:13px;color:var(--muted);margin-top:7px}.sd-diskmeta b{color:var(--ink);font-size:15px}
.sd-foot{display:flex;gap:10px;align-items:center;flex-wrap:wrap;padding:14px 20px;border-top:1px solid var(--line)}
.sd-ghost{border:1px solid var(--line);background:var(--card);border-radius:9px;padding:9px 14px;font-size:12.5px;cursor:pointer;font-weight:600;color:var(--ink)}
.sd-ghost:hover{border-color:var(--brand);color:var(--brand)}
.sd-badge{display:inline-block;font-size:11px;font-weight:700;padding:2px 9px;border-radius:20px;background:var(--card);color:#475569}
.sd-badge.crit{background:var(--dang-bg);color:#b91c1c}
.sd-undo{display:flex;justify-content:space-between;align-items:center;gap:10px;padding:6px 0;border-bottom:1px solid var(--line);font-size:12.5px}.sd-undo:last-child{border-bottom:none}
.sd-aiout{padding:0 20px 16px}
.sd-empty{padding:26px;text-align:center;color:var(--muted)}
.sd-scan{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));background:var(--card);border-bottom:1px solid var(--line)}
.sd-fact{padding:11px 16px;border-top:1px solid var(--line);border-right:1px solid var(--line)}
.sd-fact.wide{grid-column:1/-1;border-right:0}
.sd-fact .k{display:block;font-size:10.5px;text-transform:uppercase;letter-spacing:.03em;color:var(--muted);margin-bottom:3px}
.sd-fact b{font-size:13.5px}
.sd-prog{padding:14px 16px;background:var(--card);border-radius:11px;margin-top:6px}
.sd-progtop{display:flex;justify-content:space-between;align-items:center;font-size:13px;margin-bottom:8px}
.sd-progpct{font-weight:800;color:var(--brand)}
.sd-progbar{height:8px;border-radius:5px;background:var(--card);overflow:hidden;margin-bottom:12px}
.sd-progbar span{display:block;height:100%;width:0;background:var(--brand);border-radius:5px;transition:width .4s ease}
.sd-steps{display:flex;flex-direction:column;gap:6px}
.sd-step{display:flex;align-items:flex-start;gap:9px;font-size:12.5px;color:var(--ink)}
.sd-step .sd-stepic{flex-shrink:0;width:18px;text-align:center}
.sd-step.ok .sd-stepic{color:var(--good)}.sd-step.bad .sd-stepic{color:var(--dang)}.sd-step.run .sd-stepic{color:var(--brand)}
.sd-verify{margin-top:12px;padding:9px 12px;border-radius:9px;font-weight:700;font-size:13px}
.sd-verify.ok{background:var(--good-bg);color:var(--good)}.sd-verify.bad{background:var(--warn-bg);color:#92702a}
</style>
<script>
(function(){
  var form=document.getElementById('sdForm'),inp=document.getElementById('sdTarget'),out=document.getElementById('sdOut');
  function esc(s){return (s==null?'':String(s)).replace(/[&<>"]/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
  function fmtB(b){b=+b||0;return b>=1048576?(b/1048576).toFixed(1)+' MB':(b>=1024?Math.round(b/1024)+' KB':b+' B');}
  function httpCls(c){c=+c;return !c?'na':(c>=500?'bad':(c>=400?'warn':'ok'));}
  function post(act,extra){var fd=new URLSearchParams();fd.set('sd_action',act);fd.set('smpro_csrf',SD_CSRF);Object.keys(extra||{}).forEach(function(k){fd.set(k,extra[k]);});
    return fetch('index.cgi?page=site-doctor',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'}).then(function(r){return r.json();});}
  // professional progress panel: animates planned steps, then fills real results from the response
  function progress(title,plan){
    var ao=document.getElementById('sdAiOut');
    ao.innerHTML='<div class="sd-prog"><div class="sd-progtop"><b>'+title+'</b><span class="sd-progpct" id="sdPct">0%</span></div>'
      +'<div class="sd-progbar"><span id="sdFill"></span></div><div class="sd-steps" id="sdSteps">'
      +plan.map(function(s,i){return '<div class="sd-step" id="sdStp'+i+'"><span class="sd-stepic">○</span><span>'+esc(s)+'</span></div>';}).join('')+'</div></div>';
    ao.scrollIntoView({behavior:'smooth',block:'nearest'});
    var i=0,fill=document.getElementById('sdFill'),pct=document.getElementById('sdPct');
    var tm=setInterval(function(){ if(i<plan.length){var st=document.getElementById('sdStp'+i);if(st){st.className='sd-step run';st.querySelector('.sd-stepic').textContent='⏳';} i++; var p=Math.min(90,Math.round(i/plan.length*90)); fill.style.width=p+'%'; pct.textContent=p+'%'; } else clearInterval(tm); },550);
    return {done:function(steps,okfix,hb,ha,extra){ clearInterval(tm); fill.style.width='100%'; pct.textContent='100%';
      var box=document.getElementById('sdSteps');
      box.innerHTML=(steps&&steps.length?steps:plan).map(function(s){var ok=(''+s).indexOf('✓')===0,bad=(''+s).indexOf('✗')===0;
        return '<div class="sd-step '+(ok?'ok':(bad?'bad':'ok'))+'"><span class="sd-stepic">'+(bad?'✗':'✓')+'</span><span>'+esc((''+s).replace(/^[✓✗]\s*/,''))+'</span></div>';}).join('');
      var p=document.querySelector('.sd-prog');
      if(typeof ha!=='undefined')p.insertAdjacentHTML('beforeend','<div class="sd-verify '+(okfix?'ok':'bad')+'">'+(okfix?'✅ Verified by curl — site is UP':'⚠ Verified by curl — still failing')+' (HTTP '+esc(hb)+' → '+esc(ha)+')</div>');
      if(extra)p.insertAdjacentHTML('beforeend',extra);
    }};
  }
  function render(j,t){
    var h='<div class="sd-card"><div class="sd-hero"><div class="sd-http '+httpCls(j.http.code)+'">'+(j.http.code||'—')+'<small>HTTP</small></div>'
      +'<div class="sd-hmeta"><div class="sd-dom">'+esc(j.domain||j.user)+'</div><div class="sd-facts">'
      +'<span class="chip">account '+esc(j.user)+'</span>'+(j.phpver?'<span class="chip">PHP '+esc(j.phpver)+'</span>':'')
      +(j.detect&&j.detect.platform?'<span class="chip">'+esc(j.detect.platform)+(j.detect.multisite?' multisite':'')+'</span>':'')
      +(j.detect&&j.detect.multilingual?'<span class="chip">🌐 '+esc(j.detect.multilingual)+'</span>':'')
      +(j.detect&&j.detect.installs>1?'<span class="chip">'+j.detect.installs+' installs</span>':'')
      +'<span class="chip">'+esc(j.docroot||'')+'</span></div></div></div>';
    // ---- Scan summary (always visible) ----
    var dt=j.detect||{};
    var logsrc=[]; if(j.logtail&&j.logtail.length)logsrc.push('site error_log'); if(j.serverlogs&&j.serverlogs.length)logsrc.push(j.serverlogs.length+' server-log lines');
    var ml=dt.multilingual?dt.multilingual:'none detected';
    window.__sdFixes=j.fixes||[];
    var wpv=j.wp||{},isWP=(dt.platform==='WordPress'),domTip=(dt.sites&&dt.sites.length)?dt.sites.join('\n'):'';
    h+='<div class="sd-scan">'
      +'<div class="sd-fact"><span class="k">Platform</span><b>'+esc(dt.platform||'unknown')+(dt.version?' '+esc(dt.version):'')+(dt.multisite?' · multisite':'')+(dt.debug?' · <span style="color:#d97706">DEBUG on</span>':'')+'</b></div>'
      +'<div class="sd-fact" title="'+esc(domTip)+'"><span class="k">Account topology</span><b>'+(isWP?(dt.installs||0)+' WP install(s) · ':'')+((dt.sites&&dt.sites.length)||1)+' domain(s)</b><div style="font-size:11px;color:var(--muted)">hover for list</div></div>'
      +'<div class="sd-fact"><span class="k">PHP / Database</span><b>'+esc(j.phpver||'?')+(wpv.db&&wpv.db.version?' · MySQL '+esc((''+wpv.db.version).split("-")[0]):'')+'</b></div>';
    if(isWP){
      h+='<div class="sd-fact"><span class="k">Active theme</span><b>'+esc(wpv.theme||'—')+'</b></div>'
        +'<div class="sd-fact"><span class="k">Plugins</span><b>'+(dt.plugins||0)+' installed</b></div>'
        +'<div class="sd-fact"><span class="k">Multilingual</span><b>'+esc(ml)+'</b></div>';
    } else if(dt.env){
      var ev=dt.env,evp=function(k,lbl){return (k in ev)?'<div class="sd-fact"><span class="k">'+lbl+'</span><b'+((''+ev[k]).indexOf('MISSING')>=0?' style="color:var(--dang)"':'')+'>'+esc(ev[k])+'</b></div>':'';};
      h+=evp('APP_ENV','App env')+evp('APP_DEBUG','Debug')+evp('DB_CONNECTION','DB driver')+evp('APP_KEY','App key')+evp('vendor','vendor/')+evp('(.env)','.env');
    }
    h+='<div class="sd-fact"><span class="k">Logs read</span><b>'+(logsrc.length?esc(logsrc.join(' · ')):'—')+'</b></div>';
    // STEP 0 - domain / DNS validity (shown first: is the domain even pointed at this server?)
    var dns=j.dns||null;
    if(dns){var dc=(dns.state==='ok')?'var(--good)':(dns.state==='proxied'?'#d97706':'var(--dang)');
      var dlabel=(dns.state==='ok'?'✓ points here':(dns.state==='proxied'?'via Cloudflare/CDN':(dns.state==='nxdomain'?'✗ does not resolve':'✗ points elsewhere')));
      h+='<div class="sd-fact wide" title="'+esc(dns.note||'')+'"><span class="k">Domain &amp; DNS (step 1)</span><b style="color:'+dc+'">'+esc((dns.ips&&dns.ips.length?dns.ips.join(', '):'no A record'))+' — '+esc(dlabel)+'</b><div style="font-size:11px;color:var(--muted)">'+esc(dns.note||'')+'</div></div>';}
    // HTTP + redirect chain
    var ht=j.http||{};
    if(ht.first){var rtxt='HTTP '+ht.first; if(ht.hops>0)rtxt+=' → '+(ht.loop?'redirect LOOP ('+ht.hops+'+ hops)':(ht.final+' after '+ht.hops+' redirect(s)'));
      h+='<div class="sd-fact wide"><span class="k">HTTP / redirects</span><b style="color:'+(ht.loop?'var(--dang)':(ht.final>=200&&ht.final<400?'var(--good)':'var(--dang)'))+'">'+esc(rtxt)+'</b>'+(ht.final_url&&ht.final_url!==ht.url?'<div style="font-size:11px;color:var(--muted)">ends at: '+esc(ht.final_url)+'</div>':'')+'</div>';}
    h+=(dt.sites&&dt.sites.length?'<div class="sd-fact wide"><span class="k">Related domains ('+dt.sites.length+')</span><b style="font-weight:400;font-size:12.5px">'+dt.sites.map(esc).join(' · ')+'</b></div>':'')
      +(j.selfhealers&&Object.keys(j.selfhealers).length?'<div class="sd-fact wide"><span class="k">⚠ Self-healer detected</span><b style="color:var(--dang)">'+Object.keys(j.selfhealers).map(function(p){return esc(p.split("/").pop());}).join(', ')+' — reverts fixes; disabled first</b></div>':'')
      +'</div>';
    // Maintenance: platform-aware "Clear application cache" - shown for cacheable platforms even when the site is UP.
    if(dt.platform&&['WordPress','Laravel','Magento','Drupal','Joomla'].indexOf(dt.platform)>=0){
      h+='<div class="sd-fixrow" style="margin:8px 2px 0"><button type="button" class="sd-fixbtn" style="background:#0891b2" data-clearcache data-target="'+esc(t)+'" data-plat="'+esc(dt.platform)+'">&#129529; Clear '+esc(dt.platform)+' cache</button></div>';
    }
    var lc=j.live_cause||null, fixes=j.fixes||[], hasFix=fixes.length>0;
    var stale=(j.fatals&&j.fatals[0]&&!j.fatals[0].target_exists&&j.fatals[0].fix_target)?j.fatals[0]:null;
    var autobtn='<button type="button" class="sd-fixbtn go" data-fixit>&#128295; Fix it</button> <button type="button" class="sd-fixbtn ai" data-aifix>&#129302; AI Fix</button>';
    function planSteps(pre,post){var li=(pre||[]).concat(fixes.map(function(f){return esc(f.label);})).concat(post||[]);return '<ol class="sd-plan">'+li.map(function(s){return '<li>'+s+'</li>';}).join('')+'</ol>';}
    if(j.status==='dns'){
      h+='<div class="sd-card2 bad"><div class="c2h"><span class="c2ic">&#127760;</span><div class="c2t"><b>Domain is not pointed at this server</b><span class="c2sub">'+esc((dns&&dns.ips&&dns.ips.length?dns.ips.join(', '):'no DNS record')+' (server '+((dns&&dns.server_ip)||'?')+')')+'</span></div></div>'
        +'<div class="c2body"><ol class="sd-plan"><li>Set the <b>A record</b> for <code>'+esc(dns?dns.domain:'')+'</code> → <code>'+esc((dns&&dns.server_ip)||'this server')+'</code></li>'
        +'<li>Wait for DNS to propagate</li><li><b>Re-scan</b></li></ol></div></div>';
    } else if(j.status==='redirect_loop'){
      h+='<div class="sd-card2 bad"><div class="c2h"><span class="c2ic">&#128257;</span><div class="c2t"><b>Redirect loop (HTTP '+(ht.first||301)+')</b><span class="c2sub">Too many redirects — the site bounces between http/https.</span></div></div>'
        +'<div class="c2body">'+(hasFix
          ? '<div class="c2plan-t">Fix it (reversible, stops at first that works):</div>'+planSteps(['Unlock locked files'],['Verify'])
          : '<div class="c2note">Use <b>AI Fix</b> — it inspects Site URL, .htaccess &amp; SSL plugin.</div>')
        +'<div class="sd-fixrow">'+autobtn+'</div></div></div>';
    } else if(j.status==='up'&&!hasFix){
      h+='<div class="sd-cause good"><span class="ci">&#10003;</span><div class="ct"><b>Site is UP (HTTP '+j.http.code+')</b>No active error with a fixable cause.'
        +(stale?' A previously-broken '+esc(stale.component||'component')+' was already disabled.':'')+'</div></div>';
    } else if(hasFix){
      var f0=fixes[0];
      h+='<div class="sd-cause '+(j.status==='up'?'good':'bad')+'"><span class="ci">'+(j.status==='up'?'&#9888;':'&#9888;')+'</span><div class="ct">'
        +'<b>'+(j.status==='up'?'Issue found (site still responding)':'Likely cause found')+'</b>'
        +esc((lc&&lc.kind)||(f0.why)||'')+(lc&&lc.component?' <span class="sd-badge crit">'+esc(lc.component)+'</span>':'')
        +'<div style="margin-top:5px;color:var(--muted)">Recommended fix: <b>'+esc(f0.label)+'</b> (reversible)</div>'
        +'<div class="sd-fixrow">'+autobtn+'</div></div></div>';
    } else {
      var tf=(j.fatals&&j.fatals[0])||null;
      h+='<div class="sd-cause bad"><span class="ci">&#9888;</span><div class="ct"><b>Site is failing'+(j.http.code?' (HTTP '+j.http.code+')':'')+'</b>'
        +(tf?('Latest error: '+esc((tf.msg||'').slice(0,200))+(tf.kind?' <span style="color:var(--muted)">('+esc(tf.kind)+')</span>':'')):(stale?'A previously-broken '+esc(stale.component||'component')+' was already disabled, but it is still failing — the cause is elsewhere.':'No PHP fatal in the logs — likely a config/DB/server issue (see Recent log lines below).'))
        +'<div style="margin-top:6px;color:var(--muted)">Click below — it applies a fix if possible, otherwise gives a precise AI diagnosis from these errors.</div><div class="sd-fixrow">'+autobtn+'</div></div></div>';
    }
    if(j.components&&j.components.length){h+='<div class="sd-sec"><h4>&#129513; Theme &amp; plugin health</h4><div class="sd-scroll"><table class="sd-tbl"><thead><tr><th>Type</th><th>Name</th><th>Severity</th><th>Errors</th><th></th></tr></thead><tbody>';
      j.components.forEach(function(c){var active=(j.wp&&j.wp.theme&&c.type==="theme"&&c.name===j.wp.theme);
        h+='<tr><td>'+esc(c.type)+'</td><td><b>'+esc(c.name)+'</b>'+(active?' <span class="sd-badge" style="background:var(--brand-bg);color:var(--brand)">active</span>':'')+'</td>'
          +'<td><span class="sd-badge'+(c.sev==="critical"?" crit":"")+'"'+(c.sev==="warning"?' style="background:var(--warn-bg);color:#92702a"':'')+'>'+esc(c.sev)+'</span></td><td>'+c.count+'</td>'
          +'<td>'+(c.exists&&c.sev==="critical"?'<button type="button" class="sd-ghost" data-fix data-act="'+(c.type==="theme"?"disable_theme":"disable_plugin")+'" data-path="'+esc(c.path)+'">Disable</button>':'')+'</td></tr>';});
      h+='</tbody></table></div><div style="font-size:11px;color:var(--muted);margin-top:6px">Critical = PHP fatal (breaks the site) · Warning/Notice = noisy not fatal. Disable offered for critical only.</div></div>';}
    if(j.fatals&&j.fatals.length){h+='<div class="sd-sec collapsed"><h4>&#128308; PHP fatal / parse errors</h4><div class="sd-scroll"><table class="sd-tbl"><thead><tr><th>Time</th><th>Error</th><th>File</th></tr></thead><tbody>';
      j.fatals.forEach(function(f){var res=f.fix_target&&!f.target_exists;h+='<tr'+(res?' style="opacity:.6"':'')+'><td>'+esc(f.ts?new Date(f.ts*1000).toLocaleString():'')+'</td><td>'+(res?'<span class="sd-badge" style="background:var(--good-bg);color:var(--good)">resolved</span> ':'')+esc((f.msg||'').slice(0,240))+'</td><td class="sd-mono">'+esc(f.file||'')+'</td></tr>';});h+='</tbody></table></div></div>';}
    if(j.recent&&j.recent.length){h+='<div class="sd-sec collapsed"><h4>&#128221; Recently changed (48h)</h4><div class="sd-scroll"><table class="sd-tbl"><thead><tr><th>Modified</th><th>File</th></tr></thead><tbody>';
      j.recent.forEach(function(c){h+='<tr><td>'+esc(c.time)+'</td><td class="sd-mono">'+esc(c.path)+'</td></tr>';});h+='</tbody></table></div></div>';}
    if(j.wp){var w=j.wp;var dbok=w.db&&w.db.connected;h+='<div class="sd-sec collapsed"><h4>&#127760; WordPress / Database</h4><div class="sd-code">'
      +'DB: '+(dbok?'<span style="color:var(--good)">connected</span>':'<span style="color:var(--dang)">NOT CONNECTED'+(w.db&&w.db.error?' — '+esc(w.db.error):'')+'</span>')+'<br>'
      +'siteurl: '+esc(w.siteurl||'?')+'<br>home: '+esc(w.home||'?')+'<br>expected: '+esc(w.expected||'?')
      +(w.url_mismatch?'<br><span style="color:var(--dang)">&#9888; URL points to a path that does not exist on disk — regenerates the wrong .htaccess</span>':'')
      +'</div></div>';}
    if(j.hardened&&Object.keys(j.hardened).length){h+='<div class="sd-sec collapsed"><h4>&#128274; Hardened / locked files <span style="color:var(--muted);font-weight:400;font-size:11px">(block WordPress self-repair — un-hardened first by Fix)</span></h4><div class="sd-code">'+Object.keys(j.hardened).map(function(p){return esc(p)+' &mdash; '+esc(j.hardened[p]);}).join('<br>')+'</div></div>';}
    if(j.logtail&&j.logtail.length){h+='<div class="sd-sec collapsed"><h4>&#128203; Site error_log</h4><div class="sd-code">'+j.logtail.map(esc).join('<br>')+'</div></div>';}
    if(j.serverlogs&&j.serverlogs.length){h+='<div class="sd-sec collapsed"><h4>&#128421; Server logs (apache / litespeed / suexec / domlog / modsec)</h4><div class="sd-code">'+j.serverlogs.map(esc).join('<br>')+'</div></div>';}
    if(j.htaccess){h+='<div class="sd-sec collapsed"><h4>&#9881; .htaccess <span style="color:var(--muted);font-weight:400;font-size:11px">edited '+esc(j.htaccess.mtime)+'</span></h4>';
      if(j.htaccess.issues&&j.htaccess.issues.length)j.htaccess.issues.forEach(function(is){h+='<div style="background:var(--warn-bg);color:#92702a;border-radius:8px;padding:8px 11px;margin-bottom:8px;font-size:12.5px">&#9888; '+esc(is)+'</div>';});
      h+='<div class="sd-code">'+esc(j.htaccess.head).replace(/\n/g,'<br>')+'</div></div>';}
    if(j.disk){var d=j.disk,gb=function(mb){return mb>=1024?(mb/1024).toFixed(1)+' GB':mb+' MB';};
      var pc=Math.min(100,d.pct||0),pcls=pc>=90?'bad':(pc>=75?'warn':'ok');
      h+='<div class="sd-sec collapsed"><h4>&#128190; Disk usage</h4><div class="sd-disk">'
        +'<div class="sd-bar"><span class="sd-fill '+pcls+'" style="width:'+pc+'%"></span></div>'
        +'<div class="sd-diskmeta"><b>'+gb(d.used_mb)+'</b>'+(d.limit_mb?' of '+gb(d.limit_mb)+' ('+pc+'%)':' used')+' &middot; '+(d.inodes||0).toLocaleString()+' files</div>'
        +'</div></div>';}
    if(j.undo&&j.undo.length){h+='<div class="sd-sec collapsed"><h4>&#8635; Applied fixes (undo)</h4>';
      j.undo.forEach(function(u){h+='<div class="sd-undo"><span class="sd-mono">'+esc(u.action)+' · '+esc((u.from||"").split("/").pop())+(u.hardened?' <span class="sd-badge">was hardened</span>':'')+'</span><button type="button" class="sd-ghost" data-undo="'+esc(u.id)+'">Undo</button></div>';});h+='</div>';}
    h+='<div class="sd-foot"><button type="button" class="sd-ghost" data-ai>&#129302; AI verdict</button><button type="button" class="sd-ghost" data-rerun>&#8635; Re-scan</button></div><div class="sd-aiout" id="sdAiOut"></div></div>';
    out.innerHTML=h;
  }
  function run(t){ out.innerHTML='<div class="sd-card"><div class="sd-empty">&#128270; Diagnosing '+esc(t)+'… reading logs &amp; recent changes</div></div>';
    fetch('index.cgi?page=site-doctor&sd_investigate=1&target='+encodeURIComponent(t),{cache:'no-store'}).then(function(r){return r.json();}).then(function(j){
      if(!j||!j.ok){out.innerHTML='<div class="sd-card"><div class="sd-empty"><b style="color:var(--dang)">'+esc((j&&j.msg)||'Investigation failed')+'</b></div></div>';return;}
      render(j,t);
    }).catch(function(){out.innerHTML='<div class="sd-card"><div class="sd-empty"><b style="color:var(--dang)">Request failed.</b></div></div>';});}
  // ---- speed diagnosis ----
  var SEGCOL={dns:'#94a3b8',connect:'#38bdf8',tls:'#6366f1',think:'#f59e0b',download:'#10b981'};
  function tbar(tm){
    var segs=[['dns','DNS',tm.dns],['connect','Connect',tm.connect],['tls','TLS',tm.tls],['think','Server',tm.think],['download','Download',tm.download]];
    var tot=segs.reduce(function(a,s){return a+Math.max(0,s[2]||0);},0)||1;
    var bar=segs.map(function(s){var w=Math.max(0,s[2]||0)/tot*100;return w>0?'<div class="sd-tseg '+s[0]+'" style="width:'+w.toFixed(1)+'%" title="'+s[1]+': '+(s[2]||0)+' ms"></div>':'';}).join('');
    var leg=segs.map(function(s){return '<span><i style="background:'+SEGCOL[s[0]]+'"></i>'+s[1]+' '+(s[2]||0)+'ms</span>';}).join('');
    return '<div class="sd-tbar">'+bar+'</div><div class="sd-tlegend">'+leg+'</div>';
  }
  function renderSpeed(j){
    if(!j||!j.ok){out.innerHTML='<div class="sd-card"><div class="sd-empty"><b style="color:var(--dang)">'+esc((j&&j.msg)||'Speed check failed')+'</b></div></div>';return;}
    var tm=j.timing||{},vb=j.verdict||'okay',vlabel={fast:'Fast',okay:'Okay',slow:'Slow',very_slow:'Very slow'}[vb]||vb;
    var h='<div class="sd-card"><div class="sd-spdhero">'
      +'<div class="sd-spdnum"><div class="n">'+(tm.ttfb||0)+'<small> ms</small></div><div class="l">Time to first byte</div></div>'
      +'<div class="sd-tbwrap"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:7px;gap:8px"><b style="font-size:15px;word-break:break-all">'+esc(j.domain||j.user)+'</b><span class="sd-vbadge '+esc(vb)+'">'+vlabel+'</span></div>'+tbar(tm)+'</div></div>';
    var chips=['<span class="sd-tchip">total <b>'+(tm.total||0)+' ms</b></span>','<span class="sd-tchip">page <b>'+(tm.size_kb||0)+' KB</b></span>','<span class="sd-tchip">HTTP/<b>'+esc(tm.http||'?')+'</b></span>','<span class="sd-tchip'+(tm.compressed?'':' warn')+'">'+(tm.compressed?'compressed ✓':'not compressed')+'</span>'];
    if(tm.cache)chips.push('<span class="sd-tchip">cache: <b>'+esc(tm.cache)+'</b></span>');
    h+='<div class="sd-tchips">'+chips.join('')+'</div>';
    var think=tm.think||0, tt=tm.ttfb||0, cz=j.causes||[];
    var vmsg=(vb==='very_slow')?('The server takes '+think+' ms to build the page before sending a byte — very slow. The bottleneck is server-side (PHP / database / account limits) — see below.')
      :(vb==='slow')?('The server takes '+think+' ms of processing before the first byte — slow. See the server-side causes below.')
      :(vb==='okay')?('First byte in '+tt+' ms — acceptable, with room to improve.')
      :('First byte in '+tt+' ms, only '+think+' ms of it is server processing — the site responds fast.');
    h+='<div class="sd-cause '+((vb==='fast'||vb==='okay')?'good':'bad')+'"><span class="ci">'+(vb==='fast'?'&#9889;':(vb==='okay'?'&#128077;':'&#128034;'))+'</span><div class="ct"><b>'+vlabel+' response — '+tt+' ms to first byte</b>'+esc(vmsg)+'</div></div>';
    if(!cz.length){
      var tips=[]; if(!tm.compressed)tips.push('enable gzip/Brotli compression'); if(tm.http==='1.1')tips.push('enable HTTP/2');
      h+='<div class="sd-cz"><h4>&#128269; Causes</h4><div style="padding:6px 0 8px;font-size:13.5px;color:var(--ink)">&#9989; No server-side bottleneck crossed the alert thresholds — nothing is slowing this site down right now.'+(tips.length?' <span style="color:var(--muted)">Minor wins: '+tips.join(', ')+'.</span>':'')+'</div></div>';
    }else{
      h+='<div class="sd-cz"><h4>&#128269; Likely causes ('+cz.length+' — most impactful first)</h4>';
      cz.forEach(function(c){h+='<div class="sd-czrow"><span class="sd-czsev '+esc(c.sev)+'">'+esc(c.sev)+'</span><div class="sd-czmain"><b>'+esc(c.cause)+'</b><div class="sd-czev">'+esc(c.evidence)+'</div><div class="sd-czfix">'+esc(c.fix)+'</div>'+(c.action&&c.action.page?'<a class="sd-czact" href="index.cgi?page='+esc(c.action.page)+'">'+esc(c.action.label||'Open')+' &rarr;</a>':'')+'</div></div>';});
      h+='</div>';
    }
    h+='<div class="sd-foot"><button type="button" class="sd-ghost" data-respeed>&#8635; Re-measure</button><button type="button" class="sd-ghost" data-diag>&#128270; Full diagnose (failures)</button></div></div>';
    out.innerHTML=h;
  }
  function speed(t){
    var steps=['Measuring the live response time (TTFB breakdown)','Checking whole-server load &amp; memory','Checking this account’s CloudLinux (LVE) limits','Checking PHP / OPcache, caching &amp; database','Ranking the most likely causes'];
    out.innerHTML='<div class="sd-card"><div class="sd-prog" style="margin:0;border-radius:16px"><div class="sd-progtop"><b>&#9889; Diagnosing speed — '+esc(t)+'</b><span class="sd-progpct" id="sdSpP">0%</span></div><div class="sd-progbar"><span id="sdSpF"></span></div><div class="sd-steps">'+steps.map(function(s,i){return '<div class="sd-step" id="sdSpS'+i+'"><span class="sd-stepic">○</span><span>'+s+'</span></div>';}).join('')+'</div></div></div>';
    var i=0,f=document.getElementById('sdSpF'),p=document.getElementById('sdSpP');
    var iv=setInterval(function(){ if(i<steps.length){var st=document.getElementById('sdSpS'+i);if(st){st.className='sd-step run';st.querySelector('.sd-stepic').textContent='⏳';} i++; var pc=Math.min(92,Math.round(i/steps.length*92));if(f)f.style.width=pc+'%';if(p)p.textContent=pc+'%';} else clearInterval(iv); },450);
    fetch('index.cgi?page=site-doctor&sd_speed=1&target='+encodeURIComponent(t),{cache:'no-store'}).then(function(r){return r.json();}).then(function(j){clearInterval(iv);renderSpeed(j);}).catch(function(){clearInterval(iv);out.innerHTML='<div class="sd-card"><div class="sd-empty"><b style="color:var(--dang)">Request failed — try again.</b></div></div>';});
  }
  // ---- optimize layer ----
  var OICON={safe_oneclick:'⚡',needs_approval:'🛠️',advisory_only:'💡'};
  var OTAG={safe_oneclick:['safe','One-click'],needs_approval:['appr','Needs approval'],advisory_only:['adv','Recommendation']};
  window.__sdOScen=[]; window.__sdOTarget='';
  function fileRows(s,si){
    var canSel=(s.category==='assets'&&s.applicable), h='';
    h+='<table class="sd-ofiles"><thead><tr>'+(canSel?'<th>Optimize?</th>':'')+'<th>File</th><th class="sz">Size</th></tr></thead><tbody>';
    (s.files||[]).forEach(function(f,fi){
      var sel=canSel?('<td><div class="sd-ofsel"><button type="button" class="sd-fbtn on" data-appr data-si="'+si+'" data-fi="'+fi+'">✓ Yes</button><button type="button" class="sd-fbtn" data-rej data-si="'+si+'" data-fi="'+fi+'">Skip</button></div></td>'):'';
      h+='<tr id="ofr'+si+'_'+fi+'" data-rel="'+esc(f.rel)+'">'+sel+'<td class="sd-mono">'+esc(f.rel||f.name)+'</td><td class="sz" id="ofsz'+si+'_'+fi+'">'+esc(f.human||'')+'</td></tr>';
    });
    h+='</tbody></table>';
    return h;
  }
  function optCard(s,si){
    var tg=OTAG[s.safety]||['adv','—'], cls=tg[0], applic=s.applicable!==false;
    var body='<div class="sd-obody"><div class="sd-ometh">'+esc(s.method||'')+'</div>';
    if(s.skip_reason&&!applic)body+='<div class="sd-oskip">✓ '+esc(s.skip_reason)+'</div>';
    if(s.files&&s.files.length)body+=fileRows(s,si);
    // action row
    var act='';
    var deep=(s.deep_link&&s.deep_link.page)?'<a class="sd-odeep" href="index.cgi?page='+esc(s.deep_link.page)+'">'+esc(s.deep_link.label||'Open')+' →</a>':'';
    if(s.category==='advisory'){
      if(s.server_apply)act='<button type="button" class="sd-obtn appr" data-oserver data-rec="'+esc(s.server_apply)+'" data-si="'+si+'">Apply (server-wide)</button>'+deep+'<span class="sd-onote">One click via the reversible Server Tune-up engine · affects all sites on this server.</span>';
      else act=deep||'<span class="sd-onote">Recommendation — no automatic change.</span>';
    }
    else if(!applic){
      if(s.installable)act='<button type="button" class="sd-obtn appr" data-oinstall data-group="'+esc(s.install_group||'image')+'" data-si="'+si+'">&#128229; Install &amp; enable</button><span class="sd-onote">'+esc(s.skip_reason||'')+'</span>';
      else act='<span class="sd-onote">'+(s.tool_needed&&s.tool_present===false?'Requires <span class="sd-oinstall">'+esc(s.tool_needed)+'</span> on the server.':esc(s.skip_reason||'Not applicable.'))+'</span>';
    }
    else if(s.category==='htaccess'){ act='<button type="button" class="sd-obtn '+(s.safety==='safe_oneclick'?'safe':'appr')+'" data-oapply data-si="'+si+'">'+(s.safety==='safe_oneclick'?'⚡ Apply (reversible)':'Apply (reversible)')+'</button><span class="sd-onote">Backs up your .htaccess first · one-click Undo.</span>'; }
    else if(s.category==='assets'){ act='<button type="button" class="sd-obtn appr" data-oapplyfiles data-si="'+si+'">Apply to selected files</button><span class="sd-onote" id="osum'+si+'">Backup per file · runs as the account user · reversible.</span>'; }
    body+='<div class="sd-oact">'+act+'</div></div>';
    var coll=(s.category==='advisory'||!applic)?' collapsed':'';
    return '<div class="sd-ocard '+cls+coll+'" data-card="'+si+'"><div class="sd-ochd" data-otog><span class="ic">'+(OICON[s.safety]||'•')+'</span>'
      +'<div class="tt"><b>'+esc(s.title)+'</b><span class="d">'+esc(s.does||'')+'</span></div>'
      +'<span class="sd-otag '+cls+'">'+tg[1]+'</span>'+(s.impact==='high'?'<span class="sd-otag imp">High impact</span>':'')+'</div>'+body+'</div>';
  }
  function renderOptimize(j){
    if(!j||!j.ok){out.innerHTML='<div class="sd-card"><div class="sd-empty"><b style="color:var(--dang)">'+esc((j&&j.msg)||'Optimize scan failed')+'</b></div></div>';return;}
    window.__sdOScen=j.scenarios||[]; window.__sdOTarget=j.domain||j.user||'';
    var st=j.stack||{},tls=j.tools||{},ht=j.htaccess||{};
    var flav={apache:'Apache',litespeed:'LiteSpeed',cloudflare_front:'Cloudflare-fronted'}[st.flavor]||st.flavor;
    var h='<div class="sd-card"><div class="sd-hero"><div class="sd-http ok" style="background:#0891b2">🚀<small>OPTIMIZE</small></div>'
      +'<div class="sd-hmeta"><div class="sd-dom">'+esc(j.domain||j.user)+'</div><div class="sd-facts">'
      +'<span class="chip">account '+esc(j.user)+'</span>'+(j.phpver?'<span class="chip">PHP '+esc(j.phpver)+'</span>':'')
      +'<span class="chip">'+esc(st.platform||'?')+(st.version?' '+esc(st.version):'')+'</span>'
      +'<span class="chip">'+esc(flav||'?')+'</span>'+(st.cache_plugin?'<span class="chip">🧩 '+esc(st.cache_plugin)+'</span>':'')
      +'</div></div></div>';
    // stack / capability row
    h+='<div class="sd-ostack">'
      +'<span class="sd-ochip">Stack <b>'+esc(st.platform||'?')+(st.version?' '+esc(st.version):'')+'</b></span>'
      +'<span class="sd-ochip">Server <b>'+esc(flav||'?')+'</b></span>'
      +'<span class="sd-ochip">HTTP/<b>'+esc(st.http||'?')+'</b></span>'
      +'<span class="sd-ochip '+(st.compressed?'good':'warn')+'">'+(st.compressed?'gzip ✓':'no gzip')+'</span>'
      +'<span class="sd-ochip '+(ht.cache_present?'good':'warn')+'">'+(ht.cache_present?'browser cache ✓':'no browser cache')+'</span>'
      +(st.cache_plugin?'<span class="sd-ochip good">cache plugin: '+esc(st.cache_plugin)+'</span>':'')+'</div>';
    // metrics
    var scen=j.scenarios||[], nSafe=0,nAppr=0,nAdv=0,nOpt=0;
    scen.forEach(function(s){ if(s.safety==='advisory_only')nAdv++; else if(s.safety==='safe_oneclick'&&s.applicable)nSafe++; else if(s.safety==='needs_approval'&&s.applicable)nAppr++; if(s.files)nOpt+=s.files.filter(function(f){return f.status==='optimizable';}).length; });
    h+='<div class="sd-osum">'
      +'<div class="sd-ometric"><div class="n">'+(j.asset_count||0)+'</div><div class="l">Files scanned</div></div>'
      +'<div class="sd-ometric"><div class="n" style="color:var(--good)">'+nSafe+'</div><div class="l">One-click wins</div></div>'
      +'<div class="sd-ometric"><div class="n" style="color:#0891b2">'+nAppr+'</div><div class="l">Need approval</div></div>'
      +'<div class="sd-ometric"><div class="n" style="color:#64748b">'+nAdv+'</div><div class="l">Recommendations</div></div></div>';
    // groups
    function grp(title,filt){var items=scen.map(function(s,i){return [s,i];}).filter(function(x){return filt(x[0]);});
      if(!items.length)return '';var g='<div class="sd-ogrp"><h4>'+title+' <span style="color:var(--muted);font-weight:600">('+items.length+')</span></h4>';
      items.forEach(function(x){g+=optCard(x[0],x[1]);});return g+'</div>';}
    h+=grp('⚡ Quick wins — one click, reversible',function(s){return s.safety==='safe_oneclick'&&s.applicable;});
    h+=grp('🛠️ Needs your approval — choose files',function(s){return s.safety==='needs_approval'&&s.applicable;});
    h+=grp('💡 Recommendations',function(s){return s.safety==='advisory_only';});
    h+=grp('ℹ️ Already optimal / needs a server tool',function(s){return s.safety!=='advisory_only'&&s.applicable===false;});
    h+='<div class="sd-foot"><button type="button" class="sd-ghost" data-reopt>&#8635; Re-scan</button><button type="button" class="sd-ghost" data-speed2>&#9889; Diagnose speed</button><button type="button" class="sd-ghost" data-diag>&#128270; Full diagnose</button></div></div>';
    out.innerHTML=h;
  }
  function optimize(t){
    var steps=['Detecting the stack &amp; server flavor','Probing available optimization tools','Scanning files &amp; sizes (which need optimizing)','Checking browser-cache &amp; compression','Building the full optimization catalog'];
    out.innerHTML='<div class="sd-card"><div class="sd-prog" style="margin:0;border-radius:16px"><div class="sd-progtop"><b>&#128640; Analyzing optimizations — '+esc(t)+'</b><span class="sd-progpct" id="sdOpP">0%</span></div><div class="sd-progbar"><span id="sdOpF"></span></div><div class="sd-steps">'+steps.map(function(s,i){return '<div class="sd-step" id="sdOpS'+i+'"><span class="sd-stepic">○</span><span>'+s+'</span></div>';}).join('')+'</div></div></div>';
    var i=0,f=document.getElementById('sdOpF'),p=document.getElementById('sdOpP');
    var iv=setInterval(function(){ if(i<steps.length){var s=document.getElementById('sdOpS'+i);if(s){s.className='sd-step run';s.querySelector('.sd-stepic').textContent='⏳';} i++; var pc=Math.min(92,Math.round(i/steps.length*92));if(f)f.style.width=pc+'%';if(p)p.textContent=pc+'%';} else clearInterval(iv); },500);
    fetch('index.cgi?page=site-doctor&sd_optimize=1&target='+encodeURIComponent(t),{cache:'no-store'}).then(function(r){return r.json();}).then(function(j){clearInterval(iv);renderOptimize(j);}).catch(function(){clearInterval(iv);out.innerHTML='<div class="sd-card"><div class="sd-empty"><b style="color:var(--dang)">Request failed — try again.</b></div></div>';});
  }
  // ---- Auto-optimize (safe, reversible): the SYSTEM does the fixing end-to-end, client-driven ----
  function getJSON(u){return fetch(u,{cache:'no-store'}).then(function(r){return r.json();});}
  function scanURL(t){return 'index.cgi?page=site-doctor&sd_optimize=1&target='+encodeURIComponent(t);}
  function speedURL(t){return 'index.cgi?page=site-doctor&sd_speed=1&target='+encodeURIComponent(t);}
  function seq(items,fn){ // run fn over items sequentially, collecting results
    var res=[],i=0; return new Promise(function(resolve){ (function nx(){ if(i>=items.length)return resolve(res);
      Promise.resolve(fn(items[i],i)).then(function(r){res.push(r);i++;nx();},function(){res.push(null);i++;nx();}); })(); });
  }
  function autoOptimize(t){
    if(!confirm('Auto-optimize '+t+'?\n\nThe system will (all reversible with one “Undo everything”):\n • install image tools if missing (CLI tools only)\n • enable browser caching + gzip in .htaccess\n • recompress large images (as the account user)\n • generate WebP copies + serve them\n\nServer-wide changes (OPcache, HTTP/2) are NOT included here — apply those from the Optimize list. Continue?'))return;
    var runId='r'+Date.now().toString(36);
    var STEPS=['Measuring baseline speed','Installing image tools (if needed)','Enabling browser cache + gzip','Recompressing large images','Generating + serving WebP','Re-measuring'];
    out.innerHTML='<div class="sd-card"><div class="sd-prog" style="margin:0;border-radius:16px"><div class="sd-progtop"><b>&#9889; Auto-optimizing — '+esc(t)+'</b><span class="sd-progpct" id="sdAP">0%</span></div><div class="sd-progbar"><span id="sdAF"></span></div><div class="sd-steps">'+STEPS.map(function(s,i){return '<div class="sd-step" id="sdAS'+i+'"><span class="sd-stepic">○</span><span>'+s+'</span></div>';}).join('')+'</div></div></div>';
    var cur=-1; function stepDone(i,label){for(var k=cur+1;k<=i;k++){var el=document.getElementById('sdAS'+k);if(el){el.className='sd-step ok';el.querySelector('.sd-stepic').textContent='✓';}}cur=i;var p=Math.round((i+1)/STEPS.length*100);var f=document.getElementById('sdAF'),pc=document.getElementById('sdAP');if(f)f.style.width=p+'%';if(pc)pc.textContent=p+'%';if(label){var e2=document.getElementById('sdAS'+Math.min(i+1,STEPS.length-1));if(e2&&i+1<STEPS.length){e2.className='sd-step run';e2.querySelector('.sd-stepic').textContent='⏳';}}}
    var agg={img:0,webp:0,minify:0,ht:[],saved:0,undo:[],skipped:0,capped:0},CAP=60;
    var baseline=null;
    stepDone(-1,true);document.getElementById('sdAS0').className='sd-step run';document.getElementById('sdAS0').querySelector('.sd-stepic').textContent='⏳';
    getJSON(speedURL(t)).then(function(sp){ baseline=(sp&&sp.ok)?sp:null; stepDone(0,true); return getJSON(scanURL(t)); })
    .then(function(scan){
      if(!scan||!scan.ok)throw 0;
      // install image tools if any image scenario needs them
      var needInstall=(scan.scenarios||[]).some(function(s){return s.installable;});
      if(needInstall)return post('optimize_install',{group:'image'}).then(function(){stepDone(1,true);return getJSON(scanURL(t));});
      stepDone(1,true); return scan;
    })
    .then(function(scan){
      if(!scan||!scan.ok)throw 0;
      window.__sdAutoFlavor=(scan.stack||{}).flavor;
      var S=scan.scenarios||[];
      function find(id){for(var i=0;i<S.length;i++)if(S[i].id===id)return S[i];return null;}
      // 1) htaccess safe blocks
      var htIds=['htaccess:cache','htaccess:gzip','htaccess:brotli'];
      var htJobs=htIds.map(find).filter(function(s){return s&&s.applicable&&s.safety==='safe_oneclick';});
      return seq(htJobs,function(s){return post('optimize',{target:t,id:s.id,run:runId}).then(function(r){if(r&&r.ok){agg.ht.push(s.title);if(r.undo_id)agg.undo.push({id:r.undo_id,label:s.title});}});})
      .then(function(){ stepDone(2,true);
        // 2) image recompress
        var imgSc=find('assets:image'); var imgs=(imgSc&&imgSc.applicable)?(imgSc.files||[]).slice(0,CAP):[];
        return seq(imgs,function(f){return post('optimize',{target:t,id:'assets:image:'+f.rel,run:runId}).then(function(r){if(r&&r.ok&&!r.noop){agg.img++;agg.saved+=(r.before||0)-(r.after||0);if(r.undo_id)agg.undo.push({id:r.undo_id,label:f.rel});}else if(r&&r.noop)agg.skipped++;});});
      })
      .then(function(){ stepDone(3,true);
        // 3) webp gen (re-scan not needed; use scan list)
        var webpSc=find('assets:webp'); var wf=(webpSc&&webpSc.applicable)?(webpSc.files||[]).slice(0,CAP):[];
        return seq(wf,function(f){return post('optimize',{target:t,id:'assets:webp:'+f.rel,run:runId}).then(function(r){if(r&&r.ok&&!r.noop){agg.webp++;if(r.undo_id)agg.undo.push({id:r.undo_id,label:f.rel+' (WebP)'});}});});
      })
      .then(function(){
        // 4) serve webp if we created any and not cloudflare-fronted
        var ws=find('htaccess:webp_serve');
        if(agg.webp>0&&ws&&ws.applicable&&window.__sdAutoFlavor!=='cloudflare_front')
          return post('optimize',{target:t,id:'htaccess:webp_serve',run:runId}).then(function(r){if(r&&r.ok){agg.ht.push('Serve WebP');if(r.undo_id)agg.undo.push({id:r.undo_id,label:'Serve WebP'});}});
      });
    })
    .then(function(){ stepDone(4,true); return getJSON(speedURL(t)); })
    .then(function(after){ stepDone(5,true); renderAutoReport(t,baseline,(after&&after.ok)?after:null,agg,runId); })
    .catch(function(){ out.innerHTML='<div class="sd-card"><div class="sd-empty"><b style="color:var(--dang)">Auto-optimize could not complete — try the Optimize list instead.</b></div></div>'; });
  }
  function renderAutoReport(t,base,after,agg,runId){
    var bt=base&&base.timing?base.timing.ttfb:null, at=after&&after.timing?after.timing.ttfb:null;
    var parts=[];
    if(agg.img)parts.push(agg.img+' image'+(agg.img>1?'s':'')+' recompressed');
    if(agg.webp)parts.push(agg.webp+' WebP generated');
    if(agg.ht.length)parts.push('enabled '+agg.ht.join(' + '));
    var did=parts.length?parts.join(', ')+'.':'Nothing needed changing — the site is already optimized.';
    var h='<div class="sd-card"><div class="sd-cause good"><span class="ci">&#9989;</span><div class="ct"><b>Auto-optimize complete</b>'+esc(did)+'</div></div>';
    h+='<div class="sd-osum">'
      +'<div class="sd-ometric"><div class="n" style="color:var(--good)">'+fmtB(agg.saved)+'</div><div class="l">Image weight saved</div></div>'
      +'<div class="sd-ometric"><div class="n">'+agg.img+'</div><div class="l">Images optimized</div></div>'
      +'<div class="sd-ometric"><div class="n">'+agg.webp+'</div><div class="l">WebP created</div></div>'
      +'<div class="sd-ometric"><div class="n">'+(bt!=null&&at!=null?(bt+'→'+at+' ms'):'—')+'</div><div class="l">TTFB before→after</div></div></div>';
    if(agg.skipped)h+='<div class="sd-ogrp"><div class="sd-onote">'+agg.skipped+' file(s) were already optimal and left unchanged.</div></div>';
    h+='<div class="sd-foot" style="gap:10px">'
      +(agg.undo.length?'<button type="button" class="sd-obtn appr" data-undorun="'+esc(runId)+'">&#8635; Undo everything from this run ('+agg.undo.length+')</button>':'')
      +'<button type="button" class="sd-ghost" data-reopt>&#128640; Open Optimize list</button><button type="button" class="sd-ghost" data-respeed>&#9889; Re-measure speed</button></div>';
    // per-item undo list
    if(agg.undo.length){h+='<div class="sd-sec collapsed"><h4>&#8635; Changes in this run ('+agg.undo.length+')</h4>';
      agg.undo.forEach(function(u){h+='<div class="sd-undo"><span class="sd-mono">'+esc(u.label)+'</span><button type="button" class="sd-fbtn" data-undo="'+esc(u.id)+'">Undo</button></div>';});h+='</div>';}
    h+='</div>';
    out.innerHTML=h;
  }
  // ---- Clear application cache (platform-aware): dry-run preview -> confirm card -> drop-to-user clear ----
  function ccConfirm(t,plat,p,prev){
    window.__ccPrev=prev;
    if(!p||!p.ok){out.innerHTML='<div class="sd-card"><div class="sd-empty"><b style="color:var(--dang)">'+esc((p&&p.msg)||'Cannot plan cache clear.')+'</b></div><div class="sd-fixrow"><button type="button" class="sd-fixbtn" style="background:var(--muted)" data-cccancel>Back</button></div></div>';return;}
    var tg=(p.targets||[]).map(function(x){return '<li><span class="sd-mono">'+esc(x.rel||x.path||'')+'</span> — '+esc(x.human||'')+'</li>';}).join('');
    var cli=[]; if(p.cli){for(var k in p.cli){if(p.cli[k])cli.push(k);}}
    var shared=p.shared_store&&p.shared_store.shared;
    var h='<div class="sd-card"><h3 style="margin:0 0 8px">Clear '+esc(p.platform||plat)+' cache · '+esc(p.user||'')+'</h3>'
      +'<div class="sd-facts" style="margin-bottom:8px">'+(cli.length?'<span class="chip">CLI: '+esc(cli.join(', '))+'</span>':'<span class="chip">filesystem only</span>')+(p.cagefs_applicable?'<span class="chip">CageFS available</span>':'')+'</div>'
      +(tg?('<div style="font-size:12.5px;margin-bottom:4px">On-disk cache to clear:</div><ul class="sd-plan" style="margin-top:0">'+tg+'</ul>'):'<div style="color:var(--muted);font-size:12.5px;margin-bottom:6px">No on-disk cache directory found — object/DB cache flushed via CLI only.</div>');
    if(shared)h+='<div style="background:var(--warn-bg);color:#92702a;border-radius:8px;padding:8px 11px;margin:6px 0;font-size:12.5px">&#9888; '+esc(p.note||'This site shares an object cache (Redis/Memcached) — the global flush is skipped to avoid wiping other sites and logging users out; only on-disk cache is cleared.')+'</div>';
    else h+='<div style="color:var(--muted);font-size:12px;margin:4px 0">Deletes only regenerable cache inside /home/'+esc(p.user||'user')+'/ (never source, config, uploads or the database) and runs as the site user. The app rebuilds its cache on the next request.</div>';
    if(p.stampede_note)h+='<div style="color:#92702a;font-size:12px;margin:4px 0">'+esc(p.stampede_note)+'</div>';
    if(p.cagefs_applicable)h+='<label style="display:block;font-size:12.5px;margin:8px 0"><input type="checkbox" id="ccRemount"> Also refresh this user’s CageFS mount after clearing (may briefly interrupt this site’s running processes)</label>';
    h+='<div class="sd-fixrow"><button type="button" class="sd-fixbtn go" data-ccgo data-target="'+esc(t)+'">&#129529; Clear cache</button> <button type="button" class="sd-fixbtn" style="background:var(--muted)" data-cccancel>Cancel</button></div></div>';
    out.innerHTML=h;
  }
  function ccResult(res){
    if(!res){out.innerHTML='<div class="sd-card"><div class="sd-empty"><b style="color:var(--dang)">No response.</b></div></div>';return;}
    var rows=(res.cleared||[]).map(function(c){return '<tr><td>'+esc(c.label||'')+'</td><td>'+esc(c.method||'')+'</td><td>'+esc(fmtB(c.freed_bytes||0))+'</td><td>'+esc(c.note||'')+'</td></tr>';}).join('');
    var cg=res.cagefs||{};
    var h='<div class="sd-card"><h3 style="margin:0 0 8px">'+(res.ok?'&#10003; ':'&#9888; ')+'Cleared '+esc(res.platform||'')+' cache'+(res.freed_total?' · freed '+esc(fmtB(res.freed_total)):'')+'</h3>';
    if(!res.ok&&res.msg)h+='<div style="color:var(--dang);font-size:12.5px;margin-bottom:6px">'+esc(res.msg)+'</div>';
    h+=rows?('<table class="sd-tbl"><thead><tr><th>What</th><th>Method</th><th>Freed</th><th>Note</th></tr></thead><tbody>'+rows+'</tbody></table>'):'<div style="color:var(--muted)">'+esc(res.msg||'Nothing to clear.')+'</div>';
    if(cg&&typeof cg.applicable!=='undefined')h+='<div style="font-size:12.5px;margin-top:8px;color:'+(cg.ok?'var(--good)':'var(--muted)')+'">CageFS: '+esc(cg.applicable?(cg.msg||(cg.ok?'remounted':'skipped')):'not applicable — skipped')+'</div>';
    h+='<div class="sd-fixrow" style="margin-top:10px"><button type="button" class="sd-fixbtn go" data-rerun>&#128260; Re-scan</button></div></div>';
    out.innerHTML=h;
  }
  form.addEventListener('submit',function(){var t=(inp.value||'').trim();if(t){history.replaceState(0,'','index.cgi?page=site-doctor&target='+encodeURIComponent(t));run(t);}});
  document.getElementById('sdSpeed').addEventListener('click',function(){var t=(inp.value||'').trim();if(t){history.replaceState(0,'','index.cgi?page=site-doctor&target='+encodeURIComponent(t));speed(t);}else inp.focus();});
  document.getElementById('sdOpt').addEventListener('click',function(){var t=(inp.value||'').trim();if(t){history.replaceState(0,'','index.cgi?page=site-doctor&target='+encodeURIComponent(t));optimize(t);}else inp.focus();});
  document.getElementById('sdAuto').addEventListener('click',function(){var t=(inp.value||'').trim();if(t){history.replaceState(0,'','index.cgi?page=site-doctor&target='+encodeURIComponent(t));autoOptimize(t);}else inp.focus();});
  out.addEventListener('click',function(e){
    var t=(inp.value||'').trim();
    var hd=e.target.closest('.sd-sec h4');   // collapse/expand info sections
    if(hd){var sec=hd.closest('.sd-sec');if(sec)sec.classList.toggle('collapsed');return;}
    var cc=e.target.closest('[data-clearcache]');
    if(cc){var ct=cc.getAttribute('data-target')||t, plat=cc.getAttribute('data-plat')||'', prev=out.innerHTML;
      cc.disabled=true;cc.textContent='Checking…';
      fetch('index.cgi?page=site-doctor&sd_clearcache_preview=1&target='+encodeURIComponent(ct),{cache:'no-store'}).then(function(r){return r.json();}).then(function(p){ccConfirm(ct,plat,p,prev);}).catch(function(){out.innerHTML='<div class="sd-card"><div class="sd-empty"><b style="color:var(--dang)">Could not load the cache plan.</b></div></div>';});return;}
    if(e.target.closest('[data-cccancel]')){if(window.__ccPrev!=null)out.innerHTML=window.__ccPrev;return;}
    var ccg=e.target.closest('[data-ccgo]');
    if(ccg){var gt=ccg.getAttribute('data-target')||t, rm=document.getElementById('ccRemount'), doRem=(rm&&rm.checked)?'1':'';
      ccg.disabled=true;ccg.innerHTML='&#9203; Clearing…';
      post('clearcache',{target:gt,remount_cagefs:doRem}).then(function(res){ccResult(res);}).catch(function(){out.innerHTML='<div class="sd-card"><div class="sd-empty"><b style="color:var(--dang)">Clear cache request failed.</b></div></div>';});return;}
    var fx=e.target.closest('[data-fix]');
    if(fx){if(!confirm('Apply this fix on '+t+'?\n\nThe broken folder is renamed (disabled) — fully reversible via Undo. Hardening (if any) is handled automatically.'))return;
      fx.disabled=true;var ot=fx.innerHTML;fx.innerHTML='&#9203; Fixing…';
      post('fix',{act:fx.getAttribute('data-act'),target:t,path:fx.getAttribute('data-path')}).then(function(k){alert((k&&k.ok)?('✅ '+k.msg):('⚠ '+((k&&k.msg)||'fix failed')));run(t);}).catch(function(){fx.disabled=false;fx.innerHTML=ot;alert('Request failed.');});return;}
    var ft=e.target.closest('[data-fixit]');
    if(ft){if(!confirm('Fix '+t+' with the known scenario fixes?\n\nApplies the deterministic fixes in order, then verifies with curl. All reversible. If still failing, use AI Fix.'))return;
      ft.disabled=true;var ot=ft.innerHTML;ft.innerHTML='&#9203; Fixing…';
      var plan=(window.__sdFixes||[]).map(function(f){return f.label;}); if(!plan.length)plan=['Apply scenario fixes']; plan.push('Verify with curl');
      var pg=progress('🔧 Applying scenario fixes',plan);
      post('fixit',{target:t}).then(function(k){
        ft.disabled=false;ft.innerHTML=ot;
        pg.done((k&&k.steps)||[], k&&k.ok, k&&k.http_before, k&&k.http_after, (k&&k.escalate)?'<div style="margin-top:10px"><button type="button" class="sd-fixbtn ai" data-aifix>&#129302; Hand over to AI Fix</button></div>':'');
        if(k&&k.ok)setTimeout(function(){run(t);},1800);
      }).catch(function(){ft.disabled=false;ft.innerHTML=ot;pg.done(['✗ Request failed'],false);});return;}
    var af=e.target.closest('[data-aifix]');
    if(af){if(!confirm('Hand over to AI Fix for '+t+'?\n\nThe AI reads ALL the evidence (logs inside+outside the site, DB, platform) plus what Fix-it already tried, decides a plan, and EXECUTES it itself (reversible).'))return;
      af.disabled=true;var ot=af.innerHTML;af.innerHTML='&#129302; Working…';
      var pg=progress('🤖 AI Fix',['Reading logs (inside + server), DB & platform','AI deciding the fix plan','Applying the plan (reversible)','Verifying with curl']);
      post('ai_fix',{target:t}).then(function(k){
        af.disabled=false;af.innerHTML=ot;
        if(k&&k.verdict){var ao=document.getElementById('sdAiOut'); // planner fell back to diagnosis
          if(ao)ao.innerHTML='<div style="background:var(--brand-bg);border-radius:11px;padding:13px 15px;white-space:pre-wrap;font-size:13px;margin-top:4px"><b class="sd-badge" style="background:var(--card)">&#129302; Diagnosis'+(k.provider?' ('+esc(k.provider)+')':'')+'</b><div style="margin-top:8px;color:var(--muted)">'+esc(k.msg||'')+'</div><div style="margin-top:8px">'+esc(k.verdict)+'</div></div>';
          return;}
        var extra=(k&&k.cause)?'<div style="margin-top:8px;color:var(--muted);font-size:12.5px">Cause: '+esc(k.cause)+(k.provider?' · '+esc(k.provider):'')+'</div>':'';
        pg.done((k&&k.steps)||[], k&&k.ok, k&&k.http_before, k&&k.http_after, extra);
        if(k&&k.ok)setTimeout(function(){run(t);},1800);
      }).catch(function(){af.disabled=false;af.innerHTML=ot;var ao=document.getElementById('sdAiOut');if(ao)ao.innerHTML='<div class="sd-badge crit">Request failed.</div>';});return;}
    var ub=e.target.closest('[data-undo]');
    if(ub){if(!confirm('Undo this fix (restore the original folder)?'))return;
      post('undo',{id:ub.getAttribute('data-undo')}).then(function(k){alert((k&&k.ok)?('✅ '+k.msg):('⚠ '+((k&&k.msg)||'undo failed')));run(t);}).catch(function(){alert('Request failed.');});return;}
    if(e.target.closest('[data-rerun]')){run(t);return;}
    if(e.target.closest('[data-respeed]')){speed(t);return;}
    if(e.target.closest('[data-reopt]')){optimize(t);return;}
    if(e.target.closest('[data-speed2]')){speed(t);return;}
    if(e.target.closest('[data-diag]')){run(t);return;}
    // ---- optimize: collapse/expand a scenario card ----
    var otg=e.target.closest('[data-otog]');
    if(otg){otg.closest('.sd-ocard').classList.toggle('collapsed');return;}
    // ---- optimize: per-file approve / reject ----
    var ap=e.target.closest('[data-appr]'), rj=e.target.closest('[data-rej]');
    if(ap||rj){var b=ap||rj,si=b.getAttribute('data-si'),fi=b.getAttribute('data-fi'),row=document.getElementById('ofr'+si+'_'+fi);
      var yes=row.querySelector('[data-appr]'),no=row.querySelector('[data-rej]');
      if(ap){yes.classList.add('on');no.classList.remove('rejon');row.classList.remove('rej');}
      else{no.classList.add('rejon');yes.classList.remove('on');row.classList.add('rej');}
      return;}
    // ---- optimize: apply an .htaccess scenario (one-click, reversible) ----
    var oa=e.target.closest('[data-oapply]');
    if(oa){var si=oa.getAttribute('data-si'),s=window.__sdOScen[si];
      if(!confirm('Apply "'+s.title+'" on '+t+'?\n\nYour .htaccess is backed up first — fully reversible via Undo.'))return;
      oa.disabled=true;var ot=oa.innerHTML;oa.innerHTML='⏳ Applying…';
      post('optimize',{target:t,id:s.id}).then(function(k){
        if(k&&k.ok){oa.outerHTML='<span class="sd-oskip">✓ '+esc(k.msg)+'</span>'+(k.undo_id?' <button type="button" class="sd-fbtn" data-undo="'+esc(k.undo_id)+'">Undo</button>':'');}
        else{oa.disabled=false;oa.innerHTML=ot;alert('⚠ '+((k&&k.msg)||'failed')+(k&&k.manual?'\n\nAdd this manually:\n\n'+k.manual:''));}
      }).catch(function(){oa.disabled=false;oa.innerHTML=ot;alert('Request failed.');});return;}
    // ---- optimize: apply approved asset files (sequential, per-file backup + result) ----
    var of=e.target.closest('[data-oapplyfiles]');
    if(of){var si=of.getAttribute('data-si'),s=window.__sdOScen[si];
      var rows=[].slice.call(document.querySelectorAll('#osum'+si+', .sd-ocard[data-card="'+si+'"] .sd-ofiles tbody tr'));
      var todo=[].slice.call(document.querySelectorAll('.sd-ocard[data-card="'+si+'"] .sd-ofiles tbody tr')).filter(function(r){return !r.classList.contains('rej')&&!r.classList.contains('done');});
      if(!todo.length){alert('No files selected.');return;}
      if(!confirm('Optimize '+todo.length+' file(s) for '+t+'?\n\nEach file is backed up first — reversible per file via Undo.'))return;
      of.disabled=true;var ot=of.innerHTML;var done=0,saved=0,sum=document.getElementById('osum'+si);
      function step(k){ if(k>=todo.length){of.innerHTML='✓ Done — '+done+' optimized';if(sum)sum.innerHTML='Optimized '+done+' file(s), saved '+fmtB(saved)+'. Undo any row below.';setTimeout(function(){optimize(t);},1500);return;}
        var row=todo[k],rel=row.getAttribute('data-rel');of.innerHTML='⏳ '+(k+1)+'/'+todo.length+'…';
        post('optimize',{target:t,id:s.id+':'+rel}).then(function(r){
          var szc=row.querySelector('.sz');
          if(r&&r.ok&&!r.noop){row.classList.add('done');done++;saved+=(r.before||0)-(r.after||0);if(szc)szc.innerHTML=fmtB(r.before)+' → '+fmtB(r.after)+(r.undo_id?' <button type="button" class="sd-fbtn" data-undo="'+esc(r.undo_id)+'">Undo</button>':'');}
          else if(szc)szc.innerHTML+=' <span style="color:var(--muted)">'+esc(r&&r.noop?'no gain':((r&&r.msg)||'skipped'))+'</span>';
          step(k+1);
        }).catch(function(){step(k+1);});
      }
      step(0);return;}
    // ---- optimize: install the missing image tools, then re-scan ----
    var oi=e.target.closest('[data-oinstall]');
    if(oi){var g=oi.getAttribute('data-group')||'image';
      if(!confirm('Install image optimization tools (jpegoptim, optipng, gifsicle, cwebp)?\n\nThis installs standalone command-line tools only — it does not touch any website, service or config, and starts nothing. It may take up to a minute.'))return;
      oi.disabled=true;var ot=oi.innerHTML;oi.innerHTML='⏳ Installing…';
      post('optimize_install',{group:g}).then(function(k){
        if(k&&k.ok){oi.outerHTML='<span class="sd-oskip">✓ '+esc(k.msg)+'</span>';setTimeout(function(){optimize(t);},900);}
        else{oi.disabled=false;oi.innerHTML=ot;alert((k&&k.busy?'⏳ ':'⚠ ')+((k&&k.msg)||'install failed'));if(k&&k.newly&&k.newly.length)setTimeout(function(){optimize(t);},900);}
      }).catch(function(){oi.disabled=false;oi.innerHTML=ot;alert('Request failed.');});return;}
    // ---- optimize: apply a SERVER-WIDE tuning rec (affects all sites) ----
    var os=e.target.closest('[data-oserver]');
    if(os){var rec=os.getAttribute('data-rec');
      if(!confirm('This changes the WHOLE SERVER and affects ALL websites hosted on it — not just '+t+'.\n\nIt is applied through the reversible Server Tune-up engine (you can restore it there). Continue?'))return;
      os.disabled=true;var ot=os.innerHTML;os.innerHTML='⏳ Applying…';
      post('optimize_server',{rec:rec}).then(function(k){
        if(k&&k.ok){os.outerHTML='<span class="sd-oskip">✓ '+esc((k.applied?('Applied: '+k.applied):k.msg)||'Applied')+(k.note?' — '+esc(k.note):'')+'</span>';}
        else{os.disabled=false;os.innerHTML=ot;alert('⚠ '+((k&&k.msg)||'failed')+(k&&k.manual?'\n\n(Apply it in Server Tune-up / WHM.)':''));}
      }).catch(function(){os.disabled=false;os.innerHTML=ot;alert('Request failed.');});return;}
    // ---- optimize: undo everything from one auto-optimize run ----
    var ur=e.target.closest('[data-undorun]');
    if(ur){if(!confirm('Undo EVERY change from this auto-optimize run (restore originals, remove generated WebP, revert .htaccess)?'))return;
      ur.disabled=true;ur.innerHTML='⏳ Undoing…';
      post('undo_run',{run:ur.getAttribute('data-undorun')}).then(function(k){alert((k&&k.ok?'✅ ':'⚠ ')+((k&&k.msg)||'undo failed'));optimize(t);}).catch(function(){ur.disabled=false;alert('Request failed.');});return;}
    var ai=e.target.closest('[data-ai]');
    if(ai){var ao=document.getElementById('sdAiOut');ai.disabled=true;var ot=ai.innerHTML;ai.innerHTML='&#129302; Thinking…';ao.innerHTML='<div style="color:var(--muted);padding-top:6px">reviewing evidence…</div>';
      post('ai',{target:t}).then(function(k){ai.disabled=false;ai.innerHTML=ot;
        if(!k||!k.ok){ao.innerHTML='<div class="sd-badge crit">'+esc((k&&k.error)||'AI unavailable')+'</div>';return;}
        ao.innerHTML='<div style="background:var(--brand-bg);border-radius:11px;padding:13px 15px;white-space:pre-wrap;font-size:13px"><b class="sd-badge" style="background:var(--card)">&#129302; AI verdict'+(k.provider?' ('+esc(k.provider)+')':'')+'</b><div style="margin-top:8px">'+esc(k.text||'')+'</div></div>';
      }).catch(function(){ai.disabled=false;ai.innerHTML=ot;ao.innerHTML='<div class="sd-badge crit">failed</div>';});return;}
  });
  if((inp.value||'').trim())run(inp.value.trim());
})();
</script>
<?php
smpro_layout_footer();
