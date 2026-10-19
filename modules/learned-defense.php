<?php
/**
 * modules/learned-defense.php — Learned Defense: lessons the server took from confirmed incidents, the hunt they
 * drive, processes a file scan cannot see, and the root-only store of what was moved. Engine: includes/learn.php.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }
require_once SMPRO_INCLUDES . '/learn.php';
smpro_require_root();

$reqMethod = (string)($_SERVER['REQUEST_METHOD'] ?? 'GET');
$act = (string)($_POST['lr_action'] ?? '');
$flash = ''; $flashOk = true;

if ($reqMethod === 'POST' && $act !== '') {
    smpro_require_valid_csrf('lr_act');
    @ignore_user_abort(true); @set_time_limit(600);
    $ok = true; $msg = '';
    switch ($act) {
        case 'hunt':      $r = smpro_lr_hunt(500); $msg = 'Hunted ' . $r['sites'] . ' of ' . $r['of'] . ' site(s) in ' . $r['took'] . ' s: ' . count($r['findings']) . ' finding(s).' . ($r['partial'] ? ' Time budget hit; the next tick continues.' : ''); break;
        case 'teach':     $r = smpro_lr_teach_folder((string)($_POST['folder'] ?? '')); $ok = $r['ok']; $msg = $r['msg']; if ($ok) smpro_lr_hunt(400); break;
        case 'quarantine': $r = smpro_lr_quarantine((string)($_POST['path'] ?? ''), 'operator'); $ok = $r['ok']; $msg = $r['msg']; break;
        case 'restore':   $r = smpro_lr_restore((string)($_POST['kept'] ?? '')); $ok = $r['ok']; $msg = $r['msg']; break;
        case 'notbad':    $sha = preg_replace('/[^a-f0-9]/', '', (string)($_POST['sha'] ?? '')); if ($sha !== '') { smpro_lr_mark_fp($sha); $msg = 'Remembered as not malicious: this exact file is never reported again, and the lesson that matched it lost trust.'; } else { $ok = false; $msg = 'No file hash given.'; } break;
        case 'lesson':    $L = smpro_lr_lessons(); $id = preg_replace('/[^a-f0-9]/', '', (string)($_POST['id'] ?? '')); $st = (string)($_POST['state'] ?? '');
                          if (isset($L[$id]) && in_array($st, ['on', 'off'], true)) { $L[$id]['state'] = $st; smpro_lr_save('lessons', $L); $msg = 'Lesson ' . ($st === 'on' ? 'switched on' : 'switched off') . '.'; } else { $ok = false; $msg = 'Unknown lesson.'; } break;
        case 'forget':    $L = smpro_lr_lessons(); $id = preg_replace('/[^a-f0-9]/', '', (string)($_POST['id'] ?? '')); if (isset($L[$id])) { unset($L[$id]); smpro_lr_save('lessons', $L); $msg = 'Lesson forgotten.'; } else { $ok = false; $msg = 'Unknown lesson.'; } break;
        case 'kill':      $r = smpro_lr_kill((int)($_POST['pid'] ?? 0)); $ok = $r['ok']; $msg = $r['msg']; break;
        case 'cfg':       $c = smpro_lr_cfg(); $c['auto'] = ($_POST['auto'] ?? '') === 'quarantine_exact' ? 'quarantine_exact' : 'report'; $c['recent_days'] = max(1, min(365, (int)($_POST['recent_days'] ?? 30))); $c['share'] = !empty($_POST['share']) ? 'on' : 'off'; smpro_lr_save('config', $c); $msg = 'Saved.'; break;
        case 'share':     $r = smpro_lr_share(); $ok = $r['ok']; $msg = $ok ? ('Exchanged: ' . (int)$r['sent'] . ' lesson(s) sent, ' . (int)$r['pool'] . ' in the shared pool from ' . (int)$r['servers'] . ' server(s), ' . (int)$r['new'] . ' new here.') : ('Not exchanged: ' . (string)$r['why']); break;
        default:          $ok = false; $msg = 'Unknown action.';
    }
    smpro_audit('learned_defense_' . preg_replace('/[^a-z_]/', '', $act), ['ok' => $ok, 'actor' => smpro_current_actor()]);
    $flash = $msg; $flashOk = $ok;
}

$cfg = smpro_lr_cfg(); $L = smpro_lr_lessons(); $F = smpro_lr_load('findings'); $P = smpro_lr_load('procs');
$Q = smpro_lr_quarantined(100);
$findings = (array)($F['findings'] ?? []); $procs = (array)($P['rows'] ?? []);
if (!$P || time() - (int)($P['at'] ?? 0) > 900) { $procs = smpro_lr_procs(); }   // the page always shows a fresh process check
$onN = count(array_filter($L, fn($l) => ($l['state'] ?? 'on') === 'on'));
$byUser = []; foreach ($findings as $f) $byUser[$f['user']] = ($byUser[$f['user']] ?? 0) + 1;
$csrf = smpro_csrf_generate('lr_act');
$typeLabel = ['hash' => 'exact file', 'relpath' => 'place in a site', 'dotdir' => 'hidden folder', 'behaviour' => 'behaviour', 'docblock' => 'file header'];
smpro_layout_header('Learned Defense');
?>
<h1 class="h">Learned Defense <?= smpro_beta_badge() ?></h1>
<p class="sub">Every file you confirm as malware (Delete or Clean in Imunify360 Reports, Quarantine here, or a folder you teach) becomes lessons: its exact file, the place it sat, the hidden folder it hid in, and what its code does. The server hunts every site for the same lessons and shows what it finds. It also shows processes a file scan cannot see. Nothing is named in code: every lesson is data with the incident it came from, and any lesson can be switched off or forgotten.</p>
<?php if ($flash !== ''): ?><div class="card" style="border-left:4px solid var(--<?= $flashOk ? 'good' : 'dang' ?>);padding:10px 14px;margin-bottom:12px"><?= smpro_h($flash) ?></div><?php endif; ?>

<div class="ld-kpis">
  <div class="cc-kpi"><div class="l">Lessons</div><div class="v"><?= $onN ?></div><div class="s"><?= count($L) - $onN ?> switched off</div></div>
  <div class="cc-kpi"><div class="l">Findings</div><div class="v" style="color:<?= $findings ? 'var(--dang)' : 'var(--good)' ?>"><?= count($findings) ?></div><div class="s"><?= $F ? 'hunted ' . (int)$F['sites'] . ' site(s) ' . smpro_h(date('Y-m-d H:i', (int)$F['at'])) . ($F['partial'] ? ' (partial)' : '') : 'no hunt yet' ?></div></div>
  <div class="cc-kpi"><div class="l">Accounts affected</div><div class="v"><?= count($byUser) ?></div><div class="s"><?= smpro_h(implode(', ', array_slice(array_keys($byUser), 0, 4))) ?></div></div>
  <div class="cc-kpi"><div class="l">Hidden processes</div><div class="v" style="color:<?= $procs ? 'var(--dang)' : 'var(--good)' ?>"><?= count($procs) ?></div><div class="s">running now</div></div>
  <div class="cc-kpi"><div class="l">In the store</div><div class="v"><?= count(array_filter($Q, fn($q) => empty($q['restored']))) ?></div><div class="s">root-only, restorable</div></div>
</div>

<div class="card ld-bar">
  <form method="post"><input type="hidden" name="smpro_csrf" value="<?= smpro_h($csrf) ?>"><input type="hidden" name="lr_action" value="hunt"><button class="btn btn-secondary" type="submit">&#128269; Hunt now</button></form>
  <form method="post" class="ld-teach"><input type="hidden" name="smpro_csrf" value="<?= smpro_h($csrf) ?>"><input type="hidden" name="lr_action" value="teach"><input type="text" name="folder" class="tp-in" placeholder="teach from a folder of kept malware, e.g. /root/incident-2026-10" style="min-width:340px"><button class="btn btn-secondary" type="submit">Teach</button></form>
  <form method="post" class="ld-cfg"><input type="hidden" name="smpro_csrf" value="<?= smpro_h($csrf) ?>"><input type="hidden" name="lr_action" value="cfg">
    <label><select name="auto"><option value="report"<?= $cfg['auto'] === 'report' ? ' selected' : '' ?>>Report only</option><option value="quarantine_exact"<?= $cfg['auto'] === 'quarantine_exact' ? ' selected' : '' ?>>Quarantine exact-file matches automatically</option></select></label>
    <label>look at files changed in the last <input type="number" name="recent_days" min="1" max="365" value="<?= (int)$cfg['recent_days'] ?>" style="width:64px"> days</label>
    <label title="Only patterns leave this server: a file's hash and size, a hidden folder name and extension, a behaviour key. Never a path, an account, a file's contents or an address. Shared lessons are reported here, never acted on by themselves."><input type="checkbox" name="share" value="1"<?= $cfg['share'] === 'on' ? ' checked' : '' ?>> share lessons with other servers (patterns only)</label>
    <button class="btn btn-xs btn-ghost" type="submit">Save</button></form>
</div>

<?php $sh = smpro_lr_load('share'); $shN = count(array_filter($L, fn($l) => ($l['source'] ?? '') === 'shared')); ?>
<div class="card ld-share"><span><b>Shared with other servers:</b> <?= $cfg['share'] === 'on' ? ($sh ? ((int)($sh['sent'] ?? 0) . ' lesson(s) sent, ' . $shN . ' received from ' . (int)($sh['servers'] ?? 0) . ' server(s), last exchange ' . smpro_h(date('Y-m-d H:i', (int)$sh['last'])) . (!empty($sh['err']) ? ' - ' . smpro_h((string)$sh['err']) : '')) : 'no exchange yet (the worker does one every six hours)') : 'off' ?>. What is sent: a file\'s hash and size, a hidden folder name and extension, a behaviour key - never a path, an account, a file\'s contents or an address. A shared lesson is reported here and never acts on its own.</span>
  <form method="post"><input type="hidden" name="smpro_csrf" value="<?= smpro_h($csrf) ?>"><input type="hidden" name="lr_action" value="share"><button class="btn btn-xs btn-ghost" type="submit">Exchange now</button></form></div>
<?php if ($procs): ?>
<div class="card" style="padding:0;overflow:hidden;margin-bottom:14px">
  <div class="ld-head"><b>&#9888; Processes a file scan cannot see</b><span class="meta">a program running from memory, a deleted program, a false name, or a shell a web request started hours ago</span></div>
  <div style="overflow-x:auto"><table class="smpro-table" style="margin:0"><thead><tr><th>Account</th><th>PID</th><th>Running for</th><th>Why it is suspicious</th><th>Command</th><th></th></tr></thead><tbody>
  <?php foreach ($procs as $p): ?>
    <tr><td class="mono"><b><?= smpro_h($p['user']) ?></b></td><td class="mono"><?= (int)$p['pid'] ?></td><td><?= $p['age'] >= 3600 ? floor($p['age'] / 3600) . ' h ' . floor(($p['age'] % 3600) / 60) . ' min' : floor($p['age'] / 60) . ' min' ?></td>
      <td><?php foreach ($p['why'] as $w): ?><div><?= smpro_h($w) ?></div><?php endforeach; ?><div class="meta mono">exe: <?= smpro_h($p['exe'] ?: '?') ?></div></td>
      <td class="mono" style="max-width:420px;word-break:break-all;font-size:11px"><?= smpro_h($p['cmd']) ?></td>
      <td><form method="post" data-confirm="Stop process <?= (int)$p['pid'] ?> of <?= smpro_h($p['user']) ?>? What it was is kept as evidence first."><input type="hidden" name="smpro_csrf" value="<?= smpro_h($csrf) ?>"><input type="hidden" name="lr_action" value="kill"><input type="hidden" name="pid" value="<?= (int)$p['pid'] ?>"><button class="btn btn-xs btn-danger" type="submit">Stop</button></form></td></tr>
  <?php endforeach; ?>
  </tbody></table></div>
</div>
<?php endif; ?>

<div class="card" style="padding:0;overflow:hidden;margin-bottom:14px">
  <div class="ld-head"><b>Findings</b><span class="meta"><?= count($findings) ?> file(s) that match a lesson · nothing is touched until you decide</span></div>
  <?php if (!$findings): ?><div class="ld-empty" style="color:var(--good)">&#10003; Nothing on this server matches a lesson<?= $L ? '' : ' - there are no lessons yet; confirm an incident or teach a folder' ?>.</div>
  <?php else: ?>
  <div style="overflow-x:auto;max-height:520px"><table class="smpro-table" style="margin:0"><thead><tr><th>Account</th><th>File</th><th>Why</th><th>Changed</th><th class="num">Size</th><th></th></tr></thead><tbody>
  <?php foreach (array_slice($findings, 0, 500) as $f): ?>
    <tr><td class="mono"><b><?= smpro_h($f['user']) ?></b></td><td class="mono" style="word-break:break-all;font-size:11.5px"><?= smpro_h($f['path']) ?></td>
      <td><?php foreach ($f['why'] as $w): ?><div><?= smpro_h($w) ?></div><?php endforeach; ?></td>
      <td><?= smpro_h(date('Y-m-d H:i', (int)$f['mtime'])) ?></td><td class="num"><?= number_format((int)$f['size']) ?></td>
      <td style="white-space:nowrap">
        <form method="post" style="display:inline" data-confirm="Move this file to the root-only store? Restore puts it back exactly."><input type="hidden" name="smpro_csrf" value="<?= smpro_h($csrf) ?>"><input type="hidden" name="lr_action" value="quarantine"><input type="hidden" name="path" value="<?= smpro_h($f['path']) ?>"><button class="btn btn-xs btn-danger" type="submit">Quarantine</button></form>
        <form method="post" style="display:inline"><input type="hidden" name="smpro_csrf" value="<?= smpro_h($csrf) ?>"><input type="hidden" name="lr_action" value="notbad"><input type="hidden" name="sha" value="<?= smpro_h($f['sha']) ?>"><button class="btn btn-xs btn-ghost" type="submit">Not malicious</button></form>
      </td></tr>
  <?php endforeach; ?>
  </tbody></table></div>
  <?php endif; ?>
</div>

<div class="ld-two">
<div class="card" style="padding:0;overflow:hidden">
  <div class="ld-head"><b>Lessons</b><span class="meta">what the server learned, and from which incident</span></div>
  <?php if (!$L): ?><div class="ld-empty">No lessons yet.</div><?php else: ?>
  <div style="overflow-x:auto;max-height:520px"><table class="smpro-table" style="margin:0"><thead><tr><th>Kind</th><th>Lesson</th><th>From</th><th class="num">Hits</th><th></th></tr></thead><tbody>
  <?php foreach ($L as $id => $l): $last = end($l['incidents']); ?>
    <tr style="<?= ($l['state'] ?? 'on') === 'on' ? '' : 'opacity:.55' ?>"><td><span class="pill <?= ($l['state'] ?? 'on') === 'on' ? 'warn' : '' ?>"><?= smpro_h($typeLabel[$l['type']] ?? $l['type']) ?></span></td>
      <td style="font-size:12px"><?= smpro_h($l['label']) ?><?= $l['type'] === 'hash' ? '<div class="meta mono">' . smpro_h(substr(explode(':', $l['key'])[0], 0, 16)) . '…</div>' : '' ?></td>
      <td style="font-size:11.5px"><?= ($l['source'] ?? '') === 'shared' ? 'shared by ' . (int)($l['shared']['servers'] ?? 0) . ' server(s)' : count($l['incidents']) . ' incident(s)' ?><div class="meta"><?= smpro_h(date('Y-m-d', (int)($last['at'] ?? 0))) ?> · <?= smpro_h((string)($last['user'] ?? '')) ?> · <?= smpro_h((string)($last['source'] ?? '')) ?></div></td>
      <td class="num"><?= (int)$l['hits'] ?><?= !empty($l['fp']) ? '<div class="meta">' . (int)$l['fp'] . ' wrong</div>' : '' ?></td>
      <td style="white-space:nowrap"><form method="post" style="display:inline"><input type="hidden" name="smpro_csrf" value="<?= smpro_h($csrf) ?>"><input type="hidden" name="lr_action" value="lesson"><input type="hidden" name="id" value="<?= smpro_h($id) ?>"><input type="hidden" name="state" value="<?= ($l['state'] ?? 'on') === 'on' ? 'off' : 'on' ?>"><button class="btn btn-xs btn-ghost" type="submit"><?= ($l['state'] ?? 'on') === 'on' ? 'Switch off' : 'Switch on' ?></button></form>
        <form method="post" style="display:inline" data-confirm="Forget this lesson?"><input type="hidden" name="smpro_csrf" value="<?= smpro_h($csrf) ?>"><input type="hidden" name="lr_action" value="forget"><input type="hidden" name="id" value="<?= smpro_h($id) ?>"><button class="btn btn-xs btn-ghost" type="submit">Forget</button></form></td></tr>
  <?php endforeach; ?>
  </tbody></table></div><?php endif; ?>
</div>
<div class="card" style="padding:0;overflow:hidden">
  <div class="ld-head"><b>The store</b><span class="meta">moved files, root-only; Restore puts one back exactly and marks it not malicious</span></div>
  <?php if (!$Q): ?><div class="ld-empty">Nothing in the store.</div><?php else: ?>
  <div style="overflow-x:auto;max-height:520px"><table class="smpro-table" style="margin:0"><thead><tr><th>When</th><th>File</th><th>Source</th><th></th></tr></thead><tbody>
  <?php foreach ($Q as $q): ?>
    <tr style="<?= empty($q['restored']) ? '' : 'opacity:.55' ?>"><td style="white-space:nowrap"><?= smpro_h(date('m-d H:i', (int)$q['at'])) ?></td><td class="mono" style="word-break:break-all;font-size:11.5px"><?= smpro_h($q['orig']) ?></td><td style="font-size:11.5px"><?= smpro_h((string)$q['source']) ?></td>
      <td><?php if (empty($q['restored'])): ?><form method="post" data-confirm="Put this file back where it was, and remember it as not malicious?"><input type="hidden" name="smpro_csrf" value="<?= smpro_h($csrf) ?>"><input type="hidden" name="lr_action" value="restore"><input type="hidden" name="kept" value="<?= smpro_h($q['kept']) ?>"><button class="btn btn-xs btn-ghost" type="submit">Restore</button></form><?php else: ?><span class="meta">restored</span><?php endif; ?></td></tr>
  <?php endforeach; ?>
  </tbody></table></div><?php endif; ?>
</div>
</div>

<style>
.ld-kpis{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:14px}@media(max-width:1100px){.ld-kpis{grid-template-columns:repeat(3,1fr)}}@media(max-width:600px){.ld-kpis{grid-template-columns:repeat(2,1fr)}}
.cc-kpi{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:12px 14px;min-width:0}
.cc-kpi .l{font-size:11px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.cc-kpi .v{font-size:24px;font-weight:800;margin-top:4px}.cc-kpi .s{font-size:11.5px;color:var(--muted);margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.ld-bar{display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin-bottom:14px}.ld-share{display:flex;gap:12px;align-items:center;justify-content:space-between;flex-wrap:wrap;font-size:12.5px;margin-bottom:14px}.ld-teach,.ld-cfg{display:flex;gap:8px;align-items:center;flex-wrap:wrap;font-size:12.5px}.ld-cfg{margin-left:auto}
.ld-head{padding:12px 16px;border-bottom:1px solid var(--line);font-weight:700;font-size:14px;display:flex;align-items:center;gap:10px;flex-wrap:wrap}.ld-head .meta{margin-left:auto;color:var(--muted);font-size:12px;font-weight:400}
.ld-empty{padding:18px 16px;font-size:13px}.ld-two{display:grid;grid-template-columns:1fr 1fr;gap:14px}@media(max-width:1000px){.ld-two{grid-template-columns:1fr}}
.meta{color:var(--muted);font-size:11px}.mono{font-family:ui-monospace,Menlo,Consolas,monospace}
</style>
<script>
document.addEventListener('submit',function(e){var f=e.target;if(f&&f.getAttribute('data-confirm')&&!confirm(f.getAttribute('data-confirm')))e.preventDefault();});
</script>
<?php smpro_layout_footer();