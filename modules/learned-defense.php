<?php
/**
 * modules/learned-defense.php — Learned Defense: lessons the server took from confirmed incidents, the hunt they
 * drive, processes a file scan cannot see, and the root-only store of what was moved. Engine: includes/learn.php.
 *
 * The page is read top to bottom the way an operator decides: how bad is it now (the strip), what needs a decision
 * (findings, grouped by account, worst first, filterable), then what the server knows (lessons), what it holds
 * (the store), and how it is set. Every action is a plain form; nothing is touched until a button is pressed.
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
        case 'hunt':      $r = smpro_lr_hunt_bg(); $ok = $r['ok']; $msg = $r['msg']; break;   // detached: the page never waits for a server-wide walk
        case 'teach':     $r = smpro_lr_teach_folder((string)($_POST['folder'] ?? '')); $ok = $r['ok']; $msg = $r['msg']; if ($ok) { $h = smpro_lr_hunt_bg(); $msg .= ' ' . $h['msg']; } break;
        case 'quarantine': $r = smpro_lr_quarantine((string)($_POST['path'] ?? ''), 'operator'); $ok = $r['ok']; $msg = $r['msg']; break;
        case 'quarantine_exact_all':
            // every finding that is the EXACT file of a confirmed incident (hash lesson, confirmed on this server)
            $F0 = smpro_lr_load('findings'); $L0 = smpro_lr_lessons(); $n = 0; $bad = 0;
            foreach ((array)($F0['findings'] ?? []) as $f0) {
                $exact = false; foreach ((array)$f0['lessons'] as $lid) if (($L0[$lid]['type'] ?? '') === 'hash' && ($L0[$lid]['source'] ?? '') !== 'shared' && !empty($L0[$lid]['incidents'])) $exact = true;
                if (!$exact) continue;
                $r = smpro_lr_quarantine((string)$f0['path'], 'operator: all exact-file matches'); if (!empty($r['ok'])) $n++; else $bad++;
            }
            $msg = $n . ' exact-file match(es) moved to the store' . ($bad ? ', ' . $bad . ' refused (see the audit)' : '') . '.'; $ok = $bad === 0; break;
        case 'quarantine_many':
            $n = 0; $bad = []; foreach (array_slice((array)($_POST['paths'] ?? []), 0, 500) as $pth) { $r = smpro_lr_quarantine((string)$pth, 'operator: selection'); if (!empty($r['ok'])) $n++; else $bad[] = basename((string)$pth) . ': ' . (string)($r['msg'] ?? 'refused'); }
            $msg = $n . ' file(s) moved to the store' . ($bad ? '; refused: ' . implode(' · ', array_slice($bad, 0, 5)) . (count($bad) > 5 ? ' …' : '') : '') . '.'; $ok = !$bad; break;
        case 'notbad_many':
            $n = 0; foreach (array_slice((array)($_POST['shas'] ?? []), 0, 500) as $sh) { $sh = preg_replace('/[^a-f0-9]/', '', (string)$sh); if ($sh !== '') { smpro_lr_mark_fp($sh); $n++; } }
            $msg = $n . ' file(s) remembered as not malicious.'; break;
        case 'restore':   $r = smpro_lr_restore((string)($_POST['kept'] ?? '')); $ok = $r['ok']; $msg = $r['msg']; break;
        case 'notbad':    $sha = preg_replace('/[^a-f0-9]/', '', (string)($_POST['sha'] ?? '')); if ($sha !== '') { smpro_lr_mark_fp($sha); $msg = 'Remembered as not malicious: this exact file is never reported again, and the lesson that matched it counts one more wrong call.'; } else { $ok = false; $msg = 'No file given.'; } break;
        case 'lesson':    $L = smpro_lr_lessons(); $id = preg_replace('/[^a-f0-9]/', '', (string)($_POST['id'] ?? '')); $st = (string)($_POST['state'] ?? '');
                          if (isset($L[$id]) && in_array($st, ['on', 'off'], true)) { $L[$id]['state'] = $st; smpro_lr_save('lessons', $L); $msg = 'Lesson ' . ($st === 'on' ? 'switched on' : 'switched off') . '.'; } else { $ok = false; $msg = 'Unknown lesson.'; } break;
        case 'forget':    $L = smpro_lr_lessons(); $id = preg_replace('/[^a-f0-9]/', '', (string)($_POST['id'] ?? '')); if (isset($L[$id])) { unset($L[$id]); smpro_lr_save('lessons', $L); $msg = 'Lesson forgotten.'; } else { $ok = false; $msg = 'Unknown lesson.'; } break;
        case 'kill':      $r = smpro_lr_kill((int)($_POST['pid'] ?? 0)); $ok = $r['ok']; $msg = $r['msg']; break;
        case 'cfg':       $c = smpro_lr_cfg(); $c['auto'] = ($_POST['auto'] ?? '') === 'quarantine_exact' ? 'quarantine_exact' : 'report'; $c['recent_days'] = max(1, min(365, (int)($_POST['recent_days'] ?? 30))); $c['share'] = !empty($_POST['share']) ? 'on' : 'off'; smpro_lr_save('cfg', $c); smpro_lr_cron_sync(); $msg = 'Saved.'; break;
        case 'share':     $r = smpro_lr_share(); $ok = $r['ok']; $msg = $ok ? ('Exchanged: ' . (int)$r['sent'] . ' lesson(s) sent, ' . (int)$r['pool'] . ' in the shared pool from ' . (int)$r['servers'] . ' server(s), ' . (int)$r['new'] . ' new here.') : ('Not exchanged: ' . (string)($r['why'] ?? '')); break;
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
$shN = count(array_filter($L, fn($l) => ($l['source'] ?? '') === 'shared'));
$sh = smpro_lr_load('share');
$csrf = smpro_csrf_generate('lr_act');
$typeLabel = ['hash' => 'exact file', 'relpath' => 'place in a site', 'dotdir' => 'hidden folder', 'behaviour' => 'behaviour', 'docblock' => 'file header', 'name' => 'file name'];

/* How bad is one finding? From the strongest lesson that matched it, or the structural check that raised it. */
$sevOf = function (array $f) use ($L): array {
    $sev = 'medium'; $kind = 'match';
    foreach ((array)$f['lessons'] as $lid) {
        if ($lid === 'structural') { $kind = 'structural'; $sev = 'high'; continue; }
        if ($lid === 'mailguard') { $kind = 'mail'; if ($sev === 'medium') $sev = 'medium'; continue; }
        if ($lid === 'tmp') { $kind = 'tmp'; $sev = 'high'; continue; }
        $t = (string)($L[$lid]['type'] ?? ''); $shared = ($L[$lid]['source'] ?? '') === 'shared';
        if ($t === 'hash' && !$shared) { $sev = 'critical'; $kind = 'exact'; }
        elseif ($t === 'hash') { if ($sev !== 'critical') { $sev = 'high'; $kind = 'exact'; } }
        elseif (in_array($t, ['behaviour', 'docblock', 'name', 'dotdir'], true)) { if ($sev === 'medium') { $sev = 'high'; $kind = 'lesson'; } }
        elseif ($t === 'relpath') { if ($sev === 'medium') $kind = 'place'; }
    }
    return [$sev, $kind];
};
$byUser = []; $bySev = ['critical' => 0, 'high' => 0, 'medium' => 0]; $exactN = 0;
foreach ($findings as $i => $f) { [$s, $k] = $sevOf($f); $findings[$i]['_sev'] = $s; $findings[$i]['_kind'] = $k; $bySev[$s]++; if ($k === 'exact' && $s === 'critical') $exactN++; $byUser[$f['user']][] = $findings[$i]; }
uksort($byUser, function ($a, $b) use ($byUser) { $w = fn($rows) => max(array_map(fn($r) => ['critical' => 3, 'high' => 2, 'medium' => 1][$r['_sev']], $rows)); return ($w($byUser[$b]) <=> $w($byUser[$a])) ?: (count($byUser[$b]) <=> count($byUser[$a])); });
$worst = $bySev['critical'] ? 'critical' : ($bySev['high'] ? 'high' : ($findings ? 'medium' : 'ok'));
/* filters, grouping and paging come from the query string so a view can be bookmarked and reloaded after an action */
$fSev = in_array((string)($_GET['sev'] ?? ''), ['critical', 'high', 'medium'], true) ? (string)$_GET['sev'] : '';
$fKind = preg_match('/^[a-z]{1,12}$/', (string)($_GET['kind'] ?? '')) ? (string)$_GET['kind'] : '';
$fUser = preg_match('/^[a-zA-Z0-9._-]{1,64}$/', (string)($_GET['user'] ?? '')) ? (string)$_GET['user'] : '';
$fQ = strtolower(trim(substr((string)($_GET['q'] ?? ''), 0, 120)));
$groupBy = in_array((string)($_GET['group'] ?? 'account'), ['account', 'severity', 'kind', 'none'], true) ? (string)($_GET['group'] ?? 'account') : 'account';
$perPage = in_array((int)($_GET['per'] ?? 50), [25, 50, 100, 200], true) ? (int)($_GET['per'] ?? 50) : 50;
$pageNo = max(1, (int)($_GET['p'] ?? 1));
$sevRank = ['critical' => 3, 'high' => 2, 'medium' => 1];
$view = array_values(array_filter($findings, function ($f) use ($fSev, $fKind, $fUser, $fQ) {
    if ($fSev !== '' && $f['_sev'] !== $fSev) return false;
    if ($fKind !== '' && $f['_kind'] !== $fKind) return false;
    if ($fUser !== '' && $f['user'] !== $fUser) return false;
    if ($fQ !== '' && strpos(strtolower($f['user'] . ' ' . $f['path'] . ' ' . implode(' ', $f['why'])), $fQ) === false) return false;
    return true;
}));
usort($view, fn($a, $b) => ($sevRank[$b['_sev']] <=> $sevRank[$a['_sev']]) ?: (strcmp($a['user'], $b['user']) ?: ((int)$b['mtime'] <=> (int)$a['mtime'])));
$total = count($view); $pages = max(1, (int)ceil($total / $perPage)); $pageNo = min($pageNo, $pages);
$slice = array_slice($view, ($pageNo - 1) * $perPage, $perPage);
$groups = [];
foreach ($slice as $f) { $g = $groupBy === 'account' ? $f['user'] : ($groupBy === 'severity' ? $f['_sev'] : ($groupBy === 'kind' ? $f['_kind'] : 'all')); $groups[$g][] = $f; }
$qs = function (array $over = []) use ($fSev, $fKind, $fUser, $fQ, $groupBy, $perPage, $pageNo) {
    $q = array_merge(['page' => 'learned-defense', 'sev' => $fSev, 'kind' => $fKind, 'user' => $fUser, 'q' => $fQ, 'group' => $groupBy, 'per' => $perPage, 'p' => $pageNo], $over);
    return 'index.cgi?' . http_build_query(array_filter($q, fn($v) => $v !== '' && $v !== null)) . '#findings';
};
$lastHunt = (int)($F['at'] ?? 0);
$hunting = smpro_lr_hunt_running();
smpro_layout_header('Learned Defense');
?>
<style>
.ld-strip{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:0 0 14px}
.ld-t{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:12px 14px;min-width:0;position:relative;overflow:hidden}
.ld-t:before{content:"";position:absolute;left:0;top:0;bottom:0;width:4px;background:var(--line)}
.ld-t.ok:before{background:var(--good)}.ld-t.warn:before{background:var(--warn)}.ld-t.bad:before{background:var(--dang)}.ld-t.brand:before{background:var(--brand)}
.ld-t .l{font-size:11px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.ld-t .v{font-size:26px;font-weight:800;margin-top:4px;line-height:1.1}.ld-t .s{font-size:11.5px;color:var(--muted);margin-top:4px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.ld-sev{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11px;font-weight:700;letter-spacing:.02em;white-space:nowrap}
.ld-sev.critical{background:var(--dang-bg);color:var(--dang)}.ld-sev.high{background:var(--warn-bg);color:var(--warn)}.ld-sev.medium{background:var(--brand-bg);color:var(--brand)}
.ld-kind{display:inline-block;padding:1px 7px;border-radius:6px;font-size:10.5px;font-weight:600;color:var(--muted);background:var(--bg);border:1px solid var(--line);margin-left:4px}
.ld-card{background:var(--card);border:1px solid var(--line);border-radius:12px;margin-bottom:14px;overflow:hidden}
.ld-head{padding:12px 16px;border-bottom:1px solid var(--line);display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.ld-head b{font-size:14px}.ld-head .meta{margin-left:auto;color:var(--muted);font-size:12px}
.ld-body{padding:12px 16px}
.ld-empty{padding:18px 16px;font-size:13px;color:var(--muted)}
.ld-acct{border-top:1px solid var(--line)}.ld-acct:first-child{border-top:0}
.ld-acct summary{list-style:none;cursor:pointer;padding:10px 16px;display:flex;align-items:center;gap:10px;flex-wrap:wrap;font-size:13px}
.ld-acct summary::-webkit-details-marker{display:none}.ld-acct summary .arr{display:inline-block;transition:transform .15s;color:var(--muted)}.ld-acct[open] summary .arr{transform:rotate(90deg)}
.ld-acct summary .u{font-weight:700;font-family:ui-monospace,Menlo,Consolas,monospace}.ld-acct summary .meta{margin-left:auto}
.ld-row{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:8px 14px;padding:8px 16px 10px 36px;border-top:1px dashed var(--line);font-size:12.5px;align-items:start}
.ld-row .p{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:11.5px;word-break:break-all}
.ld-row .w{color:var(--ink);margin-top:3px}.ld-row .w div:before{content:"\2022\00a0";color:var(--muted)}
.ld-row .m{color:var(--muted);font-size:11px;margin-top:3px}
.ld-acts{display:flex;gap:6px;flex-wrap:wrap;justify-content:flex-end}.ld-acts form{display:inline}
.ld-filters{display:flex;gap:6px;flex-wrap:wrap;align-items:center;padding:10px 16px;border-bottom:1px solid var(--line);font-size:12px}
.ld-fb{border:1px solid var(--line);background:var(--bg);border-radius:999px;padding:3px 10px;cursor:pointer;font-size:12px;color:var(--ink)}
.ld-fb.on{background:var(--brand);color:#fff;border-color:var(--brand)}.ld-fb.off{opacity:.4;pointer-events:none}a.ld-fb{text-decoration:none}
.ld-tools{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px;margin-bottom:14px}
.ld-tool{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:12px 14px}
.ld-tool h4{margin:0 0 4px;font-size:13px}.ld-tool p{margin:0 0 8px;font-size:12px;color:var(--muted);line-height:1.5}
.ld-tool form{display:flex;gap:6px;flex-wrap:wrap;align-items:center}.ld-tool input[type=text]{flex:1;min-width:160px}
.ld-two{display:grid;grid-template-columns:1fr 1fr;gap:14px}@media(max-width:1000px){.ld-two{grid-template-columns:1fr}}
.ld-search{padding:4px 8px;border:1px solid var(--line);border-radius:8px;font-size:12px;min-width:180px;background:var(--bg);color:var(--ink)}
.ld-how{font-size:12.5px;line-height:1.6;color:var(--ink)}.ld-how b{color:var(--ink)}
.meta{color:var(--muted);font-size:11px}.mono{font-family:ui-monospace,Menlo,Consolas,monospace}
.smpro-table td{vertical-align:top}
</style>

<h1 class="h">Learned Defense <?= smpro_beta_badge() ?></h1>
<p class="sub">The server learns from every incident you confirm and hunts for the same thing everywhere - and it sees the processes a file scan cannot.
  <details style="display:inline"><summary style="display:inline;cursor:pointer;color:var(--brand)">How it works</summary>
  <span class="ld-how"> Every file you confirm as malware (Delete or Clean in Imunify360 Reports, Quarantine here, or a folder you teach) becomes <b>lessons</b>: its exact file, its file name when rare, the place it sat, the hidden folder it hid in, the header it opens with, and what its code does. The <b>hunt</b> (every 10 minutes when something changed, daily otherwise) looks for those lessons in every site, and runs three checks that need no lesson: an <b>.htaccess</b> that turns an odd extension into a CGI program, a <b>native executable</b> inside a web folder, and what <b>MailGuard</b> attributed outgoing mail to. Lessons confirmed here are <b>shared</b> with other servers as patterns only - never a path, an account, a file's contents or an address - and lessons from other servers are reported here, never acted on by themselves. Nothing is deleted: a quarantined file goes to a root-only store and <b>Restore</b> puts it back exactly.</span></details></p>
<?php if ($flash !== ''): ?><div class="ld-card" style="border-left:4px solid var(--<?= $flashOk ? 'good' : 'dang' ?>);padding:10px 14px"><?= smpro_h($flash) ?></div><?php endif; ?>

<div class="ld-strip">
  <div class="ld-t <?= $worst === 'ok' ? 'ok' : ($worst === 'medium' ? 'brand' : 'bad') ?>"><div class="l">Findings</div><div class="v" style="color:<?= $worst === 'ok' ? 'var(--good)' : ($worst === 'critical' ? 'var(--dang)' : 'var(--warn)') ?>"><?= count($findings) ?></div><div class="s"><?= $findings ? $bySev['critical'] . ' critical · ' . $bySev['high'] . ' high · ' . $bySev['medium'] . ' medium' : 'nothing matches a lesson' ?></div></div>
  <div class="ld-t <?= $byUser ? 'warn' : 'ok' ?>"><div class="l">Accounts</div><div class="v"><?= count($byUser) ?></div><div class="s"><?= $byUser ? smpro_h(implode(', ', array_slice(array_keys($byUser), 0, 4))) . (count($byUser) > 4 ? ' …' : '') : 'none affected' ?></div></div>
  <div class="ld-t <?= $procs ? 'bad' : 'ok' ?>"><div class="l">Hidden processes</div><div class="v" style="color:<?= $procs ? 'var(--dang)' : 'var(--good)' ?>"><?= count($procs) ?></div><div class="s">running now · memory-only, deleted, false name, long web shell</div></div>
  <div class="ld-t brand"><div class="l">Lessons</div><div class="v"><?= $onN ?></div><div class="s"><?= count($L) - $onN ?> off · <?= $shN ?> from other servers</div></div>
  <div class="ld-t brand"><div class="l">In the store</div><div class="v"><?= count(array_filter($Q, fn($q) => empty($q['restored']))) ?></div><div class="s">root-only, restorable</div></div>
  <div class="ld-t <?= $hunting ? 'ok' : ($lastHunt && time() - $lastHunt < 86400 * 2 ? 'ok' : 'warn') ?>" id="ldHuntTile"><div class="l">Last hunt<?= $hunting ? ' · <b style="color:var(--brand)">hunting now…</b>' : '' ?></div><div class="v" style="font-size:18px"><?= $lastHunt ? smpro_h(date('m-d H:i', $lastHunt)) : 'never' ?></div><div class="s"><?= $hunting ? 'walking every site in the background - this page refreshes itself until the findings land' : ($F ? (int)$F['sites'] . ' of ' . (int)$F['of'] . ' site(s) in ' . (int)$F['took'] . ' s' . (!empty($F['partial']) ? ' · partial, continues' : '') : 'press Hunt now') ?></div></div>
</div>

<?php if ($procs): ?>
<div class="ld-card" style="border-color:var(--dang)">
  <div class="ld-head"><b>&#9888; Processes a file scan cannot see</b><span class="meta">a program running from memory, a deleted program, a false name, or a shell a web request started hours ago - stop it, and what it was is kept as evidence</span></div>
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

<div class="ld-card" id="findings">
  <div class="ld-head"><b>Findings</b><span class="meta"><?= count($findings) ?> file(s) · <?= $total === count($findings) ? 'all shown' : $total . ' match the filter' ?> · nothing is touched until you decide</span>
    <?php if ($exactN): ?><form method="post" style="margin-left:8px" data-confirm="Move all <?= $exactN ?> exact-file match(es) of confirmed incidents to the store? Restore puts any one back exactly."><input type="hidden" name="smpro_csrf" value="<?= smpro_h($csrf) ?>"><input type="hidden" name="lr_action" value="quarantine_exact_all"><button class="btn btn-xs btn-danger" type="submit">Quarantine all <?= $exactN ?> exact matches</button></form><?php endif; ?></div>
  <?php if (!$findings): ?><div class="ld-empty" style="color:var(--good)">&#10003; Nothing on this server matches a lesson<?= $L ? '' : ' - there are no lessons yet; confirm an incident or teach a folder' ?>.</div>
  <?php else: $kl = ['exact' => 'exact file', 'lesson' => 'lesson match', 'place' => 'same place', 'structural' => 'structural', 'mail' => 'sends mail', 'tmp' => 'in tmp', 'match' => 'match']; $kinds = []; foreach ($findings as $f) $kinds[$f['_kind']] = ($kinds[$f['_kind']] ?? 0) + 1; ?>
  <form method="get" action="index.cgi" class="ld-filters" id="ldf"><input type="hidden" name="page" value="learned-defense">
    <span class="meta">severity</span>
    <a class="ld-fb<?= $fSev === '' ? ' on' : '' ?>" href="<?= smpro_h($qs(['sev' => '', 'p' => 1])) ?>">all <?= count($findings) ?></a>
    <?php foreach (['critical', 'high', 'medium'] as $k): if ($bySev[$k]): ?><a class="ld-fb<?= $fSev === $k ? ' on' : '' ?>" href="<?= smpro_h($qs(['sev' => $k, 'p' => 1])) ?>"><?= $k ?> <?= $bySev[$k] ?></a><?php endif; endforeach; ?>
    <span class="meta" style="margin-left:8px">kind</span>
    <?php foreach ($kinds as $k => $n): ?><a class="ld-fb<?= $fKind === $k ? ' on' : '' ?>" href="<?= smpro_h($qs(['kind' => $fKind === $k ? '' : $k, 'p' => 1])) ?>"><?= smpro_h($kl[$k] ?? $k) ?> <?= $n ?></a><?php endforeach; ?>
    <span class="meta" style="margin-left:8px">account</span>
    <select name="user" class="tp-sel" onchange="this.form.submit()" style="max-width:180px"><option value="">all</option><?php foreach (array_keys($byUser) as $u): ?><option value="<?= smpro_h($u) ?>"<?= $fUser === $u ? ' selected' : '' ?>><?= smpro_h($u) ?> (<?= count($byUser[$u]) ?>)</option><?php endforeach; ?></select>
    <span class="meta" style="margin-left:8px">group by</span>
    <select name="group" class="tp-sel" onchange="this.form.submit()"><?php foreach (['account' => 'account', 'severity' => 'severity', 'kind' => 'kind', 'none' => 'nothing (flat list)'] as $gv => $gl): ?><option value="<?= $gv ?>"<?= $groupBy === $gv ? ' selected' : '' ?>><?= $gl ?></option><?php endforeach; ?></select>
    <select name="per" class="tp-sel" onchange="this.form.submit()"><?php foreach ([25, 50, 100, 200] as $pp): ?><option value="<?= $pp ?>"<?= $perPage === $pp ? ' selected' : '' ?>><?= $pp ?> / page</option><?php endforeach; ?></select>
    <input type="hidden" name="sev" value="<?= smpro_h($fSev) ?>"><input type="hidden" name="kind" value="<?= smpro_h($fKind) ?>">
    <input type="text" class="ld-search" name="q" value="<?= smpro_h($fQ) ?>" placeholder="account, path or reason…" style="margin-left:auto"><button class="btn btn-xs btn-ghost" type="submit">Filter</button>
    <?php if ($fSev || $fKind || $fUser || $fQ): ?><a class="fa-lnk" href="index.cgi?page=learned-defense#findings">clear</a><?php endif; ?>
  </form>
  <form method="post" id="ldsel">
    <input type="hidden" name="smpro_csrf" value="<?= smpro_h($csrf) ?>"><input type="hidden" name="lr_action" value="" id="ldselact">
    <div class="ld-filters" style="border-top:0">
      <label class="meta" style="cursor:pointer"><input type="checkbox" id="ldall"> select all on this page</label>
      <span class="meta" id="ldcount">0 selected</span>
      <button type="button" class="btn btn-xs btn-danger" data-bulk="quarantine_many" data-confirm="Move the selected files to the root-only store? Restore puts any one back exactly.">Quarantine selected</button>
      <button type="button" class="btn btn-xs btn-ghost" data-bulk="notbad_many" data-confirm="Remember the selected files as not malicious? They are never reported again and the lessons that matched them count one more wrong call.">Not malicious (selected)</button>
      <span class="meta" style="margin-left:auto">page <?= $pageNo ?> of <?= $pages ?> · <?= $total ?> row(s)</span>
      <?php if ($pages > 1): ?><a class="ld-fb<?= $pageNo <= 1 ? ' off' : '' ?>" href="<?= smpro_h($qs(['p' => max(1, $pageNo - 1)])) ?>">&#8249; prev</a>
      <?php foreach (array_unique(array_filter([1, $pageNo - 1, $pageNo, $pageNo + 1, $pages], fn($x) => $x >= 1 && $x <= $pages)) as $pn): ?><a class="ld-fb<?= $pn === $pageNo ? ' on' : '' ?>" href="<?= smpro_h($qs(['p' => $pn])) ?>"><?= $pn ?></a><?php endforeach; ?>
      <a class="ld-fb<?= $pageNo >= $pages ? ' off' : '' ?>" href="<?= smpro_h($qs(['p' => min($pages, $pageNo + 1)])) ?>">next &#8250;</a><?php endif; ?>
    </div>
    <div id="ldlist">
    <?php foreach ($groups as $g => $rows): $w = 'medium'; foreach ($rows as $r) if ($sevRank[$r['_sev']] > $sevRank[$w]) $w = $r['_sev']; $gl = $groupBy === 'kind' ? ($kl[$g] ?? $g) : $g; ?>
      <details class="ld-acct" open>
        <summary><span class="arr">&#9654;</span><span class="u"><?= smpro_h($gl) ?></span><?php if ($groupBy !== 'severity'): ?><span class="ld-sev <?= $w ?>"><?= $w ?></span><?php endif; ?><span><?= count($rows) ?> file(s)</span>
          <?php if ($groupBy === 'account'): ?><span class="meta"><a href="index.cgi?page=user-investigation&amp;user=<?= smpro_h($g) ?>&amp;win=7" class="fa-lnk">investigate &#8250;</a></span><?php endif; ?></summary>
        <?php foreach ($rows as $f): ?>
        <div class="ld-row" data-sev="<?= $f['_sev'] ?>" data-kind="<?= $f['_kind'] ?>">
          <div><label style="display:inline-flex;gap:6px;align-items:center;cursor:pointer"><input type="checkbox" class="ldck" name="paths[]" value="<?= smpro_h($f['path']) ?>" data-sha="<?= smpro_h($f['sha']) ?>"<?= is_dir($f['path']) ? ' disabled title="a folder is reported, not quarantined"' : '' ?>><span class="ld-sev <?= $f['_sev'] ?>"><?= $f['_sev'] ?></span><span class="ld-kind"><?= smpro_h($kl[$f['_kind']] ?? $f['_kind']) ?></span><?php if ($groupBy !== 'account'): ?><span class="ld-kind"><?= smpro_h($f['user']) ?></span><?php endif; ?></label>
            <div class="p"><?= smpro_h($f['path']) ?></div>
            <div class="w"><?php foreach ($f['why'] as $wl): ?><div><?= smpro_h($wl) ?></div><?php endforeach; ?></div>
            <div class="m">changed <?= smpro_h(date('Y-m-d H:i', (int)$f['mtime'])) ?> · <?= number_format((int)$f['size']) ?> bytes<?= $f['sha'] ? ' · sha256 ' . smpro_h(substr($f['sha'], 0, 12)) . '…' : '' ?></div></div>
          <div class="ld-acts">
            <?php if (!is_dir($f['path'])): ?><button type="button" class="btn btn-xs btn-danger" data-one="quarantine" data-path="<?= smpro_h($f['path']) ?>" data-confirm="Move this file to the root-only store? Restore puts it back exactly.">Quarantine</button><?php else: ?><span class="meta">a folder: open it, quarantine the file that sends</span><?php endif; ?>
            <?php if ($f['sha']): ?><button type="button" class="btn btn-xs btn-ghost" data-one="notbad" data-sha="<?= smpro_h($f['sha']) ?>">Not malicious</button><?php endif; ?>
          </div>
        </div>
        <?php endforeach; ?>
      </details>
    <?php endforeach; ?>
    </div>
  </form>
  <?php endif; ?>
</div>

<div class="ld-tools">
  <div class="ld-tool"><h4>&#128269; Hunt</h4><p>Look for every lesson in every site now (the worker does this by itself every 10 minutes when a lesson is new, and once a day otherwise).</p>
    <form method="post"><input type="hidden" name="smpro_csrf" value="<?= smpro_h($csrf) ?>"><input type="hidden" name="lr_action" value="hunt"><button class="btn btn-secondary" type="submit"<?= $hunting ? ' disabled title="a hunt is running"' : '' ?>><?= $hunting ? 'Hunting…' : 'Hunt now' ?></button></form></div>
<?php if ($hunting): ?><script>/* a hunt is running: come back for the findings without the operator pressing anything */ setTimeout(function(){ if (!document.hidden) location.reload(); else document.addEventListener('visibilitychange', function(){ if (!document.hidden) location.reload(); }); }, 20000);</script><?php endif; ?>
  <div class="ld-tool"><h4>&#127891; Teach</h4><p>A folder of kept malware whose layout mirrors where it was found (…/home/&lt;account&gt;/…) - an isolation folder, a quarantine. Every file in it becomes lessons, and a hunt follows.</p>
    <form method="post"><input type="hidden" name="smpro_csrf" value="<?= smpro_h($csrf) ?>"><input type="hidden" name="lr_action" value="teach"><input type="text" name="folder" class="tp-in" placeholder="/root/isolated-…" required><button class="btn btn-xs btn-ghost" type="submit">Teach</button></form></div>
  <div class="ld-tool"><h4>&#9881; Settings</h4><p>What the hunt does on its own with an EXACT file of a confirmed incident, how far back it reads changed files, and whether lessons are exchanged with other servers (patterns only).</p>
    <form method="post"><input type="hidden" name="smpro_csrf" value="<?= smpro_h($csrf) ?>"><input type="hidden" name="lr_action" value="cfg">
      <select name="auto" class="tp-sel"><option value="report"<?= $cfg['auto'] === 'report' ? ' selected' : '' ?>>exact matches: report only</option><option value="quarantine_exact"<?= $cfg['auto'] === 'quarantine_exact' ? ' selected' : '' ?>>exact matches: quarantine by itself</option></select>
      <label style="font-size:12px">changed in last <input type="number" name="recent_days" min="1" max="365" value="<?= (int)$cfg['recent_days'] ?>" style="width:60px"> days</label>
      <label style="font-size:12px" title="Only patterns leave this server: a file's hash and size, a hidden folder name and extension, a behaviour key, a header hash, a rare file name. Never a path, an account, a file's contents or an address."><input type="checkbox" name="share" value="1"<?= $cfg['share'] === 'on' ? ' checked' : '' ?>> share lessons</label>
      <button class="btn btn-xs btn-ghost" type="submit">Save</button></form>
    <div class="meta" style="margin-top:6px"><?= $cfg['share'] === 'on' ? ($sh ? (int)($sh['sent'] ?? 0) . ' sent · ' . $shN . ' received from ' . (int)($sh['servers'] ?? 0) . ' server(s) · last ' . smpro_h(date('m-d H:i', (int)($sh['last'] ?? 0))) . (!empty($sh['err']) ? ' · last error: ' . smpro_h($sh['err']) : '') : 'no exchange yet') : 'sharing is off' ?>
      <form method="post" style="display:inline;margin-left:6px"><input type="hidden" name="smpro_csrf" value="<?= smpro_h($csrf) ?>"><input type="hidden" name="lr_action" value="share"><button class="btn btn-xs btn-ghost" type="submit"<?= $cfg['share'] === 'on' ? '' : ' disabled' ?>>Exchange now</button></form></div></div>
</div>

<div class="ld-two">
<div class="ld-card">
  <div class="ld-head"><b>Lessons</b><span class="meta">what the server learned, and from which incident</span></div>
  <?php if (!$L): ?><div class="ld-empty">No lessons yet - confirm an incident or teach a folder.</div><?php else: ?>
  <div class="ld-filters"><span class="meta">kind:</span><button type="button" class="ld-fb on" data-lf="">all <?= count($L) ?></button>
    <?php $tc = []; foreach ($L as $l) $tc[$l['type']] = ($tc[$l['type']] ?? 0) + 1; foreach ($tc as $t => $n): ?><button type="button" class="ld-fb" data-lf="<?= smpro_h($t) ?>"><?= smpro_h($typeLabel[$t] ?? $t) ?> <?= $n ?></button><?php endforeach; ?>
    <?php if ($shN): ?><button type="button" class="ld-fb" data-lf="shared">shared <?= $shN ?></button><?php endif; ?>
    <input type="text" class="ld-search" id="llq" placeholder="search…" style="margin-left:auto"></div>
  <div style="overflow:auto;max-height:560px"><table class="smpro-table" style="margin:0" id="lltbl"><thead><tr><th>Kind</th><th>Lesson</th><th>From</th><th class="num">Hits</th><th></th></tr></thead><tbody>
  <?php foreach ($L as $id => $l): $last = end($l['incidents']); $isSh = ($l['source'] ?? '') === 'shared'; ?>
    <tr data-t="<?= smpro_h($l['type']) ?>" data-sh="<?= $isSh ? 1 : 0 ?>" data-q="<?= smpro_h(strtolower($l['label'] . ' ' . $l['key'])) ?>" style="<?= ($l['state'] ?? 'on') === 'on' ? '' : 'opacity:.5' ?>"><td><span class="pill <?= ($l['state'] ?? 'on') === 'on' ? 'warn' : '' ?>"><?= smpro_h($typeLabel[$l['type']] ?? $l['type']) ?></span><?= $isSh ? '<div class="meta">shared</div>' : '' ?></td>
      <td style="font-size:12px"><?= smpro_h($l['label']) ?><?= $l['type'] === 'hash' ? '<div class="meta mono">' . smpro_h(substr(explode(':', $l['key'])[0], 0, 16)) . '…</div>' : '' ?></td>
      <td style="font-size:11.5px"><?= $isSh ? 'shared by ' . (int)($l['shared']['servers'] ?? 0) . ' server(s)' : count($l['incidents']) . ' incident(s)' ?><div class="meta"><?= smpro_h(date('Y-m-d', (int)($last['at'] ?? $l['created'] ?? 0))) ?><?= !empty($last['source']) ? ' · ' . smpro_h($last['source']) : '' ?></div></td>
      <td class="num"><?= (int)$l['hits'] ?><?= !empty($l['fp']) ? '<div class="meta">' . (int)$l['fp'] . ' wrong</div>' : '' ?></td>
      <td style="white-space:nowrap"><form method="post" style="display:inline"><input type="hidden" name="smpro_csrf" value="<?= smpro_h($csrf) ?>"><input type="hidden" name="lr_action" value="lesson"><input type="hidden" name="id" value="<?= smpro_h($id) ?>"><input type="hidden" name="state" value="<?= ($l['state'] ?? 'on') === 'on' ? 'off' : 'on' ?>"><button class="btn btn-xs btn-ghost" type="submit"><?= ($l['state'] ?? 'on') === 'on' ? 'Off' : 'On' ?></button></form>
        <form method="post" style="display:inline" data-confirm="Forget this lesson?"><input type="hidden" name="smpro_csrf" value="<?= smpro_h($csrf) ?>"><input type="hidden" name="lr_action" value="forget"><input type="hidden" name="id" value="<?= smpro_h($id) ?>"><button class="btn btn-xs btn-ghost" type="submit">Forget</button></form></td></tr>
  <?php endforeach; ?>
  </tbody></table></div><?php endif; ?>
</div>
<div class="ld-card">
  <div class="ld-head"><b>The store</b><span class="meta">moved files, root-only; Restore puts one back exactly and marks it not malicious</span></div>
  <?php if (!$Q): ?><div class="ld-empty">Nothing in the store.</div><?php else: ?>
  <div style="overflow:auto;max-height:560px"><table class="smpro-table" style="margin:0"><thead><tr><th>When</th><th>File</th><th>Source</th><th></th></tr></thead><tbody>
  <?php foreach ($Q as $q): ?>
    <tr style="<?= empty($q['restored']) ? '' : 'opacity:.5' ?>"><td style="white-space:nowrap"><?= smpro_h(date('m-d H:i', (int)$q['at'])) ?></td><td class="mono" style="word-break:break-all;font-size:11.5px"><?= smpro_h($q['orig']) ?></td><td style="font-size:11.5px"><?= smpro_h((string)($q['source'] ?? '')) ?><?= empty($q['restored']) ? '' : '<div class="meta">restored</div>' ?></td>
      <td><?php if (empty($q['restored'])): ?><form method="post" data-confirm="Put this file back where it was, and remember it as not malicious?"><input type="hidden" name="smpro_csrf" value="<?= smpro_h($csrf) ?>"><input type="hidden" name="lr_action" value="restore"><input type="hidden" name="kept" value="<?= smpro_h($q['kept']) ?>"><button class="btn btn-xs btn-ghost" type="submit">Restore</button></form><?php endif; ?></td></tr>
  <?php endforeach; ?>
  </tbody></table></div><?php endif; ?>
</div>
</div>

<form method="post" id="ldone" style="display:none"><input type="hidden" name="smpro_csrf" value="<?= smpro_h($csrf) ?>"><input type="hidden" name="lr_action" value=""><input type="hidden" name="path" value=""><input type="hidden" name="sha" value=""></form>
<script>
document.addEventListener('submit',function(e){var f=e.target;if(f&&f.getAttribute('data-confirm')&&!confirm(f.getAttribute('data-confirm')))e.preventDefault();});
(function(){
  var sel=document.getElementById('ldsel'); if(!sel) return;
  var cks=function(){return Array.prototype.slice.call(sel.querySelectorAll('.ldck:not(:disabled)'));};
  function count(){var n=cks().filter(function(c){return c.checked;}).length; document.getElementById('ldcount').textContent=n+' selected';}
  var all=document.getElementById('ldall'); if(all) all.addEventListener('change',function(){cks().forEach(function(c){c.checked=all.checked;});count();});
  sel.addEventListener('change',function(e){if(e.target.classList.contains('ldck')) count();});
  sel.querySelectorAll('[data-bulk]').forEach(function(b){b.addEventListener('click',function(){
    var chosen=cks().filter(function(c){return c.checked;}); if(!chosen.length){alert('Select at least one file first.');return;}
    if(!confirm(b.dataset.confirm)) return;
    document.getElementById('ldselact').value=b.dataset.bulk;
    if(b.dataset.bulk==='notbad_many'){ chosen.forEach(function(c){var h=document.createElement('input');h.type='hidden';h.name='shas[]';h.value=c.dataset.sha;sel.appendChild(h);}); cks().forEach(function(c){c.disabled=true;}); }
    sel.submit();
  });});
  var one=document.getElementById('ldone');
  document.querySelectorAll('[data-one]').forEach(function(b){b.addEventListener('click',function(){
    if(b.dataset.confirm && !confirm(b.dataset.confirm)) return;
    one.querySelector('[name=lr_action]').value=b.dataset.one; one.querySelector('[name=path]').value=b.dataset.path||''; one.querySelector('[name=sha]').value=b.dataset.sha||''; one.submit();
  });});
})();
(function(){
  var cur='', q='';
  function apply(){
    document.querySelectorAll('#ldlist .ld-row').forEach(function(r){
      var ok=true;
      if(cur.indexOf('sev:')===0) ok=r.dataset.sev===cur.slice(4);
      else if(cur.indexOf('kind:')===0) ok=r.dataset.kind===cur.slice(5);
      if(ok&&q) ok=r.dataset.p.indexOf(q)>=0;
      r.style.display=ok?'':'none';
    });
    document.querySelectorAll('#ldlist .ld-acct').forEach(function(a){var vis=a.querySelectorAll('.ld-row:not([style*="display: none"])').length; a.style.display=vis?'':'none'; if(vis&&(cur||q)) a.open=true;});
  }
  
  
  var lf='', lq='';
  function lapply(){document.querySelectorAll('#lltbl tbody tr').forEach(function(r){var ok=true; if(lf==='shared') ok=r.dataset.sh==='1'; else if(lf) ok=r.dataset.t===lf; if(ok&&lq) ok=r.dataset.q.indexOf(lq)>=0; r.style.display=ok?'':'none';});}
  document.querySelectorAll('.ld-fb[data-lf]').forEach(function(b){b.addEventListener('click',function(){document.querySelectorAll('.ld-fb[data-lf]').forEach(function(x){x.classList.remove('on');});b.classList.add('on');lf=b.dataset.lf;lapply();});});
  var ls=document.getElementById('llq'); if(ls) ls.addEventListener('input',function(){lq=ls.value.trim().toLowerCase();lapply();});
})();
</script>
<?php smpro_layout_footer();
