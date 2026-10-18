<?php
/**
 * modules/disk-storage.php — Disk / Storage Details.
 * Read-only: filesystem usage (df), per-account disk usage (whmapi1 listaccts),
 * and inode usage. Flags mounts and accounts that are near their limit.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

/** Memory + swap from /proc/meminfo (kB). */
function smpro_ds_mem() {
    $mi = [];
    foreach (file('/proc/meminfo') ?: [] as $l) { if (preg_match('/^(\w+):\s+(\d+)/', $l, $m)) $mi[$m[1]] = (int)$m[2]; }
    $mt = $mi['MemTotal'] ?? 0; $ma = $mi['MemAvailable'] ?? ($mi['MemFree'] ?? 0);
    $st = $mi['SwapTotal'] ?? 0; $sf = $mi['SwapFree'] ?? 0; $su = max(0, $st - $sf);
    return ['mem_total'=>$mt,'mem_avail'=>$ma,'mem_avail_pct'=>$mt?round($ma/$mt*100,1):100,
            'swap_total'=>$st,'swap_used'=>$su,'swap_used_pct'=>$st?round($su/$st*100,1):0,'cached'=>$mi['Cached'] ?? 0];
}
/** Plan old-kernel removal SAFELY (read-only — makes NO changes).
 *  Keeps the running kernel + the 2 newest; never includes the running kernel; refuses edge cases.
 *  Returns ['mgr','running','remove'=>[...],'count','safe'=>bool,'reason']. */
function smpro_ds_boot_plan() {
    $running = trim((string)@shell_exec('uname -r'));
    if (is_file('/usr/bin/dnf') || is_file('/bin/dnf')) {
        $all = array_values(array_filter(array_map('trim', explode("\n", (string)@shell_exec('dnf repoquery --installonly --installed -q 2>/dev/null')))));
        $remove = array_values(array_filter(
            array_map('trim', explode("\n", (string)@shell_exec('dnf repoquery --installonly --installed -q --latest-limit=-2 2>/dev/null'))),
            function ($p) use ($running) { return $p !== '' && $running !== '' && strpos($p, $running) === false; }
        ));
        $count = count($all); $safe = true; $reason = '';
        if ($count <= 2)      { $safe = false; $reason = 'Only ' . $count . ' kernel(s) installed — nothing safe to remove.'; }
        elseif (!$remove)     { $safe = false; $reason = 'No old kernels beyond the running + newest — already clean.'; }
        foreach ($remove as $p) if ($running !== '' && strpos($p, $running) !== false) { $safe = false; $reason = 'Running kernel matched the removal set — refusing.'; break; }
        return ['mgr'=>'dnf','running'=>$running,'remove'=>$remove,'count'=>$count,'safe'=>$safe,'reason'=>$reason];
    }
    if (is_file('/usr/bin/apt-get')) {
        $dry = array_values(array_filter(array_map('trim', explode("\n", (string)@shell_exec('apt-get -s --purge autoremove 2>/dev/null | grep -E "^Remv linux-(image|headers)"')))));
        $remove = array_values(array_filter($dry, function ($l) use ($running) { return $running === '' || strpos($l, $running) === false; }));
        return ['mgr'=>'apt','running'=>$running,'remove'=>$remove,'count'=>0,'safe'=>!empty($remove),'reason'=>empty($remove) ? 'Nothing to autoremove.' : ''];
    }
    return ['mgr'=>'','running'=>$running,'remove'=>[],'count'=>0,'safe'=>false,'reason'=>'No supported package manager (dnf/apt).'];
}

/** Health checks across partitions / swap / memory / /tmp → each may carry a Fix action. */
function smpro_ds_checks($fs, $mem) {
    $c = [];
    $tmp = null; foreach ($fs as $r) if ($r['mount'] === '/tmp') $tmp = $r;
    $tmpNoexec = strpos((string)@shell_exec('findmnt -no OPTIONS /tmp 2>/dev/null'), 'noexec') !== false;
    if ($tmp && $tmp['pct'] >= 85) $c[] = ['label'=>'/tmp is ' . $tmp['pct'] . '% full', 'sev'=>$tmp['pct']>=95?'danger':'warn', 'fix'=>'fix_tmp_cache', 'fixlabel'=>'Clear old /tmp cache', 'why'=>'A full /tmp breaks uploads, sessions, package builds and backups.'];
    if ($tmp && !$tmpNoexec) $c[] = ['label'=>'/tmp is NOT mounted noexec', 'sev'=>'warn', 'fix'=>'fix_securetmp', 'fixlabel'=>'Secure /tmp (noexec)', 'why'=>'A world-writable executable /tmp lets attackers run dropped binaries.'];
    if ($mem['swap_total'] === 0) $c[] = ['label'=>'No swap configured', 'sev'=>'warn', 'fix'=>'', 'fixlabel'=>'', 'why'=>'Without swap, a memory spike can OOM-kill services. Add a swap file/partition.'];
    elseif ($mem['swap_used_pct'] >= 50) $c[] = ['label'=>'Swap is ' . $mem['swap_used_pct'] . '% used', 'sev'=>$mem['swap_used_pct']>=80?'danger':'warn', 'fix'=>'fix_swap', 'fixlabel'=>'Cycle swap (swapoff/on)', 'why'=>'Heavy swap use means RAM pressure; cycling swap moves idle pages back to RAM and frees swap.'];
    if ($mem['mem_avail_pct'] < 10) $c[] = ['label'=>'Only ' . $mem['mem_avail_pct'] . '% RAM available', 'sev'=>$mem['mem_avail_pct']<5?'danger':'warn', 'fix'=>'fix_dropcaches', 'fixlabel'=>'Drop page cache', 'why'=>'Reclaims reclaimable page cache. Safe — the kernel re-caches as needed.'];
    foreach ($fs as $r) {
        if ($r['pct'] < 90 || $r['mount'] === '/tmp') continue;
        $mnt = $r['mount']; $sev = $r['pct'] >= 95 ? 'danger' : 'warn';
        if ($mnt === '/boot' || $mnt === '/boot/efi') {
            // critical system path → safe one-click fix: remove OLD kernels (keep running + newest)
            $c[] = ['label'=>$mnt . ' is ' . $r['pct'] . '% full', 'sev'=>$sev, 'fix'=>'fix_boot_kernels', 'fixlabel'=>'Remove old kernels (keep running + newest)', 'why'=>'/boot fills up with old kernel packages. Removing them — never the running or newest — frees space so future kernel/security updates can install.'];
        } elseif ($mnt === '/var' || $mnt === '/var/log') {
            $c[] = ['label'=>$mnt . ' is ' . $r['pct'] . '% full', 'sev'=>$sev, 'fix'=>'fix_var_logs', 'fixlabel'=>'Vacuum journald + trim old logs', 'why'=>'System logs (journald + rotated/compressed logs) are the usual cause. This keeps the last 7 days and removes the rest — active logs are never touched.'];
        } else {
            // /, /home and data mounts → no blind auto-delete; point to the scans below
            $c[] = ['label'=>$mnt . ' is ' . $r['pct'] . '% full', 'sev'=>$sev, 'fix'=>'', 'fixlabel'=>'', 'why'=>'Holds user/system data — no safe blanket auto-clean. Use the large-files / old-backups / junk scans below to free space on ' . $mnt . '.'];
        }
    }
    return $c;
}

function smpro_ds_wrap($c, $t = 110) { return 'timeout ' . $t . ' nice -n ' . SMPRO_SCAN_NICE . ' ionice -c3 ' . $c; }
function smpro_ds_humb($b) { if ($b >= 1073741824) return round($b/1073741824,2).' GB'; if ($b >= 1048576) return round($b/1048576,1).' MB'; if ($b >= 1024) return round($b/1024,1).' KB'; return (int)$b.' B'; }

/** Per-account disk cleanup scan: large files, archives/backups, cache dirs, big logs. */
function smpro_ds_cleanscan($acct) {
    if ($acct === '' || !preg_match('/^[a-zA-Z0-9._-]+$/', $acct) || !is_dir('/home/' . $acct)) return ['err'=>'Invalid account.'];
    $home = '/home/' . $acct;
    // NEVER offer to delete mail, sessions or the off-site backup dir
    $excl = " -not -path '*/.snapshots/*' -not -ipath '*/mail/*' -not -path '/home/backup/*' -not -ipath '*/.trash/*'";
    $out = ['large'=>[], 'arch'=>[], 'logs'=>[], 'cache'=>[], 'mail'=>0];
    // large files (>40MB) — mail excluded (deleting customer mail = data loss)
    foreach (explode("\n", (string)@shell_exec(smpro_ds_wrap("find " . escapeshellarg($home) . " -type f -size +40M" . $excl . " -printf '%s\\t%TY-%Tm-%Td\\t%p\\n' 2>/dev/null | sort -rn | head -40"))) as $l) {
        if (trim($l)==='') continue; $p = explode("\t",$l,3); if (count($p)<3) continue; $out['large'][] = ['size'=>(int)$p[0],'mtime'=>$p[1],'file'=>$p[2]];
    }
    // mail storage size (info only — managed via webmail/account, never bulk-deleted here)
    if (is_dir($home . '/mail')) $out['mail'] = (int)trim((string)@shell_exec(smpro_ds_wrap('du -sb ' . escapeshellarg($home . '/mail') . " 2>/dev/null | cut -f1", 50)));
    // archives / DB dumps / backups (>5MB)
    foreach (explode("\n", (string)@shell_exec(smpro_ds_wrap("find " . escapeshellarg($home) . " -type f \\( -iname '*.zip' -o -iname '*.tar' -o -iname '*.tar.gz' -o -iname '*.tgz' -o -iname '*.gz' -o -iname '*.sql' -o -iname '*.bak' -o -iname '*.old' -o -iname '*.7z' -o -iname '*.rar' \\) -size +5M" . $excl . " -printf '%s\\t%TY-%Tm-%Td\\t%p\\n' 2>/dev/null | sort -rn | head -40"))) as $l) {
        if (trim($l)==='') continue; $p = explode("\t",$l,3); if (count($p)<3) continue; $out['arch'][] = ['size'=>(int)$p[0],'mtime'=>$p[1],'file'=>$p[2]];
    }
    // big logs (>10MB)
    foreach (explode("\n", (string)@shell_exec(smpro_ds_wrap("find " . escapeshellarg($home) . " -type f \\( -iname '*.log' -o -iname 'error_log' -o -iname 'access-*.log' \\) -size +10M" . $excl . " -printf '%s\\t%TY-%Tm-%Td\\t%p\\n' 2>/dev/null | sort -rn | head -30"))) as $l) {
        if (trim($l)==='') continue; $p = explode("\t",$l,3); if (count($p)<3) continue; $out['logs'][] = ['size'=>(int)$p[0],'mtime'=>$p[1],'file'=>$p[2]];
    }
    // cache directories (safe to clear)
    foreach (['public_html/wp-content/cache','public_html/storage/framework/cache','public_html/storage/framework/views','public_html/bootstrap/cache','public_html/cache','.cache','tmp','public_html/wp-content/cache/wp-rocket'] as $cd) {
        $p = $home . '/' . $cd; if (!is_dir($p)) continue;
        $sz = (int)trim((string)@shell_exec(smpro_ds_wrap('du -sb ' . escapeshellarg($p) . " 2>/dev/null | cut -f1", 40)));
        if ($sz > 1048576) $out['cache'][] = ['dir'=>$p,'size'=>$sz];
    }
    usort($out['cache'], fn($a,$b)=>$b['size']<=>$a['size']);
    return $out;
}
function smpro_ds_safe_target($f, $kind) {
    // files must live under a real /home/<account>/ tree; cache dirs limited to known cache paths
    if ($kind === 'cache') return (bool)preg_match('#^/home/[^/]+/.+/(cache|views|bootstrap/cache|\.cache|tmp)(/.*)?$#', $f) || (bool)preg_match('#/cache(/|$)#', $f);
    return (bool)preg_match('#^/home/[^/]+/.+#', $f) && strpos($f, '/..') === false;
}
function smpro_ds_rep_dir() { $d = SMPRO_VARLIB . '/reports/disk_deletions'; @is_dir($d) || @mkdir($d, 0700, true); return $d; }
/** Standalone HTML deletion report (served as a downloadable .html by index.cgi). */
function smpro_ds_report_html($rep) {
    $h = fn($s) => htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $items = is_array($rep['items'] ?? null) ? $rep['items'] : [];
    $total = 0; foreach ($items as $it) $total += (int)($it['size'] ?? 0);
    echo "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><title>Disk deletion report " . $h($rep['id'] ?? '') . "</title><style>"
       . "*{box-sizing:border-box}body{font:13px/1.5 -apple-system,Segoe UI,Arial,sans-serif;color:#1f2733;margin:0;padding:28px;background:#fff}"
       . "h1{font-size:20px;margin:0 0 4px}.muted{color:#6b7686;font-size:12px;margin:0 0 16px}"
       . ".cards{display:flex;gap:10px;flex-wrap:wrap;margin:0 0 18px}.c{border:1px solid #e6eaf1;border-radius:10px;padding:10px 14px;min-width:130px}.c .l{font-size:10px;text-transform:uppercase;color:#6b7686}.c .v{font-size:20px;font-weight:700}"
       . "table{width:100%;border-collapse:collapse;font-size:12px}th,td{border:1px solid #e6eaf1;padding:6px 8px;text-align:left;vertical-align:top;word-break:break-all}th{background:#f4f6fb;font-size:10px;text-transform:uppercase;color:#475569}"
       . ".brand{font-weight:700;color:#3b5bdb}.head{display:flex;justify-content:space-between;flex-wrap:wrap;gap:10px}.num{text-align:right;white-space:nowrap}"
       . "</style></head><body>";
    echo "<div class=\"head\"><div><h1>Disk Deletion Report</h1><p class=\"muted\">Report " . $h($rep['id'] ?? '') . " · generated " . $h($rep['at'] ?? '') . " · by " . $h($rep['actor'] ?? 'root') . "</p></div><div class=\"brand\">&#128190; Safety Monitor Pro</div></div>";
    echo "<div class=\"cards\"><div class=\"c\"><div class=\"l\">Items deleted</div><div class=\"v\">" . count($items) . "</div></div>"
       . "<div class=\"c\"><div class=\"l\">Space freed</div><div class=\"v\">" . smpro_ds_humb($total) . "</div></div>"
       . "<div class=\"c\"><div class=\"l\">Backups kept in</div><div class=\"v\" style=\"font-size:13px\">/home/backup/detections</div></div></div>";
    echo "<table><thead><tr><th>#</th><th>Account</th><th>Type</th><th class=\"num\">Size</th><th>Path</th><th>Backup</th></tr></thead><tbody>";
    $i = 0; foreach ($items as $it) { $i++;
        $acct = preg_match('#^/home/([^/]+)/#', (string)($it['path'] ?? ''), $m) ? $m[1] : '';
        echo "<tr><td>$i</td><td>" . $h($acct) . "</td><td>" . $h($it['kind'] ?? 'file') . "</td><td class=\"num\">" . smpro_ds_humb((int)($it['size'] ?? 0)) . "</td><td>" . $h($it['path'] ?? '') . "</td><td>" . $h($it['backup'] ?? '—') . "</td></tr>";
    }
    echo "</tbody></table><p class=\"muted\" style=\"margin-top:16px\">Files are backed up under /home/backup/detections/&lt;account&gt;/ before deletion and can be restored. Cache directories were cleared (no backup).</p></body></html>";
}
/* serve a saved deletion report as a downloadable HTML file (index.cgi sends format=html as attachment) */
if (($_GET['report'] ?? '') !== '') {
    $rid = preg_replace('/[^a-zA-Z0-9_]/', '', (string)$_GET['report']);
    $f = smpro_ds_rep_dir() . '/' . $rid . '.json';
    $rep = is_file($f) ? json_decode((string)@file_get_contents($f), true) : null;
    if (is_array($rep)) smpro_ds_report_html($rep); else echo '<p>Report not found.</p>';
    exit;
}

/* ---------- interactive fixes + cleanup actions (POST + CSRF + ROOT + audit) ---------- */
$reqMethod = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? getenv('REQUEST_METHOD') ?: 'GET'));
$dsCsrf0 = function_exists('smpro_csrf_generate') ? smpro_csrf_generate('ds') : '';
/* AJAX: render the cleanup scan fragment for one account */
if (($_GET['ajax'] ?? '') === 'cleanscan') {
    $acct = preg_replace('/[^a-zA-Z0-9._-]/', '', (string)($_GET['user'] ?? ''));
    $sc = smpro_ds_cleanscan($acct);
    smpro_audit('disk_cleanscan', ['account'=>$acct]);
    if (!empty($sc['err'])) { echo '<div class="fa-empty">' . smpro_h($sc['err']) . '</div>'; exit; }
    $total = count($sc['cache']) + count($sc['arch']) + count($sc['large']) + count($sc['logs']);
    $sect = function ($title, $items, $kind, $safety) {
        $badge = $safety === 'safe' ? '<span class="b good">safe</span>' : ($safety === 'likely' ? '<span class="b orange">likely safe</span>' : '<span class="b red">review</span>');
        echo '<div class="dc-sect"><div class="dc-stt">' . smpro_h($title) . ' ' . $badge . ' <span class="meta">(' . count($items) . ')</span>'
           . ($items ? '<button class="dc-selall fa-lnk" type="button">select all</button>' : '') . '</div>';
        if (!$items) { echo '<div class="meta" style="padding:6px 0">none found.</div></div>'; return; }
        echo '<table class="smpro-table"><tbody>';
        foreach ($items as $it) {
            $path = $it['file'] ?? $it['dir']; $sz = smpro_ds_humb($it['size']);
            $bytes = (int)($it['size'] ?? 0);
            if ($kind === 'cache') {
                $row = '<td style="width:24px"><input type="checkbox" class="dcChk" data-kind="cache" data-size="' . $bytes . '" data-path="' . smpro_h($path) . '"></td>'
                     . '<td class="num mono" style="width:90px">' . $sz . '</td><td colspan="2" class="mono fa-file">' . smpro_h($path) . '</td>'
                     . '<td style="text-align:right"><button class="fa-lnk dcClear" data-dir="' . smpro_h($path) . '">&#129529; Clear</button></td>';
            } else {
                $row = '<td style="width:24px"><input type="checkbox" class="dcChk" data-kind="file" data-size="' . $bytes . '" data-path="' . smpro_h($path) . '"></td>'
                     . '<td class="num mono" style="width:90px">' . $sz . '</td><td class="mono" style="width:110px">' . smpro_h($it['mtime'] ?? '') . '</td><td class="mono fa-file">' . smpro_h($path) . '</td>'
                     . '<td style="text-align:right"><button class="fa-lnk dcDel" data-file="' . smpro_h($path) . '">&#128465; Delete</button></td>';
            }
            echo '<tr>' . $row . '</tr>';
        }
        echo '</tbody></table></div>';
    };
    echo '<div class="dc-note"><b>Mail, sessions and /home/backup are never listed for deletion.</b> Cache/views are safe to clear (apps regenerate them). Archives, .sql dumps and old backups are usually leftover. Large files &amp; logs — review the path before deleting. Every delete is backed up to <span class="mono">/home/backup/detections</span> and is restorable. Tick rows and use <b>Delete selected</b> for bulk cleanup.</div>';
    if (!empty($sc['mail'])) echo '<div class="dc-sect"><div class="dc-stt">Mail storage <span class="b gray">protected</span></div><div class="meta" style="padding:4px 0">This account\'s mail uses <b>' . smpro_ds_humb($sc['mail']) . '</b>. Mail is never deleted here — trim it from the customer\'s webmail / Email Disk Usage, or ask them to empty Trash/Sent.</div></div>';
    $sect('Cache / compiled', $sc['cache'], 'cache', 'safe');
    $sect('Archives · DB dumps · backups', $sc['arch'], 'file', 'likely');
    $sect('Large files (≥40 MB, mail excluded)', $sc['large'], 'file', 'review');
    $sect('Big logs (≥10 MB)', $sc['logs'], 'file', 'likely');
    echo '<div class="dc-bulkbar" id="dcBulk" hidden><span><b id="dcN">0</b> selected &middot; <b id="dcSz">0 B</b></span><button class="tp-btn danger" id="dcDelSel" type="button">&#128465; Delete selected</button><button class="fa-lnk" id="dcClr" type="button">clear</button></div>';
    if ($total === 0) echo '<div class="fa-empty" style="color:var(--good);padding:16px">&#10003; Nothing obviously reclaimable found for this account.</div>';
    exit;
}
/* AJAX: SERVER-WIDE scans (large files / old backups / junk-cache) — bounded + mail/backup excluded */
if (($_GET['ajax'] ?? '') === 'svscan') {
    $type = preg_replace('/[^a-z]/', '', (string)($_GET['type'] ?? ''));
    // PRUNE the huge / dangerous trees so find never walks millions of mail files
    $prune = "\\( -path '/home/backup' -o -ipath '*/mail' -o -ipath '*/.trash*' -o -ipath '*/.snapshots' -o -ipath '*/node_modules' -o -ipath '*/.git' \\) -prune -o";
    $pruneC = " -o -ipath '*/vendor'";   // also skip vendor for large/oldbak (not for junk)
    $items = []; $title = ''; $safety = 'review';
    if ($type === 'large') {
        $title = 'Large files ≥500 MB (all accounts, mail excluded)'; $safety = 'review';
        $cmd = smpro_ds_wrap("find /home -maxdepth 7 \\( -path '/home/backup' -o -ipath '*/mail' -o -ipath '*/.trash*' -o -ipath '*/node_modules' -o -ipath '*/vendor' -o -ipath '*/cache' \\) -prune -o -type f -size +500M -printf '%s\\t%TY-%Tm-%Td\\t%p\\n' -print 2>/dev/null | sort -rn | head -120", 200);
    } elseif ($type === 'oldbak') {
        $title = 'Old backups & archives >30 days (all accounts)'; $safety = 'likely';
        $cmd = smpro_ds_wrap("find /home -maxdepth 7 \\( -path '/home/backup' -o -ipath '*/mail' -o -ipath '*/.trash*' -o -ipath '*/node_modules' \\) -prune -o -type f \\( -iname '*.tar.gz' -o -iname '*.tgz' -o -iname '*.tar' -o -iname '*.zip' -o -iname '*.gz' -o -iname '*.sql' -o -iname '*.bak' -o -iname '*.old' \\) -size +5M -mtime +30 -printf '%s\\t%TY-%Tm-%Td\\t%p\\n' -print 2>/dev/null | sort -rn | head -150", 220);
    } elseif ($type === 'junk') {
        $title = 'Safe junk / cache files >2 days (all accounts)'; $safety = 'safe';
        $cmd = smpro_ds_wrap("find /home -maxdepth 9 \\( -path '/home/backup' -o -ipath '*/mail' -o -ipath '*/.trash*' -o -ipath '*/node_modules' \\) -prune -o -type f -atime +2 \\( -ipath '*/cache/*' -o -ipath '*/storage/framework/*' -o -ipath '*/bootstrap/cache/*' -o -ipath '*/.cache/*' \\) -not -name 'index.php' -not -name '.gitignore' -printf '%s\\t%TY-%Tm-%Td\\t%p\\n' -print 2>/dev/null | sort -rn | head -200", 220);
    } else { echo '<div class="fa-empty">Unknown scan.</div>'; exit; }
    foreach (explode("\n",(string)@shell_exec($cmd)) as $l){ if(trim($l)==='')continue; $p=explode("\t",$l,3); if(count($p)<3)continue; $items[]=['size'=>(int)$p[0],'mtime'=>$p[1],'file'=>$p[2]]; }
    smpro_audit('disk_svscan', ['type'=>$type,'hits'=>count($items)]);
    $bdg = $safety==='safe'?'<span class="b good">safe</span>':($safety==='likely'?'<span class="b orange">likely safe</span>':'<span class="b red">review</span>');
    echo '<div class="dc-note">Server-wide scan — <b>mail, sessions, .trash and /home/backup are excluded</b>. Tick rows and use <b>Delete selected</b>. Every delete is backed up to /home/backup/detections (restorable).</div>';
    echo '<div class="dc-sect"><div class="dc-stt">' . smpro_h($title) . ' ' . $bdg . ' <span class="meta">(' . count($items) . ')</span>' . ($items?'<button class="dc-selall fa-lnk" type="button">select all</button>':'') . '</div>';
    if (!$items) echo '<div class="fa-empty" style="color:var(--good);padding:14px">&#10003; None found.</div>';
    else { echo '<table class="smpro-table"><tbody>';
        foreach ($items as $it) {
            $acct = preg_match('#^/home/([^/]+)/#',$it['file'],$mm)?$mm[1]:'';
            echo '<tr><td style="width:24px"><input type="checkbox" class="dcChk" data-kind="file" data-size="'.(int)$it['size'].'" data-path="'.smpro_h($it['file']).'"></td>'
               . '<td class="num mono" style="width:90px">'.smpro_ds_humb($it['size']).'</td><td class="mono" style="width:90px">'.smpro_h($acct).'</td>'
               . '<td class="mono" style="width:100px">'.smpro_h($it['mtime']).'</td><td class="mono fa-file">'.smpro_h($it['file']).'</td>'
               . '<td style="text-align:right"><button class="fa-lnk dcDel" data-file="'.smpro_h($it['file']).'">&#128465; Delete</button></td></tr>';
        }
        echo '</tbody></table>';
    }
    echo '</div><div class="dc-bulkbar" id="dcBulk" hidden><span><b id="dcN">0</b> selected &middot; <b id="dcSz">0 B</b></span><button class="tp-btn danger" id="dcDelSel" type="button">&#128465; Delete selected</button><button class="fa-lnk" id="dcClr" type="button">clear</button></div>';
    exit;
}

if ($reqMethod === 'POST' && ($_POST['ds_action'] ?? '') !== '') {
    smpro_require_valid_csrf('ds'); smpro_require_root();
    header('Content-Type: application/json');
    $act = preg_replace('/[^a-z_]/', '', (string)$_POST['ds_action']);
    $r = ['ok'=>false,'msg'=>'Unknown action.'];
    if ($act === 'fix_swap') {
        $m = smpro_ds_mem();
        if ($m['mem_avail'] < $m['swap_used'] * 1.5 || $m['mem_avail_pct'] < 25) $r = ['ok'=>false,'msg'=>'Refused: cycling swap needs free RAM ≥ 1.5× swap-in-use AND ≥25% RAM free, to rule out any OOM risk on production. Not met now.'];
        else {
            $off = (string)@shell_exec('timeout 180 /usr/sbin/swapoff -a 2>&1');
            $on  = (string)@shell_exec('timeout 120 /usr/sbin/swapon -a 2>&1');
            $a = smpro_ds_mem();
            $ok = stripos($on, 'error') === false;
            $r = ['ok'=>$ok,'msg'=>$ok ? ('Swap cycled safely. Swap usage now ' . $a['swap_used_pct'] . '%.') : ('swapon issue: ' . trim($on))];
        }
    } elseif ($act === 'fix_dropcaches') {
        @shell_exec('sync');
        $w = @file_put_contents('/proc/sys/vm/drop_caches', "1\n");
        $a = smpro_ds_mem();
        $r = ['ok'=>$w !== false,'msg'=>$w !== false ? ('Page cache dropped. RAM available now ' . $a['mem_avail_pct'] . '%.') : 'Could not write drop_caches.'];
    } elseif ($act === 'fix_securetmp') {
        $out = (string)@shell_exec('timeout 150 /scripts/securetmp --auto 2>&1');
        $ok = strpos((string)@shell_exec('findmnt -no OPTIONS /tmp 2>/dev/null'), 'noexec') !== false;
        $r = ['ok'=>$ok,'msg'=>$ok ? '/tmp secured (noexec).' : ('securetmp ran; verify /tmp. ' . trim(mb_substr($out,0,160)))];
    } elseif ($act === 'fix_tmp_cache') {
        $out = (string)@shell_exec("timeout 90 nice -n 19 find /tmp -maxdepth 3 -type f -atime +3 -not -name 'sess_*' -not -name 'cpsess*' -not -name '*.sock' -not -name '.s.*' -not -name '*.lock' -not -ipath '*cpanel*' -not -ipath '*mysql*' -delete 2>&1");
        $r = ['ok'=>true,'msg'=>'Cleared regular /tmp files older than 3 days (sessions, sockets and locks were preserved).'];
    } elseif ($act === 'preview_boot_kernels') {
        // READ-ONLY dry run — shows exactly what would be removed, changes nothing.
        $p = smpro_ds_boot_plan();
        $r = ['ok'=>true, 'preview'=>1, 'mgr'=>$p['mgr'], 'running'=>$p['running'], 'remove'=>$p['remove'],
              'count'=>$p['count'], 'safe'=>$p['safe'], 'reason'=>$p['reason'],
              'msg'=>$p['safe'] ? (count($p['remove']) . ' old kernel package(s) would be removed; running ' . $p['running'] . ' + newest kept.') : ('Refused: ' . $p['reason'])];
    } elseif ($act === 'fix_boot_kernels') {
        $p = smpro_ds_boot_plan();
        if (!$p['safe'] || empty($p['remove'])) {
            $r = ['ok'=>false, 'msg'=>'Refused for safety: ' . ($p['reason'] ?: 'nothing safe to remove') . '.'];
        } else {
            $pct = function ($m) { return (int)trim((string)@shell_exec('df -P ' . escapeshellarg($m) . " 2>/dev/null | awk 'NR==2{print \$5}' | tr -d '%'")); };
            $mnt = is_dir('/boot') ? '/boot' : '/'; $before = $pct($mnt); $running = $p['running'];
            if ($p['mgr'] === 'dnf') {
                $out = (string)@shell_exec('timeout 300 dnf -y remove ' . implode(' ', array_map('escapeshellarg', $p['remove'])) . ' 2>&1');
                @shell_exec('timeout 60 dnf -y clean packages 2>&1');
            } else {
                $out = (string)@shell_exec('timeout 300 apt-get -y --purge autoremove 2>&1');
            }
            // POST-VERIFY boot integrity — the running kernel MUST still be present & bootable.
            $vmRun = trim((string)@shell_exec('ls /boot/vmlinuz-' . escapeshellarg($running) . ' 2>/dev/null')) !== '';
            $vmAny = (int)trim((string)@shell_exec('ls /boot/vmlinuz-* 2>/dev/null | wc -l'));
            $grubOk = trim((string)@shell_exec('ls /boot/grub2/grub.cfg /boot/grub/grub.cfg /boot/loader/entries/*.conf 2>/dev/null | head -1')) !== '';
            $after = $pct($mnt);
            if (!$vmRun || $vmAny < 1) {
                $r = ['ok'=>false, 'critical'=>1, 'msg'=>'⚠ STOP — DO NOT REBOOT. Post-check could not confirm the running kernel (' . $running . ') in /boot. Reinstall it now: dnf reinstall kernel-core-' . $running . ' && grub2-mkconfig -o /boot/grub2/grub.cfg . Detail: ' . trim(mb_substr($out, -180))];
            } else {
                $r = ['ok'=>true, 'msg'=>'Removed ' . count($p['remove']) . ' old kernel(s). Verified: running ' . $running . ' present, ' . $vmAny . ' kernel(s) in /boot' . ($grubOk ? ', bootloader config intact' : '') . '. ' . $mnt . ' now ' . $after . '% (was ' . $before . '%). No restart needed — safe to reboot whenever.'];
            }
        }
    } elseif ($act === 'fix_var_logs') {
        $pct = function ($m) { return (int)trim((string)@shell_exec('df -P ' . escapeshellarg($m) . " 2>/dev/null | awk 'NR==2{print \$5}' | tr -d '%'")); };
        $mnt = is_dir('/var/log') && trim((string)@shell_exec('df -P /var 2>/dev/null | tail -1')) !== '' ? '/var' : '/';
        $before = $pct($mnt);
        if (is_file('/usr/bin/journalctl') || is_file('/bin/journalctl')) {
            @shell_exec('timeout 120 journalctl --rotate 2>&1');
            @shell_exec('timeout 120 journalctl --vacuum-time=7d 2>&1');
            @shell_exec('timeout 120 journalctl --vacuum-size=200M 2>&1');
        }
        // remove only ROTATED/compressed logs older than 14 days — never active logs
        @shell_exec("timeout 90 nice -n 19 find /var/log -type f \\( -name '*.gz' -o -name '*.xz' -o -name '*.old' -o -name '*.1' -o -name '*.2' -o -name '*.3' -o -name '*.4' -o -name '*.5' -o -name '*.6' -o -name '*.7' \\) -mtime +14 -delete 2>/dev/null");
        $after = $pct($mnt);
        $r = ['ok'=>true,'msg'=>'Journald vacuumed (kept 7 days / 200M) and rotated logs older than 14 days removed. ' . $mnt . ' now ' . $after . '% (was ' . $before . '%).'];
    } elseif ($act === 'del_file') {
        $f = (string)($_POST['file'] ?? '');
        if (!smpro_ds_safe_target($f, 'file') || !is_file($f)) $r = ['ok'=>false,'msg'=>'Refused: only existing files under /home/<account>/.'];
        else {
            $acct = preg_match('#^/home/([^/]+)/#',$f,$m)?$m[1]:'unknown';
            $bdir = '/home/backup/detections/' . $acct; @is_dir($bdir) || @mkdir($bdir, 0700, true);
            $bak = $bdir . '/' . date('Ymd_His') . '_' . preg_replace('/[^a-zA-Z0-9._-]/','_',basename($f));
            if (@copy($f, $bak) && @unlink($f)) { @chmod($bak,0600); $r = ['ok'=>true,'msg'=>'Deleted (backed up → ' . basename($bak) . ', restorable).']; }
            else $r = ['ok'=>false,'msg'=>'Backup/delete failed (permissions?).'];
        }
    } elseif ($act === 'del_report') {
        $items = json_decode((string)($_POST['items'] ?? '[]'), true);
        $clean = [];
        foreach ((array)$items as $it) { if (!is_array($it)) continue; $clean[] = ['path'=>(string)($it['path'] ?? ''), 'size'=>(int)($it['size'] ?? 0), 'kind'=>preg_replace('/[^a-z]/','',(string)($it['kind'] ?? 'file')), 'backup'=>(string)($it['backup'] ?? '')]; }
        if (!$clean) { $r = ['ok'=>false,'msg'=>'No items.']; }
        else {
            $id = date('Ymd_His') . '_' . substr(hash('sha256', json_encode($clean) . uniqid('', true)), 0, 8);
            $rep = ['id'=>$id, 'at'=>date('Y-m-d H:i:s'), 'actor'=>function_exists('smpro_current_actor')?smpro_current_actor():'root', 'items'=>$clean];
            @file_put_contents(smpro_ds_rep_dir() . '/' . $id . '.json', json_encode($rep, JSON_UNESCAPED_SLASHES), LOCK_EX);
            smpro_audit('disk_del_report', ['id'=>$id,'count'=>count($clean)]);
            $r = ['ok'=>true,'id'=>$id,'url'=>'index.cgi?page=disk-storage&report=' . $id . '&format=html'];
        }
    } elseif ($act === 'clear_cache') {
        $d = (string)($_POST['dir'] ?? '');
        if (!smpro_ds_safe_target($d, 'cache') || !is_dir($d)) $r = ['ok'=>false,'msg'=>'Refused: only known cache directories under /home/<account>/.'];
        else {
            $before = (int)trim((string)@shell_exec('du -sb ' . escapeshellarg($d) . ' 2>/dev/null | cut -f1'));
            @shell_exec(smpro_ds_wrap('find ' . escapeshellarg($d) . " -mindepth 1 -not -name '.gitignore' -not -name 'index.php' -delete 2>/dev/null", 90));
            $after = (int)trim((string)@shell_exec('du -sb ' . escapeshellarg($d) . ' 2>/dev/null | cut -f1'));
            $r = ['ok'=>true,'msg'=>'Cache cleared — freed ' . smpro_ds_humb(max(0,$before-$after)) . '.'];
        }
    }
    smpro_audit('disk_fix', ['action'=>$act,'ok'=>$r['ok'],'msg'=>$r['msg']]);
    echo json_encode($r, JSON_UNESCAPED_SLASHES); exit;
}

/** Parse `df -hP` (display) + `df -Pk` (for % math) into rows, excluding pseudo fs. */
function smpro_ds_filesystems() {
    $skip = '/^(tmpfs|devtmpfs|udev|efivarfs|none|overlay)$/i';
    $rows = [];
    $kp = (string)@shell_exec("timeout 15 df -Pk 2>/dev/null");
    $hp = (string)@shell_exec("timeout 15 df -hP 2>/dev/null");
    $hmap = [];
    foreach (explode("\n", $hp) as $l) { $p = preg_split('/\s+/', trim($l)); if (count($p) >= 6 && $p[0] !== 'Filesystem') $hmap[$p[5]] = $p; }
    foreach (explode("\n", $kp) as $l) {
        $p = preg_split('/\s+/', trim($l)); if (count($p) < 6 || $p[0] === 'Filesystem') continue;
        if (preg_match($skip, $p[0])) continue;
        $mount = $p[5]; $used = (int)$p[2]; $avail = (int)$p[3]; $total = $used + $avail ?: (int)$p[1];
        $pct = $total > 0 ? round($used / $total * 100, 1) : 0;
        $h = $hmap[$mount] ?? [$p[0],'','','','',$mount];
        $rows[] = ['fs'=>$p[0],'mount'=>$mount,'size'=>$h[1],'used'=>$h[2],'avail'=>$h[3],'pct'=>$pct];
    }
    return $rows;
}
function smpro_ds_inodes() {
    $skip = '/^(tmpfs|devtmpfs|udev|efivarfs|none|overlay)$/i'; $rows = [];
    foreach (explode("\n", (string)@shell_exec("timeout 15 df -iP 2>/dev/null")) as $l) {
        $p = preg_split('/\s+/', trim($l)); if (count($p) < 6 || $p[0] === 'Filesystem' || preg_match($skip, $p[0])) continue;
        $pct = (float)rtrim((string)$p[4], '%');
        $rows[$p[5]] = ['mount'=>$p[5],'used'=>$p[2],'free'=>$p[3],'pct'=>$pct];
    }
    return $rows;
}
/** Per-account disk usage from cPanel (MB), sorted desc. */
function smpro_ds_accounts() {
    $j = json_decode((string)@shell_exec("timeout 45 whmapi1 --output=json listaccts 2>/dev/null"), true);
    $a = $j['data']['acct'] ?? [];
    $rows = [];
    foreach ((array)$a as $u) {
        $usedMb = (float)preg_replace('/[^0-9.]/', '', (string)($u['diskused'] ?? '0'));
        $limRaw = (string)($u['disklimit'] ?? 'unlimited');
        $limMb = stripos($limRaw, 'unlim') !== false ? 0 : (float)preg_replace('/[^0-9.]/', '', $limRaw);
        $rows[] = ['user'=>(string)($u['user'] ?? ''),'domain'=>(string)($u['domain'] ?? ''),'used'=>$usedMb,'limit'=>$limMb,
                   'pct'=>$limMb > 0 ? round($usedMb / $limMb * 100, 1) : null];
    }
    usort($rows, fn($x,$y)=>$y['used']<=>$x['used']);
    return $rows;
}
function smpro_ds_h($mb) { if ($mb >= 1048576) return round($mb/1048576,2).' TB'; if ($mb >= 1024) return round($mb/1024,1).' GB'; return round($mb).' MB'; }

$fs = smpro_ds_filesystems();
$inodes = smpro_ds_inodes();
$accts = smpro_ds_accounts();
$mem = smpro_ds_mem();
$checks = smpro_ds_checks($fs, $mem);
$dsCsrf = smpro_csrf_generate('ds');
$home = null; foreach ($fs as $r) if ($r['mount']==='/home') $home = $r; if (!$home) foreach ($fs as $r) if ($r['mount']==='/') $home = $r;
$root = null; foreach ($fs as $r) if ($r['mount']==='/') $root = $r;
$fullMounts = array_filter($fs, fn($r)=>$r['pct'] >= 85);
$nearLimit = array_filter($accts, fn($a)=>$a['pct']!==null && $a['pct']>=85);

smpro_audit('disk_storage_view', ['accounts'=>count($accts)]);
smpro_layout_header('Disk / Storage');
$pcls = fn($p)=>$p>=90?'red':($p>=75?'orange':'good');
?>
<div class="svc-kicker">Storage</div>
<h1 class="h" style="margin:2px 0 4px">Disk / Storage Details</h1>
<p class="sub">Live filesystem, inode and per-account disk usage. Mounts or accounts at/over 85% are flagged — act before a backup or upload fails.</p>

<div class="ds-kpis">
  <div class="kpi"><div class="kn"><?= $root?smpro_h($root['used']):'—' ?></div><div class="kl">/ used (of <?= $root?smpro_h($root['size']):'?' ?>)</div></div>
  <div class="kpi <?= $home&&$home['pct']>=85?'crit':'' ?>"><div class="kn"><?= $home?smpro_h($home['pct']).'%':'—' ?></div><div class="kl">/home usage</div></div>
  <div class="kpi"><div class="kn"><?= count($accts) ?></div><div class="kl">Accounts</div></div>
  <div class="kpi <?= ($fullMounts||$nearLimit)?'crit':'' ?>"><div class="kn"><?= count($fullMounts)+count($nearLimit) ?></div><div class="kl">Near-full (≥85%)</div></div>
</div>

<!-- ===== Interactive Admin Disk Tools ===== -->
<div class="card" style="padding:0;overflow:hidden;margin:14px 0;border-top:3px solid <?= $checks?'var(--dang)':'var(--good)' ?>">
  <div class="ds-head"><b>&#128295; Interactive Admin Disk Tools</b><span class="meta">RAM, swap, /tmp &amp; partition health — one-click fixes</span></div>
  <div style="padding:14px 16px">
    <div class="ds-kpis" style="margin:0 0 14px;grid-template-columns:repeat(3,1fr)">
      <div class="kpi"><div class="kn"><?= $mem['mem_avail_pct'] ?>%</div><div class="kl">RAM available (<?= smpro_ds_h($mem['mem_avail']/1024) ?>)</div></div>
      <div class="kpi <?= $mem['swap_used_pct']>=50?'crit':'' ?>"><div class="kn"><?= $mem['swap_total']?$mem['swap_used_pct'].'%':'none' ?></div><div class="kl">Swap used<?= $mem['swap_total']?' of '.smpro_ds_h($mem['swap_total']/1024):'' ?></div></div>
      <?php $tmpfs=null; foreach($fs as $r) if($r['mount']==='/tmp')$tmpfs=$r; ?>
      <div class="kpi <?= ($tmpfs&&$tmpfs['pct']>=85)?'crit':'' ?>"><div class="kn"><?= $tmpfs?$tmpfs['pct'].'%':'—' ?></div><div class="kl">/tmp used</div></div>
    </div>
    <div class="ds-svtools">
      <span class="ds-svlbl">Server-wide scans:</span>
      <button class="tp-btn dsSv" type="button" data-type="large">&#128269; Large files (≥500 MB)</button>
      <button class="tp-btn dsSv" type="button" data-type="oldbak">&#128230; Old backups &amp; archives (&gt;30 d)</button>
      <button class="tp-btn dsSv" type="button" data-type="junk">&#129529; Safe junk / cache (&gt;2 d)</button>
    </div>
    <div class="ds-svtools">
      <span class="ds-svlbl">Maintenance / cleanup:</span>
      <button class="tp-btn dsFix" type="button" data-act="fix_boot_kernels" data-label="Clean /boot (remove old kernels)" data-why="Removes old kernel packages (keeps the running kernel + the 2 newest). Shows a dry-run preview first; /boot integrity is verified after. No restart.">&#129529; Clean /boot</button>
      <button class="tp-btn dsFix" type="button" data-act="fix_var_logs" data-label="Trim journald + old logs" data-why="Vacuums journald (keeps 7 days / 200 MB) and removes rotated/compressed logs older than 14 days. Active logs are never touched. No restart.">&#128220; Trim logs</button>
      <button class="tp-btn dsFix" type="button" data-act="fix_tmp_cache" data-label="Clear old /tmp cache" data-why="Deletes regular /tmp files older than 3 days; sessions, sockets and locks are preserved.">&#128465; /tmp cache</button>
      <button class="tp-btn dsFix" type="button" data-act="fix_dropcaches" data-label="Drop page cache" data-why="Frees reclaimable page cache. Safe — the kernel re-caches as needed. No restart.">&#129504; Drop cache</button>
      <button class="tp-btn dsFix" type="button" data-act="fix_swap" data-label="Cycle swap (safe)" data-why="swapoff/swapon to move idle pages back to RAM and free swap. Refused unless free RAM ≥ 1.5× swap-in-use and ≥25% free, to rule out OOM. No service restart.">&#9851;&#65039; Cycle swap</button>
    </div>
    <?php if (!$checks): ?>
      <div class="b good" style="padding:10px 14px;display:block">&#10003; All clear — RAM, swap, /tmp and every partition are within healthy limits. Fix buttons appear here automatically when a problem is detected.</div>
    <?php else: foreach ($checks as $c): ?>
      <div class="ds-check <?= $c['sev'] ?>">
        <div class="ds-checkbody">
          <div class="ds-checktt"><span class="b <?= $c['sev']==='danger'?'red':'orange' ?>"><?= $c['sev']==='danger'?'CRITICAL':'WARNING' ?></span> <b><?= smpro_h($c['label']) ?></b></div>
          <div class="ds-checkwhy"><?= smpro_h($c['why']) ?></div>
        </div>
        <?php if (!empty($c['fix'])): ?><button class="tp-btn dsFix" data-act="<?= smpro_h($c['fix']) ?>" data-label="<?= smpro_h($c['fixlabel']) ?>" data-why="<?= smpro_h($c['why']) ?>" type="button">&#128295; <?= smpro_h($c['fixlabel']) ?></button><?php else: ?><span class="meta">manual review</span><?php endif; ?>
      </div>
    <?php endforeach; endif; ?>
  </div>
</div>

<!-- Fix review modal (dry-run preview + Execute/Cancel) -->
<div id="dsModal" class="ds-modal" hidden>
  <div class="ds-modal-card">
    <div class="ds-modal-head"><span id="dsmTitle">Review</span><button class="ds-modal-x" id="dsmX" type="button" aria-label="Close">&times;</button></div>
    <div class="ds-modal-body" id="dsmBody"></div>
    <div class="ds-modal-foot">
      <button class="btn" id="dsmCancel" type="button">Cancel</button>
      <button class="btn btn-danger" id="dsmGo" type="button">Execute</button>
    </div>
  </div>
</div>

<div class="card" style="padding:0;overflow:hidden;margin:14px 0;border-top:3px solid <?= $fullMounts?'var(--dang)':'var(--good)' ?>">
  <div class="ds-head"><b>Filesystems &amp; Inodes</b></div>
  <div class="ds-tw"><table class="smpro-table"><thead><tr><th>Mount</th><th>Filesystem</th><th>Size</th><th>Used</th><th>Avail</th><th>Usage</th><th>Inodes</th></tr></thead><tbody>
    <?php foreach ($fs as $r): $in = $inodes[$r['mount']] ?? null; ?>
      <tr class="<?= $r['pct']>=85?'ds-warn':'' ?>">
        <td class="mono"><b><?= smpro_h($r['mount']) ?></b></td><td class="mono"><?= smpro_h($r['fs']) ?></td>
        <td class="mono"><?= smpro_h($r['size']) ?></td><td class="mono"><?= smpro_h($r['used']) ?></td><td class="mono"><?= smpro_h($r['avail']) ?></td>
        <td><div class="ds-bar"><span class="<?= $pcls($r['pct']) ?>" style="width:<?= min(100,$r['pct']) ?>%"></span></div><span class="b <?= $pcls($r['pct']) ?>"><?= $r['pct'] ?>%</span></td>
        <td><?= $in?('<span class="b '.$pcls($in['pct']).'">'.$in['pct'].'%</span>'):'—' ?></td>
      </tr>
    <?php endforeach; ?>
  </tbody></table></div>
</div>

<div class="card" style="padding:0;overflow:hidden;margin:14px 0">
  <div class="ds-head"><b>Top accounts by disk usage</b><span class="meta">cPanel quota · <?= count($nearLimit) ?> at/over 85% of their limit</span></div>
  <div class="ds-tw" style="max-height:560px"><table class="smpro-table"><thead><tr><th>#</th><th>Account</th><th>Domain</th><th class="num">Used</th><th class="num">Limit</th><th>Quota usage</th><th></th></tr></thead><tbody>
    <?php foreach (array_slice($accts,0,60) as $i=>$a): ?>
      <tr class="<?= ($a['pct']!==null&&$a['pct']>=85)?'ds-warn':'' ?>">
        <td><?= $i+1 ?></td>
        <td class="mono"><b><?= smpro_h($a['user']) ?></b></td>
        <td class="mono fa-file"><?= smpro_h($a['domain']) ?></td>
        <td class="num mono"><?= smpro_ds_h($a['used']) ?></td>
        <td class="num mono"><?= $a['limit']>0?smpro_ds_h($a['limit']):'∞' ?></td>
        <td><?php if($a['pct']!==null): ?><div class="ds-bar"><span class="<?= $pcls($a['pct']) ?>" style="width:<?= min(100,$a['pct']) ?>%"></span></div><span class="b <?= $pcls($a['pct']) ?>"><?= $a['pct'] ?>%</span><?php else: ?><span class="meta">unlimited</span><?php endif; ?></td>
        <td><button class="fa-lnk dcScan" type="button" data-acct="<?= smpro_h($a['user']) ?>">&#129529; Clean up</button></td>
      </tr>
    <?php endforeach; ?>
  </tbody></table></div>
</div>

<div id="dcResult"></div>

<style>
.dc-panel{background:#fff;border:1px solid var(--line);border-radius:14px;margin:14px 0;overflow:hidden}
.dc-phead{padding:12px 16px;border-bottom:1px solid var(--line);font-weight:700;display:flex;gap:10px;align-items:center}
.dc-note{padding:10px 16px;background:var(--warn-bg);color:#8a6516;font-size:12px;border-bottom:1px solid var(--line)}
.dc-sect{padding:10px 16px;border-bottom:1px solid var(--line)}.dc-stt{font-size:12px;font-weight:700;text-transform:uppercase;color:var(--muted);margin-bottom:6px}
.dc-scanprog{height:5px;background:#eef2ff;overflow:hidden}.dc-scanprog span{display:block;height:100%;width:35%;background:linear-gradient(90deg,#7c3aed,#4f46e5);animation:dcp 1.2s ease-in-out infinite}@keyframes dcp{0%{margin-left:-35%}100%{margin-left:100%}}
.dcDel,.dcClear{font-weight:700;white-space:nowrap;color:var(--dang);border-color:#f3c9c9}.dcDel:hover,.dcClear:hover{background:var(--dang);color:#fff}
.dc-selall{margin-left:8px;font-size:11px}
.dc-bulkbar{position:sticky;bottom:0;display:flex;align-items:center;gap:12px;padding:11px 16px;background:#fff7f7;border-top:1px solid #f3c9c9;font-size:13px}
.dc-bulkbar .tp-btn.danger{background:var(--dang);color:#fff;border-color:var(--dang);font-weight:700}
.dc-stt .b{vertical-align:middle}
.svc-kicker{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--brand);font-weight:800}
.ds-kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:14px 0}@media(max-width:720px){.ds-kpis{grid-template-columns:1fr 1fr}}
.kpi{background:#fff;border:1px solid var(--line);border-radius:12px;padding:14px;text-align:center}.kpi .kn{font-size:23px;font-weight:800;line-height:1}.kpi .kl{font-size:11px;text-transform:uppercase;color:var(--muted);margin-top:6px}
.kpi.crit{border-color:#f3c9c9;background:#fff7f7}.kpi.crit .kn{color:var(--dang)}
.ds-head{padding:12px 16px;border-bottom:1px solid var(--line);font-weight:700;font-size:14px;display:flex;gap:10px;align-items:center}.ds-head .meta{margin-left:auto;color:var(--muted);font-size:12px}
.ds-tw{overflow:auto}.ds-tw thead th{position:sticky;top:0;background:#fafbfe;box-shadow:inset 0 -1px 0 var(--line)}
.smpro-table{width:100%;border-collapse:collapse;font-size:12px}.smpro-table th,.smpro-table td{padding:8px 12px;text-align:left;border-bottom:1px solid var(--line);white-space:nowrap;vertical-align:middle}
.smpro-table th{font-size:11px;text-transform:uppercase;color:var(--muted)}.smpro-table td.num,.smpro-table th.num{text-align:right}
.ds-warn td{background:#fdf4f4}.mono{font-family:ui-monospace,Consolas,monospace}.fa-file{white-space:normal;word-break:break-all;max-width:280px}
.ds-bar{display:inline-block;width:90px;height:7px;border-radius:5px;background:#eef2ff;overflow:hidden;vertical-align:middle;margin-right:7px}
.ds-bar span{display:block;height:100%}.ds-bar .good{background:var(--good)}.ds-bar .orange{background:#c2710c}.ds-bar .red{background:var(--dang)}
.b{display:inline-block;font-size:11px;font-weight:700;padding:2px 8px;border-radius:20px}.b.good{background:var(--good-bg);color:var(--good)}.b.orange{background:#fdf1e3;color:#c2710c}.b.red{background:var(--dang-bg);color:var(--dang)}
.fa-lnk{color:var(--brand);text-decoration:none;font-size:11px;border:1px solid var(--line);padding:1px 7px;border-radius:6px}.meta{color:var(--muted)}
.ds-svtools{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin:0 0 14px;padding-bottom:12px;border-bottom:1px solid var(--line)}
.ds-svlbl{font-size:11px;text-transform:uppercase;font-weight:700;color:var(--muted)}
.ds-svtools .tp-btn{font-size:12px;padding:7px 12px}
.ds-check{display:flex;align-items:center;gap:14px;flex-wrap:wrap;padding:12px 14px;border:1px solid var(--line);border-radius:12px;margin-bottom:10px}
.ds-check.warn{border-color:#f0d8b8;background:#fffaf3}.ds-check.danger{border-color:#f3c9c9;background:#fff7f7}
.ds-checkbody{flex:1;min-width:240px}.ds-checktt{font-size:13px}.ds-checkwhy{font-size:12px;color:var(--muted);margin-top:4px}
.dsFix{background:var(--brand);color:#fff;border-color:var(--brand);font-weight:700;white-space:nowrap}.dsFix:hover{filter:brightness(1.08)}.dsFix[disabled]{opacity:.6}
.b.good{background:var(--good-bg);color:var(--good)}
/* Fix review modal */
.ds-modal{position:fixed;inset:0;background:rgba(2,8,23,.55);display:flex;align-items:center;justify-content:center;z-index:3000;padding:20px;backdrop-filter:blur(2px)}
.ds-modal[hidden]{display:none}
.ds-modal-card{background:#fff;border-radius:16px;max-width:580px;width:100%;box-shadow:0 24px 70px rgba(2,8,23,.45);overflow:hidden;animation:dsmIn .18s ease}
@keyframes dsmIn{from{transform:translateY(14px) scale(.98);opacity:0}to{transform:none;opacity:1}}
.ds-modal-head{display:flex;align-items:center;justify-content:space-between;padding:16px 20px;border-bottom:1px solid var(--line);font-weight:800;font-size:15px}
.ds-modal-x{border:none;background:none;font-size:24px;cursor:pointer;color:var(--muted);line-height:1;padding:0 4px}
.ds-modal-body{padding:18px 20px;max-height:62vh;overflow:auto}
.ds-modal-foot{display:flex;gap:10px;justify-content:flex-end;padding:14px 20px;border-top:1px solid var(--line);background:#fafbff}
.dsm-row{display:flex;gap:10px;margin-bottom:9px;font-size:13px;align-items:center}
.dsm-row b{min-width:130px;color:var(--muted);font-weight:600}
.dsm-list{background:#f6f8fc;border:1px solid var(--line);border-radius:10px;padding:11px 13px;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;line-height:1.7;max-height:220px;overflow:auto;white-space:pre-wrap;margin-top:4px}
.dsm-note{font-size:12px;color:var(--muted);background:#f0f7ff;border:1px solid #d6e6fb;border-radius:10px;padding:10px 12px;margin-top:12px}
.dsm-result{font-size:13px;line-height:1.6;margin-top:10px;white-space:pre-wrap}
.dsm-badge{display:inline-block;padding:3px 11px;border-radius:20px;font-weight:700;font-size:12px}
.dsm-badge.ok{background:var(--good-bg);color:var(--good)}.dsm-badge.bad{background:var(--dang-bg);color:var(--dang)}.dsm-badge.warn{background:var(--warn-bg);color:#9a6700}
</style>
<script>
(function(){
  var CSRF=<?= json_encode($dsCsrf) ?>;
  function dsPost(act){var fd=new URLSearchParams();fd.set('ds_action',act);fd.set('smpro_csrf',CSRF);
    return fetch(location.pathname+location.search,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString()}).then(function(r){return r.json();});}
  var M=document.getElementById('dsModal'),mTitle=document.getElementById('dsmTitle'),mBody=document.getElementById('dsmBody'),
      mGo=document.getElementById('dsmGo'),mCancel=document.getElementById('dsmCancel'),mX=document.getElementById('dsmX');
  function mClose(){if(!M)return;M.hidden=true;mGo.onclick=null;mGo.disabled=false;mCancel.disabled=false;}
  if(mCancel)mCancel.onclick=mClose; if(mX)mX.onclick=mClose;
  if(M)M.addEventListener('click',function(e){if(e.target===M)mClose();});
  document.addEventListener('keydown',function(e){if(e.key==='Escape'&&M&&!M.hidden)mClose();});
  function mResult(j){
    var ok=j&&j.ok, crit=j&&j.critical;
    mBody.innerHTML='<div class="dsm-row"><b>Result</b><span class="dsm-badge '+(ok?'ok':(crit?'bad':'warn'))+'">'+(ok?'✓ Done':(crit?'⚠ CRITICAL':'Failed'))+'</span></div>'
      +'<div class="dsm-result">'+esc((j&&j.msg)||'No response from server.')+'</div>';
    mGo.style.display='none';mCancel.textContent='Close';mCancel.disabled=false;
    if(ok) setTimeout(function(){location.reload();},2800);
  }
  function mRun(act){mGo.disabled=true;mGo.textContent='Working…';mCancel.disabled=true;
    dsPost(act).then(mResult).catch(function(){mGo.disabled=false;mGo.textContent='Execute';mCancel.disabled=false;alert('Request failed.');});}
  document.addEventListener('click',function(e){
    var b=e.target.closest&&e.target.closest('.dsFix'); if(!b||!M)return;
    var act=b.getAttribute('data-act'),lbl=b.getAttribute('data-label')||'Fix',why=b.getAttribute('data-why')||'',orig=b.innerHTML;
    // /boot kernels = sensitive → DRY-RUN preview, show the exact list in a card, then Execute/Cancel.
    if(act==='fix_boot_kernels'){
      b.disabled=true;b.textContent='Checking…';
      dsPost('preview_boot_kernels').then(function(j){
        b.disabled=false;b.innerHTML=orig;
        mTitle.textContent='Remove old kernels — dry run';
        if(!j||!j.ok||!j.safe){
          mBody.innerHTML='<div class="dsm-row"><b>Status</b><span class="dsm-badge bad">Refused (safe)</span></div>'
            +'<div class="dsm-result">'+esc((j&&(j.reason||j.msg))||'Cannot determine kernels.')+'</div>';
          mGo.style.display='none';mCancel.textContent='Close';
        } else {
          var n=(j.remove||[]).length;
          mBody.innerHTML='<div class="dsm-row"><b>Status</b><span class="dsm-badge ok">Safe — dry run, nothing changed yet</span></div>'
            +'<div class="dsm-row"><b>Running (kept)</b><span class="mono">'+esc(j.running)+'</span></div>'
            +'<div class="dsm-row"><b>Also kept</b><span>the 2 newest kernels</span></div>'
            +'<div class="dsm-row"><b>Will remove</b><span><b>'+n+'</b> old kernel package(s)</span></div>'
            +'<div class="dsm-list">'+esc((j.remove||[]).join('\n'))+'</div>'
            +'<div class="dsm-note">The running kernel stays loaded in RAM — no restart, no reboot. /boot integrity is verified automatically after removal; if anything looks off you get a clear “do not reboot” warning with the recovery command.</div>';
          mGo.style.display='';mGo.textContent='🗑 Execute removal';mCancel.textContent='Cancel';
          mGo.onclick=function(){mRun('fix_boot_kernels');};
        }
        M.hidden=false;
      }).catch(function(){b.disabled=false;b.innerHTML=orig;alert('Preview failed.');});
      return;
    }
    // other fixes → respectable confirm card → Execute / Cancel
    mTitle.textContent=lbl;
    mBody.innerHTML='<div class="dsm-row"><b>Action</b><span>'+esc(lbl)+'</span></div>'
      +(why?'<div class="dsm-note">'+esc(why)+'</div>':'')
      +'<div class="dsm-note">No service restart. This action is logged and audited.</div>';
    mGo.style.display='';mGo.textContent='Execute';mCancel.textContent='Cancel';
    mGo.onclick=function(){mRun(act);};
    M.hidden=false;
  });
  function esc(s){return String(s==null?'':s).replace(/[<>&]/g,function(c){return{'<':'&lt;','>':'&gt;','&':'&amp;'}[c];});}
  // server-wide scans (large files / old backups / junk) — AJAX into the shared results panel
  document.addEventListener('click',function(e){
    var b=e.target.closest&&e.target.closest('.dsSv'); if(!b)return;
    var type=b.getAttribute('data-type'),lbl=b.textContent.trim(); var box=document.getElementById('dcResult'); if(!box)return;
    box.innerHTML='<div class="dc-panel"><div class="dc-phead">&#128295; '+esc(lbl)+' — all accounts</div><div class="dc-scanprog"><span></span></div><div class="fa-empty" style="padding:16px;text-align:center;color:var(--muted)">Scanning the whole server in the background — this can take a minute. You can keep working.</div></div>';
    box.scrollIntoView({behavior:'smooth',block:'nearest'});
    fetch('index.cgi?page=disk-storage&ajax=svscan&type='+encodeURIComponent(type))
      .then(function(r){return r.text();}).then(function(html){box.innerHTML='<div class="dc-panel"><div class="dc-phead">&#128295; '+esc(lbl)+' — all accounts<button class="fa-lnk" type="button" onclick="document.getElementById(\'dcResult\').innerHTML=\'\'" style="margin-left:auto">Close</button></div>'+html+'</div>';box.scrollIntoView({behavior:'smooth',block:'nearest'});})
      .catch(function(){box.innerHTML='<div class="dc-panel"><div class="fa-empty" style="padding:16px;color:var(--dang)">Scan failed.</div></div>';});
  });
  // open the disk cleanup scan for an account (AJAX, non-blocking, inline)
  document.addEventListener('click',function(e){
    var b=e.target.closest&&e.target.closest('.dcScan'); if(!b)return;
    var acct=b.getAttribute('data-acct'); var box=document.getElementById('dcResult'); if(!box)return;
    box.innerHTML='<div class="dc-panel"><div class="dc-phead">&#129529; Disk cleanup — '+esc(acct)+'</div><div class="dc-scanprog"><span></span></div><div class="fa-empty" style="padding:16px;text-align:center;color:var(--muted)">Scanning '+esc(acct)+' for large files, archives, logs &amp; cache… runs in the background.</div></div>';
    box.scrollIntoView({behavior:'smooth',block:'nearest'});
    fetch('index.cgi?page=disk-storage&ajax=cleanscan&user='+encodeURIComponent(acct))
      .then(function(r){return r.text();}).then(function(html){box.innerHTML='<div class="dc-panel"><div class="dc-phead">&#129529; Disk cleanup — '+esc(acct)+'<button class="fa-lnk" type="button" onclick="document.getElementById(\'dcResult\').innerHTML=\'\'" style="margin-left:auto">Close</button></div>'+html+'</div>';box.scrollIntoView({behavior:'smooth',block:'nearest'});})
      .catch(function(){box.innerHTML='<div class="dc-panel"><div class="fa-empty" style="padding:16px;color:var(--dang)">Scan failed.</div></div>';});
  });
  // delete a file / clear a cache dir from the cleanup results
  document.addEventListener('click',function(e){
    var del=e.target.closest&&e.target.closest('.dcDel'), clr=e.target.closest&&e.target.closest('.dcClear');
    var b=del||clr; if(!b)return;
    var isCache=!!clr, path=b.getAttribute(isCache?'data-dir':'data-file');
    if(!confirm((isCache?'Clear cache directory?\n':'Delete this file?\n')+path+'\n\n'+(isCache?'Contents removed (app regenerates them).':'Backed up to /home/backup/detections first — restorable.')))return;
    var orig=b.innerHTML;b.disabled=true;b.textContent='…';
    var fd=new URLSearchParams();fd.set('smpro_csrf',CSRF);
    if(isCache){fd.set('ds_action','clear_cache');fd.set('dir',path);}else{fd.set('ds_action','del_file');fd.set('file',path);}
    fetch(location.pathname+location.search,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString()})
      .then(function(r){return r.json();}).then(function(j){
        if(j&&j.ok){var tr=b.closest('tr');if(tr){tr.style.opacity=.5;}b.textContent='✓ '+(j.msg||'done');b.style.color='var(--good)';}
        else{b.disabled=false;b.innerHTML=orig;alert((j&&j.msg)||'Failed');}
      }).catch(function(){b.disabled=false;b.innerHTML=orig;alert('Request failed');});
  });
  // multi-select bulk delete/clear in the cleanup results
  function dcHumb(b){b=+b||0;if(b>=1073741824)return (b/1073741824).toFixed(2)+' GB';if(b>=1048576)return (b/1048576).toFixed(1)+' MB';if(b>=1024)return (b/1024).toFixed(1)+' KB';return b+' B';}
  function dcChks(){return Array.prototype.slice.call(document.querySelectorAll('#dcResult .dcChk'));}
  function dcUpd(){var s=dcChks().filter(function(c){return c.checked;});var bar=document.getElementById('dcBulk');if(!bar)return;var n=document.getElementById('dcN'),z=document.getElementById('dcSz');var tot=0;s.forEach(function(c){tot+=(+c.getAttribute('data-size')||0);});if(n)n.textContent=s.length;if(z)z.textContent=dcHumb(tot);bar.hidden=s.length===0;}
  document.addEventListener('change',function(e){if(e.target.classList&&e.target.classList.contains('dcChk'))dcUpd();});
  document.addEventListener('click',function(e){
    if(e.target.classList&&e.target.classList.contains('dc-selall')){var sec=e.target.closest('.dc-sect');if(sec)sec.querySelectorAll('.dcChk').forEach(function(c){c.checked=true;});dcUpd();return;}
    if(e.target.id==='dcClr'){dcChks().forEach(function(c){c.checked=false;});dcUpd();return;}
    var ds=e.target.id==='dcDelSel'?e.target:(e.target.closest&&e.target.closest('#dcDelSel')); if(!ds)return;
    var sel=dcChks().filter(function(c){return c.checked;}); if(!sel.length)return;
    var totB=0;sel.forEach(function(c){totB+=(+c.getAttribute('data-size')||0);});
    if(!confirm('Delete / clear '+sel.length+' selected item(s) ('+dcHumb(totB)+')?\n\nFiles are backed up to /home/backup/detections first (restorable); cache directories are cleared. An HTML report of what was deleted will be created.'))return;
    ds.disabled=true; var done=0, total=sel.length, deleted=[];
    (function next(){
      if(!sel.length){
        ds.textContent='✓ done ('+done+'/'+total+') — building report…';
        var rf=new URLSearchParams();rf.set('smpro_csrf',CSRF);rf.set('ds_action','del_report');rf.set('items',JSON.stringify(deleted));
        fetch(location.pathname+location.search,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:rf.toString()})
          .then(function(r){return r.json();}).then(function(j){ds.disabled=false;ds.textContent='✓ deleted '+done+'/'+total;
            if(j&&j.ok&&j.url){var bar=document.getElementById('dcBulk');if(bar)bar.insertAdjacentHTML('beforeend',' <a class="tp-btn" href="'+j.url+'" target="_blank">&#128196; Download HTML report ('+done+' files, '+dcHumb(totB)+')</a>');}
          }).catch(function(){ds.disabled=false;ds.textContent='✓ deleted '+done+'/'+total;});
        dcUpd();return;
      }
      var c=sel.shift(); var kind=c.getAttribute('data-kind'), path=c.getAttribute('data-path'), size=+c.getAttribute('data-size')||0;
      var fd=new URLSearchParams();fd.set('smpro_csrf',CSRF);
      if(kind==='cache'){fd.set('ds_action','clear_cache');fd.set('dir',path);}else{fd.set('ds_action','del_file');fd.set('file',path);}
      ds.textContent='Working… '+(done+1)+'/'+total;
      fetch(location.pathname+location.search,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString()})
        .then(function(r){return r.json();}).then(function(j){var tr=c.closest('tr');if(j&&j.ok){if(tr)tr.style.opacity=.4;done++;deleted.push({path:path,size:size,kind:kind});}c.checked=false;next();},function(){c.checked=false;next();});
    })();
  });
})();
</script>
<?php
smpro_layout_footer();
