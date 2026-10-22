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
    // Offer to DOUBLE /tmp only when its backing is actually resizable (tmpfs or a cPanel loopback) — a plain /tmp dir is refused.
    // Only probe the backing (~15 findmnt/losetup/df/cagefsctl spawns) when /tmp is actually near-full — it's unused otherwise.
    $tmpBack = ($tmp && $tmp['pct'] >= 85 && function_exists('smpro_ds_tmp_detect')) ? (smpro_ds_tmp_detect()['backing'] ?? 'unknown') : 'unknown';
    if ($tmp && $tmp['pct'] >= 85 && in_array($tmpBack, ['loop','tmpfs'], true)) $c[] = ['label'=>'/tmp is ' . $tmp['pct'] . '% full — its capacity can be doubled', 'sev'=>$tmp['pct']>=95?'danger':'warn', 'fix'=>'tmp_expand', 'fixlabel'=>'Expand /tmp (double capacity)', 'why'=>'Doubles the /tmp backing: a tmpfs is resized instantly; a cPanel loopback is rebuilt at 2× with contents preserved and automatic rollback (/tmp is guaranteed to stay mounted).'];
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

/* smpro_ds_wrap() / smpro_ds_humb() / smpro_ds_cleanscan() moved to includes/disk_scan.php so the detached
 * background scan worker (bin/cleanscan.php) can load them without executing this page. */
function smpro_ds_safe_target($f, $kind) {
    // files must live under a real /home/<account>/ tree; cache dirs limited to known cache paths
    // cache dirs must ALSO live under /home/<account>/ (the old loose '#/cache(/|$)#' fallback allowed
    // e.g. /etc/cache); allow a cache/views/tmp dir at any depth (incl. first segment) + block traversal.
    if ($kind === 'cache') return (bool)preg_match('#^/home/[^/]+/(.+/)?(cache|views|bootstrap/cache|\.cache|tmp)(/.*)?$#', $f) && strpos($f, '/..') === false;
    return (bool)preg_match('#^/home/[^/]+/.+#', $f) && strpos($f, '/..') === false;
}
function smpro_ds_rep_dir() { $d = SMPRO_VARLIB . '/reports/disk_deletions'; @is_dir($d) || @mkdir($d, 0700, true); return $d; }
/** Standalone HTML deletion report (served as a downloadable .html by index.cgi). */
function smpro_ds_report_html($rep) {
    $h = fn($s) => htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $items = is_array($rep['items'] ?? null) ? $rep['items'] : [];
    $total = 0; foreach ($items as $it) $total += (int)($it['size'] ?? 0);
    echo "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><title>Disk deletion report " . $h($rep['id'] ?? '') . "</title><style>"
       . "*{box-sizing:border-box}body{font:13px/1.5 -apple-system,Segoe UI,Arial,sans-serif;color:#1f2733;margin:0;padding:28px;background:var(--card)}"
       . "h1{font-size:20px;margin:0 0 4px}.muted{color:#6b7686;font-size:12px;margin:0 0 16px}"
       . ".cards{display:flex;gap:10px;flex-wrap:wrap;margin:0 0 18px}.c{border:1px solid #e6eaf1;border-radius:10px;padding:10px 14px;min-width:130px}.c .l{font-size:10px;text-transform:uppercase;color:#6b7686}.c .v{font-size:20px;font-weight:700}"
       . "table{width:100%;border-collapse:collapse;font-size:12px}th,td{border:1px solid #e6eaf1;padding:6px 8px;text-align:left;vertical-align:top;word-break:break-all}th{background:var(--bg);font-size:10px;text-transform:uppercase;color:#475569}"
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
    // Renders the report from the SAVED background-job result. The scan itself runs in bin/cleanscan.php so it
    // finishes even if this page is closed — this endpoint never scans inline.
    $acct = preg_replace('/[^a-zA-Z0-9._-]/', '', (string)($_GET['user'] ?? ''));
    $job  = smpro_ds_scan_read($acct);
    if (!$job)                     { echo '<div class="fa-empty">No scan has been run for this account yet.</div>'; exit; }
    if (!empty($job['cancelled'])) { echo '<div class="fa-empty">This scan was cancelled.</div>'; exit; }
    if (empty($job['done']))       { echo '<div class="fa-empty">Still scanning in the background — it will finish even if you close this page.</div>'; exit; }
    if (($job['phase'] ?? '') === 'error') { echo '<div class="fa-empty">' . smpro_h((string)($job['msg'] ?? 'Scan failed.')) . '</div>'; exit; }
    $sc = is_array($job['result'] ?? null) ? $job['result'] : ['err'=>'No result stored.'];
    if (!empty($sc['err'])) { echo '<div class="fa-empty">' . smpro_h($sc['err']) . '</div>'; exit; }
    $fin = (int)($job['finished_at'] ?? 0);
    if ($fin) echo '<div class="dc-note">Scanned ' . smpro_h(date('Y-m-d H:i', $fin)) . ' — produced in the background and kept for you.</div>';
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
    // INODE-HOG scan (read-only): which /home directories consume the most inodes. Visibility only —
    // NO checkboxes / delete buttons / bulk bar. Bounded + nice'd via smpro_ds_wrap, like the file scans.
    if ($type === 'inodes') {
        $cmd = smpro_ds_wrap("du --inodes -x /home --max-depth=4 2>/dev/null | sort -rn | head -40", 200);
        $rows = [];
        foreach (explode("\n", (string)@shell_exec($cmd)) as $l) {
            if (trim($l) === '') continue;
            $p = explode("\t", $l, 2); if (count($p) < 2) continue;
            $rows[] = ['inodes'=>(int)$p[0], 'dir'=>$p[1]];
        }
        smpro_audit('disk_svscan', ['type'=>'inodes','hits'=>count($rows)]);
        echo '<div class="dc-note">Read-only inode scan of <span class="mono">/home</span> (depth 4). Inode exhaustion is caused by many small files (often mail, cache or session directories), not by size — a filesystem can be at 100% inodes with free space left. Nothing here is deletable; use it to locate the account/directory to clean up.</div>';
        echo '<div class="dc-sect"><div class="dc-stt">Top directories by inode count (/home) <span class="b good">read-only</span> <span class="meta">(' . count($rows) . ')</span></div>';
        if (!$rows) echo '<div class="fa-empty" style="color:var(--good);padding:14px">&#10003; None found.</div>';
        else {
            echo '<table class="smpro-table"><thead><tr><th class="num">Inodes</th><th>Account</th><th>Directory</th></tr></thead><tbody>';
            foreach ($rows as $it) {
                $acct = preg_match('#^/home/([^/]+)#', $it['dir'], $mm) ? $mm[1] : '';
                echo '<tr><td class="num mono">' . number_format($it['inodes']) . '</td>'
                   . '<td class="mono">' . ($acct !== '' ? smpro_h($acct) : '<span class="meta">&mdash;</span>') . '</td>'
                   . '<td class="mono fa-file">' . smpro_h($it['dir']) . '</td></tr>';
            }
            echo '</tbody></table>';
        }
        echo '</div>';
        exit;
    }
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
        // Serialize with swap_expand/swap_remove on the SAME lock so a concurrent swapoff -a here can't drop a
        // freshly-activated managed swapfile mid-verification (the maintenance backend takes this lock too).
        $ld = smpro_mnt_locks_dir(); $lf = @fopen($ld . '/swap.lock', 'c');
        if (!$lf || !@flock($lf, LOCK_EX | LOCK_NB)) { if ($lf) @fclose($lf); $r = ['ok'=>false,'msg'=>'A swap operation is already in progress. Try again shortly.']; }
        else {
            @chmod($ld . '/swap.lock', 0600);
            $m = smpro_ds_mem();
            if ($m['mem_avail'] < $m['swap_used'] * 1.5 || $m['mem_avail_pct'] < 25) $r = ['ok'=>false,'msg'=>'Refused: cycling swap needs free RAM ≥ 1.5× swap-in-use AND ≥25% RAM free, to rule out any OOM risk on production. Not met now.'];
            else {
                $off = (string)@shell_exec('timeout 180 /usr/sbin/swapoff -a 2>&1');
                $on  = (string)@shell_exec('timeout 120 /usr/sbin/swapon -a 2>&1');
                // swapon -a restores ONLY fstab entries; re-assert a managed swapfile that is live-but-not-persisted
                // (smpro_swap_create leaves meta state='active',fstab=false when fstab_add fails), else swapoff -a
                // just dropped it permanently and the UI/meta would disagree with /proc/swaps.
                if (function_exists('smpro_swap_meta_read')) {
                    $meta = smpro_swap_meta_read(); $mp = (string)($meta['path'] ?? '');
                    if ($mp !== '' && ($meta['state'] ?? '') === 'active' && empty($meta['fstab'])) {
                        $sact = function_exists('smpro_swap_active') ? smpro_swap_active() : [];
                        if (!isset($sact[$mp]) && @file_exists($mp)) {
                            $swb = (function_exists('smpro_swap_bin') && smpro_swap_bin('swapon') !== '') ? smpro_swap_bin('swapon') : '/usr/sbin/swapon';
                            @shell_exec('timeout 30 ' . $swb . ' ' . escapeshellarg($mp) . ' 2>&1');
                        }
                    }
                }
                $a = smpro_ds_mem();
                $ok = stripos($on, 'error') === false;
                $r = ['ok'=>$ok,'msg'=>$ok ? ('Swap cycled safely. Swap usage now ' . $a['swap_used_pct'] . '%.') : ('swapon issue: ' . trim($on))];
            }
            @flock($lf, LOCK_UN); @fclose($lf);   // keep the lock FILE (never unlink the inode)
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
    } elseif ($act === 'preview_var_logs' || $act === 'preview_tmp_cache') {
        // READ-ONLY dry runs so the "Trim logs" / "/tmp cache" buttons can say exactly how many files and how
        // many bytes they would delete BEFORE the admin commits (these deletions are permanent).
        $n = 0; $bytes = 0;
        if ($act === 'preview_tmp_cache') {
            $out = (string)@shell_exec("timeout 60 nice -n 19 find /tmp -maxdepth 3 -type f -atime +3 -not -name 'sess_*' -not -name 'cpsess*' -not -name '*.sock' -not -name '.s.*' -not -name '*.lock' -not -ipath '*cpanel*' -not -ipath '*mysql*' -printf '%s\\n' 2>/dev/null");
            $what = 'regular /tmp files older than 3 days (sessions, sockets and locks are preserved)';
        } else {
            $out = (string)@shell_exec("timeout 60 nice -n 19 find /var/log -type f \\( -name '*.gz' -o -name '*.xz' -o -name '*.old' -o -name '*.1' -o -name '*.2' -o -name '*.3' -o -name '*.4' -o -name '*.5' -o -name '*.6' -o -name '*.7' \\) -mtime +14 -printf '%s\\n' 2>/dev/null");
            $what = 'rotated/compressed log files older than 14 days (active logs are never touched)';
        }
        foreach (explode("\n", $out) as $l) { $l = trim($l); if ($l !== '' && ctype_digit($l)) { $bytes += (int)$l; $n++; } }
        $extra = '';
        if ($act === 'preview_var_logs') {
            $ju = trim((string)@shell_exec('timeout 20 journalctl --disk-usage 2>/dev/null'));
            if ($ju !== '') $extra = $ju;
        }
        $r = ['ok'=>true,'preview'=>1,'files'=>$n,'bytes'=>$bytes,'human'=>smpro_ds_home_h($bytes),'what'=>$what,'journal'=>$extra];
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
                // Purge EXACTLY the kernel packages the preview listed (parse each "Remv <pkg> …" line) —
                // a blanket `apt-get autoremove` would remove every autoremovable package, not just the
                // kernels the admin saw and confirmed.
                $pkgs = [];
                foreach ((array)$p['remove'] as $l) { if (preg_match('/^Remv\s+(\S+)/', (string)$l, $mm)) $pkgs[] = $mm[1]; }
                $out = $pkgs
                    ? (string)@shell_exec('timeout 300 apt-get -y --purge remove ' . implode(' ', array_map('escapeshellarg', $pkgs)) . ' 2>&1')
                    : 'Nothing matched the confirmed kernel list.';
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
        $acct = preg_match('#^/home/([^/]+)/#',$f,$m) ? $m[1] : '';
        // SECURITY: also reject a symlink / a path resolving outside the account (copy() would leak the target).
        $safe = ($acct !== '' && function_exists('smpro_path_safe')) ? smpro_path_safe($f, [smpro_user_home($acct)]) : '';
        if (!smpro_ds_safe_target($f, 'file') || !is_file($f) || $safe === '') $r = ['ok'=>false,'msg'=>'Refused: only an existing real file under /home/<account>/ (no symlinks).'];
        else {
            $f = $safe;
            $bdir = '/home/backup/detections/' . $acct; @is_dir($bdir) || @mkdir($bdir, 0700, true);
            $bak = $bdir . '/' . date('Ymd_His') . '_' . preg_replace('/[^a-zA-Z0-9._-]/','_',basename($f));
            // Prefer rename (same filesystem → instant, needs NO extra space) — copy-then-unlink doubles the
            // file's footprint first and fails on the ≥95%-full disk this tool exists to rescue. Fall back to
            // copy for a cross-filesystem backup dir.
            $moved = @rename($f, $bak) || (@copy($f, $bak) && @unlink($f));
            if ($moved) { @chmod($bak,0600); $r = ['ok'=>true,'msg'=>'Deleted (backed up → ' . basename($bak) . ', restorable).']; }
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
    } elseif ($act === 'preview_swap_expand') {
        $tm = (int)($_POST['target_mb'] ?? 0);
        $p = smpro_swap_plan($tm > 0 ? ['target_mb' => $tm] : []);
        $r = ['ok'=>true,'preview'=>1,'safe'=>$p['safe'],'reason'=>$p['reason'],'path'=>$p['path'],'virt'=>smpro_swap_virt(),
              'resize'=>!empty($p['resize']),'old_size_h'=>($p['old_size_h'] ?? ''),
              'ram_h'=>$p['ram_h'],'cur_swap_h'=>$p['cur_swap_h'],'add_h'=>$p['add_h'],'new_total_h'=>$p['new_total_h'],
              'fstype'=>$p['fstype'],'avail_h'=>$p['avail_h'],
              // recommendation + limits so the modal can show them (were missing → modal showed "min · max · Auto" blank)
              'min_rec_h'=>($p['min_rec_h'] ?? ''),'max_rec_h'=>($p['max_rec_h'] ?? ''),'auto_h'=>($p['auto_h'] ?? ''),
              'auto_mib'=>($p['auto_mib'] ?? 0),'room_h'=>($p['room_h'] ?? ''),'room_mib'=>($p['room_mib'] ?? 0),
              'cap_h'=>($p['cap_h'] ?? ''),'clamped'=>!empty($p['clamped']),'requested_mib'=>($p['requested_mib'] ?? 0),
              'msg'=>$p['safe']
                    ? (!empty($p['resize'])
                        ? ('Would resize the managed swapfile ' . $p['old_size_h'] . ' → ' . $p['add_h'] . ' at ' . $p['path'] . ' — new swap total ' . $p['new_total_h'] . '.')
                        : ('Would add ' . $p['add_h'] . ' swap at ' . $p['path'] . ' (' . $p['fstype'] . ', ' . $p['method'] . ') — new total ' . $p['new_total_h'] . '.'))
                    : ('Refused: ' . $p['reason'])];
    } elseif ($act === 'swap_expand') {
        $tm = (int)($_POST['target_mb'] ?? 0);
        $p = smpro_swap_plan($tm > 0 ? ['target_mb' => $tm] : []);
        $r = $p['safe'] ? smpro_swap_create($p) : ['ok'=>false,'msg'=>'Refused: ' . $p['reason']];
    } elseif ($act === 'swap_remove') {
        $r = smpro_swap_remove((string)($_POST['path'] ?? SMPRO_SWAP_PATH));
    } elseif ($act === 'autopurge_save') {
        $r = smpro_mnt_act_save();
    } elseif ($act === 'autopurge_preview') {
        $r = smpro_mnt_act_preview();
    } elseif ($act === 'autopurge_run_now') {
        $r = smpro_mnt_act_run_now();
    } elseif ($act === 'swapcycle_save') {
        $ok = smpro_swapcycle_cfg_save([
            'enabled'   => !empty($_POST['sc_enabled']) && $_POST['sc_enabled'] !== '0',
            'threshold' => (int)($_POST['sc_threshold'] ?? 80),
        ]);
        $st = smpro_swapcycle_status();
        $r = ['ok' => $ok, 'msg' => $ok ? ($st['enabled'] ? ('Auto swap-cycle ON — will drain swap when usage crosses ' . $st['threshold'] . '%.') : 'Auto swap-cycle turned off.') : 'Could not save.', 'status' => $st];
    } elseif ($act === 'swapcycle_status') {
        $r = ['ok' => true, 'status' => smpro_swapcycle_status()];
    } elseif (in_array($act, ['preview_tmp_expand','tmp_expand','tmp_expand_status'], true)) {
        $r = smpro_ds_tmp_dispatch($act);   // read-only preview/status; tmp_expand launches the detached worker
    } elseif ($act === 'cleanscan_start' && function_exists('smpro_ds_scan_launch')) {
        $r = smpro_ds_scan_launch((string)($_POST['acct'] ?? ''));
    } elseif ($act === 'cleanscan_cancel' && function_exists('smpro_ds_scan_cancel')) {
        $r = smpro_ds_scan_cancel((string)($_POST['acct'] ?? ''));   // explicit admin cancel — the ONLY thing that stops a started scan
    } elseif ($act === 'cleanscan_forget' && function_exists('smpro_ds_scan_forget')) {
        $r = smpro_ds_scan_forget((string)($_POST['acct'] ?? ''));
    } elseif ($act === 'cleanscan_status' && function_exists('smpro_ds_scan_read')) {
        $j = smpro_ds_scan_read((string)($_POST['acct'] ?? ''));
        $r = ['ok'=>true, 'exists'=>!empty($j), 'phase'=>(string)($j['phase'] ?? 'idle'), 'done'=>!empty($j['done']),
              'cancelled'=>!empty($j['cancelled']), 'msg'=>(string)($j['msg'] ?? ''), 'account'=>(string)($j['account'] ?? ''),
              'started_at'=>(int)($j['started_at'] ?? 0), 'finished_at'=>(int)($j['finished_at'] ?? 0),
              'counts'=>$j['counts'] ?? null, 'reclaimable'=>(int)($j['reclaimable'] ?? 0),
              'stale'=>empty($j['done']) && !empty($j['heartbeat']) && (time()-(int)$j['heartbeat'])>900];
    } elseif (in_array($act, ['home_roots','preview_home_move','home_move','home_move_status','home_move_verify','home_move_finalize','home_move_rollback','home_capacity','home_batch_start','home_batch_cancel','home_batch_status','home_batch_clear'], true) && function_exists('smpro_ds_home_dispatch')) {
        $r = smpro_ds_home_dispatch($act);   // move an account's home dir to another partition (detached worker in bin/home_move.php)
    } elseif ($act === 'bench_start' && function_exists('smpro_bm_start')) {
        $r = smpro_bm_start((string)($_POST['mount'] ?? ''));   // launches the detached hardware-benchmark worker
    }
    if (!isset($r['msg'])) $r['msg'] = '';
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
/* live disk I/O + temperature helpers now live in includes/diskio.php (boot-loaded) so the index.php
 * `format=json&metric=diskio` live endpoint — the same mechanism the dashboard uses — can call them. */

/** Render the Disk I/O performance card — LIVE (polls itself, no page refresh) + read/write speed + busy% + temperature. */
function smpro_ds_diskio_card_html(array $io): string {
    $h = fn($s) => function_exists('smpro_h') ? smpro_h($s) : htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');
    $mb = fn($k) => $k >= 1024 ? number_format($k / 1024, 1) . ' MB/s' : number_format($k, 0) . ' KB/s';
    $pl = smpro_ds_diskio_payload($io, false);   // cache-only temps → page render never blocks on smartctl; live poll refreshes
    $devs = $pl['devices']; $worst = $pl['worst']; $hasTemp = true;   // always show the Temp column (values fill in on the first live poll)
    $accent = $worst === 'danger' ? 'var(--dang)' : ($worst === 'warn' ? '#c2710c' : 'var(--good)');
    $verdict = $worst === 'danger'
        ? '&#128308; A disk is saturated (≥85% busy) — this is a real bottleneck slowing sites &amp; queries right now.'
        : ($worst === 'warn' ? '&#128992; Disk load is above medium (60–85% busy) — watch it; sustained means it will start slowing responses.'
                             : '&#128994; Disk I/O is healthy — no disk is a bottleneck.');
    ob_start(); ?>
<div class="card ds-io-card" id="dsIoCard" style="padding:0;overflow:hidden;margin:14px 0;border-top:3px solid <?= $accent ?>">
  <div class="ds-head"><span class="ds-hic">&#9889;</span><b>Disk I/O — read / write speed &amp; load</b><span class="meta">live · updates every 5s, no refresh · busy% = the real performance signal<?= $hasTemp ? ' · °C from SMART' : '' ?></span><span class="ds-io-live" id="dsIoLive">&#9679; live</span></div>
  <div style="padding:12px 16px">
    <div class="ds-io-verdict <?= $h($worst) ?>" id="dsIoVerdict"><?= $verdict ?></div>
    <?php if (!$devs): ?>
      <p class="meta" style="margin:10px 0 0">Per-disk I/O counters aren't exposed on this host (container without /proc/diskstats).</p>
    <?php else: ?>
    <div class="ds-io-tw"><table class="smpro-table"><thead><tr><th>Disk</th><th class="num">Read</th><th class="num">Write</th><th class="num">IOPS (r/w)</th><th>Busy % (impact on performance)</th><th class="num">Temp</th></tr></thead><tbody id="dsIoBody">
      <?php foreach ($devs as $d): $c = $d['tier']==='danger'?'red':($d['tier']==='warn'?'orange':'good');
            $tc = $d['temp_tier']==='danger'?'red':($d['temp_tier']==='warn'?'orange':'good'); ?>
      <tr>
        <td class="mono"><b><?= $h($d['dev']) ?></b><?= preg_match('/^md/', $d['dev']) ? ' <span class="meta">RAID</span>' : '' ?></td>
        <td class="num mono"><?= $mb($d['r_kbs']) ?></td>
        <td class="num mono"><?= $mb($d['w_kbs']) ?></td>
        <td class="num mono"><?= round($d['r_iops']) ?> / <?= round($d['w_iops']) ?></td>
        <td><div class="ds-bar"><span class="<?= $c ?>" style="width:<?= min(100,$d['util']) ?>%"></span></div><span class="b <?= $c ?>"><?= $d['util'] ?>%</span></td>
        <td class="num mono"><?= $d['temp']!==null ? '<span class="b '.$tc.'">'.(int)$d['temp'].'°C</span>' : '<span class="meta">—</span>' ?></td>
      </tr>
      <?php endforeach; ?>
    </tbody></table></div>
    <div class="ds-io-legend"><span class="b good">&lt;60% normal</span> <span class="b orange">60–85% above medium</span> <span class="b red">≥85% danger</span> &middot; “Busy %” = share of time the disk was actively serving I/O — near 100% means requests are queuing (slow sites), regardless of the MB/s number.<?= $hasTemp ? ' Temp: <span class="b good">&lt;50°C</span> <span class="b orange">50–60</span> <span class="b red">≥60</span>.' : ' (Install <span class="mono">smartmontools</span> to show disk temperatures.)' ?></div>
    <?php endif; ?>
  </div>
</div>
<script>(function(){
  var card=document.getElementById('dsIoCard'); if(!card||window.__dsIoLive) return; window.__dsIoLive=1;
  function esc(s){var d=document.createElement('div');d.textContent=(s==null?'':String(s));return d.innerHTML;}
  function mb(k){return k>=1024?(k/1024).toFixed(1)+' MB/s':Math.round(k)+' KB/s';}
  function tier(t){return t==='danger'?'red':(t==='warn'?'orange':'good');}
  function verdict(w){return w==='danger'?'\u{1F534} A disk is saturated (≥85% busy) — a real bottleneck slowing sites &amp; queries right now.'
    :(w==='warn'?'\u{1F7E0} Disk load is above medium (60–85% busy) — watch it.':'\u{1F7E2} Disk I/O is healthy — no disk is a bottleneck.');}
  function render(j){
    var b=document.getElementById('dsIoBody'); if(!b||!j||!j.devices)return;
    var html='';
    j.devices.forEach(function(d){
      var c=tier(d.tier), tc=tier(d.temp_tier);
      html+='<tr><td class="mono"><b>'+esc(d.dev)+'</b>'+(/^md/.test(d.dev)?' <span class="meta">RAID</span>':'')+'</td>'
        +'<td class="num mono">'+mb(d.r_kbs)+'</td><td class="num mono">'+mb(d.w_kbs)+'</td>'
        +'<td class="num mono">'+Math.round(d.r_iops)+' / '+Math.round(d.w_iops)+'</td>'
        +'<td><div class="ds-bar"><span class="'+c+'" style="width:'+Math.min(100,d.util)+'%"></span></div><span class="b '+c+'">'+d.util+'%</span></td>'
        +'<td class="num mono">'+(d.temp!=null?'<span class="b '+tc+'">'+d.temp+'°C</span>':'<span class="meta">—</span>')+'</td></tr>';
    });
    b.innerHTML=html;
    var v=document.getElementById('dsIoVerdict'); if(v){v.className='ds-io-verdict '+j.worst;v.innerHTML=verdict(j.worst);}
    var ac=j.worst==='danger'?'var(--dang)':(j.worst==='warn'?'#c2710c':'var(--good)'); card.style.borderTopColor=ac;
  }
  function tick(){ if(document.hidden)return;
    fetch('index.cgi?page=disk-storage&format=json&metric=diskio',{cache:'no-store'}).then(function(r){return r.json();}).then(function(j){if(j&&j.ok)render(j);
      var l=document.getElementById('dsIoLive');if(l)l.style.opacity=1;}).catch(function(){var l=document.getElementById('dsIoLive');if(l)l.style.opacity=.3;});
  }
  setInterval(tick,5000);
  document.addEventListener('visibilitychange',function(){if(!document.hidden)tick();});
})();</script>
<?php
    return (string)ob_get_clean();
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

// Self-heal any broken/half-made managed swapfile BEFORE reading swap state, so the dashboard + tools only ever
// reflect real, active swap (never a lingering inactive /swapfile-smpro). Guarded + non-blocking; page render only.
if (function_exists('smpro_swap_reconcile')) { try { smpro_swap_reconcile(); } catch (\Throwable $e) { if (function_exists('smpro_soft_fail')) smpro_soft_fail(basename(__FILE__) . ':' . __LINE__, $e); } }
$fs = smpro_ds_filesystems();
$inodes = smpro_ds_inodes();
// Keep the two heaviest probes OFF the render path: the disk-I/O card has a 0.8s sample and the per-account
// table runs `whmapi1 listaccts` (grows to seconds/tens-of-seconds with account count — the forbidden render
// probe). Both are cached; the disk-I/O card self-polls its live endpoint, and a "Refresh" reloads the page.
$diskio = smpro_cache_through('ds_diskio', 30, fn() => smpro_ds_diskio());   // live read/write speed + busy% per disk (short sample)
$accts = smpro_cache_through('ds_accounts', 120, fn() => smpro_ds_accounts());
$hmRoots = function_exists('smpro_ds_home_roots') ? smpro_cache_through('ds_home_roots', 60, fn() => smpro_ds_home_roots()) : [];
$hmPendAll = function_exists('smpro_ds_home_pending_all') ? smpro_ds_home_pending_all() : [];   // a batch can leave SEVERAL accounts awaiting reclaim/rollback
$hmPending = $hmPendAll[0] ?? [];
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

<?php
  // Health tier for a percentage → drives the stat-card accent + number colour.
  $tier = function($p){ if ($p===null) return 'ok'; if ($p>=90) return 'danger'; if ($p>=85) return 'warn'; if ($p>=60) return 'info'; return 'ok'; };
  $rootPct = $root['pct'] ?? null; $homePct = $home['pct'] ?? null; $nearN = count($fullMounts)+count($nearLimit);
  $overall = ($fullMounts) ? 'danger' : (($nearLimit || ($homePct!==null && $homePct>=85) || ($rootPct!==null && $rootPct>=85)) ? 'warn' : 'ok');
?>
<div class="ds-stats">
  <div class="ds-stat <?= $tier($rootPct) ?>">
    <div class="ds-stat-ic">&#128190;</div>
    <div class="ds-stat-b">
      <div class="ds-stat-n"><?= $root?smpro_h($root['used']):'—' ?><?= $rootPct!==null?' <small>'.$rootPct.'%</small>':'' ?></div>
      <div class="ds-stat-l">Root disk used</div>
      <div class="ds-stat-s"><?= $root?('of '.smpro_h($root['size']).' &middot; '.smpro_h($root['avail']).' free'):'—' ?></div>
    </div>
  </div>
  <div class="ds-stat <?= $tier($homePct) ?>">
    <div class="ds-stat-ic">&#127968;</div>
    <div class="ds-stat-b">
      <div class="ds-stat-n"><?= $home?smpro_h($home['pct']).'%':'—' ?></div>
      <div class="ds-stat-l">/home usage</div>
      <div class="ds-stat-s"><?= $home?(smpro_h($home['used']).' of '.smpro_h($home['size']).' &middot; '.smpro_h($home['avail']).' free'):'no separate /home' ?></div>
    </div>
  </div>
  <div class="ds-stat info">
    <div class="ds-stat-ic">&#128101;</div>
    <div class="ds-stat-b">
      <div class="ds-stat-n"><?= count($accts) ?></div>
      <div class="ds-stat-l">Hosted accounts</div>
      <div class="ds-stat-s"><?= $nearLimit?count($nearLimit).' near their quota':'all within quota' ?></div>
    </div>
  </div>
  <div class="ds-stat <?= $nearN?'danger':'ok' ?>">
    <div class="ds-stat-ic"><?= $nearN?'&#9888;':'&#10003;' ?></div>
    <div class="ds-stat-b">
      <div class="ds-stat-n"><?= $nearN ?></div>
      <div class="ds-stat-l">Near-full (&ge;85%)</div>
      <div class="ds-stat-s"><?= $nearN?(count($fullMounts).' mount(s) &middot; '.count($nearLimit).' account(s)'):'nothing at risk' ?></div>
    </div>
  </div>
</div>

<?php
// ---- page-level overview (the RAM / swap / tmp tiles used to live inside the Admin Disk Tools card) — every tile jumps to its section
$tmpfs=null; foreach($fs as $r) if($r['mount']==='/tmp')$tmpfs=$r;
$dsOvFull = null; foreach ($fs as $r) if ($dsOvFull === null || $r['pct'] > $dsOvFull['pct']) $dsOvFull = $r;
$dsOvIo = function_exists('smpro_ds_diskio_payload') ? (string)(smpro_ds_diskio_payload($diskio, false)['worst'] ?? '') : '';   // same cache-only read the I/O card does
$dsOv = [
  ['id' => 'ds-tools', 'l' => 'RAM available', 'v' => $mem['mem_avail_pct'] . '%', 'cls' => $mem['mem_avail_pct'] < 10 ? 'dang' : ($mem['mem_avail_pct'] < 20 ? 'warn' : 'good'), 's' => smpro_ds_h($mem['mem_avail']/1024) . ' free'],
  ['id' => 'ds-tools', 'l' => 'Swap used', 'v' => $mem['swap_total'] ? $mem['swap_used_pct'] . '%' : 'none', 'cls' => $mem['swap_total'] ? ($mem['swap_used_pct'] >= 50 ? 'dang' : 'good') : 'muted', 's' => $mem['swap_total'] ? ('of ' . smpro_ds_h($mem['swap_total']/1024)) : 'no swap configured'],
  ['id' => 'ds-tools', 'l' => '/tmp used', 'v' => $tmpfs ? $tmpfs['pct'] . '%' : '—', 'cls' => ($tmpfs && $tmpfs['pct'] >= 85) ? 'dang' : ($tmpfs ? 'good' : 'muted'), 's' => $tmpfs ? ('of ' . $tmpfs['size']) : 'no separate /tmp'],
  ['id' => 'dsIoCard', 'l' => 'Disk I/O', 'v' => $dsOvIo === 'danger' ? 'Saturated' : ($dsOvIo === 'warn' ? 'Busy' : ($dsOvIo !== '' ? 'Healthy' : '—')), 'cls' => $dsOvIo === 'danger' ? 'dang' : ($dsOvIo === 'warn' ? 'warn' : ($dsOvIo !== '' ? 'good' : 'muted')), 's' => 'live busy% per disk · updates every 5s'],
  ['id' => 'ds-fs', 'l' => 'Fullest filesystem', 'v' => $dsOvFull ? $dsOvFull['pct'] . '%' : '—', 'cls' => $dsOvFull ? ($dsOvFull['pct'] >= 90 ? 'dang' : ($dsOvFull['pct'] >= 85 ? 'warn' : 'good')) : 'muted', 's' => $dsOvFull ? ($dsOvFull['mount'] . ' · ' . count($fs) . ' mount(s)') : 'no mounts read'],
  ['id' => 'ds-accts', 'l' => 'Accounts near quota', 'v' => (string)count($nearLimit), 'cls' => count($nearLimit) ? 'dang' : 'good', 's' => count($accts) . ' hosted · ≥85% of quota'],
];
$dsOvNav = [['ds-tools', '&#128295; Disk tools'], ['dsIoCard', '&#9889; Disk I/O'], ['ds-auto', '&#129302; Automation'], ['ds-fs', '&#128190; Filesystems'], ['ds-accts', '&#128101; Top accounts'], ['hmCard', '&#128230; Move account'], ['dcResult', '&#128269; Scan results']];
?>
<div class="fw-kpis">
  <?php foreach ($dsOv as $k): ?>
  <a class="fw-kpi <?= $k['cls'] ?>" href="#<?= $k['id'] ?>" data-go="<?= $k['id'] ?>"><div class="l"><?= $k['l'] ?></div><div class="v"><?= smpro_h($k['v']) ?></div><div class="s"><?= smpro_h($k['s']) ?></div></a>
  <?php endforeach; ?>
</div>
<nav class="fw-nav" id="dsNav"><?php foreach ($dsOvNav as [$id, $lbl]): ?><a href="#<?= $id ?>" data-go="<?= $id ?>"><?= $lbl ?></a><?php endforeach; ?><span class="sp"></span><button type="button" class="fw-navx" id="dsOpenAll">expand all</button><button type="button" class="fw-navx" id="dsCloseAll">collapse all</button></nav>

<!-- ===== Interactive Admin Disk Tools ===== -->
<div class="card" id="ds-tools" style="padding:0;overflow:hidden;margin:14px 0;border-top:3px solid <?= $checks?'var(--dang)':'var(--good)' ?>">
  <div class="ds-head"><b>&#128295; Interactive Admin Disk Tools</b><span class="meta">RAM, swap, /tmp &amp; partition health — one-click fixes</span></div>
  <div style="padding:14px 16px">
    <div class="ds-svtools">
      <span class="ds-svlbl">Server-wide scans:</span>
      <button class="tp-btn dsSv" type="button" data-type="large">&#128269; Large files (≥500 MB)</button>
      <button class="tp-btn dsSv" type="button" data-type="oldbak">&#128230; Old backups &amp; archives (&gt;30 d)</button>
      <button class="tp-btn dsSv" type="button" data-type="junk">&#129529; Safe junk / cache (&gt;2 d)</button>
    </div>
    <div class="ds-svtools">
      <span class="ds-svlbl">Maintenance / cleanup:</span>
      <button class="tp-btn dsFix" type="button" data-act="fix_boot_kernels" data-label="Clean /boot (remove old kernels)" data-why="Removes old kernel packages (keeps the running kernel + the 2 newest). Lists exactly which kernels will be removed, then applies on confirm; /boot integrity is verified after. No restart.">&#129529; Clean /boot</button>
      <button class="tp-btn dsFix" type="button" data-act="fix_var_logs" data-label="Trim journald + old logs" data-why="Vacuums journald (keeps 7 days / 200 MB) and removes rotated/compressed logs older than 14 days. Active logs are never touched. No restart.">&#128220; Trim logs</button>
      <button class="tp-btn dsFix" type="button" data-act="fix_tmp_cache" data-label="Clear old /tmp cache" data-why="Deletes regular /tmp files older than 3 days; sessions, sockets and locks are preserved.">&#128465; /tmp cache</button>
      <button class="tp-btn dsFix" type="button" data-act="fix_dropcaches" data-label="Drop page cache" data-why="Frees reclaimable page cache. Safe — the kernel re-caches as needed. No restart.">&#129504; Drop cache</button>
      <button class="tp-btn dsFix" type="button" data-act="fix_swap" data-label="Cycle swap (safe)" data-why="swapoff/swapon to move idle pages back to RAM and free swap. Refused unless free RAM ≥ 1.5× swap-in-use and ≥25% free, to rule out OOM. No service restart.">&#9851;&#65039; Cycle swap</button>
      <button class="tp-btn dsFix" type="button" data-act="swap_expand" data-label="Add / resize swap" data-why="Creates or resizes a dedicated persistent swapfile to a recommended (Auto) size or an exact size you type. Shows RAM, recommended min/max and the target, then applies on confirm; refuses on OpenVZ/LXC and if disk headroom is short.">&#9851;&#65039; Add / resize swap</button>
      <?php $smSwap = function_exists('smpro_swap_meta_read') ? smpro_swap_meta_read() : []; if (!empty($smSwap['path'])): ?>
      <button class="tp-btn dsFix" type="button" data-act="swap_remove" data-path="<?= smpro_h($smSwap['path']) ?>" data-label="Remove SM Pro swap" data-why="swapoff + delete the managed swapfile + strip its fstab line. Refused if RAM cannot absorb the in-use swap pages.">&#128465; Remove SM Pro swap</button>
      <?php if (($smSwap['state'] ?? '') === 'pending' || empty($smSwap['fstab'])): ?><span class="meta" style="font-size:11px;color:#c2710c">&#9888; managed swap not persistent — needs reconcile</span><?php endif; ?>
      <?php endif; ?>
      <button class="tp-btn dsFix" type="button" data-act="tmp_expand" data-label="Expand /tmp (double capacity)" data-why="Detects how /tmp is backed and doubles it. A tmpfs is resized instantly; a cPanel loopback /tmp is rebuilt at 2× with contents preserved and automatic rollback — /tmp is guaranteed to stay mounted. A plain /tmp directory is refused.">&#128190; Expand /tmp</button>
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

<?php /* Live disk I/O — read/write speed + busy%/impact (green<60, orange 60-85, red>=85) */ echo smpro_ds_diskio_card_html($diskio); ?>

<!-- Hardware Benchmark moved to its own section (Benchmark & Diagnostics) -->
<div class="card" style="margin:14px 0;display:flex;gap:12px;align-items:center;flex-wrap:wrap">
  <span style="font-size:20px">&#127937;</span>
  <div style="flex:1;min-width:220px"><b>Hardware Benchmark has moved</b>
    <div class="meta">It now lives in <b>Benchmark &amp; Diagnostics</b> — together with PHP and MySQL benchmarks, kernel &amp; software troubleshooting, and a saved report history.</div></div>
  <a class="tp-btn" href="index.cgi?page=benchmark" style="text-decoration:none">Open Benchmark &amp; Diagnostics &rarr;</a>
</div>

<!-- ===== Automation & Schedulers — Auto-Purge + Auto Swap-Cycle grouped in ONE place ===== -->
<div class="ds-autowrap" id="ds-auto">
  <div class="ds-autohd"><span class="ds-hic">&#129302;</span><b>Automation &amp; Schedulers</b><span class="meta">hands-off maintenance — reclaim safe disk junk and keep swap healthy, on a schedule</span></div>
  <div class="ds-autogrid">
    <?php if (function_exists('smpro_mnt_card_html')) echo smpro_mnt_card_html(); /* auto-purge scheduler */ ?>
    <?php if (function_exists('smpro_swapcycle_card_html')) echo smpro_swapcycle_card_html(); /* auto swap-cycle scheduler */ ?>
  </div>
</div>

<!-- Fix review/confirm modal (Apply/Cancel) -->
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

<div class="card" id="ds-fs" style="padding:0;overflow:hidden;margin:14px 0;border-top:3px solid <?= $fullMounts?'var(--dang)':'var(--good)' ?>">
  <div class="ds-head"><span class="ds-hic">&#128190;</span><b>Filesystems &amp; Inodes</b>
    <span class="ds-hchip"><span class="ds-pill"><?= count($fs) ?> mounts</span><?php if($fullMounts): ?><span class="ds-pill danger"><?= count($fullMounts) ?> near-full</span><?php else: ?><span class="ds-pill good">all healthy</span><?php endif; ?></span>
  </div>
  <div class="ds-tw"><table class="smpro-table"><thead><tr><th>Mount</th><th>Filesystem</th><th>Size</th><th>Used</th><th>Avail</th><th>Usage</th><th>Inodes</th></tr></thead><tbody>
    <?php foreach ($fs as $r): $in = $inodes[$r['mount']] ?? null; ?>
      <tr data-row class="<?= $r['pct']>=85?'ds-warn':'' ?>">
        <td class="mono"><b><?= smpro_h($r['mount']) ?></b></td><td class="mono"><?= smpro_h($r['fs']) ?></td>
        <td class="mono"><?= smpro_h($r['size']) ?></td><td class="mono"><?= smpro_h($r['used']) ?></td><td class="mono"><?= smpro_h($r['avail']) ?></td>
        <td><div class="ds-bar"><span class="<?= $pcls($r['pct']) ?>" style="width:<?= min(100,$r['pct']) ?>%"></span></div><span class="b <?= $pcls($r['pct']) ?>"><?= $r['pct'] ?>%</span></td>
        <td><?= $in?('<span class="b '.$pcls($in['pct']).'">'.$in['pct'].'%</span>'):'—' ?></td>
      </tr>
    <?php endforeach; ?>
  </tbody></table></div>
  <div class="ds-svtools" style="margin:0;padding:11px 16px;border-top:1px solid var(--line);border-bottom:0">
    <span class="ds-svlbl">Inode diagnostics:</span>
    <button class="tp-btn dsSv" type="button" data-type="inodes">&#128269; Find inode hogs (/home)</button>
    <span class="meta" style="font-size:11px">Lists the /home directories consuming the most inodes — read-only, no deletes. Results appear below.</span>
  </div>
</div>

<div class="card" id="ds-accts" style="padding:0;overflow:hidden;margin:14px 0">
  <div class="ds-head"><span class="ds-hic">&#128101;</span><b>Top accounts by disk usage</b>
    <span class="ds-hchip"><span class="meta" style="margin:0">cPanel quota &middot; top <?= min(60,count($accts)) ?> of <?= count($accts) ?></span><?php if($nearLimit): ?><span class="ds-pill danger"><?= count($nearLimit) ?> &ge;85%</span><?php else: ?><span class="ds-pill good">all within quota</span><?php endif; ?></span>
  </div>
  <div class="ds-tw" style="max-height:560px"><table class="smpro-table"><thead><tr><th>#</th><th>Account</th><th>Domain</th><th class="num">Used</th><th class="num">Limit</th><th>Quota usage</th><th></th></tr></thead><tbody>
    <?php foreach (array_slice($accts,0,60) as $i=>$a): ?>
      <tr data-row class="<?= ($a['pct']!==null&&$a['pct']>=85)?'ds-warn':'' ?>">
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

<!-- Move account home directory to another partition -->
<?php
// The mover is an occasional, deliberate operation — keep it FOLDED AWAY by default so the page stays about
// day-to-day disk work. It auto-opens only when there is something to act on: a move in progress, or a
// completed move still waiting for "delete old copy" / "undo".
$hmOpen = ($hmPending && ($hmPending['status'] ?? '') === 'moved');
$hmJob  = function_exists('smpro_ds_home_job_read') ? smpro_ds_home_job_read() : [];
if (!empty($hmJob['phase']) && $hmJob['phase'] !== 'idle' && empty($hmJob['done'])) $hmOpen = true;
?>
<details class="card hm-wrap" id="hmCard" <?= $hmOpen ? 'open' : '' ?>>
  <summary class="hm-sum">
    <span class="ds-hic">&#128230;</span>
    <span class="hm-sum-t">Move an account to another partition</span>
    <?php if ($hmOpen): ?><span class="b orange" id="hmSumBadge">needs attention</span><?php endif; ?>
    <span class="hm-sum-m">rsync live &middot; zero downtime &middot; reversible</span>
    <span class="hm-arw">&#9662;</span>
  </summary>
  <?php foreach ($hmPendAll as $hmP): if (($hmP["status"] ?? "") !== "moved") continue;
      $hmU = (string)$hmP['user']; $hmDst = (string)($hmP['dst'] ?? ''); $hmSrc = (string)($hmP['src'] ?? '');
      $hmSz = smpro_ds_home_h((int)($hmP['account_bytes'] ?? 0));
      $hmAgo = !empty($hmP['ts']) ? max(0, time() - (int)$hmP['ts']) : 0;
      $hmAgoH = $hmAgo ? ($hmAgo < 3600 ? floor($hmAgo/60) . ' min ago' : ($hmAgo < 86400 ? floor($hmAgo/3600) . 'h ago' : floor($hmAgo/86400) . 'd ago')) : ''; ?>
  <div class="hm-done hmPendRow" data-user="<?= smpro_h($hmU) ?>" data-size="<?= smpro_h($hmSz) ?>">
    <div class="hm-done-hd">
      <span class="hm-done-ic">&#9989;</span>
      <div>
        <div class="hm-done-t"><b><?= smpro_h($hmU) ?></b> is now running from <span class="mono"><?= smpro_h($hmDst) ?></span><?= $hmAgoH ? ' <span class="meta" style="font-weight:400">· moved ' . smpro_h($hmAgoH) . '</span>' : '' ?></div>
        <div class="hm-done-s">The move is complete and the account is fully switched over. Nothing is using the old location any more.</div>
      </div>
    </div>

    <div class="hm-check" id="hmCheck">
      <span class="meta">Before you delete anything, confirm the site is healthy:</span>
      <button class="tp-btn hmVerify" type="button" data-user="<?= smpro_h($hmU) ?>">&#128269; Check the site now</button>
      <span class="meta hmVerifyOut"></span>
    </div>

    <div class="hm-safety">
      <div class="hm-safety-t">&#128274; A safety copy is being kept</div>
      <div>The previous copy at <span class="mono"><?= smpro_h($hmSrc) ?></span> (<b><?= smpro_h($hmSz) ?></b>) is untouched, so this move can still be undone.
      <b>Take your time</b> — open the site, log into it, check uploads and email. There is no deadline; keeping the copy costs only the disk space.</div>
    </div>

    <div class="hm-acts">
      <button class="tp-btn hmRollback" type="button" data-user="<?= smpro_h($hmU) ?>">&#8630; Undo the move &mdash; put <?= smpro_h($hmU) ?> back on <span class="mono"><?= smpro_h(dirname($hmSrc)) ?></span></button>
      <button class="tp-btn danger hmFinalize" type="button" data-user="<?= smpro_h($hmU) ?>" data-size="<?= smpro_h($hmSz) ?>">&#128465; Delete the old copy &mdash; frees <?= smpro_h($hmSz) ?></button>
    </div>
    <div class="hm-warn">Deleting the old copy <b>cannot be undone</b>, and undo stops being possible afterwards. Only do it once you are satisfied the site is working.</div>
  </div>
  <?php endforeach; ?>
  <div style="padding:14px 18px">
    <?php if (count($hmRoots) < 2): ?>
      <p class="meta" style="margin:0">Only one home partition is configured on this server. This tool moves an account's files from one <span class="mono">/home*</span> partition to another (e.g. when <span class="mono">/home</span> is full but <span class="mono">/home2</span> has room). Add a second home partition to use it.</p>
      <div class="meta" style="margin-top:8px">Detected roots: <?php foreach ($hmRoots as $r): ?><span class="b good" style="margin-right:6px"><?= smpro_h($r['path']) ?> &middot; <?= smpro_ds_home_h($r['free']) ?> free</span><?php endforeach; ?></div>
    <?php else: ?>
      <?php $hmCap = function_exists('smpro_ds_home_capacity') ? smpro_ds_home_capacity($hmRoots[0]['path'] ?? '/home') : ['max'=>1,'recommended'=>1,'cores'=>1,'note'=>'']; ?>
      <div style="display:flex;gap:12px;align-items:flex-end;flex-wrap:wrap">
        <label style="display:flex;flex-direction:column;gap:4px;font-size:12px;font-weight:700;color:var(--muted)">Target partition
          <select id="hmTarget" class="rc-in" style="min-width:210px">
            <?php foreach ($hmRoots as $r): ?><option value="<?= smpro_h($r['path']) ?>"><?= smpro_h($r['path']) ?> — <?= smpro_ds_home_h($r['free']) ?> free of <?= smpro_ds_home_h($r['total']) ?></option><?php endforeach; ?>
          </select>
        </label>
        <label style="display:flex;flex-direction:column;gap:4px;font-size:12px;font-weight:700;color:var(--muted)" title="How many accounts are copied at the same time. The maximum is worked out from this server's cores, whether the target disk is spinning, and the load it is already carrying.">At a time
          <select id="hmThreads" class="rc-in" style="min-width:150px">
            <?php for ($t = 1; $t <= (int)$hmCap['max']; $t++): ?>
              <option value="<?= $t ?>" <?= $t === (int)$hmCap['recommended'] ? 'selected' : '' ?>><?= $t ?><?= $t === (int)$hmCap['recommended'] ? ' (recommended)' : '' ?></option>
            <?php endfor; ?>
          </select>
        </label>
        <button class="tp-btn" type="button" id="hmPreview">&#128269; Preview selected</button>
        <button class="tp-btn primary" type="button" id="hmMove" disabled title="Select accounts and preview first">&#128640; Move selected</button>
        <span class="meta" id="hmSelCount" style="align-self:center">none selected</span>
      </div>
      <div class="hm-cap">Server limit: at most <b><?= (int)$hmCap['max'] ?></b> account<?= (int)$hmCap['max'] > 1 ? 's' : '' ?> at a time
        <span class="meta">(<?= (int)$hmCap['cores'] ?> cores<?= isset($hmCap['rotational']) && $hmCap['rotational'] === true ? ', spinning target disk' : (isset($hmCap['rotational']) && $hmCap['rotational'] === false ? ', solid-state target' : '') ?>, load <?= smpro_h((string)$hmCap['load1']) ?>)<?= !empty($hmCap['note']) ? ' — ' . smpro_h($hmCap['note']) : '' ?>.
        Copying is disk-bound, so more at once finishes no sooner and would slow customer sites.</span></div>

      <div class="hm-picker">
        <div class="hm-pick-h"><b>Accounts</b>
          <label class="meta" style="margin-left:auto;display:flex;gap:6px;align-items:center"><input type="checkbox" id="hmAll"> select all shown</label>
        </div>
        <div class="hm-pick-list">
          <?php foreach ($accts as $a): ?>
            <label class="hm-pick"><input type="checkbox" class="hm-u" value="<?= smpro_h($a['user']) ?>">
              <span class="hm-pick-n"><?= smpro_h($a['user']) ?></span>
              <span class="hm-pick-d"><?= smpro_h($a['domain'] ?? '') ?></span>
              <span class="hm-pick-s"><?= smpro_ds_h($a['used']) ?></span></label>
          <?php endforeach; ?>
        </div>
      </div>
      <div id="hmBatch" style="margin-top:12px;display:none"></div>
      <div id="hmPreflight" style="margin-top:12px;display:none"></div>
      <div id="hmProgress" style="margin-top:12px;display:none">
        <div class="hm-pbar"><i id="hmBar" style="width:0%"></i></div>
        <div class="hm-prow"><b id="hmWho">—</b><span id="hmPct" class="hm-pct">0%</span></div>
        <div class="meta" id="hmProgMsg" style="margin-top:2px">Starting…</div>
        <div class="hm-pmeta">
          <span>Started <b id="hmStart">—</b></span>
          <span>Elapsed <b id="hmElapsed">—</b></span>
          <span>Speed <b id="hmRate">—</b></span>
          <span>Finishes ~<b id="hmEta">—</b></span>
        </div>
        <div class="meta" id="hmResumed" style="margin-top:4px;display:none"></div>
        <div class="hm-steps" id="hmSteps"></div>
      </div>
      <p class="meta" style="margin:12px 0 0;font-size:11.5px">Copies the home directory with a live <span class="mono">rsync</span> (the site stays up), switches cPanel to the new path, rebuilds the web/PHP/quota config, then keeps the old copy so you can <b>Reclaim space</b> or <b>Roll back</b>. Runs in the background — you can leave this page.
      <a class="lnk" href="index.cgi?page=reports-center&amp;tab=moves">Past moves &#8594;</a></p>
    <?php endif; ?>
  </div>
</details>

<div id="dcResult"></div>

<style>
.dc-panel{background:var(--card);border:1px solid var(--line);border-radius:14px;margin:14px 0;overflow:hidden}
.dc-phead{padding:12px 16px;border-bottom:1px solid var(--line);font-weight:700;display:flex;gap:10px;align-items:center}
.dc-note{padding:10px 16px;background:var(--warn-bg);color:#8a6516;font-size:12px;border-bottom:1px solid var(--line)}
.dc-sect{padding:10px 16px;border-bottom:1px solid var(--line)}.dc-stt{font-size:12px;font-weight:700;text-transform:uppercase;color:var(--muted);margin-bottom:6px}
.dc-scanprog{height:5px;background:var(--brand-bg);overflow:hidden}.dc-scanprog span{display:block;height:100%;width:35%;background:linear-gradient(90deg,#7c3aed,#4f46e5);animation:dcp 1.2s ease-in-out infinite}@keyframes dcp{0%{margin-left:-35%}100%{margin-left:100%}}
.dcDel,.dcClear{font-weight:700;white-space:nowrap;color:var(--dang);border-color:#f3c9c9}
.dc-selall{margin-left:8px;font-size:11px}
.dc-bulkbar{position:sticky;bottom:0;display:flex;align-items:center;gap:12px;padding:11px 16px;background:var(--dang-bg);border-top:1px solid #f3c9c9;font-size:13px}
.dc-bulkbar .tp-btn.danger{background:var(--dang);color:#fff;border-color:var(--dang);font-weight:700}
.dc-stt .b{vertical-align:middle}
.svc-kicker{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--brand);font-weight:800}
.ds-kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:14px 0}@media(max-width:720px){.ds-kpis{grid-template-columns:1fr 1fr}}
.kpi{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px;text-align:center}.kpi .kn{font-size:23px;font-weight:800;line-height:1}.kpi .kl{font-size:11px;text-transform:uppercase;color:var(--muted);margin-top:6px}
.kpi.crit{border-color:#f3c9c9;background:var(--dang-bg)}.kpi.crit .kn{color:var(--dang)}
.ds-head{padding:12px 16px;border-bottom:1px solid var(--line);font-weight:700;font-size:14px;display:flex;gap:10px;align-items:center}.ds-head .meta{margin-left:auto;color:var(--muted);font-size:12px}
.ds-tw{overflow:auto}.ds-tw thead th{position:sticky;top:0;background:var(--card);box-shadow:inset 0 -1px 0 var(--line)}
.smpro-table{width:100%;border-collapse:collapse;font-size:12px}.smpro-table th,.smpro-table td{padding:8px 12px;text-align:left;border-bottom:1px solid var(--line);white-space:nowrap;vertical-align:middle}
.smpro-table th{font-size:11px;text-transform:uppercase;color:var(--muted)}.smpro-table td.num,.smpro-table th.num{text-align:right}
.ds-warn td{background:var(--dang-bg)}.mono{font-family:ui-monospace,Consolas,monospace}.fa-file{white-space:normal;word-break:break-all;max-width:280px}
.ds-bar{display:inline-block;width:90px;height:7px;border-radius:5px;background:var(--brand-bg);overflow:hidden;vertical-align:middle;margin-right:7px}
.ds-bar span{display:block;height:100%}.ds-bar .good{background:var(--good)}.ds-bar .orange{background:#c2710c}.ds-bar .red{background:var(--dang)}
.b{display:inline-block;font-size:11px;font-weight:700;padding:2px 8px;border-radius:20px}.b.good{background:var(--good-bg);color:var(--good)}.b.orange{background:var(--warn-bg);color:#c2710c}.b.red{background:var(--dang-bg);color:var(--dang)}
.fa-lnk{color:var(--brand);text-decoration:none;font-size:11px;border:1px solid var(--line);padding:1px 7px;border-radius:6px}.meta{color:var(--muted)}
.ds-svtools{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin:0 0 14px;padding-bottom:12px;border-bottom:1px solid var(--line)}
.ds-svlbl{font-size:11px;text-transform:uppercase;font-weight:700;color:var(--muted)}
.ds-svtools .tp-btn{font-size:12px;padding:7px 12px}
.ds-check{display:flex;align-items:center;gap:14px;flex-wrap:wrap;padding:12px 14px;border:1px solid var(--line);border-radius:12px;margin-bottom:10px}
.ds-check.warn{border-color:#f0d8b8;background:var(--warn-bg)}.ds-check.danger{border-color:#f3c9c9;background:var(--dang-bg)}
.ds-checkbody{flex:1;min-width:240px}.ds-checktt{font-size:13px}.ds-checkwhy{font-size:12px;color:var(--muted);margin-top:4px}
.dsFix{background:var(--brand);color:#fff;border-color:var(--brand);font-weight:700;white-space:nowrap;box-shadow:0 2px 6px rgba(59,91,219,.18)}.dsFix:hover{filter:brightness(1.08)}.dsFix[disabled]{opacity:.6}
.hm-pending{padding:12px 16px;background:var(--warn-bg);border-bottom:1px solid var(--line);font-size:13px;color:#8a6516}
/* completed-move panel: success first, destructive action last and clearly marked */
.hm-done{border-bottom:1px solid var(--line);background:linear-gradient(180deg,var(--good-bg),transparent);padding:14px 18px;font-size:13px}
.hm-done-hd{display:flex;gap:12px;align-items:flex-start}
.hm-done-ic{font-size:20px;line-height:1.1}
.hm-done-t{font-size:14px}
.hm-done-s{color:var(--muted);font-size:12.5px;margin-top:3px}
.hm-check{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:12px 0 0;padding:10px 12px;border:1px solid var(--line);border-radius:10px;background:var(--card)}
.hm-safety{margin-top:10px;padding:10px 12px;border-radius:10px;background:var(--card);border:1px solid var(--line);font-size:12.5px;color:var(--muted)}
.hm-safety-t{font-weight:700;color:inherit;margin-bottom:3px}
.hm-acts{display:flex;gap:10px;flex-wrap:wrap;margin-top:12px}
.hm-acts .tp-btn{font-size:12.5px}
.hm-acts .tp-btn.danger{color:var(--dang);border-color:#f3c9c9;background:transparent;font-weight:700}
.hm-acts .tp-btn.danger:hover{background:var(--dang);color:#fff}
.hm-warn{margin-top:8px;font-size:11.5px;color:var(--muted)}
/* folded-away mover section */
.hm-wrap{padding:0;overflow:hidden;margin:14px 0}
.hm-cap{margin-top:10px;font-size:12px;padding:8px 11px;border-radius:9px;background:var(--brand-bg);color:var(--ink)}
.hm-cap .meta{display:block;margin-top:2px;font-size:11.5px}
.hm-picker{margin-top:12px;border:1px solid var(--line);border-radius:10px;overflow:hidden}
.hm-pick-h{display:flex;align-items:center;gap:10px;padding:8px 12px;border-bottom:1px solid var(--line);font-size:12.5px;background:var(--card)}
.hm-pick-list{max-height:230px;overflow:auto}
.hm-pick{display:flex;align-items:center;gap:10px;padding:6px 12px;font-size:12.5px;border-bottom:1px solid var(--line);cursor:pointer}
.hm-pick:last-child{border-bottom:none}
.hm-pick:hover{background:var(--brand-bg)}
.hm-pick-n{font-family:ui-monospace,Consolas,monospace;font-weight:700;min-width:130px}
.hm-pick-d{color:var(--muted);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.hm-pick-s{font-variant-numeric:tabular-nums;color:var(--muted)}
/* readable activity timeline — plain rows in the card, never a console */
.hm-steps{margin-top:10px;border:1px solid var(--line);border-radius:9px;background:var(--card);max-height:210px;overflow:auto}
.hm-steps-h{font-size:10.5px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);font-weight:700;padding:7px 11px;border-bottom:1px solid var(--line);position:sticky;top:0;background:var(--card)}
.hm-step{display:flex;gap:9px;align-items:baseline;padding:5px 11px;font-size:12px;border-bottom:1px solid var(--line)}
.hm-step:last-child{border-bottom:none}
.hm-step-i{width:13px;flex:none;text-align:center;color:var(--good)}
.hm-step.cur .hm-step-i{color:var(--brand)} .hm-step.bad .hm-step-i{color:var(--dang)}
.hm-step-t{font-weight:700;min-width:132px;flex:none}
.hm-step.bad .hm-step-t{color:var(--dang)}
.hm-step-m{color:var(--muted);flex:1;min-width:0;overflow-wrap:anywhere}
.hm-step-x{color:var(--muted);font-size:11px;font-variant-numeric:tabular-nums;flex:none}
.hm-step.cur{background:var(--brand-bg)}
.hm-spin{display:inline-block;width:9px;height:9px;border:2px solid var(--brand);border-right-color:transparent;border-radius:50%;animation:hmspin .7s linear infinite;vertical-align:middle}
@keyframes hmspin{to{transform:rotate(360deg)}}
@media (prefers-reduced-motion:reduce){.hm-spin{animation:none}}
.hm-rowsteps{max-height:170px;margin-top:7px}
/* per-account detail panel */
.hm-dbar{height:7px;border-radius:6px;background:var(--brand-bg);overflow:hidden;margin:9px 11px 0}
.hm-dbar i{display:block;height:100%;background:linear-gradient(90deg,#7c3aed,#4f46e5);transition:width .5s ease}
.hm-facts{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:1px;background:var(--line);margin:9px 0 0;border-top:1px solid var(--line);border-bottom:1px solid var(--line)}
.hm-fact{background:var(--card);padding:6px 11px;font-size:11.5px;display:flex;flex-direction:column;gap:1px}
.hm-fact span{color:var(--muted);font-size:10.5px;text-transform:uppercase;letter-spacing:.05em;font-weight:700}
.hm-fact b{font-size:12.5px;overflow-wrap:anywhere}
.hm-nowfile{display:flex;gap:7px;align-items:center;padding:7px 11px;font-size:12px;background:var(--brand-bg);border-bottom:1px solid var(--line);flex-wrap:wrap}
.hm-nf-l{font-weight:700;color:var(--brand)}
.hm-nowfile code,.hm-file code{font-family:ui-monospace,Consolas,monospace;font-size:11.5px;overflow-wrap:anywhere;background:transparent;color:inherit}
.hm-filelist{max-height:150px;overflow:auto}
.hm-fl-h{font-size:10.5px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);font-weight:700;padding:6px 11px;position:sticky;top:0;background:var(--card);border-bottom:1px solid var(--line)}
.hm-file{padding:3px 11px;font-size:11.5px;color:var(--muted);border-bottom:1px solid var(--line)}
.hm-file:last-child{border-bottom:none}
.hm-rowbar{height:5px;border-radius:5px;background:var(--brand-bg);overflow:hidden;margin-top:5px;min-width:80px}
.hm-rowbar i{display:block;height:100%;background:var(--brand);transition:width .5s ease}
.hm-batch{border:1px solid var(--line);border-radius:10px;overflow:hidden}.hm-batch table{width:100%;table-layout:fixed}.hm-batch td{word-break:break-word}
.hm-batch-h{display:flex;align-items:center;gap:10px;padding:9px 12px;border-bottom:1px solid var(--line);font-size:13px}
.hm-batch-s{padding:8px 12px;border-bottom:1px solid var(--line);display:flex;gap:8px;align-items:center}
.hm-sum{display:flex;align-items:center;gap:10px;padding:13px 16px;cursor:pointer;list-style:none;font-size:14px;user-select:none}
.hm-sum::-webkit-details-marker{display:none}
.hm-sum:hover{background:rgba(100,116,139,.05)}
.hm-sum-t{font-weight:700}
.hm-sum-m{margin-left:auto;color:var(--muted);font-size:11.5px}
.hm-arw{color:var(--muted);transition:transform .18s ease;font-size:12px}
.hm-wrap[open] .hm-arw{transform:rotate(180deg)}
.hm-wrap[open] .hm-sum{border-bottom:1px solid var(--line)}
/* progress card */
.hm-pbar{height:9px;border-radius:6px;background:var(--brand-bg);overflow:hidden}
.hm-pbar i{display:block;height:100%;background:linear-gradient(90deg,#7c3aed,#4f46e5);transition:width .6s ease}
.hm-prow{display:flex;justify-content:space-between;align-items:baseline;gap:10px;margin-top:7px;font-size:12.5px}
.hm-prow b{font-family:ui-monospace,Consolas,monospace}
.hm-pct{font-variant-numeric:tabular-nums;font-weight:700;color:var(--brand)}
.hm-pmeta{display:flex;gap:16px;flex-wrap:wrap;margin-top:6px;font-size:11.5px;color:var(--muted)}
.hm-pmeta b{color:inherit;font-variant-numeric:tabular-nums}
#hmCard .rc-in{padding:7px 10px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:inherit;font-size:12.5px}
#hmCard .tp-btn.primary{background:var(--brand);color:#fff;border-color:var(--brand);font-weight:700}#hmCard .tp-btn[disabled]{opacity:.55}
/* --- Interactive Admin Disk Tools polish --- */
.ds-head{background:linear-gradient(180deg,rgba(100,116,139,.06),transparent);padding:14px 18px}
html[data-theme=dark] .ds-head{background:linear-gradient(180deg,rgba(255,255,255,.035),transparent)}
.ds-kpis .kpi{position:relative;overflow:hidden;padding:16px 14px;border-radius:14px;transition:transform .14s ease,box-shadow .14s ease}
.ds-kpis .kpi::before{content:"";position:absolute;top:0;left:0;right:0;height:3px;background:var(--good);opacity:.55}
.ds-kpis .kpi.crit::before{background:var(--dang);opacity:1}
.ds-kpis .kpi:hover{transform:translateY(-2px);box-shadow:0 8px 20px rgba(15,23,42,.08)}
.ds-kpis .kpi .kn{font-size:26px}
.ds-svlbl{min-width:118px;letter-spacing:.04em}
.dsSv{background:var(--card);color:var(--brand);border:1px solid #c9d4ff;font-weight:700;white-space:nowrap}
.dsSv:hover{background:var(--brand);color:#fff;border-color:var(--brand)}
html[data-theme=dark] .dsSv{border-color:#294066}
.b.good{background:var(--good-bg);color:var(--good)}
/* Fix review modal */
.ds-modal{position:fixed;inset:0;background:rgba(2,8,23,.55);display:flex;align-items:center;justify-content:center;z-index:3000;padding:20px;backdrop-filter:blur(2px)}
.ds-modal[hidden]{display:none}
.ds-modal-card{background:var(--card);border-radius:16px;max-width:580px;width:100%;box-shadow:0 24px 70px rgba(2,8,23,.45);overflow:hidden;animation:dsmIn .18s ease}
@keyframes dsmIn{from{transform:translateY(14px) scale(.98);opacity:0}to{transform:none;opacity:1}}
.ds-modal-head{display:flex;align-items:center;justify-content:space-between;padding:16px 20px;border-bottom:1px solid var(--line);font-weight:800;font-size:15px}
.ds-modal-x{border:none;background:none;font-size:24px;cursor:pointer;color:var(--muted);line-height:1;padding:0 4px}
.ds-modal-body{padding:18px 20px;max-height:62vh;overflow:auto}
.ds-modal-foot{display:flex;gap:10px;justify-content:flex-end;padding:14px 20px;border-top:1px solid var(--line);background:var(--card)}
.dsm-row{display:flex;gap:10px;margin-bottom:9px;font-size:13px;align-items:center}
.dsm-row b{min-width:130px;color:var(--muted);font-weight:600}
.dsm-list{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:11px 13px;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;line-height:1.7;max-height:220px;overflow:auto;white-space:pre-wrap;margin-top:4px}
.dsm-note{font-size:12px;color:var(--muted);background:var(--brand-bg);border:1px solid #d6e6fb;border-radius:10px;padding:10px 12px;margin-top:12px}
.dsm-result{font-size:13px;line-height:1.6;margin-top:10px;white-space:pre-wrap}
.dsm-badge{display:inline-block;padding:3px 11px;border-radius:20px;font-weight:700;font-size:12px}
.dsm-badge.ok{background:var(--good-bg);color:var(--good)}.dsm-badge.bad{background:var(--dang-bg);color:var(--dang)}.dsm-badge.warn{background:var(--warn-bg);color:#9a6700}
.dsm-row.dsm-rec{background:var(--good-bg);border:1px solid #bfe6cd;border-radius:9px;padding:8px 11px;margin-bottom:9px}
html[data-theme=dark] .dsm-row.dsm-rec{border-color:#1d4a33}
.dsm-auto{color:var(--good)}
.dsm-sizerow{align-items:center}
.dsm-sizewrap{display:inline-flex;align-items:center;gap:8px}
.dsm-sizewrap input{padding:7px 10px;border:1px solid var(--line);border-radius:8px;width:110px;font-size:14px;font-weight:600;background:var(--card);color:var(--ink)}
.dsm-unit{font-weight:700;color:var(--muted);font-size:13px}
.dsm-maxb{font-size:11px;color:var(--muted);background:var(--card);border:1px solid var(--line);border-radius:20px;padding:2px 9px}
.dsm-hint{font-size:11.5px;color:var(--muted);margin:4px 0 0 140px;line-height:1.5}
.dsm-hint.warn{color:#9a6700}
/* ===== modern storage summary stat cards ===== */
.ds-stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:16px 0}
@media(max-width:900px){.ds-stats{grid-template-columns:1fr 1fr}}
@media(max-width:480px){.ds-stats{grid-template-columns:1fr}}
.ds-stat{display:flex;gap:13px;align-items:center;background:var(--card);border:1px solid var(--line);border-radius:16px;padding:15px 16px;position:relative;overflow:hidden;transition:transform .14s ease,box-shadow .14s ease}
.ds-stat:hover{transform:translateY(-2px);box-shadow:0 10px 24px rgba(15,23,42,.08)}
.ds-stat::before{content:"";position:absolute;left:0;top:0;bottom:0;width:4px;background:var(--good)}
.ds-stat.info::before{background:var(--brand)}.ds-stat.warn::before{background:#c2710c}.ds-stat.danger::before{background:var(--dang)}
.ds-stat-ic{width:46px;height:46px;flex:none;border-radius:13px;display:flex;align-items:center;justify-content:center;font-size:22px;background:var(--good-bg)}
.ds-stat.info .ds-stat-ic{background:var(--brand-bg)}.ds-stat.warn .ds-stat-ic{background:var(--warn-bg)}.ds-stat.danger .ds-stat-ic{background:var(--dang-bg)}
.ds-stat-b{min-width:0}
.ds-stat-n{font-size:24px;font-weight:800;line-height:1.05}.ds-stat-n small{font-size:13px;font-weight:700;color:var(--muted)}
.ds-stat.danger .ds-stat-n{color:var(--dang)}.ds-stat.warn .ds-stat-n{color:#b45309}
.ds-stat-l{font-size:12.5px;font-weight:700;margin-top:3px}
.ds-stat-s{font-size:11px;color:var(--muted);margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
/* zebra + hover for the data tables */
.smpro-table tbody tr:nth-child(even) td{background:rgba(100,116,139,.035)}
html[data-theme=dark] .smpro-table tbody tr:nth-child(even) td{background:rgba(255,255,255,.02)}
.smpro-table tbody tr:hover td{background:var(--brand-bg)}
.ds-warn td,.smpro-table tbody tr.ds-warn:hover td{background:var(--dang-bg)}
.ds-bar{width:110px}
/* section header icon + summary chips */
.ds-hic{font-size:16px;margin-right:3px}
.ds-hchip{margin-left:auto;display:flex;gap:6px;align-items:center;flex-wrap:wrap}
.ds-pill{font-size:11px;font-weight:700;padding:2px 9px;border-radius:20px;background:var(--brand-bg);color:var(--brand);white-space:nowrap}
.ds-pill.warn{background:var(--warn-bg);color:#b45309}.ds-pill.danger{background:var(--dang-bg);color:var(--dang)}.ds-pill.good{background:var(--good-bg);color:var(--good)}
/* ===== Disk I/O card ===== */
.ds-io-verdict{font-size:13px;font-weight:700;border-radius:10px;padding:9px 12px;margin-bottom:10px}
.ds-io-verdict.ok{background:var(--good-bg);color:#15803d}.ds-io-verdict.warn{background:var(--warn-bg);color:#b45309}.ds-io-verdict.danger{background:var(--dang-bg);color:var(--dang)}
.ds-io-tw{overflow:auto}
.ds-io-tw .ds-bar{width:120px}
.ds-io-legend{font-size:11px;color:var(--muted);margin-top:10px;line-height:1.6}
.ds-io-legend .b{margin-right:4px}
.ds-io-live{font-size:11px;font-weight:700;color:var(--good);margin-left:10px;transition:opacity .3s;white-space:nowrap}
/* ===== Automation & Schedulers — two schedulers grouped in one place ===== */
.ds-autowrap{margin:16px 0}
.ds-autohd{display:flex;align-items:center;gap:10px;flex-wrap:wrap;font-weight:800;font-size:15px;margin:0 0 4px}
.ds-autohd .meta{margin-left:auto;font-weight:400;font-size:12px;color:var(--muted)}
.ds-autogrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(430px,1fr));gap:14px;align-items:start}
@media(max-width:560px){.ds-autogrid{grid-template-columns:1fr}}
.ds-autogrid > .card{margin:0 !important}   /* neutralize each scheduler card's own margin so they sit as one unit */
</style>
<script>
(function(){
  var CSRF=<?= json_encode($dsCsrf) ?>;
  function dsPost(act,extra){var fd=new URLSearchParams();fd.set('ds_action',act);fd.set('smpro_csrf',CSRF);if(extra){for(var k in extra)fd.set(k,extra[k]);}
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
        mTitle.textContent='Remove old kernels';
        if(!j||!j.ok||!j.safe){
          mBody.innerHTML='<div class="dsm-row"><b>Status</b><span class="dsm-badge bad">Refused (safe)</span></div>'
            +'<div class="dsm-result">'+esc((j&&(j.reason||j.msg))||'Cannot determine kernels.')+'</div>';
          mGo.style.display='none';mCancel.textContent='Close';
        } else {
          var n=(j.remove||[]).length;
          mBody.innerHTML='<div class="dsm-row"><b>Status</b><span class="dsm-badge ok">Ready to apply — nothing changed yet</span></div>'
            +'<div class="dsm-row"><b>Running (kept)</b><span class="mono">'+esc(j.running)+'</span></div>'
            +'<div class="dsm-row"><b>Also kept</b><span>the 2 newest kernels</span></div>'
            +'<div class="dsm-row"><b>Will remove</b><span><b>'+n+'</b> old kernel package(s)</span></div>'
            +'<div class="dsm-list">'+esc((j.remove||[]).join('\n'))+'</div>'
            +'<div class="dsm-note">The running kernel stays loaded in RAM — no restart, no reboot. /boot integrity is verified automatically after removal; if anything looks off you get a clear “do not reboot” warning with the recovery command.</div>';
          mGo.style.display='';mGo.textContent='🗑 Execute removal';mCancel.textContent='Cancel';
          mGo.onclick=function(){mRun('fix_boot_kernels');};
        }
        M.hidden=false;
      }).catch(function(){b.disabled=false;b.innerHTML=orig;alert('Could not load the plan.');});
      return;
    }
    // swap_expand → dry-run preview card (with optional custom size), then create
    if(act==='swap_expand'){
      b.disabled=true;b.textContent='Checking…';
      dsPost('preview_swap_expand',{}).then(function(j){
        b.disabled=false;b.innerHTML=orig;mTitle.textContent='Add / resize swap';
        if(!j||!j.safe){mBody.innerHTML='<div class="dsm-row"><b>Status</b><span class="dsm-badge bad">Refused (safe)</span></div><div class="dsm-result">'+esc((j&&(j.reason||j.msg))||'Cannot plan swap.')+'</div>';mGo.style.display='none';mCancel.textContent='Close';M.hidden=false;return;}
        var renderWill=function(j2){var w=document.getElementById('swWill');if(w)w.innerHTML=j2.resize?('<b>'+esc(j2.old_size_h)+'</b> &rarr; <b>'+esc(j2.add_h)+'</b> · new total '+esc(j2.new_total_h)):('<b>'+esc(j2.add_h)+'</b> &rarr; new total '+esc(j2.new_total_h));
          var h=document.getElementById('swHint');if(h){h.innerHTML=j2.clamped?('&#9888; that is above the maximum — it will be capped to <b>'+esc(j2.add_h)+'</b> (max '+esc(j2.room_h)+').'):('Will create <b>'+esc(j2.add_h)+'</b> at the chosen size.');h.className='dsm-hint'+(j2.clamped?' warn':'');}};
        mBody.innerHTML='<div class="dsm-row"><b>Status</b><span class="dsm-badge ok">Ready to apply</span></div>'
          +'<div class="dsm-row"><b>Virtualization</b><span>'+esc(j.virt||'bare metal / full VM')+'</span></div>'
          +'<div class="dsm-row"><b>System RAM</b><span>'+esc(j.ram_h)+'</span></div>'
          +'<div class="dsm-row dsm-rec"><b>Recommended swap</b><span><b class="dsm-auto">Auto = '+esc(j.auto_h)+'</b> &nbsp;·&nbsp; you can set '+esc(j.min_rec_h)+' to <b>'+esc(j.room_h)+'</b> <span class="meta">(max)</span></span></div>'
          +'<div class="dsm-row"><b>Current swap</b><span>'+esc(j.cur_swap_h)+'</span></div>'
          +(j.resize?'<div class="dsm-row"><b>Resize</b><span id="swWill"><b>'+esc(j.old_size_h)+'</b> &rarr; <b>'+esc(j.add_h)+'</b> · new total '+esc(j.new_total_h)+'</span></div>':'<div class="dsm-row"><b>Will add</b><span id="swWill"><b>'+esc(j.add_h)+'</b> &rarr; new total '+esc(j.new_total_h)+'</span></div>')
          +'<div class="dsm-row"><b>Location</b><span>'+esc(j.path)+' — '+esc(j.fstype)+', '+esc(j.avail_h)+' free</span></div>'
          +'<div class="dsm-note">Made permanent so it survives a reboot. Needs thick-provisioned local disk (thin LVM / SAN / cloud volumes can run out of space at runtime). No service restart.</div>'
          +'<div class="dsm-row dsm-sizerow"><b>Size</b><span class="dsm-sizewrap"><input id="swGB" type="number" min="0.25" step="0.5" placeholder="Auto"><span class="dsm-unit">GiB</span><span class="dsm-maxb">max '+esc(j.room_h)+'</span></span></div>'
          +'<div class="dsm-hint" id="swHint">Leave empty for the recommended <b>Auto ('+esc(j.auto_h)+')</b>, or type a size in <b>GiB</b> — anything above the max is capped automatically.</div>';
        mGo.style.display='';mGo.textContent=j.resize?'Resize swapfile':'Create swapfile';mCancel.textContent='Cancel';
        var gEl=document.getElementById('swGB'),swT=null;
        if(gEl)gEl.addEventListener('input',function(){if(swT)clearTimeout(swT);swT=setTimeout(function(){var gb=gEl.value?parseFloat(gEl.value):0;var mb=gb>0?Math.round(gb*1024):0;dsPost('preview_swap_expand',mb>0?{target_mb:mb}:{}).then(function(j2){if(j2&&j2.safe)renderWill(j2);});},450);});
        mGo.onclick=function(){var g=document.getElementById('swGB');var gb=g&&g.value?parseFloat(g.value):0;var mb=gb>0?Math.round(gb*1024):0;mGo.disabled=true;mGo.textContent='Working…';mCancel.disabled=true;dsPost('swap_expand',mb>0?{target_mb:mb}:{}).then(mResult).catch(function(){mGo.disabled=false;mGo.textContent='Apply';mCancel.disabled=false;alert('Request failed.');});};
        M.hidden=false;
      }).catch(function(){b.disabled=false;b.innerHTML=orig;alert('Could not load the plan.');});
      return;
    }
    // swap_remove → plain confirm
    if(act==='swap_remove'){
      var pth=b.getAttribute('data-path')||'';mTitle.textContent=lbl;
      mBody.innerHTML='<div class="dsm-row"><b>Action</b><span>Remove managed swapfile</span></div><div class="dsm-row"><b>Path</b><span class="mono">'+esc(pth)+'</span></div><div class="dsm-note">'+esc(why)+'</div>';
      mGo.style.display='';mGo.textContent='Remove swap';mCancel.textContent='Cancel';
      mGo.onclick=function(){mGo.disabled=true;mGo.textContent='Working…';mCancel.disabled=true;dsPost('swap_remove',{path:pth}).then(mResult).catch(function(){mGo.disabled=false;mGo.textContent='Remove swap';mCancel.disabled=false;alert('Request failed.');});};
      M.hidden=false;return;
    }
    // tmp_expand → dry-run preview; loop backing needs a typed confirm + background job with progress polling
    if(act==='tmp_expand'){
      b.disabled=true;b.textContent='Checking…';
      dsPost('preview_tmp_expand',{}).then(function(j){
        b.disabled=false;b.innerHTML=orig;mTitle.textContent='Expand /tmp';
        if(!j||j.refuse||!j.safe){mBody.innerHTML='<div class="dsm-row"><b>Status</b><span class="dsm-badge bad">Refused (safe)</span></div><div class="dsm-result">'+esc((j&&(j.reason||j.msg))||'Cannot resize /tmp.')+'</div>';mGo.style.display='none';mCancel.textContent='Close';M.hidden=false;return;}
        var isLoop=(j.backing==='loop');
        var steps=(j.steps||[]).map(function(s){return '<li>'+esc(s)+'</li>';}).join('');
        mBody.innerHTML='<div class="dsm-row"><b>Status</b><span class="dsm-badge ok">Ready to apply</span></div>'
          +'<div class="dsm-row"><b>Backing</b><span>'+esc(j.backing)+'</span></div>'
          +'<div class="dsm-row"><b>Capacity</b><span>'+esc(j.cur_h||j.cur||'')+' &rarr; <b>'+esc(j.new_h||j.new||'')+'</b></span></div>'
          +(steps?'<div class="dsm-list"><ol style="margin:0;padding-left:18px">'+steps+'</ol></div>':'')
          +'<div class="dsm-note">'+(isLoop?'The cPanel loopback /tmp is briefly swapped by a background job — /tmp is guaranteed to stay mounted, with automatic rollback if any step fails.':'A tmpfs /tmp is resized instantly (contents preserved).')+(j.cagefs?' '+esc(j.cagefs):'')+'</div>'
          +(isLoop?'<div class="dsm-row" style="margin-top:8px"><label><input type="checkbox" id="tmpAck"> I understand /tmp is briefly swapped by a background maintenance job.</label></div><div class="dsm-row"><b>Type EXPAND</b><input id="tmpConf" type="text" placeholder="EXPAND" style="padding:6px 8px;border:1px solid var(--line);border-radius:8px;width:150px"></div>':'');
        mGo.style.display='';mGo.textContent=isLoop?'Expand /tmp (background)':'Expand /tmp';mCancel.textContent='Cancel';
        mGo.onclick=function(){
          if(isLoop){var ack=document.getElementById('tmpAck'),cf=document.getElementById('tmpConf');if(!ack||!ack.checked||!cf||cf.value.trim()!=='EXPAND'){alert('Tick the box and type EXPAND to proceed.');return;}}
          mGo.disabled=true;mGo.textContent='Working…';mCancel.disabled=true;
          dsPost('tmp_expand',{}).then(function(res){
            if(res&&res.inline){mResult(res);return;}
            if(!res||!res.ok||!res.job){mResult(res||{ok:false,msg:'Launch failed.'});return;}
            mBody.innerHTML='<div class="dsm-row"><b>Status</b><span class="dsm-badge warn" id="tmpPh">Starting…</span></div><div class="dsm-result" id="tmpMsg">Preparing new /tmp…</div>';
            var poll=setInterval(function(){dsPost('tmp_expand_status',{}).then(function(st){
              if(!st)return;var ph=document.getElementById('tmpPh'),ms=document.getElementById('tmpMsg');
              if(ph)ph.textContent=(st.phase||'')+' '+(st.pct||0)+'%';if(ms)ms.textContent=esc(st.msg||'');
              if(st.done){clearInterval(poll);mResult(st.result||{ok:false,msg:st.msg||'Done.'});}
            }).catch(function(){});},2000);
          }).catch(function(){mGo.disabled=false;mGo.textContent='Expand /tmp';mCancel.disabled=false;alert('Request failed.');});
        };
        M.hidden=false;
      }).catch(function(){b.disabled=false;b.innerHTML=orig;alert('Could not load the plan.');});
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
    // These two permanently delete files, so show the REAL count/size first instead of prose alone.
    if(act==='fix_var_logs'||act==='fix_tmp_cache'){
      var pact=act==='fix_var_logs'?'preview_var_logs':'preview_tmp_cache';
      mGo.disabled=true; var goT=mGo.textContent; mGo.textContent='Checking…';
      var slot=document.createElement('div'); slot.className='dsm-note'; slot.textContent='Counting what would be deleted…';
      mBody.appendChild(slot);
      dsPost(pact,{}).then(function(p){
        mGo.disabled=false; mGo.textContent=goT;
        if(p&&p.ok){
          slot.innerHTML='<b>Would delete now:</b> '+(+p.files||0)+' file(s) — '+esc(p.human||'0 B')
            +'<br><span class="meta">'+esc(p.what||'')+'</span>'
            +(p.journal?'<br><span class="meta">journald currently uses '+esc(p.journal)+'</span>':'');
          if(!p.files){mGo.disabled=true;mGo.textContent='Nothing to delete';}
        } else { slot.textContent='Could not count what would be deleted — proceed only if you are sure.'; }
      }).catch(function(){mGo.disabled=false;mGo.textContent=goT;slot.textContent='Preview failed.';});
    }
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
    var acct=b.getAttribute('data-acct');
    dcStart(acct);
  });
  // ---- background cleanup scan: starts a detached worker, survives the page closing, result waits on return ----
  var dcPoll=null;
  function dcShell(acct,inner,showCancel){
    var box=document.getElementById('dcResult'); if(!box)return;
    box.innerHTML='<div class="dc-panel"><div class="dc-phead">&#129529; Disk cleanup — '+esc(acct)+
      (showCancel?'<button class="fa-lnk dcCancel" type="button" data-acct="'+esc(acct)+'" style="margin-left:auto;color:var(--dang);border-color:#f3c9c9">Cancel scan</button>'
                 :'<button class="fa-lnk dcClose" type="button" data-acct="'+esc(acct)+'" style="margin-left:auto">Close</button>')+
      '</div>'+inner+'</div>';
  }
  function dcRender(acct){
    fetch('index.cgi?page=disk-storage&ajax=cleanscan&user='+encodeURIComponent(acct),{cache:'no-store'})
      .then(function(r){return r.text();})
      .then(function(html){dcShell(acct,html,false);var bx=document.getElementById('dcResult');if(bx)bx.scrollIntoView({behavior:'smooth',block:'nearest'});})
      .catch(function(){dcShell(acct,'<div class="fa-empty" style="padding:16px;color:var(--dang)">Could not load the report.</div>',false);});
  }
  function dcWatch(acct){
    if(dcPoll)clearInterval(dcPoll);
    dcPoll=setInterval(function(){
      dsPost('cleanscan_status',{acct:acct}).then(function(st){
        if(!st||!st.exists){clearInterval(dcPoll);dcPoll=null;return;}
        if(st.done){clearInterval(dcPoll);dcPoll=null;
          if(st.cancelled){dcShell(acct,'<div class="fa-empty" style="padding:16px">Scan cancelled.</div>',false);return;}
          dcRender(acct);return;}
        var extra=st.stale?'<div class="meta" style="padding:0 16px 10px">No progress for a while — it may have been interrupted; you can cancel and start again.</div>':'';
        dcShell(acct,'<div class="dc-scanprog"><span></span></div><div class="fa-empty" style="padding:16px;text-align:center;color:var(--muted)">'+esc(st.msg||'Scanning…')+'<br><span class="meta">This keeps running even if you close the page — the report will be here when you come back.</span></div>'+extra,true);
      }).catch(function(){});
    },2500);
  }
  function dcStart(acct){
    dcShell(acct,'<div class="dc-scanprog"><span></span></div><div class="fa-empty" style="padding:16px;text-align:center;color:var(--muted)">Starting the background scan…</div>',true);
    var bx=document.getElementById('dcResult'); if(bx)bx.scrollIntoView({behavior:'smooth',block:'nearest'});
    dsPost('cleanscan_start',{acct:acct}).then(function(j){
      if(!j||!j.ok){dcShell(acct,'<div class="fa-empty" style="padding:16px;color:var(--dang)">'+esc((j&&j.msg)||'Could not start the scan.')+'</div>',false);return;}
      dcWatch(acct);
    }).catch(function(){dcShell(acct,'<div class="fa-empty" style="padding:16px;color:var(--dang)">Request failed.</div>',false);});
  }
  document.addEventListener('click',function(e){
    var c=e.target.closest&&e.target.closest('.dcCancel');
    if(c){ var a=c.getAttribute('data-acct');
      if(!confirm('Cancel the disk-cleanup scan for '+a+'?\n\nNothing has been deleted — this only stops the scan.'))return;
      dsPost('cleanscan_cancel',{acct:a}).then(function(){if(dcPoll){clearInterval(dcPoll);dcPoll=null;}dcShell(a,'<div class="fa-empty" style="padding:16px">Scan cancelled.</div>',false);});return; }
    var cl=e.target.closest&&e.target.closest('.dcClose');
    if(cl){ var a2=cl.getAttribute('data-acct'); dsPost('cleanscan_forget',{acct:a2}).catch(function(){});
      var bx2=document.getElementById('dcResult'); if(bx2)bx2.innerHTML=''; return; }
  });
  // On page load, restore any scan that is still running or already finished while we were away.
  (function(){
    var pend=<?= json_encode(function_exists('smpro_ds_scan_all') ? smpro_ds_scan_all() : [], JSON_UNESCAPED_SLASHES) ?>;
    if(!pend||!pend.length)return;
    var run=pend.filter(function(x){return !x.done;})[0];
    if(run){dcWatch(run.account);dcShell(run.account,'<div class="dc-scanprog"><span></span></div><div class="fa-empty" style="padding:16px;text-align:center;color:var(--muted)">A scan for '+esc(run.account)+' is still running in the background…</div>',true);return;}
    var fin=pend.filter(function(x){return x.done;})[0];
    if(fin)dcRender(fin.account);
  })();
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

  /* ---------- Move account home to another partition ---------- */
  (function(){
    var tSel=document.getElementById('hmTarget');
    var bPrev=document.getElementById('hmPreview'), bMove=document.getElementById('hmMove');
    if(!bPrev) return;   // card not rendered (single partition)
    // ---- multi-account selection + batch move (concurrency capped by the server's capacity) ----
    function hmPicked(){return [].slice.call(document.querySelectorAll('.hm-u:checked')).map(function(c){return c.value;});}
    function hmCount(){var n=hmPicked().length;var s=document.getElementById('hmSelCount');
      if(s)s.textContent=n?(n+' account'+(n>1?'s':'')+' selected'):'none selected';
      bMove.disabled=true;bMove.title=n?'Preview first':'Select accounts and preview first';}
    document.addEventListener('change',function(e){
      if(e.target&&e.target.classList&&e.target.classList.contains('hm-u'))hmCount();
      if(e.target&&e.target.id==='hmAll'){var on=e.target.checked;[].slice.call(document.querySelectorAll('.hm-u')).forEach(function(c){c.checked=on;});hmCount();}
    });
    function hmBatchRender(b){
      var box=document.getElementById('hmBatch'); if(!box)return; box.style.display='block';
      var s=b.summary||null, cls={queued:'',running:'orange',moved:'good',failed:'red',skipped:'',cancelled:''};
      var rows=(b.accounts||[]).map(function(a){
        var pc=(a.status==='running'&&a.pct)?(' '+a.pct+'%'):'';
        var bar=(a.status==='running')?'<div class="hm-rowbar"><i style="width:'+Math.max(2,Math.min(100,a.pct||0))+'%"></i></div>':'';
        var can=(a.status==='running'||a.status==='moved'||a.status==='failed');
        return '<tr><td class="mono"><b>'+esc(a.user)+'</b></td>'
          +'<td><span class="b '+(cls[a.status]||'')+'">'+esc(a.status)+pc+'</span>'+bar+'</td>'
          +'<td class="meta">'+esc(a.live||a.msg||'')
          +(can?' <button type="button" class="fa-lnk hmDet" data-u="'+esc(a.user)+'">details</button>':'')
          +'<div class="hm-steps hm-rowsteps" id="hmDet_'+esc(a.user)+'" style="display:none"></div></td></tr>';}).join('');
      box.innerHTML='<div class="hm-batch">'
        +'<div class="hm-batch-h"><b>Batch move</b><span class="meta">'+esc(b.target||'')+' · '+(b.threads_effective||b.threads||1)+' at a time</span>'
        +(b.done?'<button class="fa-lnk" type="button" id="hmBatchClear" style="margin-left:auto">Clear report</button>'
                :'<button class="fa-lnk" type="button" id="hmBatchCancel" style="margin-left:auto;color:var(--dang);border-color:#f3c9c9">Cancel remaining</button>')+'</div>'
        +(s?'<div class="hm-batch-s"><span class="b good">'+s.moved+' moved</span> <span class="b '+(s.failed?'red':'')+'">'+s.failed+' failed</span> <span class="meta">of '+s.total+'</span></div>':'')
        +'<table class="smpro-table"><thead><tr><th>Account</th><th>Status</th><th>Detail</th></tr></thead><tbody>'+rows+'</tbody></table>'
        +(b.done?'':'<div class="meta" style="padding:8px 12px">This keeps running if you close the page — come back any time.</div>')
        +'</div>';
    }
    var hmBPoll=null;
    function hmBatchWatch(){ if(hmBPoll)clearInterval(hmBPoll);
      hmBPoll=setInterval(function(){ dsPost('home_batch_status',{}).then(function(j){
        if(!j||!j.exists){clearInterval(hmBPoll);hmBPoll=null;return;}
        hmBatchRender(j.batch||{});
        if(j.batch&&j.batch.done){clearInterval(hmBPoll);hmBPoll=null;}
      }).catch(function(){}); },3000); }
    document.addEventListener('click',function(e){
      if(e.target&&e.target.id==='hmBatchCancel'){ if(!confirm('Cancel the remaining accounts?\n\nAccounts already copying will finish (stopping mid-copy would leave them half-copied). Nothing new will start.'))return;
        dsPost('home_batch_cancel',{}).then(function(){}); }
      if(e.target&&e.target.id==='hmBatchClear'){ dsPost('home_batch_clear',{}).then(function(){var b=document.getElementById('hmBatch');if(b){b.style.display='none';b.innerHTML='';}}); }
      // per-account "details" → the SAME readable timeline, inline in the row. No JSON, no console.
      var d=e.target.closest&&e.target.closest('.hmDet');
      if(d){ var u=d.getAttribute('data-u'), box=document.getElementById('hmDet_'+u);
        if(!box)return;
        if(box.style.display!=='none'){box.style.display='none';d.textContent='details';return;}
        box.style.display='block'; d.textContent='hide'; box.innerHTML='<div class="hm-steps-h">Loading…</div>';
        var tick=function(){
          dsPost('home_move_status',{acct:u}).then(function(st){
            if(!st||(!st.log&&!st.bytes_total)){box.innerHTML='<div class="hm-steps-h">No detail recorded for this account yet.</div>';return;}
            renderDetail(box,u,st);
            if(!st.done&&box.style.display!=='none')setTimeout(tick,3000);   // keep it live while open
          }).catch(function(){box.innerHTML='<div class="hm-steps-h">Could not load the detail.</div>';});
        };
        tick();
      }
    });
    dsPost('home_batch_status',{}).then(function(j){ if(j&&j.exists){hmBatchRender(j.batch||{}); if(j.batch&&!j.batch.done)hmBatchWatch();} }).catch(function(){});
    // recompute the cap when the target partition changes (a spinning target lowers it)
    if(tSel)tSel.addEventListener('change',function(){
      dsPost('home_capacity',{hm_target:tSel.value}).then(function(j){
        if(!j||!j.ok||!j.capacity)return; var c=j.capacity, th=document.getElementById('hmThreads'); if(!th)return;
        var cur=Math.min(parseInt(th.value||'1',10),c.max);
        th.innerHTML=''; for(var i=1;i<=c.max;i++){var o=document.createElement('option');o.value=i;o.textContent=i+(i===c.recommended?' (recommended)':'');th.appendChild(o);}
        th.value=cur||c.recommended;
      }).catch(function(){});
    });
    var pfBox=document.getElementById('hmPreflight'), prog=document.getElementById('hmProgress'), pmsg=document.getElementById('hmProgMsg');
    var hmPoll=null;
    function esc(s){return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
    // Preview EVERY selected account so the admin sees which ones can move and which cannot, before starting.
    bPrev.addEventListener('click',function(){
      var list=hmPicked(), t=tSel.value;
      if(!list.length){pfBox.style.display='block';pfBox.innerHTML='<span class="b red">Select at least one account first.</span>';return;}
      bPrev.disabled=true; pfBox.style.display='block'; pfBox.innerHTML='<span class="meta">Checking '+list.length+' account(s)…</span>';
      var out=[], okc=0, i=0;
      (function next(){
        if(i>=list.length){
          bPrev.disabled=false;
          pfBox.innerHTML='<div style="border:1px solid var(--line);border-radius:10px;padding:10px 12px">'
            +'<div style="font-size:12px;margin-bottom:6px"><b>'+okc+'</b> of '+list.length+' account(s) can move to <span class="mono">'+esc(t)+'</span></div>'
            +out.join('')+'</div>';
          bMove.disabled=okc===0; bMove.title=okc?'':'No selected account passed pre-flight';
          return;
        }
        var u=list[i++];
        dsPost('preview_home_move',{hm_user:u,hm_target:t}).then(function(j){
          var pf=j&&j.preflight;
          if(pf&&pf.ok){okc++;out.push('<div style="font-size:12px;padding:2px 0"><span class="b good">✓</span> <b>'+esc(u)+'</b> <span class="meta">'+esc(pf.src||'')+' → '+esc(pf.dst||'')+'</span></div>');}
          else{var bad=[];((pf&&pf.checks)||[]).forEach(function(c){if(!c.ok)bad.push(c.label);});
            out.push('<div style="font-size:12px;padding:2px 0"><span class="b red">✗</span> <b>'+esc(u)+'</b> <span class="meta">'+esc(bad.slice(0,2).join('; ')||((j&&j.msg)||'pre-flight failed'))+'</span></div>');}
          next();
        }).catch(function(){out.push('<div style="font-size:12px"><span class="b red">✗</span> '+esc(u)+' — request failed</div>');next();});
      })();
    });
    /* Readable activity timeline — plain sentences in the card. Never raw job data, never a console. */
    var STEP_LABEL={queued:'Queued',starting:'Starting',rsync:'Copying files',delta:'Final sync',
                    flip:'Switching over',rebuild:'Rebuilding config',catchup:'Catching up changes',
                    verify:'Verifying',cleanup:'Cleaning up',done:'Finished',error:'Problem'};
    function hhmm(ts){var d=new Date((+ts||0)*1000);function p(n){return (n<10?'0':'')+n;}return p(d.getHours())+':'+p(d.getMinutes())+':'+p(d.getSeconds());}
    function renderSteps(box,log,done){
      if(!box)return;
      if(!log||!log.length){box.innerHTML='';return;}
      var last=log.length-1;
      box.innerHTML='<div class="hm-steps-h">What is happening</div>'+log.map(function(s,i){
        var cur=(i===last)&&!done, bad=(s.phase==='error');
        var cls=bad?'bad':(cur?'cur':'ok');
        var icon=bad?'&#10005;':(cur?'<span class="hm-spin"></span>':'&#10003;');
        return '<div class="hm-step '+cls+'">'
             +'<span class="hm-step-i">'+icon+'</span>'
             +'<span class="hm-step-t">'+esc(STEP_LABEL[s.phase]||s.phase||'')+'</span>'
             +'<span class="hm-step-m">'+esc(s.msg||'')+'</span>'
             +'<span class="hm-step-x">'+hhmm(s.ts)+'</span></div>';
      }).join('');
      box.scrollTop=box.scrollHeight;
    }
    /* Full per-account detail: where it is going, how much has moved, how long is left, how many files are
       done, which file is copying right now, and the last few that finished — then the step timeline. */
    function renderDetail(box,user,st){
      var pct=Math.max(0,Math.min(100,st.pct||0));
      var facts=[
        ['Account', user],
        ['Moving', (st.src||'?')+' &rarr; '+(st.dst||'?')],
        ['Copied', humb(st.bytes_done)+' of '+humb(st.bytes_total)+' ('+pct+'%)'],
        ['Speed', st.rate_bps?humb(st.rate_bps)+'/s':'—'],
        ['Time left', st.eta_sec?dur(st.eta_sec)+(st.eta_at?' (about '+esc(st.eta_at)+')':''):(st.done?'finished':'—')],
        ['Running for', st.elapsed_sec?dur(st.elapsed_sec):'—'],
        ['Files copied', (st.files_done||0).toLocaleString()]
      ];
      var h='<div class="hm-steps-h">Move details &mdash; '+esc(user)+'</div>'
        +'<div class="hm-dbar"><i style="width:'+Math.max(2,pct)+'%"></i></div>'
        +'<div class="hm-facts">'+facts.map(function(f){
            return '<div class="hm-fact"><span>'+f[0]+'</span><b>'+(f[0]==='Moving'?f[1]:esc(String(f[1])))+'</b></div>';}).join('')+'</div>';
      if(st.current_file&&!st.done)
        h+='<div class="hm-nowfile"><span class="hm-spin"></span> <span class="hm-nf-l">Copying now</span> <code>'+esc(st.current_file)+'</code></div>';
      var rf=(st.recent_files||[]).slice().reverse();
      if(rf.length)
        h+='<div class="hm-filelist"><div class="hm-fl-h">Recently copied ('+(st.files_done||0).toLocaleString()+' files so far)</div>'
          +rf.map(function(f){return '<div class="hm-file">&#10003; <code>'+esc(f)+'</code></div>';}).join('')+'</div>';
      box.innerHTML=h;
      var tl=document.createElement('div'); tl.className='hm-steps'; tl.style.margin='9px 0 0'; tl.style.maxHeight='150px';
      renderSteps(tl,st.log,st.done);
      if(st.log&&st.log.length)box.appendChild(tl);
    }
    function humb(b){b=+b||0;var u=['B','KB','MB','GB','TB'],i=0;while(b>=1024&&i<4){b/=1024;i++;}return (i>1?b.toFixed(1):Math.round(b))+' '+u[i];}
    function dur(s){s=+s||0;if(s<60)return s+'s';if(s<3600)return Math.floor(s/60)+'m '+(s%60)+'s';return Math.floor(s/3600)+'h '+Math.floor((s%3600)/60)+'m';}
    function setTxt(id,v){var e=document.getElementById(id);if(e)e.textContent=v;}
    function startPoll(){ if(hmPoll)clearInterval(hmPoll); prog.style.display='block';
      hmPoll=setInterval(function(){ dsPost('home_move_status',{}).then(function(st){ if(!st)return;
        if(pmsg)pmsg.textContent=(st.phase||'')+' — '+esc(st.msg||'');
        var bar=document.getElementById('hmBar'); if(bar)bar.style.width=Math.max(1,Math.min(100,st.pct||0))+'%';
        setTxt('hmPct',(st.pct||0)+'%');
        setTxt('hmWho', st.account ? (st.account+'  '+(st.src||'')+' → '+(st.dst||'')) : '—');
        setTxt('hmStart', st.started_h||'—');
        setTxt('hmElapsed', st.elapsed_sec?dur(st.elapsed_sec):'—');
        setTxt('hmRate', st.rate_bps?humb(st.rate_bps)+'/s':'—');
        setTxt('hmEta', st.eta_at?(st.eta_at+' ('+dur(st.eta_sec)+' left)'):'—');
        if(st.bytes_total>0)setTxt('hmPct',(st.pct||0)+'%  ·  '+humb(st.bytes_done)+' / '+humb(st.bytes_total));
        renderSteps(document.getElementById('hmSteps'), st.log, st.done);
        var rz=document.getElementById('hmResumed');
        if(rz){ if(st.resumed>0){rz.style.display='block';rz.innerHTML='&#8635; This move was interrupted and resumed automatically ('+st.resumed+'×) — it continues where it stopped.';}
                else if(st.stale){rz.style.display='block';rz.innerHTML='&#9203; No progress for a few minutes — the watchdog will restart it automatically.';}
                else rz.style.display='none'; }
        if(st.done){ clearInterval(hmPoll); hmPoll=null;
          var r=st.result||{ok:false,msg:st.msg}; prog.style.display='none';
          if(pfBox){pfBox.style.display='block';pfBox.innerHTML='<div class="ds-check '+(r.ok?'':'danger')+'"><div class="ds-checkbody"><div class="ds-checktt">'+(r.ok?'✅ ':'⚠ ')+esc(r.msg||'')+'</div></div></div>';}
          // Reload so free space + the follow-up banner refresh. A finalize/rollback ENDS the whole thing, so
          // the section folds itself away again; a completed move stays open because it still needs a decision.
          if(st.mode==='finalize'||st.mode==='rollback'){var c=document.getElementById('hmCard');if(c)c.removeAttribute('open');}
          setTimeout(function(){location.reload();},2500);
        }
      }).catch(function(){}); },2000);
    }
    bMove.addEventListener('click',function(){
      var list=hmPicked(), t=tSel.value, th=document.getElementById('hmThreads');
      var n=parseInt((th&&th.value)||'1',10)||1;
      if(!list.length)return;
      if(!confirm('Move '+list.length+' account(s) to '+t+'?\n\n'+list.slice(0,12).join(', ')+(list.length>12?', …':'')
        +'\n\nThey are copied '+n+' at a time so the server is not overloaded. Each site stays up during its copy, and each old copy is kept until you press "Delete the old copy".\n\nRuns in the background — you can close this page.'))return;
      bMove.disabled=true; bPrev.disabled=true;
      dsPost('home_batch_start',{hm_users:JSON.stringify(list),hm_target:t,hm_threads:n}).then(function(j){
        bPrev.disabled=false;
        if(!j||!j.ok){bMove.disabled=false;if(pfBox){pfBox.style.display='block';pfBox.innerHTML='<span class="b red">'+esc((j&&j.msg)||'Could not start')+'</span>';}return;}
        if(pfBox){pfBox.style.display='block';pfBox.innerHTML='<span class="b good">'+esc(j.msg||'Batch started.')+'</span>';}
        hmBatchWatch();
      }).catch(function(){bMove.disabled=false;bPrev.disabled=false;});
    });
    /* A batch can leave SEVERAL accounts awaiting reclaim/rollback, so each pending banner carries its own
       account and these are delegated (ids would collide across banners and only the first would ever work). */
    document.addEventListener('click',function(e){
      var v=e.target.closest&&e.target.closest('.hmVerify');
      if(v){
        var u=v.getAttribute('data-user')||'';
        var row=v.closest('.hmPendRow'), out=row?row.querySelector('.hmVerifyOut'):null;
        if(!out)return;
        v.disabled=true; out.textContent='Checking…'; out.className='meta hmVerifyOut';
        dsPost('home_move_verify',{acct:u}).then(function(j){
          v.disabled=false;
          if(!j||!j.ok){out.className='b red hmVerifyOut';out.textContent=(j&&j.msg)||'Check failed';return;}
          var bits=[];
          bits.push((j.home_ok?'✓':'✗')+' account on the new partition');
          bits.push((j.userdata_ok?'✓':'✗')+' cPanel config updated');
          if(j.site_code)bits.push((j.site_ok?'✓':'✗')+' site responds (HTTP '+esc(j.site_code)+')');
          out.className=(j.verified?'b good':'b red')+' hmVerifyOut';
          out.textContent=(j.verified?'Looks healthy — ':'Needs attention — ')+bits.join(' · ');
        }).catch(function(){v.disabled=false;out.className='b red hmVerifyOut';out.textContent='Check failed';});
        return;
      }
      var f=e.target.closest&&e.target.closest('.hmFinalize');
      if(f){
        var fu=f.getAttribute('data-user')||'', fs=f.getAttribute('data-size')||'';
        // typed confirmation: this is irreversible AND it removes the ability to undo
        var a=prompt('This permanently deletes the old copy of "'+fu+'" ('+fs+').\n\nAfter this you can NO LONGER undo the move.\nMake sure the site has been tested first.\n\nType the account name to confirm:');
        if(a===null)return;
        if(a.trim()!==fu){alert('The name did not match — nothing was deleted.');return;}
        f.disabled=true;
        dsPost('home_move_finalize',{acct:fu}).then(function(j){ if(j&&j.ok){startPoll();}else{f.disabled=false;alert((j&&j.msg)||'Could not start.');} });
        return;
      }
      var r=e.target.closest&&e.target.closest('.hmRollback');
      if(r){
        var ru=r.getAttribute('data-user')||'';
        if(!confirm('Undo the move?\n\n'+ru+' goes back to its original partition and the copied data on the new partition is removed. The account keeps working either way.'))return;
        r.disabled=true;
        dsPost('home_move_rollback',{acct:ru}).then(function(j){ if(j&&j.ok){startPoll();}else{r.disabled=false;alert((j&&j.msg)||'Could not start.');} });
        return;
      }
    });
    // if a move was already running when the page loaded, resume polling
    dsPost('home_move_status',{}).then(function(st){ if(st&&st.phase&&st.phase!=='idle'&&!st.done){ if(prog){prog.style.display='block';} startPoll(); } }).catch(function(){});
  })();
})();
</script>
<style>
/* ---- overview strip + sticky navigator + collapsible cards + folds + pager (pattern: firewall-status.php) ---- */
.fw-kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:12px 0}
@media(max-width:640px){.fw-kpis{grid-template-columns:repeat(2,1fr)}}
.fw-nav{position:sticky;top:calc(var(--toph,52px) + 6px);z-index:5;display:flex;gap:6px;flex-wrap:wrap;align-items:center;padding:8px 10px;margin:0 0 14px;background:var(--card);border:1px solid var(--line);border-radius:12px;box-shadow:0 2px 10px rgba(0,0,0,.05)}
.fw-nav a{font-size:12px;font-weight:700;text-decoration:none;color:var(--ink);padding:4px 10px;border-radius:20px;border:1px solid var(--line);white-space:nowrap}
.fw-toggle{cursor:pointer;user-select:none}.fw-toggle:hover{background:var(--bg)}
.gl-fold{margin:6px 0}.gl-fold>summary{cursor:pointer;list-style:none;font-size:12.5px;font-weight:700;color:var(--brand);display:flex;align-items:center;gap:6px}
.gl-fold>summary::-webkit-details-marker{display:none}
.gl-fold>summary .gl-chev{display:inline-block;transition:transform .15s;font-weight:800}.gl-fold[open]>summary .gl-chev{transform:rotate(90deg)}
.fw-pg{display:flex;gap:8px;align-items:center;flex-wrap:wrap;padding:8px 16px;border-bottom:1px solid var(--line);font-size:12px;color:var(--muted)}
.fw-pg input{border:1px solid var(--line);border-radius:8px;padding:5px 9px;font-size:12.5px;min-width:180px;background:var(--card);color:inherit}
.fw-pg .sp{flex:1}.fw-pg button{font-size:11.5px;font-weight:700;border:1px solid var(--line);border-radius:7px;padding:3px 9px;cursor:pointer;background:var(--card);color:var(--ink)}
.fw-pg button:disabled{opacity:.45;cursor:default}.fw-pg .n{font-variant-numeric:tabular-nums}
tr.fw-pghide{display:none !important}
</style>
<script>
(function(){
  // make every section card collapsible — click its header to open/close; the choice is remembered per section
  var KEY='smpro:disk-storage:open', SEL='.card > .ds-head', EXTRA='';
  var open={};
  try{ open=JSON.parse(localStorage.getItem(KEY)||'{}')||{}; }catch(err){ open={}; }
  function remember(){ try{ localStorage.setItem(KEY, JSON.stringify(open)); }catch(err){} }
  function toggleOf(card){ for(var i=0;i<card.children.length;i++){ var c=card.children[i]; if(c.classList&&c.classList.contains('fw-toggle')) return c; } return null; }
  function openCard(id, scroll){
    var el=document.getElementById(id); if(!el) return;
    var node=el;
    while(node && node!==document.body){
      if(node.classList && node.classList.contains('card')){ var th=toggleOf(node); if(th && !node.classList.contains('fw-open')){ node.classList.add('fw-open'); th.setAttribute('aria-expanded','true'); open[th.getAttribute('data-fold')]=true; remember(); } }
      if(node.tagName==='DETAILS' && !node.open) node.open=true;
      node=node.parentElement;
    }
    if(el.tagName!=='DETAILS' && el.classList.contains('card') && !toggleOf(el)){ var d=el.querySelector('details'); if(d && !d.open) d.open=true; }
    if(scroll){ el.style.scrollMarginTop='120px'; try{ el.scrollIntoView({behavior:'smooth',block:'start'}); }catch(e2){ el.scrollIntoView(); } }   // the page scrolls inside .smpro-main
  }
  var gos=document.querySelectorAll('[data-go]');
  for(var g=0;g<gos.length;g++){ (function(a){
    var tid=a.getAttribute('data-go');
    if(!document.getElementById(tid)){ if(a.parentElement && a.parentElement.classList.contains('fw-nav')) a.style.display='none'; return; }   // chip for a section this page does not have
    a.addEventListener('click',function(e){ e.preventDefault(); openCard(tid,true); var xs=document.querySelectorAll('.fw-nav a'); for(var i=0;i<xs.length;i++){ xs[i].classList.toggle('on', xs[i].getAttribute('data-go')===tid); } try{ history.replaceState(null,'','#'+tid); }catch(err){} });
  })(gos[g]); }
  function setAll(on){
    var cards=document.querySelectorAll('.smpro-main .card');
    for(var i=0;i<cards.length;i++){ var th=toggleOf(cards[i]); if(!th) continue; cards[i].classList.toggle('fw-open',on); th.setAttribute('aria-expanded',on?'true':'false'); open[th.getAttribute('data-fold')]=on; }
    if(EXTRA){ var ds=document.querySelectorAll(EXTRA); for(var k=0;k<ds.length;k++){ ds[k].open=on; } }
    remember();
  }
  var oa=document.getElementById('dsOpenAll'), ca=document.getElementById('dsCloseAll');
  if(oa) oa.addEventListener('click',function(){ setAll(true); });
  if(ca) ca.addEventListener('click',function(){ setAll(false); });
  var ths=document.querySelectorAll(SEL);
  for(var t=0;t<ths.length;t++){ (function(th, n){
    var card=th.parentElement; if(!card||!card.classList.contains('card')) return;
    var body=document.createElement('div'); body.className='fw-collapse';
    while(th.nextSibling){ body.appendChild(th.nextSibling); }
    card.appendChild(body);
    th.classList.add('fw-toggle');
    if(!th.querySelector('.fw-chev')) th.insertAdjacentHTML('afterbegin','<span class="fw-chev">&#9656;</span> ');
    // A stable name for this section: its own heading text (position would move every remembered state when a section is added above it).
    var id=(th.textContent||'').replace(/\s+/g,' ').trim().slice(0,60) || ('card'+n);
    th.setAttribute('data-fold', id);
    var closedByDefault=card.hasAttribute('data-fold-closed');
    var isOpen=Object.prototype.hasOwnProperty.call(open,id) ? !!open[id] : !closedByDefault;
    card.classList.toggle('fw-open', isOpen);
    th.setAttribute('role','button'); th.setAttribute('tabindex','0'); th.style.cursor='pointer'; th.setAttribute('aria-expanded', isOpen?'true':'false');
    function toggle(){ var now=card.classList.toggle('fw-open'); th.setAttribute('aria-expanded', now?'true':'false'); open[id]=now; remember(); }
    th.addEventListener('click',function(e){ if(e.target.closest('a,button,input,select,label,textarea,summary')) return; toggle(); });   // header controls keep working
    th.addEventListener('keydown',function(e){ if(e.key===' '||e.key==='Enter'||e.key==='Spacebar'){ e.preventDefault(); toggle(); } });
  })(ths[t], t); }
  if(location.hash && document.getElementById(location.hash.slice(1))) setTimeout(function(){ openCard(location.hash.slice(1), true); }, 150);
  window.smproOpenCard=openCard;

  // client-side filter + paging (50/page) for a PHP-rendered table: rows carry data-row, hidden rows get .fw-pghide
  function smproPager(tbl, opt){
    opt=opt||{}; var per=opt.per||50; if(!tbl||!tbl.tBodies||!tbl.tBodies[0]) return null;
    var tb=tbl.tBodies[0], rows=[], i;
    for(i=0;i<tb.rows.length;i++){ if(tb.rows[i].hasAttribute('data-row')) rows.push(tb.rows[i]); }
    if(rows.length<(opt.min||12)) return null;
    var wrap=tbl.parentElement, bar=document.createElement('div'); bar.className='fw-pg';
    bar.innerHTML=(opt.nofilter?'':'<input type="search" placeholder="'+(opt.ph||'Filter rows\u2026')+'">')+'<span class="sp"></span><span class="n fw-pginfo"></span><button type="button" class="fw-pgprev">&#8249; prev</button><span class="n fw-pgpos"></span><button type="button" class="fw-pgnext">next &#8250;</button>';
    wrap.parentElement.insertBefore(bar, wrap);
    var inp=bar.querySelector('input'), info=bar.querySelector('.fw-pginfo'), pos=bar.querySelector('.fw-pgpos'), prev=bar.querySelector('.fw-pgprev'), next=bar.querySelector('.fw-pgnext');
    var q='', page=0;
    function textOf(tr){ return (tr.getAttribute('data-search')||tr.textContent||'').replace(/\s+/g,' ').toLowerCase(); }
    function hide(tr,h){ tr.classList.toggle('fw-pghide',h); if(opt.follow){ var nx=tr.nextElementSibling; if(nx&&nx.classList.contains(opt.follow)) nx.classList.toggle('fw-pghide',h); } }
    function draw(){
      var view=[]; for(var k=0;k<rows.length;k++){ var tr=rows[k]; var ok=(!q||textOf(tr).indexOf(q)!==-1) && !(opt.skip&&opt.skip(tr)); if(ok) view.push(tr); else hide(tr,true); }
      var pages=Math.max(1,Math.ceil(view.length/per)); if(page>=pages) page=pages-1; if(page<0) page=0;
      for(var j=0;j<view.length;j++){ hide(view[j], j<page*per || j>=(page+1)*per); }
      var a=view.length?page*per+1:0, b=Math.min((page+1)*per,view.length);
      info.textContent=(view.length>per?('showing '+a+'\u2013'+b+' of '):'')+view.length+' of '+rows.length+' rows';
      pos.textContent=(page+1)+' / '+pages; prev.disabled=page<=0; next.disabled=page>=pages-1;
      var ctrl=rows.length>per?'':'none'; prev.style.display=ctrl; next.style.display=ctrl; pos.style.display=ctrl;
    }
    if(inp) inp.addEventListener('input',function(){ q=inp.value.trim().toLowerCase(); page=0; draw(); });
    prev.addEventListener('click',function(){ if(page>0){ page--; draw(); } });
    next.addEventListener('click',function(){ page++; draw(); });
    draw(); return {draw:draw};
  }
  window.smproPager=smproPager;

  var fsC=document.getElementById('ds-fs'); if(fsC) smproPager(fsC.querySelector('table.smpro-table'), {ph:'Filter mounts\u2026'});
  var acC=document.getElementById('ds-accts'); if(acC) smproPager(acC.querySelector('table.smpro-table'), {ph:'Filter accounts / domains\u2026'});
})();
</script>

<?php
smpro_layout_footer();
