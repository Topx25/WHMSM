<?php
/**
 * modules/forensics-audit.php — Forensics / Audit (read-only investigation).
 *
 * A full investigation section, shared-hosting safe:
 *  - Findings dashboard: consolidated, explained findings (severity, confidence,
 *    what-it-means, recommended action, evidence) from LIGHT sources only —
 *    Imunify360 active threats + persistence checks (cron / SSH keys / dotfiles).
 *    Cached (5 min) so navigation is instant; "Re-scan" forces a fresh sweep.
 *  - Saved Reports: snapshot findings to disk (90-day retention), multi-select
 *    delete (AJAX), export CSV / HTML / PDF — same pattern as Account Audit.
 *  - Deep file scans (recent PHP / PHP-in-uploads / .htaccess) stay ON-DEMAND,
 *    single-account, throttled (timeout + nice + ionice). Never auto-scans /home.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

define('SMPRO_FA_LIMIT',     300);
define('SMPRO_FA_REPORTS',   SMPRO_VARLIB . '/reports/forensics');
define('SMPRO_FA_REPIDX',    SMPRO_VARLIB . '/reports/forensics/index.json');
define('SMPRO_FA_RETENTION', 90 * 86400);
define('SMPRO_FA_CACHE',     SMPRO_VARLIB . '/cache/forensics');
define('SMPRO_FA_CACHE_TTL', 300);

/* ---------- small json store ---------- */
function smpro_fa_json_load($p) { $d = is_file($p) ? json_decode((string)@file_get_contents($p), true) : null; return is_array($d) ? $d : []; }
function smpro_fa_json_save($p, $d) { @is_dir(dirname($p)) || @mkdir(dirname($p), 0700, true); $t = $p . '.tmp'; @file_put_contents($t, json_encode($d, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE), LOCK_EX); @rename($t, $p); @chmod($p, 0600); }

define('SMPRO_FA_ALLOW', SMPRO_VARLIB . '/state/fa_key_allowlist.json');

/* ---------- trusted-key allowlist (suppress known-good keys from findings) ---------- */
function smpro_fa_allow_load() { return smpro_fa_json_load(SMPRO_FA_ALLOW); }
function smpro_fa_key_parts($keyline) {
    if (preg_match('/(ssh-\S+|ecdsa-\S+|sk-\S+)\s+(\S+)\s*(.*)$/i', (string)$keyline, $m)) return ['type'=>$m[1],'mat'=>$m[2],'comment'=>trim($m[3]) ?: '(no comment)'];
    return ['type'=>'?','mat'=>trim((string)$keyline),'comment'=>''];
}
function smpro_fa_key_sig($account, $keyline) {
    $p = smpro_fa_key_parts($keyline);
    return substr(hash('sha256', $account . '|' . $p['mat']), 0, 24);
}
function smpro_fa_allow_add($account, $keyline) {
    $sig = smpro_fa_key_sig($account, $keyline); $p = smpro_fa_key_parts($keyline);
    $a = smpro_fa_allow_load();
    $a[$sig] = ['sig'=>$sig,'account'=>$account,'type'=>$p['type'],'comment'=>$p['comment'],'added_at'=>date('c'),'added_ts'=>time()];
    smpro_fa_json_save(SMPRO_FA_ALLOW, $a); return $sig;
}
function smpro_fa_allow_remove($sig) {
    $sig = preg_replace('/[^a-f0-9]/', '', (string)$sig); if ($sig === '') return false;
    $a = smpro_fa_allow_load(); if (!isset($a[$sig])) return false;
    unset($a[$sig]); smpro_fa_json_save(SMPRO_FA_ALLOW, $a); return true;
}

function smpro_fa_users() { $u = []; foreach (glob('/var/cpanel/users/*') ?: [] as $f) { $b = basename($f); if (preg_match('/^[a-zA-Z0-9._-]+$/', $b)) $u[] = $b; } sort($u); return $u; }
function smpro_fa_path($user) { if ($user === 'all' || $user === '') return '/home'; if (!preg_match('/^[a-zA-Z0-9._-]+$/', $user) || !is_dir(smpro_user_home($user))) return ''; return smpro_user_home($user); }
function smpro_fa_wrap($inner, $t = 90) { return 'timeout ' . $t . ' nice -n ' . SMPRO_SCAN_NICE . ' ionice -c3 ' . $inner; }

/* ===========================================================================
 *  FINDINGS — the consolidated, explained investigation data (light sources).
 *  Each finding: sev, conf, cat, account, title, evidence, ref, means, action.
 * ========================================================================= */
function smpro_fa_sevrank($s) { return ['critical'=>4,'high'=>3,'medium'=>2,'info'=>1][$s] ?? 0; }

function smpro_fa_collect_findings($user) {
    $f = [];
    $scope = ($user === 'all' || $user === '') ? '' : $user;

    /* 1) Imunify360 active malware — CRITICAL, high confidence */
    if (is_executable('/usr/bin/imunify360-agent')) {
        $j = json_decode((string)@shell_exec('timeout 30 /usr/bin/imunify360-agent malware malicious list --limit 500 --json 2>/dev/null'), true);
        foreach (($j['items'] ?? []) as $r) {
            $acct = (string)($r['username'] ?? '');
            if ($scope !== '' && $acct !== $scope) continue;
            $fam = preg_match('/SMW-[A-Z]+-\d+-(.+?)-\d+$/', (string)($r['type'] ?? ''), $m) ? $m[1] : ((string)($r['type'] ?? '') ?: 'malware');
            $mfile = (string)($r['file'] ?? '');
            if ($mfile !== '' && function_exists('smpro_wpguard_trusted') && smpro_wpguard_trusted($mfile)) continue;   // trusted WP Guard file / neutralized quarantine → not a finding
            // Imunify keeps CLEANED files on the malicious list with status "cleanup_done" — the file still
            // exists on disk but the infection is gone. Reporting those as live CRITICAL malware buried the
            // real detections under a mass of false alarms (they dominate the list on a cleaned server).
            $mStatus = strtolower((string)($r['status'] ?? ''));
            if ($mStatus === 'cleanup_done') continue;
            $mGone = $mfile !== '' && strpos($mfile, '/home/') === 0 && !@is_file($mfile);   // listed but already removed from disk
            $f[] = [
                'sev'=> $mGone ? 'high' : 'critical','conf'=>'high','cat'=>'Active malware','account'=>$acct,
                'title'=>'Infected file flagged by Imunify360 (' . $fam . ')' . ($mGone ? ' — already removed' : ''),
                'evidence'=>$mfile . (!empty($r['hash']) ? '  ·  SHA-256 ' . substr($r['hash'],0,16) . '…' : ''),
                'ref'=>$mfile,
                'means'=> $mGone
                    ? 'Imunify360 still lists this file, but it is NO LONGER on disk — it was already cleaned or quarantined. Only a stale list entry remains; there is nothing to delete.'
                    : 'Imunify360 detected active malware that is still present on disk. The file is live and can be executed by an attacker right now.',
                'action'=> $mGone
                    ? 'Clear the stale entry from Imunify’s list (Remove from list). The file is already gone.'
                    : 'Clean or remove the file, then close the entry vector (vulnerable plugin / stolen password). Scan the whole account for more shells.',
                'ts'=>isset($r['created']) ? (int)$r['created'] : 0,
                'raw'=>'', 'imid'=>(string)($r['id'] ?? ''), 'hash'=>(string)($r['hash'] ?? ''), 'stale'=>$mGone,
                'act'=> !empty($r['id']) ? 'malware_quarantine' : '', 'actlabel'=>'Clean (Imunify)',
            ];
        }
    }

    /* 2) Cron persistence — CRITICAL when high-confidence pattern matches */
    $sus = '/base64|\beval\b|\/tmp\/|\/dev\/shm|\/dev\/tcp|\bnc\b\s+-|python\s+-c|perl\s+-e|\bcurl\b[^|\n]*\|\s*(?:ba)?sh|\bwget\b[^|\n]*\|\s*(?:ba)?sh|\/\.[a-z0-9_.-]+\.(?:sh|php|pl|py)\b/i';
    $cronFiles = $scope === '' ? array_merge(glob('/var/spool/cron/*') ?: [], ['/etc/crontab'], glob('/etc/cron.d/*') ?: []) : ['/var/spool/cron/' . $scope];
    foreach ($cronFiles as $cf) {
        if (!is_readable($cf)) continue;
        $acct = basename($cf) === 'crontab' ? 'system' : basename($cf);
        $mt = (int)@filemtime($cf);
        foreach (file($cf, FILE_IGNORE_NEW_LINES) ?: [] as $ln) {
            $ln = trim($ln); if ($ln === '' || $ln[0] === '#') continue;
            if (!preg_match($sus, $ln)) continue;
            $f[] = [
                'sev'=>'critical','conf'=>'high','cat'=>'Persistence (cron)','account'=>$acct,
                'title'=>'Suspicious scheduled task (re-infection / backdoor)',
                'evidence'=>$ln,'ref'=>$cf,
                'means'=>'A cron job runs attacker code on a schedule. It re-downloads or re-launches a payload, so the infection survives cleanup and reboots.',
                'action'=>'Remove this cron line and any payload it fetches, then rotate the account credentials. Check what URL/script it pulls from.',
                'ts'=>$mt,
                'raw'=>$ln, 'imid'=>'', 'act'=>'cron_disable', 'actlabel'=>'Disable cron line',
            ];
        }
    }

    /* 3) SSH authorized_keys — passwordless access / persistence (trusted keys suppressed) */
    $allow = smpro_fa_allow_load();
    $keyFiles = $scope === '' ? array_merge(['/root/.ssh/authorized_keys'], glob('/home/*/.ssh/authorized_keys') ?: []) : [smpro_user_home($scope) . '/.ssh/authorized_keys'];
    foreach ($keyFiles as $kf) {
        if (!is_readable($kf)) continue;
        $isRoot = strpos($kf, '/root/') !== false;
        $acct = $isRoot ? 'root' : (preg_match('#/home/([^/]+)/#', $kf, $m) ? $m[1] : '?');
        $mt = (int)@filemtime($kf);
        foreach (file($kf, FILE_IGNORE_NEW_LINES) ?: [] as $ln) {
            $ln = trim($ln); if ($ln === '' || $ln[0] === '#') continue;
            if (!preg_match('/^(?:[a-z0-9-]+\s+)?(ssh-\S+|ecdsa-\S+|sk-\S+)\s+\S+\s*(.*)$/i', $ln, $m)) continue;
            if (stripos($ln, 'smpro') !== false) continue;             // our own management key — known-good, never flag
            if (isset($allow[smpro_fa_key_sig($acct, $ln)])) continue;   // user-trusted — do not flag
            $cmt = trim($m[2]) ?: '(no comment)';
            $f[] = [
                'sev'=> $isRoot ? 'high' : 'medium','conf'=>'medium','cat'=>'SSH key access','account'=>$acct,
                'title'=> $isRoot ? 'Authorized SSH key on root account' : 'Authorized SSH key on a hosting account',
                'evidence'=>$m[1] . '  ·  ' . $cmt,'ref'=>$kf,
                'means'=> $isRoot
                    ? 'This public key grants passwordless root login. If you did not add it, an attacker holds permanent root access that no password change removes.'
                    : 'This public key allows passwordless SSH to the account — uncommon for hosting customers and a known persistence trick.',
                'action'=> $isRoot
                    ? 'Verify the key fingerprint/owner. Remove any key you do not recognise from /root/.ssh/authorized_keys.'
                    : 'Confirm the customer added it. If not, remove it from the account\'s authorized_keys.',
                'ts'=>$mt,
                'raw'=>$ln, 'imid'=>'',
                'act'=>'sshkey_remove', 'actlabel'=>'Remove key',
            ];
        }
    }

    /* 4) Shell-init / PHP-ini injections — login-time exec */
    $dsus = '/curl|wget|base64|eval|python\s+-c|perl\s+-e|\bnc\b|\/dev\/tcp|history\s*-c|chattr|auto_prepend|auto_append/i';
    $homes = $scope === '' ? array_slice(glob('/home/*', GLOB_ONLYDIR) ?: [], 0, 600) : [smpro_user_home($scope)];
    foreach ($homes as $h) {
        $acct = basename($h);
        foreach (['.bashrc','.bash_profile','.profile','.user.ini'] as $df) {
            $p = $h . '/' . $df; if (!is_readable($p)) continue;
            foreach (file($p, FILE_IGNORE_NEW_LINES) ?: [] as $ln) {
                if (trim($ln) === '' || trim($ln)[0] === '#') continue;
                if (!preg_match($dsus, $ln)) continue;
                $f[] = [
                    'sev'=>'high','conf'=>'medium','cat'=>'Shell-init injection','account'=>$acct,
                    'title'=>'Suspicious line in ' . $df,
                    'evidence'=>trim($ln),'ref'=>$p,
                    'means'=>'Shell startup files (.bashrc/.profile) and .user.ini can silently run commands at login or change PHP execution. Attackers hide reinfection or credential theft here.',
                    'action'=>'Inspect the line; remove the injected command and restore a clean dotfile from a known-good backup.',
                    'ts'=>(int)@filemtime($p),
                    'raw'=>trim($ln), 'imid'=>'', 'act'=>'dotfile_comment', 'actlabel'=>'Comment out line',
                ];
                if (count($f) > 800) break 3;
            }
        }
    }

    usort($f, fn($a,$b) => smpro_fa_sevrank($b['sev']) <=> smpro_fa_sevrank($a['sev']) ?: ($b['ts'] <=> $a['ts']));
    return $f;
}

/* ===========================================================================
 *  REMEDIATION — executable, reversible actions on a finding.
 *  Safety rails: allowed-path whitelist, backup before edit, preserve owner/
 *  mode, never touch the Safety Monitor management key, audit + CSRF + root.
 * ========================================================================= */
define('SMPRO_FA_QUAR', SMPRO_VARLIB . '/quarantine/forensics');
define('SMPRO_FA_MANIFEST', SMPRO_VARLIB . '/quarantine/forensics/manifest.json');

function smpro_fa_allowed_target($action, $file) {
    // SECURITY: reject a symlink target outright — a customer owns /home/<acct>/ and could replace
    // .bashrc / .ssh/authorized_keys with a symlink to /root/... or /etc/shadow; the backup-copy would
    // then leak that root file. (Also blocks a symlinked path component via the realpath re-check below.)
    if (is_link($file)) return false;
    $ok = false;
    if ($action === 'cron_disable')         $ok = ($file === '/etc/crontab' || strpos($file, '/var/spool/cron/') === 0 || strpos($file, '/etc/cron.d/') === 0);
    elseif ($action === 'dotfile_comment')  $ok = (bool)preg_match('#^/home/[^/]+/\.(bashrc|bash_profile|profile|user\.ini)$#', $file);
    elseif ($action === 'sshkey_remove')    $ok = (bool)preg_match('#^(?:/root|/home/[^/]+)/\.ssh/authorized_keys$#', $file);
    if (!$ok) return false;
    // the resolved real path must STILL equal the (canonical) allowed path — any symlink/.. resolution = reject
    $rp = @realpath($file);
    if ($rp === false) return false;
    if ($rp === $file) return true;
    // Allow a SERVER-LEVEL /home symlink (e.g. /home -> /home2, or accounts on /home2/home3): resolve ONLY
    // the /home prefix and keep the account + suffix literal. An attacker symlink (a parent dir or the
    // target pointing at /root or another account) makes the fully-resolved $rp differ from this → rejected.
    if (strpos($file, '/home/') === 0) {
        $homeReal = @realpath('/home');
        if ($homeReal !== false && $homeReal !== '/home' && $rp === $homeReal . substr($file, 5)) return true;
    }
    return false;
}
/** True if a path is one of the file types this module is ever allowed to write. */
function smpro_fa_path_whitelisted($f) {
    return $f === '/etc/crontab' || strpos($f, '/var/spool/cron/') === 0 || strpos($f, '/etc/cron.d/') === 0
        || preg_match('#^/home/[^/]+/\.(bashrc|bash_profile|profile|user\.ini)$#', $f)
        || preg_match('#^(?:/root|/home/[^/]+)/\.ssh/authorized_keys$#', $f);
}
/* ---- remediation history (manifest) for the Restore center ---- */
function smpro_fa_manifest_load() { return smpro_fa_json_load(SMPRO_FA_MANIFEST); }
function smpro_fa_manifest_add($entry) {
    $m = smpro_fa_manifest_load();
    $id = date('Ymd_His') . '_' . substr(hash('sha256', ($entry['file'] ?? '') . ($entry['imid'] ?? '') . uniqid('', true)), 0, 8);
    $entry['id'] = $id; $entry['status'] = 'applied'; $entry['applied_ts'] = time();
    $m[$id] = $entry; smpro_fa_json_save(SMPRO_FA_MANIFEST, $m);
    return $id;
}
/** Per-action detection report (one file per destructive action, esp. deletions). */
function smpro_fa_detection_report($d) {
    $dir = SMPRO_VARLIB . '/reports/detections';
    @is_dir($dir) || @mkdir($dir, 0700, true);
    $id = date('Ymd_His') . '_' . substr(hash('sha256', json_encode($d) . uniqid('', true)), 0, 8);
    $d['id'] = $id; $d['at'] = date('c'); $d['ts'] = time();
    smpro_fa_json_save($dir . '/' . $id . '.json', $d);
    return $id;
}
function smpro_fa_detection_reports($limit = 50) {
    $rows = [];
    foreach (glob(SMPRO_VARLIB . '/reports/detections/*.json') ?: [] as $f) { $d = smpro_fa_json_load($f); if ($d) $rows[] = $d; }
    usort($rows, fn($a,$b)=>($b['ts'] ?? 0) <=> ($a['ts'] ?? 0));
    return array_slice($rows, 0, $limit);
}
function smpro_fx_file_owner($file) {   // was smpro_fa_account_of: includes/fileaudit.php declares a DIFFERENT function under that name, and both can load on one page
    if (preg_match('#^/home/([^/]+)/#', $file, $m)) return $m[1];
    if (strpos($file, '/root/') === 0) return 'root';
    if (strpos($file, '/var/spool/cron/') === 0) return basename($file);
    return 'system';
}
function smpro_fa_backup($file) {
    @is_dir(SMPRO_FA_QUAR) || @mkdir(SMPRO_FA_QUAR, 0700, true);
    $b = SMPRO_FA_QUAR . '/' . date('Ymd_His') . '_' . preg_replace('/[^a-zA-Z0-9._-]/', '_', ltrim($file, '/')) . '.bak';
    @copy($file, $b); @chmod($b, 0600);
    return $b;
}
function smpro_fa_rewrite($file, $lines) {
    // SECURITY: the account owner controls their /home dir. The old code wrote to a PREDICTABLE
    // "$file.smprotmp" via symlink-following file_put_contents — an account could pre-plant that path as a
    // symlink to /root/.ssh/authorized_keys and have root write the (still attacker-controlled) rewritten
    // content through it = root SSH. Now: reject a symlinked target, and write to an UNPREDICTABLE O_EXCL
    // temp (a planted symlink makes fopen 'xb' fail rather than being followed), then atomic-rename.
    if (is_link($file)) return false;
    // SECURITY (privesc, race): smpro_fa_allowed_target() validated the parent's realpath in a SEPARATE
    // earlier function, with a file-read window in between. A customer could swap a directory component
    // (e.g. .ssh → /root/.ssh) during that window and redirect the O_EXCL-temp + rename below into a root
    // dir = root SSH overwrite. Re-verify the parent HERE, at write time: realpath(dirname) must equal the
    // literal parent (only a server-level /home → /home2 symlink is tolerated, same rule as allowed_target).
    $dir = dirname($file); $rpDir = @realpath($dir);
    if ($rpDir === false) return false;
    $okDir = ($rpDir === $dir);
    if (!$okDir && strpos($dir, '/home/') === 0) {
        $homeReal = @realpath('/home');
        $okDir = ($homeReal !== false && $homeReal !== '/home' && $rpDir === $homeReal . substr($dir, 5));
    }
    if (!$okDir) return false;
    $file = $rpDir . '/' . basename($file);          // canonical (symlink-free) parent + literal leaf
    if (is_link($file)) return false;                // leaf swapped to a symlink after the parent check
    $uid = @fileowner($file); $gid = @filegroup($file); $perm = @fileperms($file) & 0777;
    $tmp = $file . '.smpro-' . substr(bin2hex(@random_bytes(6) ?: pack('N', mt_rand())), 0, 12) . '.tmp';
    $fh = @fopen($tmp, 'xb');                                        // O_CREAT|O_EXCL → fails on a planted symlink/file
    if ($fh === false) return false;
    $ok = @fwrite($fh, implode("\n", $lines) . "\n") !== false;
    @fclose($fh);
    if (!$ok) { @unlink($tmp); return false; }
    if ($uid !== false) @chown($tmp, $uid);                         // set ownership on the file WE created, never a symlink
    if ($gid !== false) @chgrp($tmp, $gid);
    if ($perm) @chmod($tmp, $perm);
    if (!@rename($tmp, $file)) { @unlink($tmp); return false; }     // atomic; replaces a swapped symlink instead of following it
    return true;
}
function smpro_fa_remediate($action, $file, $rawLine, $imid) {
    /* Imunify cleanup — ASYNC (queued). Keeps an original backup, restorable via restore-original. */
    if ($action === 'malware_quarantine') {
        if (!is_executable('/usr/bin/imunify360-agent')) return ['ok'=>false,'msg'=>'Imunify360 not available.'];
        $id = preg_replace('/[^0-9]/', '', (string)$imid);
        if ($id === '') return ['ok'=>false,'msg'=>'Missing malware id.'];
        $out = (string)@shell_exec('timeout 90 /usr/bin/imunify360-agent malware malicious cleanup --items ' . $id . ' --json 2>&1');
        $j = json_decode($out, true);
        $err = is_array($j) ? (($j['success'] ?? null) === false) : (stripos($out, 'error') !== false || trim($out) === '');
        if ($err) return ['ok'=>false,'msg'=>'Imunify cleanup command failed.'];
        // cleanup runs in the background — report the queue status so the user knows it is processing
        $st = json_decode((string)@shell_exec('timeout 25 /usr/bin/imunify360-agent malware cleanup status --json 2>/dev/null'), true);
        $status = $st['items']['status'] ?? 'queued';
        smpro_fa_manifest_add(['kind'=>'imunify','action'=>'malware_quarantine','imid'=>$id,'file'=>(string)$file,'account'=>$file?smpro_fx_file_owner($file):'', 'label'=>'Imunify cleanup (file ' . basename((string)$file) . ')']);
        return ['ok'=>true,'msg'=>'Cleanup queued in Imunify (async, status: ' . $status . '). Press Re-scan in ~1 min to confirm. If the file was ALREADY cleaned and only flagged for leftover traces, use “Remove from list” instead.'];
    }
    /* Remove the entry from Imunify's malicious list WITHOUT touching the file — for already-cleaned / reviewed files. */
    if ($action === 'malware_removelist') {
        if (!is_executable('/usr/bin/imunify360-agent')) return ['ok'=>false,'msg'=>'Imunify360 not available.'];
        $id = preg_replace('/[^0-9]/', '', (string)$imid);
        if ($id === '') return ['ok'=>false,'msg'=>'Missing malware id.'];
        $out = (string)@shell_exec('timeout 60 /usr/bin/imunify360-agent malware malicious remove-from-list --items ' . $id . ' --json 2>&1');
        $j = json_decode($out, true);
        $ok = is_array($j) ? (($j['success'] ?? null) !== false) : (stripos($out, 'error') === false && trim($out) !== '');
        if ($ok) smpro_fa_manifest_add(['kind'=>'imunify_list','action'=>'malware_removelist','imid'=>$id,'file'=>(string)$file,'account'=>$file?smpro_fx_file_owner($file):'', 'label'=>'Removed from malicious list (file ' . basename((string)$file) . ')']);
        return ['ok'=>$ok,'msg'=>$ok ? 'Removed from Imunify malicious list (file left untouched). The finding clears on Re-scan.' : 'Remove-from-list failed.'];
    }
    /* File-edit actions */
    if (!smpro_fa_allowed_target($action, $file)) return ['ok'=>false,'msg'=>'Refused: target is outside the allowed paths.'];
    if (!is_file($file) || !is_writable($file)) return ['ok'=>false,'msg'=>'File not writable: ' . $file];
    $target = trim((string)$rawLine);
    if ($target === '') return ['ok'=>false,'msg'=>'Empty target line.'];
    if ($action === 'sshkey_remove' && stripos($target, 'smpro') !== false) return ['ok'=>false,'msg'=>'Refused: this is the Safety Monitor management key.'];
    $lines = file($file, FILE_IGNORE_NEW_LINES);
    if ($lines === false) return ['ok'=>false,'msg'=>'Cannot read file.'];
    $out = []; $done = false;
    foreach ($lines as $l) {
        if (!$done && trim($l) === $target) {
            $done = true;
            if ($action === 'sshkey_remove') continue;                 // drop the key line
            $out[] = '# [smpro disabled ' . date('Y-m-d H:i') . '] ' . $l;   // comment it out
            continue;
        }
        $out[] = $l;
    }
    if (!$done) return ['ok'=>false,'msg'=>'Line not found — it may already have been changed. Re-scan.'];
    $bak = smpro_fa_backup($file);
    if (!smpro_fa_rewrite($file, $out)) return ['ok'=>false,'msg'=>'Write failed (permissions?).'];
    $verb = $action === 'sshkey_remove' ? 'removed' : ($action === 'cron_disable' ? 'disabled' : 'commented out');
    smpro_fa_manifest_add(['kind'=>'file','action'=>$action,'file'=>$file,'backup'=>$bak,'account'=>smpro_fx_file_owner($file),'label'=>$verb . ' line in ' . basename($file)]);
    return ['ok'=>true,'msg'=>'Done — ' . $verb . '. Backup kept: ' . basename($bak),'backup'=>$bak];
}
/** Undo a remediation from its manifest entry (file restore or Imunify restore-original). */
function smpro_fa_restore($id) {
    $id = preg_replace('/[^a-zA-Z0-9_]/', '', (string)$id); if ($id === '') return ['ok'=>false,'msg'=>'Bad id.'];
    $m = smpro_fa_manifest_load();
    if (!isset($m[$id])) return ['ok'=>false,'msg'=>'Unknown restore entry.'];
    $e = $m[$id];
    if (($e['status'] ?? '') === 'restored') return ['ok'=>false,'msg'=>'Already restored.'];
    if (($e['kind'] ?? '') === 'imunify') {
        if (!is_executable('/usr/bin/imunify360-agent')) return ['ok'=>false,'msg'=>'Imunify360 not available.'];
        $imid = preg_replace('/[^0-9]/', '', (string)($e['imid'] ?? ''));
        if ($imid === '') return ['ok'=>false,'msg'=>'Missing malware id.'];
        $out = (string)@shell_exec('timeout 90 /usr/bin/imunify360-agent malware malicious restore-original --items ' . $imid . ' --json 2>&1');
        $j = json_decode($out, true);
        $ok = is_array($j) ? (($j['success'] ?? null) !== false) : (stripos($out, 'error') === false && trim($out) !== '');
        if ($ok) { $m[$id]['status'] = 'restored'; $m[$id]['restored_ts'] = time(); smpro_fa_json_save(SMPRO_FA_MANIFEST, $m); }
        return ['ok'=>$ok,'msg'=>$ok ? 'Original restored via Imunify.' : 'Imunify restore failed.'];
    }
    // restore a DELETED malware file from its /home/backup/detections copy
    if (($e['kind'] ?? '') === 'delete') {
        $file = (string)($e['file'] ?? ''); $bak = (string)($e['backup'] ?? '');
        if (!preg_match('#^/home/[^/]+/#', $file)) return ['ok'=>false,'msg'=>'Refused: target outside /home.'];
        if ($bak === '' || strpos($bak, '/home/backup/detections/') !== 0 || !is_file($bak)) return ['ok'=>false,'msg'=>'Backup copy missing.'];
        if (is_file($file)) return ['ok'=>false,'msg'=>'A file already exists at the original path — not overwriting.'];
        @is_dir(dirname($file)) || @mkdir(dirname($file), 0755, true);
        if (!@copy($bak, $file)) return ['ok'=>false,'msg'=>'Restore copy failed (permissions?).'];
        $m[$id]['status'] = 'restored'; $m[$id]['restored_ts'] = time(); smpro_fa_json_save(SMPRO_FA_MANIFEST, $m);
        return ['ok'=>true,'msg'=>'Deleted file restored from backup to ' . $file];
    }
    // file restore
    $file = (string)($e['file'] ?? ''); $bak = (string)($e['backup'] ?? '');
    if (!smpro_fa_path_whitelisted($file)) return ['ok'=>false,'msg'=>'Refused: target outside allowed paths.'];
    if ($bak === '' || strpos($bak, SMPRO_FA_QUAR) !== 0 || !is_file($bak)) return ['ok'=>false,'msg'=>'Backup file missing.'];
    $lines = file($bak, FILE_IGNORE_NEW_LINES);
    if ($lines === false) return ['ok'=>false,'msg'=>'Cannot read backup.'];
    if (!smpro_fa_rewrite($file, $lines)) return ['ok'=>false,'msg'=>'Restore write failed (permissions?).'];
    $m[$id]['status'] = 'restored'; $m[$id]['restored_ts'] = time(); smpro_fa_json_save(SMPRO_FA_MANIFEST, $m);
    return ['ok'=>true,'msg'=>'Restored ' . basename($file) . ' from backup.'];
}
function smpro_fa_cache_clear() { foreach (glob(SMPRO_FA_CACHE . '/*.json') ?: [] as $f) @unlink($f); }

/** Cached findings (5 min) keyed by scope. $force bypasses cache. */
function smpro_fa_findings($user, $force = false) {
    $key = SMPRO_FA_CACHE . '/' . ($user === 'all' || $user === '' ? 'all' : preg_replace('/[^a-zA-Z0-9._-]/','',$user)) . '.json';
    if (!$force && is_file($key) && (time() - (int)@filemtime($key)) < SMPRO_FA_CACHE_TTL) {
        $c = smpro_fa_json_load($key);
        if (isset($c['findings'])) return $c;
    }
    $f = smpro_fa_collect_findings($user);
    $c = ['findings'=>$f, 'scanned_at'=>date('c'), 'scanned_ts'=>time(), 'scope'=>$user];
    smpro_fa_json_save($key, $c);
    return $c;
}

function smpro_fa_summary($findings) {
    $s = ['total'=>count($findings),'critical'=>0,'high'=>0,'medium'=>0,'info'=>0,'malware'=>0,'persist'=>0,'accts'=>[],'by_account'=>[]];
    foreach ($findings as $f) {
        $s[$f['sev']] = ($s[$f['sev']] ?? 0) + 1;
        if ($f['cat'] === 'Active malware') $s['malware']++;
        if (strpos($f['cat'], 'Persistence') === 0) $s['persist']++;
        $a = $f['account'] ?? '';
        if ($a !== '' && $a !== 'system') {
            $s['accts'][$a] = true;
            if (!isset($s['by_account'][$a])) $s['by_account'][$a] = ['n'=>0,'cats'=>[]];
            $s['by_account'][$a]['n']++;
            $s['by_account'][$a]['cats'][$f['cat']] = true;
        }
    }
    $s['accounts'] = count($s['accts']); unset($s['accts']);
    uasort($s['by_account'], fn($x,$y)=>$y['n']<=>$x['n']);
    return $s;
}

/* ===========================================================================
 *  PHASE 4 — Incident timeline + IOC export.
 *  Pulls every thread (malware, persistence, keys, foreign logins) into one
 *  chronological story and a copy/paste-ready IOC list for blocking & sharing.
 * ========================================================================= */
function smpro_fa_iocs($findings, $timeline) {
    $io = ['files'=>[], 'hashes'=>[], 'ips'=>[], 'urls'=>[], 'cron'=>[], 'keys'=>[], 'accounts'=>[]];
    foreach ($findings as $f) {
        $acct = $f['account'] ?? '';
        if ($acct !== '' && $acct !== 'system') $io['accounts'][$acct] = true;
        $blob = ($f['evidence'] ?? '') . ' ' . ($f['raw'] ?? '');
        if (($f['cat'] ?? '') === 'Active malware') {
            if (!empty($f['ref']))  $io['files'][$f['ref']] = true;
            if (!empty($f['hash'])) $io['hashes'][$f['hash']] = true;
        }
        if (preg_match_all('#https?://[^\s\'"<>]+#i', $blob, $mm)) foreach ($mm[0] as $u) $io['urls'][rtrim($u, '.,;')] = true;
        if (preg_match_all('#/(?:home|tmp|dev/shm|var/tmp)/[^\s\'"<>]+\.(?:php|py|sh|pl|cgi)\b#', $blob, $pp)) foreach ($pp[0] as $p) $io['files'][$p] = true;
        if (strpos($f['cat'] ?? '', 'Persistence') === 0 && !empty($f['raw'])) $io['cron'][] = $f['raw'];
        if (($f['cat'] ?? '') === 'SSH key access' && !empty($f['raw']) && stripos($f['raw'], 'smpro') === false) $io['keys'][] = $acct . ': ' . $f['raw'];
    }
    foreach ($timeline as $t) if (!empty($t['ip'])) $io['ips'][$t['ip']] = trim(((string)($t['country'] ?? '')) . ' ' . (($t['result'] ?? '') === 'success' ? '(SUCCESS login)' : '(failed login)'));
    foreach (['files','hashes','urls','accounts'] as $k) $io[$k] = array_keys($io[$k]);
    return $io;
}
function smpro_fa_ioc_text($io, $scope) {
    $L = [];
    $L[] = '# Safety Monitor Pro — Indicators of Compromise (IOC)';
    $L[] = '# Scope: ' . ($scope === 'all' || $scope === '' ? 'all accounts' : $scope) . '   Generated: ' . date('Y-m-d H:i:s');
    $L[] = '';
    $sec = function ($title, $items) use (&$L) { $L[] = '## ' . $title . ' (' . count($items) . ')'; if (!$items) $L[] = '(none)'; foreach ($items as $k => $v) $L[] = is_int($k) ? '- ' . $v : '- ' . $k . (trim((string)$v) !== '' ? '   # ' . $v : ''); $L[] = ''; };
    $sec('Malicious / dropped files', $io['files']);
    $sec('File hashes (SHA-256)', $io['hashes']);
    $sec('Network — source IPs (foreign logins)', $io['ips']);
    $sec('Network — URLs (payload / C2)', $io['urls']);
    $sec('Persistence — cron entries', $io['cron']);
    $sec('SSH keys', $io['keys']);
    $sec('Affected accounts', $io['accounts']);
    return implode("\n", $L) . "\n";
}
/** normalize a cpanel login_log time string to epoch (best effort). */
function smpro_fa_login_epoch($s) {
    $s = trim((string)$s);
    if (preg_match('#^(\d{2})/(\d{2})/(\d{4}):(\d{2}:\d{2}:\d{2})#', $s, $m)) $s = $m[1] . '/' . $m[2] . '/' . $m[3] . ' ' . $m[4];
    $e = @strtotime($s);
    return $e ?: 0;
}
function smpro_fa_timeline_events($findings, $timeline) {
    $ev = [];
    foreach ($findings as $f) $ev[] = ['ts'=>(int)($f['ts'] ?? 0),'sev'=>$f['sev'],'kind'=>$f['cat'],'who'=>$f['account'] ?? '','text'=>$f['title'],'ref'=>$f['ref'] ?? ''];
    foreach ($timeline as $t) {
        $ep = smpro_fa_login_epoch($t['time'] ?? '');
        $cc = strtoupper(trim((string)($t['country'] ?? '')));
        $ev[] = ['ts'=>$ep,'sev'=>($t['result']==='success'?'high':'info'),'kind'=>'Foreign login','who'=>$t['user'] ?? '','text'=>strtoupper($t['result']) . ' login from ' . $t['ip'] . ($cc?' ('.$cc.')':'') . (!empty($t['svc'])?' via '.$t['svc']:'') . (!empty($t['provider'])?' — '.$t['provider']:'') . (!empty($t['bot'])?' [datacenter]':''),'ref'=>$t['ip'] ?? ''];
    }
    usort($ev, fn($a,$b)=>$b['ts']<=>$a['ts']);
    return array_slice($ev, 0, 60);
}

/* ---------- Saved reports ---------- */
function smpro_fa_purge_old() {
    $idx = smpro_fa_json_load(SMPRO_FA_REPIDX); $now = time(); $ch = false;
    foreach ($idx as $id => $m) { if (($now - (int)($m['created_ts'] ?? 0)) > SMPRO_FA_RETENTION) { if (!empty($m['path']) && is_file($m['path'])) @unlink($m['path']); unset($idx[$id]); $ch = true; } }
    if ($ch) smpro_fa_json_save(SMPRO_FA_REPIDX, $idx);
}
function smpro_fa_save_report($scope, $findings, $summary, $timeline = []) {
    smpro_fa_purge_old();
    $id = date('Ymd_His') . '_' . substr(hash('sha256', $scope . uniqid('', true)), 0, 10);
    $path = SMPRO_FA_REPORTS . '/' . date('Ym') . '/' . $id . '.json';
    // persist the foreign-login timeline too, so a re-rendered saved report keeps its Incident Timeline / Foreign logins / IOCs
    smpro_fa_json_save($path, ['id'=>$id,'created_at'=>date('c'),'scope'=>$scope,'summary'=>$summary,'findings'=>$findings,'timeline'=>$timeline]);
    $idx = smpro_fa_json_load(SMPRO_FA_REPIDX);
    $idx[$id] = ['id'=>$id,'created_at'=>date('c'),'created_ts'=>time(),'scope'=>$scope,
                 'total'=>$summary['total'],'critical'=>$summary['critical'],'high'=>$summary['high'],'path'=>$path];
    smpro_fa_json_save(SMPRO_FA_REPIDX, $idx);
    return $id;
}
function smpro_fa_delete_report($id) {
    $id = preg_replace('/[^a-zA-Z0-9_-]/', '', (string)$id); if ($id === '') return false;
    $idx = smpro_fa_json_load(SMPRO_FA_REPIDX); if (!isset($idx[$id])) return false;
    $p = (string)($idx[$id]['path'] ?? '');
    if ($p !== '' && strpos($p, SMPRO_FA_REPORTS) === 0 && is_file($p)) @unlink($p);
    unset($idx[$id]); smpro_fa_json_save(SMPRO_FA_REPIDX, $idx);
    return true;
}
function smpro_fa_saved() {
    $idx = smpro_fa_json_load(SMPRO_FA_REPIDX); $rows = [];
    foreach ($idx as $m) { if (is_array($m)) $rows[] = $m; }
    usort($rows, fn($a,$b) => ($b['created_ts'] ?? 0) <=> ($a['created_ts'] ?? 0));
    return array_slice($rows, 0, 12);
}

/* ---------- self-contained HTML/PDF report ---------- */
function smpro_fa_render_report($findings, $meta, $print = false, $timeline = []) {
    $s = smpro_fa_summary($findings);
    $incidents = smpro_fa_timeline_events($findings, $timeline);   // chronological story (findings + foreign logins)
    $iocs = smpro_fa_iocs($findings, $timeline);                   // copy/paste IOC list
    $h = fn($x) => htmlspecialchars((string)$x, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $sevcls = ['critical'=>'red','high'=>'orange','medium'=>'blue','info'=>'gray'];
    $title = 'Forensic Investigation Report' . (!empty($meta['scope']) && $meta['scope'] !== 'all' ? ' — ' . $meta['scope'] : ' — all accounts');
    echo "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><title>" . $h($title) . "</title><style>
*{box-sizing:border-box}body{font:13px/1.5 -apple-system,Segoe UI,Arial,sans-serif;color:#1f2733;margin:0;padding:28px;background:var(--card)}
h1{font-size:20px;margin:0 0 4px}h2.sec{font-size:15px;margin:24px 0 8px;border-bottom:2px solid #e6eaf1;padding-bottom:4px}.muted{color:#6b7686;font-size:12px;margin:0 0 16px}
.cards{display:flex;gap:10px;flex-wrap:wrap;margin:0 0 18px}
.c{border:1px solid #e6eaf1;border-radius:10px;padding:10px 14px;min-width:110px}
.c .l{font-size:10px;text-transform:uppercase;color:#6b7686;letter-spacing:.04em}.c .v{font-size:20px;font-weight:700}
table{width:100%;border-collapse:collapse;font-size:12px;margin:0 0 6px}th,td{border:1px solid #e6eaf1;padding:6px 8px;text-align:left;vertical-align:top}
th{background:var(--bg);font-size:10px;text-transform:uppercase;color:#475569}
.b{display:inline-block;font-size:10px;font-weight:700;padding:1px 7px;border-radius:20px}
.red{background:var(--dang-bg);color:#d93b3b}.orange{background:var(--warn-bg);color:#c2710c}.blue{background:var(--brand-bg);color:#2c50c9}.gray{background:var(--card);color:#475569}
.ev{font-family:ui-monospace,Consolas,monospace;font-size:11px;color:#475569;word-break:break-all}
.head{display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:10px}.brand{font-weight:700;color:#3b5bdb}
.ioc{margin:0 0 10px}.ioc>b{font-size:12px}.ioc ul{margin:3px 0 0;padding-left:18px}.ioc li{margin:1px 0}
.emptynote{color:#6b7686;font-size:12px;margin:0 0 8px}
@media print{body{padding:0}h2.sec{page-break-after:avoid}tr{page-break-inside:avoid}}
</style></head><body>";
    echo "<div class=\"head\"><div><h1>" . $h($title) . "</h1><p class=\"muted\">Generated " . $h(date('Y-m-d H:i:s'))
       . (isset($meta['saved_id']) ? ' · saved ' . $h($meta['saved_id']) : '') . " · light sources only (Imunify360 + cron/SSH/dotfiles), no heavy scan</p></div>"
       . "<div class=\"brand\">&#128737; Safety Monitor Pro</div></div>";
    echo "<div class=\"cards\">"
       . "<div class=\"c\"><div class=\"l\">Findings</div><div class=\"v\">" . (int)$s['total'] . "</div></div>"
       . "<div class=\"c\"><div class=\"l\">Critical</div><div class=\"v\" style=\"color:#d93b3b\">" . (int)$s['critical'] . "</div></div>"
       . "<div class=\"c\"><div class=\"l\">High</div><div class=\"v\" style=\"color:#c2710c\">" . (int)$s['high'] . "</div></div>"
       . "<div class=\"c\"><div class=\"l\">Needs review</div><div class=\"v\">" . (int)$s['medium'] . "</div></div>"
       . "<div class=\"c\"><div class=\"l\">Active malware</div><div class=\"v\">" . (int)$s['malware'] . "</div></div>"
       . "<div class=\"c\"><div class=\"l\">Persistence</div><div class=\"v\">" . (int)$s['persist'] . "</div></div>"
       . "<div class=\"c\"><div class=\"l\">Accounts</div><div class=\"v\">" . (int)$s['accounts'] . "</div></div></div>";

    // Affected accounts — per-account rollup (mirrors the live page)
    if (!empty($s['by_account'])) {
        echo "<h2 class=\"sec\">Affected accounts</h2><table><thead><tr><th>Account</th><th>Findings</th><th>Categories</th></tr></thead><tbody>";
        foreach ($s['by_account'] as $acct => $info) {
            echo "<tr><td><b>" . $h($acct) . "</b></td><td>" . (int)$info['n'] . "</td><td>" . $h(implode(', ', array_keys($info['cats']))) . "</td></tr>";
        }
        echo "</tbody></table>";
    }

    echo "<h2 class=\"sec\">Findings</h2>";
    echo "<table><thead><tr><th>Severity</th><th>Confidence</th><th>Category</th><th>Account</th><th>Finding</th><th>Evidence</th><th>What it means / action</th></tr></thead><tbody>";
    if (!$findings) echo "<tr><td colspan=\"7\" style=\"text-align:center;color:#1f9d55;padding:18px\">No findings — clean for this scope.</td></tr>";
    else foreach ($findings as $f) {
        $cls = $sevcls[$f['sev']] ?? 'gray';
        echo "<tr><td><span class=\"b $cls\">" . $h(strtoupper($f['sev'])) . "</span></td><td>" . $h($f['conf'] ?? '') . "</td><td>" . $h($f['cat']) . "</td><td>" . $h($f['account']) . "</td>"
           . "<td>" . $h($f['title']) . "</td><td class=\"ev\">" . $h($f['evidence']) . "<br><span class=\"muted\">" . $h($f['ref']) . "</span></td>"
           . "<td>" . $h($f['means']) . "<br><b>&#9656; " . $h($f['action']) . "</b></td></tr>";
    }
    echo "</tbody></table>";

    // Incident timeline — chronological story
    echo "<h2 class=\"sec\">Incident timeline</h2>";
    if (!$incidents) echo "<p class=\"emptynote\">No dated events for this scope.</p>";
    else {
        echo "<table><thead><tr><th>Time</th><th>Severity</th><th>Event</th><th>Account</th><th>Detail</th></tr></thead><tbody>";
        foreach ($incidents as $e) {
            $cls = $sevcls[$e['sev']] ?? 'gray';
            $when = !empty($e['ts']) ? date('Y-m-d H:i', (int)$e['ts']) : '—';
            echo "<tr><td class=\"ev\">" . $h($when) . "</td><td><span class=\"b $cls\">" . $h(strtoupper($e['sev'])) . "</span></td><td>" . $h($e['kind']) . "</td><td>" . $h($e['who']) . "</td><td>" . $h($e['text']) . (!empty($e['ref']) ? "<br><span class=\"muted ev\">" . $h($e['ref']) . "</span>" : "") . "</td></tr>";
        }
        echo "</tbody></table>";
    }

    // Foreign logins — outside home countries, with IP intel
    echo "<h2 class=\"sec\">Foreign logins (outside home countries)</h2>";
    if (!$timeline) echo "<p class=\"emptynote\">No foreign login attempts in the reviewed window.</p>";
    else {
        echo "<table><thead><tr><th>Time</th><th>Result</th><th>IP</th><th>Country</th><th>Provider / ASN</th><th>User</th><th>Service</th></tr></thead><tbody>";
        foreach ($timeline as $t) {
            $rc = (($t['result'] ?? '') === 'success') ? 'orange' : 'gray';
            $prov = trim((string)($t['provider'] ?? '') . (!empty($t['asn']) ? ' · ' . $t['asn'] : '') . (!empty($t['bot']) ? ' · datacenter' : ''));
            echo "<tr><td class=\"ev\">" . $h($t['time'] ?? '') . "</td><td><span class=\"b $rc\">" . $h(strtoupper($t['result'] ?? '')) . "</span></td><td class=\"ev\">" . $h($t['ip'] ?? '') . "</td><td>" . $h(strtoupper($t['country'] ?? '')) . "</td><td>" . $h($prov) . "</td><td>" . $h($t['user'] ?? '') . "</td><td>" . $h($t['svc'] ?? '') . "</td></tr>";
        }
        echo "</tbody></table>";
    }

    // Indicators of Compromise
    $iocAny = array_filter([$iocs['files'], $iocs['hashes'], $iocs['ips'], $iocs['urls'], $iocs['cron'], $iocs['keys']]);
    echo "<h2 class=\"sec\">Indicators of Compromise (IOC)</h2>";
    if (!$iocAny) echo "<p class=\"emptynote\">No indicators extracted for this scope.</p>";
    else {
        $iocSec = function ($label, $items) use ($h) {
            if (!$items) return;
            echo "<div class=\"ioc\"><b>" . $h($label) . "</b> <span class=\"muted\">(" . count($items) . ")</span><ul>";
            foreach ($items as $k => $v) echo "<li class=\"ev\">" . (is_int($k) ? $h($v) : $h($k) . (trim((string)$v) !== '' ? " <span class=\"muted\"># " . $h($v) . "</span>" : "")) . "</li>";
            echo "</ul></div>";
        };
        $iocSec('Malicious / dropped files', $iocs['files']);
        $iocSec('File hashes (SHA-256)', $iocs['hashes']);
        $iocSec('Source IPs (foreign logins)', $iocs['ips']);
        $iocSec('URLs (payload / C2)', $iocs['urls']);
        $iocSec('Persistence — cron entries', $iocs['cron']);
        $iocSec('SSH keys', $iocs['keys']);
    }

    if ($print) echo "<script>window.onload=function(){setTimeout(function(){window.print();},300);};</script>";
    echo "</body></html>";
}

/* ---------- on-demand deep file scans (unchanged, throttled) ---------- */
function smpro_fa_scan($type, $user, $path, $days) {
    $days = max(1, min(365, (int)$days)); $rows = []; $note = ''; $scanned = null;
    $EXCL = " -not -path '*/vendor/*' -not -ipath '*/node_modules/*' -not -path '*/storage/framework/*' -not -path '*/storage/cache/*' -not -ipath '*/bootstrap/cache/*'";
    if ($type === 'recent_php') {
        if ($path === '' || $user === 'all') return ['err'=>'Pick a single account in the scope selector above — this scan runs on one account only.','rows'=>[]];
        $cmd = smpro_fa_wrap('find ' . escapeshellarg($path) . " -type f -name '*.php' -mtime -$days" . $EXCL . " -printf '%TY-%Tm-%Td %TH:%TM\\t%s\\t%u\\t%p\\n' 2>/dev/null | sort -r | head -" . SMPRO_FA_LIMIT, 90);
        foreach (explode("\n", (string)@shell_exec($cmd)) as $l) { if (trim($l)==='') continue; $p = explode("\t",$l,4); if (count($p)<4) continue; $rows[] = ['mtime'=>$p[0],'size'=>(int)$p[1],'owner'=>$p[2],'file'=>$p[3]]; }
        $note = 'PHP files modified in the last ' . $days . ' days (vendor libraries &amp; framework caches excluded). Unexpected recent changes can indicate an injected backdoor or defacement.';
    } elseif ($type === 'uploads_php') {
        if ($path === '' || $user === 'all') return ['err'=>'Pick a single account in the scope selector above — this scan runs on one account only.','rows'=>[]];
        // ONLY real user-upload / media directories; exclude vendor libs (e.g. siriusphp/upload) and framework caches
        $cmd = smpro_fa_wrap('find ' . escapeshellarg($path) . " -type f \\( -name '*.php' -o -name '*.phtml' -o -name '*.php5' -o -name '*.php7' -o -name '*.phar' \\) \\( -ipath '*/wp-content/uploads/*' -o -ipath '*/uploads/*' -o -ipath '*/images/*' -o -ipath '*/img/*' -o -ipath '*/media/*' -o -ipath '*/userfiles/*' -o -ipath '*/attachments/*' -o -ipath '*/avatars/*' \\)" . $EXCL . " -printf '%TY-%Tm-%Td %TH:%TM\\t%u\\t%p\\n' 2>/dev/null | head -" . SMPRO_FA_LIMIT, 90);
        foreach (explode("\n", (string)@shell_exec($cmd)) as $l) { if (trim($l)==='') continue; $p = explode("\t",$l,3); if (count($p)<3) continue; $rows[] = ['mtime'=>$p[0],'owner'=>$p[1],'file'=>$p[2]]; }
        $note = 'Executable PHP found inside user-upload / media folders (wp-content/uploads, uploads, images, media, userfiles…). These receive visitor-supplied content and should NEVER contain runnable PHP — a strong sign of an uploaded web shell. Vendor libraries (e.g. siriusphp/upload) &amp; framework caches are excluded.';
    } elseif ($type === 'htaccess') {
        // Shared-hosting safe: for ALL accounts, scope to the live web roots (public_html) with shallow depth + prune heavy dirs.
        // For one account, scan its whole home. PRUNE = skip (don't descend) the big noise dirs entirely.
        $prune = "\\( -path '*/vendor' -o -ipath '*/node_modules' -o -path '*/storage/framework' -o -path '*/storage/cache' -o -path '*/bootstrap/cache' -o -path '*/.git' -o -path '*/.trash' -o -path '*/.cagefs' \\) -prune -o";
        $target = ($user === 'all' || $user === '') ? '/home/*/public_html' : escapeshellarg($path);
        $base = 'find ' . $target . " -maxdepth 6 " . $prune . " -name '.htaccess' -print0 2>/dev/null | head -z -n 20000";
        // ONE grep over all .htaccess (file:line:content). The normal cPanel handler is in nearly every file,
        // so a candidate pre-filter would overflow — instead grep all matching lines once, then classify in PHP.
        $grepCmd = smpro_fa_wrap($base . " | xargs -0 -r grep -HnEi 'auto_prepend_file|auto_append_file|php_value[[:space:]]+auto|AddHandler.*php|SetHandler.*php' 2>/dev/null | head -20000", 150);
        $matches = array_filter(array_map('trim', explode("\n", (string)@shell_exec($grepCmd))));
        // standard PHP extensions — a handler that only maps these is the normal cPanel/MultiPHP version selector, NOT a threat
        $stdExt = ['php','php4','php5','php52','php53','php54','php55','php56','php7','php70','php71','php72','php73','php74','php8','php80','php81','php82','php83','phtml','phps'];
        $classify = function ($L) use ($stdExt) {
            $L = trim($L);
            if (stripos($L, 'auto_prepend_file') !== false) return ['auto_prepend_file', 'Runs a chosen PHP file BEFORE every page on the site — the classic way to inject a site-wide backdoor that survives even when the visible files look clean.'];
            if (stripos($L, 'auto_append_file') !== false)  return ['auto_append_file', 'Runs a chosen PHP file AFTER every page — used to append a backdoor or inject spam/redirect content.'];
            if (preg_match('/php_value\s+auto_(prepend|append)/i', $L)) return ['php_value auto_*', 'Sets a PHP auto prepend/append at folder level — same risk as auto_prepend_file, applied to this directory.'];
            if (preg_match('/(?:Add|Set)Handler/i', $L) && stripos($L, 'php') !== false) {
                preg_match_all('/\.([a-z0-9]+)\b/i', $L, $mm);
                $bad = array_values(array_diff(array_map('strtolower', $mm[1]), $stdExt));
                if (!$bad) return null;   // maps only real PHP extensions → normal cPanel handler, ignore
                return ['Handler maps non-PHP type', 'Forces ' . implode(', ', array_map(fn($e) => '.' . $e, $bad)) . ' to execute as PHP — a common trick to run a web shell disguised as an image / text / odd-extension file.'];
            }
            return null;
        };
        $seen = [];
        foreach ($matches as $mln) {
            if (!preg_match('#^(/[^:]+\.htaccess|/[^:]+/\.htaccess):(\d+):(.*)$#', $mln, $pm)) continue;
            $fl = $pm[1]; $content = $pm[3];
            $r = $classify($content);
            if ($r === null) continue;   // skip normal/benign handler lines
            $k = $fl . '|' . $content; if (isset($seen[$k])) continue; $seen[$k] = 1;
            $acct = preg_match('#/home/([^/]+)/#', $fl, $am) ? $am[1] : '';
            $rows[] = ['account'=>$acct, 'file'=>$fl, 'mtime'=>date('Y-m-d H:i', (int)@filemtime($fl)), 'directive'=>$r[0], 'line'=>trim($content), 'why'=>$r[1]];
        }
        $note = 'Every .htaccess across the selected scope is checked. Normal rules (redirects, caching, the standard cPanel PHP-version handler) are ignored. This audit flags ONLY directives that can hijack PHP execution: forcing a PHP file to run on every page, or mapping a non-PHP file type (e.g. .tpl, .jpg) to run as PHP. Each row explains the risk.';
    } elseif ($type === 'deep_scan') {
        if ($path === '' || $user === 'all') return ['err'=>'Deep scan runs on ONE account only — pick a specific account in the scope selector above.','rows'=>[]];
        // HIGH-CONFIDENCE web-shell / obfuscation patterns only (avoids flagging legit framework code that merely uses base64_decode/eval once)
        $pat = 'eval[[:space:]]*\\([[:space:]]*(base64_decode|gzinflate|gzuncompress|str_rot13|\\$_(POST|GET|REQUEST|COOKIE))'
             . '|(gzinflate|gzuncompress|str_rot13)[[:space:]]*\\([[:space:]]*base64_decode'
             . '|base64_decode[[:space:]]*\\([\x27"][A-Za-z0-9+/]{200,}'
             . '|preg_replace[[:space:]]*\\([^)]*/e'
             . '|assert[[:space:]]*\\([[:space:]]*\\$_(POST|GET|REQUEST|COOKIE)'
             . '|(system|shell_exec|passthru|popen|exec)[[:space:]]*\\([[:space:]]*\\$_(POST|GET|REQUEST|COOKIE)'
             . '|\\b(c99shell|r57shell|FilesMan|b374k|WSOshell|Symlink_Sa|JFolder|phpfm)\\b'
             . '|goto[[:space:]]+[A-Za-z0-9_]+;[[:space:]]*[A-Za-z0-9_]+:[[:space:]]*goto'
             . '|artifacts of previous malicious infection'
             . '|edoced_46esab';
        $cmd = smpro_fa_wrap('grep -rlIE --include=*.php ' . escapeshellarg($pat) . ' ' . escapeshellarg($path) . ' 2>/dev/null | head -200', 150);
        $files = array_filter(array_map('trim', explode("\n", (string)@shell_exec($cmd))));
        foreach ($files as $fl) {
            $hash = trim((string)@shell_exec('timeout 10 nice -n ' . SMPRO_SCAN_NICE . ' sha256sum ' . escapeshellarg($fl) . ' 2>/dev/null'));
            $hash = $hash !== '' ? substr($hash, 0, 64) : '';
            $low = (string)@shell_exec('timeout 10 grep -oiE ' . escapeshellarg('eval|base64_decode|gzinflate|gzuncompress|str_rot13|shell_exec|passthru|system|popen|proc_open|assert|create_function|filesman|c99|r57|wso|goto-obfuscation') . ' ' . escapeshellarg($fl) . ' 2>/dev/null | tr A-Z a-z | sort -u | head -12');
            if ($ind0 = @shell_exec('grep -cE ' . escapeshellarg('goto[[:space:]]+[A-Za-z0-9_]+;[[:space:]]*[A-Za-z0-9_]+:[[:space:]]*goto') . ' ' . escapeshellarg($fl) . ' 2>/dev/null')) { if ((int)trim($ind0) > 0) $low .= "\ngoto-obfuscation"; }
            $ind = array_slice(array_values(array_unique(array_filter(array_map('trim', explode("\n", $low))))), 0, 8);
            $st = @stat($fl);
            $owner = ($st && function_exists('posix_getpwuid')) ? ((@posix_getpwuid($st['uid'])['name']) ?: (string)$st['uid']) : ($st ? (string)$st['uid'] : '');
            $rows[] = ['file'=>$fl,'sha256'=>$hash,'size'=>$st?(int)$st['size']:0,'mtime'=>$st?date('Y-m-d H:i',(int)$st['mtime']):'','owner'=>$owner,'ind'=>$ind];
        }
        $hc = [];
        foreach ($rows as $r) if ($r['sha256'] !== '') $hc[$r['sha256']] = ($hc[$r['sha256']] ?? 0) + 1;
        foreach ($rows as &$rr) $rr['dup'] = ($rr['sha256'] !== '' && ($hc[$rr['sha256']] ?? 0) > 1);
        unset($rr);
        usort($rows, fn($a,$b) => ($b['dup']<=>$a['dup']) ?: (count($b['ind'])<=>count($a['ind'])));
        $note = 'Single-account DEEP scan: PHP files whose CONTENT matches known web-shell / obfuscation indicators (eval, base64_decode, gzinflate, shell_exec, system, known shell names…). Each file is SHA-256 hashed — identical hashes across files (badge "campaign") mean the same payload was planted in several places, exactly how the Imunify finding showed the same backdoor on two accounts. Throttled (timeout/nice/ionice), capped at 200 files. Indicators alone are not proof — review each file.';
    }
    // WP Guard allowlist: drop this product's OWN verified security files + what it already neutralized
    // (mu-plugins/wp-guard.php, plugins/wp-guard/, hostguard-quarantine/**, its log & "engine off" .htaccess).
    // uploads/*.php, Protector.php and injected index.php are NOT trusted — they stay flagged.
    $wgExcluded = 0;
    if ($rows && function_exists('smpro_wpguard_trusted')) {
        $rows = array_values(array_filter($rows, function ($r) use (&$wgExcluded) {
            if (!empty($r['file']) && smpro_wpguard_trusted($r['file'])) { $wgExcluded++; return false; }
            return true;
        }));
        if ($wgExcluded > 0) $note .= ' <b>' . $wgExcluded . ' trusted WP Guard file(s) were recognised and excluded</b> (its own plugin/log/quarantine).';
    }
    return ['err'=>'','rows'=>$rows,'note'=>$note,'scanned'=>$scanned,'wpguard_excluded'=>$wgExcluded];
}

function smpro_fa_is_local_ip($ip) {
    if ($ip === '' || $ip === '::1' || strpos($ip, '127.') === 0) return true;
    if (filter_var($ip, FILTER_VALIDATE_IP) === false) return true;                 // not a real IP → noise
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) return true; // private/reserved
    return false;
}
/** Recent FOREIGN login ATTEMPTS (successful + failed): localhost/internal
 *  filtered out, then only countries outside the configured home region are
 *  kept, enriched with IP intel. */
function smpro_fa_login_timeline($limit = 40) {
    $cand = []; $uips = []; $hiddenLocal = 0;
    // grep login outcomes first (skips the huge localhost/internal noise efficiently), newest last
    $raw = (string)@shell_exec("timeout 15 grep -aE '(SUCCEEDED|FAILED)[[:space:]]+LOGIN|SUCCESS[[:space:]]+LOGIN' /usr/local/cpanel/logs/login_log 2>/dev/null | grep -avE '(^|[^0-9])(127\\.0\\.0\\.1|::1|10\\.|192\\.168\\.)' | tail -n 6000");
    foreach (array_reverse(explode("\n", $raw)) as $l) {
        $l = trim($l); if ($l === '') continue;
        $ip = ''; $svc = ''; $user = ''; $time = '';
        // ONE dash — current cPanel writes  [ts] lvl [svc] IP - user "REQUEST" MSG  (the old pattern demanded a
        // second dash and so matched none of the log, leaving the foreign-login timeline blank).
        if (preg_match('/^\[([^\]]+)\]\s+\S+\s+\[([^\]]+)\]\s+(\S+)\s+-\s+(\S+)\s+/', $l, $m)) { $time=$m[1]; $svc=$m[2]; $ip=$m[3]; $user=rawurldecode($m[4]); }
        elseif (preg_match('/^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]*)"\s+(.+)$/', $l, $m)) { $svc = preg_match('/\b([a-z0-9_]+):/i',$m[5],$s)?$s[1]:'cpanel'; $time=$m[3]; $ip=$m[1]; $user=rawurldecode($m[2]); }
        else continue;
        if (smpro_fa_is_local_ip($ip)) { $hiddenLocal++; continue; }                 // internal/localhost noise
        if (stripos($svc, 'cloudflare') !== false) continue;
        $result = preg_match('/FAILED\s+LOGIN/i', $l) ? 'failed' : 'success';
        $cand[] = ['time'=>$time,'svc'=>$svc,'ip'=>$ip,'user'=>$user,'result'=>$result];
        $uips[$ip] = 1;
        if (count($cand) >= 400) break;
    }
    if ($uips && function_exists('smpro_ip_intel_bulk')) smpro_ip_intel_bulk(array_keys($uips), true);  // warm cache once
    $rows = []; $hiddenArab = 0;
    foreach ($cand as $c) {
        $intel = function_exists('smpro_ip_intel') ? smpro_ip_intel($c['ip']) : ['country'=>'','provider'=>'','asn'=>''];
        $cc = strtoupper(trim((string)($intel['country'] ?? '')));
        if (in_array($cc, smpro_im_home_regions(), true)) { $hiddenArab++; continue; }   // configured home regions — not foreign
        $c['country']  = $intel['country']  ?? '';
        $c['provider'] = $intel['provider'] ?? '';
        $c['asn']      = $intel['asn']      ?? '';
        $c['bot']      = function_exists('smpro_ip_is_datacenter') ? smpro_ip_is_datacenter($intel) : false;
        $rows[] = $c;
        if (count($rows) >= $limit) break;
    }
    return ['rows'=>$rows, 'hidden_local'=>$hiddenLocal, 'hidden_arab'=>$hiddenArab];
}

/** Render ONLY the scan result card (used by the page and by the AJAX endpoint). */
function smpro_fa_scan_card($scan, $result, $user, $scanTypes) {
    ?>
    <div class="card" style="padding:0;overflow:hidden;margin:14px 0">
      <div class="fa-head"><b><?= smpro_h($scanTypes[$scan] ?? $scan) ?></b><span class="meta"><?= count($result['rows']) ?> result(s) · <?= smpro_h($user==='all'?'all accounts':$user) ?></span></div>
      <?php if ($result['err']): ?><div class="fa-empty"><?= smpro_h($result['err']) ?></div>
      <?php elseif (!$result['rows']): ?><div class="fa-empty" style="color:var(--good)">&#10003; <?php if ($scan==='htaccess' && isset($result['scanned'])): ?>Scanned <?= (int)$result['scanned'] ?> .htaccess file(s) across <?= smpro_h($user==='all'?'all accounts':$user) ?> — none contain PHP-hijacking directives (clean).<?php else: ?>No matches — clean for this scope.<?php endif; ?></div>
      <?php else: ?>
        <div class="fa-note"><?= $result['note'] ?></div>
        <div class="fa-tablewrap" style="max-height:520px"><table class="smpro-table">
          <?php if ($scan==='deep_scan'): ?>
            <thead><tr><th>File</th><th>Indicators</th><th>SHA-256</th><th class="num">Size</th><th>Modified</th></tr></thead><tbody>
            <?php foreach ($result['rows'] as $r): ?><tr class="<?= $r['dup']?'fa-sus':'' ?>">
              <td class="mono fa-file"><?= smpro_h($r['file']) ?><?= $r['dup']?' <span class="b red" title="Same SHA-256 found on multiple files">campaign</span>':'' ?></td>
              <td><?php foreach ($r['ind'] as $i): ?><span class="b orange" style="margin:1px"><?= smpro_h($i) ?></span> <?php endforeach; ?></td>
              <td class="mono" title="<?= smpro_h($r['sha256']) ?>"><?= $r['sha256']?smpro_h(substr($r['sha256'],0,18)).'…':'—' ?></td>
              <td class="num"><?= smpro_h(number_format($r['size']/1024,1)) ?> KB</td>
              <td class="mono"><?= smpro_h($r['mtime']) ?></td>
            </tr><?php endforeach; ?></tbody>
          <?php elseif ($scan==='recent_php' || $scan==='uploads_php'): ?>
            <thead><tr><th>Modified</th><?php if($scan==='recent_php'):?><th class="num">Size</th><?php endif;?><th>Owner</th><th>File</th></tr></thead><tbody>
            <?php foreach ($result['rows'] as $r): ?><tr><td class="mono"><?= smpro_h($r['mtime']) ?></td><?php if($scan==='recent_php'):?><td class="num"><?= smpro_h(number_format($r['size']/1024,1)) ?> KB</td><?php endif;?><td class="mono"><?= smpro_h($r['owner']) ?></td><td class="mono fa-file"><?= smpro_h($r['file']) ?></td></tr><?php endforeach; ?></tbody>
          <?php else: ?>
            <thead><tr><th>Account</th><th>Directive</th><th>What it means / risk</th><th>Line in file</th><th>File</th></tr></thead><tbody>
            <?php foreach ($result['rows'] as $r): ?><tr><td class="mono"><b><?= smpro_h($r['account'] ?? '') ?></b></td><td><span class="b orange"><?= smpro_h($r['directive']) ?></span></td><td class="fa-mean"><?= smpro_h($r['why']) ?></td><td class="mono fa-file"><?= smpro_h($r['line']) ?></td><td class="mono fa-file"><?= smpro_h($r['file']) ?></td></tr><?php endforeach; ?></tbody>
          <?php endif; ?>
        </table></div>
      <?php endif; ?>
    </div>
    <?php
}

/** Aggregate Imunify360 detection HISTORY (all events, incl DB injections) — cached 5 min. */
function smpro_fa_imunify_history($scope = '') {
    if (!is_executable('/usr/bin/imunify360-agent')) return null;
    $key = SMPRO_FA_CACHE . '/imhist_' . ($scope === '' ? 'all' : preg_replace('/[^a-zA-Z0-9._-]/','',$scope)) . '.json';
    if (is_file($key) && (time() - (int)@filemtime($key)) < 300) { $c = smpro_fa_json_load($key); if (isset($c['total'])) return $c; }
    $j = json_decode((string)@shell_exec('timeout 45 /usr/bin/imunify360-agent malware history list --limit 3000 --json 2>/dev/null'), true);
    if (!is_array($j)) return null;
    $items = $j['items'] ?? [];
    $a = ['total'=>(int)($j['max_count'] ?? count($items)),'scanned'=>count($items),'events'=>[],'db'=>0,'files'=>0,'accounts'=>[],'families'=>[],'recent'=>[]];
    foreach ($items as $r) {
        $acct = (string)($r['file_user'] ?? $r['file_owner'] ?? '');
        if ($scope !== '' && $acct !== $scope) continue;
        $ev = (string)($r['event'] ?? '?'); $a['events'][$ev] = ($a['events'][$ev] ?? 0) + 1;
        if (!empty($r['resource_type']) && $r['resource_type'] !== 'file') $a['db']++; else $a['files']++;
        if ($acct !== '') $a['accounts'][$acct] = ($a['accounts'][$acct] ?? 0) + 1;
        $fam = preg_match('/SMW-[A-Z]+-\d+-(.+?)-\d+$/', (string)($r['signature_id'] ?? ''), $mm) ? $mm[1] : '';
        if ($fam) $a['families'][$fam] = ($a['families'][$fam] ?? 0) + 1;
        if (count($a['recent']) < 14) $a['recent'][] = ['path'=>(string)($r['path'] ?? ''),'event'=>$ev,'account'=>$acct,'db'=>(!empty($r['resource_type']) && $r['resource_type']!=='file')];
    }
    arsort($a['accounts']); arsort($a['families']); arsort($a['events']);
    @is_dir(SMPRO_FA_CACHE) || @mkdir(SMPRO_FA_CACHE, 0700, true);
    smpro_fa_json_save($key, $a);
    return $a;
}

/* =========================== request params =========================== */
$users = smpro_fa_users();
$user = preg_replace('/[^a-zA-Z0-9._-]/', '', (string)($_GET['user'] ?? 'all')) ?: 'all';
if ($user !== 'all' && !in_array($user, $users, true)) $user = 'all';
$days = (int)($_GET['days'] ?? 7); if (!in_array($days, [1,3,7,14,30], true)) $days = 7;
$scan = preg_replace('/[^a-z_]/', '', (string)($_GET['scan'] ?? ''));
$scanTypes = ['deep_scan'=>'Deep Malware + SHA-256 (1 account)','recent_php'=>'Recently Modified PHP','uploads_php'=>'PHP in Upload Dirs','htaccess'=>'.htaccess Audit'];
$fmt = (string)($_GET['format'] ?? '');
$reqMethod = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? getenv('REQUEST_METHOD') ?: 'GET'));

/* ---- AJAX scan: run the scan in the background and return ONLY the result card (non-blocking) ---- */
if (($_GET['ajax'] ?? '') === 'scan') {
    $sc = preg_replace('/[^a-z_]/', '', (string)($_GET['scan'] ?? ''));
    if (isset($scanTypes[$sc])) {
        $res = smpro_fa_scan($sc, $user, smpro_fa_path($user), $days);
        smpro_audit('forensics_scan', ['scan'=>$sc, 'user'=>$user, 'hits'=>count($res['rows']), 'ajax'=>1]);
        smpro_fa_scan_card($sc, $res, $user, $scanTypes);
    } else { echo '<div class="fa-empty">Unknown scan type.</div>'; }
    exit;
}
/* ---- AJAX: Imunify history aggregation (lazy panel — heavy, loaded after the page) ---- */
if (($_GET['ajax'] ?? '') === 'imhist') {
    smpro_fa_render_imhist(smpro_fa_imunify_history($user === 'all' ? '' : $user), $user);
    exit;
}

/* ---- AJAX: save snapshot (POST + CSRF) ---- */
if ($reqMethod === 'POST' && ($_POST['fa_action'] ?? '') === 'save_report') {
    smpro_require_valid_csrf('fa_save'); smpro_require_root();
    $data = smpro_fa_findings($user, false);
    $sum = smpro_fa_summary($data['findings']);
    $tlSave = smpro_fa_login_timeline(60)['rows'];
    $id = smpro_fa_save_report($user, $data['findings'], $sum, $tlSave);
    smpro_audit('forensics_report_save', ['id'=>$id,'scope'=>$user,'total'=>$sum['total'],'critical'=>$sum['critical']]);
    header('Content-Type: application/json'); echo json_encode(['ok'=>true,'id'=>$id], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit;
}
/* ---- AJAX: delete saved report(s) (POST + CSRF) ---- */
if ($reqMethod === 'POST' && ($_POST['fa_action'] ?? '') === 'delete_report') {
    smpro_require_valid_csrf('fa_delete'); smpro_require_root();
    $ids = array_filter(array_map(fn($s)=>preg_replace('/[^a-zA-Z0-9_-]/','',$s), explode(',', (string)($_POST['report_ids'] ?? ''))));
    $del = []; foreach ($ids as $rid) if (smpro_fa_delete_report($rid)) $del[] = $rid;
    smpro_audit('forensics_report_delete', ['ids'=>$ids,'deleted'=>$del]);
    header('Content-Type: application/json'); echo json_encode(['ok'=>true,'deleted'=>$del], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit;
}
/* ---- AJAX: remediate a finding (POST + CSRF + ROOT) ---- */
if ($reqMethod === 'POST' && ($_POST['fa_action'] ?? '') === 'remediate') {
    smpro_require_valid_csrf('fa_remediate');
    smpro_require_root();
    $act  = preg_replace('/[^a-z_]/', '', (string)($_POST['act'] ?? ''));
    $file = (string)($_POST['file'] ?? '');
    $raw  = base64_decode((string)($_POST['raw'] ?? ''), true) ?: '';
    $imid = (string)($_POST['imid'] ?? '');
    $res  = smpro_fa_remediate($act, $file, $raw, $imid);
    if (!empty($res['ok'])) smpro_fa_cache_clear();
    smpro_audit('forensics_remediate', ['act'=>$act,'file'=>$file,'imid'=>$imid,'ok'=>$res['ok'],'msg'=>$res['msg']]);
    header('Content-Type: application/json'); echo json_encode($res, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit;
}

/* ---- AJAX: restore a remediation from backup (POST + CSRF + ROOT) ---- */
if ($reqMethod === 'POST' && ($_POST['fa_action'] ?? '') === 'restore') {
    smpro_require_valid_csrf('fa_remediate'); smpro_require_root();
    $res = smpro_fa_restore((string)($_POST['id'] ?? ''));
    if (!empty($res['ok'])) smpro_fa_cache_clear();
    smpro_audit('forensics_restore', ['id'=>(string)($_POST['id'] ?? ''),'ok'=>$res['ok'],'msg'=>$res['msg']]);
    header('Content-Type: application/json'); echo json_encode($res, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit;
}

/* ---- AJAX: AI analysis of a finding / the whole incident (POST + CSRF + ROOT) ---- */
if ($reqMethod === 'POST' && ($_POST['fa_action'] ?? '') === 'ai_analyze') {
    smpro_require_valid_csrf('fa_remediate'); smpro_require_root();
    header('Content-Type: application/json');
    if (!function_exists('smpro_ai_available') || !smpro_ai_available()) { echo json_encode(['ok'=>false,'error'=>'No AI provider is configured. Open AI Providers and save a key first.']); exit; }
    $mode = preg_replace('/[^a-z_]/', '', (string)($_POST['mode'] ?? 'finding'));
    if ($mode === 'incident') {
        $data = smpro_fa_findings($user, false)['findings'];
        $io = smpro_fa_iocs($data, smpro_fa_login_timeline(40)['rows']);
        $ctx = 'Scope: ' . ($user === 'all' ? 'all accounts' : $user) . "\nFindings (" . count($data) . "):\n";
        foreach (array_slice($data, 0, 40) as $f) $ctx .= '- [' . $f['sev'] . '] ' . $f['cat'] . ' @ ' . $f['account'] . ': ' . $f['title'] . ' | ' . $f['evidence'] . "\n";
        $ctx .= "\nIOC counts: files=" . count($io['files']) . ' hashes=' . count($io['hashes']) . ' ips=' . count($io['ips']) . ' urls=' . count($io['urls']) . ' cron=' . count($io['cron']) . "\n";
        if ($io['ips'])  $ctx .= 'Foreign login IPs: ' . implode(', ', array_slice(array_keys($io['ips']), 0, 15)) . "\n";
        if ($io['urls']) $ctx .= 'URLs: ' . implode(', ', array_slice($io['urls'], 0, 10)) . "\n";
        $sys = 'You are a senior DFIR analyst for a cPanel shared-hosting server. From the consolidated findings and IOCs, write a concise incident assessment with short markdown headers: ## Overall risk, ## What likely happened, ## Prioritized actions (numbered), ## Verify next. Be specific, do not invent data, and keep it under ~350 words.';
        $r = smpro_ai_chat($sys, smpro_ai_redact($ctx), ['max_tokens'=>1200, 'context'=>'forensics_incident']);
    } else {
        $title = trim((string)($_POST['title'] ?? '')); $cat = trim((string)($_POST['cat'] ?? ''));
        $acct = trim((string)($_POST['acct'] ?? '')); $ev = trim((string)($_POST['ev'] ?? '')); $ref = (string)($_POST['ref'] ?? '');
        $excerpt = '';
        // SECURITY: only ever read a file the SCANNER ACTUALLY FLAGGED (ref must match a current finding) AND not a
        // sensitive system file — otherwise $_POST['ref'] would be an "read any root file → ship to external AI" oracle.
        if ($ref !== '' && is_file($ref) && is_readable($ref) && @filesize($ref) < 3000000) {
            $rp = realpath($ref);
            $allowed = [];
            foreach (smpro_fa_findings($user, false)['findings'] as $ff) { if (!empty($ff['ref']) && ($a = realpath($ff['ref']))) $allowed[$a] = 1; }
            $sensitive = $rp && preg_match('~(/\.ssh/|/etc/(shadow|gshadow|passwd|csf/)|^/root/|\.pem$|\.key$|id_rsa|/var/lib/smpro/)~i', $rp);
            if ($rp && isset($allowed[$rp]) && !$sensitive) $excerpt = (string)@file_get_contents($ref, false, null, 0, 14000);
        }
        $ctx = "Finding: $title\nCategory: $cat\nAccount: $acct\nEvidence: $ev\nFile: $ref\n";
        if ($excerpt !== '') $ctx .= "\nFile content (first 14KB):\n" . $excerpt . "\n";
        $sys = 'You are a senior DFIR / malware analyst on a cPanel shared-hosting server. Assess the finding. Answer with short markdown headers: ## Verdict (malicious / suspicious / likely benign + confidence), ## What it does (deobfuscate if the code is obfuscated), ## Recommended action. Analyze any provided file content directly; do not invent capabilities you cannot see. Keep it under ~300 words.';
        $r = smpro_ai_chat($sys, smpro_ai_redact($ctx), ['max_tokens'=>1200, 'context'=>'forensics_finding']);
    }
    smpro_audit('forensics_ai_analyze', ['mode'=>$mode, 'ok'=>$r['ok'], 'provider'=>$r['provider'] ?? '']);
    echo json_encode(['ok'=>$r['ok'], 'text'=>$r['text'] ?? '', 'error'=>$r['error'] ?? '', 'provider'=>$r['provider'] ?? '', 'model'=>$r['model'] ?? ''], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit;
}

/* ---- AJAX: suspend / unsuspend a cPanel account (POST + CSRF + ROOT) ---- */
if ($reqMethod === 'POST' && in_array(($_POST['fa_action'] ?? ''), ['suspend','unsuspend'], true)) {
    smpro_require_valid_csrf('fa_remediate'); smpro_require_root();
    header('Content-Type: application/json');
    $acct = preg_replace('/[^a-zA-Z0-9._-]/', '', (string)($_POST['account'] ?? ''));
    if ($acct === '' || in_array($acct, ['root','system','nobody'], true) || !is_file('/var/cpanel/users/' . $acct)) {
        echo json_encode(['ok'=>false,'msg'=>'Refused: not a valid cPanel account (or protected).']); exit;
    }
    $act = $_POST['fa_action'];
    if ($act === 'suspend') {
        $out = (string)@shell_exec('timeout 60 whmapi1 --output=json suspendacct user=' . escapeshellarg($acct) . ' reason=' . escapeshellarg('Safety Monitor Pro: flagged as compromised / spam source') . ' 2>&1');
    } else {
        $out = (string)@shell_exec('timeout 60 whmapi1 --output=json unsuspendacct user=' . escapeshellarg($acct) . ' 2>&1');
    }
    $j = json_decode($out, true);
    $ok = is_array($j) && (int)($j['metadata']['result'] ?? 0) === 1;
    $msg = is_array($j) ? (string)($j['metadata']['reason'] ?? '') : 'whmapi1 failed';
    smpro_audit('forensics_' . $act, ['account'=>$acct,'ok'=>$ok,'msg'=>$msg]);
    echo json_encode(['ok'=>$ok,'msg'=>$ok ? ($act==='suspend'?'Account suspended (reversible — unsuspend anytime).':'Account unsuspended.') : ('Failed: ' . $msg)], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit;
}

/* ---- AJAX: DELETE a malware file (backup OUTSIDE the account, then remove) + per-action report ---- */
if ($reqMethod === 'POST' && ($_POST['fa_action'] ?? '') === 'delete_malware') {
    smpro_require_valid_csrf('fa_remediate'); smpro_require_root();
    header('Content-Type: application/json');
    $file = (string)($_POST['file'] ?? '');
    if (!preg_match('#^/home/([^/]+)/.+#', $file, $m) || !is_file($file)) { echo json_encode(['ok'=>false,'msg'=>'Refused: only existing files under /home/<account>/ can be deleted.']); exit; }
    $acct = $m[1];
    // SECURITY: reject a symlink / a path resolving outside the account (a customer could symlink
    // /home/<acct>/x.php -> /root/.ssh/id_rsa, making this root-run copy() leak it + unlink() destroy it).
    $safe = function_exists('smpro_path_safe') ? smpro_path_safe($file, [smpro_user_home($acct)]) : $file;
    if ($safe === '') { echo json_encode(['ok'=>false,'msg'=>'Refused: target is a symlink or resolves outside the account.']); exit; }
    $file = $safe;
    // back the file up OUTSIDE the customer folder, in /home/backup/detections/<account>/
    $bdir = '/home/backup/detections/' . $acct;
    @is_dir($bdir) || @mkdir($bdir, 0700, true); @chmod('/home/backup/detections', 0700);
    $sha = @hash_file('sha256', $file) ?: '';
    $bak = $bdir . '/' . date('Ymd_His') . '_' . preg_replace('/[^a-zA-Z0-9._-]/', '_', basename($file));
    if (!@copy($file, $bak)) { echo json_encode(['ok'=>false,'msg'=>'Could not back up the file — aborting (nothing deleted).']); exit; }
    @chmod($bak, 0600);
    $deleted = @unlink($file);
    if (!$deleted) { echo json_encode(['ok'=>false,'msg'=>'Backup saved but DELETE failed (permissions?). Backup: ' . basename($bak)]); exit; }
    // per-action detection report
    $rid = smpro_fa_detection_report(['action'=>'delete_malware','account'=>$acct,'file'=>$file,'sha256'=>$sha,'backup'=>$bak,'actor'=>function_exists('smpro_current_actor')?smpro_current_actor():'root']);
    smpro_fa_manifest_add(['kind'=>'delete','action'=>'delete_malware','file'=>$file,'backup'=>$bak,'account'=>$acct,'sha256'=>$sha,'report'=>$rid,'label'=>'Deleted malware ' . basename($file)]);
    smpro_fa_cache_clear();
    smpro_audit('forensics_delete_malware', ['account'=>$acct,'file'=>$file,'sha256'=>$sha,'backup'=>$bak,'report'=>$rid]);
    echo json_encode(['ok'=>true,'msg'=>'File DELETED. Backed up outside the account → ' . $bak . ' · report #' . $rid . ' (restorable).'], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit;
}

/* ---- AJAX: AI decision plan — structured, executable recommendations per finding ---- */
if ($reqMethod === 'POST' && ($_POST['fa_action'] ?? '') === 'ai_decide') {
    smpro_require_valid_csrf('fa_remediate'); smpro_require_root();
    header('Content-Type: application/json');
    if (!function_exists('smpro_ai_available') || !smpro_ai_available()) { echo json_encode(['ok'=>false,'error'=>'No AI provider is configured. Open AI Providers first.']); exit; }
    $data = smpro_fa_findings($user, false)['findings'];
    if (!$data) { echo json_encode(['ok'=>true,'summary'=>'No findings to decide on.','decisions'=>[]]); exit; }
    $lines = '';
    foreach ($data as $i => $f) {
        $lines .= '#' . $i . ' sev=' . $f['sev'] . ' cat="' . $f['cat'] . '" account=' . $f['account']
            . ' action=' . ($f['act'] ?: 'none') . ' title="' . $f['title'] . '" evidence="' . mb_substr((string)$f['evidence'], 0, 220) . "\"\n";
    }
    $sys = 'You are a DFIR decision engine for a cPanel shared-hosting server. For EACH finding choose exactly ONE decision from this vocabulary: '
        . '"clean" (malware — quarantine/clean the infected file via Imunify; finding action must be malware_quarantine), '
        . '"delete" (permanently DELETE a confirmed-malicious file — it is backed up outside the account first; only for malware findings whose file lives under /home), '
        . '"disable" (neutralise a malicious cron job or shell-init line; action must be cron_disable/dotfile_comment), '
        . '"remove" (delete an unauthorized SSH key; action must be sshkey_remove), '
        . '"trust" (a benign/known SSH key; action must be sshkey_remove), '
        . '"scan" (run a deep malware scan on the affected account to assess blast radius), '
        . '"suspend" (suspend the whole account when it is actively compromised / spamming — reversible), '
        . '"investigate" (needs a human), "ignore" (false positive). '
        . 'Respond with STRICT JSON ONLY, no text outside it: {"summary":"one short paragraph","decisions":[{"id":<finding number>,"decision":"clean|disable|remove|trust|scan|suspend|investigate|ignore","priority":1,"reason":"short"}]}. '
        . 'priority is 1 (highest) to 5. Match the decision to the finding action where one exists. Use only the finding numbers given. Be decisive and safe; prefer the least drastic effective action.';
    $r = smpro_ai_chat($sys, smpro_ai_redact($lines), ['max_tokens'=>1700, 'temperature'=>0, 'context'=>'forensics_decide']);
    if (empty($r['ok'])) { echo json_encode(['ok'=>false,'error'=>$r['error'] ?? 'AI request failed']); exit; }
    // extract the JSON object from the model output (robust shared parser)
    $txt = (string)$r['text'];
    $plan = function_exists('smpro_ai_json') ? smpro_ai_json($txt) : json_decode($txt, true);
    if (!is_array($plan)) { echo json_encode(['ok'=>false,'error'=>'The AI was busy or replied without a clear plan — try again.','raw'=>mb_substr($txt,0,400)]); exit; }
    // keep only decisions that map to a real finding, and attach the finding's executable action
    $decs = [];
    foreach ((array)($plan['decisions'] ?? []) as $d) {
        $id = (int)($d['id'] ?? -1); if (!isset($data[$id])) continue;
        $f = $data[$id];
        $decs[] = ['id'=>$id, 'decision'=>preg_replace('/[^a-z]/','',strtolower((string)($d['decision'] ?? 'investigate'))),
                   'priority'=>max(1,min(5,(int)($d['priority'] ?? 3))), 'reason'=>mb_substr((string)($d['reason'] ?? ''),0,300),
                   'sev'=>$f['sev'], 'cat'=>$f['cat'], 'account'=>$f['account'], 'title'=>$f['title'], 'act'=>$f['act'] ?? ''];
    }
    usort($decs, fn($x,$y)=>$x['priority']<=>$y['priority']);
    smpro_audit('forensics_ai_decide', ['count'=>count($decs)]);
    echo json_encode(['ok'=>true,'summary'=>mb_substr((string)($plan['summary'] ?? ''),0,800),'decisions'=>$decs,'provider'=>$r['provider']??'','model'=>$r['model']??''], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit;
}

/* ---- AJAX: trust a key (allowlist) / revoke trust (POST + CSRF + ROOT) ---- */
if ($reqMethod === 'POST' && ($_POST['fa_action'] ?? '') === 'allow_key') {
    smpro_require_valid_csrf('fa_remediate'); smpro_require_root();
    $acct = preg_replace('/[^a-zA-Z0-9._-]/', '', (string)($_POST['account'] ?? ''));
    $raw  = base64_decode((string)($_POST['raw'] ?? ''), true) ?: '';
    if ($acct === '' || trim($raw) === '') { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'msg'=>'Missing key.']); exit; }
    $sig = smpro_fa_allow_add($acct, $raw); smpro_fa_cache_clear();
    smpro_audit('forensics_key_allow', ['account'=>$acct,'sig'=>$sig]);
    header('Content-Type: application/json'); echo json_encode(['ok'=>true,'sig'=>$sig], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit;
}
if ($reqMethod === 'POST' && ($_POST['fa_action'] ?? '') === 'unallow_key') {
    smpro_require_valid_csrf('fa_remediate'); smpro_require_root();
    $ok = smpro_fa_allow_remove((string)($_POST['sig'] ?? '')); smpro_fa_cache_clear();
    smpro_audit('forensics_key_unallow', ['sig'=>(string)($_POST['sig'] ?? ''),'ok'=>$ok]);
    header('Content-Type: application/json'); echo json_encode(['ok'=>$ok], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit;
}
/* ---- Comprehensive Account Forensics: whitelist add/remove + accept-baseline (CSRF + root, JSON) ---- */
if ($reqMethod === 'POST' && ($_POST['fa_action'] ?? '') === 'fx_wl_add') {
    smpro_require_valid_csrf('fa_remediate'); smpro_require_root();
    header('Content-Type: application/json');
    if (!function_exists('smpro_fe_wl_add')) { echo json_encode(['ok'=>false,'msg'=>'Forensics engine unavailable.']); exit; }
    $acct = preg_replace('/[^a-zA-Z0-9._-]/', '', (string)($_POST['account'] ?? ''));
    $scope = (string)($_POST['scope'] ?? 'path');
    $value = (string)($_POST['value'] ?? '');
    $reason = trim((string)($_POST['reason'] ?? ''));
    if ($value === '' || $reason === '') { echo json_encode(['ok'=>false,'msg'=>'A file/pattern and a reason are required.']); exit; }
    if (in_array($scope, ['file_hash','path','path_size'], true) && strpos($value, '/home/') !== 0) { echo json_encode(['ok'=>false,'msg'=>'Refused: only paths under /home/<account>/ can be whitelisted.']); exit; }
    $id = smpro_fe_wl_add($acct, $scope, $value, ['reason'=>$reason]); smpro_fa_cache_clear();
    echo json_encode(['ok'=>true,'id'=>$id,'msg'=>'Whitelisted. Future re-alerts on this file are suppressed; genuine tampering (new obfuscation, 10× size jump) still fires.'], JSON_UNESCAPED_SLASHES); exit;
}
if ($reqMethod === 'POST' && ($_POST['fa_action'] ?? '') === 'fx_wl_remove') {
    smpro_require_valid_csrf('fa_remediate'); smpro_require_root();
    header('Content-Type: application/json');
    $ok = function_exists('smpro_fe_wl_remove') && smpro_fe_wl_remove((string)($_POST['id'] ?? '')); smpro_fa_cache_clear();
    echo json_encode(['ok'=>$ok,'msg'=>$ok?'Removed — the detector re-arms on the next scan.':'Not found.'], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit;
}
if ($reqMethod === 'POST' && ($_POST['fa_action'] ?? '') === 'fx_baseline_accept') {
    smpro_require_valid_csrf('fa_remediate'); smpro_require_root();
    header('Content-Type: application/json');
    $acct = preg_replace('/[^a-zA-Z0-9._-]/', '', (string)($_POST['account'] ?? ''));
    $file = (string)($_POST['file'] ?? '');
    if (!function_exists('smpro_fx_scope') || strpos($file, smpro_user_home($acct) . '/') !== 0 || !is_file($file)) { echo json_encode(['ok'=>false,'msg'=>'Invalid file.']); exit; }
    $sc = smpro_fx_scope($acct); $deep = smpro_fx_deepfile($file, $sc);
    $ok = smpro_fx_baseline_accept($acct, $deep);
    echo json_encode(['ok'=>$ok,'msg'=>'Current state accepted as the baseline for this file.'], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit;
}

/* ---- Comprehensive Account Forensics: flagged-file deep-report renderer (English-only) ---- */
function smpro_fx_render_flagged($rep, $csrf) {
    $h = fn($s) => htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');
    $vmap = ['false_positive_likely' => ['LIKELY FALSE POSITIVE', '#2563eb', '#eff4ff'], 'suspicious' => ['SUSPICIOUS — REVIEW', '#b45309', '#fff7ed'], 'likely_compromised' => ['COMPROMISE LIKELY', '#b91c1c', '#fef2f2'], 'clean' => ['CLEAN', '#15803d', '#f0fdf4']];
    $vm = $vmap[$rep['verdict']] ?? $vmap['clean'];
    echo '<div class="fx-rep">';
    echo '<div class="fx-banner" style="background:' . $vm[2] . ';border-color:' . $vm[1] . '"><div class="fx-vl" style="color:' . $vm[1] . '">' . $h($vm[0]) . '</div><div class="fx-vm">Account <b>' . $h($rep['user']) . '</b> · ' . count($rep['sections']) . ' flagged file(s) · risk score ' . (int)$rep['score'] . '/100 · read-only · ' . $h(date('Y-m-d H:i', (int)$rep['ran_at'])) . ($rep['partial'] ? ' · <span class="fx-partial">PARTIAL</span>' : '') . '</div></div>';
    foreach ($rep['sections'] as $s) {
        $d = $s['deep']; $fe = $s['flag_explain']; $v = $s['verdict'];
        echo '<div class="fx-file"><div class="fx-fh"><b class="mono">' . $h($d['path']) . '</b><span class="fx-band b-' . $h($d['band']) . '">' . $h(strtoupper($d['band'])) . '</span></div>';
        // Flag explanation
        echo '<div class="fx-sec"><h4>Why it was flagged</h4><p>' . $h($fe['verdict_contrast_text']) . '</p>';
        echo '<div class="fx-kv"><span>Matched families</span><b>' . $h(implode(', ', $fe['matched_families']) ?: 'none') . '</b></div>';
        echo '<div class="fx-kv"><span>In webroot</span><b>' . ($fe['in_webroot'] ? 'yes' : 'no') . '</b></div>';
        if ($fe['changed_within_min'] !== null) echo '<div class="fx-kv"><span>Modified</span><b>' . (int)$fe['changed_within_min'] . ' min ago</b></div>';
        echo '</div>';
        // Deep analysis
        echo '<div class="fx-sec"><h4>Deep analysis</h4>';
        echo '<div class="fx-kv"><span>SHA-256</span><b class="mono">' . $h(substr($d['sha256'], 0, 32)) . '…</b></div>';
        echo '<div class="fx-kv"><span>Size / owner / perms</span><b>' . $h(smpro_fx_human_bytes($d['size'])) . ' · owner ' . $h($d['owner_ok']) . ' · ' . $h($d['mode']) . '</b></div>';
        echo '<div class="fx-kv"><span>Entropy</span><b>' . $h($d['entropy']) . ($d['entropy'] >= 7.2 ? ' (packed/encoded)' : ' (normal PHP)') . '</b></div>';
        echo '<div class="fx-kv"><span>Nested decode→eval chain</span><b>' . ($d['nested_chain'] ? '<span style="color:#b91c1c">YES</span>' : '0') . '</b></div>';
        if (is_array($d['baseline_delta'])) echo '<div class="fx-kv"><span>Baseline diff</span><b>' . ($d['baseline_delta']['fingerprint_identical'] ? 'content-only edit (token fingerprint identical)' : (($d['baseline_delta']['added_families'] ? 'ADDED: ' . $h(implode(',', $d['baseline_delta']['added_families'])) : 'changed'))) . '</b></div>';
        if ($d['tokens']) { echo '<div class="fx-toks"><span>Top tokens:</span> '; foreach (array_slice($d['tokens'], 0, 5) as $t) echo '<code title="line ' . (int)$t['line'] . '">' . $h($t['token']) . '</code> '; echo '</div>'; }
        echo '</div>';
        // Correlation banners
        if ($s['web']) echo '<div class="fx-corr ' . ($s['web']['possible_drop'] || $s['web']['attack_hit'] ? 'bad' : 'good') . '"><b>Web-attack correlation:</b> ' . $h($s['web']['result']['banner'] ?? '') . '</div>';
        if ($s['auth']) { $ah = $s['auth']['verdict_hint']; $amap = ['app_self_write' => 'No interactive login explains this write — consistent with a legitimate app self-write / local edit.', 'admin_session_write' => 'The write correlates to an admin login session.', 'interactive_upload' => 'An interactive upload (FTP STOR / File Manager) wrote this file.', 'no_login_explains_write' => 'A write occurred with no matching login.']; echo '<div class="fx-corr ' . ($ah === 'no_login_explains_write' ? 'bad' : 'good') . '"><b>Access/auth correlation:</b> ' . $h($amap[$ah] ?? $ah) . '</div>'; }
        // Verdict reasoning
        echo '<div class="fx-sec"><h4>Verdict — ' . $h($vmap[$v['verdict']][0] ?? $v['verdict']) . ' (score ' . (int)$v['score'] . ')</h4><ul class="fx-reason">';
        foreach ($v['reasoning'] as $r) echo '<li>' . $h($r) . '</li>';
        echo '</ul></div>';
        // Actions
        echo '<div class="fx-acts">';
        echo '<button class="tp-btn primary" onclick="fxWl(this,\'path\',' . htmlspecialchars(json_encode($d['path'], JSON_INVALID_UTF8_SUBSTITUTE), ENT_QUOTES) . ',' . htmlspecialchars(json_encode($rep['user'], JSON_INVALID_UTF8_SUBSTITUTE), ENT_QUOTES) . ')">&#128272; Whitelist this file (stop re-alerts)</button>';
        echo '<button class="tp-btn" onclick="fxBaseline(this,' . htmlspecialchars(json_encode($d['path'], JSON_INVALID_UTF8_SUBSTITUTE), ENT_QUOTES) . ',' . htmlspecialchars(json_encode($rep['user'], JSON_INVALID_UTF8_SUBSTITUTE), ENT_QUOTES) . ')">Accept current as baseline</button>';
        echo '<a class="tp-btn" href="index.cgi?page=forensics-audit&fx_user=' . urlencode($rep['user']) . '&fx_file=' . urlencode($d['path']) . '">&#8635; Re-scan</a>';
        echo '</div></div>';
    }
    if ($rep['partial']) { echo '<div class="fx-skip"><b>Partial run — not collected:</b> ' . $h(implode('; ', $rep['partial'])) . '</div>'; }
    echo '<div class="fx-foot">Read-only collection — no account files were modified.</div>';
    echo '</div>';
    smpro_fx_render_assets($csrf);
}
function smpro_fx_human_bytes($b) { $b = (int)$b; return $b >= 1048576 ? round($b / 1048576, 1) . ' MB' : ($b >= 1024 ? round($b / 1024) . ' KB' : $b . ' B'); }
function smpro_fx_render_wl_manager($wl, $csrf, $user) {
    $h = fn($s) => htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');
    echo '<div class="fx-rep"><div class="fx-sec"><h4>&#128272; Whitelist Manager <span style="font-weight:400;color:var(--muted)">(' . count($wl) . ' entr' . (count($wl) === 1 ? 'y' : 'ies') . ' — shared with the Malicious-Upload detector)</span></h4>';
    if (!$wl) echo '<p class="sub">No whitelist entries. Whitelist a file from its forensics report to stop false-positive re-alerts.</p>';
    else {
        echo '<table class="smpro-table"><thead><tr><th>Scope</th><th>File / pattern</th><th>Account</th><th>Reason</th><th>Added</th><th></th></tr></thead><tbody>';
        foreach ($wl as $e) {
            echo '<tr><td><span class="fx-band b-info">' . $h($e['scope']) . '</span>' . (!empty($e['migrated']) ? ' <span class="sub">migrated</span>' : '') . '</td><td class="mono" style="word-break:break-all">' . $h($e['value']) . '</td><td>' . $h($e['account'] ?: 'all') . '</td><td>' . $h($e['reason']) . '</td><td class="sub">' . $h(substr((string)($e['created_at'] ?? ''), 0, 10)) . '</td><td><button class="tp-btn danger" onclick="fxWlDel(this,' . htmlspecialchars(json_encode($e['id'], JSON_INVALID_UTF8_SUBSTITUTE), ENT_QUOTES) . ')">Remove</button></td></tr>';
        }
        echo '</tbody></table><p class="sub">Removing an entry re-arms the detector on the next scan.</p>';
    }
    echo '</div></div>';
    smpro_fx_render_assets($csrf);
}
function smpro_fx_render_assets($csrf) {
    static $once = false; if ($once) return; $once = true;
    ?>
<style>
.fx-rep{margin:10px 0 16px}
.fx-banner{border:1px solid;border-left-width:5px;border-radius:12px;padding:14px 18px;margin-bottom:12px}
.fx-vl{font-size:20px;font-weight:800;letter-spacing:.02em}.fx-vm{font-size:12.5px;color:var(--muted);margin-top:3px}
.fx-partial{background:#fef3c7;color:#92400e;border-radius:6px;padding:1px 7px;font-weight:700}
.fx-file{border:1px solid var(--line);border-radius:12px;padding:0 16px 14px;margin-bottom:12px;background:var(--card)}
.fx-fh{display:flex;justify-content:space-between;align-items:center;gap:10px;padding:12px 0;border-bottom:1px solid var(--line);flex-wrap:wrap}
.fx-fh b{word-break:break-all;font-size:13px}
.fx-band{font-size:10px;font-weight:800;padding:3px 9px;border-radius:7px;text-transform:uppercase;white-space:nowrap}
.fx-band.b-clean,.fx-band.b-info,.fx-band.b-low{background:var(--card);color:#475569;border:1px solid var(--line)}
.fx-band.b-medium{background:#fff7ed;color:#b45309}.fx-band.b-high{background:#fef2f2;color:#b91c1c}.fx-band.b-critical{background:#b91c1c;color:#fff}
.fx-sec{padding:12px 0 4px;border-bottom:1px dashed var(--line)}.fx-sec:last-child{border-bottom:0}
.fx-sec h4{margin:0 0 8px;font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
.fx-sec p{font-size:13px;margin:0 0 8px;line-height:1.5}
.fx-kv{display:flex;justify-content:space-between;gap:14px;padding:3px 0;font-size:13px;border-bottom:1px solid var(--line)}.fx-kv:last-child{border-bottom:0}.fx-kv span{color:var(--muted)}
.fx-toks{font-size:12px;color:var(--muted);padding-top:6px}.fx-toks code{background:var(--bg);border:1px solid var(--line);border-radius:5px;padding:1px 6px;color:#334155;font-size:11px}
.fx-corr{border-radius:9px;padding:9px 12px;margin:10px 0;font-size:12.5px}.fx-corr.good{background:var(--good-bg);color:var(--good)}.fx-corr.bad{background:var(--dang-bg);color:#b91c1c}
.fx-reason{margin:0;padding-left:18px;font-size:12.5px;line-height:1.6}
.fx-acts{display:flex;gap:9px;flex-wrap:wrap;padding-top:12px}
.fx-skip{background:#fff7ed;color:#92702a;border-radius:9px;padding:10px 13px;font-size:12.5px;margin-bottom:10px}
.fx-foot{color:var(--muted);font-size:12px;text-align:center;padding:8px}
</style>
<script>
(function(){
  if(window.__fxWired)return; window.__fxWired=1;
  var C=<?= json_encode($csrf) ?>;
  function post(fd){return fetch('index.cgi?page=forensics-audit',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'}).then(function(r){return r.json();});}
  window.fxWl=function(btn,scope,file,acct){var reason=prompt('Reason for whitelisting this file (required):','Legitimate large single-file application');if(!reason)return;btn.disabled=true;var t=btn.innerHTML;btn.innerHTML='⏳ …';var fd=new URLSearchParams();fd.set('fa_action','fx_wl_add');fd.set('smpro_csrf',C);fd.set('account',acct);fd.set('scope',scope);fd.set('value',file);fd.set('reason',reason);post(fd).then(function(k){btn.disabled=false;btn.innerHTML=t;alert((k&&k.ok?'✅ ':'⚠ ')+((k&&k.msg)||'failed'));}).catch(function(){btn.disabled=false;btn.innerHTML=t;alert('Request failed.');});};
  window.fxWlDel=function(btn,id){if(!confirm('Remove this whitelist entry? The detector re-arms on the next scan.'))return;var fd=new URLSearchParams();fd.set('fa_action','fx_wl_remove');fd.set('smpro_csrf',C);fd.set('id',id);post(fd).then(function(k){alert((k&&k.ok?'✅ ':'⚠ ')+((k&&k.msg)||'failed'));if(k&&k.ok){var tr=btn.closest('tr');if(tr)tr.remove();}}).catch(function(){alert('Request failed.');});};
  window.fxBaseline=function(btn,file,acct){var fd=new URLSearchParams();fd.set('fa_action','fx_baseline_accept');fd.set('smpro_csrf',C);fd.set('file',file);fd.set('account',acct);post(fd).then(function(k){alert((k&&k.ok?'✅ ':'⚠ ')+((k&&k.msg)||'failed'));}).catch(function(){alert('Request failed.');});};
})();
</script>
    <?php
}

/* ---- IOC export (Phase 4): plain-text indicator list served by index.cgi ---- */
if ($fmt === 'ioc') {
    $fd = smpro_fa_findings($user, false)['findings'];
    $io = smpro_fa_iocs($fd, smpro_fa_login_timeline(60)['rows']);
    echo smpro_fa_ioc_text($io, $user);
    exit;
}

/* ---- exports (CSV / HTML / PDF) served by index.cgi ---- */
if (in_array($fmt, ['csv','html','pdf'], true)) {
    $savedReq = preg_replace('/[^a-zA-Z0-9_-]/', '', (string)($_GET['saved'] ?? ''));
    if ($savedReq !== '') {
        $idx = smpro_fa_json_load(SMPRO_FA_REPIDX); $path = (string)($idx[$savedReq]['path'] ?? '');
        $rep = ($path && strpos($path, SMPRO_FA_REPORTS) === 0 && is_file($path)) ? smpro_fa_json_load($path) : [];
        $findings = $rep['findings'] ?? []; $meta = ['scope'=>$rep['scope'] ?? $user,'saved_id'=>$savedReq];
        $expTimeline = $rep['timeline'] ?? [];   // saved snapshot's foreign-login rows (older saves have none)
    } else { $findings = smpro_fa_findings($user, false)['findings']; $meta = ['scope'=>$user]; $expTimeline = smpro_fa_login_timeline(60)['rows']; }
    if ($fmt === 'csv') {
        $fh = fopen('php://output','w');
        smpro_fputcsv($fh, ['severity','confidence','category','account','title','evidence','reference','recommended_action','detected']);
        foreach ($findings as $f) smpro_fputcsv($fh, [$f['sev'],$f['conf'],$f['cat'],$f['account'],$f['title'],$f['evidence'],$f['ref'],$f['action'],$f['ts']?date('Y-m-d H:i',$f['ts']):'']);
        fclose($fh);
    } else smpro_fa_render_report($findings, $meta, $fmt === 'pdf', $expTimeline);
    exit;
}

/* =========================== collect for display =========================== */
$force = isset($_GET['rescan']);
$fdata = smpro_fa_findings($user, $force);
$findings = $fdata['findings'];
$sum = smpro_fa_summary($findings);
$result = isset($scanTypes[$scan]) ? smpro_fa_scan($scan, $user, smpro_fa_path($user), $days) : null;
if ($result !== null) smpro_audit('forensics_scan', ['scan'=>$scan,'user'=>$user,'hits'=>count($result['rows'])]);
$tl = smpro_fa_login_timeline(25);
$timeline = $tl['rows']; $tlHidden = $tl['hidden_local']; $tlArab = $tl['hidden_arab'];
$incidents = smpro_fa_timeline_events($findings, $timeline);
$iocs = smpro_fa_iocs($findings, $timeline);
$iocCount = count($iocs['files']) + count($iocs['hashes']) + count($iocs['ips']) + count($iocs['urls']) + count($iocs['cron']) + count($iocs['keys']);
$saved = smpro_fa_saved();
$allowed = smpro_fa_allow_load();
uasort($allowed, fn($a,$b)=>($b['added_ts'] ?? 0) <=> ($a['added_ts'] ?? 0));
$manifest = smpro_fa_manifest_load();
uasort($manifest, fn($a,$b)=>($b['applied_ts'] ?? 0) <=> ($a['applied_ts'] ?? 0));
$manifest = array_slice($manifest, 0, 30, true);
$detReports = smpro_fa_detection_reports(40);
$csrfSave = smpro_csrf_generate('fa_save');
$csrfDel  = smpro_csrf_generate('fa_delete');
$csrfRem  = smpro_csrf_generate('fa_remediate');
$aiReady  = function_exists('smpro_ai_available') && smpro_ai_available();

smpro_audit('forensics_audit_view', ['scope'=>$user,'findings'=>$sum['total']]);
smpro_layout_header('Forensics / Audit');
$sevcls = ['critical'=>'red','high'=>'orange','medium'=>'blue','info'=>'gray'];
$qs = fn($t) => 'index.cgi?page=forensics-audit&scan=' . $t . '&user=' . urlencode($user) . '&days=' . $days;
$ageMin = max(0, (int)floor((time() - (int)$fdata['scanned_ts']) / 60));
?>
<div class="svc-kicker">Investigation</div>
<h1 class="h" style="margin:2px 0 4px">Forensics / Audit</h1>
<p class="sub">Consolidated, explained findings from light sources only (Imunify360 + cron / SSH keys / shell-init). No heavy scan. Deep file scans below are on-demand &amp; throttled.</p>
<?php
// ---- the overview: one tile per section, read from the values the cards below already use (no extra reads)
$faOv = [
  ['id' => 'fa-findings', 'l' => 'Findings', 'v' => (string)(int)$sum['total'], 'cls' => ((int)$sum['critical'] > 0 ? 'dang' : ((int)$sum['high'] > 0 ? 'warn' : 'good')), 's' => (int)$sum['critical'] . ' critical · ' . (int)$sum['high'] . ' high'],
  ['id' => 'fa-timeline', 'l' => 'Incidents', 'v' => (string)count($incidents), 'cls' => $incidents ? 'brand' : 'muted', 's' => 'correlated timeline events'],
  ['id' => 'fa-ioc', 'l' => 'IOCs', 'v' => (string)(int)$iocCount, 'cls' => $iocCount ? 'warn' : 'muted', 's' => 'indicators to block / hunt'],
  ['id' => 'fa-foreign', 'l' => 'Foreign logins', 'v' => (string)count($timeline), 'cls' => $timeline ? 'warn' : 'good', 's' => 'recent attempts outside the home regions'],
  ['id' => 'fa-detrep', 'l' => 'Pending actions', 'v' => (string)count($detReports), 'cls' => $detReports ? 'brand' : 'muted', 's' => 'recorded detection actions'],
  ['id' => 'fa-keys', 'l' => 'Trusted keys', 'v' => (string)count($allowed), 'cls' => $allowed ? 'good' : 'muted', 's' => 'SSH keys suppressed from findings'],
];
$faNav = array_values(array_filter([
  ['fa-findings', '&#128269; Findings'], ['faImHist', '&#129302; Imunify history'], $detReports ? ['fa-detrep', '&#128203; Action reports'] : null,
  ['fa-timeline', '&#128338; Timeline'], ['fa-ioc', '&#9888; IOCs'], $allowed ? ['fa-keys', '&#10003; Trusted keys'] : null, $manifest ? ['fa-remed', '&#8635; Remediation'] : null,
  ['fa-foreign', '&#127757; Foreign logins'], ['fa-preflight', '&#128196; Log preflight'], ['fa-saved', '&#128190; Saved reports'],
]));
?>
<div class="fw-kpis">
  <?php foreach ($faOv as $k): ?>
  <a class="fw-kpi <?= $k['cls'] ?>" href="#<?= $k['id'] ?>" data-go="<?= $k['id'] ?>"><div class="l"><?= smpro_h($k['l']) ?></div><div class="v"><?= smpro_h($k['v']) ?></div><div class="s"><?= smpro_h($k['s']) ?></div></a>
  <?php endforeach; ?>
</div>
<nav class="fw-nav" id="fwNav"><?php foreach ($faNav as [$id, $lbl]): ?><a href="#<?= $id ?>" data-go="<?= $id ?>"><?= $lbl ?></a><?php endforeach; ?><span class="sp"></span><button type="button" class="fw-navx" id="fwOpenAll">expand all</button><button type="button" class="fw-navx" id="fwCloseAll">collapse all</button></nav>

<?php
/* ===== Comprehensive Account Forensics — flagged-file deep report ("Open Forensics") ===== */
$fxUser = preg_replace('/[^a-zA-Z0-9._-]/', '', (string)($_GET['fx_user'] ?? ''));
$fxFile = (string)($_GET['fx_file'] ?? '');
$fxFile = ($fxUser !== '' && $fxFile !== '' && function_exists('smpro_path_safe')) ? smpro_path_safe($fxFile, [smpro_user_home($fxUser)]) : '';   // resolved, no .., no link, inside the home
if ($fxUser !== '' && $fxFile !== '' && function_exists('smpro_fx_run_flagged')) {
    $fxTs = (int)($_GET['fx_ts'] ?? time());
    $rep = smpro_fx_run_flagged($fxUser, [$fxFile], ['alert_ts' => $fxTs]);
    if (!empty($rep['ok'])) smpro_fx_render_flagged($rep, $csrfRem);
    else echo '<div class="card" style="color:var(--dang);padding:14px">' . smpro_h($rep['msg'] ?? 'Forensics run failed.') . '</div>';
}
/* ===== Whitelist Manager (Malicious-Upload / Forensics suppression list) ===== */
if (($_GET['fx_wl'] ?? '') === '1' && function_exists('smpro_fe_wl_load')) smpro_fx_render_wl_manager(smpro_fe_wl_load(), $csrfRem, $user);
?>
<?php if (function_exists('smpro_fx_run_flagged')): ?>
<form method="get" action="index.cgi" class="fa-bar" style="align-items:flex-end;gap:8px;margin:6px 0 4px">
  <input type="hidden" name="page" value="forensics-audit">
  <label class="fa-fld" style="flex:0 0 auto">Deep-analyze a flagged file<select class="tp-sel" name="fx_user"><option value="">account…</option>
    <?php foreach ($users as $u): ?><option value="<?= smpro_h($u) ?>"<?= $fxUser===$u?' selected':'' ?>><?= smpro_h($u) ?></option><?php endforeach; ?></select></label>
  <label class="fa-fld" style="flex:1;min-width:280px"><input class="tp-in mono" name="fx_file" value="<?= smpro_h($fxFile) ?>" placeholder="/home/&lt;account&gt;/…/Protector.php  (paste the flagged path)"></label>
  <button class="tp-btn primary" type="submit">&#128269; Deep-analyze</button>
  <a class="tp-btn" href="index.cgi?page=forensics-audit&fx_wl=1&user=<?= urlencode($user) ?>">&#128272; Whitelist Manager</a>
</form>
<p class="sub" style="margin:0 0 10px;font-size:12px">Paste the exact path from a "[Malicious Upload]" alert (e.g. the account's docroot + <code>Protector.php</code>) to get a read-only real-vs-false-positive verdict, then whitelist it if it is legitimate.</p>
<?php else: ?>
<div style="margin:6px 0 10px"><a class="tp-btn" href="index.cgi?page=forensics-audit&fx_wl=1&user=<?= urlencode($user) ?>">&#128272; Whitelist Manager</a></div>
<?php endif; ?>


<form method="get" action="index.cgi" class="fa-bar">
  <input type="hidden" name="page" value="forensics-audit">
  <label class="fa-fld">Scope (account)<select class="tp-sel" name="user"><option value="all"<?= $user==='all'?' selected':'' ?>>All accounts</option>
    <?php foreach ($users as $u): ?><option value="<?= smpro_h($u) ?>"<?= $user===$u?' selected':'' ?>><?= smpro_h($u) ?></option><?php endforeach; ?></select></label>
  <label class="fa-fld">Changed within (file scans)<select class="tp-sel" name="days"><?php foreach ([1=>'1 day',3=>'3 days',7=>'7 days',14=>'14 days',30=>'30 days'] as $k=>$v): ?><option value="<?= $k ?>"<?= $days===$k?' selected':'' ?>><?= $v ?></option><?php endforeach; ?></select></label>
  <?php if ($scan): ?><input type="hidden" name="scan" value="<?= smpro_h($scan) ?>"><?php endif; ?>
  <button class="tp-btn primary" type="submit">Apply scope</button>
  <a class="tp-btn" href="index.cgi?page=forensics-audit&user=<?= urlencode($user) ?>&days=<?= $days ?>&rescan=1" title="Re-read all light sources now">&#8635; Re-scan</a>
  <span class="fa-age">findings as of <?= $ageMin===0?'just now':$ageMin.' min ago' ?></span>
</form>

<!-- ===== KPI summary ===== -->
<?php $critN=(int)$sum['critical']; $highN=(int)$sum['high']; $medN=(int)$sum['medium']; $mwN=(int)$sum['malware']; $psN=(int)$sum['persist']; $acN=(int)$sum['accounts']; ?>
<div class="fa-stats">
  <div class="fa-stat <?= $critN?'danger':'ok' ?>">
    <div class="fa-stat-ic"><?= $critN?'&#9760;':'&#10003;' ?></div>
    <div class="fa-stat-b"><div class="fa-stat-n"><?= $critN ?></div><div class="fa-stat-l">Critical</div><div class="fa-stat-s"><?= $critN?'act immediately':'none' ?></div></div>
  </div>
  <div class="fa-stat <?= $highN?'warn':'ok' ?>">
    <div class="fa-stat-ic">&#9888;</div>
    <div class="fa-stat-b"><div class="fa-stat-n"><?= $highN ?></div><div class="fa-stat-l">High</div><div class="fa-stat-s"><?= $highN?'review soon':'none' ?></div></div>
  </div>
  <div class="fa-stat <?= $medN?'info':'ok' ?>">
    <div class="fa-stat-ic">&#128269;</div>
    <div class="fa-stat-b"><div class="fa-stat-n"><?= $medN ?></div><div class="fa-stat-l">Needs review</div><div class="fa-stat-s">medium confidence</div></div>
  </div>
  <div class="fa-stat <?= $mwN?'danger':'ok' ?>">
    <div class="fa-stat-ic">&#129440;</div>
    <div class="fa-stat-b"><div class="fa-stat-n"><?= $mwN ?></div><div class="fa-stat-l">Active malware</div><div class="fa-stat-s"><?= $mwN?'confirmed':'clean' ?></div></div>
  </div>
  <div class="fa-stat <?= $psN?'warn':'ok' ?>">
    <div class="fa-stat-ic">&#128257;</div>
    <div class="fa-stat-b"><div class="fa-stat-n"><?= $psN ?></div><div class="fa-stat-l">Persistence</div><div class="fa-stat-s">cron / startup hooks</div></div>
  </div>
  <div class="fa-stat <?= $acN?'info':'ok' ?>">
    <div class="fa-stat-ic">&#128101;</div>
    <div class="fa-stat-b"><div class="fa-stat-n"><?= $acN ?></div><div class="fa-stat-l">Accounts affected</div><div class="fa-stat-s"><?= $acN?'see cards below':'none' ?></div></div>
  </div>
</div>
<?php if (!empty($sum['by_account'])): $affList = $sum['by_account']; uasort($affList, fn($a, $b) => ((int)($b['n'] ?? 0)) <=> ((int)($a['n'] ?? 0))); ?>
<div class="card fa-affcard">
  <div class="fa-affhd">
    <b>&#128101; <?= count($affList) ?> affected account<?= count($affList) === 1 ? '' : 's' ?></b>
    <input type="search" class="tp-in fa-affsearch" id="faAffSearch" placeholder="&#128269; filter accounts…" autocomplete="off" spellcheck="false">
    <span class="meta fa-affhint">most findings first · click one to scope the page to it</span>
  </div>
  <div class="fa-affgrid" id="faAffGrid">
    <?php foreach ($affList as $acct => $info): $cats = array_keys((array)($info['cats'] ?? [])); $crit = in_array('Active malware', $cats, true) || ($info['sev'] ?? '') === 'critical'; ?>
      <a class="fa-achip<?= $crit ? ' crit' : '' ?>" data-acct="<?= smpro_h(strtolower((string)$acct)) ?>" href="index.cgi?page=forensics-audit&user=<?= urlencode($acct) ?>" title="<?= smpro_h(implode(', ', $cats)) ?>">
        <span class="fa-achip-n"><?= (int)($info['n'] ?? 0) ?></span>
        <span class="fa-achip-name"><?= smpro_h($acct) ?></span>
        <span class="fa-achip-cat"><?= smpro_h($cats ? $cats[0] : '') ?></span>
      </a>
    <?php endforeach; ?>
  </div>
  <div class="fa-affempty" id="faAffEmpty" style="display:none">No account matches your filter.</div>
</div>
<script>(function(){var s=document.getElementById('faAffSearch'),g=document.getElementById('faAffGrid'),e=document.getElementById('faAffEmpty');if(!s||!g)return;
  s.addEventListener('input',function(){var q=s.value.trim().toLowerCase(),n=0;Array.prototype.forEach.call(g.querySelectorAll('.fa-achip'),function(c){var m=!q||c.getAttribute('data-acct').indexOf(q)>=0;c.style.display=m?'':'none';if(m)n++;});if(e)e.style.display=n?'none':'';});})();</script>
<?php endif; ?>

<!-- ===== Findings ===== -->
<div class="card" id="fa-findings" style="padding:0;overflow:hidden;margin:14px 0;border-top:3px solid <?= $sum['critical']?'var(--dang)':($sum['high']?'#c2710c':'var(--good)') ?>">
  <div class="fa-head">
    <b>&#128269; Investigation Findings</b>
    <span class="meta"><?= $sum['total'] ?> finding(s) · scope <?= smpro_h($user==='all'?'all accounts':$user) ?></span>
    <div class="fa-acts">
      <?php if ($aiReady): ?><button class="tp-btn fa-ai" id="faAiDecide" type="button">&#129302; AI: analyze &amp; decide</button><?php endif; ?>
      <button class="tp-btn" id="faSave" type="button">&#128190; Save report</button>
      <div class="fa-dd"><button class="tp-btn" type="button" id="faExp">Export &#9662;</button>
        <div class="fa-menu" id="faExpMenu">
          <a href="index.cgi?page=forensics-audit&format=csv&user=<?= urlencode($user) ?>">CSV</a>
          <a href="index.cgi?page=forensics-audit&format=html&user=<?= urlencode($user) ?>" target="_blank">HTML</a>
          <a href="index.cgi?page=forensics-audit&format=pdf&user=<?= urlencode($user) ?>" target="_blank">PDF (print)</a>
          <a href="index.cgi?page=forensics-audit&format=ioc&user=<?= urlencode($user) ?>">IOCs (.txt)</a>
        </div>
      </div>
    </div>
  </div>
  <?php if (!$findings): ?>
    <div class="fa-empty" style="color:var(--good)">&#10003; No findings from the light sources for this scope. Run a deep file scan below for a fuller check.</div>
  <?php else: ?>
  <div class="fa-pager" id="faFindPager"><span class="meta" id="faFindInfo"></span><span><button class="tp-btn ui-sm" type="button" id="faFindPrev">&#8249;</button> <span id="faFindNum" class="mono"></span> <button class="tp-btn ui-sm" type="button" id="faFindNext">&#8250;</button></span></div>
  <div class="fa-tablewrap" style="max-height:560px"><table class="smpro-table fa-find">
    <thead><tr><th style="width:26px"><input type="checkbox" id="fAll"></th><th>Severity</th><th>Category</th><th>Account</th><th>Finding &amp; evidence</th><th>What it means / recommended action</th></tr></thead><tbody>
    <?php /* rows are built in the browser 60 at a time from FIND (fBuildRow); 475 findings used to be 1 MB of HTML */ ?>
    </tbody></table></div>
  <script>
  var FIND = <?= json_encode(array_values(array_map(fn($f) => [
      'sev' => (string)($f['sev'] ?? 'info'), 'conf' => (string)($f['conf'] ?? ''), 'cat' => (string)($f['cat'] ?? ''), 'account' => (string)($f['account'] ?? ''),
      'title' => (string)($f['title'] ?? ''), 'evidence' => (string)($f['evidence'] ?? ''), 'ref' => (string)($f['ref'] ?? ''), 'means' => (string)($f['means'] ?? ''),
      'action' => (string)($f['action'] ?? ''), 'act' => (string)($f['act'] ?? ''), 'actlabel' => (string)($f['actlabel'] ?? ''),
      'raw' => ($f['raw'] ?? '') !== '' ? base64_encode((string)$f['raw']) : '', 'rawtxt' => (string)($f['raw'] ?? ''), 'imid' => (string)($f['imid'] ?? ''), 'stale' => !empty($f['stale']), 'ts' => (int)($f['ts'] ?? 0),
  ], $findings)), JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE) ?>;
  var AI_READY = <?= !empty($aiReady) ? 'true' : 'false' ?>, FX_OK = <?= function_exists('smpro_fx_run_flagged') ? 'true' : 'false' ?>;
  var SEVCLS = {critical:'red', high:'orange', medium:'blue', info:'gray'};
  </script>
  <div class="fa-bulk" id="faBulk" hidden>
    <span class="fa-bulkn"><b id="fBulkN">0</b> selected</span>
    <button class="tp-btn" id="fBulkFix" type="button">&#9889; Apply fix (clean / remove / disable)</button>
    <button class="tp-btn" id="fBulkTrust" type="button">&#10003; Trust selected keys</button>
    <button class="tp-btn" id="fBulkClear" type="button">Clear</button>
    <span class="fa-bulkmsg" id="fBulkMsg"></span>
  </div>
  <?php endif; ?>
</div>

<!-- ===== Imunify360 detection history (aggregated, lazy-loaded so the page stays fast) ===== -->
<div id="faImHist" class="card" style="padding:0;overflow:hidden;margin:14px 0">
  <div class="fa-head"><b>&#129302; Imunify360 detection history</b><span class="meta">loading aggregated detections…</span></div>
  <div class="fa-scanprog"><span></span></div>
  <div class="fa-empty">Reading all Imunify360 detections in the background — this does not block the page.</div>
</div>
<?php
function smpro_fa_render_imhist($imHist, $user) {
    if ($imHist === null) { echo '<div class="card" style="padding:18px;color:var(--muted)">Imunify360 is not available.</div>'; return; }
    ?>
    <div class="fa-head"><b>&#129302; Imunify360 detection history</b><span class="meta"><?= number_format($imHist['total']) ?> total detections · scope <?= smpro_h($user==='all'?'all accounts':$user) ?></span></div>
    <div style="padding:14px 16px">
    <div class="fa-kpis" style="margin:0 0 12px">
      <div class="kpi"><div class="kn"><?= number_format($imHist['total']) ?></div><div class="kl">Total detections</div></div>
      <div class="kpi"><div class="kn"><?= number_format($imHist['files']) ?></div><div class="kl">File detections</div></div>
      <div class="kpi <?= $imHist['db']?'crit':'' ?>"><div class="kn"><?= number_format($imHist['db']) ?></div><div class="kl">DB injections</div></div>
      <div class="kpi"><div class="kn"><?= number_format($imHist['events']['cleanup_done'] ?? 0) ?></div><div class="kl">Cleaned</div></div>
      <div class="kpi"><div class="kn"><?= number_format($imHist['events']['cleanup_removed'] ?? 0) ?></div><div class="kl">Removed</div></div>
      <div class="kpi <?= ($imHist['events']['failed_to_cleanup'] ?? 0)?'crit':'' ?>"><div class="kn"><?= number_format($imHist['events']['failed_to_cleanup'] ?? 0) ?></div><div class="kl">Failed to clean</div></div>
    </div>
    <div class="ar-two">
      <div>
        <div class="fa-grouplbl">Top affected accounts</div>
        <?php foreach (array_slice($imHist['accounts'],0,8,true) as $ac=>$n): ?><div class="fa-iline"><a class="fa-lnk" href="index.cgi?page=forensics-audit&user=<?= urlencode($ac) ?>"><?= smpro_h($ac) ?></a><span><?= number_format($n) ?></span></div><?php endforeach; ?>
      </div>
      <div>
        <div class="fa-grouplbl">Malware families</div>
        <?php foreach (array_slice($imHist['families'],0,8,true) as $fm=>$n): ?><div class="fa-iline"><span class="mono"><?= smpro_h($fm) ?></span><span><?= number_format($n) ?></span></div><?php endforeach; ?>
      </div>
    </div>
    <div class="fa-grouplbl" style="margin-top:12px;display:flex;align-items:center;gap:10px;flex-wrap:wrap">Recent detections (incl. DB injections)
      <span style="flex:1"></span>
      <label class="fa-histsel"><input type="checkbox" class="faHistAll"> select all on-disk</label>
      <button class="fa-lnk faHistDelSel" type="button" disabled style="color:var(--dang);border-color:#f3c4c4">&#128465; Delete selected (<b class="faHistN">0</b>)</button>
    </div>
    <div class="fw-pager" data-per="50"><input type="text" class="fw-pgq" placeholder="Filter rows&hellip;"><span class="fw-pginfo"></span><span class="sp"></span><span class="fw-pgctl"><button type="button" class="fw-pgbtn fw-pgprev">&#8249;</button> <span class="mono fw-pgnum"></span> <button type="button" class="fw-pgbtn fw-pgnext">&#8250;</button></span></div>
    <div class="fa-tablewrap" style="max-height:240px"><table class="smpro-table"><tbody>
      <?php foreach ($imHist['recent'] as $r): $exists = !$r['db'] && $r['path']!=='' && strpos($r['path'],'/home/')===0 && @is_file($r['path']); ?><tr data-row><td style="width:26px"><?php if ($exists): ?><input type="checkbox" class="faHistChk" data-file="<?= smpro_h($r['path']) ?>"><?php endif; ?></td><td><span class="b <?= $r['db']?'orange':'gray' ?>"><?= $r['db']?'DB':'file' ?></span></td><td class="mono"><?= smpro_h($r['account']) ?></td><td><span class="b <?= strpos($r['event'],'fail')!==false?'red':(strpos($r['event'],'clean')!==false?'green':'gray') ?>"><?= smpro_h($r['event']) ?></span></td><td class="mono fa-file"><?= smpro_h($r['path']) ?></td><td style="text-align:right;white-space:nowrap"><?php if ($exists): ?><button class="fa-lnk faDelMal" data-file="<?= smpro_h($r['path']) ?>" title="File still present — delete it (backed up outside the account first)">&#128465; Delete</button><?php elseif ($r['db']): ?><a class="fa-lnk" href="<?= smpro_h(rtrim((string)SMPRO_CPSESS,'/').'/cgi/imunify/handlers/index.cgi') ?>" target="_blank" title="DB injections are cleaned inside Imunify">Imunify ↗</a><?php else: ?><span class="meta" style="font-size:10px">handled</span><?php endif; ?></td></tr><?php endforeach; ?>
    </tbody></table></div>
    <div style="margin-top:10px"><a class="tp-btn" href="index.cgi?page=imunify360-reports">Full Imunify360 Report →</a></div>
    </div>
    <?php
}
?>

<!-- ===== Detection action reports (every destructive action, esp. deletions) ===== -->
<?php if ($detReports): ?>
<div class="card" id="fa-detrep" style="padding:0;overflow:hidden;margin:14px 0">
  <div class="fa-head"><b>&#128203; Detection action reports</b><span class="meta"><?= count($detReports) ?> recorded action(s) · backups in /home/backup/detections</span></div>
  <div class="fw-pager" data-per="50"><input type="text" class="fw-pgq" placeholder="Filter rows&hellip;"><span class="fw-pginfo"></span><span class="sp"></span><span class="fw-pgctl"><button type="button" class="fw-pgbtn fw-pgprev">&#8249;</button> <span class="mono fw-pgnum"></span> <button type="button" class="fw-pgbtn fw-pgnext">&#8250;</button></span></div>
  <div class="fa-tablewrap" style="max-height:300px"><table class="smpro-table"><thead><tr><th>When</th><th>Action</th><th>Account</th><th>File</th><th>SHA-256</th><th>Backup</th></tr></thead><tbody>
    <?php foreach ($detReports as $d): ?><tr data-row>
      <td class="mono"><?= smpro_h(isset($d['ts'])?date('Y-m-d H:i',(int)$d['ts']):'') ?></td>
      <td><span class="b red"><?= smpro_h(str_replace('_',' ',$d['action'] ?? '')) ?></span></td>
      <td class="mono"><?= smpro_h($d['account'] ?? '') ?></td>
      <td class="mono fa-file"><?= smpro_h($d['file'] ?? '') ?></td>
      <td class="mono" title="<?= smpro_h($d['sha256'] ?? '') ?>"><?= !empty($d['sha256'])?smpro_h(substr($d['sha256'],0,14)).'…':'—' ?></td>
      <td class="mono fa-file"><?= smpro_h(basename($d['backup'] ?? '')) ?></td>
    </tr><?php endforeach; ?>
  </tbody></table></div>
</div>
<?php endif; ?>

<!-- ===== Inline AI decision plan (no popup) ===== -->
<?php if ($aiReady && $findings): ?>
<div class="card faai-inline" id="faAiInline" style="margin:14px 0;padding:0;overflow:hidden" hidden>
  <div class="fa-head"><b>&#129302; AI Decision Plan</b><span class="meta" id="faAiMeta2"></span><button class="fa-lnk" id="faAiClose2" type="button" style="margin-left:auto">Hide</button></div>
  <div id="faAiBody2" style="padding:14px 16px"></div>
</div>
<?php endif; ?>

<!-- ===== Incident Timeline & IOCs (Phase 4) ===== -->
<div class="ar-two">
  <div class="card" id="fa-timeline" style="padding:0;overflow:hidden">
    <div class="fa-head"><b>&#128338; Incident Timeline</b><span class="meta"><?= count($incidents) ?> event(s), newest first</span></div>
    <div class="fa-tablewrap" style="max-height:420px"><div class="fa-tl">
      <?php if (!$incidents): ?><div class="fa-empty">No events to correlate.</div>
      <?php else: foreach ($incidents as $e): $c = $sevcls[$e['sev']] ?? 'gray'; ?>
        <div class="fa-tlrow">
          <div class="fa-tldot <?= $c ?>"></div>
          <div class="fa-tlbody">
            <div class="fa-tltop"><span class="b <?= $c ?>"><?= smpro_h($e['kind']) ?></span> <span class="fa-tltime mono"><?= $e['ts']?smpro_h(date('Y-m-d H:i',$e['ts'])):'time n/a' ?></span></div>
            <div class="fa-tltext"><?php if($e['who']):?><b class="mono"><?= smpro_h($e['who']) ?></b> — <?php endif;?><?= smpro_h($e['text']) ?></div>
            <?php if($e['ref']):?><div class="fa-ref mono"><?= smpro_h($e['ref']) ?></div><?php endif;?>
          </div>
        </div>
      <?php endforeach; endif; ?>
    </div></div>
  </div>
  <div class="card" id="fa-ioc" style="padding:0;overflow:hidden">
    <div class="fa-head"><b>&#9888; Indicators of Compromise</b><span class="meta"><?= (int)$iocCount ?> indicator(s)</span></div>
    <div style="padding:14px 16px">
      <details class="gl-fold"><summary><span class="fw-chev gl-chev">&#9656;</span>How this works</summary>
      <p class="fa-iocintro">Indicators of Compromise (IOCs) are the concrete traces an attack leaves behind. Use them to <b>block the source</b>, <b>hunt the same payload</b> on other accounts, and <b>brief your team</b>. Each type below tells you what it is and what to do.</p>
      </details>
      <div class="fa-iocgrid">
        <div class="fa-ioc"><span class="fa-iocn"><?= count($iocs['files']) ?></span><span class="fa-iocl">Malicious files</span><span class="fa-ioce">Files on disk to delete / quarantine.</span></div>
        <div class="fa-ioc"><span class="fa-iocn"><?= count($iocs['hashes']) ?></span><span class="fa-iocl">File hashes</span><span class="fa-ioce">SHA-256 — search other accounts for the same file.</span></div>
        <div class="fa-ioc"><span class="fa-iocn"><?= count($iocs['ips']) ?></span><span class="fa-iocl">Source IPs</span><span class="fa-ioce">Foreign login IPs — block in CSF firewall.</span></div>
        <div class="fa-ioc"><span class="fa-iocn"><?= count($iocs['urls']) ?></span><span class="fa-iocl">URLs</span><span class="fa-ioce">Payload / C2 addresses — block at firewall/DNS.</span></div>
        <div class="fa-ioc"><span class="fa-iocn"><?= count($iocs['cron']) ?></span><span class="fa-iocl">Cron entries</span><span class="fa-ioce">Scheduled re-infection tasks — remove them.</span></div>
        <div class="fa-ioc"><span class="fa-iocn"><?= count($iocs['keys']) ?></span><span class="fa-iocl">SSH keys</span><span class="fa-ioce">Unrecognized access keys — remove them.</span></div>
      </div>
      <?php if ($iocs['ips'] || $iocs['urls']): ?>
      <div class="fa-ioctop">
        <div class="fa-ioctt">Top indicators to act on</div>
        <?php foreach (array_slice($iocs['urls'],0,3) as $u): ?>
          <div class="fa-iocrow"><span class="b orange">URL</span> <span class="mono"><?= smpro_h($u) ?></span> <span class="fa-iocact">→ block at firewall/DNS</span></div>
        <?php endforeach; ?>
        <?php foreach (array_slice(array_keys($iocs['ips']),0,6) as $ip): ?>
          <div class="fa-iocrow"><span class="b red">IP</span> <span class="mono"><?= smpro_h($ip) ?></span> <span class="meta"><?= smpro_h($iocs['ips'][$ip]) ?></span> <span class="fa-iocact">→ block in CSF</span></div>
        <?php endforeach; ?>
      </div>
      <?php endif; ?>
      <div style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap;align-items:center">
        <a class="tp-btn primary" href="index.cgi?page=forensics-audit&format=ioc&user=<?= urlencode($user) ?>">&#11015; Export IOCs (.txt)</a>
        <span class="meta" style="font-size:11px">Plain-text list — paste into a blocklist or share with your IR team.</span>
      </div>
    </div>
  </div>
</div>

<!-- ===== Allowed (trusted) SSH keys ===== -->
<?php if ($allowed): ?>
<div class="card" id="fa-keys" style="padding:0;overflow:hidden;margin:14px 0">
  <div class="fa-head"><b>&#10003; Trusted SSH Keys</b><span class="meta"><?= count($allowed) ?> key(s) suppressed from findings</span></div>
  <div class="fa-tablewrap" style="max-height:240px"><table class="smpro-table"><thead><tr><th>Account</th><th>Type</th><th>Comment / label</th><th>Trusted on</th><th></th></tr></thead><tbody>
    <?php foreach ($allowed as $sig => $k): ?>
      <tr data-sig="<?= smpro_h($sig) ?>">
        <td class="mono"><b><?= smpro_h($k['account'] ?? '') ?></b></td>
        <td class="mono"><?= smpro_h($k['type'] ?? '') ?></td>
        <td class="mono fa-file"><?= smpro_h($k['comment'] ?? '') ?></td>
        <td class="mono"><?= smpro_h(isset($k['added_ts']) ? date('Y-m-d H:i', (int)$k['added_ts']) : '') ?></td>
        <td><button class="fa-lnk faUnallow" data-sig="<?= smpro_h($sig) ?>" type="button">Revoke trust</button></td>
      </tr>
    <?php endforeach; ?>
  </tbody></table></div>
</div>
<?php endif; ?>

<!-- ===== Remediation history & Restore ===== -->
<?php if ($manifest): ?>
<div class="card" id="fa-remed" style="padding:0;overflow:hidden;margin:14px 0">
  <div class="fa-head"><b>&#8635; Remediation History &amp; Restore</b><span class="meta"><?= count($manifest) ?> action(s) · undo from backup</span></div>
  <div class="fa-tablewrap" style="max-height:300px"><table class="smpro-table"><thead><tr><th>When</th><th>Action</th><th>Account</th><th>Target</th><th>Status</th><th></th></tr></thead><tbody>
    <?php foreach ($manifest as $id => $e): $restored = ($e['status'] ?? '')==='restored'; ?>
      <tr data-id="<?= smpro_h($id) ?>">
        <td class="mono"><?= smpro_h(isset($e['applied_ts'])?date('Y-m-d H:i',(int)$e['applied_ts']):'') ?></td>
        <td><span class="b <?= ($e['action']??'')==='malware_quarantine'?'red':'blue' ?>"><?= smpro_h(str_replace('_',' ', $e['action'] ?? '')) ?></span></td>
        <td class="mono"><?= smpro_h($e['account'] ?? '') ?></td>
        <td class="mono fa-file"><?= smpro_h($e['file'] ?? ($e['label'] ?? '')) ?></td>
        <td><?= $restored?'<span class="b gray">restored</span>':'<span class="b green">applied</span>' ?></td>
        <td><?php if(!$restored): ?><button class="fa-lnk faRestore" data-id="<?= smpro_h($id) ?>" type="button">&#8635; Restore</button><?php else: ?><span class="meta" style="font-size:11px">↶ <?= smpro_h(isset($e['restored_ts'])?date('m-d H:i',(int)$e['restored_ts']):'') ?></span><?php endif; ?></td>
      </tr>
    <?php endforeach; ?>
  </tbody></table></div>
  <div style="padding:8px 16px;border-top:1px solid var(--line);color:var(--muted);font-size:11px">File fixes restore the exact backed-up copy. Imunify cleanups restore via <span class="mono">restore-original</span>. Backups kept under <span class="mono">/var/lib/smpro/quarantine/forensics</span>.</div>
</div>
<?php endif; ?>

<!-- ===== Deep file scans (on-demand) ===== -->
<div class="fa-grouplbl">Deep file scans — on-demand, single account, runs in the background (you can keep working)</div>
<div class="fa-scans">
  <?php foreach ($scanTypes as $t => $lbl): ?>
    <button class="fa-scan faScanBtn <?= $scan===$t?'on':'' ?>" type="button" data-scantype="<?= smpro_h($t) ?>"><div class="fa-scanlbl"><?= smpro_h($lbl) ?></div><div class="fa-scanrun">Run &#9654;</div></button>
  <?php endforeach; ?>
</div>

<div id="faScanResult"><?php if ($result !== null) smpro_fa_scan_card($scan, $result, $user, $scanTypes); ?></div>

<!-- ===== context: logins + log preflight ===== -->
<div class="ar-two">
  <div class="card" id="fa-foreign" style="padding:0;overflow:hidden">
    <?php $tlFail = 0; $tlOk = 0; foreach ($timeline as $t) { if (($t['result'] ?? '')==='failed') $tlFail++; else $tlOk++; } ?>
    <div class="fa-head"><b>Recent Foreign Login Attempts</b><span class="meta">outside <?= smpro_h(smpro_im_home_regions_short()) ?> · <?= $tlOk ?> success · <?= $tlFail ?> failed</span></div>
    <div class="fw-pager" data-per="50"><input type="text" class="fw-pgq" placeholder="Filter rows&hellip;"><span class="fw-pginfo"></span><span class="sp"></span><span class="fw-pgctl"><button type="button" class="fw-pgbtn fw-pgprev">&#8249;</button> <span class="mono fw-pgnum"></span> <button type="button" class="fw-pgbtn fw-pgnext">&#8250;</button></span></div>
    <div class="fa-tablewrap" style="max-height:420px"><table class="smpro-table"><thead><tr><th>Time</th><th>Result</th><th>Account / user</th><th>From IP</th><th>Country / Provider</th><th>Service</th></tr></thead><tbody>
      <?php if (!$timeline): ?><tr><td colspan="6" class="fa-empty">No foreign login attempts (outside <?= smpro_h(smpro_im_home_regions_short()) ?>) in the recent window<?= ($tlArab||$tlHidden)?' — '.($tlArab+$tlHidden).' home-region &amp; internal entries hidden':'' ?>.</td></tr>
      <?php else: foreach ($timeline as $t): $fail = ($t['result'] ?? '')==='failed'; ?><tr data-row>
        <td class="mono"><?= smpro_h($t['time']) ?></td>
        <td><span class="b <?= $fail?'red':'green' ?>"><?= $fail?'FAILED':'SUCCESS' ?></span></td>
        <td class="mono"><?= smpro_h($t['user']) ?></td>
        <td class="mono"><?= smpro_h($t['ip']) ?> <a class="fa-lnk" href="index.cgi?page=account-audit&do=search&q=<?= urlencode($t['ip']) ?>&loglines=200000">Audit</a></td>
        <td class="mono"><?php $cc=strtoupper(trim((string)$t['country'])); ?><b><?= smpro_h($cc && $cc!=='N/A'?$cc:'?') ?></b><?php if(!empty($t['bot'])):?> <span class="b orange" title="Datacenter / hosting IP — likely automated">bot</span><?php endif;?><?php if(!empty($t['provider']) && $t['provider']!=='n/a'):?><div class="fa-ref"><?= smpro_h($t['provider']) ?><?= !empty($t['asn'])?' · '.smpro_h($t['asn']):'' ?></div><?php endif;?></td>
        <td><?= smpro_h($t['svc']) ?></td>
      </tr><?php endforeach; endif; ?>
    </tbody></table></div>
    <div style="padding:8px 16px;border-top:1px solid var(--line);color:var(--muted);font-size:11px">Showing login attempts (success &amp; failed) from <b>outside <?= smpro_h(smpro_im_home_regions_short()) ?></b>. A foreign <b>SUCCESS</b> is the highest concern; repeated <b>FAILED</b> = brute-force. Hidden: <?= (int)$tlArab ?> home-region · <?= (int)$tlHidden ?> internal/localhost. Country/provider via Team Cymru (cached).</div>
  </div>
  <div class="card" id="fa-preflight" style="padding:0;overflow:hidden">
    <div class="fa-head"><b>Log Preflight &amp; Related</b></div>
    <table class="smpro-table"><tbody>
      <?php
      // Auth/system/mail logs are named differently across the OS families cPanel supports (RHEL-like:
      // secure / messages / maillog — Ubuntu: auth.log / syslog / mail.log). Show whichever this server
      // actually uses, so an Ubuntu box does not render three "no" rows that read as missing logs while
      // its real ones are never listed at all.
      $lgList = ['/usr/local/cpanel/logs/access_log', '/usr/local/cpanel/logs/login_log'];
      foreach ([['/var/log/secure', '/var/log/auth.log'], ['/var/log/messages', '/var/log/syslog'], ['/var/log/maillog', '/var/log/mail.log']] as $pair) {
          $lgList[] = is_readable($pair[0]) ? $pair[0] : (is_readable($pair[1]) ? $pair[1] : $pair[0]);
      }
      foreach ($lgList as $lg): $ok = is_readable($lg); ?>
        <tr><td class="mono"><?= smpro_h($lg) ?></td><td><?= $ok?'<span class="b green">readable</span>':'<span class="b gray">no</span>' ?></td></tr>
      <?php endforeach; ?>
    </tbody></table>
    <div style="padding:12px 16px;border-top:1px solid var(--line);display:flex;gap:8px;flex-wrap:wrap">
      <a class="tp-btn" href="index.cgi?page=imunify360-reports">Imunify360</a>
      <a class="tp-btn" href="index.cgi?page=account-audit">Account Audit</a>
      <a class="tp-btn" href="index.cgi?page=login-correlation">Login Correlation</a>
    </div>
  </div>
</div>

<!-- ===== Saved Reports ===== -->
<div class="card" id="fa-saved" style="padding:0;overflow:hidden;margin-top:14px">
  <div class="fa-head"><b>Saved Reports</b><span class="meta">kept 90 days</span>
    <button class="tp-btn danger" id="faDelSel" type="button" disabled style="margin-left:auto">Delete selected (<span id="faSelN">0</span>)</button>
  </div>
  <div class="fa-tablewrap" style="max-height:320px"><table class="smpro-table"><thead><tr><th style="width:28px"><input type="checkbox" id="faAll"></th><th>Saved</th><th>Scope</th><th class="num">Findings</th><th class="num">Critical</th><th class="num">High</th><th>Export</th><th></th></tr></thead><tbody id="faSavedBody">
    <?php if (!$saved): ?><tr><td colspan="8" class="fa-empty">No saved reports yet. Use “Save report” above to keep a snapshot.</td></tr>
    <?php else: foreach ($saved as $m): ?>
      <tr data-id="<?= smpro_h($m['id']) ?>">
        <td><input type="checkbox" class="faChk" value="<?= smpro_h($m['id']) ?>"></td>
        <td class="mono"><?= smpro_h(str_replace('_',' ',substr($m['id'],0,15))) ?></td>
        <td class="mono"><?= smpro_h($m['scope']==='all'?'all accounts':$m['scope']) ?></td>
        <td class="num"><?= (int)$m['total'] ?></td>
        <td class="num"><?= (int)$m['critical']?'<span class="b red">'.(int)$m['critical'].'</span>':'0' ?></td>
        <td class="num"><?= (int)$m['high']?'<span class="b orange">'.(int)$m['high'].'</span>':'0' ?></td>
        <td><a class="fa-lnk" href="index.cgi?page=forensics-audit&format=html&saved=<?= urlencode($m['id']) ?>" target="_blank">HTML</a> <a class="fa-lnk" href="index.cgi?page=forensics-audit&format=pdf&saved=<?= urlencode($m['id']) ?>" target="_blank">PDF</a> <a class="fa-lnk" href="index.cgi?page=forensics-audit&format=csv&saved=<?= urlencode($m['id']) ?>">CSV</a></td>
        <td><button class="fa-lnk faDel" data-id="<?= smpro_h($m['id']) ?>" type="button">Delete</button></td>
      </tr>
    <?php endforeach; endif; ?>
  </tbody></table></div>
</div>

<style>
.svc-kicker{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--brand);font-weight:800}
.fa-bar{display:flex;gap:12px;align-items:flex-end;flex-wrap:wrap;margin:14px 0;background:var(--card);border:1px solid var(--line);border-radius:14px;padding:14px 16px}
.fa-fld{display:flex;flex-direction:column;gap:4px;font-size:11px;text-transform:uppercase;color:var(--muted);font-weight:700}
.fa-age{font-size:12px;color:var(--muted);margin-left:auto;align-self:center}
.tp-sel{border:1px solid var(--line);border-radius:9px;padding:8px 11px;font-size:13px}
.tp-btn{border:1px solid var(--line);border-radius:9px;padding:9px 16px;font-size:13px;font-weight:600;cursor:pointer;text-decoration:none;color:var(--ink);background:var(--card)}.tp-btn:hover{background:var(--brand-bg)}
.fa-kpis{display:grid;grid-template-columns:repeat(6,1fr);gap:10px;margin:14px 0}@media(max-width:820px){.fa-kpis{grid-template-columns:repeat(3,1fr)}}
.kpi{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px;text-align:center}
.kpi .kn{font-size:26px;font-weight:800;line-height:1}.kpi .kl{font-size:11px;text-transform:uppercase;color:var(--muted);margin-top:6px;letter-spacing:.03em}
.kpi.crit{border-color:#f3c9c9;background:var(--dang-bg)}.kpi.crit .kn{color:var(--dang)}
.kpi.high{border-color:#f0d8b8;background:var(--warn-bg)}.kpi.high .kn{color:#c2710c}
.kpi.med{border-color:#cdd9fb;background:var(--card)}.kpi.med .kn{color:var(--brand)}
/* ===== modern forensics summary stat cards ===== */
.fa-stats{display:grid;grid-template-columns:repeat(6,1fr);gap:11px;margin:14px 0}
@media(max-width:1000px){.fa-stats{grid-template-columns:repeat(3,1fr)}}
@media(max-width:560px){.fa-stats{grid-template-columns:1fr 1fr}}
.fa-stat{display:flex;gap:11px;align-items:center;background:var(--card);border:1px solid var(--line);border-radius:15px;padding:13px 14px;position:relative;overflow:hidden;transition:transform .14s ease,box-shadow .14s ease}
.fa-stat:hover{transform:translateY(-2px);box-shadow:0 9px 22px rgba(15,23,42,.09)}
.fa-stat::before{content:"";position:absolute;left:0;top:0;bottom:0;width:4px;background:var(--good)}
.fa-stat.info::before{background:var(--brand)}.fa-stat.warn::before{background:#c2710c}.fa-stat.danger::before{background:var(--dang)}
.fa-stat-ic{width:40px;height:40px;flex:none;border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:19px;background:var(--good-bg)}
.fa-stat.info .fa-stat-ic{background:var(--brand-bg)}.fa-stat.warn .fa-stat-ic{background:var(--warn-bg)}.fa-stat.danger .fa-stat-ic{background:var(--dang-bg)}
.fa-stat-b{min-width:0}
.fa-stat-n{font-size:23px;font-weight:800;line-height:1}
.fa-stat.danger .fa-stat-n{color:var(--dang)}.fa-stat.warn .fa-stat-n{color:#b45309}
.fa-stat-l{font-size:12px;font-weight:700;margin-top:3px}
.fa-stat-s{font-size:10.5px;color:var(--muted);margin-top:1px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
/* zebra + hover for forensics data tables */
.smpro-table tbody tr:nth-child(even) td{background:rgba(100,116,139,.035)}
html[data-theme=dark] .smpro-table tbody tr:nth-child(even) td{background:rgba(255,255,255,.02)}
.smpro-table.fa-find tbody tr:hover td{background:var(--brand-bg)}
.fa-affected{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin:-4px 0 10px;font-size:12px}
.fa-afflbl{color:var(--muted);font-weight:700;text-transform:uppercase;font-size:11px}
.fa-chip{display:inline-flex;align-items:center;gap:6px;background:var(--card);border:1px solid var(--line);border-radius:20px;padding:4px 11px;text-decoration:none;color:var(--ink)}
.fa-chip:hover{border-color:var(--brand);background:var(--brand-bg)}.fa-chipn{background:var(--dang-bg);color:var(--dang);border-radius:20px;padding:0 7px;font-weight:700;font-size:11px}
/* Affected-accounts card — contained, searchable, worst-first (replaces the unbounded chip wall) */
.fa-affcard{padding:14px 16px;margin:14px 0}
.fa-affhd{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:12px}
.fa-affhd b{font-size:14px}
.fa-affsearch{max-width:240px;padding:6px 11px;font-size:12.5px;border-radius:9px}
.fa-affhint{font-size:11px;margin-left:auto}
.fa-affgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:8px;max-height:340px;overflow:auto;padding:2px 4px 2px 2px}
.fa-achip{display:flex;align-items:center;gap:9px;text-decoration:none;color:var(--ink);background:var(--card);border:1px solid var(--line);border-radius:10px;padding:8px 11px;transition:.12s;min-width:0}
.fa-achip:hover{border-color:var(--brand);transform:translateY(-1px);box-shadow:0 4px 12px rgba(0,0,0,.08)}
.fa-achip.crit{border-left:3px solid var(--dang)}
.fa-achip-n{flex:none;min-width:22px;height:22px;border-radius:6px;background:var(--dang-bg);color:var(--dang);font-weight:800;font-size:11px;display:flex;align-items:center;justify-content:center}
.fa-achip-name{font-weight:700;font-size:12.5px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.fa-achip-cat{font-size:10.5px;color:var(--muted);margin-left:auto;white-space:nowrap;flex:none}
.fa-affempty{color:var(--muted);font-size:12.5px;padding:14px 4px}
.fa-grouplbl{font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);font-weight:700;margin:14px 0 8px}
.fa-histsel{display:flex;align-items:center;gap:6px;font-size:11px;text-transform:none;font-weight:600;cursor:pointer}
.faHistDelSel[disabled]{opacity:.45;cursor:not-allowed}.faHistDelSel{font-size:11px}
.fa-iline{display:flex;justify-content:space-between;gap:10px;padding:4px 0;border-bottom:1px solid var(--line);font-size:12px}.fa-iline span:last-child{font-weight:700}
.fa-scans{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}@media(max-width:760px){.fa-scans{grid-template-columns:1fr}}
.fa-scan{display:block;background:var(--card);border:1px solid var(--line);border-radius:12px;padding:13px 14px;text-decoration:none;color:var(--ink)}
.fa-scan:hover{border-color:var(--brand);box-shadow:0 6px 18px rgba(59,91,219,.1)}.fa-scan.on{border-color:var(--brand);background:var(--brand-bg)}
.fa-scanlbl{font-weight:700;font-size:13px}.fa-scanrun{font-size:11px;color:var(--brand);margin-top:5px}
button.fa-scan{text-align:left;font:inherit}
.fa-scanprog{height:5px;background:var(--brand-bg);overflow:hidden}.fa-scanprog span{display:block;height:100%;width:35%;background:linear-gradient(90deg,#7c3aed,#4f46e5);animation:faprog 1.2s ease-in-out infinite}
@keyframes faprog{0%{margin-left:-35%}100%{margin-left:100%}}
.fa-head{padding:12px 16px;border-bottom:1px solid var(--line);font-weight:700;font-size:14px;display:flex;align-items:center;gap:10px;flex-wrap:wrap}.fa-head .meta{color:var(--muted);font-size:12px}
.fa-acts{margin-left:auto;display:flex;gap:8px;position:relative}
.fa-dd{position:relative}.fa-menu{display:none;position:absolute;right:0;top:calc(100% + 4px);background:var(--card);border:1px solid var(--line);border-radius:10px;box-shadow:0 10px 30px rgba(0,0,0,.12);z-index:5;min-width:130px;overflow:hidden}
.fa-menu.show{display:block}.fa-menu a{display:block;padding:9px 14px;font-size:13px;color:var(--ink);text-decoration:none}.fa-menu a:hover{background:var(--brand-bg)}
.fa-note{padding:10px 16px;background:var(--warn-bg);color:#8a6516;font-size:12px;border-bottom:1px solid var(--line)}
.fa-tablewrap{overflow:auto}.fa-tablewrap thead th{position:sticky;top:0;background:var(--card);z-index:1;box-shadow:inset 0 -1px 0 var(--line)}
.smpro-table{width:100%;border-collapse:collapse;font-size:12px}
.smpro-table th,.smpro-table td{padding:8px 12px;text-align:left;border-bottom:1px solid var(--line);white-space:nowrap;vertical-align:top}
.smpro-table th{font-size:11px;text-transform:uppercase;color:var(--muted)}.smpro-table td.num,.smpro-table th.num{text-align:right}
.fa-find td{white-space:normal}
.fa-conf{font-size:10px;color:var(--muted);margin-top:4px}
.fa-tt{font-weight:700;font-size:13px;margin-bottom:3px}
.fa-ev{background:var(--card);border:1px solid var(--line);border-radius:6px;padding:5px 8px;word-break:break-all;max-width:520px;color:#333}
.fa-ref{font-size:11px;color:var(--muted);margin-top:3px;word-break:break-all}
.fa-pager{display:flex;justify-content:space-between;align-items:center;gap:10px;padding:6px 2px;font-size:12px}
.fa-det{margin-top:6px;background:none;border:none;color:var(--brand);font-size:11px;font-weight:700;cursor:pointer;padding:0}
.fa-rawbox{margin-top:6px;background:#0f172a;border-radius:8px;padding:8px 10px;max-width:560px;overflow:auto}
.fa-rawbox .fa-rawlbl{color:#94a3b8;font-size:10px;text-transform:uppercase;letter-spacing:.04em;margin-bottom:3px}
.fa-rawbox code{color:#e2e8f0;font-size:11px;word-break:break-all;white-space:pre-wrap;display:block}
.fa-mean{max-width:460px;color:#3a4252;font-size:12px}
.fa-action{margin-top:6px;font-weight:700;color:var(--ink)}
.fa-del{margin-top:8px;margin-left:6px;padding:6px 12px;font-size:12px;background:var(--card);border-color:#f3c9c9;color:var(--dang)}.fa-del:hover{background:var(--dang);color:#fff}.fa-del.ok{background:var(--good);border-color:var(--good);color:#fff;cursor:default}
.fa-fix{margin-top:8px;padding:6px 12px;font-size:12px;background:var(--card);border-color:var(--brand);color:var(--brand)}
.fa-fix:hover{background:var(--brand);color:#fff}.fa-fix.ok{background:var(--good);border-color:var(--good);color:#fff;cursor:default}
.fa-allow{margin-top:8px;margin-left:6px;padding:6px 12px;font-size:12px;background:var(--card);border-color:var(--good);color:var(--good)}
.fa-allow:hover{background:var(--good);color:#fff}.fa-allow.ok{background:var(--good);border-color:var(--good);color:#fff;cursor:default}
.fa-rev{display:inline-block;margin-left:8px;font-size:10px;color:var(--muted)}
.fa-ai{margin-top:8px;margin-left:6px;padding:6px 12px;font-size:12px;background:var(--brand-bg);border-color:#c4a7f0;color:#7c3aed}
.fa-ai:hover{background:#7c3aed;color:#fff;border-color:#7c3aed}
.fa-aimodal{display:none;position:fixed;inset:0;background:rgba(15,23,42,.55);z-index:1000;align-items:center;justify-content:center;padding:20px}
.fa-aibox{background:var(--card);border-radius:14px;max-width:760px;width:100%;max-height:84vh;display:flex;flex-direction:column;box-shadow:0 30px 80px rgba(0,0,0,.35);overflow:hidden}
.fa-aihead{padding:13px 18px;border-bottom:1px solid var(--line);display:flex;align-items:center;gap:10px;font-size:15px}
.fa-aihead .meta{margin-left:auto;font-size:11px}.fa-aihead .fa-lnk{margin-left:8px}
.fa-aibody{padding:16px 20px;overflow:auto;font-size:13px;line-height:1.6;color:#1f2733}
.fa-aibody h3{font-size:14px;margin:14px 0 6px;color:#7c3aed}.fa-aibody h4{font-size:13px;margin:12px 0 5px}
.fa-aibody ul{margin:6px 0 10px;padding-left:20px}.fa-aibody li{margin:3px 0}
.fa-aibody code{background:var(--card);padding:1px 5px;border-radius:5px;font-family:ui-monospace,Consolas,monospace;font-size:12px;word-break:break-all}
.fa-aispin{color:var(--muted);padding:20px;text-align:center}.fa-aierr{color:var(--dang);padding:14px;background:var(--dang-bg);border-radius:8px}
.fa-aisum{background:var(--brand-bg);border:1px solid #e7dbfa;border-radius:10px;padding:12px 14px;font-size:12px;margin-bottom:12px}
.fa-plan{width:100%;border-collapse:collapse;font-size:12px}.fa-plan th,.fa-plan td{padding:7px 9px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
.fa-plan th{font-size:10px;text-transform:uppercase;color:var(--muted)}
.faExecDec{font-weight:700;white-space:nowrap}
.faExecDec.b-red{color:var(--dang);border-color:#f3c9c9}.faExecDec.b-red:hover{background:var(--dang);color:#fff}
.faExecDec.b-orange{color:#c2710c;border-color:#f0d8b8}.faExecDec.b-orange:hover{background:#c2710c;color:#fff}
.faExecDec.b-blue{color:var(--brand);border-color:#cdd9fb}.faExecDec.b-blue:hover{background:var(--brand);color:#fff}
.faExecDec.b-gray{color:#475569;border-color:var(--line)}.faExecDec.b-gray:hover{background:#475569;color:#fff}
.fa-fixed td{opacity:.55}
.fa-bulk{display:flex;align-items:center;gap:10px;flex-wrap:wrap;padding:11px 16px;border-top:1px solid var(--line);background:var(--card);position:sticky;bottom:0}
.fa-bulk .fa-bulkn{font-size:13px}.fa-bulk .tp-btn{padding:7px 13px;font-size:12px}
.fa-bulk #fBulkTrust{border-color:var(--good);color:var(--good)}.fa-bulk #fBulkTrust:hover{background:var(--good);color:#fff}
.fa-bulk #fBulkFix{border-color:var(--brand);color:var(--brand)}.fa-bulk #fBulkFix:hover{background:var(--brand);color:#fff}
.fa-bulkmsg{font-size:12px;color:var(--muted)}
.fa-tl{padding:6px 0}
.fa-tlrow{display:flex;gap:10px;padding:8px 16px;border-bottom:1px solid var(--line)}
.fa-tldot{width:10px;height:10px;border-radius:50%;margin-top:4px;flex:0 0 auto;background:#cbd5e1}
.fa-tldot.red{background:var(--dang)}.fa-tldot.orange{background:#c2710c}.fa-tldot.blue{background:var(--brand)}.fa-tldot.green{background:var(--good)}
.fa-tltop{display:flex;align-items:center;gap:8px}.fa-tltime{font-size:11px;color:var(--muted)}
.fa-tltext{font-size:12px;margin-top:3px;color:#3a4252}
.fa-iocintro{font-size:12px;color:#3a4252;margin:0 0 12px;line-height:1.55}
.fa-iocgrid{display:grid;grid-template-columns:repeat(3,1fr);gap:8px}
.fa-ioc{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px;text-align:left}
.fa-ioc .fa-iocn{display:block;font-size:22px;color:var(--ink);font-weight:800;line-height:1}
.fa-ioc .fa-iocl{display:block;font-size:11px;font-weight:700;color:var(--ink);text-transform:uppercase;margin-top:4px}
.fa-ioc .fa-ioce{display:block;font-size:11px;color:var(--muted);margin-top:3px;line-height:1.35}
.fa-ioctop{margin-top:12px;border:1px solid var(--line);border-radius:10px;overflow:hidden}
.fa-ioctt{background:var(--card);padding:7px 12px;font-size:11px;font-weight:700;text-transform:uppercase;color:var(--muted);border-bottom:1px solid var(--line)}
.fa-iocrow{display:flex;align-items:center;gap:8px;padding:7px 12px;border-bottom:1px solid var(--line);font-size:12px;flex-wrap:wrap}
.fa-iocrow:last-child{border-bottom:none}.fa-iocact{color:var(--brand);font-size:11px;font-weight:600;margin-left:auto}
.fa-sevrow.s-critical{box-shadow:inset 3px 0 0 var(--dang)}.fa-sevrow.s-high{box-shadow:inset 3px 0 0 #c2710c}.fa-sevrow.s-medium{box-shadow:inset 3px 0 0 var(--brand)}
.mono{font-family:ui-monospace,Consolas,monospace}.fa-file{white-space:normal;word-break:break-all;max-width:540px}
.fa-empty{padding:18px;color:var(--muted);text-align:center}
.fa-lnk{color:var(--brand);text-decoration:none;font-size:11px;border:1px solid var(--line);padding:1px 7px;border-radius:6px;background:var(--card);cursor:pointer}
.ar-two{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:14px}@media(max-width:900px){.ar-two{grid-template-columns:1fr}}

/* ===== overview strip / navigator / collapsible cards (same rules as firewall-status.php) ===== */
/* page additions: header-level open state (works for cards AND for header+siblings sections), prose folds, table pager */
.fw-toggle.fw-open .fw-chev{transform:rotate(90deg)}
.fw-collapse.fw-show{display:block}
.gl-fold{margin:6px 0}.gl-fold>summary{cursor:pointer;font-size:13px;font-weight:700;list-style:none;display:flex;align-items:center;gap:8px;color:var(--brand)}
.fw-pager{display:flex;gap:8px;align-items:center;flex-wrap:wrap;padding:8px 16px;border-bottom:1px solid var(--line);font-size:12px;color:var(--muted)}
.fw-pager .fw-pgq{border:1px solid var(--line);border-radius:9px;padding:5px 10px;font-size:12.5px;background:var(--card);color:var(--ink);min-width:180px}
.fw-pager .sp{flex:1}.fw-pgctl{display:inline-flex;align-items:center;gap:6px}
.fw-pgbtn{border:1px solid var(--line);background:var(--card);color:var(--ink);border-radius:7px;padding:2px 9px;font-size:13px;cursor:pointer;line-height:1.4}.fw-pgbtn[disabled]{opacity:.4;cursor:not-allowed}
.b{display:inline-block;font-size:11px;font-weight:700;padding:2px 8px;border-radius:20px}.b.green{background:var(--good-bg);color:var(--good)}.b.gray{background:var(--card);color:#475569}.b.red{background:var(--dang-bg);color:var(--dang)}.b.orange{background:var(--warn-bg);color:#c2710c}.b.blue{background:var(--brand-bg);color:var(--brand)}
.meta{color:var(--muted)}
</style>
<script>
(function(){
  var CSRF_SAVE=<?= json_encode($csrfSave) ?>, CSRF_DEL=<?= json_encode($csrfDel) ?>, CSRF_REM=<?= json_encode($csrfRem) ?>;
  function post(body){return fetch(location.pathname+location.search,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:body});}
  // ---- background (AJAX) deep scans: non-blocking, inline indicator ----
  document.addEventListener('click',function(e){
    var b=e.target.closest&&e.target.closest('.faScanBtn'); if(!b)return;
    var st=b.getAttribute('data-scantype'), lbl=(b.querySelector('.fa-scanlbl')||{}).textContent||'Scan';
    var uEl=document.querySelector('select[name="user"]'), dEl=document.querySelector('select[name="days"]');
    var u=uEl?uEl.value:'all', d=dEl?dEl.value:'7';
    var box=document.getElementById('faScanResult'); if(!box)return;
    document.querySelectorAll('.faScanBtn').forEach(function(x){x.classList.remove('on');}); b.classList.add('on');
    var hint = st==='deep_scan'?'Hashing & inspecting PHP files — up to ~2 minutes.':(st==='htaccess'?'Reading every .htaccess across the scope.':'Reading the account’s files.');
    box.innerHTML='<div class="card" style="padding:0;overflow:hidden;margin:14px 0"><div class="fa-head"><b>'+lbl+'</b><span class="meta">scanning '+(u==="all"?"all accounts":u)+'…</span></div><div class="fa-scanprog"><span></span></div><div class="fa-empty">&#128269; Running in the background — you can keep using the plugin. '+hint+'</div></div>';
    box.scrollIntoView({behavior:'smooth',block:'nearest'});
    fetch('index.cgi?page=forensics-audit&ajax=scan&scan='+encodeURIComponent(st)+'&user='+encodeURIComponent(u)+'&days='+encodeURIComponent(d))
      .then(function(r){return r.text();}).then(function(html){box.innerHTML=html;box.scrollIntoView({behavior:'smooth',block:'nearest'});})
      .catch(function(){box.innerHTML='<div class="card" style="padding:16px;margin:14px 0"><div class="fa-empty" style="color:var(--dang)">Scan request failed — try again.</div></div>';});
  });
  // lazy-load the heavy Imunify history panel after the page is interactive
  (function(){ var box=document.getElementById('faImHist'); if(!box)return;
    fetch('index.cgi?page=forensics-audit&ajax=imhist&user='+encodeURIComponent((document.querySelector('select[name="user"]')||{}).value||'all'))
      .then(function(r){return r.text();}).then(function(html){box.innerHTML=html;if(window.smproFold)window.smproFold(box);if(window.smproPagers)window.smproPagers(box);})
      .catch(function(){box.innerHTML='<div class="fa-empty" style="color:var(--muted)">Could not load Imunify history.</div>';}); })();
  // ---- AI analysis (INLINE, no popup) ----
  function aiMd(t){ var e=document.createElement('div'); e.textContent=t; var h=e.innerHTML;
    h=h.replace(/^### (.*)$/gm,'<h4>$1</h4>').replace(/^## (.*)$/gm,'<h3>$1</h3>').replace(/^# (.*)$/gm,'<h3>$1</h3>');
    h=h.replace(/\*\*([^*]+)\*\*/g,'<b>$1</b>').replace(/`([^`]+)`/g,'<code>$1</code>');
    h=h.replace(/^\s*[-*] (.*)$/gm,'<li>$1</li>').replace(/(<li>[\s\S]*?<\/li>)/g,'<ul>$1</ul>');
    h=h.replace(/^\s*\d+\. (.*)$/gm,'<li>$1</li>');
    return h.replace(/\n{2,}/g,'<br><br>').replace(/\n/g,'<br>'); }
  function esc(s){return String(s==null?'':s).replace(/[<>&]/g,function(c){return{'<':'&lt;','>':'&gt;','&':'&amp;'}[c];});}
  var inl=document.getElementById('faAiInline'), inlBody=document.getElementById('faAiBody2'), inlMeta=document.getElementById('faAiMeta2');
  var inlClose=document.getElementById('faAiClose2'); if(inlClose)inlClose.addEventListener('click',function(){inl.hidden=true;});
  function inlShow(html){ if(!inl)return; inl.hidden=false; inlBody.innerHTML=html; inl.scrollIntoView({behavior:'smooth',block:'nearest'}); }
  var ACT={clean:{l:'&#129529; Clean',c:'red'},delete:{l:'&#128465; Delete file',c:'red'},disable:{l:'&#128721; Disable',c:'orange'},remove:{l:'&#128465; Remove',c:'orange'},trust:{l:'&#10003; Trust',c:'gray'},scan:{l:'&#128269; Scan',c:'blue'},suspend:{l:'&#9940; Suspend',c:'red'},investigate:{l:'',c:'blue'},ignore:{l:'',c:'gray'}};
  function planHtml(j){
    var h='<div class="fa-aisum">'+aiMd(j.summary||'')+'</div>';
    if(!j.decisions||!j.decisions.length)return h+'<div class="meta" style="margin-top:8px">No actionable decisions returned.</div>';
    h+='<table class="fa-plan"><thead><tr><th>Pri</th><th>Finding</th><th>AI decision</th><th>Why</th><th>Action</th></tr></thead><tbody>';
    j.decisions.forEach(function(d){
      var a=ACT[d.decision]||{l:'',c:'gray'};
      var btn=a.l?'<button class="fa-lnk faExecDec b-'+a.c+'" data-idx="'+d.id+'" data-dec="'+esc(d.decision)+'" data-acct="'+esc(d.account)+'">'+a.l+'</button>':'<span class="meta">review</span>';
      h+='<tr><td><b>P'+d.priority+'</b></td><td><b class="mono">'+esc(d.account)+'</b><div>'+esc(d.title)+'</div></td><td><span class="b '+a.c+'">'+esc(d.decision)+'</span></td><td class="meta" style="white-space:normal;max-width:240px">'+esc(d.reason)+'</td><td>'+btn+'</td></tr>';
    });
    return h+'</tbody></table>';
  }
  function ajaxDeepScan(acct){
    var box=document.getElementById('faScanResult'); if(!box)return;
    box.innerHTML='<div class="card" style="padding:0;overflow:hidden;margin:14px 0"><div class="fa-head"><b>Deep Malware + SHA-256</b><span class="meta">scanning '+esc(acct)+'…</span></div><div class="fa-scanprog"><span></span></div><div class="fa-empty">&#128269; Running in the background…</div></div>';
    box.scrollIntoView({behavior:'smooth',block:'nearest'});
    fetch('index.cgi?page=forensics-audit&ajax=scan&scan=deep_scan&user='+encodeURIComponent(acct)).then(function(r){return r.text();}).then(function(html){box.innerHTML=html;box.scrollIntoView({behavior:'smooth',block:'nearest'});}).catch(function(){box.innerHTML='<div class="card" style="padding:16px;margin:14px 0"><div class="fa-empty" style="color:var(--dang)">Scan failed.</div></div>';});
  }
  function runDecide(){
    inlShow('<div class="fa-aispin">&#129302; Thinking — analyzing findings and deciding the safest actions…</div>'); if(inlMeta)inlMeta.textContent='';
    var fd=new URLSearchParams();fd.set('fa_action','ai_decide');fd.set('smpro_csrf',CSRF_REM);
    post(fd.toString()).then(function(r){return r.json();}).then(function(j){
      if(j&&j.ok){if(inlMeta)inlMeta.textContent=(j.provider||'')+' · '+(j.model||'');inlBody.innerHTML=planHtml(j);}
      else inlBody.innerHTML='<div class="fa-aierr">'+((j&&j.error)||'AI request failed')+(j&&j.raw?'<br><small>'+esc(j.raw)+'</small>':'')+'</div>';
    }).catch(function(){inlBody.innerHTML='<div class="fa-aierr">Request failed.</div>';});
  }
  var aiDec=document.getElementById('faAiDecide');
  if(aiDec)aiDec.addEventListener('click',runDecide);
  // when a scan/findings refresh just happened, AI auto-thinks and shows decision buttons inline
  if(inl && /[?&]rescan=/.test(location.search)) setTimeout(runDecide,400);
  // execute a named AI decision (Clean / Disable / Remove / Trust / Scan / Suspend)
  document.addEventListener('click',function(e){
    var b=e.target.closest&&e.target.closest('.faExecDec'); if(!b)return;
    var idx=b.getAttribute('data-idx'), dec=b.getAttribute('data-dec'), acct=b.getAttribute('data-acct')||'';
    if(dec==='scan'){ if(!acct||acct==='all'||acct==='system'||acct==='?'){alert('No single account to scan.');return;} ajaxDeepScan(acct); b.textContent='✓ scanning'; return; }
    var tr=(typeof FIND!=='undefined'&&FIND[idx])?fRowFor(idx):null; if(!tr){alert('Finding not found — re-scan and retry.');return;}
    var fd=new URLSearchParams(); fd.set('smpro_csrf',CSRF_REM); var lbl=b.innerHTML;
    if(dec==='suspend'){ if(!acct||acct==='all'||acct==='system'){alert('No account to suspend.');return;} if(!confirm('SUSPEND account "'+acct+'"?\n\nThis disables the whole site. Reversible — you can unsuspend anytime.'))return; fd.set('fa_action','suspend');fd.set('account',acct); }
    else if(dec==='delete'){ var df=tr.getAttribute('data-file'); if(!df||df.indexOf('/home/')!==0){alert('No deletable /home file for this finding.');return;} if(!confirm('DELETE malware file?\n'+df+'\n\nBacked up outside the account first; report written; restorable.'))return; fd.set('fa_action','delete_malware');fd.set('file',df); }
    else if(dec==='trust'){ fd.set('fa_action','allow_key');fd.set('account',tr.getAttribute('data-account'));fd.set('raw',tr.getAttribute('data-raw')); }
    else if(dec==='clean'||dec==='disable'||dec==='remove'){ var act=tr.getAttribute('data-act'); if(!act){alert('This finding has no executable action.');return;} if(!confirm('Apply "'+dec+'" on '+(acct||'')+'?\nReversible — a backup/restore is kept.'))return; fd.set('fa_action','remediate');fd.set('act',act);fd.set('file',tr.getAttribute('data-file'));fd.set('raw',tr.getAttribute('data-raw'));fd.set('imid',tr.getAttribute('data-imid')||''); }
    else return;
    b.disabled=true;b.textContent='…';
    post(fd.toString()).then(function(r){return r.json();}).then(function(j){
      if(j&&j.ok){b.textContent='✓ done';b.style.color='var(--good)';tr.classList.add('fa-fixed');}
      else{b.disabled=false;b.innerHTML=lbl;alert((j&&j.msg)||(j&&j.error)||'Failed');}
    }).catch(function(){b.disabled=false;b.innerHTML=lbl;alert('Request failed');});
  });
  // per-finding AI verdict — rendered INLINE in the decision panel (no popup)
  document.addEventListener('click',function(e){
    var b=e.target.closest&&e.target.closest('.faAsk'); if(!b)return;
    inlShow('<div class="fa-aispin">&#129302; Analyzing this finding…</div>'); if(inlMeta)inlMeta.textContent='';
    var fd=new URLSearchParams();fd.set('fa_action','ai_analyze');fd.set('smpro_csrf',CSRF_REM);fd.set('mode','finding');
    fd.set('title',b.getAttribute('data-title')||'');fd.set('cat',b.getAttribute('data-cat')||'');fd.set('acct',b.getAttribute('data-acct')||'');fd.set('ev',b.getAttribute('data-ev')||'');fd.set('ref',b.getAttribute('data-ref')||'');
    post(fd.toString()).then(function(r){return r.json();}).then(function(j){
      if(j&&j.ok){if(inlMeta)inlMeta.textContent=(j.provider||'')+' · '+(j.model||'');inlBody.innerHTML='<div class="fa-aisum"><b>'+esc(b.getAttribute('data-title')||'')+'</b></div>'+aiMd(j.text||'(empty)');}
      else inlBody.innerHTML='<div class="fa-aierr">'+((j&&j.error)||'AI request failed')+'</div>';
    }).catch(function(){inlBody.innerHTML='<div class="fa-aierr">Request failed.</div>';});
  });
  // remediation (execute fix on a finding)
  document.addEventListener('click',function(e){
    var b=e.target.closest&&e.target.closest('.faRem'); if(!b)return;
    var tr=b.closest('tr'); if(!tr)return;   // the finding's data lives once, on its row
    var lbl=tr.getAttribute('data-label');
    if(!confirm('Apply: '+lbl+'?\n\nThis action is reversible — a backup is kept before any change.'))return;
    b.disabled=true;var old=b.textContent;b.textContent='Working…';
    var fd=new URLSearchParams();
    fd.set('fa_action','remediate');fd.set('smpro_csrf',CSRF_REM);
    fd.set('act',tr.getAttribute('data-act'));fd.set('file',tr.getAttribute('data-file'));
    fd.set('raw',tr.getAttribute('data-raw'));fd.set('imid',tr.getAttribute('data-imid')||'');
    post(fd.toString()).then(function(r){return r.json();}).then(function(j){
      if(j&&j.ok){tr.classList.add('fa-fixed');if(FIND[tr.getAttribute('data-idx')])FIND[tr.getAttribute('data-idx')].fixed=true;b.textContent='✓ done';b.classList.add('ok');var s=b.nextElementSibling;if(s)s.textContent=j.msg||'done';}
      else{b.disabled=false;b.textContent=old;alert((j&&j.msg)||'Action failed');}
    }).catch(function(){b.disabled=false;b.textContent=old;alert('Request failed');});
  });
  // allow (trust) a key so it stops appearing as a finding
  document.addEventListener('click',function(e){
    var b=e.target.closest&&e.target.closest('.faAllow'); if(!b)return;
    var tr=b.closest('tr'); if(!tr)return;
    if(!confirm('Trust this SSH key?\n\nIt will be suppressed from future findings. You can revoke trust anytime from “Trusted SSH Keys”.'))return;
    b.disabled=true;b.textContent='…';
    var fd=new URLSearchParams();fd.set('fa_action','allow_key');fd.set('smpro_csrf',CSRF_REM);
    fd.set('account',tr.getAttribute('data-account'));fd.set('raw',tr.getAttribute('data-raw'));
    post(fd.toString()).then(function(r){return r.json();}).then(function(j){
      if(j&&j.ok){tr.classList.add('fa-fixed');b.textContent='✓ trusted';b.classList.add('ok');var rem=tr&&tr.querySelector('.faRem');if(rem)rem.style.display='none';}
      else{b.disabled=false;b.textContent='✓ Allow (trust)';alert((j&&j.msg)||'Failed');}
    }).catch(function(){b.disabled=false;b.textContent='✓ Allow (trust)';alert('Request failed');});
  });
  // remove a malware entry from Imunify's list (already-cleaned / reviewed files)
  document.addEventListener('click',function(e){
    var b=e.target.closest&&e.target.closest('.faRemlist'); if(!b)return;
    if(!confirm('Remove this entry from Imunify’s malicious list?\n\nThe FILE is left untouched — use this only for files already cleaned or confirmed safe. It re-appears if a new scan still flags it.'))return;
    b.disabled=true;b.textContent='…';
    var fd=new URLSearchParams();fd.set('fa_action','remediate');fd.set('smpro_csrf',CSRF_REM);
    fd.set('act','malware_removelist');fd.set('imid',b.getAttribute('data-imid')||'');fd.set('file',b.getAttribute('data-file')||'');fd.set('raw','');
    post(fd.toString()).then(function(r){return r.json();}).then(function(j){
      if(j&&j.ok){var tr=b.closest('tr');if(tr)tr.classList.add('fa-fixed');b.textContent='✓ removed';b.classList.add('ok');}
      else{b.disabled=false;b.textContent='✕ Remove from list';alert((j&&j.msg)||'Failed');}
    }).catch(function(){b.disabled=false;b.textContent='✕ Remove from list';alert('Request failed');});
  });
  // DELETE a malware file (backup outside the account first, then remove) + report
  document.addEventListener('click',function(e){
    var b=e.target.closest&&e.target.closest('.faDelMal'); if(!b)return;
    if(!confirm('DELETE this malware file?\n'+(b.getAttribute('data-file')||'')+'\n\nIt is backed up OUTSIDE the account (/home/backup/detections) first, and an action report is written. Restorable from Remediation History.'))return;
    b.disabled=true;b.textContent='…';
    var fd=new URLSearchParams();fd.set('fa_action','delete_malware');fd.set('smpro_csrf',CSRF_REM);fd.set('file',b.getAttribute('data-file')||'');
    post(fd.toString()).then(function(r){return r.json();}).then(function(j){
      if(j&&j.ok){var tr=b.closest('tr');if(tr)tr.classList.add('fa-fixed');b.textContent='✓ deleted';b.classList.add('ok');alert(j.msg||'Deleted.');}
      else{b.disabled=false;b.innerHTML='&#128465; Delete file';alert((j&&j.msg)||'Failed');}
    }).catch(function(){b.disabled=false;b.innerHTML='&#128465; Delete file';alert('Request failed');});
  });
  // ---- multi-select on Recent detections (Imunify history, AJAX-injected) ----
  function faHistChecked(){return Array.prototype.slice.call(document.querySelectorAll('.faHistChk')).filter(function(c){return c.checked;});}
  function faHistRefresh(){var n=faHistChecked().length;document.querySelectorAll('.faHistN').forEach(function(b){b.textContent=n;});document.querySelectorAll('.faHistDelSel').forEach(function(b){b.disabled=n===0;});}
  document.addEventListener('change',function(e){
    if(e.target.classList&&e.target.classList.contains('faHistChk'))faHistRefresh();
    if(e.target.classList&&e.target.classList.contains('faHistAll')){var on=e.target.checked;document.querySelectorAll('.faHistChk').forEach(function(c){c.checked=on;});faHistRefresh();}
  });
  document.addEventListener('click',function(e){
    var b=e.target.closest&&e.target.closest('.faHistDelSel'); if(!b)return;
    var sel=faHistChecked(); if(!sel.length)return;
    var files=sel.map(function(c){return c.getAttribute('data-file');});
    if(!confirm('DELETE '+files.length+' selected malware file(s)?\n\n'+files.slice(0,8).join('\n')+(files.length>8?'\n…(+'+(files.length-8)+' more)':'')+'\n\nEach is backed up OUTSIDE the account first; a report is written; restorable.'))return;
    b.disabled=true;b.textContent='Deleting…';var done=0,ok=0;
    seq(files,function(f){var fd=new URLSearchParams();fd.set('fa_action','delete_malware');fd.set('smpro_csrf',CSRF_REM);fd.set('file',f);return fd.toString();},
      function(f,j){done++;if(j&&j.ok){ok++;sel.forEach(function(c){if(c.getAttribute('data-file')===f){var tr=c.closest('tr');if(tr)tr.classList.add('fa-fixed');c.checked=false;c.disabled=true;}});}b.textContent='Deleting '+done+'/'+files.length+'…';})
      .then(function(){b.innerHTML='&#128465; Delete selected (<b class="faHistN">0</b>)';alert('Deleted '+ok+'/'+files.length+' file(s). Backups in /home/backup/detections.');faHistRefresh();});
  });
  // ---- findings: built in the browser 60 at a time from FIND; the selection (fSel) and the fix state live in JS,
  //      so bulk actions and AI decisions still cover every finding, rendered or not ----
  function fEsc(s){ return String(s==null?'':s).replace(/[&<>"']/g,function(ch){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch];}); }
  var fSel = {}, fDetached = {};
  function fBuildRow(idx){
    var f=FIND[idx]; var c=SEVCLS[f.sev]||'gray';
    var tr=document.createElement('tr'); tr.className='fa-sevrow s-'+f.sev+(f.fixed?' fa-fixed':'');
    tr.setAttribute('data-idx',String(idx)); tr.setAttribute('data-act',f.act); tr.setAttribute('data-file',f.ref); tr.setAttribute('data-raw',f.raw);
    tr.setAttribute('data-imid',f.imid); tr.setAttribute('data-account',f.account); tr.setAttribute('data-label',f.actlabel);
    var h='<td>'+(f.act?'<input type="checkbox" class="fChk"'+(fSel[idx]?' checked':'')+'>':'')+'</td>';
    h+='<td><span class="b '+c+'">'+fEsc(String(f.sev).toUpperCase())+'</span><div class="fa-conf">conf: '+fEsc(f.conf)+'</div></td>';
    h+='<td>'+fEsc(f.cat)+'</td>';
    h+='<td class="mono"><b>'+fEsc(f.account)+'</b>'+((f.account!=='all'&&f.account!=='system'&&f.account!=='?')?'<div><a class="fa-lnk" href="index.cgi?page=forensics-audit&user='+encodeURIComponent(f.account)+'">focus</a></div>':'')+'</td>';
    h+='<td class="fa-file"><div class="fa-tt">'+fEsc(f.title)+'</div><div class="fa-ev mono">'+fEsc(f.evidence)+'</div><div class="fa-ref mono">'+fEsc(f.ref)+'</div>';
    var hm=(f.ref&&f.ref.indexOf('/home/')===0)?f.ref.match(/^\/home\/([^\/]+)\//):null;
    if(hm&&FX_OK) h+='<a class="fa-lnk" style="display:inline-block;margin-top:4px;border:1px solid var(--brand);color:var(--brand);padding:2px 9px;border-radius:6px" href="index.cgi?page=forensics-audit&fx_user='+encodeURIComponent(hm[1])+'&fx_file='+encodeURIComponent(f.ref)+(f.ts?'&fx_ts='+f.ts:'')+'">&#128269; Deep-analyze (real vs false positive)</a>';
    if(f.raw) h+='<button class="fa-det" type="button">Details &#9662;</button><div class="fa-rawbox" hidden><div class="fa-rawlbl">'+(f.act==='sshkey_remove'?'Full public key':'Full line')+'</div><code class="mono">'+fEsc(f.rawtxt)+'</code></div>';
    h+='</td>';
    h+='<td class="fa-mean">'+fEsc(f.means)+(f.stale?' <span class="b gray" style="font-size:11px">stale entry · file gone</span>':'')+'<div class="fa-action">&#9656; '+fEsc(f.action)+'</div>';
    if(f.act){
      if(!(f.act==='malware_quarantine'&&f.stale)) h+='<button class="tp-btn fa-fix faRem" type="button">'+fEsc(f.actlabel)+'</button>';
      if(f.act==='sshkey_remove') h+='<button class="tp-btn fa-allow faAllow" type="button">&#10003; Allow (trust)</button>';
      if(f.act==='malware_quarantine') h+='<button class="tp-btn '+(f.stale?'primary':'fa-allow')+' faRemlist" type="button" data-imid="'+fEsc(f.imid)+'" data-file="'+fEsc(f.ref)+'" title="'+(f.stale?'The file is already gone — clear this leftover entry from Imunify’s list.':'Already cleaned but still flagged? Clear it from Imunify\'s list without touching the file.')+'">'+(f.stale?'&#129529; Clear stale entry':'&#10005; Remove from list')+'</button>'
        +'<button class="tp-btn fa-del faDelMal" type="button" data-file="'+fEsc(f.ref)+'" title="Delete the malicious file. Backed up first OUTSIDE the account (/home/backup/detections) — restorable.">&#128465; Delete file</button>';
      h+='<span class="fa-rev">'+(f.stale?'list-only · nothing on disk':'reversible · backup kept')+'</span>';
    }
    if(AI_READY) h+='<button class="tp-btn fa-ai faAsk" type="button" data-title="'+fEsc(f.title)+'" data-cat="'+fEsc(f.cat)+'" data-acct="'+fEsc(f.account)+'" data-ev="'+fEsc(f.evidence)+'" data-ref="'+fEsc(f.ref)+'">&#129302; Ask AI</button>';
    h+='</td>';
    tr.innerHTML=h; return tr;
  }
  // the row for a finding: the rendered one when it is on the current page, otherwise a detached one carrying the same data
  function fRowFor(idx){ var r=document.querySelector('.fa-find tbody tr[data-idx="'+idx+'"]'); if(r) return r; if(!fDetached[idx]) fDetached[idx]=fBuildRow(idx); return fDetached[idx]; }
  var fPage=0, fPER=60, fPages=Math.max(1,Math.ceil(FIND.length/fPER));
  function fShow(){
    var tb=document.querySelector('.fa-find tbody'); if(!tb) return;
    var frag=document.createDocumentFragment(); for(var k=fPage*fPER;k<Math.min((fPage+1)*fPER,FIND.length);k++) frag.appendChild(fBuildRow(k));
    tb.innerHTML=''; tb.appendChild(frag);
    var a=FIND.length?fPage*fPER+1:0,b=Math.min((fPage+1)*fPER,FIND.length); var i=document.getElementById('faFindInfo'); if(i)i.textContent='Showing '+a+' to '+b+' of '+FIND.length+' findings';
    var n=document.getElementById('faFindNum'); if(n)n.textContent=(fPage+1)+' / '+fPages;
    var pg=document.getElementById('faFindPager'); if(pg) pg.style.display=(fPages<=1)?'none':'';
  }
  (function(){ var pv=document.getElementById('faFindPrev'),nx=document.getElementById('faFindNext');
    if(pv)pv.addEventListener('click',function(){if(fPage>0){fPage--;fShow();}}); if(nx)nx.addEventListener('click',function(){if(fPage<fPages-1){fPage++;fShow();}});
    if(typeof FIND!=='undefined') fShow(); })();
  // ---- multi-select bulk actions on findings ----
  function fRows(){var out=[];for(var i=0;i<FIND.length;i++)out.push(fRowFor(i));return out;}
  function fChecked(){var out=[];for(var i=0;i<FIND.length;i++)if(fSel[i])out.push(fRowFor(i));return out;}
  function fSyncBoxes(){document.querySelectorAll('.fa-find tbody tr').forEach(function(tr){var c=tr.querySelector('.fChk');if(c)c.checked=!!fSel[tr.getAttribute('data-idx')];});}
  function fRefresh(){var n=fChecked().length;var bn=document.getElementById('fBulkN');if(bn)bn.textContent=n;var bar=document.getElementById('faBulk');if(bar){if(n>0)bar.removeAttribute('hidden');else bar.setAttribute('hidden','');}}
  var fAll=document.getElementById('fAll');
  if(fAll)fAll.addEventListener('change',function(){fSel={};if(fAll.checked)for(var i=0;i<FIND.length;i++)if(FIND[i].act)fSel[i]=true;fSyncBoxes();fRefresh();});
  document.addEventListener('change',function(e){if(e.target.classList&&e.target.classList.contains('fChk')){var tr=e.target.closest('tr');if(tr){if(e.target.checked)fSel[tr.getAttribute('data-idx')]=true;else delete fSel[tr.getAttribute('data-idx')];}fRefresh();}});
  var bClr=document.getElementById('fBulkClear');if(bClr)bClr.addEventListener('click',function(){if(fAll)fAll.checked=false;fSel={};fSyncBoxes();fRefresh();});
  // sequential processor (each item goes through its own CSRF+root+guard endpoint)
  function seq(items,build,onItem){var i=0;function next(){if(i>=items.length){return Promise.resolve();}var it=items[i++];return post(build(it)).then(function(r){return r.json();}).then(function(j){if(onItem)onItem(it,j);return next();},function(){return next();});}return next();}
  var bFix=document.getElementById('fBulkFix');
  if(bFix)bFix.addEventListener('click',function(){
    var rows=fChecked().filter(function(tr){return tr.getAttribute('data-act');});
    if(!rows.length){alert('No fixable items selected.');return;}
    var counts={};rows.forEach(function(tr){var a=tr.getAttribute('data-act');counts[a]=(counts[a]||0)+1;});
    var desc=Object.keys(counts).map(function(k){return counts[k]+'× '+k.replace('_',' ')}).join(', ');
    if(!confirm('Apply fix to '+rows.length+' finding(s)?\n\n'+desc+'\n\nAll actions are reversible — a backup is kept before each change.'))return;
    bFix.disabled=true;var msg=document.getElementById('fBulkMsg');var done=0,ok=0;
    seq(rows,function(tr){var fd=new URLSearchParams();fd.set('fa_action','remediate');fd.set('smpro_csrf',CSRF_REM);fd.set('act',tr.getAttribute('data-act'));fd.set('file',tr.getAttribute('data-file'));fd.set('raw',tr.getAttribute('data-raw'));fd.set('imid',tr.getAttribute('data-imid')||'');return fd.toString();},
      function(tr,j){done++;if(j&&j.ok){ok++;tr.classList.add('fa-fixed');}if(msg)msg.textContent=done+'/'+rows.length+' done ('+ok+' ok)';})
      .then(function(){if(msg)msg.textContent='Done — '+ok+'/'+rows.length+' applied. Reloading…';setTimeout(function(){location.reload();},900);});
  });
  var bTrust=document.getElementById('fBulkTrust');
  if(bTrust)bTrust.addEventListener('click',function(){
    var rows=fChecked().filter(function(tr){return tr.getAttribute('data-act')==='sshkey_remove';});
    if(!rows.length){alert('No SSH-key findings selected to trust.');return;}
    if(!confirm('Trust '+rows.length+' SSH key(s)?\n\nThey will be suppressed from future findings. Revoke anytime from “Trusted SSH Keys”.'))return;
    bTrust.disabled=true;var msg=document.getElementById('fBulkMsg');var done=0,ok=0;
    seq(rows,function(tr){var fd=new URLSearchParams();fd.set('fa_action','allow_key');fd.set('smpro_csrf',CSRF_REM);fd.set('account',tr.getAttribute('data-account'));fd.set('raw',tr.getAttribute('data-raw'));return fd.toString();},
      function(tr,j){done++;if(j&&j.ok){ok++;tr.classList.add('fa-fixed');}if(msg)msg.textContent=done+'/'+rows.length+' done';})
      .then(function(){if(msg)msg.textContent='Trusted '+ok+'/'+rows.length+'. Reloading…';setTimeout(function(){location.reload();},900);});
  });
  // details toggle (reveal full key / line)
  document.addEventListener('click',function(e){
    var b=e.target.closest&&e.target.closest('.fa-det'); if(!b)return;
    var box=b.nextElementSibling; if(!box)return;
    var open=box.hasAttribute('hidden'); if(open){box.removeAttribute('hidden');b.innerHTML='Details &#9652;';}else{box.setAttribute('hidden','');b.innerHTML='Details &#9662;';}
  });
  // restore a remediation from backup
  document.addEventListener('click',function(e){
    var b=e.target.closest&&e.target.closest('.faRestore'); if(!b)return;
    if(!confirm('Restore this item from its backup?\n\nThis undoes the fix and puts the original content back.'))return;
    b.disabled=true;b.textContent='…';
    var fd=new URLSearchParams();fd.set('fa_action','restore');fd.set('smpro_csrf',CSRF_REM);fd.set('id',b.getAttribute('data-id'));
    post(fd.toString()).then(function(r){return r.json();}).then(function(j){
      if(j&&j.ok){var tr=b.closest('tr');if(tr){var st=tr.querySelector('td:nth-child(5)');if(st)st.innerHTML='<span class="b gray">restored</span>';}b.outerHTML='<span class="meta" style="font-size:11px">↶ done</span>';}
      else{b.disabled=false;b.innerHTML='&#8635; Restore';alert((j&&j.msg)||'Restore failed');}
    }).catch(function(){b.disabled=false;b.innerHTML='&#8635; Restore';alert('Request failed');});
  });
  // revoke trust
  document.addEventListener('click',function(e){
    var b=e.target.closest&&e.target.closest('.faUnallow'); if(!b)return;
    if(!confirm('Revoke trust? This key will be flagged again on the next scan.'))return;
    var fd=new URLSearchParams();fd.set('fa_action','unallow_key');fd.set('smpro_csrf',CSRF_REM);fd.set('sig',b.getAttribute('data-sig'));
    post(fd.toString()).then(function(r){return r.json();}).then(function(j){if(j&&j.ok){var tr=b.closest('tr');if(tr)tr.remove();}else alert('Failed');});
  });
  // export dropdown
  var exp=document.getElementById('faExp'),menu=document.getElementById('faExpMenu');
  if(exp){exp.addEventListener('click',function(e){e.stopPropagation();menu.classList.toggle('show');});document.addEventListener('click',function(){menu.classList.remove('show');});}
  // save snapshot
  var sv=document.getElementById('faSave');
  if(sv)sv.addEventListener('click',function(){sv.disabled=true;sv.textContent='Saving…';
    var fd=new URLSearchParams();fd.set('fa_action','save_report');fd.set('smpro_csrf',CSRF_SAVE);
    post(fd.toString()).then(function(r){return r.json();}).then(function(j){if(j&&j.ok){location.reload();}else{sv.disabled=false;sv.textContent='Save report';alert('Save failed');}}).catch(function(){sv.disabled=false;sv.textContent='Save report';});});
  // saved reports multi-select delete
  function chks(){return Array.prototype.slice.call(document.querySelectorAll('.faChk'));}
  function refresh(){var s=chks().filter(function(c){return c.checked;});document.getElementById('faSelN').textContent=s.length;document.getElementById('faDelSel').disabled=s.length===0;}
  var all=document.getElementById('faAll');if(all)all.addEventListener('change',function(){chks().forEach(function(c){c.checked=all.checked;});refresh();});
  document.addEventListener('change',function(e){if(e.target.classList&&e.target.classList.contains('faChk'))refresh();});
  function del(ids){var fd=new URLSearchParams();fd.set('fa_action','delete_report');fd.set('report_ids',ids.join(','));fd.set('smpro_csrf',CSRF_DEL);
    return post(fd.toString()).then(function(r){return r.json();}).then(function(j){if(j&&j.ok){j.deleted.forEach(function(id){var tr=document.querySelector('tr[data-id="'+id+'"]');if(tr)tr.remove();});refresh();}});}
  document.addEventListener('click',function(e){
    if(e.target.classList&&e.target.classList.contains('faDel')){e.preventDefault();if(confirm('Delete this report?'))del([e.target.getAttribute('data-id')]);}
    if(e.target.id==='faDelSel'){var s=chks().filter(function(c){return c.checked;}).map(function(c){return c.value;});if(s.length&&confirm('Delete '+s.length+' report(s)?'))del(s);}
  });
})();
</script>
<script>
(function(){
  // make every section card collapsible - click its title (or chevron) to open/close; remembered per section
  var KEY='smpro:forensics-audit:open', HDR='.smpro-main .card > .fa-head';
  var open={};
  try{ open=JSON.parse(localStorage.getItem(KEY)||'{}')||{}; }catch(err){ open={}; }
  function remember(){ try{ localStorage.setItem(KEY, JSON.stringify(open)); }catch(err){} }
  function matches(el,sel){ if(!el||el.nodeType!==1) return false; var m=el.matches||el.msMatchesSelector||el.webkitMatchesSelector; return m?m.call(el,sel):false; }
  var folds={};
  function setOpen(f,on){ f.th.classList.toggle('fw-open',on); f.body.classList.toggle('fw-show',on); if(f.card) f.card.classList.toggle('fw-open',on); f.th.setAttribute('aria-expanded',on?'true':'false'); open[f.id]=on; }
  function fold(th){
    if(th.getAttribute('data-fold')) return;
    var host=th.parentElement; if(!host||host.classList.contains('fw-collapse')) return;   // a sub-header inside an already folded section
    var isCard=host.classList.contains('card') && (th.classList.contains('tp-th') || th.classList.contains('fa-head'));   // card header -> fold the whole card; anything else folds its following siblings
    var nodes=[], n=th.nextSibling;
    while(n){
      var nx=n.nextSibling;
      if(n.nodeType===1){
        var tg=n.tagName;
        if(!isCard && (matches(n,HDR) || n.classList.contains('foot'))) break;       // next section / page footer
        if(tg==='SCRIPT'||tg==='STYLE'||tg==='LINK'||tg==='DATALIST'||tg==='TEMPLATE'){ n=nx; continue; }
      }
      nodes.push(n); n=nx;
    }
    var body=document.createElement('div'); body.className='fw-collapse';
    host.insertBefore(body, th.nextSibling);
    for(var i=0;i<nodes.length;i++) body.appendChild(nodes[i]);
    // a stable name for this section: its element id when it has one, else its own heading text (read before the chevron is added)
    var id=(isCard?host.id:'')||th.id||(th.textContent||'').replace(/\s+/g,' ').trim().slice(0,60)||('card'+Math.random());
    th.classList.add('fw-toggle');
    if(!th.querySelector('.fw-chev')) th.insertAdjacentHTML('afterbegin','<span class="fw-chev">&#9656;</span> ');
    th.setAttribute('data-fold', id);
    var f={id:id, th:th, body:body, card:isCard?host:null}; folds[id]=f;
    var isOpen = Object.prototype.hasOwnProperty.call(open,id) ? !!open[id] : !th.hasAttribute('data-closed');
    setOpen(f,isOpen);
    th.setAttribute('role','button'); th.setAttribute('tabindex','0'); th.style.cursor='pointer';
    th.addEventListener('click',function(e){
      if(e.target.closest('a,button,input,select,label,textarea,summary,details,.fw-chk')) return;   // header controls keep working
      setOpen(f,!body.classList.contains('fw-show')); remember();
    });
    th.addEventListener('keydown',function(e){
      if(e.target!==th) return;
      if(e.key===' '||e.key==='Enter'||e.key==='Spacebar'){ e.preventDefault(); setOpen(f,!body.classList.contains('fw-show')); remember(); }
    });
  }
  function foldAll(root){ Array.prototype.forEach.call((root||document).querySelectorAll(HDR), fold); }
  function openCard(id, scroll){
    var el=document.getElementById(id); if(!el) return;
    var f=folds[id]; if(f && !f.body.classList.contains('fw-show')){ setOpen(f,true); remember(); }
    if(scroll){ el.style.scrollMarginTop='120px'; el.scrollIntoView({behavior:'smooth',block:'start'}); }
  }
  function all(on){ for(var k in folds){ if(Object.prototype.hasOwnProperty.call(folds,k)) setOpen(folds[k],on); } remember(); }
  function init(){
    foldAll(document);
    Array.prototype.forEach.call(document.querySelectorAll('[data-go]'),function(a){ a.addEventListener('click',function(e){ e.preventDefault(); var id=a.getAttribute('data-go'); openCard(id,true); Array.prototype.forEach.call(document.querySelectorAll('.fw-nav a'),function(x){ x.classList.toggle('on', x.getAttribute('data-go')===id); }); try{ history.replaceState(null,'','#'+id); }catch(err){} }); });
    var oa=document.getElementById('fwOpenAll'), ca=document.getElementById('fwCloseAll');
    if(oa) oa.addEventListener('click',function(){ all(true); });
    if(ca) ca.addEventListener('click',function(){ all(false); });
    if(location.hash && document.getElementById(location.hash.slice(1))) setTimeout(function(){ openCard(location.hash.slice(1), true); }, 150);
  }
  window.smproFold=foldAll;        // re-fold a container whose HTML was replaced by AJAX
  window.smproOpenCard=openCard;
  if(document.readyState==='loading') document.addEventListener('DOMContentLoaded',init); else init();
})();
(function(){
  // table pager: a <div class="fw-pager"> placed right before a table (or its wrapper) filters + pages the <tr data-row> rows of that table.
  // data-per = rows per page (0 = filter only); data-input = id of an existing filter input to read instead of its own box.
  function setup(bar){
    if(bar.getAttribute('data-init')) return; bar.setAttribute('data-init','1');
    var nx=bar.nextElementSibling; while(nx && nx.tagName!=='TABLE' && !nx.querySelector('table')) nx=nx.nextElementSibling;
    var tbl=nx ? (nx.tagName==='TABLE'?nx:nx.querySelector('table')) : null; if(!tbl) return;
    var per=parseInt(bar.getAttribute('data-per')||'50',10); if(isNaN(per)||per<0) per=50;
    var ext=bar.getAttribute('data-input'), inp=ext?document.getElementById(ext):bar.querySelector('.fw-pgq');
    if(ext){ var own=bar.querySelector('.fw-pgq'); if(own) own.style.display='none'; }
    var info=bar.querySelector('.fw-pginfo'), ctl=bar.querySelector('.fw-pgctl'), num=bar.querySelector('.fw-pgnum'), prev=bar.querySelector('.fw-pgprev'), next=bar.querySelector('.fw-pgnext');
    var page=0, q='';
    function show(r,on){ r.style.display=on?'':'none'; var d=r.nextElementSibling; if(!on && d && d.tagName==='TR' && !d.hasAttribute('data-row')) d.style.display='none'; }
    function draw(){
      var tb=tbl.tBodies[0]; if(!tb) return;
      var rows=Array.prototype.slice.call(tb.querySelectorAll('tr[data-row]')), vis=[], i;
      for(i=0;i<rows.length;i++){ var r=rows[i]; var s=((r.getAttribute('data-search')||'')+' '+(r.textContent||'')).toLowerCase(); if(!q || s.indexOf(q)>=0) vis.push(r); else show(r,false); }
      var pages=per>0?Math.max(1,Math.ceil(vis.length/per)):1; if(page>pages-1) page=pages-1; if(page<0) page=0;
      for(i=0;i<vis.length;i++) show(vis[i], per<=0 || (i>=page*per && i<(page+1)*per));
      if(info) info.textContent = q ? (vis.length+' of '+rows.length+' match') : (rows.length+' row'+(rows.length===1?'':'s'));
      if(ctl) ctl.style.display = pages>1 ? '' : 'none';
      if(num) num.textContent=(page+1)+' / '+pages;
      if(prev) prev.disabled=page<=0; if(next) next.disabled=page>=pages-1;
    }
    if(inp) inp.addEventListener('input',function(){ q=(inp.value||'').trim().toLowerCase(); page=0; draw(); });
    if(prev) prev.addEventListener('click',function(){ if(page>0){ page--; draw(); } });
    if(next) next.addEventListener('click',function(){ page++; draw(); });
    tbl.addEventListener('click',function(e){ if(e.target.closest('thead th')) setTimeout(draw,0); });   // re-page after the global column sort reorders rows
    draw();
  }
  function all(root){ Array.prototype.forEach.call((root||document).querySelectorAll('.fw-pager'), setup); }
  window.smproPagers=all;
  if(document.readyState==='loading') document.addEventListener('DOMContentLoaded',function(){ all(document); }); else all(document);
})();
</script>

<?php
smpro_layout_footer();
