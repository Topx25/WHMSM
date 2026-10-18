<?php
/**
 * includes/disk_tmp.php — "Double /tmp capacity" (smpro_ds_tmp_*). tmpfs = instant remount; cPanel loopback
 * /usr/tmpDSK = pre-staged 2x rebuild in a detached worker with a rollback ladder that GUARANTEES /tmp stays
 * mounted; a plain /tmp dir is refused. Uses the shared smpro_mnt_* helpers (require maintenance.php first).
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }
if (!defined('SMPRO_DS_TMP_MAX'))     define('SMPRO_DS_TMP_MAX', 34359738368);   // 32 GiB hard cap on the doubled loop /tmp
if (!defined('SMPRO_DS_TMP_RAMFRAC')) define('SMPRO_DS_TMP_RAMFRAC', 0.5);       // tmpfs /tmp may not double past this fraction of RAM

/* ==================== A2-tmp — "Double /tmp capacity" =========================================
 * All functions namespaced smpro_ds_tmp_*. This block lives in a NEW includes file (includes/disk_tmp.php)
 * that is require_once'd by BOTH modules/disk-storage.php AND bin/tmp_expand.php (the detached worker),
 * so it MUST stay free of render side effects. Shared helpers assumed present in scope:
 * smpro_mnt_wrap/_locks_dir/_mem/_jwrite/_jread, smpro_audit, smpro_current_actor.
 * Every shell call is timeout+nice+ionice bounded (smpro_mnt_wrap) and escapeshellarg'd.
 * ============================================================================================ */

/** Human-readable bytes (self-contained; unique name so it never collides with smpro_ds_humb). */
function smpro_ds_tmp_humb($b) {
    $b = (int)$b;
    if ($b >= 1073741824) return round($b / 1073741824, 2) . ' GB';
    if ($b >= 1048576)    return round($b / 1048576, 1) . ' MB';
    if ($b >= 1024)       return round($b / 1024, 1) . ' KB';
    return $b . ' B';
}

/** command -v probe. Name is sanitized to a fixed char-class then escapeshellarg'd (defence in depth). */
function smpro_ds_tmp_has_bin(string $bin): bool {
    $bin = preg_replace('/[^a-zA-Z0-9._-]/', '', $bin);          // strip anything that isn't a plain binary name
    if ($bin === '') return false;
    return trim((string)@shell_exec('command -v ' . escapeshellarg($bin) . ' 2>/dev/null')) !== '';
}

/** Size-scaled timeout for create/mkfs/cp of a multi-GB image: pessimistic 8 MiB/s, floor 300s, cap 2h. */
function smpro_ds_tmp_scaled_timeout(int $bytes): int {
    $t = (int)ceil($bytes / (8 * 1048576));
    return max(300, min(7200, $t));
}

/* ---------------- state directory + manifest + job status (atomic 0600 via shared helpers) ------ */
function smpro_ds_tmp_dir(): string {
    $d = SMPRO_VARLIB . '/backups/tmp_expand';
    @is_dir($d) || @mkdir($d, 0700, true);
    return $d;
}
function smpro_ds_tmp_manifest_path(): string { return smpro_ds_tmp_dir() . '/state.json'; }
/** Crash-recovery manifest: phase cursor + sizes + options + EXACT MP + loop device + /var/tmp opts. */
function smpro_ds_tmp_save(array $m): void { smpro_mnt_jwrite(smpro_ds_tmp_manifest_path(), $m); }
function smpro_ds_tmp_load(): ?array { $m = smpro_mnt_jread(smpro_ds_tmp_manifest_path()); return is_array($m) ? $m : null; }
/** Modal-poller status file (pct/phase/heartbeat/result) — separate from the recovery manifest. */
function smpro_ds_tmp_job_path(): string { return smpro_ds_tmp_dir() . '/job.json'; }
function smpro_ds_tmp_job_write(array $st): void { $st['updated_at'] = time(); smpro_mnt_jwrite(smpro_ds_tmp_job_path(), $st); }
function smpro_ds_tmp_job_read(): array { $j = smpro_mnt_jread(smpro_ds_tmp_job_path()); return is_array($j) ? $j : ['phase'=>'idle','pct'=>0,'done'=>false,'updated_at'=>0]; }
/** Fixed staging mountpoint recorded in the manifest (never a $$/PID path a fresh watchdog can't find). */
function smpro_ds_tmp_mp(): string { return smpro_ds_tmp_dir() . '/mnt'; }

/* ---------------- DETECT — single source of truth (read-only; fixed literal paths) -------------- */
function smpro_ds_tmp_detect(): array {
    $d = [
        'backing'=>'unknown','dev'=>'','fstype'=>'','file'=>'/usr/tmpDSK',
        'size_bytes'=>0,'used_bytes'=>0,'options'=>[],'options_raw'=>'',
        'var_tmp_is_bind'=>false,'var_tmp_options'=>'',
        'backfs_mount'=>'','backfs_avail_bytes'=>0,'backfs_avail_inodes'=>0,
        'container'=>false,'loop_ok'=>false,'loop_dev'=>'',
        'selinux'=>false,'cagefs'=>false,'securetmp_running'=>false,
    ];
    // /tmp mount row: TARGET SOURCE FSTYPE OPTIONS SIZE (-b => SIZE in bytes). One line, whitespace-separated;
    // OPTIONS itself contains only commas (no spaces), so preg_split on whitespace yields exactly 5 columns.
    $line = trim((string)@shell_exec('findmnt -nb -o TARGET,SOURCE,FSTYPE,OPTIONS,SIZE /tmp 2>/dev/null'));
    $target = ''; $sizeField = 0;
    if ($line !== '') {
        $p = preg_split('/\s+/', $line);
        $target            = $p[0] ?? '';
        $d['dev']          = $p[1] ?? '';
        $d['fstype']       = $p[2] ?? '';
        $d['options_raw']  = $p[3] ?? '';
        $d['options']      = $d['options_raw'] !== '' ? explode(',', $d['options_raw']) : [];
        $sizeField         = (int)($p[4] ?? 0);
    }
    // Is the loop of /usr/tmpDSK present? (first token before ':' from `losetup -j`)
    $loForDsk = trim((string)strtok((string)@shell_exec('losetup -j /usr/tmpDSK 2>/dev/null'), ':'));
    // Classify backing.
    if ($target === '/tmp') {
        if ($d['fstype'] === 'tmpfs') {
            $d['backing'] = 'tmpfs';
            $d['size_bytes'] = $sizeField;                        // tmpfs "size=" cap, in bytes
        } elseif ($loForDsk !== '' && ($d['dev'] === $loForDsk || strpos($d['dev'], '/dev/loop') === 0)) {
            $d['backing'] = 'loop';
            $d['loop_dev'] = $d['dev'] !== '' ? $d['dev'] : $loForDsk;
            $d['size_bytes'] = (int)trim((string)@shell_exec('stat -c %s /usr/tmpDSK 2>/dev/null')); // backing-file size
        } else {
            $d['backing'] = 'unknown';                           // a real dedicated /tmp partition, etc.
            $d['size_bytes'] = $sizeField;
        }
    } else {
        // findmnt resolved /tmp to a COVERING mount (e.g. "/") => /tmp is NOT its own mount => plain dir.
        $d['backing'] = 'plain';
        $d['backfs_mount'] = $target ?: '/';
    }
    // Used bytes (df Used column, KB -> bytes).
    $d['used_bytes'] = (int)trim((string)@shell_exec("df -Pk /tmp 2>/dev/null | awk 'NR==2{print \$3}'")) * 1024;
    // /var/tmp: is it a bind of /tmp, and with what options? (replicated verbatim on the re-bind).
    $vtTgt  = trim((string)@shell_exec('findmnt -no TARGET /var/tmp 2>/dev/null'));
    $vtSrc  = trim((string)@shell_exec('findmnt -no SOURCE /var/tmp 2>/dev/null'));
    $d['var_tmp_options'] = trim((string)@shell_exec('findmnt -no OPTIONS /var/tmp 2>/dev/null'));
    $d['var_tmp_is_bind'] = ($vtTgt === '/var/tmp' && $vtSrc !== '' && $vtSrc === $d['dev']);
    // Container gate.
    $virt = trim((string)@shell_exec('systemd-detect-virt --container 2>/dev/null'));
    $d['container'] = ($virt !== '' && $virt !== 'none') || @file_exists('/proc/vz');
    // Loop support gate.
    $d['loop_ok'] = strpos(trim((string)@shell_exec('losetup -f 2>/dev/null')), '/dev/loop') === 0;
    // Backing FS that holds /usr/tmpDSK == the FS mounted where dirname(/usr/tmpDSK)=/usr lives. Bytes AND inodes.
    $dir = '/usr';                                               // fixed literal = dirname('/usr/tmpDSK')
    $d['backfs_avail_bytes']  = (int)trim((string)@shell_exec("df -Pk " . escapeshellarg($dir) . " 2>/dev/null | awk 'NR==2{print \$4}'")) * 1024;
    $d['backfs_avail_inodes'] = (int)trim((string)@shell_exec("df -Pi " . escapeshellarg($dir) . " 2>/dev/null | awk 'NR==2{print \$4}'"));
    if ($d['backing'] !== 'plain') $d['backfs_mount'] = trim((string)@shell_exec("df -Pk " . escapeshellarg($dir) . " 2>/dev/null | awk 'NR==2{print \$6}'"));
    // SELinux enforcing?
    $d['selinux'] = strcasecmp(trim((string)@shell_exec('getenforce 2>/dev/null')), 'Enforcing') === 0;
    // CloudLinux CageFS enabled?
    if (@is_executable('/usr/sbin/cagefsctl')) {
        $d['cagefs'] = stripos((string)@shell_exec('/usr/sbin/cagefsctl --cagefs-status 2>/dev/null'), 'enabled') !== false;
    }
    // Is cPanel's own securetmp running right now? (our flock does not gate cPanel tooling)
    $d['securetmp_running'] = trim((string)@shell_exec('pgrep -f securetmp 2>/dev/null')) !== '';
    return $d;
}

/* ---------------- PLAN — pure bounds/safety math + human step list (never mutates) -------------- */
function smpro_ds_tmp_plan(array $d): array {
    $GiB = 1073741824;
    $cap = defined('SMPRO_DS_TMP_MAX') ? SMPRO_DS_TMP_MAX : (32 * $GiB);
    $ramfrac = defined('SMPRO_DS_TMP_RAMFRAC') ? SMPRO_DS_TMP_RAMFRAC : 0.5;
    $cur = (int)$d['size_bytes'];
    $backing = (string)$d['backing'];
    $p = ['backing'=>$backing,'cur_bytes'=>$cur,'new_bytes'=>0,'cap_bytes'=>$cap,
          'headroom_bytes'=>0,'avail_bytes'=>(int)$d['backfs_avail_bytes'],
          'safe'=>false,'refuse'=>false,'reason'=>'','steps'=>[],'caveats'=>[]];
    $refuse = function ($msg) use (&$p) { $p['refuse'] = true; $p['safe'] = false; $p['reason'] = $msg; return $p; };

    // Plain dir => nothing to double. REFUSE informatively.
    if ($backing === 'plain')
        return $refuse('/tmp is not a separate mount — it already uses the whole ' . ($d['backfs_mount'] ?: '/') . ' filesystem, so there is nothing to double. Free space by clearing /tmp cache or the parent filesystem instead.');
    if ($backing === 'unknown')
        return $refuse('/tmp is on an unrecognized backing (not tmpfs and not the cPanel /usr/tmpDSK loopback); automatic doubling is not supported here.');
    if ($cur <= 0)
        return $refuse('Could not determine the current /tmp size.');

    $new = $cur * 2;                                             // double
    if ($new <= $cur) return $refuse('Computed new size is not larger than current (overflow?).');

    if ($backing === 'tmpfs') {
        $mem = function_exists('smpro_mnt_mem') ? smpro_mnt_mem() : [];
        $memTotal = ((int)($mem['mem_total'] ?? 0)) * 1024;     // kB -> bytes
        // RAM-safety cap: doubling a RAM-backed /tmp toward total RAM invites OOM.
        if ($memTotal > 0 && $new > $ramfrac * $memTotal)
            return $refuse('Refused (RAM safety): doubling this RAM-backed /tmp to ' . smpro_ds_tmp_humb($new) . ' would exceed ' . (int)round($ramfrac * 100) . '% of total RAM (' . smpro_ds_tmp_humb((int)$memTotal) . '). tmpfs lives in RAM, so this risks OOM.');
        foreach (['findmnt','mount'] as $bin) if (!smpro_ds_tmp_has_bin($bin)) return $refuse('Required binary missing: ' . $bin . '.');
        $p['new_bytes'] = $new; $p['safe'] = true;
        $p['steps'] = [
            'Remount /tmp (tmpfs) with size=' . smpro_ds_tmp_humb($new) . ', preserving EVERY current mount option.',
            'Verify the new size took effect (else roll back to ' . smpro_ds_tmp_humb($cur) . ').',
            'Optionally update only the size= token on an existing tmpfs /tmp line in /etc/fstab.',
        ];
        return $p;
    }

    // ---- loop path bounds ----
    if ($cur >= $cap)
        return $refuse('Current /tmp (' . smpro_ds_tmp_humb($cur) . ') is already at or above the ' . smpro_ds_tmp_humb($cap) . ' cap; not expanding further.');
    $new = min($new, $cap);                                      // cap 2*cur at SMPRO_DS_TMP_MAX
    if ($new <= $cur) return $refuse('Nothing to do after applying the ' . smpro_ds_tmp_humb($cap) . ' cap.');
    if ($d['container'] && !$d['loop_ok'])
        return $refuse('This is a container (OpenVZ/LXC) without a usable loop device; /tmp cannot be resized here.');
    // ext-family ONLY: the mkfs "-F -m 0" flags are ext-specific; xfs/btrfs would be silently wrong.
    if (!in_array($d['fstype'], ['ext2','ext3','ext4'], true))
        return $refuse('/tmp is ' . ($d['fstype'] ?: 'an unknown') . ' filesystem; only ext2/ext3/ext4 loopbacks can be safely rebuilt (the mkfs flags used are ext-family specific).');
    // Never clobber a prior rollback artifact.
    if (@file_exists('/usr/tmpDSK.old'))
        return $refuse('A previous resize left /usr/tmpDSK.old in place; verify /tmp is healthy and remove the stale rollback file before running again.');
    if ($d['securetmp_running'])
        return $refuse('cPanel securetmp is currently running; wait for it to finish before resizing /tmp (our lock does not gate cPanel tooling).');
    // Free-space guard on the FS that holds /usr/tmpDSK (NOT /tmp itself): need new + headroom.
    $headroom = max($GiB, (int)ceil($new * 0.15));
    $p['headroom_bytes'] = $headroom;
    $needed = $new + $headroom;
    if ((int)$d['backfs_avail_bytes'] < $needed)
        return $refuse('Not enough free space on the backing filesystem (' . ($d['backfs_mount'] ?: '/usr') . '): ' . smpro_ds_tmp_humb((int)$d['backfs_avail_bytes']) . ' available, need ' . smpro_ds_tmp_humb($needed) . ' (new ' . smpro_ds_tmp_humb($new) . ' + ' . smpro_ds_tmp_humb($headroom) . ' headroom).');
    // Inode guard: a byte-sufficient but inode-exhausted FS still fails fallocate/dd/mkfs.
    if ((int)$d['backfs_avail_inodes'] > 0 && (int)$d['backfs_avail_inodes'] < 1000)
        return $refuse('The backing filesystem is low on free inodes (' . (int)$d['backfs_avail_inodes'] . '); cannot safely create the new /tmp image.');
    // Required binaries.
    foreach (['findmnt','losetup','mount','umount','mkfs.' . $d['fstype'],'chmod','cp','stat'] as $bin)
        if (!smpro_ds_tmp_has_bin($bin)) return $refuse('Required binary missing: ' . $bin . '.');
    if (!smpro_ds_tmp_has_bin('fallocate') && !smpro_ds_tmp_has_bin('dd'))
        return $refuse('Neither fallocate nor dd is available to create the new /tmp image.');

    $p['new_bytes'] = $new; $p['safe'] = true;
    if ($d['cagefs'])
        $p['caveats'][] = 'CloudLinux CageFS detected — caged users keep their own per-user /tmp; running caged processes keep the old /tmp until their cage is remounted (cagefsctl --remount-all, optional heavy follow-up).';
    $p['caveats'][] = 'A later cPanel securetmp / upcp run owns /usr/tmpDSK and could resize or revert this expansion.';
    $p['steps'] = [
        'Create /usr/tmpDSK.new at ' . smpro_ds_tmp_humb($new) . ' on ' . ($d['backfs_mount'] ?: '/usr') . ' (fallocate; dd fallback).',
        'Verify the image is EXACTLY ' . smpro_ds_tmp_humb($new) . ', then mkfs.' . $d['fstype'] . ' it.',
        'Mount the new image at a private staging point and copy LIVE /tmp into it (no downtime yet).',
        'Sub-second swap: detach /var/tmp bind (if any), lazily detach old /tmp, mount new at /tmp, chmod 1777, re-bind /var/tmp with its original options.',
        'Verify /tmp is mounted AND mode 1777; only then keep old image as /usr/tmpDSK.old and promote the new one.',
        'Automatic rollback guarantees /tmp stays mounted (new -> old -> emergency tmpfs) if any step fails.',
    ];
    return $p;
}

/* ---------------- VERIFY — authoritative post-mount / watchdog probe ---------------------------- */
function smpro_ds_tmp_verify_mounted(): array {
    $out = ['mounted'=>false,'writable'=>false,'mode1777'=>false,'noexec'=>false,'fstype'=>'','size_bytes'=>0];
    if (trim((string)@shell_exec('findmnt -no TARGET /tmp 2>/dev/null')) !== '/tmp') return $out; // not its own mount
    $out['mounted'] = true;
    $info = trim((string)@shell_exec('findmnt -nb -o FSTYPE,OPTIONS,SIZE /tmp 2>/dev/null'));
    if ($info !== '') {
        $pp = preg_split('/\s+/', $info);
        $out['fstype'] = $pp[0] ?? '';
        $out['noexec'] = strpos($pp[1] ?? '', 'noexec') !== false;
        $out['size_bytes'] = (int)($pp[2] ?? 0);
    }
    // AUTHORITATIVE mode check: root can write a 0755 root:root /tmp, so a write-probe alone is NOT sufficient.
    $out['mode1777'] = (trim((string)@shell_exec('stat -c %a /tmp 2>/dev/null')) === '1777');
    // Sanity write-probe (secondary).
    $t = @tempnam('/tmp', '.smpro_chk');
    if ($t !== false) { $out['writable'] = true; @unlink($t); }
    return $out;
}

/* ---------------- tmpfs path — instant, contents preserved, safe to run in-request -------------- */
function smpro_ds_tmp_expand_tmpfs(array $plan, array &$log): array {
    $cur = (int)$plan['cur_bytes']; $new = (int)$plan['new_bytes'];
    // Re-read LIVE options (atomic single remount); do not trust the preview snapshot.
    $optsRaw = trim((string)@shell_exec('findmnt -no OPTIONS /tmp 2>/dev/null'));
    if (trim((string)@shell_exec('findmnt -no FSTYPE /tmp 2>/dev/null')) !== 'tmpfs')
        return ['ok'=>false,'msg'=>'/tmp is no longer tmpfs; aborted.','from'=>$cur,'to'=>$cur,'persisted'=>false];
    $opts = $optsRaw !== '' ? explode(',', $optsRaw) : [];
    // Preserve EVERY option; replace ONLY size= (keep nr_inodes/mode/mpol/hugepages etc.).
    $kept = []; $hadSize = false;
    foreach ($opts as $o) {
        if ($o === '') continue;
        if (strpos($o, 'size=') === 0) { $kept[] = 'size=' . $new; $hadSize = true; }
        else $kept[] = $o;
    }
    if (!$hadSize) $kept[] = 'size=' . $new;
    $optStr = implode(',', $kept);
    // Defensive: mount options are fixed tokens; reject anything outside the expected char-class.
    if (!preg_match('#^[a-zA-Z0-9=,._:+%/-]+$#', $optStr))
        return ['ok'=>false,'msg'=>'Unexpected characters in current /tmp mount options; aborted for safety.','from'=>$cur,'to'=>$cur,'persisted'=>false];
    $log[] = 'remount /tmp size=' . $new;
    $res = (string)@shell_exec(smpro_mnt_wrap('mount -o ' . escapeshellarg('remount,' . $optStr) . ' /tmp 2>&1', 60));
    $now = (int)trim((string)@shell_exec('findmnt -nb -o SIZE /tmp 2>/dev/null'));
    if ($now < $new) {
        // Revert to the original size (best-effort), preserving the same options.
        $rb = []; foreach ($opts as $o) { if ($o === '') continue; $rb[] = strpos($o,'size=')===0 ? 'size='.$cur : $o; }
        @shell_exec(smpro_mnt_wrap('mount -o ' . escapeshellarg('remount,' . implode(',', $rb)) . ' /tmp 2>&1', 60));
        return ['ok'=>false,'msg'=>'Remount did not grow /tmp (now ' . smpro_ds_tmp_humb($now) . '); reverted. ' . trim(mb_substr($res,0,160)),'from'=>$cur,'to'=>$cur,'persisted'=>false];
    }
    $persisted = smpro_ds_tmp_persist_fstab('/tmp', $new, $log);
    return ['ok'=>true,'from'=>$cur,'to'=>$now,'persisted'=>$persisted,
            'msg'=>'/tmp (tmpfs) resized from ' . smpro_ds_tmp_humb($cur) . ' to ' . smpro_ds_tmp_humb($now) . '.' . ($persisted ? ' Persisted in /etc/fstab.' : ' (Not persisted — no matching fstab line; the change lasts until reboot.)')];
}

/* ---------------- tmpfs fstab persistence — rewrite ONLY size= on an EXISTING line -------------- */
function smpro_ds_tmp_persist_fstab(string $mount, int $new_bytes, array &$log): bool {
    if ($mount !== '/tmp') return false;                         // only ever manage /tmp
    $fstab = '/etc/fstab';
    if (!is_file($fstab) || !is_readable($fstab)) return false;
    $lines = @file($fstab, FILE_IGNORE_NEW_LINES);
    if (!is_array($lines)) return false;
    $idx = -1;
    foreach ($lines as $i => $l) {
        $t = trim($l);
        if ($t === '' || $t[0] === '#') continue;
        $c = preg_split('/\s+/', $t);
        if (count($c) >= 4 && $c[1] === '/tmp' && $c[2] === 'tmpfs') { $idx = $i; break; }
    }
    if ($idx < 0) return false;                                  // no existing tmpfs /tmp line — do NOT invent one
    $c = preg_split('/\s+/', trim($lines[$idx]));
    $opts = explode(',', $c[3]); $found = false;
    foreach ($opts as $k => $o) if (strpos($o, 'size=') === 0) { $opts[$k] = 'size=' . $new_bytes; $found = true; }
    if (!$found) $opts[] = 'size=' . $new_bytes;
    $c[3] = implode(',', $opts);
    $lines[$idx] = implode("\t", $c);
    // Backup first, then atomic tmp-in-same-dir + rename. NEVER runs `mount -a`.
    $bak = smpro_ds_tmp_dir() . '/fstab.' . date('Ymd_His');
    @copy($fstab, $bak); @chmod($bak, 0600);
    $tmp = $fstab . '.smpro.' . getmypid();
    if (@file_put_contents($tmp, implode("\n", $lines) . "\n", LOCK_EX) === false) { @unlink($tmp); return false; }
    @chmod($tmp, 0644);
    if (!@rename($tmp, $fstab)) { @unlink($tmp); return false; }
    $log[] = 'fstab size= updated (backup ' . basename($bak) . ')';
    return true;
}

/* ---------------- loop path — the RISKY path; runs ONLY in the detached worker under flock ------ */
function smpro_ds_tmp_expand_loop(array $plan, array &$log): array {
    $file = '/usr/tmpDSK'; $new_file = '/usr/tmpDSK.new'; $old_file = '/usr/tmpDSK.old';
    $mp = smpro_ds_tmp_mp();
    $cur0 = (int)$plan['cur_bytes'];
    $fail = function ($msg, $rolled = false, $critical = false) use ($cur0) {
        return ['ok'=>false,'msg'=>$msg,'from'=>$cur0,'to'=>$cur0,'rolled_back'=>$rolled,'critical'=>$critical];
    };

    // TOCTOU: re-detect UNDER LOCK (caller holds the flock). Backing/fstype could have changed since preview.
    $d = smpro_ds_tmp_detect();
    if ($d['backing'] !== 'loop')                      return $fail('Backing changed since preview (now ' . $d['backing'] . '); aborted before any change.');
    if (!in_array($d['fstype'], ['ext2','ext3','ext4'], true)) return $fail('/tmp fstype changed to ' . $d['fstype'] . '; aborted.');
    if ($d['securetmp_running'])                       return $fail('cPanel securetmp started running; deferring.');
    if (@file_exists($old_file))                       return $fail('Stale ' . $old_file . ' present; refusing to overwrite the rollback artifact.');

    $cur = (int)$d['size_bytes']; $newB = (int)$plan['new_bytes'];
    if ($newB <= $cur) return $fail('Recomputed new size not larger than current; aborted.');
    $to = smpro_ds_tmp_scaled_timeout($newB);
    $fstype = $d['fstype'];
    $varBind = !empty($d['var_tmp_is_bind']);
    $varOpts = (string)$d['var_tmp_options'];

    // Manifest baseline (records MP + loop device + /var/tmp opts so a watchdog can reap after a kill).
    $man = [
        'backing'=>'loop','phase'=>'prestage','cur_bytes'=>$cur,'new_bytes'=>$newB,'fstype'=>$fstype,
        'file'=>$file,'new_file'=>$new_file,'old_file'=>$old_file,'mp'=>$mp,'loop_dev'=>'','final_loop_dev'=>'',
        'var_tmp_is_bind'=>$varBind,'var_tmp_options'=>$varOpts,'options'=>$d['options'],
        'started_at'=>time(),'actor'=>function_exists('smpro_current_actor') ? smpro_current_actor() : 'root',
    ];
    smpro_ds_tmp_save($man);
    smpro_ds_tmp_job_write(['phase'=>'prestage','pct'=>5,'done'=>false,'msg'=>'Preparing new /tmp image','heartbeat'=>time()]);

    /* ---------- PHASE A — build the new fs (old /tmp stays mounted; zero downtime) ---------- */
    // Reap any leftover staging mount / .new from a previous aborted run (safe: not the live /tmp).
    @shell_exec(smpro_mnt_wrap('umount ' . escapeshellarg($mp) . ' 2>/dev/null', 30));
    @shell_exec('rm -f ' . escapeshellarg($new_file));
    @is_dir($mp) || @mkdir($mp, 0700, true); @chmod($mp, 0700);

    // 1) create image — fallocate (atomic reservation) preferred; dd fallback with a fresh free-space re-check.
    $created = false;
    if (smpro_ds_tmp_has_bin('fallocate')) {
        @shell_exec(smpro_mnt_wrap('fallocate -l ' . (int)$newB . ' ' . escapeshellarg($new_file) . ' 2>&1', $to));
        clearstatcache(); $created = ((int)@filesize($new_file) === $newB);
    }
    if (!$created) {
        @shell_exec('rm -f ' . escapeshellarg($new_file));
        $d2 = smpro_ds_tmp_detect();
        $need = $newB + max(1073741824, (int)ceil($newB * 0.15));
        if ((int)$d2['backfs_avail_bytes'] < $need) {           // a partial dd that fills ROOT is a whole-server Sev-1
            $rb = smpro_ds_tmp_rollback_loop('prestage', $d, $log);
            return $fail('Backing FS lost free space before dd; aborted, old /tmp intact.', true, !empty($rb['critical']));
        }
        $mib = (int)ceil($newB / 1048576);
        @shell_exec(smpro_mnt_wrap('dd if=/dev/zero of=' . escapeshellarg($new_file) . ' bs=1M count=' . $mib . ' status=none 2>&1', $to));
        clearstatcache();
    }
    // Exact-size assert BEFORE mkfs (catches a timeout-truncated dd -> short/broken fs).
    clearstatcache(); $actual = (int)@filesize($new_file);
    if ($actual !== $newB && $actual >= $newB && smpro_ds_tmp_has_bin('truncate')) {   // dd rounds up to whole MiB -> trim
        @shell_exec('truncate -s ' . (int)$newB . ' ' . escapeshellarg($new_file));
        clearstatcache(); $actual = (int)@filesize($new_file);
    }
    if ($actual !== $newB) {
        @shell_exec('rm -f ' . escapeshellarg($new_file));
        $rb = smpro_ds_tmp_rollback_loop('prestage', $d, $log);
        return $fail('New /tmp image not at exact size (' . smpro_ds_tmp_humb($actual) . ' vs ' . smpro_ds_tmp_humb($newB) . '); aborted, old /tmp intact.', true, !empty($rb['critical']));
    }
    smpro_ds_tmp_job_write(['phase'=>'mkfs','pct'=>25,'done'=>false,'msg'=>'Formatting new image','heartbeat'=>time()]);

    // 2) mkfs matching the ext-family fstype (whitelisted above). -F force on a file, -m0 no reserved blocks.
    $mkres = (string)@shell_exec(smpro_mnt_wrap('mkfs.' . $fstype . ' -q -F -m 0 ' . escapeshellarg($new_file) . ' 2>&1', $to));
    // 3) mount at private staging MP.
    @is_dir($mp) || @mkdir($mp, 0700, true);
    $mres = (string)@shell_exec(smpro_mnt_wrap('mount -o loop,noexec,nosuid,nodev,rw ' . escapeshellarg($new_file) . ' ' . escapeshellarg($mp) . ' 2>&1', 90));
    if (trim((string)@shell_exec('findmnt -no TARGET ' . escapeshellarg($mp) . ' 2>/dev/null')) !== $mp) {
        @shell_exec('rm -f ' . escapeshellarg($new_file));
        $rb = smpro_ds_tmp_rollback_loop('prestage', $d, $log);
        return $fail('Could not mkfs/mount the new image; aborted, old /tmp intact. ' . trim(mb_substr($mkres . ' ' . $mres, 0, 160)), true, !empty($rb['critical']));
    }
    // Record the staging loop device for rollback/watchdog cleanup.
    $man['loop_dev'] = trim((string)strtok((string)@shell_exec('losetup -j ' . escapeshellarg($new_file) . ' 2>/dev/null'), ':'));
    smpro_ds_tmp_save($man);
    @shell_exec('chmod 1777 ' . escapeshellarg($mp));
    smpro_ds_tmp_job_write(['phase'=>'copy','pct'=>40,'done'=>false,'msg'=>'Copying /tmp contents','heartbeat'=>time()]);
    // 4) copy LIVE /tmp -> staging (sessions/sockets/skeleton); services keep running.
    @shell_exec(smpro_mnt_wrap('cp -a /tmp/. ' . escapeshellarg($mp) . '/ 2>/dev/null', $to));

    /* ---------- PHASE B — the swap (sub-second; the ONLY sensitive window) ---------- */
    smpro_ds_tmp_job_write(['phase'=>'swap','pct'=>70,'done'=>false,'msg'=>'Swapping /tmp','heartbeat'=>time()]);
    // Delta copy for anything written during PHASE A.
    @shell_exec(smpro_mnt_wrap('cp -a -u /tmp/. ' . escapeshellarg($mp) . '/ 2>/dev/null', $to));
    // Free the new fs so it can be mounted at /tmp.
    @shell_exec(smpro_mnt_wrap('umount ' . escapeshellarg($mp) . ' 2>&1', 60));
    // HARD ASSERT: the staging mount/loop MUST be gone before we open a loop on $new_file at /tmp — on
    // util-linux <2.29 (CentOS7/CL7) a second `mount -o loop` on the same backing file = two rw superblocks
    // = ext4 corruption. The idle-class umount can time out, so lazy-detach + poll losetup, and if it still
    // will not release, ABORT while the OLD /tmp is still mounted (fully recoverable) rather than double-mount.
    if (trim((string)@shell_exec('findmnt -no TARGET ' . escapeshellarg($mp) . ' 2>/dev/null')) === $mp)
        @shell_exec(smpro_mnt_wrap('umount -l ' . escapeshellarg($mp) . ' 2>&1', 60));
    for ($i = 0; $i < 5; $i++) {
        if (trim((string)@shell_exec('losetup -j ' . escapeshellarg($new_file) . ' 2>/dev/null')) === '') break;
        @shell_exec('losetup -j ' . escapeshellarg($new_file) . ' 2>/dev/null | cut -d: -f1 | xargs -r -n1 losetup -d 2>/dev/null');
        @shell_exec('sleep 1');
    }
    if (trim((string)@shell_exec('losetup -j ' . escapeshellarg($new_file) . ' 2>/dev/null')) !== '') {
        $rb = smpro_ds_tmp_rollback_loop('prestage', $d, $log);   // old /tmp never detached yet -> clean
        return $fail('Staging mount/loop for the new image would not release before the swap; aborted with the old /tmp intact.', true, !empty($rb['critical']));
    }
    // Enter the sensitive window: record it BEFORE touching the live mounts.
    $man['phase'] = 'swap_detached'; smpro_ds_tmp_save($man);
    // Detach /var/tmp bind FIRST — only if it actually was a bind.
    if ($varBind) @shell_exec(smpro_mnt_wrap('umount /var/tmp 2>/dev/null', 60));
    // Clean detach of old /tmp; lazy fallback if busy (NEVER fuser -k / kill).
    @shell_exec(smpro_mnt_wrap('umount /tmp 2>&1', 60));
    if (trim((string)@shell_exec('findmnt -no TARGET /tmp 2>/dev/null')) === '/tmp')
        @shell_exec(smpro_mnt_wrap('umount -l /tmp 2>&1', 60));
    // Mount NEW image at /tmp  <-- failure here => R1 rollback.
    $mnew = (string)@shell_exec(smpro_mnt_wrap('mount -o loop,noexec,nosuid,nodev,rw ' . escapeshellarg($new_file) . ' /tmp 2>&1', 90));
    @shell_exec('chmod 1777 /tmp');
    $man['phase'] = 'swap_mounted';
    $man['final_loop_dev'] = trim((string)strtok((string)@shell_exec('losetup -j ' . escapeshellarg($new_file) . ' 2>/dev/null'), ':'));
    smpro_ds_tmp_save($man);
    // AUTHORITATIVE verify: mounted AND mode 1777 (a root write-probe passes on 0755 root:root — not trusted).
    $v = smpro_ds_tmp_verify_mounted();
    if (!$v['mounted'] || !$v['mode1777']) {
        $rb = smpro_ds_tmp_rollback_loop('swap_mounted', $d, $log);
        $man['phase'] = !empty($rb['critical']) ? 'failed' : 'rolled_back'; smpro_ds_tmp_save($man);
        return ['ok'=>false,'from'=>$cur,'to'=>$cur,'rolled_back'=>true,'critical'=>!empty($rb['critical']),
                'msg'=>'New /tmp failed verification (mounted=' . ($v['mounted']?'1':'0') . ', mode1777=' . ($v['mode1777']?'1':'0') . '). ' . ($rb['msg'] ?? 'Rolled back.')];
    }
    // SELinux relabel (guarded) so services aren't denied on the fresh /tmp.
    if (!empty($d['selinux'])) @shell_exec(smpro_mnt_wrap('restorecon -R /tmp /var/tmp 2>/dev/null', 120));
    // Re-bind /var/tmp with its ORIGINAL options (only if it was a bind).
    if ($varBind) {
        @shell_exec(smpro_mnt_wrap('mount -o bind /tmp /var/tmp 2>&1', 60));
        if ($varOpts !== '' && preg_match('#^[a-zA-Z0-9=,._:+%/-]+$#', $varOpts))
            @shell_exec(smpro_mnt_wrap('mount -o ' . escapeshellarg('remount,bind,' . $varOpts) . ' /var/tmp 2>&1', 60));
    }
    // Recreate the /tmp skeleton.
    if (smpro_ds_tmp_has_bin('systemd-tmpfiles')) @shell_exec('timeout 60 systemd-tmpfiles --create 2>/dev/null');
    // COMMIT — only AFTER verify passed: keep old image as .old, promote new. (loop tracks inode; rename is safe)
    @shell_exec('mv -f ' . escapeshellarg($file) . ' ' . escapeshellarg($old_file));
    @shell_exec('mv -f ' . escapeshellarg($new_file) . ' ' . escapeshellarg($file));
    $man['phase'] = 'committed'; $man['committed_at'] = time(); smpro_ds_tmp_save($man);
    smpro_ds_tmp_job_write(['phase'=>'done','pct'=>100,'done'=>true,'msg'=>'Done','heartbeat'=>time(),'result'=>['ok'=>true]]);
    return ['ok'=>true,'from'=>$cur,'to'=>$newB,'rolled_back'=>false,'critical'=>false,
            'msg'=>'/tmp expanded from ' . smpro_ds_tmp_humb($cur) . ' to ' . smpro_ds_tmp_humb($newB) . ' (loopback rebuilt, contents preserved). Old image kept as /usr/tmpDSK.old.'];
}

/* ---------------- ROLLBACK LADDER — GUARANTEES /tmp is mounted at exit (idempotent) ------------- */
function smpro_ds_tmp_rollback_loop(string $phase, array $d, array &$log): array {
    $file = '/usr/tmpDSK'; $new_file = '/usr/tmpDSK.new';
    $man = smpro_ds_tmp_load() ?: [];
    $mp        = (string)($man['mp'] ?? smpro_ds_tmp_mp());
    $loopDev   = (string)($man['loop_dev'] ?? '');
    $finalLoop = (string)($man['final_loop_dev'] ?? '');
    $varBind   = !empty($man['var_tmp_is_bind']) || !empty($d['var_tmp_is_bind']);
    $varOpts   = (string)($man['var_tmp_options'] ?? ($d['var_tmp_options'] ?? ''));
    $cur       = (int)($man['cur_bytes'] ?? ($d['size_bytes'] ?? 0));
    $out = ['recovered'=>false,'backing_now'=>'','critical'=>false,'msg'=>''];

    $rebindVar = function () use ($varBind, $varOpts) {
        if (!$varBind) return;
        if (trim((string)@shell_exec('findmnt -no TARGET /var/tmp 2>/dev/null')) !== '/var/tmp')
            @shell_exec(smpro_mnt_wrap('mount -o bind /tmp /var/tmp 2>&1', 60));
        if ($varOpts !== '' && preg_match('#^[a-zA-Z0-9=,._:+%/-]+$#', $varOpts))
            @shell_exec(smpro_mnt_wrap('mount -o ' . escapeshellarg('remount,bind,' . $varOpts) . ' /var/tmp 2>&1', 60));
    };
    // Release leaked staging artifacts. Resolve loops to detach ONLY path-wise via `losetup -j $new_file` — the
    // recorded $loop_dev number is unreliable after AUTOCLEAR (umount auto-frees + the number can be reused by an
    // unrelated process). AND never reap .new while it is the live backing of /tmp (killed-after-mount case).
    $freeStaging = function () use ($mp, $new_file) {
        if ($mp !== '') @shell_exec(smpro_mnt_wrap('umount ' . escapeshellarg($mp) . ' 2>/dev/null', 30));
        $tmpSrc = trim((string)@shell_exec('findmnt -no SOURCE /tmp 2>/dev/null'));
        $nl = array_values(array_filter(preg_split('/\s+/', trim((string)@shell_exec('losetup -j ' . escapeshellarg($new_file) . ' 2>/dev/null | cut -d: -f1')))));
        if ($tmpSrc !== '' && in_array($tmpSrc, $nl, true)) return;   // .new backs the live /tmp -> do NOT delete it
        @shell_exec('losetup -j ' . escapeshellarg($new_file) . ' 2>/dev/null | cut -d: -f1 | xargs -r losetup -d 2>/dev/null');
        @shell_exec('rm -f ' . escapeshellarg($new_file));
    };

    $mounted = trim((string)@shell_exec('findmnt -no TARGET /tmp 2>/dev/null')) === '/tmp';

    // PRE-DETACH: old /tmp never touched (prestage, or swap_detached but /tmp still mounted = died before umount).
    if ($phase === 'prestage' || ($phase === 'swap_detached' && $mounted)) {
        $freeStaging(); @rmdir($mp); $rebindVar();
        $out['recovered'] = true; $out['backing_now'] = 'old';
        $out['msg'] = 'Cleaned staging artifacts; the original /tmp was never detached.';
        $log[] = 'rollback: pre-detach cleanup';
        return $out;
    }

    /* POST-DETACH: /tmp may be bare, OR carrying a bad NEW mount (verify failed). Goal = ORIGINAL at /tmp, 1777. */
    $newLoops = array_values(array_filter([$finalLoop, $loopDev]));
    $src  = trim((string)@shell_exec('findmnt -no SOURCE /tmp 2>/dev/null'));
    $mode = trim((string)@shell_exec('stat -c %a /tmp 2>/dev/null'));
    $tmpMounted = trim((string)@shell_exec('findmnt -no TARGET /tmp 2>/dev/null')) === '/tmp';
    $badNew = $tmpMounted && (in_array($src, $newLoops, true) || $mode !== '1777');
    if ($badNew || !$tmpMounted) {
        if ($tmpMounted) {                                       // detach the bad/new mount (lazy if busy)
            @shell_exec(smpro_mnt_wrap('umount /tmp 2>&1', 60));
            if (trim((string)@shell_exec('findmnt -no TARGET /tmp 2>/dev/null')) === '/tmp')
                @shell_exec(smpro_mnt_wrap('umount -l /tmp 2>&1', 60));
        }
        foreach ($newLoops as $ld) if ($ld !== '' && strpos($ld, '/dev/loop') === 0) @shell_exec('losetup -d ' . escapeshellarg($ld) . ' 2>/dev/null');
        // R1: mount the ORIGINAL /usr/tmpDSK. A prior lazy `umount -l /tmp` may leave the original loop still
        // bound; REUSE it instead of opening a 2nd loop on the same image (which would double rw-mount + corrupt it).
        if (@file_exists($file)) {
            $origLoop = trim((string)strtok((string)@shell_exec('losetup -j ' . escapeshellarg($file) . ' 2>/dev/null'), ':'));
            if ($origLoop !== '' && strpos($origLoop, '/dev/loop') === 0)
                @shell_exec(smpro_mnt_wrap('mount -o noexec,nosuid,nodev,rw ' . escapeshellarg($origLoop) . ' /tmp 2>&1', 90));
            else
                @shell_exec(smpro_mnt_wrap('mount -o loop,noexec,nosuid,nodev,rw ' . escapeshellarg($file) . ' /tmp 2>&1', 90));
            @shell_exec('chmod 1777 /tmp');
        }
    }
    $mounted = trim((string)@shell_exec('findmnt -no TARGET /tmp 2>/dev/null')) === '/tmp';
    if ($mounted && trim((string)@shell_exec('stat -c %a /tmp 2>/dev/null')) === '1777') {
        $freeStaging(); @rmdir($mp); $rebindVar();
        $out['recovered'] = true; $out['backing_now'] = 'old';
        $out['msg'] = 'Recovered: original /usr/tmpDSK re-mounted at /tmp (R1).';
        $log[] = 'rollback: R1 original re-mounted';
        return $out;
    }
    // R2: last resort — emergency tmpfs so /tmp is NEVER left unmounted.
    $sz = $cur > 0 ? $cur : 1073741824;
    @shell_exec(smpro_mnt_wrap('umount /tmp 2>/dev/null', 30));
    @shell_exec(smpro_mnt_wrap('mount -t tmpfs -o ' . escapeshellarg('noexec,nosuid,nodev,size=' . (int)$sz . ',mode=1777') . ' tmpfs /tmp 2>&1', 60));
    $rebindVar();
    $mounted = trim((string)@shell_exec('findmnt -no TARGET /tmp 2>/dev/null')) === '/tmp';
    $out['recovered'] = $mounted; $out['backing_now'] = $mounted ? 'tmpfs' : ''; $out['critical'] = true;
    $out['msg'] = 'CRITICAL: original /tmp image would not mount; mounted an emergency tmpfs (' . smpro_ds_tmp_humb($sz) . ', in RAM). Recover data from /usr/tmpDSK.old / /usr/tmpDSK. Manual: umount /tmp; mount -o loop,noexec,nosuid,nodev /usr/tmpDSK /tmp; chmod 1777 /tmp.';
    $log[] = 'rollback: R2 emergency tmpfs';
    return $out;
}

/* ---------------- WATCHDOG — crash recovery from module top + cron (cheap, single-flight) -------- */
function smpro_ds_tmp_watchdog(): void {
    $mf = smpro_ds_tmp_manifest_path();
    if (!@is_file($mf)) return;                                  // cheap short-circuit: no run ever recorded
    $man = smpro_ds_tmp_load();
    if (!is_array($man)) return;
    $phase = (string)($man['phase'] ?? '');
    $sensitive = in_array($phase, ['swap_detached','swap_mounted'], true);
    // Terminal & nothing leaked => nothing to do (avoid churn on every page load).
    if (!$sensitive && !@is_file('/usr/tmpDSK.new')) return;
    // Single-flight via the SAME lock (non-blocking): if a worker holds it, IT owns recovery.
    $lockDir = function_exists('smpro_mnt_locks_dir') ? smpro_mnt_locks_dir() : SMPRO_LOCKS;
    @is_dir($lockDir) || @mkdir($lockDir, 0700, true);
    $fh = @fopen($lockDir . '/tmp_expand.lock', 'c');            // 'c' => never truncates; we never unlink the inode
    if (!$fh) return;
    if (!@flock($fh, LOCK_EX | LOCK_NB)) { @fclose($fh); return; }
    try {
        $tmpMounted = trim((string)@shell_exec('findmnt -no TARGET /tmp 2>/dev/null')) === '/tmp';
        if ($sensitive) {
            $log = []; $d = smpro_ds_tmp_detect();
            if (!$tmpMounted) {
                // Worker died mid-swap with /tmp bare -> run the ladder to restore it.
                $rb = smpro_ds_tmp_rollback_loop($phase, $d, $log);
                $man['phase'] = !empty($rb['critical']) ? 'failed' : 'rolled_back'; $man['watchdog_at'] = time();
                smpro_ds_tmp_save($man);
                if (function_exists('smpro_audit')) @smpro_audit('ds_tmp_watchdog', ['action'=>'recover','critical'=>!empty($rb['critical']),'phase'=>$phase]);
            } else {
                // /tmp is mounted — but is it the OLD original, or the NEW image (worker killed after a good mount,
                // before the commit rename)? If /tmp is already live on .new, the swap SUCCEEDED; only the rename was
                // missed — finish it (promote) rather than reaping .new (which would silently revert the expansion).
                $src = trim((string)@shell_exec('findmnt -no SOURCE /tmp 2>/dev/null'));
                $newLoopsRaw = trim((string)@shell_exec('losetup -j /usr/tmpDSK.new 2>/dev/null | cut -d: -f1'));
                $newLoops = $newLoopsRaw !== '' ? array_values(array_filter(preg_split('/\s+/', $newLoopsRaw))) : [];
                if ($src !== '' && in_array($src, $newLoops, true) && @is_file('/usr/tmpDSK.new')) {
                    if (@is_file('/usr/tmpDSK') && !@is_file('/usr/tmpDSK.old')) @shell_exec('mv -f /usr/tmpDSK /usr/tmpDSK.old');
                    @shell_exec('mv -f /usr/tmpDSK.new /usr/tmpDSK');   // loop tracks the inode -> /tmp stays mounted, re-backed by /usr/tmpDSK
                    $man['phase'] = 'committed'; $man['committed_at'] = time(); $man['watchdog_at'] = time(); smpro_ds_tmp_save($man);
                    if (function_exists('smpro_audit')) @smpro_audit('ds_tmp_watchdog', ['action'=>'promote_uncommitted','phase'=>$phase]);
                } else {
                    // Original still at /tmp: just clean leaked staging so stale guards don't wedge future runs.
                    smpro_ds_tmp_rollback_loop('prestage', $d, $log);
                    $man['phase'] = 'rolled_back'; $man['watchdog_at'] = time(); smpro_ds_tmp_save($man);
                    if (function_exists('smpro_audit')) @smpro_audit('ds_tmp_watchdog', ['action'=>'clean_leaks','phase'=>$phase]);
                }
            }
        } else {
            // Non-sensitive phase but a stray .new exists: reap orphaned staging loop/MP/.new from a prior abort.
            $mp = (string)($man['mp'] ?? smpro_ds_tmp_mp());
            if (trim((string)@shell_exec('findmnt -no TARGET ' . escapeshellarg($mp) . ' 2>/dev/null')) === $mp)
                @shell_exec(smpro_mnt_wrap('umount ' . escapeshellarg($mp) . ' 2>/dev/null', 30));
            @shell_exec('losetup -j /usr/tmpDSK.new 2>/dev/null | cut -d: -f1 | xargs -r losetup -d 2>/dev/null');
            @is_file('/usr/tmpDSK.new') && @unlink('/usr/tmpDSK.new');
        }
    } finally {
        @flock($fh, LOCK_UN); @fclose($fh);
    }
}

/* ---------------- worker launch (detached; NO inline fallback for the loop path) ---------------- */
function smpro_ds_tmp_php_bin(): string { return smpro_php_cli_bin(); }
function smpro_ds_tmp_launch_worker(array $plan): array {
    // Single-flight: refuse if a run already holds the lock.
    $lockDir = function_exists('smpro_mnt_locks_dir') ? smpro_mnt_locks_dir() : SMPRO_LOCKS;
    @is_dir($lockDir) || @mkdir($lockDir, 0700, true);
    $fh = @fopen($lockDir . '/tmp_expand.lock', 'c');
    if ($fh && @flock($fh, LOCK_EX | LOCK_NB)) { @flock($fh, LOCK_UN); @fclose($fh); }
    elseif ($fh) { @fclose($fh); return ['ok'=>false,'msg'=>'An expand is already running.']; }

    $worker = SMPRO_BASE . '/bin/tmp_expand.php';
    // NEVER run the loop swap inline: refuse if we cannot launch detached (mirrors the design's hard rule).
    if (!is_file($worker))
        return ['ok'=>false,'msg'=>'Loop /tmp expansion requires the background worker (bin/tmp_expand.php), which is missing. Refusing to run the swap inline.'];
    if (trim((string)@shell_exec('command -v setsid 2>/dev/null')) === '')
        return ['ok'=>false,'msg'=>'setsid is not available; cannot launch a detached worker. Refusing to run the loop swap inline (it would be tied to this HTTP request).'];

    $job = 'tmpexpand';                                          // server-generated fixed id (single-flight)
    // Seed the job file so the poller has state and we can detect the worker heartbeat.
    smpro_ds_tmp_job_write(['phase'=>'queued','pct'=>1,'done'=>false,'msg'=>'Launching background worker','heartbeat'=>0,'launched_at'=>time(),'new_bytes'=>(int)$plan['new_bytes']]);
    smpro_ds_tmp_save(['backing'=>'loop','phase'=>'queued','new_bytes'=>(int)$plan['new_bytes'],'cur_bytes'=>(int)$plan['cur_bytes'],'queued_at'=>time(),'actor'=>function_exists('smpro_current_actor') ? smpro_current_actor() : 'root']);

    // Detached launch with setsid + </dev/null (mirrors includes/tuning.php). No user input reaches the shell.
    @shell_exec('setsid ' . escapeshellarg(smpro_ds_tmp_php_bin()) . ' ' . escapeshellarg($worker) . ' ' . escapeshellarg('--job=' . $job) . ' >/dev/null 2>&1 </dev/null &');

    // Confirm the worker actually started: wait up to ~5s for a heartbeat, else report a launch failure.
    $started = false;
    for ($i = 0; $i < 25; $i++) {
        usleep(200000);
        $j = smpro_ds_tmp_job_read();
        if ((int)($j['heartbeat'] ?? 0) > 0 || in_array(($j['phase'] ?? ''), ['prestage','mkfs','copy','swap','swap_detached','swap_mounted','committed','done','failed','rolled_back'], true)) { $started = true; break; }
    }
    if (!$started)
        return ['ok'=>false,'msg'=>'The background worker did not start within 5s (setsid / PHP path?). No changes were made. Check bin/tmp_expand.php and the CGI PATH.'];
    if (function_exists('smpro_audit')) @smpro_audit('ds_tmp_expand', ['backing'=>'loop','action'=>'launch','new_bytes'=>(int)$plan['new_bytes']]);
    return ['ok'=>true,'job'=>$job,'msg'=>'Background /tmp expansion started. This modal will show progress.'];
}

/* ---------------- ds_action dispatch bodies (called from the module's POST block) --------------- */
function smpro_ds_tmp_dispatch(string $act): array {
    if ($act === 'preview_tmp_expand') {                        // READ-ONLY dry run — mirrors preview_boot_kernels
        $d = smpro_ds_tmp_detect(); $p = smpro_ds_tmp_plan($d);
        return [
            'ok'=>!$p['refuse'], 'preview'=>1, 'backing'=>$p['backing'],
            'cur'=>smpro_ds_tmp_humb((int)$p['cur_bytes']), 'new'=>smpro_ds_tmp_humb((int)$p['new_bytes']),
            'cur_bytes'=>(int)$p['cur_bytes'], 'new_bytes'=>(int)$p['new_bytes'],
            'avail'=>smpro_ds_tmp_humb((int)$p['avail_bytes']),
            'need'=>smpro_ds_tmp_humb((int)$p['new_bytes'] + (int)$p['headroom_bytes']),
            'steps'=>$p['steps'], 'safe'=>$p['safe'], 'refuse'=>$p['refuse'], 'reason'=>$p['reason'],
            'cagefs'=>!empty($d['cagefs']), 'caveats'=>$p['caveats'], 'backfs'=>$d['backfs_mount'],
            'msg'=>$p['refuse']
                ? ('Refused (safe): ' . $p['reason'])
                : ('Backing: ' . ($p['backing'] === 'loop' ? 'cPanel loopback (/usr/tmpDSK)' : 'tmpfs (RAM)') . ' — ' . smpro_ds_tmp_humb((int)$p['cur_bytes']) . ' -> ' . smpro_ds_tmp_humb((int)$p['new_bytes']) . '.'),
        ];
    }
    if ($act === 'tmp_expand_status') {                         // modal poller
        $j = smpro_ds_tmp_job_read();
        return ['ok'=>true,'phase'=>(string)($j['phase'] ?? 'idle'),'pct'=>(int)($j['pct'] ?? 0),
                'done'=>!empty($j['done']),'result'=>$j['result'] ?? null,'msg'=>(string)($j['msg'] ?? '')];
    }
    if ($act === 'tmp_expand') {
        $d = smpro_ds_tmp_detect(); $p = smpro_ds_tmp_plan($d);  // re-validate at execute time
        if ($p['refuse'] || !$p['safe']) return ['ok'=>false,'msg'=>'Refused (safe): ' . ($p['reason'] ?: 'not safe to expand now') . '.'];
        if ($p['backing'] === 'tmpfs') {                        // atomic + safe => run inline in-request
            $log = []; $res = smpro_ds_tmp_expand_tmpfs($p, $log);
            smpro_ds_tmp_job_write(['phase'=>'done','pct'=>100,'done'=>true,'msg'=>$res['msg'],'result'=>$res]);
            if (function_exists('smpro_audit')) @smpro_audit('ds_tmp_expand', ['backing'=>'tmpfs','from'=>$res['from'],'to'=>$res['to'],'ok'=>!empty($res['ok'])]);
            return ['ok'=>!empty($res['ok']),'inline'=>1,'backing'=>'tmpfs','msg'=>$res['msg'],'result'=>$res];
        }
        return smpro_ds_tmp_launch_worker($p);                   // loop path => detached worker only
    }
    return ['ok'=>false,'msg'=>'Unknown action.'];
}