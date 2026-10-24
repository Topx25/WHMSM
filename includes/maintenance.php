<?php
/**
 * includes/maintenance.php - server-maintenance backends shared by the Disk & Storage module + CLI workers.
 *   A1  smpro_swap_*  - add / double / remove a managed swapfile (preview + create + remove).
 *   A3  smpro_mnt_*   - auto-purge scheduler (config, hourly sampler, smart model, SAFE reclaim, cron sync, UI card).
 * Pure logic (only smpro_mnt_card_html() emits markup). Runs as root under the WHM CGI or the CLI worker.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

/* ---- constants ---- */
if (!defined('SMPRO_SWAP_PATH'))   define('SMPRO_SWAP_PATH', '/swapfile-smpro');            // fixed, at mount '/', never under /home
if (!defined('SMPRO_SWAP_META'))   define('SMPRO_SWAP_META', SMPRO_VARLIB . '/swap.json');  // 0600 managed-swap record
if (!defined('SMPRO_SWAP_MARKER')) define('SMPRO_SWAP_MARKER', '# smpro-swap:');            // fstab ownership marker
if (!defined('SMPRO_MNT_CFG'))     define('SMPRO_MNT_CFG', SMPRO_VARLIB . '/maintenance.json');        // admin schedule (cfg_save is the only writer)
if (!defined('SMPRO_MNT_STATE'))   define('SMPRO_MNT_STATE', SMPRO_VARLIB . '/maintenance-state.json');// runtime ring buffer / last_run

/* ---- shared helpers (owned HERE; A1/A3/A2 call these and never redefine them) ---- */
function smpro_mnt_wrap($c, $t = 110) { return 'timeout ' . (int)$t . ' nice -n ' . SMPRO_SCAN_NICE . ' ionice -c3 ' . $c; }
function smpro_mnt_locks_dir() { $d = defined('SMPRO_LOCKS') ? SMPRO_LOCKS : (SMPRO_VARLIB . '/locks'); if (!is_dir($d)) @mkdir($d, 0700, true); return $d; }
function smpro_mnt_mem() {
    $mi = [];
    foreach (@file('/proc/meminfo') ?: [] as $l) { if (preg_match('/^(\w+):\s+(\d+)/', $l, $m)) $mi[$m[1]] = (int)$m[2]; }
    $mt = $mi['MemTotal'] ?? 0; $ma = $mi['MemAvailable'] ?? ($mi['MemFree'] ?? 0);
    $st = $mi['SwapTotal'] ?? 0; $sf = $mi['SwapFree'] ?? 0; $su = max(0, $st - $sf);
    return ['mem_total'=>$mt,'mem_avail'=>$ma,'mem_avail_pct'=>$mt?round($ma/$mt*100,1):100,
            'swap_total'=>$st,'swap_used'=>$su,'swap_used_pct'=>$st?round($su/$st*100,1):0,'cached'=>$mi['Cached'] ?? 0];
}
function smpro_mnt_jread($path) { $d = is_file($path) ? json_decode((string)@file_get_contents($path), true) : null; return is_array($d) ? $d : []; }
function smpro_mnt_jwrite($path, $arr) {
    $dir = dirname($path); if (!is_dir($dir)) @mkdir($dir, 0700, true);
    $t = $path . '.tmp.' . getmypid();
    if (@file_put_contents($t, json_encode($arr, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), LOCK_EX) === false) { @unlink($t); return false; }
    @chmod($t, 0600); return @rename($t, $path);
}

/* ============================ A1 - managed swapfile (smpro_swap_*) ============================ */
/** Small human formatter working in whole MiB (32-bit safe; never touches raw byte ints). */
function smpro_swap_hmib($mib) {
    $mib = (int)$mib;
    if ($mib >= 1024) { $g = $mib / 1024; return (fmod($g, 1.0) == 0.0 ? (string)(int)$g : number_format($g, 1)) . ' GiB'; }
    return $mib . ' MiB';
}

/** Container/virt guard. '' = bare metal / full VM (swapfile OK); non-empty = a container where swapon(2) is blocked. */
function smpro_swap_virt() {
    // OpenVZ/Virtuozzo GUEST exposes /proc/user_beancounters; the host (HN) also has /proc/bc, so exclude that.
    if (@is_file('/proc/user_beancounters')) return 'openvz';
    if (@is_dir('/proc/vz') && !@is_dir('/proc/bc')) return 'openvz';           // vz guest, not the hardware node
    // systemd-detect-virt -c prints the container type or 'none'; time-bounded, no user input to escape.
    $v = trim((string)@shell_exec('timeout 5 systemd-detect-virt -c 2>/dev/null'));
    if ($v !== '' && strtolower($v) !== 'none') return $v;                       // lxc/docker/systemd-nspawn/...
    // no-systemd fallback: PID 1's environ carries "container=..." under lxc/docker/podman.
    $env = (string)@file_get_contents('/proc/1/environ');
    if ($env !== '' && strpos($env, 'container=') !== false) return 'container';
    return '';
}

/** Resolve an absolute path for a WHITELISTED tool name; '' if truly absent so callers can refuse/fallback. */
function smpro_swap_bin($name) {
    // whitelist so a caller can never turn this into an arbitrary-binary lookup.
    static $wl = ['fallocate','dd','mkswap','swapon','swapoff','chcon','getenforce','stat','findmnt','cp'];
    if (!in_array($name, $wl, true)) return '';
    foreach (['/usr/sbin/', '/sbin/', '/usr/bin/', '/bin/'] as $d) {            // known EL/cPanel locations first
        $p = $d . $name;
        if (@is_file($p) && @is_executable($p)) return $p;
    }
    // last resort - still no user input ($name is whitelisted above); escape defensively anyway.
    $cv = trim((string)@shell_exec('command -v ' . escapeshellarg($name) . ' 2>/dev/null'));
    return ($cv !== '' && $cv[0] === '/') ? $cv : '';
}

/** Parse /proc/swaps -> ['<path>'=>['type'=>'file|partition','size_kb'=>int,'used_kb'=>int]]. Strips ' (deleted)'. */
function smpro_swap_active() {
    $out = [];
    foreach (file('/proc/swaps') ?: [] as $i => $l) {
        if ($i === 0) continue;                                                  // header row
        // filename may contain spaces (e.g. "/swapfile-smpro (deleted)"), so capture it lazily and anchor
        // the trailing numeric columns; the kernel appends ' (deleted)' to an unlinked-but-active swapfile.
        if (!preg_match('/^(.*?)\s+(partition|file)\s+(\d+)\s+(\d+)\s+(-?\d+)\s*$/', trim($l), $m)) continue;
        $name = preg_replace('/ \(deleted\)$/', '', $m[1]);                      // strip so idempotency/removal match
        $out[$name] = ['type' => $m[2], 'size_kb' => (int)$m[3], 'used_kb' => (int)$m[4]];
    }
    return $out;
}

/** Resolve+validate the target filesystem for $dir. Accept only local ext2/3/4|xfs; avail/size returned as byte FLOATS. */
function smpro_swap_fs($dir) {
    $dir = ($dir === '' ? '/' : $dir);
    $fm = smpro_swap_bin('findmnt');
    $empty = ['ok'=>false,'reason'=>'','fstype'=>'','avail'=>0.0,'size'=>0.0,'target'=>'','source'=>''];
    if ($fm === '') { $empty['reason'] = 'findmnt not available to resolve the target filesystem.'; return $empty; }
    // -b = bytes, -n no header; --target resolves whichever mount backs $dir. $dir escaped even though default is '/'.
    $raw = trim((string)@shell_exec('timeout 15 ' . $fm . ' -nbo FSTYPE,AVAIL,SIZE,TARGET,SOURCE --target ' . escapeshellarg($dir) . ' 2>/dev/null'));
    if ($raw === '') { $empty['reason'] = 'Could not resolve a filesystem for ' . $dir . '.'; return $empty; }
    $p = preg_split('/\s+/', trim(explode("\n", $raw)[0]));
    $fstype = strtolower($p[0] ?? '');
    $res = ['ok'=>true,'reason'=>'','fstype'=>$fstype,
            'avail'=>(float)($p[1] ?? 0),                                        // byte FLOAT -> 32-bit safe > 2GB
            'size'=>(float)($p[2] ?? 0),'target'=>($p[3] ?? ''),'source'=>($p[4] ?? '')];
    // accept ONLY local, non-CoW, non-loop filesystems; btrfs excluded (swapfiles need chattr +C/no-snapshot).
    if (!in_array($fstype, ['ext2','ext3','ext4','xfs'], true)) {
        $res['ok'] = false; $res['reason'] = 'Target filesystem is ' . ($fstype ?: 'unknown')
            . '; a swapfile is only supported on ext2/3/4 or xfs (refusing btrfs/zfs/tmpfs/ramfs/overlay/aufs/nfs/fuse/squashfs/loop).';
        return $res;
    }
    if (strpos($res['source'], '/usr/tmpDSK') !== false) { $res['ok']=false; $res['reason']='Target is the loop-backed /usr/tmpDSK - refusing.'; return $res; }
    if ($res['target'] === '/tmp' || strpos($res['target'], '/tmp/') === 0) { $res['ok']=false; $res['reason']='Target is under /tmp (non-persistent) - refusing.'; return $res; }
    return $res;
}

/** Central dry-run planner (pure, NO writes). All sizing in whole-MiB integers; smpro_mnt_mem() is kB -> /1024. */
function smpro_swap_plan($opt = []) {
    $MIN_MIB = 256;                                                              // 256 MiB minimum
    $HARDCAP_MIB = 65536;                                                        // 64 GiB absolute ceiling (was 16 GiB - too low for big-RAM boxes)
    // 32-bit PHP cannot hold a 16GiB byte count -> clamp the cap under 2GiB there. cPanel PHP is 64-bit, but a
    // bin/*.php CLI could differ. All math below is MiB integers regardless, so this only bounds the ceiling.
    if (PHP_INT_SIZE < 8 && $HARDCAP_MIB > 2000) $HARDCAP_MIB = 2000;

    $dir  = (isset($opt['dir']) && $opt['dir'] !== '') ? (string)$opt['dir'] : '/';
    $path = SMPRO_SWAP_PATH;                                                     // fixed /swapfile-smpro at mount '/'
    $base = ['safe'=>false,'reason'=>'','path'=>$path,'add_mib'=>0,'add_bytes'=>0,'add_h'=>'',
             'ram_h'=>'','cur_swap_h'=>'','new_total_h'=>'','fstype'=>'','avail_h'=>'',
             'method'=>'dd','fstab_line'=>''];

    // (a) container/virt refuse - swapon is blocked inside OpenVZ/LXC/docker.
    $virt = smpro_swap_virt();
    if ($virt !== '') { $base['reason'] = 'Refused: this looks like a ' . $virt . ' container. Swap must be configured on the HOST (e.g. vzctl --swap / Proxmox CT config), not inside the guest.'; return $base; }

    // (b) PLAN-STAGE tool pre-refuse - never create a file we could not mkswap/activate.
    if (smpro_swap_bin('mkswap') === '' || smpro_swap_bin('swapon') === '') { $base['reason'] = 'Refused: mkswap/swapon not found - cannot initialise or activate a swapfile on this system.'; return $base; }

    // (c) memory (kB!) -> whole-MiB integers for ALL sizing.
    $mem = smpro_mnt_mem();
    $ram_mib = (int)intdiv((int)($mem['mem_total'] ?? 0), 1024);                 // kB -> MiB
    $cur_mib = (int)intdiv((int)($mem['swap_total'] ?? 0), 1024);               // kB -> MiB
    if ($ram_mib <= 0) { $base['reason'] = 'Refused: could not read MemTotal from /proc/meminfo.'; return $base; }

    // (c2) EXISTING MANAGED FILE -> in-place RESIZE (tear down old, create new at the same path), not a refuse.
    //      A file/active swap at our fixed path that we have NO record of (no meta, no fstab marker) is treated as a
    //      foreign/orphan occupant and refused - "Remove SM Pro swap" reclaims a genuine orphan of our own path.
    $exists  = @file_exists($path);
    $active0 = smpro_swap_active();
    $atPath  = $exists || isset($active0[$path]);
    $meta0   = smpro_swap_meta_read();
    $marked  = is_readable('/etc/fstab') && strpos((string)@file_get_contents('/etc/fstab'), SMPRO_SWAP_MARKER . $path) !== false;
    $ours    = $atPath && ((($meta0['path'] ?? '') === $path) || $marked);
    if ($atPath && !$ours) { $base['reason'] = 'Refused: something already occupies ' . $path . ' that SM Pro has no record of creating. Use "Remove SM Pro swap" first (it reclaims an orphan of this path), then Add.'; return $base; }
    $resize  = $ours;
    $old_mib = 0;                                                                // the managed file's SIZE (for the "double" default)
    $active_old_mib = 0;                                                         // its ACTIVE contribution to SwapTotal (0 if not swapped on)
    if ($resize) {
        if (isset($active0[$path])) { $active_old_mib = (int)round($active0[$path]['size_kb'] / 1024.0); $old_mib = $active_old_mib; }  // live size preferred
        if ($old_mib <= 0) $old_mib = (int)($meta0['size_mib'] ?? 0);
        if ($old_mib <= 0 && $exists) { $fb = (float)@filesize($path); if ($fb > 0) $old_mib = (int)floor($fb / 1048576.0); }
    }
    // Baseline swap that REMAINS after we remove our file = current SwapTotal minus OUR ACTIVE contribution. An
    // on-disk-but-inactive /swapfile-smpro contributes NOTHING to SwapTotal, so removing it must not lower the total
    // (using the file size here would wrongly under-count the projected total when the managed file isn't swapped on).
    $base_mib = $resize ? max(0, $cur_mib - $active_old_mib) : $cur_mib;

    $cap_mib = min(2 * $ram_mib, $HARDCAP_MIB);                                  // CAP = min(2xRAM, 64GiB)
    if ($base_mib >= $cap_mib) { $base['reason'] = 'Refused: SwapTotal' . ($resize ? ' (excluding the file being resized)' : '') . ' is already at/above the cap (' . smpro_swap_hmib($cap_mib) . ' = min of 2xRAM and 64GiB).' . ($resize ? '' : ' Remove existing swap first to resize.'); return $base; }
    $room_mib = $cap_mib - $base_mib;                                            // the largest the managed file may be
    if ($room_mib < $MIN_MIB) { $base['reason'] = 'Refused: only ' . smpro_swap_hmib($room_mib) . ' of headroom under the cap - below the 256MiB minimum.'; return $base; }

    // (c3) recommended range + Auto size - surfaced to the chooser as "RAM is X · min x · max y · Auto z".
    $max_rec_mib = $room_mib;                                                    // ceiling = min(2xRAM,16GiB) - swap that stays
    $min_rec_mib = max($MIN_MIB, min(2048, $room_mib));                          // useful 2 GiB floor (clamped to room)
    $auto_mib    = max($min_rec_mib, min($ram_mib, 8192, $room_mib));            // recommended: ~RAM, capped at 8 GiB / room

    // (d) desired managed-file size: an explicit typed size, otherwise Auto (the recommended size).
    if (isset($opt['target_mb']) && (int)$opt['target_mb'] > 0) {
        $add_mib = (int)$opt['target_mb']; $is_auto = false;                     // explicit admin size (MiB)
    } else {
        $add_mib = $auto_mib; $is_auto = true;                                   // Auto = recommended
    }
    if ($add_mib < $MIN_MIB)  $add_mib = $MIN_MIB;                               // clamp to [MIN, room]
    if ($add_mib > $room_mib) $add_mib = $room_mib;

    // (e) target FS: local ext2/3/4|xfs with disk headroom. In resize mode the old file (old_mib) is freed first.
    $fs = smpro_swap_fs($dir);
    if (!$fs['ok']) { $base['reason'] = 'Refused: ' . $fs['reason']; return $base; }
    $avail_mib  = (int)floor($fs['avail'] / 1048576.0) + ($resize ? $old_mib : 0);   // + space freed by removing the old file
    $fssize_mib = (int)floor($fs['size']  / 1048576.0);
    $reserve_mib = (int)max(1024, ceil($fssize_mib * 0.05));                     // keep max(1GiB, 5% of fs) free after
    if ($avail_mib - $add_mib < $reserve_mib) {
        $fit_mib = $avail_mib - $reserve_mib;                                    // can we still fit >= MIN honouring reserve?
        if ($fit_mib < $MIN_MIB) { $base['reason'] = 'Refused: not enough free space on ' . $fs['target'] . ' (' . $fs['fstype'] . '). Free' . ($resize ? ' (after removing the old file)' : ' now') . ' ' . smpro_swap_hmib($avail_mib) . ', need ' . smpro_swap_hmib($add_mib) . ' + a ' . smpro_swap_hmib($reserve_mib) . ' reserve. Free disk or choose a smaller size.'; return $base; }
        $add_mib = min($add_mib, $fit_mib);
    }
    // (f) an existing managed file is a RESIZE (above); a foreign/orphan occupant was refused above -> no clobber refuse here.

    // (g) method: DEFAULT dd for reliability; fallocate only an opportunistic fast path (retries via dd on holes).
    $method = (smpro_swap_bin('fallocate') !== '') ? 'fallocate' : 'dd';

    // (h) the exact fstab line (used internally for persistence; NOT shown as a raw command in the UI).
    $fstab_line = $path . ' none swap sw,nofail 0 0';

    $base['safe']        = true;
    $base['add_mib']     = $add_mib;
    $base['add_bytes']   = (PHP_INT_SIZE >= 8) ? $add_mib * 1048576 : 0;         // 32-bit: 0 (callers use add_mib)
    $base['add_h']       = smpro_swap_hmib($add_mib);
    $base['ram_h']       = smpro_swap_hmib($ram_mib);
    $base['cur_swap_h']  = smpro_swap_hmib($cur_mib);
    $base['new_total_h'] = smpro_swap_hmib($base_mib + $add_mib);                // base (swap remaining after teardown) + new file
    $base['resize']      = $resize;
    $base['old_size_h']  = $resize ? smpro_swap_hmib($old_mib) : '';
    $base['min_rec_h']   = smpro_swap_hmib($min_rec_mib);   // recommended range for the chooser
    $base['max_rec_h']   = smpro_swap_hmib($max_rec_mib);
    $base['min_rec_mib'] = $min_rec_mib;
    $base['max_rec_mib'] = $max_rec_mib;
    $base['auto_h']      = smpro_swap_hmib($auto_mib);      // Auto (recommended) size
    $base['auto_mib']    = $auto_mib;
    $base['is_auto']     = $is_auto;
    $base['fstype']      = $fs['fstype'];
    $base['avail_h']     = smpro_swap_hmib($avail_mib);
    $base['method']      = $method;
    $base['fstab_line']  = $fstab_line;
    $base['cap_h']       = smpro_swap_hmib($cap_mib);      // absolute cap = min(2xRAM, 64GiB)
    $base['room_mib']    = $room_mib;                      // largest the managed file may be (max allowed to add)
    $base['room_h']      = smpro_swap_hmib($room_mib);
    // if the admin typed a size larger than what fits, we clamped it - surface that so the UI can say so.
    $base['requested_mib'] = (isset($opt['target_mb']) && (int)$opt['target_mb'] > 0) ? (int)$opt['target_mb'] : 0;
    $base['clamped']       = ($base['requested_mib'] > 0 && $base['requested_mib'] !== $add_mib);
    return $base;
}

/** Read SMPRO_VARLIB/swap.json (0600) via the shared atomic reader. */
function smpro_swap_meta_read() {
    $d = smpro_mnt_jread(SMPRO_SWAP_META);
    return is_array($d) ? $d : [];
}
/** Write (or clear with []) swap.json atomically 0600 via the shared writer. Record: path,size_mib,created,actor,uuid,fstab,state. */
function smpro_swap_meta_write($rec) {
    return (bool)smpro_mnt_jwrite(SMPRO_SWAP_META, is_array($rec) ? $rec : []);
}

/** Persist backup-first + atomic. REFUSES an unmarked admin-authored swap line for $path; dedupes our own. */
function smpro_swap_fstab_add($path) {
    $fstab = '/etc/fstab';
    $orig = @file_get_contents($fstab);
    if ($orig === false) return ['ok'=>false,'msg'=>'Could not read /etc/fstab.','backup'=>''];

    $bkdir = SMPRO_VARLIB . '/backups'; @is_dir($bkdir) || @mkdir($bkdir, 0700, true);
    $backup = $bkdir . '/fstab.' . date('Ymd_His') . '.bak';                     // backup FIRST (0600)
    if (@file_put_contents($backup, $orig, LOCK_EX) === false) return ['ok'=>false,'msg'=>'Could not write fstab backup.','backup'=>''];
    @chmod($backup, 0600);

    $lines  = explode("\n", $orig);
    $marker = SMPRO_SWAP_MARKER . $path;                                         // '# smpro-swap:/swapfile-smpro'

    // Pass 1 - REFUSE an admin-authored (unmarked) swap entry for $path rather than rewriting its options.
    $prev = '';
    foreach ($lines as $l) {
        $t = trim($l);
        if ($t !== '' && $t[0] !== '#') {
            $f = preg_split('/\s+/', $t);
            if (isset($f[0], $f[2]) && $f[0] === $path && $f[2] === 'swap' && strpos($prev, $marker) !== 0) {
                return ['ok'=>false,'msg'=>'Refused: /etc/fstab already has a swap entry for ' . $path . ' that SM Pro did not add. Remove it manually first.','backup'=>$backup];
            }
        }
        $prev = $t;
    }
    // Pass 2 - rebuild dropping our own marker comment(s) + swap line(s) for $path (dedup), then append fresh.
    $out = [];
    foreach ($lines as $l) {
        $t = trim($l);
        if (strpos($t, $marker) === 0) continue;                                 // our marker comment
        if ($t !== '' && $t[0] !== '#') {
            $f = preg_split('/\s+/', $t);
            if (isset($f[0], $f[2]) && $f[0] === $path && $f[2] === 'swap') continue;  // our swap line (pass 1 proved it's ours)
        }
        $out[] = $l;
    }
    while (count($out) && trim(end($out)) === '') array_pop($out);               // trim trailing blanks
    $out[] = $marker . ' - added ' . date('Y-m-d') . ' by SM Pro (remove via Disk & Storage)';
    $out[] = $path . ' none swap sw,nofail 0 0';
    $new = implode("\n", $out) . "\n";

    // VALIDATE - every pre-existing line (except the swap line we intentionally replaced) survives.
    foreach ($lines as $l) {
        $t = trim($l);
        if ($t === '' || $t[0] === '#') continue;
        $f = preg_split('/\s+/', $t);
        if (isset($f[0], $f[2]) && $f[0] === $path && $f[2] === 'swap') continue;
        if (strpos($new, $l) === false) return ['ok'=>false,'msg'=>'Refused: fstab safety validation failed (a line would be lost). No change made.','backup'=>$backup];
    }

    $tmp = $fstab . '.smpro.tmp';                                                // atomic temp-in-same-dir + rename
    if (@file_put_contents($tmp, $new, LOCK_EX) === false) { @unlink($tmp); return ['ok'=>false,'msg'=>'Could not write /etc/fstab temp file.','backup'=>$backup]; }
    @chmod($tmp, 0644);
    if (!@rename($tmp, $fstab)) { @unlink($tmp); return ['ok'=>false,'msg'=>'Could not atomically replace /etc/fstab.','backup'=>$backup]; }
    return ['ok'=>true,'msg'=>'Persisted to /etc/fstab (backup: ' . basename($backup) . ').','backup'=>$backup];
}

/** Reversal: backup, drop ONLY our marker comment + the swap line for $path that our marker precedes. Never other/unmarked. */
function smpro_swap_fstab_remove($path) {
    $fstab = '/etc/fstab';
    $orig = @file_get_contents($fstab);
    if ($orig === false) return ['ok'=>false,'msg'=>'Could not read /etc/fstab.','backup'=>''];

    $bkdir = SMPRO_VARLIB . '/backups'; @is_dir($bkdir) || @mkdir($bkdir, 0700, true);
    $backup = $bkdir . '/fstab.' . date('Ymd_His') . '.bak';
    if (@file_put_contents($backup, $orig, LOCK_EX) === false) return ['ok'=>false,'msg'=>'Could not write fstab backup.','backup'=>''];
    @chmod($backup, 0600);

    $lines  = explode("\n", $orig);
    $marker = SMPRO_SWAP_MARKER . $path;
    $out = []; $prev = '';
    foreach ($lines as $l) {
        $t = trim($l);
        if (strpos($t, $marker) === 0) { $prev = $t; continue; }                 // drop our marker; remember for next line
        if ($t !== '' && $t[0] !== '#') {
            $f = preg_split('/\s+/', $t);
            if (isset($f[0], $f[2]) && $f[0] === $path && $f[2] === 'swap' && strpos($prev, $marker) === 0) { $prev = $t; continue; }  // our MARKED swap line
        }
        $prev = $t;
        $out[] = $l;
    }
    $new = implode("\n", $out);
    if (substr($new, -1) !== "\n") $new .= "\n";

    $tmp = $fstab . '.smpro.tmp';
    if (@file_put_contents($tmp, $new, LOCK_EX) === false) { @unlink($tmp); return ['ok'=>false,'msg'=>'Could not write /etc/fstab temp file.','backup'=>$backup]; }
    @chmod($tmp, 0644);
    if (!@rename($tmp, $fstab)) { @unlink($tmp); return ['ok'=>false,'msg'=>'Could not atomically replace /etc/fstab.','backup'=>$backup]; }
    return ['ok'=>true,'msg'=>'Removed our /etc/fstab swap entry (backup: ' . basename($backup) . ').','backup'=>$backup];
}

/** Execution orchestrator under SMPRO_LOCKS/swap.lock. Creates+activates+persists with a staged rollback ladder. */
function smpro_swap_create($plan) {
    if (!is_array($plan) || empty($plan['safe'])) return ['ok'=>false,'msg'=>'Refused: ' . ((is_array($plan) && !empty($plan['reason'])) ? $plan['reason'] : 'no valid plan') . '.'];
    $path    = SMPRO_SWAP_PATH;
    $add_mib = (int)($plan['add_mib'] ?? 0);
    if ($add_mib < 256) return ['ok'=>false,'msg'=>'Refused: computed size below the 256MiB minimum.'];

    // single-flight lock - SHARED with swap_remove AND the existing fix_swap (see wiring hooks).
    $ldir = smpro_mnt_locks_dir();
    $lockFp = @fopen($ldir . '/swap.lock', 'c');
    if ($lockFp === false) { return ['ok'=>false,'msg'=>'Refused: cannot open the swap lock at ' . $ldir . '/swap.lock — check that ' . $ldir . ' exists and is writable.']; }
    if (!@flock($lockFp, LOCK_EX | LOCK_NB)) { @fclose($lockFp); return ['ok'=>false,'msg'=>'A swap operation is already in progress. Try again shortly.']; }
    @chmod($ldir . '/swap.lock', 0600);
    $unlock = function () use ($lockFp) { @flock($lockFp, LOCK_UN); @fclose($lockFp); };  // NOTE: never unlink the lock file (fopen('c')+flock single-flight)
    $resize = !empty($plan['resize']);
    // On FAILURE: a fresh add unlinks its partial file + clears meta; a RESIZE keeps the file + its fstab marker +
    // pending meta so smpro_swap_reconcile() can recover the prior swap (we never stage a second/extra file).
    $failReturn = function ($msg) use ($path, $unlock, $resize) {
        if ($resize) { $m = smpro_swap_meta_read(); if (!is_array($m) || empty($m)) $m = ['path'=>$path]; $m['state'] = 'pending'; smpro_swap_meta_write($m); }
        else { @unlink($path); smpro_swap_meta_write([]); }
        $unlock(); return ['ok'=>false, 'msg'=>$msg];
    };

    // RESIZE (IN PLACE): keep the SAME managed swapfile and re-size IT - never remove it and never create a second
    // file. Just DEACTIVATE it first (OOM-pre-checked) so the allocation below can grow/shrink the same path; the
    // prior fstab line is stripped so persist re-adds one clean entry at the new size. Runs under the held lock.
    if (!empty($plan['resize'])) {
        $ract = smpro_swap_active();
        if (isset($ract[$path])) {
            if (($ract[$path]['type'] ?? '') === 'partition') { $unlock(); return ['ok'=>false,'msg'=>'Refused: ' . $path . ' resolves to a swap PARTITION, not our file.']; }
            $rmem = smpro_mnt_mem(); $rUsedKb = (int)$ract[$path]['used_kb']; $rNeedKb = (int)($rUsedKb * 1.2) + 262144;
            if ((int)($rmem['mem_avail'] ?? 0) < $rNeedKb) { $unlock(); return ['ok'=>false,'msg'=>'Refused: resizing would OOM the server. In-use swap ' . smpro_swap_hmib((int)intdiv($rUsedKb, 1024)) . ' needs ~' . smpro_swap_hmib((int)intdiv($rNeedKb, 1024)) . ' free RAM; only ' . smpro_swap_hmib((int)intdiv((int)($rmem['mem_avail'] ?? 0), 1024)) . ' available.']; }
            $rUsedMib = (int)intdiv($rUsedKb, 1024); $rt = min(1800, 120 + (int)($rUsedMib / 5));
            $roff = (string)@shell_exec('timeout ' . $rt . ' ' . smpro_swap_bin('swapoff') . ' ' . escapeshellarg($path) . ' 2>&1');
            $rchk = smpro_swap_active();
            if (isset($rchk[$path])) { $unlock(); return ['ok'=>false,'msg'=>'Resize aborted: could not deactivate the current swapfile (still active) — the swap is untouched. ' . trim(mb_substr($roff, 0, 120))]; }
        }
        // KEEP the '# smpro-swap:' fstab marker through the swapoff->allocate->mkswap->swapon window: if the process
        // is killed here, reconcile sees the marker and re-activates the still-valid file instead of losing the swap.
        // On success, smpro_swap_fstab_add() below dedupes and re-writes one clean line at the new size.
    }

    // re-check idempotency INSIDE the lock (defeats preview->execute TOCTOU). A RESIZE deliberately keeps the existing
    // file (it is grown in place below), so the no-clobber refuse applies only to a FRESH add.
    if (empty($plan['resize']) && @file_exists($path)) { $unlock(); return ['ok'=>false,'msg'=>'Refused: ' . $path . ' already exists (no clobber). Remove it first.']; }
    $act0 = smpro_swap_active();
    if (empty($plan['resize']) && isset($act0[$path])) { $unlock(); return ['ok'=>false,'msg'=>'Refused: ' . $path . ' is already active. Remove it first.']; }

    $ea    = escapeshellarg($path);
    $actor = function_exists('smpro_current_actor') ? smpro_current_actor() : (function_exists('smpro_actor') ? smpro_actor() : 'root');

    // (1) RECORD INTENT before any activation so a crash mid-create is reconcilable against /proc/swaps.
    smpro_swap_meta_write(['path'=>$path,'size_mib'=>$add_mib,'created'=>date('c'),'actor'=>$actor,'uuid'=>'','fstab'=>false,'state'=>'pending']);

    $ddbin = smpro_swap_bin('dd');
    $mkDD = function () use ($ddbin, $ea, $add_mib) {                            // reliable default allocation
        $t = min(600, 60 + (int)($add_mib / 5));                                 // scale timeout to size
        return (string)@shell_exec(smpro_mnt_wrap($ddbin . ' if=/dev/zero of=' . $ea . ' bs=1M count=' . $add_mib . ' conv=fsync status=none 2>&1', $t));
    };
    $sizeOkMiB = function () use ($path, $add_mib) {                             // on-disk size compared in MiB (32-bit safe)
        $b = (float)trim((string)@shell_exec('timeout 10 stat -c %s ' . escapeshellarg($path) . ' 2>/dev/null'));
        return ((int)floor($b / 1048576.0) === $add_mib);
    };
    $inSwaps = function () use ($path, $add_mib) {                               // PRIMARY verify: our path in /proc/swaps at size~add
        $a = smpro_swap_active();
        if (!isset($a[$path])) return false;
        return abs((int)round($a[$path]['size_kb'] / 1024.0) - $add_mib) <= 1;   // +/-1 MiB
    };

    // ---- create backing file: fallocate fast path (if chosen) else dd; verify on-disk size, dd fallback once ----
    $method = ($plan['method'] === 'fallocate' && smpro_swap_bin('fallocate') !== '') ? 'fallocate' : 'dd';
    if ($method === 'fallocate') {
        @shell_exec(smpro_mnt_wrap(smpro_swap_bin('fallocate') . ' -l ' . $add_mib . 'MiB ' . $ea . ' 2>&1', 60));
    } else {
        $mkDD();
    }
    if (!@file_exists($path) || !$sizeOkMiB()) {
        @unlink($path); $mkDD();                                                 // fall back to dd once
        if (!@file_exists($path) || !$sizeOkMiB()) {
            return $failReturn('Refused: could not allocate the swapfile at the requested size on disk.');
        }
    }

    @chmod($path, 0600);                                                         // 0600 BEFORE mkswap (else it warns/refuses)

    // best-effort SELinux label so enforcing does not deny swapon.
    if (smpro_swap_bin('getenforce') !== '') {
        $se = trim((string)@shell_exec('timeout 10 ' . smpro_swap_bin('getenforce') . ' 2>/dev/null'));
        if (strcasecmp($se, 'Enforcing') === 0 && smpro_swap_bin('chcon') !== '')
            @shell_exec('timeout 10 ' . smpro_swap_bin('chcon') . ' -t swapfile_t ' . $ea . ' 2>&1');
    }

    // mkswap (capture UUID) -> swapon (real activation gate).
    $mk = (string)@shell_exec('timeout 30 ' . smpro_swap_bin('mkswap') . ' ' . $ea . ' 2>&1');
    $uuid = preg_match('/UUID=([0-9a-fA-F-]+)/', $mk, $um) ? $um[1] : '';
    $mkOk = ($uuid !== '') || stripos($mk, 'swapspace') !== false;
    if (!$mkOk) {
        return $failReturn('Refused: mkswap failed: ' . trim(mb_substr($mk, 0, 180)));
    }
    $on = (string)@shell_exec('timeout 30 ' . smpro_swap_bin('swapon') . ' ' . $ea . ' 2>&1');

    // fallocate unwritten-extent case -> swapon rejects with holes/Invalid argument -> rebuild via dd, retry ONCE.
    if (trim($on) !== '' && preg_match('/holes|Invalid argument/i', $on) && $method === 'fallocate') {
        @shell_exec('timeout 20 ' . smpro_swap_bin('swapoff') . ' ' . $ea . ' 2>/dev/null');
        @unlink($path); $mkDD();
        if (@file_exists($path) && $sizeOkMiB()) {
            @chmod($path, 0600);
            @shell_exec('timeout 30 ' . smpro_swap_bin('mkswap') . ' ' . $ea . ' 2>&1');
            $on = (string)@shell_exec('timeout 30 ' . smpro_swap_bin('swapon') . ' ' . $ea . ' 2>&1');
        }
    }

    // VERIFY (PRIMARY = /proc/swaps membership). On failure -> swapoff -> CONFIRM absent -> ONLY THEN unlink.
    if (!$inSwaps()) {
        @shell_exec('timeout 60 ' . smpro_swap_bin('swapoff') . ' ' . $ea . ' 2>/dev/null');
        $a1 = smpro_swap_active();
        if (isset($a1[$path])) {
            // swapoff failed -> NEVER unlink an active swapfile; keep it (beneficial) and report.
            smpro_swap_meta_write(['path'=>$path,'size_mib'=>$add_mib,'created'=>date('c'),'actor'=>$actor,'uuid'=>$uuid,'fstab'=>false,'state'=>'active']);
            $unlock();
            return ['ok'=>false,'msg'=>'swapon verification was inconclusive and the file is still active - left in place (not unlinked). swapon said: ' . trim(mb_substr($on, 0, 160))];
        }
        return $failReturn('Refused: swapon did not activate ' . $path . '. ' . trim(mb_substr($on, 0, 180)));
    }

    // ACTIVE + verified -> persist (backup-first, atomic). fstab failure keeps the beneficial live swap.
    $fst = smpro_swap_fstab_add($path);
    $persistent = !empty($fst['ok']);
    smpro_swap_meta_write(['path'=>$path,'size_mib'=>$add_mib,'created'=>date('c'),'actor'=>$actor,'uuid'=>$uuid,'fstab'=>$persistent,'state'=>'active']);
    $unlock();

    if ($persistent) return ['ok'=>true,'msg'=>'Swap file created and active: ' . $path . ' (' . smpro_swap_hmib($add_mib) . '). Persistent across reboot via /etc/fstab.','path'=>$path,'add_h'=>smpro_swap_hmib($add_mib),'persistent'=>true,'uuid'=>$uuid];
    return ['ok'=>true,'msg'=>'Swap file created and ACTIVE now (' . smpro_swap_hmib($add_mib) . ') but NOT persistent across reboot (' . ($fst['msg'] ?? 'fstab not updated') . '). Add this line to /etc/fstab manually: ' . $path . ' none swap sw,nofail 0 0','path'=>$path,'add_h'=>smpro_swap_hmib($add_mib),'persistent'=>false,'uuid'=>$uuid];
}

/** Reversal orchestrator under the SAME lock. Only ever our managed regular file; OOM-precheck; scaled swapoff. */
function smpro_swap_remove($path, $heldLock = false) {
    $path = (string)$path;
    if ($path !== SMPRO_SWAP_PATH) return ['ok'=>false,'msg'=>'Refused: SM Pro only removes its own swapfile (' . SMPRO_SWAP_PATH . ').'];

    // $heldLock: the caller (smpro_swap_create resize path) already owns swap.lock - do NOT re-acquire it
    // (LOCK_NB would fail against ourselves) and do NOT release it here.
    if ($heldLock) {
        $unlock = function () {};
    } else {
        $ldir = smpro_mnt_locks_dir();
        $lockFp = @fopen($ldir . '/swap.lock', 'c');
        if ($lockFp === false) { return ['ok'=>false,'msg'=>'Refused: cannot open the swap lock at ' . $ldir . '/swap.lock — check that ' . $ldir . ' exists and is writable.']; }
        if (!@flock($lockFp, LOCK_EX | LOCK_NB)) { @fclose($lockFp); return ['ok'=>false,'msg'=>'A swap operation is already in progress. Try again shortly.']; }
        @chmod($ldir . '/swap.lock', 0600);
        $unlock = function () use ($lockFp) { @flock($lockFp, LOCK_UN); @fclose($lockFp); };
    }

    // ownership: in swap.json OR carries our fstab marker OR is our fixed-path regular file / active (orphan recovery).
    $meta    = smpro_swap_meta_read();
    $managed = (isset($meta['path']) && $meta['path'] === $path);
    if (!$managed) { $fstab = (string)@file_get_contents('/etc/fstab'); if (strpos($fstab, SMPRO_SWAP_MARKER . $path) !== false) $managed = true; }
    $isRegular = @is_file($path) && !@is_link($path);
    $active    = smpro_swap_active();
    $isActive  = isset($active[$path]);
    if (!$managed && !($path === SMPRO_SWAP_PATH && ($isRegular || $isActive))) { $unlock(); return ['ok'=>false,'msg'=>'Refused: ' . $path . ' is not a swapfile SM Pro manages.']; }
    // NEVER a swap partition / block device.
    if ($isActive && $active[$path]['type'] === 'partition') { $unlock(); return ['ok'=>false,'msg'=>'Refused: ' . $path . ' is a swap PARTITION, not our file.']; }

    // OOM pre-check: MemAvailable >= thisFile.Used*1.2 + 256MiB (all kB, consistent with smpro_mnt_mem()).
    $mem = smpro_mnt_mem();
    $memAvailKb = (int)($mem['mem_avail'] ?? 0);
    $usedKb = $isActive ? (int)$active[$path]['used_kb'] : 0;
    $needKb = (int)($usedKb * 1.2) + 262144;                                     // 256 MiB = 262144 kB
    if ($isActive && $memAvailKb < $needKb) {
        $unlock();
        return ['ok'=>false,'msg'=>'Refused: removing this swap could OOM the server. In-use swap ' . smpro_swap_hmib((int)intdiv($usedKb, 1024)) . ' needs ~' . smpro_swap_hmib((int)intdiv($needKb, 1024)) . ' free RAM; only ' . smpro_swap_hmib((int)intdiv($memAvailKb, 1024)) . ' available.'];
    }

    // DEACTIVATE: swapoff only this path, timeout scaled to used size; never swapoff -a.
    if ($isActive) {
        $usedMib = (int)intdiv($usedKb, 1024);
        $t = min(1800, 120 + (int)($usedMib / 5));
        $off = (string)@shell_exec('timeout ' . $t . ' ' . smpro_swap_bin('swapoff') . ' ' . escapeshellarg($path) . ' 2>&1');
        $a2 = smpro_swap_active();                                               // CONFIRM it left /proc/swaps
        if (isset($a2[$path])) { $unlock(); return ['ok'=>false,'msg'=>'Refused: swapoff did not complete (still active) - leaving the swapfile and fstab intact. ' . trim(mb_substr($off, 0, 160))]; }
    }

    // CLEANUP: only now unlink; strip fstab; drop swap.json.
    if (@is_file($path) && !@is_link($path)) @unlink($path);
    smpro_swap_fstab_remove($path);
    smpro_swap_meta_write([]);
    $unlock();
    return ['ok'=>true,'msg'=>'Swap removed: deactivated, file deleted and /etc/fstab entry stripped.'];
}

/** SELF-HEAL stale managed-swap state so a broken/half-made swapfile never lingers or gets counted in the UI:
 *  - a managed file that is on disk but NOT active is RE-ACTIVATED (if it swaps on) or else CLEANED UP (rm + strip
 *    fstab + clear meta);  - a meta/fstab record whose file has vanished is cleared.
 *  Only ever touches our own fixed path, never a partition. Non-blocking on the shared lock (a live create/resize
 *  owns recovery), bounded, audited. Safe to call on every Disk & Storage page load. */
function smpro_swap_reconcile() {
    $path = SMPRO_SWAP_PATH;
    $meta = smpro_swap_meta_read();
    $marked = is_readable('/etc/fstab') && strpos((string)@file_get_contents('/etc/fstab'), SMPRO_SWAP_MARKER . $path) !== false;
    if (empty($meta['path']) && !$marked && !@is_file($path)) return ['ok'=>true,'action'=>'none'];   // nothing we manage

    $active = smpro_swap_active();
    if (isset($active[$path])) {                                                 // genuinely active -> just sync meta
        if (($meta['state'] ?? '') !== 'active' || empty($meta['path'])) {
            $sz = (int)round(($active[$path]['size_kb'] ?? 0) / 1024.0);
            smpro_swap_meta_write(['path'=>$path,'size_mib'=>$sz,'created'=>($meta['created'] ?? date('c')),'actor'=>($meta['actor'] ?? 'root'),'uuid'=>($meta['uuid'] ?? ''),'fstab'=>$marked,'state'=>'active']);
        }
        return ['ok'=>true,'action'=>'ok'];
    }

    // Inactive but a record/file/marker exists = a broken/half-made state. Take the shared lock NON-blocking: a live
    // create/resize (or another reconcile) legitimately owns it -> back off silently.
    $ldir = smpro_mnt_locks_dir(); $lf = @fopen($ldir . '/swap.lock', 'c');
    if (!$lf || !@flock($lf, LOCK_EX | LOCK_NB)) { if ($lf) @fclose($lf); return ['ok'=>true,'action'=>'busy']; }
    @chmod($ldir . '/swap.lock', 0600);
    $unlock = function () use ($lf) { @flock($lf, LOCK_UN); @fclose($lf); };

    if (isset((smpro_swap_active())[$path])) { $unlock(); return ['ok'=>true,'action'=>'ok']; }   // became active meanwhile

    $owned     = !empty($meta['path']) || $marked;                              // ours iff swap.json records it OR our fstab marker
    $isRegular = @is_file($path) && !@is_link($path);

    // FOREIGN inactive file at our fixed path (no meta, no marker - e.g. admin-staged or restored) -> NEVER auto-delete;
    // mirror create()'s refuse and leave it for the explicit "Remove SM Pro swap" action.
    if (!$owned) { $unlock(); return ['ok'=>true,'action'=>'orphan']; }

    // Does the on-disk file carry a real swap signature? blkid distinguishes a valid, mountable swap from a
    // half-written / truncated one, so we only ever DELETE a genuinely-broken managed file (never a valid one).
    $sig = $isRegular ? strtolower(trim((string)@shell_exec('timeout 10 blkid -p -s TYPE -o value ' . escapeshellarg($path) . ' 2>/dev/null'))) : '';
    $validSwap = ($sig === 'swap');

    $action = '';
    if ($isRegular && $validSwap && smpro_swap_bin('swapon') !== '') {          // a real swap -> relabel + restore ONCE
        if (smpro_swap_bin('getenforce') !== '') {                             // SELinux label (mirror create) so enforcing allows swapon
            $se = trim((string)@shell_exec('timeout 10 ' . smpro_swap_bin('getenforce') . ' 2>/dev/null'));
            if (strcasecmp($se, 'Enforcing') === 0 && smpro_swap_bin('chcon') !== '')
                @shell_exec('timeout 10 ' . smpro_swap_bin('chcon') . ' -t swapfile_t ' . escapeshellarg($path) . ' 2>&1');
        }
        @shell_exec('timeout 30 ' . smpro_swap_bin('swapon') . ' ' . escapeshellarg($path) . ' 2>&1');
        $a2 = smpro_swap_active();
        if (isset($a2[$path])) {
            $sz = (int)round(($a2[$path]['size_kb'] ?? 0) / 1024.0);
            smpro_swap_meta_write(['path'=>$path,'size_mib'=>$sz,'created'=>($meta['created'] ?? date('c')),'actor'=>($meta['actor'] ?? 'root'),'uuid'=>($meta['uuid'] ?? ''),'fstab'=>$marked,'state'=>'active']);
            $action = 'reactivated';
        }
    }
    if ($action === '') {
        if ($isRegular && $validSwap) {                                        // ours + a VALID swap that just would not activate now -> KEEP, don't destroy
            $m = (is_array($meta) && !empty($meta)) ? $meta : ['path'=>$path]; $m['path'] = $path; $m['state'] = 'pending';
            smpro_swap_meta_write($m);
            $action = 'kept';
        } else {                                                                // ours but MISSING or broken/invalid (half-written) -> clean, leave nothing
            if ($isRegular) @unlink($path);
            smpro_swap_fstab_remove($path);
            smpro_swap_meta_write([]);
            $action = 'cleaned';
        }
    }
    $unlock();
    if (function_exists('smpro_audit')) @smpro_audit('swap_reconcile', ['action'=>$action]);
    return ['ok'=>true,'action'=>$action];
}

/* ==================== A3 - auto-purge scheduler (smpro_mnt_*) ==================== */
/* ---------------- ADMIN config (maintenance.json) - the ONLY writer is cfg_save ---------------- */
function smpro_mnt_cfg(): array {
    // maintenance.json holds ONLY the admin schedule. The hourly sampler writes the SEPARATE
    // maintenance-state.json, so an admin Save and a cron tick can never race on the same file.
    $d = function_exists('smpro_mnt_jread') ? smpro_mnt_jread(SMPRO_MNT_CFG)
       : (is_file(SMPRO_MNT_CFG) ? json_decode((string)@file_get_contents(SMPRO_MNT_CFG), true) : null);
    if (!is_array($d)) $d = [];   // corrupt/absent JSON decodes to [] -> safe disabled defaults below
    return $d + ['enabled' => false, 'interval' => '6h', 'mode' => 'fixed', 'journald' => true];
}
function smpro_mnt_cfg_save(array $patch): array {
    $c = array_merge(smpro_mnt_cfg(), $patch);
    // STRICT enum validation - refuse junk so a bad POST/config can never reach the scheduler.
    $c['interval'] = in_array(($c['interval'] ?? ''), ['3h','6h','12h','24h'], true) ? $c['interval'] : '6h';  // else 6h
    $c['mode']     = in_array(($c['mode'] ?? ''), ['fixed','smart'], true) ? $c['mode'] : 'fixed';               // else fixed
    $c['enabled']  = !empty($c['enabled']);    // hard bool cast
    $c['journald'] = !empty($c['journald']);   // hard bool cast
    // keep ONLY the known keys - drop anything a caller merged in
    $c = ['enabled'=>$c['enabled'],'interval'=>$c['interval'],'mode'=>$c['mode'],'journald'=>$c['journald']];
    if (function_exists('smpro_mnt_jwrite')) smpro_mnt_jwrite(SMPRO_MNT_CFG, $c);   // atomic tmp+rename, 0600
    smpro_mnt_cron_sync();   // re-assert /etc/cron.d/smpro-autopurge to match the new schedule
    return $c;
}

/* ---------------- RUNTIME state (maintenance-state.json) - MERGE-on-save ---------------- */
function smpro_mnt_state(): array {
    $d = function_exists('smpro_mnt_jread') ? smpro_mnt_jread(SMPRO_MNT_STATE)
       : (is_file(SMPRO_MNT_STATE) ? json_decode((string)@file_get_contents(SMPRO_MNT_STATE), true) : null);
    return is_array($d) ? $d : [];
}
function smpro_mnt_state_save(array $patch): void {
    // MERGE-on-save (exactly like smpro_cool_state_save): the every-tick sampler write never drops
    // last_run/last_freed, and a purge write never drops the samples ring. Atomic per write (tmp+rename)
    // but NOT serialized across processes - the purge holds autopurge.run.lock while mutating state; the
    // UNLOCKED sampler may still lost-update, which is advisory-only (history) and accepted.
    $s = array_merge(smpro_mnt_state(), $patch);
    if (function_exists('smpro_mnt_jwrite')) smpro_mnt_jwrite(SMPRO_MNT_STATE, $s);
}

/* ---------------- bounded df with separateness + inode % ---------------- */
function smpro_mnt_df(string $m): array {
    // Result: ['pct','avail'(bytes),'total'(bytes),'ok','sep','ipct']. pct/ipct are null when $m is NOT a
    // distinct mount, so the caller records null (skip) rather than /'s % under the lower tmp/home thresholds.
    $r = ['pct' => null, 'avail' => 0, 'total' => 0, 'ok' => false, 'sep' => false, 'ipct' => null];
    if ($m === '') return $r;
    // SEPARATENESS: `df -Pk /tmp` resolves to the CONTAINING fs and SUCCEEDS even with no separate /tmp.
    // findmnt -no TARGET echoes the mount point ONLY when $m is itself a distinct mount (empty => not separate).
    // timeout 15 so a stale NFS / dead loopback mount cannot hang the hourly sampler.
    $tgt = trim((string)@shell_exec('timeout 15 findmnt -no TARGET ' . escapeshellarg($m) . ' 2>/dev/null'));
    $sep = ($m === '/') || ($tgt === $m);   // '/' is always a real mount even if findmnt is absent
    if (!$sep) return $r;                    // non-distinct mount -> null metric, skipped by decide()
    $r['sep'] = true;
    // space %
    foreach (explode("\n", (string)@shell_exec('timeout 15 df -Pk ' . escapeshellarg($m) . ' 2>/dev/null')) as $l) {
        $p = preg_split('/\s+/', trim($l));
        if (count($p) < 6 || $p[0] === 'Filesystem') continue;
        $used = (int)$p[2]; $avail = (int)$p[3]; $total = ($used + $avail) ?: (int)$p[1];
        $r['avail'] = $avail * 1024; $r['total'] = $total * 1024;   // kB -> bytes
        $r['pct']   = $total > 0 ? round($used / $total * 100, 1) : 0.0;
        $r['ok']    = true;
    }
    // inode % (df -iP) - a cPanel box commonly hits 100% inodes with free space; a space-only sampler is blind.
    foreach (explode("\n", (string)@shell_exec('timeout 15 df -iP ' . escapeshellarg($m) . ' 2>/dev/null')) as $l) {
        $p = preg_split('/\s+/', trim($l));
        if (count($p) < 6 || $p[0] === 'Filesystem') continue;
        $r['ipct'] = (float)rtrim((string)$p[4], '%');
    }
    return $r;
}

/* ---------------- append one datapoint to the ring buffer ---------------- */
function smpro_mnt_sample(): array {
    $tmp  = smpro_mnt_df('/tmp');
    $root = smpro_mnt_df('/');
    $home = smpro_mnt_df('/home');
    $mem  = function_exists('smpro_mnt_mem') ? smpro_mnt_mem() : [];
    $s = [
        't'    => time(),
        'tmp'  => $tmp['sep']  ? $tmp['pct']  : null,   // null when /tmp is not its own mount -> metric skipped
        'root' => $root['pct'],                          // '/' always exists
        'home' => $home['sep'] ? $home['pct'] : null,    // null when /home is not its own mount -> metric skipped
        'swap' => isset($mem['swap_used_pct']) ? (float)$mem['swap_used_pct'] : null,
        // inode signal - /home's own inode table if separate, else /'s (whichever holds user data)
        'ino'  => $home['sep'] ? $home['ipct'] : $root['ipct'],
    ];
    $st   = smpro_mnt_state();
    $rows = is_array($st['samples'] ?? null) ? $st['samples'] : [];
    $rows[] = $s;
    // prune: drop anything older than 8 days AND cap to the last 168 rows (7d hourly)
    $cut  = time() - 8 * 86400;
    $rows = array_values(array_filter($rows, fn($rw) => (int)($rw['t'] ?? 0) >= $cut));
    if (count($rows) > 168) $rows = array_slice($rows, -168);
    smpro_mnt_state_save(['samples' => $rows, 'last_sample_at' => time()]);
    return $s;
}

/* ---------------- fill velocity (%/hour) for a metric ---------------- */
function smpro_mnt_velocity(array $rows, string $key, float $windowH = 6.0): float {
    // Ignores null datapoints (non-separate mounts). Needs >=2 usable samples spanning >=30 min.
    $pts = [];
    foreach ($rows as $rw) {
        if (isset($rw[$key]) && $rw[$key] !== null && isset($rw['t'])) $pts[] = ['t' => (int)$rw['t'], 'v' => (float)$rw[$key]];
    }
    $n = count($pts);
    if ($n < 2) return 0.0;
    $now  = $pts[$n - 1];                       // newest usable sample
    $refT = $now['t'] - $windowH * 3600;
    $ref  = null;
    foreach ($pts as $p) { if ($p['t'] >= $refT) { $ref = $p; break; } }   // first sample at/after window start
    if ($ref === null) $ref = $pts[0];          // else the oldest we have
    $dt = ($now['t'] - $ref['t']) / 3600.0;
    if ($dt < 0.5) return 0.0;                   // need >=30 min span (also traps NTP-step negative dt)
    return round(($now['v'] - $ref['v']) / $dt, 3);
}

/* ---------------- THE SMART MODEL ---------------- */
function smpro_mnt_decide(array $rows): array {
    // EXACT thresholds from spec (percent). RISE is %/hour. An inode signal is included.
    $HIGH = ['tmp'=>70, 'root'=>85, 'home'=>88, 'swap'=>60, 'ino'=>85];
    $CRIT = ['tmp'=>85, 'root'=>92, 'home'=>92, 'swap'=>85, 'ino'=>95];
    $MID  = ['tmp'=>45, 'root'=>70, 'home'=>75, 'swap'=>35, 'ino'=>60];
    $RISE = ['tmp'=>5.0,'root'=>2.0,'home'=>2.0,'swap'=>5.0,'ino'=>2.0];
    $HORIZON_H = 6; $MIN_GAP_H = 3; $FLOOR_H = 24;

    $out = ['purge'=>false, 'reason'=>'stable', 'signals'=>[], 'light'=>null, 'alert'=>null];
    if (!$rows) { $out['reason'] = 'no samples yet'; return $out; }
    $cur = $rows[count($rows) - 1];   // newest sample

    $st        = smpro_mnt_state();
    $lastPurge = (int)($st['last_purge_at'] ?? 0);
    $sinceH    = $lastPurge > 0 ? (time() - $lastPurge) / 3600.0 : 999.0;   // 999 = never purged
    $lastFreed = (int)($st['last_freed'] ?? 0);

    $anyCrit = false; $anyHigh = false; $anyProj = false; $anyFast = false; $highVal = false;
    foreach (['tmp','root','home','swap','ino'] as $k) {
        // null metric (non-separate mount / unavailable) is GENUINELY skipped - never defaulted to /'s %.
        if (!isset($cur[$k]) || $cur[$k] === null) continue;
        $v   = (float)$cur[$k];
        $vel = smpro_mnt_velocity($rows, $k);
        if ($v >= $CRIT[$k])      { $anyCrit = true; $out['signals'][] = $k.':crit'; }
        elseif ($v >= $HIGH[$k])  { $anyHigh = true; $out['signals'][] = $k.':high'; }
        if ($vel >= $RISE[$k] && $v >= $MID[$k]) { $anyFast = true; $out['signals'][] = $k.':fast'; }   // rising fast
        if ($vel > 0.5 && ($v + $vel * $HORIZON_H) >= $HIGH[$k] && $v >= $MID[$k]) { $anyProj = true; $out['signals'][] = $k.':proj'; }  // projected
        if ($v >= $HIGH[$k]) $highVal = true;
    }
    $pressure = $anyHigh || $anyProj || $anyFast;

    // (1) CRITICAL watermark -> purge NOW, overrides the anti-thrash gap.
    if ($anyCrit) { $out['purge'] = true; $out['reason'] = 'critical watermark ('.implode(',', $out['signals']).')'; return $out; }
    // (2) inside MIN_GAP and something high/rising -> HOLD (back off). If a metric is high but the last run
    //     freed <50MB, the fill is real DATA not junk -> refuse to loop, raise alert to investigate.
    if ($sinceH < $MIN_GAP_H && $pressure) {
        $out['reason'] = 'holding (purged '.round($sinceH,1).'h ago, min gap '.$MIN_GAP_H.'h)';
        if ($highVal && $lastFreed < 52428800) { $out['alert'] = true; $out['reason'] .= ' — reclaim ineffective, still high'; }
        return $out;
    }
    // (3) high / projected / fast -> purge.
    if ($pressure) { $out['purge'] = true; $out['reason'] = 'pressure ('.implode(',', $out['signals']).')'; return $out; }
    // (4) daily FLOOR - guarantee one LIGHT purge/day (tmp+junk only) even when nothing is high.
    if ($sinceH >= $FLOOR_H) { $out['purge'] = true; $out['light'] = true; $out['reason'] = 'daily floor ('.round($sinceH,1).'h since last)'; return $out; }
    // (5) stable.
    return $out;
}

/* ---------------- the actual SAFE reclaim (single-flight) ---------------- */
function smpro_mnt_purge(bool $force = false, bool $light = false): array {
    // SINGLE-FLIGHT: a UI Run-now and a cron tick cannot overlap. mkdir the locks dir first - fopen('c')
    // silently fails if the dir is absent, which would defeat the guard. Lock path is DISTINCT from the
    // cron's autopurge.cron.lock so the cron's outer flock never blocks this inner flock (no child deadlock).
    $ld = function_exists('smpro_mnt_locks_dir') ? smpro_mnt_locks_dir() : SMPRO_LOCKS;
    @is_dir($ld) || @mkdir($ld, 0700, true);
    $lockPath = $ld . '/autopurge.run.lock';
    $lockFp   = @fopen($lockPath, 'c');
    if (!$lockFp || !@flock($lockFp, LOCK_EX | LOCK_NB)) { if ($lockFp) @fclose($lockFp); return ['ok'=>false,'msg'=>'A purge is already running.']; }
    @chmod($lockPath, 0600);

    $freed   = 0;                                              // bytes reclaimed - counted ONLY on a SUCCESSFUL unlink
    $actions = ['tmp'=>0, 'junk'=>0, 'journald'=>0, 'dropcaches'=>0];
    $notes   = [];

    // ---- (a) /tmp files >3d. NO -prune here, so keeping -delete is SAFE (GNU find prints each file's size at
    //         delete time). Preserve sessions/sockets/locks; exclude *cpanel*/*mysql* paths. Literal path only,
    //         single-quoted -printf format so the shell never touches %s.
    $tmpOut = (string)@shell_exec(smpro_mnt_wrap("find /tmp -maxdepth 3 -type f -atime +3 -mtime +3 -not -name 'sess_*' -not -name 'cpsess*' -not -name '*.sock' -not -name '.s.*' -not -name '*.lock' -not -ipath '*cpanel*' -not -ipath '*mysql*' -not -ipath '*mariadb*' -printf '%s\\n' -delete 2>/dev/null", 90));
    foreach (explode("\n", $tmpOut) as $l) { $l = trim($l); if ($l !== '' && ctype_digit($l)) { $freed += (int)$l; $actions['tmp'] += (int)$l; } }

    // ---- (b) server-wide junk cache >2d - TWO-PHASE PRUNE-SAFE form (NEVER -prune + -delete). Phase 1 LISTS
    //         with -prune intact (NO -delete -> -prune WORKS), NUL-delimited "size\tpath" records. Phase 2
    //         unlinks in PHP after del_file-style re-validation. Gated behind a /proc/loadavg check even in
    //         fixed mode so a melting box is not handed a heavy /home walk. NEVER pass -L to these finds.
    $la        = @sys_getloadavg();
    $cores     = (int)trim((string)@shell_exec('nproc 2>/dev/null')); if ($cores < 1) $cores = 1;
    $loadCore  = ($la && isset($la[0])) ? ((float)$la[0] / $cores) : 0.0;
    if ($loadCore >= 6.0) {
        $notes[] = 'junk walk deferred (load/core '.round($loadCore,1).')';   // cheap /tmp already ran; defer the walk
    } else {
        $ph1 = (string)@shell_exec(smpro_mnt_wrap("find /home -maxdepth 9 \\( -path '/home/backup' -o -ipath '*/mail' -o -ipath '*/.trash*' -o -ipath '*/.snapshots' -o -ipath '*/node_modules' -o -ipath '*/.git' -o -ipath '*/system/library/*' -o -ipath '*/vendor/*' -o -ipath '*/includes/*' -o -ipath '*/lib/*' -o -ipath '*/src/*' \\) -prune -o -type f -mtime +2 \\( -ipath '*/storage/cache/*' -o -ipath '*/system/storage/cache/*' -o -ipath '*/storage/framework/cache/*' -o -ipath '*/storage/framework/views/*' -o -ipath '*/bootstrap/cache/*' -o -ipath '*/wp-content/cache/*' -o -ipath '*/var/cache/*' \\) -not -name 'index.php' -not -name '.gitignore' -not -name '.htaccess' -printf '%s\\t%p\\0' 2>/dev/null", 220));
        // CIRCUIT BREAKER: a routine cache sweep touches a modest number of files. If a pattern change (or an
        // unusual layout) ever makes the walk match a huge set, that is a symptom of a mistake, not a big
        // clean-up - so refuse to delete anything at all and leave a note, rather than discover the error by
        // its damage. The incident that motivated this deleted application source across ~92 sites in one run.
        $jCand = 0; foreach (explode("\0", $ph1) as $r0) if ($r0 !== '') $jCand++;
        if ($jCand > 20000) {
            $notes[] = 'junk purge ABORTED as a safety measure: the sweep matched ' . number_format($jCand)
                     . ' files, far more than a normal cache clean-up. Nothing was deleted — review the patterns before re-enabling.';
            if (function_exists('smpro_audit')) smpro_audit('autopurge_abort', ['candidates' => $jCand]);
            $ph1 = '';
        }
        foreach (explode("\0", $ph1) as $rec) {
            if ($rec === '') continue;
            $tab = strpos($rec, "\t"); if ($tab === false) continue;
            $size = (int)substr($rec, 0, $tab);
            $path = substr($rec, $tab + 1);
            // PHP-side RE-VALIDATION: real file, not a symlink, resolves under /home, not in any excluded tree,
            // matches the cache whitelist. Only then unlink; count bytes ONLY on a successful unlink.
            if ($path === '') continue;
            $lst = @lstat($path);                                                              // symlink-safe stat of the harvested path
            if ($lst === false || ($lst['mode'] & 0170000) !== 0100000) continue;              // must be a real regular file (NOT a symlink)
            $rp = @realpath($path);
            if ($rp === false) continue;
            if (strpos($rp, '/home/') !== 0) continue;                                         // must be under /home
            if (strpos($rp, '/home/backup/') === 0) continue;                                  // never account backups
            if (preg_match('#/(mail|\.trash|\.snapshots|node_modules|\.git)(/|$)#i', $rp)) continue;  // never these trees
            // ---------------------------------------------------------------------------------------------
            // HARD SAFETY NET (added after an incident: the old whitelist was just "/cache/", which matches
            // APPLICATION SOURCE directories that happen to be named "cache" - OpenCart's system/library/cache,
            // Twig's .../Twig/Cache, PHPExcel's CachedObjectStorage. Deleting those files does not free junk,
            // it breaks the site with a fatal error.) Three independent guards, all must pass:
            //   1. the path must be a real cache-STORAGE location, not any directory merely named "cache"
            //   2. never inside a source tree (library / vendor / includes / lib / src)
            //   3. never a source-code file - cache DATA is not .php/.js/.css/.html/.twig/.tpl
            // Any one of these would have prevented the incident; together they make it impossible.
            if (!preg_match('#/(storage/cache|system/storage/cache|storage/framework/(cache|views)|bootstrap/cache|wp-content/cache|var/cache)/#i', $rp)) continue;   // ~/.cache (XDG: browser binaries, ML weights, build caches) is NOT a web cache and is never swept
            if (preg_match('#/(system/library|vendor|includes|lib|src)/#i', $rp)) continue;
            if (preg_match('#\.(php|phtml|js|css|html?|twig|tpl|inc|json|xml|ya?ml)$#i', $rp)) continue;
            //   4. never a program or a large data file: a cache sweep deletes small generated files, not binaries
            if (@filesize($rp) > 50 * 1048576) continue;
            $mh = @fopen($rp, 'rb'); if ($mh) { $magic = (string)@fread($mh, 4); @fclose($mh); if ($magic === "\x7fELF") continue; }
            // TOCTOU-SAFE DELETE: root unlink() re-resolves EVERY parent component at delete time, so the file's
            // (unprivileged) owner could swap an intermediate dir it owns for a symlink into /home/backup or /etc
            // between our validation and the unlink, redirecting root's delete outside /home. DROP PRIVILEGES to the
            // owner for the delete - a symlink into a root-owned tree is then denied by permissions (definitive fix).
            // Where pcntl/posix are unavailable, fall back to a dev/ino re-check right before unlink (narrows the race).
            $uid = (int)$lst['uid']; $gid = (int)$lst['gid'];
            if ($uid >= 100 && function_exists('pcntl_fork') && function_exists('posix_setuid')) {
                $pid = @pcntl_fork();
                if ($pid === 0) {                                                              // child: permanently drop to the owner, then delete
                    @posix_setgid($gid); @posix_setuid($uid);
                    $ls = @lstat($rp);
                    $ok = ($ls !== false && ($ls['mode'] & 0170000) === 0100000 && (int)$ls['uid'] === $uid && @unlink($rp));
                    exit($ok ? 0 : 1);
                }
                if ($pid > 0) { $s = 0; @pcntl_waitpid($pid, $s);
                    if (function_exists('pcntl_wexitstatus') && pcntl_wexitstatus($s) === 0) { $freed += $size; $actions['junk'] += $size; }
                    continue; }
                // fork failed -> fall through to the recheck fallback
            }
            $ls = @lstat($rp);                                                                 // fallback: same-inode re-check immediately before unlink
            if ($ls === false || ($ls['mode'] & 0170000) !== 0100000) continue;
            if ((int)$ls['dev'] !== (int)$lst['dev'] || (int)$ls['ino'] !== (int)$lst['ino']) continue;
            if (@unlink($rp)) { $freed += $size; $actions['junk'] += $size; }
        }
    }

    $mem = function_exists('smpro_mnt_mem') ? smpro_mnt_mem() : [];
    // ---- (c) drop_caches - ONLY when RAM is genuinely tight (<15% avail). Pure PHP, no shell. Skipped if $light.
    if (!$light) {
        $mp = isset($mem['mem_avail_pct']) ? (float)$mem['mem_avail_pct'] : 100.0;
        if ($mp < 15) {
            $before = isset($mem['mem_avail']) ? (int)$mem['mem_avail'] : 0;   // kB
            @shell_exec('sync');
            $w = @file_put_contents('/proc/sys/vm/drop_caches', "1\n");         // read-only on OpenVZ/LXC -> false, non-fatal
            if ($w !== false) {
                $after = function_exists('smpro_mnt_mem') ? (int)(smpro_mnt_mem()['mem_avail'] ?? 0) : 0;  // kB
                $actions['dropcaches'] = max(0, ($after - $before) * 1024);     // CLAMP >=0 (concurrent alloc can go negative)
            } else { $notes[] = 'drop_caches unwritable (skipped)'; }
        }
    }
    // ---- (d) journald vacuum + rotated-log trim - ONLY when /var is high (>=80%; use / if /var not separate).
    //         Skipped if $light. journald walk has no -prune, so -delete is fine there.
    if (!$light) {
        $var    = smpro_mnt_df('/var');
        $varPct = $var['sep'] ? (float)$var['pct'] : (float)(smpro_mnt_df('/')['pct'] ?? 0);
        if ($varPct >= 80) {
            if (is_file('/usr/bin/journalctl') || is_file('/bin/journalctl')) {
                @shell_exec('timeout 120 journalctl --rotate 2>/dev/null');
                @shell_exec('timeout 120 journalctl --vacuum-time=7d 2>/dev/null');
                @shell_exec('timeout 120 journalctl --vacuum-size=200M 2>/dev/null');
            }
            @shell_exec("timeout 90 nice -n 19 find /var/log -type f \\( -name '*.gz' -o -name '*.xz' -o -name '*.old' -o -name '*.1' -o -name '*.2' -o -name '*.3' -o -name '*.4' -o -name '*.5' -o -name '*.6' -o -name '*.7' \\) -mtime +14 -delete 2>/dev/null");
            $actions['journald'] = 1;   // marker - journald frees are not byte-accounted precisely
        }
    }

    // ---- persistence LAST: deletions already freed space, so on a 100%-full disk the record still lands.
    $reason = $light ? 'light (tmp+junk)' : ($force ? 'fixed/forced' : 'smart');
    $st = smpro_mnt_state();
    smpro_mnt_state_save([
        'last_run'       => time(),
        'last_purge_at'  => time(),
        'last_freed'     => $freed,
        'last_ram_freed' => $actions['dropcaches'],
        'last_actions'   => $actions,
        'last_reason'    => $reason . ($notes ? ' — '.implode('; ', $notes) : ''),
        'runs'           => (int)($st['runs'] ?? 0) + 1,
        'total_freed'    => (int)($st['total_freed'] ?? 0) + $freed,
    ]);
    if (function_exists('smpro_audit')) smpro_audit('autopurge_run', ['mode'=>$reason, 'freed'=>$freed, 'actions'=>$actions, 'light'=>$light?1:0, 'notes'=>$notes]);

    @flock($lockFp, LOCK_UN); @fclose($lockFp);   // do NOT unlink the persistent lock file (classic flock race)
    return ['ok'=>true, 'freed'=>$freed, 'actions'=>$actions, 'reason'=>$reason, 'notes'=>$notes];
}

/* ---------------- worker entry (cron / --run-now) ---------------- */
function smpro_mnt_tick(): void {
    $cfg = smpro_mnt_cfg();
    if (empty($cfg['enabled'])) return;   // double-guard even though cron is absent when disabled
    $smp = smpro_mnt_sample();            // ALWAYS sample -> keeps history warm for smart mode
    $mode = $cfg['mode'];
    $run = false; $reason = ''; $light = false; $alert = false;
    if ($mode === 'fixed') {
        // the calendar alone is not a reason to empty every site's cache: a fixed schedule runs only when some
        // filesystem is at least 40% full (the operator can keep the old behaviour with fixed_always)
        $pct = max((float)($smp['root'] ?? 0), (float)($smp['home'] ?? 0), (float)($smp['tmp'] ?? 0));
        if (!empty($cfg['fixed_always']) || $pct >= 40) { $run = true; $reason = 'fixed ' . $cfg['interval']; }
        else { $reason = 'fixed ' . $cfg['interval'] . ' skipped: no filesystem above 40% (' . (int)$pct . '%)'; if (function_exists('smpro_audit')) smpro_audit('autopurge_skipped', ['pct' => $pct]); }
    } else {
        $st = smpro_mnt_state();
        $d  = smpro_mnt_decide(is_array($st['samples'] ?? null) ? $st['samples'] : []);
        $run = !empty($d['purge']); $reason = (string)$d['reason']; $light = !empty($d['light']); $alert = !empty($d['alert']);
    }
    // DRY-RUN: monitor only - decide/record but delete NOTHING (parity with smpro_cool_guard_tick).
    if (function_exists('smpro_ctl_dry_run') && smpro_ctl_dry_run()) {
        smpro_mnt_state_save(['last_decision' => $reason . ($run ? ' (monitor-only: would purge)' : ' (monitor-only)'), 'last_run' => time()]);
        return;
    }
    if ($run) smpro_mnt_purge($mode === 'fixed', $light);   // fixed => force; smart-floor => light (tmp+junk only)
    smpro_mnt_state_save(['last_decision' => $reason]);
    // Smart 'reclaim ineffective / still rising' alert - guarded + deduped (~once / 6h) via notifier if configured.
    if ($alert) {
        $st = smpro_mnt_state();
        if (time() - (int)($st['last_alert_at'] ?? 0) >= 6 * 3600) {
            smpro_mnt_state_save(['last_alert_at' => time()]);
            if (function_exists('smpro_notify')) @smpro_notify('autopurge_alert',
                'Auto-purge: reclaim ineffective — disk still high',
                'The auto-purge scheduler ran but the disk is still high and the last run freed very little. This usually means the fill is real data (not junk). Please investigate.',
                ['reason' => $reason]);
        }
    }
}

/* ---------------- cron schedule expression / line / idempotent sync ---------------- */
function smpro_mnt_sched_expr(array $cfg): string {
    if (($cfg['mode'] ?? 'fixed') === 'smart') return '7 * * * *';   // hourly at :07 (off the top-of-hour cron herd)
    switch ($cfg['interval'] ?? '6h') {
        case '3h':  return '9 */3 * * *';
        case '12h': return '9 */12 * * *';
        case '24h': return '9 3 * * *';    // */24 is INVALID -> daily at 03:09
        case '6h':
        default:    return '9 */6 * * *';
    }
}
function smpro_mnt_cron_line(array $cfg): string {
    // IDENTICAL shape to smpro_upd_install_cron. cron `timeout 1200` > worst-case sum of per-step timeouts so
    // a slow run is not SIGKILLed mid-reclaim. flock path is DISTINCT from the worker's inner run.lock.
    $php   = smpro_php_cli_bin();
    $bin   = SMPRO_BASE . '/bin/autopurge.php';
    $ld    = function_exists('smpro_mnt_locks_dir') ? smpro_mnt_locks_dir() : SMPRO_LOCKS;
    @is_dir($ld) || @mkdir($ld, 0700, true);
    $lock  = $ld . '/autopurge.cron.lock';
    $flock = is_executable('/usr/bin/flock') ? '/usr/bin/flock' : 'flock';
    $expr  = smpro_mnt_sched_expr($cfg);
    $tag   = (($cfg['mode'] ?? 'fixed') === 'smart') ? 'smart/hourly' : ('fixed/' . ($cfg['interval'] ?? '6h'));
    return "# Safety Monitor Pro — auto-purge scheduler ($tag)\n"
         . "$expr root $flock -n $lock timeout 1200 $php $bin >/dev/null 2>&1\n";
}
function smpro_mnt_cron_sync(): void {
    // A test must never install a live cron. The shared writer refuses too, but a test that loads only
    // this file has no shared writer to refuse - function_exists() is false and the fallback writes
    // /etc/cron.d directly. The lab caught exactly that, restored the file, and went red at random.
    if (defined('SMPRO_TEST_SRC')) return;
    // Idempotent reconcile of /etc/cron.d/smpro-autopurge to the current config. Called by cfg_save AND from
    // index.php boot (self-heals after a cPanel upcp wipes /etc/cron.d - same mechanism as smpro_upd_install_cron).
    $f   = '/etc/cron.d/smpro-autopurge';
    $cfg = smpro_mnt_cfg();
    if (empty($cfg['enabled'])) { if (is_file($f)) @unlink($f); return; }   // Off -> remove the cron file entirely
    if (!is_file(SMPRO_BASE . '/bin/autopurge.php')) return;                 // worker missing -> nothing to schedule
    $desired = smpro_mnt_cron_line($cfg);
    if (is_file($f) && (string)@file_get_contents($f) === $desired) return;  // already current -> no write
    smpro_cron_install($f, $desired);   // verified write: 0644 + trailing newline, or it reports failure
}

/* ============================ auto swap-cycle scheduler ============================
 * Like the auto-purge scheduler, but for swap. A background cron checks swap usage every 5 min and, when it
 * crosses the admin's threshold AND the SAME OOM gate as the manual "Cycle swap" passes (free RAM >= 1.5x
 * swap-in-use and >=25% RAM free), it cycles swap (swapoff -a && swapon -a) to move idle pages back to RAM.
 * If the gate is not met it SKIPS - it never forces a swapoff that could OOM. Config: enabled + threshold %. */
if (!defined('SMPRO_SWAPCYCLE_CFG'))   define('SMPRO_SWAPCYCLE_CFG',   SMPRO_VARLIB . '/swapcycle.json');
if (!defined('SMPRO_SWAPCYCLE_STATE')) define('SMPRO_SWAPCYCLE_STATE', SMPRO_VARLIB . '/swapcycle_state.json');

function smpro_swapcycle_cfg() {
    $d = @is_file(SMPRO_SWAPCYCLE_CFG) ? json_decode((string)@file_get_contents(SMPRO_SWAPCYCLE_CFG), true) : null;
    if (!is_array($d)) $d = [];
    $thr = (int)($d['threshold'] ?? 80); if ($thr < 25) $thr = 25; if ($thr > 99) $thr = 99;   // clamp 25..99
    return ['enabled' => !empty($d['enabled']), 'threshold' => $thr];
}
function smpro_swapcycle_cfg_save($c) {
    $thr = (int)($c['threshold'] ?? 80); if ($thr < 25) $thr = 25; if ($thr > 99) $thr = 99;
    $out = ['enabled' => !empty($c['enabled']), 'threshold' => $thr];
    $f = SMPRO_SWAPCYCLE_CFG; $dir = dirname($f); if (!is_dir($dir)) @mkdir($dir, 0700, true);
    $t = $f . '.tmp'; if (@file_put_contents($t, json_encode($out, JSON_PRETTY_PRINT), LOCK_EX) === false) return false;
    @chmod($t, 0600); $ok = @rename($t, $f);
    if (function_exists('smpro_swapcycle_cron_sync')) smpro_swapcycle_cron_sync();
    if (function_exists('smpro_audit')) smpro_audit('swapcycle_cfg', ['enabled' => $out['enabled'] ? 1 : 0, 'threshold' => $out['threshold']]);
    return $ok;
}
function smpro_swapcycle_state() { $d = @is_file(SMPRO_SWAPCYCLE_STATE) ? json_decode((string)@file_get_contents(SMPRO_SWAPCYCLE_STATE), true) : null; return is_array($d) ? $d : []; }
function smpro_swapcycle_state_write($s) {
    $f = SMPRO_SWAPCYCLE_STATE; $dir = dirname($f); if (!is_dir($dir)) @mkdir($dir, 0700, true);
    $t = $f . '.tmp'; if (@file_put_contents($t, json_encode($s), LOCK_EX) !== false) { @chmod($t, 0600); @rename($t, $f); }
}
function smpro_swapcycle_status() {
    $cfg = smpro_swapcycle_cfg(); $mem = smpro_mnt_mem(); $st = smpro_swapcycle_state();
    return ['enabled' => $cfg['enabled'], 'threshold' => $cfg['threshold'],
            'swap_total' => (int)($mem['swap_total'] ?? 0), 'swap_used_pct' => (float)($mem['swap_used_pct'] ?? 0),
            'last_run' => (int)($st['last_run'] ?? 0), 'last_result' => (string)($st['last_result'] ?? ''),
            'before_pct' => (float)($st['before_pct'] ?? 0), 'after_pct' => (float)($st['after_pct'] ?? 0)];
}
/** Worker body - cycles swap iff enabled + over threshold + OOM-safe + not too soon. Never forces an unsafe swapoff. */
function smpro_swapcycle_run() {
    $cfg = smpro_swapcycle_cfg();
    if (empty($cfg['enabled'])) return ['ok' => false, 'skip' => 'disabled'];
    $mem = smpro_mnt_mem();
    if ((int)($mem['swap_total'] ?? 0) <= 0) return ['ok' => false, 'skip' => 'no swap configured'];
    $pct = (float)($mem['swap_used_pct'] ?? 0);
    if ($pct < $cfg['threshold']) return ['ok' => false, 'skip' => 'below threshold', 'pct' => $pct];
    $state = smpro_swapcycle_state();
    if (!empty($state['last_run']) && (time() - (int)$state['last_run']) < 600 && (($state['last_result'] ?? '') === 'cycled'))
        return ['ok' => false, 'skip' => 'cycled recently'];                         // anti-thrash: >=10 min between cycles
    // OOM safety gate - IDENTICAL to the manual "Cycle swap"; if RAM can't absorb the pages, SKIP (never OOM).
    $memAvail = (int)($mem['mem_avail'] ?? 0); $swapUsed = (int)($mem['swap_used'] ?? 0); $availPct = (float)($mem['mem_avail_pct'] ?? 0);
    if ($memAvail < $swapUsed * 1.5 || $availPct < 25) {
        smpro_swapcycle_state_write(['last_run' => time(), 'last_result' => 'skipped-unsafe', 'before_pct' => $pct, 'after_pct' => 0]);
        if (function_exists('smpro_audit')) smpro_audit('swapcycle_skip', ['reason' => 'unsafe', 'swap_pct' => $pct, 'ram_avail_pct' => $availPct]);
        return ['ok' => false, 'skip' => 'RAM cannot safely absorb the swap right now', 'pct' => $pct];
    }
    // serialize with swap_expand / swap_remove / manual cycle on the SAME lock
    $ld = function_exists('smpro_mnt_locks_dir') ? smpro_mnt_locks_dir() : (SMPRO_VARLIB . '/locks'); @is_dir($ld) || @mkdir($ld, 0700, true);
    $lf = @fopen($ld . '/swap.lock', 'c');
    if (!$lf || !@flock($lf, LOCK_EX | LOCK_NB)) { if ($lf) @fclose($lf); return ['ok' => false, 'skip' => 'swap busy']; }
    @chmod($ld . '/swap.lock', 0600);
    $swoff = smpro_swap_bin('swapoff') ?: '/usr/sbin/swapoff'; $swon = smpro_swap_bin('swapon') ?: '/usr/sbin/swapon';
    // swapoff and swapon run as ONE detached shell: if PHP is killed by the cron timeout in between (a multi-GB
    // swapoff on a slow disk takes minutes) the pair still completes, so the server is never left without swap.
    // The remembered swap set is re-added entry by entry (swapon -a restores only fstab entries).
    $before = function_exists('smpro_swap_active') ? array_keys((array)smpro_swap_active()) : [];
    $re = ''; foreach ($before as $dev) if ($dev !== '' && @file_exists($dev)) $re .= '; ' . $swon . ' ' . escapeshellarg($dev) . ' >/dev/null 2>&1';
    @shell_exec('timeout 900 sh -c ' . escapeshellarg($swoff . ' -a; ' . $swon . ' -a' . $re) . ' >/dev/null 2>&1');
    // re-assert a managed swapfile that is live-but-not-persisted (swapon -a restores only fstab entries)
    if (function_exists('smpro_swap_meta_read')) {
        $meta = smpro_swap_meta_read(); $mp = (string)($meta['path'] ?? '');
        if ($mp !== '' && ($meta['state'] ?? '') === 'active' && empty($meta['fstab'])) {
            $sact = function_exists('smpro_swap_active') ? smpro_swap_active() : [];
            if (!isset($sact[$mp]) && @file_exists($mp)) @shell_exec('timeout 30 ' . $swon . ' ' . escapeshellarg($mp) . ' 2>&1');
        }
    }
    @flock($lf, LOCK_UN); @fclose($lf);
    $mem2 = smpro_mnt_mem(); $after = (float)($mem2['swap_used_pct'] ?? 0);
    smpro_swapcycle_state_write(['last_run' => time(), 'last_result' => 'cycled', 'before_pct' => $pct, 'after_pct' => $after]);
    if (function_exists('smpro_audit')) smpro_audit('swapcycle_run', ['before_pct' => $pct, 'after_pct' => $after]);
    return ['ok' => true, 'cycled' => true, 'before_pct' => $pct, 'after_pct' => $after];
}
function smpro_swapcycle_cron_sync() {
    // A test must never install a live cron. The shared writer refuses too, but a test that loads only
    // this file has no shared writer to refuse - function_exists() is false and the fallback writes
    // /etc/cron.d directly. The lab caught exactly that, restored the file, and went red at random.
    if (defined('SMPRO_TEST_SRC')) return true;
    $f = '/etc/cron.d/smpro-swapcycle';
    $cfg = smpro_swapcycle_cfg();
    if (empty($cfg['enabled'])) { if (is_file($f)) @unlink($f); return; }
    if (!is_file(SMPRO_BASE . '/bin/swapcycle.php')) return;
    $php = smpro_php_cli_bin();
    $ld = function_exists('smpro_mnt_locks_dir') ? smpro_mnt_locks_dir() : (SMPRO_VARLIB . '/locks'); @is_dir($ld) || @mkdir($ld, 0700, true);
    $flock = is_executable('/usr/bin/flock') ? '/usr/bin/flock' : 'flock';
    $desired = "# Safety Monitor Pro — auto swap-cycle (cycle swap when usage crosses " . (int)$cfg['threshold'] . "%, only if RAM can safely absorb it)\n"
             . "*/5 * * * * root $flock -n " . $ld . "/swapcycle.cron.lock timeout 960 $php " . SMPRO_BASE . "/bin/swapcycle.php >/dev/null 2>&1\n";
    if (is_file($f) && (string)@file_get_contents($f) === $desired) return;
    smpro_cron_install($f, $desired);   // verified write: 0644 + trailing newline, or it reports failure
}

/* ---------------- ds_action bodies (called by modules/disk-storage.php POST gate) ---------------- */
function smpro_mnt_act_save(): array {
    $choice = preg_replace('/[^a-z0-9]/', '', strtolower((string)($_POST['ap_choice'] ?? '')));
    if (!in_array($choice, ['off','3h','6h','12h','24h','smart'], true)) return ['ok'=>false,'msg'=>'Invalid schedule choice.'];
    if ($choice === 'off')          $patch = ['enabled'=>false];
    elseif ($choice === 'smart')    $patch = ['enabled'=>true, 'mode'=>'smart'];
    else                            $patch = ['enabled'=>true, 'mode'=>'fixed', 'interval'=>$choice];
    $cfg = smpro_mnt_cfg_save($patch);   // validates + cron_syncs
    if (function_exists('smpro_audit')) smpro_audit('autopurge_cfg', ['choice'=>$choice, 'cfg'=>$cfg]);
    $next = !empty($cfg['enabled']) ? smpro_mnt_sched_expr($cfg) : '';
    return ['ok'=>true, 'cfg'=>$cfg, 'choice'=>$choice, 'next'=>$next, 'msg'=>($choice==='off' ? 'Auto-purge turned off.' : 'Schedule saved.')];
}
function smpro_mnt_act_preview(): array {
    // Dry-run MEASURE - the SAME predicates as the real purge, -printf only (NO -delete -> -prune works),
    // plus the SAME PHP re-validation, so the preview is faithful (never promises exclusions the run violates).
    $tmpBytes = 0; $tmpN = 0;
    $tmpOut = (string)@shell_exec(smpro_mnt_wrap("find /tmp -maxdepth 3 -type f -atime +3 -mtime +3 -not -name 'sess_*' -not -name 'cpsess*' -not -name '*.sock' -not -name '.s.*' -not -name '*.lock' -not -ipath '*cpanel*' -not -ipath '*mysql*' -not -ipath '*mariadb*' -printf '%s\\n' 2>/dev/null", 60));
    foreach (explode("\n", $tmpOut) as $l) { $l = trim($l); if ($l !== '' && ctype_digit($l)) { $tmpBytes += (int)$l; $tmpN++; } }
    $junkBytes = 0; $junkN = 0;
    $ph1 = (string)@shell_exec(smpro_mnt_wrap("find /home -maxdepth 9 \\( -path '/home/backup' -o -ipath '*/mail' -o -ipath '*/.trash*' -o -ipath '*/.snapshots' -o -ipath '*/node_modules' -o -ipath '*/.git' -o -ipath '*/system/library/*' -o -ipath '*/vendor/*' -o -ipath '*/includes/*' -o -ipath '*/lib/*' -o -ipath '*/src/*' \\) -prune -o -type f -mtime +2 \\( -ipath '*/storage/cache/*' -o -ipath '*/system/storage/cache/*' -o -ipath '*/storage/framework/cache/*' -o -ipath '*/storage/framework/views/*' -o -ipath '*/bootstrap/cache/*' -o -ipath '*/wp-content/cache/*' -o -ipath '*/var/cache/*' \\) -not -name 'index.php' -not -name '.gitignore' -not -name '.htaccess' -printf '%s\\t%p\\0' 2>/dev/null", 180));
    foreach (explode("\0", $ph1) as $rec) {
        if ($rec === '') continue;
        $tab = strpos($rec, "\t"); if ($tab === false) continue;
        $size = (int)substr($rec, 0, $tab); $path = substr($rec, $tab + 1);
        if ($path === '' || !is_file($path) || is_link($path)) continue;
        $rp = @realpath($path); if ($rp === false) continue;
        if (strpos($rp, '/home/') !== 0 || strpos($rp, '/home/backup/') === 0) continue;
        if (preg_match('#/(mail|\.trash|\.snapshots|node_modules|\.git)(/|$)#i', $rp)) continue;
        if (!preg_match('#/(cache|storage/framework|bootstrap/cache)/#i', $rp)) continue;
        $junkBytes += $size; $junkN++;
    }
    if (function_exists('smpro_audit')) smpro_audit('autopurge_preview', ['tmp_n'=>$tmpN, 'junk_n'=>$junkN, 'bytes'=>$tmpBytes+$junkBytes]);
    return ['ok'=>true, 'preview'=>1, 'bytes'=>$tmpBytes+$junkBytes, 'tmp_n'=>$tmpN, 'junk_n'=>$junkN,
            'tmp_bytes'=>$tmpBytes, 'junk_bytes'=>$junkBytes];
}
function smpro_mnt_act_run_now(): array {
    // DETACHED background run (uninstall's `(...) &` pattern) so a large /home walk cannot be reaped by the
    // cpsrvd/PHP request timeout. The worker's --run-now path re-checks ctl gates then runs ONE purge under
    // the run.lock. The card polls maintenance-state.json (last_run/last_freed) for the result.
    $php = smpro_php_cli_bin();
    $bin = SMPRO_BASE . '/bin/autopurge.php';
    if (!is_file($bin)) {
        // fallback: synchronous run if the worker file is somehow absent - but honor the SAME control gates the
        // detached worker (bin/autopurge.php) enforces, so a monitor-only / disabled box NEVER auto-deletes.
        if ((function_exists('smpro_ctl_disabled') && smpro_ctl_disabled()) || (function_exists('smpro_ctl_dry_run') && smpro_ctl_dry_run()))
            return ['ok'=>false, 'msg'=>'Auto-purge is in monitor-only / disabled mode; nothing was deleted.'];
        $r = smpro_mnt_purge(true, false);
        return empty($r['ok']) ? $r : ['ok'=>true, 'freed'=>$r['freed'], 'actions'=>$r['actions'],
            'msg'=>'Purge complete — freed ' . (function_exists('smpro_ds_humb') ? smpro_ds_humb($r['freed']) : ($r['freed'].' B')) . '.'];
    }
    @shell_exec('(' . escapeshellarg($php) . ' ' . escapeshellarg($bin) . ' --run-now >/dev/null 2>&1) &');
    if (function_exists('smpro_audit')) smpro_audit('autopurge_run_now', ['detached'=>1]);
    return ['ok'=>true, 'started'=>1, 'msg'=>'A safe purge has started in the background. This page will refresh with the result shortly.'];
}

/* ---------------- UI card (echoed by modules/disk-storage.php) ---------------- */
function smpro_mnt_card_html(): string {
    $cfg   = smpro_mnt_cfg();
    $st    = smpro_mnt_state();
    $csrf  = function_exists('smpro_csrf_generate') ? smpro_csrf_generate('ds') : '';
    $h     = fn($s) => function_exists('smpro_h') ? smpro_h($s) : htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');
    $humb  = fn($b) => function_exists('smpro_ds_humb') ? smpro_ds_humb((int)$b) : ((int)$b . ' B');

    // current choice -> selected radio
    $choice = 'off';
    if (!empty($cfg['enabled'])) $choice = ($cfg['mode'] === 'smart') ? 'smart' : (string)$cfg['interval'];
    $opts = ['off'=>'Off', '3h'=>'Every 3 hours', '6h'=>'Every 6 hours', '12h'=>'Every 12 hours', '24h'=>'Every 24 hours', 'smart'=>'Smart (adaptive)'];

    // status strip values
    $lastRun = (int)($st['last_run'] ?? 0);
    $freed   = (int)($st['last_freed'] ?? 0);
    $reason  = (string)($st['last_reason'] ?? ($st['last_decision'] ?? ''));
    $ago = function ($t) {
        $t = (int)$t; if ($t <= 0) return 'never';
        $d = time() - $t; if ($d < 60) return $d . 's ago'; if ($d < 3600) return floor($d/60) . 'm ago';
        if ($d < 86400) return floor($d/3600) . 'h ago'; return floor($d/86400) . 'd ago';
    };
    $nextTxt = '';
    if (!empty($cfg['enabled'])) $nextTxt = ($cfg['mode'] === 'smart') ? 'Smart — checked hourly' : ('every ' . $h($cfg['interval']));

    // sparkline over the last ~48 samples (tmp/root/swap %)
    $rows  = is_array($st['samples'] ?? null) ? array_slice($st['samples'], -48) : [];
    $spark = '';
    if (count($rows) >= 2) {
        $W = 320; $H = 46; $n = count($rows);
        $line = function ($key, $color) use ($rows, $n, $W, $H) {
            $pts = [];
            foreach ($rows as $i => $rw) {
                if (!isset($rw[$key]) || $rw[$key] === null) continue;
                $x = round($i / max(1, $n - 1) * $W, 1);
                $y = round($H - ((float)$rw[$key] / 100.0) * $H, 1);
                $pts[] = $x . ',' . $y;
            }
            if (count($pts) < 2) return '';
            return '<polyline fill="none" stroke="' . $color . '" stroke-width="1.5" points="' . implode(' ', $pts) . '"/>';
        };
        $spark = '<svg viewBox="0 0 ' . $W . ' ' . $H . '" width="100%" height="46" preserveAspectRatio="none" style="display:block">'
               . $line('tmp', '#c2710c') . $line('root', '#3b5bdb') . $line('swap', '#7c3aed') . '</svg>'
               . '<div class="ap-sparkleg"><span style="color:#3b5bdb">&#9632; disk /</span> <span style="color:#c2710c">&#9632; /tmp</span> <span style="color:#7c3aed">&#9632; swap</span> · last ' . count($rows) . ' hourly samples</div>';
    }

    // build radio group
    $radios = '';
    foreach ($opts as $val => $label) {
        $sel = ($val === $choice) ? ' checked' : '';
        $radios .= '<label class="ap-opt' . ($val === $choice ? ' on' : '') . '"><input type="radio" name="ap_choice" value="' . $h($val) . '"' . $sel . '> ' . $h($label) . '</label>';
    }

    ob_start(); ?>
<div class="card ap-card" style="padding:0;overflow:hidden;margin:14px 0;border-top:3px solid <?= !empty($cfg['enabled']) ? 'var(--brand)' : 'var(--line)' ?>">
  <div class="ds-head"><b>&#129529; Auto-Purge Scheduler</b><span class="meta">Automatically reclaim safe junk on a schedule</span></div>
  <div style="padding:14px 16px">
    <p class="sub" style="margin:0 0 12px">Automatically reclaim safe junk — old /tmp files, page cache, and app cache — on a schedule. <b>Mail, backups, sessions and user data are never touched.</b></p>
    <div class="ap-radios" data-csrf="<?= $h($csrf) ?>"><?= $radios ?></div>
    <p class="ap-help" id="apSmartHelp"<?= $choice === 'smart' ? '' : ' hidden' ?>>Smart mode samples /tmp, disk, inodes and swap every hour, learns the fill rate, and purges only when something is high or rising fast — otherwise it waits. The cadence is decided automatically from the logs.</p>
    <div class="ap-actions">
      <button class="tp-btn ap-save" type="button">Save schedule</button>
      <button class="tp-btn ap-run" type="button">&#128465; Run a safe purge now</button>
    </div>
    <div class="ap-status">
      <b>Last run:</b> <?= $h($ago($lastRun)) ?><?= $lastRun ? ' · freed ' . $h($humb($freed)) . ($reason !== '' ? ' · ' . $h($reason) : '') : '' ?>.
      <?php if ($nextTxt !== ''): ?><b>Next run:</b> <?= $nextTxt ?>.<?php endif; ?>
    </div>
    <?php if ($spark !== ''): ?><div class="ap-spark"><?= $spark ?></div><?php endif; ?>
    <div class="ap-result" id="apResult" hidden></div>
  </div>
</div>
<style>
.ap-card .sub{font-size:12px;color:var(--muted)}
.ap-radios{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 10px}
.ap-opt{display:inline-flex;align-items:center;gap:6px;font-size:12px;border:1px solid var(--line);border-radius:9px;padding:7px 11px;cursor:pointer}
.ap-opt.on{border-color:var(--brand);background:var(--brand-bg);font-weight:700}
.ap-help{font-size:12px;color:var(--muted);background:var(--brand-bg);border:1px solid var(--line);border-radius:9px;padding:9px 11px;margin:0 0 12px}
.ap-actions{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:0 0 12px}
.ap-actions .ap-save{background:var(--brand);color:#fff;border-color:var(--brand);font-weight:700}
.ap-status{font-size:12px;color:var(--muted);border-top:1px solid var(--line);padding-top:10px}
.ap-spark{margin-top:10px}.ap-sparkleg{font-size:11px;color:var(--muted);margin-top:3px}
.ap-result{margin-top:10px;font-size:12px;padding:10px 12px;border-radius:9px;background:var(--brand-bg);border:1px solid var(--line)}
</style>
<script>
(function(){
  var root=document.querySelector('.ap-card'); if(!root) return;
  var CSRF=(root.querySelector('.ap-radios')||{}).getAttribute?root.querySelector('.ap-radios').getAttribute('data-csrf'):'';
  var res=root.querySelector('#apResult'), help=root.querySelector('#apSmartHelp');
  function esc(s){return String(s==null?'':s).replace(/[<>&]/g,function(c){return{'<':'&lt;','>':'&gt;','&':'&amp;'}[c];});}
  function choice(){var c=root.querySelector('input[name=ap_choice]:checked');return c?c.value:'off';}
  function show(msg,cls){if(!res)return;res.hidden=false;res.innerHTML=msg;res.style.borderColor=(cls==='bad')?'var(--dang)':'var(--line)';}
  function post(params){var fd=new URLSearchParams();fd.set('smpro_csrf',CSRF);for(var k in params)fd.set(k,params[k]);
    return fetch(location.pathname+location.search,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString()}).then(function(r){return r.json();});}
  root.querySelectorAll('.ap-opt').forEach(function(o){o.addEventListener('click',function(){
    setTimeout(function(){root.querySelectorAll('.ap-opt').forEach(function(x){x.classList.toggle('on',!!x.querySelector('input:checked'));});
      if(help)help.hidden=(choice()!=='smart');},0);});});
  var saveBtn=root.querySelector('.ap-save');
  function apHumb(b){b=+b||0;var u=['B','KB','MB','GB','TB'],i=0;while(b>=1024&&i<4){b/=1024;i++;}return (i>1?b.toFixed(1):Math.round(b))+' '+u[i];}
  function apSave(ch){
    saveBtn.disabled=true;saveBtn.textContent='Saving…';
    post({ds_action:'autopurge_save',ap_choice:ch}).then(function(j){saveBtn.disabled=false;saveBtn.textContent='Save schedule';
      if(j&&j.ok){show('✓ '+esc(j.msg||'Saved.'),'ok');setTimeout(function(){location.reload();},1400);}else show(esc((j&&j.msg)||'Save failed.'),'bad');
    }).catch(function(){saveBtn.disabled=false;saveBtn.textContent='Save schedule';show('Request failed.','bad');});
  }
  if(saveBtn)saveBtn.addEventListener('click',function(){
    var ch=choice();
    if(ch==='off'){ if(confirm('Turn auto-purge OFF? No further automatic runs will happen.'))apSave(ch); return; }
    // Enabling installs a STANDING schedule that then deletes unattended - so show what it would actually
    // remove RIGHT NOW (real counts + sizes from smpro_mnt_preview) before the admin commits to it.
    saveBtn.disabled=true;saveBtn.textContent='Checking what would be deleted…';
    post({ds_action:'autopurge_preview'}).then(function(p){
      saveBtn.disabled=false;saveBtn.textContent='Save schedule';
      var det=(p&&p.ok)
        ? '\n\nIf it ran right now it would remove:\n  • '+(+p.tmp_n||0)+' old /tmp file(s) — '+apHumb(p.tmp_bytes)
          +'\n  • '+(+p.junk_n||0)+' app-cache file(s) under /home — '+apHumb(p.junk_bytes)
          +'\n  Total right now: '+apHumb(p.bytes)+'\n'
        : '\n\n(Could not preview what would be deleted.)\n';
      if(!confirm('Enable auto-purge — '+ch+'?'+det
        +'\nThis installs a recurring schedule that keeps deleting unattended until you turn it off.\n'
        +'Only safe reclaim is ever removed: old /tmp files and app cache directories older than 2–3 days.\n'
        +'Mail, backups, sessions, sockets and user data are never touched. Every run is logged.'))return;
      apSave(ch);
    }).catch(function(){ saveBtn.disabled=false;saveBtn.textContent='Save schedule';
      if(confirm('Enable auto-purge — '+ch+'?\n\n(The preview could not run.)\n\nOnly safe reclaim is removed: old /tmp files and app caches older than 2–3 days. Mail, backups, sessions and user data are never touched.'))apSave(ch);
    });
  });
  var runBtn=root.querySelector('.ap-run');
  if(runBtn)runBtn.addEventListener('click',function(){
    if(!confirm('Run a safe purge now?\n\nOnly old /tmp files, page cache and app cache (older than 2–3 days) are cleared. Mail, backups, sessions and user data are never touched.'))return;
    runBtn.disabled=true;runBtn.textContent='Working…';
    post({ds_action:'autopurge_run_now'}).then(function(j){runBtn.disabled=false;runBtn.innerHTML='🗑 Run a safe purge now';
      if(j&&j.ok){show('✓ '+esc(j.msg||'Done.'),'ok');setTimeout(function(){location.reload();},4000);}else show(esc((j&&j.msg)||'Run failed.'),'bad');
    }).catch(function(){runBtn.disabled=false;runBtn.innerHTML='🗑 Run a safe purge now';show('Request failed.','bad');});
  });
  function dh(b){b=+b||0;if(b>=1073741824)return (b/1073741824).toFixed(2)+' GB';if(b>=1048576)return (b/1048576).toFixed(1)+' MB';if(b>=1024)return (b/1024).toFixed(1)+' KB';return b+' B';}
})();
</script>
<?php
    return (string)ob_get_clean();
}

/** Auto Swap-Cycle scheduler card - mirrors the auto-purge card. Toggle + threshold(%) + status. */
function smpro_swapcycle_card_html(): string {
    $st   = smpro_swapcycle_status();
    $csrf = function_exists('smpro_csrf_generate') ? smpro_csrf_generate('ds') : '';
    $h    = fn($s) => function_exists('smpro_h') ? smpro_h($s) : htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');
    $ago  = function ($t) {
        $t = (int)$t; if ($t <= 0) return 'never';
        $d = time() - $t; if ($d < 60) return $d . 's ago'; if ($d < 3600) return floor($d/60) . 'm ago';
        if ($d < 86400) return floor($d/3600) . 'h ago'; return floor($d/86400) . 'd ago';
    };
    $on      = !empty($st['enabled']);
    $thr     = (int)$st['threshold'];
    $curPct  = (float)$st['swap_used_pct'];
    $noSwap  = ((int)$st['swap_total'] <= 0);
    $lastRun = (int)$st['last_run'];
    $lastRes = (string)$st['last_result'];
    $resLabel = ['cycled'=>'cycled swap','skipped-unsafe'=>'skipped (RAM too tight to be safe)'][$lastRes] ?? $lastRes;

    ob_start(); ?>
<div class="card sc-card" style="padding:0;overflow:hidden;margin:14px 0;border-top:3px solid <?= $on ? 'var(--brand)' : 'var(--line)' ?>" data-csrf="<?= $h($csrf) ?>">
  <div class="ds-head"><b>&#9851;&#65039; Auto Swap-Cycle</b><span class="meta">Drain swap back to RAM automatically when it fills up</span></div>
  <div style="padding:14px 16px">
    <p class="sub" style="margin:0 0 12px">When swap usage crosses your threshold, this cycles swap in the background (swapoff&nbsp;+&nbsp;swapon) to move idle pages back into RAM — the same action as the manual <b>Cycle swap</b> button, run for you on a schedule. It runs <b>only when it's safe</b>: if free RAM can't absorb the swapped pages (needs free RAM&nbsp;&ge;&nbsp;1.5&times; swap-in-use and &ge;25% RAM free) the run is <b>skipped</b>, never forced — so it can never trigger an out-of-memory kill.</p>
    <?php if ($noSwap): ?>
      <p class="sc-help">No swap is configured on this server, so there's nothing to cycle yet. You can still enable this — it will start working automatically once swap exists.</p>
    <?php endif; ?>
    <label class="sc-toggle"><input type="checkbox" id="scEnabled"<?= $on ? ' checked' : '' ?>> <span>Enable automatic swap-cycling</span></label>
    <div class="sc-thrwrap" id="scThrWrap"<?= $on ? '' : ' hidden' ?>>
      <label for="scThreshold">Start cycling when swap usage reaches</label>
      <div class="sc-range">
        <input type="range" id="scThreshold" min="25" max="99" step="1" value="<?= $thr ?>">
        <span class="sc-thrval"><b id="scThrOut"><?= $thr ?></b>%</span>
      </div>
      <div class="sc-now">Swap is currently <b><?= number_format($curPct, 1) ?>%</b> used<?= ($curPct >= $thr && !$noSwap) ? ' — <span style="color:var(--warn)">at/over the threshold</span>' : '' ?>.</div>
    </div>
    <div class="ap-actions" style="margin-top:12px">
      <button class="tp-btn sc-save" type="button">Save</button>
    </div>
    <div class="ap-status">
      <b>Checked:</b> every 5&nbsp;min while on. <b>Last action:</b> <?= $h($ago($lastRun)) ?><?= ($lastRun && $resLabel !== '') ? ' · ' . $h($resLabel) : '' ?>.
    </div>
    <div class="ap-result" id="scResult" hidden></div>
  </div>
</div>
<style>
.sc-card .sub{font-size:12px;color:var(--muted)}
.sc-help{font-size:12px;color:var(--muted);background:var(--brand-bg);border:1px solid var(--line);border-radius:9px;padding:9px 11px;margin:0 0 12px}
.sc-toggle{display:inline-flex;align-items:center;gap:8px;font-size:13px;font-weight:700;cursor:pointer;margin:0 0 4px}
.sc-toggle input{width:16px;height:16px}
.sc-thrwrap{margin:10px 0 2px;padding:12px;border:1px solid var(--line);border-radius:10px;background:var(--brand-bg)}
.sc-thrwrap>label{display:block;font-size:12px;color:var(--muted);margin-bottom:8px}
.sc-range{display:flex;align-items:center;gap:12px}
.sc-range input[type=range]{flex:1;accent-color:var(--brand)}
.sc-thrval{font-size:15px;min-width:52px;text-align:right}.sc-thrval b{font-size:18px;color:var(--brand)}
.sc-now{font-size:12px;color:var(--muted);margin-top:8px}
</style>
<script>
(function(){
  var root=document.querySelector('.sc-card'); if(!root) return;
  var CSRF=root.getAttribute('data-csrf')||'';
  var en=root.querySelector('#scEnabled'), wrap=root.querySelector('#scThrWrap'),
      rng=root.querySelector('#scThreshold'), out=root.querySelector('#scThrOut'),
      res=root.querySelector('#scResult'), saveBtn=root.querySelector('.sc-save');
  function esc(s){return String(s==null?'':s).replace(/[<>&]/g,function(c){return{'<':'&lt;','>':'&gt;','&':'&amp;'}[c];});}
  function show(msg,cls){if(!res)return;res.hidden=false;res.innerHTML=msg;res.style.borderColor=(cls==='bad')?'var(--dang)':'var(--line)';}
  if(en)en.addEventListener('change',function(){if(wrap)wrap.hidden=!en.checked;});
  if(rng&&out)rng.addEventListener('input',function(){out.textContent=rng.value;});
  function post(params){var fd=new URLSearchParams();fd.set('smpro_csrf',CSRF);for(var k in params)fd.set(k,params[k]);
    return fetch(location.pathname+location.search,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString()}).then(function(r){return r.json();});}
  if(saveBtn)saveBtn.addEventListener('click',function(){
    var enabled=en&&en.checked, thr=rng?rng.value:80;
    var body=enabled
      ? 'Enable automatic swap-cycling?\n\nEvery 5 minutes, when swap usage crosses '+thr+'%, swap will be cycled (swapoff + swapon) to move idle pages back to RAM — but only when RAM can safely absorb them (otherwise the run is skipped). Every action is logged and audited. You can turn this off any time.'
      : 'Turn automatic swap-cycling OFF? No further automatic cycling will happen.';
    if(!confirm(body))return;
    saveBtn.disabled=true;saveBtn.textContent='Saving…';
    post({ds_action:'swapcycle_save',sc_enabled:enabled?'1':'0',sc_threshold:thr}).then(function(j){
      saveBtn.disabled=false;saveBtn.textContent='Save';
      if(j&&j.ok){show('✓ '+esc(j.msg||'Saved.'),'ok');setTimeout(function(){location.reload();},1400);}else show(esc((j&&j.msg)||'Save failed.'),'bad');
    }).catch(function(){saveBtn.disabled=false;saveBtn.textContent='Save';show('Request failed.','bad');});
  });
})();
</script>
<?php
    return (string)ob_get_clean();
}