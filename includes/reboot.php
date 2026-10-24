<?php
/**
 * includes/reboot.php - Reboot readiness + scheduled reboot.
 * Bakes the manual "is this box safe to reboot?" methodology into the plugin: before a reboot (especially when the
 * next-boot kernel differs), verify the CloudLinux LVE module (kmodlve) exists for the NEXT kernel, the boot images
 * are present, RAID is healthy, /boot has room, a fallback kernel exists, the NIC driver exists for the next kernel,
 * and fstab is sane. The scheduled auto-reboot RE-RUNS this check at fire time and ABORTS if a critical item fails -
 * so it can never reboot the server into a kernel where LVE/network/boot would break. All actions are POST+CSRF+root+
 * confirm-gated in the module; the cron worker is root already.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

if (!defined('SMPRO_RB_CFG')) define('SMPRO_RB_CFG', SMPRO_VARLIB . '/reboot.json');   // {enabled,at,target,actor,created}

/* full-PATH, timeouted read helper (bare binaries like grubby/modinfo live in /usr/sbin) */
function smpro_rb_sh($cmd, $t = 8) { return smpro_run((string)$cmd, (int)$t, ['path' => true]); }
function smpro_rb_current() { return trim(smpro_rb_sh('uname -r')); }
/** The kernel GRUB will boot next (grubby default), normalized to a `uname -r`-style version. Falls back to current. */
function smpro_rb_next() {
    $g = trim(smpro_rb_sh('grubby --default-kernel 2>/dev/null'));           // e.g. /boot/vmlinuz-5.14.0-687.26.1.el9_8.x86_64
    $k = $g !== '' ? preg_replace('#^.*/vmlinuz-#', '', $g) : '';
    return $k !== '' ? $k : smpro_rb_current();
}

/**
 * KernelCare live-patch state (READ-ONLY; every external call is timeout-bounded). Returns:
 *  ['state' => 'patched'|'stale'|'absent', 'effective' => string, 'detail' => string]
 *  - 'patched': kcarectl installed AND live patches are in effect (or KernelCare confirms the booted kernel needs
 *               none) -> the running kernel gets CVE fixes in-memory; a reboot is optional, not urgent for security.
 *  - 'stale'  : kcarectl installed but NO live patches in effect and no confirmation the kernel is current ->
 *               the running kernel is NOT being protected - this is the state to alert on.
 *  - 'absent' : kcarectl not installed -> the classic kernel-gap logic applies unchanged.
 * Output shapes verified on a real CloudLinux 9.8 box (kcarectl 3.8-1.el9):
 *  `kcarectl --uname` prints the EFFECTIVE patched version WITHOUT the arch suffix (e.g. 5.14.0-687.26.1.el9_8
 *  while `uname -r` says 5.14.0-570.30.1.el9_6.x86_64); `--status` prints NOTHING on that build (do not rely on
 *  it); `--uptrack-uname` is a legacy flag (unsupported there - kept only as a fallback for old builds);
 *  `--patch-info` lists `kpatch-name:` entries when patches are applied; `--check` prints
 *  "The latest patch is applied." but exits 1 even then - match the text, never the exit code.
 */
function smpro_reboot_kernelcare() {
    $bin = '';
    foreach (['/usr/bin/kcarectl', '/usr/sbin/kcarectl', '/usr/local/bin/kcarectl', '/usr/local/sbin/kcarectl'] as $p)
        if (@is_executable($p)) { $bin = $p; break; }
    // `command` is a shell builtin - timeout(1) cannot exec it, so this lookup runs bare (it is instant, no hang risk)
    if ($bin === '') $bin = trim((string)@shell_exec('command -v kcarectl 2>/dev/null'));
    if ($bin === '' || strpos($bin, '/') !== 0)
        return ['state' => 'absent', 'effective' => '', 'detail' => 'KernelCare (kcarectl) is not installed'];
    $norm = function ($v) { return preg_replace('/\.(x86_64|aarch64|i686|ppc64le|s390x|noarch)$/', '', trim((string)$v)); };
    $eff = trim(smpro_rb_sh(escapeshellarg($bin) . ' --uname 2>/dev/null', 10));
    if (!preg_match('/^\d+\.\d+\.\d+-\S+$/', $eff)) $eff = trim(smpro_rb_sh(escapeshellarg($bin) . ' --uptrack-uname 2>/dev/null', 10));   // legacy flag on old builds only
    if (!preg_match('/^\d+\.\d+\.\d+-\S+$/', $eff)) $eff = '';
    $run = $norm(smpro_rb_current());
    if ($eff !== '' && $norm($eff) !== $run)
        return ['state' => 'patched', 'effective' => $eff,
                'detail' => 'Live patches in effect — effective kernel ' . $eff . ' (booted: ' . $run . ')'];
    // effective == booted (or unknown): see whether live patches are actually applied for the booted kernel
    $pi = smpro_rb_sh(escapeshellarg($bin) . ' --patch-info 2>/dev/null', 10);
    if (stripos($pi, 'kpatch-name') !== false)
        return ['state' => 'patched', 'effective' => ($eff !== '' ? $eff : $run),
                'detail' => 'Live patches in effect (kcarectl --patch-info lists applied kpatches)'];
    // no patches applied - ask KernelCare whether that is because none are needed (text match; exit code is unreliable)
    $chk = smpro_rb_sh(escapeshellarg($bin) . ' --check', 12);
    if (stripos($chk, 'latest patch is applied') !== false || stripos($chk, 'kernel is safe') !== false)
        return ['state' => 'patched', 'effective' => ($eff !== '' ? $eff : $run),
                'detail' => 'KernelCare is active and reports the latest patch is applied (no live patches currently needed for the booted kernel)'];
    return ['state' => 'stale', 'effective' => $eff,
            'detail' => 'kcarectl is installed but reports NO live patches in effect — the running kernel is not receiving in-memory CVE fixes (check the KernelCare license / update status)'];
}

/**
 * Pre-reboot readiness. Returns:
 *  ['ready'=>bool,'verdict'=>'ready|caution|blocked','current','next','kernel_change'=>bool,
 *   'kernelcare'=>'patched|stale|absent','kernelcare_effective'=>string,
 *   'checks'=>[{label,status(ok|warn|fail),detail}],'fail','warn']
 * 'blocked' = at least one CRITICAL check failed -> do NOT reboot (esp. LVE/boot-images/RAID/NIC for the next kernel).
 * KernelCare-aware: a pending newer kernel is only a WARNING when the running kernel is NOT live-patched - with
 * KernelCare 'patched' the gap is informational (reboot optional, not urgent for security).
 */
function smpro_reboot_readiness() {
    $cur = smpro_rb_current();
    $next = smpro_rb_next();
    $change = ($next !== '' && $next !== $cur);
    $checks = []; $fail = 0; $warn = 0;
    $add = function ($label, $status, $detail, $fix = '') use (&$checks, &$fail, &$warn) {
        $checks[] = ['label' => $label, 'status' => $status, 'detail' => $detail, 'fix' => $fix];
        if ($status === 'fail') $fail++; elseif ($status === 'warn') $warn++;
    };

    // 1) kernel change - KernelCare-aware. A pending newer kernel only warrants a "you should reboot" WARNING when
    //    the running kernel is NOT live-patched; with KernelCare active the gap is informational (seen in production:
    //    145 days uptime on an "old" kernel that was fully CVE-patched in-memory by KernelCare).
    $kc = smpro_reboot_kernelcare();
    if (!$change) {
        $add('Next-boot kernel', 'ok', 'Same kernel (' . $cur . ') — low-risk reboot');
    } elseif ($kc['state'] === 'patched') {
        $add('Next-boot kernel', 'ok',
            'Will boot a DIFFERENT kernel: ' . $next . ' (current: ' . $cur . ') — KernelCare is live-patching the running kernel (effective: ' . $kc['effective'] . '), so this reboot is OPTIONAL, not urgent for security. The checks below still matter if you do reboot.');
    } else {
        $add('Next-boot kernel', 'warn',
            'Will boot a DIFFERENT kernel: ' . $next . ' (current: ' . $cur . ') — the checks below matter');
    }
    // 1b) KernelCare live-patch state (row shown only when kcarectl is installed; 'absent' keeps the classic behavior)
    if ($kc['state'] === 'patched') {
        $add('KernelCare live patching', 'ok', $kc['detail'] . ' — CVE fixes are applied in-memory; a reboot is optional, not urgent for security');
    } elseif ($kc['state'] === 'stale') {
        $add('KernelCare live patching', 'warn', $kc['detail'] . ($change ? ' — reboot into ' . $next . ' (or repair KernelCare) to get current security fixes' : ''));
    }

    // 2) boot images present for the next kernel
    $vm = @is_file('/boot/vmlinuz-' . $next);
    $ir = (bool)(glob('/boot/initramfs-' . $next . '*.img') ?: []) || @is_file('/boot/initrd-' . $next);
    $add('Boot images (vmlinuz + initramfs)', ($vm && $ir) ? 'ok' : 'fail',
        ($vm ? 'vmlinuz present' : 'vmlinuz MISSING') . ' · ' . ($ir ? 'initramfs present' : 'initramfs MISSING'));

    // 3) CloudLinux LVE (kmodlve) for the NEXT kernel - the big one. Module name is kmodlve (NOT "lve").
    if (@is_file('/etc/cloudlinux-release')) {
        $mi = smpro_rb_sh('modinfo -k ' . escapeshellarg($next) . ' kmodlve 2>&1');
        $has = stripos($mi, 'filename:') !== false;
        if (!$has) foreach ((glob('/lib/modules/' . $next . '/weak-updates/lve-*/kmodlve.ko') ?: []) as $l) if (@file_exists($l)) { $has = true; break; }
        $add('CloudLinux LVE module (kmodlve) for next kernel', $has ? 'ok' : 'fail',
            $has ? 'Present (via kmod-lve / weak-updates) — resource limits will load after boot'
                 : 'MISSING — LVE resource limits would NOT load on the next kernel. Install/repair kmod-lve for ' . $next . ' (or pin the current kernel) before rebooting.');
    }

    // 4) software RAID health - no degraded array
    $md = @is_file('/proc/mdstat') ? (string)@file_get_contents('/proc/mdstat') : '';
    if (strpos($md, 'md') !== false && preg_match_all('/\[([U_]+)\]/', $md, $m)) {
        $deg = false; foreach ($m[1] as $s) if (strpos($s, '_') !== false) $deg = true;
        $add('Software RAID health', $deg ? 'fail' : 'ok', $deg ? 'A RAID array is DEGRADED ([_U]) — resync before rebooting' : 'All arrays healthy [UU]');
    }

    // 5) /boot free space
    $bf = trim(smpro_rb_sh("df -Pk /boot 2>/dev/null | awk 'NR==2{print 100-int(\$3/\$2*100)}'"));
    if ($bf !== '' && is_numeric($bf)) $add('/boot free space', ((int)$bf >= 10) ? 'ok' : 'warn', $bf . '% free' . ((int)$bf < 10 ? ' — low; a failed initramfs rebuild could break boot' : ''));

    // 6) fallback kernel available (so you can boot the previous one if the new one fails)
    $kcnt = (int)trim(smpro_rb_sh("grubby --info=ALL 2>/dev/null | grep -c '^kernel'"));   // NB: not $kc - that holds the KernelCare state array read at the return below
    if ($kcnt > 0) $add('Fallback kernel available', ($kcnt >= 2) ? 'ok' : 'warn', $kcnt . ' kernel(s) in the boot menu' . ($kcnt >= 2 ? ' — the previous one is available if the new kernel fails' : ' — only ONE kernel, no fallback'));

    // 7) NIC driver present for the next kernel (so the box comes back on the network)
    $dev = trim(smpro_rb_sh("ip -o route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++)if(\$i==\"dev\"){print \$(i+1);exit}}'"));
    if ($dev === '') $dev = trim(smpro_rb_sh("ls /sys/class/net 2>/dev/null | grep -v '^lo$' | head -1"));
    if ($dev !== '') {
        $drv = trim(smpro_rb_sh('readlink -f /sys/class/net/' . escapeshellarg($dev) . '/device/driver 2>/dev/null'));
        $drv = $drv !== '' ? basename($drv) : '';
        if ($drv !== '') {
            $dm = smpro_rb_sh('modinfo -k ' . escapeshellarg($next) . ' ' . escapeshellarg($drv) . ' 2>&1');
            $ok = stripos($dm, 'filename:') !== false || $drv === 'virtio_net';
            $add('Network driver for next kernel', $ok ? 'ok' : 'fail', $dev . ' → ' . $drv . ($ok ? ' (present)' : ' — MISSING for the next kernel; the server may come back with no network'));
        }
    }

    // 8) fstab sanity + the /tmp loopback fstype mismatch (a warning, not a blocker)
    $fstab = @is_file('/etc/fstab') ? (string)@file_get_contents('/etc/fstab') : '';
    $badtmp = '';
    foreach (explode("\n", $fstab) as $l) {
        $l = trim($l); if ($l === '' || $l[0] === '#') continue;
        $p = preg_split('/\s+/', $l); if (count($p) < 3) continue;
        if ($p[1] === '/tmp' && strpos($p[0], 'tmpDSK') !== false) {
            $fdecl = $p[2];
            $real = smpro_rb_sh('file -sL ' . escapeshellarg($p[0]) . ' 2>/dev/null');
            if (preg_match('/(ext[234])\s+filesystem/i', $real, $mm) && strcasecmp($mm[1], $fdecl) !== 0)
                $badtmp = 'fstab declares /tmp as ' . $fdecl . ' but the image is ' . strtolower($mm[1]) . ' (it mounts fine via the ext4 driver — cosmetic). One-click fix aligns fstab to the real type.';
        }
    }
    if ($badtmp !== '') $add('fstab / /tmp', 'warn', $badtmp, 'fstab_tmp');

    $verdict = $fail > 0 ? 'blocked' : ($warn > 0 ? 'caution' : 'ready');
    return ['ready' => $fail === 0, 'verdict' => $verdict, 'current' => $cur, 'next' => $next, 'kernel_change' => $change,
            'kernelcare' => $kc['state'], 'kernelcare_effective' => $kc['effective'],
            'checks' => $checks, 'fail' => $fail, 'warn' => $warn];
}

/** One-click fix for the fstab /tmp fstype mismatch: align the fstab type to what the /usr/tmpDSK image ACTUALLY is
 *  (the mount already works via the ext4 driver, so this is a safe, non-disruptive fstab edit - no remount needed).
 *  Backs up /etc/fstab first and verifies the write. */
function smpro_reboot_fix_fstab_tmp() {
    $fstab = '/etc/fstab';
    $c = (string)@file_get_contents($fstab); if ($c === '') return ['ok' => false, 'msg' => 'Cannot read /etc/fstab.'];
    $lines = explode("\n", $c); $from = ''; $to = ''; $idx = -1; $dev = '';
    foreach ($lines as $i => $l) {
        $t = trim($l); if ($t === '' || $t[0] === '#') continue;
        $p = preg_split('/\s+/', $t); if (count($p) < 3) continue;
        if ($p[1] === '/tmp' && strpos($p[0], 'tmpDSK') !== false) {
            $dev = $p[0]; $decl = $p[2];
            $real = ''; $fout = smpro_rb_sh('file -sL ' . escapeshellarg($dev) . ' 2>/dev/null');
            if (preg_match('/(ext[234])\s+filesystem/i', $fout, $m)) $real = strtolower($m[1]);
            if ($real === '') return ['ok' => false, 'msg' => 'Could not detect the /tmp image filesystem type — leaving fstab unchanged.'];
            if (strcasecmp($real, $decl) === 0) return ['ok' => true, 'msg' => '/tmp in fstab already matches the image (' . $decl . ') — nothing to change.'];
            $from = $decl; $to = $real; $idx = $i;
            break;
        }
    }
    if ($idx < 0) return ['ok' => false, 'msg' => 'Could not find the /tmp (tmpDSK) line in /etc/fstab.'];
    $new = preg_replace('#^(\s*\S+\s+/tmp\s+)' . preg_quote($from, '#') . '(\s)#', '${1}' . $to . '${2}', $lines[$idx], 1, $cnt);
    if (!$cnt) return ['ok' => false, 'msg' => 'Could not rewrite the /tmp line safely — leaving fstab unchanged.'];
    $bak = $fstab . '.smpro.' . date('Ymd_His'); @copy($fstab, $bak);
    $lines[$idx] = $new;
    if (@file_put_contents($fstab, implode("\n", $lines), LOCK_EX) === false) return ['ok' => false, 'msg' => 'Could not write /etc/fstab (permission denied).'];
    // verify
    $ver = (string)@file_get_contents($fstab); $ok = (bool)preg_match('#^\s*\S+\s+/tmp\s+' . preg_quote($to, '#') . '\b#m', $ver);
    if (function_exists('smpro_audit')) smpro_audit('reboot_fix_fstab_tmp', ['from' => $from, 'to' => $to, 'ok' => $ok]);
    return ['ok' => $ok, 'msg' => $ok
        ? ('Fixed — /etc/fstab now declares /tmp as ' . $to . ' (was ' . $from . '), matching the actual image. Backup: ' . basename($bak) . '. No remount needed; the warning clears and the type is correct on the next mount/boot.')
        : 'Wrote fstab but could not verify the change — please check /etc/fstab (backup: ' . basename($bak) . ').'];
}

/* ---------------- scheduled reboot ---------------- */
function smpro_reboot_sched() {
    $d = @is_file(SMPRO_RB_CFG) ? json_decode((string)@file_get_contents(SMPRO_RB_CFG), true) : null; if (!is_array($d)) $d = [];
    return ['enabled' => !empty($d['enabled']), 'at' => (int)($d['at'] ?? 0),
            'target' => (($d['target'] ?? '') === 'current') ? 'current' : 'next', 'actor' => (string)($d['actor'] ?? '')];
}
function smpro_reboot_sched_save($c) {
    $at = (int)($c['at'] ?? 0);
    // guard: at least 2 minutes out, at most 30 days out
    if (!empty($c['enabled'])) { if ($at < time() + 120) return ['ok' => false, 'msg' => 'Pick a time at least 2 minutes in the future.']; if ($at > time() + 30 * 86400) return ['ok' => false, 'msg' => 'Pick a time within the next 30 days.']; }
    $out = ['enabled' => !empty($c['enabled']), 'at' => $at, 'target' => (($c['target'] ?? '') === 'current') ? 'current' : 'next',
            'actor' => function_exists('smpro_current_actor') ? smpro_current_actor() : 'root', 'created' => time()];
    $f = SMPRO_RB_CFG; $dir = dirname($f); if (!is_dir($dir)) @mkdir($dir, 0700, true);
    $t = $f . '.tmp'; if (@file_put_contents($t, json_encode($out, JSON_PRETTY_PRINT), LOCK_EX) === false) return ['ok' => false, 'msg' => 'Could not save.'];
    @chmod($t, 0600); @rename($t, $f);
    smpro_reboot_cron_sync();
    if (function_exists('smpro_audit')) smpro_audit('reboot_schedule', ['enabled' => $out['enabled'] ? 1 : 0, 'at' => $out['at'], 'target' => $out['target']]);
    return ['ok' => true, 'msg' => $out['enabled'] ? ('Reboot scheduled for ' . date('Y-m-d H:i', $out['at']) . ' (server time). SM Pro will re-check safety at that moment and abort if anything critical fails.') : 'Scheduled reboot cancelled.'];
}
function smpro_reboot_clear() { @unlink(SMPRO_RB_CFG); smpro_reboot_cron_sync(); }
/** Write/refresh /etc/cron.d/smpro-reboot as a one-shot at the scheduled minute (or remove it). */
function smpro_reboot_cron_sync() {
    // A test must never install a live cron. The shared writer refuses too, but a test that loads only
    // this file has no shared writer to refuse - function_exists() is false and the fallback writes
    // /etc/cron.d directly. The lab caught exactly that, restored the file, and went red at random.
    if (defined('SMPRO_TEST_SRC')) return true;
    $f = '/etc/cron.d/smpro-reboot'; $s = smpro_reboot_sched();
    if (empty($s['enabled']) || $s['at'] <= 0 || $s['at'] < time() + 30) { if (@is_file($f)) @unlink($f); return; }
    if (!@is_file(SMPRO_BASE . '/bin/reboot.php')) return;
    $php = smpro_php_cli_bin();   // canonical: cron's PATH may not resolve a bare `php`
    $ld = defined('SMPRO_LOCKS') ? SMPRO_LOCKS : (SMPRO_VARLIB . '/locks'); @is_dir($ld) || @mkdir($ld, 0700, true);
    $flock = is_executable('/usr/bin/flock') ? '/usr/bin/flock' : 'flock';
    $fields = trim(smpro_rb_sh("date -d @" . (int)$s['at'] . " +'%M %H %d %m *'"));   // server-local cron fields from the epoch
    if (!preg_match('/^\d{1,2} \d{1,2} \d{1,2} \d{1,2} \*$/', $fields)) { if (@is_file($f)) @unlink($f); return; }
    $desired = "# Safety Monitor Pro — scheduled reboot (one-shot). The worker RE-VERIFIES readiness and ABORTS if unsafe.\n"
             . $fields . " root $flock -n " . $ld . "/reboot.lock " . $php . ' ' . SMPRO_BASE . "/bin/reboot.php >/dev/null 2>&1\n";
    if (@is_file($f) && (string)@file_get_contents($f) === $desired) return;
    smpro_cron_install($f, $desired);   // verified write: 0644 + trailing newline, or it reports failure
}
/** The worker body (bin/reboot.php): re-verify, pin kernel if requested, notify, then reboot. Returns nothing. */
function smpro_reboot_run() {
    $s = smpro_reboot_sched();
    if (empty($s['enabled']) || $s['at'] <= 0) return;
    // fire only in a window around the scheduled minute (cron fires at the minute; allow slack, never fire early)
    if (time() < $s['at'] - 90) return;
    if (time() > $s['at'] + 3600) { smpro_reboot_clear(); return; }   // stale (missed by >1h) -> drop it, don't surprise-reboot
    $r = smpro_reboot_readiness();
    if (($r['verdict'] ?? '') === 'blocked') {
        $bad = array_map(fn($c) => $c['label'], array_filter($r['checks'], fn($c) => $c['status'] === 'fail'));
        if (function_exists('smpro_notify')) @smpro_notify('reboot_aborted', 'Scheduled reboot ABORTED (safety check failed)',
            "SM Pro cancelled the scheduled reboot of this server because a critical pre-reboot check FAILED: " . implode('; ', $bad) . ". No reboot was performed. Fix the issue and reschedule.", ['severity' => 'critical'], true);
        if (function_exists('smpro_audit')) @smpro_audit('reboot_aborted', ['fail' => $bad]);
        smpro_reboot_clear(); return;
    }
    if ($s['target'] === 'current') @shell_exec('timeout 20 grubby --set-default /boot/vmlinuz-' . escapeshellarg(smpro_rb_current()) . ' 2>&1');   // pin known-good kernel
    $bootK = $s['target'] === 'current' ? smpro_rb_current() : ($r['next'] ?? '');
    if (function_exists('smpro_audit')) @smpro_audit('reboot_exec', ['target' => $s['target'], 'kernel' => $bootK]);
    if (function_exists('smpro_notify')) @smpro_notify('reboot_now', 'Server rebooting now (scheduled)',
        'Safety Monitor Pro is rebooting this server now, as scheduled. Boot target: ' . $s['target'] . ' (' . $bootK . '). All pre-reboot safety checks passed. It should be back in a few minutes.', ['severity' => 'warning'], true);
    smpro_reboot_clear();   // one-shot: clear schedule + cron BEFORE rebooting so it never loops
    @shell_exec('shutdown -r +1 "Scheduled reboot by Safety Monitor Pro (safety checks passed)" 2>&1');
}
