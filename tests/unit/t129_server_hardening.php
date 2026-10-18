<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
if (!defined('SMPRO_VARLIB')) define('SMPRO_VARLIB', sys_get_temp_dir() . '/t129_varlib_' . getmypid());
require_once SMPRO_BASE . '/includes/shharden.php';
/** t129 - Security Health server hardening: each fix is offered only when weaker than the target, records how to
 *  put itself back, and Undo restores the exact previous state. Nothing about the host is assumed. */
$src = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/shharden.php'));
has($src, "smpro_sh_sshd_effective('Port')", 'U1: the SSH port for CSF limits comes from the running sshd');
hasnt($src, "'22;tcp", 'U1: no fixed SSH port in the CSF limits');
has($src, "if (\$c !== null && \$c !== \$v)", 'U2: a kernel key the running kernel lacks is never offered');
has($src, "if (trim(\$cur) !== '') continue; }   // keep an operator's own limits", "U3: an operator's own CONNLIMIT/PORTFLOOD is kept");
has($src, "LFD did not come back — csf.conf put back", 'U4: a CSF change that stops LFD is put back by itself');
has($src, "if (\$k === 'maxemailsperhour' && \$cur !== '' && (int)\$cur > 0 && (int)\$cur <= (int)\$v) continue;", 'U5: a stricter mail cap is never loosened');
$mod = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/security-health.php'));
has($mod, "empty(\$spec[\$c['fix']]['danger']) && \$c['fix'] !== 'ssh_rootlogin'", 'U6: Apply all never includes lock-out or database-restart fixes');
has($mod, "@ignore_user_abort(true)", 'U7: a started fix finishes even if the page is closed');
has($mod, "smpro_require_root();", 'U8: root only');

// journal round trip with a file op (no system change)
$f = sys_get_temp_dir() . '/t129_target_' . getmypid(); file_put_contents($f, "old\n");
$b = smpro_shh_keep($f); file_put_contents($f, "new\n");
smpro_shh_journal_add('t129', [['file', $f, $b]], 'test');
is_eq(isset(smpro_shh_undoable()['t129']), true, 'J1: the change is listed as undoable');
$r = smpro_shh_undo('t129');
is_eq([$r[0], file_get_contents($f)], [true, "old\n"], 'J2: Undo puts back the exact previous file');
is_eq(isset(smpro_shh_undoable()['t129']), false, 'J3: an undone change is not offered again');
is_eq(smpro_shh_undo('t129')[0], false, 'J4: a second Undo reports nothing to undo');
@unlink($f);

// live round trip of the kernel settings, only where the test runs as root on Linux
if (function_exists('posix_geteuid') && posix_geteuid() === 0 && is_dir('/proc/sys/kernel')) {
    $before = []; foreach (array_keys(smpro_shh_sysctl_want()) as $k) $before[$k] = smpro_shh_sysctl_get($k);
    $conf = '/etc/sysctl.d/90-smpro-harden.conf'; $hadConf = is_file($conf) ? file_get_contents($conf) : null;
    [$ok, $msg] = smpro_shh_apply('kernel_harden');
    is_eq([$ok, smpro_shh_sysctl_gaps()], [true, []], 'L1: after Apply no kernel setting is weaker than wanted');
    smpro_shh_undo('kernel_harden');
    $after = []; foreach (array_keys(smpro_shh_sysctl_want()) as $k) $after[$k] = smpro_shh_sysctl_get($k);
    is_eq($after, $before, 'L2: Undo puts every kernel value back exactly');
    is_eq(is_file($conf) ? file_get_contents($conf) : null, $hadConf, 'L3: Undo puts the sysctl.d file back as it was');
    $o0 = smpro_shh_shm_opts();
    if ($o0 !== '') {
        smpro_shh_apply('shm_noexec');
        is_eq(strpos(',' . smpro_shh_shm_opts() . ',', ',noexec,') !== false, true, 'L4: /dev/shm is noexec after Apply');
        smpro_shh_undo('shm_noexec');
        is_eq(strpos(',' . smpro_shh_shm_opts() . ',', ',noexec,') !== false, strpos(",$o0,", ',noexec,') !== false, 'L5: Undo brings /dev/shm back to how it was');
    }
}
hasnt(str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/shharden.php')), "'cookieipvalidation' =>", 'U9: cPanel sessions are never bound to the IP (a front proxy flips it and logs everyone out)');
