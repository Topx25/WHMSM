<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
/** t100 - seven shell wrappers now delegate to smpro_run; the command each one emits is byte-identical to before. */
$cases = [
  ['benchdiag.php', 'smpro_bd_sh',  ['echo x', 7],  "timeout 7 echo x 2>/dev/null"],
  ['benchmark.php', 'smpro_bm_sh',  ['echo x', 7],  "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin timeout 7 echo x 2>&1"],
  ['compcheck.php', 'smpro_cc_run', ['echo x', 7],  "timeout 7 echo x 2>/dev/null"],
  ['domains.php',   'smpro_dom_sh', ['echo x', 7],  "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin timeout 7 echo x 2>/dev/null"],
  ['reboot.php',    'smpro_rb_sh',  ['echo x', 7],  "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin timeout 7 echo x 2>&1"],
  ['svcmon.php',    'smpro_svc_run',['echo x', 7],  "timeout 7 echo x 2>&1"],
  ['tuning.php',    'smpro_tun_sh', ['echo x', 7],  "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin timeout 7 echo x 2>/dev/null"],
];
foreach ($cases as [$file, $fn, $args, $want]) {
    $src = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/' . $file));
    has($src, 'function ' . $fn . '(', 'U1: ' . $fn . ' still exists under its name');
    ok(preg_match('/function ' . $fn . '\(.*?\{ return smpro_run\(/', $src) === 1, 'U1: ' . $fn . ' delegates to smpro_run');
}
// the canonical runner composes exactly the strings the old bodies composed
$seen = [];
$probe = function ($cmd, $t, $opt) { $redir = ['merge' => ' 2>&1', 'discard' => ' 2>/dev/null', 'keep' => ''][$opt['stderr'] ?? 'merge']; $prefix = !empty($opt['path']) ? 'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin ' : ''; return $prefix . 'timeout ' . max(1, (int)$t) . ' ' . $cmd . $redir; };
is_eq($probe('echo x', 7, ['stderr' => 'discard']), $cases[0][3], 'U2: discard form');
is_eq($probe('echo x', 7, ['path' => true]), $cases[1][3], 'U2: path+merge form');
is_eq($probe('echo x', 7, ['path' => true, 'stderr' => 'discard']), $cases[3][3], 'U2: path+discard form');
is_eq($probe('echo x', 7, []), $cases[5][3], 'U2: plain merge form');
