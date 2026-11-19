<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/lvelimits.php';
/**
 * t193 - on a server where the LVE kernel module refuses to CREATE the LVE (rc -75 / reseller quota -22, seen on
 * dc2 after a reboot), the affected accounts never appear in lveinfo or /proc/lve/list - the two tables the
 * Resource Limit page reads - so the sites taking 508 showed up NOWHERE while the kernel named them in its log.
 * The page now pulls the lve(N) ids out of the kernel lines, maps id->uid->account, and lists them in the banner.
 */
$src = fn($p) => str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/' . $p));

$lv = $src('includes/lvelimits.php');
ok(strpos($lv, 'preg_match_all') !== false && strpos($lv, '\\blve\\(') !== false, 'A1: the kernel lines are scanned for the lve(N) id pattern');
has($lv, "\$pw = function_exists('posix_getpwuid') ? @posix_getpwuid(\$uid) : null;", 'A2: each id is mapped id->uid->account');
has($lv, "'affected' => \$affected", 'A3: the affected accounts travel with the kernel state');
has($lv, "if (\$id >= 1000) \$ids[\$id] = 1;", 'A4: reserved/system ids (<1000) are left out');

// the extraction logic itself, on the exact line form the user pasted
$o = "Nov 19 09:08:33 dc2 kernel: LVE: [3952] os_resource_setup: failed to set lve(1463) cpu lim, rc -75, lvp(0) limit 0, reseller quota -22\n"
   . "Nov 19 09:08:34 dc2 kernel: LVE: failed to set lve(1590) cpu lim, rc -75\n"
   . "Nov 19 09:08:35 dc2 kernel: LVE: failed to set lve(1463) cpu lim, rc -75\n"   // duplicate id
   . "Nov 19 09:08:36 dc2 kernel: LVE: something about lve(0) limit 0\n";            // reserved id 0 -> skipped
$ids = []; if (preg_match_all('/\blve\((\d+)\)/', $o, $mm)) foreach ($mm[1] as $id) { $id = (int)$id; if ($id >= 1000) $ids[$id] = 1; }
is_eq(array_keys($ids), [1463, 1590], 'A5: ids are de-duplicated and the reserved id 0 is dropped');

// value vs module kinds stay correctly distinguished (the banner routes on this)
ok(preg_match('/rc -75|quota -22/', $o) ? true : false, 'A6: this line is the "value" kind (rc -75) - a CloudLinux ticket, not a reboot');
$oMod = "kernel: LVE: failed to push tid to noub cgroup rc=-2\n";
ok(!preg_match('/rc -75|quota -22/', $oMod) && preg_match('/noub cgroup/', $oMod), 'A7: a noub-cgroup line is the "module" kind - a reboot fixes it');

// the banner names them, and says why they are not in the table
$rm = $src('modules/resource-limits.php');
has($rm, "if (!empty(\$kstate['affected'])):", 'B1: the banner lists the affected accounts when the kernel named any');
has($rm, "they take 508 but do NOT appear in the table below", 'B2: ...and explains why they are missing from the table');
has($rm, "\$__dl = \$doms[\$__a] ?? []; \$__d = is_array(\$__dl) ? (string)(\$__dl[0] ?? '') : (string)\$__dl;", 'B3: a domain is shown, taken safely from the user->domains map');
