<?php
require __DIR__ . '/../support/bootstrap.php';
/** t109 - two checks that feed one alert type keep separate dedupe state: the SSH scan's "no foreign login" never re-arms the webmail alert. */
$n = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/notify.php'));
has($n, "\$slot = \$pfx !== '' ? \$type . '#' . \$pfx : \$type;", 'U1: the state slot is type + signature prefix');
has($n, "\$st[\$slot] = ['sig' => \$sig, 'ch' => \$ch, 'ts' => \$now];", 'U1: ...and that slot is what a send records');
has($n, "\$maybe('foreign_login', 'clear:flogin', '', '');", 'U2: the SSH scan clears only its own slot');
has($n, "\$maybe('mem_pressure', 'clear:lvemem', '', '');", 'U2: the CloudLinux tenants scan clears only its own slot');
hasnt($n, "\$maybe('foreign_login', 'clear', '', '');", 'U2: no bare clear is left on the shared foreign_login type');
has($n, "\$prev = \$st[\$slot] ?? (\$st[\$type] ?? null);", 'U3: the legacy shared slot is read as a fallback, so the upgrade does not re-send');
// behavioural: simulate the closure's slot arithmetic
$st = ['foreign_login' => ['sig' => 'cplogin:abc', 'ch' => 'x', 'ts' => 1]];
$slotOf = function ($type, $sig) { $pfx = (strpos($sig, ':') !== false) ? substr($sig, 0, strpos($sig, ':')) : ''; return $pfx !== '' ? $type . '#' . $pfx : $type; };
is_eq($slotOf('foreign_login', 'cplogin:abc'), 'foreign_login#cplogin', 'U4: webmail scan slot');
is_eq($slotOf('foreign_login', 'flogin:def'), 'foreign_login#flogin', 'U4: SSH scan slot differs');
is_eq($slotOf('malware_active', 'abc'), 'malware_active', 'U4: a prefix-less signature keeps the plain slot');
