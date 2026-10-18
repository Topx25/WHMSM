<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/geologin.php';
/**
 * t83_gl_written_is_not_blocked.php — a line in csf.deny is a request; the lock reports what the kernel holds.
 *
 * THE INCIDENT. A production server's csf.deny held 246 lines against CSF's DENY_IP_LIMIT of 200. CSF silently
 * dropped the oldest, the address the lock had "blocked" was no longer in the file, `csf -g` found nothing in
 * iptables, and the same address signed in again 9 seconds after the block was recorded. The lock writes ~11
 * lines per address (one per port), so twenty addresses exhaust the default limit.
 */
$src = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/geologin.php'));
has($src, 'function smpro_gl_ensure_deny_limit(', 'U1: the lock raises DENY_IP_LIMIT itself');
has($src, "smpro_gl_ensure_deny_limit(); @file_put_contents(SMPRO_GL_DENY", 'U1: before every write, not after');
has($src, "if (!empty(\$c['enabled']) && !defined('SMPRO_TEST_SRC')) smpro_gl_ensure_deny_limit();", 'U1: and when the lock is armed');
has($src, 'function smpro_gl_rule_live(', 'U2: liveness is read back from the kernel (the DENYIN chain), not from the file');
has($src, "-S DENYIN", 'U2: with ONE chain read per request, not a csf -g per address (twelve seconds for ten rules)');
hasnt($src, "' -g ' . escapeshellarg(", 'U2: csf -g is not used for liveness');
has($src, "\$live = smpro_gl_rule_live(\$ip, true);", 'U2: after every block, read fresh');
has($src, "'ok' => \$live,", 'U2: and the block is only "ok" when the kernel holds it');
has($src, "geologin_block_not_live", 'U2: a written-but-not-live rule is audited as such');
has($src, "but NOT live in the firewall", 'U2: and said in words');
$page = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/firewall-status.php'));
has($page, 'smpro_gl_active_live()', 'U3: the page checks every listed rule against the kernel');
has($page, 'NOT live', 'U3: and shows the ones CSF dropped');
has($page, 'DENY_IP_LIMIT is', 'U3: and warns when csf.deny is at the limit');
ok(strpos($src, "'DENY_IP_LIMIT = \"' . \$want . '\"'") !== false, 'U4: the rewrite keeps CSF\'s own quoting');
