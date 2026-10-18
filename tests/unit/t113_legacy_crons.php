<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
require_once SMPRO_BASE . '/includes/update.php';
/** t113 - the predecessor product's per-minute crons are retired (moved, never deleted) so they cannot re-lock what SM Pro unprotected. */
ok(function_exists('smpro_upd_retire_legacy_crons'), 'U1: retire helper exists');
$src = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/update.php'));
has($src, "['safetylock_relock', 'safety_monitor_php_harden_relock', 'safety_monitor_php_harden_public_sync']", 'U2: exactly the three predecessor cron names');
has($src, "@rename(\$f, \$dest . '/' . \$name . '.' . date('Ymd_His'))", 'U2: moved with a timestamp, not deleted');
hasnt($src, "unlink(\$f)", 'U2: nothing is unlinked');
has($src, "smpro_audit('legacy_cron_retired'", 'U3: audited');
is_eq(smpro_upd_retire_legacy_crons(), [], 'U4: nothing to retire in the lab (no such files), returns an empty list');
$nc = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/bin/notify_check.php'));
has($nc, "smpro_upd_retire_legacy_crons();", 'U5: the worker runs it (hourly-throttled)');
