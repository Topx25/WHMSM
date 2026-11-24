<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
/**
 * t196 - the multi-service auth-log scanner (SSH / mail / FTP / cPanel-WHM-webmail) used to be hand-copied in two
 * places - smpro_ip_auth_attempts() in intrusion.php and smpro_aa_ip_auth() in account-audit.php - and the copies
 * had DRIFTED: account-audit knew the cPanel access_log, the "A=(dovecot|courier)" / "session opened" /
 * "access denied" / "LOGIN\b" phrasings and an extra FTP username pattern; intrusion did not. The same log line
 * could therefore be classified differently depending on which page or cron asked. Both now read ONE engine,
 * smpro_auth_log_scan() in helpers.php, so classification can no longer disagree. This test proves the single
 * source exists and carries the UNION of the former patterns, that both callers delegate to it (no second copy
 * of the parse loop survives), and that the engine's contract holds.
 */
$src = fn($p) => str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/' . $p));
$hp  = $src('includes/helpers.php');
$intr = $src('includes/intrusion.php');
$aa   = $src('modules/account-audit.php');

// --- A. the shared engine exists and is the single source ---
ok(function_exists('smpro_auth_log_scan'), 'A1: smpro_auth_log_scan() is defined (the one shared engine)');
has($hp, 'function smpro_auth_log_scan(', 'A2: it lives in helpers.php');

// --- B. the engine carries the UNION of both former copies' patterns (the drift is gone) ---
has($hp, 'A=(dovecot|courier)',            'B1: mail classification keeps account-audit\'s dovecot/courier phrasing');
has($hp, 'session opened',                 'B2: success regex keeps "session opened"');
has($hp, 'access denied',                  'B3: failed regex keeps "access denied"');
has($hp, 'LOGIN\\b',                       'B4: cPanel/webmail classification keeps the "LOGIN" token');
has($hp, 'Authentication failed for user', 'B5: FTP username extraction keeps account-audit\'s extra pattern');
has($hp, 'access_log',                     'B6: the optional cPanel access_log source is supported');
has($hp, 'with_access_log',                'B7: ...and is opt-in (account-audit uses it, intrusion does not)');

// --- C. both callers are now thin wrappers over the engine (no surviving second parse loop) ---
has($intr, 'smpro_auth_log_scan(', 'C1: intrusion.php smpro_ip_auth_attempts delegates to the engine');
has($aa,   'smpro_auth_log_scan(', 'C2: account-audit.php smpro_aa_ip_auth delegates to the engine');
// the old hand-copied "tail -n 250000 ... | grep -aF" shell line must exist in ONE place only (the engine)
is_eq(substr_count($hp,   'tail -n 250000'), 1, 'C3: the tail/grep command is in the engine once');
is_eq(substr_count($intr, 'tail -n 250000'), 0, 'C4: intrusion.php no longer carries its own copy');
is_eq(substr_count($aa,   'tail -n 250000'), 0, 'C5: account-audit.php no longer carries its own copy');

// --- D. engine contract: bad input is safe, and a row carries both the canonical key and the display label ---
is_eq(smpro_auth_log_scan('not-an-ip'), [], 'D1: a non-IP returns an empty list, never a warning');
is_eq(smpro_auth_log_scan('203.0.113.200'), [], 'D2: an IP with no log activity returns an empty list');
// the two callers read different fields off a row, so the engine must expose BOTH the lowercase key and the label
has($hp, "'svc' =>",       'D3: the engine row exposes the canonical lowercase service key (account-audit reads it)');
has($hp, "'svc_label' =>", 'D4: ...and the display label (intrusion\'s flat list reads it)');

// --- E. the flat-list wrapper still returns the shape its 3 callers expect (ts/source/result/user/detail) ---
has($intr, "'source' => \$r['svc_label']", 'E1: smpro_ip_auth_attempts maps svc_label -> source (unchanged contract)');
has($intr, "'detail' => ''",               'E2: ...and keeps the detail field its callers read');
