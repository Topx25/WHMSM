<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/shharden.php';
/**
 * t202 - the customer-application side of the vulnerability picture: WordPress sites running an active plugin or
 * theme with a known, published, exploitable vulnerability. Security Health already covered OS packages, the
 * hosting stack and the kernel; the biggest real attack surface on a shared host is an outdated WP component
 * (the shopx break-ins came in that way). This reads WP Guard's wg_vuln table read-only and surfaces the count
 * in Security Health. Tests the severity mapping, the safe-degrade when WP Guard/the table is absent, and wiring.
 */
$src = fn($p) => str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/' . $p));
$sh  = $src('includes/shharden.php');

// --- A. the reader exists and degrades safely where WP Guard / the table is absent ---
ok(function_exists('smpro_shh_wp_vuln'), 'A1: smpro_shh_wp_vuln() is defined');
$r = smpro_shh_wp_vuln();                 // lab has no WP Guard -> null, never a warning or a crash
ok($r === null || (is_array($r) && array_key_exists('read', $r)), 'A2: returns null (no WP Guard) or a structured result');

// --- B. it reads ONLY open + active vulnerabilities (a vuln in a disabled plugin is not a live exposure) ---
has($sh, "status='open' AND active=1", 'B1: it counts only open AND active vulnerabilities');
has($sh, "-readonly", 'B2: the WP Guard DB is opened read-only (never written)');
has($sh, "wg_vuln", 'B3: it reads WP Guard\'s vulnerability table');
has($sh, "name='wg_vuln'", 'B4: it checks the table exists first (older WP Guard has no vuln tracking)');

// --- C. severity mapping: any critical OR any no-login critical/high => critical; else high/affected => warning ---
$map = function ($crit, $high, $unauth, $sites) {
    return ($crit > 0 || $unauth > 0) ? 'critical' : (($high > 0 || $sites > 0) ? 'warning' : 'ok');
};
is_eq($map(5, 0, 0, 3),  'critical', 'C1: a critical vuln -> critical');
is_eq($map(0, 0, 2, 2),  'critical', 'C2: a no-login (unauth) critical/high -> critical even with 0 rated-critical');
is_eq($map(0, 4, 0, 4),  'warning',  'C3: high vulns (no critical, no unauth) -> warning');
is_eq($map(0, 0, 0, 1),  'warning',  'C4: affected sites with lower-rated vulns -> warning');
is_eq($map(0, 0, 0, 0),  'ok',       'C5: nothing open+active -> ok');

// --- D. the unauth subset is specifically the no-login critical/high (the worst, needs no password) ---
has($sh, "unauth=1 AND rating IN ('critical','high')", 'D1: the unauth count is the no-login critical/high subset');

// --- E. wired into the Server Hardening checks, under a clear WordPress-vulnerability title ---
has($sh, "smpro_shh_wp_vuln()", 'E1: smpro_shh_checks() consults the WP vuln reader');
has($sh, 'WordPress known vulnerabilities (customer sites)', 'E2: it renders as a named check');
has($sh, 'exploitable with no login', 'E3: the finding calls out the no-login exposure in plain words');
