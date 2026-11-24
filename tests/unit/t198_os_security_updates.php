<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/shharden.php';
require_once SMPRO_BASE . '/includes/sechealth.php';
/**
 * t198 - Security Health gained a real "known-vulnerable packages installed now" check: pending OS security
 * updates read from the distribution's OWN advisory data (dnf/yum updateinfo list --security). Before this, the
 * section only reported service VERSIONS as info and never said whether a version carried a published vulnerability
 * with a vendor fix waiting. This tests the pure parser (smpro_sh_parse_updateinfo) against real vendor output -
 * severity ranking, advisory/package/CVE counting, dedup of an advisory across package rows, and header noise.
 */

// --- A. a realistic AlmaLinux/CloudLinux `updateinfo list --security` with CVE ids ---
$fixture = <<<TXT
Last metadata expiration check: 0:05:00 ago on Tue 24 Nov 2026.
ALSA-2026:1001 Important/Sec. openssl-1:3.0.7-28.el9_4.x86_64 CVE-2026-1111
ALSA-2026:1001 Important/Sec. openssl-libs-1:3.0.7-28.el9_4.x86_64 CVE-2026-1111
ALSA-2026:1002 Critical/Sec.  kernel-5.14.0-427.el9.x86_64 CVE-2026-2222 CVE-2026-2223
ALSA-2026:1003 Moderate/Sec.  curl-7.76.1-29.el9.x86_64 CVE-2026-3333
ALSA-2026:1004 Low/Sec.       vim-minimal-8.2.el9.x86_64
TXT;
$r = smpro_sh_parse_updateinfo($fixture);
is_eq($r['advisories'], 4, 'A1: four distinct advisories (the openssl one counted once across its 2 package rows)');
is_eq($r['packages'], 5, 'A2: five affected package rows');
is_eq($r['worst'], 'critical', 'A3: worst severity is Critical (the kernel advisory)');
is_eq($r['cves'], 4, 'A4: four distinct CVE ids across the advisories');
ok(in_array('ALSA-2026:1002', $r['sample'], true), 'A5: the critical advisory id is in the sample list');

// --- B. empty input (a clean, fully-patched server) -> nothing flagged ---
$e = smpro_sh_parse_updateinfo("Last metadata expiration check: 0:02:00 ago.\n");
is_eq($e['advisories'], 0, 'B1: a clean server yields zero advisories');
is_eq($e['worst'], 'none', 'B2: ...and no severity');
is_eq($e['cves'], 0, 'B3: ...and no CVEs');

// --- C. header/noise lines never count as advisories ---
$n = smpro_sh_parse_updateinfo("Updating Subscription Management repositories.\nsome random prose line\n");
is_eq($n['advisories'], 0, 'C1: non-advisory lines are ignored (no stray advisory from prose)');

// --- D. severity ranking picks the single worst across a mixed list ---
$mix = smpro_sh_parse_updateinfo("RLSA-2026:9 Moderate/Sec. a-1.x86_64\nRLSA-2026:8 Important/Sec. b-1.x86_64\n");
is_eq($mix['worst'], 'important', 'D1: Important outranks Moderate');

// --- E. the live wrapper exists and degrades safely where no package manager is present ---
ok(function_exists('smpro_sh_os_security'), 'E1: smpro_sh_os_security() is defined');
// on the lab/runner (no dnf/yum on PATH, or stubbed) it must return a structured state, never warn/crash
$live = smpro_sh_os_security();
ok(is_array($live) && isset($live['state']) && in_array($live['state'], ['has_updates','clean','no_metadata','unavailable'], true),
   'E2: the live check returns one of the four defined states');

// --- F. the check is wired into the page scan under its own category ---
$src = fn($p) => str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/' . $p));
$sh  = $src('includes/sechealth.php');
has($sh, "\$C['Security updates']", 'F1: smpro_sh_all() emits a "Security updates" category');
has($sh, 'update --security', 'F2: the one-click fix applies ONLY security updates');
has($sh, "'no_metadata'", 'F3: the advisory-less state is handled distinctly (no false all-clear)');
