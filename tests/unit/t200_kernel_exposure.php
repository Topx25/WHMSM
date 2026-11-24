<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/shharden.php';
require_once SMPRO_BASE . '/includes/sechealth.php';
/**
 * t200 - Security Health plan step 4: is the RUNNING kernel exposed to a known, already-fixed flaw? The common
 * real case is a patched kernel installed by an update but never booted - the fix is on disk, doing nothing,
 * while uname looks "old". The trap a naive check falls into: a LIVE-PATCHING kernel (KernelCare/kpatch) fixes
 * the running kernel in memory with no reboot, so an "old" uname is actually fully patched; comparing uname to
 * the newest installed RPM there would raise a false "reboot needed". This test proves the check returns a
 * structured verdict, degrades safely, and that the live-patch-aware logic is present in the source.
 */
$src = fn($p) => str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/' . $p));
$sh  = $src('includes/sechealth.php');

// --- A. the check exists and returns a structured, bounded verdict ---
ok(function_exists('smpro_sh_kernel_exposure'), 'A1: smpro_sh_kernel_exposure() is defined');
$kx = smpro_sh_kernel_exposure();
ok(is_array($kx) && isset($kx['state']), 'A2: it returns a structured result with a state');
ok(in_array($kx['state'], ['ok', 'warning', 'unknown'], true), 'A3: the state is one of the defined values (' . $kx['state'] . ')');
ok(array_key_exists('running', $kx), 'A4: it always reports the running kernel it looked at');

// --- B. live-patch awareness is in the logic (the thing that prevents the false "reboot needed") ---
has($sh, 'kcarectl', 'B1: it consults KernelCare before comparing versions');
has($sh, 'patch is applied', 'B2: it treats an applied live patch as fixed-in-memory');
has($sh, 'No newer patch is available', 'B3: ...and only clears when no newer live patch exists');
has($sh, 'needs-restarting', 'B4: it uses needs-restarting -r as the authoritative reboot signal where present');

// --- C. the running-vs-installed comparison is the core non-live-patch case ---
has($sh, "rpm -q kernel", 'C1: without live patching it compares the running kernel to the newest installed');
has($sh, 'installed but NOT in effect until a reboot', 'C2: and names the real risk — an installed fix not yet running');

// --- D. wired into the page scan under Security updates, with a warning-only reboot fix ---
has($sh, "smpro_sh_kernel_exposure()", 'D1: smpro_sh_all() runs the kernel check');
has($sh, 'Running kernel up to date', 'D2: it renders as a named check');
has($sh, "!== 'unknown'", 'D3: an unknown verdict emits nothing rather than a misleading finding');
