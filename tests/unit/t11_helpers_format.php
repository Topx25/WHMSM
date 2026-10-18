<?php
/**
 * t11_helpers_format.php — pure formatter/classifier helpers in includes/helpers.php.
 *
 * Targets (all deterministic, value-in/value-out — no network, no shell, no I/O):
 *   - smpro_load_cls   (U55): ABSOLUTE 1-min load bands, exact ==/> boundaries
 *   - smpro_bytes      : human-readable bytes, unit ladder B..PB + PB cap
 *   - smpro_dur        : human-readable duration (Xd Yh Zm) from whole seconds
 *
 * Expected values were derived by READING the source and confirmed against ea-php82
 * directly (see the function bodies at helpers.php:56-62, 136-141, 144-149).
 *
 * NOTE: the prompt also named smpro_net_human / smpro_lo_human / smpro_lo_dur — none of
 * those exist in helpers.php (verified by enumerating every function in the file); they are
 * not tested here and are listed in 'skipped'.
 */
require __DIR__ . '/../support/bootstrap.php';
require SMPRO_BASE . '/includes/helpers.php';

/* ----------------------------------------------------------------------
 * smpro_load_cls($v) — ABSOLUTE 1-min load bands (admin spec, NOT pressure):
 *   $v = (float)$v;
 *   $v > 30  -> 'danger'
 *   $v > 25  -> 'warn'
 *   $v > 10  -> 'elev'
 *   else     -> 'good'
 * The comparisons are STRICTLY '>', so each threshold value itself falls into the
 * LOWER band. This boundary behaviour is the security/correctness-relevant part:
 * a load of exactly 30 is 'warn' (NOT 'danger'), exactly 25 is 'elev', exactly 10 is 'good'.
 * -------------------------------------------------------------------- */

// --- good band: <= 10 ---
is_eq(smpro_load_cls(0),    'good', 'load_cls(0) = good (idle)');
is_eq(smpro_load_cls(8),    'good', 'load_cls(8) = good');
is_eq(smpro_load_cls(10),   'good', 'load_cls(10) = good (==10 boundary stays good, not >10)');

// --- elev band: >10 .. <=25 ---
is_eq(smpro_load_cls(10.01),'elev', 'load_cls(10.01) = elev (just over the 10 boundary)');
is_eq(smpro_load_cls(12.5), 'elev', 'load_cls(12.5) = elev');
is_eq(smpro_load_cls(25),   'elev', 'load_cls(25) = elev (==25 boundary stays elev, not >25)');

// --- warn band: >25 .. <=30 ---
is_eq(smpro_load_cls(25.01),'warn', 'load_cls(25.01) = warn (just over the 25 boundary)');
is_eq(smpro_load_cls(30),   'warn', 'load_cls(30) = warn (==30 boundary stays warn, not >30)');

// --- danger band: >30 ---
is_eq(smpro_load_cls(30.01),'danger', 'load_cls(30.01) = danger (just over the 30 boundary)');
is_eq(smpro_load_cls(100),  'danger', 'load_cls(100) = danger (heavy load)');

// --- input coercion: (float) cast ---
is_eq(smpro_load_cls('31'),  'danger', "load_cls('31') string coerced to float -> danger");
is_eq(smpro_load_cls('8'),   'good',   "load_cls('8') string coerced to float -> good");
is_eq(smpro_load_cls(-5),    'good',   'load_cls(-5) negative -> good (defensive default)');
is_eq(smpro_load_cls(0.0),   'good',   'load_cls(0.0) float zero -> good');

// return type is always a string from the fixed set
ok(in_array(smpro_load_cls(12), ['good','elev','warn','danger'], true), 'load_cls returns a known band string');

/* ----------------------------------------------------------------------
 * smpro_bytes($b) — human-readable bytes.
 *   units = [B,KB,MB,GB,TB,PB]; while ($b>=1024 && $i<5){ $b/=1024; $i++; }
 *   round($b, $i?2:0) . ' ' . unit
 * B is rounded to 0 decimals; every higher unit to 2. The unit ladder caps at PB
 * (i never exceeds 5), so values beyond 1 PB render as "<n> PB".
 * -------------------------------------------------------------------- */

is_eq(smpro_bytes(0),        '0 B',    'bytes(0) = 0 B');
is_eq(smpro_bytes(512),      '512 B',  'bytes(512) = 512 B (no decimals for B)');
is_eq(smpro_bytes(1023),     '1023 B', 'bytes(1023) = 1023 B (just under the KB step)');
is_eq(smpro_bytes(1024),     '1 KB',   'bytes(1024) = 1 KB (==1024 promotes to KB)');
is_eq(smpro_bytes(1536),     '1.5 KB', 'bytes(1536) = 1.5 KB (2-decimal rounding)');
is_eq(smpro_bytes(1048576),  '1 MB',   'bytes(1024^2) = 1 MB');
is_eq(smpro_bytes(1073741824),'1 GB',  'bytes(1024^3) = 1 GB');
is_eq(smpro_bytes(1099511627776), '1 TB', 'bytes(1024^4) = 1 TB');
is_eq(smpro_bytes(1125899906842624), '1 PB', 'bytes(1024^5) = 1 PB (top of the ladder)');
// PB cap: beyond 1 PB the unit stays PB and the number keeps growing
is_eq(smpro_bytes(1152921504606846976), '1024 PB', 'bytes(1024^6) = 1024 PB (caps at PB, never EB)');

// rounding to 2 decimals at KB
is_eq(smpro_bytes(1126), '1.1 KB', 'bytes(1126) = 1.1 KB (1126/1024=1.099.. rounds to 1.1)');
// (float) coercion of a numeric string
is_eq(smpro_bytes('2048'), '2 KB', "bytes('2048') string coerced -> 2 KB");

/* ----------------------------------------------------------------------
 * smpro_dur($sec) — human-readable duration from WHOLE seconds.
 *   $d=intdiv($sec,86400); $sec%=86400; $h=intdiv($sec,3600); $sec%=3600; $m=intdiv($sec,60);
 *   ($d ? "{$d}d " : '') . sprintf('%dh %dm', $h, $m)
 * The days segment is omitted when 0; hours+minutes are always shown. Seconds are
 * dropped (truncated, not rounded). intdiv requires an int arg — pass ints only.
 * -------------------------------------------------------------------- */

is_eq(smpro_dur(0),     '0h 0m',     'dur(0) = 0h 0m (no days segment)');
is_eq(smpro_dur(59),    '0h 0m',     'dur(59) = 0h 0m (sub-minute truncated, not rounded)');
is_eq(smpro_dur(60),    '0h 1m',     'dur(60) = 0h 1m');
is_eq(smpro_dur(3599),  '0h 59m',    'dur(3599) = 0h 59m (just under an hour)');
is_eq(smpro_dur(3600),  '1h 0m',     'dur(3600) = 1h 0m');
is_eq(smpro_dur(3661),  '1h 1m',     'dur(3661) = 1h 1m (3661s = 1h 1m 1s -> seconds dropped)');
is_eq(smpro_dur(86399), '23h 59m',   'dur(86399) = 23h 59m (just under 1 day, no days segment yet)');

like(smpro_dur(0),       '/^\d+h \d+m$/', 'dur(0) format = "<h>h <m>m" (no days prefix when <1 day)');
is_eq(smpro_dur(86400),  '1d 0h 0m',  'dur(86400) = 1d 0h 0m (days segment appears at exactly 1 day)');
is_eq(smpro_dur(90061),  '1d 1h 1m',  'dur(90061) = 1d 1h 1m (1d 1h 1m 1s -> seconds dropped)');
is_eq(smpro_dur(172800), '2d 0h 0m',  'dur(172800) = 2d 0h 0m');

/* ----------------------------------------------------------------------
 * Intentionally NOT asserted here (out of group / do not exist / impure):
 * -------------------------------------------------------------------- */
tap_skip('smpro_net_human — function does not exist in helpers.php', 'named in prompt but no such function; nothing to test');
tap_skip('smpro_lo_human — function does not exist in helpers.php',  'named in prompt but no such function; nothing to test');
tap_skip('smpro_lo_dur — function does not exist in helpers.php',    'named in prompt but no such function; nothing to test');
