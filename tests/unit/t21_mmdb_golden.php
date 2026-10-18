<?php
/**
 * t21_mmdb_golden.php — GOLDEN lookups against a generated, valid MaxMind DB (catalog U01/U02/U03)
 * plus the poisoned-pointer hostile-input case (U06). The 8.8.8.8 -> US assertion is the EXACT
 * validity gate the real GeoIP updater uses (helpers.php), so this proves that gate works.
 * The mmdb is generated in-sandbox by mmdb_gen.php (no committed binary), then read by the REAL
 * includes/mmdb.php reader.
 */
require __DIR__ . '/../support/bootstrap.php';
require SMPRO_BASE . '/includes/mmdb.php';
require SMPRO_BASE . '/tests/support/mmdb_gen.php';

$cc = SMPRO_VARLIB . '/geoip/Test-Country.mmdb';
$asn = SMPRO_VARLIB . '/geoip/Test-ASN.mmdb';
$poison = SMPRO_VARLIB . '/geoip/poison.mmdb';
smpro_test_make_country_mmdb($cc);
smpro_test_make_asn_mmdb($asn);
smpro_test_make_poison_mmdb($poison);

/* ---------- U03: open() success path (complements t01's failure paths) ---------- */
$h = smpro_mmdb_open($cc);
ok(is_array($h), 'open(): generated country mmdb -> handle');
is_eq($h['record_size'] ?? null, 32, 'open(): record_size = 32');
is_eq($h['node_count'] ?? null, 1, 'open(): node_count = 1');
is_eq($h['ip_version'] ?? null, 4, 'open(): ip_version = 4');
is_eq($h['data_start'] ?? null, 24, 'open(): data_start = tree_size(8) + 16 = 24');
is_eq(smpro_mmdb_open($cc), $h, 'open(): second open returns the cached handle');

/* ---------- U01: golden Country lookup (THE GeoIP validation gate) ---------- */
is_eq(smpro_mmdb_country($cc, '8.8.8.8'), 'US', 'U01 country(8.8.8.8) === "US"  (the updater validity gate)');
is_eq(smpro_mmdb_country($cc, '1.1.1.1'), 'US', 'U01 country(1.1.1.1) -> US (first-bit-0 subtree)');
is_eq(smpro_mmdb_country($cc, '200.0.0.0'), '', 'U01 country(200.0.0.0) -> "" (first-bit-1 = no record)');
is_eq(smpro_mmdb_country($cc, 'not.an.ip'), '', 'U01 country(invalid ip) -> ""');
// the reader is family-agnostic (walks the bit string); a v6 addr whose FIRST bit is 1 (0xff..) hits the empty record
is_eq(smpro_mmdb_country($cc, 'ff02::1'), '', 'U01 country(v6 first-bit-1) -> "" (reader walks bits regardless of family)');

/* ---------- U02: golden ASN lookup ---------- */
$a = smpro_mmdb_asn($asn, '8.8.8.8');
is_eq($a['asn'] ?? null, 'AS15169', 'U02 asn(8.8.8.8).asn === "AS15169"');
has((string)($a['provider'] ?? ''), 'GOOGLE', 'U02 asn(8.8.8.8).provider contains GOOGLE');
is_eq(smpro_mmdb_asn($asn, '200.0.0.0'), [], 'U02 asn(no record) -> []');

/* ---------- U06: poisoned data pointer must not crash / must return null ---------- */
is_eq(smpro_mmdb_country($poison, '8.8.8.8'), '', 'U06 country(poisoned out-of-bounds pointer) -> "" (bounds guard, no crash)');
lives_ok(function () use ($poison) { smpro_mmdb_country($poison, '8.8.8.8'); }, 'U06 poisoned mmdb lookup does not throw/hang');
