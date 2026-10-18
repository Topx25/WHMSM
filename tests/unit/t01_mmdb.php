<?php
/**
 * t01_mmdb.php — pure unit tests for the self-contained MaxMind DB reader (includes/mmdb.php).
 *
 * mmdb.php is fully self-contained (only needs SMPRO_BOOT), so this loads the REAL source and
 * exercises:
 *   - smpro_mmdb_open() failure paths (mmdb.php:21-34)
 *   - smpro_mmdb_decode() every data type via hand-built byte buffers (mmdb.php:106-168)
 *   - hostile-input guards: depth cap, out-of-bounds pointer, self-referential chain (mmdb.php:109/130/131)
 *   - smpro_mmdb_country / smpro_mmdb_asn empty-DB paths (mmdb.php:172-187)
 * The golden 8.8.8.8 -> US lookup needs a real mmdb fixture and is added in Phase 2 (U01/U02).
 *
 * Every expected value below was derived by reading the source, not guessed.
 */
require __DIR__ . '/../support/bootstrap.php';
require SMPRO_BASE . '/includes/mmdb.php';

/* ---------- open() failure paths ---------- */
is_eq(smpro_mmdb_open(SMPRO_VARLIB . '/does-not-exist.mmdb'), null, 'open(): missing file -> null');

$tiny = SMPRO_VARLIB . '/tiny.bin';
file_put_contents($tiny, str_repeat('x', 16));                     // < 32 bytes (mmdb.php:23)
is_eq(smpro_mmdb_open($tiny), null, 'open(): file < 32 bytes -> null');

$nomark = SMPRO_VARLIB . '/nomark.bin';
file_put_contents($nomark, str_repeat('A', 200));                  // no MaxMind marker (mmdb.php:28)
is_eq(smpro_mmdb_open($nomark), null, 'open(): no MaxMind.com marker -> null');

/* ---------- convenience wrappers on an absent DB ---------- */
is_eq(smpro_mmdb_country(SMPRO_VARLIB . '/nope.mmdb', '8.8.8.8'), '', 'country(): absent DB -> empty string');
is_eq(smpro_mmdb_asn(SMPRO_VARLIB . '/nope.mmdb', '8.8.8.8'), [], 'asn(): absent DB -> empty array');

/* ---------- decoder: positive controls for each type (hand-built buffers) ---------- */
$dec = function (string $buf, int $dataStart = 0) {
    $p = 0;
    return smpro_mmdb_decode($buf, $p, $dataStart);
};

// type 2: utf8 string  ctrl=(2<<5)|len
is_eq($dec("\x42US"), 'US', 'decode: utf8 string "US"');

// type 5: uint16 big-endian  ctrl=(5<<5)|2 = 0xA2 ; 0x1234 = 4660
is_eq($dec("\xA2\x12\x34"), 4660, 'decode: uint16 big-endian (0x1234)');

// type 8 (extended): int32 signed -1  ctrl=0x04 (size4,ext) next=0x01 (1+7=8) FFFFFFFF
is_eq($dec("\x04\x01\xFF\xFF\xFF\xFF"), -1, 'decode: int32 sign-extension (-1)');

// type 14 (extended): boolean  ctrl size = bool ; next=0x07 (7+7=14)
is_eq($dec("\x01\x07"), true, 'decode: boolean true');
is_eq($dec("\x00\x07"), false, 'decode: boolean false');

// type 7: map {"a":"b"}  ctrl=0xE1 then "a","b" as utf8
is_eq($dec("\xE1\x41a\x41b"), ['a' => 'b'], 'decode: 1-key map');

// type 11 (extended): array ["x"]  ctrl=0x01 next=0x04 (4+7=11) then "x"
is_eq($dec("\x01\x04\x41x"), ['x'], 'decode: 1-element array');

/* ---------- decoder: hostile-input guards (the security core of the reader) ---------- */
// empty buffer: p(0) >= len(0) -> null (mmdb.php:109)
$p = 0; is_eq(smpro_mmdb_decode('', $p, 0), null, 'decode: empty buffer -> null');

// recursion depth cap: depth 65 > 64 -> null immediately (mmdb.php:109)
$p = 0; is_eq(smpro_mmdb_decode("\x42AB", $p, 0, 65), null, 'decode: depth > 64 -> null (no stack blowup)');

// pointer landing outside the file -> null (mmdb.php:130). type1 ps0: val=((ctrl&7)<<8)|next
$p = 0; is_eq(smpro_mmdb_decode("\x20\xFF", $p, 0), null, 'decode: pointer outside file -> null');

// self-referential pointer chain must TERMINATE (depth cap) and return null — never hang.
// "\x20\x00" => type1 ps0 val0 => target = dataStart(0)+0 = offset 0 = itself.
$p = 0; is_eq(smpro_mmdb_decode("\x20\x00", $p, 0), null, 'decode: self-referential pointer -> null (bounded, no infinite loop)');
