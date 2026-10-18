<?php
/**
 * mmdb_gen.php — generate a MINIMAL but VALID MaxMind DB binary the plugin's pure-PHP reader
 * (includes/mmdb.php) parses correctly. Used to make the GOLDEN fixtures: 8.8.8.8 -> US (Country)
 * and 8.8.8.8 -> AS15169/GOOGLE (ASN). 8.8.8.8 -> US is the EXACT check the real GeoIP updater
 * uses to validate a downloaded DB (helpers.php), so this proves that gate end-to-end.
 *
 * Layout produced (ip_version=4, record_size=32, node_count=1):
 *   node 0: left record (first IP bit = 0) -> data pointer to the single record; right (bit=1) -> empty
 *   => every 0.x.x.x..127.x.x.x resolves to the record; 128.x+ has no record. inet_pton failures -> ''.
 *   tree(8 bytes) + 16-byte separator + data + "\xab\xcd\xefMaxMind.com" + metadata-map.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

/** control byte(s) for a (type,size) per the MaxMind-DB spec. */
function _mg_ctrl(int $type, int $size): string {
    $first = ($type < 8) ? ($type << 5) : 0;
    if ($size < 29)            { $sb = $size; $ext = ''; }
    elseif ($size < 29 + 256)  { $sb = 29; $ext = chr($size - 29); }
    elseif ($size < 285 + 65536) { $sb = 30; $v = $size - 285; $ext = chr(($v >> 8) & 0xff) . chr($v & 0xff); }
    else                       { $sb = 31; $v = $size - 65821; $ext = chr(($v >> 16) & 0xff) . chr(($v >> 8) & 0xff) . chr($v & 0xff); }
    $out = chr($first | $sb);
    if ($type >= 8) $out .= chr($type - 7);   // extended type byte AFTER the control byte
    return $out . $ext;
}
function _mg_str(string $s): string { return _mg_ctrl(2, strlen($s)) . $s; }
function _mg_uint(int $v): string {           // type 6 (uint32), minimal big-endian bytes
    $b = '';
    if ($v > 0) { $t = $v; while ($t > 0) { $b = chr($t & 0xff) . $b; $t >>= 8; } }
    return _mg_ctrl(6, strlen($b)) . $b;
}
/** $pairs = [[key,encodedValue], ...] -> a map (type 7). */
function _mg_map(array $pairs): string {
    $out = _mg_ctrl(7, count($pairs));
    foreach ($pairs as [$k, $v]) $out .= _mg_str($k) . $v;
    return $out;
}

/** Build the mmdb bytes for one record value (already-encoded). */
function _mg_build(string $record): string {
    $nodeCount = 1;
    $recordSize = 32;
    $treeSize = (int)(($recordSize * 2 / 8) * $nodeCount);     // = 8
    // node 0: left = data pointer (nodeCount+16 -> first byte of data section), right = nodeCount (empty)
    $left = $nodeCount + 16;                                   // 17 -> reader offset = 17-1+8 = 24 = data_start
    $right = $nodeCount;                                       // 1  -> "no record"
    $node = pack('N', $left) . pack('N', $right);              // 32-bit big-endian records
    $sep = str_repeat("\x00", 16);
    $meta = _mg_map([
        ['node_count',  _mg_uint($nodeCount)],
        ['record_size', _mg_uint($recordSize)],
        ['ip_version',  _mg_uint(4)],
    ]);
    return $node . $sep . $record . "\xab\xcd\xefMaxMind.com" . $meta;
}

/** Write a generated Country mmdb (8.8.8.8 -> US) to $path. */
function smpro_test_make_country_mmdb(string $path): void {
    $rec = _mg_map([['country', _mg_map([['iso_code', _mg_str('US')]])]]);
    file_put_contents($path, _mg_build($rec));
}
/** Write a generated ASN mmdb (8.8.8.8 -> AS15169 / GOOGLE) to $path. */
function smpro_test_make_asn_mmdb(string $path): void {
    $rec = _mg_map([
        ['autonomous_system_number', _mg_uint(15169)],
        ['autonomous_system_organization', _mg_str('GOOGLE')],
    ]);
    file_put_contents($path, _mg_build($rec));
}
/** A POISONED mmdb: a valid header but a data pointer that lands OUTSIDE the file (hostile-input safety). */
function smpro_test_make_poison_mmdb(string $path): void {
    // left record points far beyond EOF -> reader's bounds guard must return null (no crash)
    $nodeCount = 1; $node = pack('N', $nodeCount + 16 + 999999) . pack('N', $nodeCount);
    $sep = str_repeat("\x00", 16);
    $meta = _mg_map([['node_count', _mg_uint(1)], ['record_size', _mg_uint(32)], ['ip_version', _mg_uint(4)]]);
    file_put_contents($path, $node . $sep . "\x42US" . "\xab\xcd\xefMaxMind.com" . $meta);
}
