<?php
/**
 * mmdb.php - self-contained MaxMind DB (.mmdb) reader in PURE PHP.
 *
 * Why this exists: the offline GeoIP lookups must work on ANY host even when the `mmdblookup`
 * binary (libmaxminddb / mmdb-bin) is NOT installed - that is the usual reason country shows
 * "N/A" on a locked-down box. helpers.php prefers the fast `mmdblookup` binary and falls back
 * to this reader, so country/ASN always resolve as long as a .mmdb file is present.
 *
 * Implements just enough of the MaxMind DB binary format (https://maxmind.github.io/MaxMind-DB/):
 * metadata parse, binary search tree walk (24/28/32-bit records, v4 + v4-in-v6), and the data
 * decoder for the types a Country/ASN DB uses (map, string, uint16/32, pointer, array, bool...).
 * No external deps. Memory-maps the file as a string and caches the handle per request.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

/** Open + parse an .mmdb file. Returns a handle array, or null on failure. Cached per request. */
function smpro_mmdb_open($file) {
    static $cache = [];
    if (array_key_exists($file, $cache)) return $cache[$file];
    if (!is_file($file) || !is_readable($file)) return $cache[$file] = null;
    $buf = @file_get_contents($file);
    if ($buf === false || strlen($buf) < 32) return $cache[$file] = null;

    // metadata starts after the LAST occurrence of this marker
    $marker = "\xab\xcd\xefMaxMind.com";
    $mpos = strrpos($buf, $marker);
    if ($mpos === false) return $cache[$file] = null;
    $metaStart = $mpos + strlen($marker);

    // decode the metadata map (its pointers are relative to $metaStart)
    $p = $metaStart;
    $meta = smpro_mmdb_decode($buf, $p, $metaStart);
    if (!is_array($meta) || empty($meta['record_size']) || !isset($meta['node_count'])) return $cache[$file] = null;

    $recordSize = (int)$meta['record_size'];
    $nodeCount  = (int)$meta['node_count'];
    $treeSize   = (int)(($recordSize * 2 / 8) * $nodeCount);
    $h = [
        'buf'        => $buf,
        'node_count' => $nodeCount,
        'record_size'=> $recordSize,
        'ip_version' => (int)($meta['ip_version'] ?? 6),
        'tree_size'  => $treeSize,
        'data_start' => $treeSize + 16,            // 16-byte separator between tree and data section
        'node_bytes' => (int)($recordSize * 2 / 8),
    ];
    return $cache[$file] = $h;
}

/** Read one record (left bit=0 / right bit=1) from a tree node. */
function smpro_mmdb_read_node($h, $node, $bit) {
    $base = $node * $h['node_bytes'];
    $b = $h['buf'];
    $rs = $h['record_size'];
    if ($rs === 24) {
        $off = $base + ($bit ? 3 : 0);
        return (ord($b[$off]) << 16) | (ord($b[$off+1]) << 8) | ord($b[$off+2]);
    }
    if ($rs === 28) {
        if ($bit === 0) {
            return ((ord($b[$base+3]) & 0xF0) << 20) | (ord($b[$base]) << 16) | (ord($b[$base+1]) << 8) | ord($b[$base+2]);
        }
        return ((ord($b[$base+3]) & 0x0F) << 24) | (ord($b[$base+4]) << 16) | (ord($b[$base+5]) << 8) | ord($b[$base+6]);
    }
    // 32-bit
    $off = $base + ($bit ? 4 : 0);
    return (ord($b[$off]) << 24) | (ord($b[$off+1]) << 16) | (ord($b[$off+2]) << 8) | ord($b[$off+3]);
}

/** Look up an IP. Returns the decoded record (array) or null. */
function smpro_mmdb_get($h, $ip) {
    if (!is_array($h)) return null;
    $packed = @inet_pton($ip);
    if ($packed === false) return null;
    $bytes = array_values(unpack('C*', $packed));   // 4 (v4) or 16 (v6) bytes
    $isV4 = count($bytes) === 4;

    // build the bit sequence to walk
    $bits = [];
    if ($isV4 && $h['ip_version'] === 6) {
        for ($i = 0; $i < 96; $i++) $bits[] = 0;     // IPv4 lives under ::/96 in a v6 tree
    }
    foreach ($bytes as $byte) for ($i = 7; $i >= 0; $i--) $bits[] = ($byte >> $i) & 1;

    $node = 0;
    $nodeCount = $h['node_count'];
    foreach ($bits as $bit) {
        if ($node >= $nodeCount) break;
        $rec = smpro_mmdb_read_node($h, $node, $bit);
        if ($rec === $nodeCount) return null;        // empty / not found
        if ($rec > $nodeCount) {                      // data pointer
            $offset = $rec - $nodeCount + $h['tree_size'];
            $p = $offset;
            return smpro_mmdb_decode($h['buf'], $p, $h['data_start']);
        }
        $node = $rec;                                 // descend
    }
    return null;
}

/**
 * Decode one value from the data section at $p (passed by reference, advanced past the value).
 * $dataStart is the base for pointer resolution.
 */
function smpro_mmdb_decode($buf, &$p, $dataStart, $depth = 0) {
    // hostile-input guards: bound recursion (crafted pointer chains) + reject out-of-bounds offsets (truncated/poisoned DB)
    $len = strlen($buf);   // O(1) in PHP
    if ($depth > 64 || $p < 0 || $p >= $len) return null;
    $ctrl = ord($buf[$p]); $p++;
    $type = $ctrl >> 5;
    if ($type === 0) { if ($p >= $len) return null; $type = ord($buf[$p]) + 7; $p++; }   // extended type

    // size
    $size = $ctrl & 0x1f;
    if ($type !== 1) {                                       // pointers compute size differently
        if ($size === 29)      { $size = 29 + ord($buf[$p]); $p += 1; }
        elseif ($size === 30)  { $size = 285 + ((ord($buf[$p]) << 8) | ord($buf[$p+1])); $p += 2; }
        elseif ($size === 31)  { $size = 65821 + ((ord($buf[$p]) << 16) | (ord($buf[$p+1]) << 8) | ord($buf[$p+2])); $p += 3; }
    }

    switch ($type) {
        case 1: // pointer
            $ps = ($ctrl >> 3) & 0x3;
            if ($ps === 0)      { $val = (($ctrl & 0x7) << 8) | ord($buf[$p]); $p += 1; }
            elseif ($ps === 1)  { $val = (($ctrl & 0x7) << 16) | (ord($buf[$p]) << 8) | ord($buf[$p+1]); $p += 2; $val += 2048; }
            elseif ($ps === 2)  { $val = (($ctrl & 0x7) << 24) | (ord($buf[$p]) << 16) | (ord($buf[$p+1]) << 8) | ord($buf[$p+2]); $p += 3; $val += 526336; }
            else                { $val = (ord($buf[$p]) << 24) | (ord($buf[$p+1]) << 16) | (ord($buf[$p+2]) << 8) | ord($buf[$p+3]); $p += 4; }
            $tp = $dataStart + $val;                         // resolve (do NOT advance caller $p past target)
            if ($tp < 0 || $tp >= $len) return null;          // pointer must land inside the file
            return smpro_mmdb_decode($buf, $tp, $dataStart, $depth + 1);
        case 2: // utf8 string
            $s = $size > 0 ? substr($buf, $p, $size) : ''; $p += $size; return $s;
        case 3: // double (8 bytes, big-endian)
            $v = unpack('E', substr($buf, $p, 8)); $p += 8; return $v[1];
        case 4: // bytes
            $s = substr($buf, $p, $size); $p += $size; return $s;
        case 5: // uint16
        case 6: // uint32
        case 9: // uint64 (read as int; fine for ASN)
        case 10: // uint128 (rare; return hex)
            $n = 0; for ($i = 0; $i < $size; $i++) { $n = ($n << 8) | ord($buf[$p]); $p++; } return $n;
        case 7: // map
            if ($size > 65536) return null;                  // sanity cap - real Country/ASN records have <20 keys
            $out = [];
            for ($i = 0; $i < $size; $i++) {
                if ($p >= $len) return $out;
                $k = smpro_mmdb_decode($buf, $p, $dataStart, $depth + 1);
                $v = smpro_mmdb_decode($buf, $p, $dataStart, $depth + 1);
                $out[(string)$k] = $v;
            }
            return $out;
        case 8: // int32 (signed)
            $n = 0; for ($i = 0; $i < $size; $i++) { $n = ($n << 8) | ord($buf[$p]); $p++; }
            if ($size > 0 && ($n & (1 << ($size*8 - 1)))) $n -= (1 << ($size*8));
            return $n;
        case 11: // array
            if ($size > 65536) return null;                  // sanity cap
            $out = [];
            for ($i = 0; $i < $size; $i++) { if ($p >= $len) break; $out[] = smpro_mmdb_decode($buf, $p, $dataStart, $depth + 1); }
            return $out;
        case 14: // boolean
            return $size !== 0;
        case 15: // float (4 bytes, big-endian)
            $v = unpack('G', substr($buf, $p, 4)); $p += 4; return $v[1];
        default:
            return null;
    }
}

/** Convenience: 2-letter country ISO for an IP via a Country/City mmdb. '' if not found. */
function smpro_mmdb_country($file, $ip) {
    $h = smpro_mmdb_open($file); if (!$h) return '';
    $r = smpro_mmdb_get($h, $ip); if (!is_array($r)) return '';
    $cc = $r['country']['iso_code'] ?? ($r['registered_country']['iso_code'] ?? '');
    return is_string($cc) ? strtoupper($cc) : '';
}

/** Convenience: ['asn'=>int,'provider'=>org] for an IP via an ASN mmdb. [] if not found. */
function smpro_mmdb_asn($file, $ip) {
    $h = smpro_mmdb_open($file); if (!$h) return [];
    $r = smpro_mmdb_get($h, $ip); if (!is_array($r)) return [];
    $out = [];
    if (isset($r['autonomous_system_number']))       $out['asn'] = 'AS' . (int)$r['autonomous_system_number'];
    if (isset($r['autonomous_system_organization'])) $out['provider'] = (string)$r['autonomous_system_organization'];
    return $out;
}
