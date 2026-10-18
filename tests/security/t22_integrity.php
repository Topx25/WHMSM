<?php
/**
 * t22_integrity.php — signed integrity-manifest anti-tamper (catalog U26, S07). Threat: root edits a
 * gate file (e.g. license.php) or forges the manifest. The manifest is RSA-signed over the ksort'd
 * file->sha256 map (integrity.php:33-34) and each file is re-hashed; a critical mismatch = Protected Mode.
 *
 * We point SMPRO_BASE at a SANDBOX fixture dir (defined BEFORE bootstrap so the real includes pick it up),
 * inject a TEST update pubkey, build a manifest signed by the matching TEST key, then prove: valid->ok,
 * non-critical drift->non-critical fail, critical file edit->critical fail, foreign-signed manifest->critical,
 * edited hash (broken sig)->fail, absent/blank manifest->skip (fail-open, never bricks).
 */
$fix = rtrim(sys_get_temp_dir(), '/\\') . '/smpro_integ_' . getmypid() . '_' . bin2hex(random_bytes(3));
@mkdir($fix, 0700, true);
define('SMPRO_BASE', $fix);                                   // BEFORE bootstrap → integrity manifest + hashing rooted here

require __DIR__ . '/../support/bootstrap.php';
require SMPRO_TEST_SRC . '/tests/support/lic_sign.php';
register_shutdown_function(function () use ($fix) { smpro_test_rmrf($fix); });

$kp = smpro_test_new_keypair();
define('SMPRO_UPD_PUBKEY', $kp['pub']);                       // integrity verifies manifest sig with THIS key
require SMPRO_TEST_SRC . '/includes/integrity.php';

file_put_contents("$fix/index.php", "<?php // gate\n");       // a CRITICAL file
file_put_contents("$fix/note.txt", "hello world\n");          // a NON-critical file

$writeManifest = function (array $files, ?string $priv = null) use ($fix, $kp) {
    ksort($files);
    $canon = json_encode($files, JSON_UNESCAPED_SLASHES);     // MUST match integrity.php:33-34 canonicalization
    $pk = openssl_pkey_get_private($priv ?? $kp['priv']);
    openssl_sign($canon, $sig, $pk, OPENSSL_ALGO_SHA256);
    file_put_contents("$fix/integrity.json", json_encode(['files' => $files, 'sig' => base64_encode($sig)]));
};
$realFiles = function () use ($fix) {
    return ['index.php' => hash_file('sha256', "$fix/index.php"), 'note.txt' => hash_file('sha256', "$fix/note.txt")];
};

/* valid signed manifest */
$writeManifest($realFiles());
is_eq(smpro_integrity_load()['ok'] ?? null, true, 'U26 integrity_load: valid TEST-signed manifest -> ok');
is_eq(smpro_integrity_check()['ok'] ?? null, true, 'U26 integrity_check: all files match -> ok');

/* non-critical drift */
file_put_contents("$fix/note.txt", "tampered\n");
$c = smpro_integrity_check();
is_eq($c['ok'] ?? null, false, 'U26 integrity_check: modified non-critical file -> not ok');
is_eq($c['critical'] ?? null, false, 'U26 integrity_check: note.txt flagged non-critical');
is_eq($c['file'] ?? null, 'note.txt', 'U26 integrity_check: names the modified file');

/* critical file edit (the actual attack: patch the gate) */
file_put_contents("$fix/note.txt", "hello world\n");          // restore
file_put_contents("$fix/index.php", "<?php /* return true; */\n");
$c = smpro_integrity_check();
is_eq($c['ok'] ?? null, false, 'S07 integrity_check: modified index.php -> not ok');
is_eq($c['critical'] ?? null, true, 'S07 integrity_check: index.php is CRITICAL (Protected Mode)');
file_put_contents("$fix/index.php", "<?php // gate\n");       // restore

/* foreign-signed manifest (forged, no private key) */
$foreign = smpro_test_new_keypair();
$writeManifest($realFiles(), $foreign['priv']);
$m = smpro_integrity_load();
is_eq($m['ok'] ?? null, false, 'S07 integrity_load: manifest signed by a FOREIGN key -> not ok');
is_eq($m['critical'] ?? null, true, 'S07 integrity_load: bad manifest signature is critical');

/* edited hash in an otherwise-valid manifest (breaks the signature) */
$writeManifest($realFiles());
$j = json_decode((string) file_get_contents("$fix/integrity.json"), true);
$j['files']['index.php'] = str_repeat('0', 64);
file_put_contents("$fix/integrity.json", json_encode($j));
is_eq(smpro_integrity_load()['ok'] ?? null, false, 'S07 integrity_load: edited hash (signature broken) -> not ok');

/* fail-open: absent + blank manifest must SKIP (never brick old/partial builds) */
@unlink("$fix/integrity.json");
is_eq(smpro_integrity_load(), ['skip' => 'no_manifest'], 'U26 integrity_load: absent manifest -> skip=no_manifest (fail-open)');
is_eq(smpro_integrity_check()['skip'] ?? null, 'no_manifest', 'U26 integrity_check: absent manifest -> skip');
file_put_contents("$fix/integrity.json", json_encode(['files' => [], 'sig' => '']));
is_eq(smpro_integrity_load(), ['skip' => 'blank_manifest'], 'U26 integrity_load: blank manifest -> skip=blank_manifest');
