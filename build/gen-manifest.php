<?php
/**
 * gen-manifest.php — build-time signed integrity manifest for Safety Monitor Pro.
 *
 * Hashes every shipped file (SHA-256), signs the canonical hash-map with the OFFLINE private key, and
 * writes <dir>/integrity.json. The plugin (includes/integrity.php) verifies it with the embedded PUBLIC
 * key. Canonicalization MUST match the plugin: ksort(files) + json_encode(JSON_UNESCAPED_SLASHES).
 *
 * Usage: php gen-manifest.php <plugin_dir> <private_key.pem>
 */
$me = array_shift($argv);
$dir  = rtrim((string)($argv[0] ?? ''), '/\\');
$priv = (string)($argv[1] ?? '');
$version = preg_replace('/[^0-9A-Za-z.-]/', '', (string)($argv[2] ?? ''));   // bound to the signed tarball; read by the self-update downgrade guard. Keep letters/'-' so -betaN suffixes survive (version_compare needs them); still strips spaces/injection chars.
if ($dir === '' || $priv === '' || !is_dir($dir) || !is_file($priv)) {
    fwrite(STDERR, "usage: php gen-manifest.php <plugin_dir> <private_key.pem> [version]\n"); exit(1);
}

$files = [];
$it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS));
foreach ($it as $f) {
    if (!$f->isFile()) continue;
    $rel = str_replace('\\', '/', substr($f->getPathname(), strlen($dir) + 1));
    if ($rel === 'integrity.json') continue;                       // the manifest never hashes itself
    $files[$rel] = hash_file('sha256', $f->getPathname());
}
ksort($files);                                                     // canonical order (must match the verifier)
$canon = json_encode($files, JSON_UNESCAPED_SLASHES);

$pk = openssl_pkey_get_private(file_get_contents($priv));
if (!$pk) { fwrite(STDERR, "ERROR: cannot load private key\n"); exit(2); }
$sig = '';
if (!openssl_sign($canon, $sig, $pk, OPENSSL_ALGO_SHA256)) { fwrite(STDERR, "ERROR: signing failed\n"); exit(3); }

// NOTE: 'sig' covers ONLY the canonical files-map (the runtime integrity gate verifies exactly that, so it is
// unchanged). 'version' rides inside the tarball whose bytes the self-update path RSA-verifies as a whole, so it
// is authenticated-by-inclusion without altering what 'sig' signs.
$out = ['v' => 1, 'version' => $version, 'files' => $files, 'sig' => base64_encode($sig)];
file_put_contents($dir . '/integrity.json', json_encode($out, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT));
echo 'manifest: ' . count($files) . ' files signed' . ($version !== '' ? " (version $version)" : '') . "\n";
