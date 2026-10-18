<?php
/**
 * Generate cpuser/stack.php from includes/phstack.php.
 *
 * The account-side plugin needs exactly the same answer as the WHM side to "which application is installed here,
 * and which of its files matter". Keeping a hand-written second copy is how the two would come to protect
 * different files while both looked fine — the drift would be silent, because each side would keep working.
 *
 * So the account-side copy is not written by hand at all: it is DERIVED here on every build. The transformation
 * is deliberately tiny — rename the function prefix, and drop the WHM boot guard, which cannot hold in a file
 * that cPanel executes directly. Anything more than that would be a second implementation wearing a generator's
 * clothes.
 *
 * Run from the plugin root:  php build/gen-cpuser-stack.php
 * Exits non-zero on any problem, so the build stops rather than packaging a stale copy.
 */

$root = dirname(__DIR__);
$src  = $root . '/includes/phstack.php';
$dst  = $root . '/cpuser/stack.php';

if (!is_file($src)) { fwrite(STDERR, "gen-cpuser-stack: missing $src\n"); exit(1); }
$code = (string)file_get_contents($src);
if ($code === '') { fwrite(STDERR, "gen-cpuser-stack: $src is empty\n"); exit(1); }

// Take ONLY the detection functions. phstack.php also carries low-level helpers the WHM side and the root worker
// need — chattr, lsattr, the account's document roots read from /etc/userdatadomains. Copying those into a page
// that runs as the ACCOUNT is wrong twice over: they cannot work without root, and shipping them invites code
// that looks like it locks files while doing nothing. It also caused a real outage: the generated sp_inside()
// collided with the page's own helper of the same name and cPanel fatalled the moment anyone opened the page.
$keep = ['smpro_ph_read_head', 'smpro_ph_de', 'smpro_ph_fe', 'smpro_ph_php_count',
         'smpro_ph_detect', 'smpro_ph_standard_files', 'smpro_ph_upload_dirs'];

$kept = '';
foreach ($keep as $fn) {
    if (!preg_match('/^function\s+' . preg_quote($fn, '/') . '\s*\(/m', $code, $m, PREG_OFFSET_CAPTURE)) {
        fwrite(STDERR, "gen-cpuser-stack: {$fn}() is not in phstack.php — refusing to generate.\n");
        exit(7);
    }
    $start = $m[0][1];
    $i = strpos($code, '{', $start) + 1;
    $depth = 1; $len = strlen($code);
    while ($i < $len && $depth > 0) {
        if ($code[$i] === '{') $depth++;
        elseif ($code[$i] === '}') $depth--;
        $i++;
    }
    $kept .= substr($code, $start, $i - $start) . "\n\n";
}
$code = str_replace('smpro_ph_', 'sp_', $kept);

// Prove the rename actually covered everything before writing: a leftover smpro_ph_ call would be a function that
// does not exist at runtime, and the page would fatal on the customer's screen rather than here.
if (strpos($code, 'smpro_ph_') !== false) {
    fwrite(STDERR, "gen-cpuser-stack: some smpro_ph_ references survived the rename — refusing to generate.\n");
    exit(3);
}
foreach (['sp_detect', 'sp_standard_files', 'sp_upload_dirs'] as $need) {
    if (strpos($code, 'function ' . $need . '(') === false) {
        fwrite(STDERR, "gen-cpuser-stack: $need() is missing from the generated file — refusing.\n");
        exit(4);
    }
}

// A name declared on both sides is a fatal error the moment cPanel loads the page, and nothing reveals it until
// a customer opens it. Checked here, where it costs a build instead of an outage.
$page = (string)@file_get_contents(dirname($dst) . '/index.live.php');
if ($page !== '' && preg_match_all('/^function\s+(sp_\w+)\s*\(/m', $page, $pm)) {
    foreach ($pm[1] as $own) {
        if (preg_match('/^function\s+' . preg_quote($own, '/') . '\s*\(/m', $code)) {
            fwrite(STDERR, "gen-cpuser-stack: {$own}() would be declared in BOTH index.live.php and the generated\n"
                         . "                  stack.php. cPanel fatals on load. Rename one of them.\n");
            exit(8);
        }
    }
}

$banner = "<?php\n"
        . "/* GENERATED FILE — do not edit.\n"
        . " * The detection half of includes/phstack.php, rewritten with the account-side prefix by\n"
        . " * build/gen-cpuser-stack.php on every build, so the two sides can never disagree about which files are\n"
        . " * worth protecting. Only the functions that need no privileges are carried over. Edit the source.\n"
        . " */\n";
$code = $banner . $code;

@is_dir(dirname($dst)) || @mkdir(dirname($dst), 0755, true);
if (file_put_contents($dst, $code) === false) { fwrite(STDERR, "gen-cpuser-stack: could not write $dst\n"); exit(5); }

// Last check: the thing we just wrote must actually parse.
$out = []; $rc = 1;
exec(escapeshellarg(PHP_BINARY) . ' -l ' . escapeshellarg($dst) . ' 2>&1', $out, $rc);
if ($rc !== 0) { fwrite(STDERR, "gen-cpuser-stack: generated file does not parse:\n" . implode("\n", $out) . "\n"); exit(6); }

echo "gen-cpuser-stack: wrote " . basename($dst) . " from " . basename($src) . "\n";
