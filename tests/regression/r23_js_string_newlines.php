<?php
/**
 * r23_js_string_newlines.php — a JS string literal must never span lines.
 *
 * Reported from a live panel (2026-09-14): "Force unprotect & ignore — لا يعمل … مافيش أي رد فعل خالص". Not an
 * error, not a failed request — the button simply did nothing.
 *
 * The cause was a confirm() message written across several lines for readability:
 *
 *     if(!confirm('Force unprotect '+PH_USER+'?
 *
 *     Every lock this plugin holds over the account is removed …
 *
 * A single-quoted JavaScript string cannot contain a raw newline. The browser raises SyntaxError and discards the
 * WHOLE <script> block — so every listener in it never binds, and every button in that block silently does
 * nothing. The force-unprotect button was simply the one somebody pressed.
 *
 * WHY NOTHING CAUGHT IT. `php -l` parses PHP, not the JavaScript inside a heredoc of markup. The render harness
 * executes the page and checks it produced output — which it did, perfectly valid HTML containing a broken
 * script. A grep for the message finds it and reports it present. Every gate we have looked straight at this and
 * saw nothing wrong, because none of them reads JavaScript. This test does the one check that catches it.
 */
require __DIR__ . '/../support/bootstrap.php';

/** Does this line leave a single-quoted JS string unterminated? */
$openQuote = function (string $line): bool {
    return (preg_match_all("/(?<!\\\\)'/", $line) % 2) === 1;
};

$bad = [];
foreach (['modules', 'includes'] as $sub) {
    $dir = SMPRO_BASE . '/' . $sub;
    if (!is_dir($dir)) continue;
    foreach (glob($dir . '/*.php') ?: [] as $file) {
        $lines = explode("\n", str_replace(chr(13), '', (string)file_get_contents($file)));
        foreach ($lines as $n => $line) {
            // Only the JS message calls. A PHP line may legitimately leave a quote open across a concatenation.
            if (strpos($line, 'confirm(') === false && strpos($line, 'alert(') === false) continue;
            if (strpos($line, '<?') !== false || strpos($line, '?>') !== false) continue;
            if (!$openQuote($line)) continue;
            $bad[] = basename($sub) . '/' . basename($file) . ':' . ($n + 1) . ' — ' . trim(substr($line, 0, 80));
        }
    }
}

is_eq($bad, [], 'J1: no confirm()/alert() leaves a string literal open across a newline'
    . ($bad ? ' — a browser discards the whole <script> block, so every button in it stops working: ' . implode(' | ', $bad) : ''));

/* The two that were found and fixed, asserted by shape so a re-break is caught by name. */
$ph = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/php-harden.php'));
has($ph, "if(!confirm('Force unprotect '+PH_USER+'?\\n\\n", 'J2: the force-unprotect message uses \\n, not a real newline');
hasnt($ph, "if(!confirm('Force unprotect '+PH_USER+'?\n", 'J2: ...and the raw-newline version is gone');

$rm = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/restore-migrate.php'));
$openInRm = 0;
foreach (explode("\n", $rm) as $line) {
    if ((strpos($line, 'confirm(') !== false || strpos($line, 'alert(') !== false)
        && strpos($line, '<?') === false && (preg_match_all("/(?<!\\\\)'/", $line) % 2) === 1) $openInRm++;
}
is_eq($openInRm, 0, 'J3: restore-migrate carries no broken dialog string either — it had one too');
