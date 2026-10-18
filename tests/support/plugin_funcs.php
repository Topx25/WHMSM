<?php
/**
 * plugin_funcs.php — SAFELY load the pure functions out of a MODULE file.
 *
 * Module files (modules/*.php) execute a router at include time (DB queries, layout output,
 * audit writes, even csf/exec). Requiring one in a test is unsafe. This extractor tokenizes
 * the file and keeps ONLY: top-level `function`/`class` definitions and top-level
 * `define(...)`/`const ...` declarations (constants the functions need). Every executable
 * top-level statement (the router, calls, assignments) is dropped. The result is written to a
 * temp file under the sandbox and required, so the module's pure functions become callable
 * with ZERO router side effects.
 *
 * Use in a test:  smpro_plugin_funcs('modules/database-cleanup.php');  then call smpro_db_*().
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

function _smpro_tok_text($t) { return is_array($t) ? $t[1] : $t; }

/** Capture a brace-balanced block starting at token index $i (a function/class). Returns [text, nextIndex]. */
function _smpro_capture_block(array $toks, int $i, int $n): array {
    $buf = ''; $opened = false; $depth = 0;
    for (; $i < $n; $i++) {
        $tok = $toks[$i];
        $txt = _smpro_tok_text($tok);
        $buf .= $txt;
        $isOpen  = ($txt === '{') || (is_array($tok) && defined('T_DOLLAR_OPEN_CURLY_BRACES') && $tok[0] === T_DOLLAR_OPEN_CURLY_BRACES);
        $isClose = ($txt === '}');
        if ($isOpen)  { $opened = true; $depth++; }
        elseif ($isClose) { $depth--; if ($opened && $depth === 0) { $i++; break; } }
    }
    return [$buf, $i];
}

/** Capture from $i up to and including the next top-level ';'. Returns [text, nextIndex]. */
function _smpro_capture_stmt(array $toks, int $i, int $n): array {
    $buf = ''; $paren = 0;
    for (; $i < $n; $i++) {
        $txt = _smpro_tok_text($toks[$i]);
        $buf .= $txt;
        if ($txt === '(') $paren++;
        elseif ($txt === ')') $paren--;
        elseif ($txt === ';' && $paren === 0) { $i++; break; }
    }
    return [$buf, $i];
}

/** Extract function/class/const/define text from a source file. */
function smpro_extract_defs(string $file, array $exclude = [], array $only = []): string {
    $src = @file_get_contents($file);
    if ($src === false) return '';
    $toks = token_get_all($src);
    $n = count($toks);
    $out = "<?php\n";
    $i = 0;
    while ($i < $n) {
        $t = $toks[$i];
        if (is_array($t) && ($t[0] === T_CLASS || $t[0] === T_TRAIT || $t[0] === T_INTERFACE)) {
            [$chunk, $i] = _smpro_capture_block($toks, $i, $n);
            $out .= $chunk . "\n";
            continue;
        }
        if (is_array($t) && $t[0] === T_FUNCTION) {
            // capture ONLY named functions (`function NAME(` or `function &NAME(`). Anonymous
            // closures (`$x = function(){...}`, top-level render helpers) are skipped so we never
            // emit a bare `function(){}` (syntax error) or leak the router code that uses them.
            $j = $i + 1;
            while ($j < $n && is_array($toks[$j]) && in_array($toks[$j][0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) $j++;
            if ($j < $n && _smpro_tok_text($toks[$j]) === '&') {
                $j++;
                while ($j < $n && is_array($toks[$j]) && $toks[$j][0] === T_WHITESPACE) $j++;
            }
            $named = ($j < $n && is_array($toks[$j]) && $toks[$j][0] === T_STRING);
            if ($named) {
                $fname = $toks[$j][1];
                [$chunk, $i] = _smpro_capture_block($toks, $i, $n);
                $want = !in_array($fname, $exclude, true) && ($only === [] || in_array($fname, $only, true));
                if ($want) $out .= $chunk . "\n";   // skip excluded callees -> a test stub provides them
                continue;
            }
            $i++;   // anonymous closure at top level -> skip keyword; loop walks the rest harmlessly
            continue;
        }
        if (is_array($t) && $t[0] === T_CONST) {
            [$chunk, $i] = _smpro_capture_stmt($toks, $i, $n);
            $out .= $chunk . "\n";
            continue;
        }
        if (is_array($t) && $t[0] === T_STRING && strtolower($t[1]) === 'define') {
            // only a bare top-level define(...) call statement
            [$chunk, $i] = _smpro_capture_stmt($toks, $i, $n);
            if (stripos($chunk, 'define(') === 0) $out .= $chunk . "\n";
            continue;
        }
        $i++;
    }
    return $out;
}

/**
 * Extract + load a module's defs. $rel is relative to SMPRO_BASE (e.g. 'modules/x.php') or absolute.
 * Returns the temp file path. Safe to call once per module per process.
 */
function smpro_plugin_funcs(string $rel): string {
    return smpro_plugin_funcs_except($rel, []);
}

/**
 * Like smpro_plugin_funcs, but OMITS the named functions in $exclude so a test can define its own stub
 * for an impure same-file callee (e.g. load update.php but stub smpro_lic_api; load notify.php but stub
 * smpro_http). Define the stubs BEFORE/AFTER — the excluded names are simply absent from the loaded code.
 */
/**
 * Load the shared helpers a module leans on, the same safe way.
 *
 * In the panel, index.cgi has already required includes/helpers.php before any module runs, so a module calling
 * smpro_user_home() is perfectly correct there. In a test only the module's own defs were loaded, so the call
 * fatalled — the test was failing on a gap in the harness, not on a bug in the product. Extracting helpers with
 * the same tokenizer keeps the "no router side effects" guarantee intact.
 */
function smpro_plugin_helpers(string $for = ''): void {
    static $done = false;
    if ($done) return;
    // A test that loads includes/helpers.php itself gets the real thing a moment from now; pre-loading a
    // second copy of one function out of the same file would only collide with it.
    if (basename($for) === 'helpers.php') { $done = true; return; }
    $done = true;
    // ONLY the named helpers, never the whole file: several modules carry their own drifted copy of
    // smpro_h() and friends, so loading all of helpers.php would make every one of those a redeclare fatal.
    $need = array_values(array_filter(['smpro_user_home'], function ($f) { return !function_exists($f); }));
    if (!$need) return;
    $h = SMPRO_BASE . '/includes/helpers.php';
    if (!is_file($h)) return;
    $tmp = rtrim(sys_get_temp_dir(), "/\\") . '/smpro_defs_' . getmypid() . '_helpers_' . md5(implode(',', $need)) . '.php';
    file_put_contents($tmp, smpro_extract_defs($h, [], $need));
    require $tmp;
}

function smpro_plugin_funcs_except(string $rel, array $exclude): string {
    $file = (strpos($rel, '/') === 0 || preg_match('#^[A-Za-z]:#', $rel)) ? $rel : SMPRO_BASE . '/' . $rel;
    smpro_plugin_helpers($file);
    $defs = smpro_extract_defs($file, $exclude);
    $tmp = rtrim(sys_get_temp_dir(), '/\\') . '/smpro_defs_' . getmypid() . '_' . md5($file . '|' . implode(',', $exclude)) . '.php';
    file_put_contents($tmp, $defs);
    require $tmp;
    return $tmp;
}
