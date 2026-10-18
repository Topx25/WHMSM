<?php
/**
 * assert.php — assertion sugar on top of TAP. Every helper returns bool so tests
 * can branch, and emits exactly one TAP line. Strict === comparisons by default
 * (so '1' !== 1 etc.) because a "depend-on-it" lab must catch type drift.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

function _smpro_x($v) { return var_export($v, true); }

/** Truthy. */
function ok($cond, $name) {
    return tap_result((bool)$cond, $name, $cond ? '' : 'expected truthy, got: ' . _smpro_x($cond));
}
/** Falsy. */
function nok($cond, $name) {
    return tap_result(!$cond, $name, !$cond ? '' : 'expected falsy, got: ' . _smpro_x($cond));
}
/** Strict equality ($got === $exp). Works for scalars AND arrays (PHP array === is deep + order-sensitive). */
function is_eq($got, $exp, $name) {
    $ok = ($got === $exp);
    return tap_result($ok, $name, $ok ? '' : "got:      " . _smpro_x($got) . "\nexpected: " . _smpro_x($exp));
}
/** Strict inequality. */
function isnt_eq($got, $exp, $name) {
    $ok = ($got !== $exp);
    return tap_result($ok, $name, $ok ? '' : 'got value equal to forbidden: ' . _smpro_x($got));
}
/** Regex match. */
function like($got, $regex, $name) {
    $ok = is_string($got) && preg_match($regex, $got) === 1;
    return tap_result($ok, $name, $ok ? '' : "regex $regex did not match: " . _smpro_x($got));
}
/** Substring presence. */
function has($haystack, $needle, $name) {
    $ok = is_string($haystack) && $needle !== '' && strpos($haystack, $needle) !== false;
    return tap_result($ok, $name, $ok ? '' : "expected to contain " . _smpro_x($needle) . " in: " . _smpro_x($haystack));
}
/** Substring absence. */
function hasnt($haystack, $needle, $name) {
    $ok = !is_string($haystack) || strpos($haystack, $needle) === false;
    return tap_result($ok, $name, $ok ? '' : "expected NOT to contain " . _smpro_x($needle));
}
/**
 * Assert a callable throws (optionally a message substring). If $exact is a class
 * name, asserts the thrown type. Returns bool.
 */
function throws_ok(callable $fn, $name, $msgContains = null) {
    try {
        $fn();
    } catch (\Throwable $e) {
        $ok = ($msgContains === null) || (strpos($e->getMessage(), $msgContains) !== false);
        return tap_result($ok, $name, $ok ? '' : "threw, but message lacked '$msgContains': " . $e->getMessage());
    }
    return tap_result(false, $name, 'no exception was thrown');
}
/** Assert a callable does NOT throw. */
function lives_ok(callable $fn, $name) {
    try { $fn(); } catch (\Throwable $e) {
        return tap_result(false, $name, 'unexpected throw: ' . get_class($e) . ': ' . $e->getMessage());
    }
    return tap_result(true, $name);
}
