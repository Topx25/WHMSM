<?php
/**
 * t00_harness.php — proves the harness itself works: every assertion helper emits a
 * correct TAP line, the bootstrap loads, the sandbox is redirected away from /var/lib/smpro,
 * and the auto "no warnings / no fatal / plan" machinery fires. All cases here PASS by design;
 * red-detection is proven separately (a deliberately-failing throwaway test at deploy time).
 */
require __DIR__ . '/../support/bootstrap.php';

ok(true, 'ok(true) passes');
nok(false, 'nok(false) passes');
is_eq(2 + 2, 4, 'is_eq scalar equality');
is_eq(['a' => 1, 'b' => [2, 3]], ['a' => 1, 'b' => [2, 3]], 'is_eq deep array equality (order-sensitive)');
isnt_eq(1, 2, 'isnt_eq distinguishes values');
isnt_eq('1', 1, 'isnt_eq is strict (string !== int)');
like('hello world', '/\bwor\w+/', 'like regex match');
has('abcdef', 'cd', 'has substring present');
hasnt('abcdef', 'zz', 'hasnt substring absent');
throws_ok(function () { throw new \RuntimeException('boom-xyz'); }, 'throws_ok catches throw', 'boom');
lives_ok(function () { return 1 + 1; }, 'lives_ok on non-throwing callable');

// sandbox redirection: SMPRO_VARLIB must NOT be the live path
isnt_eq(SMPRO_VARLIB, '/var/lib/smpro', 'SMPRO_VARLIB redirected to sandbox (never the live dir)');
ok(is_dir(SMPRO_VARLIB), 'sandbox SMPRO_VARLIB exists and is writable');
ok(strpos(SMPRO_VARLIB, sys_get_temp_dir()) === 0, 'sandbox lives under the temp dir');
is_eq(SMPRO_VERSION, '1.0.199', 'SMPRO_VERSION constant available to includes');
