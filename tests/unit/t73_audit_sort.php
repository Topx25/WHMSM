<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/breakin.php';
/**
 * t73_audit_sort.php — Account Audit orders the whole result, not the page being looked at.
 *
 * THE INCIDENT. The events table was sorted in the browser by the shared table script, which reorders the rows
 * it can see. On a live server that was fifty rows out of 15,242, across 305 pages — and the column header put an
 * arrow on itself, which says "this table is sorted", not "these fifty rows are".
 *
 * So an operator clicked Type to gather the successful logins, saw the handful that happened to be on that page,
 * and read it underneath a counter saying 533. Measured on dc1: the server's own page 1 held 13 successful
 * logins and one of them was row 1 — sorting by Type pushed all 13 below 37 failed rows, because "Failed" sorts
 * before "Successful".
 *
 * Nothing was wrong with the data. The control simply promised more than it did, which is this product's own
 * failure class wearing a different hat: the screen said something the thing behind it could not back up.
 */

/* ---------- a result that spans more than one page, as the real one does ---------- */
$ev = [];
for ($i = 1; $i <= 120; $i++) {
    // 8 successes in 120 events — roughly the 3.5% the live server actually shows
    $success = ($i % 15 === 0);
    $ev[] = [
        'ts'         => 1700000000 + $i,
        'type'       => $success ? 'Successful Login' : 'Failed Login',
        'kind'       => $success ? 'success_login' : 'failed_login',
        'result'     => $success ? 'Successful Login' : 'Failed Login Attempt',
        'service'    => $success ? 'cpaneld' : 'whostmgrd',
        'ip'         => '203.0.113.' . (($i % 7) + 1),
        'login_user' => 'user' . str_pad((string)($i % 9), 2, '0', STR_PAD_LEFT),
        'account'    => 'acct' . str_pad((string)($i % 5), 2, '0', STR_PAD_LEFT),
        'action'     => $success ? 'The account password was accepted' : 'Rejected login attempt',
    ];
}
$perPage = 50;

/* ---------- U1: the keys are a whitelist, not whatever the URL says ---------- */
$keys = smpro_aa_sort_keys();
ok(isset($keys['time'], $keys['type'], $keys['ip']), 'U1: the sortable columns are declared');
is_eq($keys['time'], 'ts', 'U1: Time sorts on the numeric timestamp');
ok(!isset($keys['details']), 'U1: a column with nothing to compare is not sortable');
// an unknown key must fall back, never reach into an arbitrary field
$fallback = smpro_aa_sort_events($ev, 'evidence; DROP', 'desc');
is_eq(count($fallback), 120, 'U1: an unknown key is ignored rather than obeyed');
is_eq($fallback[0]['ts'], 1700000120, 'U1: and falls back to newest-first');

/* ---------- U2: THE ONE THAT MATTERS — sorting gathers the whole result ---------- */
// Not "the successes on this page move up". ALL of them, from anywhere in the result, onto page 1.
$byType = smpro_aa_sort_events($ev, 'type', 'desc');          // 'Successful' > 'Failed'
$page1  = array_slice($byType, 0, $perPage);
$onPage1 = count(array_filter($page1, fn($e) => $e['kind'] === 'success_login'));
$total   = count(array_filter($ev,    fn($e) => $e['kind'] === 'success_login'));
is_eq($total, 8, 'U2: the fixture holds 8 successful logins spread through 120 events');
is_eq($onPage1, 8, 'U2: sorting by Type puts EVERY one of them on page 1 — not just the ones already there');
is_eq($page1[0]['kind'], 'success_login', 'U2: and the first row is one of them');

// the other direction is the complement, and just as total
$asc = smpro_aa_sort_events($ev, 'type', 'asc');
is_eq(count(array_filter(array_slice($asc, 0, $perPage), fn($e) => $e['kind'] === 'success_login')), 0,
      'U2: ascending puts the failures first, and none of the successes leak onto page 1');

/* ---------- U3: every column orders by the field it names ---------- */
foreach (['ip' => 'ip', 'user' => 'login_user', 'account' => 'account', 'service' => 'service'] as $k => $f) {
    $s = smpro_aa_sort_events($ev, $k, 'asc');
    $vals = array_column($s, $f);
    $want = $vals; sort($want, SORT_FLAG_CASE | SORT_STRING);
    is_eq($vals, $want, 'U3: ' . $k . ' orders by ' . $f);
}
$t = array_column(smpro_aa_sort_events($ev, 'time', 'asc'), 'ts');
is_eq($t[0] < $t[119], true, 'U3: time ascending really is oldest first');

/* ---------- U4: the order is TOTAL, so a page boundary cannot wobble ---------- */
// Two events that tie on the sorted column must still have a fixed order, or the same query returns a different
// page 2 on the next load and a row can hide between pages for ever.
$tied = [];
foreach ([5, 3, 9, 1, 7] as $n) $tied[] = ['ts' => 1700000000 + $n, 'type' => 'Failed Login', 'ip' => 'same'];
$a = array_column(smpro_aa_sort_events($tied, 'type', 'desc'), 'ts');
$b = array_column(smpro_aa_sort_events(array_reverse($tied), 'type', 'desc'), 'ts');
is_eq($a, $b, 'U4: rows that tie come back in the same order whatever order they arrived in');
is_eq($a[0], 1700000009, 'U4: and the tie-break is newest-first');

/* ---------- U5: the page must not ALSO be sorted in the browser ---------- */
// A page-only sort under a header arrow is what caused this. The table opts out of the shared script.
$mod = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/account-audit.php'));
has($mod, 'data-serversort="1"', 'U5: the events table opts out of the browser sort');
has($mod, 'smpro_aa_sort_events(', 'U5: and the page sorts through the shared helper');
$lay = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/layout.php'));
has($lay, "if(!t.hasAttribute('data-serversort'))bindSort(t)", 'U5: the shared script honours the opt-out');
has($lay, 'only, and on a paginated table that is a lie the arrow tells', 'U5: with the reason recorded where it is enforced');

/* ---------- U6: the sort survives paging, and so does the localhost setting ---------- */
// Paging used to drop showlocal entirely: hiding 127.0.0.1, then clicking Next, silently un-hid it.
has($mod, "'sort'=>\$aaSort,'dir'=>\$aaDir", 'U6: the pager carries the sort');
$pagerLine = '';
foreach (explode("\n", $mod) as $l) if (strpos($l, "if (\$pages > 1)") !== false) { $pagerLine = $l; break; }
has($pagerLine, "'showlocal'", 'U6: and the localhost setting, which it used to lose');

/* ---------- U7: the filters decide what the counters say, so they must be reachable ---------- */
// They lived in the page module, where no worker, test or diagnostic could call them. A probe written against
// them guarded with function_exists(), the guard was false, and the probe printed its numbers as though the
// country filter had been applied. The layering produced the product's own failure class.
ok(function_exists('smpro_aa_filter_country'), 'U7: the country filter is loadable outside the page');
ok(function_exists('smpro_aa_filter_local'),   'U7: and so is the localhost filter');
ok(function_exists('smpro_aa_count_local'),    'U7: and the localhost counter beside it');

$mix = [
    ['ts'=>3,'ip'=>'127.0.0.1','kind'=>'failed_login','type'=>'Failed Login'],
    ['ts'=>2,'ip'=>'::1',      'kind'=>'failed_login','type'=>'Failed Login'],
    ['ts'=>1,'ip'=>'8.8.4.4',  'kind'=>'success_login','type'=>'Successful Login'],
];
is_eq(count(smpro_aa_filter_local($mix, false)), 1, 'U7: hiding localhost removes 127.0.0.1 and ::1');
is_eq(count(smpro_aa_filter_local($mix, true)),  3, 'U7: showing it keeps them');
is_eq(smpro_aa_count_local($mix), 2, 'U7: and the count of what is hidden is reported, not guessed');
is_eq(count(smpro_aa_filter_country($mix, 'all')), 3, 'U7: "all" filters nothing');

$mod2 = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/account-audit.php'));
hasnt($mod2, 'function smpro_aa_filter_country(', 'U7: and they are no longer defined in the page as well');
ok(strpos($mod2, '<?php') === 0, 'U7: the module still starts with <?php — nothing leaks above it into the page');
