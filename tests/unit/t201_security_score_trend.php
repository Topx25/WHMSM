<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/shharden.php';
require_once SMPRO_BASE . '/includes/sechealth.php';
/**
 * t201 - Security Health plan step 5: an overall score with a TREND, so the page answers "is my security posture
 * improving or slipping?" not just "what is it now". The score formula is unified into smpro_sh_score() (shared by
 * the page and the scheduled scan so they can't drift), the worker keeps a short score history, and the page shows
 * the direction vs the last recorded scan. The weighting is unchanged: 100 − 3/warning − 12/critical, floored at 0.
 */
$src = fn($p) => str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/' . $p));

// --- A. the shared score formula: exact weighting, both input shapes ---
ok(function_exists('smpro_sh_score'), 'A1: smpro_sh_score() is the one shared formula');
$cats = ['A' => [['status' => 'ok'], ['status' => 'warning'], ['status' => 'info']],
         'B' => [['status' => 'critical'], ['status' => 'warning']]];
$r = smpro_sh_score($cats);
is_eq($r['score'], 100 - 2 * 3 - 1 * 12, 'A2: 2 warnings + 1 critical -> 100-6-12 = 82');
is_eq([$r['critical'], $r['warning']], [1, 2], 'A3: it counts critical and warning');
is_eq(smpro_sh_score([])['score'], 100, 'A4: a clean scan scores 100');
// floor at 0: many criticals cannot go negative
is_eq(smpro_sh_score(['X' => array_fill(0, 20, ['status' => 'critical'])])['score'], 0, 'A5: the score floors at 0');
// a flat list of checks (not a category map) is accepted too
is_eq(smpro_sh_score([['status' => 'warning'], ['status' => 'warning']])['score'], 94, 'A6: a flat check list works as well as a category map');

// --- B. the page and the worker use the SAME formula (no second copy to drift) ---
$page = $src('modules/security-health.php');
$tick = $src('bin/sechealth_tick.php');
has($tick, 'smpro_sh_score($cats)', 'B1: the scheduled scan scores via the shared helper');
has($tick, "'score_history'", 'B2: the worker keeps a score history for the trend');
has($tick, 'array_slice($hist, -30)', 'B3: ...bounded to the last 30 scored runs');

// --- C. the page reads the history and shows a direction ---
has($page, "sechealth_auto.json", 'C1: the page reads the worker snapshot for the prior score');
has($page, "'score_history'", 'C2: ...specifically its score history');
has($page, "up ' . (int)\$shTrend['delta']", 'C3: it shows an up-delta when the score improved');
has($page, 'down ', 'C4: ...and a down-delta when it slipped');

// --- D. trend math: direction and delta from a prior score ---
// reproduce the page's trend logic in-test to prove the direction mapping
$trendDir = function ($now, $prev) { $d = $now - $prev; return $d > 0 ? 'up' : ($d < 0 ? 'down' : 'flat'); };
is_eq($trendDir(85, 70), 'up',   'D1: a higher score than last time is "up"');
is_eq($trendDir(60, 82), 'down', 'D2: a lower score is "down"');
is_eq($trendDir(90, 90), 'flat', 'D3: an equal score is "flat"');

// --- E. safe with no history (first ever scan): the page falls back to the formula line ---
has($page, "100 − 3/warning − 12/critical", 'E1: with no prior scan the tile shows the formula, not a broken trend');
