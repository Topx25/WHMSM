<?php
/**
 * t64_nav_search.php — the panel's feature search.
 *
 * A search that cannot find a feature is worse than no search: it answers "we don't have that" about something we
 * do have. So the two things worth asserting are that the index is DERIVED from the menu the sidebar draws (it
 * cannot go stale), and that it can never show a page this licence is not allowed to open.
 */
require __DIR__ . '/../support/bootstrap.php';
require SMPRO_BASE . '/tests/support/plugin_funcs.php';
smpro_plugin_funcs('includes/menu.php');

$src = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/menu.php'));

/* ---------- N1: one list, not two ---------- */
ok(function_exists('smpro_menu_search_index'), 'N1: the index is built by code, not typed out');
has($src, 'smpro_menu_search_box(smpro_menu_search_index($visible));',
    'N1: ...from the same $visible list the sidebar links are drawn from');
has($src, 'Deriving it rather than keeping a second list is the whole point', 'N1: with the reason recorded');
// The licence filter must run BEFORE the index is built, or the search becomes a way to see what you cannot open.
$posFilter = strpos($src, "if (\$enforce && \$it['id'] !== 'license' && !smpro_lic_section_allowed(\$it['feature'] ?? '')) continue;");
$posIndex  = strpos($src, 'smpro_menu_search_box(smpro_menu_search_index($visible));');
ok($posFilter !== false && $posIndex !== false && $posFilter < $posIndex,
   'N1: the licence filter runs BEFORE the index is built, so a plan cannot search its way to a locked page');
is_eq(substr_count($src, "!smpro_lic_section_allowed(\$it['feature'] ?? '')"), 1,
   'N1: and that filter exists in exactly one place — two copies is how they start disagreeing');

/* ---------- N2: every page is findable, and describes itself ---------- */
preg_match_all("/'id'\s*=>\s*'([a-z0-9-]+)'/", $src, $im);
$ids = array_values(array_unique($im[1]));
$blurbs = smpro_menu_blurbs();
$missing = array_values(array_diff($ids, array_keys($blurbs)));
is_eq($missing, [], 'N2: every page in the menu has a one-line description' . ($missing ? ' — missing: ' . implode(', ', $missing) : ''));
$empty = [];
foreach ($blurbs as $k => $v) if (trim((string)$v) === '') $empty[] = $k;
is_eq($empty, [], 'N2: and none of them is blank');
ok(count($blurbs) >= 30, 'N2: ' . count($blurbs) . ' pages described');

/* the description is the JOB, which is what somebody actually searches for */
has($blurbs['user-investigation'], 'who deleted', 'N2: "who deleted" finds User Investigation');
has($blurbs['firewall-status'], 'Blocked and allowed addresses', 'N2: the firewall page says what it holds');
has($blurbs['php-harden'], 'restrict where it may be signed into', 'N2: ...including the country lock added to it');

/* ---------- N3: the index carries what a person would type ---------- */
$idx = smpro_menu_search_index(['Reports' => [
    ['id' => 'reports-center', 'label' => 'Reports Center', 'icon' => 'X', 'aliases' => ['ip-report', 'ip-lookup']],
]]);
is_eq(count($idx), 1, 'N3: one entry per visible page');
is_eq($idx[0]['id'], 'reports-center', 'N3: keyed by page id');
is_eq($idx[0]['section'], 'Reports', 'N3: with its section, so a result says where it lives');
has($idx[0]['alias'], 'ip-lookup', 'N3: aliases travel — the old name and the words people actually use');
has($idx[0]['about'], 'lookup on any IP', 'N3: and the description');
is_eq(smpro_menu_search_index([]), [], 'N3: nothing visible, nothing indexed');

/* a label with markup in it must not reach the client as markup */
$dirty = smpro_menu_search_index(['S' => [['id' => 'x', 'label' => 'A <b>B</b>', 'icon' => '', 'aliases' => []]]]);
is_eq($dirty[0]['label'], 'A B', 'N3: tags are stripped from labels before they are indexed');

/* ---------- N4: suggestions while typing, ranked so the obvious answer is first ---------- */
has($src, "q.addEventListener('input', render);", 'N4: results update on every keystroke');
has($src, 'if (L === n) return 0;', 'N4: an exact name match ranks first');
has($src, "if (L.indexOf(n) === 0) return 1;", 'N4: then a name that starts with what was typed');
has($src, 'Somebody typing "fire" wants Firewall Status first', 'N4: ...and why that order, in the code');
has($src, 'hits.slice(0, 12)', 'N4: the list is capped so it stays scannable');
has($src, '<mark>', 'N4: the matched part is highlighted, so the reason a result appears is visible');

/* ---------- N5: usable without a mouse ---------- */
has($src, "if (e.key === 'ArrowDown')", 'N5: arrow keys move through results');
has($src, "else if (e.key === 'Enter'){ if (cur>=0){ e.preventDefault(); go(); } }", 'N5: Enter opens the highlighted one');
has($src, "else if (e.key === 'Escape')", 'N5: Escape closes, then clears');
has($src, "if (e.key !== '/' || e.ctrlKey || e.metaKey || e.altKey) return;", 'N5: "/" focuses it from anywhere');
has($src, "if (tag === 'input' || tag === 'textarea' || tag === 'select' || (t && t.isContentEditable)) return;",
    'N5: ...but never while something is being typed into — that would swallow a slash meant for a path');
has($src, "role=\"combobox\"", 'N5: announced correctly to a screen reader');
has($src, "aria-selected", 'N5: with the highlighted option marked');
has($src, "q.setAttribute('aria-expanded','true');", 'N5: and its open state kept truthful');

/* ---------- N6: it costs nothing ---------- */
hasnt($src, "fetch('index.cgi?page=", 'N6: searching makes no request — the index is already on the page');
has($src, 'no request, no spinner', 'N6: which is the point, and is stated');
has($src, 'Nothing matches', 'N6: an empty result says so plainly rather than showing a blank panel');
