<?php
require __DIR__ . '/../support/bootstrap.php';
/** t103 - the section-tab kit (tile/nav/collapse CSS + table pager) is served once by the layout, never duplicated byte-for-byte in a module. */
$lay = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/layout.php'));
has($lay, '.fw-kpis{display:grid', 'U1: layout carries the tile strip rules');
has($lay, '.fw-nav{position:sticky', 'U1: layout carries the navigator rules');
has($lay, '.fw-pgbar{display:flex', 'U1: layout carries the pager bar rules');
has($lay, 'window.smproPager=function(o){', 'U1: layout defines the table pager once');
ok(strpos($lay, 'window.smproPager=function') < strpos($lay, 'function smpro_layout_footer'), 'U1: ...in the header, before any module script');
has($lay, 'window.smproTabs=true', 'U1: layout carries the section-tabs behaviour');
$pager = 0; $strip = 0;
foreach (glob(SMPRO_BASE . '/modules/*.php') as $f) {
    $s = str_replace(chr(13), '', (string)file_get_contents($f));
    $pager += substr_count($s, 'window.smproPager=function(o){');
    $strip += substr_count($s, ".fw-kpi .l{font-size:10.5px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}\n.fw-kpi .v{font-size:19px");
}
is_eq($pager, 0, 'U2: no module re-defines window.smproPager');
is_eq($strip, 0, 'U2: no module carries the exact kit copy of the tile rules');
