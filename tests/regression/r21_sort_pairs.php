<?php
/**
 * r21_sort_pairs.php — sorting a table must not tear an expandable row away from its parent.
 *
 * Account Audit renders TWO <tr> per event: the record, then a hidden full-width detail row. The universal sort
 * engine used to treat both as records; the detail row has no cell at the sorted column, which compared as empty,
 * so clicking TYPE sent every detail row to the top. The customer saw a page of blank rows (2026-09-09).
 */
require __DIR__ . '/../support/bootstrap.php';

$js = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/layout.php'));

has($js, "function isChild(r){return r.hasAttribute('data-child')||(r.cells.length===1&&(r.cells[0].colSpan||1)>1);}",
    'S1: a one-cell full-width row is recognised as a detail row, not a record');
has($js, "all.forEach(function(r){if(isChild(r)){if(rows.length)kids[rows.length-1].push(r);}",
    'S2: each detail row is attached to the record above it');
has($js, "order.forEach(function(i){tb.appendChild(rows[i]);kids[i].forEach(function(k){tb.appendChild(k);});});",
    'S3: ...and travels with it when the order changes');
has($js, '||(a-b);', 'S4: equal values keep the order the server sent, so a sort is stable and not shuffled');
hasnt($js, "rows.forEach(function(r){tb.appendChild(r);});}", 'S5: the old tear-them-apart append is gone');

/* The markup this exists for: the detail row really is one full-width cell. */
$aa = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/account-audit.php'));
has($aa, '<tr class="aa-det"><td colspan="9">', 'S6: Account Audit still renders the detail row the engine now pairs');
