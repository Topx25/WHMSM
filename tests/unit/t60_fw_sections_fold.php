<?php
/**
 * t60_fw_sections_fold.php — Recommended allow-lists folds like every other section on the page.
 *
 * Every card on Firewall Status was made collapsible by one loop over `.card > .tp-th`. That section carries its
 * own header class (`.fwrec-hd`), so it was silently excluded: a long optional list, always open, that most visits
 * scroll past on the way to the blocked addresses underneath it.
 */
require __DIR__ . '/../support/bootstrap.php';

$fs = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/firewall-status.php'));

/* ---------- F1: it is part of the same mechanism, not a second one ---------- */
has($fs, ".card > .tp-th, .smpro-main .card > .fwrec-hd')", 'F1: the one collapser now covers this header too');
is_eq(substr_count($fs, "className='fw-collapse'"), 1, 'F1: there is still exactly ONE folding implementation on the page');

/* ---------- F2: this one starts closed, the others do not ---------- */
has($fs, "var closedByDefault = card.classList.contains('fwrec');", 'F2: only the recommendations start folded');
has($fs, 'var isOpen = Object.prototype.hasOwnProperty.call(open, id) ? !!open[id] : !closedByDefault;',
    'F2: ...and a section the operator has never touched uses that default, while one they have keeps their choice');
has($fs, "card.classList.toggle('fw-open', isOpen);", 'F2: applied on load, so the page does not flash open then close');

/* ---------- F3: the choice survives the next page load ---------- */
has($fs, "var KEY='smpro:fw:open';", 'F3: the open/closed state is remembered');
has($fs, "th.setAttribute('data-fold', id);", 'F3: keyed by the section');
has($fs, "var id=(th.textContent||'').replace(/\\s+/g,' ').trim().slice(0,60)",
    'F3: ...by its heading text, not its position — a new section above it would otherwise shift everybody\'s remembered state');
has($fs, "try{ open=JSON.parse(localStorage.getItem(KEY)||'{}')||{}; }catch(err){ open={}; }",
    'F3: and unreadable storage (private window, blocked site data) falls back to the defaults instead of throwing');
has($fs, 'function remember(){ try{ localStorage.setItem(KEY, JSON.stringify(open)); }catch(err){} }',
    'F3: ...as does unwritable storage');

/* ---------- F4: a header that toggles has to be usable as a control ---------- */
has($fs, "th.setAttribute('role','button');", 'F4: it announces itself as a button');
has($fs, "th.setAttribute('tabindex','0');", 'F4: reachable by keyboard');
has($fs, "th.setAttribute('aria-expanded', isOpen ? 'true' : 'false');", 'F4: with its state');
has($fs, "th.setAttribute('aria-expanded', nowOpen ? 'true' : 'false');", 'F4: ...kept correct when it changes');
has($fs, "if(e.key===' '||e.key==='Enter'||e.key==='Spacebar'){ e.preventDefault(); toggle(); }", 'F4: Space and Enter work');
has($fs, "if(e.target.closest('a,button,input,select,label,.fw-chk'))return;",
    'F4: and using a control INSIDE the header does not fold the section out from under the hand using it');
has($fs, '.fwrec-hd:hover{background:rgba(127,127,127,.06)}', 'F4: it looks clickable before it is clicked');
has($fs, 'user-select:none', 'F4: ...and clicking it does not select its text instead');
has($fs, '.card:not(.fw-open)>.fwrec-hd{border-bottom:0}', 'F4: closed, its bottom rule does not float under nothing');
