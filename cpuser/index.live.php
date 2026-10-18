<?php
/**
 * Safety Lock — the page the account holder opens inside cPanel.
 *
 * It runs as the ACCOUNT, never as root, and that single fact shapes everything. The protection people actually
 * want here is the immutable bit, and setting it needs root — so this page does not set anything of the sort. It
 * ASKS. Every privileged action becomes a request the server's operator approves in WHM, and the account is told
 * plainly that it has asked rather than done.
 *
 * That applies in both directions on purpose. Asking to be protected and asking to be released are both decisions
 * about someone else's server, and a queue that only guarded one direction would be theatre: an account able to
 * release itself is an account that can switch off its own protection the moment it is broken into.
 *
 * The one thing the account genuinely can do alone is refuse code execution inside its own upload folders, because
 * that is an .htaccess it owns. That happens immediately, with no request, and it is the single most effective
 * control on this page.
 *
 * SAFETY OF THE REQUEST FORMAT. A request never carries an absolute path. It carries paths RELATIVE to a document
 * root, and root joins them to a document root it resolved by itself from the server's own records. A compromised
 * account therefore cannot name /etc/shadow and cannot escape its own tree by spelling; root additionally refuses
 * traversal, symlinks, and anything the account does not own.
 */

$HOME = getenv('HOME') ?: (posix_getpwuid(posix_geteuid())['dir'] ?? '');
$USER = posix_getpwuid(posix_geteuid())['name'] ?? (getenv('USER') ?: '');

/* ---------------------------------------------------------------- LiveAPI -- */
$cpanel = null;
if (is_file('/usr/local/cpanel/php/cpanel.php')) require_once '/usr/local/cpanel/php/cpanel.php';
if (class_exists('CPANEL')) { try { $cpanel = new CPANEL(); } catch (Throwable $e) { $cpanel = null; } }

function sp_header($cpanel, $title) {
    if ($cpanel) { echo $cpanel->header($title); return; }
    echo "<!doctype html><meta charset='utf-8'><title>" . htmlspecialchars($title) . "</title>";
}
function sp_footer($cpanel) { if ($cpanel) echo $cpanel->footer(); }
function sp_h($s) { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }

require_once __DIR__ . '/stack.php';       // detection, generated from the WHM side so both sides agree

/* ------------------------------------------------------------- doc roots -- */
/**
 * The account's web roots. cPanel is asked first because it is the only thing that truly knows which domains
 * belong here; the fallback is public_html alone, deliberately narrow, because guessing at sibling directories
 * would risk offering to modify something that is not a document root at all.
 */
function sp_docroots($cpanel, $home) {
    $roots = [];
    if ($cpanel) {
        try {
            $docs = $cpanel->uapi('DomainInfo', 'list_domains_data');
            foreach (($docs['cpanelresult']['result']['data'] ?? []) as $k => $v) {
                if (!is_array($v)) continue;
                $dr = (string)($v['documentroot'] ?? '');
                if ($dr !== '' && is_dir($dr)) $roots[realpath($dr) ?: $dr] = (string)($v['domain'] ?? $k);
            }
        } catch (Throwable $e) { /* fall through to the narrow default */ }
    }
    if (!$roots) { $p = $home . '/public_html'; if (is_dir($p)) $roots[realpath($p) ?: $p] = 'public_html'; }
    return $roots;
}

function sp_within($base, $path) {
    $b = realpath($base); $p = realpath($path);
    return $b && $p && ($p === $b || strpos($p, $b . '/') === 0);
}

/* ------------------------------------------------------------- the state -- */
function sp_state_dir($home) { return $home . '/.siteprotection'; }
function sp_state_load($home) {
    $j = json_decode((string)@file_get_contents(sp_state_dir($home) . '/state.json'), true);
    return is_array($j) ? $j : [];
}
function sp_state_save($home, array $s) {
    $d = sp_state_dir($home);
    @is_dir($d) || @mkdir($d, 0700, true);
    $s['updated'] = date('c');
    $tmp = $d . '/state.json.tmp';
    if (@file_put_contents($tmp, json_encode($s, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), LOCK_EX) === false) return false;
    @chmod($tmp, 0600);
    return @rename($tmp, $d . '/state.json');
}
function sp_log($home, $msg, array $extra = []) {
    $d = sp_state_dir($home);
    @is_dir($d) || @mkdir($d, 0700, true);
    @file_put_contents($d . '/activity.log',
        json_encode(['t' => date('c'), 'msg' => $msg, 'extra' => $extra], JSON_UNESCAPED_SLASHES) . "\n",
        FILE_APPEND | LOCK_EX);
}

/* ------------------------------------------- the one thing done directly -- */
define('SP_MARK_START', '# SAFETYLOCK_DENY_EXEC_START');
define('SP_MARK_END',   '# SAFETYLOCK_DENY_EXEC_END');

/** Make a folder refuse to execute code. The account owns the .htaccess, so this needs nobody's approval. */
function sp_guard_dir($home, $dir, $on) {
    if (!sp_within($home, $dir) || !is_dir($dir) || is_link($dir)) return ['ok' => false, 'msg' => 'That folder is not inside your account.'];
    $ht  = rtrim($dir, '/') . '/.htaccess';
    $cur = is_file($ht) ? (string)@file_get_contents($ht) : '';
    $stripped = preg_replace('/\n?' . preg_quote(SP_MARK_START, '/') . '.*?' . preg_quote(SP_MARK_END, '/') . '\s*/s', '', $cur);

    if (!$on) {
        if (trim((string)$stripped) === '') @unlink($ht);
        elseif (@file_put_contents($ht, rtrim((string)$stripped) . "\n", LOCK_EX) === false) return ['ok' => false, 'msg' => 'Could not write ' . basename($ht) . '.'];
        return ['ok' => true, 'msg' => 'Code can run in that folder again.'];
    }
    $block = SP_MARK_START . "\n<FilesMatch \"\\.(php|phtml|phar|php[0-9]|cgi|pl|py)$\">\n  Require all denied\n</FilesMatch>\nphp_flag engine off\n" . SP_MARK_END . "\n";
    $new   = rtrim((string)$stripped) === '' ? $block : rtrim((string)$stripped) . "\n\n" . $block;
    if (is_file($ht)) @copy($ht, sp_state_dir($home) . '/htaccess_' . sha1($ht) . '.bak');
    if (@file_put_contents($ht, $new, LOCK_EX) === false) return ['ok' => false, 'msg' => 'Could not write ' . basename($ht) . ' — check the folder is writable.'];
    // Read it back. A write that reported success but did not land is the failure worth catching.
    if (strpos((string)@file_get_contents($ht), SP_MARK_START) === false) {
        return ['ok' => false, 'msg' => 'The file was written but the guard is not in it. Nothing is protected there.'];
    }
    return ['ok' => true, 'msg' => 'Code can no longer run in that folder.'];
}

/** true / false / null. null means it could not be read, and is never reported as "not locked". */
function sp_is_immutable($file) {
    $out = []; $rc = 1;
    @exec('lsattr -d ' . escapeshellarg($file) . ' 2>/dev/null', $out, $rc);
    if ($rc !== 0 || !$out) return null;
    $flags = preg_split('/\s+/', trim($out[0]))[0] ?? '';
    return strpos($flags, 'i') !== false;
}

/* --------------------------------------------------------- the requests -- */
function sp_reqdir($home) { return sp_state_dir($home) . '/requests'; }

/**
 * Ask the server to do something only it can do.
 *
 * $items are paths RELATIVE to the chosen document root. They are checked here for shape and again, properly, by
 * root — this side's check is a courtesy to the person using the page, never a security boundary.
 */
function sp_request($home, $verb, $reason = '', $rootKey = '', array $items = [], $unlockTime = '') {
    $allowed = ['apply_fast', 'apply_custom', 'unlock_selected', 'unlock_permanent'];
    if (!in_array($verb, $allowed, true)) return ['ok' => false, 'msg' => 'That is not something this page can ask for.'];

    $dir = sp_reqdir($home);
    @is_dir($dir) || @mkdir($dir, 0700, true);
    if (!is_dir($dir)) return ['ok' => false, 'msg' => 'Could not create the request folder in your account.'];

    // One at a time. Several queued at once would run in an order nobody chose, with the last one winning.
    foreach (glob($dir . '/*.json') ?: [] as $ignored) {
        return ['ok' => false, 'msg' => 'A request is already waiting with your host. Give it a moment.'];
    }

    $reason = trim(preg_replace('/[^\p{L}\p{N} .,\/:@()_+\-]/u', ' ', (string)$reason));
    $reason = function_exists('mb_substr') ? mb_substr($reason, 0, 200) : substr($reason, 0, 200);
    if ($verb === 'unlock_permanent' && $reason === '') {
        return ['ok' => false, 'msg' => 'Give a reason. Your host has to decide on this, and they cannot decide on a blank request.'];
    }

    $clean = [];
    foreach ($items as $it) {
        $it = trim((string)$it);
        if ($it === '' || $it[0] === '/' || strpos($it, '..') !== false) continue;   // relative, no traversal
        $clean[] = $it;
        if (count($clean) >= 200) break;
    }
    // A permanent release is not a file operation. It stops this ACCOUNT being protected at all — every lock comes
    // off and nothing automatic puts one back — so it carries no selection, and asking for one would misdescribe
    // what is about to happen.
    if ($verb === 'unlock_permanent') $clean = [];
    elseif (in_array($verb, ['apply_custom', 'unlock_selected'], true) && !$clean) {
        return ['ok' => false, 'msg' => 'Nothing was selected, so there is nothing to ask for.'];
    }

    $id = bin2hex(random_bytes(8));
    // The address the customer is on is sent along so the operator can see it. It is NOT what any automatic
    // rule decides on: this file is written by the account, so a breached account could put any address it
    // liked here. The server establishes the real one from its own login records and compares the two.
    $ip = (string)($_SERVER['REMOTE_ADDR'] ?? '');
    if (!filter_var($ip, FILTER_VALIDATE_IP)) $ip = '';

    $payload = ['verb' => $verb, 'reason' => $reason, 'root' => (string)$rootKey,
                'items' => $clean, 'unlock' => (string)$unlockTime, 'ip' => $ip, 'at' => date('c')];
    if (@file_put_contents($dir . '/' . $id . '.json', json_encode($payload, JSON_UNESCAPED_SLASHES), LOCK_EX) === false) {
        return ['ok' => false, 'msg' => 'Could not write the request. Check that your home directory is not full.'];
    }
    @chmod($dir . '/' . $id . '.json', 0600);
    return ['ok' => true, 'msg' => 'Sent. Locking is carried out within about a minute; a release waits for your host to approve it.'];
}

function sp_last_result($home) {
    $best = null; $bestT = 0;
    foreach (glob(sp_state_dir($home) . '/results/*.json') ?: [] as $f) {
        $t = (int)@filemtime($f);
        if ($t >= $bestT) { $bestT = $t; $j = json_decode((string)@file_get_contents($f), true); if (is_array($j)) $best = $j; }
    }
    return $best;
}
function sp_pending($home) { return (bool)(glob(sp_reqdir($home) . '/*.json') ?: []); }

/* ---------------------------------------------------------- the browser -- */
/** One directory listing, as the account sees it. Never leaves the document root, never follows a link. */
function sp_browse($root, $rel) {
    $rel = trim((string)$rel, '/');
    if (strpos($rel, '..') !== false) $rel = '';
    $dir = $rel === '' ? $root : $root . '/' . $rel;
    if (!is_dir($dir) || !sp_within($root, $dir)) { $dir = $root; $rel = ''; }

    $rows = [];
    try {
        foreach (new DirectoryIterator($dir) as $f) {
            if ($f->isDot() || $f->isLink()) continue;
            $rows[] = ['name' => $f->getFilename(), 'rel' => ($rel === '' ? '' : $rel . '/') . $f->getFilename(),
                       'path' => $f->getPathname(), 'dir' => $f->isDir(),
                       'size' => $f->isDir() ? 0 : (int)$f->getSize(), 'mtime' => (int)$f->getMTime()];
        }
    } catch (Throwable $e) {}
    usort($rows, function ($a, $b) { return [$b['dir'], strtolower($a['name'])] <=> [$a['dir'], strtolower($b['name'])]; });
    return ['rel' => $rel, 'dir' => $dir, 'rows' => $rows];
}

function sp_status_of($p, $isDir) {
    if ($isDir) {
        $ht = rtrim($p, '/') . '/.htaccess';
        return (is_file($ht) && strpos((string)@file_get_contents($ht), SP_MARK_START) !== false) ? 'guarded' : 'writable';
    }
    if (sp_is_immutable($p) === true) return 'locked';
    if ((@fileperms($p) & 0222) === 0) return 'readonly';
    return 'writable';
}

function sp_size_h($b) {
    if ($b >= 1048576) return round($b / 1048576, 1) . ' MB';
    if ($b >= 1024) return round($b / 1024) . ' KB';
    return $b . ' B';
}

/* ------------------------------------------------------------ the action -- */
$notice = null;
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    $state = sp_state_load($HOME);
    $act   = (string)($_POST['sp_action'] ?? '');
    $want  = (string)($state['token'] ?? '');

    if ($want === '' || !hash_equals($want, (string)($_POST['sp_token'] ?? ''))) {
        $notice = ['ok' => false, 'msg' => 'That request could not be verified. Reload the page and try again.'];
    } elseif ($act === 'guard') {
        $notice = sp_guard_dir($HOME, (string)($_POST['dir'] ?? ''), ($_POST['on'] ?? '') === '1');
        sp_log($HOME, 'guard', $notice);
    } elseif ($act === 'ask') {
        $notice = sp_request($HOME, (string)($_POST['verb'] ?? ''), (string)($_POST['reason'] ?? ''),
                             (string)($_POST['root'] ?? ''), (array)($_POST['items'] ?? []),
                             (string)($_POST['unlock'] ?? ''));
        sp_log($HOME, 'request ' . ($_POST['verb'] ?? ''), $notice);
    }
}

/* --------------------------------------------------------------- render -- */
$state = sp_state_load($HOME);
if (empty($state['token'])) { $state['token'] = bin2hex(random_bytes(16)); sp_state_save($HOME, $state); }
$TOKEN = $state['token'];

$roots    = sp_docroots($cpanel, $HOME);
$rootKeys = array_keys($roots);
$curRoot  = (string)($_GET['root'] ?? ($rootKeys[0] ?? ''));
if (!isset($roots[$curRoot])) $curRoot = (string)($rootKeys[0] ?? '');

$mode  = (($_GET['mode'] ?? 'fast') === 'custom') ? 'custom' : 'fast';
$det   = $curRoot !== '' ? sp_detect($curRoot) : ['label' => 'Nothing found', 'confidence' => '—', 'key' => '', 'evidence' => []];
$files = $curRoot !== '' ? sp_standard_files($curRoot, $det['key']) : [];
$dirs  = $curRoot !== '' ? sp_upload_dirs($curRoot, $det['key']) : [];

$nProt = 0; $nTotal = 0;
foreach ($files as $f) { $nTotal++; if (in_array(sp_status_of($f['path'], false), ['locked', 'readonly'], true)) $nProt++; }
foreach ($dirs as $d)  { $nTotal++; if (sp_status_of($d['path'], true) === 'guarded') $nProt++; }

$pending = sp_pending($HOME);
$last    = sp_last_result($HOME);
$browse  = ($mode === 'custom' && $curRoot !== '') ? sp_browse($curRoot, (string)($_GET['d'] ?? '')) : null;
$suggest = [];
foreach ($files as $f) $suggest[$f['path']] = true;
foreach ($dirs as $d)  $suggest[$d['path']] = true;

sp_header($cpanel, 'Safety Lock');
?>
<style>
.sl{--ink:#0f172a;--mut:#64748b;--line:#e2e8f0;--card:#fff;--soft:#f8fafc;--blue:#2563eb;--blued:#1d4ed8;
    --green:#15803d;--greenbg:#dcfce7;--amber:#b45309;--amberbg:#fef3c7;--red:#b91c1c;--redbg:#fee2e2;
    font:14px/1.6 -apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;color:var(--ink);max-width:1180px}
.sl *{box-sizing:border-box}

.sl-hero{position:relative;overflow:hidden;border-radius:18px;padding:28px 30px;margin-bottom:18px;color:#fff;
  background:linear-gradient(115deg,#0b1220 0%,#132a5e 48%,#2451c7 100%)}
.sl-hero::after{content:"";position:absolute;top:-90px;right:-50px;width:260px;height:260px;border-radius:50%;background:rgba(255,255,255,.07)}
.sl-hero h1{font-size:27px;font-weight:800;margin:0 0 8px;letter-spacing:-.02em}
.sl-hero>p{margin:0 0 18px;max-width:74ch;font-size:14px;line-height:1.6;color:rgba(255,255,255,.82)}
.sl-stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;position:relative;z-index:1}
.sl-stat{background:rgba(255,255,255,.10);border:1px solid rgba(255,255,255,.18);border-radius:12px;padding:12px 15px}
.sl-stat .k{display:block;font-size:11px;font-weight:600;letter-spacing:.03em;color:rgba(255,255,255,.72);margin-bottom:4px}
.sl-stat .v{display:block;font-size:17px;font-weight:700}
.sl-stat .v small{font-weight:500;opacity:.7;font-size:13px}
.sl-hfoot{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-top:16px;position:relative;z-index:1}
.sl-path{font-family:ui-monospace,Consolas,monospace;font-size:12.5px;background:rgba(255,255,255,.10);
  border:1px solid rgba(255,255,255,.18);border-radius:9px;padding:6px 12px;color:#fff}
.sl-back{margin-left:auto;background:#fff;color:#1d4ed8;border-radius:10px;padding:9px 16px;font-weight:700;
  font-size:13.5px;text-decoration:none;display:inline-block}

.sl-card{background:var(--card);border:1px solid var(--line);border-radius:16px;margin-bottom:16px;overflow:hidden}
.sl-ch{display:flex;align-items:center;gap:12px;flex-wrap:wrap;padding:16px 20px}
.sl-ch h2{font-size:16px;font-weight:700;margin:0}
.sl-ch .sp{flex:1}

.sl-modes{display:grid;grid-template-columns:1fr 1fr;gap:14px;padding:0 20px 20px}
@media(max-width:760px){.sl-modes{grid-template-columns:1fr}}
.sl-mode{position:relative;display:block;border:1.5px solid var(--line);border-radius:14px;padding:18px 20px;
  text-decoration:none;color:inherit;background:var(--card)}
.sl-mode:hover{border-color:#bfdbfe}
.sl-mode.on{border-color:var(--blue);box-shadow:0 0 0 3px rgba(37,99,235,.10)}
.sl-mode .ic{width:38px;height:38px;border-radius:11px;background:var(--soft);display:flex;align-items:center;
  justify-content:center;font-size:18px;margin-bottom:12px}
.sl-mode b{display:block;font-size:15.5px;margin-bottom:5px}
.sl-mode span.d{display:block;font-size:13px;color:var(--mut);line-height:1.55;max-width:52ch}
.sl-tick{position:absolute;top:16px;right:16px;width:22px;height:22px;border-radius:50%;background:#cbd5e1;color:#fff;
  display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:700}
.sl-mode.on .sl-tick{background:var(--blue)}

.sl-chip{display:inline-block;font-size:12px;font-weight:600;padding:3px 11px;border-radius:20px;white-space:nowrap}
.sl-chip.b{background:#dbeafe;color:#1d4ed8}
.sl-chip.a{background:var(--amberbg);color:var(--amber)}
.sl-chip.g{background:var(--greenbg);color:var(--green)}
.sl-chip.n{background:#f1f5f9;color:var(--mut)}

.sl-two{display:grid;grid-template-columns:1fr 1fr;gap:16px;padding:0 20px 20px}
@media(max-width:760px){.sl-two{grid-template-columns:1fr}}
.sl-col{border:1px solid var(--line);border-radius:12px;overflow:hidden}
.sl-col h3{font-size:13.5px;font-weight:700;margin:0;padding:12px 15px;background:var(--soft);border-bottom:1px solid var(--line)}
.sl-col .in{padding:12px 15px}
.sl-item{font-family:ui-monospace,Consolas,monospace;font-size:12.5px;padding:8px 11px;border:1px solid var(--line);
  border-radius:9px;margin-bottom:7px;display:flex;gap:9px;align-items:center;justify-content:space-between}
.sl-item:last-child{margin-bottom:0}
.sl-none{font-size:13px;color:var(--mut);line-height:1.6}

.sl-tw{overflow-x:auto;border-top:1px solid var(--line)}
.sl-tbl{width:100%;border-collapse:collapse;font-size:13px}
.sl-tbl th{text-align:left;font-size:11px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;color:var(--mut);
  padding:11px 16px;background:var(--soft);border-bottom:1px solid var(--line);white-space:nowrap}
.sl-tbl td{padding:11px 16px;border-bottom:1px solid #f1f5f9;vertical-align:middle}
.sl-tbl tr:last-child td{border-bottom:0}
.sl-tbl tbody tr:hover{background:var(--soft)}
.sl-nm{font-weight:600}
.sl-nm a{color:var(--blue);text-decoration:none}
.sl-nm a:hover{text-decoration:underline}
.sl-sub{font-family:ui-monospace,Consolas,monospace;font-size:11px;color:#94a3b8;display:block;margin-top:2px}
.sl-num{font-variant-numeric:tabular-nums;color:var(--mut);white-space:nowrap}

.sl-tools{display:flex;gap:9px;align-items:center;flex-wrap:wrap;padding:12px 20px;border-top:1px solid var(--line)}
.sl-crumb{font-family:ui-monospace,Consolas,monospace;font-size:12px;color:var(--mut)}
.sl-root{background:#0f172a;color:#fff;font-size:11px;font-weight:700;padding:5px 11px;border-radius:8px}
.sl-in{font:400 13px/1.4 inherit;border:1px solid var(--line);border-radius:9px;padding:8px 12px}
.sl-in:focus{outline:2px solid #bfdbfe}

.sl-btn{font:600 13px/1 inherit;border:1px solid var(--line);background:#fff;color:var(--ink);border-radius:9px;
  padding:9px 15px;cursor:pointer;text-decoration:none;display:inline-block}
.sl-btn:hover{border-color:#94a3b8}
.sl-btn.p{background:var(--blue);border-color:var(--blue);color:#fff}
.sl-btn.p:hover{background:var(--blued)}
.sl-btn.g{background:var(--green);border-color:var(--green);color:#fff}
.sl-btn.g:hover{filter:brightness(1.08)}
.sl-btn.r{background:var(--red);border-color:var(--red);color:#fff}
.sl-btn.r:hover{filter:brightness(1.08)}
.sl-btn.s{padding:6px 11px;font-size:12px}
.sl-btn[disabled]{opacity:.5;cursor:not-allowed}

.sl-bar{display:flex;gap:12px;align-items:center;flex-wrap:wrap;padding:14px 20px;border-top:1px solid var(--line);background:var(--soft)}
.sl-bar .note{font-size:12px;color:var(--mut);margin-left:auto;text-align:right;max-width:44ch;line-height:1.5}

.sl-msg{padding:12px 16px;border-radius:11px;margin:0 0 16px;font-size:13.5px;line-height:1.6}
.sl-msg.ok{background:var(--greenbg);color:var(--green)}
.sl-msg.bad{background:var(--redbg);color:var(--red)}
.sl-msg.info{background:#e0f2fe;color:#075985}
.sl-msg.warn{background:var(--amberbg);color:var(--amber)}
.sl-body{padding:16px 20px;font-size:13.5px;color:var(--mut);line-height:1.65}
.sl-body b{color:var(--ink)}
.sl-legend{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:18px;padding:18px 20px}
.sl-legend p{margin:8px 0 0;font-size:12.8px;color:var(--mut);line-height:1.6}
</style>

<div class="sl">
  <div class="sl-hero">
    <h1>Safety Lock &mdash; PHP Hardening</h1>
    <p>Use <b>Fast Protection</b> for the recommended safe profile, or open <b>Custom Protection</b> when you need
    to choose exact files and folders inside your website root.</p>
    <div class="sl-stats">
      <div class="sl-stat"><span class="k">Detected Stack</span><span class="v"><?= sp_h($det['label']) ?></span></div>
      <div class="sl-stat"><span class="k">Confidence</span><span class="v"><?= sp_h($det['confidence']) ?></span></div>
      <div class="sl-stat"><span class="k">Protected Items</span><span class="v"><?= (int)$nProt ?> <small>/ <?= (int)$nTotal ?></small></span></div>
    </div>
    <div class="sl-hfoot">
      <?php if ($curRoot !== ''): ?><span class="sl-path"><?= sp_h($curRoot) ?></span><?php endif; ?>
      <a class="sl-back" href="/">Back to cPanel</a>
    </div>
  </div>

  <?php if ($notice): ?>
    <div class="sl-msg <?= $notice['ok'] ? 'ok' : 'bad' ?>"><?= $notice['ok'] ? '&#10003; ' : '&#9888; ' ?><?= sp_h($notice['msg']) ?></div>
  <?php endif; ?>

  <?php if ($pending): ?>
    <div class="sl-msg info">&#8987; A request is queued. Locking runs within about a minute; a release waits for your host.</div>
  <?php elseif ($last && !empty($last['msg'])): ?>
    <div class="sl-msg <?= !empty($last['ok']) ? 'ok' : 'bad' ?>"><?= !empty($last['ok']) ? '&#10003; ' : '&#9888; ' ?><?= sp_h($last['msg']) ?></div>
  <?php endif; ?>

  <?php if (count($roots) > 1): ?>
    <div class="sl-card"><div class="sl-ch">
      <h2>Website</h2>
      <?php foreach ($roots as $rk => $dom): ?>
        <a class="sl-btn s <?= $rk === $curRoot ? 'p' : '' ?>" href="?mode=<?= sp_h($mode) ?>&amp;root=<?= urlencode($rk) ?>"><?= sp_h($dom) ?></a>
      <?php endforeach; ?>
    </div></div>
  <?php endif; ?>

  <div class="sl-card">
    <div class="sl-ch"><h2>Choose Protection Mode</h2></div>
    <div class="sl-modes">
      <a class="sl-mode <?= $mode === 'fast' ? 'on' : '' ?>" href="?mode=fast&amp;root=<?= urlencode($curRoot) ?>">
        <span class="sl-tick">&#10003;</span>
        <div class="ic">&#9889;</div>
        <b>Fast Protection</b>
        <span class="d">Recommended automatic profile. Detects the application and protects its critical files,
        plus the upload, cache and log folders.</span>
      </a>
      <a class="sl-mode <?= $mode === 'custom' ? 'on' : '' ?>" href="?mode=custom&amp;root=<?= urlencode($curRoot) ?>">
        <span class="sl-tick">&#10003;</span>
        <div class="ic">&#129513;</div>
        <b>Custom Protection</b>
        <span class="d">Open the browser when you want to pick exact files or folders to protect or release.</span>
      </a>
    </div>
  </div>

<?php if ($mode === 'fast'): ?>
  <div class="sl-card">
    <div class="sl-ch">
      <h2>Fast Protection Preview</h2>
      <span class="sl-chip b"><?= sp_h($det['label']) ?></span>
      <span class="sl-chip <?= $det['confidence'] === 'high' ? 'g' : 'a' ?>">confidence: <?= sp_h($det['confidence']) ?></span>
      <span class="sp"></span>
      <form method="post" style="display:inline">
        <input type="hidden" name="sp_action" value="ask">
        <input type="hidden" name="sp_token" value="<?= sp_h($TOKEN) ?>">
        <input type="hidden" name="verb" value="apply_fast">
        <input type="hidden" name="root" value="<?= sp_h($curRoot) ?>">
        <button class="sl-btn p" type="submit" <?= ($pending || !$files) ? 'disabled' : '' ?>>&#9889; Apply Fast Protection</button>
      </form>
    </div>
    <div class="sl-body" style="padding-top:0">
      <?= $det['evidence'] ? sp_h(implode(' · ', $det['evidence'])) : 'Generic files detected' ?>
    </div>
    <div class="sl-two">
      <div class="sl-col">
        <h3>Critical files &mdash; locked by the server</h3>
        <div class="in">
          <?php if (!$files): ?><div class="sl-none">No standard files for this application were found here.</div><?php endif; ?>
          <?php foreach ($files as $f): $st = sp_status_of($f['path'], false); ?>
            <div class="sl-item"><span><?= sp_h($f['rel']) ?></span>
              <span class="sl-chip <?= $st === 'locked' ? 'g' : ($st === 'readonly' ? 'a' : 'n') ?>"><?= $st === 'locked' ? 'locked' : ($st === 'readonly' ? 'read-only' : 'writable') ?></span></div>
          <?php endforeach; ?>
        </div>
      </div>
      <div class="sl-col">
        <h3>Upload / cache / log folders &mdash; yours to switch</h3>
        <div class="in">
          <div class="sl-none" style="margin-bottom:9px">Blocks code from running inside these folders. Images keep
          working. This needs no approval &mdash; the file it writes belongs to you.</div>
          <?php if (!$dirs): ?><div class="sl-none">No standard upload, cache or log folders were detected.</div><?php endif; ?>
          <?php foreach ($dirs as $d): $on = sp_status_of($d['path'], true) === 'guarded'; ?>
            <form method="post" class="sl-item">
              <input type="hidden" name="sp_action" value="guard">
              <input type="hidden" name="sp_token" value="<?= sp_h($TOKEN) ?>">
              <input type="hidden" name="dir" value="<?= sp_h($d['path']) ?>">
              <input type="hidden" name="on" value="<?= $on ? '0' : '1' ?>">
              <span><?= sp_h($d['rel']) ?>/</span>
              <button class="sl-btn s <?= $on ? '' : 'g' ?>" type="submit"><?= $on ? '&#10003; blocked' : 'Block code' ?></button>
            </form>
          <?php endforeach; ?>
        </div>
      </div>
    </div>
    <div class="sl-msg warn" style="margin:0 20px 20px">Custom Protection is hidden by default. Choose it above to pick exact files.</div>
  </div>

<?php else: ?>
  <div class="sl-card">
    <div class="sl-ch">
      <h2>Custom Protection Browser</h2>
      <span class="sl-chip n" id="slCount">0 selected</span>
      <span class="sp"></span>
      <a class="sl-btn s" href="?mode=custom&amp;root=<?= urlencode($curRoot) ?>&amp;d=<?= urlencode($browse['rel']) ?>">&#8635; Refresh</a>
    </div>
    <div class="sl-body" style="padding-top:0">Pick exact files or folders inside your website root. Locking and
    releasing are carried out by the server once your host approves.</div>

    <div class="sl-tools">
      <span class="sl-root">WEB ROOT</span>
      <span class="sl-crumb">/<?= sp_h($browse['rel']) ?></span>
      <?php if ($browse['rel'] !== ''): ?>
        <a class="sl-btn s" href="?mode=custom&amp;root=<?= urlencode($curRoot) ?>&amp;d=<?= urlencode(dirname($browse['rel']) === '.' ? '' : dirname($browse['rel'])) ?>">&#11014; Up</a>
      <?php endif; ?>
      <span class="sp" style="flex:1"></span>
      <button class="sl-btn s" type="button" id="slAll">Select visible</button>
      <button class="sl-btn s" type="button" id="slNone">Clear</button>
      <button class="sl-btn s" type="button" id="slSug">Select suggested</button>
      <input class="sl-in" id="slFilter" placeholder="Filter visible…" style="max-width:200px">
    </div>

    <form method="post" id="slForm">
      <input type="hidden" name="sp_action" value="ask">
      <input type="hidden" name="sp_token" value="<?= sp_h($TOKEN) ?>">
      <input type="hidden" name="root" value="<?= sp_h($curRoot) ?>">
      <input type="hidden" name="verb" id="slVerb" value="apply_custom">
      <input type="hidden" name="unlock" id="slUnlock" value="permanent">
      <input type="hidden" name="reason" id="slReason" value="">

      <div class="sl-tw">
        <table class="sl-tbl">
          <thead><tr><th style="width:34px"></th><th>Name</th><th>Type</th><th>Size</th><th>Modified</th><th>Status</th></tr></thead>
          <tbody id="slRows">
          <?php if (!$browse['rows']): ?>
            <tr><td colspan="6" class="sl-none" style="padding:18px 16px">This folder is empty.</td></tr>
          <?php endif; ?>
          <?php foreach ($browse['rows'] as $r): $st = sp_status_of($r['path'], $r['dir']); ?>
            <tr data-name="<?= sp_h(strtolower($r['name'])) ?>">
              <td><input type="checkbox" class="slChk" name="items[]" value="<?= sp_h($r['rel']) ?>" <?= isset($suggest[$r['path']]) ? 'data-suggested="1"' : '' ?>></td>
              <td class="sl-nm">
                <?php if ($r['dir']): ?>
                  <a href="?mode=custom&amp;root=<?= urlencode($curRoot) ?>&amp;d=<?= urlencode($r['rel']) ?>">&#128193; <?= sp_h($r['name']) ?></a>
                <?php else: ?>&#128196; <?= sp_h($r['name']) ?><?php endif; ?>
                <?= isset($suggest[$r['path']]) ? ' <span class="sl-chip a">suggested</span>' : '' ?>
                <span class="sl-sub"><?= sp_h($r['rel']) ?></span>
              </td>
              <td class="sl-num"><?= $r['dir'] ? 'dir' : 'file' ?></td>
              <td class="sl-num"><?= $r['dir'] ? '—' : sp_h(sp_size_h($r['size'])) ?></td>
              <td class="sl-num"><?= sp_h(date('Y-m-d H:i', $r['mtime'])) ?></td>
              <td>
                <?php if ($st === 'locked'): ?><span class="sl-chip g">locked</span>
                <?php elseif ($st === 'guarded'): ?><span class="sl-chip g">code blocked</span>
                <?php elseif ($st === 'readonly'): ?><span class="sl-chip a">read-only</span>
                <?php else: ?><span class="sl-chip n">writable</span><?php endif; ?>
              </td>
            </tr>
          <?php endforeach; ?>
          </tbody>
        </table>
      </div>

      <div class="sl-bar">
        <button class="sl-btn g" type="button" id="slApply" <?= $pending ? 'disabled' : '' ?>>&#128274; Protect selected</button>
        <button class="sl-btn r" type="button" id="slRelease" <?= $pending ? 'disabled' : '' ?>>&#128275; Ask to release for 1 hour</button>
        <span class="note">Protecting is carried out for you. A <b>release</b> goes to your host to approve, and the
        server locks the files again by itself an hour later.</span>
      </div>
      <div id="slWarn" class="sl-msg warn" style="display:none;margin:0 20px 18px"></div>
    </form>
  </div>
<?php endif; ?>

  <div class="sl-card" style="border-color:#fecaca">
    <div class="sl-ch"><h2>Stop protecting this account</h2><span class="sl-chip a">your host decides</span></div>
    <div class="sl-body" style="padding-bottom:0">
      This is not about particular files. It asks your host to take <b>every</b> lock off this account and to stop
      protecting it automatically &mdash; nothing will put a lock back until they undo it. Ask for this when
      something you run has to keep writing these files: a deploy, an installer, a build step.
      <br><br>
      Until then, the safer thing is the one-hour release above, which restores itself.
    </div>
    <form method="post" style="padding:14px 20px 18px;display:flex;gap:10px;flex-wrap:wrap;align-items:center">
      <input type="hidden" name="sp_action" value="ask">
      <input type="hidden" name="sp_token" value="<?= sp_h($TOKEN) ?>">
      <input type="hidden" name="verb" value="unlock_permanent">
      <input type="hidden" name="root" value="<?= sp_h($curRoot) ?>">
      <input class="sl-in" name="reason" maxlength="200" required style="flex:1;min-width:260px"
             placeholder="What has to write these files? Your host reads this.">
      <button class="sl-btn r" type="submit" <?= $pending ? 'disabled' : '' ?>>Ask to stop protecting this account</button>
    </form>
  </div>

  <div class="sl-card">
    <div class="sl-ch"><h2>What the states mean</h2></div>
    <div class="sl-legend">
      <div><span class="sl-chip g">locked</span>
        <p>The real lock. Nothing running as your account can undo it &mdash; only the server, which is why every
        change to it goes through your host.</p></div>
      <div><span class="sl-chip a">read-only</span>
        <p>Stops accidental and most automated rewrites. Its limit, plainly: something already running as your
        account can make the file writable again. The gain is that the change becomes visible.</p></div>
      <div><span class="sl-chip g">code blocked</span>
        <p>An upload or cache folder that refuses to execute programs. This stops most break-ins, and it is the one
        thing here you switch yourself.</p></div>
    </div>
  </div>

  <div class="sl-card">
    <div class="sl-ch"><h2>What this page cannot see</h2><span class="sl-chip n">your host</span></div>
    <div class="sl-body">Sign-in attempts against FTP, SSH and mail, and the firewall, belong to the server rather
    than to your account, so they cannot be read from inside cPanel. They are not reported here as
    &ldquo;nothing found&rdquo; &mdash; they were not checked.</div>
  </div>
</div>

<script>
(function(){
  var form=document.getElementById('slForm'); if(!form) return;
  function chks(){return [].slice.call(document.querySelectorAll('.slChk'));}
  var count=document.getElementById('slCount');
  function sync(){count.textContent=chks().filter(function(c){return c.checked;}).length+' selected';}
  document.addEventListener('change',function(e){
    if(e.target&&e.target.classList&&e.target.classList.contains('slChk'))sync();});

  document.getElementById('slAll').addEventListener('click',function(){
    chks().forEach(function(c){var tr=c.closest('tr');if(!tr||tr.style.display!=='none')c.checked=true;});sync();});
  document.getElementById('slNone').addEventListener('click',function(){
    chks().forEach(function(c){c.checked=false;});sync();});
  document.getElementById('slSug').addEventListener('click',function(){
    chks().forEach(function(c){c.checked=c.hasAttribute('data-suggested');});sync();});

  document.getElementById('slFilter').addEventListener('input',function(){
    var q=this.value.toLowerCase();
    [].slice.call(document.querySelectorAll('#slRows tr')).forEach(function(tr){
      var n=tr.getAttribute('data-name')||'';
      tr.style.display=(q===''||n.indexOf(q)>=0)?'':'none';});});

  var warn=document.getElementById('slWarn');
  function say(t){warn.innerHTML='&#9888; '+t;warn.style.display='';}
  function picked(){return chks().some(function(c){return c.checked;});}

  document.getElementById('slApply').addEventListener('click',function(){
    if(!picked()){say('Nothing is selected, so there is nothing to ask for.');return;}
    document.getElementById('slVerb').value='apply_custom';
    if(!confirm('Lock the selected items?\n\nThe server carries this out within about a minute. Releasing them again needs your host.'))return;
    form.submit();
  });

  document.getElementById('slRelease').addEventListener('click',function(){
    if(!picked()){say('Nothing is selected, so there is nothing to ask for.');return;}
    document.getElementById('slUnlock').value='1h';
    document.getElementById('slVerb').value='unlock_selected';
    if(!confirm('Ask your host to release the selected items for one hour?\n\nThe server locks them again by itself afterwards.'))return;
    form.submit();
  });
  sync();
})();
</script>
<?php sp_footer($cpanel);
