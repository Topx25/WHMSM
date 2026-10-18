// build/jscheck.js — release gate: every inline <script> block in modules/ and includes/ must parse as JavaScript
// after the PHP tags are neutralised. A bare line break inside a JS string (beta294) disabled a whole page's
// script without any error at build time; this refuses to build such a release.
// Usage: node build/jscheck.js <source root>   → exit 0 when clean, 1 with a list otherwise.
const fs = require('fs'), path = require('path');
const root = process.argv[2] || '.';
// Blocks that are not JavaScript at that position (a PHP doc comment naming <script>, a PHP-concatenated string).
const skip = new Set(['modules/database-cleanup.php#1', 'includes/legal.php#1']);
let bad = 0, blocks = 0;
for (const dir of ['modules', 'includes']) {
  for (const f of fs.readdirSync(path.join(root, dir))) {
    if (!f.endsWith('.php')) continue;
    const t = fs.readFileSync(path.join(root, dir, f), 'utf8');
    const re = /<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g; let m, i = 0;
    while ((m = re.exec(t))) {
      i++; if (skip.has(dir + '/' + f + '#' + i)) continue;
      let s = m[1];
      if (/^\s*<\?php/.test(s)) continue;
      s = s.replace(/<\?=\s*json_encode\([\s\S]*?\)\s*\?>/g, 'null').replace(/<\?=[\s\S]*?\?>/g, '0').replace(/<\?php[\s\S]*?\?>/g, '');
      blocks++;
      try { new Function(s); } catch (e) { bad++; console.log('JS SYNTAX: ' + dir + '/' + f + ' script#' + i + ': ' + e.message); }
    }
  }
}
console.log('jscheck: ' + blocks + ' inline script blocks parsed, ' + bad + ' broken');
process.exit(bad ? 1 : 0);
