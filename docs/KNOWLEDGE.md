# SM Pro — how the project runs (start here)

Read this before the first change. `CLAUDE.md` holds the rules; this file is the map: what runs where, how a
change travels from the working copy to a customer's server, the patterns the code already has for the hard
cases, and the traps that have cost time. It names no server, address or person — those live in local settings.

Reading order for a new piece of work:
1. `CLAUDE.md` — the rules and the workflow (10 steps).
2. this file — sections 2, 3 and 6 at least.
3. `docs/FACTS-INDEX.md` — find the section of `docs/FACTS.md` that covers your area and read only that.
4. the page module AND the include it delegates to.

## 1. The product in one paragraph

A WHM plugin (PHP, runs as root through `index.cgi` → `index.php` under cPanel's CLI PHP) sold to hosting
providers. Pages live in `modules/`, logic in `includes/`, scheduled workers in `bin/`. State is JSON under
the data directory (`SMPRO_VARLIB`), logs under `SMPRO_VARLOG`. It coexists on the same servers with two
sibling products (WordPress protection, mail protection) through the shared bridge described in
`docs/HOSTGUARD-BRIDGE.md`. The licence server signs every verdict; the release key (offline) signs every
package and the file manifest inside it.

## 2. What runs where

| Role | What it is for | How it is reached |
|---|---|---|
| Build machine | the working copy, obfuscation, signing with the offline release key | local |
| Test server ("the lab") | runs the whole test suite before any build; also has the plugin INSTALLED in developer mode for live trials | `SMPRO_LAB_HOST` / `SMPRO_LAB_KEY` |
| Release + licence server | serves BETA and STABLE packages, answers licence checks | `SMPRO_LIC_HOST` / `SMPRO_LIC_KEY` |
| Production servers | take a channel by themselves (auto-update) or are updated by their operator | per server |

The host names and key paths are NOT in the repository. They come from `~/.smpro-build.env` on the build
machine; `build/obfuscate-and-package.sh` and `packaging/PUBLISH.sh` stop with a clear message without it.

The lab is shared with other work. Its load changes from minute to minute, so a run that is green in 90 s can
take 9 minutes an hour later. The render smoke test gives a page that ran out of time among the others one more
go on its own; a page that hangs alone still fails.

## 3. From a change to a customer — the exact path

1. Edit the working copy. Patch scripts are Python files (see 6.1), never shell heredocs.
2. `php -l` every touched file; run the tests that read those files (`php tests/unit/tNN_x.php`).
3. Bump `SMPRO_VERSION` in `includes/defines.php`; write `packaging/smpro-<version>.RELEASE-NOTES.txt`
   (what changed, and a line that starts "Not verified on a live server:" for whatever was not tried for real).
4. `bash build/obfuscate-and-package.sh </dev/null` — pushes the source to the lab, runs the suite there, and only
   then obfuscates, builds the signed manifest and signs the package. It must print `GATE PASS` and
   `HARDCODE GATE: clean`. A red gate is read, not retried blindly: list the failing tests first.
5. `cd packaging && bash PUBLISH.sh <version>` — BETA. It also commits and pushes the source.
6. A server on the BETA channel with auto-update takes it within ~15 minutes. Verify there: version in
   `integrity.json`, full file check, licence valid, workers not disabled.
7. `bash PUBLISH.sh <version> --stable` only on the owner's explicit word.
8. Record: `docs/FACTS.md` + the session memory + the memory index, together (the three-places rule).

Never build twice for the same version after publishing: obfuscation is not reproducible, and the publish step
refuses the same version with different bytes.

## 4. Patterns the code already has — use them, do not reinvent them

**Acting inside an account's folder (the most important one).** A folder the account owns can change between a
check and the action: a file, or any parent folder, swapped for a link. Root that follows the link writes,
reads, chowns or deletes a system file — several such places gave an account root. The rule: root never writes,
copies, renames, chmods or chowns by path inside a home. It drops to the account:

| Need | Helper (`includes/helpers.php`) |
|---|---|
| read a file | `smpro_acct_get($user, $path, $max)` — null for a link, a non-file, or over the size |
| write a file | `smpro_acct_put($user, $path, $data, $mode)` — temp file + rename, keeps the mode |
| copy / remove | `smpro_acct_copy`, `smpro_acct_rm` |
| any short script | `smpro_acct_sh($user, $script, $args, $stdin, $timeout)` |
| put a file from root's store back | `smpro_acct_restore($user, $storeFile, $dest, $mode, $mtime, $overwrite)` |
| which account owns a path | `smpro_acct_of_path($path)` |

A name freed by a delete is the classic trap: a dangling link there passes every "does a file exist" test, and
a root `copy()` then creates whatever it points at. Root keeps only what the account cannot do (`chattr`), after
a link check. Paths outside every home (the test sandbox) may be handled by root directly.

**Honest results.** A check that could not run says so ("not verified", "could not compare") and never reads as
clean. A fix reports success only from a result it read back. An automatic action is reversible and recorded.

**Backup first.** Nothing of a customer's is removed or rewritten before a copy is kept — in the plugin's store
for root-only material, as the account for material that goes back into the home.

**Logic a worker needs lives in `includes/`.** A page module is never loaded by cron. A function that a worker
calls while it still lives in a module fails silently (`function_exists` is false there). Check with the
worker's own include list, not with the page loaded.

**Blocks go through one guarded function** (`smpro_im_block_ip`): allow-list, this server's own addresses,
home-region residential addresses and the CDN edge are refused there. A direct call to a lower-level block
function skips those guards.

**Lists other tools also edit** (firewall allow/deny files) are read and rewritten under the shared lock.

## 5. The protection model, in short

- Licence: the plugin sends key + fingerprint; the server answers with a signed verdict bound to this machine.
  Offline grace is counted from the SIGNED issue time. The stop clock for background workers reads signed data
  first and keeps its local marker in two places. A refusal is trusted as the server's only when it is signed,
  once the server has said (inside a signed verdict) that it signs refusals.
- Integrity: a packaged copy must carry its signed file manifest; a missing or emptied one is tampering.
  The build sets `SMPRO_PACKAGED`; a source checkout skips the check.
- Updates: package signature by the offline key, downgrade refused by the version inside the signed manifest,
  a forced apply needs an offline-key signature over the directive.
- What a licensee with root can still do is recorded in `docs/FACTS.md` (search "STILL OPEN").

## 6. Traps that cost time

1. **Patch scripts.** Write a Python file, replace exact strings, assert the count before replacing, keep the
   file's line endings, run `php -l` after. A shell heredoc halves backslashes and breaks on quotes; a comment
   appended to the end of a one-line `foreach` swallows the rest of the line.
2. **Source-text tests.** Many tests assert that a file contains an exact line. Changing that line means updating
   the test in the same change; moving a function to another file breaks tests that read the old file.
3. **The lab is not a server.** It has no licence and no real accounts. Things only a real server showed:
   cron's short `PATH` finds the web PHP ("Only CLI access") instead of the command-line one; a scheduled check
   that reads as "not verified" on every site; a classifier that calls half the sites critical for files every
   project carries. After a feature ships, run it once on a real server and read what it says.
4. **Per-request caches.** The licence state is cached for the request; a test that writes the file by hand must
   drop the cache as a new request would.
5. **Time windows.** The alert step looks at 15 minutes, the event list at one hour. A rule that counts must say
   which, and the real case decides (three requests, ten minutes apart).
6. **Capped lists.** A list handed on is capped (300 trusted addresses); a decision about what is NO LONGER in
   the list must use the whole set.
7. **Same name, different key.** A signed block placed under a key an older build already reads can be taken
   for a forged state by that build. New signed data gets a new key name.

## 7. When a site is reported broken or hacked

1. Read-only first: what the site answers now (as a visitor and as a crawler), the error log, resource faults,
   files changed recently, the access log around the first change, who was logged in.
2. Report what was found and what is not known (the entry door most of all) before touching anything.
3. Clean only on the owner's word, into a dated backup folder: block the addresses, remove planted files, put
   core files back from the official copy, end every session (rotate the keys), lock what let them in.
4. Verify as a visitor and as a crawler; re-check the core against the official checksums.
5. Then look for the same attacker elsewhere (his addresses in every site's logs, the same file by hash, his
   tool names), and say why no layer stopped it — which layer was off, which had no rule for it.
6. Record the incident and the product lesson it leaves.

## 8. Where things are

| Looking for | Place |
|---|---|
| rules and workflow | `CLAUDE.md` |
| what happened, release by release; servers; incidents; open items | `docs/FACTS.md` (through `docs/FACTS-INDEX.md`) |
| the first code review and its plan | `docs/REVIEW-2026-11.md` |
| the contract between the sibling products | `docs/HOSTGUARD-BRIDGE.md` |
| licence-server changes prepared for the operator to apply | `server/apply_*.php`, `server/deploy-*.sh` |
| the tests that lock each review round | `tests/unit/t166` … `t170` |
