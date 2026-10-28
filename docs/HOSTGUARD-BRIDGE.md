# HostGuard bridge (format `hostguard-bridge/1`)

Several HostGuard products can run on one cPanel server: Safety Monitor Pro (`smpro`), WP Guard (`wpguard`),
MailGuard (`mailguard`). Each writes firewall denies and immutable flags on its own. Without a shared contract
they fight: one blocks a customer the other protects, one locks a file the other is asked to free. This document
is the contract. It is a set of plain files under one directory; every product reads before it acts and writes
after it acts. No network, no daemon, and no product depends on another being installed: a missing file means
"nobody said anything".

Root: `/var/lib/hostguard/` (0755, root-owned). Product ids are lower-case `[a-z0-9_-]`.

## 1. `policy.json` (written by `smpro`, read by everyone before blocking or locking)

```json
{ "format": "hostguard-bridge/1", "written_by": "smpro", "written_at": "2026-10-28T10:00:00+01:00",
  "home_regions": ["XX","YY"], "caution_regions": [], "home_shield": true,
  "allowlist": ["203.0.113.7", "198.51.100.0/24"],
  "never_block": { "google_mail": { "name": "Google mail servers", "ranges": ["..."] } },
  "excluded_accounts": [ { "account": "acct", "scope": "all", "reason": "..." } ],
  "block_requests": "events/<product>/ with action_wanted: block" }
```

Rules a product MUST follow:
- An address in `allowlist` or in any `never_block` range is never blocked, by rule or by hand.
- A RESIDENTIAL address whose country is in `home_regions` is never auto-blocked. Datacenter/hosting addresses
  are not covered (abusers rent VMs inside the home region). If the product cannot tell residential from
  datacenter, it does not auto-block any address in a home region; it reports it (section 4) and lets `smpro`
  decide. While `home_shield` is true, `smpro` lifts such blocks within a minute anyway and names the product.
- No product sets an immutable or append-only flag under an account listed in `excluded_accounts` with
  scope `all`. `smpro` removes such flags hourly and writes who set them to the account's activity log.
- The file is rewritten only when its content changes; compare `written_at` to know it moved.

## 2. `blocks.jsonl` (append-only, one JSON object per line, written by every product)

```json
{"ts":1793171020,"at":"2026-10-28T08:03:40+01:00","product":"wpguard","action":"block","ip":"203.0.113.9",
 "rule":"injection","site":"example.com","evidence":"POST /api/x 422"}
{"ts":1793171085,"at":"...","product":"smpro","action":"lift","ip":"203.0.113.9","rule":"home-region shield",
 "site":"","evidence":"blocked by: WP Guard auto-block: injection"}
```

- `action` is `block` or `lift`. A product appends a line for every deny it writes and every deny it removes,
  including temporary ones. The csf.deny comment keeps naming the product too (`<Product> ...`): the ledger
  explains, the comment identifies.
- Before writing a deny, a product reads the newest line for that address: if another product already holds a
  `block`, it appends nothing to csf.deny (no double deny) and only records its own `block` line with its rule.
- Keep it bounded: a writer may trim the file to its newest 10,000 lines when it passes 20,000.

## 3. `locks/<account>/` (who holds an immutable flag where)

- `locks/<account>/<product>.json`: `{ "format": "...", "product": "wpguard", "account": "acct",
  "written_at": "...", "paths": ["/home/acct/public_html/wp-config.php", "/home/acct/public_html/.htaccess"] }`.
  Rewritten whenever the product's set of locked paths changes; removed when the product holds nothing there.
- A product never removes a flag from a path listed in another product's file, and never sets a flag on a path
  another product lists, except when the operator presses that product's own force-release (then it may clear
  the flag and MUST write a release request).
- `locks/<account>/release-<product>.json`: `{ "from": "smpro", "to": "wpguard", "account": "acct",
  "reason": "...", "written_at": "...", "wanted": "release and do not re-lock while this file exists" }`.
  The addressed product releases its locks on that account on its next pass and does not re-apply them while
  the file exists. Only the product that wrote the request removes it.

## 4. `events/<product>/*.json` (what a product saw and wants the others to know)

File name: `<unix-ts>-<8 hex>.json`. Content, one event:
```json
{ "format": "hostguard-bridge/1", "product": "wpguard", "ts": 1793171020, "at": "...",
  "type": "attack", "ip": "203.0.113.9", "site": "example.com", "account": "acct",
  "rule": "injection", "severity": "high", "evidence": "POST /api/x 422",
  "action_wanted": "block" }
```
- `type`: `attack`, `block_lifted`, `account_excluded`, `block_declined`, `lock_released`, or a product-specific
  word. `action_wanted`: `report` (default) or `block`.
- Readers keep their own cursor (last file name seen per product directory) and never delete another product's
  files. A writer removes its own files older than 7 days.
- `smpro` decides every `action_wanted: block` by its policy: a home-region residential, allow-listed or
  infrastructure address is declined and a `block_declined` event is written back naming the reason; otherwise
  the address is blocked when auto-block is on (and recorded in `blocks.jsonl`), or held for the operator.
- `smpro` writes `block_lifted` when the home-region shield lifts a block (with the original comment),
  `account_excluded` when an account joins its ignore list, and `block_declined` as above.

## 5. Minimal implementation for a product

1. Before an automatic block: read `policy.json`; if the address is allow-listed, never-block, or a residential
   home-region address, write an `attack` event (with `action_wanted: block` if you want it blocked) and stop.
2. After any deny or lift you perform: append to `blocks.jsonl`; name yourself in the csf.deny comment.
3. Before setting an immutable flag: read `policy.json` excluded accounts and `locks/<account>/*.json`; skip
   excluded accounts and other products' paths. After locking or unlocking: rewrite your `locks/<account>/<you>.json`.
4. Every few minutes: honour `locks/<account>/release-<you>.json`; read the others' `events/` by cursor.
