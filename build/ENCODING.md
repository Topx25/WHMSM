# Encoding Safety Monitor Pro for production (license tamper-resistance)

## Why
The plugin runs as **root** on the customer's server. With plaintext PHP, root can
defeat licensing in one line (set `SMPRO_LIC_ENFORCE = false`, or stub
`smpro_lic_is_valid()` to `return true`). The runtime signature/binding checks
(`includes/license.php`) stop forged/copied `state.json` and fake servers, but
**not** source editing. Bytecode-encoding removes the plaintext source, which is
the only real defense against that.

## What's already done
- **Runtime signature re-verification** is live: `smpro_lic_is_valid()` re-checks
  the stored RSA-signed payload + server binding on every load, so a hand-edited
  `state.json` is rejected (proven on production: old code `is_valid=TRUE`, new `false`).
- **Loaders are ready on the target.** cPanel PHP 8.4 (`/usr/local/cpanel/3rdparty/bin/php`)
  has **both ionCube Loader and SourceGuardian active**. Encoded files run with
  **no loader install**.

## What you need (one-time purchase)
An **encoder** — a commercial Linux tool, run on a build machine (NOT the server):
- **ionCube Encoder 14+** — must list **PHP 8.4** as a supported target.
  https://www.ioncube.com/sa_encoder.php
- **or SourceGuardian 13+** — https://www.sourceguardian.com/

Either works; the target server already has both loaders.

## Build steps
On a Linux host with the encoder installed:

```bash
# 1. copy the plaintext build there (e.g. rsync/scp the smprov1_build dir)
# 2. run the encoder
chmod +x build/encode.sh
./build/encode.sh /path/to/smprov1_build /path/to/smprov1-encoded
```

The script:
- encodes **all `.php`** (whole plugin — no readable file left to rebuild an un-gated loader),
- copies `index.cgi` (bash wrapper) and static assets unchanged,
- targets PHP 8.4, obfuscates symbols, strips docblocks,
- **verifies** the gate files (`index.php`, `includes/license.php`, `menu.php`,
  `layout.php`) actually came out encoded and aborts if any stayed plaintext.

## Deploy + verify on the server
```bash
DIR=/usr/local/cpanel/whostmgr/docroot/cgi/addons/smprov1
PHP=/usr/local/cpanel/3rdparty/bin/php

# back up current, push encoded build
ssh -p 2245 root@production.the-customer.com "cp -a $DIR ${DIR}.plain.bak.\$(date +%s)"
rsync -az -e 'ssh -p 2245' /path/to/smprov1-encoded/ root@production.the-customer.com:$DIR/

# prove the encoded gate runs under the loader (should render, no 'requires the ionCube/SourceGuardian loader' error)
ssh -p 2245 root@production.the-customer.com \
  "cd $DIR && env -u HOME REMOTE_USER=root REQUEST_METHOD=GET QUERY_STRING='page=dashboard' $PHP index.php 2>&1 | grep -iE 'fatal|loader|ioncube|sourceguardian' | head"
# and confirm the source is gone:
ssh -p 2245 root@production.the-customer.com "grep -l SMPRO_LIC_ENFORCE $DIR/includes/license.php || echo 'OK: no plaintext gate'"
```

## Notes / gotchas
- **index.cgi stays bash** (can't be encoded). That's fine — it only execs the
  encoded `index.php`; editing it gains nothing because every PHP file is encoded.
- **PHP version lock-in.** Files encoded for 8.4 require an 8.4-capable loader. If
  cPanel later moves the 3rdparty PHP to 8.5, re-encode. (The server's `index.cgi`
  already calls the 8.4 `3rdparty/bin/php`.)
- **Expiry on the encoded files** (optional): both encoders can embed a build
  expiry / license-file lock. Leave it off for a self-licensing plugin (the
  runtime license engine already handles expiry) to avoid double-expiry surprises.
- **Keep the plaintext source** (this `smpro_build` tree) in your own private repo
  — it's your master; only the `-encoded` output ships.
- This does **not** build a distributable package — per the standing rule, no
  package is built until you approve.
