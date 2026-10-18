# License server: `POST /api/authorize` (2-way per-action challenge-response)

The plugin now demands a **live, replay-proof authorization for every state-changing
action**. This endpoint must be added to the license server (plugins.iptvpro.org),
reusing the SAME RSA private key that already signs `/api/check` responses (so the
plugin's pinned public key verifies it).

## Request (JSON body)
```
POST /api/authorize
{
  "license_key": "...",
  "server_ip":   "1.2.3.4",     // plugin's main IP
  "fingerprint": "<64 hex>",    // sha256(machine-id|hostname|smprov1)
  "hostname":    "host.tld",
  "product":     "smprov1",
  "version":     "1.0",
  "action":      "clean",       // the action being authorized
  "nonce":       "<32 hex>"     // fresh per request — MUST be echoed back, signed
}
```

## Response (JSON) — success
```
{
  "ok": true,
  "status": "active",
  "license": {
    "payload": {
      "status": "active",
      "action": "clean",            // MUST equal the requested action
      "nonce":  "<the same nonce>",  // MUST equal the request nonce (anti-replay)
      "bound_ip": "1.2.3.4",         // MUST equal request server_ip
      "fingerprint": "<64 hex>",     // MUST equal request fingerprint
      "expires_at": "2026-12-31",    // license expiry
      "plan": "pro", "product": "smprov1",
      "client_name": "...", "bound_hostname": "...",
      "issued_at": "2026-06-14T..Z", "ttl": 120
    },
    "signature": "<base64( RSA-SHA256( json_encode(payload, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES) ) )>"
  }
}
```

## What the plugin enforces (all must hold, else action is BLOCKED)
- HTTP 2xx/4xx with parseable JSON (Cloudflare HTML/5xx = unreachable → blocked, no grace for actions)
- `ok === true`
- `signature` verifies against the pinned public key over `payload`
- `payload.nonce` === the nonce we sent  ← defeats replay
- `payload.action` === the action we sent
- `payload.bound_ip` === our server_ip AND `payload.fingerprint` === our fingerprint  ← defeats relay/copy
- `payload.status` ∈ {active,valid,licensed} and `expires_at` not in the past

Signing must use **`json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)`**
— byte-identical to how `/api/check` payloads are signed. (Verified end-to-end against
a mock using this exact encoding: valid passes; replay, wrong-key, wrong-action,
wrong-binding, expired, tampered-payload, empty-nonce all rejected.)

## Server failure modes to return honestly
- Unknown/expired/revoked key, or binding mismatch → `{"ok":false,"status":"invalid|expired|revoked","message":"..."}` (plugin blocks the action, shows support message).
- Bad/missing fields → `{"ok":false,"status":"bad_request",...}`.

## Integration notes (fill after reading the live server)
- Reuse the existing private-key load + the license-by-key lookup used by `/api/check`.
- Add `action`+`nonce` to the signed payload; otherwise the payload mirrors `/api/check`.
- Keep the existing Cloudflare allowance for `/api/*` from licensed servers.
