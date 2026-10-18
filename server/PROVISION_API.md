# AiTech Provisioning API — universal integration (works with ANY platform)

The sales website provisions licenses by calling a plain **HTTPS + JSON REST API** with a
secret key in a header. Any system that can make a server-side HTTP request can use it —
WordPress/WooCommerce, Laravel, raw PHP, Node.js, Python, WHMCS, Zapier/Make, n8n, etc.
**There is nothing platform-specific.** The "universal format" is this contract.

> ⚠️ Server-to-server ONLY. The secret key must live on your **backend**. Never put it in
> browser JavaScript, a mobile app, or any public page. Call the API from your payment
> webhook / server code.

## Base URL & auth
- Base: `https://dl.iptvpro.org`  (direct host, no Cloudflare — reliable for server calls)
- Auth header (either form):
  - `X-Provision-Key: <SECRET>`
  - or `Authorization: Bearer <SECRET>`
- Content-Type: `application/json`
- Secret lives on the license server at `storage/provision.key` (ask the admin; never commit it).

## Endpoints
| Method | Path | Body | Purpose |
|---|---|---|---|
| GET/POST | `/api/ping` | — | connectivity + auth test → lists products |
| POST | `/api/provision` | `{product, plan, client_name, client_email, order_id}` | issue a license (idempotent on `order_id`) |
| POST | `/api/renew` | `{order_id` or `license_key, extend_days` or `expires_at}` | extend expiry (reactivates if suspended) |
| POST | `/api/revoke` | `{order_id` or `license_key}` | suspend the license (locks on next check-in) |
| POST | `/api/license-status` | `{order_id` or `license_key}` | current state |

- `product`: `safety_monitor` or `mailshield` (see `/api/ping` → `products`). Default `safety_monitor`.
- `plan`: `free_trial` · `basic` · `pro` · `ultra`.
- `order_id`: **your** order/invoice id. Make every provision call with it — calling twice with the
  same `order_id` returns the SAME license instead of creating a duplicate (safe to retry).
- Expiry: omit `expires_at` to use the plan's natural cycle (trial days / monthly / yearly), or pass
  an explicit `expires_at` (`YYYY-MM-DD` or any strtotime string).

## Standard flow
1. Customer pays → your payment gateway calls **your** webhook.
2. Your webhook calls `POST /api/provision` with the plan + customer email + your order id.
3. API returns `license.license_key` → you email it to the customer / show it on the thank-you page.
4. Subscription renews → `POST /api/renew`. Refund/cancel/chargeback → `POST /api/revoke`.

### Response shape (success)
```json
{ "ok": true, "status": "provisioned",
  "license": { "license_key":"SM-PRO-2026-XXXX-XXXX", "product":"safety_monitor",
               "plan":"pro", "status":"active", "client_email":"a@b.com",
               "expires_at":"2026-07-21 00:00:00", "order_ref":"INV-1001" } }
```
Errors: `{ "ok": false, "status": "...", "message": "..." }` with an HTTP 4xx/5xx code
(`401` bad key, `400` missing plan/email, `404` invalid plan or license not found).

---

## Reference snippets (pick your stack — all do the same call)

### cURL (works everywhere / quick test)
```bash
curl -s https://dl.iptvpro.org/api/provision \
  -H "X-Provision-Key: $PROVISION_KEY" -H "Content-Type: application/json" \
  -d '{"product":"safety_monitor","plan":"pro","client_email":"a@b.com","client_name":"Ali","order_id":"INV-1001"}'
```

### PHP (raw — drop into any framework or webhook)
```php
function aitech_provision(array $payload): array {
    $ch = curl_init('https://dl.iptvpro.org/api/provision');
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 20,
        CURLOPT_HTTPHEADER => [
            'Content-Type: application/json',
            'X-Provision-Key: ' . getenv('PROVISION_KEY'),
        ],
        CURLOPT_POSTFIELDS => json_encode($payload),
    ]);
    $res = curl_exec($ch); $http = curl_getinfo($ch, CURLINFO_HTTP_CODE); curl_close($ch);
    $j = json_decode($res, true) ?: [];
    return ['ok' => $http < 300 && !empty($j['ok']), 'http' => $http, 'data' => $j];
}
// usage:
$r = aitech_provision(['product'=>'safety_monitor','plan'=>'pro','client_email'=>$email,'client_name'=>$name,'order_id'=>$orderId]);
if ($r['ok']) { $key = $r['data']['license']['license_key']; /* email it */ }
```

### WordPress / WooCommerce (fire on completed order)
```php
add_action('woocommerce_order_status_completed', function ($order_id) {
    $order = wc_get_order($order_id);
    $plan  = 'pro'; // map from the purchased product/SKU
    $body  = ['product'=>'safety_monitor','plan'=>$plan,
              'client_email'=>$order->get_billing_email(),
              'client_name' =>$order->get_formatted_billing_full_name(),
              'order_id'    =>(string)$order_id];
    $resp = wp_remote_post('https://dl.iptvpro.org/api/provision', [
        'timeout' => 20,
        'headers' => ['Content-Type'=>'application/json','X-Provision-Key'=>PROVISION_KEY],
        'body'    => wp_json_encode($body),
    ]);
    $j = json_decode(wp_remote_retrieve_body($resp), true);
    if (!empty($j['ok'])) {
        $order->add_order_note('License: ' . $j['license']['license_key']);
        // email $j['license']['license_key'] to the customer
    }
});
```

### Node.js (Express webhook)
```js
async function provision(payload) {
  const r = await fetch('https://dl.iptvpro.org/api/provision', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Provision-Key': process.env.PROVISION_KEY },
    body: JSON.stringify(payload),
  });
  const data = await r.json();
  return { ok: r.ok && data.ok, http: r.status, data };
}
// app.post('/webhook/paid', ...) -> const out = await provision({product:'safety_monitor',plan:'pro',client_email,order_id});
```

### Python
```python
import os, requests
def provision(payload):
    r = requests.post('https://dl.iptvpro.org/api/provision',
        json=payload, headers={'X-Provision-Key': os.environ['PROVISION_KEY']}, timeout=20)
    return r.ok and r.json().get('ok'), r.json()
```

### WHMCS
Use a **provisioning module** (or a simple hook on `AfterModuleCreate` / `InvoicePaid`) that issues
the same `POST /api/provision` with the WHMCS invoice id as `order_id`, and calls `/api/revoke`
on `AfterModuleSuspend` / `/api/renew` on `AfterModuleRenew`. Same contract as above.

---

## Notes
- **Idempotent:** always send your `order_id`; retries never double-issue.
- **Renew/revoke** can target by `order_id` (preferred) or `license_key`.
- **Test first:** `GET /api/ping` with your key → expect `{"ok":true,"status":"pong"}`.
- Keep the key in an env var / secrets store, rotate it on the license server if leaked.
