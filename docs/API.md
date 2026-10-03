# Pasargad CDN — Customer API (`/capi/v1`)

مستندات API مشتری (کلید هر سرویس). SPEC §10.1.

Every CDN service can have up to **5** API keys. Each key is scoped to **one site** and carries
a subset of the scopes `purge`, `stats`, `dns`. A key can never see or change another site's data
and cannot reach any admin or edge endpoint.

هر سرویس CDN می‌تواند تا **۵** کلید API داشته باشد. هر کلید فقط به **یک دامنه** دسترسی دارد و
مجموعه‌ای از دسترسی‌های `purge`، `stats` و `dns` را در بر می‌گیرد. یک کلید هرگز به داده یا تنظیمات
دامنهٔ دیگر و هیچ سرویس مدیریتی دسترسی ندارد.

---

## پایه / Base URL

```
https://cdn-api.pasargadmizban.com/capi/v1
```

(همان دامنهٔ کنترلر `CONTROLLER_DOMAIN` — the controller domain.)

## احراز هویت / Authentication

هر درخواست باید هدر زیر را داشته باشد. Every request must send:

```
Authorization: Bearer pcdn_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

کلید نامعتبر یا لغوشده → `401`. کلید مدیریتی (admin key) روی `/capi/*` پذیرفته **نمی‌شود**.
An unknown or revoked key returns `401`; the admin key is **not** accepted on `/capi/*`.

## قالب خطا / Error format

همهٔ خطاها JSON با کلید `detail` هستند (متن فارسی یا انگلیسی):

```json
{"detail": "این کلید دسترسی «purge» را ندارد"}
```

| کد | معنی / meaning |
|----|----------------|
| 401 | کلید نامعتبر یا ارسال‌نشده / invalid or missing key |
| 403 | کلید این دسترسی (scope) را ندارد / key lacks the required scope |
| 404 | مورد یافت نشد / not found (record, config section) |
| 422 | ورودی نامعتبر / invalid input (validation) |
| 429 | عبور از محدودیت نرخ / rate limit exceeded |

## محدودیت نرخ / Rate limit

هر کلید تا `CAPI_RATE` درخواست در دقیقه (پیش‌فرض **۶۰**) مجاز است؛ بیش از آن → `429`.
Each key is limited to `CAPI_RATE` requests per minute (default **60**); excess returns `429`.

---

## ساخت کلید در پنل / Creating a key

در ناحیهٔ کاربری WHMCS، صفحهٔ سرویس CDN → بخش «کلیدهای API»: یک نام و دسترسی‌ها را انتخاب و کلید
بسازید. **کلید فقط یک‌بار نمایش داده می‌شود** — آن را ذخیره کنید. کلیدهای موجود را می‌توانید لغو کنید.

In the WHMCS client area, open the CDN service → "API keys": choose a name and scopes and create
the key. **The key is shown only once** — store it safely. Existing keys can be revoked.

مدیریت کلیدها از طریق API مدیریتی (فقط با admin key، از طریق ماژول WHMCS) انجام می‌شود:

```
GET    /api/v1/sites/{domain}/apikeys           # list (never returns the key itself)
POST   /api/v1/sites/{domain}/apikeys           # {name, scopes:[...]} -> returns key ONCE
DELETE /api/v1/sites/{domain}/apikeys/{id}       # revoke
```

---

## نمونه‌ها / Examples

Set your key once:

```bash
KEY="pcdn_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
BASE="https://cdn-api.pasargadmizban.com/capi/v1"
```

### `purge` — پاک‌سازی کش / cache purge

```bash
# آدرس‌های مشخص / specific URLs
curl -s -X POST "$BASE/purge" -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d '{"urls": ["https://example.com/a.css", "https://example.com/b.js"]}'

# پیشوندها / path prefixes
curl -s -X POST "$BASE/purge" -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d '{"prefixes": ["/blog/", "https://example.com/img/"]}'

# کل کش سایت / everything
curl -s -X POST "$BASE/purge" -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" -d '{"everything": true}'
```

محدودیت‌ها: حداکثر ۱۰۰ مورد در هر درخواست، حداکثر ۲۰ پیشوند، هر پیشوند تا ۲۰۰ نویسه.
Limits: up to 100 items per request, up to 20 prefixes, each prefix ≤ 200 chars.

### `stats` — آمار و رویدادها / analytics & events

```bash
# آمار / analytics  (period = 24h | 7d | 30d)
curl -s "$BASE/analytics?period=24h" -H "Authorization: Bearer $KEY"

# رویدادهای امنیتی / security events
curl -s "$BASE/events?limit=100" -H "Authorization: Bearer $KEY"
```

### `dns` — رکوردها و تنظیمات / records & config

```bash
# فهرست رکوردها / list records
curl -s "$BASE/records" -H "Authorization: Bearer $KEY"

# افزودن رکورد / add a record
curl -s -X POST "$BASE/records" -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "api", "type": "A", "content": "185.1.2.3", "proxied": true}'

# ویرایش رکورد / update a record
curl -s -X PATCH "$BASE/records/123" -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "api", "type": "A", "content": "185.1.2.9"}'

# حذف رکورد / delete a record
curl -s -X DELETE "$BASE/records/123" -H "Authorization: Bearer $KEY"

# خواندن یک بخش تنظیمات / read a config section
curl -s "$BASE/config/cache" -H "Authorization: Bearer $KEY"

# نوشتن یک بخش تنظیمات / write a config section
curl -s -X PUT "$BASE/config/firewall" -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d '{"default_action": "allow", "rules": []}'
```

بخش‌های تنظیمات مانند API مدیریتی: `cache`, `ssl`, `waf`, `ddos`, `firewall`, `ratelimit`,
`pagerules`, `pools`, `headers`, `hotlink`, `image`, `errorpages`, `tunnel`. اعتبارسنجی و محدودیت‌های
پلن دقیقاً مانند پنل مدیریت اعمال می‌شود.

Config sections are the same as the admin API; validation and plan limits are identical to the panel.

### `stats` — تونل: تنظیمات پیشنهادی و دلیل قطع اتصال / tunnel profile & drops (wave 13, SPEC §22)

```bash
# مهلت‌های لبه، دسترس‌پذیری HTTP/3 و مقادیر پیشنهادی هر مسیر برای برنامه‌ی کلاینت
# edge timers, HTTP/3 availability and recommended client settings per tunnel path
curl -s "$BASE/tunnel/profile" -H "Authorization: Bearer $KEY"

# چرا اتصال‌ها قطع شدند؟ (hours = 1..744)  /  why did tunnel sessions end?
curl -s "$BASE/tunnel/drops?hours=24" -H "Authorization: Bearer $KEY"
```

`GET tunnel/profile` (404 when the plan has no `tunnel`; no Persian text, stability settings only —
never fragment / noise / padding / SNI or address options):

```json
{"edge": {"client_idle_s": 600, "max_connection_age_s": 21600, "h2_max_streams": 512,
          "tcp_keepalive": {"idle_s": 120, "interval_s": 30, "count": 4}, "connect_timeout_s": 10},
 "http3": {"site": true, "nodes": 4, "nodes_h3": 4, "available": true},
 "paths": [{"id": "grpc1", "path": "/svc", "protocol": "grpc", "idle_timeout_s": 3600,
            "read_timeout_s": 3600, "send_timeout_s": 300, "origins": 2, "balance": "failover",
            "http3": false,
            "recommended": {"keepalive_s": 60, "mux": "off", "xmux": null,
                            "grpc": {"idle_timeout_s": 60, "health_check_timeout_s": 20,
                                     "permit_without_stream": false},
                            "ws_heartbeat_s": null}}]}
```

- `keepalive_s = max(10, min(60, floor(min(path idle, 600) / 3)))`; `mux` = `off` for grpc / xhttp / h2,
  `low` (4–8) for ws / httpupgrade; `xmux` only for xhttp; `ws_heartbeat_s` only for ws.
- `http3.available` = the site serves HTTP/3 (SSL + `ssl.http3`) **and** every online node serving the
  site has the HTTP/3 capability and its per-node switch on; `paths[].http3` = available AND xhttp.
  Counts only — never a node name or address.

`GET tunnel/drops?hours=24`:

```json
{"hours": 24, "total": 120,
 "reasons": {"normal": 80, "idle_timeout": 20, "origin": 10, "node_reload": 6, "node_drain": 3, "other": 1},
 "rejected": {"limit": 4, "origin_refused": 2, "origin_timeout": 0},
 "paths": [{"id": "grpc1", "total": 70, "reasons": {"normal": 50, "...": 0}, "top": "idle_timeout"}],
 "series": [{"t": "2026-10-02T10:00:00Z", "normal": 3, "idle_timeout": 1, "origin": 0, "node_reload": 0,
             "node_drain": 0, "other": 0}],
 "maintenance": [{"t": "2026-10-02T09:12:00Z", "kind": "upgrade"}],
 "plan": {"over_quota_since": null, "suspended": false},
 "top": "idle_timeout", "has_data": true}
```

- `top` = the largest non-`normal` reason when it is ≥ 5 % of `total` (else `null`).
- `rejected` = reconnect attempts that did not get in (connection limit / fair share, origin refused,
  origin timeout). `maintenance` = drain / upgrade times of the nodes that served the site — kind and
  time only, never a node name or address. `has_data = false` until the nodes run the wave-13 agent.

`GET tunnel/quality` paths gain `reuse_pct` = 100 × reused upstream connections / tunnel requests
(approximation: connect time exactly `0.000`; `null` without data).

## Admin API additions (wave 13, SPEC §22) — `Authorization: Bearer <ADMIN_API_KEY>`

| method + path | body / query | answer |
|---|---|---|
| `POST /api/v1/edges/{id}/drain` | `{"minutes": 15, "reason": "upgrade", "force": false}` (minutes 1..120, default `DRAIN_DEFAULT_MINUTES`; reason ≤ 64 printable, default `admin`) | `200 {"ok": true, "dns_failed": n, "edge": {…}}`; 404; 409 `{"detail": "last_edge"}` (pass `force: true`); 409 `{"detail": "already_draining"}` (a re-POST with different `minutes` only moves `drain_until`) |
| `DELETE /api/v1/edges/{id}/drain` | — | `200 {"ok": true, "dns_failed": n, "edge": {…}}` (idempotent) |
| `PATCH /api/v1/edges/{id}` | `{"http3_enabled": false}` (plus the existing fields) | `200 {"ok": true, "dns_failed": n, "edge": {…}}` |
| `GET /api/v1/sites/{domain}/tunnel/profile` | — | as `GET /capi/v1/tunnel/profile` |
| `GET /api/v1/sites/{domain}/tunnel/drops` | `hours` 1..744 | as `GET /capi/v1/tunnel/drops` |
| `POST /edge/v1/drain` (edge token) | `{"action": "start", "minutes": 15, "reason": "upgrade"}` \| `{"action": "stop"}` | `200 {"state": "draining"\|"", "until": iso\|null, "refuse_after": iso\|null}`; 409 `last_edge` (no force); 422; 429 (> 10 calls / min / edge) |

Edge object (`GET /api/v1/edges`) gains:

```json
{"drain": {"state": ""|"draining"|"drained", "since": iso|null, "until": iso|null,
           "by": "admin"|"edge"|null, "reason": str|null, "conns": int|null},
 "reloads": {"count_1h": 3, "count_24h": 20, "last_at": iso|null, "coalesced_1h": 1, "pending_s": 0,
             "deferred": false, "wst_s": 3600, "forced_shutdowns_24h": 0} | null,
 "tunnel_probe": {"degraded": false, "since": iso|null, "last": {<latest heartbeat tunnel_probe>}|null},
 "tuning": {"profile": "auto", "ram_mb": 3900, "ok": true, "cc": "bbr", "qdisc": "fq",
            "nofile": 1048576, "mismatches": []} | null,
 "http3_enabled": true,
 "dns_weight": {"level": 0, "q": null}}
```

`metrics` additionally carries `draining_workers`, `sock_tcp`, `sock_tw` when the agent reports them.
`GET /api/v1/overview` gains `tunnel_degraded: [edge names]` and `tunnel_multi_origin_sites` (count of sites
with an `origins` tunnel path, to flag nodes without `capabilities.tunnel_multi_origin`). The site object gains `ssl_key_type`
(`ecdsa-p256` | `ecdsa-p384` | `rsa-<bits>` | null) and `ssl_dual_rsa` (bool). Plan feature
`max_tunnel_origins` (1..10, default 1). TLS ticket keys never appear in any of these answers.

Section `tunnel` paths gain `origins` (2..10, plan `max_tunnel_origins`), `balance`
(`failover` | `round_robin` | `sticky_ip`), `health` (`{"type": "tcp"|"http", "interval", "timeout",
"path", "expect"}`) and `idle_timeout` (60..86400 or null = the section value); at most one of
`origin` / `origins` / `pool`. Section `pools` `health` gains `type` (`http` default | `tcp`).
