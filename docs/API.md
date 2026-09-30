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
