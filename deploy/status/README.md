# استقرار صفحهٔ وضعیت روی میزبان جداگانه

صفحهٔ وضعیت (`status/` در ریشهٔ مخزن) را **روی یک سرور و دامنهٔ جدا** از سرور مرکزی بالا می‌آورد تا
وقتی کنترلر یا کل سرور مرکزی از دسترس خارج است، صفحه همچنان باز شود و **آخرین وضعیت شناخته‌شده** را
همراه با یک اعلان «ارتباط برقرار نیست» نشان دهد.

```sh
cd deploy/status
cp .env.example .env && $EDITOR .env      # STATUS_DOMAIN و STATUS_UPSTREAMS
docker compose up -d --build
```

| فایل | کار |
|---|---|
| `docker-compose.yml` | دو سرویس: `mirror` (گرفتن و نگه‌داری status.json) و `caddy` (HTTPS) |
| `mirror.sh` | هر `MIRROR_INTERVAL` ثانیه `/status.json` را از اولین upstream در دسترس می‌گیرد، اعتبارسنجی و فیلتر می‌کند؛ در خرابی نسخهٔ قبلی را نگه می‌دارد |
| `mirror.js` | اعلان «آخرین وضعیت شناخته‌شده» را به صفحه اضافه می‌کند (فایل‌های `status/` دست نمی‌خورند) |
| `Caddyfile` | سرو ایستا، کش کوتاه، CSP سخت‌گیرانه |
| `Dockerfile.mirror` | Alpine + curl + jq، کاربر بدون دسترسی ریشه |

راهنمای کامل: [docs/MONITORING.md](../../docs/MONITORING.md) — بخش «صفحهٔ وضعیت جداگانه».
