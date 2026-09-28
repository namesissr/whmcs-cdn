# Pasargad CDN — شبکه توزیع محتوای اختصاصی + ماژول WHMCS

CDN اختصاصی **پاسارگاد میزبان** برای فروش خودکار از طریق WHMCS در `my.pasargadmizban.com`.
مدل کار مشابه آروان‌کلود / کلودفلر است: مشتری نیم‌سرورهای دامنه‌اش را به نیم‌سرورهای ما تغییر می‌دهد،
رکوردهایی که «پروکسی» باشند از طریق نودهای CDN سرو می‌شوند و بقیه فقط DNS هستند.

---

## فهرست

- [معماری](#معماری)
- [قابلیت‌ها](#قابلیتها)
- [پیش‌نیازها](#پیشنیازها)
- [۱. راه‌اندازی کنترلر و DNS](#۱-راهاندازی-کنترلر-و-dns)
- [۲. تعریف نیم‌سرورها (Glue)](#۲-تعریف-نیمسرورها-glue)
- [۳. افزودن نود Edge](#۳-افزودن-نود-edge)
- [۴. نصب ماژول WHMCS](#۴-نصب-ماژول-whmcs)
- [روند کار مشتری](#روند-کار-مشتری)
- [GeoDNS (ترافیک ایران از نودهای داخل)](#geodns-ترافیک-ایران-از-نودهای-داخل)
- [مرجع API](#مرجع-api)
- [ساختار پروژه](#ساختار-پروژه)
- [تست‌ها](#تستها)
- [عیب‌یابی](#عیبیابی)
- [امنیت و محدودیت‌ها](#امنیت-و-محدودیتها)

---

## معماری

```
                    ┌──────────────────────────── my.pasargadmizban.com (WHMCS) ───┐
                    │  modules/servers/pasargadcdn  ── Create/Suspend/Usage/... ── │
                    └───────────────────────────────┬──────────────────────────────┘
                                                    │ HTTPS + API key
                                                    ▼
 ┌─────────────── Control plane (docker compose) ────────────────┐
 │  Caddy (TLS)  →  Controller (FastAPI)  →  Postgres            │
 │                      │   ├─ صدور SSL (acme.sh, DNS-01)         │
 │                      │   └─ زمان‌بند: NS، SSL، سهمیه، failover   │
 │                      ▼                                        │
 │                 PowerDNS (ns1)  ──API──►  PowerDNS (ns2)       │
 └──────────────────────┬────────────────────────────────────────┘
        pull config / purge / usage  (HTTPS + edge token)
          ┌─────────────┼──────────────┬─────────────────┐
          ▼             ▼              ▼                 ▼
     Edge IR-1      Edge IR-2      Edge DE-1  ...   (nginx + pcdn-agent)
          ▲             ▲              ▲
          └──── بازدیدکننده (DNS پاسخ LUA: فقط نودهای سالم) ────┘
                              │ cache miss
                              ▼
                        سرور اصلی مشتری (Origin)
```

| بخش | مسیر | توضیح |
|---|---|---|
| Controller | `controller/` | API مرکزی (Python/FastAPI). سایت‌ها، رکوردها، نودها، مصرف و SSL را مدیریت می‌کند و زون‌ها را در PowerDNS می‌نویسد |
| DNS | `dns/`, `deploy/ns2-compose.yml` | PowerDNS با LUA records. رکوردهای پروکسی با `ifurlup()` فقط IP نودهای سالم را برمی‌گردانند |
| Edge | `edge/` | nginx به‌عنوان reverse proxy + cache، و `pcdn-agent` (پایتون بدون وابستگی) که کانفیگ را از کنترلر می‌گیرد |
| WHMCS | `whmcs/modules/servers/pasargadcdn/` | ماژول Provisioning: ساخت/تعلیق/حذف خودکار، ناحیه کاربری فارسی، همگام‌سازی مصرف پهنای باند |

**Failover در دو لایه:**
1. کنترلر نودهایی را که بیش از `EDGE_OFFLINE_SECONDS` گزارش نداده‌اند از DNS حذف می‌کند.
2. خود PowerDNS هر ۵ ثانیه `http://<edge-ip>/__pcdn/health` را چک می‌کند و نود از کار افتاده را فوراً از پاسخ حذف می‌کند.

اگر هیچ نودی آنلاین نباشد، رکوردهای پروکسی به‌صورت خودکار مستقیماً به IP سرور اصلی اشاره می‌کنند تا سایت از دسترس خارج نشود.

---

## قابلیت‌ها

**برای مشتری (ناحیه کاربری WHMCS):**
- مدیریت کامل DNS: رکوردهای `A`، `AAAA`، `CNAME`، `TXT`، `MX`، `SRV`، `CAA` و `NS` (زیردامنه)
- روشن/خاموش کردن پروکسی CDN برای هر رکورد (مثل ابر نارنجی کلودفلر)
- SSL رایگان Let's Encrypt برای دامنه و `*.domain`، با صدور و تمدید خودکار
- پاکسازی کش برای آدرس‌های مشخص یا کل دامنه
- حالت توسعه (غیرفعال شدن موقت کش)، انتقال اجباری HTTP به HTTPS، و انتخاب پروتکل اتصال به Origin
- تعیین مدت کش در CDN و در مرورگر
- مسدود کردن IP و رنج IP (CIDR)
- آمار ترافیک، درخواست‌ها و نرخ کش (ماه جاری و ۱۴ روز اخیر)

**برای مدیر:**
- ساخت خودکار سرویس پس از پرداخت، و تعلیق، رفع تعلیق و حذف خودکار
- تعریف پلن‌ها در WHMCS با این مشخصات: ترافیک ماهانه، سقف تعداد رکورد، SSL و محدودیت نرخ درخواست
- امکان Configurable Options برای فروش ترافیک یا رکورد اضافه
- همگام‌سازی روزانه مصرف با WHMCS، که برای صورتحساب Overage لازم است
- قطع خودکار سرویس در صورت اتمام ترافیک ماهانه، و فعال شدن دوباره در شروع ماه بعد
- دکمه‌های ادمین برای این کارها: بررسی NS، پاکسازی کش، همگام‌سازی DNS، و درخواست SSL
- نمایش صفحه فارسی تعلیق یا اتمام ترافیک به بازدیدکنندگان
- محدودیت نرخ درخواست برای هر IP (پاسخ 429)، به‌عنوان محافظت ساده در برابر حملات لایه ۷

---

## پیش‌نیازها

| سرور | تعداد | مشخصات پیشنهادی | توضیح |
|---|---|---|---|
| Control plane | ۱ | ۲ هسته، ۴GB رم | Docker + Docker Compose. پورت‌های 53 (TCP/UDP)، 80 و 443 |
| ns2 | ۱ (توصیه‌شده) | ۱ هسته، ۱GB رم | سرور جدا در دیتاسنتر دیگر، برای اینکه DNS نقطه شکست واحد نباشد |
| Edge | ۲ یا بیشتر | ۲+ هسته، ۴GB+ رم، SSD با فضای کافی برای کش | Debian 11+ یا Ubuntu 22.04+ به‌صورت **نصب تمیز**. پورت‌های 80 و 443 |

روی Ubuntu سرویس `systemd-resolved` پورت 53 را اشغال می‌کند. روی سرورهای DNS آن را آزاد کنید:
```bash
sudo sed -i 's/#\?DNSStubListener=.*/DNSStubListener=no/' /etc/systemd/resolved.conf && sudo systemctl restart systemd-resolved
```

---

## ۱. راه‌اندازی کنترلر و DNS

روی سرور Control plane:

```bash
git clone <this-repo> /opt/pcdn && cd /opt/pcdn
cp .env.example .env
# مقادیر ADMIN_API_KEY، POSTGRES_PASSWORD و PDNS_API_KEY را با مقادیر تصادفی پر کنید:
sed -i "s/^ADMIN_API_KEY=.*/ADMIN_API_KEY=$(openssl rand -hex 32)/; \
        s/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$(openssl rand -hex 16)/; \
        s/^PDNS_API_KEY=.*/PDNS_API_KEY=$(openssl rand -hex 24)/" .env
nano .env   # CONTROLLER_DOMAIN، NAMESERVERS، ACME_EMAIL را بررسی کنید
docker compose up -d --build
```

یک رکورد A برای `cdn-api.pasargadmizban.com` بسازید که به IP همین سرور اشاره کند. Caddy برای آن به‌طور خودکار گواهی می‌گیرد. سپس اتصال را آزمایش کنید:

```bash
KEY=$(grep ^ADMIN_API_KEY .env | cut -d= -f2)
curl -H "Authorization: Bearer $KEY" https://cdn-api.pasargadmizban.com/api/v1/ping
```

### ns2 روی سرور جداگانه (توصیه‌شده)

```bash
# روی سرور ns2 (پوشه‌های dns/ و deploy/ این مخزن را کپی کنید):
cd /opt/pcdn/deploy && PDNS_API_KEY=<همان کلید کنترلر> docker compose -f ns2-compose.yml up -d
# فایروال: پورت 8081 فقط برای IP کنترلر باز باشد
ufw allow 53 && ufw allow from <CONTROLLER_IP> to any port 8081 proto tcp
```

سپس در `.env` کنترلر آدرس API سرور ns2 را اضافه کنید و `docker compose up -d` را دوباره اجرا کنید:
```
PDNS_API_URL=http://pdns:8081,http://<NS2_IP>:8081
```
از این به بعد کنترلر هر زون را روی هر دو سرور می‌نویسد، پس به Zone Transfer نیازی نیست. رکوردهای چالش SSL هم روی هر دو سرور ثبت می‌شوند.

---

## ۲. تعریف نیم‌سرورها (Glue)

چون نیم‌سرورها زیر خود `pasargadmizban.com` هستند، باید در پنل ثبت‌کننده دامنه `pasargadmizban.com`، در بخش Child Nameservers / Glue Records، این دو را تعریف کنید:

| Host | IP |
|---|---|
| `ns1.pasargadmizban.com` | IP سرور Control plane |
| `ns2.pasargadmizban.com` | IP سرور ns2 (یا همان IP قبلی اگر ns2 جدا ندارید) |

همین دو رکورد A را در DNS فعلی `pasargadmizban.com` هم اضافه کنید.

آزمایش: `dig @ns1.pasargadmizban.com example.com SOA` (پس از ساخت اولین سایت).

---

## ۳. افزودن نود Edge

**روی کنترلر، نود را ثبت کنید.** `region` برای نودهای داخل ایران `home` و برای نودهای خارج `global` است:

```bash
curl -X POST https://cdn-api.pasargadmizban.com/api/v1/edges \
  -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -d '{"name":"ir-thr-1","ipv4":"5.160.x.x","region":"home"}'
# خروجی شامل "token": "edge_..." است. این توکن فقط یک بار نمایش داده می‌شود.
```

**روی سرور Edge این دستورات را اجرا کنید:**

```bash
git clone <this-repo> /opt/pcdn && cd /opt/pcdn/edge
sudo ./install.sh --controller https://cdn-api.pasargadmizban.com --token edge_xxxxxxxx
# اگر سرور IPv6 ندارد:  --no-ipv6        اندازه کش هر سایت:  --cache-size 50g
```

اسکریپت نصب این کارها را انجام می‌دهد:
- نصب nginx پایدار از مخزن nginx.org
- نصب `pcdn-agent` به‌عنوان سرویس systemd
- تنظیم logrotate
- تنظیمات شبکه (BBR، somaxconn و ...)

حداکثر یک دقیقه بعد، نود در DNS قرار می‌گیرد. وضعیت نودها را با این دستور ببینید:

```bash
curl -H "Authorization: Bearer $KEY" https://cdn-api.pasargadmizban.com/api/v1/edges
```

فیلد `last_seen_at` باید تازه باشد و `last_error` باید خالی باشد.

| دستور | کاربرد |
|---|---|
| `journalctl -u pcdn-agent -f` | لاگ agent |
| `curl -H 'Host: health.pcdn' http://127.0.0.1/__pcdn/health` | سلامت نود |
| `curl -X PATCH ".../api/v1/edges/ID?enabled=false" -H "Authorization: Bearer $KEY"` | خارج کردن موقت نود از سرویس (برای نگهداری) |
| `curl -X POST .../api/v1/edges/ID/rotate-token -H "Authorization: Bearer $KEY"` | تعویض توکن نود |

---

## ۴. نصب ماژول WHMCS

1. پوشه `whmcs/modules/servers/pasargadcdn` را در مسیر `modules/servers/` نصب WHMCS در `my.pasargadmizban.com` کپی کنید:
   ```bash
   rsync -a whmcs/modules/servers/pasargadcdn/ /path/to/whmcs/modules/servers/pasargadcdn/
   ```
2. **تعریف سرور:** در بخش `System Settings → Servers → Add New Server` این مقادیر را وارد کنید:
   - Module: **Pasargad CDN**
   - Hostname: `cdn-api.pasargadmizban.com`
   - Access Hash: مقدار `ADMIN_API_KEY` کنترلر
   - تیک **Secure** را بزنید

   سپس دکمه **Test Connection** را بزنید. بعد یک Server Group بسازید و این سرور را در آن قرار دهید.
3. **ساخت محصول:** در بخش `System Settings → Products/Services`:
   - نوع محصول: Other
   - تیک *Require Domain* را بزنید. دامنه سرویس همان دامنه‌ای است که روی CDN می‌رود.
   - تب **Module Settings**: ماژول Pasargad CDN و Server Group را انتخاب کنید. سپس ترافیک ماهانه (GB)، سقف رکورد، SSL و Rate limit را پر کنید.
   - گزینه *Automatically setup the product as soon as the first payment is received* را انتخاب کنید.
   - (اختیاری) در تب **Custom Fields** یک فیلد متنی با نام دقیق `Origin IP` بسازید. اگر مشتری IP سرورش را وارد کند، رکوردهای `@` و `www` به‌صورت پروکسی ساخته می‌شوند.
   - (اختیاری) در تب **Other**، گزینه Overage Billing را برای Bandwidth فعال کنید و قیمت هر مگابایت اضافه را تعیین کنید.
4. **Configurable Options (اختیاری):** ماژول گزینه‌هایی با این نام‌ها را می‌شناسد و مقدارشان جایگزین مقدار پلن می‌شود:

   | نام | نوع |
   |---|---|
   | `Bandwidth` | GB |
   | `DNS Records` | تعداد |
   | `SSL` | Yes/No |
   | `Rate Limit` | درخواست در ثانیه |

   با این گزینه‌ها می‌توانید ترافیک یا رکورد اضافه بفروشید. بعد از تغییر پلن، ماژول از طریق *ChangePackage* مقادیر را به‌روز می‌کند.
5. **مصرف:** کران روزانه WHMCS تابع `UsageUpdate` را اجرا می‌کند و ستون‌های `bwusage` و `bwlimit` هر سرویس به‌روز می‌شوند. تا آن زمان، ناحیه کاربری مصرف لحظه‌ای را مستقیماً از کنترلر نشان می‌دهد.

لاگ درخواست‌های ماژول در `System Logs → Module Log` ثبت می‌شود و کلید API در آن ماسک می‌شود.

---

## روند کار مشتری

1. مشتری سرویس CDN را برای `example.com` سفارش می‌دهد و پرداخت می‌کند. ماژول سایت را روی کنترلر می‌سازد و وضعیت آن `pending_ns` است.
2. در ناحیه کاربری، نیم‌سرورهای `ns1/ns2.pasargadmizban.com` نمایش داده می‌شوند. مشتری ابتدا رکوردهای فعلی‌اش را، مثل ایمیل و زیردامنه‌ها، وارد می‌کند.
3. مشتری NS دامنه را تغییر می‌دهد. کنترلر هر ۱۰ دقیقه NS را بررسی می‌کند، و مشتری با دکمه «بررسی مجدد» هم می‌تواند فوراً بررسی را انجام دهد. پس از تأیید، وضعیت به `active` تغییر می‌کند.
4. گواهی SSL برای `example.com` و `*.example.com` به‌صورت خودکار صادر می‌شود. ۳۰ روز پیش از انقضا هم خودکار تمدید می‌شود.
5. رکوردهای پروکسی به نودهای سالم CDN اشاره می‌کنند و IP سرور اصلی مخفی می‌ماند.

> **نکته برای مشتری:** روی سرور اصلی، IP واقعی بازدیدکننده در هدرهای `X-Real-IP` و `X-Forwarded-For` ارسال می‌شود. سرور اصلی را طوری تنظیم کنید که فقط به IP نودهای CDN اعتماد کند.

---

## GeoDNS (ترافیک ایران از نودهای داخل)

به‌طور پیش‌فرض، همه نودهای سالم به‌صورت تصادفی در پاسخ DNS قرار می‌گیرند. برای اینکه کاربران ایرانی به نودهای `home` و بقیه به نودهای `global` هدایت شوند، این مراحل را انجام دهید:

1. دیتابیس رایگان [GeoLite2-City](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) را دانلود کنید و در کانتینر PowerDNS در مسیر `/etc/powerdns/GeoLite2-City.mmdb` قرار دهید. برای این کار یک volume اضافه کنید.
2. یک فایل `/etc/powerdns/geo-zones.yaml` با محتوای `domains: []` بسازید.
3. سه خط `launch+=geoip`، `geoip-database-files` و `geoip-zones-file` را در `dns/pdns.conf` از حالت توضیح خارج کنید.
4. در `.env` مقدار `GEOIP_ENABLED=true` را تنظیم کنید. در صورت تمایل `LUA_SELECTOR=pickclosest` را هم بگذارید.

بعد از این تغییرات، پاسخ DNS برای کاربران ایران ابتدا نودهای `home` است. اگر همه نودهای `home` از دسترس خارج شوند، نودهای `global` جایگزین می‌شوند. برای بقیه کاربران برعکس است.

---

## مرجع API

همه مسیرهای `/api/v1/*` هدر `Authorization: Bearer <ADMIN_API_KEY>` لازم دارند.

| متد | مسیر | کاربرد |
|---|---|---|
| GET | `/api/v1/ping` | تست اتصال |
| POST | `/api/v1/sites` | ساخت سایت `{domain, external_id?, origin_ip?, plan{...}}` |
| GET | `/api/v1/sites` · `/api/v1/sites/{domain}` | فهرست / جزئیات سایت |
| PATCH | `/api/v1/sites/{domain}/plan` | تغییر پلن |
| PATCH | `/api/v1/sites/{domain}/settings` | تنظیمات کش، HTTPS و IPهای مسدود |
| POST | `/api/v1/sites/{domain}/suspend` · `/unsuspend` | تعلیق / رفع تعلیق |
| DELETE | `/api/v1/sites/{domain}` | حذف سایت و زون |
| POST | `/api/v1/sites/{domain}/ns-check` | بررسی فوری NS |
| POST | `/api/v1/sites/{domain}/ssl` | درخواست صدور (مجدد) SSL |
| POST | `/api/v1/sites/{domain}/purge` | پاکسازی کش `{urls: []}`. لیست خالی یعنی پاکسازی کل کش |
| POST | `/api/v1/sites/{domain}/dns-sync` | نوشتن دوباره زون در PowerDNS |
| GET/POST/PUT/DELETE | `/api/v1/sites/{domain}/records[/{id}]` | مدیریت رکوردها |
| GET | `/api/v1/sites/{domain}/usage?days=30` | مصرف روزانه |
| GET | `/api/v1/usage?month=YYYY-MM` | مصرف ماهانه همه سایت‌ها (برای WHMCS) |
| GET/POST/PATCH/DELETE | `/api/v1/edges[/{id}]` | مدیریت نودها |

مسیرهای `/edge/v1/*` مخصوص agent هستند و با توکن نود احراز هویت می‌شوند: `config` (با ETag)، `heartbeat`، `purges` و `usage`.

مستندات تعاملی: `https://cdn-api.pasargadmizban.com/docs`.

---

## ساختار پروژه

```
controller/            API مرکزی (FastAPI + SQLAlchemy)
  app/routes_admin.py    API مورد استفاده WHMCS
  app/routes_edge.py     API مورد استفاده نودها
  app/dnsbuild.py        ساخت رکوردهای PowerDNS (LUA برای رکوردهای پروکسی)
  app/pdns.py            کلاینت PowerDNS (نوشتن هم‌زمان روی چند سرور)
  app/scheduler.py       failover، بررسی NS، صدور/تمدید SSL، سهمیه، پاکسازی
  app/ssl.py, acme/      صدور گواهی با acme.sh و هوک DNS-01 اختصاصی
edge/
  pcdn-agent.py          agent نود (فقط کتابخانه استاندارد پایتون)
  nginx/pcdn-base.conf   کانفیگ پایه nginx
  install.sh             نصب خودکار نود
dns/pdns.conf          تنظیمات PowerDNS
deploy/ns2-compose.yml نیم‌سرور دوم
whmcs/modules/servers/pasargadcdn/   ماژول WHMCS
```

---

## تست‌ها

```bash
cd controller && pip install -r requirements-dev.txt && python -m pytest -q
sudo python3 -m pytest -q edge/tests        # برای تست nginx -t به nginx و دسترسی root نیاز است
find whmcs -name '*.php' -exec php -l {} \;
```

این تست‌ها روی GitHub Actions هم اجرا می‌شوند (`.github/workflows/ci.yml`).

---

## عیب‌یابی

| مشکل | بررسی |
|---|---|
| سایت در `pending_ns` مانده | `dig NS example.com +short` باید فقط نیم‌سرورهای ما را نشان دهد. تغییر NS در `.ir` ممکن است چند ساعت طول بکشد |
| SSL در وضعیت `failed` | متن خطا در ناحیه کاربری و تب ادمین نمایش داده می‌شود. لاگ را با `docker compose logs controller` ببینید. رکورد CAA نباید مانع `letsencrypt.org` شود. محدودیت Let's Encrypt: ۵ صدور تکراری در هفته |
| نود در DNS نیست | `last_seen_at` نود را بررسی کنید و `journalctl -u pcdn-agent`. پورت 80 نود باید برای PowerDNS باز باشد (health check) |
| `last_error: nginx -t failed` | agent کانفیگ قبلی را حفظ کرده و سایت‌ها از کار نیفتاده‌اند. متن خطا را بررسی کنید |
| خطای 502 روی سایت | سرور اصلی مشتری پاسخ نمی‌دهد، یا پروتکل Origin (HTTP/HTTPS) اشتباه انتخاب شده است |
| خطای 421 | دامنه روی این نود تعریف نشده است. نود هنوز کانفیگ جدید را نگرفته یا رکورد پروکسی نیست |
| هدر `X-Cache` | `HIT`، `MISS`، `BYPASS`، `EXPIRED` و ... برای بررسی رفتار کش |

---

## امنیت و محدودیت‌ها

- **کلیدها و دسترسی:**
  - کلید ادمین به‌صورت ثابت‌زمانی مقایسه می‌شود.
  - توکن نودها فقط به‌صورت هش SHA-256 ذخیره می‌شود.
  - فرم‌های ناحیه کاربری توکن CSRF اختصاصی دارند و فقط برای سرویس‌های Active کار می‌کنند.
- **اعتبارسنجی ورودی:** همه ورودی‌ها در کنترلر اعتبارسنجی می‌شوند. به‌عنوان نمونه، IP خصوصی یا loopback به‌عنوان Origin پذیرفته نمی‌شود. agent هم پیش از نوشتن کانفیگ nginx، نام‌ها و Originها را دوباره بررسی می‌کند.
- **کلید خصوصی SSL:**
  - روی نودها در فایلی با دسترسی `600` ذخیره می‌شود.
  - در دیتابیس کنترلر رمزنگاری نمی‌شود، پس دسترسی به دیتابیس را محدود کنید.
- **پورت Origin:** Origin فقط روی پورت 80 یا 443 پشتیبانی می‌شود و پورت دلخواه فعلاً پشتیبانی نمی‌شود.
- **روش اتصال دامنه:**
  - فقط روش تغییر NS پشتیبانی می‌شود، مشابه آروان. روش CNAME (partial setup) پیاده‌سازی نشده است.
  - گواهی wildcard فقط یک سطح زیردامنه را پوشش می‌دهد. `a.b.example.com` را پوشش نمی‌دهد.
- **محافظت در برابر حمله:** Rate limit و مسدودسازی IP محافظت پایه‌ای هستند. در برابر حملات حجیم لایه ۳ و ۴، به ظرفیت و فیلترینگ دیتاسنتر نودها نیاز دارید.
