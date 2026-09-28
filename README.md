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
| Edge | `edge/` | nginx به‌عنوان reverse proxy و cache. `edge/njs/pcdn.js` فایروال، WAF، چالش‌ها، محدودیت نرخ و توزیع بار را داخل nginx اجرا می‌کند. `pcdn-agent` (پایتون بدون وابستگی) کانفیگ را از کنترلر می‌گیرد و آمار را برمی‌گرداند. جزئیات در [`docs/EDGE.md`](docs/EDGE.md) |
| WHMCS | `whmcs/modules/servers/pasargadcdn/` | ماژول Provisioning: ساخت/تعلیق/حذف خودکار، ناحیه کاربری فارسی، همگام‌سازی مصرف پهنای باند |

**Failover در دو لایه:**
1. کنترلر نودهایی را که بیش از `EDGE_OFFLINE_SECONDS` گزارش نداده‌اند از DNS حذف می‌کند.
2. خود PowerDNS هر ۵ ثانیه `http://<edge-ip>/__pcdn/health` را چک می‌کند و نود از کار افتاده را فوراً از پاسخ حذف می‌کند.

اگر هیچ نودی آنلاین نباشد، رکوردهای پروکسی به‌صورت خودکار مستقیماً به IP سرور اصلی اشاره می‌کنند تا سایت از دسترس خارج نشود.

---

## قابلیت‌ها

فهرست زیر با امکانات CDN آروان‌کلود مقایسه شده است. ستون «پلن» یعنی مدیر می‌تواند آن قابلیت را برای هر محصول WHMCS روشن یا خاموش کند.

| دسته | قابلیت | پلن |
|---|---|---|
| **DNS** | رکوردهای A، AAAA، CNAME، **ALIAS** (روی ریشه دامنه)، TXT، MX، SRV، CAA و NS | سقف تعداد رکورد |
| | پروکسی (ابر نارنجی) برای هر رکورد و مخفی ماندن IP سرور اصلی | |
| | **Health check روی رکوردهای چند IP** بدون پروکسی: فقط IPهای سالم پاسخ داده می‌شوند | |
| | **DNSSEC** با یک کلید مشترک روی همه نیم‌سرورها، همراه با نمایش رکورد DS | ✔ |
| | **ورود و خروجی فایل زون** (BIND) | |
| | GeoDNS: کاربران ایران به نودهای داخل هدایت می‌شوند | |
| **کش** | سطح کش استاندارد (احترام به هدرهای Origin) یا تهاجمی (کش همه پاسخ‌ها) | |
| | مدت کش در CDN و در مرورگر، نادیده گرفتن Query String، و عبور از کش برای کوکی‌های مشخص (مثل ورود وردپرس) | |
| | Always Online: نمایش نسخه کش‌شده وقتی Origin از دسترس خارج است | |
| | حالت توسعه، و پاکسازی کش برای آدرس‌های مشخص یا کل دامنه | |
| | فشرده‌سازی Brotli و gzip، HTTP/2 و WebSocket | |
| **قوانین صفحه** | برای هر الگوی مسیر (مثلاً `/wp-admin/*`): عبور از کش یا کش همه‌چیز، TTL، Query String، خاموش کردن WAF، و ریدایرکت 301/302/307/308 | سقف تعداد |
| **SSL/TLS** | گواهی رایگان Let's Encrypt برای دامنه و wildcard، با صدور و تمدید خودکار | ✔ |
| | **آپلود گواهی اختصاصی** با بررسی تطابق کلید، انقضا و پوشش دامنه | ✔ |
| | HTTPS اجباری، **HSTS** (شامل preload)، **حداقل نسخه TLS**، اتصال HTTPS به Origin با امکان بررسی گواهی Origin | |
| **امنیت** | **فایروال** با قوانین مرتب. شرط‌ها: IP/CIDR، کشور، مسیر، هاست، Query، User-Agent، Referer، متد و هدر. اقدام‌ها: اجازه، مسدود، چالش JS، کپچا و ثبت | سقف تعداد |
| | **WAF** با گروه‌های SQLi، XSS، LFI، RCE، PHP، اسکنرها و پروتکل. حالت تشخیص یا مسدودسازی، سه سطح حساسیت، و استثنا بر اساس قانون و مسیر | ✔ |
| | **حفاظت DDoS لایه ۷**: حالت خودکار (چالش پس از عبور از آستانه)، چالش JS برای همه، یا کپچا برای همه | ✔ |
| | **محدودیت نرخ درخواست** بر اساس مسیر و متد، با اقدام مسدود یا چالش | سقف تعداد |
| | **جلوگیری از Hotlink** و مسدودسازی IP | |
| **توزیع بار** | استخر سرورهای Origin با وزن و سرور پشتیبان، روش وزنی یا چسبنده (IP Hash)، و **Health check فعال** از روی هر نود | ✔ |
| | پورت دلخواه برای Origin | |
| **سایر** | **بهینه‌سازی تصویر**: تغییر اندازه با `?width=` و `?height=` و تنظیم کیفیت | ✔ |
| | **هدرهای سفارشی** در درخواست به Origin و پاسخ به کاربر (افزودن یا حذف) | |
| | **صفحات خطای سفارشی** برای خطاهای 4xx و 5xx | |
| **گزارش‌ها** | **آنالیتیکس**: درخواست، ترافیک، نرخ کش، کدهای وضعیت، کشورها، پرترافیک‌ترین مسیرها و آمار امنیتی. بازه‌های ۲۴ ساعت، ۷ روز و ۳۰ روز | |
| | **رویدادهای امنیتی**: ۱۰۰۰ رویداد آخر همراه با IP، کشور، مسیر، قانون و اقدام | |
| **WHMCS** | ساخت، تعلیق و حذف خودکار، تغییر پلن، همگام‌سازی مصرف برای صورتحساب ترافیک اضافه، و قطع سرویس با اتمام ترافیک | |
| | پنل کاربری فارسی تک‌صفحه‌ای با همه بخش‌های بالا | |

**فعلاً پیاده‌سازی نشده (نسبت به آروان):**
- HTTP/3/QUIC: nginx مخزن Ubuntu آن را ندارد.
- بازرسی بدنه درخواست POST در WAF: فقط URL، پارامترها و هدرها بررسی می‌شوند.
- تبدیل خودکار تصاویر به WebP.
- کش لایه‌ای (Origin Shield).
- ارسال لاگ به سرویس بیرونی (Log Forwarding).
- دسترسی چندکاربره و API برای مشتری. مشتری از طریق WHMCS کار می‌کند.
- اتصال با CNAME (partial setup).

سرویس‌های مستقل آروان، یعنی پخش ویدیو، فضای ابری Object Storage و Edge Computing، جزو CDN نیستند و در این پروژه قرار ندارند.

---

## پیش‌نیازها

| سرور | تعداد | مشخصات پیشنهادی | توضیح |
|---|---|---|---|
| Control plane | ۱ | ۲ هسته، ۴GB رم | Docker + Docker Compose. پورت‌های 53 (TCP/UDP)، 80 و 443 |
| ns2 | ۱ (توصیه‌شده) | ۱ هسته، ۱GB رم | سرور جدا در دیتاسنتر دیگر، برای اینکه DNS نقطه شکست واحد نباشد |
| Edge | ۲ یا بیشتر | ۲+ هسته، ۴GB+ رم، SSD با فضای کافی برای کش | **Ubuntu 24.04** به‌صورت نصب تمیز (برای njs، GeoIP2، Brotli و image-filter). پورت‌های 80 و 443 |

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
ufw allow 53
sudo ./ns2-firewall.sh <CONTROLLER_IP>   # ufw روی پورت‌های Docker اثر ندارد
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
- نصب nginx مخزن Ubuntu همراه با ماژول‌های njs، GeoIP2، Brotli و image-filter
- دانلود ماهانه دیتابیس رایگان کشورها (DB-IP Lite) برای قوانین فایروال بر اساس کشور. با `--no-geoip` این مرحله انجام نمی‌شود.
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

> راهنمای کامل WHMCS، شامل پنل مدیریت CDN، ساخت خودکار پلن‌ها و قیمت‌ها و سناریوی سفارش مشتری، در [`docs/WHMCS.md`](docs/WHMCS.md) آمده است. خلاصه آن:
> 1. پوشه‌های `whmcs/modules/servers/pasargadcdn` و `whmcs/modules/addons/pasargadcdn_admin` را آپلود کنید.
> 2. افزونه «مدیریت CDN پاسارگاد» را در `System Settings → Addon Modules` فعال کنید و دسترسی نقش مدیران را به آن بدهید.
> 3. سرور را تعریف کنید و از صفحه «پلن‌ها و قیمت‌گذاری» جادوی ساخت محصولات را اجرا کنید.
>
> مراحل دستی زیر برای مواقعی است که بخواهید محصولات را خودتان بسازید.

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
5. **قابلیت‌های پلن:** در تب Module Settings، علاوه بر ۴ گزینه قبلی، این گزینه‌ها هم هستند:
   - روشن/خاموش: WAF، حفاظت DDoS، توزیع بار، بهینه‌سازی تصویر، گواهی اختصاصی و DNSSEC
   - سقف تعداد: قوانین صفحه، قوانین فایروال، قوانین محدودیت نرخ و استخرهای توزیع بار

   با Configurable Options به این نام‌ها می‌توانید هر کدام را جداگانه بفروشید: `WAF`، `DDoS`، `Load Balancer`، `Image Optimization`، `Custom SSL`، `DNSSEC`، `Page Rules`، `Firewall Rules`، `Rate Limit Rules` و `LB Pools`.
   > اگر محصولی را پیش از این نسخه ساخته‌اید، این گزینه‌ها برایش خالی هستند و همه قابلیت‌ها خاموش حساب می‌شوند. قبل از اجرای ChangePackage آن‌ها را تیک بزنید.
6. **پنل مشتری:** ناحیه کاربری یک برنامه تک‌صفحه‌ای فارسی است: فایل‌های `assets/*.js`، بدون هیچ کتابخانه خارجی، با فونت Vazirmatn که همراه ماژول است. امکانات پنل:
   - منوی کناری گروه‌بندی‌شده
   - داشبورد با چک‌لیست راه‌اندازی و اقدامات سریع (پاکسازی کش، حالت توسعه، حالت زیر حمله)
   - قالب‌های آماده برای فایروال، WAF، کش، قوانین صفحه و محدودیت نرخ
   - بخش «راهنما و آموزش» با ۱۱ آموزش گام‌به‌گام. کدهای تنظیم سرور در این آموزش‌ها (nginx، Apache، وردپرس، Laravel و فایروال) به‌طور خودکار با IP نودهای CDN ساخته می‌شوند.

   این برنامه این برنامه از طریق `modules/servers/pasargadcdn/api.php` با کنترلر حرف می‌زند:
   - مالکیت سرویس و توکن CSRF بررسی می‌شود.
   - فقط مسیرهای مجاز به کنترلر ارسال می‌شوند.
   - دامنه همیشه از خود سرویس خوانده می‌شود، نه از درخواست کاربر.
   - کلید API هرگز به مرورگر نمی‌رسد.
   - روی سرویس معلق فقط امکان مشاهده وجود دارد.
7. **مصرف:** کران روزانه WHMCS تابع `UsageUpdate` را اجرا می‌کند و ستون‌های `bwusage` و `bwlimit` هر سرویس به‌روز می‌شوند. تا آن زمان، ناحیه کاربری مصرف لحظه‌ای را مستقیماً از کنترلر نشان می‌دهد.

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

به‌طور پیش‌فرض، همه نودهای سالم به‌صورت تصادفی در پاسخ DNS قرار می‌گیرند. با GeoDNS:
- کاربران ایران فقط نودهای `home` را می‌گیرند.
- بقیه کاربران نودهای `global` را می‌گیرند.
- اگر همه نودهای یک گروه از کار بیفتند، گروه دیگر خودکار جایگزین می‌شود.

این رفتار روی PowerDNS 4.9 واقعی تست شده است.

روی سرور کنترل‌پنل (و روی ns2، اگر جداست):

1. دیتابیس رایگان کشورها (DB-IP Lite، مجوز CC BY 4.0) را دانلود کنید:
   ```bash
   cd /opt/pcdn && sudo deploy/geoip-update.sh --no-restart
   ```
2. به `.env` این دو خط را اضافه کنید:
   ```
   COMPOSE_FILE=docker-compose.yml:deploy/geoip.override.yml
   GEOIP_ENABLED=true
   ```
3. سرویس‌ها را بالا بیاورید و همه زون‌ها را دوباره بنویسید:
   ```bash
   sudo docker compose up -d
   sudo docker compose exec controller python -m app.manage dns-sync
   ```
4. برای به‌روزرسانی ماهانه دیتابیس، کران اضافه کنید:
   ```bash
   echo '0 4 3 * * root /opt/pcdn/deploy/geoip-update.sh >> /var/log/pcdn-geoip.log 2>&1' | sudo tee /etc/cron.d/pcdn-geoip
   ```
5. **روی ns2:** مرحله ۱ را در همان مسیر اجرا کنید، سپس با `-f ns2-compose.yml -f ns2-geoip.override.yml` بالا بیاورید. هر دو نیم‌سرور باید پاسخ یکسان بدهند.

اگر `download.db-ip.com` از سرور در دسترس نبود، فایل `dbip-country-lite-YYYY-MM.mmdb.gz` را از جای دیگری دانلود کنید. آن را از حالت فشرده خارج کنید و با نام `dns/geo/country.mmdb` روی سرور بگذارید.

## مرجع API

همه مسیرهای `/api/v1/*` هدر `Authorization: Bearer <ADMIN_API_KEY>` لازم دارند. قرارداد کامل بین اجزا، شامل ساختار JSON هر بخش، در [`docs/SPEC.md`](docs/SPEC.md) آمده است.

| متد | مسیر | کاربرد |
|---|---|---|
| GET | `/api/v1/ping` | تست اتصال |
| POST | `/api/v1/sites` | ساخت سایت `{domain, external_id?, origin_ip?, plan{..., features{...}}}` |
| GET | `/api/v1/sites` · `/api/v1/sites/{domain}` | فهرست / جزئیات سایت (شامل `config` همه بخش‌ها) |
| PATCH | `/api/v1/sites/{domain}/plan` | تغییر پلن و قابلیت‌ها |
| GET / PUT | `/api/v1/sites/{domain}/config/{section}` | بخش‌های `cache`، `ssl`، `waf`، `ddos`، `firewall`، `ratelimit`، `pagerules`، `pools`، `headers`، `hotlink`، `image` و `errorpages` |
| PATCH | `/api/v1/sites/{domain}/settings` | تنظیمات v1 (برای سازگاری) |
| POST | `/api/v1/sites/{domain}/suspend` · `/unsuspend` | تعلیق / رفع تعلیق |
| DELETE | `/api/v1/sites/{domain}` | حذف سایت و زون |
| POST | `/api/v1/sites/{domain}/ns-check` | بررسی فوری NS |
| POST | `/api/v1/sites/{domain}/ssl` | درخواست صدور (مجدد) Let's Encrypt |
| PUT / DELETE | `/api/v1/sites/{domain}/ssl/custom` | آپلود / حذف گواهی اختصاصی |
| GET / POST | `/api/v1/sites/{domain}/dnssec` | وضعیت / فعال‌سازی DNSSEC (همراه با DS) |
| POST | `/api/v1/sites/{domain}/purge` | پاکسازی کش `{urls: []}`. لیست خالی یعنی پاکسازی کل کش |
| POST | `/api/v1/sites/{domain}/dns-sync` | نوشتن دوباره زون در PowerDNS |
| GET/POST/PUT/DELETE | `/api/v1/sites/{domain}/records[/{id}]` | رکوردها، شامل `pool`، `origin_port`، `health_check` و `health_port` |
| POST / GET | `/api/v1/sites/{domain}/records/import` · `/export` | ورود و خروجی فایل زون BIND |
| GET | `/api/v1/sites/{domain}/analytics?period=24h\|7d\|30d` | آنالیتیکس |
| GET | `/api/v1/sites/{domain}/events?limit=100` | رویدادهای امنیتی |
| GET | `/api/v1/sites/{domain}/usage?days=30` | مصرف روزانه |
| GET | `/api/v1/usage?month=YYYY-MM` | مصرف ماهانه همه سایت‌ها (برای WHMCS) |
| GET/POST/PATCH/DELETE | `/api/v1/edges[/{id}]` | مدیریت نودها |

مسیرهای `/edge/v1/*` مخصوص agent هستند و با توکن نود احراز هویت می‌شوند: `config` (با ETag)، `heartbeat`، `purges` و `usage` (که آمار و رویدادها را هم شامل می‌شود).

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
  njs/pcdn.js            منطق امنیت و توزیع بار داخل nginx (فایروال، WAF، چالش، محدودیت نرخ، health check)
  nginx/pcdn-base.conf   قالب کانفیگ پایه nginx
  install.sh             نصب خودکار نود
  pcdn-geoip-update.sh   به‌روزرسانی ماهانه دیتابیس کشورها
dns/pdns.conf          تنظیمات PowerDNS
deploy/ns2-compose.yml نیم‌سرور دوم
whmcs/modules/servers/pasargadcdn/   ماژول WHMCS
  api.php, lib/ClientApi.php         پروکسی امن بین پنل مشتری و کنترلر
  assets/app.js, assets/app.css      پنل مشتری
docs/SPEC.md           قرارداد بین اجزا
docs/EDGE.md           معماری نود
```

---

## تست‌ها

```bash
cd controller && pip install -r requirements-dev.txt && python -m pytest -q       # ۹۱ تست (۱۲ تست PostgreSQL با PCDN_TEST_PG_URL)
# تست‌های نود روی nginx واقعی با njs اجرا می‌شوند (Ubuntu 24.04 + ماژول‌های بالا، با دسترسی root)
sudo python3 -m pytest -q edge/tests                                              # ۴۶ تست
find whmcs -name '*.php' -exec php -l {} \;
```

این تست‌ها روی GitHub Actions هم اجرا می‌شوند (`.github/workflows/ci.yml`).

---

## نگهداری و عملیات

راهنمای کامل نگهداری در [`docs/OPERATIONS.md`](docs/OPERATIONS.md) آمده است و این موارد را پوشش می‌دهد:
- **مهاجرت دیتابیس (Alembic):** در هر بار شروع خودکار اجرا می‌شود.
- **هشدار تلگرام و ایمیل:** برای قطع شدن نودها، خطای DNS، مشکلات SSL و شکست پشتیبان‌گیری.
- **پشتیبان‌گیری روزانه:** رمزنگاری‌شده، با امکان آپلود روی فضای S3 مثل فضای ابری آروان، و راهنمای بازیابی.
- **High Availability:** چند نسخه کنترلر با انتخاب رهبر، و راهنمای راه‌اندازی دو سروره.
- **رمزنگاری کلیدها و تعویض کلید.**
- **پایش سلامت** از طریق `/healthz/deep`.

دستورهای مدیریتی با `docker compose exec controller python -m app.manage <command>` اجرا می‌شوند.

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
  - در دیتابیس کنترلر با `DATA_ENCRYPTION_KEY` رمزنگاری می‌شود (همین‌طور کلید چالش‌های امنیتی هر سایت). اگر کلید تنظیم نشده باشد، در لاگ شروع و در `/healthz/deep` هشدار داده می‌شود. جزئیات در [`docs/OPERATIONS.md`](docs/OPERATIONS.md).
- **رفتار امن‌تر از مشخصات:**
  - در کش تهاجمی و قانون «کش همه‌چیز»، پاسخ‌هایی که کوکی تنظیم می‌کنند هرگز کش نمی‌شوند تا نشست یک کاربر به کاربر دیگر نرسد.
  - اگر کشور یک IP مشخص نباشد، شرط کشور در فایروال برقرار نمی‌شود. به این ترتیب قانون «همه به‌جز ایران را مسدود کن» در نبود دیتابیس GeoIP همه را مسدود نمی‌کند.
- **حداقل نسخه TLS:** در nginx 1.24 تنظیم آن برای هر دامنه جداگانه عمل نمی‌کند، پس در njs اعمال می‌شود: درخواست با TLS پایین‌تر رد می‌شود، ولی handshake انجام می‌شود.
- **روش اتصال دامنه:**
  - فقط روش تغییر NS پشتیبانی می‌شود، مشابه آروان. روش CNAME (partial setup) پیاده‌سازی نشده است.
  - گواهی wildcard فقط یک سطح زیردامنه را پوشش می‌دهد. `a.b.example.com` را پوشش نمی‌دهد.
- **محافظت در برابر حمله:** Rate limit و مسدودسازی IP محافظت پایه‌ای هستند. در برابر حملات حجیم لایه ۳ و ۴، به ظرفیت و فیلترینگ دیتاسنتر نودها نیاز دارید.
