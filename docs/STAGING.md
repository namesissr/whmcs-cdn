# محیط Staging و آزمون‌های یکپارچه (End-to-End) — CDN پاسارگاد

این سند توضیح می‌دهد چطور با **یک دستور** یک نسخهٔ کامل و ایزوله از کل سامانه (کنترلر، PostgreSQL،
PowerDNS، دو نود Edge، یک سرور اصلی نمونه و در صورت نیاز MinIO) را روی یک ماشین با Docker بالا
بیاوریم و آزمون‌های سرتاسری `tests/integration` را روی آن اجرا کنیم. همین مسیر در CI (job
`integration`) روی هر push و pull request اجرا می‌شود.

> **فقط برای آزمون.** همهٔ کلیدها و رمزهای `deploy/staging/compose.yml` مقادیر ثابت و عمومی‌اند
> (مثل `staging-admin-key` و یک `DATA_ENCRYPTION_KEY` ثابت). هرگز آن‌ها را در محیط واقعی به کار نبرید
> و این پشته را روی اینترنت منتشر نکنید (هیچ پورتی روی میزبان publish نمی‌شود).

## فهرست

- [شروع سریع](#شروع-سریع)
- [اجزای پشته](#اجزای-پشته)
- [نود Edge چطور ثبت و نصب می‌شود](#نود-edge-چطور-ثبت-و-نصب-میشود)
- [چرا تصویر Ubuntu و نه تصویر اختصاصی؟](#چرا-تصویر-ubuntu-و-نه-تصویر-اختصاصی)
- [آزمون‌ها چه چیزی را می‌سنجند](#آزمونها-چه-چیزی-را-میسنجند)
- [اجرای آزمون‌ها از روی میزبان](#اجرای-آزمونها-از-روی-میزبان)
- [پروفایل‌های اختیاری: Storage و L4](#پروفایلهای-اختیاری-storage-و-l4)
- [CI](#ci)
- [دروازهٔ انتشار (staging gate)](#دروازهٔ-انتشار-staging-gate)
- [عیب‌یابی](#عیبیابی)
- [محدودیت‌ها و تفاوت با محیط واقعی](#محدودیتها-و-تفاوت-با-محیط-واقعی)

## شروع سریع

پیش‌نیاز: Docker Engine با Compose v2 (۲.۱۷ یا جدیدتر برای `--wait-timeout`) و دسترسی خروجی به
اینترنت (ساخت تصاویر، و `apt-get update` که `install.sh` روی نودها اجرا می‌کند).

```bash
deploy/staging/staging.sh up      # build + up + صبر تا همهٔ سرویس‌ها healthy شوند (چند دقیقه بار اول)
deploy/staging/staging.sh test    # اجرای tests/integration داخل کانتینر runner
deploy/staging/staging.sh down    # حذف کامل کانتینرها، شبکه و volumeها
```

یا همه با هم (کاری که CI انجام می‌دهد؛ در صورت شکست لاگ‌ها چاپ می‌شوند و در هر حال پشته پاک می‌شود):

```bash
deploy/staging/staging.sh ci
```

دستورهای کمکی:

| دستور | کار |
|---|---|
| `staging.sh test -k purge -x` | آرگومان‌های pytest مستقیم پاس داده می‌شوند |
| `staging.sh logs [dir]` | لاگ همهٔ سرویس‌ها + `error.log` و `agent.conf` (توکن حذف‌شده) و `nginx -T` هر نود + فهرست نودها از API |
| `staging.sh ps` | وضعیت کانتینرها |
| `staging.sh compose <args>` | هر دستور `docker compose` روی همین پشته (مثلاً `compose exec edge-1 bash`) |
| `staging.sh config` | اعتبارسنجی فایل compose |

متغیرهای محیطی: `STAGING_STORAGE=1` (افزودن MinIO)، `STAGING_NET=a.b.c` (تغییر زیرشبکهٔ /24)،
`STAGING_WAIT_TIMEOUT` (ثانیه، پیش‌فرض ۹۰۰)، `STAGING_ADMIN_API_KEY`.

## اجزای پشته

همهٔ سرویس‌ها روی یک شبکهٔ bridge با زیرشبکهٔ `11.200.0.0/24` هستند و IP ثابت دارند:

| سرویس | IP | توضیح |
|---|---|---|
| `db` | پویا | `postgres:16-alpine` (همان نسخهٔ محیط واقعی) |
| `pdns` | `11.200.0.53` | `powerdns/pdns-auth-49` با همان `dns/pdns.conf` (رکوردهای LUA، `ifurlup`) |
| `controller` | `11.200.0.10` | تصویر ساخته‌شده از `controller/Dockerfile`؛ HTTP روی ۸۰۰۰، بستهٔ نود از `edge/` سرو می‌شود |
| `origin` | `11.200.0.80` | `deploy/staging/origin/staging_origin.py`: اکوی HTTP روی ۸۰، سرور `tools/loadtest/origin.py` (WebSocket/HTTPUpgrade/XHTTP/gRPC) روی ۸۰۸۰، اکوی TCP روی ۹۰۰۰ |
| `runner` | `11.200.0.100` | ثبت نودها از طریق API ادمین، سپس میزبان اجرای pytest (`dig`، `boto3`) |
| `edge-1`، `edge-2` | `11.200.0.21`، `.22` | Ubuntu 24.04 که با نصب‌کنندهٔ تک‌دستوری خود کنترلر نصب می‌شود |
| `minio`، `minio-init` | `11.200.0.90` | فقط با پروفایل `storage` |

**چرا `11.200.0.0/24` و نه یک بازهٔ خصوصی؟** کنترلر آدرس خصوصی را برای نود و سرور اصلی نمی‌پذیرد
(`validate_ip`: «آدرس IP باید عمومی باشد»)، پس `10/8`، `172.16/12` و `192.168/16` قابل استفاده نیستند.
این بازه از درون bridge به اینترنت مسیریابی نمی‌شود؛ اگر روی میزبان شما تداخل دارد با
`STAGING_NET=<a.b.c>` یک /24 دیگر (غیرخصوصی از نگاه پایتون) انتخاب کنید.

تنظیمات کنترلر برای سرعت آزمون: `SCHEDULER_INTERVAL=5`، `EDGE_OFFLINE_SECONDS=60`،
`LUA_SELECTOR=all` (پاسخ DNS همهٔ نودهای سالم را دارد تا آزمون قطعی باشد)، `NS_RESOLVERS` روی
PowerDNS خودمان (تا بررسی نیم‌سرور دامنه‌های `.staging.test` موفق شود)، و خاموش بودن پشتیبان‌گیری،
GeoDNS، بررسی Geo و دریافت بازه‌های ربات (بدون ترافیک خروجی غیرضروری). پلن سایت‌های آزمون
`ssl_allowed=false` است تا ACME اجرا نشود.

نرخ‌های عامل نود با متغیرهای `PCDN_*` (که `load_config` عامل می‌خواند) کوتاه شده‌اند:
poll هر ۲ ثانیه، heartbeat هر ۱۰، گزارش مصرف هر ۵، و `RELOAD_MIN_INTERVAL=2` / `RELOAD_DEBOUNCE=1`
(در محیط واقعی ۲۰/۶۰/۶۰/۱۲۰/۵).

## نود Edge چطور ثبت و نصب می‌شود

هیچ میان‌بری از مسیر محصول وجود ندارد:

1. `runner` (نقش اپراتور/WHMCS) با `ADMIN_API_KEY` برای هر نود `POST /api/v1/edges` را با نام، IP،
   region=`global` و group=`general` صدا می‌زند و **توکن یک‌بارمصرف** و **تک‌دستور نصب** را که کنترلر
   برمی‌گرداند در volume مشترک `staging-tokens` می‌نویسد (`deploy/staging/runner/provision.py`). اگر
   نود از قبل وجود داشته باشد ولی فایل توکنش نباشد، توکن با `rotate-token` چرخانده می‌شود.
2. کانتینر نود (`deploy/staging/edge/entrypoint.sh`) منتظر فایل توکن خودش می‌ماند و **همان تک‌دستور**
   را اجرا می‌کند:
   `curl -fsSL <controller>/edge/bootstrap.sh | sudo PCDN_EDGE_TOKEN=edge_... bash -s -- --controller <controller> --region global --role general`
   (توکن در **محیط** `PCDN_EDGE_TOKEN` است، نه پرچم `--token`، تا در `ps` / `/proc/<pid>/cmdline` دیده
   نشود). یعنی `bootstrap.sh` بستهٔ `GET /edge/bundle.tar.gz` را از کنترلر می‌گیرد، نسخهٔ `GET /edge/version` را
   ثبت می‌کند و `install.sh` واقعی را اجرا می‌کند. فقط این تفاوت‌های عمدی را دارد:
   - آدرس `https://<CONTROLLER_DOMAIN>` به `http://controller:8000` تبدیل می‌شود (در staging جلوی
     کنترلر TLS/Caddy نیست)؛ برای همین پرچم `--insecure-http` لازم است (`bootstrap.sh` بدون آن آدرس
     `http://` کنترلر را رد می‌کند)؛
   - `sudo` حذف می‌شود (کانتینر root است و `sudo` متغیرهای `PCDN_*` را پاک می‌کرد)؛ توکن از تک‌دستور
     جدا و به‌صورت `PCDN_EDGE_TOKEN` به `bash` داده می‌شود (همان کاری که `sudo PCDN_EDGE_TOKEN=… bash`
     می‌کند) و در لاگ کانتینر `edge_<redacted>` چاپ می‌شود. `provision.py` تک‌دستوری با شکل دیگر (مثلاً
     با `--token`) را رد می‌کند؛
   - پرچم‌های `--insecure-http --no-geoip --no-ipv6 --no-avif` (متغیر `EDGE_INSTALL_FLAGS`) اضافه می‌شوند؛
   - `PCDN_ORIGIN_PRIVATE_ALLOW=<STAGING_NET>.0/24` (پیش‌فرض `11.200.0.0/24`) در محیط نود است: نگهبان
     مبدأ (origin guard) لبه — هم بررسی عامل و هم جدول nftables `pcdn_origin_guard` که `install.sh` با
     همین مقدار می‌سازد — شبکهٔ staging را (مبدأ `.80`، MinIO `.90`، نام‌های DNS داکر) به‌عنوان شبکهٔ
     خصوصی مجاز مبدأ می‌پذیرد. روی سرور واقعی همین تنظیم `ORIGIN_PRIVATE_ALLOW=` در `/etc/pcdn/agent.conf` است.
3. پس از نصب، nginx (daemon) بالا است و `pcdn-agent` در پیش‌زمینه به‌عنوان فرایند اصلی کانتینر اجرا
   می‌شود (معادل `pcdn-agent.service`). عامل کانفیگ را از `/edge/v1/config` می‌کشد، heartbeat می‌فرستد و
   کنترلر پس از نخستین heartbeat نود را وارد DNS می‌کند.

healthcheck نود: پاسخ `/__pcdn/health` با Host `health.pcdn` **و** وجود `state.json` عامل (یعنی دست‌کم
یک همگام‌سازی موفق با کنترلر). `staging.sh up` تا healthy شدن همهٔ سرویس‌ها صبر می‌کند.

## چرا تصویر Ubuntu و نه تصویر اختصاصی؟

انتخاب: **تصویر `ubuntu:24.04` که `edge/install.sh` واقعی را از طریق `bootstrap.sh` اجرا می‌کند**
(`deploy/staging/edge/Dockerfile`). دلیل: هدف staging آزمودن همان مسیری است که اپراتور روی سرور تازه
طی می‌کند — بستهٔ کنترلر، `bootstrap.sh`، ویرایش‌های `nginx.conf`، `agent.conf`، `pcdn-agent bootstrap` و
`once` — و یک تصویر اختصاصی که nginx و عامل را مستقیم نصب کند همهٔ این‌ها را دور می‌زد.

برای سرعت و پایداری، همان بسته‌هایی که `install.sh` نصب می‌کند (nginx توزیع + njs، geoip2،
image-filter، brotli، stream و python3-pil) **از قبل در تصویر** نصب شده‌اند؛ `install.sh` در زمان اجرا
فقط `apt-get update` می‌کند و `apt-get install`ش بی‌اثر است (پس نود به mirror اوبونتو دسترسی لازم دارد).

بخش‌هایی که در کانتینر غیرفعال‌اند یا جایگزین دارند:

| بخش | وضعیت در staging |
|---|---|
| systemd | وجود ندارد؛ `deploy/staging/edge/systemctl` (shim) فراخوانی‌ها را ترجمه می‌کند: `nginx` ← اجرای daemon / `nginx -s reload`، `pcdn-imaged` ← اجرا در پس‌زمینه (بدون sandbox سیستم‌دی)، `pcdn-agent` ← بی‌اثر (entrypoint اجرایش می‌کند)، بقیه (تایمرهای GeoIP، `pcdn-guard`، `pcdn-fn`) ← بی‌اثر با پیام |
| sysctl / modprobe / `tc qdisc` / conntrack | `install.sh` خودش شکست آن‌ها را تحمل می‌کند (`|| true`)؛ در کانتینر بدون امتیاز اعمال نمی‌شوند |
| nftables (`--harden-net`) | نصب نمی‌شود (پیش‌فرض خاموش) |
| نگهبان مبدأ (origin guard، nftables) | `install.sh` نصبش را امتحان می‌کند؛ در کانتینر بدون `CAP_NET_ADMIN`، `nft` معمولاً رد می‌کند و نصب با هشدار رد می‌شود (`ORIGIN_GUARD=no`)؛ بررسی آدرس مبدأ در خود عامل با `PCDN_ORIGIN_PRIVATE_ALLOW` همچنان فعال است |
| توابع لبه (`--functions`) | نصب نمی‌شود (Landlock/seccomp/DynamicUser نیاز به systemd دارند) |
| GeoIP | `--no-geoip`: پایگاه کشور دانلود نمی‌شود؛ قوانین کشوری fail-open هستند |
| IPv6 | `--no-ipv6` |
| init | `tini` به‌عنوان PID 1 (جمع کردن فرایندهای reload nginx) |

اگر کانتینر نود دوباره راه‌اندازی شود، نشانگر `/var/lib/pcdn/.staging-installed` (فقط پس از نصب موفق
نوشته می‌شود) باعث می‌شود نصب تکرار نشود و فقط nginx و عامل بالا بیایند.

## آزمون‌ها چه چیزی را می‌سنجند

`tests/integration/test_e2e.py` یک سایت می‌سازد و به ترتیب فایل اجرا می‌شود (هر گام برای بخش
«به‌مرور سازگار» — poll عامل، reload، ارسال مصرف — با `wait_until` صبر می‌کند، نه sleep ثابت):

1. نودها از بستهٔ کنترلر نصب شده‌اند: `bundle_version` هر نود با `GET /edge/version` برابر است، region/group
   درست است و قابلیت `njs` گزارش شده.
2. ساخت سایت با `POST /api/v1/sites` (رکوردهای پروکسی `@` و `www`)، افزودن رکوردهای `api` (پروکسی)،
   `direct` (بدون پروکسی) و TXT؛ `ns-check` وضعیت را از `pending_ns` به `active` می‌برد.
3. DNS: `dig` روی PowerDNS — نام‌های پروکسی دقیقاً IP نودها را برمی‌گردانند (هرگز IP اصلی را)،
   `direct` IP اصلی را، NS و TXT درست‌اند.
4. HTTP از هر نود به سرور اصلی می‌رسد و Host حفظ می‌شود؛ میزبان ناشناخته به هیچ اصلی نمی‌رسد.
5. کش: درخواست اول `X-Cache: MISS`، دوم `HIT` با همان بدنه و فقط یک برخورد به اصل.
6. Purge با API ادمین ← نود دوباره از اصل می‌گیرد (MISS و بدنهٔ جدید) و سپس دوباره HIT.
7. WAF (حالت block، الگوی XSS) و قانون فایروال (مسیر) ← 403 و درخواست مسدود به اصل نمی‌رسد.
8. تونل: مسیر `ws` با origin روی ۸۰۸۰ ← دست‌دادن 101 و اکوی پیام WebSocket از هر نود.
9. مصرف به کنترلر می‌رسد: `GET /sites/{d}/usage` (ساعتی، با cache_hits)، `GET /usage`،
   `analytics/live` (دقیقه‌ای) و رخدادهای امنیتی (`waf` و `firewall`) در `GET /sites/{d}/events`.
10. گزارش SLA (`/sla`)، تحلیل سایت و پلتفرم (`/analytics`)، `overview` و `status.json` داده دارند.
11. تعلیق ← هر نود 503 با صفحهٔ `suspended.html` می‌دهد، مسیر تونل 503 بی‌بدنه، و هیچ درخواستی به اصل نمی‌رسد.
12. رفع تعلیق ← سایت و تونل دوباره کار می‌کنند.

`test_l4.py` (پیش‌فرض فعال؛ `STAGING_L4=0` برای رد کردن): برنامهٔ TCP روی پلن `l4_proxy`، پورت از بازهٔ
۲۰۰۰۰–۲۹۹۹۹ توسط کنترلر تخصیص می‌یابد، داده از `<edge>:<port>` به اکوی TCP اصل می‌رسد و برمی‌گردد، و
`l4-echo.<domain>` به نودها resolve می‌شود.

`test_storage.py` فقط با `STAGING_STORAGE=1`: ساخت باکت با API ادمین، آپلود با کلید خود باکت (boto3)،
رکورد پروکسی با `storage` و دریافت شیء از هر نود؛ و این‌که باکت بدون توکن نود عمومی نیست.

سایت‌های آزمون نام یکتا دارند (`shop-<run>.staging.test`) و در پایان حذف می‌شوند؛ با `STAGING_KEEP=1`
برای بررسی دستی نگه داشته می‌شوند.

## اجرای آزمون‌ها از روی میزبان

آدرس‌ها از متغیر محیطی خوانده می‌شوند (پیش‌فرض‌ها همان compose هستند). روی لینوکس IPهای bridge از
میزبان قابل دسترس‌اند، پس می‌توان بدون runner اجرا کرد (نیاز: `pytest` و `dig`):

```bash
STAGING_CONTROLLER_URL=http://11.200.0.10:8000 \
  python3 -m pytest -c tests/integration/pytest.ini tests/integration
```

| متغیر | پیش‌فرض |
|---|---|
| `STAGING_CONTROLLER_URL` | `http://controller:8000` |
| `STAGING_ADMIN_API_KEY` | `staging-admin-key` |
| `STAGING_EDGES` | `edge-1=11.200.0.21,edge-2=11.200.0.22` |
| `STAGING_DNS` | `11.200.0.53` |
| `STAGING_ORIGIN_IP` | `11.200.0.80` |
| `STAGING_TIMEOUT` | `90` (ثانیه برای هر انتظار) |

روی Docker Desktop (macOS/Windows) شبکهٔ bridge از میزبان در دسترس نیست؛ از `staging.sh test` استفاده کنید.
همین متغیرها اجازه می‌دهند آزمون‌ها روی پشته‌ای که دستی (بدون Docker) بالا آمده هم اجرا شوند.

## پروفایل‌های اختیاری: Storage و L4

```bash
STAGING_STORAGE=1 deploy/staging/staging.sh up
STAGING_STORAGE=1 deploy/staging/staging.sh test
STAGING_STORAGE=1 deploy/staging/staging.sh down
```

با `STAGING_STORAGE=1` اسکریپت پروفایل `storage` را فعال می‌کند (MinIO + `minio-init` که کاربر کنترلر را با
`deploy/storage/pcdn-controller-policy.json` می‌سازد — همان کاری که `deploy/storage/bootstrap.sh` روی سرور
واقعی انجام می‌دهد) و `STORAGE_ENDPOINT=http://minio:9000` را با `STORAGE_INSECURE_HTTP=true` به کنترلر
می‌دهد. L4 پروفایل جدایی ندارد چون nginx نود ماژول stream را دارد.

## CI

job `integration` در `.github/workflows/ci.yml` (ubuntu-24.04، سقف ۲۰ دقیقه، زمان معمول کمتر از ۱۵ دقیقه):
`staging.sh config` ← `staging.sh up` (build و `--wait`) ← `staging.sh test` ← در صورت شکست لاگ‌ها چاپ و به‌عنوان
artifact (`staging-logs`) بارگذاری می‌شوند ← در هر حال `staging.sh down`. پروفایل storage در CI اجرا نمی‌شود.

## دروازهٔ انتشار (staging gate)

پیش از هر انتشار سکو، head همان PR انتشار روی staging با `tools/release/staging-verify.sh` سنجیده می‌شود
(SPEC §23.1، [RELEASE §۴](RELEASE.md#۴-دروازهٔ-staging-staging-verifysh)): نسخهٔ کنترلر و نودها، preflight
سخت‌گیر، مهاجرت‌ها در head، همین `staging.sh test`، آزمون بار با آستانه، پشتیبان + آزمون بازیابی کامل،
پیش‌نمایش rollout و بازبینی امنیتی. شواهد در `release-evidence/vX.Y.Z/` (`report.md`، `report.json`، `raw/`).

- کنترلر این پشته `PCDN_ENVIRONMENT=staging` و `PCDN_VERSION` (از فایل `VERSION`، با `staging.sh` صادر
  می‌شود) دارد؛ دروازه هر کنترلری را که `production` گزارش کند یا در `PCDN_PROD_CONTROLLERS` باشد **رد**
  می‌کند (کد ۲، بدون گزینهٔ دور زدن).
- تنظیمات دروازه در `deploy/staging/staging-gate.env` (از روی `staging-gate.env.example`، git-ignored،
  `chmod 600`): `PCDN_CONTROLLER_URL`، `PCDN_ADMIN_KEY`، `STAGING_EDGE_TARGET`، `STAGING_LOADTEST_HOST`،
  `STAGING_NS`، `PCDN_PROD_CONTROLLERS`.
- این پشتهٔ Docker پشتیبان‌گیری را خاموش دارد و پورت منتشر نمی‌کند؛ برای دروازهٔ کامل از یک staging شبیه
  تولید (کنترلر با `BACKUP_ENABLED`، `BACKUP_VERIFY_DATABASE_URL` و نودهای واقعی) استفاده کنید، یا گام‌های
  نامربوط را با `--skip-backup` / `--skip-loadtest` رد کنید (نتیجه PARTIAL، کد ۳).

نمونه روی همین پشته (از ماشینی که به شبکهٔ پشته دسترسی دارد):

```bash
tools/release/staging-verify.sh --env-file deploy/staging/staging-gate.env \
    --controller http://11.200.0.10:8000 --ns 11.200.0.53 --skip-loadtest --skip-backup
```

## عیب‌یابی

| نشانه | بررسی |
|---|---|
| `up` روی نود منتظر می‌ماند | `staging.sh compose logs -f edge-1` — خطای `apt-get update` (دسترسی اینترنت) یا دانلود بسته از کنترلر |
| runner healthy نمی‌شود | `staging.sh compose logs runner` — کنترلر بالا نیامده یا `ADMIN_API_KEY` اشتباه است |
| DNS خالی است | نودها آنلاین نیستند: `staging.sh logs` و بخش «controller: GET /api/v1/edges» |
| تغییر کانفیگ دیر اعمال می‌شود | `staging.sh compose exec edge-1 cat /var/lib/pcdn/state.json` (`pending_version`، `last_error`) |
| تداخل زیرشبکه | `STAGING_NET=11.201.0 deploy/staging/staging.sh up` |

## محدودیت‌ها و تفاوت با محیط واقعی

- فقط یک PowerDNS (ns1)؛ `ns2.staging.test` فقط در رکورد NS آمده است. GeoDNS خاموش است.
- کنترلر بدون Caddy/TLS و روی HTTP داخلی؛ SSL سایت‌ها (ACME) آزمون نمی‌شود.
- تنظیمات کرنل، nftables، sandbox سرویس‌های systemd و توابع لبه در کانتینر آزموده نمی‌شوند (پوشش
  آن‌ها با آزمون‌های واحد `edge/tests` است).
- نصب نود به `apt-get update` (اینترنت) وابسته است.
