# بازیابی از فاجعه (Disaster Recovery) — CDN پاسارگاد

این سند runbookهای عملی برای بازگرداندن سامانه پس از از دست رفتن یک جزء است: دیتابیس، کنترلر، نود،
کلیدهای رمزنگاری یا نیم‌سرور. هر runbook پیش‌نیازها، ترتیب گام‌ها و دستور دقیق را دارد. برای مفاهیم
پس‌زمینه (پشتیبان‌گیری، HA، رمزنگاری) به [`docs/OPERATIONS.md`](OPERATIONS.md) و برای تصویر کلی به
[`docs/ARCHITECTURE.md`](ARCHITECTURE.md) مراجعه کنید.

> در این سند، `manage` یعنی دستور زیر از پوشهٔ نصب (مثلاً `/opt/pcdn`):
> ```bash
> docker compose exec controller python -m app.manage <دستور>
> ```
> برای کارهایی که کنترلر باید **خاموش** باشد (بازیابی، بازیابی PowerDNS) از کانتینر یک‌بارمصرف `tools`
> استفاده می‌شود که volume مربوط به PowerDNS را با دسترسی نوشتن mount می‌کند. `--no-deps` مانع روشن‌شدن
> خودکار سرویس‌های دیگر می‌شود، پس `db` باید از قبل روشن باشد:
> ```bash
> docker compose --profile tools run --rm --no-deps tools python -m app.manage <دستور>
> ```

## فهرست

- [پیش‌نیازهای حیاتی (قبل از هر فاجعه)](#پیشنیازهای-حیاتی-قبل-از-هر-فاجعه)
- [۱. بازگردانی PostgreSQL از پشتیبان رمزنگاری‌شده](#۱-بازگردانی-postgresql-از-پشتیبان-رمزنگاریشده)
- [۲. از دست رفتن کنترلر (failover یا بازسازی)](#۲-از-دست-رفتن-کنترلر-failover-یا-بازسازی)
- [۳. از دست رفتن / تعویض یک نود Edge](#۳-از-دست-رفتن--تعویض-یک-نود-edge)
- [۴. از دست رفتن یا چرخش DATA_ENCRYPTION_KEY](#۴-از-دست-رفتن-یا-چرخش-data_encryption_key)
- [۵. از دست رفتن یا چرخش PDNS_API_KEY](#۵-از-دست-رفتن-یا-چرخش-pdns_api_key)
- [۶. خرابی DNS / نیم‌سرور](#۶-خرابی-dns--نیمسرور)
- [۷. تأیید اینکه پشتیبان‌ها واقعاً قابل‌بازیابی‌اند](#۷-تأیید-اینکه-پشتیبانها-واقعاً-قابلبازیاناند)
- [مرجع دستورهای manage](#مرجع-دستورهای-manage)

---

## پیش‌نیازهای حیاتی (قبل از هر فاجعه)

بازیابی فقط وقتی ممکن است که این‌ها **بیرون از سرور** نگه‌داری شوند. بدون آن‌ها، پشتیبان رمزنگاری‌شده
بی‌فایده است:

1. **`DATA_ENCRYPTION_KEY`** — کلید Fernet که کلید خصوصی گواهی‌ها و secret سایت‌ها را در دیتابیس
   رمزنگاری می‌کند. بدون آن، همین داده‌ها در پشتیبان هم قابل‌خواندن نیستند.
2. **`BACKUP_PASSPHRASE`** — رمز فایل پشتیبان (AES-256-GCM). بدون آن، آرشیو رمزنگاری‌شده باز نمی‌شود.
3. یک کپی از `.env` (یا دست‌کم مقادیر `ADMIN_API_KEY`، `PDNS_API_KEY`، `POSTGRES_PASSWORD`،
   `DATA_ENCRYPTION_KEY`، `BACKUP_PASSPHRASE`).

این‌ها را در یک مدیر رمز/خزانهٔ جدا از سرور نگه دارید. پشتیبان‌ها هم بهتر است off-box باشند
(`BACKUP_S3_*`؛ مثلاً Object Storage آروان). وضعیت فعلی را همیشه با `manage backups` و
`manage health` بسنجید.

## ۱. بازگردانی PostgreSQL از پشتیبان رمزنگاری‌شده

هر آرشیو (`pcdn-backup-YYYYmmddTHHMMSSZ.tar.gz[.enc]`) شامل dump دیتابیس کنترلر
(`pg_dump -Fc`)، کپی سازگار دیتابیس PowerDNS (زون‌ها + کلید DNSSEC) و acme.sh home است
(`controller/app/backup.py`).

**پیش‌نیاز:** `BACKUP_PASSPHRASE` (اگر پشتیبان رمزنگاری‌شده است) و همان `DATA_ENCRYPTION_KEY`ای که
داده‌ها با آن رمزنگاری شده‌اند، در `.env` باشند.

**ترتیب گام‌ها:**

1. پشتیبان‌های موجود (محلی و ابری) را ببینید:
   ```bash
   docker compose exec controller python -m app.manage backups
   ```
2. **کنترلرها را خاموش کنید** تا هیچ‌کس حین بازگردانی روی دیتابیس ننویسد (ولی `db` روشن بماند):
   ```bash
   docker compose stop controller caddy
   ```
3. بازگردانی را با کانتینر `tools` اجرا کنید (فقط دیتابیس کنترلر):
   ```bash
   docker compose --profile tools run --rm --no-deps tools \
       python -m app.manage restore pcdn-backup-YYYYmmddTHHMMSSZ.tar.gz.enc --yes
   ```
   - اگر آرشیو در فضای ابری است: به‌جای نام فایل از `s3:<key>` استفاده کنید (مثلاً
     `s3:pcdn-backups/pcdn-backup-....tar.gz.enc`)؛ ابتدا دانلود می‌شود.
   - اگر رمز را در `.env` نگذاشته‌اید: `--passphrase -` تا تعاملی پرسیده شود.
   - `restore` پس از بازگردانی دیتابیس، خودکار migrationها را تا `head` اجرا می‌کند.
4. اگر لازم است **زون‌های PowerDNS** هم از همین پشتیبان بازگردند (مثلاً دیتابیس PowerDNS هم از دست
   رفته)، PowerDNS را خاموش و با `--pdns` بازگردانید (بخش ۶ را ببینید).
5. کنترلرها را روشن کنید و DNS را دوباره sync کنید:
   ```bash
   docker compose up -d
   docker compose exec controller python -m app.manage dns-sync
   ```
6. سلامت را بسنجید:
   ```bash
   docker compose exec controller python -m app.manage health
   ```

> نکته: اگر فقط می‌خواهید محتوای یک پشتیبان را بدون بازنویسی چیزی ببینید، از `--extract DIR` و
> `--no-controller` استفاده کنید.

## ۲. از دست رفتن کنترلر (failover یا بازسازی)

### الف) اگر معماری دوسروره (HA) دارید

کنترلر بدون وضعیت است و حالت در PostgreSQL می‌نشیند. اگر سرور **B** (پشتیبان) بیفتد، سرور A بدون
تغییر کار می‌کند (فقط هشدار «PowerDNS در دسترس نیست» برای ns2 می‌آید). اگر سرور **A** (primary)
بیفتد، failover **دستی** است (حدود ۵ دقیقه): دیتابیس B را promote کنید و `cdn-api` را به B منتقل
کنید؛ در این مدت نودها و DNS کار می‌کنند ولی API در دسترس نیست. مراحل دقیق promote و بازگرداندن A
به‌عنوان standby جدید در [`docs/OPERATIONS.md`](OPERATIONS.md) بخش HA آمده است. promote خودکار عمداً
پیاده نشده (خطر split-brain با دو سرور).

### ب) بازسازی کامل روی یک سرور تازه

1. Docker و compose را نصب کنید، مخزن را clone کنید، و `.env` را از کپی امن بازگردانید (همان
   `ADMIN_API_KEY`، `DATA_ENCRYPTION_KEY`، `PDNS_API_KEY`، `POSTGRES_PASSWORD`).
2. سرویس‌ها را بالا بیاورید تا دیتابیس خالی ساخته شود:
   ```bash
   docker compose up -d db pdns
   ```
3. آخرین پشتیبان را بازگردانید (بخش ۱؛ معمولاً هم دیتابیس کنترلر و هم `--pdns` و `--acme`):
   ```bash
   docker compose --profile tools run --rm --no-deps tools \
       python -m app.manage restore s3:pcdn-backups/pcdn-backup-....tar.gz.enc --yes --pdns --acme
   ```
4. کل استک را بالا بیاورید و DNS را دوباره بنویسید:
   ```bash
   docker compose up -d
   docker compose exec controller python -m app.manage dns-sync
   docker compose exec controller python -m app.manage health
   ```
5. در WHMCS مطمئن شوید «Server Hostname» (= `CONTROLLER_DOMAIN`) و «Access Hash» (= `ADMIN_API_KEY`)
   درست‌اند. نودها خودکار دوباره به کنترلر وصل و کانفیگ را pull می‌کنند (توکنشان تغییر نکرده).

## ۳. از دست رفتن / تعویض یک نود Edge

نودها بدون وضعیتِ یکتا هستند؛ کل کانفیگ از کنترلر می‌آید. برای یک نودِ از کار افتاده:

1. **اختیاری — خروج موقت از DNS:** نود را در پنل غیرفعال کنید یا با
   `PATCH /api/v1/edges/{id}?enabled=false`؛ به‌هرحال اگر نود واقعاً از دسترس خارج شده باشد،
   PowerDNS با health check خودش ظرف چند ثانیه آن را از پاسخ‌ها حذف می‌کند و پروب سلامت کنترلر هم
   پس از `PROBE_FAIL_CHECKS` شکست آن را کنار می‌گذارد.
2. **نصب روی ماشین جایگزین با یک دستور** (SPEC §11.1). اگر همان توکن قبلی را دارید، می‌توانید دوباره
   از آن استفاده کنید؛ وگرنه در پنل یک نود جدید بسازید و توکن یک‌بارمصرفش را بردارید:
   ```bash
   curl -fsSL https://<controller>/edge/bootstrap.sh | sudo bash -s -- \
       --controller https://<controller> --token edge_xxxxx --region home --role general
   ```
   نودِ تازه در نخستین heartbeat خودش `region`/`group` و IP عمومی‌اش را گزارش می‌کند و خودکار در
   استخر درست ثبت می‌شود و کانفیگ را pull می‌کند.
3. **از رده خارج کردن نود قدیمی:** آن را در پنل غیرفعال و سپس حذف کنید
   (`DELETE /api/v1/edges/{id}`). جزئیات نصب، به‌روزرسانی و decommission در
   [`docs/NODES.md`](NODES.md).

> اگر نود چند آدرس داشت (SPEC §12)، failover آدرس‌ها خودکار و مبتنی بر سلامت است؛ نیازی به دخالت
> نیست و قاعدهٔ fail-open استخر را خالی نمی‌گذارد.

## ۴. از دست رفتن یا چرخش DATA_ENCRYPTION_KEY

### چرخش عادی (بدون قطعی)

کلید جدید را **اول** و کلید قدیمی را بعد از کاما بگذارید، سپس:

```bash
# 1) تولید کلید جدید
docker compose exec controller python -m app.manage gen-key
# 2) در .env:  DATA_ENCRYPTION_KEY=<new>,<old>   سپس:
docker compose up -d
# 3) همه‌چیز را با کلید جدید دوباره رمزنگاری کن
docker compose exec controller python -m app.manage rotate-key
# 4) در .env:  DATA_ENCRYPTION_KEY=<new>   و دوباره:
docker compose up -d
```

هر دو سرور HA باید همیشه همان مقدار را داشته باشند. وضعیت رمزنگاری را با
`manage encryption-status` و `manage health` ببینید.

### اگر کلید کاملاً از دست رفته باشد

اگر هیچ کپی از `DATA_ENCRYPTION_KEY` ندارید، کلید خصوصی گواهی‌ها و secretها **غیرقابل‌بازیابی**اند
(همین‌طور در پشتیبان‌ها). آخرین‌راه، فراموش‌کردن داده‌های غیرقابل‌رمزگشایی است تا سامانه دوباره کار کند:

```bash
docker compose exec controller python -m app.manage drop-unreadable-secrets --yes
```

این دستور گواهی‌های Let's Encrypt را برای صدور دوباره صف می‌کند، گواهی‌های سفارشی مشتری را حذف می‌کند
(مشتری باید دوباره آپلود کند) و secret چالش‌ها را از نو می‌سازد. پس از آن، `job_ssl` گواهی‌ها را
دوباره صادر می‌کند.

## ۵. از دست رفتن یا چرخش PDNS_API_KEY

`PDNS_API_KEY` کلید مشترک کنترلر و همهٔ نیم‌سرورهای PowerDNS است. برای چرخش:

1. کلید جدید بسازید: `openssl rand -hex 24`.
2. آن را روی **هر** نیم‌سرور ست کنید (در docker-compose از `PDNS_AUTH_API_KEY: ${PDNS_API_KEY}` خوانده
   می‌شود) و PowerDNS را روی هر سرور ری‌استارت کنید.
3. همان مقدار را در `.env` کنترلر (`PDNS_API_KEY`) بگذارید و کنترلر را ری‌استارت کنید.
4. زون‌ها را دوباره بنویسید و بسنجید:
   ```bash
   docker compose exec controller python -m app.manage dns-sync
   docker compose exec controller python -m app.manage health
   ```

کلید PowerDNS در دیتابیس کنترلر ذخیره نمی‌شود و در پشتیبان نیست؛ فقط در `.env` زندگی می‌کند، پس
«از دست رفتن» آن یعنی فقط باید یک مقدار جدید ست و همگام کنید (داده‌ای از بین نمی‌رود).

## ۶. خرابی DNS / نیم‌سرور

- **یک نیم‌سرور از کار افتاده (مثلاً ns2):** resolverها از نیم‌سرور دیگر جواب می‌گیرند؛ سرویس ادامه
  دارد. هشدار «PowerDNS در دسترس نیست» می‌آید. سرور ns2 را با `deploy/ns2-compose.yml` دوباره بالا
  بیاورید و مطمئن شوید پورت `8081` آن فقط به IP کنترلر باز است (`sudo ./deploy/ns2-firewall.sh <controller-ip>`).
- **زون‌های یک نیم‌سرور گم/خراب شده‌اند:** کافی است کنترلر دوباره همه را بنویسد:
  ```bash
  docker compose exec controller python -m app.manage dns-sync
  ```
  (نیازی به zone transfer نیست؛ کنترلر هر زون را روی همهٔ آدرس‌های `PDNS_API_URL` می‌نویسد.)
- **دیتابیس PowerDNS از دست رفته (زون‌ها + کلید DNSSEC):** از آخرین پشتیبان بازگردانید. PowerDNS باید
  خاموش باشد، چون فایل sqlite جایگزین می‌شود:
  ```bash
  docker compose stop pdns
  docker compose --profile tools run --rm --no-deps tools \
      python -m app.manage restore s3:pcdn-backups/pcdn-backup-....tar.gz.enc --yes --no-controller --pdns
  docker compose up -d pdns
  docker compose exec controller python -m app.manage dns-sync
  ```
  > بازگردانی DNSSEC از پشتیبان، کلیدهای امضای زون را هم برمی‌گرداند، پس زنجیرهٔ اعتماد نزد والد
  > (`.ir` و ...) نمی‌شکند. اگر پشتیبان کلید DNSSEC نداشت، باید DNSSEC را دوباره راه بیندازید و رکورد
  > DS را نزد ثبت‌کنندهٔ دامنه به‌روز کنید.
- **درستی GeoDNS:** پس از هر تغییر، با `manage geo-check` بسنجید که هر نیم‌سرور بازدیدکنندهٔ داخل و
  خارج را درست مسیردهی می‌کند.

## ۷. تأیید اینکه پشتیبان‌ها واقعاً قابل‌بازیابی‌اند

یک پشتیبانِ نیازموده، پشتیبان نیست. دو راه:

1. **خودکار (SPEC §13.3) — `manage backup-verify`:** آخرین پشتیبان را در یک دیتابیس یک‌بارمصرف
   بازمی‌گرداند و schema/head و سلامت ردیف‌ها را بررسی می‌کند، تا بدانید پشتیبان قابل‌بازگردانی است.
   (این دستور در موج ۵ طبق SPEC §13.3 در حال افزوده‌شدن است.)
   ```bash
   docker compose exec controller python -m app.manage backup-verify
   ```
2. **دستی (همیشه در دسترس):** آرشیو را روی یک محیط آزمایشی جدا و با `--extract` باز کنید، یا در یک
   استک آزمایشی مجزا `restore` را اجرا کنید؛ سپس `manage health` را ببینید. هرگز این تمرین را روی
   استک تولیدِ در حال کار انجام ندهید.

علاوه بر این، `/healthz/deep` (و `manage health`) سن آخرین پشتیبان موفق را گزارش می‌دهد و اگر در
۲۶ ساعت گذشته پشتیبان موفقی نبوده هشدار می‌دهد؛ `job_backup` هم شکست پشتیبان‌گیری را با هشدار
«پشتیبان‌گیری ناموفق بود» اعلام می‌کند.

## مرجع دستورهای manage

| دستور | کار |
|---|---|
| `backup [--no-upload]` | ساخت فوری یک پشتیبان (در `BACKUP_DIR` و در صورت تنظیم، ابری) |
| `backups` | فهرست پشتیبان‌های محلی و ابری |
| `restore <file\|s3:KEY> --yes [--passphrase P] [--no-controller] [--pdns [PATH]] [--acme [PATH]] [--extract DIR]` | بازگردانی اجزای یک پشتیبان |
| `backup-verify` | بازگردانی آزمایشی آخرین پشتیبان و بررسی سلامت (SPEC §13.3؛ در حال افزوده‌شدن) |
| `migrate [--revision head]` | اجرای migrationهای دیتابیس |
| `current` / `heads` / `history` | وضعیت migrationها |
| `gen-key` | تولید یک `DATA_ENCRYPTION_KEY` تازه |
| `encryption-status` | شمارش secretهای plaintext/رمزنگاری‌شده و خوانایی با کلید فعلی |
| `encrypt-secrets` | رمزنگاری secretهای plaintext با کلید فعلی |
| `rotate-key` | رمزنگاری دوبارهٔ همه‌چیز با کلید اول `DATA_ENCRYPTION_KEY` |
| `drop-unreadable-secrets --yes` | (آخرین‌راه پس از از دست رفتن کلید) فراموش‌کردن دادهٔ غیرقابل‌رمزگشایی |
| `dns-sync` | بازنویسی همهٔ زون‌ها روی همهٔ نیم‌سرورها |
| `geo-check` | پرسش از هر نیم‌سرور که بازدیدکنندهٔ داخل/خارج چه نودی می‌گیرد |
| `health` | چاپ `/healthz/deep` برای این پروسه |
| `alerts-test` | ارسال پیام آزمایشی روی همهٔ کانال‌های هشدار |

راهنمای کامل عملیات روزمره در [`docs/OPERATIONS.md`](OPERATIONS.md).
