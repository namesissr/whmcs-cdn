# راهنمای عملیات (Operations) — CDN پاسارگاد

این سند برای مدیر فنی سرور مرکزی (Control plane) نوشته شده است و پنج موضوع را پوشش می‌دهد:
مهاجرت دیتابیس، هشدارها، پشتیبان‌گیری و بازیابی، دسترس‌پذیری بالا (HA) و رمزنگاری کلیدهای خصوصی.
همه دستورها از پوشه نصب (مثلاً `/opt/pcdn`) اجرا می‌شوند.

## فهرست

- [خلاصه متغیرهای جدید](#خلاصه-متغیرهای-جدید)
- [۱. مهاجرت دیتابیس (Alembic)](#۱-مهاجرت-دیتابیس-alembic)
- [۲. هشدار تلگرام و ایمیل](#۲-هشدار-تلگرام-و-ایمیل)
- [۳. پشتیبان‌گیری خودکار](#۳-پشتیبانگیری-خودکار)
- [۴. بازیابی از پشتیبان (Disaster Recovery)](#۴-بازیابی-از-پشتیبان-disaster-recovery)
- [۵. دسترس‌پذیری بالا (HA) برای سرور مرکزی](#۵-دسترسپذیری-بالا-ha-برای-سرور-مرکزی)
- [۶. رمزنگاری کلیدهای خصوصی و مدیریت کلید](#۶-رمزنگاری-کلیدهای-خصوصی-و-مدیریت-کلید)
- [۷. مانیتورینگ با /healthz/deep](#۷-مانیتورینگ-با-healthzdeep)
- [۸. پایش سلامت نودها، صفحه وضعیت عمومی و رخدادها](#۸-پایش-سلامت-نودها-صفحه-وضعیت-عمومی-و-رخدادها-spec-8)
- [مرجع دستورهای مدیریتی](#مرجع-دستورهای-مدیریتی)

> در این سند، `manage` یعنی:
> ```bash
> docker compose exec controller python -m app.manage <دستور>
> ```
> برای کارهایی که کنترلر باید خاموش باشد (مثل بازیابی) از کانتینر یک‌بارمصرف `tools` استفاده می‌شود. این کانتینر
> volume مربوط به PowerDNS را با دسترسی نوشتن mount می‌کند. `--no-deps` باعث می‌شود سرویس‌های دیگر (مثلاً PowerDNS
> متوقف‌شده) خودکار روشن نشوند، پس سرویس `db` باید از قبل روشن باشد:
> ```bash
> docker compose --profile tools run --rm --no-deps tools python -m app.manage <دستور>
> ```

---

## خلاصه متغیرهای جدید

همه این متغیرها با توضیح در `.env.example` آمده‌اند.

| متغیر | پیش‌فرض | کاربرد |
|---|---|---|
| `DATA_ENCRYPTION_KEY` | خالی | کلید Fernet برای رمزنگاری کلید خصوصی گواهی‌ها و secret سایت‌ها. چند کلید با کاما (اولی = کلید فعلی) |
| `TELEGRAM_BOT_TOKEN`، `TELEGRAM_CHAT_IDS` | خالی | هشدار تلگرام |
| `TELEGRAM_API_URL` | `https://api.telegram.org` | آدرس رله/پروکسی API تلگرام (برای ایران) |
| `HTTPS_PROXY` | خالی | پروکسی خروجی (برای تلگرام و S3) |
| `SMTP_HOST`، `SMTP_PORT`، `SMTP_USER`، `SMTP_PASSWORD`، `SMTP_FROM`، `SMTP_SECURITY`، `ALERT_EMAILS` | — | هشدار ایمیلی. `SMTP_SECURITY` یکی از `starttls`، `ssl` یا `none` |
| `ALERT_REMINDER_HOURS` | `6` | تکرار هشدارِ حل‌نشده هر چند ساعت (۰ = بدون تکرار) |
| `ALERT_CERT_DAYS` | `7` | هشدار برای گواهی Let's Encrypt که تا این تعداد روز منقضی می‌شود |
| `BACKUP_ENABLED` | `false` (در `.env.example` روشن است) | پشتیبان‌گیری روزانه |
| `BACKUP_HOUR` | `2` | ساعت پشتیبان‌گیری به UTC (۲ = ۵:۳۰ تهران) |
| `BACKUP_KEEP` | `14` | تعداد نسخه‌های نگه‌داشته‌شده |
| `BACKUP_DIR` | `/data/backups` | محل نسخه‌های محلی (داخل volume `controller-data`) |
| `BACKUP_PASSPHRASE` | خالی | رمز فایل پشتیبان (AES-256) |
| `BACKUP_S3_ENDPOINT`، `BACKUP_S3_BUCKET`، `BACKUP_S3_ACCESS_KEY`، `BACKUP_S3_SECRET_KEY`، `BACKUP_S3_REGION`، `BACKUP_S3_PREFIX`، `BACKUP_S3_KEEP` | — | ارسال به فضای ابری سازگار با S3 (مثل Object Storage آروان) |
| `INSTANCE_NAME` | نام کانتینر | نام این نمونه کنترلر در `/healthz/deep` و پیام‌ها |
| `PROBE_ENABLED` | `true` | آزمون سلامت مصنوعی هر ۶۰ ثانیه از هر نود فعال (SPEC §8.1) |
| `PROBE_TIMEOUT` | `5` | مهلت هر آزمون سلامت (ثانیه) |
| `PROBE_IPV6` | `true` | آزمون آدرس IPv6 نود هم (سالم اگر هرکدام پاسخ دهند) |
| `PROBE_FAIL_CHECKS` | `3` | شکست پیاپی لازم برای هشدار «گزارش می‌دهد ولی سالم نیست» |

---

## ۱. مهاجرت دیتابیس (Alembic)

ساختار دیتابیس کنترلر با [Alembic](https://alembic.sqlalchemy.org) نسخه‌بندی می‌شود. فایل‌های مهاجرت در
`controller/migrations/versions/` هستند:

| نسخه | توضیح |
|---|---|
| `0001` | خط پایه: دقیقاً همان ساختاری که نسخه‌های قبلی با `create_all` می‌ساختند |
| `0002` | ستون `sites.secret` از `VARCHAR(64)` به `TEXT` تا مقدار رمزنگاری‌شده در آن جا شود |

### هنگام راه‌اندازی چه اتفاقی می‌افتد؟

کنترلر در هر بار شروع، خودش `upgrade head` را اجرا می‌کند:

- **دیتابیس خالی:** همه مهاجرت‌ها اجرا می‌شوند.
- **دیتابیس نصب‌های قدیمی** (جدول‌ها هستند ولی جدول `alembic_version` نیست): ابتدا نسخه `0001` روی آن
  «مُهر» (stamp) می‌شود و سپس مهاجرت‌های بعدی اجرا می‌شوند. هیچ داده‌ای پاک نمی‌شود. در لاگ این خط را می‌بینید:
  `database was created without migrations: stamping baseline 0001`
- **چند کنترلر هم‌زمان** (HA): مهاجرت زیر قفل `pg_advisory_lock` اجرا می‌شود؛ یکی مهاجرت می‌کند و بقیه صبر
  می‌کنند و بعد دیتابیس را به‌روز می‌بینند.

> پیش از به‌روزرسانی نسخه کنترلر یک پشتیبان بگیرید: `manage backup`.

### دستورها

```bash
manage current            # نسخه فعلی دیتابیس و آخرین نسخه موجود
manage migrate            # اجرای مهاجرت‌ها (همان کاری که هنگام شروع انجام می‌شود)
manage history            # فهرست مهاجرت‌ها
manage stamp 0001         # فقط علامت‌گذاری نسخه، بدون اجرای SQL (برای موارد خاص)
manage downgrade 0001 --yes   # برگرداندن (ممکن است داده حذف شود؛ اول پشتیبان بگیرید)
```

دستور استاندارد `alembic` هم از داخل پوشه `controller/` کار می‌کند و آدرس دیتابیس را از `DATABASE_URL` می‌خواند
(مثلاً `alembic current`).

### افزودن مهاجرت جدید (برای توسعه‌دهنده)

1. مدل را در `controller/app/models.py` تغییر دهید.
2. یک دیتابیس توسعه را به آخرین نسخه ببرید و مهاجرت را خودکار بسازید:
   ```bash
   cd controller
   export DATABASE_URL=sqlite:///./dev.db
   python -m app.manage migrate
   python -m app.manage makemigration -m "add foo to sites" --rev-id 0003
   ```
3. فایل ساخته‌شده در `migrations/versions/0003_add_foo_to_sites.py` را **بازبینی کنید**:
   - برای SQLite عملیات داخل `batch_alter_table` نوشته می‌شوند (جدول دوباره ساخته می‌شود). این رفتار درست است.
   - تغییر نوع ستون، ایندکس‌ها و مقدار پیش‌فرض سمت سرور را بررسی کنید.
   - اگر داده باید تبدیل شود، آن را با `op.execute(...)` یا `op.get_bind()` در همان فایل بنویسید.
4. تست‌ها را اجرا کنید. `tests/test_migrations.py` بررسی می‌کند که پس از اجرای همه مهاجرت‌ها، ساختار دیتابیس
   (هم SQLite و هم PostgreSQL) **دقیقاً** با مدل‌ها یکی باشد:
   ```bash
   python -m pytest -q tests/test_migrations.py
   # با PostgreSQL واقعی:
   PCDN_TEST_PG_URL=postgresql+psycopg://user:pass@127.0.0.1:5432/postgres python -m pytest -q
   ```
5. قواعد:
   - مهاجرتی را که منتشر شده ویرایش نکنید؛ مهاجرت جدید بسازید.
   - در راه‌اندازی دوسروره، کنترلرها یکی‌یکی به‌روز می‌شوند و برای مدتی نسخه قدیم و جدید با یک دیتابیس کار می‌کنند.
     پس تغییرها را «افزایشی» نگه دارید: ستون جدید nullable یا با پیش‌فرض باشد، و حذف یا تغییر نام ستون را به
     نسخه بعدی موکول کنید (expand/contract).
   - تاریخچه باید یک head داشته باشد (تست `test_single_head`).

---

## ۲. هشدار تلگرام و ایمیل

کنترلر در این رخدادها به مدیر پیام می‌دهد (متن فارسی، موضوع با پیشوند `[Pasargad CDN]`):

| رخداد | شدت | پیام «رفع شد» |
|---|---|---|
| نود از دسترس خارج شد (بیش از `EDGE_ALERT_SECONDS` گزارش نداده؛ تا `EDGE_OFFLINE_SECONDS` هنوز در DNS می‌ماند) | هشدار | «نود دوباره آنلاین شد» همراه با مدت قطعی |
| هیچ نود فعالی آنلاین نیست (رکوردهای پروکسی مستقیم به سرور اصلی مشتری‌ها اشاره می‌کنند) | بحرانی | ✔ |
| بار پردازنده نود بالا مانده، یا دیسک/حافظه نود پر شده (`EDGE_CPU_ALERT`/`EDGE_DISK_ALERT`/`EDGE_MEM_ALERT`؛ دیسک/حافظه نیازمند نسخه جدید ایجنت) | هشدار (دیسک پر: بحرانی) | ✔ |
| نود نتوانست کانفیگ جدید را اعمال کند (`last_error`، مثلاً `nginx -t failed`) | هشدار | ✔ |
| API یکی از سرورهای PowerDNS پاسخ نمی‌دهد (برای هر سرور جدا) | بحرانی | ✔ |
| همگام‌سازی DNS روی یک سرور PowerDNS ناموفق است (برای هر سرور جدا) | بحرانی | ✔ و زون‌ها خودکار دوباره نوشته می‌شوند |
| صدور یا تمدید گواهی Let's Encrypt ناموفق بود | هشدار | ✔ |
| گواهی خودکار یک دامنه تا `ALERT_CERT_DAYS` روز دیگر منقضی می‌شود و تمدید نشده | هشدار (زیر ۲ روز: بحرانی) | ✔ |
| پشتیبان‌گیری ناموفق بود | بحرانی | «پشتیبان‌گیری دوباره موفق شد» |
| یکی از کارهای زمان‌بندی‌شده کنترلر با خطا متوقف شد | هشدار | ✔ |

**جلوگیری از پیام تکراری:** هر مشکل یک «وضعیت باز» در جدول `state` دیتابیس دارد. پیام فقط یک بار فرستاده
می‌شود. تا وقتی مشکل حل نشده، هر `ALERT_REMINDER_HOURS` ساعت یک یادآوری می‌آید، و پس از رفع مشکل پیام «رفع شد»
ارسال می‌شود. چون این وضعیت در دیتابیس است، با ری‌استارت یا جابه‌جایی رهبر (HA) پیام تکراری ارسال نمی‌شود.
اگر ارسال پیام ناموفق باشد، هر ۵ دقیقه دوباره تلاش می‌شود. ارسال پیام هیچ‌وقت کارهای کنترلر را متوقف نمی‌کند:
حداکثر زمان انتظار برای هر کانال ۱۰ ثانیه است و خطا فقط در لاگ ثبت می‌شود.

> پس از قطعی خود کنترلر (مثلاً ری‌استارت طولانی)، کنترلر به اندازه `EDGE_OFFLINE_SECONDS` صبر می‌کند تا نودها
> دوباره گزارش دهند و بعد درباره آفلاین بودن آن‌ها تصمیم می‌گیرد. در غیر این صورت همه نودها یک‌جا از DNS خارج
> می‌شدند و برای هر کدام هشدار می‌آمد.

**در دسترس‌بودن نودها (Uptime):** کنترلر هر بار اجرای زمان‌بند، وضعیت آنلاین بودن هر نود را ثبت می‌کند و
درصد در دسترس‌بودن ۲۴ ساعت و ۳۰ روز را نگه می‌دارد. این آمار در پنل مدیریت (صفحه «نودها» و گزارش «در
دسترس‌بودن») و در `/healthz/deep` دیده می‌شود. برای گرفتن آمار یک نود از API:
`GET /api/v1/edges/{id}/uptime?days=30`. داده‌ها تا ۴۰۰ روز نگه داشته و بعد پاک می‌شوند.

### ساخت ربات تلگرام

1. در تلگرام با [@BotFather](https://t.me/BotFather) گفتگو کنید، دستور `/newbot` را بفرستید، نام و نام کاربری
   ربات را بدهید. توکنی مثل `123456789:AA...` دریافت می‌کنید. این همان `TELEGRAM_BOT_TOKEN` است و باید محرمانه بماند.
2. **گرفتن chat id:**
   - **پیام خصوصی:** به ربات پیام بدهید (دکمه Start) و سپس:
     ```bash
     curl -s "https://api.telegram.org/bot<TOKEN>/getUpdates" | python3 -m json.tool | grep -A3 '"chat"'
     ```
     عدد `"id"` همان chat id است.
   - **گروه:** ربات را به گروه اضافه کنید و یک پیام در گروه بفرستید. شناسه گروه منفی است، مثلاً `-4012345678`.
   - **کانال:** ربات را مدیر (Admin) کانال کنید. شناسه کانال به شکل `-100...` است.
     روش دیگر: یک پیام کانال را برای [@userinfobot](https://t.me/userinfobot) فوروارد کنید.
3. در `.env`:
   ```
   TELEGRAM_BOT_TOKEN=123456789:AA...
   TELEGRAM_CHAT_IDS=111111111,-1001234567890
   ```

### نکته مهم برای سرورهای داخل ایران

`api.telegram.org` از داخل ایران فیلتر است. یکی از این دو راه را انتخاب کنید:

**الف) رله روی یک سرور خارج از ایران** (پیشنهادی). مثلاً با nginx روی یک VPS خارجی:

```nginx
server {
    listen 443 ssl;
    server_name tg-relay.example.com;
    ssl_certificate     /etc/letsencrypt/live/tg-relay.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/tg-relay.example.com/privkey.pem;

    allow <IP_کنترلر>;   # فقط سرور مرکزی
    deny all;

    location /bot {
        proxy_pass https://api.telegram.org;
        proxy_set_header Host api.telegram.org;
        proxy_ssl_server_name on;
    }
}
```

سپس در `.env` این مقدار را بگذارید: `TELEGRAM_API_URL=https://tg-relay.example.com`.
توکن ربات در مسیر URL است و از رله عبور می‌کند، پس رله باید سرور مورد اعتماد خودتان باشد.
رله‌های عمومی ناشناس را استفاده نکنید.

**ب) پروکسی HTTP:** مقدار `HTTPS_PROXY=http://proxy.example.com:3128` را در `.env` بگذارید. کنترلر همه
درخواست‌های `https://` را از این پروکسی عبور می‌دهد، یعنی تلگرام و آپلود S3. API سرورهای PowerDNS با `http://`
صدا زده می‌شود و از پروکسی عبور نمی‌کند. اگر فضای ابری پشتیبان داخل ایران است، آدرس آن را در `NO_PROXY` بگذارید
تا از پروکسی خارجی عبور نکند، مثلاً `NO_PROXY=s3.ir-thr-at1.arvanstorage.ir,localhost`.

### ایمیل (SMTP)

```
SMTP_HOST=mail.pasargadmizban.com
SMTP_PORT=587
SMTP_SECURITY=starttls        # یا ssl با پورت 465، یا none
SMTP_USER=cdn-alerts@pasargadmizban.com
SMTP_PASSWORD=...
SMTP_FROM=cdn-alerts@pasargadmizban.com
ALERT_EMAILS=noc@pasargadmizban.com,admin@pasargadmizban.com
```

هر دو کانال اختیاری هستند و می‌توانند هم‌زمان فعال باشند.

### آزمایش و وضعیت

```bash
docker compose up -d                  # اعمال تغییرات .env
manage alerts-test                    # ارسال پیام آزمایشی روی همه کانال‌ها
# یا از طریق API:
curl -X POST -H "Authorization: Bearer $KEY" https://cdn-api.pasargadmizban.com/api/v1/alerts/test
curl -H "Authorization: Bearer $KEY" https://cdn-api.pasargadmizban.com/api/v1/alerts/status
```

پاسخ `alerts/test` نتیجه هر کانال را جدا نشان می‌دهد، مثلاً
`{"ok": false, "results": {"telegram": "ok", "email": "SMTPAuthenticationError: ..."}}`.
`alerts/status` کانال‌های تنظیم‌شده و فهرست مشکلات باز را برمی‌گرداند. توکن و رمزها هرگز در پاسخ یا لاگ نمایش
داده نمی‌شوند.

---

## ۳. پشتیبان‌گیری خودکار

هر شب در ساعت `BACKUP_HOUR` (به وقت UTC)، کنترلرِ رهبر یک فایل پشتیبان می‌سازد:
`pcdn-backup-YYYYmmddTHHMMSSZ.tar.gz` (یا `.tar.gz.enc` اگر رمز داشته باشد). محتوای فایل:

| فایل داخل پشتیبان | محتوا |
|---|---|
| `controller.pgdump` | خروجی `pg_dump --format=custom` از دیتابیس کنترلر: سایت‌ها، رکوردها، تنظیمات، گواهی‌ها، نودها و مصرف |
| `controller.sqlite3` | همان محتوا برای نصب‌های SQLite، با API پشتیبان‌گیری آنلاین SQLite |
| `pdns.sqlite3` | دیتابیس PowerDNS ns1: زون‌ها و **کلیدهای DNSSEC**. کپی سازگار با API پشتیبان‌گیری SQLite، از volume `pdns-data` که فقط‌خواندنی در `/pdns-data` کنترلر mount شده است |
| `acme/` | پوشه acme.sh: حساب Let's Encrypt و گواهی‌های صادرشده |
| `manifest.json` | زمان، نسخه مهاجرت دیتابیس و فهرست محتوا |

- اگر کنترلر در ساعت تعیین‌شده خاموش باشد، پشتیبان‌گیری همان روز پس از روشن شدن انجام می‌شود.
- اگر پشتیبان‌گیری ناموفق باشد، هشدار «بحرانی» ارسال می‌شود و هر یک ساعت دوباره تلاش می‌شود. پس از موفقیت،
  پیام «رفع شد» می‌آید.
- فقط `BACKUP_KEEP` نسخه آخر نگه داشته می‌شود. بقیه، هم در سرور و هم در فضای ابری، پاک می‌شوند.
  برای فضای ابری می‌توانید با `BACKUP_S3_KEEP` تعداد دیگری تعیین کنید.
- فایل‌ها با دسترسی `600` در `/data/backups` در volume `controller-data` ذخیره می‌شوند.

### رمزنگاری فایل پشتیبان

با تعیین `BACKUP_PASSPHRASE`، فایل با AES-256-GCM رمز می‌شود. کلید با scrypt و salt تصادفی از رمز ساخته می‌شود
و فایل در قطعه‌های ۱ مگابایتی احراز اصالت می‌شود، پس هر دست‌کاری یا ناقص بودن فایل هنگام بازیابی تشخیص داده
می‌شود. **رمز را بیرون از سرور نگه دارید** (مثلاً در password manager). بدون آن فایل قابل بازیابی نیست.

> فایل پشتیبان شامل کلیدهای خصوصی گواهی‌ها است. حتی اگر `DATA_ENCRYPTION_KEY` فعال باشد، کلیدهای DNSSEC داخل
> `pdns.sqlite3` و حساب ACME رمزنگاری نشده‌اند. پس برای نسخه‌هایی که از سرور خارج می‌شوند، حتماً
> `BACKUP_PASSPHRASE` بگذارید.

### ارسال به فضای ابری (Object Storage آروان یا هر S3 دیگر)

1. در پنل آروان‌کلود، در بخش فضای ابری، یک باکت **خصوصی** بسازید، مثلاً `pcdn-backups`، و یک کلید دسترسی
   (Access/Secret key) بگیرید.
2. در `.env`:
   ```
   BACKUP_S3_ENDPOINT=https://s3.ir-thr-at1.arvanstorage.ir
   BACKUP_S3_REGION=ir-thr-at1
   BACKUP_S3_BUCKET=pcdn-backups
   BACKUP_S3_ACCESS_KEY=...
   BACKUP_S3_SECRET_KEY=...
   BACKUP_S3_PREFIX=pcdn-backups/
   ```
   آدرس endpoint را از پنل همان منطقه بردارید. آدرس‌دهی به شکل path-style است (`endpoint/bucket/key`)
   و امضای درخواست‌ها AWS SigV4 است.
3. برای آزمایش:
   ```bash
   manage backup          # یک پشتیبان همین حالا (خروجی JSON: مسیر، حجم، uploaded)
   manage backups         # فهرست نسخه‌های محلی و ابری
   ```

پیشنهاد: فضای ابری را در دیتاسنتر یا ارائه‌دهنده‌ای جدا از سرور مرکزی انتخاب کنید.

### بررسی سلامت پشتیبان‌ها

- در خروجی `/healthz/deep`، فیلد `backup.last_success_age_hours` نباید از ۲۶ بیشتر باشد.
- هر چند وقت یک بار یک نسخه را روی سرور آزمایشی بازیابی کنید (بخش بعد). پشتیبانی که آزمایش نشده، قابل اتکا نیست.
- برای باز کردن یک نسخه بدون تغییر در هیچ دیتابیسی:
  ```bash
  docker compose --profile tools run --rm --no-deps tools python -m app.manage restore /data/backups/<file> \
      --no-controller --extract /data/restore-check --yes
  ```

---

## ۴. بازیابی از پشتیبان (Disaster Recovery)

`manage restore` بدون `--yes` هیچ کاری انجام نمی‌دهد. گزینه‌ها:

| گزینه | کاربرد |
|---|---|
| `<file>` یا `s3:<key>` | مسیر فایل، یا کلید آن در فضای ابری (مستقیماً دانلود می‌شود) |
| `--passphrase P` | رمز فایل. `-` یعنی رمز از ورودی پرسیده شود. پیش‌فرض: `BACKUP_PASSPHRASE` |
| `--no-controller` | دیتابیس کنترلر بازیابی نشود |
| `--pdns [PATH]` | دیتابیس PowerDNS هم بازیابی شود. پیش‌فرض: `/pdns-data/pdns.sqlite3`. PowerDNS باید متوقف باشد |
| `--acme [PATH]` | پوشه acme.sh هم بازیابی شود. نسخه قبلی با پسوند `.before-restore-<زمان>` نگه داشته می‌شود |
| `--extract DIR` | کپی محتوای رمزگشایی‌شده در یک پوشه |

دیتابیس کنترلر در PostgreSQL با `pg_restore --clean --single-transaction` جایگزین می‌شود: یا کامل انجام می‌شود یا
هیچ تغییری نمی‌کند. پس از آن، مهاجرت‌ها اجرا می‌شوند تا نسخه قدیمی به ساختار فعلی برسد.

### سناریو ۱: دیتابیس کنترلر خراب شده یا داده اشتباه پاک شده (سرور سالم است)

```bash
cd /opt/pcdn
docker compose stop controller caddy               # جلوی نوشتن جدید را بگیرید
docker compose --profile tools run --rm --no-deps tools python -m app.manage backup --no-upload   # نسخه از وضعیت فعلی
docker compose --profile tools run --rm --no-deps tools python -m app.manage backups
docker compose --profile tools run --rm --no-deps tools python -m app.manage restore /data/backups/pcdn-backup-XXXX.tar.gz.enc --yes
docker compose up -d
docker compose exec controller python -m app.manage dns-sync     # زون‌ها را از روی دیتابیس بازیابی‌شده دوباره بنویس
```

تغییرهایی که بعد از زمان پشتیبان انجام شده‌اند (مثل سایت‌ها و رکوردهای جدید) از بین می‌روند. سایت‌هایی که در این
فاصله در WHMCS ساخته شده‌اند را با دکمه Create در WHMCS دوباره بسازید.

### سناریو ۲: سرور مرکزی کاملاً از دست رفته (سرور جدید)

پیش‌نیاز: فایل `.env` قبلی (یا دست‌کم `DATA_ENCRYPTION_KEY`، `BACKUP_PASSPHRASE`، `ADMIN_API_KEY`، `PDNS_API_KEY` و
مشخصات S3) باید جایی بیرون از سرور نگه داشته شده باشد.

1. سرور جدید را آماده کنید (Docker، و آزاد کردن پورت 53 مطابق README) و مخزن را در `/opt/pcdn` کلون کنید.
2. فایل `.env` قبلی را برگردانید. `ADMIN_API_KEY` و `PDNS_API_KEY` باید همان مقادیر قبلی باشند تا WHMCS و ns2
   بدون تغییر کار کنند.
3. دیتابیس و PowerDNS خالی را بسازید و PowerDNS را متوقف کنید:
   ```bash
   docker compose up -d --build db pdns
   docker compose stop pdns
   ```
4. بازیابی را انجام دهید.
   - از فضای ابری:
     ```bash
     docker compose --profile tools run --rm --no-deps tools python -m app.manage backups
     docker compose --profile tools run --rm --no-deps tools python -m app.manage restore \
         s3:pcdn-backups/pcdn-backup-XXXX.tar.gz.enc --pdns --acme --yes
     ```
   - از فایلی که به سرور کپی کرده‌اید:
     ```bash
     docker compose --profile tools run --rm --no-deps -v /root/pcdn-backup-XXXX.tar.gz.enc:/restore/b.enc:ro tools \
         python -m app.manage restore /restore/b.enc --pdns --acme --yes
     ```
5. همه سرویس‌ها را روشن کنید و زون‌ها را دوباره بنویسید:
   ```bash
   docker compose up -d
   docker compose exec controller python -m app.manage dns-sync
   ```
6. **DNSSEC:** اگر ns2 سالم مانده است، کلیدهای آن معتبرترین نسخه هستند، چون کلیدهای DNSSEC که بعد از زمان پشتیبان
   ساخته شده‌اند فقط روی ns2 وجود دارند. برای سایت‌هایی که DNSSEC دارند، با
   `curl -H "Authorization: Bearer $KEY" .../api/v1/sites/<domain>/dnssec` مقدار DS را با DS ثبت‌شده نزد
   ثبت‌کننده دامنه مقایسه کنید. اگر فرق داشت، کلید را از ns2 به ns1 کپی کنید:
   - در `.env` موقتاً سرور ns2 را اول بگذارید: `PDNS_API_URL=http://<NS2_IP>:8081,http://pdns:8081`
   - `docker compose up -d controller`
   - برای هر دامنه این دستور را اجرا کنید:
     `curl -X POST -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' -d '{"enabled":true}' .../api/v1/sites/<domain>/dnssec`
     (کلید سرور اول روی بقیه سرورها کپی می‌شود.)
   - `PDNS_API_URL` را به حالت قبل برگردانید.
7. اگر IP سرور عوض شده است، این موارد را به‌روز کنید: رکورد A دامنه `cdn-api`، رکورد Glue دامنه `ns1` نزد ثبت‌کننده،
   و فایروال ns2 (اجازه دسترسی IP جدید به پورت 8081).
8. بررسی نهایی:
   ```bash
   curl -s https://cdn-api.pasargadmizban.com/healthz/deep | python3 -m json.tool
   curl -H "Authorization: Bearer $KEY" https://cdn-api.pasargadmizban.com/api/v1/edges   # last_seen_at باید تازه شود
   dig @<NEW_IP> example.com SOA +short
   ```

نودها در تمام این مدت کانفیگ قبلی خود را حفظ می‌کنند و سایت‌ها را سرو می‌کنند. آمار مصرف در صف agent می‌ماند و
پس از برگشت کنترلر ارسال می‌شود.

### سناریو ۳: فقط دیتابیس PowerDNS ns1 خراب شده

```bash
docker compose stop pdns
docker compose --profile tools run --rm --no-deps tools python -m app.manage restore /data/backups/<file> --no-controller --pdns --yes
docker compose up -d pdns
docker compose exec controller python -m app.manage dns-sync
```

فایل قبلی با پسوند `.before-restore-<زمان>` نگه داشته می‌شود و مالک فایل (کاربر `pdns`) حفظ می‌شود.
نکته DNSSEC در مرحله ۶ سناریو ۲ اینجا هم صدق می‌کند.

---

## ۵. دسترس‌پذیری بالا (HA) برای سرور مرکزی

### کنترلر اکنون چندنمونه‌ای است

- **API بدون وضعیت (stateless) است.** همه وضعیت در PostgreSQL نگه داشته می‌شود، از جمله وضعیت هشدارها و
  زمان آخرین اجرای زمان‌بند. حافظه داخلی هر پروسه فقط کش است: کلاینت PowerDNS و کش ۵ ثانیه‌ای `/healthz/deep`.
- **فقط یک نمونه کارهای زمان‌بندی‌شده را اجرا می‌کند.** این کارها شامل failover نودها، بررسی NS، صدور SSL، هشدار
  و پشتیبان‌گیری هستند. انتخاب رهبر با `pg_try_advisory_lock` روی یک اتصال اختصاصی انجام می‌شود. رهبر در هر
  دور (`SCHEDULER_INTERVAL`) بررسی می‌کند که قفل هنوز در دست خودش است. اگر رهبر از کار بیفتد یا اتصالش قطع شود،
  PostgreSQL قفل را آزاد می‌کند و نمونه دیگر **در دور بعدی** رهبر می‌شود. این رفتار با kill شدن کانتینر آزمایش
  شده است و جابه‌جایی کمتر از یک دور طول کشید.
- در SQLite (نصب تک‌سرور بدون Postgres)، قفل فایل (`flock`) مانع می‌شود که پروسه دوم هم کارها را اجرا کند.
  SQLite برای HA مناسب نیست.

**چند کنترلر روی یک سرور** (برای ری‌استارت بدون قطعی و تحمل کرش یک پروسه):

```bash
docker compose up -d --scale controller=2
```

Caddy (`deploy/Caddyfile`) درخواست‌ها را بین همه کانتینرهای `controller` پخش می‌کند. اگر اتصال به یک کانتینر
ناموفق باشد، درخواست به کانتینر دیگر فرستاده می‌شود و کانتینر خراب ۳۰ ثانیه کنار گذاشته می‌شود.

### معماری دوسروره پیشنهادی

```
                 cdn-api.pasargadmizban.com  →  Floating IP (یا رکورد DNS با TTL کوتاه)
                                │
            ┌───────────────────┴───────────────────┐
   سرور A (اصلی)                               سرور B (پشتیبان) = همان ns2
   Caddy + controller                           Caddy + controller
   PostgreSQL primary  ── streaming replication ─► PostgreSQL hot standby
   PowerDNS ns1 ◄──── کنترلرها روی هر دو می‌نویسند ────► PowerDNS ns2
```

- کنترلرهای **هر دو سرور** با یک `DATABASE_URL` که هر دو دیتابیس را دارد کار می‌کنند:
  `...@/pcdn?host=<A>:5432&host=<B>:5432&target_session_attrs=read-write`.
  libpq همیشه به دیتابیسی وصل می‌شود که قابل نوشتن (primary) است. پس کنترلر B در حالت عادی روی دیتابیس A
  می‌نویسد، و پس از ارتقای B به primary، **خودکار** به دیتابیس محلی B وصل می‌شود. این رفتار با PostgreSQL 16
  واقعی آزمایش شده است.
- ns1 و ns2 از قبل روی دو سرور جدا هستند و هر کنترلر زون‌ها را روی هر دو می‌نویسد.
- اگر هر دو کنترلر یا کل سرور مرکزی از کار بیفتد، نودها با **آخرین کانفیگ اعمال‌شده** به سرو سایت‌ها ادامه
  می‌دهند (agent فایل‌های nginx را تغییر نمی‌دهد) و آمار مصرف را در صف نگه می‌دارند. PowerDNS هم همچنان پاسخ
  می‌دهد و سلامت نودها را با health check خودش بررسی می‌کند. آنچه متوقف می‌شود: API (پنل WHMCS، ساخت سایت،
  تغییر تنظیمات)، صدور SSL و failover نودها در لایه کنترلر.

### چه چیزی خودکار است و چه چیزی دستی؟

| رخداد | نتیجه |
|---|---|
| یکی از کانتینرهای کنترلر کرش می‌کند | **خودکار.** Caddy به نمونه دیگر می‌فرستد و زمان‌بند در دور بعد جابه‌جا می‌شود |
| سرور B یا دیتابیس standby از کار می‌افتد | **خودکار.** A بدون تغییر کار می‌کند (ns2 هم پاسخ نمی‌دهد، ولی resolverها از ns1 جواب می‌گیرند). هشدار «PowerDNS در دسترس نیست» می‌آید |
| سرور A (یا دیتابیس primary) از کار می‌افتد | **دستی (حدود ۵ دقیقه).** دیتابیس B باید promote شود و `cdn-api` به B منتقل شود. در این مدت نودها و DNS کار می‌کنند، ولی API در دسترس نیست |
| برگشت A پس از failover | **دستی.** A باید به‌عنوان standby جدید دوباره ساخته شود |

promote خودکار عمداً پیاده نشده است. با فقط دو سرور، سیستم نمی‌تواند «A مرده است» را از «ارتباط A و B قطع شده
است» تشخیص دهد. در حالت دوم، promote خودکار باعث split-brain می‌شود: دو دیتابیس primary که هر کدام داده متفاوتی
دارند. اگر failover خودکار لازم دارید، از PostgreSQL مدیریت‌شده با failover داخلی استفاده کنید یا Patroni را با
حداقل سه عضو etcd راه بیندازید. کنترلر با هر دو سازگار است، چون فقط `DATABASE_URL` را تغییر می‌دهید.

### راه‌اندازی (یک بار)

فرض: A با IP خصوصی `10.0.0.1` و B با IP خصوصی `10.0.0.2`. ارتباط خصوصی بین دو سرور برقرار است (در غیر این صورت
از WireGuard استفاده کنید). B در حال حاضر ns2 است و با `deploy/ns2-compose.yml` اجرا می‌شود.

**روی سرور A:**

1. در `.env` این مقادیر را اضافه کنید:
   ```
   PRIVATE_IP=10.0.0.1
   INSTANCE_NAME=server-a
   DATABASE_URL=postgresql+psycopg://pcdn:<POSTGRES_PASSWORD>@/pcdn?host=db:5432&host=10.0.0.2:5432&target_session_attrs=read-write&connect_timeout=5
   PDNS_API_URL=http://pdns:8081,http://10.0.0.2:8081
   ```
2. PostgreSQL و API PowerDNS را روی IP خصوصی باز کنید:
   ```bash
   docker compose -f docker-compose.yml -f deploy/ha-primary.override.yml up -d
   ufw allow from 10.0.0.2 to any port 5432 proto tcp
   ufw allow from 10.0.0.2 to any port 8081 proto tcp
   ```
   از این به بعد همیشه با هر دو فایل `-f` اجرا کنید. می‌توانید `COMPOSE_FILE=docker-compose.yml:deploy/ha-primary.override.yml`
   را در `.env` بگذارید تا لازم به تکرار نباشد.
3. کاربر replication و slot بسازید و دسترسی B را اضافه کنید:
   ```bash
   docker compose exec db psql -U pcdn -d pcdn -c "CREATE ROLE replicator WITH REPLICATION LOGIN PASSWORD '<REPL_PASSWORD>'" \
       -c "SELECT pg_create_physical_replication_slot('server_b')"
   docker compose exec db sh -c "echo 'host replication replicator 10.0.0.2/32 scram-sha-256' >> /var/lib/postgresql/data/pg_hba.conf"
   docker compose exec db psql -U pcdn -d pcdn -c "SELECT pg_reload_conf()"
   ```

**روی سرور B:**

1. سرویس ns2 قبلی را متوقف کنید و داده آن (زون‌ها و کلیدهای DNSSEC) را به volume پروژه جدید کپی کنید.
   `ns2-compose.yml` از پوشه `deploy` اجرا می‌شد، پس نام volume آن `deploy_pdns-data` است. نام دقیق را با
   `docker volume ls` بررسی کنید.
   ```bash
   cd /opt/pcdn/deploy && docker compose -f ns2-compose.yml down        # volume حذف نمی‌شود
   docker volume create pcdn_pdns-data
   docker run --rm -v deploy_pdns-data:/from -v pcdn_pdns-data:/to alpine sh -c 'cp -a /from/. /to/'
   ```
2. مخزن کامل را در `/opt/pcdn` داشته باشید و `.env` سرور A را کپی کنید. `DATA_ENCRYPTION_KEY`، `ADMIN_API_KEY`،
   `PDNS_API_KEY`، `POSTGRES_PASSWORD` و `BACKUP_PASSPHRASE` باید **یکسان** باشند. سپس این مقادیر را تغییر دهید:
   ```
   PRIVATE_IP=10.0.0.2
   INSTANCE_NAME=server-b
   DATABASE_URL=postgresql+psycopg://pcdn:<POSTGRES_PASSWORD>@/pcdn?host=10.0.0.1:5432&host=db:5432&target_session_attrs=read-write&connect_timeout=5
   PDNS_API_URL=http://10.0.0.1:8081,http://pdns:8081
   ```
3. دیتابیس standby را از روی A بسازید:
   ```bash
   cd /opt/pcdn
   docker volume create pcdn_db-data
   docker run --rm -e PGPASSWORD='<REPL_PASSWORD>' -v pcdn_db-data:/var/lib/postgresql/data postgres:16-alpine \
     sh -c 'pg_basebackup -h 10.0.0.1 -U replicator -D /var/lib/postgresql/data -R -X stream -S server_b -P \
            && chown -R postgres:postgres /var/lib/postgresql/data && chmod 700 /var/lib/postgresql/data'
   ```
   گزینه `-R` فایل `standby.signal` و تنظیم اتصال به A را می‌نویسد، پس این دیتابیس به‌صورت فقط‌خواندنی و همگام با A
   بالا می‌آید.
4. سرویس‌ها را روشن کنید:
   ```bash
   docker compose -p pcdn -f deploy/ha-standby-compose.yml --env-file .env up -d --build
   ufw allow from 10.0.0.1 to any port 5432 proto tcp
   ufw allow from 10.0.0.1 to any port 8081 proto tcp
   ```
5. بررسی:
   ```bash
   docker compose -p pcdn -f deploy/ha-standby-compose.yml exec db psql -U pcdn -d pcdn -Atc "select pg_is_in_recovery()"   # t
   # روی A:
   docker compose exec db psql -U pcdn -d pcdn -c "select client_addr, state, replay_lag from pg_stat_replication"  # streaming
   docker compose exec controller python -m app.manage dns-sync
   # روی B:
   docker compose -p pcdn -f deploy/ha-standby-compose.yml exec controller python -m app.manage health   # scheduler.role = follower
   ```

**آدرس `cdn-api`:** بهترین گزینه Floating IP (IP شناور) ارائه‌دهنده است که در حالت عادی به A وصل است.
اگر Floating IP ندارید، رکورد A دامنه `cdn-api` را با TTL برابر ۶۰ ثانیه تعریف کنید و هنگام failover آن را به B
تغییر دهید. WHMCS و نودها از نام `cdn-api` استفاده می‌کنند و تغییری لازم ندارند. Caddy سرور B گواهی را وقتی
می‌گیرد که ترافیک به B برسد؛ این کار چند ثانیه طول می‌کشد.

### Failover دستی (A از کار افتاده است)

1. **مطمئن شوید A واقعاً خاموش است یا دیگر نمی‌تواند بنویسد (fencing).** اگر A در دسترس است:
   `docker compose stop db controller`. اگر در دسترس نیست، از پنل ارائه‌دهنده سرور A را خاموش کنید یا Floating IP
   را از آن جدا کنید. تا A خاموش نشده، B را promote نکنید.
2. دیتابیس B را promote کنید:
   ```bash
   docker compose -p pcdn -f deploy/ha-standby-compose.yml exec db psql -U pcdn -d pcdn -c "SELECT pg_promote()"
   ```
   کنترلر B ظرف چند ثانیه به دیتابیس محلی وصل و رهبر زمان‌بند می‌شود. این را در `/healthz/deep` ببینید:
   `scheduler.role = leader`.
3. `cdn-api` را منتقل کنید: Floating IP را به B وصل کنید، یا رکورد DNS را به IP عمومی B تغییر دهید.
4. بررسی: `curl -s https://cdn-api.pasargadmizban.com/healthz/deep` و «Test Connection» در WHMCS.
   تا وقتی ns1 (روی A) خاموش است، هشدار PowerDNS برای آن باز می‌ماند و زون‌ها فقط روی ns2 نوشته می‌شوند.
   پس از برگشت ns1، زون‌ها خودکار دوباره نوشته می‌شوند.

### برگشت A (failback)

**A را با دیتابیس قدیمی‌اش روشن نکنید.** در آن صورت دو primary خواهید داشت. سرویس db روی A با
`restart: unless-stopped` پس از ریبوت خودکار بالا می‌آید، پس ترتیب زیر مهم است:

1. قبل از روشن کردن Docker روی A، یا بلافاصله پس از بوت: `docker compose stop db controller caddy`.
2. روی B (primary جدید) کاربر replication و slot بسازید (مرحله ۳ A را روی B و با IP A تکرار کنید)
   و `pg_hba.conf` را اصلاح کنید.
3. دیتای A را پاک کنید و از روی B بسازید:
   ```bash
   docker compose rm -sf db && docker volume rm pcdn_db-data
   docker volume create pcdn_db-data
   docker run --rm -e PGPASSWORD='<REPL_PASSWORD>' -v pcdn_db-data:/var/lib/postgresql/data postgres:16-alpine \
     sh -c 'pg_basebackup -h 10.0.0.2 -U replicator -D /var/lib/postgresql/data -R -X stream -S server_a -P \
            && chown -R postgres:postgres /var/lib/postgresql/data && chmod 700 /var/lib/postgresql/data'
   docker compose up -d
   ```
   نام volume به نام پروژه بستگی دارد. آن را با `docker volume ls` پیدا کنید.
4. اکنون B اصلی و A پشتیبان است. `DATABASE_URL` هر دو سرور هر دو میزبان را دارد، پس تغییر دیگری لازم نیست.
   اگر می‌خواهید A دوباره اصلی شود، در یک زمان کم‌ترافیک این کارها را انجام دهید: کنترلرها را متوقف کنید،
   دیتابیس B را با `docker compose stop db` خاموش کنید، A را promote کنید، B را مثل مرحله ۳ از روی A بسازید
   و کنترلرها را روشن کنید.

### آزمایش دوره‌ای

هر چند ماه یک بار در زمان کم‌ترافیک، failover را روی محیط آزمایشی یا با اطلاع قبلی تمرین کنید.
در این تمرین `/healthz/deep` و `/api/v1/alerts/status` را بررسی کنید.

---

## ۶. رمزنگاری کلیدهای خصوصی و مدیریت کلید

با تعیین `DATA_ENCRYPTION_KEY`، این مقادیر در دیتابیس به‌صورت رمزنگاری‌شده (Fernet: AES-128-CBC + HMAC-SHA256) و
با پیشوند `enc:v1:` ذخیره می‌شوند:

- `sites.ssl_key`: کلید خصوصی گواهی‌های Let's Encrypt و گواهی‌های اختصاصی مشتری‌ها
- `sites.secret`: کلید HMAC کوکی عبور از چالش روی نودها

رمزگشایی فقط در حافظه کنترلر و هنگام ساخت کانفیگ نودها انجام می‌شود. نودها مثل قبل کلید را به‌صورت PEM دریافت
می‌کنند و در فایلی با دسترسی `600` نگه می‌دارند. API مدیریت هیچ‌وقت کلید را برنمی‌گرداند.
این موارد در این لایه رمزنگاری **نمی‌شوند**: کلیدهای DNSSEC که در PowerDNS هستند، و حساب acme.sh. برای محافظت از
آن‌ها دسترسی به سرور را محدود کنید و برای فایل‌های پشتیبان `BACKUP_PASSPHRASE` بگذارید.

### فعال‌سازی روی نصب فعلی

```bash
docker compose exec controller python -m app.manage gen-key      # یک کلید جدید چاپ می‌کند
# کلید را در .env بگذارید:  DATA_ENCRYPTION_KEY=<key>
# و یک نسخه از آن را بیرون از سرور (password manager) ذخیره کنید
docker compose up -d                                              # هنگام شروع، ردیف‌های قبلی خودکار رمز می‌شوند
docker compose exec controller python -m app.manage encryption-status
# {"key_configured": true, "plaintext": 0, "encrypted": 124, "readable": true, ...}
```

اگر کلید تعیین نشده باشد، کنترلر مثل قبل کار می‌کند و مقادیر را بدون رمز ذخیره می‌کند. ولی هنگام شروع یک هشدار در
لاگ می‌نویسد و `/healthz/deep` هم آن را در `warnings` نشان می‌دهد. دستور `manage encrypt-secrets` هم هر زمان
ردیف‌های رمزنشده را رمز می‌کند.

### چرخش کلید (rotation)

1. یک کلید جدید بسازید و آن را **اول** بگذارید. کلید قبلی را بعد از کاما نگه دارید:
   `DATA_ENCRYPTION_KEY=<new>,<old>`
2. همه کنترلرها را ری‌استارت کنید (در HA روی هر دو سرور). در این حالت هر دو کلید برای خواندن پذیرفته می‌شوند.
3. همه مقادیر را با کلید جدید دوباره رمز کنید:
   `docker compose exec controller python -m app.manage rotate-key`
4. با `manage encryption-status` مطمئن شوید `readable: true` است. سپس کلید قدیمی را حذف کنید
   (`DATA_ENCRYPTION_KEY=<new>`) و دوباره ری‌استارت کنید.
5. توجه کنید که فایل‌های پشتیبانِ قبل از چرخش با کلید قدیمی رمز شده‌اند. کلید قدیمی را تا وقتی آن پشتیبان‌ها
   نگه داشته می‌شوند (`BACKUP_KEEP` روز) در جای امن نگه دارید.

### خطاها

| وضعیت | رفتار |
|---|---|
| کلید با فرمت اشتباه | کنترلر اصلاً بالا نمی‌آید و پیام `DATA_ENCRYPTION_KEY: key #N is not a valid Fernet key` را نشان می‌دهد |
| کلید درست نیست یا کلید قدیمی حذف شده | کنترلر بالا می‌آید، لاگ `CRITICAL stored secrets cannot be decrypted` را ثبت می‌کند و `/healthz/deep` در حالت `degraded` و `encryption.readable=false` قرار می‌گیرد. دریافت کانفیگ نودها خطا می‌دهد و نودها با کانفیگ قبلی کار می‌کنند. کلید درست را برگردانید |
| کلید تعیین نشده ولی داده رمزشده وجود دارد | خطای `an encrypted secret was found in the database but DATA_ENCRYPTION_KEY is not set` |

**اگر کلید برای همیشه از دست رفته باشد:** کلیدهای رمزشده قابل بازیابی نیستند. آخرین راه این دستور است:

```bash
docker compose exec controller python -m app.manage drop-unreadable-secrets --yes
```

این دستور کلیدهای غیرقابل‌خواندن را فراموش می‌کند. گواهی‌های Let's Encrypt دوباره صادر می‌شوند، گواهی‌های
اختصاصی حذف می‌شوند (مشتری باید دوباره آپلود کند) و secretها از نو ساخته می‌شوند. پیش از اجرا یک کلید جدید در
`DATA_ENCRYPTION_KEY` بگذارید.

---

## ۷. مانیتورینگ با /healthz/deep

| مسیر | احراز هویت | کاربرد |
|---|---|---|
| `GET /healthz` | ندارد | زنده بودن پروسه. برای healthcheck داکر و load balancer |
| `GET /healthz/deep` | ندارد | وضعیت کامل برای مانیتورینگ بیرونی. پاسخ ۵ ثانیه کش می‌شود. هیچ کلید، رمز یا آدرس داخلی در آن نیست |

نمونه پاسخ:

```json
{
  "status": "ok",
  "instance": "server-a",
  "database": {"ok": true, "dialect": "postgresql", "revision": "0002", "head": "0002"},
  "pdns": [{"server": 1, "ok": true, "latency_ms": 3}, {"server": 2, "ok": true, "latency_ms": 41}],
  "scheduler": {"role": "leader", "last_run_age_seconds": 12, "leader": "server-a"},
  "encryption": {"enabled": true, "readable": true, "plaintext_secrets": 0, "encrypted_secrets": 248},
  "backup": {"enabled": true, "last_success_age_hours": 7.5, "failing": false},
  "alerts": {"channels": ["telegram", "email"], "open": 0, "critical": 0},
  "warnings": []
}
```

- **کد HTTP:** اگر دیتابیس در دسترس نباشد `503` برمی‌گردد و `status` برابر `down` است. در بقیه حالت‌ها `200`
  برمی‌گردد و `status` یکی از `ok` یا `degraded` است. `degraded` یعنی یکی از این موارد: سرور PowerDNS در دسترس
  نیست، زمان‌بند بیش از `3×SCHEDULER_INTERVAL + 15 دقیقه` اجرا نشده است، مهاجرتی در انتظار است، یا کلید رمزنگاری
  نمی‌تواند داده‌ها را بخواند. هشدارهای کم‌اهمیت‌تر در `warnings` می‌آیند، مثل نبود کلید رمزنگاری، نبود کانال هشدار
  یا پشتیبانِ قدیمی‌تر از ۲۶ ساعت.
- `pdns[].server` شماره سرور به ترتیب `PDNS_API_URL` است.
- `scheduler.role` یکی از این مقادیر است: `leader`، `follower`، `disabled` (با `SCHEDULER_ENABLED=false`) یا
  `not-running`. در HA دقیقاً یک نمونه باید `leader` باشد. فیلد `leader` نام آخرین نمونه‌ای است که کارها را اجرا کرده.
- `pdns` به‌صورت `server` و `ok` نمایش داده می‌شود و آدرس سرورها نمایش داده نمی‌شود.

**Uptime Kuma** (یا هر سرویس مشابه): یک مانیتور HTTP(s) - Keyword با آدرس
`https://cdn-api.pasargadmizban.com/healthz/deep` و کلمه کلیدی `"status":"ok"` بسازید. سرویس مانیتورینگ را روی
سروری جدا از سرور مرکزی اجرا کنید، چون هشدار «کنترلر از کار افتاده» را خود کنترلر نمی‌تواند بفرستد.
در HA، Caddy سرور پشتیبان تا زمان failover گواهی `cdn-api` را ندارد. برای بررسی جداگانه هر سرور، روی خود آن سرور
از cron دستور `docker compose ... exec -T controller python -m app.manage health` را اجرا کنید. اگر وضعیت `ok`
نباشد، کد خروج آن ۱ است.

**cron ساده روی یک سرور دیگر:**

```bash
*/2 * * * * curl -fsS --max-time 10 https://cdn-api.pasargadmizban.com/healthz/deep | grep -q '"status":"ok"' \
  || curl -s "https://tg-relay.example.com/bot<TOKEN>/sendMessage" -d chat_id=<ID> -d text="CDN controller NOT OK"
```

---

## ۸. پایش سلامت نودها، صفحه وضعیت عمومی و رخدادها (SPEC §8)

### آزمون سلامت مصنوعی (synthetic probes)

هر حدود ۶۰ ثانیه، کنترلر (فقط نمونه leader) خودش از هر نود فعال آدرس
`http://<node>/__pcdn/health` را با هدر `Host: health.pcdn` می‌خواند و زمان پاسخ و موفق/ناموفق بودن
آن را ذخیره می‌کند. این کار نودی را می‌گیرد که هنوز heartbeat می‌فرستد (agent سالم است) اما درخواست‌ها
را با خطا پاسخ می‌دهد — مثلاً بعد از یک `nginx -t` خراب. موفقیت یعنی HTTP 200 که بدنه‌اش با `ok` شروع
شود. اگر نود IPv6 داشته باشد و `PROBE_IPV6=true` باشد، آدرس IPv6 هم آزمایش می‌شود؛ نود سالم شمرده
می‌شود اگر **هرکدام** از دو خانواده آدرس پاسخ دهند و خانواده ناموفق در `probe_error` ثبت می‌شود.

پس از `PROBE_FAIL_CHECKS` (پیش‌فرض ۳) شکست پیاپی، در حالی که نود هنوز heartbeat می‌فرستد، هشدار
`edge_probe:{id}` («نود گزارش می‌دهد ولی سالم نیست») ارسال می‌شود؛ با یک آزمون موفق برطرف می‌شود. اگر
نود اصلاً heartbeat نفرستد، همان هشدار `edge_offline` پوشش می‌دهد و این هشدار ارسال نمی‌شود. نتیجه در
`GET /api/v1/edges` (فیلد `probe`) و شمار نودهای ناسالم در `GET /healthz/deep` (`edges.probe_failing`)
دیده می‌شود. تنظیم‌ها: `PROBE_ENABLED`، `PROBE_TIMEOUT`، `PROBE_IPV6`، `PROBE_FAIL_CHECKS`.

### صفحه وضعیت عمومی

`GET /status.json` (بدون احراز هویت، مانند `/healthz`) وضعیت کلی سرویس را برمی‌گرداند: وضعیت کلی، شمار
کلی/آنلاین نودها (فقط عدد)، سه مؤلفه (CDN، سرویس تونل، DNS) و متن رخدادهای نوشته‌شده توسط اپراتور. این
پاسخ **هیچ‌گاه** آدرس IP، نام، منطقه نود، دامنه مشتری یا معیاری که زیرساخت را لو دهد نمایش نمی‌دهد؛ فقط
اعداد جمعی و متن رخدادها. صفحه ثابت `status/index.html` (فارسی، RTL، روشن/تیره) این آدرس را می‌خواند و
نمایش می‌دهد؛ آن را روی هر دامنه‌ای (یا میزبان WHMCS) قرار دهید.

### رخدادها (incidents)

اپراتور با API زیر (نیازمند کلید ادمین) رخداد می‌سازد و به‌روزرسانی می‌کند:

```text
GET   /api/v1/incidents[?all=1]          # باز، یا همه با all=1، جدیدترین اول
POST  /api/v1/incidents                  # {title, body, severity, status?}
POST  /api/v1/incidents/{id}/updates     # {status, body} — وضعیت رخداد را هم جابه‌جا می‌کند
PATCH /api/v1/incidents/{id}             # {title?, body?, severity?, status?}
```

`severity` یکی از `minor`، `major`، `maintenance` و `status` یکی از `investigating`، `identified`،
`monitoring`، `resolved`، `scheduled` است. رخداد `resolved` پس از ۱۰ رخداد برطرف‌شده از `status.json`
حذف می‌شود ولی همچنان با `?all=1` دیده می‌شود.

---

## مرجع دستورهای مدیریتی

```text
python -m app.manage migrate [--revision head]
python -m app.manage current | heads | history [-v]
python -m app.manage stamp <rev>
python -m app.manage downgrade <rev> --yes
python -m app.manage makemigration -m "msg" [--rev-id 0003] [--empty]
python -m app.manage backup [--dir DIR] [--no-upload]
python -m app.manage backups [--dir DIR]
python -m app.manage restore <file|s3:KEY> --yes [--passphrase P|-] [--no-controller] [--pdns [PATH]] [--acme [PATH]] [--extract DIR]
python -m app.manage dns-sync
python -m app.manage gen-key
python -m app.manage encryption-status
python -m app.manage encrypt-secrets
python -m app.manage rotate-key
python -m app.manage drop-unreadable-secrets --yes
python -m app.manage alerts-test
python -m app.manage health
```

API مدیریت (با `Authorization: Bearer <ADMIN_API_KEY>`):

| متد | مسیر | کاربرد |
|---|---|---|
| GET | `/api/v1/alerts/status` | کانال‌های تنظیم‌شده و مشکلات باز |
| POST | `/api/v1/alerts/test` | ارسال پیام آزمایشی و نتیجه هر کانال |
