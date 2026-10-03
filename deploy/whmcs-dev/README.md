# محیط تست WHMCS روی کامپیوتر خودتان (مک / ویندوز / لینوکس)

این پوشه یک محیط کامل تست با Docker می‌سازد: WHMCS (نسخه دارای لایسنس خودتان) + PHP 8.2 + ionCube
+ MariaDB + کران WHMCS + سرور مرکزی CDN همین ریپو. ماژول‌های CDN مستقیم از ریپو وصل می‌شوند،
پس هر تغییری در کد ماژول فوراً در WHMCS دیده می‌شود.

> فایل‌های WHMCS در ریپو قرار نمی‌گیرند (پوشه `whmcs/` در `.gitignore` است).

## پیش‌نیاز
- **Docker Desktop** از docker.com (برای مک، نسخه Apple Silicon یا Intel را متناسب با مک خود انتخاب کنید) — نصب کنید و اجرا کنید تا آیکون نهنگ در نوار بالا ثابت شود.
- فایل zip نصبی WHMCS و **کلید لایسنس** (ترجیحاً لایسنس تست/توسعه، نه لایسنس سایت اصلی).
- نسخه WHMCS شما باید از PHP 8.2 پشتیبانی کند (WHMCS 8.11 به بعد). اگر نسخه قدیمی‌تر دارید، در
  `docker-compose.yml` بخش `web` و `cron` این را اضافه کنید:
  `build: { context: ., args: { PHP_VERSION: "8.1" } }`

## راه‌اندازی
1. ریپو را دریافت کنید (یا از GitHub با Code ← Download ZIP):
   ```bash
   git clone https://github.com/namesissr/whmcs-cdn.git
   cd whmcs-cdn/deploy/whmcs-dev
   ```
2. فایل zip WHMCS را باز کنید و **محتویات** پوشه `whmcs` داخل آن را در پوشه جدیدی به نام `whmcs`
   همین‌جا بگذارید، طوری که فایل `whmcs/index.php` وجود داشته باشد. سپس:
   ```bash
   cp whmcs/configuration.php.new whmcs/configuration.php
   ```
3. همه چیز را بالا بیاورید (بار اول چند دقیقه طول می‌کشد):
   ```bash
   docker compose up -d --build
   ```
4. در مرورگر باز کنید: **http://localhost:8080/install/install.php** و مراحل را بروید:
   - کلید لایسنس
   - دیتابیس: Host = `db` ، Port = `3306` ، Username = `whmcs` ، Password = `whmcs-dev-pass` ، Database = `whmcs`
   - ساخت حساب مدیر
5. بعد از پایان نصب، پوشه نصب را پاک کنید:
   ```bash
   rm -rf whmcs/install
   ```
   پنل مدیر: http://localhost:8080/admin — ناحیه مشتری: http://localhost:8080

## نصب ماژول CDN در WHMCS
ماژول‌ها از قبل در جای خود هستند؛ فقط فعالشان کنید:
1. **System Settings ← Addon Modules** ← «مدیریت CDN پاسارگاد» ← Activate ← Configure ← تیک Full Administrator.
2. **System Settings ← Servers ← Add New Server**:
   - Module: **Pasargad CDN**
   - Hostname: `controller` ، Port: `8000` ، تیک Secure را **نزنید**
   - Access Hash: `dev-admin-key`
   - Test Connection باید موفق شود.
3. **Addons ← مدیریت CDN پاسارگاد ← پلن‌ها و قیمت‌گذاری** ← جادوی ساخت محصولات را اجرا کنید.
4. **تنظیمات و سلامت** را باز کنید و هشدارها را برطرف کنید.
5. برای تست پرداخت از کیف پول: در WHMCS **Setup ← Payments ← Payment Gateways** یک درگاه تستی
   (مثلاً Bank Transfer) فعال کنید، یک مشتری تستی بسازید، از پرونده مشتری **Add Credit** بزنید
   و از ناحیه مشتری یک پلن CDN سفارش دهید.

> این محیط PowerDNS و نود CDN واقعی ندارد؛ برای تست WHMCS، پنل‌ها، سفارش و صورتحساب کافی است.
> مصرف ترافیک را می‌توانید با API سرور مرکزی (http://localhost:8000/docs) شبیه‌سازی کنید.

## دستورهای مفید
```bash
docker compose ps                 # وضعیت
docker compose logs -f web        # لاگ وب‌سرور/PHP
docker compose exec cron php -q /var/www/html/crons/cron.php   # اجرای دستی کران
docker compose down               # خاموش کردن (داده‌ها می‌مانند)
docker compose down -v            # پاک کردن کامل همه داده‌ها
```
