# فضای ذخیره‌سازی ابری (Object Storage) — SPEC §16.8

این سند راه‌اندازی، تنظیم، API، صورتحساب، پشتیبان‌گیری و ارتقای سرویس «فضای ذخیره‌سازی» را توضیح می‌دهد.
سرویس روی **MinIO** (سازگار با S3) اجرا می‌شود، جلوی آن **Caddy** با گواهی خودکار Let's Encrypt قرار دارد و
کنترلر برای هر مشتری باکت، کلید دسترسی محدود به همان باکت، سهمیه (quota) و گزارش مصرف ساعتی می‌سازد. هر باکت
می‌تواند مستقیماً **مبدأ (origin) CDN** یک رکورد باشد.

```
 مشتری (aws-cli, rclone, SDK) ──HTTPS/S3──┐
                                          ▼
 لبه‌ها (edge) ──HTTPS + Referer توکن──▶ Caddy (TLS) ──▶ MinIO (تک‌دیسک یا ۴ دیسک erasure)
                                          ▲
 کنترلر ──HTTPS: S3 + /minio/admin (فقط از IP کنترلر)
```

---

## ۱. طراحی و دلایل انتخاب

| موضوع | انتخاب | چرا |
|---|---|---|
| مدیریت MinIO | پیاده‌سازی کوچک داخل کنترلر (`app/minio_client.py`): امضای SigV4 + رمزنگاری payload مدیریتی MinIO (Argon2id/PBKDF2 + AES-GCM/ChaCha20 در قالب DARE/sio) | فقط کتابخانه استاندارد و `cryptography` (که از قبل وابستگی است). بدون `mc` در ایمیج کنترلر، بدون subprocess و بدون قرار گرفتن کلید روی خط فرمان. خروجی رمزنگاری بایت‌به‌بایت با madmin-go/sio-go یکسان است (بردارهای آزمون Go در `tests/test_storage.py`) و کل جریان روی MinIO واقعی هم آزموده شده است. |
| کلید مشتری | **Service account** (Access Key) متعلق به کاربر کنترلر با **policy درون‌خطی محدود به همان باکت** | MinIO دسترسی service account را «policy والد ∩ policy درون‌خطی» حساب می‌کند. هر کاربر بدون هیچ مجوز admin می‌تواند service accountهای خودش را بسازد/حذف کند؛ پس کنترلر به `admin:CreateUser`، `admin:CreatePolicy`، `admin:AttachUserOrGroupPolicy`، `admin:CreateServiceAccount` یا `admin:UpdateServiceAccount` نیاز ندارد — این مجوزها اجازهٔ ساخت کلید برای کاربران دیگر (حتی root) را می‌دادند. |
| چرخش کلید | ساخت service account جدید، سپس حذف قبلی | `UpdateServiceAccount` به مجوز سراسری نیاز دارد؛ با این روش لازم نیست. Access Key هم عوض می‌شود. |
| نام باکت | `STORAGE_BUCKET_PREFIX` + برچسب تصادفی ۸ حرفی هر سایت + `-` + نام مشتری، مثل `cdn-k3m9q2xa-assets` | نام باکت در MinIO سراسری است؛ پیشوند جلوی تداخل بین مشتری‌ها را می‌گیرد و policy کنترلر را به `cdn-*` محدود می‌کند. برچسب تصادفی (نه id سایت) نمی‌گذارد سایت جدیدی که id یک سایت حذف‌شده را گرفته به باکت باقیمانده برسد. کنترلر هرگز باکتی را که خودش همان لحظه نساخته «تصاحب» نمی‌کند (۴۰۹). |
| سهمیه | سهمیهٔ سخت MinIO روی هر باکت = حجم خود باکت + فضای باقیماندهٔ سایت (`storage_gb` پلن منهای مجموع مصرف)، حداقل ۱ بایت | MinIO سهمیه را برای هر باکت جدا می‌شناسد؛ این فرمول سقف کل سایت را تقریب می‌زند. هر ساعت، هنگام ساخت/حذف باکت و هنگام تغییر پلن دوباره محاسبه می‌شود. علاوه بر آن ساخت باکت جدید وقتی سایت پر است رد می‌شود و برای اپراتور هشدار `storage_quota:<دامنه>` باز می‌شود. |
| مبدأ CDN | policy باکت: `s3:GetObject` ناشناس **فقط** با هدر `Referer` برابر توکن تصادفی همان باکت | باکت عمومی نمی‌شود؛ فقط لبه‌ها توکن را دارند. توکن فقط همان چیزی را می‌دهد که CDN به‌هرحال منتشر می‌کند (GET فایل‌های همان باکت، بدون فهرست‌گیری). کلید و رمز مشتری هرگز به لبه نمی‌رود. |

---

## ۲. راه‌اندازی سرور ذخیره‌سازی

یک سرور جدا (Ubuntu 24.04 + Docker) پیشنهاد می‌شود. پوشهٔ `deploy/storage/` را روی آن کپی کنید.

1. **DNS:** رکورد A/AAAA برای دامنهٔ S3 (مثلاً `s3.pasargadmizban.com`) به IP همین سرور. این رکورد را
   پروکسی (CDN) نکنید.
2. **فایروال:** پورت‌های 80 و 443 باز. پورت 9000 MinIO منتشر نمی‌شود (فقط Caddy در شبکهٔ داخلی Docker به آن وصل است).
3. **دیسک‌ها:**
   * تک‌گره (`docker-compose.yml`): یک مسیر داده (`MINIO_DATA_DIR`). فقط **یک نسخه** از هر شیء نگه داشته
     می‌شود؛ زیر آن RAID1/RAID10 بگذارید یا نسخهٔ erasure را انتخاب کنید و حتماً پشتیبان بگیرید.
   * چهار دیسک با erasure coding (`docker-compose.erasure.yml`): چهار دیسک هم‌اندازه، هر کدام XFS، بدون RAID/LVM،
     با UUID در `/etc/fstab` روی `MINIO_DISK1..4` مونت شوند. پیش‌فرض MinIO روی ۴ دیسک EC:2 است: ظرفیت مفید
     نصف ظرفیت خام، و از کار افتادن ۲ دیسک خواندن را متوقف نمی‌کند (نوشتن تا ۱ دیسک خراب ادامه دارد).
     ```sh
     mkfs.xfs -L disk1 /dev/sdb   # و همین‌طور برای sdc, sdd, sde
     echo 'LABEL=disk1 /mnt/disk1 xfs defaults,noatime 0 2' >> /etc/fstab   # ... disk2..disk4
     mkdir -p /mnt/disk{1..4} && mount -a
     ```
4. **تنظیمات:**
   ```sh
   cd deploy/storage
   cp .env.example .env && chmod 600 .env
   # STORAGE_DOMAIN, ACME_EMAIL, MINIO_ROOT_USER, MINIO_ROOT_PASSWORD (۴۰ کاراکتر تصادفی)
   # ADMIN_ALLOW_IPS = IP سرور(های) کنترلر، مثلاً "203.0.113.10/32 203.0.113.11/32"
   ```
   اعتبارنامهٔ root فقط در همین `.env` روی سرور ذخیره‌سازی است؛ نه در مخزن git و نه در `.env` کنترلر
   (`.env` در `.gitignore` است).
5. **اجرا:**
   ```sh
   docker compose up -d                                   # تک‌گره
   # یا
   docker compose -f docker-compose.erasure.yml up -d     # ۴ دیسک
   docker compose ps          # minio و caddy باید healthy باشند
   curl -fsS https://s3.pasargadmizban.com/minio/health/live
   ```
   سلامت: MinIO با `mc ready local` و Caddy با API مدیریتی داخلی خودش (`:2019`) بررسی می‌شوند؛ Caddy هم هر
   ۱۵ ثانیه `/minio/health/live` را چک می‌کند.
6. **کاربر کنترلر:**
   ```sh
   ./bootstrap.sh                                  # یا: ./bootstrap.sh -f docker-compose.erasure.yml
   ```
   این اسکریپت policy زیر را با نام `pcdn-controller` می‌سازد، کاربر `pcdn-controller` را با رمز تصادفی
   ۴۰ کاراکتری ایجاد و policy را به آن وصل می‌کند و **فقط یک بار** این دو مقدار را چاپ می‌کند:
   ```
   STORAGE_ADMIN_ACCESS_KEY=pcdn-controller
   STORAGE_ADMIN_SECRET_KEY=...
   ```
   اجرای دوباره فقط policy را دوباره اعمال می‌کند؛ `--rotate` رمز تازه می‌سازد (بعد `.env` کنترلر را به‌روز و
   کنترلر را ری‌استارت کنید).

### policy دقیق کاربر کنترلر (`deploy/storage/pcdn-controller-policy.json`)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PcdnBucketQuotaAndUsage",
      "Effect": "Allow",
      "Action": ["admin:SetBucketQuota", "admin:GetBucketQuota", "admin:DataUsageInfo"]
    },
    {
      "Sid": "PcdnCustomerBucketsOnly",
      "Effect": "Allow",
      "Action": ["s3:*"],
      "Resource": ["arn:aws:s3:::cdn-*", "arn:aws:s3:::cdn-*/*"]
    }
  ]
}
```

* `s3:*` فقط روی باکت‌های `cdn-*`: ساخت/حذف باکت، policy باکت و همهٔ عملیاتی که کلیدهای مشتری لازم دارند
  (کلید مشتری زیرمجموعهٔ همین است). باکت‌های دیگر MinIO (مثلاً پشتیبان‌ها) برای کنترلر قابل دسترس نیستند.
* ساخت/حذف service account برای **خود** کاربر به هیچ مجوز admin نیاز ندارد (MinIO فقط deny صریح را بررسی می‌کند).
  `admin:CreateServiceAccount`/`admin:UpdateServiceAccount` عمداً **داده نشده‌اند**: با آن‌ها می‌شد برای root
  کلید ساخت. آزمون `test_real_minio` و آزمون دستی نشان داده‌اند که با این policy ساخت کلید برای root، ساخت کاربر
  و ارتقای دسترسی از طریق service account رد می‌شود (403).
* اگر `STORAGE_BUCKET_PREFIX` را عوض کنید، `cdn-*` را در این فایل هم عوض و `./bootstrap.sh` را دوباره اجرا کنید.

### policy کلید هر مشتری (درون‌خطی، ساخته‌شده توسط کنترلر)

روی `arn:aws:s3:::<bucket>`: `s3:GetBucketLocation`، `s3:ListBucket`، `s3:ListBucketMultipartUploads`؛
روی `arn:aws:s3:::<bucket>/*`: `s3:GetObject`، `s3:PutObject`، `s3:DeleteObject`، `s3:AbortMultipartUpload`،
`s3:ListMultipartUploadParts` و Get/Put/DeleteObjectTagging. بدون تغییر policy باکت، versioning، lifecycle،
حذف باکت یا هر عملیات admin.

---

## ۳. تنظیم کنترلر

در `.env` کنترلر (بخش «object storage» در `.env.example`):

| متغیر | توضیح |
|---|---|
| `STORAGE_ENDPOINT` | آدرس https که کنترلر برای S3 و admin API استفاده می‌کند. خالی = سرویس خاموش (مسیرهای storage پاسخ 503). |
| `STORAGE_PUBLIC_ENDPOINT` | آدرسی که به مشتری نشان داده و در config لبه‌ها گذاشته می‌شود (پیش‌فرض همان `STORAGE_ENDPOINT`). |
| `STORAGE_ADMIN_ACCESS_KEY` / `STORAGE_ADMIN_SECRET_KEY` | خروجی `bootstrap.sh` (نام قدیمی `STORAGE_ADMIN_SECRET` هم پذیرفته می‌شود). هرگز root. |
| `STORAGE_REGION` | باید با `MINIO_REGION` سرور ذخیره‌سازی یکی باشد (پیش‌فرض `us-east-1`). |
| `STORAGE_BUCKET_PREFIX` | پیش‌فرض `cdn-`؛ باید با Resource در policy کنترلر بخواند. |
| `STORAGE_MAX_BUCKETS` | سقف تعداد باکت هر سایت (پیش‌فرض ۱۰، حداکثر ۱۰۰). |
| `STORAGE_INSECURE_HTTP` | فقط برای MinIO در شبکهٔ خصوصی بدون TLS؛ در غیر این صورت `http://` پذیرفته نمی‌شود. |

`STORAGE_ENDPOINT` تنظیم اپراتور و مورد اعتماد است؛ هیچ ورودی مشتری میزبان (host) را انتخاب نمی‌کند — نام باکت
فقط `[a-z0-9-]` است و همیشه با پیشوند ساخته می‌شود. درخواست‌های کنترلر به MinIO از proxy محیط عبور نمی‌کنند و
redirect را دنبال نمی‌کنند.

**پلن:** ویژگی `storage_gb` (گیگابایت = GiB، ۰ = بدون فضای ذخیره‌سازی) با همان API پلن:
`PATCH /api/v1/sites/{domain}/plan {"features": {"storage_gb": 50}}`. کاهش آن سهمیه‌ها را بلافاصله پایین می‌آورد
(نوشتن متوقف می‌شود، خواندن/حذف ادامه دارد)؛ با `0` باکت‌ها در حجم فعلی منجمد می‌شوند و رکوردهای storage از
config لبه حذف می‌شوند.

**رمزنگاری در حالت سکون:** رمز کلید مشتری (فقط برای سابقه نگه داشته می‌شود؛ یک بار نمایش داده شده) و توکن مبدأ هر
باکت با `DATA_ENCRYPTION_KEY` رمز می‌شوند و در `encrypt-secrets`، `rotate-key`، `encryption-status` و
`drop-unreadable-secrets` لحاظ شده‌اند. اگر کلید از دست برود، `drop-unreadable-secrets` رمز ذخیره‌شدهٔ مشتری را
فراموش می‌کند (مشتری با rotate-key کلید تازه می‌گیرد) و توکن مبدأ جدید می‌سازد؛ کار ساعتی policy باکت‌ها را دوباره
اعمال می‌کند.

---

## ۴. API برای WHMCS (کلید ادمین)

همه زیر `/api/v1` با `Authorization: Bearer <ADMIN_API_KEY>`. خطاها: `{"detail": "<پیام فارسی>"}`.

| روش و مسیر | پاسخ |
|---|---|
| `GET /sites/{d}/storage` یا `GET /sites/{d}/storage/buckets` | نمای کلی + باکت‌ها (بدون هیچ رمز) |
| `POST /sites/{d}/storage/buckets` بدنه `{"name": "assets"}` | **201** باکت + `access_key` + `secret_key` (فقط همین یک بار) |
| `DELETE /sites/{d}/storage/buckets/{name}` | `{"ok": true}`؛ **409** اگر خالی نیست یا مبدأ رکوردی است |
| `POST /sites/{d}/storage/buckets/{name}/rotate-key` | **200** کلید جدید (`access_key` و `secret_key`، فقط همین یک بار)؛ کلید قبلی بلافاصله باطل |
| `GET /sites/{d}/storage/usage?month=YYYY-MM` | گزارش GB-ساعت ماه برای صورتحساب (بدون month = ماه جاری) |
| `GET /storage/usage?month=YYYY-MM` | همان گزارش برای همهٔ سایت‌هایی که آن ماه مصرف داشته‌اند (cron) |

کدها: 422 نام نامعتبر (۳ تا ۴۰ کاراکتر `a-z 0-9 -`، شروع و پایان با حرف/رقم)، 403 پلن بدون فضای ذخیره‌سازی / سقف
تعداد باکت / سایت پر، 404 باکت یا سایت ناموجود، 409 نام تکراری یا نام گرفته‌شده در MinIO، 502 خطای MinIO (هر چه
ساخته شده بود برگردانده می‌شود)، 503 فضای ذخیره‌سازی روی کنترلر تنظیم نشده.

**نمای کلی (GET):**
```json
{
  "available": true, "enabled": true,
  "storage_gb": 50, "limit_bytes": 53687091200,
  "used_bytes": 1048576, "used_gb": 0.001, "over_quota": false,
  "endpoint": "https://s3.pasargadmizban.com", "region": "us-east-1",
  "max_buckets": 10, "usage_stale": false,
  "buckets": [{
    "name": "assets", "bucket": "cdn-k3m9q2xa-assets", "access_key": "PCDN7Q4J2M1X0A9B8C7D",
    "endpoint": "https://s3.pasargadmizban.com", "region": "us-east-1",
    "quota_bytes": 53686042624,
    "usage": {"bytes": 1048576, "objects": 12, "gb": 0.001, "at": "2026-10-01T12:00:00Z"},
    "created_at": "2026-10-01T10:00:00Z", "rotated_at": null
  }]
}
```
مصرف از scanner خود MinIO می‌آید (هر چند دقیقه به‌روز می‌شود، نه لحظه‌ای). در هر GET تازه خوانده می‌شود؛ اگر MinIO
در دسترس نباشد آخرین مقدار ذخیره‌شده با `"usage_stale": true` برمی‌گردد.

**ساخت / چرخش کلید (POST):** همان شیء باکت به‌علاوهٔ
```json
{"secret_key": "<40 کاراکتر>", "secret_note": "این کلید فقط همین یک بار نمایش داده می‌شود؛ آن را ذخیره کنید."}
```
WHMCS باید `secret_key` را فقط به مشتری نشان دهد و جایی ذخیره نکند.

**گزارش ماه (`/storage/usage`):**
```json
{
  "domain": "example.com", "external_id": "123", "month": "2026-09",
  "complete": true, "hours_in_month": 720, "hours_elapsed": 720,
  "storage_gb": 50,
  "byte_hours": 7730941132800, "gb_hours": 7200.0, "gb_month": 10.0, "peak_gb": 12.5,
  "buckets": [{"bucket": "cdn-k3m9q2xa-assets", "name": "assets", "deleted": false,
               "byte_hours": 7730941132800, "gb_hours": 7200.0, "peak_gb": 12.5, "samples": 720}]
}
```
* `gb_hours` = مجموع نمونه‌های ساعتی (بایت × ۱ ساعت) ÷ 1024³.
* `gb_month` = `gb_hours ÷ hours_in_month` = میانگین حجم ذخیره‌شده در کل ماه؛ قیمت «هر GB-ماه» روی همین اعمال
  می‌شود. برای فاکتور پایان ماه، ماه قبل را با `complete: true` بخوانید.
* مصرف باکت حذف‌شده تا پایان همان ماه در گزارش می‌ماند (`"deleted": true`).
* اگر کنترلر چند ساعت خاموش باشد، ساعت‌های جاافتاده (حداکثر ۷۲ ساعت) با **کمترین** مقدار قبل و بعد پر می‌شوند تا
  هرگز بیشتر از واقعیت صورتحساب نشود.

**صفحهٔ مشتری «فضای ذخیره‌سازی»** (بعداً در WHMCS): نمایش endpoint، region، فهرست باکت‌ها با مصرف و سهمیه،
فرم ساخت باکت، دکمهٔ حذف (فقط خالی) و «کلید جدید»، و نمونهٔ تنظیم:
```sh
aws configure set aws_access_key_id PCDN...; aws configure set aws_secret_access_key ...
aws --endpoint-url https://s3.pasargadmizban.com s3 cp ./logo.png s3://cdn-k3m9q2xa-assets/img/logo.png
# rclone: type=s3, provider=Minio, endpoint=https://s3.pasargadmizban.com, force_path_style=true
```
آدرس‌دهی باید **path-style** باشد (`https://endpoint/<bucket>/<key>`).

---

## ۵. باکت به‌عنوان مبدأ CDN

رکورد پروکسی‌شده با فیلد `storage` (نام کوتاه باکت همان سایت):

```http
POST /api/v1/sites/example.com/records
{"name": "cdn", "type": "CNAME", "content": "", "proxied": true, "storage": "assets"}
```
* `content` خالی ← یک CNAME به میزبان endpoint ذخیره می‌شود (فقط نمایشی؛ نام پروکسی‌شده همیشه با IP لبه‌ها
  پاسخ می‌گیرد). برای ریشه (`@`) که MX/TXT هم دارد، `type: "A"` با یک IP عمومی بدهید (مبدأ همچنان باکت است).
* فقط برای رکورد پروکسی‌شده؛ همراه `pool` مجاز نیست؛ باکت باید متعلق به همان سایت باشد؛ پلن باید `storage_gb > 0`
  داشته باشد. `GET records` فیلد `"storage": "assets"` را برمی‌گرداند. همین برای API مشتری (`/capi/v1`) هم کار می‌کند.
* در استخرها (pools) پشتیبانی نمی‌شود: upstream یک استخر یک Host مشترک دارد و هر مبدأ storage میزبان/مسیر خودش
  را لازم دارد؛ استخر تک‌عضوی storage هم معادل همین رکورد است.
* تا وقتی رکوردی از باکت استفاده می‌کند حذف باکت ۴۰۹ می‌دهد.

**بلوک config لبه** (`sites[].hosts[].origin`):
```json
{"storage": {
  "host": "s3.pasargadmizban.com", "port": 443, "tls": true,
  "host_header": "s3.pasargadmizban.com",
  "bucket": "cdn-k3m9q2xa-assets", "path_prefix": "/cdn-k3m9q2xa-assets",
  "referer": "<توکن ۴۸ کاراکتری باکت>"
}}
```
کاری که لبه باید بکند (در `edge/`): اتصال `https://host:port` با SNI و بررسی گواهی برای `host`، هدر
`Host: host_header`، URI = `path_prefix` + مسیر درخواست (بدون query string)، `Referer: referer` (جایگزین Referer
بازدیدکننده)، حذف `Authorization`/`Cookie`/`X-Amz-*` بازدیدکننده، فقط GET/HEAD. سایر تنظیمات سایت (کش، WAF، ...)
مثل هر مبدأ دیگر. لبه‌های قدیمی‌تر این شکل را نمی‌شناسند و فقط همان میزبان را نادیده می‌گیرند.

---

## ۶. امنیت (خلاصه)

* root MinIO فقط در `.env` سرور ذخیره‌سازی؛ کنترلر کاربر محدود `pcdn-controller` دارد.
* `/minio/admin/*` و متریک‌ها فقط از `ADMIN_ALLOW_IPS` (Caddy پاسخ 403 به بقیه).
* کنسول وب MinIO خاموش است (`MINIO_BROWSER=off`).
* رمز مشتری فقط یک بار در پاسخ؛ هرگز در GET، audit log (فقط نام باکت)، لاگ یا config لبه. config لبه فقط توکن
  Referer باکت را دارد.
* کلید مشتری نمی‌تواند policy باکت را عوض کند (پس نمی‌تواند باکت را عمومی کند)، باکت بسازد/حذف کند یا به باکت دیگری
  برسد.
* حذف سایت: همهٔ کلیدهای مشتری باطل، policy مبدأ برداشته و باکت‌های خالی حذف می‌شوند؛ باکت‌های پر **حذف نمی‌شوند**
  و هشدار `storage_orphans:<دامنه>` باز می‌شود. پس از مهلت نگهداری:
  `docker compose --profile tools run --rm mc -c "mc rb --force local/cdn-xxxxxxxx-name"`.

---

## ۷. پشتیبان‌گیری

پشتیبان کنترلر (`BACKUP_*`) شامل جدول باکت‌ها و مصرف است، **نه** داده‌های داخل MinIO. برای داده‌ها:

1. **کپی به S3 دیگر (پیشنهادی):** یک سرور/سرویس S3 دیگر (مثلاً ArvanCloud یا MinIO دوم در دیتاسنتر دیگر) و کران روزانه:
   ```sh
   docker compose --profile tools run --rm -e MC_HOST_backup='https://AK:SK@backup.example.com' mc \
     -c "mc mirror --overwrite --remove --preserve local/ backup/pcdn-storage-mirror/"
   ```
   (`--remove` فایل‌های حذف‌شده را در مقصد هم حذف می‌کند؛ اگر نسخه‌های قبلی را می‌خواهید آن را بردارید و روی مقصد
   versioning/lifecycle تنظیم کنید.)
2. **Site replication / bucket replication MinIO** برای کپی تقریباً لحظه‌ای به MinIO دوم (`mc admin replicate add`).
3. **پیکربندی IAM:** `mc admin cluster iam export local` (کاربر کنترلر، policyها و service accountها) را بعد از هر
   تغییر مهم بگیرید و رمزشده بیرون از سرور نگه دارید. service accountهای مشتری‌ها هم در همین خروجی هستند.
4. **بازیابی:** MinIO جدید با همان `MINIO_ROOT_*` و `MINIO_REGION`، `mc admin cluster iam import`، سپس
   `mc mirror backup/... local/`. تا وقتی نام باکت‌ها و service accountها یکی باشد، کنترلر بدون تغییر کار می‌کند؛
   کار ساعتی policy مبدأ و سهمیه‌ها را دوباره اعمال می‌کند.

دیسک‌ها: در حالت erasure، دیسک خراب را با دیسک هم‌اندازه عوض کنید (همان mount point)، MinIO خودکار heal می‌کند
(`mc admin heal -r local` برای بررسی). در حالت تک‌گره، RAID زیرین تنها حفاظت سخت‌افزاری است.

---

## ۸. ارتقا

* نسخهٔ MinIO در `.env` (`MINIO_IMAGE`) پین شده است. از اواخر ۲۰۲۵ ایمیج/باینری رسمی جامعه برای همهٔ نسخه‌ها منتشر
  نمی‌شود: پیش از ارتقا advisoryهای امنیتی MinIO را بررسی کنید و در صورت نیاز از سورس بسازید
  (`go install github.com/minio/minio@<commit>` با Go نسخهٔ مورد نیاز) و ایمیج داخلی خودتان را بسازید.
* روند: پشتیبان (بخش ۷) ← `MINIO_IMAGE` جدید در `.env` ← `docker compose pull minio && docker compose up -d minio`.
  تک‌گره چند ثانیه قطعی دارد (لبه‌ها از کش سرو می‌کنند؛ آپلودها باید دوباره تلاش شوند). ارتقا به عقب (downgrade)
  پشتیبانی نمی‌شود؛ پیش از ارتقا پشتیبان بگیرید.
* Caddy: `docker compose pull caddy && docker compose up -d caddy` (گواهی‌ها در volume `caddy-data` می‌مانند).
* بعد از ارتقا: `curl -fsS https://<domain>/minio/health/live`، و در کنترلر `GET /api/v1/sites/<d>/storage` باید
  `"usage_stale": false` بدهد.

---

## ۹. عیب‌یابی

| نشانه | بررسی |
|---|---|
| 503 «پیکربندی نشده» | `STORAGE_ENDPOINT`/`STORAGE_ADMIN_*` در `.env` کنترلر؛ endpoint باید `https://` باشد. |
| 502 با `AccessDenied` | policy کنترلر اعمال نشده یا پیشوند با `cdn-*` نمی‌خواند (`./bootstrap.sh`)؛ IP کنترلر در `ADMIN_ALLOW_IPS`. |
| 502 با `SignatureDoesNotMatch` | رمز اشتباه یا ساعت سرورها هم‌زمان نیست (NTP)؛ `STORAGE_REGION` ≠ `MINIO_REGION`. |
| هشدار `storage_usage` | کنترلر datausageinfo را نمی‌خواند؛ هر دقیقه دوباره تلاش می‌کند. |
| هشدار `storage_quota:<دامنه>` | مصرف سایت از `storage_gb` بیشتر است؛ نوشتن متوقف شده تا مشتری فایل حذف یا پلن را ارتقا دهد. |
| لبه 403 از مبدأ | policy باکت برداشته شده (کار ساعتی دوباره اعمال می‌کند) یا لبه هدر Referer را نمی‌فرستد. |

---

## ۱۰. محدودیت‌ها

* سهمیه تقریبی است: MinIO مصرف را با scanner (چند دقیقه تأخیر) می‌سنجد و سهمیهٔ سایت بین باکت‌ها هر ساعت/هر تغییر
  دوباره تقسیم می‌شود؛ بین دو محاسبه، چند باکت هم‌زمان می‌توانند تا مجموعاً حداکثر حدود دو برابر فضای باقیمانده بنویسند.
  با `storage_gb = 0` یک باکت خالی هنوز ۱ بایت جا دارد (MinIO سهمیهٔ صفر را «بدون سهمیه» می‌خواند).
* تعلیق سایت (suspend) دسترسی S3 مشتری را قطع نمی‌کند (غیرفعال کردن service account به `admin:UpdateServiceAccount`
  نیاز دارد که عمداً داده نشده)؛ لبه‌ها برای سایت معلق صفحهٔ تعلیق نشان می‌دهند.
* مبدأ storage فقط برای رکوردها، نه استخرها و نه مسیرهای تونل.
* versioning، lifecycle، CORS و دامنهٔ اختصاصی برای خود S3 در این نسخه نیست؛ برای دامنهٔ مشتری از رکورد CDN استفاده کنید.
* فقط یک deployment MinIO (یک endpoint) برای کل پلتفرم.
