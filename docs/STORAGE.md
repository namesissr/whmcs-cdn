# فضای ذخیره‌سازی ابری (Object Storage) — SPEC §16.8

این سند راه‌اندازی، تنظیم، API، صورتحساب، پشتیبان‌گیری و ارتقای سرویس «فضای ذخیره‌سازی» را توضیح می‌دهد.
سرویس روی **SeaweedFS** (سازگار با S3) اجرا می‌شود، جلوی آن **Caddy** با گواهی خودکار Let's Encrypt قرار دارد و
کنترلر برای هر مشتری باکت، کلید دسترسی محدود به همان باکت، سهمیه (quota) و گزارش مصرف ساعتی می‌سازد. هر باکت
می‌تواند مستقیماً **مبدأ (origin) CDN** یک رکورد باشد.

> **چرا SeaweedFS و نه MinIO:** نسخهٔ جامعهٔ MinIO در ۱۳ فوریهٔ ۲۰۲۶ آرشیو شد و ایمیج‌هایش در سپتامبر ۲۰۲۶ از
> Docker Hub (و بعد از آن کشیدن ناشناس از quay.io) برداشته شد، پس بستهٔ قدیمی دیگر بالا نمی‌آید. SeaweedFS با
> لایسنس Apache-2.0، توسعهٔ فعال و مسیر رشد (چند سرور داده، erasure coding، tiering) جایگزین شد. اگر سروری دارید
> که همچنان MinIO یا AIStor اجرا می‌کند، با `STORAGE_BACKEND=minio` بدون تغییر کار می‌کند (بخش ۱۱).

```
 مشتری (aws-cli, rclone, SDK) ──HTTPS/S3──┐
                                          ▼
 لبه‌ها (edge) ──HTTPS + Referer توکن──▶ Caddy (TLS) ──▶ SeaweedFS (master + volume + filer + S3)
                                          ▲
 کنترلر ──HTTPS: S3 + IAM + متریک مصرف (فقط از IP کنترلر)
```

---

## ۱. طراحی و دلایل انتخاب

| موضوع | انتخاب | چرا |
|---|---|---|
| مدیریت سرور ذخیره‌سازی | پیاده‌سازی کوچک داخل کنترلر (`app/seaweed_client.py` روی `app/minio_client.py`): امضای SigV4 برای S3 و برای IAM | فقط کتابخانهٔ استاندارد و `httpx`/`cryptography` که از قبل وابستگی‌اند. بدون CLI در ایمیج کنترلر، بدون subprocess و بدون قرار گرفتن کلید روی خط فرمان. مسیر دادهٔ S3 بین دو backend مشترک است؛ فقط سه تماس سمت اپراتور (سهمیه، کلید مشتری، مصرف) تفاوت دارد. کل جریان روی SeaweedFS واقعی آزموده می‌شود (`tests/test_storage_seaweed.py::test_real_seaweed`). |
| کلید مشتری | یک **کاربر IAM** هم‌نام همان access key، با **policy درون‌خطی محدود به همان باکت** و همان یک جفت کلیدی که کنترلر ساخته | SeaweedFS policy را به مجموعهٔ اقدام‌های همان هویت ترجمه و اعمال می‌کند؛ کلید مشتری فقط به اشیای باکت خودش می‌رسد. کلیدها در filer ذخیره می‌شوند، پس ری‌استارت سرور آن‌ها را از دست نمی‌دهد و هیچ‌وقت در فایلی روی دیسک نیستند. دو نام اقدام چندبخشی (`ListBucketMultipartUploads`/`ListMultipartUploadParts`) در این سرور `ListMultipartUploads`/`ListParts` هستند و کلاینت همان لحظه ترجمه می‌کند. |
| هویت کنترلر | کاربر `pcdn-controller` با policy: `s3:*` روی `cdn-*` به‌اضافهٔ همان چند تماس IAM لازم برای ساخت/حذف کلید مشتری | بدون Admin، بدون دسترسی به باکت‌های دیگر (مثلاً پشتیبان‌ها) و بدون دسترسی به پیکربندی خود سرور. API مدیریتی و متریک‌ها فقط از IP کنترلر قابل دسترسی‌اند (Caddy). |
| مصرف | شمارندهٔ Prometheus خود gateway (`SeaweedFS_s3_bucket_size_bytes` / `..._bucket_object_count`) که هر دقیقه بازمحاسبه می‌شود | همان دقت و همان تأخیرِ scanner مینیو، بدون هیچ مجوز admin؛ مسیرش در Caddy فقط برای IP کنترلر باز است. |
| چرخش کلید | ساخت service account جدید، سپس حذف قبلی | `UpdateServiceAccount` به مجوز سراسری نیاز دارد؛ با این روش لازم نیست. Access Key هم عوض می‌شود. |
| نام باکت | `STORAGE_BUCKET_PREFIX` + برچسب تصادفی ۸ حرفی هر سایت + `-` + نام مشتری، مثل `cdn-k3m9q2xa-assets` | نام باکت روی سرور ذخیره‌سازی سراسری است؛ پیشوند جلوی تداخل بین مشتری‌ها را می‌گیرد و policy کنترلر را به `cdn-*` محدود می‌کند. برچسب تصادفی (نه id سایت) نمی‌گذارد سایت جدیدی که id یک سایت حذف‌شده را گرفته به باکت باقیمانده برسد. کنترلر هرگز باکتی را که خودش همان لحظه نساخته «تصاحب» نمی‌کند (۴۰۹). |
| سهمیه | سهمیهٔ سخت هر باکت = حجم خود باکت + فضای باقیماندهٔ سایت (`storage_gb` پلن منهای مجموع مصرف)، حداقل ۱ بایت | سهمیه در هر دو backend برای هر باکت جداگانه است؛ این فرمول سقف کل سایت را تقریب می‌زند. هر ساعت، هنگام ساخت/حذف باکت و هنگام تغییر پلن دوباره محاسبه می‌شود. علاوه بر آن ساخت باکت جدید وقتی سایت پر است رد می‌شود و برای اپراتور هشدار `storage_quota:<دامنه>` باز می‌شود. |
| مبدأ CDN | policy باکت: `s3:GetObject` ناشناس **فقط** با هدر `Referer` برابر توکن تصادفی همان باکت | باکت عمومی نمی‌شود؛ فقط لبه‌ها توکن را دارند. توکن فقط همان چیزی را می‌دهد که CDN به‌هرحال منتشر می‌کند (GET فایل‌های همان باکت، بدون فهرست‌گیری). کلید و رمز مشتری هرگز به لبه نمی‌رود. |

---

## ۲. راه‌اندازی سرور ذخیره‌سازی

یک سرور جدا (Ubuntu 24.04 + Docker، با پلاگین `docker compose`) پیشنهاد می‌شود. پوشهٔ `deploy/storage/` را روی آن
کپی کنید (مثلاً `tar -czf - deploy/storage | ssh root@s3 'tar -xzf -'`).

1. **DNS:** رکورد A/AAAA برای دامنهٔ S3 (مثلاً `s3.pasargadmizban.com`) به IP همین سرور. این رکورد را
   پروکسی (CDN) نکنید. پیش از ادامه با `dig +short <دامنه>` تأیید کنید.
2. **فایروال:** پورت‌های 80 و 443 باز. هیچ پورت دیگری منتشر نمی‌شود (فقط Caddy در شبکهٔ داخلی Docker به gateway
   وصل است).
3. **دیسک:** یک مسیر داده (`SEAWEED_DATA_DIR`). فقط **یک نسخه** از هر شیء نگه داشته می‌شود؛ زیر آن RAID1/RAID10
   بگذارید و حتماً پشتیبان بگیرید (بخش ۷). برای رشد بعدی، سرور دوم را با یک `weed volume` که به همین master وصل
   می‌شود اضافه کنید.
4. **تنظیمات:**
   ```sh
   cd deploy/storage
   cp .env.example .env && chmod 600 .env
   # STORAGE_DOMAIN, ACME_EMAIL
   # ADMIN_ALLOW_IPS = IP سرور(های) کنترلر، مثلاً "203.0.113.10/32 203.0.113.11/32"
   # SEAWEED_DATA_DIR, VOLUME_SIZE_MB (پیش‌فرض ۱۰۲۴ مگابایت)
   mkdir -p /srv/seaweedfs/data
   ```
   `VOLUME_SIZE_MB` مهم است: هر باکت یک collection جدا با volumeهای خودش است، پس اندازهٔ volume یعنی دانه‌بندی
   تخصیص دیسک. ۱ گیگابایت برای باکت‌های مشتری مناسب است؛ اگر چند باکت بسیار بزرگ دارید آن را بالا ببرید. تعداد
   volume سقف ندارد (`-volume.max=0`، یعنی فضای آزاد تقسیم بر این اندازه) — پیش‌فرض خود SeaweedFS ۸ volume است که
   کل سرور را روی چند باکت متوقف می‌کرد (`No writable volumes and no free volumes left`).
5. **اجرا:**
   ```sh
   docker compose up -d
   docker compose ps                    # seaweedfs و caddy باید healthy شوند
   docker compose logs --tail 30 caddy  # صدور گواهی
   curl -fsS https://s3.pasargadmizban.com/
   ```
   (پاسخ 403 به یک درخواست بدون امضا یعنی gateway بالا است و درست رد می‌کند.)
6. **هویت‌ها:**
   ```sh
   ./bootstrap.sh
   ```
   این اسکریپت `s3.json` را می‌سازد (هویت ادمین اضطراری `pcdn-admin`، هویت محدود `pcdn-controller`، و هویت
   `anonymous` بی‌مجوز که فقط policy باکت می‌تواند به آن اجازهٔ GET بدهد)، سرویس را ری‌استارت می‌کند و **یک بار**
   این دو مقدار را چاپ می‌کند:
   ```
   STORAGE_ADMIN_ACCESS_KEY=...
   STORAGE_ADMIN_SECRET_KEY=...
   ```
   اجرای دوباره چیزی را عوض نمی‌کند؛ `--rotate` کلید تازه برای کنترلر می‌سازد (بعد `.env` کنترلر را به‌روز و
   کنترلر را ری‌استارت کنید). برخلاف مینیو، این مقادیر در `s3.json` روی همین سرور می‌مانند، پس اگر گم شدند
   می‌توانید از همان فایل بخوانید — و همین فایل را باید محرمانه نگه دارید (0600).

کلیدهای مشتری‌ها در `s3.json` نیستند: کنترلر آن‌ها را روی IAM می‌سازد و سرور در filer نگه می‌دارد.

### policy دقیق هویت کنترلر (`deploy/storage/bootstrap.sh`)

```json
{"Version": "2012-10-17", "Statement": [
  {"Sid": "PcdnCustomerBucketsOnly", "Effect": "Allow", "Action": ["s3:*"],
   "Resource": ["arn:aws:s3:::cdn-*", "arn:aws:s3:::cdn-*/*"]},
  {"Sid": "PcdnCustomerKeys", "Effect": "Allow", "Resource": ["*"],
   "Action": ["iam:CreateUser", "iam:DeleteUser", "iam:GetUser", "iam:PutUserPolicy",
              "iam:DeleteUserPolicy", "iam:GetUserPolicy", "iam:CreateAccessKey",
              "iam:DeleteAccessKey", "iam:ListAccessKeys"]}]}
```

* `s3:*` فقط روی باکت‌های `cdn-*`: ساخت/حذف باکت، policy باکت، سهمیه و همهٔ عملیات دادهٔ همان باکت‌ها. باکت‌های
  دیگر سرور (مثلاً پشتیبان‌ها) برای کنترلر قابل دسترس نیستند — آزمون `test_real_seaweed` این را تأیید می‌کند.
* گرنت‌های `iam:` فقط همان چند تماسی هستند که ساخت و حذف کلید مشتری لازم دارد؛ `Admin` داده نشده، پس کنترلر
  نمی‌تواند هویت اپراتور بسازد یا پیکربندی سرور را عوض کند.
* اگر `STORAGE_BUCKET_PREFIX` را عوض کنید، همان مقدار را در `.env` سرور ذخیره‌سازی بگذارید و `./bootstrap.sh
  --rotate` را دوباره اجرا کنید تا policy با پیشوند تازه نوشته شود.

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
| `STORAGE_BACKEND` | `seaweedfs` (نصب تازه) یا `minio` (سروری که همچنان MinIO/AIStor است). پیش‌فرض `minio` تا نصب‌های موجود با ارتقا عوض نشوند؛ در `deploy/storage` تازه حتماً `seaweedfs` بگذارید. |
| `STORAGE_ENDPOINT` | آدرس https که کنترلر برای S3 و IAM استفاده می‌کند. خالی = سرویس خاموش (مسیرهای storage پاسخ 503). |
| `STORAGE_PUBLIC_ENDPOINT` | آدرسی که به مشتری نشان داده و در config لبه‌ها گذاشته می‌شود (پیش‌فرض همان `STORAGE_ENDPOINT`). |
| `STORAGE_ADMIN_ACCESS_KEY` / `STORAGE_ADMIN_SECRET_KEY` | خروجی `bootstrap.sh` (نام قدیمی `STORAGE_ADMIN_SECRET` هم پذیرفته می‌شود). هرگز root. |
| `STORAGE_METRICS_PATH` | از کجا مصرف هر باکت خوانده شود: مسیری روی `STORAGE_ENDPOINT` که سرور ذخیره‌سازی به پورت متریک gateway پروکسی می‌کند (پیش‌فرض `/__pcdn/storage-metrics`، همان چیزی که `deploy/storage/Caddyfile` فقط برای IP کنترلر باز می‌کند) یا یک URL کامل از آن پورت در شبکهٔ خصوصی. فقط backend سیدفس. |
| `STORAGE_REGION` | منطقهٔ SigV4؛ پیش‌فرض `us-east-1` و برای سیدفس همین کافی است (برای MinIO باید با `MINIO_REGION` یکی باشد). |
| `STORAGE_BUCKET_PREFIX` | پیش‌فرض `cdn-`؛ باید با Resource در policy کنترلر بخواند. |
| `STORAGE_MAX_BUCKETS` | سقف تعداد باکت هر سایت (پیش‌فرض ۱۰، حداکثر ۱۰۰). |
| `STORAGE_INSECURE_HTTP` | فقط برای سرور ذخیره‌سازی در شبکهٔ خصوصی بدون TLS؛ در غیر این صورت `http://` پذیرفته نمی‌شود. |

`STORAGE_ENDPOINT` تنظیم اپراتور و مورد اعتماد است؛ هیچ ورودی مشتری میزبان (host) را انتخاب نمی‌کند — نام باکت
فقط `[a-z0-9-]` است و همیشه با پیشوند ساخته می‌شود. درخواست‌های کنترلر به سرور ذخیره‌سازی از proxy محیط عبور نمی‌کنند و
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
تعداد باکت / سایت پر، 404 باکت یا سایت ناموجود، 409 نام تکراری یا نام گرفته‌شده روی سرور ذخیره‌سازی، 502 خطای سرور ذخیره‌سازی (هر چه
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
مصرف از شمارندهٔ خود سرور ذخیره‌سازی می‌آید (دقیقه‌ای به‌روز می‌شود، نه لحظه‌ای). در هر GET تازه خوانده می‌شود؛ اگر سرور
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

* هویت ادمین اضطراری (`pcdn-admin`) فقط در `s3.json` سرور ذخیره‌سازی؛ کنترلر هویت محدود `pcdn-controller` دارد.
* مسیر متریک مصرف و IAM (POST به `/`) فقط از `ADMIN_ALLOW_IPS` (Caddy پاسخ 403 به بقیه). ترافیک S3 عمومی است.
* هیچ کنسول وب یا پورت مدیریتی منتشر نمی‌شود؛ listenerهای Iceberg و Lance خاموش‌اند.
* رمز مشتری فقط یک بار در پاسخ؛ هرگز در GET، audit log (فقط نام باکت)، لاگ یا config لبه. config لبه فقط توکن
  Referer باکت را دارد.
* کلید مشتری نمی‌تواند policy باکت را عوض کند (پس نمی‌تواند باکت را عمومی کند)، باکت بسازد/حذف کند یا به باکت دیگری
  برسد.
* حذف سایت: همهٔ کلیدهای مشتری باطل، policy مبدأ برداشته و باکت‌های خالی حذف می‌شوند؛ باکت‌های پر **حذف نمی‌شوند**
  و هشدار `storage_orphans:<دامنه>` باز می‌شود. پس از مهلت نگهداری، با هویت ادمین اضطراری یا هر کلاینت S3:
  `aws --endpoint-url https://<دامنه> s3 rb --force s3://cdn-xxxxxxxx-name`.

---

## ۷. پشتیبان‌گیری

پشتیبان کنترلر (`BACKUP_*`) شامل جدول باکت‌ها و مصرف است، **نه** داده‌های داخل سرور ذخیره‌سازی. برای داده‌ها:

1. **کپی به S3 دیگر (پیشنهادی):** یک سرور/سرویس S3 دیگر (مثلاً ArvanCloud یا سیدفس دوم در دیتاسنتر دیگر) و کران
   روزانه با هر کلاینت S3؛ با هویت ادمین اضطراری که به همهٔ باکت‌ها دسترسی دارد:
   ```sh
   aws --endpoint-url https://s3.example.com s3 sync s3://cdn-xxxxxxxx-assets \
       s3://backup-bucket/cdn-xxxxxxxx-assets --delete
   ```
   (یا `rclone sync` که برای چند باکت راحت‌تر است.)
2. **کپی در سطح سرور:** `weed filer.backup` / `weed filer.sync` برای کپی تقریباً لحظه‌ای به سیدفس دوم
   (`docker compose exec seaweedfs weed filer.sync -a <اینجا> -b <آنجا>`).
3. **هویت‌ها:** `s3.json` (هویت‌های اپراتور) و کلیدهای مشتری که در filer زیر `/etc/iam/` هستند. هر دو را
   رمزشده بیرون از سرور نگه دارید:
   ```sh
   docker compose exec seaweedfs weed filer.copy -- /etc/iam /tmp/iam-backup   # یا filer.backup
   ```
   کلید و توکن مبدأ هر باکت در دیتابیس کنترلر هم هست، پس پشتیبان کنترلر + داده‌ها برای بازیابی کافی است.
4. **بازیابی:** سرور تازه با همان `.env`، `s3.json` بازگردانده‌شده، سپس همگام‌سازی داده‌ها از پشتیبان. تا وقتی نام
   باکت‌ها یکی باشد کنترلر بدون تغییر کار می‌کند؛ کار ساعتی policy مبدأ و سهمیه‌ها را دوباره اعمال می‌کند. اگر
   کلیدهای مشتری از دست رفته باشند، برای هر باکت یک بار `POST .../rotate-key` بزنید (کلید تازه در پنل مشتری
   دیده می‌شود).

دیسک: در حالت تک‌گره، RAID زیرین تنها حفاظت سخت‌افزاری است. برای افزونگی واقعی یک volume server دوم روی سرور
دیگر اضافه کنید و replication را روشن کنید (`-defaultReplication=001`).

---

## ۸. ارتقا

* نسخهٔ سرور در `.env` (`SEAWEED_IMAGE`) پین شده است؛ نسخهٔ آزموده‌شدهٔ این انتشار در `.env.example` است.
* روند: پشتیبان (بخش ۷) ← `SEAWEED_IMAGE` جدید در `.env` ← `docker compose pull seaweedfs && docker compose up -d
  seaweedfs`. تک‌گره چند ثانیه قطعی دارد (لبه‌ها از کش سرو می‌کنند؛ آپلودها باید دوباره تلاش شوند).
* Caddy: `docker compose pull caddy && docker compose up -d caddy` (گواهی‌ها در volume `caddy-data` می‌مانند).
* بعد از ارتقا: `curl -fsS https://<domain>/` باید 403 بدهد (gateway بالا و بدون امضا رد می‌کند)، و در کنترلر
  `GET /api/v1/sites/<d>/storage` باید `"usage_stale": false` بدهد. اولین مقدار مصرف تا یک دقیقه بعد از
  بالا آمدن سرور صفر است (شمارنده‌ها دقیقه‌ای بازمحاسبه می‌شوند).

---

## ۹. عیب‌یابی

| نشانه | بررسی |
|---|---|
| 503 «پیکربندی نشده» | `STORAGE_ENDPOINT`/`STORAGE_ADMIN_*` در `.env` کنترلر؛ endpoint باید `https://` باشد. |
| 502 با `AccessDenied` | policy کنترلر اعمال نشده یا پیشوند با `cdn-*` نمی‌خواند (`./bootstrap.sh`)؛ IP کنترلر در `ADMIN_ALLOW_IPS`. |
| 502 با `SignatureDoesNotMatch` | رمز اشتباه یا ساعت سرورها هم‌زمان نیست (NTP). |
| ساخت کلید مشتری با 403 روی IAM | سرور با `-s3.iam.readOnly=false` اجرا نشده (پیش‌فرض خودش `true` است و هر نوشتن IAM را 403 می‌کند)، یا POST به `/` از IP کنترلر نیست. |
| آپلود با 500 و «No writable volumes» | سقف تعداد volume پر شده: `-volume.max=0` و `VOLUME_SIZE_MB` کوچک‌تر (هر باکت collection خودش را دارد). |
| هشدار `storage_usage` | کنترلر مسیر متریک را نمی‌خواند (`STORAGE_METRICS_PATH`، دسترسی IP در Caddy)؛ هر دقیقه دوباره تلاش می‌کند. |
| هشدار `storage_quota:<دامنه>` | مصرف سایت از `storage_gb` بیشتر است؛ نوشتن متوقف شده تا مشتری فایل حذف یا پلن را ارتقا دهد. |
| لبه 403 از مبدأ | policy باکت برداشته شده (کار ساعتی دوباره اعمال می‌کند) یا لبه هدر Referer را نمی‌فرستد. |

---

## ۱۰. محدودیت‌ها

* سهمیه تقریبی است: سرور مصرف را دقیقه‌ای بازمحاسبه می‌کند (نه در لحظهٔ هر نوشتن) و سهمیهٔ سایت بین باکت‌ها هر ساعت/هر تغییر
  دوباره تقسیم می‌شود؛ بین دو محاسبه، چند باکت هم‌زمان می‌توانند تا مجموعاً حداکثر حدود دو برابر فضای باقیمانده بنویسند.
  با `storage_gb = 0` یک باکت خالی هنوز ۱ بایت جا دارد (سهمیهٔ صفر در هر دو backend «بدون سهمیه» خوانده می‌شود).
* تعلیق سایت (suspend) دسترسی S3 مشتری را قطع نمی‌کند؛ لبه‌ها برای سایت معلق صفحهٔ تعلیق نشان می‌دهند.
* مبدأ storage فقط برای رکوردها، نه استخرها و نه مسیرهای تونل.
* versioning، lifecycle، CORS و دامنهٔ اختصاصی برای خود S3 در این نسخه نیست؛ برای دامنهٔ مشتری از رکورد CDN استفاده کنید.
* فقط یک سرور ذخیره‌سازی (یک endpoint) برای کل پلتفرم.
* باکت‌ها path-style آدرس می‌شوند (`https://<دامنه>/<باکت>/<کلید>`)؛ virtual-host style گواهی wildcard لازم دارد
  و روشن نیست. کلاینت‌هایی که پیش‌فرض virtual-host هستند را روی path-style بگذارید (مثلاً در aws-cli:
  `s3.addressing_style = path`).

---

## ۱۱. سرور قدیمی MinIO / AIStor

اگر سروری دارید که همچنان MinIO (یا جانشین تجاری آن AIStor) اجرا می‌کند، همان بسته زیر `deploy/storage/minio/`
نگه داشته شده و کنترلر با `STORAGE_BACKEND=minio` دقیقاً مثل قبل کار می‌کند: کلید مشتری service account با policy
درون‌خطی است، سهمیه و مصرف از `‎/minio/admin/v3` خوانده می‌شوند و `app/minio_client.py` دست‌نخورده است.

نکته‌ها:

* ایمیج `minio/minio` از Docker Hub حذف شده و کشیدن ناشناس از quay.io هم بسته است؛ پس آن compose فقط روی سروری
  کار می‌کند که ایمیج را از قبل دارد یا به رجیستری خودتان دسترسی دارد.
* نسخهٔ آخر جامعه دیگر وصلهٔ امنیتی نمی‌گیرد. برای سروری که داده دارد، مسیر مهاجرت: یک سرور سیدفس تازه با
  `deploy/storage` بالا بیاورید، داده‌ها را باکت‌به‌باکت کپی کنید (`rclone sync minio:cdn-… seaweed:cdn-…`)، برای هر
  باکت یک بار `rotate-key` بزنید تا کلید تازه روی سرور تازه ساخته شود، بعد `STORAGE_ENDPOINT` و
  `STORAGE_BACKEND=seaweedfs` را در `.env` کنترلر عوض کنید. تا پایان کپی، سرویس روی سرور قدیمی سالم می‌ماند.
* گزینهٔ AIStor Free فقط تک‌گره مجاز است و شرایط لایسنس تجاری دارد؛ بررسی حقوقی‌اش با خودتان است.
