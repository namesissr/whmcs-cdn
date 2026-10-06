# Terraform provider برای CDN پاسارگاد (`pcdn`)

این سند راهنمای مشتری برای مدیریت یک سرویس CDN با Terraform است (SPEC §14.3.6). provider با
**کلید API مشتری** (همان کلید `/capi/v1`، SPEC §10.1) کار می‌کند و فقط به همان یک دامنه دسترسی دارد؛
برای همین هیچ منبعی نام دامنه نمی‌گیرد. کد provider در پوشهٔ
[`terraform-provider-pcdn/`](../terraform-provider-pcdn/) است و نمونه‌ها در
[`terraform-provider-pcdn/examples/`](../terraform-provider-pcdn/examples/).

## فهرست

- [چه چیزهایی را مدیریت می‌کند](#چه-چیزهایی-را-مدیریت-میکند)
- [۱. ساخت کلید API در ناحیهٔ کاربری WHMCS](#۱-ساخت-کلید-api-در-ناحیهٔ-کاربری-whmcs)
- [۲. ساخت و نصب provider](#۲-ساخت-و-نصب-provider)
- [۳. پیکربندی provider](#۳-پیکربندی-provider)
- [۴. نمونه‌ها](#۴-نمونهها)
- [۵. وارد کردن (import) منابع موجود](#۵-وارد-کردن-import-منابع-موجود)
- [۶. محدودیت‌ها و رفتارهای مهم](#۶-محدودیتها-و-رفتارهای-مهم)
- [۷. عیب‌یابی](#۷-عیبیابی)
- [۸. افزودن نود با Terraform (ویژهٔ اپراتور)](#۸-افزودن-نود-با-terraform-ویژهٔ-اپراتور)

> **دو چیز جدا:** بخش‌های ۱ تا ۷ دربارهٔ **provider مشتری** (`terraform-provider-pcdn/`، منابع یک سایت) است.
> ساختن **نودهای لبه** روی ابر توسط اپراتور با پوشهٔ [`terraform/`](../terraform/) و ابزار `pcdn-provision`
> انجام می‌شود — [بخش ۸](#۸-افزودن-نود-با-terraform-ویژهٔ-اپراتور).

## چه چیزهایی را مدیریت می‌کند

| نوع | نام | API | دسترسی لازم کلید |
|-----|-----|-----|------------------|
| منبع | `pcdn_record` | `/capi/v1/records` | `dns` |
| منبع | `pcdn_config_section` | `/capi/v1/config/{section}` | `dns` |
| منبع | `pcdn_purge` | `POST /capi/v1/purge` | `purge` |
| منبع داده | `pcdn_site` | `GET /capi/v1/site` | هر دسترسی |

---

## ۱. ساخت کلید API در ناحیهٔ کاربری WHMCS

1. وارد ناحیهٔ کاربری `my.pasargadmizban.com` شوید و سرویس CDN را باز کنید.
2. از منوی برنامه، گروه «توسعه‌دهندگان» ← صفحهٔ **«API و کلیدها»** را باز کنید.
3. یک نام (مثلاً `terraform`) بدهید و دسترسی‌ها را انتخاب کنید:
   - **«DNS و تنظیمات»** (`dns`) برای `pcdn_record` و `pcdn_config_section`؛
   - **«پاکسازی کش»** (`purge`) برای `pcdn_purge`؛
   - `pcdn_site` با هر دسترسی‌ای کار می‌کند.
4. کلید (`pcdn_` + ۴۰ کاراکتر هگز) **فقط یک‌بار** نمایش داده می‌شود؛ آن را در جای امن (مثلاً مدیر
   رمز یا متغیر محیطی CI) نگه دارید. هر سرویس حداکثر ۵ کلید فعال دارد و هر کلید را می‌توانید از همان
   صفحه لغو کنید.

> کلید مدیریتی (admin key) روی `/capi/*` پذیرفته نمی‌شود و provider هم کلیدی را که با `pcdn_` شروع
> نشود رد می‌کند (بدون نمایش مقدار آن در خطا).

## ۲. ساخت و نصب provider

provider در Terraform Registry عمومی منتشر **نشده** است؛ آن را از کد بسازید (Go نسخهٔ 1.24 یا بالاتر) و
به‌صورت محلی نصب کنید. Terraform نسخهٔ 1.0 یا بالاتر لازم است (پروتکل ۶).

```bash
cd terraform-provider-pcdn
go build -ldflags "-X main.version=0.1.0" -o terraform-provider-pcdn .
```

### روش پیشنهادی: filesystem mirror

فایل اجرایی را با این ساختار مسیر کپی کنید (`linux_amd64` را با سیستم خود عوض کنید، مثلاً
`darwin_arm64` یا `windows_amd64`):

```bash
d=~/.terraform.d/plugins/registry.terraform.io/namesissr/pcdn/0.1.0/linux_amd64
mkdir -p "$d"
cp terraform-provider-pcdn "$d/terraform-provider-pcdn_v0.1.0"
```

`~/.terraform.d/plugins` یک mirror ضمنی است و به تنظیم دیگری نیاز ندارد (به شرطی که فایل
`~/.terraformrc` بلوک `provider_installation` نداشته باشد). برای مسیر دیگر، مثلاً `/opt/terraform/providers`
روی سرور CI، این را در `~/.terraformrc` بگذارید:

```hcl
provider_installation {
  filesystem_mirror {
    path    = "/opt/terraform/providers"
    include = ["registry.terraform.io/namesissr/pcdn"]
  }
  direct {
    exclude = ["registry.terraform.io/namesissr/pcdn"]
  }
}
```

سپس در پیکربندی خود:

```hcl
terraform {
  required_providers {
    pcdn = {
      source  = "namesissr/pcdn"
      version = "~> 0.1"
    }
  }
}
```

و `terraform init` را اجرا کنید (برای این provider به اینترنت نیازی نیست).

### روش توسعه: `dev_overrides`

برای آزمایش یک build تازه بدون `terraform init`:

```hcl
# ~/.terraformrc
provider_installation {
  dev_overrides {
    "namesissr/pcdn" = "/home/me/whmcs-cdn/terraform-provider-pcdn"   # پوشه‌ای که فایل اجرایی در آن است
  }
  direct {}
}
```

Terraform در این حالت هشدار «Provider development overrides are in effect» می‌دهد که طبیعی است.

## ۳. پیکربندی provider

```hcl
provider "pcdn" {
  endpoint = "https://cdn-api.pasargadmizban.com"   # یا متغیر محیطی PCDN_ENDPOINT
  api_key  = var.pcdn_api_key                       # یا متغیر محیطی PCDN_API_KEY

  timeout_seconds = 30   # اختیاری: مهلت هر درخواست HTTP (۱ تا ۶۰۰)
  max_retries     = 8    # اختیاری: تعداد تلاش دوباره (۰ تا ۲۰)
}

variable "pcdn_api_key" {
  type      = string
  sensitive = true
}
```

- `endpoint` آدرس کنترلر است؛ `/capi/v1` در انتهای آن هم پذیرفته می‌شود. فقط `https` مجاز است (به جز
  `http://localhost`، `127.0.0.1` و `[::1]` برای آزمایش). ریدایرکت‌ها دنبال نمی‌شوند.
- ساده‌ترین راه در CI: `export PCDN_ENDPOINT=... PCDN_API_KEY=...` و بلوک خالی `provider "pcdn" {}`.
- کلید فقط در هدر `Authorization` فرستاده می‌شود و هرگز در لاگ (حتی با `TF_LOG=DEBUG`) یا پیام خطا
  نمی‌آید. توجه کنید که Terraform مقدار متغیرها را در فایل state به‌صورت متن ساده نگه می‌دارد؛ state را
  محافظت کنید.

## ۴. نمونه‌ها

### رکورد DNS — `pcdn_record`

```hcl
resource "pcdn_record" "apex" {
  name    = "@"
  type    = "A"
  content = "185.1.2.3"
  proxied = true          # از طریق CDN (فقط A / AAAA / CNAME)
}

resource "pcdn_record" "www" {
  name        = "www"
  type        = "CNAME"
  content     = "example.com"
  proxied     = true
  origin_port = 8080      # پورت مبدأ برای رکورد پروکسی بدون pool
}

resource "pcdn_record" "mail" {
  type     = "MX"
  content  = "mail.example.com"
  priority = 10           # اگر ندهید برای MX/SRV همان ۱۰ است
}

resource "pcdn_record" "spf" {
  type    = "TXT"
  content = "v=spf1 mx -all"
  ttl     = 3600
}
```

ویژگی‌ها دقیقاً همان `RecordIn` کنترلر است: `type`، `content`، `name` (پیش‌فرض `@`)، `ttl` (۶۰ تا ۸۶۴۰۰،
پیش‌فرض ۳۰۰)، `priority`، `proxied`، `pool`، `origin_port`، `health_check`، `health_port` و (SPEC §16.7)
`weight`، `health_protocol` و `health_path`. تغییر هر ویژگی (حتی `type`) با `PATCH` و بدون حذف و ساخت دوباره
انجام می‌شود و شناسهٔ رکورد ثابت می‌ماند؛ provider همیشه کل رکورد (از جمله `weight` و تنظیمات probe) را
می‌فرستد تا هیچ فیلدی ناخواسته پاک نشود.

#### رکوردهای وزن‌دار / failover (SPEC §16.7)

```hcl
# دو مقصد با وزن ۷۰/۳۰؛ کنترلر هر ۶۰ ثانیه با HTTPS بررسی می‌کند و عضو ناسالم را از پاسخ DNS
# کنار می‌گذارد (هرگز همه را)
resource "pcdn_record" "app_a" {
  name            = "app"
  type            = "A"
  content         = "185.1.2.10"
  weight          = 70
  health_check    = true
  health_protocol = "https"
  health_port     = 443
  health_path     = "/healthz"   # اگر ندهید برای http/https همان "/" است
}

resource "pcdn_record" "app_b" {
  name            = "app"
  type            = "A"
  content         = "185.1.2.11"
  weight          = 30
  health_check    = true
  health_protocol = "https"
}

output "app_a_up" {
  value = pcdn_record.app_a.health.ok   # فقط‌خواندنی: ok، ms، fail، checked_at، error، advertised
}
```

- `weight` (۰ تا ۱۰۰؛ ۰ = پشتیبان) فقط برای رکوردهای A/AAAA/CNAME **بدون پروکسی**؛ چند CNAME هم‌نام فقط
  وقتی مجازند که همه وزن‌دار باشند. `health_check` روی CNAME فقط همراه `weight` معنا دارد.
- `health_protocol` (`tcp`/`http`/`https`) فقط با `health_check = true` و `health_path` فقط با `http`/`https`.
- `health` نتیجهٔ آخرین بررسی کنترلر است (بدون `health_check` خالی)؛ در هر refresh به‌روز می‌شود و هیچ‌وقت
  باعث تغییر در plan نمی‌شود.

### بخش تنظیمات — `pcdn_config_section`

```hcl
resource "pcdn_config_section" "cache" {
  section = "cache"
  config = jsonencode({
    enabled        = true
    edge_ttl       = 86400
    bypass_cookies = ["wordpress_logged_in", "PHPSESSID"]
  })
}

resource "pcdn_config_section" "firewall" {
  section = "firewall"
  config = jsonencode({
    default_action = "allow"
    rules = [{
      id         = "block-countries"
      action     = "block"
      conditions = [{ field = "country", op = "in", value = ["CN", "RU"] }]
    }]
  })
}
```

بخش‌های مجاز: `cache`، `ssl`، `waf`، `ddos`، `firewall`، `ratelimit`، `pagerules`، `pools`، `headers`،
`hotlink`، `image`، `errorpages`، `tunnel`، `transform`، `redirects`، `bots`، `logs`، `webhooks` (شکل هر بخش
در SPEC §2 و §14 آمده است). `result` (فقط‌خواندنی) نسخهٔ ذخیره‌شده در کنترلر با همهٔ مقادیر پیش‌فرض است
(بدون هیچ راز)، مثلاً `jsondecode(pcdn_config_section.cache.result).edge_ttl`.

**خروجی لاگ با کلید فقط‌نوشتنی:**

```hcl
resource "pcdn_config_section" "logs" {
  section = "logs"
  config = jsonencode({
    enabled     = true
    s3_endpoint = "https://s3.example.net"
    bucket      = "cdn-logs"
    access_key  = var.logs_access_key
    secret_key  = var.logs_secret_key    # فقط‌نوشتنی؛ کنترلر آن را برنمی‌گرداند
    sample_rate = 0.1
  })
}
```

**وب‌هوک‌ها و رازهای امضا:**

```hcl
resource "pcdn_config_section" "webhooks" {
  section = "webhooks"
  config = jsonencode({
    items = [{ url = "https://hooks.example.com/pcdn", events = ["purge.completed", "ssl.failed"] }]
  })
}

output "webhook_secrets" {
  value     = pcdn_config_section.webhooks.secrets   # map: شناسهٔ وب‌هوک ← whsec_...
  sensitive = true
}
```

### پاک‌سازی کش — `pcdn_purge`

```hcl
resource "pcdn_purge" "assets" {
  urls     = ["https://example.com/assets/app.css", "https://example.com/assets/app.js"]
  triggers = { release = var.release }    # با هر نسخهٔ جدید، یک purge تازه
}

resource "pcdn_purge" "blog" {
  prefixes = ["/blog/", "https://example.com/img/"]
}

resource "pcdn_purge" "all" {
  everything = true
  triggers   = { release = var.release }
}
```

### اطلاعات سایت — `pcdn_site`

```hcl
data "pcdn_site" "this" {}

output "nameservers" { value = data.pcdn_site.this.nameservers }
output "waf_allowed" { value = jsondecode(data.pcdn_site.this.plan_json).features.waf }
```

ویژگی‌ها: `domain`، `status`، `suspended`، `plan_json` (پلن و قابلیت‌ها به‌صورت JSON)، `nameservers`،
`cname_target`، `ssl_status`.

## ۵. وارد کردن (import) منابع موجود

```bash
terraform import pcdn_record.www 123              # شناسهٔ عددی رکورد (از GET /capi/v1/records)
terraform import pcdn_config_section.cache cache  # نام بخش
```

- برای رکورد، اگر نام یا مقدار را با املای دیگری نوشته باشید (حروف بزرگ، نقطهٔ انتهایی، شکل دیگر IPv6)
  تفاوتی نشان داده نمی‌شود.
- برای بخش تنظیمات، import کل بخش ذخیره‌شده را در state می‌گذارد؛ اگر `config` شما فقط بعضی کلیدها را
  دارد، plan بعدی **یک‌بار** به‌روزرسانی نشان می‌دهد (همان PUT که کلیدهای ننوشته را به پیش‌فرض برمی‌گرداند).
- `pcdn_purge` قابل import نیست.

## ۶. محدودیت‌ها و رفتارهای مهم

- **بخش‌های تنظیمات حذف‌شدنی نیستند.** `terraform destroy` یا حذف منبع `pcdn_config_section` فقط آن را از
  state بیرون می‌برد و هشدار می‌دهد؛ تنظیمات روی کنترلر همان‌طور می‌ماند. برای برگرداندن به پیش‌فرض، پیش از
  حذف یک‌بار `config = jsonencode({})` را apply کنید.
- **هر بخش به‌طور کامل جایگزین می‌شود.** هر کلیدی که در `config` نیاید مقدار پیش‌فرض کنترلر را می‌گیرد؛
  پس اگر کلیدی را از `config` حذف کنید، روی کنترلر به پیش‌فرض برمی‌گردد. برای هر بخش فقط **یک**
  `pcdn_config_section` بسازید.
- **مقایسهٔ معنایی JSON.** ترتیب کلیدها، فاصله‌ها و `1` در برابر `1.0` تفاوت حساب نمی‌شوند. مقادیر پیش‌فرضی که
  کنترلر اضافه می‌کند هم باعث diff دائمی نمی‌شوند: provider تغییرات بیرونی را با مقایسهٔ بخش فعلی کنترلر و
  `result` آخرین apply تشخیص می‌دهد. اگر کسی بخش را از پنل عوض کند، plan بعدی دقیقاً همان کلیدهای تغییرکرده
  را نشان می‌دهد و apply تنظیمات شما را برمی‌گرداند.
- **رازهای فقط‌نوشتنی.** `logs.secret_key` در پاسخ کنترلر `""` است (به‌همراه `secret_key_set`). provider
  مقدار شما را در `config` نگه می‌دارد، در `result` نمی‌گذارد و به خاطر آن diff نشان نمی‌دهد؛ با هر PUT همان
  بخش دوباره فرستاده می‌شود. تغییر این راز از پنل قابل تشخیص نیست. مقدار در state ذخیره می‌شود؛ متغیر را
  `sensitive` تعریف کنید تا در خروجی plan پنهان بماند.
- **راز وب‌هوک‌ها فقط یک‌بار برگردانده می‌شود** (هنگام ساخت وب‌هوک). provider آن را در ویژگی حساس `secrets`
  نگه می‌دارد و با حذف وب‌هوک پاکش می‌کند. وب‌هوکی که در `config` شناسه ندارد با `url` یکسان به وب‌هوک
  ذخیره‌شده وصل می‌شود تا ویرایش آن شناسه و راز را عوض نکند؛ اگر دو وب‌هوک یک `url` دارند، `id` را صریح
  بنویسید (از `jsondecode(pcdn_config_section.webhooks.result).items`).
- **معنای purge.** `pcdn_purge` یک «اقدام» است نه یک شیء: فقط هنگام ساخت، purge را در صف می‌گذارد. خواندن و
  حذف آن هیچ درخواستی نمی‌فرستد (purge برگشت‌پذیر نیست). هر تغییری در `urls`، `prefixes`، `everything` یا
  `triggers` منبع را جایگزین می‌کند و یعنی یک purge تازه. درخواست خالی پذیرفته نمی‌شود (کنترلر آن را «پاک‌سازی
  کل کش» تعبیر می‌کند)؛ برای کل کش صریحاً `everything = true` بنویسید که با `urls`/`prefixes` ترکیب نمی‌شود.
  حداکثر ۱۰۰ آدرس + پیشوند در هر purge و حداکثر ۲۰ پیشوند (هر کدام تا ۲۰۰ نویسه).
- **محدودیت نرخ.** هر کلید `CAPI_RATE` درخواست در دقیقه (پیش‌فرض ۶۰) و برای نوشتن رکورد/تنظیمات
  `CAPI_CONFIG_RATE` (پیش‌فرض **۶** در دقیقه) دارد. provider پاسخ `429` را با تأخیر نمایی (و رعایت
  `Retry-After`) دوباره امتحان می‌کند، پس apply بزرگ کند ولی درست انجام می‌شود (مثلاً ساخت ۳۰ رکورد چند
  دقیقه طول می‌کشد). اگر `429` تمام نشد `max_retries` را بیشتر کنید.
- **نوشتن‌ها پشت سر هم انجام می‌شوند.** کنترلر همهٔ بخش‌های یک سایت را در یک سند JSON نگه می‌دارد و دو PUT
  هم‌زمان روی بخش‌های مختلف می‌توانند تغییر یکدیگر را از بین ببرند؛ برای همین provider در هر لحظه فقط یک
  درخواست نوشتن می‌فرستد (خواندن‌ها موازی‌اند). در یک پیکربندی، برای یک کلید فقط یک بلوک provider (بدون
  alias تکراری) استفاده کنید و هم‌زمان با Terraform همان بخش‌ها را از پنل عوض نکنید.
- **تلاش دوباره فقط برای درخواست‌های امن.** خطای `5xx` یا قطع شبکه فقط برای GET/PUT/DELETE و PATCH رکورد (که
  کل رکورد را می‌فرستد) دوباره امتحان می‌شود؛ ساخت رکورد (`POST`) و purge دوباره فرستاده نمی‌شوند تا تکراری
  نشوند.
- **ترکیب‌های نامعتبر رکورد پیش از apply رد می‌شوند**: `proxied` برای نوعی غیر از A/AAAA/CNAME، `pool` یا
  `origin_port` بدون `proxied = true`، `origin_port` همراه `pool`، `priority` برای نوعی غیر از MX/SRV،
  `health_check` روی رکورد پروکسی یا غیر A/AAAA/CNAME (و CNAME بدون `weight`)، `health_port` یا
  `health_protocol` بدون `health_check`، `health_path` بدون probe از نوع `http`/`https`، و `weight` روی
  رکورد پروکسی یا نوعی غیر از A/AAAA/CNAME.
- **خطای همگام‌سازی DNS** (`dns_error`) خطا نیست: رکورد ذخیره شده و کنترلر خودش دوباره تلاش می‌کند؛ provider
  فقط هشدار می‌دهد.

## ۷. عیب‌یابی

| خطا | معنی | چه کنیم |
|-----|------|---------|
| `HTTP 401` | کلید نامعتبر یا لغوشده | کلید تازه بسازید؛ فاصله یا خط اضافه در متغیر نباشد |
| `HTTP 403` با «این کلید دسترسی «dns» را ندارد» | کلید آن دسترسی را ندارد | کلیدی با دسترسی لازم بسازید |
| `HTTP 403` با «در پلن شما فعال نیست» | قابلیت یا سقف پلن | پلن سرویس را ارتقا دهید یا تنظیم را خاموش کنید |
| `HTTP 422` | ورودی نامعتبر | پیام کنترلر (فارسی) با مسیر فیلد، مثلاً `rules.0.id: …`، در خطا آمده است |
| `HTTP 429` پس از همهٔ تلاش‌ها | محدودیت نرخ | کمی بعد دوباره اجرا کنید یا `max_retries` را بیشتر کنید |
| `endpoint must use https` | آدرس http | از `https://` استفاده کنید |

برای دیدن جزئیات درخواست‌ها: `TF_LOG_PROVIDER=DEBUG terraform apply` (روش، مسیر، کد پاسخ و تلاش‌ها لاگ
می‌شوند؛ کلید هرگز).

برای توسعه‌دهندگان: `gofmt -l .`، `go vet ./...`، `go test ./...` و `go build ./...` در پوشهٔ
`terraform-provider-pcdn` اجرا می‌شوند (job `terraform` در CI). تست‌ها کاملاً آفلاین‌اند: چرخهٔ واقعی
`terraform plan/apply/import/destroy` روی یک کنترلر جعلی (httptest)؛ به فایل اجرایی Terraform نیاز دارند
(`TF_ACC_TERRAFORM_PATH` یا `terraform` در `PATH`) و بدون آن رد می‌شوند، مگر `PCDN_REQUIRE_TERRAFORM=1`.

## ۸. افزودن نود با Terraform (ویژهٔ اپراتور)

افزودن نود بر اساس **ظرفیت** (SPEC §23.9): وقتی هشدار ظرفیت یک گروه (`capacity:{group}`) باز می‌شود، کنترلر
یک **پیشنهاد** می‌سازد (اندازه و تعداد فقط از p95 در برابر `capacity_mbps` — هرگز از دسترس‌پذیری، فیلترینگ یا
دادهٔ ISP؛ هر نود تازه نشانی‌های معمولی و ثابت می‌گیرد). هیچ چیزی بدون **دو تأیید مدیر** ساخته نمی‌شود و کنترلر
هرگز کلید ابری ندارد:

```text
پیشنهاد ──تأیید مدیر──▶ approved ──pcdn-provision: terraform plan──▶ planned (خلاصهٔ طرح در پنل)
        ──تأیید «اجرای طرح»──▶ apply_approved ──pcdn-provision: terraform apply──▶ applied ──پیوستن نودها──▶ joined
```

### اجزا

| مسیر | کار |
|---|---|
| `terraform/modules/pcdn-edge-node` | ماژول بی‌منبع و مستقل از ابر: برای هر نام نود `user_data` (cloud-init) با **توکن پیوستن یک‌بارمصرف** |
| `terraform/providers/hcloud` | نمونهٔ Hetzner Cloud: یک `hcloud_server` برای هر نام؛ نوع سرور از `server_types` (اندازه‌های `PROVISION_SIZES`) و محل از `locations` (منطقه) |
| `terraform/providers/fake` | provider ساختگی برای آزمون و CI: `terraform_data` + فایل cloud-init هر نود در `out/` — بدون ابر |
| `tools/provision/pcdn-provision` | provisioner اپراتور (Python stdlib + `terraform`) |

قرارداد cloud-init (SPEC §23.18 #8) — هر نود در اولین بوت اجرا می‌کند:

```bash
curl -fsSL --proto '=https' https://<controller>/edge/bootstrap.sh |
  PCDN_JOIN_TOKEN=jt_… bash -s -- --controller https://<controller> --role <general|tunnel> --region <home|global> [--version vX.Y.Z]
```

توکن پیوستن (`jt_` + ۴۰ hex) یک‌بارمصرف است و پس از `JOIN_TOKEN_HOURS` (پیش‌فرض ۲۴) منقضی می‌شود؛ نود با آن
`POST /edge/v1/join` می‌زند و توکن دائمی خودش را می‌گیرد. پس کپی توکن در metadata ابر یا state ترافرم پس از
پیوستن بی‌ارزش است. `--version` همان نسخهٔ پین‌شدهٔ گروه است ([RELEASE.md](RELEASE.md)).

### اجرای provisioner

```bash
# روی ماشین اپراتور (نه روی کنترلر)؛ کلید ابر فقط در محیط همین فرایند
install -m 600 /dev/null /etc/pcdn/provisioner.token && $EDITOR /etc/pcdn/provisioner.token   # = PROVISIONER_TOKEN کنترلر (≥ ۳۲ نویسه)
export HCLOUD_TOKEN=…            # یا متغیرهای ابر دیگر؛ هرگز در فایل‌های مخزن یا کنترلر
tools/provision/pcdn-provision --controller https://cdn-api.example.com \
    --token-file /etc/pcdn/provisioner.token --workdir /var/lib/pcdn-provision \
    --module terraform/providers/hcloud            # --once برای یک کار و خروج (cron / آزمون)
```

- هر ۶۰ ثانیه (`--interval`) `GET /api/v1/provisioner/jobs/next` را می‌پرسد (Bearer `PROVISIONER_TOKEN`؛ کنترلر
  با `PROVISIONING_ENABLED=true`).
- **plan:** در `<workdir>/job-<id>/` (مجوز ۰۷۰۰) یک ماژول ریشهٔ کوچک می‌سازد که `--module` را صدا می‌زند،
  `terraform.tfvars.json` (بدون راز) و `secrets.auto.tfvars.json` (۰۶۰۰، توکن‌های پیوستن) را می‌نویسد،
  `terraform init` / `plan -out=plan.bin` / `show` را اجرا و خلاصهٔ طرح را با توکن‌های پوشانده (`jt_***`) به
  `POST …/jobs/{id}/plan` می‌فرستد (`adds`/`changes`/`destroys` از `terraform show -json`).
- **apply:** پس از تأیید دوم مدیر، `terraform apply plan.bin`؛ طرحی که چیزی را **حذف یا جایگزین** کند هرگز اجرا
  نمی‌شود (`plan_destroys`، هم در کنترلر هم در provisioner)، و `terraform destroy` هرگز اجرا نمی‌شود. پس از apply
  فایل راز و `plan.bin` پاک می‌شوند و نتیجه به `POST …/jobs/{id}/result` می‌رود.
- خطاها (حداکثر ۵۰۰ نویسه) پیش از ارسال از هر توکن پیوستن پاک می‌شوند.
- state ترافرم هر کار در `<workdir>/job-<id>/terraform.tfstate` می‌ماند (شامل user_data نودها)؛ پوشه را خصوصی نگه
  دارید و برای حذف نود از پنل/دستی اقدام کنید — این ابزار چیزی را پاک نمی‌کند.

### افزودن ابر دیگر

پوشهٔ `terraform/providers/<name>` بسازید با **همان متغیرها** (`controller_url`، `names`، `join_tokens` حساس،
`region`، `role`، `group`، `size`، `release`) که ماژول `../../modules/pcdn-edge-node` را صدا بزند و برای هر نام
یک سرور با `user_data = module.node.user_data[name]` بسازد؛ کلید ابر فقط از محیط (مثل `HCLOUD_TOKEN`). نام
منابع ابرهای دیگر (مثلاً IaaS ابر آروان) فرض‌هایی‌اند که باید روی حساب خودتان آزموده شوند؛ پوشهٔ آزموده‌نشده در
مخزن قرار نمی‌گیرد.

### بررسی محلی

```bash
terraform fmt -check -recursive terraform
for d in terraform/modules/pcdn-edge-node terraform/providers/fake terraform/providers/hcloud; do
  terraform -chdir=$d init -backend=false && terraform -chdir=$d validate
done
python3 -m pytest -q tools/provision/tests     # با terraform روی PATH، مسیر کامل با providers/fake هم آزموده می‌شود
```

CI همین‌ها را در کار `provisioning` اجرا می‌کند (`PCDN_REQUIRE_TERRAFORM=1`).
