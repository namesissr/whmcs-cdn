# ابزار خط فرمان `pcdn` و انتشار نسخه‌ها

این سند راهنمای ابزار خط فرمان **`pcdn`** برای API مشتری CDN پاسارگاد (`/capi/v1`، SPEC §10.1) و روال
انتشار نسخه‌های امضاشدهٔ CLI و `terraform-provider-pcdn` است (SPEC §16.2). کد CLI در پوشهٔ
[`cli/`](../cli/) است (Go، بدون وابستگی خارجی).

## فهرست

- [۱. نصب](#۱-نصب)
- [۲. پیکربندی: endpoint و کلید API](#۲-پیکربندی-endpoint-و-کلید-api)
- [۳. فرمان‌ها](#۳-فرمانها)
- [۴. خروجی جدول یا JSON](#۴-خروجی-جدول-یا-json)
- [۵. تلاش دوباره، کد خروج و عیب‌یابی](#۵-تلاش-دوباره-کد-خروج-و-عیبیابی)
- [۶. انتشار نسخه (CLI و provider)](#۶-انتشار-نسخه-cli-و-provider)
- [۷. ساخت کلید GPG و secretهای GitHub](#۷-ساخت-کلید-gpg-و-secretهای-github)
- [۸. بررسی امضا توسط کاربر](#۸-بررسی-امضا-توسط-کاربر)
- [۹. انتشار provider در رجیستری Terraform](#۹-انتشار-provider-در-رجیستری-terraform)

---

## ۱. نصب

### از صفحهٔ Releases

از صفحهٔ Releases مخزن، نسخهٔ `cli/vX.Y.Z` را باز کنید و فایل سیستم خود را بگیرید:

| سیستم | فایل |
|-------|------|
| لینوکس x86-64 / ARM64 | `pcdn_X.Y.Z_linux_amd64.tar.gz` / `pcdn_X.Y.Z_linux_arm64.tar.gz` |
| macOS اینتل / Apple Silicon | `pcdn_X.Y.Z_darwin_amd64.tar.gz` / `pcdn_X.Y.Z_darwin_arm64.tar.gz` |
| ویندوز x86-64 / ARM64 | `pcdn_X.Y.Z_windows_amd64.zip` / `pcdn_X.Y.Z_windows_arm64.zip` |

```bash
tar -xzf pcdn_0.1.0_linux_amd64.tar.gz
sudo install -m 0755 pcdn /usr/local/bin/pcdn
pcdn version
```

پیش از نصب، checksum و امضا را بررسی کنید ([بخش ۸](#۸-بررسی-امضا-توسط-کاربر)).

### از کد

```bash
cd cli
go build -ldflags "-X main.version=0.1.0" -o pcdn ./cmd/pcdn
```

Go نسخهٔ 1.24 یا بالاتر لازم است.

## ۲. پیکربندی: endpoint و کلید API

`pcdn` دقیقاً مثل provider ترافورم پیکربندی می‌شود ([TERRAFORM.md](TERRAFORM.md)):

| تنظیم | فلگ | متغیر محیطی |
|-------|-----|-------------|
| آدرس کنترلر | `--endpoint` | `PCDN_ENDPOINT` |
| کلید API مشتری | `--api-key` | `PCDN_API_KEY` |
| قالب خروجی | `--output` / `-o` | `PCDN_OUTPUT` |

```bash
export PCDN_ENDPOINT=https://cdn-api.example.com
export PCDN_API_KEY=pcdn_…   # از ناحیهٔ کاربری WHMCS ← «API و کلیدها»
pcdn site
```

- فلگ بر متغیر محیطی مقدم است.
- **کلید را با متغیر محیطی بدهید**، نه فلگ: فلگ‌ها در `ps` و تاریخچهٔ shell دیده می‌شوند.
- `pcdn` کلید را **هرگز چاپ نمی‌کند** (نه در خطا، نه در `--verbose`)، و کلیدی را که با `pcdn_` شروع نشود
  (مثلاً کلید مدیریتی) بدون نمایش مقدارش رد می‌کند.
- endpoint باید `https` باشد؛ `http` فقط برای `localhost` / `127.0.0.1` / `[::1]` (آزمایش محلی) پذیرفته
  می‌شود. پسوند `/capi/v1` در آدرس اختیاری است. ریدایرکت هرگز دنبال نمی‌شود.
- هر کلید فقط به یک سرویس (دامنه) دسترسی دارد، پس هیچ فرمانی نام دامنه نمی‌گیرد. دسترسی لازم هر فرمان
  (`dns`، `purge`، `stats`) در جدول زیر آمده است؛ نبودِ آن خطای 403 می‌دهد.

فلگ‌های عمومی را می‌توان قبل یا بعد از نام فرمان نوشت (`pcdn -o json site` یا `pcdn site -o json`).

## ۳. فرمان‌ها

| فرمان | کار | دسترسی |
|-------|-----|--------|
| `pcdn site` | خلاصهٔ سرویس: دامنه، وضعیت، پلن، nameserverها، هدف CNAME | هر دسترسی |
| `pcdn records list` | فهرست رکوردهای DNS | `dns` |
| `pcdn records add …` | افزودن رکورد | `dns` |
| `pcdn records update <id> …` | تغییر فیلدهای یک رکورد | `dns` |
| `pcdn records delete <id>` | حذف رکورد | `dns` |
| `pcdn config get <section>` | خواندن یک بخش تنظیمات (JSON) | `dns` |
| `pcdn config set <section> [file\|-]` | جایگزینی یک بخش از فایل یا stdin | `dns` |
| `pcdn config history [--limit N] [--before V]` | تاریخچهٔ تنظیمات: چه کسی، کی، کدام بخش‌ها | `config` |
| `pcdn config diff <v> [--against current\|V] [--section S]` | تغییرات یک نسخه نسبت به حالا یا نسخهٔ دیگر | `config` |
| `pcdn config restore <v> [--section S …] [--dry-run]` | بازگردانی بخش‌های یک نسخهٔ قدیمی‌تر | `config` (`functions` به `functions` هم نیاز دارد) |
| `pcdn purge --url … / --prefix … / --everything` | پاکسازی کش | `purge` |
| `pcdn analytics [--period 24h\|7d\|30d]` | آمار ترافیک | `stats` |
| `pcdn analytics live [--minutes N]` | آمار دقیقه‌ای زنده (۱ تا ۱۴۴۰ دقیقه) | `stats` |
| `pcdn tunnel quality [--hours N]` | کیفیت تونل به تفکیک مسیر و edge (۱ تا ۷۴۴ ساعت) | `stats` |
| `pcdn tunnel usage [--days N]` | مصرف روزانهٔ تونل + پیش‌بینی ماه (۱ تا ۹۰ روز) | `stats` |
| `pcdn tunnel health` | سلامت origin مسیرهای تونل از دید edgeها | `stats` |
| `pcdn version` / `pcdn help` | نسخه / راهنما | — |

راهنمای هر فرمان: `pcdn records -h`، `pcdn purge -h` و …

### رکوردها

```bash
pcdn records list
pcdn records add --type A --name www --content 203.0.113.10 --proxied
pcdn records add --type MX --content mail.example.com --priority 10
pcdn records update 42 --ttl 600 --proxied=false
pcdn records update 42 --pool none          # پاک کردن فیلد اختیاری
pcdn records update 43 --weight 0 --health-protocol https --health-path /healthz
pcdn records delete 42
```

فلگ‌ها: `--name` (پیش‌فرض `@`)، `--type`، `--content`، `--ttl` (پیش‌فرض ۳۰۰)، `--priority`، `--proxied`،
`--pool`، `--origin-port`، `--health-check`، `--health-port` و برای رکوردهای وزن‌دار/failover (SPEC §16.7)
`--weight` (۰ تا ۱۰۰)، `--health-protocol` (`tcp`/`http`/`https`) و `--health-path`. برای خاموش کردن فلگ‌های بولی از `=false`
استفاده کنید و برای خالی کردن فیلدهای اختیاری از مقدار `none`.

`update` ابتدا رکورد را می‌خواند، فقط فیلدهایی را که داده‌اید عوض می‌کند و کل رکورد را می‌فرستد (API
همیشه رکورد کامل می‌گیرد)؛ فیلدهایی که این نسخهٔ CLI نمی‌شناسد (فیلدهای جدیدتر API) همان‌طور که ذخیره
شده‌اند برگردانده می‌شوند و پاک نمی‌شوند. اگر ذخیره شد ولی همگام‌سازی DNS خطا داد، هشدار روی stderr چاپ می‌شود
(کنترلر بعداً دوباره همگام می‌کند).

### تنظیمات (بخش‌ها)

نام بخش‌ها همان بخش‌های API است: `cache`، `ssl`، `waf`، `ddos`، `firewall`، `ratelimit`، `pagerules`،
`pools`، `headers`، `hotlink`، `image`، `errorpages`، `tunnel`، `transform`، `redirects`، `bots`، `logs`،
`webhooks`.

```bash
pcdn config get waf > waf.json
nano waf.json
pcdn config set waf waf.json
# یا از stdin:
jq '.enabled = true' waf.json | pcdn config set waf -
```

- خروجی `config get` و `config set` همیشه JSON است (مستقل از `--output`) تا رفت‌وبرگشت بالا کار کند.
- `config set` کل بخش را **جایگزین** می‌کند؛ ورودی باید یک شیء JSON باشد (BOM ویندوز مشکلی ندارد).
- هشدارهای غیرمسدودکنندهٔ کنترلر (`X-Pcdn-Warnings`) روی stderr چاپ می‌شوند.
- برای بخش `webhooks` پاسخ ممکن است `new_secrets` داشته باشد؛ این رازها **فقط یک‌بار** نمایش داده
  می‌شوند، آن‌ها را نگه دارید.

### تاریخچه، مقایسه و بازگردانی تنظیمات

هر تغییر تنظیمات (از پنل، API، CLI، Terraform، یادگیری WAF یا انتقال) یک **نسخه** می‌سازد (SPEC §23.4):

```bash
pcdn config history                          # جدیدترین ۵۰ نسخه؛ --limit 1..200، --before V برای صفحهٔ بعد
pcdn config diff 9                           # تغییرات از نسخهٔ ۹ تا حالا
pcdn config diff 9 --against 12 --section waf
pcdn config restore 9 --dry-run              # پیش‌نمایش: چه بخش‌هایی اعمال / بدون تغییر / حذف می‌شوند
pcdn config restore 9 --section cache --section waf   # یا --section cache,waf
```

- ستون «BY»: `account owner`، `collaborator <نام>`، `support`، `API key <نام>` یا `system (<کار>)`.
- مقادیر حساس (رازها، سرآیندهای احراز هویت) در خروجی `"[redacted]"` هستند؛ کد توابع هرگز در diff نیست.
- بازگردانی یک نسخهٔ **تازه** با «restored from» می‌سازد؛ رازهای ذخیره‌شده تغییر نمی‌کنند. بخش‌هایی که پلن فعلی
  اجازه نمی‌دهد حذف و فهرست‌های بیش از سقف پلن کوتاه می‌شوند (`Dropped: …` و `Warning: …` در خروجی). بدون
  `--section` همهٔ بخش‌هایی که فرق دارند بازگردانده می‌شوند.
- `restore` یک نوشتن غیرتکراری است: پس از 5xx خودکار دوباره فرستاده نمی‌شود (۴۲۹ چرا). سقف: ۱۰ بازگردانی در
  ساعت برای هر سایت.

### پاکسازی کش

```bash
pcdn purge --url https://example.com/app.css --url https://example.com/app.js
pcdn purge --prefix https://example.com/static/
pcdn purge --everything
```

`--url` و `--prefix` تکرارپذیر و قابل ترکیب‌اند؛ `--everything` با آن‌ها ترکیب نمی‌شود.

### آمار و تونل

```bash
pcdn analytics --period 7d
pcdn analytics live --minutes 30
pcdn tunnel quality --hours 6
pcdn tunnel usage --days 7
pcdn tunnel health
```

در `tunnel quality` اگر کنترلر برای مسیری توصیه (فارسی) داشته باشد، زیر جدول نمایش داده می‌شود.

## ۴. خروجی جدول یا JSON

- `--output table` (پیش‌فرض): جدول خوانا با جداکنندهٔ هزارگان و حجم‌ها به KiB/MiB/GiB.
- `--output json`: همان پاسخ کنترلر، دست‌نخورده و مرتب‌شده (ترتیب کلیدها حفظ می‌شود) — برای اسکریپت و
  `jq` مناسب است.

```bash
pcdn records list -o json | jq -r '.[] | select(.proxied) | .name'
```

پیام‌ها و هشدارها روی stderr و داده روی stdout می‌روند، پس pipe کردن خروجی امن است.

## ۵. تلاش دوباره، کد خروج و عیب‌یابی

- **429** (محدودیت نرخ) برای همهٔ درخواست‌ها دوباره تلاش می‌شود (کنترلر پیش از انجام کار رد می‌کند) و
  `Retry-After` رعایت می‌شود.
- **5xx** و خطای شبکه فقط برای درخواست‌های idempotent (GET، PUT، DELETE و PATCH رکورد که کل رکورد را
  می‌فرستد) دوباره تلاش می‌شوند؛ `records add` و `purge` (POST) پس از 5xx تکرار **نمی‌شوند** تا دوبار
  اجرا نشوند.
- `--max-retries N` (پیش‌فرض ۵) و `--timeout 30s` (برای هر تلاش) قابل تنظیم‌اند. `Ctrl+C` درخواست را
  فوراً لغو می‌کند.
- `-v` / `--verbose` هر درخواست و هر تلاش دوباره را روی stderr نشان می‌دهد (بدون کلید).

| کد خروج | معنی |
|---------|------|
| `0` | موفق |
| `1` | خطای API، شبکه یا ورودی (پیام کنترلر و یک راهنمای کوتاه `Hint:` چاپ می‌شود) |
| `2` | فرمان یا فلگ نادرست، یا endpoint/کلید تنظیم نشده |

| خطا | علت معمول |
|-----|-----------|
| `HTTP 401` | کلید اشتباه یا لغوشده |
| `HTTP 403` | کلید دسترسی لازم (`dns`/`purge`/`stats`) را ندارد یا قابلیت در پلن نیست |
| `HTTP 422` | ورودی نامعتبر؛ پیام فارسی کنترلر با مسیر فیلد نمایش داده می‌شود |
| `HTTP 429` پس از تلاش‌ها | سقف درخواست/تغییر پیکربندی در دقیقه؛ کمی بعد دوباره |
| `endpoint must use https` | آدرس `http` غیرمحلی؛ از `https` استفاده کنید |

---

## ۶. انتشار نسخه (CLI و provider)

انتشار کاملاً با تگ git انجام می‌شود؛ workflow [`release.yml`](../.github/workflows/release.yml):

| تگ | چه منتشر می‌شود | پیکربندی |
|-----|-----------------|----------|
| `cli/vX.Y.Z` | باینری‌های `pcdn` برای linux/darwin/windows × amd64/arm64 | [`cli/.goreleaser.yml`](../cli/.goreleaser.yml) |
| `provider/vX.Y.Z` | `terraform-provider-pcdn` در قالب رجیستری Terraform | [`terraform-provider-pcdn/.goreleaser.yml`](../terraform-provider-pcdn/.goreleaser.yml) |

```bash
# CI روی main سبز باشد، سپس:
git tag -a cli/v0.1.0 -m "pcdn 0.1.0"
git push origin cli/v0.1.0

git tag -a provider/v0.1.0 -m "terraform-provider-pcdn 0.1.0"
git push origin provider/v0.1.0
```

نسخه باید SemVer باشد (`1.2.3` یا پیش‌انتشار `1.2.3-rc.1`؛ پیش‌انتشار به‌صورت pre-release منتشر می‌شود).

workflow این مراحل را اجرا می‌کند:

1. از روی تگ، بخش (`cli`/`provider`) و نسخه را تشخیص می‌دهد و `go vet` / `go test` را اجرا می‌کند.
2. کلید GPG را از secretها در keyring موقت runner وارد می‌کند (`crazy-max/ghaction-import-gpg`).
3. چون GoReleaser نسخهٔ متن‌باز تگ‌های پیشونددار (`cli/v…`) را نمی‌فهمد، یک تگ محلی `vX.Y.Z` روی همان
   commit می‌سازد (push **نمی‌شود**) و GoReleaser را با `GORELEASER_CURRENT_TAG=vX.Y.Z` اجرا می‌کند.
4. GoReleaser می‌سازد، بسته‌بندی می‌کند، `SHA256SUMS` می‌سازد و آن را با `GPG_FINGERPRINT` امضا می‌کند
   (امضای جدا و باینری `.sig`).
5. امضا و checksumها بررسی می‌شوند و فایل‌ها با `gh release create` به Release همان تگ اصلی
   (`cli/vX.Y.Z` یا `provider/vX.Y.Z`) آپلود می‌شوند.

فایل‌های هر Release:

- CLI: `pcdn_X.Y.Z_<os>_<arch>.tar.gz` (ویندوز `.zip`)، `pcdn_X.Y.Z_SHA256SUMS`، `pcdn_X.Y.Z_SHA256SUMS.sig`
- provider: `terraform-provider-pcdn_X.Y.Z_<os>_<arch>.zip` (linux/darwin/windows/freebsd)،
  `terraform-provider-pcdn_X.Y.Z_SHA256SUMS`، `terraform-provider-pcdn_X.Y.Z_SHA256SUMS.sig`،
  `terraform-provider-pcdn_X.Y.Z_manifest.json` (پروتکل `6.0`؛ در SHA256SUMS هم آمده است)

آزمایش محلی بدون امضا و انتشار (نیاز به [GoReleaser v2](https://goreleaser.com/install/)):

```bash
cd cli && goreleaser check && goreleaser release --snapshot --clean --skip=sign
cd terraform-provider-pcdn && goreleaser check && goreleaser release --snapshot --clean --skip=sign
```

(پوشهٔ `dist/` ساخته‌شده را commit نکنید.)

## ۷. ساخت کلید GPG و secretهای GitHub

کلید خصوصی **هرگز** در مخزن قرار نمی‌گیرد؛ فقط در secretهای GitHub.

### ساخت کلید (یک‌بار، روی سیستم امن)

```bash
gpg --full-generate-key
#   نوع: RSA and RSA (یا ECC/ed25519)، طول RSA ‏4096، انقضا مثلاً 2y
#   نام/ایمیل: Pasargad CDN Releases <release@example.com>
#   یک passphrase قوی بگذارید
gpg --list-secret-keys --keyid-format=long
#   FPR = اثرانگشت ۴۰ کاراکتری کلید
```

> رجیستری Terraform کلید RSA یا DSA می‌خواهد؛ اگر provider را در رجیستری منتشر می‌کنید RSA ‏4096 بسازید.

### خروجی گرفتن

```bash
FPR=<اثرانگشت>
gpg --armor --export-secret-keys "$FPR" > release-private.asc   # فقط برای secret؛ بعد پاک کنید
gpg --armor --export "$FPR" > release-public.asc                # کلید عمومی، قابل انتشار
```

### ثبت secretها

در GitHub: **Settings ← Secrets and variables ← Actions ← New repository secret**

| نام secret | مقدار |
|------------|-------|
| `GPG_PRIVATE_KEY` | کل محتوای `release-private.asc` (از `-----BEGIN PGP PRIVATE KEY BLOCK-----` تا انتها) |
| `PASSPHRASE` | passphrase کلید |

یا با GitHub CLI:

```bash
gh secret set GPG_PRIVATE_KEY < release-private.asc
gh secret set PASSPHRASE          # passphrase را تایپ کنید
shred -u release-private.asc      # نسخهٔ محلی را پاک کنید
```

`GPG_FINGERPRINT` secret نیست: workflow آن را از خروجی مرحلهٔ import می‌گیرد. کلید عمومی
(`release-public.asc`) را منتشر کنید (وب‌سایت، keyserver یا README) تا کاربران امضا را بررسی کنند.
پیشنهاد: secretها را در یک GitHub Environment با reviewer اجباری نگه دارید و تگ‌های `cli/v*` و
`provider/v*` را با Tag protection rule محافظت کنید.

برای چرخش کلید: کلید جدید بسازید، دو secret را جایگزین کنید، کلید عمومی جدید را منتشر کنید (و در رجیستری
Terraform اضافه کنید). نسخه‌های قبلی با کلید قبلی معتبر می‌مانند.

## ۸. بررسی امضا توسط کاربر

```bash
gpg --import release-public.asc
gpg --verify pcdn_0.1.0_SHA256SUMS.sig pcdn_0.1.0_SHA256SUMS
sha256sum --check --ignore-missing pcdn_0.1.0_SHA256SUMS
```

خروجی باید `Good signature` با اثرانگشت منتشرشده و `OK` برای فایل دانلودشده باشد. روی macOS به‌جای
`sha256sum` از `shasum -a 256 -c --ignore-missing` استفاده کنید.

## ۹. انتشار provider در رجیستری Terraform

فایل‌های Release دقیقاً با قالبی که رجیستری Terraform می‌خواهد ساخته می‌شوند (zip با نام
`terraform-provider-pcdn_{{Version}}_{{Os}}_{{Arch}}.zip`، فایل‌های `SHA256SUMS` و `.sig` و manifest).
دو محدودیت رجیستری عمومی (`registry.terraform.io`):

- مخزن باید نامش `terraform-provider-pcdn` باشد و تگ‌ها `vX.Y.Z` (بدون پیشوند). این مخزن یک monorepo است،
  پس برای رجیستری عمومی، فایل‌های همین Release را در Release یک مخزن آینه با نام
  `terraform-provider-pcdn` و تگ `vX.Y.Z` قرار دهید (یا آن پوشه را به آن مخزن split کنید)؛
- کلید عمومی GPG باید در تنظیمات namespace رجیستری ثبت شده باشد.

برای رجیستری خصوصی (Terraform Cloud/Enterprise) همین فایل‌ها با API «private provider versions» آپلود
می‌شوند، و بدون رجیستری هم می‌توانید zipها را در یک filesystem/network mirror قرار دهید
([TERRAFORM.md](TERRAFORM.md) ← نصب provider).
