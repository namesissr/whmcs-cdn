# انتشار نسخهٔ سکو (Release) — CDN پاسارگاد

این راهنما مسیر کامل انتشار یک نسخهٔ سکو را از «همهٔ تغییرات در `[Unreleased]`» تا «Release منتشرشده در
GitHub» توضیح می‌دهد: نسخه‌گذاری، آماده‌سازی CHANGELOG، دروازهٔ staging، بازبینی امنیتی، برچسب و ساخت
بستهٔ لبهٔ پین‌شده. قرارداد این بخش [SPEC §23.1](SPEC.md) است؛ استقرار تدریجی روی نودها در
[ROLLOUT.md](ROLLOUT.md) و انتشار خودکار نودها (rollout) در [OPERATIONS.md](OPERATIONS.md) آمده است.

> **قاعدهٔ اصلی:** ادغام PR انتشار در `main`، ساختن و push برچسب `vX.Y.Z` و انتشار (publish) Release در
> GitHub **تصمیم مالک مخزن** است و فقط با **تأیید صریح او** انجام می‌شود. هیچ اسکریپت یا Workflow این مخزن
> خودش ادغام، برچسب یا انتشار نمی‌کند: ابزارها فقط آماده و بررسی می‌کنند و فرمان‌ها را **چاپ** می‌کنند.

**English summary.** `VERSION` holds the platform version (SemVer, no `v`); the tag is `v$(cat VERSION)`.
Flow: `tools/release/prepare.sh X.Y.Z` (CHANGELOG + VERSION, prints the git/PR commands) → release PR →
`tools/release/staging-verify.sh` on staging (evidence in `release-evidence/vX.Y.Z/`) →
`tools/release/security-check.sh` + signed `security-signoff.md` → **the owner confirms → merge → tag**
`vX.Y.Z` → `.github/workflows/release-platform.yml` re-runs all CI jobs, builds
`pcdn-edge-vX.Y.Z.tar.gz` (+ `.sha256`) and creates a **draft** GitHub release that the owner publishes.
No tool in this repository merges, tags, pushes or publishes on its own.

## فهرست

- [۱. نسخه‌گذاری و فایل VERSION](#۱-نسخهگذاری-و-فایل-version)
- [۲. نمای کلی جریان انتشار](#۲-نمای-کلی-جریان-انتشار)
- [۳. آماده‌سازی: prepare.sh](#۳-آمادهسازی-preparesh)
- [۴. دروازهٔ staging: staging-verify.sh](#۴-دروازهٔ-staging-staging-verifysh)
- [۵. بازبینی امنیتی](#۵-بازبینی-امنیتی)
- [۶. تأیید مالک، ادغام و برچسب](#۶-تأیید-مالک-ادغام-و-برچسب)
- [۷. Workflow انتشار و بستهٔ لبهٔ پین‌شده](#۷-workflow-انتشار-و-بستهٔ-لبهٔ-پینشده)
- [۸. پوشهٔ شواهد (release-evidence)](#۸-پوشهٔ-شواهد-release-evidence)
- [۹. نسخهٔ نامزد (rc) و رفع اشکال (patch)](#۹-نسخهٔ-نامزد-rc-و-رفع-اشکال-patch)
- [۱۰. ابزارها در یک نگاه](#۱۰-ابزارها-در-یک-نگاه)

---

## ۱. نسخه‌گذاری و فایل VERSION

- فایل `VERSION` در ریشهٔ مخزن یک خط است: SemVer **بدون** `v` — مثل `2.1.0` یا برای نامزد `2.1.0-rc.1`
  (پسوند build با `+` پذیرفته نیست). برچسب سکو همیشه `v$(cat VERSION)` است.
- رشتهٔ نسخه‌ها همان `2.x` مستند در [CHANGELOG.md](../CHANGELOG.md) و [ROLLOUT §۹](ROLLOUT.md#۹-نسخهگذاری-و-انتشار)
  است: `VERSION` از `2.0.0` (هنوز برچسب نخورده) شروع می‌شود و تغییرات موج ۱۳ و ۱۴ نسخهٔ `2.1.0` می‌شوند.
  برچسبی مثل `v1.13.0` به عقب برمی‌گردد؛ ابزارها هر SemVer بزرگ‌تری را که مالک انتخاب کند می‌پذیرند.
- **قواعد SemVer:** `MAJOR` برای تغییر ناسازگار API مشتری / قرارداد لبه یا اقدام دستی اجباری اپراتور،
  `MINOR` برای امکان تازهٔ سازگار (معمولاً هر موج)، `PATCH` برای رفع اشکال. ترتیب نامزدها طبق SemVer §11:
  `2.1.0-rc.1 < 2.1.0-rc.2 < 2.1.0`.
- هر جزء نسخه را گزارش می‌کند:
  - **کنترلر:** `PCDN_VERSION` (env) یا خط اول `VERSION`؛ در `GET /healthz` و `/healthz/deep` فیلد `version` و
    در `/metrics` سری `pcdn_build_info{version}`. در استقرار Docker مقدار را در `.env` بدهید:
    `PCDN_VERSION=2.1.0` (staging این کار را خودکار از `VERSION` می‌کند).
  - **محیط:** `PCDN_ENVIRONMENT` روی کنترلر (`staging`، `production` یا خالی) در `/healthz/deep`؛ دروازهٔ staging
    هر کنترلری را که `production` گزارش کند رد می‌کند.
  - **نود:** بستهٔ ساخته‌شده از برچسب، فایل `edge/RELEASE` (`vX.Y.Z`) دارد؛ نود آن را در heartbeat با نام
    `release` گزارش می‌کند و پنل مدیر ستون «نسخه» را نشان می‌دهد.
  - **افزونهٔ WHMCS** نسخهٔ خودش (`1.x`) را دارد و نسخهٔ کنترلر را از `/healthz` نشان می‌دهد.
- **CLI و Terraform provider** برچسب‌های جدای `cli/vA.B.C` و `provider/vA.B.C` دارند
  (`.github/workflows/release.yml`)؛ این راهنما دربارهٔ برچسب سکو `vX.Y.Z` است.

## ۲. نمای کلی جریان انتشار

| # | گام | چه کسی | ابزار | خروجی |
|---|---|---|---|---|
| ۱ | همهٔ PRها تغییرات خود را زیر `## [Unreleased]` نوشته‌اند و CI سبز است | توسعه‌دهندگان | CI (`release-meta` و بقیه) | `main` قابل انتشار |
| ۲ | آماده‌سازی نسخه روی یک شاخهٔ تمیز | مسئول انتشار | `tools/release/prepare.sh X.Y.Z` | تغییر `CHANGELOG.md` + `VERSION`، فرمان‌های چاپ‌شده |
| ۳ | commit، push شاخه و باز کردن PR انتشار | مسئول انتشار | فرمان‌های چاپ‌شدهٔ گام ۲ | PR «Release vX.Y.Z» |
| ۴ | استقرار head همان PR روی staging و اجرای دروازه | مسئول انتشار | `tools/release/staging-verify.sh` | `release-evidence/vX.Y.Z/report.md` = **PASS** |
| ۵ | بازبینی امنیتی خودکار + امضای چک‌لیست دستی | بازبین | `tools/release/security-check.sh` | `security-signoff.md` امضاشده |
| ۶ | **تأیید صریح مالک** با دیدن PR، گزارش staging و امضای امنیتی | **مالک مخزن** | — | «تأیید می‌کنم» |
| ۷ | ادغام PR در `main` | **مالک** (یا با تأیید صریح او) | GitHub | commit ادغام |
| ۸ | ساختن و push برچسب `vX.Y.Z` روی commit ادغام | **مالک** (یا با تأیید صریح او) | `git tag -a` / `git push origin vX.Y.Z` | برچسب |
| ۹ | آزمون دوباره، ساخت بستهٔ لبه و Release پیش‌نویس | خودکار | `release-platform.yml` | Release **draft** با دارایی‌ها |
| ۱۰ | بررسی و انتشار پیش‌نویس | **مالک** | GitHub → Publish | Release منتشرشده |
| ۱۱ | پر کردن `EDGE_RELEASES_DIR` و انتشار تدریجی روی نودها | اپراتور | `fetch-edge-release.sh`، صفحهٔ «انتشار نسخه» | [ROLLOUT.md](ROLLOUT.md) |

خلاصهٔ پایان جریان: **owner confirms → merge → tag** — بدون تأیید صریح مالک هیچ‌کدام انجام نمی‌شود.

## ۳. آماده‌سازی: prepare.sh

```bash
git switch main && git pull --ff-only
tools/release/prepare.sh 2.1.0            # یا 2.1.0-rc.1 ؛ --date YYYY-MM-DD برای تاریخ دیگر (پیش‌فرض: امروز UTC)
git diff                                   # بازبینی تغییر CHANGELOG.md و VERSION
```

`prepare.sh` در این موارد **رد می‌کند** (کد ۱، هیچ فایلی تغییر نمی‌کند):

- درخت کاری تمیز نیست (هر تغییر یا فایل untracked)؛
- نسخه SemVer معتبر نیست یا بزرگ‌تر از `VERSION` نیست (ترتیب نامزدها طبق SemVer §11). تنها استثنا: برابر با
  `VERSION` وقتی CHANGELOG هنوز `## [X.Y.Z] - Unreleased` دارد (مثل `2.0.0` امروز که هرگز برچسب نخورده)؛
- بخش `[Unreleased]` خالی است، یا بخش `[X.Y.Z]` با تاریخ از قبل وجود دارد.

کارهایی که انجام می‌دهد:

1. `## [Unreleased]` را به `## [X.Y.Z] - <تاریخ UTC>` تبدیل می‌کند و یک `## [Unreleased]` خالی بالای آن می‌گذارد.
   اگر بخشی با عنوان `## [X.Y.Z] - Unreleased` وجود داشته باشد، **ادغام** می‌شود (مقدمهٔ آن اول، زیربخش‌های
   هم‌نام یکی می‌شوند و مدخل‌های تازه‌تر بالاتر می‌آیند) و تکرار نمی‌شود. اگر بخش نسخهٔ قدیمی‌تری هنوز
   `Unreleased` باشد هشدار می‌دهد.
2. پیوندهای مقایسهٔ پایین فایل را به‌روز می‌کند: `[Unreleased]: …/compare/vX.Y.Z...HEAD` و
   `[X.Y.Z]: …/compare/v<آخرین نسخهٔ تاریخ‌دار>...vX.Y.Z` (یا `…/releases/tag/vX.Y.Z` وقتی نسخهٔ منتشرشدهٔ
   قبلی نیست).
3. `VERSION` را می‌نویسد.
4. فرمان‌های بعدی را **فقط چاپ می‌کند** (اجرا نمی‌کند): ساخت شاخهٔ `release/vX.Y.Z`، `git commit`، push شاخه،
   `gh pr create` با متن `changelog-section.sh`، و — **فقط پس از ادغام با تأیید مالک** —
   `git tag -a vX.Y.Z -m "Pasargad CDN vX.Y.Z" <commit ادغام>` و `git push origin vX.Y.Z`.

متن یک بخش (یادداشت انتشار) را هر وقت بخواهید:

```bash
tools/release/changelog-section.sh 2.1.0      # یا v2.1.0 / Unreleased
```

## ۴. دروازهٔ staging: staging-verify.sh

head همان PR انتشار را روی staging مستقر کنید (کنترلر با `PCDN_VERSION` = نسخهٔ جدید و
`PCDN_ENVIRONMENT=staging`، نودهای staging، WHMCS آزمایشی — [STAGING.md](STAGING.md)) و سپس:

```bash
cp deploy/staging/staging-gate.env.example deploy/staging/staging-gate.env && chmod 600 deploy/staging/staging-gate.env
$EDITOR deploy/staging/staging-gate.env      # PCDN_ADMIN_KEY، نشانی کنترلر، نود و سایت آزمون بار، PCDN_PROD_CONTROLLERS
tools/release/staging-verify.sh --env-file deploy/staging/staging-gate.env \
    --controller https://staging-api.example.com --ns ns1.staging.example.com \
    --edge-target 203.0.113.10:443 --loadtest-host lt.staging.example.com
```

گام‌ها به ترتیب (هر گام شکست بخورد بقیه برای جمع‌آوری شواهد ادامه می‌یابند):

| گام | روش | قبول وقتی |
|---|---|---|
| version | `GET /healthz` و `release` هر نود از `GET /api/v1/edges` | کنترلر = `VERSION`؛ نودها = `vVERSION` (بقیه «در انتظار rollout» فهرست می‌شوند) |
| preflight | `tools/preflight/preflight.py --strict --json` | بدون FAIL و بدون WARN |
| migrations | `/healthz/deep` → `database.revision` | برابر head کد (`controller/migrations/versions`) |
| integration | `deploy/staging/staging.sh test` | کد خروج ۰ |
| loadtest | `pcdn-loadtest http` (۱۲۰ ث) و `ws` (۶۰ ث) روی `--edge-target` | زیر آستانه‌ها: `--max-error-pct 0.5`، `--max-p99-ms 1500` (http)؛ قابل تغییر با همین گزینه‌ها |
| backup | `POST /api/v1/backups/run` و `/verify`، سپس پایش `GET /api/v1/backups` | هر دو `ok` و سطح آزمون بازیابی `full` |
| rollout | `POST /api/v1/rollouts` با `{"release": "vX.Y.Z", "dry_run": true}` | پاسخ ۲۰۰ و هیچ نود `blocked` |
| security | `tools/release/security-check.sh` | کد ۰ **و** `release-evidence/vX.Y.Z/security-signoff.md` امضاشده |

- **کد خروج:** ۰ = PASS، ۱ = FAIL، ۲ = رد شد (کنترلر تولید یا خطای استفاده)، ۳ = PARTIAL (گامی با `--skip-…`
  رد شده: `--skip-preflight`، `--skip-integration`، `--skip-loadtest`، `--skip-backup`، `--skip-rollout`،
  `--skip-security`). انتشار فقط با **PASS**؛ PARTIAL فقط با دلیل مکتوب در PR و پذیرش مالک.
- **هرگز روی تولید اجرا نمی‌شود:** اگر نشانی کنترلر در `PCDN_PROD_CONTROLLERS` (env یا فایل env، فهرست با
  کاما) باشد یا `/healthz/deep` مقدار `"environment": "production"` بدهد، اسکریپت پیش از هر درخواست مدیریتی
  با کد ۲ متوقف می‌شود و هیچ گزینه‌ای برای دور زدن آن ندارد.
- کلید مدیر فقط از فایل env (یا متغیر محیطی `PCDN_ADMIN_KEY`) خوانده می‌شود، فقط برای مسیرهای `/api/` فرستاده
  می‌شود و در خروجی و شواهد با `***` جایگزین می‌شود.
- آزمون بار فقط یک نود staging را هدف می‌گیرد ([LOADTEST.md](LOADTEST.md))؛ برای گواهی آزمایشی
  `--loadtest-arg=--insecure` یا `--loadtest-arg=--ca --loadtest-arg=<pem>` بدهید.

## ۵. بازبینی امنیتی

### بخش خودکار

```bash
tools/release/security-check.sh               # تغییرات از برچسب v* قبلی؛ --since <ref> برای بازهٔ دیگر
```

| بررسی | ابزار | نبودِ ابزار |
|---|---|---|
| secrets | `gitleaks detect` روی تغییرات از برچسب قبلی؛ در غیر این‌صورت اسکن داخلی: کلید خصوصی (با بدنهٔ base64)، `edge_[0-9a-f]{32,}`، `pcdn_[0-9a-f]{40}`، `jt_[0-9a-f]{40}`، کلیدهای AWS، توکن ربات `\d{6,}:[A-Za-z0-9_-]{30,}`، `Apikey …` | اسکن داخلی |
| files | هیچ `.env`، `*.pem` یا `agent.conf` در git نباشد (`.env.example` مجاز است) | — |
| pip-audit | `pip-audit -r controller/requirements.txt` | SKIP |
| govulncheck | `govulncheck ./...` در `cli/` | SKIP |
| bandit | `bandit -q -r controller/app -lll` | SKIP |
| whmcs-text | آزمون harness افزونه («WHMCS» در متن مشتری نباشد) از `whmcs/tests` | SKIP |
| hard-constraint | ماژول‌های انتخاب نود (`dnsbuild.py`، `rollout.py`، `provisioning.py`) هیچ import از `rum`/ISP ندارند (SPEC §23.7) | — |

مقادیر یافته‌شده هرگز کامل چاپ نمی‌شوند (فقط ۱۲ نویسهٔ اول). نمونه‌های آزمایشی آشکار (رشته‌های تکراری مثل
`pcdn_0123456789abcdef…`) نادیده گرفته می‌شوند؛ یک خط آزمایشی واقع‌نما را با توضیح `secret-scan: allow` علامت
بزنید. هر FAIL کد ۱ می‌دهد و انتشار را متوقف می‌کند.

### بخش دستی (چک‌لیست بازبین)

بازبین موارد زیر را روی diff از برچسب قبلی بررسی و در `release-evidence/vX.Y.Z/security-signoff.md` امضا
می‌کند (الگو: `tools/release/security-check.sh --template-only`؛ خط `Signed:` باید نام بازبین باشد):

- [ ] هر endpoint تازه/تغییرکرده مجوز درست دارد (admin، scope کلید API، توکن نود، توکن provisioner، عمومی) و
      محدودیت نرخ جایی که SPEC خواسته؛
- [ ] هیچ رازی (کلید، توکن، گذرواژه، کلید API ارائه‌دهنده، توکن پیوستن) لاگ، audit، برگردانده یا در متن خطا
      گذاشته نمی‌شود و رازهای تازه در پایگاه داده رمز می‌شوند؛
- [ ] پیش‌فرض متغیرهای محیطی تازه رفتار قبلی را حفظ می‌کند؛
- [ ] downgrade مهاجرت آزموده شده است (upgrade → downgrade → upgrade روی یک کپی)؛
- [ ] قید سخت SPEC §23: هیچ چیزی برای دور زدن فیلترینگ، پنهان/چرخاندن IP نودها یا انتخاب نود بر اساس
      «در دسترس بودن از شبکهٔ کاربران» نیست؛ داده‌های RUM/ISP به انتخاب نود نمی‌رسند؛ مشتری نام یا IP نود را
      نمی‌بیند (جز فهرست بی‌برچسب `edge_ips`)؛
- [ ] متن‌های مشتری کلمهٔ «WHMCS» ندارند.

## ۶. تأیید مالک، ادغام و برچسب

مالک مخزن PR انتشار را با این پیوست‌ها بررسی می‌کند: `report.md` دروازهٔ staging (PASS)، خروجی
`security-check.sh` و `security-signoff.md` امضاشده، و CI سبز. **فقط پس از تأیید صریح مالک**:

```bash
# ادغام PR در main از رابط GitHub (یا با تأیید صریح مالک)
git fetch origin
git log --oneline -1 origin/main                  # commit ادغام را پیدا کنید
git tag -a v2.1.0 -m "Pasargad CDN v2.1.0" <merge-commit>
git push origin v2.1.0
```

برچسب باید دقیقاً `v$(cat VERSION)` روی commit ادغام باشد؛ در غیر این‌صورت Workflow انتشار شکست می‌خورد.
برچسب را جابه‌جا یا بازنویسی نکنید؛ اگر اشتباه شد، نسخهٔ بعدی (`patch` یا `rc` بعدی) را منتشر کنید.

## ۷. Workflow انتشار و بستهٔ لبهٔ پین‌شده

`.github/workflows/release-platform.yml` با push برچسب `v*` اجرا می‌شود (برچسب‌های `cli/v*` و `provider/v*`
همچنان با `release.yml` هستند):

1. **meta:** برچسب = `v$(cat VERSION)`، `VERSION` معتبر، بخش CHANGELOG همان نسخه موجود؛
2. **tests:** همهٔ کارهای `ci.yml` (از طریق `workflow_call` — هرگز بررسی کمتر)؛
3. **draft-release:** `tools/release/build-edge-bundle.sh vX.Y.Z --from-tag` → `dist/pcdn-edge-vX.Y.Z.tar.gz` و
   `dist/pcdn-edge-vX.Y.Z.tar.gz.sha256` (قالب `sha256sum`)، ساخت دوباره و مقایسهٔ بایت‌به‌بایت، سپس یک
   Release **پیش‌نویس** با عنوان `Pasargad CDN vX.Y.Z`، متن بخش CHANGELOG و دو دارایی بالا. اگر پیش‌نویس از قبل
   باشد دارایی‌ها جایگزین می‌شوند؛ Release منتشرشده هرگز تغییر نمی‌کند. **انتشار پیش‌نویس با مالک است.**

**بستهٔ لبه** همان چیدمان بستهٔ زندهٔ کنترلر (`controller/app/bundle.py`) را دارد: پوشهٔ بالایی `edge/`، بدون
`__pycache__`، `tests`، `*.pyc` و `agent.conf`، به‌اضافهٔ `edge/RELEASE`. ساخت **قطعی** است: ترتیب مرتب، زمان
همهٔ فایل‌ها = زمان commit برچسب، uid/gid صفر و gzip بدون نام و زمان (`gzip -n`)؛ هر کس از همان برچسب بسازد همان
sha256 را می‌گیرد.

پس از انتشار، اپراتور بسته را در `EDGE_RELEASES_DIR` کنترلر می‌گذارد:

```bash
tools/release/fetch-edge-release.sh v2.1.0 --dir /srv/pcdn/edge-releases    # دانلود از Release + بررسی sha256
# یا از یک checkout محلی برچسب:
tools/release/build-edge-bundle.sh v2.1.0 --from-tag --out /srv/pcdn/edge-releases
```

`fetch-edge-release.sh` فقط https (یا http روی localhost برای آینهٔ محلی) دانلود می‌کند، sha256 را بررسی
می‌کند و فایل موجود با محتوای متفاوت را **هرگز** جایگزین نمی‌کند. سپس `EDGE_RELEASE=v2.1.0` (پین نصب‌های تازه)
و انتشار تدریجی روی نودها از صفحهٔ «انتشار نسخه» یا API (`POST /api/v1/rollouts`) — جزئیات در
[OPERATIONS.md](OPERATIONS.md) و [ROLLOUT.md](ROLLOUT.md).

## ۸. پوشهٔ شواهد (release-evidence)

`staging-verify.sh` شواهد را در `release-evidence/vX.Y.Z/` می‌نویسد (یا `--out DIR`):

```text
release-evidence/
  .gitignore                 # «*» — شواهد هرگز commit نمی‌شوند
  v2.1.0/
    report.md                # جدول گام‌ها، نتیجه (PASS/FAIL/PARTIAL)، commit، زمان
    report.json              # همان به‌صورت ماشینی
    security-signoff.md      # امضای بازبین (دستی)
    raw/                     # healthz، edges، preflight، integration، loadtest-*.json، backups-*، rollout-dry-run…
```

`report.md` و `security-signoff.md` را به PR انتشار پیوست کنید (یا متنشان را در توضیح PR بگذارید) و
`report.json` را تا انتشار بعدی نگه دارید.

## ۹. نسخهٔ نامزد (rc) و رفع اشکال (patch)

- **rc:** `prepare.sh 2.1.0-rc.1` → همان جریان؛ برچسب `v2.1.0-rc.1` یک Release پیش‌نویس با نشان pre-release
  می‌سازد. برای canary مناسب است. نسخهٔ نهایی بعداً با `prepare.sh 2.1.0` (بزرگ‌تر از هر `rc`).
- **patch:** رفع اشکال روی `main` با مدخل `### Fixed` زیر `[Unreleased]`، سپس `prepare.sh 2.1.1` و همان جریان
  (دروازهٔ staging کوتاه‌تر با `--skip-…` فقط با پذیرش مالک).
- **بازگشت:** برچسب‌ها پاک یا جابه‌جا نمی‌شوند؛ بازگشت نودها با «بازگردانی» rollout یا نسخهٔ پین‌شدهٔ قبلی است
  ([ROLLOUT §۸](ROLLOUT.md#۸-بازگشت-rollback-هر-جزء)).

## ۱۰. ابزارها در یک نگاه

| ابزار | کار |
|---|---|
| `VERSION` | نسخهٔ سکو (SemVer بدون `v`) |
| `tools/release/prepare.sh X.Y.Z[-rc.N]` | CHANGELOG + VERSION، چاپ فرمان‌های git / PR / برچسب |
| `tools/release/changelog-section.sh X.Y.Z` | متن یک بخش CHANGELOG |
| `tools/release/staging-verify.sh` | دروازهٔ staging و پوشهٔ شواهد |
| `tools/release/security-check.sh` | بازبینی امنیتی خودکار + الگوی امضا |
| `tools/release/build-edge-bundle.sh vX.Y.Z [--from-tag]` | بستهٔ لبهٔ قطعی + `.sha256` |
| `tools/release/fetch-edge-release.sh vX.Y.Z --dir D` | دانلود و بررسی بستهٔ منتشرشده برای `EDGE_RELEASES_DIR` |
| `tools/release/check-meta.sh` | همان بررسی کار CI `release-meta` |
| `.github/workflows/release-platform.yml` | آزمون، ساخت بسته و Release پیش‌نویس با برچسب `v*` |
