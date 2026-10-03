# پایش و هشدار (Monitoring) — CDN پاسارگاد

این سند راه‌اندازی **پشتهٔ پایش** (Prometheus + Alertmanager + Grafana + پروب‌های blackbox) در
`deploy/monitoring/` و **صفحهٔ وضعیت عمومی روی میزبان جداگانه** در `deploy/status/` را توضیح می‌دهد.
هشدارهای داخلی خودِ کنترلر (تلگرام/ایمیل، [OPERATIONS.md §۲](OPERATIONS.md)) و `GET /healthz/deep`
([OPERATIONS.md §۷](OPERATIONS.md)) سر جای خود می‌مانند؛ این پشته **مستقل از سرور مرکزی** است و دقیقاً
وقتی به کار می‌آید که خود کنترلر (و در نتیجه هشدارهایش) از کار افتاده است.

## فهرست

- [۱. معماری](#۱-معماری)
- [۲. راه‌اندازی سریع](#۲-راهاندازی-سریع)
- [۳. متغیرهای `.env`](#۳-متغیرهای-env)
- [۴. منابع داده](#۴-منابع-داده)
- [۵. داشبوردها](#۵-داشبوردها)
- [۶. هشدارها و مسیر ارسال](#۶-هشدارها-و-مسیر-ارسال)
- [۷. صفحهٔ وضعیت جداگانه](#۷-صفحهٔ-وضعیت-جداگانه)
- [۸. اعتبارسنجی و CI](#۸-اعتبارسنجی-و-ci)
- [۹. عیب‌یابی](#۹-عیبیابی)
- [۱۰. محدودیت‌ها](#۱۰-محدودیتها)

## ۱. معماری

```
   میزبان پایش (جدا از سرور مرکزی)                         سرور مرکزی (docker-compose.yml اصلی)
 ┌──────────────────────────────────────────┐            ┌─────────────────────────────────┐
 │ Prometheus ──HTTPS + Bearer METRICS_TOKEN──────────────▶ Caddy ─▶ controller GET /metrics │
 │     │      ──blackbox: /healthz, /healthz/deep, /status.json ─▶                           │
 │     │      ──(اختیاری) json-exporter ─ Bearer ADMIN_API_KEY ─▶ /api/v1/overview, analytics │
 │     ▼                                    │            └─────────────────────────────────┘
 │ Alertmanager ─▶ تلگرام (یا رلهٔ آن) / ایمیل │
 │ Grafana (127.0.0.1:3000) ◀── داشبوردهای provisioned                                   │
 └──────────────────────────────────────────┘
   میزبان صفحهٔ وضعیت (دامنه و ترجیحاً DNS جدا)
 ┌──────────────────────────────────────────┐
 │ mirror ──هر ۲۰ ثانیه──▶ controller /status.json (و standby) │
 │ Caddy (HTTPS) ◀── بازدیدکنندگان: آخرین وضعیت شناخته‌شده      │
 └──────────────────────────────────────────┘
```

- **چرا میزبان جدا؟** اگر Prometheus روی همان سروری باشد که از کار افتاده، هشدار «کنترلر در دسترس نیست»
  هرگز ارسال نمی‌شود. یک VPS کوچک (۱ هسته، ۱ تا ۲ گیگابایت RAM) کافی است؛ بهتر است در دیتاسنتر یا
  کشور دیگری باشد. میزبان پایش و میزبان صفحهٔ وضعیت می‌توانند یکی باشند.
- **هیچ دادهٔ مشتری‌ای وارد Prometheus نمی‌شود:** `/metrics` فقط شمارش‌های کل پلتفرم را می‌دهد
  (SPEC §13.1) و پل اختیاری admin-API فقط فیلدهای مشخص‌شده در `json-exporter/config.yml` را تبدیل
  می‌کند (نام نود و گروه به‌عنوان برچسب؛ هیچ دامنه یا IP).

## ۲. راه‌اندازی سریع

پیش‌نیاز: Docker و **Docker Compose نسخهٔ 2.23 یا بالاتر** (برای `secrets` از متغیر محیطی).

روی سرور مرکزی (یک‌بار): در `.env` اصلی یک توکن برای `/metrics` بگذارید و کنترلر را دوباره بالا بیاورید:

```sh
openssl rand -hex 32        # مقدار را در METRICS_TOKEN=... بگذارید
docker compose up -d
```

روی میزبان پایش:

```sh
git clone <repo> && cd <repo>/deploy/monitoring
cp .env.example .env && chmod 600 .env
$EDITOR .env        # CONTROLLER_URL، METRICS_TOKEN، GRAFANA_ADMIN_PASSWORD، تلگرام/ایمیل
docker compose up -d
docker compose ps
```

- Grafana: `http://127.0.0.1:3000` (فقط روی loopback). از بیرون با تونل SSH:
  `ssh -L 3000:127.0.0.1:3000 monitor-host` یا پشت یک reverse proxy با TLS و احراز هویت.
- Prometheus: `127.0.0.1:9090` و Alertmanager: `127.0.0.1:9093` (همین‌طور فقط loopback).
- داشبوردها در پوشهٔ **Pasargad CDN** هستند و داشبورد «Platform overview» صفحهٔ خانه است.

اگر پایش را روی همان سرور مرکزی می‌خواهید (مثلاً در محیط آزمایشی)، از شبکهٔ Docker استفاده کنید:

```sh
# .env:  CONTROLLER_URL=http://controller:8000   MAIN_STACK_NETWORK=whmcs-cdn_default
docker compose -f docker-compose.yml -f same-host.override.yml up -d
```

## ۳. متغیرهای `.env`

| متغیر | پیش‌فرض | توضیح |
|---|---|---|
| `CONTROLLER_URL` | — (الزامی) | آدرس پایهٔ API کنترلر، مثل `https://cdn-api.example.com` |
| `METRICS_TOKEN` | خالی | همان مقدار `METRICS_TOKEN` در `.env` سرور مرکزی (خالی یعنی `/metrics` باز است) |
| `STATUS_PAGE_URL` | خالی | آدرس صفحهٔ وضعیت جداگانه برای پروب |
| `PROBE_EXTRA_URLS` | خالی | آدرس‌های HTTPS دیگر برای پروب (با فاصله)، مثل کنترلر standby یا WHMCS |
| `PCDN_API_BRIDGE` | `0` | `1` = فعال‌سازی پل admin-API (همراه با `--profile api-bridge`) |
| `PCDN_ADMIN_API_KEY` | خالی | فقط برای پل؛ همان `ADMIN_API_KEY` کنترلر (هشدار بخش ۴.۳) |
| `TELEGRAM_BOT_TOKEN`، `TELEGRAM_CHAT_ID` | خالی | ربات و شناسهٔ عددی گفتگو (چند شناسه با ویرگول؛ گروه‌ها منفی‌اند) |
| `TELEGRAM_API_URL` | `https://api.telegram.org` | رله/پروکسی API تلگرام (مثل `TELEGRAM_API_URL` کنترلر) |
| `ALERT_HTTPS_PROXY` | خالی | پروکسی خروجی برای ارسال تلگرام |
| `ALERT_EMAIL_TO`، `SMTP_SMARTHOST`، `SMTP_FROM` | خالی | هر سه لازم‌اند تا ایمیل فعال شود |
| `SMTP_USERNAME`، `SMTP_PASSWORD`، `SMTP_REQUIRE_TLS` | خالی / `true` | احراز هویت SMTP |
| `GRAFANA_ADMIN_PASSWORD` | — (الزامی) | رمز کاربر `admin` در Grafana |
| `GRAFANA_URL` | `http://127.0.0.1:3000` | آدرس عمومی Grafana (در صورت reverse proxy) |
| `PROMETHEUS_RETENTION` | `30d` | مدت نگه‌داری داده |

**اسرار:** `METRICS_TOKEN`، `TELEGRAM_BOT_TOKEN`، `SMTP_PASSWORD`، `GRAFANA_ADMIN_PASSWORD` و
`PCDN_ADMIN_API_KEY` فقط به‌صورت فایل در `/run/secrets/*` به کانتینر مربوطه داده می‌شوند و هیچ‌وقت در
فایل پیکربندی نوشته نمی‌شوند (Prometheus از `credentials_file`، Alertmanager از `bot_token_file` و
`smtp_auth_password_file` استفاده می‌کند). `.env` در `.gitignore` است؛ آن را commit نکنید و در
پشتیبان بدون رمز نگذارید ([SECURITY.md](SECURITY.md)).

## ۴. منابع داده

### ۴.۱ `GET /metrics` کنترلر (همیشه)

از `controller/app/routes_metrics.py`؛ همه gauge هستند مگر خلاف آن ذکر شود:

| سری | معنی |
|---|---|
| `pcdn_edges_total`، `pcdn_edges_online` | نودهای ثبت‌شده / نودهای فعالِ دیده‌شده در `EDGE_OFFLINE_SECONDS` |
| `pcdn_edges_shed`، `pcdn_edges_probe_failing` | نودهای خارج‌شده از DNS به‌علت بار / نودهایی که پروب سلامت را رد می‌کنند |
| `pcdn_sites_total`، `pcdn_sites{status}` | سایت‌ها و وضعیت مؤثرشان (`active`، `suspended`، `over_quota`، ...) |
| `pcdn_ssl_certificates{status}` | گواهی‌ها بر حسب `none`/`pending`/`active`/`failed` |
| `pcdn_ssl_certs_expiring` | گواهی‌هایی که در `ALERT_CERT_DAYS` منقضی می‌شوند |
| `pcdn_scheduler_last_run_age_seconds` | ثانیه از آخرین اجرای زمان‌بند (leader) |
| `pcdn_scheduler_job_last_run_age_seconds{job}` | برای هر کار؛ در Prometheus برچسب `job` به `exported_job` تغییر نام می‌دهد |
| `pcdn_dns_last_sync_age_seconds`، `pcdn_dns_sync_errors` | تازگی همگام‌سازی DNS و خطاهای باز PowerDNS |
| `pcdn_usage_batches_ingested_total` (counter) | گزارش‌های مصرف پذیرفته‌شده از نودها |
| `pcdn_backup_last_success_age_seconds` | ثانیه از آخرین پشتیبان موفق (اگر هرگز موفق نشده، سری وجود ندارد) |
| `pcdn_active_alerts`، `pcdn_active_alerts_by_severity{severity}` | هشدارهای باز خود کنترلر |
| `pcdn_audit_log_entries` | تعداد ردیف‌های لاگ حسابرسی |
| `pcdn_webhook_deliveries{status}` | تحویل‌های وب‌هوک `pending`/`failed` (۷ روز اخیر) |
| `pcdn_log_export_pending_records` | رکوردهای لاگ در صف آپلود به باکت مشتری |
| `pcdn_edges_draining`، `pcdn_edges_tunnel_degraded` | موج ۱۳: نودهای در حال تخلیه (بیرون از DNS) / نودهایی که پروب داخلی تونلشان پیاپی رد می‌شود |
| `pcdn_edge_reloads_1h{edge}` | موج ۱۳: بارگذاری مجدد nginx در ساعت گذشته‌ی هر نود آنلاین (برچسب فقط **نام** نود، هرگز آدرس) |
| `pcdn_edge_draining_workers{edge}` | موج ۱۳: نسل‌های کارگر nginx که هنوز در حال خاموش شدن‌اند (برای هر نود آنلاینی که گزارش می‌دهد) |

### ۴.۲ پروب‌های blackbox (همیشه)

از میزبان پایش: `CONTROLLER_URL/healthz` (زنده بودن)، `/healthz/deep` (باید `"status": "ok"` و کد 200
بدهد)، `/status.json`، صفحهٔ وضعیت جداگانه و `PROBE_EXTRA_URLS`. سری‌ها: `probe_success`،
`probe_duration_seconds`، `probe_ssl_earliest_cert_expiry` (انقضای گواهی TLS دامنهٔ کنترلر).

### ۴.۳ پل admin-API (اختیاری، پروفایل `api-bridge`)

بار هر نود، درصد ظرفیت، uptime، ترافیک، نسبت cache و رخدادهای امنیتی در `/metrics` نیستند (عمداً، چون
`/metrics` فقط تجمیعی است). پل `json-exporter` این فیلدها را از `GET /api/v1/overview` (هر ۲ دقیقه) و
`GET /api/v1/analytics?period=24h` (هر ۵ دقیقه) به سری‌های `pcdn_api_*` تبدیل می‌کند:

- هر نود (`edge`، `edge_id`، `group`): `pcdn_api_edge_{enabled,online,shed,capacity_mbps,rx_mbps,tx_mbps,connections,load1,cpus,uptime_24h_percent,uptime_30d_percent}`
- هر گروه نود: `pcdn_api_group_{p95_mbps,capacity_mbps,capacity_used_percent}` (p95 سه‌روزه، SPEC §15.5)
- کل پلتفرم: `pcdn_api_edges_*`، `pcdn_api_month_{bytes,requests}`، `pcdn_api_24h_{requests,bytes,cache_hits}`،
  `pcdn_api_24h_status_requests_{2xx,3xx,4xx,5xx}`، `pcdn_api_24h_security_events_{waf,firewall,ratelimit,challenge,ddos,hotlink,bots}`،
  `pcdn_api_last_hour_{requests,bytes,cache_hits}` و `pcdn_api_last_hour_security_events_total`

> **هشدار امنیتی:** این پل به `ADMIN_API_KEY` نیاز دارد که **کنترل کامل CDN** را می‌دهد (کنترلر کلید
> فقط‌خواندنی ندارد). فقط روی میزبان پایشِ سخت‌شده فعالش کنید، پورت‌ها را فقط روی loopback نگه دارید و
> اگر میزبان پایش به خطر افتاد کلید را بچرخانید. بدون این پروفایل، پنل‌های مربوطه «No data» نشان
> می‌دهند و باقی پایش کامل کار می‌کند.

```sh
# .env:  PCDN_API_BRIDGE=1   PCDN_ADMIN_API_KEY=...
docker compose --profile api-bridge up -d
docker compose restart prometheus     # تا اهداف پل از نو ساخته شوند
```

json-exporter برای فیلدهای `null` (نودی که هنوز متریک نفرستاده، ظرفیت نامعلوم) در هر scrape خطای
«Failed to extract/convert value» در لاگ می‌نویسد؛ این عادی است و آن سری فقط ساخته نمی‌شود.

## ۵. داشبوردها

| داشبورد | منبع | محتوا |
|---|---|---|
| Platform overview | `/metrics` + پروب | وضعیت کنترلر از بیرون، `/healthz/deep`، سن زمان‌بند/DNS/پشتیبان، شمار نودها و سایت‌ها، SSL، هشدارهای باز، تأخیر پروب، هشدارهای فعال Prometheus |
| Edges | `/metrics` + پل | آنلاین/ثبت‌شده/shed، جدول هر نود (آنلاین، درصد ظرفیت، tx/rx، اتصال‌ها، load به ازای CPU، uptime ۲۴ساعت/۳۰روز)، p95 گروه‌ها |
| Traffic & cache | پل + `/metrics` | درخواست و ترافیک ۲۴ ساعت و ماه، نسبت cache، نسبت 5xx، کلاس‌های وضعیت، نرخ دریافت گزارش مصرف |
| Security events | پل | رخدادهای امنیتی ۲۴ ساعت بر حسب منبع، رخدادهای ساعت اخیر، نسبت 4xx |
| Tunnel quality | پل | نودهای گروه `tunnel`: آنلاین، بار، uptime، p95 در برابر ظرفیت |
| Webhooks, log export & jobs | `/metrics` | صف وب‌هوک، صف خروجی لاگ، سن هر کار زمان‌بندی‌شده، پشتیبان، DNS |

داشبوردها فایل JSON تولیدشده‌اند: برای تغییر، `deploy/monitoring/tools/gen_dashboards.py` را ویرایش و
اجرا کنید (ویرایش در UI ذخیره نمی‌شود؛ `allowUiUpdates: false`).

## ۶. هشدارها و مسیر ارسال

قوانین در `deploy/monitoring/prometheus/rules/pcdn-alerts.yml` (متن فارسی) و آزمون‌های واحدشان در
`prometheus/tests/` هستند.

| هشدار | شرط | شدت |
|---|---|---|
| `PcdnControllerDown` | پروب `/healthz` از بیرون ۲ دقیقه شکست | critical |
| `PcdnControllerScrapeFailing` | `up{job="pcdn-controller"} == 0` به مدت ۳ دقیقه (اغلب توکن اشتباه = 401) | critical |
| `PcdnControllerMetricsAbsent` / `…Incomplete` | هدفی تعریف نشده / `/metrics` بدون شمارش نودها (خطای دیتابیس) | warning |
| `PcdnDeepHealthDegraded` | `/healthz/deep` ده دقیقه `ok` نیست | warning |
| `PcdnControllerProbeErrorRatioHigh` | بیش از ۲۰٪ پروب‌های کنترلر در ۱۵ دقیقه شکست | warning |
| `PcdnControllerTlsExpiring` | گواهی TLS کنترلر کمتر از ۱۴ روز | warning |
| `PcdnSchedulerStalled` / `PcdnSchedulerJobFailing` | زمان‌بند > ۱۰ دقیقه اجرا نشده / یک کار > ۱۵ دقیقه موفق نشده | critical / warning |
| `PcdnEdgesAllOffline` | هیچ نود آنلاینی نیست | critical |
| `PcdnEdgesOffline` | نودهای آنلاین کمتر از بیشینهٔ یک ساعت اخیر | warning |
| `PcdnEdgesProbeFailing` / `PcdnEdgesShed` | نود heartbeat دارد ولی پروب رد / نود به‌علت بار shed شده | warning |
| `PcdnDnsSyncStale` / `PcdnDnsSyncErrors` | DNS > ۱۵ دقیقه همگام نشده / خطای باز PowerDNS | warning |
| `PcdnCertificatesFailed` / `…FailedRising` / `…Expiring` | گواهی شکست‌خورده / ≥۵ شکست در ساعت / در حال انقضا | warning |
| `PcdnBackupStale` / `PcdnBackupVeryStale` / `PcdnBackupNeverSucceeded` | پشتیبان > ۲۶ ساعت / > ۵۰ ساعت / هرگز | warning / critical / warning |
| `PcdnWebhookBacklog` / `PcdnWebhookFailuresRising` | > ۵۰۰ در صف / > ۵۰ شکست در ساعت | warning / info |
| `PcdnLogExportBacklog` | > یک میلیون رکورد و رو به رشد | warning |
| `PcdnControllerCriticalAlertsOpen` | هشدار بحرانی باز در خود کنترلر | info |
| `PcdnStatusPageDown` / `PcdnPublicStatusJsonDown` | صفحهٔ وضعیت جداگانه / `/status.json` کنترلر | warning |
| `PcdnEdgeOffline` (پل) | نود مشخص فعال است ولی آفلاین | warning |
| `PcdnEdgeLoadHigh` (پل) | بیشینهٔ rx/tx بیش از ۸۵٪ `capacity_mbps` به مدت ۱۵ دقیقه | warning |
| `PcdnGroupCapacityHigh` (پل) | p95 سه‌روزهٔ گروه > ۸۰٪ ظرفیت | warning |
| `PcdnEdgeUptimeLow` (پل) | uptime ۲۴ ساعتهٔ نود < ۹۵٪ | info |
| `PcdnErrorRatioHigh` (پل) | نسبت 5xx ِ ۲۴ ساعت غلتان > ۵٪ (با حداقل ۱۰۰۰ درخواست) | warning |
| `PcdnApiBridgeFailing` (پل) | json-exporter داده نمی‌گیرد | warning |

**هشدارهای داخلی کنترلر در موج ۱۳ (SPEC §22)** — مثل بقیه‌ی هشدارهای کنترلر از تلگرام/ایمیل خود کنترلر
فرستاده می‌شوند و در `pcdn_active_alerts` شمرده می‌شوند:

| کلید | شرط | شدت |
|---|---|---|
| `edge_tunnel_degraded:<id>` | «مسیر تونل نود X خراب است (پروب داخلی)»: `TUNNEL_PROBE_FAIL_CHECKS` گزارش ناموفق پیاپی پروب داخلی؛ با بازگشت (`TUNNEL_PROBE_OK_CHECKS` گزارش موفق و ≥ ۱۰ دقیقه) بسته می‌شود | warning |
| `edge_reload_storm:<id>` | بیش از ۱۲ بارگذاری مجدد در ساعت در ۳ heartbeat پیاپی؛ با ≤ ۶ بسته می‌شود | warning |
| `edge_draining_pileup:<id>` | `draining_workers` بیش از ۴ × تعداد هسته در ۵ heartbeat پیاپی | warning |
| `edge_tuning:<id>` | بررسی تنظیمات هسته‌ی نود (sysctl/qdisc/nofile) در ≥ ۳ heartbeat ناموفق | info |
| `edge_drain_stuck:<id>` | تخلیه‌ای که `DRAIN_MAX_HOLD_MINUTES` بعد از پایانش هنوز باز بود خودکار لغو شد؛ با تخلیه/لغو بعدی همان نود بسته می‌شود | warning |

**مسیرها (Alertmanager):** همه به گیرندهٔ `pcdn` (تلگرام + ایمیل)؛ `critical` با `repeat_interval` یک
ساعته؛ `info` فقط به تلگرام (یا ایمیل اگر تلگرام نیست) و روزی یک‌بار. قواعد inhibit: وقتی کنترلر در
دسترس نیست هشدارهای برگرفته از `/metrics` (`source="metrics"`) ساکت می‌شوند؛ «همهٔ نودها آفلاین»
هشدارهای تک‌نود را می‌پوشاند.

`alertmanager.yml` هنگام شروع کانتینر از روی محیط توسط `render-config.sh` ساخته می‌شود: اگر توکن ربات
یا `TELEGRAM_CHAT_ID` خالی باشد تلگرام، و اگر یکی از `ALERT_EMAIL_TO`/`SMTP_SMARTHOST`/`SMTP_FROM`
خالی باشد ایمیل حذف می‌شود (بدون هیچ کانالی، هشدارها فقط در UI دیده می‌شوند و در لاگ هشدار ثبت می‌شود).

**تلگرام از ایران:** مانند کنترلر ([OPERATIONS.md §۲](OPERATIONS.md))، یا `TELEGRAM_API_URL` را روی یک
رله بگذارید یا `ALERT_HTTPS_PROXY` را تنظیم کنید. اگر میزبان پایش بیرون از ایران است معمولاً هیچ‌کدام
لازم نیست — دلیل دیگری برای جدا بودن آن.

آزمایش دستی یک هشدار:

```sh
docker compose exec alertmanager amtool alert add alertname=PcdnTest severity=warning \
  --annotation=summary="آزمایش مسیر هشدار" --alertmanager.url=http://127.0.0.1:9093
```

## ۷. صفحهٔ وضعیت جداگانه

صفحهٔ `status/` اگر روی همان سرور مرکزی میزبانی شود، درست وقتی همه‌چیز خراب است خودش هم باز نمی‌شود.
`deploy/status/` آن را روی **میزبان و دامنهٔ جدا** بالا می‌آورد:

- سرویس `mirror` هر `MIRROR_INTERVAL` ثانیه (پیش‌فرض ۲۰) `/status.json` را از اولین آدرس در دسترسِ
  `STATUS_UPSTREAMS` می‌گیرد (مثلاً اول کنترلر اصلی، بعد standby در HA)، نوع فیلدها را بررسی می‌کند،
  **فقط فیلدهای عمومی** (وضعیت، اجزا، شمار نودها، رخدادها) را نگه می‌دارد و فایل را اتمیک جایگزین می‌کند.
- اگر هیچ upstreamی پاسخ ندهد، `status.json` قبلی **دست نمی‌خورد** (آخرین وضعیت شناخته‌شده) و فقط
  `mirror.json` (`ok`، `checked_at`، `last_ok_at`) به‌روز می‌شود. این داده روی volume است و پس از
  ری‌استارت هم باقی می‌ماند. جزئیات خطا و آدرس upstreamها فقط در لاگ است، نه در فایل عمومی.
- `mirror.js` به صفحه اضافه می‌شود (فایل‌های `status/` تغییر نمی‌کنند؛ هنگام شروع کپی و یک خط
  `<script>` اضافه می‌شود) و وقتی داده کهنه است اعلان «ارتباط با سرور وضعیت موقتاً برقرار نیست؛ آخرین
  وضعیت شناخته‌شده (دریافت‌شده X دقیقه پیش) نمایش داده می‌شود» را نشان می‌دهد.
- Caddy گواهی را خودکار می‌گیرد، `status.json` را با `max-age=10` و `stale-if-error` سرو می‌کند و CSP
  سخت‌گیرانه (`default-src 'none'`، فقط اسکریپت و استایل از همان مبدأ) دارد.

```sh
cd deploy/status
cp .env.example .env     # STATUS_DOMAIN=status.example.net  STATUS_UPSTREAMS="https://cdn-api.example.com https://standby.example.com"
docker compose up -d --build
docker compose logs -f mirror
```

نکته‌ها:

1. رکورد DNS دامنهٔ صفحهٔ وضعیت را نزد **ارائه‌دهندهٔ DNS دیگری** (نه ns1/ns2 خود CDN) بگذارید؛ وگرنه با
   قطع PowerDNS صفحه هم resolve نمی‌شود.
2. کنترلر برای `/status.json` هدر `Cache-Control: no-store` می‌دهد و mirror با فاصلهٔ ۲۰ ثانیه می‌خواند؛
   بار روی کنترلر ناچیز است و بازدیدکنندگان هرگز مستقیم به کنترلر وصل نمی‌شوند.
3. بدون Docker: `mirror.sh` (نیاز به `curl` و `jq`) را با systemd یا cron اجرا کنید
   (`SRC_DIR=/path/status WWW_DIR=/var/www/status DATA_DIR=/var/www/status-data MIRROR_JS=/path/deploy/status/mirror.js STATUS_UPSTREAMS=... mirror.sh`)
   و همان `Caddyfile` را با مسیرهای خودتان استفاده کنید. برای میزبان کاملاً ایستا (آبجکت‌استوریج)،
   `mirror.sh --once` را در cron اجرا و پوشهٔ خروجی را همگام کنید.
4. در `deploy/monitoring/.env` مقدار `STATUS_PAGE_URL` را بگذارید تا خود صفحه هم پایش شود.

## ۸. اعتبارسنجی و CI

```sh
# پیکربندی‌ها و آزمون‌های قوانین (promtool از انتشار Prometheus 3.x)
cd deploy/monitoring
promtool check rules prometheus/rules/*.yml
(cd prometheus && promtool test rules tests/pcdn-alerts.test.yml)
docker compose --env-file .env.example config -q

# داشبوردها: JSON معتبر، uid یکتا، datasource درست، همهٔ سری‌های pcdn_* واقعاً وجود دارند،
# همهٔ عبارت‌های PromQL parse می‌شوند و JSONها با تولیدکننده یکی‌اند
PROMTOOL=$(which promtool) python3 tools/check_monitoring.py

# Alertmanager: پیکربندی تولیدشده را با amtool بررسی کنید
RENDER_ONLY=1 RENDER_DIR=/tmp/am SECRETS_DIR=/tmp/sec sh render-config.sh alertmanager
amtool check-config /tmp/am/alertmanager.yml
```

`check_monitoring.py` نام‌های سری را مستقیم از `controller/app/routes_metrics.py` و
`json-exporter/config.yml` می‌خواند؛ اگر متریکی در کنترلر تغییر نام دهد، CI شکست می‌خورد.

## ۸ب. موج ۱۴ — هشدارها و متریک‌های جدید (SPEC §23)

| هشدار | شدت | معنا |
|---|---|---|
| `rollout_blocked:<id>` | هشدار (بحرانی هنگام بازگردانی) | انتشار به آخرین نود یک استخر رسید و متوقف شد |
| `rollout_failed:<id>` | بحرانی | نودی در پایش رد شد؛ بازگردانی خودکار (با `rolled_back` رفع می‌شود) |
| `backup_not_offsite` / `backup_unencrypted_offsite` | اطلاع / هشدار | پشتیبان فقط محلی است / بدون رمز به S3 می‌رود |
| `backup_verify_failed` / `backup_verify_partial` | بحرانی / اطلاع | آزمون بازیابی هفتگی ناموفق / دو هفته فقط جزئی |
| `provision_proposed:<group>` / `provision_failed:<id>` | اطلاع / هشدار | پیشنهاد نود جدید / اجرای terraform ناموفق |
| `abuse_overdue:<id>` | هشدار | مهلت مالک برای رسیدگی به گزارش تخلف گذشت |
| `slo_burn_fast:<g>:<sli>` | بحرانی | نرخ مصرف بودجه ≥ ۱۴٫۴ در ۱ ساعت و ۵ دقیقه |
| `slo_burn_slow:<g>:<sli>` | هشدار | نرخ مصرف ≥ ۶ در ۶ ساعت و ۳۰ دقیقه |
| `slo_budget_exhausted:<g>:<sli>` | هشدار | بودجهٔ خطای ماه تمام شد |

هشدار SLO فقط با نمونهٔ کافی باز می‌شود (۳۰ تیک در ۱ ساعت برای سریع، ۱۸۰ در ۶ ساعت برای کند، ۱۰۰۰ درخواست برای
خطاها) و با پایین آمدن پنجرهٔ کوتاه رفع می‌شود. یا این هشدارها یا قواعد `pcdn-slo.yml` را pager کنید، نه هر دو.

متریک‌ها: `pcdn_build_info{version}`، `pcdn_rollout_state{rollout,state}`، `pcdn_rollout_edges{state}`،
`pcdn_slo_objective{group,sli}`، `pcdn_slo_ratio{group,sli,window="30d"|"month"}`،
`pcdn_slo_error_budget_remaining{group,sli}`، `pcdn_slo_burn_rate{group,sli,window="5m"|"30m"|"1h"|"6h"}`.
SLIها: دسترس‌پذیری (هر تیک پروب: در هر استخر منطقه دست‌کم یک نود فعال و غیرتخلیه سالم)، تأخیر (پروب‌های
موفق ≤ `SLO_LATENCY_MS`) و خطا (`pe` دقیقه‌ای، در نبود آن خطاهای پلتفرم ساعتی). هدف‌ها: `SLO_AVAILABILITY`،
`SLO_LATENCY`، `SLO_ERRORS`، `SLO_OVERRIDES`. `/healthz/deep` حالا `version`، `environment` و
`backup.verify_age_s|verify_ok|offsite` دارد.

## ۹. عیب‌یابی

| نشانه | علت محتمل |
|---|---|
| `PcdnControllerScrapeFailing` ولی `/healthz` سالم | `METRICS_TOKEN` دو طرف یکی نیست (401). `curl -H "Authorization: Bearer $T" $CONTROLLER_URL/metrics` |
| همهٔ پنل‌های پل «No data» | پروفایل `api-bridge` یا `PCDN_API_BRIDGE=1` فعال نیست؛ `docker compose logs json-exporter` |
| کانتینر Prometheus بالا نمی‌آید | `CONTROLLER_URL` خالی/نامعتبر؛ `docker compose logs prometheus` (پیام `render-config:`) |
| هیچ پیامی در تلگرام نمی‌آید | `docker compose logs alertmanager`؛ `telegram=0` یعنی توکن یا chat id خالی است؛ دسترسی به `api.telegram.org` |
| `secret ... environment` خطا می‌دهد | Docker Compose قدیمی است (< 2.23)؛ به‌روز کنید |
| صفحهٔ وضعیت همیشه اعلان کهنگی دارد | `docker compose logs mirror` در `deploy/status`: upstream در دسترس نیست یا JSON نامعتبر است |

## ۱۰. محدودیت‌ها

- `/metrics` کنترلر هیچ متریکی برای **کیفیت تونل هر سایت** (RTT مبدأ، اتصال مجدد)، **صف‌های فضای
  ذخیره‌سازی (MinIO)** یا **نرخ خطای HTTP خود کنترلر** ندارد؛ داشبوردها چیزی برای این‌ها جعل نمی‌کنند.
  کیفیت تونل به ازای هر سایت در پنل مدیریت و `GET /api/v1/sites/{domain}/tunnel/stats` است. برای MinIO
  می‌توان `/minio/v2/metrics/cluster` را با توکن `mc admin prometheus generate` به‌عنوان job جدا اضافه کرد
  ([STORAGE.md](STORAGE.md)).
- نسبت خطا و رخدادهای امنیتی از پنجرهٔ غلتان ۲۴ ساعته و «آخرین ساعت کامل» API می‌آیند، نه از شمارنده‌های
  لحظه‌ای؛ هشدارها کند (ده‌ها دقیقه) واکنش نشان می‌دهند.
- `pcdn_edges_total` نودهای غیرفعال را هم می‌شمارد؛ بدون پل، هشدار «نود آفلاین» نسبت به بیشینهٔ یک ساعت
  اخیر سنجیده می‌شود و نام نود را نمی‌داند.
