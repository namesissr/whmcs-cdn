# مستندات CDN پاسارگاد

شبکهٔ توزیع محتوای اختصاصی **پاسارگاد میزبان**: کنترلر مرکزی، نودهای لبه، DNS ژئو، ماژول‌های WHMCS،
API مشتری، CLI و Terraform. این سایت مستقیماً از پوشهٔ `docs/` مخزن ساخته می‌شود.

## از کجا شروع کنم؟

| می‌خواهم… | سند |
|---|---|
| سامانه را از صفر راه‌اندازی کنم | [راه‌اندازی (README)](getting-started.md) و [معماری](ARCHITECTURE.md) |
| نسخهٔ جدید را روی سیستم در حال کار اعمال کنم | [به‌روزرسانی](UPGRADE.md) |
| سرور مرکزی را نگه‌داری کنم (هشدار، پشتیبان، HA) | [راهنمای عملیات](OPERATIONS.md) |
| Prometheus/Grafana و صفحهٔ وضعیت جداگانه داشته باشم | [پایش و هشدار](MONITORING.md) |
| نود لبه اضافه یا عیب‌یابی کنم | [عملیات نودها](NODES.md) و [Edge node](EDGE.md) |
| CDN را در WHMCS بفروشم | [WHMCS](WHMCS.md) |
| با API، CLI یا Terraform کار کنم | [API](API.md)، [CLI](CLI.md)، [Terraform](TERRAFORM.md) |
| سامانه را سخت‌سازی کنم | [امنیت](SECURITY.md) |
| پس از خرابی بازیابی کنم | [بازیابی از فاجعه](DISASTER_RECOVERY.md) |
| ظرفیت نودها را بسنجم | [آزمون بار](LOADTEST.md) |
| فضای ذخیره‌سازی ابری راه بیندازم | [فضای ذخیره‌سازی](STORAGE.md) |

قرارداد داخلی بین اجزا (انگلیسی) در [SPEC](SPEC.md) است.

## ساخت همین سایت

```sh
pip install -r docs-site/requirements.txt
mkdocs serve              # پیش‌نمایش در http://127.0.0.1:8000
mkdocs build --strict     # خروجی در docs-site/_build/
```
