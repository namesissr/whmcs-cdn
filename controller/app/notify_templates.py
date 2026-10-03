"""Customer notification texts (SPEC §23.5), fa + en, plain text. SMS texts stay ≤ 300 characters (the
provider splits longer messages). They never contain a node name, a node address or the billing
system's name; the brand comes from NOTIFY_BRAND (default «پاسارگاد CDN» / "Pasargad CDN")."""

from .config import settings

_FA_DIGITS = str.maketrans("0123456789", "۰۱۲۳۴۵۶۷۸۹")
SMS_MAX = 300

# event -> lang -> (subject, text)
TEMPLATES: dict[str, dict[str, tuple[str, str]]] = {
    "origin.down": {
        "fa": ("سرور اصلی {domain} پاسخ نمی‌دهد", "{brand}: سرور اصلی {domain} پاسخ نمی‌دهد (از {time}). جزئیات در پنل."),
        "en": ("The origin of {domain} is not responding",
               "{brand}: the origin server of {domain} is not responding (since {time}). Details in your panel."),
    },
    "origin.up": {
        "fa": ("سرور اصلی {domain} دوباره پاسخ می‌دهد", "{brand}: سرور اصلی {domain} دوباره پاسخ می‌دهد ({time})."),
        "en": ("The origin of {domain} is back", "{brand}: the origin server of {domain} is responding again ({time})."),
    },
    "tunnel.origin_down": {
        "fa": ("مقصد تونل {domain} در دسترس نیست", "{brand}: مقصد تونل {domain} در دسترس نیست (از {time}). جزئیات در پنل."),
        "en": ("The tunnel origin of {domain} is down",
               "{brand}: the tunnel origin of {domain} is unreachable (since {time}). Details in your panel."),
    },
    "tunnel.origin_up": {
        "fa": ("مقصد تونل {domain} دوباره در دسترس است", "{brand}: مقصد تونل {domain} دوباره در دسترس است ({time})."),
        "en": ("The tunnel origin of {domain} is back", "{brand}: the tunnel origin of {domain} is reachable again ({time})."),
    },
    "quota.warning": {
        "fa": ("۸۰٪ ترافیک ماهانهٔ {domain} مصرف شد", "{brand}: ۸۰٪ ترافیک ماهانهٔ {domain} مصرف شد."),
        "en": ("80% of the monthly traffic of {domain} used", "{brand}: 80% of the monthly traffic of {domain} has been used."),
    },
    "quota.exceeded": {
        "fa": ("ترافیک ماهانهٔ {domain} تمام شد", "{brand}: ترافیک ماهانهٔ {domain} تمام شد. برای ادامه، بستهٔ خود را ارتقا دهید."),
        "en": ("The monthly traffic of {domain} is used up",
               "{brand}: the monthly traffic of {domain} is used up. Upgrade your plan to continue."),
    },
    "ssl.expiring": {
        "fa": ("گواهی SSL {domain} به‌زودی منقضی می‌شود", "{brand}: گواهی SSL {domain} تا {days} روز دیگر منقضی می‌شود."),
        "en": ("The SSL certificate of {domain} expires soon", "{brand}: the SSL certificate of {domain} expires in {days} days."),
    },
    "ssl.failed": {
        "fa": ("صدور گواهی SSL {domain} ناموفق بود", "{brand}: صدور گواهی SSL {domain} ناموفق بود. جزئیات در پنل."),
        "en": ("SSL certificate for {domain} failed", "{brand}: issuing the SSL certificate of {domain} failed. Details in your panel."),
    },
    "attack.detected": {
        "fa": ("حمله به {domain} شناسایی شد", "{brand}: حجم بالای درخواست‌های مسدودشده برای {domain} شناسایی شد ({time})."),
        "en": ("Attack detected on {domain}", "{brand}: a high volume of blocked requests was detected for {domain} ({time})."),
    },
    "site.suspended": {
        "fa": ("سرویس {domain} معلق شد", "{brand}: سرویس {domain} معلق شد. جزئیات در پنل."),
        "en": ("{domain} was suspended", "{brand}: the service {domain} was suspended. Details in your panel."),
    },
    "site.unsuspended": {
        "fa": ("سرویس {domain} دوباره فعال شد", "{brand}: سرویس {domain} دوباره فعال شد."),
        "en": ("{domain} is active again", "{brand}: the service {domain} is active again."),
    },
    "incident.opened": {
        "fa": ("اختلال: {title}", "{brand}: اختلال در سرویس — {title}. وضعیت در صفحهٔ وضعیت."),
        "en": ("Incident: {title}", "{brand}: service incident — {title}. See the status page."),
    },
    "incident.resolved": {
        "fa": ("برطرف شد: {title}", "{brand}: اختلال برطرف شد — {title}."),
        "en": ("Resolved: {title}", "{brand}: the incident is resolved — {title}."),
    },
    "abuse.notice": {
        "fa": ("گزارش تخلف دربارهٔ {domain} ({ticket})",
               "{brand}: گزارشی دربارهٔ محتوای {domain} (دسته: {category}) دریافت شد. نشانی‌ها:\n{urls}\n"
               "لطفاً تا {deadline} موضوع را بررسی و برطرف کنید. شمارهٔ پیگیری: {ticket}.\n{message}"),
        "en": ("Abuse report about {domain} ({ticket})",
               "{brand}: we received a report about content on {domain} (category: {category}). URLs:\n{urls}\n"
               "Please review and resolve it by {deadline}. Reference: {ticket}.\n{message}"),
    },
    "test": {
        "fa": ("پیام آزمایشی", "{brand}: این یک پیام آزمایشی است؛ هشدارهای شما درست تنظیم شده‌اند."),
        "en": ("Test message", "{brand}: this is a test message; your alerts are set up correctly."),
    },
    "digest": {
        "fa": ("{n} هشدار دیگر", "{brand}: {n} هشدار دیگر در پنل."),
        "en": ("{n} more alerts", "{brand}: {n} more alerts in your panel."),
    },
}


class _Safe(dict):
    def __missing__(self, key):
        return ""


def brand(lang: str) -> str:
    if settings.notify_brand:
        return settings.notify_brand
    return "پاسارگاد CDN" if lang == "fa" else "Pasargad CDN"


def render(event: str, lang: str, values: dict, channel: str = "email") -> tuple[str, str]:
    """(subject, text) of `event` in `lang`; numbers in Persian digits for fa (except domains)."""
    lang = lang if lang in ("fa", "en") else "fa"
    tpl = TEMPLATES.get(event) or TEMPLATES["test"]
    subject, text = tpl[lang]
    vals = _Safe({k: ("" if v is None else str(v)) for k, v in (values or {}).items()})
    vals["brand"] = brand(lang)
    if lang == "fa":
        for k in ("days", "n"):
            if vals.get(k):
                vals[k] = vals[k].translate(_FA_DIGITS)
    subject = subject.format_map(vals)
    text = text.format_map(vals).strip()
    if channel == "sms" and len(text) > SMS_MAX:
        text = text[: SMS_MAX - 1] + "…"
    return subject, text
