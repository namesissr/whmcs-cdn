"""Monthly usage statements (SPEC §18.3): ``GET /api/v1/sites/{d}/statement?month=YYYY-MM&format=
pdf|csv|json&lang=fa|en`` (+ capi, scope stats) built from the hourly usage, the storage samples and
the plan. No customer IPs. A future month is refused (422); the current month is month-to-date.

The plan's display name and the size of an extra-traffic block live in WHMCS, which passes them as
optional query values ``plan`` (≤100 characters) and ``block_gb`` (> 0): ``quota.blocks`` = ceil of
the overage over the plan's bandwidth limit / block_gb.

PDF: A4, fpdf2 with the bundled Vazirmatn font (app/fonts, SIL OFL 1.1, OFL.txt next to it), Persian
shaped right-to-left by HarfBuzz (uharfbuzz). Without uharfbuzz the PDF is still produced, unshaped
(SHAPING tells which). Deterministic for the same data: the document's creation date is the first
second of the month, nothing else depends on the clock.
"""

import csv
import importlib.util
import io
import json
import math
import os
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import sections, storage
from .models import Site, UsageHourly, utcnow
from .validation import ValidationError, num
from .validation import obj as _obj

GIB = 1024**3
FONT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fonts")
FONT_REGULAR = os.path.join(FONT_DIR, "Vazirmatn-Regular.ttf")
FONT_BOLD = os.path.join(FONT_DIR, "Vazirmatn-Bold.ttf")
PDF_MAX_BYTES = 2 * 1024 * 1024
FORMATS = ("pdf", "csv", "json")
LANGS = ("fa", "en")

# text shaping (RTL joining) for Persian; optional (the image installs it, requirements.txt)
SHAPING = importlib.util.find_spec("uharfbuzz") is not None

FA_DIGITS = str.maketrans("0123456789", "۰۱۲۳۴۵۶۷۸۹")

T = {
    "title": {"fa": "صورت‌حساب مصرف", "en": "Usage statement"},
    "site": {"fa": "سرویس", "en": "Service"},
    "month": {"fa": "ماه", "en": "Month"},
    "mtd": {"fa": "تا امروز، ماه جاری کامل نشده", "en": "month to date, not complete"},
    "complete": {"fa": "کامل", "en": "complete"},
    "plan": {"fa": "پلن", "en": "Plan"},
    "quota": {"fa": "سهمیهٔ ترافیک (GB)", "en": "Traffic quota (GB)"},
    "unlimited": {"fa": "نامحدود", "en": "unlimited"},
    "overage": {"fa": "ترافیک مازاد (GB)", "en": "Overage (GB)"},
    "blocks": {"fa": "بستهٔ اضافه مصرف‌شده", "en": "Extra blocks consumed"},
    "traffic": {"fa": "ترافیک (GB)", "en": "Traffic (GB)"},
    "requests": {"fa": "درخواست", "en": "Requests"},
    "hit": {"fa": "نسبت کش (٪)", "en": "Cache hit (%)"},
    "day": {"fa": "روز", "en": "Day"},
    "total": {"fa": "جمع", "en": "Total"},
    "tunnel": {"fa": "ترافیک تونل (GB)", "en": "Tunnel traffic (GB)"},
    "l4": {"fa": "ترافیک TCP/UDP (GB)", "en": "TCP/UDP traffic (GB)"},
    "storage": {"fa": "فضای ذخیره‌سازی (GB-ماه)", "en": "Storage (GB-month)"},
    "functions": {"fa": "اجرای توابع لبه", "en": "Edge function invocations"},
    "security": {"fa": "رویدادهای امنیتی", "en": "Security events"},
    "none": {"fa": "—", "en": "—"},
    "footer": {"fa": "این گزارش از داده‌های مصرف ثبت‌شده توسط سرورهای لبه تهیه شده است.",
               "en": "Generated from the usage reported by the edge servers."},
}


def _t(key: str, lang: str) -> str:
    return T[key][lang]


def parse_month(month: str | None, now: datetime | None = None) -> tuple[datetime, datetime]:
    """(start, end) of YYYY-MM; the current month when omitted; ValidationError for junk or the future."""
    now = now or utcnow()
    if not month:
        start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    else:
        try:
            start = datetime.strptime(month.strip(), "%Y-%m")
        except ValueError:
            raise ValidationError("month باید به شکل YYYY-MM باشد") from None
        if start.year < 2000:
            raise ValidationError("month نامعتبر است")
    if start > now:
        raise ValidationError("ماه آینده هنوز گزارشی ندارد")
    end = (start.replace(day=28) + timedelta(days=4)).replace(day=1)
    return start, end


def _gb(b: int) -> float:
    return round(b / GIB, 3)


def build(db: Session, site: Site, month: str | None = None, plan: str | None = None,
          block_gb: float | None = None, now: datetime | None = None) -> dict:
    """The statement data (the JSON format; CSV / PDF render the same document)."""
    now = now or utcnow()
    start, end = parse_month(month, now)
    if plan is not None and len(plan) > 100:
        raise ValidationError("plan حداکثر ۱۰۰ نویسه است")
    if block_gb is not None and not (0 < block_gb <= 1_000_000):
        raise ValidationError("block_gb باید بزرگ‌تر از صفر باشد")
    days: dict[str, dict] = {}
    t = start
    while t < end and t <= now:
        key = t.strftime("%Y-%m-%d")
        days[key] = {"date": key, "bytes": 0, "requests": 0, "cache_hits": 0}
        t += timedelta(days=1)
    tunnel_b = l4_b = invocations = 0
    security: dict[str, int] = {}
    for hour, b, r, h, details in db.execute(
            select(UsageHourly.hour, UsageHourly.bytes, UsageHourly.requests, UsageHourly.cache_hits,
                   UsageHourly.details)
            .where(UsageHourly.site_id == site.id, UsageHourly.hour >= start, UsageHourly.hour < end)).all():
        key = hour.strftime("%Y-%m-%d")
        d = days.setdefault(key, {"date": key, "bytes": 0, "requests": 0, "cache_hits": 0})
        d["bytes"] += int(b or 0)
        d["requests"] += int(r or 0)
        d["cache_hits"] += int(h or 0)
        try:
            det = json.loads(details or "{}")
        except ValueError:
            det = {}
        det = det if isinstance(det, dict) else {}
        tn = _obj(det.get("tunnel"))
        tunnel_b += num(tn.get("bytes_up")) + num(tn.get("bytes_down"))
        for c in _obj(det.get("l4")).values():
            c = _obj(c)
            l4_b += num(c.get("bytes_in")) + num(c.get("bytes_out"))
        invocations += num(_obj(det.get("functions")).get("invocations"))
        for k, v in _obj(det.get("security")).items():
            k = str(k)[:32]
            if k in security or len(security) < 20:
                security[k] = security.get(k, 0) + num(v)
    rows = []
    for key in sorted(days):
        d = days[key]
        rows.append({"date": key, "gb": _gb(d["bytes"]), "bytes": d["bytes"], "requests": d["requests"],
                     "cache_hits": d["cache_hits"],
                     "cache_hit_ratio": round(d["cache_hits"] * 100 / d["requests"], 2) if d["requests"] else 0.0})
    tb = sum(d["bytes"] for d in days.values())
    tr = sum(d["requests"] for d in days.values())
    th = sum(d["cache_hits"] for d in days.values())
    try:
        st = storage.month_report(db, site, start.strftime("%Y-%m"), now)
        storage_block = {"gb_month": st["gb_month"], "gb_hours": st["gb_hours"], "peak_gb": st["peak_gb"]}
    except Exception:  # noqa: BLE001 - storage samples are optional for a statement
        storage_block = {"gb_month": 0.0, "gb_hours": 0.0, "peak_gb": 0.0}
    limit_gb = int(site.bandwidth_limit_gb or 0)
    used_gb = tb / GIB
    over_gb = max(0.0, used_gb - limit_gb) if limit_gb > 0 else 0.0
    return {
        "domain": site.domain,
        "month": start.strftime("%Y-%m"),
        "from": start.isoformat() + "Z",
        "to": end.isoformat() + "Z",
        "complete": now >= end,
        "month_to_date": now < end,
        "plan": {"name": plan or None, "bandwidth_limit_gb": limit_gb,
                 "features": {k: v for k, v in sections.features_of(site).items()
                              if k in ("waf", "ddos", "tunnel", "l4_proxy", "edge_functions", "storage_gb",
                                       "waiting_room", "access")}},
        "quota": {"limit_gb": limit_gb, "used_gb": round(used_gb, 3), "overage_gb": round(over_gb, 3),
                  "block_gb": block_gb, "blocks": math.ceil(over_gb / block_gb) if block_gb and over_gb > 0 else 0},
        "totals": {"bytes": tb, "gb": _gb(tb), "requests": tr, "cache_hits": th,
                   "cache_hit_ratio": round(th * 100 / tr, 2) if tr else 0.0},
        "tunnel_gb": _gb(tunnel_b),
        "l4_gb": _gb(l4_b),
        "storage": storage_block,
        "functions_invocations": invocations,
        "security": dict(sorted(security.items())),
        "security_total": sum(security.values()),
        "days": rows,
    }


# ------------------------------------------------------------------ CSV

def to_csv(doc: dict, lang: str = "en") -> bytes:
    """UTF-8 with BOM (Excel): the daily rows, then the summary as label,value lines."""
    out = io.StringIO()
    w = csv.writer(out, lineterminator="\r\n")
    w.writerow([_t("site", lang), doc["domain"]])
    w.writerow([_t("month", lang), doc["month"] + (" (" + _t("mtd", lang) + ")" if doc["month_to_date"] else "")])
    w.writerow([])
    w.writerow([_t("day", lang), _t("traffic", lang), _t("requests", lang), _t("hit", lang)])
    for r in doc["days"]:
        w.writerow([r["date"], f"{r['gb']:.3f}", r["requests"], f"{r['cache_hit_ratio']:.2f}"])
    tot = doc["totals"]
    w.writerow([_t("total", lang), f"{tot['gb']:.3f}", tot["requests"], f"{tot['cache_hit_ratio']:.2f}"])
    w.writerow([])
    for label, value in _summary(doc, lang, csv_mode=True):
        w.writerow([label, value])
    return ("﻿" + out.getvalue()).encode("utf-8")


def _summary(doc: dict, lang: str, csv_mode: bool = False) -> list[tuple[str, str]]:
    q = doc["quota"]
    out = [
        (_t("plan", lang), doc["plan"]["name"] or _t("none", lang)),
        (_t("quota", lang), str(q["limit_gb"]) if q["limit_gb"] else _t("unlimited", lang)),
        (_t("overage", lang), f"{q['overage_gb']:.3f}"),
        (_t("blocks", lang), str(q["blocks"])),
        (_t("tunnel", lang), f"{doc['tunnel_gb']:.3f}"),
        (_t("l4", lang), f"{doc['l4_gb']:.3f}"),
        (_t("storage", lang), f"{doc['storage']['gb_month']:.4f}"),
        (_t("functions", lang), str(doc["functions_invocations"])),
        (_t("security", lang), str(doc["security_total"])),
    ]
    if csv_mode:
        out += [(f"{_t('security', lang)}: {k}", str(v)) for k, v in doc["security"].items()]
    return out


# ------------------------------------------------------------------ PDF

def _num_fa(s: str, lang: str) -> str:
    return s.translate(FA_DIGITS) if lang == "fa" else s


def to_pdf(doc: dict, lang: str = "fa") -> bytes:
    """A4 statement; Persian right-to-left (columns mirrored) with HarfBuzz shaping."""
    from fpdf import FPDF

    rtl = lang == "fa"
    start = datetime.strptime(doc["month"], "%Y-%m").replace(tzinfo=timezone.utc)
    pdf = FPDF(format="A4", unit="mm")
    pdf.set_creation_date(start)  # deterministic output for the same data
    pdf.set_title(f"{_t('title', lang)} {doc['domain']} {doc['month']}")
    pdf.set_creator("Pasargad CDN")
    pdf.set_author("Pasargad CDN")
    pdf.add_font("Vazirmatn", "", FONT_REGULAR)
    pdf.add_font("Vazirmatn", "B", FONT_BOLD)
    pdf.set_auto_page_break(True, margin=15)
    if SHAPING:
        # fa: right-to-left paragraphs; en: direction from the text (Unicode bidi), so a Persian plan
        # name inside the English statement still reads correctly
        if rtl:
            pdf.set_text_shaping(use_shaping_engine=True, direction="rtl", script="arab", language="fas")
        else:
            pdf.set_text_shaping(use_shaping_engine=True)
    align = "R" if rtl else "L"
    talign = "RIGHT" if rtl else "LEFT"

    def n(v) -> str:
        return _num_fa(str(v), lang)

    def line(text: str, size: int = 10, bold: bool = False, h: float = 7):
        pdf.set_font("Vazirmatn", "B" if bold else "", size)
        pdf.cell(0, h, text, align=align, new_x="LMARGIN", new_y="NEXT")

    def table(rows: list[list[str]], widths: tuple, heading: bool = True):
        if rtl:
            rows = [list(reversed(r)) for r in rows]
            widths = tuple(reversed(widths))
        with pdf.table(text_align=talign, col_widths=widths, line_height=6,
                       first_row_as_headings=heading) as tb:
            for r in rows:
                row = tb.row()
                for c in r:
                    row.cell(c)

    pdf.add_page()
    line(f"{_t('title', lang)} — {doc['domain']}", 16, True, 10)
    status = _t("mtd", lang) if doc["month_to_date"] else _t("complete", lang)
    line(f"{_t('month', lang)}: {doc['month']} ({status})")  # dates keep Latin digits (bidi-stable)
    pdf.ln(2)
    tot = doc["totals"]
    summary = [[_t("traffic", lang), n(format(tot["gb"], ".3f"))],
               [_t("requests", lang), n(tot["requests"])],
               [_t("hit", lang), n(format(tot["cache_hit_ratio"], ".2f"))]]
    summary += [[label, n(value)] for label, value in _summary(doc, lang)]
    pdf.set_font("Vazirmatn", "", 10)
    table(summary, (90, 90), heading=False)
    pdf.ln(4)
    line(_t("day", lang) + " / " + _t("traffic", lang), 11, True)
    daily = [[_t("day", lang), _t("traffic", lang), _t("requests", lang), _t("hit", lang)]]
    daily += [[r["date"], n(format(r["gb"], ".3f")), n(r["requests"]), n(format(r["cache_hit_ratio"], ".2f"))]
              for r in doc["days"]]
    daily.append([_t("total", lang), n(format(tot["gb"], ".3f")), n(tot["requests"]),
                  n(format(tot["cache_hit_ratio"], ".2f"))])
    pdf.set_font("Vazirmatn", "", 9)
    table(daily, (45, 45, 45, 45))
    if doc["security"]:
        pdf.ln(4)
        line(_t("security", lang), 11, True)
        pdf.set_font("Vazirmatn", "", 9)
        table([[_t("security", lang), _t("total", lang)]] + [[k, n(v)] for k, v in doc["security"].items()],
              (90, 90))
    pdf.ln(4)
    line(_t("footer", lang), 8)
    out = bytes(pdf.output())
    if len(out) > PDF_MAX_BYTES:  # cannot happen with ≤31 daily rows; a guard for the SPEC's limit
        raise ValidationError("statement PDF too large")
    return out


def render(doc: dict, fmt: str, lang: str) -> tuple[bytes, str, str]:
    """(body, media type, file name)."""
    name = f"statement-{doc['domain']}-{doc['month']}"
    if fmt == "csv":
        return to_csv(doc, lang), "text/csv; charset=utf-8", name + ".csv"
    if fmt == "pdf":
        return to_pdf(doc, lang), "application/pdf", name + ".pdf"
    return json.dumps(doc, ensure_ascii=False).encode("utf-8"), "application/json", name + ".json"
