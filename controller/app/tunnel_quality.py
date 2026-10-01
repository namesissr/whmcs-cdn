"""Wave 7 (SPEC §15.3–§15.5): tunnel quality / usage reports, origin-down detection with site
events + webhooks, and the edge-group capacity alert.

Scope: quality, reliability and diagnostics only. Nothing here selects, ranks or recommends edge
nodes or addresses; the per-edge breakdown is a diagnostic view of the site's own traffic by the
edge *name* that served it (never an address).

Data sources
* `usage_hourly.details.tunnel.paths` — per (site, edge, hour) path-id counters sent by the edges
  (SPEC §15.1), merged at ingestion (routes_edge.merge_tunnel_paths, ≤ 50 ids per row). The table is
  already keyed per edge, so the per-edge breakdown needs no schema change.
* `analytics_minute.details.tunnel_attempts` / `tunnel_errors` — per-minute counters from the edges'
  `live` items, summed over every edge (origin-down detection).
* `site_events` — origin-down / origin-up transitions for the WHMCS cron (GET /api/v1/events?type=tunnel).
"""

import json
import logging
import math
from calendar import monthrange
from datetime import datetime, timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from . import alerts, kv, sections, webhooks
from .config import settings
from .models import AnalyticsMinute, Edge, Site, SiteEvent, State, UsageHourly, utcnow
from .routes_edge import TUNNEL_ERROR_KEYS, TUNNEL_PROTOCOLS
from .services import month_start, usage_totals

log = logging.getLogger("pcdn.tunnel")

MAX_QUALITY_HOURS = 744
MAX_USAGE_DAYS = 90

# fixed Persian advice per dominant error class (SPEC §15.3); one sentence each
ADVICE = {
    "origin_refused": "سرور شما روی پورت مسیر اتصال را رد می‌کند؛ سرویس Xray/sing-box و پورت را بررسی کنید.",
    "origin_timeout": "سرور شما در زمان مقرر پاسخ نمی‌دهد؛ روشن بودن سرور، فایروال و درستی آدرس و پورت مسیر "
                      "را بررسی کنید.",
    "origin_error": "سرور شما پاسخ داد ولی اتصال را نپذیرفت؛ path/serviceName و نوع inbound را با تنظیمات مسیر "
                    "یکسان کنید.",
    "limit": "اتصال‌ها به سقف مجاز رسیده‌اند؛ سقف اتصال هر IP را بررسی کنید یا پلن سرویس را ارتقا دهید.",
    "country": "درخواست‌هایی از کشورهای خارج از فهرست مجاز رد شده‌اند؛ فهرست کشورهای مجاز مسیر را بررسی کنید.",
    "protocol": "کلاینت با پروتکل نادرست وصل می‌شود؛ نوع انتقال (transport) و TLS کانفیگ کلاینت را با پروتکل "
                "مسیر یکسان کنید.",
    "edge": "خطای موقتی در سمت CDN رخ داده است؛ اگر ادامه پیدا کرد با پشتیبانی تماس بگیرید.",
}
assert set(ADVICE) == set(TUNNEL_ERROR_KEYS)

PATH_COUNTERS = ("sessions", "seconds", "bytes_up", "bytes_down", "abnormal", "connect_ms_sum", "connect_n")


def _loads(s: str | None) -> dict:
    try:
        d = json.loads(s or "{}")
    except ValueError:
        return {}
    return d if isinstance(d, dict) else {}


def _hour_iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:00:00Z")


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat(timespec="seconds") + "Z" if dt else None


def _tunnel_paths(details: dict) -> dict:
    paths = (details.get("tunnel") or {}).get("paths") or {}
    return paths if isinstance(paths, dict) else {}


def _empty() -> dict:
    return {**{k: 0 for k in PATH_COUNTERS}, "errors": {k: 0 for k in TUNNEL_ERROR_KEYS}}


def _add(dst: dict, src: dict) -> None:
    for k in PATH_COUNTERS:
        dst[k] += max(int(src.get(k) or 0), 0)
    errs = src.get("errors") or {}
    for k in TUNNEL_ERROR_KEYS:
        dst["errors"][k] += max(int(errs.get(k) or 0), 0)


def _pct(num: float, den: float) -> float | None:
    return round(100.0 * num / den, 3) if den > 0 else None


def top_issue(errors: dict) -> str | None:
    """The dominant error class (ties: SPEC order), None without errors."""
    best = max(TUNNEL_ERROR_KEYS, key=lambda k: (errors.get(k, 0), -TUNNEL_ERROR_KEYS.index(k)))
    return best if errors.get(best, 0) > 0 else None


def path_metrics(c: dict) -> dict:
    """Derived quality numbers of summed counters (SPEC §15.3); null where there is no data."""
    sessions = c["sessions"]
    error_total = sum(c["errors"].values())
    issue = top_issue(c["errors"])
    return {
        "sessions": sessions,
        "avg_session_s": round(c["seconds"] / sessions, 1) if sessions else None,
        "abnormal_pct": _pct(c["abnormal"], sessions),
        "connect_ms_avg": round(c["connect_ms_sum"] / c["connect_n"], 1) if c["connect_n"] else None,
        "errors": dict(c["errors"]),
        "error_total": error_total,
        "success_pct": _pct(sessions, sessions + error_total),
        "top_issue": issue,
        "advice": ADVICE.get(issue) if issue else None,
    }


# ------------------------------------------------------------------ quality (SPEC §15.3)

def quality(db: Session, site: Site, hours: int, now: datetime | None = None) -> dict:
    """`{hours, paths, edges, series}`; callers validate 1 <= hours <= 744."""
    end = (now or utcnow()).replace(minute=0, second=0, microsecond=0)
    start = end - timedelta(hours=hours - 1)
    per_path: dict[str, dict] = {}
    per_edge: dict[int, dict] = {}
    per_hour: dict[datetime, dict] = {}
    rows = db.execute(select(UsageHourly.edge_id, UsageHourly.hour, UsageHourly.details).where(
        UsageHourly.site_id == site.id, UsageHourly.hour >= start, UsageHourly.hour <= end))
    for edge_id, hour, details in rows:
        paths = _tunnel_paths(_loads(details))
        if not paths:
            continue
        e = per_edge.setdefault(edge_id, _empty())
        h = per_hour.setdefault(hour, {"sessions": 0, "errors": 0, "abnormal": 0})
        for pid, c in paths.items():
            if not isinstance(c, dict):
                continue
            _add(per_path.setdefault(str(pid), _empty()), c)
            _add(e, c)
            h["sessions"] += max(int(c.get("sessions") or 0), 0)
            h["abnormal"] += max(int(c.get("abnormal") or 0), 0)
            h["errors"] += sum(max(int((c.get("errors") or {}).get(k) or 0), 0) for k in TUNNEL_ERROR_KEYS)

    configured = sections.get_section(site, "tunnel")["paths"]
    out_paths = []
    for p in configured:
        m = path_metrics(per_path.get(p["id"]) or _empty())
        out_paths.append({"id": p["id"], "path": p["path"], "protocol": p["protocol"], **m, "removed": False})
    known = {p["id"] for p in configured}
    for pid in sorted(set(per_path) - known):  # path ids no longer configured
        out_paths.append({"id": pid, "path": None, "protocol": None, **path_metrics(per_path[pid]),
                          "removed": True})

    names = dict(db.execute(select(Edge.id, Edge.name).where(Edge.id.in_(list(per_edge)))).all()) \
        if per_edge else {}
    out_edges = []
    for edge_id, c in per_edge.items():
        m = path_metrics(c)
        out_edges.append({"name": names.get(edge_id, f"edge-{edge_id}"), "sessions": m["sessions"],
                          "abnormal_pct": m["abnormal_pct"], "connect_ms_avg": m["connect_ms_avg"],
                          "error_total": m["error_total"]})
    out_edges.sort(key=lambda e: e["name"])

    series, t = [], start
    while t <= end:  # zero-filled, one point per hour, oldest first
        h = per_hour.get(t) or {"sessions": 0, "errors": 0, "abnormal": 0}
        series.append({"t": _hour_iso(t), **h})
        t += timedelta(hours=1)
    return {"hours": hours, "paths": out_paths, "edges": out_edges, "series": series}


# ------------------------------------------------------------------ usage + forecast (SPEC §15.3)

def month_forecast(used: int, limit: int | None, now: datetime) -> dict:
    """Month-to-date average daily total × days in month; the exhaust date is the day the average
    pace reaches the limit (this month only; null without a limit or when it is not reached)."""
    start = month_start(now)
    days_in_month = monthrange(now.year, now.month)[1]
    next_month = start + timedelta(days=days_in_month)
    elapsed_days = max((now - start).total_seconds() / 86400.0, 1.0)  # day 1: never extrapolate minutes
    daily = used / elapsed_days
    forecast = int(round(daily * days_in_month))
    exhaust = None
    if limit:
        if used >= limit:
            exhaust = now.date().isoformat()
        elif daily > 0 and limit / daily < days_in_month:
            at = start + timedelta(days=limit / daily)
            if at < next_month:
                exhaust = max(at, now).date().isoformat()
    return {"used_bytes": used, "limit_bytes": limit, "forecast_bytes": forecast,
            "forecast_exhaust_date": exhaust}


def usage(db: Session, site: Site, days: int, now: datetime | None = None) -> dict:
    """`{days: [{date, bytes_up, bytes_down, sessions, by_protocol, by_path}], month: {...}}`; callers
    validate 1 <= days <= 90. `month.used_bytes` is the site's billed month usage (the quota counter:
    tunnel traffic is billed from the same plan bandwidth), `month.tunnel_bytes` the tunnel share."""
    now = now or utcnow()
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)
    first = today - timedelta(days=days - 1)
    mstart = month_start(now)
    since = min(first, mstart)
    buckets: dict[str, dict] = {}
    tunnel_month = 0
    rows = db.execute(select(UsageHourly.hour, UsageHourly.details).where(
        UsageHourly.site_id == site.id, UsageHourly.hour >= since))
    for hour, details in rows:
        tn = _loads(details).get("tunnel") or {}
        if not isinstance(tn, dict) or not tn:
            continue
        up, down = max(int(tn.get("bytes_up") or 0), 0), max(int(tn.get("bytes_down") or 0), 0)
        if hour >= mstart:
            tunnel_month += up + down
        if hour < first:
            continue
        b = buckets.setdefault(hour.date().isoformat(), {"bytes_up": 0, "bytes_down": 0, "sessions": 0,
                                                         "by_protocol": {}, "by_path": {}})
        b["bytes_up"] += up
        b["bytes_down"] += down
        b["sessions"] += max(int(tn.get("sessions") or 0), 0)
        for proto, v in (tn.get("by_protocol") or {}).items():
            if proto in TUNNEL_PROTOCOLS:
                b["by_protocol"][proto] = b["by_protocol"].get(proto, 0) + max(int(v), 0)
        for pid, c in _tunnel_paths({"tunnel": tn}).items():
            if isinstance(c, dict):
                n = max(int(c.get("bytes_up") or 0), 0) + max(int(c.get("bytes_down") or 0), 0)
                b["by_path"][str(pid)] = b["by_path"].get(str(pid), 0) + n
    out, d = [], first
    while d <= today:
        key = d.date().isoformat()
        out.append({"date": key, **(buckets.get(key) or {"bytes_up": 0, "bytes_down": 0, "sessions": 0,
                                                         "by_protocol": {}, "by_path": {}})})
        d += timedelta(days=1)
    used = usage_totals(db, site.id, mstart)["bytes"]
    limit = site.bandwidth_limit_gb * 1024**3 if site.bandwidth_limit_gb > 0 else None
    return {"days": out, "month": {**month_forecast(used, limit, now), "tunnel_bytes": tunnel_month,
                                   "month": now.strftime("%Y-%m")}}


# ------------------------------------------------------------------ site events (SPEC §15.4)

EVENT_TYPES = {"tunnel": ("tunnel.origin_down", "tunnel.origin_up")}


def record_event(db: Session, site: Site, event: str, data: dict, now: datetime | None = None) -> str:
    """Store a site event (polled by WHMCS) and queue the matching webhooks with the SAME event id.
    Caller commits."""
    now = now or utcnow()
    event_id = webhooks.new_event_id()
    db.add(SiteEvent(event_id=event_id, site_id=site.id, type=event,
                     data=json.dumps(data, ensure_ascii=False, sort_keys=True), created_at=now))
    webhooks.emit(db, site, event, data, now, event_id=event_id)
    return event_id


def list_events(db: Session, kind: str, since: datetime | None, limit: int) -> list[dict]:
    """Events of one kind (`tunnel`), oldest first, created at or after `since` (inclusive: poll with
    the last seen `created_at` and dedupe by `id`)."""
    q = select(SiteEvent, Site.domain, Site.external_id).join(Site, Site.id == SiteEvent.site_id).where(
        SiteEvent.type.in_(EVENT_TYPES[kind]))
    if since is not None:
        q = q.where(SiteEvent.created_at >= since)
    rows = db.execute(q.order_by(SiteEvent.created_at, SiteEvent.id).limit(max(1, min(limit, 1000)))).all()
    return [{"id": e.event_id, "seq": e.id, "type": e.type, "domain": domain, "external_id": ext,
             "created_at": _iso(e.created_at), "data": _loads(e.data)} for e, domain, ext in rows]


def prune_events(db: Session, now: datetime | None = None) -> None:
    now = now or utcnow()
    db.execute(delete(SiteEvent).where(
        SiteEvent.created_at < now - timedelta(days=settings.site_events_retention_days)))


# ------------------------------------------------------------------ origin-down detection (SPEC §15.4)

ORIGIN_KEY = "tunnel_origin:{}"
ORIGIN_PREFIX = "tunnel_origin:"
ORIGIN_LAST_RUN = "tunnel_origin_check:last_run"
WINDOW = timedelta(minutes=5)
DOWN_MIN_ATTEMPTS, DOWN_PCT = 10, 80
UP_MIN_ATTEMPTS, UP_PCT = 5, 20
FLAP_GUARD = timedelta(minutes=30)


def _window(db: Session, now: datetime) -> dict[int, tuple[int, int]]:
    """{site_id: (attempts, origin_errors)} summed over the minute buckets of the last 5 minutes."""
    since = (now - WINDOW).replace(second=0, microsecond=0)
    out: dict[int, list[int]] = {}
    for sid, details in db.execute(select(AnalyticsMinute.site_id, AnalyticsMinute.details).where(
            AnalyticsMinute.minute >= since, AnalyticsMinute.minute <= now)):
        d = _loads(details)
        a = max(int(d.get("tunnel_attempts") or 0), 0)
        e = max(int(d.get("tunnel_errors") or 0), 0)
        if a or e:
            acc = out.setdefault(sid, [0, 0])
            acc[0] += a
            acc[1] += e
    return {sid: (a, min(e, a)) for sid, (a, e) in out.items()}


def _failing_paths(db: Session, site: Site, now: datetime) -> list[str]:
    """Path ids with origin_refused / origin_timeout in the hourly data covering the window (the
    current hour, plus the previous one while the window reaches into it), busiest first; the
    configured path ids when the edges send no per-path data (pre-wave-7 agents)."""
    since = (now - WINDOW).replace(minute=0, second=0, microsecond=0)
    counts: dict[str, int] = {}
    for (details,) in db.execute(select(UsageHourly.details).where(
            UsageHourly.site_id == site.id, UsageHourly.hour >= since)):
        for pid, c in _tunnel_paths(_loads(details)).items():
            errs = (c.get("errors") or {}) if isinstance(c, dict) else {}
            n = int(errs.get("origin_refused") or 0) + int(errs.get("origin_timeout") or 0)
            if n > 0:
                counts[str(pid)] = counts.get(str(pid), 0) + n
    if counts:
        return [k for k, _ in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))]
    return [p["id"] for p in sections.get_section(site, "tunnel")["paths"]]


def decide(current: str, attempts: int, errors: int) -> str:
    """New state from the window counts; insufficient data keeps the current state."""
    if attempts >= DOWN_MIN_ATTEMPTS and errors * 100 >= DOWN_PCT * attempts:
        return "down"
    if attempts >= UP_MIN_ATTEMPTS and errors * 100 < UP_PCT * attempts:
        return "up"
    return current


def check_origins(db: Session, now: datetime | None = None) -> list[tuple[str, str]]:
    """Leader job body (every scheduler tick): evaluate every site with tunnel minute data in the
    window or a stored origin state; record transitions. Returns [(domain, event)] emitted."""
    now = now or utcnow()
    window = _window(db, now)
    stored = {int(k.removeprefix(ORIGIN_PREFIX)): k for (k,) in db.execute(
        select(State.key).where(State.key.startswith(ORIGIN_PREFIX, autoescape=True))) if k.removeprefix(ORIGIN_PREFIX).isdigit()}
    emitted: list[tuple[str, str]] = []
    for sid in sorted(set(window) | set(stored)):
        site = db.get(Site, sid)
        key = ORIGIN_KEY.format(sid)
        if site is None:
            row = db.get(State, key)
            if row is not None:
                db.delete(row)
            continue
        st = kv.get_json(db, key)
        cur = st.get("state") or "unknown"
        attempts, errors = window.get(sid, (0, 0))
        new = decide(cur, attempts, errors)
        if new == cur:
            continue
        nowiso = _iso(now)
        if new == "down":
            last = st.get("down_notified_at")
            notify = not last or now - datetime.fromisoformat(last) >= FLAP_GUARD
            paths = _failing_paths(db, site, now)
            st.update(state="down", since=now.isoformat(), paths=paths, down_notified=notify,
                      attempts=attempts, origin_errors=errors)
            if notify:
                st["down_notified_at"] = now.isoformat()
                record_event(db, site, "tunnel.origin_down", {"paths": paths, "attempts": attempts,
                                                              "origin_errors": errors, "since": nowiso}, now)
                emitted.append((site.domain, "tunnel.origin_down"))
            else:
                log.info("tunnel origin of %s down again within %s: notification suppressed", site.domain,
                         FLAP_GUARD)
        else:  # up (from down, or the first verdict after unknown)
            notify = cur == "down" and bool(st.get("down_notified"))
            down_since = st.get("since") if cur == "down" else None
            paths = st.get("paths") or []
            st.update(state="up", since=now.isoformat(), attempts=attempts, origin_errors=errors,
                      down_notified=False)
            if notify:
                record_event(db, site, "tunnel.origin_up", {
                    "paths": paths, "attempts": attempts, "origin_errors": errors, "since": nowiso,
                    "down_since": _iso(datetime.fromisoformat(down_since)) if down_since else None}, now)
                emitted.append((site.domain, "tunnel.origin_up"))
        kv.set_json(db, key, st)
    kv.set_json(db, ORIGIN_LAST_RUN, {"at": now.isoformat()})
    db.commit()
    return emitted


def health(db: Session, site: Site) -> dict:
    """`{state: up|down|unknown, since, last_check}` (SPEC §15.4)."""
    st = kv.get_json(db, ORIGIN_KEY.format(site.id))
    last = kv.get_json(db, ORIGIN_LAST_RUN).get("at")
    since = st.get("since")
    return {"state": st.get("state") or "unknown",
            "since": _iso(datetime.fromisoformat(since)) if since else None,
            "last_check": _iso(datetime.fromisoformat(last)) if last else None}


# ------------------------------------------------------------------ capacity (SPEC §15.5)

CAPACITY_HOURS = 72
CAPACITY_LAST_RUN = "capacity_check:last_day"
_FA_DIGITS = str.maketrans("0123456789", "۰۱۲۳۴۵۶۷۸۹")


def p95(values: list[float]) -> float:
    """Nearest-rank 95th percentile (0 for no values)."""
    if not values:
        return 0.0
    s = sorted(values)
    return s[max(math.ceil(0.95 * len(s)) - 1, 0)]


def capacity(db: Session, now: datetime | None = None) -> list[dict]:
    """Per edge group of the enabled edges: the 95th percentile of the hourly tx (Mbps) over the last
    72 completed hours (zero-filled) vs the summed capacity_mbps. Hourly tx = `usage_hourly.bytes`
    (bytes sent to clients + tunnel bytes_up, i.e. the billed total that already includes tunnel
    traffic) summed over the group's edges with a known capacity (capacity_mbps > 0); edges with an
    unknown capacity are left out of both sides. `pct` is null for a group without known capacity."""
    end = (now or utcnow()).replace(minute=0, second=0, microsecond=0)
    start = end - timedelta(hours=CAPACITY_HOURS)
    groups: dict[str, dict] = {}
    edge_group: dict[int, str] = {}
    for e in db.scalars(select(Edge).where(Edge.enabled.is_(True)).order_by(Edge.id)):
        g = groups.setdefault(e.group, {"capacity": 0, "hours": {}})
        if (e.capacity_mbps or 0) > 0:
            g["capacity"] += e.capacity_mbps
            edge_group[e.id] = e.group
    if edge_group:
        rows = db.execute(select(UsageHourly.edge_id, UsageHourly.hour, func.sum(UsageHourly.bytes)).where(
            UsageHourly.hour >= start, UsageHourly.hour < end, UsageHourly.edge_id.in_(list(edge_group)))
            .group_by(UsageHourly.edge_id, UsageHourly.hour))
        for edge_id, hour, b in rows:
            hours = groups[edge_group[edge_id]]["hours"]
            hours[hour] = hours.get(hour, 0) + int(b or 0)
    out = []
    for name in sorted(groups):
        g = groups[name]
        mbps = [b * 8 / 3600 / 1e6 for b in g["hours"].values()]
        mbps += [0.0] * (CAPACITY_HOURS - len(mbps))
        peak = round(p95(mbps), 2)
        out.append({"group": name, "p95_mbps": peak, "capacity_mbps": g["capacity"],
                    "pct": round(100.0 * peak / g["capacity"], 1) if g["capacity"] > 0 else None})
    return out


def check_capacity(db: Session, now: datetime | None = None, force: bool = False) -> list[dict] | None:
    """Daily leader job: open `capacity:{group}` at >= CAPACITY_ALERT_PERCENT, keep it open down to
    CAPACITY_RESOLVE_PERCENT (hysteresis), resolve below. Returns the report, None when skipped."""
    now = now or utcnow()
    today = now.date().isoformat()
    if not force and kv.get_json(db, CAPACITY_LAST_RUN).get("day") == today:
        return None
    report = capacity(db, now)
    kv.set_json(db, CAPACITY_LAST_RUN, {"day": today})
    db.commit()
    open_keys = {c.get("key") for c in alerts.open_alerts(db)}
    hi, lo = settings.capacity_alert_percent, settings.capacity_resolve_percent
    active = {}
    for g in report:
        key = f"capacity:{g['group']}"
        pct = g["pct"]
        if pct is None:
            continue
        if pct >= hi or (key in open_keys and pct >= lo):
            label = f"{hi:g}".translate(_FA_DIGITS)
            active[key] = (
                f"ظرفیت گروه {g['group']} به {label}٪ رسیده؛ نود اضافه کنید",
                f"صدک ۹۵ ترافیک خروجی ساعتی گروه {g['group']} در ۳ روز گذشته {g['p95_mbps']:g} مگابیت بر ثانیه "
                f"است، یعنی {pct:g}٪ از ظرفیت مجموع {g['capacity_mbps']} مگابیت بر ثانیه‌ی نودهای این گروه. "
                f"برای حفظ کیفیت، نود جدیدی به این گروه اضافه کنید یا ظرفیت نودها را افزایش دهید.",
                "warning",
            )
    alerts.sync("capacity:", active, lambda c: "ترافیک گروه به زیر آستانه‌ی ظرفیت برگشت.")
    return report
