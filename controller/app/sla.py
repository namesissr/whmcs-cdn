"""Per-site monthly SLA report (SPEC §14.3.4).

* request_success_pct = 100 × (1 − platform_errors / requests) from the hourly usage, where
  platform_errors are 5xx responses the edges produced themselves (origin errors never count).
* edge_uptime_pct = mean availability of the edges in the site's edge group (the per-edge,
  per-hour EdgeUptime rollup the scheduler samples every tick; see uptime.py): each edge's
  online/total samples for the day (or month), averaged over the edges that have samples. When the
  group has no samples at all in the month, every edge is used — the same fail-open DNS applies.
* availability_pct = the lower of the two non-null values; 3 decimals; null without data.
"""

import json
from collections import defaultdict
from datetime import date, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import dnsbuild, sections
from .models import Edge, EdgeUptime, Site, UsageHourly, utcnow
from .validation import ValidationError

MAX_MONTHS_BACK = 12


def parse_month(month: str | None, now: datetime | None = None) -> datetime:
    """`YYYY-MM` (default: the current UTC month) -> first instant of the month; ValidationError
    when malformed, in the future or more than 12 months back."""
    now = now or utcnow()
    if not month:
        return now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    try:
        start = datetime.strptime(month.strip(), "%Y-%m")
    except ValueError:
        raise ValidationError("month باید به شکل YYYY-MM باشد") from None
    back = (now.year * 12 + now.month) - (start.year * 12 + start.month)
    if back < 0:
        raise ValidationError("ماه گزارش نمی‌تواند در آینده باشد")
    if back > MAX_MONTHS_BACK:
        raise ValidationError(f"گزارش SLA حداکثر برای {MAX_MONTHS_BACK} ماه گذشته در دسترس است")
    return start


def _next_month(start: datetime) -> datetime:
    return (start.replace(day=28) + timedelta(days=4)).replace(day=1)


def _pct(v: float | None) -> float | None:
    return None if v is None else round(max(0.0, min(100.0, v)), 3)


def _success(requests: int, errors: int) -> float | None:
    return _pct(100 * (1 - errors / requests)) if requests > 0 else None


def _mean(values: list[float]) -> float | None:
    return _pct(sum(values) / len(values)) if values else None


def _availability(a: float | None, b: float | None) -> float | None:
    vals = [v for v in (a, b) if v is not None]
    return round(min(vals), 3) if vals else None


def report(db: Session, site: Site, month: str | None = None, now: datetime | None = None) -> dict:
    now = now or utcnow()
    start = parse_month(month, now)
    end = _next_month(start)
    last_day = min(end - timedelta(days=1), now).date()

    # requests / platform errors per day (hourly usage of every edge)
    req: dict[date, int] = defaultdict(int)
    err: dict[date, int] = defaultdict(int)
    for row in db.scalars(select(UsageHourly).where(
            UsageHourly.site_id == site.id, UsageHourly.hour >= start, UsageHourly.hour < end)):
        day = row.hour.date()
        req[day] += int(row.requests or 0)
        try:
            pe = int((json.loads(row.details or "{}") or {}).get("platform_errors") or 0)
        except (ValueError, TypeError, AttributeError):
            pe = 0
        err[day] += max(pe, 0)

    # edge availability: per edge per day (online, total)
    group = dnsbuild.site_edge_group(site)
    edge_groups = {eid: g or "general" for eid, g in db.execute(select(Edge.id, Edge.group)).all()}
    samples: dict[int, dict[date, list[int]]] = defaultdict(lambda: defaultdict(lambda: [0, 0]))
    for r in db.scalars(select(EdgeUptime).where(EdgeUptime.hour >= start, EdgeUptime.hour < end)):
        if r.edge_id not in edge_groups or not r.samples_total:
            continue
        s = samples[r.edge_id][r.hour.date()]
        s[0] += int(r.samples_online or 0)
        s[1] += int(r.samples_total or 0)
    in_group = {eid for eid in samples if edge_groups.get(eid) == group}
    edges = in_group or set(samples)  # fail-open like DNS: no sample of the group -> every edge

    def uptime(days: set[date] | None) -> float | None:
        values = []
        for eid in edges:
            online = total = 0
            for day, (o, t) in samples[eid].items():
                if days is None or day in days:
                    online, total = online + o, total + t
            if total > 0:
                values.append(online * 100 / total)
        return _mean(values)

    days = []
    d = start.date()
    while d <= last_day:
        days.append({"date": d.isoformat(), "requests": req.get(d, 0), "platform_errors": err.get(d, 0),
                     "request_success_pct": _success(req.get(d, 0), err.get(d, 0)),
                     "edge_uptime_pct": uptime({d})})
        d += timedelta(days=1)

    requests, errors = sum(req.values()), sum(err.values())
    success = _success(requests, errors)
    edge_uptime = uptime(None)
    availability = _availability(success, edge_uptime)
    target = float(sections.features_of(site).get("sla_target", 99.9))
    return {
        "month": start.strftime("%Y-%m"),
        "domain": site.domain,
        "requests": requests,
        "platform_errors": errors,
        "request_success_pct": success,
        "edge_uptime_pct": edge_uptime,
        "availability_pct": availability,
        "target_pct": target,
        "met": None if availability is None else availability >= target,
        "days": days,
    }
