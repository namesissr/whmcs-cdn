"""Near-real-time analytics (SPEC §14.3.1): per-site minute buckets from the edges' `live` list.

Edges send 1-minute aggregates inside POST /edge/v1/usage (same transaction and batch_id dedup as
the hourly items); they are summed per (site, minute) into AnalyticsMinute and kept for 24 h
(scheduler.job_cleanup). GET .../analytics/live serves a zero-filled per-minute series.
"""

import json
from collections import Counter
from datetime import datetime, timedelta

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from . import kv
from .models import AnalyticsMinute, Site, utcnow
from .validation import num, obj

RETENTION = timedelta(hours=24)
MAX_MINUTES = 1440
FUTURE_SLACK = timedelta(minutes=5)  # an edge clock slightly ahead is accepted (clamped to now)
STATUS_CLASSES = ("2xx", "3xx", "4xx", "5xx")
DETAIL_KEYS = ("status", "countries", "paths")


def floor_minute(dt: datetime) -> datetime:
    return dt.replace(second=0, microsecond=0)


def _loads(s: str | None) -> dict:
    try:
        d = json.loads(s or "{}")
    except ValueError:
        return {}
    return d if isinstance(d, dict) else {}


def ingest(db: Session, items: list[dict], site_for_host, merge, now: datetime | None = None) -> int:
    """Sum the `live` items of one usage POST into AnalyticsMinute rows; returns how many
    (site, minute) buckets were touched. `site_for_host(host) -> site_id | None` maps hosts exactly
    like hourly usage, `merge(current, add)` is the capped detail merge of the hourly details.
    Items outside the 24 h window are ignored. Caller commits (same transaction as the batch)."""
    now = now or utcnow()
    oldest, newest = floor_minute(now - RETENTION), floor_minute(now)
    agg: dict[tuple[int, datetime], dict] = {}
    for it in items:
        sid = site_for_host(it["host"])
        if sid is None:
            continue
        minute = floor_minute(it["minute"])
        if minute < oldest or minute > floor_minute(now + FUTURE_SLACK):
            continue
        minute = min(minute, newest)
        a = agg.setdefault((sid, minute), {"r": 0, "b": 0, "h": 0, "d": {}})
        a["r"] += it["requests"]
        a["b"] += it["bytes"]
        a["h"] += it["cache_hits"]
        merge(a["d"], {k: it.get(k) or {} for k in DETAIL_KEYS})
        add_tunnel_counters(a["d"], it)
    for (sid, minute), a in sorted(agg.items()):  # a fixed lock order across concurrent edges
        # every edge reports the same (site, minute): create the bucket race-free, then lock it
        kv.insert_ignore(db, AnalyticsMinute, {"site_id": sid, "minute": minute, "requests": 0, "bytes": 0,
                                               "cache_hits": 0, "details": "{}"})
        row = db.scalar(select(AnalyticsMinute).where(
            AnalyticsMinute.site_id == sid, AnalyticsMinute.minute == minute).with_for_update()
            .execution_options(populate_existing=True))
        row.requests += a["r"]
        row.bytes += a["b"]
        row.cache_hits += a["h"]
        details = merge(_loads(row.details), a["d"])
        add_tunnel_counters(details, a["d"])
        row.details = json.dumps(details)
    return len(agg)


TUNNEL_COUNTERS = ("tunnel_attempts", "tunnel_errors")
# SPEC §23.5: origin-attributed 5xx / platform errors per minute; the key is present (also 0) whenever an
# agent sent it, so readers can tell "no errors" from "agent does not count them"
ERROR_COUNTERS = ("oe", "pe")


def add_tunnel_counters(dst: dict, src: dict) -> None:
    """SPEC §15.4: sum the optional per-minute `tunnel_attempts` / `tunnel_errors` (origin errors)
    into the minute bucket details; absent / zero counters add no key. SPEC §23.5: `oe` / `pe` are
    summed whenever present."""
    for k in TUNNEL_COUNTERS:
        n = max(int(src.get(k) or 0), 0)
        if n:
            dst[k] = int(dst.get(k) or 0) + n
    for k in ERROR_COUNTERS:
        if src.get(k) is not None:
            dst[k] = int(dst.get(k) or 0) + max(int(src.get(k) or 0), 0)


def prune(db: Session, now: datetime | None = None) -> None:
    """Delete minute buckets older than 24 h (leader, job_cleanup). Caller commits."""
    now = now or utcnow()
    db.execute(delete(AnalyticsMinute).where(AnalyticsMinute.minute < floor_minute(now) - RETENTION))


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:00Z")


def _status(d: dict | None = None) -> dict:
    out = {k: 0 for k in STATUS_CLASSES}
    for k, v in (d or {}).items():
        out[str(k)] = out.get(str(k), 0) + num(v)
    return out


def _top(counter: Counter, n: int = 10) -> list[list]:
    return [[k, v] for k, v in sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))[:n] if v > 0]


def series(db: Session, site: Site, minutes: int, now: datetime | None = None) -> dict:
    """`{minutes, from, to, series, totals, top_paths, top_countries}` (SPEC §14.3.1): one point per
    minute, zero-filled, oldest first; `to` is the current (possibly partial) minute, `from` the
    first one. Callers validate 1 <= minutes <= 1440."""
    now = now or utcnow()
    end = floor_minute(now)
    start = end - timedelta(minutes=minutes - 1)
    rows = db.scalars(select(AnalyticsMinute).where(
        AnalyticsMinute.site_id == site.id, AnalyticsMinute.minute >= start, AnalyticsMinute.minute <= end))
    buckets: dict[datetime, dict] = {}
    totals = {"requests": 0, "bytes": 0, "cache_hits": 0, "status": _status()}
    paths, countries = Counter(), Counter()
    for row in rows:
        d = _loads(row.details)
        status = _status(d.get("status"))
        buckets[row.minute] = {"t": _iso(row.minute), "requests": int(row.requests), "bytes": int(row.bytes),
                               "cache_hits": int(row.cache_hits), "status": status}
        totals["requests"] += int(row.requests)
        totals["bytes"] += int(row.bytes)
        totals["cache_hits"] += int(row.cache_hits)
        for k, v in status.items():
            totals["status"][k] = totals["status"].get(k, 0) + v
        paths.update({str(k): num(v) for k, v in obj(d.get("paths")).items()})
        countries.update({str(k): num(v) for k, v in obj(d.get("countries")).items()})
    out, t = [], start
    while t <= end:
        out.append(buckets.get(t) or {"t": _iso(t), "requests": 0, "bytes": 0, "cache_hits": 0,
                                      "status": _status()})
        t += timedelta(minutes=1)
    req = totals["requests"]
    hit_ratio = round(min(totals["cache_hits"] / req, 1.0), 4) if req > 0 else None
    return {
        "minutes": minutes,
        "from": _iso(start),
        "to": _iso(end),
        "series": out,
        "totals": {"requests": req, "bytes": totals["bytes"], "cache_hits": totals["cache_hits"],
                   "hit_ratio": hit_ratio, "status": totals["status"]},
        "top_paths": _top(paths),
        "top_countries": _top(countries),
    }
