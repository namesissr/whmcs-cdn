"""Edge availability tracking.

Every scheduler tick samples each enabled edge's online state into a per-edge, per-hour
rollup (EdgeUptime): samples_total counts the ticks taken that hour, samples_online the
ticks where the edge had reported within EDGE_OFFLINE_SECONDS. Uptime % over any window is
sum(online) / sum(total). Cheap: one row per edge per hour, upserted in place.
"""

import logging
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import settings
from .models import Edge, EdgeUptime, utcnow

log = logging.getLogger("pcdn.uptime")

RETAIN_DAYS = 400


def floor_hour(dt: datetime) -> datetime:
    return dt.replace(minute=0, second=0, microsecond=0)


def sample(db: Session, now: datetime | None = None) -> None:
    """Record one availability sample for every enabled edge. Caller-independent (commits)."""
    now = now or utcnow()
    hour = floor_hour(now)
    cutoff = now - timedelta(seconds=settings.edge_offline_seconds)
    edges = list(db.scalars(select(Edge).where(Edge.enabled.is_(True))))
    if not edges:
        return
    rows = {r.edge_id: r for r in db.scalars(
        select(EdgeUptime).where(EdgeUptime.hour == hour, EdgeUptime.edge_id.in_([e.id for e in edges])))}
    for e in edges:
        online = e.last_seen_at is not None and e.last_seen_at >= cutoff
        row = rows.get(e.id)
        if row is None:
            row = EdgeUptime(edge_id=e.id, hour=hour, samples_total=0, samples_online=0)
            db.add(row)
        row.samples_total += 1
        row.samples_online += 1 if online else 0
    db.commit()


def prune(db: Session, now: datetime | None = None) -> None:
    from sqlalchemy import delete
    now = now or utcnow()
    db.execute(delete(EdgeUptime).where(EdgeUptime.hour < now - timedelta(days=RETAIN_DAYS)))


def _pct(rows) -> float | None:
    total = sum(r.samples_total for r in rows)
    if total <= 0:
        return None
    return round(sum(r.samples_online for r in rows) * 100 / total, 2)


def summary(db: Session, edge_id: int, now: datetime | None = None) -> dict:
    """{'h24': %|None, 'd30': %|None} for one edge (None until there is data)."""
    now = now or utcnow()
    rows = list(db.scalars(select(EdgeUptime).where(
        EdgeUptime.edge_id == edge_id, EdgeUptime.hour >= floor_hour(now) - timedelta(days=30))))
    h24_from = now - timedelta(hours=24)
    return {"h24": _pct([r for r in rows if r.hour >= floor_hour(h24_from)]), "d30": _pct(rows)}


def summaries(db: Session, now: datetime | None = None) -> dict[int, dict]:
    """summary() for every edge that has any rows, in one query."""
    now = now or utcnow()
    rows = list(db.scalars(select(EdgeUptime).where(
        EdgeUptime.hour >= floor_hour(now) - timedelta(days=30))))
    by_edge: dict[int, list] = {}
    for r in rows:
        by_edge.setdefault(r.edge_id, []).append(r)
    h24 = floor_hour(now - timedelta(hours=24))
    return {eid: {"h24": _pct([r for r in rs if r.hour >= h24]), "d30": _pct(rs)}
            for eid, rs in by_edge.items()}


def daily(db: Session, edge_id: int, days: int, now: datetime | None = None) -> dict:
    """Per-day uptime for the last `days` days plus the overall %."""
    now = now or utcnow()
    days = max(1, min(days, 365))
    start_day = (now - timedelta(days=days - 1)).date()
    rows = list(db.scalars(select(EdgeUptime).where(
        EdgeUptime.edge_id == edge_id, EdgeUptime.hour >= datetime(start_day.year, start_day.month, start_day.day))))
    by_day: dict[str, list] = {}
    for r in rows:
        by_day.setdefault(r.hour.date().isoformat(), []).append(r)
    out = []
    for i in range(days):
        day = (start_day + timedelta(days=i)).isoformat()
        out.append({"day": day, "uptime": _pct(by_day.get(day, []))})
    return {"days": out, "overall": _pct(rows)}
