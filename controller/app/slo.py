"""Operator SLO dashboard (SPEC §23.11): SLIs per edge group, error budget and multi-window burn alerts.

SLIs
* availability: each probe tick (job_probe), per group: good when at least one enabled, non-draining
  edge of EVERY region pool of the group that has such edges answered the controller probe; ticks with
  no enabled edge in the group are not counted. edge_availability (informational) = good probes / all
  probes over the group's edges (per month, in `state`).
* latency: successful probes with probe_ms <= SLO_LATENCY_MS / successful probes.
* errors: 1 - platform errors / requests from the minute buckets' `pe` (sites of the group), falling
  back to the hourly usage platform errors for hours without `pe` data.
Storage: slo_buckets 5m (kept 3 days) and 1h (SLO_RETENTION_DAYS). Operator-only; no customer impact.
"""

import json
from datetime import datetime, timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from . import alerts, dnsbuild, kv
from .config import settings
from .models import AnalyticsMinute, Edge, Site, SloBucket, UsageHourly, utcnow

SLIS = ("availability", "latency", "errors")
GROUPS = ("general", "tunnel")
WINDOWS = {"5m": timedelta(minutes=5), "30m": timedelta(minutes=30), "1h": timedelta(hours=1),
           "6h": timedelta(hours=6)}
FAST, SLOW = 14.4, 6.0
# burn alerts need enough samples in the LONG window (probe ticks / probes, or requests): a single bad
# probe right after a restart must not page anyone
MIN_SAMPLES = {"fast": 30, "slow": 180, "exhausted": 60}
MIN_REQUESTS = 1000


def enough(sli: str, total: int, kind: str) -> bool:
    return total >= (MIN_REQUESTS if sli == "errors" else MIN_SAMPLES[kind])
FIVE = timedelta(minutes=5)
LAST_5M = "slo:errors_done"
LAST_1H = "slo:rollup_done"
EDGE_AVAIL = "slo:edge_avail:{}:{}"
PROBE_FRESH = timedelta(minutes=3)


def objectives(group: str) -> dict[str, float]:
    base = {"availability": settings.slo_availability, "latency": settings.slo_latency, "errors": settings.slo_errors}
    over = settings.slo_overrides.get(group) if isinstance(settings.slo_overrides, dict) else None
    if isinstance(over, dict):
        for k, v in over.items():
            if k in base and isinstance(v, (int, float)) and 50 <= v < 100:
                base[k] = float(v)
    return base


def floor5(dt: datetime) -> datetime:
    return dt.replace(minute=dt.minute - dt.minute % 5, second=0, microsecond=0)


def _bucket(db: Session, group: str, start: datetime, res: str) -> SloBucket:
    from . import kv as _kv

    _kv.insert_ignore(db, SloBucket, {"group": group, "start": start, "res": res, "avail_good": 0, "avail_total": 0,
                                      "lat_good": 0, "lat_total": 0, "requests": 0, "errors": 0})
    return db.scalar(select(SloBucket).where(SloBucket.group == group, SloBucket.start == start,
                                             SloBucket.res == res).execution_options(populate_existing=True))


# ------------------------------------------------------------------ probe ticks

def classify(edges: list, now: datetime) -> dict[str, dict]:
    """Pure: per group {"tick": True|False|None, "probes": n, "good_probes": n, "ok": n, "fast": n}."""
    out = {}
    by_group: dict[str, list] = {}
    for e in edges:
        if e.enabled:
            by_group.setdefault(dnsbuild.edge_group(e), []).append(e)
    for group, members in by_group.items():
        fresh = [e for e in members if e.probe_at is not None and now - e.probe_at <= PROBE_FRESH
                 and e.probe_ok is not None]
        pools: dict[str, list] = {}
        for e in members:
            if not dnsbuild.is_draining(e):
                pools.setdefault(dnsbuild.region_of(e), []).append(e)
        if not pools:
            tick = None
        else:
            tick = all(any(e.probe_ok and e.probe_at is not None and now - e.probe_at <= PROBE_FRESH for e in pool)
                       for pool in pools.values())
        ok = [e for e in fresh if e.probe_ok]
        out[group] = {"tick": tick, "probes": len(fresh), "good_probes": len(ok), "ok": len(ok),
                      "fast": sum(1 for e in ok if (e.probe_ms or 0) <= settings.slo_latency_ms)}
    return out


def record_probe_tick(db: Session, now: datetime | None = None) -> dict:
    """Called after each probe run (job_probe). Caller commits."""
    if not settings.slo_enabled:
        return {}
    now = now or utcnow()
    res = classify(list(db.scalars(select(Edge))), now)
    month = now.strftime("%Y-%m")
    for group, r in res.items():
        b = _bucket(db, group, floor5(now), "5m")
        if r["tick"] is not None:
            b.avail_total += 1
            b.avail_good += 1 if r["tick"] else 0
        b.lat_total += r["ok"]
        b.lat_good += r["fast"]
        key = EDGE_AVAIL.format(group, month)
        doc = kv.get_json(db, key)
        kv.set_json(db, key, {"good": int(doc.get("good", 0)) + r["good_probes"],
                              "total": int(doc.get("total", 0)) + r["probes"]})
    return res


# ------------------------------------------------------------------ errors + rollup (job_slo)

def _site_groups(db: Session) -> dict[int, str]:
    return {s.id: dnsbuild.site_edge_group(s) for s in db.scalars(select(Site))}


def fill_errors(db: Session, start: datetime, end: datetime) -> None:
    groups = _site_groups(db)
    acc: dict[str, list] = {}
    for sid, req, details in db.execute(select(AnalyticsMinute.site_id, AnalyticsMinute.requests,
                                               AnalyticsMinute.details).where(
            AnalyticsMinute.minute >= start, AnalyticsMinute.minute < end)):
        try:
            d = json.loads(details or "{}")
        except ValueError:
            continue
        if not isinstance(d, dict) or "pe" not in d:
            continue  # minutes from agents that do not send `pe`: the hourly fallback covers them
        a = acc.setdefault(groups.get(sid, "general"), [0, 0])
        a[0] += int(req or 0)
        a[1] += max(int(d.get("pe") or 0), 0)
    for group, (req, err) in acc.items():
        b = _bucket(db, group, start, "5m")
        b.requests += req
        b.errors += min(err, req)


def rollup_hour(db: Session, hour: datetime) -> None:
    end = hour + timedelta(hours=1)
    rows = db.execute(select(SloBucket.group, func.sum(SloBucket.avail_good), func.sum(SloBucket.avail_total),
                             func.sum(SloBucket.lat_good), func.sum(SloBucket.lat_total),
                             func.sum(SloBucket.requests), func.sum(SloBucket.errors)).where(
        SloBucket.res == "5m", SloBucket.start >= hour, SloBucket.start < end).group_by(SloBucket.group)).all()
    fallback: dict[str, list] = {}
    for g, req, details in db.execute(select(Edge.group, UsageHourly.requests, UsageHourly.details)
                                      .join(Edge, Edge.id == UsageHourly.edge_id).where(UsageHourly.hour == hour)):
        try:
            d = json.loads(details or "{}")
        except ValueError:
            d = {}
        a = fallback.setdefault(g or "general", [0, 0])
        a[0] += int(req or 0)
        a[1] += int((d or {}).get("platform_errors") or 0)
    seen = set()
    for g, ag, at, lg, lt, req, err in rows:
        seen.add(g)
        b = _bucket(db, g, hour, "1h")
        b.avail_good, b.avail_total, b.lat_good, b.lat_total = int(ag or 0), int(at or 0), int(lg or 0), int(lt or 0)
        if int(req or 0) > 0:
            b.requests, b.errors = int(req), int(err or 0)
        elif g in fallback:
            b.requests, b.errors = fallback[g][0], min(fallback[g][1], fallback[g][0])
    for g, (req, err) in fallback.items():
        if g not in seen and req:
            b = _bucket(db, g, hour, "1h")
            b.requests, b.errors = req, min(err, req)


def run(db: Session, now: datetime | None = None) -> dict:
    """job_slo: error counters of completed 5-minute windows, hourly rollup, burn alerts, retention."""
    if not settings.slo_enabled:
        return {}
    now = now or utcnow()
    cur5 = floor5(now)
    done = kv.get_json(db, LAST_5M).get("end")
    t = datetime.fromisoformat(done) if done else cur5 - FIVE
    t = max(t, cur5 - timedelta(hours=1))
    while t < cur5:
        fill_errors(db, t, t + FIVE)
        t += FIVE
    kv.set_json(db, LAST_5M, {"end": cur5.isoformat()})
    hour = now.replace(minute=0, second=0, microsecond=0)
    done_h = kv.get_json(db, LAST_1H).get("end")
    h = datetime.fromisoformat(done_h) if done_h else hour - timedelta(hours=1)
    h = max(h, hour - timedelta(hours=48))
    while h < hour:
        rollup_hour(db, h)
        h += timedelta(hours=1)
    kv.set_json(db, LAST_1H, {"end": hour.isoformat()})
    db.execute(delete(SloBucket).where(SloBucket.res == "5m", SloBucket.start < now - timedelta(days=3)))
    db.execute(delete(SloBucket).where(SloBucket.res == "1h",
                                       SloBucket.start < now - timedelta(days=settings.slo_retention_days)))
    db.commit()
    state = evaluate(db, now)
    sync_alerts(state)
    return state


# ------------------------------------------------------------------ math

def bad_total(b: dict, sli: str) -> tuple[int, int]:
    if sli == "availability":
        return b["avail_total"] - b["avail_good"], b["avail_total"]
    if sli == "latency":
        return b["lat_total"] - b["lat_good"], b["lat_total"]
    return b["errors"], b["requests"]


def burn_rate(bad: int, total: int, objective: float) -> float:
    budget = 1 - objective / 100.0
    if total <= 0 or budget <= 0:
        return 0.0
    return round((bad / total) / budget, 3)


def _sum(db: Session, group: str, res: str, start: datetime, end: datetime) -> dict:
    row = db.execute(select(func.sum(SloBucket.avail_good), func.sum(SloBucket.avail_total),
                            func.sum(SloBucket.lat_good), func.sum(SloBucket.lat_total),
                            func.sum(SloBucket.requests), func.sum(SloBucket.errors)).where(
        SloBucket.group == group, SloBucket.res == res, SloBucket.start >= start, SloBucket.start < end)).one()
    keys = ("avail_good", "avail_total", "lat_good", "lat_total", "requests", "errors")
    return {k: int(v or 0) for k, v in zip(keys, row)}


def _add(a: dict, b: dict) -> dict:
    return {k: a[k] + b[k] for k in a}


def window(db: Session, group: str, now: datetime, span: timedelta) -> dict:
    return _sum(db, group, "5m", floor5(now) - span + FIVE, floor5(now) + FIVE)


def month_bounds(month: str | None, now: datetime) -> tuple[datetime, datetime]:
    if month:
        y, m = (int(x) for x in month.split("-"))
    else:
        y, m = now.year, now.month
    start = datetime(y, m, 1)
    end = datetime(y + (m == 12), m % 12 + 1, 1)
    return start, end


def month_totals(db: Session, group: str, start: datetime, end: datetime, now: datetime) -> dict:
    """1h rows of the month + the 5m rows not rolled up yet."""
    rolled = datetime.fromisoformat(kv.get_json(db, LAST_1H).get("end")) if kv.get_json(db, LAST_1H).get("end") \
        else start
    rolled = min(max(rolled, start), end)
    total = _sum(db, group, "1h", start, rolled)
    if rolled < end:
        total = _add(total, _sum(db, group, "5m", rolled, min(end, now + FIVE)))
    return total


def evaluate(db: Session, now: datetime | None = None, month: str | None = None) -> dict:
    now = now or utcnow()
    start, end = month_bounds(month, now)
    groups = sorted({g for (g,) in db.execute(select(Edge.group).distinct())} | set(GROUPS))
    out = {"month": start.strftime("%Y-%m"), "objectives": {g: objectives(g) for g in groups}, "groups": []}
    current = start <= now < end
    for g in groups:
        obj = objectives(g)
        tot = month_totals(db, g, start, end, now)
        wins = {name: window(db, g, now, span) for name, span in WINDOWS.items()} if current else {}
        slis = {}
        for sli in SLIS:
            bad, total = bad_total(tot, sli)
            budget = 1 - obj[sli] / 100.0
            actual = round(100.0 * (total - bad) / total, 3) if total else None
            remaining = round(100.0 * (1 - (bad / total) / budget), 1) if total and budget > 0 else None
            burn = {name: burn_rate(*bad_total(w, sli), obj[sli]) for name, w in wins.items()}
            alert = None
            exhausted = remaining is not None and remaining <= 0 and enough(sli, total, "exhausted")
            if current:
                if burn["1h"] >= FAST and burn["5m"] >= FAST and enough(sli, bad_total(wins["1h"], sli)[1], "fast"):
                    alert = "fast"
                elif burn["6h"] >= SLOW and burn["30m"] >= SLOW and enough(sli, bad_total(wins["6h"], sli)[1],
                                                                            "slow"):
                    alert = "slow"
                elif exhausted:
                    alert = "exhausted"
            slis[sli] = {"objective": obj[sli], "actual": actual, "good": total - bad, "total": total,
                         "budget_remaining_pct": remaining, "burn": burn, "alert": alert,
                         "exhausted": exhausted}
        ea = kv.get_json(db, EDGE_AVAIL.format(g, start.strftime("%Y-%m")))
        daily = []
        d = start
        while d < min(end, now + timedelta(days=1)):
            day = _sum(db, g, "1h", d, d + timedelta(days=1))
            entry = {"day": d.date().isoformat()}
            for sli in SLIS:
                bad, total = bad_total(day, sli)
                entry[sli] = round(100.0 * (total - bad) / total, 3) if total else None
            daily.append(entry)
            d += timedelta(days=1)
        out["groups"].append({"group": g, "slis": slis,
                              "edge_availability": round(100.0 * ea["good"] / ea["total"], 3)
                              if ea.get("total") else None, "daily": daily})
    return out


def sync_alerts(state: dict) -> None:
    fast, slow, exhausted = {}, {}, {}
    open_keys = {c.get("key") for c in alerts.open_alerts()}
    for g in state.get("groups", []):
        for sli, v in g["slis"].items():
            key = f"{g['group']}:{sli}"
            burn = v.get("burn") or {}
            # an open alert stays open while its SHORT window is still at/above the threshold
            if v["alert"] == "fast" or (f"slo_burn_fast:{key}" in open_keys and burn.get("5m", 0) >= FAST):
                fast[f"slo_burn_fast:{key}"] = (f"مصرف سریع بودجهٔ خطای {sli} در گروه {g['group']}",
                                                f"نرخ مصرف بودجهٔ خطا در ۱ ساعت و ۵ دقیقهٔ اخیر ≥ {FAST} است "
                                                f"(1h={v['burn'].get('1h')}, 5m={v['burn'].get('5m')}).", "critical")
            if v["alert"] == "slow" or (f"slo_burn_slow:{key}" in open_keys and burn.get("30m", 0) >= SLOW):
                slow[f"slo_burn_slow:{key}"] = (f"مصرف کند بودجهٔ خطای {sli} در گروه {g['group']}",
                                                f"نرخ مصرف بودجهٔ خطا در ۶ ساعت و ۳۰ دقیقهٔ اخیر ≥ {SLOW} است "
                                                f"(6h={v['burn'].get('6h')}, 30m={v['burn'].get('30m')}).", "warning")
            if v.get("exhausted"):
                exhausted[f"slo_budget_exhausted:{key}"] = (f"بودجهٔ خطای ماه برای {sli} در گروه {g['group']} تمام شد",
                                                            f"هدف {v['objective']}٪؛ مقدار فعلی {v['actual']}٪.",
                                                            "warning")
    # resolve when the SHORT window drops below the threshold (no condition above -> resolved)
    alerts.sync("slo_burn_fast:", fast)
    alerts.sync("slo_burn_slow:", slow)
    alerts.sync("slo_budget_exhausted:", exhausted)
