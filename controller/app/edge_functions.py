"""Edge functions statistics (SPEC §16.9).

The edges bill every pcdn-fn invocation into the `functions` counters of the host-hour usage item
({invocations, cpu_ms, errors, timeouts}); /edge/v1/usage sums them into UsageHourly.details. This
module reads them back for the admin API (/api/v1/sites/{domain}/functions/stats) and the customer
API (/capi/v1/functions/stats, scope stats).
"""

import json
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Site, UsageHourly, utcnow

COUNTERS = ("invocations", "cpu_ms", "errors", "timeouts")
MAX_HOURS = 744  # 31 days


def stats(db: Session, site: Site, hours: int) -> dict:
    """Totals and a zero-filled hourly series of the last `hours` hours (the current hour included).
    error_pct = (errors + timeouts) / invocations in percent (the two are disjoint), 0 without
    invocations."""
    now = utcnow().replace(minute=0, second=0, microsecond=0)
    since = now - timedelta(hours=hours - 1)
    buckets: dict[str, dict] = {}
    rows = db.execute(select(UsageHourly.hour, UsageHourly.details).where(
        UsageHourly.site_id == site.id, UsageHourly.hour >= since))
    for hour, details in rows:
        try:
            fn = json.loads(details or "{}").get("functions") or {}
        except (ValueError, AttributeError):
            continue
        if not isinstance(fn, dict) or not fn:
            continue
        key = hour.strftime("%Y-%m-%dT%H:00:00Z")
        b = buckets.setdefault(key, {"t": key, **{k: 0 for k in COUNTERS}})
        for k in COUNTERS:
            try:
                b[k] += max(int(fn.get(k) or 0), 0)
            except (TypeError, ValueError):
                pass
    series, t = [], since
    while t <= now:
        key = t.strftime("%Y-%m-%dT%H:00:00Z")
        series.append(buckets.get(key, {"t": key, **{k: 0 for k in COUNTERS}}))
        t += timedelta(hours=1)
    totals = {k: sum(b[k] for b in series) for k in COUNTERS}
    inv = totals["invocations"]
    return {
        "hours": hours,
        **totals,
        "error_pct": round((totals["errors"] + totals["timeouts"]) * 100 / inv, 2) if inv else 0.0,
        "series": [{k: b[k] for k in ("t", "invocations", "errors", "timeouts", "cpu_ms")} for b in series],
    }
