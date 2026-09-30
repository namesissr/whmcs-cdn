"""Synthetic edge health probes (SPEC §8.1).

Every ~60s the scheduler (leader only) has the controller itself fetch
``http://<edge.ipv4>/__pcdn/health`` with ``Host: health.pcdn`` for every enabled edge —
and the IPv6 address too when the edge has one and PROBE_IPV6 is on. This catches a node
that still heartbeats (its agent is alive) but serves errors, e.g. after a bad ``nginx -t``.

Success = HTTP 200 whose body starts with ``ok``. The result is stored on the Edge object
(probe_ok / probe_ms / probe_at / probe_error) and the consecutive-failure counter
(probe_fail) is bumped or reset. An edge counts as OK when EITHER address family answers;
the failing family is still noted in probe_error. run() never raises.
"""

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import settings
from .models import Edge, utcnow

log = logging.getLogger("pcdn.probe")

HEALTH_HOST = "health.pcdn"
MAX_WORKERS = 16


def probe_url(edge: Edge, family: str) -> str:
    """The health URL for one address family ("4" | "6"). Monkeypatched in tests."""
    host = edge.ipv4 if family == "4" else f"[{edge.ipv6}]"
    return f"http://{host}/__pcdn/health"


def _probe_family(edge: Edge, family: str, timeout: float) -> tuple[bool, int | None, str | None]:
    """Fetch one family's health URL. Returns (ok, latency_ms, error); never raises."""
    url = probe_url(edge, family)
    t0 = time.monotonic()
    try:
        # trust_env=False: probe the edge IP directly, never through an HTTP(S) proxy
        with httpx.Client(timeout=timeout, trust_env=False) as c:
            r = c.get(url, headers={"Host": HEALTH_HOST})
    except httpx.HTTPError as e:
        return False, None, f"{type(e).__name__}: {e}"[:300]
    ms = int((time.monotonic() - t0) * 1000)
    if r.status_code != 200:
        return False, ms, f"HTTP {r.status_code}"
    if not (r.text or "").startswith("ok"):
        return False, ms, "پاسخ نامعتبر (بدنه با ok شروع نمی‌شود)"
    return True, ms, None


def _apply(edge: Edge, r4, r6, now: datetime) -> None:
    results = [r for r in (r4, r6) if r is not None]
    ok = any(r[0] for r in results)
    ok_ms = [r[1] for r in results if r[0] and r[1] is not None]
    if ok_ms:
        ms = min(ok_ms)
    else:
        ms = next((r[1] for r in results if r[1] is not None), None)
    errors = []
    if r4 is not None and not r4[0]:
        errors.append(f"IPv4: {r4[2]}")
    if r6 is not None and not r6[0]:
        errors.append(f"IPv6: {r6[2]}")
    edge.probe_ok = ok
    edge.probe_ms = ms
    edge.probe_at = now
    edge.probe_error = " | ".join(errors) or None
    edge.probe_fail = 0 if ok else (edge.probe_fail or 0) + 1


def run(db: Session, now: datetime | None = None) -> None:
    """Probe every enabled edge concurrently and persist the result. Never raises. Commits."""
    now = now or utcnow()
    edges = list(db.scalars(select(Edge).where(Edge.enabled.is_(True)).order_by(Edge.id)))
    if not edges:
        return
    tasks: list[tuple[Edge, str]] = []
    for e in edges:
        tasks.append((e, "4"))
        if e.ipv6 and settings.probe_ipv6:
            tasks.append((e, "6"))
    timeout = settings.probe_timeout
    results: dict[tuple[int, str], tuple] = {}
    workers = max(1, min(len(tasks), MAX_WORKERS))
    try:
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="pcdn-probe") as pool:
            futures = {pool.submit(_probe_family, e, fam, timeout): (e.id, fam) for e, fam in tasks}
            for fut in as_completed(futures):
                key = futures[fut]
                try:
                    results[key] = fut.result()
                except Exception as ex:  # noqa: BLE001 - a probe never breaks the job
                    results[key] = (False, None, f"{type(ex).__name__}: {ex}"[:300])
    except Exception:  # noqa: BLE001
        log.exception("probe run failed")
        return
    for e in edges:
        _apply(e, results.get((e.id, "4")), results.get((e.id, "6")), now)
    db.commit()
