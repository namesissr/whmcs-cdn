"""Synthetic edge health probes (SPEC §8.1, extended for multi-address failover §12).

Every ~60s the scheduler (leader only) has the controller itself fetch
``http://<address>/__pcdn/health`` with ``Host: health.pcdn`` for EVERY enabled address of
every enabled edge — the primary (edges.ipv4/ipv6, and the v6 family only when PROBE_IPV6 is
on) AND every enabled additional address (EdgeAddress, §12). This catches a node/address that
still heartbeats (its agent is alive) but serves errors, e.g. after a bad ``nginx -t``.

Success = HTTP 200 whose body starts with ``ok``. Each address stores its own
probe_ok / probe_ms / probe_at / probe_error and a consecutive-failure counter (probe_fail)
that is bumped or reset. The edge-level probe (edges.probe_*) keeps its §8.1 meaning: it
reflects the PRIMARY address (OK when EITHER primary family answers) so the existing edge
probe alert is unchanged; the failing family is still noted in probe_error. run() never raises.
"""

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import settings
from .models import Edge, EdgeAddress, utcnow

log = logging.getLogger("pcdn.probe")

HEALTH_HOST = "health.pcdn"
MAX_WORKERS = 16


def address_url(ip: str, family: str) -> str:
    """The health URL for one address ("4" | "6" family). Monkeypatched in tests."""
    host = ip if family == "4" else f"[{ip}]"
    return f"http://{host}/__pcdn/health"


def probe_url(edge: Edge, family: str) -> str:
    """The health URL for the edge's PRIMARY address of a family ("4" | "6"). Monkeypatched in tests."""
    return address_url(edge.ipv4 if family == "4" else edge.ipv6, family)


def _fetch(url: str, timeout: float) -> tuple[bool, int | None, str | None]:
    """Fetch one health URL. Returns (ok, latency_ms, error); never raises."""
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


def _probe_family(edge: Edge, family: str, timeout: float) -> tuple[bool, int | None, str | None]:
    """Fetch one primary family's health URL. Returns (ok, latency_ms, error); never raises."""
    return _fetch(probe_url(edge, family), timeout)


def _probe_address(ip: str, family: str, timeout: float) -> tuple[bool, int | None, str | None]:
    """Fetch one additional address's health URL. Returns (ok, latency_ms, error); never raises."""
    return _fetch(address_url(ip, family), timeout)


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
    # F32: the primary IPv4 and IPv6 address get INDEPENDENT probe state, so a dead family is
    # withdrawn from DNS (dnsbuild._edge_family_addresses) while the healthy family stays advertised.
    # Only touch a family we actually probed this run; the aggregate above stays for the §8.1 alert.
    if r4 is not None:
        edge.probe_ok4 = r4[0]
        edge.probe_fail4 = 0 if r4[0] else (edge.probe_fail4 or 0) + 1
    if r6 is not None:
        edge.probe_ok6 = r6[0]
        edge.probe_fail6 = 0 if r6[0] else (edge.probe_fail6 or 0) + 1


def _apply_address(a: EdgeAddress, result: tuple[bool, int | None, str | None], now: datetime) -> None:
    """Store one additional address's probe result and bump/reset its fail counter (like _apply)."""
    ok, ms, err = result
    fam = "IPv6" if a.family == 6 else "IPv4"
    a.probe_ok = ok
    a.probe_ms = ms
    a.probe_at = now
    a.probe_error = None if ok else f"{fam}: {err}"
    a.probe_fail = 0 if ok else (a.probe_fail or 0) + 1


def run(db: Session, now: datetime | None = None) -> None:
    """Probe every enabled address of every enabled edge concurrently and persist. Never raises.

    Commits. The primary keeps its edge-level probe semantics; each enabled additional address
    (§12) gets its own probe_ok/ms/at/error/fail.
    """
    now = now or utcnow()
    edges = list(db.scalars(select(Edge).where(Edge.enabled.is_(True)).order_by(Edge.id)))
    if not edges:
        return
    timeout = settings.probe_timeout
    # each task is either a primary family of an edge ("p") or one additional address ("a")
    prim: list[tuple[Edge, str]] = []
    addrs: list[EdgeAddress] = []
    for e in edges:
        prim.append((e, "4"))
        if e.ipv6 and settings.probe_ipv6:
            prim.append((e, "6"))
        for a in e.addresses:
            if not a.enabled or (a.family == 6 and not settings.probe_ipv6):
                continue
            addrs.append(a)
    prim_res: dict[tuple[int, str], tuple] = {}
    addr_res: dict[int, tuple] = {}
    workers = max(1, min(len(prim) + len(addrs), MAX_WORKERS))
    try:
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="pcdn-probe") as pool:
            futures: dict = {}
            for e, fam in prim:
                futures[pool.submit(_probe_family, e, fam, timeout)] = ("p", e.id, fam)
            for a in addrs:
                fam = "6" if a.family == 6 else "4"
                futures[pool.submit(_probe_address, a.ip, fam, timeout)] = ("a", a.id, fam)
            for fut in as_completed(futures):
                kind = futures[fut]
                try:
                    res = fut.result()
                except Exception as ex:  # noqa: BLE001 - a probe never breaks the job
                    res = (False, None, f"{type(ex).__name__}: {ex}"[:300])
                if kind[0] == "p":
                    prim_res[(kind[1], kind[2])] = res
                else:
                    addr_res[kind[1]] = res
    except Exception:  # noqa: BLE001
        log.exception("probe run failed")
        return
    for e in edges:
        _apply(e, prim_res.get((e.id, "4")), prim_res.get((e.id, "6")), now)
        for a in e.addresses:
            if a.id in addr_res:
                _apply_address(a, addr_res[a.id], now)
    db.commit()
