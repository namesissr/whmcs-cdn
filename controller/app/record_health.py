"""Controller health checks of non-proxied DNS records (SPEC §16.7).

Every 60 s the scheduler leader probes every non-proxied A/AAAA/CNAME record with health_check:

* ``tcp`` (default): a TCP connection to the address on ``health_port`` (default 80);
* ``http`` / ``https``: ``GET <health_path>`` on ``health_port`` (default 80 / 443) with
  ``Host: <record name>`` (and that SNI); healthy = status 200..399; certificates are not verified
  (this is a reachability check, not a TLS audit).

A CNAME is probed on its target, resolved here. Only public addresses are ever contacted (the A/AAAA
contents are validated public on write; a CNAME target resolving to a non-public address is
reported unhealthy and never connected to), so a record cannot point the controller's probe into its
own network.

The result is stored on the record (health_ok / health_ms / health_at / health_error) with a
consecutive-failure counter health_fail; dnsbuild withdraws a member after PROBE_FAIL_CHECKS failures
in a row and never withdraws every member of a set (fail-open). When the answer of a site's zone
changes, that zone is re-synced right away. run() never raises.
"""

import logging
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import dnsbuild, netguard
from .config import settings
from .models import Record, Site, utcnow
from .validation import fqdn

log = logging.getLogger("pcdn.record_health")

MAX_WORKERS = 32
MAX_RECORDS = 1000  # per run; a pathological zone must not stall the scheduler


def _addresses(r: Record) -> list[str]:
    """The public addresses to probe for a record (CNAME: the resolved target)."""
    if r.type in ("A", "AAAA"):
        return [r.content] if netguard.is_public_ip(r.content) else []
    ips = netguard.resolver(r.content, 80)
    if any(not netguard.is_public_ip(ip) for ip in ips):
        raise ValueError("مقصد CNAME به آدرس غیرعمومی اشاره می‌کند")
    return sorted(ips, key=lambda ip: ":" in ip)[:2]


def check(r: Record, host: str, timeout: float) -> tuple[bool, int | None, str | None]:
    """Probe one record. Returns (ok, latency_ms, error); never raises. Monkeypatched in tests."""
    proto = r.health_protocol or "tcp"
    port = r.health_port or (443 if proto == "https" else 80)
    t0 = time.monotonic()
    try:
        ips = _addresses(r)
    except (OSError, UnicodeError, ValueError) as e:
        return False, None, str(e)[:300] or "resolve failed"
    if not ips:
        return False, None, "آدرس عمومی برای بررسی پیدا نشد"
    last = None
    for ip in ips:
        try:
            if proto == "tcp":
                with socket.create_connection((ip, port), timeout=timeout):
                    pass
                return True, int((time.monotonic() - t0) * 1000), None
            hostpart = f"[{ip}]" if ":" in ip else ip
            ext = {"sni_hostname": host} if proto == "https" else {}
            with httpx.Client(timeout=timeout, verify=False, trust_env=False, follow_redirects=False) as c:
                resp = c.get(f"{proto}://{hostpart}:{port}{r.health_path or '/'}", headers={"Host": host},
                             extensions=ext)
            ms = int((time.monotonic() - t0) * 1000)
            if 200 <= resp.status_code < 400:
                return True, ms, None
            return False, ms, f"HTTP {resp.status_code}"
        except (OSError, httpx.HTTPError) as e:
            last = f"{type(e).__name__}: {e}"[:300]
    return False, None, last


def _answer(site: Site) -> str:
    """Fingerprint of the advertised members of the site's checked sets (decides a zone re-sync)."""
    return ",".join(f"{r.id}:{int(dnsbuild.record_advertised(r))}" for r in site.records if r.health_check)


def run(db: Session, now=None) -> list[str]:
    """Probe every health-checked non-proxied record, persist, re-sync changed zones. Returns the
    domains whose zone was re-synced."""
    from .services import sync_site_dns

    now = now or utcnow()
    recs = list(db.scalars(select(Record).where(Record.health_check.is_(True), Record.proxied.is_(False),
                                                Record.type.in_(("A", "AAAA", "CNAME")))
                           .order_by(Record.id).limit(MAX_RECORDS)))
    if not recs:
        return []
    sites = {r.site_id: r.site for r in recs}
    before = {sid: _answer(s) for sid, s in sites.items()}
    results: dict[int, tuple] = {}
    timeout = settings.record_probe_timeout
    try:
        with ThreadPoolExecutor(max_workers=max(1, min(len(recs), MAX_WORKERS)),
                                thread_name_prefix="pcdn-rprobe") as pool:
            futures = {pool.submit(check, r, fqdn(r.name, r.site.domain), timeout): r.id for r in recs}
            for fut in as_completed(futures):
                try:
                    results[futures[fut]] = fut.result()
                except Exception as e:  # noqa: BLE001 - a probe never breaks the job
                    results[futures[fut]] = (False, None, f"{type(e).__name__}: {e}"[:300])
    except Exception:  # noqa: BLE001
        log.exception("record probe run failed")
        return []
    for r in recs:
        ok, ms, err = results.get(r.id, (False, None, "no result"))
        r.health_ok, r.health_ms, r.health_at, r.health_error = ok, ms, now, None if ok else err
        r.health_fail = 0 if ok else (r.health_fail or 0) + 1
    db.commit()
    synced = []
    for sid, site in sites.items():
        if _answer(site) != before[sid]:
            log.info("record health changed for %s: re-syncing the zone", site.domain)
            sync_site_dns(db, site)
            synced.append(site.domain)
    return synced
