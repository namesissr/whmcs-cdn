"""Tunnel mode helpers for the customer API (SPEC §7.5): traffic stats and origin reachability."""

import ipaddress
import json
import socket
import ssl as ssl_lib
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import sections
from .models import Site, UsageHourly, utcnow
from .services import resolve_origin
from .validation import fqdn

COUNTERS = ("sessions", "seconds", "bytes_up", "bytes_down")
CONNECT_TIMEOUT = 5.0  # TCP connect, and again for the TLS handshake
MAX_WORKERS = 16


# ------------------------------------------------------------------ stats

def stats(db: Session, site: Site, hours: int) -> dict:
    now = utcnow().replace(minute=0, second=0, microsecond=0)
    since = now - timedelta(hours=hours - 1)
    buckets: dict[str, dict] = {}
    by_protocol: dict[str, int] = {}
    for row in db.scalars(select(UsageHourly).where(UsageHourly.site_id == site.id, UsageHourly.hour >= since)):
        try:
            tn = json.loads(row.details or "{}").get("tunnel") or {}
        except ValueError:
            continue
        if not tn:
            continue
        key = row.hour.strftime("%Y-%m-%dT%H:00:00Z")
        b = buckets.setdefault(key, {"hour": key, **{k: 0 for k in COUNTERS}})
        for k in COUNTERS:
            b[k] += int(tn.get(k) or 0)
        for proto, v in (tn.get("by_protocol") or {}).items():
            by_protocol[proto] = by_protocol.get(proto, 0) + int(v)
    series, t = [], since
    while t <= now:  # zero-filled: one point per hour
        key = t.strftime("%Y-%m-%dT%H:00:00Z")
        series.append(buckets.get(key, {"hour": key, **{k: 0 for k in COUNTERS}}))
        t += timedelta(hours=1)
    return {
        "hours": series,
        "by_protocol": by_protocol,
        "totals": {k: sum(b[k] for b in series) for k in ("sessions", "bytes_up", "bytes_down")},
    }


# ------------------------------------------------------------------ reachability check

def _host_origin(site: Site, cfg: dict) -> list[dict] | str:
    """Targets of the site's own origin (a path with neither origin nor pool).

    Tunnel paths apply to every proxied host; the apex (or else the first proxied
    host) stands for them, like the host list of the edge config.
    """
    proxied = [r for r in site.records if r.proxied]
    rec = next((r for r in proxied if r.name == "@"), proxied[0] if proxied else None)
    if rec is None:
        return "هیچ رکورد پروکسی‌شده‌ای برای این سایت وجود ندارد"
    if rec.pool:
        return _pool_targets(site, cfg, rec.pool)
    address = resolve_origin(site, rec)
    if not address:
        return f"سرور اصلی {fqdn(rec.name, site.domain)} مشخص نیست"
    tls = cfg["ssl"]["origin_protocol"] == "https"
    return [{"address": address, "port": rec.origin_port or (443 if tls else 80), "tls": tls,
             "sni": fqdn(rec.name, site.domain), "verify": cfg["ssl"]["origin_verify"]}]


def _pool_targets(site: Site, cfg: dict, name: str) -> list[dict] | str:
    pool = next((p for p in cfg["pools"]["pools"] if p["name"] == name), None)
    if pool is None:
        return f"استخر {name} تعریف نشده است"
    tls = pool["protocol"] == "https"
    return [{"address": o["address"], "port": o["port"], "tls": tls, "sni": site.domain,
             "verify": cfg["ssl"]["origin_verify"]} for o in pool["origins"]]


def targets(site: Site) -> list[tuple[str, list[dict] | str]]:
    """(path id, [target...] or an error) for every tunnel path of the site."""
    cfg = sections.all_config(site)
    out = []
    for p in cfg["tunnel"]["paths"]:
        if p["origin"]:
            o = p["origin"]
            out.append((p["id"], [{**o, "sni": o["sni"] or site.domain}]))
        elif p["pool"]:
            out.append((p["id"], _pool_targets(site, cfg, p["pool"])))
        else:
            out.append((p["id"], _host_origin(site, cfg)))
    return out


def _public(ip: str) -> bool:
    """Only public addresses are probed: a hostname must not lead the controller into its own network."""
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:  # e.g. a scoped link-local address
        return False


def _resolve(host: str, port: int) -> list[str]:
    """Public addresses of host, IPv4 first (the controller's network often has no IPv6)."""
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    ips = list(dict.fromkeys(info[4][0] for info in infos))
    public = sorted((ip for ip in ips if _public(ip)), key=lambda ip: ":" in ip)
    if not public:
        raise ValueError("آدرس سرور اصلی عمومی نیست" if ips else "نام میزبان پیدا نشد")
    return public[:3]


def _connect(ips: list[str], port: int) -> socket.socket:
    """First address that accepts the connection; the last error when none does."""
    last: Exception | None = None
    for ip in ips:
        try:
            return socket.create_connection((ip, port), timeout=CONNECT_TIMEOUT)
        except OSError as e:
            last = e
    raise last  # type: ignore[misc]


def probe(target: dict) -> dict:
    """TCP connect (+ TLS handshake) to one origin. Never raises."""
    host = target["address"].strip("[]")
    start = time.monotonic()
    try:
        ips = _resolve(host, target["port"])
        start = time.monotonic()
        with _connect(ips, target["port"]) as sock:
            if target.get("tls"):
                ctx = ssl_lib.create_default_context()
                if not target.get("verify"):
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl_lib.CERT_NONE
                sock.settimeout(CONNECT_TIMEOUT)
                with ctx.wrap_socket(sock, server_hostname=target.get("sni") or None):
                    pass
        return {"ok": True, "ms": int((time.monotonic() - start) * 1000), "error": None}
    except socket.gaierror:
        error = "نام میزبان پیدا نشد"
    except (TimeoutError, socket.timeout):
        error = f"پاسخی در {CONNECT_TIMEOUT:g} ثانیه دریافت نشد"
    except ConnectionRefusedError:
        error = "اتصال رد شد (پورت بسته است)"
    except ssl_lib.SSLCertVerificationError as e:
        error = f"گواهی سرور اصلی معتبر نیست: {e.verify_message or e}"[:300]
    except ssl_lib.SSLError as e:
        error = f"خطای TLS: {e.reason or e}"[:300]
    except ValueError as e:
        error = str(e)[:300]
    except Exception as e:  # noqa: BLE001 - a check never fails the request
        error = f"{type(e).__name__}: {e}"[:300]
    return {"ok": False, "ms": None, "error": error}


def check(paths: list[tuple[str, list[dict] | str]]) -> list[dict]:
    """Probe every path's effective origin (from targets()) concurrently; a pool path is ok
    when any of its origins answers."""
    jobs = [(i, t) for i, (_, ts) in enumerate(paths) if not isinstance(ts, str) for t in ts]
    results: dict[int, list[dict]] = {}
    pool = ThreadPoolExecutor(max_workers=min(MAX_WORKERS, max(len(jobs), 1)))
    try:
        futures = [(i, pool.submit(probe, t)) for i, t in jobs]
        deadline = time.monotonic() + 3 * CONNECT_TIMEOUT  # resolving + connect + handshake
        for i, f in futures:
            try:
                r = f.result(timeout=max(deadline - time.monotonic(), 0.1))
            except FutureTimeout:
                r = {"ok": False, "ms": None, "error": f"پاسخی در {CONNECT_TIMEOUT:g} ثانیه دریافت نشد"}
            results.setdefault(i, []).append(r)
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    out = []
    for i, (path_id, ts) in enumerate(paths):
        if isinstance(ts, str):
            out.append({"id": path_id, "ok": False, "ms": None, "error": ts})
            continue
        rs = results.get(i, [])
        good = [r for r in rs if r["ok"]]
        if good:
            out.append({"id": path_id, "ok": True, "ms": min(r["ms"] for r in good), "error": None})
        else:
            errors = list(dict.fromkeys(r["error"] for r in rs))
            out.append({"id": path_id, "ok": False, "ms": None, "error": "؛ ".join(errors)[:500] or None})
    return out
