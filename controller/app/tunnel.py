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
from .validation import fqdn, num

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
            by_protocol[proto] = by_protocol.get(proto, 0) + num(v)
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
        if p.get("origins"):  # SPEC §22.4: every member (ok when any answers, like a pool)
            out.append((p["id"], [{k: o[k] for k in ("address", "port", "tls", "verify")}
                                  | {"sni": o["sni"] or site.domain} for o in p["origins"]]))
        elif p["origin"]:
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


# ------------------------------------------------------------------ client profile (SPEC §22.5 / §22.9 / §22.11)

# The edge's tunnel timers — ONE documented contract with the edge render (edge/pcdn_agent/render/
# site.py keeps the same values and has a matching golden test): keepalive_timeout of tunnel hosts,
# keepalive_time, http2_max_concurrent_streams, the listeners' so_keepalive and the upstream connect
# timeout (TUNNEL_CONNECT_TIMEOUT on the edge).
EDGE_TUNNEL_TIMERS = {
    "client_idle_s": 600,
    "max_connection_age_s": 21600,
    "h2_max_streams": 512,
    "tcp_keepalive": {"idle_s": 120, "interval_s": 30, "count": 4},
    "connect_timeout_s": 10,
}
SEND_TIMEOUT_MAX = 300  # edge: send_timeout = min(idle, 300)
GRPC_HEALTH_CHECK_TIMEOUT_S = 20
XMUX = {"max_concurrency": "16-32", "c_max_reuse_times": 0, "h_max_request_times": "600-900",
        "h_max_reusable_secs": "1800-3000"}


def keepalive_s(path_idle: int) -> int:
    """Recommended client keepalive / ping interval: max(10, min(60, floor(min(idle, client_idle) / 3)))."""
    return max(10, min(60, min(int(path_idle), EDGE_TUNNEL_TIMERS["client_idle_s"]) // 3))


def recommended(protocol: str, k: int) -> dict:
    """Stability settings only (keepalive, mux, protocol transport options) — never fragment / noise /
    padding / SNI or address options."""
    return {
        "keepalive_s": k,
        "mux": "off" if protocol in ("grpc", "xhttp", "h2") else "low",
        "xmux": {**XMUX, "h_keepalive_period_s": k} if protocol == "xhttp" else None,
        "grpc": ({"idle_timeout_s": k, "health_check_timeout_s": GRPC_HEALTH_CHECK_TIMEOUT_S,
                  "permit_without_stream": False} if protocol == "grpc" else None),
        "ws_heartbeat_s": k if protocol == "ws" else None,
    }


def http3_status(db: Session, site: Site) -> dict:
    """{site, nodes, nodes_h3, available} (SPEC §22.9): HTTP/3 is offered to a client only when the
    site serves it and EVERY online node serving the site speaks it. Counts only, never a node."""
    from . import dnsbuild
    from .services import edge_capabilities, online_edges

    ssl_ok = bool(site.ssl_cert and site.ssl_key_stored and site.ssl_status in ("active", "pending")
                  and (site.ssl_expires_at is None or site.ssl_expires_at > utcnow()))
    site_h3 = bool(sections.get_section(site, "ssl").get("http3")) and ssl_ok
    serving = dnsbuild.dns_edges(site, online_edges(db))
    h3 = sum(1 for e in serving
             if (edge_capabilities(e) or {}).get("http3") and (e.http3_enabled is None or e.http3_enabled))
    return {"site": site_h3, "nodes": len(serving), "nodes_h3": h3,
            "available": bool(site_h3 and serving and h3 == len(serving))}


def tunnel_cities(db: Session, site: Site) -> list[dict]:
    """SPEC §23.13: the cities a client can pin a tunnel hostname to — [{slug, label{fa,en}}].

    One entry per city DNS actually publishes a hostname for, so a city whose nodes are all withdrawn
    is left out and never reaches a client's list. Carries only the operator-set city label and its DNS
    slug — never a node name, address or per-city node count.
    """
    from . import dnsbuild, edge_labels
    from .config import settings
    from .services import online_edges

    if not settings.dns_city_labels:
        return []
    serving = dnsbuild.dns_edges(site, online_edges(db))
    published = dnsbuild.city_pools(serving, 4)
    out: dict[str, dict] = {}
    for e in serving:
        slug = edge_labels.city_slug(e)
        if slug in published and slug not in out:
            fa, en = edge_labels.city_of(e)
            out[slug] = {"slug": slug, "label": edge_labels.label_for(fa, en, None)}
    return [out[k] for k in sorted(out)]


def _origin_count(cfg: dict, p: dict, max_origins: int) -> int:
    if p.get("origins"):
        return min(len(p["origins"]), max(1, max_origins))
    if p.get("pool"):
        pool = next((x for x in cfg["pools"]["pools"] if x["name"] == p["pool"]), None)
        return len(pool["origins"]) if pool else 0
    return 1


def profile(db: Session, site: Site) -> dict | None:
    """GET …/tunnel/profile (SPEC §22.11): edge timers, HTTP/3 availability and per path the
    effective timeouts with the recommended client values. None when the plan has no tunnel."""
    feats = sections.features_of(site)
    if not feats.get("tunnel"):
        return None
    cfg = sections.all_config(site)
    tn = cfg["tunnel"]
    h3 = http3_status(db, site)
    max_origins = int(feats.get("max_tunnel_origins") or 1)
    paths = []
    for p in tn["paths"][: feats["max_tunnel_paths"]]:
        idle = int(p.get("idle_timeout") or tn["idle_timeout"])
        k = keepalive_s(idle)
        paths.append({
            "id": p["id"], "path": p["path"], "protocol": p["protocol"],
            "idle_timeout_s": idle, "read_timeout_s": idle, "send_timeout_s": min(idle, SEND_TIMEOUT_MAX),
            "origins": _origin_count(cfg, p, max_origins),
            "balance": p.get("balance") if p.get("origins") and max_origins > 1 else None,
            "http3": bool(h3["available"] and p["protocol"] == "xhttp"),
            "recommended": recommended(p["protocol"], k),
        })
    return {"edge": {**EDGE_TUNNEL_TIMERS, "tcp_keepalive": dict(EDGE_TUNNEL_TIMERS["tcp_keepalive"])},
            "http3": h3, "paths": paths, "cities": tunnel_cities(db, site)}
