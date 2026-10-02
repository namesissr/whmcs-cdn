"""Customer origin hosts must be public (security review follow-up: origin host names).

Customers name the servers the EDGES connect to: proxied A/AAAA/CNAME records (`origin`), pool
members (section `pools`), tunnel path origins (`tunnel`) and TCP/UDP proxy origins (`l4`). Storage
origins are platform-generated and not covered here. Without a check a customer could point the
edges at 127.0.0.1, the edge's own loopback services, 169.254.169.254 (cloud metadata) or the
operator's private network — directly, or through a host name that resolves there
(`localhost`, `127.0.0.1.nip.io`, `metadata.google.internal` …).

THE RULE (the edges enforce the same at connect time, see docs/SECURITY.md):

* an IP literal must be globally routable unicast — ``netguard.is_public_ip``: not private
  (10/8, 172.16/12, 192.168/16, fc00::/7), loopback, link-local (169.254/16, fe80::/10), CGNAT
  (100.64/10), unspecified, multicast, reserved / documentation / benchmarking ranges, site-local,
  nor an IPv6 form embedding a non-public IPv4 (::ffff:0:0/96, 6to4 2002::/16, Teredo, NAT64
  64:ff9b::/96 and 64:ff9b:1::/48);
* a host name must be fully qualified (2+ labels), its last label alphabetic (or an IDN ``xn--``
  label: no numeric / hex "TLDs" such as ``0x7f.1`` that resolvers turn into addresses), and not
  under a special-use / internal name (``localhost``, ``local``, ``internal``, ``arpa`` …, see
  SPECIAL_SUFFIXES);
* on save the host name is resolved (A + AAAA, ``netguard.resolver``) and refused when ANY address
  is not public. A name that does not resolve (yet) is accepted — the edges refuse to connect to
  it anyway while it resolves to nothing public;
* the scheduler leader re-resolves every origin host name every ORIGIN_RECHECK_MINUTES; a name now
  resolving to a non-public address is put on a block list (State ``origin_guard:blocked``): the
  hosts / pool members / tunnel paths / L4 apps using it are left out of the edge config and an
  alert opens. It is lifted automatically once the name resolves to public addresses only.
"""

import ipaddress
import json
import logging
import re
import socket
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from concurrent.futures import as_completed

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import netguard
from .config import settings
from .models import Site, State, utcnow

log = logging.getLogger("pcdn.origin_guard")

SPECIAL_SUFFIXES = ("localhost", "localdomain", "local", "internal", "intranet", "lan", "home", "corp",
                    "private", "arpa", "test", "invalid", "onion", "alt", "example")
TLD_RE = re.compile(r"^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$")
STATE_KEY = "origin_guard:blocked"
ALERT_KEY = "origin_guard"
MAX_WORKERS = 16
MAX_HOSTS = 5000  # per re-check run

_pool = ThreadPoolExecutor(max_workers=MAX_WORKERS, thread_name_prefix="origin-guard")


def name_problem(host: str) -> str | None:
    """Problem with the NAME itself (no DNS lookup), Persian; None when acceptable.
    Monkeypatched by tests whose origins are local test servers."""
    labels = host.lower().rstrip(".").split(".")
    if len(labels) < 2:
        return f"نام میزبان مبدأ باید کامل باشد (مثل origin.example.com): {host}"
    if not TLD_RE.match(labels[-1]):
        return f"نام میزبان مبدأ نامعتبر است: {host}"
    h = ".".join(labels)
    for suf in SPECIAL_SUFFIXES:
        if h == suf or h.endswith("." + suf):
            return f"نام میزبان {host} داخلی/ویژه است؛ مبدأ باید نام یا آدرس عمومی اینترنت باشد"
    return None


def resolve(host: str) -> list[str] | None:
    """Every address of host (netguard.resolver, bounded by ORIGIN_RESOLVE_TIMEOUT); None when it
    does not resolve or the lookup timed out."""
    fut = _pool.submit(netguard.resolver, host, 443)
    try:
        ips = fut.result(timeout=settings.origin_resolve_timeout)
    except FutureTimeout:
        return None
    except (OSError, UnicodeError, socket.gaierror, ValueError):
        return None
    return list(ips) or None


def host_problem(host: str) -> str | None:
    """The full save-time check of one origin host name; None when acceptable."""
    p = name_problem(host)
    if p:
        return p
    ips = resolve(host)
    if not ips:
        return None
    bad = [ip for ip in ips if not netguard.is_public_ip(ip)]
    if bad:
        return (f"نام میزبان {host} به آدرس غیرعمومی ({bad[0]}) اشاره می‌کند؛ مبدأ باید فقط به آدرس‌های "
                "عمومی اینترنت resolve شود")
    return None


def check_hosts(hosts: list[str]) -> dict[str, str]:
    """{host: problem} for the host names that fail host_problem (resolved in parallel)."""
    uniq = list(dict.fromkeys(h.lower().rstrip(".") for h in hosts if h))
    if not uniq:
        return {}
    if len(uniq) == 1:
        p = host_problem(uniq[0])
        return {uniq[0]: p} if p else {}
    out = {}
    with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(uniq))) as ex:
        futs = {ex.submit(host_problem, h): h for h in uniq}
        for f in as_completed(futs):
            p = f.result()
            if p:
                out[futs[f]] = p
    return out


# ------------------------------------------------------------------ periodic re-check (leader)

def site_origin_hosts(site: Site) -> set[str]:
    """Every origin host name / IP literal a site currently hands to the edges (proxied records +
    pools / tunnel / l4)."""
    from . import sections
    from .services import resolve_origin

    out: set[str] = set()
    for r in site.records:
        if r.proxied and r.type in ("A", "AAAA", "CNAME") and not r.storage_bucket:
            target = resolve_origin(site, r)
            if target:
                out.add(target.strip("[]").lower())
    cfg = sections.all_config(site)
    for name in sections.ORIGIN_SECTIONS:
        out.update(h.lower() for h, _ in sections.origin_hosts(name, cfg[name], include_ips=True))
    return out


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def blocked(db: Session) -> dict[str, dict]:
    """{host: {"ips": [...], "at": iso}} of origin host names currently blocked."""
    row = db.get(State, STATE_KEY)
    if row is None or not row.value:
        return {}
    try:
        v = json.loads(row.value)
    except ValueError:
        return {}
    return v if isinstance(v, dict) else {}


def is_blocked(blocked_hosts: dict | set, address: str | None) -> bool:
    return bool(address) and str(address).strip("[]").lower().rstrip(".") in blocked_hosts


def recheck(db: Session) -> dict[str, dict]:
    """Re-resolve every origin host name; update the block list and the alert. Returns it."""
    hosts: dict[str, set[str]] = {}
    for site in db.scalars(select(Site)):
        try:
            names = site_origin_hosts(site)
        except Exception:  # noqa: BLE001 - one broken site must not stop the run
            log.exception("could not list origin hosts of %s", site.domain)
            continue
        for h in names:
            hosts.setdefault(h, set()).add(site.domain)
    names = sorted(hosts)[:MAX_HOSTS]
    now = utcnow().isoformat()
    old = blocked(db)
    new: dict[str, dict] = {}

    def one(h: str):
        if _is_ip(h):  # stored before the strict check (CGNAT, NAT64 …): no DNS involved
            return h, [] if netguard.is_public_ip(h) else [h]
        if name_problem(h):
            return h, ["(name)"]
        ips = resolve(h)
        return h, [ip for ip in (ips or []) if not netguard.is_public_ip(ip)]

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        for h, bad in ex.map(one, names):
            if bad:
                new[h] = {"ips": bad[:4], "at": old.get(h, {}).get("at") or now,
                          "sites": sorted(hosts[h])[:10]}
    if new != old:
        row = db.get(State, STATE_KEY)
        if row is None:
            db.add(State(key=STATE_KEY, value=json.dumps(new)))
        else:
            row.value = json.dumps(new)
        db.commit()
        for h in set(new) - set(old):
            log.warning("origin host %s of %s resolves to non-public %s: left out of the edge config",
                        h, ", ".join(new[h]["sites"]), new[h]["ips"])
    from . import alerts

    if new:
        lines = [f"• {h} → {', '.join(v['ips'])} ({', '.join(v['sites'])})" for h, v in sorted(new.items())[:20]]
        alerts.raise_alert(ALERT_KEY, "مبدأ مشتری به آدرس داخلی اشاره می‌کند",
                           "این نام‌های میزبان مبدأ به آدرس غیرعمومی resolve می‌شوند و تا رفع، از پیکربندی "
                           "لبه‌ها حذف شده‌اند:\n" + "\n".join(lines), "warning")
    else:
        alerts.resolve_alert(ALERT_KEY, "همهٔ نام‌های میزبان مبدأ دوباره فقط به آدرس عمومی اشاره می‌کنند.")
    return new
