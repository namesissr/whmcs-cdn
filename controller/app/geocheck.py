"""GeoDNS self-test: asks every nameserver which pool a home and a foreign visitor get.

Each zone with proxied records carries a `_pcdn-geo` TXT record (dnsbuild.DIAG_LABEL)
that reports the nameserver's own decision: the visitor's country as the nameserver's
country database sees it and the pool it serves. Querying it on every nameserver with
an EDNS Client Subnet from the home country and one from abroad catches a nameserver
without the geoip backend or database (everyone looks "foreign" there) and a nameserver
whose answers differ from the others.
"""

import ipaddress
import json
import logging
import socket
from urllib.parse import urlparse

import dns.edns
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype
from sqlalchemy import select

from .config import settings
from .dnsbuild import DIAG_LABEL
from .models import Record, Site, State, utcnow

log = logging.getLogger("pcdn.geocheck")

STATE_KEY = "geo:last_check"


def dns_targets() -> list[tuple[str, str, int]]:
    """(label, ip, port) of every nameserver: PDNS_DNS_ADDRS, else the PDNS_API_URL hosts."""
    raw = settings.pdns_dns_addrs or [urlparse(u.strip()).hostname or "" for u in settings.pdns_api_url.split(",")]
    out = []
    for i, item in enumerate(raw):
        host, port = item, 53
        if item.count(":") == 1:  # host:port (IPv6 addresses have more colons)
            host, p = item.split(":")
            port = int(p)
        host = host.strip("[]")
        if not host:
            continue
        try:
            ip = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)[0][4][0]
        except OSError:
            ip = host
        out.append((f"ns{i + 1} ({host})", ip, port))
    return out


def as_subnet(value: str) -> str:
    """A visitor IP as a resolver would send it (/24 for IPv4, /48 for IPv6)."""
    net = ipaddress.ip_network(value.strip() if "/" in value else
                               f"{value.strip()}/{24 if ':' not in value else 48}", strict=False)
    return str(net)


def parse_diag(txt: str) -> dict:
    return dict(part.split("=", 1) for part in txt.split() if "=" in part)


def ask(ip: str, port: int, name: str, subnet: str | None, timeout: float = 3.0) -> dict:
    """The nameserver's decision for a visitor in `subnet` (None: as the controller itself)."""
    opts = [dns.edns.ECSOption.from_text(subnet)] if subnet else []
    q = dns.message.make_query(name, "TXT", use_edns=0, options=opts)
    try:
        r = dns.query.udp(q, ip, port=port, timeout=timeout)
    except dns.message.Truncated:
        r = dns.query.tcp(q, ip, port=port, timeout=timeout)
    for rrset in r.answer:
        if rrset.rdtype == dns.rdatatype.TXT:
            for rd in rrset:
                return parse_diag(b"".join(rd.strings).decode("utf-8", "replace"))
    raise LookupError(f"no TXT answer (rcode {dns.rcode.to_text(r.rcode())})")


def probe_domain(db) -> str | None:
    """A zone that has the diagnostic record: any site with a proxied record."""
    return db.scalar(select(Site.domain).join(Record, Record.site_id == Site.id)
                     .where(Record.proxied.is_(True)).order_by(Site.id).limit(1))


def check(db, domain: str | None = None, extra_subnets: list[str] | None = None) -> dict:
    """Run the self-test on every nameserver. Returns a JSON-able report."""
    domain = domain or probe_domain(db)
    report: dict = {"at": utcnow().isoformat(), "geoip_enabled": settings.geoip_enabled, "domain": domain,
                    "servers": [], "problems": []}
    if not domain:
        report["skipped"] = "no site with proxied records yet"
        return report
    home_cc = [c.lower() for c in settings.geo_home_countries]
    name = f"{DIAG_LABEL}.{domain}"
    subnets = [("home", settings.geo_check_home_subnet), ("foreign", settings.geo_check_foreign_subnet)]
    subnets += [(s, s) for s in map(as_subnet, extra_subnets or [])]
    decisions: dict[str, set] = {}
    for label, ip, port in dns_targets():
        srv: dict = {"server": label, "ok": True, "answers": {}}
        for kind, subnet in subnets:
            try:
                d = ask(ip, port, name, subnet)
            except Exception as e:  # noqa: BLE001
                srv["ok"] = False
                srv["answers"][kind] = {"error": f"{type(e).__name__}: {e}"[:200]}
                report["problems"].append(f"{label}: no answer for {subnet} ({type(e).__name__})")
                continue
            srv["answers"][kind] = d
            decisions.setdefault(kind, set()).add(d.get("pool", "?"))
            country = d.get("country", "--")
            if not settings.geoip_enabled or kind not in ("home", "foreign"):
                continue
            if country in ("--", ""):
                srv["ok"] = False
                report["problems"].append(
                    f"{label}: country of {subnet} is unknown - the geoip backend or dns/geo/country.mmdb "
                    "is missing on this nameserver, so its visitors are not routed by country")
            elif kind == "home" and country not in home_cc:
                srv["ok"] = False
                report["problems"].append(
                    f"{label}: {subnet} is placed in '{country}' instead of {'/'.join(home_cc)} "
                    "(outdated country database: run deploy/geoip-update.sh on it)")
            elif kind == "foreign" and country in home_cc:
                srv["ok"] = False
                report["problems"].append(f"{label}: foreign subnet {subnet} is placed in '{country}'")
        report["servers"].append(srv)
    for kind, pools in decisions.items():
        if len(pools) > 1:
            report["problems"].append(
                f"nameservers disagree for the {kind} visitor ({', '.join(sorted(pools))}): "
                "visitors switch between pools depending on which nameserver their resolver asks")
    if not report["servers"]:
        report["problems"].append("no nameserver address (PDNS_API_URL / PDNS_DNS_ADDRS)")
    return report


def geo_off_warning(db) -> str | None:
    """Home and global edges both exist but GeoDNS is off: every visitor gets random edges."""
    if settings.geoip_enabled:
        return None
    from .services import online_edges

    regions = {e.region for e in online_edges(db)}
    if {"home", "global"} <= regions:
        return ("GEOIP_ENABLED is off while there are online edges in Iran (home) and abroad (global): "
                "every visitor gets a random edge from both groups")
    return None


def last_report(db) -> dict | None:
    row = db.get(State, STATE_KEY)
    if not row or not row.value:
        return None
    try:
        return json.loads(row.value)
    except ValueError:
        return None


def save_report(db, report: dict):
    row = db.get(State, STATE_KEY)
    value = json.dumps(report, ensure_ascii=False)
    if row is None:
        db.add(State(key=STATE_KEY, value=value))
    else:
        row.value = value
    db.commit()
