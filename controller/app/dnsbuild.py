"""Turns a site's records + the live edge list into PowerDNS rrsets."""

from collections import defaultdict

from .config import settings
from .models import Edge, Site
from .validation import fqdn


def dot(name: str) -> str:
    return name if name.endswith(".") else name + "."


def _txt(value: str) -> str:
    chunks = [value[i : i + 255] for i in range(0, len(value), 255)] or [""]
    return " ".join(f'"{c}"' for c in chunks)


def _lua_list(ips: list[str]) -> str:
    return "{" + ",".join(f"'{ip}'" for ip in ips) + "}"


def lua_expression(home: list[str], global_: list[str]) -> str:
    """Build the LUA snippet that answers with healthy edges.

    ifurlup() probes EDGE_HEALTH_URL on every candidate IP and returns the first
    set that has at least one healthy address, so the second set is a fallback.
    """
    url = settings.health_url
    opts = f"{{selector='{settings.lua_selector}', backupSelector='all'}}"
    if settings.geoip_enabled and home and global_:
        cc = settings.geo_home_country
        return (
            f";if country('{cc}') then "
            f"return ifurlup('{url}', {{{_lua_list(home)},{_lua_list(global_)}}}, {opts}) "
            f"else return ifurlup('{url}', {{{_lua_list(global_)},{_lua_list(home)}}}, {opts}) end"
        )
    all_ips = home + global_
    return f"ifurlup('{url}', {{{_lua_list(all_ips)}}}, {opts})"


def edge_pools(edges: list[Edge], family: int) -> tuple[list[str], list[str]]:
    home, global_ = [], []
    for e in edges:
        ip = e.ipv4 if family == 4 else e.ipv6
        if not ip:
            continue
        (home if e.region == "home" else global_).append(ip)
    return sorted(home), sorted(global_)


def build_rrsets(site: Site, edges: list[Edge]) -> list[dict]:
    """Return the full desired set of rrsets for the zone (SOA excluded)."""
    domain = site.domain
    grouped: dict[tuple[str, str], dict] = {}

    def add(name: str, rtype: str, ttl: int, content: str):
        key = (dot(name), rtype)
        rr = grouped.setdefault(key, {"name": dot(name), "type": rtype, "ttl": ttl, "records": []})
        rr["ttl"] = min(rr["ttl"], ttl)
        if not any(r["content"] == content for r in rr["records"]):
            rr["records"].append({"content": content, "disabled": False})

    for ns in settings.nameservers:
        add(domain, "NS", 3600, dot(ns))

    v4_home, v4_global = edge_pools(edges, 4)
    v6_home, v6_global = edge_pools(edges, 6)
    have_v4 = bool(v4_home or v4_global)
    have_v6 = bool(v6_home or v6_global)

    # non-proxied A/AAAA sets where the customer asked for health checks
    checked: dict[tuple[str, str], list] = defaultdict(list)
    for r in site.records:
        if not (r.proxied and have_v4) and r.type in ("A", "AAAA"):
            checked[(fqdn(r.name, domain), r.type)].append(r)
    checked = {k: v for k, v in checked.items() if any(getattr(r, "health_check", False) for r in v)}

    proxied_names: dict[str, list] = defaultdict(list)
    for r in site.records:
        name = fqdn(r.name, domain)
        if r.proxied and have_v4:
            proxied_names[name].append(r)
            continue
        ttl = r.ttl or settings.default_ttl
        if (name, r.type) in checked:
            continue
        if r.type in ("CNAME", "NS", "ALIAS"):
            add(name, r.type, ttl, dot(r.content))
        elif r.type == "MX":
            add(name, "MX", ttl, f"{r.priority} {dot(r.content)}")
        elif r.type == "SRV":
            w, p, target = r.content.split()
            add(name, "SRV", ttl, f"{r.priority} {w} {p} {dot(target)}")
        elif r.type == "TXT":
            add(name, "TXT", ttl, _txt(r.content))
        else:
            add(name, r.type, ttl, r.content)

    for (name, rtype), recs in checked.items():
        port = next((r.health_port for r in recs if r.health_port), None) or 80
        ips = sorted({r.content for r in recs})
        ttl = min(r.ttl or settings.default_ttl for r in recs)
        add(name, "LUA", min(ttl, settings.proxied_ttl),
            f"{rtype} \"ifportup({int(port)}, {_lua_list(ips)}, {{selector='all', backupSelector='all'}})\"")

    for name in proxied_names:
        # The customer sees their record; resolvers see our edges.
        add(name, "LUA", settings.proxied_ttl, "A \"" + lua_expression(v4_home, v4_global) + "\"")
        if have_v6:
            add(name, "LUA", settings.proxied_ttl, "AAAA \"" + lua_expression(v6_home, v6_global) + "\"")

    return list(grouped.values())


def soa_content(domain: str) -> str:
    primary = dot(settings.nameservers[0]) if settings.nameservers else dot("ns1." + domain)
    return f"{primary} {dot(settings.soa_email)} 1 10800 3600 604800 300"
