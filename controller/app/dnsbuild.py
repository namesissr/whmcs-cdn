"""Turns a site's records + the live edge list into PowerDNS rrsets."""

import ipaddress
import json
from collections import defaultdict
from datetime import timedelta

from .config import settings
from .models import Edge, Site, utcnow
from .validation import fqdn


def dot(name: str) -> str:
    return name if name.endswith(".") else name + "."


def _txt(value: str) -> str:
    chunks = [value[i : i + 255] for i in range(0, len(value), 255)] or [""]
    return " ".join(f'"{c}"' for c in chunks)


def _lua_list(ips: list[str]) -> str:
    return "{" + ",".join(f"'{ip}'" for ip in ips) + "}"


# bump when the generated records change so the scheduler rewrites every zone once
BUILD_VERSION = "2"
SELECTORS = ("random", "all", "hashed", "first", "pickclosest")
# TXT record answering "which pool would this resolver/visitor get, and why" (see README)
DIAG_LABEL = "_pcdn-geo"


def _selector() -> str:
    sel = (settings.lua_selector or "random").strip().lower()
    return sel if sel in SELECTORS else "random"


def _cidrs(values: list[str]) -> list[str]:
    out = []
    for v in values:
        try:
            out.append(str(ipaddress.ip_network(v.strip(), strict=False)))
        except ValueError:
            continue
    return out


def _countries() -> list[str]:
    return [c.lower() for c in settings.geo_home_countries if len(c) == 2 and c.isalpha()] or ["ir"]


def home_test() -> str:
    """LUA statements that set `c` (country code) and `home` (true: serve the home pool).

    countryCode() looks up the visitor's subnet when the resolver sends one (EDNS Client
    Subnet), else the resolver's own address. Resolvers known to never send it (Cloudflare)
    and addresses missing from the database follow GEO_NO_ECS_POOL / GEO_UNKNOWN_POOL.
    """
    cond = " or ".join(f"c=='{c}'" for c in _countries())
    lua = f"local c=countryCode() local home=({cond})"
    if settings.geo_unknown_pool in ("home", "global"):
        val = "true" if settings.geo_unknown_pool == "home" else "false"
        lua += f" if c=='--' or c=='' then home={val} end"
    resolvers = _cidrs(settings.geo_no_ecs_resolvers)
    if settings.geo_no_ecs_pool in ("home", "global") and resolvers:
        val = "true" if settings.geo_no_ecs_pool == "home" else "false"
        only = [c.lower() for c in settings.geo_no_ecs_countries if len(c) == 2 and c.isalpha()]
        where = (" and (" + " or ".join(f"c=='{c}'" for c in only) + ")") if only else ""
        lua += f" if ecswho==nil{where} and netmask({_lua_list(resolvers)}) then home={val} end"
    return lua


def _pick(ips: list[str]) -> str:
    """LUA expression choosing among the edges of one pool."""
    if not ips:
        return "{}"  # e.g. AAAA when the pool has no IPv6 edge: the visitor uses IPv4
    lst = _lua_list(ips)
    sel = _selector()
    if settings.edge_probe:
        # PowerDNS probes the pool's edges itself; if none looks healthy from this
        # nameserver it still answers with the whole pool (never with the other pool)
        return f"ifurlup('{settings.health_url}', {{{lst}}}, {{selector='{sel}', backupSelector='all'}})"
    return {"all": lst, "hashed": f"pickhashed({lst})", "first": f"'{ips[0]}'",
            "pickclosest": f"pickclosest({lst})"}.get(sel, f"pickrandom({lst})")


def geo_split(home_alive: bool, global_alive: bool) -> bool:
    return settings.geoip_enabled and home_alive and global_alive


def _log(rtype: str, pool: str) -> str:
    """GEO_LOG: one PowerDNS log line per decision (docker compose logs pdns | grep pcdn-geo)."""
    if not settings.geo_log:
        return ""
    return (f" pdnslog('pcdn-geo '..qname:toString()..' {rtype} resolver='..who:toString()"
            f"..' ecs='..(ecswho and ecswho:toString() or '-')..' country='..countryCode()..' pool='..{pool},"
            f" pdns.loglevels.Warning)")


def lua_expression(home: list[str], global_: list[str],
                   home_alive: bool | None = None, global_alive: bool | None = None, rtype: str = "A") -> str:
    """Build the LUA snippet that answers with the visitor's pool of online edges.

    home/global_: the online edges of one address family. *_alive: whether the pool has
    any online edge at all (from IPv4, so an AAAA query of an IPv4-only home pool gets no
    answer instead of the foreign IPv6 edges). Which pool is alive comes from the
    controller, so every nameserver gives the same answer.
    """
    home_alive = bool(home) if home_alive is None else home_alive
    global_alive = bool(global_) if global_alive is None else global_alive
    if geo_split(home_alive, global_alive):
        log = _log(rtype, "(home and 'home' or 'global')")
        return f";{home_test()}{log} if home then return {_pick(home)} else return {_pick(global_)} end"
    if settings.geo_log:
        pool = "'all'" if not settings.geoip_enabled else ("'home-only'" if home_alive else "'global-only'")
        return f";{_log(rtype, pool).strip()} return {_pick(home + global_)}"
    return f";return {_pick(home + global_)}"


def diag_expression(home_alive: bool, global_alive: bool) -> str:
    """TXT answer describing the GeoDNS decision for the asking resolver/visitor."""
    if settings.geoip_enabled:
        head = home_test()
        pool = "(home and 'home' or 'global')"
        if not (home_alive and global_alive):
            pool = "'home-only'" if home_alive else "'global-only'"  # the other pool is offline
    else:
        head = "local c=countryCode()"
        pool = "'all'"  # GEOIP_ENABLED=false: every online edge
    return (f";{head} return 'ip='..bestwho:toString()..' ecs='..(ecswho and 'yes' or 'no')"
            f"..' resolver='..who:toString()..' country='..c..' pool='..{pool}")


def address_advertised(enabled: bool, probe_ok: bool | None, probe_fail: int | None) -> bool:
    """Whether one address (primary or additional, SPEC §12.1) may appear in DNS.

    Advertised while the address is enabled AND it is healthy (probe_ok True) or never probed
    yet (probe_ok None) OR it has not yet failed PROBE_FAIL_CHECKS probes in a row. It is only
    withdrawn once its probe_fail reaches PROBE_FAIL_CHECKS (the same threshold as the §8.1
    alert), so a single transient probe failure never yanks it; `enabled=false` (operator
    maintenance) withdraws it immediately.
    """
    if not enabled:
        return False
    return probe_ok is True or probe_ok is None or (probe_fail or 0) < settings.probe_fail_checks


def _edge_family_addresses(e, family: int) -> list[tuple[str, bool, bool]]:
    """(ip, enabled, advertised) for every address of the edge in `family`: the primary
    (edges.ipv4/ipv6, whose health is the edge-level probe) + every additional EdgeAddress."""
    out: list[tuple[str, bool, bool]] = []
    ip = e.ipv4 if family == 4 else e.ipv6
    if ip:
        out.append((ip, True, address_advertised(True, getattr(e, "probe_ok", None),
                                                  getattr(e, "probe_fail", 0))))
    for a in (getattr(e, "addresses", None) or []):
        if getattr(a, "family", None) == family and getattr(a, "ip", None):
            out.append((a.ip, bool(a.enabled),
                        address_advertised(bool(a.enabled), a.probe_ok, a.probe_fail)))
    return out


def edge_pools(edges: list[Edge], family: int) -> tuple[list[str], list[str]]:
    """The home and global pools of `family` addresses: for each edge, ALL of its advertised
    addresses (primary + additional, SPEC §12.3), not just the single primary.

    Fail-open (§12.3): if health withdrawal would leave a pool EMPTY, the withdrawal is ignored
    for that pool and its known (enabled) addresses are advertised anyway — a pool is NEVER
    emptied by health state. Operator-disabled addresses are never resurrected by fail-open.
    """
    known: dict[str, list[str]] = {"home": [], "global": []}   # enabled, ignoring health
    adv: dict[str, list[str]] = {"home": [], "global": []}      # enabled and advertised
    for e in edges:
        region = "home" if e.region == "home" else "global"
        for ip, enabled, advertised in _edge_family_addresses(e, family):
            if not enabled:
                continue
            known[region].append(ip)
            if advertised:
                adv[region].append(ip)
    # fail-open: never emit an empty pool because of health withdrawal
    home = adv["home"] or known["home"]
    global_ = adv["global"] or known["global"]
    return sorted(set(home)), sorted(set(global_))


def site_edge_group(site) -> str:
    """The plan's edge_group (SPEC §7.4); "general" for sites without the feature."""
    try:
        group = json.loads(getattr(site, "features", None) or "{}").get("edge_group")
    except (ValueError, AttributeError):
        group = None
    return group if group in ("general", "tunnel") else "general"


def edge_group(e) -> str:
    return getattr(e, "group", None) or "general"


def is_shed(e, now=None) -> bool:
    """Shed by load (services.update_shed) and the metrics behind that are still fresh."""
    at = getattr(e, "metrics_at", None)
    return bool(getattr(e, "shed", False)) and at is not None and (
        (now or utcnow()) - at <= timedelta(seconds=settings.edge_offline_seconds))


def dns_edges(site, edges: list) -> list:
    """The online edges that answer for this site.

    Only the site's edge group; every online edge when that group has none (fail open).
    A saturated (shed) edge is left out while another edge of the same region (pool)
    stays in, so a pool never goes empty because of load.
    """
    group = site_edge_group(site)
    chosen = [e for e in edges if edge_group(e) == group] or list(edges)
    now = utcnow()
    keep_region = {e.region for e in chosen if not is_shed(e, now)}
    return [e for e in chosen if not is_shed(e, now) or e.region not in keep_region]


def build_rrsets(site: Site, edges: list[Edge]) -> list[dict]:
    """Return the full desired set of rrsets for the zone (SOA excluded).

    edges: every online edge; the site's group and load shedding are applied here.
    """
    domain = site.domain
    edges = dns_edges(site, edges)
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

    home_alive, global_alive = bool(v4_home), bool(v4_global)
    for name in proxied_names:
        # The customer sees their record; resolvers see our edges.
        add(name, "LUA", settings.proxied_ttl,
            "A \"" + lua_expression(v4_home, v4_global, home_alive, global_alive) + "\"")
        if have_v6:
            add(name, "LUA", settings.proxied_ttl,
                "AAAA \"" + lua_expression(v6_home, v6_global, home_alive, global_alive, "AAAA") + "\"")
    if proxied_names:
        add(f"{DIAG_LABEL}.{domain}", "LUA", 5, "TXT \"" + diag_expression(home_alive, global_alive) + "\"")

    return list(grouped.values())


def soa_content(domain: str) -> str:
    primary = dot(settings.nameservers[0]) if settings.nameservers else dot("ns1." + domain)
    return f"{primary} {dot(settings.soa_email)} 1 10800 3600 604800 300"
