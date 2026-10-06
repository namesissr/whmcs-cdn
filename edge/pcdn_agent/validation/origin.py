"""Origin address policy (security review, SPEC §14.1): which origin addresses nginx may connect to
(public only, plus ORIGIN_PRIVATE_ALLOW), origin pools and tunnel sections, and the loopback
source/ports of the edge's own services."""

import ipaddress
import re
import socket

from ..common import (
    IP_LITERAL, SAFE_ID, SAFE_NAME, SAFE_ORIGIN, SAFE_PATTERN, SAFE_TUNNEL_PATH, TUNNEL_PROTOCOLS, _hp,
    _int, _sec,
)
from ..settings import log


def _ip_literal(v) -> str | None:
    """A shield peer address as an nginx server address ("1.2.3.4" / "[2001:db8::1]"), or None."""
    s = str(v or "").strip().strip("[]")
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return None
    if ip.is_unspecified or ip.is_multicast:
        return None
    return f"[{ip.compressed}]" if ip.version == 6 else ip.compressed


# ----------------------------------------------------------------- origin address policy
# Customers choose origin addresses (proxied record targets, pool members, tunnel path origins, L4
# origins, storage endpoints). An origin on loopback, a private / link-local (169.254.169.254
# metadata) / CGNAT / multicast / reserved address would make this edge connect to its own local
# services or the provider's internal network on the customer's behalf. Two layers:
#   * render time (here): an IP-literal origin must be globally routable - the same rules as the
#     controller's netguard.is_public_ip (mirrored, not imported: the edge is standalone) - unless
#     the operator's ORIGIN_PRIVATE_ALLOW (CIDRs, agent.conf) covers it; otherwise it is skipped
#     with a warning. Numeric host names that the resolver library would read as an IPv4 address
#     ("127.1", "2130706433", "0x7f.1") count as IP literals;
#   * connect time (host names, DNS rebinding): the nftables table inet pcdn_origin_guard
#     (render_origin_guard, install.sh, default on) rejects the nginx workers' connections to
#     those ranges, with the same allow-list.
ORIGIN_CGNAT = ipaddress.ip_network("100.64.0.0/10")
ORIGIN_NAT64 = (ipaddress.ip_network("64:ff9b::/96"), ipaddress.ip_network("64:ff9b:1::/48"))


def _v4_public(ip: ipaddress.IPv4Address) -> bool:
    return bool(ip.is_global and not (ip.is_multicast or ip.is_reserved or ip.is_loopback or ip.is_link_local
                                     or ip.is_private or ip.is_unspecified or ip in ORIGIN_CGNAT))


def _embedded_v4(ip: ipaddress.IPv6Address) -> list:
    out = []
    if ip.sixtofour is not None:
        out.append(ip.sixtofour)
    if ip.teredo is not None:
        out.extend(ip.teredo)
    if any(ip in net for net in ORIGIN_NAT64):
        out.append(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
    return out


def is_public_ip(value) -> bool:
    """True only for a globally routable unicast address (mirror of controller/app/netguard.py)."""
    if "%" in str(value):  # scoped (link-local) address
        return False
    try:
        ip = ipaddress.ip_address(str(value).strip("[]"))
    except ValueError:
        return False
    if ip.version == 4:
        return _v4_public(ip)
    if ip.ipv4_mapped is not None:  # ::ffff:a.b.c.d connects to a.b.c.d
        return _v4_public(ip.ipv4_mapped)
    if not ip.is_global or ip.is_multicast or ip.is_reserved or ip.is_loopback or ip.is_link_local \
            or ip.is_private or ip.is_unspecified or ip.is_site_local:
        return False
    return all(_v4_public(v4) for v4 in _embedded_v4(ip))


def origin_private_allow(cfg: dict) -> list:
    """ORIGIN_PRIVATE_ALLOW: the operator's CIDRs where non-public origins are permitted (for
    providers whose customers' origins sit in the same private network). Invalid entries ignored."""
    nets = []
    for n in re.split(r"[\s,]+", str((cfg or {}).get("ORIGIN_PRIVATE_ALLOW") or "").strip()):
        try:
            nets.append(ipaddress.ip_network(n.split("%")[0], strict=False))
        except ValueError:
            continue
    return nets


def _literal_ip(host: str):
    """The address an origin host string denotes when it is an IP literal (also the numeric forms
    inet_aton / getaddrinfo accept: "127.1", "2130706433", "0x7f000001"), else None."""
    h = str(host or "").strip().lower()
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    try:
        return ipaddress.ip_address(h.split("%")[0])
    except ValueError:
        pass
    if re.match(r"^(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+)){0,3}$", h):
        try:
            return ipaddress.IPv4Address(socket.inet_aton(h))
        except OSError:
            return None
    return None


def origin_host_allowed(host: str, cfg: dict) -> bool:
    """False for an IP-literal origin that is not globally routable and not in ORIGIN_PRIVATE_ALLOW.
    Host names pass (they are guarded at connect time by the nftables origin guard)."""
    ip = _literal_ip(host)
    if ip is None:
        return True
    if "%" not in str(host) and is_public_ip(str(ip)):
        return True
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return any(ip.version == n.version and ip in n for n in origin_private_allow(cfg))


def origin_hp_allowed(hp: str, cfg: dict) -> bool:
    """origin_host_allowed for "host:port" / "[v6]:port"."""
    return origin_host_allowed(str(hp).rsplit(":", 1)[0], cfg)


def guard_pools(pools: dict, cfg: dict, sid) -> dict:
    """Pools with every origin the address policy refuses removed (warned); a pool left without
    origins stays (its hosts answer 502, as for a pool whose members are all down)."""
    out = {}
    for name, p in pools.items():
        keep = [o for o in p["origins"] if origin_hp_allowed(o["hp"], cfg)]
        for o in p["origins"]:
            if o not in keep:
                log.warning("site %s: pool %s origin %s skipped: not a public address (ORIGIN_PRIVATE_ALLOW)",
                            sid, name, o["hp"])
        out[name] = dict(p, origins=keep)
    return out


def guard_tunnel(tunnel: dict | None, cfg: dict, sid) -> dict | None:
    """The tunnel section without the paths whose origin the address policy refuses (warned)."""
    if not tunnel:
        return tunnel
    paths = []
    for p in tunnel["paths"]:
        if p["origin"] and not origin_hp_allowed(p["origin"]["hp"], cfg):
            log.warning("site %s: tunnel path %s skipped: origin %s is not a public address (ORIGIN_PRIVATE_ALLOW)",
                        sid, p["path"], p["origin"]["hp"])
            continue
        if p.get("pool_def"):   # SPEC §22.4: members the address policy refuses are dropped
            pd = p["pool_def"]
            keep = [o for o in pd["origins"] if origin_hp_allowed(o["hp"], cfg)]
            for o in pd["origins"]:
                if o not in keep:
                    log.warning("site %s: tunnel path %s origin %s skipped: not a public address "
                                "(ORIGIN_PRIVATE_ALLOW)", sid, p["path"], o["hp"])
            if not keep:
                continue
            p = dict(p, pool_def=dict(pd, origins=keep))
        paths.append(p)
    return dict(tunnel, paths=paths) if paths else None


def resolve_origin(host: dict, pools: dict, default_proto: str):
    """-> (proto, pool name or None, "host:port" or None), or None when unusable."""
    origin = host.get("origin")
    if isinstance(origin, str):  # v1 shape: bare address
        origin = {"address": origin, "port": None}
    if not isinstance(origin, dict) or "storage" in origin:   # storage: norm_storage_origin
        return None
    if origin.get("pool") is not None:
        name = str(origin["pool"])
        if not SAFE_ID.match(name) or name not in pools:
            return None
        return pools[name]["protocol"], name, None
    addr = str(origin.get("address") or "").lower()
    if not SAFE_ORIGIN.match(addr):
        return None
    port = origin.get("port")
    if port is None:
        port = 443 if default_proto == "https" else 80
    elif not (isinstance(port, int) or str(port).isdigit()) or not 1 <= int(port) <= 65535:
        return None
    return default_proto, None, _hp(addr, port)


def norm_pools(site: dict) -> dict:
    out = {}
    for p in (_sec(site, "pools").get("pools") or []):
        name = str(p.get("name") or "")
        if not SAFE_ID.match(name):
            continue
        proto = "https" if p.get("protocol") == "https" else "http"
        origins = []
        for o in p.get("origins") or []:
            addr = str(o.get("address") or "").lower()
            if not SAFE_ORIGIN.match(addr):
                continue
            port = _int(o.get("port"), 443 if proto == "https" else 80, 1, 65535)
            origins.append({"hp": _hp(addr, port), "weight": _int(o.get("weight"), 1, 1, 1000), "backup": bool(o.get("backup"))})
        h = p.get("health") or {}
        hpath = str(h.get("path") or "/")
        hhost = str(h.get("host") or "").lower()
        health = {"enabled": bool(h.get("enabled")), "path": hpath if SAFE_PATTERN.match(hpath) else "/",
                  "interval": _int(h.get("interval"), 10, 1, 3600), "timeout": _int(h.get("timeout"), 3, 1, 10),
                  "expect": str(h.get("expect") or "2xx,3xx")[:100],
                  "host": hhost if hhost and SAFE_NAME.match(hhost) and "*" not in hhost else None}
        if h.get("type") == "tcp":   # SPEC §22.4: checked by the agent (TCP connect), not by njs
            health["type"] = "tcp"
            health["timeout"] = _int(h.get("timeout"), 3, 1, 30)
        out[name] = {
            "method": "ip_hash" if p.get("method") == "ip_hash" else "weighted",
            "protocol": proto,
            "origins": origins,
            "health": health,
        }
    return out


TUNNEL_ORIGINS_MAX = 10   # SPEC §22.4: 2..10 origins per tunnel path (plan max_tunnel_origins)
INTERNAL_POOL_PREFIX = "tn."   # internal pools of multi-origin tunnel paths ("tn.<path id>")


def _tunnel_origin(o) -> dict | None:
    """One validated tunnel origin ({address, port, tls, sni, verify}) -> {hp, ip, tls, sni, verify}."""
    if not isinstance(o, dict):
        return None
    addr = str(o.get("address") or "").lower()
    port = o.get("port")
    sni = str(o.get("sni") or "").lower()
    if (not SAFE_ORIGIN.match(addr) or isinstance(port, bool) or not (isinstance(port, int) or str(port).isdigit())
            or not 1 <= int(port) <= 65535 or (sni and (not SAFE_NAME.match(sni) or "*" in sni))):
        return None
    return {"hp": _hp(addr, port), "ip": bool(IP_LITERAL.match(addr)), "tls": bool(o.get("tls")),
            "sni": sni or None, "verify": bool(o.get("verify"))}


def norm_tunnel_origins(p: dict) -> dict | None:
    """SPEC §22.4: the internal pool ("tn.<path id>") of a tunnel path with `origins`, or None when the
    path has no usable `origins` (the single `origin` then applies, as for an old controller).
    balance failover / round_robin -> weighted with the backup flags as sent (the controller already
    turned "failover" into first-primary + backups), sticky_ip -> ip_hash. Members that differ from the
    first one in tls / verify / sni are skipped (the controller refuses them); at least one primary."""
    items = p.get("origins")
    if not isinstance(items, list) or not items:
        return None
    members, first, seen = [], None, set()
    for o in items[:TUNNEL_ORIGINS_MAX]:
        t = _tunnel_origin(o)
        if t is None or t["hp"] in seen:
            continue
        if first is None:
            first = t
        elif (t["tls"], t["verify"], t["sni"]) != (first["tls"], first["verify"], first["sni"]):
            continue
        seen.add(t["hp"])
        members.append({"hp": t["hp"], "weight": _int(o.get("weight"), 1, 1, 100), "backup": o.get("backup") is True})
    if not members or all(m["backup"] for m in members):
        return None
    h = p.get("health") if isinstance(p.get("health"), dict) else {}
    htype = "http" if h.get("type") == "http" else "tcp"
    interval = _int(h.get("interval"), 10, 5, 300)
    timeout = min(_int(h.get("timeout"), 3, 1, 30), max(1, interval - 1))
    hpath = str(h.get("path") or "/")
    health = {"enabled": True, "type": htype, "path": hpath if SAFE_PATTERN.match(hpath) else "/",
              "interval": interval, "timeout": timeout if htype == "tcp" else min(timeout, 10),
              "expect": str(h.get("expect") or "2xx,3xx,4xx")[:100], "host": None}
    if htype == "http":   # njs health(): pools without "type" are HTTP-checked
        del health["type"]
    return {"method": "ip_hash" if p.get("balance") == "sticky_ip" else "weighted",
            "protocol": "https" if first["tls"] else "http", "origins": members, "health": health,
            # tunnel_loc: TLS name / verification of the members (one setting for all of them)
            "sni": first["sni"], "verify": first["verify"]}


def norm_tunnel(site: dict, pools: dict) -> dict | None:
    """Validated `tunnel` section (SPEC §7.2/7.3), or None when tunnel mode is off."""
    t = _sec(site, "tunnel")
    if not t.get("enabled") or site.get("status", "active") != "active":
        return None
    paths, seen = [], set()
    for p in t.get("paths") or []:
        if not isinstance(p, dict):
            continue
        pid, path, proto = str(p.get("id") or "").lower(), str(p.get("path") or ""), p.get("protocol")
        if (not SAFE_ID.match(pid) or not SAFE_TUNNEL_PATH.match(path) or path.startswith("/__pcdn")
                or proto not in TUNNEL_PROTOCOLS or path in seen):
            continue
        entry = {"id": pid, "path": path, "protocol": proto, "origin": None, "pool": None}
        # SPEC §22.5 per-path idle timeout (None = the site's idle_timeout)
        pit = p.get("idle_timeout")
        if not isinstance(pit, bool) and (isinstance(pit, int) or str(pit or "").isdigit()):
            entry["idle_timeout"] = _int(pit, 3600, 60, 86400)
        o, pool = p.get("origin"), p.get("pool")
        multi = norm_tunnel_origins(p) if pool is None else None
        if multi is not None:   # SPEC §22.4: rendered exactly like a pool path
            entry["pool"], entry["pool_def"] = INTERNAL_POOL_PREFIX + pid, multi
        elif isinstance(o, dict):
            entry["origin"] = _tunnel_origin(o)
            if entry["origin"] is None:
                continue
        elif pool is not None:
            if str(pool) not in pools:
                continue
            entry["pool"] = str(pool)
        seen.add(path)
        paths.append(entry)
    if not paths:
        return None
    return {
        "paths": paths,
        "idle_timeout": _int(t.get("idle_timeout"), 3600, 60, 86400),
        "per_connection_mbps": _int(t.get("per_connection_mbps"), 0, 0, 100000),
        "max_connections_per_ip": _int(t.get("max_connections_per_ip"), 0, 0, 10000),
        "max_connections": _int(t.get("max_connections"), 0, 0, 10000000),
        "allowed_countries": sorted({str(c).upper() for c in (t.get("allowed_countries") or [])
                                     if re.match(r"^[A-Za-z]{2}$", str(c))}),
        "fallback": t.get("fallback") if t.get("fallback") in ("decoy", "404") else "origin",
        # SPEC §15.2 fair share (default on; only `false` turns it off)
        "fair_share": t.get("fair_share", True) is not False,
    }


def internal_src(cfg: dict) -> str:
    """INTERNAL_SRC: the loopback source address nginx binds when it calls the edge's own loopback
    services (127.0.0.0/8 but never 127.0.0.1, the address an origin resolving to loopback uses)."""
    try:
        ip = ipaddress.IPv4Address(str(cfg.get("INTERNAL_SRC") or ""))
    except ValueError:
        return "127.0.0.2"
    return str(ip) if ip in ipaddress.ip_network("127.0.0.0/8") and str(ip) != "127.0.0.1" else "127.0.0.2"


def internal_ports(cfg: dict) -> list[int]:
    """The edge's own loopback services the nginx workers connect to: the image resizer (an nginx
    server), the image transformer (pcdn-imaged), the object-storage fetch server (nginx) and the
    tunnel probe's echo origin (agent) and h2c body server (nginx)."""
    return sorted({_int(cfg.get(k), d, 1, 65535) for k, d in
                   (("RESIZE_PORT", 8089), ("IMAGE_PORT", 8090), ("STORAGE_FETCH_PORT", 8091),
                    # SPEC §22.3 synthetic tunnel probe: the agent's WS echo origin and the h2c body server
                    ("PROBE_ECHO_PORT", 8092), ("PROBE_H2C_PORT", 8093))})
