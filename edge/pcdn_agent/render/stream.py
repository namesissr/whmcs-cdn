"""L4 proxy (SPEC §16.4): validation of the L4 apps, the port range and the stream {} config."""

import ipaddress
import os
import re

from ..capabilities import l4_ready
from ..common import SAFE_FSPATH, SAFE_ID, SAFE_NAME, SAFE_ORIGIN, SAFE_RESOLVER, _int, _sec, _v6
from ..settings import log
from ..validation.origin import _ip_literal, origin_hp_allowed


L4_APPS_MAX = 2000           # apps rendered per node (every port of the default range fits)
L4_ALLOW_MAX = 100           # ip_allow entries per app


def l4_port_range(cfg: dict) -> tuple[int, int]:
    """L4_PORT_RANGE ("20000-29999"); a malformed value falls back to the default."""
    m = re.match(r"^\s*(\d{1,5})\s*-\s*(\d{1,5})\s*$", str(cfg.get("L4_PORT_RANGE") or ""))
    lo, hi = (int(m.group(1)), int(m.group(2))) if m else (20000, 29999)
    lo, hi = max(1024, lo), min(65535, hi)
    return (lo, hi) if lo <= hi else (20000, 29999)


def _l4_origin(o) -> tuple[str, bool] | None:
    """origin {address, port} -> ("host:port", is_ip) or None."""
    if not isinstance(o, dict):
        return None
    addr = str(o.get("address") or "").strip().lower()
    port = o.get("port")
    if isinstance(port, bool) or not isinstance(port, (int, str)) or not str(port).isdigit():
        return None
    port = int(port)
    if not 1 <= port <= 65535:
        return None
    ip = _ip_literal(addr)
    if ip:
        return f"{ip}:{port}", True
    if not SAFE_ORIGIN.match(addr) or addr.startswith("[") or len(addr) > 253:
        return None
    return f"{addr}:{port}", False


def norm_l4(site: dict) -> list[dict]:
    """Validated, enabled apps of a site's `l4` section (SPEC §16.4); edge_port is range-checked by
    render_l4 (it needs the node settings). Invalid apps are skipped, never "fixed"."""
    apps = _sec(site, "l4").get("apps")
    out, seen = [], set()
    for a in apps if isinstance(apps, list) else []:
        if not isinstance(a, dict) or a.get("enabled") is False:
            continue
        aid = str(a.get("id") if a.get("id") is not None else "").lower()
        proto = a.get("protocol")
        port = a.get("edge_port")
        origin = _l4_origin(a.get("origin"))
        if (not SAFE_ID.match(aid) or aid in seen or proto not in ("tcp", "udp") or origin is None
                or isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535):
            continue
        allow = []
        for c in (a.get("ip_allow") if isinstance(a.get("ip_allow"), list) else [])[:L4_ALLOW_MAX]:
            try:
                allow.append(str(ipaddress.ip_network(str(c).strip(), strict=False)))
            except ValueError:
                continue
        pp = a.get("proxy_protocol") if proto == "tcp" and a.get("proxy_protocol") in ("v1", "v2") else "off"
        seen.add(aid)
        out.append({"id": aid, "protocol": proto, "port": port, "target": origin[0], "ip": origin[1],
                    "proxy_protocol": pp, "allow": list(dict.fromkeys(allow)),
                    "idle": _int(a.get("idle_timeout"), 300, 10, 3600)})
    return out


def l4_sites(config: dict) -> list[dict]:
    """The L4 apps of this node per site: [{"id", "domain", "edge_group", "status", "l4": {"apps"}}].
    The controller sends them twice (SPEC §16.4): the node-wide `l4` list (own group only, active
    sites, enabled apps; it also covers sites without any proxied HTTP host, which are not in
    `sites`) and, per site, an `l4` block of the same apps. The node-wide list wins when present."""
    node = config.get("l4") if isinstance(config, dict) else None
    if isinstance(node, list):
        by: dict = {}
        for e in node:
            if not isinstance(e, dict):
                continue
            try:
                sid = int(e.get("site_id"))
            except (TypeError, ValueError):
                continue
            s = by.setdefault(sid, {"id": sid, "domain": str(e.get("site") or ""), "l4": {"apps": []}})
            s["l4"]["apps"].append({"id": e.get("app_id"), "protocol": e.get("protocol"), "edge_port": e.get("port"),
                                    "origin": e.get("origin"), "proxy_protocol": e.get("proxy_protocol"),
                                    "ip_allow": e.get("ip_allow"), "idle_timeout": e.get("idle_timeout")})
        return [by[k] for k in sorted(by)]
    return [s for s in config.get("sites", []) if isinstance(s, dict)
            and s.get("status", "active") not in ("suspended", "over_quota")]


def l4_busy_ports(cfg: dict, proc: str = "/proc/net") -> set:
    """(protocol, port) pairs some OTHER process already listens on: listening TCP / bound UDP sockets
    from /proc/net minus the ports of the L4 config nginx currently runs. An app on such a port is not
    rendered, because nginx would fail to bind it on reload and every later config apply would be
    rejected with it."""
    busy = set()
    for proto, files, state in (("tcp", ("tcp", "tcp6"), "0A"), ("udp", ("udp", "udp6"), "07")):
        for name in files:
            try:
                with open(os.path.join(proc, name)) as f:
                    next(f, None)
                    for line in f:
                        parts = line.split()
                        if len(parts) > 3 and parts[3] == state:
                            busy.add((proto, int(parts[1].rsplit(":", 1)[1], 16)))
            except (OSError, ValueError, IndexError):
                continue
    mine = set()
    sdir = os.path.join(cfg["NGINX_DIR"], "l4", "sites")
    try:
        for name in os.listdir(sdir):
            with open(os.path.join(sdir, name)) as f:
                for m in re.finditer(r"^\s*listen (?:\[::\]:)?(\d+)( udp)?", f.read(), re.M):
                    mine.add(("udp" if m.group(2) else "tcp", int(m.group(1))))
    except OSError:
        pass
    return busy - mine


def render_l4(config: dict, cfg: dict, reserved_extra: tuple = ()) -> dict:
    """SPEC §16.4 stream config: {"l4/stream.conf": main stream {} block, "l4/sites/<id>.conf": one
    server per app}; {} when no app is rendered (so nodes and sites without L4 keep their tree).
    nginx.conf includes NGINX_DIR/l4/*.conf at the main context. Apps outside L4_PORT_RANGE, on a
    port this node uses itself, or on a (protocol, port) already taken are skipped with a warning:
    ports are unique per edge group, but every node gets every site, so on a clash the apps of this
    node's own group (and of sites without a group) win over foreign ones, then the lower site id."""
    sites = l4_sites(config)
    if not l4_ready(cfg):
        if any(norm_l4(s) for s in sites):
            log.warning("L4 apps configured but this node has no stream module / nginx.conf include; skipped")
        return {}
    lo, hi = l4_port_range(cfg)
    reserved = {_int(cfg.get(k), 0, 0, 65535) for k in ("HTTP_PORT", "HTTPS_PORT", "RESIZE_PORT", "IMAGE_PORT")}
    reserved |= {int(x) for x in re.findall(r"\d{1,5}", str(cfg.get("GUARD_SSH_PORTS") or "22"))}
    reserved |= set(reserved_extra)   # e.g. STORAGE_FETCH_PORT while it is rendered (SPEC §16.8)
    group = cfg.get("GROUP") or ""
    busy = l4_busy_ports(cfg) if any(norm_l4(x) for x in sites) else set()
    sites.sort(key=lambda s: (bool(group and s.get("edge_group") not in (None, "", group)), int(s["id"])))
    v6 = _v6(cfg)
    taken, files, count = set(), {}, 0
    for site in sites:
        domain = str(site.get("domain") or "").lower()
        if not SAFE_NAME.match(domain) or "*" in domain:
            continue
        servers = []
        for a in norm_l4(site):
            key = (a["protocol"], a["port"])
            if not origin_hp_allowed(a["target"], cfg):
                log.warning("site %s: L4 app %s skipped: origin %s is not a public address (ORIGIN_PRIVATE_ALLOW)",
                            site.get("id"), a["id"], a["target"])
                continue
            if (not lo <= a["port"] <= hi or a["port"] in reserved or key in taken or key in busy
                    or count >= L4_APPS_MAX):
                log.warning("site %s: L4 app %s (%s/%d) skipped (outside %d-%d, reserved, taken or in use by "
                            "another process)", site.get("id"), a["id"], a["protocol"], a["port"], lo, hi)
                continue
            taken.add(key)
            count += 1
            opt = " udp reuseport" if a["protocol"] == "udp" else " reuseport"
            L = [f"listen {a['port']}{opt};"] + ([f"listen [::]:{a['port']}{opt};"] if v6 else [])
            L.append(f'set $pcdn_l4_app "{domain}|{a["id"]}";')
            if a["allow"]:
                L += [f"allow {c};" for c in a["allow"]] + ["deny all;"]
            L.append(f"proxy_timeout {a['idle']}s;")
            if a["proxy_protocol"] != "off":
                # nginx sends PROXY protocol v1 only; "v2" is sent as v1 (capability l4_proxy_protocol)
                L.append("proxy_protocol on;")
            if a["ip"]:
                L.append(f"proxy_pass {a['target']};")
            else:   # hostname: resolved at connect time through the stream resolver
                L += [f'set $pcdn_l4_t "{a["target"]}";', "proxy_pass $pcdn_l4_t;"]
            servers.append(f"# app {a['id']} ({a['protocol']})\nserver {{\n" + "".join(f"    {x}\n" for x in L) + "}")
        if servers:
            sid = int(site["id"])
            files[f"l4/sites/{sid}.conf"] = (f"# {domain} (site {sid}) L4 apps — generated by pcdn-agent, do not edit\n"
                                             + "\n".join(servers) + "\n")
    if not files:
        return {}
    nd = cfg["NGINX_DIR"].rstrip("/")
    logp = cfg.get("L4_ACCESS_LOG") or "/var/log/nginx/pcdn-l4.log"
    if not SAFE_FSPATH.match(logp) or not SAFE_FSPATH.match(nd):
        raise ValueError("unsafe L4_ACCESS_LOG / NGINX_DIR")
    resolver = cfg["RESOLVER"] if SAFE_RESOLVER.match(cfg.get("RESOLVER") or "") else "1.1.1.1"
    files["l4/stream.conf"] = (
        "# L4 proxy (SPEC §16.4) — generated by pcdn-agent, do not edit. Included from nginx.conf at the\n"
        "# main context. One JSON line per session; the agent bills bi/bo per app (usage `l4`).\n"
        "stream {\n"
        "    log_format pcdn_l4 escape=json '{\"t\":\"$time_iso8601\",\"a\":\"$pcdn_l4_app\",\"p\":\"$protocol\","
        "\"ip\":\"$remote_addr\",\"bi\":$bytes_received,\"bo\":$bytes_sent,\"st\":$status,\"d\":$session_time}';\n"
        f"    access_log {logp} pcdn_l4 buffer=16k flush=5s;\n"
        f"    resolver {resolver} valid=300s ipv6=off;\n"
        "    resolver_timeout 11s;\n"
        f"    proxy_connect_timeout {_int(cfg.get('TUNNEL_CONNECT_TIMEOUT'), 10, 3, 30)}s;\n"
        f"    include {nd}/l4/sites/*.conf;\n"
        "}\n")
    return files
