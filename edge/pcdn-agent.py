#!/usr/bin/env python3
"""Pasargad CDN edge agent (v2).

Pulls site configuration from the controller, renders the nginx base config,
one vhost per proxied host and the njs data module (sites.js), installs
certificates, executes cache purges and reports per-host usage + security
events. Standard library only, so it runs on any stock Debian/Ubuntu python3.

    pcdn-agent            run the loop
    pcdn-agent once       one sync (config, purges, usage)
    pcdn-agent bootstrap  write an empty tree if none exists (used by install.sh
                          so nginx can start before the first sync)
"""

import hashlib
import json
import logging
import os
import re
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

log = logging.getLogger("pcdn-agent")
HERE = os.path.dirname(os.path.abspath(__file__))

DEFAULTS = {
    "CONTROLLER_URL": "",
    "EDGE_TOKEN": "",
    "NGINX_DIR": "/etc/nginx/pcdn",
    "CACHE_DIR": "/var/cache/pcdn",
    "STATE_FILE": "/var/lib/pcdn/state.json",
    "ACCESS_LOG": "/var/log/nginx/pcdn-access.log",
    "PAGES_DIR": "/usr/share/pcdn/pages",
    "NJS_FILE": "/usr/share/pcdn/njs/pcdn.js",
    "BASE_TEMPLATE": "/usr/share/pcdn/nginx/pcdn-base.conf",
    "GEOIP_DB": "/usr/share/pcdn/geo/country.mmdb",
    "CA_BUNDLE": "/etc/ssl/certs/ca-certificates.crt",
    "RESOLVER": "1.1.1.1 8.8.8.8",
    "HTTP_PORT": "80",
    "HTTPS_PORT": "443",
    "RESIZE_PORT": "8089",
    "DICT_SIZE": "32m",
    "CACHE_MAX_SIZE": "10g",
    "CACHE_KEYS_ZONE": "5m",
    "CACHE_INACTIVE": "7d",
    # cap on cache files scanned for a prefix purge; beyond it, fall back to a full-site purge
    "PURGE_SCAN_MAX": "500000",
    "NGINX_TEST_CMD": "nginx -t -q",
    "NGINX_RELOAD_CMD": "nginx -s reload",
    "NGINX_USER": "www-data",
    "LISTEN_IPV6": "yes",
    "POLL_INTERVAL": "20",
    "USAGE_INTERVAL": "60",
    "HEARTBEAT_INTERVAL": "60",
    # idle upstream connections kept per worker to each tunnel origin (gRPC/h2/XHTTP): a warm
    # connection removes a TCP+TLS round-trip from the border on the next stream/request
    "TUNNEL_KEEPALIVE": "64",
}

STATIC_EXT = "css|js|mjs|map|jpg|jpeg|png|gif|webp|avif|svg|ico|bmp|woff|woff2|ttf|eot|otf|mp4|webm|mp3|ogg|pdf|zip|gz|rar|7z|txt|xml|json"
SAFE_NAME = re.compile(r"^[a-z0-9*][a-z0-9.*-]*$")
SAFE_ORIGIN = re.compile(r"^(\[[0-9a-f:]+\]|[a-z0-9][a-z0-9.-]*)$")
SAFE_ID = re.compile(r"^[a-z0-9_-]{1,32}$")
SAFE_HEADER = re.compile(r"^[A-Za-z0-9-]{1,64}$")
SAFE_VALUE = re.compile(r"^[\x20-\x7e]{0,512}$")
SAFE_PATTERN = re.compile(r"^/[A-Za-z0-9._~%/*+,=:@!&()'-]{0,500}$")
SAFE_URL = re.compile(r"^https?://[A-Za-z0-9.-]+(:\d{1,5})?([/?#][A-Za-z0-9._~%/+,=:@!&?#()'-]{0,1000})?$")
SAFE_COOKIE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
SAFE_CIDR = re.compile(r"^[0-9a-fA-F.:]{2,45}(/\d{1,3})?$")
SAFE_FSPATH = re.compile(r"^/[A-Za-z0-9._/-]+$")
SAFE_SIZE = re.compile(r"^\d{1,6}[kKmMgG]?$")
SAFE_RESOLVER = re.compile(r"^[0-9a-fA-F.:\[\] ]{2,200}$")
SAFE_TUNNEL_PATH = re.compile(r"^/[A-Za-z0-9._~/-]{1,200}$")
IP_LITERAL = re.compile(r"^(\d{1,3}(\.\d{1,3}){3}|\[[0-9a-f:]+\])$")
TUNNEL_PROTOCOLS = ("ws", "httpupgrade", "grpc", "xhttp", "h2")
HOP_HEADERS = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer",
               "transfer-encoding", "upgrade", "host", "content-length"}
FW_ACTIONS = {"allow", "block", "challenge", "captcha", "log"}
FW_FIELDS = {"ip", "country", "path", "host", "query", "user_agent", "referer", "method", "header"}
FW_OPS = {"eq", "ne", "contains", "not_contains", "starts_with", "ends_with", "regex", "in", "not_in"}
WAF_GROUPS = {"sqli", "xss", "lfi", "rce", "php", "scanner", "protocol"}
MAX_ITEMS, MAX_EVENTS, EVENT_BACKLOG, PATHS_PER_ITEM, PATH_TRACK = 20000, 2000, 10000, 50, 1000


def load_config(path: str) -> dict:
    cfg = dict(DEFAULTS)
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                cfg[k.strip()] = v.strip().strip('"').strip("'")
    for k in DEFAULTS:
        if os.getenv("PCDN_" + k):
            cfg[k] = os.environ["PCDN_" + k]
    return cfg


def asset(cfg: dict, key: str, rel: str) -> str:
    """Installed asset path, falling back to the source tree (running from a checkout)."""
    p = cfg.get(key) or ""
    return p if os.path.exists(p) else os.path.join(HERE, rel)


# ----------------------------------------------------------------- escaping helpers

def _q(s: str) -> str:
    """Quote a validated token for nginx config (defence in depth: strips anything special)."""
    return '"' + s.replace("\\", "").replace('"', "").replace("$", "").replace("\n", "") + '"'


def _qv(s: str) -> str:
    """Quote a free-form printable value for nginx, keeping `$` literal via the $pcdn_dollar geo."""
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"').replace("$", "${pcdn_dollar}") + '"'


def _int(v, default: int, lo: int, hi: int) -> int:
    try:
        v = int(v)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, v))


def wildcard_re(pattern: str) -> str:
    """Page-rule style pattern ('*' = anything, including '/') -> anchored regex source.
    re.escape output is valid in PCRE and in JS (non-unicode) regexes."""
    return "^" + "".join(".*" if c == "*" else re.escape(c) for c in pattern) + "$"


def _sec(site: dict, name: str) -> dict:
    v = site.get(name)
    return v if isinstance(v, dict) else {}


def _hp(address: str, port) -> str:
    return f"{address}:{int(port)}"


def _v6(cfg: dict) -> bool:
    return cfg.get("LISTEN_IPV6", "yes").lower() in ("1", "yes", "true", "on")


# ----------------------------------------------------------------- rendering

def render_http(cfg: dict, hc_interval: int = 2) -> str:
    """The base http-context config (from the template), see nginx/pcdn-base.conf.
    hc_interval: js_periodic tick for pool health checks (> the largest check timeout)."""
    with open(asset(cfg, "BASE_TEMPLATE", "nginx/pcdn-base.conf")) as f:
        text = f.read()
    geo = cfg.get("GEOIP_DB") or ""
    if SAFE_FSPATH.match(geo) and os.path.isfile(geo):
        geo_conf = f"geoip2 {geo} {{\n    auto_reload 60m;\n    $pcdn_country country iso_code;\n}}"
    else:  # nginx must start without the database; country rules then never match
        geo_conf = "map $host $pcdn_country {\n    default \"\";\n}"
    subst = {
        "NGINX_DIR": cfg["NGINX_DIR"].rstrip("/"),
        "HTTP_PORT": str(_int(cfg["HTTP_PORT"], 80, 1, 65535)),
        "HTTPS_PORT": str(_int(cfg["HTTPS_PORT"], 443, 1, 65535)),
        "RESIZE_PORT": str(_int(cfg["RESIZE_PORT"], 8089, 1, 65535)),
        "RESOLVER": cfg["RESOLVER"] if SAFE_RESOLVER.match(cfg["RESOLVER"]) else "1.1.1.1",
        "DICT_SIZE": cfg["DICT_SIZE"] if SAFE_SIZE.match(cfg["DICT_SIZE"]) else "32m",
        "GEOIP": geo_conf,
        "HC_INTERVAL": str(_int(hc_interval, 2, 2, 11)),
    }
    if not SAFE_FSPATH.match(subst["NGINX_DIR"]):
        raise ValueError("unsafe NGINX_DIR")
    for k, v in subst.items():
        text = text.replace("{{" + k + "}}", v)
    if not _v6(cfg):
        text = "\n".join(line for line in text.splitlines() if "listen [::]" not in line) + "\n"
    return text


def _legacy_sections(site: dict) -> tuple[dict, dict]:
    """v2 `cache` / `ssl_options` sections, derived from v1 flat fields when absent."""
    cache = site.get("cache") if isinstance(site.get("cache"), dict) else {
        "enabled": bool(site.get("cache_enabled")), "level": "standard",
        "edge_ttl": site.get("edge_cache_ttl") or 0, "browser_ttl": site.get("browser_cache_ttl") or 0,
        "always_online": True}
    sslo = site.get("ssl_options") if isinstance(site.get("ssl_options"), dict) else {
        "force_https": bool(site.get("force_https")), "origin_protocol": site.get("origin_protocol") or "http"}
    return cache, sslo


def resolve_origin(host: dict, pools: dict, default_proto: str):
    """-> (proto, pool name or None, "host:port" or None), or None when unusable."""
    origin = host.get("origin")
    if isinstance(origin, str):  # v1 shape: bare address
        origin = {"address": origin, "port": None}
    if not isinstance(origin, dict):
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
        out[name] = {
            "method": "ip_hash" if p.get("method") == "ip_hash" else "weighted",
            "protocol": proto,
            "origins": origins,
            "health": {"enabled": bool(h.get("enabled")), "path": hpath if SAFE_PATTERN.match(hpath) else "/",
                       "interval": _int(h.get("interval"), 10, 1, 3600), "timeout": _int(h.get("timeout"), 3, 1, 10),
                       "expect": str(h.get("expect") or "2xx,3xx")[:100],
                       "host": hhost if hhost and SAFE_NAME.match(hhost) and "*" not in hhost else None},
        }
    return out


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
        o, pool = p.get("origin"), p.get("pool")
        if isinstance(o, dict):
            addr = str(o.get("address") or "").lower()
            port = o.get("port")
            sni = str(o.get("sni") or "").lower()
            if (not SAFE_ORIGIN.match(addr) or not (isinstance(port, int) or str(port).isdigit())
                    or not 1 <= int(port) <= 65535 or (sni and (not SAFE_NAME.match(sni) or "*" in sni))):
                continue
            entry["origin"] = {"hp": _hp(addr, port), "ip": bool(IP_LITERAL.match(addr)), "tls": bool(o.get("tls")),
                               "sni": sni or None, "verify": bool(o.get("verify"))}
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
    }


def decoy_page(cfg: dict, domain: str) -> str:
    """Neutral placeholder page served on non-tunnel paths when tunnel.fallback = decoy."""
    path = os.path.join(cfg.get("PAGES_DIR") or "", "decoy.html")
    if not os.path.isfile(path):
        path = os.path.join(HERE, "pages", "decoy.html")
    with open(path) as f:
        text = f.read()
    name = domain.split(".")[0].replace("-", " ").title() if domain else "Welcome"
    return text.replace("{{NAME}}", name).replace("{{YEAR}}", str(datetime.now(timezone.utc).year))


def page_rules(site: dict) -> list:
    rules = []
    for r in (_sec(site, "pagerules").get("rules") or []):
        pat = str(r.get("pattern") or "")
        if r.get("enabled") is False or not SAFE_PATTERN.match(pat):
            continue
        rules.append(dict(r, _re=wildcard_re(pat)))
    return rules


def site_js(site: dict, hosts: list, pools: dict, sslo: dict, tunnel: dict | None = None) -> dict:
    """Per-site data for njs (sites.js). Only validated / typed values end up here."""
    fw = _sec(site, "firewall")
    rules = []
    for r in fw.get("rules") or []:
        rid = str(r.get("id") or "").lower()
        if r.get("enabled") is False or not SAFE_ID.match(rid) or r.get("action") not in FW_ACTIONS:
            continue
        conds = []
        for c in r.get("conditions") or []:
            if c.get("field") not in FW_FIELDS or c.get("op") not in FW_OPS:
                break
            val = c.get("value")
            val = [str(x) for x in val] if isinstance(val, list) else str(val if val is not None else "")
            cond = {"field": c["field"], "op": c["op"], "value": val}
            if c["field"] == "header":
                if not SAFE_HEADER.match(str(c.get("name") or "")):
                    break
                cond["name"] = c["name"]
            conds.append(cond)
        else:  # only rules whose every condition is understood
            if conds:
                rules.append({"id": rid, "action": r["action"], "conditions": conds})

    rl = []
    for r in (_sec(site, "ratelimit").get("rules") or []):
        rid, pat = str(r.get("id") or "").lower(), str(r.get("path") or "/*")
        if r.get("enabled") is False or not SAFE_ID.match(rid) or not SAFE_PATTERN.match(pat):
            continue
        rl.append({"id": rid, "path_re": wildcard_re(pat),
                   "methods": [str(m).upper() for m in r.get("methods") or [] if re.match(r"^[A-Za-z]{1,16}$", str(m))],
                   "requests": _int(r.get("requests"), 10, 1, 1000000), "period": _int(r.get("period"), 60, 1, 3600),
                   "action": r.get("action") if r.get("action") in ("block", "challenge", "captcha") else "block",
                   "block_seconds": _int(r.get("block_seconds"), 600, 1, 86400)})

    waf = _sec(site, "waf")
    excl = []
    for e in waf.get("exclusions") or []:
        path = e.get("path")
        if path and not SAFE_PATTERN.match(str(path)):
            continue
        excl.append({"rule_id": _int(e.get("rule_id"), 0, 0, 99999999), "path_re": wildcard_re(path) if path else None})

    hl, dd, im = _sec(site, "hotlink"), _sec(site, "ddos"), _sec(site, "image")
    return {
        "domain": site["domain"],
        "secret": str(site.get("secret") or ""),
        "hosts": hosts,
        "blocked_ips": [str(c) for c in (site.get("blocked_ips") or []) if SAFE_CIDR.match(str(c))],
        "min_tls": "1.3" if sslo.get("min_tls") == "1.3" else "1.2",
        "firewall": {"default_action": "block" if fw.get("default_action") == "block" else "allow", "rules": rules},
        "hotlink": {"enabled": bool(hl.get("enabled")),
                    "extensions": [str(e) for e in (hl.get("extensions") or []) if re.match(r"^[A-Za-z0-9]{1,10}$", str(e))],
                    "allowed_referers": [str(h).lower() for h in (hl.get("allowed_referers") or []) if SAFE_NAME.match(str(h).lower())],
                    "allow_empty": hl.get("allow_empty", True) is not False},
        "ratelimit": rl,
        "ddos": {"mode": dd.get("mode") if dd.get("mode") in ("auto", "js", "captcha") else "off",
                 "threshold_rps": _int(dd.get("threshold_rps"), 200, 1, 10000000),
                 "clearance_ttl": _int(dd.get("clearance_ttl"), 3600, 60, 30 * 86400)},
        "waf": {"mode": waf.get("mode") if waf.get("mode") in ("detect", "block") else "off",
                "paranoia": _int(waf.get("paranoia"), 1, 1, 3),
                "groups": [g for g in (waf.get("groups") or []) if g in WAF_GROUPS],
                "exclusions": excl,
                "off_paths": [r["_re"] for r in page_rules(site) if r.get("waf") is False]},
        "pools": pools,
        "image": {"enabled": bool(im.get("enabled")), "quality": _int(im.get("quality"), 85, 1, 100),
                  "max_width": _int(im.get("max_width"), 2000, 16, 10000)},
        # prefixes where only firewall allow/block/log rules apply (tunnel mode)
        "tunnel_paths": [p["path"] for p in tunnel["paths"]] if tunnel else [],
    }


def render_site(site: dict, cfg: dict) -> tuple[str, dict]:
    """Return (nginx config text, {relative_path: content}) for one site."""
    text, files, _ = _render_site(site, cfg)
    return text, files


def _render_site(site: dict, cfg: dict) -> tuple[str, dict, dict | None]:
    sid = int(site["id"])
    domain = site["domain"]
    files = {}
    zone = f"pcdn_{sid}"
    cache_path = os.path.join(cfg["CACHE_DIR"], str(sid))
    out = [f"# {domain} (site {sid}) — generated by pcdn-agent, do not edit"]
    out.append(
        f"proxy_cache_path {cache_path} levels=1:2 keys_zone={zone}:{cfg['CACHE_KEYS_ZONE']} "
        f"max_size={cfg['CACHE_MAX_SIZE']} inactive={cfg['CACHE_INACTIVE']} use_temp_path=off;"
    )
    rps = int(site.get("rate_limit_rps") or 0)
    if rps > 0:
        out.append(f"limit_req_zone $binary_remote_addr zone=pcdn_rl_{sid}:1m rate={rps}r/s;")

    ssl = site.get("ssl")
    if ssl:
        files[f"certs/{sid}.crt"] = ssl["cert"]
        files[f"certs/{sid}.key"] = ssl["key"]

    status = site.get("status", "active")
    cache, sslo = _legacy_sections(site)
    pools = norm_pools(site)
    origin_proto = "https" if sslo.get("origin_protocol") == "https" else "http"
    cache_on = bool(cache.get("enabled"))
    level = "aggressive" if cache.get("level") == "aggressive" else "standard"
    edge_ttl = _int(cache.get("edge_ttl"), 86400, 0, 31536000)
    browser_ttl = _int(cache.get("browser_ttl"), 0, 0, 31536000)
    ignore_q = bool(cache.get("ignore_query"))
    always_online = cache.get("always_online", True) is not False
    port, sport = _int(cfg["HTTP_PORT"], 80, 1, 65535), _int(cfg["HTTPS_PORT"], 443, 1, 65535)
    v6 = _v6(cfg)

    # --- per-site maps (http context)
    cookies = [str(c) for c in (cache.get("bypass_cookies") or []) if SAFE_COOKIE.match(str(c))]
    nocache_var = None
    if cookies and cache_on:
        nocache_var = f"$pcdn_nocache_{sid}"
        alt = "|".join(re.escape(c) for c in cookies)
        out.append(f"map $http_cookie {nocache_var} {{\n    \"~(?:^|;)\\s*(?:{alt})[^=;]*=\" 1;\n    default \"\";\n}}")
    hsts = _sec(sslo, "hsts")
    hsts_var = None
    if ssl and hsts.get("enabled"):
        v = f"max-age={_int(hsts.get('max_age'), 31536000, 0, 63072000)}"
        v += "; includeSubDomains" if hsts.get("include_subdomains") else ""
        v += "; preload" if hsts.get("preload") else ""
        hsts_var = f"$pcdn_hsts_{sid}"
        out.append(f"map $scheme {hsts_var} {{\n    https \"{v}\";\n    default \"\";\n}}")

    # --- header rules
    hdr = _sec(site, "headers")
    req_headers = {}
    for h in hdr.get("request") or []:
        n, v = str(h.get("name") or ""), h.get("value")
        if SAFE_HEADER.match(n) and n.lower() not in HOP_HEADERS and v is not None and SAFE_VALUE.match(str(v)):
            req_headers[n.lower()] = (n, _qv(str(v)))
    resp_add, resp_hide = [], []
    for h in hdr.get("response") or []:
        n, v = str(h.get("name") or ""), h.get("value")
        if not SAFE_HEADER.match(n) or n.lower() in HOP_HEADERS:
            continue
        if v is None:
            resp_hide.append(n)
        elif SAFE_VALUE.match(str(v)):
            resp_hide.append(n)  # replace the origin's value instead of sending both
            resp_add.append(f"add_header {n} {_qv(str(v))} always;")
    base_req = [("Host", "$host"), ("X-Real-IP", "$remote_addr"), ("X-Forwarded-For", "$proxy_add_x_forwarded_for"),
                ("X-Forwarded-Proto", "$scheme"), ("X-Country-Code", "$pcdn_country")]

    def req_hdrs(directive, conn=(("Upgrade", "$http_upgrade"), ("Connection", "$pcdn_connection_upgrade"))):
        pairs = [(n, v) for n, v in base_req if n.lower() not in req_headers] + list(req_headers.values()) + list(conn)
        return [f"{directive} {n} {v};" for n, v in pairs]

    # nginx drops inherited proxy_set_header / add_header / proxy_hide_header as soon as
    # a location sets one of them, so every proxying location gets the complete set.
    proxy_hdrs = req_hdrs("proxy_set_header")

    def loc_common(hides=(), extra_add=()):
        lines = list(proxy_hdrs)
        for n in dict.fromkeys(list(hides) + resp_hide):
            lines.append(f"proxy_hide_header {n};")
        lines += list(extra_add)
        lines.append("add_header X-Served-By $hostname always;")
        if hsts_var:
            lines.append(f"add_header Strict-Transport-Security {hsts_var} always;")
        return lines + resp_add

    def proxy_loc(match, mode, ttl, bttl, iq):
        """mode: bypass | dynamic (honour origin; ttl>0 = default TTL) | aggressive | everything | static."""
        L, hides, adds = [], [], []
        if mode == "bypass" or not cache_on:
            adds.append("add_header X-Cache BYPASS always;")
        else:
            key = "$scheme://$host$pcdn_path" if iq else "$scheme://$host$request_uri"
            L += [f"proxy_cache {zone};", f"proxy_cache_key {key};"]
            no_cache = []
            if mode == "static":
                L += [f"proxy_cache_valid 200 206 301 {max(ttl, 60)}s;", "proxy_cache_valid 404 1m;",
                      "proxy_ignore_headers Cache-Control Expires Set-Cookie Vary;"]
                hides.append("Set-Cookie")
            elif mode in ("aggressive", "everything"):
                # cache regardless of Cache-Control, but never store a response that sets
                # cookies (it would hand one visitor's session to everybody)
                L += [f"proxy_cache_valid 200 206 301 {max(ttl, 60)}s;",
                      "proxy_ignore_headers Cache-Control Expires Vary X-Accel-Expires;"]
                no_cache.append("$upstream_http_set_cookie")
            elif ttl > 0:  # dynamic with an explicit edge TTL (page rule): used when the origin sends none
                L.append(f"proxy_cache_valid 200 301 {max(ttl, 60)}s;")
            if nocache_var and mode != "static":
                L.append(f"proxy_cache_bypass {nocache_var};")
                no_cache.insert(0, nocache_var)
            if no_cache:
                L.append("proxy_no_cache " + " ".join(no_cache) + ";")
            stale = "error timeout updating http_500 http_502 http_503 http_504" if always_online else "updating"
            L += [f"proxy_cache_use_stale {stale};", "proxy_cache_lock on;", "proxy_cache_background_update on;"]
            adds.append("add_header X-Cache $upstream_cache_status always;")
        if bttl > 0:
            hides += ["Cache-Control", "Expires"]
            adds.append(f"add_header Cache-Control \"public, max-age={bttl}\" always;")
        L = loc_common(hides, adds) + L + ["proxy_pass $pcdn_proto://$pcdn_target;"]
        return [f"    location {match} {{"] + ["        " + x for x in L] + ["    }"]

    # --- custom error pages (files next to the config, served from an internal location)
    ep = _sec(site, "errorpages")
    err_pages = {}
    for cls, codes in (("5xx", "500 502 503 504"), ("4xx", "400 403 404 405 410")):
        body = ep.get(cls)
        if isinstance(body, str) and body.strip() and len(body.encode()) <= 65536:
            files[f"errors/{sid}-{cls}.html"] = body
            err_pages[cls] = codes

    image_on = bool(_sec(site, "image").get("enabled"))
    resize_port = _int(cfg["RESIZE_PORT"], 8089, 1, 65535)
    prules = page_rules(site)
    valid_hosts = []

    # --- tunnel mode (SPEC §7): per-site http-context parts
    tunnel = norm_tunnel(site, pools)
    fallback = tunnel["fallback"] if tunnel else "origin"
    image_on = image_on and fallback == "origin"  # decoy / 404 sites never fetch origin content
    decoy = decoy_page(cfg, domain) if fallback == "decoy" else None
    tn_upstreams = {}  # (h2?, host:port) -> upstream name (keepalive towards IP-literal origins)
    if tunnel and tunnel["allowed_countries"]:
        out.append(f"map $pcdn_country $pcdn_tcc_{sid} {{\n"
                   + "".join(f"    {cc} 1;\n" for cc in tunnel["allowed_countries"]) + "    default 0;\n}")

    def tn_upstream(hp, h2):
        # separate pools for HTTP/2 (grpc_pass) and HTTP/1.1 (proxy_pass): a cached keepalive
        # connection must never be handed to the other protocol
        if (h2, hp) not in tn_upstreams:
            name = f"pcdn_tn_{sid}_{len(tn_upstreams)}"
            tn_upstreams[(h2, hp)] = name
            # one server: never marked down (max_fails=0). A warm pool of idle keepalive
            # connections to the VPN origin removes the TCP+TLS handshake across the border from
            # the next stream; keepalive_requests/keepalive_time keep long VPN sessions from
            # recycling a working upstream connection mid-use.
            ka = _int(cfg.get("TUNNEL_KEEPALIVE"), 64, 1, 4096)
            out.append(f"upstream {name} {{\n    server {hp} max_fails=0;\n    keepalive {ka};\n"
                       f"    keepalive_timeout 300s;\n    keepalive_requests 1000000;\n"
                       f"    keepalive_time 1h;\n}}")
        return tn_upstreams[(h2, hp)]

    def tunnel_loc(p, proto, pool, target):
        """One `location ^~ <path>` for a tunnel path; host defaults: proto / pool / target."""
        kind, idle = p["protocol"], tunnel["idle_timeout"]
        grpc = kind in ("grpc", "h2")
        keepalive_ok = kind in ("xhttp", "grpc", "h2")  # upgraded (ws) connections are never reused
        L = [f"set $pcdn_tn {kind};"]
        if tunnel["allowed_countries"]:
            L.append(f"if ($pcdn_tcc_{sid} = 0) {{ return 403; }}")
        o = p["origin"]
        if o:
            tls, sni, verify = o["tls"], o["sni"] or "$host", o["verify"]
            if o["ip"] and keepalive_ok:
                dest = tn_upstream(o["hp"], grpc)
            else:
                L.append(f"set $pcdn_tn_target {_q(o['hp'])};")  # variable: resolved at request time
                dest = "$pcdn_tn_target"
        elif p["pool"]:
            tls, sni, verify = pools[p["pool"]]["protocol"] == "https", "$host", bool(sslo.get("origin_verify"))
            L += [f"set $pcdn_tn_pool {_q(p['pool'])};", "set $pcdn_tn_target $pcdn_tn_upstream;"]
            dest = "$pcdn_tn_target"
        else:
            tls, sni, verify = proto == "https", "$host", bool(sslo.get("origin_verify"))
            host_addr = (target or "").rsplit(":", 1)[0]
            dest = tn_upstream(target, grpc) if not pool and keepalive_ok and IP_LITERAL.match(host_addr) else "$pcdn_target"
        if tunnel["max_connections"]:
            L.append(f"limit_conn pcdn_tn_site {tunnel['max_connections']};")
        if tunnel["max_connections_per_ip"]:
            L.append(f"limit_conn pcdn_tn_ip {tunnel['max_connections_per_ip']};")
        L.append("limit_conn_status 429;")
        if rps > 0:
            L.append("limit_req_dry_run on;")  # the legacy per-IP request limit is not for streams
        # tunnel.per_connection_mbps is not rendered: nginx 1.24 resets limit_rate to 0 for
        # unbuffered proxying (proxy_buffering off, every grpc_pass) and never applies it to
        # upgraded (101) connections, where a limit_rate delay on the 101 response even makes
        # nginx miss the client's close. See docs/EDGE.md.
        L += ["client_max_body_size 0;", f"client_body_timeout {idle}s;", f"send_timeout {idle}s;",
              "tcp_nodelay on;", "gzip off;", "brotli off;"]
        if grpc:
            L += req_hdrs("grpc_set_header", conn=())
            L += [f"grpc_read_timeout {idle}s;", f"grpc_send_timeout {idle}s;", "grpc_socket_keepalive on;",
                  "grpc_next_upstream off;", "grpc_intercept_errors off;"]
            if tls:
                L += ["grpc_ssl_server_name on;", f"grpc_ssl_name {sni};"]
                if verify:
                    L += ["grpc_ssl_verify on;", f"grpc_ssl_trusted_certificate {cfg['CA_BUNDLE']};",
                          "grpc_ssl_verify_depth 4;"]
            L.append(f"grpc_pass {'grpcs' if tls else 'grpc'}://{dest};")
        else:
            conn = (("Connection", '""'),) if kind == "xhttp" else (
                ("Upgrade", "$http_upgrade"), ("Connection", "$pcdn_connection_upgrade"))
            L += ["proxy_http_version 1.1;"] + req_hdrs("proxy_set_header", conn)
            L += ["proxy_buffering off;", "proxy_request_buffering off;", "proxy_cache off;",
                  f"proxy_read_timeout {idle}s;", f"proxy_send_timeout {idle}s;", "proxy_socket_keepalive on;",
                  "proxy_next_upstream off;", "proxy_intercept_errors off;"]
            if tls:
                L += ["proxy_ssl_server_name on;", f"proxy_ssl_name {sni};"]
                L += (["proxy_ssl_verify on;", f"proxy_ssl_trusted_certificate {cfg['CA_BUNDLE']};",
                       "proxy_ssl_verify_depth 4;"] if verify else ["proxy_ssl_verify off;"])
            L.append(f"proxy_pass {'https' if tls else 'http'}://{dest};")
        return [f"    location ^~ {_q(p['path'])} {{"] + ["        " + x for x in L] + ["    }"]

    for host in site["hosts"]:
        name = str(host["name"]).lower()
        res = resolve_origin(host, pools, origin_proto)
        if not SAFE_NAME.match(name) or res is None:
            log.warning("skipping unsafe host entry %r -> %r", name, host.get("origin"))
            continue
        proto, pool, target = res
        valid_hosts.append(name)
        s = ["server {"]
        s.append(f"    listen {port};")
        if v6:
            s.append(f"    listen [::]:{port};")
        if ssl:
            # "listen ... http2" works on every nginx >= 1.9.5 (newer ones only warn)
            s.append(f"    listen {sport} ssl http2;")
            if v6:
                s.append(f"    listen [::]:{sport} ssl http2;")
            s.append(f"    ssl_certificate {cfg['NGINX_DIR']}/certs/{sid}.crt;")
            s.append(f"    ssl_certificate_key {cfg['NGINX_DIR']}/certs/{sid}.key;")
        s.append(f"    server_name {name};")
        s.append(f"    access_log {cfg['ACCESS_LOG']} pcdn;")
        s.append(f"    set $pcdn_site {sid};")
        s.append("    location = /__pcdn/health { access_log off; return 200 \"ok\\n\"; }")

        if status in ("suspended", "over_quota"):
            page = "suspended.html" if status == "suspended" else "over_quota.html"
            s.append(f"    root {cfg['PAGES_DIR']};")
            s.append(f"    error_page 503 /{page};")
            s.append(f"    location = /{page} {{ internal; add_header Cache-Control no-store always; }}")
            s.append("    location / { return 503; }")
            s.append("}")
            out.append("\n".join(s))
            continue

        s.append(f"    set $pcdn_proto {proto};")
        if pool:
            s.append(f"    set $pcdn_pool {_q(pool)};")
            s.append("    set $pcdn_target $pcdn_upstream;")
        else:
            s.append(f"    set $pcdn_target {_q(target)};")
        # security verdict (njs): firewall, hotlink, rate limits, DDoS challenge, WAF
        s.append("    if ($pcdn_verdict !~ \"^(?:ok|log:)\") { rewrite ^ /__pcdn/deny/$pcdn_verdict? last; }")
        if sslo.get("force_https") and ssl:
            s.append("    if ($scheme = http) { return 301 https://$host$request_uri; }")
        if image_on:
            s.append("    if ($pcdn_img_w) { rewrite ^ /__pcdn/img$uri last; }")
        if rps > 0:
            s.append(f"    limit_req zone=pcdn_rl_{sid} burst={rps * 2} nodelay;")
            s.append("    limit_req_status 429;")
        s.append("    proxy_ssl_server_name on;")
        s.append("    proxy_ssl_name $host;")
        if proto == "https" and sslo.get("origin_verify"):
            s.append("    proxy_ssl_verify on;")
            s.append(f"    proxy_ssl_trusted_certificate {cfg['CA_BUNDLE']};")
            s.append("    proxy_ssl_verify_depth 4;")
        for cls, codes in err_pages.items():
            s.append(f"    error_page {codes} /__pcdn/err/{cls}.html;")
        if err_pages:
            s.append("    proxy_intercept_errors on;")

        s.append("    location ^~ /__pcdn/ { return 404; }")
        s.append("    location ^~ /__pcdn/deny/ { internal; js_content pcdn.deny; }")
        s.append("    location = /__pcdn/verify { js_content pcdn.verify; }")
        s.append("    location = /__pcdn/captcha { client_max_body_size 16k; client_body_buffer_size 16k; js_content pcdn.captcha; }")
        for cls in err_pages:
            s.append(f"    location = /__pcdn/err/{cls}.html {{ internal; default_type text/html; "
                     f"alias {cfg['NGINX_DIR']}/errors/{sid}-{cls}.html; add_header Cache-Control no-store always; }}")

        if image_on:
            L = ["internal;", "rewrite ^/__pcdn/img(/.*)$ $1 break;"]
            adds = []
            if cache_on:
                key = ("$scheme://$host$pcdn_path?w=$pcdn_img_w&h=$pcdn_img_h" if ignore_q
                       else "$scheme://$host$request_uri")
                L += [f"proxy_cache {zone};", f"proxy_cache_key \"{key}\";",
                      f"proxy_cache_valid 200 {max(edge_ttl, 60)}s;",
                      "proxy_ignore_headers Cache-Control Expires Set-Cookie Vary;", "proxy_cache_lock on;"]
                adds.append("add_header X-Cache $upstream_cache_status always;")
            else:
                adds.append("add_header X-Cache BYPASS always;")
            L = L + loc_common(["Set-Cookie"], adds) + [
                "proxy_set_header X-Pcdn-Origin $pcdn_proto://$pcdn_target;",
                "proxy_set_header X-Pcdn-W $pcdn_img_w;",
                "proxy_set_header X-Pcdn-H $pcdn_img_h;",
                "proxy_set_header X-Pcdn-Q $pcdn_img_q;",
                f"proxy_pass http://127.0.0.1:{resize_port};"]
            s += ["    location ^~ /__pcdn/img/ {"] + ["        " + x for x in L] + ["    }"]

        # tunnel paths: "^~" prefix locations, so no page rule / static regex location can take them
        if tunnel:
            for p in tunnel["paths"]:
                s += tunnel_loc(p, proto, pool, target)
            if fallback == "decoy":
                s.append("    location / {")
                s.append("        default_type text/html;")
                s.append("        add_header Cache-Control \"no-cache\" always;")
                s.append(f"        return 200 {_qv(decoy)};")
                s.append("    }")
                s.append("}")
                out.append("\n".join(s))
                continue
            if fallback == "404":
                s.append("    location / { return 404; }")
                s.append("}")
                out.append("\n".join(s))
                continue

        # page rules: regex locations in order (nginx uses the first matching regex)
        for r in prules:
            match = f"~ \"{r['_re']}\""
            red = r.get("redirect")
            if isinstance(red, dict) and SAFE_URL.match(str(red.get("url") or "")):
                code = red.get("code") if red.get("code") in (301, 302, 307, 308) else 301
                s.append(f"    location {match} {{ return {code} {_qv(red['url'])}; }}")
                continue
            if all(r.get(k) is None for k in ("cache", "edge_ttl", "browser_ttl", "ignore_query")):
                continue  # WAF-only rule: handled in njs
            default_mode = "aggressive" if level == "aggressive" else "dynamic"
            mode = {"bypass": "bypass", "standard": "dynamic", "everything": "everything"}.get(r.get("cache"), default_mode)
            if r.get("edge_ttl") is not None:
                ttl = _int(r["edge_ttl"], edge_ttl, 0, 31536000)
            else:
                ttl = 0 if mode == "dynamic" else edge_ttl
            bttl = browser_ttl if r.get("browser_ttl") is None else _int(r["browser_ttl"], 0, 0, 31536000)
            iq = ignore_q if r.get("ignore_query") is None else bool(r["ignore_query"])
            s += proxy_loc(match, mode, ttl, bttl, iq)

        if cache_on:
            # static assets: cached at the edge even without origin headers
            s += proxy_loc(f"~* \\.(?:{STATIC_EXT})$", "static", edge_ttl, browser_ttl, ignore_q)
            s += proxy_loc("/", "aggressive" if level == "aggressive" else "dynamic",
                           edge_ttl if level == "aggressive" else 0, 0, ignore_q)
        else:
            s += proxy_loc("/", "bypass", 0, 0, False)
        s.append("}")
        out.append("\n".join(s))

    js = site_js(site, valid_hosts, pools, sslo, tunnel) if status not in ("suspended", "over_quota") and valid_hosts else None
    return "\n\n".join(out) + "\n", files, js


def render_all(config: dict, cfg: dict) -> dict:
    with open(asset(cfg, "NJS_FILE", "njs/pcdn.js")) as f:
        files = {"js/pcdn.js": f.read()}
    js_sites = {}
    max_timeout = 1
    for site in config.get("sites", []):
        text, extra, js = _render_site(site, cfg)
        files[f"sites/{int(site['id'])}.conf"] = text
        files.update(extra)
        if js:
            js_sites[str(int(site["id"]))] = js
            for p in js["pools"].values():
                if p["health"]["enabled"]:
                    max_timeout = max(max_timeout, p["health"]["timeout"])
    files["http.conf"] = render_http(cfg, max_timeout + 1)
    # JSON is valid JS; ensure_ascii keeps U+2028 & co. out of the source
    files["js/sites.js"] = ("// generated by pcdn-agent, do not edit\nexport default "
                            + json.dumps(js_sites, ensure_ascii=True, sort_keys=True) + ";\n")
    return files


# ----------------------------------------------------------------- apply

def run(cmd: str) -> tuple[int, str]:
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return p.returncode, (p.stdout + p.stderr).strip()


def write_tree(root: str, files: dict):
    os.makedirs(os.path.join(root, "sites"), exist_ok=True)
    os.makedirs(os.path.join(root, "certs"), mode=0o700, exist_ok=True)
    for rel, content in files.items():
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        # keys and the HMAC secrets are only read by the nginx master (root) at load time
        mode = 0o600 if rel.endswith(".key") or rel == "js/sites.js" else 0o644
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        with os.fdopen(fd, "w") as f:
            f.write(content)


def ensure_cache_dirs(config: dict, cfg: dict):
    base = cfg["CACHE_DIR"]
    os.makedirs(base, exist_ok=True)
    wanted = {str(int(s["id"])) for s in config.get("sites", [])}
    for sid in wanted:
        os.makedirs(os.path.join(base, sid), exist_ok=True)
        try:
            shutil.chown(os.path.join(base, sid), user=cfg["NGINX_USER"])
        except (LookupError, PermissionError, OSError):
            pass
    for name in os.listdir(base):
        if name.isdigit() and name not in wanted:
            shutil.rmtree(os.path.join(base, name), ignore_errors=True)


def apply_config(config: dict, cfg: dict) -> str | None:
    """Atomically swap the rendered tree in; roll back if nginx rejects it."""
    root = cfg["NGINX_DIR"].rstrip("/")
    new, old = root + ".new", root + ".old"
    shutil.rmtree(new, ignore_errors=True)
    shutil.rmtree(old, ignore_errors=True)
    write_tree(new, render_all(config, cfg))
    ensure_cache_dirs(config, cfg)

    had_old = os.path.exists(root)
    if had_old:
        os.rename(root, old)
    os.rename(new, root)
    code, output = run(cfg["NGINX_TEST_CMD"])
    if code != 0:
        shutil.rmtree(root, ignore_errors=True)
        if had_old:
            os.rename(old, root)
        return "nginx -t failed: " + output[-1500:]
    code, output = run(cfg["NGINX_RELOAD_CMD"])
    shutil.rmtree(old, ignore_errors=True)
    if code != 0:
        return "nginx reload failed: " + output[-1500:]
    return None


def bootstrap(cfg: dict):
    """Empty tree so nginx can start before the first successful sync."""
    root = cfg["NGINX_DIR"].rstrip("/")
    if not os.path.exists(os.path.join(root, "http.conf")):
        write_tree(root, render_all({"sites": []}, cfg))
    os.makedirs(cfg["CACHE_DIR"], exist_ok=True)


def render_rev(cfg: dict) -> str:
    """Changes whenever local rendering inputs change (agent/njs/template upgrade, GeoIP DB
    appearing, local settings) so the next sync re-renders even if the config ETag is unchanged."""
    h = hashlib.sha256()
    decoy = os.path.join(cfg.get("PAGES_DIR") or "", "decoy.html")
    for path in (asset(cfg, "NJS_FILE", "njs/pcdn.js"), asset(cfg, "BASE_TEMPLATE", "nginx/pcdn-base.conf"),
                 decoy if os.path.isfile(decoy) else os.path.join(HERE, "pages", "decoy.html"),
                 os.path.abspath(__file__)):
        try:
            with open(path, "rb") as f:
                h.update(f.read())
        except OSError:
            pass
    h.update(str(os.path.isfile(cfg.get("GEOIP_DB") or "")).encode())
    h.update(json.dumps({k: cfg.get(k) for k in sorted(DEFAULTS) if k not in ("CONTROLLER_URL", "EDGE_TOKEN")}).encode())
    return h.hexdigest()


# ----------------------------------------------------------------- purge

def cache_file(cache_dir: str, site_id: int, key: str) -> str:
    h = hashlib.md5(key.encode()).hexdigest()
    return os.path.join(cache_dir, str(site_id), h[-1], h[-3:-1], h)


def wipe_cache(base: str) -> int:
    """Delete the whole site cache dir contents (everything / legacy empty-urls purge)."""
    removed = 0
    if os.path.isdir(base):
        for name in os.listdir(base):
            shutil.rmtree(os.path.join(base, name), ignore_errors=True)
            removed += 1
    return removed


def _prefix_target(prefix: str) -> tuple[str | None, str] | None:
    """A purge prefix -> (host_or_None, path). '/blog/' matches any host; a full URL pins the host."""
    if prefix.startswith(("http://", "https://")):
        m = re.match(r"^https?://([^/?#]+)([^#]*)", prefix)
        if not m:
            return None
        host, path = m.group(1).lower(), m.group(2) or "/"
        if not path.startswith("/"):
            path = "/" + path
        return host, path
    return (None, prefix) if prefix.startswith("/") else None


def _cache_key_host_path(key: str) -> tuple[str, str] | None:
    """Split a cache KEY '<scheme>://<host><uri>' into (host, path)."""
    m = re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://([^/]*)(.*)$", key)
    if not m:
        return None
    return m.group(1).lower(), m.group(2) or "/"


def _read_cache_key(path: str) -> str | None:
    """nginx writes a 'KEY: <scheme>://<host><uri>' line near the top of every cache file."""
    try:
        with open(path, "rb") as f:
            head = f.read(16384)
    except OSError:
        return None
    i = head.find(b"\nKEY: ")
    if i < 0:
        return None
    j = head.find(b"\n", i + 6)
    if j < 0:
        return None
    return head[i + 6:j].decode("latin-1", "replace")


def purge_prefixes(base: str, prefixes: list[str], scan_max: int) -> tuple[int, bool]:
    """Scan the site's cache files and delete those whose KEY path starts with a prefix.
    Returns (removed, overflow); overflow=True means the scan cap was hit."""
    targets = [t for t in (_prefix_target(p) for p in prefixes) if t]
    if not targets or not os.path.isdir(base):
        return 0, False
    removed = scanned = 0
    for root, _dirs, files in os.walk(base):
        for name in files:
            scanned += 1
            if scanned > scan_max:
                return removed, True
            fpath = os.path.join(root, name)
            key = _read_cache_key(fpath)
            if key is None:
                continue
            hp = _cache_key_host_path(key)
            if hp is None:
                continue
            khost, kpath = hp
            for phost, ppath in targets:
                if phost is not None and khost != phost:
                    continue
                if kpath.startswith(ppath):
                    try:
                        os.remove(fpath)
                        removed += 1
                    except OSError:
                        pass
                    break
    return removed, False


def do_purge(item: dict, cfg: dict) -> int:
    sid = int(item["site_id"])
    base = os.path.join(cfg["CACHE_DIR"], str(sid))
    urls = item.get("urls") or []
    prefixes = item.get("prefixes") or []
    everything = bool(item.get("everything"))
    # whole-site wipe: explicit `everything`, or the legacy empty-urls request (no prefixes either)
    if everything or (not urls and not prefixes):
        return wipe_cache(base)
    removed = 0
    for url in urls:  # exact URLs keep the fast hashed-key delete
        m = re.match(r"^https?://([^/?#]+)([^#]*)", url)
        if not m:
            continue
        host, path = m.group(1).lower(), m.group(2) or "/"
        if not path.startswith("/"):
            path = "/" + path
        # cache keys are "$scheme://$host$request_uri", or "$scheme://$host$pcdn_path"
        # (query dropped) on sites with ignore_query: remove both variants
        for scheme in ("http", "https"):
            for p in dict.fromkeys((path, path.split("?", 1)[0])):
                try:
                    os.remove(cache_file(cfg["CACHE_DIR"], sid, f"{scheme}://{host}{p}"))
                    removed += 1
                except FileNotFoundError:
                    pass
    if prefixes:
        scan_max = _int(cfg.get("PURGE_SCAN_MAX"), 500000, 1, 10 ** 9)
        n, overflow = purge_prefixes(base, prefixes, scan_max)
        if overflow:  # too many files to scan safely -> fall back to a full-site purge
            log.warning("purge scan cap %d exceeded for site %s; falling back to full purge", scan_max, sid)
            return wipe_cache(base)
        removed += n
    return removed


# ----------------------------------------------------------------- usage

def _utc(ts: str) -> datetime:
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def floor_hour(ts: str) -> str:
    return _utc(ts).replace(minute=0, second=0, microsecond=0).strftime("%Y-%m-%dT%H:00:00Z")


def _bucket(pending: dict, key: str) -> dict:
    a = pending.get(key)
    if isinstance(a, list):  # v1 state file: [bytes, requests, cache_hits]
        a = {"bytes": a[0], "requests": a[1], "cache_hits": a[2]}
    if a is None:
        a = {"bytes": 0, "requests": 0, "cache_hits": 0}
    for k in ("status", "codes", "countries", "paths", "security"):
        a.setdefault(k, {})
    pending[key] = a
    return a


def _inc(d: dict, k: str, n: int = 1):
    d[k] = d.get(k, 0) + n


def _account(e: dict, pending: dict, events: list):
    host = e["h"].lower()
    a = _bucket(pending, f"{host}|{floor_hour(e['t'])}")
    a["bytes"] += int(e.get("b") or 0)
    a["requests"] += 1
    if e.get("c") in ("HIT", "STALE", "UPDATING", "REVALIDATED"):
        a["cache_hits"] += 1
    code = int(e.get("s") or 0)
    if 100 <= code <= 599:
        _inc(a["status"], f"{code // 100}xx")
        _inc(a["codes"], str(code))
    cc = str(e.get("cc") or "").upper()
    if re.match(r"^[A-Z]{2}$", cc):
        _inc(a["countries"], cc)
    uri = str(e.get("u") or "")
    if uri:
        path = uri.split("?", 1)[0][:512]
        if path in a["paths"] or len(a["paths"]) < PATH_TRACK:
            _inc(a["paths"], path)
    tn = e.get("tn")
    if tn in TUNNEL_PROTOCOLS:
        _account_tunnel(a, e, tn, code)
    parts = str(e.get("v") or "ok").split(":", 2)
    if len(parts) == 3 and parts[0] in ("block", "challenge", "captcha", "log"):
        action, source, rule = parts
        _inc(a["security"], source)
        if action in ("challenge", "captcha"):
            _inc(a["security"], "challenge")
        events.append({"t": _utc(e["t"]).strftime("%Y-%m-%dT%H:%M:%SZ"), "host": host, "ip": str(e.get("ip") or ""),
                       "country": cc, "method": str(e.get("m") or ""), "path": uri[:2048], "action": action,
                       "source": source, "rule": rule, "user_agent": str(e.get("ua") or "")[:512]})


def _nsum(v) -> int:
    """Sum of an nginx multi-upstream value ("12, 34 : 5"; "-" / "" = 0)."""
    return sum(int(x) for x in re.findall(r"\d+", str(v or "")))


def _account_tunnel(a: dict, e: dict, proto: str, code: int):
    """Tunnel counters of a host-hour (SPEC §7.3). One log line = one tunnel request: a whole
    WebSocket / HTTPUpgrade session or gRPC / h2 stream, or one XHTTP request.
    Bytes from the client: $request_length counts request bodies (HTTP/1.1 and HTTP/2) but not
    the frames of an upgraded connection; $upstream_bytes_sent counts everything written to the
    origin, including upgraded frames. Both include the request head, so the larger one is used."""
    t = a.setdefault("tunnel", {"sessions": 0, "seconds": 0.0, "bytes_up": 0, "bytes_down": 0, "by_protocol": {}})
    if code == 101 or 200 <= code < 300:
        t["sessions"] += 1
    try:
        t["seconds"] += max(0.0, float(e.get("rt") or 0))
    except (TypeError, ValueError):
        pass
    up = max(int(e.get("bu") or 0), _nsum(e.get("ub")))
    down = int(e.get("b") or 0)
    t["bytes_up"] += up
    t["bytes_down"] += down
    _inc(t["by_protocol"], proto, up + down)


def _consume(path: str, pos: int, state: dict, max_bytes: int) -> int:
    """Aggregate complete lines from path starting at pos; returns the new position."""
    with open(path, "rb") as f:
        f.seek(pos)
        chunk = f.read(max_bytes)
    end = chunk.rfind(b"\n")
    if end < 0:
        return pos
    pending = state.setdefault("pending", {})
    events = state.setdefault("events", [])
    for raw in chunk[: end + 1].splitlines():
        try:
            _account(json.loads(raw), pending, events)
        except (ValueError, KeyError, TypeError, AttributeError):
            continue
    return pos + end + 1


def read_usage(state: dict, log_path: str, max_bytes: int = 200 * 1024 * 1024) -> None:
    """Consume new access-log lines and merge them into state['pending'] / state['events']."""
    try:
        st = os.stat(log_path)
    except FileNotFoundError:
        return
    pending = state.setdefault("pending", {})
    pos = state.get("log_pos", 0)
    if state.get("log_inode") not in (None, st.st_ino):
        # logrotate moved the file: finish the old one (now .1) before starting the new one
        rotated = log_path + ".1"
        try:
            if os.stat(rotated).st_ino == state["log_inode"]:
                _consume(rotated, pos, state, max_bytes)
        except FileNotFoundError:
            pass
        pos = 0
    elif st.st_size < pos:
        pos = 0  # truncated
    state["log_pos"] = _consume(log_path, pos, state, max_bytes)
    state["log_inode"] = st.st_ino
    if len(pending) > 50000:  # controller unreachable for a long time: keep newest
        for k in sorted(pending, key=lambda k: k.split("|")[1])[: len(pending) - 50000]:
            del pending[k]
    events = state.get("events") or []
    if len(events) > EVENT_BACKLOG:
        del events[: len(events) - EVENT_BACKLOG]


def usage_item(key: str, a) -> dict:
    a = _bucket({key: a}, key)
    host, hour = key.split("|", 1)
    item = {"host": host, "hour": hour, "bytes": a["bytes"], "requests": a["requests"], "cache_hits": a["cache_hits"]}
    for k in ("status", "codes", "countries", "security"):
        if a[k]:
            item[k] = a[k]
    if a.get("tunnel"):
        t = a["tunnel"]
        item["tunnel"] = {"sessions": t["sessions"], "seconds": int(round(t["seconds"])), "bytes_up": t["bytes_up"],
                          "bytes_down": t["bytes_down"], "by_protocol": dict(t["by_protocol"])}
    if a["paths"]:
        item["paths"] = dict(sorted(a["paths"].items(), key=lambda kv: (-kv[1], kv[0]))[:PATHS_PER_ITEM])
    return item


def usage_items(pending: dict) -> list[dict]:
    return [usage_item(k, v) for k, v in pending.items()]


# ----------------------------------------------------------------- metrics (heartbeat, SPEC §7.4)

VIRTUAL_IFACES = re.compile(r"^(lo|docker|veth|br-|virbr|cni|flannel|cali|vxlan|tun|tap|wg|kube|dummy)")


def default_iface(route_path: str = "/proc/net/route") -> str | None:
    """Interface of the IPv4 default route (None when there is none)."""
    try:
        with open(route_path) as f:
            next(f, None)
            for line in f:
                p = line.split()
                if len(p) > 3 and p[1] == "00000000" and int(p[3], 16) & 1 and not VIRTUAL_IFACES.match(p[0]):
                    return p[0]
    except (OSError, ValueError):
        pass
    return None


def net_bytes(iface: str | None, dev_path: str = "/proc/net/dev") -> tuple[int, int] | None:
    """(rx, tx) bytes of iface, or of every non-virtual interface when iface is None."""
    rx = tx = 0
    found = False
    try:
        with open(dev_path) as f:
            for line in f:
                if ":" not in line:
                    continue
                name, data = line.split(":", 1)
                name, p = name.strip(), data.split()
                if (iface and name != iface) or (not iface and VIRTUAL_IFACES.match(name)) or len(p) < 9:
                    continue
                rx, tx, found = rx + int(p[0]), tx + int(p[8]), True
    except (OSError, ValueError):
        return None
    return (rx, tx) if found else None


def tcp_established(ports, paths=("/proc/net/tcp", "/proc/net/tcp6")) -> int | None:
    """ESTABLISHED TCP connections whose local port is one of `ports` (client connections)."""
    want = {f"{int(p):04X}" for p in ports}
    n, ok = 0, False
    for path in paths:
        try:
            with open(path) as f:
                ok = True
                next(f, None)
                for line in f:
                    p = line.split(None, 4)
                    if len(p) > 3 and p[3] == "01" and p[1].rsplit(":", 1)[-1] in want:
                        n += 1
        except (OSError, ValueError):
            continue
    return n if ok else None


def net_sample(cfg: dict) -> tuple[float, tuple[int, int] | None]:
    return time.monotonic(), net_bytes(default_iface(cfg.get("PROC_ROUTE", "/proc/net/route")),
                                       cfg.get("PROC_NET_DEV", "/proc/net/dev"))


def collect_metrics(cfg: dict, prev: tuple | None, cur: tuple | None = None) -> dict:
    """Heartbeat metrics from two net samples (see net_sample). Never raises; missing values are 0."""
    m = {"rx_mbps": 0.0, "tx_mbps": 0.0, "connections": 0, "load1": 0.0, "cpus": 0}
    try:
        cur = cur or net_sample(cfg)
        if prev and prev[1] and cur[1] and cur[0] > prev[0]:
            dt = cur[0] - prev[0]
            m["rx_mbps"] = round(max(0, cur[1][0] - prev[1][0]) * 8 / dt / 1e6, 3)  # counter reset -> 0
            m["tx_mbps"] = round(max(0, cur[1][1] - prev[1][1]) * 8 / dt / 1e6, 3)
    except Exception as e:  # noqa: BLE001
        log.debug("net metrics: %s", e)
    try:
        ports = {_int(cfg.get("HTTP_PORT"), 80, 1, 65535), _int(cfg.get("HTTPS_PORT"), 443, 1, 65535)}
        m["connections"] = tcp_established(ports, cfg.get("PROC_TCP", ("/proc/net/tcp", "/proc/net/tcp6"))) or 0
    except Exception as e:  # noqa: BLE001
        log.debug("connection count: %s", e)
    try:
        m["load1"] = round(os.getloadavg()[0], 2)
    except (OSError, AttributeError):
        pass
    m["cpus"] = os.cpu_count() or 0
    disk = disk_pct(cfg.get("CACHE_DIR") or cfg.get("NGINX_DIR") or "/")
    if disk is not None:
        m["disk_pct"] = disk
    mem = mem_pct(cfg.get("PROC_MEMINFO", "/proc/meminfo"))
    if mem is not None:
        m["mem_pct"] = mem
    return m


def disk_pct(path: str) -> float | None:
    """Percent of the filesystem holding `path` that is used. None on error."""
    try:
        st = os.statvfs(path)
        total = st.f_blocks * st.f_frsize
        if total <= 0:
            return None
        free = st.f_bavail * st.f_frsize
        return round((total - free) * 100 / total, 1)
    except OSError:
        return None


def mem_pct(meminfo: str = "/proc/meminfo") -> float | None:
    """Percent of RAM in use (total - available). None on error."""
    try:
        vals = {}
        with open(meminfo) as f:
            for line in f:
                k, _, rest = line.partition(":")
                if k in ("MemTotal", "MemAvailable"):
                    vals[k] = int(rest.split()[0])  # kB
        total, avail = vals.get("MemTotal", 0), vals.get("MemAvailable")
        if total <= 0 or avail is None:
            return None
        return round((total - avail) * 100 / total, 1)
    except (OSError, ValueError, IndexError):
        return None


# ----------------------------------------------------------------- controller

class Controller:
    def __init__(self, url: str, token: str):
        self.url = url.rstrip("/")
        self.token = token

    def call(self, method: str, path: str, body=None, headers=None, timeout=30):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.url + path, data=data, method=method)
        req.add_header("Authorization", f"Bearer {self.token}")
        req.add_header("User-Agent", "pcdn-agent/2.0")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw = r.read()
                return r.status, dict(r.headers), (json.loads(raw) if raw else None)
        except urllib.error.HTTPError as e:
            if e.code == 304:
                return 304, dict(e.headers), None
            raise


# ----------------------------------------------------------------- main loop

def load_state(path: str) -> dict:
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, ValueError):
        return {}


def save_state(path: str, state: dict):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f)
    os.replace(tmp, path)


class Agent:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.ctl = Controller(cfg["CONTROLLER_URL"], cfg["EDGE_TOKEN"])
        self.state = load_state(cfg["STATE_FILE"])
        self.running = True
        self.last_usage = 0.0
        self.last_heartbeat = 0.0
        self.net_prev = None

    def sync_config(self):
        headers = {}
        rev = render_rev(self.cfg)
        if self.state.get("etag") and os.path.isdir(self.cfg["NGINX_DIR"]) and self.state.get("render_rev") == rev:
            headers["If-None-Match"] = self.state["etag"]
        code, hdrs, body = self.ctl.call("GET", "/edge/v1/config", headers=headers)
        if code == 304:
            return
        err = apply_config(body, self.cfg)
        self.state["last_error"] = err
        if err:
            log.error(err)
            self.ctl.call("POST", "/edge/v1/heartbeat",
                          {"applied_version": self.state.get("version"), "error": err})
            return
        self.state["etag"] = hdrs.get("ETag") or hdrs.get("etag")
        self.state["version"] = body["version"]
        self.state["render_rev"] = rev
        log.info("applied config %s (%d sites)", body["version"][:12], len(body.get("sites", [])))
        self.ctl.call("POST", "/edge/v1/heartbeat", {"applied_version": body["version"], "error": None})

    def sync_purges(self):
        after = int(self.state.get("purge_id", 0))
        _, _, items = self.ctl.call("GET", f"/edge/v1/purges?after={after}")
        if "purge_id" not in self.state:
            # first run: a fresh node has an empty cache, so skip history and remember where we are
            self.state["purge_id"] = items[-1]["id"] if items else 0
            return
        for it in items or []:
            n = do_purge(it, self.cfg)
            what = "ALL" if it.get("everything") else (it["urls"] or it.get("prefixes") or "ALL")
            log.info("purge %s %s -> %d entries", it["domain"], what, n)
            self.state["purge_id"] = it["id"]

    def push_usage(self):
        read_usage(self.state, self.cfg["ACCESS_LOG"])
        pending = self.state.setdefault("pending", {})
        events = self.state.setdefault("events", [])
        keys = list(pending)
        # batches respect the controller limits; anything not acknowledged stays for the next try
        while keys or events:
            batch, keys = keys[:MAX_ITEMS], keys[MAX_ITEMS:]
            evs = events[:MAX_EVENTS]
            body = {"items": [usage_item(k, pending[k]) for k in batch]}
            if evs:
                body["events"] = evs
            self.ctl.call("POST", "/edge/v1/usage", body)
            for k in batch:
                del pending[k]
            del events[: len(evs)]

    def metrics(self) -> dict:
        """Current load; the first call measures the network rate over one second."""
        try:
            if self.net_prev is None or time.monotonic() - self.net_prev[0] < 1:
                self.net_prev = net_sample(self.cfg)
                time.sleep(1)
            cur = net_sample(self.cfg)
        except Exception:  # noqa: BLE001
            cur = None
        m = collect_metrics(self.cfg, self.net_prev, cur)
        if cur:
            self.net_prev = cur
        return m

    def heartbeat(self):
        """Periodic heartbeat with load metrics (keeps applied_version / last error as reported)."""
        self.ctl.call("POST", "/edge/v1/heartbeat", {"applied_version": self.state.get("version"),
                                                     "error": self.state.get("last_error"),
                                                     "metrics": self.metrics()})

    def tick(self):
        for step in (self.sync_config, self.sync_purges):
            try:
                step()
            except Exception as e:  # noqa: BLE001
                log.error("%s failed: %s", step.__name__, e)
        if time.time() - self.last_heartbeat >= int(self.cfg.get("HEARTBEAT_INTERVAL") or 60):
            try:
                self.heartbeat()
                self.last_heartbeat = time.time()
            except Exception as e:  # noqa: BLE001
                log.error("heartbeat failed: %s", e)
        if time.time() - self.last_usage >= int(self.cfg["USAGE_INTERVAL"]):
            try:
                self.push_usage()
                self.last_usage = time.time()
            except Exception as e:  # noqa: BLE001 - pending usage stays in state for next try
                log.error("usage push failed: %s", e)
        save_state(self.cfg["STATE_FILE"], self.state)

    def loop(self):
        while self.running:
            self.tick()
            for _ in range(int(self.cfg["POLL_INTERVAL"])):
                if not self.running:
                    break
                time.sleep(1)


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    cfg = load_config(os.getenv("PCDN_CONFIG", "/etc/pcdn/agent.conf"))
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "bootstrap":
        bootstrap(cfg)
        return
    if not cfg["CONTROLLER_URL"] or not cfg["EDGE_TOKEN"]:
        log.error("CONTROLLER_URL and EDGE_TOKEN must be set in /etc/pcdn/agent.conf")
        sys.exit(1)
    agent = Agent(cfg)

    def stop(*_):
        agent.running = False

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    if cmd == "once":
        agent.tick()
        return
    agent.loop()


if __name__ == "__main__":
    main()
