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

import collections
import hashlib
import ipaddress
import json
import logging
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone

log = logging.getLogger("pcdn-agent")
HERE = os.path.dirname(os.path.abspath(__file__))


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class LogBuffer(logging.Handler):
    """Keeps the agent's own recent WARNING+ records so they can be shipped to the controller
    with the nginx error log (SPEC §11.2). Bounded; never raises into the caller."""

    def __init__(self, maxlen: int = 200):
        super().__init__(level=logging.WARNING)
        self.records: collections.deque = collections.deque(maxlen=maxlen)

    def emit(self, record: logging.LogRecord) -> None:
        try:
            level = {"WARNING": "warn", "ERROR": "error", "CRITICAL": "crit"}.get(record.levelname, "warn")
            self.records.append({"t": _now_iso(), "level": level, "msg": record.getMessage()})
        except Exception:  # noqa: BLE001 - logging must never crash the agent
            pass

    def drain(self) -> list:
        out = list(self.records)
        self.records.clear()
        return out


AGENT_LOGS = LogBuffer()

DEFAULTS = {
    "CONTROLLER_URL": "",
    "EDGE_TOKEN": "",
    "NGINX_DIR": "/etc/nginx/pcdn",
    "CACHE_DIR": "/var/cache/pcdn",
    "STATE_FILE": "/var/lib/pcdn/state.json",
    "ACCESS_LOG": "/var/log/nginx/pcdn-access.log",
    # centralized node logs (SPEC §11.2): the nginx error log the agent tails for WARN/ERROR/crit
    "ERROR_LOG": "/var/log/nginx/error.log",
    # running bundle version file written by bootstrap.sh; reported in the heartbeat (SPEC §11.1)
    "BUNDLE_VERSION_FILE": "/etc/pcdn/bundle.version",
    # region / role (edge group): reported on first heartbeat so a fresh node self-registers
    "REGION": "",
    "GROUP": "",
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
    # F3: per-stream client body buffer for HTTP/2 tunnel uploads (gRPC/h2/XHTTP). The default h2
    # window is 64k; this raises in-flight upload capacity per stream. Cost ~= concurrent streams ×
    # size, so install.sh --role tunnel can raise it and low-RAM nodes should lower it to 128k.
    "TUNNEL_H2_BODY_BUFFER": "256k",
    # F14: relay buffer for the tunnel data path (proxy_buffer_size / grpc_buffer_size /
    # http2_chunk_size) and the ssl_buffer_size on pure-tunnel (decoy/404) hosts.
    "TUNNEL_RELAY_BUFFER": "16k",
    # F14: http-level ssl_buffer_size; install.sh sets 16k on --role tunnel nodes, 4k elsewhere for
    # faster TLS first byte on general web traffic.
    "SSL_BUFFER_SIZE": "4k",
    # F12: connect timeout for both proxy_pass and grpc_pass tunnel origins (seconds, 3-30).
    "TUNNEL_CONNECT_TIMEOUT": "10",
    # N2/F27: client-facing HTTP/2 stream cap per connection on tunnel hosts (a low value forces a
    # mid-session GOAWAY + reconnect for stream-heavy XHTTP/gRPC tunnels).
    "TUNNEL_KEEPALIVE_REQUESTS": "10000000",
    # F5: reload coalescing. A config version is applied only once it has settled (seen on two polls)
    # or has been pending for RELOAD_MIN_INTERVAL, and never more often than RELOAD_MIN_INTERVAL,
    # so a burst of site edits collapses into one nginx reload (one GOAWAY to all h2 tunnels).
    "RELOAD_MIN_INTERVAL": "120",
    # F5: a freshly-seen version waits at least this long before applying, so sub-debounce bursts of
    # different versions coalesce.
    "RELOAD_DEBOUNCE": "5",
    # F29: seconds the agent polls /__pcdn/confver after a reload before treating it as not applied.
    "RELOAD_VERIFY": "yes",
    # F7: usage POST timeout (seconds); strictly greater than Caddy's 120 s header timeout so the
    # agent never gives up just as the controller responds and replays a batch.
    "USAGE_TIMEOUT": "150",
    # F7: drop (and log) an unacknowledged usage batch older than this many days, comfortably inside
    # the controller's 7-day batch_id dedup window, so a stuck batch cannot be re-applied after its
    # dedup row is purged.
    "USAGE_OUTBOX_MAX_DAYS": "6",
    # F21: defer a reload up to this many seconds when every changed site belongs to another edge
    # group (and no global file changed and no site was added/removed/suspended or had its cert
    # rotated), so a tunnel-role node does not reload for general-website edits.
    "FOREIGN_DEFER": "900",
    # SPEC §14.1: nginx binary probed once per agent start with `-V` (version, --with-http_v3_module,
    # modules path) and the directory whose module .so files decide which optional directives
    # (geoip2, brotli, njs, image_filter) are rendered. Empty = the --modules-path nginx reports.
    "NGINX_BIN": "nginx",
    "NGINX_MODULES_DIR": "",
    # origin shield hop port on the shield peers (empty = this node's HTTPS_PORT); hops are TLS only
    "SHIELD_HTTPS_PORT": "",
    # TCP congestion control written by install.sh --cc (informational for the agent)
    "TCP_CC": "bbr",
    # SPEC §14.3.2 log export: sampled access-log records of sites with logs.enabled are spooled
    # here (0700 dir, 0600 files; empty = "logship" next to STATE_FILE) and POSTed to
    # /edge/v1/logship. The spool is capped (oldest batches dropped beyond it, counted) so a long
    # controller outage can never fill the disk.
    "LOGSHIP_SPOOL_DIR": "",
    "LOGSHIP_SPOOL_MAX_MB": "256",
    # seconds between shipping runs (own cadence, after config / purges / usage in the same loop)
    "LOGSHIP_INTERVAL": "30",
    # per-POST timeout (seconds); a run starts no new POST after LOGSHIP_RUN_BUDGET seconds
    "LOGSHIP_TIMEOUT": "30",
    # SPEC §15.2 tunnel fair share / §15.6 speed test. The controller's node block
    # ({"node": {"capacity_mbps", "fair_share_pct", "name"}}) wins; these are the fallbacks.
    # CAPACITY_MBPS 0 = unknown: the node is never "hot" and fair share never refuses anything.
    "CAPACITY_MBPS": "0",
    "FAIR_SHARE_PCT": "25",
    # node name hashed into the speed-test X-Pcdn-Node header (empty = the system host name)
    "NODE_NAME": "",
    # SPEC §15.6 speed-test random file (10 MiB + 64 B, written once; empty = speed.bin next to STATE_FILE)
    "SPEED_FILE": "",
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
               "transfer-encoding", "upgrade", "host", "content-length",
               "x-pcdn-shield"}  # SPEC §14.1: the shield hop header is reserved for the edge itself
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


def geoip_present(cfg: dict) -> bool:
    """True when the GeoIP country database is installed AND the geoip2 module is available (F9,
    SPEC §14.1): tunnel allowed_countries only enforces when it is, and fails open (allow) when
    either is missing (e.g. an nginx.org build without geoip2)."""
    geo = cfg.get("GEOIP_DB") or ""
    return bool(SAFE_FSPATH.match(geo) and os.path.isfile(geo)) and has_module(cfg, "geoip2")


# ----------------------------------------------------------------- nginx capabilities (SPEC §14.1)

# optional dynamic modules the rendered config can use -> their .so file in the modules directory
MODULE_FILES = {"njs": "ngx_http_js_module.so", "geoip2": "ngx_http_geoip2_module.so",
                "image_filter": "ngx_http_image_filter_module.so", "brotli": "ngx_http_brotli_filter_module.so"}
# statically compiled variants, recognised in `nginx -V` configure arguments
_STATIC_MODULE = {"njs": re.compile(r"--add-module=\S*njs"), "geoip2": re.compile(r"--add-module=\S*geoip2"),
                  "brotli": re.compile(r"--add-module=\S*brotli"),
                  "image_filter": re.compile(r"--with-http_image_filter_module(?!=dynamic)(?:\s|$)")}
# WebP for image.auto_webp: ngx_http_image_filter_module always writes the INPUT format (JPEG in ->
# JPEG out, PNG in -> PNG out; WebP is only produced from WebP input), so no stock nginx can convert
# JPEG/PNG to WebP and webp_convert is always False. The edge therefore uses the "accept_key" mode:
# the cache key carries the client's WebP capability for JPEG/PNG URIs, Accept is passed through to
# origins that negotiate formats, and those responses get "Vary: Accept" (see pcdn-base.conf).
WEBP_MODE = "accept_key"
# what an undetectable nginx is assumed to be: today's distro build (Ubuntu 1.24 + all modules)
LEGACY_CAPS = {"nginx": None, "http3": False, "early_hints": False, "http2_directive": False,
               "webp_convert": False, "webp_mode": WEBP_MODE, "modules": sorted(MODULE_FILES), "flv": True}
_CAPS_CACHE: dict = {}


def _version(text: str) -> tuple:
    m = re.search(r"nginx version: [^/\s]*/(\d+)\.(\d+)\.(\d+)", text or "")
    return tuple(int(x) for x in m.groups()) if m else ()


def parse_nginx_v(text: str, modules_dir: str | None = None, exists=os.path.isfile) -> dict:
    """Capabilities from `nginx -V` output (stderr). http3 needs --with-http_v3_module and nginx
    >= 1.25.1 (`listen ... quic` 1.25.0, `http3` directive 1.25.1); early_hints needs >= 1.29.0
    (`early_hints` directive, ngx_http_core_module). modules: optional modules compiled in or whose
    .so is present in the modules directory (install.sh writes a load_module line for each)."""
    ver = _version(text)
    if not ver:
        return dict(LEGACY_CAPS, modules=list(LEGACY_CAPS["modules"]))
    args = ""
    for line in text.splitlines():
        if line.startswith("configure arguments:"):
            args = line.split(":", 1)[1]
    mdir = modules_dir
    if not mdir:
        m = re.search(r"--modules-path=(\S+)", args)
        if m:
            mdir = m.group(1).strip("'\"")
        else:
            m = re.search(r"--prefix=(\S+)", args)
            mdir = os.path.join(m.group(1).strip("'\"") if m else "/usr/local/nginx", "modules")
    mods = sorted(name for name, so in MODULE_FILES.items()
                  if _STATIC_MODULE[name].search(args) or exists(os.path.join(mdir, so)))
    v3 = bool(re.search(r"(?:^|\s)--with-http_v3_module(?:\s|$)", args))
    return {"nginx": ".".join(str(x) for x in ver), "http3": v3 and ver >= (1, 25, 1),
            "early_hints": ver >= (1, 29, 0), "http2_directive": ver >= (1, 25, 1),
            "webp_convert": False, "webp_mode": WEBP_MODE, "modules": mods,
            # SPEC §15.6: the speed-test download is served through the (static) flv module
            "flv": bool(re.search(r"(?:^|\s)--with-http_flv_module(?:\s|$)", args))}


def nginx_capabilities(cfg: dict) -> dict:
    """Probe `nginx -V` once per agent start (cached per binary/modules dir). A test or an operator
    tool may pass a ready dict as cfg["NGINX_CAPS"]. When nginx cannot be probed, the legacy distro
    build is assumed so rendering stays exactly as before."""
    caps = cfg.get("NGINX_CAPS")
    if isinstance(caps, dict):
        return dict(LEGACY_CAPS, **caps)
    binary = cfg.get("NGINX_BIN") or "nginx"
    key = (binary, cfg.get("NGINX_MODULES_DIR") or "")
    if key not in _CAPS_CACHE:
        try:
            p = subprocess.run([binary, "-V"], capture_output=True, text=True, timeout=15)
            text = (p.stdout or "") + (p.stderr or "")
        except (OSError, subprocess.SubprocessError, ValueError):
            text = ""
        _CAPS_CACHE[key] = parse_nginx_v(text, cfg.get("NGINX_MODULES_DIR") or None)
    return dict(_CAPS_CACHE[key])


def has_module(cfg: dict, name: str) -> bool:
    return name in nginx_capabilities(cfg)["modules"]


def heartbeat_capabilities(cfg: dict) -> dict:
    """The `capabilities` object of the heartbeat (SPEC §14.1)."""
    c = nginx_capabilities(cfg)
    return {"http3": bool(c["http3"]), "early_hints": bool(c["early_hints"]),
            "webp_convert": bool(c["webp_convert"]), "webp_mode": c["webp_mode"],
            "modules": list(c["modules"]), "nginx": c["nginx"],
            "waf_packs": dict(WAF_PACK_VERSIONS),   # SPEC §14.2 managed rule-set versions
            # SPEC §14.3: this agent sends 1-minute `live` aggregates + platform_errors with its usage
            # and ships sampled access-log records to /edge/v1/logship
            "live_analytics": True, "logship": True}


_GUARD = re.compile(r"^# @if (\w+)\n(.*?)(?:^# @else \1\n(.*?))?^# @endif \1\n", re.S | re.M)


def module_blocks(text: str, modules) -> str:
    """Resolve the template's "# @if <module>" / "# @else" / "# @endif" blocks (SPEC §14.1)."""
    def sub(m):
        return m.group(2) if m.group(1) in modules else (m.group(3) or "")
    prev = None
    while prev != text:   # nested guards resolve from the inside out
        prev, text = text, _GUARD.sub(sub, text)
    return text


# ----------------------------------------------------------------- origin shield (SPEC §14.1)

SAFE_SHIELD_SECRET = re.compile(r"^[0-9a-fA-F]{16,256}$")
SHIELD_MAX_PEERS = 64


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


def norm_shield(config: dict) -> dict | None:
    """Node-wide `shield` section {self, peers, secret}; None when unusable (no valid secret, or
    neither a shield itself nor any peer to send misses to). Missing -> today's behaviour."""
    sh = config.get("shield") if isinstance(config, dict) else None
    if not isinstance(sh, dict):
        return None
    secret = str(sh.get("secret") or "")
    if not SAFE_SHIELD_SECRET.match(secret):
        return None
    is_self = sh.get("self") is True
    peers = sorted({p for p in (_ip_literal(x) for x in (sh.get("peers") or []) if isinstance(x, str)) if p})
    peers = peers[:SHIELD_MAX_PEERS]
    if not is_self and not peers:
        return None
    # a shield never re-shields: its own misses always go to the origin
    return {"self": is_self, "peers": [] if is_self else peers, "secret": secret.lower()}


def render_shield(shield: dict | None, cfg: dict) -> str | None:
    """shield.conf (0600: it holds the shared secret). Shield nodes get the maps that accept a valid
    X-Pcdn-Shield hop; other nodes get the peer upstream (consistent hash on the request's cache key,
    $pcdn_ck) plus the header value they send. None when the node takes no part in shielding.
    The secret is fleet-wide and a valid hop skips the verdict / rate limits, so it only ever travels
    over TLS: edges shield only sites with a certificate (verified TLS hop) and a shield accepts the
    header only on a TLS connection ($https = on); over plain HTTP it is an ordinary visitor."""
    if not shield:
        return None
    sec = shield["secret"]
    out = ["# origin shield (SPEC §14.1) — generated by pcdn-agent, do not edit"]
    if shield["self"]:
        out += [
            "# a valid X-Pcdn-Shield received over TLS marks a cache miss forwarded by another edge;",
            "# anything else (no / wrong header, or any header over plain HTTP) is an ordinary visitor",
            f"map \"$https:$http_x_pcdn_shield\" $pcdn_shield_ok {{\n    default 0;\n    \"on:{sec}\" 1;\n}}",
            "# shield hops skip the security verdict (the visitor-facing edge already ran it) ...",
            "map $pcdn_shield_ok $pcdn_gate {\n    1       ok;\n    default $pcdn_verdict;\n}",
            "# ... keep the visitor's address / country / scheme the edge forwarded ...",
            "map $pcdn_shield_ok $pcdn_client_ip {\n    1       $http_x_real_ip;\n    default $remote_addr;\n}",
            "map $pcdn_shield_ok $pcdn_xff {\n    1       $http_x_forwarded_for;\n"
            "    default $proxy_add_x_forwarded_for;\n}",
            "map $pcdn_shield_ok $pcdn_cc {\n    1       $http_x_country_code;\n    default $pcdn_country;\n}",
            "map \"$pcdn_shield_ok:$http_x_forwarded_proto\" $pcdn_scheme {\n    \"1:https\" https;\n"
            "    \"1:http\"  http;\n    default   $scheme;\n}",
            "# ... and are not logged (usage is billed once, at the visitor-facing edge)",
            "map $pcdn_shield_ok $pcdn_log_ok {\n    1       0;\n    default 1;\n}",
        ]
        return "\n".join(out) + "\n"
    sp = _int(cfg.get("SHIELD_HTTPS_PORT") or cfg.get("HTTPS_PORT"), 443, 1, 65535)
    out += [
        "map $uri $pcdn_shield_ok {\n    default 0;\n}",
        "# cache key of the current request (set by each shielded location): every edge sends a given",
        "# object to the same shield, so it is fetched from the origin once",
        "map $uri $pcdn_ck {\n    default \"\";\n}",
        "# only GET/HEAD are shielded; other methods go straight to the origin (never replayed)",
        "map $request_method $pcdn_sh_skip {\n    GET     \"\";\n    HEAD    \"\";\n    default 1;\n}",
        f"geo $pcdn_shield_secret {{\n    default \"{sec}\";\n}}",
    ]
    servers = "".join(f"    server {p}:{sp} max_fails=1 fail_timeout=10s;\n" for p in shield["peers"])
    out.append(f"upstream pcdn_shield_https {{\n    hash $pcdn_ck consistent;\n{servers}"
               f"    keepalive 32;\n    keepalive_timeout 60s;\n}}")
    return "\n".join(out) + "\n"


# ----------------------------------------------------------------- rendering

FAIR_HOT_PCT = 85      # SPEC §15.2: the node is "hot" at >= 85 % of its capacity (tx_mbps) ...
FAIR_COOL_PCT = 80     # ... and stays hot until it drops below 80 % (hysteresis, no flapping)


def fair_hot(tx_mbps: float, capacity_mbps: int, was_hot: bool) -> bool:
    """SPEC §15.2 node "hot" state with hysteresis; never hot without a known capacity."""
    if capacity_mbps <= 0:
        return False
    pct = float(tx_mbps) * 100 / capacity_mbps
    return pct >= FAIR_HOT_PCT or (was_hot and pct >= FAIR_COOL_PCT)


def norm_node(config: dict, cfg: dict) -> dict:
    """Node-wide block of the edge config (SPEC §15.2): {"capacity_mbps", "fair_share_pct", "name"}.
    Every key is optional; agent.conf CAPACITY_MBPS / FAIR_SHARE_PCT / NODE_NAME are the fallbacks
    (capacity 0 = unknown: the node is never considered hot, fair share stays idle)."""
    n = config.get("node") if isinstance(config.get("node"), dict) else {}
    name = str(n.get("name") or cfg.get("NODE_NAME") or "").strip()
    if not name:
        try:
            name = socket.gethostname()
        except OSError:
            name = ""
    # the controller sends capacity_mbps 0 for "unknown": the agent.conf value (if any) applies then
    cap = _int(n.get("capacity_mbps"), 0, 0, 10_000_000) or _int(cfg.get("CAPACITY_MBPS"), 0, 0, 10_000_000)
    return {"capacity_mbps": cap,
            "fair_share_pct": _int(n.get("fair_share_pct", cfg.get("FAIR_SHARE_PCT")), 25, 1, 100),
            "name": name[:253]}


def node_tag(name: str) -> str:
    """Speed-test X-Pcdn-Node value (SPEC §15.6): 8 hex chars of a hash of the node NAME. It tells a
    customer whether two measurements hit the same node; it is never an address and cannot be used
    to pick or reach a node."""
    return hashlib.sha256(("pcdn-node|" + name).encode()).hexdigest()[:8]


def render_http(cfg: dict, hc_interval: int = 2, shield: dict | None = None, bots: bool = False,
                mtls: bool = False, node: dict | None = None) -> str:
    """The base http-context config (from the template), see nginx/pcdn-base.conf.
    hc_interval: js_periodic tick for pool health checks (> the largest check timeout).
    shield: the node's normalised shield section (norm_shield) or None.
    bots / mtls: bots.conf / mtls.conf were rendered and are included (SPEC §14.2).
    node: the normalised node block (norm_node); its name feeds the speed-test X-Pcdn-Node tag."""
    with open(asset(cfg, "BASE_TEMPLATE", "nginx/pcdn-base.conf")) as f:
        text = f.read()
    caps = nginx_capabilities(cfg)
    text = module_blocks(text, caps["modules"])
    if geoip_present(cfg):
        geo = cfg["GEOIP_DB"]
        geo_conf = f"geoip2 {geo} {{\n    auto_reload 60m;\n    $pcdn_country country iso_code;\n}}"
    else:  # nginx must start without the database (or module); country rules then never match
        geo_conf = "map $host $pcdn_country {\n    default \"\";\n}"
    sport = str(_int(cfg["HTTPS_PORT"], 443, 1, 65535))
    extra = []
    if caps["http2_directive"]:
        extra.append("    http2 on;")
    if caps["http3"]:
        # one `quic reuseport` per address (on the default server); site servers add plain `quic`
        extra += [f"    listen {sport} quic default_server reuseport;",
                  f"    listen [::]:{sport} quic default_server reuseport;"]
    if caps["early_hints"]:
        # SPEC §14.1: pass 103 Early Hints to HTTP/2+ navigations only (HTTP/1.1 clients and
        # intermediaries are known to mishandle 1xx); used by sites with preload page rules
        eh = "$http2$http3" if caps["http3"] else "$http2"
        eh_conf = f"map $http_sec_fetch_mode $pcdn_early_hints {{\n    default \"\";\n    navigate {eh};\n}}"
    else:
        eh_conf = ""
    if shield:
        shield_conf = f"include {cfg['NGINX_DIR'].rstrip('/')}/shield.conf;"
    else:
        shield_conf = "map $uri $pcdn_shield_ok {\n    default 0;\n}"
    # no verified crawler ranges (or no site using bot management): "" = crawler UAs fail open
    bots_conf = (f"include {cfg['NGINX_DIR'].rstrip('/')}/bots.conf;" if bots
                 else "geo $pcdn_vbot {\n    default \"\";\n}")
    mtls_conf = (f"include {cfg['NGINX_DIR'].rstrip('/')}/mtls.conf;" if mtls
                 else "map $uri $pcdn_mtls_crt {\n    default \"\";\n}\nmap $uri $pcdn_mtls_key {\n    default \"\";\n}")
    subst = {
        "NGINX_DIR": cfg["NGINX_DIR"].rstrip("/"),
        "HTTP_PORT": str(_int(cfg["HTTP_PORT"], 80, 1, 65535)),
        "HTTPS_PORT": str(_int(cfg["HTTPS_PORT"], 443, 1, 65535)),
        "RESIZE_PORT": str(_int(cfg["RESIZE_PORT"], 8089, 1, 65535)),
        "RESOLVER": cfg["RESOLVER"] if SAFE_RESOLVER.match(cfg["RESOLVER"]) else "1.1.1.1",
        "DICT_SIZE": cfg["DICT_SIZE"] if SAFE_SIZE.match(cfg["DICT_SIZE"]) else "32m",
        "GEOIP": geo_conf,
        "HC_INTERVAL": str(_int(hc_interval, 2, 2, 11)),
        "CONNECT_TIMEOUT": str(_int(cfg.get("TUNNEL_CONNECT_TIMEOUT"), 10, 3, 30)),
        "SSL_BUFFER_SIZE": cfg["SSL_BUFFER_SIZE"] if SAFE_SIZE.match(cfg.get("SSL_BUFFER_SIZE") or "") else "4k",
        "SHIELD": shield_conf,
        "BOTS": bots_conf,
        "MTLS": mtls_conf,
        "EARLY_HINTS": eh_conf,
        "LISTEN_H2": "" if caps["http2_directive"] else " http2",
        "HTTPS_DEFAULT_EXTRA": "\n".join(extra),
        "NODE_TAG": node_tag((node or norm_node({}, cfg))["name"]),
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
        # SPEC §15.2 fair share (default on; only `false` turns it off)
        "fair_share": t.get("fair_share", True) is not False,
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


PRELOAD_AS = ("script", "style", "image", "font", "fetch")
PRELOAD_MAX = 10
# same-site path or absolute http(s) URL (no protocol-relative "//host"); printable ASCII without
# space (so no CR/LF either)
SAFE_PRELOAD_URL = re.compile(r"^(?:https?://[A-Za-z0-9.-]+(?::\d{1,5})?)?/(?!/)[\x21-\x7e]{0,1000}$")
PRELOAD_BAD = set("\"'<>\\`")


def preload_links(rule: dict) -> list[str]:
    """Validated `Link` values of a page rule's `preload` list (SPEC §14.1), re-checked on the edge:
    quotes, CR/LF, whitespace and <> are rejected (they could break out of the header or the
    nginx string); `$` is kept literal by _qv at render time."""
    out = []
    pre = rule.get("preload")
    for p in (pre if isinstance(pre, list) else [])[:PRELOAD_MAX]:
        if not isinstance(p, dict):
            continue
        url, kind = str(p.get("url") or ""), p.get("as")
        if kind not in PRELOAD_AS or not SAFE_PRELOAD_URL.match(url) or PRELOAD_BAD & set(url):
            continue
        # fonts are always fetched in CORS mode; without `crossorigin` the preload is wasted
        out.append(f"<{url}>; rel=preload; as={kind}" + ("; crossorigin" if kind == "font" else ""))
    return list(dict.fromkeys(out))


SAFE_KEY_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")             # cookie names
SAFE_QUERY_NAME = re.compile(r"^[A-Za-z0-9_.\[\]-]{1,64}$")     # query parameter names ("f[x]")
NGX_VAR_NAME = re.compile(r"^[A-Za-z0-9_]{1,64}$")
KEY_COOKIES_MAX, KEY_QUERY_MAX = 10, 50


def key_options(site: dict) -> dict:
    """Cache-key options of a site (SPEC §14.1), validated again on the edge. Names must be cookie /
    query-parameter tokens; ones that are not valid nginx variable suffixes ("wp-lang") are read
    through a per-site regex map instead of $cookie_<name> / $arg_<name>. image.auto_webp is
    independent of the resize toggle; the plan's image_optimization gate is folded in by the
    controller (it sends auto_webp=false when the feature is off)."""
    cache, _ = _legacy_sections(site)

    def names(v, cap, rx):
        return list(dict.fromkeys(x for x in (v if isinstance(v, list) else [])
                                  if isinstance(x, str) and rx.match(x)))[:cap]
    return {"dev": cache.get("key_device") is True,
            "cookies": names(cache.get("key_cookies"), KEY_COOKIES_MAX, SAFE_KEY_NAME),
            "qa": names(cache.get("key_query_allow"), KEY_QUERY_MAX, SAFE_QUERY_NAME),
            "webp": _sec(site, "image").get("auto_webp") is True}


def key_infos(config: dict) -> dict:
    """Per-site cache-key shape for exact-URL purges ({site_id: options}); only sites whose key is
    not the plain "<scheme>://<host><uri>" are listed."""
    out = {}
    for s in config.get("sites", []) if isinstance(config, dict) else []:
        try:
            k = key_options(s)
            sid = str(int(s["id"]))
        except (KeyError, TypeError, ValueError):
            continue
        if k["dev"] or k["cookies"] or k["qa"] or k["webp"]:
            out[sid] = k
    return out


# ----------------------------------------------------------------- rules & security (SPEC §14.2)
# Everything below is validated again on the edge (the controller already did): a value that does
# not pass is dropped, never "fixed", and a rule whose condition cannot be understood is skipped as
# a whole (a broken condition must never widen what a rule applies to).

WAF_PACKS = ("generic", "wordpress", "joomla", "drupal", "laravel", "api")
# rule-set versions of the managed packs shipped in njs/pcdn.js (WAF_PACK_VERSION there; a unit
# test keeps both in sync), reported in the heartbeat capabilities
WAF_PACK_VERSIONS = {"generic": 1, "wordpress": 1, "joomla": 1, "drupal": 1, "laravel": 1, "api": 1}
BOT_MODES = ("log", "challenge", "block")
BODY_CAP = 131072   # request bodies inspected by the WAF packs (njs BODY_CAP)
BOT_ENGINES = (("google", "1", "g"), ("bing", "2", "b"))   # name, $pcdn_vbot value, "known" flag
BOT_MIN_PREFIX = {4: 16, 6: 32}   # anything broader is not a crawler range (tampered / bogus list)
BOT_MAX_PREFIXES = 2000
REDIRECT_CODES = (301, 302, 307, 308)
TF_MAX_RULES, TF_MAX_ACTIONS, REDIRECT_MAX = 1000, 10, 10000
# header names a transform rule may never touch (mirrors the controller's TRANSFORM_RESERVED):
# hop-by-hop / framing, the visitor-address chain the edge sets, and every internal X-Pcdn-* header
TF_RESERVED = HOP_HEADERS | {"x-real-ip", "forwarded", "trailers"}
TF_RESERVED_PREFIX = ("x-pcdn-", "x-forwarded-", "proxy-")
TF_REMOVE_ONLY = {"cookie", "set-cookie"}
SAFE_TF_VALUE = re.compile(r"^[\x20-\x7e]{1,1024}$")
# redirect source (exact / prefix): a raw request path as the controller normalises it (percent-encoded)
SAFE_REDIRECT_SOURCE = re.compile(r"^/[A-Za-z0-9\-._~!&'()*+,;=:@/%]{0,1023}$")
# redirect target / rewrite replacement characters: RFC 3986 unreserved + reserved + "%" and "$"
# (only as $1..$9). Double quotes, backslashes, whitespace, CR/LF, <> and backticks never pass.
URL_CHARS = re.compile(r"^[A-Za-z0-9\-._~!&'()*+,;=:@/?#\[\]%$]*$")
REDIRECT_ABS = re.compile(r"^https?://[A-Za-z0-9.-]{1,253}(?::\d{1,5})?(?=[/?#]|$)")
SAFE_REWRITE = re.compile(r"^/(?!/)[A-Za-z0-9\-._~!$&'()*+,;=:@/?%]{0,1023}$")
# map_hash_bucket_size is 128: longer exact redirect sources are matched by an anchored regex instead
REDIRECT_HASH_MAX_KEY = 96


def _qre(s: str) -> str:
    """A regex (or other text without `$` interpolation concerns) as a double-quoted nginx token:
    nginx un-escapes \\\\ and \\" inside quotes, so both are escaped."""
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _hvar(name: str) -> str:
    """nginx variable of a request header ($http_x_foo for X-Foo)."""
    return "$http_" + name.lower().replace("-", "_")


def pcre_regex(src, max_len: int = 512):
    """A customer regex that PCRE (nginx) will run: printable ASCII, compiles in Python, and none of
    the Python-only syntax PCRE rejects (\\N \\u \\U \\l \\L escapes, inline flags other than imsx).
    Returns the compiled Python pattern (for its group count) or None."""
    if not isinstance(src, str) or not 0 < len(src) <= max_len or not re.match(r"^[\x20-\x7e]+$", src):
        return None
    if re.search(r"\\[NuUlL]", src):
        return None
    for m in re.finditer(r"\(\?([A-Za-z-]+)[:)]", src):
        if set(m.group(1)) - set("imsx-"):
            return None
    try:
        return re.compile(src)
    except (re.error, RecursionError, OverflowError, ValueError):
        return None


def _refs_ok(text: str, groups: int | None) -> bool:
    """`$` only as $1..$9 naming an existing group (groups None: no `$` at all)."""
    for m in re.finditer(r"\$(\d?)(\d?)", text):
        if groups is None or not m.group(1) or m.group(1) == "0" or m.group(2) or int(m.group(1)) > groups:
            return False
    return True


def _under(path: str, prefixes) -> bool:
    return any(path.startswith(p) for p in prefixes)


def norm_redirects(site: dict, tunnel_prefixes=()) -> list[dict]:
    """Validated `redirects.rules` in order: {id, match, source, target, status, preserve_query,
    groups (regex only), re (compiled, regex only)}. Exact / prefix sources inside /__pcdn/ or a
    tunnel path are dropped (those paths are never redirected)."""
    out = []
    for r in (_sec(site, "redirects").get("rules") or [])[:REDIRECT_MAX]:
        if not isinstance(r, dict) or r.get("enabled") is False:
            continue
        rid, match, status = str(r.get("id") or "").lower(), r.get("match") or "exact", r.get("status")
        src, target = r.get("source"), r.get("target")
        if (not SAFE_ID.match(rid) or match not in ("exact", "prefix", "regex") or status not in REDIRECT_CODES
                or isinstance(status, bool) or not isinstance(src, str) or not isinstance(target, str)):
            continue
        groups, rx = None, None
        if match == "regex":
            rx = pcre_regex(src)
            if rx is None:
                continue
            groups = rx.groups
        elif (not SAFE_REDIRECT_SOURCE.match(src) or src.lower().startswith("/__pcdn")
              or _under(src, tunnel_prefixes)):
            continue
        if (not target or len(target) > 2048 or not URL_CHARS.match(target) or not _refs_ok(target, groups)
                or not (REDIRECT_ABS.match(target) or (target.startswith("/") and not target.startswith("//")))):
            continue
        out.append({"id": rid, "match": match, "source": src, "target": target, "status": status,
                    "preserve_query": r.get("preserve_query") is True, "groups": groups, "re": rx})
    return out


def _rd_matches(rule: dict, path: str) -> bool:
    if rule["match"] == "prefix":
        return path.startswith(rule["source"])
    if rule["match"] == "regex":
        return rule["re"].search(path) is not None
    return path == rule["source"]


def redirect_maps(sid: int, rules: list[dict], tunnel_prefixes=()) -> tuple[list[str], str | None, list[int]]:
    """http-level maps of a site's redirect rules -> (maps, variable, status codes used). The
    variable is "<status><Location>" of the first enabled rule (in order) matching the RAW request
    path ($pcdn_path: percent-encoded like the controller's sources; regex captures can never carry a
    decoded CR/LF into the Location header), or "".
     * exact sources: one hash lookup ($pcdn_rdh_*). nginx lower-cases map hash keys, so the hit is
       confirmed case-sensitively by a backreference ($pcdn_rde_*: the path must repeat the source).
       An exact rule shadowed by an EARLIER prefix / regex rule matching that same path is dropped
       (unreachable), so the hash may take precedence over the ordered map.
     * prefix / regex rules (and exact sources too long for the hash or differing from a hashed one
       only by case): one ordered regex map ($pcdn_rdc_*), first match wins; /__pcdn/ and tunnel
       prefixes are guarded first (never redirected).
    The value carries $1..$9 (regex rules) and, with preserve_query, the query string."""
    def value(r):
        t = r["target"]
        if r["preserve_query"]:
            base, mark, frag = t.partition("#")
            t = base + ("$pcdn_args_amp" if "?" in base else "$is_args$args") + mark + frag
        return f"{r['status']}{t}"

    hashed, ordered, before, seen, seen_low, codes = [], [], [], set(), set(), set()
    for r in rules:
        if r["match"] == "exact":
            src = r["source"]
            if src in seen or any(_rd_matches(p, src) for p in before):
                continue
            seen.add(src)
            if src.lower() not in seen_low and len(src) <= REDIRECT_HASH_MAX_KEY:
                seen_low.add(src.lower())
                hashed.append((src, value(r)))
                codes.add(r["status"])
                continue
            ordered.append(("~^" + re.escape(src) + "$", value(r)))
        elif r["match"] == "prefix":
            ordered.append(("~^" + re.escape(r["source"]), value(r)))
        else:
            ordered.append(("~" + r["source"], value(r)))
        before.append(r)
        codes.add(r["status"])
    maps, rde, rdc = [], None, None
    if hashed:
        maps.append(f"map $pcdn_path $pcdn_rdh_{sid} {{\n    default \"\";\n"
                    + "".join(f'    {_qre(src)} "{src} {val}";\n' for src, val in hashed) + "}")
        maps.append(f'map "$pcdn_path $pcdn_rdh_{sid}" $pcdn_rde_{sid} {{\n    default "";\n'
                    f'    "~^(\\\\S+) \\\\1 (.+)$" $2;\n}}')
        rde = f"$pcdn_rde_{sid}"
    if ordered:
        guards = ['    "~^/__pcdn/" "";\n']
        if tunnel_prefixes:
            guards.append(f"    {_qre('~^(?:' + '|'.join(re.escape(p) for p in tunnel_prefixes) + ')')} \"\";\n")
        maps.append(f"map $pcdn_path $pcdn_rdc_{sid} {{\n    default \"\";\n" + "".join(guards)
                    + "".join(f'    {_qre(k)} "{val}";\n' for k, val in ordered) + "}")
        rdc = f"$pcdn_rdc_{sid}"
    if rde and rdc:
        maps.append(f'map {rde} $pcdn_rd_{sid} {{\n    "~." {rde};\n    default {rdc};\n}}')
        return maps, f"$pcdn_rd_{sid}", sorted(codes)
    return maps, rde or rdc, sorted(codes)


def _tf_header_ok(name, remove: bool) -> bool:
    if not isinstance(name, str) or not SAFE_HEADER.match(name):
        return False
    low = name.lower()
    if low in TF_RESERVED or low.startswith(TF_RESERVED_PREFIX):
        return False
    return remove or low not in TF_REMOVE_ONLY


def norm_transform(site: dict) -> list[dict]:
    """Validated `transform.rules` in order: {"cond": None (always) | {methods, countries, path_re},
    "actions": [...]}. Actions: {type, name, value} for headers, {type, re, regex, groups,
    replacement} for rewrite_path."""
    out = []
    for r in (_sec(site, "transform").get("rules") or [])[:TF_MAX_RULES]:
        if not isinstance(r, dict) or r.get("enabled") is False:
            continue
        m = r.get("match") if isinstance(r.get("match"), dict) else {}
        pat = m.get("path", m.get("pattern"))
        methods, countries = m.get("methods") or [], m.get("countries") or []
        if pat not in (None, "", "/*", "*") and not (isinstance(pat, str) and SAFE_PATTERN.match(pat)):
            continue
        if not isinstance(methods, list) or not all(isinstance(x, str) and re.match(r"^[A-Za-z]{1,16}$", x)
                                                    for x in methods):
            continue
        if not isinstance(countries, list) or not all(isinstance(x, str) and re.match(r"^[A-Za-z]{2}$", x)
                                                      for x in countries):
            continue
        cond = {"methods": sorted({x.upper() for x in methods}), "countries": sorted({x.upper() for x in countries}),
                "path_re": wildcard_re(pat) if pat not in (None, "", "/*", "*") else None}
        if not cond["methods"] and not cond["countries"] and cond["path_re"] is None:
            cond = None
        actions = []
        for a in (r.get("actions") if isinstance(r.get("actions"), list) else [])[:TF_MAX_ACTIONS]:
            if not isinstance(a, dict):
                continue
            t = a.get("type")
            if t == "rewrite_path":
                rx, rep = pcre_regex(a.get("regex")), a.get("replacement")
                if (rx is None or not isinstance(rep, str) or not SAFE_REWRITE.match(rep)
                        or rep.lower().startswith("/__pcdn") or not _refs_ok(rep, rx.groups)):
                    continue
                actions.append({"type": t, "regex": a["regex"], "groups": rx.groups, "replacement": rep})
            elif t in ("set_request_header", "set_response_header"):
                v = a.get("value")
                if _tf_header_ok(a.get("name"), False) and isinstance(v, str) and SAFE_TF_VALUE.match(v):
                    actions.append({"type": t, "name": a["name"], "value": v})
            elif t in ("remove_request_header", "remove_response_header"):
                if _tf_header_ok(a.get("name"), True):
                    actions.append({"type": t, "name": a["name"]})
        if actions:
            out.append({"cond": cond, "actions": actions})
    return out


def norm_bots(site: dict) -> dict | None:
    """Per-site `bots` section; None when absent or mode off (today's behaviour)."""
    b = _sec(site, "bots")
    if b.get("mode") not in BOT_MODES:
        return None
    return {"mode": b["mode"], "allow_verified": b.get("allow_verified") is not False,
            "block_empty_ua": b.get("block_empty_ua") is not False}


def norm_bot_ranges(config: dict) -> dict:
    """Node-wide verified crawler ranges {engine: [cidr]} (only engines with at least one valid
    network). Broad or malformed networks are dropped; duplicates (also across engines) are kept
    once, for the first engine."""
    b = config.get("bots") if isinstance(config, dict) else None
    ver = b.get("verified") if isinstance(b, dict) else None
    out, seen = {}, set()
    if not isinstance(ver, dict):
        return out
    for name, _, _ in BOT_ENGINES:
        nets = []
        for c in (ver.get(name) if isinstance(ver.get(name), list) else [])[:BOT_MAX_PREFIXES * 2]:
            if not isinstance(c, str) or not SAFE_CIDR.match(c.strip()):
                continue
            try:
                n = ipaddress.ip_network(c.strip(), strict=False)
            except ValueError:
                continue
            if n.prefixlen < BOT_MIN_PREFIX[n.version] or n in seen:
                continue
            seen.add(n)
            nets.append(n)
        if nets:
            out[name] = [str(n) for n in sorted(nets, key=lambda n: (n.version, n))][:BOT_MAX_PREFIXES]
    return out


def with_cached_bot_ranges(body: dict, state: dict) -> dict:
    """The agent's cache of verified crawler ranges (SPEC §14.2): every engine's last non-empty list
    is kept in the state file and used while the controller sends none for it (e.g. a controller
    restored from an old backup). Nothing received ever -> nothing cached -> crawler UAs fail open."""
    if not isinstance(body, dict):
        return body
    got = norm_bot_ranges(body)
    cache = state.get("bot_ranges") if isinstance(state.get("bot_ranges"), dict) else {}
    cache = {k: v for k, v in cache.items() if isinstance(v, list) and v}
    cache.update(got)
    if cache:
        state["bot_ranges"] = cache
    if cache == got:
        return body
    b = body.get("bots") if isinstance(body.get("bots"), dict) else {}
    return dict(body, bots=dict(b, verified=dict(cache)))


def render_bots(ranges: dict) -> str | None:
    """bots.conf (0644, CIDRs only): `geo $pcdn_vbot` = "<engine><known>" where engine is 1 (google)
    / 2 (bing) / 0 (neither) and <known> lists the engines this node has ranges for, so njs can fail
    open for an engine without ranges. None when no engine has ranges ($pcdn_vbot is then "")."""
    if not ranges:
        return None
    known = "".join(flag for name, _, flag in BOT_ENGINES if ranges.get(name))
    out = ["# verified crawler ranges (SPEC §14.2) — generated by pcdn-agent, do not edit",
           "geo $pcdn_vbot {", f'    default "0{known}";']
    for name, val, _ in BOT_ENGINES:
        out += [f'    {c} "{val}{known}";' for c in ranges.get(name) or []]
    return "\n".join(out) + "\n}\n"


SAFE_PEM = re.compile(r"^[A-Za-z0-9+/=\-\s:,._()]+$")


def _pem_ok(cert, key) -> bool:
    """A PEM certificate (chain) + unencrypted private key, shape-checked so a malformed upload
    cannot make `nginx -t` reject the whole tree."""
    return (isinstance(cert, str) and isinstance(key, str) and 0 < len(cert) <= 65536 and 0 < len(key) <= 16384
            and SAFE_PEM.match(cert) is not None and SAFE_PEM.match(key) is not None
            and "-----BEGIN CERTIFICATE-----" in cert and "-----END CERTIFICATE-----" in cert
            and re.search(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", key) is not None and "ENCRYPTED" not in key)


def norm_origin_pull(config: dict) -> dict | None:
    """Node-wide platform client certificate {cert, key}, or None."""
    op = config.get("origin_pull") if isinstance(config, dict) else None
    if isinstance(op, dict) and _pem_ok(op.get("cert"), op.get("key")):
        return {"cert": op["cert"], "key": op["key"]}
    return None


def origin_client(sslo: dict) -> dict:
    """ssl_options.origin_client of a site: {"mode": off|platform|custom, cert?, key?}; the bare
    `origin_client_auth` string is understood too. A custom mode without a usable pair is off."""
    oc = sslo.get("origin_client")
    if isinstance(oc, dict):
        mode, cert, key = oc.get("mode"), oc.get("cert"), oc.get("key")
    else:
        mode, cert, key = sslo.get("origin_client_auth"), None, None
    if mode == "platform":
        return {"mode": "platform"}
    if mode == "custom" and _pem_ok(cert, key):
        return {"mode": "custom", "cert": cert, "key": key}
    return {"mode": "off"}


def site_js(site: dict, hosts: list, pools: dict, sslo: dict, tunnel: dict | None = None,
            tf_resp: list | None = None) -> dict:
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
    # SPEC §14.2 additions appear only when used, so sites without them keep a byte-identical entry
    packs = list(dict.fromkeys(p for p in (waf.get("packs") if isinstance(waf.get("packs"), list) else [])
                               if p in WAF_PACKS))
    extra = {}
    bots = norm_bots(site)
    if bots:
        extra["bots"] = bots
    if tf_resp:
        extra["tf_resp"] = tf_resp
    if tunnel:   # SPEC §15.2 (tunnel sites only, so other sites keep a byte-identical entry)
        extra["tunnel_fair"] = bool(tunnel["fair_share"])
    return dict({
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
        "waf": dict({"mode": waf.get("mode") if waf.get("mode") in ("detect", "block") else "off",
                     "paranoia": _int(waf.get("paranoia"), 1, 1, 3),
                     "groups": [g for g in (waf.get("groups") or []) if g in WAF_GROUPS],
                     "exclusions": excl,
                     "off_paths": [r["_re"] for r in page_rules(site) if r.get("waf") is False]},
                    **({"packs": packs} if packs else {})),
        "pools": pools,
        "image": {"enabled": bool(im.get("enabled")), "quality": _int(im.get("quality"), 85, 1, 100),
                  "max_width": _int(im.get("max_width"), 2000, 16, 10000)},
        # prefixes where only firewall allow/block/log rules apply (tunnel mode)
        "tunnel_paths": [p["path"] for p in tunnel["paths"]] if tunnel else [],
    }, **extra)


def render_site(site: dict, cfg: dict, shield: dict | None = None, platform_pull: tuple | None = None) -> tuple[str, dict]:
    """Return (nginx config text, {relative_path: content}) for one site."""
    text, files, _, _ = _render_site(site, cfg, shield, platform_pull)
    return text, files


SPEED_MAX_BYTES = 10 * 1024 * 1024   # SPEC §15.6: /__pcdn/speed/down?bytes=N and the upload body, N <= 10 MB
SPEED_FILE_SIZE = SPEED_MAX_BYTES + 64   # random file the downloads are cut from (pcdn.js SPEED_FILE_SIZE)


def speed_file(cfg: dict) -> str:
    """Path of the speed-test random file (SPEED_FILE, default next to the state file)."""
    return cfg.get("SPEED_FILE") or os.path.join(os.path.dirname(cfg.get("STATE_FILE") or "/var/lib/pcdn/x"),
                                                 "speed.bin")


def ensure_speed_file(cfg: dict):
    """Create the speed-test file (SPEED_FILE_SIZE bytes of os.urandom, 0644) once. Outside the
    rendered tree (that is swapped on every apply) and never re-written while it has the right size.
    Fail-soft: without it the download endpoint answers 404, nothing else is affected."""
    path = speed_file(cfg)
    try:
        if os.path.isfile(path) and os.path.getsize(path) == SPEED_FILE_SIZE:
            return
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        with os.fdopen(fd, "wb") as f:
            left = SPEED_FILE_SIZE
            while left > 0:
                chunk = os.urandom(min(left, 1 << 20))
                f.write(chunk)
                left -= len(chunk)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except OSError as e:
        log.warning("speed-test file %s not written: %s", path, e)


def speed_locations(cfg: dict, njs_ok: bool, brotli_ok: bool, flv_ok: bool = True) -> list[str]:
    """Speed-test endpoints of every active site server (SPEC §15.6; diagnostics only). The page runs in
    the WHMCS client area, a DIFFERENT origin than the customer domain, so every response - also the
    400 / 405 / 413 / 429 ones (`always`) and the internal file location whose headers the browser
    sees for downloads - carries Access-Control-Allow-Origin: * (no credentials), exposes X-Pcdn-Node
    and allows Resource Timing. The app sends only simple requests (GET, POST text/plain, no custom
    headers), so there is no OPTIONS handler: a preflight gets 204 (ping), 400 (down) or 405 (up),
    never a 5xx. Extra query arguments (the app's cache-buster "_") are ignored. Per-IP rate limits (pcdn-base.conf zones pcdn_speed / pcdn_speedp),
    never cached or compressed, logged and counted as normal traffic. X-Pcdn-Node is a hash of the
    node name ($pcdn_node), never an address. The security verdict still runs at server level: firewall
    block rules / blocked_ips / default block apply, challenges and the WAF do not (pcdn.js).
    down?bytes=N: pcdn.speedDown validates N and internally redirects to the static random file
    through the flv module ("?start=" serves the file from an offset with a 13-byte FLV header, status
    200, exact Content-Length, sendfile: no per-request or per-worker memory); N < 64 comes from njs."""
    hdr = ("add_header Cache-Control \"no-store, no-transform\" always; add_header X-Pcdn-Node $pcdn_node always; "
           "add_header Access-Control-Allow-Origin * always; "
           "add_header Access-Control-Expose-Headers X-Pcdn-Node always; add_header Timing-Allow-Origin * always;")
    nz = "gzip off;" + (" brotli off;" if brotli_ok else "")
    lim = "limit_req zone=pcdn_speed burst=12 nodelay; limit_req_status 429;"
    out = ["    location = /__pcdn/speed/ping { limit_req zone=pcdn_speedp burst=20 nodelay; limit_req_status 429; "
           f"{hdr} return 204; }}"]
    if njs_ok:
        if flv_ok:   # an nginx built without --with-http_flv_module has no download endpoint (404)
            path = speed_file(cfg)
            if not SAFE_FSPATH.match(path):
                raise ValueError("unsafe SPEED_FILE")
            out += [f"    location = /__pcdn/speed/down {{ {lim} {nz} {hdr} js_content pcdn.speedDown; }}",
                    f"    location = /__pcdn/speed/file {{ internal; flv; max_ranges 0; etag off; {nz} "
                    f"default_type application/octet-stream; {hdr} alias {path}; }}"]
        out.append(f"    location = /__pcdn/speed/up {{ {lim} client_max_body_size {SPEED_MAX_BYTES}; "
                   f"client_body_buffer_size 64k; {hdr} js_content pcdn.speedUp; }}")
    return out


def _render_site(site: dict, cfg: dict, shield: dict | None = None,
                 platform_pull: tuple | None = None) -> tuple[str, dict, dict | None, dict]:
    """-> (config text, extra files, sites.js entry or None, meta). platform_pull: the node's
    (cert, key) platform client certificate for authenticated origin pulls (SPEC §14.2), or None."""
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
        # F40: key on $pcdn_rl_key (client IP for normal requests, "" for tunnel locations) so the
        # legacy per-IP limit never touches tunnel streams. New zone name (…rlk) because nginx
        # rejects a reload that changes an existing zone's key.
        out.append(f"limit_req_zone $pcdn_rl_key zone=pcdn_rlk_{sid}:1m rate={rps}r/s;")

    ssl = site.get("ssl")
    if ssl:
        files[f"certs/{sid}.crt"] = ssl["cert"]
        files[f"certs/{sid}.key"] = ssl["key"]

    status = site.get("status", "active")
    # F35: tunnel path prefixes the controller keeps sending while a site is suspended / over_quota,
    # so those paths answer a cheap rate-limited 503 instead of a full HTML page on every reconnect.
    cut_paths = []
    if status in ("suspended", "over_quota"):
        seen_cut = set()
        for cp in _sec(site, "tunnel").get("cut_paths") or []:
            cp = str(cp)
            if SAFE_TUNNEL_PATH.match(cp) and not cp.startswith("/__pcdn") and cp not in seen_cut:
                seen_cut.add(cp)
                cut_paths.append(cp)
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
    caps = nginx_capabilities(cfg)
    njs_ok, brotli_ok = "njs" in caps["modules"], "brotli" in caps["modules"]
    # SPEC §14.1 stale content: stale_while_revalidate -> "updating" + background update;
    # stale_if_error > 0 (and always_online) -> serve stale on error/timeout/5xx. nginx cannot bound
    # the stale age per request; entries live until `inactive` (CACHE_INACTIVE, 7d >= the 604800 s
    # maximum). Origin Cache-Control stale-* extensions keep working natively where Cache-Control is
    # honoured. Missing fields keep today's behaviour.
    swr = cache.get("stale_while_revalidate", True) is not False
    sie = cache.get("stale_if_error")
    stale_err = always_online and (sie is None or _int(sie, 86400, 0, 604800) > 0)
    # SPEC §14.1 HTTP/3: only on capable nodes, for HTTPS sites whose ssl.http3 is not off
    h3_flag = sslo.get("http3")
    if h3_flag is None and isinstance(site.get("ssl"), dict):
        h3_flag = site["ssl"].get("http3")
    h3 = bool(caps["http3"] and ssl and h3_flag is not False)
    alt_svc = f"add_header Alt-Svc 'h3=\":{sport}\"; ma=86400' always;"
    # SPEC §14.1 origin shield
    shield_self = bool(shield and shield.get("self"))
    shield_peers = [] if not shield or shield_self else list(shield.get("peers") or [])
    # only sites with a certificate: the hop (and the secret it carries) must be TLS. HTTP-only sites
    # always fetch from the origin directly and never send X-Pcdn-Shield.
    shielded = bool(shield_peers) and cache_on and cache.get("shield") is True and bool(ssl)

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

    # --- cache key (SPEC §14.1). Variant fields are appended after the URI as ";<field>=<value>":
    # no field value can contain ";" (device class, WebP flag, cookie values), so a key always
    # splits back into one URI + fixed fields and two different requests never share a key.
    # Without options the key text stays exactly "<scheme>://$host<uri>" as before.
    kopt = key_options(site)
    scheme_var = "$pcdn_scheme" if shield_self else "$scheme"

    def _kvar(kind, i, name):
        if NGX_VAR_NAME.match(name):
            return f"${{{kind}_{name}}}"
        var = f"pcdn_k{kind[0]}_{sid}_{i}"
        src, sep = ("$http_cookie", ";") if kind == "cookie" else ("$args", "&")
        lead = "(?:^|;)\\s*" if kind == "cookie" else "(?:^|&)"
        out.append(f"map {src} ${var} {{\n    default \"\";\n    \"~*{lead}{re.escape(name)}=([^{sep}]*)\" $1;\n}}")
        return f"${{{var}}}"
    key_cookies = [(n, _kvar("cookie", i, n)) for i, n in enumerate(kopt["cookies"])]
    key_args = [(n, _kvar("arg", i, n)) for i, n in enumerate(kopt["qa"])]
    webp_on = kopt["webp"]
    key_suffix = (("" if not kopt["dev"] else ";d=${pcdn_dev}")
                  + "".join(f";c.{n}={v}" for n, v in key_cookies)
                  + (";w=${pcdn_webp}" if webp_on else ""))

    def cache_key(iq, image=False):
        """-> (key text, needs quoting)."""
        if image:
            uri = "$pcdn_path?w=$pcdn_img_w&h=$pcdn_img_h" if (iq or key_args) else "$request_uri"
        elif iq:
            uri = "$pcdn_path"
        elif key_args:   # cache.key_query_allow: only these parameters, in a fixed order
            uri = "$pcdn_path?" + "&".join(f"{n}={v}" for n, v in key_args)
        else:
            uri = "$request_uri"
        key = f"{scheme_var}://$host{uri}{key_suffix}"
        return key, bool(key_suffix or (key_args and not iq and not image))

    # --- preload page rules (SPEC §14.1): the first rule with `preload` matching the URI adds its
    # Link headers on every proxied location (the same first-match-per-feature model as WAF rules)
    link_rules = [(r["_re"], ", ".join(lk)) for r in page_rules(site) if (lk := preload_links(r))]
    link_var = f"$pcdn_link_{sid}" if link_rules else None
    if link_var:
        out.append(f"map $uri {link_var} {{\n    default \"\";\n"
                   + "".join(f"    \"~{rx}\" {_qv(v)};\n" for rx, v in link_rules) + "}")
    # nginx relays 103 responses it receives from the origin but cannot originate one; on
    # early_hints-capable nodes those are passed to HTTP/2+ navigations of preload-rule sites
    eh_on = bool(link_var and caps["early_hints"])

    # --- header rules
    hdr = _sec(site, "headers")
    req_headers = {}
    for h in hdr.get("request") or []:
        n, v = str(h.get("name") or ""), h.get("value")
        if SAFE_HEADER.match(n) and n.lower() not in HOP_HEADERS and v is not None and SAFE_VALUE.match(str(v)):
            req_headers[n.lower()] = (n, _qv(str(v)))
    resp_add, resp_hide = [], []
    resp_static = {}   # lower name -> (name, value | None): the last headers.response entry
    for h in hdr.get("response") or []:
        n, v = str(h.get("name") or ""), h.get("value")
        if not SAFE_HEADER.match(n) or n.lower() in HOP_HEADERS:
            continue
        if v is None:
            resp_hide.append(n)
            resp_static[n.lower()] = (n, None)
        elif SAFE_VALUE.match(str(v)):
            resp_hide.append(n)  # replace the origin's value instead of sending both
            resp_add.append((n, f"add_header {n} {_qv(str(v))} always;"))
            resp_static[n.lower()] = (n, str(v))

    # --- transform rules (SPEC §14.2), web locations only (tunnel paths keep today's headers).
    # Conditions (methods / countries / path pattern) become one flag map per rule over
    # "$request_method|$pcdn_country|$pcdn_shield_ok|$pcdn_ouri" ($pcdn_ouri = the request's $uri
    # pinned at server level, before any internal rewrite; (?s): a "*" also spans a decoded
    # newline). A valid shield hop never matches, so a shield does not transform again what the
    # visitor-facing edge already did. Rules run in order; a later matching rule wins for a header.
    #  * request headers: proxy_set_header with a chain of maps (flag 1 -> this rule's value, "" for a
    #    removal; otherwise the previous value, at the bottom the visitor's own $http_<name>);
    #  * response headers: unconditional -> proxy_hide_header + add_header; conditional -> the njs
    #    header filter pcdn.tfHeaders (exact set / delete of every value, also multi-value Set-Cookie,
    #    which a "$upstream_http_<name>" pass-through would join into one broken line);
    #  * rewrite_path: the regex runs on the RAW request path ($pcdn_path, percent-encoded, so a
    #    capture can never put a decoded CR/LF into the request line) and the result is passed as the
    #    URI of proxy_pass; the cache key stays on the visitor's original URI.
    active = status not in ("suspended", "over_quota")
    tf_rules = norm_transform(site) if active else []
    tf_flag, tf_req, tf_resp, tf_hide, tf_add, tf_done, rewrites = {}, {}, [], [], [], set(), []
    req_ops, resp_ops = {}, {}
    for i, rule in enumerate(tf_rules):
        c = rule["cond"]
        if c is not None:
            meth = "(?:" + "|".join(c["methods"]) + ")" if c["methods"] else "[^|]*"
            ccs = "(?:" + "|".join(c["countries"]) + ")" if c["countries"] else "[^|]*"
            path = c["path_re"][1:] if c["path_re"] else ".*"
            tf_flag[i] = f"pcdn_tf_{sid}_{i}"
            out.append(f'map "$request_method|$pcdn_country|$pcdn_shield_ok|$pcdn_ouri" ${tf_flag[i]} {{\n'
                       f"    {_qre('~(?s)^' + meth + '[|]' + ccs + '[|]0[|]' + path)} 1;\n    default 0;\n}}")
        f = tf_flag.get(i)
        for a in rule["actions"]:
            t = a["type"]
            if t == "rewrite_path":
                rewrites.append((f, a))
            elif t.endswith("_request_header"):
                req_ops.setdefault(a["name"].lower(), []).append(
                    (f, _qv(a["value"]) if t.startswith("set_") else '""', a["name"]))
            else:
                resp_ops.setdefault(a["name"].lower(), []).append(
                    (f, "set" if t.startswith("set_") else "del", a.get("value"), a["name"]))
    for low, ops in resp_ops.items():
        name, base = ops[0][3], resp_static.get(low)
        if all(o[0] is None for o in ops):
            state = ops[-1][1:3]
            tf_hide.append(name)
            if state[0] == "set":
                tf_add.append(f"add_header {name} {_qv(state[1])} always;")
            tf_done.add(low)
        elif njs_ok:
            if base:
                tf_resp.append({"f": "", "op": "set", "n": name, "v": base[1]} if base[1] is not None
                               else {"f": "", "op": "del", "n": name})
            for f, op, v, _ in ops:
                tf_resp.append({"f": f or "", "op": op, "n": name, "v": v} if op == "set"
                               else {"f": f or "", "op": op, "n": name})
            tf_done.add(low)
        else:
            log.warning("site %s: conditional response-header transforms need njs; skipped for %s", sid, name)
    if tf_done:   # these names are handled by the transform rules (their headers.response entry is the base)
        resp_hide = [n for n in resp_hide if n.lower() not in tf_done]
        resp_add = [x for x in resp_add if x[0].lower() not in tf_done]
    resp_add = [line for _, line in resp_add] + tf_add
    if shield_self:
        # a shield keeps the visitor's address / scheme / country forwarded by a valid shield hop
        base_req = [("Host", "$host"), ("X-Real-IP", "$pcdn_client_ip"), ("X-Forwarded-For", "$pcdn_xff"),
                    ("X-Forwarded-Proto", "$pcdn_scheme"), ("X-Country-Code", "$pcdn_cc")]
    else:
        base_req = [("Host", "$host"), ("X-Real-IP", "$remote_addr"), ("X-Forwarded-For", "$proxy_add_x_forwarded_for"),
                    ("X-Forwarded-Proto", "$scheme"), ("X-Country-Code", "$pcdn_country")]
    # never forwarded to an origin, also on a node that is no longer a shield while edges still
    # send it hops (config propagation lag)
    base_req.append(("X-Pcdn-Shield", '""'))

    # transform request headers: start from the static headers.request value (or the edge's own
    # value for a base header, or the visitor's header) and apply the rules in order
    base_vals = {n.lower(): v for n, v in base_req}
    for k, (low, ops) in enumerate(req_ops.items()):
        cur = req_headers[low][1] if low in req_headers else base_vals.get(low) or _hvar(ops[0][2])
        for j, (f, expr, _) in enumerate(ops):
            if f is None:
                cur = expr
            else:
                var = f"pcdn_tq_{sid}_{k}_{j}"
                out.append(f"map ${f} ${var} {{\n    1 {expr};\n    default {cur};\n}}")
                cur = "$" + var
        tf_req[low] = (ops[0][2], cur)

    def req_hdrs(directive, conn=(("Upgrade", "$http_upgrade"), ("Connection", "$pcdn_connection_upgrade")), tf=False):
        over = tf_req if tf else {}
        pairs = ([(n, v) for n, v in base_req if n.lower() not in req_headers and n.lower() not in over]
                 + [hv for low, hv in req_headers.items() if low not in over] + list(over.values()) + list(conn))
        return [f"{directive} {n} {v};" for n, v in pairs]

    # nginx drops inherited proxy_set_header / add_header / proxy_hide_header as soon as
    # a location sets one of them, so every proxying location gets the complete set.
    proxy_hdrs = req_hdrs("proxy_set_header", tf=True)

    # rewrite_path: per rule, $pcdn_tfu_* is the rewritten URI when the rule's condition holds
    # ($pcdn_tfr_*: its regex on the raw path) and otherwise the next rule's, so the first rule whose
    # condition and regex both match wins ("" = none: proxy_pass keeps the request URI). Unconditional
    # rules are skipped on a valid shield hop too (the edge already sent the rewritten path).
    tf_uri = ""
    if rewrites:
        nxt = '""'
        for j, (f, a) in reversed(list(enumerate(rewrites))):
            rep = a["replacement"] + ("$pcdn_args_amp" if "?" in a["replacement"] else "$is_args$args")
            out.append(f"map $pcdn_path $pcdn_tfr_{sid}_{j} {{\n    default {nxt};\n"
                       f"    {_qre('~' + a['regex'])} \"{rep}\";\n}}")
            src, hit = (f"${f}", "1") if f else ("$pcdn_shield_ok", "0")
            out.append(f"map {src} $pcdn_tfu_{sid}_{j} {{\n    {hit} $pcdn_tfr_{sid}_{j};\n    default {nxt};\n}}")
            nxt = f"$pcdn_tfu_{sid}_{j}"
        tf_uri = nxt
    mtls_now = []   # proxy_ssl_certificate lines of the host being rendered (origin-bound HTTPS only)

    def loc_common(hides=(), extra_add=(), hdrs=None):
        lines = list(proxy_hdrs if hdrs is None else hdrs)
        for n in dict.fromkeys(list(hides) + resp_hide + tf_hide):
            lines.append(f"proxy_hide_header {n};")
        lines += list(extra_add)
        lines.append("add_header X-Served-By $hostname always;")
        if hsts_var:
            lines.append(f"add_header Strict-Transport-Security {hsts_var} always;")
        if h3:
            lines.append(alt_svc)
        if link_var:
            lines.append(f"add_header Link {link_var};")
        if webp_on:
            lines.append("add_header Vary $pcdn_webp_vary;")
        if eh_on:
            lines.append("early_hints $pcdn_early_hints;")
        if tf_resp:
            lines.append("js_header_filter pcdn.tfHeaders;")
        return lines + resp_add

    def ind(lines):
        return ["        " + x for x in lines]

    named = [0]

    def proxy_loc(match, mode, ttl, bttl, iq, uri=""):
        """mode: bypass | dynamic (honour origin; ttl>0 = default TTL) | aggressive | everything | static.
        uri: explicit URI variable for proxy_pass (default: the rewrite_path result, "" = unchanged)."""
        L, hides, adds = [], [], []
        cacheable = mode != "bypass" and cache_on
        key = None
        if not cacheable:
            adds.append("add_header X-Cache BYPASS always;")
        else:
            key, quote = cache_key(iq)
            L += [f"proxy_cache {zone};", "proxy_cache_key " + (f'"{key}"' if quote else key) + ";"]
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
            stale = ((["error", "timeout"] if stale_err else []) + (["updating"] if swr else [])
                     + (["http_500", "http_502", "http_503", "http_504"] if stale_err else []))
            L += [f"proxy_cache_use_stale {' '.join(stale) or 'off'};", "proxy_cache_lock on;"]
            if swr:
                L.append("proxy_cache_background_update on;")
            adds.append("add_header X-Cache $upstream_cache_status always;")
        if bttl > 0:
            hides += ["Cache-Control", "Expires"]
            adds.append(f"add_header Cache-Control \"public, max-age={bttl}\" always;")
        origin = loc_common(hides, adds) + L + mtls_now + [f"proxy_pass $pcdn_proto://$pcdn_target{uri or tf_uri};"]
        if not (shielded and cacheable):
            return [f"    location {match} {{"] + ind(origin) + ["    }"]
        # SPEC §14.1 origin shield: GET/HEAD cache misses go to the shield peers (consistent hash on
        # the cache key); any other method, and every request once all shields are unreachable
        # (nginx-generated 502/504), is re-run in a named location that fetches from the origin.
        # proxy_intercept_errors stays off so a shield's own answer (also an error page) is passed
        # as is and never replayed against the origin.
        named[0] += 1
        fb = f"@pcdn_origin_{named[0]}"
        sh_hdrs = [x if not x.startswith("proxy_set_header X-Pcdn-Shield ")
                   else "proxy_set_header X-Pcdn-Shield $pcdn_shield_secret;" for x in proxy_hdrs]
        # headers the shield adds itself; this edge adds its own copies
        sh_hides = hides + ["X-Cache", "X-Served-By"] + (["Strict-Transport-Security"] if hsts_var else []) \
            + (["Alt-Svc"] if h3 else [])
        S = ["if ($pcdn_sh_skip) { return 418; }", f"set $pcdn_ck \"{key}\";"]
        S += loc_common(sh_hides, adds, sh_hdrs) + L
        for cls, codes in err_pages.items():
            rest = " ".join(c for c in codes.split() if c not in ("502", "504"))
            if rest:
                S.append(f"error_page {rest} /__pcdn/err/{cls}.html;")
        S += [f"error_page 418 502 504 = {fb};", "proxy_intercept_errors off;",
              f"proxy_connect_timeout {min(5, _int(cfg.get('TUNNEL_CONNECT_TIMEOUT'), 10, 3, 30))}s;",
              f"proxy_next_upstream_tries {len(shield_peers)};"]
        # always TLS, verified against $host (the shield serves the site's certificate). The upstream
        # is shared by every shielded site, so a TLS session saved for one site must not be resumed
        # for another (a resumed session keeps the first site's certificate, the name check fails and
        # the hop silently falls back to the origin); idle keepalive connections are still reused.
        S += ["proxy_ssl_server_name on;", "proxy_ssl_name $host;", "proxy_ssl_verify on;",
              f"proxy_ssl_trusted_certificate {cfg['CA_BUNDLE']};", "proxy_ssl_verify_depth 4;",
              "proxy_ssl_session_reuse off;", f"proxy_pass https://pcdn_shield_https{tf_uri};"]
        return ([f"    location {match} {{"] + ind(S) + ["    }"]
                + [f"    location {fb} {{"] + ind(origin) + ["    }"])

    # --- custom error pages (files next to the config, served from an internal location)
    ep = _sec(site, "errorpages")
    err_pages = {}
    for cls, codes in (("5xx", "500 502 503 504"), ("4xx", "400 403 404 405 410")):
        body = ep.get(cls)
        if isinstance(body, str) and body.strip() and len(body.encode()) <= 65536:
            files[f"errors/{sid}-{cls}.html"] = body
            err_pages[cls] = codes

    # the resizer needs the image_filter module and the njs imgW/imgH/imgQ parameters
    image_on = bool(_sec(site, "image").get("enabled")) and "image_filter" in caps["modules"] and njs_ok
    resize_port = _int(cfg["RESIZE_PORT"], 8089, 1, 65535)
    prules = page_rules(site)
    valid_hosts = []

    # --- tunnel mode (SPEC §7): per-site http-context parts
    tunnel = norm_tunnel(site, pools)
    fallback = tunnel["fallback"] if tunnel else "origin"
    image_on = image_on and fallback == "origin"  # decoy / 404 sites never fetch origin content
    webp_on = webp_on and fallback == "origin"
    decoy = decoy_page(cfg, domain) if fallback == "decoy" else None
    geo_ok = geoip_present(cfg)
    ka = _int(cfg.get("TUNNEL_KEEPALIVE"), 64, 1, 4096)
    h2_buf = cfg.get("TUNNEL_H2_BODY_BUFFER") if SAFE_SIZE.match(cfg.get("TUNNEL_H2_BODY_BUFFER") or "") else "256k"
    relay_buf = cfg.get("TUNNEL_RELAY_BUFFER") if SAFE_SIZE.match(cfg.get("TUNNEL_RELAY_BUFFER") or "") else "16k"
    resolver = cfg["RESOLVER"] if SAFE_RESOLVER.match(cfg.get("RESOLVER") or "") else "1.1.1.1"
    tn_upstreams = {}  # (h2?, host:port) -> upstream name (keepalive towards IP-literal origins)
    _up_rendered = set()
    if tunnel and tunnel["allowed_countries"]:
        # F9: only enforce the country gate when the GeoIP DB is installed; otherwise fail open.
        # `"" 1;` lets a client the DB cannot resolve pass instead of being 403'd.
        if geo_ok:
            out.append(f"map $pcdn_country $pcdn_tcc_{sid} {{\n    \"\" 1;\n"
                       + "".join(f"    {cc} 1;\n" for cc in tunnel["allowed_countries"]) + "    default 0;\n}")
        else:
            log.warning("no GeoIP DB / geoip2 module on this edge; tunnel allowed_countries fails open for site %s",
                        sid)
    # F34: a force_https site with tunnel paths must not 301 its ws/httpupgrade/xhttp clients on
    # port 80 (they cannot follow a redirect). Map the tunnel prefixes to 1 and skip the redirect
    # for them; non-tunnel sites keep the plain one-line redirect.
    force_https_tn = bool(tunnel and tunnel["paths"] and sslo.get("force_https") and ssl)
    if force_https_tn:
        # nginx `if` compares a single variable (it cannot concatenate $scheme with the flag), so a
        # second map combines them: redirect only when scheme is http AND the path is not a tunnel path.
        alt = "|".join(re.escape(p["path"]) for p in tunnel["paths"])
        out.append(f"map $uri $pcdn_tnp_{sid} {{\n    volatile;\n    default 0;\n    \"~^(?:{alt})\" 1;\n}}")
        out.append(f"map \"$scheme$pcdn_tnp_{sid}\" $pcdn_httpredir_{sid} {{\n    volatile;\n"
                   f"    \"http0\" 1;\n    default 0;\n}}")

    # --- redirect rules (SPEC §14.2): server level, after the security verdict and force_https and
    # before the request-body check, image resizing, page rules, cache and origin
    tn_prefixes = [p["path"] for p in tunnel["paths"]] if tunnel else []
    rd_var, rd_codes = None, []
    if active:
        rd_maps, rd_var, rd_codes = redirect_maps(sid, norm_redirects(site, tn_prefixes), tn_prefixes)
        out += rd_maps

    # --- WAF packs (SPEC §14.2): xmlrpc.php / JSON request bodies are read and inspected by njs
    # (/__pcdn/body/ -> pcdn.bodyInspect) before they are proxied through @pcdn_body
    waf_sec = _sec(site, "waf")
    body_packs = {"wordpress", "api"} & set(p for p in (waf_sec.get("packs") if isinstance(waf_sec.get("packs"), list)
                                                        else []) if isinstance(p, str))
    body_on = bool(active and njs_ok and fallback == "origin" and body_packs
                   and waf_sec.get("mode") in ("detect", "block"))

    # --- authenticated origin pulls (SPEC §14.2): client certificate on origin-bound HTTPS hops only
    # (never on the edge -> shield hop, which carries the shield's own TLS; the shield itself presents
    # it to the origin). Origins over plain HTTP get nothing.
    oc = origin_client(sslo) if active else {"mode": "off"}
    mtls_id, mtls_pair, mtls_used = None, None, False
    if oc["mode"] == "platform":
        if platform_pull:
            mtls_id, mtls_pair = "platform", platform_pull
        else:
            log.warning("site %s: origin_client platform but no origin_pull certificate in the config", sid)
    elif oc["mode"] == "custom":
        mtls_id, mtls_pair = str(sid), (oc["cert"], oc["key"])
    mtls_lines = [f"proxy_ssl_certificate {cfg['NGINX_DIR']}/mtls/{mtls_id}.crt;",
                  f"proxy_ssl_certificate_key {cfg['NGINX_DIR']}/mtls/{mtls_id}.key;"] if mtls_id else []
    meta = {"mtls_resizer": None}
    # @pcdn_body proxies the visitor's original URI (or its rewrite_path result) explicitly: the
    # request URI there is the internal /__pcdn/body/... one
    body_uri = "$request_uri"
    if body_on and tf_uri:
        out.append(f'map {tf_uri} $pcdn_bu_{sid} {{\n    "~." {tf_uri};\n    default $request_uri;\n}}')
        body_uri = f"$pcdn_bu_{sid}"

    def _upstream_block(name, hp, h2):
        # one server: never marked down (max_fails=0). A warm pool of idle keepalive connections to
        # the VPN origin removes the TCP+TLS handshake across the border from the next stream;
        # keepalive_requests/keepalive_time keep long VPN sessions from recycling a connection mid-use.
        # Separate names per (h2, hp): a cached keepalive connection must never cross protocols.
        if name not in _up_rendered:
            _up_rendered.add(name)
            out.append(f"upstream {name} {{\n    server {hp} max_fails=0;\n    keepalive {ka};\n"
                       f"    keepalive_timeout 300s;\n    keepalive_requests 1000000;\n"
                       f"    keepalive_time 1h;\n}}")
        return name

    def tn_upstream(hp, h2):
        if (h2, hp) not in tn_upstreams:
            tn_upstreams[(h2, hp)] = _upstream_block(f"pcdn_tn_{sid}_{len(tn_upstreams)}", hp, h2)
        return tn_upstreams[(h2, hp)]

    # F1/F11: give IP-literal pool members keepalive upstreams and session affinity. For every pool
    # of this tunnel site, render (deterministically named, separate from tn_upstream's counter) a
    # keepalive upstream per IP-literal member for each keepalive-capable protocol the tunnel uses,
    # and record the names on the pool origins so tunnelUpstream() in njs returns the upstream name
    # for the member it picks. Hostname members keep the request-time resolver path.
    pool_names = sorted(pools)
    if tunnel:
        kinds = {p["protocol"] for p in tunnel["paths"]}
        need_h2 = bool(kinds & {"grpc", "h2"})
        need_h1 = "xhttp" in kinds
        for pi, pname in enumerate(pool_names):
            for oi, o in enumerate(pools[pname]["origins"]):
                if not IP_LITERAL.match(o["hp"].rsplit(":", 1)[0]):
                    o["up"] = None
                    continue
                up = {"h1": None, "h2": None}
                base = f"pcdn_tn_{sid}_p{pi}_{oi}"
                if need_h2:
                    up["h2"] = _upstream_block(base + "_h2", o["hp"], True)
                if need_h1:
                    up["h1"] = _upstream_block(base, o["hp"], False)
                o["up"] = up if (up["h1"] or up["h2"]) else None

    def tunnel_loc(p, proto, pool, target):
        """One `location ^~ <path>` for a tunnel path; host defaults: proto / pool / target."""
        kind, idle = p["protocol"], tunnel["idle_timeout"]
        grpc = kind in ("grpc", "h2")
        keepalive_ok = kind in ("xhttp", "grpc", "h2")  # upgraded (ws) connections are never reused
        h2buf = kind in ("grpc", "h2", "xhttp")          # HTTP/2 body path (F3)
        resolved = False   # dest resolved at request time via the nginx resolver
        L = [f"set $pcdn_tn {kind};", f"set $pcdn_tp {p['id']};"]   # SPEC §15.1 access-log "tp"
        # F13: count only the session-opening request against limit_conn. ws/grpc/h2 sessions and
        # streams each open one; xhttp counts only the downlink GET ($pcdn_tn_isget), so packet-up
        # POSTs do not consume a slot and the limit refuses new sessions instead of tearing down old.
        L.append("set $pcdn_tn_ckey " + ("$pcdn_tn_isget;" if kind == "xhttp" else "$pcdn_site;"))
        if tunnel["allowed_countries"] and geo_ok:  # F9: no gate at all without a GeoIP DB
            L.append(f"if ($pcdn_tcc_{sid} = 0) {{ return 403; }}")
        if kind in ("ws", "httpupgrade"):
            # SPEC §15.1 "protocol": a ws/httpupgrade path without an Upgrade header (a browser, a
            # probe, an HTTP/2 client - nginx cannot carry WebSocket over HTTP/2) is answered by the
            # edge with 426 instead of being passed to the origin, so the wrong-protocol case is
            # visible in the access log. Real ws/httpupgrade clients always send Upgrade.
            L.append('if ($http_upgrade = "") { return 426; }')
        if njs_ok:
            # SPEC §15.2 fair share: "1" only while the node is hot and this site holds more than its
            # share of the node's NEW tunnel sessions (pcdn.js tunnelFair); refuses only a new session
            # (never an established one; xhttp packet POSTs are never refused), 429 like limit_conn.
            L.append("if ($pcdn_tn_fair) { return 429; }")
        o = p["origin"]
        if o:
            tls, sni, verify = o["tls"], o["sni"] or "$host", o["verify"]
            if o["ip"] and keepalive_ok:
                dest = tn_upstream(o["hp"], grpc)
            else:
                L.append(f"set $pcdn_tn_target {_q(o['hp'])};")  # variable: resolved at request time
                dest, resolved = "$pcdn_tn_target", not o["ip"]
        elif p["pool"]:
            tls, sni, verify = pools[p["pool"]]["protocol"] == "https", "$host", bool(sslo.get("origin_verify"))
            # F1: prefix + pool set before $pcdn_tn_target so the js_set tunnelUpstream (lazy, cached
            # on first reference) sees them; xhttp/h2 then stick every request of a session to one
            # origin via a rendezvous hash on the session id parsed out of the path.
            L += [f"set $pcdn_tn_pool {_q(p['pool'])};", f"set $pcdn_tn_prefix {_q(p['path'])};",
                  "set $pcdn_tn_target $pcdn_tn_upstream;"]
            dest, resolved = "$pcdn_tn_target", True
        elif pool:
            # F1: a host that inherits a pool must route its tunnel paths through the tunnel picker
            # (affinity + keepalive), not the web balancer ($pcdn_target), which splits sessions.
            tls, sni, verify = pools[pool]["protocol"] == "https", "$host", bool(sslo.get("origin_verify"))
            L += [f"set $pcdn_tn_pool {_q(pool)};", f"set $pcdn_tn_prefix {_q(p['path'])};",
                  "set $pcdn_tn_target $pcdn_tn_upstream;"]
            dest, resolved = "$pcdn_tn_target", True
        else:
            tls, sni, verify = proto == "https", "$host", bool(sslo.get("origin_verify"))
            host_addr = (target or "").rsplit(":", 1)[0]
            if keepalive_ok and IP_LITERAL.match(host_addr):
                dest = tn_upstream(target, grpc)
            else:
                dest, resolved = "$pcdn_target", True
        # N4: IPv6-only tunnel origins are unreachable through the http-level ipv6=off resolver; on a
        # node that listens on IPv6 (has v6 egress), enable AAAA for the request-time-resolved path
        # only, leaving proxied web origins on the IPv4-only resolver.
        if resolved and v6:
            L.append(f"resolver {resolver} valid=300s;")
        if tunnel["max_connections"]:
            L.append(f"limit_conn pcdn_tn_site2 {tunnel['max_connections']};")
        if tunnel["max_connections_per_ip"]:
            L.append(f"limit_conn pcdn_tn_ip2 {tunnel['max_connections_per_ip']};")
        L.append("limit_conn_status 429;")
        # F40: the legacy per-IP limit_req is skipped on tunnel paths via the empty $pcdn_rl_key
        # (see pcdn-base.conf); no limit_req_dry_run needed and no shared-memory lock is taken.
        # tunnel.per_connection_mbps is not rendered: nginx 1.24 resets limit_rate to 0 for
        # unbuffered proxying (proxy_buffering off, every grpc_pass) and never applies it to
        # upgraded (101) connections, where a limit_rate delay on the 101 response even makes
        # nginx miss the client's close. See docs/EDGE.md.
        L += ["client_max_body_size 0;"]
        if h2buf:  # F3: raise per-stream in-flight upload capacity above the 64k default window
            L.append(f"client_body_buffer_size {h2_buf};")
        L += [f"client_body_timeout {idle}s;", f"send_timeout {idle}s;",
              "tcp_nodelay on;", "gzip off;"] + (["brotli off;"] if brotli_ok else []) + [
              f"http2_chunk_size {relay_buf};"]  # F14: larger client-facing HTTP/2 DATA frames
        if grpc:
            L += req_hdrs("grpc_set_header", conn=())
            L += [f"grpc_read_timeout {idle}s;", f"grpc_send_timeout {idle}s;", "grpc_socket_keepalive on;",
                  f"grpc_buffer_size {relay_buf};",  # F14
                  # F28: allow the safe connect-failure failover (a stream is still never replayed)
                  "grpc_next_upstream error timeout;", "grpc_next_upstream_tries 2;",
                  "grpc_next_upstream_timeout 15s;", "grpc_intercept_errors off;"]
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
                  f"proxy_buffer_size {relay_buf};",  # F14
                  f"proxy_read_timeout {idle}s;", f"proxy_send_timeout {idle}s;", "proxy_socket_keepalive on;",
                  # F28: allow the safe connect-failure failover (a stream is still never replayed)
                  "proxy_next_upstream error timeout;", "proxy_next_upstream_tries 2;",
                  "proxy_next_upstream_timeout 15s;", "proxy_intercept_errors off;"]
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
            if caps["http2_directive"]:   # nginx >= 1.25.1 deprecates "listen ... http2" (warns)
                s.append(f"    listen {sport} ssl;")
                if v6:
                    s.append(f"    listen [::]:{sport} ssl;")
                s.append("    http2 on;")
            else:  # "listen ... http2" works on every nginx >= 1.9.5
                s.append(f"    listen {sport} ssl http2;")
                if v6:
                    s.append(f"    listen [::]:{sport} ssl http2;")
            if h3:  # SPEC §14.1; `reuseport` lives on the default server's quic listen
                s.append(f"    listen {sport} quic;")
                if v6:
                    s.append(f"    listen [::]:{sport} quic;")
                s.append("    http3 on;")
                s.append(f"    {alt_svc}")
            s.append(f"    ssl_certificate {cfg['NGINX_DIR']}/certs/{sid}.crt;")
            s.append(f"    ssl_certificate_key {cfg['NGINX_DIR']}/certs/{sid}.key;")
        s.append(f"    server_name {name};")
        # F23: buffer the access log so a tunnel stream/packet request does not write an unbuffered
        # line from the worker event loop; flush often enough that usage accounting barely lags.
        # SPEC §14.1: a shield does not log (bill) the cache misses other edges forward to it
        s.append(f"    access_log {cfg['ACCESS_LOG']} pcdn buffer=64k flush=1s"
                 + (" if=$pcdn_log_ok;" if shield_self else ";"))
        s.append(f"    set $pcdn_site {sid};")
        if tf_flag:   # transform conditions see the visitor's path, also after an internal rewrite
            s.append("    set $pcdn_ouri $uri;")
        s.append("    location = /__pcdn/health { access_log off; return 200 \"ok\\n\"; }")
        if tunnel and status not in ("suspended", "over_quota"):
            # F27/N2: raise the client-facing HTTP/2 connection timers for tunnel hosts so idle
            # tunnels are not closed after 75 s and stream-heavy XHTTP/gRPC connections are not
            # forced to GOAWAY + reconnect at the 100000-stream cap. Bounded, not unlimited.
            kreq = _int(cfg.get("TUNNEL_KEEPALIVE_REQUESTS"), 10000000, 1000, 2 ** 31 - 1)
            s.append("    keepalive_timeout 600s;")
            s.append("    keepalive_time 6h;")
            s.append(f"    keepalive_requests {kreq};")
            s.append(f"    send_timeout {min(tunnel['idle_timeout'], 300)}s;")
            if fallback in ("decoy", "404") and ssl:
                # F14: pure-tunnel hosts favour throughput over TLS first-byte latency
                s.append(f"    ssl_buffer_size {relay_buf};")

        if status in ("suspended", "over_quota"):
            page = "suspended.html" if status == "suspended" else "over_quota.html"
            # F35: cheap, rate-limited, body-less 503 on tunnel path prefixes so reconnect storms
            # cost neither an access-log line nor an HTML page read. error_page is scoped to
            # `location /` so only the browser-facing catch-all serves the localized page.
            for cp in cut_paths:
                s.append(f"    location ^~ {_q(cp)} {{ access_log off; "
                         f"limit_req zone=pcdn_cut burst=5 nodelay; limit_req_status 503; return 503; }}")
            s.append(f"    location = /{page} {{ internal; root {cfg['PAGES_DIR']}; "
                     f"add_header Cache-Control no-store always; }}")
            s.append(f"    location / {{ error_page 503 /{page}; return 503; }}")
            s.append("}")
            out.append("\n".join(s))
            continue

        s.append(f"    set $pcdn_proto {proto};")
        # client certificate towards this host's origin (only when it is reached over HTTPS)
        mtls_now[:] = mtls_lines if proto == "https" else []
        mtls_used = mtls_used or bool(mtls_now)
        if pool:
            s.append(f"    set $pcdn_pool {_q(pool)};")
            s.append("    set $pcdn_target $pcdn_upstream;")
        else:
            s.append(f"    set $pcdn_target {_q(target)};")
        # security verdict (njs): firewall, hotlink, rate limits, DDoS challenge, WAF
        gate = "$pcdn_gate" if shield_self else "$pcdn_verdict"   # a valid shield hop skips the verdict
        s.append(f"    if ({gate} !~ \"^(?:ok|log:)\") {{ rewrite ^ /__pcdn/deny/{gate}? last; }}")
        if sslo.get("force_https") and ssl:
            if force_https_tn:  # F34: redirect http, but never tunnel-path requests
                s.append(f"    if ($pcdn_httpredir_{sid}) {{ return 301 https://$host$request_uri; }}")
            else:
                s.append("    if ($scheme = http) { return 301 https://$host$request_uri; }")
        for code in rd_codes:   # SPEC §14.2 redirect rules (first matching rule, see redirect_maps)
            s.append(f"    if ({rd_var} ~ \"^{code}(.*)$\") {{ return {code} $1; }}")
        if body_on:
            s.append("    if ($pcdn_bodychk) { rewrite ^ /__pcdn/body$uri last; }")
        if image_on:
            s.append("    if ($pcdn_img_w) { rewrite ^ /__pcdn/img$uri last; }")
        if rps > 0:
            s.append(f"    limit_req zone=pcdn_rlk_{sid} burst={rps * 2} nodelay;")
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
        s += speed_locations(cfg, njs_ok, brotli_ok, bool(caps.get("flv")))
        if njs_ok:
            s.append("    location ^~ /__pcdn/deny/ { internal; js_content pcdn.deny; }")
            s.append("    location = /__pcdn/verify { js_content pcdn.verify; }")
            s.append("    location = /__pcdn/captcha { client_max_body_size 16k; client_body_buffer_size 16k; "
                     "js_content pcdn.captcha; }")
        else:  # no njs module (never a verdict other than "ok"): keep nginx -t passing
            s.append("    location ^~ /__pcdn/deny/ { internal; return 403; }")
        for cls in err_pages:
            s.append(f"    location = /__pcdn/err/{cls}.html {{ internal; default_type text/html; "
                     f"alias {cfg['NGINX_DIR']}/errors/{sid}-{cls}.html; add_header Cache-Control no-store always; }}")
        if body_on:
            # the body is read here (in memory: bodyNeed only routes requests whose declared length
            # fits), inspected, then proxied as is (never cached) with the original request URI
            s.append(f"    location ^~ /__pcdn/body/ {{ internal; client_max_body_size {BODY_CAP}; "
                     f"client_body_buffer_size {BODY_CAP}; client_body_in_single_buffer on; "
                     "js_content pcdn.bodyInspect; }")
            s += proxy_loc("@pcdn_body", "bypass", 0, 0, False, uri=body_uri)

        if image_on:
            L = ["internal;", "rewrite ^/__pcdn/img(/.*)$ $1 break;"]
            adds = []
            if cache_on:
                key, _ = cache_key(ignore_q, image=True)
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
                "proxy_set_header X-Pcdn-Q $pcdn_img_q;"]
            if mtls_now:   # the resizer presents this site's client certificate (mtls.conf)
                tok = mtls_token(mtls_id, mtls_pair)
                L.append(f"proxy_set_header X-Pcdn-Mtls {tok};")
                meta["mtls_resizer"] = (tok, mtls_pair)
            else:          # never let a visitor's own X-Pcdn-Mtls header reach the resizer
                L.append('proxy_set_header X-Pcdn-Mtls "";')
            L.append(f"proxy_pass http://127.0.0.1:{resize_port}{tf_uri};")
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

    if mtls_used and mtls_id != "platform":
        files[f"mtls/{sid}.crt"], files[f"mtls/{sid}.key"] = mtls_pair
    meta["mtls_platform"] = mtls_used and mtls_id == "platform"
    js = site_js(site, valid_hosts, pools, sslo, tunnel, tf_resp) if active and valid_hosts else None
    return "\n\n".join(out) + "\n", files, js, meta


MTLS_CHUNK = 3000   # nginx limits one config token to its 4 KiB read buffer


def mtls_token(ident: str, pair: tuple) -> str:
    """The X-Pcdn-Mtls value naming a client certificate for the image resizer: "<id>-<hash of the
    key>", so a visitor cannot pick a certificate by sending the header itself (client headers pass
    through an image location that does not set it). Deterministic: the tree digest stays stable."""
    return f"{ident}-" + hashlib.sha256(b"pcdn-mtls|" + pair[1].encode()).hexdigest()[:32]


def render_mtls_resizer(pairs: dict) -> str | None:
    """mtls.conf (0600): the client certificates the local image resizer presents to origins
    (SPEC §14.2), selected by the X-Pcdn-Mtls header the calling site sets (mtls_token). The
    resizer runs in unprivileged workers, so the PEM travels in variables ("data:...",
    nginx >= 1.21) instead of root-only files; long PEMs are split over several variables."""
    if not pairs:
        return None
    out = ["# client certificates for the image resizer (SPEC §14.2) — generated by pcdn-agent, do not edit"]
    sel = {"c": [], "k": []}
    for ident in sorted(pairs):
        for kind, pem in zip("ck", pairs[ident]):
            names = []
            for i in range(0, len(pem), MTLS_CHUNK):
                var = f"pcdn_m{kind}_{ident.split('-')[0]}_{i // MTLS_CHUNK}"
                out.append(f'map $uri ${var} {{\n    default "{pem[i:i + MTLS_CHUNK]}";\n}}')
                names.append("$" + var)
            sel[kind].append(f'    "{ident}" "data:{"".join(names)}";\n')
    for kind, var in (("c", "$pcdn_mtls_crt"), ("k", "$pcdn_mtls_key")):
        out.append(f"map $http_x_pcdn_mtls {var} {{\n    default \"\";\n" + "".join(sel[kind]) + "}")
    return "\n".join(out) + "\n"


def render_all(config: dict, cfg: dict) -> dict:
    with open(asset(cfg, "NJS_FILE", "njs/pcdn.js")) as f:
        files = {"js/pcdn.js": f.read()}
    js_sites = {}
    max_timeout = 1
    shield = norm_shield(config)   # node-wide (SPEC §14.1); None -> today's behaviour
    sh_conf = render_shield(shield, cfg)
    if sh_conf:
        files["shield.conf"] = sh_conf
    platform = norm_origin_pull(config)   # node-wide platform client certificate (SPEC §14.2)
    platform_pair = (platform["cert"], platform["key"]) if platform else None
    resizer_pairs, platform_used = {}, False
    for site in config.get("sites", []):
        text, extra, js, meta = _render_site(site, cfg, shield, platform_pair)
        files[f"sites/{int(site['id'])}.conf"] = text
        files.update(extra)
        platform_used = platform_used or meta.get("mtls_platform")
        if meta.get("mtls_resizer"):
            ident, pair = meta["mtls_resizer"]
            resizer_pairs[ident] = pair
        if js:
            js_sites[str(int(site["id"]))] = js
            for p in js["pools"].values():
                if p["health"]["enabled"]:
                    max_timeout = max(max_timeout, p["health"]["timeout"])
    if platform_used:   # one 0600 pair per node, only while some site presents it
        files["mtls/platform.crt"], files["mtls/platform.key"] = platform_pair
    # verified crawler ranges: only while some site uses bot management (a daily range refresh
    # must not reload nodes where nobody needs them)
    bots_conf = render_bots(norm_bot_ranges(config)) if any("bots" in j for j in js_sites.values()) else None
    if bots_conf:
        files["bots.conf"] = bots_conf
    mtls_conf = render_mtls_resizer(resizer_pairs)
    if mtls_conf:
        files["mtls.conf"] = mtls_conf
    files["http.conf"] = render_http(cfg, max_timeout + 1, shield, bool(bots_conf), bool(mtls_conf),
                                     norm_node(config, cfg))
    # JSON is valid JS; ensure_ascii keeps U+2028 & co. out of the source
    files["js/sites.js"] = ("// generated by pcdn-agent, do not edit\nexport default "
                            + json.dumps(js_sites, ensure_ascii=True, sort_keys=True) + ";\n")
    return files


CONFVER_MARKER = "__PCDN_CONFVER__"


def tree_digest(files: dict) -> str:
    """Order-independent digest of a rendered tree (F20/F29). Rendering is deterministic (sites.js
    uses sort_keys; decoy {{YEAR}} shifts once a year), so an identical config produces an identical
    digest and the agent can skip the write/test/reload."""
    h = hashlib.sha256()
    for rel in sorted(files):
        h.update(rel.encode() + b"\0" + files[rel].encode() + b"\0")
    return h.hexdigest()


def render_tree(config: dict, cfg: dict) -> tuple[dict, str]:
    """Rendered files plus the tree digest. The digest is computed over the tree while http.conf
    still carries the CONFVER_MARKER placeholder (F29: the digest must not depend on itself), then
    substituted into the /__pcdn/confver endpoint so the agent can verify the reload took effect."""
    files = render_all(config, cfg)
    digest = tree_digest(files)
    if "http.conf" in files:
        files["http.conf"] = files["http.conf"].replace(CONFVER_MARKER, digest)
    return files, digest


def _group_digests(files: dict, pattern: str) -> dict:
    """Per-site digests of the rendered files whose path matches `pattern` (F21)."""
    groups: dict = {}
    for rel in sorted(files):
        m = re.match(pattern, rel)
        if m:
            groups.setdefault(m.group(1), []).append(rel)
    return {sid: tree_digest({rel: files[rel] for rel in rels}) for sid, rels in groups.items()}


def site_digests(files: dict) -> dict:
    """Per-site content digest (config + certs + error pages) for group-aware reload deferral (F21)."""
    return _group_digests(files, r"^(?:sites|certs|errors|mtls)/(\d+)")


def cert_digests(files: dict) -> dict:
    """Per-site certificate/key digest, so a foreign-group site's cert rotation is never deferred."""
    return _group_digests(files, r"^certs/(\d+)\.")


GLOBAL_FILES = ("http.conf", "js/pcdn.js", "shield.conf", "bots.conf", "mtls.conf", "mtls/platform.crt",
                "mtls/platform.key")


def global_digest(files: dict) -> str:
    """Digest of the node-global rendered files (base http.conf + njs module + shield.conf): any
    change here affects every site and must not be deferred (F21)."""
    return tree_digest({k: files[k] for k in GLOBAL_FILES if k in files})


def verify_reload(cfg: dict, digest: str) -> bool:
    """Poll /__pcdn/confver (localhost) until it returns the digest of the tree just written, or the
    RELOAD_VERIFY budget expires (F29). A reload the nginx master rejected keeps serving the old
    digest, so the caller can retry instead of recording the config as applied."""
    port = _int(cfg.get("HTTP_PORT"), 80, 1, 65535)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    deadline = time.monotonic() + 10
    url = f"http://127.0.0.1:{port}/__pcdn/confver"
    while time.monotonic() < deadline:
        try:
            with opener.open(url, timeout=2) as r:
                if r.read().decode("utf-8", "replace").strip() == digest:
                    return True
        except Exception:  # noqa: BLE001 - connection refused mid-reload etc.: keep polling
            pass
        time.sleep(0.3)
    return False


# ----------------------------------------------------------------- apply

def run(cmd: str) -> tuple[int, str]:
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return p.returncode, (p.stdout + p.stderr).strip()


def write_tree(root: str, files: dict):
    os.makedirs(os.path.join(root, "sites"), exist_ok=True)
    os.makedirs(os.path.join(root, "certs"), mode=0o700, exist_ok=True)
    if any(rel.startswith("mtls/") for rel in files):
        os.makedirs(os.path.join(root, "mtls"), mode=0o700, exist_ok=True)
    for rel, content in files.items():
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        # keys and the HMAC / shield secrets are only read by the nginx master (root) at load time;
        # so are the origin-pull client certificates (mtls/, mtls.conf; SPEC §14.2)
        mode = 0o600 if (rel.endswith(".key") or rel in ("js/sites.js", "shield.conf", "mtls.conf")
                         or rel.startswith("mtls/")) else 0o644
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


def apply_config(config: dict, cfg: dict, files: dict | None = None, digest: str | None = None) -> str | None:
    """Atomically swap the rendered tree in; roll back if nginx rejects it. `files`/`digest` may be
    passed pre-rendered (F20/F29) to avoid a second render; otherwise they are rendered here."""
    root = cfg["NGINX_DIR"].rstrip("/")
    new, old = root + ".new", root + ".old"
    shutil.rmtree(new, ignore_errors=True)
    shutil.rmtree(old, ignore_errors=True)
    if files is None:
        files, digest = render_tree(config, cfg)
    write_tree(new, files)
    ensure_cache_dirs(config, cfg)
    ensure_speed_file(cfg)   # SPEC §15.6 (once; outside the swapped tree)

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
    # F29: confirm the master actually applied the new tree (a rejected reload keeps the old one).
    if digest and str(cfg.get("RELOAD_VERIFY", "yes")).lower() in ("1", "yes", "true", "on"):
        if not verify_reload(cfg, digest):
            return "nginx reload not applied (see error.log)"
    return None


def bootstrap(cfg: dict):
    """Empty tree so nginx can start before the first successful sync."""
    root = cfg["NGINX_DIR"].rstrip("/")
    if not os.path.exists(os.path.join(root, "http.conf")):
        files, _ = render_tree({"sites": []}, cfg)
        write_tree(root, files)
    os.makedirs(cfg["CACHE_DIR"], exist_ok=True)
    ensure_speed_file(cfg)


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
    # an nginx swap (install.sh --http3) changes what can be rendered (SPEC §14.1)
    h.update(json.dumps(nginx_capabilities(cfg), sort_keys=True).encode())
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


def _arg(query: str, name: str) -> str:
    """nginx $arg_<name> semantics: raw value of the first `name=` parameter (name case-insensitive)."""
    for part in query.split("&"):
        k, eq, v = part.partition("=")
        if eq and k.lower() == name.lower():
            return v
    return ""


def url_key_bases(path: str, kinfo: dict | None) -> list[str]:
    """The "<uri>" parts (after scheme://host) an exact URL can be cached under: the full request
    URI, the query-less path (ignore_query) and, for cache.key_query_allow sites, the path with
    only the allowed parameters in their configured order (SPEC §14.1)."""
    noq, _, query = path.partition("?")
    bases = [path, noq]
    if kinfo and kinfo.get("qa"):
        bases.append(noq + "?" + "&".join(f"{n}={_arg(query, n)}" for n in kinfo["qa"]))
    return list(dict.fromkeys(bases))


def key_suffixes(kinfo: dict | None) -> list[str] | None:
    """Every variant suffix of a key when they can be enumerated (device class, WebP flag), or None
    when cookie values are part of the key (the cache then has to be scanned)."""
    if not kinfo:
        return [""]
    if kinfo.get("cookies"):
        return None
    devs = [";d=mobile", ";d=desktop"] if kinfo.get("dev") else [""]
    webps = [";w=", ";w=0", ";w=1"] if kinfo.get("webp") else [""]
    return [d + w for d in devs for w in webps]


def purge_exact_scan(base: str, targets: set, fields: int, scan_max: int) -> tuple[int, bool]:
    """Delete cache files whose KEY minus its `fields` trailing ";<field>" parts is in `targets`."""
    if not targets or not os.path.isdir(base):
        return 0, False
    removed = scanned = 0
    for root, _dirs, names in os.walk(base):
        for name in names:
            scanned += 1
            if scanned > scan_max:
                return removed, True
            fpath = os.path.join(root, name)
            key = _read_cache_key(fpath)
            if key is None:
                continue
            if (key.rsplit(";", fields)[0] if fields else key) in targets:
                try:
                    os.remove(fpath)
                    removed += 1
                except OSError:
                    pass
    return removed, False


def do_purge(item: dict, cfg: dict, kinfo: dict | None = None) -> int:
    """kinfo: the site's cache-key options (key_infos) when its keys carry variants."""
    sid = int(item["site_id"])
    base = os.path.join(cfg["CACHE_DIR"], str(sid))
    urls = item.get("urls") or []
    prefixes = item.get("prefixes") or []
    everything = bool(item.get("everything"))
    # whole-site wipe: explicit `everything`, or the legacy empty-urls request (no prefixes either)
    if everything or (not urls and not prefixes):
        return wipe_cache(base)
    removed = 0
    scan_max = _int(cfg.get("PURGE_SCAN_MAX"), 500000, 1, 10 ** 9)
    suffixes = key_suffixes(kinfo)
    scan_targets = set()
    for url in urls:  # exact URLs keep the fast hashed-key delete
        m = re.match(r"^https?://([^/?#]+)([^#]*)", url)
        if not m:
            continue
        host, path = m.group(1).lower(), m.group(2) or "/"
        if not path.startswith("/"):
            path = "/" + path
        # cache keys are "$scheme://$host$request_uri", or "$scheme://$host$pcdn_path"
        # (query dropped) on sites with ignore_query: remove both variants (plus the
        # key_query_allow form and every device/WebP variant, SPEC §14.1)
        for scheme in ("http", "https"):
            for p in url_key_bases(path, kinfo):
                if suffixes is None:   # cookie-keyed variants: found by scanning below
                    scan_targets.add(f"{scheme}://{host}{p}")
                    continue
                for suf in suffixes:
                    try:
                        os.remove(cache_file(cfg["CACHE_DIR"], sid, f"{scheme}://{host}{p}{suf}"))
                        removed += 1
                    except FileNotFoundError:
                        pass
    if scan_targets:
        fields = int(bool(kinfo.get("dev"))) + len(kinfo.get("cookies") or []) + int(bool(kinfo.get("webp")))
        n, overflow = purge_exact_scan(base, scan_targets, fields, scan_max)
        if overflow:
            log.warning("purge scan cap %d exceeded for site %s; falling back to full purge", scan_max, sid)
            return wipe_cache(base)
        removed += n
    if prefixes:
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


_TS_MEMO: list = [None, None]   # last access-log timestamp -> (UTC datetime, hour key, minute key)


def _times(ts: str) -> tuple:
    """(UTC datetime, "YYYY-MM-DDTHH:00:00Z", "YYYY-MM-DDTHH:MM:00Z") of an access-log timestamp,
    memoised for the last value (consecutive lines mostly share a second)."""
    if _TS_MEMO[0] == ts:
        return _TS_MEMO[1]
    dt = _utc(ts)
    v = (dt, dt.strftime("%Y-%m-%dT%H:00:00Z"), dt.strftime("%Y-%m-%dT%H:%M:00Z"))
    _TS_MEMO[0], _TS_MEMO[1] = ts, v
    return v


CACHE_SERVED = ("HIT", "STALE", "UPDATING", "REVALIDATED")
SECURITY_ACTIONS = ("block", "challenge", "captcha")
# 5xx answers nginx gives to a malformed / unsupported CLIENT request (unknown transfer coding or
# method, bad HTTP version): client-triggerable, so they never count against the platform
CLIENT_5XX = (501, 505)


def platform_error(e: dict) -> bool:
    """SPEC §14.3.1 `platform_errors`: is this access-log record a 5xx the edge produced itself?

    Counted only when ALL of these hold:
      * status 500..599, except 501 / 505 (nginx's answer to an unsupported client request: the
        visitor can trigger it at will, so it says nothing about the platform);
      * the record carries the "us" field (a pre-6D log line without it is never counted: no
        evidence either way) and it is empty: no upstream was contacted. Any value - "502" (origin
        connect failure / bad gateway), "504" (origin timeout), "-" (upstream state without a
        status), "502, 200" (several attempts) - means the origin was involved: an origin error;
      * the response was not served from the cache (HIT / STALE / UPDATING / REVALIDATED: content
        the origin produced earlier);
      * no security action: the verdict "v" is not block / challenge / captcha (WAF, firewall,
        rate-limit, DDoS, bot, hotlink decisions are the customer's settings, not errors; "log:..."
        verdicts are not actions);
      * it is not the suspended / over-quota page of the site ("pg" = "site": the site's own status).
    What remains: e.g. njs or internal nginx failures (500), an origin hostname that the edge's
    resolver could not resolve (502, nginx records no upstream for it - the SPEC rule counts it),
    and a customer error page served for such an edge-produced 5xx."""
    try:
        code = int(e.get("s") or 0)
    except (TypeError, ValueError):
        return False
    if code < 500 or code > 599 or code in CLIENT_5XX:
        return False
    if "us" not in e or str(e.get("us") or "").strip():
        return False
    if e.get("c") in CACHE_SERVED:
        return False
    if str(e.get("v") or "ok").split(":", 1)[0] in SECURITY_ACTIONS:
        return False
    return not e.get("pg")


# ---- tunnel quality (SPEC §15.1)
TUNNEL_ERRORS = ("origin_refused", "origin_timeout", "origin_error", "limit", "country", "protocol", "edge")
ORIGIN_DOWN_ERRORS = ("origin_refused", "origin_timeout")   # SPEC §15.4 live `tunnel_errors`
TUNNEL_PATHS_MAX = 50                                         # path ids per host-hour
_ACCEPTED = re.compile(r"^(?:101|2\d\d)$")
_LIST_SPLIT = re.compile(r"\s*[,:]\s*")


def _last_value(v) -> str:
    """Last entry of an nginx per-attempt list ("502, 101", "0.001 : -"); "" when empty."""
    parts = [x for x in _LIST_SPLIT.split(str(v or "").strip()) if x]
    return parts[-1] if parts else ""


def classify_tunnel(e: dict) -> str | None:
    """Outcome of one tunnel access-log line (tn set): "session", one of TUNNEL_ERRORS, or None
    (not counted either way). Rules, first match wins - pinned against real nginx 1.24 output in
    test_tunnel_quality_e2e.py ($status / $upstream_status "us" / $upstream_connect_time "uct"):

      1. grpc path over HTTP/1.x ("pr" HTTP/1.0/1.1)       -> protocol (a gRPC client is always HTTP/2;
                                                              nginx still forwards it, so the status
                                                              alone cannot tell)
      2. status 101 or 2xx                                 -> session
      3. status 499 and the last us is 101/2xx             -> session (client closed an accepted stream:
                                                              a clean end, never abnormal)
         status 499 otherwise                              -> None (client gave up first, e.g. while the
                                                              edge was still connecting)
      4. no upstream contacted (us "" or absent):
           429 / 503                                       -> limit (limit_conn per site / per IP, fair
                                                              share, F35 cut 503)
           403                                             -> country (the only 403 inside a tunnel
                                                              location; firewall blocks are rewritten to
                                                              the deny location and carry no tn)
           400 / 426                                       -> protocol (426: ws/httpupgrade without
                                                              Upgrade, answered by the edge)
           5xx                                             -> edge (e.g. an origin hostname the edge
                                                              could not resolve)
           anything else                                   -> None
      5. last us = 502 (connect refused / reset, "uct" "-", or closed before a response header)
                                                           -> origin_refused
         last us = 504 (connect or header timeout)        -> origin_timeout
         last us not a number ("-"): status 504 -> origin_timeout, 502 -> origin_refused,
                                     other 5xx -> edge, else None
         last us any other number (the origin answered, but not 101/2xx: 400/404/5xx ...)
                                                           -> origin_error
    An origin that itself answers 502/504 (e.g. its own reverse proxy) is indistinguishable from a
    connect failure in the access log and is counted as refused / timeout."""
    try:
        code = int(e.get("s") or 0)
    except (TypeError, ValueError):
        return None
    if e.get("tn") == "grpc" and str(e.get("pr") or "").startswith("HTTP/1"):
        return "protocol"
    if code == 101 or 200 <= code < 300:
        return "session"
    us = _last_value(e.get("us"))
    if code == 499:
        return "session" if _ACCEPTED.match(us) else None
    if not us:
        if code in (429, 503):
            return "limit"
        if code == 403:
            return "country"
        if code in (400, 426):
            return "protocol"
        return "edge" if 500 <= code <= 599 else None
    if us == "502":
        return "origin_refused"
    if us == "504":
        return "origin_timeout"
    if not us.isdigit():
        if code == 504:
            return "origin_timeout"
        if code == 502:
            return "origin_refused"
        return "edge" if 500 <= code <= 599 else None
    return "origin_error"


def connect_ms(e: dict) -> int | None:
    """$upstream_connect_time of the attempt that connected (the last one), in ms; None without one."""
    v = _last_value(e.get("uct"))
    try:
        return int(round(float(v) * 1000)) if v and v != "-" else None
    except ValueError:
        return None


def _new_tpath() -> dict:
    return {"sessions": 0, "seconds": 0.0, "bytes_up": 0, "bytes_down": 0, "abnormal": 0, "connect_ms_sum": 0,
            "connect_n": 0, "errors": dict.fromkeys(TUNNEL_ERRORS, 0)}


def _tpath(t: dict, pid: str) -> dict | None:
    """The per-path counters of a host-hour tunnel object (≤ TUNNEL_PATHS_MAX ids; None beyond)."""
    paths = t.setdefault("paths", {})
    p = paths.get(pid)
    if p is None:
        if len(paths) >= TUNNEL_PATHS_MAX:
            return None
        p = paths[pid] = _new_tpath()
    return p


# ---- live minute aggregates (SPEC §14.3.1)
LIVE_MAX = 5000                    # `live` items per usage POST
LIVE_TOP = 20                      # top countries / paths per item
LIVE_PATH_TRACK = 100              # distinct paths counted per host-minute before taking the top
LIVE_CC_TRACK = 64                 # distinct countries counted per host-minute
LIVE_PATH_LEN = 256
LIVE_PENDING_MAX = 20000           # host-minutes held between two pushes (oldest dropped beyond)
LIVE_MAX_BYTES = 2 * 1024 * 1024   # estimated JSON size of the `live` list of one POST
LIVE_BACKLOG_MAX = 20000           # live items kept across the whole outbox (newest win)
LIVE_BACKLOG_BYTES = 8 * 1024 * 1024
LIVE_WINDOW = 86400                # the controller keeps 24 h of minutes; older ones are never sent


def live_cutoff(now: float | None = None) -> str:
    """Minute key 24 h ago: live buckets older than this are not counted or sent."""
    t = time.time() if now is None else now
    return datetime.fromtimestamp(t - LIVE_WINDOW, timezone.utc).strftime("%Y-%m-%dT%H:%M:00Z")


def _prune_live(live: dict):
    """Drop the oldest quarter of the pending host-minutes (amortised: called at the cap)."""
    keys = sorted(live, key=lambda k: k.rsplit("|", 1)[1])
    for k in keys[: max(1, len(keys) // 4)]:
        del live[k]


def _account_live(live: dict, host: str, minute: str, nbytes: int, hit: bool, code: int, cc: str, path: str,
                  tunnel: str | None = None):
    """tunnel: None for a request without a tunnel path id, else its classify_tunnel() outcome
    ("" when the line is not counted as a session or an error)."""
    key = f"{host}|{minute}"
    b = live.get(key)
    if b is None:
        if len(live) >= LIVE_PENDING_MAX:
            _prune_live(live)
        b = live[key] = {"requests": 0, "bytes": 0, "cache_hits": 0, "status": {}, "countries": {}, "paths": {}}
    b["requests"] += 1
    b["bytes"] += nbytes
    if hit:
        b["cache_hits"] += 1
    if 200 <= code <= 599:
        _inc(b["status"], f"{code // 100}xx")
    if cc and (cc in b["countries"] or len(b["countries"]) < LIVE_CC_TRACK):
        _inc(b["countries"], cc)
    if path:
        path = path[:LIVE_PATH_LEN]
        if path in b["paths"] or len(b["paths"]) < LIVE_PATH_TRACK:
            _inc(b["paths"], path)
    # SPEC §15.4 (controller contract): attempts = every tunnel request attributed to a path id in
    # this minute, whatever its outcome; errors = the origin_refused + origin_timeout ones among them
    if tunnel is not None:
        b["tunnel_attempts"] = b.get("tunnel_attempts", 0) + 1
        if tunnel in ORIGIN_DOWN_ERRORS:
            b["tunnel_errors"] = b.get("tunnel_errors", 0) + 1


def _top(d: dict, n: int) -> dict:
    return dict(sorted(d.items(), key=lambda kv: (-kv[1], kv[0]))[:n])


def live_item(key: str, b: dict) -> dict | None:
    """One `live` entry: {host, minute, requests, bytes, cache_hits, status, countries (top 20),
    paths (top 20, query already stripped)}. None for a host the controller would reject."""
    host, minute = key.rsplit("|", 1)
    if not host or len(host) > 253:
        return None

    def cnt(d):   # the controller rejects the WHOLE usage POST (422) on a negative number
        return {k: max(0, int(v)) for k, v in d.items()}
    item = {"host": host, "minute": minute, "requests": max(0, int(b.get("requests") or 0)),
            "bytes": max(0, int(b.get("bytes") or 0)), "cache_hits": max(0, int(b.get("cache_hits") or 0)),
            "status": cnt(b.get("status") or {}), "countries": cnt(_top(b.get("countries") or {}, LIVE_TOP)),
            "paths": cnt(_top(b.get("paths") or {}, LIVE_TOP))}
    if b.get("tunnel_attempts"):   # SPEC §15.4, optional: only minutes with tunnel attempts carry them
        item["tunnel_attempts"] = max(0, int(b["tunnel_attempts"]))
        item["tunnel_errors"] = max(0, int(b.get("tunnel_errors") or 0))
    return item


def _live_size(item: dict) -> int:
    """Cheap upper estimate of an item's JSON size (bytes)."""
    return (200 + len(item["host"]) + sum(len(k) + 12 for k in item["paths"])
            + 10 * len(item["countries"]) + 12 * len(item["status"]))


def _select_live(items: list, cutoff: str, max_items: int, max_bytes: int) -> list:
    """Newest minutes first within the caps (older ones are dropped), returned oldest first."""
    keep = []
    for it in sorted((x for x in items if x["minute"] >= cutoff), key=lambda x: x["minute"], reverse=True):
        size = _live_size(it)
        if len(keep) >= max_items or size > max_bytes:
            break
        keep.append(it)
        max_bytes -= size
    keep.reverse()
    return keep


def live_items(live: dict, cutoff: str) -> list[dict]:
    """The pending host-minutes as one POST's `live` list (≤ LIVE_MAX, ≤ LIVE_MAX_BYTES, no minute
    older than 24 h; when there are more, the OLDEST minutes are dropped - live data is best-effort)."""
    items = [it for it in (live_item(k, v) for k, v in live.items()) if it]
    return _select_live(items, cutoff, LIVE_MAX, LIVE_MAX_BYTES)


def trim_live_backlog(outbox: list, cutoff: str):
    """Bound the live data held in the usage outbox (controller unreachable): drop minutes older than
    24 h and keep only the newest LIVE_BACKLOG_MAX items / LIVE_BACKLOG_BYTES across all entries.
    Only `live` is ever trimmed - an entry's hourly items and events, and its batch_id, are untouched,
    so a retried batch stays idempotent (the controller dedups the whole body on batch_id)."""
    n, size = LIVE_BACKLOG_MAX, LIVE_BACKLOG_BYTES
    for entry in reversed(outbox):          # newest entries first
        live = entry.get("live")
        if not live:
            continue
        keep = _select_live(live, cutoff, n, size) if n > 0 and size > 0 else []
        n -= len(keep)
        size -= sum(_live_size(x) for x in keep)
        if keep:
            entry["live"] = keep
        else:
            entry.pop("live", None)


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


_CC = re.compile(r"^[A-Z]{2}$")


def _account(e: dict, pending: dict, events: list, live: dict | None = None, cutoff: str = "",
             ship=None, raw: bytes | None = None):
    """Fold one access-log record into the host-hour (`pending`), the security `events`, the
    host-minute `live` buckets (SPEC §14.3.1; minutes before `cutoff` skipped) and, for sites with
    log export, the sampler `ship` (SPEC §14.3.2; `raw` is the log line, the sampling key)."""
    host = e["h"].lower()
    dt, hour, minute = _times(e["t"])
    a = _bucket(pending, f"{host}|{hour}")
    nbytes = int(e.get("b") or 0)
    a["bytes"] += nbytes
    a["requests"] += 1
    hit = e.get("c") in CACHE_SERVED
    if hit:
        a["cache_hits"] += 1
    code = int(e.get("s") or 0)
    if 100 <= code <= 599:
        _inc(a["status"], f"{code // 100}xx")
        _inc(a["codes"], str(code))
        if code >= 500 and platform_error(e):
            a["platform_errors"] = a.get("platform_errors", 0) + 1
    cc = str(e.get("cc") or "").upper()
    if not _CC.match(cc):
        cc = ""
    if cc:
        _inc(a["countries"], cc)
    uri = str(e.get("u") or "")
    path = uri.split("?", 1)[0][:512] if uri else ""
    if path and (path in a["paths"] or len(a["paths"]) < PATH_TRACK):
        _inc(a["paths"], path)
    tn = e.get("tn")
    tcls = live_tn = None
    if tn in TUNNEL_PROTOCOLS:
        tcls = classify_tunnel(e)
        _account_tunnel(a, e, tn, code, tcls)
        if e.get("tp"):
            live_tn = tcls or ""
    parts = str(e.get("v") or "ok").split(":", 2)
    if len(parts) == 3 and parts[0] in ("block", "challenge", "captcha", "log"):
        action, source, rule = parts
        _inc(a["security"], source)
        if action in ("challenge", "captcha"):
            _inc(a["security"], "challenge")
        events.append({"t": dt.strftime("%Y-%m-%dT%H:%M:%SZ"), "host": host, "ip": str(e.get("ip") or ""),
                       "country": cc, "method": str(e.get("m") or ""), "path": uri[:2048], "action": action,
                       "source": source, "rule": rule, "user_agent": str(e.get("ua") or "")[:512]})
    # best-effort extras last, so nothing in them can cut the hourly / security accounting short
    if live is not None and minute >= cutoff:
        _account_live(live, host, minute, nbytes, hit, code, cc, path, live_tn)
    if ship is not None:
        try:
            ship.offer(e, host, dt, raw)
        except Exception as exc:  # noqa: BLE001 - log export must never break usage accounting
            log.debug("logship: record skipped: %s", exc)


def _nsum(v) -> int:
    """Sum of an nginx multi-upstream value ("12, 34 : 5"; "-" / "" = 0)."""
    return sum(int(x) for x in re.findall(r"\d+", str(v or "")))


def _account_tunnel(a: dict, e: dict, proto: str, code: int, tcls: str | None = None):
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
    # F37: $request_length ($bu) already counts the request head + body the client sent. Only
    # ws/httpupgrade omit post-101 upgrade frames from it, so only those consult $upstream_bytes_sent
    # ($ub); for grpc/h2/xhttp bill $bu and drop the edge-injected header delta / retry re-sends.
    bu = int(e.get("bu") or 0)
    up = max(bu, _nsum(e.get("ub"))) if proto in ("ws", "httpupgrade") else (bu or max(bu, _nsum(e.get("ub"))))
    down = int(e.get("b") or 0)
    t["bytes_up"] += up
    t["bytes_down"] += down
    _inc(t["by_protocol"], proto, up + down)
    # SPEC §15.1 per path id ("tp"; lines without it - pre-wave-7 - only feed the totals above)
    pid = str(e.get("tp") or "")
    if not pid or not SAFE_ID.match(pid):
        return
    p = _tpath(t, pid)
    if p is None:
        return
    p["bytes_up"] += up
    p["bytes_down"] += down
    if tcls == "session":
        p["sessions"] += 1
        try:
            p["seconds"] += max(0.0, float(e.get("rt") or 0))
        except (TypeError, ValueError):
            pass
    elif tcls in TUNNEL_ERRORS:
        p["errors"][tcls] = p["errors"].get(tcls, 0) + 1
    ms = connect_ms(e)
    if ms is not None:   # every tunnel request whose (last) upstream connect succeeded, whatever came next
        p["connect_ms_sum"] += ms
        p["connect_n"] += 1


def _consume(path: str, pos: int, state: dict, max_bytes: int, deadline: float | None = None,
             ship=None, cutoff: str | None = None) -> int:
    """Aggregate complete lines from path starting at pos with O(line) memory (F24); returns the new
    position. Stops after max_bytes or the time budget, so a huge backlog is drained over ticks
    instead of held in RAM 2-3x on one thread. A partial trailing line is left for the next read.
    Also fills state['live'] (host-minutes since `cutoff`) and feeds the log-export sampler `ship`."""
    pending = state.setdefault("pending", {})
    events = state.setdefault("events", [])
    live = state.setdefault("live", {})
    cutoff = live_cutoff() if cutoff is None else cutoff
    read = 0
    with open(path, "rb", buffering=1 << 20) as f:
        f.seek(pos)
        for raw in f:
            if not raw.endswith(b"\n"):
                break  # partial line at EOF: re-read it next time
            pos += len(raw)
            read += len(raw)
            try:
                _account(json.loads(raw), pending, events, live, cutoff, ship, raw)
            except (ValueError, KeyError, TypeError, AttributeError):
                pass
            if read >= max_bytes or (deadline is not None and time.monotonic() > deadline):
                break
    return pos


def _drain_rotated(state: dict, log_path: str, max_bytes: int, deadline: float | None, ship=None) -> bool:
    """Drain the rotated (.1) file recorded in state across ticks (F24). Returns True while more of
    it remains (so the caller can defer the live file to the next tick)."""
    rotated = log_path + ".1"
    try:
        rst = os.stat(rotated)
    except (FileNotFoundError, OSError):
        state.pop("rot_inode", None), state.pop("rot_pos", None)
        return False
    if rst.st_ino != state.get("rot_inode"):
        state.pop("rot_inode", None), state.pop("rot_pos", None)
        return False
    newpos = _consume(rotated, int(state.get("rot_pos", 0)), state, max_bytes, deadline, ship)
    if newpos >= rst.st_size:  # fully drained
        state.pop("rot_inode", None), state.pop("rot_pos", None)
        return False
    state["rot_pos"] = newpos
    return True


def read_usage(state: dict, log_path: str, max_bytes: int = 64 * 1024 * 1024, time_budget: float = 5.0,
               ship=None) -> None:
    """Consume new access-log lines and merge them into state['pending'] / state['events'] /
    state['live']; sampled log-export records go to `ship` (a LogShip, None = export off)."""
    deadline = time.monotonic() + time_budget
    # finish any rotated file still being drained from an earlier tick before touching the live file
    if state.get("rot_inode") is not None and _drain_rotated(state, log_path, max_bytes, deadline, ship):
        return
    try:
        st = os.stat(log_path)
    except FileNotFoundError:
        return
    pending = state.setdefault("pending", {})
    pos = state.get("log_pos", 0)
    if state.get("log_inode") not in (None, st.st_ino):
        # logrotate moved the file: record the old one (now .1) to drain across ticks, start new at 0
        state["rot_inode"], state["rot_pos"] = state["log_inode"], pos
        pos = 0
        _drain_rotated(state, log_path, max_bytes, deadline, ship)
    elif st.st_size < pos:
        pos = 0  # truncated
    state["log_pos"] = _consume(log_path, pos, state, max_bytes, deadline, ship)
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
    item = {"host": host, "hour": hour, "bytes": a["bytes"], "requests": a["requests"], "cache_hits": a["cache_hits"],
            # SPEC §14.3.1: edge-produced 5xx of this host-hour (see platform_error); 0 when none
            "platform_errors": int(a.get("platform_errors") or 0)}
    for k in ("status", "codes", "countries", "security"):
        if a[k]:
            item[k] = a[k]
    if a.get("tunnel"):
        t = a["tunnel"]
        item["tunnel"] = {"sessions": t["sessions"], "seconds": int(round(t["seconds"])), "bytes_up": t["bytes_up"],
                          "bytes_down": t["bytes_down"], "by_protocol": dict(t["by_protocol"])}
        if t.get("paths"):   # SPEC §15.1 (optional; pre-wave-7 agents omit it)
            item["tunnel"]["paths"] = {pid: tpath_item(p) for pid, p in sorted(t["paths"].items())}
    if a["paths"]:
        item["paths"] = dict(sorted(a["paths"].items(), key=lambda kv: (-kv[1], kv[0]))[:PATHS_PER_ITEM])
    return item


def tpath_item(p: dict) -> dict:
    """Wire shape of one `tunnel.paths` entry (SPEC §15.1): integers only, all seven error keys."""
    def n(v):
        try:
            return max(0, int(round(float(v or 0))))
        except (TypeError, ValueError):
            return 0
    errs = p.get("errors") or {}
    return {"sessions": n(p.get("sessions")), "seconds": n(p.get("seconds")), "bytes_up": n(p.get("bytes_up")),
            "bytes_down": n(p.get("bytes_down")), "abnormal": n(p.get("abnormal")),
            "connect_ms_sum": n(p.get("connect_ms_sum")), "connect_n": n(p.get("connect_n")),
            "errors": {k: n(errs.get(k)) for k in TUNNEL_ERRORS}}


def usage_items(pending: dict) -> list[dict]:
    return [usage_item(k, v) for k, v in pending.items()]


# ----------------------------------------------------------------- log export (SPEC §14.3.2)
#
# Per site the edge config carries `logs: {enabled, sample_rate, anonymize_ip}` (never the bucket or
# keys). While the agent reads the access log for usage it samples the records of enabled sites,
# builds the export record (anonymizing the IP first), and appends it to a batch; full batches (5000
# records or ~2 MiB) and, after each read, the partial one are written to the on-disk spool, one file
# per batch whose name carries its batch_id. Shipping runs on its own cadence after config / purges /
# usage in the same loop: oldest batch first, `POST /edge/v1/logship {batch_id, records}`, the file is
# deleted only on success and the SAME batch_id is resent on any retry (the controller dedups it).

LOGSHIP_MAX_RECORDS = 5000               # per batch = per POST (SPEC §14.3.2)
LOGSHIP_BATCH_BYTES = 2 * 1024 * 1024    # a batch is also closed at ~2 MiB, so one POST stays short
LOGSHIP_MAX_AGE = 72 * 3600              # the controller drops older records; so does the spool
LOGSHIP_RUN_BUDGET = 5.0                 # seconds per run after which no new POST is started
# CPU seconds record building may take per access-log read pass (that pass has 5 s for everything):
# beyond it the sampled records of the pass are dropped (counted), so export never slows usage
LOGSHIP_SAMPLE_BUDGET = 2.0
LOGSHIP_BACKOFF = (30, 900)              # first / max seconds between attempts after a failure
LOGSHIP_WARN_EVERY = 600                 # at most one "dropped" warning per 10 minutes
SPOOL_FILE = re.compile(r"^(\d{13})-([0-9a-f]{32})-(\d{1,6})\.jsonl$")


_IP_MEMO: dict = {}   # (address, anonymize) -> export value; visitors repeat, parsing an IP does not
_ISO_MEMO: list = [None, ""]
_JSON_LINE = json.JSONEncoder(ensure_ascii=False, separators=(",", ":"), check_circular=False)


def anonymize_ip(value) -> str:
    """IPv4: last octet zeroed; IPv6: only the first 48 bits kept (an IPv4-mapped IPv6 address is
    treated as IPv4); "" when not an IP. Idempotent, like the controller's re-application."""
    try:
        ip = ipaddress.ip_address(str(value or "").strip().strip("[]"))
    except ValueError:
        return ""
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if ip.version == 4:
        return str(ipaddress.IPv4Address(int(ip) & 0xFFFFFF00))
    return str(ipaddress.IPv6Address(int(ip) >> 80 << 80))   # drops any %zone as well


def _clean_ip(value) -> str:
    try:
        return str(ipaddress.ip_address(str(value or "").strip().strip("[]")))
    except ValueError:
        return ""


def _s(v, n: int) -> str:
    """Visitor-controlled text, truncated to n characters. nginx logs non-UTF-8 bytes raw and
    json.loads(bytes) decodes them with surrogatepass, so a lone surrogate is replaced (U+FFFD): the
    record must stay encodable as UTF-8 all the way into the customer's export."""
    s = ("" if v is None else str(v))[:n]
    return s if s.isascii() else s.encode("utf-8", "surrogatepass").decode("utf-8", "replace")[:n]


def _no_query(v, n: int) -> str:
    """Path / URL without query string and fragment, truncated to n characters."""
    return _s(("" if v is None else str(v)).split("?", 1)[0].split("#", 1)[0], n)


def _num(v, cast, default=0):
    try:
        x = cast(v)
    except (TypeError, ValueError):
        return default
    return x if x == x and 0 <= x < 10 ** 15 else default   # NaN / negative / absurd -> default


def _export_ip(value, anonymize: bool) -> str:
    key = (value, anonymize)
    v = _IP_MEMO.get(key)
    if v is None:
        v = anonymize_ip(value) if anonymize else _clean_ip(value)
        if len(_IP_MEMO) >= 65536:
            _IP_MEMO.clear()
        _IP_MEMO[key] = v
    return v


def log_record(e: dict, host: str, dt: datetime, anonymize: bool) -> dict:
    """The export record of one access-log line (SPEC §14.3.2), IP already anonymized when asked.
    Keys in the order the controller writes them to the customer's objects."""
    cc = str(e.get("cc") or "").upper()
    if _ISO_MEMO[0] != dt:
        _ISO_MEMO[0], _ISO_MEMO[1] = dt, dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    ip = e.get("ip")
    return {"t": _ISO_MEMO[1], "host": _s(host, 253),
            "ip": _export_ip(ip if isinstance(ip, str) else str(ip or ""), anonymize),
            "method": _s(e.get("m"), 16), "scheme": _s(e.get("sc"), 8), "path": _no_query(e.get("u"), 2048),
            "status": _num(e.get("s"), int), "bytes": _num(e.get("b"), int),
            "rt": round(_num(e.get("rt"), float, 0.0), 3), "cache": _s(e.get("c"), 16),
            "country": cc if _CC.match(cc) else "", "ua": _s(e.get("ua"), 512),
            "referer": _no_query(e.get("rf"), 1024), "proto": _s(e.get("pr"), 16)}


def sample_point(raw: bytes) -> float:
    """Deterministic sampling key in [0, 1): a hash of the raw log line. The same line always gets
    the same decision (a re-read after a restart samples identically, tests are reproducible) and
    distinct lines are spread uniformly, so `sample_point(line) < sample_rate` keeps that fraction."""
    return int.from_bytes(hashlib.blake2b(raw, digest_size=8).digest(), "big") / 18446744073709551616.0


def _internal_path(uri: str) -> bool:
    """/__pcdn/... (health, challenge verification, captcha, ...) also when percent-encoded or
    with extra leading slashes; never exported."""
    head = uri[:64]
    if "%" in head:
        head = urllib.parse.unquote(head)
    return head.lstrip("/").startswith("__pcdn/") or head.lstrip("/") == "__pcdn"


def logship_sites(body: dict) -> dict:
    """{domain: [sample_rate, anonymize_ip] | None} from the edge config: every site with
    logs.enabled (rate clamped to 0.01..1, anonymize unless explicitly false), plus - as None - the
    disabled sites nested under an enabled domain, so the longest-suffix host -> site mapping (the
    controller's) never attributes their hosts to the enabled parent."""
    enabled, off = {}, set()
    for s in body.get("sites") or []:
        if not isinstance(s, dict):
            continue
        dom = str(s.get("domain") or "").lower().rstrip(".")
        if not dom or len(dom) > 253:
            continue
        lg = s.get("logs")
        if isinstance(lg, dict) and lg.get("enabled") is True:
            rate = _num(lg.get("sample_rate", 1.0), float, 1.0)
            enabled[dom] = [min(1.0, max(0.01, rate)), lg.get("anonymize_ip") is not False]
        else:
            off.add(dom)
    out: dict = dict(enabled)
    for dom in off:
        parts = dom.split(".")
        if dom not in out and any(".".join(parts[i:]) in enabled for i in range(1, len(parts))):
            out[dom] = None
    return out


class LogShip:
    """Sampling, spool and shipping of the log export (SPEC §14.3.2). Persistent bits live in
    state["logship"]: sites (logship_sites), cfg (last config version seen), off (config version at
    which the controller answered 404: shipping stays off until the version changes) and dropped
    (records dropped by the spool cap / age / a rejected batch, reported in the heartbeat)."""

    def __init__(self, cfg: dict, state: dict):
        self.cfg, self.state = cfg, state
        st = state.get("logship")
        if not isinstance(st, dict):
            st = state["logship"] = {}
        self.st = st
        self.dir = cfg.get("LOGSHIP_SPOOL_DIR") or os.path.join(
            os.path.dirname(cfg.get("STATE_FILE") or "/var/lib/pcdn/state.json"), "logship")
        try:
            mb = float(cfg.get("LOGSHIP_SPOOL_MAX_MB") or 256)
        except (TypeError, ValueError):
            mb = 256.0
        self.cap = int(min(max(mb, 0.001), 1e6) * 1024 * 1024)
        self.buf: list[str] = []
        self.buf_bytes = 0
        self.memo: dict = {}          # host -> (rate, anonymize) | None
        self.next_run = 0.0           # monotonic: shipping cadence / backoff
        self.backoff = 0
        self.last_warn = 0.0
        self.last_ms = 0              # batch names sort in creation order, also within one millisecond
        self.spent = 0.0              # record-building seconds in the current read pass
        self.over = 0                 # records not built this pass (sampling budget exhausted)
        self._dir_ok = False

    # ---- configuration
    def update_config(self, body: dict):
        """Called with every full config body (not on 304): new site settings, and a new version
        re-enables shipping after a 404."""
        self.st["sites"] = logship_sites(body)
        self.memo = {}
        ver = str(body.get("version") or "")
        if "off" in self.st and self.st["off"] != ver:
            self.st.pop("off", None)
            self.next_run = 0.0
            log.info("logship: config changed, shipping re-enabled")
        self.st["cfg"] = ver

    @property
    def active(self) -> bool:
        """Some site exports its logs (otherwise the reader skips the sampler entirely)."""
        return any(self.st.get("sites", {}).values())

    def site_for(self, host: str):
        """(sample_rate, anonymize_ip) of the site serving `host`, or None (longest domain suffix,
        like the controller's host -> site mapping)."""
        v = self.memo.get(host, False)
        if v is not False:
            return v
        sites = self.st.get("sites") or {}
        parts = host.split(".")
        v = None
        for i in range(len(parts) - 1):
            d = ".".join(parts[i:])
            if d in sites:
                v = tuple(sites[d]) if sites[d] else None
                break
        if len(self.memo) < 10000:
            self.memo[host] = v
        return v

    # ---- sampling
    def begin_pass(self):
        self.spent, self.over = 0.0, 0

    def end_pass(self):
        """After a read pass: spool the partial batch, count what the sampling budget skipped."""
        if self.over:
            self._dropped(self.over, f"sampling budget {LOGSHIP_SAMPLE_BUDGET:.0f} s per read pass")
            self.over = 0
        self.flush()

    def offer(self, e: dict, host: str, dt: datetime, raw: bytes | None):
        """Sample one access-log record: only sites with logs.enabled, never tunnel traffic or the
        edge's own /__pcdn/ endpoints; kept when sample_point(line) < sample_rate."""
        st = self.site_for(host)
        if st is None or e.get("tn") in TUNNEL_PROTOCOLS:
            return
        rate, anonymize = st
        if rate < 1.0:
            key = raw if raw is not None else json.dumps(e, sort_keys=True).encode()
            if sample_point(key) >= rate:
                return
        if _internal_path(str(e.get("u") or "")):
            return
        if self.spent > LOGSHIP_SAMPLE_BUDGET:
            self.over += 1
            return
        t0 = time.monotonic()
        line = _JSON_LINE.encode(log_record(e, host, dt, anonymize))
        self.buf.append(line)
        self.buf_bytes += len(line) + 1
        if len(self.buf) >= LOGSHIP_MAX_RECORDS or self.buf_bytes >= LOGSHIP_BATCH_BYTES:
            self.flush()
        self.spent += time.monotonic() - t0

    def flush(self):
        """Write the pending records as one spooled batch (never raises: export is best-effort)."""
        if not self.buf:
            return
        lines, self.buf, self.buf_bytes = self.buf, [], 0
        try:
            self._ensure_dir()
            self.last_ms = max(int(time.time() * 1000), self.last_ms + 1)
            name = f"{self.last_ms:013d}-{uuid.uuid4().hex}-{len(lines)}.jsonl"
            tmp = os.path.join(self.dir, ".tmp-" + name)
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write("\n".join(lines) + "\n")
            os.replace(tmp, os.path.join(self.dir, name))
        except OSError as e:
            self._dropped(len(lines), f"spool write failed ({e})")
            return
        self.enforce()

    # ---- spool
    def _ensure_dir(self):
        if not self._dir_ok:
            os.makedirs(self.dir, mode=0o700, exist_ok=True)
            os.chmod(self.dir, 0o700)
            self._dir_ok = True

    def batches(self) -> list[tuple]:
        """Spooled batches oldest first: (name, ms, batch_id, records, size). Stale temp files of
        an interrupted write are removed."""
        try:
            names = os.listdir(self.dir)
        except OSError:
            return []
        out = []
        for n in names:
            p = os.path.join(self.dir, n)
            m = SPOOL_FILE.match(n)
            try:
                if m:
                    out.append((n, int(m.group(1)), m.group(2), int(m.group(3)), os.path.getsize(p)))
                elif n.startswith(".tmp-") and time.time() - os.path.getmtime(p) > 600:
                    os.unlink(p)
            except OSError:
                pass
        out.sort()
        return out

    def enforce(self) -> list[tuple]:
        """Drop batches older than 72 h, then the oldest ones while the spool exceeds its cap;
        returns what is left (oldest first)."""
        files = self.batches()
        total = sum(f[4] for f in files)
        old = (time.time() - LOGSHIP_MAX_AGE) * 1000
        keep, dropped = [], 0
        for f in files:
            if f[1] < old or total > self.cap:
                try:
                    os.unlink(os.path.join(self.dir, f[0]))
                except FileNotFoundError:
                    pass
                except OSError:
                    keep.append(f)
                    continue
                total -= f[4]
                dropped += f[3]
            else:
                keep.append(f)
        if dropped:
            self._dropped(dropped, f"spool cap {self.cap // (1024 * 1024)} MB / age {LOGSHIP_MAX_AGE // 3600} h")
        return keep

    def _dropped(self, n: int, why: str):
        self.st["dropped"] = int(self.st.get("dropped") or 0) + n
        now = time.monotonic()
        if now - self.last_warn >= LOGSHIP_WARN_EVERY or not self.last_warn:
            self.last_warn = now
            log.warning("logship: dropped %d records (%s); %d dropped in total", n, why, self.st["dropped"])

    def stats(self) -> dict:
        """Heartbeat block: spool size, drops, whether shipping is off after a 404."""
        files = self.batches()
        return {"sites": sum(1 for v in (self.st.get("sites") or {}).values() if v),
                "spool_batches": len(files), "spool_records": sum(f[3] for f in files),
                "spool_bytes": sum(f[4] for f in files), "dropped": int(self.st.get("dropped") or 0),
                "disabled": "off" in self.st}

    # ---- shipping
    def _read(self, name: str) -> list | None:
        try:
            with open(os.path.join(self.dir, name), encoding="utf-8") as f:
                text = f.read()
        except FileNotFoundError:
            return None
        except OSError:
            return []
        out = []
        for ln in text.splitlines():
            try:
                rec = json.loads(ln)
            except ValueError:
                continue
            if isinstance(rec, dict):
                out.append(rec)
        return out[:LOGSHIP_MAX_RECORDS]

    def _remove(self, name: str):
        try:
            os.unlink(os.path.join(self.dir, name))
        except OSError:
            pass

    def due(self) -> bool:
        return "off" not in self.st and time.monotonic() >= self.next_run

    def ship(self, ctl) -> int:
        """One shipping run: POST spooled batches oldest first until the spool is empty or
        LOGSHIP_RUN_BUDGET has passed (no new POST is started after it; each POST is time-boxed by
        LOGSHIP_TIMEOUT). The next run is at least LOGSHIP_INTERVAL and 3x this run's duration away,
        so shipping takes a bounded share of the loop. Returns the number of batches delivered.
          * 2xx -> the batch file is deleted;
          * 404 -> an old controller without the endpoint: shipping stops until the config version
            changes (the spool is kept, capped and aged as usual);
          * 400 / 413 / 422 -> this batch can never be accepted: dropped (counted), next batch;
          * anything else (timeout, connection error, 5xx, 401, 429) -> exponential backoff
            (30 s .. 15 min); the batch is retried later with the SAME batch_id."""
        if not self.due():
            return 0
        start = time.monotonic()
        interval = _int(self.cfg.get("LOGSHIP_INTERVAL"), 30, 1, 3600)
        timeout = _int(self.cfg.get("LOGSHIP_TIMEOUT"), 30, 3, 600)
        sent = 0
        failed = False
        for name, _, bid, count, _ in self.enforce():
            if time.monotonic() - start > LOGSHIP_RUN_BUDGET:
                break
            records = self._read(name)
            if records is None:          # vanished (dropped by the cap meanwhile)
                continue
            if not records:              # unreadable / corrupt: never retried forever
                self._remove(name)
                self._dropped(count, "unreadable spool batch")
                continue
            try:
                ctl.call("POST", "/edge/v1/logship", {"batch_id": bid, "records": records}, timeout=timeout)
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    self.st["off"] = str(self.st.get("cfg") or "")
                    log.warning("logship: the controller has no /edge/v1/logship (404); "
                                "shipping is off until the next config change")
                    return sent
                if e.code in (400, 413, 422):
                    self._remove(name)
                    self._dropped(len(records), f"batch rejected with HTTP {e.code}")
                    continue
                failed = True
                log.warning("logship: POST failed: HTTP %s", e.code)
                break
            except Exception as e:  # noqa: BLE001 - timeouts, connection errors: retry later
                failed = True
                log.warning("logship: POST failed: %s", e)
                break
            self._remove(name)
            sent += 1
        took = time.monotonic() - start
        if failed:
            self.backoff = min(LOGSHIP_BACKOFF[1], self.backoff * 2 if self.backoff else LOGSHIP_BACKOFF[0])
            self.next_run = time.monotonic() + self.backoff
        else:
            self.backoff = 0
            self.next_run = time.monotonic() + max(interval, 3 * took)
        return sent


# ----------------------------------------------------------------- centralized logs (SPEC §11.2)

LOG_MSG_MAX = 500
LOG_MAX_PER_REPORT = 40
LOG_MAX_SCAN = 2 * 1024 * 1024   # bytes of new error-log tail read per cycle
# nginx error line: "2024/01/02 15:04:05 [error] 1234#0: *5 message ..." (the *N conn id is optional)
NGINX_ERR_RE = re.compile(r"^(\d{4}/\d\d/\d\d \d\d:\d\d:\d\d) \[(\w+)\] \d+#\d+: (?:\*\d+ )?(.*)$")
# map nginx severities to the controller's small level set (warn/error/crit/notice/info)
NGINX_LEVEL = {"warn": "warn", "error": "error", "crit": "crit", "alert": "crit", "emerg": "crit",
               "notice": "notice", "info": "info"}
SHIP_LEVELS = {"warn", "error", "crit"}
# redaction (defence in depth): never ship visitor IPs, tokens or keys, only operational text
_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_IPV6 = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}\b")
_SECRET = re.compile(r"\b(?:edge_|pcdn_)[A-Za-z0-9_-]{6,}")
_CLIENT = re.compile(r"\bclient:\s*\S+")


def redact(msg: str) -> str:
    """Strip anything that could identify a visitor or leak a secret from an error line."""
    msg = _SECRET.sub("[redacted]", msg)
    msg = _CLIENT.sub("client: [redacted]", msg)
    msg = _IPV6.sub("[ip]", msg)
    msg = _IPV4.sub("[ip]", msg)
    return msg


def parse_error_lines(text: str) -> list[dict]:
    """Turn raw nginx error-log text into shippable {t, level, msg} for WARN/ERROR/crit only."""
    out = []
    for raw in text.splitlines():
        raw = raw.strip()
        if not raw:
            continue
        m = NGINX_ERR_RE.match(raw)
        if m:
            t, sev, body = m.group(1), m.group(2).lower(), m.group(3)
            level = NGINX_LEVEL.get(sev)
            if level not in SHIP_LEVELS:
                continue
            out.append({"t": t, "level": level, "msg": redact(body)[:LOG_MSG_MAX]})
        # lines we cannot classify are dropped (never ship access logs or unknown formats)
    return out


def read_error_log(state: dict, path: str, raw_hook=None) -> list[dict]:
    """New WARN/ERROR/crit lines since the last offset (handles rotation/truncation). Fail-soft.
    raw_hook(text): sees the raw, unredacted new text first (tunnel abnormal-end accounting)."""
    try:
        st = os.stat(path)
    except (FileNotFoundError, OSError):
        return []
    pos = int(state.get("err_pos", 0))
    prev_inode = state.get("err_inode")
    text = ""
    try:
        if prev_inode not in (None, st.st_ino):
            # rotated: finish the old file (now .1) then start the new one at 0
            rotated = path + ".1"
            try:
                if os.stat(rotated).st_ino == prev_inode:
                    text += _read_tail(rotated, pos)
            except (FileNotFoundError, OSError):
                pass
            pos = 0
        elif st.st_size < pos:
            pos = 0  # truncated
        with open(path, "rb") as f:
            f.seek(pos)
            chunk = f.read(LOG_MAX_SCAN)
            state["err_pos"] = f.tell()
        text += chunk.decode("utf-8", "replace")
        state["err_inode"] = st.st_ino
    except OSError as e:
        log.debug("error-log read: %s", e)
        return []
    if raw_hook is not None:
        try:
            raw_hook(text)
        except Exception as e:  # noqa: BLE001 - never let accounting break log shipping
            log.debug("error-log hook: %s", e)
    return parse_error_lines(text)


# SPEC §15.1 `abnormal`: nginx 1.24 logs an established tunnel session that the ORIGIN ended badly with
# the same $status / $upstream_status as a clean end (101 / 200), so the access log cannot tell. The
# error log can: an [error] line "... while proxying upgraded connection" (ws / httpupgrade after the
# 101: upstream reset, upstream idle timeout) or "... while reading upstream" (grpc / h2 / xhttp
# response body: upstream reset, premature close, read timeout). Client-side failures of the same
# phases are logged at [info] (nginx logs client connection errors at info), and failures before a
# response header ("while connecting to upstream", "while reading response header from upstream")
# are already origin_refused / origin_timeout in the access log, so they are not matched here.
# The line is attributed to the path id by host + longest tunnel prefix of its request path.
ABNORMAL_RE = re.compile(r'^(\d{4}/\d\d/\d\d \d\d:\d\d:\d\d) \[error\] .* while (?:proxying upgraded connection|'
                         r'reading upstream), .*?request: "[A-Z]{1,16} (\S+) [^"]*".*, host: "([^"]+)"\s*$')


def tunnel_map(config: dict) -> dict:
    """{host: [[prefix, path id], ...] longest prefix first} for the abnormal-end attribution."""
    out = {}
    for site in config.get("sites", []):
        try:
            tn = norm_tunnel(site, norm_pools(site))
        except Exception:  # noqa: BLE001 - a broken site entry never stops the others
            tn = None
        if not tn:
            continue
        prefixes = sorted(([p["path"], p["id"]] for p in tn["paths"]), key=lambda x: (-len(x[0]), x[0]))
        for h in site.get("hosts") or []:
            name = str(h.get("name") or "").lower() if isinstance(h, dict) else ""
            if name and SAFE_NAME.match(name):
                out[name] = prefixes
    return out


def _tmap_lookup(tmap: dict, host: str, path: str) -> str | None:
    host = host.lower().split(":", 1)[0]
    prefixes = tmap.get(host)
    if prefixes is None:   # wildcard host entries ("*.example.com")
        for name, pre in tmap.items():
            if name.startswith("*.") and host.endswith(name[1:]):
                prefixes = pre
                break
    for prefix, pid in prefixes or ():
        if path.startswith(prefix):
            return pid
    return None


def account_abnormal(state: dict, text: str) -> int:
    """Add the abnormal tunnel-session ends found in raw error-log text to the pending host-hours
    (tunnel.paths[id].abnormal). Returns how many were counted."""
    tmap = state.get("tunnel_map") or {}
    if not tmap or " while " not in text:
        return 0
    pending = state.setdefault("pending", {})
    n = 0
    for raw in text.splitlines():
        m = ABNORMAL_RE.match(raw.strip())
        if not m:
            continue
        ts, uri, host = m.groups()
        pid = _tmap_lookup(tmap, host, uri.split("?", 1)[0])
        if not pid:
            continue
        try:   # nginx writes the error log in local time
            hour = (datetime.strptime(ts, "%Y/%m/%d %H:%M:%S").astimezone(timezone.utc)
                    .strftime("%Y-%m-%dT%H:00:00Z"))
        except (ValueError, OverflowError, OSError):
            continue
        a = _bucket(pending, f"{host.lower().split(':', 1)[0]}|{hour}")
        t = a.setdefault("tunnel", {"sessions": 0, "seconds": 0.0, "bytes_up": 0, "bytes_down": 0, "by_protocol": {}})
        p = _tpath(t, pid)
        if p is not None:
            p["abnormal"] += 1
            n += 1
    return n


def _read_tail(path: str, pos: int) -> str:
    try:
        with open(path, "rb") as f:
            f.seek(pos)
            return f.read(LOG_MAX_SCAN).decode("utf-8", "replace")
    except OSError:
        return ""


def collect_logs(state: dict, cfg: dict) -> list[dict]:
    """Gather new problem lines (nginx error log + the agent's own), de-duplicated and capped.

    De-dup is against the fingerprints of the last batch so an identical repeating line is not
    re-sent every cycle. Never raises."""
    try:
        lines = read_error_log(state, cfg.get("ERROR_LOG") or "", lambda text: account_abnormal(state, text))
    except Exception as e:  # noqa: BLE001 - log shipping must never break the agent
        log.debug("collect error log failed: %s", e)
        lines = []
    lines.extend(AGENT_LOGS.drain())
    if not lines:
        return []
    seen_prev = set(state.get("logs_seen") or [])
    out, fps = [], []
    for ln in lines:
        fp = f"{ln['level']}|{ln['msg']}"
        if fp in seen_prev or fp in fps:
            continue
        fps.append(fp)
        out.append(ln)
    # keep only the newest LOG_MAX_PER_REPORT lines
    out = out[-LOG_MAX_PER_REPORT:]
    # remember the fingerprints we just shipped so an identical repeat next cycle is skipped
    state["logs_seen"] = [f"{ln['level']}|{ln['msg']}" for ln in out][-LOG_MAX_PER_REPORT:]
    return out


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


def count_draining_workers(proc: str = "/proc") -> int:
    """Count nginx worker processes still draining after a reload (F5/F6). Each reload leaves a
    generation pinned by long-lived tunnels; too many means reloads are outpacing shutdown, which
    the agent uses for reload back-pressure and reports in the heartbeat."""
    n = 0
    try:
        for pid in os.listdir(proc):
            if not pid.isdigit():
                continue
            try:
                with open(os.path.join(proc, pid, "cmdline"), "rb") as f:
                    if b"worker process is shutting down" in f.read():
                        n += 1
            except OSError:
                continue
    except OSError:
        return 0
    return n


def sockstat_counts(path: str = "/proc/net/sockstat") -> tuple[int, int]:
    """(TCP inuse, TIME_WAIT) from /proc/net/sockstat (F18). O(1); used to watch outbound ephemeral
    port pressure toward origins. (0, 0) on error."""
    try:
        with open(path) as f:
            for line in f:
                if line.startswith("TCP:"):
                    p = line.split()
                    d = {p[i]: int(p[i + 1]) for i in range(1, len(p) - 1, 2) if p[i + 1].lstrip("-").isdigit()}
                    return d.get("inuse", 0), d.get("tw", 0)
    except (OSError, ValueError, IndexError):
        pass
    return 0, 0


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
    try:
        m["draining_workers"] = count_draining_workers(cfg.get("PROC_DIR", "/proc"))  # F5/F6
    except Exception as e:  # noqa: BLE001
        log.debug("draining workers: %s", e)
    try:
        tcp_inuse, tw = sockstat_counts(cfg.get("PROC_SOCKSTAT", "/proc/net/sockstat"))  # F18
        m["sock_tcp"], m["sock_tw"] = tcp_inuse, tw
        lo, hi = 10240, 65535  # default ephemeral range (not widened; F18 is monitoring-only)
        rng = cfg.get("PORT_RANGE")
        if isinstance(rng, (tuple, list)) and len(rng) == 2:
            lo, hi = int(rng[0]), int(rng[1])
        span = max(1, hi - lo + 1)
        if tcp_inuse + tw > 0.7 * span:
            log.warning("ephemeral TCP usage high: inuse=%d tw=%d (>70%% of %d)", tcp_inuse, tw, span)
    except Exception as e:  # noqa: BLE001
        log.debug("sockstat: %s", e)
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
        f.flush()
        try:  # F8: durable across power loss, but a filesystem rejecting fsync must not be fatal
            os.fsync(f.fileno())
        except OSError:
            pass
    os.replace(tmp, path)


def _new_batch_id() -> str:
    """Stable idempotency key for a usage batch (F7): the controller dedups on it, and the agent
    reuses it on every retry/replay of the same batch (persisted in the outbox)."""
    return uuid.uuid4().hex


def bundle_version(cfg: dict) -> str | None:
    """The running edge bundle version (SPEC §11.1): the value bootstrap.sh recorded, else a
    stable hash of the installed agent as a fallback. None when neither is available."""
    path = cfg.get("BUNDLE_VERSION_FILE") or ""
    try:
        if path and os.path.isfile(path):
            v = open(path, encoding="utf-8").read().strip()
            if v:
                return v[:64]
    except OSError:
        pass
    try:  # fallback: hash the running agent file (won't match the controller, but is a stable signal)
        with open(os.path.abspath(__file__), "rb") as f:
            return "agent-" + hashlib.sha256(f.read()).hexdigest()[:10]
    except OSError:
        return None


class Agent:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.ctl = Controller(cfg["CONTROLLER_URL"], cfg["EDGE_TOKEN"])
        self.state = load_state(cfg["STATE_FILE"])
        self.running = True
        self.last_usage = 0.0
        self.last_heartbeat = 0.0
        self.net_prev = None

    @property
    def logship(self) -> LogShip:
        """The log-export sampler / spool / shipper (SPEC §14.3.2), bound to the current state."""
        ls = self.__dict__.get("_logship")
        if ls is None or ls.state is not self.state:
            ls = self.__dict__["_logship"] = LogShip(self.cfg, self.state)
        return ls

    def _reload_min_interval(self) -> float:
        """F5 reload back-pressure: base RELOAD_MIN_INTERVAL, doubled (up to 600 s) while more than
        2×nproc worker generations are still draining, so reloads never outpace worker shutdown."""
        base = _int(self.cfg.get("RELOAD_MIN_INTERVAL"), 120, 0, 3600)
        try:
            if count_draining_workers(self.cfg.get("PROC_DIR", "/proc")) > 2 * (os.cpu_count() or 1):
                return min(600, base * 2)
        except Exception:  # noqa: BLE001
            pass
        return base

    def _foreign_defer(self, body: dict, files: dict) -> int:
        """F21: seconds this change may be deferred because every changed site belongs to another
        edge group; 0 means apply now. Deferral needs a known node GROUP and per-site edge_group from
        the controller; a global-file change, an added/removed site, a status change or a cert
        rotation on any changed site force an immediate apply."""
        group = self.cfg.get("GROUP")
        if not group:
            return 0
        st = self.state
        cur, prev = site_digests(files), st.get("site_digests") or {}
        changed = {sid for sid in set(cur) | set(prev) if cur.get(sid) != prev.get(sid)}
        if not changed:
            return 0
        if global_digest(files) != st.get("global_digest"):
            return 0
        groups = {str(int(s["id"])): s.get("edge_group") for s in body.get("sites", [])}
        statuses = {str(int(s["id"])): s.get("status", "active") for s in body.get("sites", [])}
        cur_certs, prev_certs = cert_digests(files), st.get("cert_digests") or {}
        for sid in changed:
            if groups.get(sid) in (None, group):                       # own or unknown group
                return 0
            if statuses.get(sid) in ("suspended", "over_quota"):       # serving/blocking change
                return 0
            if cur_certs.get(sid) != prev_certs.get(sid):              # cert rotation
                return 0
        return _int(self.cfg.get("FOREIGN_DEFER"), 900, 0, 86400)

    def _store_applied(self, body, files, digest, etag, version, rev):
        st = self.state
        st["etag"], st["version"], st["render_rev"] = etag, version, rev
        st["tree_digest"] = digest
        st["site_digests"], st["cert_digests"] = site_digests(files), cert_digests(files)
        st["global_digest"] = global_digest(files)
        st["keyinfo"] = key_infos(body)   # cache-key shapes for exact-URL purges (SPEC §14.1)
        for k in ("pending_version", "pending_since"):
            st.pop(k, None)
        st["last_reload"] = time.monotonic()

    def sync_config(self):
        cfg, st = self.cfg, self.state
        rev = render_rev(cfg)
        root = cfg["NGINX_DIR"].rstrip("/")
        first_boot = not os.path.isfile(os.path.join(root, "http.conf"))
        headers = {}
        # While a version is pending we re-fetch the full config each poll so we always apply the
        # newest one (F5); the ETag is only used once everything has settled and applied cleanly.
        if (st.get("etag") and os.path.isdir(root) and st.get("render_rev") == rev
                and not st.get("pending_version") and not st.get("last_error")):
            headers["If-None-Match"] = st["etag"]
        code, hdrs, body = self.ctl.call("GET", "/edge/v1/config", headers=headers)
        if code == 304:
            return
        try:   # SPEC §14.3.2: log-export settings are agent-side only (never rendered, no reload)
            self.logship.update_config(body)
        except Exception as e:  # noqa: BLE001 - never let log export break config sync
            log.error("logship config update failed: %s", e)
        try:   # SPEC §15.1/§15.2: agent-side only (abnormal-end attribution, fair-share hot flag)
            st["tunnel_map"] = tunnel_map(body)
            st["node"] = norm_node(body, cfg)
        except Exception as e:  # noqa: BLE001
            log.error("tunnel map / node block update failed: %s", e)
        version = body["version"]
        etag = hdrs.get("ETag") or hdrs.get("etag")
        body = with_cached_bot_ranges(body, st)   # SPEC §14.2: keep the last good crawler ranges
        files, digest = render_tree(body, cfg)
        now = time.monotonic()

        # F20: an identical rendered tree needs no write/test/reload (covers controller version bumps
        # for fields the agent never renders, and agent upgrades that change nothing).
        if (digest == st.get("tree_digest") and os.path.isfile(os.path.join(root, "http.conf"))
                and not st.get("last_error")):
            ensure_cache_dirs(body, cfg)
            st["etag"], st["version"], st["render_rev"] = etag, version, rev
            st["keyinfo"] = key_infos(body)
            for k in ("pending_version", "pending_since"):
                st.pop(k, None)
            self._report(version, None)
            return

        def apply_now():
            err = apply_config(body, cfg, files, digest)
            st["last_error"] = err
            if err:
                log.error(err)
                self._report(st.get("version"), err)   # keep etag unset so the next poll retries
                return
            self._store_applied(body, files, digest, etag, version, rev)
            log.info("applied config %s (%d sites)", version[:12], len(body.get("sites", [])))
            self._report(version, None)

        if first_boot or bool(body.get("urgent")):   # bootstrap / security-relevant: apply at once
            return apply_now()

        # F5 coalescing: hold a freshly-seen version until it settles (unchanged across two polls) or
        # has been pending for RELOAD_MIN_INTERVAL, and never reload more often than that interval.
        settled = st.get("pending_version") == version
        if not settled:
            st["pending_version"], st["pending_since"] = version, now
        age = now - st.get("pending_since", now)
        min_interval = self._reload_min_interval()
        debounce = _int(cfg.get("RELOAD_DEBOUNCE"), 5, 0, 3600)
        if age < debounce or not (settled or age >= min_interval):
            return
        if now - st.get("last_reload", 0) < min_interval:
            return
        defer = self._foreign_defer(body, files)   # F21
        if defer and age < defer:
            log.info("deferring foreign-group config %s (%.0fs/%ds)", version[:12], age, defer)
            self._report(st.get("version"), st.get("last_error"))   # heartbeat during the deferral
            return
        apply_now()

    def _report(self, version, error):
        self.ctl.call("POST", "/edge/v1/heartbeat", self._hb(applied_version=version, error=error))

    def sync_purges(self):
        after = int(self.state.get("purge_id", 0))
        _, _, items = self.ctl.call("GET", f"/edge/v1/purges?after={after}")
        if "purge_id" not in self.state:
            # first run: a fresh node has an empty cache, so skip history and remember where we are
            self.state["purge_id"] = items[-1]["id"] if items else 0
            return
        kinfo = self.state.get("keyinfo") or {}
        for it in items or []:
            n = do_purge(it, self.cfg, kinfo.get(str(it.get("site_id"))))
            what = "ALL" if it.get("everything") else (it["urls"] or it.get("prefixes") or "ALL")
            log.info("purge %s %s -> %d entries", it["domain"], what, n)
            self.state["purge_id"] = it["id"]

    def _enqueue_usage(self):
        """Move newly-read pending usage / events into the persisted outbox (F7): each entry gets a
        stable batch_id that is reused on every retry, so a timed-out or replayed POST is deduped by
        the controller instead of double-billing."""
        pending = self.state.setdefault("pending", {})
        events = self.state.setdefault("events", [])
        live = self.state.setdefault("live", {})
        if not pending and not events and not live:
            return
        outbox = self.state.setdefault("outbox", [])
        keys, evs = list(pending), list(events)
        now = time.time()
        cutoff = live_cutoff(now)
        entries = []
        while keys or evs:
            bk, keys = keys[:MAX_ITEMS], keys[MAX_ITEMS:]
            be, evs = evs[:MAX_EVENTS], evs[MAX_EVENTS:]
            entries.append({"id": _new_batch_id(), "ts": now, "items": [usage_item(k, pending[k]) for k in bk],
                            "events": be})
        # SPEC §14.3.1: the host-minutes ride in the same outbox entry (same batch_id, so a retry stays
        # idempotent); ≤ LIVE_MAX per POST, oldest minutes dropped beyond that (best-effort)
        lv = live_items(live, cutoff)
        if lv:
            if not entries:
                entries.append({"id": _new_batch_id(), "ts": now, "items": [], "events": []})
            entries[0]["live"] = lv
        outbox.extend(entries)
        pending.clear()
        del events[:]
        live.clear()
        trim_live_backlog(outbox, cutoff)

    def push_usage(self):
        ls = self.logship
        ls.begin_pass()
        try:
            read_usage(self.state, self.cfg["ACCESS_LOG"], ship=ls if ls.active else None)
        finally:
            ls.end_pass()   # the partial log-export batch of this read goes to the spool (never raises)
        self._enqueue_usage()
        # F8: persist the outbox (with its batch_ids and the advanced log_pos) BEFORE the first POST,
        # so a crash or restart replays the SAME batch rather than a different one. A save failure is
        # non-fatal (skip pushing this tick) so state persistence issues never kill the agent.
        try:
            save_state(self.cfg["STATE_FILE"], self.state)
        except OSError as e:
            log.error("state save before usage push failed, skipping push: %s", e)
            return
        outbox = self.state.setdefault("outbox", [])
        max_age = _int(self.cfg.get("USAGE_OUTBOX_MAX_DAYS"), 6, 1, 60) * 86400
        now, kept = time.time(), []
        for e in outbox:
            if now - e.get("ts", now) > max_age:   # bound by the controller's dedup retention window
                log.warning("dropping usage batch %s older than %d days", e.get("id"), max_age // 86400)
                continue
            kept.append(e)
        outbox[:] = kept
        trim_live_backlog(outbox, live_cutoff(now))   # retried entries never carry minutes older than 24 h
        timeout = _int(self.cfg.get("USAGE_TIMEOUT"), 150, 10, 600)
        for entry in list(outbox):
            body = {"batch_id": entry["id"], "items": entry["items"]}
            if entry["events"]:
                body["events"] = entry["events"]
            if entry.get("live"):
                body["live"] = entry["live"]
            try:
                self.ctl.call("POST", "/edge/v1/usage", body, timeout=timeout)   # retries reuse batch_id
            except urllib.error.HTTPError as e:
                # live data must never hold back the hourly usage: a request the controller rejects as
                # a whole (validation / size) is resent once without `live`, under the same batch_id
                # (a rejected request was not applied, so the dedup row does not exist yet)
                if e.code not in (400, 413, 422) or "live" not in body:
                    raise
                log.warning("usage batch %s rejected (HTTP %d) with live data; resending without it",
                            entry["id"], e.code)
                entry.pop("live", None)
                body.pop("live")
                self.ctl.call("POST", "/edge/v1/usage", body, timeout=timeout)
            outbox.remove(entry)

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

    def _hb(self, **over) -> dict:
        """Base heartbeat body: bundle version + (when configured) region/role, so a fresh node
        self-registers into the right pool (SPEC §11.1). Overrides fill applied_version/error/metrics."""
        body: dict = {"bundle_version": bundle_version(self.cfg), "geoip": geoip_present(self.cfg),
                      "capabilities": heartbeat_capabilities(self.cfg)}   # SPEC §14.1
        if self.cfg.get("REGION"):
            body["region"] = self.cfg["REGION"]
        if self.cfg.get("GROUP"):
            body["group"] = self.cfg["GROUP"]
        body.update(over)
        return body

    def heartbeat(self):
        """Periodic heartbeat with load metrics (keeps applied_version / last error as reported) and
        the log-export spool state (SPEC §14.3.2: dropped records are counted here)."""
        extra = {}
        try:
            extra["logship"] = self.logship.stats()
        except Exception:  # noqa: BLE001 - informational only
            pass
        m = self.metrics()
        try:
            self.fair_signal(m)
        except Exception as e:  # noqa: BLE001 - fair share is best-effort and fails open
            log.debug("fair share signal: %s", e)
        self.ctl.call("POST", "/edge/v1/heartbeat", self._hb(applied_version=self.state.get("version"),
                                                             error=self.state.get("last_error"),
                                                             metrics=m, **extra))

    def fair_signal(self, m: dict):
        """SPEC §15.2: tell nginx (localhost /__pcdn/fair, pcdn.js tunnelFair) whether the node is hot:
        tx_mbps >= 85 % of the node capacity; it stays hot until tx drops below 80 %. Sent on every
        heartbeat; the flag expires in nginx (180 s zone timeout) if the agent stops sending it."""
        if not has_module(self.cfg, "njs"):
            return
        node = self.state.get("node") or norm_node({}, self.cfg)
        was = bool(self.state.get("fair_hot"))
        self.state["fair_hot"] = hot = fair_hot(m.get("tx_mbps") or 0, node["capacity_mbps"], was)
        if hot != was:
            log.info("node %s (tx %.0f of %d Mbps): tunnel fair share %s", "hot" if hot else "no longer hot",
                     m.get("tx_mbps") or 0, node["capacity_mbps"],
                     f"active at {node['fair_share_pct']} %" if hot else "idle")
        port = _int(self.cfg.get("HTTP_PORT"), 80, 1, 65535)
        url = f"http://127.0.0.1:{port}/__pcdn/fair?hot={node['fair_share_pct'] if hot else 0}"
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(url, timeout=2) as r:
            r.read()

    def ship_logs(self):
        """Ship new WARN/ERROR/crit lines to the controller (SPEC §11.2). Fail-soft: never raises."""
        lines = collect_logs(self.state, self.cfg)
        if lines:
            self.ctl.call("POST", "/edge/v1/logs", {"lines": lines})

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
            try:
                self.ship_logs()
            except Exception as e:  # noqa: BLE001 - log shipping must never break the heartbeat
                log.error("log shipping failed: %s", e)
        if time.time() - self.last_usage >= int(self.cfg["USAGE_INTERVAL"]):
            try:
                self.push_usage()
                self.last_usage = time.time()
            except Exception as e:  # noqa: BLE001 - pending usage stays in state for next try
                log.error("usage push failed: %s", e)
        # SPEC §14.3.2: log export last, on its own cadence and time budget, so it never delays the
        # config sync, purges, heartbeat or usage of this tick (LogShip.ship)
        try:
            self.logship.ship(self.ctl)
        except Exception as e:  # noqa: BLE001 - log export is best-effort
            log.error("logship failed: %s", e)
        try:  # F8: a persistence failure must not exit the process (systemd would restart-and-replay)
            save_state(self.cfg["STATE_FILE"], self.state)
        except OSError as e:
            log.error("state save failed: %s", e)

    def loop(self):
        while self.running:
            self.tick()
            for _ in range(int(self.cfg["POLL_INTERVAL"])):
                if not self.running:
                    break
                time.sleep(1)


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    # capture the agent's own WARN/ERROR lines so they ship with the nginx error log (SPEC §11.2)
    logging.getLogger("pcdn-agent").addHandler(AGENT_LOGS)
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
