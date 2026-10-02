"""Shared validation patterns and small helpers used by every renderer: the SAFE_* regexes that
gate what reaches nginx/njs, protocol constants, nginx quoting (_q / _qv), bounded ints and the
default network interface."""

import re


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
               "x-pcdn-shield",  # SPEC §14.1: the shield hop header is reserved for the edge itself
               "x-pcdn-origin", "x-pcdn-mtls"}   # the resizer's internal fetch URL / client-cert token
FW_ACTIONS = {"allow", "block", "challenge", "captcha", "log"}
FW_FIELDS = {"ip", "country", "path", "host", "query", "user_agent", "referer", "method", "header"}
FW_OPS = {"eq", "ne", "contains", "not_contains", "starts_with", "ends_with", "regex", "in", "not_in"}
WAF_GROUPS = {"sqli", "xss", "lfi", "rce", "php", "scanner", "protocol"}
MAX_ITEMS, MAX_EVENTS, EVENT_BACKLOG, PATHS_PER_ITEM, PATH_TRACK = 20000, 2000, 10000, 50, 1000


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


def wildcard_re(pattern: str, js: bool = False) -> str:
    """Page-rule style pattern ('*' = anything, including '/') -> anchored regex source.
    re.escape output is valid in PCRE and in JS (non-unicode) regexes.
    One '*' (the usual "/blog/*") stays the plain `^/blog/.*$`. With more, `^/.*a.*a.*b$` would
    backtrack polynomially (PCRE2 hits its match limit on a 2 kB path, on every request), so each
    middle segment is matched at its LEFTMOST occurrence without backtracking into it - an atomic
    group `(?>.*?seg)` for PCRE (nginx), `(?=(.*?seg))\\N` for JS (njs has no atomic groups) - and
    only the last segment backtracks (`.*last$`): linear, and the same strings match (the earliest
    occurrence of each middle segment always leaves the most room for the rest)."""
    segs = re.sub(r"\*+", "*", pattern).split("*")
    if len(segs) <= 2:
        return "^" + "".join(".*" if c == "*" else re.escape(c) for c in pattern) + "$"
    out = "^" + re.escape(segs[0])
    for i, seg in enumerate(segs[1:-1], 1):
        out += f"(?=(.*?{re.escape(seg)}))\\{i}" if js else f"(?>.*?{re.escape(seg)})"
    return out + ".*" + re.escape(segs[-1]) + "$"


def _sec(site: dict, name: str) -> dict:
    v = site.get(name)
    return v if isinstance(v, dict) else {}


def _hp(address: str, port) -> str:
    return f"{address}:{int(port)}"


def _v6(cfg: dict) -> bool:
    return cfg.get("LISTEN_IPV6", "yes").lower() in ("1", "yes", "true", "on")


# ----------------------------------------------------------------- default interface (metrics, host guard)

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
