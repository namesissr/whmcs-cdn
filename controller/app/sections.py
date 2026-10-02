"""Per-site configuration sections (SPEC §2) — validation, defaults, plan limits."""

import functools
import hashlib
import ipaddress
import json
import re
import warnings
from typing import Literal
from urllib.parse import quote

from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator, model_validator

from .validation import ValidationError

ID_RE = r"^[a-z0-9_-]{1,32}$"
PATH_PATTERN_RE = re.compile(r"^/[A-Za-z0-9\-._~%!$&'()*+,;=:@/]*$")
TUNNEL_PATH_RE = re.compile(r"^/[A-Za-z0-9._~/-]{1,200}$")
HEADER_NAME_RE = r"^[A-Za-z0-9-]{1,64}$"
FORBIDDEN_HEADERS = {"host", "content-length", "connection", "keep-alive", "transfer-encoding", "upgrade",
                     "te", "trailer", "proxy-authorization", "proxy-authenticate"}

DEFAULT_FEATURES = {
    "waf": True,
    "ddos": True,
    "load_balancer": True,
    "image_optimization": True,
    "custom_ssl": True,
    "dnssec": True,
    "max_page_rules": 10,
    "max_firewall_rules": 20,
    "max_ratelimit_rules": 5,
    "max_pools": 3,
    # tunnel mode (SPEC §7.1)
    "tunnel": False,
    "max_tunnel_paths": 10,
    "max_tunnel_connections": 0,  # per site per edge, 0 = unlimited
    "tunnel_max_mbps": 0,         # cap for tunnel.per_connection_mbps, 0 = no cap
    "edge_group": "general",      # which edges DNS answers with: general | tunnel
    # rules & security (SPEC §14.2)
    "max_transform_rules": 10,
    "max_redirects": 100,
    # analytics & platform (SPEC §14.3)
    "log_export": True,           # section `logs` may be enabled
    "max_webhooks": 10,           # items of section `webhooks`, 0 = none
    "sla_target": 99.9,           # monthly availability target (%) of the SLA report
    # wave 8 (SPEC §16.4): TCP/UDP proxy apps (section `l4`)
    "l4_proxy": False,
    "max_l4_apps": 0,
    # SPEC §16.8: object storage quota of the site in GB (GiB), 0 = no storage product
    "storage_gb": 0,
    # SPEC §16.9: edge functions (section `functions`), sandboxed JS run by pcdn-fn on the edges
    "edge_functions": False,
    "max_functions": 0,
    # security review H1: section `dns_secondary` (our nameservers AXFR the zone from the customer's
    # primary) is a plan feature, off by default
    "dns_secondary": False,
    # wave 10 (SPEC §18.1 / §18.2): sections `waiting_room` and `access`, off by default
    "waiting_room": False,
    "access": False,
}
EDGE_GROUPS = ("general", "tunnel")
WEBHOOKS_MAX = 50  # hard cap of section `webhooks` items, whatever the plan says
L4_APPS_MAX = 100  # hard cap of section `l4` apps, whatever the plan says
FUNCTIONS_MAX = 32  # hard cap of section `functions` items (the edge's FN_MAX_PER_SITE)


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


# validation context of data read back from the database (all_config, dns_secondary, l4): checks
# added after the data may have been stored (security review wave 9: regex safety, strict public
# origin addresses) are not applied there, so legacy data keeps parsing instead of silently falling
# back to the section default; the edge config build and the origin guard filter such data instead
STORED = {"stored": True}


def _stored(info: ValidationInfo | None) -> bool:
    return bool(info is not None and info.context and info.context.get("stored"))


class Features(Strict):
    waf: bool = True
    ddos: bool = True
    load_balancer: bool = True
    image_optimization: bool = True
    custom_ssl: bool = True
    dnssec: bool = True
    max_page_rules: int = Field(10, ge=0, le=1000)
    max_firewall_rules: int = Field(20, ge=0, le=1000)
    max_ratelimit_rules: int = Field(5, ge=0, le=1000)
    max_pools: int = Field(3, ge=0, le=100)
    tunnel: bool = False
    max_tunnel_paths: int = Field(10, ge=0, le=50)
    max_tunnel_connections: int = Field(0, ge=0, le=1000000)
    tunnel_max_mbps: int = Field(0, ge=0, le=100000)
    edge_group: Literal["general", "tunnel"] = "general"
    max_transform_rules: int = Field(10, ge=0, le=1000)
    max_redirects: int = Field(100, ge=0, le=10000)
    log_export: bool = True
    max_webhooks: int = Field(10, ge=0, le=WEBHOOKS_MAX)
    sla_target: float = Field(99.9, ge=0, le=100)
    l4_proxy: bool = False
    max_l4_apps: int = Field(0, ge=0, le=L4_APPS_MAX)
    storage_gb: int = Field(0, ge=0, le=1000000)
    edge_functions: bool = False
    max_functions: int = Field(0, ge=0, le=FUNCTIONS_MAX)
    dns_secondary: bool = False
    waiting_room: bool = False
    access: bool = False


# ------------------------------------------------------------------ sections

COOKIE_NAME_RE = re.compile(r"^[A-Za-z0-9_\-.]{1,64}$")
QUERY_PARAM_RE = re.compile(r"^[A-Za-z0-9_\-.\[\]]{1,64}$")


def _cookie_names(v: list[str], dedupe: bool = False) -> list[str]:
    out = []
    for c in v:
        c = c.strip()
        if not COOKIE_NAME_RE.match(c):
            raise ValueError(f"نام کوکی نامعتبر: {c}")
        if not dedupe or c not in out:
            out.append(c)
    return out


class Cache(Strict):
    enabled: bool = True
    dev_mode: bool = False
    level: Literal["standard", "aggressive"] = "standard"
    edge_ttl: int = Field(86400, ge=60, le=31536000)
    browser_ttl: int = Field(0, ge=0, le=31536000)
    ignore_query: bool = False
    bypass_cookies: list[str] = Field(default_factory=lambda: ["wordpress_logged_in", "wp-postpass", "PHPSESSID"],
                                      max_length=20)
    always_online: bool = True
    # SPEC §14.1 (6A): stale content, origin shield and cache-key options
    stale_while_revalidate: bool = True
    stale_if_error: int = Field(86400, ge=0, le=604800)
    shield: bool = False  # tiered cache through the edge group's shield edges (when it has any)
    key_device: bool = False  # separate desktop / mobile variants
    key_cookies: list[str] = Field(default_factory=list, max_length=10)  # cookie values join the key
    key_query_allow: list[str] = Field(default_factory=list, max_length=50)  # only these params key

    @field_validator("bypass_cookies")
    @classmethod
    def _cookies(cls, v):
        return _cookie_names(v)

    @field_validator("key_cookies")
    @classmethod
    def _key_cookies(cls, v):
        return _cookie_names(v, dedupe=True)

    @field_validator("key_query_allow")
    @classmethod
    def _key_query(cls, v):
        out = []
        for p in v:
            p = p.strip()
            if not QUERY_PARAM_RE.match(p):
                raise ValueError(f"نام پارامتر نامعتبر: {p}")
            if p not in out:
                out.append(p)
        return out

    @model_validator(mode="after")
    def _query_conflict(self):
        if self.key_query_allow and self.ignore_query:
            raise ValueError("key_query_allow با ignore_query=true سازگار نیست؛ وقتی کل رشته پرس‌وجو از "
                             "کلید کش حذف می‌شود، فهرست پارامترهای مجاز معنا ندارد. یکی را خاموش کنید.")
        return self


class Hsts(Strict):
    enabled: bool = False
    max_age: int = Field(31536000, ge=0, le=63072000)
    include_subdomains: bool = False
    preload: bool = False


class Ssl(Strict):
    force_https: bool = False
    hsts: Hsts = Hsts()
    min_tls: Literal["1.2", "1.3"] = "1.2"
    origin_protocol: Literal["http", "https"] = "http"
    origin_verify: bool = False
    # HTTP/3 (QUIC) on this site; only rendered on nodes reporting the http3 capability (SPEC §14.1)
    http3: bool = True
    # authenticated origin pulls (mTLS, SPEC §14.2): the client certificate the edges present to the
    # origin. platform = the platform's client certificate (CA at GET /origin-pull-ca.pem); custom =
    # the certificate uploaded with PUT /sites/{domain}/ssl/origin-client
    origin_client_auth: Literal["off", "platform", "custom"] = "off"


class WafExclusion(Strict):
    rule_id: int = Field(ge=0, le=9999999)
    path: str | None = None

    @field_validator("path")
    @classmethod
    def _path(cls, v):
        return _pattern(v) if v else None


WAF_GROUPS = ["sqli", "xss", "lfi", "rce", "php", "scanner", "protocol"]
# managed rule packs (SPEC §14.2): versioned rule sets with stable rule ids, shipped with the edge
WAF_PACKS = ["generic", "wordpress", "joomla", "drupal", "laravel", "api"]


def _iso_or_none(v):
    """A controller-managed ISO 8601 UTC timestamp ("2026-10-09T12:00:00Z") or None; anything that
    does not parse is dropped (these fields are ignored on input, see waf_learning.manage)."""
    from .waf_learning import fmt_iso, parse_iso

    dt = parse_iso(v)
    return None if dt is None else fmt_iso(dt)


class WafLearning(Strict):
    """SPEC §17: WAF learning mode. `enabled` and `days` (1..30) are the customer's input; `until`
    and `started_at` are managed by the controller (waf_learning.manage): whatever a client sends
    for them is replaced by the stored values."""
    enabled: bool = False
    days: int = Field(7, ge=1, le=30)
    until: str | None = Field(None, max_length=40)
    started_at: str | None = Field(None, max_length=40)

    @field_validator("until", "started_at", mode="before")
    @classmethod
    def _ts(cls, v):
        return _iso_or_none(v) if isinstance(v, str) else None


class Waf(Strict):
    mode: Literal["off", "detect", "block"] = "off"
    paranoia: int = Field(1, ge=1, le=3)
    groups: list[Literal["sqli", "xss", "lfi", "rce", "php", "scanner", "protocol"]] = Field(
        default_factory=lambda: list(WAF_GROUPS))
    exclusions: list[WafExclusion] = Field(default_factory=list, max_length=100)
    # empty = no managed pack (today's behaviour); packs honour `mode` and `exclusions`
    packs: list[Literal["generic", "wordpress", "joomla", "drupal", "laravel", "api"]] = Field(
        default_factory=list, max_length=20)
    # SPEC §17: learning mode (observe in log mode, propose exclusions / rate limits / pack changes)
    learning: WafLearning = Field(default_factory=WafLearning)

    @field_validator("packs")
    @classmethod
    def _packs(cls, v):
        return list(dict.fromkeys(v))  # de-duplicated, order kept


class Ddos(Strict):
    mode: Literal["off", "auto", "js", "captcha"] = "off"
    threshold_rps: int = Field(200, ge=10, le=1000000)
    clearance_ttl: int = Field(3600, ge=300, le=604800)


STRING_FIELDS = {"path", "host", "query", "user_agent", "referer", "method", "header"}
STRING_OPS = {"eq", "ne", "contains", "not_contains", "starts_with", "ends_with", "regex", "in", "not_in"}


class Condition(Strict):
    field: Literal["ip", "country", "path", "host", "query", "user_agent", "referer", "method", "header"]
    op: str
    value: str | list[str]
    name: str | None = None  # header name

    @model_validator(mode="after")
    def _check(self, info: ValidationInfo):
        values = self.value if isinstance(self.value, list) else [self.value]
        if len(values) > 500 or any(len(v) > 1024 for v in values):
            raise ValueError("مقدار شرط بیش از حد بزرگ است")
        if self.field == "ip":
            if self.op not in ("in", "not_in"):
                raise ValueError("برای IP فقط in / not_in مجاز است")
            try:
                self.value = [str(ipaddress.ip_network(v.strip(), strict=False)) for v in values]
            except ValueError as e:
                raise ValueError(f"IP/CIDR نامعتبر: {e}") from None
        elif self.field == "country":
            if self.op not in ("in", "not_in"):
                raise ValueError("برای کشور فقط in / not_in مجاز است")
            codes = [v.strip().upper() for v in values]
            if not all(re.match(r"^[A-Z]{2}$", c) for c in codes):
                raise ValueError("کد کشور باید دو حرفی باشد (مثل IR)")
            self.value = codes
        else:
            if self.op not in STRING_OPS:
                raise ValueError(f"عملگر نامعتبر: {self.op}")
            if self.op in ("in", "not_in"):
                self.value = values
            elif isinstance(self.value, list):
                raise ValueError("برای این عملگر یک مقدار متنی لازم است")
            if self.op == "regex":
                # H2: the edge runs this on every request of the site (njs, header / UA / path);
                # same safety checks as transform / redirect regexes (length, nesting, ambiguity)
                _regex_of(self.value, info)
            if self.field == "header":
                if not self.name or not re.match(HEADER_NAME_RE, self.name):
                    raise ValueError("نام هدر لازم است")
        if self.field != "header":
            self.name = None
        return self


class FirewallRule(Strict):
    id: str = Field(pattern=ID_RE)
    name: str = Field("", max_length=100)
    enabled: bool = True
    action: Literal["allow", "block", "challenge", "captcha", "log"]
    conditions: list[Condition] = Field(min_length=1, max_length=10)


class Firewall(Strict):
    default_action: Literal["allow", "block"] = "allow"
    rules: list[FirewallRule] = Field(default_factory=list)

    @field_validator("rules")
    @classmethod
    def _unique(cls, v):
        return _unique_ids(v)


class RateRule(Strict):
    id: str = Field(pattern=ID_RE)
    enabled: bool = True
    path: str = "/*"
    methods: list[Literal["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]] = Field(default_factory=list)
    requests: int = Field(ge=1, le=1000000)
    period: int = Field(ge=1, le=3600)
    action: Literal["block", "challenge", "captcha"] = "block"
    block_seconds: int = Field(60, ge=1, le=86400)

    @field_validator("path")
    @classmethod
    def _path(cls, v):
        return _pattern(v)


class RateLimit(Strict):
    rules: list[RateRule] = Field(default_factory=list)

    @field_validator("rules")
    @classmethod
    def _unique(cls, v):
        return _unique_ids(v)


class Redirect(Strict):
    url: str = Field(max_length=2048, pattern=r"^https?://[^\s\"'<>\\]+$")
    code: Literal[301, 302, 307, 308] = 301


# A preload URL ends up inside a `Link: <url>; rel=preload; as=...` header that the edge renders
# into nginx config, so only RFC 3986 URL characters are allowed: no whitespace/CR/LF, quotes,
# angle brackets, backslash, `$` (nginx variable interpolation) or braces.
PRELOAD_URL_CHARS_RE = re.compile(r"^[A-Za-z0-9\-._~:/?#\[\]@!&()*+,;=%]+$")


class Preload(Strict):
    """One `Link: rel=preload` / 103 Early Hints entry of a page rule (SPEC §14.1)."""
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    url: str = Field(max_length=2048)
    as_: Literal["script", "style", "image", "font", "fetch"] = Field(alias="as")

    @field_validator("url")
    @classmethod
    def _url(cls, v):
        v = (v or "").strip()
        if not v or not PRELOAD_URL_CHARS_RE.match(v):
            raise ValueError("آدرس preload نامعتبر است (فاصله، گیومه، < > و کاراکترهای خاص مجاز نیستند)")
        if v.startswith("/"):
            if v.startswith("//"):
                raise ValueError("آدرس preload باید مسیری با / (مثل /app.css) یا آدرس کامل https:// باشد")
            return v
        if not re.match(r"^https://[A-Za-z0-9.\-]+(:\d{1,5})?(/|$)", v, re.IGNORECASE):
            raise ValueError("آدرس preload باید مسیری با / (مثل /app.css) یا آدرس کامل https:// باشد")
        return v


class PageRule(Strict):
    id: str = Field(pattern=ID_RE)
    enabled: bool = True
    pattern: str
    cache: Literal["bypass", "standard", "everything"] | None = None
    edge_ttl: int | None = Field(None, ge=0, le=31536000)
    browser_ttl: int | None = Field(None, ge=0, le=31536000)
    ignore_query: bool | None = None
    waf: Literal[False] | None = None
    redirect: Redirect | None = None
    # `Link: <url>; rel=preload; as=<as>` headers (and 103 Early Hints on capable nodes), SPEC §14.1
    preload: list[Preload] = Field(default_factory=list, max_length=10)

    @field_validator("pattern")
    @classmethod
    def _pattern(cls, v):
        return _pattern(v)


class PageRules(Strict):
    rules: list[PageRule] = Field(default_factory=list)

    @field_validator("rules")
    @classmethod
    def _unique(cls, v):
        return _unique_ids(v)


class PoolOrigin(Strict):
    address: str
    port: int = Field(80, ge=1, le=65535)
    weight: int = Field(1, ge=1, le=100)
    backup: bool = False

    @field_validator("address")
    @classmethod
    def _addr(cls, v, info: ValidationInfo):
        return _origin_address(v, lenient=_stored(info))


class Health(Strict):
    enabled: bool = True
    path: str = Field("/", max_length=512, pattern=r"^/[^\s\"'<>\\]*$")
    interval: int = Field(10, ge=5, le=300)
    timeout: int = Field(3, ge=1, le=30)
    expect: str = Field("2xx,3xx", pattern=r"^([1-5]xx|[1-5]\d\d)(,([1-5]xx|[1-5]\d\d))*$")
    host: str | None = None

    @field_validator("host")
    @classmethod
    def _host(cls, v):
        from .validation import validate_hostname

        return validate_hostname(v) if v else None


class Pool(Strict):
    name: str = Field(pattern=ID_RE)
    method: Literal["weighted", "ip_hash"] = "weighted"
    protocol: Literal["http", "https"] = "http"
    origins: list[PoolOrigin] = Field(min_length=1, max_length=20)
    health: Health = Health()


class Pools(Strict):
    pools: list[Pool] = Field(default_factory=list)

    @field_validator("pools")
    @classmethod
    def _unique(cls, v):
        names = [p.name for p in v]
        if len(names) != len(set(names)):
            raise ValueError("نام استخرها باید یکتا باشد")
        return v


class TunnelOrigin(Strict):
    address: str
    port: int | None = Field(None, ge=1, le=65535)  # default 443 with tls, else 80
    tls: bool = False
    sni: str | None = None
    verify: bool = False

    @field_validator("address")
    @classmethod
    def _addr(cls, v, info: ValidationInfo):
        return _origin_address(v, lenient=_stored(info))

    @field_validator("sni")
    @classmethod
    def _sni(cls, v):
        from .validation import validate_hostname

        return validate_hostname(v) if v else None

    @model_validator(mode="after")
    def _port(self):
        if self.port is None:
            self.port = 443 if self.tls else 80
        return self


class TunnelPath(Strict):
    id: str = Field(pattern=ID_RE)
    path: str
    protocol: Literal["ws", "httpupgrade", "grpc", "xhttp", "h2"]
    origin: TunnelOrigin | None = None
    pool: str | None = Field(None, pattern=ID_RE)

    @field_validator("path")
    @classmethod
    def _path(cls, v):
        v = (v or "").strip()
        if not TUNNEL_PATH_RE.match(v):
            raise ValueError("مسیر تونل باید با / شروع شود و فقط حروف انگلیسی، عدد و . _ ~ / - داشته باشد "
                             "(حداکثر ۲۰۰ کاراکتر، مثل /my-secret-service)")
        if v.lower().startswith("/__pcdn"):
            raise ValueError("مسیرهای /__pcdn رزرو شده‌اند")
        return v

    @model_validator(mode="after")
    def _target(self):
        if self.origin is not None and self.pool is not None:
            raise ValueError("برای هر مسیر تونل فقط یکی از origin یا pool را تعیین کنید")
        return self


class Tunnel(Strict):
    enabled: bool = False
    paths: list[TunnelPath] = Field(default_factory=list, max_length=50)
    idle_timeout: int = Field(3600, ge=60, le=86400)
    per_connection_mbps: int = Field(0, ge=0, le=100000)
    max_connections_per_ip: int = Field(0, ge=0, le=10000)
    allowed_countries: list[str] = Field(default_factory=list, max_length=250)
    fallback: Literal["origin", "decoy", "404"] = "origin"
    # SPEC §15.2: share-based admission of new tunnel sessions while the node is hot
    fair_share: bool = True

    @field_validator("paths")
    @classmethod
    def _unique(cls, v):
        _unique_ids(v)
        paths = [p.path for p in v]
        if len(paths) != len(set(paths)):
            raise ValueError("مسیرهای تونل باید یکتا باشند")
        return v

    @field_validator("allowed_countries")
    @classmethod
    def _countries(cls, v):
        out = []
        for c in v:
            c = c.strip().upper()
            if not re.match(r"^[A-Z]{2}$", c):
                raise ValueError("کد کشور باید دو حرفی باشد (مثل IR)")
            if c not in out:
                out.append(c)
        return out


class Header(Strict):
    name: str = Field(pattern=HEADER_NAME_RE)
    value: str | None = Field(None, max_length=512, pattern=r"^[\x20-\x21\x23-\x7e]*$")

    @field_validator("name")
    @classmethod
    def _allowed(cls, v):
        if v.lower() in FORBIDDEN_HEADERS:
            raise ValueError(f"هدر {v} قابل تغییر نیست")
        return v


class Headers(Strict):
    request: list[Header] = Field(default_factory=list, max_length=20)
    response: list[Header] = Field(default_factory=list, max_length=20)


class Hotlink(Strict):
    enabled: bool = False
    extensions: list[str] = Field(default_factory=lambda: ["jpg", "jpeg", "png", "gif", "webp", "svg", "mp4"],
                                  max_length=50)
    allowed_referers: list[str] = Field(default_factory=list, max_length=100)
    allow_empty: bool = True

    @field_validator("extensions")
    @classmethod
    def _ext(cls, v):
        v = [e.strip().lower().lstrip(".") for e in v]
        if not all(re.match(r"^[a-z0-9]{1,10}$", e) for e in v):
            raise ValueError("پسوند نامعتبر")
        return v

    @field_validator("allowed_referers")
    @classmethod
    def _refs(cls, v):
        out = []
        for r in v:
            r = r.strip().lower()
            if not re.match(r"^(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$", r):
                raise ValueError(f"دامنه نامعتبر: {r}")
            out.append(r)
        return out


TRANSFORM_SECRET_RE = re.compile(r"^[A-Za-z0-9_\-]{32,128}$")


class Image(Strict):
    """Image optimization. SPEC §16.6 (images v2): `avif` (AVIF for clients accepting it, on nodes
    with the `avif` capability), `smart_crop` (entropy crop for fit=cover) and the signed-URL key
    `transform_secret`: write-only — stored encrypted outside the section (site_secrets), GET returns
    "" plus `transform_secret_set`; a PUT with ""/omitted keeps the stored key (generate one with
    POST /sites/{domain}/image/transform-secret, remove it with DELETE). While a key is set the
    edges only build variants for URLs carrying a valid `sig` (see app/images.py for the algorithm).
    `transform_secret_set` is output only and ignored on input."""
    enabled: bool = False
    quality: int = Field(85, ge=10, le=100)
    max_width: int = Field(2000, ge=16, le=8000)
    # serve WebP for JPEG/PNG to clients sending Accept: image/webp (SPEC §14.1); independent of the
    # resizing toggle `enabled`, but like it gated by features.image_optimization
    auto_webp: bool = False
    avif: bool = False
    smart_crop: bool = False
    transform_secret: str = Field("", max_length=128)
    transform_secret_set: bool | None = None

    @field_validator("transform_secret")
    @classmethod
    def _secret(cls, v):
        v = (v or "").strip()
        if v and not TRANSFORM_SECRET_RE.match(v):
            raise ValueError("کلید امضای تبدیل تصویر باید ۳۲ تا ۱۲۸ نویسه از حروف انگلیسی، عدد، - و _ باشد")
        return v


# ------------------------------------------------------------------ video (SPEC §16.5)

class Video(Strict):
    """HLS/DASH delivery: manifests (*.m3u8, *.mpd) cached `manifest_ttl` seconds with
    stale-while-revalidate, segments (*.ts, *.m4s, *.mp4, *.aac) `segment_ttl` seconds (byte-range
    slices of large mp4), CORS * on media, optional prefetch of the next numbered segment."""
    enabled: bool = False
    segment_ttl: int = Field(86400, ge=60, le=31536000)
    manifest_ttl: int = Field(2, ge=1, le=3600)
    prefetch_next: bool = True


# ------------------------------------------------------------------ TCP/UDP proxy (SPEC §16.4)

L4_ID_RE = r"^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$"  # also the DNS label of l4-<id>.<domain>
L4_PORT_MIN = 1024
ALWAYS_RESERVED_PORTS = {22, 53, 80, 443, 8089, 8090, 8091}  # edge loopback image (8089/8090) and storage-fetch (8091) servers


class L4Origin(Strict):
    address: str
    port: int = Field(ge=1, le=65535)

    @field_validator("address")
    @classmethod
    def _addr(cls, v, info: ValidationInfo):
        return _origin_address(v, lenient=_stored(info))


class L4App(Strict):
    """One TCP/UDP proxy app. `edge_port` null/omitted = allocated by the controller (and kept on
    later writes of the same app id); `hostname` (l4-<id>.<domain>, resolving to the edges of the
    site's group) is output only and ignored on input."""
    id: str = Field(pattern=L4_ID_RE)
    protocol: Literal["tcp", "udp"] = "tcp"
    edge_port: int | None = Field(None, ge=L4_PORT_MIN, le=65535)
    origin: L4Origin
    proxy_protocol: Literal["off", "v1"] = "off"  # nginx stream sends PROXY protocol v1 only
    ip_allow: list[str] = Field(default_factory=list, max_length=100)  # empty = every client
    idle_timeout: int = Field(300, ge=10, le=3600)
    enabled: bool = True
    hostname: str | None = None

    @field_validator("ip_allow")
    @classmethod
    def _cidrs(cls, v):
        out = []
        for c in v:
            try:
                net = str(ipaddress.ip_network(str(c).strip(), strict=False))
            except ValueError:
                raise ValueError(f"IP/CIDR نامعتبر: {c}") from None
            if net not in out:
                out.append(net)
        return out

    @model_validator(mode="after")
    def _check(self):
        if self.protocol == "udp" and self.proxy_protocol != "off":
            raise ValueError("PROXY protocol فقط برای برنامه‌های TCP پشتیبانی می‌شود")
        return self


class L4(Strict):
    apps: list[L4App] = Field(default_factory=list, max_length=L4_APPS_MAX)

    @field_validator("apps")
    @classmethod
    def _unique(cls, v):
        ids = [a.id for a in v]
        if len(ids) != len(set(ids)):
            raise ValueError("شناسه برنامه‌ها باید یکتا باشد")
        ports = [a.edge_port for a in v if a.edge_port is not None]
        if len(ports) != len(set(ports)):
            raise ValueError("پورت لبه (edge_port) هر برنامه باید یکتا باشد")
        return v


# ------------------------------------------------------------------ secondary DNS (SPEC §16.7)

TSIG_NAME_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]{0,61}"
                          r"[a-z0-9_])?)*$")
TSIG_ALGORITHMS = ("hmac-sha256", "hmac-sha384", "hmac-sha512", "hmac-sha1", "hmac-md5")


def _public_ip(v: str, what: str, cidr: bool = False, lenient: bool = False) -> str:
    v = str(v or "").strip()
    try:
        net = ipaddress.ip_network(v, strict=False) if cidr else None
        ip = net.network_address if net is not None else ipaddress.ip_address(v)
    except ValueError:
        raise ValueError(f"{what} نامعتبر است: {v}") from None
    from .netguard import is_public_ip

    if ip.is_private or ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local \
            or ip.is_reserved or (not lenient and not is_public_ip(str(ip))):
        raise ValueError(f"{what} باید آدرس عمومی باشد: {v}")
    if net is not None:
        return str(net)
    return str(ip)


class TsigKey(Strict):
    """TSIG key shared with the customer's DNS servers. `secret` (base64) is write-only: stored
    encrypted outside the section, GET returns "" plus `secret_set`; ""/omitted keeps the stored one."""
    name: str = Field(max_length=253)
    algorithm: Literal["hmac-sha256", "hmac-sha384", "hmac-sha512", "hmac-sha1", "hmac-md5"] = "hmac-sha256"
    secret: str = Field("", max_length=512)
    secret_set: bool | None = None

    @field_validator("name")
    @classmethod
    def _name(cls, v):
        v = (v or "").strip().lower().rstrip(".")
        if not TSIG_NAME_RE.match(v):
            raise ValueError("نام کلید TSIG نامعتبر است (مثل transfer-key یا key.example.com)")
        return v

    @field_validator("secret")
    @classmethod
    def _secret(cls, v):
        import base64
        import binascii

        v = (v or "").strip()
        if not v:
            return ""
        try:
            raw = base64.b64decode(v, validate=True)
        except (binascii.Error, ValueError):
            raise ValueError("کلید مخفی TSIG باید base64 باشد") from None
        if len(raw) < 16:
            raise ValueError("کلید مخفی TSIG باید دست‌کم ۱۶ بایت (۱۲۸ بیت) باشد")
        return v


class DnsSecondary(Strict):
    """Secondary DNS (SPEC §16.7). mode primary_elsewhere: our nameservers serve the zone as a
    PowerDNS slave zone transferred (AXFR) from the customer's `primaries` (with `tsig` when set);
    the records managed here are then NOT published. `allow_axfr`: addresses of the customer's own
    secondaries allowed to transfer the zone from us (requires `tsig`)."""
    mode: Literal["off", "primary_elsewhere"] = "off"
    primaries: list[str] = Field(default_factory=list, max_length=10)
    tsig: TsigKey | None = None
    allow_axfr: list[str] = Field(default_factory=list, max_length=20)

    @field_validator("primaries")
    @classmethod
    def _primaries(cls, v, info: ValidationInfo):
        return list(dict.fromkeys(_public_ip(x, "آدرس سرور اصلی (primary)", lenient=_stored(info)) for x in v))

    @field_validator("allow_axfr")
    @classmethod
    def _axfr(cls, v, info: ValidationInfo):
        return list(dict.fromkeys(_public_ip(x, "آدرس مجاز انتقال زون", cidr=True, lenient=_stored(info))
                                  for x in v))

    @model_validator(mode="after")
    def _check(self):
        if self.mode == "primary_elsewhere" and not self.primaries:
            raise ValueError("برای حالت primary_elsewhere دست‌کم یک آدرس سرور اصلی (primaries) لازم است")
        if self.allow_axfr and self.tsig is None:
            raise ValueError("انتقال زون به سرورهای شما (allow_axfr) فقط با کلید TSIG مجاز است")
        return self


class ErrorPages(Strict):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    e5xx: str | None = Field(None, alias="5xx", max_length=65536)
    e4xx: str | None = Field(None, alias="4xx", max_length=65536)


# ------------------------------------------------------------------ rules & security (SPEC §14.2)

HTTP_METHODS = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
# headers a transform rule may never set or remove: hop-by-hop / framing headers and the headers the
# platform itself relies on (visitor IP + forwarding chain, internal X-Pcdn-* hop headers)
TRANSFORM_RESERVED = {"connection", "keep-alive", "transfer-encoding", "upgrade", "te", "trailer", "trailers",
                      "host", "content-length", "x-real-ip", "forwarded"}
TRANSFORM_RESERVED_PREFIXES = ("proxy-", "x-pcdn-", "x-forwarded-")
# may be removed but never set: a rule must not forge a visitor's cookies or plant cookies
TRANSFORM_REMOVE_ONLY = {"cookie", "set-cookie"}
# printable ASCII only (no CR/LF or other control characters: no header injection)
HEADER_VALUE_RE = re.compile(r"^[\x20-\x7e]{1,1024}$")
# rewrite_path replacement: a path (optionally with a query) using URL characters and $1..$9
REWRITE_RE = re.compile(r"^/[A-Za-z0-9\-._~%!$&'()*+,;=:@/?]*$")
PCT_BAD_RE = re.compile(r"%(?![0-9A-Fa-f]{2})")
HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$")
# characters kept literally when normalising redirect sources / targets (everything else, e.g.
# non-ASCII letters or a space, is percent-encoded; existing %XX escapes are kept as they are)
REDIRECT_SOURCE_SAFE = "!&'()*+,;=:@/%"
REDIRECT_TARGET_SAFE = "!&'()*+,;=:@/?#[]%$"

REGEX_MAX_LEN = 256
REGEX_MAX_UNBOUNDED = 10  # `*`, `+`, `{n,}` in one pattern


def _country_codes(v: list[str]) -> list[str]:
    out = []
    for c in v:
        c = c.strip().upper()
        if not re.match(r"^[A-Z]{2}$", c):
            raise ValueError("کد کشور باید دو حرفی باشد (مثل IR)")
        if c not in out:
            out.append(c)
    return out


# --- regular-expression safety (firewall regex conditions, transform rewrite_path, regex redirects)
# The edges evaluate these patterns (PCRE / PCRE2 behind njs: backtracking engines) on every
# request, on values the visitor chooses, so a pattern with catastrophic or high-degree polynomial
# backtracking would be a self-inflicted DoS. This is a faithful port of the edge's own check
# (edge/pcdn-agent.py regex_unsafe, which re-checks every customer regex and SKIPS an unsafe one):
# keeping both verdicts identical means a customer gets a 422 here at save time instead of a rule
# that the edge silently drops (controller/tests/test_regex_parity.py loads the agent and compares).
#   * no back-references / conditionals;
#   * no quantified group that itself contains a quantifier unless a mandatory character the inner
#     quantifiers can never consume separates the repetitions (`(a+)+`, `(.*a)*`, `(\w+\s?)*` are
#     rejected, `(?:/[a-z]+)*` is fine), and no repeated alternation whose alternatives can start
#     alike (`(a|ab)*`);
#   * at most REGEX_MAX_UNBOUNDED unbounded quantifiers;
#   * polynomial backtracking bounded: wide quantifiers (unbounded, or bounded above
#     REGEX_WIDE_REPEAT) that follow each other without a separating mandatory character form a
#     chain; its length, plus one for an unanchored pattern (every start position is tried), must
#     stay <= REGEX_MAX_DEGREE (`a.*b.*c`, `Mozilla.*Windows.*Chrome`, `^/(.*)/(.*)/(.*)x$` are 3).
# Character sets are compared case-insensitively (njs compiles firewall regexes with `i`, nginx
# page-rule locations are `~*`) over a fixed sample of code points, exactly as the edge does.

try:  # Python 3.11+
    from re import _constants as _sre_c
    from re import _parser as _sre_p
except ImportError:  # pragma: no cover - older Pythons
    import sre_constants as _sre_c
    import sre_parse as _sre_p

REGEX_MAX_DEGREE = 2    # edge REGEX_MAX_DEGREE
REGEX_WIDE_REPEAT = 32  # edge REGEX_WIDE_REPEAT: `{n,m}` with m >= this counts as wide

_REPEAT_OPS = {_sre_c.MAX_REPEAT, _sre_c.MIN_REPEAT} | (
    {_sre_c.POSSESSIVE_REPEAT} if hasattr(_sre_c, "POSSESSIVE_REPEAT") else set())
_ATOMIC = getattr(_sre_c, "ATOMIC_GROUP", None)
# characters tried when testing whether two character sets overlap (edge _RX_SAMPLE)
_RX_SAMPLE = list(range(0x20, 0x7f)) + [0x09, 0x0a, 0xa0, 0xe9, 0x627, 0x6cc, 0x4e00]


class _RegexUnsafe(ValueError):
    pass


def _children(op, av) -> list:
    if op in _REPEAT_OPS:
        return [av[2]]
    if op == _sre_c.SUBPATTERN:
        return [av[-1]]
    if op == _sre_c.BRANCH:
        return list(av[1])
    if op in (_sre_c.ASSERT, _sre_c.ASSERT_NOT):
        return [av[1]]
    if _ATOMIC is not None and op == _ATOMIC:
        return [av]
    return []


def _category_has(cat, c: int) -> bool:
    ch = chr(c)
    word = ch.isalnum() or ch == "_"
    return {_sre_c.CATEGORY_DIGIT: ch.isdigit(), _sre_c.CATEGORY_NOT_DIGIT: not ch.isdigit(),
            _sre_c.CATEGORY_SPACE: ch.isspace(), _sre_c.CATEGORY_NOT_SPACE: not ch.isspace(),
            _sre_c.CATEGORY_WORD: word, _sre_c.CATEGORY_NOT_WORD: not word}.get(cat, True)


def _in_item_has(item, c: int) -> bool:
    op, av = item
    if op == _sre_c.LITERAL:
        return c == av
    if op == _sre_c.RANGE:
        return av[0] <= c <= av[1]
    if op == _sre_c.CATEGORY:
        return _category_has(av, c)
    return True


def _char_pred(op, av):
    """Predicate "can this one-character element match code point c" (case-insensitive), or None
    for any other element."""
    if op == _sre_c.ANY:
        return lambda c: True
    if op == _sre_c.LITERAL:
        def base(c):
            return c == av
    elif op == _sre_c.NOT_LITERAL:
        def base(c):
            return c != av
    elif op == _sre_c.IN:
        items = list(av)
        neg = bool(items) and items[0][0] == _sre_c.NEGATE
        items = items[1:] if neg else items

        def base(c):
            hit = any(_in_item_has(i, c) for i in items)
            return not hit if neg else hit
    else:
        return None

    def pred(c):
        if base(c):
            return True
        ch = chr(c)
        return any(base(ord(x)) for x in (ch.lower(), ch.upper()) if len(x) == 1 and x != ch)
    return pred


def _consumable(sub) -> list:
    """Predicates of every single-character element anywhere inside `sub`."""
    out = []
    for op, av in sub:
        p = _char_pred(op, av)
        if p is not None:
            out.append(p)
        for child in _children(op, av):
            out.extend(_consumable(child))
    return out


def _separators(sub) -> list:
    """Mandatory one-character elements at the top of `sub` (plain groups too), as predicates."""
    out = []
    for op, av in sub:
        if op in (_sre_c.LITERAL, _sre_c.IN):
            out.append(_char_pred(op, av))
        elif op == _sre_c.SUBPATTERN:
            out.extend(_separators(av[-1]))
    return out


def _overlap(a: list, b: list) -> bool:
    return any(any(p(c) for p in a) and any(q(c) for q in b) for c in _RX_SAMPLE)


def _repeats(sub):
    """(lo, hi, body) of every quantifier inside `sub`, recursively."""
    for op, av in sub:
        if op in _REPEAT_OPS:
            yield av
        for child in _children(op, av):
            yield from _repeats(child)


def _ambiguous(body) -> bool:
    """A repeated `body` holding an inner quantifier and no separator the inner ones never consume."""
    inner = [r for r in _repeats(body) if r[1] > 1]
    if not inner:
        return False
    preds = [p for r in inner for p in _consumable(r[2])]
    for sep in _separators(body):
        if not any(sep(c) and any(p(c) for p in preds) for c in _RX_SAMPLE):
            return False  # a character the inner quantifiers never consume splits the repetitions
    return True


def _first_preds(sub) -> tuple[list, bool]:
    """Predicates for the first character `sub` can consume, and whether `sub` can match empty."""
    preds: list = []
    for op, av in sub:
        p = _char_pred(op, av)
        if p is not None:
            return preds + [p], False
        if op in (_sre_c.AT, _sre_c.ASSERT, _sre_c.ASSERT_NOT):
            continue  # zero-width
        if op == _sre_c.SUBPATTERN:
            fp, nullable = _first_preds(av[-1])
        elif op in _REPEAT_OPS:
            fp, nullable = _first_preds(av[2])
            nullable = nullable or av[0] == 0
        elif op == _sre_c.BRANCH:
            fp, nullable = [], False
            for b in av[1]:
                bp, bn = _first_preds(b)
                fp += bp
                nullable = nullable or bn
        else:
            return preds + [lambda c: True], False  # unknown element: assume anything
        preds += fp
        if not nullable:
            return preds, False
    return preds, True


def _quantified_alternations(v: str) -> list[list[str]]:
    """Alternatives of every group in the raw pattern that is repeated more than once, e.g. `(a|ab)+`
    -> [["a", "ab"]]. Python's parser merges / factors alternatives (`(a|a)` becomes `[a]`), but the
    edges' PCRE backtracks through each alternative, so this is checked on the pattern text."""
    out, stack, i, n, in_class = [], [], 0, len(v), False
    while i < n:
        ch = v[i]
        if ch == "\\":
            i += 2
            continue
        if in_class:
            in_class = ch != "]"
            i += 1
            continue
        if ch == "[":
            in_class, i = True, i + 1
            if v[i:i + 1] == "^":
                i += 1
            if v[i:i + 1] == "]":
                i += 1
            continue
        if ch == "(":
            stack.append((i, []))
        elif ch == "|" and stack:
            stack[-1][1].append(i)
        elif ch == ")" and stack:
            start, bars = stack.pop()
            rest = v[i + 1:]
            m = re.match(r"\{(\d*)(,?)(\d*)\}", rest)
            if rest[:1] in ("*", "+"):
                hi = 2
            elif m:
                hi = int(m.group(3)) if m.group(3) else (2 if m.group(2) else int(m.group(1) or 0))
            else:
                hi = 0
            if hi > 1 and bars:
                body = start + 1
                pre = re.match(r"\?(?:[:=!>|]|<[=!]|[a-zA-Z-]+:|P<\w+>)", v[body:i])
                body += pre.end() if pre else 0
                parts, prev = [], body
                for b in bars:
                    parts.append(v[prev:b])
                    prev = b + 1
                parts.append(v[prev:i])
                out.append(parts)
        i += 1
    return out


def _overlapping_alternatives(parts: list[str]) -> bool:
    firsts = []
    for part in parts:
        try:
            preds, nullable = _first_preds(_sre_p.parse(part))
        except Exception:  # noqa: BLE001 - not parseable on its own: assume the worst (as the edge)
            return True
        if nullable:
            return True  # an empty alternative inside a repeat
        firsts.append(preds)
    return any(_overlap(firsts[a], firsts[b]) for a in range(len(firsts)) for b in range(a + 1, len(firsts)))


def _chain(sub, chain: list, length: int, state: dict) -> tuple[list, int]:
    """Walk `sub` as a sequence, carrying the current chain of wide quantifiers (the predicates of
    what they consume, and how many); state["degree"] keeps the longest chain seen (edge _rx_chain)."""
    for op, av in sub:
        if op in _REPEAT_OPS and (av[1] == _sre_c.MAXREPEAT or av[1] >= REGEX_WIDE_REPEAT):
            preds = _consumable(av[2]) or [lambda c: True]
            if chain and _overlap(chain, preds):
                chain, length = chain + preds, length + 1
            else:
                chain, length = list(preds), 1
            state["degree"] = max(state["degree"], length)
            _chain(av[2], [], 0, state)  # a body with its own inner quantifier: _ambiguous
        elif op in _REPEAT_OPS:  # optional / small bounded repeat: its body continues the sequence
            for _ in range(max(1, min(av[1], 3))):
                chain, length = _chain(av[2], chain, length, state)
        elif op == _sre_c.SUBPATTERN:
            chain, length = _chain(av[-1], chain, length, state)
        elif _ATOMIC is not None and op == _ATOMIC:
            chain, length = _chain(av, chain, length, state)
        elif op == _sre_c.BRANCH:
            # any alternative may be the one taken: the union of what they leave, the longest chain
            outs = [_chain(b, list(chain), length, state) for b in av[1]]
            chain, length = [p for c2, _ in outs for p in c2], max([l2 for _, l2 in outs] + [0])
        elif op in (_sre_c.ASSERT, _sre_c.ASSERT_NOT):
            _chain(av[1], [], 0, state)  # runs at each position on its own
        else:
            p = _char_pred(op, av)
            if p is not None and chain and not any(p(c) and any(q(c) for q in chain) for c in _RX_SAMPLE):
                chain, length = [], 0  # a mandatory character the chain never consumes splits it
    return chain, length


def _check_tree(sub, state: dict):
    for op, av in sub:
        if op in (_sre_c.GROUPREF, _sre_c.GROUPREF_EXISTS):
            raise _RegexUnsafe("ارجاع به گروه (مثل \\1) و شرط در عبارت منظم مجاز نیست")
        if op in _REPEAT_OPS:
            lo, hi, body = av
            if hi == _sre_c.MAXREPEAT:
                state["unbounded"] += 1
            if hi > 1 and _ambiguous(body):
                raise _RegexUnsafe("عبارت منظم کمیت‌سنج تودرتو دارد (مثل (a+)+) و ممکن است بسیار کند اجرا شود؛ "
                                   "آن را ساده کنید")
        for child in _children(op, av):
            _check_tree(child, state)


def _safe_regex(v: str | None, nginx: bool = False) -> re.Pattern:
    """Compile a customer regex after the safety checks; raises ValueError (Persian). Same verdict as
    the edge's regex_unsafe (edge/pcdn-agent.py). nginx: the pattern is rendered into the nginx
    config (regex redirects, rewrite_path), where the edge only accepts printable ASCII and the
    syntax PCRE shares with Python (edge pcre_regex)."""
    if not isinstance(v, str) or not v:
        raise ValueError("عبارت منظم (regex) لازم است")
    if len(v) > REGEX_MAX_LEN:
        raise ValueError(f"عبارت منظم حداکثر {REGEX_MAX_LEN} کاراکتر می‌تواند باشد")
    if any(ch.isspace() or ord(ch) < 0x20 or 0x7f <= ord(ch) < 0xa0 for ch in v):
        raise ValueError("عبارت منظم نباید فاصله یا کاراکتر کنترلی داشته باشد (برای فاصله از \\s یا %20 "
                         "استفاده کنید)")
    if nginx:
        if not re.match(r"^[\x21-\x7e]+$", v):
            raise ValueError("این عبارت منظم فقط کاراکترهای ASCII (بدون فاصله) می‌پذیرد؛ لبه‌ها عبارت منظم "
                             "مسیر با حروف غیرلاتین را اجرا نمی‌کنند")
        if re.search(r"\\[NuUlL]", v) or any(set(m.group(1)) - set("imsx-")
                                              for m in re.finditer(r"\(\?([A-Za-z-]+)[:)]", v)):
            raise ValueError("این عبارت منظم نحوی دارد که لبه‌ها (PCRE) پشتیبانی نمی‌کنند (\\N، \\u، \\U، "
                             "\\l، \\L یا پرچمی جز i، m، s، x)")
    if "(?P" in v:
        raise ValueError("گروه نام‌دار پایتونی (?P<...>) پشتیبانی نمی‌شود؛ از گروه معمولی (...) و $1..$9 "
                         "استفاده کنید")
    try:
        with warnings.catch_warnings():  # FutureWarning on "[[" / "--" etc.: not ours to report
            warnings.simplefilter("ignore")
            compiled = re.compile(v)
            tree = _sre_p.parse(v)
    except (re.error, RecursionError, OverflowError, ValueError, TypeError) as e:
        raise ValueError(f"عبارت منظم نامعتبر: {e}") from None
    state = {"unbounded": 0, "degree": 0}
    try:
        _check_tree(tree, state)
        if state["unbounded"] > REGEX_MAX_UNBOUNDED:
            raise _RegexUnsafe(f"عبارت منظم بیش از {REGEX_MAX_UNBOUNDED} کمیت‌سنج نامحدود (* یا +) دارد؛ "
                               "آن را ساده کنید")
        if any(_overlapping_alternatives(parts) for parts in _quantified_alternations(v)):
            raise _RegexUnsafe("عبارت منظم گروه تکرارشونده‌ای دارد که گزینه‌هایش با یک کاراکتر شروع می‌شوند "
                               "(مثل (a|ab)+) و ممکن است بسیار کند اجرا شود؛ آن را ساده کنید")
        _chain(tree, [], 0, state)
    except _RegexUnsafe as e:
        raise ValueError(str(e)) from None
    except RecursionError:
        raise ValueError("عبارت منظم بیش از حد تودرتو است؛ آن را ساده کنید") from None
    if state["degree"] + (0 if v.startswith("^") else 1) > REGEX_MAX_DEGREE:
        raise ValueError(
            "عبارت منظم چند کمیت‌سنج باز (مثل .* یا .+) پشت سر هم دارد (مثل a.*b.*c) و ممکن است روی "
            "ورودی بلند بسیار کند اجرا شود؛ لبه‌ها چنین قاعده‌ای را اجرا نمی‌کنند. تعداد .* ها را کم کنید، "
            "به‌جای .* از مجموعهٔ محدودتری مثل [^/]* استفاده کنید یا عبارت را با ^ لنگر بزنید")
    return compiled


def _regex_of(v, info: ValidationInfo | None, nginx: bool = False) -> re.Pattern:
    """A customer regex of a section being validated: the full safety check on a write; stored data
    (context STORED) only has to compile, so a rule saved before a check was added keeps parsing
    (and is shown with a warning) instead of the whole section falling back to its default. The
    edge config build drops such rules (unsafe_regex_rules) and the edges skip them too."""
    if not _stored(info):
        return _safe_regex(v, nginx=nginx)
    if not isinstance(v, str) or not v:
        raise ValueError("عبارت منظم (regex) لازم است")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            return re.compile(v)
    except (re.error, RecursionError, OverflowError, ValueError) as e:
        raise ValueError(f"عبارت منظم نامعتبر: {e}") from None


@functools.lru_cache(maxsize=4096)
def regex_problem(v: str, nginx: bool = False) -> str | None:
    """Why `v` fails _safe_regex (Persian), or None when it passes (cached: the edge config build
    checks stored rules on every poll)."""
    try:
        _safe_regex(v, nginx=nginx)
        return None
    except ValueError as e:
        return str(e)


def regex_safe(v: str, nginx: bool = False) -> bool:
    """True when `v` passes _safe_regex."""
    return regex_problem(v, nginx) is None


def firewall_rule_safe(rule: dict) -> bool:
    """A stored firewall rule whose regex conditions all pass the safety check (H2)."""
    return all(regex_safe(c["value"]) for c in rule.get("conditions") or []
               if c.get("op") == "regex" and isinstance(c.get("value"), str))


def transform_rule_safe(rule: dict) -> bool:
    """A stored transform rule whose rewrite_path regexes all pass the safety check (the whole rule
    is dropped: its other actions may only make sense together with the rewrite)."""
    return all(regex_safe(a["regex"], nginx=True) for a in rule.get("actions") or []
               if a.get("type") == "rewrite_path" and isinstance(a.get("regex"), str))


def redirect_rule_safe(rule: dict) -> bool:
    """A stored redirect rule whose regex source passes the safety check."""
    return rule.get("match") != "regex" or not isinstance(rule.get("source"), str) or regex_safe(
        rule["source"], nginx=True)


_RULE_SAFE = {"firewall": firewall_rule_safe, "transform": transform_rule_safe, "redirects": redirect_rule_safe}


def unsafe_regex_rules(cfg: dict) -> dict[str, list[str]]:
    """{section: [rule id, ...]} of the stored rules (firewall / transform / redirects) whose regex
    fails today's safety check, for the edge config build (dropped), the per-site warnings and the
    scheduler alert. `cfg` is all_config(site) (or any dict holding those sections)."""
    out: dict[str, list[str]] = {}
    for name, ok in _RULE_SAFE.items():
        bad = [str(r.get("id")) for r in (cfg.get(name) or {}).get("rules") or [] if not ok(r)]
        if bad:
            out[name] = bad
    return out


def drop_unsafe_regex_rules(cfg: dict) -> dict:
    """`cfg` with the firewall / transform / redirect rules whose regex fails the safety check
    removed (the edges would skip them anyway; dropping only a condition would widen a rule)."""
    out = dict(cfg)
    for name, ok in _RULE_SAFE.items():
        if name in out:
            out[name] = dict(out[name], rules=[r for r in out[name]["rules"] if ok(r)])
    return out


def regex_rule_warnings(site, name: str) -> list[str]:
    """Persian warnings for stored rules of section `name` whose regex the edges refuse to run."""
    if name not in _RULE_SAFE:
        return []
    ids = unsafe_regex_rules({name: get_section(site, name)}).get(name)
    if not ids:
        return []
    return [f"عبارت منظم این قاعده‌ها دیگر بررسی ایمنی را رد نمی‌کند و لبه‌ها آن‌ها را اجرا نمی‌کنند: "
            f"{'، '.join(ids)}. عبارت منظم را ساده کنید (مثلاً کمیت‌سنج‌های باز پشت سر هم مثل a.*b.*c "
            f"یا ارجاع به گروه مثل \\1) و دوباره ذخیره کنید."]


def _check_refs(text: str, groups: int, allowed: bool):
    """`$` is only allowed as $1..$9 referring to an existing regex group (and only with a regex)."""
    for m in re.finditer(r"\$(\d?)(\d?)", text):
        if not allowed:
            raise ValueError("ارجاع $1..$9 (و علامت $) فقط وقتی نوع تطبیق regex است مجاز است")
        if not m.group(1) or m.group(1) == "0" or m.group(2):
            raise ValueError("علامت $ فقط به شکل $1 تا $9 (ارجاع به گروه‌های عبارت منظم) مجاز است")
        if int(m.group(1)) > groups:
            raise ValueError(f"${m.group(1)} به گروهی اشاره می‌کند که در عبارت منظم وجود ندارد "
                             f"(تعداد گروه‌ها: {groups})")


def _no_controls(v: str, what: str):
    if any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in v):
        raise ValueError(f"{what} نباید کاراکتر کنترلی یا خط جدید (CR/LF) داشته باشد")


# --- transform rules -----------------------------------------------------------------------------

def _transform_header(v: str | None, remove: bool) -> str:
    if not v or not re.match(HEADER_NAME_RE, v):
        raise ValueError("نام هدر لازم است و فقط حروف انگلیسی، عدد و خط تیره (حداکثر ۶۴ کاراکتر) مجاز است")
    low = v.lower()
    if low in TRANSFORM_RESERVED or low.startswith(TRANSFORM_RESERVED_PREFIXES):
        raise ValueError(f"هدر {v} رزرو شده است و در قوانین تبدیل قابل تغییر نیست")
    if low in TRANSFORM_REMOVE_ONLY and not remove:
        raise ValueError(f"هدر {v} را فقط می‌توان حذف کرد، نه مقداردهی")
    return v


class TransformMatch(Strict):
    path: str = "/*"
    methods: list[Literal["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]] = Field(
        default_factory=list, max_length=7)  # empty = every method
    countries: list[str] = Field(default_factory=list, max_length=50)  # empty = every country

    @field_validator("path")
    @classmethod
    def _path(cls, v):
        return _pattern(v)

    @field_validator("methods")
    @classmethod
    def _methods(cls, v):
        return list(dict.fromkeys(v))

    @field_validator("countries")
    @classmethod
    def _countries(cls, v):
        return _country_codes(v)


class TransformAction(Strict):
    """set/remove a request or response header, or rewrite the path sent to the origin.
    Fields that do not apply to `type` are normalised to null."""
    type: Literal["set_request_header", "remove_request_header", "set_response_header",
                  "remove_response_header", "rewrite_path"]
    name: str | None = None
    value: str | None = None
    regex: str | None = None
    replacement: str | None = None

    @model_validator(mode="after")
    def _check(self, info: ValidationInfo):
        if self.type == "rewrite_path":
            groups = _regex_of(self.regex, info, nginx=True).groups
            rep = self.replacement
            if not rep or len(rep) > 1024 or not REWRITE_RE.match(rep) or rep.startswith("//"):
                raise ValueError("مسیر جایگزین (replacement) باید با / شروع شود (مثل /new/$1) و فقط "
                                 "کاراکترهای مجاز URL داشته باشد (حداکثر ۱۰۲۴ کاراکتر)")
            if PCT_BAD_RE.search(rep):
                raise ValueError("کدگذاری درصدی (%XX) در مسیر جایگزین نامعتبر است")
            if rep.lower().startswith("/__pcdn"):
                raise ValueError("مسیرهای /__pcdn رزرو شده‌اند")
            _check_refs(rep, groups, allowed=True)
            self.name = self.value = None
            return self
        remove = self.type.startswith("remove_")
        self.name = _transform_header(self.name, remove)
        if remove:
            self.value = None
        elif self.value is None or not HEADER_VALUE_RE.match(self.value):
            raise ValueError("مقدار هدر لازم است و باید حداکثر ۱۰۲۴ کاراکتر چاپ‌پذیر انگلیسی بدون خط جدید "
                             "(CR/LF) باشد")
        self.regex = self.replacement = None
        return self


class TransformRule(Strict):
    id: str = Field(pattern=ID_RE)
    enabled: bool = True
    match: TransformMatch = TransformMatch()
    actions: list[TransformAction] = Field(min_length=1, max_length=10)


class Transform(Strict):
    """Transform rules (SPEC §14.2): applied in order; every matching enabled rule runs its actions."""
    rules: list[TransformRule] = Field(default_factory=list, max_length=1000)

    @field_validator("rules")
    @classmethod
    def _unique(cls, v):
        return _unique_ids(v)


# --- redirect rules ------------------------------------------------------------------------------

def _redirect_source(v: str) -> str:
    """exact / prefix source: a path, normalised (non-ASCII and spaces percent-encoded)."""
    v = (v or "").strip()
    _no_controls(v, "مبدأ ریدایرکت")
    if "?" in v or "#" in v:
        raise ValueError("مبدأ ریدایرکت فقط مسیر است؛ رشته پرس‌وجو (?) و # پشتیبانی نمی‌شود")
    v = quote(v, safe=REDIRECT_SOURCE_SAFE)
    if not v.startswith("/") or len(v) > 1024:
        raise ValueError("مبدأ ریدایرکت باید مسیری باشد که با / شروع می‌شود (مثل /old-page، حداکثر ۱۰۲۴ "
                         "کاراکتر)")
    if PCT_BAD_RE.search(v):
        raise ValueError("کدگذاری درصدی (%XX) در مبدأ ریدایرکت نامعتبر است")
    return v


def _url_host(h: str) -> str:
    m = re.match(r"^(.*?)(?::(\d{1,5}))?$", h.strip().lower())
    host, port = m.group(1), m.group(2)
    if "@" in host:
        raise ValueError("آدرس مقصد نباید نام کاربری/رمز (user@) داشته باشد")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError("نام میزبان مقصد نامعتبر است") from None
    if not HOST_RE.match(host) or len(host) > 253:
        raise ValueError("نام میزبان مقصد نامعتبر است")
    if port is not None:
        if not 1 <= int(port) <= 65535:
            raise ValueError("پورت مقصد نامعتبر است")
        return f"{host}:{int(port)}"
    return host


def _redirect_target(v: str, groups: int | None) -> str:
    """Absolute http(s) URL or a path; normalised. `groups` is the regex group count (None when the
    match type is not regex: no $n allowed)."""
    v = (v or "").strip()
    if not v:
        raise ValueError("مقصد ریدایرکت لازم است")
    _no_controls(v, "مقصد ریدایرکت")
    m = re.match(r"^(https?)://([^/?#]*)(.*)$", v, re.IGNORECASE)
    if m:
        rest = m.group(3)
        out = f"{m.group(1).lower()}://{_url_host(m.group(2))}{quote(rest, safe=REDIRECT_TARGET_SAFE)}"
    elif v.startswith("/") and not v.startswith("//"):
        out = quote(v, safe=REDIRECT_TARGET_SAFE)
    else:
        raise ValueError("مقصد باید آدرس کامل http(s):// یا مسیری که با / شروع می‌شود باشد")
    if len(out) > 2048:
        raise ValueError("مقصد ریدایرکت حداکثر ۲۰۴۸ کاراکتر می‌تواند باشد")
    if PCT_BAD_RE.search(out):
        raise ValueError("کدگذاری درصدی (%XX) در مقصد ریدایرکت نامعتبر است")
    _check_refs(out, groups or 0, allowed=groups is not None)
    return out


class RedirectRule(Strict):
    """exact: the path equals `source`; prefix: the path starts with `source` (the target is used as
    is, nothing is appended); regex: `source` is a regex on the path and `target` may use $1..$9.
    `preserve_query` appends the request's query string to the target."""
    id: str = Field(pattern=ID_RE)
    enabled: bool = True
    source: str
    match: Literal["exact", "prefix", "regex"] = "exact"
    target: str
    status: Literal[301, 302, 307, 308] = 301
    preserve_query: bool = False

    @model_validator(mode="after")
    def _check(self, info: ValidationInfo):
        if self.match == "regex":
            compiled = _regex_of(self.source, info, nginx=True)
            self.target = _redirect_target(self.target, compiled.groups)
            loop = (self.target.startswith("/") and "$" not in self.target
                    and compiled.search(self.target.split("?", 1)[0].split("#", 1)[0]) is not None)
        else:
            self.source = _redirect_source(self.source)
            self.target = _redirect_target(self.target, None)
            path = self.target.split("?", 1)[0].split("#", 1)[0] if self.target.startswith("/") else None
            loop = path is not None and (path == self.source if self.match == "exact"
                                         else path.startswith(self.source))
        if loop:
            raise ValueError("مقصد این ریدایرکت دوباره با همین مبدأ تطبیق می‌خورد و حلقه بی‌پایان می‌سازد")
        return self


class Redirects(Strict):
    """Redirect rules (SPEC §14.2): evaluated in order, the first enabled match wins."""
    rules: list[RedirectRule] = Field(default_factory=list, max_length=10000)

    @field_validator("rules")
    @classmethod
    def _unique(cls, v):
        _unique_ids(v)
        seen = set()
        for r in v:
            key = (r.match, r.source)
            if key in seen:
                raise ValueError(f"مبدأ «{r.source}» با نوع تطبیق {r.match} بیش از یک بار تعریف شده است")
            seen.add(key)
        return v


# --- bot management ------------------------------------------------------------------------------

class Bots(Strict):
    """Bot management (SPEC §14.2). Verified crawlers (published IP ranges, see the node-wide `bots`
    block of the edge config, AND a matching User-Agent) pass when allow_verified; unverified
    automation signals get `mode`."""
    mode: Literal["off", "log", "challenge", "block"] = "off"
    allow_verified: bool = True
    block_empty_ua: bool = True


# ------------------------------------------------------------------ analytics & platform (SPEC §14.3)

S3_BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
LOG_PREFIX_RE = re.compile(r"^[A-Za-z0-9/_.-]{0,128}$")
S3_REGION_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
S3_KEY_RE = re.compile(r"^[\x21-\x7e]*$")  # printable ASCII without spaces


def _outbound_url(v: str, what: str) -> str:
    """Syntax of an outbound URL only: no DNS here, because this also runs on every read of the
    stored section. The policy — https only, every resolved address public (SSRF guard) — is
    netguard.vet, run by validate_section on every write and again before every delivery/upload."""
    import httpx

    if not v or any(ch.isspace() or ord(ch) < 0x20 for ch in v):
        raise ValueError(f"{what} لازم است و نباید فاصله داشته باشد")
    try:
        u = httpx.URL(v)
    except Exception:  # noqa: BLE001 - httpx.InvalidURL
        raise ValueError(f"{what} نامعتبر است") from None
    if u.scheme not in ("http", "https") or not u.raw_host:
        raise ValueError(f"{what} باید آدرس کامل https:// باشد")
    return v


class Logs(Strict):
    """Log export (SPEC §14.3.2). `secret_key` is write-only: it is stored encrypted outside the
    section (site_secrets) and GET returns "" plus `secret_key_set`; a PUT with ""/omitted keeps the
    stored key. `secret_key_set` is output only and ignored on input."""
    enabled: bool = False
    s3_endpoint: str = Field("", max_length=512)
    region: str = "us-east-1"
    bucket: str = Field("", max_length=63)
    prefix: str = Field("", max_length=128)
    access_key: str = Field("", max_length=128)
    secret_key: str = Field("", max_length=256)
    secret_key_set: bool | None = None
    anonymize_ip: bool = True
    sample_rate: float = Field(1.0, ge=0.01, le=1)

    @field_validator("s3_endpoint")
    @classmethod
    def _endpoint(cls, v):
        v = (v or "").strip()
        if not v:
            return ""
        if "?" in v or "#" in v:
            raise ValueError("آدرس S3 نباید رشته پرس‌وجو (?) یا # داشته باشد")
        return _outbound_url(v, "آدرس S3").rstrip("/")

    @field_validator("region")
    @classmethod
    def _region(cls, v):
        v = (v or "").strip() or "us-east-1"
        if not S3_REGION_RE.match(v):
            raise ValueError("ناحیه (region) فقط حروف انگلیسی، عدد، - و _ (حداکثر ۶۴ کاراکتر) می‌تواند باشد")
        return v

    @field_validator("bucket")
    @classmethod
    def _bucket(cls, v):
        v = (v or "").strip()
        if v and (not S3_BUCKET_RE.match(v) or ".." in v or re.match(r"^\d+\.\d+\.\d+\.\d+$", v)):
            raise ValueError("نام باکت نامعتبر است (۳ تا ۶۳ حرف کوچک انگلیسی، عدد، نقطه و خط تیره؛ با حرف یا "
                             "عدد شروع و تمام شود)")
        return v

    @field_validator("prefix")
    @classmethod
    def _prefix(cls, v):
        v = (v or "").strip()
        if not LOG_PREFIX_RE.match(v) or ".." in v:
            raise ValueError("پیشوند فقط حروف انگلیسی، عدد و / _ . - (حداکثر ۱۲۸ کاراکتر، بدون ..) می‌تواند باشد")
        return v

    @field_validator("access_key", "secret_key")
    @classmethod
    def _key(cls, v):
        v = (v or "").strip()
        if not S3_KEY_RE.match(v):
            raise ValueError("کلید دسترسی نامعتبر است (فقط کاراکترهای چاپ‌پذیر انگلیسی بدون فاصله)")
        return v

    @model_validator(mode="after")
    def _complete(self):
        if self.enabled and not (self.s3_endpoint and self.bucket and self.access_key):
            raise ValueError("برای فعال‌سازی خروجی لاگ، آدرس S3، نام باکت و هر دو کلید لازم است")
        return self


WEBHOOK_EVENTS = ("purge.completed", "ssl.issued", "ssl.failed", "quota.warning", "quota.exceeded",
                  "site.suspended", "site.unsuspended", "attack.detected",
                  # SPEC §15.4: the site's tunnel origin went down / came back
                  "tunnel.origin_down", "tunnel.origin_up")
WEBHOOK_ID_RE = re.compile(r"^wh_[0-9a-f]{8}$")


class WebhookItem(Strict):
    """One webhook (SPEC §14.3.3). `id` is assigned by the controller when missing/unknown; the
    signing secret is controller-generated and stored outside the section (site_secrets).
    `secret_set` is output only and ignored on input."""
    id: str | None = Field(None, max_length=64)
    url: str = Field(max_length=512)
    events: list[Literal[WEBHOOK_EVENTS]] = Field(min_length=1, max_length=50)
    enabled: bool = True
    description: str = Field("", max_length=100)
    secret_set: bool | None = None

    @field_validator("id")
    @classmethod
    def _id(cls, v):
        v = (v or "").strip()
        return v if WEBHOOK_ID_RE.match(v) else None  # anything else: a new item

    @field_validator("url")
    @classmethod
    def _url(cls, v):
        return _outbound_url((v or "").strip(), "آدرس وب‌هوک")

    @field_validator("events")
    @classmethod
    def _events(cls, v):
        return list(dict.fromkeys(v))

    @field_validator("description")
    @classmethod
    def _description(cls, v):
        v = (v or "").strip()
        _no_controls(v, "توضیح")
        return v


class Webhooks(Strict):
    items: list[WebhookItem] = Field(default_factory=list, max_length=WEBHOOKS_MAX)

    @field_validator("items")
    @classmethod
    def _unique(cls, v):
        ids = [i.id for i in v if i.id]
        if len(ids) != len(set(ids)):
            raise ValueError("شناسه وب‌هوک‌ها باید یکتا باشد")
        return v


# ------------------------------------------------------------------ edge functions (SPEC §16.9)
#
# Validated exactly like the edge's norm_functions (edge/pcdn-agent.py), only stricter, so nothing the
# controller accepts is silently skipped by the edge: the route is a path prefix bound with nginx
# `location ^~`, the code is UTF-8 JavaScript run by pcdn-fn in a sandboxed QuickJS process.

FUNCTION_ROUTE_RE = re.compile(r"/[A-Za-z0-9._~/-]{0,255}")  # fullmatch (the edge's FN_ROUTE)
FUNCTION_CODE_MAX = 256 * 1024     # bytes of UTF-8 source per function (the edge's FN_MAX_CODE)
FUNCTION_ON_ERROR = Literal["502", "origin"]
# output-only fields of a function item in the API views (never stored, ignored on input)
FUNCTION_OUTPUT_FIELDS = ("code_bytes", "sha256")


def function_route_problem(route: str) -> str | None:
    """Why the edge would skip this route, or None (mirrors norm_functions)."""
    if not FUNCTION_ROUTE_RE.fullmatch(route):
        return ("مسیر تابع باید با / شروع شود و فقط حروف انگلیسی، عدد و . _ ~ / - داشته باشد "
                "(حداکثر ۲۵۶ کاراکتر، مثل /api/auth)")
    if route.lower().startswith("/__pcdn"):
        return "مسیرهای /__pcdn رزرو شده‌اند"
    segs = route.split("/")[1:-1] if route.endswith("/") else route.split("/")[1:]
    if "//" in route or any(x in (".", "..") for x in segs):
        return "مسیر تابع نباید // یا بخش‌های . و .. داشته باشد"
    return None


def routes_nest(a: str, b: str) -> bool:
    """The edge's overlap test of a function route and a tunnel path (plain string prefixes)."""
    return a.startswith(b) or b.startswith(a)


class FunctionItem(Strict):
    id: str = Field(pattern=ID_RE)
    route: str
    code: str
    enabled: bool = True
    timeout_ms: int = Field(50, ge=1, le=200, strict=True)   # CPU milliseconds per invocation
    memory_mb: int = Field(32, ge=8, le=128, strict=True)    # JS heap per invocation
    on_error: FUNCTION_ON_ERROR | None = None                # None = the section's on_error

    @field_validator("route")
    @classmethod
    def _route(cls, v):
        problem = function_route_problem(v)
        if problem:
            raise ValueError(problem)
        return v

    @field_validator("code")
    @classmethod
    def _code(cls, v):
        if not v.strip():
            raise ValueError("کد تابع خالی است")
        try:
            raw = v.encode("utf-8")
        except UnicodeEncodeError:
            raise ValueError("کد تابع باید متن UTF-8 معتبر باشد") from None
        if len(raw) > FUNCTION_CODE_MAX:
            raise ValueError(f"کد هر تابع حداکثر {FUNCTION_CODE_MAX // 1024} کیلوبایت است")
        return v


class Functions(Strict):
    enabled: bool = False
    on_error: FUNCTION_ON_ERROR = "502"   # fail closed: a broken auth function never opens the origin
    items: list[FunctionItem] = Field(default_factory=list, max_length=FUNCTIONS_MAX)

    @field_validator("items")
    @classmethod
    def _unique(cls, v):
        ids = [f.id for f in v]
        if len(ids) != len(set(ids)):
            raise ValueError("شناسه توابع باید یکتا باشد")
        routes = [f.route for f in v]
        if len(routes) != len(set(routes)):
            raise ValueError("مسیر توابع باید یکتا باشد")
        return v


def _strip_function_outputs(data):
    """Accept a GET -> PUT round trip: drop the output-only code_bytes / sha256 of each item."""
    if not isinstance(data, dict) or not isinstance(data.get("items"), list):
        return data
    return {**data, "items": [{k: v for k, v in i.items() if k not in FUNCTION_OUTPUT_FIELDS}
                              if isinstance(i, dict) else i for i in data["items"]]}


def function_facts(code: str) -> dict:
    raw = code.encode("utf-8", "surrogatepass")
    return {"code_bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def functions_view(fn: dict, code: bool = True) -> dict:
    """The functions section as the API shows it: each item with its output-only code_bytes and
    sha256; `code=False` leaves the bodies out (whole-site views: GET /config, the site object —
    the code is read from GET .../config/functions)."""
    return {**fn, "items": [{**{k: v for k, v in i.items() if code or k != "code"}, **function_facts(i["code"])}
                            for i in fn["items"]]}


def config_view(cfg: dict) -> dict:
    """A whole-site config view (all_config output) without the function bodies."""
    if "functions" in cfg:
        cfg = {**cfg, "functions": functions_view(cfg["functions"], code=False)}
    return cfg


def functions_audit(value: dict) -> dict:
    """Audit detail of a functions write: ids, count and sizes, never the code."""
    return {"section": "functions", "enabled": value["enabled"], "count": len(value["items"]),
            "items": [{"id": i["id"], "route": i["route"], "enabled": i["enabled"],
                       "code_bytes": len(i["code"].encode("utf-8", "surrogatepass"))}
                      for i in value["items"]]}


# ------------------------------------------------------------------ wave 10 (SPEC §18.1 / §18.2)

PREFIX_MAX = 256
RESERVED_PREFIX = "/__pcdn"  # the edge's own endpoints: never queued, never protected
TEXT_MAX = 500
EMAIL_RE = re.compile(r"^[a-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
                      r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")
EMAIL_DOMAIN_RE = re.compile(r"^@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")
ACCESS_APP_ID_RE = r"^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$"
# a CIDR shorter than these would open (access) / bypass (waiting room) for most of the internet
CIDR_MIN_PREFIX = {4: 8, 6: 16}


def _prefixes(v: list[str], what: str) -> list[str]:
    """URL path prefixes: start with /, the PATH_PATTERN_RE characters, no query, never /__pcdn;
    duplicates removed (order kept)."""
    out = []
    for p in v:
        p = (p or "").strip()
        if not p.startswith("/") or len(p) > PREFIX_MAX or not PATH_PATTERN_RE.match(p) or "*" in p:
            raise ValueError(f"{what}: پیشوند مسیر باید با / شروع شود و بدون * و ? باشد ({p[:60]})")
        if p == RESERVED_PREFIX or p.startswith(RESERVED_PREFIX + "/") or p.startswith(RESERVED_PREFIX + "_"):
            raise ValueError(f"{what}: مسیرهای /__pcdn/ رزرو شده‌اند")
        if p not in out:
            out.append(p)
    return out


def _cidrs_list(v: list[str], what: str) -> list[str]:
    """IPv4/IPv6 addresses or networks, normalized (host bits cleared), deduplicated."""
    out = []
    for c in v:
        try:
            net = ipaddress.ip_network((c or "").strip(), strict=False)
        except ValueError:
            raise ValueError(f"{what}: آدرس یا شبکهٔ نامعتبر: {str(c)[:60]}") from None
        if net.prefixlen < CIDR_MIN_PREFIX[net.version]:
            raise ValueError(f"{what}: شبکهٔ {net} بیش از حد بزرگ است (حداقل /{CIDR_MIN_PREFIX[net.version]})")
        s = str(net)
        if s not in out:
            out.append(s)
    return out


def _plain_text(v: str, what: str) -> str:
    """Plain text shown on an edge page (the edge HTML-escapes it): no control characters except
    newline / tab."""
    v = (v or "").strip()
    if any((ord(ch) < 32 and ch not in "\n\t") or ord(ch) == 127 for ch in v):
        raise ValueError(f"{what}: نویسهٔ کنترلی مجاز نیست")
    return v


class QueuePage(Strict):
    """Texts of the waiting room's queue page; "" = the edge's built-in text."""
    title_fa: str = Field("", max_length=TEXT_MAX)
    title_en: str = Field("", max_length=TEXT_MAX)
    message_fa: str = Field("", max_length=TEXT_MAX)
    message_en: str = Field("", max_length=TEXT_MAX)

    @field_validator("title_fa", "title_en", "message_fa", "message_en")
    @classmethod
    def _text(cls, v, info: ValidationInfo):
        return _plain_text(v, info.field_name)


class WaitingRoomBypass(Strict):
    verified_bots: bool = True
    paths: list[str] = Field(default_factory=list, max_length=20)
    ips: list[str] = Field(default_factory=list, max_length=50)

    @field_validator("paths")
    @classmethod
    def _paths(cls, v):
        return _prefixes(v, "bypass.paths")

    @field_validator("ips")
    @classmethod
    def _ips(cls, v):
        return _cidrs_list(v, "bypass.ips")


class WaitingRoom(Strict):
    """SPEC §18.1: queue visitors above `max_active` active visitors site-wide. The controller sends
    each serving edge `node_max` = ceil(max_active / healthy edges of the site's group) (waiting_room.py)."""
    enabled: bool = False
    mode: Literal["queue", "off"] = "queue"
    paths: list[str] = Field(default_factory=lambda: ["/"], min_length=1, max_length=20)
    max_active: int = Field(1000, ge=1, le=1_000_000)
    session_minutes: int = Field(10, ge=1, le=120)
    queue_page: QueuePage = Field(default_factory=QueuePage)
    bypass: WaitingRoomBypass = Field(default_factory=WaitingRoomBypass)

    @field_validator("paths")
    @classmethod
    def _paths(cls, v):
        return _prefixes(v, "paths")


def _emails(v: list[str]) -> list[str]:
    out = []
    for e in v:
        e = (e or "").strip().lower()
        if len(e) > 254 or not (EMAIL_RE.match(e) or EMAIL_DOMAIN_RE.match(e)):
            raise ValueError(f"ایمیل یا دامنهٔ نامعتبر: {e[:80]} (مثل a@b.com یا @company.com)")
        if e not in out:
            out.append(e)
    return out


def prefixes_overlap(a: str, b: str) -> bool:
    """Two path prefixes overlap when one is a (string) prefix of the other, as the edge matches."""
    return a.startswith(b) or b.startswith(a)


class AccessApp(Strict):
    id: str = Field(pattern=ACCESS_APP_ID_RE)
    name: str = Field(min_length=1, max_length=100)
    paths: list[str] = Field(min_length=1, max_length=20)
    methods: Literal["otp", "ip", "otp_or_ip"] = "otp"
    emails: list[str] = Field(default_factory=list, max_length=200)
    ips: list[str] = Field(default_factory=list, max_length=100)
    session_hours: int = Field(24, ge=1, le=720)

    @field_validator("name")
    @classmethod
    def _name(cls, v):
        v = _plain_text(v, "name")
        if not v or "\n" in v:
            raise ValueError("نام برنامه لازم است (یک خط)")
        return v

    @field_validator("paths")
    @classmethod
    def _paths(cls, v):
        return _prefixes(v, "paths")

    @field_validator("emails")
    @classmethod
    def _emails(cls, v):
        return _emails(v)

    @field_validator("ips")
    @classmethod
    def _ips(cls, v):
        return _cidrs_list(v, "ips")

    @model_validator(mode="after")
    def _method_needs(self):
        if self.methods == "otp" and not self.emails:
            raise ValueError(f"برنامه «{self.id}»: روش otp دست‌کم یک ایمیل یا @دامنه لازم دارد")
        if self.methods == "ip" and not self.ips:
            raise ValueError(f"برنامه «{self.id}»: روش ip دست‌کم یک آدرس IP یا شبکه لازم دارد")
        if self.methods == "otp_or_ip" and not (self.emails or self.ips):
            raise ValueError(f"برنامه «{self.id}»: دست‌کم یک ایمیل یا یک آدرس IP لازم است")
        return self


class Access(Strict):
    """SPEC §18.2: protect path prefixes with an e-mail one-time code and/or an IP allow list. The
    per-site `access_secret` lives in site_secrets (access.py), never in the section."""
    enabled: bool = False
    apps: list[AccessApp] = Field(default_factory=list, max_length=20)

    @field_validator("apps")
    @classmethod
    def _apps(cls, v):
        ids = [a.id for a in v]
        if len(ids) != len(set(ids)):
            raise ValueError("شناسهٔ برنامه‌ها باید یکتا باشد")
        for i, a in enumerate(v):
            for b in v[i + 1:]:
                for pa in a.paths:
                    for pb in b.paths:
                        if prefixes_overlap(pa, pb):
                            raise ValueError(f"مسیر {pa} از برنامهٔ «{a.id}» با مسیر {pb} از برنامهٔ «{b.id}» "
                                             "هم‌پوشانی دارد")
        return v


SECTIONS: dict[str, type[BaseModel]] = {
    "cache": Cache,
    "ssl": Ssl,
    "waf": Waf,
    "ddos": Ddos,
    "firewall": Firewall,
    "ratelimit": RateLimit,
    "pagerules": PageRules,
    "pools": Pools,
    "headers": Headers,
    "hotlink": Hotlink,
    "image": Image,
    "errorpages": ErrorPages,
    "tunnel": Tunnel,
    "transform": Transform,
    "redirects": Redirects,
    "bots": Bots,
    "logs": Logs,
    "webhooks": Webhooks,
    # wave 8 (SPEC §16)
    "l4": L4,
    "video": Video,
    "dns_secondary": DnsSecondary,
    # SPEC §16.9
    "functions": Functions,
    # wave 10 (SPEC §18.1 / §18.2)
    "waiting_room": WaitingRoom,
    "access": Access,
}

# section -> feature flag that must be on to write it
FEATURE_GATES = {"waf": "waf", "ddos": "ddos", "pools": "load_balancer", "image": "image_optimization",
                 "tunnel": "tunnel", "logs": "log_export", "l4": "l4_proxy",
                 "functions": "edge_functions", "dns_secondary": "dns_secondary",
                 "waiting_room": "waiting_room", "access": "access"}


# ------------------------------------------------------------------ helpers

def _origin_address(v: str, lenient: bool = False) -> str:
    """Public IPv4, [IPv6] or hostname of an origin server (origin_guard.py: IP literals must be
    globally routable; host names must be fully qualified and not special-use — whether they
    RESOLVE to public addresses is checked on save by check_targets and re-checked periodically)."""
    from . import origin_guard
    from .validation import validate_hostname, validate_ip

    v = (v or "").strip().lower().strip("[]")
    if ":" in v:
        return "[" + validate_ip(v, 6, strict=not lenient) + "]"
    if lenient and re.match(r"^\d+\.\d+\.\d+\.\d+$", v):
        return validate_ip(v, 4, strict=False)
    if not lenient and re.match(r"^[0-9.]+$", v):
        return validate_ip(v, 4)
    host = validate_hostname(v)
    if lenient:
        return host
    problem = origin_guard.name_problem(host)
    if problem:
        raise ValueError(problem)
    return host


def _pattern(v: str) -> str:
    v = (v or "").strip()
    if not v.startswith("/") or len(v) > 512 or not PATH_PATTERN_RE.match(v):
        raise ValueError("الگوی مسیر باید با / شروع شود (مثل /blog/*)")
    return v


def _unique_ids(rules):
    ids = [r.id for r in rules]
    if len(ids) != len(set(ids)):
        raise ValueError("شناسه قوانین باید یکتا باشد")
    return rules


def dump(model: BaseModel) -> dict:
    return model.model_dump(mode="json", by_alias=True)


def features_of(site) -> dict:
    try:
        stored = json.loads(site.features or "{}")
    except ValueError:
        stored = {}
    return {**DEFAULT_FEATURES, **stored}


def all_config(site) -> dict:
    try:
        stored = json.loads(site.config or "{}")
    except ValueError:
        stored = {}
    out = {}
    for name, model in SECTIONS.items():
        try:
            out[name] = dump(model.model_validate(stored.get(name, {}), context=STORED))
        except Exception:  # noqa: BLE001 - corrupt/legacy data falls back to defaults
            out[name] = dump(model())
    return redact(site, out)


def redact(site, cfg: dict) -> dict:
    """Write-only secrets (SPEC §14.3): never a value, only whether one is stored."""
    from . import site_secrets

    if "logs" in cfg:
        cfg["logs"] = dict(cfg["logs"], secret_key="", secret_key_set=site_secrets.has_logs_secret(site))
    if "webhooks" in cfg:
        ids = site_secrets.webhook_secret_ids(site)
        cfg["webhooks"] = {**cfg["webhooks"],
                           "items": [dict(i, secret_set=i["id"] in ids) for i in cfg["webhooks"]["items"]]}
    if "image" in cfg:
        cfg["image"] = dict(cfg["image"], transform_secret="",
                            transform_secret_set=site_secrets.has_secret(site, "image_transform"))
    if "dns_secondary" in cfg and cfg["dns_secondary"].get("tsig"):
        cfg["dns_secondary"] = dict(cfg["dns_secondary"], tsig=dict(
            cfg["dns_secondary"]["tsig"], secret="", secret_set=site_secrets.has_secret(site, "tsig")))
    if "l4" in cfg:
        domain = getattr(site, "domain", "")
        cfg["l4"] = {**cfg["l4"], "apps": [dict(a, hostname=l4_hostname(a["id"], domain))
                                           for a in cfg["l4"]["apps"]]}
    return cfg


def l4_hostname(app_id: str, domain: str) -> str:
    """The DNS name of a TCP/UDP proxy app (SPEC §16.4), answered with the site's edges."""
    return f"l4-{app_id}.{domain}"


def storable(name: str, value: dict) -> dict:
    """The section as stored: write-only / output-only fields removed."""
    if name == "logs":
        return {k: v for k, v in value.items() if k not in ("secret_key", "secret_key_set")}
    if name == "webhooks":
        return {**value, "items": [{k: v for k, v in i.items() if k != "secret_set"} for i in value["items"]]}
    if name == "image":
        return {k: v for k, v in value.items() if k not in ("transform_secret", "transform_secret_set")}
    if name == "dns_secondary" and value.get("tsig"):
        return {**value, "tsig": {k: v for k, v in value["tsig"].items() if k not in ("secret", "secret_set")}}
    if name == "l4":
        return {**value, "apps": [{k: v for k, v in a.items() if k != "hostname"} for a in value["apps"]]}
    if name == "functions":
        return _strip_function_outputs(value)
    return value


def get_section(site, name: str) -> dict:
    return all_config(site)[name]


def validate_section(site, name: str, data: dict, pools_in_use: set[str] | None = None,
                     vet: bool = True) -> dict:
    """Validate a section against schema + plan. Raises ValidationError / PermissionError.
    `vet=False` skips the outbound-URL SSRF check (the caller ran check_targets already)."""
    model = SECTIONS.get(name)
    if model is None:
        raise KeyError(name)
    feats = features_of(site)
    gate = FEATURE_GATES.get(name)
    if name == "functions":
        data = _strip_function_outputs(data)
    parsed = model.model_validate(data)
    value = dump(parsed)
    if name == "waf":  # SPEC §17: started_at / until are controller-managed
        from . import waf_learning

        value = waf_learning.manage(site, value)
    if gate and not feats[gate]:
        # allow writing the "disabled" shape so clients can always turn things off
        if value != dump(model()) and _is_enabled(name, value):
            raise PermissionError("این قابلیت در پلن شما فعال نیست")
    limits = {"firewall": ("rules", "max_firewall_rules"), "ratelimit": ("rules", "max_ratelimit_rules"),
              "pagerules": ("rules", "max_page_rules"), "pools": ("pools", "max_pools"),
              "transform": ("rules", "max_transform_rules"), "redirects": ("rules", "max_redirects"),
              "webhooks": ("items", "max_webhooks"), "l4": ("apps", "max_l4_apps"),
              "functions": ("items", "max_functions")}
    if name in limits:
        key, feat = limits[name]
        if len(value[key]) > feats[feat]:
            raise PermissionError(f"حداکثر {feats[feat]} مورد در پلن شما مجاز است")
    if name == "pools":
        # pools referenced by tunnel paths cannot be removed either
        pools_in_use = set(pools_in_use or ()) | {p["pool"] for p in get_section(site, "tunnel")["paths"]
                                                  if p["pool"]}
    if name == "pools" and pools_in_use:
        missing = pools_in_use - {p["name"] for p in value["pools"]}
        if missing:
            raise ValidationError(f"استخر {', '.join(sorted(missing))} در رکوردها استفاده شده است")
    if name == "tunnel":
        _check_tunnel(site, value, feats)
        _check_tunnel_vs_functions(get_section(site, "functions"), value)
    if name == "functions":
        _check_functions(value)
        _check_tunnel_vs_functions(value, get_section(site, "tunnel"))
    if name == "ssl" and value["hsts"]["preload"] and not (
            value["hsts"]["include_subdomains"] and value["hsts"]["max_age"] >= 31536000):
        raise ValidationError("preload نیازمند includeSubDomains و max-age حداقل یک سال است")
    if name == "logs" and value["enabled"] and not (value["secret_key"] or _has_logs_secret(site)):
        raise ValidationError("برای فعال‌سازی خروجی لاگ، کلید مخفی (secret_key) لازم است")
    if name == "l4":
        _check_l4(site, value)
    if name == "dns_secondary" and value["tsig"] and not value["tsig"]["secret"] and not _same_tsig(site, value):
        raise ValidationError("کلید مخفی TSIG (tsig.secret) لازم است")
    if name == "dns_secondary" and value["tsig"] and not _tsig_name_ok(site, value["tsig"]["name"]):
        # L2: PowerDNS TSIG key names are global; a customer key lives under the site's own domain
        # (a name stored before this rule is kept)
        domain = getattr(site, "domain", "")
        raise ValidationError(f"نام کلید TSIG باید زیر دامنهٔ همین سرویس باشد (مثل transfer.{domain})")
    if vet:
        check_targets(name, value)
    return value


# sections whose values name outbound targets the controller itself contacts (SSRF guard)
OUTBOUND_SECTIONS = ("logs", "webhooks")
# sections whose values name origin hosts the EDGES connect to (origin_guard.py): host names are
# resolved on save and refused when any address is not public
ORIGIN_SECTIONS = ("pools", "tunnel", "l4")
# checked by check_targets (DNS lookups) before the site row is locked
PRELOCK_SECTIONS = OUTBOUND_SECTIONS + ORIGIN_SECTIONS


def origin_hosts(name: str, value: dict, include_ips: bool = False) -> list[tuple[str, str]]:
    """(host name, label) of every origin host name in a pools / tunnel / l4 section value. IP
    literals are left out unless include_ips (on save the model validates them as public)."""
    out = []

    def add(addr: str, label: str):
        a = (addr or "").strip("[]")
        if a and (include_ips or (not re.match(r"^[0-9.]+$", a) and ":" not in a)):
            out.append((a, label))

    if name == "pools":
        for p in value.get("pools") or []:
            for o in p.get("origins") or []:
                add(o.get("address"), f"استخر {p.get('name')}")
    elif name == "tunnel":
        for p in value.get("paths") or []:
            if p.get("origin"):
                add(p["origin"].get("address"), f"مسیر تونل {p.get('id')}")
    elif name == "l4":
        for a in value.get("apps") or []:
            add((a.get("origin") or {}).get("address"), f"برنامه {a.get('id')}")
    return out


def check_targets(name: str, value: dict) -> None:
    """SSRF check of a section's outbound URLs (SPEC §14.3.2/§14.3.3): https, host resolving only
    to public addresses; and of its origin host names (origin_guard.py). Needs no site state, so
    writers run it BEFORE locking the site row (DNS can be slow). Raises ValidationError."""
    if name == "logs" and value["s3_endpoint"]:
        _vet_url(value["s3_endpoint"], "آدرس S3")
    if name == "webhooks":
        for i, item in enumerate(value["items"]):
            _vet_url(item["url"], f"وب‌هوک شماره {i + 1}")
    if name in ORIGIN_SECTIONS:
        from . import origin_guard

        hosts = origin_hosts(name, value)
        problems = origin_guard.check_hosts([h for h, _ in hosts])
        for host, label in hosts:
            if host in problems:
                raise ValidationError(f"{label}: {problems[host]}")


def _has_logs_secret(site) -> bool:
    from . import site_secrets

    return site_secrets.has_logs_secret(site)


def _vet_url(url: str, what: str) -> None:
    """SSRF check on save (SPEC §14.3.2/§14.3.3): https, host resolving only to public addresses."""
    from . import netguard

    try:
        netguard.vet(url)
    except netguard.UnsafeTarget as e:
        raise ValidationError(f"{what}: {e}") from None


def _pool_multi_origin(site, pool_name: str) -> bool:
    """True when the named pool has more than one non-backup origin (F1)."""
    for p in get_section(site, "pools")["pools"]:
        if p["name"] == pool_name:
            return sum(1 for o in p["origins"] if not o.get("backup")) > 1
    return False


def _host_pools_multi_origin(site) -> bool:
    """True when any pool the site's proxied hosts inherit has more than one non-backup origin (F1).
    A tunnel path with neither origin nor pool inherits the host origin, which may be such a pool."""
    return any(_pool_multi_origin(site, r.pool)
               for r in getattr(site, "records", []) if getattr(r, "pool", None) and r.proxied)


def section_warnings(site, name: str, value: dict) -> list[str]:
    """Non-blocking Persian warnings for a validated section (F1, F34). The section is still saved;
    these only surface a footgun to the panel. Returned to the caller (a response header), never
    raised."""
    out: list[str] = []
    if name == "tunnel":
        # F1: an xhttp/h2 tunnel session is split across origins when the pool has more than one
        # non-backup origin, because (until the edge-side rendezvous fix ships) the origin is picked
        # per HTTP request. ws/grpc are unaffected.
        for p in value.get("paths", []):
            if p["protocol"] not in ("xhttp", "h2"):
                continue
            multi = _pool_multi_origin(site, p["pool"]) if p["pool"] else (
                not p["origin"] and _host_pools_multi_origin(site))
            if multi:
                out.append(f"مسیر تونل «{p['id']}» با پروتکل {p['protocol']} روی استخری با بیش از یک "
                           f"مبدأ (origin) تعریف شده است؛ هر درخواست ممکن است به مبدأ دیگری برود و "
                           f"نشست کاربر بشکند. برای این پروتکل‌ها از استخر تک‌مبدأ یا یک origin مشخص "
                           f"استفاده کنید.")
        # F34: force_https + tunnel paths — a ws/httpupgrade/xhttp client on port 80 gets a 301 and
        # can never connect. Warn when the site has force_https on and any tunnel path exists.
        if value.get("paths") and _force_https_on(site):
            out.append("force_https روشن است و این سایت مسیر تونل دارد؛ کلاینت‌های تونل روی پورت ۸۰ "
                       "با ریدایرکت ۳۰۱ روبه‌رو می‌شوند و نمی‌توانند وصل شوند. اگر تونل روی پورت ۸۰ "
                       "لازم است، force_https را خاموش کنید.")
    elif name == "ssl":
        # F34 from the other side: turning force_https on while tunnel paths exist
        if value.get("force_https") and get_section(site, "tunnel").get("paths"):
            out.append("force_https روشن شد ولی این سایت مسیر تونل دارد؛ کلاینت‌های تونل روی پورت ۸۰ "
                       "با ریدایرکت ۳۰۱ روبه‌رو می‌شوند و نمی‌توانند وصل شوند.")
        # SPEC §14.2: a client certificate is only presented on an HTTPS connection to the origin
        mode = value.get("origin_client_auth", "off")
        if mode != "off" and value.get("origin_protocol") != "https" and not any(
                p.get("protocol") == "https" for p in get_section(site, "pools")["pools"]):
            out.append("احراز هویت لبه نزد مبدأ (origin_client_auth) فقط روی اتصال HTTPS به مبدأ کار می‌کند؛ "
                       "تا origin_protocol روی https نباشد گواهی کلاینت به مبدأ ارائه نمی‌شود.")
        if mode == "custom":
            from .origin_pull import custom_ready

            if not custom_ready(site):
                out.append("حالت custom انتخاب شده ولی هنوز گواهی کلاینت معتبری بارگذاری نشده است؛ تا "
                           "بارگذاری گواهی، لبه‌ها بدون گواهی کلاینت به مبدأ وصل می‌شوند.")
    elif name == "cache":
        # SPEC §14.1: cache.shield is inert until the site's edge group has an enabled shield edge
        if value.get("shield") and not _group_has_shield(site):
            out.append("در گروه لبه این سایت هنوز هیچ سرور سپر (shield) فعالی وجود ندارد؛ تنظیم ذخیره شد "
                       "ولی تا وقتی مدیر سامانه سرور سپری اضافه نکند، درخواست‌ها مستقیم به مبدأ می‌روند.")
    return out


def _group_has_shield(site) -> bool:
    """True when the site's edge group has at least one enabled shield edge (online or not)."""
    from sqlalchemy import select
    from sqlalchemy.orm import object_session

    from .dnsbuild import site_edge_group
    from .models import Edge

    db = object_session(site)
    if db is None:
        return True  # cannot tell: do not warn
    group = site_edge_group(site)
    return db.scalar(select(Edge.id).where(Edge.enabled.is_(True), Edge.shield.is_(True),
                                           Edge.group == group).limit(1)) is not None


def _force_https_on(site) -> bool:
    try:
        return bool(get_section(site, "ssl").get("force_https"))
    except Exception:  # noqa: BLE001
        return False


def _check_tunnel(site, value: dict, feats: dict):
    """Plan limits and references of the tunnel section (the shape is checked by Tunnel)."""
    if len(value["paths"]) > feats["max_tunnel_paths"]:
        raise PermissionError(f"حداکثر {feats['max_tunnel_paths']} مسیر تونل در پلن شما مجاز است")
    cap = feats["tunnel_max_mbps"]
    # 0 (unlimited) is accepted: the edge config then applies the plan's cap (see tunnel_for_edge)
    if cap > 0 and value["per_connection_mbps"] > cap:
        raise PermissionError(f"سرعت هر اتصال تونل در پلن شما حداکثر {cap} مگابیت بر ثانیه است")
    pools = {p["name"] for p in get_section(site, "pools")["pools"]}
    for p in value["paths"]:
        if p["pool"] and p["pool"] not in pools:
            raise ValidationError(f"استخر {p['pool']} در بخش استخرها (pools) تعریف نشده است")


def _check_functions(value: dict):
    """The functions section as a whole (SPEC §16.9): the operator's total code budget per site."""
    from .config import settings

    total = sum(len(i["code"].encode("utf-8")) for i in value["items"])
    cap = settings.functions_max_site_kb * 1024
    if total > cap:
        raise ValidationError(f"مجموع کد توابع این سایت حداکثر {settings.functions_max_site_kb} کیلوبایت است")


def _functions_live(fn: dict) -> bool:
    return bool(fn.get("enabled")) and any(i.get("enabled", True) for i in fn.get("items") or [])


def _check_tunnel_vs_functions(fn: dict, tn: dict):
    """A function route must not equal or nest with a tunnel path (the edge would skip the function:
    tunnel paths keep their own location), and functions never run while a tunnel with a decoy / 404
    fallback is on (the edge serves no origin content then). Checked on both sides: a functions PUT
    against the stored tunnel section and a tunnel PUT against the stored functions."""
    for f in fn.get("items") or []:
        for p in tn.get("paths") or []:
            if routes_nest(f["route"], p["path"]):
                raise ValidationError(f"مسیر تابع «{f['id']}» ({f['route']}) با مسیر تونل «{p['id']}» "
                                      f"({p['path']}) هم‌پوشانی دارد")
    if tn.get("enabled") and tn.get("fallback", "origin") != "origin" and _functions_live(fn):
        raise ValidationError("توابع لبه با تونلی که پاسخ پیش‌فرض آن decoy یا 404 است اجرا نمی‌شوند؛ "
                              "fallback تونل را origin کنید یا توابع را خاموش کنید")


def _check_l4(site, value: dict):
    """Ports of the l4 section: inside L4_PORT_RANGE and not reserved; app hostnames must not clash
    with the site's own records. Uniqueness across sites is enforced by l4.apply_write (409)."""
    from .config import settings

    lo, hi = settings.l4_port_range
    reserved = ALWAYS_RESERVED_PORTS | settings.l4_reserved_ports
    names = {getattr(r, "name", None) for r in getattr(site, "records", None) or []}
    for a in value["apps"]:
        p = a["edge_port"]
        if p is not None and (p < lo or p > hi):
            raise ValidationError(f"پورت لبه برنامه «{a['id']}» باید در بازه {lo} تا {hi} باشد")
        if p is not None and p in reserved:
            raise ValidationError(f"پورت {p} رزرو شده است")
        if f"l4-{a['id']}" in names:
            raise ValidationError(f"رکورد l4-{a['id']} از قبل وجود دارد؛ شناسه دیگری برای برنامه انتخاب کنید")


def _same_tsig(site, value: dict) -> bool:
    """A TSIG key without a new secret keeps the stored secret — only for the same key name."""
    from . import site_secrets

    if not site_secrets.has_secret(site, "tsig"):
        return False
    try:
        old = (json.loads(site.config or "{}").get("dns_secondary") or {}).get("tsig") or {}
    except (ValueError, AttributeError):
        old = {}
    return old.get("name") == value["tsig"]["name"]


def _tsig_name_ok(site, name: str) -> bool:
    domain = getattr(site, "domain", "") or ""
    if domain and (name == domain or name.endswith("." + domain)):
        return True
    try:
        old = (json.loads(site.config or "{}").get("dns_secondary") or {}).get("tsig") or {}
    except (ValueError, AttributeError):
        old = {}
    return bool(old) and old.get("name") == name


def _is_enabled(name: str, value: dict) -> bool:
    if name == "waf":
        return value["mode"] != "off" or bool((value.get("learning") or {}).get("enabled"))
    if name == "ddos":
        return value["mode"] != "off"
    if name == "image":
        return value["enabled"] or value["auto_webp"] or value["avif"]
    if name == "pools":
        return bool(value["pools"])
    if name == "l4":
        return bool(value["apps"])
    if name in ("tunnel", "logs", "access"):
        return value["enabled"]
    if name == "waiting_room":
        return value["enabled"] and value["mode"] != "off"
    if name == "functions":
        return value["enabled"] or bool(value["items"])
    if name == "dns_secondary":
        return value["mode"] != "off" or bool(value["allow_axfr"]) or value["tsig"] is not None
    return True


def store_section(site, name: str, value: dict):
    try:
        stored = json.loads(site.config or "{}")
    except ValueError:
        stored = {}
    stored[name] = value
    site.config = json.dumps(stored, ensure_ascii=False)


# ------------------------------------------------------------------ redirects CSV import (SPEC §14.2)

CSV_MAX_BYTES = 2_000_000
CSV_MAX_ROWS = 10000
CSV_MAX_ERRORS = 200
_CSV_TRUE = {"1", "true", "yes", "y", "on", "بله", "آری", "درست"}
_CSV_FALSE = {"0", "false", "no", "n", "off", "خیر", "نه", "نادرست"}


def _csv_error(line: int, msg: str) -> dict:
    # the {loc, msg} shape of the other 422 bodies, plus the (1-based) line number on its own
    return {"loc": ["csv", line], "line": line, "msg": msg}


def parse_redirects_csv(text: str, existing: list[dict]) -> tuple[list[dict], list[dict]]:
    """Rows `source,target,status[,match][,preserve_query][,enabled]` (an optional header row starting
    with "source" and blank / `#` lines are skipped) -> (validated rules, per-row errors). `enabled`
    (default true) lets a CSV exported by the client app be imported back unchanged.

    New rules get ids csv-1, csv-2, ... not used by `existing` (the rules they will be appended to;
    empty for a replace). A source already defined (same match type) is an error on that row. Nothing
    is stored here; the caller saves only when there are no errors."""
    import csv
    import io

    import pydantic

    rules: list[dict] = []
    errors: list[dict] = []
    if len(text.encode("utf-8", "replace")) > CSV_MAX_BYTES:
        return [], [_csv_error(0, "فایل CSV بیش از حد بزرگ است (حداکثر ۲ مگابایت)")]
    taken = {r["id"] for r in existing}
    seen = {(r["match"], r["source"]) for r in existing}
    counter = 0
    reader = csv.reader(io.StringIO(text.lstrip("﻿")))
    first = True
    try:
        for row in reader:
            if len(errors) >= CSV_MAX_ERRORS:
                break
            line = reader.line_num
            cells = [c.strip() for c in row]
            if not any(cells) or cells[0].startswith("#"):
                continue
            if first and cells[0].lower() == "source":
                first = False
                continue
            first = False
            if len(rules) + len(errors) >= CSV_MAX_ROWS:
                errors.append(_csv_error(line, f"حداکثر {CSV_MAX_ROWS} ردیف در هر بار وارد کردن مجاز است"))
                break
            if len(cells) < 2 or len(cells) > 6:
                errors.append(_csv_error(line, "هر ردیف باید به شکل source,target,status[,match][,preserve_query]"
                                               "[,enabled] باشد"))
                continue
            cells += [""] * (6 - len(cells))
            source, target, status, match, preserve, enabled = cells
            try:
                status_i = int(status) if status else 301
            except ValueError:
                status_i = 0
            if status_i not in (301, 302, 307, 308):
                errors.append(_csv_error(line, "کد وضعیت باید یکی از 301، 302، 307 یا 308 باشد"))
                continue
            match = match.lower() or "exact"
            if match not in ("exact", "prefix", "regex"):
                errors.append(_csv_error(line, "نوع تطبیق باید exact، prefix یا regex باشد"))
                continue
            pq, en = preserve.lower(), enabled.lower()
            if pq and pq not in _CSV_TRUE | _CSV_FALSE:
                errors.append(_csv_error(line, "مقدار preserve_query باید true یا false باشد"))
                continue
            if en and en not in _CSV_TRUE | _CSV_FALSE:
                errors.append(_csv_error(line, "مقدار enabled باید true یا false باشد"))
                continue
            counter += 1
            while f"csv-{counter}" in taken:
                counter += 1
            rid = f"csv-{counter}"
            try:
                rule = dump(RedirectRule.model_validate({
                    "id": rid, "source": source, "target": target, "status": status_i, "match": match,
                    "preserve_query": pq in _CSV_TRUE, "enabled": en not in _CSV_FALSE}))
            except pydantic.ValidationError as e:
                errors.append(_csv_error(line, "؛ ".join(err["msg"].removeprefix("Value error, ")
                                                        for err in e.errors())))
                continue
            key = (rule["match"], rule["source"])
            if key in seen:
                errors.append(_csv_error(line, f"مبدأ «{rule['source']}» ({rule['match']}) تکراری است"))
                continue
            seen.add(key)
            taken.add(rid)
            rules.append(rule)
    except csv.Error as e:
        errors.append(_csv_error(reader.line_num, f"فایل CSV قابل خواندن نیست: {e}"))
    return rules, errors[:CSV_MAX_ERRORS]
