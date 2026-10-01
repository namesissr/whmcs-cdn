"""Per-site configuration sections (SPEC §2) — validation, defaults, plan limits."""

import ipaddress
import json
import re
from typing import Literal
from urllib.parse import quote

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

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
}
EDGE_GROUPS = ("general", "tunnel")
WEBHOOKS_MAX = 50  # hard cap of section `webhooks` items, whatever the plan says
L4_APPS_MAX = 100  # hard cap of section `l4` apps, whatever the plan says


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


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


class Waf(Strict):
    mode: Literal["off", "detect", "block"] = "off"
    paranoia: int = Field(1, ge=1, le=3)
    groups: list[Literal["sqli", "xss", "lfi", "rce", "php", "scanner", "protocol"]] = Field(
        default_factory=lambda: list(WAF_GROUPS))
    exclusions: list[WafExclusion] = Field(default_factory=list, max_length=100)
    # empty = no managed pack (today's behaviour); packs honour `mode` and `exclusions`
    packs: list[Literal["generic", "wordpress", "joomla", "drupal", "laravel", "api"]] = Field(
        default_factory=list, max_length=20)

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
    def _check(self):
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
                try:
                    re.compile(self.value)
                except re.error as e:
                    raise ValueError(f"عبارت منظم نامعتبر: {e}") from None
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
    def _addr(cls, v):
        return _origin_address(v)


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
    def _addr(cls, v):
        return _origin_address(v)

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
ALWAYS_RESERVED_PORTS = {22, 53, 80, 443, 8089, 8090}  # 8089/8090: the edges' loopback image servers


class L4Origin(Strict):
    address: str
    port: int = Field(ge=1, le=65535)

    @field_validator("address")
    @classmethod
    def _addr(cls, v):
        return _origin_address(v)


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


def _public_ip(v: str, what: str, cidr: bool = False) -> str:
    v = str(v or "").strip()
    try:
        net = ipaddress.ip_network(v, strict=False) if cidr else None
        ip = net.network_address if net is not None else ipaddress.ip_address(v)
    except ValueError:
        raise ValueError(f"{what} نامعتبر است: {v}") from None
    if ip.is_private or ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local \
            or ip.is_reserved:
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
    def _primaries(cls, v):
        return list(dict.fromkeys(_public_ip(x, "آدرس سرور اصلی (primary)") for x in v))

    @field_validator("allow_axfr")
    @classmethod
    def _axfr(cls, v):
        return list(dict.fromkeys(_public_ip(x, "آدرس مجاز انتقال زون", cidr=True) for x in v))

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


# --- regular-expression safety (transform rewrite_path, regex redirects) ---------------------------
# The edges evaluate these patterns (PCRE) on every request, so a pattern with catastrophic
# backtracking would be a self-inflicted DoS. Python's own parser gives us the pattern tree; a
# quantified group that itself contains a quantifier is rejected unless a mandatory character the
# inner quantifiers can never consume separates the repetitions (e.g. `(?:/[a-z]+)*` is fine,
# `(a+)+`, `(a|a)+`, `(.*/)+` are not). Back-references and conditionals are rejected outright.

try:  # Python 3.11+
    from re import _constants as _sre_c
    from re import _parser as _sre_p
except ImportError:  # pragma: no cover - older Pythons
    import sre_constants as _sre_c
    import sre_parse as _sre_p

_REPEAT_OPS = {_sre_c.MAX_REPEAT, _sre_c.MIN_REPEAT}
_POSSESSIVE = getattr(_sre_c, "POSSESSIVE_REPEAT", None)
_ATOMIC = getattr(_sre_c, "ATOMIC_GROUP", None)


class _RegexUnsafe(ValueError):
    pass


def _children(op, av) -> list:
    if op in _REPEAT_OPS or (_POSSESSIVE is not None and op == _POSSESSIVE):
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
    table = {_sre_c.CATEGORY_DIGIT: ch.isdigit(), _sre_c.CATEGORY_NOT_DIGIT: not ch.isdigit(),
             _sre_c.CATEGORY_SPACE: ch.isspace(), _sre_c.CATEGORY_NOT_SPACE: not ch.isspace(),
             _sre_c.CATEGORY_WORD: word, _sre_c.CATEGORY_NOT_WORD: not word}
    return table.get(cat, True)  # unknown category: assume it overlaps


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
    """Predicate "can this one-character element match code point c", or None for other ops."""
    if op == _sre_c.LITERAL:
        return lambda c: c == av
    if op == _sre_c.NOT_LITERAL:
        return lambda c: c != av
    if op == _sre_c.ANY:
        return lambda c: True
    if op == _sre_c.IN:
        items = list(av)
        neg = bool(items) and items[0][0] == _sre_c.NEGATE
        items = items[1:] if neg else items
        return lambda c: (not any(_in_item_has(i, c) for i in items)) if neg else any(
            _in_item_has(i, c) for i in items)
    return None


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


def _separators(sub) -> list[set[int]]:
    """Mandatory one-character elements at the top of `sub` (inside plain groups too), as small
    explicit character sets; elements with a large/unknown set are not usable as separators."""
    out = []
    for op, av in sub:
        if op == _sre_c.LITERAL:
            out.append({av})
        elif op == _sre_c.IN and av and av[0][0] != _sre_c.NEGATE:
            chars: set[int] = set()
            for iop, iav in av:
                if iop == _sre_c.LITERAL:
                    chars.add(iav)
                elif iop == _sre_c.RANGE and iav[1] - iav[0] <= 256:
                    chars.update(range(iav[0], iav[1] + 1))
                else:
                    chars = set()
                    break
            if chars:
                out.append(chars)
        elif op == _sre_c.SUBPATTERN:
            out.extend(_separators(av[-1]))
    return out


def _repeats(sub, depth=0):
    """(lo, hi, body) of every quantifier inside `sub`, recursively."""
    for op, av in sub:
        if op in _REPEAT_OPS or (_POSSESSIVE is not None and op == _POSSESSIVE):
            yield av
        for child in _children(op, av):
            yield from _repeats(child, depth + 1)


def _ambiguous(body) -> bool:
    inner = [r for r in _repeats(body) if r[1] > 1]
    if not inner:
        return False
    preds = [p for r in inner for p in _consumable(r[2])]
    for sep in _separators(body):
        if not any(p(c) for c in sep for p in preds):
            return False  # a character the inner quantifiers never consume splits the repetitions
    return True


def _first_preds(sub) -> tuple[list, bool]:
    """Predicates for the first character `sub` can consume, and whether `sub` can match empty."""
    preds: list = []
    for op, av in sub:
        p = _char_pred(op, av)
        if p is not None:
            preds.append(p)
            return preds, False
        if op in (_sre_c.AT, _sre_c.ASSERT, _sre_c.ASSERT_NOT):
            continue  # zero-width
        if op == _sre_c.SUBPATTERN:
            fp, nullable = _first_preds(av[-1])
        elif op in _REPEAT_OPS or (_POSSESSIVE is not None and op == _POSSESSIVE):
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


# characters tried when testing whether two alternatives can start alike
_OVERLAP_SAMPLE = list(range(0x20, 0x7f)) + [0x0a, 0xa0, 0xe9, 0x627, 0x6cc, 0x4e00]


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
                pre = re.match(r"\?(?:[:=!>|]|<[=!]|[a-zA-Z-]+:)", v[body:i])
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
        except Exception:  # noqa: BLE001 - not parseable on its own: do not judge it
            return False
        if nullable:
            return True  # an empty alternative inside a repeat
        firsts.append(preds)
    for a in range(len(firsts)):
        for b in range(a + 1, len(firsts)):
            if any(any(p(c) for p in firsts[a]) and any(p(c) for p in firsts[b]) for c in _OVERLAP_SAMPLE):
                return True
    return False


def _check_tree(sub, state: dict):
    for op, av in sub:
        if op in (_sre_c.GROUPREF, _sre_c.GROUPREF_EXISTS):
            raise _RegexUnsafe("ارجاع به گروه (مثل \\1) و شرط در عبارت منظم مجاز نیست")
        if op in _REPEAT_OPS or (_POSSESSIVE is not None and op == _POSSESSIVE):
            lo, hi, body = av
            if hi == _sre_c.MAXREPEAT:
                state["unbounded"] += 1
            if hi > 1 and _ambiguous(body):
                raise _RegexUnsafe("عبارت منظم کمیت‌سنج تودرتو دارد (مثل (a+)+) و ممکن است بسیار کند اجرا شود؛ "
                                   "آن را ساده کنید")
        for child in _children(op, av):
            _check_tree(child, state)


def _safe_regex(v: str | None) -> re.Pattern:
    """Compile a customer regex after the safety checks; raises ValueError (Persian)."""
    if not isinstance(v, str) or not v:
        raise ValueError("عبارت منظم (regex) لازم است")
    if len(v) > REGEX_MAX_LEN:
        raise ValueError(f"عبارت منظم حداکثر {REGEX_MAX_LEN} کاراکتر می‌تواند باشد")
    if any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7f for ch in v):
        raise ValueError("عبارت منظم نباید فاصله یا کاراکتر کنترلی داشته باشد (برای فاصله از \\s یا %20 "
                         "استفاده کنید)")
    if "(?P" in v:
        raise ValueError("گروه نام‌دار پایتونی (?P<...>) پشتیبانی نمی‌شود؛ از گروه معمولی (...) و $1..$9 "
                         "استفاده کنید")
    try:
        compiled = re.compile(v)
    except re.error as e:
        raise ValueError(f"عبارت منظم نامعتبر: {e}") from None
    try:
        tree = _sre_p.parse(v)
    except Exception:  # noqa: BLE001 - internal parser unavailable/changed: use the string heuristic
        tree = None
    if tree is not None:
        state = {"unbounded": 0}
        try:
            _check_tree(tree, state)
        except _RegexUnsafe as e:
            raise ValueError(str(e)) from None
        if state["unbounded"] > REGEX_MAX_UNBOUNDED:
            raise ValueError(f"عبارت منظم بیش از {REGEX_MAX_UNBOUNDED} کمیت‌سنج نامحدود (* یا +) دارد؛ "
                             "آن را ساده کنید")
        if any(_overlapping_alternatives(parts) for parts in _quantified_alternations(v)):
            raise ValueError("عبارت منظم گروه تکرارشونده‌ای دارد که گزینه‌هایش با یک کاراکتر شروع می‌شوند "
                             "(مثل (a|ab)+) و ممکن است بسیار کند اجرا شود؛ آن را ساده کنید")
    elif re.search(r"\([^()]*[*+}][^()]*\)[*+{]", v) or re.search(r"\\[1-9]", v):
        raise ValueError("عبارت منظم کمیت‌سنج تودرتو یا ارجاع به گروه دارد و ممکن است بسیار کند اجرا شود")
    return compiled


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
    def _check(self):
        if self.type == "rewrite_path":
            groups = _safe_regex(self.regex).groups
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
    def _check(self):
        if self.match == "regex":
            compiled = _safe_regex(self.source)
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
}

# section -> feature flag that must be on to write it
FEATURE_GATES = {"waf": "waf", "ddos": "ddos", "pools": "load_balancer", "image": "image_optimization",
                 "tunnel": "tunnel", "logs": "log_export", "l4": "l4_proxy"}


# ------------------------------------------------------------------ helpers

def _origin_address(v: str) -> str:
    """Public IPv4, [IPv6] or hostname of an origin server."""
    from .validation import validate_hostname, validate_ip

    v = (v or "").strip().lower().strip("[]")
    if ":" in v:
        return "[" + validate_ip(v, 6) + "]"
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", v):
        return validate_ip(v, 4)
    return validate_hostname(v)


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
            out[name] = dump(model.model_validate(stored.get(name, {})))
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
    parsed = model.model_validate(data)
    value = dump(parsed)
    if gate and not feats[gate]:
        # allow writing the "disabled" shape so clients can always turn things off
        if value != dump(model()) and _is_enabled(name, value):
            raise PermissionError("این قابلیت در پلن شما فعال نیست")
    limits = {"firewall": ("rules", "max_firewall_rules"), "ratelimit": ("rules", "max_ratelimit_rules"),
              "pagerules": ("rules", "max_page_rules"), "pools": ("pools", "max_pools"),
              "transform": ("rules", "max_transform_rules"), "redirects": ("rules", "max_redirects"),
              "webhooks": ("items", "max_webhooks"), "l4": ("apps", "max_l4_apps")}
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
    if name == "ssl" and value["hsts"]["preload"] and not (
            value["hsts"]["include_subdomains"] and value["hsts"]["max_age"] >= 31536000):
        raise ValidationError("preload نیازمند includeSubDomains و max-age حداقل یک سال است")
    if name == "logs" and value["enabled"] and not (value["secret_key"] or _has_logs_secret(site)):
        raise ValidationError("برای فعال‌سازی خروجی لاگ، کلید مخفی (secret_key) لازم است")
    if name == "l4":
        _check_l4(site, value)
    if name == "dns_secondary" and value["tsig"] and not value["tsig"]["secret"] and not _same_tsig(site, value):
        raise ValidationError("کلید مخفی TSIG (tsig.secret) لازم است")
    if vet:
        check_targets(name, value)
    return value


# sections whose values name outbound targets the controller itself contacts (SSRF guard)
OUTBOUND_SECTIONS = ("logs", "webhooks")


def check_targets(name: str, value: dict) -> None:
    """SSRF check of a section's outbound URLs (SPEC §14.3.2/§14.3.3): https, host resolving only
    to public addresses. Needs no site state, so writers run it BEFORE locking the site row (DNS can
    be slow). Raises ValidationError."""
    if name == "logs" and value["s3_endpoint"]:
        _vet_url(value["s3_endpoint"], "آدرس S3")
    if name == "webhooks":
        for i, item in enumerate(value["items"]):
            _vet_url(item["url"], f"وب‌هوک شماره {i + 1}")


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


def _is_enabled(name: str, value: dict) -> bool:
    if name == "waf":
        return value["mode"] != "off"
    if name == "ddos":
        return value["mode"] != "off"
    if name == "image":
        return value["enabled"] or value["auto_webp"] or value["avif"]
    if name == "pools":
        return bool(value["pools"])
    if name == "l4":
        return bool(value["apps"])
    if name in ("tunnel", "logs"):
        return value["enabled"]
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
