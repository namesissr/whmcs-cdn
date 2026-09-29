"""Per-site configuration sections (SPEC §2) — validation, defaults, plan limits."""

import ipaddress
import json
import re
from typing import Literal

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
}
EDGE_GROUPS = ("general", "tunnel")


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


# ------------------------------------------------------------------ sections

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

    @field_validator("bypass_cookies")
    @classmethod
    def _cookies(cls, v):
        out = []
        for c in v:
            c = c.strip()
            if not re.match(r"^[A-Za-z0-9_\-.]{1,64}$", c):
                raise ValueError(f"نام کوکی نامعتبر: {c}")
            out.append(c)
        return out


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


class WafExclusion(Strict):
    rule_id: int = Field(ge=0, le=9999999)
    path: str | None = None

    @field_validator("path")
    @classmethod
    def _path(cls, v):
        return _pattern(v) if v else None


WAF_GROUPS = ["sqli", "xss", "lfi", "rce", "php", "scanner", "protocol"]


class Waf(Strict):
    mode: Literal["off", "detect", "block"] = "off"
    paranoia: int = Field(1, ge=1, le=3)
    groups: list[Literal["sqli", "xss", "lfi", "rce", "php", "scanner", "protocol"]] = Field(
        default_factory=lambda: list(WAF_GROUPS))
    exclusions: list[WafExclusion] = Field(default_factory=list, max_length=100)


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


class Image(Strict):
    enabled: bool = False
    quality: int = Field(85, ge=10, le=100)
    max_width: int = Field(2000, ge=16, le=8000)


class ErrorPages(Strict):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    e5xx: str | None = Field(None, alias="5xx", max_length=65536)
    e4xx: str | None = Field(None, alias="4xx", max_length=65536)


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
}

# section -> feature flag that must be on to write it
FEATURE_GATES = {"waf": "waf", "ddos": "ddos", "pools": "load_balancer", "image": "image_optimization",
                 "tunnel": "tunnel"}


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
    return out


def get_section(site, name: str) -> dict:
    return all_config(site)[name]


def validate_section(site, name: str, data: dict, pools_in_use: set[str] | None = None) -> dict:
    """Validate a section against schema + plan. Raises ValidationError / PermissionError."""
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
              "pagerules": ("rules", "max_page_rules"), "pools": ("pools", "max_pools")}
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
    return value


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


def _is_enabled(name: str, value: dict) -> bool:
    if name == "waf":
        return value["mode"] != "off"
    if name == "ddos":
        return value["mode"] != "off"
    if name == "image":
        return value["enabled"]
    if name == "pools":
        return bool(value["pools"])
    if name == "tunnel":
        return value["enabled"]
    return True


def store_section(site, name: str, value: dict):
    try:
        stored = json.loads(site.config or "{}")
    except ValueError:
        stored = {}
    stored[name] = value
    site.config = json.dumps(stored, ensure_ascii=False)
