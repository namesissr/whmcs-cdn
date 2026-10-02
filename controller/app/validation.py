import ipaddress
import re

from .netguard import is_public_ip

LABEL = r"(?!-)[a-z0-9-]{1,63}(?<!-)"
DOMAIN_RE = re.compile(rf"^(?:{LABEL}\.)+[a-z][a-z0-9-]{{1,62}}$")
HOST_RE = re.compile(rf"^(?:{LABEL}\.)*{LABEL}\.?$")
NAME_RE = re.compile(r"^(?:@|\*|(?:\*\.)?(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?)(?:\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?)*)$")

RECORD_TYPES = {"A", "AAAA", "CNAME", "ALIAS", "TXT", "MX", "NS", "SRV", "CAA"}
PROXYABLE = {"A", "AAAA", "CNAME"}


class ValidationError(ValueError):
    pass


def normalize_domain(domain: str) -> str:
    d = (domain or "").strip().lower().rstrip(".")
    if d.startswith("www."):
        d = d[4:]
    try:
        d = d.encode("idna").decode("ascii")
    except UnicodeError as e:
        raise ValidationError("دامنه نامعتبر است") from e
    if len(d) > 253 or not DOMAIN_RE.match(d):
        raise ValidationError("دامنه نامعتبر است")
    return d


def normalize_name(name: str, domain: str) -> str:
    n = (name or "@").strip().lower().rstrip(".")
    if n in ("", "@", domain):
        return "@"
    if n.endswith("." + domain):
        n = n[: -(len(domain) + 1)]
    if not NAME_RE.match(n):
        raise ValidationError("نام رکورد نامعتبر است")
    return n


def fqdn(name: str, domain: str) -> str:
    return domain if name == "@" else f"{name}.{domain}"


def validate_ip(ip: str, version: int, strict: bool = True) -> str:
    """A public IP address of `version`. strict (customer input: records, origins): the netguard rule
    (globally routable unicast only — also refuses CGNAT 100.64/10, NAT64 / 6to4 / Teredo forms
    embedding a non-public IPv4, reserved and documentation ranges). strict=False (operator input:
    edge addresses) keeps the older check (private, loopback, unspecified, multicast, link-local)."""
    try:
        addr = ipaddress.ip_address((ip or "").strip())
    except ValueError as e:
        raise ValidationError("آدرس IP نامعتبر است") from e
    if addr.version != version:
        raise ValidationError(f"برای این نوع رکورد آدرس IPv{version} لازم است")
    if addr.is_private or addr.is_loopback or addr.is_unspecified or addr.is_multicast or addr.is_link_local:
        raise ValidationError("آدرس IP باید عمومی باشد")
    if strict and not is_public_ip(str(addr)):
        raise ValidationError("آدرس IP باید عمومی باشد (CGNAT، NAT64، رزروشده و آدرس‌های مستندسازی مجاز نیستند)")
    return str(addr)


def validate_hostname(h: str) -> str:
    h = h.strip().lower().rstrip(".")
    if not h or len(h) > 253 or not HOST_RE.match(h):
        raise ValidationError("نام میزبان نامعتبر است")
    return h


def validate_record(rtype: str, content: str, priority: int | None, proxied: bool) -> tuple[str, str, int | None, bool]:
    rtype = (rtype or "").upper().strip()
    if rtype not in RECORD_TYPES:
        raise ValidationError("نوع رکورد پشتیبانی نمی‌شود")
    content = (content or "").strip()
    if not content:
        raise ValidationError("مقدار رکورد خالی است")
    if len(content) > 2048:
        raise ValidationError("مقدار رکورد بیش از حد طولانی است")
    if proxied and rtype not in PROXYABLE:
        proxied = False
    if rtype == "A":
        content = validate_ip(content, 4)
    elif rtype == "AAAA":
        content = validate_ip(content, 6)
    elif rtype in ("CNAME", "NS", "ALIAS"):
        content = validate_hostname(content)
    elif rtype == "MX":
        content = validate_hostname(content)
        priority = 10 if priority is None else priority
    elif rtype == "SRV":
        # content: "weight port target"
        parts = content.split()
        if len(parts) != 3 or not parts[0].isdigit() or not parts[1].isdigit():
            raise ValidationError("فرمت SRV: weight port target")
        content = f"{int(parts[0])} {int(parts[1])} {validate_hostname(parts[2])}"
        priority = 10 if priority is None else priority
    elif rtype == "CAA":
        if not re.match(r'^\d{1,3} (issue|issuewild|iodef) "[^"]*"$', content):
            raise ValidationError('فرمت CAA: 0 issue "letsencrypt.org"')
    elif rtype == "TXT":
        content = content.strip('"')
        if '"' in content or "\\" in content:
            raise ValidationError("کاراکتر نامعتبر در TXT")
    if priority is not None and not (0 <= priority <= 65535):
        raise ValidationError("اولویت نامعتبر است")
    if rtype not in ("MX", "SRV"):
        priority = None
    return rtype, content, priority, proxied


def num(v) -> int:
    """A stored / reported counter as a non-negative int; anything malformed (a string, a dict,
    NaN …) counts as 0 instead of failing the request (security review L5)."""
    if isinstance(v, bool):
        return int(v)
    if isinstance(v, int):
        return max(v, 0)
    if isinstance(v, float):
        return max(int(round(v)), 0) if v == v and v not in (float("inf"), float("-inf")) else 0
    if isinstance(v, str):
        try:
            return max(int(v.strip()), 0)
        except ValueError:
            return 0
    return 0


def obj(v) -> dict:
    """v when it is a dict, else {} (malformed stored / reported details)."""
    return v if isinstance(v, dict) else {}
