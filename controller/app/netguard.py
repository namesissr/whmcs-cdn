"""SSRF guard for customer-supplied outbound URLs (SPEC §14.3.2 log export, §14.3.3 webhooks).

Customers choose where the controller sends data (webhook receivers, S3-compatible log buckets),
so every such URL is vetted before it is saved AND again before every delivery/upload:

* scheme ``https`` only, no user-info, a host and a valid port;
* an IP-literal host must be a globally routable address;
* a host name is resolved and refused when ANY resolved address is not globally routable:
  private, loopback, link-local, CGNAT (100.64/10), multicast, reserved, unspecified, site-local,
  and IPv6 forms that embed such an IPv4 address (IPv4-mapped, 6to4, Teredo, NAT64).

The connection then goes to the vetted address itself (``PinnedTransport``), while the TLS SNI,
certificate verification and the ``Host`` header keep using the host name, so a DNS answer that
changes between the check and the connection (DNS rebinding) cannot redirect the request into the
controller's own network. Redirects are never followed by the callers.

Test-only injection point: tests replace the module attributes ``resolver`` (fake DNS) or ``vet``
(e.g. to allow a local ``http://127.0.0.1`` receiver). Callers always look them up on the module
(``netguard.vet(...)``) so the monkeypatch takes effect; there is deliberately NO environment flag
that could switch the guard off in production.
"""

import ipaddress
import socket
from collections.abc import Callable
from dataclasses import dataclass, field

import httpx

CGNAT = ipaddress.ip_network("100.64.0.0/10")
NAT64 = (ipaddress.ip_network("64:ff9b::/96"), ipaddress.ip_network("64:ff9b:1::/48"))
MAX_ADDRESSES = 4  # connection attempts per request (IPv4 first)


class UnsafeTarget(ValueError):
    """The URL may not be contacted (Persian message, safe to show to the customer)."""


@dataclass
class Target:
    url: str              # the URL as requested (host name kept)
    scheme: str
    host: str             # host name (or IP literal) used for SNI / Host / certificate checks
    port: int
    ips: list[str] = field(default_factory=list)  # vetted addresses to connect to


def system_resolve(host: str, port: int) -> list[str]:
    """Every address the system resolver returns for host (de-duplicated, resolver order)."""
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return list(dict.fromkeys(str(info[4][0]) for info in infos))


# test-only injection point (see the module docstring): host, port -> [address, ...]
resolver: Callable[[str, int], list[str]] = system_resolve


def _v4_public(ip: ipaddress.IPv4Address) -> bool:
    return bool(ip.is_global and not (ip.is_multicast or ip.is_reserved or ip.is_loopback or ip.is_link_local
                                     or ip.is_private or ip.is_unspecified or ip in CGNAT))


def _embedded_v4(ip: ipaddress.IPv6Address) -> list[ipaddress.IPv4Address]:
    out = []
    if ip.sixtofour is not None:
        out.append(ip.sixtofour)
    if ip.teredo is not None:
        out.extend(ip.teredo)
    if any(ip in net for net in NAT64):
        out.append(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
    return out


def is_public_ip(value: str) -> bool:
    """True only for a globally routable unicast address (see the module docstring)."""
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


def parse_url(url: str) -> tuple[str, str, int]:
    """(scheme, host, port) of an https URL, or UnsafeTarget with a Persian message."""
    raw = (url or "").strip()
    if not raw or any(ch.isspace() or ord(ch) < 0x20 for ch in raw):
        raise UnsafeTarget("آدرس نامعتبر است")
    try:
        u = httpx.URL(raw)
    except Exception:  # noqa: BLE001 - httpx.InvalidURL and friends
        raise UnsafeTarget("آدرس نامعتبر است") from None
    if u.scheme != "https":
        raise UnsafeTarget("فقط آدرس https:// مجاز است")
    if u.userinfo:
        raise UnsafeTarget("آدرس نباید نام کاربری/رمز (user@) داشته باشد")
    try:  # the ASCII (IDNA) form: what DNS, SNI and the Host header use
        host = u.raw_host.decode("ascii").rstrip(".").lower()
    except UnicodeDecodeError:
        raise UnsafeTarget("آدرس نامعتبر است") from None
    if not host:
        raise UnsafeTarget("آدرس باید نام میزبان داشته باشد")
    port = u.port if u.port is not None else 443
    if not 1 <= port <= 65535:
        raise UnsafeTarget("پورت آدرس نامعتبر است")
    return u.scheme, host, port


def _ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def default_vet(url: str) -> Target:
    """Check `url` (scheme, host, every resolved address). Raises UnsafeTarget."""
    scheme, host, port = parse_url(url)
    if _ip_literal(host):
        ip = host.strip("[]")
        if not is_public_ip(ip):
            raise UnsafeTarget("آدرس IP مقصد عمومی نیست (آدرس‌های داخلی، loopback و رزروشده مجاز نیستند)")
        return Target(url=url.strip(), scheme=scheme, host=host, port=port, ips=[ip])
    try:
        ips = resolver(host, port)
    except (OSError, UnicodeError):
        raise UnsafeTarget(f"نام میزبان {host} پیدا نشد") from None
    if not ips:
        raise UnsafeTarget(f"نام میزبان {host} پیدا نشد")
    bad = [ip for ip in ips if not is_public_ip(ip)]
    if bad:
        raise UnsafeTarget(f"نام میزبان {host} به آدرسی غیرعمومی اشاره می‌کند؛ فقط مقصدهای عمومی اینترنت "
                           "مجاز هستند")
    ips = sorted(ips, key=lambda ip: ":" in ip)[:MAX_ADDRESSES]  # IPv4 first
    return Target(url=url.strip(), scheme=scheme, host=host, port=port, ips=ips)


# guard hook: the function every caller uses (netguard.vet(url)); tests may monkeypatch it
vet: Callable[[str], Target] = default_vet


class PinnedTransport(httpx.BaseTransport):
    """Send requests for `target.host` to the vetted `target.ips` (tried in order) while SNI,
    certificate verification and the Host header keep the host name (DNS rebinding defence).

    Proxies: httpx disables environment proxies when a transport is given, so these customer-bound
    requests always connect directly to the vetted address."""

    def __init__(self, target: Target, **kwargs):
        self.target = target
        self._inner = httpx.HTTPTransport(**kwargs)

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        host = request.url.raw_host.decode("ascii", "replace").rstrip(".").lower()
        port = request.url.port or (443 if request.url.scheme == "https" else 80)
        if host != self.target.host.strip("[]").lower() or port != self.target.port:
            raise httpx.ConnectError("request to a host that was not vetted", request=request)
        original = request.url
        last: Exception | None = None
        for ip in self.target.ips or []:
            request.url = original.copy_with(host=ip.strip("[]"))
            if original.scheme == "https":
                request.extensions = {**request.extensions, "sni_hostname": self.target.host}
            try:
                return self._inner.handle_request(request)
            except (httpx.ConnectError, httpx.ConnectTimeout) as e:
                last = e
            finally:
                request.url = original
        raise last or httpx.ConnectError("no vetted address to connect to", request=request)

    def close(self) -> None:
        self._inner.close()
