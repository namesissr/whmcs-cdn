"""Let's Encrypt certificates via acme.sh DNS-01 on our own nameservers (covers apex and wildcard)."""

import logging
import os
import re
import subprocess
from datetime import datetime

from .config import settings
from .models import Site

log = logging.getLogger("pcdn.ssl")


class SslError(RuntimeError):
    pass


def _run(args: list[str], timeout: int = 600) -> str:
    cmd = [settings.acme_sh, "--config-home", settings.acme_home, *args]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    out = (p.stdout or "") + (p.stderr or "")
    # acme.sh exits 2 when the cert is not due for renewal; we always --force so treat non-zero as error
    if p.returncode != 0:
        raise SslError(out[-2000:])
    return out


def cert_expiry(pem: str) -> datetime:
    p = subprocess.run(["openssl", "x509", "-noout", "-enddate"], input=pem, capture_output=True, text=True)
    if p.returncode != 0 or "notAfter=" not in p.stdout:
        raise SslError("cannot parse certificate")
    return datetime.strptime(p.stdout.strip().split("=", 1)[1], "%b %d %H:%M:%S %Y %Z")


def issue(site: Site) -> None:
    """Issue (or renew) a cert for domain + *.domain and store it on the site. Caller commits."""
    domain = site.domain
    if settings.acme_email:
        try:
            _run(["--register-account", "-m", settings.acme_email, "--server", settings.acme_server], timeout=120)
        except SslError:
            log.warning("acme account registration failed (may already exist)")
    _run([
        "--issue", "--force", "--dns", "dns_pcdn", "--dnssleep", "20",
        "-d", domain, "-d", f"*.{domain}",
        "--keylength", "ec-256", "--server", settings.acme_server,
    ])
    base = os.path.join(settings.acme_home, f"{domain}_ecc")
    with open(os.path.join(base, "fullchain.cer")) as f:
        cert = f.read()
    with open(os.path.join(base, f"{domain}.key")) as f:
        key = f.read()
    site.ssl_cert, site.ssl_key = cert, key
    site.ssl_expires_at = cert_expiry(cert)
    site.ssl_status, site.ssl_error, site.ssl_source = "active", None, "letsencrypt"


def _openssl(args: list[str], stdin: str) -> str:
    p = subprocess.run(["openssl", *args], input=stdin, capture_output=True, text=True, timeout=20)
    if p.returncode != 0:
        raise SslError(p.stderr.strip()[-300:] or "openssl failed")
    return p.stdout


def cert_info(pem: str) -> dict:
    """Names (SAN, else CN) and expiry of the first certificate in a PEM chain."""
    out = _openssl(["x509", "-noout", "-subject", "-enddate", "-ext", "subjectAltName", "-nameopt", "RFC2253"], pem)
    names = [n.strip().lower() for n in re.findall(r"DNS:([^,\s]+)", out)]
    if not names:
        m = re.search(r"subject=.*?CN=([^,\n]+)", out)
        names = [m.group(1).strip().lower()] if m else []
    m = re.search(r"notAfter=(.+)", out)
    return {"names": names, "expires_at": datetime.strptime(m.group(1).strip(), "%b %d %H:%M:%S %Y %Z")}


def covers(names: list[str], host: str) -> bool:
    for n in names:
        if n == host or (n.startswith("*.") and host.count(".") == n.count(".") and host.endswith(n[1:])):
            return True
    return False


def validate_custom(domain: str, cert: str, key: str) -> dict:
    """Check a customer-supplied certificate; returns cert_info. Raises SslError with a Persian message."""
    if "PRIVATE KEY" not in key or "BEGIN CERTIFICATE" not in cert:
        raise SslError("گواهی یا کلید خصوصی در قالب PEM نیست")
    if "ENCRYPTED" in key:
        raise SslError("کلید خصوصی نباید رمزگذاری‌شده باشد")
    try:
        info = cert_info(cert)
        cert_pub = _openssl(["x509", "-noout", "-pubkey"], cert)
        key_pub = _openssl(["pkey", "-pubout"], key)
    except SslError as e:
        raise SslError(f"گواهی یا کلید قابل خواندن نیست: {e}") from None
    if cert_pub.strip() != key_pub.strip():
        raise SslError("کلید خصوصی با گواهی مطابقت ندارد")
    if info["expires_at"] <= datetime.utcnow():
        raise SslError("این گواهی منقضی شده است")
    if not covers(info["names"], domain):
        raise SslError(f"این گواهی دامنه {domain} را پوشش نمی‌دهد")
    return info
