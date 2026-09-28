"""Let's Encrypt certificates via acme.sh DNS-01 on our own nameservers (covers apex and wildcard)."""

import logging
import os
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
    site.ssl_status, site.ssl_error = "active", None
