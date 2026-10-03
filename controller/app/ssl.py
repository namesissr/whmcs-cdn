"""Let's Encrypt certificates via acme.sh DNS-01 on our own nameservers (covers apex and wildcard)."""

import functools
import logging
import os
import re
import subprocess
from datetime import datetime, timezone

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
    cert, key = _read_pair(os.path.join(settings.acme_home, f"{domain}_ecc"), domain)
    site.ssl_cert, site.ssl_key = cert, key
    site.ssl_expires_at = cert_expiry(cert)
    site.ssl_status, site.ssl_error, site.ssl_source = "active", None, "letsencrypt"
    if settings.acme_dual_rsa:
        issue_rsa(site)


def _read_pair(base: str, domain: str) -> tuple[str, str]:
    with open(os.path.join(base, "fullchain.cer")) as f:
        cert = f.read()
    with open(os.path.join(base, f"{domain}.key")) as f:
        key = f.read()
    return cert, key


def issue_rsa(site: Site) -> bool:
    """SPEC §22.8 (ACME_DUAL_RSA): an RSA-2048 certificate for the same names next to the ECDSA one
    (acme.sh dir `<domain>`, not `<domain>_ecc`). A failure never fails the ECDSA issuance: it is
    logged, the previous RSA pair (if any) is kept, and the next renewal retries. Caller commits."""
    domain = site.domain
    try:
        _run([
            "--issue", "--force", "--dns", "dns_pcdn", "--dnssleep", "20",
            "-d", domain, "-d", f"*.{domain}",
            "--keylength", "2048", "--server", settings.acme_server,
        ])
        cert, key = _read_pair(os.path.join(settings.acme_home, domain), domain)
        if cert_key_type(cert) is None or not cert_key_type(cert).startswith("rsa-"):
            raise SslError("the RSA certificate could not be read")
    except Exception as e:  # noqa: BLE001 - the ECDSA certificate stays issued
        log.warning("RSA certificate for %s failed (the ECDSA certificate is kept): %s", domain, str(e)[-300:])
        return False
    site.ssl_cert_rsa, site.ssl_key_rsa = cert, key
    return True


# ------------------------------------------------------------------ certificate facts (SPEC §22.8)

def _certs(pem: str) -> list:
    from cryptography import x509

    blocks = re.findall(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", pem or "", re.S)
    out = []
    for b in blocks:
        try:
            out.append(x509.load_pem_x509_certificate(b.encode()))
        except ValueError:
            continue
    return out


@functools.lru_cache(maxsize=2048)
def cert_key_type(pem: str) -> str | None:
    """"ecdsa-p256" | "ecdsa-p384" | "rsa-<bits>" | None of the leaf certificate."""
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    certs = _certs(pem)
    if not certs:
        return None
    key = certs[0].public_key()
    if isinstance(key, ec.EllipticCurvePublicKey):
        return {"secp256r1": "ecdsa-p256", "secp384r1": "ecdsa-p384"}.get(key.curve.name, f"ecdsa-{key.curve.name}")
    if isinstance(key, rsa.RSAPublicKey):
        return f"rsa-{key.key_size}"
    return None


@functools.lru_cache(maxsize=2048)
def ocsp_capable(pem: str) -> bool:
    """OCSP stapling makes sense only when the leaf names an OCSP responder (AIA) and the chain
    includes its issuer (Let's Encrypt certificates issued since 2025 carry no OCSP URL -> False)."""
    from cryptography import x509
    from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID

    certs = _certs(pem)
    if len(certs) < 2:
        return False
    leaf = certs[0]
    try:
        aia = leaf.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
    except x509.ExtensionNotFound:
        return False
    if not any(d.access_method == AuthorityInformationAccessOID.OCSP for d in aia):
        return False
    return any(c.subject == leaf.issuer for c in certs[1:])


@functools.lru_cache(maxsize=2048)
def _not_after(pem: str) -> datetime | None:
    certs = _certs(pem)
    if not certs:
        return None
    return certs[0].not_valid_after_utc.astimezone(timezone.utc).replace(tzinfo=None)


def cert_valid(pem: str) -> bool:
    """The leaf certificate is readable and not expired."""
    na = _not_after(pem)
    return na is not None and na > datetime.now(timezone.utc).replace(tzinfo=None)


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
