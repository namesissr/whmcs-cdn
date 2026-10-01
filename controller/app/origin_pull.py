"""Authenticated origin pulls: mTLS from the edges to the customer's origin (SPEC §14.2).

ssl.origin_client_auth decides which client certificate the edges present to a site's origin:

* platform — one platform client certificate shared by every edge. The controller creates, once
  and lazily, a platform CA (EC P-256, 10 years) and a client certificate signed by it (EC P-256,
  2 years, renewed automatically when fewer than 30 days remain). Customers configure their origin
  to require client certificates issued by that CA, published WITHOUT authentication at
  GET /origin-pull-ca.pem. The edges receive the client certificate + key only (node-wide
  `origin_pull` block of the edge config); the CA private key never leaves the controller.
* custom — a client certificate + key the customer uploads (PUT /sites/{domain}/ssl/origin-client),
  encrypted at rest like custom SSL keys and sent only in that site's edge config.

Both private keys of the platform pair are stored encrypted (crypto.encrypt) in one `state` row.
Creation is leader-safe without being leader-only: the row is INSERTed with a fixed primary key, so
when two controllers race the loser gets an IntegrityError and uses the winner's CA; a renewal is
an optimistic UPDATE ... WHERE value = <what we read>, so only one renewal wins.
"""

import json
import logging
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from sqlalchemy import update
from sqlalchemy.exc import IntegrityError

from . import crypto
from .models import State, utcnow

log = logging.getLogger("pcdn.origin_pull")

STATE_KEY = "origin_pull:platform"
SECRET_FIELDS = ("ca_key", "client_key")  # encrypted at rest; see crypto.STATE_SECRETS
CA_DAYS = 3650
CLIENT_DAYS = 730
RENEW_BEFORE = timedelta(days=30)
ORG = "Pasargad CDN"
CA_CN = "Pasargad CDN Origin Pull CA"
CLIENT_CN = "Pasargad CDN Origin Pull"
CA_PATH = "/origin-pull-ca.pem"
MAX_CHAIN = 10


class OriginClientError(ValueError):
    pass


# ------------------------------------------------------------------ certificate helpers

def _aware(dt: datetime) -> datetime:
    return dt.replace(tzinfo=timezone.utc)


def _naive(dt: datetime) -> datetime:
    return dt.astimezone(timezone.utc).replace(tzinfo=None)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORG),
                      x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _key_pem(key) -> str:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode()


def _cert_pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _make_ca(now: datetime) -> tuple[str, str, datetime]:
    key = ec.generate_private_key(ec.SECP256R1())
    not_after = now + timedelta(days=CA_DAYS)
    cert = (x509.CertificateBuilder()
            .subject_name(_name(CA_CN)).issuer_name(_name(CA_CN))
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_aware(now - timedelta(hours=1)))
            .not_valid_after(_aware(not_after))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                         crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256()))
    return _cert_pem(cert), _key_pem(key), not_after


def _make_client(ca_cert_pem: str, ca_key_pem: str, now: datetime,
                 ca_not_after: datetime) -> tuple[str, str, datetime]:
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode())
    ca_key = serialization.load_pem_private_key(ca_key_pem.encode(), password=None)
    key = ec.generate_private_key(ec.SECP256R1())
    not_after = min(now + timedelta(days=CLIENT_DAYS), ca_not_after)
    cert = (x509.CertificateBuilder()
            .subject_name(_name(CLIENT_CN)).issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_aware(now - timedelta(hours=1)))
            .not_valid_after(_aware(not_after))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                         crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    return _cert_pem(cert), _key_pem(key), not_after


# ------------------------------------------------------------------ platform pair (state row)

def _session():
    from .db import SessionLocal

    return SessionLocal()


def _new_doc(now: datetime) -> dict:
    ca_cert, ca_key, ca_na = _make_ca(now)
    cl_cert, cl_key, cl_na = _make_client(ca_cert, ca_key, now, ca_na)
    return {"version": 1, "ca_cert": ca_cert, "ca_key": crypto.encrypt(ca_key), "ca_not_after": ca_na.isoformat(),
            "client_cert": cl_cert, "client_key": crypto.encrypt(cl_key), "client_not_after": cl_na.isoformat(),
            "created_at": now.isoformat(), "renewed_at": None}


def _renewal_due(doc: dict, now: datetime) -> bool:
    client_na = datetime.fromisoformat(doc["client_not_after"])
    ca_na = datetime.fromisoformat(doc["ca_not_after"])
    if client_na - now >= RENEW_BEFORE:
        return False
    # a renewal must actually extend the certificate (it can never outlive the CA)
    return min(now + timedelta(days=CLIENT_DAYS), ca_na) > client_na + timedelta(days=1)


def _renewed(doc: dict, now: datetime) -> dict:
    ca_na = datetime.fromisoformat(doc["ca_not_after"])
    cert, key, na = _make_client(doc["ca_cert"], crypto.decrypt(doc["ca_key"]), now, ca_na)
    return {**doc, "client_cert": cert, "client_key": crypto.encrypt(key), "client_not_after": na.isoformat(),
            "renewed_at": now.isoformat()}


def ensure(now: datetime | None = None, create: bool = True) -> dict | None:
    """The platform CA + client certificate document (keys still encrypted), created on first use
    and renewed when the client certificate has fewer than RENEW_BEFORE left. Uses its own database
    session (never commits the caller's work). None only when create=False and nothing exists yet."""
    now = now or utcnow()
    db = _session()
    try:
        for _ in range(3):
            row = db.get(State, STATE_KEY)
            if row is None:
                if not create:
                    return None
                doc = _new_doc(now)
                db.add(State(key=STATE_KEY, value=json.dumps(doc)))
                try:
                    db.commit()
                except IntegrityError:
                    db.rollback()  # another controller created it at the same time: use theirs
                    continue
                log.info("created the platform origin-pull CA and client certificate")
                return doc
            doc = json.loads(row.value)
            if not _renewal_due(doc, now):
                return doc
            new = _renewed(doc, now)
            res = db.execute(update(State).where(State.key == STATE_KEY, State.value == row.value)
                             .values(value=json.dumps(new)))
            if res.rowcount == 1:
                db.commit()
                log.info("renewed the platform origin-pull client certificate (valid until %s)",
                         new["client_not_after"])
                return new
            db.rollback()  # another controller renewed it first: read theirs
        row = db.get(State, STATE_KEY)
        return json.loads(row.value) if row is not None else None
    finally:
        db.close()


def ca_cert_pem() -> str:
    return ensure()["ca_cert"]


def client_pair(create: bool = True) -> dict | None:
    """{"cert", "key"} of the platform client certificate (key decrypted), for the edges."""
    doc = ensure(create=create)
    if doc is None:
        return None
    return {"cert": doc["client_cert"], "key": crypto.decrypt(doc["client_key"])}


# ------------------------------------------------------------------ custom client certificate

def validate_custom(cert_pem: str, key_pem: str, now: datetime | None = None) -> dict:
    """Check a customer-supplied client certificate + key. Returns {"subject", "issuer",
    "expires_at"}; raises OriginClientError with a Persian message."""
    now = now or utcnow()
    if "BEGIN CERTIFICATE" not in cert_pem or "PRIVATE KEY" not in key_pem:
        raise OriginClientError("گواهی یا کلید خصوصی در قالب PEM نیست")
    if "ENCRYPTED" in key_pem:
        raise OriginClientError("کلید خصوصی نباید رمزگذاری‌شده باشد")
    try:
        certs = x509.load_pem_x509_certificates(cert_pem.encode())
    except ValueError:
        raise OriginClientError("گواهی قابل خواندن نیست") from None
    if not certs:
        raise OriginClientError("گواهی قابل خواندن نیست")
    if len(certs) > MAX_CHAIN:
        raise OriginClientError(f"زنجیره گواهی حداکثر {MAX_CHAIN} گواهی می‌تواند داشته باشد")
    leaf = certs[0]
    try:
        key = serialization.load_pem_private_key(key_pem.encode(), password=None)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        raise OriginClientError("کلید خصوصی قابل خواندن نیست") from None
    if not isinstance(key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey)):
        raise OriginClientError("نوع کلید پشتیبانی نمی‌شود (RSA، EC یا Ed25519)")
    if isinstance(key, rsa.RSAPrivateKey) and key.key_size < 2048:
        raise OriginClientError("کلید RSA باید حداقل ۲۰۴۸ بیتی باشد")

    def spki(k) -> bytes:
        return k.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

    try:
        same = spki(leaf.public_key()) == spki(key.public_key())
    except (ValueError, UnsupportedAlgorithm):
        same = False
    if not same:
        raise OriginClientError("کلید خصوصی با گواهی مطابقت ندارد")
    expires = _naive(leaf.not_valid_after_utc)
    if expires <= now:
        raise OriginClientError("این گواهی منقضی شده است")
    try:
        eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        eku = None
    if eku is not None and ExtendedKeyUsageOID.CLIENT_AUTH not in eku \
            and ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE not in eku:
        raise OriginClientError("این گواهی برای احراز هویت کلاینت (clientAuth) صادر نشده است")
    return {"subject": leaf.subject.rfc4514_string(), "issuer": leaf.issuer.rfc4514_string(),
            "expires_at": expires}


def custom_ready(site, now: datetime | None = None) -> bool:
    """A custom client certificate + key is stored and not expired."""
    expires = getattr(site, "origin_client_expires_at", None)
    return bool(getattr(site, "origin_client_cert", None) and getattr(site, "origin_client_key_stored", None)
                and (expires is None or expires > (now or utcnow())))


def effective_mode(site, mode: str) -> str:
    """What the edges actually do: custom without a usable certificate falls back to off."""
    if mode == "custom":
        return "custom" if custom_ready(site) else "off"
    return mode if mode in ("off", "platform") else "off"


def edge_block(site, mode: str) -> dict:
    """Per-site `ssl_options.origin_client` of the edge config: {"mode": off|platform} or
    {"mode": "custom", "cert", "key"} (this site's own certificate, key decrypted)."""
    eff = effective_mode(site, mode)
    if eff == "custom":
        return {"mode": "custom", "cert": site.origin_client_cert, "key": site.origin_client_key}
    return {"mode": eff}


def site_info(site, mode: str | None = None) -> dict:
    """What the panel shows: the setting, what the edges do, and the uploaded certificate's facts
    (never the key)."""
    if mode is None:
        from . import sections

        mode = sections.get_section(site, "ssl")["origin_client_auth"]
    custom = None
    if site.origin_client_cert:
        subject = issuer = None
        try:
            leaf = x509.load_pem_x509_certificates(site.origin_client_cert.encode())[0]
            subject, issuer = leaf.subject.rfc4514_string(), leaf.issuer.rfc4514_string()
        except (ValueError, IndexError):
            pass
        exp = site.origin_client_expires_at
        custom = {"subject": subject, "issuer": issuer,
                  "expires_at": exp.isoformat() + "Z" if exp else None,
                  "expired": bool(exp and exp <= utcnow())}
    return {"mode": mode, "effective": effective_mode(site, mode), "custom": custom, "ca_url": CA_PATH}
