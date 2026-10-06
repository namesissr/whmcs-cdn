"""Test certificates for SPEC §22.8 (OCSP AIA detection, key types, dual RSA), generated with
`cryptography` at import time: a self-signed test CA and leaf certificates signed by it."""

from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import AuthorityInformationAccessOID, NameOID

NOW = datetime.now(timezone.utc)


def _pem(cert) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _key_pem(key) -> str:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode()


_CA_KEY = ec.generate_private_key(ec.SECP256R1())
_CA_NAME = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PCDN Test CA")])
CA = (x509.CertificateBuilder().subject_name(_CA_NAME).issuer_name(_CA_NAME)
      .public_key(_CA_KEY.public_key()).serial_number(1)
      .not_valid_before(NOW - timedelta(days=1)).not_valid_after(NOW + timedelta(days=3650))
      .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
      .sign(_CA_KEY, hashes.SHA256()))
CA_PEM = _pem(CA)


def leaf(domain: str = "example.com", key_type: str = "ec256", ocsp: bool = False,
         days: int = 90) -> tuple[str, str]:
    """(leaf certificate PEM, private key PEM) signed by the test CA."""
    if key_type == "rsa":
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    elif key_type == "ec384":
        key = ec.generate_private_key(ec.SECP384R1())
    else:
        key = ec.generate_private_key(ec.SECP256R1())
    b = (x509.CertificateBuilder()
         .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)]))
         .issuer_name(_CA_NAME).public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(NOW - timedelta(days=1)).not_valid_after(NOW + timedelta(days=days))
         .add_extension(x509.SubjectAlternativeName([x509.DNSName(domain), x509.DNSName(f"*.{domain}")]),
                        critical=False))
    if ocsp:
        b = b.add_extension(x509.AuthorityInformationAccess([
            x509.AccessDescription(AuthorityInformationAccessOID.OCSP,
                                   x509.UniformResourceIdentifier("http://ocsp.test-ca.invalid")),
            x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS,
                                   x509.UniformResourceIdentifier("http://ca.test-ca.invalid/ca.crt")),
        ]), critical=False)
    return _pem(b.sign(_CA_KEY, hashes.SHA256())), _key_pem(key)


def chain(domain: str = "example.com", key_type: str = "ec256", ocsp: bool = False,
          with_issuer: bool = True) -> tuple[str, str]:
    """(fullchain PEM, key PEM): the leaf followed by the test CA when with_issuer."""
    cert, key = leaf(domain, key_type, ocsp)
    return (cert + CA_PEM if with_issuer else cert), key
