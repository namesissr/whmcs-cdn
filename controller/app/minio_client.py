"""Minimal MinIO client for the object storage product (SPEC §16.8).

Only what the controller needs, in the standard library + `cryptography` (already a dependency):

* S3 API (AWS SigV4, path-style): create / head / delete a bucket, "is it empty?", bucket policy.
* MinIO admin API (`/minio/admin/v3`, the same SigV4 signature): self-owned service accounts
  ("access keys") with an inline policy, bucket quota, data usage. Requests and responses of the
  service-account calls are encrypted the way `madmin-go` does it (`EncryptData` / `DecryptData`):

      salt (32) | algorithm id (1) | nonce (8) | sio-go DARE stream

  The key is derived from the caller's *secret key* with Argon2id (t=1, m=64 MiB, p=4) — ids 0x00
  (AES-256-GCM) and 0x01 (ChaCha20-Poly1305) — or PBKDF2-SHA256 (8192 rounds, id 0x02, MinIO in FIPS
  mode). The stream is cut into 16 KiB fragments, each sealed with nonce = nonce(8) || LE32(seq) and
  associated data = flag (0x00, 0x80 on the final fragment) || the tag of an empty seal at seq 0.
  `encrypt_data` / `decrypt_data` are checked against vectors produced by madmin-go / sio-go
  themselves (tests/test_storage.py) and, when a MinIO binary is available, against a real server.

Why not `mc` in the controller image or a 3rd-party SDK: one ~200 line module, no subprocess and no
credentials on a command line or in a config file; the admin secret only lives in the process.

Nothing here logs a secret: errors carry the HTTP status, the S3/MinIO error code and message only.
"""

import hashlib
import hmac
import json
import os
import secrets
import string
from datetime import datetime, timezone
from urllib.parse import quote
from xml.etree import ElementTree

import httpx
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

ADMIN_PREFIX = "/minio/admin/v3"

# madmin-go EncryptData algorithm ids
ARGON2ID_AES_GCM = 0x00
ARGON2ID_CHACHA20_POLY1305 = 0x01
PBKDF2_AES_GCM = 0x02
_SIO_BUF = 1 << 14  # sio-go BufSize
_TAG = 16


class MinioError(RuntimeError):
    """A failed storage call. `status` is the HTTP status (None: no answer), `code` the S3/MinIO
    error code (e.g. BucketNotEmpty, XMinioAdminServiceAccountNotFound)."""

    def __init__(self, message: str, status: int | None = None, code: str | None = None):
        super().__init__(message)
        self.status = status
        self.code = code


# ------------------------------------------------------------------ madmin payload encryption

def _derive(alg: int, password: bytes, salt: bytes) -> bytes:
    if alg in (ARGON2ID_AES_GCM, ARGON2ID_CHACHA20_POLY1305):
        from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

        return Argon2id(salt=salt, length=32, iterations=1, lanes=4, memory_cost=64 * 1024).derive(password)
    if alg == PBKDF2_AES_GCM:
        return hashlib.pbkdf2_hmac("sha256", password, salt, 8192, 32)
    raise MinioError("madmin: invalid encryption algorithm id")


def _aead(alg: int, key: bytes):
    return ChaCha20Poly1305(key) if alg == ARGON2ID_CHACHA20_POLY1305 else AESGCM(key)


def _nonce(base: bytes, seq: int) -> bytes:
    return base + seq.to_bytes(4, "little")


def encrypt_data(password: str, data: bytes, alg: int = ARGON2ID_AES_GCM,
                 salt: bytes | None = None, nonce: bytes | None = None) -> bytes:
    """madmin.EncryptData. `salt` / `nonce` are for test vectors only (random otherwise)."""
    salt = salt if salt is not None else os.urandom(32)
    nonce = nonce if nonce is not None else os.urandom(8)
    if len(salt) != 32 or len(nonce) != 8:
        raise ValueError("salt must be 32 and nonce 8 bytes")
    aead = _aead(alg, _derive(alg, password.encode(), salt))
    ad = b"\x00" + aead.encrypt(_nonce(nonce, 0), b"", None)
    out = [salt, bytes([alg]), nonce]
    # every fragment but the last is exactly _SIO_BUF bytes; the last holds 0.._SIO_BUF bytes
    full = (len(data) - 1) // _SIO_BUF if data else 0
    seq = 1
    for i in range(full):
        out.append(aead.encrypt(_nonce(nonce, seq), data[i * _SIO_BUF:(i + 1) * _SIO_BUF], ad))
        seq += 1
    out.append(aead.encrypt(_nonce(nonce, seq), data[full * _SIO_BUF:], b"\x80" + ad[1:]))
    return b"".join(out)


def decrypt_data(password: str, data: bytes) -> bytes:
    """madmin.DecryptData."""
    if len(data) < 32 + 1 + 8 + _TAG:
        raise MinioError("madmin: unexpected header")
    salt, alg, nonce, body = data[:32], data[32], data[33:41], data[41:]
    aead = _aead(alg, _derive(alg, password.encode(), salt))
    ad = b"\x00" + aead.encrypt(_nonce(nonce, 0), b"", None)
    out, seq, i, frag = [], 1, 0, _SIO_BUF + _TAG
    try:
        while len(body) - i > frag:
            out.append(aead.decrypt(_nonce(nonce, seq), body[i:i + frag], ad))
            i += frag
            seq += 1
        out.append(aead.decrypt(_nonce(nonce, seq), body[i:], b"\x80" + ad[1:]))
    except InvalidTag:
        raise MinioError("madmin: data is not authentic (wrong secret key?)") from None
    return b"".join(out)


# ------------------------------------------------------------------ SigV4

def _q(v: str) -> str:
    return quote(v, safe="-_.~")


def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def sign_v4(method: str, base: httpx.URL, path: str, query: dict[str, str], payload: bytes,
            access_key: str, secret_key: str, region: str, now: datetime | None = None) -> tuple[str, dict]:
    """-> (url, headers) of a SigV4-signed request (service s3). `path` is already URI-encoded."""
    now = now or datetime.now(timezone.utc)
    amz_date, day = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
    host = base.host if ":" not in base.host else f"[{base.host}]"
    if base.port:
        host += f":{base.port}"
    payload_hash = hashlib.sha256(payload).hexdigest()
    headers = {"host": host, "x-amz-content-sha256": payload_hash, "x-amz-date": amz_date}
    signed = ";".join(sorted(headers))
    cq = "&".join(f"{_q(k)}={_q(v)}" for k, v in sorted(query.items()))
    canonical = "\n".join([method, path, cq, "".join(f"{k}:{headers[k]}\n" for k in sorted(headers)),
                           signed, payload_hash])
    scope = f"{day}/{region}/s3/aws4_request"
    to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope, hashlib.sha256(canonical.encode()).hexdigest()])
    k = _hmac(_hmac(_hmac(_hmac(("AWS4" + secret_key).encode(), day), region), "s3"), "aws4_request")
    sig = hmac.new(k, to_sign.encode(), hashlib.sha256).hexdigest()
    out = {"x-amz-content-sha256": payload_hash, "x-amz-date": amz_date,
           "Authorization": f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, "
                            f"SignedHeaders={signed}, Signature={sig}"}
    url = f"{base.scheme}://{host}{path}" + (f"?{cq}" if cq else "")
    return url, out


# ------------------------------------------------------------------ client

_ALNUM_UPPER = string.ascii_uppercase + string.digits
_SECRET_CHARS = string.ascii_letters + string.digits


def new_access_key(prefix: str = "PCDN") -> str:
    """20 characters like an AWS access key id (MinIO accepts 3..20 for service accounts)."""
    return prefix + "".join(secrets.choice(_ALNUM_UPPER) for _ in range(20 - len(prefix)))


def new_secret_key() -> str:
    return "".join(secrets.choice(_SECRET_CHARS) for _ in range(40))


class MinioClient:
    def __init__(self, endpoint: str, access_key: str, secret_key: str, region: str = "us-east-1",
                 transport: httpx.BaseTransport | None = None, timeout: float = 20):
        self.base = httpx.URL(endpoint.rstrip("/"))
        self.prefix = self.base.path.rstrip("/")
        self.access_key = access_key
        self.secret_key = secret_key
        self.region = region or "us-east-1"
        # operator-configured endpoint (trusted): no proxy from the environment, never follow redirects
        self.http = httpx.Client(timeout=timeout, transport=transport, trust_env=False, follow_redirects=False)

    def close(self):
        self.http.close()

    # -- transport

    def _call(self, method: str, path: str, query: dict | None = None, body: bytes = b"",
              ok: tuple[int, ...] = (200, 204), headers: dict | None = None) -> httpx.Response:
        full = self.prefix + path
        url, h = sign_v4(method, self.base, full, query or {}, body, self.access_key, self.secret_key,
                         self.region)
        if headers:
            h.update(headers)
        try:
            r = self.http.request(method, url, headers=h, content=body)
        except httpx.HTTPError as e:
            raise MinioError(f"storage endpoint unreachable: {type(e).__name__}") from None
        if r.status_code not in ok:
            code, msg = _error_of(r)
            raise MinioError(f"storage {method} {path.split('?')[0]}: HTTP {r.status_code} {code or ''} "
                             f"{msg or ''}".strip(), r.status_code, code)
        return r

    @staticmethod
    def _bucket_path(bucket: str) -> str:
        return "/" + quote(bucket, safe="")

    # -- S3

    def bucket_exists(self, bucket: str) -> bool:
        """True for any existing bucket, including one owned by someone else (403)."""
        r = self._call("HEAD", self._bucket_path(bucket), ok=(200, 403, 404))
        return r.status_code != 404

    def make_bucket(self, bucket: str) -> None:
        body = b""
        if self.region != "us-east-1":
            body = (f'<CreateBucketConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
                    f"<LocationConstraint>{self.region}</LocationConstraint></CreateBucketConfiguration>").encode()
        self._call("PUT", self._bucket_path(bucket), body=body)

    def delete_bucket(self, bucket: str) -> None:
        self._call("DELETE", self._bucket_path(bucket))

    def bucket_is_empty(self, bucket: str) -> bool:
        r = self._call("GET", self._bucket_path(bucket), {"list-type": "2", "max-keys": "1"})
        root = ElementTree.fromstring(r.content)
        ns = root.tag.split("}")[0] + "}" if root.tag.startswith("{") else ""
        return root.find(f"{ns}Contents") is None and root.find(f"{ns}CommonPrefixes") is None

    def put_bucket_policy(self, bucket: str, policy: dict) -> None:
        self._call("PUT", self._bucket_path(bucket), {"policy": ""}, json.dumps(policy).encode())

    def delete_bucket_policy(self, bucket: str) -> None:
        self._call("DELETE", self._bucket_path(bucket), {"policy": ""}, ok=(200, 204, 404))

    # -- admin (self-owned service accounts, quota, usage)

    def add_service_account(self, access_key: str, secret_key: str, policy: dict,
                            name: str = "", description: str = "") -> dict:
        req = {"policy": policy, "accessKey": access_key, "secretKey": secret_key}
        if name:
            req["name"] = name[:32]
        if description:
            req["description"] = description[:256]
        r = self._call("PUT", ADMIN_PREFIX + "/add-service-account",
                       body=encrypt_data(self.secret_key, json.dumps(req).encode()))
        creds = json.loads(decrypt_data(self.secret_key, r.content)).get("credentials") or {}
        if creds.get("accessKey") != access_key:
            raise MinioError("storage: the server returned another access key than requested")
        return creds

    def delete_service_account(self, access_key: str) -> bool:
        """False when it did not exist (already gone)."""
        try:
            self._call("DELETE", ADMIN_PREFIX + "/delete-service-account", {"accessKey": access_key})
        except MinioError as e:
            if e.code == "XMinioAdminServiceAccountNotFound" or e.status == 404:
                return False
            raise
        return True

    def set_bucket_quota(self, bucket: str, size: int) -> None:
        """Hard quota in bytes; 0 removes the quota."""
        body = json.dumps({"quota": size, "size": size, "quotatype": "hard"}).encode()
        self._call("PUT", ADMIN_PREFIX + "/set-bucket-quota", {"bucket": bucket}, body)

    def data_usage(self) -> dict:
        """{"last_update": str|None, "buckets": {name: {"size": int, "objects": int}}} from the MinIO
        scanner (eventually consistent: refreshed every few minutes, not per request)."""
        r = self._call("GET", ADMIN_PREFIX + "/datausageinfo")
        doc = r.json()
        out = {}
        for name, u in (doc.get("bucketsUsageInfo") or {}).items():
            out[name] = {"size": int(u.get("size") or 0), "objects": int(u.get("objectsCount") or 0)}
        for name, size in (doc.get("bucketsSizes") or {}).items():  # very old servers
            out.setdefault(name, {"size": int(size or 0), "objects": 0})
        return {"last_update": doc.get("lastUpdate"), "buckets": out}

    # -- root-only helpers: used by the integration test and documented for the bootstrap only. The
    # controller's own credentials never have the permissions these need.

    def add_user(self, access_key: str, secret_key: str) -> None:
        body = encrypt_data(self.secret_key, json.dumps({"secretKey": secret_key, "status": "enabled"}).encode())
        self._call("PUT", ADMIN_PREFIX + "/add-user", {"accessKey": access_key}, body)

    def add_canned_policy(self, name: str, policy: dict) -> None:
        self._call("PUT", ADMIN_PREFIX + "/add-canned-policy", {"name": name}, json.dumps(policy).encode())

    def attach_user_policy(self, user: str, policy: str) -> None:
        self._call("PUT", ADMIN_PREFIX + "/set-user-or-group-policy",
                   {"policyName": policy, "userOrGroup": user, "isGroup": "false"})


def _error_of(r: httpx.Response) -> tuple[str | None, str | None]:
    """(code, message) of an S3 XML or MinIO admin JSON error body; never the request."""
    text = r.text[:2000] if r.content else ""
    if not text:
        return None, None
    try:
        doc = json.loads(text)
        if isinstance(doc, dict):
            return doc.get("Code"), (doc.get("Message") or "")[:300]
    except ValueError:
        pass
    try:
        root = ElementTree.fromstring(text)
        return root.findtext("Code"), (root.findtext("Message") or "")[:300]
    except ElementTree.ParseError:
        return None, text[:200]
