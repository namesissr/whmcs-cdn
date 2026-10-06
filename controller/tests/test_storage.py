"""Object storage (SPEC §16.8): MinIO client crypto/signing, bucket API, quota, usage billing, edge
origin shortcut. A fake MinIO (httpx MockTransport) checks every SigV4 signature and decrypts the
madmin payloads; test_real_minio runs the same flow against a real `minio` binary when one is
available (PCDN_TEST_MINIO_BIN or `minio` on PATH)."""

import hashlib
import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
from datetime import datetime, timedelta
from xml.sax.saxutils import escape

import httpx
import pytest
from sqlalchemy import select

from app import alerts, minio_client, scheduler, storage
from app.config import settings
from app.db import SessionLocal
from app.minio_client import MinioClient, MinioError, decrypt_data, encrypt_data, sign_v4
from app.models import AuditLog, StorageBucket, StorageUsageHourly
from tests.test_api import edge_get
from tests.test_wave8 import activate, online_edge

S = "/api/v1/sites/example.com"
ENDPOINT = "https://s3.cdn.test"
ADMIN_AK, ADMIN_SK = "pcdn-controller", "controller-secret-123"
GIB = 1024 ** 3


# ------------------------------------------------------------------ madmin encryption / SigV4

# produced by madmin-go v3.0.110 / sio-go v0.3.1 (Go) with salt = 0x11*32 and nonce = 0x22*8:
# EncryptData-format of `{"credentials":{"accessKey":"AK","secretKey":"SK"}}` with password "minio-secret"
GO_SMALL = bytes.fromhex(
    "1111111111111111111111111111111111111111111111111111111111111111002222222222222222562ea75bb322088b55d0b7f"
    "bc14b9c0a3259aa2672e2312d0a5fb8ac108e8c755ed699c652b0b7f9ad5f6ac6884bdfd75225ec46da80eb7b4d5bfb49d1f9926ad5"
    "1768")
# (plaintext length, algorithm id) -> (ciphertext length, sha256) for a byte pattern, password "pw"
GO_HASHES = {
    (0, 0): (57, "986a299485812ec8a576d8bc5f86428a93dbe6570a6ddd08ffa12ca23bb203fa"),
    (0, 1): (57, "73f7252fc13170fb45c8bd82ed7efc3be293cffdeaf97368057a089f35d80d63"),
    (0, 2): (57, "16d492030f68dddf4f0dc80f51118fe8a4c099f25215ffff1c5dc477599078f8"),
    (16384, 0): (16441, "3bdc2909d73541715793a158fa59315891613936515574a6b66ed8d3cab7ce64"),
    (16384, 1): (16441, "909b1961466b2f1f180d79d97a715c956f0c01595f3d756ba3edb4e66e223106"),
    (16384, 2): (16441, "5a3b335e0bb8bee0de7df040c94dbcbbbd57d3cbbc5b7091f3ae4a877ef58cf9"),
    (40000, 0): (40089, "52669ad9c4dc532a9da43b6d6963881ed1c653cf8899a22b0aa1b81356ad9214"),
    (40000, 1): (40089, "f412e88f2eaedd7dfed75b74e0562c2b1af2bd7da1edafe3150dc4b2c7e1d29b"),
    (40000, 2): (40089, "25a6f5537a8cdd85645f5fd3a14047422dca5f832d223f8201b5791803dc8036"),
}


def _pattern(n: int) -> bytes:
    return bytes((i * 7 + 3) % 251 for i in range(n))


def test_madmin_decrypts_go_ciphertext():
    assert json.loads(decrypt_data("minio-secret", GO_SMALL)) == {"credentials": {"accessKey": "AK", "secretKey": "SK"}}
    with pytest.raises(MinioError):
        decrypt_data("wrong", GO_SMALL)
    with pytest.raises(MinioError):
        decrypt_data("minio-secret", GO_SMALL[:-1] + bytes([GO_SMALL[-1] ^ 1]))
    with pytest.raises(MinioError):
        decrypt_data("minio-secret", GO_SMALL[:40])


@pytest.mark.parametrize("size,alg", sorted(GO_HASHES))
def test_madmin_encryption_is_byte_identical_to_go(size, alg):
    """Fixed salt/nonce: the ciphertext equals what madmin-go/sio-go produce, fragment boundaries
    (exactly 16 KiB, multi-fragment) and all three algorithm ids included."""
    c = encrypt_data("pw", _pattern(size), alg=alg, salt=b"\x11" * 32, nonce=b"\x22" * 8)
    assert (len(c), hashlib.sha256(c).hexdigest()) == GO_HASHES[(size, alg)]
    assert decrypt_data("pw", c) == _pattern(size)


def test_madmin_random_salt_roundtrip():
    a, b = encrypt_data("pw", b"x" * 20000), encrypt_data("pw", b"x" * 20000)
    assert a != b and a[32] == minio_client.ARGON2ID_AES_GCM
    assert decrypt_data("pw", a) == decrypt_data("pw", b) == b"x" * 20000


def test_sigv4_matches_botocore(monkeypatch):
    pytest.importorskip("botocore")
    import botocore.auth
    from botocore.auth import S3SigV4Auth
    from botocore.awsrequest import AWSRequest
    from botocore.credentials import Credentials

    now = datetime(2026, 10, 1, 12, 30, 0)
    body = b'{"quota":1}'
    url, headers = sign_v4("PUT", httpx.URL("https://s3.cdn.test:9443"), "/minio/admin/v3/set-bucket-quota",
                           {"bucket": "cdn-abc-x", "z": "a b/c"}, body, "AK", "SK", "us-east-1", now=now)
    req = AWSRequest(method="PUT", url=url, data=body)
    monkeypatch.setattr(botocore.auth, "get_current_datetime", lambda *a, **k: now)
    S3SigV4Auth(Credentials("AK", "SK"), "s3", "us-east-1").add_auth(req)
    want = req.headers["Authorization"].split("Signature=")[1]
    assert headers["Authorization"].split("Signature=")[1] == want
    assert url == "https://s3.cdn.test:9443/minio/admin/v3/set-bucket-quota?bucket=cdn-abc-x&z=a%20b%2Fc"


# ------------------------------------------------------------------ fake MinIO

class FakeMinio:
    """Enough of MinIO for the controller: verifies SigV4 of every request against the known
    secrets, decrypts the madmin service-account payloads with the caller's secret and encrypts the
    answer, keeps buckets / objects / policies / quotas / service accounts in memory."""

    def __init__(self):
        self.users = {ADMIN_AK: ADMIN_SK}
        self.sas: dict[str, dict] = {}  # access key -> {"secret", "policy", "parent"}
        self.buckets: dict[str, dict] = {}  # name -> {"objects": {key: bytes}, "policy", "quota"}
        self.fail: dict[str, int] = {}  # "<METHOD> <path>" -> status to answer
        self.fail_once: dict[str, int] = {}  # the same, for the next such request only
        self.calls: list[str] = []
        self.down = False

    def secret_of(self, ak):
        return self.users.get(ak) or (self.sas.get(ak) or {}).get("secret")

    def check_sig(self, request: httpx.Request) -> str:
        auth = request.headers.get("authorization", "")
        ak = auth.split("Credential=")[1].split("/")[0]
        secret = self.secret_of(ak)
        assert secret, f"unknown access key {ak}"
        query = dict(httpx.QueryParams(request.url.query))
        now = datetime.strptime(request.headers["x-amz-date"], "%Y%m%dT%H%M%SZ")
        base = httpx.URL(f"{request.url.scheme}://{request.headers['host']}")
        _, want = sign_v4(request.method, base, request.url.raw_path.split(b"?")[0].decode(), query,
                          request.content, ak, secret, "us-east-1", now=now)
        assert want["Authorization"] == auth, "SigV4 signature mismatch"
        assert request.headers["x-amz-content-sha256"] == hashlib.sha256(request.content).hexdigest()
        return ak

    @staticmethod
    def err(status, code, msg="", json_=False):
        if json_:
            return httpx.Response(status, json={"Code": code, "Message": msg})
        return httpx.Response(status, text=f"<Error><Code>{code}</Code><Message>{escape(msg)}</Message></Error>")

    def handler(self, request: httpx.Request) -> httpx.Response:
        if self.down:
            raise httpx.ConnectError("connection refused")
        ak = self.check_sig(request)
        path = request.url.path
        q = dict(httpx.QueryParams(request.url.query))
        key = f"{request.method} {path}"
        self.calls.append(key + ("?" + "&".join(sorted(q)) if q else ""))
        status = self.fail.get(key) or self.fail_once.pop(key, None)
        if status:
            return self.err(status, "InjectedFailure", "injected", json_=path.startswith("/minio/"))
        if path.startswith("/minio/admin/v3/"):
            if ak in self.sas:
                return self.err(403, "AccessDenied", "service account", json_=True)
            return self.admin(request, ak, path.removeprefix("/minio/admin/v3/"), q)
        return self.s3(request, ak, path, q)

    def admin(self, request, ak, op, q):
        secret = self.users[ak]
        if op == "add-service-account":
            req = json.loads(decrypt_data(secret, request.content))
            assert "targetUser" not in req  # always self-owned
            if req["accessKey"] in self.sas:
                return self.err(409, "XMinioAdminServiceAccountExists", json_=True)
            self.sas[req["accessKey"]] = {"secret": req["secretKey"], "policy": req["policy"], "parent": ak,
                                          "name": req.get("name"), "description": req.get("description")}
            body = {"credentials": {"accessKey": req["accessKey"], "secretKey": req["secretKey"],
                                    "expiration": "1970-01-01T00:00:00Z"}}
            return httpx.Response(200, content=encrypt_data(secret, json.dumps(body).encode(),
                                                            alg=minio_client.PBKDF2_AES_GCM))
        if op == "delete-service-account" and request.method == "DELETE":
            if self.sas.pop(q["accessKey"], None) is None:
                return self.err(404, "XMinioAdminServiceAccountNotFound", json_=True)
            return httpx.Response(204)
        if op == "set-bucket-quota":
            b = self.buckets.get(q["bucket"])
            if b is None:
                return self.err(404, "NoSuchBucket", json_=True)
            doc = json.loads(request.content)
            assert doc["quotatype"] == "hard" and doc["size"] == doc["quota"]
            b["quota"] = doc["size"]
            return httpx.Response(200)
        if op == "storageinfo":
            return httpx.Response(200, json={"disks": [
                {"endpoint": "/export1", "totalspace": 200 * 1024 ** 3, "usedspace": 40 * 1024 ** 3,
                 "availspace": 160 * 1024 ** 3},
                {"endpoint": "/export2", "totalspace": 100 * 1024 ** 3, "usedspace": 10 * 1024 ** 3,
                 "availspace": 90 * 1024 ** 3},
                {"endpoint": "/offline", "totalspace": 0, "usedspace": 0, "availspace": 0},
            ]})
        if op == "datausageinfo":
            usage = {n: {"size": sum(len(v) for v in b["objects"].values()), "objectsCount": len(b["objects"])}
                     for n, b in self.buckets.items()}
            return httpx.Response(200, json={"lastUpdate": "2026-10-01T00:00:00Z", "bucketsUsageInfo": usage})
        return self.err(400, "XMinioAdminUnknown", op, json_=True)

    def s3(self, request, ak, path, q):
        parts = path.lstrip("/").split("/", 1)
        bucket, obj = parts[0], (parts[1] if len(parts) > 1 else "")
        sa = self.sas.get(ak)
        if sa is not None and f"arn:aws:s3:::{bucket}" not in json.dumps(sa["policy"]):
            return self.err(403, "AccessDenied")
        b = self.buckets.get(bucket)
        if not obj:
            if request.method == "HEAD":
                return httpx.Response(200 if b else 404)
            if request.method == "PUT" and "policy" in q:
                if b is None:
                    return self.err(404, "NoSuchBucket")
                b["policy"] = json.loads(request.content)
                return httpx.Response(204)
            if request.method == "DELETE" and "policy" in q:
                if b is not None:
                    b["policy"] = None
                return httpx.Response(204)
            if request.method == "PUT":
                if b is not None:
                    return self.err(409, "BucketAlreadyOwnedByYou")
                self.buckets[bucket] = {"objects": {}, "policy": None, "quota": 0}
                return httpx.Response(200)
            if request.method == "DELETE":
                if b is None:
                    return self.err(404, "NoSuchBucket")
                if b["objects"]:
                    return self.err(409, "BucketNotEmpty")
                del self.buckets[bucket]
                return httpx.Response(204)
            if request.method == "GET" and q.get("list-type") == "2":
                if b is None:
                    return self.err(404, "NoSuchBucket")
                keys = sorted(b["objects"])[: int(q.get("max-keys", 1000))]
                contents = "".join(f"<Contents><Key>{escape(k)}</Key><Size>{len(b['objects'][k])}</Size></Contents>"
                                   for k in keys)
                return httpx.Response(200, text='<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
                                                f"<KeyCount>{len(keys)}</KeyCount>{contents}</ListBucketResult>")
        if b is None:
            return self.err(404, "NoSuchBucket")
        if request.method == "PUT":
            used = sum(len(v) for v in b["objects"].values())
            if b["quota"] and used + len(request.content) > b["quota"]:
                return self.err(400, "XMinioAdminBucketQuotaExceeded")
            b["objects"][obj] = request.content
            return httpx.Response(200)
        if request.method == "DELETE":
            b["objects"].pop(obj, None)
            return httpx.Response(204)
        return self.err(400, "NotImplemented")


@pytest.fixture()
def minio(monkeypatch):
    fake = FakeMinio()
    monkeypatch.setattr(settings, "storage_endpoint", ENDPOINT)
    monkeypatch.setattr(settings, "storage_public_endpoint", ENDPOINT)
    monkeypatch.setattr(settings, "storage_admin_access_key", ADMIN_AK)
    monkeypatch.setattr(settings, "storage_admin_secret_key", ADMIN_SK)
    storage.set_client(MinioClient(ENDPOINT, ADMIN_AK, ADMIN_SK, transport=httpx.MockTransport(fake.handler)))
    yield fake
    storage.set_client(None)


@pytest.fixture()
def fresh_alerts():
    """The alert channels are not configured in tests; open conditions live in the State table."""
    yield
    for c in alerts.open_alerts():
        alerts.resolve_alert(c["key"], notify=False)


def make_site(client, storage_gb=1, domain="example.com", **features):
    r = client.post("/api/v1/sites", json={"domain": domain, "origin_ip": "93.184.216.34",
                                           "plan": {"features": {"storage_gb": storage_gb, **features}}})
    assert r.status_code == 201, r.text
    return r.json()


def put_object(fake: FakeMinio, ak: str, secret: str, bucket: str, key: str, data: bytes) -> httpx.Response:
    """A customer upload with the customer's own key (signed like any S3 client)."""
    cli = MinioClient(ENDPOINT, ak, secret, transport=httpx.MockTransport(fake.handler))
    return cli._call("PUT", f"/{bucket}/{key}", body=data, ok=(200, 400, 403))


# ------------------------------------------------------------------ API

def test_storage_unconfigured_and_plan_gate(client, monkeypatch):
    make_site(client, storage_gb=0)
    r = client.get(f"{S}/storage/buckets")
    assert r.status_code == 200 and r.json()["available"] is False and r.json()["enabled"] is False
    assert client.post(f"{S}/storage/buckets", json={"name": "assets"}).status_code == 503
    assert client.patch(f"{S}/plan", json={"features": {"storage_gb": -1}}).status_code == 422


def test_bucket_lifecycle(client, minio, monkeypatch):
    from cryptography.fernet import Fernet

    monkeypatch.setattr(settings, "data_encryption_key", Fernet.generate_key().decode())
    make_site(client, storage_gb=0)
    assert client.post(f"{S}/storage/buckets", json={"name": "assets"}).status_code == 403  # plan: none
    client.patch(f"{S}/plan", json={"features": {"storage_gb": 2}})

    r = client.post(f"{S}/storage/buckets", json={"name": "Assets"})
    assert r.status_code == 201, r.text
    created = r.json()
    bucket, ak, secret = created["bucket"], created["access_key"], created["secret_key"]
    assert created["name"] == "assets" and created["endpoint"] == ENDPOINT
    assert bucket.startswith("cdn-") and bucket.endswith("-assets") and len(bucket.split("-")[1]) == 8
    assert len(ak) == 20 and ak.startswith("PCDN") and len(secret) == 40
    fb = minio.buckets[bucket]
    assert fb["quota"] == 2 * GIB
    # the service account is self-owned, scoped to this bucket only, without bucket-policy rights
    sa = minio.sas[ak]
    assert sa["parent"] == ADMIN_AK and sa["secret"] == secret
    text = json.dumps(sa["policy"])
    assert f"arn:aws:s3:::{bucket}" in text and "PutBucketPolicy" not in text and "admin:" not in text
    # origin policy: anonymous GetObject only with the edges' Referer token
    stmt = fb["policy"]["Statement"][0]
    assert stmt["Action"] == ["s3:GetObject"] and stmt["Resource"] == [f"arn:aws:s3:::{bucket}/*"]
    token = stmt["Condition"]["StringEquals"]["aws:Referer"][0]
    assert len(token) == 48

    # stored encrypted, never listed, never audited
    with SessionLocal() as db:
        row = db.scalar(select(StorageBucket))
        assert row.secret_key_stored.startswith("enc:v1:") and row.origin_token_stored.startswith("enc:v1:")
        assert row.secret_key == secret and row.origin_token == token
        audit = " ".join(a.detail + (a.action or "") for a in db.scalars(select(AuditLog)))
    assert "storage.bucket.create" in audit and secret not in audit and token not in audit
    listing = client.get(f"{S}/storage/buckets").json()
    assert secret not in json.dumps(listing) and token not in json.dumps(listing)
    assert listing["enabled"] and listing["storage_gb"] == 2 and listing["buckets"][0]["access_key"] == ak

    # duplicate / invalid names
    assert client.post(f"{S}/storage/buckets", json={"name": "assets"}).status_code == 409
    for bad_name in ("ab", "-abc", "abc-", "a.b.c", "x" * 41, "ab_c", "ünï"):
        assert client.post(f"{S}/storage/buckets", json={"name": bad_name}).status_code == 422, bad_name
    assert client.post(f"{S}/storage/buckets", json={"name": "abc", "extra": 1}).status_code == 422

    # usage (live from the MinIO scanner) + quota re-balance
    assert put_object(minio, ak, secret, bucket, "a.txt", b"x" * 1000).status_code == 200
    usage = client.get(f"{S}/storage/buckets").json()
    assert usage["used_bytes"] == 1000 and usage["buckets"][0]["usage"]["objects"] == 1
    assert usage["usage_stale"] is False

    # rotate: a new service account, the old one is gone, the new secret shown once
    r = client.post(f"{S}/storage/buckets/assets/rotate-key")
    assert r.status_code == 200, r.text
    rot = r.json()
    assert rot["access_key"] != ak and rot["secret_key"] != secret and rot["rotated_at"]
    assert ak not in minio.sas and rot["access_key"] in minio.sas
    with SessionLocal() as db:
        assert db.scalar(select(StorageBucket)).secret_key == rot["secret_key"]

    # delete: only an empty bucket
    r = client.delete(f"{S}/storage/buckets/assets")
    assert r.status_code == 409 and "خالی" in r.json()["detail"]
    del minio.buckets[bucket]["objects"]["a.txt"]
    assert client.delete(f"{S}/storage/buckets/assets").status_code == 200
    assert bucket not in minio.buckets and rot["access_key"] not in minio.sas
    assert client.delete(f"{S}/storage/buckets/assets").status_code == 404
    assert client.get(f"{S}/storage/buckets").json()["buckets"] == []


def test_bucket_limits_and_site_tag(client, minio, monkeypatch):
    monkeypatch.setattr(settings, "storage_max_buckets", 2)
    make_site(client, storage_gb=1)
    a = client.post(f"{S}/storage/buckets", json={"name": "one"}).json()
    b = client.post(f"{S}/storage/buckets", json={"name": "two"}).json()
    assert a["bucket"].split("-")[1] == b["bucket"].split("-")[1]  # one tag per site
    assert client.post(f"{S}/storage/buckets", json={"name": "three"}).status_code == 403
    # another site never gets the same global names
    make_site(client, storage_gb=1, domain="other.com")
    c = client.post("/api/v1/sites/other.com/storage/buckets", json={"name": "one"}).json()
    assert c["bucket"] != a["bucket"]
    # a name taken on MinIO (not created by this controller) is refused, never adopted
    monkeypatch.setattr(storage, "_new_tag", lambda: "fixedtag")
    minio.buckets["cdn-fixedtag-taken"] = {"objects": {"x": b"secret data"}, "policy": None, "quota": 0}
    make_site(client, storage_gb=1, domain="third.com")
    r = client.post("/api/v1/sites/third.com/storage/buckets", json={"name": "taken"})
    assert r.status_code == 409 and minio.buckets["cdn-fixedtag-taken"]["objects"] == {"x": b"secret data"}


def test_over_quota_refuses_new_buckets(client, minio):
    make_site(client, storage_gb=1)
    r = client.post(f"{S}/storage/buckets", json={"name": "full"}).json()
    minio.buckets[r["bucket"]]["objects"]["big"] = b"x"  # pretend the scanner sees > 1 GiB
    import app.minio_client as mc

    real = mc.MinioClient.data_usage

    def big(self):
        out = real(self)
        out["buckets"][r["bucket"]]["size"] = GIB + 1
        return out

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(mc.MinioClient, "data_usage", big)
        resp = client.post(f"{S}/storage/buckets", json={"name": "more"})
        assert resp.status_code == 403 and "پر" in resp.json()["detail"]
        assert client.get(f"{S}/storage/buckets").json()["over_quota"] is True


def test_create_rolls_back_on_failure(client, minio):
    make_site(client)
    minio.fail["PUT /minio/admin/v3/add-service-account"] = 500
    r = client.post(f"{S}/storage/buckets", json={"name": "assets"})
    assert r.status_code == 502 and "InjectedFailure" in r.json()["detail"]
    assert minio.buckets == {} and minio.sas == {}
    with SessionLocal() as db:
        assert db.scalar(select(StorageBucket)) is None
    minio.fail.clear()
    minio.down = True
    assert client.post(f"{S}/storage/buckets", json={"name": "assets"}).status_code == 502
    r = client.get(f"{S}/storage/buckets")  # listing still answers from the stored values
    assert r.status_code == 200 and r.json()["buckets"] == []


def test_rotate_failure_keeps_old_key(client, minio):
    make_site(client)
    old = client.post(f"{S}/storage/buckets", json={"name": "assets"}).json()
    minio.fail_once["DELETE /minio/admin/v3/delete-service-account"] = 500
    assert client.post(f"{S}/storage/buckets/assets/rotate-key").status_code == 502
    assert list(minio.sas) == [old["access_key"]]  # the new key was removed again
    with SessionLocal() as db:
        assert db.scalar(select(StorageBucket)).access_key == old["access_key"]


def test_plan_change_rebalances_quotas(client, minio):
    make_site(client, storage_gb=3)
    a = client.post(f"{S}/storage/buckets", json={"name": "a-1"}).json()
    b = client.post(f"{S}/storage/buckets", json={"name": "b-2"}).json()
    put_object(minio, a["access_key"], a["secret_key"], a["bucket"], "f", b"y" * 500)
    assert minio.buckets[a["bucket"]]["quota"] == 3 * GIB
    client.get(f"{S}/storage/buckets")  # refresh usage
    client.patch(f"{S}/plan", json={"features": {"storage_gb": 1}})
    # own size + the site's headroom (limit - total)
    assert minio.buckets[a["bucket"]]["quota"] == 500 + (GIB - 500)
    assert minio.buckets[b["bucket"]]["quota"] == GIB - 500
    client.patch(f"{S}/plan", json={"features": {"storage_gb": 0}})  # storage removed: frozen
    assert minio.buckets[a["bucket"]]["quota"] == 500 and minio.buckets[b["bucket"]]["quota"] == 1
    assert put_object(minio, b["access_key"], b["secret_key"], b["bucket"], "g", b"zz").status_code == 400


def test_hourly_usage_billing_and_report(client, minio, fresh_alerts):
    make_site(client, storage_gb=1)
    a = client.post(f"{S}/storage/buckets", json={"name": "media"}).json()
    put_object(minio, a["access_key"], a["secret_key"], a["bucket"], "f", b"x" * 2048)
    t0 = datetime(2026, 9, 1, 0, 5)
    with SessionLocal() as db:
        out = storage.run_hourly(db, now=t0)
        assert out["samples"] == 1 and out["buckets"] == 1
        assert storage.run_hourly(db, now=t0 + timedelta(minutes=30)) is None  # once per hour
        # controller down for 5 hours, meanwhile the bucket grew: gaps get min(before, now)
        minio.buckets[a["bucket"]]["objects"]["g"] = b"y" * 1024
        out = storage.run_hourly(db, now=t0 + timedelta(hours=6))
        assert out["samples"] == 6
        rows = db.scalars(select(StorageUsageHourly).order_by(StorageUsageHourly.hour)).all()
        assert [r.bytes for r in rows] == [2048] * 6 + [3072]
        assert rows[0].hour == datetime(2026, 9, 1, 0, 0)
        # the edges' origin policy is re-applied every run (self-heal)
        minio.buckets[a["bucket"]]["policy"] = None
        storage.run_hourly(db, now=t0 + timedelta(hours=7))
        assert minio.buckets[a["bucket"]]["policy"]["Statement"][0]["Action"] == ["s3:GetObject"]

    rep = client.get(f"{S}/storage/usage", params={"month": "2026-09"}).json()
    byte_hours = 2048 * 6 + 3072 * 2
    assert rep["month"] == "2026-09" and rep["hours_in_month"] == 720 and rep["complete"] is True
    assert rep["byte_hours"] == byte_hours and rep["gb_hours"] == round(byte_hours / GIB, 4)
    assert rep["gb_month"] == round(byte_hours / GIB / 720, 4) and rep["storage_gb"] == 1
    assert rep["buckets"][0]["name"] == "media" and rep["buckets"][0]["samples"] == 8
    assert client.get(f"{S}/storage/usage", params={"month": "2026-13"}).status_code == 422
    assert client.get(f"{S}/storage/usage", params={"month": "2026-08"}).json()["byte_hours"] == 0
    allr = client.get("/api/v1/storage/usage", params={"month": "2026-09"}).json()
    assert [s["domain"] for s in allr["sites"]] == ["example.com"]
    assert allr["sites"][0]["byte_hours"] == byte_hours

    # a deleted bucket's usage stays billable for the month
    minio.buckets[a["bucket"]]["objects"].clear()
    assert client.delete(f"{S}/storage/buckets/media").status_code == 200
    rep = client.get(f"{S}/storage/usage", params={"month": "2026-09"}).json()
    assert rep["byte_hours"] == byte_hours and rep["buckets"][0]["deleted"] is True


def test_hourly_job_alerts(client, minio, fresh_alerts, monkeypatch):
    make_site(client, storage_gb=1)
    a = client.post(f"{S}/storage/buckets", json={"name": "media"}).json()
    import app.minio_client as mc

    real = mc.MinioClient.data_usage
    monkeypatch.setattr(mc.MinioClient, "data_usage",
                        lambda self: {**real(self), "buckets": {a["bucket"]: {"size": 2 * GIB, "objects": 9}}})
    with SessionLocal() as db:
        scheduler.job_storage(db, now=datetime(2026, 9, 2, 10, 0))
    keys = [c["key"] for c in alerts.open_alerts()]
    assert "storage_quota:example.com" in keys
    assert minio.buckets[a["bucket"]]["quota"] == 2 * GIB  # frozen at its size (no headroom)
    minio.down = True
    with SessionLocal() as db:
        out = scheduler.job_storage(db, now=datetime(2026, 9, 2, 11, 0))
    assert "error" in out and "storage_usage" in [c["key"] for c in alerts.open_alerts()]
    minio.down = False
    monkeypatch.setattr(mc.MinioClient, "data_usage", real)
    with SessionLocal() as db:
        scheduler.job_storage(db, now=datetime(2026, 9, 2, 11, 1))
    keys = [c["key"] for c in alerts.open_alerts()]
    assert "storage_usage" not in keys and "storage_quota:example.com" not in keys


def test_storage_origin_record_and_edge_config(client, minio):
    make_site(client, storage_gb=1)
    activate()
    token = online_edge(client)
    b = client.post(f"{S}/storage/buckets", json={"name": "static"}).json()
    # validation
    r = client.post(f"{S}/records", json={"name": "cdn", "type": "CNAME", "storage": "static"})
    assert r.status_code == 422  # not proxied
    r = client.post(f"{S}/records", json={"name": "cdn", "type": "CNAME", "proxied": True, "storage": "nope"})
    assert r.status_code == 422
    r = client.post(f"{S}/records", json={"name": "cdn", "type": "CNAME", "proxied": True, "storage": "static",
                                          "pool": "p1"})
    assert r.status_code == 422
    r = client.post(f"{S}/records", json={"name": "cdn", "type": "CNAME", "proxied": True, "storage": "../x"})
    assert r.status_code == 422
    r = client.post(f"{S}/records", json={"name": "cdn", "type": "CNAME", "proxied": True, "storage": "static"})
    assert r.status_code == 201, r.text
    rec = r.json()
    assert rec["storage"] == "static" and rec["content"] == "s3.cdn.test" and rec["origin_port"] is None

    cfg = edge_get(client, token, "/edge/v1/config").json()
    hosts = {h["name"]: h["origin"] for h in cfg["sites"][0]["hosts"]}
    with SessionLocal() as db:
        row = db.scalar(select(StorageBucket))
        origin_token, secret = row.origin_token, row.secret_key
    assert hosts["cdn.example.com"] == {"storage": {
        "host": "s3.cdn.test", "port": 443, "tls": True, "host_header": "s3.cdn.test", "bucket": b["bucket"],
        "path_prefix": "/" + b["bucket"], "referer": origin_token}}
    assert hosts["example.com"] == {"address": "93.184.216.34", "port": None}
    dumped = json.dumps(cfg)
    assert secret not in dumped and b["access_key"] not in dumped

    # the bucket in use cannot be deleted
    r = client.delete(f"{S}/storage/buckets/static")
    assert r.status_code == 409 and "cdn" in r.json()["detail"]
    # plan without storage: the host leaves the edge config, records cannot point at storage
    client.patch(f"{S}/plan", json={"features": {"storage_gb": 0}})
    cfg = edge_get(client, token, "/edge/v1/config").json()
    assert "cdn.example.com" not in {h["name"] for h in cfg["sites"][0]["hosts"]}
    r = client.post(f"{S}/records", json={"name": "img", "type": "CNAME", "proxied": True, "storage": "static"})
    assert r.status_code == 403
    client.patch(f"{S}/plan", json={"features": {"storage_gb": 1}})
    # custom port in the public endpoint -> Host header carries it
    storage.settings.storage_public_endpoint = "https://files.cdn.test:9443/s3"
    try:
        cfg = edge_get(client, token, "/edge/v1/config").json()
    finally:
        storage.settings.storage_public_endpoint = ENDPOINT
    o = {h["name"]: h["origin"] for h in cfg["sites"][0]["hosts"]}["cdn.example.com"]["storage"]
    assert (o["host"], o["port"], o["host_header"], o["path_prefix"]) == (
        "files.cdn.test", 9443, "files.cdn.test:9443", f"/s3/{b['bucket']}")
    # changing the record back to a normal origin frees the bucket
    rid = rec["id"]
    r = client.put(f"{S}/records/{rid}", json={"name": "cdn", "type": "A", "content": "93.184.216.34",
                                               "proxied": True})
    assert r.status_code == 200 and r.json()["storage"] is None
    assert client.delete(f"{S}/storage/buckets/static").status_code == 200


def test_site_delete_revokes_keys_and_keeps_data(client, minio, fresh_alerts):
    make_site(client)
    full = client.post(f"{S}/storage/buckets", json={"name": "full"}).json()
    empty = client.post(f"{S}/storage/buckets", json={"name": "empty"}).json()
    put_object(minio, full["access_key"], full["secret_key"], full["bucket"], "k", b"data")
    assert client.delete(S).status_code == 200
    assert minio.sas == {}  # every customer key revoked
    assert empty["bucket"] not in minio.buckets
    assert minio.buckets[full["bucket"]]["objects"] == {"k": b"data"}  # never deleted implicitly
    assert minio.buckets[full["bucket"]]["policy"] is None  # no longer an origin
    assert "storage_orphans:example.com" in [c["key"] for c in alerts.open_alerts()]
    with SessionLocal() as db:
        assert db.scalar(select(StorageBucket)) is None


def test_crypto_bulk_ops_cover_storage(client, minio, monkeypatch):
    from cryptography.fernet import Fernet

    from app import crypto

    make_site(client)
    created = client.post(f"{S}/storage/buckets", json={"name": "assets"}).json()
    with SessionLocal() as db:
        assert db.scalar(select(StorageBucket)).secret_key_stored == created["secret_key"]  # no key: plaintext
    k1, k2 = Fernet.generate_key().decode(), Fernet.generate_key().decode()
    monkeypatch.setattr(settings, "data_encryption_key", k1)
    with SessionLocal() as db:
        assert crypto.encrypt_existing(db) >= 2
        assert crypto.status(db)["plaintext"] == 0
        row = db.scalar(select(StorageBucket))
        assert row.secret_key_stored.startswith("enc:v1:") and row.secret_key == created["secret_key"]
    monkeypatch.setattr(settings, "data_encryption_key", f"{k2},{k1}")
    with SessionLocal() as db:
        crypto.rotate_all(db)
    monkeypatch.setattr(settings, "data_encryption_key", k2)
    with SessionLocal() as db:
        assert db.scalar(select(StorageBucket)).secret_key == created["secret_key"]
    # key lost: the secret copy is forgotten, a new origin token is generated
    monkeypatch.setattr(settings, "data_encryption_key", Fernet.generate_key().decode())
    with SessionLocal() as db:
        crypto.drop_unreadable(db)
        row = db.scalar(select(StorageBucket))
        assert row.secret_key_stored == "" and len(row.origin_token) == 48


# ------------------------------------------------------------------ real MinIO (optional)

def _minio_bin() -> str | None:
    return os.environ.get("PCDN_TEST_MINIO_BIN") or shutil.which("minio")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture()
def real_minio(monkeypatch):
    binary = _minio_bin()
    if not binary:
        pytest.skip("no minio binary (set PCDN_TEST_MINIO_BIN)")
    data = tempfile.mkdtemp()
    port = _free_port()
    env = {**os.environ, "MINIO_ROOT_USER": "rootadmin", "MINIO_ROOT_PASSWORD": "rootpassword-123",
           "MINIO_BROWSER": "off"}
    proc = subprocess.Popen([binary, "server", data, "--address", f"127.0.0.1:{port}", "--quiet"],
                            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    url = f"http://127.0.0.1:{port}"
    try:
        for _ in range(100):
            try:
                if httpx.get(url + "/minio/health/live", timeout=1, trust_env=False).status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            time.sleep(0.1)
        root = MinioClient(url, "rootadmin", "rootpassword-123")
        policy_file = os.path.join(os.path.dirname(__file__), "..", "..", "deploy", "storage", "minio",
                                   "pcdn-controller-policy.json")
        root.add_canned_policy("pcdn-controller", json.load(open(policy_file)))
        root.add_user(ADMIN_AK, ADMIN_SK)
        root.attach_user_policy(ADMIN_AK, "pcdn-controller")
        monkeypatch.setattr(settings, "storage_endpoint", url)
        monkeypatch.setattr(settings, "storage_public_endpoint", url)
        monkeypatch.setattr(settings, "storage_admin_access_key", ADMIN_AK)
        monkeypatch.setattr(settings, "storage_admin_secret_key", ADMIN_SK)
        storage.set_client(MinioClient(url, ADMIN_AK, ADMIN_SK))
        yield url
    finally:
        storage.set_client(None)
        proc.terminate()
        proc.wait(10)
        shutil.rmtree(data, ignore_errors=True)


def test_minio_disk_status(client, minio):
    """SPEC §16.8 capacity panel on the MinIO backend: drive totals from admin/v3/storageinfo, with
    an offline drive (all zeroes) skipped rather than counted as a full one."""
    out = storage.client().disk_status()
    assert (out["total"], out["used"], out["free"]) == (300 * GIB, 50 * GIB, 250 * GIB)
    assert [d["dir"] for d in out["dirs"]] == ["/export1", "/export2"]
    storage._capacity_cache.clear()
    d = client.get("/api/v1/storage/capacity").json()
    assert d["backend"] == "minio" and d["disk"]["total"] == 300 * GIB
    storage._capacity_cache.clear()


def test_real_minio(client, real_minio):
    url = real_minio
    make_site(client, storage_gb=1)
    created = client.post(f"{S}/storage/buckets", json={"name": "assets"})
    assert created.status_code == 201, created.text
    c = created.json()
    cust = MinioClient(url, c["access_key"], c["secret_key"])
    cust._call("PUT", f"/{c['bucket']}/hello.txt", body=b"hello")
    with pytest.raises(MinioError) as e:  # no bucket policy rights, no other bucket, no admin
        cust.put_bucket_policy(c["bucket"], {})
    assert e.value.status == 403
    with pytest.raises(MinioError):
        cust.set_bucket_quota(c["bucket"], 0)
    with SessionLocal() as db:
        token = db.scalar(select(StorageBucket)).origin_token
    plain = httpx.Client(trust_env=False)
    assert plain.get(f"{url}/{c['bucket']}/hello.txt").status_code == 403
    r = plain.get(f"{url}/{c['bucket']}/hello.txt", headers={"Referer": token})
    assert r.status_code == 200 and r.text == "hello"
    assert plain.get(f"{url}/{c['bucket']}/", headers={"Referer": token}).status_code == 403  # no listing
    assert client.delete(f"{S}/storage/buckets/assets").status_code == 409
    with SessionLocal() as db:  # data usage + quota + policy re-apply against the real admin API
        out = storage.run_hourly(db, force=True)
    assert "error" not in out and out["quota_failed"] == [] and out["policy_failed"] == []
    rot = client.post(f"{S}/storage/buckets/assets/rotate-key").json()
    with pytest.raises(MinioError):
        cust._call("GET", f"/{c['bucket']}/hello.txt")
    MinioClient(url, rot["access_key"], rot["secret_key"])._call("DELETE", f"/{c['bucket']}/hello.txt")
    assert client.delete(f"{S}/storage/buckets/assets").status_code == 200
    assert not storage.client().bucket_exists(c["bucket"])
