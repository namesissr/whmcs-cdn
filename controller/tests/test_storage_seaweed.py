"""Object storage on SeaweedFS (SPEC §16.8, the default backend since MinIO's community images were
removed from Docker Hub): the quota / IAM / usage calls that differ from MinIO, the backend switch,
and — when a `weed` binary is available (PCDN_TEST_WEED_BIN or `weed` on PATH) — the whole bucket
flow against a real server started with the identities deploy/storage/bootstrap.sh writes."""

import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import time
from urllib.parse import parse_qs

import httpx
import pytest
from sqlalchemy import select

from app import seaweed_client, storage
from app.config import settings
from app.db import SessionLocal
from app.minio_client import MinioClient, MinioError, new_access_key, new_secret_key
from app.models import StorageBucket
from app.seaweed_client import SeaweedClient, translate_policy
from tests.test_storage import S, make_site

ENDPOINT = "https://s3.cdn.test"
AK, SK = "CTRLKEY00000000000AA", "ctrl-secret-123"
BUCKET = "cdn-abcdefgh-assets"
GIB = 1024 ** 3
HERE = os.path.dirname(__file__)
BOOTSTRAP = os.path.join(HERE, "..", "..", "deploy", "storage", "bootstrap.sh")


# ------------------------------------------------------------------ a fake SeaweedFS

class FakeSeaweed:
    """Just enough of the S3 / IAM / metrics surface to record what the client sends."""

    def __init__(self):
        self.users: dict[str, dict] = {}   # name -> {"policy": dict|None, "keys": {ak: sk}}
        self.buckets: dict[str, dict] = {}   # name -> {"policy": dict|None, "objects": int}
        self.quota: dict[str, dict] = {}
        self.usage = {BUCKET: (128, 1)}
        self.calls: list[tuple[str, str]] = []   # (action or method, path)
        self.fail: dict[str, tuple[int, str]] = {}   # action -> (status, code)

    def err(self, status: int, code: str, iam: bool = False) -> httpx.Response:
        if iam:
            body = ('<?xml version="1.0" encoding="UTF-8"?><ErrorResponse '
                    'xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><Error>'
                    f"<Code>{code}</Code><Message>no</Message><Type>Sender</Type></Error></ErrorResponse>")
        else:
            body = f"<Error><Code>{code}</Code><Message>no</Message></Error>"
        return httpx.Response(status, text=body)

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        query = parse_qs(request.url.query.decode(), keep_blank_values=True)
        if path == "/__pcdn/storage-metrics":
            lines = ["# HELP SeaweedFS_s3_bucket_size_bytes size", "# TYPE SeaweedFS_s3_bucket_size_bytes gauge"]
            for name, (size, objects) in self.usage.items():
                lines.append(f'SeaweedFS_s3_bucket_size_bytes{{bucket="{name}"}} {size}')
                lines.append(f'SeaweedFS_s3_bucket_object_count{{bucket="{name}"}} {objects}')
            lines.append("SeaweedFS_s3_requests_total 7")                     # no bucket label: ignored
            lines.append('SeaweedFS_s3_bucket_size_bytes{bucket="bad"} oops')  # unparsable: ignored
            return httpx.Response(200, text="\n".join(lines) + "\n")
        if request.method == "POST" and path == "/":
            return self.iam(request)
        if "seaweedfs-quota" in query and request.method in ("PUT", "GET"):
            bucket = path.strip("/")
            if request.method == "PUT":
                self.calls.append(("quota", bucket))
                self.quota[bucket] = json.loads(request.content)
                return httpx.Response(200)
            return httpx.Response(200, json=self.quota.get(bucket, {"quota_size": 0, "quota_unit": "B",
                                                                    "quota_enabled": False}))
        self.calls.append((request.method, path))
        bucket, _, key = path.strip("/").partition("/")
        if not bucket:
            return self.err(403, "AccessDenied")
        if request.method == "HEAD" and not key:
            return httpx.Response(200 if bucket in self.buckets else 404)
        if request.method == "PUT" and not key and "policy" not in query:
            if bucket in self.buckets:
                return self.err(409, "BucketAlreadyOwnedByYou")
            self.buckets[bucket] = {"policy": None, "objects": 0}
            return httpx.Response(200)
        if bucket not in self.buckets:
            return self.err(404, "NoSuchBucket")
        if request.method == "PUT" and "policy" in query:
            self.buckets[bucket]["policy"] = json.loads(request.content)
            return httpx.Response(200)
        if request.method == "DELETE" and "policy" in query:
            self.buckets[bucket]["policy"] = None
            return httpx.Response(204)
        if request.method == "GET" and not key:
            contents = "<Contents><Key>x</Key></Contents>" if self.buckets[bucket]["objects"] else ""
            return httpx.Response(200, text=f"<ListBucketResult>{contents}</ListBucketResult>")
        if request.method == "DELETE" and not key:
            if self.buckets[bucket]["objects"]:
                return self.err(409, "BucketNotEmpty")
            self.buckets.pop(bucket)
            self.quota.pop(bucket, None)
            return httpx.Response(204)
        return httpx.Response(200)

    def iam(self, request: httpx.Request) -> httpx.Response:
        form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
        action, user = form.get("Action", ""), form.get("UserName", "")
        self.calls.append((action, user))
        if action in self.fail:
            status, code = self.fail[action]
            return self.err(status, code, iam=True)
        if action == "CreateUser":
            if user in self.users:
                return self.err(409, "EntityAlreadyExists", iam=True)
            self.users[user] = {"policy": None, "keys": {}}
        elif action == "PutUserPolicy":
            if user not in self.users:
                return self.err(404, "NoSuchEntity", iam=True)
            self.users[user]["policy"] = json.loads(form["PolicyDocument"])
            self.users[user]["policy_name"] = form["PolicyName"]
        elif action == "CreateAccessKey":
            if user not in self.users:
                return self.err(404, "NoSuchEntity", iam=True)
            self.users[user]["keys"][form["AccessKeyId"]] = form["SecretAccessKey"]
        elif action in ("DeleteUserPolicy", "DeleteAccessKey", "DeleteUser"):
            if user not in self.users:
                return self.err(404, "NoSuchEntity", iam=True)
            if action == "DeleteUser":
                self.users.pop(user)
            elif action == "DeleteUserPolicy":
                self.users[user]["policy"] = None
            else:
                self.users[user]["keys"].pop(form.get("AccessKeyId", ""), None)
        else:
            return self.err(400, "InvalidAction", iam=True)
        return httpx.Response(200, text="<Response/>")


@pytest.fixture()
def fake():
    return FakeSeaweed()


@pytest.fixture()
def cli(fake):
    return SeaweedClient(ENDPOINT, AK, SK, transport=httpx.MockTransport(fake.handler))


@pytest.fixture()
def seaweed(monkeypatch, fake):
    """The storage product wired to the fake SeaweedFS (the API tests of test_storage.py, but on
    this backend)."""
    monkeypatch.setattr(settings, "storage_backend", "seaweedfs")
    monkeypatch.setattr(settings, "storage_endpoint", ENDPOINT)
    monkeypatch.setattr(settings, "storage_public_endpoint", ENDPOINT)
    monkeypatch.setattr(settings, "storage_admin_access_key", AK)
    monkeypatch.setattr(settings, "storage_admin_secret_key", SK)
    storage.set_client(SeaweedClient(ENDPOINT, AK, SK, transport=httpx.MockTransport(fake.handler)))
    yield fake
    storage.set_client(None)


# ------------------------------------------------------------------ the pieces that differ

def test_backend_switch(monkeypatch):
    monkeypatch.setattr(settings, "storage_endpoint", ENDPOINT)
    monkeypatch.setattr(settings, "storage_public_endpoint", ENDPOINT)
    monkeypatch.setattr(settings, "storage_admin_access_key", AK)
    monkeypatch.setattr(settings, "storage_admin_secret_key", SK)
    try:
        for value, cls in (("seaweedfs", SeaweedClient), ("minio", MinioClient),
                           ("SeaweedFS", SeaweedClient), ("", SeaweedClient)):
            storage.set_client(None)
            monkeypatch.setattr(settings, "storage_backend", value)
            c = storage.client()
            assert type(c) is cls, value
            assert storage.backend() == ("minio" if value == "minio" else "seaweedfs")
    finally:
        storage.set_client(None)


def test_metrics_parsing_and_usage(cli, fake):
    fake.usage = {BUCKET: (4096, 3), "cdn-other01-media": (0, 0)}
    out = cli.data_usage()
    assert out["buckets"] == {BUCKET: {"size": 4096, "objects": 3},
                              "cdn-other01-media": {"size": 0, "objects": 0}}
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", out["last_update"])
    # a metric without the bucket label, an unparsable value and the comment lines are skipped
    assert seaweed_client._metric_values("# c\nX_s3_bucket_size_bytes 5\n", "s3_bucket_size_bytes") == {}


def test_metrics_url_forms(fake):
    on_path = SeaweedClient(ENDPOINT, AK, SK, transport=httpx.MockTransport(fake.handler))
    assert on_path.metrics_url == ENDPOINT + "/__pcdn/storage-metrics"
    direct = SeaweedClient(ENDPOINT, AK, SK, transport=httpx.MockTransport(fake.handler),
                           metrics_path="http://10.0.0.9:9327/metrics")
    assert direct.metrics_url == "http://10.0.0.9:9327/metrics"

    def dead(request):
        return httpx.Response(502, text="bad gateway")
    bad = SeaweedClient(ENDPOINT, AK, SK, transport=httpx.MockTransport(dead))
    with pytest.raises(MinioError) as e:
        bad.data_usage()
    assert e.value.status == 502


def test_quota_requests(cli, fake):
    cli.set_bucket_quota(BUCKET, 2 * GIB)
    assert fake.quota[BUCKET] == {"quota_size": 2 * GIB, "quota_unit": "B", "quota_enabled": True}
    assert cli.get_bucket_quota(BUCKET) == 2 * GIB
    cli.set_bucket_quota(BUCKET, 0)
    assert fake.quota[BUCKET] == {"quota_size": 0, "quota_unit": "B", "quota_enabled": False}
    assert cli.get_bucket_quota(BUCKET) == 0
    cli.set_bucket_quota(BUCKET, -5)   # never a negative quota (SeaweedFS reads that as "disabled")
    assert fake.quota[BUCKET]["quota_size"] == 0
    # a quota the operator set in another unit reads back in bytes; a disabled one reads as none
    fake.quota[BUCKET] = {"quota_size": 3, "quota_unit": "gb", "quota_enabled": True}
    assert cli.get_bucket_quota(BUCKET) == 3 * GIB
    fake.quota[BUCKET] = {"quota_size": 3, "quota_unit": "GB", "quota_enabled": False}
    assert cli.get_bucket_quota(BUCKET) == 0


def test_customer_key_creation(cli, fake):
    ak, sk = new_access_key(), new_secret_key()
    policy = storage.customer_policy(BUCKET)
    assert cli.add_service_account(ak, sk, policy) == {"accessKey": ak, "secretKey": sk}
    assert [c[0] for c in fake.calls] == ["CreateUser", "PutUserPolicy", "CreateAccessKey"]
    user = fake.users[ak]
    assert user["keys"] == {ak: sk} and user["policy_name"] == seaweed_client.CUSTOMER_POLICY
    text = json.dumps(user["policy"])
    assert f"arn:aws:s3:::{BUCKET}" in text and "PutBucketPolicy" not in text
    # SeaweedFS's own names for the two multipart actions, and nothing it would reject
    assert "ListMultipartUploads" in text and "ListBucketMultipartUploads" not in text
    assert "ListParts" in text and "ListMultipartUploadParts" not in text


def test_policy_translation_leaves_everything_else_alone():
    policy = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Resource": ["arn:aws:s3:::b"], "Action": "s3:ListBucketMultipartUploads"},
        {"Effect": "Allow", "Resource": ["arn:aws:s3:::b/*"],
         "Action": ["s3:GetObject", "s3:ListMultipartUploadParts", "s3:PutObjectTagging"]},
        {"Effect": "Deny", "Resource": ["*"], "Action": ["s3:DeleteBucket"]}]}
    out = translate_policy(policy)
    assert out["Statement"][0]["Action"] == "s3:ListMultipartUploads"
    assert out["Statement"][1]["Action"] == ["s3:GetObject", "s3:ListParts", "s3:PutObjectTagging"]
    assert out["Statement"][2] == policy["Statement"][2] and out["Version"] == "2012-10-17"
    assert policy["Statement"][0]["Action"] == "s3:ListBucketMultipartUploads"   # input untouched


def test_half_created_key_is_cleaned_up(cli, fake):
    ak, sk = new_access_key(), new_secret_key()
    fake.fail["CreateAccessKey"] = (500, "ServiceFailure")
    with pytest.raises(MinioError):
        cli.add_service_account(ak, sk, storage.customer_policy(BUCKET))
    assert ak not in fake.users          # the user it had already created is gone again
    assert "DeleteUser" in [c[0] for c in fake.calls]


def test_delete_is_idempotent_and_reports(cli, fake):
    ak, sk = new_access_key(), new_secret_key()
    cli.add_service_account(ak, sk, storage.customer_policy(BUCKET))
    assert cli.delete_service_account(ak) is True
    assert cli.delete_service_account(ak) is False     # already gone: not an error
    fake.fail["DeleteUser"] = (500, "ServiceFailure")  # a real failure still raises
    cli.add_service_account(ak, sk, storage.customer_policy(BUCKET))
    with pytest.raises(MinioError):
        cli.delete_service_account(ak)


def test_iam_error_code_is_reported(cli, fake):
    """The IAM API nests Code in <Error> under a default xmlns; the storage error must still carry
    it, otherwise the operator sees a bare "HTTP 400"."""
    fake.fail["CreateUser"] = (400, "MalformedPolicyDocument")
    with pytest.raises(MinioError) as e:
        cli.add_service_account(new_access_key(), new_secret_key(), {})
    assert e.value.code == "MalformedPolicyDocument" and e.value.status == 400


def test_operator_helpers_are_not_available(cli):
    for call in (lambda: cli.add_user("a", "b"), lambda: cli.add_canned_policy("p", {}),
                 lambda: cli.attach_user_policy("a", "p")):
        with pytest.raises(NotImplementedError):
            call()


def test_bucket_api_on_this_backend(client, seaweed, monkeypatch):
    """The customer-facing flow once more, on the SeaweedFS backend: create, quota, usage, delete."""
    from cryptography.fernet import Fernet

    monkeypatch.setattr(settings, "data_encryption_key", Fernet.generate_key().decode())
    make_site(client, storage_gb=2)
    r = client.post(f"{S}/storage/buckets", json={"name": "assets"})
    assert r.status_code == 201, r.text
    created = r.json()
    bucket, ak = created["bucket"], created["access_key"]
    assert seaweed.quota[bucket] == {"quota_size": 2 * GIB, "quota_unit": "B", "quota_enabled": True}
    assert seaweed.users[ak]["keys"] == {ak: created["secret_key"]}
    seaweed.usage = {bucket: (5 * 1024 * 1024, 4)}
    with SessionLocal() as db:
        out = storage.run_hourly(db, force=True)
    assert "error" not in out and out["quota_failed"] == [] and out["policy_failed"] == []
    rot = client.post(f"{S}/storage/buckets/assets/rotate-key").json()
    assert rot["access_key"] != ak and ak not in seaweed.users
    assert client.delete(f"{S}/storage/buckets/assets").status_code == 200
    assert seaweed.users == {}


# ------------------------------------------------------------------ real SeaweedFS (optional)

def _weed_bin() -> str | None:
    return os.environ.get("PCDN_TEST_WEED_BIN") or shutil.which("weed")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _shipped_controller_policy(prefix: str = "cdn-") -> dict:
    """The controller identity's policy exactly as deploy/storage/bootstrap.sh writes it, so this
    test fails if the shipped policy stops covering what the controller does."""
    with open(BOOTSTRAP) as f:
        text = f.read()
    m = re.search(r'"content": "(\{\\"Version.*?)"\n', text, re.S)
    assert m, "the controller policy was not found in bootstrap.sh"
    raw = m.group(1).replace('\\"', '"').replace("${PREFIX}", prefix)
    return json.loads(raw)


@pytest.fixture()
def real_seaweed(monkeypatch):
    binary = _weed_bin()
    if not binary:
        pytest.skip("no weed binary (set PCDN_TEST_WEED_BIN)")
    data = tempfile.mkdtemp()
    s3_port, metrics_port = _free_port(), _free_port()
    config = {
        "identities": [
            {"name": "pcdn-controller", "credentials": [{"accessKey": AK, "secretKey": SK}],
             "policyNames": ["pcdn-controller"]},
            # with no permissions of its own: what a bucket policy grants it is all it can do
            {"name": "anonymous", "actions": []},
        ],
        "policies": [{"name": "pcdn-controller", "content": json.dumps(_shipped_controller_policy())}],
    }
    config_path = os.path.join(data, "s3.json")
    with open(config_path, "w") as f:
        json.dump(config, f)
    log = open(os.path.join(data, "weed.log"), "w+")
    proc = subprocess.Popen(
        [binary, "server", f"-dir={data}", "-ip=127.0.0.1",
         f"-master.port={_free_port()}", f"-volume.port={_free_port()}", "-volume.max=20",
         "-master.volumeSizeLimitMB=64", "-filer", f"-filer.port={_free_port()}",
         "-s3", f"-s3.port={s3_port}", f"-s3.config={config_path}", "-s3.iam.readOnly=false",
         "-s3.port.iceberg=0", "-s3.port.lance=0", f"-metricsPort={metrics_port}"],
        stdout=subprocess.DEVNULL, stderr=log)
    url = f"http://127.0.0.1:{s3_port}"
    try:
        for _ in range(300):
            if proc.poll() is not None:
                log.seek(0)
                why = [ln for ln in log.read().splitlines() if ln.startswith(("F", "E"))][-3:]
                pytest.skip(f"weed exited with {proc.returncode}: " + " | ".join(why))
            try:
                # 403 = the gateway is up and refusing an unsigned ListBuckets
                if httpx.get(url, timeout=1, trust_env=False).status_code in (200, 403):
                    break
            except httpx.HTTPError:
                pass
            time.sleep(0.2)
        monkeypatch.setattr(settings, "storage_backend", "seaweedfs")
        monkeypatch.setattr(settings, "storage_endpoint", url)
        monkeypatch.setattr(settings, "storage_public_endpoint", url)
        monkeypatch.setattr(settings, "storage_admin_access_key", AK)
        monkeypatch.setattr(settings, "storage_admin_secret_key", SK)
        monkeypatch.setattr(settings, "storage_insecure_http", True)
        storage.set_client(SeaweedClient(url, AK, SK, timeout=60,
                                         metrics_path=f"http://127.0.0.1:{metrics_port}/metrics"))
        yield url
    finally:
        storage.set_client(None)
        proc.terminate()
        try:
            proc.wait(20)
        except subprocess.TimeoutExpired:
            proc.kill()
        log.close()
        shutil.rmtree(data, ignore_errors=True)


def test_real_seaweed(client, real_seaweed):
    url = real_seaweed
    make_site(client, storage_gb=1)
    created = client.post(f"{S}/storage/buckets", json={"name": "assets"})
    assert created.status_code == 201, created.text
    c = created.json()
    cust = MinioClient(url, c["access_key"], c["secret_key"], timeout=60)
    cust._call("PUT", f"/{c['bucket']}/hello.txt", body=b"hello")
    assert cust._call("GET", f"/{c['bucket']}/hello.txt").text == "hello"
    # the customer key reaches its own objects and nothing else
    for call in (lambda: cust.put_bucket_policy(c["bucket"], {}),
                 lambda: cust.set_bucket_quota(c["bucket"], 0),
                 lambda: cust.make_bucket("cdn-zzzzzzzz-other")):
        with pytest.raises(MinioError) as e:
            call()
        assert e.value.status == 403
    # the edges' origin shortcut: anonymous GET only with the Referer token, never a listing
    with SessionLocal() as db:
        token = db.scalar(select(StorageBucket)).origin_token
    plain = httpx.Client(trust_env=False)
    assert plain.get(f"{url}/{c['bucket']}/hello.txt").status_code == 403
    r = plain.get(f"{url}/{c['bucket']}/hello.txt", headers={"Referer": token})
    assert r.status_code == 200 and r.text == "hello"
    assert plain.get(f"{url}/{c['bucket']}/?list-type=2", headers={"Referer": token}).status_code == 403
    # a non-empty bucket is not deleted
    assert client.delete(f"{S}/storage/buckets/assets").status_code == 409
    # quota + policy re-apply and the usage read against the real server
    cli = storage.client()
    assert cli.get_bucket_quota(c["bucket"]) == GIB
    with SessionLocal() as db:
        out = storage.run_hourly(db, force=True)
    assert "error" not in out and out["quota_failed"] == [] and out["policy_failed"] == []
    # rotating the key revokes the old one
    rot = client.post(f"{S}/storage/buckets/assets/rotate-key").json()
    with pytest.raises(MinioError):
        cust._call("GET", f"/{c['bucket']}/hello.txt")
    MinioClient(url, rot["access_key"], rot["secret_key"], timeout=60)._call(
        "DELETE", f"/{c['bucket']}/hello.txt")
    assert client.delete(f"{S}/storage/buckets/assets").status_code == 200
    assert not cli.bucket_exists(c["bucket"])
