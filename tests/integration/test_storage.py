"""Object-storage origin (SPEC §16.8) on the staging stack: needs the MinIO profile
(STAGING_STORAGE=1 deploy/staging/staging.sh up). A bucket is created through the admin API, an object
is uploaded with the bucket's own (customer) keys, and a proxied record with `storage` serves it
through every edge."""

import os
import uuid

import pytest

from conftest import ApiError, KEEP, ORIGIN_IP, edge_request, new_domain, wait_until

pytestmark = [pytest.mark.storage, pytest.mark.skipif(os.environ.get("STAGING_STORAGE", "0") != "1",
                                                      reason="needs STAGING_STORAGE=1 (MinIO profile)")]

DOMAIN = new_domain("files")


@pytest.fixture(scope="module")
def storage_site(api, edges):
    api.post("/api/v1/sites", {"domain": DOMAIN, "origin_ip": ORIGIN_IP, "plan": {
        "ssl_allowed": False, "features": {"storage_gb": 1}}})
    yield DOMAIN
    if not KEEP:
        try:
            api.delete(f"/api/v1/sites/{DOMAIN}")
        except ApiError:
            pass


def test_storage_bucket_served_through_the_edges(api, edges, storage_site):
    boto3 = pytest.importorskip("boto3")
    from botocore.config import Config

    # MinIO and its controller user come up in parallel with the rest: retry until the API can create
    def create():
        try:
            return api.post(f"/api/v1/sites/{DOMAIN}/storage/buckets", {"name": "assets"})
        except ApiError as e:
            if e.status == 409:
                raise AssertionError("bucket exists from an earlier run") from None
            raise
    b = wait_until(create, "bucket creation through the admin API", timeout=120, interval=3)
    endpoint = os.environ.get("STAGING_STORAGE_ENDPOINT") or "http://minio:9000"
    s3 = boto3.client("s3", endpoint_url=endpoint, aws_access_key_id=b["access_key"],
                      aws_secret_access_key=b["secret_key"], region_name="us-east-1",
                      config=Config(s3={"addressing_style": "path"}, signature_version="s3v4"))
    body = ("hello from storage " + uuid.uuid4().hex).encode()
    s3.put_object(Bucket=b["bucket"], Key="hello.txt", Body=body, ContentType="text/plain")

    api.post(f"/api/v1/sites/{DOMAIN}/records",
             {"name": "files", "type": "CNAME", "content": "", "proxied": True, "storage": "assets"})
    host = f"files.{DOMAIN}"
    for name, ip in edges.items():
        r = wait_until(lambda: (lambda r: r if r.status == 200 and r.body == body else None)(
            edge_request(ip, host, "/hello.txt")), f"{host}/hello.txt via {name}")
        assert r.headers.get("x-cache") in ("MISS", "HIT", "EXPIRED", None)
    # the bucket is not public: only the edges (with the bucket's origin token) can read it
    import urllib.error
    import urllib.request
    with pytest.raises(urllib.error.HTTPError):
        urllib.request.urlopen(f"{endpoint}/{b['bucket']}/hello.txt", timeout=10)
