"""SeaweedFS client for the object storage product (SPEC §16.8), the default backend since MinIO
removed its community images from Docker Hub and archived the repository.

The data plane is plain S3, so everything MinioClient does with the S3 API is inherited unchanged
(create / head / delete a bucket, "is it empty?", bucket policy — the anonymous origin policy with
its Referer condition included). Only the three operator-side calls differ:

* bucket quota — the SeaweedFS S3 extension `PUT /{bucket}?seaweedfs-quota` with
  {"quota_size", "quota_unit", "quota_enabled"}, authorized as `s3:PutBucketQuota`.
* a customer's access key — the IAM API on the same port (`POST /`, SigV4 with service `iam`):
  CreateUser + PutUserPolicy (our inline policy, which the server turns into the identity's
  enforced actions) + CreateAccessKey with the key pair we generated. The IAM user is named after
  the access key, so deleting the key needs no lookup. The server must run with
  `-iam.readOnly=false`, otherwise every write here answers 403.
* data usage — the S3 gateway's Prometheus gauges (`SeaweedFS_s3_bucket_size_bytes`,
  `..._bucket_object_count`), refreshed once a minute by the gateway, which is the same
  eventually-consistent figure MinIO's scanner gave us. The metrics port carries no credentials, so
  it is reached through the storage server's own reverse proxy on a path only the controller's
  address may call (deploy/storage/Caddyfile), exactly like the MinIO admin API was.

Errors are MinioError (the storage-call error of this package, kept so callers stay backend-agnostic)
and never carry a secret: status, S3/IAM error code and message only.
"""

import json
from datetime import datetime, timezone
from urllib.parse import urlencode

import httpx

from .minio_client import MinioClient, MinioError

# the policy name of the single inline policy a customer key carries
CUSTOMER_POLICY = "pcdn-bucket"
IAM_VERSION = "2010-05-08"
QUOTA_PARAM = "seaweedfs-quota"
# path on the storage endpoint that the storage server maps to the S3 gateway's metrics port
DEFAULT_METRICS_PATH = "/__pcdn/storage-metrics"
_SIZE_METRIC = "s3_bucket_size_bytes"
_COUNT_METRIC = "s3_bucket_object_count"
_NOT_FOUND = ("NoSuchEntity", "NoSuchEntityException", "NoSuchBucketPolicy")
# SeaweedFS names two multipart actions differently from AWS/MinIO and rejects a policy document
# naming an action it does not know (MalformedPolicyDocument), so the customer policy is translated
# on the way in. Anything else is passed through unchanged: an action this server does not know must
# fail loudly rather than be silently dropped from the grant.
ACTION_ALIASES = {
    "s3:ListBucketMultipartUploads": "s3:ListMultipartUploads",
    "s3:ListMultipartUploadParts": "s3:ListParts",
}


def translate_policy(policy: dict) -> dict:
    """`policy` with the action names this server's policy parser expects."""
    out = dict(policy)
    statements = []
    for st in policy.get("Statement") or []:
        st = dict(st)
        action = st.get("Action")
        if isinstance(action, str):
            st["Action"] = ACTION_ALIASES.get(action, action)
        elif isinstance(action, list):
            st["Action"] = [ACTION_ALIASES.get(a, a) for a in action]
        statements.append(st)
    out["Statement"] = statements
    return out


def _metric_values(text: str, suffix: str) -> dict[str, float]:
    """{bucket: value} of a Prometheus gauge whose name ends in `suffix` and whose only label is
    bucket. The namespace prefix is not hard-coded so a renamed namespace still parses."""
    out: dict[str, float] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "{" not in line:
            continue
        name, rest = line.split("{", 1)
        if not name.endswith(suffix):
            continue
        labels, _, value = rest.partition("}")
        bucket = ""
        for part in labels.split(","):
            k, _, v = part.partition("=")
            if k.strip() == "bucket":
                bucket = v.strip().strip('"')
        try:
            if bucket:
                out[bucket] = float(value.split()[0])
        except (ValueError, IndexError):
            continue
    return out


class SeaweedClient(MinioClient):
    """MinioClient's S3 surface with SeaweedFS's quota / IAM / usage calls."""

    def __init__(self, endpoint: str, access_key: str, secret_key: str, region: str = "us-east-1",
                 transport: httpx.BaseTransport | None = None, timeout: float = 20,
                 metrics_path: str = DEFAULT_METRICS_PATH):
        super().__init__(endpoint, access_key, secret_key, region, transport, timeout)
        path = metrics_path or DEFAULT_METRICS_PATH
        # a full URL (the gateway's metrics port straight from a private network) or a path on the
        # storage endpoint, which the storage server proxies to that port for the controller's
        # address only (deploy/storage/Caddyfile)
        self.metrics_url = path if path.startswith(("http://", "https://")) else \
            str(self.base) + "/" + path.lstrip("/")

    # -- IAM (customer access keys)

    def _iam(self, action: str, params: dict[str, str], ok: tuple[int, ...] = (200,)) -> httpx.Response:
        body = urlencode({"Action": action, "Version": IAM_VERSION, **params}).encode()
        return self._call("POST", "/", body=body, ok=ok, service="iam",
                          headers={"content-type": "application/x-www-form-urlencoded"})

    def _iam_optional(self, action: str, params: dict[str, str]) -> bool:
        """An IAM call whose "it was not there" answer is a success. -> was something removed?"""
        try:
            self._iam(action, params)
        except MinioError as e:
            if e.code in _NOT_FOUND or e.status == 404:
                return False
            raise
        return True

    def add_service_account(self, access_key: str, secret_key: str, policy: dict,
                            name: str = "", description: str = "") -> dict:
        """An IAM user named after the access key, carrying `policy` and that one key pair. `name` /
        `description` have no IAM equivalent and are ignored (MinIO put them on the credential)."""
        self._iam("CreateUser", {"UserName": access_key})
        try:
            self._iam("PutUserPolicy", {"UserName": access_key, "PolicyName": CUSTOMER_POLICY,
                                        "PolicyDocument": json.dumps(translate_policy(policy))})
            self._iam("CreateAccessKey", {"UserName": access_key, "AccessKeyId": access_key,
                                          "SecretAccessKey": secret_key})
        except MinioError:
            # never leave a user behind that has no policy yet (it would hold the name and, worse,
            # could later be given a key by a retry while its policy was still missing)
            try:
                self.delete_service_account(access_key)
            except MinioError:
                pass
            raise
        return {"accessKey": access_key, "secretKey": secret_key}

    def delete_service_account(self, access_key: str) -> bool:
        """False when nothing was there any more. The policy goes first: deleting the user alone
        would leave its inline policy in the credential store."""
        self._iam_optional("DeleteUserPolicy", {"UserName": access_key, "PolicyName": CUSTOMER_POLICY})
        self._iam_optional("DeleteAccessKey", {"UserName": access_key, "AccessKeyId": access_key})
        return self._iam_optional("DeleteUser", {"UserName": access_key})

    # -- quota

    def set_bucket_quota(self, bucket: str, size: int) -> None:
        """Hard quota in bytes; 0 removes it (SeaweedFS stores 0 as "no quota")."""
        size = max(0, int(size))
        body = json.dumps({"quota_size": size, "quota_unit": "B", "quota_enabled": size > 0}).encode()
        self._call("PUT", self._bucket_path(bucket), {QUOTA_PARAM: ""}, body)

    def get_bucket_quota(self, bucket: str) -> int:
        """The configured quota in bytes (0 = none, a disabled quota reads as 0)."""
        r = self._call("GET", self._bucket_path(bucket), {QUOTA_PARAM: ""})
        doc = r.json() if r.content else {}
        size, unit = int(doc.get("quota_size") or 0), str(doc.get("quota_unit") or "B").upper()
        if not doc.get("quota_enabled") or size <= 0:
            return 0
        return size * {"B": 1, "KB": 1 << 10, "MB": 1 << 20, "GB": 1 << 30, "TB": 1 << 40}.get(unit, 1)

    # -- usage

    def data_usage(self) -> dict:
        """{"last_update": iso, "buckets": {name: {"size": int, "objects": int}}} from the gateway's
        bucket gauges. The gateway recomputes them once a minute, so this lags writes by up to that.

        The metrics endpoint carries no credentials and takes none, so this one call is unsigned; it
        is reachable only from the controller's address (the storage server's reverse proxy)."""
        try:
            r = self.http.get(self.metrics_url)
        except httpx.HTTPError as e:
            raise MinioError(f"storage metrics unreachable: {type(e).__name__}") from None
        if r.status_code != 200:
            raise MinioError(f"storage metrics: HTTP {r.status_code}", r.status_code)
        sizes = _metric_values(r.text, _SIZE_METRIC)
        counts = _metric_values(r.text, _COUNT_METRIC)
        buckets = {name: {"size": int(size), "objects": int(counts.get(name) or 0)}
                   for name, size in sizes.items()}
        return {"last_update": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "buckets": buckets}

    # -- not part of this backend: the MinIO-only bootstrap helpers. SeaweedFS's operator identities
    # come from the server's own config file (deploy/storage/bootstrap.sh), never over the wire.

    def add_user(self, access_key: str, secret_key: str) -> None:
        raise NotImplementedError("SeaweedFS operator identities live in the server's config file")

    def add_canned_policy(self, name: str, policy: dict) -> None:
        raise NotImplementedError("SeaweedFS operator identities live in the server's config file")

    def attach_user_policy(self, user: str, policy: str) -> None:
        raise NotImplementedError("SeaweedFS operator identities live in the server's config file")
