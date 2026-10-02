import json
import os
import tempfile

_tmp = tempfile.mkdtemp()
os.environ.update({
    "DATABASE_URL": f"sqlite:///{_tmp}/test.db",
    "ADMIN_API_KEY": "test-admin-key",
    "SCHEDULER_ENABLED": "false",
    "NAMESERVERS": "ns1.example-cdn.com,ns2.example-cdn.com",
    # no outbound fetch of the crawler IP ranges from the scheduler in tests (test_rules_security
    # turns it on with an injected fetcher)
    "BOT_RANGES_ENABLED": "false",
})

import httpx  # noqa: E402
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import pdns  # noqa: E402
from app.db import Base, engine  # noqa: E402
from app.main import app  # noqa: E402


class FakePdns:
    """In-memory stand-in for the PowerDNS HTTP API."""

    def __init__(self):
        self.zones: dict[str, dict] = {}
        self.down = False  # simulate an unreachable server
        # secondary DNS (SPEC §16.7): TSIG keys by id ("name."), zone metadata, axfr-retrieve calls
        self.tsigkeys: dict[str, dict] = {}
        self.axfr_retrieved: list[str] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path.split("/api/v1/servers/localhost", 1)[1]
        if self.down:
            raise httpx.ConnectError("connection refused")
        if path == "" and request.method == "GET":
            return httpx.Response(200, json={"id": "localhost", "type": "Server"})
        if path == "/zones" and request.method == "POST":
            body = json.loads(request.content)
            self.zones[body["name"]] = {"name": body["name"], "rrsets": body.get("rrsets", []),
                                        "kind": body.get("kind", "Native"), "masters": body.get("masters", []),
                                        "metadata": {}}
            return httpx.Response(201, json=self.zones[body["name"]])
        if "/cryptokeys" in path:
            return self.cryptokeys(request, path)
        if path.startswith("/tsigkeys"):
            return self.tsig(request, path)
        if "/metadata/" in path:
            zone_name, _, kind = path.removeprefix("/zones/").partition("/metadata/")
            zone = self.zones.get(zone_name)
            if zone is None:
                return httpx.Response(404)
            meta = zone.setdefault("metadata", {})
            if request.method == "PUT":
                meta[kind] = json.loads(request.content)["metadata"]
                return httpx.Response(200, json={"kind": kind, "metadata": meta[kind]})
            if request.method == "DELETE":
                meta.pop(kind, None)
                return httpx.Response(204)
            return httpx.Response(200, json={"kind": kind, "metadata": meta.get(kind, [])})
        if path.endswith("/axfr-retrieve") and request.method == "PUT":
            self.axfr_retrieved.append(path.removeprefix("/zones/").removesuffix("/axfr-retrieve"))
            return httpx.Response(200, json={"result": "queued"})
        name = path.removeprefix("/zones/")
        zone = self.zones.get(name)
        if request.method == "GET":
            return httpx.Response(404) if zone is None else httpx.Response(200, json=zone)
        if request.method == "DELETE":
            self.zones.pop(name, None)
            return httpx.Response(204)
        if request.method == "PUT":  # zone kind / masters
            if zone is None:
                return httpx.Response(404)
            body = json.loads(request.content)
            zone.update({k: body[k] for k in ("kind", "masters") if k in body})
            return httpx.Response(204)
        if request.method == "PATCH":
            if zone is None:
                return httpx.Response(404)
            if zone.get("kind") == "Slave":  # PowerDNS refuses rrset edits of a slave zone
                return httpx.Response(422, json={"error": "Modifying RRsets in Slave zones is prohibited"})
            for rr in json.loads(request.content)["rrsets"]:
                key = (rr["name"], rr["type"])
                zone["rrsets"] = [r for r in zone["rrsets"] if (r["name"], r["type"]) != key]
                if rr["changetype"] == "REPLACE":
                    zone["rrsets"].append({k: v for k, v in rr.items() if k != "changetype"})
            return httpx.Response(204)
        return httpx.Response(400)

    def tsig(self, request, path):
        key_id = path.removeprefix("/tsigkeys").strip("/")
        if request.method == "POST" and not key_id:
            body = json.loads(request.content)
            kid = body["name"].rstrip(".") + "."
            if kid in self.tsigkeys:
                return httpx.Response(409)
            self.tsigkeys[kid] = {"id": kid, "name": body["name"], "algorithm": body["algorithm"], "key": body["key"]}
            return httpx.Response(201, json=self.tsigkeys[kid])
        key = self.tsigkeys.get(key_id)
        if request.method == "GET":
            return httpx.Response(404) if key is None else httpx.Response(200, json=key)
        if request.method == "PUT":
            if key is None:
                return httpx.Response(404)
            key.update({k: v for k, v in json.loads(request.content).items() if k in ("algorithm", "key")})
            return httpx.Response(200, json=key)
        if request.method == "DELETE":
            self.tsigkeys.pop(key_id, None)
            return httpx.Response(204)
        return httpx.Response(400)

    def cryptokeys(self, request, path):
        zone_name, _, rest = path.removeprefix("/zones/").partition("/cryptokeys")
        zone = self.zones.get(zone_name)
        if zone is None:
            return httpx.Response(404)
        keys = zone.setdefault("keys", [])
        key_id = rest.strip("/")
        if request.method == "GET" and not key_id:
            return httpx.Response(200, json=[{k: v for k, v in key.items() if k != "privatekey"} for key in keys])
        if request.method == "GET":
            key = next((k for k in keys if str(k["id"]) == key_id), None)
            return httpx.Response(404) if key is None else httpx.Response(200, json=key)
        if request.method == "POST":
            body = json.loads(request.content)
            priv = body.get("privatekey") or f"PRIVATE-{len(self.zones)}-{zone_name}"
            key = {"id": len(keys) + 1, "active": True, "privatekey": priv,
                   "dnskey": f"257 3 13 {priv}",
                   "ds": [f"4242 13 1 SHA1{priv}", f"4242 13 2 SHA256{priv}"]}
            keys.append(key)
            return httpx.Response(201, json=key)
        if request.method == "DELETE":
            zone["keys"] = [k for k in keys if str(k["id"]) != key_id]
            return httpx.Response(204)
        return httpx.Response(400)

    def rrset(self, zone: str, name: str, rtype: str):
        for rr in self.zones[zone]["rrsets"]:
            if rr["name"] == name and rr["type"] == rtype:
                return rr
        return None


@pytest.fixture(autouse=True)
def _no_outbound_dns(monkeypatch):
    """No real DNS from the controller code under test: the origin guard / SSRF guard resolver
    (netguard.resolver) knows only localhost (tests that need names use `fake_dns`), and the NS
    check's parent-delegation walk (nscheck.parent_delegation) reports "could not be checked"."""
    import socket

    from app import netguard, nscheck

    def resolve(host, port):
        if host == "localhost" or host.endswith(".localhost"):
            return ["127.0.0.1"]
        raise socket.gaierror(-2, "Name or service not known")

    monkeypatch.setattr(netguard, "resolver", resolve)
    monkeypatch.setattr(nscheck, "parent_delegation", lambda domain: None)


@pytest.fixture()
def fake_pdns():
    fake = FakePdns()
    pdns.set_client(pdns.PdnsClient("http://pdns", "k", "localhost", transport=httpx.MockTransport(fake.handler)))
    yield fake
    pdns.set_client(None)


@pytest.fixture()
def client(fake_pdns):
    from app import routes_ops

    routes_ops._cache["body"] = None  # /healthz/deep caches its answer for a few seconds
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as c:
        c.headers["Authorization"] = "Bearer test-admin-key"
        yield c


# ---------------------------------------------------------------- PostgreSQL (optional)
#
# Tests marked with the `pg_url` fixture run against a real PostgreSQL server when
# PCDN_TEST_PG_URL is set (CI sets it; locally e.g.
# PCDN_TEST_PG_URL=postgresql+psycopg://pcdn:pcdn@127.0.0.1:5432/postgres). Every test gets
# a fresh database that is dropped afterwards; the role needs CREATEDB.

PG_URL = os.environ.get("PCDN_TEST_PG_URL", "")


@pytest.fixture()
def pg_url():
    if not PG_URL:
        pytest.skip("PCDN_TEST_PG_URL not set")
    import uuid

    from sqlalchemy import create_engine, text
    from sqlalchemy.engine import make_url

    name = "pcdn_t_" + uuid.uuid4().hex[:10]
    admin = create_engine(PG_URL, isolation_level="AUTOCOMMIT")
    with admin.connect() as c:
        c.execute(text(f'CREATE DATABASE "{name}"'))
    url = make_url(PG_URL).set(database=name).render_as_string(hide_password=False)
    yield url
    with admin.connect() as c:
        c.execute(text(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = :n AND pid <> pg_backend_pid()"
        ), {"n": name})
        c.execute(text(f'DROP DATABASE IF EXISTS "{name}"'))
    admin.dispose()


@pytest.fixture()
def s3_server():
    """A local moto S3 server with bucket `pcdn` (region ir-thr-at1); backups and log export."""
    moto_server = pytest.importorskip("moto.server")
    import boto3

    server = moto_server.ThreadedMotoServer(ip_address="127.0.0.1", port=0, verbose=False)
    server.start()
    host, port = server.get_host_and_port()
    endpoint = f"http://{host}:{port}"
    # moto keeps its state per process: start every test from an empty S3
    httpx.post(f"{endpoint}/moto-api/reset", trust_env=False)
    boto3.client("s3", endpoint_url=endpoint, aws_access_key_id="AK", aws_secret_access_key="SK",
                 region_name="ir-thr-at1").create_bucket(
        Bucket="pcdn", CreateBucketConfiguration={"LocationConstraint": "ir-thr-at1"})
    yield endpoint
    server.stop()


# ---------------------------------------------------------------- analytics & platform (SPEC §14.3)

@pytest.fixture()
def fake_dns(monkeypatch):
    """The SSRF guard's resolver (app.netguard.resolver, its test-only injection point) -> a mutable
    table (tests may change it, e.g. to simulate DNS rebinding); unknown names do not resolve."""
    import socket

    from app import netguard
    from tests.platform_helpers import FAKE_DNS

    table = {k: list(v) for k, v in FAKE_DNS.items()}

    def resolve(host, port):
        if host in table:
            return list(table[host])
        raise socket.gaierror(-2, "Name or service not known")

    monkeypatch.setattr(netguard, "resolver", resolve)
    return table


@pytest.fixture()
def local_vet(monkeypatch):
    """Test-only guard hook (app.netguard.vet): URLs on LOCAL_HOST / 127.0.0.1 (any scheme) are
    'vetted' to 127.0.0.1, so the real code path (PinnedTransport, signing, no redirects, S3 SigV4)
    runs against a local server; every other URL still goes through the real guard."""
    from app import netguard
    from tests.platform_helpers import LOCAL_HOST

    real = netguard.default_vet

    def vet(url):
        u = httpx.URL(url)
        host = u.raw_host.decode()
        if host in (LOCAL_HOST, "127.0.0.1"):
            port = u.port or (443 if u.scheme == "https" else 80)
            return netguard.Target(url=url, scheme=u.scheme, host=host, port=port, ips=["127.0.0.1"])
        return real(url)

    monkeypatch.setattr(netguard, "vet", vet)


@pytest.fixture()
def receiver():
    """A local HTTP endpoint (tests.platform_helpers.Receiver) recording every request."""
    from tests.platform_helpers import Receiver

    r = Receiver()
    yield r
    r.close()


@pytest.fixture()
def alert_settings(monkeypatch):
    """Reset alert channel settings (tests opt into the channels they need)."""
    from app import alerts
    from app.config import settings

    for k, v in {"telegram_bot_token": "", "telegram_chat_ids": [], "smtp_host": "", "alert_emails": [],
                 "telegram_api_url": "https://api.telegram.org", "alert_reminder_hours": 6.0}.items():
        monkeypatch.setattr(settings, k, v)
    monkeypatch.setattr(alerts, "telegram_transport", None)
    return settings
