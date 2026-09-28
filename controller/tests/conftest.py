import json
import os
import tempfile

_tmp = tempfile.mkdtemp()
os.environ.update({
    "DATABASE_URL": f"sqlite:///{_tmp}/test.db",
    "ADMIN_API_KEY": "test-admin-key",
    "SCHEDULER_ENABLED": "false",
    "NAMESERVERS": "ns1.example-cdn.com,ns2.example-cdn.com",
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

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path.split("/api/v1/servers/localhost", 1)[1]
        if path == "/zones" and request.method == "POST":
            body = json.loads(request.content)
            self.zones[body["name"]] = {"name": body["name"], "rrsets": body["rrsets"]}
            return httpx.Response(201, json=self.zones[body["name"]])
        name = path.removeprefix("/zones/")
        zone = self.zones.get(name)
        if request.method == "GET":
            return httpx.Response(404) if zone is None else httpx.Response(200, json=zone)
        if request.method == "DELETE":
            self.zones.pop(name, None)
            return httpx.Response(204)
        if request.method == "PATCH":
            if zone is None:
                return httpx.Response(404)
            for rr in json.loads(request.content)["rrsets"]:
                key = (rr["name"], rr["type"])
                zone["rrsets"] = [r for r in zone["rrsets"] if (r["name"], r["type"]) != key]
                if rr["changetype"] == "REPLACE":
                    zone["rrsets"].append({k: v for k, v in rr.items() if k != "changetype"})
            return httpx.Response(204)
        return httpx.Response(400)

    def rrset(self, zone: str, name: str, rtype: str):
        for rr in self.zones[zone]["rrsets"]:
            if rr["name"] == name and rr["type"] == rtype:
                return rr
        return None


@pytest.fixture()
def fake_pdns():
    fake = FakePdns()
    pdns.set_client(pdns.PdnsClient("http://pdns", "k", "localhost", transport=httpx.MockTransport(fake.handler)))
    yield fake
    pdns.set_client(None)


@pytest.fixture()
def client(fake_pdns):
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as c:
        c.headers["Authorization"] = "Bearer test-admin-key"
        yield c
