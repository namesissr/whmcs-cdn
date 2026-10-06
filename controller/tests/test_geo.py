"""GeoDNS self-test (app/geocheck.py) against tiny in-process DNS servers."""

import ipaddress
import socket
import threading

import dns.edns
import dns.message
import dns.rrset
import pytest

from app import alerts, geocheck, scheduler
from app.config import settings
from app.db import SessionLocal
from app.models import Edge, Record, Site, utcnow

IR = ipaddress.ip_network("2.176.0.0/12")


class FakeNameserver(threading.Thread):
    """Answers _pcdn-geo TXT like the generated LUA record does.

    geo=False behaves like a PowerDNS without the geoip backend (country '--').
    """

    def __init__(self, geo=True):
        super().__init__(daemon=True)
        self.geo = geo
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.stop = False

    def run(self):
        self.sock.settimeout(0.2)
        while not self.stop:
            try:
                data, addr = self.sock.recvfrom(4096)
            except OSError:
                continue
            q = dns.message.from_wire(data)
            ecs = next((o for o in q.options if isinstance(o, dns.edns.ECSOption)), None)
            ip = ecs.address if ecs else addr[0]
            country = "--"
            if self.geo:
                country = "ir" if ipaddress.ip_address(ip) in IR else "us"
            pool = "home" if country in ("ir", "--") else "global"
            r = dns.message.make_response(q)
            txt = f'"ip={ip} ecs={"yes" if ecs else "no"} resolver={addr[0]} country={country} pool={pool}"'
            r.answer.append(dns.rrset.from_text(q.question[0].name, 5, "IN", "TXT", txt))
            self.sock.sendto(r.to_wire(), addr)


@pytest.fixture()
def nameservers(monkeypatch):
    servers = []

    def make(*modes):
        for geo in modes:
            s = FakeNameserver(geo)
            s.start()
            servers.append(s)
        monkeypatch.setattr(settings, "pdns_dns_addrs", [f"127.0.0.1:{s.port}" for s in servers])
        return servers

    yield make
    for s in servers:
        s.stop = True


def _site_and_edges(regions=("home", "global")):
    db = SessionLocal()
    site = Site(domain="geo.example", status="active")
    db.add(site)
    db.flush()
    db.add(Record(site_id=site.id, name="www", type="A", content="192.0.2.1", proxied=True, ttl=300))
    for i, region in enumerate(regions):
        db.add(Edge(name=f"e{i}", ipv4=f"198.51.100.{i + 1}", region=region, enabled=True,
                    last_seen_at=utcnow(), token_hash=f"h{i}"))
    db.commit()
    db.close()


def test_as_subnet():
    assert geocheck.as_subnet("5.120.10.7") == "5.120.10.0/24"
    assert geocheck.as_subnet("2a00:1ce0::5") == "2a00:1ce0::/48"
    assert geocheck.as_subnet("5.120.0.0/16") == "5.120.0.0/16"


def test_targets_default_to_pdns_api_hosts(monkeypatch):
    monkeypatch.setattr(settings, "pdns_dns_addrs", [])
    monkeypatch.setattr(settings, "pdns_api_url", "http://127.0.0.1:8081, http://[::1]:8081")
    assert geocheck.dns_targets() == [("ns1 (127.0.0.1)", "127.0.0.1", 53), ("ns2 (::1)", "::1", 53)]


def test_all_nameservers_ok(client, nameservers, monkeypatch):
    monkeypatch.setattr(settings, "geoip_enabled", True)
    _site_and_edges()
    nameservers(True, True)
    with SessionLocal() as db:
        report = geocheck.check(db, extra_subnets=["2.180.1.1"])
    assert report["domain"] == "geo.example" and not report["problems"]
    assert [s["ok"] for s in report["servers"]] == [True, True]
    ans = report["servers"][0]["answers"]
    assert ans["home"]["country"] == "ir" and ans["home"]["pool"] == "home"
    assert ans["foreign"]["pool"] == "global" and ans["2.180.1.0/24"]["pool"] == "home"


def test_nameserver_without_geoip_is_reported_and_alerted(client, nameservers, monkeypatch, alert_settings):
    monkeypatch.setattr(settings, "geoip_enabled", True)
    _site_and_edges()
    nameservers(True, False)
    with SessionLocal() as db:
        scheduler.job_geo(db, force=True)
        report = geocheck.last_report(db)
    assert report["servers"][1]["ok"] is False
    assert any("geoip backend" in p for p in report["problems"])
    assert any("disagree" in p for p in report["problems"])
    keys = {c["key"] for c in alerts.open_alerts()}
    assert "geo:check" in keys
    # fixed: the alert resolves on the next check
    monkeypatch.setattr(settings, "pdns_dns_addrs", settings.pdns_dns_addrs[:1])
    with SessionLocal() as db:
        scheduler.job_geo(db, force=True)
    assert "geo:check" not in {c["key"] for c in alerts.open_alerts()}


def test_geoip_off_with_home_and_global_edges_is_alerted(client, nameservers, monkeypatch, alert_settings):
    monkeypatch.setattr(settings, "geoip_enabled", False)
    _site_and_edges()
    nameservers(True)
    with SessionLocal() as db:
        scheduler.job_geo(db, force=True)
    assert "geo:off" in {c["key"] for c in alerts.open_alerts()}
    body = client.get("/healthz/deep").json()
    assert body["geodns"]["enabled"] is False
    assert any("GEOIP_ENABLED is off" in w for w in body["warnings"])


def test_geo_check_is_throttled(client, nameservers, monkeypatch, alert_settings):
    monkeypatch.setattr(settings, "geoip_enabled", True)
    _site_and_edges(("home",))
    nameservers(True)
    calls = []
    real = geocheck.check
    monkeypatch.setattr(geocheck, "check", lambda db, *a, **k: calls.append(1) or real(db, *a, **k))
    with SessionLocal() as db:
        scheduler.job_geo(db)
        scheduler.job_geo(db)
    assert len(calls) == 1


def test_changing_geo_settings_rewrites_zones(client, fake_pdns, monkeypatch):
    _site_and_edges()
    with SessionLocal() as db:
        site = db.query(Site).one()
        fake_pdns.zones["geo.example."] = {"name": "geo.example.", "rrsets": []}
        scheduler.job_edges(db)
        first = fake_pdns.rrset("geo.example.", "www.geo.example.", "LUA")["records"][0]["content"]
        assert "countryCode" not in first
        monkeypatch.setattr(settings, "geoip_enabled", True)
        scheduler.job_edges(db)
        second = fake_pdns.rrset("geo.example.", "www.geo.example.", "LUA")["records"][0]["content"]
        assert "countryCode" in second and site.domain == "geo.example"
