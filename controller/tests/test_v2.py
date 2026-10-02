import subprocess
from datetime import datetime, timezone

import httpx

from app import pdns
from app.db import SessionLocal
from app.routes_v2 import prune_events
from tests.conftest import FakePdns
from tests.test_api import add_edge, edge_get

S = "/api/v1/sites/example.com"


def site(client, **plan):
    r = client.post("/api/v1/sites", json={"domain": "example.com", "origin_ip": "93.184.216.34",
                                           "plan": plan})
    assert r.status_code == 201, r.text
    return r.json()


def test_sections_defaults_and_roundtrip(client):
    s = site(client)
    assert s["plan"]["features"]["max_page_rules"] == 10
    assert set(s["config"]) == {"cache", "ssl", "waf", "ddos", "firewall", "ratelimit", "pagerules", "pools",
                                "headers", "hotlink", "image", "errorpages", "tunnel",
                                "transform", "redirects", "bots", "logs", "webhooks",
                                "l4", "video", "dns_secondary", "functions", "waiting_room", "access"}
    assert s["config"]["cache"]["level"] == "standard"

    fw = {"default_action": "allow", "rules": [
        {"id": "r1", "name": "no cn", "action": "block",
         "conditions": [{"field": "country", "op": "in", "value": ["cn", "ru"]},
                        {"field": "ip", "op": "not_in", "value": ["1.2.3.4", "10.0.0.0/8"]}]},
        {"id": "r2", "action": "challenge",
         "conditions": [{"field": "header", "name": "X-Bot", "op": "contains", "value": "scan"}]},
    ]}
    r = client.put(f"{S}/config/firewall", json=fw)
    assert r.status_code == 200, r.text
    conds = r.json()["rules"][0]["conditions"]
    assert conds[0]["value"] == ["CN", "RU"] and conds[1]["value"] == ["1.2.3.4/32", "10.0.0.0/8"]
    assert client.get(f"{S}/config/firewall").json() == r.json()
    assert client.get(S).json()["config"]["firewall"] == r.json()


def test_section_validation_errors(client):
    site(client)
    bad = [
        ("firewall", {"rules": [{"id": "x", "action": "block",
                                 "conditions": [{"field": "country", "op": "in", "value": ["IRAN"]}]}]}),
        ("firewall", {"rules": [{"id": "x", "action": "block",
                                 "conditions": [{"field": "path", "op": "regex", "value": "("}]}]}),
        ("firewall", {"rules": [{"id": "Bad Id", "action": "block",
                                 "conditions": [{"field": "path", "op": "eq", "value": "/"}]}]}),
        ("headers", {"request": [{"name": "Host", "value": "evil"}]}),
        ("headers", {"response": [{"name": "X-A", "value": 'a"b'}]}),
        ("pagerules", {"rules": [{"id": "p", "pattern": "no-slash"}]}),
        ("pagerules", {"rules": [{"id": "p", "pattern": "/x", "redirect": {"url": "javascript:alert(1)"}}]}),
        ("cache", {"edge_ttl": 5}),
        ("cache", {"unknown": 1}),
        ("ssl", {"hsts": {"enabled": True, "preload": True}}),
        ("pools", {"pools": [{"name": "a", "origins": [{"address": "10.0.0.1"}]}]}),
        ("hotlink", {"allowed_referers": ["bad domain"]}),
    ]
    for section, body in bad:
        r = client.put(f"{S}/config/{section}", json=body)
        assert r.status_code == 422, (section, body, r.text)
    assert client.put(f"{S}/config/nope", json={}).status_code == 404


def test_plan_gates_and_limits(client):
    site(client, features={"waf": False, "max_page_rules": 1, "load_balancer": False})
    assert client.put(f"{S}/config/waf", json={"mode": "block"}).status_code == 403
    assert client.put(f"{S}/config/waf", json={"mode": "off"}).status_code == 200  # turning off always allowed
    two = {"rules": [{"id": "a", "pattern": "/a*", "cache": "bypass"}, {"id": "b", "pattern": "/b*"}]}
    assert client.put(f"{S}/config/pagerules", json=two).status_code == 403
    pools = {"pools": [{"name": "main", "origins": [{"address": "185.1.2.3"}]}]}
    assert client.put(f"{S}/config/pools", json=pools).status_code == 403
    assert client.patch(f"{S}/plan", json={"features": {"bogus": True}}).status_code == 422
    r = client.patch(f"{S}/plan", json={"features": {"waf": True, "load_balancer": True}})
    assert r.json()["plan"]["features"]["waf"] is True
    assert r.json()["plan"]["features"]["max_page_rules"] == 1  # untouched keys kept
    assert client.put(f"{S}/config/waf", json={"mode": "block", "paranoia": 2}).status_code == 200


def test_pools_records_and_edge_config(client):
    site(client)
    pools = {"pools": [{"name": "main", "method": "ip_hash", "origins": [
        {"address": "185.1.2.3", "port": 8080, "weight": 5},
        {"address": "Origin2.Example.net", "port": 80, "backup": True},
        {"address": "2a01:4f8::5", "port": 443}]}]}
    r = client.put(f"{S}/config/pools", json=pools)
    assert r.status_code == 200, r.text
    assert [o["address"] for o in r.json()["pools"][0]["origins"]] == ["185.1.2.3", "origin2.example.net",
                                                                       "[2a01:4f8::5]"]
    # a record can use a defined pool only
    assert client.post(f"{S}/records", json={"name": "api", "type": "A", "content": "185.1.2.3",
                                             "proxied": True, "pool": "nope"}).status_code == 422
    rec = client.post(f"{S}/records", json={"name": "api", "type": "A", "content": "185.1.2.3",
                                            "proxied": True, "pool": "main"}).json()
    assert rec["pool"] == "main"
    port = client.post(f"{S}/records", json={"name": "app", "type": "A", "content": "185.1.2.9",
                                             "proxied": True, "origin_port": 8443}).json()
    assert port["origin_port"] == 8443
    # pool in use cannot be removed
    assert client.put(f"{S}/config/pools", json={"pools": []}).status_code == 422

    client.put(f"{S}/config/waf", json={"mode": "block"})
    client.patch(f"{S}/settings", json={"dev_mode": True, "force_https": True})
    token = add_edge(client)
    assert client.get(S).json()["edge_ips"] == ["5.160.1.10"]
    cfg = edge_get(client, token, "/edge/v1/config").json()["sites"][0]
    hosts = {h["name"]: h["origin"] for h in cfg["hosts"]}
    assert hosts["api.example.com"] == {"pool": "main"}
    assert hosts["app.example.com"] == {"address": "185.1.2.9", "port": 8443}
    assert cfg["cache"]["enabled"] is False and cfg["cache"]["dev_mode"] is True
    assert cfg["ssl_options"]["force_https"] is False  # no certificate yet
    assert cfg["waf"]["mode"] == "block" and len(cfg["secret"]) == 64
    assert cfg["pools"]["pools"][0]["method"] == "ip_hash"

    # plan downgrade: feature disappears from the edge config without touching stored data
    client.patch(f"{S}/plan", json={"features": {"waf": False, "load_balancer": False}})
    cfg = edge_get(client, token, "/edge/v1/config").json()["sites"][0]
    assert cfg["waf"]["mode"] == "off" and cfg["pools"] == {"pools": []}
    assert "api.example.com" not in {h["name"] for h in cfg["hosts"]}
    assert client.get(f"{S}/config/waf").json()["mode"] == "block"


def test_legacy_settings_map_to_sections(client):
    site(client)
    r = client.patch(f"{S}/settings", json={"cache_enabled": False, "edge_cache_ttl": 3600,
                                            "origin_protocol": "https"})
    body = r.json()
    assert body["config"]["cache"]["enabled"] is False and body["config"]["cache"]["edge_ttl"] == 3600
    assert body["config"]["ssl"]["origin_protocol"] == "https"
    assert body["settings"]["cache_enabled"] is False


def test_alias_and_health_checked_records(client, fake_pdns):
    site(client)
    assert client.post(f"{S}/records", json={"name": "@", "type": "ALIAS", "content": "lb.host.net"}).status_code \
        == 422  # conflicts with the proxied @ A record
    client.delete(f"{S}/records/1")
    assert client.post(f"{S}/records", json={"name": "@", "type": "ALIAS", "content": "lb.host.net"}).status_code \
        == 201
    for ip in ("185.1.1.1", "185.1.1.2"):
        client.post(f"{S}/records", json={"name": "mail", "type": "A", "content": ip,
                                          "health_check": True, "health_port": 25})
    assert fake_pdns.rrset("example.com.", "example.com.", "ALIAS")["records"][0]["content"] == "lb.host.net."
    lua = fake_pdns.rrset("example.com.", "mail.example.com.", "LUA")["records"][0]["content"]
    assert lua.startswith('A "ifportup(25, {\'185.1.1.1\',\'185.1.1.2\'}')
    assert fake_pdns.rrset("example.com.", "mail.example.com.", "A") is None


def test_zone_import_export(client):
    site(client)
    zone = """$TTL 3600
@   IN SOA ns1.old.com. host.old.com. 1 2 3 4 5
@   IN NS  ns1.old.com.
@   IN MX  10 mail.example.com.
mail  300 IN A 185.10.10.10
blog  IN CNAME example.wordpress.com.
@   IN TXT "v=spf1 include:_spf.google.com ~all"
_sip._tcp IN SRV 10 5 5060 sip.example.com.
@   IN CAA 0 issue "letsencrypt.org"
lan IN A 192.168.1.1
old IN HINFO "x" "y"
"""
    r = client.post(f"{S}/records/import", json={"zone": zone})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["imported"] == 6
    reasons = " ".join(s["reason"] for s in body["skipped"])
    assert "عمومی" in reasons and len(body["skipped"]) == 4  # SOA, NS, private IP, HINFO
    types = {(x["name"], x["type"]) for x in client.get(f"{S}/records").json()}
    assert ("_sip._tcp", "SRV") in types and ("blog", "CNAME") in types
    again = client.post(f"{S}/records/import", json={"zone": zone}).json()
    assert again["imported"] == 0

    out = client.get(f"{S}/records/export").json()["zone"]
    assert "mail\t300\tIN\tA\t185.10.10.10" in out and "; cdn-proxied" in out
    assert "_sip._tcp\t3600\tIN\tSRV\t10 5 5060 sip.example.com." in out
    assert client.post(f"{S}/records/import", json={"zone": "@ IN A"}).status_code == 422

    r = client.post(f"{S}/records/import", json={"zone": "www 60 IN A 185.1.1.1\n", "replace": True})
    assert r.json()["imported"] == 1 and len(client.get(f"{S}/records").json()) == 1


def test_dnssec_same_key_on_all_servers(client, fake_pdns):
    second = FakePdns()
    pdns.set_client(pdns.PdnsCluster([
        pdns.PdnsClient("http://a", "k", "localhost", transport=httpx.MockTransport(fake_pdns.handler)),
        pdns.PdnsClient("http://b", "k", "localhost", transport=httpx.MockTransport(second.handler)),
    ]))
    site(client)
    r = client.post(f"{S}/dnssec", json={"enabled": True})
    assert r.status_code == 200, r.text
    assert r.json()["enabled"] and r.json()["ds"] and all(" 2 " in d for d in r.json()["ds"])
    k1 = fake_pdns.zones["example.com."]["keys"][0]["privatekey"]
    assert [k["privatekey"] for k in second.zones["example.com."]["keys"]] == [k1]
    assert client.get(f"{S}/dnssec").json()["ds"] == r.json()["ds"]
    assert client.get(S).json()["dnssec"] is True
    client.post(f"{S}/dnssec", json={"enabled": False})
    assert second.zones["example.com."]["keys"] == [] and client.get(f"{S}/dnssec").json()["enabled"] is False
    client.patch(f"{S}/plan", json={"features": {"dnssec": False}})
    assert client.post(f"{S}/dnssec", json={"enabled": True}).status_code == 403


def _cert(tmp_path, cn, days=30):
    key, crt = tmp_path / f"{cn}.key", tmp_path / f"{cn}.crt"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                    "-nodes", "-subj", f"/CN={cn}", "-addext", f"subjectAltName=DNS:{cn},DNS:*.{cn}",
                    "-days", str(days), "-keyout", key, "-out", crt], check=True, capture_output=True)
    return crt.read_text(), key.read_text()


def test_custom_ssl(client, tmp_path):
    site(client)
    cert, key = _cert(tmp_path, "example.com")
    other_cert, other_key = _cert(tmp_path, "other.org")
    assert client.put(f"{S}/ssl/custom", json={"cert": other_cert, "key": other_key}).status_code == 422
    assert client.put(f"{S}/ssl/custom", json={"cert": cert, "key": other_key}).status_code == 422
    assert client.put(f"{S}/ssl/custom", json={"cert": "junk", "key": "junk"}).status_code == 422
    r = client.put(f"{S}/ssl/custom", json={"cert": cert, "key": key})
    assert r.status_code == 200, r.text
    assert r.json()["source"] == "custom" and r.json()["names"] == ["example.com", "*.example.com"]
    assert client.post(f"{S}/ssl").status_code == 409  # LE request blocked while custom cert active

    token = add_edge(client)
    assert edge_get(client, token, "/edge/v1/config").json()["sites"][0]["ssl"]["cert"].startswith("-----BEGIN")
    assert client.delete(f"{S}/ssl/custom").json()["status"] == "none"  # NS not verified -> nothing to issue
    client.patch(f"{S}/plan", json={"features": {"custom_ssl": False}})
    assert client.put(f"{S}/ssl/custom", json={"cert": cert, "key": key}).status_code == 403


def test_analytics_and_events(client):
    site(client)
    token = add_edge(client)
    now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    payload = {
        "items": [
            {"host": "example.com", "hour": now.isoformat(), "bytes": 1000, "requests": 10, "cache_hits": 6,
             "status": {"2xx": 8, "4xx": 2}, "codes": {"200": 8, "403": 2}, "countries": {"IR": 9, "DE": 1},
             "paths": {"/": 7, "/a.css": 3}, "security": {"waf": 2}},
            {"host": "www.example.com", "hour": now.isoformat(), "bytes": 500, "requests": 5,
             "countries": {"IR": 5}, "paths": {"/": 5}},
        ],
        "events": [{"t": now.isoformat(), "host": "example.com", "ip": "5.5.5.5", "country": "ir",
                    "method": "GET", "path": "/?id=1'", "action": "block", "source": "waf", "rule": "942100",
                    "user_agent": "sqlmap"},
                   {"t": now.isoformat(), "host": "nothere.org", "action": "block", "source": "waf"}],
    }
    auth = {"Authorization": f"Bearer {token}"}
    r = client.post("/edge/v1/usage", json=payload, headers=auth)
    assert r.json()["events"] == 1
    client.post("/edge/v1/usage", json={"items": payload["items"][:1]}, headers=auth)  # merge into same hour

    a = client.get(f"{S}/analytics?period=24h").json()
    assert a["totals"]["requests"] == 25 and a["totals"]["cache_hits"] == 12
    assert a["totals"]["status"]["4xx"] == 4 and a["totals"]["security"]["waf"] == 4
    assert a["countries"][0] == {"code": "IR", "requests": 23}
    assert a["paths"][0] == {"path": "/", "requests": 19}
    assert a["status_codes"][0] == {"code": 200, "requests": 16}
    assert len(a["series"]) == 24 and a["series"][-1]["requests"] == 25
    assert len(client.get(f"{S}/analytics?period=7d").json()["series"]) in (7, 8)
    assert client.get(f"{S}/analytics?period=1y").status_code == 422

    ev = client.get(f"{S}/events").json()
    assert len(ev) == 1 and ev[0]["country"] == "IR" and ev[0]["rule"] == "942100"
    with SessionLocal() as db:
        prune_events(db, keep=0)
        db.commit()
    assert client.get(f"{S}/events").json() == []


def test_platform_analytics(client):
    site(client)
    client.post("/api/v1/sites", json={"domain": "other.org"})
    token = add_edge(client)
    now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    client.post("/edge/v1/usage", headers={"Authorization": f"Bearer {token}"}, json={
        "items": [
            {"host": "example.com", "hour": now.isoformat(), "bytes": 1000, "requests": 10, "cache_hits": 6,
             "status": {"2xx": 8, "4xx": 2}, "countries": {"IR": 9, "DE": 1}, "security": {"waf": 2}},
            {"host": "other.org", "hour": now.isoformat(), "bytes": 500, "requests": 5, "cache_hits": 1,
             "countries": {"IR": 5}, "security": {"firewall": 3, "ratelimit": 1}},
        ]})
    a = client.get("/api/v1/analytics?period=24h").json()
    assert a["period"] == "24h"
    assert a["totals"]["requests"] == 15 and a["totals"]["bytes"] == 1500 and a["totals"]["cache_hits"] == 7
    assert a["totals"]["status"]["2xx"] == 8 and a["totals"]["status"]["4xx"] == 2
    assert a["totals"]["security"] == {"waf": 2, "firewall": 3, "ratelimit": 1, "challenge": 0, "ddos": 0,
                                       "hotlink": 0, "bots": 0}
    assert a["countries"][0] == {"code": "IR", "requests": 14}
    assert a["sites"][0] == {"domain": "example.com", "requests": 10, "bytes": 1000}
    assert {s["domain"] for s in a["sites"]} == {"example.com", "other.org"}
    assert len(a["series"]) == 24 and a["series"][-1]["requests"] == 15
    assert len(a["security_series"]) == 24 and a["security_series"][-1]["events"] == 6
    assert sum(b["events"] for b in a["security_series"]) == 6
    assert len(client.get("/api/v1/analytics?period=7d").json()["security_series"]) in (7, 8)
    assert client.get("/api/v1/analytics?period=1y").status_code == 422
    assert client.get("/api/v1/analytics", headers={"Authorization": "Bearer x"}).status_code == 401


def test_platform_overview_and_events(client):
    site(client)
    client.post("/api/v1/sites", json={"domain": "other.org"})
    token = add_edge(client)
    add_edge(client, "de-1", "88.99.1.10", "global")
    edge_get(client, token, "/edge/v1/config")  # first edge checks in -> online
    now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    client.post("/edge/v1/usage", headers={"Authorization": f"Bearer {token}"}, json={
        "items": [{"host": "example.com", "hour": now.isoformat(), "bytes": 5000, "requests": 50,
                   "security": {"waf": 3}},
                  {"host": "other.org", "hour": now.isoformat(), "bytes": 100, "requests": 1}],
        "events": [{"t": now.isoformat(), "host": "example.com", "ip": "1.1.1.1", "action": "block",
                    "source": "waf", "rule": "942100"},
                   {"t": now.isoformat(), "host": "other.org", "ip": "2.2.2.2", "action": "block",
                    "source": "firewall", "rule": "r1"}]})
    o = client.get("/api/v1/overview").json()
    assert o["sites"] == {"total": 2, "by_status": {"pending_ns": 2}, "by_owner": {"client": 2}}
    assert {k: o["edges"][k] for k in ("total", "enabled", "online", "with_errors", "shed")} == \
        {"total": 2, "enabled": 2, "online": 1, "with_errors": 0, "shed": 0}
    assert len(o["edges"]["list"]) == 2 and all("uptime" in e for e in o["edges"]["list"])
    assert o["month"]["bytes"] == 5100 and o["month"]["security"] == {"waf": 3}
    assert o["top_sites"][0] == {"domain": "example.com", "bytes": 5000, "requests": 50}
    ev = client.get("/api/v1/events").json()
    assert {e["domain"] for e in ev} == {"example.com", "other.org"}
    assert [e["domain"] for e in client.get("/api/v1/events?source=firewall").json()] == ["other.org"]
    assert client.get("/api/v1/overview", headers={"Authorization": "Bearer x"}).status_code == 401
