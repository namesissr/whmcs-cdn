"""Security review wave 9 (docs/SECURITY.md): regression tests for the controller-side findings.

Every proof of concept of the review is here in its fail-safe form: the input it used to get
accepted is now refused (or neutralised), next to the legitimate cases that must keep working.
"""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import dns.message
import dns.rrset
import pytest
from sqlalchemy import select

from app import alerts, nscheck, origin_guard, pdns, psl, routes_capi, scheduler, sections, services, tenancy
from app.auth import hash_token, new_token
from app.config import settings
from app.db import SessionLocal
from app.models import ApiKey, Edge, Purge, Site, UsageHourly
from app.validation import ValidationError, validate_ip

CAPI = "/capi/v1"
REPO = Path(__file__).resolve().parents[2]
OURS = ["ns1.example-cdn.com", "ns2.example-cdn.com"]


def site(client, domain, status=201, **body):
    r = client.post("/api/v1/sites", json={"domain": domain, "origin_ip": "8.8.8.8", **body})
    assert r.status_code == status, r.text
    return r.json()


def key(client, domain, scopes):
    routes_capi._hits.clear()
    routes_capi._config_hits.clear()
    r = client.post(f"/api/v1/sites/{domain}/apikeys", json={"name": "k", "scopes": list(scopes)})
    assert r.status_code == 201, r.text
    return {"Authorization": f"Bearer {r.json()['key']}"}


def edge(name="e1", group="general", capacity_mbps=0, ipv4="9.9.9.9") -> str:
    tok = new_token()
    with SessionLocal() as db:
        db.add(Edge(name=name, ipv4=ipv4, token_hash=hash_token(tok), group=group, capacity_mbps=capacity_mbps))
        db.commit()
    return tok


def hour_iso(delta_hours=0):
    h = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0) + timedelta(hours=delta_hours)
    return h.isoformat()


# ================================================================== C1: sub-zone takeover

def test_c1_child_of_another_owners_site_is_refused(client, monkeypatch):
    """PoC: shop.victim.com by another customer used to be created (201) and verified."""
    site(client, "victim.com", client_id=1)
    r = client.post("/api/v1/sites", json={"domain": "shop.victim.com", "origin_ip": "1.1.1.1", "client_id": 2})
    assert r.status_code == 422 and "زیردامنه" in r.json()["detail"]
    # no owner at all (an admin / older WHMCS module): refused as well
    site(client, "shop.victim.com", status=422)
    site(client, "a.b.victim.com", status=422, client_id=2)  # any depth
    # and the other way round: the parent of an existing site of another owner
    site(client, "x.other.org", client_id=3)
    site(client, "other.org", status=422, client_id=4)
    # an exact duplicate stays 409 (WHMCS treats 409 as a re-run of its own Create)
    site(client, "victim.com", status=409, client_id=1)
    with SessionLocal() as db:
        assert {s.domain for s in db.scalars(select(Site))} == {"victim.com", "x.other.org"}


def test_c1_same_owner_may_nest(client):
    site(client, "example.com", client_id=7)
    child = site(client, "shop.example.com", client_id=7)
    assert child["client_id"] == 7
    # a reseller's sub-sites belong to the reseller (owner = reseller_client_id)
    site(client, "blog.example.com", reseller_client_id=7, reseller_label="end customer")
    site(client, "deep.shop.example.com", status=422, reseller_client_id=8)


def test_c1_public_suffixes_are_refused(client):
    for d in ("co.ir", "ac.ir", "gov.ir", "org.ir", "net.ir", "sch.ir", "id.ir", "co.uk", "com.au"):
        r = client.post("/api/v1/sites", json={"domain": d})
        assert r.status_code == 422, (d, r.text)
        assert "پسوند عمومی" in r.json()["detail"]
    site(client, "example.co.ir")
    assert psl.is_public_suffix("ir") and psl.is_public_suffix("xn--mgba3a4f16a.ir")  # ایران.ir
    assert psl.registrable("a.b.example.co.ir") == "example.co.ir"
    assert not psl.is_public_suffix("example.ir")


def test_c1_domain_check_endpoint_and_owner_patch(client):
    site(client, "victim.com", client_id=1)
    chk = lambda **b: client.post("/api/v1/domain-check", json=b).json()  # noqa: E731
    assert chk(domain="shop.victim.com", client_id=2)["code"] == "nested"
    assert chk(domain="shop.victim.com", client_id=1) == {"ok": True, "code": None, "error": None,
                                                          "domain": "shop.victim.com"}
    assert chk(domain="co.ir")["code"] == "public_suffix"
    assert chk(domain="victim.com", client_id=1)["code"] == "exists"
    assert chk(domain="bad domain")["code"] == "invalid"
    # the owner can be set on a site created without one; a change that would split a same-owner
    # parent/child pair is refused
    site(client, "shop.victim.com", client_id=1)
    r = client.patch("/api/v1/sites/shop.victim.com/owner", json={"client_id": 2})
    assert r.status_code == 422
    assert client.patch("/api/v1/sites/shop.victim.com/reseller", json={"reseller_client_id": 5}).status_code == 200
    assert client.patch("/api/v1/sites/victim.com/owner", json={"client_id": 1}).json()["client_id"] == 1


def _legacy_child(domain="shop.victim.com", parent="victim.com", parent_owner=1, child_owner=None):
    """A nested pair created before the C1 rule existed (inserted directly)."""
    with SessionLocal() as db:
        for d, owner in ((parent, parent_owner), (domain, child_owner)):
            if db.scalar(select(Site).where(Site.domain == d)) is None:
                db.add(Site(domain=d, client_id=owner))
        db.commit()


def test_c1_nscheck_refuses_a_legacy_foreign_child(client, monkeypatch):
    """PoC: with our NS answering for the child, ns-check used to flip it to active."""
    _legacy_child()
    monkeypatch.setattr(nscheck, "lookup_ns", lambda d: list(OURS))
    r = client.post("/api/v1/sites/shop.victim.com/ns-check").json()
    assert r["ok"] is False and r["status"] == "pending_ns" and r["reason"] == "parent_site:victim.com"
    # the parent itself is unaffected
    assert client.post("/api/v1/sites/victim.com/ns-check").json()["ok"] is True
    # the security audit job alerts on the legacy pair
    monkeypatch.setattr(alerts, "raise_alert", lambda k, t, x, s="warning": raised.append(k))
    raised = []
    with SessionLocal() as db:
        out = scheduler.job_security_audit(db, force=True)
    assert out["nested"] == [("victim.com", "shop.victim.com")] and "nested_sites" in raised


def test_c1_nscheck_parent_delegation(client, monkeypatch):
    site(client, "example.com", client_id=1)
    site(client, "shop.example.com", client_id=1)
    site(client, "stranger.net")
    monkeypatch.setattr(nscheck, "lookup_ns", lambda d: list(OURS))
    walk = {}
    monkeypatch.setattr(nscheck, "parent_delegation", lambda d: walk.get(d))
    # the registered parent delegates exactly this name to us -> active
    walk["stranger.net"] = ("stranger.net", OURS)
    assert client.post("/api/v1/sites/stranger.net/ns-check").json()["ok"] is True
    # delegated through our own zone of the SAME owner (example.com) -> accepted
    walk["shop.example.com"] = ("example.com", OURS)
    assert client.post("/api/v1/sites/shop.example.com/ns-check").json()["ok"] is True
    # the parent delegates to someone else (only a resolver cache / our own answer says "ours")
    site(client, "late.org")
    walk["late.org"] = ("late.org", ["ns1.elsewhere.net"])
    r = client.post("/api/v1/sites/late.org/ns-check").json()
    assert r["ok"] is False and r["reason"] == "parent_delegation"
    # a referral reaching our nameservers for a parent that is not a same-owner site
    site(client, "sub.unrelated.io")
    walk["sub.unrelated.io"] = ("unrelated.io", OURS)
    r = client.post("/api/v1/sites/sub.unrelated.io/ns-check").json()
    assert r["ok"] is False and r["reason"] == "parent_site:unrelated.io"
    # parent servers unreachable (None): the recursive answer + the parent-site rule decide
    site(client, "offline.org")
    assert client.post("/api/v1/sites/offline.org/ns-check").json()["ok"] is True
    monkeypatch.setattr(settings, "ns_check_parent", False)
    walk["late.org"] = ("late.org", ["ns1.elsewhere.net"])
    assert client.post("/api/v1/sites/late.org/ns-check").json()["ok"] is True


def _referral(qname, owner, targets, glue=None, answer=False):
    q = dns.message.make_query(qname, "NS")
    resp = dns.message.make_response(q)
    rr = dns.rrset.from_text(owner + ".", 3600, "IN", "NS", *[t + "." for t in targets])
    (resp.answer if answer else resp.authority).append(rr)
    for name, ip in (glue or {}).items():
        resp.additional.append(dns.rrset.from_text(name + ".", 3600, "IN", "A", ip))
    return resp


def test_c1_parent_delegation_walk(monkeypatch):
    """The iterative walk (the real nscheck.parent_delegation, with a fake network)."""
    monkeypatch.undo()  # drop the autouse stub of parent_delegation: test the real one
    walk = nscheck.parent_delegation
    tld = "192.0.2.53"
    monkeypatch.setattr(nscheck, "lookup_ns", lambda d: {"com": ["a.gtld.tld-servers.net"]}.get(d, []))
    monkeypatch.setattr(nscheck, "server_addresses", lambda names, glue=None, limit=6: [
        (glue or {}).get(n, [tld])[0] for n in names][:limit])
    answers = {}

    def query(server, name):
        if (server, name) not in answers:
            raise TimeoutError("no answer")
        return answers[(server, name)]

    monkeypatch.setattr(nscheck, "query", query)
    # victim.com is delegated to us by .com; shop.victim.com has no delegation of its own in .com
    answers[(tld, "shop.victim.com")] = _referral("shop.victim.com", "victim.com", OURS)
    assert walk("shop.victim.com") == ("victim.com", OURS)
    answers[(tld, "victim.com")] = _referral("victim.com", "victim.com", OURS)
    assert walk("victim.com") == ("victim.com", OURS)
    # parent hosted elsewhere, delegating the sub-domain to us
    answers[(tld, "cdn.custom.com")] = _referral("cdn.custom.com", "custom.com", ["ns.dnshost.net"],
                                                 glue={"ns.dnshost.net": "198.51.100.53"})
    answers[("198.51.100.53", "cdn.custom.com")] = _referral("cdn.custom.com", "cdn.custom.com", OURS)
    assert walk("cdn.custom.com") == ("cdn.custom.com", OURS)
    # the parent serves the name itself (no zone cut): not delegated
    answers[(tld, "www.self.com")] = _referral("www.self.com", "self.com", ["ns.dnshost.net"],
                                               glue={"ns.dnshost.net": "198.51.100.54"})
    answers[("198.51.100.54", "www.self.com")] = dns.message.make_response(
        dns.message.make_query("www.self.com", "NS"))
    assert walk("www.self.com") == ("self.com", [])
    # unreachable parent servers: unknown; a public suffix has no parent to ask
    assert walk("down.com") is None
    assert walk("co.ir") is None


# ================================================================== H1: secondary DNS

def test_h1_dns_secondary_needs_the_plan_feature_and_slaves_get_lua_off(client, fake_pdns):
    """PoC: any customer could make its zone a Slave of its own primary with LUA enabled."""
    site(client, "attacker.com")
    h = key(client, "attacker.com", ["dns"])
    body = {"mode": "primary_elsewhere", "primaries": ["8.8.4.4"]}
    r = client.put(f"{CAPI}/config/dns_secondary", headers=h, json=body)
    assert r.status_code == 403
    assert fake_pdns.zones["attacker.com."]["kind"] == "Native"
    # the disabled shape is always writable
    routes_capi._config_hits.clear()
    assert client.put(f"{CAPI}/config/dns_secondary", headers=h, json={"mode": "off"}).status_code == 200
    # with the feature: a Slave zone, LUA records off for it
    client.patch("/api/v1/sites/attacker.com/plan", json={"features": {"dns_secondary": True}})
    routes_capi._config_hits.clear()
    r = client.put(f"{CAPI}/config/dns_secondary", headers=h, json=body)
    assert r.status_code == 200, r.text
    z = fake_pdns.zones["attacker.com."]
    assert z["kind"] == "Slave" and z["metadata"]["ENABLE-LUA-RECORDS"] == ["0"]
    # primaries must be public (CGNAT too)
    routes_capi._config_hits.clear()
    assert client.put(f"{CAPI}/config/dns_secondary", headers=h,
                      json={**body, "primaries": ["100.64.0.1"]}).status_code == 422


def test_h1_existing_slave_zone_gets_lua_off_on_sync(client, fake_pdns):
    """A zone made a slave by an older controller (no metadata) is fixed on the next sync; a zone
    turned back to Native gets LUA again only after the controller rewrote its records."""
    site(client, "old.com", plan={"features": {"dns_secondary": True}})
    with SessionLocal() as db:
        s = db.scalar(select(Site).where(Site.domain == "old.com"))
        s.config = json.dumps({"dns_secondary": {"mode": "primary_elsewhere", "primaries": ["8.8.4.4"]}})
        db.commit()
        z = fake_pdns.zones["old.com."]
        z.update(kind="Slave", masters=["8.8.4.4"], metadata={})
        assert services.sync_site_dns(db, s) is None
        assert z["metadata"]["ENABLE-LUA-RECORDS"] == ["0"]
        s.config = json.dumps({"dns_secondary": {"mode": "off"}})
        db.commit()
        assert services.sync_site_dns(db, s) is None
    assert z["kind"] == "Native" and "ENABLE-LUA-RECORDS" not in z["metadata"]
    assert any(rr["type"] == "NS" for rr in z["rrsets"])  # the controller's records are back


def test_h1_pdns_conf_and_compose():
    conf = (REPO / "dns" / "pdns.conf").read_text()
    allow = [ln for ln in conf.splitlines() if ln.startswith("webserver-allow-from=")]
    assert allow and "0.0.0.0/0" not in allow[0] and "::/0" not in allow[0]
    compose = (REPO / "docker-compose.yml").read_text()
    assert "--webserver-allow-from=${PDNS_API_ALLOW_FROM:-" in compose


# ================================================================== H2: regexes

def test_h2_firewall_regex_is_checked_like_redirects(client):
    """PoC: ^(a+)+$ was refused for redirects but accepted for firewall conditions."""
    site(client, "attacker.com")
    h = key(client, "attacker.com", ["config"])
    evil = "^(a+)+$"
    for v in (evil, "(a|aa)+$", "x" * 300, "(.*a){20}"):
        routes_capi._config_hits.clear()
        r = client.put(f"{CAPI}/config/firewall", headers=h, json={"rules": [
            {"id": "f1", "action": "log", "conditions": [{"field": "user_agent", "op": "regex", "value": v}]}]})
        assert r.status_code == 422, (v, r.text)
    routes_capi._config_hits.clear()
    ok = client.put(f"{CAPI}/config/firewall", headers=h, json={"rules": [
        {"id": "f1", "action": "block", "conditions": [{"field": "path", "op": "regex", "value": r"^/wp-(admin|login)"},
                                                       {"field": "header", "name": "X-A", "op": "regex",
                                                        "value": "bot[0-9]+"}]}]})
    assert ok.status_code == 200, ok.text


def test_h2_stored_unsafe_firewall_rule_is_not_sent_to_edges(client):
    """A rule stored before the check keeps parsing (no silent fallback to an empty firewall) but
    is left out of the edge config; the other rules stay."""
    site(client, "legacy.com")
    fw = {"default_action": "block", "rules": [
        {"id": "bad", "action": "allow", "conditions": [{"field": "user_agent", "op": "regex", "value": "^(a+)+$"}]},
        {"id": "good", "action": "allow", "conditions": [{"field": "country", "op": "in", "value": ["IR"]}]}]}
    with SessionLocal() as db:
        s = db.scalar(select(Site).where(Site.domain == "legacy.com"))
        s.config = json.dumps({"firewall": fw})
        db.commit()
        stored = sections.get_section(s, "firewall")
        assert stored["default_action"] == "block" and [r["id"] for r in stored["rules"]] == ["bad", "good"]
        cfg = services.build_edge_config(db)
    fwe = next(x for x in cfg["sites"] if x["domain"] == "legacy.com")["firewall"]
    assert fwe["default_action"] == "block" and [r["id"] for r in fwe["rules"]] == ["good"]


# ================================================================== M1: usage plausibility

def test_m1_forged_usage_is_dropped_and_alerted(client, monkeypatch):
    """PoC: a forged 10^15 bytes for victim.com was accepted (931,322 GB)."""
    site(client, "victim.com")
    client.patch("/api/v1/sites/victim.com/plan", json={"bandwidth_limit_gb": 100})
    raised = []
    monkeypatch.setattr(alerts, "raise_alert", lambda k, *a, **kw: raised.append(k))
    tok = edge("evil", capacity_mbps=1000)
    hdr = {"Authorization": f"Bearer {tok}"}
    r = client.post("/edge/v1/usage", headers=hdr,
                    json={"items": [{"host": "victim.com", "hour": hour_iso(), "bytes": 10**15, "requests": 1}]})
    assert r.status_code == 200 and r.json()["dropped"]["implausible"] == 1 and r.json()["accepted"] == 0
    s = client.get("/api/v1/sites/victim.com").json()
    assert s["status"] != "over_quota" and s["usage_month"]["bytes"] == 0
    assert raised and raised[0].startswith("usage_implausible:")
    # 1 Gbit/s x 1 h x 1.5 = 675 GB: a plausible report is applied, and the hour's running total counts
    good = 400 * 10**9
    r = client.post("/edge/v1/usage", headers=hdr,
                    json={"items": [{"host": "victim.com", "hour": hour_iso(), "bytes": good, "requests": 10}]})
    assert r.json()["accepted"] == 1
    r = client.post("/edge/v1/usage", headers=hdr,
                    json={"items": [{"host": "victim.com", "hour": hour_iso(), "bytes": good, "requests": 10}]})
    assert r.json()["dropped"]["implausible"] == 1
    # future and too-old hours
    r = client.post("/edge/v1/usage", headers=hdr, json={"items": [
        {"host": "victim.com", "hour": hour_iso(5), "bytes": 1, "requests": 1},
        {"host": "victim.com", "hour": hour_iso(-24 * 40), "bytes": 1, "requests": 1}]})
    assert r.json()["dropped"]["out_of_window"] == 2
    # bytes above the schema bound are a 422
    assert client.post("/edge/v1/usage", headers=hdr, json={"items": [
        {"host": "victim.com", "hour": hour_iso(), "bytes": 10**19, "requests": 1}]}).status_code == 422
    with SessionLocal() as db:
        assert db.scalar(select(UsageHourly.bytes)) == good


def test_m1_edge_reports_only_its_own_group(client):
    site(client, "web.com")
    site(client, "tun.com", plan={"features": {"tunnel": True, "edge_group": "tunnel"}})
    gen, tun = edge("g1"), edge("t1", group="tunnel", ipv4="9.9.9.8")
    items = [{"host": h, "hour": hour_iso(), "bytes": 100, "requests": 1} for h in ("web.com", "tun.com")]
    events = [{"t": hour_iso(), "host": "tun.com", "action": "block"}]
    r = client.post("/edge/v1/usage", headers={"Authorization": f"Bearer {gen}"},
                    json={"items": items, "events": events})
    assert r.json()["accepted"] == 1 and r.json()["dropped"]["foreign_group"] == 1 and r.json()["events"] == 0
    r = client.post("/edge/v1/usage", headers={"Authorization": f"Bearer {tun}"}, json={"items": items})
    assert r.json()["accepted"] == 1 and r.json()["dropped"]["foreign_group"] == 1
    with SessionLocal() as db:
        rows = {(db.get(Site, u.site_id).domain, db.get(Edge, u.edge_id).name) for u in db.scalars(select(UsageHourly))}
    assert rows == {("web.com", "g1"), ("tun.com", "t1")}


# ================================================================== M2 / M3: customer API keys

def test_m2_suspended_site_keys_are_read_only(client):
    """PoC: a config write with a customer key worked while the site was suspended."""
    site(client, "attacker.com")
    h = key(client, "attacker.com", ["purge", "stats", "dns", "config"])
    client.post("/api/v1/sites/attacker.com/suspend")
    assert client.put(f"{CAPI}/config/cache", headers=h, json={"enabled": True}).status_code == 403
    assert client.post(f"{CAPI}/records", headers=h, json={"name": "x", "type": "A", "content": "8.8.8.8"}
                       ).status_code == 403
    assert client.post(f"{CAPI}/purge", headers=h, json={"everything": True}).status_code == 403
    assert client.post(f"{CAPI}/image/transform-secret", headers=h).status_code == 403
    # reads keep working
    for path in ("/config/cache", "/records", "/analytics", "/site"):
        assert client.get(CAPI + path, headers=h).status_code == 200, path
    client.post("/api/v1/sites/attacker.com/unsuspend")
    routes_capi._config_hits.clear()
    assert client.put(f"{CAPI}/config/cache", headers=h, json={"enabled": True}).status_code == 200


def test_m3_scopes_are_split(client):
    site(client, "example.com", plan={"features": {"edge_functions": True, "max_functions": 2,
                                                   "dns_secondary": True}})
    dns_k = key(client, "example.com", ["dns"])
    cfg_k = key(client, "example.com", ["config"])
    fn_k = key(client, "example.com", ["functions"])
    fn = {"enabled": True, "items": [{"id": "hello", "route": "/hello", "code":
                                      "export default { fetch() { return new Response('hi') } }"}]}

    def put(h, section, body):
        routes_capi._config_hits.clear()
        return client.put(f"{CAPI}/config/{section}", headers=h, json=body).status_code

    # dns: records + secondary DNS only
    assert client.get(f"{CAPI}/records", headers=dns_k).status_code == 200
    assert put(dns_k, "dns_secondary", {"mode": "off"}) == 200
    assert put(dns_k, "cache", {"enabled": True}) == 403
    assert put(dns_k, "functions", fn) == 403
    assert client.get(f"{CAPI}/config/functions", headers=dns_k).status_code == 403
    # config: every other section, not records / functions
    assert put(cfg_k, "cache", {"enabled": True}) == 200
    assert client.get(f"{CAPI}/records", headers=cfg_k).status_code == 403
    assert put(cfg_k, "functions", fn) == 403
    assert put(cfg_k, "dns_secondary", {"mode": "off"}) == 403
    # functions: the edge function code
    assert put(fn_k, "functions", fn) == 200
    assert put(fn_k, "cache", {"enabled": True}) == 403
    # the scope list of the admin API
    r = client.post("/api/v1/sites/example.com/apikeys", json={"name": "x", "scopes": ["nope"]})
    assert r.status_code == 422 and "functions" in r.text
    assert "functions (edge function code)" in client.get(f"{CAPI}/openapi.json").json()["info"]["description"]


def test_m3_migration_keeps_config_for_existing_dns_keys(tmp_path):
    from sqlalchemy import create_engine, text

    from app import migrate

    eng = create_engine(f"sqlite:///{tmp_path}/m.db")
    migrate.upgrade(eng, "0018")
    with eng.begin() as c:
        c.execute(text("INSERT INTO sites (domain, status, suspended, over_quota, ns_found, bandwidth_limit_gb,"
                       " max_records, ssl_allowed, rate_limit_rps, features, config, blocked_ips, secret,"
                       " dnssec_enabled, ssl_status, created_at, updated_at) VALUES ('a.com', 'active', false,"
                       " false, '[]', 0, 100, true, 0, '{}', '{}', '[]', 'x', false, 'none', CURRENT_TIMESTAMP,"
                       " CURRENT_TIMESTAMP)"))
        for i, scopes in enumerate((["purge", "stats", "dns"], ["stats"], ["dns"])):
            c.execute(text("INSERT INTO api_keys (site_id, key_hash, name, scopes, created_at, revoked)"
                           " VALUES (1, :h, 'k', :s, CURRENT_TIMESTAMP, false)"),
                      {"h": f"h{i}", "s": json.dumps(scopes)})
    migrate.upgrade(eng)
    with eng.connect() as c:
        got = [json.loads(s) for (s,) in c.execute(text("SELECT scopes FROM api_keys ORDER BY id"))]
    assert got == [["purge", "stats", "dns", "config"], ["stats"], ["dns", "config"]]
    migrate.downgrade(eng, "0018")
    with eng.connect() as c:
        got = [json.loads(s) for (s,) in c.execute(text("SELECT scopes FROM api_keys ORDER BY id"))]
    assert got == [["purge", "stats", "dns"], ["stats"], ["dns"]]
    eng.dispose()


# ================================================================== purge ids (staging finding)

def test_purge_ids_are_never_reused(client):
    """Edges fetch purges with ?after=<last id>: an id handed out again after a deletion was
    silently skipped by every edge whose cursor was past it."""
    def purge_ids():
        with SessionLocal() as db:
            return list(db.scalars(select(Purge.id).order_by(Purge.id)))

    first = site(client, "one.com")["id"]
    for _ in range(3):
        assert client.post("/api/v1/sites/one.com/purge", json={"everything": True}).status_code == 200
    ids = purge_ids()
    assert len(ids) == 3
    client.delete("/api/v1/sites/one.com")
    assert purge_ids() == []  # every row of the deleted site is gone
    assert site(client, "two.com")["id"] > first  # site ids are not reused either
    client.post("/api/v1/sites/two.com/purge", json={"everything": True})
    (new,) = purge_ids()
    assert new > max(ids)
    tok = edge("cursor")
    items = client.get(f"/edge/v1/purges?after={max(ids)}", headers={"Authorization": f"Bearer {tok}"}).json()
    assert [i["id"] for i in items] == [new]


def test_purge_ids_migration_sqlite(tmp_path):
    from sqlalchemy import create_engine, text

    from app import migrate

    eng = create_engine(f"sqlite:///{tmp_path}/p.db")
    migrate.upgrade(eng, "0018")
    with eng.begin() as c:
        c.execute(text("INSERT INTO sites (domain, status, suspended, over_quota, ns_found, bandwidth_limit_gb,"
                       " max_records, ssl_allowed, rate_limit_rps, features, config, blocked_ips, secret,"
                       " dnssec_enabled, ssl_status, created_at, updated_at) VALUES ('a.com', 'active', false,"
                       " false, '[]', 0, 100, true, 0, '{}', '{}', '[]', 'x', false, 'none', CURRENT_TIMESTAMP,"
                       " CURRENT_TIMESTAMP)"))
        for _ in range(3):
            c.execute(text("INSERT INTO purges (site_id, urls, prefixes, everything, created_at)"
                           " VALUES (1, '[]', '[]', true, CURRENT_TIMESTAMP)"))
    migrate.upgrade(eng)
    with eng.begin() as c:
        assert "AUTOINCREMENT" in c.execute(text("SELECT sql FROM sqlite_master WHERE name = 'purges'")).scalar()
        assert [r for (r,) in c.execute(text("SELECT id FROM purges ORDER BY id"))] == [1, 2, 3]
        c.execute(text("DELETE FROM purges"))
        c.execute(text("INSERT INTO purges (site_id, urls, prefixes, everything, created_at)"
                       " VALUES (1, '[]', '[]', true, CURRENT_TIMESTAMP)"))
        assert c.execute(text("SELECT id FROM purges")).scalar() > 3 + 100_000
    eng.dispose()


# ================================================================== M5: PowerDNS API transport

def test_m5_insecure_pdns_api_urls(monkeypatch):
    assert pdns.insecure_api_urls("http://pdns:8081,http://10.0.0.2:8081,https://ns2.example.net:8443,"
                                  "http://127.0.0.1:8081") == []
    assert pdns.insecure_api_urls("http://pdns:8081,http://203.0.113.0:8081,http://ns2.example.net:8081") == [
        "http://ns2.example.net:8081"]  # 203.0.113.0/24 is documentation space (not public)
    assert pdns.insecure_api_urls("http://5.160.1.10:8081") == ["http://5.160.1.10:8081"]
    monkeypatch.setattr(settings, "pdns_api_url", "http://5.160.1.10:8081")
    monkeypatch.setattr(settings, "pdns_enabled", True)
    pdns.check_transport()  # warns only by default
    monkeypatch.setattr(settings, "pdns_api_require_private", True)
    with pytest.raises(RuntimeError):
        pdns.check_transport()


# ================================================================== L1 / L2 / L3 / L5

@pytest.mark.parametrize("ip,version", [("100.64.1.1", 4), ("100.127.255.254", 4), ("192.0.2.1", 4),
                                        ("198.18.0.1", 4), ("240.0.0.1", 4), ("0.1.2.3", 4),
                                        ("64:ff9b::7f00:1", 6), ("2002:7f00:1::1", 6), ("::ffff:127.0.0.1", 6),
                                        ("2001:db8::1", 6), ("fd00::1", 6)])
def test_l1_validate_ip_refuses_non_public(ip, version):
    with pytest.raises(ValidationError):
        validate_ip(ip, version)


def test_l1_records_and_origin_ip(client):
    site(client, "example.com")
    assert client.post("/api/v1/sites", json={"domain": "cg.com", "origin_ip": "100.64.0.10"}).status_code == 422
    r = client.post("/api/v1/sites/example.com/records", json={"name": "x", "type": "AAAA",
                                                               "content": "64:ff9b::a00:1", "proxied": True})
    assert r.status_code == 422
    assert validate_ip("8.8.8.8", 4) == "8.8.8.8" and validate_ip("2606:4700::1111", 6) == "2606:4700::1111"
    # operator input (edges) keeps the older check: a lab edge on 100.64/10 still works
    assert client.post("/api/v1/edges", json={"name": "lab", "ipv4": "100.64.0.5"}).status_code == 201


def test_l3_uvicorn_trusts_only_private_proxies():
    df = (REPO / "controller" / "Dockerfile").read_text()
    assert '"--forwarded-allow-ips", "*"' not in df and "FORWARDED_ALLOW_IPS=127.0.0.1" in df
    assert "FORWARDED_ALLOW_IPS: ${FORWARDED_ALLOW_IPS:-" in (REPO / "docker-compose.yml").read_text()


def test_l5_malformed_details_do_not_500(client):
    site(client, "example.com")
    tok = edge()
    hdr = {"Authorization": f"Bearer {tok}"}
    r = client.post("/edge/v1/usage", headers=hdr,
                    json={"items": [{"host": "example.com", "hour": hour_iso(), "bytes": 1, "requests": 1}]})
    assert r.status_code == 200
    with SessionLocal() as db:
        row = db.scalar(select(UsageHourly))
        row.details = json.dumps({"status": {"2xx": "lots"}, "countries": ["IR"], "paths": {"/": {"x": 1}},
                                  "codes": {"200": None}, "video": "big", "l4": {"a": "b"},
                                  "tunnel": {"sessions": "x", "paths": {"p": {"sessions": "y"}}}})
        db.commit()
    for path in ("/api/v1/sites/example.com/analytics", "/api/v1/analytics", "/api/v1/overview"):
        assert client.get(path).status_code == 200, path
    r = client.post("/edge/v1/usage", headers=hdr, json={"items": [
        {"host": "example.com", "hour": hour_iso(), "bytes": 1, "requests": 1, "status": {"2xx": 1},
         "tunnel": {"sessions": 1, "paths": {"p": {"sessions": 2}}}}]})
    assert r.status_code == 200, r.text
    with SessionLocal() as db:
        d = json.loads(db.scalar(select(UsageHourly)).details)
    assert d["status"]["2xx"] == 1 and d["tunnel"]["paths"]["p"]["sessions"] == 2


# ================================================================== origin host names

def test_origin_literals_and_names_are_refused(client, fake_dns):
    """PoC: localhost / 169.254.169.254.nip.io / localhost:22 were accepted as origins."""
    fake_dns.update({"169.254.169.254.nip.io": ["169.254.169.254"], "internal.evil-dns.net": ["10.1.2.3"],
                     "mixed.evil-dns.net": ["93.184.216.34", "127.0.0.1"], "good.origin.com": ["93.184.216.34"]})
    site(client, "attacker.com", plan={"features": {"load_balancer": True, "tunnel": True, "l4_proxy": True,
                                                    "max_l4_apps": 5}})
    h = key(client, "attacker.com", ["dns", "config"])

    def rec(content, proxied=True):
        routes_capi._config_hits.clear()
        return client.post(f"{CAPI}/records", headers=h, json={"name": "x", "type": "CNAME", "content": content,
                                                               "proxied": proxied, "origin_port": 8089})

    def put(section, body):
        routes_capi._config_hits.clear()
        return client.put(f"{CAPI}/config/{section}", headers=h, json=body)

    for bad in ("localhost", "foo.localhost", "metadata.google.internal", "printer.local", "127.0.0.1",
                "0x7f.1", "intranet", "internal.evil-dns.net", "mixed.evil-dns.net", "169.254.169.254.nip.io"):
        r = rec(bad)
        assert r.status_code == 422, (bad, r.text)
    # DNS-only (not proxied) records are not origins: the edges never connect to them
    assert rec("internal.evil-dns.net", proxied=False).status_code == 201
    pool = lambda a: {"pools": [{"name": "p", "origins": [{"address": a, "port": 80}]}]}  # noqa: E731
    for bad in ("169.254.169.254.nip.io", "localhost", "100.64.0.1", "[fd00::1]", "10.0.0.1", "[::ffff:10.0.0.1]"):
        r = put("pools", pool(bad))
        assert r.status_code == 422, (bad, r.text)
    assert put("pools", pool("good.origin.com")).status_code == 200
    assert put("pools", pool("not-resolving-yet.origin.com")).status_code == 200  # edges refuse at connect
    r = put("l4", {"apps": [{"id": "ssh", "protocol": "tcp", "origin": {"address": "localhost", "port": 22}}]})
    assert r.status_code == 422
    r = put("tunnel", {"enabled": True, "paths": [{"id": "t", "path": "/t", "protocol": "ws",
                                                   "origin": {"address": "internal.evil-dns.net", "port": 80}}]})
    assert r.status_code == 422 and "تونل" in r.text
    # the edge config carries no internal origin
    tok = edge()
    cfg = client.get("/edge/v1/config", headers={"Authorization": f"Bearer {tok}"}).json()
    s = next(x for x in cfg["sites"] if x["domain"] == "attacker.com")
    assert all(hh["origin"].get("address") not in ("localhost", "internal.evil-dns.net") for hh in s["hosts"])


def test_origin_recheck_blocks_and_unblocks(client, fake_dns, monkeypatch):
    """A name that resolved to a public address on save and later points inside is left out of the
    edge config (records, pool members, tunnel paths, l4 apps) until it is public again."""
    fake_dns.update({"o.origin-host.net": ["93.184.216.34"], "p.origin-host.net": ["93.184.216.35"]})
    site(client, "cust.com", plan={"features": {"load_balancer": True, "tunnel": True, "l4_proxy": True,
                                                "max_l4_apps": 2}})
    S = "/api/v1/sites/cust.com"
    assert client.post(f"{S}/records", json={"name": "app", "type": "CNAME", "content": "o.origin-host.net",
                                             "proxied": True}).status_code == 201
    assert client.put(f"{S}/config/pools", json={"pools": [{"name": "p", "origins": [
        {"address": "o.origin-host.net"}, {"address": "p.origin-host.net"}]}]}).status_code == 200
    assert client.put(f"{S}/config/tunnel", json={"enabled": True, "paths": [
        {"id": "t", "path": "/t", "protocol": "ws", "origin": {"address": "o.origin-host.net", "port": 80}}]}).status_code == 200
    assert client.put(f"{S}/config/l4", json={"apps": [
        {"id": "db", "origin": {"address": "o.origin-host.net", "port": 5432}}]}).status_code == 200
    with SessionLocal() as db:
        s = db.scalar(select(Site).where(Site.domain == "cust.com"))
        s.status = "active"
        db.commit()
    tok = edge()
    hdr = {"Authorization": f"Bearer {tok}"}
    opened, closed = [], []
    monkeypatch.setattr(alerts, "raise_alert", lambda k, *a, **kw: opened.append(k))
    monkeypatch.setattr(alerts, "resolve_alert", lambda k, *a, **kw: closed.append(k))

    def site_cfg():
        cfg = client.get("/edge/v1/config", headers=hdr).json()
        return next(x for x in cfg["sites"] if x["domain"] == "cust.com"), cfg

    before, cfg = site_cfg()
    assert "app.cust.com" in {x["name"] for x in before["hosts"]} and before["tunnel"]["paths"]
    assert len(before["pools"]["pools"][0]["origins"]) == 2 and cfg["l4"]
    # DNS rebinding: o.origin-host.net now points at the metadata service
    fake_dns["o.origin-host.net"] = ["169.254.169.254"]
    with SessionLocal() as db:
        blocked = scheduler.job_security_audit(db, force=True)["blocked"]
    assert set(blocked) == {"o.origin-host.net"} and "origin_guard" in opened
    after, cfg = site_cfg()
    assert "app.cust.com" not in {x["name"] for x in after["hosts"]}
    assert [o["address"] for o in after["pools"]["pools"][0]["origins"]] == ["p.origin-host.net"]
    assert after["tunnel"]["paths"] == [] and after["l4"]["apps"] == [] and cfg["l4"] == []
    # public again -> back in the edge config, alert resolved
    fake_dns["o.origin-host.net"] = ["93.184.216.34"]
    with SessionLocal() as db:
        assert scheduler.job_security_audit(db, force=True)["blocked"] == {}
        assert origin_guard.blocked(db) == {}
    assert "origin_guard" in closed
    again, _ = site_cfg()
    assert "app.cust.com" in {x["name"] for x in again["hosts"]} and again["tunnel"]["paths"]


def test_tenancy_helpers():
    assert tenancy.ancestors("a.b.example.co.ir") == ["b.example.co.ir", "example.co.ir", "co.ir"]
    assert tenancy.owner_of(None, 5) == 5 and tenancy.owner_of(3, 5) == 3 and tenancy.owner_of(None, None) is None
    assert origin_guard.name_problem("origin.example.com") is None
    assert origin_guard.name_problem("x.xn--mgba3a4f16a") is None
    for bad in ("localhost", "a.local", "a.b.internal", "1.2.3.4", "host", "x.home.arpa", "0x7f.0x1"):
        assert origin_guard.name_problem(bad), bad


def test_api_key_scope_list_unknown_values_are_harmless(client):
    """A key row with junk scopes grants nothing (scope_list is used as-is)."""
    site(client, "example.com")
    with SessionLocal() as db:
        s = db.scalar(select(Site).where(Site.domain == "example.com"))
        k = ApiKey(site_id=s.id, key_hash=hash_token("pcdn_" + "a" * 40), name="j", scopes='"dns"')
        db.add(k)
        db.commit()
    routes_capi._hits.clear()
    r = client.get(f"{CAPI}/records", headers={"Authorization": "Bearer pcdn_" + "a" * 40})
    assert r.status_code == 403
