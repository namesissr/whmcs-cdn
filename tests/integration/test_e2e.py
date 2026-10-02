"""End-to-end flow through the whole product on the staging stack (docs/STAGING.md).

The tests run in file order and share one site: admin API -> PowerDNS -> edges -> origin -> usage back
to the controller. Each step waits for the eventually-consistent part (agent poll + coalesced reload,
usage push) instead of sleeping a fixed time.
"""

import time
import uuid

import pytest

from conftest import (ApiError, ORIGIN_IP, KEEP, dig, edge_request, new_domain, origin_hits, wait_until,
                      ws_echo)

DOMAIN = new_domain("shop")
ASSET = f"/assets/app-{uuid.uuid4().hex[:8]}.js"
TUNNEL_PATH = "/tun-ws-" + uuid.uuid4().hex[:6]
SUSPENDED_MARK = "سرویس معلق است"  # <title> of edge/pages/suspended.html


@pytest.fixture(scope="module")
def site(api, edges):
    plan = {
        "ssl_allowed": False,  # no ACME in staging
        "bandwidth_limit_gb": 0,
        "features": {"waf": True, "tunnel": True, "max_tunnel_paths": 5, "max_firewall_rules": 5},
    }
    out = api.post("/api/v1/sites", {"domain": DOMAIN, "origin_ip": ORIGIN_IP, "external_id": "staging-e2e",
                                     "plan": plan})
    assert out["domain"] == DOMAIN
    assert out.get("dns_error") is None, out
    yield out
    if not KEEP:
        try:
            api.delete(f"/api/v1/sites/{DOMAIN}")
        except ApiError:
            pass


def _all_edges(edges, fn, desc, timeout=None):
    for name, ip in edges.items():
        wait_until(lambda: fn(ip), f"{desc} on {name} ({ip})", timeout=timeout)


def test_01_edges_installed_from_the_controller_bundle(api, edges):
    """The edges registered through the real flow: the version bootstrap.sh recorded from
    GET /edge/version is what each agent reports in its heartbeat."""
    bundle = api.get("/edge/version", auth=False)["version"]
    assert bundle
    rows = {e["name"]: e for e in api.get("/api/v1/edges")}
    for name, ip in edges.items():
        e = rows[name]
        assert e["ipv4"] == ip and e["enabled"]
        assert e["region"] == "global" and e["group"] == "general"
        assert e["bundle_version"] == bundle, (name, e["bundle_version"], bundle)
        caps = e["capabilities"] or {}
        assert "njs" in (caps.get("modules") or []), caps


def test_02_site_records_and_delegation(api, site):
    api.post(f"/api/v1/sites/{DOMAIN}/records", {"name": "api", "type": "A", "content": ORIGIN_IP, "proxied": True})
    api.post(f"/api/v1/sites/{DOMAIN}/records", {"name": "direct", "type": "A", "content": ORIGIN_IP,
                                                 "proxied": False, "ttl": 300})
    api.post(f"/api/v1/sites/{DOMAIN}/records", {"name": "@", "type": "TXT", "content": "staging=1"})
    recs = {(r["name"], r["type"]): r for r in api.get(f"/api/v1/sites/{DOMAIN}/records")}
    for key in (("@", "A"), ("www", "CNAME"), ("api", "A"), ("direct", "A"), ("@", "TXT")):
        assert key in recs, recs
    # the delegation check asks our PowerDNS (NS_RESOLVERS): pending_ns -> active
    ns = api.post(f"/api/v1/sites/{DOMAIN}/ns-check")
    assert ns["ok"], ns
    assert api.get(f"/api/v1/sites/{DOMAIN}")["status"] == "active"


def test_03_dns_answers_point_at_the_edges(edges, site):
    want = sorted(edges.values())
    for name in (DOMAIN, f"www.{DOMAIN}", f"api.{DOMAIN}"):
        # LUA_SELECTOR=all in staging: every healthy edge is in the answer (www is a CNAME to the apex)
        wait_until(lambda: [a for a in dig(name, "A") if a[0].isdigit()] == want, f"A {name} -> {want}")
    assert dig(f"direct.{DOMAIN}", "A") == [ORIGIN_IP]  # not proxied: the origin itself
    assert dig(DOMAIN, "NS") == ["ns1.staging.test.", "ns2.staging.test."]
    assert '"staging=1"' in dig(DOMAIN, "TXT")
    assert ORIGIN_IP not in dig(DOMAIN, "A")  # a proxied name never leaks the origin


def test_04_http_through_every_edge_reaches_the_origin(edges, site):
    def ok(ip, host=DOMAIN, path="/hello?nocache=1"):
        r = edge_request(ip, host, path)
        return r if r.status == 200 and r.headers.get("x-origin") == "pcdn-staging" else None

    for name, ip in edges.items():
        r = wait_until(lambda: ok(ip), f"{DOMAIN} served by {name}")
        body = r.json()
        assert body["host"] == DOMAIN          # Host is preserved towards the origin
        assert body["path"] == "/hello"
        assert body["headers"].get("x-forwarded-for")
        # waited for like the apex: right after the edge applies the site, a connection can still land
        # on an nginx worker of the previous config (graceful reload) and get the 421 of an unknown host
        r = wait_until(lambda: ok(ip, f"api.{DOMAIN}", "/v1/ping?nocache=1"), f"api.{DOMAIN} served by {name}")
        assert r.json()["host"] == f"api.{DOMAIN}"
    r = edge_request(edges["edge-1"], "unknown.staging.test", "/")
    assert r.headers.get("x-origin") != "pcdn-staging"  # unknown hosts never reach an origin


def test_05_cache_miss_then_hit(edges, site):
    ip = edges["edge-1"]
    first = edge_request(ip, DOMAIN, ASSET)
    assert first.status == 200, first
    assert first.headers.get("x-cache") == "MISS", first.headers
    second = wait_until(lambda: (lambda r: r if r.headers.get("x-cache") == "HIT" else None)(
        edge_request(ip, DOMAIN, ASSET)), f"HIT for {ASSET}", timeout=20)
    assert second.json()["serial"] == first.json()["serial"]  # the same stored object
    assert origin_hits(ASSET) == 1


def test_06_purge(api, edges, site):
    ip = edges["edge-1"]
    before = edge_request(ip, DOMAIN, ASSET).json()["serial"]
    out = api.post(f"/api/v1/sites/{DOMAIN}/purge", {"urls": [f"http://{DOMAIN}{ASSET}"]})
    assert out["ok"], out

    def purged():
        r = edge_request(ip, DOMAIN, ASSET)
        return r if r.headers.get("x-cache") in ("MISS", "EXPIRED") else None
    r = wait_until(purged, "the purged URL to be fetched from the origin again")
    assert r.json()["serial"] != before
    assert origin_hits(ASSET) == 2
    again = edge_request(ip, DOMAIN, ASSET)
    assert again.headers.get("x-cache") == "HIT"


def test_07_waf_and_firewall_block(api, edges, site):
    api.put(f"/api/v1/sites/{DOMAIN}/config/waf", {"mode": "block", "paranoia": 1})
    api.put(f"/api/v1/sites/{DOMAIN}/config/firewall", {"default_action": "allow", "rules": [
        {"id": "staging-deny", "name": "staging", "action": "block",
         "conditions": [{"field": "path", "op": "starts_with", "value": "/staging-blocked"}]}]})
    xss = "/search?q=%3Cscript%3Ealert(1)%3C/script%3E"
    _all_edges(edges, lambda ip: edge_request(ip, DOMAIN, xss).status == 403, "WAF block (xss)")
    _all_edges(edges, lambda ip: edge_request(ip, DOMAIN, "/staging-blocked/x").status == 403, "firewall block")
    # once the rules are live, blocked requests never reach the origin (requests sent while the
    # agents were still reloading may have)
    before = origin_hits("/search"), origin_hits("/staging-blocked/x")
    for ip in edges.values():
        assert edge_request(ip, DOMAIN, xss).status == 403
        assert edge_request(ip, DOMAIN, "/staging-blocked/x").status == 403
    assert (origin_hits("/search"), origin_hits("/staging-blocked/x")) == before
    for ip in edges.values():
        assert edge_request(ip, DOMAIN, "/clean?nocache=1").status == 200  # clean traffic still passes


def test_08_tunnel_websocket_end_to_end(api, edges, site):
    api.put(f"/api/v1/sites/{DOMAIN}/config/tunnel", {
        "enabled": True, "fallback": "origin",
        "paths": [{"id": "ws", "path": TUNNEL_PATH, "protocol": "ws",
                   "origin": {"address": ORIGIN_IP, "port": 8080}}]})

    def echo(ip):
        msg = "ping-" + uuid.uuid4().hex
        status, got = ws_echo(ip, DOMAIN, TUNNEL_PATH, msg)
        return status == 101 and got == msg
    _all_edges(edges, echo, "WebSocket echo through the tunnel path")
    # tunnel sites answer with every healthy edge (TUNNEL_LUA_SELECTOR=all)
    assert [a for a in dig(DOMAIN, "A") if a[0].isdigit()] == sorted(edges.values())


def test_09_usage_reaches_the_controller(api, edges, site):
    def hourly():
        m = api.get(f"/api/v1/sites/{DOMAIN}/usage?days=2")["month"]
        return m if m["requests"] >= 5 and m["bytes"] > 0 and m["cache_hits"] >= 1 else None
    month = wait_until(hourly, "hourly usage (UsageHourly) for the site")
    assert month["requests"] >= 5

    allu = api.get("/api/v1/usage")
    row = next(s for s in allu["sites"] if s["domain"] == DOMAIN)
    assert row["requests"] >= month["requests"] and row["external_id"] == "staging-e2e"

    def live():
        t = api.get(f"/api/v1/sites/{DOMAIN}/analytics/live?minutes=30")["totals"]
        return t if t["requests"] > 0 and t["cache_hits"] > 0 else None
    t = wait_until(live, "live (per-minute) analytics for the site")
    assert t["hit_ratio"] is not None

    def events():
        ev = api.get(f"/api/v1/sites/{DOMAIN}/events?limit=50")
        return ev if {e["source"] for e in ev} >= {"waf", "firewall"} else None
    ev = wait_until(events, "WAF + firewall security events for the site")
    assert all(e["action"] == "block" for e in ev if e["source"] in ("waf", "firewall"))


def test_10_sla_and_analytics_endpoints(api, site):
    month = time.strftime("%Y-%m", time.gmtime())
    sla = wait_until(lambda: (lambda r: r if r["requests"] > 0 else None)(api.get(f"/api/v1/sites/{DOMAIN}/sla")),
                     "SLA report with requests")
    assert sla["domain"] == DOMAIN and sla["month"] == month
    assert sla["request_success_pct"] is not None and sla["days"]
    for k in ("edge_uptime_pct", "availability_pct", "target_pct", "met", "platform_errors"):
        assert k in sla
    a = api.get(f"/api/v1/sites/{DOMAIN}/analytics?period=24h")
    assert a["totals"]["requests"] > 0 and a["totals"]["cache_hits"] > 0
    assert sum(a["totals"]["security"].values()) > 0
    assert any(p["requests"] > 0 for p in a["series"])
    pa = api.get("/api/v1/analytics?period=24h")
    assert any(s["domain"] == DOMAIN for s in pa["sites"])
    assert api.get("/api/v1/overview")
    assert api.get("/status.json", auth=False)


def test_11_suspend_serves_the_suspended_page(api, edges, site):
    api.post(f"/api/v1/sites/{DOMAIN}/suspend")
    assert api.get(f"/api/v1/sites/{DOMAIN}")["status"] == "suspended"

    def suspended(ip):
        r = edge_request(ip, DOMAIN, "/hello?nocache=1")
        return r.status == 503 and SUSPENDED_MARK in r.text and r.headers.get("x-origin") is None
    _all_edges(edges, suspended, "the suspended page")
    hits = origin_hits("/hello")
    for ip in edges.values():
        status, _ = ws_echo(ip, DOMAIN, TUNNEL_PATH, "x")
        assert status == 503  # tunnel reconnects get the cheap 503 too (cut_paths)
        edge_request(ip, DOMAIN, "/hello?nocache=1")
    assert origin_hits("/hello") == hits  # nothing reaches the origin while suspended


def test_12_unsuspend_restores_service(api, edges, site):
    api.post(f"/api/v1/sites/{DOMAIN}/unsuspend")
    assert api.get(f"/api/v1/sites/{DOMAIN}")["status"] == "active"

    def back(ip):
        r = edge_request(ip, DOMAIN, "/hello?nocache=1")
        return r.status == 200 and r.json()["host"] == DOMAIN
    _all_edges(edges, back, "service restored after unsuspend")
    _all_edges(edges, lambda ip: ws_echo(ip, DOMAIN, TUNNEL_PATH, "back")[1] == "back", "tunnel restored")
