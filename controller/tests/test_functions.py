"""Edge functions, controller side (SPEC §16.9): plan gate, section validation identical to the edge
(edge/pcdn-agent.py norm_functions), tunnel-path nesting both ways, edge config passthrough, views
without code, audit, usage ingestion, stats (admin + customer API) and the heartbeat capability."""

import hashlib
import importlib.util
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import select

from app import routes_capi, sections
from app.config import settings
from app.db import SessionLocal
from app.models import Site
from tests.test_api import add_edge, edge_get

S = "/api/v1/sites/example.com"
CODE = "export default { fetch(req) { return new Response('hi'); } }"
AGENT = Path(__file__).resolve().parents[2] / "edge" / "pcdn-agent.py"


@pytest.fixture(scope="module")
def agent():
    spec = importlib.util.spec_from_file_location("pcdn_agent_fn", AGENT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(autouse=True)
def _reset_rate():
    routes_capi._hits.clear()
    routes_capi._config_hits.clear()
    yield
    routes_capi._hits.clear()
    routes_capi._config_hits.clear()


def make_site(client, domain="example.com", **features):
    r = client.post("/api/v1/sites", json={"domain": domain, "origin_ip": "93.184.216.34",
                                           "plan": {"features": features}})
    assert r.status_code == 201, r.text
    return r.json()


def activate(domain="example.com"):
    with SessionLocal() as db:
        site = db.scalar(select(Site).where(Site.domain == domain))
        site.status = "active"
        db.commit()


def fn(fid="auth", route="/api/", code=CODE, **kw):
    return {"id": fid, "route": route, "code": code, **kw}


def put(client, body, base=S):
    # json.dumps escapes non-ASCII (a lone surrogate travels as the JSON escape \ud800)
    return client.put(f"{base}/config/functions", content=json.dumps(body),
                      headers={"Content-Type": "application/json"})


# ------------------------------------------------------------------ plan gate

def test_plan_gate_and_limit(client):
    make_site(client)
    feats = client.get(S).json()["plan"]["features"]
    assert feats["edge_functions"] is False and feats["max_functions"] == 0
    # the off shape can always be written
    assert put(client, {}).status_code == 200
    assert put(client, {"enabled": False, "items": []}).status_code == 200
    # no feature: enabling or storing items -> 403
    assert put(client, {"enabled": True}).status_code == 403
    assert put(client, {"enabled": False, "items": [fn()]}).status_code == 403
    # feature but max_functions 0 -> 403 on any item
    client.patch(f"{S}/plan", json={"features": {"edge_functions": True}})
    r = put(client, {"enabled": True, "items": [fn()]})
    assert r.status_code == 403 and "حداکثر 0" in r.text
    client.patch(f"{S}/plan", json={"features": {"max_functions": 2}})
    assert put(client, {"enabled": True, "items": [fn("a", "/a"), fn("b", "/b")]}).status_code == 200
    r = put(client, {"enabled": True, "items": [fn("a", "/a"), fn("b", "/b"), fn("c", "/c")]})
    assert r.status_code == 403
    # plan feature bounds
    assert client.patch(f"{S}/plan", json={"features": {"max_functions": 33}}).status_code == 422
    assert client.patch(f"{S}/plan", json={"features": {"max_functions": -1}}).status_code == 422
    assert client.patch(f"{S}/plan", json={"features": {"max_functions": 32}}).status_code == 200


# ------------------------------------------------------------------ validation (edge parity)

BAD_ITEMS = [
    fn(fid="Bad"),                       # id pattern
    fn(fid=""),
    fn(fid="a" * 33),
    fn(route="api"),                     # must start with /
    fn(route="/a b"),
    fn(route="/a?x=1"),
    fn(route="/" + "a" * 256),           # > 256 chars
    fn(route="/a\n"),                    # the edge regex would allow a trailing newline; never stored
    fn(route="/__pcdn/x"),
    fn(route="/__PCDN"),
    fn(route="/a//b"),
    fn(route="/a/./b"),
    fn(route="/a/../b"),
    fn(route="/.."),
    fn(route="/a/."),
    fn(route="/./"),
    fn(code=""),
    fn(code="   \n\t"),
    fn(code="ج" * (128 * 1024 + 1)),     # 262146 bytes of UTF-8 (fewer characters than the cap)
    fn(code="a\ud800b"),                 # lone surrogate: not UTF-8
    fn(code=7),
    fn(timeout_ms=0),
    fn(timeout_ms=201),
    fn(timeout_ms=True),
    fn(timeout_ms="50"),
    fn(timeout_ms=50.5),
    fn(memory_mb=7),
    fn(memory_mb=129),
    fn(on_error="500"),
    fn(bogus=1),
]


@pytest.mark.parametrize("item", BAD_ITEMS)
def test_invalid_items_rejected(client, item):
    make_site(client, edge_functions=True, max_functions=32)
    r = put(client, {"enabled": True, "items": [item]})
    assert r.status_code == 422, (item.get("route"), r.text)


def test_section_level_validation(client):
    make_site(client, edge_functions=True, max_functions=32)
    for body in ({"enabled": True, "items": [fn("a", "/a"), fn("a", "/b")]},     # duplicate id
                 {"enabled": True, "items": [fn("a", "/a"), fn("b", "/a")]},     # duplicate route
                 {"enabled": True, "items": [fn(f"f{i}", f"/r{i}") for i in range(33)]},  # > 32
                 {"enabled": True, "on_error": "pass"},
                 {"enabled": True, "bogus": True},
                 {"enabled": True, "items": "x"}):
        assert put(client, body).status_code == 422, body
    # nested (but not equal) routes of two functions are fine: nginx picks the longest prefix
    assert put(client, {"enabled": True, "items": [fn("a", "/"), fn("b", "/api")]}).status_code == 200
    # the size cap is exact: 262144 bytes pass
    assert put(client, {"enabled": True, "items": [fn(code="a" * 262144)]}).status_code == 200


def test_defaults_roundtrip_and_views(client):
    make_site(client, edge_functions=True, max_functions=5)
    assert client.get(f"{S}/config/functions").json() == {"enabled": False, "on_error": "502", "items": []}
    body = {"enabled": True, "on_error": "origin",
            "items": [fn("auth", "/api/", timeout_ms=100, memory_mb=64, on_error="502"),
                      fn("root", "/", code="  x  ", enabled=False)]}
    r = put(client, body)
    assert r.status_code == 200, r.text
    out = r.json()
    sha = hashlib.sha256(CODE.encode()).hexdigest()
    assert out["items"][0] == {**body["items"][0], "enabled": True, "code_bytes": len(CODE), "sha256": sha}
    assert out["items"][1] == {**body["items"][1], "timeout_ms": 50, "memory_mb": 32, "on_error": None,
                               "code_bytes": 5, "sha256": hashlib.sha256(b"  x  ").hexdigest()}
    got = client.get(f"{S}/config/functions").json()
    assert got == out
    # GET -> PUT round trip with the output-only fields is accepted and stores no output field
    assert put(client, got).json() == out
    with SessionLocal() as db:
        stored = json.loads(db.scalar(select(Site.config).where(Site.domain == "example.com")))["functions"]
    assert "sha256" not in json.dumps(stored) and stored["items"][0]["code"] == CODE
    # whole-site views carry no code (only its size / hash)
    for view in (client.get(f"{S}/config").json()["functions"], client.get(S).json()["config"]["functions"]):
        assert [set(i) for i in view["items"]] == [
            {"id", "route", "enabled", "timeout_ms", "memory_mb", "on_error", "code_bytes", "sha256"}] * 2
        assert view["items"][0]["sha256"] == sha
    # the site list stays small
    assert CODE not in client.get("/api/v1/sites").text


def test_total_code_cap_setting(client, monkeypatch):
    make_site(client, edge_functions=True, max_functions=5)
    monkeypatch.setattr(settings, "functions_max_site_kb", 256)
    big = "a" * (200 * 1024)
    r = put(client, {"enabled": True, "items": [fn("a", "/a", code=big), fn("b", "/b", code=big)]})
    assert r.status_code == 422 and "256" in r.text
    assert put(client, {"enabled": True, "items": [fn("a", "/a", code=big)]}).status_code == 200


def test_total_code_cap_env(monkeypatch):
    from app.config import Settings

    for raw, want in ((None, 8192), ("1024", 1024), ("1", 256), ("100000", 8192)):
        if raw is None:
            monkeypatch.delenv("FUNCTIONS_MAX_SITE_KB", raising=False)
        else:
            monkeypatch.setenv("FUNCTIONS_MAX_SITE_KB", raw)
        assert Settings().functions_max_site_kb == want


# ------------------------------------------------------------------ tunnel paths

def tpath(pid="ws", path="/ws-secret"):
    return {"id": pid, "path": path, "protocol": "ws"}


def test_tunnel_nesting_both_ways(client):
    make_site(client, edge_functions=True, max_functions=5, tunnel=True)
    assert client.put(f"{S}/config/tunnel", json={"enabled": True, "paths": [tpath()]}).status_code == 200
    for route in ("/ws-secret", "/ws-secret/x", "/ws", "/", "/ws-secretX"):   # plain string prefixes
        r = put(client, {"enabled": True, "items": [fn(route=route)]})
        assert r.status_code == 422 and "تونل" in r.text, route
    # also a disabled function (it could be enabled later without a re-check of the tunnel)
    assert put(client, {"enabled": False, "items": [fn(route="/ws", enabled=False)]}).status_code == 422
    assert put(client, {"enabled": True, "items": [fn(route="/api")]}).status_code == 200
    # the reverse: a tunnel path nesting with a stored function route -> 422
    r = client.put(f"{S}/config/tunnel", json={"enabled": True, "paths": [tpath(), tpath("g", "/api/grpc")]})
    assert r.status_code == 422 and "auth" in r.text
    r = client.put(f"{S}/config/tunnel", json={"enabled": False, "paths": [tpath("g", "/a")]})
    assert r.status_code == 422
    assert client.put(f"{S}/config/tunnel", json={"enabled": True, "paths": [tpath("g", "/grpc")]}).status_code == 200


def test_tunnel_decoy_fallback_both_ways(client):
    make_site(client, edge_functions=True, max_functions=5, tunnel=True)
    assert put(client, {"enabled": True, "items": [fn(route="/api")]}).status_code == 200
    r = client.put(f"{S}/config/tunnel", json={"enabled": True, "fallback": "decoy", "paths": [tpath()]})
    assert r.status_code == 422 and "fallback" in r.text
    # stored but off: fine; functions off: fine
    assert client.put(f"{S}/config/tunnel", json={"enabled": False, "fallback": "404",
                                                 "paths": [tpath()]}).status_code == 200
    assert put(client, {"enabled": False, "items": [fn(route="/api")]}).status_code == 200
    assert client.put(f"{S}/config/tunnel", json={"enabled": True, "fallback": "404",
                                                 "paths": [tpath()]}).status_code == 200
    r = put(client, {"enabled": True, "items": [fn(route="/api")]})
    assert r.status_code == 422 and "fallback" in r.text
    # every item disabled: nothing would run, accepted
    assert put(client, {"enabled": True, "items": [fn(route="/api", enabled=False)]}).status_code == 200


# ------------------------------------------------------------------ edge config

def test_edge_config_passthrough_and_edge_parity(client, agent):
    make_site(client, edge_functions=True, max_functions=3, tunnel=True)
    activate()
    token = add_edge(client)
    assert client.put(f"{S}/config/tunnel", json={"enabled": True, "paths": [tpath()]}).status_code == 200
    body = {"enabled": True, "on_error": "origin",
            "items": [fn("auth", "/api/", timeout_ms=10, memory_mb=8),
                      fn("off", "/off", enabled=False),
                      fn("root", "/x", code="ok", on_error="502", timeout_ms=200, memory_mb=128)]}
    assert put(client, body).status_code == 200
    site = edge_get(client, token, "/edge/v1/config").json()["sites"][0]
    assert site["functions"] == {"enabled": True, "on_error": "origin", "items": [
        {"id": "auth", "route": "/api/", "code": CODE, "enabled": True, "timeout_ms": 10, "memory_mb": 8,
         "on_error": "origin"},
        {"id": "root", "route": "/x", "code": "ok", "enabled": True, "timeout_ms": 200, "memory_mb": 128,
         "on_error": "502"}]}
    # parity: the edge runs every function the controller sent (none silently skipped)
    assert agent._fn_site_ok(site)
    got = agent.norm_functions(site, agent._fn_tunnel_prefixes(site))
    assert [(f["id"], f["on_error"], f["timeout_ms"], f["memory_mb"]) for f in got] == [
        ("auth", "origin", 10, 8), ("root", "502", 200, 128)]
    assert got[0]["sha256"] == client.get(f"{S}/config/functions").json()["items"][0]["sha256"]

    # plan shrinks: only the first max_functions items travel
    client.patch(f"{S}/plan", json={"features": {"max_functions": 1}})
    assert [f["id"] for f in edge_get(client, token, "/edge/v1/config").json()["sites"][0]["functions"]["items"]] \
        == ["auth"]
    # plan without the feature, suspended site, section off: no code travels
    client.patch(f"{S}/plan", json={"features": {"max_functions": 3, "edge_functions": False}})
    off = {"enabled": False, "on_error": "origin", "items": []}
    assert edge_get(client, token, "/edge/v1/config").json()["sites"][0]["functions"] == off
    client.patch(f"{S}/plan", json={"features": {"edge_functions": True}})
    client.post(f"{S}/suspend")
    assert edge_get(client, token, "/edge/v1/config").json()["sites"][0]["functions"] == off
    client.post(f"{S}/unsuspend")
    assert edge_get(client, token, "/edge/v1/config").json()["sites"][0]["functions"]["enabled"] is True
    body["enabled"] = False
    assert put(client, body).status_code == 200
    assert edge_get(client, token, "/edge/v1/config").json()["sites"][0]["functions"] == off


def test_accepted_sections_are_never_skipped_by_the_edge(agent):
    """Unit parity over tricky but valid routes: what the model accepts, norm_functions keeps."""
    routes = ["/", "/a", "/a/", "/a.b/c~d_e-f", "/" + "a" * 255, "/.well-known/x", "/a/...", "/a..b"]
    items = [{"id": f"f{i}", "route": r, "code": "x"} for i, r in enumerate(routes)]
    value = sections.dump(sections.Functions.model_validate({"enabled": True, "items": items}))
    from types import SimpleNamespace

    from app import services
    site = SimpleNamespace(effective_status="active")
    feats = {"edge_functions": True, "max_functions": 32}
    edge_site = {"id": 1, "status": "active", "functions": services.functions_for_edge(site, value, feats)}
    assert [f["route"] for f in agent.norm_functions(edge_site, ())] == routes


# ------------------------------------------------------------------ audit

def test_audit_has_ids_and_sizes_but_no_code(client):
    make_site(client, edge_functions=True, max_functions=5)
    assert put(client, {"enabled": True, "items": [fn("auth", "/api/"), fn("b", "/b", enabled=False)]}).status_code == 200
    entry = client.get("/api/v1/audit", params={"action": "config.update"}).json()[0]
    assert entry["detail"] == {"section": "functions", "enabled": True, "count": 2, "items": [
        {"id": "auth", "route": "/api/", "enabled": True, "code_bytes": len(CODE)},
        {"id": "b", "route": "/b", "enabled": False, "code_bytes": len(CODE)}]}
    assert "Response" not in json.dumps(entry)
    # other sections keep the plain detail
    client.put(f"{S}/config/video", json={"enabled": True})
    assert client.get("/api/v1/audit", params={"action": "config.update"}).json()[0]["detail"] == {"section": "video"}


def test_capi_functions_write_and_audit(client):
    make_site(client, edge_functions=True, max_functions=5)
    key = client.post(f"{S}/apikeys", json={"name": "ci", "scopes": ["dns"]}).json()["key"]
    h = {"Authorization": f"Bearer {key}"}
    r = client.put("/capi/v1/config/functions", json={"enabled": True, "items": [fn()]}, headers=h)
    assert r.status_code == 200 and r.json()["items"][0]["code"] == CODE
    assert client.get("/capi/v1/config/functions", headers=h).json()["items"][0]["code_bytes"] == len(CODE)
    entry = client.get("/api/v1/audit", params={"action": "config.update"}).json()[0]
    assert entry["actor"] == "ci" and entry["detail"]["count"] == 1 and CODE not in json.dumps(entry)
    assert client.put("/capi/v1/config/functions", json={"enabled": True, "items": [fn(route="/__pcdn")]},
                      headers=h).status_code == 422


# ------------------------------------------------------------------ usage + stats

def post_usage(client, token, items):
    return client.post("/edge/v1/usage", json={"items": items}, headers={"Authorization": f"Bearer {token}"})


def test_usage_ingestion_and_stats(client):
    make_site(client, edge_functions=True, max_functions=5)
    token = add_edge(client)
    now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    prev = now - timedelta(hours=2)
    items = [
        {"host": "example.com", "hour": now.isoformat(), "bytes": 100, "requests": 2,
         "functions": {"invocations": 10, "cpu_ms": 55, "errors": 1, "timeouts": 1}},
        {"host": "www.example.com", "hour": now.isoformat(), "bytes": 0, "requests": 0,
         "functions": {"invocations": 5, "cpu_ms": 5, "future": 3}},
        {"host": "example.com", "hour": prev.isoformat(), "bytes": 0, "requests": 0,
         "functions": {"invocations": 5, "cpu_ms": 1, "errors": 0, "timeouts": 2}},
        {"host": "example.com", "hour": prev.isoformat(), "bytes": 7, "requests": 1},   # optional
    ]
    assert post_usage(client, token, items).status_code == 200
    assert post_usage(client, token, items[:1]).status_code == 200    # merges into the same row
    # functions are not billed as bytes
    assert client.get("/api/v1/usage").json()["sites"][0]["bytes"] == 207
    st = client.get(f"{S}/functions/stats").json()
    assert (st["hours"], st["invocations"], st["cpu_ms"], st["errors"], st["timeouts"]) == (24, 30, 116, 2, 4)
    assert st["error_pct"] == 20.0 and len(st["series"]) == 24
    assert st["series"][-1] == {"t": now.strftime("%Y-%m-%dT%H:00:00Z"), "invocations": 25, "errors": 2,
                                "timeouts": 2, "cpu_ms": 115}
    assert st["series"][-3] == {"t": prev.strftime("%Y-%m-%dT%H:00:00Z"), "invocations": 5, "errors": 0,
                                "timeouts": 2, "cpu_ms": 1}
    assert st["series"][0]["invocations"] == 0
    one = client.get(f"{S}/functions/stats", params={"hours": 1}).json()
    assert one["invocations"] == 25 and len(one["series"]) == 1 and one["error_pct"] == 16.0
    for h in (0, 745, -1):
        assert client.get(f"{S}/functions/stats", params={"hours": h}).status_code == 422
    assert len(client.get(f"{S}/functions/stats", params={"hours": 744}).json()["series"]) == 744
    assert client.get("/api/v1/sites/nope.com/functions/stats").status_code == 404
    # malformed counters -> 422 like every other usage counter
    for bad in ({"invocations": -1}, {"cpu_ms": 1.5}, {"errors": "3"}, {"timeouts": True}, 5):
        r = post_usage(client, token, [{"host": "example.com", "hour": now.isoformat(), "bytes": 0,
                                        "requests": 0, "functions": bad}])
        assert r.status_code == 422, bad


def test_stats_empty_site(client):
    make_site(client)
    st = client.get(f"{S}/functions/stats", params={"hours": 3}).json()
    assert st["invocations"] == 0 and st["error_pct"] == 0 and [p["cpu_ms"] for p in st["series"]] == [0, 0, 0]


def test_capi_stats_scope(client):
    make_site(client, edge_functions=True, max_functions=5)
    token = add_edge(client)
    now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    post_usage(client, token, [{"host": "example.com", "hour": now.isoformat(), "bytes": 0, "requests": 0,
                                "functions": {"invocations": 4, "cpu_ms": 8, "errors": 1, "timeouts": 0}}])
    stats_key = client.post(f"{S}/apikeys", json={"name": "s", "scopes": ["stats"]}).json()["key"]
    dns_key = client.post(f"{S}/apikeys", json={"name": "d", "scopes": ["dns"]}).json()["key"]
    r = client.get("/capi/v1/functions/stats", headers={"Authorization": f"Bearer {stats_key}"})
    assert r.status_code == 200 and r.json() == client.get(f"{S}/functions/stats").json()
    assert r.json()["error_pct"] == 25.0
    assert client.get("/capi/v1/functions/stats?hours=745",
                      headers={"Authorization": f"Bearer {stats_key}"}).status_code == 422
    assert client.get("/capi/v1/functions/stats", headers={"Authorization": f"Bearer {dns_key}"}).status_code == 403
    paths = client.get("/capi/v1/openapi.json").json()["paths"]
    assert "/capi/v1/functions/stats" in paths


# ------------------------------------------------------------------ capability

def test_heartbeat_edge_functions_capability(client):
    token = add_edge(client)
    h = {"Authorization": f"Bearer {token}"}
    assert client.post("/edge/v1/heartbeat", headers=h, json={"capabilities": {"l4": True}}).status_code == 200
    assert client.get("/api/v1/edges").json()[0]["capabilities"]["edge_functions"] is False
    client.post("/edge/v1/heartbeat", headers=h, json={"capabilities": {"edge_functions": True}})
    assert client.get("/api/v1/edges").json()[0]["capabilities"]["edge_functions"] is True
