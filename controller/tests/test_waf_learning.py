"""SPEC §17 controller side: WAF learning mode — the managed `waf.learning` window, the scheduler
ending it, `waf_learn` usage ingestion (validated + bounded), the proposal engine, apply
(validation, audit, idempotency), plan interactions and the customer API."""

import json
import random
from datetime import datetime, timedelta, timezone

import pytest

from app import routes_capi, sections, waf_learning
from app.db import SessionLocal
from app.models import Site, UsageHourly, utcnow
from tests.test_api import add_edge, edge_get

S = "/api/v1/sites/example.com"
CAPI = "/capi/v1"


@pytest.fixture(autouse=True)
def _reset_rate():
    routes_capi._hits.clear()
    routes_capi._config_hits.clear()
    yield
    routes_capi._hits.clear()
    routes_capi._config_hits.clear()


# ------------------------------------------------------------------ helpers

def mk_site(client, domain="example.com", **features):
    r = client.post("/api/v1/sites", json={"domain": domain, "origin_ip": "93.184.216.34",
                                           "plan": {"features": features}})
    assert r.status_code == 201, r.text


def put_waf(client, body, domain="example.com"):
    return client.put(f"/api/v1/sites/{domain}/config/waf", json=body)


def start(client, days=7, **waf):
    r = put_waf(client, {"mode": "detect", **waf, "learning": {"enabled": True, "days": days}})
    assert r.status_code == 200, r.text
    return r.json()


def hour_now():
    return datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)


def post_usage(client, token, waf_learn, host="example.com", requests=100, hour=None):
    item = {"host": host, "hour": (hour or hour_now()).isoformat(), "bytes": 1000, "requests": requests,
            "waf_learn": waf_learn}
    return client.post("/edge/v1/usage", json={"items": [item]}, headers={"Authorization": f"Bearer {token}"})


def stored_learn(domain="example.com"):
    with SessionLocal() as db:
        site = db.query(Site).filter_by(domain=domain).one()
        out = {}
        for row in db.query(UsageHourly).filter_by(site_id=site.id):
            d = json.loads(row.details or "{}")
            if "waf_learn" in d:
                out = waf_learning.merge(out, d["waf_learn"], waf_learning.AGG_CAPS)
        return out


def learning(client):
    r = client.get(f"{S}/waf/learning")
    assert r.status_code == 200, r.text
    return r.json()


def by_kind(rep, kind):
    return [p for p in rep["proposals"] if p["kind"] == kind]


# synthetic learning data: one FP rule, rules below each threshold, rate-limit prefixes
SYNTH = {
    "rules": {
        # FP: 100 / 10000 = 1% of /api/v1, 25 distinct clients, no attack signal -> exclusion
        "942100": {"hits": 100, "clients": 25, "paths": {"/api/v1": {"hits": 100, "clients": 25}},
                   "methods": {"POST": 100}},
        # too few distinct clients
        "941100": {"hits": 100, "clients": 10, "paths": {"/api/v1": 100}},
        # 10 / 10000 = 0.1% < 0.5%
        "942190": {"hits": 10, "clients": 30, "paths": {"/api/v1": 10}},
        # other attack signals on those requests
        "930100": {"hits": 200, "clients": 50, "attack": 3, "paths": {"/api/v1": {"hits": 200, "attack": 3}}},
        # prefix not among the reported paths (ratio unknown)
        "932100": {"hits": 50, "clients": 50, "paths": {"/unknown": 50}},
    },
    "paths": {
        "/api/v1": {"req": 10000, "max_rpm": 40, "p95_rpm": 15, "methods": {"GET": 9000, "POST": 1000}},
        "/small": {"req": 500, "max_rpm": 100, "p95_rpm": 50},          # < 1000 requests: no limit
        "/low": {"req": 2000, "max_rpm": 5, "p95_rpm": 2},              # floor of 30 rpm
        "/p95": {"req": 5000, "max_rpm": 30, "p95_rpm": 25},            # 3 x p95 wins: 75
    },
    "clients": {"max_rpm": 40, "p95_rpm": 12},
}


# ------------------------------------------------------------------ the learning window

def test_enable_sets_controller_managed_window(client):
    mk_site(client)
    before = utcnow().replace(microsecond=0)
    # client-sent started_at / until are ignored
    r = put_waf(client, {"mode": "off", "learning": {"enabled": True, "days": 3,
                                                       "until": "2099-01-01T00:00:00Z",
                                                       "started_at": "2000-01-01T00:00:00Z"}})
    assert r.status_code == 200, r.text
    ln = r.json()["learning"]
    start, until = waf_learning.parse_iso(ln["started_at"]), waf_learning.parse_iso(ln["until"])
    assert ln["enabled"] is True and ln["days"] == 3 and ln["started_at"].endswith("Z")
    assert before <= start <= utcnow() and until - start == timedelta(days=3)
    rep = learning(client)
    assert rep["state"] == "learning" and rep["started_at"] == ln["started_at"] and rep["until"] == ln["until"]
    assert rep["proposals"] == [] and rep["requests_observed"] == 0 and 0 <= rep["progress"] < 0.01

    # re-saving the section (e.g. another paranoia) keeps the window
    r = put_waf(client, {"mode": "detect", "paranoia": 2, "learning": {"enabled": True, "days": 3}})
    assert r.json()["learning"]["started_at"] == ln["started_at"] and r.json()["learning"]["until"] == ln["until"]
    # changing days moves `until` relative to started_at
    r = put_waf(client, {"mode": "detect", "learning": {"enabled": True, "days": 10}})
    assert waf_learning.parse_iso(r.json()["learning"]["until"]) - start == timedelta(days=10)
    # default days 7; bounds 1..30
    assert put_waf(client, {"learning": {"enabled": True, "days": 0}}).status_code == 422
    assert put_waf(client, {"learning": {"enabled": True, "days": 31}}).status_code == 422
    assert put_waf(client, {"learning": {"enabled": True, "extra": 1}}).status_code == 422

    # edge config: SPEC §17.1 {enabled, until} only
    cfg = edge_get(client, add_edge(client), "/edge/v1/config").json()
    w = next(s for s in cfg["sites"] if s["domain"] == "example.com")["waf"]
    assert w["learning"] == {"enabled": True, "until": r.json()["learning"]["until"]}

    # stop: until = now, state learned, started_at kept
    r = put_waf(client, {"mode": "detect", "learning": {"enabled": False}})
    ln2 = r.json()["learning"]
    assert ln2["enabled"] is False and ln2["started_at"] == ln["started_at"]
    assert waf_learning.parse_iso(ln2["until"]) <= utcnow()
    assert learning(client)["state"] == "learned" and learning(client)["progress"] == 1.0
    # a later save without learning keeps the learned window (the proposals stay available)
    r = put_waf(client, {"mode": "block"})
    assert r.json()["learning"]["started_at"] == ln["started_at"] and learning(client)["state"] == "learned"
    cfg = edge_get(client, add_edge(client, name="e2", ip="5.160.1.11"), "/edge/v1/config").json()
    assert next(s for s in cfg["sites"] if s["domain"] == "example.com")["waf"]["learning"] == \
        {"enabled": False, "until": None}
    # starting again opens a new window
    r = put_waf(client, {"mode": "block", "learning": {"enabled": True}})
    assert r.json()["learning"]["enabled"] is True and r.json()["learning"]["days"] == 7
    assert waf_learning.parse_iso(r.json()["learning"]["started_at"]) >= start


def test_fresh_site_state_off(client):
    mk_site(client)
    rep = learning(client)
    assert rep == {"state": "off", "enabled": False, "days": 7, "started_at": None, "until": None,
                   "progress": 0.0, "requests_observed": 0, "proposals": []}
    assert client.get(f"{S}/config/waf").json()["learning"] == \
        {"enabled": False, "days": 7, "until": None, "started_at": None}


def test_plan_without_waf_cannot_learn(client):
    mk_site(client, waf=False)
    r = put_waf(client, {"mode": "off", "learning": {"enabled": True}})
    assert r.status_code == 403
    assert put_waf(client, {"mode": "off", "learning": {"enabled": False}}).status_code == 200
    # plan loses the WAF while learning: the edges stop learning
    client.patch(f"{S}/plan", json={"features": {"waf": True}})
    start(client)
    client.patch(f"{S}/plan", json={"features": {"waf": False}})
    cfg = edge_get(client, add_edge(client), "/edge/v1/config").json()
    w = next(s for s in cfg["sites"] if s["domain"] == "example.com")["waf"]
    assert w["mode"] == "off" and w["learning"] == {"enabled": False, "until": None}


def test_job_ends_learning(client):
    from app import scheduler

    mk_site(client)
    mk_site(client, domain="other.org")
    start(client, days=1)
    with SessionLocal() as db:
        assert scheduler.job_waf_learning(db) == []  # not over yet
        ended = scheduler.job_waf_learning(db, utcnow() + timedelta(days=1, minutes=1))
    assert ended == ["example.com"]
    rep = learning(client)
    assert rep["state"] == "learned" and rep["enabled"] is False
    assert client.get(f"{S}/config/waf").json()["learning"]["enabled"] is False
    a = client.get("/api/v1/audit", params={"action": "waf.learning.end"}).json()
    assert a[0]["target"] == "example.com" and a[0]["actor_kind"] == "system"
    with SessionLocal() as db:  # idempotent
        assert scheduler.job_waf_learning(db, utcnow() + timedelta(days=2)) == []
    assert scheduler.job_waf_learning in scheduler.JOBS


def test_expired_window_is_not_restarted_by_a_resave(client, monkeypatch):
    mk_site(client)
    ln = start(client, days=1)["learning"]
    later = utcnow() + timedelta(days=1, hours=1)
    monkeypatch.setattr(waf_learning, "utcnow", lambda: later)
    r = put_waf(client, {"mode": "detect", "learning": {"enabled": True, "days": 1}})
    out = r.json()["learning"]
    assert out["enabled"] is False and out["started_at"] == ln["started_at"] and out["until"] == ln["until"]


# ------------------------------------------------------------------ ingestion (SPEC §17.1)

def test_ingestion_validates_and_bounds(client):
    mk_site(client)
    start(client)
    token = add_edge(client)
    rules = {str(942000 + i): {"hits": i + 1} for i in range(150)}
    rules.update({"abc": {"hits": 5}, "0": {"hits": 5}, "12345678": {"hits": 5}})
    rules["942100"] = {"hits": 1000, "clients": 30, "attack": 0,
                       "paths": {"/a/b/c": 40, "/a/b/d": {"hits": 60, "clients": 9}, "*": 1, "nope": 1,
                                 "/x/../y": 1, **{f"/p{i}": i + 1 for i in range(20)}},
                       "methods": {"post": 3, "GET": 2, "bad method": 1, **{f"M{c}": 1 for c in "ABCDEFGHIJKL"}}}
    paths = {f"/q{i}": {"req": i + 1, "max_rpm": 1} for i in range(80)}
    paths["/api/v1/users"] = {"req": 700, "max_ip_rpm": 12, "p95_rps_min": 12, "p95_rpm": 4}
    paths["/api/v1/items"] = {"req": 300, "p95_rps_min": 20, "p95_rpm": 2}
    paths["/q?x=1"] = {"req": 5}
    r = post_usage(client, token, {"rules": rules, "paths": paths, "clients": {"max_rpm": 20, "p95_rpm": 3},
                                   "unknown": {"x": 1}})
    assert r.status_code == 200, r.text
    st = stored_learn()
    assert len(st["rules"]) == 100 and "0" not in st["rules"] and "12345678" not in st["rules"]
    assert all(k.isdigit() for k in st["rules"])
    r942 = st["rules"]["942100"]
    assert r942["hits"] == 1000 and r942["clients"] == 30
    assert len(r942["paths"]) == 10 and r942["paths"]["/a/b"] == {"hits": 100, "attack": 0, "clients": 9}
    assert "*" not in r942["paths"] and "nope" not in r942["paths"]
    assert len(r942["methods"]) == 10 and r942["methods"]["POST"] == 3
    assert len(st["paths"]) == 50
    # '/api/v1/users' and '/api/v1/items' fold into '/api/v1'; max_ip_rpm / p95_rps_min (SPEC: the
    # max per-client rpm) are read as max_rpm
    assert st["paths"]["/api/v1"] == {"req": 1000, "max_rpm": 20, "p95_rpm": 4, "methods": {}}
    assert st["clients"] == {"max_rpm": 20, "p95_rpm": 3}

    # a second batch of the same hour merges: counts add, rates / distinct clients keep the max
    r = post_usage(client, token, {"rules": {"942100": {"hits": 1, "clients": 3}},
                                   "paths": {"/api/v1": {"req": 5, "max_rpm": 99}}})
    assert r.status_code == 200
    st = stored_learn()
    assert st["rules"]["942100"]["hits"] == 1001 and st["rules"]["942100"]["clients"] == 30
    assert st["paths"]["/api/v1"]["req"] == 1005 and st["paths"]["/api/v1"]["max_rpm"] == 99


@pytest.mark.parametrize("bad", [
    {"rules": {"942100": {"hits": -1}}},
    {"rules": {"942100": {"hits": "many"}}},
    {"rules": {"942100": {"paths": {"/a": -3}}}},
    {"paths": {"/a": {"req": "x"}}},
    {"paths": {"/a": {"req": 1, "methods": {"GET": -1}}}},
    {"clients": {"max_rpm": -5}},
    {"rules": ["942100"]},
    {"paths": "nope"},
    "not-an-object",
])
def test_ingestion_wrong_types_422(client, bad):
    mk_site(client)
    start(client)
    token = add_edge(client)
    assert post_usage(client, token, bad).status_code == 422


def test_ingestion_dropped_for_sites_not_learning(client):
    mk_site(client)
    token = add_edge(client)
    data = {"rules": {"942100": {"hits": 5}}, "paths": {"/a": {"req": 10}}}
    r = post_usage(client, token, data)
    assert r.status_code == 200 and r.json()["accepted"] == 1  # the usage itself is billed
    assert stored_learn() == {}
    # learning: an hour before the window started is dropped, the current hour kept
    start(client)
    assert post_usage(client, token, data, hour=hour_now() - timedelta(hours=3)).status_code == 200
    assert stored_learn() == {}
    assert post_usage(client, token, data).status_code == 200
    assert stored_learn()["rules"]["942100"]["hits"] == 5
    # usage items without waf_learn (pre-§17 agents) keep working
    r = client.post("/edge/v1/usage", json={"items": [{"host": "example.com", "hour": hour_now().isoformat(),
                                                       "bytes": 1, "requests": 1, "waf_learn": None}]},
                    headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200


# ------------------------------------------------------------------ proposals (SPEC §17.2)

def test_proposals_on_synthetic_data(client):
    mk_site(client, max_ratelimit_rules=10)
    start(client)
    token = add_edge(client)
    assert post_usage(client, token, SYNTH, requests=17500).status_code == 200
    rep = learning(client)
    assert rep["state"] == "learning" and rep["requests_observed"] == 17500

    ex = by_kind(rep, "waf_exclusion")
    assert len(ex) == 1
    p = ex[0]
    assert p["change"] == {"section": "waf", "op": "add_exclusion", "value": {"rule_id": 942100, "path": "/api/v1*"}}
    assert p["id"] == waf_learning.proposal_id("waf_exclusion", "942100|/api/v1*")
    assert 0.5 <= p["confidence"] <= 1 and p["applied"] is False
    assert "942100" in p["summary"] and "/api/v1*" in p["detail"]
    assert any("؀" <= ch <= "ۿ" for ch in p["summary"])  # Persian
    assert p["evidence"] == {"rule_id": 942100, "path_prefix": "/api/v1", "hits": 100, "requests": 10000,
                             "ratio": 0.01, "clients": 25}

    rl = {q["change"]["value"]["path"]: q for q in by_kind(rep, "rate_limit")}
    assert set(rl) == {"/api/v1*", "/low*", "/p95*"}  # /small has < 1000 requests
    rule = rl["/api/v1*"]["change"]["value"]
    # max(3 x 15, 1.5 x 40, 30) = 60
    assert rule["requests"] == 60 and rule["period"] == 60 and rule["action"] == "challenge"
    assert rule["methods"] == [] and rule["enabled"] is True and rule["id"].startswith("learn-")
    assert rl["/low*"]["change"]["value"]["requests"] == 30   # never below 30 rpm
    assert rl["/p95*"]["change"]["value"]["requests"] == 75   # 3 x 25 > 1.5 x 30
    assert rl["/api/v1*"]["change"]["section"] == "ratelimit" and rl["/api/v1*"]["change"]["op"] == "add_rule"
    assert by_kind(rep, "pack_off") == []
    # ids are deterministic across reads
    assert [q["id"] for q in learning(client)["proposals"]] == [q["id"] for q in rep["proposals"]]


def test_thresholds_not_met_no_proposals(client):
    mk_site(client)
    start(client)
    token = add_edge(client)
    data = {"rules": {"942100": {"hits": 49, "clients": 100, "paths": {"/a": 49}},     # 0.49 %
                      "941100": {"hits": 500, "clients": 19, "paths": {"/a": 500}},    # 19 clients
                      "942190": {"hits": 500, "paths": {"/a": 500}},                   # clients unknown
                      "930100": {"hits": 500, "clients": 99, "attack": 1,              # attack, unattributed
                                 "paths": {"/a": 500}}},
            "paths": {"/a": {"req": 10000},                     # no per-client rate reported
                      "/b": {"req": 999, "max_rpm": 50}}}       # < 1000 requests
    assert post_usage(client, token, data).status_code == 200
    rep = learning(client)
    assert rep["proposals"] == []


def test_root_prefix_and_one_segment_rate_limit_patterns(client):
    mk_site(client, max_ratelimit_rules=10)
    start(client)
    token = add_edge(client)
    data = {"rules": {"941110": {"hits": 100, "clients": 40, "paths": {"/": 100}}},
            "paths": {"/": {"req": 2000, "max_rpm": 10}, "/shop": {"req": 2000, "max_rpm": 10},
                      "/shop/cart": {"req": 2000, "max_rpm": 10}}}
    assert post_usage(client, token, data).status_code == 200
    rep = learning(client)
    assert by_kind(rep, "waf_exclusion")[0]["change"]["value"] == {"rule_id": 941110, "path": "/"}
    paths = sorted(p["change"]["value"]["path"] for p in by_kind(rep, "rate_limit"))
    # '/' = the home page only; '/shop' has deeper prefixes observed -> exact path
    assert paths == ["/", "/shop", "/shop/cart*"]


def test_pack_off(client):
    mk_site(client)
    start(client, packs=["wordpress", "generic"])
    token = add_edge(client)
    data = {"rules": {
        # every wordpress hit is FP-like and covered by exclusion proposals
        "991130": {"hits": 300, "clients": 40, "paths": {"/blog": {"hits": 200, "clients": 40},
                                                         "/news": {"hits": 100, "clients": 30}}},
        # a generic rule with an attack signal: the generic pack stays
        "990100": {"hits": 100, "clients": 40, "attack": 1, "paths": {"/blog": {"hits": 100, "attack": 1}}},
    }, "paths": {"/blog": {"req": 10000}, "/news": {"req": 5000}}}
    assert post_usage(client, token, data).status_code == 200
    rep = learning(client)
    packs = by_kind(rep, "pack_off")
    assert [p["change"] for p in packs] == [{"section": "waf", "op": "remove_pack", "value": "wordpress"}]
    assert packs[0]["id"] == waf_learning.proposal_id("pack_off", "wordpress")
    assert {p["change"]["value"]["path"] for p in by_kind(rep, "waf_exclusion")} == {"/blog*", "/news*"}

    # a hit not covered by an exclusion proposal (a prefix outside the reported top paths) -> no pack_off
    data2 = {"rules": {"991160": {"hits": 5, "clients": 40, "paths": {"/elsewhere": 5}}}}
    assert post_usage(client, token, data2).status_code == 200
    assert by_kind(learning(client), "pack_off") == []


# ------------------------------------------------------------------ apply

def _learned_site(client, **features):
    mk_site(client, **{"max_ratelimit_rules": 10, **features})
    start(client, packs=["wordpress"])
    token = add_edge(client)
    data = json.loads(json.dumps(SYNTH))
    data["rules"]["991130"] = {"hits": 200, "clients": 40, "paths": {"/api/v1": {"hits": 200, "clients": 40}}}
    assert post_usage(client, token, data).status_code == 200
    return learning(client)


def test_apply_and_idempotency(client):
    rep = _learned_site(client)
    ids = [p["id"] for p in rep["proposals"]]
    kinds = {p["kind"] for p in rep["proposals"]}
    assert kinds == {"waf_exclusion", "rate_limit", "pack_off"}
    r = client.post(f"{S}/waf/learning/apply", json={"ids": ids})
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["applied"] == ids and out["unchanged"] == [] and out["changed"] == ["ratelimit", "waf"]
    waf = out["sections"]["waf"]
    assert {"rule_id": 942100, "path": "/api/v1*"} in waf["exclusions"]
    assert {"rule_id": 991130, "path": "/api/v1*"} in waf["exclusions"]
    assert waf["packs"] == [] and waf["learning"]["enabled"] is True  # learning untouched
    assert len(out["sections"]["ratelimit"]["rules"]) == 3
    assert client.get(f"{S}/config/waf").json() == waf
    a = client.get("/api/v1/audit", params={"action": "waf.learning.apply"}).json()
    assert len(a) == 1 and a[0]["detail"]["items"] == ids and a[0]["detail"]["section"] == "ratelimit,waf"

    # proposals stay listed as applied; applying again changes nothing
    rep2 = learning(client)
    assert [p["id"] for p in rep2["proposals"]] == [p["id"] for p in rep["proposals"]]
    assert all(p["applied"] for p in rep2["proposals"])
    r = client.post(f"{S}/waf/learning/apply", json={"ids": ids + ids[:1]})
    assert r.status_code == 200 and r.json()["applied"] == [] and r.json()["unchanged"] == ids
    assert r.json()["sections"] == out["sections"]
    assert len(client.get("/api/v1/audit", params={"action": "waf.learning.apply"}).json()) == 1

    # unknown id: 422, nothing applied
    r = client.post(f"{S}/waf/learning/apply", json={"ids": ["p_0000000000000000"]})
    assert r.status_code == 422 and "p_0000000000000000" in r.text
    assert client.post(f"{S}/waf/learning/apply", json={"ids": []}).status_code == 422


def test_apply_subset_only(client):
    rep = _learned_site(client)
    one = by_kind(rep, "rate_limit")[0]
    r = client.post(f"{S}/waf/learning/apply", json={"ids": [one["id"]]})
    assert r.status_code == 200 and r.json()["changed"] == ["ratelimit"]
    assert client.get(f"{S}/config/ratelimit").json()["rules"] == [one["change"]["value"]]
    assert client.get(f"{S}/config/waf").json()["exclusions"] == []
    applied = {p["id"]: p["applied"] for p in learning(client)["proposals"]}
    assert applied[one["id"]] is True and sum(applied.values()) == 1


def test_never_auto_applied(client):
    from app import scheduler

    _learned_site(client)
    with SessionLocal() as db:
        scheduler.job_waf_learning(db, utcnow() + timedelta(days=30))
    rep = learning(client)
    assert rep["state"] == "learned" and rep["proposals"] and not any(p["applied"] for p in rep["proposals"])
    assert client.get(f"{S}/config/waf").json()["exclusions"] == []
    assert client.get(f"{S}/config/ratelimit").json()["rules"] == []


# ------------------------------------------------------------------ plan / feature interactions

def test_plan_limits_and_existing_rules(client):
    mk_site(client, max_ratelimit_rules=2)
    client.put(f"{S}/config/ratelimit", json={"rules": [
        {"id": "mine", "path": "/p95*", "requests": 10, "period": 60}]})
    client.put(f"{S}/config/waf", json={"exclusions": [{"rule_id": 0, "path": "/api/v1*"}]})
    start(client, exclusions=[{"rule_id": 0, "path": "/api/v1*"}])
    token = add_edge(client)
    assert post_usage(client, token, SYNTH).status_code == 200
    rep = learning(client)
    # the customer's own exclusion (all rules on /api/v1*) already covers the FP rule
    assert by_kind(rep, "waf_exclusion") == []
    # /p95* is already rate limited by the customer; one free slot -> the busiest prefix only
    assert [p["change"]["value"]["path"] for p in by_kind(rep, "rate_limit")] == ["/api/v1*"]
    r = client.post(f"{S}/waf/learning/apply", json={"ids": [p["id"] for p in rep["proposals"]]})
    assert r.status_code == 200 and len(r.json()["sections"]["ratelimit"]["rules"]) == 2

    # plan shrinks afterwards: no new rate-limit proposals, the applied one stays listed
    client.patch(f"{S}/plan", json={"features": {"max_ratelimit_rules": 0}})
    assert [p["applied"] for p in by_kind(learning(client), "rate_limit")] == [True]


def test_stale_proposal_after_plan_change(client):
    mk_site(client, max_ratelimit_rules=5)
    start(client)
    assert post_usage(client, add_edge(client), SYNTH).status_code == 200
    ids = [p["id"] for p in by_kind(learning(client), "rate_limit")]
    client.patch(f"{S}/plan", json={"features": {"max_ratelimit_rules": 0}})
    # no longer proposed (the plan has no free slot): refused, nothing applied
    r = client.post(f"{S}/waf/learning/apply", json={"ids": ids})
    assert r.status_code == 422
    assert client.get(f"{S}/config/ratelimit").json()["rules"] == []


def test_edge_wire_shape(client):
    """The edge agent's wire shape (edge/pcdn_agent/usage.py waf_learn_item): per prefix
    {req, max_ip_rpm, p95_rps_min, methods}, per rule {hits, paths: {prefix: n}, methods} without
    distinct-client counts -> rate limits are proposed, exclusions are not (the ≥ 20 distinct
    clients condition of SPEC §17.2 cannot be checked)."""
    mk_site(client)
    start(client)
    wire = {"rules": {"942100": {"hits": 500, "paths": {"/api/v1": 500}, "methods": {"POST": 499, "OTHER": 1}}},
            "paths": {"/api/v1": {"req": 5000, "max_ip_rpm": 40, "p95_rps_min": 40,
                                  "methods": {"GET": 4000, "POST": 999, "OTHER": 1}}},
            "clients": {"max_rpm": 40, "p95_rpm": 9}}
    assert post_usage(client, add_edge(client), wire).status_code == 200
    st = stored_learn()
    assert st["paths"]["/api/v1"]["max_rpm"] == 40 and st["paths"]["/api/v1"]["methods"]["OTHER"] == 1
    rep = learning(client)
    assert by_kind(rep, "waf_exclusion") == []
    assert [p["change"]["value"]["requests"] for p in by_kind(rep, "rate_limit")] == [60]
    # with distinct clients reported the same data yields the exclusion
    wire["rules"]["942100"]["clients"] = 21
    assert post_usage(client, add_edge(client, name="e2", ip="5.160.1.11"), wire).status_code == 200
    assert len(by_kind(learning(client), "waf_exclusion")) == 1


def test_waf_feature_off_only_rate_limits(client):
    _learned_site(client)
    client.patch(f"{S}/plan", json={"features": {"waf": False}})
    rep = learning(client)
    assert {p["kind"] for p in rep["proposals"]} == {"rate_limit"}
    r = client.post(f"{S}/waf/learning/apply", json={"ids": [p["id"] for p in rep["proposals"]]})
    assert r.status_code == 200, r.text


def test_exclusion_slots_capped_at_100(client):
    mk_site(client)
    start(client, exclusions=[{"rule_id": 900000 + i, "path": f"/x{i}"} for i in range(99)])
    token = add_edge(client)
    data = {"rules": {str(942100 + i): {"hits": 100 + i, "clients": 30, "paths": {"/a": 100 + i}} for i in range(5)},
            "paths": {"/a": {"req": 1000}}}
    assert post_usage(client, token, data).status_code == 200
    ex = by_kind(learning(client), "waf_exclusion")
    assert len(ex) == 1 and ex[0]["change"]["value"]["rule_id"] == 942104  # the busiest
    assert client.post(f"{S}/waf/learning/apply", json={"ids": [ex[0]["id"]]}).status_code == 200


def test_proposals_always_validate_fuzz(client):
    """Random learning data: every proposal, applied alone and all together, passes the section
    validators."""
    mk_site(client, max_ratelimit_rules=1000)
    start(client, packs=list(sections.WAF_PACKS))
    token = add_edge(client)
    rnd = random.Random(1717)
    seg = ["a", "api", "v1", "wp-admin", "x.php", "%7Euser", "b-c", "~t", "s;p", "q=1", "@me", "(x)", "!"]
    for _ in range(6):
        prefixes = ["/" + "/".join(rnd.choice(seg) for _ in range(rnd.randint(0, 3))) for _ in range(30)]
        ids = list(range(1, 10_000_000, 9973))[:40] + [990100, 991130, 992100, 993100, 994100, 995150]
        rules = {}
        for rid in rnd.sample(ids, 30):
            ps = {p: {"hits": rnd.randint(0, 5000), "clients": rnd.randint(0, 200)} for p in rnd.sample(prefixes, 5)}
            rules[str(rid)] = {"hits": sum(v["hits"] for v in ps.values()), "clients": rnd.randint(0, 300),
                               "paths": ps}
        paths = {p: {"req": rnd.randint(0, 200_000), "max_rpm": rnd.randint(0, 10**7),
                     "p95_rpm": rnd.randint(0, 10**6)} for p in prefixes}
        assert post_usage(client, token, {"rules": rules, "paths": paths}).status_code == 200
    rep = learning(client)
    assert len(by_kind(rep, "waf_exclusion")) > 5 and len(by_kind(rep, "rate_limit")) > 5
    with SessionLocal() as db:
        site = db.query(Site).filter_by(domain="example.com").one()
        for p in rep["proposals"]:
            ch = p["change"]
            cur = sections.storable(ch["section"], sections.get_section(site, ch["section"]))
            if ch["op"] == "add_exclusion":
                cur["exclusions"] = (cur["exclusions"] + [ch["value"]])[-100:]
            elif ch["op"] == "remove_pack":
                cur["packs"] = [k for k in cur["packs"] if k != ch["value"]]
            else:
                assert 30 <= ch["value"]["requests"] <= 1_000_000
                cur["rules"] = cur["rules"] + [ch["value"]]
            sections.validate_section(site, ch["section"], cur)  # raises on a rejected proposal
    r = client.post(f"{S}/waf/learning/apply", json={"ids": [p["id"] for p in rep["proposals"]]})
    assert r.status_code == 200, r.text
    assert len(r.json()["sections"]["waf"]["exclusions"]) <= 100


# ------------------------------------------------------------------ customer API

def new_key(client, scopes):
    r = client.post(f"{S}/apikeys", json={"name": "k", "scopes": list(scopes)})
    assert r.status_code == 201, r.text
    return {"Authorization": f"Bearer {r.json()['key']}"}


def test_capi_scopes(client):
    rep = _learned_site(client)
    stats = new_key(client, ["stats"])
    config = new_key(client, ["config"])
    r = client.get(f"{CAPI}/waf/learning", headers=stats)
    assert r.status_code == 200 and r.json() == rep
    assert client.get(f"{CAPI}/waf/learning", headers=config).status_code == 403
    ids = [rep["proposals"][0]["id"]]
    assert client.post(f"{CAPI}/waf/learning/apply", json={"ids": ids}, headers=stats).status_code == 403
    r = client.post(f"{CAPI}/waf/learning/apply", json={"ids": ids}, headers=config)
    assert r.status_code == 200 and r.json()["applied"] == ids
    a = client.get("/api/v1/audit", params={"action": "waf.learning.apply"}).json()
    assert a[0]["actor_kind"] == "capi"
    # suspended: read only
    assert client.post(f"{S}/suspend").status_code == 200
    assert client.get(f"{CAPI}/waf/learning", headers=stats).status_code == 200
    assert client.post(f"{CAPI}/waf/learning/apply", json={"ids": ids}, headers=config).status_code == 403
    # a key only ever sees its own site
    mk_site(client, domain="other.org")
    r = client.post("/api/v1/sites/other.org/apikeys", json={"name": "o", "scopes": ["stats", "config"]})
    other = {"Authorization": f"Bearer {r.json()['key']}"}
    assert client.get(f"{CAPI}/waf/learning", headers=other).json()["state"] == "off"
    r = client.post(f"{CAPI}/waf/learning/apply", json={"ids": ids}, headers=other)
    assert r.status_code == 422
    # learning is started / stopped through the waf section (scope config)
    r = client.put(f"{CAPI}/config/waf", json={"learning": {"enabled": True, "days": 2}}, headers=other)
    assert r.status_code == 200 and r.json()["learning"]["enabled"] is True
    assert "/capi/v1/waf/learning" in client.get(f"{CAPI}/openapi.json").json()["paths"]
