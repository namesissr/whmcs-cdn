"""Wave 6A (SPEC §14.1) controller side: cache / ssl / image / pagerule fields, the edge shield
flag + heartbeat capabilities, and the per-edge `shield` block of the edge config."""

import hashlib
import hmac
import json
from datetime import timedelta

import pytest

from app import services
from app.config import settings
from app.db import SessionLocal
from app.models import Edge, Site, utcnow
from tests.test_api import edge_get

AUTH = "Authorization"
S = "/api/v1/sites/example.com"


def mk_site(client, domain="example.com", group="general", origin="93.184.216.34", **features):
    r = client.post("/api/v1/sites", json={"domain": domain, "origin_ip": origin,
                                           "plan": {"features": {"edge_group": group, **features}}})
    assert r.status_code == 201, r.text
    return r.json()


def mk_edge(client, name, ip, group="general", shield=False, online=True):
    r = client.post("/api/v1/edges", json={"name": name, "ipv4": ip, "region": "home", "group": group,
                                           "shield": shield})
    assert r.status_code == 201, r.text
    e = r.json()
    if online:
        hb(client, e["token"])
    return e


def hb(client, token, **body):
    r = client.post("/edge/v1/heartbeat", json={"applied_version": "v", **body},
                    headers={AUTH: f"Bearer {token}"})
    assert r.status_code == 200, r.text
    return r


def edge_cfg(client, token):
    r = edge_get(client, token, "/edge/v1/config")
    assert r.status_code == 200, r.text
    return r.json()


def site_of(cfg, domain="example.com"):
    return next(s for s in cfg["sites"] if s["domain"] == domain)


def edge_obj(client, name):
    return next(e for e in client.get("/api/v1/edges").json() if e["name"] == name)


# ------------------------------------------------------------------ sections: defaults

def test_section_defaults_for_existing_and_new_sites(client):
    s = mk_site(client)
    c = s["config"]
    assert {k: c["cache"][k] for k in ("stale_while_revalidate", "stale_if_error", "shield", "key_device",
                                       "key_cookies", "key_query_allow")} == {
        "stale_while_revalidate": True, "stale_if_error": 86400, "shield": False, "key_device": False,
        "key_cookies": [], "key_query_allow": []}
    assert c["ssl"]["http3"] is True
    assert c["image"]["auto_webp"] is False
    # a config stored before Wave 6A (no new keys) still reads, with the defaults filled in
    with SessionLocal() as db:
        site = db.query(Site).filter_by(domain="example.com").one()
        site.config = json.dumps({"cache": {"edge_ttl": 600, "ignore_query": True},
                                  "pagerules": {"rules": [{"id": "p1", "pattern": "/a/*", "cache": "bypass"}]}})
        db.commit()
    c = client.get(f"{S}/config").json()
    assert c["cache"]["edge_ttl"] == 600 and c["cache"]["ignore_query"] is True
    assert c["cache"]["key_query_allow"] == [] and c["cache"]["stale_if_error"] == 86400
    assert c["pagerules"]["rules"][0]["preload"] == []


# ------------------------------------------------------------------ sections: cache

def test_cache_new_fields_roundtrip(client):
    mk_site(client)
    body = {**client.get(f"{S}/config/cache").json(),
            "stale_while_revalidate": False, "stale_if_error": 0, "shield": True, "key_device": True,
            "key_cookies": [" lang ", "currency", "lang"], "key_query_allow": ["page", "utm[source]", "id-1", "page"]}
    r = client.put(f"{S}/config/cache", json=body)
    assert r.status_code == 200, r.text
    got = r.json()
    assert got["key_cookies"] == ["lang", "currency"]  # trimmed + de-duplicated
    assert got["key_query_allow"] == ["page", "utm[source]", "id-1"]
    assert (got["stale_while_revalidate"], got["stale_if_error"], got["shield"], got["key_device"]) == (
        False, 0, True, True)
    # GET == PUT and the GET body can be PUT back unchanged
    assert client.get(f"{S}/config/cache").json() == got
    assert client.put(f"{S}/config/cache", json=got).json() == got


def test_cache_key_query_allow_conflicts_with_ignore_query(client):
    mk_site(client)
    r = client.put(f"{S}/config/cache", json={"ignore_query": True, "key_query_allow": ["page"]})
    assert r.status_code == 422
    msg = json.dumps(r.json(), ensure_ascii=False)
    assert "key_query_allow" in msg and "ignore_query" in msg
    # either alone is fine
    assert client.put(f"{S}/config/cache", json={"ignore_query": True}).status_code == 200
    assert client.put(f"{S}/config/cache", json={"key_query_allow": ["page"]}).status_code == 200
    assert client.put(f"{S}/config/cache", json={"ignore_query": True, "key_query_allow": []}).status_code == 200


@pytest.mark.parametrize("body", [
    {"key_cookies": ["bad cookie"]},
    {"key_cookies": ["a=b"]},
    {"key_cookies": ["x" * 65]},
    {"key_cookies": [f"c{i}" for i in range(11)]},
    {"key_query_allow": ["a b"]},
    {"key_query_allow": ["a=b"]},
    {"key_query_allow": ["q\r\nx"]},
    {"key_query_allow": [""]},
    {"key_query_allow": ["p" * 65]},
    {"key_query_allow": [f"p{i}" for i in range(51)]},
    {"stale_if_error": -1},
    {"stale_if_error": 604801},
    {"stale_while_revalidate": "sometimes"},
    {"shield": "maybe"},
])
def test_cache_rejects(client, body):
    mk_site(client)
    assert client.put(f"{S}/config/cache", json=body).status_code == 422, body


def test_cache_limits_accepted_at_the_edges(client):
    mk_site(client)
    r = client.put(f"{S}/config/cache", json={"stale_if_error": 604800,
                                              "key_cookies": [f"c{i}" for i in range(10)],
                                              "key_query_allow": [f"p{i}" for i in range(50)]})
    assert r.status_code == 200, r.text


def test_cache_shield_warns_when_group_has_no_shield_edge(client):
    mk_site(client)
    r = client.put(f"{S}/config/cache", json={"shield": True})
    assert r.status_code == 200
    warnings = json.loads(r.headers["X-Pcdn-Warnings"])
    assert any("shield" in w for w in warnings)
    # a shield edge of ANOTHER group does not help this site
    mk_edge(client, "t-shield", "5.160.9.1", group="tunnel", shield=True)
    assert "X-Pcdn-Warnings" in client.put(f"{S}/config/cache", json={"shield": True}).headers
    mk_edge(client, "g-shield", "5.160.9.2", group="general", shield=True)
    r = client.put(f"{S}/config/cache", json={"shield": True})
    assert r.status_code == 200 and "X-Pcdn-Warnings" not in r.headers
    # shield off: never a warning
    client.patch(f"/api/v1/edges/{edge_obj(client, 'g-shield')['id']}", json={"shield": False})
    assert "X-Pcdn-Warnings" not in client.put(f"{S}/config/cache", json={"shield": False}).headers


# ------------------------------------------------------------------ sections: ssl / image

def test_ssl_http3_and_image_auto_webp_roundtrip(client):
    mk_site(client)
    ssl = {**client.get(f"{S}/config/ssl").json(), "http3": False}
    r = client.put(f"{S}/config/ssl", json=ssl)
    assert r.status_code == 200 and r.json()["http3"] is False
    assert client.get(f"{S}/config/ssl").json() == r.json()
    assert client.put(f"{S}/config/ssl", json={"http3": "yes please"}).status_code == 422

    img = {**client.get(f"{S}/config/image").json(), "auto_webp": True}
    r = client.put(f"{S}/config/image", json=img)
    assert r.status_code == 200 and r.json()["auto_webp"] is True and r.json()["enabled"] is False
    assert client.get(f"{S}/config/image").json() == r.json()


def test_image_auto_webp_needs_the_plan_feature(client):
    mk_site(client, image_optimization=False)
    assert client.put(f"{S}/config/image", json={"auto_webp": True}).status_code == 403
    assert client.put(f"{S}/config/image", json={"auto_webp": False}).status_code == 200
    # saved while allowed, then the plan loses the feature: the edge gets it switched off
    client.patch(f"{S}/plan", json={"features": {"image_optimization": True}})
    assert client.put(f"{S}/config/image", json={"auto_webp": True, "enabled": True}).status_code == 200
    tok = mk_edge(client, "e1", "5.160.1.10")["token"]
    assert site_of(edge_cfg(client, tok))["image"]["auto_webp"] is True
    client.patch(f"{S}/plan", json={"features": {"image_optimization": False}})
    img = site_of(edge_cfg(client, tok))["image"]
    assert img["auto_webp"] is False and img["enabled"] is False


# ------------------------------------------------------------------ sections: page rule preload

PRELOAD = [{"url": "/static/app.css", "as": "style"},
           {"url": "https://cdn.example.com/js/app.js?v=3", "as": "script"},
           {"url": "/fonts/a.woff2", "as": "font"},
           {"url": "/hero.webp", "as": "image"},
           {"url": "/api/boot.json", "as": "fetch"}]


def test_pagerule_preload_roundtrip(client):
    mk_site(client)
    rules = {"rules": [{"id": "p1", "pattern": "/*", "preload": PRELOAD}]}
    r = client.put(f"{S}/config/pagerules", json=rules)
    assert r.status_code == 200, r.text
    got = r.json()
    assert got["rules"][0]["preload"] == PRELOAD  # JSON key is "as", never "as_"
    assert "as_" not in json.dumps(got)
    assert client.get(f"{S}/config/pagerules").json() == got
    assert client.put(f"{S}/config/pagerules", json=got).json() == got
    # a rule without preload stays valid (default [])
    r = client.put(f"{S}/config/pagerules", json={"rules": [{"id": "p2", "pattern": "/x", "cache": "bypass"}]})
    assert r.status_code == 200 and r.json()["rules"][0]["preload"] == []


@pytest.mark.parametrize("entry", [
    {"url": "/a.css\r\nSet-Cookie: x=1", "as": "style"},   # header injection
    {"url": "/a.css\nX: y", "as": "style"},
    {"url": "/a\".css", "as": "style"},
    {"url": "/a'.css", "as": "style"},
    {"url": "/a<b>.css", "as": "style"},
    {"url": "/a b.css", "as": "style"},
    {"url": "/a\\b.css", "as": "style"},
    {"url": "/$host.css", "as": "style"},                  # nginx variable interpolation
    {"url": "/a{b}.css", "as": "style"},
    {"url": "//evil.example/x.js", "as": "script"},        # protocol-relative
    {"url": "http://cdn.example.com/x.js", "as": "script"},  # https only
    {"url": "javascript:alert(1)", "as": "script"},
    {"url": "app.css", "as": "style"},
    {"url": "https://", "as": "script"},
    {"url": "", "as": "style"},
    {"url": "/" + "a" * 2048, "as": "style"},
    {"url": "/a.css", "as": "document"},
    {"url": "/a.css"},
    {"url": "/a.css", "as": "style", "crossorigin": True},
])
def test_pagerule_preload_rejects(client, entry):
    mk_site(client)
    r = client.put(f"{S}/config/pagerules", json={"rules": [{"id": "p1", "pattern": "/*", "preload": [entry]}]})
    assert r.status_code == 422, (entry, r.text)


def test_pagerule_preload_max_ten(client):
    mk_site(client)
    many = [{"url": f"/f{i}.js", "as": "script"} for i in range(11)]
    r = client.put(f"{S}/config/pagerules", json={"rules": [{"id": "p1", "pattern": "/*", "preload": many}]})
    assert r.status_code == 422
    r = client.put(f"{S}/config/pagerules", json={"rules": [{"id": "p1", "pattern": "/*", "preload": many[:10]}]})
    assert r.status_code == 200


# ------------------------------------------------------------------ edge: shield flag (admin)

def test_edge_patch_shield_and_audit(client):
    e = mk_edge(client, "e1", "5.160.1.10", online=False)
    assert e["shield"] is False and e["capabilities"] is None
    r = client.patch(f"/api/v1/edges/{e['id']}", json={"shield": True})
    assert r.status_code == 200, r.text
    assert r.json()["edge"]["shield"] is True
    assert edge_obj(client, "e1")["shield"] is True
    assert client.patch(f"/api/v1/edges/{e['id']}", json={"shield": "sometimes"}).status_code == 422
    audit = client.get("/api/v1/audit", params={"action": "edge.patch"}).json()
    assert audit[0]["target"] == "e1"
    assert audit[0]["detail"]["shield"] is True and audit[0]["detail"]["fields"] == ["shield"]
    client.patch(f"/api/v1/edges/{e['id']}", json={"shield": False})
    assert client.get("/api/v1/audit", params={"action": "edge.patch"}).json()[0]["detail"]["shield"] is False
    # can also be set at creation
    assert mk_edge(client, "e2", "5.160.1.11", shield=True, online=False)["shield"] is True


# ------------------------------------------------------------------ edge: heartbeat capabilities

def test_heartbeat_capabilities_stored_and_sanitised(client):
    tok = mk_edge(client, "e1", "5.160.1.10")["token"]
    assert edge_obj(client, "e1")["capabilities"] is None  # never reported
    mods = ["njs", "image_filter", "njs", "bad name", 7, "../../etc", "brotli"]
    hb(client, tok, capabilities={"http3": True, "early_hints": True, "webp_convert": False,
                                  "modules": mods, "future_key": 1})
    caps = edge_obj(client, "e1")["capabilities"]
    assert caps == {"http3": True, "early_hints": True, "webp_convert": False,
                    "modules": ["brotli", "image_filter", "njs"],
                    "waf_packs": {}, "live_analytics": False, "logship": False}
    # a heartbeat without capabilities keeps the last report
    hb(client, tok)
    assert edge_obj(client, "e1")["capabilities"] == caps
    # the module list is capped
    hb(client, tok, capabilities={"modules": [f"m{i:03d}" for i in range(500)]})
    caps2 = edge_obj(client, "e1")["capabilities"]
    assert len(caps2["modules"]) == 64 and caps2["http3"] is False


def test_heartbeat_capabilities_wave6_fields(client):
    """SPEC §14.2/§14.3: WAF pack versions and the 6D agent features are kept for the panel; junk
    pack entries are dropped without failing the heartbeat."""
    tok = mk_edge(client, "e1", "5.160.1.10")["token"]
    hb(client, tok, capabilities={"http3": False, "live_analytics": True, "logship": True,
                                  "waf_packs": {"generic": 1, "wordpress": 2, "bad name": 1,
                                                "api": "x", "joomla": True, "drupal": -1}})
    caps = edge_obj(client, "e1")["capabilities"]
    assert caps["live_analytics"] is True and caps["logship"] is True
    assert caps["waf_packs"] == {"generic": 1, "wordpress": 2}
    hb(client, tok, capabilities={"waf_packs": "v1"})
    assert edge_obj(client, "e1")["capabilities"]["waf_packs"] == {}


@pytest.mark.parametrize("bad", [
    {"http3": "maybe"},
    {"early_hints": [1]},
    {"webp_convert": {"x": 1}},
    {"modules": "njs"},
    "http3",
    [True],
])
def test_heartbeat_malformed_capabilities_are_ignored_not_fatal(client, bad):
    tok = mk_edge(client, "e1", "5.160.1.10")["token"]
    hb(client, tok, capabilities={"http3": True, "modules": ["njs"]})
    before = edge_obj(client, "e1")
    # the heartbeat itself still succeeds (a 422 would make a healthy node look silent)...
    r = hb(client, tok, capabilities=bad)
    assert r.json() == {"ok": True}
    after = edge_obj(client, "e1")
    # ...the node stays online and the previous capabilities are kept
    assert after["last_seen_at"] >= before["last_seen_at"]
    assert after["capabilities"] == {"http3": True, "early_hints": False, "webp_convert": False,
                                     "modules": ["njs"], "waf_packs": {}, "live_analytics": False,
                                     "logship": False}


# ------------------------------------------------------------------ edge config: per-site fields

def test_edge_config_carries_new_site_fields(client):
    mk_site(client)
    client.put(f"{S}/config/cache", json={"key_device": True, "key_cookies": ["lang"],
                                          "key_query_allow": ["page"], "stale_if_error": 3600})
    client.put(f"{S}/config/pagerules", json={"rules": [{"id": "p1", "pattern": "/*", "preload": PRELOAD[:2]}]})
    client.put(f"{S}/config/image", json={"auto_webp": True})
    tok = mk_edge(client, "e1", "5.160.1.10")["token"]
    s = site_of(edge_cfg(client, tok))
    c = s["cache"]
    assert (c["key_device"], c["key_cookies"], c["key_query_allow"], c["stale_if_error"],
            c["stale_while_revalidate"], c["shield"]) == (True, ["lang"], ["page"], 3600, True, False)
    assert s["pagerules"]["rules"][0]["preload"] == PRELOAD[:2]
    assert s["image"]["auto_webp"] is True
    # no certificate -> no HTTPS server on the edge -> http3 folded off (like force_https)
    assert s["ssl"] is None and s["ssl_options"]["http3"] is False
    with SessionLocal() as db:
        site = db.query(Site).filter_by(domain="example.com").one()
        site.ssl_status, site.ssl_cert, site.ssl_key = "active", "C", "K"
        site.ssl_expires_at = utcnow() + timedelta(days=60)
        db.commit()
    assert site_of(edge_cfg(client, tok))["ssl_options"]["http3"] is True
    client.put(f"{S}/config/ssl", json={"http3": False})
    assert site_of(edge_cfg(client, tok))["ssl_options"]["http3"] is False


# ------------------------------------------------------------------ edge config: shield block

def test_shield_peers_same_group_online_enabled_excluding_self(client):
    mk_site(client)  # general group
    client.put(f"{S}/config/cache", json={"shield": True})
    a = mk_edge(client, "a", "5.160.1.1")                                     # plain edge, requester
    s1 = mk_edge(client, "s1", "5.160.2.1", shield=True)                      # online shield
    mk_edge(client, "s2", "5.160.2.2", shield=True, online=False)             # never heartbeated
    s3 = mk_edge(client, "s3", "5.160.2.3", shield=True)                      # disabled below
    mk_edge(client, "t1", "5.160.3.1", group="tunnel", shield=True)           # other group
    s5 = mk_edge(client, "s5", "5.160.2.5", shield=True)                      # stale below
    client.patch(f"/api/v1/edges/{s3['id']}", json={"enabled": False})
    with SessionLocal() as db:
        db.get(Edge, s5["id"]).last_seen_at = utcnow() - timedelta(seconds=settings.edge_offline_seconds + 60)
        db.commit()

    cfg = edge_cfg(client, a["token"])
    assert cfg["shield"]["self"] is False
    assert cfg["shield"]["peers"] == ["5.160.2.1"]
    assert site_of(cfg)["cache"]["shield"] is True

    # the shield itself: flagged self, never listed as its own peer; alone in its group -> inert
    cfg = edge_cfg(client, s1["token"])
    assert cfg["shield"]["self"] is True and cfg["shield"]["peers"] == []
    assert site_of(cfg)["cache"]["shield"] is False
    # a second online shield in the group becomes its peer (ordered by edge id)
    s6 = mk_edge(client, "s6", "5.160.2.6", shield=True)
    assert edge_cfg(client, s1["token"])["shield"]["peers"] == ["5.160.2.6"]
    assert edge_cfg(client, a["token"])["shield"]["peers"] == ["5.160.2.1", "5.160.2.6"]
    assert edge_cfg(client, s6["token"])["shield"]["peers"] == ["5.160.2.1"]

    # a tunnel-group edge sees only tunnel-group shields, and does not shield a general-group site
    t2 = mk_edge(client, "t2", "5.160.3.2", group="tunnel")
    cfg = edge_cfg(client, t2["token"])
    assert cfg["shield"]["peers"] == [] and site_of(cfg)["cache"]["shield"] is False


def test_shield_inert_without_peers_or_users(client):
    mk_site(client)
    a = mk_edge(client, "a", "5.160.1.1")
    # site wants shield, but the group has no shield edge -> folded off
    client.put(f"{S}/config/cache", json={"shield": True})
    cfg = edge_cfg(client, a["token"])
    assert cfg["shield"]["peers"] == [] and site_of(cfg)["cache"]["shield"] is False
    # a shield edge exists but no site uses it -> no peer list (no version churn on its heartbeats)
    mk_edge(client, "s1", "5.160.2.1", shield=True)
    client.put(f"{S}/config/cache", json={"shield": False})
    cfg = edge_cfg(client, a["token"])
    assert cfg["shield"]["peers"] == [] and site_of(cfg)["cache"]["shield"] is False
    # dev mode (cache off) never shields
    client.put(f"{S}/config/cache", json={"shield": True, "dev_mode": True})
    cfg = edge_cfg(client, a["token"])
    assert site_of(cfg)["cache"]["shield"] is False and cfg["shield"]["peers"] == []
    client.put(f"{S}/config/cache", json={"shield": True})
    cfg = edge_cfg(client, a["token"])
    assert site_of(cfg)["cache"]["shield"] is True and cfg["shield"]["peers"] == ["5.160.2.1"]


def test_shield_tunnel_group_site(client):
    mk_site(client, group="tunnel", tunnel=True)
    client.put(f"{S}/config/cache", json={"shield": True})
    g = mk_edge(client, "g", "5.160.1.1", shield=True)
    t = mk_edge(client, "t", "5.160.3.1", group="tunnel")
    # only a general-group shield exists: the tunnel-group site stays unshielded everywhere
    assert site_of(edge_cfg(client, t["token"]))["cache"]["shield"] is False
    assert site_of(edge_cfg(client, g["token"]))["cache"]["shield"] is False
    mk_edge(client, "ts", "5.160.3.9", group="tunnel", shield=True)
    cfg = edge_cfg(client, t["token"])
    assert site_of(cfg)["cache"]["shield"] is True and cfg["shield"]["peers"] == ["5.160.3.9"]


def test_shield_secret_stable_and_not_the_raw_key(client, monkeypatch):
    mk_site(client)
    client.put(f"{S}/config/cache", json={"shield": True})
    a = mk_edge(client, "a", "5.160.1.1")
    s1 = mk_edge(client, "s1", "5.160.2.1", shield=True)
    sec_a = edge_cfg(client, a["token"])["shield"]["secret"]
    sec_s = edge_cfg(client, s1["token"])["shield"]["secret"]
    assert sec_a == sec_s == edge_cfg(client, a["token"])["shield"]["secret"]  # all edges agree
    assert len(sec_a) == 64 and int(sec_a, 16) >= 0
    assert sec_a != settings.admin_api_key and settings.admin_api_key not in json.dumps(
        edge_cfg(client, a["token"]))
    assert sec_a == hmac.new(settings.admin_api_key.encode(), b"pcdn-shield", hashlib.sha256).hexdigest()

    # with DATA_ENCRYPTION_KEY set, the primary key is the material (and never sent raw)
    monkeypatch.setattr(settings, "data_encryption_key", "PRIMARYKEY,OLDKEY")
    sec = services.shield_secret()
    assert sec == hmac.new(b"PRIMARYKEY", b"pcdn-shield", hashlib.sha256).hexdigest()
    assert sec != sec_a and "PRIMARYKEY" not in sec
    monkeypatch.setattr(settings, "data_encryption_key", "")

    # no secret material at all -> shield off entirely (never a guessable secret)
    monkeypatch.setattr(settings, "admin_api_key", "")
    assert services.shield_secret() == ""
    with SessionLocal() as db:
        cfg = services.build_edge_config(db, db.get(Edge, s1["id"]))
    assert cfg["shield"] == {"self": False, "peers": [], "secret": ""}
    assert site_of(cfg)["cache"]["shield"] is False


def test_config_version_per_edge_and_etag(client):
    mk_site(client)
    client.put(f"{S}/config/cache", json={"shield": True})
    a = mk_edge(client, "a", "5.160.1.1")
    b = mk_edge(client, "b", "5.160.1.2")
    s1 = mk_edge(client, "s1", "5.160.2.1", shield=True)
    ca, cb, cs = (edge_cfg(client, x["token"]) for x in (a, b, s1))
    # identical bodies (same peers, same self) -> same version; the shield's own view differs
    assert ca["version"] == cb["version"] and ca["version"] != cs["version"]
    # unchanged -> 304 with the same ETag (no reload)
    r = edge_get(client, a["token"], "/edge/v1/config", headers={"If-None-Match": f'"{ca["version"]}"'})
    assert r.status_code == 304
    # the shield going offline changes the peer list and so the version
    with SessionLocal() as db:
        db.get(Edge, s1["id"]).last_seen_at = utcnow() - timedelta(seconds=settings.edge_offline_seconds + 60)
        db.commit()
    ca2 = edge_cfg(client, a["token"])
    assert ca2["shield"]["peers"] == [] and ca2["version"] != ca["version"]
    # without a requesting edge (internal callers) the block is inert but well-formed
    with SessionLocal() as db:
        cfg = services.build_edge_config(db)
    assert cfg["shield"]["self"] is False and cfg["shield"]["peers"] == []
    assert len(cfg["shield"]["secret"]) == 64


def test_shield_peer_address_skips_placeholder(client):
    """A batch-created shield that has not reported its address is never a peer."""
    mk_site(client)
    client.put(f"{S}/config/cache", json={"shield": True})
    a = mk_edge(client, "a", "5.160.1.1")
    r = client.post("/api/v1/edges/batch", json={"count": 1, "name_prefix": "sh"})
    eid = r.json()["edges"][0]["id"]
    client.patch(f"/api/v1/edges/{eid}", json={"shield": True})
    with SessionLocal() as db:
        db.get(Edge, eid).last_seen_at = utcnow()  # online, still 0.0.0.0
        db.commit()
    assert edge_cfg(client, a["token"])["shield"]["peers"] == []
    with SessionLocal() as db:
        db.get(Edge, eid).ipv6 = "2a01:4f8::9"
        db.commit()
    assert edge_cfg(client, a["token"])["shield"]["peers"] == ["2a01:4f8::9"]
