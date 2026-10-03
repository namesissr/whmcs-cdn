"""Controller-side tunnel-stability fixes (audit workstream `controller`):
F1/F34 validation warnings, F2 cert-during-renewal, F7 usage idempotency, F10 control-plane-outage
DNS guard, F21 edge_group, F25 load-shed hysteresis, F26 probe-withdrawal budget, F32 per-family
primary probe, F33 tunnel DNS selector, F35 cut_paths."""

import json
from datetime import datetime, timedelta
from types import SimpleNamespace

from app import dnsbuild, scheduler, services
from app import ssl as sslmod
from app.config import settings
from app.db import SessionLocal
from app.models import Edge, Site, UsageBatch, utcnow
from app.scheduler import job_edges
from tests.test_api import add_edge, edge_get
from tests.test_tunnel import S, activate, edge, rec, site

AUTH = "Authorization"


def _tunnel_of(client, token):
    return edge_get(client, token, "/edge/v1/config").json()["sites"][0]


# ------------------------------------------------------------------ F2: cert kept during renewal

def test_f2_cert_served_through_failed_renewal_and_pending(client, monkeypatch):
    site(client)
    activate()
    with SessionLocal() as db:
        s = db.query(Site).filter_by(domain="example.com").one()
        s.ssl_status, s.ssl_cert, s.ssl_key = "active", "CERTDATA", "KEYDATA"
        s.ssl_expires_at = utcnow() + timedelta(days=10)  # inside the 30-day renewal window
        db.commit()

    def ssl_of():
        with SessionLocal() as db:
            cfg = services.build_edge_config(db)
            return next(x for x in cfg["sites"] if x["domain"] == "example.com")["ssl"]

    assert ssl_of() == {"cert": "CERTDATA", "key": "KEYDATA", "ocsp": False}  # before a renewal

    # a renewal that fails must NOT drop the still-valid cert
    monkeypatch.setattr(sslmod, "issue", lambda s: (_ for _ in ()).throw(RuntimeError("acme boom")))
    with SessionLocal() as db:
        scheduler.job_ssl(db)  # picks the renewal-window site, issue() raises
        s = db.query(Site).filter_by(domain="example.com").one()
        assert s.ssl_status == "active" and s.ssl_error  # kept active, error recorded
    assert ssl_of() == {"cert": "CERTDATA", "key": "KEYDATA", "ocsp": False}  # after a failed renewal

    # a manual re-request (request_ssl) flips to pending but keeps the cert served
    with SessionLocal() as db:
        s = db.query(Site).filter_by(domain="example.com").one()
        s.ssl_status = "pending"
        db.commit()
    assert ssl_of() == {"cert": "CERTDATA", "key": "KEYDATA", "ocsp": False}

    # only when the cert is genuinely unusable (expired + reissue failed) do we drop HTTPS
    with SessionLocal() as db:
        s = db.query(Site).filter_by(domain="example.com").one()
        s.ssl_status, s.ssl_expires_at = "active", utcnow() - timedelta(days=1)
        db.commit()
    assert ssl_of() is None


def test_f2_request_ssl_endpoint_keeps_cert(client):
    site(client)
    activate()
    with SessionLocal() as db:
        s = db.query(Site).filter_by(domain="example.com").one()
        s.ssl_status, s.ssl_cert, s.ssl_key = "active", "C", "K"
        s.ssl_expires_at = utcnow() + timedelta(days=40)
        db.commit()
    assert client.post(f"{S}/ssl").status_code == 200
    with SessionLocal() as db:
        s = db.query(Site).filter_by(domain="example.com").one()
        assert s.ssl_status == "pending" and s.ssl_cert == "C"  # cert not cleared by re-request
        cfg = services.build_edge_config(db)
        assert next(x for x in cfg["sites"] if x["domain"] == "example.com")["ssl"] == {"cert": "C", "key": "K", "ocsp": False}


# ------------------------------------------------------------------ F7: usage idempotency

def _usage(client, token, batch_id=None, bytes_=1000, hour="2026-09-15T10:00:00Z"):
    body = {"items": [{"host": "example.com", "hour": hour, "bytes": bytes_, "requests": 5}]}
    if batch_id is not None:
        body["batch_id"] = batch_id
    return client.post("/edge/v1/usage", json=body, headers={AUTH: f"Bearer {token}"})


def _month_bytes(sid):
    with SessionLocal() as db:
        return services.usage_totals(db, sid, datetime(2026, 9, 1))["bytes"]


def test_f7_duplicate_batch_id_counted_once(client):
    site(client)
    activate()
    token = add_edge(client)
    with SessionLocal() as db:
        sid = db.query(Site).filter_by(domain="example.com").one().id

    r1 = _usage(client, token, batch_id="a" * 32)
    assert r1.json()["accepted"] == 1
    r2 = _usage(client, token, batch_id="a" * 32)  # replay of the same batch
    assert r2.json().get("duplicate") is True
    assert _month_bytes(sid) == 1000  # counted once, not twice

    _usage(client, token, batch_id="b" * 32)  # a different batch counts again
    assert _month_bytes(sid) == 2000
    with SessionLocal() as db:
        assert db.query(UsageBatch).count() == 2


def test_f7_missing_batch_id_still_works(client):
    site(client)
    activate()
    token = add_edge(client)
    with SessionLocal() as db:
        sid = db.query(Site).filter_by(domain="example.com").one().id
    # back-compat: no batch_id -> at-least-once (both POSTs apply)
    _usage(client, token)
    _usage(client, token)
    assert _month_bytes(sid) == 2000
    with SessionLocal() as db:
        assert db.query(UsageBatch).count() == 0


def test_f7_bad_batch_id_rejected(client):
    site(client)
    activate()
    token = add_edge(client)
    assert _usage(client, token, batch_id="not-hex!").status_code == 422


# ------------------------------------------------------------------ F10: control-plane outage guard

def _proxied_lua(fake_pdns):
    rr = fake_pdns.rrset("example.com.", "example.com.", "LUA")
    return " ".join(r["content"] for r in rr["records"])


def test_f10_bulk_silence_keeps_last_known_pool(client, fake_pdns, alert_settings, monkeypatch):
    monkeypatch.setattr(settings, "edge_probe", True)
    site(client)
    activate()
    ips = [f"5.160.1.{i}" for i in range(1, 5)]
    for i, ip in enumerate(ips, 1):
        add_edge(client, f"ir-{i}", ip)
    with SessionLocal() as db:
        for e in db.query(Edge).all():
            e.last_seen_at = utcnow()
        db.commit()
        job_edges(db)  # first publish: all four
    assert all(ip in _proxied_lua(fake_pdns) for ip in ips)

    # three of four nodes lose the controller at once (>50%): keep the last-known DNS, do not shrink
    with SessionLocal() as db:
        for e in db.query(Edge).order_by(Edge.id).limit(3):
            e.last_seen_at = utcnow() - timedelta(hours=1)
        db.commit()
        job_edges(db)
    assert all(ip in _proxied_lua(fake_pdns) for ip in ips)  # still all four (fail-static)
    with SessionLocal() as db:
        assert any(a["key"] == scheduler.SILENT_GUARD_ALERT for a in __import__("app").alerts.open_alerts(db))


def test_f10_tunnel_site_never_falls_back_to_origin():
    # no edges online at all: a general site exposes its origin (capped TTL), a tunnel site does not
    gen = SimpleNamespace(domain="ex.com", features="{}", config="{}",
                          records=[rec("@", "A", "9.9.9.9", proxied=True)])
    rr = {(r["name"], r["type"]): r for r in dnsbuild.build_rrsets(gen, [])}
    assert rr[("ex.com.", "A")]["records"][0]["content"] == "9.9.9.9"
    assert rr[("ex.com.", "A")]["ttl"] <= settings.proxied_ttl  # F10(d)

    tun = SimpleNamespace(domain="ex.com", features='{"edge_group": "tunnel"}', config="{}",
                          records=[rec("@", "A", "9.9.9.9", proxied=True)])
    rr = {(r["name"], r["type"]): r for r in dnsbuild.build_rrsets(tun, [])}
    assert ("ex.com.", "A") not in rr  # F10(c): tunnel origin never exposed


def test_f10_single_node_loss_is_not_guarded(client, fake_pdns, alert_settings, monkeypatch):
    monkeypatch.setattr(settings, "edge_probe", True)
    site(client)
    activate()
    ips = [f"5.160.1.{i}" for i in range(1, 5)]
    for i, ip in enumerate(ips, 1):
        add_edge(client, f"ir-{i}", ip)
    with SessionLocal() as db:
        for e in db.query(Edge).all():
            e.last_seen_at = utcnow()
        db.commit()
        job_edges(db)
    # one node goes offline (25% <= 50%): normal removal, DNS shrinks to the remaining three
    with SessionLocal() as db:
        db.query(Edge).order_by(Edge.id).first().last_seen_at = utcnow() - timedelta(hours=1)
        db.commit()
        job_edges(db)
    lua = _proxied_lua(fake_pdns)
    assert ips[0] not in lua and all(ip in lua for ip in ips[1:])


# ------------------------------------------------------------------ F25: load-shed hysteresis

def _edge_row(db, name="c1", ip="5.1.1.1", cap=100, region="home"):
    e = Edge(name=name, ipv4=ip, token_hash=name, capacity_mbps=cap, region=region, enabled=True,
             last_seen_at=utcnow())
    db.add(e)
    db.commit()
    return e


def test_f25_shed_needs_consecutive_reports_and_holds(client, monkeypatch):
    monkeypatch.setattr(settings, "edge_shed_percent", 90.0)
    monkeypatch.setattr(settings, "edge_shed_checks", 3)
    monkeypatch.setattr(settings, "edge_shed_hold", 300)
    with SessionLocal() as db:
        e = _edge_row(db)

        def rep(peak):
            services.record_metrics(e, {"rx_mbps": peak, "tx_mbps": 0}, utcnow())
            db.commit()

        rep(95)
        assert not e.shed  # 1 report
        rep(95)
        assert not e.shed  # 2 reports: still below EDGE_SHED_CHECKS
        rep(95)
        assert e.shed      # 3rd consecutive -> shed
        rep(5)
        assert e.shed      # held for EDGE_SHED_HOLD even though load dropped
        e.shed_since = utcnow() - timedelta(seconds=400)
        db.commit()
        rep(5)
        assert not e.shed  # hold elapsed and load recovered -> released


def test_f25_pool_cap_keeps_capacity_above_load(client, monkeypatch):
    monkeypatch.setattr(settings, "edge_shed_percent", 90.0)
    monkeypatch.setattr(settings, "edge_shed_checks", 1)
    monkeypatch.setattr(settings, "edge_shed_hold", 0)
    with SessionLocal() as db:
        a = _edge_row(db, "a", "5.1.1.1", cap=100, region="home")
        b = _edge_row(db, "b", "5.1.1.2", cap=100, region="home")
        # both saturated at once; without the pool cap both would leave DNS and herd the region
        for e, peak in ((a, 95), (b, 95)):
            services.record_metrics(e, {"rx_mbps": peak, "tx_mbps": 0}, utcnow())
        db.commit()
        assert a.shed and b.shed
        services.rebalance_pool_shed(db)
        # the pool's unshed capacity may not fall below its ~190 Mbps load -> at least one comes back
        assert not (dnsbuild.is_shed(a) and dnsbuild.is_shed(b))


# ------------------------------------------------------------------ F26: probe-withdrawal budget

def _fam_edge(ip, ok4=True, fail4=0, region="global"):
    return SimpleNamespace(ipv4=ip, ipv6=None, region=region, probe_ok4=ok4, probe_fail4=fail4,
                           probe_ok6=None, probe_fail6=0, addresses=[])


def test_f26_withdrawal_budget_caps_probe_only_removal(monkeypatch):
    monkeypatch.setattr(settings, "probe_fail_checks", 3)
    monkeypatch.setattr(settings, "probe_withdraw_max_fraction", 0.34)
    # six addresses, five "down" only from the controller probe -> floor(6*0.34)=2 may be withdrawn
    edges = [_fam_edge("5.1.1.1")] + [_fam_edge(f"5.1.1.{i}", ok4=False, fail4=3) for i in range(2, 7)]
    _, glob = dnsbuild.edge_pools(edges, 4)
    assert len(glob) == 4  # 6 - budget(2); never pulled down to the last one
    assert "5.1.1.1" in glob  # the genuinely-healthy address always stays


def test_f26_budget_disabled_withdraws_all_unhealthy(monkeypatch):
    monkeypatch.setattr(settings, "probe_fail_checks", 3)
    monkeypatch.setattr(settings, "probe_withdraw_max_fraction", 1.0)
    edges = [_fam_edge("5.1.1.1")] + [_fam_edge(f"5.1.1.{i}", ok4=False, fail4=3) for i in range(2, 7)]
    _, glob = dnsbuild.edge_pools(edges, 4)
    assert glob == ["5.1.1.1"]  # budget off -> only the healthy one advertised


# ------------------------------------------------------------------ F32: per-family primary probe

def test_f32_dead_family_withdrawn_healthy_family_stays(monkeypatch):
    monkeypatch.setattr(settings, "probe_fail_checks", 3)
    monkeypatch.setattr(settings, "probe_withdraw_max_fraction", 1.0)  # isolate from the F26 budget
    healthy = SimpleNamespace(ipv4="5.1.1.1", ipv6="2a01::1", region="home",
                              probe_ok4=True, probe_fail4=0, probe_ok6=True, probe_fail6=0, addresses=[])
    # its IPv6 is dead (3 fails) while its IPv4 is fine
    split = SimpleNamespace(ipv4="5.1.1.2", ipv6="2a01::2", region="home",
                            probe_ok4=True, probe_fail4=0, probe_ok6=False, probe_fail6=3, addresses=[])
    v4, _ = dnsbuild.edge_pools([healthy, split], 4)
    v6, _ = dnsbuild.edge_pools([healthy, split], 6)
    assert "5.1.1.2" in v4                    # healthy v4 family stays
    assert "2a01::2" not in v6 and "2a01::1" in v6  # dead v6 family withdrawn, healthy v6 stays


# ------------------------------------------------------------------ F33: tunnel DNS selector

def _answer(site_obj, edges):
    rr = {(r["name"], r["type"]): r for r in dnsbuild.build_rrsets(site_obj, edges)}
    return rr[("ex.com.", "LUA")]["records"][0]["content"]


def _tsite(group="general", config="{}"):
    return SimpleNamespace(domain="ex.com", features=f'{{"edge_group": "{group}"}}', config=config,
                           records=[rec("@", "A", "1.2.3.4", proxied=True)])


def test_f33_tunnel_sites_get_all_edges(monkeypatch):
    monkeypatch.setattr(settings, "lua_selector", "random")
    monkeypatch.setattr(settings, "tunnel_lua_selector", "all")
    monkeypatch.setattr(settings, "edge_probe", True)
    edges = [edge("5.5.5.1", group="tunnel"), edge("5.5.5.2", group="tunnel")]
    assert "selector='all'" in _answer(_tsite("tunnel"), edges)          # edge_group=tunnel
    assert "selector='all'" in _answer(_tsite("general", '{"tunnel": {"enabled": true}}'),
                                       [edge("5.5.5.1"), edge("5.5.5.2")])  # tunnel section enabled
    assert "selector='random'" in _answer(_tsite("general"), [edge("5.5.5.1")])  # general keeps LUA_SELECTOR


def test_f33_selector_in_dns_signature(monkeypatch):
    before = scheduler.dns_signature()
    monkeypatch.setattr(settings, "tunnel_lua_selector", "first")
    assert scheduler.dns_signature() != before


# ------------------------------------------------------------------ F21 + F35: edge config

def test_f21_edge_group_in_site_config(client):
    site(client, features={"edge_group": "tunnel"})
    activate()
    token = add_edge(client)
    assert _tunnel_of(client, token)["edge_group"] == "tunnel"


def test_f35_cut_paths_while_suspended(client):
    site(client, features={"max_tunnel_connections": 500})
    client.put(f"{S}/config/pools", json={"pools": [{"name": "vpn", "origins": [{"address": "185.1.2.3"}]}]})
    paths = [{"id": "x1", "path": "/xh", "protocol": "xhttp", "pool": "vpn"},
             {"id": "ws1", "path": "/ws", "protocol": "ws"}]
    assert client.put(f"{S}/config/tunnel", json={"enabled": True, "paths": paths}).status_code == 200
    activate()
    token = add_edge(client)

    t = _tunnel_of(client, token)["tunnel"]
    assert t["enabled"] is True and t["cut_paths"] == []  # active: normal serving

    with SessionLocal() as db:
        db.query(Site).filter_by(domain="example.com").one().suspended = True
        db.commit()
    t = _tunnel_of(client, token)["tunnel"]
    assert t["enabled"] is False
    assert sorted(t["cut_paths"]) == ["/ws", "/xh"]  # prefixes kept for cheap rate-limited 503s


# ------------------------------------------------------------------ F1 + F34: validation warnings

def _warnings(resp):
    return json.loads(resp.headers.get("X-Pcdn-Warnings", "[]"))


def test_f1_multi_origin_pool_warning_for_xhttp(client):
    site(client)
    client.put(f"{S}/config/pools", json={"pools": [
        {"name": "multi", "origins": [{"address": "185.1.2.3"}, {"address": "185.1.2.4"}]},
        {"name": "solo", "origins": [{"address": "185.1.2.5"}]},
    ]})
    r = client.put(f"{S}/config/tunnel", json={"enabled": True,
                   "paths": [{"id": "x1", "path": "/xh", "protocol": "xhttp", "pool": "multi"}]})
    assert r.status_code == 200 and any("x1" in w for w in _warnings(r))

    # a single-origin pool, or a ws path, raises no F1 warning
    r = client.put(f"{S}/config/tunnel", json={"enabled": True,
                   "paths": [{"id": "x2", "path": "/xh2", "protocol": "xhttp", "pool": "solo"},
                             {"id": "w1", "path": "/ws", "protocol": "ws", "pool": "multi"}]})
    assert r.status_code == 200 and not any("x2" in w or "w1" in w for w in _warnings(r))


def test_f34_force_https_with_tunnel_paths_warning(client):
    site(client)
    client.put(f"{S}/config/tunnel", json={"enabled": True,
               "paths": [{"id": "w1", "path": "/ws", "protocol": "ws"}]})
    # turning force_https on while tunnel paths exist warns (from the ssl side)
    r = client.put(f"{S}/config/ssl", json={"force_https": True})
    assert r.status_code == 200 and any("force_https" in w for w in _warnings(r))
    # and re-saving the tunnel section while force_https is on warns (from the tunnel side)
    r = client.put(f"{S}/config/tunnel", json={"enabled": True,
                   "paths": [{"id": "w1", "path": "/ws", "protocol": "ws"}]})
    assert r.status_code == 200 and any("force_https" in w for w in _warnings(r))
