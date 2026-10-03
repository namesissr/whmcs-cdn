"""Wave 14 (SPEC §23), operator side: versions + pinned edge releases (§23.1), staged rollouts with
automatic rollback (§23.2), backups / restore test (§23.3), provisioning + join tokens (§23.9), SLO
(§23.11), customer-visible node naming (§23.12) and the 0023 data model."""

import ast
import hashlib
import json
import os
from datetime import timedelta

import httpx
import pytest
from cryptography.fernet import Fernet
from sqlalchemy import select

from app import alerts, backup, backup_runs, bundle, edge_labels, provisioning, rollout, scheduler, slo
from app.config import settings
from app.db import SessionLocal
from app.models import (AuditLog, BackupRun, Edge, EdgeJoinToken, ProvisionProposal, Rollout, RolloutEdge,
                        SloBucket, State, UsageHourly, utcnow)

ADMIN = "/api/v1"


def auth(tok: str) -> dict:
    return {"Authorization": f"Bearer {tok}"}


def mk_edge(client, name, ip, region="home", group="general"):
    r = client.post(f"{ADMIN}/edges", json={"name": name, "ipv4": ip, "region": region, "group": group})
    assert r.status_code == 201, r.text
    return r.json()["id"], r.json()["token"]


def hb(client, tok, **body):
    r = client.post("/edge/v1/heartbeat", json={"applied_version": "v", **body}, headers=auth(tok))
    assert r.status_code == 200, r.text


def write_release(d, version, data=None):
    data = data or f"bundle {version}".encode()
    p = d / f"pcdn-edge-{version}.tar.gz"
    p.write_bytes(data)
    (d / f"pcdn-edge-{version}.tar.gz.sha256").write_text(
        f"{hashlib.sha256(data).hexdigest()}  pcdn-edge-{version}.tar.gz\n")
    return hashlib.sha256(data).hexdigest()


@pytest.fixture()
def releases(tmp_path, monkeypatch):
    d = tmp_path / "rel"
    d.mkdir()
    for v in ("v2.0.0", "v2.1.0", "v2.1.0-rc.1"):
        write_release(d, v)
    monkeypatch.setattr(settings, "edge_releases_dir", str(d))
    monkeypatch.setattr(settings, "edge_release", "")
    return d


# ================================================================== §23.1 versions + pinned releases

def test_healthz_version_and_deep_environment(client, monkeypatch):
    monkeypatch.setattr(settings, "app_version", "2.1.0")
    monkeypatch.setattr(settings, "environment", "staging")
    assert client.get("/healthz").json() == {"ok": True, "version": "2.1.0"}
    deep = client.get("/healthz/deep").json()
    assert deep["version"] == "2.1.0" and deep["environment"] == "staging"
    assert "revision" in deep["database"]
    assert 'pcdn_build_info{version="2.1.0"} 1' in client.get("/metrics").text


def test_app_version_sources(monkeypatch, tmp_path):
    from app import config

    monkeypatch.setenv("PCDN_VERSION", "v2.2.0")
    assert config._app_version() == "2.2.0"
    monkeypatch.delenv("PCDN_VERSION")
    monkeypatch.setattr(config, "_version_file", lambda: "2.0.0")
    assert config._app_version() == "2.0.0"


def test_releases_off_by_default_is_todays_behaviour(client, monkeypatch):
    monkeypatch.setattr(settings, "edge_releases_dir", "")
    assert client.get("/edge/releases").status_code == 404
    assert client.get("/edge/releases/v2.0.0.sha256").status_code == 404
    assert client.get("/edge/bundle.tar.gz?version=v2.0.0").status_code == 404
    r = client.get("/edge/version")
    if r.status_code == 200:
        assert r.json()["release"] is None


def test_release_listing_sha_and_version_regex(client, releases):
    body = client.get("/edge/releases").json()
    assert [r["version"] for r in body["releases"]] == ["v2.1.0", "v2.1.0-rc.1", "v2.0.0"]
    assert body["pinned"] is None and body["groups"] == {"general": None, "tunnel": None}
    assert all(len(r["sha256"]) == 64 and r["size"] > 0 for r in body["releases"])
    t = client.get("/edge/releases/v2.1.0.sha256")
    assert t.status_code == 200 and t.text == f"{hashlib.sha256(b'bundle v2.1.0').hexdigest()}  pcdn-edge-v2.1.0.tar.gz\n"
    assert client.get("/edge/bundle.tar.gz?version=2.1.0").status_code == 422
    assert client.get("/edge/bundle.tar.gz?version=v2.1.0/../x").status_code == 422
    assert client.get("/edge/bundle.tar.gz?version=v9.9.9").status_code == 404
    r = client.get("/edge/bundle.tar.gz?version=v2.1.0")
    assert r.status_code == 200 and r.content == b"bundle v2.1.0"
    assert client.get("/edge/releases/v9.9.9.sha256").status_code == 404


def test_semver_ordering():
    keys = sorted(["v1.10.0", "v1.2.0", "v1.10.0-rc.2", "v1.10.0-rc.10", "v1.10.0-alpha"], key=bundle.semver_key)
    assert keys == ["v1.2.0", "v1.10.0-alpha", "v1.10.0-rc.2", "v1.10.0-rc.10", "v1.10.0"]


def test_pin_resolution_env_group_state_and_missing_file(client, releases, monkeypatch):
    monkeypatch.setattr(settings, "edge_release", "v2.0.0")
    with SessionLocal() as db:
        assert bundle.group_pin(db, "general") == "v2.0.0"
        bundle.set_group_pin(db, "tunnel", "v2.1.0")
        db.commit()
        assert bundle.pins(db) == {"general": "v2.0.0", "tunnel": "v2.1.0"}
    # the live bundle is replaced by the pin of ?group= (default general)
    assert client.get("/edge/bundle.tar.gz").content == b"bundle v2.0.0"
    assert client.get("/edge/bundle.tar.gz?group=tunnel").content == b"bundle v2.1.0"
    # a pin that is not in the directory is ignored (live bundle)
    monkeypatch.setattr(settings, "edge_release", "v3.0.0")
    with SessionLocal() as db:
        assert bundle.group_pin(db, "general") is None
    # install one-liner carries --version of the group's pin
    monkeypatch.setattr(settings, "edge_release", "v2.0.0")
    r = client.post(f"{ADMIN}/edges", json={"name": "n1", "ipv4": "5.160.1.20"})
    assert "--version v2.0.0" in r.json()["install"]


def test_edge_dict_release_fields(client, releases, monkeypatch):
    monkeypatch.setattr(settings, "edge_release", "v2.1.0")
    eid, tok = mk_edge(client, "e1", "5.160.1.10")
    hb(client, tok, release="v2.0.0")
    e = next(x for x in client.get(f"{ADMIN}/edges").json() if x["id"] == eid)
    assert (e["release"], e["pinned_release"], e["release_ok"]) == ("v2.0.0", "v2.1.0", False)
    hb(client, tok, release="not-a-version")
    e = next(x for x in client.get(f"{ADMIN}/edges").json() if x["id"] == eid)
    assert e["release"] is None
    monkeypatch.setattr(settings, "edge_release", "")
    e = next(x for x in client.get(f"{ADMIN}/edges").json() if x["id"] == eid)
    assert e["pinned_release"] is None and e["release_ok"] is None


def test_unknown_heartbeat_and_usage_keys_are_ignored(client):
    """§23.16: the models keep pydantic's default extra="ignore" (old controller / new agent pinned)."""
    from app import routes_edge

    for model in (routes_edge.Heartbeat, routes_edge.UsageItem, routes_edge.LiveItem, routes_edge.UsageIn):
        assert model.model_config.get("extra", "ignore") == "ignore"
    _, tok = mk_edge(client, "e1", "5.160.1.10")
    hb(client, tok, future_field={"x": 1}, upgrade={"bad": True}, capabilities={"self_upgrade": True, "rum": 1})


# ================================================================== §23.2 rollouts

def fleet(client, n_home=4, n_global=0, release="v2.0.0", caps=None):
    out = []
    for i in range(n_home):
        out.append(mk_edge(client, f"h{i}", f"5.160.1.{10 + i}", "home"))
    for i in range(n_global):
        out.append(mk_edge(client, f"g{i}", f"8.8.1.{10 + i}", "global"))
    for _, tok in out:
        hb(client, tok, release=release, capabilities=caps if caps is not None else {"self_upgrade": True})
    return out


def test_ring_computation_canary_percent_region_spread_manual(client, releases):
    edges = fleet(client, n_home=4, n_global=3)
    _, tok = mk_edge(client, "old", "5.160.1.99")
    hb(client, tok, release="v2.0.0")  # no self_upgrade -> manual
    r = client.post(f"{ADMIN}/rollouts", json={"release": "v2.1.0", "dry_run": True})
    assert r.status_code == 200 and r.json()["dry_run"] is True
    rings = {x["ring"]: x["edges"] for x in r.json()["rings"]}
    # canary: the edge with the most siblings (home pool: 5 incl. the manual one), lowest id
    assert [e["name"] for e in rings[0]] == ["h0"]
    # ring 1 = ceil(25 % of the 6 remaining) = 2, round-robin over the region pools (global, home)
    assert sorted(e["name"] for e in rings[1]) == ["g0", "h1"]
    assert {e["name"]: e["state"] for e in rings[2]}["old"] == "manual"
    with SessionLocal() as db:
        assert db.scalar(select(Rollout.id)) is None  # dry run stores nothing
    assert len(edges) == 7


def test_create_refusals(client, releases):
    fleet(client, 2)
    assert client.post(f"{ADMIN}/rollouts", json={"release": "v9.0.0"}).status_code == 404
    _, tok = mk_edge(client, "norb", "5.160.1.50")
    hb(client, tok, release="v1.0.0", capabilities={"self_upgrade": True})  # v1.0.0 not in the dir
    r = client.post(f"{ADMIN}/rollouts", json={"release": "v2.1.0"})
    assert r.status_code == 422 and r.json() == {"detail": "no_rollback_release", "edges": ["norb"]}
    r = client.post(f"{ADMIN}/rollouts", json={"release": "v2.1.0", "allow_no_rollback": True})
    assert r.status_code == 201
    r2 = client.post(f"{ADMIN}/rollouts", json={"release": "v2.1.0"})
    assert r2.status_code == 409 and r2.json()["detail"] == "rollout_active"
    rid = r.json()["id"]
    bad = client.post(f"{ADMIN}/rollouts/{rid}/resume")
    assert bad.status_code == 409 and bad.json() == {"detail": "invalid_state", "state": "planned"}
    assert client.post(f"{ADMIN}/rollouts/{rid}/start").json()["state"] == "running"
    with SessionLocal() as db:
        assert db.scalar(select(AuditLog).where(AuditLog.action == "rollout.start")) is not None


def _tick(now=None):
    with SessionLocal() as db:
        return rollout.tick(db, now or utcnow())


def _state(rid):
    with SessionLocal() as db:
        r = db.get(Rollout, rid)
        return r.state, {db.get(Edge, x.edge_id).name: x.state for x in
                         db.scalars(select(RolloutEdge).where(RolloutEdge.rollout_id == rid))}


def test_rollout_happy_path_node_upgrade_shape_and_pin_advance(client, releases):
    edges = fleet(client, 2)
    rid = client.post(f"{ADMIN}/rollouts", json={"release": "v2.1.0", "soak_minutes": 5}).json()["id"]
    client.post(f"{ADMIN}/rollouts/{rid}/start")
    before = client.get("/edge/v1/config", headers=auth(edges[0][1])).json()
    _tick()
    st, es = _state(rid)
    assert es == {"h0": "upgrading", "h1": "pending"}  # parallel 1 per pool
    cfg = client.get("/edge/v1/config", headers=auth(edges[0][1])).json()
    up = cfg["node"]["upgrade"]
    assert up == {"id": f"{rid}-1", "release": "v2.1.0", "sha256": hashlib.sha256(b"bundle v2.1.0").hexdigest(),
                  "drain_minutes": 15, "rollback": False, "timeout_s": 3600}
    # node.upgrade is the only difference of the body (it is a non-rendered key on the edge)
    strip = lambda c: {k: v for k, v in c.items() if k != "version"}  # noqa: E731
    assert {**strip(cfg), "node": {**cfg["node"], "upgrade": None}} == strip(before)
    assert client.get("/edge/v1/config", headers=auth(edges[1][1])).json()["node"]["upgrade"] is None
    hb(client, edges[0][1], release="v2.1.0", upgrade={"id": f"{rid}-1", "release": "v2.1.0", "state": "done",
                                                       "error": None, "rollback": False})
    _tick()
    assert _state(rid)[1]["h0"] == "soaking"

    def soak_over():
        with SessionLocal() as db:
            for x in db.scalars(select(RolloutEdge).where(RolloutEdge.state == "soaking")):
                x.soak_until = utcnow() - timedelta(seconds=1)
            db.commit()

    soak_over()
    _tick()
    st, es = _state(rid)
    assert es["h0"] == "healthy" and es["h1"] == "upgrading"
    hb(client, edges[1][1], release="v2.1.0", upgrade={"id": f"{rid}-1", "release": "v2.1.0", "state": "done",
                                                       "rollback": False})
    _tick()
    soak_over()
    _tick()
    assert _state(rid)[0] == "completed"
    with SessionLocal() as db:
        assert bundle.group_pin(db, "general") == "v2.1.0"
    m = client.get("/metrics").text
    assert f'pcdn_rollout_state{{rollout="{rid}",state="completed"}} 1' in m


def test_last_edge_block_skip_and_force(client, releases):
    (eid, tok), = fleet(client, 1)
    rid = client.post(f"{ADMIN}/rollouts", json={"release": "v2.1.0"}).json()["id"]
    client.post(f"{ADMIN}/rollouts/{rid}/start")
    _tick()
    with SessionLocal() as db:
        r = db.get(Rollout, rid)
        assert r.state == "paused" and r.reason == "last_edge:h0"
    assert "rollout_blocked:%d" % rid in {c["key"] for c in alerts.open_alerts()}
    assert _state(rid)[1] == {"h0": "blocked"}
    body = client.post(f"{ADMIN}/rollouts/{rid}/edges/{eid}/force").json()
    assert body["state"] == "running"
    _tick()
    assert _state(rid)[1] == {"h0": "upgrading"}
    assert client.get("/edge/v1/config", headers=auth(tok)).json()["node"]["upgrade"]["drain_minutes"] == 0


def test_wait_when_pool_would_be_empty_and_upgrade_timeout(client, releases):
    edges = fleet(client, 2)
    rid = client.post(f"{ADMIN}/rollouts", json={"release": "v2.1.0", "auto_rollback": False}).json()["id"]
    client.post(f"{ADMIN}/rollouts/{rid}/start")
    with SessionLocal() as db:  # the sibling is offline: the canary waits (not blocked: h1 may return)
        e = db.scalar(select(Edge).where(Edge.name == "h1"))
        e.last_seen_at = utcnow() - timedelta(hours=1)
        db.commit()
    _tick()
    assert _state(rid)[1]["h0"] == "pending"
    hb(client, edges[1][1], release="v2.0.0")
    _tick()
    assert _state(rid)[1]["h0"] == "upgrading"
    _tick(utcnow() + timedelta(minutes=61))
    st, es = _state(rid)
    assert es["h0"] == "failed" and st == "paused"
    with SessionLocal() as db:
        x = db.scalar(select(RolloutEdge).where(RolloutEdge.rollout_id == rid, RolloutEdge.state == "failed"))
        assert x.error == "upgrade_timeout"
    # retry puts it back to pending and resumes
    eid = edges[0][0]
    assert client.post(f"{ADMIN}/rollouts/{rid}/edges/{eid}/retry").json()["state"] == "running"


def _to_soak(client, rid, tok, baseline=None):
    _tick()
    hb(client, tok, release="v2.1.0", upgrade={"id": f"{rid}-1", "release": "v2.1.0", "state": "done", "rollback": False})
    _tick()


def test_gates_probe_tunnel_probe_and_error_pct(client, releases):
    edges = fleet(client, 2, caps={"self_upgrade": True, "tunnel_probe": True})
    rid = client.post(f"{ADMIN}/rollouts", json={"release": "v2.1.0"}).json()["id"]
    client.post(f"{ADMIN}/rollouts/{rid}/start")
    _to_soak(client, rid, edges[0][1])
    with SessionLocal() as db:
        x = db.scalar(select(RolloutEdge).where(RolloutEdge.rollout_id == rid, RolloutEdge.state == "soaking"))
        e = db.get(Edge, x.edge_id)
        g = rollout.gate(db, x, e, utcnow())
        assert g["heartbeat"] and g["probe"] and g["tunnel_probe"] is True and g["error_pct"] is None
        assert g["limit_pct"] == 1.0
        # error % only from 200 requests on, against max(1 %, 2 × baseline)
        hour = utcnow().replace(minute=0, second=0, microsecond=0)
        db.add(UsageHourly(site_id=0, edge_id=e.id, hour=hour, bytes=0, requests=150,
                           details=json.dumps({"platform_errors": 50})))
        db.commit()
        x.started_at = hour
        assert rollout.gate(db, x, e, utcnow())["error_pct"] is None
        db.query(UsageHourly).update({"requests": 300})
        db.commit()
        assert rollout.gate(db, x, e, utcnow())["error_pct"] == pytest.approx(16.667, abs=0.01)
        x.baseline_err_pct = 10.0
        assert rollout.gate(db, x, e, utcnow())["limit_pct"] == 20.0
        db.rollback()
        e.tunnel_degraded = True
        db.commit()
    _tick()
    st, es = _state(rid)
    assert es["h0"] == "rolling_back" and st == "rolling_back"  # auto rollback
    with SessionLocal() as db:
        assert db.scalar(select(RolloutEdge).where(RolloutEdge.state == "rolling_back")).error is None
    assert f"rollout_failed:{rid}" in {c["key"] for c in alerts.open_alerts()}


def test_tunnel_probe_gate_needs_the_capability(client, releases):
    edges = fleet(client, 2)
    rid = client.post(f"{ADMIN}/rollouts", json={"release": "v2.1.0"}).json()["id"]
    client.post(f"{ADMIN}/rollouts/{rid}/start")
    _to_soak(client, rid, edges[0][1])
    with SessionLocal() as db:
        e = db.scalar(select(Edge).where(Edge.name == "h0"))
        e.tunnel_degraded = True
        db.commit()
    _tick()
    assert _state(rid)[1]["h0"] == "soaking"


def test_probe_gate_and_auto_rollback_completion(client, releases):
    edges = fleet(client, 2)
    rid = client.post(f"{ADMIN}/rollouts", json={"release": "v2.1.0"}).json()["id"]
    client.post(f"{ADMIN}/rollouts/{rid}/start")
    _to_soak(client, rid, edges[0][1])
    with SessionLocal() as db:
        db.scalar(select(Edge).where(Edge.name == "h0")).probe_fail = settings.probe_fail_checks
        db.commit()
    _tick()
    assert _state(rid)[0] == "rolling_back"
    cfg = client.get("/edge/v1/config", headers=auth(edges[0][1])).json()["node"]["upgrade"]
    assert cfg["release"] == "v2.0.0" and cfg["rollback"] is True and cfg["id"] == f"{rid}-2"
    hb(client, edges[0][1], release="v2.0.0", upgrade={"id": f"{rid}-2", "release": "v2.0.0", "state": "done",
                                                       "rollback": True})
    _tick()
    assert _state(rid) == ("rolled_back", {"h0": "rolled_back", "h1": "skipped"}) or _state(rid)[0] == "rolled_back"
    assert f"rollout_failed:{rid}" not in {c["key"] for c in alerts.open_alerts()}


def test_blocked_rollback_pauses_and_alerts_critical(client, releases, monkeypatch):
    sent = []
    monkeypatch.setattr(alerts, "raise_alert", lambda k, t, x, s="warning": sent.append((k, s)))
    (eid, tok), = fleet(client, 1)
    rid = client.post(f"{ADMIN}/rollouts", json={"release": "v2.1.0"}).json()["id"]
    client.post(f"{ADMIN}/rollouts/{rid}/start")
    client.post(f"{ADMIN}/rollouts/{rid}/edges/{eid}/force")
    _to_soak(client, rid, tok)
    with SessionLocal() as db:
        x = db.scalar(select(RolloutEdge))
        x.force_no_drain = False
        db.get(Edge, eid).probe_fail = 99
        db.commit()
    _tick()
    with SessionLocal() as db:
        r = db.get(Rollout, rid)
        assert r.state == "paused" and r.reason.startswith("last_edge")
    assert (f"rollout_blocked:{rid}", "critical") in sent
    # resume puts the edge back into the rollback
    client.post(f"{ADMIN}/rollouts/{rid}/edges/{eid}/force")
    with SessionLocal() as db:
        assert db.get(Rollout, rid).state == "rolling_back"


def test_manual_rollback_abort_and_transitions(client, releases):
    fleet(client, 2)
    rid = client.post(f"{ADMIN}/rollouts", json={"release": "v2.1.0"}).json()["id"]
    assert client.post(f"{ADMIN}/rollouts/{rid}/pause").status_code == 409
    client.post(f"{ADMIN}/rollouts/{rid}/start")
    assert client.post(f"{ADMIN}/rollouts/{rid}/pause").json()["state"] == "paused"
    assert client.post(f"{ADMIN}/rollouts/{rid}/resume").json()["state"] == "running"
    assert client.post(f"{ADMIN}/rollouts/{rid}/abort").json()["state"] == "aborted"
    assert client.post(f"{ADMIN}/rollouts/{rid}/abort").status_code == 409
    listing = client.get(f"{ADMIN}/rollouts").json()["rollouts"]
    assert listing[0]["id"] == rid and listing[0]["rings"]
    rel = client.get(f"{ADMIN}/releases").json()
    assert rel["nodes"] == {"v2.0.0": 2} and {r["version"] for r in rel["releases"]} >= {"v2.1.0"}


def test_rollout_never_reads_rum_or_reachability():
    """Hard constraint (§23.7 / §23.2 / §23.9): node selection / rollouts / provisioning never import rum."""
    base = os.path.join(os.path.dirname(__file__), "..", "app")
    for name in ("dnsbuild.py", "rollout.py", "provisioning.py", "services.py", "probe.py", "edge_state.py"):
        tree = ast.parse(open(os.path.join(base, name), encoding="utf-8").read())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                mods = [node.module or ""] + [a.name for a in node.names]
            elif isinstance(node, ast.Import):
                mods = [a.name for a in node.names]
            else:
                continue
            if name == "services.py":
                # services only builds the per-site RUM edge block (rum.edge_block) and deletes a
                # deleted site's rows; it never reads RUM aggregates
                import re

                src = open(os.path.join(base, name), encoding="utf-8").read()
                assert not re.search(r"\brum\.(report|percentile|ingest)\(", src)
                assert "select(RumHourly" not in src
                continue
            assert not any(m.split(".")[-1] in ("rum", "isp_names") for m in mods), (name, mods)
    # scheduler DNS jobs never touch RUM
    src = open(os.path.join(base, "scheduler.py"), encoding="utf-8").read()
    for job in ("def job_edges", "def job_probe"):
        body = src.split(job, 1)[1].split("\ndef ", 1)[0]
        assert "rum" not in body.replace("return", "")


# ================================================================== §23.3 backups

@pytest.fixture()
def benv(tmp_path, monkeypatch):
    for k, v in {"backup_dir": str(tmp_path / "backups"), "backup_pdns_db": "", "acme_home": "",
                 "backup_passphrase": "", "backup_encryption_key": "", "backup_keep": 14,
                 "backup_s3_endpoint": "", "backup_s3_keep": 0, "backup_enabled": True, "backup_hour": 2,
                 "backup_require_encryption": False, "backup_s3_keep_days": 0, "data_encryption_key": ""}.items():
        monkeypatch.setattr(settings, k, v)
    return tmp_path


def test_backup_key_alias_conflict_and_data_key(benv, monkeypatch):
    monkeypatch.setattr(settings, "backup_encryption_key", "k1")
    assert backup.backup_key() == "k1"
    monkeypatch.setattr(settings, "backup_passphrase", "k1")
    assert backup.backup_key() == "k1"
    monkeypatch.setattr(settings, "backup_passphrase", "k2")
    with pytest.raises(backup.BackupError, match="backup_key_conflict"):
        backup.backup_key()
    monkeypatch.setattr(settings, "backup_passphrase", "")
    key = Fernet.generate_key().decode()
    monkeypatch.setattr(settings, "data_encryption_key", key)
    monkeypatch.setattr(settings, "backup_encryption_key", key)
    with pytest.raises(backup.BackupError, match="backup_key_equals_data_key"):
        backup.backup_key()


def test_scrub_removes_every_secret(monkeypatch):
    for k, v in {"backup_encryption_key": "PASSPHRASE1", "backup_s3_secret_key": "S3SECRETKEY",
                 "backup_s3_access_key": "AKIAXYZ", "data_encryption_key": "DATAKEY1,DATAKEY2"}.items():
        monkeypatch.setattr(settings, k, v)
    text = ("failed PASSPHRASE1 S3SECRETKEY AKIAXYZ DATAKEY2 postgresql://user:pw@db/x "
            "Authorization: AWS4-HMAC-SHA256 Credential=abc X-Amz-Signature=deadbeef00")
    out = backup.scrub(text)
    for secret in ("PASSPHRASE1", "S3SECRETKEY", "AKIAXYZ", "DATAKEY2", "user:pw", "deadbeef00", "Credential=abc"):
        assert secret not in out


class FakeS3:
    def __init__(self, tamper=False):
        self.objects, self.tamper = {}, tamper

    def handler(self, request: httpx.Request) -> httpx.Response:
        key = request.url.path.split("/b/", 1)[-1] if "/b/" in request.url.path else ""
        if request.method == "PUT":
            self.objects[key] = (request.read(), request.headers.get("x-amz-meta-sha256"))
            return httpx.Response(200)
        if request.method == "HEAD":
            data, meta = self.objects[key]
            return httpx.Response(200, headers={"content-length": str(len(data)),
                                                "x-amz-meta-sha256": "0" * 64 if self.tamper else meta})
        if request.method == "GET" and request.url.params.get("list-type"):
            items = "".join(f"<Contents><Key>{k}</Key><Size>{len(v[0])}</Size></Contents>"
                            for k, v in sorted(self.objects.items()))
            return httpx.Response(200, text=f"<ListBucketResult>{items}<IsTruncated>false</IsTruncated>"
                                            "</ListBucketResult>")
        if request.method == "GET":
            return httpx.Response(200, content=self.objects[key][0])
        if request.method == "DELETE":
            self.objects.pop(key, None)
            return httpx.Response(204)
        return httpx.Response(400)


def _s3(fake):
    return backup.S3Client("https://s3.test", "b", "AK", "SK", transport=httpx.MockTransport(fake.handler))


def test_offsite_head_sha_verify_and_require_encryption(client, benv, monkeypatch):
    monkeypatch.setattr(settings, "backup_s3_prefix", "p/")
    fake = FakeS3()
    res = backup.create_backup(s3=_s3(fake))
    assert res["uploaded"] and fake.objects[f"p/{res['name']}"][1] == res["sha256"]
    bad = FakeS3(tamper=True)
    with pytest.raises(backup.BackupError, match="offsite_verify_failed"):
        backup.create_backup(s3=_s3(bad))
    monkeypatch.setattr(settings, "backup_require_encryption", True)
    with pytest.raises(backup.BackupError, match="backup_unencrypted_refused"):
        backup.create_backup(s3=_s3(FakeS3()))


def test_keep_days_pruning_keeps_newest(benv):
    import datetime as dt

    fake = FakeS3()
    s3 = _s3(fake)
    for d in (1, 5, 20, 30):
        fake.objects[f"p/pcdn-backup-202609{d:02d}T020000Z.tar.gz"] = (b"x", None)
    now = dt.datetime(2026, 10, 3, tzinfo=dt.timezone.utc)
    removed = backup.prune_remote_days(s3, "p/", 10, now)
    assert removed == ["p/pcdn-backup-20260901T020000Z.tar.gz", "p/pcdn-backup-20260905T020000Z.tar.gz",
                       "p/pcdn-backup-20260920T020000Z.tar.gz"]
    assert list(fake.objects) == ["p/pcdn-backup-20260930T020000Z.tar.gz"]
    # only one, very old -> the newest is never deleted
    fake.objects = {"p/pcdn-backup-20200101T020000Z.tar.gz": (b"x", None)}
    assert backup.prune_remote_days(s3, "p/", 10, now) == []


def test_manifest_counts_and_full_sqlite_verify(client, benv, monkeypatch):
    client.post(f"{ADMIN}/sites", json={"domain": "example.com", "origin_ip": "93.184.216.34"})
    monkeypatch.setattr(settings, "backup_encryption_key", "pass-phrase-1")
    res = backup.create_backup(upload=False)
    out = backup.verify_backup(s3=None)
    assert out["ok"] and out["level"] == "full" and out["location"] == "local", out
    assert {"download", "decrypt", "members", "revision", "counts", "decrypt_secret"} <= set(out["checks"])
    assert out["name"] == res["name"]
    # a wrong key fails without leaking it
    monkeypatch.setattr(settings, "backup_encryption_key", "other-key")
    bad = backup.verify_backup(s3=None)
    assert not bad["ok"] and "other-key" not in (bad["error"] or "")


def test_pg_scratch_refusals(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "database_url", "postgresql+psycopg://u:p@db:5432/pcdn")
    with pytest.raises(backup.BackupError, match="scratch_is_live_database"):
        backup._verify_pg_full("x", {}, {}, "postgresql+psycopg://other:pw@db:5432/pcdn")
    assert not backup._same_database("postgresql://u@db/pcdn", "postgresql://u@db/scratch")


def test_pg_full_verify_and_marker_refusal(pg_url, tmp_path, monkeypatch):
    from sqlalchemy import create_engine, text

    from app import migrate

    live = create_engine(pg_url)
    migrate.upgrade(live)
    monkeypatch.setattr(settings, "database_url", pg_url)
    scratch_name = "pcdn_scratch_" + os.urandom(4).hex()
    admin = create_engine(pg_url, isolation_level="AUTOCOMMIT")
    with admin.connect() as c:
        c.execute(text(f'CREATE DATABASE "{scratch_name}"'))
    from sqlalchemy.engine import make_url

    scratch = make_url(pg_url).set(database=scratch_name).render_as_string(hide_password=False)
    try:
        dump = backup.dump_controller_db(str(tmp_path), pg_url)
        manifest = {"alembic_revision": migrate.head_revision(), "counts": backup._dump_counts(dump, "postgresql")}
        checks = {}
        backup._verify_pg_full(dump, manifest, checks, scratch)
        assert checks["revision"] and checks["counts"], checks
        eng = create_engine(scratch)
        with eng.begin() as c:
            c.execute(text("CREATE TABLE pcdn_live_marker (id integer)"))
        eng.dispose()
        with pytest.raises(backup.BackupError, match="scratch_has_live_marker"):
            backup._verify_pg_full(dump, manifest, {}, scratch)
    finally:
        live.dispose()
        with admin.connect() as c:
            c.execute(text(f'DROP DATABASE IF EXISTS "{scratch_name}" WITH (FORCE)'))
        admin.dispose()


def test_backup_api_queue_runs_history_and_alerts(client, benv, monkeypatch, alert_settings):
    st = client.get(f"{ADMIN}/backups").json()
    assert st["enabled"] is True and st["encrypted"] is False and st["offsite"] is False
    assert st["last_backup"] is None and st["schedule"]["verify"]["enabled"] is False
    assert client.post(f"{ADMIN}/backups/run").status_code == 202
    assert client.post(f"{ADMIN}/backups/run").status_code == 409
    assert client.post(f"{ADMIN}/backups/verify").status_code == 202
    with SessionLocal() as db:
        scheduler.job_backup(db, now=utcnow().replace(hour=0))
        scheduler.job_backup_verify(db, now=utcnow())
    st = client.get(f"{ADMIN}/backups").json()
    lb, lv = st["last_backup"], st["last_verify"]
    assert lb["ok"] and lb["kind"] == "backup" and lb["location"] == "local" and lb["finished_at"]
    assert lv["ok"] and lv["level"] == "full" and lv["id"]
    assert "backup_not_offsite" in {c["key"] for c in alerts.open_alerts()}
    deep = client.get("/healthz/deep").json()["backup"]
    assert deep["verify_ok"] is True and deep["offsite"] is False and deep["verify_age_s"] is not None
    # a failing verify alerts critical and the error is scrubbed
    monkeypatch.setattr(settings, "backup_encryption_key", "SECRETKEY99")
    monkeypatch.setattr(backup, "verify_backup", lambda: {"ok": False, "level": None, "checks": {}, "name": "x",
                                                          "size": None, "location": None, "sha256": None,
                                                          "error": "boom SECRETKEY99"})
    with SessionLocal() as db:
        scheduler.job_backup_verify(db, now=utcnow(), force=True)
        assert "SECRETKEY99" not in db.scalar(select(BackupRun).order_by(BackupRun.id.desc())).error
    assert "backup_verify_failed" in {c["key"] for c in alerts.open_alerts()}
    with SessionLocal() as db:
        for _ in range(backup_runs.KEEP + 5):
            db.add(BackupRun(kind="backup", checks="{}"))
        db.commit()
        backup_runs.finish(db, db.scalar(select(BackupRun).order_by(BackupRun.id.desc())), True)
        assert db.query(BackupRun).count() == backup_runs.KEEP


def test_partial_streak_alert(client, monkeypatch, alert_settings):
    with SessionLocal() as db:
        for _ in range(2):
            backup_runs.record_verify_alerts(db, {"ok": True, "level": "partial", "name": "x"})
    assert "backup_verify_partial" in {c["key"] for c in alerts.open_alerts()}


# ================================================================== §23.9 provisioning + join

@pytest.fixture()
def prov(monkeypatch):
    monkeypatch.setattr(settings, "provisioning_enabled", True)
    monkeypatch.setattr(settings, "provisioner_token", "p" * 40)
    monkeypatch.setattr(settings, "data_encryption_key", Fernet.generate_key().decode())
    provisioning._join_hits.clear()
    yield
    provisioning._join_hits.clear()


def test_provisioning_off_by_default(client):
    assert client.get(f"{ADMIN}/provisioning/proposals").status_code == 404
    assert client.get(f"{ADMIN}/provisioner/jobs/next", headers=auth("p" * 40)).status_code == 404


def test_sizing_formula_capacity_only(monkeypatch):
    monkeypatch.setattr(settings, "provision_target_pct", 60.0)
    assert provisioning.count_for(900, 1000, 500) == 1   # 900/0.6 = 1500 - 1000 = 500 -> 1
    assert provisioning.count_for(1500, 1000, 500) == 3  # 2500 - 1000 = 1500 -> 3
    assert provisioning.count_for(100, 1000, 500) == 1


def test_proposal_on_capacity_alert_once_and_full_flow(client, prov, monkeypatch):
    for i, cap in enumerate((1000, 1000)):
        r = client.post(f"{ADMIN}/edges", json={"name": f"e{i}", "ipv4": f"5.160.1.{10 + i}", "region": "home",
                                                 "capacity_mbps": cap})
        assert r.status_code == 201
    report = [{"group": "general", "p95_mbps": 1500.0, "capacity_mbps": 2000, "pct": 75.0}]
    monkeypatch.setattr(alerts, "open_alerts", lambda db=None: [{"key": "capacity:general"}])
    with SessionLocal() as db:
        ids = provisioning.propose_from_capacity(db, report)
        assert len(ids) == 1 and provisioning.propose_from_capacity(db, report) == []
    p = client.get(f"{ADMIN}/provisioning/proposals").json()["proposals"][0]
    assert (p["group"], p["size"], p["count"], p["state"]) == ("general", "medium", 1, "proposed")
    assert client.post(f"{ADMIN}/provisioning/proposals/{p['id']}/apply").status_code == 409
    r = client.post(f"{ADMIN}/provisioning/proposals/{p['id']}/approve", json={"count": 2})
    assert r.status_code == 200 and r.json()["state"] == "approved" and len(r.json()["edges"]) == 2
    # provisioner auth
    assert client.get(f"{ADMIN}/provisioner/jobs/next").status_code == 401
    assert client.get(f"{ADMIN}/provisioner/jobs/next", headers=auth("x" * 40)).status_code == 401
    job = client.get(f"{ADMIN}/provisioner/jobs/next", headers=auth("p" * 40)).json()["job"]
    assert job["action"] == "plan" and all(e["join_token"].startswith("jt_") for e in job["edges"])
    tokens = [e["join_token"] for e in job["edges"]]
    with SessionLocal() as db:
        assert db.get(ProvisionProposal, p["id"]).join_tokens_enc is None  # wiped after the first fetch
    assert client.get(f"{ADMIN}/provisioner/jobs/next", headers=auth("p" * 40)).json()["job"] is None
    r = client.post(f"{ADMIN}/provisioner/jobs/{p['id']}/plan", headers=auth("p" * 40),
                    json={"summary": f"user_data {tokens[0]}", "adds": 2, "changes": 0, "destroys": 0})
    assert r.status_code == 422
    r = client.post(f"{ADMIN}/provisioner/jobs/{p['id']}/plan", headers=auth("p" * 40),
                    json={"summary": "2 to add, jt_***", "adds": 2, "changes": 0, "destroys": 1})
    assert r.status_code == 200
    r = client.post(f"{ADMIN}/provisioning/proposals/{p['id']}/apply")
    assert r.status_code == 409 and r.json()["detail"] == "plan_destroys"
    with SessionLocal() as db:
        db.get(ProvisionProposal, p["id"]).plan_destroys = 0
        db.commit()
    assert client.post(f"{ADMIN}/provisioning/proposals/{p['id']}/apply").json()["state"] == "apply_approved"
    job = client.get(f"{ADMIN}/provisioner/jobs/next", headers=auth("p" * 40)).json()["job"]
    assert job["action"] == "apply" and "join_token" not in job["edges"][0]
    client.post(f"{ADMIN}/provisioner/jobs/{p['id']}/result", headers=auth("p" * 40), json={"ok": True})
    # join: single use, expiry, then the proposal becomes joined
    for t in tokens:
        r = client.post("/edge/v1/join", json={"join_token": t, "hostname": "n"})
        assert r.status_code == 200 and r.json()["token"].startswith("edge_")
        hb(client, r.json()["token"])
    assert client.post("/edge/v1/join", json={"join_token": tokens[0]}).status_code == 401
    with SessionLocal() as db:
        provisioning.check(db)
        assert db.get(ProvisionProposal, p["id"]).state == "joined"


def test_join_expiry_rate_limit_and_admin_mint(client, prov):
    eid, _ = mk_edge(client, "fresh", "5.160.1.30")
    r = client.post(f"{ADMIN}/edges/{eid}/join-token")
    body = r.json()
    assert body["join_token"].startswith("jt_") and "PCDN_JOIN_TOKEN=" in body["install"]
    with SessionLocal() as db:
        assert db.scalar(select(EdgeJoinToken)).token_hash != body["join_token"]
        db.scalar(select(EdgeJoinToken)).expires_at = utcnow() - timedelta(seconds=1)
        db.commit()
    assert client.post("/edge/v1/join", json={"join_token": body["join_token"]}).status_code == 401
    for _ in range(9):
        client.post("/edge/v1/join", json={"join_token": "jt_" + "0" * 40})
    assert client.post("/edge/v1/join", json={"join_token": "jt_" + "0" * 40}).status_code == 429
    # an edge that already heartbeated gets no join token
    eid2, tok2 = mk_edge(client, "old", "5.160.1.31")
    hb(client, tok2)
    assert client.post(f"{ADMIN}/edges/{eid2}/join-token").status_code == 409
    with SessionLocal() as db:
        assert "jt_" not in json.dumps([a.detail for a in db.scalars(select(AuditLog))])


def test_approval_needs_encryption_and_reject_drops_edges(client, prov, monkeypatch):
    p = client.post(f"{ADMIN}/provisioning/proposals", json={"group": "general", "region": "global",
                                                              "size": "small", "count": 1}).json()
    monkeypatch.setattr(settings, "data_encryption_key", "")
    r = client.post(f"{ADMIN}/provisioning/proposals/{p['id']}/approve")
    assert r.status_code == 422 and r.json()["detail"] == "encryption_required"
    monkeypatch.setattr(settings, "data_encryption_key", Fernet.generate_key().decode())
    client.post(f"{ADMIN}/provisioning/proposals/{p['id']}/approve")
    assert client.post(f"{ADMIN}/provisioning/proposals/{p['id']}/reject").json()["state"] == "rejected"
    with SessionLocal() as db:
        assert db.scalar(select(Edge).where(Edge.name.like("general-global-p%"))) is None


# ================================================================== §23.11 SLO

def _edge_ns(group="general", region="home", ok=True, ms=100, drain="", at=None):
    from types import SimpleNamespace

    return SimpleNamespace(enabled=True, group=group, region=region, probe_ok=ok, probe_ms=ms,
                           probe_at=at or utcnow(), drain_state=drain)


def test_tick_classification():
    now = utcnow()
    r = slo.classify([_edge_ns(), _edge_ns(region="global", ok=False)], now)
    assert r["general"]["tick"] is False  # the global pool has no healthy edge
    r = slo.classify([_edge_ns(), _edge_ns(ok=False), _edge_ns(region="global", ok=False, drain="draining")], now)
    assert r["general"]["tick"] is True  # draining edges are excluded from the pools
    r = slo.classify([_edge_ns(ms=500), _edge_ns(ms=100)], now)
    assert r["general"]["ok"] == 2 and r["general"]["fast"] == 1
    assert slo.classify([], now) == {}


def test_burn_math_and_overrides(monkeypatch):
    assert slo.burn_rate(1, 1000, 99.9) == 1.0
    assert slo.burn_rate(0, 0, 99.9) == 0.0
    assert slo.burn_rate(144, 10000, 99.9) == 14.4
    monkeypatch.setattr(settings, "slo_overrides", {"tunnel": {"availability": 99.5}})
    assert slo.objectives("tunnel")["availability"] == 99.5 and slo.objectives("general")["availability"] == 99.9


def test_fast_and_slow_burn_alerts_and_resolution(client, alert_settings):
    now = utcnow()
    with SessionLocal() as db:
        start = slo.floor5(now)
        for i in range(72):  # 6 h of 5-minute buckets
            t = start - timedelta(minutes=5 * i)
            db.add(SloBucket(group="general", start=t, res="5m", avail_good=0, avail_total=5, lat_good=5, lat_total=5,
                             requests=0, errors=0))
        db.commit()
        state = slo.run(db, now)
    g = next(x for x in state["groups"] if x["group"] == "general")
    assert g["slis"]["availability"]["alert"] == "fast"
    keys = {c["key"] for c in alerts.open_alerts()}
    assert "slo_burn_fast:general:availability" in keys
    with SessionLocal() as db:
        db.query(SloBucket).filter(SloBucket.start >= start - timedelta(minutes=5)).update(
            {"avail_good": 5}, synchronize_session=False)
        db.commit()
        slo.run(db, now)
    assert "slo_burn_fast:general:availability" not in {c["key"] for c in alerts.open_alerts()}


def test_errors_from_pe_with_hourly_fallback_and_api_metrics(client):
    from app.models import AnalyticsMinute

    client.post(f"{ADMIN}/sites", json={"domain": "example.com"})
    eid, _ = mk_edge(client, "e1", "5.160.1.10")
    now = utcnow()
    t = slo.floor5(now) - timedelta(minutes=5)
    with SessionLocal() as db:
        db.add(AnalyticsMinute(site_id=1, minute=t, requests=1000, bytes=0, cache_hits=0,
                               details=json.dumps({"pe": 2, "oe": 0})))
        hour = now.replace(minute=0, second=0, microsecond=0) - timedelta(hours=2)
        db.add(UsageHourly(site_id=1, edge_id=eid, hour=hour, bytes=0, requests=500,
                           details=json.dumps({"platform_errors": 5})))
        db.commit()
        slo.fill_errors(db, t, t + timedelta(minutes=5))
        slo.rollup_hour(db, hour)
        db.commit()
        b5 = db.scalar(select(SloBucket).where(SloBucket.res == "5m", SloBucket.start == t))
        b1 = db.scalar(select(SloBucket).where(SloBucket.res == "1h", SloBucket.start == hour))
        assert (b5.requests, b5.errors) == (1000, 2) and (b1.requests, b1.errors) == (500, 5)
    body = client.get(f"{ADMIN}/slo").json()
    g = next(x for x in body["groups"] if x["group"] == "general")
    assert set(g["slis"]) == {"availability", "latency", "errors"} and g["daily"]
    assert client.get(f"{ADMIN}/slo?month=2026-13").status_code == 422
    m = client.get("/metrics").text
    for name in ("pcdn_slo_objective", "pcdn_slo_burn_rate", "pcdn_slo_error_budget_remaining"):
        assert name in m
    assert 'pcdn_slo_burn_rate{group="general",sli="availability",window="5m"}' in m


def test_slo_retention(client):
    now = utcnow()
    with SessionLocal() as db:
        db.add(SloBucket(group="general", start=now - timedelta(days=4), res="5m", avail_good=0, avail_total=0,
                         lat_good=0, lat_total=0, requests=0, errors=0))
        db.commit()
        slo.run(db, now)
        assert db.query(SloBucket).filter(SloBucket.start < now - timedelta(days=3)).count() == 0


# ================================================================== §23.12 node naming

def test_labels_numbering_disabled_keeps_numbers_region_default_en(client):
    a, _ = mk_edge(client, "edge-secret-1", "5.160.1.10")
    b, _ = mk_edge(client, "edge-secret-2", "5.160.1.11")
    c, _ = mk_edge(client, "edge-secret-3", "8.8.1.10", region="global")
    for eid in (a, b):
        assert client.patch(f"{ADMIN}/edges/{eid}", json={"display_city": "تهران"}).status_code == 200
    client.patch(f"{ADMIN}/edges/{b}", json={"enabled": False})
    with SessionLocal() as db:
        lab = edge_labels.labels(db)
    assert lab[a] == {"fa": "نود تهران ۱", "en": "Tehran node 1"}
    assert lab[b] == {"fa": "نود تهران ۲", "en": "Tehran node 2"}
    assert lab[c] == {"fa": "نود بین‌المللی", "en": "International node"}
    assert client.patch(f"{ADMIN}/edges/{a}", json={"display_city": "تهران1"}).status_code == 422
    client.patch(f"{ADMIN}/edges/{a}", json={"display_city": "کرج", "display_city_en": "Karaj City"})
    e = next(x for x in client.get(f"{ADMIN}/edges").json() if x["id"] == a)
    assert (e["display_label"], e["display_label_en"]) == ("نود کرج", "Karaj City node")
    client.patch(f"{ADMIN}/edges/{a}", json={"display_city": ""})
    e = next(x for x in client.get(f"{ADMIN}/edges").json() if x["id"] == a)
    assert e["display_city"] is None and e["display_label"] == "نود ایران"


def test_public_tag_stable_keyed_and_filter(client, monkeypatch):
    a, tok = mk_edge(client, "edge-secret-1", "5.160.1.10")
    e = next(x for x in client.get(f"{ADMIN}/edges").json() if x["id"] == a)
    tag = e["public_tag"]
    assert len(tag) == 8 and tag != hashlib.sha256(b"edge-secret-1").hexdigest()[:8]
    assert client.get("/edge/v1/config", headers=auth(tok)).json()["node"]["public_tag"] == tag
    assert [x["id"] for x in client.get(f"{ADMIN}/edges?tag={tag}").json()] == [a]
    assert client.get(f"{ADMIN}/edges?tag=zz").status_code == 422
    with SessionLocal() as db:
        assert edge_labels.public_tag(a, db) == tag  # stable
    monkeypatch.setattr(settings, "data_encryption_key", Fernet.generate_key().decode())
    with SessionLocal() as db:
        assert edge_labels.public_tag(a, db) != tag  # a different key -> a different tag


def test_edge_ips_unlabeled_sorted_deduplicated(client):
    mk_edge(client, "b", "9.9.9.9")
    assert client.post(f"{ADMIN}/edges", json={"name": "a", "ipv4": "11.1.0.2", "ipv6": "2a01:4f8::1"}).status_code == 201
    client.post(f"{ADMIN}/edges", json={"name": "c", "ipv4": "9.9.9.9"})
    client.post(f"{ADMIN}/edges/batch", json={"count": 1})
    client.post(f"{ADMIN}/sites", json={"domain": "example.com"})
    ips = client.get(f"{ADMIN}/sites/example.com").json()["edge_ips"]
    assert ips == ["9.9.9.9", "11.1.0.2", "2a01:4f8::1"]


def test_migration_live_marker_and_state_keys(client):
    with SessionLocal() as db:
        from app.models import LiveMarker

        assert db.get(LiveMarker, 1) is not None
        assert db.get(State, "node_tag_key") is None or db.get(State, "node_tag_key").value
