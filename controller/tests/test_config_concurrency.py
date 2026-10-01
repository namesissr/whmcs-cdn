"""Concurrent writes to one site's configuration never lose an update (each PUT rewrites the whole
site.config JSON, so a writer must merge into the row as locked now, not a copy loaded earlier),
and the rate limiters' 429 answers carry Retry-After."""

import threading

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app import migrate, routes_capi, routes_platform, sections
from app.config import settings
from app.db import SessionLocal
from app.models import Site
from app.routes_v2 import import_redirects_of, write_section_of
from tests.platform_helpers import S, auth, make_site

BODIES = {
    "cache": {"edge_ttl": 1234},
    "waf": {"mode": "detect"},
    "ddos": {"mode": "js"},
    "hotlink": {"enabled": True},
    "image": {"enabled": True},
    "bots": {"mode": "log"},
    "headers": {"request": [{"name": "X-A", "value": "1"}]},
    "errorpages": {"4xx": "<p>x</p>"},
}


@pytest.fixture(autouse=True)
def _reset_rate():
    for store in (routes_capi._hits, routes_capi._config_hits, routes_platform._test_hits):
        store.clear()
    yield
    for store in (routes_capi._hits, routes_capi._config_hits, routes_platform._test_hits):
        store.clear()


def _assert_saved(cfg: dict, bodies: dict):
    for section, body in bodies.items():
        for k, v in body.items():
            assert cfg[section][k] == v, (section, cfg[section])


def test_a_stale_site_object_does_not_overwrite_a_section_saved_in_between(client):
    make_site(client)
    with SessionLocal() as db:
        stale = db.scalar(select(Site))
        assert sections.get_section(stale, "cache")["edge_ttl"] == 86400  # loaded before the other write
        # another request saves the cache section meanwhile
        assert client.put(f"{S}/config/cache", json={"edge_ttl": 1234}).status_code == 200
        write_section_of(db, stale, "waf", {"mode": "detect"})
        # an append-import merges with the redirects as stored now, too
        assert client.put(f"{S}/config/redirects", json={"rules": [
            {"id": "r1", "source": "/a", "target": "/b"}]}).status_code == 200
        import_redirects_of(db, stale, "/c,/d,301", "append")
    cfg = client.get(f"{S}/config").json()
    assert cfg["cache"]["edge_ttl"] == 1234 and cfg["waf"]["mode"] == "detect"
    assert [r["source"] for r in cfg["redirects"]["rules"]] == ["/a", "/c"]


def test_plan_and_settings_writers_reread_the_row(client):
    make_site(client)
    assert client.put(f"{S}/config/cache", json={"edge_ttl": 777}).status_code == 200
    assert client.patch(f"{S}/settings", json={"force_https": True}).status_code == 200
    assert client.patch(f"{S}/plan", json={"features": {"max_webhooks": 3}}).status_code == 200
    assert client.patch(f"{S}/plan", json={"features": {"sla_target": 99.5}}).status_code == 200
    site = client.get(S).json()
    assert site["config"]["cache"]["edge_ttl"] == 777 and site["config"]["ssl"]["force_https"] is True
    feats = site["plan"]["features"]
    assert feats["max_webhooks"] == 3 and feats["sla_target"] == 99.5


def test_concurrent_section_writes_never_lose_an_update_pg(pg_url):
    """Real row locks (PostgreSQL): every writer starts from a stale copy, all PUT at once."""
    eng = create_engine(pg_url)
    try:
        migrate.upgrade(eng)
        Session = sessionmaker(bind=eng, expire_on_commit=False)
        with Session() as db:
            db.add(Site(domain="example.com"))
            db.commit()
        for _ in range(5):
            with Session() as db:
                db.scalar(select(Site)).config = "{}"
                db.commit()
            barrier = threading.Barrier(len(BODIES))
            errors = []

            def writer(section, body):
                try:
                    with Session() as db:
                        site = db.scalar(select(Site))
                        assert site.config == "{}"
                        db.commit()  # keep the (soon stale) copy, end the read transaction
                        barrier.wait()
                        write_section_of(db, site, section, body)
                except Exception as e:  # noqa: BLE001 - reported below
                    errors.append(e)

            threads = [threading.Thread(target=writer, args=item) for item in BODIES.items()]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            assert errors == []
            with Session() as db:
                _assert_saved(sections.all_config(db.scalar(select(Site))), BODIES)
    finally:
        eng.dispose()


# ------------------------------------------------------------------ Retry-After on 429

def test_capi_rate_limit_429_has_retry_after(client, monkeypatch):
    make_site(client)
    key = client.post(f"{S}/apikeys", json={"name": "k", "scopes": ["stats", "dns"]}).json()["key"]
    monkeypatch.setattr(settings, "capi_config_rate", 1)
    assert client.put("/capi/v1/config/bots", json={"mode": "log"}, headers=auth(key)).status_code == 200
    r = client.put("/capi/v1/config/bots", json={"mode": "off"}, headers=auth(key))
    assert r.status_code == 429 and 1 <= int(r.headers["Retry-After"]) <= 60
    monkeypatch.setattr(settings, "capi_rate", 3)
    codes = [client.get("/capi/v1/analytics", headers=auth(key)) for _ in range(2)]
    assert [c.status_code for c in codes] == [200, 429]  # 2 calls above + 1 here hit CAPI_RATE
    assert 1 <= int(codes[-1].headers["Retry-After"]) <= 60


def test_test_endpoint_429_has_retry_after(client, monkeypatch):
    make_site(client)
    monkeypatch.setattr(settings, "capi_config_rate", 1)
    assert client.post(f"{S}/logs/test").status_code == 200
    r = client.post(f"{S}/logs/test")
    assert r.status_code == 429 and 1 <= int(r.headers["Retry-After"]) <= 60
