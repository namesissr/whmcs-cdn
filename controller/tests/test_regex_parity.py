"""Customer regex safety: the controller's _safe_regex (save time, 422) must give the same verdict
as the edge's regex_unsafe / pcre_regex (edge/pcdn-agent.py), which SKIPS a rule it refuses. A
pattern the controller accepts but the edge refuses is a rule that silently does nothing.

Also: stored rules saved before today's check are dropped from the edge config, raise one alert
and are reported on GET of their section (X-Pcdn-Warnings)."""
import importlib.util
import json
from pathlib import Path

import pytest
from sqlalchemy import select

from app import alerts, scheduler, sections, services
from app.db import SessionLocal
from app.models import Site

AGENT = Path(__file__).resolve().parents[2] / "edge" / "pcdn-agent.py"

# no whitespace / (?P<..>: the controller refuses those outright (stricter than the edge on purpose)
CORPUS = [
    # safe
    r"^/blog/(\d+)/(.*)$", r"(?:/[a-z0-9-]+)*", r"([^/]+/)*x", r"(\w+\.)*com", r"^/(fa|en)/p-(\d+)$",
    r"(?:jpg|jpeg|png)$", r"(ab|cd)+", r"^/wp-(admin|login)", r"bot[0-9]+", r"^/(.*)$", r"\.php$",
    r"^/old/([^/]+)/(.*)$", r"^/a/.*", r"^(.*)/(\d+)$", r"Mozilla", r"curl/[0-9.]+", r"^/x{1,10}y",
    r"^/(?:a|b)/(.*)", r"^/[a-z]{1,40}/", r"(?i)^/admin", r"^/a.*b", r"^.*\.(jpg|png)$",
    r"^/(?=x)abc", r"^[^?]*\?.*$", r"^/a+b+$",
    # unsafe: nesting, alternation, back-references, conditionals
    r"(a+)+", r"(a*)*", r"(.*)+", r"(.*/)+", r"(a+a)+", r"(x{1,100}){1,100}", r"(a|a)+", r"(a|ab)+c",
    r"(x|)+", r"(?:/?[a-z]+)*", r"(a)\1", r"^(a)\1$", r"(a)?(?(1)b|c)", r"(\w+\s?)*", r"(.*a)*",
    r"(?:[a-z]+A)*", ".*" * 11,
    # unsafe: chained wide quantifiers (degree = chain length, +1 unanchored, must be <= 2)
    r"a.*b.*c", r"Mozilla.*Windows.*Chrome", r"^/(.*)/(.*)/(.*)x$", r"^a.*a.*b$", r".*x", r"a.*b",
    r"^/a.+b.+c", r"^\d+\d+\d+$", r"^/a.{0,100}b.{0,100}c", r"^(.*),(.*),(.*)$",
    # borderline: small bounded repeats are not wide, separators split the chain
    r"^/a.{0,10}b.{0,10}c.{0,10}d", r"^/([a-z]+)/([0-9]+)/([a-z]+)$", r"^[a-z]+-[0-9]+$",
    r"^a*b*$", r"^\w+@\w+\.com$",
    # does not compile / empty / too long
    "(", "[a-", "x" * 300, "",
]
# nginx-rendered patterns (redirect sources, rewrite_path): printable ASCII and PCRE syntax only
NGINX_ONLY = ["^/مقاله/(\\d+)$", r"\N{DIGIT ONE}", r"(?a:x)", r"^/A", r"(?i:x)"]


@pytest.fixture(scope="module")
def agent():
    spec = importlib.util.spec_from_file_location("pcdn_agent_rx", AGENT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.parametrize("pattern", CORPUS)
def test_regex_verdict_matches_the_edge(agent, pattern):
    """njs (firewall conditions: any printable text) and nginx (ASCII) both."""
    edge_ok = agent.regex_unsafe(pattern, ascii_only=False) is None
    assert sections.regex_safe(pattern) == edge_ok, (pattern, agent.regex_unsafe(pattern, ascii_only=False))
    assert sections.regex_safe(pattern, nginx=True) == (agent.pcre_regex(pattern) is not None), pattern


@pytest.mark.parametrize("pattern", NGINX_ONLY)
def test_nginx_regex_verdict_matches_the_edge(agent, pattern):
    assert sections.regex_safe(pattern, nginx=True) == (agent.pcre_regex(pattern) is not None), pattern


def test_controller_is_never_laxer_than_the_edge(agent):
    for p in CORPUS + NGINX_ONLY + ["a b", "(?P<n>x)", "a\tb"]:
        if sections.regex_safe(p):
            assert agent.regex_unsafe(p, ascii_only=False) is None, p
        if sections.regex_safe(p, nginx=True):
            assert agent.pcre_regex(p) is not None, p


def test_edge_limits_are_mirrored(agent):
    assert sections.REGEX_MAX_LEN == agent.REGEX_MAX_LEN
    assert sections.REGEX_MAX_UNBOUNDED == agent.REGEX_MAX_UNBOUNDED
    assert sections.REGEX_MAX_DEGREE == agent.REGEX_MAX_DEGREE
    assert sections.REGEX_WIDE_REPEAT == agent.REGEX_WIDE_REPEAT


def test_chained_quantifiers_get_a_clear_422(client):
    client.post("/api/v1/sites", json={"domain": "rx.com", "origin_ip": "8.8.8.8"})
    S = "/api/v1/sites/rx.com/config"
    for section, body in (
            ("firewall", {"rules": [{"id": "f", "action": "block", "conditions": [
                {"field": "user_agent", "op": "regex", "value": "Mozilla.*Windows.*Chrome"}]}]}),
            ("redirects", {"rules": [{"id": "r", "match": "regex", "source": "^/(.*)/(.*)/(.*)x$",
                                      "target": "/n/$1"}]}),
            ("transform", {"rules": [{"id": "t", "actions": [
                {"type": "rewrite_path", "regex": "a.*b.*c", "replacement": "/x"}]}]})):
        r = client.put(f"{S}/{section}", json=body)
        assert r.status_code == 422, (section, r.text)
        assert "a.*b.*c" in json.dumps(r.json(), ensure_ascii=False), r.text  # the message names the shape
    r = client.put(f"{S}/firewall", json={"rules": [{"id": "f", "action": "block", "conditions": [
        {"field": "path", "op": "regex", "value": r"^/(a)\1"}]}]})
    assert r.status_code == 422 and "ارجاع" in json.dumps(r.json(), ensure_ascii=False)


def test_stored_unsafe_rules_are_dropped_warned_and_alerted(client, monkeypatch):
    client.post("/api/v1/sites", json={"domain": "legacy-rx.com", "origin_ip": "8.8.8.8"})
    stored = {
        "firewall": {"rules": [
            {"id": "fbad", "action": "block", "conditions": [
                {"field": "user_agent", "op": "regex", "value": "Mozilla.*Windows.*Chrome"}]},
            {"id": "fgood", "action": "block", "conditions": [{"field": "path", "op": "regex", "value": "^/wp-"}]}]},
        "redirects": {"rules": [
            {"id": "rbad", "match": "regex", "source": "^/(.*)/(.*)/(.*)x$", "target": "/n/$1"},
            {"id": "rgood", "match": "regex", "source": "^/old/(.*)$", "target": "/new/$1"}]},
        "transform": {"rules": [
            {"id": "tbad", "actions": [{"type": "rewrite_path", "regex": r"^/(a)\1", "replacement": "/x"}]},
            {"id": "tgood", "actions": [{"type": "rewrite_path", "regex": "^/a/(.*)$", "replacement": "/b/$1"}]}]},
    }
    with SessionLocal() as db:
        s = db.scalar(select(Site).where(Site.domain == "legacy-rx.com"))
        s.config = json.dumps(stored)
        db.commit()
        # the sections still parse (no silent fallback to an empty section)
        for name, ids in (("firewall", ["fbad", "fgood"]), ("redirects", ["rbad", "rgood"]),
                          ("transform", ["tbad", "tgood"])):
            assert [r["id"] for r in sections.get_section(s, name)["rules"]] == ids
        cfg = services.build_edge_config(db)
    e = next(x for x in cfg["sites"] if x["domain"] == "legacy-rx.com")
    assert [r["id"] for r in e["firewall"]["rules"]] == ["fgood"]
    assert [r["id"] for r in e["redirects"]["rules"]] == ["rgood"]
    assert [r["id"] for r in e["transform"]["rules"]] == ["tgood"]

    for name, rid in (("firewall", "fbad"), ("redirects", "rbad"), ("transform", "tbad")):
        r = client.get(f"/api/v1/sites/legacy-rx.com/config/{name}")
        assert r.status_code == 200 and len(r.json()["rules"]) == 2
        w = json.loads(r.headers["X-Pcdn-Warnings"])
        assert len(w) == 1 and rid in w[0] and "good" not in w[0].replace(rid, "")
    assert "X-Pcdn-Warnings" not in client.get("/api/v1/sites/legacy-rx.com/config/cache").headers

    raised, resolved = [], []
    monkeypatch.setattr(alerts, "raise_alert", lambda k, t, x, s="warning": raised.append((k, x)))
    monkeypatch.setattr(alerts, "resolve_alert", lambda k, *a, **kw: resolved.append(k))
    with SessionLocal() as db:
        out = scheduler.job_security_audit(db, force=True)
    hit = [x for k, x in raised if k == "unsafe_regex"]
    assert len(hit) == 1 and "legacy-rx.com" in hit[0] and "Mozilla" not in hit[0]
    assert any("legacy-rx.com" in line for line in out["unsafe_regex"])

    # fixed by the customer: the alert resolves
    with SessionLocal() as db:
        s = db.scalar(select(Site).where(Site.domain == "legacy-rx.com"))
        s.config = json.dumps({})
        db.commit()
        raised.clear()
        scheduler.job_security_audit(db, force=True)
    assert not [k for k, _ in raised if k == "unsafe_regex"] and "unsafe_regex" in resolved
