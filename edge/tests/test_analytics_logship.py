"""Unit tests for SPEC §14.3.1 (live minute aggregates, platform_errors) and §14.3.2 (log export:
sampling, record shape, IP anonymization, on-disk spool, shipping) of the edge agent."""

import importlib.util
import io
import json
import os
import pathlib
import re
import subprocess
import urllib.error
from datetime import datetime, timedelta, timezone

import pytest
from conftest import TEST_ORIGIN_ALLOW

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("agent_6d", HERE.parent / "pcdn-agent.py")
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)

TOKEN = "edge_" + "t0ken" * 8
SITE_SECRET = "ab" * 32


def make_cfg(tmp_path, **over):
    cfg = dict(agent.DEFAULTS, ORIGIN_PRIVATE_ALLOW=TEST_ORIGIN_ALLOW)
    cfg.update({
        "CONTROLLER_URL": "http://127.0.0.1:9", "EDGE_TOKEN": TOKEN,
        "NGINX_DIR": str(tmp_path / "pcdn"), "CACHE_DIR": str(tmp_path / "cache"),
        "STATE_FILE": str(tmp_path / "state.json"), "ACCESS_LOG": str(tmp_path / "access.log"), "L4_ACCESS_LOG": str(tmp_path / "l4.log"), "FN_USAGE_LOG": str(tmp_path / "fn-usage.log"),
        "ERROR_LOG": str(tmp_path / "error.log"), "BUNDLE_VERSION_FILE": str(tmp_path / "bundle.version"),
        "PAGES_DIR": str(HERE.parent / "pages"), "NJS_FILE": str(HERE.parent / "njs/pcdn.js"),
        "BASE_TEMPLATE": str(HERE.parent / "nginx/pcdn-base.conf"), "GEOIP_DB": str(tmp_path / "missing.mmdb"),
        "NGINX_TEST_CMD": "true", "NGINX_RELOAD_CMD": "true", "NGINX_USER": "root", "RELOAD_VERIFY": "no",
        "NGINX_CAPS": dict(agent.LEGACY_CAPS, nginx="1.24.0"),
    })
    cfg.update(over)
    return cfg


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S+00:00")


NOW = datetime.now(timezone.utc).replace(microsecond=0)
T0 = NOW.replace(second=5) - timedelta(minutes=10)   # a recent minute (inside the 24 h live window)


def line(**kw) -> dict:
    """A current-format access-log record (pcdn-base.conf log_format)."""
    e = {"t": iso(T0), "h": "a.com", "b": 100, "s": 200, "c": "MISS", "ip": "203.0.113.77", "cc": "IR", "m": "GET",
         "u": "/p?q=secret", "ua": "Mozilla/5.0", "v": "ok", "tn": "", "rt": 0.012, "bu": 80, "ub": "90",
         "us": "200", "pg": "", "sc": "https", "pr": "HTTP/2.0", "rf": "https://ref.example/x?token=1#frag"}
    e.update(kw)
    return e


def write_log(path, rows):
    with open(path, "a") as f:
        f.write("".join(json.dumps(r) + "\n" for r in rows))


class Ctl:
    """Records POSTs; `fail` maps a path to an exception factory (or None = succeed)."""

    def __init__(self):
        self.posts, self.fail, self.calls = [], {}, 0

    def call(self, method, path, body=None, headers=None, timeout=30):
        self.calls += 1
        f = self.fail.get(path)
        if f is not None:
            raise f()
        self.posts.append((path, json.loads(json.dumps(body)), timeout))
        return 200, {}, {"ok": True}

    def bodies(self, path):
        return [b for p, b, _ in self.posts if p == path]


def http_error(code):
    return lambda: urllib.error.HTTPError("http://c/x", code, "err", {}, io.BytesIO(b""))


def new_agent(tmp_path, **over):
    a = agent.Agent.__new__(agent.Agent)
    a.cfg, a.state, a.ctl = make_cfg(tmp_path, **over), {}, Ctl()
    return a


SITES_CFG = {"version": "v1", "sites": [
    {"id": 1, "domain": "a.com", "secret": SITE_SECRET, "hosts": [{"name": "a.com", "origin": {"address": "1.2.3.4"}}],
     "logs": {"enabled": True, "sample_rate": 1.0, "anonymize_ip": True, "secret_key": "S3CRET-KEY-X"}},
    {"id": 2, "domain": "b.com", "secret": SITE_SECRET, "hosts": [{"name": "b.com", "origin": {"address": "1.2.3.4"}}],
     "logs": {"enabled": False, "sample_rate": 1.0, "anonymize_ip": True}},
    {"id": 3, "domain": "raw.com", "secret": SITE_SECRET,
     "hosts": [{"name": "raw.com", "origin": {"address": "1.2.3.4"}}],
     "logs": {"enabled": True, "sample_rate": 1.0, "anonymize_ip": False}},
    {"id": 4, "domain": "shop.a.com", "secret": SITE_SECRET,
     "hosts": [{"name": "shop.a.com", "origin": {"address": "1.2.3.4"}}]},   # nested, no logs section
]}


# ----------------------------------------------------------------- live minute aggregates

def test_minute_bucketing_and_top_n(tmp_path):
    log = tmp_path / "access.log"
    m1 = T0
    m2 = T0 + timedelta(minutes=1)
    rows = [line(t=iso(m1), s=200, c="HIT", b=10, u="/a?x=1", cc="IR"),
            line(t=iso(m1 + timedelta(seconds=30)), s=404, b=20, u="/a?y=2", cc="DE"),
            line(t=iso(m1), s=503, us="", b=5, u="/b", cc="", h="B.a.com"),
            line(t=iso(m2), s=301, c="STALE", b=7, u="/c", cc="us"),
            line(t=iso(m2), s=101, b=1, u="/ws", tn="ws", cc="IR")]
    # 30 countries and 150 distinct paths in one minute of c.com: counted with a cap, top 20 sent
    ccs = [chr(65 + i // 26) + chr(65 + i % 26) for i in range(30)]
    for i, cc in enumerate(ccs):
        rows += [line(t=iso(m1), h="c.com", cc=cc, u="/hot")] * (i + 1)
    rows += [line(t=iso(m1), h="c.com", u=f"/p{i}?q={i}") for i in range(150)]
    rows += [line(t=iso(m1), h="c.com", u="/p5")] * 3      # a tracked path keeps counting past the cap
    rows += [line(t=iso(m1), h="c.com", u="/late")] * 50   # new path beyond the tracking cap: not counted
    write_log(log, rows)
    state = {}
    agent.read_usage(state, str(log))
    items = {(i["host"], i["minute"]): i for i in agent.live_items(state["live"], agent.live_cutoff())}
    k1, k2 = m1.strftime("%Y-%m-%dT%H:%M:00Z"), m2.strftime("%Y-%m-%dT%H:%M:00Z")
    a1 = items[("a.com", k1)]
    assert a1 == {"host": "a.com", "minute": k1, "requests": 2, "bytes": 30, "cache_hits": 1,
                  "status": {"2xx": 1, "4xx": 1}, "countries": {"IR": 1, "DE": 1}, "paths": {"/a": 2}}
    assert items[("b.a.com", k1)]["status"] == {"5xx": 1} and items[("b.a.com", k1)]["countries"] == {}
    a2 = items[("a.com", k2)]
    # 1xx (WebSocket 101) is not one of the four status classes; tunnels still count as requests
    assert a2["requests"] == 2 and a2["cache_hits"] == 1 and a2["status"] == {"3xx": 1}
    assert a2["countries"] == {"US": 1, "IR": 1} and a2["paths"] == {"/c": 1, "/ws": 1}
    c = items[("c.com", k1)]
    assert len(c["countries"]) == 20 and c["countries"][ccs[-1]] == 30 and ccs[0] not in c["countries"]
    assert len(c["paths"]) == 20 and c["paths"]["/hot"] == sum(range(1, 31)) and c["paths"]["/p5"] == 4
    raw = state["live"][f"c.com|{k1}"]["paths"]
    assert len(raw) == agent.LIVE_PATH_TRACK and "/late" not in raw and "/p149" not in raw
    assert all("?" not in p for p in raw)
    # minutes are ISO with seconds = 0 (UTC)
    assert all(re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:00Z", m) for _, m in items)


def test_live_window_and_post_bound(tmp_path):
    log = tmp_path / "access.log"
    old = NOW - timedelta(hours=25)
    write_log(log, [line(t=iso(old), u="/old"), line(u="/new")])
    state = {}
    agent.read_usage(state, str(log))
    # hourly usage still counts the old line; live never counts minutes older than 24 h
    assert sum(a["requests"] for a in state["pending"].values()) == 2
    assert [k.split("|")[1] for k in state["live"]] == [T0.strftime("%Y-%m-%dT%H:%M:00Z")]

    # more host-minutes than one POST may carry: the OLDEST minutes are dropped
    live = {}
    base = NOW.replace(second=0) - timedelta(minutes=100)
    for m in range(100):
        minute = (base + timedelta(minutes=m)).strftime("%Y-%m-%dT%H:%M:00Z")
        for h in range(60):
            live[f"h{h}.com|{minute}"] = {"requests": 1, "bytes": 1, "cache_hits": 0, "status": {"2xx": 1},
                                          "countries": {}, "paths": {"/": 1}}
    items = agent.live_items(live, agent.live_cutoff())
    assert len(items) == agent.LIVE_MAX
    minutes = [i["minute"] for i in items]
    assert minutes == sorted(minutes)                                      # oldest first in the POST
    newest = (base + timedelta(minutes=99)).strftime("%Y-%m-%dT%H:%M:00Z")
    dropped = (base + timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:00Z")
    assert newest in minutes and dropped not in minutes
    # a host the controller would reject (> 253 chars) is never sent
    assert agent.live_item("x" * 254 + "|" + newest, live[f"h0.com|{newest}"]) is None


def test_live_pending_cap_drops_oldest(monkeypatch):
    monkeypatch.setattr(agent, "LIVE_PENDING_MAX", 8)
    live = {}
    for m in range(12):
        agent._account_live(live, "a.com", f"2026-10-01T10:{m:02d}:00Z", 1, False, 200, "IR", "/")
    assert len(live) <= 8 and "a.com|2026-10-01T10:11:00Z" in live and "a.com|2026-10-01T10:00:00Z" not in live


def test_live_rides_in_the_usage_batch_and_retries_with_same_batch_id(tmp_path):
    a = new_agent(tmp_path)
    write_log(a.cfg["ACCESS_LOG"], [line(u="/x?a=1"), line(u="/x", s=500, us="")])
    a.ctl.fail["/edge/v1/usage"] = lambda: OSError("controller down")
    with pytest.raises(OSError):
        a.push_usage()
    [entry] = a.state["outbox"]
    assert entry["live"] and a.state["live"] == {} and a.state["pending"] == {}
    persisted = json.loads(pathlib.Path(a.cfg["STATE_FILE"]).read_text())   # saved before the POST (F8)
    assert persisted["outbox"][0]["id"] == entry["id"] and persisted["outbox"][0]["live"] == entry["live"]
    a.ctl.fail.clear()
    a.push_usage()
    [body] = a.ctl.bodies("/edge/v1/usage")
    assert body["batch_id"] == entry["id"] and re.fullmatch(r"[0-9a-f]{32}", body["batch_id"])
    [lv] = body["live"]
    assert lv["host"] == "a.com" and lv["requests"] == 2 and lv["status"] == {"2xx": 1, "5xx": 1}
    assert lv["paths"] == {"/x": 2}
    [item] = body["items"]
    assert item["platform_errors"] == 1 and item["requests"] == 2
    assert a.state["outbox"] == []


def test_live_backlog_bounded_and_24h_cutoff_on_retry(tmp_path, monkeypatch):
    monkeypatch.setattr(agent, "LIVE_BACKLOG_MAX", 5)
    fresh = NOW.replace(second=0).strftime("%Y-%m-%dT%H:%M:00Z")
    stale = (NOW - timedelta(hours=25)).strftime("%Y-%m-%dT%H:%M:00Z")

    def li(minute, host="a.com"):
        return {"host": host, "minute": minute, "requests": 1, "bytes": 1, "cache_hits": 0, "status": {},
                "countries": {}, "paths": {}}
    outbox = [{"id": "1" * 32, "ts": 0, "items": [{"host": "a.com"}], "events": [], "live": [li(stale), li(fresh)]},
              {"id": "2" * 32, "ts": 0, "items": [], "events": [], "live": [li(fresh, f"h{i}") for i in range(4)]}]
    agent.trim_live_backlog(outbox, agent.live_cutoff())
    assert [x["minute"] for x in outbox[0]["live"]] == [fresh]           # > 24 h dropped, newest entries win
    assert len(outbox[1]["live"]) == 4
    assert outbox[0]["items"] == [{"host": "a.com"}] and outbox[0]["id"] == "1" * 32   # hourly untouched
    outbox.append({"id": "3" * 32, "ts": 0, "items": [], "events": [], "live": [li(fresh, "z")] * 2})
    agent.trim_live_backlog(outbox, agent.live_cutoff())
    assert "live" not in outbox[0] and len(outbox[1]["live"]) == 3 and len(outbox[2]["live"]) == 2


def test_usage_rejected_with_live_is_resent_without_it(tmp_path):
    a = new_agent(tmp_path)
    write_log(a.cfg["ACCESS_LOG"], [line()])
    seen = []

    class Picky(Ctl):
        def call(self, method, path, body=None, headers=None, timeout=30):
            seen.append(json.loads(json.dumps(body)))
            if "live" in body:
                raise http_error(422)()
            return super().call(method, path, body, headers, timeout)
    a.ctl = Picky()
    a.push_usage()
    assert len(seen) == 2 and "live" in seen[0] and "live" not in seen[1]
    assert seen[0]["batch_id"] == seen[1]["batch_id"] and seen[1]["items"][0]["requests"] == 1
    assert a.state["outbox"] == []


# ----------------------------------------------------------------- platform_errors

PE_CASES = [
    # (record overrides, counted?, why)
    (dict(s=500, us=""), True, "njs / internal failure: no upstream"),
    (dict(s=502, us=""), True, "origin hostname not resolved by the edge: no upstream recorded"),
    (dict(s=504, us="", c=""), True, "edge-produced 504"),
    (dict(s=500, us="", v="log:waf:942100"), True, "a log-only verdict is not an action"),
    (dict(s=500, us="", pg=""), True, "custom 5xx error page for an edge error"),
    (dict(s=502, us="502"), False, "origin connect failure (nginx records the upstream)"),
    (dict(s=504, us="504"), False, "origin timeout"),
    (dict(s=500, us="500"), False, "origin answered 500"),
    (dict(s=503, us="-"), False, "upstream state without a status"),
    (dict(s=502, us="502, 502"), False, "several upstream attempts"),
    (dict(s=502, us="504 : 502"), False, "shield hop failed, origin fallback failed"),
    (dict(s=500, us="", c="HIT"), False, "served from cache"),
    (dict(s=500, us="", c="STALE"), False, "stale cache entry"),
    (dict(s=503, us="", v="challenge:ddos:auto"), False, "DDoS challenge"),
    (dict(s=503, us="", v="block:ratelimit:login"), False, "rate-limit block"),
    (dict(s=500, us="", v="captcha:firewall:r1"), False, "captcha"),
    (dict(s=503, us="", pg="site"), False, "suspended / over-quota page"),
    (dict(s=501, us=""), False, "unsupported client request"),
    (dict(s=505, us=""), False, "unsupported HTTP version"),
    (dict(s=499, us=""), False, "client closed: < 500"),
    (dict(s=404, us=""), False, "4xx"),
    (dict(s=200, us=""), False, "2xx"),
    (dict(s="x", us=""), False, "garbage status"),
]


@pytest.mark.parametrize("over,counted,why", PE_CASES, ids=[c[2] for c in PE_CASES])
def test_platform_error_classification(over, counted, why):
    assert agent.platform_error(line(**over)) is counted, why


def test_platform_errors_in_hourly_items_and_old_lines(tmp_path):
    log = tmp_path / "access.log"
    rows = [line(**over) for over, _, _ in PE_CASES if isinstance(over["s"], int)]
    old = {"t": iso(T0), "h": "a.com", "b": 10, "s": 500, "c": "", "v": "ok", "u": "/old"}   # pre-6D format
    rows.append(old)
    write_log(log, rows)
    state = {}
    agent.read_usage(state, str(log))
    [item] = agent.usage_items(state["pending"])
    assert item["platform_errors"] == sum(1 for over, c, _ in PE_CASES if c)
    assert item["requests"] == len(rows)                                  # the old line still counts
    assert not agent.platform_error(old)                                  # no "us": never counted
    no_pe = agent.usage_item("x.com|2026-10-01T10:00:00Z", {"bytes": 1, "requests": 1, "cache_hits": 0})
    assert no_pe["platform_errors"] == 0                                  # v1 state entry


# ----------------------------------------------------------------- record shape / anonymization

@pytest.mark.parametrize("ip,anon", [
    ("203.0.113.77", "203.0.113.0"), ("203.0.113.0", "203.0.113.0"),
    ("2001:db8:abcd:1234:5678::1", "2001:db8:abcd::"), ("[2001:db8:abcd:ffff::9]", "2001:db8:abcd::"),
    ("::ffff:198.51.100.9", "198.51.100.0"), ("fe80::1%eth0", "fe80::"),
    ("", ""), ("-", ""), ("not-an-ip", ""), ("1.2.3.4.5", ""), (None, ""),
])
def test_anonymize_ip(ip, anon):
    assert agent.anonymize_ip(ip) == anon
    assert agent.anonymize_ip(agent.anonymize_ip(ip)) == anon   # idempotent (the controller re-applies it)


def test_log_record_shape_query_stripping_and_truncation():
    dt = datetime(2026, 10, 1, 10, 5, 3, tzinfo=timezone.utc)
    e = line(u="/" + "p" * 3000 + "?q=1", ua="U" * 600, rf="https://r.example/" + "r" * 2000 + "?s=1", m="GET",
             s=206, b=1234, rt="1.23456", c="HIT", cc="ir", sc="https", pr="HTTP/2.0", ip="198.51.100.200")
    r = agent.log_record(e, "a.com", dt, True)
    assert list(r) == ["t", "host", "ip", "method", "scheme", "path", "status", "bytes", "rt", "cache", "country",
                       "ua", "referer", "proto"]   # the controller's export order
    assert r["t"] == "2026-10-01T10:05:03Z" and r["ip"] == "198.51.100.0" and r["country"] == "IR"
    assert len(r["path"]) == 2048 and "?" not in r["path"] and len(r["ua"]) == 512
    assert len(r["referer"]) == 1024 and "?" not in r["referer"]
    assert (r["status"], r["bytes"], r["rt"], r["cache"], r["scheme"], r["proto"]) == (206, 1234, 1.235, "HIT",
                                                                                        "https", "HTTP/2.0")
    short = agent.log_record(line(rf="https://ref.example/x?token=1#frag", u="/a/b?c=d#e"), "a.com", dt, False)
    assert short["referer"] == "https://ref.example/x" and short["path"] == "/a/b" and short["ip"] == "203.0.113.77"
    # an old-format line still yields a valid record; junk numbers / countries are neutralised
    old = agent.log_record({"t": "x", "h": "a.com", "s": "bad", "b": None, "rt": "nan", "cc": "XYZ"}, "a.com", dt, True)
    assert (old["status"], old["bytes"], old["rt"], old["country"], old["ip"], old["scheme"], old["referer"]) == (
        0, 0, 0.0, "", "", "", "")
    # a lone surrogate (raw non-UTF-8 bytes in a header) never makes a record unencodable
    bad = agent.log_record(json.loads(b'{"ua": "x\xed\xa0\x80y", "u": "/\xed\xa0\x80"}'), "a.com", dt, True)
    json.dumps(bad, ensure_ascii=False).encode("utf-8")
    assert bad["ua"].startswith("x�") and bad["ua"].endswith("y") and bad["path"].startswith("/�")


def test_sampling_is_deterministic_and_bounded(tmp_path):
    cfg = make_cfg(tmp_path)
    state = {}
    ls = agent.LogShip(cfg, state)
    body = {"version": "v1", "sites": [dict(SITES_CFG["sites"][0], logs={"enabled": True, "sample_rate": 0.1}),
                                       dict(SITES_CFG["sites"][1], logs={"enabled": True, "sample_rate": 0.0001}),
                                       dict(SITES_CFG["sites"][2], logs={"enabled": True, "sample_rate": 7})]}
    ls.update_config(body)
    assert ls.site_for("a.com") == (0.1, True) and ls.site_for("www.b.com") == (0.01, True)   # clamped
    assert ls.site_for("raw.com") == (1.0, True) and ls.site_for("other.com") is None
    raws = [json.dumps(line(u=f"/r{i}", ip=f"10.0.{i // 250}.{i % 250}")).encode() for i in range(20000)]
    pts = [agent.sample_point(r) for r in raws]
    assert all(0.0 <= p < 1.0 for p in pts)
    assert 1700 <= sum(p < 0.1 for p in pts) <= 2300            # ~10 %
    assert 120 <= sum(p < 0.01 for p in pts) <= 300             # ~1 %
    assert [agent.sample_point(r) for r in raws[:50]] == pts[:50]   # same line -> same decision
    log = tmp_path / "access.log"
    log.write_bytes(b"".join(r + b"\n" for r in raws))
    agent.read_usage(state, str(log), ship=ls)
    ls.flush()
    [b] = ls.batches()
    assert 1700 <= b[3] <= 2300
    # read again from scratch: the very same lines are selected
    first = sorted(r["path"] for r in ls._read(b[0]))
    state2 = {}
    ls2 = agent.LogShip(make_cfg(tmp_path, LOGSHIP_SPOOL_DIR=str(tmp_path / "spool2")), state2)
    ls2.update_config(body)
    agent.read_usage(state2, str(log), ship=ls2)
    ls2.flush()
    assert sorted(r["path"] for r in ls2._read(ls2.batches()[0][0])) == first


def test_sampling_scope_disabled_tunnel_internal_and_nested_sites(tmp_path):
    a = new_agent(tmp_path)
    a.logship.update_config(SITES_CFG)
    rows = [line(h="a.com", u="/keep?x=1"), line(h="www.a.com", u="/sub"),
            line(h="b.com", u="/disabled-site"), line(h="www.b.com", u="/disabled-site"),
            line(h="shop.a.com", u="/nested-disabled"), line(h="x.shop.a.com", u="/nested-disabled"),
            line(h="a.com", u="/vpn", tn="ws", s=101), line(h="a.com", u="/grpc", tn="grpc"),
            line(h="a.com", u="/__pcdn/verify?t=1"), line(h="a.com", u="/%5F%5Fpcdn/captcha"),
            line(h="a.com", u="//__pcdn/health"), line(h="unknown.org", u="/nosite"),
            line(h="raw.com", u="/raw", ip="2001:db8::1")]
    write_log(a.cfg["ACCESS_LOG"], rows)
    a.push_usage()
    recs = [r for f in a.logship.batches() for r in a.logship._read(f[0])]
    assert sorted((r["host"], r["path"]) for r in recs) == [("a.com", "/keep"), ("raw.com", "/raw"),
                                                           ("www.a.com", "/sub")]
    by = {r["path"]: r for r in recs}
    assert by["/keep"]["ip"] == "203.0.113.0" and by["/raw"]["ip"] == "2001:db8::1"   # anonymize_ip false
    assert by["/keep"]["referer"] == "https://ref.example/x" and by["/keep"]["proto"] == "HTTP/2.0"
    # every request still counts for usage / live
    [body] = a.ctl.bodies("/edge/v1/usage")
    assert sum(i["requests"] for i in body["items"]) == len(rows) == sum(x["requests"] for x in body["live"])


def test_sampling_budget_never_slows_usage(tmp_path, monkeypatch):
    """Record building has its own CPU budget per read pass; beyond it the pass's export records are
    dropped and counted while every line is still accounted for usage."""
    monkeypatch.setattr(agent, "LOGSHIP_SAMPLE_BUDGET", -1.0)   # exhausted from the first record
    a = new_agent(tmp_path)
    a.logship.update_config(SITES_CFG)
    write_log(a.cfg["ACCESS_LOG"], [line(u=f"/x{i}") for i in range(7)] + [line(h="b.com")])
    a.push_usage()
    [body] = a.ctl.bodies("/edge/v1/usage")
    assert sum(i["requests"] for i in body["items"]) == 8
    assert a.logship.batches() == [] and a.logship.stats()["dropped"] == 7   # b.com is not exported
    monkeypatch.setattr(agent, "LOGSHIP_SAMPLE_BUDGET", 2.0)    # next pass: budget again
    write_log(a.cfg["ACCESS_LOG"], [line(u="/y")])
    a.push_usage()
    assert [r["path"] for f in a.logship.batches() for r in a.logship._read(f[0])] == ["/y"]


def test_export_failure_never_disturbs_usage_or_security_accounting(tmp_path, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("bug in record building")
    monkeypatch.setattr(agent, "log_record", boom)
    a = new_agent(tmp_path)
    a.logship.update_config(SITES_CFG)
    write_log(a.cfg["ACCESS_LOG"], [line(s=403, v="block:waf:942100", u="/?id=1"), line(tn="ws", u="/t", s=101, bu=5)])
    a.push_usage()
    [body] = a.ctl.bodies("/edge/v1/usage")
    [item] = body["items"]
    assert item["requests"] == 2 and item["security"] == {"waf": 1} and item["tunnel"]["sessions"] == 1
    assert [e["rule"] for e in body["events"]] == ["942100"] and sum(x["requests"] for x in body["live"]) == 2
    assert a.logship.batches() == []


def test_unreadable_spool_batch_is_dropped_and_counted(tmp_path):
    a = spooled(tmp_path, 2, per=3)
    first = a.logship.batches()[0][0]
    (pathlib.Path(a.logship.dir) / first).write_text("not json\n{also not\n")
    assert a.logship.ship(a.ctl) == 1
    assert a.logship.batches() == [] and a.state["logship"]["dropped"] == 3


def test_no_sampling_without_enabled_sites(tmp_path):
    a = new_agent(tmp_path)
    a.logship.update_config({"version": "v", "sites": [SITES_CFG["sites"][1], SITES_CFG["sites"][3]]})
    assert not a.logship.active
    write_log(a.cfg["ACCESS_LOG"], [line(h="b.com"), line(h="a.com")])
    a.push_usage()
    assert a.logship.batches() == [] and not os.path.exists(a.logship.dir)
    a.logship.ship(a.ctl)
    assert a.ctl.bodies("/edge/v1/logship") == []


# ----------------------------------------------------------------- spool + shipping

def spooled(tmp_path, n_batches, per=3, **cfg_over):
    a = new_agent(tmp_path, **cfg_over)
    a.logship.update_config(SITES_CFG)
    for b in range(n_batches):
        for i in range(per):
            a.logship.offer(line(u=f"/b{b}/{i}"), "a.com", T0, None)
        a.logship.flush()
    return a


def test_spool_files_are_private_and_survive_a_restart(tmp_path):
    a = spooled(tmp_path, 3)
    files = a.logship.batches()
    assert [f[3] for f in files] == [3, 3, 3]
    d = pathlib.Path(a.logship.dir)
    assert d == tmp_path / "logship" and (d.stat().st_mode & 0o777) == 0o700
    assert all((d / f[0]).stat().st_mode & 0o777 == 0o600 for f in files)
    ids = [f[2] for f in files]
    # agent restart: a fresh LogShip on the same state file/dir sees the same batches and ids
    agent.save_state(a.cfg["STATE_FILE"], a.state)
    b = new_agent(tmp_path)
    b.state = agent.load_state(b.cfg["STATE_FILE"])
    assert [f[2] for f in b.logship.batches()] == ids and b.logship.site_for("a.com") == (1.0, True)
    assert b.logship.ship(b.ctl) == 3
    posts = b.ctl.bodies("/edge/v1/logship")
    assert [p["batch_id"] for p in posts] == ids                       # oldest first, ids from the spool
    assert [r["path"] for r in posts[0]["records"]] == ["/b0/0", "/b0/1", "/b0/2"]
    assert b.logship.batches() == []


def test_failed_post_keeps_batch_and_retries_with_same_id_after_backoff(tmp_path, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(agent.time, "monotonic", lambda: clock[0])
    a = spooled(tmp_path, 2)
    ids = [f[2] for f in a.logship.batches()]
    a.ctl.fail["/edge/v1/logship"] = lambda: TimeoutError("timed out")
    assert a.logship.ship(a.ctl) == 0 and a.ctl.calls == 1             # stops at the first failure
    assert [f[2] for f in a.logship.batches()] == ids
    a.ctl.fail.clear()
    clock[0] += 10
    assert a.logship.ship(a.ctl) == 0 and a.ctl.calls == 1             # backing off (30 s)
    clock[0] += 25
    assert a.logship.ship(a.ctl) == 2
    assert [p["batch_id"] for p in a.ctl.bodies("/edge/v1/logship")] == ids
    a.ctl.fail["/edge/v1/logship"] = http_error(503)
    spooled_more = a.logship
    spooled_more.offer(line(), "a.com", T0, None)
    spooled_more.flush()
    for _ in range(2):                                                 # backoff doubles: 30 s, 60 s
        clock[0] += 3600
        a.logship.ship(a.ctl)
    assert a.logship.backoff == 60 and len(a.logship.batches()) == 1


def test_404_disables_shipping_until_the_config_changes(tmp_path):
    a = spooled(tmp_path, 2)
    a.ctl.fail["/edge/v1/logship"] = http_error(404)
    assert a.logship.ship(a.ctl) == 0 and a.ctl.calls == 1
    assert a.logship.stats()["disabled"] and len(a.logship.batches()) == 2   # spool kept
    a.logship.next_run = 0
    for _ in range(5):                                                 # no spinning
        a.logship.ship(a.ctl)
    assert a.ctl.calls == 1
    a.logship.update_config(SITES_CFG)                                 # same version: still off
    a.logship.ship(a.ctl)
    assert a.ctl.calls == 1
    # the off flag survives a restart
    agent.save_state(a.cfg["STATE_FILE"], a.state)
    b = new_agent(tmp_path)
    b.state = agent.load_state(b.cfg["STATE_FILE"])
    b.logship.ship(b.ctl)
    assert b.ctl.calls == 0
    b.logship.update_config(dict(SITES_CFG, version="v2"))            # a config change re-enables it
    assert b.logship.ship(b.ctl) == 2 and not b.logship.stats()["disabled"]


def test_rejected_batch_is_dropped_and_counted(tmp_path):
    a = spooled(tmp_path, 2, per=4)
    first = a.logship.batches()[0][0]

    class OneBad(Ctl):
        def call(self, method, path, body=None, headers=None, timeout=30):
            if first.split("-")[1] == body["batch_id"]:
                raise http_error(422)()
            return super().call(method, path, body, headers, timeout)
    a.ctl = OneBad()
    assert a.logship.ship(a.ctl) == 1
    assert a.logship.batches() == [] and a.state["logship"]["dropped"] == 4


def test_spool_cap_and_age_drop_oldest_and_count(tmp_path):
    a = spooled(tmp_path, 1, per=2, LOGSHIP_SPOOL_MAX_MB="0.002")      # ~2 KB
    for b in range(1, 6):
        for i in range(2):
            a.logship.offer(line(u=f"/b{b}/{i}"), "a.com", T0, None)
        a.logship.flush()
    files = a.logship.batches()
    assert 0 < len(files) < 6 and sum(f[4] for f in files) <= a.logship.cap
    kept = [r["path"] for f in files for r in a.logship._read(f[0])]
    assert "/b5/1" in kept and "/b0/0" not in kept                      # the oldest went first
    st = a.logship.stats()
    assert st["dropped"] == 12 - len(kept) and st["spool_records"] == len(kept)
    assert a.state["logship"]["dropped"] == st["dropped"]
    # batches older than 72 h are dropped (and counted) too
    d = pathlib.Path(a.logship.dir)
    ancient = d / f"{int((agent.time.time() - 73 * 3600) * 1000):013d}-{'c' * 32}-7.jsonl"
    ancient.write_text(json.dumps({"host": "a.com"}) + "\n")
    a.logship.enforce()
    assert not ancient.exists() and a.logship.stats()["dropped"] == st["dropped"] + 7


def test_run_budget_bounds_one_shipping_run(tmp_path, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(agent.time, "monotonic", lambda: clock[0])
    a = spooled(tmp_path, 6)

    class Slow(Ctl):
        def call(self, method, path, body=None, headers=None, timeout=30):
            clock[0] += 2.0                                            # every POST takes 2 s
            return super().call(method, path, body, headers, timeout)
    a.ctl = Slow()
    assert a.logship.ship(a.ctl) == 3                                   # 0, 2, 4 s started; not at 6 s
    assert len(a.logship.batches()) == 3
    assert all(t == 30 for _, _, t in a.ctl.posts)                      # LOGSHIP_TIMEOUT per POST
    assert a.logship.next_run - clock[0] >= 30 - 6                       # own cadence
    assert a.logship.ship(a.ctl) == 0                                    # not due yet
    clock[0] += 60
    assert a.logship.ship(a.ctl) == 3


def test_tick_ships_after_usage_and_reports_spool_in_heartbeat(tmp_path):
    a = new_agent(tmp_path, HEARTBEAT_INTERVAL="60", USAGE_INTERVAL="60")
    a.running, a.last_usage, a.last_heartbeat, a.net_prev = True, 0.0, 0.0, None

    class Cfg(Ctl):
        def call(self, method, path, body=None, headers=None, timeout=30):
            if path == "/edge/v1/config":
                return 200, {"ETag": "e1"}, json.loads(json.dumps(SITES_CFG))
            if path.startswith("/edge/v1/purges"):
                return 200, {}, []
            return super().call(method, path, body, headers, timeout)
    a.ctl = Cfg()
    a.metrics = lambda: {}
    write_log(a.cfg["ACCESS_LOG"], [line(u="/one?x=1"), line(h="b.com")])
    a.tick()
    order = [p for p, _, _ in a.ctl.posts]
    assert order.index("/edge/v1/usage") < order.index("/edge/v1/logship")
    [lb] = a.ctl.bodies("/edge/v1/logship")
    assert [r["path"] for r in lb["records"]] == ["/one"] and lb["records"][0]["ip"] == "203.0.113.0"
    hb = [b for b in a.ctl.bodies("/edge/v1/heartbeat") if "metrics" in b][0]
    assert hb["capabilities"]["live_analytics"] is True and hb["capabilities"]["logship"] is True
    assert set(hb["logship"]) == {"sites", "spool_batches", "spool_records", "spool_bytes", "dropped", "disabled"}
    assert hb["logship"]["sites"] == 2


def test_no_secrets_in_state_spool_or_payloads(tmp_path):
    a = spooled(tmp_path, 1)
    write_log(a.cfg["ACCESS_LOG"], [line()])
    a.push_usage()
    agent.save_state(a.cfg["STATE_FILE"], a.state)
    a.logship.ship(a.ctl)
    blobs = [pathlib.Path(a.cfg["STATE_FILE"]).read_text(), json.dumps(a.ctl.posts),
             json.dumps(a.logship.stats())]
    blobs += [(pathlib.Path(a.logship.dir) / f).read_text() for f in os.listdir(a.logship.dir)]
    for blob in blobs:
        for secret in (TOKEN, SITE_SECRET, "S3CRET-KEY-X", "secret_key", "token=1", "q=secret"):
            assert secret not in blob
    assert a.state["logship"]["sites"] == {"a.com": [1.0, True], "raw.com": [1.0, False], "shop.a.com": None}


def test_install_upgrade_keeps_logship_tunables(tmp_path):
    """agent.conf is rewritten by every install.sh run; --upgrade carries LOGSHIP_* lines over, a
    fresh install leaves them to the agent's defaults."""
    install = (HERE.parent / "install.sh").read_text()

    def block(start, end):
        return start + install.split(start, 1)[1].split(end, 1)[0]
    upgrade = block('if [ "$UPGRADE" = yes ]; then', 'TCP_CC="${TCP_CC:-bbr}"')
    write = block("cat > /etc/pcdn/agent.conf <<EOF", "\nEOF") + "\nEOF\n"
    keep = block("# >>> pcdn keep logship", "# <<< pcdn keep logship")
    conf = tmp_path / "agent.conf"
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "CONTROLLER": "", "TOKEN": "", "REGION": "", "ROLE": "",
           "TCP_CC": "", "HTTP3": "", "KEEP_CONF": "", "NGINX_USER": "www-data", "IPV6": "yes", "CACHE_SIZE": "10g",
           "HTTP_PORT": "80", "HTTPS_PORT": "443"}

    def run(script, **over):
        script = script.replace("/etc/pcdn/agent.conf", str(conf))
        subprocess.run(["bash", "-euc", script], env=dict(env, **over), check=True, capture_output=True)
    conf.write_text("CONTROLLER_URL=https://c\nEDGE_TOKEN=t\nLOGSHIP_SPOOL_MAX_MB=1024\nLOGSHIP_INTERVAL=45\n"
                    "LOGSHIP_EVIL=x\n")
    run(upgrade + write + keep, UPGRADE="yes")
    cfg = agent.load_config(str(conf))
    assert cfg["LOGSHIP_SPOOL_MAX_MB"] == "1024" and cfg["LOGSHIP_INTERVAL"] == "45" and cfg["EDGE_TOKEN"] == "t"
    assert "LOGSHIP_EVIL" not in conf.read_text() and conf.read_text().count("LOGSHIP_SPOOL_MAX_MB") == 1
    run(write + keep, UPGRADE="no", CONTROLLER="https://c", TOKEN="t")          # fresh install: defaults
    assert "LOGSHIP" not in conf.read_text() and agent.load_config(str(conf))["LOGSHIP_SPOOL_MAX_MB"] == "256"


def test_logs_section_never_changes_rendering(tmp_path):
    cfg = make_cfg(tmp_path)
    site = {"id": 7, "domain": "example.com", "status": "active", "secret": SITE_SECRET, "ssl": None,
            "hosts": [{"name": "example.com", "origin": {"address": "127.0.0.1", "port": 18080}}],
            "cache": {"enabled": True, "level": "standard"}}
    with_logs = dict(site, logs={"enabled": True, "sample_rate": 0.5, "anonymize_ip": False})
    assert agent.render_site(site, cfg) == agent.render_site(with_logs, cfg)
    f1, d1 = agent.render_tree({"sites": [site]}, cfg)
    f2, d2 = agent.render_tree({"sites": [with_logs]}, cfg)
    assert d1 == d2 and f1 == f2
    assert '"us":"$upstream_status"' in f1["http.conf"] and "map $uri $pcdn_page" in f1["http.conf"]


# ----------------------------------------------------------------- tunnel quality (SPEC §15.1 / §15.4)
# Representative lines as real nginx 1.24 writes them (pinned in test_tunnel_quality_e2e.py).

def tline(**kw) -> dict:
    return line(**dict({"h": "t.com", "u": "/ws", "tn": "ws", "tp": "w1", "pr": "HTTP/1.1", "us": "101",
                        "uct": "0.004", "s": 101, "rt": 30.5, "b": 500, "bu": 200, "ub": "9000"}, **kw))


CLASSIFY = [
    # (fields, class, why)
    ({}, "session", "ws upgrade accepted"),
    ({"tn": "grpc", "pr": "HTTP/2.0", "s": 200, "us": "200"}, "session", "grpc stream"),
    ({"tn": "xhttp", "s": 200, "us": "502, 200", "uct": "-, 0.003"}, "session", "connect failover then success"),
    ({"s": 499, "us": "101"}, "session", "client closed an accepted session: clean end"),
    ({"s": 499, "us": "-", "uct": "-"}, None, "client gave up while the edge was connecting"),
    ({"s": 502, "us": "502", "uct": "-"}, "origin_refused", "connect() failed (111: Connection refused)"),
    ({"tn": "grpc", "pr": "HTTP/2.0", "s": 502, "us": "502", "uct": "-"}, "origin_refused", "grpc refused"),
    ({"s": 502, "us": "502", "uct": "0.009"}, "origin_refused", "closed before a response header"),
    ({"s": 502, "us": "502, 502", "uct": "-, -"}, "origin_refused", "both attempts refused"),
    ({"s": 504, "us": "504", "uct": "-"}, "origin_timeout", "connect timeout"),
    ({"s": 504, "us": "-", "uct": "-"}, "origin_timeout", "timeout without an upstream status"),
    ({"s": 502, "us": "-", "uct": "-"}, "origin_refused", "502 without an upstream status"),
    ({"s": 404, "us": "404"}, "origin_error", "origin answered 404"),
    ({"s": 400, "us": "400"}, "origin_error", "origin answered 400 (not the edge)"),
    ({"tn": "grpc", "pr": "HTTP/2.0", "s": 500, "us": "500"}, "origin_error", "origin 5xx"),
    ({"s": 429, "us": "", "uct": ""}, "limit", "limit_conn / fair share"),
    ({"s": 503, "us": "", "uct": ""}, "limit", "limit_req / F35 cut"),
    ({"s": 403, "us": "", "uct": ""}, "country", "allowed_countries gate"),
    ({"s": 426, "us": "", "uct": ""}, "protocol", "ws path without Upgrade (edge 426)"),
    ({"s": 400, "us": "", "uct": ""}, "protocol", "edge 400"),
    ({"tn": "grpc", "pr": "HTTP/1.1", "s": 200, "us": "200"}, "protocol", "gRPC path over HTTP/1.1"),
    ({"tn": "grpc", "pr": "HTTP/1.1", "s": 429, "us": ""}, "protocol", "wrong protocol wins"),
    ({"tn": "h2", "pr": "HTTP/1.1", "s": 200, "us": "200"}, "session", "h2 path over HTTP/1.1 is allowed"),
    ({"s": 500, "us": "", "uct": ""}, "edge", "edge 5xx (e.g. unresolvable origin hostname)"),
    ({"s": 404, "us": "", "uct": ""}, None, "other edge 4xx: not classified"),
    ({"s": "x"}, None, "garbage status"),
]


@pytest.mark.parametrize("over,cls,why", CLASSIFY, ids=[c[2] for c in CLASSIFY])
def test_classify_tunnel(over, cls, why):
    assert agent.classify_tunnel(tline(**over)) == cls, why


def test_classify_old_lines_without_new_fields():
    old = {"t": iso(T0), "h": "t.com", "b": 10, "s": 101, "c": "", "ip": "1.2.3.4", "cc": "IR", "m": "GET",
           "u": "/ws", "ua": "x", "v": "ok", "tn": "ws", "rt": 1, "bu": 1, "ub": "1"}   # pre-6D, no us/tp/uct
    assert agent.classify_tunnel(old) == "session" and agent.connect_ms(old) is None
    assert agent.classify_tunnel(dict(old, s=403)) == "country"


def test_connect_ms():
    assert agent.connect_ms({"uct": "0.004"}) == 4 and agent.connect_ms({"uct": "-, 0.120"}) == 120
    assert agent.connect_ms({"uct": "-"}) is None and agent.connect_ms({"uct": ""}) is None
    assert agent.connect_ms({}) is None and agent.connect_ms({"uct": "0.001 : 0.002"}) == 2


def test_tunnel_paths_aggregation_and_wire_shape(tmp_path):
    log = tmp_path / "access.log"
    rows = [tline(rt=100.4), tline(rt=50.2, uct="0.010"),
            tline(s=502, us="502", uct="-", rt=0.001, b=300),
            tline(s=502, us="502", uct="0.020", rt=0.0),                      # connected, closed: counted
            tline(s=426, us="", uct="", rt=0, b=150, ub=""),
            tline(tp="g1", tn="grpc", pr="HTTP/2.0", s=504, us="504", uct="-", rt=10),
            tline(tp="g1", tn="grpc", pr="HTTP/2.0", s=200, us="200", uct="0.002", rt=5, bu=40000, ub="40100"),
            tline(tp="", s=101),                                               # no path id: totals only
            tline(tp="BAD ID", s=101),                                         # invalid id: totals only
            line(u="/", s=200)]                                                 # not a tunnel request
    rows += [tline(tp=f"p{i}", s=101) for i in range(60)]                     # > 50 path ids
    write_log(log, rows)
    state = {}
    agent.read_usage(state, str(log))
    item = {i["host"]: i for i in agent.usage_items(state["pending"])}["t.com"]
    t = item["tunnel"]
    assert t["sessions"] == 2 + 1 + 2 + 60
    paths = t["paths"]
    assert len(paths) == agent.TUNNEL_PATHS_MAX and "w1" in paths and "g1" in paths and "p47" in paths
    assert "p48" not in paths and "BAD ID" not in paths and "" not in paths
    w1 = paths["w1"]
    assert w1 == {"sessions": 2, "seconds": 151, "bytes_up": 9000 * 4 + 200, "bytes_down": 500 * 2 + 300 + 500 + 150,
                  "abnormal": 0, "connect_ms_sum": 4 + 10 + 20, "connect_n": 3,
                  "errors": {"origin_refused": 2, "origin_timeout": 0, "origin_error": 0, "limit": 0,
                             "country": 0, "protocol": 1, "edge": 0},
                  # SPEC §22.7 / §22.12: no reload / drain windows in this state -> both ends are normal
                  "reused_n": 0, "ends": {"normal": 2, "idle_timeout": 0, "origin": 0, "node_reload": 0,
                                          "node_drain": 0, "other": 0}}
    g1 = paths["g1"]
    assert g1["sessions"] == 1 and g1["seconds"] == 5 and g1["errors"]["origin_timeout"] == 1
    assert g1["connect_n"] == 1 and g1["connect_ms_sum"] == 2 and g1["bytes_up"] == 40000 + 200
    for p in paths.values():   # the controller rejects the whole POST on a negative / non-numeric counter
        assert all(type(v) is int and v >= 0 for k, v in p.items() if k not in ("errors", "ends"))
        assert list(p["ends"]) == list(agent.TUNNEL_END_KEYS) and sum(p["ends"].values()) == p["sessions"]
        assert list(p["errors"]) == list(agent.TUNNEL_ERRORS) and all(type(v) is int for v in p["errors"].values())
    json.dumps(state)
    # by_protocol (bytes) and the path bytes add up for lines with a path id
    assert sum(p["bytes_up"] + p["bytes_down"] for p in paths.values()) <= sum(t["by_protocol"].values())
    # a later read of the same hour keeps adding to the same path entries (state round trip)
    state = json.loads(json.dumps(state))
    write_log(log, [tline(rt=1)])
    agent.read_usage(state, str(log))
    item = {i["host"]: i for i in agent.usage_items(state["pending"])}["t.com"]
    assert item["tunnel"]["paths"]["w1"]["sessions"] == 3


def test_tpath_item_sanitises():
    p = agent.tpath_item({"sessions": -3, "seconds": 2.6, "connect_ms_sum": "7", "errors": {"limit": 2, "x": 9}})
    assert p["sessions"] == 0 and p["seconds"] == 3 and p["connect_ms_sum"] == 7
    assert p["errors"] == dict(dict.fromkeys(agent.TUNNEL_ERRORS, 0), limit=2)


def test_live_tunnel_attempts_and_errors(tmp_path):
    log = tmp_path / "access.log"
    m1, m2 = T0, T0 + timedelta(minutes=1)
    rows = [tline(t=iso(m1)), tline(t=iso(m1), s=502, us="502", uct="-"), tline(t=iso(m1), s=504, us="504", uct="-"),
            tline(t=iso(m1), s=404, us="404"), tline(t=iso(m1), s=429, us="", uct=""),
            tline(t=iso(m1), s=499, us="-", uct="-"),                      # not classified, still an attempt
            tline(t=iso(m1), tp="", s=502, us="502"),                      # no path id: not attributed
            line(t=iso(m1), h="t.com"),                                    # normal request
            line(t=iso(m2), h="t.com")]                                    # a minute without tunnel lines
    write_log(log, rows)
    state = {}
    agent.read_usage(state, str(log))
    items = {i["minute"]: i for i in agent.live_items(state["live"], agent.live_cutoff()) if i["host"] == "t.com"}
    k1, k2 = m1.strftime("%Y-%m-%dT%H:%M:00Z"), m2.strftime("%Y-%m-%dT%H:%M:00Z")
    assert items[k1]["tunnel_attempts"] == 6 and items[k1]["tunnel_errors"] == 2
    assert "tunnel_attempts" not in items[k2] and "tunnel_errors" not in items[k2]


ERRLOG = [
    '2026/10/01 19:54:50 [error] 3701#3701: *23 recv() failed (104: Connection reset by peer) while proxying '
    'upgraded connection, client: 127.0.0.1, server: t.com, request: "GET /ws?ed=2048 HTTP/1.1", upstream: '
    '"http://127.0.0.1:41969/ws?ed=2048", host: "t.com"',
    '2026/10/01 19:54:51 [error] 3702#3702: *25 recv() failed (104: Connection reset by peer) while reading '
    'upstream, client: 127.0.0.1, server: t.com, request: "POST /svc/Tun HTTP/2.0", upstream: '
    '"grpc://127.0.0.1:32805", host: "t.com"',
    '2026/10/01 19:54:52 [error] 3702#3702: *26 upstream timed out (110: Connection timed out) while proxying '
    'upgraded connection, client: 127.0.0.1, server: t.com, request: "GET /ws HTTP/1.1", upstream: '
    '"http://127.0.0.1:41969/ws", host: "T.com:443"',
    '2026/10/01 19:54:53 [error] 3702#3702: *27 upstream prematurely closed connection while reading upstream, '
    'client: 127.0.0.1, server: *.w.com, request: "GET /xh/abc/0 HTTP/1.1", upstream: "http://10.0.0.1:80/xh", '
    'host: "a.w.com"',
    # not abnormal ends: before the response header, client side ([info]), unknown host / path, limits
    '2026/10/01 19:54:44 [error] 3701#3701: *9 connect() failed (111: Connection refused) while connecting to '
    'upstream, client: 127.0.0.1, server: t.com, request: "GET /ws HTTP/1.1", upstream: "http://127.0.0.1:1/ws", '
    'host: "t.com"',
    '2026/10/01 19:54:50 [error] 3702#3702: *21 upstream prematurely closed connection while reading response '
    'header from upstream, client: 127.0.0.1, server: t.com, request: "GET /ws HTTP/1.1", upstream: '
    '"http://127.0.0.1:41969/ws", host: "t.com"',
    '2026/10/01 19:54:50 [info] 3702#3702: *22 recv() failed (104: Connection reset by peer) while proxying '
    'upgraded connection, client: 127.0.0.1, server: t.com, request: "GET /ws HTTP/1.1", upstream: '
    '"http://127.0.0.1:41969/ws", host: "t.com"',
    '2026/10/01 19:54:50 [error] 3702#3702: *28 recv() failed (104: Connection reset by peer) while reading '
    'upstream, client: 127.0.0.1, server: t.com, request: "GET /page HTTP/1.1", upstream: "http://1.2.3.4/page", '
    'host: "t.com"',
    '2026/10/01 19:54:50 [error] 3702#3702: *29 recv() failed (104: Connection reset by peer) while reading '
    'upstream, client: 127.0.0.1, server: x.com, request: "GET /ws HTTP/1.1", upstream: "http://1.2.3.4/ws", '
    'host: "x.com"',
    '2026/10/01 19:54:51 [error] 3701#3701: *35 limiting connections by zone "pcdn_tn_ip2", client: 127.0.0.1, '
    'server: t.com, request: "GET /ws HTTP/1.1", host: "t.com"',
]
TN_CONFIG = {"sites": [
    {"id": 1, "domain": "t.com", "status": "active", "hosts": [{"name": "t.com", "origin": {"address": "1.2.3.4"}}],
     "tunnel": {"enabled": True, "paths": [
         {"id": "w1", "path": "/ws", "protocol": "ws"}, {"id": "g1", "path": "/svc", "protocol": "grpc"},
         {"id": "w2", "path": "/ws/deep", "protocol": "ws"}]}},
    {"id": 2, "domain": "w.com", "status": "active", "hosts": [{"name": "*.w.com", "origin": {"address": "1.2.3.4"}}],
     "tunnel": {"enabled": True, "paths": [{"id": "x1", "path": "/xh", "protocol": "xhttp"}]}},
    {"id": 3, "domain": "off.com", "status": "active", "hosts": [{"name": "off.com", "origin": {"address": "1.2.3.4"}}],
     "tunnel": {"enabled": False, "paths": [{"id": "z", "path": "/z", "protocol": "ws"}]}},
]}


def test_tunnel_map_longest_prefix_and_wildcards():
    m = agent.tunnel_map(TN_CONFIG)
    assert m["t.com"] == [["/ws/deep", "w2"], ["/svc", "g1"], ["/ws", "w1"]] and "off.com" not in m
    assert agent._tmap_lookup(m, "t.com", "/ws/deep/x") == "w2" and agent._tmap_lookup(m, "T.com:443", "/ws") == "w1"
    assert agent._tmap_lookup(m, "a.w.com", "/xh/1") == "x1" and agent._tmap_lookup(m, "w.com", "/xh") is None
    assert agent._tmap_lookup(m, "t.com", "/other") is None


def test_abnormal_ends_from_error_log(tmp_path):
    cfg = make_cfg(tmp_path)
    (tmp_path / "error.log").write_text("\n".join(ERRLOG) + "\n")
    state = {"tunnel_map": agent.tunnel_map(TN_CONFIG)}
    shipped = agent.collect_logs(state, cfg)
    assert shipped and all("127.0.0.1" not in ln["msg"] for ln in shipped)   # shipping still redacts
    hour = datetime.strptime("2026/10/01 19:00:00", "%Y/%m/%d %H:%M:%S").astimezone(timezone.utc) \
        .strftime("%Y-%m-%dT%H:00:00Z")   # nginx writes local time
    items = {i["host"]: i for i in agent.usage_items(state["pending"])}
    assert set(items) == {"t.com", "a.w.com"} and items["t.com"]["hour"] == hour
    t = items["t.com"]["tunnel"]["paths"]
    assert t["w1"]["abnormal"] == 2 and t["g1"]["abnormal"] == 1 and "w2" not in t
    assert items["a.w.com"]["tunnel"]["paths"]["x1"]["abnormal"] == 1
    assert items["t.com"]["requests"] == 0 and items["t.com"]["tunnel"]["sessions"] == 0
    # read again: nothing new, nothing double-counted; no map -> nothing counted
    agent.collect_logs(state, cfg)
    assert {i["host"]: i for i in agent.usage_items(state["pending"])}["t.com"]["tunnel"]["paths"]["w1"]["abnormal"] == 2
    assert agent.account_abnormal({}, "\n".join(ERRLOG)) == 0


def test_fair_hot_hysteresis_and_node_block(tmp_path):
    assert agent.fair_hot(850, 1000, False) and not agent.fair_hot(849, 1000, False)
    assert agent.fair_hot(810, 1000, True) and not agent.fair_hot(799, 1000, True)
    assert not agent.fair_hot(10_000, 0, True)                      # unknown capacity: never hot
    cfg = make_cfg(tmp_path, NODE_NAME="ir-1", CAPACITY_MBPS="900", FAIR_SHARE_PCT="30")
    assert agent.norm_node({}, cfg) == {"capacity_mbps": 900, "fair_share_pct": 30, "name": "ir-1", "http3": True}
    assert agent.norm_node({"node": {"capacity_mbps": 2000, "fair_share_pct": 500, "name": "x"}}, cfg) == \
        {"capacity_mbps": 2000, "fair_share_pct": 100, "name": "x", "http3": True}
    assert agent.norm_node({"node": "junk"}, make_cfg(tmp_path))["fair_share_pct"] == 25
    tag = agent.node_tag("ir-1")
    assert re.fullmatch(r"[0-9a-f]{8}", tag) and tag == agent.node_tag("ir-1") != agent.node_tag("ir-2")


def test_fair_signal_reports_hot_flag_on_localhost(tmp_path, monkeypatch):
    a = new_agent(tmp_path)
    a.state["node"] = {"capacity_mbps": 1000, "fair_share_pct": 25, "name": "n"}
    urls = []

    class Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *e):
            return False

    class Opener:
        def open(self, url, timeout=0):
            urls.append(url)
            return Resp(b"")
    monkeypatch.setattr(agent.urllib.request, "build_opener", lambda *a: Opener())
    a.fair_signal({"tx_mbps": 900})
    a.fair_signal({"tx_mbps": 820})
    a.fair_signal({"tx_mbps": 100})
    port = a.cfg["HTTP_PORT"]
    assert urls == [f"http://127.0.0.1:{port}/__pcdn/fair?hot=25"] * 2 + [f"http://127.0.0.1:{port}/__pcdn/fair?hot=0"]
    a.cfg["NGINX_CAPS"] = dict(agent.LEGACY_CAPS, nginx="1.24.0", modules=[])   # no njs: nothing to tell
    a.fair_signal({"tx_mbps": 900})
    assert len(urls) == 3
