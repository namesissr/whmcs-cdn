"""SPEC §17.1 WAF learning mode, edge side.

* rendering: `waf.learning` -> sites.js `waf.learn_until` (UNIX second) only for learning sites; the
  body inspection is routed for a learning site even when its WAF mode is off;
* njs: while learning, the WAF (signatures, packs, request-body inspection) is log-only - the verdict
  is "log:waf:<rule>" and never a block - and firewall / rate limits are untouched; after `until`
  the configured mode applies again without a re-render;
* usage: the per host-hour `waf_learn` aggregate (rules / paths / clients), its caps and the p95;
* real nginx: an attack-looking request on a learning site is answered 200, logged "log:waf:<id>"
  and counted in waf_learn; the same request on a blocking site gets 403.
"""

import http.client
import http.server
import importlib.util
import json
import pathlib
import shutil
import subprocess
import threading
import time
import urllib.parse
from datetime import datetime, timedelta, timezone

import pytest

from conftest import TEST_ORIGIN_ALLOW, modules_available, nginx_conf, pick_port
from test_njs_logic import ALL_GROUPS, build, run, site as js_site

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("agent_waflearn", HERE.parent / "pcdn-agent.py")
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)

NODE = shutil.which("node") is not None
SQLI = "/?id=" + urllib.parse.quote("1' or '1'='1")


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


FUTURE = iso(datetime.now(timezone.utc) + timedelta(days=3))
PAST = iso(datetime.now(timezone.utc) - timedelta(hours=1))


# ----------------------------------------------------------------- normalisation / rendering

def test_norm_waf_learning():
    n = agent.norm_waf_learning
    assert n({}) is None
    assert n({"waf": {"learning": {"enabled": False, "until": FUTURE}}}) is None
    assert n({"waf": {"learning": {"enabled": True, "until": None}}}) is None
    assert n({"waf": {"learning": {"enabled": True, "until": "soon"}}}) is None
    assert n({"waf": {"learning": {"enabled": "yes", "until": FUTURE}}}) is None
    assert n({"waf": {"learning": True}}) is None
    s = {"waf": {"learning": {"enabled": True, "until": "2030-01-02T03:04:05Z"}}}
    assert n(s) == 1893553445
    assert n({"waf": {"learning": {"enabled": True, "until": "2030-01-02T06:34:05+03:30"}}}) == 1893553445
    assert n({"waf": {"learning": {"enabled": True, "until": "2030-01-02T03:04:05"}}}) == 1893553445   # naive = UTC
    # with `now`: past -> None, far future capped at now + 31 days
    assert n(s, now=1893553445) is None
    assert n(s, now=1893553444) == 1893553445
    assert n(s, now=1700000000) == 1700000000 + 31 * 86400


def _js(**waf):
    return agent.site_js({"id": 1, "domain": "x.test", "waf": waf}, ["x.test"], {}, {})


def test_site_js_learn_until_only_for_learning_sites():
    plain = _js(mode="block", groups=["sqli"])
    assert "learn_until" not in plain["waf"]
    assert _js(mode="block", groups=["sqli"], learning={"enabled": False, "until": FUTURE}) == plain
    assert _js(mode="block", groups=["sqli"], learning={"enabled": True, "until": None}) == plain
    on = _js(mode="block", groups=["sqli"], learning={"enabled": True, "until": "2030-01-02T03:04:05Z"})
    assert on["waf"] == dict(plain["waf"], learn_until=1893553445)
    assert json.dumps(on["waf"]).count("learn_until") == 1


# ----------------------------------------------------------------- njs logic

LEARN = int(time.time()) + 86400


@pytest.mark.skipif(not NODE, reason="node not installed")
def test_njs_learning_is_log_only(tmp_path):
    waf = {"mode": "block", "paranoia": 1, "groups": ALL_GROUPS, "exclusions": [], "off_paths": [],
           "packs": ["api", "wordpress"]}
    fw = {"default_action": "allow", "rules": [
        {"id": "fwblk", "action": "block", "conditions": [{"field": "path", "op": "starts_with", "value": "/fwblock"}]},
        {"id": "fwlog", "action": "log", "conditions": [{"field": "path", "op": "starts_with", "value": "/fwlog"}]}]}
    rl = [{"id": "rl", "path_re": "^/rl$", "methods": [], "requests": 1, "period": 60, "action": "block",
           "block_seconds": 60}]
    build(tmp_path, {
        "1": js_site(waf=dict(waf, learn_until=LEARN), firewall=fw, ratelimit=rl),   # learning
        "2": js_site(waf=waf, firewall=fw),                                           # blocking
        "3": js_site(waf=dict(waf, learn_until=int(time.time()) - 5)),                # learning over
        "4": js_site(waf=dict(waf, mode="off", learn_until=LEARN)),                   # off + learning
        "5": js_site(waf=dict(waf, mode="detect", learn_until=LEARN)),
    })
    q = "id=1%27+or+%271%27%3D%271"
    two = q + "&x=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
    res = run(tmp_path, [
        {"kind": "verdict", "site": "1", "uri": "/", "args": q},
        {"kind": "verdict", "site": "2", "uri": "/", "args": q},
        {"kind": "verdict", "site": "3", "uri": "/", "args": q},
        {"kind": "verdict", "site": "4", "uri": "/", "args": q},
        {"kind": "verdict", "site": "5", "uri": "/", "args": q},
        {"kind": "verdict", "site": "1", "uri": "/.env"},                                  # scanner group
        {"kind": "verdict", "site": "1", "uri": "/", "extra": {"method": "TRACK"}},       # protocol group
        {"kind": "verdict", "site": "1", "uri": "/fwblock", "args": q},                    # firewall untouched
        {"kind": "verdict", "site": "1", "uri": "/fwlog", "args": q},                      # WAF id wins over a log
        {"kind": "verdict", "site": "2", "uri": "/fwlog", "args": "a=1"},
        {"kind": "verdict", "site": "1", "uri": "/", "args": "a=1"},
        {"kind": "verdict", "site": "1", "uri": "/rl"},
        {"kind": "verdict", "site": "1", "uri": "/rl"},                                    # rate limit untouched
        {"kind": "verdict", "site": "1", "uri": "/", "args": two},                         # two rules: ":a"
        {"kind": "verdict", "site": "2", "uri": "/", "args": two},
        {"kind": "verdict", "site": "1", "uri": "/", "args": two, "extra": {"headers": {"User-Agent": "sqlmap/1.7"}}},
    ])
    assert res[:13] == ["log:waf:942100", "block:waf:942100", "block:waf:942100", "log:waf:942100", "log:waf:942100",
                        "log:waf:913120", "log:waf:920100", "block:firewall:fwblk", "log:waf:942100:a",
                        "log:firewall:fwlog", "ok", "ok", "block:ratelimit:rl"]
    first = res[14].split(":")[2]
    assert res[13] == f"log:waf:{first}:a" and res[14] == f"block:waf:{first}"
    assert res[15].startswith("log:waf:") and res[15].endswith(":a")


@pytest.mark.skipif(not NODE, reason="node not installed")
def test_njs_learning_body_inspection_is_log_only(tmp_path):
    waf = {"mode": "block", "paranoia": 1, "groups": ["sqli"], "exclusions": [], "off_paths": [],
           "packs": ["api", "wordpress"]}
    build(tmp_path, {"1": js_site(waf=dict(waf, learn_until=LEARN)), "2": js_site(waf=waf),
                     "4": js_site(waf=dict(waf, mode="off", learn_until=LEARN)),
                     "6": js_site(waf=dict(waf, mode="off", learn_until=int(time.time()) - 5))})
    j = {"Content-Type": "application/json", "Content-Length": "20"}
    body = '{"__proto__": {"x": 1}}'
    res = run(tmp_path, [
        {"kind": "inspect", "site": "1", "uri": "/api", "body": body, "extra": {"headers": j}},
        {"kind": "inspect", "site": "2", "uri": "/api", "body": body, "extra": {"headers": j}},
        {"kind": "inspect", "site": "4", "uri": "/api", "body": body, "extra": {"headers": j}},
        # an earlier non-WAF log verdict is replaced by the WAF rule id; an earlier WAF one is kept
        {"kind": "inspect", "site": "1", "uri": "/api", "body": body,
         "extra": {"headers": j, "vars": {"pcdn_vmemo": "log:firewall:x"}}},
        {"kind": "inspect", "site": "1", "uri": "/api", "body": body,
         "extra": {"headers": j, "vars": {"pcdn_vmemo": "log:waf:942100"}}},
        {"kind": "inspect", "site": "1", "uri": "/api", "body": body,
         "extra": {"headers": j, "vars": {"pcdn_vmemo": "log:waf:995220"}}},
        {"kind": "inspect", "site": "2", "uri": "/api", "body": '{"a": 1}',
         "extra": {"headers": j, "vars": {"pcdn_vmemo": "log:firewall:x"}}},
        {"kind": "bodyneed", "site": "4", "uri": "/api", "extra": {"method": "POST", "headers": j}},
        {"kind": "bodyneed", "site": "6", "uri": "/api", "extra": {"method": "POST", "headers": j}},
    ])
    assert res[0] == {"redirect": "@pcdn_body", "v": "log:waf:995220"}
    assert res[1] == {"code": 403, "body": "", "v": "block:waf:995220"}
    assert res[2] == {"redirect": "@pcdn_body", "v": "log:waf:995220"}
    # an earlier signal on the same request: the WAF id is kept and marked ":a"
    assert res[3] == {"redirect": "@pcdn_body", "v": "log:waf:995220:a"}
    assert res[4] == {"redirect": "@pcdn_body", "v": "log:waf:942100:a"}
    assert res[5] == {"redirect": "@pcdn_body", "v": None}                 # the same rule again: unchanged
    assert res[6] == {"redirect": "@pcdn_body", "v": None}                 # clean body, not learning
    assert res[7:] == ["1", ""]


# ----------------------------------------------------------------- usage aggregation

def rec(t, path="/", v="ok", ip="10.0.0.1", m="GET", host="learn.test", **kw):
    e = {"t": t, "h": host, "b": 100, "s": 200, "c": "MISS", "ip": ip, "cc": "IR", "m": m, "u": path, "ua": "x",
         "v": v, "tn": "", "rt": 0.001, "bu": 10}
    e.update(kw)
    return e


def feed(state, records):
    learn = agent._learn_ctx(state) if state.get("learn_hosts") else None
    pending, events = state.setdefault("pending", {}), state.setdefault("events", [])
    for e in records:
        agent._account(e, pending, events, None, "", None, None, None, learn)


def items(state, flush=True):
    if flush:
        agent.learn_flush(state)
    return {it["host"] + "|" + it["hour"]: it for it in agent.usage_items(state["pending"], state.get("waf_learn_hour"))}


def lh_state(until=4102444000, wild=False):
    return {"learn_hosts": {"exact": {} if wild else {"learn.test": until}, "wild": {".learn.test": until} if wild else {}}}


def test_learn_hosts_from_config():
    sites = [{"id": 1, "status": "active", "hosts": [{"name": "a.test"}, {"name": "*.w.test"}],
              "waf": {"learning": {"enabled": True, "until": FUTURE}}},
             {"id": 2, "status": "suspended", "hosts": [{"name": "s.test"}], "waf": {"learning": {"enabled": True, "until": FUTURE}}},
             {"id": 3, "hosts": [{"name": "past.test"}], "waf": {"learning": {"enabled": True, "until": PAST}}},
             {"id": 4, "hosts": [{"name": "plain.test"}], "waf": {"mode": "block"}}]
    lh = agent.learn_hosts({"sites": sites})
    u = agent.norm_waf_learning(sites[0])
    assert lh == {"exact": {"a.test": u}, "wild": {".w.test": u}}
    assert agent.learn_until(lh, "a.test") == u and agent.learn_until(lh, "x.w.test") == u
    assert agent.learn_until(lh, "plain.test") == 0
    assert agent.learn_hosts({"sites": sites[1:]}) == {}


def test_learn_prefix():
    p = agent.learn_prefix
    assert [p("/"), p("/a"), p("/a/"), p("/a/b"), p("/a/b/c/d"), p("//a//b")] == ["/", "/a", "/a", "/a/b", "/a/b", "/a/b"]
    assert p("/" + "x" * 300 + "/y") == "/" + "x" * 64 + "/y"


def test_waf_learn_aggregate():
    st = lh_state()
    T = "2026-10-02T10:0{}:{:02d}+00:00"
    recs = []
    # minute 0: client .1 sends 5 requests to /wp-json/wp/..., 2 of them hit rule 942100 (log verdict)
    for i in range(5):
        recs.append(rec(T.format(0, i), f"/wp-json/wp/v2/posts?x={i}", v="log:waf:942100" if i < 2 else "ok",
                        m="POST" if i == 4 else "GET"))
    # minute 0: client .2 sends 2; firewall log and a WAF hit on another prefix
    recs.append(rec(T.format(0, 10), "/api/x", ip="10.0.0.2", v="log:firewall:r1"))
    recs.append(rec(T.format(0, 11), "/api/y", ip="10.0.0.2", v="log:waf:941100", m="put"))
    # minute 1: client .1 sends 3 to /api
    for i in range(3):
        recs.append(rec(T.format(1, i), "/api/z", ip="10.0.0.1"))
    # another (non-learning) host and tunnel / internal lines: never in waf_learn
    recs.append(rec(T.format(1, 5), "/?a", host="plain.test", v="log:waf:942100"))
    recs.append(rec(T.format(1, 6), "/tn", tn="ws", v="ok"))
    recs.append(rec(T.format(1, 7), "/__pcdn/verify", v="ok"))
    feed(st, recs)
    out = items(st)
    assert "waf_learn" not in out["plain.test|2026-10-02T10:00:00Z"]
    wl = out["learn.test|2026-10-02T10:00:00Z"]["waf_learn"]
    assert wl["rules"] == {
        "942100": {"hits": 2, "clients": 1, "attack": 0, "paths": {"/wp-json/wp": {"hits": 2, "clients": 1, "attack": 0}},
                   "methods": {"GET": 2}},
        "941100": {"hits": 1, "clients": 1, "attack": 0, "paths": {"/api/y": {"hits": 1, "clients": 1, "attack": 0}},
                   "methods": {"PUT": 1}}}
    assert list(wl["rules"]) == ["942100", "941100"]   # most hits first

    def pth(req, mx, methods):
        return {"req": req, "max_rpm": mx, "p95_rpm": mx, "p95_rps_min": mx, "methods": methods}
    assert wl["paths"] == {"/wp-json/wp": pth(5, 5, {"GET": 4, "POST": 1}), "/api/z": pth(3, 3, {"GET": 3}),
                           "/api/x": pth(1, 1, {"GET": 1}), "/api/y": pth(1, 1, {"PUT": 1})}
    # client-minutes: (.1, m0) = 5, (.2, m0) = 2, (.1, m1) = 3 -> max 5, p95 (nearest rank 3 of 3) = 5
    assert wl["clients"] == {"max_rpm": 5, "p95_rpm": 5}
    assert not st["waf_learn_win"]
    json.dumps(out)


def test_waf_learn_respects_until_and_wildcards():
    until = int(datetime(2026, 10, 2, 10, 0, 30, tzinfo=timezone.utc).timestamp())
    st = lh_state(until, wild=True)
    feed(st, [rec("2026-10-02T10:00:10+00:00", "/a", host="x.learn.test", v="log:waf:942100"),
              rec("2026-10-02T10:00:40+00:00", "/b", host="x.learn.test", v="block:waf:942100")])
    wl = items(st)["x.learn.test|2026-10-02T10:00:00Z"]["waf_learn"]
    assert wl["paths"] == {"/a": {"req": 1, "max_rpm": 1, "p95_rpm": 1, "p95_rps_min": 1, "methods": {"GET": 1}}}
    assert wl["rules"]["942100"]["hits"] == 1


def test_waf_learn_hour_attribution_and_late_lines():
    st = lh_state()
    feed(st, [rec("2026-10-02T10:59:01+00:00", "/a"), rec("2026-10-02T10:59:02+00:00", "/a"),
              rec("2026-10-02T11:00:01+00:00", "/a"),
              rec("2026-10-02T10:59:59+00:00", "/a")])   # logged late: counted, not in the closed window
    out = items(st)
    a, b = out["learn.test|2026-10-02T10:00:00Z"]["waf_learn"], out["learn.test|2026-10-02T11:00:00Z"]["waf_learn"]
    assert a["paths"]["/a"]["req"] == 3 and a["paths"]["/a"]["max_rpm"] == 2 and a["clients"]["max_rpm"] == 2
    assert b["paths"]["/a"]["req"] == 1 and b["clients"] == {"max_rpm": 1, "p95_rpm": 1}


def test_rpm_bucket_and_p95_math():
    b = agent.rpm_bucket
    assert [b(0), b(1), b(64), b(200)] == [0, 1, 64, 200]
    prev = 200
    for n in list(range(201, 5000)) + [10 ** 6, 10 ** 7, 123456789]:
        k = b(n)
        assert n <= k <= n * agent.RPM_STEP + 1, (n, k)
        assert k >= prev
        prev = k
    assert len({b(n) for n in range(1, 10 ** 7, 997)}) < 450   # bounded number of histogram keys
    p = agent.p95_hist
    assert p({}) == 0
    assert p({"7": 1}) == 7
    assert p({str(i): 1 for i in range(1, 101)}) == 95             # nearest rank: ceil(0.95 * 100) = 95
    assert p({str(i): 1 for i in range(1, 21)}) == 19              # ceil(0.95 * 20) = 19
    assert p({"1": 94, "50": 1, "900": 5}) == 50                   # rank 95 is the single 50
    assert p({"1": 95, "50": 1, "900": 4}) == 1
    assert p({"1": 94, "50": 2, "900": 4}) == 50


def test_p95_from_requests():
    st = lh_state()
    recs = []
    # 100 clients in one minute: client i sends i requests -> p95 = 95, max = 100
    for i in range(1, 101):
        recs += [rec("2026-10-02T10:00:%02d+00:00" % (j % 60), "/x", ip=f"10.1.{i // 256}.{i % 256}") for j in range(i)]
    recs.sort(key=lambda e: e["t"])
    feed(st, recs)
    wl = items(st)["learn.test|2026-10-02T10:00:00Z"]["waf_learn"]
    assert wl["clients"] == {"max_rpm": 100, "p95_rpm": 95}
    assert wl["paths"]["/x"]["max_rpm"] == 100 and wl["paths"]["/x"]["req"] == 5050
    # per prefix: the coarser histogram (exact to 32, then ≤ 20 % high)
    assert 95 <= wl["paths"]["/x"]["p95_rpm"] <= 100


def test_waf_learn_bounds(monkeypatch):
    st = lh_state()
    recs = []
    t = "2026-10-02T10:00:00+00:00"
    for i in range(60):    # one rule on 60 prefixes
        recs.append(rec(t, f"/k{i}", v="log:waf:942100"))
    for i in range(300):   # 300 rules, 300 prefixes, 30 methods, 5000 client IPs
        recs.append(rec(t, f"/p{i}/q{i}/r", v=f"log:waf:{900000 + i}", m="M" + chr(65 + i % 26) + chr(65 + i % 30 // 26),
                        ip=f"10.2.{i // 250}.{i % 250}"))
    for i in range(5000):
        recs.append(rec(t, "/p0/q0", ip=f"10.3.{i // 250}.{i % 250}"))
    recs.append(rec(t, "/", v="log:waf:notanid"))
    for i in range(30):    # 30 methods on one prefix and one rule
        recs.append(rec(t, "/p0/q0", m="X" + chr(65 + i % 26) + chr(65 + i // 26), v="log:waf:942100"))
    feed(st, recs)
    win = st["waf_learn_win"]["learn.test"]
    assert len(win["ip"]) == agent.WAF_LEARN_IPS and len(win["pi"]) <= agent.WAF_LEARN_PAIRS
    L = st["pending"]["learn.test|2026-10-02T10:00:00Z"]["waf_learn"]
    assert len(L["rules"]) == agent.WAF_LEARN_RULES and "notanid" not in L["rules"]
    assert len(L["paths"]) == agent.WAF_LEARN_PATHS
    assert all(len(r["paths"]) <= agent.WAF_LEARN_RULE_PATHS for r in L["rules"].values())
    assert all(len(r["methods"]) <= agent.WAF_LEARN_METHODS + 1 for r in L["rules"].values())
    assert all(len(p["methods"]) <= agent.WAF_LEARN_METHODS + 1 for p in L["paths"].values())
    wl = items(st)["learn.test|2026-10-02T10:00:00Z"]["waf_learn"]
    assert len(wl["rules"]) == 100 and len(wl["paths"]) == agent.WAF_LEARN_PATHS_TOP
    assert all(len(r["paths"]) <= agent.WAF_LEARN_RULE_TOP for r in wl["rules"].values())
    assert wl["rules"]["942100"]["hits"] == 90
    assert wl["paths"]["/p0/q0"]["req"] == 5031
    assert list(wl["paths"])[0] == "/p0/q0"
    for meth in (wl["paths"]["/p0/q0"]["methods"], wl["rules"]["942100"]["methods"]):
        assert len(meth) == agent.WAF_LEARN_METHODS + 1 and meth["OTHER"] > 0


def test_waf_learn_host_windows_bounded():
    st = {"learn_hosts": {"exact": {}, "wild": {".t": 4102444000}}}
    feed(st, [rec("2026-10-02T10:00:00+00:00", "/", host=f"h{i}.t") for i in range(agent.WAF_LEARN_HOSTS + 20)])
    assert len(st["waf_learn_win"]) == agent.WAF_LEARN_HOSTS
    out = items(st)
    # every host still gets its request / path counts; only the client window is skipped beyond the cap
    assert len([k for k, v in out.items() if "waf_learn" in v]) == agent.WAF_LEARN_HOSTS + 20


def test_read_usage_flushes_closed_minutes(tmp_path):
    log = tmp_path / "access.log"
    old = "2026-01-01T10:00:%02d+00:00"
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")
    log.write_text("".join(json.dumps(e) + "\n" for e in [rec(old % 1, "/a"), rec(old % 2, "/a"), rec(now, "/b")]))
    st = lh_state()
    agent.read_usage(st, str(log))
    # the old minute is closed (its window folded into the host-hour), the current one stays open
    assert list(st["waf_learn_win"]) == ["learn.test"] and st["waf_learn_win"]["learn.test"]["m"] > "2026-01-01"
    k = "learn.test|2026-01-01T10:00:00Z"
    wl = agent.usage_item(k, st["pending"][k], st.get("waf_learn_hour"))["waf_learn"]
    assert wl["paths"]["/a"]["max_rpm"] == 2 and wl["clients"]["max_rpm"] == 2


def test_attack_marker_counted_and_stripped():
    st = lh_state()
    feed(st, [rec("2026-10-02T10:00:01+00:00", "/a/b/c", v="log:waf:942100:a", ip="10.0.0.1"),
              rec("2026-10-02T10:00:02+00:00", "/a/b/d", v="log:waf:942100", ip="10.0.0.2"),
              rec("2026-10-02T10:00:03+00:00", "/z", v="log:waf:942100:a", ip="10.0.0.3", host="plain.test")])
    # security events carry the plain rule id (also for hosts that are not learning)
    assert [(ev["action"], ev["source"], ev["rule"]) for ev in st["events"]] == [("log", "waf", "942100")] * 3
    r = items(st)["learn.test|2026-10-02T10:00:00Z"]["waf_learn"]["rules"]["942100"]
    assert r == {"hits": 2, "clients": 2, "attack": 1, "methods": {"GET": 2},
                 "paths": {"/a/b": {"hits": 2, "clients": 2, "attack": 1}}}


def test_distinct_client_sketch():
    for n, bits in ((1, 256), (20, 256), (100, 256), (300, 256), (20, 128)):
        bm = 0
        for i in range(n):
            bm = agent.sketch_add(bm, f"192.0.2.{i % 250}-{i // 250}", bits)
            bm = agent.sketch_add(bm, f"192.0.2.{i % 250}-{i // 250}", bits)   # repeats do not count
        est = agent.sketch_count(bm, bits)
        assert abs(est - n) <= max(2, 0.15 * n), (n, bits, est)
    assert agent.sketch_count(0, 128) == 0
    assert agent.sketch_count((1 << 128) - 1, 128) == round(128 * __import__("math").log(128))   # saturated
    assert agent.sketch_count((1 << 256) - 1, 256) == 1420


def test_hour_to_date_values_across_pushes():
    """Every push reports the hour-to-date distinct clients / rates (the controller keeps the max),
    while counters are deltas; a minute closed after its push still produces an item."""
    st = lh_state()
    t = "2026-10-02T10:%02d:%02d+00:00"
    feed(st, [rec(t % (0, i), "/x", v="log:waf:942100", ip=f"10.0.0.{i}") for i in range(10)])
    first = items(st, flush=False)["learn.test|2026-10-02T10:00:00Z"]["waf_learn"]
    assert first["rules"]["942100"]["hits"] == 10 and first["rules"]["942100"]["clients"] == 10
    assert first["clients"] == {"max_rpm": 0, "p95_rpm": 0}         # the minute is still open
    st["pending"].clear()                                              # pushed
    feed(st, [rec(t % (1, i), "/x", v="log:waf:942100", ip=f"10.0.0.{i}") for i in range(5, 25)])
    second = items(st, flush=False)["learn.test|2026-10-02T10:00:00Z"]["waf_learn"]
    assert second["rules"]["942100"]["hits"] == 20 and 23 <= second["rules"]["942100"]["clients"] <= 27
    assert second["clients"] == {"max_rpm": 1, "p95_rpm": 1}           # minute 0 closed by minute 1
    assert second["paths"]["/x"]["req"] == 20
    st["pending"].clear()
    agent.learn_flush(st)                                              # minute 1 closes: an item again
    third = items(st, flush=False)["learn.test|2026-10-02T10:00:00Z"]
    assert third["requests"] == 0 and third["waf_learn"]["rules"] == {}
    assert third["waf_learn"]["paths"] == {"/x": {"req": 0, "max_rpm": 1, "p95_rpm": 1, "p95_rps_min": 1, "methods": {}}}
    # hour statistics are bounded in time
    feed(st, [rec("2026-10-02T13:00:00+00:00", "/x", v="log:waf:942100")])
    agent.learn_flush(st)
    agent.prune_learn_hours(st)
    assert "learn.test|2026-10-02T10:00:00Z" in st["waf_learn_hour"]
    feed(st, [rec("2026-10-02T14:00:00+00:00", "/x", v="log:waf:942100")])
    agent.learn_flush(st)
    agent.prune_learn_hours(st)
    assert sorted(st["waf_learn_hour"]) == ["learn.test|2026-10-02T13:00:00Z", "learn.test|2026-10-02T14:00:00Z"]


def test_controller_contract_shape():
    """Keys / bounds the controller's waf_learning.WafLearn reads (caps 100 rules, 10 prefixes per
    rule, 50 paths, 10 methods; method names [A-Z]{1,10}; prefix = first two path segments)."""
    import re
    st = lh_state()
    feed(st, [rec("2026-10-02T10:00:00+00:00", f"/s{i % 71}/t/u?q", v=f"log:waf:{942100 + i % 3}",
                  m=["GET", "POST", "propfind", "VERYLONGMETHODNAME", "X1"][i % 5], ip=f"10.9.0.{i % 200}")
              for i in range(2000)])
    wl = items(st)["learn.test|2026-10-02T10:00:00Z"]["waf_learn"]
    assert set(wl) == {"rules", "paths", "clients"} and set(wl["clients"]) == {"max_rpm", "p95_rpm"}
    assert len(wl["rules"]) <= 100 and len(wl["paths"]) <= 50
    for rid, r in wl["rules"].items():
        assert re.match(r"^[1-9][0-9]{0,6}$", rid)
        assert set(r) == {"hits", "clients", "attack", "paths", "methods"} and len(r["paths"]) <= 10
        assert all(set(c) == {"hits", "clients", "attack"} for c in r["paths"].values())
    for k, p in wl["paths"].items():
        assert re.match(r"^/[^/?]*(/[^/?]+)?$", k) and set(p) == {"req", "max_rpm", "p95_rpm", "p95_rps_min", "methods"}
        assert len(p["methods"]) <= 10 and all(re.match(r"^[A-Z]{1,10}$", m) for m in p["methods"])
    assert wl["paths"]["/s0/t"]["methods"]["OTHER"] > 0                       # bad method names


def test_usage_item_without_learning_unchanged():
    st = {}
    feed(st, [rec("2026-10-02T10:00:00+00:00", "/?a", v="block:waf:942100")])
    it = agent.usage_items(st["pending"])[0]
    assert "waf_learn" not in it and not st.get("waf_learn_win")


# ----------------------------------------------------------------- real nginx

E2E = shutil.which("nginx") is not None and modules_available()


class Origin:
    def __init__(self):
        me = self
        self.hits = 0

        class H(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _ok(self):
                me.hits += 1
                n = int(self.headers.get("Content-Length") or 0)
                if n:
                    self.rfile.read(n)
                body = f"origin {self.path}".encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_GET = do_POST = _ok

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


def req(port, host, path="/", method="GET", body=None, headers=None):
    h = {"Host": host, "User-Agent": "pytest", "Connection": "close"}
    h.update(headers or {})
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=20)
    try:
        c.request(method, path, body=body, headers=h)
        r = c.getresponse()
        return r.status, r.read()
    finally:
        c.close()


def wait_for(fn, timeout=15.0):
    end = time.time() + timeout
    while time.time() < end:
        try:
            if fn():
                return True
        except (OSError, http.client.HTTPException):
            pass
        time.sleep(0.2)
    return False


@pytest.fixture(scope="module")
def edge(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("waflearn")
    o = Origin()
    cfg = dict(agent.DEFAULTS, ORIGIN_PRIVATE_ALLOW=TEST_ORIGIN_ALLOW)
    cfg.update({
        "NGINX_DIR": str(tmp / "pcdn"), "CACHE_DIR": str(tmp / "cache"), "STATE_FILE": str(tmp / "state.json"),
        "ACCESS_LOG": str(tmp / "access.log"), "L4_ACCESS_LOG": str(tmp / "l4.log"),
        "FN_USAGE_LOG": str(tmp / "fn-usage.log"), "PAGES_DIR": str(HERE.parent / "pages"),
        "NJS_FILE": str(HERE.parent / "njs/pcdn.js"), "BASE_TEMPLATE": str(HERE.parent / "nginx/pcdn-base.conf"),
        "GEOIP_DB": str(tmp / "missing.mmdb"), "RESOLVER": "127.0.0.1", "NGINX_USER": "root", "LISTEN_IPV6": "no",
        "HTTP_PORT": str(pick_port()), "HTTPS_PORT": str(pick_port()), "RESIZE_PORT": str(pick_port()),
        "IMAGE_PORT": str(pick_port()), "STORAGE_FETCH_PORT": str(pick_port()), "DICT_SIZE": "4m", "IMAGED": "no",
    })
    conf = nginx_conf(tmp, cfg)
    A = {"address": "127.0.0.1", "port": o.port}
    groups = ["sqli", "xss", "lfi", "rce", "php", "scanner", "protocol"]
    waf = {"mode": "block", "paranoia": 1, "groups": groups, "packs": ["api"]}
    fw = {"default_action": "allow", "rules": [
        {"id": "fwblk", "action": "block", "conditions": [{"field": "path", "op": "starts_with", "value": "/fwblock"}]}]}

    def site(sid, host, **sections):
        s = {"id": sid, "domain": host, "status": "active", "secret": "6f" * 32, "ssl": None, "rate_limit_rps": 0,
             "blocked_ips": [], "hosts": [{"name": host, "origin": A}],
             "cache": {"enabled": False, "level": "standard", "edge_ttl": 3600, "browser_ttl": 0,
                       "ignore_query": False, "bypass_cookies": [], "always_online": True}}
        s.update(sections)
        return s
    sites = [site(301, "learn.test", waf=dict(waf, learning={"enabled": True, "until": FUTURE}), firewall=fw),
             site(302, "block.test", waf=waf, firewall=fw),
             site(303, "learnoff.test", waf=dict(waf, mode="off", learning={"enabled": True, "until": FUTURE})),
             site(304, "expired.test", waf=dict(waf, learning={"enabled": True, "until": PAST}))]
    agent.bootstrap(cfg)
    p = subprocess.run(["nginx", "-c", str(conf)], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    port = int(cfg["HTTP_PORT"])
    try:
        assert wait_for(lambda: req(port, "unknown.test", "/__pcdn/health")[0] == 200)
        cfg["NGINX_TEST_CMD"] = f"nginx -t -q -c {conf}"
        cfg["NGINX_RELOAD_CMD"] = f"nginx -s reload -c {conf}"
        err = agent.apply_config({"sites": sites}, cfg)
        assert err is None, err
        assert wait_for(lambda: req(port, "learn.test", "/ok")[0] == 200), (tmp / "error.log").read_text()[-3000:]
        yield port, cfg, sites, o
    finally:
        subprocess.run(["nginx", "-s", "stop", "-c", str(conf)], capture_output=True)
        o.stop()


def log_lines(cfg, marker):
    try:
        lines = pathlib.Path(cfg["ACCESS_LOG"]).read_text().splitlines()
    except FileNotFoundError:
        return []
    return [json.loads(x) for x in lines if marker in x]


@pytest.mark.skipif(not E2E, reason="nginx with njs/geoip2/image_filter/brotli modules not installed")
def test_e2e_learning_site_logs_instead_of_blocking(edge):
    port, cfg, sites, _ = edge
    js = (pathlib.Path(cfg["NGINX_DIR"]) / "js/sites.js").read_text()
    assert js.count('"learn_until"') == 3   # learn, learnoff, expired (njs compares the clock)
    attack = SQLI + "&m=L1"
    assert req(port, "learn.test", attack)[0] == 200
    assert req(port, "block.test", attack)[0] == 403
    assert req(port, "learnoff.test", attack)[0] == 200
    assert req(port, "expired.test", attack)[0] == 403
    assert req(port, "learn.test", "/fwblock" + attack[1:])[0] == 403          # firewall untouched
    j = {"Content-Type": "application/json"}
    proto = b'{"__proto__": {"polluted": 1}, "m": "L1"}'
    assert req(port, "learn.test", "/api/v1/items?m=L1", "POST", proto, j)[0] == 200
    assert req(port, "block.test", "/api/v1/items?m=L1", "POST", proto, j)[0] == 403
    assert req(port, "learnoff.test", "/api/v1/items?m=L1", "POST", proto, j)[0] == 200
    for i in range(3):
        assert req(port, "learn.test", f"/shop/cart/{i}?m=L1")[0] == 200
    assert wait_for(lambda: len(log_lines(cfg, "m=L1")) >= 11), [(e["h"], e["u"], e["v"]) for e in log_lines(cfg, "m=L1")]
    by = {(e["h"], e["u"]): e["v"] for e in log_lines(cfg, "m=L1")}
    assert by[("learn.test", attack)] == "log:waf:942100"
    assert by[("block.test", attack)] == "block:waf:942100"
    assert by[("learnoff.test", attack)] == "log:waf:942100"
    assert by[("expired.test", attack)] == "block:waf:942100"
    assert by[("learn.test", "/fwblock" + attack[1:])] == "block:firewall:fwblk"
    assert by[("learn.test", "/api/v1/items?m=L1")] == "log:waf:995220"
    assert by[("learnoff.test", "/api/v1/items?m=L1")] == "log:waf:995220"
    assert by[("block.test", "/api/v1/items?m=L1")] == "block:waf:995220"

    # the agent's usage pass: waf_learn only for the learning hosts
    st = {"learn_hosts": agent.learn_hosts({"sites": sites})}
    assert set(st["learn_hosts"]["exact"]) == {"learn.test", "learnoff.test"}
    agent.read_usage(st, cfg["ACCESS_LOG"])
    agent.learn_flush(st)
    its = agent.usage_items(st["pending"], st.get("waf_learn_hour"))
    learn = [it for it in its if it["host"] == "learn.test"]
    assert all("waf_learn" not in it for it in its if it["host"] in ("block.test", "expired.test"))
    rules, paths, mx = {}, {}, 0
    for it in learn:
        wl = it["waf_learn"]
        for k, r in wl["rules"].items():
            rules[k] = rules.get(k, 0) + r["hits"]
        for k, p in wl["paths"].items():
            paths[k] = paths.get(k, 0) + p["req"]
        mx = max(mx, wl["clients"]["max_rpm"])
    assert rules.get("942100", 0) >= 1 and rules.get("995220", 0) >= 1
    assert any(it["waf_learn"]["rules"].get("942100", {}).get("clients") == 1 for it in learn), [it["waf_learn"] for it in learn]
    assert paths.get("/shop/cart", 0) >= 3 and paths.get("/api/v1", 0) >= 1
    assert mx >= 3   # three requests to /shop/cart from one client in (almost certainly) one minute
    assert max(p["max_rpm"] for it in learn for k, p in it["waf_learn"]["paths"].items() if k == "/shop/cart") >= 1
    json.dumps(its)
