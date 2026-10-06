"""SPEC §18.1 waiting room, §18.2 access apps and §18.4 errors_last_hour, edge side.

* validation (norm_waiting_room / norm_access): SPEC limits, invalid sections skipped with a log, an
  access app that cannot be validated stays protected (IP ranges only);
* rendering: sites.js / site config / http.conf / edge-auth.conf (0600) only for sites using them;
* njs (node harness): queue / FIFO admission / bypass, OTP parity with the controller formula,
  safe `next`;
* usage `waiting_room`, `access`, `access_events`; heartbeat `waiting_room` and `errors_last_hour`;
* real nginx: queue page over node_max, admission once a slot frees, bypass; access login redirect,
  one-time code sign-in (cookie, X-PCDN-Access-Email), wrong code, lockout, IP allow, header
  stripping, open-redirect attempts, the controller hop with the edge token.
"""

import hashlib
import hmac
import http.client
import http.server
import importlib.util
import json
import logging
import os
import pathlib
import re
import shutil
import stat
import subprocess
import threading
import time
import urllib.parse

import pytest

from conftest import TEST_ORIGIN_ALLOW, modules_available, nginx_conf, pick_port
from test_njs_logic import build as js_build, site as js_site

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("agent_gates_w10", HERE.parent / "pcdn-agent.py")
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)

NODE = shutil.which("node") is not None
E2E = shutil.which("nginx") is not None and modules_available()
SECRET = "a1" * 32
WR_SECRET = "5e" * 32


def ref_otp(secret_hex, app, email, window):
    """The controller's formula (RFC 4226 dynamic truncation over HMAC-SHA256), written out
    independently of the agent."""
    d = hmac.new(bytes.fromhex(secret_hex), f"otp|{app}|{email.strip().lower()}|{window}".encode(), hashlib.sha256).digest()
    off = d[31] & 0x0F
    b = ((d[off] & 0x7F) << 24) | (d[off + 1] << 16) | (d[off + 2] << 8) | d[off + 3]
    return "%06d" % (b % 1000000)


# the controller's published test vectors
VEC_SECRET = bytes(range(32)).hex()
OTP_VECTORS = [(VEC_SECRET, "admin", "alice@example.com", 5000000, "412921"),
               (VEC_SECRET, "admin", "Alice@Example.com", 5000000, "412921"),
               (VEC_SECRET, "admin", "alice@example.com", 4999999, "512275"),
               (VEC_SECRET, "wiki", "bob@company.com", 5872320, "291143"),
               (VEC_SECRET, "a", "x@y.io", 0, "921788"),
               ("ff" * 32, "admin", "alice@example.com", 5000000, "900693")]


def ehash(email, secret=SECRET):
    return hmac.new(bytes.fromhex(secret), ("email|" + email.lower()).encode(), hashlib.sha256).hexdigest()[:16]


def wr_site(**w):
    base = {"enabled": True, "mode": "queue", "paths": ["/"], "max_active": 100, "node_max": 50, "session_minutes": 10,
            "queue_page": {"title_fa": "صف", "title_en": "Queue", "message_fa": "<b>صبر</b>", "message_en": "Wait\x00 please"},
            "bypass": {"verified_bots": True, "paths": ["/api/"], "ips": ["10.0.0.0/8"]}}
    base.update(w)
    base.setdefault("secret", WR_SECRET)
    return {"id": 7, "domain": "w.test", "waiting_room": base}


def acc_site(apps, secret=SECRET, **kw):
    s = {"id": 8, "domain": "a.test", "access": {"enabled": True, "apps": apps, "secret": secret}}
    s.update(kw)
    return s


APP = {"id": "admin", "name": "Admin <panel>", "paths": ["/admin"], "methods": "otp_or_ip",
       "emails": ["Alice@Example.com", "@corp.test"], "ips": ["10.9.9.0/24"], "session_hours": 2}


# ----------------------------------------------------------------- validation

def test_norm_waiting_room(caplog):
    n = agent.norm_waiting_room
    w = n(wr_site())
    assert w == {"paths": ["/"], "max": 50, "session_s": 600, "secret": WR_SECRET,
                 "page": {"title_fa": "صف", "title_en": "Queue", "message_fa": "<b>صبر</b>", "message_en": "Wait  please"},
                 "bypass": {"bots": True, "paths": ["/api/"], "ips": ["10.0.0.0/8"]}}
    assert n({}) is None and n(wr_site(enabled=False)) is None and n(wr_site(mode="off")) is None
    s = wr_site()
    del s["waiting_room"]["node_max"]
    assert n(s)["max"] == 100                               # falls back to max_active
    caplog.set_level(logging.WARNING, logger="pcdn-agent")
    for bad in (dict(node_max=0), dict(node_max=1_000_001), dict(node_max="5"), dict(session_minutes=121),
                dict(session_minutes=0), dict(paths=["/"] * 21), dict(paths="/"), dict(paths=["no-slash"]),
                dict(bypass={"ips": ["10.0.0.0/8"] * 51}), dict(bypass={"paths": ["/x"] * 21})):
        assert n(wr_site(**bad)) is None, bad
    assert n(wr_site(secret="short")) is None
    assert n(wr_site(secret="")) is None
    assert "waiting room skipped" in caplog.text
    # /__pcdn/ paths are never covered; duplicates and dot segments dropped; percent-decoded
    w = n(wr_site(paths=["/shop", "/shop", "/__pcdn/x", "/a/../b", "/caf%C3%A9"]))
    assert w["paths"] == ["/shop", "/café"]
    w = n(wr_site(queue_page={"title_en": "x" * 900}, bypass={"verified_bots": False}))
    assert len(w["page"]["title_en"]) == 500 and w["bypass"] == {"bots": False, "paths": [], "ips": []}
    # legacy: a site-level wr_secret when the section carries none
    s = wr_site()
    s["wr_secret"] = s["waiting_room"].pop("secret")
    assert n(s)["secret"] == WR_SECRET
    assert n(wr_site(secret=WR_SECRET.upper()))["secret"] == WR_SECRET


def test_norm_access(caplog):
    n = agent.norm_access
    a = n(acc_site([APP]))
    assert a == {"secret": SECRET, "apps": [{"id": "admin", "name": "Admin <panel>", "paths": ["/admin"],
                                             "methods": "otp_or_ip", "emails": ["alice@example.com", "@corp.test"],
                                             "ips": ["10.9.9.0/24"], "session_s": 7200}]}
    assert n({}) is None and n(acc_site([APP], access=None)) is None
    assert n({"id": 1, "access": {"enabled": False, "apps": [APP]}}) is None
    assert n(acc_site([])) is None
    caplog.set_level(logging.WARNING, logger="pcdn-agent")
    # an app that does not validate keeps its paths protected (IP ranges only)
    bad = dict(APP, methods="sms")
    assert n(acc_site([bad]))["apps"][0]["methods"] == "none"
    assert n(acc_site([dict(APP, session_hours=721)]))["apps"][0]["methods"] == "none"
    assert n(acc_site([dict(APP, id="Bad Id!")]))["apps"][0] == dict(
        n(acc_site([APP]))["apps"][0], id="app0", methods="none")
    # enabled without a usable secret: fail closed (every app denies everyone, IP ranges included)
    for sec in ("", "zz"):
        for app in (APP, dict(APP, methods="ip"), dict(APP, methods="otp")):
            got = n(acc_site([app], secret=sec))
            assert got["secret"] == "" and got["apps"][0]["methods"] == "none" and got["apps"][0]["ips"] == []
    # overlapping paths of a later app are dropped; an app without paths is skipped
    two = n(acc_site([APP, dict(APP, id="b", paths=["/admin/x", "/b"]), dict(APP, id="c", paths=["/__pcdn/x"])]))
    assert [(x["id"], x["paths"]) for x in two["apps"]] == [("admin", ["/admin"]), ("b", ["/b"])]
    # limits: emails / ips / apps truncated, bad entries skipped
    many = n(acc_site([dict(APP, emails=["u%d@x.test" % i for i in range(250)] + ["bad"], ips=["10.0.0.%d" % i for i in range(150)])]))
    assert len(many["apps"][0]["emails"]) == 200 and len(many["apps"][0]["ips"]) == 100
    apps = [dict(APP, id=f"a{i}", paths=[f"/p{i}/"]) for i in range(25)]
    assert len(n(acc_site(apps))["apps"]) == 20
    assert "overlaps another app" in caplog.text


def test_otp_parity_with_controller_formula():
    for sec, app, email, w, code in OTP_VECTORS:
        assert agent.access_otp(sec, app, email, w) == code == ref_otp(sec, app, email, w)
    for w in (0, 1, 5_900_000, 6_000_123):
        for email in ("alice@example.com", " Bob@Corp.Test "):
            assert agent.access_otp(SECRET, "admin", email, w) == ref_otp(SECRET, "admin", email, w)
    assert agent.access_email_hash(SECRET, "Alice@Example.com") == ehash("alice@example.com")


def test_gate_sites():
    sites = [wr_site(), acc_site([APP]), dict(wr_site(), id=9, status="suspended"), {"id": 10}]
    assert agent.gate_sites({"sites": sites}) == {"wr": ["w.test"], "access": ["a.test"]}


# ----------------------------------------------------------------- rendering

def test_site_js_only_with_sections():
    plain = agent.site_js({"id": 1, "domain": "x.test"}, ["x.test"], {}, {})
    assert "waiting_room" not in plain and "access" not in plain
    with_wr = agent.site_js(dict(wr_site(), id=1, domain="x.test"), ["x.test"], {}, {})
    assert with_wr["waiting_room"]["max"] == 50
    with_wr.pop("waiting_room")
    assert with_wr == plain
    a = agent.site_js(dict(acc_site([APP]), id=1, domain="x.test"), ["x.test"], {}, {})
    assert a["access"]["apps"][0]["id"] == "admin"


def render_cfg(tmp_path, **over):
    cfg = dict(agent.DEFAULTS, ORIGIN_PRIVATE_ALLOW=TEST_ORIGIN_ALLOW)
    cfg.update({"NGINX_DIR": str(tmp_path / "pcdn"), "CACHE_DIR": str(tmp_path / "cache"),
                "PAGES_DIR": str(HERE.parent / "pages"), "NJS_FILE": str(HERE.parent / "njs/pcdn.js"),
                "BASE_TEMPLATE": str(HERE.parent / "nginx/pcdn-base.conf"), "GEOIP_DB": str(tmp_path / "x.mmdb"),
                "CONTROLLER_URL": "https://ctl.example.test:8443/", "EDGE_TOKEN": "tok_ABC123.xyz"})
    cfg.update(over)
    return cfg


def full_site(sid, host, **sections):
    s = {"id": sid, "domain": host, "status": "active", "secret": "6f" * 32, "ssl": None, "rate_limit_rps": 0,
         "blocked_ips": [], "hosts": [{"name": host, "origin": {"address": "127.0.0.1", "port": 9}}],
         "cache": {"enabled": True, "level": "standard", "edge_ttl": 3600, "browser_ttl": 0, "ignore_query": False,
                   "bypass_cookies": [], "always_online": True}}
    s.update(sections)
    return s


@pytest.mark.skipif(not modules_available(), reason="nginx modules not installed")
def test_render_tree_gates(tmp_path):
    cfg = render_cfg(tmp_path)
    plain = full_site(1, "p.test")
    base, _ = agent.render_tree({"sites": [plain]}, cfg)
    assert "edge-auth.conf" not in base and "pcdn_wr" not in base["http.conf"] and "acc_email" not in base["http.conf"]
    w = dict(full_site(2, "w.test"), **{k: v for k, v in wr_site().items() if k not in ("id", "domain")})
    a = dict(full_site(3, "a.test"), **{k: v for k, v in acc_site([APP]).items() if k not in ("id", "domain")})
    files, _ = agent.render_tree({"sites": [plain, w, a]}, cfg)
    assert files["sites/1.conf"] == base["sites/1.conf"]   # a site without the sections is unchanged
    http = files["http.conf"]
    nodig = lambda x: re.sub(r'[0-9a-f]{64}', "", x)   # noqa: E731 - the tree digest
    gate_block = http[len(http.rstrip("\n").rsplit("\n\n", 1)[0]):]
    assert "visitor gates" in gate_block and nodig(http[:-len(gate_block)]) + "\n" == nodig(base["http.conf"])
    assert "js_shared_dict_zone zone=pcdn_wr:48m type=number timeout=10800s evict;" in http
    assert "js_var $pcdn_wrc;" in http and "js_set $pcdn_acc_email pcdn.accessEmail;" in http
    wc, ac = files["sites/2.conf"], files["sites/3.conf"]
    assert "add_header Set-Cookie $pcdn_wrc always;" in wc and "pcdn_acc_email" not in wc
    assert "proxy_set_header X-PCDN-Access-Email $pcdn_acc_email;" in ac
    assert "proxy_cache_bypass $pcdn_acc_email;" in ac and "$pcdn_acc_email;" in ac
    assert "location = /__pcdn/access/verify" in ac and "js_content pcdn.accessSend;" in ac
    assert f"include {cfg['NGINX_DIR']}/edge-auth.conf;" in ac
    assert 'set $pcdn_ctl_otp "https://ctl.example.test:8443/edge/v1/access/otp";' in ac
    assert 'proxy_ssl_name "ctl.example.test";' in ac
    assert files["edge-auth.conf"].endswith('proxy_set_header Authorization "Bearer tok_ABC123.xyz";\n')
    js = json.loads(files["js/sites.js"].split("export default ", 1)[1].rstrip().rstrip(";"))
    assert "wr_secret" not in files["js/sites.js"]
    assert js["2"]["waiting_room"]["max"] == 50 and js["3"]["access"]["secret"] == SECRET
    # an access section that is present but disabled: the visitor's header is still stripped
    off = dict(full_site(4, "o.test"), access={"enabled": False, "apps": []})
    files, _ = agent.render_tree({"sites": [off]}, cfg)
    assert 'proxy_set_header X-PCDN-Access-Email "";' in files["sites/4.conf"]
    assert "edge-auth.conf" not in files
    # a token that is not a plain token is never written; a bad controller URL -> 503 location
    cfg2 = render_cfg(tmp_path, EDGE_TOKEN='x"; evil', CONTROLLER_URL="ftp://x")
    files, _ = agent.render_tree({"sites": [a]}, cfg2)
    assert "Authorization" not in files["edge-auth.conf"] and "evil" not in files["edge-auth.conf"]
    assert "location = /__pcdn/access/otp { internal; return 503; }" in files["sites/3.conf"]
    # 0600 when written
    agent.write_tree(str(tmp_path / "tree"), {"edge-auth.conf": "x", "sites/1.conf": "y"})
    assert stat.S_IMODE(os.stat(tmp_path / "tree/edge-auth.conf").st_mode) == 0o600
    assert stat.S_IMODE(os.stat(tmp_path / "tree/sites/1.conf").st_mode) == 0o644


# ----------------------------------------------------------------- usage / heartbeat

def rec(v, t="2026-10-02T10:05:00+00:00", host="g.test", s=200, **kw):
    e = {"t": t, "h": host, "b": 10, "s": s, "c": "", "ip": "10.0.0.1", "cc": "", "m": "GET", "u": "/", "ua": "x",
         "v": v, "tn": "", "us": "", "rt": 0.001, "bu": 10}
    e.update(kw)
    return e


def test_usage_gate_counters():
    pending, events = {}, []
    eh = ehash("alice@example.com")
    for v in ("ok:wr:a:3:0", "ok:wr:a:7:42", "ok:wr:t:9", "wr:qn:1:9", "wr:qn:2:9", "wr:q:1:10", "ok", "log:waf:1",
              f"ok:acc:ok:admin:{eh}", f"ok:acc:fail:admin:{eh}", "ok:acc:fail:-:-", f"ok:acc:otp:admin:{eh}",
              "acc:login:admin", "acc:deny:admin", "ok:acc:locked:admin:-", "ok:acc:limited:-", "ok:wr:a:1:99999999"):
        agent._account(rec(v), pending, events)
    agent._account(rec("wr:q:1:2", s=503), pending, events)
    it = agent.usage_items(pending)[0]
    assert it["waiting_room"] == {"admitted": 3, "queued": 2, "max_wait_s": 7 * 86400, "peak_active": 10}
    assert it["access"] == {"ok": 1, "fail": 2, "otp": 1}
    assert it["access_events"] == [{"t": "2026-10-02T10:05:00Z", "app": "admin", "email_hash": eh, "ok": True},
                                   {"t": "2026-10-02T10:05:00Z", "app": "admin", "email_hash": eh, "ok": False}]
    assert it["platform_errors"] == 0                       # a queued API call's 503 is not a platform error
    assert it["security"] == {"waf": 1}
    # bounded event list
    pending = {}
    for _ in range(80):
        agent._account(rec(f"ok:acc:fail:admin:{eh}"), pending, events)
    it = agent.usage_items(pending)[0]
    assert it["access"]["fail"] == 80 and len(it["access_events"]) == 50
    # items without gate verdicts carry no gate keys
    pending = {}
    agent._account(rec("ok"), pending, events)
    assert not {"waiting_room", "access", "access_events"} & set(agent.usage_items(pending)[0])


def test_gate_hour_to_date_maxima():
    st = {}
    p1 = {}
    agent._account(rec("ok:wr:a:9:30"), p1, [])
    agent._account(rec("ok:wr:a:2:5", t="2026-10-02T11:00:00+00:00"), p1, [])
    agent.gate_hour_merge(st, p1)
    p2 = {}
    agent._account(rec("ok:wr:a:3:4"), p2, [])
    agent.gate_hour_merge(st, p2)
    it = agent.usage_items(p2)[0]
    assert it["waiting_room"] == {"admitted": 1, "queued": 0, "max_wait_s": 30, "peak_active": 9}
    assert set(st["wr_hour"]) == {"g.test|2026-10-02T10:00:00Z", "g.test|2026-10-02T11:00:00Z"}
    p3 = {}
    agent._account(rec("ok:wr:a:1:1", t="2026-10-02T15:00:00+00:00"), p3, [])
    agent.gate_hour_merge(st, p3)
    assert set(st["wr_hour"]) == {"g.test|2026-10-02T15:00:00Z"}     # older than 3 h: dropped


def test_heartbeat_waiting_room_and_errors():
    raw = json.dumps({"w.test": {"active": 3, "queued": -2}, "v.test": {"active": "x"}, "z.test": {"active": 1}}).encode()
    assert agent.wr_heartbeat(raw, ["w.test", "v.test"]) == {"w.test": {"active": 3, "queued": 0},
                                                             "v.test": {"active": 0, "queued": 0}}
    assert agent.wr_heartbeat(b"not json", [7]) == {}
    big = json.dumps({f"s{i}.test": {"active": 1, "queued": 0} for i in range(1200)}).encode()
    assert len(agent.wr_heartbeat(big, [f"s{i}.test" for i in range(1200)])) == agent.HB_WR_SITES_MAX == 1000
    c = agent.ErrorCounter(cap=5)
    lg = logging.getLogger("pcdn-gates-test")
    lg.addHandler(c)
    lg.propagate = False
    try:
        lg.warning("not counted")
        for _ in range(3):
            lg.error("boom")
        try:
            raise ValueError("x")
        except ValueError:
            lg.exception("exc")
    finally:
        lg.removeHandler(c)
    assert c.last_hour() == 4
    assert c.last_hour(now=time.time() + 3601) == 0
    for _ in range(10):
        c.times.append(time.time())
    assert c.last_hour() == 5                                 # bounded


def test_hb_carries_errors_last_hour(monkeypatch):
    a = agent.Agent.__new__(agent.Agent)
    a.cfg = dict(agent.DEFAULTS)
    monkeypatch.setattr(agent.AGENT_ERRORS, "times", __import__("collections").deque([time.time()] * 2, maxlen=10))
    body = a._hb(applied_version="v1")
    assert body["errors_last_hour"] == 2


# ----------------------------------------------------------------- njs logic (node)

HARNESS = r"""
import m from './pcdn.mjs';
import { T } from './pcdn.mjs';
const stores = {};
function mk(name) {
  const st = stores[name] = {};
  return { get: k => st[k], set: (k, v) => { st[k] = v; }, incr: (k, d, i) => (st[k] = (st[k] === undefined ? (i || 0) : st[k]) + d),
    delete: k => { delete st[k]; } };
}
globalThis.ngx = { shared: { pcdn_cnt: mk('cnt'), pcdn_blk: mk('blk'), pcdn_hc: mk('hc'), pcdn_fair: mk('fair'), pcdn_wr: mk('wr') } };
let clock = Date.now();
Date.now = () => clock;
function req(c) {
  const vars = Object.assign({ pcdn_site: c.site, remote_addr: c.ip || '127.0.0.1', request_uri: c.uri, args: '', host: 'x.test',
    pcdn_country: 'IR', ssl_protocol: '', scheme: 'https', pcdn_vbot: c.vbot || '' }, c.vars || {});
  const hin = Object.assign({ 'User-Agent': 'Mozilla/5.0', Accept: 'text/html' }, c.headers || {});
  if (c.cookie) hin.Cookie = c.cookie;
  return { uri: c.uri, method: c.method || 'GET', variables: vars, headersIn: hin, headersOut: {}, args: {},
    error: () => {}, log: () => {} };
}
const cookies = {};
const cases = JSON.parse(process.argv[2]);
const out = cases.map(c => {
  if (c.kind === 'advance') { clock += c.s * 1000; return null; }
  if (c.kind === 'v') {   // a visitor's request: verdict + cookie jar per visitor name
    const r = req(Object.assign({}, c, { cookie: c.who && cookies[c.who] ? cookies[c.who] : c.cookie }));
    const v = m.verdict(r);
    if (c.who && r.variables.pcdn_wrc) cookies[c.who] = r.variables.pcdn_wrc.split(';')[0];
    return v;
  }
  if (c.kind === 'otp') return T.otpCode(Buffer.from(c.secret, 'hex'), c.app, c.email, c.win);
  if (c.kind === 'ehash') return T.emailHash(T.S[c.site].access, c.email);
  if (c.kind === 'next') return c.values.map(T.safeNext);
  if (c.kind === 'stats') return T.wrStats();
  if (c.kind === 'email') return m.accessEmail(req(c));
  if (c.kind === 'cookie') return T.accCookie(c.site, c.app, c.email, c.exp);
});
console.log(JSON.stringify(out));
"""


def js_run(tmp_path, sites, cases):
    js_build(tmp_path, sites)
    src = (tmp_path / "pcdn.mjs").read_text()
    src += ("\nT.otpCode = otpCode; T.safeNext = safeNext; T.wrStats = wrStats; T.emailHash = emailHash; T.S = S;\n"
            "T.accCookie = function (sid, app, email, exp) { const A = S[sid].access;"
            " const b = Buffer.from(app + '|' + email + '|' + exp).toString('base64url'); return b + '.' + accSig(A, b); };\n")
    (tmp_path / "pcdn.mjs").write_text(src)
    (tmp_path / "h.mjs").write_text(HARNESS)
    p = subprocess.run(["node", str(tmp_path / "h.mjs"), json.dumps(cases)], capture_output=True, text=True, cwd=tmp_path)
    assert p.returncode == 0, p.stderr
    return json.loads(p.stdout)


def js_wr(**kw):
    w = agent.norm_waiting_room(wr_site(**kw))
    return js_site(domain="w.test", waiting_room=w)


@pytest.mark.skipif(not NODE, reason="node not installed")
def test_njs_waiting_room_queue_and_fifo(tmp_path):
    sites = {"1": js_wr(node_max=2, session_minutes=1)}
    V = lambda who, **kw: dict({"kind": "v", "site": "1", "uri": "/page", "who": who}, **kw)   # noqa: E731
    res = js_run(tmp_path, sites, [
        {"kind": "advance", "s": 60 - (time.time() % 60) + 1},        # start of a minute
        V("a"), V("b"), V("a"),                                       # two admitted, a returns in the same minute
        V("c"), V("d"), V("c"),                                       # c / d queued (tickets 1 / 2), c polls
        V("x", uri="/api/v1"), V("x", ip="10.1.2.3"), V("x", vbot="1gb", headers={"User-Agent": "Googlebot/2.1"}),
        V("y", uri="/__pcdn/verify"),
        {"kind": "stats"},
        {"kind": "advance", "s": 60},                                 # a / b idle for a minute: expired
        V("d"), V("c"), V("d"), V("e"), V("f"),                       # FIFO: d waits behind c, then both in
        {"kind": "stats"},
    ])
    assert res[1].startswith("ok:wr:a:1:") and res[2].startswith("ok:wr:a:2:") and res[3] == "ok"
    assert res[4] == "wr:qn:1:2" and res[5] == "wr:qn:2:2" and res[6] == "wr:q:1:2"
    assert res[7:11] == ["ok", "ok", "ok", "ok"]                     # bypass path / IP / verified bot, /__pcdn/
    assert res[11] == {"w.test": {"active": 2, "queued": 2}}
    # new minute: free = 2; d (ticket 2) is within the first 2 tickets after the last admitted one
    assert res[13].startswith("ok:wr:a:1:") and res[14].startswith("ok:wr:a:2:")
    assert res[15] == "ok"                                            # d holds a session now
    assert res[16] == "wr:qn:1:2" and res[17] == "wr:qn:2:2"         # full again: e / f queue
    assert res[18] == {"w.test": {"active": 2, "queued": 2}}


@pytest.mark.skipif(not NODE, reason="node not installed")
def test_njs_waiting_room_skips_abandoned_tickets_and_forged_cookies(tmp_path):
    sites = {"1": js_wr(node_max=1, session_minutes=1)}
    V = lambda who, **kw: dict({"kind": "v", "site": "1", "uri": "/", "who": who}, **kw)   # noqa: E731
    res = js_run(tmp_path, sites, [
        {"kind": "advance", "s": 60 - (time.time() % 60) + 1},
        V("a"), V("gone"), V("c"),                                    # a in, ticket 1 (abandons), ticket 2
        {"kind": "advance", "s": 60},                                 # a expired: one slot free
        V("c"),                                                       # c is 2nd: ticket 1 holds the slot ...
        {"kind": "advance", "s": 50},                                 # ... until nobody claims it for 45 s
        V("c"),
        V("z", cookie="__pcdn_wr=0123456789abcdef.0.1.1.a." + "0" * 64),   # forged: a new visitor
    ])
    assert res[1].startswith("ok:wr:a:") and res[2] == "wr:qn:1:1" and res[3] == "wr:qn:2:1"
    assert res[5] == "wr:q:2:0" and res[7].startswith("ok:wr:a:1:")
    assert res[8] == "wr:qn:1:1"


@pytest.mark.skipif(not NODE, reason="node not installed")
def test_njs_access_gate_otp_and_next(tmp_path):
    acc = agent.norm_access(acc_site([APP, {"id": "lab", "paths": ["/lab"], "methods": "ip", "ips": ["127.0.0.1/32"]},
                                      {"id": "closed", "paths": ["/closed"], "methods": "ip", "ips": ["10.1.0.0/16"]}]))
    sites = {"1": js_site(domain="a.test", access=acc)}
    exp = int(time.time()) + 3600
    win = int(time.time()) // 300
    cases = [{"kind": "otp", "secret": SECRET, "app": "admin", "email": e, "win": w}
             for e in ("alice@example.com", "x@corp.test") for w in (win, 5_900_000)]
    cases += [{"kind": "otp", "secret": v[0], "app": v[1], "email": v[2].lower(), "win": v[3]} for v in OTP_VECTORS]
    cases += [{"kind": "ehash", "site": "1", "email": "alice@example.com"}]
    cases += [
        {"kind": "v", "site": "1", "uri": "/admin/x"},
        {"kind": "v", "site": "1", "uri": "/ADMIN/x"},                               # case-insensitive
        {"kind": "v", "site": "1", "uri": "/admin/x", "ip": "10.9.9.7"},             # IP allowed
        {"kind": "v", "site": "1", "uri": "/lab/1"}, {"kind": "v", "site": "1", "uri": "/closed"},
        {"kind": "v", "site": "1", "uri": "/public"},
        {"kind": "cookie", "site": "1", "app": "admin", "email": "alice@example.com", "exp": exp},
        {"kind": "next", "values": ["/a?b=1", "//evil.com", "https://evil.com", "/\\evil.com", "\\\\evil.com", "/\tx",
                                    "/a b", "", None, "/__pcdn/access/login", "javascript:alert(1)", "/ok#f", "/é"]},
    ]
    res = js_run(tmp_path, sites, cases)
    assert res[:4] == [ref_otp(SECRET, "admin", e, w) for e in ("alice@example.com", "x@corp.test") for w in (win, 5_900_000)]
    assert res[4:10] == [v[4] for v in OTP_VECTORS]
    assert res[10] == ehash("alice@example.com")
    res = res[7:]
    assert res[4:10] == ["acc:login:admin", "acc:login:admin", "ok", "ok", "acc:deny:closed", "ok"]
    ck = res[10]
    assert res[11] == ["/a?b=1", "/", "/", "/", "/", "/", "/", "/", "/", "/", "/", "/ok#f", "/"]
    res = js_run(tmp_path, sites, [
        {"kind": "v", "site": "1", "uri": "/admin/x", "cookie": "__pcdn_access_admin=" + ck},
        {"kind": "email", "site": "1", "uri": "/admin/x", "cookie": "__pcdn_access_admin=" + ck},
        {"kind": "email", "site": "1", "uri": "/__pcdn/img/admin/x.png", "cookie": "__pcdn_access_admin=" + ck},
        {"kind": "email", "site": "1", "uri": "/public", "cookie": "__pcdn_access_admin=" + ck},
        {"kind": "v", "site": "1", "uri": "/admin/x", "cookie": "__pcdn_access_admin=" + ck[:-1] + ("0" if ck[-1] != "0" else "1")},
        {"kind": "v", "site": "1", "uri": "/lab", "cookie": "__pcdn_access_lab=" + ck},
    ])
    assert res == ["ok", "alice@example.com", "alice@example.com", "", "acc:login:admin", "ok"]


# ----------------------------------------------------------------- real nginx

class Origin:
    def __init__(self):
        me = self
        self.seen = []

        class H(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _ok(self):
                n = int(self.headers.get("Content-Length") or 0)
                body_in = self.rfile.read(n) if n else b""
                me.seen.append((self.command, self.path, dict(self.headers), body_in))
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
        return r.status, {k.lower(): v for k, v in r.getheaders()}, r.read(), r.msg.get_all("Set-Cookie") or []
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


HTML = {"Accept": "text/html,application/xhtml+xml"}
FORM = {"Content-Type": "application/x-www-form-urlencoded"}


@pytest.fixture(scope="module")
def edge(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("gates")
    o, ctl = Origin(), Origin()
    cfg = dict(agent.DEFAULTS, ORIGIN_PRIVATE_ALLOW=TEST_ORIGIN_ALLOW)
    cfg.update({
        "NGINX_DIR": str(tmp / "pcdn"), "CACHE_DIR": str(tmp / "cache"), "STATE_FILE": str(tmp / "state.json"),
        "ACCESS_LOG": str(tmp / "access.log"), "L4_ACCESS_LOG": str(tmp / "l4.log"),
        "FN_USAGE_LOG": str(tmp / "fn-usage.log"), "PAGES_DIR": str(HERE.parent / "pages"),
        "NJS_FILE": str(HERE.parent / "njs/pcdn.js"), "BASE_TEMPLATE": str(HERE.parent / "nginx/pcdn-base.conf"),
        "GEOIP_DB": str(tmp / "missing.mmdb"), "RESOLVER": "127.0.0.1", "NGINX_USER": "root", "LISTEN_IPV6": "no",
        "HTTP_PORT": str(pick_port()), "HTTPS_PORT": str(pick_port()), "RESIZE_PORT": str(pick_port()),
        "IMAGE_PORT": str(pick_port()), "STORAGE_FETCH_PORT": str(pick_port()), "DICT_SIZE": "4m", "IMAGED": "no",
        "WR_DICT_SIZE": "4m", "CONTROLLER_URL": f"http://127.0.0.1:{ctl.port}", "EDGE_TOKEN": "edge-token-0123456789",
    })
    conf = nginx_conf(tmp, cfg)
    A = {"address": "127.0.0.1", "port": o.port}

    def site(sid, host, **sections):
        s = {"id": sid, "domain": host, "status": "active", "secret": "6f" * 32, "ssl": None, "rate_limit_rps": 0,
             "blocked_ips": [], "hosts": [{"name": host, "origin": A}],
             "cache": {"enabled": True, "level": "standard", "edge_ttl": 3600, "browser_ttl": 0,
                       "ignore_query": False, "bypass_cookies": [], "always_online": True}}
        s.update(sections)
        return s

    apps = [APP, {"id": "lab", "name": "Lab", "paths": ["/lab"], "methods": "ip", "ips": ["127.0.0.1/32"]},
            {"id": "closed", "name": "Closed", "paths": ["/closed"], "methods": "ip", "ips": ["10.1.0.0/16"]}]
    wr = dict(wr_site(node_max=2, session_minutes=1)["waiting_room"], bypass={"paths": ["/api/"], "ips": []})
    sites = [site(401, "wr.test", waiting_room=wr),
             site(402, "acc.test", access={"enabled": True, "apps": apps, "secret": SECRET}),
             site(403, "lock.test", access={"enabled": True, "apps": [APP], "secret": SECRET}),
             site(404, "plain.test", access={"enabled": False, "apps": [], "secret": ""}),
             site(405, "wrbypass.test", waiting_room=dict(wr, node_max=1, bypass={"ips": ["127.0.0.0/8"]})),
             site(406, "closed.test", access={"enabled": True, "apps": [APP], "secret": ""})]
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
        assert wait_for(lambda: req(port, "plain.test", "/ok")[0] == 200), (tmp / "error.log").read_text()[-3000:]
        yield port, cfg, sites, o, ctl, tmp
    finally:
        subprocess.run(["nginx", "-s", "stop", "-c", str(conf)], capture_output=True)
        o.stop()
        ctl.stop()


def loc(h, host):
    """The Location of a redirect, which must stay on `host` (nginx makes it absolute): path + query."""
    u = urllib.parse.urlsplit(h["location"])
    assert u.hostname in (None, host), h["location"]
    return u.path + ("?" + u.query if u.query else "")


def jar(cookies):
    return "; ".join(c.split(";")[0] for c in cookies)


def log_lines(cfg):
    try:
        return [json.loads(x) for x in pathlib.Path(cfg["ACCESS_LOG"]).read_text().splitlines()]
    except FileNotFoundError:
        return []


@pytest.mark.skipif(not E2E, reason="nginx with njs/geoip2/image_filter/brotli modules not installed")
def test_e2e_edge_auth_file(edge):
    _, cfg, *_ = edge
    p = pathlib.Path(cfg["NGINX_DIR"]) / "edge-auth.conf"
    st = os.stat(p)
    assert stat.S_IMODE(st.st_mode) == 0o600 and st.st_uid == os.geteuid()
    assert 'proxy_set_header Authorization "Bearer edge-token-0123456789";' in p.read_text()


@pytest.mark.skipif(not E2E, reason="nginx with njs/geoip2/image_filter/brotli modules not installed")
def test_e2e_waiting_room(edge):
    port, cfg, sites, o, *_ = edge
    # start right after a minute boundary so the two sessions stay active while the test runs
    time.sleep((60 - time.time() % 60) + 0.5 if time.time() % 60 > 40 else 0)
    s1, h1, b1, c1 = req(port, "wr.test", "/p1", headers=HTML)
    s2, _, _, c2 = req(port, "wr.test", "/p2", headers=HTML)
    assert s1 == 200 and b1 == b"origin /p1" and s2 == 200
    assert c1 and c1[0].startswith("__pcdn_wr=") and "HttpOnly" in c1[0] and "SameSite=Lax" in c1[0]
    assert req(port, "wr.test", "/p1b", headers=dict(HTML, Cookie=jar(c1)))[0] == 200   # admitted visitor returns
    # the node is full: a third visitor queues
    s3, h3, b3, c3 = req(port, "wr.test", "/p3", headers=dict(HTML, **{"Accept-Language": "en-US,en;q=0.9"}))
    assert s3 == 200 and b"origin" not in b3
    assert h3["cache-control"] == "no-store" and 15 <= int(h3["retry-after"]) <= 30
    m = re.search(rb'<meta http-equiv="refresh" content="(\d+)">', b3)
    assert m and 15 <= int(m.group(1)) <= 30
    assert b"Wait  please" in b3 and b"&lt;b&gt;" in b3 and b"<b>" not in b3       # escaped customer text
    assert b'<html lang="en"' in b3 and b"position in the queue: 1" in b3
    assert "default-src 'none'" in h3["content-security-policy"] and b"<script" not in b3
    assert c3 and c3[0].startswith("__pcdn_wr=")
    # the queued visitor's API call: 503 + Retry-After, JSON
    s, h, b, _ = req(port, "wr.test", "/data.json", headers={"Accept": "application/json", "Cookie": jar(c3)})
    assert s == 503 and int(h["retry-after"]) >= 15 and json.loads(b)["position"] == 1
    s, h, b, _ = req(port, "wr.test", "/p3", headers=dict(HTML, Cookie=jar(c3), **{"X-Requested-With": "XMLHttpRequest"}))
    assert s == 503
    s, _, b, _ = req(port, "wr.test", "/p3", headers=dict(HTML, Cookie=jar(c3)))
    assert s == 200 and "جایگاه".encode() in b and b'<html lang="fa"' in b
    # bypass: path and IP; /__pcdn/ never
    assert req(port, "wr.test", "/api/x", headers=HTML)[:3:2] == (200, b"origin /api/x")
    assert req(port, "wrbypass.test", "/x", headers=HTML)[0] == 200
    assert req(port, "wrbypass.test", "/y", headers=HTML)[0] == 200
    assert req(port, "wr.test", "/__pcdn/health")[0] == 200
    # heartbeat stats through the agent's localhost call
    a = agent.Agent.__new__(agent.Agent)
    a.cfg, a.state = cfg, {"wr_sites": ["wr.test", "wrbypass.test"], "node": agent.norm_node({}, cfg)}
    a.fair_signal({"tx_mbps": 0})
    assert a.wr_stats == {"wr.test": {"active": 2, "queued": 1}, "wrbypass.test": {"active": 0, "queued": 0}}
    # a slot frees: the sessions are idle for session_minutes (1 minute)
    time.sleep(60 - time.time() % 60 + 1)
    s, h, b, c = req(port, "wr.test", "/p3", headers=dict(HTML, Cookie=jar(c3)))
    assert s == 200 and b == b"origin /p3" and c and c[0].startswith("__pcdn_wr=")
    assert req(port, "wr.test", "/p3/next", headers=dict(HTML, Cookie=jar(c)))[0] == 200
    # usage
    assert wait_for(lambda: any(e["h"] == "wr.test" and e["u"] == "/p3/next" for e in log_lines(cfg)))
    st = {}
    agent.read_usage(st, cfg["ACCESS_LOG"])
    wr_items = [it for it in agent.usage_items(st["pending"]) if it["host"] == "wr.test"]
    tot = {k: sum(it.get("waiting_room", {}).get(k, 0) for it in wr_items) for k in ("admitted", "queued")}
    assert tot == {"admitted": 3, "queued": 1}
    assert max(it.get("waiting_room", {}).get("max_wait_s", 0) for it in wr_items) >= 20
    assert max(it.get("waiting_room", {}).get("peak_active", 0) for it in wr_items) == 2
    assert all(it["platform_errors"] == 0 for it in wr_items)


def otp(email, app="admin"):
    return ref_otp(SECRET, app, email, int(time.time()) // 300)


def form(**kw):
    return urllib.parse.urlencode(kw)


@pytest.mark.skipif(not E2E, reason="nginx with njs/geoip2/image_filter/brotli modules not installed")
def test_e2e_access_sign_in(edge):
    port, cfg, sites, o, ctl, tmp = edge
    # an unauthenticated visitor: 302 to the login page (HTML), 401 JSON otherwise
    s, h, _, _ = req(port, "acc.test", "/admin/x?y=1", headers=HTML)
    assert s == 302 and loc(h, "acc.test") == "/__pcdn/access/login?app=admin&next=%2Fadmin%2Fx%3Fy%3D1"
    s, h, b, _ = req(port, "acc.test", "/admin/x", headers={"Accept": "application/json"})
    assert s == 401 and json.loads(b)["login"].startswith("/__pcdn/access/login?app=admin")
    assert req(port, "acc.test", "/admin/x", "POST", b"a=1", FORM)[0] == 401
    s, h, b, _ = req(port, "acc.test", "/__pcdn/access/login?app=admin&next=%2Fadmin%2Fx", headers=HTML)
    assert s == 200 and b"Admin &lt;panel&gt;" in b and b'action="/__pcdn/access/send"' in b and b"<script" not in b
    assert "default-src 'none'" in h["content-security-policy"] and h["cache-control"] == "no-store"
    assert req(port, "acc.test", "/__pcdn/access/login?app=nope", headers=HTML)[0] == 404
    assert req(port, "acc.test", "/__pcdn/access/otp", "POST", b"{}", {"Content-Type": "application/json"})[0] == 404
    # IP allow / IP-only apps / unprotected paths
    assert req(port, "acc.test", "/lab/1", headers=HTML)[:3:2] == (200, b"origin /lab/1")
    assert req(port, "acc.test", "/closed", headers=HTML)[0] == 403
    # code requests: the same neutral answer for an allowed and an unknown address
    n0 = len(ctl.seen)
    s1, _, b1, _ = req(port, "acc.test", "/__pcdn/access/send", "POST",
                       json.dumps({"app": "admin", "email": "Alice@Example.com"}), {"Content-Type": "application/json"})
    s2, _, b2, _ = req(port, "acc.test", "/__pcdn/access/send", "POST",
                       json.dumps({"app": "admin", "email": "mallory@evil.test"}), {"Content-Type": "application/json"})
    assert s1 == s2 == 200 and b1 == b2
    assert wait_for(lambda: len(ctl.seen) >= n0 + 1)
    time.sleep(0.5)
    assert len(ctl.seen) == n0 + 1
    method, path, hdrs, body = ctl.seen[-1]
    assert (method, path) == ("POST", "/edge/v1/access/otp")
    assert hdrs["Authorization"] == "Bearer edge-token-0123456789" and "Cookie" not in hdrs
    assert json.loads(body) == {"domain": "acc.test", "app": "admin", "email": "alice@example.com"}
    # HTML form flow: the code page
    s, _, b, _ = req(port, "acc.test", "/__pcdn/access/send", "POST",
                     form(app="admin", email="x1@corp.test", next="/admin/x"), dict(FORM, **HTML))
    assert s == 200 and b'action="/__pcdn/access/verify"' in b and b'value="x1@corp.test"' in b
    # cross-site posts are refused
    assert req(port, "acc.test", "/__pcdn/access/send", "POST", form(app="admin", email="a@corp.test"),
               dict(FORM, Origin="https://evil.test"))[0] == 403
    # wrong code
    s, _, b, c = req(port, "acc.test", "/__pcdn/access/verify", "POST",
                     form(app="admin", email="alice@example.com", code="000000" if otp("alice@example.com") != "000000" else "111111"),
                     FORM)
    assert s == 401 and not c
    # the right code: cookie + redirect to next
    good = otp("alice@example.com")
    s, h, _, c = req(port, "acc.test", "/__pcdn/access/verify", "POST",
                     form(app="admin", email="alice@example.com", code=good, next="/admin/x?y=1"), FORM)
    assert s == 302 and loc(h, "acc.test") == "/admin/x?y=1"
    assert c and c[0].startswith("__pcdn_access_admin=") and "HttpOnly" in c[0] and "SameSite=Lax" in c[0]
    assert "Max-Age=7200" in c[0]
    ck = jar(c)
    # a code signs in once
    assert req(port, "acc.test", "/__pcdn/access/verify", "POST",
               form(app="admin", email="alice@example.com", code=good), FORM)[0] == 401
    # signed in: the origin gets the email; a visitor's own header never passes
    o.seen.clear()
    s, _, b, _ = req(port, "acc.test", "/admin/x?y=1", headers=dict(HTML, Cookie=ck, **{"X-PCDN-Access-Email": "ceo@corp.test"}))
    assert s == 200 and b == b"origin /admin/x?y=1"
    assert o.seen[-1][2].get("X-PCDN-Access-Email") == "alice@example.com"
    s, _, _, _ = req(port, "acc.test", "/public", headers={"Cookie": ck, "X-PCDN-Access-Email": "ceo@corp.test"})
    assert s == 200 and "X-PCDN-Access-Email" not in o.seen[-1][2]
    assert req(port, "plain.test", "/x", headers={"X-PCDN-Access-Email": "a@b.test"})[0] == 200   # access disabled
    assert "X-PCDN-Access-Email" not in o.seen[-1][2]
    # enabled without a secret: closed for everyone
    assert req(port, "closed.test", "/admin/x", headers=HTML)[0] == 403
    assert req(port, "closed.test", "/other", headers=HTML)[0] == 200
    # the cookie of one app does not open another; a tampered cookie does not open anything
    assert req(port, "acc.test", "/closed", headers=dict(HTML, Cookie=ck))[0] == 403
    assert req(port, "acc.test", "/admin/x", headers=dict(HTML, Cookie=ck[:-2] + "00"))[0] == 302
    # logout
    s, h, _, c = req(port, "acc.test", "/__pcdn/access/logout?app=admin&next=//evil.test")
    assert s == 302 and loc(h, "acc.test") == "/" and c[0].startswith("__pcdn_access_admin=;") and "Max-Age=0" in c[0]
    # open-redirect attempts: next is a same-host relative path or "/"
    for i, nxt in enumerate(["//evil.test/x", "https://evil.test", "/\\evil.test", "\\\\evil.test", "/%09/evil.test",
                             "/\t/evil.test", "javascript:alert(1)", "/ok/path?q=1"]):
        email = f"r{i}@corp.test"
        s, h, _, _ = req(port, "acc.test", "/__pcdn/access/verify", "POST",
                         form(app="admin", email=email, code=otp(email), next=nxt), FORM)
        assert s == 302, nxt
        assert loc(h, "acc.test") == ({"/%09/evil.test": "/%09/evil.test", "/ok/path?q=1": "/ok/path?q=1"}.get(nxt, "/")), nxt
    # code requests: 5 per minute per client IP and site (11 in a row span at most two minutes)
    statuses = [req(port, "acc.test", "/__pcdn/access/send", "POST", form(app="admin", email="z@corp.test"), FORM)
                for _ in range(11)]
    limited = [x for x in statuses if x[0] == 429]
    assert limited and limited[0][1]["retry-after"] == "60" and set(x[0] for x in statuses) == {200, 429}
    # usage: access counters and events (email hashed)
    assert wait_for(lambda: any(e["h"] == "acc.test" and e["v"].startswith("ok:acc:ok:") for e in log_lines(cfg)))
    st = {}
    agent.read_usage(st, cfg["ACCESS_LOG"])
    its = [it for it in agent.usage_items(st["pending"]) if it["host"] == "acc.test"]
    tot = {k: sum(it.get("access", {}).get(k, 0) for it in its) for k in ("ok", "fail", "otp")}
    assert tot["ok"] == 9 and tot["fail"] == 2 and tot["otp"] >= 3
    evs = [e for it in its for e in it.get("access_events", [])]
    eh = ehash("alice@example.com")
    assert {"app": "admin", "email_hash": eh, "ok": True} in [{k: e[k] for k in ("app", "email_hash", "ok")} for e in evs]
    assert "alice" not in json.dumps(its)


@pytest.mark.skipif(not E2E, reason="nginx with njs/geoip2/image_filter/brotli modules not installed")
def test_e2e_access_lockout(edge):
    port, *_ = edge
    good = otp("bob@corp.test")
    bad = "%06d" % ((int(good) + 1) % 1000000)
    for _ in range(10):
        assert req(port, "lock.test", "/__pcdn/access/verify", "POST",
                   form(app="admin", email="bob@corp.test", code=bad), FORM)[0] == 401
    s, h, b, c = req(port, "lock.test", "/__pcdn/access/verify", "POST",
                     form(app="admin", email="bob@corp.test", code=good), FORM)
    assert s == 429 and not c and int(h["retry-after"]) > 500
    # another site of the same edge is not locked
    s, _, _, c = req(port, "acc.test", "/__pcdn/access/verify", "POST",
                     form(app="admin", email="bob@corp.test", code=good), FORM)
    assert s == 302 and c
