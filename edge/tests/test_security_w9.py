"""Security review w9, edge side (unit level):

* H2: every customer regex is re-checked on the edge before nginx / njs run it (regex_unsafe),
  unsafe rules are skipped with a warning, never crash rendering; multi-star wildcards compile to a
  linear form; customer regex maps never see over-long paths;
* origin address safety: IP-literal origins must be public unless ORIGIN_PRIVATE_ALLOW covers them,
  the nftables origin guard ruleset (connect time) and its install.sh / bootstrap.sh plumbing;
* L6: bootstrap.sh keeps the token off argv and refuses plain-http controllers.

Real-engine timing (njs / nginx PCRE) and the real nftables guard: test_security_w9_e2e.py and
test_njs_logic.py.
"""

import importlib.util
import ipaddress
import logging
import os
import pathlib
import random
import re
import shutil
import subprocess
import sys
import tarfile

import pytest
from conftest import TEST_ORIGIN_ALLOW

HERE = pathlib.Path(__file__).resolve().parent
EDGE = HERE.parent
spec = importlib.util.spec_from_file_location("agent_w9", EDGE / "pcdn-agent.py")
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)


def make_cfg(tmp_path, **over):
    cfg = dict(agent.DEFAULTS, ORIGIN_PRIVATE_ALLOW=TEST_ORIGIN_ALLOW)
    cfg.update({
        "NGINX_DIR": str(tmp_path / "pcdn"), "CACHE_DIR": str(tmp_path / "cache"),
        "STATE_FILE": str(tmp_path / "state.json"), "ACCESS_LOG": str(tmp_path / "access.log"), "L4_ACCESS_LOG": str(tmp_path / "l4.log"), "FN_USAGE_LOG": str(tmp_path / "fn-usage.log"),
        "PAGES_DIR": str(EDGE / "pages"), "NJS_FILE": str(EDGE / "njs/pcdn.js"),
        "BASE_TEMPLATE": str(EDGE / "nginx/pcdn-base.conf"), "GEOIP_DB": str(tmp_path / "missing.mmdb"),
        "NGINX_USER": "root", "NGINX_CAPS": dict(agent.LEGACY_CAPS, nginx="1.24.0"),
    })
    cfg.update(over)
    return cfg


def site(sid=7, origin=None, **sections):
    s = {"id": sid, "domain": "example.com", "status": "active", "secret": "k" * 32, "ssl": None,
         "hosts": [{"name": "example.com", "origin": origin or {"address": "203.0.113.10", "port": 80}}]}
    s.update(sections)
    return s


# ----------------------------------------------------------------- H2: regex safety

UNSAFE = [r"^(a+)+$", r"(a|aa)*c", r"(.*a){12}", r"^(\w+\s?)*$", r"(a|ab)+", r"^(?:a|a?)+$", r"([a-z]+)*x",
          r"(?:\d+)+\.", r"a.*a.*b", r"Mozilla.*Windows.*Chrome", r"^/(.*)/(.*)/(.*)x$", r"x{0,5000}x{0,5000}z",
          r"(a)\1", r"(?P<x>a)(?P=x)", "x" * 257, "a\nb", r"(", r"^(?=(a+)+b)", r"\d+\d+$"]
SAFE = [r"bot|crawl|spider", r"^evil-bot/[0-9]+$", r"Mozilla.*Chrome", r"^/api/v[0-9]+/", r"^/blog/(.*)$",
        r"^/(.*)/(.*)$", r"^/old/(\d+)/(.*)$", r".*\.php$", r"(curl|wget|python-requests)", r"foo[^/]*/bar.*",
        r"^(?:/[a-z]+)*$", r"^/shop/([a-z0-9-]+)/p/(\d+)$", r"^/(en|fa)/(.*)$", r"^.*a.*$", r"^/x{0,1000}y{0,1000}$",
        r"\.(?:jpe?g|png|gif)$", r"^/p/(\d+)/(.*)$", r"^/q/(\d+)$", r"^/api/(.*)$"]


@pytest.mark.parametrize("src", UNSAFE)
def test_regex_unsafe_rejects_catastrophic_patterns(src):
    assert agent.regex_unsafe(src, ascii_only=False), src
    assert agent.pcre_regex(src) is None


@pytest.mark.parametrize("src", SAFE)
def test_regex_unsafe_accepts_ordinary_patterns(src):
    assert agent.regex_unsafe(src) is None, (src, agent.regex_unsafe(src))
    assert agent.pcre_regex(src) is not None


def test_regex_unsafe_never_raises():
    rnd = random.Random(7)
    alphabet = "a.*+?()[]{}|^$\\/:-0123456789,"
    for _ in range(3000):
        src = "".join(rnd.choice(alphabet) for _ in range(rnd.randint(1, 24)))
        assert agent.regex_unsafe(src) is None or isinstance(agent.regex_unsafe(src), str)
    for bad in (None, 5, b"x", "", ["a"]):
        assert agent.regex_unsafe(bad)
    assert agent.regex_unsafe("(" * 300 + ")" * 300)          # too long / too deep: refused, no crash


def test_firewall_unsafe_regex_rule_skipped_with_warning(tmp_path, caplog):
    fw = {"default_action": "allow", "rules": [
        {"id": "ok", "action": "block", "conditions": [{"field": "user_agent", "op": "regex", "value": "^evil-bot/[0-9]+$"}]},
        {"id": "redos", "action": "block", "conditions": [{"field": "user_agent", "op": "regex", "value": "^(a+)+$"}]},
        {"id": "poly", "action": "block", "conditions": [{"field": "path", "op": "contains", "value": "/x"},
                                                          {"field": "header", "name": "X-A", "op": "regex",
                                                           "value": ["ok", "a.*a.*a.*b"]}]},
        {"id": "long", "action": "log", "conditions": [{"field": "query", "op": "regex", "value": "a" * 300}]},
        "not-a-dict", {"id": "nd", "action": "block", "conditions": ["x"]},
        {"id": "fa", "action": "block", "conditions": [{"field": "user_agent", "op": "regex", "value": "سلام.*"}]}]}
    with caplog.at_level(logging.WARNING):
        js = agent.site_js(site(firewall=fw), [], {}, {})
    assert [r["id"] for r in js["firewall"]["rules"]] == ["ok", "fa"]   # non-ASCII is fine in njs
    text = caplog.text
    for rid in ("redos", "poly", "long"):
        assert f"firewall rule {rid} skipped: unsafe regex" in text


def test_redirect_and_rewrite_unsafe_regex_skipped(tmp_path, caplog):
    rules = [{"id": "a", "match": "regex", "source": "^(a+)+$", "target": "/x", "status": 301},
             {"id": "b", "match": "regex", "source": "^/r/(.*)/(.*)x$", "target": "/y/$1", "status": 302}]
    tf = {"rules": [{"id": "t1", "actions": [{"type": "rewrite_path", "regex": "a.*a.*b", "replacement": "/z"}]},
                    {"id": "t2", "actions": [{"type": "rewrite_path", "regex": "^/q/(\\d+)$", "replacement": "/i/$1"}]}]}
    with caplog.at_level(logging.WARNING):
        files = agent.render_all({"sites": [site(redirects={"rules": rules}, transform=tf)]}, make_cfg(tmp_path))
    text = files["sites/7.conf"]
    assert "(a+)+" not in text and "a.*a.*b" not in text
    assert '"~^/r/(.*)/(.*)x$" "302/y/$1";' in text and '"~^/q/(\\\\d+)$" "/i/$1$is_args$args";' in text
    assert "customer regex '^(a+)+$' skipped: nested quantifier" in caplog.text
    # customer regex maps are guarded by the path length (lazy maps: never evaluated beyond 2048 bytes)
    assert 'map $pcdn_rxlong $pcdn_rdc_7 {\n    1 "";\n    default $pcdn_rdcx_7;\n}' in text
    assert "map $pcdn_rxlong $pcdn_tfr_7_0 {" in text
    http = files["http.conf"]
    assert 'map $pcdn_path $pcdn_rxlong {\n    default 0;\n    "~(?s)^.{2049}" 1;\n}' in http
    assert agent.REGEX_INPUT_MAX_PATH == 2048
    # only exact / prefix redirects: no length guard needed (no customer regex)
    t2 = agent.render_all({"sites": [site(redirects={"rules": [
        {"id": "p", "match": "prefix", "source": "/blog/", "target": "/b/", "status": 301},
        {"id": "e", "match": "exact", "source": "/" + "a" * 120, "target": "/x", "status": 301}]})]},
        make_cfg(tmp_path))["sites/7.conf"]
    assert "$pcdn_rdcx_7" not in t2 and "map $pcdn_path $pcdn_rdc_7 {" in t2


def test_njs_input_cap_matches_agent():
    js = (EDGE / "njs/pcdn.js").read_text()
    assert f"RE_SRC_MAX = {agent.REGEX_MAX_LEN}, RE_INPUT_MAX = {agent.REGEX_INPUT_MAX_NJS};" in js


def _glob(p, s):
    return re.fullmatch("".join(".*" if c == "*" else re.escape(c) for c in p), s) is not None


def test_wildcard_re_linear_form_is_equivalent():
    rnd = random.Random(3)
    for _ in range(20000):
        p = "/" + "".join(rnd.choice("ab*/.") for _ in range(rnd.randint(0, 8)))
        s = "/" + "".join(rnd.choice("ab/.") for _ in range(rnd.randint(0, 10)))
        want = _glob(p, s)
        assert (re.search(agent.wildcard_re(p), s) is not None) == want, (p, s)
        assert (re.search(agent.wildcard_re(p, js=True), s) is not None) == want, (p, s)
    # one star keeps the familiar form (byte-identical renders for the common case)
    assert agent.wildcard_re("/blog/*") == "^/blog/.*$" and agent.wildcard_re("/x") == "^/x$"
    assert agent.wildcard_re("/a/*/b/*.php") == r"^/a/(?>.*?/b/).*\.php$"
    assert agent.wildcard_re("/a/*/b/*.php", js=True) == r"^/a/(?=(.*?/b/))\1.*\.php$"


def test_wildcard_js_form_in_node():
    if shutil.which("node") is None:
        pytest.skip("node not installed")
    rnd = random.Random(5)
    cases = []
    for _ in range(3000):
        p = "/" + "".join(rnd.choice("ab*/") for _ in range(rnd.randint(2, 8)))
        s = "/" + "".join(rnd.choice("ab/") for _ in range(rnd.randint(0, 10)))
        cases.append([agent.wildcard_re(p, js=True), s, _glob(p, s)])
    script = ("const c = JSON.parse(require('fs').readFileSync(0, 'utf8'));"
              "const bad = c.filter(x => new RegExp(x[0], 'i').test(x[1]) !== x[2]);"
              "console.log(JSON.stringify(bad.slice(0, 5)));")
    import json
    p = subprocess.run(["node", "-e", script], input=json.dumps(cases), capture_output=True, text=True, check=True)
    assert p.stdout.strip() == "[]"


def test_site_js_uses_js_wildcards(tmp_path):
    s = site(ratelimit={"rules": [{"id": "r", "path": "/*a*b"}]},
             waf={"mode": "block", "exclusions": [{"rule_id": 1, "path": "/x/*/y/*"}]},
             pagerules={"rules": [{"id": "p", "pattern": "/n/*/w/*", "waf": False, "cache": "bypass"}]})
    js = agent.site_js(s, [], {}, {})
    assert js["ratelimit"][0]["path_re"] == r"^/(?=(.*?a))\1.*b$"
    assert js["waf"]["exclusions"][0]["path_re"] == r"^/x/(?=(.*?/y/))\1.*$"
    assert js["waf"]["off_paths"] == [r"^/n/(?=(.*?/w/))\1.*$"]
    text = agent.render_all({"sites": [s]}, make_cfg(tmp_path))["sites/7.conf"]
    assert r"/n/(?>.*?/w/).*$" in text      # nginx page-rule location: PCRE atomic form


# ----------------------------------------------------------------- origin address policy (render time)

def test_is_public_ip_mirrors_controller_netguard():
    samples = ["8.8.8.8", "1.1.1.1", "203.0.113.5", "10.0.0.1", "172.16.5.4", "192.168.1.1", "127.0.0.1",
               "169.254.169.254", "100.64.0.1", "100.127.255.254", "0.0.0.0", "224.0.0.1", "240.0.0.1",
               "255.255.255.255", "198.18.0.1", "192.0.2.1", "::1", "::", "fe80::1", "fd00::1", "fc00::1",
               "ff02::1", "2001:db8::1", "2606:4700::1111", "::ffff:127.0.0.1", "::ffff:8.8.8.8",
               "64:ff9b::a9fe:a9fe", "64:ff9b::808:808", "2002:7f00:1::1", "2002:808:808::1",
               "2001:0:4136:e378:8000:63bf:3fff:fdd2", "fe80::1%eth0", "not-an-ip", "[2606:4700::1111]"]
    want = {s: agent.is_public_ip(s) for s in samples}
    assert want["8.8.8.8"] and want["2606:4700::1111"] and want["[2606:4700::1111]"] and want["::ffff:8.8.8.8"]
    for s in ("10.0.0.1", "127.0.0.1", "169.254.169.254", "100.64.0.1", "::1", "fd00::1", "fe80::1",
              "::ffff:127.0.0.1", "64:ff9b::a9fe:a9fe", "2002:7f00:1::1", "fe80::1%eth0", "224.0.0.1"):
        assert not want[s], s
    try:
        sys.path.insert(0, str(EDGE.parent / "controller"))
        from app import netguard   # noqa: PLC0415
    except Exception:  # noqa: BLE001 - controller deps (httpx) missing: the table above still holds
        return
    finally:
        sys.path.pop(0)
    for s in samples:
        assert netguard.is_public_ip(s) == want[s], s


def test_origin_guard_deny_sets_cover_exactly_non_public_space():
    for n in agent.ORIGIN_DENY4:
        net = ipaddress.ip_network(n)
        for ip in (net.network_address, net.broadcast_address):
            assert not agent.is_public_ip(str(ip)), ip
    deny6 = [ipaddress.ip_network(n) for n in agent._origin_deny6()]
    for s in ("64:ff9b::a9fe:a9fe", "64:ff9b::7f00:1", "2002:7f00:1::1", "2002:a00:1::", "fd12::1", "fe80::5",
              "::1", "ff05::2", "2001:db8::5", "fec0::1"):
        assert any(ipaddress.ip_address(s) in n for n in deny6), s
    for s in ("2606:4700::1111", "64:ff9b::808:808", "2002:808:808::1", "2a01:4f8::1"):
        assert not any(ipaddress.ip_address(s) in n for n in deny6), s


def test_literal_ip_forms():
    assert str(agent._literal_ip("127.1")) == "127.0.0.1"
    assert str(agent._literal_ip("2130706433")) == "127.0.0.1"
    assert str(agent._literal_ip("0x7f.0.0.1")) == "127.0.0.1"
    assert str(agent._literal_ip("[::1]")) == "::1"
    assert agent._literal_ip("origin.example.com") is None and agent._literal_ip("deadbeef") is None


def test_origin_host_allowed_policy():
    cfg = {"ORIGIN_PRIVATE_ALLOW": "10.1.0.0/16, fd00:1::/32  junk"}
    ok = agent.origin_host_allowed
    assert ok("203.0.113.10", {}) is False             # documentation range: not globally routable
    assert ok("8.8.8.8", {}) and ok("origin.example.com", {}) and ok("[2606:4700::1111]", {})
    for bad in ("127.0.0.1", "127.1", "2130706433", "169.254.169.254", "10.0.0.5", "100.64.1.1", "[::1]",
                "[fe80::1]", "[fd00::1]", "0.0.0.0", "224.0.0.1", "[::ffff:127.0.0.1]"):
        assert not ok(bad, {}), bad
    assert ok("10.1.2.3", cfg) and not ok("10.2.0.1", cfg) and ok("[fd00:1::5]", cfg)
    assert agent.origin_hp_allowed("10.1.2.3:8080", cfg) and not agent.origin_hp_allowed("[::1]:80", cfg)


def test_render_skips_private_ip_literal_origins(tmp_path, caplog):
    cfg = make_cfg(tmp_path, ORIGIN_PRIVATE_ALLOW="10.9.0.0/16")
    s = site(hosts=[{"name": "example.com", "origin": {"address": "8.8.8.8", "port": 80}},
                    {"name": "meta.example.com", "origin": {"address": "169.254.169.254", "port": 80}},
                    {"name": "lo.example.com", "origin": {"address": "127.1", "port": 8090}},
                    {"name": "priv.example.com", "origin": {"address": "10.9.1.1", "port": 80}},
                    {"name": "named.example.com", "origin": {"address": "origin.example.net", "port": 80}},
                    {"name": "lb.example.com", "origin": {"pool": "p"}},
                    {"name": "sto.example.com", "origin": {"storage": {
                        "host": "10.0.0.5", "port": 9000, "tls": False, "host_header": "10.0.0.5:9000",
                        "bucket": "bkt", "path_prefix": "/bkt", "referer": "r" * 20}}}],
             pools={"pools": [{"name": "p", "protocol": "http", "origins": [
                 {"address": "192.168.1.1", "port": 80}, {"address": "8.8.4.4", "port": 80}]}]},
             tunnel={"enabled": True, "paths": [
                 {"id": "a", "path": "/ws-a", "protocol": "ws", "origin": {"address": "127.0.0.1", "port": 9000}},
                 {"id": "b", "path": "/ws-b", "protocol": "ws", "origin": {"address": "9.9.9.9", "port": 9000}}]})
    with caplog.at_level(logging.WARNING):
        files = agent.render_all({"sites": [s]}, cfg)
    text = files["sites/7.conf"]
    for name in ("example.com", "priv.example.com", "named.example.com", "lb.example.com"):
        assert f"server_name {name};" in text, name
    for name in ("meta.example.com", "lo.example.com", "sto.example.com"):
        assert f"server_name {name};" not in text, name
    blob = "\n".join(files.values())
    assert "192.168.1.1" not in blob and '"hp": "8.8.4.4:80"' in files["js/sites.js"]
    assert "/ws-b" in text and "/ws-a" not in text and "127.0.0.1:9000" not in text
    assert "169.254.169.254" not in text and "not a public address" in caplog.text
    assert "storage/7.conf" not in files


def test_render_l4_skips_private_origin(tmp_path):
    cfg = make_cfg(tmp_path, ORIGIN_PRIVATE_ALLOW="", L4_PORT_RANGE="20000-20100",
                   NGINX_CAPS=dict(agent.LEGACY_CAPS, nginx="1.24.0", l4=True))
    apps = [{"id": "a", "protocol": "tcp", "edge_port": 20001, "origin": {"address": "10.0.0.1", "port": 22}},
            {"id": "b", "protocol": "tcp", "edge_port": 20002, "origin": {"address": "8.8.8.8", "port": 53}},
            {"id": "c", "protocol": "udp", "edge_port": 20003, "origin": {"address": "2130706433", "port": 53}}]
    s = site(l4={"apps": apps})
    files = agent.render_l4({"sites": [s]}, cfg)
    text = files.get("l4/sites/7.conf", "")
    assert "8.8.8.8:53" in text and "10.0.0.1" not in text and "2130706433" not in text and "20003" not in text


def test_origin_requests_never_carry_resizer_headers(tmp_path):
    s = site(headers={"request": [{"name": "X-Pcdn-Mtls", "value": "stolen"},
                                  {"name": "X-Pcdn-Origin", "value": "http://x"}]},
             image={"enabled": True}, cache={"enabled": True})
    files = agent.render_all({"sites": [s]}, make_cfg(tmp_path))
    text = files["sites/7.conf"]
    assert "stolen" not in text and "http://x" not in text
    for loc in text.split("    location ")[1:]:
        if "proxy_pass $pcdn_proto://" in loc:
            assert 'proxy_set_header X-Pcdn-Origin "";' in loc and 'proxy_set_header X-Pcdn-Mtls "";' in loc
    img = text.split("location ^~ /__pcdn/img/ {", 1)[1].split("\n    }", 1)[0]
    assert img.count("X-Pcdn-Origin") == 1 and "proxy_set_header X-Pcdn-Origin $pcdn_proto://$pcdn_target;" in img
    assert img.count("X-Pcdn-Mtls") == 1
    assert "proxy_bind 127.0.0.2;" in img
    http = files["http.conf"]
    assert "proxy_bind $pcdn_rz_bind;" in http and "allow 127.0.0.2;" in http
    assert '"~^http://127\\\\.0\\\\.0\\\\.1:" 127.0.0.2;' in http


# ----------------------------------------------------------------- origin guard (connect time)

def test_render_origin_guard(tmp_path):
    cfg = dict(agent.DEFAULTS, RESOLVER="127.0.0.53 [2606:4700::1111] 9.9.9.9:5353 bogus",
               ORIGIN_PRIVATE_ALLOW="10.1.0.0/16 fd00:1::/32", RESIZE_PORT="8189", IMAGE_PORT="8190",
               STORAGE_FETCH_PORT="8191", HTTPS_PORT="8443", SHIELD_HTTPS_PORT="9443", INTERNAL_SRC="127.0.0.9")
    r = agent.render_origin_guard(cfg, uid=33)
    assert r.splitlines()[5:8] == ["table inet pcdn_origin_guard {}", "delete table inet pcdn_origin_guard",
                                   "table inet pcdn_origin_guard {"]
    assert "meta skuid != 33 accept" in r
    assert "meta l4proto tcp tcp flags & (syn | ack) != syn accept" in r
    assert "ip daddr 127.0.0.53 meta l4proto { tcp, udp } th dport 53 accept" in r
    assert "ip daddr 9.9.9.9 meta l4proto { tcp, udp } th dport 5353 accept" in r
    assert "ip6 daddr 2606:4700::1111 meta l4proto { tcp, udp } th dport 53 accept" in r
    # + the tunnel probe's echo origin / h2c body server (SPEC §22.3)
    assert "ip saddr 127.0.0.9 ip daddr 127.0.0.1 tcp dport { 8092, 8093, 8189, 8190, 8191 } accept" in r
    assert "elements = { 10.1.0.0/16 }" in r and "elements = { fd00:1::/32 }" in r
    assert "ip daddr @peers4 tcp dport 9443 accept" in r and "udp sport { 8443, 20000-29999 }" in r
    for want in ("127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10", "10.0.0.0/8", "172.16.0.0/12",
                 "192.168.0.0/16", "224.0.0.0/4"):
        assert want in r
    for want in ("fe80::/10", "fc00::/7", "ff00::/8", "::/127", "64:ff9b::a9fe:0/112"):
        assert want in r
    # every accept comes before the rejects; the rejects cover the host's own addresses too
    first_reject = r.index("reject")
    assert all(r.index(x) < first_reject for x in ("@allow4", "@peers6", "th dport 53"))
    assert "fib daddr type local counter reject" in r
    with pytest.raises(ValueError):
        agent.render_origin_guard(cfg, uid=0)
    assert agent.internal_src({"INTERNAL_SRC": "127.0.0.1"}) == "127.0.0.2"
    assert agent.internal_src({"INTERNAL_SRC": "10.0.0.1"}) == "127.0.0.2"
    assert agent.internal_src({"INTERNAL_SRC": "127.3.2.1"}) == "127.3.2.1"
    if shutil.which("nft") and os.geteuid() == 0:
        f = tmp_path / "og.nft"
        f.write_text(r)
        p = subprocess.run(["nft", "-c", "-f", str(f)], capture_output=True, text=True)
        assert p.returncode == 0, p.stderr
        # https port inside the L4 range: no overlapping set elements
        f.write_text(agent.render_origin_guard(dict(cfg, HTTPS_PORT="20443"), uid=33))
        p = subprocess.run(["nft", "-c", "-f", str(f)], capture_output=True, text=True)
        assert p.returncode == 0, p.stderr


def test_origin_guard_cli(tmp_path):
    conf = tmp_path / "agent.conf"
    conf.write_text("NGINX_USER=root\n")
    env = dict(os.environ, PCDN_CONFIG=str(conf))
    p = subprocess.run([sys.executable, str(EDGE / "pcdn-agent.py"), "origin-guard"], env=env,
                       capture_output=True, text=True)
    assert p.returncode == 1 and "non-root" in p.stderr
    import pwd
    try:
        user = pwd.getpwuid(65534).pw_name
    except KeyError:
        pytest.skip("no nobody user")
    conf.write_text(f"NGINX_USER={user}\n")
    p = subprocess.run([sys.executable, str(EDGE / "pcdn-agent.py"), "origin-guard"], env=env,
                       capture_output=True, text=True)
    assert p.returncode == 0 and "meta skuid != 65534 accept" in p.stdout


def test_sync_origin_guard_peers(tmp_path):
    guard = tmp_path / "og.nft"
    cfg = {"ORIGIN_GUARD": "yes", "ORIGIN_GUARD_FILE": str(guard)}
    calls = []

    class P:
        returncode, stderr = 0, ""

    def run(cmd, input=None, **kw):
        calls.append((cmd, input))
        return P()
    st = {}
    assert agent.sync_origin_guard_peers(cfg, st, ["10.0.0.5"], run=run) is False   # no guard file
    guard.write_text("x")
    assert agent.sync_origin_guard_peers(cfg, st, ["10.0.0.5", "8.8.8.8", "[fd00::5]"], run=run)
    cmd, script = calls[-1]
    assert cmd == ["nft", "-f", "-"]
    assert "add element inet pcdn_origin_guard peers4 { 10.0.0.5 }" in script
    assert "add element inet pcdn_origin_guard peers6 { fd00::5 }" in script and "8.8.8.8" not in script
    assert "flush set inet pcdn_origin_guard peers4" in script
    assert agent.sync_origin_guard_peers(cfg, st, ["10.0.0.5", "8.8.8.8", "[fd00::5]"], run=run) is False
    st["og_peers_at"] -= 601                  # the table may have been reloaded: re-applied periodically
    assert agent.sync_origin_guard_peers(cfg, st, ["10.0.0.5", "[fd00::5]"], run=run)
    assert agent.sync_origin_guard_peers(cfg, st, [], run=run)
    assert "add element" not in calls[-1][1]


def test_agent_applies_at_once_when_guard_needs_bind(tmp_path):
    a = agent.Agent.__new__(agent.Agent)
    root = tmp_path / "pcdn"
    root.mkdir()
    a.cfg = {"ORIGIN_GUARD": "yes", "ORIGIN_GUARD_FILE": str(tmp_path / "og.nft")}
    (root / "http.conf").write_text("server { listen 127.0.0.1:8089; }")
    assert a._origin_guard_needs_bind(str(root)) is False          # guard not installed
    (tmp_path / "og.nft").write_text("x")
    assert a._origin_guard_needs_bind(str(root)) is True
    (root / "http.conf").write_text("proxy_bind $pcdn_rz_bind;")
    assert a._origin_guard_needs_bind(str(root)) is False


# ----------------------------------------------------------------- install.sh / bootstrap.sh

def _block(start, end):
    install = (EDGE / "install.sh").read_text()
    return start + install.split(start, 1)[1].split(end, 1)[0]


def test_install_origin_guard_default_on_and_upgrade(tmp_path):
    conf = tmp_path / "agent.conf"
    upgrade = _block('if [ "$UPGRADE" = yes ]; then', 'HTTP3="${HTTP3:-no}"') + 'HTTP3="${HTTP3:-no}"\n'
    defaults = 'HARDEN_NET="${HARDEN_NET:-no}"\nAVIF="${AVIF:-yes}"\nORIGIN_GUARD="${ORIGIN_GUARD:-yes}"\n'
    write = _block("cat > /etc/pcdn/agent.conf <<EOF", "\nEOF") + "\nEOF\n"
    keep = _block("# >>> pcdn keep logship", "# <<< pcdn keep logship")
    w8 = _block("# >>> pcdn wave8 conf", "# <<< pcdn wave8 conf")
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "CONTROLLER": "", "TOKEN": "", "REGION": "", "ROLE": "",
           "TCP_CC": "", "HTTP3": "", "KEEP_CONF": "", "NGINX_USER": "www-data", "IPV6": "yes", "CACHE_SIZE": "10g",
           "HTTP_PORT": "80", "HTTPS_PORT": "443", "UPGRADE": "no", "OG_NEW": "no"}

    def run(script, **over):
        script = script.replace("/etc/pcdn/agent.conf", str(conf))
        p = subprocess.run(["bash", "-euc", script + '\necho "O=$ORIGIN_GUARD N=$OG_NEW"'], env=dict(env, **over),
                           capture_output=True, text=True, check=True)
        return p.stdout.strip().splitlines()[-1]
    full = upgrade + defaults + write + keep + w8
    assert run(defaults + write + keep + w8, CONTROLLER="https://c", TOKEN="t") == "O=yes N=no"   # fresh: on
    assert agent.load_config(str(conf))["ORIGIN_GUARD"] == "yes"
    # an edge from before the guard: --upgrade turns it on (and prints the upgrade note)
    conf.write_text("CONTROLLER_URL=https://c\nEDGE_TOKEN=t\nGUARD=no\nORIGIN_PRIVATE_ALLOW=10.1.0.0/16\n")
    assert run(full, UPGRADE="yes") == "O=yes N=yes"
    cfg = agent.load_config(str(conf))
    assert cfg["ORIGIN_GUARD"] == "yes" and cfg["ORIGIN_PRIVATE_ALLOW"] == "10.1.0.0/16"
    # an operator's opt-out survives --upgrade; flags win
    conf.write_text("CONTROLLER_URL=https://c\nEDGE_TOKEN=t\nORIGIN_GUARD=no\n")
    assert run(full, UPGRADE="yes") == "O=no N=no"
    assert run(full, UPGRADE="yes", ORIGIN_GUARD="yes") == "O=yes N=no"
    install = (EDGE / "install.sh").read_text()
    assert "--no-origin-guard) ORIGIN_GUARD=no" in install and "pcdn-origin-guard.service" in install
    og = _block("# >>> pcdn origin guard", "# <<< pcdn origin guard")
    assert "pcdn-agent origin-guard" in og and "nft -c -f /etc/pcdn/origin-guard.nft.new" in og
    assert "nft delete table inet pcdn_origin_guard" in og
    unit = (EDGE / "systemd/pcdn-origin-guard.service").read_text()
    assert "ExecStop=-/usr/sbin/nft delete table inet pcdn_origin_guard" in unit and "Before=nginx.service" in unit
    assert subprocess.run(["bash", "-n", str(EDGE / "install.sh")]).returncode == 0


@pytest.fixture
def boot_env(tmp_path):
    """bootstrap.sh against stub curl / install.sh: records install.sh's argv and token env."""
    if os.geteuid() != 0:
        pytest.skip("bootstrap.sh requires root")
    stub = tmp_path / "bin"
    stub.mkdir()
    bundle = tmp_path / "bundle"
    (bundle / "edge").mkdir(parents=True)
    rec = tmp_path / "rec"
    (bundle / "edge/install.sh").write_text(
        f'#!/bin/bash\nprintf "%s\\n" "$@" > {rec}.argv\nprintf "%s" "${{PCDN_EDGE_TOKEN:-}}" > {rec}.env\n')
    with tarfile.open(tmp_path / "bundle.tar.gz", "w:gz") as tf:
        tf.add(bundle / "edge", arcname="edge")
    (stub / "curl").write_text(
        f'#!/bin/bash\nprintf "%s\\n" "$@" >> {rec}.curl\nout=""\n'
        'while [ $# -gt 0 ]; do [ "$1" = -o ] && out="$2"; shift; done\n'
        f'case "$out" in *bundle.tar.gz) cp {tmp_path}/bundle.tar.gz "$out" ;; *) exit 22 ;; esac\n')
    (stub / "curl").chmod(0o755)

    def run(*args, env=None, stdin=None):
        e = {"PATH": f"{stub}:/usr/bin:/bin"}
        e.update(env or {})
        for f in (rec.with_suffix(".argv"), rec.with_suffix(".env"), rec.with_suffix(".curl")):
            if f.exists():
                f.unlink()
        p = subprocess.run(["setsid", "bash", str(EDGE / "bootstrap.sh"), *args], env=e, capture_output=True,
                           text=True, stdin=subprocess.DEVNULL if stdin is None else stdin)
        argv = rec.with_suffix(".argv").read_text().split("\n") if rec.with_suffix(".argv").exists() else None
        tok = rec.with_suffix(".env").read_text() if rec.with_suffix(".env").exists() else None
        curl = rec.with_suffix(".curl").read_text() if rec.with_suffix(".curl").exists() else ""
        return p, argv, tok, curl
    return run, tmp_path


def test_bootstrap_token_off_argv_and_https_only(boot_env):
    run, tmp = boot_env
    p, argv, tok, curl = run("--controller", "https://c.example", "--token", "edge_secret1", "--role", "tunnel")
    assert p.returncode == 0, p.stderr
    assert tok == "edge_secret1" and "edge_secret1" not in "\n".join(argv) and "--token" not in argv
    assert argv[:2] == ["--controller", "https://c.example"] and "--role" in argv
    assert "--proto\n=https" in curl and "--proto-redir\n=https" in curl
    # environment / token file
    p, argv, tok, _ = run("--controller", "https://c.example", env={"PCDN_EDGE_TOKEN": "edge_env2"})
    assert p.returncode == 0 and tok == "edge_env2"
    tf = tmp / "tok"
    tf.write_text("edge_file3\n")
    p, argv, tok, _ = run("--controller", "https://c.example", "--token-file", str(tf))
    assert p.returncode == 0 and tok == "edge_file3"
    # plain http: refused unless --insecure-http (which install.sh also gets)
    p, argv, tok, _ = run("--controller", "http://c.example", "--token", "edge_x")
    assert p.returncode == 1 and "refusing the plain-http controller URL" in p.stderr and argv is None
    p, argv, tok, curl = run("--controller", "http://c.example", "--token", "edge_x", "--insecure-http")
    assert p.returncode == 0 and "--insecure-http" in argv and "=http,https" in curl
    p, argv, tok, _ = run("--controller", "ftp://c.example", "--token", "edge_x")
    assert p.returncode == 1 and argv is None
    # no token: refused (no terminal to ask on), except --upgrade, which keeps the installed token
    p, argv, tok, _ = run("--controller", "https://c.example")
    assert p.returncode == 1 and argv is None
    p, argv, tok, _ = run("--controller", "https://c.example", "--upgrade", "--no-origin-guard")
    assert p.returncode == 0 and tok == "" and "--upgrade" in argv and "--no-origin-guard" in argv
