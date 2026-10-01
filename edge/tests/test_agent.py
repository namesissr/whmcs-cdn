import hashlib
import importlib.util
import json
import os
import pathlib
import re
import shutil
import subprocess

import pytest

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("agent", HERE.parent / "pcdn-agent.py")
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)


def make_cfg(tmp_path, **over):
    cfg = dict(agent.DEFAULTS)
    cfg.update({
        "NGINX_DIR": str(tmp_path / "pcdn"),
        "CACHE_DIR": str(tmp_path / "cache"),
        "STATE_FILE": str(tmp_path / "state.json"),
        "ACCESS_LOG": str(tmp_path / "access.log"),
        "ERROR_LOG": str(tmp_path / "error.log"),
        "BUNDLE_VERSION_FILE": str(tmp_path / "bundle.version"),
        "PAGES_DIR": str(HERE.parent / "pages"),
        "NJS_FILE": str(HERE.parent / "njs/pcdn.js"),
        "BASE_TEMPLATE": str(HERE.parent / "nginx/pcdn-base.conf"),
        "GEOIP_DB": str(tmp_path / "missing.mmdb"),
        "NGINX_TEST_CMD": "true",
        "NGINX_RELOAD_CMD": "true",
        "NGINX_USER": "root",
        "RELOAD_VERIFY": "no",  # no real nginx to poll /__pcdn/confver in unit tests
    })
    cfg.update(over)
    return cfg


def self_signed(tmp_path, cn="example.com"):
    key, crt = tmp_path / "k.pem", tmp_path / "c.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                    "-nodes", "-subj", f"/CN={cn}", "-days", "2", "-keyout", key, "-out", crt],
                   check=True, capture_output=True)
    return crt.read_text(), key.read_text()


SITE = {
    "id": 7, "domain": "example.com", "status": "active", "secret": "ab" * 32,
    "hosts": [{"name": "example.com", "origin": {"address": "127.0.0.1", "port": 18080}},
              {"name": "www.example.com", "origin": {"address": "[2a01:4f8::1]", "port": None}},
              {"name": "evil.example.com", "origin": {"address": "x; include /etc/passwd", "port": None}},
              {"name": "evil2.example.com", "origin": {"address": "1.2.3.4", "port": "80; include /etc/passwd"}},
              {"name": "lb.example.com", "origin": {"pool": "nope"}}],
    "cache": {"enabled": True, "level": "standard", "edge_ttl": 3600, "browser_ttl": 600, "ignore_query": False,
              "bypass_cookies": ["wordpress_logged_in", "bad cookie\""], "always_online": True},
    "ssl_options": {"force_https": True, "hsts": {"enabled": True}, "min_tls": "1.2", "origin_protocol": "http"},
    "rate_limit_rps": 20,
    "blocked_ips": ["1.2.3.4/32", "not-an-ip\"}"], "ssl": None,
}


def test_render_rejects_unsafe_and_skips_https_without_cert(tmp_path):
    text, files = agent.render_site(SITE, make_cfg(tmp_path))
    assert "evil" not in text and "/etc/passwd" not in text
    assert "lb.example.com" not in text  # unknown pool
    assert 'set $pcdn_target "127.0.0.1:18080";' in text
    assert 'set $pcdn_target "[2a01:4f8::1]:80";' in text
    assert "listen 443" not in text and "return 301" not in text  # no cert -> no https redirect
    assert "Strict-Transport-Security" not in text  # HSTS only with a certificate
    assert "limit_req zone=pcdn_rlk_7 burst=40" in text  # F40: renamed zone keyed on $pcdn_rl_key
    assert 'max-age=600' in text
    assert "wordpress_logged_in" in text and "bad cookie" not in text
    assert files == {}


def test_sites_js_is_escaped_json(tmp_path):
    site = dict(SITE, domain='x"; import evil from "/etc/passwd', firewall={"rules": [
        {"id": "r1", "action": "block", "conditions": [{"field": "path", "op": "contains", "value": "</script> "}]},
        {"id": "BAD ID", "action": "block", "conditions": [{"field": "path", "op": "eq", "value": "/"}]},
        {"id": "r3", "action": "explode", "conditions": [{"field": "path", "op": "eq", "value": "/"}]},
    ]})
    files = agent.render_all({"sites": [site]}, make_cfg(tmp_path))
    src = files["js/sites.js"]
    assert src.startswith("// generated") and "export default {" in src
    data = json.loads(src.split("export default ", 1)[1].rstrip().rstrip(";"))
    s = data["7"]
    assert s["domain"] == site["domain"] and " " not in src
    assert [r["id"] for r in s["firewall"]["rules"]] == ["r1"]
    assert s["blocked_ips"] == ["1.2.3.4/32"]
    assert s["hosts"] == ["example.com", "www.example.com"]


def test_header_values_escaped(tmp_path):
    site = dict(SITE, headers={
        "request": [{"name": "X-From-CDN", "value": 'a$host\\"b'}, {"name": "Host", "value": "evil"},
                    {"name": "Bad Name", "value": "x"}],
        "response": [{"name": "X-Frame-Options", "value": "SAMEORIGIN"}, {"name": "Server", "value": None},
                     {"name": "X-Nl", "value": "a\nadd_header x y"}]})
    text, _ = agent.render_site(site, make_cfg(tmp_path))
    assert 'proxy_set_header X-From-CDN "a${pcdn_dollar}host\\\\\\"b";' in text
    assert "evil" not in text and "Bad Name" not in text and "X-Nl" not in text
    assert "proxy_hide_header Server;" in text
    assert 'add_header X-Frame-Options "SAMEORIGIN" always;' in text


def test_page_rules_render(tmp_path):
    site = dict(SITE, pagerules={"rules": [
        {"id": "p1", "pattern": "/wp-admin/*", "cache": "bypass"},
        {"id": "p2", "pattern": "/old", "redirect": {"url": "https://example.com/new", "code": 302}},
        {"id": "p3", "pattern": "/api/*", "waf": False},
        {"id": "p4", "pattern": "/x\"; }", "cache": "bypass"},
        {"id": "p5", "pattern": "/r", "redirect": {"url": "https://e.com/$host", "code": 301}},
    ]})
    text, _ = agent.render_site(site, make_cfg(tmp_path))
    assert 'location ~ "^/wp\\-admin/.*$" {' in text
    assert 'location ~ "^/old$" { return 302 "https://example.com/new"; }' in text
    assert "/api" not in text and 'x"' not in text and "$host\"" not in text
    # page rules come before the static-file location
    assert text.index("wp\\-admin") < text.index("~* \\.(?:css")
    js = agent.render_all({"sites": [site]}, make_cfg(tmp_path))["js/sites.js"]
    assert "^/api/.*$" in js


def test_render_suspended(tmp_path):
    cfg = make_cfg(tmp_path)
    text, _ = agent.render_site(dict(SITE, status="suspended"), cfg)
    assert "return 503" in text and "proxy_pass" not in text
    assert json.loads(agent.render_all({"sites": [dict(SITE, status="suspended")]}, cfg)["js/sites.js"]
                      .split("export default ", 1)[1].rstrip().rstrip(";")) == {}


def test_origin_regex_blocks_port_injection():
    # ports travel in origin.port (validated as int); the address regex never allows them
    assert not agent.SAFE_ORIGIN.match("127.0.0.1:18080")
    assert agent.SAFE_ORIGIN.match("[2a01:4f8::1]")
    assert agent.SAFE_ORIGIN.match("shops.myshopify.com")
    assert agent.resolve_origin({"origin": {"address": "1.2.3.4", "port": 8080}}, {}, "http") == ("http", None, "1.2.3.4:8080")
    assert agent.resolve_origin({"origin": {"address": "1.2.3.4", "port": None}}, {}, "https")[2] == "1.2.3.4:443"
    assert agent.resolve_origin({"origin": {"address": "1.2.3.4", "port": "x"}}, {}, "http") is None
    assert agent.resolve_origin({"origin": {"address": "1.2.3.4", "port": 70000}}, {}, "http") is None


def test_http_conf_ports_and_geo(tmp_path):
    cfg = make_cfg(tmp_path, HTTP_PORT="8081", HTTPS_PORT="8443", LISTEN_IPV6="no")
    text = agent.render_http(cfg)
    # F4/F16/F17: default_server listens carry reuseport + backlog + so_keepalive
    assert "listen 8081 default_server reuseport backlog=65535 so_keepalive=120s:30s:4;" in text
    assert "listen 8443 ssl http2 default_server reuseport backlog=65535 so_keepalive=120s:30s:4;" in text
    assert "[::]" not in text and "{{" not in text
    assert "grpc_connect_timeout 10s;" in text and "resolver_timeout 11s;" in text  # F12 / F15
    assert "geoip2" not in text and "map $host $pcdn_country" in text
    db = tmp_path / "c.mmdb"
    db.write_bytes(b"x")
    assert f"geoip2 {db} {{" in agent.render_http(make_cfg(tmp_path, GEOIP_DB=str(db)))


def test_apply_rollback(tmp_path):
    cfg = make_cfg(tmp_path)
    assert agent.apply_config({"sites": [SITE]}, cfg) is None
    first = (tmp_path / "pcdn/sites/7.conf").read_text()
    assert (tmp_path / "cache/7").is_dir()
    assert oct((tmp_path / "pcdn/js/sites.js").stat().st_mode & 0o777) == "0o600"
    cfg["NGINX_TEST_CMD"] = "echo broken >&2; false"
    err = agent.apply_config({"sites": [dict(SITE, domain="changed.com")]}, cfg)
    assert "broken" in err
    assert (tmp_path / "pcdn/sites/7.conf").read_text() == first
    cfg["NGINX_TEST_CMD"] = "true"
    agent.apply_config({"sites": []}, cfg)
    assert not (tmp_path / "cache/7").exists()


def test_bootstrap(tmp_path):
    cfg = make_cfg(tmp_path)
    agent.bootstrap(cfg)
    assert (tmp_path / "pcdn/http.conf").exists() and (tmp_path / "pcdn/js/pcdn.js").exists()
    assert "export default {}" in (tmp_path / "pcdn/js/sites.js").read_text()


def test_purge(tmp_path):
    cfg = make_cfg(tmp_path)
    p = pathlib.Path(agent.cache_file(cfg["CACHE_DIR"], 7, "https://example.com/a.css"))
    p.parent.mkdir(parents=True)
    p.write_text("x")
    h = hashlib.md5(b"https://example.com/a.css").hexdigest()
    assert p.name == h and p.parent.name == h[-3:-1] and p.parent.parent.name == h[-1]
    assert agent.do_purge({"site_id": 7, "urls": ["https://Example.com/a.css"]}, cfg) == 1
    # ignore_query sites store the key without the query string
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("x")
    assert agent.do_purge({"site_id": 7, "urls": ["https://example.com/a.css?v=3"]}, cfg) == 1
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("x")
    assert agent.do_purge({"site_id": 7, "urls": []}, cfg) == 1
    assert not p.exists()


def _fake_cache_file(base, key, body=b"data"):
    # nginx cache files carry a binary header then a "KEY: <scheme>://<host><uri>" line; the
    # prefix scan reads that line, so the on-disk name/location need not match the key's hash
    h = hashlib.md5(key.encode()).hexdigest()
    d = pathlib.Path(base) / h[-1] / h[-3:-1]
    d.mkdir(parents=True, exist_ok=True)
    fp = d / h
    fp.write_bytes(b"\x00" * 40 + b"\nKEY: " + key.encode() + b"\nHTTP/1.1 200 OK\r\n\r\n" + body)
    return fp


def test_purge_prefixes_synthetic(tmp_path):
    cfg = make_cfg(tmp_path)
    base = os.path.join(cfg["CACHE_DIR"], "7")
    assert agent._read_cache_key(str(_fake_cache_file(base, "https://example.com/k"))) == "https://example.com/k"

    blog = _fake_cache_file(base, "https://example.com/blog/post-1")
    blog2 = _fake_cache_file(base, "http://example.com/blog/post-2")
    other_host = _fake_cache_file(base, "https://other.com/blog/x")
    img = _fake_cache_file(base, "https://example.com/img/logo.png")
    root = _fake_cache_file(base, "https://example.com/index.html")

    # a host-less prefix matches any host/scheme by path
    assert agent.do_purge({"site_id": 7, "prefixes": ["/blog/"]}, cfg) == 3
    assert not blog.exists() and not blog2.exists() and not other_host.exists()
    assert img.exists() and root.exists()

    # a host-pinned prefix only matches that host
    other_img = _fake_cache_file(base, "https://other.com/img/a")
    assert agent.do_purge({"site_id": 7, "prefixes": ["https://example.com/img/"]}, cfg) == 1
    assert not img.exists() and other_img.exists()

    # everything wipes the whole site dir (even with urls present)
    _fake_cache_file(base, "https://example.com/still/here")
    assert agent.do_purge({"site_id": 7, "everything": True, "urls": ["https://example.com/x"]}, cfg) >= 1
    assert not any(pathlib.Path(base).iterdir())

    # a scan that blows past PURGE_SCAN_MAX falls back to a full-site purge
    for i in range(6):
        _fake_cache_file(base, f"https://example.com/keep/{i}")
    cfg["PURGE_SCAN_MAX"] = "2"
    assert agent.do_purge({"site_id": 7, "prefixes": ["/nomatch/"]}, cfg) >= 1
    assert not any(pathlib.Path(base).iterdir())


def test_usage_reader_handles_rotation(tmp_path):
    log = tmp_path / "access.log"
    lines = [
        {"t": "2026-09-28T14:05:03+03:30", "h": "Example.com", "b": 100, "c": "HIT"},
        {"t": "2026-09-28T10:59:59+00:00", "h": "example.com", "b": 50, "c": "MISS"},
    ]
    log.write_text("\n".join(json.dumps(x) for x in lines) + "\n" + '{"partial": ')
    state = {}
    agent.read_usage(state, str(log))
    key = "example.com|2026-09-28T10:00:00Z"
    tot = lambda a: [a["bytes"], a["requests"], a["cache_hits"]]  # noqa: E731
    assert list(state["pending"]) == [key] and tot(state["pending"][key]) == [150, 2, 1]
    agent.read_usage(state, str(log))  # nothing new (partial line not consumed)
    assert tot(state["pending"][key]) == [150, 2, 1]
    # a line lands after our last read, then logrotate moves the file to .1
    with open(log, "a") as f:
        f.write('"x"}\n' + json.dumps({"t": "2026-09-28T10:30:00Z", "h": "example.com", "b": 1000}) + "\n")
    os.rename(log, str(log) + ".1")
    log.write_text(json.dumps({"t": "2026-09-28T11:00:00Z", "h": "www.example.com", "b": 7}) + "\n")
    agent.read_usage(state, str(log))
    assert tot(state["pending"][key]) == [1150, 3, 1]
    assert tot(state["pending"]["www.example.com|2026-09-28T11:00:00Z"]) == [7, 1, 0]
    items = agent.usage_items(state["pending"])
    assert {i["host"] for i in items} == {"example.com", "www.example.com"}


def test_usage_v2_payload(tmp_path):
    log = tmp_path / "access.log"
    base = {"t": "2026-09-28T10:05:00+00:00", "h": "example.com", "b": 10, "c": "MISS", "ip": "1.2.3.4",
            "cc": "IR", "m": "GET", "ua": "curl/8", "v": "ok"}
    rows = [dict(base, s=200, u="/?a=1", c="HIT"), dict(base, s=200, u="/a.css"), dict(base, s=404, u="/x", cc="DE"),
            dict(base, s=403, u="/?id=1'or'1", v="block:waf:942100"),
            dict(base, s=403, u="/", v="challenge:ddos:auto"),
            dict(base, s=200, u="/", v="log:firewall:r3", cc="")]
    rows += [dict(base, s=200, u=f"/p{i}") for i in range(60)]
    log.write_text("".join(json.dumps(r) + "\n" for r in rows))
    state = {"pending": {"example.com|2026-09-28T10:00:00Z": [5, 1, 0]}}  # v1 state file entry
    agent.read_usage(state, str(log))
    [item] = agent.usage_items(state["pending"])
    assert item["requests"] == len(rows) + 1 and item["bytes"] == 10 * len(rows) + 5 and item["cache_hits"] == 1
    assert item["status"] == {"2xx": 63, "4xx": 3} and item["codes"]["404"] == 1
    assert item["countries"] == {"IR": 64, "DE": 1}
    assert len(item["paths"]) == 50 and item["paths"]["/"] == 4
    assert item["security"] == {"waf": 1, "ddos": 1, "challenge": 1, "firewall": 1}
    ev = state["events"]
    assert [(e["action"], e["source"], e["rule"]) for e in ev] == [
        ("block", "waf", "942100"), ("challenge", "ddos", "auto"), ("log", "firewall", "r3")]
    assert ev[0] == {"t": "2026-09-28T10:05:00Z", "host": "example.com", "ip": "1.2.3.4", "country": "IR",
                     "method": "GET", "path": "/?id=1'or'1", "action": "block", "source": "waf",
                     "rule": "942100", "user_agent": "curl/8"}


class RecordingCtl:
    def __init__(self, fail=False):
        self.bodies, self.fail = [], fail

    def call(self, method, path, body=None, headers=None, timeout=30):
        if self.fail:
            raise OSError("controller down")
        self.bodies.append(body)
        return 200, {}, None


def test_push_usage_batches_and_keeps_backlog(tmp_path, monkeypatch):
    monkeypatch.setattr(agent, "MAX_EVENTS", 3)
    monkeypatch.setattr(agent, "MAX_ITEMS", 2)
    log = tmp_path / "access.log"
    rows = [{"t": f"2026-09-28T{h:02d}:00:00Z", "h": "example.com", "b": 1, "s": 403, "u": "/",
             "v": "block:firewall:r1"} for h in range(5)]
    log.write_text("".join(json.dumps(r) + "\n" for r in rows))
    a = agent.Agent.__new__(agent.Agent)
    a.cfg, a.state = make_cfg(tmp_path), {}
    a.ctl = RecordingCtl(fail=True)
    with pytest.raises(OSError):
        a.push_usage()
    # F7: nothing lost — pending/events drained into the persisted outbox with stable batch_ids
    assert sum(len(e["items"]) for e in a.state["outbox"]) == 5
    assert sum(len(e["events"]) for e in a.state["outbox"]) == 5
    assert a.state["pending"] == {} and a.state["events"] == []
    ids = [e["id"] for e in a.state["outbox"]]
    assert all(re.fullmatch(r"[0-9a-f]{32}", i) for i in ids)
    a.ctl = RecordingCtl()
    a.push_usage()
    assert [len(b["items"]) for b in a.ctl.bodies] == [2, 2, 1]
    assert [len(b.get("events", [])) for b in a.ctl.bodies] == [3, 2, 0]
    # F7: the retry reuses the SAME batch_ids as the failed attempt, so the controller dedups them
    assert [b["batch_id"] for b in a.ctl.bodies] == ids
    assert a.state["outbox"] == [] and a.state["pending"] == {} and a.state["events"] == []


MINSITE = {"id": 1, "domain": "a.com", "status": "active", "secret": "ab" * 32,
           "hosts": [{"name": "a.com", "origin": {"address": "1.2.3.4", "port": 80}}]}


class SeqCtl:
    """Serves a controlled config version/etag; ignores If-None-Match so the diff-skip path is hit."""
    def __init__(self):
        self.body = {"version": "v0", "sites": []}
        self.etag = "e0"
        self.hb = []

    def serve(self, version, etag, sites=None):
        self.body, self.etag = {"version": version, "sites": sites if sites is not None else []}, etag

    def call(self, method, path, body=None, headers=None, timeout=30):
        if path == "/edge/v1/config":
            return 200, {"ETag": self.etag}, dict(self.body)
        if "heartbeat" in path:
            self.hb.append(body)
        return 200, {}, None


def test_reload_coalescing_and_diff_skip(tmp_path, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(agent.time, "monotonic", lambda: clock[0])
    cfg = make_cfg(tmp_path, RELOAD_MIN_INTERVAL="120", RELOAD_DEBOUNCE="5")
    root = cfg["NGINX_DIR"].rstrip("/")
    applies = []

    def fake_apply(config, cfg_, files=None, digest=None):
        applies.append(digest)
        agent.write_tree(root, files)   # so first_boot is False afterwards
        return None
    monkeypatch.setattr(agent, "apply_config", fake_apply)
    a = agent.Agent.__new__(agent.Agent)
    a.cfg, a.state, a.ctl = cfg, {}, SeqCtl()

    a.ctl.serve("v1", "e1")            # first boot -> apply immediately
    a.sync_config()
    assert len(applies) == 1 and a.state["version"] == "v1"

    # F20: a new version whose rendered tree is identical is applied without a reload
    a.ctl.serve("v2", "e2")
    a.sync_config()
    assert len(applies) == 1 and a.state["version"] == "v2" and a.state["etag"] == "e2"

    # F5: a genuinely changed config is coalesced — held until it settles AND the min interval passes
    a.ctl.serve("v3", "e3", [MINSITE])
    clock[0] = 1010
    a.sync_config()                    # freshly seen -> pending, nothing applied (age < debounce)
    assert len(applies) == 1
    clock[0] = 1016
    a.sync_config()                    # settled, but only 16s since the last reload (< 120)
    assert len(applies) == 1
    clock[0] = 1140
    a.sync_config()                    # settled and > 120s since the last reload -> apply once
    assert len(applies) == 2 and a.state["version"] == "v3"
    assert "pending_version" not in a.state


def test_diff_skip_runs_reload_once(tmp_path):
    counter = tmp_path / "reloads"
    cfg = make_cfg(tmp_path, NGINX_RELOAD_CMD=f"sh -c 'echo x >> {counter}'")

    class C:
        def __init__(self):
            self.n = 0
        def call(self, method, path, body=None, headers=None, timeout=30):
            if path == "/edge/v1/config":
                self.n += 1
                return 200, {"ETag": f"e{self.n}"}, {"version": f"v{self.n}", "sites": [MINSITE]}
            return 200, {}, None
    a = agent.Agent.__new__(agent.Agent)
    a.cfg, a.state, a.ctl = cfg, {}, C()
    a.sync_config()   # first boot -> write + reload
    a.sync_config()   # identical tree (new version/etag) -> diff-skip, no reload
    a.sync_config()
    assert counter.read_text().count("x") == 1  # F20: only the first apply reloaded


@pytest.mark.skipif(shutil.which("nginx") is None, reason="nginx not installed")
def test_nginx_accepts_generated_config(tmp_path):
    from conftest import nginx_conf, modules_available
    if not modules_available():
        pytest.skip("nginx dynamic modules (njs, geoip2, image_filter, brotli) not installed")
    cert, key = self_signed(tmp_path)
    cfg = make_cfg(tmp_path, LISTEN_IPV6="no", HTTP_PORT="18580", HTTPS_PORT="18543")  # CI often lacks IPv6
    site = dict(SITE, hosts=[{"name": "example.com", "origin": {"address": "127.0.0.1", "port": None}},
                             {"name": "*.example.com", "origin": {"address": "origin.example.net", "port": 8080}},
                             {"name": "v6.example.com", "origin": {"address": "[2a01:4f8::1]", "port": None}},
                             {"name": "lb.example.com", "origin": {"pool": "main"}}],
                ssl={"cert": cert, "key": key},
                pools={"pools": [{"name": "main", "origins": [{"address": "10.0.0.1", "port": 80}], "health": {"enabled": True}}]},
                pagerules={"rules": [{"id": "p", "pattern": "/a/*", "cache": "everything", "edge_ttl": 60}]},
                image={"enabled": True}, errorpages={"5xx": "<h1>down</h1>", "4xx": "<h1>nope</h1>"},
                headers={"request": [{"name": "X-A", "value": "$x"}], "response": [{"name": "X-B", "value": "1"}]})
    other = dict(SITE, id=8, domain="b.com", status="over_quota", hosts=[{"name": "b.com", "origin": "1.1.1.1"}])
    legacy = {"id": 9, "domain": "c.com", "status": "active", "cache_enabled": False, "origin_protocol": "https",
              "hosts": [{"name": "c.com", "origin": "1.1.1.1"}], "ssl": None}
    assert agent.apply_config({"sites": [site, other, legacy]}, cfg) is None
    conf = nginx_conf(tmp_path, cfg)
    p = subprocess.run(["nginx", "-t", "-c", str(conf)], capture_output=True, text=True)
    assert p.returncode == 0 and "[warn]" not in p.stderr, p.stderr


@pytest.mark.skipif(not os.path.exists("/etc/nginx/nginx.conf") or shutil.which("nginx") is None,
                    reason="distro nginx not installed")
def test_installer_edits_make_stock_nginx_conf_valid(tmp_path):
    """install.sh comments out stock directives that our http.conf sets; the result must pass nginx -t."""
    install = (HERE.parent / "install.sh").read_text()
    block = install.split("# >>> nginx.conf edits", 1)[1].split("\n", 1)[1].split("# <<< nginx.conf edits", 1)[0]
    stock = tmp_path / "nginx.conf"
    shutil.copy("/etc/nginx/nginx.conf", stock)
    for _ in range(2):  # idempotent
        subprocess.run(["bash", "-ec", block.replace("/etc/nginx/nginx.conf", str(stock))], check=True)
    edited = stock.read_text()
    assert edited.count("worker_rlimit_nofile 524288;") == 1 and edited.count("multi_accept off;") == 1
    assert edited.count("worker_shutdown_timeout") == 1 and "worker_shutdown_timeout 1h;" in edited  # F6
    assert "worker_connections 65535;" in edited
    cfg = make_cfg(tmp_path, LISTEN_IPV6="no", HTTP_PORT="18680", HTTPS_PORT="18643")
    agent.bootstrap(cfg)
    text = stock.read_text()
    text = text.replace("include /etc/nginx/conf.d/*.conf;", f"include {cfg['NGINX_DIR']}/http.conf;")
    text = text.replace("include /etc/nginx/sites-enabled/*;", "")
    text = text.replace("pid /run/nginx.pid;", f"pid {tmp_path}/nginx.pid;")
    stock.write_text(text)
    p = subprocess.run(["nginx", "-t", "-c", str(stock), "-g", f"error_log {tmp_path}/e.log;"],
                       capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    assert "# pcdn (set in pcdn http.conf): gzip on;" in text
    assert subprocess.run(["bash", "-n", str(HERE.parent / "install.sh")]).returncode == 0
    assert subprocess.run(["bash", "-n", str(HERE.parent / "pcdn-geoip-update.sh")]).returncode == 0


class FakeCtl:
    def __init__(self, purges):
        self.purges = purges

    def call(self, method, path, body=None, headers=None, timeout=30):
        after = int(path.split("after=")[1])
        return 200, {}, [p for p in self.purges if p["id"] > after]


def test_purge_cursor_first_run_then_new(tmp_path):
    cfg = make_cfg(tmp_path)
    a = agent.Agent.__new__(agent.Agent)
    a.cfg, a.state = cfg, {}
    a.ctl = FakeCtl([])
    a.sync_purges()  # first run, nothing yet
    assert a.state["purge_id"] == 0
    p = pathlib.Path(agent.cache_file(cfg["CACHE_DIR"], 7, "http://example.com/x"))
    p.parent.mkdir(parents=True)
    p.write_text("x")
    a.ctl = FakeCtl([{"id": 3, "site_id": 7, "domain": "example.com", "urls": ["http://example.com/x"]}])
    a.sync_purges()
    assert not p.exists() and a.state["purge_id"] == 3


# ----------------------------------------------------------------- tunnel mode (SPEC §7)

TUNNEL = {"enabled": True, "idle_timeout": 7200, "per_connection_mbps": 5, "max_connections_per_ip": 8,
          "max_connections": 500, "allowed_countries": ["ir", "DE", "bad"], "fallback": "origin", "paths": [
              {"id": "g1", "path": "/svc", "protocol": "grpc", "origin": None, "pool": None},
              {"id": "w1", "path": "/ws", "protocol": "ws",
               "origin": {"address": "vpn.example.net", "port": 8443, "tls": True, "sni": "vpn.example.net", "verify": True}},
              {"id": "h1", "path": "/h2", "protocol": "h2",
               "origin": {"address": "10.0.0.5", "port": 2053, "tls": True, "sni": None, "verify": False}},
              {"id": "x1", "path": "/xh", "protocol": "xhttp", "origin": None, "pool": "main"},
              {"id": "u1", "path": "/up", "protocol": "httpupgrade",
               "origin": {"address": "[2a01:4f8::2]", "port": 80, "tls": False}},
              {"id": "dup", "path": "/svc", "protocol": "ws"},                                     # duplicate path
              {"id": "bad1", "path": "/__pcdn/x", "protocol": "ws"},                               # reserved
              {"id": "bad2", "path": "/a\"; include /etc/passwd", "protocol": "ws"},              # injection
              {"id": "bad3", "path": "/ok", "protocol": "quic"},                                   # unknown protocol
              {"id": "bad4", "path": "/ok2", "protocol": "ws", "pool": "nope"},                    # unknown pool
              {"id": "bad5", "path": "/ok3", "protocol": "ws", "origin": {"address": "1.2.3.4", "port": "1; x"}},
              {"id": "BAD ID", "path": "/ok4", "protocol": "ws"}]}
POOLS = {"pools": [{"name": "main", "protocol": "https", "origins": [{"address": "10.0.0.1", "port": 443}]}]}


def test_tunnel_normalisation():
    t = agent.norm_tunnel(dict(SITE, tunnel=TUNNEL, pools=POOLS), agent.norm_pools(dict(SITE, pools=POOLS)))
    assert [p["id"] for p in t["paths"]] == ["g1", "w1", "h1", "x1", "u1"]
    assert t["allowed_countries"] == ["DE", "IR"] and t["idle_timeout"] == 7200 and t["max_connections"] == 500
    assert t["paths"][1]["origin"] == {"hp": "vpn.example.net:8443", "ip": False, "tls": True, "sni": "vpn.example.net",
                                       "verify": True}
    assert t["paths"][4]["origin"]["ip"] is True
    assert agent.norm_tunnel(dict(SITE, tunnel=dict(TUNNEL, enabled=False)), {}) is None
    assert agent.norm_tunnel(dict(SITE, tunnel=TUNNEL, status="suspended"), {}) is None
    assert agent.norm_tunnel(dict(SITE, tunnel=dict(TUNNEL, paths=[])), {}) is None
    assert agent.norm_tunnel(SITE, {}) is None
    clamp = agent.norm_tunnel(dict(SITE, tunnel=dict(TUNNEL, idle_timeout=5, fallback="evil")), {})
    assert clamp["idle_timeout"] == 60 and clamp["fallback"] == "origin"


def test_tunnel_render(tmp_path):
    db = tmp_path / "geo.mmdb"
    db.write_bytes(b"x")  # F9: a present GeoIP DB enables the allowed_countries gate
    cfg = make_cfg(tmp_path, GEOIP_DB=str(db))
    site = dict(SITE, tunnel=TUNNEL, pools=POOLS, rate_limit_rps=0,
                hosts=[{"name": "example.com", "origin": {"address": "127.0.0.1", "port": 18080}},
                       {"name": "lb.example.com", "origin": {"pool": "main"}}],
                headers={"request": [{"name": "X-A", "value": "1"}], "response": [{"name": "X-B", "value": "2"}]},
                pagerules={"rules": [{"id": "p", "pattern": "/svc*", "cache": "everything"}]})
    text, files = agent.render_site(site, cfg)
    assert files == {}
    srv = text.split("server {")[1]
    loc = lambda path: srv.split(f'location ^~ "{path}" {{', 1)[1].split("\n    }", 1)[0]  # noqa: E731
    assert 'location ^~ "/svc" {' in srv and srv.index('location ^~ "/svc"') < srv.index('location ~ "^/svc.*$"')
    assert "__pcdn/x" not in text and "passwd" not in text and "/ok" not in text
    # F9: an empty country ("" -> unresolved client) passes; only listed countries + "" -> 1
    assert "map $pcdn_country $pcdn_tcc_7 {\n    \"\" 1;\n    DE 1;\n    IR 1;\n    default 0;\n}" in text
    g = loc("/svc")
    assert "set $pcdn_tn grpc;" in g and "if ($pcdn_tcc_7 = 0) { return 403; }" in g
    assert "set $pcdn_tn_ckey $pcdn_site;" in g   # F13: grpc stream counts one slot
    assert "grpc_pass grpc://pcdn_tn_7_0;" in g and "grpc_set_header X-A \"1\";" in g and "grpc_read_timeout 7200s;" in g
    assert "grpc_buffer_size 16k;" in g           # F14
    assert "grpc_next_upstream error timeout;" in g and "grpc_next_upstream_tries 2;" in g  # F28
    assert "limit_conn pcdn_tn_site2 500;" in g and "limit_conn pcdn_tn_ip2 8;" in g and "limit_rate" not in g
    assert "limit_req_dry_run" not in g          # F40: skipped via the empty $pcdn_rl_key instead
    assert "client_body_buffer_size 256k;" in g and "http2_chunk_size 16k;" in g  # F3 / F14
    assert "upstream pcdn_tn_7_0 {\n    server 127.0.0.1:18080 max_fails=0;\n    keepalive 64;" in text
    w = loc("/ws")
    assert 'set $pcdn_tn_target "vpn.example.net:8443";' in w and "proxy_pass https://$pcdn_tn_target;" in w
    assert "proxy_ssl_name vpn.example.net;" in w and "proxy_ssl_verify on;" in w
    assert "proxy_set_header Upgrade $http_upgrade;" in w and "proxy_read_timeout 7200s;" in w
    assert "client_body_buffer_size" not in w    # F3: only the HTTP/2 body path gets the buffer
    assert "add_header" not in w and "proxy_cache off;" in w and "gzip off;" in w and "brotli off;" in w
    h = loc("/h2")
    assert "grpc_pass grpcs://pcdn_tn_7_1;" in h and "grpc_ssl_name $host;" in h and "grpc_ssl_verify" not in h
    x = loc("/xh")
    assert "set $pcdn_tn_pool \"main\";" in x and "set $pcdn_tn_target $pcdn_tn_upstream;" in x
    assert 'set $pcdn_tn_prefix "/xh";' in x      # F1: session-affinity prefix, set before target
    assert x.index('set $pcdn_tn_prefix "/xh";') < x.index("set $pcdn_tn_target $pcdn_tn_upstream;")
    assert "set $pcdn_tn_ckey $pcdn_tn_isget;" in x   # F13: xhttp counts only the downlink GET
    assert "proxy_pass https://$pcdn_tn_target;" in x and 'proxy_set_header Connection "";' in x
    assert "proxy_buffer_size 16k;" in x and "client_body_buffer_size 256k;" in x  # F14 / F3
    assert "proxy_buffering off;" in x and "proxy_request_buffering off;" in x and "client_max_body_size 0;" in x
    u = loc("/up")
    assert 'set $pcdn_tn_target "[2a01:4f8::2]:80";' in u and "proxy_pass http://$pcdn_tn_target;" in u
    # F11: IP-literal pool member (main -> 10.0.0.1:443) gets keepalive upstreams (h1 + h2)
    assert "upstream pcdn_tn_7_p0_0 {\n    server 10.0.0.1:443 max_fails=0;\n    keepalive 64;" in text
    assert "upstream pcdn_tn_7_p0_0_h2 {" in text
    # F1: a host that inherits a pool routes tunnel paths through the tunnel picker, not $pcdn_target
    lb = text.split("server_name lb.example.com;")[1]
    lbsvc = lb.split('location ^~ "/svc" {', 1)[1].split("\n    }", 1)[0]
    assert "grpc_pass grpcs://$pcdn_tn_target;" in lbsvc and 'set $pcdn_tn_pool "main";' in lbsvc
    assert "$pcdn_target" not in lbsvc
    # HTTP/2 and HTTP/1.1 tunnels to the same origin never share keepalive connections
    both = dict(SITE, hosts=site["hosts"][:1], tunnel=dict(TUNNEL, paths=[
        {"id": "a", "path": "/a", "protocol": "grpc"}, {"id": "b", "path": "/b", "protocol": "xhttp"},
        {"id": "c", "path": "/c", "protocol": "h2"}]))
    t2, _ = agent.render_site(both, make_cfg(tmp_path))
    assert t2.count("server 127.0.0.1:18080 max_fails=0;") == 2
    assert "grpc_pass grpc://pcdn_tn_7_0;" in t2 and "proxy_pass http://pcdn_tn_7_1;" in t2
    assert t2.count("grpc_pass grpc://pcdn_tn_7_0;") == 2
    js = json.loads(agent.render_all({"sites": [site]}, cfg)["js/sites.js"]
                    .split("export default ", 1)[1].rstrip().rstrip(";"))
    assert js["7"]["tunnel_paths"] == ["/svc", "/ws", "/h2", "/xh", "/up"]
    # F11: pool origin carries the keepalive upstream names for the tunnel picker
    assert js["7"]["pools"]["main"]["origins"][0]["up"] == {"h1": "pcdn_tn_7_p0_0", "h2": "pcdn_tn_7_p0_0_h2"}


def test_tunnel_fallback_render(tmp_path):
    decoy = dict(SITE, domain="acme-shop.com", tunnel=dict(TUNNEL, fallback="decoy"), image={"enabled": True})
    text, _ = agent.render_site(decoy, make_cfg(tmp_path))
    assert "return 200 \"<!doctype html>" in text and "Acme Shop" in text and "{{" not in text
    assert "proxy_cache_path" in text and "location ~* " not in text and "/__pcdn/img" not in text
    assert text.count("proxy_pass $pcdn_proto://$pcdn_target;") == 0
    nf, _ = agent.render_site(dict(SITE, tunnel=dict(TUNNEL, fallback="404")), make_cfg(tmp_path))
    assert "location / { return 404; }" in nf and "location ~" not in nf
    plain, _ = agent.render_site(SITE, make_cfg(tmp_path))
    assert "location ^~ \"/" not in plain and "$pcdn_tn" not in plain


def test_tunnel_allowed_countries_fail_open_without_geoip(tmp_path):
    site = dict(SITE, tunnel=TUNNEL, pools=POOLS, rate_limit_rps=0,
                hosts=[{"name": "example.com", "origin": {"address": "127.0.0.1", "port": 18080}}])
    # F9: no GeoIP DB (make_cfg points at a missing file) -> the country gate fails open (no 403)
    text, _ = agent.render_site(site, make_cfg(tmp_path))
    assert "$pcdn_tcc_7" not in text
    # with the DB present the gate is enforced, and an unresolved ("") client still passes
    db = tmp_path / "g.mmdb"
    db.write_bytes(b"x")
    text2, _ = agent.render_site(site, make_cfg(tmp_path, GEOIP_DB=str(db)))
    assert "if ($pcdn_tcc_7 = 0) { return 403; }" in text2 and '    "" 1;' in text2


def test_force_https_excludes_tunnel_paths(tmp_path):
    cert, key = self_signed(tmp_path)
    site = dict(SITE, ssl={"cert": cert, "key": key}, tunnel=TUNNEL, pools=POOLS,
                hosts=[{"name": "example.com", "origin": {"address": "127.0.0.1", "port": 18080}}])
    text, _ = agent.render_site(site, make_cfg(tmp_path))   # SITE has force_https True
    assert "map $uri $pcdn_tnp_7 {" in text and 'map "$scheme$pcdn_tnp_7" $pcdn_httpredir_7 {' in text
    assert "if ($pcdn_httpredir_7) { return 301 https://$host$request_uri; }" in text
    assert "if ($scheme = http)" not in text               # replaced by the tunnel-aware redirect
    # a non-tunnel force_https site keeps the plain one-line redirect
    plain, _ = agent.render_site(dict(SITE, ssl={"cert": cert, "key": key}), make_cfg(tmp_path))
    assert "if ($scheme = http) { return 301 https://$host$request_uri; }" in plain
    assert "$pcdn_httpredir" not in plain


def test_suspended_tunnel_cut_paths(tmp_path):
    site = dict(SITE, status="suspended", tunnel={"enabled": True, "cut_paths": ["/vpn", "/ws", "/__pcdn/x"]})
    text, _ = agent.render_site(site, make_cfg(tmp_path))
    # F35: cheap, rate-limited, body-less 503 on the tunnel prefixes (reserved /__pcdn dropped)
    assert 'location ^~ "/vpn" { access_log off; limit_req zone=pcdn_cut burst=5 nodelay; ' \
           'limit_req_status 503; return 503; }' in text
    assert 'location ^~ "/ws" {' in text and "__pcdn/x" not in text
    # error_page is scoped to the website catch-all so cut paths return nginx's tiny built-in 503
    assert "location / { error_page 503 /suspended.html; return 503; }" in text
    assert "proxy_pass" not in text


def test_sysctl_heredoc(tmp_path):
    install = (HERE.parent / "install.sh").read_text()
    block = install.split("# >>> pcdn sysctl", 1)[1].split("# <<< pcdn sysctl", 1)[0]
    body = block.split("<<'EOF'", 1)[1].split("\nEOF", 1)[0]
    kv = {}
    for line in body.splitlines():
        if "=" in line and not line.strip().startswith("#"):
            k, v = line.split("=", 1)
            kv[k.strip()] = v.strip()
    assert kv["net.ipv4.tcp_congestion_control"] == "bbr" and kv["net.core.default_qdisc"] == "fq"
    assert kv["net.core.somaxconn"] == "65535" and kv["net.ipv4.tcp_keepalive_time"] == "300"
    assert kv["fs.file-max"] == "9223372036854775807" and "fs.nr_open" not in kv          # F31
    assert kv["net.ipv4.ip_local_port_range"] == "10240 65535"                            # F18: not widened
    assert "/etc/sysctl.d/999-pcdn.conf" in install and "rm -f /etc/sysctl.d/99-pcdn.conf" in install  # F30


@pytest.mark.skipif(shutil.which("nginx") is None, reason="nginx not installed")
def test_nginx_accepts_tunnel_config(tmp_path):
    from conftest import nginx_conf, modules_available
    if not modules_available():
        pytest.skip("nginx dynamic modules (njs, geoip2, image_filter, brotli) not installed")
    cert, key = self_signed(tmp_path)
    cfg = make_cfg(tmp_path, LISTEN_IPV6="no", HTTP_PORT="18780", HTTPS_PORT="18743")
    hosts = [{"name": "example.com", "origin": {"address": "127.0.0.1", "port": None}},
             {"name": "lb.example.com", "origin": {"pool": "main"}},
             {"name": "n.example.com", "origin": {"address": "origin.example.net", "port": 8080}}]
    sites = [dict(SITE, hosts=hosts, ssl={"cert": cert, "key": key}, pools=POOLS, tunnel=TUNNEL,
                  errorpages={"5xx": "<h1>down</h1>", "4xx": None}, image={"enabled": True},
                  pagerules={"rules": [{"id": "p", "pattern": "/svc/*", "cache": "bypass"}]}),
             dict(SITE, id=8, domain="b.com", hosts=[{"name": "b.com", "origin": {"address": "1.1.1.1", "port": None}}],
                  tunnel=dict(TUNNEL, fallback="decoy")),
             dict(SITE, id=9, domain="c.com", hosts=[{"name": "c.com", "origin": {"address": "1.1.1.1", "port": None}}],
                  tunnel=dict(TUNNEL, fallback="404", allowed_countries=[]))]
    assert agent.apply_config({"sites": sites}, cfg) is None
    conf = nginx_conf(tmp_path, cfg)
    p = subprocess.run(["nginx", "-t", "-c", str(conf)], capture_output=True, text=True)
    assert p.returncode == 0 and "[warn]" not in p.stderr, p.stderr


def test_tunnel_usage_aggregation(tmp_path):
    log = tmp_path / "access.log"
    base = {"t": "2026-09-28T10:05:00+00:00", "h": "example.com", "c": "", "ip": "1.2.3.4", "cc": "IR", "m": "GET",
            "ua": "Go-http-client/1.1", "v": "ok"}
    rows = [
        dict(base, s=101, u="/ws", tn="ws", rt=1800.25, b=5000, bu=300, ub="900000"),        # frames only in ub
        dict(base, s=200, u="/svc/Tun", tn="grpc", rt="600.5", b=7000, bu=40000, ub="40100"),
        dict(base, s=200, u="/xh/1", tn="xhttp", rt=0.2, b=100, bu=1000, ub="1100, 50"),      # retried upstream
        dict(base, s=403, u="/ws", tn="ws", rt=0, b=150, bu=200, ub=""),                     # refused: no session
        dict(base, s=200, u="/", tn="", rt=0.01, b=999, bu=80, ub="120"),                    # normal request
        dict(base, s=200, u="/old", b=10),                                                   # old log format
    ]
    log.write_text("".join(json.dumps(r) + "\n" for r in rows))
    state = {}
    agent.read_usage(state, str(log))
    [item] = agent.usage_items(state["pending"])
    assert item["requests"] == 6 and item["bytes"] == 5000 + 7000 + 100 + 150 + 999 + 10
    # F37: grpc/h2/xhttp bill $request_length ($bu); only ws/httpupgrade consult $upstream_bytes_sent
    assert item["tunnel"] == {"sessions": 3, "seconds": 2401, "bytes_up": 900000 + 40000 + 1000 + 200,
                              "bytes_down": 5000 + 7000 + 100 + 150,
                              "by_protocol": {"ws": 905000 + 350, "grpc": 47000, "xhttp": 1100}}
    json.dumps(state)  # the state file stays JSON
    no_tn = agent.usage_item("x.com|2026-09-28T10:00:00Z", {"bytes": 1, "requests": 1, "cache_hits": 0})
    assert "tunnel" not in no_tn


# ----------------------------------------------------------------- heartbeat metrics (SPEC §7.4)

PROC_DEV = """Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: {lo} 10 0 0 0 0 0 0 {lo} 10 0 0 0 0 0 0
  eth0: {rx} 100 0 0 0 0 0 0 {tx} 100 0 0 0 0 0 0
docker0: 999999999 1 0 0 0 0 0 0 999999999 1 0 0 0 0 0 0
vethab12: 999999999 1 0 0 0 0 0 0 999999999 1 0 0 0 0 0 0
"""
PROC_ROUTE = """Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
docker0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0
eth0\t00000000\t010200C0\t0003\t0\t0\t0\t00000000\t0\t0\t0
"""
PROC_TCP = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0000000000000000 100 0 0 10 0
   1: 0100007F:01BB 0200007F:C350 01 00000000:00000000 00:00000000 00000000     0        0 2 1 0000000000000000 20 4 30 10 -1
   2: 0100007F:0050 0200007F:C351 01 00000000:00000000 00:00000000 00000000     0        0 3 1 0000000000000000 20 4 30 10 -1
   3: 0100007F:C352 0200007F:01BB 01 00000000:00000000 00:00000000 00000000     0        0 4 1 0000000000000000 20 4 30 10 -1
   4: 0100007F:01BB 0200007F:C353 06 00000000:00000000 00:00000000 00000000     0        0 5 1 0000000000000000 20 4 30 10 -1
"""


def test_metrics_collection(tmp_path):
    dev, route, tcp = tmp_path / "dev", tmp_path / "route", tmp_path / "tcp"
    route.write_text(PROC_ROUTE)
    tcp.write_text(PROC_TCP)
    cfg = make_cfg(tmp_path, PROC_NET_DEV=str(dev), PROC_ROUTE=str(route), PROC_TCP=(str(tcp),),
                   HTTP_PORT="80", HTTPS_PORT="443")
    assert agent.default_iface(str(route)) == "eth0"
    dev.write_text(PROC_DEV.format(lo=5, rx=1000000, tx=2000000))
    prev = (100.0, agent.net_bytes("eth0", str(dev)))
    dev.write_text(PROC_DEV.format(lo=10**12, rx=1000000 + 12500000, tx=2000000 + 25000000))  # +100/+200 Mbit in 1 s
    cur = (101.0, agent.net_bytes("eth0", str(dev)))
    m = agent.collect_metrics(cfg, prev, cur)
    assert m["rx_mbps"] == 100.0 and m["tx_mbps"] == 200.0
    assert m["connections"] == 2  # ESTABLISHED on :443 / :80 only (not LISTEN, TIME_WAIT or outgoing)
    assert m["cpus"] >= 1 and m["load1"] >= 0
    # counter reset, missing files, no default route: never raises, zeros instead
    assert agent.collect_metrics(cfg, cur, (102.0, (0, 0)))["rx_mbps"] == 0
    bad = make_cfg(tmp_path, PROC_NET_DEV="/nonexistent", PROC_ROUTE="/nonexistent", PROC_TCP=("/nonexistent",))
    m = agent.collect_metrics(bad, None)
    assert m["rx_mbps"] == 0 and m["connections"] == 0
    # without a default route every non-virtual interface counts (not lo / docker / veth)
    assert agent.net_bytes(None, str(dev)) == (13500000, 27000000)
    # disk/mem are added from the real host and stay in a sane range
    assert 0 <= m2["disk_pct"] <= 100 if (m2 := agent.collect_metrics(cfg, None)).get("disk_pct") is not None else True


def test_disk_and_mem_pct(tmp_path):
    mi = tmp_path / "meminfo"
    mi.write_text("MemTotal:       8000000 kB\nMemFree:  1000000 kB\nMemAvailable: 2000000 kB\nBuffers: 5 kB\n")
    assert agent.mem_pct(str(mi)) == 75.0  # (8000000 - 2000000) / 8000000
    assert agent.mem_pct(str(tmp_path / "nope")) is None
    (tmp_path / "no_avail").write_text("MemTotal: 100 kB\n")
    assert agent.mem_pct(str(tmp_path / "no_avail")) is None  # old kernels without MemAvailable
    d = agent.disk_pct(str(tmp_path))
    assert d is not None and 0 <= d <= 100
    assert agent.disk_pct("/nonexistent/path/xyz") is None


def test_periodic_heartbeat_carries_metrics(tmp_path, monkeypatch):
    monkeypatch.setattr(agent.time, "sleep", lambda s: None)
    a = agent.Agent.__new__(agent.Agent)
    a.cfg, a.state = make_cfg(tmp_path, CONTROLLER_URL="http://x", EDGE_TOKEN="t"), {"version": "v1", "last_error": None}
    a.ctl, a.net_prev, a.last_heartbeat, a.last_usage = RecordingCtl(), None, 0.0, 10**12
    a.sync_config = a.sync_purges = lambda: None
    a.tick()
    [body] = a.ctl.bodies
    assert body["applied_version"] == "v1" and body["error"] is None
    assert {"rx_mbps", "tx_mbps", "connections", "load1", "cpus"} <= set(body["metrics"])
    assert set(body["metrics"]) <= {"rx_mbps", "tx_mbps", "connections", "load1", "cpus", "disk_pct",
                                    "mem_pct", "draining_workers", "sock_tcp", "sock_tw"}
    assert body["geoip"] is False  # F9: no GeoIP DB in the unit-test cfg
    a.tick()  # within HEARTBEAT_INTERVAL: nothing new
    assert len(a.ctl.bodies) == 1
    a.ctl = RecordingCtl(fail=True)
    a.last_heartbeat = 0
    a.tick()  # controller down: logged, never raised


# ---------------------------------------------------------------- centralized logs (SPEC §11.2)

def test_parse_error_lines_filters_levels():
    text = (
        "2026/09/30 10:00:00 [error] 12#0: *5 upstream timed out\n"
        "2026/09/30 10:00:01 [warn] 12#0: *6 using stale response\n"
        "2026/09/30 10:00:02 [crit] 12#0: *7 SSL_do_handshake failed\n"
        "2026/09/30 10:00:03 [notice] 12#0: signal process started\n"   # dropped (not warn+)
        "2026/09/30 10:00:04 [info] 12#0: something\n"                    # dropped
        "a malformed line with no timestamp\n"                            # dropped
    )
    out = agent.parse_error_lines(text)
    assert [l["level"] for l in out] == ["error", "warn", "crit"]
    assert out[0]["msg"] == "upstream timed out"


def test_redact_strips_ips_and_tokens():
    r = agent.redact("connect() to 10.1.2.3:80 failed, client: 8.8.8.8, token edge_abc123def456")
    assert "10.1.2.3" not in r and "8.8.8.8" not in r
    assert "edge_abc123def456" not in r and "[ip]" in r
    r6 = agent.redact("peer 2a01:4f8:abcd:1234::10 closed")
    assert "2a01:4f8" not in r6 and "[ip]" in r6


def test_read_error_log_tracks_offset(tmp_path):
    p = tmp_path / "error.log"
    p.write_text("2026/09/30 10:00:00 [error] 1#0: *1 first problem\n")
    st = {}
    first = agent.read_error_log(st, str(p))
    assert [l["msg"] for l in first] == ["first problem"]
    # nothing new -> empty on the next read (offset advanced)
    assert agent.read_error_log(st, str(p)) == []
    # append a new line -> only that one comes back
    with open(p, "a") as f:
        f.write("2026/09/30 10:00:05 [warn] 1#0: *2 second problem\n")
    again = agent.read_error_log(st, str(p))
    assert [l["msg"] for l in again] == ["second problem"]


def test_collect_logs_dedup_and_cap(tmp_path):
    p = tmp_path / "error.log"
    lines = "".join(f"2026/09/30 10:00:{i:02d} [error] 1#0: *{i} problem-{i}\n" for i in range(50))
    p.write_text(lines)
    cfg = make_cfg(tmp_path)
    st = {}
    out = agent.collect_logs(st, cfg)
    assert len(out) <= agent.LOG_MAX_PER_REPORT  # capped at 40/report
    # an identical repeating line is not re-sent next cycle
    with open(p, "a") as f:
        f.write("2026/09/30 10:01:00 [error] 1#0: *99 problem-49\n")  # same msg text as one just sent
    out2 = agent.collect_logs(st, cfg)
    assert all("problem-49" != l["msg"] for l in out2) or out2 == []


def test_collect_logs_failsoft_missing_file(tmp_path):
    cfg = make_cfg(tmp_path, ERROR_LOG=str(tmp_path / "nope.log"))
    assert agent.collect_logs({}, cfg) == []


def test_bundle_version_from_file_and_fallback(tmp_path):
    cfg = make_cfg(tmp_path)
    assert agent.bundle_version(cfg).startswith("agent-")  # no file -> agent hash fallback
    vf = tmp_path / "bundle.version"
    vf.write_text("deadbeef1234\n")
    assert agent.bundle_version(cfg) == "deadbeef1234"
