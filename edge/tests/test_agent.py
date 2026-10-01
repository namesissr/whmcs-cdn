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
        # deterministic capabilities: today's distro build (nginx 1.24, all modules, no HTTP/3)
        "NGINX_CAPS": dict(agent.LEGACY_CAPS, nginx="1.24.0"),
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


def _sysctl_kv(tmp_path, tcp_cc):
    """Run install.sh's sysctl heredoc (it expands ${TCP_CC}) and parse what it writes."""
    install = (HERE.parent / "install.sh").read_text()
    block = install.split("# >>> pcdn sysctl", 1)[1].split("\n", 1)[1].split("# <<< pcdn sysctl", 1)[0]
    out = tmp_path / f"999-pcdn-{tcp_cc}.conf"
    subprocess.run(["bash", "-euc", block.replace("/etc/sysctl.d/999-pcdn.conf", str(out))],
                   check=True, env={"TCP_CC": tcp_cc, "PATH": os.environ.get("PATH", "/usr/bin:/bin")})
    kv = {}
    for line in out.read_text().splitlines():
        if "=" in line and not line.strip().startswith("#"):
            k, v = line.split("=", 1)
            kv[k.strip()] = v.strip()
    return kv


def test_sysctl_heredoc(tmp_path):
    install = (HERE.parent / "install.sh").read_text()
    kv = _sysctl_kv(tmp_path, "bbr")
    assert kv["net.ipv4.tcp_congestion_control"] == "bbr" and kv["net.core.default_qdisc"] == "fq"
    # SPEC §14.1 --cc: the heredoc writes the chosen algorithm; nothing else in it is expanded
    cubic = _sysctl_kv(tmp_path, "cubic")
    assert cubic["net.ipv4.tcp_congestion_control"] == "cubic"
    assert {k: v for k, v in cubic.items() if k != "net.ipv4.tcp_congestion_control"} == \
        {k: v for k, v in kv.items() if k != "net.ipv4.tcp_congestion_control"}
    assert 'TCP_CC="${TCP_CC:-bbr}"' in install and "--cc must be bbr or cubic" in install
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


# ----------------------------------------------------------------- Wave 6A: edge performance & cache (SPEC §14.1)

V_UBUNTU = """nginx version: nginx/1.24.0 (Ubuntu)
built with OpenSSL 3.0.13 30 Jan 2024
TLS SNI support enabled
configure arguments: --with-cc-opt='-g -O2' --prefix=/usr/share/nginx --conf-path=/etc/nginx/nginx.conf --modules-path=/usr/lib/nginx/modules --with-http_ssl_module --with-http_v2_module --with-http_geoip_module=dynamic --with-http_image_filter_module=dynamic --with-stream=dynamic
"""
V_NGINX_ORG = """nginx version: nginx/1.29.1
built by gcc 13.2.0 (Ubuntu 13.2.0-23ubuntu4)
built with OpenSSL 3.0.13 30 Jan 2024
TLS SNI support enabled
configure arguments: --prefix=/etc/nginx --sbin-path=/usr/sbin/nginx --modules-path=/usr/lib/nginx/modules --conf-path=/etc/nginx/nginx.conf --with-http_ssl_module --with-http_v2_module --with-http_v3_module --with-stream --with-cc-opt='-g -O2'
"""


def caps_cfg(tmp_path, **kw):
    """make_cfg with capability overrides (lower-case keys) and cfg overrides (UPPER-CASE keys)."""
    over = {k: v for k, v in kw.items() if k.isupper()}
    caps = dict(agent.LEGACY_CAPS, nginx="1.24.0")
    caps.update({k: v for k, v in kw.items() if not k.isupper()})
    return make_cfg(tmp_path, NGINX_CAPS=caps, **over)


H3 = {"nginx": "1.29.1", "http3": True, "early_hints": True, "http2_directive": True}


def directives(text):
    """Config text without comment lines (the template documents the directives it guards)."""
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
ORG_MODULES = ["image_filter", "njs"]


def test_parse_nginx_v_capabilities():
    present = {"/usr/lib/nginx/modules/" + so for so in agent.MODULE_FILES.values()}
    c = agent.parse_nginx_v(V_UBUNTU, exists=lambda p: p in present)
    assert c["nginx"] == "1.24.0" and c["http3"] is False and c["early_hints"] is False
    assert c["http2_directive"] is False and c["webp_convert"] is False and c["webp_mode"] == "accept_key"
    assert c["modules"] == ["brotli", "geoip2", "image_filter", "njs"]
    # nginx.org mainline: HTTP/3 + early hints, only njs / image-filter module files present
    org = {"/usr/lib/nginx/modules/ngx_http_js_module.so", "/usr/lib/nginx/modules/ngx_http_image_filter_module.so"}
    c = agent.parse_nginx_v(V_NGINX_ORG, exists=lambda p: p in org)
    assert c["nginx"] == "1.29.1" and c["http3"] and c["early_hints"] and c["http2_directive"]
    assert c["modules"] == ORG_MODULES
    # http3 needs the module AND >= 1.25.1; early_hints >= 1.29.0
    v3 = lambda ver: V_NGINX_ORG.replace("nginx/1.29.1", f"nginx/{ver}")  # noqa: E731
    assert not agent.parse_nginx_v(v3("1.25.0"), exists=lambda p: False)["http3"]
    c = agent.parse_nginx_v(v3("1.27.4"), exists=lambda p: False)
    assert c["http3"] and not c["early_hints"]
    assert agent.parse_nginx_v(v3("1.29.0"), exists=lambda p: False)["early_hints"]
    no_v3 = agent.parse_nginx_v(V_NGINX_ORG.replace(" --with-http_v3_module", ""), exists=lambda p: False)
    assert not no_v3["http3"] and no_v3["early_hints"]
    # a lookalike flag is not the module
    assert not agent.parse_nginx_v(V_NGINX_ORG.replace("--with-http_v3_module", "--with-http_v3_modulex"),
                                   exists=lambda p: False)["http3"]
    # statically compiled modules count without a .so; =dynamic needs the file
    static = V_UBUNTU.replace("--with-http_image_filter_module=dynamic",
                              "--with-http_image_filter_module --add-module=/build/ngx_brotli")
    assert agent.parse_nginx_v(static, exists=lambda p: False)["modules"] == ["brotli", "image_filter"]
    assert agent.parse_nginx_v(V_UBUNTU, exists=lambda p: False)["modules"] == []
    # an explicit modules dir wins over --modules-path
    c = agent.parse_nginx_v(V_UBUNTU, "/opt/mods", exists=lambda p: p == "/opt/mods/ngx_http_js_module.so")
    assert c["modules"] == ["njs"]
    # unparseable output (nginx missing): today's distro build is assumed
    assert agent.parse_nginx_v("") == dict(agent.LEGACY_CAPS)


def test_nginx_capabilities_probed_once(tmp_path, monkeypatch):
    monkeypatch.setattr(agent, "_CAPS_CACHE", {})
    calls, fake = tmp_path / "calls", tmp_path / "nginx"
    out = tmp_path / "v.txt"
    out.write_text(V_NGINX_ORG)
    fake.write_text(f"#!/bin/sh\necho x >> {calls}\ncat {out} >&2\n")
    fake.chmod(0o755)
    (tmp_path / "mods").mkdir()
    (tmp_path / "mods/ngx_http_js_module.so").write_bytes(b"")
    cfg = dict(agent.DEFAULTS, NGINX_BIN=str(fake), NGINX_MODULES_DIR=str(tmp_path / "mods"))
    for _ in range(3):
        c = agent.nginx_capabilities(cfg)
    assert calls.read_text().count("x") == 1                      # once per agent start
    assert c["http3"] and c["modules"] == ["njs"] and agent.has_module(cfg, "njs")
    assert not agent.has_module(cfg, "geoip2")
    # nginx not installed / not runnable -> legacy assumption, never an exception
    assert agent.nginx_capabilities(dict(cfg, NGINX_BIN=str(tmp_path / "nope")))["modules"] == sorted(agent.MODULE_FILES)
    # the capabilities are part of render_rev: an nginx swap (install.sh --http3) forces a re-render
    a, b = caps_cfg(tmp_path), caps_cfg(tmp_path, **H3)
    assert agent.render_rev(a) != agent.render_rev(b) and agent.render_rev(a) == agent.render_rev(caps_cfg(tmp_path))


def test_heartbeat_reports_capabilities(tmp_path):
    a = agent.Agent.__new__(agent.Agent)
    a.cfg = caps_cfg(tmp_path, modules=ORG_MODULES, **H3)
    body = a._hb(applied_version="v1")
    assert body["capabilities"] == {"http3": True, "early_hints": True, "webp_convert": False,
                                    "webp_mode": "accept_key", "modules": ORG_MODULES, "nginx": "1.29.1",
                                    "waf_packs": agent.WAF_PACK_VERSIONS,
                                    "live_analytics": True, "logship": True}   # SPEC §14.3
    json.dumps(body)


def h3_site(cert, key, **over):
    return dict(SITE, hosts=[{"name": "example.com", "origin": {"address": "127.0.0.1", "port": 18080}}],
                ssl={"cert": cert, "key": key}, **over)


def test_http3_rendered_only_when_capable_and_enabled(tmp_path):
    cert, key = self_signed(tmp_path)
    site = h3_site(cert, key)
    alt = "add_header Alt-Svc 'h3=\":443\"; ma=86400' always;"
    # capable node: default server owns `quic reuseport`, sites add plain `quic` + http3 + Alt-Svc
    cfg = caps_cfg(tmp_path, **H3)
    http = agent.render_http(cfg)
    assert "    listen 443 quic default_server reuseport;\n    listen [::]:443 quic default_server reuseport;" in http
    assert "listen 443 ssl default_server reuseport" in http and "http2 on;" in http and "ssl http2" not in http
    text, _ = agent.render_site(site, cfg)
    assert "    listen 443 ssl;\n    listen [::]:443 ssl;\n    http2 on;\n    listen 443 quic;\n" \
           "    listen [::]:443 quic;\n    http3 on;\n    " + alt in text
    assert text.count("quic reuseport") == 0
    loc = text.split("    location / {", 1)[1]
    assert alt in loc                       # locations with add_header repeat it (no inheritance)
    # IPv6 off: no [::] quic listener
    assert "[::]" not in agent.render_http(caps_cfg(tmp_path, LISTEN_IPV6="no", **H3))
    # site toggle off (in the ssl section the edge receives as ssl_options)
    off, _ = agent.render_site(dict(site, ssl_options=dict(SITE["ssl_options"], http3=False)), cfg)
    assert not re.search(r" quic[ ;]|http3 on|Alt-Svc", off) and "http2 on;" in off
    # a site without a certificate never gets h3
    nocert, _ = agent.render_site(dict(site, ssl=None), cfg)
    assert not re.search(r" quic[ ;]|http3 on|Alt-Svc", nocert)
    # non-capable node (nginx 1.24): nothing h3-related anywhere, listen ... http2 as before
    legacy = caps_cfg(tmp_path)
    t2, _ = agent.render_site(site, legacy)
    http2 = directives(agent.render_http(legacy))
    for s in (t2, http2):
        assert not re.search(r" quic[ ;]|http3 on|\$http3|Alt-Svc|http2 on", s)
    assert "listen 443 ssl http2;" in t2 and "listen 443 ssl http2 default_server" in http2
    assert "{{" not in http and "{{" not in http2


def test_module_guards(tmp_path):
    db = tmp_path / "geo.mmdb"
    db.write_bytes(b"x")
    site = dict(SITE, tunnel=TUNNEL, pools=POOLS, image={"enabled": True},
                hosts=[{"name": "example.com", "origin": {"address": "127.0.0.1", "port": 18080}}])
    full = caps_cfg(tmp_path, GEOIP_DB=str(db))
    http = agent.render_http(full)
    assert "geoip2 " in http and "brotli on;" in http and "js_import" in http and "image_filter resize" in http
    assert not re.search(r"^# @(?:if|else|endif) ", http, re.M)     # every guard resolved
    text, _ = agent.render_site(site, full)
    assert "brotli off;" in text and "js_content pcdn.deny" in text and "/__pcdn/img/" in text
    assert "$pcdn_tcc_7" in text
    # nginx.org build: njs + image_filter only. GeoIP DB present but no module -> no geoip2 directives
    # and the tunnel country gate fails open; no brotli directives anywhere
    org = caps_cfg(tmp_path, GEOIP_DB=str(db), modules=ORG_MODULES)
    assert not agent.geoip_present(org)
    http = directives(agent.render_http(org))
    assert "geoip2" not in http and "map $host $pcdn_country" in http and "brotli" not in http
    assert "js_import" in http and "image_filter resize" in http
    text, _ = agent.render_site(site, org)
    assert "brotli" not in text and "$pcdn_tcc_7" not in text and "js_content pcdn.deny" in text
    # nothing optional at all: njs fallbacks keep the variables defined, no js_* / image_filter
    bare = caps_cfg(tmp_path, modules=[])
    http = directives(agent.render_http(bare))
    assert "js_" not in http and "image_filter" not in http and "brotli" not in http
    assert "map $uri $pcdn_verdict {\n    default \"ok\";\n}" in http
    text, _ = agent.render_site(site, bare)
    assert "js_content" not in text and "location ^~ /__pcdn/deny/ { internal; return 403; }" in text
    assert "/__pcdn/img/" not in text and "$pcdn_img_w" not in text


@pytest.mark.skipif(shutil.which("nginx") is None, reason="nginx not installed")
@pytest.mark.parametrize("mods", [ORG_MODULES, []])
def test_nginx_accepts_config_without_optional_modules(tmp_path, mods):
    """nginx.org-like build (njs + image_filter, no geoip2 / brotli) and a build with no optional
    module at all both pass a real `nginx -t` with everything enabled."""
    from conftest import nginx_conf, modules_available
    if not modules_available():
        pytest.skip("nginx dynamic modules not installed")
    cert, key = self_signed(tmp_path)
    db = tmp_path / "geo.mmdb"
    db.write_bytes(b"x")  # a DB without the module must not render geoip2
    cfg = caps_cfg(tmp_path, LISTEN_IPV6="no", HTTP_PORT="18880", HTTPS_PORT="18843", GEOIP_DB=str(db), modules=mods)
    site = dict(SITE, hosts=[{"name": "example.com", "origin": {"address": "127.0.0.1", "port": None}},
                             {"name": "lb.example.com", "origin": {"pool": "main"}}],
                ssl={"cert": cert, "key": key}, pools=POOLS, tunnel=TUNNEL, image={"enabled": True, "auto_webp": True},
                errorpages={"5xx": "<h1>down</h1>"},
                cache=dict(SITE["cache"], shield=True, key_device=True, key_cookies=["lang"]),
                pagerules={"rules": [{"id": "p", "pattern": "/", "preload": [{"url": "/a.css", "as": "style"}]}]})
    shield = {"self": False, "peers": ["10.0.0.1"], "secret": "ab" * 16}
    assert agent.apply_config({"sites": [site], "shield": shield}, cfg) is None
    so = {"njs": "ngx_http_js_module.so", "image_filter": "ngx_http_image_filter_module.so"}
    conf = nginx_conf(tmp_path, cfg, modules=[so[m] for m in mods])
    p = subprocess.run(["nginx", "-t", "-c", str(conf)], capture_output=True, text=True)
    assert p.returncode == 0 and "[warn]" not in p.stderr, p.stderr


SHIELD_SECRET = "0123456789abcdef" * 2


def shield_site(**cache):
    return dict(SITE, hosts=[{"name": "example.com", "origin": {"address": "127.0.0.1", "port": 18080}}],
                cache=dict(SITE["cache"], shield=True, **cache), errorpages={"5xx": "<h1>down</h1>", "4xx": "<h1>no</h1>"},
                pagerules={"rules": [{"id": "p1", "pattern": "/wp-admin/*", "cache": "bypass"}]})


def test_norm_shield():
    ok = {"self": False, "peers": ["10.0.0.2", "10.0.0.1", "10.0.0.1", "2001:DB8::1", "x; evil", "0.0.0.0", 5],
          "secret": SHIELD_SECRET.upper()}
    assert agent.norm_shield({"shield": ok}) == {"self": False, "peers": ["10.0.0.1", "10.0.0.2", "[2001:db8::1]"],
                                                 "secret": SHIELD_SECRET}
    assert agent.norm_shield({}) is None and agent.norm_shield({"shield": "x"}) is None
    assert agent.norm_shield({"shield": dict(ok, secret="short")}) is None
    assert agent.norm_shield({"shield": dict(ok, secret='a"; }')}) is None
    assert agent.norm_shield({"shield": dict(ok, peers=[])}) is None       # nothing to send misses to
    # a shield never re-shields: its peers are ignored
    assert agent.norm_shield({"shield": dict(ok, self=True)}) == {"self": True, "peers": [], "secret": SHIELD_SECRET}


def test_shield_render_edge_node(tmp_path):
    cfg = make_cfg(tmp_path, SHIELD_HTTPS_PORT="8443")
    cert, key = self_signed(tmp_path)
    tls = dict(shield_site(), id=9, domain="tls.example.com", ssl={"cert": cert, "key": key},
               hosts=[{"name": "tls.example.com", "origin": {"address": "127.0.0.1", "port": 18080}}])
    config = {"sites": [shield_site(), dict(SITE, id=8, domain="b.com", hosts=[{"name": "b.com", "origin": "1.1.1.1"}]),
                        tls],
              "shield": {"self": False, "peers": ["10.0.0.2", "10.0.0.1"], "secret": SHIELD_SECRET}}
    files = agent.render_all(config, cfg)
    sh = files["shield.conf"]
    # the hop is TLS only: one upstream, on the peers' HTTPS port
    assert "upstream pcdn_shield_https {\n    hash $pcdn_ck consistent;\n    server 10.0.0.1:8443 max_fails=1 " in sh
    assert "pcdn_shield_http " not in sh and ":80 " not in sh
    assert f'geo $pcdn_shield_secret {{\n    default "{SHIELD_SECRET}";\n}}' in sh
    assert "$pcdn_shield_ok" in sh and "pcdn_gate" not in sh
    assert f"include {cfg['NGINX_DIR']}/shield.conf;" in files["http.conf"]
    # an HTTP-only site (no certificate) never shields: straight to the origin, no secret sent
    plain = files["sites/7.conf"]
    assert "pcdn_shield" not in plain and "$pcdn_sh_skip" not in plain and "@pcdn_origin_" not in plain
    assert plain.count('proxy_set_header X-Pcdn-Shield "";') == plain.count("proxy_pass $pcdn_proto://$pcdn_target;")
    # a site with a certificate hops over TLS, verified against $host
    text = files["sites/9.conf"]
    for f in files.values():
        assert SHIELD_SECRET not in f or f is sh                             # only in the 0600 file
    static = text.split("    location ~* \\.(?:css", 1)[1].split("\n    }\n", 1)[0]
    assert "if ($pcdn_sh_skip) { return 418; }" in static
    assert 'set $pcdn_ck "$scheme://$host$request_uri";' in static
    assert "proxy_set_header X-Pcdn-Shield $pcdn_shield_secret;" in static
    assert "proxy_set_header Host $host;" in static                          # Host preserved
    assert "error_page 418 502 504 = @pcdn_origin_" in static and "proxy_intercept_errors off;" in static
    assert "error_page 500 503 /__pcdn/err/5xx.html;" in static              # custom pages kept
    assert "error_page 400 403 404 405 410 /__pcdn/err/4xx.html;" in static
    assert "proxy_hide_header X-Cache;" in static and "proxy_hide_header X-Served-By;" in static
    assert "proxy_hide_header Strict-Transport-Security;" in static
    assert "proxy_pass https://pcdn_shield_https;" in static and "proxy_ssl_verify on;" in static
    assert "proxy_ssl_session_reuse off;" in static      # never resume another site's TLS session
    assert f"proxy_ssl_trusted_certificate {cfg['CA_BUNDLE']};" in static and "proxy_ssl_name $host;" in static
    assert "proxy_cache pcdn_9;" in static and "proxy_cache_key $scheme://$host$request_uri;" in static
    name = re.search(r"error_page 418 502 504 = (@pcdn_origin_\d+);", static).group(1)
    fb = text.split(f"    location {name} {{", 1)[1].split("\n    }\n", 1)[0]
    assert 'proxy_set_header X-Pcdn-Shield "";' in fb and "proxy_pass $pcdn_proto://$pcdn_target;" in fb
    assert "proxy_cache pcdn_9;" in fb and "pcdn_shield" not in fb
    # a bypass page rule is never shielded; the dynamic catch-all is
    wp = text.split('location ~ "^/wp\\-admin/.*$" {', 1)[1].split("\n    }\n", 1)[0]
    assert "pcdn_shield" not in wp and 'proxy_set_header X-Pcdn-Shield "";' in wp
    assert text.count("proxy_pass https://pcdn_shield_https;") == 2
    # a site without cache.shield only strips the header
    other = files["sites/8.conf"]
    assert "pcdn_shield" not in other and 'proxy_set_header X-Pcdn-Shield "";' in other
    # the file holding the secret is root-only
    agent.write_tree(str(tmp_path / "tree"), files)
    assert oct((tmp_path / "tree/shield.conf").stat().st_mode & 0o777) == "0o600"
    # a customer request header can never set or clear the shield header
    s2, _ = agent.render_site(dict(tls, headers={"request": [{"name": "X-Pcdn-Shield", "value": "x"}]}),
                              cfg, agent.norm_shield(config))
    assert 'X-Pcdn-Shield "x"' not in s2 and "pcdn_shield_https" in s2
    # cache off -> never shielded
    s3, _ = agent.render_site(dict(tls, cache=dict(SITE["cache"], enabled=False, shield=True)),
                              cfg, agent.norm_shield(config))
    assert "pcdn_shield" not in s3


def test_shield_render_shield_node(tmp_path):
    cfg = make_cfg(tmp_path)
    config = {"sites": [shield_site()], "shield": {"self": True, "peers": ["10.0.0.1"], "secret": SHIELD_SECRET}}
    files = agent.render_all(config, cfg)
    sh = files["shield.conf"]
    # accepted only over TLS: a valid header on a plain-HTTP connection is an ordinary visitor
    assert f'map "$https:$http_x_pcdn_shield" $pcdn_shield_ok {{\n    default 0;\n    "on:{SHIELD_SECRET}" 1;\n}}' in sh
    assert "upstream" not in sh and "$pcdn_gate" in sh and "$pcdn_log_ok" in sh
    text = files["sites/7.conf"]
    assert "pcdn_shield_https" not in text and "$pcdn_sh_skip" not in text   # never re-shields
    # valid hops skip the verdict and the access log; visitor address/scheme come from the edge
    assert 'if ($pcdn_gate !~ "^(?:ok|log:)") { rewrite ^ /__pcdn/deny/$pcdn_gate? last; }' in text
    assert "pcdn buffer=64k flush=1s if=$pcdn_log_ok;" in text
    assert "proxy_set_header X-Real-IP $pcdn_client_ip;" in text and "proxy_set_header X-Forwarded-For $pcdn_xff;" in text
    assert "proxy_set_header X-Forwarded-Proto $pcdn_scheme;" in text
    assert 'proxy_set_header X-Pcdn-Shield "";' in text               # stripped before the origin
    assert "proxy_cache_key $pcdn_scheme://$host$request_uri;" in text
    assert SHIELD_SECRET not in text
    # no shield section -> no shield.conf, today's rendering (digest-stable)
    plain = agent.render_all({"sites": [shield_site()]}, cfg)
    assert "shield.conf" not in plain and "pcdn_shield_secret" not in plain["sites/7.conf"]
    assert 'proxy_set_header X-Pcdn-Shield "";' in plain["sites/7.conf"]   # stripped on every node
    assert "map $uri $pcdn_shield_ok {\n    default 0;\n}" in plain["http.conf"]
    # shield.conf is node-global: a peer/secret change is never deferred as a foreign-group edit (F21)
    other = agent.render_all(dict(config, shield=dict(config["shield"], secret="f" * 32)), cfg)
    assert agent.global_digest(other) != agent.global_digest(files)
    assert agent.site_digests(other) == agent.site_digests(files)


def test_stale_mapping(tmp_path):
    cfg = make_cfg(tmp_path)

    def loc(**cache):
        text, _ = agent.render_site(dict(SITE, cache=dict(SITE["cache"], **cache)), cfg)
        return text.split("    location / {", 1)[1].split("\n    }", 1)[0]
    default = loc()
    assert "proxy_cache_use_stale error timeout updating http_500 http_502 http_503 http_504;" in default
    assert "proxy_cache_background_update on;" in default
    assert loc(stale_while_revalidate=True, stale_if_error=86400) == default   # explicit defaults: same
    no_swr = loc(stale_while_revalidate=False)
    assert "proxy_cache_use_stale error timeout http_500 http_502 http_503 http_504;" in no_swr
    assert "background_update" not in no_swr
    assert "proxy_cache_use_stale updating;" in loc(stale_if_error=0)
    assert "proxy_cache_use_stale off;" in loc(stale_if_error=0, stale_while_revalidate=False)
    assert "proxy_cache_use_stale updating;" in loc(always_online=False, stale_if_error=600)
    assert "proxy_cache_use_stale error timeout updating" in loc(stale_if_error="junk")   # defensive
    # origin Cache-Control (incl. stale-* extensions) stays honoured where it was
    assert "proxy_ignore_headers" not in default


def test_cache_key_options(tmp_path):
    cfg = make_cfg(tmp_path)
    plain, _ = agent.render_site(SITE, cfg)
    assert "proxy_cache_key $scheme://$host$request_uri;" in plain and ";d=" not in plain
    site = dict(SITE, cache=dict(SITE["cache"], key_device=True,
                                 key_cookies=["lang", "wp-lang", "bad cookie", 'x";', "lang"] + [f"c{i}" for i in range(20)],
                                 key_query_allow=["v", "utm.x", "a&b", "$x", "f[c]"]),
                pagerules={"rules": [{"id": "p", "pattern": "/iq/*", "ignore_query": True, "cache": "standard"}]})
    text, _ = agent.render_site(site, cfg)
    k = agent.key_options(site)
    assert k["cookies"][:2] == ["lang", "wp-lang"] and len(k["cookies"]) == 10 and k["qa"] == ["v", "utm.x", "f[c]"]
    assert "bad cookie" not in text and 'x";' not in text and "a&b" not in text
    # names that are not nginx variable suffixes are read through a regex map
    assert 'map $http_cookie $pcdn_kc_7_1 {\n    default "";\n    "~*(?:^|;)\\s*wp\\-lang=([^;]*)" $1;\n}' in text
    assert 'map $args $pcdn_ka_7_1 {\n    default "";\n    "~*(?:^|&)utm\\.x=([^&]*)" $1;\n}' in text
    assert 'map $args $pcdn_ka_7_2 {\n    default "";\n    "~*(?:^|&)f\\[c\\]=([^&]*)" $1;\n}' in text
    key = ('"$scheme://$host$pcdn_path?v=${arg_v}&utm.x=${pcdn_ka_7_1}&f[c]=${pcdn_ka_7_2};d=${pcdn_dev};'
           'c.lang=${cookie_lang};c.wp-lang=${pcdn_kc_7_1};c.c0=${cookie_c0}')
    root = text.split("    location / {", 1)[1].split("\n    }", 1)[0]
    assert f"proxy_cache_key {key}" in root
    # a page rule with ignore_query drops the query entirely, variants stay
    iq = text.split('location ~ "^/iq/.*$" {', 1)[1].split("\n    }", 1)[0]
    assert 'proxy_cache_key "$scheme://$host$pcdn_path;d=${pcdn_dev};c.lang=' in iq
    # site ignore_query wins over key_query_allow (the controller rejects the combination)
    t2, _ = agent.render_site(dict(SITE, cache=dict(SITE["cache"], ignore_query=True, key_query_allow=["v"])), cfg)
    assert "proxy_cache_key $scheme://$host$pcdn_path;" in t2 and "arg_v" not in t2
    # the agent records the key shape for exact-URL purges (only sites that need it)
    infos = agent.key_infos({"sites": [site, SITE]})
    assert list(infos) == ["7"] and infos["7"]["dev"] and infos["7"]["qa"] == ["v", "utm.x", "f[c]"]


def test_purge_variant_keys(tmp_path):
    cfg = make_cfg(tmp_path)
    base = os.path.join(cfg["CACHE_DIR"], "7")
    kinfo = {"dev": True, "cookies": [], "qa": ["v"], "webp": True}
    keys = [f"https://example.com/a.png?v=1;d={d};w={w}" for d in ("mobile", "desktop") for w in ("0", "1")]
    paths = []
    for k in keys + ["https://example.com/other.png?v=1;d=mobile;w=0"]:
        p = pathlib.Path(agent.cache_file(cfg["CACHE_DIR"], 7, k))
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("x")
        paths.append(p)
    # the purged URL carries extra / reordered params: the key_query_allow form is derived from it
    assert agent.do_purge({"site_id": 7, "urls": ["https://example.com/a.png?utm=1&V=1&v=2"]}, cfg, kinfo) == 4
    assert not any(p.exists() for p in paths[:4]) and paths[4].exists()
    # cookie-keyed variants cannot be enumerated: the cache is scanned for "<url>;<fields>"
    ck = {"dev": False, "cookies": ["lang"], "qa": [], "webp": False}
    a = _fake_cache_file(base, "http://example.com/p;x?q=1;c.lang=fa")
    b = _fake_cache_file(base, "http://example.com/p;x?q=1;c.lang=en")
    c = _fake_cache_file(base, "http://example.com/p;x?q=2;c.lang=en")
    assert agent.do_purge({"site_id": 7, "urls": ["http://example.com/p;x?q=1"]}, cfg, ck) == 2
    assert not a.exists() and not b.exists() and c.exists()
    # without key info the hashed fast path is unchanged
    assert agent.key_suffixes(None) == [""] and agent.url_key_bases("/a?b=1", None) == ["/a?b=1", "/a"]


def test_agent_records_keyinfo_and_passes_it_to_purges(tmp_path):
    cfg = make_cfg(tmp_path)
    site = dict(MINSITE, cache={"enabled": True, "key_device": True})
    a = agent.Agent.__new__(agent.Agent)
    a.cfg, a.state, a.ctl = cfg, {}, SeqCtl()
    a.ctl.serve("v1", "e1", [site])
    a.sync_config()
    assert a.state["keyinfo"] == {"1": {"dev": True, "cookies": [], "qa": [], "webp": False}}
    for d in ("mobile", "desktop"):
        p = pathlib.Path(agent.cache_file(cfg["CACHE_DIR"], 1, f"http://a.com/x;d={d}"))
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("x")
    a.state["purge_id"] = 0
    a.ctl = FakeCtl([{"id": 1, "site_id": 1, "domain": "a.com", "urls": ["http://a.com/x"]}])
    a.sync_purges()
    assert not pathlib.Path(agent.cache_file(cfg["CACHE_DIR"], 1, "http://a.com/x;d=mobile")).exists()
    assert not pathlib.Path(agent.cache_file(cfg["CACHE_DIR"], 1, "http://a.com/x;d=desktop")).exists()


def test_webp_accept_key_mode(tmp_path):
    cfg = make_cfg(tmp_path)
    assert agent.nginx_capabilities(cfg)["webp_convert"] is False   # image_filter keeps the input format
    site = dict(SITE, image={"enabled": True, "auto_webp": True})
    text, _ = agent.render_site(site, cfg)
    static = text.split("    location ~* \\.(?:css", 1)[1].split("\n    }", 1)[0]
    assert 'proxy_cache_key "$scheme://$host$request_uri;w=${pcdn_webp}";' in static
    assert "add_header Vary $pcdn_webp_vary;" in static
    img = text.split("    location ^~ /__pcdn/img/ {", 1)[1].split("\n    }", 1)[0]
    assert ";w=${pcdn_webp}" in img and "add_header Vary $pcdn_webp_vary;" in img
    assert "proxy_set_header Accept" not in text            # the client's Accept goes to the origin
    http = agent.render_http(cfg)
    assert '"~*\\.(?:jpe?g|png)$" $pcdn_accept_webp;' in http and '"~*image/webp" 1;' in http
    # independent of the resize toggle (the controller folds the plan gate into auto_webp)
    t1, _ = agent.render_site(dict(SITE, image={"enabled": False, "auto_webp": True}), cfg)
    assert ";w=${pcdn_webp}" in t1 and "/__pcdn/img/" not in t1
    # off (or a decoy tunnel site that never fetches origin content) -> unchanged rendering
    for s in (dict(SITE, image={"enabled": True}), dict(SITE, image={"enabled": True, "auto_webp": False}),
              dict(SITE, image={"auto_webp": True}, tunnel=dict(TUNNEL, fallback="decoy"))):
        t2, _ = agent.render_site(s, cfg)
        assert "pcdn_webp" not in t2


def test_preload_links(tmp_path):
    cfg = make_cfg(tmp_path)
    bad = ['/x"y', "/x\ny", "/x\r\n", "/a b", "/<x>", "/x'", "javascript:alert(1)", "//evil.com/x", "/x\\y", "", None]
    rule = {"id": "p", "pattern": "/", "preload": (
        [{"url": u, "as": "style"} for u in bad[:9]]
        + [{"url": "/a.css", "as": "style"}, {"url": "/f.woff2", "as": "font"}, {"url": "/a.css", "as": "evil"},
           {"url": "https://cdn.example.com/x.js?v=$1", "as": "script"}, "junk"])}
    assert agent.preload_links(rule) == ["</a.css>; rel=preload; as=style"]   # only the first 10 entries count
    assert not agent.preload_links({"preload": [{"url": u, "as": "style"} for u in bad]})
    rule["preload"] = rule["preload"][9:]
    links = agent.preload_links(rule)
    assert links == ["</a.css>; rel=preload; as=style", "</f.woff2>; rel=preload; as=font; crossorigin",
                     "<https://cdn.example.com/x.js?v=$1>; rel=preload; as=script"]
    site = dict(SITE, pagerules={"rules": [rule, {"id": "b", "pattern": "/blog/*", "preload": [{"url": "/b.js", "as": "script"}]},
                                           {"id": "c", "pattern": "/nopre/*", "cache": "bypass"}]})
    text, _ = agent.render_site(site, cfg)
    assert ('map $uri $pcdn_link_7 {\n    default "";\n    "~^/$" "</a.css>; rel=preload; as=style, '
            '</f.woff2>; rel=preload; as=font; crossorigin, <https://cdn.example.com/x.js?v=${pcdn_dollar}1>; '
            'rel=preload; as=script";\n    "~^/blog/.*$" "</b.js>; rel=preload; as=script";\n}') in text
    # preload-only rules add no location (static files keep their own location); headers everywhere
    assert 'location ~ "^/$"' not in text and 'location ~ "^/blog/.*$"' not in text
    assert text.count("add_header Link $pcdn_link_7;") == text.count("proxy_pass $pcdn_proto://$pcdn_target;")
    assert "early_hints" not in text
    # 103 Early Hints only on capable nodes (nginx relays an origin's 103 to HTTP/2+ navigations)
    eh, _ = agent.render_site(site, caps_cfg(tmp_path, **H3))
    assert "early_hints $pcdn_early_hints;" in eh
    http = agent.render_http(caps_cfg(tmp_path, **H3))
    assert "map $http_sec_fetch_mode $pcdn_early_hints {\n    default \"\";\n    navigate $http2$http3;\n}" in http
    assert "$http3" not in agent.render_http(caps_cfg(tmp_path, nginx="1.29.0", early_hints=True))
    assert "pcdn_early_hints" not in agent.render_http(cfg)
    # no preload -> no map / header
    assert "pcdn_link" not in agent.render_site(SITE, cfg)[0]


def test_new_fields_absent_or_default_keep_rendering(tmp_path):
    """SPEC §14.1 fields missing or at their defaults leave a site's config byte-identical, so a
    controller upgrade alone never triggers a reload."""
    cfg = make_cfg(tmp_path)
    cert, key = self_signed(tmp_path)
    base = dict(SITE, ssl={"cert": cert, "key": key}, image={"enabled": True},
                pagerules={"rules": [{"id": "p", "pattern": "/a/*", "cache": "everything"}]})
    explicit = dict(base, cache=dict(SITE["cache"], stale_while_revalidate=True, stale_if_error=86400, shield=False,
                                     key_device=False, key_cookies=[], key_query_allow=[]),
                    ssl_options=dict(SITE["ssl_options"], http3=True), image={"enabled": True, "auto_webp": False},
                    pagerules={"rules": [{"id": "p", "pattern": "/a/*", "cache": "everything", "preload": []}]})
    assert agent.render_site(base, cfg) == agent.render_site(explicit, cfg)
    f1 = agent.render_all({"sites": [base]}, cfg)
    f2 = agent.render_all({"sites": [explicit], "shield": None}, cfg)
    assert agent.tree_digest(f1) == agent.tree_digest(f2)


def _install_block(start, end):
    install = (HERE.parent / "install.sh").read_text()
    return install.split(start, 1)[1].split(end, 1)[0]


def test_install_upgrade_roundtrip_new_keys(tmp_path):
    """install.sh writes TCP_CC / HTTP3 to agent.conf and --upgrade reads them back (flags win)."""
    conf = tmp_path / "agent.conf"
    write = "cat > /etc/pcdn/agent.conf <<EOF" + _install_block("cat > /etc/pcdn/agent.conf <<EOF", "\nEOF") + "\nEOF\n"
    upgrade = ('if [ "$UPGRADE" = yes ]; then' + _install_block('if [ "$UPGRADE" = yes ]; then', 'HTTP3="${HTTP3:-no}"')
               + 'HTTP3="${HTTP3:-no}"\n')

    def run(script, **env):
        base = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "CONTROLLER": "", "TOKEN": "", "REGION": "",
                "ROLE": "", "UPGRADE": "yes", "TCP_CC": "", "HTTP3": ""}
        base.update(env)
        script = script.replace("/etc/pcdn/agent.conf", str(conf))
        return subprocess.run(["bash", "-euc", script + '\necho "CC=$TCP_CC H3=$HTTP3"'], env=base,
                              capture_output=True, text=True, check=True).stdout.strip().splitlines()[-1]
    run(write, CONTROLLER="https://c", TOKEN="t", NGINX_USER="www-data", IPV6="yes", CACHE_SIZE="10g",
        HTTP_PORT="80", HTTPS_PORT="443", TCP_CC="cubic", HTTP3="yes")
    text = conf.read_text()
    assert "TCP_CC=cubic\n" in text and "HTTP3=yes\n" in text
    assert run(upgrade) == "CC=cubic H3=yes"                         # read back
    assert run(upgrade, TCP_CC="bbr", HTTP3="no") == "CC=bbr H3=no"  # explicit flags win
    conf.write_text("CONTROLLER_URL=https://c\nEDGE_TOKEN=t\n")       # an older install: defaults
    assert run(upgrade) == "CC=bbr H3=no"
    conf.write_text("CONTROLLER_URL=https://c\nEDGE_TOKEN=t\nTCP_CC=reno\nHTTP3=maybe\n")   # junk ignored
    assert run(upgrade) == "CC=bbr H3=no"


def test_install_http3_load_module_block(tmp_path):
    """--http3 writes one load_module line per optional module file present (idempotent) and warns
    about geoip2 / brotli being unavailable."""
    block = _install_block("# >>> pcdn load_module", "# <<< pcdn load_module").split("\n", 1)[1]
    mods = tmp_path / "modules"
    mods.mkdir()
    for so in ("ngx_http_js_module.so", "ngx_http_image_filter_module.so"):
        (mods / so).write_bytes(b"")
    ngx = tmp_path / "nginx.conf"
    ngx.write_text("user nginx;\nworker_processes auto;\nevents { worker_connections 1024; }\nhttp { }\n")
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HTTP3": "yes", "MODULES_DIR": str(mods)}
    script = block.replace("/etc/nginx/nginx.conf", str(ngx))
    outs = [subprocess.run(["bash", "-euc", script], env=env, capture_output=True, text=True, check=True).stdout
            for _ in range(2)]
    text = ngx.read_text()
    assert text.count(f"load_module {mods}/ngx_http_js_module.so;") == 1
    assert text.count(f"load_module {mods}/ngx_http_image_filter_module.so;") == 1
    assert "geoip2_module" not in text and "brotli" not in text and text.index("load_module") < text.index("user nginx;")
    assert "warning: no geoip2 module" in outs[0] and "warning: no brotli module" in outs[0]
    # the distro path never touches nginx.conf here
    subprocess.run(["bash", "-euc", script], env=dict(env, HTTP3="no"), check=True)
    assert ngx.read_text() == text
    install = (HERE.parent / "install.sh").read_text()
    assert "https://nginx.org/packages/mainline/$NGINX_DISTRO $CODENAME nginx" in install
    assert "NGINX_KEY_FPR=573BFD6B3D8FBC641079A6ABABF5BD827BD9BF62" in install
    assert "nginx nginx-module-njs nginx-module-image-filter" in install
    assert 'allow UDP/$HTTPS_PORT' in install
    boot = (HERE.parent / "bootstrap.sh").read_text()
    assert "--http3|--no-http3" in boot and "|--cc)" in boot


# ----------------------------------------------------------------- SPEC §14.2 rules & security

def rd(rid, source, match, target, status=301, preserve_query=False, enabled=True):
    return {"id": rid, "enabled": enabled, "source": source, "match": match, "target": target, "status": status,
            "preserve_query": preserve_query}


def site_6b(**over):
    s = dict(SITE, hosts=[{"name": "example.com", "origin": {"address": "127.0.0.1", "port": 18080}}])
    s.update(over)
    return s


def test_redirect_rules_render(tmp_path):
    rules = [rd("a", "/old", "exact", "https://new.example/p"),
             rd("b", "/About", "exact", "/about", 308),
             rd("c", "/about", "exact", "/x", 302),                         # case collision -> ordered regex
             rd("d", "/blog/", "prefix", "https://b.example/?s=1#top", 302, True),
             rd("e", r"^/p/(\d+)/(.*)$", "regex", "/post/$2?id=$1", 307, True),
             rd("f", "/p/1/x", "exact", "/never", 301),                     # shadowed by the earlier regex
             rd("g", "/k", "exact", "/kept", 301, True),
             rd("h", "/" + "a" * 120, "exact", "/long", 301),               # too long for the hash
             rd("off", "/off", "exact", "/x", 301, enabled=False)]
    text, _ = agent.render_site(site_6b(redirects={"rules": rules}), make_cfg(tmp_path))
    h = text.split("map $pcdn_path $pcdn_rdh_7 {", 1)[1].split("}", 1)[0]
    assert '"/old" "/old 301https://new.example/p";' in h
    assert '"/About" "/About 308/about";' in h and '"/k" "/k 301/kept$is_args$args";' in h
    assert "/about\" " not in h and "/never" not in text and "/off" not in text and "/p/1/x" not in h
    assert 'map "$pcdn_path $pcdn_rdh_7" $pcdn_rde_7 {\n    default "";\n    "~^(\\\\S+) \\\\1 (.+)$" $2;\n}' in text
    c = text.split("map $pcdn_path $pcdn_rdc_7 {", 1)[1].split("\n}", 1)[0]
    lines = [x.strip() for x in c.strip().splitlines()]
    assert lines == ['default "";', '"~^/__pcdn/" "";', '"~^/about$" "302/x";',
                     '"~^/blog/" "302https://b.example/?s=1$pcdn_args_amp#top";',
                     '"~^/p/(\\\\d+)/(.*)$" "307/post/$2?id=$1$pcdn_args_amp";', '"~^/' + "a" * 120 + '$" "301/long";']
    assert "map $pcdn_rde_7 $pcdn_rd_7 {\n    \"~.\" $pcdn_rde_7;\n    default $pcdn_rdc_7;\n}" in text
    # one return per status in use, after the security verdict, before any location
    srv = text.split("server_name example.com;", 1)[1]
    for code in (301, 302, 307, 308):
        assert f'    if ($pcdn_rd_7 ~ "^{code}(.*)$") {{ return {code} $1; }}' in srv
    assert srv.index("$pcdn_verdict !~") < srv.index("$pcdn_rd_7 ~ \"^301") < srv.index("    location ^~ /__pcdn/ {")
    # only exact rules -> the confirmed hash alone; only regex rules -> the ordered map alone
    t2, _ = agent.render_site(site_6b(redirects={"rules": [rd("a", "/x", "exact", "/y")]}), make_cfg(tmp_path))
    assert "$pcdn_rdc_7" not in t2 and 'if ($pcdn_rde_7 ~ "^301(.*)$") { return 301 $1; }' in t2
    t3, _ = agent.render_site(site_6b(redirects={"rules": [rd("a", "^/x", "regex", "/y", 302)]}), make_cfg(tmp_path))
    assert "$pcdn_rdh_7" not in t3 and 'if ($pcdn_rdc_7 ~ "^302(.*)$") { return 302 $1; }' in t3


def test_redirect_rules_revalidated(tmp_path):
    bad = [rd("a", "/a", "exact", 'https://e.example/"; return 200 x'),     # quote
           rd("b", "/b", "exact", "https://e.example/\r\nSet-Cookie: x=1"),  # CR/LF
           rd("c", "/c", "exact", "/x/$1"),                                  # $1 without a regex
           rd("d", r"^/d/(\d+)$", "regex", "/x/$2"),                        # group that does not exist
           rd("e", "/e", "exact", "//evil.example/"),                       # protocol-relative
           rd("f", "/f", "exact", "javascript:alert(1)"),
           rd("g", "/g", "exact", "/x", 303),                               # status not allowed
           rd("h", "/__pcdn/verify", "exact", "/x"),                        # internal endpoint
           rd("i", "/tun/x", "prefix", "/x"),                               # under a tunnel path
           rd("j", "/j\"", "exact", "/x"), rd("k", "no-slash", "exact", "/x"),
           rd("l", r"(?a)^/l", "regex", "/x"), rd("m", r"^/m\N{DIGIT ONE}", "regex", "/x"),
           rd("n", "^/n(", "regex", "/x"), rd("o", "/o", "exact", "/x\\y"), rd("BAD ID", "/p", "exact", "/x"),
           rd("q", "/q", "exact", "/x", True)]                             # bool is not a status
    tunnel = dict(TUNNEL, paths=[{"id": "t", "path": "/tun", "protocol": "ws"}])
    assert agent.norm_redirects(site_6b(redirects={"rules": bad}), ["/tun"]) == []
    text, _ = agent.render_site(site_6b(redirects={"rules": bad + [rd("ok", "^/(.*)$", "regex", "/n/$1")]},
                                        tunnel=tunnel), make_cfg(tmp_path))
    assert "$pcdn_rdh_7" not in text and "evil" not in text and "Set-Cookie: x" not in text
    assert '    "~^(?:/tun)" "";\n' in text               # tunnel prefixes are never redirected


def tfr(actions, path="/*", methods=(), countries=(), enabled=True):
    return {"id": "r", "enabled": enabled, "match": {"path": path, "methods": list(methods), "countries": list(countries)},
            "actions": [dict({"name": None, "value": None, "regex": None, "replacement": None}, **a) for a in actions]}


def test_transform_rules_render(tmp_path):
    cfg = make_cfg(tmp_path)
    rules = [tfr([{"type": "set_request_header", "name": "X-All", "value": 'a$b"c'},
                  {"type": "remove_request_header", "name": "X-Drop"},
                  {"type": "set_response_header", "name": "X-Frame-Options", "value": "DENY"},
                  {"type": "remove_response_header", "name": "Server"}]),
             tfr([{"type": "set_request_header", "name": "X-Static", "value": "t"},
                  {"type": "remove_request_header", "name": "Cookie"},
                  {"type": "remove_response_header", "name": "Set-Cookie"},
                  {"type": "rewrite_path", "regex": r"^/api/(.*)$", "replacement": "/v2/$1"}],
                 path="/api/*", methods=["post", "PUT"], countries=["ir"]),
             tfr([{"type": "rewrite_path", "regex": r"^/q/(\d+)$", "replacement": "/item?id=$1"}])]
    site = site_6b(transform={"rules": rules}, headers={"request": [{"name": "X-Static", "value": "s"}],
                                                        "response": [{"name": "X-Frame-Options", "value": "SAMEORIGIN"}]})
    files = agent.render_all({"sites": [site]}, cfg)
    text = files["sites/7.conf"]
    assert ('map "$request_method|$pcdn_country|$pcdn_shield_ok|$pcdn_ouri" $pcdn_tf_7_1 {\n'
            '    "~(?s)^(?:POST|PUT)[|](?:IR)[|]0[|]/api/.*$" 1;\n    default 0;\n}') in text
    assert "$pcdn_tf_7_0" not in text and "$pcdn_tf_7_2" not in text          # unconditional rules: no flag
    assert "map $pcdn_tf_7_1 $pcdn_tq_7_2_0 {\n    1 \"t\";\n    default \"s\";\n}" in text   # static value as base
    assert "map $pcdn_tf_7_1 $pcdn_tq_7_3_0 {\n    1 \"\";\n    default $http_cookie;\n}" in text
    # rewrite_path: regex on the raw path, first matching rule wins, never on a shield hop
    assert ('map $pcdn_path $pcdn_tfr_7_0 {\n    default $pcdn_tfu_7_1;\n    "~^/api/(.*)$" "/v2/$1$is_args$args";\n}'
            in text)
    assert 'map $pcdn_path $pcdn_tfr_7_1 {\n    default "";\n    "~^/q/(\\\\d+)$" "/item?id=$1$pcdn_args_amp";\n}' in text
    assert "map $pcdn_tf_7_1 $pcdn_tfu_7_0 {\n    1 $pcdn_tfr_7_0;\n    default $pcdn_tfu_7_1;\n}" in text
    assert "map $pcdn_shield_ok $pcdn_tfu_7_1 {\n    0 $pcdn_tfr_7_1;\n    default \"\";\n}" in text
    srv = text.split("server {", 1)[1]
    assert "    set $pcdn_ouri $uri;\n" in srv
    n_proxy = srv.count("proxy_pass ")
    assert n_proxy == srv.count("$pcdn_tfu_7_0;") and n_proxy >= 2       # every web location
    for loc in srv.split("    location ")[1:]:
        if "proxy_pass" not in loc:
            continue
        assert 'proxy_set_header X-All "a${pcdn_dollar}b\\"c";' in loc and 'proxy_set_header X-Drop "";' in loc
        assert "proxy_set_header X-Static $pcdn_tq_7_2_0;" in loc and "proxy_set_header Cookie $pcdn_tq_7_3_0;" in loc
        assert loc.count("X-Static") == 1                                 # the static entry is replaced
        assert "proxy_hide_header X-Frame-Options;" in loc and 'add_header X-Frame-Options "DENY" always;' in loc
        assert "SAMEORIGIN" not in loc and "proxy_hide_header Server;" in loc
        assert "js_header_filter pcdn.tfHeaders;" in loc
    js = json.loads(files["js/sites.js"].split("export default ", 1)[1].rstrip().rstrip(";"))["7"]
    assert js["tf_resp"] == [{"f": "pcdn_tf_7_1", "op": "del", "n": "Set-Cookie"}]


def test_transform_tunnel_paths_untouched(tmp_path):
    site = site_6b(transform={"rules": [tfr([{"type": "set_request_header", "name": "X-T", "value": "1"},
                                             {"type": "rewrite_path", "regex": "^/(.*)$", "replacement": "/x/$1"}])]},
                   tunnel=dict(TUNNEL, paths=[{"id": "t", "path": "/tun", "protocol": "ws"},
                                              {"id": "g", "path": "/grpc.S", "protocol": "grpc"}]))
    text, _ = agent.render_site(site, make_cfg(tmp_path))
    for loc in text.split("    location ^~ ")[1:]:
        if loc.startswith(('"/tun"', '"/grpc.S"')):
            body = loc.split("\n    }", 1)[0]
            assert "X-T" not in body and "pcdn_tfu" not in body


def test_transform_rules_revalidated(tmp_path):
    bad = [{"type": "set_request_header", "name": n, "value": "x"}
           for n in ("Host", "Connection", "X-Pcdn-Shield", "X-Forwarded-For", "X-Real-IP", "Proxy-Authorization",
                     "Cookie", "Content-Length", "Bad Name", "Transfer-Encoding")]
    bad += [{"type": "set_response_header", "name": "Set-Cookie", "value": "a=1"},
            {"type": "set_request_header", "name": "X-Nl", "value": "a\r\nb: c"},
            {"type": "set_request_header", "name": "X-Long", "value": "x" * 1025},
            {"type": "rewrite_path", "regex": "^/(.*)$", "replacement": "/__pcdn/img/$1"},
            {"type": "rewrite_path", "regex": "^/(.*)$", "replacement": "//evil/$1"},
            {"type": "rewrite_path", "regex": "^/(.*)$", "replacement": "/x/$2"},
            {"type": "rewrite_path", "regex": "^/(.*)$", "replacement": "/x/\"y"},
            {"type": "rewrite_path", "regex": "(?u)^/x", "replacement": "/y"},
            {"type": "unknown", "name": "X-A", "value": "1"}]
    assert agent.norm_transform(site_6b(transform={"rules": [tfr(bad)]})) == []
    ok = [{"type": "remove_request_header", "name": "Cookie"}, {"type": "remove_response_header", "name": "Set-Cookie"}]
    assert len(agent.norm_transform(site_6b(transform={"rules": [tfr(ok)]}))[0]["actions"]) == 2
    # a condition the edge cannot understand skips the whole rule (never widens it)
    for m in ({"path": "no-slash"}, {"methods": ["GET;"]}, {"countries": ["IRN"]}, {"methods": "GET"}):
        r = tfr(ok)
        r["match"] = m
        assert agent.norm_transform(site_6b(transform={"rules": [r]})) == []
    assert agent.norm_transform(site_6b(transform={"rules": [tfr(ok, enabled=False)]})) == []
    text, _ = agent.render_site(site_6b(transform={"rules": [tfr(bad)]}), make_cfg(tmp_path))
    assert "evil" not in text and "__pcdn/img/$1" not in text and "X-Nl" not in text and "pcdn_tf" not in text


def test_waf_packs_and_body_inspection_render(tmp_path):
    cfg = make_cfg(tmp_path)
    waf = {"mode": "block", "paranoia": 1, "groups": ["sqli"], "packs": ["wordpress", "bogus", "laravel", "wordpress"]}
    files = agent.render_all({"sites": [site_6b(waf=waf)]}, cfg)
    js = json.loads(files["js/sites.js"].split("export default ", 1)[1].rstrip().rstrip(";"))["7"]
    assert js["waf"]["packs"] == ["wordpress", "laravel"]
    text = files["sites/7.conf"]
    assert "    if ($pcdn_bodychk) { rewrite ^ /__pcdn/body$uri last; }" in text
    assert ("location ^~ /__pcdn/body/ { internal; client_max_body_size 131072; client_body_buffer_size 131072; "
            "client_body_in_single_buffer on; js_content pcdn.bodyInspect; }") in text
    body = text.split("    location @pcdn_body {", 1)[1].split("\n    }", 1)[0]
    assert "proxy_pass $pcdn_proto://$pcdn_target$request_uri;" in body and "proxy_cache " not in body
    assert "js_set $pcdn_bodychk pcdn.bodyNeed;" in files["http.conf"] and "js_var $pcdn_wafskip;" in files["http.conf"]
    # no body packs, WAF off, or no njs -> no body routing at all
    for w in (dict(waf, packs=["laravel"]), dict(waf, mode="off"), dict(waf, packs=[])):
        t, _ = agent.render_site(site_6b(waf=w), cfg)
        assert "pcdn_bodychk" not in t and "@pcdn_body" not in t
    t, _ = agent.render_site(site_6b(waf=waf), make_cfg(tmp_path, NGINX_CAPS=dict(agent.LEGACY_CAPS, modules=["geoip2"])))
    assert "pcdn_bodychk" not in t
    # the agent's pack catalog mirrors njs/pcdn.js
    src = (HERE.parent / "njs/pcdn.js").read_text()
    m = re.search(r"const WAF_PACK_VERSION = (\{[^}]*\});", src)
    assert json.loads(re.sub(r"(\w+):", r'"\1":', m.group(1))) == agent.WAF_PACK_VERSIONS
    assert tuple(agent.WAF_PACK_VERSIONS) == agent.WAF_PACKS
    assert f"const BODY_CAP = {agent.BODY_CAP};" in src


def test_bot_ranges_render(tmp_path):
    cfg = make_cfg(tmp_path)
    ranges = {"verified": {"google": ["66.249.66.0/27", "66.249.66.1/27", "2001:4860:4801:10::/64", "10.0.0.0/8",
                                      "bad", "1.2.3.4/33", '1.1.1.1/32"; }'],
                           "bing": ["157.55.39.0/24", "66.249.66.0/27"], "yandex": ["5.255.0.0/16"]},
              "fetched_at": "2026-10-01T00:00:00Z"}
    assert agent.norm_bot_ranges({"bots": ranges}) == {"google": ["66.249.66.0/27", "2001:4860:4801:10::/64"],
                                                     "bing": ["157.55.39.0/24"]}
    bsite = site_6b(bots={"mode": "challenge", "allow_verified": True, "block_empty_ua": False})
    files = agent.render_all({"sites": [bsite], "bots": ranges}, cfg)
    assert files["bots.conf"] == ('# verified crawler ranges (SPEC §14.2) — generated by pcdn-agent, do not edit\n'
                                  'geo $pcdn_vbot {\n    default "0gb";\n    66.249.66.0/27 "1gb";\n'
                                  '    2001:4860:4801:10::/64 "1gb";\n    157.55.39.0/24 "2gb";\n}\n')
    assert f"include {cfg['NGINX_DIR']}/bots.conf;" in files["http.conf"]
    js = json.loads(files["js/sites.js"].split("export default ", 1)[1].rstrip().rstrip(";"))["7"]
    assert js["bots"] == {"mode": "challenge", "allow_verified": True, "block_empty_ua": False}
    agent.write_tree(str(tmp_path / "t"), files)
    assert oct((tmp_path / "t/bots.conf").stat().st_mode & 0o777) == "0o644"
    # only google ranges: bing crawlers fail open ("0g" lists the known engines)
    one = agent.render_all({"sites": [bsite], "bots": {"verified": {"google": ["66.249.66.0/27"]}}}, cfg)
    assert '    default "0g";\n    66.249.66.0/27 "1g";' in one["bots.conf"]
    # nothing received, or no site using bot management: no bots.conf, $pcdn_vbot is "" (fail open)
    for config in ({"sites": [bsite], "bots": {"verified": {}, "fetched_at": None}},
                   {"sites": [site_6b()], "bots": ranges}, {"sites": [site_6b(bots={"mode": "off"})], "bots": ranges}):
        f = agent.render_all(config, cfg)
        assert "bots.conf" not in f and 'geo $pcdn_vbot {\n    default "";\n}' in f["http.conf"]
    assert agent.global_digest(files) != agent.global_digest(one)    # a range change is never deferred


def test_bot_ranges_cached_by_the_agent(tmp_path):
    ranges = {"google": ["66.249.66.0/27"], "bing": ["157.55.39.0/24"]}
    st = {}
    body = {"version": "v1", "sites": [], "bots": {"verified": ranges, "fetched_at": "x"}}
    assert agent.with_cached_bot_ranges(body, st) is body and st["bot_ranges"] == ranges
    # the controller sends none (or only one engine): the last good lists are used
    b2 = agent.with_cached_bot_ranges({"version": "v2", "sites": [], "bots": {"verified": {}, "fetched_at": None}}, st)
    assert b2["bots"]["verified"] == ranges
    b3 = agent.with_cached_bot_ranges({"version": "v3", "sites": [], "bots": {"verified": {"google": ["66.249.70.0/27"]}}}, st)
    assert b3["bots"]["verified"] == {"google": ["66.249.70.0/27"], "bing": ["157.55.39.0/24"]}
    # never received anything: nothing invented (fail open)
    st2 = {}
    b4 = {"version": "v", "sites": []}
    assert agent.with_cached_bot_ranges(b4, st2) is b4 and "bot_ranges" not in st2


def test_bot_ranges_dropped_by_controller_do_not_reload(tmp_path):
    """F20 diff-skip keeps working: a config whose ranges vanished renders identically from the cache."""
    counter = tmp_path / "reloads"
    cfg = make_cfg(tmp_path, NGINX_RELOAD_CMD=f"sh -c 'echo x >> {counter}'")
    bsite = dict(MINSITE, bots={"mode": "block"})
    bodies = [{"version": "v1", "sites": [bsite], "bots": {"verified": {"google": ["66.249.66.0/27"]}}},
              {"version": "v2", "sites": [bsite], "bots": {"verified": {}, "fetched_at": None}}]

    class C:
        def call(self, method, path, body=None, headers=None, timeout=30):
            if path == "/edge/v1/config":
                b = bodies.pop(0)
                return 200, {"ETag": b["version"]}, b
            return 200, {}, None
    a = agent.Agent.__new__(agent.Agent)
    a.cfg, a.state, a.ctl = cfg, {}, C()
    a.sync_config()
    a.sync_config()
    assert counter.read_text().count("x") == 1 and a.state["version"] == "v2"
    assert "66.249.66.0/27" in (pathlib.Path(cfg["NGINX_DIR"]) / "bots.conf").read_text()


def test_origin_pull_render(tmp_path):
    cfg = make_cfg(tmp_path)
    crt, key = self_signed(tmp_path)
    https = {"origin_protocol": "https", "force_https": False}
    plat = site_6b(ssl_options=dict(https, origin_client={"mode": "platform"}), image={"enabled": True})
    cust = site_6b(id=8, domain="b.com", hosts=[{"name": "b.com", "origin": {"address": "10.0.0.2", "port": 443}}],
                   ssl_options=dict(https, origin_client={"mode": "custom", "cert": crt, "key": key}))
    http = site_6b(id=9, domain="c.com", hosts=[{"name": "c.com", "origin": {"address": "10.0.0.3", "port": 80}}],
                   ssl_options={"origin_protocol": "http", "origin_client_auth": "platform"})
    off = site_6b(id=10, domain="d.com", hosts=[{"name": "d.com", "origin": {"address": "10.0.0.4", "port": 443}}],
                  ssl_options=dict(https, origin_client={"mode": "custom", "cert": "junk", "key": key}))
    config = {"sites": [plat, cust, http, off], "origin_pull": {"cert": crt, "key": key}}
    files = agent.render_all(config, cfg)
    d = cfg["NGINX_DIR"]
    assert files["mtls/platform.crt"] == crt and files["mtls/platform.key"] == key
    assert files["mtls/8.crt"] == crt and files["mtls/8.key"] == key and "mtls/10.crt" not in files
    p7 = files["sites/7.conf"]
    for loc in p7.split("    location ")[1:]:
        if "proxy_pass $pcdn_proto://" in loc:
            assert f"proxy_ssl_certificate {d}/mtls/platform.crt;" in loc
            assert f"proxy_ssl_certificate_key {d}/mtls/platform.key;" in loc
    tok = agent.mtls_token("platform", (crt, key))
    assert re.fullmatch(r"platform-[0-9a-f]{32}", tok) and f"proxy_set_header X-Pcdn-Mtls {tok};" in p7   # resizer hop
    assert f"proxy_ssl_certificate {d}/mtls/8.crt;" in files["sites/8.conf"]
    assert "proxy_ssl_certificate" not in files["sites/9.conf"]              # plain-HTTP origin: nothing
    assert "proxy_ssl_certificate" not in files["sites/10.conf"]             # unusable custom pair: off
    mt = files["mtls.conf"]
    assert f'    "{tok}" "data:$pcdn_mc_platform_0";' in mt and '"data:$pcdn_mk_platform_0"' in mt
    assert '"platform" ' not in mt                                        # never selectable by a bare name
    assert f"include {d}/mtls.conf;" in files["http.conf"]
    assert "proxy_ssl_certificate $pcdn_mtls_crt;" in files["http.conf"]    # resizer
    agent.write_tree(str(tmp_path / "t"), files)
    for rel in ("mtls/platform.crt", "mtls/platform.key", "mtls/8.crt", "mtls/8.key", "mtls.conf"):
        assert oct((tmp_path / "t" / rel).stat().st_mode & 0o777) == "0o600", rel
    assert oct((tmp_path / "t/mtls").stat().st_mode & 0o777) == "0o700"
    assert "8" in agent.site_digests(files) and agent.site_digests(files)["8"] != agent.site_digests(
        agent.render_all(dict(config, sites=[plat, dict(cust, ssl_options=dict(https))]), cfg)).get("8")
    # platform mode without the node's pair renders nothing (nginx would not start otherwise); a
    # pair nobody uses is not written
    f2 = agent.render_all({"sites": [plat]}, cfg)
    assert "mtls/platform.crt" not in f2 and "proxy_ssl_certificate " not in f2["sites/7.conf"]
    f3 = agent.render_all({"sites": [http], "origin_pull": {"cert": crt, "key": key}}, cfg)
    assert not [k for k in f3 if k.startswith("mtls")] and 'map $uri $pcdn_mtls_crt {\n    default "";\n}' in f3["http.conf"]
    # long PEMs are split over several variables (nginx caps one config token at 4 KiB)
    big = agent.render_mtls_resizer({"7": (crt * 8, key)})
    assert "$pcdn_mc_7_0$pcdn_mc_7_1" in big and all(len(t) < 4000 for t in re.findall(r'"([^"]*)"', big))


def test_origin_pull_never_on_the_shield_hop(tmp_path):
    cfg = make_cfg(tmp_path)
    crt, key = self_signed(tmp_path)
    site = dict(shield_site(), ssl={"cert": crt, "key": key},
                ssl_options={"origin_protocol": "https", "origin_client": {"mode": "platform"}})
    config = {"sites": [site], "shield": {"self": False, "peers": ["10.0.0.1"], "secret": SHIELD_SECRET},
              "origin_pull": {"cert": crt, "key": key}}
    text = agent.render_all(config, cfg)["sites/7.conf"]
    for loc in text.split("    location ")[1:]:
        if "proxy_pass https://pcdn_shield_https" in loc:
            assert "proxy_ssl_certificate " not in loc                      # the edge -> shield hop
        elif "proxy_pass $pcdn_proto://" in loc:
            assert "proxy_ssl_certificate " in loc                          # origin fallback / bypass


def test_6b_fields_absent_or_default_keep_rendering(tmp_path):
    """SPEC §14.2 fields missing or at their defaults leave a site's config and sites.js entry
    byte-identical, so a controller upgrade alone never triggers a reload."""
    cfg = make_cfg(tmp_path)
    cert, key = self_signed(tmp_path)
    base = dict(SITE, ssl={"cert": cert, "key": key}, image={"enabled": True},
                waf={"mode": "block", "paranoia": 1, "groups": ["sqli"]},
                pagerules={"rules": [{"id": "p", "pattern": "/a/*", "cache": "everything"}]})
    explicit = dict(base, waf=dict(base["waf"], packs=[]), transform={"rules": []}, redirects={"rules": []},
                    bots={"mode": "off", "allow_verified": True, "block_empty_ua": True},
                    ssl_options=dict(SITE["ssl_options"], origin_client_auth="off", origin_client={"mode": "off"}))
    assert agent.render_site(base, cfg) == agent.render_site(explicit, cfg)
    f1 = agent.render_all({"sites": [base]}, cfg)
    f2 = agent.render_all({"sites": [explicit], "bots": {"verified": {}, "fetched_at": None}, "origin_pull": None}, cfg)
    assert agent.tree_digest(f1) == agent.tree_digest(f2)
    # node-wide blocks nobody uses do not change the tree either
    f3 = agent.render_all({"sites": [explicit], "bots": {"verified": {"google": ["66.249.66.0/27"]}},
                           "origin_pull": {"cert": cert, "key": key}}, cfg)
    assert agent.tree_digest(f1) == agent.tree_digest(f3)


@pytest.mark.skipif(shutil.which("nginx") is None, reason="nginx not installed")
def test_nginx_accepts_6b_config(tmp_path):
    from conftest import nginx_conf, modules_available
    if not modules_available():
        pytest.skip("nginx dynamic modules (njs, geoip2, image_filter, brotli) not installed")
    cert, key = self_signed(tmp_path)
    cfg = make_cfg(tmp_path, LISTEN_IPV6="no", HTTP_PORT="18680", HTTPS_PORT="18643")
    site = dict(SITE, ssl={"cert": cert, "key": key}, image={"enabled": True},
                hosts=[{"name": "example.com", "origin": {"address": "127.0.0.1", "port": 443}},
                       {"name": "lb.example.com", "origin": {"pool": "main"}}],
                pools={"pools": [{"name": "main", "protocol": "https", "origins": [{"address": "10.0.0.1", "port": 443}]}]},
                ssl_options={"origin_protocol": "https", "origin_client": {"mode": "platform"}},
                waf={"mode": "detect", "paranoia": 3, "groups": ["sqli"], "packs": list(agent.WAF_PACKS)},
                bots={"mode": "challenge"}, tunnel=dict(TUNNEL, paths=[{"id": "t", "path": "/tun", "protocol": "ws"}]),
                transform={"rules": [tfr([{"type": "set_request_header", "name": "X-A", "value": "1"},
                                          {"type": "remove_response_header", "name": "Set-Cookie"},
                                          {"type": "rewrite_path", "regex": r"^/a/(\d+)", "replacement": "/b?x=$1"}],
                                         path="/a/*", methods=["GET"], countries=["IR"])]},
                redirects={"rules": [rd("a", "/x", "exact", "/y", 301, True), rd("b", "/p/", "prefix", "https://e.example/", 302),
                                     rd("c", r"^/r/(\w+)$", "regex", "/s/$1", 307, True),
                                     rd("d", "/%D8%B3%D9%84%D8%A7%D9%85", "exact", "/fa", 308)]})
    config = {"sites": [site], "bots": {"verified": {"google": ["66.249.66.0/27", "2001:4860:4801:10::/64"]}},
              "origin_pull": {"cert": cert, "key": key}}
    assert agent.apply_config(config, cfg) is None
    p = subprocess.run(["nginx", "-t", "-c", str(nginx_conf(tmp_path, cfg))], capture_output=True, text=True)
    assert p.returncode == 0 and "[warn]" not in p.stderr, p.stderr


def test_bot_and_pack_verdicts_become_security_events():
    pending, events = {}, []
    for v in ("block:bots:spoofed", "challenge:bots:library", "log:bots:empty_ua", "block:waf:991100"):
        agent._account({"t": "2026-10-01T10:00:00+00:00", "h": "a.com", "b": 10, "s": 403, "u": "/x", "v": v,
                        "ip": "1.2.3.4", "m": "GET", "ua": "curl/8"}, pending, events)
    a = pending["a.com|2026-10-01T10:00:00Z"]
    assert a["security"] == {"bots": 3, "challenge": 1, "waf": 1}
    assert [(e["action"], e["source"], e["rule"]) for e in events] == [
        ("block", "bots", "spoofed"), ("challenge", "bots", "library"), ("log", "bots", "empty_ua"),
        ("block", "waf", "991100")]
