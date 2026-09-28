import hashlib
import importlib.util
import json
import os
import pathlib
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
        "PAGES_DIR": str(HERE.parent / "pages"),
        "NJS_FILE": str(HERE.parent / "njs/pcdn.js"),
        "BASE_TEMPLATE": str(HERE.parent / "nginx/pcdn-base.conf"),
        "GEOIP_DB": str(tmp_path / "missing.mmdb"),
        "NGINX_TEST_CMD": "true",
        "NGINX_RELOAD_CMD": "true",
        "NGINX_USER": "root",
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
    assert "limit_req zone=pcdn_rl_7 burst=40" in text
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
    assert "listen 8081 default_server;" in text and "listen 8443 ssl http2 default_server;" in text
    assert "[::]" not in text and "{{" not in text
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
    assert len(a.state["pending"]) == 5 and len(a.state["events"]) == 5  # nothing lost
    a.ctl = RecordingCtl()
    a.push_usage()
    assert [len(b["items"]) for b in a.ctl.bodies] == [2, 2, 1]
    assert [len(b.get("events", [])) for b in a.ctl.bodies] == [3, 2, 0]
    assert a.state["pending"] == {} and a.state["events"] == []


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
    sed = next(line for line in install.splitlines() if "pcdn (set in pcdn http.conf)" in line)
    stock = tmp_path / "nginx.conf"
    shutil.copy("/etc/nginx/nginx.conf", stock)
    subprocess.run(["bash", "-c", sed.replace("/etc/nginx/nginx.conf", str(stock))], check=True)
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
