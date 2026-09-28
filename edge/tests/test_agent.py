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
        "NGINX_TEST_CMD": "true",
        "NGINX_RELOAD_CMD": "true",
        "NGINX_USER": "root",
    })
    cfg.update(over)
    return cfg


def self_signed(tmp_path):
    key, crt = tmp_path / "k.pem", tmp_path / "c.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                    "-nodes", "-subj", "/CN=example.com", "-days", "2", "-keyout", key, "-out", crt],
                   check=True, capture_output=True)
    return crt.read_text(), key.read_text()


SITE = {
    "id": 7, "domain": "example.com", "status": "active",
    "hosts": [{"name": "example.com", "origin": "127.0.0.1:18080"},
              {"name": "www.example.com", "origin": "[2a01:4f8::1]"},
              {"name": "evil.example.com", "origin": "x; include /etc/passwd"}],
    "cache_enabled": True, "force_https": True, "origin_protocol": "http",
    "edge_cache_ttl": 3600, "browser_cache_ttl": 600, "rate_limit_rps": 20,
    "blocked_ips": ["1.2.3.4/32"], "ssl": None,
}


def test_render_rejects_unsafe_and_skips_https_without_cert(tmp_path):
    SAFE = dict(SITE, hosts=SITE["hosts"])
    text, files = agent.render_site(SAFE, make_cfg(tmp_path))
    assert "evil.example.com" not in text and "/etc/passwd" not in text
    assert "listen 443" not in text and "return 301" not in text  # no cert -> no https redirect
    assert "limit_req zone=pcdn_rl_7 burst=40" in text
    assert "deny 1.2.3.4/32;" in text
    assert 'max-age=600' in text
    assert files == {}


def test_render_suspended(tmp_path):
    text, _ = agent.render_site(dict(SITE, status="suspended"), make_cfg(tmp_path))
    assert "return 503" in text and "proxy_pass" not in text


def test_origin_regex_blocks_port_injection():
    # the controller never emits ports; the agent only allows host / [v6]
    assert not agent.SAFE_ORIGIN.match("127.0.0.1:18080")
    assert agent.SAFE_ORIGIN.match("[2a01:4f8::1]")
    assert agent.SAFE_ORIGIN.match("shops.myshopify.com")


def test_apply_rollback(tmp_path):
    cfg = make_cfg(tmp_path)
    assert agent.apply_config({"sites": [SITE]}, cfg) is None
    first = (tmp_path / "pcdn/sites/7.conf").read_text()
    assert (tmp_path / "cache/7").is_dir()
    cfg["NGINX_TEST_CMD"] = "echo broken >&2; false"
    err = agent.apply_config({"sites": [dict(SITE, domain="changed.com")]}, cfg)
    assert "broken" in err
    assert (tmp_path / "pcdn/sites/7.conf").read_text() == first
    cfg["NGINX_TEST_CMD"] = "true"
    agent.apply_config({"sites": []}, cfg)
    assert not (tmp_path / "cache/7").exists()


def test_purge(tmp_path):
    cfg = make_cfg(tmp_path)
    p = pathlib.Path(agent.cache_file(cfg["CACHE_DIR"], 7, "https://example.com/a.css"))
    p.parent.mkdir(parents=True)
    p.write_text("x")
    h = hashlib.md5(b"https://example.com/a.css").hexdigest()
    assert p.name == h and p.parent.name == h[-3:-1] and p.parent.parent.name == h[-1]
    assert agent.do_purge({"site_id": 7, "urls": ["https://Example.com/a.css"]}, cfg) == 1
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
    assert state["pending"] == {"example.com|2026-09-28T10:00:00Z": [150, 2, 1]}
    agent.read_usage(state, str(log))  # nothing new (partial line not consumed)
    assert state["pending"]["example.com|2026-09-28T10:00:00Z"] == [150, 2, 1]
    # a line lands after our last read, then logrotate moves the file to .1
    with open(log, "a") as f:
        f.write('"x"}\n' + json.dumps({"t": "2026-09-28T10:30:00Z", "h": "example.com", "b": 1000}) + "\n")
    os.rename(log, str(log) + ".1")
    log.write_text(json.dumps({"t": "2026-09-28T11:00:00Z", "h": "www.example.com", "b": 7}) + "\n")
    agent.read_usage(state, str(log))
    assert state["pending"]["example.com|2026-09-28T10:00:00Z"] == [1150, 3, 1]
    assert state["pending"]["www.example.com|2026-09-28T11:00:00Z"] == [7, 1, 0]
    items = agent.usage_items(state["pending"])
    assert {i["host"] for i in items} == {"example.com", "www.example.com"}


@pytest.mark.skipif(shutil.which("nginx") is None, reason="nginx not installed")
def test_nginx_accepts_generated_config(tmp_path):
    cert, key = self_signed(tmp_path)
    cfg = make_cfg(tmp_path, LISTEN_IPV6="no")  # CI containers often lack IPv6
    site = dict(SITE, hosts=[{"name": "example.com", "origin": "127.0.0.1"},
                             {"name": "*.example.com", "origin": "origin.example.net"},
                             {"name": "v6.example.com", "origin": "[2a01:4f8::1]"}],
                ssl={"cert": cert, "key": key})
    other = dict(SITE, id=8, domain="b.com", status="over_quota", hosts=[{"name": "b.com", "origin": "1.1.1.1"}])
    nocache = dict(SITE, id=9, domain="c.com", cache_enabled=False, rate_limit_rps=0, blocked_ips=[],
                   hosts=[{"name": "c.com", "origin": "1.1.1.1"}], origin_protocol="https")
    assert agent.apply_config({"sites": [site, other, nocache]}, cfg) is None

    base = (HERE.parent / "nginx/pcdn-base.conf").read_text().replace("/etc/nginx/pcdn", cfg["NGINX_DIR"])
    base = "\n".join(line for line in base.splitlines() if "listen [::]" not in line)
    (tmp_path / "base.conf").write_text(base)
    (tmp_path / "nginx.conf").write_text(
        f"pid {tmp_path}/nginx.pid;\nerror_log {tmp_path}/error.log;\nevents {{}}\n"
        f"http {{\n access_log off;\n"
        + "".join(f" {d}_temp_path {tmp_path}/{d};\n" for d in ("client_body", "proxy", "fastcgi", "uwsgi", "scgi"))
        + f" include {tmp_path}/base.conf;\n}}\n")
    p = subprocess.run(["nginx", "-t", "-c", str(tmp_path / "nginx.conf")], capture_output=True, text=True)
    assert p.returncode == 0 and "[warn]" not in p.stderr, p.stderr


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
