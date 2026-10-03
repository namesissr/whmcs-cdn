"""SPEC §16.8 object-storage origins on the edge: validation of `origin = {"storage": {...}}` and
the rendering of storage hosts (cache, WAF, image resizer, shield, transforms, functions, video,
tunnels). Real nginx runs against a local TLS bucket emulator are in test_storage_e2e.py."""

import copy
import logging
import os
import stat

import pytest

from test_agent import SITE, agent, make_cfg, self_signed

TOKEN = "Tk_" + "a1B2-c3D4" * 5            # 48 chars of [A-Za-z0-9_-]
STO = {"host": "s3.example.net", "port": 443, "tls": True, "host_header": "s3.example.net",
       "bucket": "cdn-k3m9q2xa-assets", "path_prefix": "/cdn-k3m9q2xa-assets", "referer": TOKEN}
SHIELD_SECRET = "5f" * 32


def sto(**kw):
    return {"storage": dict(STO, **kw)}


def ssite(**kw):
    s = dict(copy.deepcopy(SITE), hosts=[{"name": "example.com", "origin": {"address": "127.0.0.1", "port": 18080}},
                                         {"name": "cdn.example.com", "origin": sto()}])
    s.update(kw)
    return s


def server_of(text, name, listen=None):
    """The server block whose server_name is `name` (the first one, or the one on `listen`)."""
    pos = 0
    while True:
        i = text.index(f"    server_name {name};", pos)
        start = text.rindex("server {", 0, i)
        end = text.index("\n}", i)
        blk = text[start:end + 2]
        if listen is None or f"listen {listen}" in blk:
            return blk
        pos = end


# ----------------------------------------------------------------- validation

def test_norm_storage_origin_valid_shapes():
    st = agent.norm_storage_origin(sto())
    assert st == {"proto": "https", "tls": True, "hp": "s3.example.net:443", "host": "s3.example.net",
                  "ssl_name": "s3.example.net", "host_header": "s3.example.net", "bucket": STO["bucket"],
                  "prefix": STO["path_prefix"], "referer": TOKEN}
    st = agent.norm_storage_origin(sto(host="S3.Example.NET", port=9443, host_header="s3.example.net:9443",
                                       path_prefix="/s3/v1/" + STO["bucket"]))
    assert st["hp"] == "s3.example.net:9443" and st["host_header"] == "s3.example.net:9443"
    assert st["prefix"] == "/s3/v1/cdn-k3m9q2xa-assets"
    st = agent.norm_storage_origin(sto(host="10.0.0.5", tls=False, port=9000, host_header="10.0.0.5:9000"))
    assert st["proto"] == "http" and st["hp"] == "10.0.0.5:9000" and st["ssl_name"] == "10.0.0.5"
    st = agent.norm_storage_origin(sto(host="2001:DB8::1", host_header="[2001:db8::1]"))
    assert st["hp"] == "[2001:db8::1]:443" and st["ssl_name"] == "2001:db8::1"
    assert agent.norm_storage_origin(sto(host="[2001:db8::1]", host_header="[2001:db8::1]:443"))["hp"] == "[2001:db8::1]:443"
    assert agent.norm_storage_origin(sto(referer="x" * 16)) and agent.norm_storage_origin(sto(referer="Z" * 128))


@pytest.mark.parametrize("bad", [
    {"host": "s3.example.net; include /etc/passwd"}, {"host": "s3_example.net"}, {"host": ""}, {"host": "-s3.net"},
    {"host": "a..b"}, {"host": "s3.example.net:443"}, {"host": "0.0.0.0"}, {"host": "1.2.3"}, {"host": "224.0.0.1"},
    {"host": "x" * 64 + ".net"}, {"host": 5},
    {"port": 0}, {"port": 65536}, {"port": "443"}, {"port": True}, {"port": 443.0}, {"port": None},
    {"tls": "yes"}, {"tls": 1}, {"tls": None},
    {"host_header": "s3.example.net\r\nX-Evil: 1"}, {"host_header": "s3 example"}, {"host_header": "a.net:0"},
    {"host_header": "a.net:99999"}, {"host_header": 'a.net"'}, {"host_header": "$host"}, {"host_header": ""},
    {"bucket": "Cdn-Upper"}, {"bucket": "ab"}, {"bucket": "a..b"}, {"bucket": "-cdn"}, {"bucket": "cdn/x"},
    {"bucket": "cdn-k3m9q2xa-other"},                                      # prefix no longer ends in /<bucket>
    {"path_prefix": "cdn-k3m9q2xa-assets"}, {"path_prefix": "/../cdn-k3m9q2xa-assets"},
    {"path_prefix": "/./cdn-k3m9q2xa-assets"}, {"path_prefix": "/%2e%2e/cdn-k3m9q2xa-assets"},
    {"path_prefix": "//cdn-k3m9q2xa-assets"}, {"path_prefix": "/cdn-k3m9q2xa-assets/"},
    {"path_prefix": "/a b/cdn-k3m9q2xa-assets"}, {"path_prefix": "/$x/cdn-k3m9q2xa-assets"},
    {"path_prefix": "/other-bucket"},
    {"referer": "short"}, {"referer": "x" * 129}, {"referer": "tok en" + "x" * 20}, {"referer": "tok$" + "x" * 20},
    {"referer": 'tok"' + "x" * 20}, {"referer": "tok.x" + "x" * 20}, {"referer": None},
])
def test_norm_storage_origin_rejects(bad):
    assert agent.norm_storage_origin(sto(**bad)) is None


def test_norm_storage_origin_rejects_shapes():
    assert agent.norm_storage_origin({"storage": "s3.example.net"}) is None
    assert agent.norm_storage_origin({"storage": STO, "pool": "p"}) is None           # never with a pool
    assert agent.norm_storage_origin({"storage": STO, "address": "1.2.3.4"}) is None
    for k in STO:
        assert agent.norm_storage_origin({"storage": {x: v for x, v in STO.items() if x != k}}) is None, k
    # the classic resolver never takes a storage origin
    assert agent.resolve_origin({"origin": sto()}, {}, "http") is None
    assert agent.resolve_origin({"origin": {"address": "1.2.3.4", "port": 80}}, {}, "http") == ("http", None, "1.2.3.4:80")


def test_invalid_storage_host_is_skipped_and_the_token_never_logged(tmp_path, caplog):
    s = ssite()
    s["hosts"][1]["origin"] = sto(host="evil host")
    with caplog.at_level(logging.WARNING, logger="pcdn-agent"):
        files = agent.render_all({"sites": [s]}, make_cfg(tmp_path))
    assert "cdn.example.com" not in files["sites/7.conf"] and "storage/7.conf" not in files
    assert any("cdn.example.com" in r.getMessage() for r in caplog.records)
    assert all(TOKEN not in r.getMessage() for r in caplog.records)
    assert "<redacted>" in caplog.text and TOKEN not in caplog.text
    assert TOKEN not in agent.storage_log_repr(sto()) and "s3.example.net" in agent.storage_log_repr(sto())


# ----------------------------------------------------------------- rendering

def test_render_storage_host(tmp_path):
    cfg = make_cfg(tmp_path)
    files = agent.render_all({"sites": [ssite()]}, cfg)
    text = files["sites/7.conf"]
    # the read token is only in the 0600 storage file, never in the site config / http.conf / sites.js
    assert TOKEN not in text and TOKEN not in files["http.conf"] and TOKEN not in files["js/sites.js"]
    assert files["storage/7.conf"].count(TOKEN) == 1 and "$pcdn_sref_7_0" in files["storage/7.conf"]
    assert f"include {cfg['NGINX_DIR']}/storage/7.conf;" in text
    blk = server_of(text, "cdn.example.com")
    for line in ('set $pcdn_target "s3.example.net:443";', "set $pcdn_proto https;",
                 'proxy_ssl_name "s3.example.net";', "proxy_ssl_verify on;",
                 f"proxy_ssl_trusted_certificate {cfg['CA_BUNDLE']};", "proxy_ssl_server_name on;"):
        assert line in blk, line
    assert "proxy_ssl_name $host;" not in blk
    loc = blk[blk.index("    location / {"):]
    for line in ("if ($pcdn_sm_7) { return 405; }", "if ($pcdn_sbad_7) { return 400; }",
                 "proxy_pass_request_headers off;", "proxy_pass_request_body off;",
                 'proxy_set_header Host "s3.example.net";', "proxy_set_header Referer $pcdn_sref_7_0;",
                 "proxy_set_header Accept $http_accept;", "add_header Allow $pcdn_sm_7 always;",
                 "proxy_pass $pcdn_proto://$pcdn_target/cdn-k3m9q2xa-assets$pcdn_path;"):
        assert line in loc, line
    # nothing of the visitor's request is forwarded: no Cookie / Authorization / X-Forwarded-* / Range
    # in a cached location (it would store partial content), no header rules
    for frag in ("$http_cookie", "$http_authorization", "X-Forwarded-For", "X-Real-IP", "Range", "$is_args",
                 "$request_uri;", "Upgrade"):
        assert frag not in loc.split("proxy_cache_key")[0] + loc.split("proxy_cache_key")[1].split("\n", 1)[1], frag
    # uncached locations (page rule bypass) pass Range / conditional requests through
    s = ssite(pagerules={"rules": [{"id": "nc", "pattern": "/live/*", "cache": "bypass"}]})
    blk = server_of(agent.render_site(s, cfg)[0], "cdn.example.com")
    rule = blk[blk.index('location ~ "^/live/.*$"'):]
    rule = rule[:rule.index("\n    }")]
    assert "proxy_set_header Range $http_range;" in rule and "proxy_set_header If-None-Match $http_if_none_match;" in rule
    assert "proxy_cache " not in rule and "X-Cache BYPASS" in rule
    # the ordinary host of the same site is untouched
    plain = server_of(text, "example.com")
    assert "proxy_set_header Host $host;" in plain and "pcdn_sm_7" not in plain and "proxy_ssl_name $host;" in plain
    # maps: method / path guards
    assert 'map $request_method $pcdn_sm_7 {\n    GET "";\n    HEAD "";\n    default "GET, HEAD";\n}' in text
    assert "map $pcdn_path $pcdn_sbad_7 {" in text


def test_storage_path_guard_regex():
    """The 400 guard (dot segments, encoded / back slashes, NUL, non origin-form) with the same PCRE
    semantics in Python for the cases that matter."""
    import re
    rx = re.compile(r"(?:^[^/]|/(?:[.]|%2e){1,2}(?:/|$)|%2f|%5c|\x5c|%00)", re.I)
    for bad in ("/a/../b", "/..", "/a/.", "/%2e%2e/x", "/%2E./x", "/a%2fb", "/a%5C..", "/a\\b", "/x%00", "http://h/x",
                "*", "/./x"):
        assert rx.search(bad), bad
    for good in ("/", "/a/b.jpg", "/a..b/c", "/.well/x", "/v/seg_0001.ts", "/a%20b/c.png", "/..a", "/a/b..",
                 "/%2e.x"):
        assert not rx.search(good), good
    import inspect
    assert '/(?:[.]|%2e){1,2}(?:/|$)|%2f|%5c|\\\\x5c|%00' in inspect.getsource(agent._render_site)


def test_storage_tls_off_and_ip_endpoint(tmp_path):
    s = ssite()
    s["hosts"][1]["origin"] = sto(host="10.0.0.5", tls=False, port=9000, host_header="10.0.0.5:9000")
    blk = server_of(agent.render_site(s, make_cfg(tmp_path))[0], "cdn.example.com")
    assert "set $pcdn_proto http;" in blk and 'set $pcdn_target "10.0.0.5:9000";' in blk
    assert "proxy_ssl_verify on;" not in blk and 'proxy_set_header Host "10.0.0.5:9000";' in blk


def test_storage_host_never_gets_the_origin_client_certificate(tmp_path):
    crt, key = self_signed(tmp_path)
    s = ssite(ssl_options={"origin_protocol": "https", "origin_verify": True,
                           "origin_client": {"mode": "custom", "cert": crt, "key": key}})
    text, _ = agent.render_site(s, make_cfg(tmp_path))
    assert "proxy_ssl_certificate " in server_of(text, "example.com")
    assert "proxy_ssl_certificate" not in server_of(text, "cdn.example.com")


def test_storage_body_inspection_tunnels_and_functions(tmp_path):
    cfg = make_cfg(tmp_path, FUNCTIONS="yes", FN_SOCKET=str(tmp_path / "fn.sock"),
                   FN_FETCH_SOCKET=str(tmp_path / "fetch.sock"))
    s = ssite(waf={"mode": "block", "packs": ["wordpress"]},
              tunnel={"enabled": True, "paths": [
                  {"id": "own", "path": "/tn-own", "protocol": "ws", "origin": {"address": "10.0.0.9", "port": 8443,
                                                                               "tls": True}},
                  {"id": "inh", "path": "/tn-inh", "protocol": "ws"}]},
              functions={"enabled": True, "items": [{"id": "f", "route": "/api/", "enabled": True, "on_error": "origin",
                                                     "code": "function handleRequest(r){return r.pass()}"}]})
    text, files = agent.render_site(s, cfg)
    blk = server_of(text, "cdn.example.com", listen="80")
    # WAF body inspection: storage hosts take no bodies (GET/HEAD only), the other host keeps it
    assert "rewrite ^ /__pcdn/body$uri last;" not in blk and "@pcdn_body" not in blk
    assert "rewrite ^ /__pcdn/body$uri last;" in server_of(text, "example.com", listen="80")
    # tunnels: a path with its own origin works, one inheriting the storage origin is refused
    assert "location ^~ \"/tn-inh\" { return 404; }" in blk
    assert 'set $pcdn_tn_target "10.0.0.9:8443";' in blk
    # functions: the route answers any method itself; the pass to the origin is GET/HEAD only
    route = blk[blk.index("location ^~ /api/ {"):]
    route = route[:route.index("\n    }")]
    assert "pcdn_sm_7" not in route and "Referer" not in route
    fpass = blk[blk.index("location @pcdn_fn_pass {"):]
    fpass = fpass[:fpass.index("\n    }")]
    assert "if ($pcdn_sm_7) { return 405; }" in fpass and "/cdn-k3m9q2xa-assets$pcdn_path;" in fpass
    # fetch(): the storage host's fetch server proxies to the bucket like the host itself
    fetch = server_of(text, "cdn.example.com", listen=f"unix:{cfg['FN_FETCH_SOCKET']}")
    for line in ('if ($http_x_pcdn_fn_site != "7") { return 421; }', "if ($pcdn_sm_7) { return 405; }",
                 "proxy_pass_request_headers off;", "proxy_set_header Referer $pcdn_sref_7_0;",
                 'proxy_ssl_name "s3.example.net";', "proxy_ssl_verify on;", "proxy_cache off;",
                 "proxy_pass $pcdn_proto://$pcdn_target/cdn-k3m9q2xa-assets$pcdn_path;"):
        assert line in fetch, line
    assert "proxy_set_header Host $host;" not in fetch


def test_storage_image_resizer_goes_through_the_loopback_storage_server(tmp_path):
    cfg = make_cfg(tmp_path, STORAGE_FETCH_PORT="18091")
    s = ssite(image={"enabled": True})
    files = agent.render_all({"sites": [s]}, cfg)
    text = files["sites/7.conf"]
    blk = server_of(text, "cdn.example.com", listen="80")
    img = blk[blk.index("location ^~ /__pcdn/img/ {"):]
    img = img[:img.index("\n    }")]
    # guard before the rewrite (break ends the rewrite directives), visitor headers to the resizer as
    # for any origin (Host $host selects the loopback server), the origin is the loopback server
    assert img.index("if ($pcdn_sm_7) { return 405; }") < img.index("rewrite ^/__pcdn/img")
    assert "proxy_set_header X-Pcdn-Origin http://127.0.0.1:18091;" in img
    assert "proxy_set_header Host $host;" in img and 'proxy_set_header X-Pcdn-Mtls "";' in img
    assert TOKEN not in img
    loop = server_of(text, "cdn.example.com", listen="127.0.0.1:18091")
    for line in ("access_log off;", "if ($pcdn_sm_7) { return 405; }", "if ($pcdn_sbad_7) { return 400; }",
                 "proxy_pass_request_headers off;", "proxy_set_header Referer $pcdn_sref_7_0;",
                 'proxy_set_header Host "s3.example.net";', "proxy_ssl_verify on;", "proxy_cache off;",
                 "proxy_pass $pcdn_proto://$pcdn_target/cdn-k3m9q2xa-assets$pcdn_path;"):
        assert line in loop, line
    assert "Range" not in loop
    assert "listen 127.0.0.1:18091 default_server;" in files["http.conf"]
    # the ordinary host keeps its own origin for the resizer
    assert "proxy_set_header X-Pcdn-Origin $pcdn_proto://$pcdn_target;" in server_of(text, "example.com", listen="80")
    # an L4 app can never take the loopback port while it is rendered
    s["l4"] = {"enabled": True, "apps": [{"id": "x", "protocol": "tcp", "edge_port": 18091, "enabled": True,
                                          "origin": {"address": "10.0.0.5", "port": 5432}, "proxy_protocol": "off",
                                          "ip_allow": [], "idle_timeout": 300}]}
    cfg["NGINX_CAPS"] = dict(cfg["NGINX_CAPS"], l4=True)
    cfg["L4_PORT_RANGE"] = "10000-60000"
    files = agent.render_all({"sites": [s]}, cfg)
    assert not any(k.startswith("l4/sites/") for k in files)


def test_storage_rewrite_path_drops_the_query(tmp_path):
    s = ssite(transform={"rules": [{"id": "rw", "enabled": True, "match": {"path": "/*", "methods": [], "countries": []},
                                    "actions": [{"type": "rewrite_path", "regex": "^/old/(.*)$",
                                                 "replacement": "/new/$1?v=1", "name": None, "value": None}]}]})
    text, _ = agent.render_site(s, make_cfg(tmp_path))
    assert 'map $pcdn_tfu_7_0 $pcdn_sp_7 {\n    "~^(/[^?]*)" $1;\n    default $pcdn_path;\n}' in text
    assert "map $pcdn_sp_7 $pcdn_sbad_7 {" in text and "map $pcdn_path $pcdn_sbadp_7 {" in text
    blk = server_of(text, "cdn.example.com")
    assert "proxy_pass $pcdn_proto://$pcdn_target/cdn-k3m9q2xa-assets$pcdn_sp_7;" in blk
    assert "$pcdn_tfu_7_0;" in server_of(text, "example.com")


def test_storage_shield_hop_and_fallback(tmp_path):
    crt, key = self_signed(tmp_path)
    s = ssite(ssl={"cert": crt, "key": key}, cache=dict(SITE["cache"], shield=True))
    cfg = make_cfg(tmp_path)
    shield = agent.norm_shield({"shield": {"self": False, "peers": ["10.0.0.2"], "secret": SHIELD_SECRET}})
    text, _ = agent.render_site(s, cfg, shield)
    blk = server_of(text, "cdn.example.com")
    hop = blk[blk.index("    location / {"):]
    hop = hop[:hop.index("\n    }")]
    # the edge -> shield hop is an ordinary TLS hop for the site's host (the shield renders the same
    # storage host and adds the token itself): no token, no storage Host
    assert "proxy_pass https://pcdn_shield_https;" in hop and "proxy_set_header Host $host;" in hop
    assert "Referer" not in hop and "proxy_pass_request_headers off;" not in hop
    assert "proxy_set_header X-Pcdn-Shield $pcdn_shield_secret;" in hop and "proxy_ssl_name $host;" in hop
    assert "if ($pcdn_sm_7) { return 405; }" in hop
    fb = blk[blk.index("    location @pcdn_origin_"):]
    fb = fb[:fb.index("\n    }")]
    assert "proxy_set_header Referer $pcdn_sref_7_0;" in fb and "/cdn-k3m9q2xa-assets$pcdn_path;" in fb
    # on the shield itself the storage host fetches from the bucket
    me = agent.norm_shield({"shield": {"self": True, "peers": [], "secret": SHIELD_SECRET}})
    blk = server_of(agent.render_site(s, cfg, me)[0], "cdn.example.com")
    assert "proxy_set_header Referer $pcdn_sref_7_0;" in blk and "pcdn_shield_https" not in blk


def test_storage_video_locations(tmp_path):
    s = ssite(video={"enabled": True, "prefetch_next": True})
    blk = server_of(agent.render_site(s, make_cfg(tmp_path))[0], "cdn.example.com")
    vpf = blk[blk.index("location = /__pcdn/vpf {"):]
    vpf = vpf[:vpf.index("\n    }")]
    assert "proxy_pass $pcdn_proto://$pcdn_target/cdn-k3m9q2xa-assets$pcdn_vnext;" in vpf
    assert "proxy_set_header Referer $pcdn_sref_7_0;" in vpf
    mp4 = blk[blk.index("location ~* \\.mp4$ {"):]
    mp4 = mp4[:mp4.index("\n    }")]
    assert "proxy_set_header Range $slice_range;" in mp4 and "$http_range" not in mp4
    assert "/cdn-k3m9q2xa-assets$pcdn_path;" in mp4


def test_storage_suspended_site_has_no_token(tmp_path):
    files = agent.render_all({"sites": [ssite(status="suspended")]}, make_cfg(tmp_path))
    assert "storage/7.conf" not in files and "server_name cdn.example.com;" in files["sites/7.conf"]
    assert "s3.example.net" not in files["sites/7.conf"]


def test_sites_without_storage_render_unchanged(tmp_path):
    """No storage host anywhere: none of the storage pieces (maps, include, loopback port, files)."""
    cfg = make_cfg(tmp_path, FUNCTIONS="yes", FN_SOCKET=str(tmp_path / "fn.sock"),
                   FN_FETCH_SOCKET=str(tmp_path / "fetch.sock"))
    s = dict(copy.deepcopy(SITE), image={"enabled": True}, video={"enabled": True, "prefetch_next": True},
             waf={"mode": "block", "packs": ["wordpress"]},
             functions={"enabled": True, "items": [{"id": "f", "route": "/api/", "enabled": True,
                                                    "code": "function handleRequest(r){}"}]})
    files = agent.render_all({"sites": [s]}, cfg)
    blob = "\n".join(files.values())
    for frag in ("pcdn_sm_", "pcdn_sbad", "pcdn_sref", "storage/", "8091", "proxy_pass_request_headers",
                 "add_header Allow "):
        assert frag not in blob, frag
    assert not any(k.startswith("storage/") for k in files)


def test_storage_tokens_written_0600_and_grouped_as_secrets(tmp_path):
    files = agent.render_all({"sites": [ssite()]}, make_cfg(tmp_path))
    root = tmp_path / "tree"
    agent.write_tree(str(root), files)
    assert stat.S_IMODE(os.stat(root / "storage").st_mode) == 0o700
    assert stat.S_IMODE(os.stat(root / "storage/7.conf").st_mode) == 0o600
    assert stat.S_IMODE(os.stat(root / "sites/7.conf").st_mode) == 0o644
    # a token rotation is a per-site change that is never deferred (like a certificate rotation)
    assert "7" in agent.cert_digests(files) and "7" in agent.site_digests(files)
    other = dict(files, **{"storage/7.conf": files["storage/7.conf"].replace(TOKEN, "n" * 48)})
    assert agent.cert_digests(other)["7"] != agent.cert_digests(files)["7"]
