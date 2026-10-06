"""Wave 8 edge unit tests (SPEC §16.3 host guard, §16.4 L4 proxy, §16.5 video, §16.6 images v2).

Rendering, capability gating, usage wire shapes, the nftables guard ruleset, the image transformer
(Pillow) and the pcdn.js image / video logic (node). Real nginx runs are in test_wave8_e2e.py.
"""

import hashlib
import hmac
import io
import json
import os
import pathlib
import re
import shutil
import subprocess

import pytest

from test_agent import SITE, agent, make_cfg

HERE = pathlib.Path(__file__).resolve().parent

try:
    from PIL import Image
except ImportError:  # pragma: no cover - python3-pil missing
    Image = None
needs_pil = pytest.mark.skipif(Image is None, reason="python3-pil not installed")

NO_IMG = {"transform": False, "webp": False, "avif": False}
ALL_IMG = {"transform": True, "webp": True, "avif": True}


def w8cfg(tmp_path, l4=False, img=None, **over):
    """make_cfg with pinned wave-8 capabilities (L4 readiness, image transformer)."""
    cfg = make_cfg(tmp_path, **over)
    cfg["NGINX_CAPS"] = dict(cfg["NGINX_CAPS"], l4=l4)
    cfg["IMAGE_CAPS"] = dict(NO_IMG if img is None else img)
    return cfg


def site8(**kw):
    s = dict(SITE, hosts=[{"name": "example.com", "origin": {"address": "127.0.0.1", "port": 18080}}])
    s.update(kw)
    return s


APP = {"id": "db", "protocol": "tcp", "edge_port": 20001, "origin": {"address": "10.0.0.5", "port": 5432},
       "proxy_protocol": "off", "ip_allow": [], "idle_timeout": 300, "enabled": True}


# ----------------------------------------------------------------- byte-identical rendering

def test_wave8_fields_absent_or_default_keep_rendering(tmp_path):
    """Sites without the new fields, or with them at their defaults, render byte-identically (no
    reload from a controller upgrade alone); so does a node-wide empty `l4` list."""
    for img in (NO_IMG, ALL_IMG):
        cfg = w8cfg(tmp_path, l4=True, img=img)
        base = site8(image={"enabled": True, "quality": 80, "max_width": 1500})
        dflt = dict(base, image={"enabled": True, "quality": 80, "max_width": 1500, "avif": False,
                                 "smart_crop": False, "transform_secret": ""},
                    video={"enabled": False, "segment_ttl": 86400, "manifest_ttl": 2, "prefetch_next": True},
                    l4={"apps": []})
        assert agent.render_site(base, cfg) == agent.render_site(dflt, cfg)
        f1, d1 = agent.render_tree({"sites": [base]}, cfg)
        f2, d2 = agent.render_tree({"sites": [dflt], "l4": []}, cfg)
        assert d1 == d2 and f1 == f2
        assert not any(k.startswith("l4/") for k in f1)
        js = json.loads(f1["js/sites.js"].split("export default ", 1)[1].rstrip(";\n"))
        assert js["7"]["image"] == {"enabled": True, "quality": 80, "max_width": 1500} and "video" not in js["7"]


# ----------------------------------------------------------------- capabilities

def test_capabilities_parse_stream_and_slice():
    ubuntu = ("nginx version: nginx/1.24.0 (Ubuntu)\nconfigure arguments: --modules-path=/usr/lib/nginx/modules "
              "--with-http_slice_module --with-stream=dynamic --with-http_flv_module")
    c = agent.parse_nginx_v(ubuntu, exists=lambda p: p.endswith("ngx_stream_module.so"))
    assert c["stream"] is True and c["slice"] is True
    c = agent.parse_nginx_v(ubuntu, exists=lambda p: False)
    assert c["stream"] is False                              # libnginx-mod-stream not installed
    org = "nginx version: nginx/1.29.1\nconfigure arguments: --prefix=/etc/nginx --with-stream --with-http_v3_module"
    c = agent.parse_nginx_v(org, exists=lambda p: False)
    assert c["stream"] is True and c["slice"] is False
    assert agent.LEGACY_CAPS["stream"] is False and agent.LEGACY_CAPS["slice"] is True


def test_l4_ready_needs_stream_module_and_include(tmp_path):
    cfg = make_cfg(tmp_path)
    conf = tmp_path / "nginx.conf"
    cfg["NGINX_CONF"] = str(conf)
    cfg["NGINX_CAPS"] = dict(cfg["NGINX_CAPS"], stream=True)
    conf.write_text("events {}\nhttp {}\n")
    assert agent.l4_ready(cfg) is False                       # no include yet (install.sh adds it)
    conf.write_text(f"events {{}}\nhttp {{}}\ninclude {cfg['NGINX_DIR']}/l4/*.conf;\n")
    assert agent.l4_ready(cfg) is True
    cfg["NGINX_CAPS"]["stream"] = False
    assert agent.l4_ready(cfg) is False                       # include but no module
    cfg["NGINX_CONF"] = str(tmp_path / "missing.conf")
    cfg["NGINX_CAPS"]["stream"] = True
    assert agent.l4_ready(cfg) is False


def test_image_capabilities_pinned_and_disabled(tmp_path):
    cfg = make_cfg(tmp_path, IMAGE_CAPS={"transform": False, "avif": True})
    assert agent.image_capabilities(cfg)["avif"] is False     # avif needs the transformer
    cfg = make_cfg(tmp_path, IMAGED="no")
    assert agent.image_capabilities(cfg) == {"transform": False, "webp": False, "avif": False, "pillow_avif": False}


def test_heartbeat_wave8_capabilities(tmp_path):
    a = agent.Agent.__new__(agent.Agent)
    a.cfg = w8cfg(tmp_path, l4=True, img=ALL_IMG, L4_PORT_RANGE="30000-30100", GUARD="yes",
                  GUARD_FILE=str(tmp_path / "guard.nft"))
    caps = a._hb()["capabilities"]
    assert caps["l4"] is True and caps["l4_port_range"] == "30000-30100" and caps["avif"] is True
    assert caps["image_transform"] is True and caps["slice"] is True and caps["video"] is True
    assert caps["net_guard"] is False                         # GUARD=yes but no rule file
    (tmp_path / "guard.nft").write_text("table inet pcdn_guard {}\n")
    assert a._hb()["capabilities"]["net_guard"] is True
    assert agent.l4_port_range({"L4_PORT_RANGE": "garbage"}) == (20000, 29999)
    assert agent.l4_port_range({"L4_PORT_RANGE": "80-90000"}) == (1024, 65535)


# ----------------------------------------------------------------- L4 rendering (SPEC §16.4)

def test_l4_render_and_validation(tmp_path):
    cfg = w8cfg(tmp_path, l4=True)
    apps = [APP,
            dict(APP, id="dns", protocol="udp", edge_port=20002, origin={"address": "2001:db8::5", "port": 53},
                 ip_allow=["1.2.3.4", "10.0.0.0/8", "bad"], idle_timeout=5, proxy_protocol="v1"),
            dict(APP, id="pp", edge_port=20003, proxy_protocol="v2", origin={"address": "db.example.net", "port": 3306}),
            dict(APP, id="off", edge_port=20004, enabled=False),
            dict(APP, id="out", edge_port=40000),                          # outside L4_PORT_RANGE
            dict(APP, id="dup", edge_port=20001),                          # tcp/20001 already taken
            dict(APP, id="Bad id!", edge_port=20005),
            dict(APP, id="inj", edge_port=20006, origin={"address": "1.2.3.4; include /x", "port": 1}),
            dict(APP, id="sport", edge_port="20007")]
    files = agent.render_all({"sites": [site8(l4={"apps": apps})]}, cfg)
    main, s7 = files["l4/stream.conf"], files["l4/sites/7.conf"]
    assert main.startswith("# L4 proxy") and "stream {" in main and "log_format pcdn_l4 escape=json" in main
    assert f"access_log {cfg['L4_ACCESS_LOG']} pcdn_l4 buffer=16k flush=5s;" in main
    assert f"include {cfg['NGINX_DIR']}/l4/sites/*.conf;" in main
    assert "listen 20001 reuseport;" in s7 and "listen [::]:20001 reuseport;" in s7
    assert 'set $pcdn_l4_app "example.com|db";' in s7 and "proxy_pass 10.0.0.5:5432;" in s7
    assert "proxy_timeout 300s;" in s7
    udp = s7.split("# app dns (udp)")[1].split("# app")[0]
    assert "listen 20002 udp reuseport;" in udp and "proxy_pass [2001:db8::5]:53;" in udp
    assert "allow 1.2.3.4/32;\n    allow 10.0.0.0/8;\n    deny all;" in udp and "proxy_timeout 10s;" in udp
    assert "proxy_protocol" not in udp                                  # UDP never sends PROXY protocol
    pp = s7.split("# app pp (tcp)")[1]
    assert "proxy_protocol on;" in pp                                   # v2 is sent as v1 (nginx)
    assert 'set $pcdn_l4_t "db.example.net:3306";' in pp and "proxy_pass $pcdn_l4_t;" in pp
    for bad in ("app off", "app out", "app dup", "20005", "include /x", "app sport"):
        assert bad not in s7
    assert "l4/stream.conf" in agent.GLOBAL_FILES and "7" in agent.site_digests(files)
    # IPv6 off; ports the node uses itself are never taken
    cfg6 = w8cfg(tmp_path, l4=True, LISTEN_IPV6="no", L4_PORT_RANGE="1024-65535", GUARD_SSH_PORTS="2222")
    s = agent.render_all({"sites": [site8(l4={"apps": [APP, dict(APP, id="ssh", edge_port=2222),
                                                        dict(APP, id="rz", edge_port=8089)]})]}, cfg6)
    assert "[::]" not in s["l4/sites/7.conf"] and "2222" not in s["l4/sites/7.conf"] and "8089" not in s["l4/sites/7.conf"]


def test_l4_skips_ports_used_by_other_processes(tmp_path, monkeypatch):
    """A port another process listens on would make nginx fail the reload (and every later apply):
    such an app is skipped, while the ports of the L4 config nginx runs itself stay rendered."""
    net = tmp_path / "net"
    net.mkdir()
    hdr = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
    (net / "tcp").write_text(hdr + "   0: 00000000:4E21 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1\n"
                             "   1: 00000000:4E22 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 2\n")
    (net / "udp").write_text(hdr + "   0: 00000000:4E23 00000000:0000 07 00000000:00000000 00:00000000 00000000 0 0 3\n")
    cfg = w8cfg(tmp_path, l4=True)
    real = agent.l4_busy_ports
    monkeypatch.setattr(agent, "l4_busy_ports", lambda c: real(c, str(net)))
    sdir = pathlib.Path(cfg["NGINX_DIR"]) / "l4" / "sites"
    sdir.mkdir(parents=True)
    (sdir / "7.conf").write_text("server {\n    listen 20002 reuseport;\n}\n")      # nginx's own (current tree)
    apps = [dict(APP, id="a", edge_port=20001), dict(APP, id="b", edge_port=20002),
            dict(APP, id="c", edge_port=20003, protocol="udp"), dict(APP, id="d", edge_port=20003)]
    text = agent.render_all({"sites": [site8(l4={"apps": apps})]}, cfg)["l4/sites/7.conf"]
    assert "app a" not in text and "app b" in text and "app c" not in text and "app d" in text


def test_l4_not_rendered_without_capability_or_for_inactive_sites(tmp_path):
    site = site8(l4={"apps": [APP]})
    assert not any(k.startswith("l4/") for k in agent.render_all({"sites": [site]}, w8cfg(tmp_path, l4=False)))
    cfg = w8cfg(tmp_path, l4=True)
    for status in ("suspended", "over_quota"):
        files = agent.render_all({"sites": [dict(site, status=status)]}, cfg)
        assert not any(k.startswith("l4/") for k in files)


def test_l4_node_wide_list_wins_and_covers_sites_without_http(tmp_path):
    """The controller's node-wide `l4` list (own group only) also carries apps of sites that have no
    proxied HTTP host (absent from `sites`)."""
    cfg = w8cfg(tmp_path, l4=True)
    node = [{"site": "l4only.com", "site_id": 9, "app_id": "game", "hostname": "l4-game.l4only.com",
             "protocol": "udp", "port": 20100, "origin": {"address": "5.6.7.8", "port": 27015},
             "proxy_protocol": "off", "ip_allow": [], "idle_timeout": 60},
            {"site": "example.com", "site_id": 7, "app_id": "db", "protocol": "tcp", "port": 20001,
             "origin": {"address": "10.0.0.5", "port": 5432}, "proxy_protocol": "off", "ip_allow": [],
             "idle_timeout": 300}]
    files = agent.render_all({"sites": [site8(l4={"apps": [dict(APP, id="stale", edge_port=20009)]})], "l4": node}, cfg)
    assert 'set $pcdn_l4_app "l4only.com|game";' in files["l4/sites/9.conf"]
    assert "listen 20100 udp reuseport;" in files["l4/sites/9.conf"]
    assert "app db" in files["l4/sites/7.conf"] and "stale" not in files["l4/sites/7.conf"]


def test_l4_port_clash_prefers_own_group(tmp_path):
    cfg = w8cfg(tmp_path, l4=True, GROUP="tunnel")
    foreign = site8(id=3, domain="a.com", edge_group="general", l4={"apps": [APP]})
    own = site8(id=8, domain="b.com", edge_group="tunnel", l4={"apps": [dict(APP, id="mine")]})
    files = agent.render_all({"sites": [foreign, own]}, cfg)
    assert "l4/sites/8.conf" in files and "l4/sites/3.conf" not in files


# ----------------------------------------------------------------- L4 usage

def test_l4_usage_from_stream_log_with_rotation(tmp_path):
    log = tmp_path / "l4.log"

    def line(app, bi, bo, t="2026-10-01T10:15:00+00:00"):
        return json.dumps({"t": t, "a": app, "p": "TCP", "ip": "1.2.3.4", "bi": bi, "bo": bo, "st": 200,
                           "d": 1.5}) + "\n"
    log.write_text(line("example.com|db", 100, 1000) + line("example.com|db", 1, 2) + line("Bad|x y", 5, 5)
                   + line("example.com|dns", 7, 9, "2026-10-01T11:00:01+00:00") + '{"broken"\n' + '{"t": "x"')
    st = {}
    agent.read_l4_usage(st, str(log))
    p = st["pending"]
    assert p["example.com|2026-10-01T10:00:00Z"]["l4"] == {"db": {"bytes_in": 101, "bytes_out": 1002, "sessions": 2}}
    assert p["example.com|2026-10-01T11:00:00Z"]["l4"]["dns"]["sessions"] == 1
    # rotation: the rest of the old file (.1) is read, then the new one from 0
    with open(log, "a") as f:
        f.write("\n" + line("example.com|db", 10, 10))   # completes the partial line (ignored) + one more
    os.rename(log, str(log) + ".1")
    log.write_text(line("example.com|db", 1000, 1000))
    agent.read_l4_usage(st, str(log))
    assert p["example.com|2026-10-01T10:00:00Z"]["l4"]["db"] == {"bytes_in": 1111, "bytes_out": 2012, "sessions": 4}
    item = agent.usage_item("example.com|2026-10-01T10:00:00Z", p["example.com|2026-10-01T10:00:00Z"])
    assert item["bytes"] == 0 and item["requests"] == 0          # L4 is NOT part of `bytes`
    assert item["l4"] == {"db": {"bytes_in": 1111, "bytes_out": 2012, "sessions": 4}}
    agent.read_l4_usage(st, str(tmp_path / "missing.log"))       # no stream log: no-op


def test_push_usage_includes_l4(tmp_path, monkeypatch):
    from test_agent import RecordingCtl
    cfg = make_cfg(tmp_path, L4_ACCESS_LOG=str(tmp_path / "l4.log"))
    (tmp_path / "l4.log").write_text(json.dumps({"t": "2026-10-01T10:15:00+00:00", "a": "example.com|db",
                                                 "bi": 3, "bo": 4, "st": 200}) + "\n")
    a = agent.Agent(cfg)
    a.ctl = RecordingCtl()
    a.push_usage()
    items = [it for b in a.ctl.bodies if b for it in b.get("items", [])]
    assert items and items[0]["l4"] == {"db": {"bytes_in": 3, "bytes_out": 4, "sessions": 1}}


# ----------------------------------------------------------------- video (SPEC §16.5)

VIDEO = {"enabled": True, "segment_ttl": 3600, "manifest_ttl": 3, "prefetch_next": True}


def _loc(text, head):
    return text.split(f"location {head} {{", 1)[1].split("\n    }", 1)[0]


def test_video_locations_render(tmp_path):
    cfg = w8cfg(tmp_path)
    text, _ = agent.render_site(site8(video=VIDEO), cfg)
    m = _loc(text, "~* \\.(?:m3u8|mpd)$")
    assert "proxy_cache_valid 200 3s;" in m and "proxy_cache_background_update on;" in m
    assert "proxy_cache_use_stale updating error timeout http_500 http_502 http_503 http_504;" in m
    assert "add_header Access-Control-Allow-Origin * always;" in m and "proxy_hide_header Access-Control-Allow-Origin;" in m
    assert "proxy_no_cache $pcdn_nocache_7 $upstream_http_set_cookie;" in m
    seg = _loc(text, "~* \\.(?:ts|m4s|aac)$")
    assert "proxy_cache_valid 200 206 3600s;" in seg and "proxy_cache_lock on;" in seg
    assert "mirror /__pcdn/vpf;" in seg and "mirror_request_body off;" in seg and "slice" not in seg
    mp4 = _loc(text, "~* \\.mp4$")
    assert "slice 1m;" in mp4 and "proxy_set_header Range $slice_range;" in mp4
    assert 'proxy_cache_key "$scheme://$host$request_uri;r=$slice_range";' in mp4
    vpf = _loc(text, "= /__pcdn/vpf")
    assert "internal;" in vpf and 'if ($pcdn_vnext = "") { return 204; }' in vpf
    assert 'proxy_cache_key "$scheme://$host$pcdn_vnext$is_args$args";' in vpf
    assert "proxy_pass $pcdn_proto://$pcdn_target$pcdn_vnext$is_args$args;" in vpf
    # order: page rules, then video, then the static-extension location (which also matches .mp4)
    assert text.index("~* \\.(?:m3u8|mpd)$") < text.index("location ~* \\.(?:css|js")
    js = agent.render_all({"sites": [site8(video=VIDEO)]}, cfg)["js/sites.js"]
    assert '"video": {"prefetch": true}' in js


def test_video_degrades(tmp_path):
    no_slice = w8cfg(tmp_path)
    no_slice["NGINX_CAPS"] = dict(no_slice["NGINX_CAPS"], slice=False)
    text, _ = agent.render_site(site8(video=VIDEO), no_slice)
    assert "slice" not in text and "~* \\.mp4$" in text
    no_njs = w8cfg(tmp_path)
    no_njs["NGINX_CAPS"] = dict(no_njs["NGINX_CAPS"], modules=["image_filter"])
    text, _ = agent.render_site(site8(video=VIDEO), no_njs)
    assert "mirror" not in text and "/__pcdn/vpf" not in text and "m3u8" in text
    cfg = w8cfg(tmp_path)
    text, _ = agent.render_site(site8(video=dict(VIDEO, prefetch_next=False)), cfg)
    assert "mirror" not in text
    js = agent.render_all({"sites": [site8(video=dict(VIDEO, prefetch_next=False))]}, cfg)["js/sites.js"]
    assert '"video"' not in js
    # cache off (dev mode) / suspended: no video locations
    text, _ = agent.render_site(site8(video=VIDEO, cache=dict(SITE["cache"], enabled=False)), cfg)
    assert "m3u8" not in text
    text, _ = agent.render_site(site8(video=VIDEO, status="suspended"), cfg)
    assert "m3u8" not in text
    # rewrite_path rules: no prefetch (the next segment's URI could be mapped elsewhere)
    tf = {"rules": [{"id": "rw", "enabled": True, "match": {"path": "/*", "methods": [], "countries": []},
                     "actions": [{"type": "rewrite_path", "regex": "^/a/(.*)$", "replacement": "/b/$1"}]}]}
    text, _ = agent.render_site(site8(video=VIDEO, transform=tf), cfg)
    assert "m3u8" in text and "mirror" not in text


def test_video_usage_attribution(tmp_path):
    body = {"sites": [site8(video=VIDEO, hosts=[{"name": "example.com", "origin": {"address": "1.1.1.1"}},
                                                  {"name": "*.cdn.example.com", "origin": {"address": "1.1.1.1"}}]),
                      site8(id=8, domain="b.com", hosts=[{"name": "b.com", "origin": {"address": "1.1.1.1"}}])]}
    vh = agent.video_hosts(body)
    assert vh == {"exact": ["example.com"], "wild": [".cdn.example.com"]}
    log = tmp_path / "a.log"

    def rec(h, u, b=100, c="MISS", tn=""):
        return json.dumps({"t": "2026-10-01T10:00:05+00:00", "h": h, "b": b, "s": 200, "c": c, "u": u, "tn": tn,
                           "v": "ok"}) + "\n"
    log.write_text(rec("example.com", "/live/s1.ts?x=1", 1000, "HIT") + rec("example.com", "/live/index.m3u8", 50)
                   + rec("v.cdn.example.com", "/a.mp4") + rec("example.com", "/page.html")
                   + rec("b.com", "/x.ts") + rec("example.com", "/tn/x.ts", tn="ws"))
    st = {"video_hosts": vh}
    agent.read_usage(st, str(log))
    p = st["pending"]
    assert p["example.com|2026-10-01T10:00:00Z"]["video"] == {"bytes": 1050, "requests": 2, "cache_hits": 1}
    assert p["v.cdn.example.com|2026-10-01T10:00:00Z"]["video"]["requests"] == 1
    assert "video" not in p["b.com|2026-10-01T10:00:00Z"]
    item = agent.usage_item("example.com|2026-10-01T10:00:00Z", p["example.com|2026-10-01T10:00:00Z"])
    assert item["video"] == {"bytes": 1050, "requests": 2, "cache_hits": 1} and item["bytes"] >= 1050
    assert agent.video_hosts({"sites": [site8()]}) == {}


def test_video_purge_removes_slices(tmp_path):
    cfg = make_cfg(tmp_path)
    base = tmp_path / "cache" / "7"
    from test_agent import _fake_cache_file
    keys = ["https://example.com/v/a.mp4;r=bytes=0-1048575", "https://example.com/v/a.mp4;r=bytes=1048576-2097151",
            "https://example.com/v/b.mp4;r=bytes=0-1048575", "https://example.com/v/a.mp4"]
    for k in keys:
        _fake_cache_file(base, k)
    kinfo = agent.key_infos({"sites": [site8(video=VIDEO)]})["7"]
    assert kinfo.get("slice") is True
    n = agent.do_purge({"site_id": 7, "urls": ["https://example.com/v/a.mp4"]}, cfg, kinfo)
    assert n == 3
    left = [agent._read_cache_key(os.path.join(r, f)) for r, _, fs in os.walk(base) for f in fs]
    assert left == ["https://example.com/v/b.mp4;r=bytes=0-1048575"]
    assert "7" not in agent.key_infos({"sites": [site8()]})


# ----------------------------------------------------------------- images v2 rendering (SPEC §16.6)

SECRET = "imgsec_" + "ab" * 24


def test_image_v2_site_render(tmp_path):
    cfg = w8cfg(tmp_path, img=ALL_IMG)
    plain, _ = agent.render_site(site8(image={"enabled": True}), cfg)
    assert 'if ($pcdn_img_w = "!")' not in plain and "add_header Vary Accept;" not in plain
    text, _ = agent.render_site(site8(image={"enabled": True, "avif": True, "transform_secret": SECRET,
                                             "smart_crop": True}), cfg)
    assert text.index('if ($pcdn_img_w = "!") { return 403; }') < text.index("if ($pcdn_img_w) { rewrite")
    img = text.split("location ^~ /__pcdn/img/ {")[1].split("\n    }")[0]
    assert 'proxy_cache_key "$scheme://$host$pcdn_path?w=$pcdn_img_w&h=$pcdn_img_h";' in img
    assert "add_header Vary Accept;" in img
    js = json.loads(agent.render_all({"sites": [site8(image={"enabled": True, "avif": True, "smart_crop": True,
                                                              "transform_secret": SECRET})]},
                                     cfg)["js/sites.js"].split("export default ", 1)[1].rstrip(";\n"))
    assert js["7"]["image"] == {"enabled": True, "quality": 85, "max_width": 2000, "avif": True, "smart": True,
                                "secret": SECRET}
    # a malformed secret is treated as unset (never a weaker check: no signing, like the controller's "")
    assert agent.norm_image_v2(site8(image={"transform_secret": "short"}))["secret"] == ""


def test_image_on_without_image_filter_uses_the_transformer(tmp_path):
    cfg = w8cfg(tmp_path, img=ALL_IMG)
    cfg["NGINX_CAPS"] = dict(cfg["NGINX_CAPS"], modules=["njs"])
    text, _ = agent.render_site(site8(image={"enabled": True}), cfg)
    assert "/__pcdn/img/" in text
    cfg["IMAGE_CAPS"] = dict(NO_IMG)
    text, _ = agent.render_site(site8(image={"enabled": True}), cfg)
    assert "/__pcdn/img/" not in text


def test_resizer_render_per_capability(tmp_path):
    def rz(mods, img):
        cfg = w8cfg(tmp_path, img=img)
        cfg["NGINX_CAPS"] = dict(cfg["NGINX_CAPS"], modules=mods)
        return agent.render_resizer(cfg)
    full = rz(["image_filter", "njs"], ALL_IMG)
    assert 'map $uri $pcdn_avif_ok {\n    default "1";\n}' in full
    assert "    default resize;\n" in full and '"~^[^|]*[|][^:]*:" v2;' in full
    assert "location ^~ /__pcdn_rz/resize/ {" in full and "image_filter resize $pcdn_rz_w $pcdn_rz_h;" in full
    assert "location ^~ /__pcdn_rz/v2/ {" in full and "proxy_pass http://127.0.0.1:8090;" in full
    assert "error_page 413 415 500 502 503 504 = $pcdn_rz_fb;" in full and "location @pcdn_rz_fbr {" in full
    assert "add_header X-Accel-Expires 60;" in full and "/__pcdn_rz/crop/" not in full
    src = full.split("location ^~ /__pcdn_rz/src/ {")[1].split("}")[0]
    assert "allow 127.0.0.1;" in src and "deny all;" in src
    filt_only = rz(["image_filter", "njs"], NO_IMG)
    assert 'default "0";' in filt_only and "/__pcdn_rz/v2/" not in filt_only and "/__pcdn_rz/crop/" in filt_only
    assert '"~^-[|]-:" src;' in filt_only and '"~^[^|]*[|][^:]*:cover:" crop;' in filt_only
    tr_only = rz(["njs"], ALL_IMG)
    assert "image_filter" not in tr_only.replace("image_filter module", "") and "    default v2;\n" in tr_only
    assert "error_page 413 415 500 502 503 504 = @pcdn_rz_fbs;" in tr_only
    none = rz(["njs"], NO_IMG)
    assert "server {" not in none and "$pcdn_avif_ok" in none
    assert "server {" not in rz(["image_filter"], ALL_IMG)        # no njs: nobody routes images


def test_image_signature_reference():
    sig = agent.image_signature(SECRET, "/img/cat.jpg", {"fit": "cover", "w": "300", "x": "ignored"})
    want = hmac.new(SECRET.encode(), b"/img/cat.jpg?w=300&fit=cover", hashlib.sha256).hexdigest()
    assert sig == want and len(sig) == 64


# ----------------------------------------------------------------- pcdn.js image / video logic

NJS = r"""
import m from './pcdn.mjs';
const store = {};
const dict = { get: k => store[k], set: (k, v) => { store[k] = v; }, add: (k, v) => (k in store ? false : ((store[k] = v), true)),
  incr: (k, d, i) => (store[k] = (store[k] === undefined ? i : store[k]) + d), delete: k => { delete store[k]; } };
globalThis.ngx = { shared: { pcdn_cnt: dict, pcdn_blk: dict, pcdn_hc: dict, pcdn_fair: dict, pcdn_vpf: dict } };
function argsOf(q) { const o = {}; q.split('&').forEach(p => { if (!p) return; const i = p.indexOf('=');
  const k = i < 0 ? p : p.slice(0, i); if (!(k in o)) o[k] = decodeURIComponent(i < 0 ? '' : p.slice(i + 1)); }); return o; }
const out = JSON.parse(process.argv[2]).map(c => {
  const [path, q] = c.url.split('?');
  const r = { uri: decodeURIComponent(path), method: 'GET', args: argsOf(q || ''),
    variables: { pcdn_site: c.site, args: q || '', request_uri: c.url, host: 'x.test', pcdn_avif_ok: c.avif ? '1' : '0' },
    headersIn: { Accept: c.accept || '*/*' } };
  if (c.kind === 'img') return [m.imgW(r), m.imgH(r), m.imgQ(r)];
  if (c.kind === 'vnext') return m.videoNext(r);
});
console.log(JSON.stringify(out));
"""


def njs_run(tmp_path, sites, cases):
    src = (HERE.parent / "njs/pcdn.js").read_text().replace("from 'sites.js'", "from './sites.mjs'")
    (tmp_path / "pcdn.mjs").write_text(src)
    (tmp_path / "sites.mjs").write_text("export default " + json.dumps(sites) + ";\n")
    (tmp_path / "h.mjs").write_text(NJS)
    p = subprocess.run(["node", str(tmp_path / "h.mjs"), json.dumps(cases)], capture_output=True, text=True, cwd=tmp_path)
    assert p.returncode == 0, p.stderr
    return json.loads(p.stdout)


def jsite(image=None, video=None):
    s = {"domain": "x.test", "secret": "k", "hosts": ["x.test"], "blocked_ips": [], "min_tls": "1.2",
         "firewall": {"default_action": "allow", "rules": []}, "hotlink": {"enabled": False}, "ratelimit": [],
         "ddos": {"mode": "off"}, "waf": {"mode": "off", "groups": [], "exclusions": [], "off_paths": []},
         "pools": {}, "image": image or {"enabled": False}, "tunnel_paths": []}
    if video:
        s["video"] = video
    return s


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_njs_image_params(tmp_path):
    sites = {"1": jsite({"enabled": True, "quality": 80, "max_width": 5000}),
             "2": jsite({"enabled": True, "quality": 80, "max_width": 2000, "avif": True, "smart": True,
                         "secret": SECRET}),
             "3": jsite({"enabled": True, "quality": 80, "max_width": 300, "avif": True})}
    good = agent.image_signature(SECRET, "/a%20b.jpg", {"w": "300", "fit": "cover"})
    cases = [
        {"kind": "img", "site": "1", "url": "/a.jpg?width=6000&height=x"},           # legacy unchanged
        {"kind": "img", "site": "1", "url": "/a.jpg?w=9999&fit=cover&q=50&fmt=webp"},
        {"kind": "img", "site": "1", "url": "/a.jpg?h=200&fmt=avif", "avif": False},  # no AVIF here: keep
        {"kind": "img", "site": "1", "url": "/a.jpg?h=200&fmt=avif", "avif": True},
        {"kind": "img", "site": "1", "url": "/a.jpg?fit=cover"},                     # nothing to do
        {"kind": "img", "site": "1", "url": "/a.jpg?q=0&w=0"},
        {"kind": "img", "site": "1", "url": "/a.jpg"},
        {"kind": "img", "site": "3", "url": "/a.png", "avif": True, "accept": "image/avif,image/webp,*/*"},
        {"kind": "img", "site": "3", "url": "/a.gif", "avif": True, "accept": "image/avif"},
        {"kind": "img", "site": "3", "url": "/a.png", "avif": False, "accept": "image/avif"},
        {"kind": "img", "site": "3", "url": "/a.png?w=1000", "avif": True, "accept": "image/avif"},  # cap 300
        {"kind": "img", "site": "2", "url": "/a%20b.jpg?w=300&fit=cover"},            # unsigned
        {"kind": "img", "site": "2", "url": f"/a%20b.jpg?fit=cover&w=300&sig={good}"},
        {"kind": "img", "site": "2", "url": f"/a%20b.jpg?fit=cover&w=301&sig={good}"},  # tampered
        {"kind": "img", "site": "2", "url": f"/a%20b.jpg?fit=cover&w=300&sig={good.upper()}&x=1"},
        {"kind": "img", "site": "2", "url": "/a%20b.jpg", "accept": "image/avif", "avif": True},  # no params: no sig
        {"kind": "img", "site": "2", "url": "/a.css?w=300"},
    ]
    r = njs_run(tmp_path, sites, cases)
    assert r[0] == ["5000", "-", "80"]
    assert r[1] == ["4096", "-:cover:webp:50:0", "50"]
    assert r[2] == ["-", "200:contain:keep:80:0", "80"]
    assert r[3] == ["-", "200:contain:avif:80:0", "80"]
    assert r[4] == ["", "", ""] and r[5] == ["", "", ""] and r[6] == ["", "", ""]
    assert r[7] == ["-", "-:contain:avif:80:0", "80"]
    assert r[8] == ["", "", ""] and r[9] == ["", "", ""]
    assert r[10] == ["300", "-:contain:avif:80:0", "80"]
    assert r[11] == ["!", "!", ""]
    assert r[12] == ["300", "-:cover:keep:80:1", "80"]                          # smart crop on cover
    assert r[13] == ["!", "!", ""]
    assert r[14] == ["300", "-:cover:keep:80:1", "80"]                          # hex case-insensitive
    assert r[15] == ["-", "-:contain:avif:80:0", "80"]
    assert r[16] == ["", "", ""]


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_njs_video_next(tmp_path):
    sites = {"1": jsite(video={"prefetch": True}), "2": jsite()}
    cases = [{"kind": "vnext", "site": "1", "url": u} for u in
             ("/live/seg_0099.ts?tok=1", "/live/seg_0099.ts", "/a/b9/x7.m4s", "/a/v.mp4", "/a/index.m3u8",
              "/a/999999999.aac", "/a/noseq.ts")] + [{"kind": "vnext", "site": "2", "url": "/s1.ts"}]
    r = njs_run(tmp_path, sites, cases)
    assert r[0] == "/live/seg_0100.ts" and r[1] == ""                          # once per next segment
    assert r[2] == "/a/b9/x8.m4s" and r[3] == "" and r[4] == ""
    assert r[5] == "/a/1000000000.aac" and r[6] == "" and r[7] == ""


# ----------------------------------------------------------------- image transformer (Pillow)

def _img(fmt="JPEG", size=(400, 200), mode="RGB", color=(200, 30, 30)):
    im = Image.new(mode, size, color if mode == "RGB" else color + (128,))
    # a high-entropy patch on the right, so the smart crop has something to find
    for x in range(size[0] - 60, size[0] - 10):
        for y in range(0, size[1], 2):
            im.putpixel((x, y), ((x * 37) % 255, (y * 91) % 255, (x * y) % 255) + (() if mode == "RGB" else (255,)))
    buf = io.BytesIO()
    im.save(buf, fmt)
    return buf.getvalue()


def test_parse_image_spec():
    assert agent.parse_image_spec("300", "-:cover:webp:50:1", "50") == {"w": 300, "h": None, "fit": "cover",
                                                                       "fmt": "webp", "q": 50, "smart": True}
    assert agent.parse_image_spec("9999", "200", "77") == {"w": 4096, "h": 200, "fit": "contain", "fmt": "keep",
                                                          "q": 77, "smart": False}
    for bad in (("x", "-", "1"), ("1", "-:fill:webp:50:0", "1"), ("1", "1:cover:gif:1:0", "1"), ("1", "!", "")):
        assert agent.parse_image_spec(*bad) is None


@needs_pil
def test_transform_image_resize_formats_and_crop():
    out, ct = agent.transform_image(_img(), agent.parse_image_spec("100", "-:contain:keep:80:0", "80"))
    assert ct == "image/jpeg" and Image.open(io.BytesIO(out)).size == (100, 50)
    out, ct = agent.transform_image(_img(), agent.parse_image_spec("1000", "-:contain:webp:80:0", "80"))
    im = Image.open(io.BytesIO(out))
    assert ct == "image/webp" and im.format == "WEBP" and im.size == (400, 200)     # never enlarged
    out, ct = agent.transform_image(_img("PNG", mode="RGBA"), agent.parse_image_spec("-", "-:contain:jpeg:70:0", "70"))
    assert ct == "image/jpeg" and Image.open(io.BytesIO(out)).mode == "RGB"         # alpha flattened
    out, ct = agent.transform_image(_img("PNG"), agent.parse_image_spec("-", "-", "80"))
    assert ct == "image/png"
    # cover: exact box; smart crop moves toward the busy right side, the center crop does not
    center, _ = agent.transform_image(_img(), agent.parse_image_spec("100", "100:cover:keep:95:0", "80"))
    smart, _ = agent.transform_image(_img(), agent.parse_image_spec("100", "100:cover:keep:95:1", "80"))
    c, s = Image.open(io.BytesIO(center)), Image.open(io.BytesIO(smart))
    assert c.size == s.size == (100, 100)
    assert s.convert("L").entropy() > c.convert("L").entropy()
    # AVIF: Pillow plugin or avifenc; "none" keeps the source format
    out, ct = agent.transform_image(_img(), agent.parse_image_spec("50", "-:contain:avif:60:0", "60"), "none")
    assert ct == "image/jpeg"


@needs_pil
def test_transform_image_rejects_bad_input(monkeypatch):
    spec = agent.parse_image_spec("10", "-", "80")
    with pytest.raises(ValueError):
        agent.transform_image(b"not an image", spec)
    frames = [Image.new("RGB", (20, 20), c) for c in ((255, 0, 0), (0, 255, 0))]
    buf = io.BytesIO()
    frames[0].save(buf, "GIF", save_all=True, append_images=frames[1:])
    with pytest.raises(ValueError):
        agent.transform_image(buf.getvalue(), spec)                             # animated: fallback
    monkeypatch.setattr(agent, "IMAGE_MAX_PIXELS", 100)
    with pytest.raises(ValueError):
        agent.transform_image(_img(), spec)                                     # pixel bomb guard


@needs_pil
def test_avif_via_avifenc_is_used_without_pillow_avif(monkeypatch, tmp_path):
    calls = []

    def fake_run(cmd, capture_output, timeout):
        calls.append(cmd)
        pathlib.Path(cmd[-1]).write_bytes(b"\x00\x00\x00\x1cftypavif")
        return subprocess.CompletedProcess(cmd, 0, b"", b"")
    monkeypatch.setattr(agent.shutil, "which", lambda name: "/usr/bin/avifenc" if name == "avifenc" else None)
    monkeypatch.setattr(agent.subprocess, "run", fake_run)
    out, ct = agent.transform_image(_img(), agent.parse_image_spec("50", "-:contain:avif:61:0", "61"), "avifenc")
    assert ct == "image/avif" and out.endswith(b"ftypavif")
    assert calls[0][:5] == ["/usr/bin/avifenc", "-q", "61", "-s", "8"]


# ----------------------------------------------------------------- host guard (SPEC §16.3)

def test_guard_ruleset_order_and_values(tmp_path):
    cfg = make_cfg(tmp_path, GUARD_SSH_PORTS="22 2222", GUARD_ALLOW="203.0.113.0/24, 2001:db8::/48 junk",
                   GUARD_SYN_RATE="500", HTTP_PORT="8080")
    text = agent.render_guard(cfg, synproxy=True, allow=agent.guard_allow(
        dict(cfg, CONTROLLER_URL="https://ctl.example"), resolve=lambda h, p: [(2, 1, 6, "", ("198.51.100.7", 0))]),
        wscale=10, mtu=1500)
    rules = text.split("chain input {")[1]
    order = [rules.index(x) for x in ('iif "lo" accept', "tcp dport { 22, 2222 } accept", "ip saddr @allow4 accept",
                                      "ip6 saddr @allow6 accept", "update @syn4", "synproxy mss 1460 wscale 10",
                                      "synproxy mss 1440 wscale 10", "ct state invalid drop", "limit rate over 50000/second",
                                      "udp dport 443 update @udp4", "icmp type echo-request")]
    assert order == sorted(order)
    assert "elements = { 198.51.100.7/32, 203.0.113.0/24 }" in text and "elements = { 2001:db8::/48 }" in text
    assert "limit rate over 500/second burst 2000 packets" in text
    assert "tcp dport { 8080, 443 } tcp flags & (fin|syn|rst|ack) == syn notrack" in text
    assert text.count("policy accept;") == 2 and "policy drop" not in text
    assert text.startswith("# pcdn host network guard") and "table inet pcdn_guard {}\ndelete table inet pcdn_guard\n" in text
    plain = agent.render_guard(cfg, allow=([], []), wscale=7, mtu=1500)
    assert "synproxy" not in plain and "chain raw" not in plain and "notrack" not in plain
    assert "elements" not in plain.split("set syn4")[0]                          # empty allow sets


@pytest.mark.skipif(shutil.which("nft") is None or os.geteuid() != 0, reason="nft / root not available")
def test_guard_ruleset_accepted_by_nft(tmp_path):
    cfg = make_cfg(tmp_path, GUARD_ALLOW="203.0.113.5 2001:db8::1")
    for sp in (False, True):
        f = tmp_path / f"g{sp}.nft"
        f.write_text(agent.render_guard(cfg, synproxy=sp, allow=agent.guard_allow(cfg)))
        p = subprocess.run(["nft", "-c", "-f", str(f)], capture_output=True, text=True)
        if p.returncode != 0 and "Operation not permitted" in p.stderr:
            pytest.skip("no netlink permission for nft -c")
        assert p.returncode == 0, p.stderr


def test_tcp_wscale_and_mtu(tmp_path):
    proc = tmp_path / "proc"
    (proc / "net/ipv4").mkdir(parents=True)
    (proc / "net/core").mkdir(parents=True)
    (proc / "net/ipv4/tcp_rmem").write_text("4096 131072 67108864\n")
    (proc / "net/core/rmem_max").write_text("67108864\n")
    assert agent.tcp_wscale(str(proc)) == 11
    (proc / "net/ipv4/tcp_rmem").write_text("4096 131072 6291456\n")
    (proc / "net/core/rmem_max").write_text("212992\n")
    assert agent.tcp_wscale(str(proc)) == 7
    assert agent.tcp_wscale(str(tmp_path / "none")) == 7
    (tmp_path / "net/eth0").mkdir(parents=True)
    (tmp_path / "net/eth0/mtu").write_text("9000\n")
    assert agent.iface_mtu("eth0", str(tmp_path / "net")) == 9000 and agent.iface_mtu(None, str(tmp_path)) == 1500


def test_guard_cli_prints_ruleset(tmp_path):
    conf = tmp_path / "agent.conf"
    conf.write_text("CONTROLLER_URL=https://127.0.0.1:1\nGUARD_SSH_PORTS=2200\n")
    p = subprocess.run(["python3", str(HERE.parent / "pcdn-agent.py"), "guard"], capture_output=True, text=True,
                       env=dict(os.environ, PCDN_CONFIG=str(conf)))
    assert p.returncode == 0 and "tcp dport { 2200 } accept" in p.stdout and "127.0.0.1/32" in p.stdout


# ----------------------------------------------------------------- install.sh (wave 8 blocks)

def _block(start, end):
    install = (HERE.parent / "install.sh").read_text()
    return start + install.split(start, 1)[1].split(end, 1)[0]


def test_install_wave8_conf_and_upgrade(tmp_path):
    conf = tmp_path / "agent.conf"
    upgrade = _block('if [ "$UPGRADE" = yes ]; then', 'HTTP3="${HTTP3:-no}"') + 'HTTP3="${HTTP3:-no}"\n'
    defaults = 'HARDEN_NET="${HARDEN_NET:-no}"\nAVIF="${AVIF:-yes}"\n'
    write = _block("cat > /etc/pcdn/agent.conf <<EOF", "\nEOF") + "\nEOF\n"
    keep = _block("# >>> pcdn keep logship", "# <<< pcdn keep logship")
    w8 = _block("# >>> pcdn wave8 conf", "# <<< pcdn wave8 conf")
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "CONTROLLER": "", "TOKEN": "", "REGION": "", "ROLE": "",
           "TCP_CC": "", "HTTP3": "", "KEEP_CONF": "", "NGINX_USER": "www-data", "IPV6": "yes", "CACHE_SIZE": "10g",
           "HTTP_PORT": "80", "HTTPS_PORT": "443", "UPGRADE": "no"}

    def run(script, **over):
        script = script.replace("/etc/pcdn/agent.conf", str(conf))
        p = subprocess.run(["bash", "-euc", script + '\necho "G=$HARDEN_NET A=$AVIF"'], env=dict(env, **over),
                           capture_output=True, text=True, check=True)
        return p.stdout.strip().splitlines()[-1]
    # fresh install, defaults: guard off, AVIF tooling on, SSH ports recorded
    assert run(defaults + write + keep + w8, CONTROLLER="https://c", TOKEN="t") == "G=no A=yes"
    cfg = agent.load_config(str(conf))
    assert cfg["GUARD"] == "no" and cfg["AVIF"] == "yes" and re.match(r"^[\d ]+$", cfg["GUARD_SSH_PORTS"])
    # an operator's wave-8 tunables + the guard survive --upgrade
    conf.write_text("CONTROLLER_URL=https://c\nEDGE_TOKEN=t\nGUARD=evil\nGUARD=yes\nAVIF=no\nGUARD_SSH_PORTS=2222\n"
                    "GUARD_SYN_RATE=300\nL4_PORT_RANGE=30000-31000\nIMAGED=no\n")
    assert run(upgrade + defaults + write + keep + w8, UPGRADE="yes") == "G=yes A=no"
    text = conf.read_text()
    cfg = agent.load_config(str(conf))
    assert cfg["GUARD"] == "yes" and cfg["GUARD_SSH_PORTS"] == "2222" and cfg["GUARD_SYN_RATE"] == "300"
    assert cfg["L4_PORT_RANGE"] == "30000-31000" and cfg["IMAGED"] == "no" and text.count("GUARD_SSH_PORTS=") == 1
    # explicit flags win over the installed values
    assert run(upgrade + defaults + write + keep + w8, UPGRADE="yes", HARDEN_NET="no", AVIF="yes") == "G=no A=yes"


def test_install_nginx_conf_gets_main_context_l4_include(tmp_path):
    block = _block("# >>> nginx.conf edits", "# <<< nginx.conf edits")
    ngx = tmp_path / "nginx.conf"
    ngx.write_text("user www-data;\nevents {\n    worker_connections 768;\n}\nhttp {\n    gzip on;\n}\n#mail {\n#}\n")
    for _ in range(2):
        subprocess.run(["bash", "-ec", block.replace("/etc/nginx/nginx.conf", str(ngx))], check=True)
    text = ngx.read_text()
    assert text.count("include /etc/nginx/pcdn/l4/*.conf;") == 1
    assert text.rstrip().endswith("include /etc/nginx/pcdn/l4/*.conf;")       # after http {}: main context
    install = (HERE.parent / "install.sh").read_text()
    assert "libnginx-mod-stream" in install and "/var/log/nginx/pcdn-l4.log" in install
    assert "pcdn-imaged.service" in install and "pcdn-guard.service" in install
    for unit in ("pcdn-imaged.service", "pcdn-guard.service"):
        assert (HERE.parent / "systemd" / unit).is_file()
    imaged = (HERE.parent / "systemd/pcdn-imaged.service").read_text()
    assert "DynamicUser=yes" in imaged and "IPAddressDeny=any" in imaged and "IPAddressAllow=localhost" in imaged
    guard = (HERE.parent / "systemd/pcdn-guard.service").read_text()
    assert "ExecStop=-/usr/sbin/nft delete table inet pcdn_guard" in guard
    boot = (HERE.parent / "bootstrap.sh").read_text()
    assert "|--harden-net|--no-harden-net|--avif|--no-avif)" in boot
    assert subprocess.run(["bash", "-n", str(HERE.parent / "install.sh")]).returncode == 0
