"""SPEC §16.9 edge functions: validation / rendering / usage (agent) and the pcdn-fn sandbox.

Unit tests cover the edge-config contract (norm_functions), the pcdn-fn bundle, the nginx rendering,
the capability and usage plumbing, and pcdn-fn's response / header / cookie validation.

Real-process tests run the actual sandbox (Landlock + seccomp + rlimits + CPU timer) around
(1) a compiled C probe that tries every escape directly at the syscall level and (2) QuickJS workers
running hostile customer code: no file reads, no sockets, no processes, no signals, CPU / memory /
wall-clock / output caps, and no data shared between invocations or sites.
"""

import asyncio
import importlib.util
import json
import os
import pathlib
import shutil
import socket
import stat
import subprocess
import time

import pytest
from conftest import TEST_ORIGIN_ALLOW

HERE = pathlib.Path(__file__).resolve().parent
EDGE = HERE.parent


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, EDGE / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


agent = _load("agent_fn", "pcdn-agent.py")
fn = _load("pcdn_fn", "pcdn-fn.py")

QJS = shutil.which("qjs")
RUNTIME = str(EDGE / "fn" / "runtime.js")
LANDLOCK = fn.landlock_abi() if hasattr(fn, "landlock_abi") else 0
needs_sandbox = pytest.mark.skipif(not QJS or LANDLOCK < 1 or os.uname().machine not in fn.SYSCALLS,
                                   reason="needs qjs (package quickjs) and Landlock")


def site(sid=7, functions=None, **kw):
    s = {"id": sid, "domain": "ex.test", "status": "active", "secret": "5e" * 32, "ssl": None,
         "hosts": [{"name": "ex.test", "origin": {"address": "127.0.0.1", "port": 8080}},
                   {"name": "www.ex.test", "origin": {"address": "127.0.0.1", "port": 8080}}],
         "cache": {"enabled": True, "level": "standard", "edge_ttl": 3600}}
    if functions is not None:
        s["functions"] = functions
    s.update(kw)
    return s


def item(fid="hello", route="/api/", code="function handleRequest(r){return new Response('x')}", **kw):
    return dict({"id": fid, "route": route, "code": code, "enabled": True}, **kw)


def cfg_for(tmp, **over):
    cfg = dict(agent.DEFAULTS, ORIGIN_PRIVATE_ALLOW=TEST_ORIGIN_ALLOW)
    cfg.update({"FUNCTIONS": "yes", "NGINX_CAPS": {"modules": ["njs"], "nginx": "1.24.0"},
                "NJS_FILE": str(EDGE / "njs/pcdn.js"), "BASE_TEMPLATE": str(EDGE / "nginx/pcdn-base.conf"),
                "NGINX_DIR": str(tmp / "pcdn"), "FN_DIR": str(tmp / "fn"), "FN_STATUS": str(tmp / "status.json"),
                "FN_SOCKET": str(tmp / "fn.sock"), "FN_FETCH_SOCKET": str(tmp / "fetch.sock"),
                "GEOIP_DB": str(tmp / "none.mmdb"), "NGINX_USER": "root"})
    cfg.update(over)
    return cfg


# ================================================================== edge-config contract

def test_norm_functions_valid_defaults_and_contract():
    out = agent.norm_functions(site(functions={"enabled": True, "items": [item()]}))
    assert len(out) == 1
    f = out[0]
    assert (f["id"], f["route"], f["timeout_ms"], f["memory_mb"], f["on_error"]) == ("hello", "/api/", 50, 32, "502")
    assert f["sha256"] == __import__("hashlib").sha256(f["code"].encode()).hexdigest()
    # explicit limits / on_error, site-level on_error default
    out = agent.norm_functions(site(functions={"enabled": True, "on_error": "origin", "items": [
        item(timeout_ms=200, memory_mb=128), item("b", "/b", on_error="502"), item("c", "/c", timeout_ms=1,
                                                                             memory_mb=8)]}))
    assert [(f["id"], f["timeout_ms"], f["memory_mb"], f["on_error"]) for f in out] == [
        ("hello", 200, 128, "origin"), ("b", 50, 32, "502"), ("c", 1, 8, "origin")]


@pytest.mark.parametrize("bad", [
    {"id": "Bad"}, {"id": "x" * 33}, {"id": ""}, {"route": "api"}, {"route": "/__pcdn/x"}, {"route": "/__pcdnx"},
    {"route": "/a//b"}, {"route": "/a/../b"}, {"route": "/a/./b"}, {"route": "/.."}, {"route": "/a b"},
    {"route": "/a?b"}, {"route": "/a;b"}, {"route": "/a\"b"}, {"route": "/" + "a" * 256}, {"code": ""},
    {"code": "   "}, {"code": 5}, {"code": "x" * (256 * 1024 + 1)}, {"code": "م" * (128 * 1024 + 1)},
    {"timeout_ms": 0}, {"timeout_ms": 201}, {"timeout_ms": "50"}, {"timeout_ms": True}, {"memory_mb": 7},
    {"memory_mb": 129}, {"on_error": "pass"}, {"enabled": False},
])
def test_norm_functions_rejects_invalid_items(bad):
    assert agent.norm_functions(site(functions={"enabled": True, "items": [dict(item(), **bad)]})) == []


def test_norm_functions_section_off_duplicates_tunnel_overlap_and_cap():
    assert agent.norm_functions(site(functions={"enabled": False, "items": [item()]})) == []
    assert agent.norm_functions(site(functions={"items": [item()]})) == []
    assert agent.norm_functions(site()) == []
    out = agent.norm_functions(site(functions={"enabled": True, "items": [
        item("a", "/x"), item("a", "/y"), item("b", "/x"), item("c", "/z")]}))
    assert [(f["id"], f["route"]) for f in out] == [("a", "/x"), ("c", "/z")]
    out = agent.norm_functions(site(functions={"enabled": True, "items": [
        item("a", "/tn"), item("b", "/tn/sub"), item("c", "/t"), item("d", "/other")]}), ["/tn"])
    assert [f["id"] for f in out] == ["d"]
    many = [item(f"f{i}", f"/r{i}") for i in range(40)]
    assert len(agent.norm_functions(site(functions={"enabled": True, "items": many}))) == agent.FN_MAX_PER_SITE
    # exactly 256 KB of UTF-8 is accepted
    assert agent.norm_functions(site(functions={"enabled": True, "items": [item(code="x" * 256 * 1024)]}))


# ================================================================== bundle + rendering

def test_render_functions_bundle(tmp_path):
    cfg = cfg_for(tmp_path)
    cfg_off = dict(cfg, FUNCTIONS="no")
    conf = {"sites": [site(functions={"enabled": True, "items": [item(), item("b", "/b", code="1")]}),
                      site(8, functions={"enabled": True, "items": [item()]}, status="suspended"),
                      site(9)]}
    assert agent.render_functions(conf, cfg_off) == {}
    files = agent.render_functions(conf, cfg)
    man = json.loads(files["manifest.json"])
    assert list(man["sites"]) == ["7"]
    s7 = man["sites"]["7"]
    assert s7["domain"] == "ex.test" and s7["hosts"] == ["ex.test", "www.ex.test"]
    assert set(s7["functions"]) == {"hello", "b"} and "code" not in s7["functions"]["hello"]
    for f in s7["functions"].values():
        assert f"code/{f['sha256']}.js" in files
    assert "\"secret\"" not in files["manifest.json"]


def test_write_and_sync_functions_permissions(tmp_path):
    cfg = cfg_for(tmp_path)
    conf = {"sites": [site(functions={"enabled": True, "items": [item()]})]}
    st = {}
    agent.sync_functions(conf, cfg, st)
    root = pathlib.Path(cfg["FN_DIR"])
    assert stat.S_IMODE(root.stat().st_mode) == 0o750
    assert stat.S_IMODE((root / "code").stat().st_mode) == 0o750
    for p in [root / "manifest.json"] + list((root / "code").iterdir()):
        assert stat.S_IMODE(p.stat().st_mode) == 0o640
    d1 = st["fn_digest"]
    ino = (root / "manifest.json").stat().st_ino
    agent.sync_functions(conf, cfg, st)                        # unchanged: not rewritten
    assert (root / "manifest.json").stat().st_ino == ino
    conf["sites"][0]["functions"]["items"][0]["code"] = "function handleRequest(){return null}"
    agent.sync_functions(conf, cfg, st)
    assert st["fn_digest"] != d1 and len(list((root / "code").iterdir())) == 1
    agent.sync_functions({"sites": []}, cfg, st)               # last function removed: empty bundle
    assert not (root / "manifest.json").exists()


def _render(tmp_path, s, **over):
    cfg = cfg_for(tmp_path, **over)
    text, _, _, meta = agent._render_site(s, cfg)
    return text, meta, cfg


def test_render_routes_named_locations_and_fetch_server(tmp_path):
    s = site(functions={"enabled": True, "items": [item(on_error="origin"), item("b", "/x.y", timeout_ms=10)]})
    text, meta, cfg = _render(tmp_path, s)
    assert meta["functions"] is True
    assert text.count("location ^~ /api/ {") == 2 and text.count("location ^~ /x.y {") == 2   # 2 hosts
    assert f"proxy_pass http://unix:{cfg['FN_SOCKET']}:;" in text
    blk = text[text.index("location ^~ /api/ {"):]
    blk = blk[:blk.index("    }")]
    for line in ("proxy_set_header X-Pcdn-Fn-Site 7;", "proxy_set_header X-Pcdn-Fn-Id hello;",
                 "proxy_set_header X-Pcdn-Fn-Err @pcdn_fn_pass;", "error_page 502 504 = @pcdn_fn_pass;",
                 "proxy_intercept_errors off;", "client_max_body_size 1048576;", 'proxy_set_header X-Pcdn-Shield "";'):
        assert line in blk, line
    blk = text[text.index("location ^~ /x.y {"):]
    blk = blk[:blk.index("    }")]
    assert "X-Pcdn-Fn-Err @pcdn_fn_err;" in blk and "error_page" not in blk
    assert text.count("location @pcdn_fn_err { return 502; }") == 2
    assert text.count("location @pcdn_fn_pass {") == 2
    # the WAF body inspector / image resizer never take a function route
    assert '"~^(?:/api/|/x\\.y)" 1;' in text
    assert "if ($pcdn_bodychk)" not in text
    # one local fetch server per host, never on a TCP port
    assert text.count(f"listen unix:{cfg['FN_FETCH_SOCKET']};") == 2
    assert "server_name www.ex.test;" in text and "real_ip_header X-Pcdn-Fn-Client;" in text
    fetch = text[text.index(f"listen unix:{cfg['FN_FETCH_SOCKET']};"):]
    assert "proxy_cache off;" in fetch and 'proxy_set_header X-Pcdn-Fn-Client "";' in fetch
    files = agent.render_all({"sites": [s]}, cfg)
    assert f"listen unix:{cfg['FN_FETCH_SOCKET']} default_server;" in files["http.conf"]
    assert "return 421;" in files["http.conf"]


def test_render_without_functions_is_unchanged(tmp_path):
    plain, _, cfg = _render(tmp_path, site())
    off, _, _ = _render(tmp_path, site(functions={"enabled": False, "items": [item()]}))
    assert plain == off and "pcdn_fn" not in plain and "unix:" not in plain
    files = agent.render_all({"sites": [site()]}, cfg)
    assert cfg["FN_FETCH_SOCKET"] not in files["http.conf"]


def test_render_node_without_pcdn_fn_fails_closed(tmp_path):
    s = site(functions={"enabled": True, "items": [item(), item("b", "/b", on_error="origin")]})
    text, meta, _ = _render(tmp_path, s, FUNCTIONS="no")
    assert not meta["functions"] and "unix:" not in text
    assert text.count("location ^~ /api/ { return 502; }") == 2      # fail-closed function
    assert "location ^~ /b" not in text                              # on_error origin: origin as usual


def test_render_root_route_owns_location(tmp_path):
    text, _, cfg = _render(tmp_path, site(functions={"enabled": True, "items": [item(route="/")]}))
    main = text[:text.index("listen unix:")]
    assert "location ^~ / {" in main and "    location / {" not in main
    text, _, _ = _render(tmp_path, site(functions={"enabled": True, "items": [item(route="/")]}), FUNCTIONS="no")
    assert "location ^~ / { return 502; }" in text and "    location / {" not in text


def test_render_suspended_or_decoy_site_has_no_functions(tmp_path):
    s = site(functions={"enabled": True, "items": [item()]}, status="suspended")
    text, meta, _ = _render(tmp_path, s)
    assert "pcdn_fn" not in text and not meta["functions"]


# ================================================================== capability + usage

def test_functions_ready_capability(tmp_path):
    cfg = cfg_for(tmp_path)
    assert agent.functions_ready(cfg) is False                        # no status yet
    good = {"ok": True, "checks": {"engine": True, "fs_denied": True}}
    pathlib.Path(cfg["FN_STATUS"]).write_text(json.dumps(good))
    assert agent.functions_ready(cfg) is False                        # no socket
    s = socket.socket(socket.AF_UNIX)
    s.bind(cfg["FN_SOCKET"])
    try:
        assert agent.functions_ready(cfg) is True
        assert agent.heartbeat_capabilities(dict(cfg, NGINX_CAPS={"modules": [], "nginx": "1.24.0"},
                                                 IMAGE_CAPS={}))["edge_functions"] is True
        assert agent.functions_ready(dict(cfg, FUNCTIONS="no")) is False
        pathlib.Path(cfg["FN_STATUS"]).write_text(json.dumps({"ok": True, "checks": {"engine": True,
                                                                                    "fs_denied": False}}))
        assert agent.functions_ready(cfg) is False                    # a failed sandbox check
        pathlib.Path(cfg["FN_STATUS"]).write_text(json.dumps(good))
        old = time.time() - agent.FN_STATUS_MAX_AGE - 5
        os.utime(cfg["FN_STATUS"], (old, old))
        assert agent.functions_ready(cfg) is False                    # pcdn-fn stopped refreshing it
    finally:
        s.close()


def test_read_fn_usage_and_usage_item(tmp_path):
    log = tmp_path / "usage.log"
    lines = [{"t": "2026-10-01T10:05:00Z", "h": "ex.test", "n": 3, "c": 41, "e": 1, "o": 1},
             {"t": "2026-10-01T10:59:59Z", "h": "ex.test", "n": 2, "c": 9, "e": 0, "o": 0},
             {"t": "2026-10-01T11:00:01Z", "h": "ex.test", "n": 1, "c": 5, "e": 0, "o": 0},
             {"t": "2026-10-01T10:00:00Z", "h": "BAD HOST", "n": 9}]
    log.write_text("".join(json.dumps(x) + "\n" for x in lines) + '{"t": "partial')
    st = {}
    agent.read_fn_usage(st, str(log))
    item10 = agent.usage_item("ex.test|2026-10-01T10:00:00Z", st["pending"]["ex.test|2026-10-01T10:00:00Z"])
    assert item10["functions"] == {"invocations": 5, "cpu_ms": 50, "errors": 1, "timeouts": 1}
    assert item10["bytes"] == 0 and item10["requests"] == 0
    assert st["pending"]["ex.test|2026-10-01T11:00:00Z"]["functions"]["invocations"] == 1
    assert len(st["pending"]) == 2
    # rotation by pcdn-fn: the rest of the old file is read first, then the new one
    with open(log, "a") as f:
        f.write('"}\n' + json.dumps({"t": "2026-10-01T11:10:00Z", "h": "ex.test", "n": 4}) + "\n")
    os.replace(log, str(log) + ".1")
    log.write_text(json.dumps({"t": "2026-10-01T11:20:00Z", "h": "ex.test", "n": 10}) + "\n")
    agent.read_fn_usage(st, str(log))
    assert st["pending"]["ex.test|2026-10-01T11:00:00Z"]["functions"]["invocations"] == 15
    assert "functions" not in agent.usage_item("a.test|2026-10-01T10:00:00Z", {"bytes": 1, "requests": 1,
                                                                               "cache_hits": 0})


# ================================================================== pcdn-fn validation (unit)

def test_clean_headers_policy():
    h = fn.clean_headers([["Content-Type", "text/plain"], ["X-Accel-Redirect", "/__pcdn/x"],
                          ["x-accel-buffering", "no"], ["Transfer-Encoding", "chunked"], ["Connection", "x"],
                          ["Content-Length", "1"], ["X-Pcdn-Fn-Site", "1"], ["Server", "evil"], ["Status", "200"],
                          ["Set-Cookie", "a=1; Domain=evil.test"], ["Set-Cookie", "b=2; Domain=.ex.test; Path=/"],
                          ["Set-Cookie", "c=3"], ["Set-Cookie", "d=4; domain=test"], ["Set-Cookie", "e=5; Domain=ex.test.evil"],
                          ["Set-Cookie", "f=6; Domain=www.ex.test"], ["Set-Cookie", "g=7; Domain=other.ex.test"],
                          ["X-Ok", "v"]], host="www.ex.test", domain="ex.test")
    assert h == [("Content-Type", "text/plain"), ("Set-Cookie", "b=2; Domain=.ex.test; Path=/"),
                 ("Set-Cookie", "c=3"), ("Set-Cookie", "f=6; Domain=www.ex.test"), ("X-Ok", "v")]
    for bad in ([["Bad Name", "x"]], [["X", "a\r\nInjected: 1"]], [["X", "a\nb"]], [["X", "\x00"]], [["X"]],
                [[1, "x"]], "notalist", [["X", "y" * 9000]]):
        with pytest.raises(ValueError):
            fn.clean_headers(bad, host="ex.test", domain="ex.test")
    with pytest.raises(ValueError):
        fn.clean_headers([[f"X-{i}", "v"] for i in range(fn.MAX_HEADERS + 1)], host="ex.test", domain="ex.test")
    with pytest.raises(ValueError):
        fn.clean_headers([[f"X-{i}", "v" * 4000] for i in range(10)], host="ex.test", domain="ex.test")
    many = fn.clean_headers([["Set-Cookie", f"k{i}=v"] for i in range(40)], host="ex.test", domain="ex.test")
    assert len(many) == fn.MAX_SET_COOKIE


def test_limits_bpf_and_helpers():
    assert fn.clamp_limits(None, None) == (50, 32)
    assert fn.clamp_limits(10_000, 10_000) == (200, 128)
    assert fn.clamp_limits(0, 0) == (1, 8)
    assert fn.host_matches("*.ex.test", "a.ex.test") and not fn.host_matches("*.ex.test", "ex.test")
    assert not fn.host_matches("ex.test", "evil-ex.test")
    for arch in fn.SYSCALLS:
        prog = fn.seccomp_program(arch)
        assert len(prog) % 8 == 0
        import struct
        ins = [struct.unpack("=HBBI", prog[i:i + 8]) for i in range(0, len(prog), 8)]
        assert ins[0] == (0x20, 0, 0, 4) and ins[1][3] == fn.AUDIT_ARCH[arch] and ins[2] == (6, 0, 0, fn.RET_KILL)
        allowed = {k for c, _, _, k in ins if c == 0x15}
        nrs = fn.SYSCALLS[arch]
        for forbidden in ("socket", "connect", "fork", "clone", "kill", "ptrace", "ioctl", "rt_sigaction"):
            assert forbidden not in nrs
        assert nrs["execve"] in allowed and nrs["read"] in allowed
    if QJS:
        assert fn.elf_interp(os.path.realpath(QJS)).startswith("/")


def test_manifest_rejects_tampered_code(tmp_path):
    (tmp_path / "code").mkdir()
    good = b"function handleRequest(){return null}"
    sha = __import__("hashlib").sha256(good).hexdigest()
    (tmp_path / "code" / f"{sha}.js").write_bytes(good)
    bad_sha = "0" * 64
    (tmp_path / "code" / f"{bad_sha}.js").write_bytes(good)
    (tmp_path / "manifest.json").write_text(json.dumps({"v": 1, "sites": {"7": {"functions": {"a": {"sha256": sha}}}}}))
    m = fn.Manifest(str(tmp_path))
    site_, f = m.lookup("7", "a")
    assert f["sha256"] == sha and m.source(sha) == good.decode()
    assert m.source(bad_sha) is None and m.source("../manifest") is None
    assert m.lookup("8", "a") == (None, None)


# ================================================================== real processes: the sandbox

PROBE_C = r"""
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
static void r(const char *n, long v) { printf("%s=%ld:%d\n", n, v, v < 0 ? errno : 0); fflush(stdout); }
int main(int argc, char **argv) {
  r("socket_inet", socket(AF_INET, SOCK_STREAM, 0));
  r("socket_inet6", socket(AF_INET6, SOCK_DGRAM, 0));
  r("socket_unix", socket(AF_UNIX, SOCK_STREAM, 0));
  r("socket_netlink", socket(AF_NETLINK, SOCK_RAW, 0));
  int sv[2]; r("socketpair", socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
  r("open_passwd", open("/etc/passwd", O_RDONLY));
  r("open_secret", open(argv[1], O_RDONLY));
  r("open_proc", open("/proc/self/environ", O_RDONLY));
  r("open_write_tmp", open("/tmp/pcdn-fn-probe", O_WRONLY | O_CREAT, 0600));
  r("mkdir", mkdir("/tmp/pcdn-fn-probe-dir", 0700));
  r("fork", (long)syscall(SYS_fork));
  r("clone", (long)syscall(SYS_clone, SIGCHLD, 0, 0, 0, 0));
  r("kill_init", kill(1, 0));
  r("kill_parent", kill(getppid(), 0));
  r("ptrace", ptrace(PTRACE_ATTACH, getppid(), 0, 0));
  char *av[] = {"/bin/true", 0};
  r("execve_true", execve("/bin/true", av, 0));
  struct stat st; r("stat_passwd", stat("/etc/passwd", &st));
  r("ioctl", ioctl(0, 0x5401, 0));
  struct rlimit rl = {1 << 30, 1 << 30}; r("raise_rlimit", setrlimit(RLIMIT_AS, &rl));
  r("sigaction", syscall(SYS_rt_sigaction, SIGPROF, 0, 0, 8));
  void *p = mmap(0, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  r("mmap_wx", p == MAP_FAILED ? -1 : 0);
  r("unshare", (long)syscall(SYS_unshare, 0x10000000));
  r("chdir", chdir("/etc"));
  r("fcntl_setown", fcntl(1, F_SETOWN, getppid()));
  r("fcntl_setsig", fcntl(1, F_SETSIG, SIGKILL));
  r("fcntl_getfl", fcntl(1, F_GETFL) >= 0 ? 0 : -1);
  r("open_opath", open("/etc/passwd", O_PATH));
  r("done", 0);
  return 0;
}
"""


@pytest.fixture(scope="module")
def probe(tmp_path_factory):
    if not shutil.which("gcc") or LANDLOCK < 1 or os.uname().machine not in fn.SYSCALLS:
        pytest.skip("needs gcc and Landlock")
    import tempfile
    d = pathlib.Path(tempfile.mkdtemp(prefix="pcdn-fn-probe-", dir="/tmp"))   # traversable by the worker uid
    os.chmod(d, 0o755)
    (d / "probe.c").write_text(PROBE_C)
    exe = d / "probe"
    subprocess.run(["gcc", "-O0", "-o", str(exe), str(d / "probe.c")], check=True, capture_output=True)
    os.chmod(exe, 0o755)
    secret = d / "other-site-secret.js"
    secret.write_text("var key = 'site-8-secret';")
    os.chmod(secret, 0o644)
    yield str(exe), str(secret)
    shutil.rmtree(d, ignore_errors=True)


def test_sandbox_blocks_escapes_at_syscall_level(probe):
    """The OS sandbox is the boundary: verified with native code, not JS."""
    exe, secret = probe
    sb = fn.Sandbox(exe)
    p = sb.spawn([exe, secret], cpu_ms=2000, memory_mb=16)
    out, _ = p.communicate(timeout=20)
    res = {}
    for line in out.decode().splitlines():
        k, _, v = line.partition("=")
        ret, _, err = v.partition(":")
        res[k] = (int(ret), int(err))
    assert res.get("done") == (0, 0), out
    for k in ("socket_inet", "socket_inet6", "socket_unix", "socket_netlink", "socketpair", "fork", "clone",
              "kill_init", "kill_parent", "ptrace", "stat_passwd", "ioctl", "sigaction", "unshare", "chdir",
              "fcntl_setown", "fcntl_setsig", "open_opath"):
        assert res[k] == (-1, 1), (k, res[k])                    # EPERM from the seccomp allow-list
    for k in ("open_passwd", "open_secret", "open_proc", "open_write_tmp", "execve_true"):
        assert res[k] == (-1, 13), (k, res[k])                   # EACCES from Landlock
    assert res["mkdir"][0] == -1 and res["raise_rlimit"][0] == -1 and res["fcntl_getfl"] == (0, 0)
    if tuple(int(x) for x in os.uname().release.split(".")[:2]) >= (6, 3):
        assert res["mmap_wx"] == (-1, 13)                        # PR_SET_MDWE: no W+X memory
    assert not os.path.exists("/tmp/pcdn-fn-probe") and not os.path.exists("/tmp/pcdn-fn-probe-dir")


def test_sandbox_kills_cpu_hog_and_foreign_arch(probe):
    exe, _ = probe
    # a native busy loop (python -c is not allowed: only the probe binary may execute)
    d = pathlib.Path(exe).parent
    (d / "spin.c").write_text("int main(){volatile unsigned long i=0; for(;;) i++;}")
    spin = d / "spin"
    subprocess.run(["gcc", "-o", str(spin), str(d / "spin.c")], check=True, capture_output=True)
    os.chmod(spin, 0o755)
    sb = fn.Sandbox(str(spin))
    t0 = time.monotonic()
    p = sb.spawn([str(spin)], cpu_ms=50, memory_mb=16)
    _, status, ru = os.wait4(p.pid, 0)
    p.returncode = 0
    assert os.WIFSIGNALED(status) and os.WTERMSIG(status) == 27          # SIGPROF
    assert time.monotonic() - t0 < 2 and (ru.ru_utime + ru.ru_stime) < 0.5


# ---------------------------------------------------------------- QuickJS workers

@pytest.fixture(scope="module")
def svc(tmp_path_factory):
    if not QJS or LANDLOCK < 1 or os.uname().machine not in fn.SYSCALLS:
        pytest.skip("needs qjs (package quickjs) and Landlock")
    d = tmp_path_factory.mktemp("fnsvc")
    os.chmod(d, 0o755)
    (d / "code").mkdir()
    secret_code = "var API_KEY = 'site-8-secret-key';"
    sha = __import__("hashlib").sha256(secret_code.encode()).hexdigest()
    (d / "code" / f"{sha}.js").write_text(secret_code)
    os.chmod(d / "code" / f"{sha}.js", 0o644)
    (d / "manifest.json").write_text(json.dumps({"v": 1, "sites": {"8": {"functions": {"a": {"sha256": sha}}}}}))
    os.chmod(d / "manifest.json", 0o644)
    cfg = fn.load_config(None)
    cfg.update(FN_DIR=str(d), FN_RUNTIME=RUNTIME, FN_QJS=QJS, FN_WALL_MS="1500", FN_STATUS=str(d / "status.json"),
               FN_USAGE_LOG=str(d / "usage.log"), FN_MAX_FETCHES="2")
    s = fn.Service(cfg)
    assert s.sandbox is not None, s.sandbox_error
    s.secret_path = str(d / "code" / f"{sha}.js")
    return s


REQ = {"method": "POST", "url": "https://ex.test/api/x?q=1", "headers": [["X-Test", "1"], ["Cookie", "s=1"]],
       "client": {"ip": "203.0.113.9", "country": "DE"}}


def run(svc, code, body=b"", timeout_ms=50, memory_mb=32, ctx=None):
    async def go():
        return await svc.run(code, REQ, body, timeout_ms, memory_mb, ctx)
    return asyncio.run(go())


@needs_sandbox
def test_worker_request_response_roundtrip(svc):
    r = run(svc, """
      async function handleRequest(req) {
        const u = new URL(req.url);
        const b = await req.text();
        return Response.json({m: req.method, p: u.pathname, q: u.searchParams.get('q'), h: req.headers.get('x-test'),
                              b, ip: req.client.ip, cc: req.client.country, enc: new TextEncoder().encode('é').length},
                             {status: 202, headers: {'X-Fn': 'yes'}});
      }""", body="سلام".encode())
    assert r.kind == "resp" and r.status == 202, r.message
    assert ["X-Fn", "yes"] in r.headers
    assert json.loads(r.body) == {"m": "POST", "p": "/api/x", "q": "1", "h": "1", "b": "سلام", "ip": "203.0.113.9",
                                  "cc": "DE", "enc": 2}
    assert 0 < r.cpu_ms < 200
    r = run(svc, "addEventListener('fetch', e => e.respondWith(new Response(new Uint8Array([0,1,255]))))")
    assert r.kind == "resp" and r.body == b"\x00\x01\xff"
    assert run(svc, "function handleRequest(){return null}").kind == "pass"
    assert run(svc, "addEventListener('fetch', e => {})").kind == "pass"
    assert run(svc, "addEventListener('fetch', e => {e.passThroughOnException(); throw 1})").kind == "pass"
    r = run(svc, "function handleRequest(){throw new Error('boom')}")
    assert r.kind == "error" and "boom" in r.message
    assert run(svc, "this is not js").kind == "error"
    assert run(svc, "var x = 1").kind == "error"                                  # no handler
    assert run(svc, "function handleRequest(){return 'str'}").kind == "error"     # not a Response


@needs_sandbox
def test_worker_cannot_read_files(svc):
    paths = ["/etc/passwd", "/etc/hostname", svc.secret_path, svc.cfg["FN_DIR"] + "/manifest.json",
             "/proc/self/environ", "/proc/1/cmdline", "/root/.bashrc", "/dev/zero"]
    r = run(svc, """
      async function handleRequest() {
        const std = await import('std'); const os = await import('os');
        const opened = %s.filter(p => std.open(p, 'r') !== null);
        const fd = os.open('%s', os.O_RDONLY);
        const ls = os.readdir('/etc');
        const w = std.open('/tmp/pcdn-fn-js-write', 'w');
        const ld = std.loadFile('/etc/passwd');
        return Response.json({opened, fd, ls: ls[1], w: w !== null, ld});
      }""" % (json.dumps(paths), svc.secret_path))
    assert r.kind == "resp", r.message
    d = json.loads(r.body)
    assert d["opened"] == [] and d["fd"] < 0 and d["ls"] != 0 and d["w"] is False and d["ld"] is None
    assert not os.path.exists("/tmp/pcdn-fn-js-write")


@needs_sandbox
def test_worker_cannot_spawn_signal_or_use_network(svc):
    r = run(svc, """
      async function handleRequest() {
        const std = await import('std'); const os = await import('os');
        let ex; try { ex = os.exec(['/bin/sh', '-c', 'echo pwned > /tmp/pcdn-fn-pwned'], {block: true}); }
                catch (e) { ex = 'denied'; }
        let url; try { url = std.urlGet('http://127.0.0.1:1/'); } catch (e) { url = 'denied'; }
        let pop; try { pop = std.popen('id', 'r'); } catch (e) { pop = 'denied'; }
        const k1 = os.kill(1, 0), k2 = os.kill(2, 0);
        let sig; try { os.signal(os.SIGPROF, () => {}); sig = 'set'; } catch (e) { sig = 'denied'; }
        let w; try { w = new os.Worker('x.js'); } catch (e) { w = 'denied'; }
        return Response.json({ex: String(ex), url: String(url), pop: String(pop), k1, k2, sig, w: String(w)});
      }""")
    assert r.kind == "resp", r.message
    d = json.loads(r.body)
    assert d["ex"] == "denied" and d["url"] in ("denied", "null") and d["pop"] in ("denied", "null")
    assert d["k1"] < 0 and d["k2"] < 0 and d["w"] == "denied"
    assert not os.path.exists("/tmp/pcdn-fn-pwned")
    # even if os.signal "succeeds" in the engine, the handler is never installed: the CPU timer still kills
    t0 = time.monotonic()
    r = run(svc, "async function handleRequest(){const os=await import('os');"
                 "try{os.signal(os.SIGPROF,()=>{})}catch(e){} for(;;){}}", timeout_ms=20)
    assert r.kind == "timeout" and time.monotonic() - t0 < 1.5


@needs_sandbox
def test_worker_cpu_limit(svc):
    for code in ("function handleRequest(){for(;;){}}",
                 "async function handleRequest(){await null; for(;;){}}",
                 "function handleRequest(){let s=0; for(let i=0;i<1e9;i++) s+=i; return new Response(String(s))}"):
        t0 = time.monotonic()
        r = run(svc, code, timeout_ms=10)
        took = time.monotonic() - t0
        assert r.kind == "timeout", (code, r.kind, r.message)
        assert took < 1.0 and r.cpu_ms < 10 + svc.startup_ms + 40, (took, r.cpu_ms)


@needs_sandbox
def test_worker_wall_clock_limit(svc):
    t0 = time.monotonic()
    r = run(svc, "async function handleRequest(){const os=await import('os'); os.sleep(60000)}")
    assert r.kind == "timeout" and 1.4 < time.monotonic() - t0 < 3
    r = run(svc, "function handleRequest(){return new Promise(res => setTimeout(() => res(new Response('t')), 10))}")
    assert r.kind == "resp" and r.body == b"t"
    r = run(svc, "function handleRequest(){return new Promise(() => setTimeout(() => {}, 60000))}")
    assert r.kind == "timeout"
    # a worker that answered but keeps a timer pending is still a success (killed after its answer)
    r = run(svc, "function handleRequest(){setTimeout(()=>{}, 60000); return new Response('ok')}")
    assert r.kind == "resp" and r.body == b"ok"


@needs_sandbox
def test_worker_memory_limit(svc):
    for code in ("function handleRequest(){let a=[]; for(;;) a.push(new Array(1e5).fill(1.5))}",
                 "function handleRequest(){const b=new ArrayBuffer(200*1024*1024); return new Response(String(b.byteLength))}",
                 "function handleRequest(){let s='x'; for(;;) s+=s; }"):
        r = run(svc, code, memory_mb=16, timeout_ms=200)
        assert r.kind in ("error", "timeout") and r.kind != "resp", (code, r.kind)
    r = run(svc, "function handleRequest(){const b=new ArrayBuffer(8*1024*1024); return new Response(String(b.byteLength))}",
            memory_mb=16)
    assert r.kind == "resp" and r.body == str(8 * 1024 * 1024).encode()


@needs_sandbox
def test_worker_output_caps(svc):
    r = run(svc, "function handleRequest(){return new Response('x'.repeat(5*1024*1024 + 1))}", timeout_ms=200,
            memory_mb=64)
    assert r.kind == "error" and "5 MB" in r.message
    r = run(svc, "function handleRequest(){return new Response('x'.repeat(5*1024*1024))}", timeout_ms=200, memory_mb=64)
    assert r.kind == "resp" and len(r.body) == 5 * 1024 * 1024
    r = run(svc, "function handleRequest(){return new Response('x', {status: 101})}")
    assert r.kind == "error"
    # a function writing its own garbage frames only breaks itself
    r = run(svc, "async function handleRequest(){const std=await import('std'); std.out.puts('junk\\n'); "
                 "return new Response('x')}")
    assert r.kind == "error"


@needs_sandbox
def test_no_state_shared_between_invocations_or_sites(svc):
    """One fresh process per invocation: globals, the heap and the module state never survive."""
    code = """
      var counter = (globalThis.counter || 0) + 1; globalThis.counter = counter;
      function handleRequest(req) {
        const seen = typeof SECRET === 'undefined' ? null : SECRET;
        globalThis.SECRET = 'site-' + req.headers.get('x-site');
        return Response.json({counter, seen});
      }"""
    async def both():
        req7 = dict(REQ, headers=[["x-site", "7"]])
        req8 = dict(REQ, headers=[["x-site", "8"]])
        return await asyncio.gather(*[svc.run(code, rq, b"", 50, 16) for rq in (req7, req8, req7, req8)])
    for r in asyncio.run(both()):
        assert r.kind == "resp" and json.loads(r.body) == {"counter": 1, "seen": None}
    # nothing from another site's code file is reachable, even with its exact path
    r = run(svc, "async function handleRequest(){const std=await import('std');"
                 "return new Response(String(std.loadFile(%s)))}" % json.dumps(svc.secret_path))
    assert r.kind == "resp" and r.body == b"null"


@needs_sandbox
def test_worker_runs_unprivileged_and_seccomp_is_active(svc):
    state = {}

    def hook(fr, proc):
        with open(f"/proc/{proc.pid}/status") as f:
            st = dict(ln.split(":", 1) for ln in f.read().splitlines() if ":" in ln)
        state.update({k: st[k].split() for k in ("Uid", "Gid", "Groups", "Seccomp", "NoNewPrivs", "CapEff")
                      if k in st})
        return {"status": 204, "headers": []}
    r = run(svc, "async function handleRequest(){await fetch('/x'); return new Response('ok')}",
            ctx={"selftest_hook": hook})
    assert r.kind == "resp"
    assert state["Seccomp"] == ["2"] and state["NoNewPrivs"] == ["1"]
    assert state["CapEff"] == ["0000000000000000"]
    if os.geteuid() == 0:
        assert state["Uid"][0] == "65534" and state["Gid"][0] == "65534" and state.get("Groups", []) == []


@needs_sandbox
def test_fetch_policy(svc):
    ctx = {"host": "ex.test", "hosts": ["ex.test", "*.ex.test"], "ip": "203.0.113.9", "sid": "7"}
    code = """
      async function handleRequest() {
        const out = [];
        for (const u of %s) { try { await fetch(u); out.push('sent'); } catch (e) { out.push(String(e.message)); } }
        return Response.json(out);
      }"""
    urls = ["https://evil.test/", "http://127.0.0.1/", "http://ex.test.evil.test/", "file:///etc/passwd",
            "http://[::1]/", "ftp://ex.test/"]
    svc.max_fetches = 10
    try:
        r = run(svc, code % json.dumps(urls), ctx=ctx)
    finally:
        svc.max_fetches = 2
    out = json.loads(r.body)
    assert all("restricted" in x or "invalid url" in x for x in out), out
    # own hosts are allowed through to the (absent) fetch socket; the 3rd call exceeds FN_MAX_FETCHES=2
    r = run(svc, code % json.dumps(["/a", "https://www.ex.test/b", "/c"]), ctx=ctx)
    out = json.loads(r.body)
    assert out[0].startswith("fetch failed") and out[1].startswith("fetch failed") and "too many" in out[2]


@needs_sandbox
def test_selftest_passes(svc):
    res = asyncio.run(svc.selftest())
    assert res["ok"] is True, res
    assert set(res["checks"]) == {"engine", "fs_denied", "exec_denied", "signal_denied", "cpu_limit", "memory_limit",
                                  "seccomp_active"}


def test_selftest_fails_closed_without_sandbox(tmp_path):
    cfg = fn.load_config(None)
    cfg.update(FN_QJS=str(tmp_path / "missing-qjs"), FN_RUNTIME=RUNTIME, FN_DIR=str(tmp_path))
    s = fn.Service(cfg)
    assert s.sandbox is None and s.ready is False
    res = asyncio.run(s.selftest())
    assert res["ok"] is False
    r = asyncio.run(s.run("function handleRequest(){return new Response('x')}", REQ, b"", 50, 16))
    assert r.kind == "error" and "sandbox unavailable" in r.message


def test_usage_writer_rotates(tmp_path):
    u = fn.Usage(str(tmp_path / "usage.log"))
    u.add("ex.test", 12.4, "ok")
    u.add("ex.test", 3.0, "error")
    u.add("ex.test", 50.2, "timeout")
    u.add("www.ex.test", 1.0, "ok")
    u.flush()
    lines = [json.loads(x) for x in (tmp_path / "usage.log").read_text().splitlines()]
    assert [(x["h"], x["n"], x["c"], x["e"], x["o"]) for x in lines] == [("ex.test", 3, 66, 1, 1),
                                                                        ("www.ex.test", 1, 1, 0, 0)]
    u.flush()   # nothing new: nothing written
    assert len((tmp_path / "usage.log").read_text().splitlines()) == 2


# ================================================================== install.sh / systemd unit

def _block(start, end):
    install = (EDGE / "install.sh").read_text()
    return start + install.split(start, 1)[1].split(end, 1)[0]


def test_install_functions_flag_roundtrip(tmp_path):
    conf = tmp_path / "agent.conf"
    upgrade = _block('if [ "$UPGRADE" = yes ]; then', 'HTTP3="${HTTP3:-no}"') + 'HTTP3="${HTTP3:-no}"\n'
    defaults = 'HARDEN_NET="${HARDEN_NET:-no}"\nAVIF="${AVIF:-yes}"\nFUNCTIONS="${FUNCTIONS:-no}"\n'
    write = _block("cat > /etc/pcdn/agent.conf <<EOF", "\nEOF") + "\nEOF\n"
    keep = _block("# >>> pcdn keep logship", "# <<< pcdn keep logship")
    w8 = _block("# >>> pcdn wave8 conf", "# <<< pcdn wave8 conf")
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "CONTROLLER": "https://c", "TOKEN": "t", "REGION": "",
           "ROLE": "", "TCP_CC": "", "HTTP3": "", "KEEP_CONF": "", "NGINX_USER": "www-data", "IPV6": "yes",
           "CACHE_SIZE": "10g", "HTTP_PORT": "80", "HTTPS_PORT": "443", "UPGRADE": "no", "FUNCTIONS": ""}

    def run(script, **over):
        script = script.replace("/etc/pcdn/agent.conf", str(conf))
        p = subprocess.run(["bash", "-euc", script + '\necho "F=$FUNCTIONS"'], env=dict(env, **over),
                           capture_output=True, text=True, check=True)
        return p.stdout.strip().splitlines()[-1]
    assert run(defaults + write + keep + w8) == "F=no"                        # opt-in: off by default
    assert agent.load_config(str(conf))["FUNCTIONS"] == "no"
    assert run(defaults + write + keep + w8, FUNCTIONS="yes") == "F=yes"
    conf.write_text(conf.read_text() + "FN_WALL_MS=3000\nFN_SITE_WORKERS=2\n")
    assert run(upgrade + defaults + write + keep + w8, UPGRADE="yes") == "F=yes"   # kept on --upgrade
    cfg = agent.load_config(str(conf))
    assert cfg["FUNCTIONS"] == "yes" and cfg["FN_WALL_MS"] == "3000" and cfg["FN_SITE_WORKERS"] == "2"
    assert run(upgrade + defaults + write + keep + w8, UPGRADE="yes", FUNCTIONS="no") == "F=no"   # flag wins
    conf.write_text("CONTROLLER_URL=https://c\nEDGE_TOKEN=t\nFUNCTIONS=maybe\n")
    assert run(upgrade + defaults + write + keep + w8, UPGRADE="yes") == "F=no"


def test_install_functions_block_and_unit():
    install = (EDGE / "install.sh").read_text()
    block = _block("# >>> pcdn functions", "# <<< pcdn functions")
    for s in ("apt-get install -y -q quickjs", "/usr/share/pcdn/fn/runtime.js", "/usr/local/bin/pcdn-fn",
              "SupplementaryGroups=\\nSupplementaryGroups=%s", "d /run/pcdn-fnfetch 0750 root %s -",
              "install -d -m 750 -o root -g \"$NGINX_GROUP\" /var/lib/pcdn-fn", "systemctl disable --now pcdn-fn",
              "FUNCTIONS=no", "/run/pcdn-fn/status.json"):
        assert s in block, s
    assert "--functions) FUNCTIONS=yes" in install and "--no-functions) FUNCTIONS=no" in install
    assert install.index("# >>> pcdn functions") < install.index('echo "==> services"')   # before nginx -t
    boot = (EDGE / "bootstrap.sh").read_text()
    assert "    --functions|--no-functions)" in boot
    assert subprocess.run(["bash", "-n", str(EDGE / "install.sh")]).returncode == 0
    unit = (EDGE / "systemd" / "pcdn-fn.service").read_text()
    for d in ("DynamicUser=yes", "NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes",
              "PrivateDevices=yes", "PrivateNetwork=yes", "RestrictAddressFamilies=AF_UNIX\n", "IPAddressDeny=any",
              "MemoryDenyWriteExecute=yes", "LockPersonality=yes", "CapabilityBoundingSet=\n", "MemoryMax=",
              "TasksMax=", "SystemCallFilter=@system-service @sandbox", "SystemCallArchitectures=native",
              "RestrictNamespaces=yes", "ProtectProc=invisible", "RuntimeDirectory=pcdn-fn", "LogsDirectory=pcdn-fn"):
        assert d in unit, d
    assert "IPAddressAllow" not in unit and "AF_INET" not in unit
    deny = [ln for ln in unit.splitlines() if ln.startswith("SystemCallFilter=~")][0]
    for g in ("@privileged", "@mount", "@debug", "@module", "@raw-io", "@reboot", "@swap", "@obsolete", "@setuid"):
        assert g in deny
    if shutil.which("systemd-analyze"):
        p = subprocess.run(["systemd-analyze", "verify", str(EDGE / "systemd" / "pcdn-fn.service")],
                           capture_output=True, text=True)
        assert p.returncode == 0 and "pcdn-fn.service" not in p.stderr, p.stderr


@needs_sandbox
def test_many_invocations_no_hang_no_fd_leak(svc):
    """Regression: pipe fds are reused by later workers; a stale event-loop registration once left a
    finished worker's output unread until the wall-clock limit."""
    codes = [("function handleRequest(){return null}", "pass"),
             ("function handleRequest(){return new Response('y'.repeat(70000))}", "resp"),
             ("function handleRequest(){throw 1}", "error"),
             ("async function handleRequest(){const std=await import('std'); std.exit(0)}", "error")]

    async def go():
        fds = len(os.listdir("/proc/self/fd"))
        t0 = time.monotonic()
        for i in range(160):
            code, want = codes[i % len(codes)]
            r = await svc.run(code, REQ, b"", 50, 16)
            assert r.kind == want, (i, r.kind, r.message)
        await asyncio.sleep(0.05)
        return time.monotonic() - t0, fds, len(os.listdir("/proc/self/fd"))
    took, before, after = asyncio.run(go())
    assert took < 30 and after <= before, (took, before, after)


# ================================================================== older kernels / diagnostics (CI)

ABIS = [a for a in range(1, 7) if a <= LANDLOCK]


@pytest.mark.parametrize("abi", ABIS or [1])
def test_sandbox_per_landlock_abi(probe, abi):
    """Every Landlock ABI path (1: base fs, 2: +refer, 3: +truncate, 4: +TCP — Ubuntu 24.04 / 6.8,
    5: +ioctl_dev, 6: +signal/abstract-unix scoping) keeps the documented guarantees."""
    if abi > LANDLOCK:
        pytest.skip("kernel ABI lower")
    exe, secret = probe
    sb = fn.Sandbox(exe, abi_max=abi)
    assert sb.abi == abi
    p = sb.spawn([exe, secret], cpu_ms=2000, memory_mb=16)
    out, err = p.communicate(timeout=20)
    res = {ln.split("=")[0]: tuple(int(x) for x in ln.split("=")[1].split(":")) for ln in out.decode().splitlines()}
    assert res.get("done") == (0, 0), (out, err)
    for k in ("open_passwd", "open_secret", "open_proc", "open_write_tmp", "execve_true"):
        assert res[k] == (-1, 13), (abi, k, res[k])
    for k in ("socket_inet", "socket_unix", "fork", "kill_parent", "ptrace", "fcntl_setown", "open_opath"):
        assert res[k] == (-1, 1), (abi, k, res[k])


@needs_sandbox
@pytest.mark.parametrize("abi", ABIS or [1])
def test_selftest_per_landlock_abi(svc, abi):
    cfg = dict(svc.cfg, FN_LANDLOCK_ABI_MAX=str(abi))
    s = fn.Service(cfg)
    assert s.sandbox is not None and s.sandbox.abi == abi, s.sandbox_error
    res = asyncio.run(s.selftest())
    assert res["ok"] is True, res


@needs_sandbox
def test_no_landlock_fails_closed(svc):
    s = fn.Service(dict(svc.cfg, FN_LANDLOCK_ABI_MAX="0"))
    assert s.sandbox is None and "Landlock" in s.sandbox_error and not s.ready
    res = asyncio.run(s.selftest())
    assert res["ok"] is False and "Landlock" in res["error"]
    r = asyncio.run(s.run("function handleRequest(){return new Response('x')}", REQ, b"", 50, 16))
    assert r.kind == "error" and "sandbox unavailable" in r.message


@needs_sandbox
@pytest.mark.parametrize("stage", ["no_new_privs", "landlock_restrict_self", "seccomp", f"setrlimit({__import__('resource').RLIMIT_AS})"])
def test_setup_failure_is_diagnosed(svc, stage):
    svc.sandbox.fail_at = stage
    try:
        r = run(svc, "function handleRequest(){return new Response('x')}")
        st = asyncio.run(svc.selftest())
    finally:
        svc.sandbox.fail_at = None
    assert r.kind == "error"
    assert f"sandbox setup failed at {stage}: errno 22" in r.message and "exit status 126" in r.message, r.message
    assert st["ok"] is False and f"failed at {stage}" in st["details"]["engine"]


@needs_sandbox
def test_engine_start_errors_are_surfaced(svc):
    r = run(svc, "function handleRequest(){ return new Response('x') }; std.exit(0)")   # std is not a global
    assert r.kind == "error"
    r = run(svc, "async function handleRequest(){const std=await import('std'); std.err.puts('boom\\n'); std.exit(5)}")
    assert r.kind == "error" and "exit status 5" in r.message and "boom" in r.message


@needs_sandbox
def test_runtime_behind_untraversable_directory(tmp_path):
    """The CI failure: a checkout under a 0750 home. As root, workers run as nobody, so the runtime is
    staged into a private world-readable copy; a worker uid that cannot read it is reported precisely."""
    if os.geteuid() != 0:
        pytest.skip("needs root")
    import tempfile
    d = pathlib.Path(tempfile.mkdtemp(prefix="pcdn-fn-ci-", dir="/tmp"))
    try:
        (d / "work").mkdir()
        shutil.copy(RUNTIME, d / "work" / "runtime.js")
        os.chmod(d, 0o750)
        assert not fn.dac_readable(str(d / "work" / "runtime.js"), 65534, 65534)
        assert fn.dac_readable(str(d / "work" / "runtime.js"), 0, 0)
        cfg = fn.load_config(None)
        cfg.update(FN_DIR=str(tmp_path), FN_RUNTIME=str(d / "work" / "runtime.js"), FN_QJS=QJS)
        s = fn.Service(cfg)
        assert s.sandbox is not None and s.runtime != cfg["FN_RUNTIME"] and fn.dac_readable(s.runtime, 65534, 65534)
        r = asyncio.run(s.run("function handleRequest(){return null}", REQ, b"", 50, 16))
        assert r.kind == "pass", r.message
        # without staging the preflight names the problem instead of a silent engine failure
        with pytest.raises(fn.SandboxError, match="not readable by the worker uid 65534"):
            fn.Sandbox(QJS, read_files=[cfg["FN_RUNTIME"]])
    finally:
        os.chmod(d, 0o755)
        shutil.rmtree(d, ignore_errors=True)


def test_dac_readable():
    assert fn.dac_readable("/etc/passwd", 65534, 65534)
    assert not fn.dac_readable("/etc/shadow", 65534, 65534)
    assert not fn.dac_readable("/nonexistent/x", 65534, 65534)
