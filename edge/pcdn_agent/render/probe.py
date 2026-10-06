"""The synthetic tunnel probe servers of http.conf (SPEC §22.3) and their files outside the rendered
tree: a self-signed certificate for probe.pcdn.invalid and the gRPC download body.

The probe tests the node's OWN health only (its public listener, TLS, workers and tunnel proxy path)
against a loopback echo origin (or an operator-run one); it never measures reachability from user
networks. Public clients get 403 and nothing is logged."""

import os
import shutil
import subprocess

from ..capabilities import nginx_capabilities
from ..common import _int, _v6
from ..settings import log
from ..validation.origin import internal_src
from .site import tunnel_pass_lines

PROBE_HOST = "probe.pcdn.invalid"
PROBE_WS_PATH = "/__pcdn_probe/ws"
PROBE_GRPC_PATH = "/__pcdn_probe/grpc"
PROBE_IDLE = 60          # s; read/send timeouts of the probe locations
PROBE_BYTES_MIN, PROBE_BYTES_MAX = 16384, 4194304


def probe_enabled(cfg: dict) -> bool:
    return str(cfg.get("PROBE_ENABLED") or "yes").lower() in ("1", "yes", "true", "on")


def probe_bytes(cfg: dict) -> int:
    return _int(cfg.get("PROBE_BYTES"), 262144, PROBE_BYTES_MIN, PROBE_BYTES_MAX)


def probe_dir(cfg: dict) -> str:
    """PROBE_DIR (install.sh: /etc/pcdn/probe), default "probe" next to the state file."""
    return cfg.get("PROBE_DIR") or os.path.join(os.path.dirname(cfg.get("STATE_FILE") or "/var/lib/pcdn/x"), "probe")


def probe_files(cfg: dict) -> dict:
    d = probe_dir(cfg)
    return {"crt": os.path.join(d, "probe.crt"), "key": os.path.join(d, "probe.key"), "body": os.path.join(d, "body.bin")}


def probe_ready(cfg: dict) -> bool:
    """The probe server can be rendered: probe on, certificate + key present, body of PROBE_BYTES."""
    if not probe_enabled(cfg):
        return False
    f = probe_files(cfg)
    try:
        return (os.path.isfile(f["crt"]) and os.path.isfile(f["key"])
                and os.path.getsize(f["body"]) == probe_bytes(cfg))
    except OSError:
        return False


def ensure_probe_files(cfg: dict, run=subprocess.run) -> bool:
    """Create the probe certificate (openssl, EC P-256, 10 years, 0600 key) and the gRPC body
    (PROBE_BYTES random bytes, 0644) once, outside the swapped tree. Without openssl the probe is
    disabled (reported unsupported). Fail-soft; True when the probe server can be rendered."""
    if not probe_enabled(cfg):
        return False
    f = probe_files(cfg)
    try:
        os.makedirs(os.path.dirname(f["crt"]), mode=0o755, exist_ok=True)
        if not (os.path.isfile(f["crt"]) and os.path.isfile(f["key"])):
            if not shutil.which("openssl"):
                log.warning("tunnel probe: openssl not found; the probe is unsupported on this node")
                return False
            tmpk, tmpc = f["key"] + ".tmp", f["crt"] + ".tmp"
            p = run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                     "-days", "3650", "-subj", f"/CN={PROBE_HOST}", "-keyout", tmpk, "-out", tmpc],
                    capture_output=True, text=True, timeout=30)
            if p.returncode != 0 or not os.path.isfile(tmpk):
                log.warning("tunnel probe: certificate not created: %s", (p.stderr or "").strip()[-200:])
                return False
            os.chmod(tmpk, 0o600)
            os.chmod(tmpc, 0o644)
            os.replace(tmpk, f["key"])
            os.replace(tmpc, f["crt"])
        n = probe_bytes(cfg)
        if not (os.path.isfile(f["body"]) and os.path.getsize(f["body"]) == n):
            tmp = f["body"] + ".tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
            with os.fdopen(fd, "wb") as fh:
                fh.write(os.urandom(n))
            os.chmod(tmp, 0o644)
            os.replace(tmp, f["body"])
    except (OSError, subprocess.SubprocessError) as e:
        log.warning("tunnel probe: files not written: %s", e)
        return False
    return probe_ready(cfg)


def render_probe(cfg: dict) -> str:
    """The probe server on the public HTTPS listener(s) (loopback clients only, no access log) and
    the loopback h2c body server; "" when the probe is off or its files are missing. The WS / gRPC
    locations are built by the same tunnel_pass_lines as a customer ws / grpc path. The WS location
    always proxies to the agent's local echo port: a controller-provided echo origin (node.probe) is
    reached through that port's relay, so node.probe never changes the rendered tree (SPEC §22.2)."""
    if not probe_ready(cfg):
        return ""
    caps = nginx_capabilities(cfg)
    f = probe_files(cfg)
    sport = _int(cfg.get("HTTPS_PORT"), 443, 1, 65535)
    echo = _int(cfg.get("PROBE_ECHO_PORT"), 8092, 1, 65535)
    h2c = _int(cfg.get("PROBE_H2C_PORT"), 8093, 1, 65535)
    src = internal_src(cfg)
    brotli_ok = "brotli" in caps["modules"]
    h2d = caps["http2_directive"]

    def hdrs(directive, conn=()):
        return [f"{directive} Host $host;"] + [f"{directive} {n} {v};" for n, v in conn]

    out = ["server {"]
    for addr in ([str(sport)] + ([f"[::]:{sport}"] if _v6(cfg) else [])):
        out.append(f"    listen {addr} ssl;" if h2d else f"    listen {addr} ssl http2;")
    if h2d:
        out.append("    http2 on;")
    out += [f"    server_name {PROBE_HOST};", f"    ssl_certificate {f['crt']};", f"    ssl_certificate_key {f['key']};",
            "    access_log off;", "    allow 127.0.0.0/8;", "    allow ::1;", "    deny all;"]
    for path, kind, dest, bind in ((PROBE_WS_PATH, "ws", f"127.0.0.1:{echo}", "proxy_bind"),
                                   (PROBE_GRPC_PATH, "grpc", f"127.0.0.1:{h2c}", "grpc_bind")):
        L = tunnel_pass_lines(kind, dest, False, "$host", False, PROBE_IDLE, hdrs, cfg, brotli_ok)
        L.insert(-1, f"{bind} {src};")   # the origin guard admits loopback services only from INTERNAL_SRC
        out += [f"    location ^~ {path} {{"] + ["        " + x for x in L] + ["    }"]
    out += ["    location / { return 404; }", "}"]
    # h2c (prior knowledge) body server: any method -> 200 application/grpc, PROBE_BYTES bytes, grpc-status 0
    out += ["server {", f"    listen 127.0.0.1:{h2c}{'' if h2d else ' http2'};"] + (["    http2 on;"] if h2d else []) + [
        "    server_name _;", "    access_log off;",
        "    location / { error_page 405 =200 /__pcdn_probe_body; return 405; }",
        "    location = /__pcdn_probe_body { internal; types { } default_type application/grpc; "
        f"add_trailer grpc-status 0 always; alias {f['body']}; }}",
        "}"]
    return "\n".join(out)
