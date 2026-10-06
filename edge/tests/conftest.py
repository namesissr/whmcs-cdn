"""Shared helpers for the edge tests: a minimal nginx.conf around the agent's real http.conf."""

import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

MODULES_DIR = "/usr/lib/nginx/modules"
MODULES = ["ngx_http_js_module.so", "ngx_http_geoip2_module.so", "ngx_http_image_filter_module.so",
           "ngx_http_brotli_filter_module.so"]


# The test origins listen on loopback (and some fixtures use documentation / private addresses):
# operators allow such origins with ORIGIN_PRIVATE_ALLOW, the tests do the same
TEST_ORIGIN_ALLOW = ("127.0.0.0/8 ::1/128 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 192.0.2.0/24 198.51.100.0/24 "
                     "203.0.113.0/24 2001:db8::/32 fc00::/7")


def modules_available() -> bool:
    return all(os.path.exists(os.path.join(MODULES_DIR, m)) for m in MODULES)


def nginx_conf(tmp_path, cfg, workers=2, modules=None) -> pathlib.Path:
    """Stand-alone nginx.conf (own pid/logs/temp dirs) that includes NGINX_DIR/http.conf the
    same way /etc/nginx/conf.d/00-pcdn.conf does in production. `user root` because
    pytest temp dirs are not traversable by unprivileged workers. `modules`: the .so files to
    load (default: all four), e.g. only njs + image_filter to mimic the nginx.org build."""
    tmp = pathlib.Path(tmp_path)
    user = "user root;\n" if os.geteuid() == 0 else ""
    text = (user
            + "".join(f"load_module {MODULES_DIR}/{m};\n" for m in (MODULES if modules is None else modules))
            + f"worker_processes {workers};\npid {tmp}/nginx.pid;\nerror_log {tmp}/error.log info;\n"
            + "events { worker_connections 1024; }\n"
            + "http {\n include /etc/nginx/mime.types;\n default_type application/octet-stream;\n access_log off;\n"
            + "".join(f" {d}_temp_path {tmp}/{d};\n" for d in ("client_body", "proxy", "fastcgi", "uwsgi", "scgi"))
            + f" include {cfg['NGINX_DIR']}/http.conf;\n}}\n")
    path = tmp / "nginx.conf"
    path.write_text(text)
    return path


_PICKED_PORTS: set[int] = set()


def pick_port(host: str = "127.0.0.1") -> int:
    """A free TCP+UDP port for a test listener, chosen from 10000-19999: below the kernel's ephemeral
    range (outgoing connections never take it between our check and nginx's bind) and below the
    default L4 app range, and never handed out twice in one test run."""
    import random
    import socket

    for _ in range(500):
        port = random.randint(10000, 19999)
        if port in _PICKED_PORTS:
            continue
        try:
            for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
                for addr in ("0.0.0.0", host):
                    with socket.socket(socket.AF_INET, kind) as s:
                        s.bind((addr, port))
        except OSError:
            continue
        _PICKED_PORTS.add(port)
        return port
    raise RuntimeError("no free test port in 10000-19999")
