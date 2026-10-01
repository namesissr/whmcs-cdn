"""Shared helpers for the edge tests: a minimal nginx.conf around the agent's real http.conf."""

import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

MODULES_DIR = "/usr/lib/nginx/modules"
MODULES = ["ngx_http_js_module.so", "ngx_http_geoip2_module.so", "ngx_http_image_filter_module.so",
           "ngx_http_brotli_filter_module.so"]


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
