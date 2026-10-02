"""nginx capabilities (SPEC §14.1): `nginx -V` parsing, the optional dynamic modules, L4 / image
transformer readiness, the `# @if module` template blocks and the GeoIP gate."""

import os
import re
import shutil
import subprocess
import warnings

from .common import SAFE_FSPATH


def geoip_present(cfg: dict) -> bool:
    """True when the GeoIP country database is installed AND the geoip2 module is available (F9,
    SPEC §14.1): tunnel allowed_countries only enforces when it is, and fails open (allow) when
    either is missing (e.g. an nginx.org build without geoip2)."""
    geo = cfg.get("GEOIP_DB") or ""
    return bool(SAFE_FSPATH.match(geo) and os.path.isfile(geo)) and has_module(cfg, "geoip2")


# ----------------------------------------------------------------- nginx capabilities (SPEC §14.1)

# optional dynamic modules the rendered config can use -> their .so file in the modules directory
MODULE_FILES = {"njs": "ngx_http_js_module.so", "geoip2": "ngx_http_geoip2_module.so",
                "image_filter": "ngx_http_image_filter_module.so", "brotli": "ngx_http_brotli_filter_module.so"}
# statically compiled variants, recognised in `nginx -V` configure arguments
_STATIC_MODULE = {"njs": re.compile(r"--add-module=\S*njs"), "geoip2": re.compile(r"--add-module=\S*geoip2"),
                  "brotli": re.compile(r"--add-module=\S*brotli"),
                  "image_filter": re.compile(r"--with-http_image_filter_module(?!=dynamic)(?:\s|$)")}
# WebP for image.auto_webp: ngx_http_image_filter_module always writes the INPUT format (JPEG in ->
# JPEG out, PNG in -> PNG out; WebP is only produced from WebP input), so no stock nginx can convert
# JPEG/PNG to WebP and webp_convert is always False. The edge therefore uses the "accept_key" mode:
# the cache key carries the client's WebP capability for JPEG/PNG URIs, Accept is passed through to
# origins that negotiate formats, and those responses get "Vary: Accept" (see pcdn-base.conf).
WEBP_MODE = "accept_key"
# what an undetectable nginx is assumed to be: today's distro build (Ubuntu 1.24 + all modules)
LEGACY_CAPS = {"nginx": None, "http3": False, "early_hints": False, "http2_directive": False,
               "webp_convert": False, "webp_mode": WEBP_MODE, "modules": sorted(MODULE_FILES), "flv": True,
               # SPEC §16.4 / §16.5: ngx_stream_module (libnginx-mod-stream was not installed before
               # wave 8, so an undetectable nginx is assumed without it) and the slice module
               "stream": False, "slice": True}
_CAPS_CACHE: dict = {}


def _version(text: str) -> tuple:
    m = re.search(r"nginx version: [^/\s]*/(\d+)\.(\d+)\.(\d+)", text or "")
    return tuple(int(x) for x in m.groups()) if m else ()


def parse_nginx_v(text: str, modules_dir: str | None = None, exists=os.path.isfile) -> dict:
    """Capabilities from `nginx -V` output (stderr). http3 needs --with-http_v3_module and nginx
    >= 1.25.1 (`listen ... quic` 1.25.0, `http3` directive 1.25.1); early_hints needs >= 1.29.0
    (`early_hints` directive, ngx_http_core_module). modules: optional modules compiled in or whose
    .so is present in the modules directory (install.sh writes a load_module line for each)."""
    ver = _version(text)
    if not ver:
        return dict(LEGACY_CAPS, modules=list(LEGACY_CAPS["modules"]))
    args = ""
    for line in text.splitlines():
        if line.startswith("configure arguments:"):
            args = line.split(":", 1)[1]
    mdir = modules_dir
    if not mdir:
        m = re.search(r"--modules-path=(\S+)", args)
        if m:
            mdir = m.group(1).strip("'\"")
        else:
            m = re.search(r"--prefix=(\S+)", args)
            mdir = os.path.join(m.group(1).strip("'\"") if m else "/usr/local/nginx", "modules")
    mods = sorted(name for name, so in MODULE_FILES.items()
                  if _STATIC_MODULE[name].search(args) or exists(os.path.join(mdir, so)))
    v3 = bool(re.search(r"(?:^|\s)--with-http_v3_module(?:\s|$)", args))
    return {"nginx": ".".join(str(x) for x in ver), "http3": v3 and ver >= (1, 25, 1),
            "early_hints": ver >= (1, 29, 0), "http2_directive": ver >= (1, 25, 1),
            "webp_convert": False, "webp_mode": WEBP_MODE, "modules": mods,
            # SPEC §15.6: the speed-test download is served through the (static) flv module
            "flv": bool(re.search(r"(?:^|\s)--with-http_flv_module(?:\s|$)", args)),
            # SPEC §16.4: stream compiled in (nginx.org) or the dynamic module file (libnginx-mod-stream)
            "stream": bool(re.search(r"(?:^|\s)--with-stream(?:\s|$)", args)) or exists(os.path.join(mdir, STREAM_SO)),
            # SPEC §16.5: byte-range slicing of large mp4 files (static module only)
            "slice": bool(re.search(r"(?:^|\s)--with-http_slice_module(?:\s|$)", args))}


def nginx_capabilities(cfg: dict) -> dict:
    """Probe `nginx -V` once per agent start (cached per binary/modules dir). A test or an operator
    tool may pass a ready dict as cfg["NGINX_CAPS"]. When nginx cannot be probed, the legacy distro
    build is assumed so rendering stays exactly as before."""
    caps = cfg.get("NGINX_CAPS")
    if isinstance(caps, dict):
        return dict(LEGACY_CAPS, **caps)
    binary = cfg.get("NGINX_BIN") or "nginx"
    key = (binary, cfg.get("NGINX_MODULES_DIR") or "")
    if key not in _CAPS_CACHE:
        try:
            p = subprocess.run([binary, "-V"], capture_output=True, text=True, timeout=15)
            text = (p.stdout or "") + (p.stderr or "")
        except (OSError, subprocess.SubprocessError, ValueError):
            text = ""
        _CAPS_CACHE[key] = parse_nginx_v(text, cfg.get("NGINX_MODULES_DIR") or None)
    return dict(_CAPS_CACHE[key])


def has_module(cfg: dict, name: str) -> bool:
    return name in nginx_capabilities(cfg)["modules"]


STREAM_SO = "ngx_stream_module.so"


def l4_ready(cfg: dict) -> bool:
    """SPEC §16.4: stream {} is rendered only when nginx has the stream module AND the main nginx.conf
    includes NGINX_DIR/l4/*.conf at the main context (install.sh adds it). Otherwise the node reports
    `l4: false` and renders no L4 app (a stream block nginx cannot load would fail every apply)."""
    caps = nginx_capabilities(cfg)
    if "l4" in caps:   # tests / operator tools may pin it
        return bool(caps["l4"])
    if not caps.get("stream"):
        return False
    want = cfg["NGINX_DIR"].rstrip("/") + "/l4/*.conf"
    try:
        with open(cfg.get("NGINX_CONF") or "/etc/nginx/nginx.conf") as f:
            text = f.read()
    except OSError:
        return False
    return any(re.match(r"^\s*include\s+" + re.escape(want) + r"\s*;", line) for line in text.splitlines())


_IMAGE_CAPS: dict = {}


def image_capabilities(cfg: dict) -> dict:
    """SPEC §16.6: what the loopback image transformer (pcdn-agent imaged) can do on this node, probed
    once per agent start: transform = python3-pil importable (and IMAGED != no); webp = Pillow WebP;
    avif = transform and (Pillow AVIF plugin or the avifenc binary of libavif-bin). Tests / tools may
    pass a ready dict as cfg["IMAGE_CAPS"]."""
    caps = cfg.get("IMAGE_CAPS")
    if isinstance(caps, dict):
        return {"transform": bool(caps.get("transform")), "webp": bool(caps.get("webp")),
                "avif": bool(caps.get("transform") and caps.get("avif")),
                "pillow_avif": bool(caps.get("pillow_avif"))}
    if str(cfg.get("IMAGED") or "auto").lower() in ("no", "off", "0", "false"):
        return {"transform": False, "webp": False, "avif": False, "pillow_avif": False}
    if "v" not in _IMAGE_CAPS:
        out = {"transform": False, "webp": False, "avif": False, "pillow_avif": False}
        try:
            from PIL import features  # noqa: PLC0415 - optional dependency (python3-pil)
            out["transform"] = True
            out["webp"] = bool(features.check("webp"))
            try:
                with warnings.catch_warnings():   # Pillow < 11.2 warns "Unknown feature 'avif'"
                    warnings.simplefilter("ignore")
                    out["pillow_avif"] = bool(features.check("avif"))
            except (ValueError, KeyError):   # Pillow < 11.2 has no "avif" feature name
                out["pillow_avif"] = False
        except Exception:  # noqa: BLE001 - ImportError or a broken install: no transformer
            pass
        out["avif"] = bool(out["transform"] and (out["pillow_avif"] or shutil.which("avifenc")))
        _IMAGE_CAPS["v"] = out
    return dict(_IMAGE_CAPS["v"])


def guard_installed(cfg: dict) -> bool:
    """SPEC §16.3: install.sh --harden-net installed the nftables guard (GUARD=yes + its rule file)."""
    return str(cfg.get("GUARD") or "").lower() == "yes" and os.path.isfile(cfg.get("GUARD_FILE") or "/etc/pcdn/guard.nft")


_GUARD = re.compile(r"^# @if (\w+)\n(.*?)(?:^# @else \1\n(.*?))?^# @endif \1\n", re.S | re.M)


def module_blocks(text: str, modules) -> str:
    """Resolve the template's "# @if <module>" / "# @else" / "# @endif" blocks (SPEC §14.1)."""
    def sub(m):
        return m.group(2) if m.group(1) in modules else (m.group(3) or "")
    prev = None
    while prev != text:   # nested guards resolve from the inside out
        prev, text = text, _GUARD.sub(sub, text)
    return text
