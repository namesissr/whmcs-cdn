"""`pcdn-agent imaged` (SPEC §16.6): the loopback image transformer service (AVIF/WebP, resize,
smart crop) behind the nginx image resizer."""

import os
import re
import shutil
import signal
import subprocess
import urllib.error
import urllib.request

from .capabilities import image_capabilities
from .common import _int
from .settings import log


# ----------------------------------------------------------------- image transformer (SPEC §16.6)
#
# `pcdn-agent imaged`: a loopback-only HTTP server (IMAGE_PORT) run as its own sandboxed systemd
# service (pcdn-imaged, DynamicUser, no network beyond localhost). The resizer server of http.conf
# proxies v2 requests here with the spec from pcdn.js; the original is fetched back through that
# resizer (/__pcdn_rz/src/, which talks to the origin) and transformed with Pillow; AVIF is encoded
# by Pillow when it has the plugin, else by avifenc (libavif-bin). Every failure answers 415 / 413 /
# 502 / 503 and nginx falls back to image_filter / the original, so the transformer can never take
# images down. Bounds: originals <= IMAGE_MAX_SOURCE_MB and <= IMAGE_MAX_PIXELS, output <= 4096 px a
# side (pcdn.js already caps w/h at min(4096, max_width)), never enlarged, IMAGE_WORKERS at a time.

IMAGE_MAX_DIM = 4096
IMAGE_MAX_PIXELS = 50_000_000
IMAGE_FMTS = ("keep", "webp", "avif", "jpeg")
_SPEC_RE = re.compile(r"^(\d{1,5}|-):(contain|cover):(keep|webp|avif|jpeg):(\d{1,3}):([01])$")


def parse_image_spec(w: str, h: str, q: str) -> dict | None:
    """X-Pcdn-W / -H / -Q -> {w, h, fit, fmt, q, smart} (w/h None = free). Legacy ("N"/"-" in H) is a
    contain resize in the source format with the site quality. None = not a valid spec."""
    w, h, q = str(w or "").strip(), str(h or "").strip(), str(q or "").strip()
    if not re.match(r"^(\d{1,5}|-)$", w):
        return None
    m = _SPEC_RE.match(h)
    if m:
        hh, fit, fmt, qq, smart = m.groups()
    elif re.match(r"^(\d{1,5}|-)$", h):
        hh, fit, fmt, qq, smart = h, "contain", "keep", (q if re.match(r"^\d{1,3}$", q) else "85"), "0"
    else:
        return None

    def dim(v):
        return None if v == "-" else max(1, min(IMAGE_MAX_DIM, int(v)))
    return {"w": dim(w), "h": dim(hh), "fit": fit, "fmt": fmt, "q": max(1, min(100, int(qq))), "smart": smart == "1"}


def _smart_offset(img, cw: int, ch: int) -> tuple[int, int]:
    """Top-left corner of a cw x ch window inside img (already scaled to cover it) that maximises
    image entropy, weighted toward the centre (SPEC §16.6 smart_crop). Scored on a small grayscale
    copy at 17 positions along the free axis: deterministic and cheap."""
    W, H = img.size
    free_x, free_y = W - cw, H - ch
    if free_x <= 0 and free_y <= 0:
        return 0, 0
    small = img.convert("L")
    scale = min(1.0, 256.0 / max(W, H))
    if scale < 1.0:
        small = small.resize((max(1, int(W * scale)), max(1, int(H * scale))))
    sw, sh = max(1, int(cw * scale)), max(1, int(ch * scale))
    best, best_score, steps = 0.0, -1.0, 16
    for i in range(steps + 1):
        t = i / steps
        if free_x > 0:
            x0 = int(round(t * (small.size[0] - sw)))
            box = (x0, 0, x0 + sw, min(small.size[1], sh))
        else:
            y0 = int(round(t * (small.size[1] - sh)))
            box = (0, y0, min(small.size[0], sw), y0 + sh)
        ent = small.crop(box).entropy()
        score = ent * (1.0 - 0.35 * abs(t - 0.5) * 2)   # centre-weighted
        if score > best_score + 1e-9:
            best, best_score = t, score
    return int(round(best * free_x)) if free_x > 0 else 0, int(round(best * free_y)) if free_y > 0 else 0


def _avifenc(img, q: int, timeout: float = 30.0) -> bytes:
    """AVIF through the avifenc CLI (libavif-bin): PNG in, AVIF out, in a private temp dir."""
    import tempfile   # noqa: PLC0415
    exe = shutil.which("avifenc")
    if not exe:
        raise RuntimeError("no avifenc")
    with tempfile.TemporaryDirectory(prefix="pcdn-img-") as d:
        src, dst = os.path.join(d, "in.png"), os.path.join(d, "out.avif")
        img.save(src, "PNG", compress_level=1)
        p = subprocess.run([exe, "-q", str(q), "-s", "8", "-j", "1", src, dst], capture_output=True, timeout=timeout)
        if p.returncode != 0 or not os.path.isfile(dst):
            raise RuntimeError("avifenc failed: " + p.stderr.decode("utf-8", "replace")[-300:])
        with open(dst, "rb") as f:
            return f.read()


def transform_image(data: bytes, spec: dict, avif_mode: str = "auto") -> tuple[bytes, str]:
    """Apply a parsed spec to an original image -> (bytes, content type). Raises ValueError for input
    that cannot be transformed (not an image, animated, too many pixels): the caller answers 415.
    avif_mode: auto (Pillow plugin, else avifenc), pillow, avifenc, none (AVIF not possible: the source
    format is kept)."""
    from PIL import Image, ImageOps   # noqa: PLC0415 - optional dependency (python3-pil)
    import io   # noqa: PLC0415
    Image.MAX_IMAGE_PIXELS = IMAGE_MAX_PIXELS
    try:
        img = Image.open(io.BytesIO(data))
        src_fmt = (img.format or "").upper()
        if src_fmt not in ("JPEG", "PNG", "WEBP", "GIF"):
            raise ValueError(f"unsupported source format {src_fmt or '?'}")
        if getattr(img, "is_animated", False) and getattr(img, "n_frames", 1) > 1:
            raise ValueError("animated image")
        if img.size[0] * img.size[1] > IMAGE_MAX_PIXELS:
            raise ValueError("too many pixels")
        img.load()
    except (OSError, Image.DecompressionBombError) as e:
        raise ValueError(str(e)) from e
    img = ImageOps.exif_transpose(img)
    W, H = img.size
    tw, th = spec["w"], spec["h"]
    if tw or th:
        if spec["fit"] == "cover" and tw and th:
            tw, th = min(tw, W), min(th, H)            # never enlarged
            scale = max(tw / W, th / H)
            sw, sh = max(tw, int(round(W * scale))), max(th, int(round(H * scale)))
            if (sw, sh) != (W, H):
                img = img.resize((sw, sh), Image.LANCZOS)
            if spec["smart"]:
                x0, y0 = _smart_offset(img, tw, th)
            else:
                x0, y0 = (img.size[0] - tw) // 2, (img.size[1] - th) // 2
            img = img.crop((x0, y0, x0 + tw, y0 + th))
        else:   # contain (or cover with one free side): proportional, inside the box
            scale = min((tw or W) / W, (th or H) / H, 1.0)
            if scale < 1.0:
                img = img.resize((max(1, int(round(W * scale))), max(1, int(round(H * scale)))), Image.LANCZOS)
    fmt = spec["fmt"]
    if fmt == "avif" and avif_mode == "none":
        fmt = "keep"
    if fmt == "keep":
        fmt = {"JPEG": "jpeg", "PNG": "png", "WEBP": "webp", "GIF": "png"}[src_fmt]
    q = spec["q"]
    out = io.BytesIO()
    alpha = img.mode in ("RGBA", "LA") or (img.mode == "P" and "transparency" in img.info)
    if fmt == "jpeg":
        if alpha:
            bg = Image.new("RGB", img.size, (255, 255, 255))
            bg.paste(img.convert("RGBA"), mask=img.convert("RGBA").split()[-1])
            img = bg
        elif img.mode != "RGB":
            img = img.convert("RGB")
        img.save(out, "JPEG", quality=q, optimize=True, progressive=True)
        return out.getvalue(), "image/jpeg"
    if fmt == "png":
        img.save(out, "PNG", optimize=True)
        return out.getvalue(), "image/png"
    img = img.convert("RGBA" if alpha else "RGB")
    if fmt == "webp":
        img.save(out, "WEBP", quality=q, method=4)
        return out.getvalue(), "image/webp"
    # avif
    if avif_mode in ("auto", "pillow"):
        try:
            img.save(out, "AVIF", quality=q, speed=8)
            return out.getvalue(), "image/avif"
        except (KeyError, OSError, ValueError):
            if avif_mode == "pillow":
                raise
    return _avifenc(img, q), "image/avif"


def imaged_server(cfg: dict):
    """The transformer's ThreadingHTTPServer on 127.0.0.1:IMAGE_PORT (not started)."""
    import http.server   # noqa: PLC0415
    import threading     # noqa: PLC0415
    port = _int(cfg.get("IMAGE_PORT"), 8090, 1, 65535)
    rz_port = _int(cfg.get("RESIZE_PORT"), 8089, 1, 65535)
    max_src = _int(cfg.get("IMAGE_MAX_SOURCE_MB"), 20, 1, 200) * 1024 * 1024
    slots = threading.BoundedSemaphore(_int(cfg.get("IMAGE_WORKERS"), 2, 1, 64))
    icaps = image_capabilities(dict(cfg, IMAGED="auto"))
    avif_mode = "auto" if icaps["avif"] else "none"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "pcdn-imaged"

        def log_message(self, *a):   # nginx logs the request; keep the journal quiet
            pass

        def _reply(self, code: int, body: bytes = b"", ctype: str = "text/plain"):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def do_GET(self):
            spec = parse_image_spec(self.headers.get("X-Pcdn-W"), self.headers.get("X-Pcdn-H"),
                                    self.headers.get("X-Pcdn-Q"))
            path = self.path.split("?", 1)[0]
            if spec is None or not path.startswith("/") or not self.headers.get("X-Pcdn-Origin"):
                return self._reply(400)
            if not slots.acquire(timeout=5):
                return self._reply(503)
            try:
                req = urllib.request.Request(f"http://127.0.0.1:{rz_port}/__pcdn_rz/src{path}")
                for h in ("Host", "X-Pcdn-Origin", "X-Pcdn-Mtls"):
                    if self.headers.get(h):
                        req.add_header(h, self.headers[h])
                try:
                    with opener.open(req, timeout=30) as r:
                        data = r.read(max_src + 1)
                except urllib.error.HTTPError as e:
                    return self._reply(e.code if 400 <= e.code < 500 else 502)
                except (OSError, ValueError):
                    return self._reply(502)
                if len(data) > max_src:
                    return self._reply(413)
                try:
                    body, ctype = transform_image(data, spec, avif_mode)
                except ValueError:
                    return self._reply(415)
                except Exception as e:  # noqa: BLE001 - encoder trouble: nginx falls back
                    log.warning("image transform failed for %s: %s", path[:200], e)
                    return self._reply(500)
                self._reply(200, body, ctype)
            finally:
                slots.release()

        do_HEAD = do_GET

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    srv.daemon_threads = True
    log.info("image transformer on 127.0.0.1:%d (avif: %s)", port, avif_mode)
    return srv


def run_imaged(cfg: dict):
    """The `pcdn-agent imaged` service loop (see above). Binds 127.0.0.1 only."""
    import threading     # noqa: PLC0415
    srv = imaged_server(cfg)

    def stop(*_):
        threading.Thread(target=srv.shutdown, daemon=True).start()
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        srv.serve_forever()
    finally:
        srv.server_close()
