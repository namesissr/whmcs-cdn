"""Synthetic tunnel probe (SPEC §22.3): the WS echo origin (`pcdn-agent echo-origin`, and a daemon
thread of the agent on 127.0.0.1:PROBE_ECHO_PORT), the WS / gRPC probe clients that go through this
node's own nginx (127.0.0.1:HTTPS_PORT, SNI probe.pcdn.invalid) and the background runner that feeds
the heartbeat's `tunnel_probe`.

Only the node's OWN health is tested (public listener, TLS, workers, tunnel proxy path) against a
loopback / operator-run echo origin. Nothing here measures reachability from user networks, ISPs or
countries, and no address ever appears in a reported error.

Echo protocol (RFC 6455 frames over an HTTP/1.1 upgrade on any path):
  binary message            -> echoed back byte-identically
  text "down:<n>"           -> n bytes (binary frames of <= 64 KiB), then text "end"
  text "up:<n>" + n bytes   -> the binary data following it (any number of messages) is consumed; when
                               n bytes have arrived the origin answers text "up:<n>"
  ping -> pong, close -> close. n <= 4 MiB per command, 16 concurrent connections, idle 30 s."""

import base64
import hashlib
import os
import re
import select
import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time

from .common import SAFE_ORIGIN, _int
from .render.probe import PROBE_GRPC_PATH, PROBE_HOST, PROBE_WS_PATH, probe_bytes, probe_enabled, probe_ready
from .settings import log

WS_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
ECHO_MAX_CMD = 4 * 1024 * 1024
ECHO_MAX_CONNS = 16
ECHO_IDLE = 30
ECHO_CHUNK = 65536
PROBE_BUDGET = 10.0      # s for one round (ws + grpc), never more
PROBE_SETUP_FAIL_MS = 3000
PROBE_ERR_MAX = 120
_ADDR = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b|\[?(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\]?(?::\d+)?")


class WSError(Exception):
    pass


def _recv_exact(sock, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(min(n - len(buf), 1 << 20))
        if not chunk:
            raise WSError("connection closed")
        buf += chunk
    return bytes(buf)


def ws_frame(opcode: int, payload: bytes, mask: bool) -> bytes:
    head = bytearray([0x80 | opcode])
    n = len(payload)
    mbit = 0x80 if mask else 0
    if n < 126:
        head.append(mbit | n)
    elif n < 65536:
        head += bytes([mbit | 126]) + struct.pack("!H", n)
    else:
        head += bytes([mbit | 127]) + struct.pack("!Q", n)
    if mask:
        key = os.urandom(4)
        head += key
        payload = _mask(payload, key)
    return bytes(head) + payload


def _mask(data: bytes, key: bytes) -> bytes:
    if not data:
        return data
    k = (key * (len(data) // 4 + 1))[:len(data)]
    return (int.from_bytes(data, "big") ^ int.from_bytes(k, "big")).to_bytes(len(data), "big")


def ws_read_frame(sock, max_len: int = ECHO_MAX_CMD + 1024) -> tuple[bool, int, bytes]:
    """-> (fin, opcode, payload) of one frame (unmasked)."""
    b1, b2 = _recv_exact(sock, 2)
    fin, opcode, masked, n = bool(b1 & 0x80), b1 & 0x0F, bool(b2 & 0x80), b2 & 0x7F
    if n == 126:
        n = struct.unpack("!H", _recv_exact(sock, 2))[0]
    elif n == 127:
        n = struct.unpack("!Q", _recv_exact(sock, 8))[0]
    if n > max_len:
        raise WSError("frame too large")
    key = _recv_exact(sock, 4) if masked else b""
    data = _recv_exact(sock, n) if n else b""
    return fin, opcode, (_mask(data, key) if masked else data)


def ws_read_message(sock, sender_mask: bool) -> tuple[int, bytes]:
    """One complete message (continuation frames joined); answers pings in between."""
    op, parts = None, []
    while True:
        fin, opcode, data = ws_read_frame(sock)
        if opcode == 0x9:   # ping
            sock.sendall(ws_frame(0xA, data, sender_mask))
            continue
        if opcode == 0xA:   # pong
            continue
        if opcode == 0x8:
            return 0x8, data
        if opcode != 0x0:
            op = opcode
        parts.append(data)
        if sum(len(p) for p in parts) > ECHO_MAX_CMD + 1024:
            raise WSError("message too large")
        if fin:
            return (op or 0x2), b"".join(parts)


# ----------------------------------------------------------------- echo origin

def _read_http_head(sock, limit: int = 16384) -> bytes:
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise WSError("closed before the request head")
        buf += chunk
        if len(buf) > limit:
            raise WSError("request head too large")
    return buf


def _echo_session(conn):
    head = _read_http_head(conn).decode("latin-1")
    key = None
    for line in head.split("\r\n")[1:]:
        k, _, v = line.partition(":")
        if k.strip().lower() == "sec-websocket-key":
            key = v.strip()
    if not key or "upgrade" not in head.lower():
        conn.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        return
    accept = base64.b64encode(hashlib.sha1(key.encode() + WS_GUID).digest()).decode()
    conn.sendall(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                  f"Sec-WebSocket-Accept: {accept}\r\n\r\n").encode())
    up_left = up_total = None
    while True:
        op, data = ws_read_message(conn, False)
        if op == 0x8:
            conn.sendall(ws_frame(0x8, data[:2], False))
            return
        if op == 0x1:
            cmd = data.decode("utf-8", "replace")
            m = re.match(r"^(down|up):(\d{1,8})$", cmd)
            if not m or int(m.group(2)) > ECHO_MAX_CMD:
                conn.sendall(ws_frame(0x1, b"error", False))
                continue
            n = int(m.group(2))
            if m.group(1) == "down":
                left = n
                while left > 0:
                    k = min(left, ECHO_CHUNK)
                    conn.sendall(ws_frame(0x2, os.urandom(k), False))
                    left -= k
                conn.sendall(ws_frame(0x1, b"end", False))
            else:
                up_left = up_total = n
                if up_left == 0:
                    conn.sendall(ws_frame(0x1, b"up:0", False))
                    up_left = None
            continue
        if up_left is not None:   # upload data: consumed, answered once complete
            up_left -= len(data)
            if up_left <= 0:
                conn.sendall(ws_frame(0x1, f"up:{up_total}".encode(), False))
                up_left = None
            continue
        conn.sendall(ws_frame(0x2, data, False))   # echo


def _relay(conn, target: tuple):
    """Pipe a connection to the controller-provided echo origin (node.probe.origin): host, port, tls."""
    host, port, use_tls = target
    up = socket.create_connection((host, port), timeout=5)
    try:
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE   # the operator's own echo origin; the probe tests the node
            up = ctx.wrap_socket(up, server_hostname=host if not re.match(r"^[0-9.:\[\]]+$", host) else None)
        up.settimeout(ECHO_IDLE)
        conn.settimeout(ECHO_IDLE)
        socks = [conn, up]
        while True:
            r, _, _ = select.select(socks, [], [], ECHO_IDLE)
            if not r:
                return
            for s in r:
                data = s.recv(65536)
                if not data:
                    return
                while s is up and use_tls and up.pending():   # bytes already decrypted by the TLS layer
                    data += up.recv(up.pending())
                (up if s is conn else conn).sendall(data)
    finally:
        try:
            up.close()
        except OSError:
            pass


class EchoServer:
    """The WS echo origin: a threaded TCP server (<= ECHO_MAX_CONNS connections, idle ECHO_IDLE s).
    relay = (host, port, tls) forwards every connection to that echo origin instead (node.probe)."""

    def __init__(self, host: str = "127.0.0.1", port: int = 8092, relay: tuple | None = None):
        self.host, self.port, self.relay = host, port, relay
        self.sem = threading.BoundedSemaphore(ECHO_MAX_CONNS)
        self.sock = None
        self.running = False

    def start(self) -> "EchoServer":
        fam = socket.AF_INET6 if ":" in self.host else socket.AF_INET
        s = socket.socket(fam, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.host.strip("[]"), self.port))
        s.listen(64)
        self.port = s.getsockname()[1]
        self.sock, self.running = s, True
        threading.Thread(target=self._accept, name="pcdn-echo", daemon=True).start()
        return self

    def stop(self):
        self.running = False
        for op in ("shutdown", "close"):   # shutdown wakes the thread blocked in accept()
            try:
                getattr(self.sock, op)(*((socket.SHUT_RDWR,) if op == "shutdown" else ()))
            except (OSError, AttributeError):
                pass

    def _accept(self):
        while self.running:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                if not self.running:
                    return
                time.sleep(0.2)
                continue
            if not self.sem.acquire(blocking=False):
                conn.close()
                continue
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        try:
            conn.settimeout(ECHO_IDLE)
            if self.relay:
                _relay(conn, self.relay)
            else:
                _echo_session(conn)
        except (OSError, WSError, ValueError):
            pass
        finally:
            self.sem.release()
            try:
                conn.close()
            except OSError:
                pass


def norm_probe_node(config: dict) -> dict:
    """node.probe = {"origin": {"host", "port", "tls"} | null, "interval": 30..600} (agent-side only:
    never rendered). -> {"origin": (host, port, tls) | None, "interval": int | None}."""
    n = config.get("node") if isinstance(config.get("node"), dict) else {}
    p = n.get("probe") if isinstance(n.get("probe"), dict) else {}
    o = p.get("origin") if isinstance(p.get("origin"), dict) else None
    origin = None
    if o:
        host = str(o.get("host") or "").lower()
        port = o.get("port")
        if (SAFE_ORIGIN.match(host) and not isinstance(port, bool) and isinstance(port, int) and 1 <= port <= 65535):
            origin = (host.strip("[]"), port, o.get("tls") is True)
    iv = p.get("interval")
    return {"origin": origin, "interval": _int(iv, 60, 30, 600) if isinstance(iv, int) and not isinstance(iv, bool)
            else None}


# ----------------------------------------------------------------- probe clients

def _clean_err(e) -> str:
    """A short error text without addresses (SPEC §22.3)."""
    msg = e if isinstance(e, str) else (type(e).__name__ + (": " + str(e) if str(e) else ""))
    return _ADDR.sub("[addr]", msg)[:PROBE_ERR_MAX]


def ws_probe(port: int, nbytes: int, timeout: float, host: str = "127.0.0.1") -> dict:
    """WS probe through this node's nginx: TLS (SNI probe.pcdn.invalid, verification skipped), upgrade
    on PROBE_WS_PATH, 3 x 1 KiB echoes, a download and an upload of nbytes."""
    res = {"ok": False, "setup_ms": None, "echo_ok": False, "down_kbps": None, "up_kbps": None, "error": None}
    deadline = time.monotonic() + timeout
    sock = None
    try:
        t0 = time.monotonic()
        raw = socket.create_connection((host, port), timeout=max(0.5, deadline - time.monotonic()))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["http/1.1"])
        sock = ctx.wrap_socket(raw, server_hostname=PROBE_HOST)
        sock.settimeout(max(0.5, deadline - time.monotonic()))
        key = base64.b64encode(os.urandom(16)).decode()
        sock.sendall((f"GET {PROBE_WS_PATH} HTTP/1.1\r\nHost: {PROBE_HOST}\r\nUpgrade: websocket\r\n"
                      f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
                      "User-Agent: pcdn-probe/1\r\n\r\n").encode())
        head = _read_http_head(sock)
        status = head.split(b"\r\n", 1)[0]
        if b" 101 " not in status + b" ":
            raise WSError("no upgrade: " + status.decode("latin-1", "replace")[:40])
        res["setup_ms"] = int((time.monotonic() - t0) * 1000)
        ok = True
        for _ in range(3):
            msg = os.urandom(1024)
            sock.sendall(ws_frame(0x2, msg, True))
            op, data = ws_read_message(sock, True)
            ok = ok and op == 0x2 and data == msg
        res["echo_ok"] = ok
        t1, got = time.monotonic(), 0
        sock.sendall(ws_frame(0x1, f"down:{nbytes}".encode(), True))
        while True:
            op, data = ws_read_message(sock, True)
            if op == 0x1 and data == b"end":
                break
            if op != 0x2:
                raise WSError("unexpected frame during download")
            got += len(data)
        dt = max(time.monotonic() - t1, 1e-6)
        if got != nbytes:
            raise WSError(f"download size {got} != {nbytes}")
        res["down_kbps"] = int(got * 8 / dt / 1000)
        t2 = time.monotonic()
        sock.sendall(ws_frame(0x1, f"up:{nbytes}".encode(), True))
        left = nbytes
        while left > 0:
            k = min(left, ECHO_CHUNK)
            sock.sendall(ws_frame(0x2, os.urandom(k), True))
            left -= k
        op, data = ws_read_message(sock, True)
        if op != 0x1 or data != f"up:{nbytes}".encode():
            raise WSError("upload not acknowledged")
        res["up_kbps"] = int(nbytes * 8 / max(time.monotonic() - t2, 1e-6) / 1000)
        try:
            sock.sendall(ws_frame(0x8, struct.pack("!H", 1000), True))
        except OSError:
            pass
    except (OSError, WSError, ValueError, ssl.SSLError) as e:
        res["error"] = _clean_err(e)
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    res["ok"] = bool(res["echo_ok"] and res["error"] is None and res["setup_ms"] is not None
                     and res["setup_ms"] <= PROBE_SETUP_FAIL_MS)
    return res


_CURL_H2: dict = {}


def curl_has_http2(run=subprocess.run) -> bool:
    """curl present and `curl -V` lists the HTTP2 feature (cached)."""
    if "v" not in _CURL_H2:
        ok = False
        if shutil.which("curl"):
            try:
                p = run(["curl", "-V"], capture_output=True, text=True, timeout=10)
                ok = bool(re.search(r"^Features:.*\bHTTP2\b", p.stdout or "", re.M))
            except (OSError, subprocess.SubprocessError):
                ok = False
        _CURL_H2["v"] = ok
    return _CURL_H2["v"]


def grpc_probe(port: int, nbytes: int, timeout: float, run=subprocess.run) -> dict:
    """gRPC probe: curl --http2 POST (application/grpc, one empty 5-byte frame) through this node's nginx
    to the loopback h2c body server; expects HTTP 200 and exactly nbytes."""
    if not curl_has_http2(run):
        return {"unsupported": True}
    res = {"ok": False, "setup_ms": None, "echo_ok": False, "down_kbps": None, "error": None}
    with tempfile.NamedTemporaryFile(prefix="pcdn-grpc-", delete=True) as f:
        f.write(b"\x00\x00\x00\x00\x00")
        f.flush()
        cmd = ["curl", "--http2", "-sk", "--resolve", f"{PROBE_HOST}:{port}:127.0.0.1", "-X", "POST",
               "-H", "content-type: application/grpc", "-H", "te: trailers", "--data-binary", f"@{f.name}",
               "-o", "/dev/null", "--max-time", str(max(1, int(timeout))), "-w",
               "%{http_code} %{size_download} %{time_starttransfer} %{time_total}",
               f"https://{PROBE_HOST}:{port}{PROBE_GRPC_PATH}"]
        try:
            p = run(cmd, capture_output=True, text=True, timeout=timeout + 2)
        except (OSError, subprocess.SubprocessError) as e:
            res["error"] = _clean_err(e)
            return res
    try:
        code, size, ttfb, total = (p.stdout or "").split()[:4]
        code, size, ttfb, total = int(code), int(size), float(ttfb), float(total)
    except ValueError:
        res["error"] = _clean_err(f"curl exit {p.returncode}")
        return res
    res["setup_ms"] = int(ttfb * 1000) if ttfb > 0 else None
    res["echo_ok"] = code == 200 and size == nbytes
    if size and total > ttfb:
        res["down_kbps"] = int(size * 8 / (total - ttfb) / 1000)
    if not res["echo_ok"]:
        res["error"] = _clean_err(f"http {code}, {size} bytes" + (f", curl exit {p.returncode}" if p.returncode else ""))
    res["ok"] = bool(res["echo_ok"] and res["setup_ms"] is not None and res["setup_ms"] <= PROBE_SETUP_FAIL_MS)
    return res


def _iso_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def run_probe(cfg: dict, ws_supported: bool, run=subprocess.run) -> dict | None:
    """One probe round within PROBE_BUDGET: the heartbeat object without consecutive_fail, or None when
    no probe is supported on this node."""
    port = _int(cfg.get("HTTPS_PORT"), 443, 1, 65535)
    n = probe_bytes(cfg)
    start = time.monotonic()
    ws = ws_probe(port, n, PROBE_BUDGET * 0.6) if ws_supported else {"unsupported": True}
    left = PROBE_BUDGET - (time.monotonic() - start)
    grpc = grpc_probe(port, n, max(1.0, left), run) if ws_supported else {"unsupported": True}
    supported = [x for x in (ws, grpc) if not x.get("unsupported")]
    if not supported:
        return None
    return {"at": _iso_now(), "ok": all(x["ok"] for x in supported), "ws": ws, "grpc": grpc}


class ProbeRunner:
    """Background thread: one probe round every PROBE_INTERVAL (or node.probe.interval) seconds, never
    blocking the main loop. `result` is the latest heartbeat object (None: no supported probe yet)."""

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.result: dict | None = None
        self.rounds = 0
        self.consecutive_fail = 0
        self.interval: int | None = None    # node.probe.interval (controller), None = PROBE_INTERVAL
        self.rendered = False               # the applied nginx tree has the probe server
        self.unsupported = not probe_enabled(cfg)
        self._stop = threading.Event()
        self._wake = threading.Event()
        self.thread = None

    def start(self):
        if self.thread is None and probe_enabled(self.cfg):
            self.thread = threading.Thread(target=self._loop, name="pcdn-probe", daemon=True)
            self.thread.start()

    def stop(self):
        self._stop.set()
        self._wake.set()

    def kick(self):
        self._wake.set()

    def first_passed_or_unsupported(self) -> bool:
        """SPEC §22.1 upgrade auto-undrain condition: the first probe after the restart passed, or the
        probe is unsupported on this node (off, no openssl, nothing renderable)."""
        if self.unsupported or not probe_enabled(self.cfg) or not probe_ready(self.cfg):
            return True
        if self.rounds == 0:
            return False
        return self.result is None or bool(self.result.get("ok"))

    def round(self, run=subprocess.run) -> dict | None:
        ws_ok = self.rendered and probe_ready(self.cfg)
        try:
            res = run_probe(self.cfg, ws_ok, run)
        except Exception as e:  # noqa: BLE001 - a probe never breaks the agent
            log.warning("tunnel probe failed to run: %s", _clean_err(e))
            res = None
        self.rounds += 1
        if res is None:
            self.result = None
            return None
        self.consecutive_fail = 0 if res["ok"] else self.consecutive_fail + 1
        res["consecutive_fail"] = self.consecutive_fail
        if not res["ok"] and self.consecutive_fail in (1, 3):
            log.warning("tunnel probe failed (%d in a row): ws %s, grpc %s", self.consecutive_fail,
                        res["ws"].get("error") or ("ok" if res["ws"].get("ok") else "-"),
                        res["grpc"].get("error") or ("ok" if res["grpc"].get("ok") else "-"))
        self.result = res
        return res

    def _loop(self):
        # first round soon after start (the upgrade auto-undrain waits for it), then every interval
        self._wake.wait(5)
        while not self._stop.is_set():
            self._wake.clear()
            if self.rendered:
                self.round()
            iv = self.interval or _int(self.cfg.get("PROBE_INTERVAL"), 60, 30, 600)
            self._wake.wait(iv if self.rounds else 5)


def echo_origin_main(argv: list) -> int:
    """`pcdn-agent echo-origin --listen HOST:PORT`: run the echo origin in the foreground (operators
    run it on a platform host as the TUNNEL_PROBE_ORIGIN of the controller)."""
    listen = "0.0.0.0:8092"
    if "--listen" in argv:
        i = argv.index("--listen")
        listen = argv[i + 1] if i + 1 < len(argv) else ""
    if "-h" in argv or "--help" in argv:
        print("usage: pcdn-agent echo-origin [--listen HOST:PORT]   (default 0.0.0.0:8092)")
        return 0
    m = re.match(r"^\[?([0-9A-Za-z.:-]+?)\]?:(\d{1,5})$", listen)
    if not m or not 1 <= int(m.group(2)) <= 65535:
        print("echo-origin: --listen must be HOST:PORT")
        return 2
    srv = EchoServer(m.group(1), int(m.group(2))).start()
    print(f"pcdn echo origin listening on {listen}")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        srv.stop()
    return 0
