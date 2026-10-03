"""Helpers for the staging end-to-end tests (docs/STAGING.md). Python stdlib + pytest (+ boto3 for the
optional storage test). Every address comes from the environment, with defaults matching
deploy/staging/compose.yml, so the suite runs inside the runner container (staging.sh test) or from a
Linux host that can route to the staging bridge network:

    STAGING_CONTROLLER_URL / CONTROLLER_URL   http://controller:8000 (from the host: http://11.200.0.10:8000)
    STAGING_ADMIN_API_KEY / ADMIN_API_KEY     staging-admin-key
    STAGING_EDGES        edge-1=11.200.0.21,edge-2=11.200.0.22
    STAGING_DNS          11.200.0.53          (PowerDNS, port 53)
    STAGING_ORIGIN_IP    11.200.0.80
    STAGING_TIMEOUT      default wait for an eventually-consistent step, seconds (90)
"""

import base64
import http.client
import json
import os
import shutil
import socket
import struct
import subprocess
import time
import urllib.error
import urllib.request
import uuid

import pytest


def _env(*names, default=""):
    for n in names:
        v = os.environ.get(n)
        if v:
            return v
    return default


CONTROLLER = _env("STAGING_CONTROLLER_URL", "CONTROLLER_URL", default="http://controller:8000").rstrip("/")
ADMIN_KEY = _env("STAGING_ADMIN_API_KEY", "ADMIN_API_KEY", default="staging-admin-key")
EDGES = dict(x.strip().split("=", 1) for x in
             _env("STAGING_EDGES", default="edge-1=11.200.0.21,edge-2=11.200.0.22").split(",") if x.strip())
DNS = _env("STAGING_DNS", default="11.200.0.53")
ORIGIN_IP = _env("STAGING_ORIGIN_IP", default="11.200.0.80")
TIMEOUT = float(_env("STAGING_TIMEOUT", default="90"))
RUN_ID = _env("STAGING_RUN_ID", default=uuid.uuid4().hex[:6])
KEEP = _env("STAGING_KEEP", default="0") == "1"


# ------------------------------------------------------------------ waiting

def wait_until(fn, desc: str, timeout: float | None = None, interval: float = 1.0):
    """Call fn() until it returns a truthy value (returned); exceptions count as "not yet"."""
    end = time.monotonic() + (timeout or TIMEOUT)
    last = None
    while True:
        try:
            v = fn()
            if v:
                return v
            last = v
        except Exception as e:  # noqa: BLE001 - reported on timeout
            last = f"{type(e).__name__}: {e}"
        if time.monotonic() > end:
            raise AssertionError(f"timed out after {timeout or TIMEOUT:.0f}s waiting for {desc}; last: {last!r}")
        time.sleep(interval)


# ------------------------------------------------------------------ controller admin API

class ApiError(Exception):
    def __init__(self, status, body):
        super().__init__(f"HTTP {status}: {body!r}"[:2000])
        self.status, self.body = status, body


class Api:
    def __init__(self, base: str, key: str):
        self.base, self.key = base, key

    def call(self, method: str, path: str, body=None, auth: bool = True, timeout: float = 30):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method)
        if auth:
            req.add_header("Authorization", f"Bearer {self.key}")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw = r.read()
                return json.loads(raw) if raw and r.headers.get_content_type() == "application/json" else raw
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                raw = json.loads(raw)
            except ValueError:
                pass
            raise ApiError(e.code, raw) from None

    def get(self, path, **kw):
        return self.call("GET", path, **kw)

    def post(self, path, body=None, **kw):
        return self.call("POST", path, body if body is not None else {}, **kw)

    def put(self, path, body, **kw):
        return self.call("PUT", path, body, **kw)

    def delete(self, path, **kw):
        return self.call("DELETE", path, **kw)


# ------------------------------------------------------------------ HTTP through an edge

class Resp:
    def __init__(self, status, headers, body):
        self.status, self.headers, self.body = status, headers, body

    def json(self):
        return json.loads(self.body)

    @property
    def text(self):
        return self.body.decode("utf-8", "replace")

    def __repr__(self):
        return f"<Resp {self.status} {dict(self.headers)} {self.body[:200]!r}>"


def edge_request(ip: str, host: str, path: str, method: str = "GET", headers: dict | None = None,
                 port: int = 80, timeout: float = 10) -> Resp:
    """One HTTP/1.1 request to an edge IP with the given Host header (what a resolver would send us)."""
    c = http.client.HTTPConnection(ip, port, timeout=timeout)
    try:
        h = {"Host": host, "User-Agent": "pcdn-staging-tests/1", "Connection": "close"}
        h.update(headers or {})
        c.request(method, path, headers=h)
        r = c.getresponse()
        return Resp(r.status, {k.lower(): v for k, v in r.getheaders()}, r.read())
    finally:
        c.close()


def origin_hits(path: str) -> int:
    r = edge_request(ORIGIN_IP, "origin", f"/__staging/hits?path={path}")
    return int(r.json()["hits"])


# ------------------------------------------------------------------ DNS

def dig(name: str, rtype: str = "A") -> list[str]:
    """Answers of our PowerDNS for name/rtype (dig +short), sorted. Needs `dig` (dnsutils)."""
    if shutil.which("dig") is None:
        pytest.skip("dig (dnsutils) is not installed")
    host, _, port = DNS.partition(":")
    out = subprocess.run(["dig", "+short", "+time=3", "+tries=2", "-p", port or "53", f"@{host}", name, rtype],
                         capture_output=True, text=True, timeout=20)
    if out.returncode != 0:
        raise AssertionError(f"dig {name} {rtype} failed: {out.stdout} {out.stderr}")
    return sorted(line.strip() for line in out.stdout.splitlines() if line.strip() and not line.startswith(";"))


# ------------------------------------------------------------------ WebSocket (RFC 6455) client

def _recv_exact(s: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return buf


def ws_echo(ip: str, host: str, path: str, message: str, port: int = 80, timeout: float = 10) -> tuple[int, str]:
    """Open a WebSocket through the edge, send one text frame, return (handshake status, echoed text)."""
    key = base64.b64encode(os.urandom(16)).decode()
    s = socket.create_connection((ip, port), timeout=timeout)
    try:
        s.sendall((f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                   f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
                   "User-Agent: pcdn-staging-tests/1\r\n\r\n").encode())
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = s.recv(4096)
            if not chunk:
                break
            head += chunk
        line = head.split(b"\r\n", 1)[0].decode(errors="replace")
        status = int(line.split()[1]) if len(line.split()) > 1 else 0
        if status != 101:
            return status, ""
        rest = head.split(b"\r\n\r\n", 1)[1]
        payload = message.encode()
        mask = os.urandom(4)
        n = len(payload)
        hdr = bytes([0x81]) + (bytes([0x80 | n]) if n < 126 else bytes([0x80 | 126]) + struct.pack("!H", n))
        s.sendall(hdr + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))

        class _Buf:
            def __init__(self, pre):
                self.pre = pre

            def read(self, k):
                out, self.pre = self.pre[:k], self.pre[k:]
                return out + (_recv_exact(s, k - len(out)) if len(out) < k else b"")

        b = _Buf(rest)
        b0, b1 = b.read(2)
        ln = b1 & 0x7F
        if ln == 126:
            ln = struct.unpack("!H", b.read(2))[0]
        elif ln == 127:
            ln = struct.unpack("!Q", b.read(8))[0]
        data = b.read(ln)
        if b1 & 0x80:
            m = b.read(4)
            data = bytes(x ^ m[i % 4] for i, x in enumerate(data))
        if b0 & 0x0F != 1:
            raise AssertionError(f"unexpected websocket opcode {b0 & 0x0F}")
        try:  # polite close
            s.sendall(bytes([0x88, 0x82]) + mask + bytes(x ^ mask[i % 4] for i, x in enumerate(b"\x03\xe8")))
        except OSError:
            pass
        return status, data.decode()
    finally:
        s.close()


# ------------------------------------------------------------------ fixtures

@pytest.fixture(scope="session")
def api() -> Api:
    a = Api(CONTROLLER, ADMIN_KEY)
    try:
        a.get("/healthz", auth=False, timeout=10)
    except Exception as e:  # noqa: BLE001
        pytest.fail(f"staging controller {CONTROLLER} is not reachable ({e}); start the stack with "
                    "deploy/staging/staging.sh up (docs/STAGING.md)", pytrace=False)
    return a


@pytest.fixture(scope="session")
def edges(api) -> dict:
    """{name: ip} of the staging edges, once every one is online and has applied a config."""
    def ready():
        rows = {e["name"]: e for e in api.get("/api/v1/edges")}
        missing = [n for n in EDGES if n not in rows]
        assert not missing, f"edges not registered: {missing}"
        for n, ip in EDGES.items():
            e = rows[n]
            if e["ipv4"] != ip or not e["last_seen_at"] or not e["applied_version"] or e["last_error"]:
                return None
        return rows
    wait_until(ready, "every staging edge online with an applied config", timeout=max(TIMEOUT, 180))
    return dict(EDGES)


def new_domain(prefix: str) -> str:
    return f"{prefix}-{RUN_ID}.staging.test"
