"""Fakes for the preflight tests: a controller (HTTP or HTTPS) and authoritative DNS servers, each in
a thread on 127.0.0.1. Deliberately not a conftest.py (other suites may share one pytest session)."""

import contextlib
import json
import pathlib
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PF_DIR = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PF_DIR))

import preflight  # noqa: E402

KEY = "pf-test-admin-key-0123456789abcdef"
BUNDLE = "2026.10.01-abc123"


def iso_ago(seconds: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(seconds=seconds)).replace(tzinfo=None).isoformat() + "Z"


def healthy_routes(overrides=None):
    """Route table for a healthy controller; values are (status, body) or callables returning that."""
    deep = {"status": "ok", "instance": "a", "warnings": [],
            "database": {"ok": True, "dialect": "postgresql", "revision": "0020", "head": "0020"},
            "backup": {"enabled": True, "last_success_age_hours": 3.5, "failing": False},
            "alerts": {"channels": ["telegram"], "open": 0, "critical": 0}}
    routes = {
        ("GET", "/healthz"): (200, {"ok": True}),
        ("GET", "/healthz/deep"): (200, deep),
        ("GET", "/edge/version"): (200, {"version": BUNDLE}),
        ("GET", "/api/v1/edges"): lambda: (200, [
            {"id": 1, "name": "edge-1", "enabled": True, "last_seen_at": iso_ago(20), "bundle_version": BUNDLE,
             "last_error": None, "probe": {"ok": True}},
            {"id": 2, "name": "edge-2", "enabled": True, "last_seen_at": iso_ago(40), "bundle_version": BUNDLE,
             "last_error": None, "probe": {"ok": True}},
            {"id": 3, "name": "old-off", "enabled": False, "last_seen_at": None, "bundle_version": None},
        ]),
        ("GET", "/api/v1/sites"): (200, [{"domain": "suspended.test", "status": "suspended"},
                                         {"domain": "shop.test", "status": "active"}]),
        ("GET", "/metrics"): (401, {"detail": "missing bearer token"}),
        ("POST", "/api/v1/alerts/test"): (200, {"ok": True, "results": {"telegram": "ok"}}),
    }
    routes.update(overrides or {})
    return routes


class FakeController:
    def __init__(self, routes, tls_ctx=None):
        self.routes = routes
        self.seen = []  # (method, path, authorization)
        fake = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _serve(self, method):
                if method == "POST":
                    self.rfile.read(int(self.headers.get("Content-Length") or 0))
                auth = self.headers.get("Authorization")
                fake.seen.append((method, self.path, auth))
                route = fake.routes.get((method, self.path.split("?")[0]))
                if route is None:
                    code, body = 404, {"detail": "Not Found"}
                else:
                    code, body = route() if callable(route) else route
                if self.path.startswith("/api/") and auth != "Bearer " + KEY:
                    code, body = 401, {"detail": "invalid api key"}
                raw = body.encode() if isinstance(body, str) else json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self):
                self._serve("GET")

            def do_POST(self):
                self._serve("POST")

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        if tls_ctx is not None:
            self.srv.socket = tls_ctx.wrap_socket(self.srv.socket, server_side=True)
        self.port = self.srv.server_address[1]
        self.url = f"{'https' if tls_ctx else 'http'}://127.0.0.1:{self.port}"
        self.t = threading.Thread(target=self.srv.serve_forever, daemon=True)

    def __enter__(self):
        self.t.start()
        return self

    def __exit__(self, *exc):
        self.srv.shutdown()
        self.srv.server_close()


class FakeDNS:
    """mode: 'soa' (answer serial), 'refused', 'silent'; aa toggles the authoritative bit."""

    def __init__(self, serial=2026100201, mode="soa", aa=True):
        self.serial, self.mode, self.aa = serial, mode, aa
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.spec = f"127.0.0.1:{self.port}"
        self._stop = threading.Event()
        self.t = threading.Thread(target=self._loop, daemon=True)

    def _answer(self, q: bytes) -> bytes:
        qid = struct.unpack(">H", q[:2])[0]
        # question ends after the name + 4 bytes
        off = 12
        while q[off]:
            off += q[off] + 1
        question = q[12:off + 5]
        flags = 0x8000 | (0x0400 if self.aa else 0)
        if self.mode == "refused":
            return struct.pack(">HHHHHH", qid, flags | 5, 1, 0, 0, 0) + question
        rdata = (b"\x03ns1\xc0\x0c" + b"\x0ahostmaster\xc0\x0c"   # mname/rname compressed to the qname
                 + struct.pack(">IIIII", self.serial, 10800, 3600, 604800, 3600))
        rr = b"\xc0\x0c" + struct.pack(">HHIH", 6, 1, 3600, len(rdata)) + rdata
        return struct.pack(">HHHHHH", qid, flags, 1, 1, 0, 0) + question + rr

    def _loop(self):
        while not self._stop.is_set():
            try:
                q, addr = self.sock.recvfrom(512)
            except socket.timeout:
                continue
            except OSError:
                return
            if self.mode != "silent":
                self.sock.sendto(self._answer(q), addr)

    def __enter__(self):
        self.t.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self.t.join(2)
        self.sock.close()


def closed_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@contextlib.contextmanager
def listening_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(8)
    try:
        yield s.getsockname()[1]
    finally:
        s.close()


def have_openssl() -> bool:
    return shutil.which("openssl") is not None


def make_cert(tmp_path, days: int):
    """Self-signed cert for 127.0.0.1 valid `days` days -> (server SSLContext, cert path)."""
    cert, key = tmp_path / f"c{days}.pem", tmp_path / f"k{days}.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert),
                    "-days", str(days), "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1"],
                   check=True, capture_output=True)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert), str(key))
    return ctx, str(cert)


def run_main(capsys, *args):
    rc = preflight.main([str(a) for a in args])
    return rc, capsys.readouterr().out
