"""Shared helpers for the analytics & platform tests (SPEC §14.3): the fake DNS table for the SSRF
guard and a local HTTP receiver. The fixtures using them (fake_dns, local_vet, receiver) live in
conftest.py. Nothing here touches the network beyond the loopback interface."""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from tests.test_api import add_edge

S = "/api/v1/sites/example.com"
LOCAL_HOST = "hooks.local.test"  # "vetted" to 127.0.0.1 by the local_vet fixture

FAKE_DNS = {
    "hooks.public.example": ["93.184.216.34"],
    "s3.public.example": ["93.184.216.35"],
    "v6.public.example": ["2606:4700::1111"],
    "private.example": ["10.1.2.3"],
    "loop.example": ["127.0.0.1"],
    "metadata.example": ["169.254.169.254"],
    "cgnat.example": ["100.64.1.1"],
    "multicast.example": ["224.0.0.251"],
    "mixed.example": ["93.184.216.34", "192.168.1.1"],
    "ula.example": ["fd00::1"],
    "mapped.example": ["::ffff:127.0.0.1"],
    "sixtofour.example": ["2002:7f00:1::1"],
}


class Receiver:
    """A local HTTP endpoint recording every request; `status`, `location` and `body` shape the
    answer."""

    def __init__(self):
        self.requests: list[dict] = []
        self.status = 200
        self.location: str | None = None
        self.body = b"ok"
        rec = self

        class Handler(BaseHTTPRequestHandler):
            def _handle(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n) if n else b""
                rec.requests.append({"method": self.command, "path": self.path, "body": body,
                                     "headers": {k.lower(): v for k, v in self.headers.items()}})
                self.send_response(rec.status)
                if rec.location:
                    self.send_header("Location", rec.location)
                self.send_header("Content-Length", str(len(rec.body)))
                self.end_headers()
                self.wfile.write(rec.body)

            do_POST = do_GET = do_PUT = _handle

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def url(self, path="/hook") -> str:
        return f"http://{LOCAL_HOST}:{self.port}{path}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def make_site(client, domain="example.com", **features):
    r = client.post("/api/v1/sites", json={"domain": domain, "origin_ip": "93.184.216.34",
                                           "plan": {"features": features} if features else {}})
    assert r.status_code == 201, r.text
    return r.json()


def edge_token(client, name="ir-thr-1", ip="5.160.1.10"):
    return add_edge(client, name=name, ip=ip)


def auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}
