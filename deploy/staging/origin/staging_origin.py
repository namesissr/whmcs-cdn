#!/usr/bin/env python3
"""STAGING ONLY — sample origin for the staging stack (docs/STAGING.md). Python stdlib only.

  :80    HTTP echo. Every request is answered with JSON describing what the origin received
         ({"serial", "method", "path", "host", "headers"}), Cache-Control: public, max-age=3600
         (?nocache=1 -> no-store). `serial` grows per origin request, so a cache HIT on the edge returns
         an older serial. GET /__staging/hits?path=/x -> how often the origin saw /x. GET /healthz.
  :8080  tools/loadtest/origin.py (WebSocket / HTTPUpgrade / XHTTP echo, h2c gRPC echo) for tunnels.
  :9000  raw TCP echo for the L4 (TCP proxy) test.
"""

import asyncio
import json
import os
import socketserver
import sys
import threading
import urllib.parse
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HITS: Counter = Counter()
LOCK = threading.Lock()
SERIAL = [0]


class Echo(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "pcdn-staging-origin"

    def log_message(self, fmt, *args):
        sys.stdout.write("origin %s %s\n" % (self.address_string(), fmt % args))

    def _send(self, code: int, body: bytes, ctype: str, cache: str):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", cache)
        self.send_header("X-Origin", "pcdn-staging")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _handle(self):
        u = urllib.parse.urlsplit(self.path)
        q = urllib.parse.parse_qs(u.query)
        if u.path == "/healthz":
            return self._send(200, b"ok\n", "text/plain", "no-store")
        if u.path == "/__staging/hits":
            p = (q.get("path") or [""])[0]
            with LOCK:
                n = HITS[p]
            return self._send(200, json.dumps({"path": p, "hits": n}).encode(), "application/json", "no-store")
        n = int(self.headers.get("Content-Length") or 0)
        if n:
            self.rfile.read(n)
        with LOCK:
            HITS[u.path] += 1
            SERIAL[0] += 1
            serial = SERIAL[0]
        body = json.dumps({
            "serial": serial, "method": self.command, "path": u.path, "query": u.query,
            "host": self.headers.get("Host", ""),
            "headers": {k.lower(): v for k, v in self.headers.items()},
        }, sort_keys=True).encode()
        cache = "no-store" if "nocache" in q else "public, max-age=3600"
        self._send(200, body, "application/json", cache)

    do_GET = do_HEAD = do_POST = do_PUT = do_DELETE = _handle


class TcpEcho(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            data = self.request.recv(65536)
            if not data:
                return
            self.request.sendall(data)


class TcpServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def run_tunnel_origin(port: int):
    sys.path.insert(0, os.environ.get("LOADTEST_DIR", "/srv/loadtest"))
    import origin as lt  # tools/loadtest/origin.py

    o = lt.Origin(quiet=True)
    asyncio.run(lt.serve("0.0.0.0", port, o, ready=lambda p: print(f"tunnel echo origin on :{p}", flush=True)))


def main():
    threading.Thread(target=run_tunnel_origin, args=(8080,), daemon=True).start()
    tcp = TcpServer(("0.0.0.0", 9000), TcpEcho)
    threading.Thread(target=tcp.serve_forever, daemon=True).start()
    print("tcp echo origin on :9000", flush=True)
    http = ThreadingHTTPServer(("0.0.0.0", 80), Echo)
    http.daemon_threads = True
    print("http echo origin on :80", flush=True)
    http.serve_forever()


if __name__ == "__main__":
    main()
