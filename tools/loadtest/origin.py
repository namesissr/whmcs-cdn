#!/usr/bin/env python3
"""Echo / sink origin for pcdn-loadtest (SPEC §16.1). Python 3.11 stdlib only.

Point a test site (and its tunnel paths) of YOUR OWN edge at this process. One TCP port serves:

  * WebSocket       "Upgrade: websocket" + Sec-WebSocket-Key  -> RFC 6455 echo of every message
  * HTTPUpgrade     any other "Upgrade:" request                -> 101, then raw byte echo
  * XHTTP (HTTP/1.1, requests carrying "X-PCDN-LT: xhttp*", which pcdn-loadtest sends)
                    GET  <base>/<sid>                -> chunked downlink of everything uploaded to <sid>
                    POST <base>/<sid>/<seq>          -> packet-up: body appended to <sid>, 200
                    POST <base>/<sid> (chunked)      -> stream-up: every chunk appended to <sid>
  * h2c (prior knowledge, what nginx grpc_pass speaks) for gRPC / h2 tunnel paths:
                    every stream gets :status 200 + content-type application/grpc, each DATA frame is
                    echoed on the same stream, END_STREAM is answered with grpc-status 0 trailers.
  * plain HTTP      GET /bytes/<n> or ?size=<n> -> n bytes (default --body-size), cacheable
                    (Cache-Control: public, max-age=--max-age); POST -> sink, answers the byte count;
                    GET /__lt/stats -> JSON counters.

Optional TLS (--tls-cert/--tls-key, ALPN h2 + http/1.1) for testing the client directly.
No third-party packages are needed (the HTTP/2 code is in lt_proto.py).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import socket
import ssl
import sys
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lt_proto import (H2Conn, LTError, PREFACE, chunk, hpack_encode, read_body, read_chunk,  # noqa: E402
                      read_head, ws_accept, ws_frame, ws_read)

MAX_BODY = 100 * 1024 * 1024


class XSession:
    def __init__(self):
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=256)
        self.created = time.monotonic()
        self.attached = False


class Origin:
    def __init__(self, body_size: int = 16384, max_age: int = 3600, quiet: bool = True):
        self.body_size, self.max_age, self.quiet = body_size, max_age, quiet
        self.blob = os.urandom(1 << 20)
        self.sessions: dict[str, XSession] = {}
        self.stats = {"connections": 0, "active": 0, "requests": 0, "ws": 0, "httpupgrade": 0, "xhttp_down": 0,
                      "xhttp_up": 0, "h2_streams": 0, "bytes_in": 0, "bytes_out": 0, "started": time.time()}

    # -------------------------------------------------------------- entry
    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        sock = writer.get_extra_info("socket")
        if sock is not None:
            try:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError:
                pass
        self.stats["connections"] += 1
        self.stats["active"] += 1
        try:
            sslobj = writer.get_extra_info("ssl_object")
            if sslobj is not None and sslobj.selected_alpn_protocol() == "h2":
                await self.h2(reader, writer, b"")
                return
            first = await reader.readexactly(3)
            if first == b"PRI":
                await self.h2(reader, writer, first)
            elif not first.isalpha():   # e.g. a TLS ClientHello on the plain port: refuse quickly
                writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                await writer.drain()
            else:
                await self.http1(reader, writer, first)
        except (asyncio.IncompleteReadError, ConnectionError, OSError, LTError, asyncio.LimitOverrunError):
            pass
        finally:
            self.stats["active"] -= 1
            try:
                writer.close()
            except Exception:
                pass

    # -------------------------------------------------------------- HTTP/1.1
    async def http1(self, reader, writer, prefix: bytes):
        while True:
            line, hdrs = await read_head(reader, prefix)
            prefix = b""
            self.stats["requests"] += 1
            parts = line.split(" ")
            if len(parts) < 3:
                writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                await writer.drain()
                return
            method, target = parts[0], parts[1]
            u = urllib.parse.urlsplit(target)
            lt = hdrs.get("x-pcdn-lt", "").lower()
            if "upgrade" in hdrs:
                return await self.upgraded(reader, writer, hdrs)
            if lt.startswith("xhttp"):
                if method == "GET":
                    return await self.xhttp_down(reader, writer, u.path)
                if method == "POST":
                    await self.xhttp_up(reader, writer, u.path, hdrs, stream=(lt == "xhttp-stream"))
                    if hdrs.get("connection", "").lower() == "close":
                        return
                    continue
            if method == "POST" or method == "PUT":
                n = await read_body(reader, hdrs, method, 0)
                self.stats["bytes_in"] += n
                self._reply(writer, 200, json.dumps({"bytes": n}).encode(), "application/json", "no-store")
            elif method in ("GET", "HEAD"):
                if u.path == "/__lt/stats":
                    s = dict(self.stats, xhttp_sessions=len(self.sessions), uptime=round(time.time() - self.stats["started"]))
                    self._reply(writer, 200, json.dumps(s).encode(), "application/json", "no-store")
                else:
                    n = self._size(u)
                    self._reply(writer, 200, None, "application/octet-stream",
                                f"public, max-age={self.max_age}" if self.max_age > 0 else "no-store",
                                length=n, head=(method == "HEAD"))
                    if method == "GET":
                        await self._send_blob(writer, n)
            else:
                self._reply(writer, 405, b"", "text/plain", "no-store")
            await writer.drain()
            if hdrs.get("connection", "").lower() == "close":
                return

    def _size(self, u) -> int:
        n = self.body_size
        segs = [s for s in u.path.split("/") if s]
        if len(segs) >= 2 and segs[-2] == "bytes" and segs[-1].isdigit():
            n = int(segs[-1])
        q = urllib.parse.parse_qs(u.query)
        if "size" in q and q["size"][0].isdigit():
            n = int(q["size"][0])
        return max(0, min(n, MAX_BODY))

    def _reply(self, writer, status, body, ctype, cache, length=None, head=False):
        reason = {200: "OK", 400: "Bad Request", 404: "Not Found", 405: "Method Not Allowed"}.get(status, "OK")
        n = len(body) if body is not None else length
        writer.write((f"HTTP/1.1 {status} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {n}\r\n"
                      f"Cache-Control: {cache}\r\nX-Origin: pcdn-loadtest\r\n\r\n").encode())
        if body and not head:
            writer.write(body)
            self.stats["bytes_out"] += len(body)

    async def _send_blob(self, writer, n):
        blob = self.blob
        while n > 0:
            k = min(n, len(blob))
            writer.write(blob[:k])
            self.stats["bytes_out"] += k
            n -= k
            await writer.drain()

    async def upgraded(self, reader, writer, hdrs):
        if "sec-websocket-key" in hdrs:
            self.stats["ws"] += 1
            writer.write(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                          f"Sec-WebSocket-Accept: {ws_accept(hdrs['sec-websocket-key'])}\r\n\r\n").encode())
            await writer.drain()
            while True:
                op, data = await ws_read(reader)
                if op == 8:
                    writer.write(ws_frame(data[:2], 8, mask=False))
                    await writer.drain()
                    return
                if op == 9:
                    writer.write(ws_frame(data, 10, mask=False))
                elif op in (1, 2):
                    self.stats["bytes_in"] += len(data)
                    self.stats["bytes_out"] += len(data)
                    writer.write(ws_frame(data, op, mask=False))
                await writer.drain()
        self.stats["httpupgrade"] += 1
        up = hdrs.get("upgrade", "websocket")
        writer.write(f"HTTP/1.1 101 Switching Protocols\r\nUpgrade: {up}\r\nConnection: Upgrade\r\n\r\n".encode())
        await writer.drain()
        while d := await reader.read(1 << 18):
            self.stats["bytes_in"] += len(d)
            self.stats["bytes_out"] += len(d)
            writer.write(d)
            await writer.drain()

    # -------------------------------------------------------------- XHTTP over HTTP/1.1
    def _session(self, key: str) -> XSession:
        s = self.sessions.get(key)
        if s is None:
            if len(self.sessions) > 200000:  # stale packet-up sessions without a GET
                now = time.monotonic()
                for k in [k for k, v in self.sessions.items() if not v.attached and now - v.created > 60]:
                    del self.sessions[k]
            s = self.sessions[key] = XSession()
        return s

    async def xhttp_down(self, reader, writer, path):
        key = path.rstrip("/")
        s = self._session(key)
        s.attached = True
        self.stats["xhttp_down"] += 1
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n"
                     b"Cache-Control: no-store\r\nX-Accel-Buffering: no\r\n\r\n")
        await writer.drain()
        eof = asyncio.create_task(reader.read(1))  # the client closing the downlink ends the session
        try:
            while True:
                get = asyncio.create_task(s.queue.get())
                done, _ = await asyncio.wait({get, eof}, return_when=asyncio.FIRST_COMPLETED)
                if get not in done:
                    get.cancel()
                    return
                data = get.result()
                if data is None:
                    writer.write(b"0\r\n\r\n")
                    await writer.drain()
                    return
                self.stats["bytes_out"] += len(data)
                writer.write(chunk(data))
                await writer.drain()
        finally:
            eof.cancel()
            if self.sessions.get(key) is s:
                del self.sessions[key]

    async def xhttp_up(self, reader, writer, path, hdrs, stream: bool):
        key = path.rstrip("/") if stream else path.rstrip("/").rsplit("/", 1)[0]
        s = self._session(key)
        self.stats["xhttp_up"] += 1
        total = 0

        if "chunked" in hdrs.get("transfer-encoding", "").lower():
            while (c := await read_chunk(reader)) is not None:
                total += len(c)
                await s.queue.put(c)
        else:
            left = int(hdrs.get("content-length", "0"))
            while left > 0:
                d = await reader.read(min(left, 1 << 18))
                if not d:
                    raise LTError("closed")
                left -= len(d)
                total += len(d)
                await s.queue.put(d)
        self.stats["bytes_in"] += total
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nCache-Control: no-store\r\n\r\n")
        await writer.drain()

    # -------------------------------------------------------------- h2c / h2 echo (gRPC, h2 tunnel paths)
    async def h2(self, reader, writer, prefix: bytes):
        if prefix:
            rest = await reader.readexactly(len(PREFACE) - len(prefix))
            if prefix + rest != PREFACE:
                return
        else:
            if await reader.readexactly(len(PREFACE)) != PREFACE:
                return
        conn = H2Conn(reader, writer, client=False, on_stream=self.h2_stream)
        await conn.start()
        try:
            await conn._task
        except asyncio.CancelledError:
            pass

    async def h2_stream(self, s):
        self.stats["h2_streams"] += 1
        try:
            s.send_headers(None, raw=b"\x88" + hpack_encode([("content-type", "application/grpc")]))
            while (data := await s.recv()) is not None:
                self.stats["bytes_in"] += len(data)
                self.stats["bytes_out"] += len(data)
                await s.send(data)
            s.send_headers([("grpc-status", "0")], end=True)
            await s.conn.drain()
            s.conn._maybe_done(s)
        except (LTError, ConnectionError, OSError):
            pass


async def serve(host: str, port: int, origin: Origin, ssl_ctx=None, ready=None):
    server = await asyncio.start_server(origin.handle, host, port, ssl=ssl_ctx, backlog=4096, limit=1 << 20,
                                        reuse_address=True)
    bound = server.sockets[0].getsockname()[1]
    if ready is not None:
        ready(bound)
    if not origin.quiet or ready is None:
        print(f"pcdn-loadtest origin listening on {host}:{bound} ({'TLS' if ssl_ctx else 'plain'}; "
              f"ws, httpupgrade, xhttp, h2c/gRPC, http)", flush=True)
    async with server:
        await server.serve_forever()


def main(argv=None):
    ap = argparse.ArgumentParser(description="Echo / sink origin for pcdn-loadtest (SPEC §16.1).")
    ap.add_argument("--listen", default="0.0.0.0", help="bind address (default 0.0.0.0)")
    ap.add_argument("--port", type=int, default=8080, help="port (default 8080; 0 = any free port)")
    ap.add_argument("--body-size", type=int, default=16384, help="default GET body size in bytes (16384)")
    ap.add_argument("--max-age", type=int, default=3600, help="Cache-Control max-age for GET bodies (0 = no-store)")
    ap.add_argument("--tls-cert", help="serve TLS with this certificate (PEM)")
    ap.add_argument("--tls-key", help="private key for --tls-cert")
    ap.add_argument("--port-file", help="write the bound port to this file (tests)")
    a = ap.parse_args(argv)
    ctx = None
    if a.tls_cert:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(a.tls_cert, a.tls_key)
        ctx.set_alpn_protocols(["h2", "http/1.1"])
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        if soft < hard:
            resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))
    except (ImportError, ValueError, OSError):
        pass
    origin = Origin(a.body_size, a.max_age, quiet=False)

    def ready(port):
        print(f"pcdn-loadtest origin listening on {a.listen}:{port} ({'TLS' if ctx else 'plain'}; "
              "ws, httpupgrade, xhttp, h2c/gRPC, http)", flush=True)
        if a.port_file:
            with open(a.port_file + ".tmp", "w") as f:
                f.write(str(port))
            os.replace(a.port_file + ".tmp", a.port_file)
    origin.quiet = True
    try:
        asyncio.run(serve(a.listen, a.port, origin, ctx, ready))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
