"""Standard-library tunnel endpoints for the edge tests (no h2 / websockets packages needed).

TunnelOrigin  one TCP port that behaves like an Xray inbound behind the CDN:
              - "Upgrade: websocket" + Sec-WebSocket-Key -> RFC 6455 echo (text/binary frames)
              - any other "Upgrade:" (HTTPUpgrade transport) -> 101, then raw byte echo
              - POST (chunked or Content-Length) -> reads the body as it arrives and records when
                every piece came in, answers with those arrival times as JSON
              - GET .../down... -> chunked response, one chunk every `gap` seconds
              - GET .../big?n=N -> N bytes as fast as possible
              - GET anything else -> JSON echo of the request line + headers
H2Origin      h2c (prior knowledge) server: answers every stream with HEADERS(:status 200), echoes
              each DATA frame back on the same stream and closes with grpc-status trailers. Header
              blocks from nginx are never decoded (HPACK Huffman is not needed for that).
H2Client      HTTP/2 over TLS (ALPN h2) client that opens one bidirectional stream.
ws_*          minimal WebSocket client helpers over a plain or TLS socket.
"""

import base64
import hashlib
import json
import os
import socket
import ssl
import struct
import threading
import time

WS_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


# ----------------------------------------------------------------- small socket helpers

def read_until(sock, marker: bytes, buf: bytes = b"") -> tuple[bytes, bytes]:
    while marker not in buf:
        d = sock.recv(65536)
        if not d:
            raise ConnectionError("closed before %r" % marker)
        buf += d
    i = buf.index(marker) + len(marker)
    return buf[:i], buf[i:]


def read_exact(sock, n: int, buf: bytes = b"") -> tuple[bytes, bytes]:
    while len(buf) < n:
        d = sock.recv(65536)
        if not d:
            raise ConnectionError("closed")
        buf += d
    return buf[:n], buf[n:]


def parse_head(head: bytes) -> tuple[str, dict]:
    lines = head.decode("latin-1").split("\r\n")
    hdrs = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            hdrs[k.strip().lower()] = v.strip()
    return lines[0], hdrs


# ----------------------------------------------------------------- websocket framing

def ws_frame(payload: bytes, opcode: int = 2, mask: bool = True) -> bytes:
    n = len(payload)
    b1 = 0x80 | opcode
    if n < 126:
        hdr = struct.pack("!BB", b1, (0x80 if mask else 0) | n)
    elif n < 65536:
        hdr = struct.pack("!BBH", b1, (0x80 if mask else 0) | 126, n)
    else:
        hdr = struct.pack("!BBQ", b1, (0x80 if mask else 0) | 127, n)
    if not mask:
        return hdr + payload
    key = os.urandom(4)
    return hdr + key + bytes(b ^ key[i % 4] for i, b in enumerate(payload))


def ws_read(sock, buf: bytes = b"") -> tuple[int, bytes, bytes]:
    """-> (opcode, payload, remaining buffer)."""
    h, buf = read_exact(sock, 2, buf)
    opcode, n, masked = h[0] & 0x0F, h[1] & 0x7F, h[1] & 0x80
    if n == 126:
        x, buf = read_exact(sock, 2, buf)
        n = struct.unpack("!H", x)[0]
    elif n == 127:
        x, buf = read_exact(sock, 8, buf)
        n = struct.unpack("!Q", x)[0]
    key = b""
    if masked:
        key, buf = read_exact(sock, 4, buf)
    data, buf = read_exact(sock, n, buf)
    if masked:
        data = bytes(b ^ key[i % 4] for i, b in enumerate(data))
    return opcode, data, buf


def ws_accept(key: str) -> str:
    return base64.b64encode(hashlib.sha1(key.encode() + WS_GUID).digest()).decode()


def upgrade_request(host: str, path: str, ws: bool = True, extra: dict | None = None) -> bytes:
    h = {"Host": host, "Upgrade": "websocket", "Connection": "Upgrade", "User-Agent": "Go-http-client/1.1"}
    if ws:
        h["Sec-WebSocket-Key"] = base64.b64encode(os.urandom(16)).decode()
        h["Sec-WebSocket-Version"] = "13"
    h.update(extra or {})
    return (f"GET {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in h.items()) + "\r\n").encode()


def connect(port: int, host: str, tls: bool, alpn=None, timeout: float = 10):
    sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        if alpn:
            ctx.set_alpn_protocols(alpn)
        sock = ctx.wrap_socket(sock, server_hostname=host)
    return sock


# ----------------------------------------------------------------- HTTP/1.1 tunnel origin

class TunnelOrigin:
    def __init__(self, gap: float = 0.4, chunks: int = 4):
        self.gap, self.chunks = gap, chunks
        self.requests = []          # (request line, headers) of every request
        self.upgraded_bytes = 0     # payload bytes echoed on upgraded connections
        self.lsock = socket.socket()
        self.lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.lsock.bind(("127.0.0.1", 0))
        self.lsock.listen(128)
        self.port = self.lsock.getsockname()[1]
        self.running = True
        threading.Thread(target=self._accept, daemon=True).start()

    def stop(self):
        self.running = False
        try:
            self.lsock.close()
        except OSError:
            pass

    def _accept(self):
        while self.running:
            try:
                c, _ = self.lsock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(c,), daemon=True).start()

    def _serve(self, c):
        c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        c.settimeout(30)
        buf = b""
        try:
            while True:  # keep-alive loop
                head, buf = read_until(c, b"\r\n\r\n", buf)
                line, hdrs = parse_head(head)
                self.requests.append((line, hdrs))
                method, path = line.split(" ")[:2]
                if "upgrade" in hdrs:
                    return self._upgraded(c, hdrs, buf)
                if method == "POST":
                    buf = self._post(c, hdrs, buf)
                elif "/down" in path:
                    self._down(c)
                elif "/big" in path:
                    body = b"b" * int(path.rsplit("=", 1)[1])
                    c.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: "
                              + str(len(body)).encode() + b"\r\n\r\n" + body)
                else:
                    body = json.dumps({"line": line, "headers": hdrs}).encode()
                    c.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                              + str(len(body)).encode() + b"\r\n\r\n" + body)
        except (OSError, ConnectionError, ValueError):
            pass
        finally:
            c.close()

    def _upgraded(self, c, hdrs, buf):
        if "sec-websocket-key" in hdrs:
            c.sendall(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                       f"Sec-WebSocket-Accept: {ws_accept(hdrs['sec-websocket-key'])}\r\n\r\n").encode())
            while True:
                op, data, buf = ws_read(c, buf)
                if op == 8:
                    c.sendall(ws_frame(data, 8, mask=False))
                    return
                self.upgraded_bytes += len(data)
                c.sendall(ws_frame(data, op, mask=False))
        c.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
        if buf:
            self.upgraded_bytes += len(buf)
            c.sendall(buf)
        while True:
            d = c.recv(65536)
            if not d:
                return
            self.upgraded_bytes += len(d)
            c.sendall(d)

    def _post(self, c, hdrs, buf):
        t0, arrivals, total = time.time(), [], 0
        if hdrs.get("transfer-encoding", "").lower() == "chunked":
            while True:
                size_line, buf = read_until(c, b"\r\n", buf)
                n = int(size_line.split(b";")[0], 16)
                data, buf = read_exact(c, n + 2, buf)
                if n == 0:
                    break
                arrivals.append(round(time.time() - t0, 3))
                total += n
        else:
            left = int(hdrs.get("content-length", "0"))
            while left > 0:
                if not buf:
                    buf = c.recv(65536)
                    if not buf:
                        raise ConnectionError("closed")
                take = min(left, len(buf))
                arrivals.append(round(time.time() - t0, 3))
                total, left, buf = total + take, left - take, buf[take:]
        body = json.dumps({"arrivals": arrivals, "bytes": total, "headers": hdrs}).encode()
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                  + str(len(body)).encode() + b"\r\n\r\n" + body)
        return buf

    def _down(self, c):
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n"
                  b"Cache-Control: no-store\r\n\r\n")
        for i in range(self.chunks):
            piece = f"chunk-{i}|".encode()
            c.sendall(b"%x\r\n%s\r\n" % (len(piece), piece))
            time.sleep(self.gap)
        c.sendall(b"0\r\n\r\n")


# ----------------------------------------------------------------- HTTP/2 framing

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
DATA, HEADERS, RST, SETTINGS, PING, GOAWAY, WINDOW, CONT = 0, 1, 3, 4, 6, 7, 8, 9
END_STREAM, END_HEADERS, ACK = 0x1, 0x4, 0x1


def h2_frame(ftype: int, flags: int, sid: int, payload: bytes = b"") -> bytes:
    return struct.pack("!I", len(payload))[1:] + bytes((ftype, flags)) + struct.pack("!I", sid) + payload


def h2_read(sock, buf: bytes) -> tuple[int, int, int, bytes, bytes]:
    h, buf = read_exact(sock, 9, buf)
    n = int.from_bytes(h[:3], "big")
    payload, buf = read_exact(sock, n, buf)
    return h[3], h[4], int.from_bytes(h[5:9], "big") & 0x7FFFFFFF, payload, buf


def hpack_literal(name: str, value: str) -> bytes:
    """Literal header field without indexing, new name, no Huffman (RFC 7541 6.2.2)."""
    def s(x):
        b = x.encode()
        assert len(b) < 127
        return bytes((len(b),)) + b
    return b"\x00" + s(name) + s(value)


def h2_status(block: bytes) -> int | None:
    """:status from a response header block as nginx / H2Origin encode it (first field)."""
    if not block:
        return None
    static = {0x88: 200, 0x89: 204, 0x8a: 206, 0x8b: 304, 0x8c: 400, 0x8d: 404, 0x8e: 500}
    if block[0] in static:
        return static[block[0]]
    if block[0] & 0x0F == 8 and block[1] == 3:  # literal, indexed name :status, 3 raw digits
        return int(block[2:5])
    return None


def _grpc_msg(data: bytes) -> bytes:
    return b"\x00" + struct.pack("!I", len(data)) + data


class H2Origin:
    """h2c prior-knowledge echo server (see module docstring)."""

    def __init__(self):
        self.streams = 0
        self.echoed = 0
        self.lsock = socket.socket()
        self.lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.lsock.bind(("127.0.0.1", 0))
        self.lsock.listen(64)
        self.port = self.lsock.getsockname()[1]
        self.running = True
        threading.Thread(target=self._accept, daemon=True).start()

    def stop(self):
        self.running = False
        try:
            self.lsock.close()
        except OSError:
            pass

    def _accept(self):
        while self.running:
            try:
                c, _ = self.lsock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(c,), daemon=True).start()

    def _serve(self, c):
        c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        lock = threading.Lock()

        def send(*frames):
            with lock:
                c.sendall(b"".join(frames))
        try:
            _, buf = read_exact(c, len(PREFACE))
            send(h2_frame(SETTINGS, 0, 0))
            while True:
                ftype, flags, sid, payload, buf = h2_read(c, buf)
                if ftype == SETTINGS and not flags & ACK:
                    send(h2_frame(SETTINGS, ACK, 0))
                elif ftype == PING and not flags & ACK:
                    send(h2_frame(PING, ACK, 0, payload))
                elif ftype == HEADERS:
                    self.streams += 1
                    send(h2_frame(HEADERS, END_HEADERS, sid, b"\x88" + hpack_literal("content-type", "application/grpc")))
                    if flags & END_STREAM:
                        send(h2_frame(DATA, 0, sid, b"hello"),
                             h2_frame(HEADERS, END_HEADERS | END_STREAM, sid, hpack_literal("grpc-status", "0")))
                elif ftype == DATA:
                    if payload:
                        inc = struct.pack("!I", len(payload))
                        self.echoed += len(payload)
                        send(h2_frame(WINDOW, 0, 0, inc), h2_frame(WINDOW, 0, sid, inc), h2_frame(DATA, 0, sid, payload))
                    if flags & END_STREAM:
                        send(h2_frame(HEADERS, END_HEADERS | END_STREAM, sid, hpack_literal("grpc-status", "0")))
                elif ftype == GOAWAY:
                    return
        except (OSError, ConnectionError):
            pass
        finally:
            c.close()


class H2Client:
    """One HTTP/2 stream over TLS; send() and recv_data() interleave freely (bidirectional)."""

    def __init__(self, port: int, host: str, path: str, method: str = "POST", ctype: str = "application/grpc",
                 end_stream: bool = False):
        self.sock = connect(port, host, True, alpn=["h2"])
        assert self.sock.selected_alpn_protocol() == "h2", self.sock.selected_alpn_protocol()
        self.buf = b""
        self.status = None
        self.trailers = False
        self.closed = False
        block = b"".join(hpack_literal(k, v) for k, v in (
            (":method", method), (":scheme", "https"), (":path", path), (":authority", host),
            ("content-type", ctype), ("te", "trailers"), ("user-agent", "grpc-go/1.60")))
        # big windows so the test never waits on flow control
        self.sock.sendall(PREFACE + h2_frame(SETTINGS, 0, 0, struct.pack("!HI", 4, 16 * 1024 * 1024))
                          + h2_frame(WINDOW, 0, 0, struct.pack("!I", 64 * 1024 * 1024))
                          + h2_frame(HEADERS, END_HEADERS | (END_STREAM if end_stream else 0), 1, block))

    def send(self, data: bytes, end: bool = False):
        self.sock.sendall(h2_frame(DATA, END_STREAM if end else 0, 1, data))

    def recv_data(self, timeout: float = 10) -> bytes | None:
        """Next DATA payload on stream 1 (None when the stream ended)."""
        self.sock.settimeout(timeout)
        while True:
            if self.closed:
                return None
            ftype, flags, sid, payload, self.buf = h2_read(self.sock, self.buf)
            if ftype == SETTINGS and not flags & ACK:
                self.sock.sendall(h2_frame(SETTINGS, ACK, 0))
            elif ftype == PING and not flags & ACK:
                self.sock.sendall(h2_frame(PING, ACK, 0, payload))
            elif ftype == GOAWAY:
                self.closed = True
            elif sid == 1 and ftype == RST:
                self.closed = True
            elif sid == 1 and ftype == HEADERS:
                if self.status is None:
                    self.status = h2_status(payload)
                else:
                    self.trailers = True
                if flags & END_STREAM:
                    self.closed = True
            elif sid == 1 and ftype == DATA:
                if flags & END_STREAM:
                    self.closed = True
                if payload:
                    return payload

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass
