"""Wire protocols for pcdn-loadtest and its echo origin (stdlib only, asyncio).

* HTTP/1.1 heads and chunked bodies
* WebSocket (RFC 6455) handshake + framing
* a minimal HTTP/2 (RFC 9113) connection with real flow control, used for both the gRPC/h2
  client and the h2c echo origin. HPACK encoding uses literal fields without Huffman (always
  valid); decoding only extracts ``:status`` (static index or a raw literal, which is how nginx
  and our origin encode it). That is all a load test needs, so the ``h2`` package is NOT required.
* the in-band measurement message used by every tunnel scenario
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import os
import struct
import time

WS_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
HEAD_LIMIT = 64 * 1024


class LTError(Exception):
    """An error with a stable machine-readable kind (see loadtest.ERROR_FA)."""

    def __init__(self, kind: str, detail: str = ""):
        super().__init__(f"{kind}: {detail}" if detail else kind)
        self.kind, self.detail = kind, detail


# ----------------------------------------------------------------- HTTP/1.1

def parse_head(head: bytes) -> tuple[str, dict]:
    lines = head.decode("latin-1").split("\r\n")
    hdrs: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            k = k.strip().lower()
            hdrs[k] = (hdrs[k] + ", " + v.strip()) if k in hdrs else v.strip()
    return lines[0], hdrs


async def read_head(reader: asyncio.StreamReader, prefix: bytes = b"") -> tuple[str, dict]:
    try:
        head = prefix + await reader.readuntil(b"\r\n\r\n")
    except asyncio.IncompleteReadError as e:
        if not e.partial and not prefix:
            raise LTError("closed", "connection closed before a response") from None
        raise LTError("closed", "connection closed in the middle of the HTTP head") from None
    except asyncio.LimitOverrunError:
        raise LTError("protocol", "HTTP head too large") from None
    return parse_head(head)


def status_code(line: str) -> int:
    parts = line.split(" ", 2)
    if len(parts) < 2 or not parts[0].startswith("HTTP/") or not parts[1].isdigit():
        raise LTError("protocol", f"not an HTTP response: {line[:60]!r}")
    return int(parts[1])


async def read_chunk(reader: asyncio.StreamReader) -> bytes | None:
    """One chunk of a chunked body; None at the terminating zero chunk (trailers skipped)."""
    line = await reader.readuntil(b"\r\n")
    try:
        n = int(line.split(b";")[0].strip(), 16)
    except ValueError:
        raise LTError("protocol", "bad chunk size") from None
    if n == 0:
        while (await reader.readuntil(b"\r\n")) != b"\r\n":
            pass
        return None
    data = await reader.readexactly(n + 2)
    return data[:-2]


async def read_body(reader: asyncio.StreamReader, hdrs: dict, method: str = "GET", status: int = 200,
                    sink=None) -> int:
    """Read a whole HTTP/1.1 body; returns its size. `sink(bytes)` sees every piece."""
    if method == "HEAD" or status in (204, 304) or 100 <= status < 200:
        return 0
    total = 0
    if "chunked" in hdrs.get("transfer-encoding", "").lower():
        while (c := await read_chunk(reader)) is not None:
            total += len(c)
            if sink:
                sink(c)
        return total
    if "content-length" in hdrs:
        left = int(hdrs["content-length"])
        while left > 0:
            d = await reader.read(min(left, 1 << 18))
            if not d:
                raise LTError("closed", "body shorter than Content-Length")
            left -= len(d)
            total += len(d)
            if sink:
                sink(d)
        return total
    if method in ("POST", "PUT") and status == 0:  # a request without a body
        return 0
    while d := await reader.read(1 << 18):  # close-delimited response
        total += len(d)
        if sink:
            sink(d)
    return total


def http_request(method: str, path: str, host: str, headers: dict | None = None, body: bytes = b"") -> bytes:
    h = {"Host": host, "User-Agent": "pcdn-loadtest/1"}
    h.update(headers or {})
    if body and "Content-Length" not in h and "Transfer-Encoding" not in h:
        h["Content-Length"] = str(len(body))
    return (f"{method} {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in h.items()) + "\r\n").encode() + body


def chunk(data: bytes) -> bytes:
    return b"%x\r\n" % len(data) + data + b"\r\n"


# ----------------------------------------------------------------- WebSocket

def ws_accept(key: str) -> str:
    return base64.b64encode(hashlib.sha1(key.encode() + WS_GUID).digest()).decode()


def _xor(data: bytes, key: bytes) -> bytes:
    n = len(data)
    if not n:
        return data
    k = (key * (n // 4 + 1))[:n]
    return (int.from_bytes(data, "big") ^ int.from_bytes(k, "big")).to_bytes(n, "big")


def ws_frame(payload: bytes, opcode: int = 2, mask: bool = True) -> bytes:
    n = len(payload)
    b1 = 0x80 | opcode
    m = 0x80 if mask else 0
    if n < 126:
        hdr = struct.pack("!BB", b1, m | n)
    elif n < 65536:
        hdr = struct.pack("!BBH", b1, m | 126, n)
    else:
        hdr = struct.pack("!BBQ", b1, m | 127, n)
    if not mask:
        return hdr + payload
    key = os.urandom(4)
    return hdr + key + _xor(payload, key)


async def ws_read(reader: asyncio.StreamReader) -> tuple[int, bytes]:
    """-> (opcode, payload) of one complete message (continuation frames are joined)."""
    opcode, parts = None, []
    while True:
        h = await reader.readexactly(2)
        fin, op, n, masked = h[0] & 0x80, h[0] & 0x0F, h[1] & 0x7F, h[1] & 0x80
        if n == 126:
            n = struct.unpack("!H", await reader.readexactly(2))[0]
        elif n == 127:
            n = struct.unpack("!Q", await reader.readexactly(8))[0]
        key = await reader.readexactly(4) if masked else b""
        data = await reader.readexactly(n)
        if masked:
            data = _xor(data, key)
        if op >= 8:                      # control frames may interleave
            return op, data
        if opcode is None:
            opcode = op
        parts.append(data)
        if fin:
            return opcode, b"".join(parts)


# ----------------------------------------------------------------- in-band measurement messages
# plain:  [u32 total length][u64 send time ns][u32 seq][padding]
# grpc:   [u8 0][u32 inner length] + [u64 send time ns][u32 seq][padding]   (a valid gRPC message)

MSG_MIN = 16


def build_msg(size: int, seq: int, pad: bytes, grpc: bool = False) -> bytes:
    t = time.monotonic_ns()
    if grpc:
        inner = max(size - 5, 12)
        return b"\x00" + struct.pack("!IQI", inner, t, seq) + pad[:inner - 12]
    size = max(size, MSG_MIN)
    return struct.pack("!IQI", size, t, seq) + pad[:size - 16]


class MsgParser:
    """Feeds an echoed byte stream, yields (send_time_ns, seq) for every complete message."""

    def __init__(self, grpc: bool = False):
        self.grpc = grpc
        self.buf = bytearray()

    def feed(self, data: bytes) -> list[tuple[int, int]]:
        self.buf += data
        out = []
        while True:
            if self.grpc:
                if len(self.buf) < 17:
                    break
                n = struct.unpack_from("!I", self.buf, 1)[0] + 5
                if n < 17:
                    raise LTError("corrupt", "bad echoed gRPC message length")
                if len(self.buf) < n:
                    break
                t, seq = struct.unpack_from("!QI", self.buf, 5)
            else:
                if len(self.buf) < 16:
                    break
                n = struct.unpack_from("!I", self.buf, 0)[0]
                if n < 16:
                    raise LTError("corrupt", "bad echoed message length")
                if len(self.buf) < n:
                    break
                t, seq = struct.unpack_from("!QI", self.buf, 4)
            del self.buf[:n]
            out.append((t, seq))
        return out


# ----------------------------------------------------------------- HTTP/2

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
DATA, HEADERS, PRIORITY, RST, SETTINGS, PUSH, PING, GOAWAY, WINDOW, CONT = range(10)
END_STREAM, ACK, END_HEADERS, PADDED, PRIO = 0x1, 0x1, 0x4, 0x8, 0x20
S_ENABLE_PUSH, S_MAX_STREAMS, S_INITIAL_WINDOW, S_MAX_FRAME = 2, 3, 4, 5
BIG_WINDOW = 16 * 1024 * 1024
RST_NAMES = {0: "no_error", 1: "protocol_error", 2: "internal_error", 3: "flow_control_error", 5: "stream_closed",
             7: "refused_stream", 8: "cancel", 11: "enhance_your_calm", 13: "http_1_1_required"}


def h2_frame(ftype: int, flags: int, sid: int, payload: bytes = b"") -> bytes:
    return struct.pack("!I", len(payload))[1:] + bytes((ftype, flags)) + struct.pack("!I", sid) + payload


def hpack_int(value: int, prefix_bits: int, first: int = 0) -> bytes:
    limit = (1 << prefix_bits) - 1
    if value < limit:
        return bytes((first | value,))
    out = [first | limit]
    value -= limit
    while value >= 128:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def hpack_encode(headers) -> bytes:
    """Literal header fields without indexing, new names, no Huffman (RFC 7541 §6.2.2)."""
    out = bytearray()
    for name, value in headers:
        n, v = name.encode(), str(value).encode()
        out += b"\x00" + hpack_int(len(n), 7) + n + hpack_int(len(v), 7) + v
    return bytes(out)


STATIC_STATUS = {0x88: 200, 0x89: 204, 0x8a: 206, 0x8b: 304, 0x8c: 400, 0x8d: 404, 0x8e: 500}


def h2_status(block: bytes) -> int | None:
    """:status from a response header block (the first field, as nginx / our origin encode it)."""
    if not block:
        return None
    b0 = block[0]
    if b0 in STATIC_STATUS:
        return STATIC_STATUS[b0]
    # literal with indexed name 8 (:status): incremental (0x48), without (0x08), never (0x18)
    if b0 in (0x48, 0x08, 0x18) and len(block) >= 5 and block[1] == 3:
        digits = block[2:5]
        if digits.isdigit():
            return int(digits)
    return None


class H2Stream:
    def __init__(self, conn: "H2Conn", sid: int):
        self.conn, self.sid = conn, sid
        self.send_window = conn.peer_initial_window
        self.queue: asyncio.Queue = asyncio.Queue()
        self.headers_event = asyncio.Event()
        self.status: int | None = None
        self.request_block = b""
        self.remote_closed = False
        self.local_closed = False
        self.error: LTError | None = None
        self.recv_unacked = 0

    async def wait_headers(self) -> int | None:
        await self.headers_event.wait()
        if self.error and self.status is None:
            raise self.error
        return self.status

    async def recv(self) -> bytes | None:
        """Next DATA payload; None at END_STREAM. Raises the stream / connection error."""
        item = await self.queue.get()
        if isinstance(item, LTError):
            raise item
        if item is None:
            return None
        self.conn._consumed(self, len(item))
        return item

    def send_headers(self, headers, end: bool = False, raw: bytes | None = None):
        block = raw if raw is not None else hpack_encode(headers)
        self.conn._write(h2_frame(HEADERS, END_HEADERS | (END_STREAM if end else 0), self.sid, block))
        if end:
            self.local_closed = True

    async def send(self, data: bytes, end: bool = False):
        c = self.conn
        view = memoryview(data)
        while len(view):
            while True:
                if self.error:
                    raise self.error
                if c.error:
                    raise c.error
                n = min(len(view), c.send_window, self.send_window, c.peer_max_frame)
                if n > 0:
                    break
                c.window_event.clear()
                await c.window_event.wait()
            last = n == len(view)
            c._write(h2_frame(DATA, END_STREAM if (end and last) else 0, self.sid, bytes(view[:n])))
            c.send_window -= n
            self.send_window -= n
            view = view[n:]
            if c.writer.transport.get_write_buffer_size() > 1 << 20:
                await c.drain()
        if end and not len(data):
            c._write(h2_frame(DATA, END_STREAM, self.sid))
        if end:
            self.local_closed = True
        await c.drain()

    def reset(self, code: int = 8):
        if not (self.local_closed and self.remote_closed) and not self.conn.error:
            self.conn._write(h2_frame(RST, 0, self.sid, struct.pack("!I", code)))
        self.local_closed = self.remote_closed = True
        self.conn.streams.pop(self.sid, None)

    def _fail(self, err: LTError):
        if self.error is None:
            self.error = err
        self.headers_event.set()
        self.queue.put_nowait(err)


class H2Conn:
    """One HTTP/2 connection (client or server role) with connection + stream flow control."""

    def __init__(self, reader, writer, client: bool = True, on_stream=None, window: int = BIG_WINDOW):
        self.reader, self.writer, self.client, self.on_stream = reader, writer, client, on_stream
        self.window = window
        self.streams: dict[int, H2Stream] = {}
        self.next_sid = 1
        self.peer_initial_window = 65535
        self.peer_max_frame = 16384
        self.peer_max_streams: int | None = None
        self.send_window = 65535
        self.recv_unacked = 0
        self.window_event = asyncio.Event()
        self.error: LTError | None = None
        self.settings_event = asyncio.Event()
        self._task: asyncio.Task | None = None
        self._drain_lock = asyncio.Lock()
        self._cont: tuple[int, int, bytearray] | None = None

    # -- lifecycle
    async def start(self):
        settings = struct.pack("!HI", S_INITIAL_WINDOW, self.window)
        if self.client:
            settings = struct.pack("!HI", S_ENABLE_PUSH, 0) + settings
        self._write((PREFACE if self.client else b"") + h2_frame(SETTINGS, 0, 0, settings)
                    + h2_frame(WINDOW, 0, 0, struct.pack("!I", self.window - 65535)))
        await self.drain()
        self._task = asyncio.create_task(self._reader())

    async def close(self):
        if self.error is None:
            try:
                self._write(h2_frame(GOAWAY, 0, 0, struct.pack("!II", 0, 0)))
                await asyncio.wait_for(self.drain(), 2)
            except (OSError, asyncio.TimeoutError, LTError):
                pass
        self._fail(LTError("closed", "connection closed locally"))
        try:
            self.writer.close()
        except Exception:
            pass
        if self._task:
            self._task.cancel()

    # -- I/O
    def _write(self, data: bytes):
        if self.error:
            raise self.error
        self.writer.write(data)

    async def drain(self):
        async with self._drain_lock:
            try:
                await self.writer.drain()
            except (ConnectionError, OSError) as e:
                self._fail(LTError("reset", str(e)))
                raise self.error from None

    def open_stream(self, headers, end: bool = False) -> H2Stream:
        if self.error:
            raise self.error
        sid = self.next_sid
        self.next_sid += 2
        s = H2Stream(self, sid)
        self.streams[sid] = s
        s.send_headers(headers, end=end)
        return s

    def _consumed(self, s: H2Stream, n: int):
        s.recv_unacked += n
        self.recv_unacked += n
        out = b""
        if self.recv_unacked >= self.window // 2:
            out += h2_frame(WINDOW, 0, 0, struct.pack("!I", self.recv_unacked))
            self.recv_unacked = 0
        if s.recv_unacked >= self.window // 2 and not s.remote_closed:
            out += h2_frame(WINDOW, 0, s.sid, struct.pack("!I", s.recv_unacked))
            s.recv_unacked = 0
        if out and not self.error:
            try:
                self.writer.write(out)
            except Exception:
                pass

    def _fail(self, err: LTError):
        if self.error is None:
            self.error = err
        for s in list(self.streams.values()):
            s._fail(err)
        self.window_event.set()
        self.settings_event.set()

    async def _reader(self):
        r = self.reader
        try:
            while True:
                h = await r.readexactly(9)
                n = int.from_bytes(h[:3], "big")
                ftype, flags, sid = h[3], h[4], int.from_bytes(h[5:9], "big") & 0x7FFFFFFF
                payload = await r.readexactly(n) if n else b""
                await self._frame(ftype, flags, sid, payload)
        except asyncio.CancelledError:
            raise
        except asyncio.IncompleteReadError:
            self._fail(LTError("closed", "HTTP/2 connection closed by peer"))
        except (ConnectionError, OSError) as e:
            self._fail(LTError("reset", str(e)))
        except LTError as e:
            self._fail(e)
        except Exception as e:  # never leave streams hanging
            self._fail(LTError("protocol", f"{type(e).__name__}: {e}"))

    @staticmethod
    def _strip(flags: int, payload: bytes, prio: bool) -> bytes:
        if flags & PADDED:
            pad = payload[0]
            payload = payload[1:len(payload) - pad]
        if prio and flags & PRIO:
            payload = payload[5:]
        return payload

    async def _frame(self, ftype, flags, sid, payload):
        if self._cont and ftype != CONT:
            raise LTError("protocol", "expected CONTINUATION")
        if ftype == DATA:
            s = self.streams.get(sid)
            data = self._strip(flags, payload, False)
            if s is None:
                # still account for the connection window
                self.recv_unacked += len(payload)
                if self.recv_unacked >= self.window // 2:
                    self._write(h2_frame(WINDOW, 0, 0, struct.pack("!I", self.recv_unacked)))
                    self.recv_unacked = 0
                return
            pad_extra = len(payload) - len(data)
            if pad_extra:
                self._consumed(s, pad_extra)
            if data:
                s.queue.put_nowait(data)
            elif not flags & END_STREAM:
                pass
            if flags & END_STREAM:
                s.remote_closed = True
                s.queue.put_nowait(None)
                self._maybe_done(s)
        elif ftype in (HEADERS, CONT):
            if ftype == HEADERS:
                block = bytearray(self._strip(flags, payload, True))
                self._cont = (sid, flags, block)
            else:
                if not self._cont or self._cont[0] != sid:
                    raise LTError("protocol", "unexpected CONTINUATION")
                self._cont[2].extend(payload)
            if flags & END_HEADERS:
                hsid, hflags, block = self._cont
                self._cont = None
                self._headers(hsid, hflags, bytes(block))
        elif ftype == SETTINGS:
            if flags & ACK:
                return
            for i in range(0, len(payload) - len(payload) % 6, 6):
                key, val = struct.unpack_from("!HI", payload, i)
                if key == S_INITIAL_WINDOW:
                    delta = val - self.peer_initial_window
                    self.peer_initial_window = val
                    for s in self.streams.values():
                        s.send_window += delta
                elif key == S_MAX_FRAME:
                    self.peer_max_frame = val
                elif key == S_MAX_STREAMS:
                    self.peer_max_streams = val
            self._write(h2_frame(SETTINGS, ACK, 0))
            self.window_event.set()
            self.settings_event.set()
        elif ftype == PING:
            if not flags & ACK:
                self._write(h2_frame(PING, ACK, 0, payload))
        elif ftype == WINDOW:
            inc = struct.unpack("!I", payload[:4])[0] & 0x7FFFFFFF
            if sid == 0:
                self.send_window += inc
            elif sid in self.streams:
                self.streams[sid].send_window += inc
            self.window_event.set()
        elif ftype == RST:
            s = self.streams.pop(sid, None)
            if s:
                code = struct.unpack("!I", payload[:4])[0]
                s.remote_closed = True
                s._fail(LTError("h2_" + RST_NAMES.get(code, f"rst_{code}"), "stream reset by peer"))
        elif ftype == GOAWAY:
            last, code = struct.unpack("!II", payload[:8])
            err = LTError("goaway", f"code {code}")
            for s_id, s in list(self.streams.items()):
                if s_id > (last & 0x7FFFFFFF):
                    s._fail(err)
            self.next_sid = 1 << 31  # no new streams on this connection
            if not self.streams:
                raise err

    def _headers(self, sid: int, flags: int, block: bytes):
        s = self.streams.get(sid)
        if s is None:
            if self.client or sid % 2 == 0:
                return
            s = H2Stream(self, sid)
            s.request_block = block
            self.streams[sid] = s
            s.headers_event.set()
            if self.on_stream:
                asyncio.create_task(self.on_stream(s))
        elif s.status is None and self.client:
            s.status = h2_status(block)
            if s.status is None:
                s.status = 0  # undecodable: unknown but present
            s.headers_event.set()
        # later header blocks are trailers: nothing to decode
        if flags & END_STREAM:
            s.remote_closed = True
            s.headers_event.set()
            s.queue.put_nowait(None)
            self._maybe_done(s)

    def _maybe_done(self, s: H2Stream):
        if s.remote_closed and s.local_closed:
            self.streams.pop(s.sid, None)
