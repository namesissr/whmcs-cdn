#!/usr/bin/env python3
"""pcdn-loadtest — load-test kit for ONE edge node you own (SPEC §16.1).

Scenarios
  http         cache hit/miss mix over HTTP/1.1 keep-alive (--rps, --concurrency, --miss-ratio)
  ws           WebSocket tunnel sessions (RFC 6455 echo)          ┐ every session sends timestamped
  httpupgrade  HTTPUpgrade tunnel sessions (raw bytes after 101)  │ messages at --mbps each and
  grpc         gRPC streams over HTTP/2 (TLS+ALPN h2, or h2c)     │ measures the echo round trip
  h2           raw HTTP/2 streams (XHTTP stream-one style)        │ (needs tools/loadtest/origin.py,
  xhttp        XHTTP over HTTP/1.1 (packet-up or stream-up)       ┘ or any echo, as the origin)
  ramp         step up connections of --protocol until the error rate or p99 crosses a threshold
  merge        merge the JSON results of several parallel runs (several client processes / VMs)

Output: a JSON report (--out) and a Persian summary (max sustainable connections, Mbps,
p50/p95/p99, errors by type).

SAFETY: this generates real load. Use it only against an edge node YOU operate, addressed by IP
(--target IP:port) with the Host/SNI of a test site on it (--host). It refuses to run without an
explicit IP target. Never point it at third-party infrastructure.

Python 3.11+, standard library only (uvloop is used when installed; HTTP/2 framing is built in,
the `h2` package is not needed).
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import collections
import datetime
import errno
import ipaddress
import json
import math
import os
import random
import re
import socket
import ssl
import sys
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lt_proto import (H2Conn, LTError, MsgParser, build_msg, chunk, http_request, read_body,  # noqa: E402
                      read_chunk, read_head, status_code, ws_accept, ws_frame, ws_read)

VERSION = 1
TUNNEL_PROTOCOLS = ("ws", "httpupgrade", "grpc", "h2", "xhttp")
DEFAULT_PATHS = {"http": "/bytes/16384", "ws": "/lt-ws", "httpupgrade": "/lt-hu", "grpc": "/lt.Tunnel/Tun",
                 "h2": "/lt-h2", "xhttp": "/lt-xh"}
MAX_CONNECTIONS = 200000

WARNING = (
    "هشدار: این ابزار بار واقعی تولید می‌کند. فقط روی نودی که خودتان مالک/اپراتور آن هستید اجرا کنید؛ "
    "اجرای آن روی زیرساخت دیگران (یا بدون مجوز) ممنوع است.\n"
    "WARNING: pcdn-loadtest generates real load. Run it ONLY against infrastructure you own and operate.")

# Persian explanation for each error kind (summary); the SPEC §15.1 edge category in brackets.
ERROR_FA = {
    "connect_refused": "اتصال TCP رد شد (پورت بسته یا nginx بالا نیست)",
    "connect_timeout": "اتصال TCP در زمان مقرر برقرار نشد (فایروال/backlog پر/شبکه)",
    "tls_timeout": "دست‌دهی TLS در زمان مقرر تمام نشد",
    "tls_verify": "گواهی TLS معتبر نیست یا با Host نمی‌خواند (برای گواهی تستی ‎--ca یا در صورت لزوم ‎--insecure)",
    "tls_error": "خطای TLS",
    "handshake_timeout": "درخواست Upgrade/HTTP2 در زمان مقرر پاسخ نگرفت",
    "protocol": "پاسخ با پروتکل مورد انتظار نمی‌خواند (مسیر/پروتکل تونل اشتباه، ALPN یا 101 نیامد)",
    "closed": "اتصال از سمت مقابل بسته شد",
    "reset": "اتصال reset شد",
    "echo_timeout": "پاسخ echo در زمان ‎--timeout برنگشت (گلوگاه/صف‌شدن در مسیر)",
    "timeout": "مهلت درخواست تمام شد",
    "corrupt": "داده‌ی برگشتی خراب بود",
    "goaway": "سرور HTTP/2 اتصال را با GOAWAY بست",
    "h2_refused_stream": "سرور HTTP/2 استریم را نپذیرفت (حد استریم هم‌زمان)",
    "h2_internal_error": "خطای داخلی HTTP/2 (معمولاً قطع اتصال به origin)",
    "h2_cancel": "استریم HTTP/2 لغو شد",
    "http_400": "۴۰۰ — درخواست نامعتبر [protocol]",
    "http_403": "۴۰۳ — کشور مجاز نیست یا فایروال/IP مسدود [country]",
    "http_404": "۴۰۴ — مسیر تونل/فایل روی سایت تعریف نشده",
    "http_426": "۴۲۶ — مسیر ws/httpupgrade بدون Upgrade [protocol]",
    "http_429": "۴۲۹ — سقف اتصال سایت/IP یا fair share [limit]",
    "http_499": "۴۹۹ — بسته‌شدن از سمت کلاینت",
    "http_502": "۵۰۲ — نود به origin وصل نشد [origin_refused]",
    "http_503": "۵۰۳ — محدودیت یا سرویس در دسترس نیست [limit]",
    "http_504": "۵۰۴ — مهلت اتصال/پاسخ origin [origin_timeout]",
    "client_fd_limit": "سقف فایل‌باز (ulimit -n) روی ماشین کلاینت پر شد — محدودیت کلاینت است نه نود",
    "client_ports": "پورت‌های محلی کلاینت تمام شد (ip_local_port_range) — محدودیت کلاینت است نه نود",
    "unreachable": "مسیر شبکه به هدف وجود ندارد",
    "os_error": "خطای سیستم‌عامل",
    "other": "خطای دیگر",
}


# ----------------------------------------------------------------- statistics

class Hist:
    """Log-bucket latency histogram (1 % resolution, 1 µs .. hours) — exact merge, tiny memory."""

    BASE, LOG = 0.001, math.log(1.01)

    def __init__(self):
        self.b: dict[int, int] = collections.Counter()
        self.n = 0
        self.max = 0.0

    def add(self, ms: float):
        self.b[int(math.log(max(ms, self.BASE) / self.BASE) / self.LOG)] += 1
        self.n += 1
        if ms > self.max:
            self.max = ms

    def pct(self, p: float) -> float | None:
        if not self.n:
            return None
        rank, acc = p / 100 * self.n, 0
        for k in sorted(self.b):
            acc += self.b[k]
            if acc >= rank:
                return min(self.BASE * 1.01 ** (k + 0.5), self.max)
        return self.max

    def summary(self) -> dict:
        r = lambda v: None if v is None else round(v, 2)  # noqa: E731
        return {"n": self.n, "p50": r(self.pct(50)), "p95": r(self.pct(95)), "p99": r(self.pct(99)),
                "max": r(self.max) if self.n else None}

    def raw(self) -> dict:
        return {"b": {str(k): v for k, v in self.b.items()}, "n": self.n, "max": self.max}

    @classmethod
    def from_raw(cls, d: dict) -> "Hist":
        h = cls()
        for k, v in (d or {}).get("b", {}).items():
            h.b[int(k)] += v
        h.n, h.max = (d or {}).get("n", 0), (d or {}).get("max", 0.0)
        return h

    def merge(self, o: "Hist"):
        for k, v in o.b.items():
            self.b[k] += v
        self.n += o.n
        self.max = max(self.max, o.max)


class Stats:
    def __init__(self, active: int = 0):
        self.t0 = time.monotonic()
        self.c: collections.Counter = collections.Counter()
        self.errors: collections.Counter = collections.Counter()
        self.status: collections.Counter = collections.Counter()
        self.cache: collections.Counter = collections.Counter()
        self.rtt, self.connect, self.latency, self.ttfb = Hist(), Hist(), Hist(), Hist()
        self.up = self.down = 0
        self.active_start = active
        self.peak = active
        self.lag_max = 0.0

    def elapsed(self) -> float:
        return max(time.monotonic() - self.t0, 1e-6)

    def mbps(self) -> dict:
        dt = self.elapsed()
        up, down = self.up * 8 / dt / 1e6, self.down * 8 / dt / 1e6
        return {"up": round(up, 3), "down": round(down, 3), "total": round(up + down, 3)}


class Recorder:
    """Fans every observation out to the run total and to any open measurement windows."""

    def __init__(self):
        self.total = Stats()
        self.windows: list[Stats] = []
        self.active = 0

    def window(self) -> Stats:
        s = Stats(self.active)
        self.windows.append(s)
        return s

    def close(self, s: Stats):
        if s in self.windows:
            self.windows.remove(s)

    def _all(self):
        return (self.total, *self.windows)

    def inc(self, key, n=1):
        for s in self._all():
            s.c[key] += n

    def error(self, kind):
        for s in self._all():
            s.errors[kind] += 1

    def hist(self, name, ms):
        for s in self._all():
            getattr(s, name).add(ms)

    def bytes(self, up=0, down=0):
        for s in self._all():
            s.up += up
            s.down += down

    def add_active(self, d):
        self.active += d
        for s in self._all():
            if self.active > s.peak:
                s.peak = self.active

    def http(self, status, cache):
        for s in self._all():
            s.status[str(status)] += 1
            if cache:
                s.cache[cache] += 1


def classify(e: BaseException) -> str:
    if isinstance(e, LTError):
        return e.kind
    if isinstance(e, ssl.SSLCertVerificationError):
        return "tls_verify"
    if isinstance(e, ssl.SSLError):
        return "tls_error"
    if isinstance(e, ConnectionRefusedError):
        return "connect_refused"
    if isinstance(e, (ConnectionResetError, BrokenPipeError, ConnectionAbortedError)):
        return "reset"
    if isinstance(e, asyncio.IncompleteReadError):
        return "closed"
    if isinstance(e, (asyncio.TimeoutError, TimeoutError)):
        return "timeout"
    if isinstance(e, asyncio.LimitOverrunError):
        return "protocol"
    if isinstance(e, OSError):
        if e.errno in (errno.EMFILE, errno.ENFILE):
            return "client_fd_limit"
        if e.errno == errno.EADDRNOTAVAIL:
            return "client_ports"
        if e.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH):
            return "unreachable"
        if e.errno == errno.ETIMEDOUT:
            return "connect_timeout"
        if e.errno == errno.ECONNREFUSED:
            return "connect_refused"
        return "os_error"
    return "other"


# ----------------------------------------------------------------- target / connections

def parse_target(value: str) -> tuple[str, int]:
    m = re.fullmatch(r"\[([0-9a-fA-F:.]+)\]:(\d{1,5})|([0-9.]+):(\d{1,5})", value or "")
    if not m:
        raise ValueError("--target must be IP:port (IPv6 as [addr]:port), e.g. 203.0.113.10:443")
    host, port = (m.group(1), m.group(2)) if m.group(1) else (m.group(3), m.group(4))
    ipaddress.ip_address(host)  # hostnames are refused on purpose: the operator names ONE node
    port = int(port)
    if not 1 <= port <= 65535:
        raise ValueError("port out of range")
    return host, port


class Ctx:
    """Everything a session / worker needs: arguments, recorder, TLS contexts, padding."""

    def __init__(self, a, rec: Recorder):
        self.a, self.rec = a, rec
        self.ip, self.port = parse_target(a.target)
        self.tls = a.tls if a.tls is not None else self.port == 443
        self.pad = os.urandom(max(a.msg_size, 1 << 16))
        self.extra = dict(a.header_dict)
        self._ssl: dict[tuple, ssl.SSLContext] = {}
        self.warnings: list[str] = []
        self.h2pool = H2Pool(self)

    def ssl_ctx(self, alpn: tuple) -> ssl.SSLContext:
        c = self._ssl.get(alpn)
        if c is None:
            c = ssl.create_default_context(cafile=self.a.ca)
            if self.a.insecure:
                c.check_hostname, c.verify_mode = False, ssl.CERT_NONE
            c.set_alpn_protocols(list(alpn))
            self._ssl[alpn] = c
        return c

    def warn(self, msg: str):
        if msg not in self.warnings:
            self.warnings.append(msg)

    async def connect(self, alpn: tuple):
        a = self.a
        try:
            r, w = await asyncio.wait_for(asyncio.open_connection(self.ip, self.port, limit=1 << 20),
                                          a.connect_timeout)
        except (asyncio.TimeoutError, TimeoutError):
            raise LTError("connect_timeout", f"{self.ip}:{self.port}") from None
        sock = w.get_extra_info("socket")
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except (OSError, AttributeError):
            pass
        if self.tls:
            try:
                await asyncio.wait_for(w.start_tls(self.ssl_ctx(alpn), server_hostname=a.host), a.connect_timeout)
            except (asyncio.TimeoutError, TimeoutError):
                w.close()
                raise LTError("tls_timeout") from None
            except BaseException:
                w.close()
                raise
            got = w.get_extra_info("ssl_object").selected_alpn_protocol()
            if alpn == ("h2",) and got != "h2":
                w.close()
                raise LTError("protocol", f"the node did not negotiate HTTP/2 (ALPN {got!r}); "
                                          "gRPC/h2 need a TLS certificate on the site")
        return r, w


async def close_writer(w):
    if w is None:
        return
    try:
        w.close()   # not awaiting wait_closed(): a TLS peer may hold close_notify for a while
    except Exception:
        pass


# ----------------------------------------------------------------- tunnel transports

class Transport:
    grpc_framing = False
    handshake_ms = 0.0

    async def open(self):
        raise NotImplementedError

    async def send(self, data: bytes):
        raise NotImplementedError

    async def recv(self) -> bytes | None:
        raise NotImplementedError

    async def close(self):
        pass


class WsTransport(Transport):
    def __init__(self, ctx: Ctx, idx: int):
        self.ctx, self.r, self.w = ctx, None, None

    async def open(self):
        c = self.ctx
        self.r, self.w = await c.connect(("http/1.1",))
        key = base64.b64encode(os.urandom(16)).decode()
        self.w.write(http_request("GET", c.a.path, c.a.host, dict({
            "Upgrade": "websocket", "Connection": "Upgrade", "Sec-WebSocket-Key": key,
            "Sec-WebSocket-Version": "13"}, **c.extra)))
        await self.w.drain()
        line, h = await read_head(self.r)
        code = status_code(line)
        if code != 101:
            raise LTError(f"http_{code}", line)
        if h.get("sec-websocket-accept") != ws_accept(key):
            raise LTError("protocol", "bad Sec-WebSocket-Accept")

    async def send(self, data):
        self.w.write(ws_frame(data, 2, True))
        await self.w.drain()

    async def recv(self):
        while True:
            op, data = await ws_read(self.r)
            if op == 8:
                return None
            if op == 9:
                self.w.write(ws_frame(data, 10, True))
                continue
            if op in (1, 2):
                return data

    async def close(self):
        if self.w is not None:
            try:
                self.w.write(ws_frame(b"\x03\xe8", 8, True))
            except Exception:
                pass
        await close_writer(self.w)


class HttpUpgradeTransport(Transport):
    def __init__(self, ctx: Ctx, idx: int):
        self.ctx, self.r, self.w = ctx, None, None

    async def open(self):
        c = self.ctx
        self.r, self.w = await c.connect(("http/1.1",))
        self.w.write(http_request("GET", c.a.path, c.a.host,
                                  dict({"Upgrade": "websocket", "Connection": "Upgrade"}, **c.extra)))
        await self.w.drain()
        line, _ = await read_head(self.r)
        code = status_code(line)
        if code != 101:
            raise LTError(f"http_{code}", line)

    async def send(self, data):
        self.w.write(data)
        await self.w.drain()

    async def recv(self):
        d = await self.r.read(1 << 18)
        return d or None

    async def close(self):
        await close_writer(self.w)


class H2Pool:
    """Shares HTTP/2 connections between --streams-per-conn sessions (gRPC multiplexing)."""

    def __init__(self, ctx: Ctx):
        self.ctx = ctx
        self.conns: dict[int, asyncio.Future] = {}
        self.refs: collections.Counter = collections.Counter()

    async def acquire(self, ci: int) -> H2Conn:
        fut = self.conns.get(ci)
        if fut is not None and fut.done() and (fut.cancelled() or fut.exception() or fut.result().error):
            fut = None
        if fut is None:
            fut = asyncio.get_running_loop().create_future()
            self.conns[ci] = fut
            try:
                r, w = await self.ctx.connect(("h2",))
                conn = H2Conn(r, w, client=True)
                await conn.start()
                fut.set_result(conn)
            except BaseException as e:
                fut.set_exception(e if isinstance(e, Exception) else LTError("other", repr(e)))
                fut.exception()
                if self.conns.get(ci) is fut:
                    del self.conns[ci]
                raise
        conn = await asyncio.shield(fut)
        self.refs[ci] += 1
        return conn

    def release(self, ci: int, conn: H2Conn):
        self.refs[ci] -= 1
        if self.refs[ci] <= 0:
            del self.refs[ci]
            fut = self.conns.get(ci)
            if fut is not None and fut.done() and not fut.exception() and fut.result() is conn:
                del self.conns[ci]
            asyncio.create_task(conn.close())


class H2Transport(Transport):
    def __init__(self, ctx: Ctx, idx: int, grpc: bool):
        self.ctx, self.grpc_framing = ctx, grpc
        self.ci = idx // max(1, ctx.a.streams_per_conn)
        self.conn = self.stream = None

    async def open(self):
        c = self.ctx
        self.conn = await c.h2pool.acquire(self.ci)
        mx = self.conn.peer_max_streams
        if mx is not None and c.a.streams_per_conn > mx:
            c.warn(f"--streams-per-conn {c.a.streams_per_conn} is above the node's "
                   f"SETTINGS_MAX_CONCURRENT_STREAMS {mx}")
        hdrs = [(":method", "POST"), (":scheme", "https" if c.tls else "http"), (":path", c.a.path),
                (":authority", c.a.host),
                ("content-type", "application/grpc" if self.grpc_framing else "application/octet-stream"),
                ("te", "trailers"), ("user-agent", "grpc-python/1.60 pcdn-loadtest/1")]
        hdrs += [(k.lower(), v) for k, v in c.extra.items()]
        self.stream = self.conn.open_stream(hdrs)
        await self.conn.drain()
        st = await self.stream.wait_headers()
        if st not in (200, 0):
            raise LTError(f"http_{st}" if st else "protocol", "HTTP/2 response status")
        if self.stream.remote_closed:
            raise LTError("closed", "stream ended right after the response headers")

    async def send(self, data):
        await self.stream.send(data)

    async def recv(self):
        return await self.stream.recv()

    async def close(self):
        if self.stream is not None:
            try:
                self.stream.reset(8)
            except Exception:
                pass
        if self.conn is not None:
            self.ctx.h2pool.release(self.ci, self.conn)
            self.conn = None


class XhttpTransport(Transport):
    """XHTTP over HTTP/1.1: one downlink GET <path>/<sid> (chunked), uplink as packet-up POSTs
    <path>/<sid>/<seq> on a keep-alive connection, or one chunked stream-up POST <path>/<sid>."""

    def __init__(self, ctx: Ctx, idx: int):
        self.ctx = ctx
        self.sid = uuid.uuid4().hex
        self.base = ctx.a.path.rstrip("/")
        self.stream_up = ctx.a.xhttp_mode == "stream-up"
        self.dr = self.dw = self.ur = self.uw = None
        self.seq = 0
        self.chunked = True

    async def _up_conn(self):
        c = self.ctx
        self.ur, self.uw = await c.connect(("http/1.1",))
        if self.stream_up:
            self.uw.write(http_request("POST", f"{self.base}/{self.sid}", c.a.host, dict({
                "X-PCDN-LT": "xhttp-stream", "Transfer-Encoding": "chunked",
                "Content-Type": "application/octet-stream"}, **c.extra)))
            await self.uw.drain()

    async def open(self):
        c = self.ctx
        self.dr, self.dw = await c.connect(("http/1.1",))
        self.dw.write(http_request("GET", f"{self.base}/{self.sid}", c.a.host, dict({
            "X-PCDN-LT": "xhttp", "Accept": "*/*", "Cache-Control": "no-cache"}, **c.extra)))
        await self.dw.drain()
        line, h = await read_head(self.dr)
        code = status_code(line)
        if code != 200:
            raise LTError(f"http_{code}", line)
        self.chunked = "chunked" in h.get("transfer-encoding", "").lower()
        await self._up_conn()

    async def send(self, data):
        c = self.ctx
        if self.stream_up:
            self.uw.write(chunk(data))
            await self.uw.drain()
            return
        if self.uw is None:
            await self._up_conn()
        self.uw.write(http_request("POST", f"{self.base}/{self.sid}/{self.seq}", c.a.host, dict({
            "X-PCDN-LT": "xhttp-packet", "Content-Type": "application/octet-stream"}, **c.extra), body=data))
        self.seq += 1
        await self.uw.drain()
        line, h = await read_head(self.ur)
        code = status_code(line)
        await read_body(self.ur, h, "POST", code)
        if code != 200:
            raise LTError(f"http_{code}", "packet-up POST: " + line)
        if h.get("connection", "").lower() == "close":
            await close_writer(self.uw)
            self.uw = self.ur = None

    async def recv(self):
        if self.chunked:
            return await read_chunk(self.dr)
        d = await self.dr.read(1 << 18)
        return d or None

    async def close(self):
        if self.stream_up and self.uw is not None:
            try:
                self.uw.write(b"0\r\n\r\n")
            except Exception:
                pass
        await close_writer(self.uw)
        await close_writer(self.dw)


def make_transport(ctx: Ctx, proto: str, idx: int) -> Transport:
    if proto == "ws":
        return WsTransport(ctx, idx)
    if proto == "httpupgrade":
        return HttpUpgradeTransport(ctx, idx)
    if proto in ("grpc", "h2"):
        return H2Transport(ctx, idx, grpc=(proto == "grpc"))
    if proto == "xhttp":
        return XhttpTransport(ctx, idx)
    raise ValueError(proto)


# ----------------------------------------------------------------- tunnel sessions

async def sleep_or_stop(stop: asyncio.Event, delay: float) -> bool:
    """Sleep up to `delay`; True when `stop` was set meanwhile."""
    if delay <= 0:
        return stop.is_set()
    try:
        await asyncio.wait_for(stop.wait(), delay)
        return True
    except (asyncio.TimeoutError, TimeoutError):
        return False


async def echo_loop(tr: Transport, ctx: Ctx, stop: asyncio.Event):
    a, rec = ctx.a, ctx.rec
    loop = asyncio.get_running_loop()
    parser = MsgParser(tr.grpc_framing)
    pending: collections.deque = collections.deque()
    sem = asyncio.Semaphore(max(1, a.inflight))
    interval = a.msg_size * 8 / (a.mbps * 1e6) if a.mbps > 0 else 0.0

    async def sender():
        seq, nxt = 0, loop.time() + random.random() * interval  # spread sessions over the interval
        while not stop.is_set():
            await sem.acquire()
            if interval:
                now = loop.time()
                if nxt < now - 1.0:          # fell behind (slow path): do not burst to catch up
                    nxt = now
                if await sleep_or_stop(stop, nxt - now):
                    return
                nxt += interval
            if stop.is_set():
                return
            msg = build_msg(a.msg_size, seq, ctx.pad, tr.grpc_framing)
            pending.append(loop.time())
            try:
                await tr.send(msg)
            except asyncio.CancelledError:
                if pending:              # interrupted by the stop: this one will never be echoed
                    pending.pop()
                raise
            rec.bytes(up=len(msg))
            rec.inc("msgs_sent")
            seq += 1

    async def receiver():
        while True:
            data = await tr.recv()
            if data is None:
                raise LTError("closed", "the tunnel was closed by the other side")
            rec.bytes(down=len(data))
            now_ns = time.monotonic_ns()
            for t_ns, _ in parser.feed(data):
                rec.hist("rtt", (now_ns - t_ns) / 1e6)
                rec.inc("msgs_recv")
                if pending:
                    pending.popleft()
                sem.release()

    async def watchdog():
        while True:
            await asyncio.sleep(0.25)
            if pending and loop.time() - pending[0] > a.timeout:
                raise LTError("echo_timeout", f"no echo for {a.timeout}s")

    tasks = [asyncio.create_task(sender()), asyncio.create_task(receiver()), asyncio.create_task(watchdog())]
    stopper = asyncio.create_task(stop.wait())
    try:
        done, _ = await asyncio.wait(tasks + [stopper], return_when=asyncio.FIRST_COMPLETED)
        for t in done:
            if t is not stopper and not t.cancelled() and t.exception() is not None:
                raise t.exception()
        # stopping: give in-flight messages a moment to come back, then end cleanly
        tasks[0].cancel()
        deadline = loop.time() + min(2.0, a.timeout)
        while pending and loop.time() < deadline and not tasks[1].done():
            await asyncio.sleep(0.05)
    finally:
        for t in tasks + [stopper]:
            t.cancel()
        await asyncio.gather(*tasks, stopper, return_exceptions=True)


async def tunnel_session(ctx: Ctx, proto: str, idx: int, stop: asyncio.Event):
    rec = ctx.rec
    tr = make_transport(ctx, proto, idx)
    rec.inc("opens")
    t0 = time.monotonic()
    try:
        await asyncio.wait_for(tr.open(), ctx.a.handshake_timeout)
    except (asyncio.TimeoutError, TimeoutError):
        rec.inc("open_fail")
        rec.error("handshake_timeout")
        await tr.close()
        return
    except asyncio.CancelledError:
        await tr.close()
        raise
    except Exception as e:
        rec.inc("open_fail")
        rec.error(classify(e))
        await tr.close()
        return
    rec.inc("open_ok")
    rec.hist("connect", (time.monotonic() - t0) * 1000)
    rec.add_active(1)
    try:
        await echo_loop(tr, ctx, stop)
        rec.inc("closed_ok")
    except asyncio.CancelledError:
        raise
    except Exception as e:
        if not stop.is_set():
            rec.inc("dropped")
            rec.error(classify(e))
    finally:
        rec.add_active(-1)
        await tr.close()


async def tunnel_unit(ctx: Ctx, proto: str, idx: int, stop: asyncio.Event):
    """One simulated client: keeps a tunnel session up, reconnecting after 1 s like Xray does."""
    while not stop.is_set():
        await tunnel_session(ctx, proto, idx, stop)
        if stop.is_set() or ctx.a.no_reconnect:
            return
        await sleep_or_stop(stop, 1.0)


# ----------------------------------------------------------------- http scenario

class Pacer:
    def __init__(self, rps: float):
        self.interval = 1.0 / rps if rps and rps > 0 else 0.0
        self.next = time.monotonic()

    async def wait(self, stop: asyncio.Event) -> bool:
        if not self.interval:
            return not stop.is_set()
        now = time.monotonic()
        t = max(self.next, now)
        self.next = t + self.interval
        return not await sleep_or_stop(stop, t - now)


async def http_worker(ctx: Ctx, idx: int, stop: asyncio.Event, pacer: Pacer):
    a, rec = ctx.a, ctx.rec
    r = w = None
    counted = False
    try:
        while not stop.is_set():
            if not await pacer.wait(stop):
                return
            try:
                if w is None:
                    t0 = time.monotonic()
                    r, w = await ctx.connect(("http/1.1",))
                    rec.hist("connect", (time.monotonic() - t0) * 1000)
                    rec.inc("opens")
                    rec.inc("open_ok")
                    rec.add_active(1)
                    counted = True
                path = a.path
                if random.random() < a.miss_ratio:
                    path += ("&" if "?" in path else "?") + "pcdn_lt=" + uuid.uuid4().hex[:16]
                t0 = time.monotonic()
                w.write(http_request("GET", path, a.host, dict({"Accept": "*/*", "Accept-Encoding": "identity"},
                                                               **ctx.extra)))
                await w.drain()

                async def response():
                    line, h = await read_head(r)
                    st = status_code(line)
                    rec.hist("ttfb", (time.monotonic() - t0) * 1000)
                    n = await read_body(r, h, "GET", st)
                    return st, h, n
                st, h, n = await asyncio.wait_for(response(), a.timeout)
                rec.hist("latency", (time.monotonic() - t0) * 1000)
                rec.bytes(down=n)
                rec.inc("requests")
                rec.http(st, h.get("x-cache", "").upper() or None)
                if st >= 400:
                    rec.error(f"http_{st}")
                    rec.inc("req_errors")
                if h.get("connection", "").lower() == "close":
                    raise ConnectionResetError("server closed keep-alive")  # reconnect silently
            except asyncio.CancelledError:
                raise
            except Exception as e:
                quiet = isinstance(e, ConnectionResetError) and str(e) == "server closed keep-alive"
                if not quiet:
                    if w is None:
                        rec.inc("opens")
                        rec.inc("open_fail")
                    else:
                        rec.inc("requests")
                        rec.inc("req_errors")
                    rec.error(classify(e) if not isinstance(e, (asyncio.TimeoutError, TimeoutError)) else "timeout")
                if counted:
                    rec.add_active(-1)
                    counted = False
                await close_writer(w)
                r = w = None
                if not quiet:
                    await sleep_or_stop(stop, 0.2)
    finally:
        if counted:
            rec.add_active(-1)
        await close_writer(w)


# ----------------------------------------------------------------- runner

class Runner:
    def __init__(self, a):
        self.a = a
        self.rec = Recorder()
        self.ctx = Ctx(a, self.rec)
        self.stop = asyncio.Event()
        self.units: list[asyncio.Task] = []
        self.timeline: list[dict] = []
        self.proto = a.protocol if a.scenario == "ramp" else a.scenario
        self.pacer = Pacer(a.rps) if self.proto == "http" else None
        self.t_start = time.monotonic()

    def spawn(self):
        idx = len(self.units)
        if self.proto == "http":
            coro = http_worker(self.ctx, idx, self.stop, self.pacer)
        else:
            coro = tunnel_unit(self.ctx, self.proto, idx, self.stop)
        self.units.append(asyncio.create_task(coro))

    async def spawn_to(self, n: int):
        """Grow to n units at --open-rate per second."""
        rate = max(1.0, self.a.open_rate)
        t0, base = time.monotonic(), len(self.units)
        while len(self.units) < n and not self.stop.is_set():
            due = base + int((time.monotonic() - t0) * rate) + 1
            while len(self.units) < min(n, due):
                self.spawn()
            await asyncio.sleep(0.01)

    async def sampler(self):
        rec, a = self.rec, self.a
        last_up = last_down = last_err = 0
        last_t = time.monotonic()
        while True:
            await asyncio.sleep(1.0)
            now = time.monotonic()
            dt = now - last_t
            lag = max(0.0, (dt - 1.0) * 1000)
            t = rec.total
            err = sum(t.errors.values())
            up = (t.up - last_up) * 8 / dt / 1e6
            down = (t.down - last_down) * 8 / dt / 1e6
            row = {"t": round(now - self.t_start, 1), "active": rec.active, "units": len(self.units),
                   "up_mbps": round(up, 3), "down_mbps": round(down, 3), "errors": err - last_err,
                   "requests": t.c["requests"], "loop_lag_ms": round(lag, 1)}
            self.timeline.append(row)
            for s in rec._all():
                s.lag_max = max(s.lag_max, lag)
            last_up, last_down, last_err, last_t = t.up, t.down, err, now
            if not a.quiet:
                extra = f" req={t.c['requests']}" if self.proto == "http" else ""
                print(f"[{row['t']:>6.0f}s] active={rec.active}/{len(self.units)} up={up:.1f} down={down:.1f} Mbps "
                      f"errors={err}{extra}" + (f" (client loop lag {lag:.0f} ms)" if lag > 100 else ""),
                      file=sys.stderr, flush=True)

    async def finish(self):
        self.stop.set()
        if self.units:
            done, pending = await asyncio.wait(self.units, timeout=self.a.timeout + 5)
            for t in pending:
                t.cancel()
            await asyncio.gather(*self.units, return_exceptions=True)
        await asyncio.sleep(0.1)  # let the closes reach the wire

    # -- scenarios
    async def run_fixed(self) -> dict:
        a = self.a
        n = a.concurrency if self.proto == "http" else a.connections
        smp = asyncio.create_task(self.sampler())
        try:
            await self.spawn_to(n)
            await asyncio.sleep(min(1.0, a.duration / 4))   # let the last sessions finish opening
            steady = self.rec.window()
            steady_from = len(self.timeline)
            await sleep_or_stop(self.stop, a.duration)
            self.rec.close(steady)
            steady_elapsed = steady.elapsed()
            # sessions held during the steady phase (the first sample may still see late opens)
            rows = self.timeline[steady_from + 1:] or self.timeline[steady_from:]
            sustained = min([r["active"] for r in rows] + [self.rec.active])
        finally:
            await self.finish()
            smp.cancel()
        return {"target_connections": n, "steady": steady, "steady_seconds": steady_elapsed,
                "max_sustainable_connections": sustained, "rows": rows}

    async def run_ramp(self) -> dict:
        a = self.a
        smp = asyncio.create_task(self.sampler())
        steps, best, reason = [], None, "max_reached"
        target = a.start
        try:
            while True:
                errw = self.rec.window()
                carried = self.rec.active
                await self.spawn_to(target)
                await asyncio.sleep(min(1.0, a.step_duration / 4))
                latw = self.rec.window()
                await sleep_or_stop(self.stop, a.step_duration)
                self.rec.close(errw)
                self.rec.close(latw)
                st = step_result(len(steps) + 1, target, carried, errw, latw, self.rec.active, self.proto, a)
                steps.append(st)
                if not a.quiet:
                    print(f"  step {st['step']}: target={target} active={st['active']} "
                          f"{st['total_mbps']} Mbps p99={st['p99_ms']} ms err={st['error_rate'] * 100:.2f}% "
                          f"-> {'OK' if st['pass'] else 'FAIL: ' + st['reason']}", file=sys.stderr, flush=True)
                if not st["pass"]:
                    reason = st["reason"]
                    break
                best = st
                if target >= a.max:
                    break
                target = min(a.max, target + a.step)
        finally:
            await self.finish()
            smp.cancel()
        return {"steps": steps, "best": best, "stop_reason": reason}


def step_result(i, target, carried, errw: Stats, latw: Stats, active_end, proto, a) -> dict:
    if proto == "http":
        attempts = max(1, errw.c["requests"] + errw.c["open_fail"])
        errors = errw.c["req_errors"] + errw.c["open_fail"]
        lat = latw.latency
    else:
        attempts = max(1, errw.c["opens"] + carried)
        errors = errw.c["open_fail"] + errw.c["dropped"]
        lat = latw.rtt
    rate = errors / attempts
    p99 = lat.pct(99)
    m = latw.mbps()
    st = {"step": i, "target": target, "active": active_end, "attempts": attempts, "errors": errors,
          "error_rate": round(rate, 5), "errors_by_type": dict(errw.errors),
          "p50_ms": round(lat.pct(50), 2) if lat.n else None, "p95_ms": round(lat.pct(95), 2) if lat.n else None,
          "p99_ms": round(p99, 2) if p99 is not None else None, "samples": lat.n,
          "up_mbps": m["up"], "down_mbps": m["down"], "total_mbps": m["total"],
          "rps": round(errw.c["requests"] / errw.elapsed(), 1) if proto == "http" else None,
          "client_loop_lag_ms": round(latw.lag_max, 1), "pass": True, "reason": None}
    if rate > a.max_error_rate:
        st.update({"pass": False, "reason": "error_rate"})
    elif p99 is None:
        st.update({"pass": False, "reason": "no_samples"})
    elif p99 > a.max_p99_ms:
        st.update({"pass": False, "reason": "p99"})
    elif proto != "http" and active_end < target * (1 - a.max_error_rate) - 0.5:
        st.update({"pass": False, "reason": "sessions_not_held"})
    elif latw.lag_max > a.max_client_lag_ms:
        st.update({"pass": False, "reason": "client_saturated"})
    return st


# ----------------------------------------------------------------- report

def raise_nofile() -> int:
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        if soft < hard:
            resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))
            soft = hard
        return soft
    except (ImportError, ValueError, OSError):
        return -1


def lat_block(s: Stats) -> dict:
    return {"rtt": s.rtt.summary(), "connect": s.connect.summary(), "ttfb": s.ttfb.summary(),
            "request": s.latency.summary()}


def build_report(runner: Runner, out: dict, started: str) -> dict:
    a, rec, ctx = runner.a, runner.rec, runner.ctx
    t = rec.total
    proto = runner.proto
    params = {k: v for k, v in vars(a).items() if k not in ("func", "header_dict")}
    rep = {"tool": "pcdn-loadtest", "version": VERSION, "scenario": a.scenario, "protocol": proto,
           "target": a.target, "host": a.host, "tls": ctx.tls, "started_at": started,
           "duration_s": round(time.monotonic() - runner.t_start, 2), "params": params}
    if proto == "http":
        attempts = max(1, t.c["requests"] + t.c["open_fail"])
        errors = t.c["req_errors"] + t.c["open_fail"]
    else:
        attempts = max(1, t.c["opens"])
        errors = t.c["open_fail"] + t.c["dropped"]
    conns = {"opened": t.c["open_ok"], "open_failed": t.c["open_fail"], "dropped": t.c["dropped"],
             "peak_active": t.peak, "attempts": t.c["opens"]}
    peak_1s = max((r["up_mbps"] + r["down_mbps"] for r in runner.timeline), default=0.0)
    if a.scenario == "ramp":
        best = out["best"]
        msc = best["target"] if best else 0
        thr = ({"up": best["up_mbps"], "down": best["down_mbps"], "total": best["total_mbps"]} if best
               else {"up": 0.0, "down": 0.0, "total": 0.0})
        lat = {"rtt" if proto != "http" else "request": {"p50": best["p50_ms"], "p95": best["p95_ms"],
                                                         "p99": best["p99_ms"]} if best else None}
        rep["steps"] = out["steps"]
        rep["stop_reason"] = out["stop_reason"]
        conns["target"] = out["steps"][-1]["target"] if out["steps"] else 0
    else:
        steady = out["steady"]
        msc = out["max_sustainable_connections"]
        thr = steady.mbps()
        lat = lat_block(steady)
        conns["target"] = out["target_connections"]
        rep["steady_seconds"] = round(out["steady_seconds"], 2)
    thr["peak_1s_total"] = round(peak_1s, 3)
    res = {"max_sustainable_connections": msc, "connections": conns, "throughput_mbps": thr,
           # an echo through the node: the node sends `down` to the client and `up` to the origin,
           # so its NIC tx (what heartbeat tx_mbps / capacity_mbps compare) ~= up + down
           "node_tx_estimate_mbps": round(thr["total"], 3) if proto != "http" else round(thr["down"], 3),
           "latency_ms": lat, "errors": dict(t.errors), "error_rate": round(errors / attempts, 5),
           "messages": {"sent": t.c["msgs_sent"], "echoed": t.c["msgs_recv"]} if proto != "http" else None}
    if proto == "http":
        dur = (out["steady_seconds"] if a.scenario != "ramp" else rep["duration_s"]) or 1
        src = out["steady"] if a.scenario != "ramp" else t
        res["requests"] = {"total": t.c["requests"], "errors": t.c["req_errors"],
                           "rps": round(src.c["requests"] / dur, 1), "status": dict(t.status),
                           "cache": dict(t.cache),
                           "hit_ratio": round(t.cache.get("HIT", 0) / max(1, sum(t.cache.values())), 4)
                           if t.cache else None}
    if a.scenario == "ramp" and out["best"]:
        res["capacity_hint_mbps"] = int(out["best"]["total_mbps"] if proto != "http" else out["best"]["down_mbps"])
    rep["result"] = res
    lag = max((r["loop_lag_ms"] for r in runner.timeline), default=0)
    if lag > 200:
        ctx.warn(f"client event loop lagged up to {lag:.0f} ms: the client machine/process is a bottleneck, "
                 "results are a lower bound (run several processes or client VMs and `merge`)")
    if t.errors.get("client_fd_limit") or t.errors.get("client_ports"):
        ctx.warn("client-side resource limit hit (open files / local ports): raise ulimit -n and "
                 "net.ipv4.ip_local_port_range, or add client IPs/VMs")
    rep["client"] = {"nofile_limit": a._nofile, "python": sys.version.split()[0],
                     "event_loop": a._loop_name, "warnings": ctx.warnings}
    rep["timeline"] = runner.timeline
    rep["raw"] = {"rtt": t.rtt.raw(), "connect": t.connect.raw(), "request": t.latency.raw(), "ttfb": t.ttfb.raw()}
    return rep


def fa_summary(rep: dict) -> str:
    r = rep["result"]
    proto = rep["protocol"]
    L = []
    L.append("══════ خلاصه‌ی آزمون بار pcdn-loadtest ══════")
    L.append(f"سناریو: {rep['scenario']}" + (f" (پروتکل {proto})" if rep["scenario"] == "ramp" else "")
             + f" | هدف: {rep['target']} | Host/SNI: {rep['host']} | TLS: {'بله' if rep['tls'] else 'خیر'}"
             + f" | مدت: {rep['duration_s']:.0f} ثانیه")
    c = r["connections"]
    L.append(f"بیشینه‌ی اتصال پایدار: {r['max_sustainable_connections']} "
             f"(هدف {c.get('target')}, اوج هم‌زمان {c['peak_active']}, باز شده {c['opened']}, "
             f"ناموفق در باز شدن {c['open_failed']}, قطع‌شده {c['dropped']})")
    t = r["throughput_mbps"]
    L.append(f"پهنای باند (Mbps): میانگین کل {t['total']} | بالا (کلاینت→نود) {t['up']} | پایین (نود→کلاینت) "
             f"{t['down']} | اوج ۱ثانیه‌ای {t['peak_1s_total']}")
    L.append(f"برآورد ترافیک خروجی نود (tx): حدود {r['node_tx_estimate_mbps']} Mbps")
    lat = r["latency_ms"] or {}
    key = "rtt" if proto != "http" else "request"
    lab = "تأخیر رفت‌وبرگشت echo" if proto != "http" else "زمان کامل درخواست"
    v = lat.get(key) or {}
    L.append(f"{lab} (ms): p50={v.get('p50')} | p95={v.get('p95')} | p99={v.get('p99')}")
    if lat.get("connect") and lat["connect"].get("n"):
        cc = lat["connect"]
        L.append(f"زمان برقراری اتصال/دست‌دهی (ms): p50={cc['p50']} | p95={cc['p95']} | p99={cc['p99']}")
    if r.get("requests"):
        q = r["requests"]
        L.append(f"درخواست‌ها: {q['total']} | RPS پایدار {q['rps']} | کدها {q['status']}"
                 + (f" | نسبت HIT کش {q['hit_ratio'] * 100:.1f}٪" if q.get("hit_ratio") is not None else ""))
    L.append(f"نرخ خطا: {r['error_rate'] * 100:.3f}٪")
    if r["errors"]:
        L.append("خطاها به تفکیک نوع:")
        for k, n in sorted(r["errors"].items(), key=lambda x: -x[1]):
            L.append(f"  - {k}: {n} — {ERROR_FA.get(k, ERROR_FA['other'] if not k.startswith('http_') else 'کد HTTP غیرموفق')}")
    else:
        L.append("خطا: هیچ")
    if rep["scenario"] == "ramp":
        reasons = {"error_rate": "نرخ خطا از آستانه گذشت", "p99": "p99 تأخیر از آستانه گذشت",
                   "sessions_not_held": "همه‌ی نشست‌ها برقرار نماندند", "max_reached": "به سقف ‎--max رسید",
                   "client_saturated": "ماشین کلاینت اشباع شد (نتیجه کران پایین است)",
                   "no_samples": "هیچ نمونه‌ی تأخیری ثبت نشد"}
        L.append(f"توقف پله‌ها: {reasons.get(rep['stop_reason'], rep['stop_reason'])}")
        for s in rep["steps"]:
            L.append(f"  پله {s['step']}: {s['target']} اتصال | {s['total_mbps']} Mbps | p99={s['p99_ms']} ms | "
                     f"خطا {s['error_rate'] * 100:.2f}٪ | {'قبول' if s['pass'] else 'رد (' + str(s['reason']) + ')'}")
        if r.get("capacity_hint_mbps") is not None:
            L.append(f"پیشنهاد اولیه برای capacity_mbps نود: حدود {r['capacity_hint_mbps']} "
                     "(کمتر از سرعت پورت/قرارداد؛ روش دقیق در docs/LOADTEST.md)")
    for w in rep["client"]["warnings"]:
        L.append(f"⚠ {w}")
    return "\n".join(L)


# ----------------------------------------------------------------- merge

def merge_reports(paths: list[str]) -> dict:
    reps = [json.load(open(p)) for p in paths]
    if not reps:
        raise SystemExit("nothing to merge")
    base = json.loads(json.dumps(reps[0]))
    r = base["result"]
    for o in reps[1:]:
        ro = o["result"]
        r["max_sustainable_connections"] += ro["max_sustainable_connections"]
        for k in r["connections"]:
            if isinstance(r["connections"][k], (int, float)):
                r["connections"][k] += ro["connections"].get(k, 0) or 0
        for k in r["throughput_mbps"]:
            r["throughput_mbps"][k] = round(r["throughput_mbps"][k] + ro["throughput_mbps"].get(k, 0), 3)
        r["node_tx_estimate_mbps"] = round(r["node_tx_estimate_mbps"] + ro["node_tx_estimate_mbps"], 3)
        for k, v in ro["errors"].items():
            r["errors"][k] = r["errors"].get(k, 0) + v
        if r.get("requests") and ro.get("requests"):
            q, qo = r["requests"], ro["requests"]
            q["total"] += qo["total"]
            q["errors"] += qo["errors"]
            q["rps"] = round(q["rps"] + qo["rps"], 1)
            for d in ("status", "cache"):
                for k, v in qo[d].items():
                    q[d][k] = q[d].get(k, 0) + v
        base["client"]["warnings"] += [w for w in o["client"]["warnings"] if w not in base["client"]["warnings"]]
        base["duration_s"] = max(base["duration_s"], o["duration_s"])
    # exact latency percentiles from the raw histograms (whole run of every process)
    for key in ("rtt", "connect", "request", "ttfb"):
        h = Hist()
        for o in reps:
            h.merge(Hist.from_raw(o.get("raw", {}).get(key)))
        base["raw"][key] = h.raw()
        if r.get("latency_ms") is not None and h.n:
            r["latency_ms"][key] = h.summary()
    attempts = sum(max(1, o["result"]["connections"]["attempts"]) for o in reps)
    r["error_rate"] = round(sum(o["result"]["error_rate"] * max(1, o["result"]["connections"]["attempts"])
                                for o in reps) / max(1, attempts), 5)
    base["merged_from"] = len(reps)
    base.pop("timeline", None)
    base.pop("steps", None)
    return base


# ----------------------------------------------------------------- CLI

def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="pcdn-loadtest",
        description="Load-test ONE edge node you own (SPEC §16.1). " + WARNING.split("\n")[1],
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="scenario", required=True)

    def common(p):
        g = p.add_argument_group("target (required, explicit)")
        g.add_argument("--target", help="node address as IP:port (IPv6: [addr]:port). Hostnames are refused.")
        g.add_argument("--host", help="Host header and TLS SNI of a test site on that node")
        tls = g.add_mutually_exclusive_group()
        tls.add_argument("--tls", dest="tls", action="store_true", default=None, help="use TLS (default: port 443)")
        tls.add_argument("--no-tls", dest="tls", action="store_false", help="plain TCP even on 443")
        g.add_argument("--ca", help="CA bundle (PEM) to verify the node certificate (e.g. a test CA)")
        g.add_argument("--insecure", action="store_true",
                       help="do NOT verify the TLS certificate (only for self-signed test certificates)")
        g.add_argument("--header", action="append", default=[], metavar="NAME:VALUE", help="extra request header")
        g.add_argument("--path", help="request / tunnel path (default per scenario, see docs/LOADTEST.md)")
        g.add_argument("--connect-timeout", type=float, default=10.0, help="TCP and TLS timeout each (10 s)")
        g.add_argument("--handshake-timeout", type=float, default=15.0, help="whole session setup timeout (15 s)")
        g.add_argument("--timeout", type=float, default=10.0, help="echo / request timeout (10 s)")
        g.add_argument("--open-rate", type=float, default=200.0, help="new connections per second (200)")
        g.add_argument("--out", help="JSON report file (default pcdn-loadtest-<scenario>-<UTC>.json; '-' = stdout)")
        g.add_argument("--quiet", action="store_true", help="no per-second progress on stderr")

    def tunnel_opts(p, ramp=False):
        g = p.add_argument_group("tunnel sessions")
        if not ramp:
            g.add_argument("--connections", type=int, default=100, help="concurrent tunnel sessions (100)")
            g.add_argument("--duration", type=float, default=30.0, help="steady-state seconds after ramp-up (30)")
        g.add_argument("--mbps", type=float, default=1.0,
                       help="upload rate per session in Mbps, echoed back (1; 0 = as fast as --inflight allows)")
        g.add_argument("--msg-size", type=int, default=16384, help="bytes per message (16384, min 17)")
        g.add_argument("--inflight", type=int, default=8, help="max un-echoed messages per session (8)")
        g.add_argument("--streams-per-conn", type=int, default=1, help="grpc/h2: streams per HTTP/2 connection (1)")
        g.add_argument("--xhttp-mode", choices=("packet-up", "stream-up"), default="packet-up",
                       help="xhttp uplink: POST per packet or one chunked POST (packet-up)")
        g.add_argument("--no-reconnect", action="store_true", help="do not reopen dropped sessions")

    def http_opts(p, ramp=False):
        g = p.add_argument_group("http")
        if not ramp:
            g.add_argument("--concurrency", type=int, default=50, help="keep-alive connections (50)")
            g.add_argument("--duration", type=float, default=30.0, help="steady-state seconds (30)")
        g.add_argument("--rps", type=float, default=0, help="total requests/s cap (0 = as fast as possible)")
        g.add_argument("--miss-ratio", type=float, default=0.1,
                       help="share of requests with a unique query string = cache MISS (0.1)")

    p = sub.add_parser("http", help="cache hit/miss mix over HTTP/1.1")
    common(p)
    http_opts(p)
    for name, hlp in (("ws", "WebSocket tunnel sessions"), ("httpupgrade", "HTTPUpgrade tunnel sessions"),
                      ("grpc", "gRPC (HTTP/2) tunnel streams"), ("h2", "raw HTTP/2 tunnel streams"),
                      ("xhttp", "XHTTP over HTTP/1.1 tunnel sessions")):
        p = sub.add_parser(name, help=hlp)
        common(p)
        tunnel_opts(p)
    p = sub.add_parser("ramp", help="step up connections until errors or p99 cross a threshold")
    common(p)
    g = p.add_argument_group("ramp")
    g.add_argument("--protocol", choices=("http",) + TUNNEL_PROTOCOLS, default="ws", help="what to ramp (ws)")
    g.add_argument("--start", type=int, default=10, help="connections in the first step (10)")
    g.add_argument("--step", type=int, default=10, help="connections added per step (10)")
    g.add_argument("--step-duration", type=float, default=10.0, help="seconds per step (10)")
    g.add_argument("--max", type=int, default=1000, help="stop at this many connections (1000)")
    g.add_argument("--max-error-rate", type=float, default=0.01, help="fail a step above this error rate (0.01)")
    g.add_argument("--max-p99-ms", type=float, default=500.0, help="fail a step above this p99 in ms (500)")
    g.add_argument("--max-client-lag-ms", type=float, default=250.0,
                   help="stop when the client's own event loop lags more (250): the client is the bottleneck")
    tunnel_opts(p, ramp=True)
    http_opts(p, ramp=True)
    p = sub.add_parser("merge", help="merge JSON reports of parallel runs")
    p.add_argument("files", nargs="+")
    p.add_argument("--out", help="merged JSON file ('-' = stdout)")
    return ap


def validate(a, ap):
    if a.scenario == "merge":
        return
    if not a.target:
        print(WARNING, file=sys.stderr)
        ap.error("--target IP:port is required: pcdn-loadtest refuses to run without an explicit target "
                 "(ONE node you own). / بدون ‎--target اجرا نمی‌شود.")
    try:
        parse_target(a.target)
    except ValueError as e:
        print(WARNING, file=sys.stderr)
        ap.error(f"{e} (hostnames are refused on purpose: name the node by its IP)")
    if not a.host:
        ap.error("--host is required (Host header / SNI of a test site on that node)")
    if not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", a.host):
        ap.error("--host must be a plain host name")
    proto = a.protocol if a.scenario == "ramp" else a.scenario
    a.path = a.path or DEFAULT_PATHS[proto]
    if not a.path.startswith("/"):
        ap.error("--path must start with /")
    a.header_dict = {}
    for h in a.header:
        if ":" not in h:
            ap.error(f"--header {h!r}: expected NAME:VALUE")
        k, v = h.split(":", 1)
        a.header_dict[k.strip()] = v.strip()
    if proto != "http":
        if a.msg_size < 17 or a.msg_size > 16 * 1024 * 1024:
            ap.error("--msg-size must be 17 .. 16777216")
        if a.mbps < 0:
            ap.error("--mbps must be >= 0")
    else:
        if not 0 <= a.miss_ratio <= 1:
            ap.error("--miss-ratio must be 0..1")
    # defaults the other branch needs
    for k, v in (("connections", 0), ("concurrency", 0), ("duration", 0), ("msg_size", 16384), ("mbps", 1.0),
                 ("inflight", 8), ("streams_per_conn", 1), ("xhttp_mode", "packet-up"), ("no_reconnect", False),
                 ("rps", 0), ("miss_ratio", 0.1), ("protocol", None)):
        if not hasattr(a, k):
            setattr(a, k, v)
    n = a.max if a.scenario == "ramp" else (a.concurrency if proto == "http" else a.connections)
    if not 1 <= n <= MAX_CONNECTIONS:
        ap.error(f"connections must be 1..{MAX_CONNECTIONS}")
    if a.scenario == "ramp" and (a.start < 1 or a.step < 1 or a.start > a.max):
        ap.error("ramp needs 1 <= --start <= --max and --step >= 1")
    if a.scenario != "ramp" and a.duration <= 0:
        ap.error("--duration must be > 0")


async def run(a) -> dict:
    started = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    runner = Runner(a)
    out = await (runner.run_ramp() if a.scenario == "ramp" else runner.run_fixed())
    return build_report(runner, out, started)


def main(argv=None) -> int:
    ap = build_parser()
    a = ap.parse_args(argv)
    validate(a, ap)
    if a.scenario == "merge":
        rep = merge_reports(a.files)
        text = json.dumps(rep, ensure_ascii=False, indent=1)
        if a.out and a.out != "-":
            with open(a.out, "w") as f:
                f.write(text)
        else:
            print(text)
        print(fa_summary(rep), file=sys.stderr if a.out in (None, "-") else sys.stdout)
        return 0
    print(WARNING, file=sys.stderr)
    a._nofile = raise_nofile()
    a._loop_name = "asyncio"
    try:
        import uvloop  # optional
        a._loop_name = "uvloop"
        rep = uvloop.run(run(a)) if hasattr(uvloop, "run") else None
        if rep is None:
            uvloop.install()
            rep = asyncio.run(run(a))
    except ImportError:
        rep = asyncio.run(run(a))
    text = json.dumps(rep, ensure_ascii=False, indent=1)
    out = a.out or f"pcdn-loadtest-{a.scenario}-{rep['started_at'].replace(':', '')}.json"
    if out == "-":
        print(text)
        print(fa_summary(rep), file=sys.stderr)
    else:
        with open(out, "w") as f:
            f.write(text)
        print(fa_summary(rep))
        print(f"گزارش JSON: {out}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
