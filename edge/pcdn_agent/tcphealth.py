"""TCP health checks of pool members (SPEC §22.4): every origin of a pool whose health.type is "tcp"
(customer pools and the internal "tn.<path id>" pools of multi-origin tunnel paths) gets a TCP connect
every `interval` seconds from a daemon thread of the agent (at most 64 at a time). The consecutive
failure counts are pushed into nginx's pcdn_hc dict through the localhost-only /__pcdn/hc (pcdn.js
hcSet), where pick() reads them exactly like the njs HTTP checks (HC_FALL). If the agent stops, the
entries age out (dict timeout) and a missing entry counts as up: fail open.

The origin guard applies here too: the agent never connects to an address the edge would refuse
(IP literals via origin_hp_allowed, host names via their resolved addresses)."""

import json
import socket
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from .common import _int
from .settings import log
from .validation.origin import origin_host_allowed, origin_hp_allowed

HC_MAX_CONCURRENT = 64
HC_PUSH_MAX_KEYS = 4096
HC_REFRESH = 600     # s: every entry is re-pushed this often (the pcdn_hc dict times out after 3600 s)


def tcp_targets(files: dict) -> list:
    """[[key, host, port, interval, timeout], ...] of the tcp-checked pool members in a rendered tree's
    sites.js (exactly the pools njs sees). key = "<site id>|<pool>|<host:port>" (pcdn.js hcKey)."""
    raw = files.get("js/sites.js") or ""
    try:
        sites = json.loads(raw.split("export default ", 1)[1].rstrip().rstrip(";"))
    except (IndexError, ValueError):
        return []
    out = []
    for sid, js in sorted(sites.items()):
        for name, p in sorted((js.get("pools") or {}).items()):
            h = p.get("health") or {}
            if not h.get("enabled") or h.get("type") != "tcp":
                continue
            for o in p.get("origins") or []:
                hp = str(o.get("hp") or "")
                host, _, port = hp.rpartition(":")
                if not host or not port.isdigit():
                    continue
                out.append([f"{sid}|{name}|{hp}", host.strip("[]"), int(port),
                            _int(h.get("interval"), 10, 1, 3600), _int(h.get("timeout"), 3, 1, 30)])
    return out


def tcp_check(host: str, port: int, timeout: float, cfg: dict, connect=socket.create_connection) -> bool:
    """One TCP connect. Refused by the origin address policy -> counted as a failure, never attempted."""
    if not origin_hp_allowed(f"{host}:{port}", cfg):
        return False
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError:
        return False
    for fam, _, _, _, addr in infos:
        if not origin_host_allowed(addr[0], cfg):
            continue
        try:
            with connect((addr[0], port), timeout=timeout):
                return True
        except OSError:
            continue
    return False


class TcpHealth:
    """The checker thread. set_targets() swaps the target list (after a config sync)."""

    def __init__(self, cfg: dict, push=None):
        self.cfg = cfg
        self.targets: list = []
        self.fails: dict = {}
        self.due: dict = {}
        self.pushed: dict = {}
        self.last_full = 0.0
        self.push = push or self._push
        self.pool = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self.thread = None

    def enabled(self) -> bool:
        return str(self.cfg.get("ORIGIN_TCP_HEALTH") or "yes").lower() in ("1", "yes", "true", "on")

    def set_targets(self, targets: list):
        with self._lock:
            self.targets = [list(t) for t in targets or []]
            keys = {t[0] for t in self.targets}
            for d in (self.fails, self.due, self.pushed):
                for k in list(d):
                    if k not in keys:
                        del d[k]

    def start(self):
        if self.thread is None and self.enabled():
            self.pool = ThreadPoolExecutor(HC_MAX_CONCURRENT, thread_name_prefix="pcdn-hc")
            self.thread = threading.Thread(target=self._loop, name="pcdn-tcphealth", daemon=True)
            self.thread.start()

    def stop(self):
        self._stop.set()

    def _push(self, data: dict) -> bool:
        port = _int(self.cfg.get("HTTP_PORT"), 80, 1, 65535)
        req = urllib.request.Request(f"http://127.0.0.1:{port}/__pcdn/hc", data=json.dumps(data).encode(),
                                     method="POST", headers={"Content-Type": "application/json"})
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=5) as r:
            return r.status == 200

    def step(self, now: float | None = None, check=None) -> dict:
        """Run the due checks (in parallel, <= 64) and push the changed counts (all of them every
        HC_REFRESH s). -> the pushed {key: fails}."""
        now = time.monotonic() if now is None else now
        check = check or (lambda h, p, t: tcp_check(h, p, t, self.cfg))
        with self._lock:
            due = [t for t in self.targets if self.due.get(t[0], 0) <= now]
        if due:
            if self.pool is not None:
                results = list(self.pool.map(lambda t: check(t[1], t[2], t[4]), due))
            else:
                results = [check(t[1], t[2], t[4]) for t in due]
            with self._lock:
                for t, ok in zip(due, results):
                    self.fails[t[0]] = 0 if ok else min(1000, self.fails.get(t[0], 0) + 1)
                    self.due[t[0]] = now + t[3]
        full = now - self.last_full >= HC_REFRESH
        with self._lock:
            out = {k: v for k, v in self.fails.items() if full or self.pushed.get(k) != v}
        if not out:
            return {}
        items = list(out.items())
        try:
            for i in range(0, len(items), HC_PUSH_MAX_KEYS):
                self.push(dict(items[i:i + HC_PUSH_MAX_KEYS]))
        except Exception as e:  # noqa: BLE001 - nginx reloading / njs missing: retried next round
            log.debug("tcp health push: %s", e)
            return {}
        with self._lock:
            self.pushed.update(out)
        if full:
            self.last_full = now
        return out

    def _loop(self):
        while not self._stop.is_set():
            try:
                self.step()
            except Exception as e:  # noqa: BLE001 - never let the checker die
                log.debug("tcp health: %s", e)
            self._stop.wait(1)
