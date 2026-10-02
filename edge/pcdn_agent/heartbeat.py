"""Heartbeat data (SPEC §7.4, §14.1): node metrics (traffic, connections, workers, disk, memory)
and the capabilities object."""

import os
import time

from .capabilities import guard_installed, image_capabilities, l4_ready, nginx_capabilities
from .common import VIRTUAL_IFACES, _int, default_iface
from .functions import functions_ready
from .render.stream import l4_port_range
from .settings import log
from .validation.rules import WAF_PACK_VERSIONS


def heartbeat_capabilities(cfg: dict) -> dict:
    """The `capabilities` object of the heartbeat (SPEC §14.1)."""
    c = nginx_capabilities(cfg)
    return {"http3": bool(c["http3"]), "early_hints": bool(c["early_hints"]),
            "webp_convert": bool(c["webp_convert"]), "webp_mode": c["webp_mode"],
            "modules": list(c["modules"]), "nginx": c["nginx"],
            "waf_packs": dict(WAF_PACK_VERSIONS),   # SPEC §14.2 managed rule-set versions
            # SPEC §14.3: this agent sends 1-minute `live` aggregates + platform_errors with its usage
            # and ships sampled access-log records to /edge/v1/logship
            "live_analytics": True, "logship": True,
            # SPEC §16.3-§16.6 (wave 8)
            "l4": l4_ready(cfg), "l4_port_range": "%d-%d" % l4_port_range(cfg),
            "slice": bool(c.get("slice")), "video": True,
            "avif": image_capabilities(cfg)["avif"], "image_transform": image_capabilities(cfg)["transform"],
            "net_guard": guard_installed(cfg),
            # SPEC §16.9: true only while pcdn-fn runs and its sandbox self-test passes
            "edge_functions": functions_ready(cfg)}


def net_bytes(iface: str | None, dev_path: str = "/proc/net/dev") -> tuple[int, int] | None:
    """(rx, tx) bytes of iface, or of every non-virtual interface when iface is None."""
    rx = tx = 0
    found = False
    try:
        with open(dev_path) as f:
            for line in f:
                if ":" not in line:
                    continue
                name, data = line.split(":", 1)
                name, p = name.strip(), data.split()
                if (iface and name != iface) or (not iface and VIRTUAL_IFACES.match(name)) or len(p) < 9:
                    continue
                rx, tx, found = rx + int(p[0]), tx + int(p[8]), True
    except (OSError, ValueError):
        return None
    return (rx, tx) if found else None


def tcp_established(ports, paths=("/proc/net/tcp", "/proc/net/tcp6")) -> int | None:
    """ESTABLISHED TCP connections whose local port is one of `ports` (client connections)."""
    want = {f"{int(p):04X}" for p in ports}
    n, ok = 0, False
    for path in paths:
        try:
            with open(path) as f:
                ok = True
                next(f, None)
                for line in f:
                    p = line.split(None, 4)
                    if len(p) > 3 and p[3] == "01" and p[1].rsplit(":", 1)[-1] in want:
                        n += 1
        except (OSError, ValueError):
            continue
    return n if ok else None


def net_sample(cfg: dict) -> tuple[float, tuple[int, int] | None]:
    return time.monotonic(), net_bytes(default_iface(cfg.get("PROC_ROUTE", "/proc/net/route")),
                                       cfg.get("PROC_NET_DEV", "/proc/net/dev"))


def count_draining_workers(proc: str = "/proc") -> int:
    """Count nginx worker processes still draining after a reload (F5/F6). Each reload leaves a
    generation pinned by long-lived tunnels; too many means reloads are outpacing shutdown, which
    the agent uses for reload back-pressure and reports in the heartbeat."""
    n = 0
    try:
        for pid in os.listdir(proc):
            if not pid.isdigit():
                continue
            try:
                with open(os.path.join(proc, pid, "cmdline"), "rb") as f:
                    if b"worker process is shutting down" in f.read():
                        n += 1
            except OSError:
                continue
    except OSError:
        return 0
    return n


def sockstat_counts(path: str = "/proc/net/sockstat") -> tuple[int, int]:
    """(TCP inuse, TIME_WAIT) from /proc/net/sockstat (F18). O(1); used to watch outbound ephemeral
    port pressure toward origins. (0, 0) on error."""
    try:
        with open(path) as f:
            for line in f:
                if line.startswith("TCP:"):
                    p = line.split()
                    d = {p[i]: int(p[i + 1]) for i in range(1, len(p) - 1, 2) if p[i + 1].lstrip("-").isdigit()}
                    return d.get("inuse", 0), d.get("tw", 0)
    except (OSError, ValueError, IndexError):
        pass
    return 0, 0


def collect_metrics(cfg: dict, prev: tuple | None, cur: tuple | None = None) -> dict:
    """Heartbeat metrics from two net samples (see net_sample). Never raises; missing values are 0."""
    m = {"rx_mbps": 0.0, "tx_mbps": 0.0, "connections": 0, "load1": 0.0, "cpus": 0}
    try:
        cur = cur or net_sample(cfg)
        if prev and prev[1] and cur[1] and cur[0] > prev[0]:
            dt = cur[0] - prev[0]
            m["rx_mbps"] = round(max(0, cur[1][0] - prev[1][0]) * 8 / dt / 1e6, 3)  # counter reset -> 0
            m["tx_mbps"] = round(max(0, cur[1][1] - prev[1][1]) * 8 / dt / 1e6, 3)
    except Exception as e:  # noqa: BLE001
        log.debug("net metrics: %s", e)
    try:
        ports = {_int(cfg.get("HTTP_PORT"), 80, 1, 65535), _int(cfg.get("HTTPS_PORT"), 443, 1, 65535)}
        m["connections"] = tcp_established(ports, cfg.get("PROC_TCP", ("/proc/net/tcp", "/proc/net/tcp6"))) or 0
    except Exception as e:  # noqa: BLE001
        log.debug("connection count: %s", e)
    try:
        m["load1"] = round(os.getloadavg()[0], 2)
    except (OSError, AttributeError):
        pass
    m["cpus"] = os.cpu_count() or 0
    disk = disk_pct(cfg.get("CACHE_DIR") or cfg.get("NGINX_DIR") or "/")
    if disk is not None:
        m["disk_pct"] = disk
    mem = mem_pct(cfg.get("PROC_MEMINFO", "/proc/meminfo"))
    if mem is not None:
        m["mem_pct"] = mem
    try:
        m["draining_workers"] = count_draining_workers(cfg.get("PROC_DIR", "/proc"))  # F5/F6
    except Exception as e:  # noqa: BLE001
        log.debug("draining workers: %s", e)
    try:
        tcp_inuse, tw = sockstat_counts(cfg.get("PROC_SOCKSTAT", "/proc/net/sockstat"))  # F18
        m["sock_tcp"], m["sock_tw"] = tcp_inuse, tw
        lo, hi = 10240, 65535  # default ephemeral range (not widened; F18 is monitoring-only)
        rng = cfg.get("PORT_RANGE")
        if isinstance(rng, (tuple, list)) and len(rng) == 2:
            lo, hi = int(rng[0]), int(rng[1])
        span = max(1, hi - lo + 1)
        if tcp_inuse + tw > 0.7 * span:
            log.warning("ephemeral TCP usage high: inuse=%d tw=%d (>70%% of %d)", tcp_inuse, tw, span)
    except Exception as e:  # noqa: BLE001
        log.debug("sockstat: %s", e)
    return m


def disk_pct(path: str) -> float | None:
    """Percent of the filesystem holding `path` that is used. None on error."""
    try:
        st = os.statvfs(path)
        total = st.f_blocks * st.f_frsize
        if total <= 0:
            return None
        free = st.f_bavail * st.f_frsize
        return round((total - free) * 100 / total, 1)
    except OSError:
        return None


def mem_pct(meminfo: str = "/proc/meminfo") -> float | None:
    """Percent of RAM in use (total - available). None on error."""
    try:
        vals = {}
        with open(meminfo) as f:
            for line in f:
                k, _, rest = line.partition(":")
                if k in ("MemTotal", "MemAvailable"):
                    vals[k] = int(rest.split()[0])  # kB
        total, avail = vals.get("MemTotal", 0), vals.get("MemAvailable")
        if total <= 0 or avail is None:
            return None
        return round((total - avail) * 100 / total, 1)
    except (OSError, ValueError, IndexError):
        return None
