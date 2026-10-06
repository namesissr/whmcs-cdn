"""Heartbeat data (SPEC §7.4, §14.1): node metrics (traffic, connections, workers, disk, memory)
and the capabilities object."""

import os
import signal
import time
from datetime import datetime, timezone

from .capabilities import guard_installed, image_capabilities, l4_ready, nginx_capabilities, self_upgrade_capable
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
            "edge_functions": functions_ready(cfg),
            # SPEC §22 (wave 13): node drain flag, synthetic tunnel probe, multi-origin tunnel paths and
            # re-resolved keepalive upstreams for host-name origins (nginx >= 1.27.3)
            "drain": True, "tunnel_probe": True, "tunnel_multi_origin": True,
            "upstream_resolve": bool(c.get("upstream_resolve")),
            # SPEC §23 (wave 14): node.upgrade handled (SELF_UPGRADE=no / no systemd-run -> false: rollouts
            # treat the node as manual); RUM beacons served and aggregated (needs njs for the ingestion)
            "self_upgrade": self_upgrade_capable(cfg), "rum": "njs" in c["modules"]}


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


# ----------------------------------------------------------------- reload metrics (SPEC §22.2)

RELOAD_TIMES_MAX, RELOAD_KEEP_S = 500, 48 * 3600
FORCED_MAX = 200


def _iso(ts: float | None) -> str | None:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if ts else None


def prune_times(times: list, keep_s: int, cap: int, now: float) -> list:
    """Epoch timestamps of the last keep_s seconds, at most cap (newest kept)."""
    out = [t for t in times or [] if isinstance(t, (int, float)) and now - t <= keep_s]
    return out[-cap:]


def reload_stats(state: dict, wst_s: int | None, now: float | None = None, mono: float | None = None) -> dict:
    """The heartbeat `reloads` object: successful reloads in the last hour / day, the last one, config
    versions superseded before being applied (coalesced) in the last hour, the age of the pending
    version, whether a reload is being deferred, worker_shutdown_timeout and forced worker shutdowns."""
    now = time.time() if now is None else now
    mono = time.monotonic() if mono is None else mono
    rt = [t for t in state.get("reload_times") or [] if isinstance(t, (int, float))]
    co = [t for t in state.get("coalesced_times") or [] if isinstance(t, (int, float))]
    fs = [f.get("t") for f in state.get("forced_shutdowns") or [] if isinstance(f, dict)]
    pending = 0
    if state.get("pending_version") and isinstance(state.get("pending_first", state.get("pending_since")), (int, float)):
        pending = max(0, int(mono - state.get("pending_first", state.get("pending_since"))))
    return {"count_1h": sum(1 for t in rt if now - t <= 3600), "count_24h": sum(1 for t in rt if now - t <= 86400),
            "last_at": _iso(max(rt)) if rt else None, "coalesced_1h": sum(1 for t in co if now - t <= 3600),
            "pending_s": pending, "deferred": bool(state.get("reload_deferred")),
            "wst_s": wst_s, "forced_shutdowns_24h": sum(1 for t in fs if isinstance(t, (int, float)) and now - t <= 86400)}


# ----------------------------------------------------------------- memory guard (SPEC §22.2)

def shutting_down_workers(proc: str = "/proc") -> list[tuple[int, int]]:
    """[(start time in clock ticks, pid)] of nginx workers of OLD generations ("worker process is
    shutting down"), oldest first. Never the master or a current-generation worker."""
    out = []
    try:
        names = os.listdir(proc)
    except OSError:
        return out
    for pid in names:
        if not pid.isdigit():
            continue
        try:
            with open(os.path.join(proc, pid, "cmdline"), "rb") as f:
                if b"worker process is shutting down" not in f.read():
                    continue
            with open(os.path.join(proc, pid, "stat")) as f:
                stat = f.read()
            # field 22 (starttime) counted after the ")" that closes the command name
            start = int(stat.rsplit(")", 1)[1].split()[19])
        except (OSError, ValueError, IndexError):
            continue
        out.append((start, int(pid)))
    return sorted(out)


def _still_shutting_down(proc: str, pid: int) -> bool:
    """True while `pid` is still an nginx worker of an old generation (so a recycled pid is never hit)."""
    try:
        with open(os.path.join(proc, str(pid), "cmdline"), "rb") as f:
            return b"worker process is shutting down" in f.read()
    except OSError:
        return False


def memory_guard(state: dict, cfg: dict, mem: float | None, now: float | None = None, kill=os.kill) -> int | None:
    """Called once per heartbeat. When mem_pct >= MEM_GUARD_PCT for 2 consecutive heartbeats and old
    worker generations are still draining, SIGTERM the oldest shutting-down worker (at most one per 60 s)
    and record it in state["forced_shutdowns"] (session-end classification). -> the pid or None.

    From MEM_GUARD_HARD_PCT up the node is minutes away from the OOM killer, which does not pick the
    worker the guard would: it can take the master instead, and with it every tunnel on the node (plus
    a pid file nothing rewrites, so no later reload works either). So above that line the guard acts on
    the FIRST heartbeat, without the 60 s cooldown, on up to MEM_GUARD_MAX_KILLS of the oldest
    generations at once, and SIGKILLs a worker that ignored its SIGTERM for MEM_GUARD_KILL_GRACE_S."""
    now = time.time() if now is None else now
    pct = _int(cfg.get("MEM_GUARD_PCT"), 92, 0, 99)
    if pct and pct < 50:
        pct = 50
    if not pct or mem is None or mem < pct:
        state["mem_high"] = 0
        return None
    hard = _int(cfg.get("MEM_GUARD_HARD_PCT"), 97, 0, 99)
    critical = bool(hard) and mem >= max(pct, hard)
    state["mem_high"] = int(state.get("mem_high") or 0) + 1
    if not critical and (state["mem_high"] < 2 or now - float(state.get("mem_guard_at") or 0) < 60):
        return None
    proc = cfg.get("PROC_DIR", "/proc")
    victims = shutting_down_workers(proc)
    fs = [f for f in state.get("forced_shutdowns") or [] if isinstance(f, dict) and now - f.get("t", 0) <= RELOAD_KEEP_S]
    killed = None
    if critical:   # a worker that ignored its SIGTERM holds its memory until worker_shutdown_timeout
        grace = _int(cfg.get("MEM_GUARD_KILL_GRACE_S"), 60, 5, 3600)
        for f in fs:
            pid = f.get("pid")
            if f.get("sig") == "kill" or not isinstance(pid, int) or now - f.get("t", 0) < grace:
                continue
            if not _still_shutting_down(proc, pid):
                continue
            try:
                kill(pid, signal.SIGKILL)
            except OSError as e:
                log.warning("memory guard: cannot SIGKILL old nginx worker %d: %s", pid, e)
                continue
            f["sig"] = "kill"
            killed = killed or pid
            log.warning("memory guard: memory at %.1f %% (critical): SIGKILLed old nginx worker %d, which had "
                        "not stopped %.0f s after SIGTERM", mem, pid, now - f.get("t", 0))
    done = {f.get("pid") for f in fs if isinstance(f.get("pid"), int)}
    want = _int(cfg.get("MEM_GUARD_MAX_KILLS"), 3, 1, 32) if critical else 1
    for _start, pid in victims:
        if want <= 0:
            break
        if pid in done:   # already SIGTERMed (and SIGKILLed above once the grace passed)
            continue
        try:
            kill(pid, signal.SIGTERM)
        except OSError as e:
            log.warning("memory guard: cannot stop old nginx worker %d: %s", pid, e)
            continue
        log.warning("memory guard: memory at %.1f %% (>= %d %%): stopped the oldest shutting-down nginx worker %d",
                    mem, pct, pid)
        state["mem_guard_at"] = now
        fs.append({"t": now, "pid": pid, "sig": "term"})
        killed = killed or pid
        want -= 1
    state["forced_shutdowns"] = fs[-FORCED_MAX:]
    return killed
