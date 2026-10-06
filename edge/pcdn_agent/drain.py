"""Node drain (SPEC §22.1): the state-file lock shared by the agent loop and the CLI, the node.drain
block of the config, the njs drain flag (localhost /__pcdn/fair?drain=0|1), and the
`pcdn-agent drain` / `undrain` commands (used by install.sh / bootstrap.sh --upgrade --drain).

A drain refuses NEW tunnel connections on this node only after the DNS grace (refuse_after, from the
controller), never touches established sessions or xhttp POSTs, and is a njs flag (no nginx reload).
The flag expires in nginx 180 s after the agent last set it, so a stopped agent fails open."""

import argparse
import contextlib
import fcntl
import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

from .common import _int
from .controller import Controller
from .heartbeat import tcp_established
from .settings import log

DRAIN_STATES = ("draining", "drained")
DRAIN_CHECK_S = 10            # s between drained checks while draining
DRAIN_LAG_S = 120             # a local drain younger than this survives a config that does not show it yet
DRAIN_GRACE_FALLBACK = 330    # s after the start when the controller gave no refuse_after (PROXIED_TTL + 30)
DRAIN_LOG_MAX, DRAIN_LOG_KEEP = 50, 48 * 3600
EXIT_OK, EXIT_ERR, EXIT_LAST_EDGE = 0, 2, 3
LAST_EDGE_MSG = ("this is the last active node of its group; upgrade without --drain\n"
                 "این آخرین نود فعال گروه است؛ بدون --drain به‌روزرسانی کنید")


def iso(ts: float | None) -> str | None:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if ts else None


def parse_iso(v) -> float | None:
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return float(v)
    if not isinstance(v, str) or not v:
        return None
    try:
        dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


# ----------------------------------------------------------------- state file lock

@contextlib.contextmanager
def state_lock(state_file: str):
    """Exclusive lock (STATE_FILE.lock) held by the agent while it saves and by the CLI while it
    rewrites state["drain"]."""
    os.makedirs(os.path.dirname(state_file) or ".", exist_ok=True)
    fd = os.open(state_file + ".lock", os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def _load(path: str) -> dict:
    try:
        with open(path) as f:
            v = json.load(f)
        return v if isinstance(v, dict) else {}
    except (OSError, ValueError):
        return {}


def _save(path: str, state: dict):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f)
        f.flush()
        try:
            os.fsync(f.fileno())
        except OSError:
            pass
    os.replace(tmp, path)


def merge_disk_drain(state: dict, disk: dict) -> bool:
    """Adopt the drain written by the CLI (newer `at`) into the agent's in-memory state."""
    d, cur = disk.get("drain"), state.get("drain")
    if isinstance(d, dict) and float(d.get("at") or 0) > float((cur or {}).get("at") or 0):
        state["drain"] = d
        state.pop("ctl_drain", None)   # the controller's view predates the CLI's call: wait for a fresh one
        return True
    return False


def write_drain(state_file: str, drain: dict) -> dict:
    """CLI side: replace state["drain"] in the state file (only that key) under the lock."""
    drain = dict(drain, at=time.time())
    with state_lock(state_file):
        st = _load(state_file)
        prev = st.get("drain") if isinstance(st.get("drain"), dict) else {}
        if prev.get("state") in DRAIN_STATES and drain.get("state") not in DRAIN_STATES:
            log_drain_end(st, prev, time.time())
        st["drain"] = drain
        _save(state_file, st)
    return drain


def log_drain_end(state: dict, d: dict, now: float):
    """Keep the finished drain's window (start / until / upgrade restart) for §22.12 classification."""
    entry = {"s": d.get("since"), "u": d.get("until"), "r": d.get("restart_at"), "e": iso(now),
             "upgrade": bool(d.get("upgrade"))}
    lg = [x for x in state.get("drain_log") or []
          if isinstance(x, dict) and now - (parse_iso(x.get("e")) or now) <= DRAIN_LOG_KEEP]
    lg.append(entry)
    state["drain_log"] = lg[-DRAIN_LOG_MAX:]


# ----------------------------------------------------------------- config / flag

def norm_drain(config: dict) -> dict | None:
    """node.drain of the config -> {"state", "refuse_after", "until"} (epoch seconds), or None when the
    controller does not send the key (old controller: no drain from there)."""
    n = config.get("node") if isinstance(config.get("node"), dict) else None
    if not n or "drain" not in n:
        return None
    d = n.get("drain") if isinstance(n.get("drain"), dict) else {}
    state = d.get("state") if d.get("state") in DRAIN_STATES else ""
    return {"state": state, "refuse_after": parse_iso(d.get("refuse_after")), "until": parse_iso(d.get("until"))}


def apply_config_drain(state: dict, nd: dict | None, now: float | None = None) -> str | None:
    """Fold the controller's node.drain into state["drain"]. -> "start" / "end" / None (no change)."""
    if nd is None:
        return None
    now = time.time() if now is None else now
    cur = state.get("drain") if isinstance(state.get("drain"), dict) else {}
    active = cur.get("state") in DRAIN_STATES
    if nd["state"] in DRAIN_STATES:
        upd = {"refuse_after": iso(nd["refuse_after"]), "until": iso(nd["until"])}
        if not active:
            state["drain"] = dict(upd, state="draining", since=iso(now), by=cur.get("by") or "admin",
                                  upgrade=False, ok=0, ctl=True, at=now)
            return "start"
        if not cur.get("ctl") or any(cur.get(k) != v for k, v in upd.items() if v):
            # "ctl": the controller has shown this drain, so its disappearance later is an undrain
            state["drain"] = dict(cur, **{k: v for k, v in upd.items() if v}, ctl=True, at=now)
        return None
    if not active:
        return None
    # The controller no longer shows the drain. A drain it HAS shown ends at once (admin / edge undrain,
    # auto-undrain). Only a drain the CLI just started and the controller has not shown yet (config fetched
    # before the POST) survives, for DRAIN_LAG_S after its start - never measured from `at`, which local
    # transitions (drained) bump.
    started = parse_iso(cur.get("since")) or float(cur.get("at") or 0)
    if cur.get("ctl") or now - started > DRAIN_LAG_S:
        end_drain(state, now)
        return "end"
    return None


def end_drain(state: dict, now: float):
    cur = state.get("drain") if isinstance(state.get("drain"), dict) else {}
    if cur.get("state") in DRAIN_STATES:
        log_drain_end(state, cur, now)
    state["drain"] = {"state": "", "at": now}


def refuse_now(d: dict, now: float) -> bool:
    """The DNS grace is over: new connections are refused (flag on)."""
    if not isinstance(d, dict) or d.get("state") not in DRAIN_STATES:
        return False
    ra = parse_iso(d.get("refuse_after"))
    if ra is None:
        ra = (parse_iso(d.get("since")) or now) + DRAIN_GRACE_FALLBACK
    return now >= ra


def set_flag(cfg: dict, on: bool, opener=None) -> bool:
    """/__pcdn/fair?drain=0|1 on the localhost default server (pcdn.js fairSet); True when nginx took it."""
    port = _int(cfg.get("HTTP_PORT"), 80, 1, 65535)
    opener = opener or urllib.request.build_opener(urllib.request.ProxyHandler({})).open
    try:
        with opener(f"http://127.0.0.1:{port}/__pcdn/fair?drain={1 if on else 0}", timeout=2) as r:
            return 200 <= r.status < 300
    except (OSError, urllib.error.URLError, ValueError):
        return False


def public_conns(cfg: dict) -> int:
    """ESTABLISHED client connections on the public ports (the metrics.connections source)."""
    ports = {_int(cfg.get("HTTP_PORT"), 80, 1, 65535), _int(cfg.get("HTTPS_PORT"), 443, 1, 65535)}
    return tcp_established(ports, cfg.get("PROC_TCP", ("/proc/net/tcp", "/proc/net/tcp6"))) or 0


def drained_check(d: dict, conns: int, idle_max: int, now: float) -> bool:
    """One drained check: 2 consecutive checks at or below DRAIN_IDLE_CONNS, or `until` reached.
    Updates d["ok"] / d["conns"]; True when the drain is now complete."""
    d["conns"] = conns
    d["ok"] = int(d.get("ok") or 0) + 1 if conns <= idle_max else 0
    until = parse_iso(d.get("until"))
    return d["ok"] >= 2 or (until is not None and now >= until)


def heartbeat_drain(d, conns: int) -> dict:
    d = d if isinstance(d, dict) else {}
    st = d.get("state") if d.get("state") in DRAIN_STATES else ""
    return {"state": st, "conns": int(conns or 0), "since": d.get("since") if st else None}


# ----------------------------------------------------------------- CLI

def _ctl_error(e) -> tuple[int, str]:
    if isinstance(e, urllib.error.HTTPError):
        detail = ""
        try:
            body = json.loads(e.read() or b"{}")
            detail = str(body.get("detail") or "") if isinstance(body, dict) else ""
        except (ValueError, OSError):
            pass
        if e.code == 409 and detail == "last_edge":
            return EXIT_LAST_EDGE, LAST_EDGE_MSG
        if e.code == 404:
            return EXIT_ERR, "the controller has no drain endpoint (older controller): continuing without drain"
        return EXIT_ERR, f"controller answered HTTP {e.code}{': ' + detail if detail else ''}"
    return EXIT_ERR, f"controller not reachable: {type(e).__name__}"


def drain_main(cfg: dict, argv: list, ctl=None, sleep=time.sleep, out=sys.stdout, now=time.time) -> int:
    """`pcdn-agent drain --minutes N [--reason R] [--wait] [--timeout S]`. Exit 0 when the drain started
    (with --wait: when drained or `until` / the timeout was reached), 3 on last_edge, 2 on other errors."""
    ap = argparse.ArgumentParser(prog="pcdn-agent drain", description="Drain this edge node (SPEC §22.1): "
                                 "DNS stops sending clients here, then new tunnel connections are refused.")
    ap.add_argument("--minutes", type=int, default=15, help="1..120 (default 15)")
    ap.add_argument("--reason", default="admin", help="short reason (\"upgrade\" = auto-undrain after the upgrade)")
    ap.add_argument("--wait", action="store_true", help="wait until drained (prints the connections every 10 s)")
    ap.add_argument("--timeout", type=int, default=None, help="seconds to wait at most (default minutes*60+60)")
    args = ap.parse_args(argv)
    if not 1 <= args.minutes <= 120:
        print("drain: --minutes must be 1..120", file=out)
        return EXIT_ERR
    reason = "".join(c for c in str(args.reason) if c.isprintable())[:64] or "admin"
    if ctl is None:
        if not cfg.get("CONTROLLER_URL") or not cfg.get("EDGE_TOKEN"):
            print("drain: CONTROLLER_URL and EDGE_TOKEN must be set in /etc/pcdn/agent.conf", file=out)
            return EXIT_ERR
        ctl = Controller(cfg["CONTROLLER_URL"], cfg["EDGE_TOKEN"])
    try:
        _, _, body = ctl.call("POST", "/edge/v1/drain", {"action": "start", "minutes": args.minutes, "reason": reason},
                              timeout=30)
    except (urllib.error.URLError, OSError, ValueError) as e:
        code, msg = _ctl_error(e)
        print(f"drain: {msg}", file=out)
        return code
    body = body if isinstance(body, dict) else {}
    t0 = now()
    prev = _load(cfg["STATE_FILE"]).get("drain")
    prev = prev if isinstance(prev, dict) and prev.get("state") in DRAIN_STATES else None
    d = {"state": "draining", "since": iso(t0), "until": body.get("until") or iso(t0 + args.minutes * 60),
         "refuse_after": body.get("refuse_after"), "by": "edge", "upgrade": reason == "upgrade", "ok": 0}
    if prev and prev.get("by") != "edge":   # an admin drain in progress is extended, never auto-undrained
        d.update(since=prev.get("since") or d["since"], by=prev.get("by") or "admin", upgrade=False)
    write_drain(cfg["STATE_FILE"], d)
    print(f"drain: started (until {d['until']}, new tunnel connections refused from "
          f"{d['refuse_after'] or 'the DNS grace'})", file=out)
    if not args.wait:
        return EXIT_OK
    timeout = args.timeout if args.timeout is not None else args.minutes * 60 + 60
    deadline = t0 + max(1, timeout)
    idle = _int(cfg.get("DRAIN_IDLE_CONNS"), 10, 0, 100000)
    while True:
        t = now()
        if refuse_now(d, t):
            set_flag(cfg, True)
        conns = public_conns(cfg)
        print(f"drain: connections {conns}", file=out, flush=True)
        if drained_check(d, conns, idle, t):
            d["state"] = "drained"
            write_drain(cfg["STATE_FILE"], d)
            print("drain: drained", file=out)
            return EXIT_OK
        if t >= deadline:
            print("drain: timeout reached; continuing (remaining sessions follow the graceful reload)", file=out)
            return EXIT_OK
        sleep(DRAIN_CHECK_S)


def undrain_main(cfg: dict, argv: list, ctl=None, out=sys.stdout) -> int:
    """`pcdn-agent undrain`: POST action stop, clear the local flag and state. 0 ok, 2 controller error
    (the local drain is cleared anyway)."""
    ap = argparse.ArgumentParser(prog="pcdn-agent undrain", description="End this node's drain (SPEC §22.1).")
    ap.parse_args(argv)
    rc = EXIT_OK
    try:
        if ctl is None:
            ctl = Controller(cfg["CONTROLLER_URL"], cfg["EDGE_TOKEN"])
        ctl.call("POST", "/edge/v1/drain", {"action": "stop"}, timeout=30)
    except (urllib.error.URLError, OSError, ValueError, KeyError) as e:
        rc, msg = _ctl_error(e)
        rc = EXIT_ERR
        print(f"undrain: {msg}", file=out)
    write_drain(cfg["STATE_FILE"], {"state": ""})
    set_flag(cfg, False)
    print("undrain: done" if rc == EXIT_OK else "undrain: local drain cleared", file=out)
    log.info("drain ended by pcdn-agent undrain")
    return rc
