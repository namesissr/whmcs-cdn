"""Usage accounting from the access log: per-host hourly usage, security events, tunnel quality
(SPEC §15.1), live minute aggregates (SPEC §14.3.1), platform errors and L4 usage (SPEC §16.4)."""

import json
import os
import re
import time
from datetime import datetime, timezone

from .common import EVENT_BACKLOG, PATHS_PER_ITEM, PATH_TRACK, SAFE_ID, SAFE_NAME, TUNNEL_PROTOCOLS
from .settings import log
from .validation.rules import norm_video


# ----------------------------------------------------------------- usage

def _utc(ts: str) -> datetime:
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def floor_hour(ts: str) -> str:
    return _utc(ts).replace(minute=0, second=0, microsecond=0).strftime("%Y-%m-%dT%H:00:00Z")


_TS_MEMO: list = [None, None]   # last access-log timestamp -> (UTC datetime, hour key, minute key)


def _times(ts: str) -> tuple:
    """(UTC datetime, "YYYY-MM-DDTHH:00:00Z", "YYYY-MM-DDTHH:MM:00Z") of an access-log timestamp,
    memoised for the last value (consecutive lines mostly share a second)."""
    if _TS_MEMO[0] == ts:
        return _TS_MEMO[1]
    dt = _utc(ts)
    v = (dt, dt.strftime("%Y-%m-%dT%H:00:00Z"), dt.strftime("%Y-%m-%dT%H:%M:00Z"))
    _TS_MEMO[0], _TS_MEMO[1] = ts, v
    return v


CACHE_SERVED = ("HIT", "STALE", "UPDATING", "REVALIDATED")
SECURITY_ACTIONS = ("block", "challenge", "captcha")
# 5xx answers nginx gives to a malformed / unsupported CLIENT request (unknown transfer coding or
# method, bad HTTP version): client-triggerable, so they never count against the platform
CLIENT_5XX = (501, 505)


def platform_error(e: dict) -> bool:
    """SPEC §14.3.1 `platform_errors`: is this access-log record a 5xx the edge produced itself?

    Counted only when ALL of these hold:
      * status 500..599, except 501 / 505 (nginx's answer to an unsupported client request: the
        visitor can trigger it at will, so it says nothing about the platform);
      * the record carries the "us" field (a pre-6D log line without it is never counted: no
        evidence either way) and it is empty: no upstream was contacted. Any value - "502" (origin
        connect failure / bad gateway), "504" (origin timeout), "-" (upstream state without a
        status), "502, 200" (several attempts) - means the origin was involved: an origin error;
      * the response was not served from the cache (HIT / STALE / UPDATING / REVALIDATED: content
        the origin produced earlier);
      * no security action: the verdict "v" is not block / challenge / captcha (WAF, firewall,
        rate-limit, DDoS, bot, hotlink decisions are the customer's settings, not errors; "log:..."
        verdicts are not actions);
      * it is not the suspended / over-quota page of the site ("pg" = "site": the site's own status).
    What remains: e.g. njs or internal nginx failures (500), an origin hostname that the edge's
    resolver could not resolve (502, nginx records no upstream for it - the SPEC rule counts it),
    and a customer error page served for such an edge-produced 5xx."""
    try:
        code = int(e.get("s") or 0)
    except (TypeError, ValueError):
        return False
    if code < 500 or code > 599 or code in CLIENT_5XX:
        return False
    if "us" not in e or str(e.get("us") or "").strip():
        return False
    if e.get("c") in CACHE_SERVED:
        return False
    if str(e.get("v") or "ok").split(":", 1)[0] in SECURITY_ACTIONS:
        return False
    return not e.get("pg")


# ---- tunnel quality (SPEC §15.1)
TUNNEL_ERRORS = ("origin_refused", "origin_timeout", "origin_error", "limit", "country", "protocol", "edge")
ORIGIN_DOWN_ERRORS = ("origin_refused", "origin_timeout")   # SPEC §15.4 live `tunnel_errors`
TUNNEL_PATHS_MAX = 50                                         # path ids per host-hour
_ACCEPTED = re.compile(r"^(?:101|2\d\d)$")
_LIST_SPLIT = re.compile(r"\s*[,:]\s*")


def _last_value(v) -> str:
    """Last entry of an nginx per-attempt list ("502, 101", "0.001 : -"); "" when empty."""
    parts = [x for x in _LIST_SPLIT.split(str(v or "").strip()) if x]
    return parts[-1] if parts else ""


def classify_tunnel(e: dict) -> str | None:
    """Outcome of one tunnel access-log line (tn set): "session", one of TUNNEL_ERRORS, or None
    (not counted either way). Rules, first match wins - pinned against real nginx 1.24 output in
    test_tunnel_quality_e2e.py ($status / $upstream_status "us" / $upstream_connect_time "uct"):

      1. grpc path over HTTP/1.x ("pr" HTTP/1.0/1.1)       -> protocol (a gRPC client is always HTTP/2;
                                                              nginx still forwards it, so the status
                                                              alone cannot tell)
      2. status 101 or 2xx                                 -> session
      3. status 499 and the last us is 101/2xx             -> session (client closed an accepted stream:
                                                              a clean end, never abnormal)
         status 499 otherwise                              -> None (client gave up first, e.g. while the
                                                              edge was still connecting)
      4. no upstream contacted (us "" or absent):
           429 / 503                                       -> limit (limit_conn per site / per IP, fair
                                                              share, F35 cut 503)
           403                                             -> country (the only 403 inside a tunnel
                                                              location; firewall blocks are rewritten to
                                                              the deny location and carry no tn)
           400 / 426                                       -> protocol (426: ws/httpupgrade without
                                                              Upgrade, answered by the edge)
           5xx                                             -> edge (e.g. an origin hostname the edge
                                                              could not resolve)
           anything else                                   -> None
      5. last us = 502 (connect refused / reset, "uct" "-", or closed before a response header)
                                                           -> origin_refused
         last us = 504 (connect or header timeout)        -> origin_timeout
         last us not a number ("-"): status 504 -> origin_timeout, 502 -> origin_refused,
                                     other 5xx -> edge, else None
         last us any other number (the origin answered, but not 101/2xx: 400/404/5xx ...)
                                                           -> origin_error
    An origin that itself answers 502/504 (e.g. its own reverse proxy) is indistinguishable from a
    connect failure in the access log and is counted as refused / timeout."""
    try:
        code = int(e.get("s") or 0)
    except (TypeError, ValueError):
        return None
    if e.get("tn") == "grpc" and str(e.get("pr") or "").startswith("HTTP/1"):
        return "protocol"
    if code == 101 or 200 <= code < 300:
        return "session"
    us = _last_value(e.get("us"))
    if code == 499:
        return "session" if _ACCEPTED.match(us) else None
    if not us:
        if code in (429, 503):
            return "limit"
        if code == 403:
            return "country"
        if code in (400, 426):
            return "protocol"
        return "edge" if 500 <= code <= 599 else None
    if us == "502":
        return "origin_refused"
    if us == "504":
        return "origin_timeout"
    if not us.isdigit():
        if code == 504:
            return "origin_timeout"
        if code == 502:
            return "origin_refused"
        return "edge" if 500 <= code <= 599 else None
    return "origin_error"


def connect_ms(e: dict) -> int | None:
    """$upstream_connect_time of the attempt that connected (the last one), in ms; None without one."""
    v = _last_value(e.get("uct"))
    try:
        return int(round(float(v) * 1000)) if v and v != "-" else None
    except ValueError:
        return None


def _new_tpath() -> dict:
    return {"sessions": 0, "seconds": 0.0, "bytes_up": 0, "bytes_down": 0, "abnormal": 0, "connect_ms_sum": 0,
            "connect_n": 0, "errors": dict.fromkeys(TUNNEL_ERRORS, 0)}


def _tpath(t: dict, pid: str) -> dict | None:
    """The per-path counters of a host-hour tunnel object (≤ TUNNEL_PATHS_MAX ids; None beyond)."""
    paths = t.setdefault("paths", {})
    p = paths.get(pid)
    if p is None:
        if len(paths) >= TUNNEL_PATHS_MAX:
            return None
        p = paths[pid] = _new_tpath()
    return p


# ---- live minute aggregates (SPEC §14.3.1)
LIVE_MAX = 5000                    # `live` items per usage POST
LIVE_TOP = 20                      # top countries / paths per item
LIVE_PATH_TRACK = 100              # distinct paths counted per host-minute before taking the top
LIVE_CC_TRACK = 64                 # distinct countries counted per host-minute
LIVE_PATH_LEN = 256
LIVE_PENDING_MAX = 20000           # host-minutes held between two pushes (oldest dropped beyond)
LIVE_MAX_BYTES = 2 * 1024 * 1024   # estimated JSON size of the `live` list of one POST
LIVE_BACKLOG_MAX = 20000           # live items kept across the whole outbox (newest win)
LIVE_BACKLOG_BYTES = 8 * 1024 * 1024
LIVE_WINDOW = 86400                # the controller keeps 24 h of minutes; older ones are never sent


def live_cutoff(now: float | None = None) -> str:
    """Minute key 24 h ago: live buckets older than this are not counted or sent."""
    t = time.time() if now is None else now
    return datetime.fromtimestamp(t - LIVE_WINDOW, timezone.utc).strftime("%Y-%m-%dT%H:%M:00Z")


def _prune_live(live: dict):
    """Drop the oldest quarter of the pending host-minutes (amortised: called at the cap)."""
    keys = sorted(live, key=lambda k: k.rsplit("|", 1)[1])
    for k in keys[: max(1, len(keys) // 4)]:
        del live[k]


def _account_live(live: dict, host: str, minute: str, nbytes: int, hit: bool, code: int, cc: str, path: str,
                  tunnel: str | None = None):
    """tunnel: None for a request without a tunnel path id, else its classify_tunnel() outcome
    ("" when the line is not counted as a session or an error)."""
    key = f"{host}|{minute}"
    b = live.get(key)
    if b is None:
        if len(live) >= LIVE_PENDING_MAX:
            _prune_live(live)
        b = live[key] = {"requests": 0, "bytes": 0, "cache_hits": 0, "status": {}, "countries": {}, "paths": {}}
    b["requests"] += 1
    b["bytes"] += nbytes
    if hit:
        b["cache_hits"] += 1
    if 200 <= code <= 599:
        _inc(b["status"], f"{code // 100}xx")
    if cc and (cc in b["countries"] or len(b["countries"]) < LIVE_CC_TRACK):
        _inc(b["countries"], cc)
    if path:
        path = path[:LIVE_PATH_LEN]
        if path in b["paths"] or len(b["paths"]) < LIVE_PATH_TRACK:
            _inc(b["paths"], path)
    # SPEC §15.4 (controller contract): attempts = every tunnel request attributed to a path id in
    # this minute, whatever its outcome; errors = the origin_refused + origin_timeout ones among them
    if tunnel is not None:
        b["tunnel_attempts"] = b.get("tunnel_attempts", 0) + 1
        if tunnel in ORIGIN_DOWN_ERRORS:
            b["tunnel_errors"] = b.get("tunnel_errors", 0) + 1


def _top(d: dict, n: int) -> dict:
    return dict(sorted(d.items(), key=lambda kv: (-kv[1], kv[0]))[:n])


def live_item(key: str, b: dict) -> dict | None:
    """One `live` entry: {host, minute, requests, bytes, cache_hits, status, countries (top 20),
    paths (top 20, query already stripped)}. None for a host the controller would reject."""
    host, minute = key.rsplit("|", 1)
    if not host or len(host) > 253:
        return None

    def cnt(d):   # the controller rejects the WHOLE usage POST (422) on a negative number
        return {k: max(0, int(v)) for k, v in d.items()}
    item = {"host": host, "minute": minute, "requests": max(0, int(b.get("requests") or 0)),
            "bytes": max(0, int(b.get("bytes") or 0)), "cache_hits": max(0, int(b.get("cache_hits") or 0)),
            "status": cnt(b.get("status") or {}), "countries": cnt(_top(b.get("countries") or {}, LIVE_TOP)),
            "paths": cnt(_top(b.get("paths") or {}, LIVE_TOP))}
    if b.get("tunnel_attempts"):   # SPEC §15.4, optional: only minutes with tunnel attempts carry them
        item["tunnel_attempts"] = max(0, int(b["tunnel_attempts"]))
        item["tunnel_errors"] = max(0, int(b.get("tunnel_errors") or 0))
    return item


def _live_size(item: dict) -> int:
    """Cheap upper estimate of an item's JSON size (bytes)."""
    return (200 + len(item["host"]) + sum(len(k) + 12 for k in item["paths"])
            + 10 * len(item["countries"]) + 12 * len(item["status"]))


def _select_live(items: list, cutoff: str, max_items: int, max_bytes: int) -> list:
    """Newest minutes first within the caps (older ones are dropped), returned oldest first."""
    keep = []
    for it in sorted((x for x in items if x["minute"] >= cutoff), key=lambda x: x["minute"], reverse=True):
        size = _live_size(it)
        if len(keep) >= max_items or size > max_bytes:
            break
        keep.append(it)
        max_bytes -= size
    keep.reverse()
    return keep


def live_items(live: dict, cutoff: str) -> list[dict]:
    """The pending host-minutes as one POST's `live` list (≤ LIVE_MAX, ≤ LIVE_MAX_BYTES, no minute
    older than 24 h; when there are more, the OLDEST minutes are dropped - live data is best-effort)."""
    items = [it for it in (live_item(k, v) for k, v in live.items()) if it]
    return _select_live(items, cutoff, LIVE_MAX, LIVE_MAX_BYTES)


def trim_live_backlog(outbox: list, cutoff: str):
    """Bound the live data held in the usage outbox (controller unreachable): drop minutes older than
    24 h and keep only the newest LIVE_BACKLOG_MAX items / LIVE_BACKLOG_BYTES across all entries.
    Only `live` is ever trimmed - an entry's hourly items and events, and its batch_id, are untouched,
    so a retried batch stays idempotent (the controller dedups the whole body on batch_id)."""
    n, size = LIVE_BACKLOG_MAX, LIVE_BACKLOG_BYTES
    for entry in reversed(outbox):          # newest entries first
        live = entry.get("live")
        if not live:
            continue
        keep = _select_live(live, cutoff, n, size) if n > 0 and size > 0 else []
        n -= len(keep)
        size -= sum(_live_size(x) for x in keep)
        if keep:
            entry["live"] = keep
        else:
            entry.pop("live", None)


def _bucket(pending: dict, key: str) -> dict:
    a = pending.get(key)
    if isinstance(a, list):  # v1 state file: [bytes, requests, cache_hits]
        a = {"bytes": a[0], "requests": a[1], "cache_hits": a[2]}
    if a is None:
        a = {"bytes": 0, "requests": 0, "cache_hits": 0}
    for k in ("status", "codes", "countries", "paths", "security"):
        a.setdefault(k, {})
    pending[key] = a
    return a


def _inc(d: dict, k: str, n: int = 1):
    d[k] = d.get(k, 0) + n


_CC = re.compile(r"^[A-Z]{2}$")
VIDEO_EXT = re.compile(r"\.(?:m3u8|mpd|ts|m4s|aac|mp4)$", re.I)


def video_hosts(config: dict) -> dict:
    """SPEC §16.5 usage `video`: the host names of active video-enabled sites ({"exact": [...],
    "wild": [suffixes]}), kept in the agent state so access-log lines can be attributed without a
    log-format change (requests whose path ends in a media extension, never tunnel requests)."""
    exact, wild = set(), set()
    for s in config.get("sites", []) if isinstance(config, dict) else []:
        if not isinstance(s, dict) or s.get("status", "active") in ("suspended", "over_quota") or not norm_video(s):
            continue
        for h in s.get("hosts") or []:
            n = str((h or {}).get("name") or "").lower() if isinstance(h, dict) else ""
            if n.startswith("*.") and SAFE_NAME.match(n):
                wild.add(n[1:])
            elif SAFE_NAME.match(n):
                exact.add(n)
    return {"exact": sorted(exact), "wild": sorted(wild)} if exact or wild else {}


def video_host(vh: dict, host: str) -> bool:
    if host in vh.get("_set", ()) or host in (vh.get("exact") or ()):
        return True
    return any(host.endswith(w) for w in vh.get("wild") or ())


def _account(e: dict, pending: dict, events: list, live: dict | None = None, cutoff: str = "",
             ship=None, raw: bytes | None = None, vhosts: dict | None = None):
    """Fold one access-log record into the host-hour (`pending`), the security `events`, the
    host-minute `live` buckets (SPEC §14.3.1; minutes before `cutoff` skipped) and, for sites with
    log export, the sampler `ship` (SPEC §14.3.2; `raw` is the log line, the sampling key)."""
    host = e["h"].lower()
    dt, hour, minute = _times(e["t"])
    a = _bucket(pending, f"{host}|{hour}")
    nbytes = int(e.get("b") or 0)
    a["bytes"] += nbytes
    a["requests"] += 1
    hit = e.get("c") in CACHE_SERVED
    if hit:
        a["cache_hits"] += 1
    code = int(e.get("s") or 0)
    if 100 <= code <= 599:
        _inc(a["status"], f"{code // 100}xx")
        _inc(a["codes"], str(code))
        if code >= 500 and platform_error(e):
            a["platform_errors"] = a.get("platform_errors", 0) + 1
    cc = str(e.get("cc") or "").upper()
    if not _CC.match(cc):
        cc = ""
    if cc:
        _inc(a["countries"], cc)
    uri = str(e.get("u") or "")
    path = uri.split("?", 1)[0][:512] if uri else ""
    if path and (path in a["paths"] or len(a["paths"]) < PATH_TRACK):
        _inc(a["paths"], path)
    tn = e.get("tn")
    tcls = live_tn = None
    if tn in TUNNEL_PROTOCOLS:
        tcls = classify_tunnel(e)
        _account_tunnel(a, e, tn, code, tcls)
        if e.get("tp"):
            live_tn = tcls or ""
    if vhosts and not tn and VIDEO_EXT.search(path) and video_host(vhosts, host):
        # SPEC §16.5: a media request of a video-enabled host (part of `bytes` too)
        v = a.setdefault("video", {"bytes": 0, "requests": 0, "cache_hits": 0})
        v["bytes"] += nbytes
        v["requests"] += 1
        v["cache_hits"] += int(hit)
    parts = str(e.get("v") or "ok").split(":", 2)
    if len(parts) == 3 and parts[0] in ("block", "challenge", "captcha", "log"):
        action, source, rule = parts
        _inc(a["security"], source)
        if action in ("challenge", "captcha"):
            _inc(a["security"], "challenge")
        events.append({"t": dt.strftime("%Y-%m-%dT%H:%M:%SZ"), "host": host, "ip": str(e.get("ip") or ""),
                       "country": cc, "method": str(e.get("m") or ""), "path": uri[:2048], "action": action,
                       "source": source, "rule": rule, "user_agent": str(e.get("ua") or "")[:512]})
    # best-effort extras last, so nothing in them can cut the hourly / security accounting short
    if live is not None and minute >= cutoff:
        _account_live(live, host, minute, nbytes, hit, code, cc, path, live_tn)
    if ship is not None:
        try:
            ship.offer(e, host, dt, raw)
        except Exception as exc:  # noqa: BLE001 - log export must never break usage accounting
            log.debug("logship: record skipped: %s", exc)


def _nsum(v) -> int:
    """Sum of an nginx multi-upstream value ("12, 34 : 5"; "-" / "" = 0)."""
    return sum(int(x) for x in re.findall(r"\d+", str(v or "")))


def _account_tunnel(a: dict, e: dict, proto: str, code: int, tcls: str | None = None):
    """Tunnel counters of a host-hour (SPEC §7.3). One log line = one tunnel request: a whole
    WebSocket / HTTPUpgrade session or gRPC / h2 stream, or one XHTTP request.
    Bytes from the client: $request_length counts request bodies (HTTP/1.1 and HTTP/2) but not
    the frames of an upgraded connection; $upstream_bytes_sent counts everything written to the
    origin, including upgraded frames. Both include the request head, so the larger one is used."""
    t = a.setdefault("tunnel", {"sessions": 0, "seconds": 0.0, "bytes_up": 0, "bytes_down": 0, "by_protocol": {}})
    if code == 101 or 200 <= code < 300:
        t["sessions"] += 1
    try:
        t["seconds"] += max(0.0, float(e.get("rt") or 0))
    except (TypeError, ValueError):
        pass
    # F37: $request_length ($bu) already counts the request head + body the client sent. Only
    # ws/httpupgrade omit post-101 upgrade frames from it, so only those consult $upstream_bytes_sent
    # ($ub); for grpc/h2/xhttp bill $bu and drop the edge-injected header delta / retry re-sends.
    bu = int(e.get("bu") or 0)
    up = max(bu, _nsum(e.get("ub"))) if proto in ("ws", "httpupgrade") else (bu or max(bu, _nsum(e.get("ub"))))
    down = int(e.get("b") or 0)
    t["bytes_up"] += up
    t["bytes_down"] += down
    _inc(t["by_protocol"], proto, up + down)
    # SPEC §15.1 per path id ("tp"; lines without it - pre-wave-7 - only feed the totals above)
    pid = str(e.get("tp") or "")
    if not pid or not SAFE_ID.match(pid):
        return
    p = _tpath(t, pid)
    if p is None:
        return
    p["bytes_up"] += up
    p["bytes_down"] += down
    if tcls == "session":
        p["sessions"] += 1
        try:
            p["seconds"] += max(0.0, float(e.get("rt") or 0))
        except (TypeError, ValueError):
            pass
    elif tcls in TUNNEL_ERRORS:
        p["errors"][tcls] = p["errors"].get(tcls, 0) + 1
    ms = connect_ms(e)
    if ms is not None:   # every tunnel request whose (last) upstream connect succeeded, whatever came next
        p["connect_ms_sum"] += ms
        p["connect_n"] += 1


def _consume(path: str, pos: int, state: dict, max_bytes: int, deadline: float | None = None,
             ship=None, cutoff: str | None = None) -> int:
    """Aggregate complete lines from path starting at pos with O(line) memory (F24); returns the new
    position. Stops after max_bytes or the time budget, so a huge backlog is drained over ticks
    instead of held in RAM 2-3x on one thread. A partial trailing line is left for the next read.
    Also fills state['live'] (host-minutes since `cutoff`) and feeds the log-export sampler `ship`."""
    pending = state.setdefault("pending", {})
    events = state.setdefault("events", [])
    live = state.setdefault("live", {})
    cutoff = live_cutoff() if cutoff is None else cutoff
    vh = state.get("video_hosts") or None
    vhosts = dict(vh, _set=frozenset(vh.get("exact") or ())) if isinstance(vh, dict) else None
    read = 0
    with open(path, "rb", buffering=1 << 20) as f:
        f.seek(pos)
        for raw in f:
            if not raw.endswith(b"\n"):
                break  # partial line at EOF: re-read it next time
            pos += len(raw)
            read += len(raw)
            try:
                _account(json.loads(raw), pending, events, live, cutoff, ship, raw, vhosts)
            except (ValueError, KeyError, TypeError, AttributeError):
                pass
            if read >= max_bytes or (deadline is not None and time.monotonic() > deadline):
                break
    return pos


def _drain_rotated(state: dict, log_path: str, max_bytes: int, deadline: float | None, ship=None) -> bool:
    """Drain the rotated (.1) file recorded in state across ticks (F24). Returns True while more of
    it remains (so the caller can defer the live file to the next tick)."""
    rotated = log_path + ".1"
    try:
        rst = os.stat(rotated)
    except (FileNotFoundError, OSError):
        state.pop("rot_inode", None), state.pop("rot_pos", None)
        return False
    if rst.st_ino != state.get("rot_inode"):
        state.pop("rot_inode", None), state.pop("rot_pos", None)
        return False
    newpos = _consume(rotated, int(state.get("rot_pos", 0)), state, max_bytes, deadline, ship)
    if newpos >= rst.st_size:  # fully drained
        state.pop("rot_inode", None), state.pop("rot_pos", None)
        return False
    state["rot_pos"] = newpos
    return True


def read_usage(state: dict, log_path: str, max_bytes: int = 64 * 1024 * 1024, time_budget: float = 5.0,
               ship=None) -> None:
    """Consume new access-log lines and merge them into state['pending'] / state['events'] /
    state['live']; sampled log-export records go to `ship` (a LogShip, None = export off)."""
    deadline = time.monotonic() + time_budget
    # finish any rotated file still being drained from an earlier tick before touching the live file
    if state.get("rot_inode") is not None and _drain_rotated(state, log_path, max_bytes, deadline, ship):
        return
    try:
        st = os.stat(log_path)
    except FileNotFoundError:
        return
    pending = state.setdefault("pending", {})
    pos = state.get("log_pos", 0)
    if state.get("log_inode") not in (None, st.st_ino):
        # logrotate moved the file: record the old one (now .1) to drain across ticks, start new at 0
        state["rot_inode"], state["rot_pos"] = state["log_inode"], pos
        pos = 0
        _drain_rotated(state, log_path, max_bytes, deadline, ship)
    elif st.st_size < pos:
        pos = 0  # truncated
    state["log_pos"] = _consume(log_path, pos, state, max_bytes, deadline, ship)
    state["log_inode"] = st.st_ino
    if len(pending) > 50000:  # controller unreachable for a long time: keep newest
        for k in sorted(pending, key=lambda k: k.split("|")[1])[: len(pending) - 50000]:
            del pending[k]
    events = state.get("events") or []
    if len(events) > EVENT_BACKLOG:
        del events[: len(events) - EVENT_BACKLOG]


# ----------------------------------------------------------------- L4 usage (SPEC §16.4)

L4_APPS_PER_ITEM = 100        # the controller keeps at most 100 app ids per item
L4_READ_MAX = 32 * 1024 * 1024   # bytes of the stream access log consumed per usage tick


def _account_l4(e: dict, pending: dict):
    """One stream access-log line (one TCP connection / UDP session of an app) -> the `l4` counters of
    the app's site host-hour: {app_id: {bytes_in, bytes_out, sessions}}. bytes_in = from the client
    ($bytes_received), bytes_out = to the client ($bytes_sent)."""
    host, _, app = str(e.get("a") or "").partition("|")
    host = host.lower()
    if not SAFE_NAME.match(host) or not SAFE_ID.match(app):
        return
    _, hour, _ = _times(e["t"])
    a = _bucket(pending, f"{host}|{hour}")
    l4 = a.setdefault("l4", {})
    if app not in l4 and len(l4) >= L4_APPS_PER_ITEM:
        return
    c = l4.setdefault(app, {"bytes_in": 0, "bytes_out": 0, "sessions": 0})
    c["bytes_in"] += max(0, int(e.get("bi") or 0))
    c["bytes_out"] += max(0, int(e.get("bo") or 0))
    c["sessions"] += 1


def _consume_l4(path: str, pos: int, pending: dict, max_bytes: int) -> int:
    read = 0
    with open(path, "rb", buffering=1 << 20) as f:
        f.seek(pos)
        for raw in f:
            if not raw.endswith(b"\n"):
                break
            pos += len(raw)
            read += len(raw)
            try:
                _account_l4(json.loads(raw), pending)
            except (ValueError, KeyError, TypeError, AttributeError):
                pass
            if read >= max_bytes:
                break
    return pos


def read_l4_usage(state: dict, path: str, max_bytes: int = L4_READ_MAX) -> None:
    """Fold new stream access-log lines into state['pending'] (own offset / inode: l4_pos, l4_inode).
    After a rotation the rest of the old file (<path>.1, same inode) is read first."""
    try:
        st = os.stat(path)
    except OSError:
        return
    pending = state.setdefault("pending", {})
    pos, ino = int(state.get("l4_pos") or 0), state.get("l4_inode")
    if ino is not None and ino != st.st_ino:
        try:
            if os.stat(path + ".1").st_ino == ino:
                _consume_l4(path + ".1", pos, pending, max_bytes)
        except OSError:
            pass
        pos = 0
    elif st.st_size < pos:
        pos = 0
    state["l4_pos"] = _consume_l4(path, pos, pending, max_bytes)
    state["l4_inode"] = st.st_ino


def usage_item(key: str, a) -> dict:
    a = _bucket({key: a}, key)
    host, hour = key.split("|", 1)
    item = {"host": host, "hour": hour, "bytes": a["bytes"], "requests": a["requests"], "cache_hits": a["cache_hits"],
            # SPEC §14.3.1: edge-produced 5xx of this host-hour (see platform_error); 0 when none
            "platform_errors": int(a.get("platform_errors") or 0)}
    for k in ("status", "codes", "countries", "security"):
        if a[k]:
            item[k] = a[k]
    if a.get("tunnel"):
        t = a["tunnel"]
        item["tunnel"] = {"sessions": t["sessions"], "seconds": int(round(t["seconds"])), "bytes_up": t["bytes_up"],
                          "bytes_down": t["bytes_down"], "by_protocol": dict(t["by_protocol"])}
        if t.get("paths"):   # SPEC §15.1 (optional; pre-wave-7 agents omit it)
            item["tunnel"]["paths"] = {pid: tpath_item(p) for pid, p in sorted(t["paths"].items())}
    if a["paths"]:
        item["paths"] = dict(sorted(a["paths"].items(), key=lambda kv: (-kv[1], kv[0]))[:PATHS_PER_ITEM])
    if a.get("video"):   # SPEC §16.5 (optional): the video share of this host-hour (already in bytes)
        item["video"] = {k: int(a["video"].get(k) or 0) for k in ("bytes", "requests", "cache_hits")}
    if a.get("l4"):      # SPEC §16.4 (optional): per app; NOT included in bytes (billed by the controller)
        item["l4"] = {app: {k: int(c.get(k) or 0) for k in ("bytes_in", "bytes_out", "sessions")}
                      for app, c in sorted(a["l4"].items())}
    if a.get("functions"):   # SPEC §16.9 (optional): edge function invocations of this host-hour
        item["functions"] = {k: int(a["functions"].get(k) or 0)
                             for k in ("invocations", "cpu_ms", "errors", "timeouts")}
    return item


def tpath_item(p: dict) -> dict:
    """Wire shape of one `tunnel.paths` entry (SPEC §15.1): integers only, all seven error keys."""
    def n(v):
        try:
            return max(0, int(round(float(v or 0))))
        except (TypeError, ValueError):
            return 0
    errs = p.get("errors") or {}
    return {"sessions": n(p.get("sessions")), "seconds": n(p.get("seconds")), "bytes_up": n(p.get("bytes_up")),
            "bytes_down": n(p.get("bytes_down")), "abnormal": n(p.get("abnormal")),
            "connect_ms_sum": n(p.get("connect_ms_sum")), "connect_n": n(p.get("connect_n")),
            "errors": {k: n(errs.get(k)) for k in TUNNEL_ERRORS}}


def usage_items(pending: dict) -> list[dict]:
    return [usage_item(k, v) for k, v in pending.items()]
