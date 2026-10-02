"""Usage accounting from the access log: per-host hourly usage, security events, tunnel quality
(SPEC §15.1), live minute aggregates (SPEC §14.3.1), platform errors and L4 usage (SPEC §16.4)."""

import hashlib
import json
import math
import os
import re
import time
from datetime import datetime, timezone

from .common import EVENT_BACKLOG, PATHS_PER_ITEM, PATH_TRACK, SAFE_ID, SAFE_NAME, TUNNEL_PROTOCOLS
from .settings import log
from .validation.rules import norm_video, norm_waf_learning


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


# ---- WAF learning mode (SPEC §17.1): per host-hour `waf_learn`, only for hosts of learning sites.
# Every structure below is capped; what does not fit is not counted (never an unbounded dict).
#
# Counters (rule hits, path requests, methods) live in the pending host-hour bucket and are sent
# as deltas with each usage push, like every other counter. Distinct clients and per-minute rates
# cannot be summed, so they are kept per host-hour across pushes (state["waf_learn_hour"]) and
# every push reports the hour-to-date value; the controller keeps the maximum.
WAF_LEARN_RULES = 100          # rule ids per host-hour
WAF_LEARN_RULE_PATHS = 50      # path prefixes counted per rule (top WAF_LEARN_RULE_TOP sent)
WAF_LEARN_RULE_TOP = 10
WAF_LEARN_PATHS = 200          # path prefixes counted per host-hour (top WAF_LEARN_PATHS_TOP sent)
WAF_LEARN_PATHS_TOP = 50
WAF_LEARN_METHODS = 9          # methods per map; any further one is counted as "OTHER" (≤ 10 keys)
WAF_LEARN_SEG = 64             # characters kept of each of the two path segments
WAF_LEARN_HOSTS = 64           # hosts with an open per-minute client window at the same time
WAF_LEARN_IPS = 2000           # client IPs counted per host-minute
WAF_LEARN_PAIRS = 4000         # (path prefix, client IP) pairs counted per host-minute
WAF_LEARN_RULE_PATH_SKETCHES = 1000   # (rule, prefix) distinct-client sketches per host-hour
WAF_LEARN_HOURS = 128          # host-hours of hour-to-date statistics kept
WAF_LEARN_HOUR_TTL = 3 * 3600  # ... and at most this much older than the newest one (s)
WAF_LEARN_FLUSH_LAG = 120      # a host-minute is closed once the clock is this far past it (s)
RPM_EXACT = 200                # per-client rpm values up to this are kept exactly in the histogram,
RPM_STEP = 1.05                # larger ones in geometric buckets (≤ 5 % high; ≈ 220 more keys up to 1e7)
PATH_RPM_EXACT = 32            # the same per path prefix, coarser (≤ 20 % high; ≈ 100 keys up to 1e7)
PATH_RPM_STEP = 1.2
SKETCH_RULE_BITS = 256         # linear-counting bitmaps of distinct client IPs: ≈ exact for small
SKETCH_PATH_BITS = 256         # counts, ≤ ~15 % off up to a few hundred, saturating at m ln m = 1420
_METHOD = re.compile(r"^[A-Z]{1,10}$")
_WAF_RULE = re.compile(r"^[1-9]\d{0,6}$")


def learn_hosts(config: dict, now: float | None = None) -> dict:
    """SPEC §17.1: {"exact": {host: until}, "wild": {".suffix": until}} of the active sites that are
    learning now (until = UNIX second learning ends, see norm_waf_learning); {} when none. Kept in the
    agent state (agent-side only) to attribute access-log lines without a log-format change."""
    t = time.time() if now is None else now
    exact, wild = {}, {}
    for s in config.get("sites", []) if isinstance(config, dict) else []:
        if not isinstance(s, dict) or s.get("status", "active") in ("suspended", "over_quota"):
            continue
        until = norm_waf_learning(s, t)
        if until is None:
            continue
        for h in s.get("hosts") or []:
            n = str((h or {}).get("name") or "").lower() if isinstance(h, dict) else ""
            if n.startswith("*.") and SAFE_NAME.match(n):
                wild[n[1:]] = until
            elif SAFE_NAME.match(n):
                exact[n] = until
    return {"exact": exact, "wild": wild} if exact or wild else {}


def learn_until(lh: dict, host: str) -> int:
    """End of learning (UNIX second) of a host; 0 = not learning."""
    u = (lh.get("exact") or {}).get(host)
    if u:
        return int(u)
    for suf, u in (lh.get("wild") or {}).items():
        if host.endswith(suf):
            return int(u)
    return 0


def learn_prefix(path: str) -> str:
    """Path prefix of the learning aggregates: the first two segments ("/wp-json/wp/v2/x" ->
    "/wp-json/wp"; "/" -> "/"), each cut to WAF_LEARN_SEG characters."""
    segs = [x for x in path.split("/") if x][:2]
    return "/" + "/".join(x[:WAF_LEARN_SEG] for x in segs)


def _learn_method(m) -> str:
    m = str(m or "").upper()
    return m if _METHOD.match(m) else "OTHER"


def _minc(d: dict, m: str):
    if m not in d and len(d) >= WAF_LEARN_METHODS:
        m = "OTHER"
    d[m] = d.get(m, 0) + 1


def rpm_bucket(n: int, exact: int = RPM_EXACT, step: float = RPM_STEP) -> int:
    """Histogram key of a per-client-minute request count: exact up to `exact`, else the upper
    bound of its geometric bucket (≥ n, < n * step + 1)."""
    if n <= exact:
        return max(0, int(n))
    k = math.ceil(math.log(n / exact) / math.log(step))
    b = math.ceil(exact * step ** k)
    while b < n:                       # float rounding
        k += 1
        b = math.ceil(exact * step ** k)
    return b


def p95_hist(hist: dict) -> int:
    """Nearest-rank 95th percentile of a {value: count} histogram (keys may be strings); 0 if empty."""
    items = sorted((int(k), int(v)) for k, v in hist.items() if int(v) > 0)
    total = sum(v for _, v in items)
    if not total:
        return 0
    rank, acc = math.ceil(0.95 * total), 0
    for val, cnt in items:
        acc += cnt
        if acc >= rank:
            return val
    return items[-1][0]


def _hinc(hist: dict, n: int, exact: int, step: float):
    k = str(rpm_bucket(n, exact, step))
    hist[k] = hist.get(k, 0) + 1


def sketch_add(bm: int, ip: str, bits: int) -> int:
    """Linear-counting bitmap (an int, JSON-safe) with `ip` added."""
    h = int.from_bytes(hashlib.blake2b(ip.encode(), digest_size=4).digest(), "big")
    return bm | (1 << (h % bits))


def sketch_count(bm: int, bits: int) -> int:
    """Estimated distinct IPs of a bitmap: -m ln(zero bits / m), m ln m once every bit is set."""
    zeros = bits - bin(int(bm) & ((1 << bits) - 1)).count("1")
    return int(round(bits * math.log(bits))) if zeros <= 0 else int(round(-bits * math.log(zeros / bits)))


def _learn_obj(a: dict) -> dict:
    return a.setdefault("waf_learn", {"rules": {}, "paths": {}})


def _learn_hour(hours: dict, key: str) -> dict:
    """Hour-to-date statistics of a host-hour ("host|hour"): client rpm histogram / max, per prefix
    rpm histogram / max, distinct-client sketches per rule and per (rule, prefix)."""
    H = hours.get(key)
    if H is None:
        if len(hours) >= WAF_LEARN_HOURS:
            for k in sorted(hours, key=lambda k: k.rsplit("|", 1)[1])[: max(1, len(hours) // 4)]:
                del hours[k]
        H = hours[key] = {"mx": 0, "h": {}, "pmx": {}, "ph": {}, "rc": {}, "rpc": {}}
    return H


def prune_learn_hours(state: dict):
    """Drop hour-to-date statistics more than WAF_LEARN_HOUR_TTL older than the newest hour held
    (relative to the log, not the clock, so a backlog read after an outage keeps its statistics)."""
    hours = state.get("waf_learn_hour")
    if not hours:
        state.pop("waf_learn_hour", None)
        return
    newest = max(k.rsplit("|", 1)[1] for k in hours)
    try:
        cut = (_utc(newest.replace("Z", "+00:00")).timestamp() - WAF_LEARN_HOUR_TTL)
    except ValueError:
        return
    cut_key = datetime.fromtimestamp(cut, timezone.utc).strftime("%Y-%m-%dT%H:00:00Z")
    for k in [k for k in hours if k.rsplit("|", 1)[1] < cut_key]:
        del hours[k]


def _learn_close(learn: dict, host: str, w: dict):
    """Fold one closed host-minute client window into its host-hour statistics (and make sure the
    next usage push carries an item for that host-hour, so the new values are reported)."""
    key = f"{host}|{w['h']}"
    _learn_obj(_bucket(learn["pending"], key))
    H = _learn_hour(learn["hour"], key)
    for n in w["ip"].values():
        if n > H["mx"]:
            H["mx"] = n
        _hinc(H["h"], n, RPM_EXACT, RPM_STEP)
    pmx, ph = H["pmx"], H["ph"]
    for key, n in w["pi"].items():
        prefix = key.rsplit(" ", 1)[0]
        if prefix not in pmx and len(pmx) >= WAF_LEARN_PATHS:
            continue
        if n > pmx.get(prefix, 0):
            pmx[prefix] = n
        _hinc(ph.setdefault(prefix, {}), n, PATH_RPM_EXACT, PATH_RPM_STEP)


def _learn_ctx(state: dict) -> dict:
    return {"hosts": state.get("learn_hosts") or {}, "win": state.setdefault("waf_learn_win", {}),
            "hour": state.setdefault("waf_learn_hour", {}), "pending": state.setdefault("pending", {})}


def learn_flush(state: dict, before_minute: str | None = None):
    """Close the per-minute client windows (state['waf_learn_win']) of minutes before
    `before_minute` ("YYYY-MM-DDTHH:MM:00Z"; None = all of them) into the hour-to-date statistics."""
    if not state.get("waf_learn_win"):
        return
    learn = _learn_ctx(state)
    for host, w in list(learn["win"].items()):
        if before_minute is None or w["m"] < before_minute:
            _learn_close(learn, host, w)
            del learn["win"][host]


def _account_learn(a: dict, learn: dict, host: str, hour: str, minute: str, e: dict, path: str,
                   source: str, rule: str, attack: bool = False):
    """One request of a learning host (SPEC §17.1). attack: the WAF verdict carried ":a" (the request
    also had another attack signal, see waf() in pcdn.js)."""
    L = _learn_obj(a)
    prefix = learn_prefix(path)
    method = _learn_method(e.get("m"))
    ip = str(e.get("ip") or "")[:45]
    paths = L["paths"]
    p = paths.get(prefix)
    if p is None and len(paths) < WAF_LEARN_PATHS:
        p = paths[prefix] = {"req": 0, "methods": {}}
    if p is not None:
        p["req"] += 1
        _minc(p["methods"], method)
    if source == "waf" and _WAF_RULE.match(rule):
        rules = L["rules"]
        r = rules.get(rule)
        if r is None and len(rules) < WAF_LEARN_RULES:
            r = rules[rule] = {"hits": 0, "attack": 0, "paths": {}, "pa": {}, "methods": {}}
        if r is not None:
            r["hits"] += 1
            tracked = prefix in r["paths"] or len(r["paths"]) < WAF_LEARN_RULE_PATHS
            if tracked:
                _inc(r["paths"], prefix)
            if attack:
                r["attack"] += 1
                if tracked:
                    _inc(r["pa"], prefix)
            _minc(r["methods"], method)
            if ip:   # distinct clients, hour to date
                H = _learn_hour(learn["hour"], f"{host}|{hour}")
                rc, rpc = H["rc"], H["rpc"]
                if rule in rc or len(rc) < WAF_LEARN_RULES:
                    rc[rule] = sketch_add(rc.get(rule, 0), ip, SKETCH_RULE_BITS)
                k = rule + " " + prefix
                if k in rpc or len(rpc) < WAF_LEARN_RULE_PATH_SKETCHES:
                    rpc[k] = sketch_add(rpc.get(k, 0), ip, SKETCH_PATH_BITS)
    # per-client requests per minute: one open window per host (the current minute); a line of an
    # older minute (logged late) is not counted there
    win = learn["win"]
    w = win.get(host)
    if w is None or minute > w["m"]:
        if w is not None:
            _learn_close(learn, host, w)
        elif len(win) >= WAF_LEARN_HOSTS:
            return
        w = win[host] = {"m": minute, "h": hour, "ip": {}, "pi": {}}
    if minute != w["m"] or not ip:
        return
    if ip in w["ip"] or len(w["ip"]) < WAF_LEARN_IPS:
        _inc(w["ip"], ip)
    k = prefix + " " + ip
    if k in w["pi"] or len(w["pi"]) < WAF_LEARN_PAIRS:
        _inc(w["pi"], k)


def waf_learn_item(L: dict | None, H: dict | None) -> dict:
    """Wire shape of a host-hour `waf_learn` (SPEC §17.1; field names as the controller's
    waf_learning.WafLearn): L = the counters of this push (deltas), H = hour-to-date statistics.

      rules:   {rule_id: {hits, clients, attack, methods: {M: n}, paths: {prefix: {hits, clients, attack}}}}
               clients = distinct client IPs (hour to date, estimated), attack = hits on requests that
               also carried another attack signal
               (≤ 100 rules, busiest first; ≤ 10 prefixes per rule)
      paths:   {prefix: {req, max_rpm, p95_rpm, p95_rps_min, methods: {M: n}}} (≤ 50 prefixes)
               max_rpm = most requests one client IP sent to the prefix in one minute (hour to date),
               p95_rps_min = the same value under the SPEC §17.1 name, p95_rpm = the 95th percentile
               of the per-(client IP, minute) request counts to the prefix
      clients: {max_rpm, p95_rpm} over every (client IP, minute) of the host-hour (hour to date)."""
    L, H = L or {}, H or {}

    def n(v):
        try:
            return max(0, int(v or 0))
        except (TypeError, ValueError):
            return 0
    rc, rpc = H.get("rc") or {}, H.get("rpc") or {}
    rules = {}
    for rid, r in sorted((L.get("rules") or {}).items(), key=lambda kv: (-n(kv[1].get("hits")), kv[0]))[:WAF_LEARN_RULES]:
        rp = _top(r.get("paths") or {}, WAF_LEARN_RULE_TOP)
        rules[rid] = {"hits": n(r.get("hits")),
                      "clients": sketch_count(rc[rid], SKETCH_RULE_BITS) if rid in rc else 0,
                      "attack": n(r.get("attack")),
                      "paths": {k: {"hits": n(v), "clients": sketch_count(rpc[f"{rid} {k}"], SKETCH_PATH_BITS)
                                    if f"{rid} {k}" in rpc else 0, "attack": n((r.get("pa") or {}).get(k))}
                                for k, v in rp.items()},
                      "methods": {k: n(v) for k, v in sorted((r.get("methods") or {}).items())}}
    lp, pmx, ph = L.get("paths") or {}, H.get("pmx") or {}, H.get("ph") or {}
    order = sorted(lp, key=lambda k: (-n(lp[k].get("req")), k))
    # prefixes with only hour-to-date rates in this push (their minute closed after their requests
    # were sent) follow, busiest client first
    order += sorted((k for k in pmx if k not in lp), key=lambda k: (-n(pmx[k]), k))
    paths = {}
    for k in order[:WAF_LEARN_PATHS_TOP]:
        p, mx = lp.get(k) or {}, n(pmx.get(k))
        paths[k] = {"req": n(p.get("req")), "max_rpm": mx, "p95_rpm": min(mx, p95_hist(ph.get(k) or {})),
                    "p95_rps_min": mx, "methods": {m: n(v) for m, v in sorted((p.get("methods") or {}).items())}}
    mx = n(H.get("mx"))
    return {"rules": rules, "paths": paths, "clients": {"max_rpm": mx, "p95_rpm": min(mx, p95_hist(H.get("h") or {}))}}


def _account(e: dict, pending: dict, events: list, live: dict | None = None, cutoff: str = "",
             ship=None, raw: bytes | None = None, vhosts: dict | None = None, learn: dict | None = None):
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
    attack = False
    if len(parts) == 3 and parts[1] == "waf" and parts[2].endswith(":a"):   # SPEC §17.1 learning marker
        parts[2], attack = parts[2][:-2], True
    if len(parts) == 3 and parts[0] in ("block", "challenge", "captcha", "log"):
        action, source, rule = parts
        _inc(a["security"], source)
        if action in ("challenge", "captcha"):
            _inc(a["security"], "challenge")
        events.append({"t": dt.strftime("%Y-%m-%dT%H:%M:%SZ"), "host": host, "ip": str(e.get("ip") or ""),
                       "country": cc, "method": str(e.get("m") or ""), "path": uri[:2048], "action": action,
                       "source": source, "rule": rule, "user_agent": str(e.get("ua") or "")[:512]})
    # best-effort extras last, so nothing in them can cut the hourly / security accounting short
    if learn and not tn and not path.startswith("/__pcdn/"):
        # SPEC §17.1: learning hosts only, until their learning ends (learn = _learn_ctx(state))
        lu = learn_until(learn["hosts"], host)
        if lu and dt.timestamp() < lu:
            src, rid = (parts[1], parts[2]) if len(parts) == 3 else ("", "")
            _account_learn(a, learn, host, hour, minute, e, path, src, rid, attack)
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
    learn = _learn_ctx(state) if state.get("learn_hosts") else None
    read = 0
    with open(path, "rb", buffering=1 << 20) as f:
        f.seek(pos)
        for raw in f:
            if not raw.endswith(b"\n"):
                break  # partial line at EOF: re-read it next time
            pos += len(raw)
            read += len(raw)
            try:
                _account(json.loads(raw), pending, events, live, cutoff, ship, raw, vhosts, learn)
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
    if state.get("waf_learn_win") and state["log_pos"] >= st.st_size:
        # SPEC §17.1: close the client windows of minutes that are over (only once the log is read
        # up to its end, so a backlog drained over several ticks does not split a minute)
        learn_flush(state, datetime.fromtimestamp(time.time() - WAF_LEARN_FLUSH_LAG, timezone.utc)
                    .strftime("%Y-%m-%dT%H:%M:00Z"))
    prune_learn_hours(state)
    if not state.get("waf_learn_win"):
        state.pop("waf_learn_win", None)
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


def usage_item(key: str, a, learn_hours: dict | None = None) -> dict:
    """One hourly usage item. learn_hours: state['waf_learn_hour'] (SPEC §17.1 hour-to-date stats)."""
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
    lhour = (learn_hours or {}).get(key)
    if a.get("waf_learn") or lhour:   # SPEC §17.1 (optional): learning sites only
        item["waf_learn"] = waf_learn_item(a.get("waf_learn"), lhour)
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


def usage_items(pending: dict, learn_hours: dict | None = None) -> list[dict]:
    return [usage_item(k, v, learn_hours) for k, v in pending.items()]
