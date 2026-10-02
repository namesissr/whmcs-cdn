"""Centralized node logs (SPEC §11.2): the nginx error log tail (redacted), the agent's own lines
and the abnormal tunnel stream ends attributed to their tunnel path."""

import os
import re
from datetime import datetime, timezone

from .common import SAFE_NAME
from .settings import AGENT_LOGS, log
from .usage import _bucket, _tpath
from .validation.origin import norm_pools, norm_tunnel


# ----------------------------------------------------------------- centralized logs (SPEC §11.2)

LOG_MSG_MAX = 500
LOG_MAX_PER_REPORT = 40
LOG_MAX_SCAN = 2 * 1024 * 1024   # bytes of new error-log tail read per cycle
# nginx error line: "2024/01/02 15:04:05 [error] 1234#0: *5 message ..." (the *N conn id is optional)
NGINX_ERR_RE = re.compile(r"^(\d{4}/\d\d/\d\d \d\d:\d\d:\d\d) \[(\w+)\] \d+#\d+: (?:\*\d+ )?(.*)$")
# map nginx severities to the controller's small level set (warn/error/crit/notice/info)
NGINX_LEVEL = {"warn": "warn", "error": "error", "crit": "crit", "alert": "crit", "emerg": "crit",
               "notice": "notice", "info": "info"}
SHIP_LEVELS = {"warn", "error", "crit"}
# redaction (defence in depth): never ship visitor IPs, tokens or keys, only operational text
_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_IPV6 = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}\b")
_SECRET = re.compile(r"\b(?:edge_|pcdn_)[A-Za-z0-9_-]{6,}")
_CLIENT = re.compile(r"\bclient:\s*\S+")


def redact(msg: str) -> str:
    """Strip anything that could identify a visitor or leak a secret from an error line."""
    msg = _SECRET.sub("[redacted]", msg)
    msg = _CLIENT.sub("client: [redacted]", msg)
    msg = _IPV6.sub("[ip]", msg)
    msg = _IPV4.sub("[ip]", msg)
    return msg


def parse_error_lines(text: str) -> list[dict]:
    """Turn raw nginx error-log text into shippable {t, level, msg} for WARN/ERROR/crit only."""
    out = []
    for raw in text.splitlines():
        raw = raw.strip()
        if not raw:
            continue
        m = NGINX_ERR_RE.match(raw)
        if m:
            t, sev, body = m.group(1), m.group(2).lower(), m.group(3)
            level = NGINX_LEVEL.get(sev)
            if level not in SHIP_LEVELS:
                continue
            out.append({"t": t, "level": level, "msg": redact(body)[:LOG_MSG_MAX]})
        # lines we cannot classify are dropped (never ship access logs or unknown formats)
    return out


def read_error_log(state: dict, path: str, raw_hook=None) -> list[dict]:
    """New WARN/ERROR/crit lines since the last offset (handles rotation/truncation). Fail-soft.
    raw_hook(text): sees the raw, unredacted new text first (tunnel abnormal-end accounting)."""
    try:
        st = os.stat(path)
    except (FileNotFoundError, OSError):
        return []
    pos = int(state.get("err_pos", 0))
    prev_inode = state.get("err_inode")
    text = ""
    try:
        if prev_inode not in (None, st.st_ino):
            # rotated: finish the old file (now .1) then start the new one at 0
            rotated = path + ".1"
            try:
                if os.stat(rotated).st_ino == prev_inode:
                    text += _read_tail(rotated, pos)
            except (FileNotFoundError, OSError):
                pass
            pos = 0
        elif st.st_size < pos:
            pos = 0  # truncated
        with open(path, "rb") as f:
            f.seek(pos)
            chunk = f.read(LOG_MAX_SCAN)
            state["err_pos"] = f.tell()
        text += chunk.decode("utf-8", "replace")
        state["err_inode"] = st.st_ino
    except OSError as e:
        log.debug("error-log read: %s", e)
        return []
    if raw_hook is not None:
        try:
            raw_hook(text)
        except Exception as e:  # noqa: BLE001 - never let accounting break log shipping
            log.debug("error-log hook: %s", e)
    return parse_error_lines(text)


# SPEC §15.1 `abnormal`: nginx 1.24 logs an established tunnel session that the ORIGIN ended badly with
# the same $status / $upstream_status as a clean end (101 / 200), so the access log cannot tell. The
# error log can: an [error] line "... while proxying upgraded connection" (ws / httpupgrade after the
# 101: upstream reset, upstream idle timeout) or "... while reading upstream" (grpc / h2 / xhttp
# response body: upstream reset, premature close, read timeout). Client-side failures of the same
# phases are logged at [info] (nginx logs client connection errors at info), and failures before a
# response header ("while connecting to upstream", "while reading response header from upstream")
# are already origin_refused / origin_timeout in the access log, so they are not matched here.
# The line is attributed to the path id by host + longest tunnel prefix of its request path.
ABNORMAL_RE = re.compile(r'^(\d{4}/\d\d/\d\d \d\d:\d\d:\d\d) \[error\] .* while (?:proxying upgraded connection|'
                         r'reading upstream), .*?request: "[A-Z]{1,16} (\S+) [^"]*".*, host: "([^"]+)"\s*$')


def tunnel_map(config: dict) -> dict:
    """{host: [[prefix, path id], ...] longest prefix first} for the abnormal-end attribution."""
    out = {}
    for site in config.get("sites", []):
        try:
            tn = norm_tunnel(site, norm_pools(site))
        except Exception:  # noqa: BLE001 - a broken site entry never stops the others
            tn = None
        if not tn:
            continue
        prefixes = sorted(([p["path"], p["id"]] for p in tn["paths"]), key=lambda x: (-len(x[0]), x[0]))
        for h in site.get("hosts") or []:
            name = str(h.get("name") or "").lower() if isinstance(h, dict) else ""
            if name and SAFE_NAME.match(name):
                out[name] = prefixes
    return out


def _tmap_lookup(tmap: dict, host: str, path: str) -> str | None:
    host = host.lower().split(":", 1)[0]
    prefixes = tmap.get(host)
    if prefixes is None:   # wildcard host entries ("*.example.com")
        for name, pre in tmap.items():
            if name.startswith("*.") and host.endswith(name[1:]):
                prefixes = pre
                break
    for prefix, pid in prefixes or ():
        if path.startswith(prefix):
            return pid
    return None


def account_abnormal(state: dict, text: str) -> int:
    """Add the abnormal tunnel-session ends found in raw error-log text to the pending host-hours
    (tunnel.paths[id].abnormal). Returns how many were counted."""
    tmap = state.get("tunnel_map") or {}
    if not tmap or " while " not in text:
        return 0
    pending = state.setdefault("pending", {})
    n = 0
    for raw in text.splitlines():
        m = ABNORMAL_RE.match(raw.strip())
        if not m:
            continue
        ts, uri, host = m.groups()
        pid = _tmap_lookup(tmap, host, uri.split("?", 1)[0])
        if not pid:
            continue
        try:   # nginx writes the error log in local time
            hour = (datetime.strptime(ts, "%Y/%m/%d %H:%M:%S").astimezone(timezone.utc)
                    .strftime("%Y-%m-%dT%H:00:00Z"))
        except (ValueError, OverflowError, OSError):
            continue
        a = _bucket(pending, f"{host.lower().split(':', 1)[0]}|{hour}")
        t = a.setdefault("tunnel", {"sessions": 0, "seconds": 0.0, "bytes_up": 0, "bytes_down": 0, "by_protocol": {}})
        p = _tpath(t, pid)
        if p is not None:
            p["abnormal"] += 1
            n += 1
    return n


def _read_tail(path: str, pos: int) -> str:
    try:
        with open(path, "rb") as f:
            f.seek(pos)
            return f.read(LOG_MAX_SCAN).decode("utf-8", "replace")
    except OSError:
        return ""


def collect_logs(state: dict, cfg: dict) -> list[dict]:
    """Gather new problem lines (nginx error log + the agent's own), de-duplicated and capped.

    De-dup is against the fingerprints of the last batch so an identical repeating line is not
    re-sent every cycle. Never raises."""
    try:
        lines = read_error_log(state, cfg.get("ERROR_LOG") or "", lambda text: account_abnormal(state, text))
    except Exception as e:  # noqa: BLE001 - log shipping must never break the agent
        log.debug("collect error log failed: %s", e)
        lines = []
    lines.extend(AGENT_LOGS.drain())
    if not lines:
        return []
    seen_prev = set(state.get("logs_seen") or [])
    out, fps = [], []
    for ln in lines:
        fp = f"{ln['level']}|{ln['msg']}"
        if fp in seen_prev or fp in fps:
            continue
        fps.append(fp)
        out.append(ln)
    # keep only the newest LOG_MAX_PER_REPORT lines
    out = out[-LOG_MAX_PER_REPORT:]
    # remember the fingerprints we just shipped so an identical repeat next cycle is skipped
    state["logs_seen"] = [f"{ln['level']}|{ln['msg']}" for ln in out][-LOG_MAX_PER_REPORT:]
    return out
