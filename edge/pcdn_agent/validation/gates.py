"""Visitor gates of wave 10: the waiting room (SPEC §18.1) and access apps (SPEC §18.2).

The controller validates both sections; the edge checks them again before anything reaches
sites.js (defence in depth, mirroring the SPEC limits). A waiting room that does not validate is
skipped with a log line (fail open: no queue). An access app is never silently dropped while its
paths are usable: an app whose other settings are broken, or a site without a usable
access_secret, keeps its paths protected and admits only the app's IP ranges (fail closed).
Nothing here raises on bad input."""

import hashlib
import hmac
import ipaddress
import re
import urllib.parse

from ..common import _int, _sec
from ..settings import log

# ---- controller wire names (the one place to change if the controller's contract differs)
WR_SECTION = "waiting_room"           # site section
ACCESS_SECTION = "access"             # site section
SECTION_SECRET = "secret"             # in both sections: 64 hex (32 raw bytes, the HMAC key)
WR_SECRET = "wr_secret"               # legacy / fallback site-level keys of the same secrets
ACCESS_SECRET = "access_secret"
WR_NODE_MAX = "node_max"              # this node's share of max_active (controller computed)

# ---- SPEC limits
WR_PATHS_MAX = 20
WR_BYPASS_PATHS_MAX = 20
WR_BYPASS_IPS_MAX = 50
WR_MAX_ACTIVE = 1_000_000
WR_TEXT_MAX = 500
WR_SESSION_MIN = (1, 120, 10)          # lo, hi, default (minutes)
ACCESS_APPS_MAX = 20
ACCESS_PATHS_MAX = 20
ACCESS_EMAILS_MAX = 200
ACCESS_IPS_MAX = 100
ACCESS_SESSION_H = (1, 720, 24)        # lo, hi, default (hours)
ACCESS_METHODS = ("otp", "ip", "otp_or_ip")

# ---- OTP (SPEC §18.2, controller contract): d = HMAC-SHA256(bytes.fromhex(secret),
#      "otp|" + app + "|" + lower(trim(email)) + "|" + str(window)), RFC 4226 dynamic truncation
#      (offset = d[31] & 0x0f, 31 bits big-endian from there) mod 10^6, zero-padded; window =
#      floor(unix / 300); the current and the previous window are accepted.
#      pcdn.js (OTP_* constants, otpCode) computes the same; keep both in step.
OTP_PREFIX = "otp"
OTP_WINDOW_S = 300
OTP_DIGITS = 6
OTP_WINDOWS = 2

SAFE_GATE_PATH = re.compile(r"^/[A-Za-z0-9._~%/+,=:@!&()*'-]{0,255}$")
SAFE_APP_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
SAFE_HEX_SECRET = re.compile(r"^(?:[0-9a-fA-F]{2}){16,64}$")
EMAIL_RE = re.compile(r"^[a-z0-9._%+'-]{1,64}@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
EMAIL_DOMAIN_RE = re.compile(r"^@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_CTRL = re.compile(r"[\x00-\x1f\x7f]")


def access_otp(secret_hex: str, app: str, email: str, window: int) -> str:
    """The 6-digit code of (app, email) in OTP window `window` (parity with the controller)."""
    msg = f"{OTP_PREFIX}|{app}|{email.strip().lower()}|{int(window)}".encode()
    d = hmac.new(bytes.fromhex(secret_hex), msg, hashlib.sha256).digest()
    off = d[31] & 0x0F
    return str((int.from_bytes(d[off:off + 4], "big") & 0x7FFFFFFF) % 10 ** OTP_DIGITS).zfill(OTP_DIGITS)


def access_email_hash(secret_hex: str, email: str) -> str:
    """`access_events` email_hash: first 16 hex of HMAC-SHA256(secret, "email|" + lower(email))."""
    return hmac.new(bytes.fromhex(secret_hex), f"email|{email.strip().lower()}".encode(), hashlib.sha256).hexdigest()[:16]


def _hex_secret(site: dict, key: str, section: dict) -> str | None:
    v = section.get(SECTION_SECRET)
    if v is None:
        v = site.get(key)
    v = str(v or "").strip()
    return v.lower() if SAFE_HEX_SECRET.match(v) else None


def _prefixes(v, cap: int, what: str, sid) -> list | None:
    """Validated path prefixes (no /__pcdn/, deduplicated); None when not a list or over the cap."""
    if not isinstance(v, list) or len(v) > cap:
        log.warning("site %s: %s: not a list of at most %d paths", sid, what, cap)
        return None
    out = []
    for p in v:
        p = str(p) if isinstance(p, str) else ""
        if SAFE_GATE_PATH.match(p):
            p = urllib.parse.unquote(p)   # njs compares with nginx's decoded $uri
        if (not p.startswith("/") or len(p) > 256 or _CTRL.search(p) or "\\" in p or "//" in p
                or "/../" in p or "/./" in p or p.endswith(("/..", "/."))):
            log.warning("site %s: %s: path %r skipped", sid, what, str(p)[:80])
            continue
        if p.lower().startswith("/__pcdn"):
            continue   # /__pcdn/ paths are never gated
        if p not in out:
            out.append(p)
    return out


def _cidrs(v, cap: int, what: str, sid) -> list | None:
    if v is None:
        return []
    if not isinstance(v, list) or len(v) > cap:
        log.warning("site %s: %s: not a list of at most %d CIDRs", sid, what, cap)
        return None
    out = []
    for c in v:
        try:
            n = ipaddress.ip_network(str(c).strip(), strict=False)
        except ValueError:
            log.warning("site %s: %s: CIDR %r skipped", sid, what, str(c)[:60])
            continue
        if str(n) not in out:
            out.append(str(n))
    return out


def _text(v) -> str:
    """Plain text of the queue page (njs escapes it): control characters dropped, ≤ WR_TEXT_MAX."""
    if not isinstance(v, str):
        return ""
    return _CTRL.sub(" ", v).strip()[:WR_TEXT_MAX]


def norm_waiting_room(site: dict) -> dict | None:
    """SPEC §18.1 -> the sites.js `waiting_room` entry, or None (absent / disabled / mode off /
    invalid: logged and skipped, which means no queue).
    {paths, max (this node's limit), session_s, secret, page: {title_fa, title_en, message_fa,
    message_en}, bypass: {bots, paths, ips}}"""
    w = site.get(WR_SECTION)
    if not isinstance(w, dict) or w.get("enabled") is not True or w.get("mode", "queue") != "queue":
        return None
    sid = site.get("id")
    secret = _hex_secret(site, WR_SECRET, w)
    if not secret:
        log.warning("site %s: waiting room skipped: no valid secret", sid)
        return None
    raw_max = w.get(WR_NODE_MAX, w.get("max_active"))
    if isinstance(raw_max, bool) or not isinstance(raw_max, int) or not 1 <= raw_max <= WR_MAX_ACTIVE:
        log.warning("site %s: waiting room skipped: invalid %s %r", sid, WR_NODE_MAX, raw_max)
        return None
    sm = w.get("session_minutes", WR_SESSION_MIN[2])
    if isinstance(sm, bool) or not isinstance(sm, int) or not WR_SESSION_MIN[0] <= sm <= WR_SESSION_MIN[1]:
        log.warning("site %s: waiting room skipped: invalid session_minutes %r", sid, sm)
        return None
    paths = _prefixes(w.get("paths", ["/"]), WR_PATHS_MAX, "waiting_room.paths", sid)
    if not paths:
        log.warning("site %s: waiting room skipped: no usable paths", sid)
        return None
    by = w.get("bypass") if isinstance(w.get("bypass"), dict) else {}
    bpaths = _prefixes(by.get("paths", []), WR_BYPASS_PATHS_MAX, "waiting_room.bypass.paths", sid)
    bips = _cidrs(by.get("ips", []), WR_BYPASS_IPS_MAX, "waiting_room.bypass.ips", sid)
    if bpaths is None or bips is None:
        log.warning("site %s: waiting room skipped: invalid bypass", sid)
        return None
    qp = _sec(w, "queue_page")
    return {"paths": paths, "max": raw_max, "session_s": sm * 60, "secret": secret,
            "page": {k: _text(qp.get(k)) for k in ("title_fa", "title_en", "message_fa", "message_en")},
            "bypass": {"bots": by.get("verified_bots", True) is not False, "paths": bpaths, "ips": bips}}


def _email_entries(v, sid, app_id) -> list | None:
    if not isinstance(v, list):
        return None if v is not None else []
    out = []
    for e in v[:ACCESS_EMAILS_MAX]:
        e = str(e).strip().lower() if isinstance(e, str) else ""
        if (EMAIL_RE.match(e) or EMAIL_DOMAIN_RE.match(e)) and len(e) <= 254:
            if e not in out:
                out.append(e)
        else:
            log.warning("site %s: access app %s: email entry %r skipped", sid, app_id, e[:80])
    if len(v) > ACCESS_EMAILS_MAX:
        log.warning("site %s: access app %s: only the first %d emails are used", sid, app_id, ACCESS_EMAILS_MAX)
    return out


def _overlaps(a: str, b: str) -> bool:
    a, b = a.lower(), b.lower()
    return a.startswith(b) or b.startswith(a)


def norm_access(site: dict) -> dict | None:
    """SPEC §18.2 -> the sites.js `access` entry, or None (absent / disabled / no app).
    {secret: hex | "", apps: [{id, name, paths, methods, emails, ips, session_s}]}
    methods "none" = the app could not be validated: its paths stay protected and only its IP ranges
    are admitted. Enabled without a usable secret: every app denies everyone (fail closed, controller
    contract). Paths overlapping an earlier app are dropped."""
    a = site.get(ACCESS_SECTION)
    if not isinstance(a, dict) or a.get("enabled") is not True:
        return None
    sid = site.get("id")
    secret = _hex_secret(site, ACCESS_SECRET, a) or ""
    apps_in = a.get("apps")
    if not isinstance(apps_in, list) or not apps_in:
        return None
    if len(apps_in) > ACCESS_APPS_MAX:
        log.warning("site %s: access: only the first %d apps are used", sid, ACCESS_APPS_MAX)
    apps, seen_ids, taken = [], set(), []
    for i, app in enumerate(apps_in[:ACCESS_APPS_MAX]):
        if not isinstance(app, dict):
            log.warning("site %s: access app #%d skipped: not an object", sid, i)
            continue
        raw_paths = app.get("paths")
        if isinstance(raw_paths, list) and len(raw_paths) > ACCESS_PATHS_MAX:
            raw_paths = raw_paths[:ACCESS_PATHS_MAX]   # protect what we can rather than nothing
            log.warning("site %s: access app #%d: only the first %d paths are used", sid, i, ACCESS_PATHS_MAX)
        paths = _prefixes(raw_paths, ACCESS_PATHS_MAX, f"access app #{i} paths", sid) or []
        keep = []
        for p in paths:
            if any(_overlaps(p, q) for q in taken):
                log.warning("site %s: access app #%d: path %s overlaps another app; skipped", sid, i, p)
                continue
            keep.append(p)
        if not keep:
            log.warning("site %s: access app #%d skipped: no usable paths", sid, i)
            continue
        taken += keep
        aid = str(app.get("id") or "").lower()
        bad = []
        if not SAFE_APP_ID.match(aid) or aid in seen_ids:
            bad.append("id")
            aid = f"app{i}"
            while aid in seen_ids:
                aid += "x"
        seen_ids.add(aid)
        methods = app.get("methods", "otp")
        if methods not in ACCESS_METHODS:
            bad.append("methods")
        emails = _email_entries(app.get("emails"), sid, aid)
        if emails is None:
            bad.append("emails")
            emails = []
        raw_ips = app.get("ips")
        if isinstance(raw_ips, list) and len(raw_ips) > ACCESS_IPS_MAX:
            raw_ips = raw_ips[:ACCESS_IPS_MAX]
            log.warning("site %s: access app %s: only the first %d IP ranges are used", sid, aid, ACCESS_IPS_MAX)
        ips = _cidrs(raw_ips, ACCESS_IPS_MAX, f"access app {aid} ips", sid)
        if ips is None:
            bad.append("ips")
            ips = []
        sh = app.get("session_hours", ACCESS_SESSION_H[2])
        if isinstance(sh, bool) or not isinstance(sh, int) or not ACCESS_SESSION_H[0] <= sh <= ACCESS_SESSION_H[1]:
            bad.append("session_hours")
            sh = ACCESS_SESSION_H[2]
        if bad:
            log.warning("site %s: access app %s: invalid %s; its paths admit only its IP ranges",
                        sid, aid, ", ".join(bad))
            methods = "none"
        if not secret:
            log.warning("site %s: access app %s: no valid secret; its paths are closed", sid, aid)
            methods, ips = "none", []
        name = _CTRL.sub(" ", str(app.get("name") or aid)).strip()[:100] or aid
        apps.append({"id": aid, "name": name, "paths": keep, "methods": methods, "emails": emails,
                     "ips": ips, "session_s": _int(sh, 24, 1, 720) * 3600})
    if not apps:
        return None
    return {"secret": secret, "apps": apps}


def gate_sites(config: dict) -> dict:
    """{"wr": [domains of sites with a waiting room], "access": [domains of sites with access apps]}
    of the active sites (agent state: the heartbeat's per-site waiting-room state)."""
    wr, acc = set(), set()
    for s in config.get("sites", []) if isinstance(config, dict) else []:
        if not isinstance(s, dict) or s.get("status", "active") in ("suspended", "over_quota"):
            continue
        dom = str(s.get("domain") or "").lower()
        if not dom or len(dom) > 253:
            continue
        if isinstance(s.get(WR_SECTION), dict) and s[WR_SECTION].get("enabled") is True:
            wr.add(dom)
        if isinstance(s.get(ACCESS_SECTION), dict) and s[ACCESS_SECTION].get("enabled") is True:
            acc.add(dom)
    return {"wr": sorted(wr), "access": sorted(acc)}
