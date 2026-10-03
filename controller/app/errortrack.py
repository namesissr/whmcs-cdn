"""Error tracking (SPEC §18.4, opt-in).

* ``init_sentry()`` (main.py lifespan): only when SENTRY_DSN is set; sentry-sdk is imported lazily so
  the package stays optional. ``send_default_pii=False``, request bodies never attached, and every
  event / breadcrumb passes ``scrub_event`` first.
* ``scrub_event``: removes Authorization / Cookie / Set-Cookie / Proxy-Authorization / X-*-Token /
  X-*-Key headers, cookies, query strings (request + every URL in the event), request bodies, the
  environment, and replaces any value under a key that looks like key/secret/token/password, plus
  ``Bearer …``, ``pcdn_…`` keys and ``password=…``-style fragments inside strings.
* ``POST /api/v1/client-errors`` (admin key, the WHMCS module proxy forwards the client app's
  errors): counted per page in ``pcdn_client_errors_total{page}`` (bounded label set: PAGES or
  "other") and forwarded to Sentry when configured.
"""

import logging
import re

from sqlalchemy.orm import Session

from .config import settings
from .models import State

log = logging.getLogger("pcdn")

FILTERED = "[Filtered]"
MAX_DEPTH = 12
SENSITIVE_KEY_RE = re.compile(r"(passw|secret|token|api[_-]?key|apikey|authorization|cookie|session|dsn|"
                              r"private|credential|signature|^key$|_key$|-key$)", re.I)
SENSITIVE_HEADER_RE = re.compile(r"^(authorization|proxy-authorization|cookie|set-cookie|x-.*-(token|key|secret)|"
                                 r"x-(api|auth)-.*)$", re.I)
_VALUE_RES = (
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+"), r"\1 " + FILTERED),
    (re.compile(r"\bpcdn_[A-Za-z0-9_-]+"), FILTERED),
    (re.compile(r"\bwhsec_[A-Za-z0-9]+"), FILTERED),
    (re.compile(r"(?i)\b([a-z0-9_-]*(?:passw(?:or)?d|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)"
                r"[a-z0-9_-]*)(\"?\s*[:=]\s*\"?)[^\s\"'&,;]+"), r"\1\2" + FILTERED),
    (re.compile(r"(https?://[^\s?#\"']+)\?[^\s#\"']*"), r"\1?" + FILTERED),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), FILTERED),
)

_enabled = False


def scrub_string(v: str) -> str:
    for rx, repl in _VALUE_RES:
        v = rx.sub(repl, v)
    return v


def _scrub(v, depth: int = 0):
    if depth > MAX_DEPTH:
        return FILTERED
    if isinstance(v, dict):
        return {k: (FILTERED if isinstance(k, str) and SENSITIVE_KEY_RE.search(k) and v[k] not in (None, "", [], {})
                    else _scrub(x, depth + 1)) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_scrub(x, depth + 1) for x in v]
    if isinstance(v, str):
        return scrub_string(v)
    return v


def _scrub_request(req: dict) -> dict:
    req = dict(req)
    headers = req.get("headers")
    if isinstance(headers, dict):
        req["headers"] = {k: v for k, v in headers.items() if not SENSITIVE_HEADER_RE.match(str(k))}
    elif isinstance(headers, list):  # [[name, value], ...]
        req["headers"] = [h for h in headers if not (isinstance(h, (list, tuple)) and h
                                                    and SENSITIVE_HEADER_RE.match(str(h[0])))]
    for k in ("cookies", "data", "query_string", "env"):
        req.pop(k, None)
    if isinstance(req.get("url"), str):
        req["url"] = req["url"].split("?", 1)[0].split("#", 1)[0]
    return req


def scrub_event(event, hint=None):
    """Sentry before_send / before_breadcrumb hook: the event without secrets or PII (never None,
    so errors are still reported)."""
    if not isinstance(event, dict):
        return event
    event = dict(event)
    if isinstance(event.get("request"), dict):
        event["request"] = _scrub_request(event["request"])
    event.pop("user", None)
    if isinstance(event.get("extra"), dict):
        event["extra"].pop("sys.argv", None)
    return _scrub(event)


def scrub_breadcrumb(crumb, hint=None):
    if isinstance(crumb, dict) and isinstance(crumb.get("data"), dict):
        crumb = dict(crumb, data={k: v for k, v in crumb["data"].items() if k not in ("query", "body")})
    return _scrub(crumb)


def init_sentry() -> bool:
    """Initialise sentry-sdk when SENTRY_DSN is set; False when off or the package is missing."""
    global _enabled
    if not settings.sentry_dsn:
        return False
    try:
        import sentry_sdk
    except ImportError:
        log.warning("SENTRY_DSN is set but sentry-sdk is not installed; error tracking stays off")
        return False
    sentry_sdk.init(dsn=settings.sentry_dsn, environment=settings.sentry_environment,
                    traces_sample_rate=settings.sentry_traces_sample_rate, send_default_pii=False,
                    max_request_body_size="never", include_local_variables=False,
                    before_send=scrub_event, before_send_transaction=scrub_event,
                    before_breadcrumb=scrub_breadcrumb)
    _enabled = True
    log.info("error tracking (Sentry) enabled, environment %s", settings.sentry_environment)
    return True


def enabled() -> bool:
    return _enabled


# ------------------------------------------------------------------ client errors (WHMCS client app)

# the client app's pages; anything else is counted as "other" (bounded Prometheus label set)
PAGES = ("overview", "dashboard", "dns", "ssl", "cache", "firewall", "waf", "ratelimit", "rules", "redirects",
         "transform", "bots", "pagerules", "pools", "tunnel", "analytics", "live", "events", "logs", "webhooks",
         "functions", "storage", "l4", "video", "images", "settings", "api", "statement", "audit", "access",
         "waiting_room", "speedtest", "reseller", "pricing", "referral", "status")
STATE_PREFIX = "metrics:client_errors:"


def page_label(page) -> str:
    p = str(page or "").strip().lower().replace("-", "_")
    return p if p in PAGES else "other"


def count_client_error(db: Session, page: str) -> None:
    """+1 on the page's counter (State table, shared by every controller instance). Caller commits."""
    key = STATE_PREFIX + page
    row = db.get(State, key)
    if row is None:
        db.add(State(key=key, value="1"))
    else:
        try:
            row.value = str(int(row.value or "0") + 1)
        except ValueError:
            row.value = "1"


def client_error_counts(db: Session) -> dict[str, int]:
    from sqlalchemy import select

    out = {}
    for key, value in db.execute(select(State.key, State.value).where(State.key.like(STATE_PREFIX + "%"))).all():
        page = key[len(STATE_PREFIX):]
        if page in PAGES or page == "other":
            try:
                out[page] = int(value or 0)
            except ValueError:
                continue
    return out


def forward_client_error(page: str, data: dict) -> None:
    """Send the (scrubbed) client error to Sentry when it is configured; never raises."""
    if not _enabled:
        return
    try:
        import sentry_sdk

        with sentry_sdk.new_scope() as scope:
            scope.set_tag("source", "whmcs-client")
            scope.set_tag("page", page)
            scope.set_context("client_error", _scrub({k: data.get(k) for k in ("source", "line", "col", "stack", "ua")}))
            sentry_sdk.capture_message(scrub_string(str(data.get("message") or "client error"))[:1000], level="error")
    except Exception:  # noqa: BLE001 - error tracking never breaks the caller
        log.exception("forwarding a client error to Sentry failed")
