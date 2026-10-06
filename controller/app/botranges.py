"""Verified search-engine crawler IP ranges for bot management (SPEC §14.2).

The scheduler leader fetches the IP ranges Google and Bing publish for their crawlers once a day
(and right away when none are stored yet), validates them and keeps the last good list per source
in the `state` table. A failed fetch keeps the last good list; when a source could not be refreshed
for BOT_RANGES_STALE_DAYS a warning alert opens. The edges get the lists node-wide (edge config
`bots: {"verified": {"google": [cidr...], "bing": [...]}, "fetched_at": ...}`) and treat a request
as a verified crawler only when its IP is in that source's ranges AND its User-Agent matches.

Outbound requests go through httpx like the alerts do, so HTTPS_PROXY / ALL_PROXY apply. Tests
inject `fetcher` (or pass `fetch=`) — nothing here touches the network in the test suite.
"""

import ipaddress
import json
import logging
from collections.abc import Callable
from datetime import datetime, timedelta

import httpx

from . import alerts
from .config import settings
from .models import State, utcnow

log = logging.getLogger("pcdn.bots")

SOURCES = {
    "google": "https://developers.google.com/static/search/apis/ipranges/googlebot.json",
    "bing": "https://www.bing.com/toolbox/bingbot.json",
}
STATE_KEY = "bots:verified"
ALERT_PREFIX = "bot_ranges:"
REFRESH = timedelta(days=1)
RETRY = timedelta(hours=2)  # after a failed (or partial) refresh
MAX_PREFIXES = 1000  # per source; a longer list is truncated (and logged)
# anything broader than this is not a crawler range: a bogus or tampered list must never mark
# large parts of the internet as "verified Googlebot"
MIN_PREFIXLEN = {4: 16, 6: 32}
FETCH_TIMEOUT = 15.0
MAX_BYTES = 2_000_000

# tests inject a fetcher(url) -> parsed JSON document here; None = real HTTP
fetcher: Callable[[str], object] | None = None


def _http_fetch(url: str) -> object:
    with httpx.Client(timeout=FETCH_TIMEOUT, follow_redirects=True,
                      headers={"User-Agent": "pasargad-cdn-controller (bot ranges)"}) as client:
        r = client.get(url)
        r.raise_for_status()
        if len(r.content) > MAX_BYTES:
            raise ValueError(f"response larger than {MAX_BYTES} bytes")
        return r.json()


def parse(doc: object) -> list[str]:
    """`prefixes[].ipv4Prefix / ipv6Prefix` -> sorted, de-duplicated, validated CIDRs (capped).
    Raises ValueError when the document has no usable prefix (the last good list is then kept)."""
    if not isinstance(doc, dict) or not isinstance(doc.get("prefixes"), list):
        raise ValueError("unexpected document: no `prefixes` list")
    nets: dict[str, ipaddress.IPv4Network | ipaddress.IPv6Network] = {}
    dropped = 0
    for p in doc["prefixes"]:
        if not isinstance(p, dict):
            dropped += 1
            continue
        for k in ("ipv4Prefix", "ipv6Prefix"):
            v = p.get(k)
            if v is None:
                continue
            try:
                net = ipaddress.ip_network(str(v).strip(), strict=False)
            except ValueError:
                dropped += 1
                continue
            if net.prefixlen < MIN_PREFIXLEN[net.version] or not net.is_global:
                dropped += 1
                continue
            nets[str(net)] = net
    if dropped:
        log.warning("bot ranges: ignored %d invalid / too broad / non-public prefix(es)", dropped)
    if not nets:
        raise ValueError("no valid prefix in the document")
    out = [str(n) for n in sorted(nets.values(), key=lambda n: (n.version, int(n.network_address), n.prefixlen))]
    if len(out) > MAX_PREFIXES:
        log.warning("bot ranges: %d prefixes, keeping the first %d", len(out), MAX_PREFIXES)
        out = out[:MAX_PREFIXES]
    return out


def load(db) -> dict:
    row = db.get(State, STATE_KEY)
    if row is None:
        return {}
    try:
        doc = json.loads(row.value)
    except ValueError:
        return {}
    return doc if isinstance(doc, dict) else {}


def _save(db, doc: dict):
    row = db.get(State, STATE_KEY)
    value = json.dumps(doc, sort_keys=True)
    if row is None:
        db.add(State(key=STATE_KEY, value=value))
    else:
        row.value = value


def _parse_dt(v) -> datetime | None:
    try:
        return datetime.fromisoformat(v) if v else None
    except (TypeError, ValueError):
        return None


def due(state: dict, now: datetime) -> bool:
    attempt = _parse_dt(state.get("attempt_at"))
    if attempt is None:
        return True  # never fetched (first start): right away
    srcs = state.get("sources") or {}
    complete = all(n in srcs for n in SOURCES) and not state.get("errors")
    return now - attempt >= (REFRESH if complete else RETRY)


def refresh(db, now: datetime | None = None, force: bool = False,
            fetch: Callable[[str], object] | None = None) -> dict:
    """Fetch every source when due (or forced); keep the last good list of a source that fails.
    Never raises for a fetch/parse failure. Commits."""
    now = now or utcnow()
    state = load(db)
    if not force and not due(state, now):
        _stale_alerts(state, now)
        return state
    fetch = fetch or fetcher or _http_fetch
    db.rollback()  # no transaction is held open across the network calls
    sources = dict(state.get("sources") or {})
    errors: dict[str, str] = {}
    for name, url in SOURCES.items():
        try:
            cidrs = parse(fetch(url))
        except Exception as e:  # noqa: BLE001 - a bad fetch never breaks the scheduler
            errors[name] = f"{type(e).__name__}: {e}"[:300]
            log.warning("bot ranges: fetching %s failed (keeping the last good list): %s", name, errors[name])
            continue
        if cidrs != (sources.get(name) or {}).get("cidrs"):
            log.info("bot ranges: %s now has %d prefixes", name, len(cidrs))
        sources[name] = {"cidrs": cidrs, "fetched_at": now.isoformat()}
    new = {"sources": sources, "errors": errors, "attempt_at": now.isoformat(),
           "first_attempt_at": state.get("first_attempt_at") or now.isoformat()}
    _save(db, new)
    db.commit()
    _stale_alerts(new, now)
    return new


def _stale_alerts(state: dict, now: datetime):
    days = settings.bot_ranges_stale_days
    active = {}
    if days > 0 and state:
        srcs = state.get("sources") or {}
        first = _parse_dt(state.get("first_attempt_at"))
        stale = []
        for name in SOURCES:
            last = _parse_dt((srcs.get(name) or {}).get("fetched_at")) or first
            if last is not None and now - last > timedelta(days=days):
                stale.append(name)
        if stale:
            errs = state.get("errors") or {}
            detail = "\n".join(f"- {n}: {errs.get(n, '')}" for n in stale)
            active[ALERT_PREFIX + "stale"] = (
                "فهرست IP ربات‌های تأییدشده به‌روز نمی‌شود",
                f"کنترلر بیش از {days} روز است که نتوانسته فهرست IP خزنده‌های {', '.join(stale)} را دریافت کند؛ "
                f"آخرین فهرست سالم همچنان به لبه‌ها فرستاده می‌شود. دسترسی کنترلر به اینترنت (یا HTTPS_PROXY) "
                f"را بررسی کنید.\n{detail}",
                "warning")
    alerts.sync(ALERT_PREFIX, active, lambda c: "فهرست IP ربات‌های تأییدشده دوباره به‌روز شد.")


def edge_block(db) -> dict:
    """Node-wide `bots` block of the edge config. `fetched_at` is the oldest successful fetch of
    the listed sources (ISO 8601 UTC) or null when nothing was ever fetched."""
    srcs = load(db).get("sources") or {}
    verified = {n: list(srcs[n]["cidrs"]) for n in SOURCES
                if isinstance(srcs.get(n), dict) and srcs[n].get("cidrs")}
    fetched = sorted(srcs[n]["fetched_at"] for n in verified if srcs[n].get("fetched_at"))
    return {"verified": verified, "fetched_at": fetched[0] + "Z" if fetched else None}
