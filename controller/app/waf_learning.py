"""WAF learning mode (SPEC §17): observe in log mode, propose, never apply on its own.

* `waf.learning` {enabled, days 1..30} is the customer's input; `started_at` / `until` are managed
  here (`manage`, called by sections.validate_section) and the scheduler ends an expired window
  (`end_expired`, state `learned`).
* While a site learns, every edge adds an optional `waf_learn` object to its hourly usage items
  (`WafLearn` below validates and bounds it; it is merged into usage_hourly.details["waf_learn"]).
* `report` aggregates the learning window and derives the proposals of SPEC §17.2; `apply` applies
  chosen proposals through the normal section validation. Proposal ids are a hash of kind + target,
  so they are stable across reads and an applied proposal stays listed with `applied: true`
  (applying it again is a no-op).
"""

import hashlib
import json
import math
import re
from datetime import datetime, timedelta, timezone
from typing import Annotated

from pydantic import AliasChoices, BaseModel, Field, field_validator
from sqlalchemy import select

from .models import UsageHourly, utcnow

BIG = 10**18
Counter = Annotated[int, Field(ge=0, le=BIG)]

# ingestion bounds per usage item (SPEC §17.1) — beyond them the least busy keys are dropped
MAX_RULES = 100
MAX_RULE_PATHS = 10
MAX_METHODS = 10
MAX_PATHS = 50
# bounds of one stored hourly row (several batches of the same edge-hour are merged into it)
ROW_CAPS = {"rules": MAX_RULES, "rule_paths": MAX_RULE_PATHS, "methods": MAX_METHODS, "paths": MAX_PATHS}
# bounds of the aggregate over the whole learning window
AGG_CAPS = {"rules": 1000, "rule_paths": 100, "methods": 20, "paths": 1000}

RULE_ID_RE = re.compile(r"^[0-9]{1,7}$")  # WafExclusion.rule_id: 1..9999999 (0 = all rules: never)
METHOD_RE = re.compile(r"^[A-Z]{1,10}$")
# a path prefix: the first (at most) two segments of the URL path, no query, no wildcard; the
# characters are a subset of sections.PATH_PATTERN_RE, so a pattern built from it always validates
PREFIX_RE = re.compile(r"^/[A-Za-z0-9\-._~%!$&'()+,;=:@/]{0,255}$")

# SPEC §17.2 thresholds
EXCL_MIN_RATIO = 0.005      # rule hits / requests to the path prefix
EXCL_MIN_CLIENTS = 20       # distinct clients
RL_MIN_REQUESTS = 1000      # requests to the path prefix over the window
RL_P95_FACTOR = 3
RL_MAX_FACTOR = 1.5
RL_FLOOR = 30               # requests per minute
RL_CEIL = 1_000_000         # RateRule.requests upper bound

# managed pack rule-id ranges (edge/njs/pcdn.js WAF_PACK_VERSION): generic 990xxx … api 995xxx
PACK_RANGES = {"generic": 990000, "wordpress": 991000, "joomla": 992000, "drupal": 993000,
               "laravel": 994000, "api": 995000}


# ------------------------------------------------------------------ time helpers

def parse_iso(v) -> datetime | None:
    """ISO 8601 -> naive UTC datetime, None when missing / unparsable."""
    if not isinstance(v, str) or not v.strip() or len(v) > 40:
        return None
    raw = v.strip()
    if raw[-1] in "Zz":
        raw = raw[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def fmt_iso(dt: datetime | None) -> str | None:
    return None if dt is None else dt.replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _hour(dt: datetime) -> datetime:
    return dt.replace(minute=0, second=0, microsecond=0)


# ------------------------------------------------------------------ section value (SPEC §17.2)

def _stored_learning(site) -> dict:
    from . import sections

    try:
        return sections.get_section(site, "waf").get("learning") or {}
    except Exception:  # noqa: BLE001 - a broken stored section = never learned
        return {}


def manage(site, value: dict, now: datetime | None = None) -> dict:
    """The waf section `value` (validated) with learning.started_at / until set by the controller
    from the stored section: off -> on starts a window of `days`; on -> on keeps it (a changed
    `days` moves `until` relative to started_at; a window already over ends now); on -> off stops
    it now (state learned); off -> off keeps the last window (learned) as stored."""
    now = (now or utcnow()).replace(microsecond=0)
    ln = dict(value.get("learning") or {})
    old = _stored_learning(site)
    o_start, o_until = parse_iso(old.get("started_at")), parse_iso(old.get("until"))
    was_on = bool(old.get("enabled")) and o_start is not None
    o_active = was_on and o_until is not None and o_until > now
    days = int(ln.get("days") or 7)
    if ln.get("enabled"):
        if o_active:
            start = o_start
            until = o_until if days == old.get("days") else start + timedelta(days=days)
            if until <= now:
                ln["enabled"], until = False, now
        elif was_on:  # expired, the scheduler has not ended it yet: it is over (learned)
            ln["enabled"], start, until = False, o_start, o_until
        else:
            start, until = now, now + timedelta(days=days)
    elif o_active:
        start, until = o_start, now
    else:
        start, until = o_start, o_until if o_start is not None else None
    ln.update(days=days, started_at=fmt_iso(start), until=fmt_iso(until))
    return {**value, "learning": ln}


def state_of(ln: dict, now: datetime | None = None) -> str:
    now = now or utcnow()
    start, until = parse_iso(ln.get("started_at")), parse_iso(ln.get("until"))
    if ln.get("enabled") and start is not None and until is not None and until > now:
        return "learning"
    return "learned" if start is not None else "off"


def edge_waf(waf: dict, feats: dict) -> dict:
    """The waf block of the edge config: learning reduced to SPEC §17.1 {enabled, until}; off when
    the plan has no WAF (the edge compares `until` with its clock itself)."""
    ln = waf.get("learning") or {}
    on = bool(ln.get("enabled")) and bool(feats.get("waf")) and parse_iso(ln.get("until")) is not None
    return {**waf, "learning": {"enabled": on, "until": ln.get("until") if on else None}}


def accepts(ln: dict, hour: datetime) -> bool:
    """Whether a `waf_learn` report for `hour` (naive UTC, start of the hour) belongs to the site's
    learning window (started_at's hour .. until); reports outside it are dropped."""
    start, until = parse_iso(ln.get("started_at")), parse_iso(ln.get("until"))
    if start is None or hour < _hour(start):
        return False
    return until is None or hour <= until


# ------------------------------------------------------------------ ingestion (SPEC §17.1)

def norm_prefix(p) -> str | None:
    """'/a/b/c?x' -> None (no query), '/a/b/c/' -> '/a/b', '/a/' -> '/a', '/' -> '/'; None when not
    a plain URL path (wildcards, dot segments, control characters, > 256 characters)."""
    if not isinstance(p, str) or not PREFIX_RE.match(p):
        return None
    segs = [s for s in p.split("/") if s]
    if any(s in (".", "..") for s in segs):
        return None
    return "/" + "/".join(segs[:2])


def _dict_or_fail(v, what: str) -> dict:
    if v is None:
        return {}
    if not isinstance(v, dict):
        raise ValueError(f"waf_learn.{what} must be an object")
    return v


def _methods(v) -> dict:
    """Method keys upper-cased; junk keys dropped. Values are validated by the field type (422)."""
    out = {}
    for k, n in _dict_or_fail(v, "methods").items():
        k = str(k).upper()
        if METHOD_RE.match(k):
            out[k] = n
    return out


def _top(d: dict, key, cap: int) -> dict:
    if len(d) <= cap:
        return d
    return dict(sorted(d.items(), key=lambda kv: (-key(kv[1]), kv[0]))[:cap])


class RulePath(BaseModel):
    """Hits of one rule under one path prefix. A bare integer is the hit count (SPEC §17.1)."""
    hits: Counter = 0
    clients: Counter = 0   # distinct client IPs (optional)
    attack: Counter = 0    # hits on requests that also carried another attack signal (optional)


class RuleLearn(BaseModel):
    hits: Counter = 0
    # optional: distinct client IPs that triggered the rule in this host-hour, and how many of the
    # hits were on requests that also carried another attack signal (another WAF rule of a different
    # group / pack, a bot / firewall / rate-limit / DDoS action)
    clients: Counter = 0
    attack: Counter = 0
    paths: dict[str, RulePath] = {}
    methods: dict[str, Counter] = {}

    @field_validator("paths", mode="before")
    @classmethod
    def _paths(cls, v):
        groups = _group(v, "rules.*.paths")
        return {p: cs[0] if len(cs) == 1 else _fold(RulePath, cs) for p, cs in groups.items()}

    @field_validator("paths", mode="after")
    @classmethod
    def _cap_paths(cls, v):
        return _top(v, lambda c: c.hits, MAX_RULE_PATHS)

    @field_validator("methods", mode="before")
    @classmethod
    def _m(cls, v):
        return _methods(v)

    @field_validator("methods", mode="after")
    @classmethod
    def _cap_m(cls, v):
        return _top(v, lambda n: n, MAX_METHODS)


class PathLearn(BaseModel):
    req: Counter = 0
    # max requests in one minute from a single client IP under this prefix. SPEC §17.1 names the key
    # `p95_rps_min` but defines its value as exactly this maximum ("keep it simple"), so it is read
    # as max_rpm; `max_ip_rpm` is accepted too (first present of max_rpm, max_ip_rpm, p95_rps_min)
    max_rpm: Counter = Field(0, validation_alias=AliasChoices("max_rpm", "max_ip_rpm", "p95_rps_min"))
    # optional: a real p95 of the per-client per-minute request counts under this prefix
    p95_rpm: Counter = 0
    methods: dict[str, Counter] = {}

    @field_validator("methods", mode="before")
    @classmethod
    def _m(cls, v):
        return _methods(v)

    @field_validator("methods", mode="after")
    @classmethod
    def _cap_m(cls, v):
        return _top(v, lambda n: n, MAX_METHODS)


class ClientsLearn(BaseModel):
    max_rpm: Counter = 0
    p95_rpm: Counter = 0


class WafLearn(BaseModel):
    """`waf_learn` of one host-hour usage item (SPEC §17.1). Unknown keys are ignored; malformed
    rule ids / path prefixes / methods are dropped and the busiest 100 rules / 50 prefixes / 10
    rule prefixes / 10 methods are kept, instead of rejecting the batch (it is informational).
    A counter of the wrong type or negative is a 422, like every other usage counter."""
    rules: dict[str, RuleLearn] = {}
    paths: dict[str, PathLearn] = {}
    clients: ClientsLearn | None = None

    @field_validator("rules", mode="before")
    @classmethod
    def _rules(cls, v):
        out = {}
        for k, c in _dict_or_fail(v, "rules").items():
            k = str(k).strip()
            if RULE_ID_RE.match(k) and int(k) > 0:
                out[str(int(k))] = c
        return out

    @field_validator("rules", mode="after")
    @classmethod
    def _cap_rules(cls, v):
        return _top(v, lambda r: r.hits, MAX_RULES)

    @field_validator("paths", mode="before")
    @classmethod
    def _paths(cls, v):
        groups = _group(v, "paths")
        return {p: cs[0] if len(cs) == 1 else _fold(PathLearn, cs) for p, cs in groups.items()}

    @field_validator("paths", mode="after")
    @classmethod
    def _cap_paths(cls, v):
        return _top(v, lambda c: c.req, MAX_PATHS)


def _group(v, what: str) -> dict[str, list]:
    """Raw entries by normalized prefix ('/a/b/c' and '/a/b/d' both fold into '/a/b'); entries
    whose key is not a plain path are dropped. A bare integer is a hit count."""
    groups: dict[str, list] = {}
    for k, c in _dict_or_fail(v, what).items():
        p = norm_prefix(k)
        if p is not None:
            groups.setdefault(p, []).append({"hits": c} if isinstance(c, int) and not isinstance(c, bool) else c)
    return groups


def _fold(model, items: list) -> dict:
    """Several raw entries of the same prefix, each validated (422 on a bad counter), merged:
    counts add up, distinct clients / per-minute rates keep the maximum."""
    out: dict = {}
    for c in items:
        d = model.model_validate(c).model_dump()
        for k, v in d.items():
            if k == "methods":
                m = out.setdefault("methods", {})
                for meth, n in v.items():
                    m[meth] = m.get(meth, 0) + n
            elif k in ("clients", "max_rpm", "p95_rpm"):
                out[k] = max(out.get(k, 0), v)
            else:
                out[k] = out.get(k, 0) + v
    return out


# ------------------------------------------------------------------ merging (stored / aggregate)

def _n(v) -> int:
    from .validation import num

    return num(v)


def _o(v) -> dict:
    return v if isinstance(v, dict) else {}


def _sum_into(dst: dict, src: dict, cap: int, key_ok) -> None:
    for k, v in _o(src).items():
        k = str(k)
        if not key_ok(k) or (k not in dst and len(dst) >= cap):
            continue
        dst[k] = _n(dst.get(k)) + _n(v)


def merge(current, add, caps: dict | None = None) -> dict:
    """Merge one `waf_learn` document into another (tolerant of malformed stored data): hit /
    request / attack counters add up; distinct clients and per-minute rates keep the maximum (a
    lower bound: the same client may appear in several edge-hours). New keys beyond the caps are
    dropped."""
    caps = caps or ROW_CAPS
    cur = current if isinstance(current, dict) else {}
    add = _o(add)
    rules = cur["rules"] = _o(cur.get("rules"))
    for rid, r in _o(add.get("rules")).items():
        rid = str(rid)
        if not RULE_ID_RE.match(rid) or not isinstance(r, dict):
            continue
        if rid not in rules and len(rules) >= caps["rules"]:
            continue
        d = rules[rid] = _o(rules.get(rid))
        d["hits"] = _n(d.get("hits")) + _n(r.get("hits"))
        d["attack"] = _n(d.get("attack")) + _n(r.get("attack"))
        d["clients"] = max(_n(d.get("clients")), _n(r.get("clients")))
        paths = d["paths"] = _o(d.get("paths"))
        for p, c in _o(r.get("paths")).items():
            c = {"hits": c} if not isinstance(c, dict) else c
            if norm_prefix(p) != p or (p not in paths and len(paths) >= caps["rule_paths"]):
                continue
            e = paths[p] = _o(paths.get(p))
            e["hits"] = _n(e.get("hits")) + _n(c.get("hits"))
            e["attack"] = _n(e.get("attack")) + _n(c.get("attack"))
            e["clients"] = max(_n(e.get("clients")), _n(c.get("clients")))
        d["methods"] = _o(d.get("methods"))
        _sum_into(d["methods"], r.get("methods"), caps["methods"], METHOD_RE.match)
    paths = cur["paths"] = _o(cur.get("paths"))
    for p, c in _o(add.get("paths")).items():
        if norm_prefix(p) != p or not isinstance(c, dict) or (p not in paths and len(paths) >= caps["paths"]):
            continue
        e = paths[p] = _o(paths.get(p))
        e["req"] = _n(e.get("req")) + _n(c.get("req"))
        e["max_rpm"] = max(_n(e.get("max_rpm")), _n(c.get("max_rpm")))
        e["p95_rpm"] = max(_n(e.get("p95_rpm")), _n(c.get("p95_rpm")))
        e["methods"] = _o(e.get("methods"))
        _sum_into(e["methods"], c.get("methods"), caps["methods"], METHOD_RE.match)
    cl = _o(add.get("clients"))
    if cl:
        dst = cur["clients"] = _o(cur.get("clients"))
        for k in ("max_rpm", "p95_rpm"):
            dst[k] = max(_n(dst.get(k)), _n(cl.get(k)))
    return cur


# ------------------------------------------------------------------ report + proposals (SPEC §17.2)

def window(ln: dict, now: datetime | None = None) -> tuple[datetime, datetime] | None:
    now = now or utcnow()
    start, until = parse_iso(ln.get("started_at")), parse_iso(ln.get("until"))
    if start is None:
        return None
    end = min(until, now) if until is not None else now
    return start, max(start, end)


def aggregate(db, site, ln: dict, now: datetime | None = None) -> tuple[dict, int]:
    """(merged waf_learn of the learning window, requests observed in it)."""
    w = window(ln, now)
    if w is None:
        return {}, 0
    start, end = w
    agg: dict = {}
    total = 0
    q = select(UsageHourly.details, UsageHourly.requests).where(
        UsageHourly.site_id == site.id, UsageHourly.hour >= _hour(start), UsageHourly.hour <= end)
    for details, requests in db.execute(q):
        total += int(requests or 0)
        try:
            d = json.loads(details or "{}")
        except ValueError:
            continue
        if isinstance(d, dict) and isinstance(d.get("waf_learn"), dict):
            merge(agg, d["waf_learn"], AGG_CAPS)
    return agg, total


def proposal_id(kind: str, target: str) -> str:
    return "p_" + hashlib.sha256(f"{kind}:{target}".encode()).hexdigest()[:16]


def pattern_of(prefix: str, wildcard: bool = True) -> str:
    """The section path pattern of a learned prefix: '/' stays '/' (the home page only), else the
    prefix followed by '*' (everything under it)."""
    return prefix if prefix == "/" or not wildcard else prefix + "*"


def pack_of(rule_id: int) -> str | None:
    for pack, base in PACK_RANGES.items():
        if base <= rule_id < base + 1000:
            return pack
    return None


def _pct(x: float) -> str:
    return f"{x * 100:.2f}".rstrip("0").rstrip(".")


def _exclusion_candidates(agg: dict) -> list[dict]:
    paths = _o(agg.get("paths"))
    out = []
    for rid, r in _o(agg.get("rules")).items():
        rule_id = int(rid)
        rpaths = _o(r.get("paths"))
        # attack signals not attributed to any reported prefix: be conservative, no proposal
        unattributed = _n(r.get("attack")) - sum(_n(_o(c).get("attack")) for c in rpaths.values())
        for prefix, c in rpaths.items():
            hits, attack = _n(c.get("hits")), _n(c.get("attack"))
            req = _n(_o(paths.get(prefix)).get("req"))
            clients = _n(c.get("clients")) or _n(r.get("clients"))
            if hits <= 0 or req <= 0 or attack > 0 or unattributed > 0:
                continue
            ratio = min(1.0, hits / req)
            if ratio < EXCL_MIN_RATIO or clients < EXCL_MIN_CLIENTS:
                continue
            path = pattern_of(prefix)
            conf = 0.5 + 0.25 * min(1.0, (clients - EXCL_MIN_CLIENTS) / 80) + 0.25 * min(1.0, ratio / 0.05)
            out.append({
                "id": proposal_id("waf_exclusion", f"{rule_id}|{path}"),
                "kind": "waf_exclusion",
                "summary": (f"قانون WAF شمارهٔ {rule_id} روی مسیر {path} احتمالاً هشدار اشتباه است: "
                            f"{hits} بار در {req} درخواست ({_pct(ratio)}٪) از دست‌کم {clients} کاربر "
                            f"متفاوت، بدون هیچ نشانهٔ حملهٔ دیگری. پیشنهاد: استثنای این قانون روی این مسیر."),
                "detail": (f"Rule {rule_id} matched {hits} of {req} requests ({_pct(ratio)}%) under {prefix} "
                           f"from at least {clients} distinct clients with no other attack signal; "
                           f"propose excluding rule {rule_id} on {path}."),
                "confidence": round(conf, 2),
                "change": {"section": "waf", "op": "add_exclusion", "value": {"rule_id": rule_id, "path": path}},
                "evidence": {"rule_id": rule_id, "path_prefix": prefix, "hits": hits, "requests": req,
                             "ratio": round(ratio, 4), "clients": clients},
                "_hits": hits,
            })
    return out


def _rate_candidates(agg: dict) -> list[dict]:
    paths = _o(agg.get("paths"))
    out = []
    for prefix, c in paths.items():
        req, mx, p95 = _n(c.get("req")), _n(c.get("max_rpm")), _n(c.get("p95_rpm"))
        if req < RL_MIN_REQUESTS or (mx <= 0 and p95 <= 0):
            continue
        limit = max(RL_P95_FACTOR * p95, math.ceil(mx * RL_MAX_FACTOR), RL_FLOOR)
        limit = min(int(limit), RL_CEIL)
        # a one-segment prefix with deeper prefixes observed under it: only that path itself
        deeper = prefix != "/" and any(p.startswith(prefix + "/") for p in paths)
        path = pattern_of(prefix, wildcard=not deeper)
        pid = proposal_id("rate_limit", path)
        rule = {"id": "learn-" + pid[2:14], "enabled": True, "path": path, "methods": [], "requests": limit,
                "period": 60, "action": "challenge", "block_seconds": 60}
        conf = 0.5 + 0.4 * min(1.0, math.log10(req / RL_MIN_REQUESTS) / 2) + (0.1 if p95 > 0 else 0.0)
        out.append({
            "id": pid,
            "kind": "rate_limit",
            "summary": (f"محدودیت نرخ {limit} درخواست در دقیقه برای هر IP روی مسیر {path} با اقدام «چالش». "
                        f"در دورهٔ یادگیری {req} درخواست دیده شد؛ بیشترین نرخ یک کاربر {mx} و صدک ۹۵ "
                        f"{p95} درخواست در دقیقه بود."),
            "detail": (f"{req} requests under {prefix}; per-client max {mx} rpm, p95 {p95} rpm. Proposed limit "
                       f"max(3 x p95, 1.5 x max, 30) = {limit} requests per 60 s per client IP, action challenge."),
            "confidence": round(min(1.0, conf), 2),
            "change": {"section": "ratelimit", "op": "add_rule", "value": rule},
            "evidence": {"path_prefix": prefix, "requests": req, "max_rpm": mx, "p95_rpm": p95},
            "_hits": req,
        })
    return out


def _pack_candidates(agg: dict, excl: list[dict]) -> list[dict]:
    """A pack whose rules matched only traffic every hit of which is covered by exclusion proposals
    (no attack-like traffic at all) -> propose turning the pack off."""
    covered: dict[int, int] = {}
    confs: dict[int, list[float]] = {}
    for p in excl:
        rid = p["evidence"]["rule_id"]
        covered[rid] = covered.get(rid, 0) + p["evidence"]["hits"]
        confs.setdefault(rid, []).append(p["confidence"])
    by_pack: dict[str, list[tuple[int, dict]]] = {}
    for rid, r in _o(agg.get("rules")).items():
        pack = pack_of(int(rid))
        if pack and _n(r.get("hits")) > 0:
            by_pack.setdefault(pack, []).append((int(rid), r))
    out = []
    for pack, rules in sorted(by_pack.items()):
        if any(_n(r.get("attack")) > 0 or covered.get(rid, 0) < _n(r.get("hits")) for rid, r in rules):
            continue
        hits = sum(_n(r.get("hits")) for _, r in rules)
        conf = 0.9 * min(min(confs[rid]) for rid, _ in rules)
        ids = sorted(rid for rid, _ in rules)
        out.append({
            "id": proposal_id("pack_off", pack),
            "kind": "pack_off",
            "summary": (f"بستهٔ قوانین «{pack}» در دورهٔ یادگیری هیچ ترافیک حمله‌مانندی نگرفت و همهٔ "
                        f"{hits} تطبیق آن هشدار اشتباه بود؛ پیشنهاد: خاموش کردن این بسته."),
            "detail": (f"Pack {pack} matched {hits} requests (rules {', '.join(map(str, ids))}), all of them "
                       f"false-positive-like (covered by exclusion proposals, no attack signal); "
                       f"propose removing it from waf.packs."),
            "confidence": round(conf, 2),
            "change": {"section": "waf", "op": "remove_pack", "value": pack},
            "evidence": {"pack": pack, "hits": hits, "rules": ids},
            "_hits": hits,
        })
    return out


def _applied(p: dict, waf: dict, rl: dict) -> bool:
    ch = p["change"]
    if ch["op"] == "add_exclusion":
        v = ch["value"]
        return any(e["rule_id"] == v["rule_id"] and e.get("path") == v["path"] for e in waf["exclusions"])
    if ch["op"] == "add_rule":
        return any(r["id"] == ch["value"]["id"] for r in rl["rules"])
    if ch["op"] == "remove_pack":
        return ch["value"] not in waf["packs"]
    return False


def proposals(site, agg: dict) -> list[dict]:
    """The proposals of SPEC §17.2 for the aggregated learning data, against the site's current
    sections and plan: every not-yet-applied proposal, applied alone or together with the others,
    passes the section validation (plan limits respected; proposals already covered by the
    customer's own exclusion / rate-limit rule are left out)."""
    from . import sections

    feats = sections.features_of(site)
    waf, rl = sections.get_section(site, "waf"), sections.get_section(site, "ratelimit")
    out: list[dict] = []
    if feats["waf"]:
        excl = _exclusion_candidates(agg)
        packs = _pack_candidates(agg, excl)
        # exclusions the customer already has (all rules on the path, or the rule everywhere)
        excl = [p for p in excl if _applied(p, waf, rl) or not any(
            (e["rule_id"] in (0, p["change"]["value"]["rule_id"]))
            and (not e.get("path") or e["path"] == p["change"]["value"]["path"]) for e in waf["exclusions"])]
        free = 100 - len(waf["exclusions"])
        kept = []
        for p in sorted(excl, key=lambda p: (-p["_hits"], p["id"])):
            if _applied(p, waf, rl):
                kept.append(p)
            elif free > 0:
                kept.append(p)
                free -= 1
        out += kept
        out += packs
    rates = [p for p in _rate_candidates(agg) if _applied(p, waf, rl) or not any(
        r["path"] == p["change"]["value"]["path"] for r in rl["rules"])]
    free = feats["max_ratelimit_rules"] - len(rl["rules"])
    for p in sorted(rates, key=lambda p: (-p["_hits"], p["id"])):
        if _applied(p, waf, rl):
            out.append(p)
        elif free > 0:
            out.append(p)
            free -= 1
    for p in out:
        p["applied"] = _applied(p, waf, rl)
        p.pop("_hits", None)
    order = {"waf_exclusion": 0, "rate_limit": 1, "pack_off": 2}
    out.sort(key=lambda p: (order[p["kind"]], -p["confidence"], p["id"]))
    return out


def report(db, site, now: datetime | None = None) -> dict:
    from . import sections

    now = now or utcnow()
    ln = sections.get_section(site, "waf")["learning"]
    state = state_of(ln, now)
    agg, total = aggregate(db, site, ln, now) if state != "off" else ({}, 0)
    start, until = parse_iso(ln.get("started_at")), parse_iso(ln.get("until"))
    progress = 0.0
    if state == "learned":
        progress = 1.0
    elif state == "learning" and until > start:
        progress = min(1.0, max(0.0, (now - start) / (until - start)))
    return {"state": state, "enabled": bool(ln.get("enabled")) and state == "learning",
            "days": ln.get("days", 7), "started_at": ln.get("started_at"), "until": ln.get("until"),
            "progress": round(progress, 3), "requests_observed": total,
            "proposals": proposals(site, agg) if state != "off" else []}


class UnknownProposals(LookupError):
    def __init__(self, ids: list[str]):
        super().__init__(", ".join(ids))
        self.ids = ids


def apply(db, site, ids: list[str], now: datetime | None = None) -> dict:
    """Apply the chosen proposals through the normal section validation and store them in one
    commit. Proposals already applied are reported as `unchanged` (idempotent). Raises
    UnknownProposals, sections' PermissionError / ValidationError / pydantic.ValidationError."""
    from . import sections
    from .services import lock_site

    site = lock_site(db, site)
    by_id = {p["id"]: p for p in report(db, site, now)["proposals"]}
    ids = list(dict.fromkeys(ids))
    unknown = [i for i in ids if i not in by_id]
    if unknown:
        raise UnknownProposals(unknown)
    waf = sections.storable("waf", sections.get_section(site, "waf"))
    rl = sections.storable("ratelimit", sections.get_section(site, "ratelimit"))
    applied, unchanged, touched = [], [], set()
    for i in ids:
        p = by_id[i]
        if p["applied"]:
            unchanged.append(i)
            continue
        ch = p["change"]
        if ch["op"] == "add_exclusion":
            waf = {**waf, "exclusions": waf["exclusions"] + [dict(ch["value"])]}
        elif ch["op"] == "remove_pack":
            waf = {**waf, "packs": [k for k in waf["packs"] if k != ch["value"]]}
        elif ch["op"] == "add_rule":
            rl = {**rl, "rules": rl["rules"] + [dict(ch["value"])]}
        touched.add(ch["section"])
        applied.append(i)
    values = {}
    for name, value in (("waf", waf), ("ratelimit", rl)):
        if name in touched:
            values[name] = sections.validate_section(site, name, value)
    for name, value in values.items():
        sections.store_section(site, name, value)
    db.commit()
    return {"applied": applied, "unchanged": unchanged, "changed": sorted(values),
            "sections": {"waf": sections.get_section(site, "waf"),
                         "ratelimit": sections.get_section(site, "ratelimit")}}


# ------------------------------------------------------------------ scheduler (SPEC §17.2)

def end_expired(db, now: datetime | None = None) -> list[str]:
    """End every learning window whose `until` has passed (state learned). Returns the domains."""
    from . import sections
    from .audit import record_audit
    from .models import Site
    from .services import lock_site

    now = now or utcnow()
    ended = []
    # prefilter: sections are stored by json.dumps (", " / ": " separators), `enabled` first
    q = select(Site).where(Site.config.like('%"learning": {"enabled": true%')).order_by(Site.id)
    for site in db.scalars(q).all():
        ln = sections.get_section(site, "waf")["learning"]
        until = parse_iso(ln.get("until"))
        if not ln.get("enabled") or (until is not None and until > now):
            continue
        site = lock_site(db, site)
        waf = sections.storable("waf", sections.get_section(site, "waf"))
        waf["learning"] = {**waf["learning"], "enabled": False}
        sections.store_section(site, "waf", waf)
        db.commit()
        record_audit(db, actor="system", actor_kind="system", action="waf.learning.end", target=site.domain,
                     detail={"section": "waf"})
        ended.append(site.domain)
    return ended
