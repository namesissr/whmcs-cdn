"""Real user monitoring (SPEC §23.7): ingestion of the edges' per host-hour histograms and the site
owner's performance report.

HARD CONSTRAINT: RUM aggregates are read only by this module's report code and the client API. They are
never read by dnsbuild, the scheduler's DNS jobs, rollouts, provisioning or any node-selection code (an
import test enforces it), never compared across nodes, and carry no node dimension at all.

Histogram contract (shared with the edge, pinned by golden tests): ms metrics use the upper bounds
MS_BOUNDS (17 counts, the last one unbounded), CLS ×1000 uses CLS_BOUNDS (8 counts).
"""

import json
import math
import os
from datetime import datetime, timedelta

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from . import kv, sections
from .config import settings
from .models import RumHourly, Site, utcnow

MS_BOUNDS = [50, 100, 200, 300, 500, 800, 1000, 1500, 1800, 2000, 2500, 3000, 4000, 5000, 8000, 12000, math.inf]
CLS_BOUNDS = [10, 50, 100, 150, 250, 500, 1000, math.inf]
MS_METRICS = ("ttfb", "fcp", "lcp", "inp", "dns", "tcp", "tls", "dom", "load")
METRICS = MS_METRICS + ("cls",)
DIMS = {"cc": 30, "asn": 20, "rg": 31, "dev": 3, "path": 50, "cs": 10}
BY_DIM = {"country": "cc", "isp": "asn", "region": "rg", "device": "dev", "path": "path"}
THRESHOLDS = {"lcp": [2500, 4000], "inp": [200, 500], "cls": [0.1, 0.25], "ttfb": [800, 1800], "fcp": [1800, 3000]}
REPORT_METRICS = ("lcp", "inp", "cls", "ttfb", "fcp")
HOURS = (24, 168, 720)
IMPACT_MIN = 30
KEY_MAX = 200
DEVICE_LABELS = {"m": ("موبایل", "Mobile"), "t": ("تبلت", "Tablet"), "d": ("دسکتاپ", "Desktop")}


def bounds(metric: str) -> list:
    return CLS_BOUNDS if metric == "cls" else MS_BOUNDS


# ------------------------------------------------------------------ ingestion

def clean_hist(h) -> dict | None:
    """A valid <H> or None: {"n": int ≥ 0, metric: [non-negative ints of the contract length]}."""
    if not isinstance(h, dict):
        return None
    n = h.get("n")
    if isinstance(n, bool) or not isinstance(n, int) or n < 0 or n > 10**12:
        return None
    out = {"n": n}
    for m in METRICS:
        v = h.get(m)
        if v is None:
            continue
        if not isinstance(v, list) or len(v) != len(bounds(m)) or \
                any(isinstance(x, bool) or not isinstance(x, int) or x < 0 or x > 10**12 for x in v):
            return None
        out[m] = v
    return out


def clean(rum) -> dict | None:
    """The usage item's `rum` object validated; malformed -> None (ignored, never a 422)."""
    if not isinstance(rum, dict):
        return None
    allh = clean_hist(rum.get("all"))
    if allh is None:
        return None
    by = {}
    for dim, top in DIMS.items():
        src = (rum.get("by") or {}).get(dim) if isinstance(rum.get("by"), dict) else None
        if not isinstance(src, dict):
            continue
        entries = {}
        for k, h in list(src.items())[: top + 1]:
            ch = clean_hist(h)
            if ch is not None and isinstance(k, str) and 0 < len(k) <= KEY_MAX:
                entries[k] = ch
        if entries:
            by[dim] = entries
    return {"all": allh, "by": by}


def _add(a: dict, b: dict) -> dict:
    out = {"n": int(a.get("n") or 0) + int(b.get("n") or 0)}
    for m in METRICS:
        va, vb = a.get(m), b.get(m)
        if va is None and vb is None:
            continue
        size = len(bounds(m))
        va, vb = (va or [0] * size), (vb or [0] * size)
        out[m] = [int(x) + int(y) for x, y in zip(va, vb)]
    return out


def ingest(db: Session, site_id: int, hour: datetime, rum: dict) -> int:
    """Merge one item's histograms into rum_hourly (caller commits). Returns rows touched."""
    rows = [("all", "", rum["all"])]
    for dim, entries in rum["by"].items():
        rows += [(dim, k[:KEY_MAX], h) for k, h in entries.items()]
    for dim, key, h in rows:
        # every edge reports the same (site, hour, dim, key): create the row race-free, then lock it
        kv.insert_ignore(db, RumHourly, {"site_id": site_id, "hour": hour, "dim": dim, "key": key, "n": 0,
                                         "hist": "{}"})
        row = db.scalar(select(RumHourly).where(RumHourly.site_id == site_id, RumHourly.hour == hour,
                                                RumHourly.dim == dim, RumHourly.key == key).with_for_update()
                        .execution_options(populate_existing=True))
        merged = _add(_loads(row.hist), h)
        row.n = merged["n"]
        row.hist = json.dumps(merged, separators=(",", ":"))
    return len(rows)


def site_accepts(site: Site) -> bool:
    return bool(sections.features_of(site).get("rum"))


def prune(db: Session, now: datetime | None = None) -> None:
    cutoff = (now or utcnow()) - timedelta(days=settings.rum_retention_days)
    db.execute(delete(RumHourly).where(RumHourly.hour < cutoff))


def _loads(raw: str | None) -> dict:
    try:
        v = json.loads(raw or "{}")
    except ValueError:
        return {}
    return v if isinstance(v, dict) else {}


# ------------------------------------------------------------------ statistics

def percentile(counts: list[int], metric: str, q: float = 0.75) -> float | None:
    """p-quantile from a bucketed histogram with linear interpolation inside the bucket (the last,
    unbounded bucket reports its lower bound). CLS is returned unscaled (÷1000)."""
    n = sum(counts or [])
    if n <= 0:
        return None
    b = bounds(metric)
    rank = q * n
    cum, lower = 0, 0.0
    for i, c in enumerate(counts):
        upper = b[i]
        if c > 0 and cum + c >= rank:
            if math.isinf(upper):
                value = lower
            else:
                value = lower + (upper - lower) * ((rank - cum) / c)
            return round(value / 1000, 3) if metric == "cls" else round(value, 1)
        cum += c
        lower = upper if not math.isinf(upper) else lower
    return round(lower / 1000, 3) if metric == "cls" else round(lower, 1)


def shares(counts: list[int], metric: str) -> tuple[float | None, float | None]:
    """(good_pct, poor_pct) with the Google thresholds (bucket bounds coincide with them)."""
    n = sum(counts or [])
    if n <= 0 or metric not in THRESHOLDS:
        return None, None
    good_t, poor_t = THRESHOLDS[metric]
    scale = 1000 if metric == "cls" else 1
    b = bounds(metric)
    good = sum(c for i, c in enumerate(counts) if b[i] <= good_t * scale)
    poor = sum(c for i, c in enumerate(counts) if (b[i - 1] if i else 0) >= poor_t * scale)
    return round(100.0 * good / n, 1), round(100.0 * poor / n, 1)


def metric_block(h: dict, metric: str) -> dict:
    counts = h.get(metric) or [0] * len(bounds(metric))
    good, poor = shares(counts, metric)
    return {"p75": percentile(counts, metric), "good_pct": good, "poor_pct": poor, "hist": counts}


# ------------------------------------------------------------------ labels

_labels: dict[str, dict] = {}


def _data(name: str) -> dict:
    if name not in _labels:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", name)
        try:
            with open(path, encoding="utf-8") as f:
                _labels[name] = json.load(f)
        except (OSError, ValueError):
            _labels[name] = {}
    return _labels[name]


def label(dim: str, key: str) -> tuple[str, str]:
    if dim == "cc":
        v = _data("countries.json").get(key.upper())
        return (v["fa"], v["en"]) if v else (key, key)
    if dim == "asn":
        v = _data("isp_names.json").get(str(key))
        return (v["fa"], v["en"]) if v else (f"AS{key}", f"AS{key}")
    if dim == "dev":
        return DEVICE_LABELS.get(key, (key, key))
    if key == "other":
        return "سایر", "Other"
    return key, key


# ------------------------------------------------------------------ report

def report(db: Session, site: Site, hours: int, by: str | None, now: datetime | None = None) -> dict:
    now = now or utcnow()
    end = now.replace(minute=0, second=0, microsecond=0)
    start = end - timedelta(hours=hours - 1)
    cfg = sections.get_section(site, "rum")
    rows = list(db.scalars(select(RumHourly).where(RumHourly.site_id == site.id, RumHourly.hour >= start,
                                                   RumHourly.hour <= end)))
    total: dict = {"n": 0}
    per_hour: dict[datetime, dict] = {}
    per_key: dict[tuple[str, str], dict] = {}
    for r in rows:
        h = _loads(r.hist)
        if r.dim == "all":
            total = _add(total, h)
            per_hour[r.hour] = _add(per_hour.get(r.hour, {"n": 0}), h)
        else:
            per_key[(r.dim, r.key)] = _add(per_key.get((r.dim, r.key), {"n": 0}), h)
    out = {"enabled": bool(cfg.get("enabled")), "sample_rate": cfg.get("sample_rate"), "hours": hours,
           "n": int(total.get("n") or 0),
           "metrics": {m: metric_block(total, m) for m in REPORT_METRICS},
           "thresholds": THRESHOLDS, "by": [], "series": [], "cdn_impact": None,
           "has_data": int(total.get("n") or 0) > 0}
    dim = BY_DIM.get(by or "country", "cc")
    entries = [(k, h) for (d, k), h in per_key.items() if d == dim]
    entries.sort(key=lambda kh: (-int(kh[1].get("n") or 0), kh[0]))
    for k, h in entries[:50]:
        fa, en = label(dim, k)
        out["by"].append({"key": k, "label": fa, "label_en": en, "n": int(h.get("n") or 0),
                          "p75": {m: percentile(h.get(m) or [], m) for m in ("lcp", "inp", "cls", "ttfb")}})
    t = start
    while t <= end:
        h = per_hour.get(t)
        if h:
            out["series"].append({"t": t.isoformat() + "Z", "n": int(h.get("n") or 0),
                                  **{f"{m}_p75": percentile(h.get(m) or [], m) for m in ("lcp", "inp", "cls", "ttfb")}})
        t += timedelta(hours=1)
    hit = per_key.get(("cs", "HIT"))
    miss = per_key.get(("cs", "MISS"))
    if hit and miss and hit.get("n", 0) >= IMPACT_MIN and miss.get("n", 0) >= IMPACT_MIN:
        hp = {m: percentile(hit.get(m) or [], m) for m in ("ttfb", "lcp")}
        mp = {m: percentile(miss.get(m) or [], m) for m in ("ttfb", "lcp")}

        def gain(a, b):
            return round(100.0 * (b - a) / b, 1) if a is not None and b else None

        cs_total = sum(int(h.get("n") or 0) for (d, _), h in per_key.items() if d == "cs")
        out["cdn_impact"] = {
            "hit": {"n": int(hit["n"]), "ttfb_p75": hp["ttfb"], "lcp_p75": hp["lcp"]},
            "miss": {"n": int(miss["n"]), "ttfb_p75": mp["ttfb"], "lcp_p75": mp["lcp"]},
            "ttfb_gain_pct": gain(hp["ttfb"], mp["ttfb"]), "lcp_gain_pct": gain(hp["lcp"], mp["lcp"]),
            "hit_ratio_pct": round(100.0 * int(hit["n"]) / cs_total, 1) if cs_total else None}
    return out


def edge_block(site: Site, cfg: dict, feats: dict) -> dict | None:
    """Edge config per site `rum` (SPEC §23.7) or None (absent: old agents ignore it)."""
    if not feats.get("rum") or not cfg.get("enabled"):
        return None
    return {"enabled": True, "sample": cfg["sample_rate"], "inject": cfg["inject"], "exclude": cfg["exclude_paths"],
            "spa": bool(cfg["spa"])}
