"""Customer-visible node naming (SPEC §23.12).

Customers never see an internal node name (`Edge.name`) or a node address next to a node: wherever a
customer page needs "which node", it gets a city label («نود تهران» / "Tehran node", numbered
«نود تهران ۱», «نود تهران ۲» when several edges share a city) or the node's public tag.

* `labels(db)` -> {edge id: {"fa", "en"}}: numbering by ascending edge id over ALL edges (enabled or
  not, so numbers do not shift when one is disabled); city = `display_city`, else the region default
  («ایران» / "Iran" for home, «بین‌المللی» / "International" for global).
* `public_tag(edge_id)` -> 8 hex = HMAC-SHA256(key, "edge:<id>") with key = HKDF(DATA_ENCRYPTION_KEY,
  info "pcdn-node-tag") or, without it, of a random `state` value `node_tag_key` created once. Stable
  per edge, not reversible to a name; used for `X-Served-By` / `X-Pcdn-Node` by the agents.
"""

import hashlib
import hmac
import json
import os
import re

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Edge

_CITY_RE = re.compile(r"^[^\W\d_]+(?:[ ‌][^\W\d_]+)*$")
_FA_DIGITS = str.maketrans("0123456789", "۰۱۲۳۴۵۶۷۸۹")
REGION_DEFAULT = {"home": ("ایران", "Iran"), "global": ("بین‌المللی", "International")}
TAG_STATE_KEY = "node_tag_key"
TAG_RE = re.compile(r"^[0-9a-f]{8}$")

_cities: dict[str, str] | None = None


def cities() -> dict[str, str]:
    """Persian city -> English name (app/data/cities.json)."""
    global _cities
    if _cities is None:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "cities.json")
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            _cities = {str(k): str(v) for k, v in data.items()} if isinstance(data, dict) else {}
        except (OSError, ValueError):
            _cities = {}
    return _cities


def clean_city(v: str | None) -> str | None:
    """EdgePatch.display_city(_en): letters, spaces and ZWNJ only, ≤ 32 chars; "" -> "" (= clear)."""
    if v is None:
        return None
    v = re.sub(r"\s+", " ", v.strip())
    if v == "":
        return ""
    if len(v) > 32 or not _CITY_RE.match(v):
        raise ValueError("نام شهر فقط می‌تواند حرف، فاصله و نیم‌فاصله باشد (حداکثر ۳۲ نویسه)")
    return v


def city_of(e) -> tuple[str, str]:
    """(fa, en) effective city of an edge."""
    fa = (getattr(e, "display_city", None) or "").strip()
    if not fa:
        return REGION_DEFAULT["home" if getattr(e, "region", None) == "home" else "global"]
    en = (getattr(e, "display_city_en", None) or "").strip() or cities().get(fa) or fa
    return fa, en


def label_for(city_fa: str, city_en: str, n: int | None) -> dict[str, str]:
    if n is None:
        return {"fa": f"نود {city_fa}", "en": f"{city_en} node"}
    return {"fa": f"نود {city_fa} {str(n).translate(_FA_DIGITS)}", "en": f"{city_en} node {n}"}


def compute(edges: list) -> dict[int, dict[str, str]]:
    """Pure: {edge id: {"fa", "en"}} for these edges (all of them: numbering is over the list)."""
    by_city: dict[str, list] = {}
    for e in sorted(edges, key=lambda x: x.id):
        by_city.setdefault(city_of(e)[0], []).append(e)
    out = {}
    for members in by_city.values():
        for i, e in enumerate(members, 1):
            fa, en = city_of(e)
            out[e.id] = label_for(fa, en, i if len(members) > 1 else None)
    return out


def labels(db: Session) -> dict[int, dict[str, str]]:
    """Labels of every edge (cached on the session for the request)."""
    cache = db.info.get("edge_labels")
    if cache is None:
        cache = compute(list(db.scalars(select(Edge).order_by(Edge.id))))
        db.info["edge_labels"] = cache
    return cache


def label_of(db: Session, edge_id: int) -> dict[str, str]:
    return labels(db).get(edge_id) or {"fa": "نود", "en": "Node"}


# ------------------------------------------------------------------ public tag (§23.12.2)

def tag_key(db: Session | None = None) -> bytes:
    """HKDF(DATA_ENCRYPTION_KEY, info "pcdn-node-tag"), else of the random state value node_tag_key."""
    from . import keys

    return keys.key("pcdn-node-tag", db, state_key=TAG_STATE_KEY)


def public_tag(edge_id: int, db: Session | None = None, key: bytes | None = None) -> str:
    key = key or tag_key(db)
    return hmac.new(key, f"edge:{edge_id}".encode(), hashlib.sha256).hexdigest()[:8]


def tags(db: Session) -> dict[int, str]:
    key = tag_key(db)
    return {eid: public_tag(eid, key=key) for (eid,) in db.execute(select(Edge.id))}
