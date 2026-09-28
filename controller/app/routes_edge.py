"""API polled by edge agents."""

import json
from datetime import datetime

from fastapi import APIRouter, Depends, Header, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .auth import require_edge
from .db import get_db
from .models import Edge, Purge, Site, UsageHourly, utcnow
from .services import build_edge_config

router = APIRouter(prefix="/edge/v1")


@router.get("/config")
def config(
    response: Response,
    if_none_match: str | None = Header(default=None),
    edge: Edge = Depends(require_edge),
    db: Session = Depends(get_db),
):
    edge.last_seen_at = utcnow()
    db.commit()
    cfg = build_edge_config(db)
    etag = f'"{cfg["version"]}"'
    if if_none_match == etag:
        return Response(status_code=304, headers={"ETag": etag})
    response.headers["ETag"] = etag
    return cfg


class Heartbeat(BaseModel):
    applied_version: str | None = None
    error: str | None = Field(default=None, max_length=4000)


@router.post("/heartbeat")
def heartbeat(body: Heartbeat, edge: Edge = Depends(require_edge), db: Session = Depends(get_db)):
    edge.last_seen_at = utcnow()
    edge.applied_version = body.applied_version
    edge.last_error = body.error
    db.commit()
    return {"ok": True}


@router.get("/purges")
def purges(after: int = 0, edge: Edge = Depends(require_edge), db: Session = Depends(get_db)):
    rows = db.execute(
        select(Purge, Site.domain).join(Site, Site.id == Purge.site_id)
        .where(Purge.id > after).order_by(Purge.id).limit(500)
    ).all()
    return [{"id": p.id, "domain": d, "site_id": p.site_id, "urls": json.loads(p.urls)} for p, d in rows]


class UsageItem(BaseModel):
    host: str
    hour: datetime
    bytes: int = Field(ge=0)
    requests: int = Field(ge=0)
    cache_hits: int = Field(default=0, ge=0)


class UsageIn(BaseModel):
    items: list[UsageItem] = Field(max_length=20000)


def _site_for_host(host: str, domains: dict[str, int]) -> int | None:
    host = host.lower().rstrip(".").split(":")[0]
    parts = host.split(".")
    for i in range(len(parts) - 1):
        sid = domains.get(".".join(parts[i:]))
        if sid:
            return sid
    return None


@router.post("/usage")
def usage(body: UsageIn, edge: Edge = Depends(require_edge), db: Session = Depends(get_db)):
    domains = {d: i for i, d in db.execute(select(Site.id, Site.domain)).all()}
    agg: dict[tuple[int, datetime], list[int]] = {}
    for it in body.items:
        sid = _site_for_host(it.host, domains)
        if sid is None:
            continue
        hour = it.hour.replace(tzinfo=None, minute=0, second=0, microsecond=0)
        a = agg.setdefault((sid, hour), [0, 0, 0])
        a[0] += it.bytes
        a[1] += it.requests
        a[2] += it.cache_hits
    for (sid, hour), (b, r, h) in agg.items():
        row = db.scalar(select(UsageHourly).where(
            UsageHourly.site_id == sid, UsageHourly.edge_id == edge.id, UsageHourly.hour == hour))
        if row is None:
            db.add(UsageHourly(site_id=sid, edge_id=edge.id, hour=hour, bytes=b, requests=r, cache_hits=h))
        else:
            row.bytes += b
            row.requests += r
            row.cache_hits += h
    edge.last_seen_at = utcnow()
    db.commit()
    return {"ok": True, "accepted": len(agg)}
