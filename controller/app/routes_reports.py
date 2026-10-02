"""Wave 10 admin API (SPEC §18): waiting room stats, access secret rotation + sign-in log, monthly
statements, audit export, client error intake. The `*_of` helpers are shared with the customer API
(routes_capi) so both surfaces behave identically."""

import csv
import io
import json
from datetime import timedelta

import pydantic
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import access, errortrack, sections, statements, waiting_room
from .audit import record_audit
from .auth import require_admin
from .db import get_db
from .models import AuditLog, Site, utcnow
from .routes_admin import bad, get_site
from .services import lock_site
from .validation import ValidationError

router = APIRouter(prefix="/api/v1", dependencies=[Depends(require_admin)])

AUDIT_EXPORT_MAX = 10000
AUDIT_DEFAULT_DAYS = 30


def _admin_audit(db: Session, request: Request, action: str, target: str | None, detail: dict | None = None):
    record_audit(db, actor="admin", actor_kind="admin", action=action, target=target, detail=detail,
                 ip=request.client.host if request.client else None)


# ------------------------------------------------------------------ waiting room (SPEC §18.1)

def waiting_room_of(db: Session, site: Site, hours: int) -> dict:
    if not 1 <= hours <= waiting_room.MAX_HOURS:
        bad(ValidationError(f"hours باید بین 1 و {waiting_room.MAX_HOURS} باشد"))
    return waiting_room.stats(db, site, hours)


@router.get("/sites/{domain}/waiting-room")
def waiting_room_stats(domain: str, hours: int = 24, db: Session = Depends(get_db)):
    """{enabled, feature, mode, max_active, serving_edges, node_max, active_estimate, queued_estimate,
    edges_reporting, last_hour: {admitted, queued, max_wait_s, peak_active}, hours, hourly: [{t, ...}]}"""
    return waiting_room_of(db, get_site(db, domain), hours)


# ------------------------------------------------------------------ access (SPEC §18.2)

def access_rotate_of(db: Session, site: Site) -> dict:
    """A new access_secret: every session cookie and pending code becomes invalid. The secret is
    never returned (only the edges need it)."""
    if not sections.features_of(site).get("access"):
        raise HTTPException(403, "دسترسی محافظت‌شده (access) در پلن شما فعال نیست")
    site = lock_site(db, site)  # read-modify-write of site.integration_secrets
    access.rotate(site)
    db.commit()
    return {"ok": True, "rotated_at": utcnow().replace(microsecond=0).isoformat() + "Z"}


def access_log_of(db: Session, site: Site, limit: int) -> dict:
    return access.access_log(db, site, limit)


@router.post("/sites/{domain}/access/rotate")
def access_rotate(domain: str, request: Request, db: Session = Depends(get_db)):
    site = get_site(db, domain)
    result = access_rotate_of(db, site)
    _admin_audit(db, request, "access.rotate", site.domain)
    return result


@router.get("/sites/{domain}/access/log")
def access_log(domain: str, limit: int = 200, db: Session = Depends(get_db)):
    """{enabled, apps, last_24h: {ok, fail, otp}, last_30d: {...}, events: [{t, app, email_hash, ok}]}
    (newest first, ≤200)."""
    return access_log_of(db, get_site(db, domain), limit)


# ------------------------------------------------------------------ statements (SPEC §18.3)

def statement_of(db: Session, site: Site, month: str | None, fmt: str, lang: str,
                 plan: str | None = None, block_gb: float | None = None) -> Response:
    if fmt not in statements.FORMATS:
        bad(ValidationError("format باید pdf، csv یا json باشد"))
    if lang not in statements.LANGS:
        bad(ValidationError("lang باید fa یا en باشد"))
    try:
        doc = statements.build(db, site, month, plan=plan, block_gb=block_gb)
        body, media, name = statements.render(doc, fmt, lang)
    except ValidationError as e:
        bad(e)
    headers = {"Content-Disposition": f'attachment; filename="{name}"', "Cache-Control": "no-store"}
    return Response(body, media_type=media, headers=headers)


@router.get("/sites/{domain}/statement")
def statement(domain: str, month: str | None = None, format: str = "json", lang: str = "fa",
              plan: str | None = None, block_gb: float | None = None, db: Session = Depends(get_db)):
    return statement_of(db, get_site(db, domain), month, format, lang, plan, block_gb)


# ------------------------------------------------------------------ audit export (SPEC §18.3)

def _range(frm: str | None, to: str | None):
    from .routes_v2 import _since

    end = _since(to) or utcnow()
    start = _since(frm) or end - timedelta(days=AUDIT_DEFAULT_DAYS)
    if start > end:
        bad(ValidationError("from باید پیش از to باشد"))
    return start, end


def masked_actor(e: AuditLog) -> str:
    """kind + short label: the operator's and the edges' identities are not shown to customers."""
    kind = e.actor_kind or "admin"
    if kind == "capi":
        return "capi:" + (e.actor or "")[:24]
    return kind


def _detail(e: AuditLog) -> dict:
    try:
        d = json.loads(e.detail or "{}")
    except ValueError:
        return {}
    return d if isinstance(d, dict) else {}


def _audit_rows(db: Session, frm, to, target: str | None):
    q = select(AuditLog).where(AuditLog.at >= frm, AuditLog.at <= to)
    if target is not None:
        q = q.where(AuditLog.target == target)
    rows = list(db.scalars(q.order_by(AuditLog.at.desc(), AuditLog.id.desc()).limit(AUDIT_EXPORT_MAX + 1)))
    return rows[:AUDIT_EXPORT_MAX], len(rows) > AUDIT_EXPORT_MAX


def _csv(header: list[str], rows: list[list]) -> bytes:
    out = io.StringIO()
    w = csv.writer(out, lineterminator="\r\n")
    w.writerow(header)
    w.writerows(rows)
    return ("﻿" + out.getvalue()).encode("utf-8")  # UTF-8 BOM for Excel


def site_audit_of(db: Session, site: Site, frm: str | None, to: str | None, fmt: str) -> Response:
    """The site's audit entries (actor masked, no IPs), newest first, ≤10 000."""
    if fmt not in ("json", "csv"):
        bad(ValidationError("format باید json یا csv باشد"))
    start, end = _range(frm, to)
    rows, truncated = _audit_rows(db, start, end, site.domain)
    items = [{"at": e.at.isoformat() + "Z", "actor": masked_actor(e), "action": e.action, "target": e.target,
              "detail": _detail(e)} for e in rows]
    headers = {"X-Pcdn-Truncated": "true" if truncated else "false", "Cache-Control": "no-store"}
    if fmt == "csv":
        body = _csv(["at", "actor", "action", "target", "detail"],
                    [[i["at"], i["actor"], i["action"], i["target"] or "",
                      json.dumps(i["detail"], ensure_ascii=False, sort_keys=True)] for i in items])
        headers["Content-Disposition"] = f'attachment; filename="audit-{site.domain}.csv"'
        return Response(body, media_type="text/csv; charset=utf-8", headers=headers)
    return Response(json.dumps({"domain": site.domain, "from": start.isoformat() + "Z", "to": end.isoformat() + "Z",
                                "truncated": truncated, "items": items}, ensure_ascii=False),
                    media_type="application/json", headers=headers)


@router.get("/sites/{domain}/audit")
def site_audit(domain: str, request: Request, format: str = "json", db: Session = Depends(get_db)):
    q = request.query_params
    return site_audit_of(db, get_site(db, domain), q.get("from"), q.get("to"), format)


@router.get("/audit/export")
def audit_export(request: Request, format: str = "csv", db: Session = Depends(get_db)):
    """Every audit entry in [from, to] (default the last 30 days), newest first, ≤10 000; CSV (BOM) or
    JSON. Operator view: actor and IP unmasked."""
    if format not in ("json", "csv"):
        bad(ValidationError("format باید json یا csv باشد"))
    q = request.query_params
    start, end = _range(q.get("from"), q.get("to"))
    rows, truncated = _audit_rows(db, start, end, None)
    items = [{"id": e.id, "at": e.at.isoformat() + "Z", "actor_kind": e.actor_kind, "actor": e.actor,
              "action": e.action, "target": e.target, "detail": _detail(e), "ip": e.ip} for e in rows]
    headers = {"X-Pcdn-Truncated": "true" if truncated else "false", "Cache-Control": "no-store"}
    if format == "csv":
        body = _csv(["id", "at", "actor_kind", "actor", "action", "target", "detail", "ip"],
                    [[i["id"], i["at"], i["actor_kind"], i["actor"], i["action"], i["target"] or "",
                      json.dumps(i["detail"], ensure_ascii=False, sort_keys=True), i["ip"] or ""] for i in items])
        headers["Content-Disposition"] = 'attachment; filename="audit.csv"'
        return Response(body, media_type="text/csv; charset=utf-8", headers=headers)
    return Response(json.dumps({"from": start.isoformat() + "Z", "to": end.isoformat() + "Z",
                                "truncated": truncated, "items": items}, ensure_ascii=False),
                    media_type="application/json", headers=headers)


# ------------------------------------------------------------------ client errors (SPEC §18.4)

class ClientErrorIn(BaseModel):
    """What the WHMCS client app reports (via the module proxy); unknown keys are ignored."""
    message: str = Field("", max_length=2000)
    source: str = Field("", max_length=1000)
    line: int | None = Field(None, ge=0, le=10_000_000)
    col: int | None = Field(None, ge=0, le=10_000_000)
    stack: str = Field("", max_length=8192)
    page: str = Field("", max_length=64)
    ua: str = Field("", max_length=512)


@router.post("/client-errors")
def client_errors(body: dict, db: Session = Depends(get_db)):
    """Count the error per page (pcdn_client_errors_total{page}) and forward it to Sentry when
    configured. Nothing is stored besides the counter."""
    try:
        data = ClientErrorIn.model_validate(body)
    except pydantic.ValidationError as e:
        raise HTTPException(422, [{"loc": list(err["loc"]), "msg": err["msg"]} for err in e.errors()]) from None
    page = errortrack.page_label(data.page)
    errortrack.count_client_error(db, page)
    db.commit()
    payload = data.model_dump()
    payload["source"] = payload["source"].split("?", 1)[0].split("#", 1)[0]  # path only
    payload["stack"] = errortrack.scrub_string(payload["stack"])[:4096]
    errortrack.forward_client_error(page, payload)
    return {"ok": True, "page": page, "forwarded": errortrack.enabled()}
