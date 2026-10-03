"""Wave 14 (SPEC §23) operator API: releases + rollouts (§23.2), backups (§23.3), customer alert
accounts + notification outbox (§23.5), provisioning + join tokens (§23.9), abuse desk (§23.10), SLO
(§23.11); the provisioner API (bearer PROVISIONER_TOKEN) and the public abuse intake."""

from typing import Literal

from fastapi import APIRouter, Body, Depends, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import abuse, backup_runs, notify, notify_providers, provisioning, rollout, slo
from .audit import record_audit, with_actor
from .auth import require_admin
from .config import settings
from .db import get_db
from .models import Edge, ProvisionProposal, Rollout
from .services import sync_site_dns

router = APIRouter(prefix="/api/v1", dependencies=[Depends(require_admin)])
provisioner_router = APIRouter(prefix="/api/v1/provisioner")
public_router = APIRouter(prefix="/public/v1")


def _ip(request: Request | None) -> str | None:
    return request.client.host if request is not None and request.client else None


def _audit(db: Session, request: Request, action: str, target: str | None = None, detail: dict | None = None):
    record_audit(db, actor="admin", actor_kind="admin", action=action, target=target,
                 detail=with_actor(detail, request), ip=_ip(request))


# ------------------------------------------------------------------ releases + rollouts (§23.2)

class RolloutIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    release: str = Field(max_length=40)
    groups: list[Literal["general", "tunnel"]] | None = None
    soak_minutes: int | None = Field(default=None, ge=5, le=1440)
    ring_percent: int = Field(default=25, ge=1, le=90)
    auto_rollback: bool | None = None
    allow_no_rollback: bool = False
    dry_run: bool = False


@router.get("/releases")
def releases(db: Session = Depends(get_db)):
    return rollout.releases(db)


@router.post("/rollouts", status_code=201)
def create_rollout(body: RolloutIn, request: Request, db: Session = Depends(get_db)):
    data = body.model_dump()
    if data["groups"] is not None:
        data["groups"] = sorted(set(data["groups"]))
    r, preview = rollout.create(db, data, "admin")
    if r is None:
        return JSONResponse(preview, status_code=200)
    _audit(db, request, "rollout.create", r.release, {"items": r.id, "groups": data["groups"]})
    return rollout.to_dict(db, r)


@router.get("/rollouts")
def list_rollouts(limit: int = 20, db: Session = Depends(get_db)):
    limit = max(1, min(limit, 100))
    rows = db.scalars(select(Rollout).order_by(Rollout.id.desc()).limit(limit))
    return {"rollouts": [rollout.to_dict(db, r, with_gate=False) for r in rows]}


def _rollout(db: Session, rollout_id: int) -> Rollout:
    r = db.get(Rollout, rollout_id)
    if r is None:
        raise HTTPException(404, "rollout not found")
    return r


@router.get("/rollouts/{rollout_id}")
def get_rollout(rollout_id: int, db: Session = Depends(get_db)):
    return rollout.to_dict(db, _rollout(db, rollout_id))


@router.post("/rollouts/{rollout_id}/{action}")
def rollout_action(rollout_id: int, action: Literal["start", "pause", "resume", "abort", "rollback"],
                   request: Request, db: Session = Depends(get_db)):
    r = _rollout(db, rollout_id)
    rollout.act(db, r, action)
    _audit(db, request, f"rollout.{action}", r.release, {"items": r.id})
    return rollout.to_dict(db, r)


@router.post("/rollouts/{rollout_id}/edges/{edge_id}/{action}")
def rollout_edge_action(rollout_id: int, edge_id: int, action: Literal["skip", "force", "retry"], request: Request,
                        db: Session = Depends(get_db)):
    r = _rollout(db, rollout_id)
    rollout.edge_act(db, r, edge_id, action)
    _audit(db, request, f"rollout.{action}", r.release, {"items": r.id, "record_id": edge_id})
    return rollout.to_dict(db, r)


# ------------------------------------------------------------------ backups (§23.3)

@router.get("/backups")
def backups_status(db: Session = Depends(get_db)):
    return backup_runs.status(db)


@router.post("/backups/{kind}", status_code=202)
def backups_queue(kind: Literal["run", "verify"], request: Request, db: Session = Depends(get_db)):
    k = "backup" if kind == "run" else "verify"
    if not backup_runs.queue(db, k):
        raise HTTPException(409, "already queued or running")
    _audit(db, request, "backup.run" if kind == "run" else "backup.verify")
    return {"queued": True}


# ------------------------------------------------------------------ SLO (§23.11)

@router.get("/slo")
def slo_report(month: str | None = None, db: Session = Depends(get_db)):
    import re

    if month is not None and not re.match(r"^\d{4}-(0[1-9]|1[0-2])$", month):
        raise HTTPException(422, "month must be YYYY-MM")
    if not settings.slo_enabled:
        raise HTTPException(404, "SLO is disabled")
    return slo.evaluate(db, month=month)


# ------------------------------------------------------------------ notifications (§23.5)

@router.get("/notifications/status")
def notifications_status():
    return notify_providers.status()


@router.get("/notifications/outbox")
def notifications_outbox(channel: Literal["email"] = "email", after: int = 0, limit: int = 200,
                         db: Session = Depends(get_db)):
    return notify.outbox(db, max(0, after), max(1, min(limit, 500)))


class AckIn(BaseModel):
    results: dict[str, Literal["sent", "failed", "skipped"]] = Field(default_factory=dict)


@router.post("/notifications/outbox/ack")
def notifications_ack(body: AckIn, db: Session = Depends(get_db)):
    return notify.ack(db, body.results)


def _account(db: Session, client_id: int) -> int:
    if client_id < 1 or not notify.account_sites(db, client_id):
        raise HTTPException(404, "account not found")
    return client_id


class QuietIn(BaseModel):
    start: str
    end: str
    bypass_critical: bool = True


class SubIn(BaseModel):
    id: int | None = None
    site: str | None = None
    events: list[str] = Field(min_length=1, max_length=20)
    channels: list[str] = Field(min_length=1, max_length=4)
    lang: str = "fa"
    quiet_hours: QuietIn | None = None
    enabled: bool = True


class SubsIn(BaseModel):
    items: list[SubIn] = Field(default_factory=list, max_length=100)


@router.get("/accounts/{client_id}/alerts")
def account_alerts(client_id: int, db: Session = Depends(get_db)):
    return notify.account_view(db, _account(db, client_id))


@router.put("/accounts/{client_id}/alerts/subscriptions")
def put_subscriptions(client_id: int, body: SubsIn, request: Request, db: Session = Depends(get_db)):
    cid = _account(db, client_id)
    notify.replace_subscriptions(db, cid, [i.model_dump() for i in body.items])
    db.commit()
    _audit(db, request, "alerts.update", f"client:{cid}", {"count": len(body.items)})
    return notify.account_view(db, cid)


class PhoneIn(BaseModel):
    phone: str = Field(max_length=20)


@router.post("/accounts/{client_id}/alerts/targets/sms", status_code=202)
def add_sms(client_id: int, body: PhoneIn, request: Request, db: Session = Depends(get_db)):
    cid = _account(db, client_id)
    out = notify.add_sms_target(db, cid, body.phone)
    db.commit()
    _audit(db, request, "alerts.target.add", f"client:{cid}", {"type": "sms"})
    return out


class CodeIn(BaseModel):
    code: str = Field(max_length=12)


@router.post("/accounts/{client_id}/alerts/targets/{target_id}/verify")
def verify_sms(client_id: int, target_id: int, body: CodeIn, request: Request, db: Session = Depends(get_db)):
    cid = _account(db, client_id)
    out = notify.verify_sms_target(db, cid, target_id, body.code)
    db.commit()
    _audit(db, request, "alerts.target.verify", f"client:{cid}", {"type": "sms"})
    return out


@router.post("/accounts/{client_id}/alerts/targets/{channel}/link")
def link_bot(client_id: int, channel: Literal["bale", "telegram"], request: Request, db: Session = Depends(get_db)):
    cid = _account(db, client_id)
    out = notify.new_link_code(db, cid, channel)
    db.commit()
    _audit(db, request, "alerts.target.add", f"client:{cid}", {"type": channel})
    return out


@router.get("/accounts/{client_id}/alerts/targets/link/{code}")
def link_status(client_id: int, code: str, db: Session = Depends(get_db)):
    return notify.link_status(db, _account(db, client_id), code)


@router.delete("/accounts/{client_id}/alerts/targets/{target_id}")
def delete_target(client_id: int, target_id: int, request: Request, db: Session = Depends(get_db)):
    cid = _account(db, client_id)
    t = notify.delete_target(db, cid, target_id)
    db.commit()
    _audit(db, request, "alerts.target.delete", f"client:{cid}", {"type": t.channel, "label": t.masked})
    return {"ok": True}


class TestIn(BaseModel):
    channel: Literal["email", "sms", "bale", "telegram"]
    target_id: int | None = None


@router.post("/accounts/{client_id}/alerts/test", status_code=202)
def alerts_test(client_id: int, body: TestIn, request: Request, db: Session = Depends(get_db)):
    cid = _account(db, client_id)
    n = notify.queue_test(db, cid, body.channel, body.target_id)
    db.commit()
    _audit(db, request, "alerts.test", f"client:{cid}", {"type": body.channel, "count": n})
    return {"queued": n}


# ------------------------------------------------------------------ provisioning (§23.9)

def _prov_on():
    if not settings.provisioning_enabled:
        raise HTTPException(404, "provisioning is disabled")


def _proposal(db: Session, pid: int) -> ProvisionProposal:
    p = db.get(ProvisionProposal, pid)
    if p is None:
        raise HTTPException(404, "proposal not found")
    return p


@router.get("/provisioning/proposals")
def list_proposals(db: Session = Depends(get_db)):
    _prov_on()
    rows = db.scalars(select(ProvisionProposal).order_by(ProvisionProposal.id.desc()).limit(100))
    return {"proposals": [provisioning.proposal_dict(db, p) for p in rows]}


class ProposalIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    group: Literal["general", "tunnel"]
    region: Literal["home", "global"]
    size: str = Field(max_length=16)
    count: int = Field(ge=1, le=20)


@router.post("/provisioning/proposals", status_code=201)
def create_proposal(body: ProposalIn, request: Request, db: Session = Depends(get_db)):
    _prov_on()
    p = provisioning.create_manual(db, body.group, body.region, body.size, body.count, "admin")
    _audit(db, request, "provision.create", body.group, {"items": p.id, "count": body.count})
    return provisioning.proposal_dict(db, p)


@router.get("/provisioning/proposals/{pid}")
def get_proposal(pid: int, db: Session = Depends(get_db)):
    _prov_on()
    return provisioning.proposal_dict(db, _proposal(db, pid))


class ApproveIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    region: Literal["home", "global"] | None = None
    size: str | None = Field(default=None, max_length=16)
    count: int | None = Field(default=None, ge=1, le=20)


@router.post("/provisioning/proposals/{pid}/approve")
def approve_proposal(pid: int, request: Request, body: ApproveIn | None = Body(default=None),
                     db: Session = Depends(get_db)):
    _prov_on()
    p = _proposal(db, pid)
    body = body or ApproveIn()
    provisioning.approve(db, p, body.region, body.size, body.count, "admin")
    _audit(db, request, "provision.approve", p.group, {"items": p.id, "count": p.count})
    return provisioning.proposal_dict(db, p)


@router.post("/provisioning/proposals/{pid}/apply")
def apply_proposal(pid: int, request: Request, db: Session = Depends(get_db)):
    _prov_on()
    p = _proposal(db, pid)
    provisioning.approve_apply(db, p, "admin")
    _audit(db, request, "provision.apply", p.group, {"items": p.id})
    return provisioning.proposal_dict(db, p)


@router.post("/provisioning/proposals/{pid}/reject")
def reject_proposal(pid: int, request: Request, db: Session = Depends(get_db)):
    _prov_on()
    p = _proposal(db, pid)
    provisioning.reject(db, p, "admin")
    _audit(db, request, "provision.reject", p.group, {"items": p.id})
    return provisioning.proposal_dict(db, p)


@router.post("/edges/{edge_id}/join-token")
def edge_join_token(edge_id: int, request: Request, db: Session = Depends(get_db)):
    """A one-time join token for an edge that has not heartbeated yet (SPEC §23.9); shown once."""
    e = db.get(Edge, edge_id)
    if e is None:
        raise HTTPException(404, "edge not found")
    if e.last_seen_at is not None:
        raise HTTPException(409, "edge_already_joined")
    token, expires = provisioning.mint(db, e, "admin")
    db.commit()
    _audit(db, request, "edge.join_token", e.name)  # never the token
    return {"join_token": token, "expires_at": expires.isoformat() + "Z",
            "install": provisioning.install_command(e, token, db)}


# provisioner API (bearer PROVISIONER_TOKEN; the provisioner holds the cloud credentials, never us)

def _prov_auth(authorization: str | None = Header(default=None)) -> None:
    if not settings.provisioning_enabled:
        raise HTTPException(404, "provisioning is disabled")
    provisioning.provisioner_auth(authorization)


@provisioner_router.get("/jobs/next", dependencies=[Depends(_prov_auth)])
def provisioner_next(db: Session = Depends(get_db)):
    return {"job": provisioning.next_job(db)}


class PlanIn(BaseModel):
    summary: str = Field(max_length=70000)
    adds: int = Field(ge=0, le=100000)
    changes: int = Field(ge=0, le=100000)
    destroys: int = Field(ge=0, le=100000)


@provisioner_router.post("/jobs/{pid}/plan", dependencies=[Depends(_prov_auth)])
def provisioner_plan(pid: int, body: PlanIn, db: Session = Depends(get_db)):
    p = _proposal(db, pid)
    provisioning.upload_plan(db, p, body.summary, body.adds, body.changes, body.destroys)
    record_audit(db, actor="provisioner", actor_kind="system", action="provision.plan", target=p.group,
                 detail={"items": p.id})
    return {"ok": True}


class ResultIn(BaseModel):
    ok: bool
    error: str | None = Field(default=None, max_length=2000)


@provisioner_router.post("/jobs/{pid}/result", dependencies=[Depends(_prov_auth)])
def provisioner_result(pid: int, body: ResultIn, db: Session = Depends(get_db)):
    p = _proposal(db, pid)
    provisioning.upload_result(db, p, body.ok, body.error)
    record_audit(db, actor="provisioner", actor_kind="system", action="provision.result", target=p.group,
                 detail={"items": p.id, "ok": body.ok})
    return {"ok": True}


# ------------------------------------------------------------------ abuse desk (§23.10)

class ChallengeIn(BaseModel):
    id: str = Field(max_length=64)
    salt: str = Field(max_length=64)
    # a decimal string (sha256(UTF-8(salt + nonce)) needs ≥ bits leading zero bits); a JSON number
    # is accepted and read as its decimal string
    nonce: str = Field(max_length=64)

    @field_validator("nonce", mode="before")
    @classmethod
    def _nonce(cls, v):
        return str(v) if isinstance(v, int) and not isinstance(v, bool) else v


class AbuseIn(BaseModel):
    category: str = Field(max_length=16)
    urls: list[str] = Field(max_length=10)
    description: str = Field(default="", max_length=4000)
    email: str | None = Field(default=None, max_length=254)
    challenge: ChallengeIn | None = None
    website: str = Field(default="", max_length=200)


def _abuse_on():
    if not settings.abuse_enabled:
        raise HTTPException(404, "not found")


CORS = {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type"}


@public_router.options("/abuse/{rest:path}")
def abuse_preflight(rest: str):
    _abuse_on()
    return Response(status_code=204, headers=CORS)


@public_router.get("/abuse/challenge")
def abuse_challenge():
    _abuse_on()
    return JSONResponse(abuse.challenge(), headers={**CORS, "Cache-Control": "no-store"})


@public_router.post("/abuse/reports", status_code=201)
async def abuse_submit(request: Request, db: Session = Depends(get_db)):
    """404 while ABUSE_ENABLED=false, whatever the body; malformed bodies get a generic 422."""
    from fastapi.concurrency import run_in_threadpool
    from pydantic import ValidationError as PydanticError

    _abuse_on()
    try:
        body = AbuseIn.model_validate_json(await request.body() or b"{}")
    except (PydanticError, ValueError):
        raise HTTPException(422, "invalid_request") from None
    out = await run_in_threadpool(abuse.submit, db, body.model_dump(), _ip(request))
    return JSONResponse(out, status_code=201, headers={**CORS, "Cache-Control": "no-store"})


@public_router.get("/abuse/reports/{ticket}")
def abuse_status(ticket: str, token: str = "", db: Session = Depends(get_db)):
    _abuse_on()
    return JSONResponse(abuse.public_status(db, ticket, token), headers={**CORS, "Cache-Control": "no-store"})


@router.post("/abuse/reports", status_code=201)
def admin_abuse_submit(body: AbuseIn, request: Request, x_pcdn_reporter_ip: str | None = Header(default=None),
                       db: Session = Depends(get_db)):
    """The WHMCS abuse page submits server-side with the visitor's IP in X-PCDN-Reporter-IP (hashed at
    once, never stored). The proof of work is checked like the public endpoint."""
    return abuse.submit(db, body.model_dump(), (x_pcdn_reporter_ip or "").strip()[:45] or _ip(request))


@router.get("/abuse/reports")
def admin_abuse_list(status: str | None = None, category: str | None = None, q: str | None = None,
                     limit: int = 100, db: Session = Depends(get_db)):
    return {"reports": abuse.list_reports(db, status, category, q, max(1, min(limit, 500)))}


@router.get("/abuse/reports/{report_id}")
def admin_abuse_get(report_id: int, db: Session = Depends(get_db)):
    return abuse.report_dict(db, abuse.get(db, report_id), detail=True)


class AbusePatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["new", "triage", "notified", "actioned", "closed", "rejected"] | None = None
    site: str | None = Field(default=None, max_length=253)
    public_note: str | None = Field(default=None, max_length=500)
    note: str | None = Field(default=None, max_length=2000)


@router.patch("/abuse/reports/{report_id}")
def admin_abuse_patch(report_id: int, body: AbusePatch, request: Request, db: Session = Depends(get_db)):
    r = abuse.get(db, report_id)
    abuse.patch(db, r, body.model_dump(exclude_none=True))
    _audit(db, request, "abuse.update", r.ticket, {"fields": sorted(body.model_dump(exclude_none=True))})
    return abuse.report_dict(db, r, detail=True)


class NotifyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    deadline_hours: int | None = Field(default=None, ge=1, le=720)
    lang: Literal["fa", "en"] = "fa"
    message: str | None = Field(default=None, max_length=2000)


@router.post("/abuse/reports/{report_id}/notify")
def admin_abuse_notify(report_id: int, request: Request, body: NotifyIn | None = Body(default=None),
                       db: Session = Depends(get_db)):
    r = abuse.get(db, report_id)
    body = body or NotifyIn()
    abuse.notify_owner(db, r, body.deadline_hours, body.lang, body.message)
    _audit(db, request, "abuse.notify", r.ticket)
    return abuse.report_dict(db, r, detail=True)


class AbuseActionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: Literal["warn", "suspend", "unsuspend", "close", "reject"]
    public_note: str | None = Field(default=None, max_length=500)


@router.post("/abuse/reports/{report_id}/action")
def admin_abuse_action(report_id: int, body: AbuseActionIn, request: Request, db: Session = Depends(get_db)):
    r = abuse.get(db, report_id)
    site = abuse.action(db, r, body.action, body.public_note)
    dns_error = None
    if site is not None:
        # DNS and the edge config follow at once (the config is rebuilt on the edges' next poll)
        dns_error = sync_site_dns(db, site)
    _audit(db, request, f"abuse.{body.action}", r.ticket, {"domain": site.domain} if site is not None else None)
    return {**abuse.report_dict(db, r, detail=True), "dns_error": dns_error}

