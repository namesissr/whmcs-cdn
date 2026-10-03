"""Admin API for analytics & platform (SPEC §14.3): live analytics, log export status/test, webhook
rotate/test/deliveries and the monthly SLA report. The `logs` and `webhooks` sections themselves go
through the generic GET/PUT /sites/{domain}/config/{section} (routes_v2.write_section_of)."""

import math
import time

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from . import live, logexport, sections, sla, webhooks
from .audit import record_audit, with_actor
from .auth import require_admin
from .config import settings
from .db import get_db
from .models import Site
from .routes_admin import bad, get_site
from .services import lock_site
from .validation import ValidationError

router = APIRouter(prefix="/api/v1", dependencies=[Depends(require_admin)])

# "rate-limited like config writes" (SPEC §14.3.2): the test endpoints make outbound connections to
# customer-chosen hosts, so each site gets CAPI_CONFIG_RATE of them per minute (in-process window,
# like routes_capi; with several workers the effective limit multiplies)
_test_hits: dict[tuple[str, int], list[float]] = {}


def rate_limit_test(kind: str, site: Site) -> None:
    now = time.monotonic()
    window = _test_hits.setdefault((kind, site.id), [])
    window[:] = [t for t in window if t > now - 60]
    limit = max(1, settings.capi_config_rate)
    if len(window) >= limit:
        raise HTTPException(429, f"محدودیت نرخ آزمایش ({limit} در دقیقه) رد شد؛ کمی بعد دوباره تلاش کنید",
                            headers={"Retry-After": str(max(1, math.ceil(window[0] + 60 - now)))})
    window.append(now)


def _audit(db: Session, request: Request, action: str, target: str, detail: dict | None = None) -> None:
    ip = request.client.host if request.client else None
    record_audit(db, actor="admin", actor_kind="admin", action=action, target=target, detail=with_actor(detail, request), ip=ip)


# ------------------------------------------------------------------ live analytics (SPEC §14.3.1)

def live_of(db: Session, site: Site, minutes: int) -> dict:
    """Shared by the admin and customer APIs."""
    if not 1 <= minutes <= live.MAX_MINUTES:
        bad(ValidationError("minutes باید بین 1 و 1440 باشد"))
    return live.series(db, site, minutes)


@router.get("/sites/{domain}/analytics/live")
def analytics_live(domain: str, minutes: int = 60, db: Session = Depends(get_db)):
    return live_of(db, get_site(db, domain), minutes)


# ------------------------------------------------------------------ log export (SPEC §14.3.2)

@router.get("/sites/{domain}/logs/status")
def logs_status(domain: str, db: Session = Depends(get_db)):
    return logexport.status(db, get_site(db, domain))


@router.post("/sites/{domain}/logs/test")
def logs_test(domain: str, request: Request, db: Session = Depends(get_db)):
    site = get_site(db, domain)
    if not sections.features_of(site)["log_export"]:
        raise HTTPException(403, "خروجی لاگ در پلن شما فعال نیست")
    rate_limit_test("logs", site)
    name = site.domain
    result = logexport.test_upload(db, site)
    _audit(db, request, "logs.test", name, {"ok": result["ok"]})
    return result


# ------------------------------------------------------------------ webhooks (SPEC §14.3.3)

@router.post("/sites/{domain}/webhooks/{hook_id}/rotate")
def webhook_rotate(domain: str, hook_id: str, request: Request, db: Session = Depends(get_db)):
    site = lock_site(db, get_site(db, domain))  # read-modify-write of site.integration_secrets
    secret = webhooks.rotate(site, hook_id)
    if secret is None:
        raise HTTPException(404, "وب‌هوک یافت نشد")
    db.commit()
    # the new secret is returned this once and never written to the audit log
    _audit(db, request, "webhook.rotate", site.domain, {"hook_id": hook_id})
    return {"id": hook_id, "secret": secret}


@router.post("/sites/{domain}/webhooks/{hook_id}/test")
def webhook_test(domain: str, hook_id: str, request: Request, db: Session = Depends(get_db)):
    site = get_site(db, domain)
    if webhooks.find_hook(site, hook_id) is None:
        raise HTTPException(404, "وب‌هوک یافت نشد")
    rate_limit_test("webhooks", site)
    name = site.domain
    result = webhooks.test(db, site, hook_id)
    _audit(db, request, "webhook.test", name, {"hook_id": hook_id, "ok": result["ok"]})
    return result


@router.get("/sites/{domain}/webhooks/deliveries")
def webhook_deliveries(domain: str, limit: int = 50, db: Session = Depends(get_db)):
    return webhooks.deliveries(db, get_site(db, domain), limit)


# ------------------------------------------------------------------ SLA report (SPEC §14.3.4)

@router.get("/sites/{domain}/sla")
def sla_report(domain: str, month: str | None = None, db: Session = Depends(get_db)):
    site = get_site(db, domain)
    try:
        return sla.report(db, site, month)
    except ValidationError as e:
        bad(e)
