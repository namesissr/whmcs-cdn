"""Operations endpoints: deep health check (for monitors / load balancers) and alerts admin."""

import time
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy import text

from . import alerts, crypto
from .auth import require_admin
from .config import settings
from .db import SessionLocal
from .leader import instance_id
from .models import State, utcnow

router = APIRouter(prefix="/api/v1", dependencies=[Depends(require_admin)])
health_router = APIRouter()

_cache: dict = {"at": 0.0, "body": None, "code": 200}
CACHE_SECONDS = 5


def _age_seconds(iso: str | None) -> int | None:
    if not iso:
        return None
    try:
        return int((utcnow() - datetime.fromisoformat(iso)).total_seconds())
    except ValueError:
        return None


def deep_health() -> tuple[dict, int]:
    """Everything a monitor needs to know; contains no secrets, URLs or keys."""
    from . import migrate, scheduler
    from .db import engine

    warnings: list[str] = []
    degraded = False
    body: dict = {"instance": instance_id()}

    # database ---------------------------------------------------------------
    db = SessionLocal()
    try:
        db.execute(text("SELECT 1"))
        state = {r.key: r.value for r in db.query(State).filter(State.key.in_([
            "scheduler:last_run", "scheduler:leader", "backup:last_success_at", "backup:last_failure_at",
        ]))}
        rev = migrate.current_revision(engine)
        head = migrate.head_revision()
        body["database"] = {"ok": True, "dialect": engine.dialect.name, "revision": rev, "head": head}
        if rev != head:
            degraded = True
            warnings.append("database migrations are pending")
        enc = crypto.status(db)
        open_alerts = alerts.open_alerts(db)
    except Exception as e:  # noqa: BLE001
        db.rollback()
        body.update(status="down", database={"ok": False, "error": type(e).__name__})
        return body, 503
    finally:
        db.close()

    # PowerDNS ---------------------------------------------------------------
    if settings.pdns_enabled:
        from . import pdns

        servers = []
        for i, c in enumerate(pdns.client().clients):
            t0 = time.monotonic()
            err = pdns.ping(c, timeout=3)
            servers.append({"server": i + 1, "ok": err is None, "latency_ms": int((time.monotonic() - t0) * 1000)})
            if err:
                degraded = True
                warnings.append(f"PowerDNS server #{i + 1} is unreachable")
        body["pdns"] = servers

    # GeoDNS --------------------------------------------------------------------
    from . import geocheck

    db = SessionLocal()
    try:
        off = geocheck.geo_off_warning(db)
        geo = geocheck.last_report(db)
    except Exception:  # noqa: BLE001
        db.rollback()
        off, geo = None, None
    finally:
        db.close()
    body["geodns"] = {"enabled": settings.geoip_enabled, "last_check": geo and geo.get("at"),
                      "problems": (geo or {}).get("problems", []) if settings.geoip_enabled else []}
    if off:
        warnings.append(off)
    for p in body["geodns"]["problems"]:
        warnings.append(f"GeoDNS: {p}")

    # scheduler / leader election ---------------------------------------------
    sched = scheduler.current
    if not settings.scheduler_enabled:
        role = "disabled"
    elif sched is None or not sched.is_alive():
        role = "not-running"  # e.g. a management command, or the thread died
    else:
        role = "leader" if sched.is_leader else "follower"
    age = _age_seconds(state.get("scheduler:last_run"))
    body["scheduler"] = {"role": role, "last_run_age_seconds": age, "leader": state.get("scheduler:leader")}
    stale_after = 3 * settings.scheduler_interval + 900
    if settings.scheduler_enabled and (age is None or age > stale_after):
        degraded = True
        warnings.append("no controller has run the scheduler recently")

    # encryption at rest -------------------------------------------------------
    body["encryption"] = {"enabled": enc["key_configured"], "readable": enc["readable"],
                          "plaintext_secrets": enc["plaintext"], "encrypted_secrets": enc["encrypted"]}
    if not enc["key_configured"]:
        warnings.append("DATA_ENCRYPTION_KEY is not set: private keys are stored in plaintext")
    elif enc["plaintext"]:
        warnings.append("some secrets are still stored in plaintext (run: python -m app.manage encrypt-secrets)")
    if not enc["readable"]:
        degraded = True
        warnings.append("stored secrets cannot be decrypted with DATA_ENCRYPTION_KEY")

    # backups ------------------------------------------------------------------
    b_age = _age_seconds(state.get("backup:last_success_at"))
    body["backup"] = {"enabled": settings.backup_enabled,
                      "last_success_age_hours": round(b_age / 3600, 1) if b_age is not None else None,
                      "failing": bool(state.get("backup:last_failure_at"))}
    if settings.backup_enabled and (b_age is None or b_age > 26 * 3600):
        warnings.append("no successful backup in the last 26 hours")

    # alerts -------------------------------------------------------------------
    body["alerts"] = {"channels": [n.name for n in alerts.configured_channels()], "open": len(open_alerts),
                      "critical": sum(1 for c in open_alerts if c.get("severity") == "critical")}
    if not body["alerts"]["channels"]:
        warnings.append("no alert channel (Telegram / e-mail) is configured")

    body["status"] = "degraded" if degraded else "ok"
    body["warnings"] = warnings
    return {"status": body.pop("status"), **body}, 200


@health_router.get("/healthz/deep")
def healthz_deep():
    now = time.monotonic()
    if _cache["body"] is None or now - _cache["at"] > CACHE_SECONDS:
        body, code = deep_health()
        _cache.update(at=now, body=body, code=code)
    return JSONResponse(_cache["body"], status_code=_cache["code"], headers={"Cache-Control": "no-store"})


# ------------------------------------------------------------------ alerts admin

@router.get("/alerts/status")
def alerts_status():
    return {
        "channels": {n.name: n.describe() for n in alerts.notifiers()},
        "reminder_hours": settings.alert_reminder_hours,
        "open": alerts.open_alerts(),
    }


@router.post("/alerts/test")
def alerts_test():
    if not alerts.configured_channels():
        raise HTTPException(409, "هیچ کانال هشداری (تلگرام یا ایمیل) تنظیم نشده است")
    results = alerts.send("info", "پیام آزمایشی",
                          f"این یک پیام آزمایشی از کنترلر CDN پاسارگاد ({instance_id()}) است. "
                          "اگر آن را می‌بینید، هشدارها درست تنظیم شده‌اند.")
    return {"ok": all(v == "ok" for v in results.values()), "results": results}
