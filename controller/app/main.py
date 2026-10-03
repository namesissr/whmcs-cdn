import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from . import (
    routes_admin,
    routes_bundle,
    routes_capi,
    routes_cx,
    routes_edge,
    routes_metrics,
    routes_ops,
    routes_ops14,
    routes_platform,
    routes_reports,
    routes_storage,
    routes_tunnel,
    routes_v2,
)
from .config import settings
from .db import init_db
from .errors import ApiError

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
# "Context impl ..." is logged on every revision lookup (e.g. each /healthz/deep); app.migrate logs upgrades
logging.getLogger("alembic.runtime").setLevel(logging.WARNING)
# httpx logs every request at INFO (PowerDNS health checks every tick); errors are logged by the callers
logging.getLogger("httpx").setLevel(logging.WARNING)
log = logging.getLogger("pcdn")


def secrets_at_rest():
    """Warn when secrets are stored in plaintext; encrypt leftovers when a key is configured."""
    from . import crypto
    from .db import SessionLocal

    crypto.enabled()  # a malformed DATA_ENCRYPTION_KEY stops startup (CryptoError)
    db = SessionLocal()
    try:
        if not crypto.enabled():
            log.warning("DATA_ENCRYPTION_KEY is not set: certificate private keys and site secrets are stored "
                        "in PLAINTEXT in the database (see docs/OPERATIONS.md, 'key management')")
            return
        n = crypto.encrypt_existing(db)
        if n:
            log.info("encrypted %d plaintext secret(s) with the current DATA_ENCRYPTION_KEY", n)
        st = crypto.status(db)
        if not st["readable"]:
            log.critical("stored secrets cannot be decrypted: %s", st["error"])
    except crypto.CryptoError as e:
        log.critical("%s", e)
    except Exception:  # noqa: BLE001 - never block startup on this
        log.exception("checking encryption at rest failed")
        db.rollback()
    finally:
        db.close()


def wave14_startup():
    """SPEC §23: EDGE_RELEASE must exist in EDGE_RELEASES_DIR (logged once, then ignored); backup key
    conflicts are logged (never the values); the live database carries the pcdn_live_marker row."""
    from . import backup, bundle
    from .db import SessionLocal
    from .models import LiveMarker

    try:
        bundle.configured_pin()
        from . import edge_labels, keys

        edge_labels.tag_key()  # the node tag / lookup-hash keys exist before any request needs them
        keys.key("startup")
        problem = backup.key_problem()
        if problem:
            log.error("backup encryption key problem: %s (backups fail until it is fixed)", problem)
        db = SessionLocal()
        try:
            if db.get(LiveMarker, 1) is None:
                db.add(LiveMarker(id=1))
                db.commit()
        finally:
            db.close()
    except Exception:  # noqa: BLE001 - never block startup on this
        log.exception("wave 14 startup checks failed")


@asynccontextmanager
async def lifespan(app: FastAPI):
    from . import errortrack

    errortrack.init_sentry()  # SPEC §18.4: only with SENTRY_DSN (sentry-sdk imported lazily)
    init_db()
    secrets_at_rest()
    from . import tls_tickets

    tls_tickets.startup_check()  # SPEC §22.8: TLS_TICKETS=on is refused without DATA_ENCRYPTION_KEY
    from . import pdns

    pdns.check_transport()  # M5: plain-HTTP PowerDNS API over a public network
    wave14_startup()
    sched = None
    if settings.scheduler_enabled:
        from . import scheduler

        sched = scheduler.Scheduler()
        scheduler.current = sched
        sched.start()
    yield
    if sched:
        sched.stop()


# no public /docs, /redoc or /openapi.json: they would map every admin and edge route for anyone.
# Customers get the schema of their own API at /capi/v1/openapi.json (SPEC §14.3.5).
app = FastAPI(title="Pasargad CDN Controller", version="1.1.0", lifespan=lifespan,
              docs_url=None, redoc_url=None, openapi_url=None)
app.include_router(routes_admin.router)
# wave 14 (SPEC §23): config history / import / RUM / diagnostics — before routes_v2 so
# /config/history is never taken for a section name
app.include_router(routes_cx.router)
app.include_router(routes_v2.router)
# wave 14 (SPEC §23): releases, rollouts, backups, alerts, provisioning, abuse desk, SLO; the provisioner
# API (bearer PROVISIONER_TOKEN) and the public abuse intake (ABUSE_ENABLED)
app.include_router(routes_ops14.router)
app.include_router(routes_ops14.provisioner_router)
app.include_router(routes_ops14.public_router)
# analytics & platform (SPEC §14.3): live analytics, log export, webhooks, SLA
app.include_router(routes_platform.router)
# wave 7 (SPEC §15.3/§15.4): tunnel quality, usage forecast, origin health
app.include_router(routes_tunnel.router)
# wave 10 (SPEC §18): waiting room / access / statements / audit export / client errors
app.include_router(routes_reports.router)
# SPEC §16.8: object storage buckets (MinIO) + GB-hour usage for invoicing
app.include_router(routes_storage.router)
# public, unauthenticated: the platform origin-pull CA certificate (SPEC §14.2)
app.include_router(routes_v2.public_router)
app.include_router(routes_capi.router)
app.include_router(routes_edge.router)
app.include_router(routes_ops.router)
app.include_router(routes_ops.health_router)
# public, unauthenticated: the secret-free edge bundle (SPEC §11.1)
app.include_router(routes_bundle.router)
# public (optional METRICS_TOKEN): platform-aggregate Prometheus metrics (SPEC §13.1)
app.include_router(routes_metrics.router)


@app.exception_handler(ApiError)
async def _api_error(request: Request, exc: ApiError):
    return JSONResponse(exc.body, status_code=exc.status)


@app.middleware("http")
async def _config_actor(request: Request, call_next):
    """SPEC §23.4: who a config version is attributed to. Admin requests carry the validated
    X-PCDN-Actor of the WHMCS client / collaborator; the capi key resolver completes the capi entry."""
    from . import audit, config_history

    path = request.url.path
    token = None
    if path.startswith("/api/v1/"):
        token = config_history.set_actor(kind="admin", actor="admin", on_behalf_of=audit.on_behalf_of(request))
    elif path.startswith("/capi/v1/"):
        token = config_history.set_actor(kind="capi", actor="capi", source="capi")
    try:
        return await call_next(request)
    finally:
        if token is not None:
            config_history.ACTOR.reset(token)


@app.get("/healthz")
def healthz():
    # SPEC §23.1: + the platform version (PCDN_VERSION / VERSION file, "" when unknown)
    return {"ok": True, "version": settings.app_version}
