import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from . import (
    routes_admin,
    routes_bundle,
    routes_capi,
    routes_edge,
    routes_metrics,
    routes_ops,
    routes_platform,
    routes_storage,
    routes_tunnel,
    routes_v2,
)
from .config import settings
from .db import init_db

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


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    secrets_at_rest()
    from . import pdns

    pdns.check_transport()  # M5: plain-HTTP PowerDNS API over a public network
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
app.include_router(routes_v2.router)
# analytics & platform (SPEC §14.3): live analytics, log export, webhooks, SLA
app.include_router(routes_platform.router)
# wave 7 (SPEC §15.3/§15.4): tunnel quality, usage forecast, origin health
app.include_router(routes_tunnel.router)
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


@app.get("/healthz")
def healthz():
    return {"ok": True}
