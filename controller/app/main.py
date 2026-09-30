import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from . import routes_admin, routes_capi, routes_edge, routes_ops, routes_v2
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
    sched = None
    if settings.scheduler_enabled:
        from . import scheduler

        sched = scheduler.Scheduler()
        scheduler.current = sched
        sched.start()
    yield
    if sched:
        sched.stop()


app = FastAPI(title="Pasargad CDN Controller", version="1.1.0", lifespan=lifespan)
app.include_router(routes_admin.router)
app.include_router(routes_v2.router)
app.include_router(routes_capi.router)
app.include_router(routes_edge.router)
app.include_router(routes_ops.router)
app.include_router(routes_ops.health_router)


@app.get("/healthz")
def healthz():
    return {"ok": True}
