import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from . import routes_admin, routes_edge, routes_v2
from .config import settings
from .db import init_db

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    sched = None
    if settings.scheduler_enabled:
        from .scheduler import Scheduler

        sched = Scheduler()
        sched.start()
    yield
    if sched:
        sched.stop_event.set()


app = FastAPI(title="Pasargad CDN Controller", version="1.0.0", lifespan=lifespan)
app.include_router(routes_admin.router)
app.include_router(routes_v2.router)
app.include_router(routes_edge.router)


@app.get("/healthz")
def healthz():
    return {"ok": True}
