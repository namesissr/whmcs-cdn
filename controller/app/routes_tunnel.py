"""Admin API for tunnel quality, usage and origin health (SPEC §15.3/§15.4). The customer API
(/capi/v1/tunnel/*, scope stats) reuses the *_of helpers below."""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from . import tunnel_quality
from .auth import require_admin
from .db import get_db
from .models import Site
from .routes_admin import bad, get_site
from .validation import ValidationError

router = APIRouter(prefix="/api/v1", dependencies=[Depends(require_admin)])


def quality_of(db: Session, site: Site, hours: int) -> dict:
    if not 1 <= hours <= tunnel_quality.MAX_QUALITY_HOURS:
        bad(ValidationError(f"hours باید بین 1 و {tunnel_quality.MAX_QUALITY_HOURS} باشد"))
    return tunnel_quality.quality(db, site, hours)


def usage_of(db: Session, site: Site, days: int) -> dict:
    if not 1 <= days <= tunnel_quality.MAX_USAGE_DAYS:
        bad(ValidationError(f"days باید بین 1 و {tunnel_quality.MAX_USAGE_DAYS} باشد"))
    return tunnel_quality.usage(db, site, days)


@router.get("/sites/{domain}/tunnel/quality")
def tunnel_quality_report(domain: str, hours: int = 24, db: Session = Depends(get_db)):
    return quality_of(db, get_site(db, domain), hours)


@router.get("/sites/{domain}/tunnel/usage")
def tunnel_usage(domain: str, days: int = 30, db: Session = Depends(get_db)):
    return usage_of(db, get_site(db, domain), days)


@router.get("/sites/{domain}/tunnel/health")
def tunnel_health(domain: str, db: Session = Depends(get_db)):
    return tunnel_quality.health(db, get_site(db, domain))
