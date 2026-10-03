"""Admin API for tunnel quality, usage and origin health (SPEC §15.3/§15.4). The customer API
(/capi/v1/tunnel/*, scope stats) reuses the *_of helpers below."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from . import tunnel, tunnel_quality
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


def drops_of(db: Session, site: Site, hours: int) -> dict:
    if not 1 <= hours <= tunnel_quality.MAX_QUALITY_HOURS:
        bad(ValidationError(f"hours باید بین 1 و {tunnel_quality.MAX_QUALITY_HOURS} باشد"))
    return tunnel_quality.drops(db, site, hours)


def profile_of(db: Session, site: Site) -> dict:
    out = tunnel.profile(db, site)
    if out is None:
        raise HTTPException(404, "tunnel is not part of this plan")
    return out


@router.get("/sites/{domain}/tunnel/profile")
def tunnel_profile(domain: str, db: Session = Depends(get_db)):
    """Edge timers, HTTP/3 availability and recommended client settings per path (SPEC §22.11)."""
    return profile_of(db, get_site(db, domain))


@router.get("/sites/{domain}/tunnel/drops")
def tunnel_drops(domain: str, hours: int = 24, db: Session = Depends(get_db)):
    """Why tunnel sessions ended in the last `hours` (1..744) hours (SPEC §22.12)."""
    return drops_of(db, get_site(db, domain), hours)


@router.get("/sites/{domain}/tunnel/quality")
def tunnel_quality_report(domain: str, hours: int = 24, db: Session = Depends(get_db)):
    return quality_of(db, get_site(db, domain), hours)


@router.get("/sites/{domain}/tunnel/usage")
def tunnel_usage(domain: str, days: int = 30, db: Session = Depends(get_db)):
    return usage_of(db, get_site(db, domain), days)


@router.get("/sites/{domain}/tunnel/health")
def tunnel_health(domain: str, db: Session = Depends(get_db)):
    return tunnel_quality.health(db, get_site(db, domain))
