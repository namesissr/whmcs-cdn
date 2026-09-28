import hashlib
import hmac
import secrets

from fastapi import Depends, Header, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import settings
from .db import get_db
from .models import Edge


def _bearer(authorization: str | None) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "missing bearer token")
    return authorization[7:].strip()


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def new_token() -> str:
    return "edge_" + secrets.token_urlsafe(32)


def require_admin(authorization: str | None = Header(default=None)) -> None:
    token = _bearer(authorization)
    if not settings.admin_api_key or not hmac.compare_digest(token, settings.admin_api_key):
        raise HTTPException(401, "invalid api key")


def require_edge(authorization: str | None = Header(default=None), db: Session = Depends(get_db)) -> Edge:
    token = _bearer(authorization)
    edge = db.scalar(select(Edge).where(Edge.token_hash == hash_token(token)))
    if edge is None or not edge.enabled:
        raise HTTPException(401, "invalid edge token")
    return edge
