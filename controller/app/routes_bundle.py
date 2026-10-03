"""Public, UNAUTHENTICATED edge bundle routes (SPEC §11.1).

These serve the open-source edge agent and templates so a node can be brought up with one
command. They hold NO secrets, keys or tokens and MUST NOT sit behind the admin or edge auth
dependency. When EDGE_BUNDLE_DIR is unset/missing the bundle routes return 404 with a clear
message and the admin panel falls back to manual git/scp instructions.
"""

from fastapi import APIRouter, HTTPException, Response
from fastapi.responses import FileResponse, PlainTextResponse

from . import bundle
from .db import SessionLocal

# no auth dependency: this router is mounted bare in main.py
router = APIRouter(tags=["edge-bundle"])

_NO_BUNDLE = ("edge bundle is not available on this controller "
              "(EDGE_BUNDLE_DIR unset or missing); use the manual git/scp install")


@router.get("/edge/bootstrap.sh")
def bootstrap_sh():
    script = bundle.bootstrap_script()
    if script is None:
        raise HTTPException(404, _NO_BUNDLE)
    return Response(content=script, media_type="text/x-shellscript")


def _pin(group: str) -> str | None:
    db = SessionLocal()
    try:
        return bundle.group_pin(db, group)
    finally:
        db.close()


def _release_response(version: str):
    path = bundle.release_file(version)
    if path is None:
        raise HTTPException(404, "unknown edge release")
    # FileResponse streams the file (never read into memory); the name comes from the validated version
    return FileResponse(path, media_type="application/gzip", filename=f"pcdn-edge-{version}.tar.gz")


@router.get("/edge/bundle.tar.gz")
def bundle_tar(version: str | None = None, group: str = "general"):
    """SPEC §23.1: ?version=vX.Y.Z serves that pinned release (422 bad format, 404 unknown); without it
    the effective pin of ?group= (default general) when EDGE_RELEASES_DIR has one, else the live bundle."""
    if version is not None:
        if not bundle.VERSION_RE.match(version):
            raise HTTPException(422, "invalid version (expected vX.Y.Z)")
        if not bundle.releases_enabled():
            raise HTTPException(404, "edge releases are not configured on this controller")
        return _release_response(version)
    if bundle.releases_enabled() and group in bundle.GROUPS:
        pin = _pin(group)
        if pin:
            return _release_response(pin)
    data = bundle.build_tar()
    if data is None:
        raise HTTPException(404, _NO_BUNDLE)
    return Response(
        content=data,
        media_type="application/gzip",
        headers={"Content-Disposition": 'attachment; filename="pcdn-edge-bundle.tar.gz"'},
    )


@router.get("/edge/version")
def bundle_ver():
    v = bundle.version()
    if v is None:
        raise HTTPException(404, _NO_BUNDLE)
    # SPEC §23.1: + the effective pin of the general group (null without EDGE_RELEASES_DIR / a pin)
    return {"version": v, "release": _pin("general") if bundle.releases_enabled() else None}


@router.get("/edge/releases")
def releases():
    """SPEC §23.1: the pinned releases this controller serves; 404 when EDGE_RELEASES_DIR is unset."""
    if not bundle.releases_enabled():
        raise HTTPException(404, "edge releases are not configured on this controller")
    db = SessionLocal()
    try:
        groups = bundle.pins(db)
    finally:
        db.close()
    return {"pinned": bundle.configured_pin(), "groups": groups, "releases": bundle.list_releases()}


@router.get("/edge/releases/{name}")
def release_sha(name: str):
    """GET /edge/releases/vX.Y.Z.sha256 -> "<hex>  pcdn-edge-vX.Y.Z.tar.gz\\n" (sha256sum format)."""
    if not bundle.releases_enabled():
        raise HTTPException(404, "edge releases are not configured on this controller")
    if not name.endswith(".sha256") or not bundle.VERSION_RE.match(name[:-7]):
        raise HTTPException(404, "not found")
    version = name[:-7]
    digest = bundle.release_sha256(version)
    if digest is None:
        raise HTTPException(404, "unknown edge release")
    return PlainTextResponse(f"{digest}  pcdn-edge-{version}.tar.gz\n")
