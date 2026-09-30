"""Public, UNAUTHENTICATED edge bundle routes (SPEC §11.1).

These serve the open-source edge agent and templates so a node can be brought up with one
command. They hold NO secrets, keys or tokens and MUST NOT sit behind the admin or edge auth
dependency. When EDGE_BUNDLE_DIR is unset/missing the bundle routes return 404 with a clear
message and the admin panel falls back to manual git/scp instructions.
"""

from fastapi import APIRouter, HTTPException, Response

from . import bundle

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


@router.get("/edge/bundle.tar.gz")
def bundle_tar():
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
    return {"version": v}
