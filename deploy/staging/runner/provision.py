#!/usr/bin/env python3
"""STAGING ONLY — register the staging edges through the controller's admin API (docs/STAGING.md).

For every NAME=IPv4 in STAGING_EDGES this does what an operator does in the panel:
  * POST /api/v1/edges {name, ipv4, region, group}  -> one-time token + install one-liner, or
  * when the edge already exists but its token file is gone: POST /api/v1/edges/{id}/rotate-token
    and GET /api/v1/edges/install for the one-liner,
and writes {name, id, token, install} to TOKENS_DIR/NAME.json (0600) for that edge container, which
runs the one-liner. The one-liner carries the token in the environment
(`... | sudo PCDN_EDGE_TOKEN=edge_... bash -s -- --controller ...`, never `--token`); a one-liner of
another shape is refused here already, so a controller change shows up in the runner log.
TOKENS_DIR/.done marks completion (the runner's healthcheck).
"""

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

CONTROLLER = os.environ.get("CONTROLLER_URL", "http://controller:8000").rstrip("/")
KEY = os.environ.get("ADMIN_API_KEY", "staging-admin-key")
TOKENS = os.environ.get("TOKENS_DIR", "/staging/tokens")
EDGES = os.environ.get("STAGING_EDGES", "edge-1=11.200.0.21,edge-2=11.200.0.22")
REGION = os.environ.get("STAGING_EDGE_REGION", "global")
GROUP = os.environ.get("STAGING_EDGE_GROUP", "general")


def api(method: str, path: str, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(CONTROLLER + path, data=data, method=method)
    req.add_header("Authorization", f"Bearer {KEY}")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=30) as r:
        raw = r.read()
        return json.loads(raw) if raw else None


def wait_controller(timeout: float = 300):
    end = time.time() + timeout
    while True:
        try:
            with urllib.request.urlopen(CONTROLLER + "/healthz", timeout=5) as r:
                if r.status == 200:
                    return
        except (urllib.error.URLError, OSError):
            pass
        if time.time() > end:
            sys.exit(f"provision: controller {CONTROLLER} not healthy after {timeout}s")
        time.sleep(2)


def write_token(name: str, doc: dict):
    os.makedirs(TOKENS, exist_ok=True)
    path = os.path.join(TOKENS, f"{name}.json")
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(doc, f)
    # the edge containers read it as root through a read-only mount
    os.replace(tmp, path)


def main():
    wait_controller()
    done = os.path.join(TOKENS, ".done")
    if os.path.exists(done):
        os.remove(done)
    existing = {e["name"]: e for e in api("GET", "/api/v1/edges")}
    for item in [x.strip() for x in EDGES.split(",") if x.strip()]:
        name, ip = item.split("=", 1)
        tf = os.path.join(TOKENS, f"{name}.json")
        e = existing.get(name)
        if e is not None and os.path.exists(tf):
            print(f"provision: {name} (id {e['id']}) already provisioned", flush=True)
            continue
        if e is None:
            out = api("POST", "/api/v1/edges", {"name": name, "ipv4": ip, "region": REGION, "group": GROUP})
            doc = {"name": name, "id": out["id"], "token": out["token"], "install": out["install"]}
            print(f"provision: created {name} (id {out['id']}, {ip}, {REGION}/{GROUP})", flush=True)
        else:
            tok = api("POST", f"/api/v1/edges/{e['id']}/rotate-token")["token"]
            q = urllib.parse.urlencode({"token": tok, "region": e["region"], "role": e["group"]})
            install = api("GET", f"/api/v1/edges/install?{q}")["command"]
            doc = {"name": name, "id": e["id"], "token": tok, "install": install}
            print(f"provision: rotated the token of {name} (id {e['id']})", flush=True)
        if f"| sudo PCDN_EDGE_TOKEN={doc['token']} bash -s -- " not in doc["install"]:
            sys.exit(f"provision: unexpected install one-liner shape for {name} (token not in PCDN_EDGE_TOKEN)")
        write_token(name, doc)
    open(done, "w").close()
    print("provision: done", flush=True)


if __name__ == "__main__":
    main()
    if "--then-sleep" in sys.argv:
        while True:
            time.sleep(3600)
