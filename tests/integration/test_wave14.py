"""Wave 14 on the staging stack (SPEC §23.18 integration, agent B): X-Served-By is the node's public tag,
heartbeats carry `release`, a RUM beacon reaches the controller's report, the pinned-release download that
bootstrap.sh --version does, and (opt-in) a two-edge rollout with an injected failure rolling back.

Every test skips against a pre-wave-14 controller (no public_tag / release / rum / rollouts endpoints) or
pre-wave-14 agents (no capabilities.rum / self_upgrade), so the suite keeps passing on older stacks.

    STAGING_ROLLOUT_RELEASE  a release in the controller's EDGE_RELEASES_DIR to roll out (opt-in)
    STAGING_ROLLOUT_INJECT   a shell command that breaks the canary's nginx during the soak, run with the
                             canary's edge name in $EDGE (e.g. "docker exec staging-$EDGE-1 nginx -s stop")
"""

import json
import os
import pathlib
import re
import subprocess
import time
import urllib.request
import uuid

import pytest

from conftest import CONTROLLER, KEEP, ORIGIN_IP, TIMEOUT, ApiError, edge_request, new_domain, wait_until

DOMAIN = new_domain("w14")
BOOTSTRAP = pathlib.Path(__file__).resolve().parents[2] / "edge" / "bootstrap.sh"
RELEASE_RE = re.compile(r"^v\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$")


def _edge_rows(api):
    return {e["name"]: e for e in api.get("/api/v1/edges")}


@pytest.fixture(scope="module")
def site(api, edges):
    plan = {"ssl_allowed": False, "bandwidth_limit_gb": 0, "features": {"rum": True}}
    out = api.post("/api/v1/sites", {"domain": DOMAIN, "origin_ip": ORIGIN_IP, "external_id": "staging-w14",
                                     "plan": plan})
    yield out
    if not KEEP:
        try:
            api.delete(f"/api/v1/sites/{DOMAIN}")
        except ApiError:
            pass


def test_x_served_by_is_the_public_tag(api, edges, site):
    rows = _edge_rows(api)
    for name, ip in edges.items():
        e = rows[name]
        tag = e.get("public_tag")
        if not tag:
            pytest.skip("pre-wave-14 controller: no public_tag in the edge list")
        if "rum" not in (e.get("capabilities") or {}):
            pytest.skip(f"{name} runs a pre-wave-14 agent (X-Served-By is still the host name there)")
        r = wait_until(lambda: (lambda x: x if x.status == 200 and x.headers.get("x-served-by") == tag else None)(
            edge_request(ip, DOMAIN, "/w14-tag")), f"X-Served-By {tag} from {name}")
        assert name not in r.headers.get("x-served-by", "")
        ping = edge_request(ip, DOMAIN, "/__pcdn/speed/ping")
        assert ping.headers.get("x-pcdn-node") == tag
        # the admin can map a customer's header back to the node
        try:
            found = api.get(f"/api/v1/edges?tag={tag}")
        except ApiError as ex:
            if ex.status in (404, 422):
                continue
            raise
        assert [x["name"] for x in found] == [name]


def test_heartbeat_reports_release(api, edges):
    rows = _edge_rows(api)
    e = rows[sorted(edges)[0]]
    if "release" not in e:
        pytest.skip("pre-wave-14 controller: no release in the edge list")
    if "self_upgrade" not in (e.get("capabilities") or {}):
        pytest.skip("pre-wave-14 agent")
    assert e["release"] is None or RELEASE_RE.match(e["release"])


def test_rum_beacon_reaches_the_report(api, edges, site):
    try:
        api.put(f"/api/v1/sites/{DOMAIN}/config/rum", {"enabled": True, "sample_rate": 1.0, "inject": "manual",
                                                     "exclude_paths": [], "spa": False})
    except ApiError as e:
        if e.status in (404, 422):
            pytest.skip("pre-wave-14 controller: no rum section")
        raise
    rows = _edge_rows(api)
    name = sorted(edges)[0]
    if not (rows[name].get("capabilities") or {}).get("rum"):
        pytest.skip(f"{name} runs a pre-wave-14 agent (capabilities.rum)")
    ip = edges[name]
    wait_until(lambda: edge_request(ip, DOMAIN, "/__pcdn/rum.js").status == 200, "the beacon script on the edge")
    body = json.dumps({"v": 1, "p": "/w14", "nt": "navigate", "dev": "d", "cs": "MISS", "ttfb": 210, "fcp": 700,
                       "lcp": 1500, "cls": 0.02, "inp": 90}).encode()

    def send():
        req = urllib.request.Request(f"http://{ip}/__pcdn/rum", data=body, method="POST", headers={
            "Host": DOMAIN, "Content-Type": "text/plain;charset=UTF-8", "Origin": f"http://{DOMAIN}"})
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status == 204
    for _ in range(3):
        assert send()

    def report():
        rep = api.get(f"/api/v1/sites/{DOMAIN}/rum?hours=24")
        return rep if rep.get("n", 0) >= 3 else None
    try:
        rep = wait_until(report, "the RUM report to show the beacons", timeout=max(TIMEOUT, 240))
    except ApiError as e:
        if e.status == 404:
            pytest.skip("the controller has no RUM report (pre-wave-14 or plan without rum)")
        raise
    assert rep["metrics"]["lcp"]["p75"] > 0
    assert ip not in json.dumps(rep) and name not in json.dumps(rep)


def test_pinned_release_download_like_bootstrap(api):
    """bootstrap.sh's own release block (run here with the real curl) against GET /edge/releases."""
    try:
        with urllib.request.urlopen(CONTROLLER + "/edge/releases", timeout=10) as r:
            listing = json.loads(r.read())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            pytest.skip("pre-wave-14 controller or EDGE_RELEASES_DIR unset: no pinned releases")
        raise
    if not listing.get("releases"):
        pytest.skip("EDGE_RELEASES_DIR holds no release")
    if not BOOTSTRAP.exists():
        pytest.skip("edge/bootstrap.sh is not mounted here")
    text = BOOTSTRAP.read_text()
    if "# >>> pcdn bootstrap release" not in text:
        pytest.skip("pre-wave-14 bootstrap.sh")
    block = text.split("# >>> pcdn bootstrap release", 1)[1].split("\n", 1)[1].split("# <<< pcdn bootstrap release")[0]
    rel = listing["releases"][0]
    tmp = pathlib.Path(f"/tmp/w14-{uuid.uuid4().hex[:6]}")
    tmp.mkdir()
    proto = "--proto =https" if CONTROLLER.startswith("https") else "--proto =http,https"
    script = (f'CONTROLLER="{CONTROLLER}"; CURL_PROTO=({proto}); TMP="{tmp}"; VERSION="{rel["version"]}"; '
              f'GROUP=general\n' + block + '\necho "RELEASE=$RELEASE"')
    p = subprocess.run(["bash", "-euo", "pipefail", "-c", script], capture_output=True, text=True, timeout=300)
    assert p.returncode == 0, p.stdout + p.stderr
    assert f"RELEASE={rel['version']}" in p.stdout and "sha256 verified" in p.stdout
    assert (tmp / "bundle.tar.gz").stat().st_size == rel["size"]


def test_rollout_with_injected_failure_rolls_back(api, edges):
    target = os.environ.get("STAGING_ROLLOUT_RELEASE", "")
    inject = os.environ.get("STAGING_ROLLOUT_INJECT", "")
    if not target or not inject:
        pytest.skip("opt-in: STAGING_ROLLOUT_RELEASE and STAGING_ROLLOUT_INJECT")
    rows = _edge_rows(api)
    if not all((rows[n].get("capabilities") or {}).get("self_upgrade") for n in edges):
        pytest.skip("the staging edges cannot upgrade themselves (no systemd-run / pre-wave-14 agents)")
    if len(edges) < 2:
        pytest.skip("needs two edges")
    try:
        ro = api.post("/api/v1/rollouts", {"release": target, "soak_minutes": 5, "ring_percent": 50,
                                           "auto_rollback": True, "allow_no_rollback": False})
    except ApiError as e:
        if e.status == 404:
            pytest.skip("pre-wave-14 controller or unknown release")
        raise
    rid = ro["id"]
    if ro.get("state") == "planned":
        api.post(f"/api/v1/rollouts/{rid}/start")

    def canary_soaking():
        r = api.get(f"/api/v1/rollouts/{rid}")
        for ring in r["rings"]:
            for e in ring["edges"]:
                if e["state"] == "soaking":
                    return e["name"]
        return None
    canary = wait_until(canary_soaking, "the canary to soak on the new release", timeout=max(TIMEOUT, 900))
    subprocess.run(["sh", "-c", inject], env=dict(os.environ, EDGE=canary), check=False, timeout=60)
    final = wait_until(lambda: (lambda r: r if r["state"] in ("rolled_back", "failed") else None)(
        api.get(f"/api/v1/rollouts/{rid}")), "automatic rollback", timeout=max(TIMEOUT, 1800))
    assert final["state"] == "rolled_back", final
    time.sleep(1)
    after = _edge_rows(api)[canary]
    assert after.get("release") != target
