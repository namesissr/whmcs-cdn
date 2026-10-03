"""Node drain on the staging stack (SPEC §22.1, §22.16): drain an edge -> it leaves the zone, a new
WebSocket session through it is refused only after the DNS grace, undrain restores it.

Skipped when the controller has no drain endpoint (pre-wave-13) or an edge's agent does not enforce the
drain flag (capabilities.drain), so the suite keeps passing against older stacks."""

import time
import uuid

import pytest

from conftest import ApiError, KEEP, ORIGIN_IP, TIMEOUT, dig, new_domain, wait_until, ws_echo

DOMAIN = new_domain("drain")
TUNNEL_PATH = "/drain-ws-" + uuid.uuid4().hex[:6]


def _iso_ts(v):
    from datetime import datetime, timezone
    if not v:
        return None
    dt = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp()


@pytest.fixture(scope="module")
def tsite(api, edges):
    if len(edges) < 2:
        pytest.skip("draining needs a second edge in the group (409 last_edge otherwise)")
    plan = {"ssl_allowed": False, "bandwidth_limit_gb": 0, "features": {"tunnel": True, "max_tunnel_paths": 5}}
    out = api.post("/api/v1/sites", {"domain": DOMAIN, "origin_ip": ORIGIN_IP, "external_id": "staging-drain",
                                     "plan": plan})
    api.put(f"/api/v1/sites/{DOMAIN}/config/tunnel", {
        "enabled": True, "fallback": "origin",
        "paths": [{"id": "ws", "path": TUNNEL_PATH, "protocol": "ws", "origin": {"address": ORIGIN_IP, "port": 8080}}]})
    yield out
    if not KEEP:
        try:
            api.delete(f"/api/v1/sites/{DOMAIN}")
        except ApiError:
            pass


def _echo_ok(ip):
    msg = "drain-" + uuid.uuid4().hex
    status, got = ws_echo(ip, DOMAIN, TUNNEL_PATH, msg)
    return status == 101 and got == msg


def test_drain_leaves_the_zone_refuses_after_the_grace_and_undrain_restores(api, edges, tsite):
    rows = {e["name"]: e for e in api.get("/api/v1/edges")}
    name = sorted(edges)[0]
    ip, edge = edges[name], rows[name]
    if not (edge.get("capabilities") or {}).get("drain"):
        pytest.skip("the edge agent does not enforce drain (capabilities.drain)")
    wait_until(lambda: _echo_ok(ip), f"WebSocket echo through {name}")
    try:
        out = api.post(f"/api/v1/edges/{edge['id']}/drain", {"minutes": 10, "reason": "staging"})
    except ApiError as e:
        if e.status in (404, 405):
            pytest.skip("the controller has no drain endpoint (pre-wave-13)")
        raise
    try:
        drain = out["edge"]["drain"]
        assert drain["state"] in ("draining", "drained")
        # DNS: the drained edge leaves the answers of the tunnel site
        wait_until(lambda: ip not in dig(DOMAIN, "A") and dig(DOMAIN, "A"), f"{name} out of the {DOMAIN} answers")
        # the refusal starts after the DNS grace (PROXIED_TTL + 30 s from the start of the drain)
        since = _iso_ts(drain.get("since")) or time.time()
        if time.time() < since + 25:
            assert _echo_ok(ip), "a new session was refused before the DNS grace"
        # after the grace, a NEW session through the drained edge is refused (503, the agent's njs flag)
        def refused():
            status, _ = ws_echo(ip, DOMAIN, TUNNEL_PATH, "x")
            return status == 503
        wait_until(refused, f"new sessions refused on {name}", timeout=max(TIMEOUT, 480))
        # the other edges keep serving
        for other, oip in edges.items():
            if other != name:
                assert _echo_ok(oip)
    finally:
        api.delete(f"/api/v1/edges/{edge['id']}/drain")
    wait_until(lambda: _echo_ok(ip), f"{name} serves new sessions again after undrain", timeout=max(TIMEOUT, 120))
    wait_until(lambda: ip in dig(DOMAIN, "A"), f"{name} back in the {DOMAIN} answers")
