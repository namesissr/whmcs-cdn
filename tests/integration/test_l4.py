"""TCP proxy (SPEC §16.4) through the staging edges: an L4 app is allocated an edge port by the controller,
the agents render a stream {} listener, and bytes sent to <edge>:<port> come back from the origin's TCP
echo (:9000). Skipped with STAGING_L4=0."""

import os
import socket
import uuid

import pytest

from conftest import ApiError, KEEP, ORIGIN_IP, dig, new_domain, wait_until

pytestmark = [pytest.mark.l4, pytest.mark.skipif(os.environ.get("STAGING_L4", "1") == "0",
                                                 reason="STAGING_L4=0")]

DOMAIN = new_domain("l4")


@pytest.fixture(scope="module")
def l4_site(api, edges):
    api.post("/api/v1/sites", {"domain": DOMAIN, "origin_ip": ORIGIN_IP, "plan": {
        "ssl_allowed": False, "features": {"l4_proxy": True, "max_l4_apps": 2}}})
    assert api.post(f"/api/v1/sites/{DOMAIN}/ns-check")["ok"]  # L4 apps are served for active sites only
    yield DOMAIN
    if not KEEP:
        try:
            api.delete(f"/api/v1/sites/{DOMAIN}")
        except ApiError:
            pass


def _echo(ip: str, port: int, payload: bytes) -> bytes:
    with socket.create_connection((ip, port), timeout=5) as s:
        s.sendall(payload)
        got = b""
        while len(got) < len(payload):
            chunk = s.recv(65536)
            if not chunk:
                break
            got += chunk
        return got


def test_tcp_proxy_through_every_edge(api, edges, l4_site):
    out = api.put(f"/api/v1/sites/{DOMAIN}/config/l4", {"apps": [
        {"id": "echo", "protocol": "tcp", "origin": {"address": ORIGIN_IP, "port": 9000}}]})
    app = out["apps"][0]
    port = app["edge_port"]
    assert port and 20000 <= port <= 29999, app
    assert app["hostname"] == f"l4-echo.{DOMAIN}"
    rows = {e["name"]: e for e in api.get("/api/v1/edges")}
    for name, ip in edges.items():
        if not (rows[name]["capabilities"] or {}).get("l4"):
            pytest.fail(f"{name} does not report the l4 capability: {rows[name]['capabilities']}")
        payload = uuid.uuid4().hex.encode() * 4
        wait_until(lambda: _echo(ip, port, payload) == payload, f"TCP echo via {name}:{port}")
    wait_until(lambda: sorted(dig(f"l4-echo.{DOMAIN}", "A")) == sorted(edges.values()),
               "l4-<id> hostname answering with the edges")
