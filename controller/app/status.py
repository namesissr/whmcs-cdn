"""Public status page data (SPEC §8.2).

Builds the /status.json payload from open incidents, DNS reachability and node
availability. It exposes ONLY aggregate node counts, the three component states and the
operator-written incident text — never a node IP, name, region, customer domain, or any
metric that could identify infrastructure.
"""

import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import settings
from .models import Edge, Incident, utcnow

log = logging.getLogger("pcdn.status")

# component / overall status, worst-first for max()
RANK = {"operational": 0, "maintenance": 1, "degraded": 2, "major_outage": 3}
RESOLVED_KEEP = 10

# a component name shown on the public page (Persian, no infrastructure detail)
CDN_NAME = "شبکه توزیع محتوا (CDN)"
TUNNEL_NAME = "سرویس تونل"
DNS_NAME = "DNS"


def worst(*statuses: str) -> str:
    return max(statuses, key=lambda s: RANK.get(s, 0)) if statuses else "operational"


def _nodes_status(enabled: int, online: int, probe_failing: int) -> str:
    if enabled == 0:
        return "operational"
    if online == 0:
        return "major_outage"
    if online < enabled or probe_failing > 0:
        return "degraded"
    return "operational"


def _dns_status(db: Session) -> str:
    from . import geocheck

    status = "operational"
    if settings.pdns_enabled:
        from . import pdns

        clients = pdns.client().clients
        down = sum(1 for c in clients if pdns.ping(c, timeout=3))
        if clients and down == len(clients):
            status = "major_outage"
        elif down:
            status = "degraded"
    try:
        if geocheck.geo_off_warning(db):
            status = worst(status, "degraded")
    except Exception:  # noqa: BLE001
        db.rollback()
    return status


def _incident_status(incidents: list[Incident]) -> str:
    sev_to_status = {"maintenance": "maintenance", "minor": "degraded", "major": "major_outage"}
    return worst("operational", *(sev_to_status.get(i.severity, "degraded") for i in incidents))


def incident_dict(inc: Incident, with_updates: bool = True) -> dict:
    out = {
        "id": inc.id,
        "title": inc.title,
        "body": inc.body,
        "severity": inc.severity,
        "status": inc.status,
        "created_at": inc.created_at.isoformat() + "Z",
        "updated_at": inc.updated_at.isoformat() + "Z",
    }
    if with_updates:
        out["updates"] = [{"at": u.created_at.isoformat() + "Z", "status": u.status, "body": u.body}
                          for u in inc.updates]
    return out


def public_status(db: Session) -> dict:
    from .services import online_edges

    edges = list(db.scalars(select(Edge).where(Edge.enabled.is_(True))))
    online_ids = {e.id for e in online_edges(db)}
    fail_checks = settings.probe_fail_checks

    def group_status(group: str | None) -> str:
        sel = [e for e in edges if group is None or e.group == group]
        online = sum(1 for e in sel if e.id in online_ids)
        probe_failing = sum(1 for e in sel if (e.probe_fail or 0) >= fail_checks)
        return _nodes_status(len(sel), online, probe_failing)

    cdn = group_status("general")
    tunnel = group_status("tunnel")
    dns = _dns_status(db)

    open_incidents = list(db.scalars(
        select(Incident).where(Incident.status != "resolved").order_by(Incident.id.desc())))
    resolved = list(db.scalars(
        select(Incident).where(Incident.status == "resolved")
        .order_by(Incident.id.desc()).limit(RESOLVED_KEEP)))

    overall = worst(cdn, tunnel, dns, _incident_status(open_incidents))
    total = len(edges)
    online = len(online_ids & {e.id for e in edges})
    return {
        "status": overall,
        "updated_at": utcnow().isoformat() + "Z",
        "nodes": {"total": total, "online": online},
        "components": [
            {"name": CDN_NAME, "status": cdn},
            {"name": TUNNEL_NAME, "status": tunnel},
            {"name": DNS_NAME, "status": dns},
        ],
        "incidents": [incident_dict(i) for i in open_incidents] + [incident_dict(i) for i in resolved],
    }
