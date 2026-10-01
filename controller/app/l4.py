"""TCP/UDP proxy product "Spectrum" (SPEC §16.4): edge-port allocation, hostnames, edge config.

* Ports: every app of the section `l4` holds one edge port, unique across all sites of the same edge
  group (the nodes of a group carry the `stream` listeners of all its sites) and inside
  L4_PORT_RANGE. The table `l4_ports` (unique group + port) is the source of truth for that
  uniqueness, so two concurrent writers cannot take the same port: the loser gets 409.
* Hostname: `l4-<app id>.<domain>`, rendered by dnsbuild like a proxied host (the online edges of the
  site's group) while the app is enabled and the plan has l4_proxy; it disappears with the app.
* Edge config: node-wide `l4` list with the apps of the requesting node's group only, of active sites
  whose plan allows l4_proxy (at most max_l4_apps per site), enabled apps only.
* Billing: usage items carry `l4: {app id: {bytes_in, bytes_out, sessions}}`; both directions are
  added to the site's billed bytes (like tunnels).
"""

import json

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from . import dnsbuild, sections
from .config import settings
from .models import L4Port, Site


class PortConflict(Exception):
    """409: the port is used by another site of the same edge group / no free port is left."""


def _apps(site: Site) -> list[dict]:
    """The stored l4 apps of a site (validated; [] when absent or corrupt)."""
    try:
        stored = json.loads(site.config or "{}").get("l4") or {}
        return sections.dump(sections.L4.model_validate(stored))["apps"]
    except Exception:  # noqa: BLE001 - corrupt/legacy data: no apps
        return []


def apply_write(db: Session, site: Site, value: dict) -> dict:
    """Allocate / check the edge ports of a validated `l4` section and replace the site's rows in
    `l4_ports`. Apps without edge_port keep the port they already hold (same id), else get the
    lowest free port of L4_PORT_RANGE. Raises PortConflict. Caller commits (an IntegrityError on
    commit/flush is a concurrent allocation of the same port: also a conflict)."""
    group = dnsbuild.site_edge_group(site)
    lo, hi = settings.l4_port_range
    reserved = sections.ALWAYS_RESERVED_PORTS | settings.l4_reserved_ports
    rows = list(db.scalars(select(L4Port).where(L4Port.group == group)))
    others = {r.port: r for r in rows if r.site_id != site.id}
    held = {r.app_id: r.port for r in rows if r.site_id == site.id}
    apps = [dict(a) for a in value["apps"]]
    for a in apps:
        p = a["edge_port"]
        if p is not None and p in others:
            raise PortConflict(f"پورت {p} در این گروه لبه به سرویس دیگری اختصاص داده شده است؛ پورت دیگری "
                               "انتخاب کنید یا آن را خالی بگذارید تا خودکار تعیین شود")
    used = set(others) | {a["edge_port"] for a in apps if a["edge_port"] is not None}
    for a in apps:
        if a["edge_port"] is None and a["id"] in held and held[a["id"]] not in used:
            a["edge_port"] = held[a["id"]]
            used.add(a["edge_port"])
    free = (p for p in range(lo, hi + 1) if p not in used and p not in reserved)
    for a in apps:
        if a["edge_port"] is None:
            a["edge_port"] = next(free, None)
            if a["edge_port"] is None:
                raise PortConflict("پورت آزادی در بازه پورت‌های TCP/UDP باقی نمانده است")
    db.execute(delete(L4Port).where(L4Port.site_id == site.id))
    db.flush()
    for a in apps:
        db.add(L4Port(group=group, port=a["edge_port"], site_id=site.id, app_id=a["id"]))
    db.flush()
    return sections.storable("l4", {**value, "apps": apps})


def rehome(db: Session, site: Site) -> list[dict]:
    """The site moved to another edge group (plan change): move its port rows along. An app whose
    port is taken in the new group gets a new port (the section is updated). Returns
    [{"app_id", "old_port", "new_port"}] of the moved apps. Caller commits."""
    apps = _apps(site)
    if not apps:
        db.execute(delete(L4Port).where(L4Port.site_id == site.id))
        return []
    before = {a["id"]: a["edge_port"] for a in apps}
    group = dnsbuild.site_edge_group(site)
    taken = {r.port for r in db.scalars(select(L4Port).where(L4Port.group == group, L4Port.site_id != site.id))}
    value = {"apps": [dict(a, edge_port=None if a["edge_port"] in taken else a["edge_port"]) for a in apps]}
    stored = apply_write(db, site, value)
    sections.store_section(site, "l4", stored)
    return [{"app_id": a["id"], "old_port": before[a["id"]], "new_port": a["edge_port"]}
            for a in stored["apps"] if a["edge_port"] != before[a["id"]]]


def dns_names(site: Site) -> list[str]:
    """The `l4-<id>` names (relative to the zone) dnsbuild answers with the site's edges."""
    if getattr(site, "features", None) is None or getattr(site, "config", None) is None:
        return []  # a bare site stand-in (dnsbuild unit tests)
    feats = sections.features_of(site)
    if not feats["l4_proxy"]:
        return []
    return [f"l4-{a['id']}" for a in _apps(site)[: feats["max_l4_apps"]] if a["enabled"]]


def _serves(site: Site, edge, feats: dict) -> bool:
    return (edge is not None and feats["l4_proxy"] and site.effective_status == "active"
            and dnsbuild.site_edge_group(site) == dnsbuild.edge_group(edge))


def site_block(site: Site, edge) -> dict:
    """The per-site `l4` block of the edge config: the section shape ({"apps": [...]}, each app with
    its allocated edge_port and hostname) holding exactly the apps the node-wide `l4` list carries
    for this site — empty unless the requesting node is of the site's group, the site is active and
    its plan has l4_proxy; disabled apps and apps beyond max_l4_apps are left out."""
    feats = sections.features_of(site)
    if not _serves(site, edge, feats):
        return {"apps": []}
    return {"apps": [dict(a, hostname=sections.l4_hostname(a["id"], site.domain))
                     for a in _apps(site)[: feats["max_l4_apps"]] if a["enabled"] and a["edge_port"] is not None]}


def edge_block(db: Session, edge) -> list[dict]:
    """Node-wide `l4` list of the edge config for `edge` (see the module docstring)."""
    if edge is None:
        return []
    group = dnsbuild.edge_group(edge)
    out = []
    for site in db.scalars(select(Site).order_by(Site.id)):
        if dnsbuild.site_edge_group(site) != group:
            continue
        feats = sections.features_of(site)
        if not _serves(site, edge, feats):
            continue
        for a in _apps(site)[: feats["max_l4_apps"]]:
            if not a["enabled"] or a["edge_port"] is None:
                continue
            out.append({
                "site": site.domain,
                "site_id": site.id,
                "app_id": a["id"],
                "hostname": sections.l4_hostname(a["id"], site.domain),
                "protocol": a["protocol"],
                "port": a["edge_port"],
                "origin": {"address": a["origin"]["address"], "port": a["origin"]["port"]},
                "proxy_protocol": a["proxy_protocol"],
                "ip_allow": a["ip_allow"],
                "idle_timeout": a["idle_timeout"],
            })
    return sorted(out, key=lambda x: x["port"])


def delete_site(db: Session, site_id: int) -> None:
    db.execute(delete(L4Port).where(L4Port.site_id == site_id))
