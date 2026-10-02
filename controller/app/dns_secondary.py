"""Secondary DNS (SPEC §16.7): section `dns_secondary` -> PowerDNS zone kind, masters, TSIG key and
zone metadata.

* mode "primary_elsewhere": the zone becomes a PowerDNS **Slave** zone with `masters` = the
  customer's primaries on every nameserver of PDNS_API_URL (each one transfers the zone itself);
  with `tsig` the transfer is signed (metadata AXFR-MASTER-TSIG). The records managed by this
  controller are not published while the zone is a slave (pdns.sync_zone skips the rrset write).
* `allow_axfr`: the customer's own secondaries may transfer the zone from us (metadata
  ALLOW-AXFR-FROM), always TSIG-signed (metadata TSIG-ALLOW-AXFR = the tsig key).
* The TSIG key is created / updated through the PowerDNS tsigkeys API under the customer's key name
  (it must match on both ends), so one key name belongs to one site only (409 otherwise).

PowerDNS needs `secondary=yes` (4.5+; `slave=yes` before) for slave zones; AXFR out is governed by
the per-zone metadata above.
"""

import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import sections, site_secrets
from .models import Site

SECRET_KEY = "tsig"
OFF = {"kind": "Native", "masters": [], "tsig": None, "allow_axfr": []}


class TsigConflict(Exception):
    """409: the TSIG key name is already used by another site."""


def _stored(site) -> dict | None:
    try:
        raw = json.loads(getattr(site, "config", None) or "{}").get("dns_secondary")
    except (ValueError, AttributeError):
        return None
    if raw is None:
        return None
    try:
        return sections.dump(sections.DnsSecondary.model_validate(raw, context=sections.STORED))
    except Exception:  # noqa: BLE001 - corrupt: treat as off
        return sections.dump(sections.DnsSecondary())


def configured(site) -> bool:
    """The site has a stored dns_secondary section (it uses or once used secondary DNS)."""
    return _stored(site) is not None


def spec(site, force: bool = False) -> dict | None:
    """What PowerDNS should hold for the site's zone: {"kind", "masters", "tsig": {name, algorithm,
    secret} | None, "allow_axfr"}. None when nothing needs managing (the section is off / never set)
    unless `force` (the write path also clears what an earlier setting left behind)."""
    value = _stored(site)
    if value is None or (value["mode"] == "off" and not value["allow_axfr"] and not value["tsig"]):
        return dict(OFF) if force else None
    tsig = None
    if value["tsig"]:
        try:
            secret = site_secrets.get_secret(site, SECRET_KEY)
        except Exception:  # noqa: BLE001 - undecryptable: no TSIG (transfers fail closed)
            secret = None
        if secret:
            tsig = {"name": value["tsig"]["name"], "algorithm": value["tsig"]["algorithm"], "secret": secret}
    slave = value["mode"] == "primary_elsewhere"
    return {"kind": "Slave" if slave else "Native", "masters": value["primaries"] if slave else [],
            "tsig": tsig, "allow_axfr": value["allow_axfr"] if tsig else []}


def apply_write(db: Session, site: Site, value: dict) -> tuple[dict, str | None]:
    """PUT dns_secondary: store a supplied TSIG secret encrypted (""/omitted keeps the stored one for
    the same key name), forget it when tsig is null. Returns (section as stored, old TSIG key name to
    remove from PowerDNS or None). Raises TsigConflict."""
    old = _stored(site)
    old_name = old["tsig"]["name"] if old and old.get("tsig") else None
    tsig = value.get("tsig")
    if tsig:
        name = tsig["name"]
        for other in db.scalars(select(Site).where(Site.id != site.id, Site.config.contains(name))):
            o = _stored(other)
            if o and o.get("tsig") and o["tsig"]["name"] == name:
                raise TsigConflict(f"کلید TSIG با نام «{name}» برای سرویس دیگری ثبت شده است؛ نام دیگری "
                                   "انتخاب کنید")
        if tsig.get("secret"):
            site_secrets.set_secret(site, SECRET_KEY, tsig["secret"])
    else:
        site_secrets.set_secret(site, SECRET_KEY, None)
    new_name = tsig["name"] if tsig else None
    stale = old_name if old_name and old_name != new_name else None
    return sections.storable("dns_secondary", value), stale
