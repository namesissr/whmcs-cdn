"""Audit log of platform mutations (SPEC §13.2).

Only *writes* are recorded (reads are never audited). `record_audit` is called by the admin,
customer-API and scheduler code paths after a change has been committed. The `detail` document
is reduced to a small whitelist of non-sensitive keys, so a secret, token, private key or
password can never end up in the log even if a caller passes one in.
"""

import json
import logging
import re

from sqlalchemy.orm import Session

from .models import AuditLog

log = logging.getLogger("pcdn.audit")

# SPEC §20.3: WHMCS names the person behind an admin-key write made for a domain collaborator
# ("share:<member client id>:<role>"); anything else in the header is ignored
_ACTOR_RE = re.compile(r"^[a-z0-9:_-]{1,64}$")


def on_behalf_of(request) -> str | None:
    """The validated X-PCDN-Actor header of an admin request, or None."""
    try:
        v = (request.headers.get("x-pcdn-actor") or "").strip() if request is not None else ""
    except Exception:  # noqa: BLE001 - a request stub without headers
        return None
    return v if _ACTOR_RE.match(v) else None


def with_actor(detail: dict | None, request) -> dict | None:
    """`detail` plus {"on_behalf_of": ...} when the request names one."""
    who = on_behalf_of(request)
    if who is None:
        return detail
    return {**(detail or {}), "on_behalf_of": who}

# Only these keys may appear in a detail document. Anything else (and anything that looks like a
# secret — see _SECRET_HINTS) is dropped. Keep this list small and non-sensitive.
DETAIL_WHITELIST = {
    # SPEC §20.3: the domain collaborator WHMCS acted for (validated X-PCDN-Actor)
    "on_behalf_of",
    # sites / plan
    "domain", "external_id", "origin_ip", "plan", "bandwidth_limit_gb", "max_records",
    "ssl_allowed", "rate_limit_rps", "features", "ssl_source", "dnssec",
    # reseller tag
    "reseller_client_id", "reseller_label",
    # edges / addresses
    "name", "region", "group", "capacity_mbps", "enabled", "ipv4", "ipv6",
    "family", "ip", "label", "address_id", "count", "shield",
    # records / config / keys / purge
    "record_id", "type", "section", "key_id", "scopes", "name_count",
    "everything", "urls", "prefixes", "items", "fields",
    # bulk imports (e.g. redirects CSV): replace | append
    "mode",
    # webhooks / log export (SPEC §14.3): which hook, and the outcome of a test
    "hook_id", "ok",
    # wave 10 (SPEC §18.2): access app id and a hash reference of the e-mail address (never the
    # address or the code), access.rotate / access.otp_sent
    "app", "email_ref",
    # SPEC §19: site owner (client_id / owner_kind / operator_note) and site.transfer
    # {from, to, related, revoked_keys, paused, billing_since, dry_run}
    "client_id", "owner_kind", "operator_note", "from", "to", "related", "revoked_keys", "paused",
    "billing_since", "rotated",
    # wave 13 (SPEC §22): edge.drain {minutes, reason, force}, edge.undrain {auto, hold_minutes},
    # edge.patch http3_enabled
    "minutes", "reason", "force", "auto", "hold_minutes", "http3_enabled",
}
# whitelisted keys that contain a _SECRET_HINTS substring but hold no secret (a count)
_HINT_EXEMPT = {"revoked_keys"}
# NB "items" is also how a functions write is audited (SPEC §16.9): [{id, route, enabled, code_bytes}],
# never the code itself (sections.functions_audit)
# a key containing any of these substrings is never stored, as a second line of defence
_SECRET_HINTS = ("secret", "token", "key", "password", "passphrase", "cert", "hash", "private")


def _clean_detail(detail: dict | None) -> dict:
    if not detail:
        return {}
    out = {}
    for k, v in detail.items():
        kl = str(k).lower()
        if k not in DETAIL_WHITELIST:
            continue
        if k not in _HINT_EXEMPT and any(h in kl for h in _SECRET_HINTS):
            continue
        out[k] = v
    return out


def record_audit(db: Session, *, actor: str, actor_kind: str, action: str,
                 target: str | None = None, detail: dict | None = None, ip: str | None = None) -> None:
    """Append one audit entry and commit it. Never raises — auditing must not break a mutation
    that already succeeded."""
    try:
        row = AuditLog(
            actor=(str(actor)[:120] if actor else ""),
            actor_kind=actor_kind,
            action=action,
            target=(str(target)[:253] if target is not None else None),
            detail=json.dumps(_clean_detail(detail), ensure_ascii=False, sort_keys=True),
            ip=(str(ip)[:45] if ip else None),
        )
        db.add(row)
        db.commit()
    except Exception:  # noqa: BLE001 - auditing never breaks the caller
        log.exception("audit write failed for %s", action)
        try:
            db.rollback()
        except Exception:  # noqa: BLE001
            pass
