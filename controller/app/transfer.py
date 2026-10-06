"""Domain transfer: a complete move of a site to another owner (SPEC §19.2).

Directions: client -> client, operator -> client, client -> operator. Reseller sub-sites are moved by
the reseller tooling only. In ONE transaction, for the site (and, with include_related, every
same-owner parent/child site linked to it, tenancy.owner_group):

* owner fields (owner_kind, client_id, reseller fields, external_id, operator_note) are replaced;
* ``revoke_credentials``: the customer API keys of the site are revoked;
* ``pause_integrations``: log export and every webhook endpoint are disabled and their stored secrets
  cleared (the other settings are kept so the new owner re-enables them with their own secrets); the
  old owner's queued webhook deliveries and spooled log chunks are dropped, so nothing reaches the
  old owner's endpoints / bucket and the new owner never receives the old owner's logs;
* the access-app secret is rotated (every session and pending one-time code ends);
* ``revoke_credentials`` also rotates every other credential the old owner may hold: the image
  transform signing key, the secondary-DNS TSIG secret (pushed to PowerDNS after the commit like a
  normal TSIG change; the customer-side primary / secondary must be re-configured with the new
  secret by the new owner) and the access keys of the site's storage buckets. MinIO cannot be part
  of the DB transaction: the buckets are marked ``credentials_rotation_pending_at`` in it and rotated
  right after the commit (after_commit); a failure stays marked and scheduler.job_storage_rotation
  retries until done (/healthz/deep warns meanwhile);
* ``reset_billing_anchor``: billing_since = now (quota and WHMCS month usage count from there).

Everything else (DNS records, config sections, SSL, rules, WAF, functions, storage buckets, analytics
and usage history) stays with the site. No webhook is emitted (the old owner's endpoints are paused
first and nothing is sent to the new owner either).
"""

import base64
import json
import secrets as pysecrets
from datetime import datetime

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from . import access, dns_secondary, images, logexport, sections, site_secrets, storage, tenancy
from .models import ApiKey, LogSpool, Site, State, StorageBucket, WebhookDelivery, utcnow
from .services import lock_site, refresh_quota, sync_site_dns

RESELLER_MSG = ("زیرسایت‌های نماینده (reseller) از اینجا منتقل نمی‌شوند؛ انتقال آن‌ها فقط با ابزار نمایندگی "
                "انجام می‌شود")
SAME_OWNER_MSG = "این دامنه همین حالا متعلق به همین مالک است"
OPERATOR_TARGET_MSG = "برای انتقال به اپراتور client_id و external_id نباید فرستاده شود"
CLIENT_TARGET_MSG = "برای انتقال به مشتری client_id مقصد لازم است (و operator_note مجاز نیست)"


class TransferError(Exception):
    """A refused transfer (HTTP 422, Persian message)."""


def owner_view(site: Site) -> dict:
    return {"kind": site.owner_kind or "client", "client_id": site.client_id, "external_id": site.external_id}


def clean_note(note: str | None) -> str | None:
    """operator_note: one line of plain text, ≤200 characters; empty = none."""
    if note is None:
        return None
    note = "".join(ch for ch in note if ch >= " " and ch != "\x7f").strip()[:200]
    return note or None


def _stored_config(site: Site) -> dict:
    try:
        doc = json.loads(site.config or "{}")
    except ValueError:
        doc = {}
    return doc if isinstance(doc, dict) else {}


def pause_integrations(db: Session, site: Site) -> list[dict]:
    """Disable log export + every webhook, clear their stored secrets, keep their other settings.
    Returns what was paused: [{domain, type: logs|webhook, id, url}]. Caller commits."""
    out: list[dict] = []
    stored = _stored_config(site)
    logs = stored.get("logs")
    logs = logs if isinstance(logs, dict) else None
    if (logs is not None and logs.get("enabled")) or site_secrets.has_logs_secret(site):
        out.append({"domain": site.domain, "type": "logs", "id": None, "url": None})
    if logs is not None and logs.get("enabled"):
        sections.store_section(site, "logs", {**logs, "enabled": False})
    site_secrets.set_logs_secret(site, None)

    hooks = stored.get("webhooks")
    with_secret = site_secrets.webhook_secret_ids(site)
    if isinstance(hooks, dict) and isinstance(hooks.get("items"), list):
        items = []
        for item in hooks["items"]:
            if isinstance(item, dict):
                if item.get("enabled", True) or item.get("id") in with_secret:
                    out.append({"domain": site.domain, "type": "webhook", "id": item.get("id"),
                                "url": item.get("url")})
                item = {**item, "enabled": False}
            items.append(item)
        sections.store_section(site, "webhooks", {**hooks, "items": items})
    site_secrets.keep_webhook_secrets(site, set())

    # the old owner's queued deliveries and spooled log chunks never go anywhere
    db.execute(delete(WebhookDelivery).where(WebhookDelivery.site_id == site.id))
    db.execute(delete(LogSpool).where(LogSpool.site_id == site.id))
    db.execute(delete(State).where(State.key.in_([logexport.STATUS_KEY.format(site.id),
                                                  logexport.DROPPED_KEY.format(site.id)])))
    return out


# raw TSIG key bytes per algorithm (the HMAC block / output size; ≥16 bytes as sections.Tsig requires)
TSIG_KEY_BYTES = {"hmac-sha256": 32, "hmac-sha384": 48, "hmac-sha512": 64, "hmac-sha1": 32, "hmac-md5": 32}


def rotate_tsig(site: Site) -> str | None:
    """A new TSIG secret for the site's dns_secondary key (same name / algorithm); returns the key
    name, or None when the site has no TSIG key. Caller commits, then pushes it (sync_site_dns)."""
    tsig = (_stored_config(site).get("dns_secondary") or {}).get("tsig")
    if not isinstance(tsig, dict) or not site_secrets.has_secret(site, dns_secondary.SECRET_KEY):
        return None
    n = TSIG_KEY_BYTES.get(tsig.get("algorithm"), 32)
    site_secrets.set_secret(site, dns_secondary.SECRET_KEY, base64.b64encode(pysecrets.token_bytes(n)).decode())
    return tsig.get("name")


def _check_target(to) -> tenancy.Owner:
    if to.kind == "operator":
        if to.client_id is not None or to.external_id is not None:
            raise TransferError(OPERATOR_TARGET_MSG)
        return tenancy.OPERATOR
    if to.client_id is None or to.operator_note:
        raise TransferError(CLIENT_TARGET_MSG)
    return to.client_id


def transfer(db: Session, site: Site, body, now: datetime | None = None) -> tuple[dict, dict]:
    """Apply (or, with body.dry_run, compute) a transfer -> (response, post-commit work for
    after_commit). Does NOT commit or roll back: the caller commits and then calls after_commit, or
    rolls back for a dry run. Raises TransferError (422)."""
    now = now or utcnow()
    to = body.to
    new_owner = _check_target(to)
    site = lock_site(db, site)
    if site.owner_kind == "reseller":
        raise TransferError(RESELLER_MSG)
    old_owner = tenancy.site_owner(site)
    if old_owner is not None and old_owner == new_owner:
        raise TransferError(SAME_OWNER_MSG)

    group, foreign = tenancy.owner_group(db, site)
    resellers = [s.domain for s in group if s.owner_kind == "reseller"]
    if resellers:
        raise TransferError(f"{RESELLER_MSG}: سایت مرتبط {'، '.join(resellers)} زیرسایت نماینده است")
    if group and not body.include_related:
        raise TransferError(
            f"سایت‌های مرتبط (دامنهٔ والد یا زیردامنه) با همین مالک وجود دارند: {'، '.join(s.domain for s in group)}؛ "
            "یا آن‌ها را هم با include_related منتقل کنید یا ابتدا جدایشان کنید")
    blockers = [s.domain for s in foreign if not tenancy.same_owner(new_owner, s)]
    if blockers:
        raise TransferError(
            f"دامنهٔ والد یا زیردامنهٔ {'، '.join(blockers)} متعلق به حساب دیگری است؛ پس از انتقال "
            "سایت‌های تودرتو مالک متفاوت خواهند داشت (C1)")

    moving = sorted([site, *group], key=lambda s: s.id)
    for i, s in enumerate(moving):  # row locks in id order (no deadlock between two transfers)
        moving[i] = lock_site(db, s)
    before = owner_view(site)

    revoked = 0
    paused: list[dict] = []
    image_key = False
    tsig: list[dict] = []
    tsig_ids: list[int] = []
    buckets: list[StorageBucket] = []
    for s in moving:
        main = s.id == site.id
        if to.kind == "operator":
            s.owner_kind = "operator"
            s.client_id = s.reseller_client_id = s.reseller_label = s.external_id = None
            s.operator_note = clean_note(to.operator_note) if main else None
        else:
            s.owner_kind = "client"
            s.client_id = to.client_id
            s.reseller_client_id = s.reseller_label = None
            s.operator_note = None
            if main and "external_id" in to.model_fields_set:
                s.external_id = to.external_id
        if body.revoke_credentials:
            for k in db.scalars(select(ApiKey).where(ApiKey.site_id == s.id, ApiKey.revoked.is_(False))):
                k.revoked = True
                revoked += 1
            if site_secrets.has_secret(s, images.SECRET_KEY):
                images.rotate(s)  # old signed image URLs stop working
                image_key = True
            name = rotate_tsig(s)
            if name is not None:
                tsig.append({"domain": s.domain, "name": name})
                tsig_ids.append(s.id)
            for b in db.scalars(select(StorageBucket).where(StorageBucket.site_id == s.id)
                                .order_by(StorageBucket.id)):
                b.credentials_rotation_pending_at = now
                buckets.append(b)
        if body.pause_integrations:
            paused += pause_integrations(db, s)
        if site_secrets.has_secret(s, access.SECRET_KEY):
            access.rotate(s)  # every access-app session / pending code of the old owner ends
        if body.reset_billing_anchor:
            s.billing_since = now
            s.quota_warned_at = None
            refresh_quota(db, s, now, emit=False)
    db.flush()
    return {
        "domain": site.domain,
        "from": before,
        "to": owner_view(site),
        "related": [s.domain for s in group],
        "revoked_keys": revoked,
        "paused": paused,
        "access_rotated": [s.domain for s in moving if site_secrets.has_secret(s, access.SECRET_KEY)],
        "billing_since": site.billing_since.isoformat() + "Z" if site.billing_since else None,
        # revoke_credentials: what was (dry_run: would be) rotated. tsig: the customer's own DNS servers
        # must get the new secret; buckets: done after the commit, `pending` ones are retried
        "rotated": {"image_key": image_key, "tsig": tsig,
                    "buckets": {"done": [], "pending": [b.bucket for b in buckets]}},
        "dry_run": bool(body.dry_run),
    }, {"tsig_site_ids": tsig_ids, "bucket_ids": [b.id for b in buckets]}


def after_commit(db: Session, result: dict, post: dict) -> dict:
    """After the transfer's commit: push the rotated TSIG keys to PowerDNS (a failure marks DNS dirty,
    the scheduler re-syncs) and rotate the storage keys on MinIO (failures stay pending and are
    retried by scheduler.job_storage_rotation). Updates and returns `result`."""
    for entry, sid in zip(result["rotated"]["tsig"], post["tsig_site_ids"]):
        s = db.get(Site, sid)
        entry["dns_error"] = sync_site_dns(db, s, force_secondary=True) if s is not None else None
    if post["bucket_ids"]:
        done, pending = storage.rotate_pending(db, post["bucket_ids"])
        result["rotated"]["buckets"] = {"done": done, "pending": pending}
    return result
