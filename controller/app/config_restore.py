"""Writing whole sections back under the CURRENT plan (SPEC §23.4 restore, §23.6 import apply).

Every section is re-validated with `validate_section` against the current plan: a feature gate drops
the section (warning), a list limit (`max_*`) truncates the list keeping the first items (warning), any
other validation error drops the section with its message. Write-only secrets (`site_secrets`) are never
changed: a restored `logs.enabled` without a stored secret is restored disabled; restored webhook items
whose id has no signing secret get a new one (warning). Everything happens in the caller's
transaction, so one commit produces one config-history version.
"""

import json

import pydantic
from fastapi import HTTPException
from sqlalchemy.orm import Session

from . import config_history, sections, site_secrets
from .models import Site
from .services import lock_site
from .validation import ValidationError

LIMITS = {"firewall": ("rules", "max_firewall_rules"), "ratelimit": ("rules", "max_ratelimit_rules"),
          "pagerules": ("rules", "max_page_rules"), "pools": ("pools", "max_pools"),
          "transform": ("rules", "max_transform_rules"), "redirects": ("rules", "max_redirects"),
          "webhooks": ("items", "max_webhooks"), "l4": ("apps", "max_l4_apps"),
          "functions": ("items", "max_functions")}
W_FEATURE = "این بخش به قابلیتی نیاز دارد که در پلن فعلی نیست"


def _err(e: Exception) -> str:
    if isinstance(e, pydantic.ValidationError):
        return "; ".join(err["msg"].removeprefix("Value error, ") for err in e.errors())[:300]
    if isinstance(e, HTTPException):
        return str(e.detail)[:300]
    return str(e)[:300]


def apply_sections(db: Session, site: Site, values: dict) -> dict:
    """Validate + store each section (caller holds the site lock and commits). Returns {"applied",
    "dropped", "warnings", "touched"} (touched: sections whose PowerDNS state must be re-synced)."""
    from .routes_v2 import apply_section_write

    feats = sections.features_of(site)
    applied, dropped, warnings, touched = [], [], [], []
    pools_in_use = {r.pool for r in site.records if r.pool}
    for name, raw in values.items():
        if name not in sections.SECTIONS:
            continue
        if config_history.is_omitted(raw):
            dropped.append({"section": name, "reason": "not_restorable"})
            continue
        value = json.loads(json.dumps(raw))
        gate = sections.FEATURE_GATES.get(name)
        if gate and not feats.get(gate):
            try:
                parsed = sections.dump(sections.SECTIONS[name].model_validate(value, context=sections.STORED))
            except pydantic.ValidationError:
                parsed = None
            if parsed is None or (parsed != sections.dump(sections.SECTIONS[name]())
                                  and sections._is_enabled(name, parsed)):
                dropped.append({"section": name, "reason": "feature_missing", "feature": gate})
                warnings.append(f"{name}: {W_FEATURE}")
                continue
        if name in LIMITS and isinstance(value.get(LIMITS[name][0]), list):
            key, feat = LIMITS[name]
            limit = int(feats.get(feat) or 0)
            if len(value[key]) > limit:
                removed = len(value[key]) - limit
                value[key] = value[key][:limit]
                dropped.append({"section": name, "reason": "limit", "feature": feat, "kept": limit, "removed": removed})
                warnings.append(f"{name}: فقط {limit} مورد اول نگه داشته شد (سقف پلن فعلی)")
        if name == "logs" and value.get("enabled") and not site_secrets.has_logs_secret(site):
            value["enabled"] = False
            warnings.append("logs: کلید مخفی خروجی لاگ ذخیره نشده است؛ خروجی لاگ خاموش بازگردانده شد")
        try:
            v = sections.validate_section(site, name, value, pools_in_use)
            if name == "webhooks":
                ids = site_secrets.webhook_secret_ids(site)
                items = []
                for item in v["items"]:
                    item = dict(item)
                    if not item.get("id"):
                        from . import webhooks

                        item["id"] = webhooks.new_hook_id({x.get("id") for x in items})
                    if item["id"] not in ids:
                        site_secrets.set_webhook_secret(site, item["id"], site_secrets.new_webhook_secret())
                        warnings.append(f"کلید امضای وبهوک {item['id']} از نو ساخته شد؛ آن را در صفحهٔ وبهوک "
                                        "بچرخانید و دوباره بردارید")
                    items.append(item)
                site_secrets.keep_webhook_secrets(site, {i["id"] for i in items})
                v = sections.storable("webhooks", {**v, "items": items})
            else:
                v, _, _ = apply_section_write(db, site, name, v)
        except (pydantic.ValidationError, ValidationError, PermissionError, ValueError, HTTPException) as e:
            dropped.append({"section": name, "reason": "invalid", "detail": _err(e)})
            continue
        sections.store_section(site, name, v)
        applied.append(name)
        if name in ("l4", "dns_secondary"):
            touched.append(name)
    return {"applied": applied, "dropped": dropped, "warnings": warnings, "touched": touched}


def restore(db: Session, site: Site, version: int, wanted: list[str] | None, dry_run: bool,
            exclude: tuple = ()) -> dict:
    """POST …/config/history/{version}/restore (SPEC §23.4). Raises HTTPException 404 / 429."""
    from .services import sync_site_dns

    if config_history.get_version(db, site.id, version) is None:
        raise HTTPException(404, "version not found")
    if not dry_run and config_history.restores_last_hour(db, site.id) >= config_history.RESTORES_PER_HOUR:
        raise HTTPException(429, "rate_limited")
    target = config_history.config_at(db, site.id, version) or {}
    site = lock_site(db, site)
    stored = config_history._stored(site.config)
    differing = [n for n in sections.SECTIONS
                 if config_history.sha(target.get(n)) != config_history.sha(config_history.section_value(stored, n))
                 and not (config_history.is_omitted(target.get(n))
                          and target[n].get("sha256") == config_history.sha(config_history.section_value(stored, n)))]
    if wanted is None:
        chosen = [n for n in differing if n not in exclude]
    else:
        bad_names = [n for n in wanted if n not in sections.SECTIONS]
        if bad_names:
            raise HTTPException(422, f"unknown section: {bad_names[0]}")
        chosen = list(dict.fromkeys(wanted))
    unchanged = [n for n in chosen if n not in differing]
    todo = {n: target.get(n) for n in chosen if n in differing}
    with config_history.source("restore", restored_from=version):
        result = apply_sections(db, site, todo)
        if dry_run:
            db.rollback()
            new_version = None
        else:
            db.commit()
            new_version = config_history.current_version(db, site.id) if result["applied"] else None
    if not dry_run:
        for name in result["touched"]:
            sync_site_dns(db, site, force_secondary=name == "dns_secondary")
    return {"version": new_version, "restored_from": version, "applied": result["applied"],
            "unchanged": unchanged, "dropped": result["dropped"], "warnings": result["warnings"]}
