"""Cloudflare DNS (+ four settings) import (SPEC §23.6). A read-only API token (Zone.Zone Read +
Zone.DNS Read) as `Authorization: Bearer <token>`; base `CLOUDFLARE_API_URL`. The token is a parameter
of `fetch` only: never stored, logged or put into an error."""

from ..config import settings
from . import MAX_RECORDS, Budget, ProviderError, clamp_ttl, client, get_json, relative

UNMAPPED = [{"what": "other_settings", "reason": "از Cloudflare فقط رکوردهای DNS و چهار تنظیم منتقل می‌شوند"}]


def fetch(api_key: str, zone: str, budget: Budget | None = None) -> dict:
    budget = budget or Budget()
    base = settings.cloudflare_api_url.rstrip("/")
    token = (api_key or "").strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    name = zone.strip().rstrip(".").lower()
    with client() as c:
        doc = get_json(c, f"{base}/zones", headers, budget, params={"name": name}, zone_check=True)
        zones = (doc or {}).get("result") or []
        if not zones:
            raise ProviderError("provider_zone_not_found")
        zid = str(zones[0].get("id") or "")
        if not zid.isalnum():
            raise ProviderError("provider_zone_not_found")
        records, page = [], 1
        while True:
            doc = get_json(c, f"{base}/zones/{zid}/dns_records", headers, budget,
                           params={"per_page": 100, "page": page})
            items = [x for x in (doc or {}).get("result") or [] if isinstance(x, dict)]
            records += items
            if len(records) > MAX_RECORDS:
                raise ProviderError("provider_too_large")
            info = (doc or {}).get("result_info") or {}
            if page >= int(info.get("total_pages") or 1) or not items:
                break
            page += 1
        settings_doc = get_json(c, f"{base}/zones/{zid}/settings", headers, budget, optional=True)
    return {"dns": records, "settings": (settings_doc or {}).get("result") if settings_doc else None}


def map_records(raw: list, zone: str) -> list[dict]:
    out = []
    for r in raw or []:
        rtype = str(r.get("type") or "").upper()
        name = relative(str(r.get("name") or "@"), zone)
        ttl = clamp_ttl(r.get("ttl"))
        proxied = bool(r.get("proxied")) and rtype in ("A", "AAAA", "CNAME")
        prio = r.get("priority")
        content = str(r.get("content") or "")
        data = r.get("data") if isinstance(r.get("data"), dict) else {}
        if rtype == "SOA" or (rtype == "NS" and name == "@"):
            out.append({"name": name, "type": rtype, "content": content, "ttl": ttl, "proxied": False, "priority": None,
                        "status": "unsupported", "reason": "به‌صورت خودکار مدیریت می‌شود"})
            continue
        if rtype == "SRV" and data:
            content = f"{int(data.get('weight') or 0)} {int(data.get('port') or 0)} {data.get('target')}"
            prio = data.get("priority")
        elif rtype == "CAA" and data:
            content = f'{int(data.get("flags") or 0)} {data.get("tag")} "{data.get("value")}"'
        if rtype in ("CNAME", "NS", "MX"):
            content = content.rstrip(".")
        out.append({"name": name, "type": rtype, "content": content, "ttl": ttl, "proxied": proxied,
                    "priority": int(prio) if isinstance(prio, int) else None})
    return out


def map_settings(items) -> dict:
    if not isinstance(items, list):
        note = ["تنظیمات Cloudflare خوانده نشد (توکن دسترسی خواندن تنظیمات ندارد)"]
        return {"cache": {"status": "none", "fields": {}, "notes": note},
                "ssl": {"status": "none", "fields": {}, "notes": note},
                "ddos": {"status": "none", "fields": {}, "notes": note}}
    s = {str(i.get("id")): i.get("value") for i in items if isinstance(i, dict)}
    cache, ssl, ddos = {}, {}, {}
    if "browser_cache_ttl" in s and isinstance(s["browser_cache_ttl"], int):
        cache["browser_ttl"] = max(0, min(int(s["browser_cache_ttl"]), 31536000))
    if s.get("development_mode") in ("on", "off"):
        cache["dev_mode"] = s["development_mode"] == "on"
    if s.get("always_use_https") in ("on", "off"):
        ssl["force_https"] = s["always_use_https"] == "on"
    if s.get("security_level") == "under_attack":
        ddos["mode"] = "js"

    def part(fields):
        return {"status": "maps" if fields else "none", "fields": fields, "notes": []}

    return {"cache": part(cache), "ssl": part(ssl), "ddos": part(ddos)}


def map_all(raw: dict, zone: str) -> tuple[list[dict], dict, list[dict]]:
    return map_records(raw.get("dns") or [], zone), map_settings(raw.get("settings")), list(UNMAPPED)
