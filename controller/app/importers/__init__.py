"""Provider importers (SPEC §23.6): ArvanCloud and Cloudflare.

Each module has a fetcher (`fetch(api_key, zone, client)` -> raw provider JSON, the key held only in
a local variable for the duration of the call) and pure mappers (`map_all(raw)` -> (records, sections,
unmapped)) so tests run on fixtures. Mapped records: {"name", "type", "content", "ttl", "proxied",
"priority"} (name relative to the zone, "@" for the apex). Sections: {section: {"status":
"maps"|"partial"|"none", "fields": {...partial section...}, "rules": [...] (list sections), "notes":
[str]}}. Unmapped: [{"what", "reason"}].
"""


class ProviderError(Exception):
    """detail: provider_auth (422) | provider_zone_not_found (404) | provider_unreachable (502) |
    provider_too_large (502). Never carries the key or a provider URL."""

    STATUS = {"provider_auth": 422, "provider_zone_not_found": 404, "provider_unreachable": 502,
              "provider_too_large": 502}

    def __init__(self, detail: str):
        super().__init__(detail)
        self.detail = detail
        self.status = self.STATUS.get(detail, 502)


def clamp_ttl(v) -> int:
    try:
        n = int(v)
    except (TypeError, ValueError):
        n = 300
    if n <= 1:  # "auto" in some providers
        n = 300
    return min(max(n, 60), 86400)


def relative(name: str, zone: str) -> str:
    name = (name or "@").strip().rstrip(".").lower()
    zone = zone.strip().rstrip(".").lower()
    if name in ("", "@", zone):
        return "@"
    if name.endswith("." + zone):
        return name[: -len(zone) - 1]
    return name


import time  # noqa: E402

import httpx  # noqa: E402

TOTAL_SECONDS = 60
MAX_BYTES = 5 * 1024 * 1024
MAX_RECORDS = 10000
# tests inject an httpx.MockTransport here
transport: httpx.BaseTransport | None = None


class Budget:
    """60 s / 5 MB for one preview (SPEC §23.6)."""

    def __init__(self, seconds: float = TOTAL_SECONDS, max_bytes: int = MAX_BYTES):
        self.deadline = time.monotonic() + seconds
        self.left = max_bytes

    def timeout(self) -> float:
        rest = self.deadline - time.monotonic()
        if rest <= 0:
            raise ProviderError("provider_unreachable")
        return min(rest, 20.0)


def client() -> httpx.Client:
    return httpx.Client(transport=transport, follow_redirects=False)


def get_json(c: httpx.Client, url: str, headers: dict, budget: Budget, params: dict | None = None,
             optional: bool = False, zone_check: bool = False):
    """GET JSON within the budget. 401/403 -> provider_auth; 404 -> None when optional, zone not found
    when zone_check, else unreachable; timeout / 5xx -> provider_unreachable. Never logs the URL."""
    try:
        r = c.get(url, headers=headers, params=params, timeout=budget.timeout())
    except httpx.HTTPError:
        raise ProviderError("provider_unreachable") from None
    if r.status_code in (401, 403):
        raise ProviderError("provider_auth")
    if r.status_code == 404:
        if optional:
            return None
        raise ProviderError("provider_zone_not_found" if zone_check else "provider_unreachable")
    if r.status_code >= 300:
        if optional and 400 <= r.status_code < 500:
            return None
        raise ProviderError("provider_unreachable")
    budget.left -= len(r.content)
    if budget.left < 0:
        raise ProviderError("provider_too_large")
    try:
        return r.json()
    except ValueError:
        raise ProviderError("provider_unreachable") from None
