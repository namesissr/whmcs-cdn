import json
import logging

import dns.resolver

from .config import settings
from .models import Site, utcnow

log = logging.getLogger("pcdn.ns")


def lookup_ns(domain: str) -> list[str]:
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = settings.ns_resolvers
    r.lifetime = 8
    try:
        ans = r.resolve(domain, "NS")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        return []
    return sorted({str(x.target).lower().rstrip(".") for x in ans})


def is_delegated(found: list[str]) -> bool:
    ours = set(settings.nameservers)
    return bool(found) and set(found) <= ours


def check_and_update(site: Site) -> tuple[bool, list[str]]:
    """Check delegation; flips pending_ns -> active and queues SSL. Caller commits."""
    found = lookup_ns(site.domain)
    ok = is_delegated(found)
    site.ns_checked_at = utcnow()
    site.ns_found = json.dumps(found)
    if ok:
        if site.ns_verified_at is None:
            site.ns_verified_at = utcnow()
            log.info("%s delegated to us", site.domain)
        if site.status == "pending_ns":
            site.status = "active"
        if site.ssl_allowed and site.ssl_status in ("none", "failed") and not site.ssl_error:
            site.ssl_status = "pending"
    return ok, found
