"""Nameserver delegation check: a pending site goes active once its domain is delegated to us.

Three conditions (security review C1):

1. a recursive lookup (NS_RESOLVERS) of the domain's NS returns only our nameservers;
2. no parent site of a DIFFERENT owner exists (tenancy.py). Our nameservers host every site's
   zone and answer from the most specific one, so a child zone of a parent delegated to us passes
   (1) by itself — this is what kept a foreign `shop.victim.com` from being "verified";
3. (NS_CHECK_PARENT, default on) the delegation really comes from the domain's registered parent:
   walking down from the public suffix's own servers (non-recursive queries, following referrals)
   the referral for exactly this name must point to our nameservers. A referral that reaches our
   nameservers for a PARENT name first means the delegation would come from a zone we host; that
   is accepted only when that parent is a site of the same owner. When no parent server answers
   (outbound DNS blocked, timeouts) this step is skipped with a warning — (2) still applies.
"""

import json
import logging

import dns.exception
import dns.flags
import dns.message
import dns.query
import dns.rdatatype
import dns.resolver
from sqlalchemy import select
from sqlalchemy.orm import object_session

from . import psl, tenancy
from .config import settings
from .models import Site, utcnow

log = logging.getLogger("pcdn.ns")

MAX_REFERRALS = 8
QUERY_TIMEOUT = 3.0


def _resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = settings.ns_resolvers
    r.lifetime = 8
    return r


def lookup_ns(domain: str) -> list[str]:
    try:
        ans = _resolver().resolve(domain, "NS")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        return []
    return sorted({str(x.target).lower().rstrip(".") for x in ans})


def is_delegated(found: list[str]) -> bool:
    ours = set(settings.nameservers)
    return bool(found) and set(found) <= ours


def server_addresses(names: list[str], glue: dict[str, list[str]] | None = None, limit: int = 6) -> list[str]:
    """IPv4 addresses of name servers: glue first, else the recursive resolver. Monkeypatched in tests."""
    out: list[str] = []
    for n in names[:4]:
        ips = (glue or {}).get(n)
        if not ips:
            try:
                ips = [a.address for a in _resolver().resolve(n, "A")]
            except Exception:  # noqa: BLE001 - one unresolvable server name is not fatal
                ips = []
        out.extend(ip for ip in ips if ip not in out)
    return out[:limit]


def query(server: str, name: str) -> dns.message.Message:
    """One non-recursive NS query (UDP, TCP when truncated). Monkeypatched in tests."""
    q = dns.message.make_query(name, dns.rdatatype.NS)
    q.flags &= ~dns.flags.RD
    resp = dns.query.udp(q, server, timeout=QUERY_TIMEOUT)
    if resp.flags & dns.flags.TC:
        resp = dns.query.tcp(q, server, timeout=QUERY_TIMEOUT)
    return resp


def _ask(servers: list[str], name: str) -> dns.message.Message | None:
    for s in servers:
        try:
            return query(s, name)
        except Exception:  # noqa: BLE001 - timeout / network: try the next server
            continue
    return None


def _cut(resp: dns.message.Message, domain: str) -> tuple[str, list[str], dict[str, list[str]]] | None:
    """The deepest NS rrset in the answer/authority sections at or above `domain`, with glue."""
    best = None
    for rrset in list(resp.answer) + list(resp.authority):
        if rrset.rdtype != dns.rdatatype.NS:
            continue
        owner = rrset.name.to_text().lower().rstrip(".")
        if owner != domain and not domain.endswith("." + owner):
            continue
        if best is None or len(owner) > len(best[0]):
            best = (owner, sorted({str(r.target).lower().rstrip(".") for r in rrset}))
    if best is None:
        return None
    glue: dict[str, list[str]] = {}
    for rrset in resp.additional:
        if rrset.rdtype == dns.rdatatype.A:
            glue.setdefault(rrset.name.to_text().lower().rstrip("."), []).extend(r.address for r in rrset)
    return best[0], best[1], glue


def parent_delegation(domain: str) -> tuple[str, list[str]] | None:
    """Follow referrals from the public suffix's servers towards `domain`.

    Returns (owner, nameservers) of the delegation found: owner == domain when the parent delegates
    exactly this name; a parent name when the walk reached OUR nameservers for that parent first;
    (zone, []) when the zone holding the name does not delegate it. None = could not be checked.
    Monkeypatched in tests (conftest: None, i.e. "could not be checked")."""
    zone = psl.public_suffix(domain)
    if zone == domain:
        return None
    servers = server_addresses(lookup_ns(zone))
    for _ in range(MAX_REFERRALS):
        if not servers:
            return None
        resp = _ask(servers, domain)
        if resp is None:
            return None
        cut = _cut(resp, domain)
        if cut is None or cut[0] == zone:  # answered from `zone` itself: no delegation below it
            return zone, []
        owner, targets, glue = cut
        if owner == domain or is_delegated(targets):
            return owner, targets
        zone, servers = owner, server_addresses(targets, glue)
    return None


def check(site: Site) -> tuple[bool, list[str], str | None]:
    """(delegated, NS found, reason when not). Does not change the site.
    reason: nameservers | parent_site:<domain> | parent_delegation."""
    found = lookup_ns(site.domain)
    if not is_delegated(found):
        return False, found, "nameservers"
    db = object_session(site)
    if db is not None:
        parent = tenancy.foreign_parent(db, site)
        if parent is not None:
            return False, found, f"parent_site:{parent.domain}"
    if settings.ns_check_parent:
        try:
            result = parent_delegation(site.domain)
        except Exception:  # noqa: BLE001 - never fail the job on the walk itself
            log.exception("parent delegation check of %s failed", site.domain)
            result = None
        if result is None:
            log.warning("could not verify the parent delegation of %s (parent servers unreachable); "
                        "relying on the recursive answer and the parent-site rule", site.domain)
        else:
            owner, targets = result
            if not is_delegated(targets):
                return False, found, "parent_delegation"
            if owner != site.domain:
                # delegated through a zone we host (a parent site): only for that parent's own owner
                parent_site = db.scalar(select(Site).where(Site.domain == owner)) if db is not None else None
                if parent_site is None or not tenancy.same_owner(tenancy.site_owner(site), parent_site):
                    return False, found, f"parent_site:{owner}"
    return True, found, None


def check_and_update(site: Site) -> tuple[bool, list[str]]:
    """Check delegation; flips pending_ns -> active and queues SSL. Caller commits."""
    ok, found, _reason = check_and_update_reason(site)
    return ok, found


def check_and_update_reason(site: Site) -> tuple[bool, list[str], str | None]:
    ok, found, reason = check(site)
    site.ns_checked_at = utcnow()
    site.ns_found = json.dumps(found)
    if reason and reason != "nameservers":
        log.warning("%s: our nameservers answer but the delegation is refused (%s)", site.domain, reason)
    if ok:
        if site.ns_verified_at is None:
            site.ns_verified_at = utcnow()
            log.info("%s delegated to us", site.domain)
        if site.status == "pending_ns":
            site.status = "active"
        if site.ssl_allowed and site.ssl_status in ("none", "failed") and not site.ssl_error:
            site.ssl_status = "pending"
    return ok, found, reason
