"""Who owns a domain, and the parent/child zone rule between tenants (security review C1).

All zones live on the same nameservers, and PowerDNS answers a name from the MOST SPECIFIC zone it
hosts. A site `shop.victim.com` of another tenant would therefore override every record of
`shop.victim.com` (and below) of the site `victim.com` once victim.com is delegated to us — and pass
the NS check and DNS-01 issuance with it. So:

* a site may not be created when an existing site is its parent or its child (any depth) unless
  both have the SAME owner;
* a public suffix (``com``, ``co.ir``, ``ac.ir`` …, see psl.py) is never a site.

The owner of a site is the WHMCS client it belongs to: ``client_id`` (sent by WHMCS for a normal
service) or else ``reseller_client_id`` (a reseller's sub-site belongs to the reseller). A site with
neither (created by an admin or by an older WHMCS module) has NO owner and never matches anyone, so
it can neither nest nor be nested; an operator can set ``client_id`` on it
(PATCH /api/v1/sites/{domain}/owner) to allow it.

Operator sites (SPEC §19.1, ``owner_kind == "operator"``: the platform's own domains, no WHMCS
client) all share ONE owner identity, :data:`OPERATOR`, which is distinct from every client id, so
the operator may nest its own domains but a customer can never add a parent/child of an operator
domain and vice versa. Owners are therefore comparable values: an ``int`` (WHMCS client id),
:data:`OPERATOR`, or ``None`` (nobody — never equal to anything, not even another ``None``).
"""

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from . import psl
from .models import Site


OPERATOR = "operator"  # the one owner identity of every operator site (SPEC §19.1)

Owner = int | str | None


def owner_of(client_id: int | None, reseller_client_id: int | None, operator: bool = False) -> Owner:
    if operator:
        return OPERATOR
    return client_id or reseller_client_id or None


def site_owner(site: Site) -> Owner:
    return owner_of(getattr(site, "client_id", None), getattr(site, "reseller_client_id", None),
                    getattr(site, "owner_kind", None) == "operator")


def ancestors(domain: str) -> list[str]:
    """Proper parent names of `domain` that could be sites (2+ labels), nearest first."""
    labels = domain.split(".")
    return [".".join(labels[i:]) for i in range(1, len(labels) - 1)]


def related_sites(db: Session, domain: str, exclude_id: int | None = None) -> list[Site]:
    """Existing sites that are a parent or a child (any depth) of `domain`."""
    cond = [Site.domain.like(f"%.{domain}")]
    parents = ancestors(domain)
    if parents:
        cond.append(Site.domain.in_(parents))
    stmt = select(Site).where(or_(*cond))
    if exclude_id is not None:
        stmt = stmt.where(Site.id != exclude_id)
    # LIKE treats "_" as a wildcard; domains have no "_", but re-check the suffix exactly anyway
    return [s for s in db.scalars(stmt) if s.domain in parents or s.domain.endswith("." + domain)]


def same_owner(owner: Owner, site: Site) -> bool:
    return owner is not None and site_owner(site) == owner


def domain_problem(db: Session, domain: str, owner: Owner, exclude_id: int | None = None
                   ) -> tuple[str, str] | None:
    """Why `domain` may not become a site of `owner`: (code, Persian message) or None.
    code: public_suffix | exists | nested."""
    if psl.is_public_suffix(domain):
        return "public_suffix", "این دامنه پسوند عمومی (مثل com یا co.ir) است و نمی‌تواند سایت باشد"
    other = db.scalar(select(Site).where(Site.domain == domain))
    if other is not None and other.id != exclude_id:
        return "exists", "این دامنه قبلاً ثبت شده است"
    for s in related_sites(db, domain, exclude_id):
        if not same_owner(owner, s):
            kind = "زیردامنهٔ" if domain.endswith("." + s.domain) else "دامنهٔ والدِ"
            return "nested", (f"این دامنه {kind} سایت دیگری است که متعلق به حساب دیگری است؛ زیردامنه‌ها و دامنهٔ "
                              "والد فقط برای همان مالک قابل ثبت‌اند")
    return None


def foreign_parent(db: Session, site: Site) -> Site | None:
    """The nearest parent site of `site` with a different owner (a legacy pair created before the
    rule existed), or None."""
    parents = ancestors(site.domain)
    if not parents:
        return None
    owner = site_owner(site)
    rows = {s.domain: s for s in db.scalars(select(Site).where(Site.domain.in_(parents), Site.id != site.id))}
    for p in parents:  # nearest first
        s = rows.get(p)
        if s is not None and not same_owner(owner, s):
            return s
    return None


def nested_conflicts(db: Session) -> list[tuple[str, str]]:
    """Every (parent, child) site pair with different owners — legacy data the creation rule would
    refuse today (reported by the security audit job)."""
    sites = list(db.scalars(select(Site)))
    by_domain = {s.domain: s for s in sites}
    out = []
    for s in sites:
        for p in ancestors(s.domain):
            parent = by_domain.get(p)
            if parent is not None and not same_owner(site_owner(s), parent):
                out.append((parent.domain, s.domain))
    return sorted(out)


def owner_group(db: Session, site: Site) -> tuple[list[Site], list[Site]]:
    """For a transfer (SPEC §19.2): (sites of the same owner linked to `site` through parent/child
    relations, any number of hops — they must move together; other-owner sites related to any of
    them). `site` itself is in neither list. A site without an owner has no group."""
    owner = site_owner(site)
    group: dict[int, Site] = {site.id: site}
    foreign: dict[int, Site] = {}
    queue = [site]
    while queue:
        cur = queue.pop()
        for other in related_sites(db, cur.domain, exclude_id=cur.id):
            if other.id in group or other.id in foreign:
                continue
            if same_owner(owner, other):
                group[other.id] = other
                queue.append(other)
            else:
                foreign[other.id] = other
    group.pop(site.id)
    by_domain = lambda s: s.domain  # noqa: E731
    return sorted(group.values(), key=by_domain), sorted(foreign.values(), key=by_domain)
