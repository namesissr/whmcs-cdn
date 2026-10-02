"""v2 admin API: configuration sections, custom SSL, zone import/export, DNSSEC, analytics (SPEC §2–4)."""

import json
import logging
from collections import Counter
from datetime import timedelta

import dns.exception
import dns.rdatatype
import dns.zone
import pydantic
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import (dns_secondary, edge_functions, images, l4, logexport, origin_pull, pdns, sections, ssl, tunnel,
               waf_learning, webhooks)
from .audit import record_audit
from .auth import require_admin
from .config import settings
from .db import get_db
from .models import Incident, IncidentUpdate, Record, SecurityEvent, Site, UsageHourly, utcnow
from .routes_admin import RecordIn, _record_from, bad, get_site
from .services import lock_site, site_to_dict, sync_site_dns
from .validation import ValidationError, num
from .validation import obj as _obj

router = APIRouter(prefix="/api/v1", dependencies=[Depends(require_admin)])
# unauthenticated: the platform origin-pull CA certificate (SPEC §14.2)
public_router = APIRouter()
log = logging.getLogger("pcdn")


def _pydantic_422(e: pydantic.ValidationError):
    raise HTTPException(422, [{"loc": list(err["loc"]), "msg": err["msg"].removeprefix("Value error, ")}
                              for err in e.errors()])


def _audit(db: Session, request: Request, action: str, target: str | None = None,
           detail: dict | None = None) -> None:
    """Record an admin mutation on the v2 surface (SPEC §13.2)."""
    ip = request.client.host if request.client else None
    record_audit(db, actor="admin", actor_kind="admin", action=action, target=target,
                 detail=detail, ip=ip)


# ------------------------------------------------------------------ sections

@router.get("/sites/{domain}/config")
def read_config(domain: str, db: Session = Depends(get_db)):
    # every section; the function bodies only in GET .../config/functions (SPEC §16.9)
    return sections.config_view(sections.all_config(get_site(db, domain)))


# section handlers factored so the admin and customer APIs share identical validation/logic

def read_section_of(site: Site, section: str, response: Response | None = None) -> dict:
    if section not in sections.SECTIONS:
        raise HTTPException(404, "بخش نامعتبر است")
    value = sections.get_section(site, section)
    if section == "functions":  # + output-only code_bytes / sha256 per item (SPEC §16.9)
        value = sections.functions_view(value)
    # stored rules whose regex fails today's safety check (the edges do not run them): surfaced the
    # same way as the write warnings, so the body stays the stored section
    if response is not None:
        warnings = sections.regex_rule_warnings(site, section)
        if warnings:
            response.headers["X-Pcdn-Warnings"] = json.dumps(warnings)
    return value


def write_section_of(db: Session, site: Site, section: str, body: dict,
                     response: Response | None = None) -> dict:
    if section not in sections.SECTIONS:
        raise HTTPException(404, "بخش نامعتبر است")
    try:
        outbound = section in sections.PRELOCK_SECTIONS
        if outbound:
            # SSRF check of the outbound URLs / origin host names first: it resolves DNS and needs no
            # site state, so it must not run while the site row is locked
            parsed = sections.dump(sections.SECTIONS[section].model_validate(body))
            sections.check_targets(section, parsed)
        # every PUT rewrites the whole site.config document: validate and merge against the row as
        # locked now, never a copy loaded earlier, so concurrent writers cannot drop each other's
        # sections (lost update)
        site = lock_site(db, site)
        pools_in_use = {r.pool for r in site.records if r.pool}
        value = sections.validate_section(site, section, body, pools_in_use, vet=not outbound)
    except pydantic.ValidationError as e:
        _pydantic_422(e)
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except ValidationError as e:
        bad(e)
    new_secrets = None
    stale_tsig = None
    if section == "logs":  # write-only secret_key: stored encrypted outside the section (SPEC §14.3.2)
        value = logexport.apply_write(site, value)
    elif section == "webhooks":  # ids + signing secrets assigned by the controller (SPEC §14.3.3)
        value, new_secrets = webhooks.apply_write(site, value)
    elif section == "image":  # write-only transform_secret (SPEC §16.6)
        value = images.apply_write(site, value)
    elif section == "dns_secondary":  # write-only TSIG secret, key name unique per site (SPEC §16.7)
        try:
            value, stale_tsig = dns_secondary.apply_write(db, site, value)
        except dns_secondary.TsigConflict as e:
            db.rollback()
            raise HTTPException(409, str(e))
    elif section == "l4":  # edge ports allocated / checked across the edge group (SPEC §16.4)
        try:
            value = l4.apply_write(db, site, value)
        except l4.PortConflict as e:
            db.rollback()
            raise HTTPException(409, str(e))
        except IntegrityError:
            db.rollback()
            raise HTTPException(409, "همین حالا پورتی که انتخاب شد به سرویس دیگری داده شد؛ دوباره تلاش کنید")
    sections.store_section(site, section, value)
    try:
        db.commit()
    except IntegrityError:  # l4: a concurrent writer took the same port (unique group + port)
        db.rollback()
        raise HTTPException(409, "همین حالا پورتی که انتخاب شد به سرویس دیگری داده شد؛ دوباره تلاش کنید")
    dns_error = None
    if section in ("l4", "dns_secondary"):
        # the l4-<id> names / the zone kind and transfer settings live in PowerDNS
        if section == "dns_secondary" and stale_tsig and settings.pdns_enabled:
            try:
                pdns.client().delete_tsigkey(stale_tsig)
            except Exception as e:  # noqa: BLE001 - a stale key is harmless; reported only
                log.warning("could not remove TSIG key %s: %s", stale_tsig, e)
        dns_error = sync_site_dns(db, site, force_secondary=section == "dns_secondary")
    if section in ("logs", "webhooks", "image", "dns_secondary", "l4"):
        # the stored view: secrets never returned, only secret_key_set / secret_set; the secrets of
        # newly created webhooks are shown this once
        value = sections.get_section(site, section)
        if new_secrets is not None:
            value["new_secrets"] = new_secrets
    if section == "functions":
        value = sections.functions_view(value)
    if section == "ssl" and value["origin_client_auth"] == "platform":
        # create the platform origin-pull CA now (once), so the CA the customer downloads next is the
        # one the edges' client certificate chains to; a failure here is retried on the next edge poll
        try:
            origin_pull.ensure()
        except Exception:  # noqa: BLE001 - never fail a saved section on this
            log.exception("could not create the platform origin-pull certificate")
    # F1/F34: non-blocking warnings (e.g. an xhttp/h2 tunnel path on a multi-origin pool, or
    # force_https that would 301 tunnel clients on port 80) go in a header so the saved section body
    # is unchanged. json.dumps is ASCII (escapes Persian) so it is a valid latin-1 header value.
    if response is not None:
        warnings = sections.section_warnings(site, section, value)
        if warnings:
            response.headers["X-Pcdn-Warnings"] = json.dumps(warnings)
        if dns_error:  # the section is saved; the zone is re-synced by the scheduler (DNS dirty)
            response.headers["X-Pcdn-Dns-Error"] = json.dumps(dns_error[:500])
    return value


@router.get("/sites/{domain}/config/{section}")
def read_section(domain: str, section: str, response: Response, db: Session = Depends(get_db)):
    return read_section_of(get_site(db, domain), section, response)


@router.put("/sites/{domain}/config/{section}")
def write_section(domain: str, section: str, body: dict, response: Response, request: Request,
                  db: Session = Depends(get_db)):
    site = get_site(db, domain)
    result = write_section_of(db, site, section, body, response)
    _audit(db, request, "config.update", site.domain, config_audit(section, result))
    return result


def config_audit(section: str, value: dict) -> dict:
    """Audit detail of a section write: the section name; for functions also the ids, count and code
    sizes (never the code, SPEC §16.9)."""
    if section == "functions":
        return sections.functions_audit(value)
    return {"section": section}


# ------------------------------------------------------------------ WAF learning mode (SPEC §17.2)

class LearningApplyIn(BaseModel):
    ids: list[str] = Field(min_length=1, max_length=200)


def waf_learning_of(db: Session, site: Site) -> dict:
    return waf_learning.report(db, site)


def waf_learning_apply_of(db: Session, site: Site, ids: list[str]) -> dict:
    """Apply the chosen proposals (normal section validation, one commit); already applied ones
    are `unchanged` (idempotent). Unknown ids -> 422 and nothing is applied."""
    try:
        return waf_learning.apply(db, site, ids)
    except waf_learning.UnknownProposals as e:
        db.rollback()
        raise HTTPException(422, "پیشنهاد نامعتبر یا منقضی است: " + ", ".join(e.ids[:20]))
    except pydantic.ValidationError as e:
        db.rollback()
        _pydantic_422(e)
    except PermissionError as e:
        db.rollback()
        raise HTTPException(403, str(e))
    except ValidationError as e:
        db.rollback()
        bad(e)


def waf_learning_audit(result: dict) -> dict:
    return {"section": ",".join(result["changed"]), "items": result["applied"],
            "count": len(result["applied"])}


@router.get("/sites/{domain}/waf/learning")
def waf_learning_report(domain: str, db: Session = Depends(get_db)):
    """Learning state and proposals (SPEC §17.2). Nothing is ever applied automatically."""
    return waf_learning_of(db, get_site(db, domain))


@router.post("/sites/{domain}/waf/learning/apply")
def waf_learning_apply(domain: str, body: LearningApplyIn, request: Request, db: Session = Depends(get_db)):
    site = get_site(db, domain)
    result = waf_learning_apply_of(db, site, body.ids)
    if result["applied"]:
        _audit(db, request, "waf.learning.apply", site.domain, waf_learning_audit(result))
    return result


# ------------------------------------------------------------------ images v2 (SPEC §16.6)

def image_secret_create_of(db: Session, site: Site) -> dict:
    """Generate (or replace) the site's image transform secret; returned this once."""
    if not sections.features_of(site)["image_optimization"]:
        raise HTTPException(403, "بهینه‌سازی تصویر در پلن شما فعال نیست")
    site = lock_site(db, site)  # read-modify-write of site.integration_secrets
    secret = images.rotate(site)
    db.commit()
    return {"transform_secret": secret, "transform_secret_set": True,
            "algorithm": "hex(HMAC-SHA256(transform_secret, canonical))",
            "signed_params": list(images.SIGNED_PARAMS)}


def image_secret_delete_of(db: Session, site: Site) -> dict:
    site = lock_site(db, site)
    if not images.remove(site):
        raise HTTPException(404, "کلید امضای تبدیل تصویر ثبت نشده است")
    db.commit()
    return {"transform_secret_set": False}


@router.post("/sites/{domain}/image/transform-secret")
def image_secret_create(domain: str, request: Request, db: Session = Depends(get_db)):
    site = get_site(db, domain)
    result = image_secret_create_of(db, site)
    # the secret itself is never written to the audit log
    _audit(db, request, "image.transform_secret", site.domain, {"mode": "rotate"})
    return result


@router.delete("/sites/{domain}/image/transform-secret")
def image_secret_delete(domain: str, request: Request, db: Session = Depends(get_db)):
    site = get_site(db, domain)
    result = image_secret_delete_of(db, site)
    _audit(db, request, "image.transform_secret", site.domain, {"mode": "remove"})
    return result


# ------------------------------------------------------------------ edge functions (SPEC §16.9)

def functions_stats_of(db: Session, site: Site, hours: int) -> dict:
    if not 1 <= hours <= edge_functions.MAX_HOURS:
        bad(ValidationError(f"hours باید بین 1 و {edge_functions.MAX_HOURS} باشد"))
    return edge_functions.stats(db, site, hours)


@router.get("/sites/{domain}/functions/stats")
def functions_stats(domain: str, hours: int = 24, db: Session = Depends(get_db)):
    """Invocations, CPU ms, errors and timeouts of the site's edge functions, last `hours` (1..744)."""
    return functions_stats_of(db, get_site(db, domain), hours)


# ------------------------------------------------------------------ tunnel mode (SPEC §7.5)

@router.get("/sites/{domain}/tunnel/stats")
def tunnel_stats(domain: str, hours: int = 24, db: Session = Depends(get_db)):
    site = get_site(db, domain)
    return tunnel.stats(db, site, max(1, min(hours, 24 * 31)))


@router.post("/sites/{domain}/tunnel/check")
def tunnel_check(domain: str, db: Session = Depends(get_db)):
    """Can the controller reach each tunnel path's origin (TCP, plus TLS when used)?"""
    paths = tunnel.targets(get_site(db, domain))
    db.rollback()  # do not hold a transaction open while connecting
    return {"results": tunnel.check(paths)}


# ------------------------------------------------------------------ custom SSL

class CustomCert(BaseModel):
    cert: str = Field(max_length=65536)
    key: str = Field(max_length=16384)


@router.put("/sites/{domain}/ssl/custom")
def upload_cert(domain: str, body: CustomCert, request: Request, db: Session = Depends(get_db)):
    site = get_site(db, domain)
    if not sections.features_of(site)["custom_ssl"]:
        raise HTTPException(403, "گواهی اختصاصی در پلن شما فعال نیست")
    try:
        info = ssl.validate_custom(site.domain, body.cert.strip() + "\n", body.key.strip() + "\n")
    except ssl.SslError as e:
        bad(e)
    site.ssl_cert, site.ssl_key = body.cert.strip() + "\n", body.key.strip() + "\n"
    site.ssl_expires_at = info["expires_at"]
    site.ssl_status, site.ssl_source, site.ssl_error = "active", "custom", None
    db.commit()
    # NB: the certificate and (especially) the private key are never written to the audit log
    _audit(db, request, "ssl.custom.upload", site.domain, {"ssl_source": "custom"})
    return site_to_dict(db, site)["ssl"]


@router.delete("/sites/{domain}/ssl/custom")
def remove_cert(domain: str, request: Request, db: Session = Depends(get_db)):
    site = get_site(db, domain)
    if site.ssl_source != "custom":
        raise HTTPException(404, "گواهی اختصاصی ثبت نشده است")
    site.ssl_cert = site.ssl_key = site.ssl_expires_at = None
    site.ssl_source, site.ssl_error = None, None
    site.ssl_status = "pending" if site.ssl_allowed and site.ns_verified_at else "none"
    db.commit()
    _audit(db, request, "ssl.custom.remove", site.domain)
    return site_to_dict(db, site)["ssl"]


# ------------------------------------------------------------------ authenticated origin pulls (SPEC §14.2)

@public_router.get("/origin-pull-ca.pem")
def origin_pull_ca():
    """The platform CA customers configure their origin to trust (client certificates the edges
    present with ssl.origin_client_auth = platform chain to it). Public, CA certificate only."""
    return Response(origin_pull.ca_cert_pem(), media_type="application/x-pem-file",
                    headers={"Content-Disposition": 'attachment; filename="pcdn-origin-pull-ca.pem"',
                             "Cache-Control": "public, max-age=3600"})


@router.get("/sites/{domain}/ssl/origin-client")
def origin_client_status(domain: str, db: Session = Depends(get_db)):
    return origin_pull.site_info(get_site(db, domain))


@router.put("/sites/{domain}/ssl/origin-client")
def upload_origin_client(domain: str, body: CustomCert, request: Request, db: Session = Depends(get_db)):
    """Upload the client certificate + key for ssl.origin_client_auth = custom (encrypted at rest)."""
    site = get_site(db, domain)
    cert, key = body.cert.strip() + "\n", body.key.strip() + "\n"
    try:
        info = origin_pull.validate_custom(cert, key)
    except origin_pull.OriginClientError as e:
        bad(e)
    site.origin_client_cert, site.origin_client_key = cert, key
    site.origin_client_expires_at = info["expires_at"]
    db.commit()
    # NB: the certificate and the private key are never written to the audit log
    _audit(db, request, "ssl.origin_client.upload", site.domain)
    return origin_pull.site_info(site)


@router.delete("/sites/{domain}/ssl/origin-client")
def remove_origin_client(domain: str, request: Request, db: Session = Depends(get_db)):
    """Forget the custom origin client certificate; a site still set to custom is switched to off."""
    site = lock_site(db, get_site(db, domain))  # read-modify-write of site.config below
    if not site.origin_client_cert and not site.origin_client_key_stored:
        raise HTTPException(404, "گواهی کلاینت مبدأ ثبت نشده است")
    site.origin_client_cert = site.origin_client_key_stored = site.origin_client_expires_at = None
    ssl_cfg = sections.get_section(site, "ssl")
    if ssl_cfg["origin_client_auth"] == "custom":
        sections.store_section(site, "ssl", dict(ssl_cfg, origin_client_auth="off"))
    db.commit()
    _audit(db, request, "ssl.origin_client.remove", site.domain)
    return origin_pull.site_info(site)


# ------------------------------------------------------------------ redirects CSV import (SPEC §14.2)

async def csv_body(request: Request) -> dict:
    """The CSV text of an import: a JSON body {"csv": "...", "mode"?: "..."} or the raw text/csv body."""
    raw = await request.body()
    if len(raw) > sections.CSV_MAX_BYTES + 65536:
        raise HTTPException(413, "فایل CSV بیش از حد بزرگ است (حداکثر ۲ مگابایت)")
    if "json" in request.headers.get("content-type", "").lower():
        try:
            data = json.loads(raw or b"{}")
        except ValueError:
            raise HTTPException(422, "بدنه JSON نامعتبر است") from None
        if not isinstance(data, dict) or not isinstance(data.get("csv"), str):
            raise HTTPException(422, "فیلد csv (متن فایل CSV) لازم است")
        mode = data.get("mode")
        return {"csv": data["csv"], "mode": mode if isinstance(mode, str) else None}
    try:
        return {"csv": raw.decode("utf-8-sig"), "mode": None}
    except UnicodeDecodeError:
        raise HTTPException(422, "فایل CSV باید با کدگذاری UTF-8 ذخیره شده باشد") from None


def import_redirects_of(db: Session, site: Site, text: str, mode: str,
                        response: Response | None = None) -> dict:
    """Validate every row first; on any error nothing is saved (422 with per-row errors). replace
    swaps the whole list, append adds after the existing rules. Plan limit -> 403."""
    if mode not in ("replace", "append"):
        bad(ValidationError("mode باید replace یا append باشد"))
    site = lock_site(db, site)  # append merges with the rules as stored now (write_section_of keeps it)
    existing = [] if mode == "replace" else sections.get_section(site, "redirects")["rules"]
    rules, errors = sections.parse_redirects_csv(text, existing)
    if errors:
        raise HTTPException(422, errors)
    if not rules:
        bad(ValidationError("هیچ ردیف ریدایرکتی در فایل CSV پیدا نشد"))
    value = write_section_of(db, site, "redirects", {"rules": existing + rules}, response)
    return {"imported": len(rules), "total": len(value["rules"]), "mode": mode}


@router.post("/sites/{domain}/redirects/import")
def import_redirects(domain: str, request: Request, response: Response, mode: str | None = None,
                     body: dict = Depends(csv_body), db: Session = Depends(get_db)):
    site = get_site(db, domain)
    mode = body["mode"] or mode or "append"
    result = import_redirects_of(db, site, body["csv"], mode, response)
    _audit(db, request, "redirects.import", site.domain, {"count": result["imported"], "mode": mode})
    return result


# ------------------------------------------------------------------ zone import / export

class ZoneImport(BaseModel):
    zone: str = Field(max_length=1_000_000)
    replace: bool = False


def _rdata_to_record(rtype: str, rd) -> tuple[str, int | None]:
    if rtype in ("A", "AAAA"):
        return rd.address, None
    if rtype in ("CNAME", "NS"):
        return rd.target.to_text(omit_final_dot=True), None
    if rtype == "MX":
        return rd.exchange.to_text(omit_final_dot=True), rd.preference
    if rtype == "SRV":
        return f"{rd.weight} {rd.port} {rd.target.to_text(omit_final_dot=True)}", rd.priority
    if rtype == "TXT":
        return b"".join(rd.strings).decode("utf-8", "replace"), None
    if rtype == "CAA":
        return f'{rd.flags} {rd.tag.decode()} "{rd.value.decode()}"', None
    raise ValidationError("نوع رکورد پشتیبانی نمی‌شود")


@router.post("/sites/{domain}/records/import")
def import_zone(domain: str, body: ZoneImport, db: Session = Depends(get_db)):
    site = get_site(db, domain)
    try:
        # relativize=False keeps in-zone targets (e.g. "sip" in SRV) fully qualified
        zone = dns.zone.from_text(body.zone, origin=site.domain + ".", relativize=False, check_origin=False)
    except (dns.exception.DNSException, ValueError) as e:
        bad(ValidationError(f"فایل زون قابل خواندن نیست: {e}"))
    if body.replace:
        site.records.clear()
    imported, skipped = 0, []
    for name, node in zone.nodes.items():
        rel = name.relativize(zone.origin).to_text()
        rel = "@" if rel in ("@", "") else rel
        for rdataset in node.rdatasets:
            rtype = dns.rdatatype.to_text(rdataset.rdtype)
            for rd in rdataset:
                line = f"{rel} {rdataset.ttl} {rtype} {rd.to_text()}"
                if rtype == "SOA" or (rtype == "NS" and rel == "@"):
                    skipped.append({"line": line, "reason": "به‌صورت خودکار مدیریت می‌شود"})
                    continue
                if len(site.records) >= site.max_records:
                    skipped.append({"line": line, "reason": "سقف تعداد رکوردها"})
                    continue
                try:
                    content, prio = _rdata_to_record(rtype, rd)
                    rec_in = RecordIn(name=rel, type=rtype, content=content, priority=prio,
                                      ttl=min(max(rdataset.ttl, 60), 86400))
                    data = _record_from(site, rec_in)
                except (ValidationError, PermissionError, pydantic.ValidationError) as e:
                    skipped.append({"line": line, "reason": str(e)[:200]})
                    continue
                if any(r.name == data["name"] and r.type == data["type"] and r.content == data["content"]
                       for r in site.records):
                    skipped.append({"line": line, "reason": "تکراری"})
                    continue
                site.records.append(Record(**data))
                imported += 1
    db.commit()
    return {"imported": imported, "skipped": skipped, "dns_error": sync_site_dns(db, site)}


@router.get("/sites/{domain}/records/export")
def export_zone(domain: str, db: Session = Depends(get_db)):
    site = get_site(db, domain)
    lines = [f"$ORIGIN {site.domain}.", f"; exported {utcnow().isoformat()}Z"]
    for r in site.records:
        if r.type in ("CNAME", "NS", "ALIAS", "MX"):
            content = f"{r.content}."
        elif r.type == "SRV":
            w, p, t = r.content.split()
            content = f"{w} {p} {t}."
        elif r.type == "TXT":
            content = " ".join(f'"{r.content[i:i + 255]}"' for i in range(0, max(len(r.content), 1), 255))
        else:
            content = r.content
        prio = f"{r.priority} " if r.priority is not None else ""
        note = "  ; cdn-proxied" if r.proxied else ""
        lines.append(f"{r.name}\t{r.ttl}\tIN\t{r.type}\t{prio}{content}{note}")
    return {"zone": "\n".join(lines) + "\n"}


# ------------------------------------------------------------------ DNSSEC

class DnssecIn(BaseModel):
    enabled: bool


@router.get("/sites/{domain}/dnssec")
def dnssec_status(domain: str, db: Session = Depends(get_db)):
    site = get_site(db, domain)
    if not site.dnssec_enabled or not settings.pdns_enabled:
        return {"enabled": site.dnssec_enabled, "ds": [], "dnskey": None}
    try:
        return pdns.client().dnssec_info(site.domain)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(502, f"خطای DNS: {e}")


@router.post("/sites/{domain}/dnssec")
def dnssec_toggle(domain: str, body: DnssecIn, request: Request, db: Session = Depends(get_db)):
    site = get_site(db, domain)
    if body.enabled and not sections.features_of(site)["dnssec"]:
        raise HTTPException(403, "DNSSEC در پلن شما فعال نیست")
    if settings.pdns_enabled:
        try:
            err = sync_site_dns(db, site)  # make sure the zone exists everywhere first
            if err:
                raise RuntimeError(err)
            info = pdns.client().enable_dnssec(site.domain) if body.enabled else None
            if not body.enabled:
                pdns.client().disable_dnssec(site.domain)
        except Exception as e:  # noqa: BLE001
            raise HTTPException(502, f"خطای DNS: {e}")
    else:
        info = None
    site.dnssec_enabled = body.enabled
    db.commit()
    _audit(db, request, "dnssec", site.domain, {"dnssec": body.enabled})
    return info or {"enabled": body.enabled, "ds": [], "dnskey": None}


# ------------------------------------------------------------------ analytics

PERIODS = {"24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30)}
# security sources always present (zero-filled) in analytics totals; `bots` = bot management
# (SPEC §14.2). Any other source an edge reports is still summed in.
SECURITY_SOURCES = ("waf", "firewall", "ratelimit", "challenge", "ddos", "hotlink", "bots")


def _loads(s: str) -> dict:
    try:
        v = json.loads(s or "{}")
    except ValueError:
        return {}
    return v if isinstance(v, dict) else {}


def site_analytics(db: Session, site: Site, period: str) -> dict:
    """Per-site analytics (SPEC §4), shared by the admin and customer APIs."""
    if period not in PERIODS:
        bad(ValidationError("period باید 24h، 7d یا 30d باشد"))
    now = utcnow().replace(minute=0, second=0, microsecond=0)
    since = now - PERIODS[period] + timedelta(hours=1)
    hourly = period == "24h"
    rows = db.scalars(select(UsageHourly).where(UsageHourly.site_id == site.id, UsageHourly.hour >= since))

    totals = {"requests": 0, "bytes": 0, "cache_hits": 0,
              "status": {k: 0 for k in ("2xx", "3xx", "4xx", "5xx")},
              "security": {k: 0 for k in SECURITY_SOURCES},
              # SPEC §16.5 / §16.4: video bytes (part of `bytes`) and TCP/UDP proxy traffic
              "video": {"bytes": 0, "requests": 0, "cache_hits": 0},
              "l4": {"bytes_in": 0, "bytes_out": 0, "sessions": 0, "apps": {}}}
    buckets: dict[str, dict] = {}
    countries, paths, codes = Counter(), Counter(), Counter()
    for row in rows:
        key = row.hour.strftime("%Y-%m-%dT%H:00:00Z") if hourly else row.hour.strftime("%Y-%m-%dT00:00:00Z")
        b = buckets.setdefault(key, {"t": key, "requests": 0, "bytes": 0, "cache_hits": 0})
        b["requests"] += row.requests
        b["bytes"] += row.bytes
        b["cache_hits"] += row.cache_hits
        totals["requests"] += row.requests
        totals["bytes"] += row.bytes
        totals["cache_hits"] += row.cache_hits
        d = _loads(row.details)
        # L5: details come from the edges; a malformed value counts as 0 instead of a 500
        for k, v in _obj(d.get("status")).items():
            totals["status"][k] = totals["status"].get(k, 0) + num(v)
        for k, v in _obj(d.get("security")).items():
            totals["security"][k] = totals["security"].get(k, 0) + num(v)
        countries.update({str(k): num(v) for k, v in _obj(d.get("countries")).items()})
        paths.update({str(k): num(v) for k, v in _obj(d.get("paths")).items()})
        codes.update({str(k): num(v) for k, v in _obj(d.get("codes")).items()})
        v = _obj(d.get("video"))
        totals["video"]["bytes"] += num(v.get("bytes"))
        totals["video"]["requests"] += num(v.get("requests"))
        totals["video"]["cache_hits"] += num(v.get("cache_hits"))
        for app_id, c in _obj(d.get("l4")).items():
            c = _obj(c)
            a = totals["l4"]["apps"].setdefault(str(app_id), {"bytes_in": 0, "bytes_out": 0, "sessions": 0})
            for k in ("bytes_in", "bytes_out", "sessions"):
                a[k] += num(c.get(k))
                totals["l4"][k] += num(c.get(k))

    # zero-filled series so charts have a point per hour/day
    series, step = [], timedelta(hours=1) if hourly else timedelta(days=1)
    t = since if hourly else since.replace(hour=0)
    while t <= now:
        key = t.strftime("%Y-%m-%dT%H:00:00Z") if hourly else t.strftime("%Y-%m-%dT00:00:00Z")
        series.append(buckets.get(key, {"t": key, "requests": 0, "bytes": 0, "cache_hits": 0}))
        t += step
    return {
        "period": period,
        "totals": totals,
        "series": series,
        "countries": [{"code": k, "requests": v} for k, v in countries.most_common(20)],
        "paths": [{"path": k, "requests": v} for k, v in paths.most_common(20)],
        "status_codes": [{"code": int(k), "requests": v} for k, v in codes.most_common(10) if k.isdigit()],
    }


@router.get("/sites/{domain}/analytics")
def analytics(domain: str, period: str = "24h", db: Session = Depends(get_db)):
    return site_analytics(db, get_site(db, domain), period)


@router.get("/analytics")
def platform_analytics(period: str = "24h", db: Session = Depends(get_db)):
    """Same shape as the per-site analytics, aggregated across ALL sites (SPEC §9.1)."""
    if period not in PERIODS:
        bad(ValidationError("period باید 24h، 7d یا 30d باشد"))
    now = utcnow().replace(minute=0, second=0, microsecond=0)
    since = now - PERIODS[period] + timedelta(hours=1)
    hourly = period == "24h"
    rows = db.scalars(select(UsageHourly).where(UsageHourly.hour >= since))

    totals = {"requests": 0, "bytes": 0, "cache_hits": 0,
              "status": {k: 0 for k in ("2xx", "3xx", "4xx", "5xx")},
              "security": {k: 0 for k in SECURITY_SOURCES}}
    buckets: dict[str, dict] = {}
    sec_buckets: Counter = Counter()
    countries = Counter()
    site_requests, site_bytes = Counter(), Counter()
    for row in rows:  # one bounded pass over the window
        key = row.hour.strftime("%Y-%m-%dT%H:00:00Z") if hourly else row.hour.strftime("%Y-%m-%dT00:00:00Z")
        b = buckets.setdefault(key, {"t": key, "requests": 0, "bytes": 0, "cache_hits": 0})
        b["requests"] += row.requests
        b["bytes"] += row.bytes
        b["cache_hits"] += row.cache_hits
        totals["requests"] += row.requests
        totals["bytes"] += row.bytes
        totals["cache_hits"] += row.cache_hits
        site_requests[row.site_id] += row.requests
        site_bytes[row.site_id] += row.bytes
        d = _loads(row.details)
        for k, v in _obj(d.get("status")).items():
            totals["status"][k] = totals["status"].get(k, 0) + num(v)
        for k, v in _obj(d.get("security")).items():
            totals["security"][k] = totals["security"].get(k, 0) + num(v)
            sec_buckets[key] += num(v)
        countries.update({str(k): num(v) for k, v in _obj(d.get("countries")).items()})

    # zero-filled series so charts have a point per hour/day
    series, security_series = [], []
    step = timedelta(hours=1) if hourly else timedelta(days=1)
    t = since if hourly else since.replace(hour=0)
    while t <= now:
        key = t.strftime("%Y-%m-%dT%H:00:00Z") if hourly else t.strftime("%Y-%m-%dT00:00:00Z")
        series.append(buckets.get(key, {"t": key, "requests": 0, "bytes": 0, "cache_hits": 0}))
        security_series.append({"t": key, "events": sec_buckets.get(key, 0)})
        t += step
    domains = dict(db.execute(select(Site.id, Site.domain)).all())
    return {
        "period": period,
        "totals": totals,
        "series": series,
        "countries": [{"code": k, "requests": v} for k, v in countries.most_common(20)],
        "sites": [{"domain": domains.get(sid, "?"), "requests": r, "bytes": site_bytes[sid]}
                  for sid, r in site_requests.most_common(20)],
        "security_series": security_series,
    }


def site_events(db: Session, site: Site, limit: int) -> list[dict]:
    """Per-site security events (SPEC §4), shared by the admin and customer APIs."""
    limit = max(1, min(limit, 1000))
    rows = db.scalars(select(SecurityEvent).where(SecurityEvent.site_id == site.id)
                      .order_by(SecurityEvent.ts.desc(), SecurityEvent.id.desc()).limit(limit))
    return [{"t": e.ts.isoformat() + "Z", "ip": e.ip, "country": e.country, "method": e.method, "host": e.host,
             "path": e.path, "action": e.action, "source": e.source, "rule": e.rule, "user_agent": e.user_agent}
            for e in rows]


@router.get("/sites/{domain}/events")
def events(domain: str, limit: int = 100, db: Session = Depends(get_db)):
    return site_events(db, get_site(db, domain), limit)


def prune_events(db: Session, keep: int = 1000):
    for (site_id,) in db.execute(select(Site.id)).all():
        cutoff = db.scalar(select(SecurityEvent.id).where(SecurityEvent.site_id == site_id)
                           .order_by(SecurityEvent.id.desc()).offset(keep).limit(1))
        if cutoff is not None:
            db.execute(delete(SecurityEvent).where(SecurityEvent.site_id == site_id, SecurityEvent.id <= cutoff))


# ------------------------------------------------------------------ platform-wide (admin panel)

@router.get("/overview")
def overview(db: Session = Depends(get_db)):
    """One call for the WHMCS admin dashboard: site/edge counts, month totals, top sites."""
    from .models import Edge
    from .services import month_start, online_edges

    start = month_start()
    by_status = Counter()
    for s in db.scalars(select(Site)):
        by_status[s.effective_status] += 1
    usage = Counter()
    requests = Counter()
    security = Counter()
    for row in db.scalars(select(UsageHourly).where(UsageHourly.hour >= start)):
        usage[row.site_id] += row.bytes
        requests[row.site_id] += row.requests
        for k, v in _obj(_loads(row.details).get("security")).items():
            security[k] += num(v)
    domains = dict(db.execute(select(Site.id, Site.domain)).all())
    online = {e.id for e in online_edges(db)}
    edges = list(db.scalars(select(Edge).order_by(Edge.id)))
    from . import tunnel_quality
    from . import uptime as up
    from .services import edge_metrics
    ups = up.summaries(db)
    return {
        "sites": {"total": sum(by_status.values()), "by_status": dict(by_status)},
        "edges": {"total": len(edges), "enabled": sum(1 for e in edges if e.enabled), "online": len(online),
                  "with_errors": sum(1 for e in edges if e.last_error),
                  "shed": sum(1 for e in edges if e.shed),
                  "list": [{"id": e.id, "name": e.name, "group": e.group, "enabled": e.enabled,
                            "online": e.id in online, "shed": e.shed, "capacity_mbps": e.capacity_mbps,
                            "metrics": edge_metrics(e), "uptime": ups.get(e.id, {"h24": None, "d30": None})}
                           for e in edges]},
        "month": {"start": start.isoformat() + "Z", "bytes": sum(usage.values()), "requests": sum(requests.values()),
                  "security": dict(security)},
        "top_sites": [{"domain": domains.get(sid, "?"), "bytes": b, "requests": requests[sid]}
                      for sid, b in usage.most_common(10)],
        "nameservers": settings.nameservers,
        # SPEC §15.5: per edge group, 3-day p95 of the hourly tx vs the group's summed capacity
        "capacity": tunnel_quality.capacity(db),
    }


# ------------------------------------------------------------------ incidents (SPEC §8.3)

INCIDENT_SEVERITIES = ("minor", "major", "maintenance")
INCIDENT_STATUSES = ("investigating", "identified", "monitoring", "resolved", "scheduled")


class IncidentIn(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    body: str = Field(default="", max_length=20000)
    severity: str
    status: str = "investigating"


class IncidentUpdateIn(BaseModel):
    status: str
    body: str = Field(default="", max_length=20000)


class IncidentPatch(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=200)
    body: str | None = Field(default=None, max_length=20000)
    severity: str | None = None
    status: str | None = None


def _check_severity(sev: str):
    if sev not in INCIDENT_SEVERITIES:
        bad(ValidationError("شدت باید یکی از minor، major یا maintenance باشد"))


def _check_status(st: str):
    if st not in INCIDENT_STATUSES:
        bad(ValidationError("وضعیت باید یکی از investigating، identified، monitoring، resolved یا scheduled باشد"))


def _get_incident(db: Session, incident_id: int) -> Incident:
    inc = db.get(Incident, incident_id)
    if inc is None:
        raise HTTPException(404, "رخداد یافت نشد")
    return inc


@router.get("/incidents")
def list_incidents(all: bool = False, db: Session = Depends(get_db)):
    from .status import incident_dict

    q = select(Incident).order_by(Incident.id.desc())
    if not all:
        q = q.where(Incident.status != "resolved")
    return [incident_dict(i) for i in db.scalars(q)]


@router.post("/incidents", status_code=201)
def create_incident(body: IncidentIn, db: Session = Depends(get_db)):
    from .status import incident_dict

    _check_severity(body.severity)
    _check_status(body.status)
    inc = Incident(title=body.title.strip(), body=body.body, severity=body.severity, status=body.status)
    db.add(inc)
    db.flush()
    inc.updates.append(IncidentUpdate(status=body.status, body=body.body))
    db.commit()
    return incident_dict(inc)


@router.post("/incidents/{incident_id}/updates", status_code=201)
def add_incident_update(incident_id: int, body: IncidentUpdateIn, db: Session = Depends(get_db)):
    from .status import incident_dict

    _check_status(body.status)
    inc = _get_incident(db, incident_id)
    inc.updates.append(IncidentUpdate(status=body.status, body=body.body))
    inc.status = body.status
    inc.updated_at = utcnow()
    db.commit()
    return incident_dict(inc)


@router.patch("/incidents/{incident_id}")
def update_incident(incident_id: int, body: IncidentPatch, db: Session = Depends(get_db)):
    from .status import incident_dict

    inc = _get_incident(db, incident_id)
    data = body.model_dump(exclude_none=True)
    if "severity" in data:
        _check_severity(data["severity"])
    if "status" in data:
        _check_status(data["status"])
    if not data:
        bad(ValidationError("هیچ تغییری ارسال نشده است"))
    for k, v in data.items():
        setattr(inc, k, v.strip() if k == "title" else v)
    inc.updated_at = utcnow()
    db.commit()
    return incident_dict(inc)


def _since(value: str | None):
    """`since` query value: ISO 8601 (`Z` / offset / naive = UTC) -> naive UTC; 422 otherwise."""
    if value is None or value == "":
        return None
    from datetime import datetime, timezone

    raw = value.strip().replace("Z", "+00:00").replace("z", "+00:00")
    dt = None
    # an unencoded "+hh:mm" offset arrives as " hh:mm"
    for candidate in (raw, raw[:-6] + "+" + raw[-5:] if len(raw) > 6 and raw[-6] == " " else None):
        try:
            dt = datetime.fromisoformat(candidate) if candidate else None
        except ValueError:
            continue
        if dt is not None:
            break
    if dt is None:
        bad(ValidationError("since باید یک زمان ISO 8601 باشد (مثلاً 2026-10-01T12:00:00Z)"))
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


@router.get("/events")
def all_events(limit: int = 100, source: str | None = None, type: str | None = None, since: str | None = None,
               db: Session = Depends(get_db)):
    """Security events across every site, newest first (admin panel; default / `type=security`), or
    with `type=tunnel` the tunnel origin-down / origin-up site events (SPEC §15.4), oldest first,
    created at or after `since` — polled by the WHMCS cron, deduped by the stable event `id`."""
    from . import tunnel_quality

    kind = (type or "security").strip().lower()
    if kind not in ("security", *tunnel_quality.EVENT_TYPES):
        bad(ValidationError("type باید security یا tunnel باشد"))
    after = _since(since)
    if kind in tunnel_quality.EVENT_TYPES:
        return tunnel_quality.list_events(db, kind, after, limit)
    limit = max(1, min(limit, 1000))
    q = select(SecurityEvent, Site.domain).join(Site, Site.id == SecurityEvent.site_id)
    if source:
        q = q.where(SecurityEvent.source == source)
    if after is not None:
        q = q.where(SecurityEvent.ts >= after)
    rows = db.execute(q.order_by(SecurityEvent.ts.desc(), SecurityEvent.id.desc()).limit(limit)).all()
    return [{"domain": d, "t": e.ts.isoformat() + "Z", "ip": e.ip, "country": e.country, "method": e.method,
             "host": e.host, "path": e.path, "action": e.action, "source": e.source, "rule": e.rule,
             "user_agent": e.user_agent} for e, d in rows]
