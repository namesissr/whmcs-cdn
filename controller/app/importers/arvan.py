"""ArvanCloud CDN API v4 import (SPEC §23.6). Endpoint shapes are assumptions to verify on staging with a
test account; everything provider-specific lives in this one module and is fixture-tested.

Base `ARVAN_API_URL` (default https://napi.arvancloud.ir/cdn/4.0), header `Authorization: Apikey <key>`.
The key is a parameter of `fetch` only: never stored, logged or put into an error.
"""

import re

from ..config import settings
from . import MAX_RECORDS, Budget, ProviderError, clamp_ttl, client, get_json, relative

NOTE_UNAVAILABLE = "در این نسخهٔ API در دسترس نبود"
STATIC_UNMAPPED = [
    {"what": "load_balancers", "reason": "توزیع‌کنندهٔ بار آروان منتقل نمی‌شود؛ از استخرها (pools) استفاده کنید"},
    {"what": "waf_managed_rules", "reason": "قوانین مدیریت‌شدهٔ WAF آروان معادل مستقیم ندارند"},
    {"what": "apps", "reason": "اپلیکیشن‌های آروان منتقل نمی‌شوند"},
    {"what": "custom_pages", "reason": "صفحه‌های سفارشی خطا منتقل نمی‌شوند"},
    {"what": "tls_certificates", "reason": "گواهی‌ها هرگز منتقل نمی‌شوند؛ گواهی رایگان صادر کنید یا گواهی خود را بارگذاری کنید"},
    {"what": "log_forwarders", "reason": "ارسال لاگ آروان منتقل نمی‌شود؛ خروجی لاگ را جداگانه تنظیم کنید"},
]


def auth_header(api_key: str) -> dict:
    key = (api_key or "").strip()
    if not key.lower().startswith("apikey "):
        key = "Apikey " + key
    return {"Authorization": key, "Accept": "application/json"}


def _data(doc):
    return doc.get("data") if isinstance(doc, dict) and "data" in doc else doc


def fetch(api_key: str, zone: str, budget: Budget | None = None) -> dict:
    """Raw provider JSON of one zone: {"dns": [...], "caching", "https", "firewall", "page_rules", "ddos",
    "rate_limit"} (optional parts None when the endpoint is not available)."""
    budget = budget or Budget()
    base = settings.arvan_api_url.rstrip("/")
    headers = auth_header(api_key)
    d = zone.strip().rstrip(".").lower()
    out: dict = {}
    with client() as c:
        get_json(c, f"{base}/domains/{d}", headers, budget, zone_check=True)
        records, page = [], 1
        while True:
            doc = get_json(c, f"{base}/domains/{d}/dns-records", headers, budget,
                           params={"page": page, "per_page": 100})
            items = _data(doc) or []
            if not isinstance(items, list):
                items = []
            records += [x for x in items if isinstance(x, dict)]
            if len(records) > MAX_RECORDS:
                raise ProviderError("provider_too_large")
            meta = (doc or {}).get("meta") or {} if isinstance(doc, dict) else {}
            last = meta.get("last_page") or (meta.get("pagination") or {}).get("last_page") or 1
            if page >= int(last or 1) or not items:
                break
            page += 1
        out["dns"] = records
        out["caching"] = _data(get_json(c, f"{base}/domains/{d}/caching", headers, budget, optional=True))
        https = get_json(c, f"{base}/domains/{d}/https", headers, budget, optional=True)
        if https is None:
            https = get_json(c, f"{base}/domains/{d}/ssl", headers, budget, optional=True)
        out["https"] = _data(https)
        out["firewall"] = _data(get_json(c, f"{base}/domains/{d}/firewall/rules", headers, budget, optional=True))
        out["page_rules"] = _data(get_json(c, f"{base}/domains/{d}/page-rules", headers, budget, optional=True))
        out["ddos"] = _data(get_json(c, f"{base}/domains/{d}/ddos", headers, budget, optional=True))
        out["rate_limit"] = _data(get_json(c, f"{base}/domains/{d}/rate-limit/rules", headers, budget,
                                           optional=True))
    return out


# ------------------------------------------------------------------ pure mappers

def _values(v) -> list:
    if isinstance(v, list):
        return v
    return [v] if v not in (None, "") else []


def _first(d: dict, *keys):
    for k in keys:
        if isinstance(d, dict) and d.get(k) not in (None, ""):
            return d.get(k)
    return None


def map_records(raw: list, zone: str) -> tuple[list[dict], list[dict]]:
    """Arvan DNS records -> (our records, unmapped notes). One record per value; ANAME -> ALIAS;
    cloud -> proxied (A/AAAA/CNAME/ALIAS only); TTL clamped 60..86400; apex NS / SOA skipped."""
    out, unmapped = [], []
    for r in raw or []:
        rtype = str(r.get("type") or "").upper()
        name = relative(str(r.get("name") or "@"), zone)
        ttl = clamp_ttl(r.get("ttl"))
        cloud = bool(r.get("cloud"))
        values = _values(r.get("value"))
        label = f"{name} {rtype}"
        if rtype == "ANAME":
            rtype = "ALIAS"
        proxied = cloud and rtype in ("A", "AAAA", "CNAME", "ALIAS")
        if rtype == "SOA" or (rtype == "NS" and name == "@"):
            out.append({"name": name, "type": rtype, "content": "", "ttl": ttl, "proxied": False, "priority": None,
                        "status": "unsupported", "reason": "به‌صورت خودکار مدیریت می‌شود"})
            continue
        upstream = r.get("upstream_https")
        if upstream not in (None, "", "default"):
            unmapped.append({"what": f"dns:{label}:upstream_https", "reason": "پروتکل اتصال به مبدأ را در بخش SSL تنظیم کنید"})
        ipf = r.get("ip_filter_mode")
        if isinstance(ipf, dict) and any(v not in (None, "", "none", "single") for k, v in ipf.items()
                                         if k in ("geo_filter", "order", "count")):
            unmapped.append({"what": f"dns:{label}:ip_filter_mode", "reason": "فیلتر/ترتیب IP آروان معادل ندارد"})
        if rtype in ("A", "AAAA"):
            weights = [v.get("weight") for v in values if isinstance(v, dict)]
            all_weighted = bool(values) and all(isinstance(w, int) and not isinstance(w, bool) for w in weights) \
                and len(weights) == len(values) and len(values) > 1
            if any(isinstance(v, dict) and v.get("country") for v in values):
                unmapped.append({"what": f"dns:{label}:country", "reason": "مقدار به تفکیک کشور پشتیبانی نمی‌شود"})
            if weights and any(w is not None for w in weights) and not all_weighted:
                unmapped.append({"what": f"dns:{label}:weight", "reason": "وزن فقط وقتی همهٔ مقادیر وزن دارند منتقل می‌شود"})
            for v in values:
                ip = v.get("ip") if isinstance(v, dict) else str(v)
                if not ip:
                    continue
                rec = {"name": name, "type": rtype, "content": str(ip), "ttl": ttl, "proxied": proxied,
                       "priority": None}
                if isinstance(v, dict) and v.get("port") and proxied:
                    rec["origin_port"] = int(v["port"]) if str(v["port"]).isdigit() else None
                if all_weighted and not proxied:
                    rec["weight"] = max(0, min(100, int(v.get("weight") or 0)))
                    rec["partial"] = True
                out.append(rec)
            continue
        for v in values or [None]:
            content, prio = None, None
            if rtype in ("CNAME", "NS"):
                content = _first(v, "host", "target") if isinstance(v, dict) else v
            elif rtype == "ALIAS":
                content = _first(v, "location", "host") if isinstance(v, dict) else v
            elif rtype == "MX":
                content = _first(v, "host", "exchange") if isinstance(v, dict) else v
                prio = _first(v, "priority", "preference") if isinstance(v, dict) else None
            elif rtype == "TXT":
                content = _first(v, "text", "value") if isinstance(v, dict) else v
            elif rtype == "SRV" and isinstance(v, dict):
                target = _first(v, "target", "host")
                content = f"{int(v.get('weight') or 0)} {int(v.get('port') or 0)} {target}" if target else None
                prio = v.get("priority")
            elif rtype == "CAA" and isinstance(v, dict):
                tag, val = v.get("tag"), v.get("value")
                content = f'{int(v.get("flags") or 0)} {tag} "{val}"' if tag and val is not None else None
            elif rtype == "PTR":
                content = _first(v, "domain", "host") if isinstance(v, dict) else v
            if content in (None, ""):
                out.append({"name": name, "type": rtype, "content": "", "ttl": ttl, "proxied": False, "priority": None,
                            "status": "unsupported", "reason": "نوع یا مقدار رکورد پشتیبانی نمی‌شود"})
                continue
            content = str(content).rstrip(".") if rtype in ("CNAME", "NS", "ALIAS", "MX", "PTR") else str(content)
            if rtype in ("CNAME", "NS", "ALIAS", "MX", "PTR") and content == "@":
                content = zone
            out.append({"name": name, "type": rtype, "content": content, "ttl": ttl, "proxied": proxied,
                        "priority": int(prio) if isinstance(prio, (int, float)) or str(prio or "").isdigit() else None})
    return out, unmapped


_DUR_RE = re.compile(r"^(\d+)\s*([smhd]?)$")


def duration(v) -> int | None:
    """Arvan durations: seconds, or "30m" / "1h" / "2d"; "off" / 0 -> 0; unknown -> None."""
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return int(v)
    s = str(v or "").strip().lower()
    if s in ("off", "0", "none", ""):
        return 0 if s else None
    m = _DUR_RE.match(s)
    if not m:
        return None
    return int(m.group(1)) * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]


def map_caching(c) -> dict:
    if not isinstance(c, dict):
        return {"status": "none", "fields": {}, "notes": [NOTE_UNAVAILABLE]}
    fields, notes, partial = {}, [], False
    status = str(c.get("cache_status") or "").lower()
    if status == "off":
        fields["enabled"] = False
    elif status == "uri":
        fields.update(enabled=True, ignore_query=True)
    elif status == "query_string":
        fields.update(enabled=True, ignore_query=False)
    elif status == "advance":
        fields["enabled"] = True
        notes.append("حالت پیشرفتهٔ کلید کش آروان به‌طور کامل منتقل نمی‌شود")
        partial = True
    edge = duration(c.get("cache_page_200"))
    if edge:
        fields["edge_ttl"] = max(60, min(edge, 31536000))
    browser = duration(c.get("cache_browser"))
    if browser is not None:
        fields["browser_ttl"] = max(0, min(browser, 31536000))
    if "cache_developer_mode" in c:
        fields["dev_mode"] = bool(c.get("cache_developer_mode"))
    if c.get("cache_ignore_sc"):
        notes.append("نادیده‌گرفتن Set-Cookie معادل مستقیم ندارد")
        partial = True
    if not fields:
        return {"status": "none", "fields": {}, "notes": notes or ["تنظیمی برای انتقال پیدا نشد"]}
    return {"status": "partial" if partial else "maps", "fields": fields, "notes": notes}


def map_https(h) -> dict:
    if not isinstance(h, dict):
        return {"status": "none", "fields": {}, "notes": [NOTE_UNAVAILABLE]}
    fields, notes = {}, []
    if "https_redirect" in h:
        fields["force_https"] = bool(h.get("https_redirect"))
    hsts = {}
    if "hsts_status" in h:
        hsts["enabled"] = bool(h.get("hsts_status"))
    if h.get("hsts_max_age") is not None:
        try:
            hsts["max_age"] = max(0, min(int(h["hsts_max_age"]), 63072000))
        except (TypeError, ValueError):
            pass
    if "hsts_subdomain" in h:
        hsts["include_subdomains"] = bool(h.get("hsts_subdomain"))
    if h.get("hsts_preload"):
        if hsts.get("include_subdomains") and hsts.get("max_age", 0) >= 31536000:
            hsts["preload"] = True
        else:
            notes.append("preload فقط با includeSubDomains و max-age حداقل یک سال مجاز است؛ منتقل نشد")
    if hsts:
        fields["hsts"] = hsts
    if not fields:
        return {"status": "none", "fields": {}, "notes": ["تنظیمی برای انتقال پیدا نشد"]}
    return {"status": "partial" if notes else "maps", "fields": fields, "notes": notes}


_IP_IN = re.compile(r"^\(?\s*ip\.src\s+in\s+\{([^}]*)\}\s*\)?$")
_IP_EQ = re.compile(r"^\(?\s*ip\.src\s+(?:eq|==)\s+([0-9a-fA-F:./]+)\s*\)?$")
_CC_IN = re.compile(r"^\(?\s*ip\.geoip\.country\s+in\s+\{([^}]*)\}\s*\)?$")
_PATH_EQ = re.compile(r'^\(?\s*http\.request\.uri\.path\s+(?:eq|==)\s+"([^"]*)"\s*\)?$')
_PATH_SW = re.compile(r'^\(?\s*starts_with\(\s*http\.request\.uri\.path\s*,\s*"([^"]*)"\s*\)\s*\)?$')
ACTIONS = {"allow": "allow", "deny": "block", "block": "block", "challenge": "challenge"}


def _split(v: str) -> list[str]:
    return [x.strip().strip('"') for x in re.split(r"[\s,]+", v) if x.strip().strip('"')]


def parse_expr(expr: str) -> list[dict] | None:
    """Simple filter expressions (clauses joined by `and`) -> our conditions; None when not simple."""
    expr = (expr or "").strip()
    if not expr or re.search(r"\bor\b|\bnot\b|\|\||!", expr):
        return None
    conds = []
    for clause in re.split(r"\s+and\s+|\s*&&\s*", expr):
        clause = clause.strip()
        while clause.startswith("(") and clause.endswith(")") and clause.count("(") == 1:
            clause = clause[1:-1].strip()
        if m := _IP_IN.match(clause):
            conds.append({"field": "ip", "op": "in", "value": _split(m.group(1))})
        elif m := _IP_EQ.match(clause):
            conds.append({"field": "ip", "op": "in", "value": [m.group(1)]})
        elif m := _CC_IN.match(clause):
            conds.append({"field": "country", "op": "in", "value": [c.upper() for c in _split(m.group(1))]})
        elif m := _PATH_EQ.match(clause):
            conds.append({"field": "path", "op": "eq", "value": m.group(1)})
        elif m := _PATH_SW.match(clause):
            conds.append({"field": "path", "op": "starts_with", "value": m.group(1)})
        else:
            return None
    return conds or None


def map_firewall(rules) -> tuple[dict, list[dict]]:
    if not isinstance(rules, list):
        return {"status": "none", "rules": [], "notes": [NOTE_UNAVAILABLE]}, []
    out, unmapped = [], []
    for i, r in enumerate(rules):
        if not isinstance(r, dict):
            continue
        name = str(r.get("name") or f"rule {i + 1}")[:100]
        action = ACTIONS.get(str(r.get("action") or "").lower())
        conds = parse_expr(str(r.get("filter_expr") or r.get("expression") or ""))
        if action is None or conds is None:
            unmapped.append({"what": f"firewall:{name}", "reason": "عبارت یا عمل این قانون ساده نیست و منتقل نمی‌شود"})
            continue
        out.append({"id": f"imp-fw-{len(out) + 1}", "name": name, "enabled": r.get("is_enabled", True) is not False,
                    "action": action, "conditions": conds})
    status = "none" if not out else ("partial" if unmapped else "maps")
    return {"status": status, "rules": out, "notes": []}, unmapped


def _path_of(url: str) -> str:
    u = re.sub(r"^[a-z]+://", "", (url or "").strip(), flags=re.I)
    if "/" in u and not u.startswith("/"):
        u = u[u.index("/"):]
    return u if u.startswith("/") else "/" + u


def map_page_rules(rules) -> tuple[dict, list[dict]]:
    if not isinstance(rules, list):
        return {"status": "none", "rules": [], "notes": [NOTE_UNAVAILABLE]}, []
    out, unmapped = [], []
    for i, r in enumerate(rules):
        if not isinstance(r, dict):
            continue
        target = r.get("forward_url") or r.get("redirect_url")
        url = str(r.get("url") or r.get("pattern") or "")
        if not target or not url:
            unmapped.append({"what": f"page_rule:{url or i + 1}", "reason": "فقط قوانین هدایت (forward) منتقل می‌شوند"})
            continue
        status = int(r.get("forward_status") or r.get("status") or 301)
        path = _path_of(url)
        match = "exact"
        if path.endswith("*"):
            path, match = path.rstrip("*") or "/", "prefix"
        out.append({"id": f"imp-rd-{len(out) + 1}", "enabled": True, "source": path, "match": match,
                    "target": str(target), "status": status if status in (301, 302) else 301, "preserve_query": False})
    status = "none" if not out else ("partial" if unmapped else "maps")
    return {"status": status, "rules": out, "notes": []}, unmapped


DDOS_MODES = {"off": "off", "cookie": "js", "js": "js", "javascript": "js", "captcha": "captcha"}


def map_ddos(d) -> dict:
    if not isinstance(d, dict):
        return {"status": "none", "fields": {}, "notes": [NOTE_UNAVAILABLE]}
    mode = DDOS_MODES.get(str(d.get("ddos_protection_mode") or d.get("mode") or "").lower())
    if mode is None:
        return {"status": "none", "fields": {}, "notes": ["حالت محافظت DDoS شناخته نشد"]}
    return {"status": "maps", "fields": {"mode": mode}, "notes": []}


def map_rate_limit(rules) -> tuple[dict, list[dict]]:
    if not isinstance(rules, list):
        return {"status": "none", "rules": [], "notes": [NOTE_UNAVAILABLE]}, []
    out, unmapped = [], []
    for i, r in enumerate(rules):
        if not isinstance(r, dict):
            continue
        path = str(r.get("url_pattern") or r.get("path") or "")
        rate = r.get("rate") or r.get("requests")
        period = duration(r.get("duration") or r.get("period") or 1)
        if not path.startswith("/") or not isinstance(rate, int) or not period:
            unmapped.append({"what": f"rate_limit:{path or i + 1}", "reason": "فقط قوانین ساده (مسیر + تعداد) منتقل می‌شوند"})
            continue
        out.append({"id": f"imp-rl-{len(out) + 1}", "enabled": True, "path": path if "*" in path else path,
                    "methods": [], "requests": max(1, min(rate, 1000000)), "period": max(1, min(period, 3600)),
                    "action": "block", "block_seconds": 60})
    status = "none" if not out else ("partial" if unmapped else "maps")
    return {"status": status, "rules": out, "notes": []}, unmapped


def map_all(raw: dict, zone: str) -> tuple[list[dict], dict, list[dict]]:
    records, unmapped = map_records(raw.get("dns") or [], zone)
    fw, u1 = map_firewall(raw.get("firewall"))
    pr, u2 = map_page_rules(raw.get("page_rules"))
    rl, u3 = map_rate_limit(raw.get("rate_limit"))
    secs = {"cache": map_caching(raw.get("caching")), "ssl": map_https(raw.get("https")),
            "firewall": fw, "redirects": pr, "ddos": map_ddos(raw.get("ddos")), "ratelimit": rl}
    return records, secs, unmapped + u1 + u2 + u3 + list(STATIC_UNMAPPED)
