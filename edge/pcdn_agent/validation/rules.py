"""Normalisation of the per-site rule sections (SPEC §14.2, §16): page rules and preload links,
cache-key options, redirects, transform rules, bot management, authenticated origin pulls,
images v2 and video. Everything is validated again on the edge; what does not pass is dropped,
never "fixed"."""

import hashlib
import ipaddress
import re
from datetime import datetime, timezone

from ..common import HOP_HEADERS, SAFE_CIDR, SAFE_HEADER, SAFE_ID, SAFE_PATTERN, _int, _sec, wildcard_re
from .regex import pcre_regex


def _legacy_sections(site: dict) -> tuple[dict, dict]:
    """v2 `cache` / `ssl_options` sections, derived from v1 flat fields when absent."""
    cache = site.get("cache") if isinstance(site.get("cache"), dict) else {
        "enabled": bool(site.get("cache_enabled")), "level": "standard",
        "edge_ttl": site.get("edge_cache_ttl") or 0, "browser_ttl": site.get("browser_cache_ttl") or 0,
        "always_online": True}
    sslo = site.get("ssl_options") if isinstance(site.get("ssl_options"), dict) else {
        "force_https": bool(site.get("force_https")), "origin_protocol": site.get("origin_protocol") or "http"}
    return cache, sslo


def page_rules(site: dict) -> list:
    rules = []
    for r in (_sec(site, "pagerules").get("rules") or []):
        pat = str(r.get("pattern") or "")
        if r.get("enabled") is False or not SAFE_PATTERN.match(pat):
            continue
        rules.append(dict(r, _re=wildcard_re(pat), _jre=wildcard_re(pat, js=True)))
    return rules


PRELOAD_AS = ("script", "style", "image", "font", "fetch")
PRELOAD_MAX = 10
# same-site path or absolute http(s) URL (no protocol-relative "//host"); printable ASCII without
# space (so no CR/LF either)
SAFE_PRELOAD_URL = re.compile(r"^(?:https?://[A-Za-z0-9.-]+(?::\d{1,5})?)?/(?!/)[\x21-\x7e]{0,1000}$")
PRELOAD_BAD = set("\"'<>\\`")


def preload_links(rule: dict) -> list[str]:
    """Validated `Link` values of a page rule's `preload` list (SPEC §14.1), re-checked on the edge:
    quotes, CR/LF, whitespace and <> are rejected (they could break out of the header or the
    nginx string); `$` is kept literal by _qv at render time."""
    out = []
    pre = rule.get("preload")
    for p in (pre if isinstance(pre, list) else [])[:PRELOAD_MAX]:
        if not isinstance(p, dict):
            continue
        url, kind = str(p.get("url") or ""), p.get("as")
        if kind not in PRELOAD_AS or not SAFE_PRELOAD_URL.match(url) or PRELOAD_BAD & set(url):
            continue
        # fonts are always fetched in CORS mode; without `crossorigin` the preload is wasted
        out.append(f"<{url}>; rel=preload; as={kind}" + ("; crossorigin" if kind == "font" else ""))
    return list(dict.fromkeys(out))


SAFE_KEY_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")             # cookie names
SAFE_QUERY_NAME = re.compile(r"^[A-Za-z0-9_.\[\]-]{1,64}$")     # query parameter names ("f[x]")
NGX_VAR_NAME = re.compile(r"^[A-Za-z0-9_]{1,64}$")
KEY_COOKIES_MAX, KEY_QUERY_MAX = 10, 50


def key_options(site: dict) -> dict:
    """Cache-key options of a site (SPEC §14.1), validated again on the edge. Names must be cookie /
    query-parameter tokens; ones that are not valid nginx variable suffixes ("wp-lang") are read
    through a per-site regex map instead of $cookie_<name> / $arg_<name>. image.auto_webp is
    independent of the resize toggle; the plan's image_optimization gate is folded in by the
    controller (it sends auto_webp=false when the feature is off)."""
    cache, _ = _legacy_sections(site)

    def names(v, cap, rx):
        return list(dict.fromkeys(x for x in (v if isinstance(v, list) else [])
                                  if isinstance(x, str) and rx.match(x)))[:cap]
    return {"dev": cache.get("key_device") is True,
            "cookies": names(cache.get("key_cookies"), KEY_COOKIES_MAX, SAFE_KEY_NAME),
            "qa": names(cache.get("key_query_allow"), KEY_QUERY_MAX, SAFE_QUERY_NAME),
            "webp": _sec(site, "image").get("auto_webp") is True}


def key_infos(config: dict) -> dict:
    """Per-site cache-key shape for exact-URL purges ({site_id: options}); only sites whose key is
    not the plain "<scheme>://<host><uri>" are listed."""
    out = {}
    for s in config.get("sites", []) if isinstance(config, dict) else []:
        try:
            k = key_options(s)
            sid = str(int(s["id"]))
        except (KeyError, TypeError, ValueError):
            continue
        if k["dev"] or k["cookies"] or k["qa"] or k["webp"]:
            out[sid] = k
        if norm_video(s):   # SPEC §16.5: *.mp4 may be cached in 1 MB slices (";r=<range>" key field)
            out[sid] = dict(out.get(sid) or k, slice=True)
    return out


# ----------------------------------------------------------------- rules & security (SPEC §14.2)
# Everything below is validated again on the edge (the controller already did): a value that does
# not pass is dropped, never "fixed", and a rule whose condition cannot be understood is skipped as
# a whole (a broken condition must never widen what a rule applies to).

WAF_PACKS = ("generic", "wordpress", "joomla", "drupal", "laravel", "api")
# rule-set versions of the managed packs shipped in njs/pcdn.js (WAF_PACK_VERSION there; a unit
# test keeps both in sync), reported in the heartbeat capabilities
WAF_PACK_VERSIONS = {"generic": 1, "wordpress": 1, "joomla": 1, "drupal": 1, "laravel": 1, "api": 1}
BOT_MODES = ("log", "challenge", "block")
BODY_CAP = 131072   # request bodies inspected by the WAF packs (njs BODY_CAP)
BOT_ENGINES = (("google", "1", "g"), ("bing", "2", "b"))   # name, $pcdn_vbot value, "known" flag
BOT_MIN_PREFIX = {4: 16, 6: 32}   # anything broader is not a crawler range (tampered / bogus list)
BOT_MAX_PREFIXES = 2000
REDIRECT_CODES = (301, 302, 307, 308)
TF_MAX_RULES, TF_MAX_ACTIONS, REDIRECT_MAX = 1000, 10, 10000
# header names a transform rule may never touch (mirrors the controller's TRANSFORM_RESERVED):
# hop-by-hop / framing, the visitor-address chain the edge sets, and every internal X-Pcdn-* header
TF_RESERVED = HOP_HEADERS | {"x-real-ip", "forwarded", "trailers"}
TF_RESERVED_PREFIX = ("x-pcdn-", "x-forwarded-", "proxy-")
TF_REMOVE_ONLY = {"cookie", "set-cookie"}
SAFE_TF_VALUE = re.compile(r"^[\x20-\x7e]{1,1024}$")
# redirect source (exact / prefix): a raw request path as the controller normalises it (percent-encoded)
SAFE_REDIRECT_SOURCE = re.compile(r"^/[A-Za-z0-9\-._~!&'()*+,;=:@/%]{0,1023}$")
# redirect target / rewrite replacement characters: RFC 3986 unreserved + reserved + "%" and "$"
# (only as $1..$9). Double quotes, backslashes, whitespace, CR/LF, <> and backticks never pass.
URL_CHARS = re.compile(r"^[A-Za-z0-9\-._~!&'()*+,;=:@/?#\[\]%$]*$")
REDIRECT_ABS = re.compile(r"^https?://[A-Za-z0-9.-]{1,253}(?::\d{1,5})?(?=[/?#]|$)")
SAFE_REWRITE = re.compile(r"^/(?!/)[A-Za-z0-9\-._~!$&'()*+,;=:@/?%]{0,1023}$")
# map_hash_bucket_size is 128: longer exact redirect sources are matched by an anchored regex instead
REDIRECT_HASH_MAX_KEY = 96


def _qre(s: str) -> str:
    """A regex (or other text without `$` interpolation concerns) as a double-quoted nginx token:
    nginx un-escapes \\\\ and \\" inside quotes, so both are escaped."""
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _hvar(name: str) -> str:
    """nginx variable of a request header ($http_x_foo for X-Foo)."""
    return "$http_" + name.lower().replace("-", "_")


def _refs_ok(text: str, groups: int | None) -> bool:
    """`$` only as $1..$9 naming an existing group (groups None: no `$` at all)."""
    for m in re.finditer(r"\$(\d?)(\d?)", text):
        if groups is None or not m.group(1) or m.group(1) == "0" or m.group(2) or int(m.group(1)) > groups:
            return False
    return True


def _under(path: str, prefixes) -> bool:
    return any(path.startswith(p) for p in prefixes)


def norm_redirects(site: dict, tunnel_prefixes=()) -> list[dict]:
    """Validated `redirects.rules` in order: {id, match, source, target, status, preserve_query,
    groups (regex only), re (compiled, regex only)}. Exact / prefix sources inside /__pcdn/ or a
    tunnel path are dropped (those paths are never redirected)."""
    out = []
    for r in (_sec(site, "redirects").get("rules") or [])[:REDIRECT_MAX]:
        if not isinstance(r, dict) or r.get("enabled") is False:
            continue
        rid, match, status = str(r.get("id") or "").lower(), r.get("match") or "exact", r.get("status")
        src, target = r.get("source"), r.get("target")
        if (not SAFE_ID.match(rid) or match not in ("exact", "prefix", "regex") or status not in REDIRECT_CODES
                or isinstance(status, bool) or not isinstance(src, str) or not isinstance(target, str)):
            continue
        groups, rx = None, None
        if match == "regex":
            rx = pcre_regex(src)
            if rx is None:
                continue
            groups = rx.groups
        elif (not SAFE_REDIRECT_SOURCE.match(src) or src.lower().startswith("/__pcdn")
              or _under(src, tunnel_prefixes)):
            continue
        if (not target or len(target) > 2048 or not URL_CHARS.match(target) or not _refs_ok(target, groups)
                or not (REDIRECT_ABS.match(target) or (target.startswith("/") and not target.startswith("//")))):
            continue
        out.append({"id": rid, "match": match, "source": src, "target": target, "status": status,
                    "preserve_query": r.get("preserve_query") is True, "groups": groups, "re": rx})
    return out


def _rd_matches(rule: dict, path: str) -> bool:
    if rule["match"] == "prefix":
        return path.startswith(rule["source"])
    if rule["match"] == "regex":
        return rule["re"].search(path) is not None
    return path == rule["source"]


def redirect_maps(sid: int, rules: list[dict], tunnel_prefixes=()) -> tuple[list[str], str | None, list[int]]:
    """http-level maps of a site's redirect rules -> (maps, variable, status codes used). The
    variable is "<status><Location>" of the first enabled rule (in order) matching the RAW request
    path ($pcdn_path: percent-encoded like the controller's sources; regex captures can never carry a
    decoded CR/LF into the Location header), or "".
     * exact sources: one hash lookup ($pcdn_rdh_*). nginx lower-cases map hash keys, so the hit is
       confirmed case-sensitively by a backreference ($pcdn_rde_*: the path must repeat the source).
       An exact rule shadowed by an EARLIER prefix / regex rule matching that same path is dropped
       (unreachable), so the hash may take precedence over the ordered map.
     * prefix / regex rules (and exact sources too long for the hash or differing from a hashed one
       only by case): one ordered regex map ($pcdn_rdc_*), first match wins; /__pcdn/ and tunnel
       prefixes are guarded first (never redirected).
    The value carries $1..$9 (regex rules) and, with preserve_query, the query string."""
    def value(r):
        t = r["target"]
        if r["preserve_query"]:
            base, mark, frag = t.partition("#")
            t = base + ("$pcdn_args_amp" if "?" in base else "$is_args$args") + mark + frag
        return f"{r['status']}{t}"

    hashed, ordered, before, seen, seen_low, codes = [], [], [], set(), set(), set()
    for r in rules:
        if r["match"] == "exact":
            src = r["source"]
            if src in seen or any(_rd_matches(p, src) for p in before):
                continue
            seen.add(src)
            if src.lower() not in seen_low and len(src) <= REDIRECT_HASH_MAX_KEY:
                seen_low.add(src.lower())
                hashed.append((src, value(r)))
                codes.add(r["status"])
                continue
            ordered.append(("~^" + re.escape(src) + "$", value(r)))
        elif r["match"] == "prefix":
            ordered.append(("~^" + re.escape(r["source"]), value(r)))
        else:
            ordered.append(("~" + r["source"], value(r)))
        before.append(r)
        codes.add(r["status"])
    maps, rde, rdc = [], None, None
    if hashed:
        maps.append(f"map $pcdn_path $pcdn_rdh_{sid} {{\n    default \"\";\n"
                    + "".join(f'    {_qre(src)} "{src} {val}";\n' for src, val in hashed) + "}")
        maps.append(f'map "$pcdn_path $pcdn_rdh_{sid}" $pcdn_rde_{sid} {{\n    default "";\n'
                    f'    "~^(\\\\S+) \\\\1 (.+)$" $2;\n}}')
        rde = f"$pcdn_rde_{sid}"
    if ordered:
        guards = ['    "~^/__pcdn/" "";\n']
        if tunnel_prefixes:
            guards.append(f"    {_qre('~^(?:' + '|'.join(re.escape(p) for p in tunnel_prefixes) + ')')} \"\";\n")
        if any(r["match"] == "regex" for r in before):
            # customer regexes never run on an over-long path ($pcdn_rxlong, security review H2)
            maps.append(f'map $pcdn_rxlong $pcdn_rdc_{sid} {{\n    1 "";\n    default $pcdn_rdcx_{sid};\n}}')
            rdc_var = f"pcdn_rdcx_{sid}"
        else:
            rdc_var = f"pcdn_rdc_{sid}"
        maps.append(f"map $pcdn_path ${rdc_var} {{\n    default \"\";\n" + "".join(guards)
                    + "".join(f'    {_qre(k)} "{val}";\n' for k, val in ordered) + "}")
        rdc = f"$pcdn_rdc_{sid}"
    if rde and rdc:
        maps.append(f'map {rde} $pcdn_rd_{sid} {{\n    "~." {rde};\n    default {rdc};\n}}')
        return maps, f"$pcdn_rd_{sid}", sorted(codes)
    return maps, rde or rdc, sorted(codes)


def _tf_header_ok(name, remove: bool) -> bool:
    if not isinstance(name, str) or not SAFE_HEADER.match(name):
        return False
    low = name.lower()
    if low in TF_RESERVED or low.startswith(TF_RESERVED_PREFIX):
        return False
    return remove or low not in TF_REMOVE_ONLY


def norm_transform(site: dict) -> list[dict]:
    """Validated `transform.rules` in order: {"cond": None (always) | {methods, countries, path_re},
    "actions": [...]}. Actions: {type, name, value} for headers, {type, re, regex, groups,
    replacement} for rewrite_path."""
    out = []
    for r in (_sec(site, "transform").get("rules") or [])[:TF_MAX_RULES]:
        if not isinstance(r, dict) or r.get("enabled") is False:
            continue
        m = r.get("match") if isinstance(r.get("match"), dict) else {}
        pat = m.get("path", m.get("pattern"))
        methods, countries = m.get("methods") or [], m.get("countries") or []
        if pat not in (None, "", "/*", "*") and not (isinstance(pat, str) and SAFE_PATTERN.match(pat)):
            continue
        if not isinstance(methods, list) or not all(isinstance(x, str) and re.match(r"^[A-Za-z]{1,16}$", x)
                                                    for x in methods):
            continue
        if not isinstance(countries, list) or not all(isinstance(x, str) and re.match(r"^[A-Za-z]{2}$", x)
                                                      for x in countries):
            continue
        cond = {"methods": sorted({x.upper() for x in methods}), "countries": sorted({x.upper() for x in countries}),
                "path_re": wildcard_re(pat) if pat not in (None, "", "/*", "*") else None}
        if not cond["methods"] and not cond["countries"] and cond["path_re"] is None:
            cond = None
        actions = []
        for a in (r.get("actions") if isinstance(r.get("actions"), list) else [])[:TF_MAX_ACTIONS]:
            if not isinstance(a, dict):
                continue
            t = a.get("type")
            if t == "rewrite_path":
                rx, rep = pcre_regex(a.get("regex")), a.get("replacement")
                if (rx is None or not isinstance(rep, str) or not SAFE_REWRITE.match(rep)
                        or rep.lower().startswith("/__pcdn") or not _refs_ok(rep, rx.groups)):
                    continue
                actions.append({"type": t, "regex": a["regex"], "groups": rx.groups, "replacement": rep})
            elif t in ("set_request_header", "set_response_header"):
                v = a.get("value")
                if _tf_header_ok(a.get("name"), False) and isinstance(v, str) and SAFE_TF_VALUE.match(v):
                    actions.append({"type": t, "name": a["name"], "value": v})
            elif t in ("remove_request_header", "remove_response_header"):
                if _tf_header_ok(a.get("name"), True):
                    actions.append({"type": t, "name": a["name"]})
        if actions:
            out.append({"cond": cond, "actions": actions})
    return out


def norm_bots(site: dict) -> dict | None:
    """Per-site `bots` section; None when absent or mode off (today's behaviour)."""
    b = _sec(site, "bots")
    if b.get("mode") not in BOT_MODES:
        return None
    return {"mode": b["mode"], "allow_verified": b.get("allow_verified") is not False,
            "block_empty_ua": b.get("block_empty_ua") is not False}


def norm_bot_ranges(config: dict) -> dict:
    """Node-wide verified crawler ranges {engine: [cidr]} (only engines with at least one valid
    network). Broad or malformed networks are dropped; duplicates (also across engines) are kept
    once, for the first engine."""
    b = config.get("bots") if isinstance(config, dict) else None
    ver = b.get("verified") if isinstance(b, dict) else None
    out, seen = {}, set()
    if not isinstance(ver, dict):
        return out
    for name, _, _ in BOT_ENGINES:
        nets = []
        for c in (ver.get(name) if isinstance(ver.get(name), list) else [])[:BOT_MAX_PREFIXES * 2]:
            if not isinstance(c, str) or not SAFE_CIDR.match(c.strip()):
                continue
            try:
                n = ipaddress.ip_network(c.strip(), strict=False)
            except ValueError:
                continue
            if n.prefixlen < BOT_MIN_PREFIX[n.version] or n in seen:
                continue
            seen.add(n)
            nets.append(n)
        if nets:
            out[name] = [str(n) for n in sorted(nets, key=lambda n: (n.version, n))][:BOT_MAX_PREFIXES]
    return out


def with_cached_bot_ranges(body: dict, state: dict) -> dict:
    """The agent's cache of verified crawler ranges (SPEC §14.2): every engine's last non-empty list
    is kept in the state file and used while the controller sends none for it (e.g. a controller
    restored from an old backup). Nothing received ever -> nothing cached -> crawler UAs fail open."""
    if not isinstance(body, dict):
        return body
    got = norm_bot_ranges(body)
    cache = state.get("bot_ranges") if isinstance(state.get("bot_ranges"), dict) else {}
    cache = {k: v for k, v in cache.items() if isinstance(v, list) and v}
    cache.update(got)
    if cache:
        state["bot_ranges"] = cache
    if cache == got:
        return body
    b = body.get("bots") if isinstance(body.get("bots"), dict) else {}
    return dict(body, bots=dict(b, verified=dict(cache)))


SAFE_PEM = re.compile(r"^[A-Za-z0-9+/=\-\s:,._()]+$")


def _pem_ok(cert, key) -> bool:
    """A PEM certificate (chain) + unencrypted private key, shape-checked so a malformed upload
    cannot make `nginx -t` reject the whole tree."""
    return (isinstance(cert, str) and isinstance(key, str) and 0 < len(cert) <= 65536 and 0 < len(key) <= 16384
            and SAFE_PEM.match(cert) is not None and SAFE_PEM.match(key) is not None
            and "-----BEGIN CERTIFICATE-----" in cert and "-----END CERTIFICATE-----" in cert
            and re.search(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", key) is not None and "ENCRYPTED" not in key)


def norm_origin_pull(config: dict) -> dict | None:
    """Node-wide platform client certificate {cert, key}, or None."""
    op = config.get("origin_pull") if isinstance(config, dict) else None
    if isinstance(op, dict) and _pem_ok(op.get("cert"), op.get("key")):
        return {"cert": op["cert"], "key": op["key"]}
    return None


def origin_client(sslo: dict) -> dict:
    """ssl_options.origin_client of a site: {"mode": off|platform|custom, cert?, key?}; the bare
    `origin_client_auth` string is understood too. A custom mode without a usable pair is off."""
    oc = sslo.get("origin_client")
    if isinstance(oc, dict):
        mode, cert, key = oc.get("mode"), oc.get("cert"), oc.get("key")
    else:
        mode, cert, key = sslo.get("origin_client_auth"), None, None
    if mode == "platform":
        return {"mode": "platform"}
    if mode == "custom" and _pem_ok(cert, key):
        return {"mode": "custom", "cert": cert, "key": key}
    return {"mode": "off"}


# ----------------------------------------------------------------- wave 8: images v2, video (SPEC §16)

SAFE_TRANSFORM_SECRET = re.compile(r"^[\x21-\x7e]{16,256}$")


def norm_image_v2(site: dict) -> dict:
    """SPEC §16.6 additions of the `image` section (falsy = absent / default, so a site that does not
    use them renders exactly as before): avif, transform_secret (16-256 printable characters, no
    spaces; anything else is treated as unset) and smart_crop."""
    im = _sec(site, "image")
    sec = im.get("transform_secret")
    return {"avif": im.get("avif") is True,
            "secret": sec if isinstance(sec, str) and SAFE_TRANSFORM_SECRET.match(sec) else "",
            "smart": im.get("smart_crop") is True}


def image_signature(secret: str, path: str, params: dict) -> str:
    """Reference signer for image transform URLs (SPEC §16.6; pcdn.js imgParams verifies it):
    hex HMAC-SHA256(transform_secret, "<path>?<k=v&...>") over w, h, fit, q, fmt, width, height in
    that order (only the ones present), path and values exactly as they appear in the URL (raw,
    percent-encoded). The URL then carries &sig=<hex>."""
    import hmac as _hmac   # noqa: PLC0415
    base = path + "?" + "&".join(f"{k}={params[k]}" for k in ("w", "h", "fit", "q", "fmt", "width", "height")
                                 if k in params)
    return _hmac.new(secret.encode(), base.encode(), hashlib.sha256).hexdigest()


def norm_video(site: dict) -> dict | None:
    """SPEC §16.5 `video` section {enabled, segment_ttl, manifest_ttl, prefetch_next}; None = off."""
    v = _sec(site, "video")
    if v.get("enabled") is not True:
        return None
    return {"segment_ttl": _int(v.get("segment_ttl"), 86400, 1, 31536000),
            "manifest_ttl": _int(v.get("manifest_ttl"), 2, 1, 3600),
            "prefetch": v.get("prefetch_next", True) is not False}


LEARN_MAX_SECONDS = 31 * 86400   # the controller allows 1..30 days; a later `until` is not trusted


def norm_waf_learning(site: dict, now: float | None = None) -> int | None:
    """SPEC §17.1 `waf.learning` {enabled, until: ISO 8601 | null} -> the end of learning as a UNIX
    epoch second, or None (not learning: disabled, no / unparsable `until`).

    With `now` the result is None once `until` has passed and is capped at now + 31 days; without it
    the parsed `until` is returned as is (deterministic, for rendering: njs compares it with the
    clock at request time, so learning ends on time without a re-render)."""
    ln = _sec(site, "waf").get("learning")
    if not isinstance(ln, dict) or ln.get("enabled") is not True or not isinstance(ln.get("until"), str):
        return None
    raw = ln["until"].strip()
    if not raw or len(raw) > 40:
        return None
    try:
        dt = datetime.fromisoformat(raw[:-1] + "+00:00" if raw.endswith(("Z", "z")) else raw)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    until = int(dt.timestamp())
    if until <= 0 or until > 4102444800:   # 2100-01-01: nonsense
        return None
    if now is not None:
        if until <= now:
            return None
        until = min(until, int(now) + LEARN_MAX_SECONDS)
    return until
