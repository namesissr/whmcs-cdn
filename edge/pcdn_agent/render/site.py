"""Per-site nginx rendering: one server/vhost file per site plus its certificates, error pages and
storage tokens, the speed-test endpoints and the decoy page."""

import os
import re
from datetime import datetime, timezone

from ..capabilities import geoip_present, image_capabilities, nginx_capabilities
from ..common import (
    HOP_HEADERS, IP_LITERAL, SAFE_COOKIE, SAFE_FSPATH, SAFE_HEADER, SAFE_NAME, SAFE_RESOLVER, SAFE_SIZE,
    SAFE_TUNNEL_PATH, SAFE_URL, SAFE_VALUE, STATIC_EXT, _int, _q, _qv, _sec, _v6,
)
from ..functions import functions_enabled, norm_functions
from ..settings import HERE, log
from ..validation.origin import (
    guard_pools, guard_tunnel, internal_src, norm_pools, norm_tunnel, origin_host_allowed,
    origin_hp_allowed, resolve_origin,
)
from ..validation.rules import (
    BODY_CAP, NGX_VAR_NAME, _hvar, _legacy_sections, _qre, key_options, norm_image_v2, norm_redirects,
    norm_transform, norm_video, norm_waf_learning, origin_client, page_rules, preload_links, redirect_maps,
)
from ..validation.storage import norm_storage_origin, storage_log_repr
from .http import mtls_token
from .njs import site_js


def decoy_page(cfg: dict, domain: str) -> str:
    """Neutral placeholder page served on non-tunnel paths when tunnel.fallback = decoy."""
    path = os.path.join(cfg.get("PAGES_DIR") or "", "decoy.html")
    if not os.path.isfile(path):
        path = os.path.join(HERE, "pages", "decoy.html")
    with open(path) as f:
        text = f.read()
    name = domain.split(".")[0].replace("-", " ").title() if domain else "Welcome"
    return text.replace("{{NAME}}", name).replace("{{YEAR}}", str(datetime.now(timezone.utc).year))


def render_site(site: dict, cfg: dict, shield: dict | None = None, platform_pull: tuple | None = None) -> tuple[str, dict]:
    """Return (nginx config text, {relative_path: content}) for one site."""
    text, files, _, _ = _render_site(site, cfg, shield, platform_pull)
    return text, files


SPEED_MAX_BYTES = 10 * 1024 * 1024   # SPEC §15.6: /__pcdn/speed/down?bytes=N and the upload body, N <= 10 MB
SPEED_FILE_SIZE = SPEED_MAX_BYTES + 64   # random file the downloads are cut from (pcdn.js SPEED_FILE_SIZE)


def speed_file(cfg: dict) -> str:
    """Path of the speed-test random file (SPEED_FILE, default next to the state file)."""
    return cfg.get("SPEED_FILE") or os.path.join(os.path.dirname(cfg.get("STATE_FILE") or "/var/lib/pcdn/x"),
                                                 "speed.bin")


def ensure_speed_file(cfg: dict):
    """Create the speed-test file (SPEED_FILE_SIZE bytes of os.urandom, 0644) once. Outside the
    rendered tree (that is swapped on every apply) and never re-written while it has the right size.
    Fail-soft: without it the download endpoint answers 404, nothing else is affected."""
    path = speed_file(cfg)
    try:
        if os.path.isfile(path) and os.path.getsize(path) == SPEED_FILE_SIZE:
            return
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        with os.fdopen(fd, "wb") as f:
            left = SPEED_FILE_SIZE
            while left > 0:
                chunk = os.urandom(min(left, 1 << 20))
                f.write(chunk)
                left -= len(chunk)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except OSError as e:
        log.warning("speed-test file %s not written: %s", path, e)


def speed_locations(cfg: dict, njs_ok: bool, brotli_ok: bool, flv_ok: bool = True) -> list[str]:
    """Speed-test endpoints of every active site server (SPEC §15.6; diagnostics only). The page runs in
    the WHMCS client area, a DIFFERENT origin than the customer domain, so every response - also the
    400 / 405 / 413 / 429 ones (`always`) and the internal file location whose headers the browser
    sees for downloads - carries Access-Control-Allow-Origin: * (no credentials), exposes X-Pcdn-Node
    and allows Resource Timing. The app sends only simple requests (GET, POST text/plain, no custom
    headers), so there is no OPTIONS handler: a preflight gets 204 (ping), 400 (down) or 405 (up),
    never a 5xx. Extra query arguments (the app's cache-buster "_") are ignored. Per-IP rate limits (pcdn-base.conf zones pcdn_speed / pcdn_speedp),
    never cached or compressed, logged and counted as normal traffic. X-Pcdn-Node is a hash of the
    node name ($pcdn_node), never an address. The security verdict still runs at server level: firewall
    block rules / blocked_ips / default block apply, challenges and the WAF do not (pcdn.js).
    down?bytes=N: pcdn.speedDown validates N and internally redirects to the static random file
    through the flv module ("?start=" serves the file from an offset with a 13-byte FLV header, status
    200, exact Content-Length, sendfile: no per-request or per-worker memory); N < 64 comes from njs."""
    hdr = ("add_header Cache-Control \"no-store, no-transform\" always; add_header X-Pcdn-Node $pcdn_node always; "
           "add_header Access-Control-Allow-Origin * always; "
           "add_header Access-Control-Expose-Headers X-Pcdn-Node always; add_header Timing-Allow-Origin * always;")
    nz = "gzip off;" + (" brotli off;" if brotli_ok else "")
    lim = "limit_req zone=pcdn_speed burst=12 nodelay; limit_req_status 429;"
    out = ["    location = /__pcdn/speed/ping { limit_req zone=pcdn_speedp burst=20 nodelay; limit_req_status 429; "
           f"{hdr} return 204; }}"]
    if njs_ok:
        if flv_ok:   # an nginx built without --with-http_flv_module has no download endpoint (404)
            path = speed_file(cfg)
            if not SAFE_FSPATH.match(path):
                raise ValueError("unsafe SPEED_FILE")
            out += [f"    location = /__pcdn/speed/down {{ {lim} {nz} {hdr} js_content pcdn.speedDown; }}",
                    f"    location = /__pcdn/speed/file {{ internal; flv; max_ranges 0; etag off; {nz} "
                    f"default_type application/octet-stream; {hdr} alias {path}; }}"]
        out.append(f"    location = /__pcdn/speed/up {{ {lim} client_max_body_size {SPEED_MAX_BYTES}; "
                   f"client_body_buffer_size 64k; {hdr} js_content pcdn.speedUp; }}")
    return out


def _render_site(site: dict, cfg: dict, shield: dict | None = None,
                 platform_pull: tuple | None = None) -> tuple[str, dict, dict | None, dict]:
    """-> (config text, extra files, sites.js entry or None, meta). platform_pull: the node's
    (cert, key) platform client certificate for authenticated origin pulls (SPEC §14.2), or None."""
    sid = int(site["id"])
    domain = site["domain"]
    files = {}
    zone = f"pcdn_{sid}"
    cache_path = os.path.join(cfg["CACHE_DIR"], str(sid))
    out = [f"# {domain} (site {sid}) — generated by pcdn-agent, do not edit"]
    out.append(
        f"proxy_cache_path {cache_path} levels=1:2 keys_zone={zone}:{cfg['CACHE_KEYS_ZONE']} "
        f"max_size={cfg['CACHE_MAX_SIZE']} inactive={cfg['CACHE_INACTIVE']} use_temp_path=off;"
    )
    rps = int(site.get("rate_limit_rps") or 0)
    if rps > 0:
        # F40: key on $pcdn_rl_key (client IP for normal requests, "" for tunnel locations) so the
        # legacy per-IP limit never touches tunnel streams. New zone name (…rlk) because nginx
        # rejects a reload that changes an existing zone's key.
        out.append(f"limit_req_zone $pcdn_rl_key zone=pcdn_rlk_{sid}:1m rate={rps}r/s;")

    ssl = site.get("ssl")
    if ssl:
        files[f"certs/{sid}.crt"] = ssl["cert"]
        files[f"certs/{sid}.key"] = ssl["key"]

    status = site.get("status", "active")
    # F35: tunnel path prefixes the controller keeps sending while a site is suspended / over_quota,
    # so those paths answer a cheap rate-limited 503 instead of a full HTML page on every reconnect.
    cut_paths = []
    if status in ("suspended", "over_quota"):
        seen_cut = set()
        for cp in _sec(site, "tunnel").get("cut_paths") or []:
            cp = str(cp)
            if SAFE_TUNNEL_PATH.match(cp) and not cp.startswith("/__pcdn") and cp not in seen_cut:
                seen_cut.add(cp)
                cut_paths.append(cp)
    cache, sslo = _legacy_sections(site)
    pools = guard_pools(norm_pools(site), cfg, sid)
    origin_proto = "https" if sslo.get("origin_protocol") == "https" else "http"
    cache_on = bool(cache.get("enabled"))
    level = "aggressive" if cache.get("level") == "aggressive" else "standard"
    edge_ttl = _int(cache.get("edge_ttl"), 86400, 0, 31536000)
    browser_ttl = _int(cache.get("browser_ttl"), 0, 0, 31536000)
    ignore_q = bool(cache.get("ignore_query"))
    always_online = cache.get("always_online", True) is not False
    port, sport = _int(cfg["HTTP_PORT"], 80, 1, 65535), _int(cfg["HTTPS_PORT"], 443, 1, 65535)
    v6 = _v6(cfg)
    caps = nginx_capabilities(cfg)
    njs_ok, brotli_ok = "njs" in caps["modules"], "brotli" in caps["modules"]
    # SPEC §14.1 stale content: stale_while_revalidate -> "updating" + background update;
    # stale_if_error > 0 (and always_online) -> serve stale on error/timeout/5xx. nginx cannot bound
    # the stale age per request; entries live until `inactive` (CACHE_INACTIVE, 7d >= the 604800 s
    # maximum). Origin Cache-Control stale-* extensions keep working natively where Cache-Control is
    # honoured. Missing fields keep today's behaviour.
    swr = cache.get("stale_while_revalidate", True) is not False
    sie = cache.get("stale_if_error")
    stale_err = always_online and (sie is None or _int(sie, 86400, 0, 604800) > 0)
    # SPEC §14.1 HTTP/3: only on capable nodes, for HTTPS sites whose ssl.http3 is not off
    h3_flag = sslo.get("http3")
    if h3_flag is None and isinstance(site.get("ssl"), dict):
        h3_flag = site["ssl"].get("http3")
    h3 = bool(caps["http3"] and ssl and h3_flag is not False)
    alt_svc = f"add_header Alt-Svc 'h3=\":{sport}\"; ma=86400' always;"
    # SPEC §14.1 origin shield
    shield_self = bool(shield and shield.get("self"))
    shield_peers = [] if not shield or shield_self else list(shield.get("peers") or [])
    # only sites with a certificate: the hop (and the secret it carries) must be TLS. HTTP-only sites
    # always fetch from the origin directly and never send X-Pcdn-Shield.
    shielded = bool(shield_peers) and cache_on and cache.get("shield") is True and bool(ssl)

    # --- per-site maps (http context)
    cookies = [str(c) for c in (cache.get("bypass_cookies") or []) if SAFE_COOKIE.match(str(c))]
    nocache_var = None
    if cookies and cache_on:
        nocache_var = f"$pcdn_nocache_{sid}"
        alt = "|".join(re.escape(c) for c in cookies)
        out.append(f"map $http_cookie {nocache_var} {{\n    \"~(?:^|;)\\s*(?:{alt})[^=;]*=\" 1;\n    default \"\";\n}}")
    hsts = _sec(sslo, "hsts")
    hsts_var = None
    if ssl and hsts.get("enabled"):
        v = f"max-age={_int(hsts.get('max_age'), 31536000, 0, 63072000)}"
        v += "; includeSubDomains" if hsts.get("include_subdomains") else ""
        v += "; preload" if hsts.get("preload") else ""
        hsts_var = f"$pcdn_hsts_{sid}"
        out.append(f"map $scheme {hsts_var} {{\n    https \"{v}\";\n    default \"\";\n}}")

    # --- cache key (SPEC §14.1). Variant fields are appended after the URI as ";<field>=<value>":
    # no field value can contain ";" (device class, WebP flag, cookie values), so a key always
    # splits back into one URI + fixed fields and two different requests never share a key.
    # Without options the key text stays exactly "<scheme>://$host<uri>" as before.
    kopt = key_options(site)
    scheme_var = "$pcdn_scheme" if shield_self else "$scheme"

    def _kvar(kind, i, name):
        if NGX_VAR_NAME.match(name):
            return f"${{{kind}_{name}}}"
        var = f"pcdn_k{kind[0]}_{sid}_{i}"
        src, sep = ("$http_cookie", ";") if kind == "cookie" else ("$args", "&")
        lead = "(?:^|;)\\s*" if kind == "cookie" else "(?:^|&)"
        out.append(f"map {src} ${var} {{\n    default \"\";\n    \"~*{lead}{re.escape(name)}=([^{sep}]*)\" $1;\n}}")
        return f"${{{var}}}"
    key_cookies = [(n, _kvar("cookie", i, n)) for i, n in enumerate(kopt["cookies"])]
    key_args = [(n, _kvar("arg", i, n)) for i, n in enumerate(kopt["qa"])]
    webp_on = kopt["webp"]
    key_suffix = (("" if not kopt["dev"] else ";d=${pcdn_dev}")
                  + "".join(f";c.{n}={v}" for n, v in key_cookies)
                  + (";w=${pcdn_webp}" if webp_on else ""))

    imv2 = norm_image_v2(site)

    def cache_key(iq, image=False):
        """-> (key text, needs quoting)."""
        if image:
            # image.avif (SPEC §16.6): the output format depends on Accept, which pcdn.js folds into
            # $pcdn_img_h, so such sites always key on the normalised transform spec
            uri = ("$pcdn_path?w=$pcdn_img_w&h=$pcdn_img_h" if (iq or key_args or imv2["avif"])
                   else "$request_uri")
        elif iq:
            uri = "$pcdn_path"
        elif key_args:   # cache.key_query_allow: only these parameters, in a fixed order
            uri = "$pcdn_path?" + "&".join(f"{n}={v}" for n, v in key_args)
        else:
            uri = "$request_uri"
        key = f"{scheme_var}://$host{uri}{key_suffix}"
        return key, bool(key_suffix or (key_args and not iq and not image))

    # --- preload page rules (SPEC §14.1): the first rule with `preload` matching the URI adds its
    # Link headers on every proxied location (the same first-match-per-feature model as WAF rules)
    link_rules = [(r["_re"], ", ".join(lk)) for r in page_rules(site) if (lk := preload_links(r))]
    link_var = f"$pcdn_link_{sid}" if link_rules else None
    if link_var:
        out.append(f"map $uri {link_var} {{\n    default \"\";\n"
                   + "".join(f"    \"~{rx}\" {_qv(v)};\n" for rx, v in link_rules) + "}")
    # nginx relays 103 responses it receives from the origin but cannot originate one; on
    # early_hints-capable nodes those are passed to HTTP/2+ navigations of preload-rule sites
    eh_on = bool(link_var and caps["early_hints"])

    # --- header rules
    hdr = _sec(site, "headers")
    req_headers = {}
    for h in hdr.get("request") or []:
        n, v = str(h.get("name") or ""), h.get("value")
        if SAFE_HEADER.match(n) and n.lower() not in HOP_HEADERS and v is not None and SAFE_VALUE.match(str(v)):
            req_headers[n.lower()] = (n, _qv(str(v)))
    resp_add, resp_hide = [], []
    resp_static = {}   # lower name -> (name, value | None): the last headers.response entry
    for h in hdr.get("response") or []:
        n, v = str(h.get("name") or ""), h.get("value")
        if not SAFE_HEADER.match(n) or n.lower() in HOP_HEADERS:
            continue
        if v is None:
            resp_hide.append(n)
            resp_static[n.lower()] = (n, None)
        elif SAFE_VALUE.match(str(v)):
            resp_hide.append(n)  # replace the origin's value instead of sending both
            resp_add.append((n, f"add_header {n} {_qv(str(v))} always;"))
            resp_static[n.lower()] = (n, str(v))

    # --- transform rules (SPEC §14.2), web locations only (tunnel paths keep today's headers).
    # Conditions (methods / countries / path pattern) become one flag map per rule over
    # "$request_method|$pcdn_country|$pcdn_shield_ok|$pcdn_ouri" ($pcdn_ouri = the request's $uri
    # pinned at server level, before any internal rewrite; (?s): a "*" also spans a decoded
    # newline). A valid shield hop never matches, so a shield does not transform again what the
    # visitor-facing edge already did. Rules run in order; a later matching rule wins for a header.
    #  * request headers: proxy_set_header with a chain of maps (flag 1 -> this rule's value, "" for a
    #    removal; otherwise the previous value, at the bottom the visitor's own $http_<name>);
    #  * response headers: unconditional -> proxy_hide_header + add_header; conditional -> the njs
    #    header filter pcdn.tfHeaders (exact set / delete of every value, also multi-value Set-Cookie,
    #    which a "$upstream_http_<name>" pass-through would join into one broken line);
    #  * rewrite_path: the regex runs on the RAW request path ($pcdn_path, percent-encoded, so a
    #    capture can never put a decoded CR/LF into the request line) and the result is passed as the
    #    URI of proxy_pass; the cache key stays on the visitor's original URI.
    active = status not in ("suspended", "over_quota")
    tf_rules = norm_transform(site) if active else []
    tf_flag, tf_req, tf_resp, tf_hide, tf_add, tf_done, rewrites = {}, {}, [], [], [], set(), []
    req_ops, resp_ops = {}, {}
    for i, rule in enumerate(tf_rules):
        c = rule["cond"]
        if c is not None:
            meth = "(?:" + "|".join(c["methods"]) + ")" if c["methods"] else "[^|]*"
            ccs = "(?:" + "|".join(c["countries"]) + ")" if c["countries"] else "[^|]*"
            path = c["path_re"][1:] if c["path_re"] else ".*"
            tf_flag[i] = f"pcdn_tf_{sid}_{i}"
            out.append(f'map "$request_method|$pcdn_country|$pcdn_shield_ok|$pcdn_ouri" ${tf_flag[i]} {{\n'
                       f"    {_qre('~(?s)^' + meth + '[|]' + ccs + '[|]0[|]' + path)} 1;\n    default 0;\n}}")
        f = tf_flag.get(i)
        for a in rule["actions"]:
            t = a["type"]
            if t == "rewrite_path":
                rewrites.append((f, a))
            elif t.endswith("_request_header"):
                req_ops.setdefault(a["name"].lower(), []).append(
                    (f, _qv(a["value"]) if t.startswith("set_") else '""', a["name"]))
            else:
                resp_ops.setdefault(a["name"].lower(), []).append(
                    (f, "set" if t.startswith("set_") else "del", a.get("value"), a["name"]))
    for low, ops in resp_ops.items():
        name, base = ops[0][3], resp_static.get(low)
        if all(o[0] is None for o in ops):
            state = ops[-1][1:3]
            tf_hide.append(name)
            if state[0] == "set":
                tf_add.append(f"add_header {name} {_qv(state[1])} always;")
            tf_done.add(low)
        elif njs_ok:
            if base:
                tf_resp.append({"f": "", "op": "set", "n": name, "v": base[1]} if base[1] is not None
                               else {"f": "", "op": "del", "n": name})
            for f, op, v, _ in ops:
                tf_resp.append({"f": f or "", "op": op, "n": name, "v": v} if op == "set"
                               else {"f": f or "", "op": op, "n": name})
            tf_done.add(low)
        else:
            log.warning("site %s: conditional response-header transforms need njs; skipped for %s", sid, name)
    if tf_done:   # these names are handled by the transform rules (their headers.response entry is the base)
        resp_hide = [n for n in resp_hide if n.lower() not in tf_done]
        resp_add = [x for x in resp_add if x[0].lower() not in tf_done]
    resp_add = [line for _, line in resp_add] + tf_add
    if shield_self:
        # a shield keeps the visitor's address / scheme / country forwarded by a valid shield hop
        base_req = [("Host", "$host"), ("X-Real-IP", "$pcdn_client_ip"), ("X-Forwarded-For", "$pcdn_xff"),
                    ("X-Forwarded-Proto", "$pcdn_scheme"), ("X-Country-Code", "$pcdn_cc")]
    else:
        base_req = [("Host", "$host"), ("X-Real-IP", "$remote_addr"), ("X-Forwarded-For", "$proxy_add_x_forwarded_for"),
                    ("X-Forwarded-Proto", "$scheme"), ("X-Country-Code", "$pcdn_country")]
    # never forwarded to an origin, also on a node that is no longer a shield while edges still
    # send it hops (config propagation lag)
    base_req.append(("X-Pcdn-Shield", '""'))
    # the edge's internal resizer headers never reach an origin either: an origin that is (or resolves
    # to) the loopback resizer must not get a visitor-chosen fetch URL or client-certificate token
    base_req += [("X-Pcdn-Origin", '""'), ("X-Pcdn-Mtls", '""')]

    # transform request headers: start from the static headers.request value (or the edge's own
    # value for a base header, or the visitor's header) and apply the rules in order
    base_vals = {n.lower(): v for n, v in base_req}
    for k, (low, ops) in enumerate(req_ops.items()):
        cur = req_headers[low][1] if low in req_headers else base_vals.get(low) or _hvar(ops[0][2])
        for j, (f, expr, _) in enumerate(ops):
            if f is None:
                cur = expr
            else:
                var = f"pcdn_tq_{sid}_{k}_{j}"
                out.append(f"map ${f} ${var} {{\n    1 {expr};\n    default {cur};\n}}")
                cur = "$" + var
        tf_req[low] = (ops[0][2], cur)

    def req_hdrs(directive, conn=(("Upgrade", "$http_upgrade"), ("Connection", "$pcdn_connection_upgrade")), tf=False):
        over = tf_req if tf else {}
        pairs = ([(n, v) for n, v in base_req if n.lower() not in req_headers and n.lower() not in over]
                 + [hv for low, hv in req_headers.items() if low not in over] + list(over.values()) + list(conn))
        return [f"{directive} {n} {v};" for n, v in pairs]

    # nginx drops inherited proxy_set_header / add_header / proxy_hide_header as soon as
    # a location sets one of them, so every proxying location gets the complete set.
    proxy_hdrs = req_hdrs("proxy_set_header", tf=True)

    # rewrite_path: per rule, $pcdn_tfu_* is the rewritten URI when the rule's condition holds
    # ($pcdn_tfr_*: its regex on the raw path) and otherwise the next rule's, so the first rule whose
    # condition and regex both match wins ("" = none: proxy_pass keeps the request URI). Unconditional
    # rules are skipped on a valid shield hop too (the edge already sent the rewritten path).
    tf_uri = ""
    if rewrites:
        nxt = '""'
        for j, (f, a) in reversed(list(enumerate(rewrites))):
            rep = a["replacement"] + ("$pcdn_args_amp" if "?" in a["replacement"] else "$is_args$args")
            # the customer regex never runs on an over-long path ($pcdn_rxlong, security review H2)
            out.append(f"map $pcdn_rxlong $pcdn_tfr_{sid}_{j} {{\n    1 {nxt};\n    default $pcdn_tfx_{sid}_{j};\n}}")
            out.append(f"map $pcdn_path $pcdn_tfx_{sid}_{j} {{\n    default {nxt};\n"
                       f"    {_qre('~' + a['regex'])} \"{rep}\";\n}}")
            src, hit = (f"${f}", "1") if f else ("$pcdn_shield_ok", "0")
            out.append(f"map {src} $pcdn_tfu_{sid}_{j} {{\n    {hit} $pcdn_tfr_{sid}_{j};\n    default {nxt};\n}}")
            nxt = f"$pcdn_tfu_{sid}_{j}"
        tf_uri = nxt

    # --- SPEC §16.8 object-storage origins (records only): per host index the validated origin.
    # The bucket's read token (Referer) lives in storage/<sid>.conf (0600, root-only like the shield
    # secret), never in this 0644 file; $pcdn_sm_<sid> is "" for GET/HEAD and the Allow value for any
    # other method (405); $pcdn_sbad_<sid> refuses paths that a storage server would normalise
    # out of the bucket (dot segments, encoded slashes / backslashes) or that are not origin-form.
    stor_of = {}
    for hi, h in enumerate(site.get("hosts") or []):
        if isinstance(h, dict) and isinstance(h.get("origin"), dict) and "storage" in h["origin"]:
            st = norm_storage_origin(h["origin"])
            if st and not origin_host_allowed(st["host"], cfg):
                log.warning("site %s: storage origin %s skipped: not a public address (ORIGIN_PRIVATE_ALLOW)",
                            sid, st["host"])
                st = None
            if st:
                stor_of[hi] = dict(st, var=f"$pcdn_sref_{sid}_{len(stor_of)}")
    stor_path = stor_bad = stor_badp = None
    if stor_of and active:
        files[f"storage/{sid}.conf"] = (
            f"# {domain} (site {sid}) object-storage read tokens (SPEC §16.8) — generated by pcdn-agent\n"
            + "".join(f"map $uri {st['var']} {{\n    default {_q(st['referer'])};\n}}\n" for st in stor_of.values()))
        out.append(f"include {cfg['NGINX_DIR'].rstrip('/')}/storage/{sid}.conf;")
        out.append(f'map $request_method $pcdn_sm_{sid} {{\n    GET "";\n    HEAD "";\n    default "GET, HEAD";\n}}')
        bad_re = '"~*(?:^[^/]|/(?:[.]|%2e){1,2}(?:/|$)|%2f|%5c|\\x5c|%00)"'
        # the path sent to the bucket: the visitor's raw path, or a rewrite_path result without its query
        stor_path = "$pcdn_path"
        if tf_uri:
            out.append(f'map {tf_uri} $pcdn_sp_{sid} {{\n    "~^(/[^?]*)" $1;\n    default $pcdn_path;\n}}')
            stor_path = f"$pcdn_sp_{sid}"
        stor_bad, stor_badp = f"$pcdn_sbad_{sid}", f"$pcdn_sbad_{sid}"
        out.append(f"map {stor_path} {stor_bad} {{\n    default \"\";\n    {bad_re} 1;\n}}")
        if tf_uri:   # servers that never apply rewrite_path (resizer origin, functions fetch)
            stor_badp = f"$pcdn_sbadp_{sid}"
            out.append(f"map $pcdn_path {stor_badp} {{\n    default \"\";\n    {bad_re} 1;\n}}")
    sport_sto = _int(cfg.get("STORAGE_FETCH_PORT"), 8091, 1, 65535)
    stor_now = {}   # the storage origin of the host being rendered ({} = an ordinary origin)

    def stor_hdrs(st, cond=False):
        """Request headers towards a storage origin: nothing of the visitor's request but Accept /
        Accept-Encoding (no Authorization, Cookie, X-Amz-*, X-Pcdn-*, header rules), Host =
        host_header and the bucket's Referer token. cond: also the visitor's Range / conditional
        headers (uncached locations only: in a cached one they would store partial content)."""
        L = ["proxy_pass_request_headers off;", "proxy_pass_request_body off;",
             f"proxy_set_header Host {_q(st['host_header'])};", f"proxy_set_header Referer {st['var']};",
             'proxy_set_header Content-Length "";', "proxy_set_header Accept $http_accept;",
             "proxy_set_header Accept-Encoding $http_accept_encoding;"]
        if cond:
            L += [f"proxy_set_header {n} $http_{n.lower().replace('-', '_')};"
                  for n in ("Range", "If-Range", "If-None-Match", "If-Modified-Since", "If-Match", "If-Unmodified-Since")]
        return L

    def stor_guard(bad):
        return [f"if ($pcdn_sm_{sid}) {{ return 405; }}", f"if ({bad}) {{ return 400; }}"]

    def origin_pass(uri=""):
        """proxy_pass to the current host's origin; a storage origin always gets path_prefix + the
        path (never the query string)."""
        if stor_now:
            return f"proxy_pass $pcdn_proto://$pcdn_target{stor_now['prefix']}{stor_path};"
        return f"proxy_pass $pcdn_proto://$pcdn_target{uri};"

    mtls_now = []   # proxy_ssl_certificate lines of the host being rendered (origin-bound HTTPS only)

    def loc_common(hides=(), extra_add=(), hdrs=None, guard=True, cached=True):
        """guard: an origin-bound location (storage origins: GET/HEAD only, safe paths). cached:
        the location caches (storage origins then get no Range / conditional headers)."""
        if stor_now:
            lines = (stor_guard(stor_bad) if guard else []) + list(
                stor_hdrs(stor_now, not cached) if hdrs is None else hdrs)
            if guard:
                extra_add = [f"add_header Allow $pcdn_sm_{sid} always;"] + list(extra_add)
        else:
            lines = list(proxy_hdrs if hdrs is None else hdrs)
        for n in dict.fromkeys(list(hides) + resp_hide + tf_hide):
            lines.append(f"proxy_hide_header {n};")
        lines += list(extra_add)
        lines.append("add_header X-Served-By $hostname always;")
        if hsts_var:
            lines.append(f"add_header Strict-Transport-Security {hsts_var} always;")
        if h3:
            lines.append(alt_svc)
        if link_var:
            lines.append(f"add_header Link {link_var};")
        if webp_on:
            lines.append("add_header Vary $pcdn_webp_vary;")
        if eh_on:
            lines.append("early_hints $pcdn_early_hints;")
        if tf_resp:
            lines.append("js_header_filter pcdn.tfHeaders;")
        return lines + resp_add

    def ind(lines):
        return ["        " + x for x in lines]

    named = [0]

    def proxy_loc(match, mode, ttl, bttl, iq, uri=""):
        """mode: bypass | dynamic (honour origin; ttl>0 = default TTL) | aggressive | everything | static.
        uri: explicit URI variable for proxy_pass (default: the rewrite_path result, "" = unchanged)."""
        L, hides, adds = [], [], []
        cacheable = mode != "bypass" and cache_on
        key = None
        if not cacheable:
            adds.append("add_header X-Cache BYPASS always;")
        else:
            key, quote = cache_key(iq)
            L += [f"proxy_cache {zone};", "proxy_cache_key " + (f'"{key}"' if quote else key) + ";"]
            no_cache = []
            if mode == "static":
                L += [f"proxy_cache_valid 200 206 301 {max(ttl, 60)}s;", "proxy_cache_valid 404 1m;",
                      "proxy_ignore_headers Cache-Control Expires Set-Cookie Vary;"]
                hides.append("Set-Cookie")
            elif mode in ("aggressive", "everything"):
                # cache regardless of Cache-Control, but never store a response that sets
                # cookies (it would hand one visitor's session to everybody)
                L += [f"proxy_cache_valid 200 206 301 {max(ttl, 60)}s;",
                      "proxy_ignore_headers Cache-Control Expires Vary X-Accel-Expires;"]
                no_cache.append("$upstream_http_set_cookie")
            elif ttl > 0:  # dynamic with an explicit edge TTL (page rule): used when the origin sends none
                L.append(f"proxy_cache_valid 200 301 {max(ttl, 60)}s;")
            if nocache_var and mode != "static":
                L.append(f"proxy_cache_bypass {nocache_var};")
                no_cache.insert(0, nocache_var)
            if no_cache:
                L.append("proxy_no_cache " + " ".join(no_cache) + ";")
            stale = ((["error", "timeout"] if stale_err else []) + (["updating"] if swr else [])
                     + (["http_500", "http_502", "http_503", "http_504"] if stale_err else []))
            L += [f"proxy_cache_use_stale {' '.join(stale) or 'off'};", "proxy_cache_lock on;"]
            if swr:
                L.append("proxy_cache_background_update on;")
            adds.append("add_header X-Cache $upstream_cache_status always;")
        if bttl > 0:
            hides += ["Cache-Control", "Expires"]
            adds.append(f"add_header Cache-Control \"public, max-age={bttl}\" always;")
        origin = loc_common(hides, adds, cached=cacheable) + L + mtls_now + [origin_pass(uri or tf_uri)]
        if not (shielded and cacheable):
            return [f"    location {match} {{"] + ind(origin) + ["    }"]
        # SPEC §14.1 origin shield: GET/HEAD cache misses go to the shield peers (consistent hash on
        # the cache key); any other method, and every request once all shields are unreachable
        # (nginx-generated 502/504), is re-run in a named location that fetches from the origin.
        # proxy_intercept_errors stays off so a shield's own answer (also an error page) is passed
        # as is and never replayed against the origin.
        named[0] += 1
        fb = f"@pcdn_origin_{named[0]}"
        sh_hdrs = [x if not x.startswith("proxy_set_header X-Pcdn-Shield ")
                   else "proxy_set_header X-Pcdn-Shield $pcdn_shield_secret;" for x in proxy_hdrs]
        # headers the shield adds itself; this edge adds its own copies
        sh_hides = hides + ["X-Cache", "X-Served-By"] + (["Strict-Transport-Security"] if hsts_var else []) \
            + (["Alt-Svc"] if h3 else [])
        S = ["if ($pcdn_sh_skip) { return 418; }", f"set $pcdn_ck \"{key}\";"]
        S += loc_common(sh_hides, adds, sh_hdrs) + L
        for cls, codes in err_pages.items():
            rest = " ".join(c for c in codes.split() if c not in ("502", "504"))
            if rest:
                S.append(f"error_page {rest} /__pcdn/err/{cls}.html;")
        S += [f"error_page 418 502 504 = {fb};", "proxy_intercept_errors off;",
              f"proxy_connect_timeout {min(5, _int(cfg.get('TUNNEL_CONNECT_TIMEOUT'), 10, 3, 30))}s;",
              f"proxy_next_upstream_tries {len(shield_peers)};"]
        # always TLS, verified against $host (the shield serves the site's certificate). The upstream
        # is shared by every shielded site, so a TLS session saved for one site must not be resumed
        # for another (a resumed session keeps the first site's certificate, the name check fails and
        # the hop silently falls back to the origin); idle keepalive connections are still reused.
        S += ["proxy_ssl_server_name on;", "proxy_ssl_name $host;", "proxy_ssl_verify on;",
              f"proxy_ssl_trusted_certificate {cfg['CA_BUNDLE']};", "proxy_ssl_verify_depth 4;",
              "proxy_ssl_session_reuse off;", f"proxy_pass https://pcdn_shield_https{tf_uri};"]
        return ([f"    location {match} {{"] + ind(S) + ["    }"]
                + [f"    location {fb} {{"] + ind(origin) + ["    }"])

    # --- custom error pages (files next to the config, served from an internal location)
    ep = _sec(site, "errorpages")
    err_pages = {}
    for cls, codes in (("5xx", "500 502 503 504"), ("4xx", "400 403 404 405 410")):
        body = ep.get(cls)
        if isinstance(body, str) and body.strip() and len(body.encode()) <= 65536:
            files[f"errors/{sid}-{cls}.html"] = body
            err_pages[cls] = codes

    # the resizer needs the image_filter module and the njs imgW/imgH/imgQ parameters
    # (or, SPEC §16.6, the image transformer when this node has no image_filter module)
    image_on = (bool(_sec(site, "image").get("enabled")) and njs_ok
                and ("image_filter" in caps["modules"] or image_capabilities(cfg)["transform"]))
    resize_port = _int(cfg["RESIZE_PORT"], 8089, 1, 65535)
    prules = page_rules(site)
    valid_hosts = []

    # --- tunnel mode (SPEC §7): per-site http-context parts
    tunnel = guard_tunnel(norm_tunnel(site, pools), cfg, sid)
    fallback = tunnel["fallback"] if tunnel else "origin"
    image_on = image_on and fallback == "origin"  # decoy / 404 sites never fetch origin content
    webp_on = webp_on and fallback == "origin"
    decoy = decoy_page(cfg, domain) if fallback == "decoy" else None
    # SPEC §16.5 video delivery: cached sites serving origin content only
    video = norm_video(site) if (active and cache_on and fallback == "origin") else None
    vslice = bool(video and caps.get("slice"))
    # prefetch needs njs ($pcdn_vnext) and is skipped when rewrite_path rules could map the next
    # segment's URI elsewhere than the prefetch would fetch
    vprefetch = bool(video and video["prefetch"] and njs_ok and not rewrites)
    geo_ok = geoip_present(cfg)
    ka = _int(cfg.get("TUNNEL_KEEPALIVE"), 64, 1, 4096)
    h2_buf = cfg.get("TUNNEL_H2_BODY_BUFFER") if SAFE_SIZE.match(cfg.get("TUNNEL_H2_BODY_BUFFER") or "") else "256k"
    relay_buf = cfg.get("TUNNEL_RELAY_BUFFER") if SAFE_SIZE.match(cfg.get("TUNNEL_RELAY_BUFFER") or "") else "16k"
    resolver = cfg["RESOLVER"] if SAFE_RESOLVER.match(cfg.get("RESOLVER") or "") else "1.1.1.1"
    tn_upstreams = {}  # (h2?, host:port) -> upstream name (keepalive towards IP-literal origins)
    _up_rendered = set()
    if tunnel and tunnel["allowed_countries"]:
        # F9: only enforce the country gate when the GeoIP DB is installed; otherwise fail open.
        # `"" 1;` lets a client the DB cannot resolve pass instead of being 403'd.
        if geo_ok:
            out.append(f"map $pcdn_country $pcdn_tcc_{sid} {{\n    \"\" 1;\n"
                       + "".join(f"    {cc} 1;\n" for cc in tunnel["allowed_countries"]) + "    default 0;\n}")
        else:
            log.warning("no GeoIP DB / geoip2 module on this edge; tunnel allowed_countries fails open for site %s",
                        sid)
    # F34: a force_https site with tunnel paths must not 301 its ws/httpupgrade/xhttp clients on
    # port 80 (they cannot follow a redirect). Map the tunnel prefixes to 1 and skip the redirect
    # for them; non-tunnel sites keep the plain one-line redirect.
    force_https_tn = bool(tunnel and tunnel["paths"] and sslo.get("force_https") and ssl)
    if force_https_tn:
        # nginx `if` compares a single variable (it cannot concatenate $scheme with the flag), so a
        # second map combines them: redirect only when scheme is http AND the path is not a tunnel path.
        alt = "|".join(re.escape(p["path"]) for p in tunnel["paths"])
        out.append(f"map $uri $pcdn_tnp_{sid} {{\n    volatile;\n    default 0;\n    \"~^(?:{alt})\" 1;\n}}")
        out.append(f"map \"$scheme$pcdn_tnp_{sid}\" $pcdn_httpredir_{sid} {{\n    volatile;\n"
                   f"    \"http0\" 1;\n    default 0;\n}}")

    # --- redirect rules (SPEC §14.2): server level, after the security verdict and force_https and
    # before the request-body check, image resizing, page rules, cache and origin
    tn_prefixes = [p["path"] for p in tunnel["paths"]] if tunnel else []
    rd_var, rd_codes = None, []
    if active:
        rd_maps, rd_var, rd_codes = redirect_maps(sid, norm_redirects(site, tn_prefixes), tn_prefixes)
        out += rd_maps

    # --- WAF packs (SPEC §14.2): xmlrpc.php / JSON request bodies are read and inspected by njs
    # (/__pcdn/body/ -> pcdn.bodyInspect) before they are proxied through @pcdn_body
    waf_sec = _sec(site, "waf")
    body_packs = {"wordpress", "api"} & set(p for p in (waf_sec.get("packs") if isinstance(waf_sec.get("packs"), list)
                                                        else []) if isinstance(p, str))
    # a learning site (SPEC §17.1) inspects bodies log-only even when its WAF mode is off
    body_on = bool(active and njs_ok and fallback == "origin" and body_packs
                   and (waf_sec.get("mode") in ("detect", "block") or norm_waf_learning(site) is not None))

    # --- authenticated origin pulls (SPEC §14.2): client certificate on origin-bound HTTPS hops only
    # (never on the edge -> shield hop, which carries the shield's own TLS; the shield itself presents
    # it to the origin). Origins over plain HTTP get nothing.
    oc = origin_client(sslo) if active else {"mode": "off"}
    mtls_id, mtls_pair, mtls_used = None, None, False
    if oc["mode"] == "platform":
        if platform_pull:
            mtls_id, mtls_pair = "platform", platform_pull
        else:
            log.warning("site %s: origin_client platform but no origin_pull certificate in the config", sid)
    elif oc["mode"] == "custom":
        mtls_id, mtls_pair = str(sid), (oc["cert"], oc["key"])
    mtls_lines = [f"proxy_ssl_certificate {cfg['NGINX_DIR']}/mtls/{mtls_id}.crt;",
                  f"proxy_ssl_certificate_key {cfg['NGINX_DIR']}/mtls/{mtls_id}.key;"] if mtls_id else []
    meta = {"mtls_resizer": None}

    # --- edge functions (SPEC §16.9): customer JS runs in pcdn-fn, never here. Each enabled function
    # becomes `location ^~ <route>` proxied over FN_SOCKET; pcdn-fn answers with the function's
    # response or an X-Accel-Redirect to @pcdn_fn_pass (continue to the origin) / the on_error target
    # (@pcdn_fn_pass for "origin", @pcdn_fn_err -> 502 for "502"). A node without pcdn-fn renders a
    # plain 502 for fail-closed ("502") functions and nothing for "origin" ones.
    fns = norm_functions(site, tn_prefixes) if (active and fallback == "origin") else []
    fn_live = bool(fns) and functions_enabled(cfg)
    fn_root = any(f["route"] == "/" for f in fns if fn_live or f["on_error"] == "502")
    if fns and not fn_live:
        log.warning("site %s has edge functions but this node has no pcdn-fn (install.sh --functions)", sid)
    fn_sock = cfg.get("FN_SOCKET") or "/run/pcdn-fn/fn.sock"
    fn_fetch_sock = cfg.get("FN_FETCH_SOCKET") or "/run/pcdn-fnfetch/fetch.sock"
    if fn_live and not (SAFE_FSPATH.match(fn_sock) and SAFE_FSPATH.match(fn_fetch_sock)):
        raise ValueError("unsafe FN_SOCKET / FN_FETCH_SOCKET")
    fn_bodychk, fn_imgw = "$pcdn_bodychk", "$pcdn_img_w"
    if fn_live:
        # function routes are never rewritten into the WAF body inspector or the image resizer
        # (both would proxy the request to the origin and bypass the function)
        alt = "|".join(f["route"].replace(".", "\\.") for f in fns)
        out.append(f'map $uri $pcdn_fnr_{sid} {{\n    default 0;\n    "~^(?:{alt})" 1;\n}}')
        out.append(f'map $pcdn_fnr_{sid} $pcdn_fnbc_{sid} {{\n    1 "";\n    default $pcdn_bodychk;\n}}')
        out.append(f'map $pcdn_fnr_{sid} $pcdn_fniw_{sid} {{\n    1 "";\n    default $pcdn_img_w;\n}}')
        fn_bodychk, fn_imgw = f"$pcdn_fnbc_{sid}", f"$pcdn_fniw_{sid}"
    fn_wall = _int(cfg.get("FN_WALL_MS"), 5000, 100, 60000)
    # @pcdn_body proxies the visitor's original URI (or its rewrite_path result) explicitly: the
    # request URI there is the internal /__pcdn/body/... one
    body_uri = "$request_uri"
    if body_on and tf_uri:
        out.append(f'map {tf_uri} $pcdn_bu_{sid} {{\n    "~." {tf_uri};\n    default $request_uri;\n}}')
        body_uri = f"$pcdn_bu_{sid}"

    def _upstream_block(name, hp, h2):
        # one server: never marked down (max_fails=0). A warm pool of idle keepalive connections to
        # the VPN origin removes the TCP+TLS handshake across the border from the next stream;
        # keepalive_requests/keepalive_time keep long VPN sessions from recycling a connection mid-use.
        # Separate names per (h2, hp): a cached keepalive connection must never cross protocols.
        if name not in _up_rendered:
            _up_rendered.add(name)
            out.append(f"upstream {name} {{\n    server {hp} max_fails=0;\n    keepalive {ka};\n"
                       f"    keepalive_timeout 300s;\n    keepalive_requests 1000000;\n"
                       f"    keepalive_time 1h;\n}}")
        return name

    def tn_upstream(hp, h2):
        if (h2, hp) not in tn_upstreams:
            tn_upstreams[(h2, hp)] = _upstream_block(f"pcdn_tn_{sid}_{len(tn_upstreams)}", hp, h2)
        return tn_upstreams[(h2, hp)]

    # F1/F11: give IP-literal pool members keepalive upstreams and session affinity. For every pool
    # of this tunnel site, render (deterministically named, separate from tn_upstream's counter) a
    # keepalive upstream per IP-literal member for each keepalive-capable protocol the tunnel uses,
    # and record the names on the pool origins so tunnelUpstream() in njs returns the upstream name
    # for the member it picks. Hostname members keep the request-time resolver path.
    pool_names = sorted(pools)
    if tunnel:
        kinds = {p["protocol"] for p in tunnel["paths"]}
        need_h2 = bool(kinds & {"grpc", "h2"})
        need_h1 = "xhttp" in kinds
        for pi, pname in enumerate(pool_names):
            for oi, o in enumerate(pools[pname]["origins"]):
                if not IP_LITERAL.match(o["hp"].rsplit(":", 1)[0]):
                    o["up"] = None
                    continue
                up = {"h1": None, "h2": None}
                base = f"pcdn_tn_{sid}_p{pi}_{oi}"
                if need_h2:
                    up["h2"] = _upstream_block(base + "_h2", o["hp"], True)
                if need_h1:
                    up["h1"] = _upstream_block(base, o["hp"], False)
                o["up"] = up if (up["h1"] or up["h2"]) else None

    def tunnel_loc(p, proto, pool, target):
        """One `location ^~ <path>` for a tunnel path; host defaults: proto / pool / target."""
        kind, idle = p["protocol"], tunnel["idle_timeout"]
        grpc = kind in ("grpc", "h2")
        keepalive_ok = kind in ("xhttp", "grpc", "h2")  # upgraded (ws) connections are never reused
        h2buf = kind in ("grpc", "h2", "xhttp")          # HTTP/2 body path (F3)
        resolved = False   # dest resolved at request time via the nginx resolver
        L = [f"set $pcdn_tn {kind};", f"set $pcdn_tp {p['id']};"]   # SPEC §15.1 access-log "tp"
        # F13: count only the session-opening request against limit_conn. ws/grpc/h2 sessions and
        # streams each open one; xhttp counts only the downlink GET ($pcdn_tn_isget), so packet-up
        # POSTs do not consume a slot and the limit refuses new sessions instead of tearing down old.
        L.append("set $pcdn_tn_ckey " + ("$pcdn_tn_isget;" if kind == "xhttp" else "$pcdn_site;"))
        if tunnel["allowed_countries"] and geo_ok:  # F9: no gate at all without a GeoIP DB
            L.append(f"if ($pcdn_tcc_{sid} = 0) {{ return 403; }}")
        if kind in ("ws", "httpupgrade"):
            # SPEC §15.1 "protocol": a ws/httpupgrade path without an Upgrade header (a browser, a
            # probe, an HTTP/2 client - nginx cannot carry WebSocket over HTTP/2) is answered by the
            # edge with 426 instead of being passed to the origin, so the wrong-protocol case is
            # visible in the access log. Real ws/httpupgrade clients always send Upgrade.
            L.append('if ($http_upgrade = "") { return 426; }')
        if njs_ok:
            # SPEC §15.2 fair share: "1" only while the node is hot and this site holds more than its
            # share of the node's NEW tunnel sessions (pcdn.js tunnelFair); refuses only a new session
            # (never an established one; xhttp packet POSTs are never refused), 429 like limit_conn.
            L.append("if ($pcdn_tn_fair) { return 429; }")
        o = p["origin"]
        if o:
            tls, sni, verify = o["tls"], o["sni"] or "$host", o["verify"]
            if o["ip"] and keepalive_ok:
                dest = tn_upstream(o["hp"], grpc)
            else:
                L.append(f"set $pcdn_tn_target {_q(o['hp'])};")  # variable: resolved at request time
                dest, resolved = "$pcdn_tn_target", not o["ip"]
        elif p["pool"]:
            tls, sni, verify = pools[p["pool"]]["protocol"] == "https", "$host", bool(sslo.get("origin_verify"))
            # F1: prefix + pool set before $pcdn_tn_target so the js_set tunnelUpstream (lazy, cached
            # on first reference) sees them; xhttp/h2 then stick every request of a session to one
            # origin via a rendezvous hash on the session id parsed out of the path.
            L += [f"set $pcdn_tn_pool {_q(p['pool'])};", f"set $pcdn_tn_prefix {_q(p['path'])};",
                  "set $pcdn_tn_target $pcdn_tn_upstream;"]
            dest, resolved = "$pcdn_tn_target", True
        elif pool:
            # F1: a host that inherits a pool must route its tunnel paths through the tunnel picker
            # (affinity + keepalive), not the web balancer ($pcdn_target), which splits sessions.
            tls, sni, verify = pools[pool]["protocol"] == "https", "$host", bool(sslo.get("origin_verify"))
            L += [f"set $pcdn_tn_pool {_q(pool)};", f"set $pcdn_tn_prefix {_q(p['path'])};",
                  "set $pcdn_tn_target $pcdn_tn_upstream;"]
            dest, resolved = "$pcdn_tn_target", True
        else:
            tls, sni, verify = proto == "https", "$host", bool(sslo.get("origin_verify"))
            host_addr = (target or "").rsplit(":", 1)[0]
            if keepalive_ok and IP_LITERAL.match(host_addr):
                dest = tn_upstream(target, grpc)
            else:
                dest, resolved = "$pcdn_target", True
        # N4: IPv6-only tunnel origins are unreachable through the http-level ipv6=off resolver; on a
        # node that listens on IPv6 (has v6 egress), enable AAAA for the request-time-resolved path
        # only, leaving proxied web origins on the IPv4-only resolver.
        if resolved and v6:
            L.append(f"resolver {resolver} valid=300s;")
        if tunnel["max_connections"]:
            L.append(f"limit_conn pcdn_tn_site2 {tunnel['max_connections']};")
        if tunnel["max_connections_per_ip"]:
            L.append(f"limit_conn pcdn_tn_ip2 {tunnel['max_connections_per_ip']};")
        L.append("limit_conn_status 429;")
        # F40: the legacy per-IP limit_req is skipped on tunnel paths via the empty $pcdn_rl_key
        # (see pcdn-base.conf); no limit_req_dry_run needed and no shared-memory lock is taken.
        # tunnel.per_connection_mbps is not rendered: nginx 1.24 resets limit_rate to 0 for
        # unbuffered proxying (proxy_buffering off, every grpc_pass) and never applies it to
        # upgraded (101) connections, where a limit_rate delay on the 101 response even makes
        # nginx miss the client's close. See docs/EDGE.md.
        L += ["client_max_body_size 0;"]
        if h2buf:  # F3: raise per-stream in-flight upload capacity above the 64k default window
            L.append(f"client_body_buffer_size {h2_buf};")
        L += [f"client_body_timeout {idle}s;", f"send_timeout {idle}s;",
              "tcp_nodelay on;", "gzip off;"] + (["brotli off;"] if brotli_ok else []) + [
              f"http2_chunk_size {relay_buf};"]  # F14: larger client-facing HTTP/2 DATA frames
        if grpc:
            L += req_hdrs("grpc_set_header", conn=())
            L += [f"grpc_read_timeout {idle}s;", f"grpc_send_timeout {idle}s;", "grpc_socket_keepalive on;",
                  f"grpc_buffer_size {relay_buf};",  # F14
                  # F28: allow the safe connect-failure failover (a stream is still never replayed)
                  "grpc_next_upstream error timeout;", "grpc_next_upstream_tries 2;",
                  "grpc_next_upstream_timeout 15s;", "grpc_intercept_errors off;"]
            if tls:
                L += ["grpc_ssl_server_name on;", f"grpc_ssl_name {sni};"]
                if verify:
                    L += ["grpc_ssl_verify on;", f"grpc_ssl_trusted_certificate {cfg['CA_BUNDLE']};",
                          "grpc_ssl_verify_depth 4;"]
            L.append(f"grpc_pass {'grpcs' if tls else 'grpc'}://{dest};")
        else:
            conn = (("Connection", '""'),) if kind == "xhttp" else (
                ("Upgrade", "$http_upgrade"), ("Connection", "$pcdn_connection_upgrade"))
            L += ["proxy_http_version 1.1;"] + req_hdrs("proxy_set_header", conn)
            L += ["proxy_buffering off;", "proxy_request_buffering off;", "proxy_cache off;",
                  f"proxy_buffer_size {relay_buf};",  # F14
                  f"proxy_read_timeout {idle}s;", f"proxy_send_timeout {idle}s;", "proxy_socket_keepalive on;",
                  # F28: allow the safe connect-failure failover (a stream is still never replayed)
                  "proxy_next_upstream error timeout;", "proxy_next_upstream_tries 2;",
                  "proxy_next_upstream_timeout 15s;", "proxy_intercept_errors off;"]
            if tls:
                L += ["proxy_ssl_server_name on;", f"proxy_ssl_name {sni};"]
                L += (["proxy_ssl_verify on;", f"proxy_ssl_trusted_certificate {cfg['CA_BUNDLE']};",
                       "proxy_ssl_verify_depth 4;"] if verify else ["proxy_ssl_verify off;"])
            L.append(f"proxy_pass {'https' if tls else 'http'}://{dest};")
        return [f"    location ^~ {_q(p['path'])} {{"] + ["        " + x for x in L] + ["    }"]

    def video_locs():
        """SPEC §16.5: manifests (*.m3u8|*.mpd: short TTL, stale-while-revalidate), segments
        (*.ts|*.m4s|*.aac: long TTL, cache lock, optional next-segment prefetch) and *.mp4 (long TTL,
        1 MB slices on slice-capable nodes so byte ranges of large files are cached piecewise). CORS
        `*` on every media response. Same cache key shape as the site's other locations (plus
        ";r=<range>" per slice); video locations always fetch from the origin (never the shield)."""
        key, quote = cache_key(ignore_q)
        cors = (["Access-Control-Allow-Origin", "Access-Control-Expose-Headers"],
                ["add_header Access-Control-Allow-Origin * always;",
                 'add_header Access-Control-Expose-Headers "Content-Length, Content-Range" always;',
                 "add_header X-Cache $upstream_cache_status always;"])
        stale_e = ["error", "timeout", "http_500", "http_502", "http_503", "http_504"] if stale_err else []
        out_l = []

        def block(match, manifest=False, sliced=False, mirror=False):
            ttl = video["manifest_ttl"] if manifest else video["segment_ttl"]
            k = key + (";r=$slice_range" if sliced else "")
            L = loc_common(cors[0] + ([] if manifest else ["Set-Cookie"]), cors[1])
            if sliced:
                L += ["slice 1m;", "proxy_set_header Range $slice_range;"]
            L += [f"proxy_cache {zone};", "proxy_cache_key " + (f'"{k}"' if (quote or sliced) else k) + ";"]
            if manifest:
                L += [f"proxy_cache_valid 200 {ttl}s;", "proxy_ignore_headers Cache-Control Expires Vary X-Accel-Expires;"]
                if nocache_var:
                    L.append(f"proxy_cache_bypass {nocache_var};")
                L += ["proxy_no_cache " + " ".join(([nocache_var] if nocache_var else []) + ["$upstream_http_set_cookie"])
                      + ";", f"proxy_cache_use_stale {' '.join(['updating'] + stale_e)};",
                      "proxy_cache_background_update on;", "proxy_cache_lock on;", "proxy_cache_lock_timeout 3s;"]
            else:
                L += [f"proxy_cache_valid 200 206 {ttl}s;", "proxy_cache_valid 404 10s;",
                      "proxy_ignore_headers Cache-Control Expires Set-Cookie Vary;",
                      f"proxy_cache_use_stale {' '.join(stale_e) or 'off'};",
                      "proxy_cache_lock on;", "proxy_cache_lock_timeout 10s;", "proxy_cache_lock_age 10s;"]
            if mirror:
                L += ["mirror /__pcdn/vpf;", "mirror_request_body off;"]
            L += mtls_now + [origin_pass(tf_uri)]
            return [f"    location {match} {{"] + ind(L) + ["    }"]

        out_l += block("~* \\.(?:m3u8|mpd)$", manifest=True)
        out_l += block("~* \\.(?:ts|m4s|aac)$", mirror=vprefetch)
        out_l += block("~* \\.mp4$", sliced=vslice)
        if vprefetch:
            # mirror subrequest of a segment request (response discarded, never logged): pcdn.js
            # videoNext names the next segment once per segment and bounded per node; it is fetched
            # into the cache under exactly the key its own request will use (HIT when it arrives)
            nkey = key.replace("$request_uri", "$pcdn_vnext$is_args$args").replace("$pcdn_path", "$pcdn_vnext")
            L = ["internal;", 'if ($pcdn_vnext = "") { return 204; }'] + (
                stor_hdrs(stor_now) if stor_now else list(proxy_hdrs)) + [
                f"proxy_cache {zone};", f'proxy_cache_key "{nkey}";',
                f"proxy_cache_valid 200 206 {video['segment_ttl']}s;", "proxy_cache_valid 404 10s;",
                "proxy_ignore_headers Cache-Control Expires Set-Cookie Vary;", "proxy_cache_lock on;",
                "proxy_cache_lock_timeout 10s;"] + mtls_now + [
                f"proxy_pass $pcdn_proto://$pcdn_target{stor_now['prefix']}$pcdn_vnext;" if stor_now else
                "proxy_pass $pcdn_proto://$pcdn_target$pcdn_vnext$is_args$args;"]
            out_l += ["    location = /__pcdn/vpf {"] + ind(L) + ["    }"]
        return out_l

    def fn_locations(host_name):
        """The function routes of one server plus @pcdn_fn_pass (the site's default origin handling,
        used for `pass` and on_error "origin") and @pcdn_fn_err (502 through the site's error pages)."""
        L = []
        # the site's response headers (HSTS, Alt-Svc, header rules); a function answers any method
        # itself, only its pass to a storage origin (@pcdn_fn_pass) is GET/HEAD-only
        common = loc_common(hdrs=[], guard=False)
        for f in fns:
            err = "@pcdn_fn_pass" if f["on_error"] == "origin" else "@pcdn_fn_err"
            B = [f"client_max_body_size {1024 * 1024};",
                 f"client_body_buffer_size {1024 * 1024};", "proxy_request_buffering on;",
                 "proxy_http_version 1.0;", "proxy_set_header Host $host;", 'proxy_set_header Connection "";',
                 f"proxy_set_header X-Pcdn-Fn-Site {sid};", f"proxy_set_header X-Pcdn-Fn-Id {f['id']};",
                 f"proxy_set_header X-Pcdn-Fn-Host {_q(host_name)};",
                 'proxy_set_header X-Pcdn-Fn-Url "$scheme://$host$request_uri";',
                 "proxy_set_header X-Pcdn-Fn-Ip $remote_addr;",
                 "proxy_set_header X-Pcdn-Fn-Country $pcdn_country;",
                 "proxy_set_header X-Pcdn-Fn-Pass @pcdn_fn_pass;", f"proxy_set_header X-Pcdn-Fn-Err {err};",
                 'proxy_set_header X-Pcdn-Shield "";',
                 # never replace a function's own 4xx/5xx with the site's error pages
                 "proxy_intercept_errors off;", "proxy_connect_timeout 2s;", "proxy_send_timeout 30s;",
                 f"proxy_read_timeout {fn_wall // 1000 + 10}s;", "proxy_buffer_size 64k;",
                 "proxy_buffers 16 64k;", "proxy_busy_buffers_size 128k;", "proxy_cache off;",
                 "add_header X-Cache BYPASS always;"] + common
            if f["on_error"] == "origin":
                # pcdn-fn down / unreachable (nginx-generated 502/504): continue to the origin
                B.append("error_page 502 504 = @pcdn_fn_pass;")
            B.append(f"proxy_pass http://unix:{fn_sock}:;")
            L += [f"    location ^~ {f['route']} {{"] + ind(B) + ["    }"]
        L.append("    location @pcdn_fn_err { return 502; }")
        if cache_on:
            L += proxy_loc("@pcdn_fn_pass", "aggressive" if level == "aggressive" else "dynamic",
                           edge_ttl if level == "aggressive" else 0, 0, ignore_q)
        else:
            L += proxy_loc("@pcdn_fn_pass", "bypass", 0, 0, False)
        return L

    def fn_fetch_server(host_name, proto, pool, target):
        """fetch() of this host's functions: listens only on the local FN_FETCH_SOCKET (pcdn-fn is its
        only client: the socket's directory is root:<nginx group> 0750 and pcdn-fn has no network) and
        proxies to the host's own origin, never cached, never logged/billed. pcdn-fn has already
        restricted the target to this site's hosts and sets X-Pcdn-Fn-Client to the visitor's address."""
        F = ["server {", f"    listen unix:{fn_fetch_sock};", f"    server_name {host_name};", "    access_log off;",
             "    set_real_ip_from unix:;", "    real_ip_header X-Pcdn-Fn-Client;", f"    set $pcdn_site {sid};",
             f"    set $pcdn_proto {proto};", f"    client_max_body_size {1024 * 1024};",
             f"    client_body_buffer_size {1024 * 1024};"]
        if pool:
            F += [f"    set $pcdn_pool {_q(pool)};", "    set $pcdn_target $pcdn_upstream;"]
        else:
            F.append(f"    set $pcdn_target {_q(target)};")
        if stor_now:
            F += storage_server_tail(f'if ($http_x_pcdn_fn_site != "{sid}") {{ return 421; }}', True)
            return "\n".join(F)
        F += ["    proxy_ssl_server_name on;", "    proxy_ssl_name $host;"]
        if proto == "https" and sslo.get("origin_verify"):
            F += ["    proxy_ssl_verify on;", f"    proxy_ssl_trusted_certificate {cfg['CA_BUNDLE']};",
                  "    proxy_ssl_verify_depth 4;"]
        hd = [("Host", "$host"), ("X-Real-IP", "$remote_addr"), ("X-Forwarded-For", "$remote_addr"),
              ("X-Forwarded-Proto", "$scheme"), ("X-Pcdn-Shield", '""'), ("X-Pcdn-Fn-Client", '""'),
              ("X-Pcdn-Fn-Site", '""'), ("Connection", '""')]
        hd = [(n, v) for n, v in hd if n.lower() not in req_headers] + list(req_headers.values())
        # pcdn-fn names the calling site: a request that reached another site's fetch server (e.g. a
        # wildcard host of this site shadowed by another site's exact host) is refused
        L = [f'if ($http_x_pcdn_fn_site != "{sid}") {{ return 421; }}']
        L += [f"proxy_set_header {n} {v};" for n, v in hd]
        L += ["proxy_cache off;", "proxy_intercept_errors off;", f"proxy_read_timeout {fn_wall // 1000 + 5}s;"]
        L += (mtls_lines if proto == "https" else []) + ["proxy_pass $pcdn_proto://$pcdn_target;"]
        F += ["    location / {"] + ind(L) + ["    }", "}"]
        return "\n".join(F)

    def storage_server_tail(first, cond):
        """The rest of a loopback server towards the current host's storage origin (functions
        fetch, resizer originals): GET/HEAD only, safe paths, never cached, storage headers."""
        st = stor_now
        F = ["    proxy_ssl_server_name on;", f"    proxy_ssl_name {_q(st['ssl_name'])};"]
        if st["tls"]:
            F += ["    proxy_ssl_verify on;", f"    proxy_ssl_trusted_certificate {cfg['CA_BUNDLE']};",
                  "    proxy_ssl_verify_depth 4;"]
        L = [first] + stor_guard(stor_badp) + stor_hdrs(st, cond)
        L += ["proxy_cache off;", "proxy_intercept_errors off;", f"add_header Allow $pcdn_sm_{sid} always;",
              f"proxy_pass $pcdn_proto://$pcdn_target{st['prefix']}$pcdn_path;"]
        return F + ["    location / {"] + ind(L) + ["    }", "}"]

    def storage_fetch_server(host_name):
        """127.0.0.1:STORAGE_FETCH_PORT server of a storage host with images on: the resizer /
        transformer fetch originals here (X-Pcdn-Origin), Host = the site host as for any origin."""
        F = ["server {", f"    listen 127.0.0.1:{sport_sto};", f"    server_name {host_name};", "    access_log off;",
             f"    set $pcdn_proto {stor_now['proto']};", f"    set $pcdn_target {_q(stor_now['hp'])};"]
        return "\n".join(F + storage_server_tail("proxy_read_timeout 60s;", False))

    for hi, host in enumerate(site["hosts"]):
        name = str(host["name"]).lower()
        st = stor_of.get(hi)
        res = (st["proto"], None, st["hp"]) if st else resolve_origin(host, pools, origin_proto)
        if res is not None and res[2] is not None and not origin_hp_allowed(res[2], cfg):
            log.warning("site %s: host %r skipped: origin %s is not a public address (ORIGIN_PRIVATE_ALLOW)",
                        sid, name, res[2])
            continue
        if not SAFE_NAME.match(name) or res is None:
            log.warning("skipping unsafe host entry %r -> %s", name, storage_log_repr(host.get("origin")))
            continue
        proto, pool, target = res
        valid_hosts.append(name)
        s = ["server {"]
        s.append(f"    listen {port};")
        if v6:
            s.append(f"    listen [::]:{port};")
        if ssl:
            if caps["http2_directive"]:   # nginx >= 1.25.1 deprecates "listen ... http2" (warns)
                s.append(f"    listen {sport} ssl;")
                if v6:
                    s.append(f"    listen [::]:{sport} ssl;")
                s.append("    http2 on;")
            else:  # "listen ... http2" works on every nginx >= 1.9.5
                s.append(f"    listen {sport} ssl http2;")
                if v6:
                    s.append(f"    listen [::]:{sport} ssl http2;")
            if h3:  # SPEC §14.1; `reuseport` lives on the default server's quic listen
                s.append(f"    listen {sport} quic;")
                if v6:
                    s.append(f"    listen [::]:{sport} quic;")
                s.append("    http3 on;")
                s.append(f"    {alt_svc}")
            s.append(f"    ssl_certificate {cfg['NGINX_DIR']}/certs/{sid}.crt;")
            s.append(f"    ssl_certificate_key {cfg['NGINX_DIR']}/certs/{sid}.key;")
        s.append(f"    server_name {name};")
        # F23: buffer the access log so a tunnel stream/packet request does not write an unbuffered
        # line from the worker event loop; flush often enough that usage accounting barely lags.
        # SPEC §14.1: a shield does not log (bill) the cache misses other edges forward to it
        s.append(f"    access_log {cfg['ACCESS_LOG']} pcdn buffer=64k flush=1s"
                 + (" if=$pcdn_log_ok;" if shield_self else ";"))
        s.append(f"    set $pcdn_site {sid};")
        if tf_flag:   # transform conditions see the visitor's path, also after an internal rewrite
            s.append("    set $pcdn_ouri $uri;")
        s.append("    location = /__pcdn/health { access_log off; return 200 \"ok\\n\"; }")
        if tunnel and status not in ("suspended", "over_quota"):
            # F27/N2: raise the client-facing HTTP/2 connection timers for tunnel hosts so idle
            # tunnels are not closed after 75 s and stream-heavy XHTTP/gRPC connections are not
            # forced to GOAWAY + reconnect at the 100000-stream cap. Bounded, not unlimited.
            kreq = _int(cfg.get("TUNNEL_KEEPALIVE_REQUESTS"), 10000000, 1000, 2 ** 31 - 1)
            s.append("    keepalive_timeout 600s;")
            s.append("    keepalive_time 6h;")
            s.append(f"    keepalive_requests {kreq};")
            s.append(f"    send_timeout {min(tunnel['idle_timeout'], 300)}s;")
            if fallback in ("decoy", "404") and ssl:
                # F14: pure-tunnel hosts favour throughput over TLS first-byte latency
                s.append(f"    ssl_buffer_size {relay_buf};")

        if status in ("suspended", "over_quota"):
            page = "suspended.html" if status == "suspended" else "over_quota.html"
            # F35: cheap, rate-limited, body-less 503 on tunnel path prefixes so reconnect storms
            # cost neither an access-log line nor an HTML page read. error_page is scoped to
            # `location /` so only the browser-facing catch-all serves the localized page.
            for cp in cut_paths:
                s.append(f"    location ^~ {_q(cp)} {{ access_log off; "
                         f"limit_req zone=pcdn_cut burst=5 nodelay; limit_req_status 503; return 503; }}")
            s.append(f"    location = /{page} {{ internal; root {cfg['PAGES_DIR']}; "
                     f"add_header Cache-Control no-store always; }}")
            s.append(f"    location / {{ error_page 503 /{page}; return 503; }}")
            s.append("}")
            out.append("\n".join(s))
            continue

        s.append(f"    set $pcdn_proto {proto};")
        stor_now.clear()
        stor_now.update(st or {})
        # client certificate towards this host's origin (only when it is reached over HTTPS; never
        # towards the platform's own object storage)
        mtls_now[:] = mtls_lines if proto == "https" and not st else []
        mtls_used = mtls_used or bool(mtls_now)
        if pool:
            s.append(f"    set $pcdn_pool {_q(pool)};")
            s.append("    set $pcdn_target $pcdn_upstream;")
        else:
            s.append(f"    set $pcdn_target {_q(target)};")
        # security verdict (njs): firewall, hotlink, rate limits, DDoS challenge, WAF
        gate = "$pcdn_gate" if shield_self else "$pcdn_verdict"   # a valid shield hop skips the verdict
        s.append(f"    if ({gate} !~ \"^(?:ok|log:)\") {{ rewrite ^ /__pcdn/deny/{gate}? last; }}")
        if sslo.get("force_https") and ssl:
            if force_https_tn:  # F34: redirect http, but never tunnel-path requests
                s.append(f"    if ($pcdn_httpredir_{sid}) {{ return 301 https://$host$request_uri; }}")
            else:
                s.append("    if ($scheme = http) { return 301 https://$host$request_uri; }")
        for code in rd_codes:   # SPEC §14.2 redirect rules (first matching rule, see redirect_maps)
            s.append(f"    if ({rd_var} ~ \"^{code}(.*)$\") {{ return {code} $1; }}")
        if body_on and not st:   # storage origins take no request bodies (GET/HEAD only)
            s.append(f"    if ({fn_bodychk}) {{ rewrite ^ /__pcdn/body$uri last; }}")
        if image_on:
            if imv2["secret"]:   # SPEC §16.6 signed transform URLs: unsigned / wrong signature -> 403
                s.append(f'    if ({fn_imgw} = "!") {{ return 403; }}')
            s.append(f"    if ({fn_imgw}) {{ rewrite ^ /__pcdn/img$uri last; }}")
        if rps > 0:
            s.append(f"    limit_req zone=pcdn_rlk_{sid} burst={rps * 2} nodelay;")
            s.append("    limit_req_status 429;")
        s.append("    proxy_ssl_server_name on;")
        if st:   # SPEC §16.8: the storage endpoint's own name, always verified
            s.append(f"    proxy_ssl_name {_q(st['ssl_name'])};")
        else:
            s.append("    proxy_ssl_name $host;")
        if (proto == "https" and sslo.get("origin_verify")) or (st and st["tls"]):
            s.append("    proxy_ssl_verify on;")
            s.append(f"    proxy_ssl_trusted_certificate {cfg['CA_BUNDLE']};")
            s.append("    proxy_ssl_verify_depth 4;")
        for cls, codes in err_pages.items():
            s.append(f"    error_page {codes} /__pcdn/err/{cls}.html;")
        if err_pages:
            s.append("    proxy_intercept_errors on;")

        s.append("    location ^~ /__pcdn/ { return 404; }")
        s += speed_locations(cfg, njs_ok, brotli_ok, bool(caps.get("flv")))
        if njs_ok:
            s.append("    location ^~ /__pcdn/deny/ { internal; js_content pcdn.deny; }")
            s.append("    location = /__pcdn/verify { js_content pcdn.verify; }")
            s.append("    location = /__pcdn/captcha { client_max_body_size 16k; client_body_buffer_size 16k; "
                     "js_content pcdn.captcha; }")
        else:  # no njs module (never a verdict other than "ok"): keep nginx -t passing
            s.append("    location ^~ /__pcdn/deny/ { internal; return 403; }")
        for cls in err_pages:
            s.append(f"    location = /__pcdn/err/{cls}.html {{ internal; default_type text/html; "
                     f"alias {cfg['NGINX_DIR']}/errors/{sid}-{cls}.html; add_header Cache-Control no-store always; }}")
        if body_on and not st:
            # the body is read here (in memory: bodyNeed only routes requests whose declared length
            # fits), inspected, then proxied as is (never cached) with the original request URI
            s.append(f"    location ^~ /__pcdn/body/ {{ internal; client_max_body_size {BODY_CAP}; "
                     f"client_body_buffer_size {BODY_CAP}; client_body_in_single_buffer on; "
                     "js_content pcdn.bodyInspect; }")
            s += proxy_loc("@pcdn_body", "bypass", 0, 0, False, uri=body_uri)

        if image_on:
            # storage origins: the GET/HEAD / path guard runs before the rewrite (`break` ends the
            # rewrite directives of this location)
            L = ["internal;"] + (stor_guard(stor_bad) if st else []) + ["rewrite ^/__pcdn/img(/.*)$ $1 break;"]
            adds = [f"add_header Allow $pcdn_sm_{sid} always;"] if st else []
            if cache_on:
                key, _ = cache_key(ignore_q, image=True)
                L += [f"proxy_cache {zone};", f"proxy_cache_key \"{key}\";",
                      f"proxy_cache_valid 200 {max(edge_ttl, 60)}s;",
                      "proxy_ignore_headers Cache-Control Expires Set-Cookie Vary;", "proxy_cache_lock on;"]
                adds.append("add_header X-Cache $upstream_cache_status always;")
            else:
                adds.append("add_header X-Cache BYPASS always;")
            if imv2["avif"] and not webp_on:   # the variant depends on Accept (webp_on adds its own Vary)
                adds.append("add_header Vary Accept;")
            # a storage origin: the resizer fetches originals through this host's loopback storage
            # server (storage_fetch_server), which adds the bucket's Host / Referer / path prefix
            img_hdrs = [x for x in proxy_hdrs if not x.startswith(("proxy_set_header X-Pcdn-Origin ",
                                                                   "proxy_set_header X-Pcdn-Mtls "))]
            L = L + loc_common(["Set-Cookie"], adds, hdrs=img_hdrs, guard=False) + [
                f"proxy_set_header X-Pcdn-Origin http://127.0.0.1:{sport_sto};" if st else
                "proxy_set_header X-Pcdn-Origin $pcdn_proto://$pcdn_target;",
                "proxy_set_header X-Pcdn-W $pcdn_img_w;",
                "proxy_set_header X-Pcdn-H $pcdn_img_h;",
                "proxy_set_header X-Pcdn-Q $pcdn_img_q;"]
            if mtls_now:   # the resizer presents this site's client certificate (mtls.conf)
                tok = mtls_token(mtls_id, mtls_pair)
                L.append(f"proxy_set_header X-Pcdn-Mtls {tok};")
                meta["mtls_resizer"] = (tok, mtls_pair)
            else:          # never let a visitor's own X-Pcdn-Mtls header reach the resizer
                L.append('proxy_set_header X-Pcdn-Mtls "";')
            # from INTERNAL_SRC: the origin guard admits only that source to the loopback services
            L += [f"proxy_bind {internal_src(cfg)};", f"proxy_pass http://127.0.0.1:{resize_port}{tf_uri};"]
            s += ["    location ^~ /__pcdn/img/ {"] + ["        " + x for x in L] + ["    }"]

        if fn_live:
            s += fn_locations(name)
        else:
            for f in fns:   # no pcdn-fn on this node: fail closed where the customer asked for it
                if f["on_error"] == "502":
                    s.append(f"    location ^~ {f['route']} {{ return 502; }}")

        # tunnel paths: "^~" prefix locations, so no page rule / static regex location can take them
        if tunnel:
            for p in tunnel["paths"]:
                if st and not p["origin"] and not p["pool"]:
                    # a storage origin never carries tunnels (SPEC §16.8): only paths with their own
                    # origin / pool work on such a host
                    s.append(f"    location ^~ {_q(p['path'])} {{ return 404; }}")
                    continue
                s += tunnel_loc(p, proto, pool, target)
            if fallback == "decoy":
                s.append("    location / {")
                s.append("        default_type text/html;")
                s.append("        add_header Cache-Control \"no-cache\" always;")
                s.append(f"        return 200 {_qv(decoy)};")
                s.append("    }")
                s.append("}")
                out.append("\n".join(s))
                continue
            if fallback == "404":
                s.append("    location / { return 404; }")
                s.append("}")
                out.append("\n".join(s))
                continue

        # page rules: regex locations in order (nginx uses the first matching regex)
        for r in prules:
            match = f"~ \"{r['_re']}\""
            red = r.get("redirect")
            if isinstance(red, dict) and SAFE_URL.match(str(red.get("url") or "")):
                code = red.get("code") if red.get("code") in (301, 302, 307, 308) else 301
                s.append(f"    location {match} {{ return {code} {_qv(red['url'])}; }}")
                continue
            if all(r.get(k) is None for k in ("cache", "edge_ttl", "browser_ttl", "ignore_query")):
                continue  # WAF-only rule: handled in njs
            default_mode = "aggressive" if level == "aggressive" else "dynamic"
            mode = {"bypass": "bypass", "standard": "dynamic", "everything": "everything"}.get(r.get("cache"), default_mode)
            if r.get("edge_ttl") is not None:
                ttl = _int(r["edge_ttl"], edge_ttl, 0, 31536000)
            else:
                ttl = 0 if mode == "dynamic" else edge_ttl
            bttl = browser_ttl if r.get("browser_ttl") is None else _int(r["browser_ttl"], 0, 0, 31536000)
            iq = ignore_q if r.get("ignore_query") is None else bool(r["ignore_query"])
            s += proxy_loc(match, mode, ttl, bttl, iq)

        if video:
            s += video_locs()
        if cache_on:
            # static assets: cached at the edge even without origin headers
            s += proxy_loc(f"~* \\.(?:{STATIC_EXT})$", "static", edge_ttl, browser_ttl, ignore_q)
            if not fn_root:   # a function bound to "/" owns `location ^~ /`
                s += proxy_loc("/", "aggressive" if level == "aggressive" else "dynamic",
                               edge_ttl if level == "aggressive" else 0, 0, ignore_q)
        elif not fn_root:
            s += proxy_loc("/", "bypass", 0, 0, False)
        s.append("}")
        out.append("\n".join(s))
        if fn_live:
            out.append(fn_fetch_server(name, proto, pool, target))
        if st and image_on:
            out.append(storage_fetch_server(name))
            meta["storage_fetch"] = True

    if mtls_used and mtls_id != "platform":
        files[f"mtls/{sid}.crt"], files[f"mtls/{sid}.key"] = mtls_pair
    meta["mtls_platform"] = mtls_used and mtls_id == "platform"
    meta["functions"] = fn_live and bool(valid_hosts)
    js = (site_js(site, valid_hosts, pools, sslo, tunnel, tf_resp, video if vprefetch else None)
          if active and valid_hosts else None)
    return "\n\n".join(out) + "\n", files, js, meta
