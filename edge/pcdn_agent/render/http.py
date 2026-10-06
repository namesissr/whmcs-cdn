"""Node-wide nginx rendering: http.conf (from the pcdn-base.conf template), the image resizer
server, the mTLS resizer upstreams, the verified-crawler ranges (bots.conf), and the node block
(fair share, speed-test node tag)."""

import base64
import binascii
import hashlib
import os
import re
import socket

from ..capabilities import geoip_present, has_module, image_capabilities, module_blocks, nginx_capabilities
from ..common import SAFE_FSPATH, SAFE_RESOLVER, SAFE_SIZE, _int, _v6
from ..settings import asset, log
from ..validation.origin import internal_src
from ..validation.rules import BOT_ENGINES


# ----------------------------------------------------------------- node block (SPEC §15.2)

FAIR_HOT_PCT = 85      # SPEC §15.2: the node is "hot" at >= 85 % of its capacity (tx_mbps) ...
FAIR_COOL_PCT = 80     # ... and stays hot until it drops below 80 % (hysteresis, no flapping)


def fair_hot(tx_mbps: float, capacity_mbps: int, was_hot: bool) -> bool:
    """SPEC §15.2 node "hot" state with hysteresis; never hot without a known capacity."""
    if capacity_mbps <= 0:
        return False
    pct = float(tx_mbps) * 100 / capacity_mbps
    return pct >= FAIR_HOT_PCT or (was_hot and pct >= FAIR_COOL_PCT)


def norm_node(config: dict, cfg: dict) -> dict:
    """Node-wide block of the edge config (SPEC §15.2): {"capacity_mbps", "fair_share_pct", "name"}.
    Every key is optional; agent.conf CAPACITY_MBPS / FAIR_SHARE_PCT / NODE_NAME are the fallbacks
    (capacity 0 = unknown: the node is never considered hot, fair share stays idle)."""
    n = config.get("node") if isinstance(config.get("node"), dict) else {}
    name = str(n.get("name") or cfg.get("NODE_NAME") or "").strip()
    if not name:
        try:
            name = socket.gethostname()
        except OSError:
            name = ""
    # the controller sends capacity_mbps 0 for "unknown": the agent.conf value (if any) applies then
    cap = _int(n.get("capacity_mbps"), 0, 0, 10_000_000) or _int(cfg.get("CAPACITY_MBPS"), 0, 0, 10_000_000)
    return {"capacity_mbps": cap,
            "fair_share_pct": _int(n.get("fair_share_pct", cfg.get("FAIR_SHARE_PCT")), 25, 1, 100),
            "name": name[:253],
            # SPEC §22.9 per-node HTTP/3 switch (absent = on where the nginx build has HTTP/3)
            "http3": n.get("http3") is not False,
            # SPEC §23.12.2 public node tag (8 hex, keyed HMAC on the controller; "" = old controller)
            "public_tag": public_tag(n)}


_PUBLIC_TAG = re.compile(r"^[0-9a-f]{8}$")


def public_tag(n: dict) -> str:
    """node.public_tag of the config when it is exactly 8 lower-case hex characters, else "" (an old
    controller sends none: the agent then falls back to node_tag(name))."""
    v = n.get("public_tag") if isinstance(n, dict) else None
    return v if isinstance(v, str) and _PUBLIC_TAG.match(v) else ""


# ----------------------------------------------------------------- TLS session tickets (SPEC §22.8)

TICKET_KEY_LEN = 80   # nginx AES-256 ticket key format
TICKET_FILES = ("tickets/0.key", "tickets/1.key", "tickets/2.key")
_TICKET_ID = re.compile(r"^[0-9a-f]{8}$")


def norm_tickets(config: dict) -> list[bytes] | None:
    """node.tls_tickets = {"id": "<8 hex>", "keys": [b64 current, b64 next, b64 previous]} -> the raw
    80-byte keys in that order (nginx encrypts with the first, decrypts with all), or None (tickets off)
    when absent / null / malformed. Key material is never logged."""
    n = config.get("node") if isinstance(config.get("node"), dict) else {}
    t = n.get("tls_tickets")
    if not isinstance(t, dict):
        return None
    keys = t.get("keys")
    if not _TICKET_ID.match(str(t.get("id") or "")) or not isinstance(keys, list) or not 1 <= len(keys) <= 3:
        log.warning("node.tls_tickets ignored: malformed (tickets stay off)")
        return None
    out = []
    for k in keys:
        try:
            raw = base64.b64decode(str(k), validate=True)
        except (binascii.Error, ValueError):
            raw = b""
        if len(raw) != TICKET_KEY_LEN:
            log.warning("node.tls_tickets ignored: a key is not %d bytes (tickets stay off)", TICKET_KEY_LEN)
            return None
        out.append(raw)
    return out


def tickets_conf(cfg: dict, n: int) -> str:
    """http-level session-ticket directives: off, or on with the n key files (first = encryption key)."""
    if not n:
        return "ssl_session_tickets off;"
    root = cfg["NGINX_DIR"].rstrip("/")
    return "ssl_session_tickets on;\n" + "\n".join(f"ssl_session_ticket_key {root}/{TICKET_FILES[i]};"
                                                    for i in range(n))


def node_tag(name: str) -> str:
    """Fallback X-Pcdn-Node / X-Served-By value (SPEC §15.6, §23.12.2) for a controller that sends no
    node.public_tag: 8 hex chars of a hash of the node NAME. It tells a customer whether two
    measurements hit the same node; it is never an address and cannot be used to pick or reach a node."""
    return hashlib.sha256(("pcdn-node|" + name).encode()).hexdigest()[:8]


def served_tag(node: dict) -> str:
    """The value of X-Served-By and of the speed-test X-Pcdn-Node ($pcdn_node, SPEC §23.12.2): the
    controller's public tag, else the name hash (old controller). Never the host name."""
    return node.get("public_tag") or node_tag(node.get("name") or "")


def rum_geo_conf(cfg: dict) -> str:
    """SPEC §23.7: $pcdn_asn / $pcdn_region for the RUM ingestion (read only there, at ingestion; the
    client address itself is never logged). Each comes from its optional mmdb when the geoip2 module and
    the file exist, else a constant (asn "0", region "")."""
    out = []
    geo2 = has_module(cfg, "geoip2")
    for key, var, path, default in (("RUM_ASN_DB", "$pcdn_asn", "autonomous_system_number", "0"),
                                    ("RUM_REGION_DB", "$pcdn_region", "subdivisions 0 names en", "")):
        db = cfg.get(key) or ""
        if geo2 and SAFE_FSPATH.match(db) and os.path.isfile(db):
            out.append(f"geoip2 {db} {{\n    auto_reload 60m;\n    {var} {path};\n}}")
        else:
            out.append(f"map $host {var} {{\n    default \"{default}\";\n}}")
    return "\n".join(out)


def render_http(cfg: dict, hc_interval: int = 2, shield: dict | None = None, bots: bool = False,
                mtls: bool = False, node: dict | None = None, probe: str = "", tickets: int = 0) -> str:
    """The base http-context config (from the template), see nginx/pcdn-base.conf.
    hc_interval: js_periodic tick for pool health checks (> the largest check timeout).
    shield: the node's normalised shield section (norm_shield) or None.
    bots / mtls: bots.conf / mtls.conf were rendered and are included (SPEC §14.2).
    node: the normalised node block (norm_node); its name feeds the speed-test X-Pcdn-Node tag and
    node.http3 false turns QUIC off (SPEC §22.9).
    probe: the synthetic tunnel probe servers (render_probe, SPEC §22.3; "" = none).
    tickets: number of shared session-ticket key files (SPEC §22.8; 0 = tickets off)."""
    with open(asset(cfg, "BASE_TEMPLATE", "nginx/pcdn-base.conf")) as f:
        text = f.read()
    caps = nginx_capabilities(cfg)
    text = module_blocks(text, caps["modules"])
    if geoip_present(cfg):
        geo = cfg["GEOIP_DB"]
        geo_conf = f"geoip2 {geo} {{\n    auto_reload 60m;\n    $pcdn_country country iso_code;\n}}"
    else:  # nginx must start without the database (or module); country rules then never match
        geo_conf = "map $host $pcdn_country {\n    default \"\";\n}"
    sport = str(_int(cfg["HTTPS_PORT"], 443, 1, 65535))
    extra = []
    if caps["http2_directive"]:
        extra.append("    http2 on;")
    if caps["http3"] and (node or {}).get("http3") is not False:
        # one `quic reuseport` per address (on the default server); site servers add plain `quic`
        extra += [f"    listen {sport} quic default_server reuseport;",
                  f"    listen [::]:{sport} quic default_server reuseport;"]
    if caps["early_hints"]:
        # SPEC §14.1: pass 103 Early Hints to HTTP/2+ navigations only (HTTP/1.1 clients and
        # intermediaries are known to mishandle 1xx); used by sites with preload page rules
        eh = "$http2$http3" if caps["http3"] else "$http2"
        eh_conf = f"map $http_sec_fetch_mode $pcdn_early_hints {{\n    default \"\";\n    navigate {eh};\n}}"
    else:
        eh_conf = ""
    if shield:
        shield_conf = f"include {cfg['NGINX_DIR'].rstrip('/')}/shield.conf;"
    else:
        shield_conf = "map $uri $pcdn_shield_ok {\n    default 0;\n}"
    # no verified crawler ranges (or no site using bot management): "" = crawler UAs fail open
    bots_conf = (f"include {cfg['NGINX_DIR'].rstrip('/')}/bots.conf;" if bots
                 else "geo $pcdn_vbot {\n    default \"\";\n}")
    mtls_conf = (f"include {cfg['NGINX_DIR'].rstrip('/')}/mtls.conf;" if mtls
                 else "map $uri $pcdn_mtls_crt {\n    default \"\";\n}\nmap $uri $pcdn_mtls_key {\n    default \"\";\n}")
    subst = {
        "NGINX_DIR": cfg["NGINX_DIR"].rstrip("/"),
        "HTTP_PORT": str(_int(cfg["HTTP_PORT"], 80, 1, 65535)),
        "HTTPS_PORT": str(_int(cfg["HTTPS_PORT"], 443, 1, 65535)),
        "RESIZE_PORT": str(_int(cfg["RESIZE_PORT"], 8089, 1, 65535)),
        "RESOLVER": cfg["RESOLVER"] if SAFE_RESOLVER.match(cfg["RESOLVER"]) else "1.1.1.1",
        "DICT_SIZE": cfg["DICT_SIZE"] if SAFE_SIZE.match(cfg["DICT_SIZE"]) else "32m",
        "GEOIP": geo_conf,
        "HC_INTERVAL": str(_int(hc_interval, 2, 2, 11)),
        "CONNECT_TIMEOUT": str(_int(cfg.get("TUNNEL_CONNECT_TIMEOUT"), 10, 3, 30)),
        "SSL_BUFFER_SIZE": cfg["SSL_BUFFER_SIZE"] if SAFE_SIZE.match(cfg.get("SSL_BUFFER_SIZE") or "") else "4k",
        "SHIELD": shield_conf,
        "BOTS": bots_conf,
        "MTLS": mtls_conf,
        "EARLY_HINTS": eh_conf,
        "LISTEN_H2": "" if caps["http2_directive"] else " http2",
        "HTTPS_DEFAULT_EXTRA": "\n".join(extra),
        "NODE_TAG": served_tag(node or norm_node({}, cfg)),
        "RUM_GEO": rum_geo_conf(cfg),
        "RESIZER": render_resizer(cfg),
        "PROBE": probe,
        "SSL_TICKETS": tickets_conf(cfg, tickets),
    }
    if not SAFE_FSPATH.match(subst["NGINX_DIR"]):
        raise ValueError("unsafe NGINX_DIR")
    for k, v in subst.items():
        text = text.replace("{{" + k + "}}", v)
    if not _v6(cfg):
        text = "\n".join(line for line in text.splitlines() if "listen [::]" not in line) + "\n"
    return text


WR_DICT_TIMEOUT = 10800   # s; > the longest session (120 min): idle sessions and old counters expire


def render_gates(cfg: dict, wr: bool, access: bool) -> str:
    """http-level part of the visitor gates (SPEC §18.1 / §18.2), appended to http.conf only while
    some site uses them (nodes without them keep a byte-identical http.conf): the waiting-room dict
    (sessions, per-minute activity buckets, ticket counters; bounded by size + timeout + evict), the
    $pcdn_wrc cookie handed from the verdict to the response, and the signed-in access email."""
    out = ["", "# visitor gates (SPEC §18.1 waiting room, §18.2 access) - pcdn.js wr* / access*"]
    if wr:
        size = cfg.get("WR_DICT_SIZE") or "48m"
        size = size if SAFE_SIZE.match(size) else "48m"
        out += [f"js_shared_dict_zone zone=pcdn_wr:{size} type=number timeout={WR_DICT_TIMEOUT}s evict;",
                "js_var $pcdn_wrc;"]
    if access:
        out.append("js_set $pcdn_acc_email pcdn.accessEmail;")
    return "\n".join(out) + "\n"


def render_file_links() -> str:
    """http-level part of SPEC §16.8 signed file links, appended only while some site hands out a
    bucket by signed link (other nodes keep a byte-identical http.conf). js_var: a storage host's
    server block sets the key from its 0600 conf, so the key never reaches sites.js."""
    return ("\n# signed file links (SPEC §16.8) - pcdn.js fileLink\n"
            "js_var $pcdn_flink_key;\njs_set $pcdn_flink pcdn.fileLink;\n")


def render_resizer(cfg: dict) -> str:
    """The loopback image server block of http.conf (SPEC §2 resize, §16.6 images v2).

    Site image locations proxy here with Host, X-Pcdn-Origin (origin base URL), X-Pcdn-W/-H/-Q
    (pcdn.js imgW/imgH/imgQ) and X-Pcdn-Mtls. $pcdn_rz_mode picks the handler per request:
      resize - nginx image_filter resize (legacy ?width/?height: exactly the pre-wave-8 behaviour)
      crop   - image_filter crop (v2 fit=cover without the transformer; center crop)
      v2     - the transformer (`pcdn-agent imaged`, IMAGE_PORT): resize / cover / smart crop and
               WebP / AVIF / JPEG output; any failure (not running, 415, 5xx, timeout) falls back to
               image_filter resize (or the untouched original) cached for 60 s only
      src    - the untouched original (v2 request without dimensions and no transformer)
    /__pcdn_rz/src/ is also how the transformer fetches originals (through this server, so origin
    TLS / client certificates / resolver work exactly as for the resizer)."""
    caps = nginx_capabilities(cfg)
    filt = "image_filter" in caps["modules"]
    v2 = image_capabilities(cfg)["transform"]
    avif = "1" if image_capabilities(cfg)["avif"] else "0"
    out = ["# AVIF output possible on this node (SPEC §16.6, pcdn.js avifOk)",
           f"map $uri $pcdn_avif_ok {{\n    default \"{avif}\";\n}}"]
    if "njs" not in caps["modules"] or not (filt or v2):
        out.append("# no image resizer on this node (needs njs and image_filter or the image transformer)")
        return "\n".join(out)
    port = _int(cfg.get("RESIZE_PORT"), 8089, 1, 65535)
    iport = _int(cfg.get("IMAGE_PORT"), 8090, 1, 65535)
    legacy = "resize" if filt else "v2"
    if v2:
        v2_rules = '    "~^[^|]*[|][^:]*:" v2;\n'
    else:   # no transformer: v2 specs map onto image_filter (fmt / smart crop ignored)
        v2_rules = ('    "~^-[|]-:" src;\n    "~^[^|]*[|][^:]*:cover:" crop;\n'
                    '    "~^[^|]*[|][^:]*:" resize;\n')
    out += [
        "map $http_x_pcdn_w $pcdn_rz_w {\n    default \"-\";\n    \"~^(\\d+)$\" $1;\n}",
        "map $http_x_pcdn_h $pcdn_rz_h {\n    default \"-\";\n    \"~^(\\d+)\" $1;\n}",
        "map $http_x_pcdn_q $pcdn_rz_q {\n    default 85;\n    \"~^(\\d{1,3})$\" $1;\n}",
        f"map \"$http_x_pcdn_w|$http_x_pcdn_h\" $pcdn_rz_mode {{\n    default {legacy};\n{v2_rules}}}",
    ]
    common = ["proxy_set_header Host $host;", 'proxy_set_header X-Pcdn-Origin "";', 'proxy_set_header X-Pcdn-W "";',
              'proxy_set_header X-Pcdn-H "";', 'proxy_set_header X-Pcdn-Q "";', 'proxy_set_header X-Pcdn-Mtls "";',
              'proxy_set_header Accept-Encoding "";', "proxy_ssl_server_name on;", "proxy_ssl_name $host;",
              # SPEC §14.2 authenticated origin pulls: the calling site names its client certificate in
              # X-Pcdn-Mtls ("" = none; an empty certificate variable sends no client certificate)
              "proxy_ssl_certificate $pcdn_mtls_crt;", "proxy_ssl_certificate_key $pcdn_mtls_key;"]

    def filt_lines(op):
        return [f"image_filter {op} $pcdn_rz_w $pcdn_rz_h;", "image_filter_jpeg_quality $pcdn_rz_q;",
                "image_filter_webp_quality $pcdn_rz_q;", "image_filter_buffer 20M;", "image_filter_interlace on;"]

    def loc(head, body):
        return [f"    location {head} {{"] + ["        " + x for x in body] + ["    }"]

    # the origin guard admits loopback-service connections only from INTERNAL_SRC: the resizer binds
    # it for the transformer and for a loopback fetch URL (a storage host's fetch server; only the
    # edge sets X-Pcdn-Origin, visitors' copies are dropped before any origin), nothing else
    src = internal_src(cfg)
    out.append(f"map $http_x_pcdn_origin $pcdn_rz_bind {{\n    default \"\";\n"
               f"    \"~^http://127\\\\.0\\\\.0\\\\.1:\" {src};\n}}")
    srv = ["server {", f"    listen 127.0.0.1:{port};", "    server_name _;", "    access_log off;",
           "    proxy_bind $pcdn_rz_bind;"]
    srv += ["    " + x for x in common]
    srv += loc("/", ['if ($http_x_pcdn_origin = "") { return 404; }',
                     # the original is fetched without the resize / transform args ($uri, not a
                     # capture: evaluating the regex map would overwrite $1)
                     "rewrite ^ /__pcdn_rz/$pcdn_rz_mode$uri? last;"])
    if filt:
        srv += loc("^~ /__pcdn_rz/resize/", ["internal;", "rewrite ^/__pcdn_rz/resize(/.*)$ $1 break;"]
                   + filt_lines("resize") + ["proxy_pass $http_x_pcdn_origin;"])
        if not v2:
            srv += loc("^~ /__pcdn_rz/crop/", ["internal;", "rewrite ^/__pcdn_rz/crop(/.*)$ $1 break;"]
                       + filt_lines("crop") + ["proxy_pass $http_x_pcdn_origin;"])
    # originals: the v2 mode without dimensions, and the transformer's own fetches (loopback only)
    srv += loc("^~ /__pcdn_rz/src/", ["allow 127.0.0.1;", f"allow {src};", "allow ::1;", "deny all;",
                                      'if ($http_x_pcdn_origin = "") { return 404; }',
                                      "rewrite ^/__pcdn_rz/src(/.*)$ $1 break;", "proxy_pass $http_x_pcdn_origin;"])
    if v2:
        fb = "@pcdn_rz_fbr" if filt else "@pcdn_rz_fbs"
        if filt:
            out.append("map \"$http_x_pcdn_w|$pcdn_rz_h\" $pcdn_rz_fb {\n    default @pcdn_rz_fbr;\n"
                       "    \"-|-\" @pcdn_rz_fbs;\n}")
            fb = "$pcdn_rz_fb"
        srv += loc("^~ /__pcdn_rz/v2/", [
            "internal;", "rewrite ^/__pcdn_rz/v2(/.*)$ $1 break;",
            "proxy_set_header Host $host;", "proxy_set_header X-Pcdn-Origin $http_x_pcdn_origin;",
            "proxy_set_header X-Pcdn-W $http_x_pcdn_w;", "proxy_set_header X-Pcdn-H $http_x_pcdn_h;",
            "proxy_set_header X-Pcdn-Q $http_x_pcdn_q;", "proxy_set_header X-Pcdn-Mtls $http_x_pcdn_mtls;",
            'proxy_set_header Accept-Encoding "";', "proxy_connect_timeout 2s;", "proxy_read_timeout 60s;",
            "proxy_intercept_errors on;", f"error_page 413 415 500 502 503 504 = {fb};",
            f"proxy_bind {src};", f"proxy_pass http://127.0.0.1:{iport};"])
        # fallbacks: short-lived in the site cache (X-Accel-Expires), so the real variant replaces
        # them once the transformer is back
        if filt:
            srv += loc("@pcdn_rz_fbr", filt_lines("resize") + ["add_header X-Accel-Expires 60;",
                                                               "proxy_pass $http_x_pcdn_origin;"])
        srv += loc("@pcdn_rz_fbs", ["add_header X-Accel-Expires 60;", "proxy_pass $http_x_pcdn_origin;"])
    srv.append("}")
    return "\n".join(out + srv)


def render_bots(ranges: dict) -> str | None:
    """bots.conf (0644, CIDRs only): `geo $pcdn_vbot` = "<engine><known>" where engine is 1 (google)
    / 2 (bing) / 0 (neither) and <known> lists the engines this node has ranges for, so njs can fail
    open for an engine without ranges. None when no engine has ranges ($pcdn_vbot is then "")."""
    if not ranges:
        return None
    known = "".join(flag for name, _, flag in BOT_ENGINES if ranges.get(name))
    out = ["# verified crawler ranges (SPEC §14.2) — generated by pcdn-agent, do not edit",
           "geo $pcdn_vbot {", f'    default "0{known}";']
    for name, val, _ in BOT_ENGINES:
        out += [f'    {c} "{val}{known}";' for c in ranges.get(name) or []]
    return "\n".join(out) + "\n}\n"


MTLS_CHUNK = 3000   # nginx limits one config token to its 4 KiB read buffer


def mtls_token(ident: str, pair: tuple) -> str:
    """The X-Pcdn-Mtls value naming a client certificate for the image resizer: "<id>-<hash of the
    key>", so a visitor cannot pick a certificate by sending the header itself (client headers pass
    through an image location that does not set it). Deterministic: the tree digest stays stable."""
    return f"{ident}-" + hashlib.sha256(b"pcdn-mtls|" + pair[1].encode()).hexdigest()[:32]


def render_mtls_resizer(pairs: dict) -> str | None:
    """mtls.conf (0600): the client certificates the local image resizer presents to origins
    (SPEC §14.2), selected by the X-Pcdn-Mtls header the calling site sets (mtls_token). The
    resizer runs in unprivileged workers, so the PEM travels in variables ("data:...",
    nginx >= 1.21) instead of root-only files; long PEMs are split over several variables."""
    if not pairs:
        return None
    out = ["# client certificates for the image resizer (SPEC §14.2) — generated by pcdn-agent, do not edit"]
    sel = {"c": [], "k": []}
    for ident in sorted(pairs):
        for kind, pem in zip("ck", pairs[ident]):
            names = []
            for i in range(0, len(pem), MTLS_CHUNK):
                var = f"pcdn_m{kind}_{ident.split('-')[0]}_{i // MTLS_CHUNK}"
                out.append(f'map $uri ${var} {{\n    default "{pem[i:i + MTLS_CHUNK]}";\n}}')
                names.append("$" + var)
            sel[kind].append(f'    "{ident}" "data:{"".join(names)}";\n')
    for kind, var in (("c", "$pcdn_mtls_crt"), ("k", "$pcdn_mtls_key")):
        out.append(f"map $http_x_pcdn_mtls {var} {{\n    default \"\";\n" + "".join(sel[kind]) + "}")
    return "\n".join(out) + "\n"
