# Pasargad CDN v2 — internal contract

This file is the single source of truth shared by the three components:
controller (`controller/`), edge (`edge/`) and WHMCS module (`whmcs/`).
Anything not listed here keeps the v1 behaviour described in README.md.

Conventions: JSON everywhere, snake_case keys, times are ISO-8601 UTC with `Z`.
All admin endpoints need `Authorization: Bearer <ADMIN_API_KEY>`; edge endpoints
need the edge token. Errors: HTTP 4xx with `{"detail": "<Persian message>"}` or
FastAPI's validation list `{"detail": [{"loc": [...], "msg": "..."}]}`.

---------------------------------------------------------------------------
## 1. Plan / features

`site.plan` (returned by GET site, set by POST /sites and PATCH /sites/{d}/plan):

```json
{
  "bandwidth_limit_gb": 100,        // 0 = unlimited
  "max_records": 100,
  "ssl_allowed": true,
  "rate_limit_rps": 0,              // legacy global per-IP limit, 0 = off
  "features": {
    "waf": true,
    "ddos": true,
    "load_balancer": true,
    "image_optimization": true,
    "custom_ssl": true,
    "dnssec": true,
    "max_page_rules": 10,
    "max_firewall_rules": 20,
    "max_ratelimit_rules": 5,
    "max_pools": 3
  }
}
```
PATCH plan merges `features` keys (unknown keys rejected). Defaults for a new
site = the values above. When a feature is off the controller rejects writes to
that section with 403 and the edge config treats it as disabled.

---------------------------------------------------------------------------
## 2. Site configuration sections

Read all: `GET /api/v1/sites/{domain}` → includes `"config": {<section>: ...}`
for every section below.
The site object also carries `"edge_ips": ["5.160.1.10", ...]` — public IPs of all enabled
edges (for the customer's origin firewall allow-list and real-IP configuration).
Read one: `GET /api/v1/sites/{domain}/config/{section}`.
Replace one: `PUT /api/v1/sites/{domain}/config/{section}` with the full section
body; response = the stored (normalised) section. Sections:

### cache
```json
{
  "enabled": true,
  "dev_mode": false,
  "level": "standard",            // "standard": honour origin Cache-Control, force-cache static files
                                  // "aggressive": cache every 200/301 response for edge_ttl (ignores Cache-Control/Set-Cookie)
  "edge_ttl": 86400,              // seconds, 60..31536000
  "browser_ttl": 0,               // 0 = keep origin header
  "ignore_query": false,          // drop the query string from the cache key
  "bypass_cookies": ["wordpress_logged_in", "PHPSESSID"],  // any cookie whose name starts with one of these → no cache
  "always_online": true           // serve stale on origin errors
}
```
(v1 `settings` fields `cache_enabled`, `dev_mode`, `edge_cache_ttl`,
`browser_cache_ttl` stay readable/writable through PATCH /settings and map onto
this section.)

### ssl
```json
{
  "force_https": false,
  "hsts": {"enabled": false, "max_age": 31536000, "include_subdomains": false, "preload": false},
  "min_tls": "1.2",               // "1.2" | "1.3"
  "origin_protocol": "http",      // "http" | "https"
  "origin_verify": false          // verify the origin certificate when origin_protocol=https
}
```
Custom certificate: `PUT /api/v1/sites/{d}/ssl/custom {"cert": PEM chain, "key": PEM}` →
validated (key matches, not expired, covers the domain) → ssl.status=active,
ssl.source="custom". `DELETE /api/v1/sites/{d}/ssl/custom` → back to Let's Encrypt
(status pending). Site `ssl` object gains `"source": "letsencrypt"|"custom"|null`
and `"names": ["example.com","*.example.com"]`.

### waf
```json
{
  "mode": "off",                  // "off" | "detect" (log only) | "block"
  "paranoia": 1,                  // 1..3 — higher enables more (noisier) signatures
  "groups": ["sqli", "xss", "lfi", "rce", "php", "scanner", "protocol"],
  "exclusions": [ {"rule_id": 942100, "path": "/api/*"} ]  // path optional ("*" wildcard); rule_id 0 = all rules on that path
}
```

### ddos
```json
{
  "mode": "off",                  // "off" | "auto" | "js" | "captcha"
                                  // auto: when requests to the site on ONE edge exceed `threshold_rps`
                                  //       (10 s window) every visitor without clearance gets the JS challenge
                                  // js / captcha: every visitor without clearance is challenged
  "threshold_rps": 200,
  "clearance_ttl": 3600           // seconds the clearance cookie stays valid
}
```

### firewall
Ordered list, first matching rule wins, max `features.max_firewall_rules`:
```json
{
  "default_action": "allow",      // "allow" | "block"
  "rules": [
    {
      "id": "r1",                 // client supplied or generated, [a-z0-9_-]{1,32}
      "name": "Block bad country",
      "enabled": true,
      "action": "block",          // "allow" | "block" | "challenge" (JS) | "captcha" | "log"
      "conditions": [             // ALL must match
        {"field": "country", "op": "in", "value": ["CN", "RU"]}
      ]
    }
  ]
}
```
Fields: `ip` (ops: `in`/`not_in` with CIDR list), `country` (`in`/`not_in`,
ISO-3166 alpha-2), `path` / `host` / `query` / `user_agent` / `referer` / `method`
(ops: `eq`, `ne`, `contains`, `not_contains`, `starts_with`, `ends_with`,
`regex`, `in`, `not_in`), `header` (same string ops, plus `"name": "X-Header"`).
`value` is a string, or a list of strings for `in`/`not_in`. String compares
are case-insensitive except `regex` (JS regex, flags "i"). `allow` skips WAF,
DDoS and rate limits for that request. `log` records a security event and
continues evaluation.

### ratelimit
```json
{
  "rules": [
    {"id": "login", "enabled": true, "path": "/wp-login.php*", "methods": ["POST"],
     "requests": 10, "period": 60, "action": "block", "block_seconds": 600}
  ]
}
```
Counted per client IP per edge; `action`: "block" (429) | "challenge" | "captcha".
`methods` empty = all. Max `features.max_ratelimit_rules`.

### pagerules
Ordered, first match wins, max `features.max_page_rules`:
```json
{
  "rules": [
    {"id": "p1", "enabled": true, "pattern": "/wp-admin/*",
     "cache": "bypass",           // null | "bypass" | "standard" | "everything"
     "edge_ttl": null, "browser_ttl": null, "ignore_query": null,
     "waf": null,                 // null | false (disable WAF on these paths)
     "redirect": null             // null | {"url": "https://example.com/new", "code": 301}
    }
  ]
}
```
`pattern` is a URL path starting with `/`; `*` matches any characters (including `/`).
Page rules apply to every proxied host of the site.

### pools (load balancer)
Max `features.max_pools`, requires `features.load_balancer`:
```json
{
  "pools": [
    {
      "name": "main",             // [a-z0-9_-]{1,32}, referenced by records
      "method": "weighted",       // "weighted" (weighted random) | "ip_hash" (sticky)
      "protocol": "http",         // protocol towards these origins
      "origins": [
        {"address": "185.1.2.3", "port": 80, "weight": 10, "backup": false},
        {"address": "origin2.example.net", "port": 8080, "weight": 5, "backup": true}
      ],
      "health": {"enabled": true, "path": "/", "interval": 10, "timeout": 3,
                 "expect": "2xx,3xx", "host": null}
    }
  ]
}
```
Backup origins are used only when all non-backup origins are down. If every
origin is down the edge still tries a non-backup origin (fail open).

### headers
```json
{
  "request":  [ {"name": "X-From-CDN", "value": "pasargad"} ],   // added/overridden towards origin
  "response": [ {"name": "X-Frame-Options", "value": "SAMEORIGIN"},
                {"name": "Server", "value": null} ]              // null = remove
}
```
Header names `[A-Za-z0-9-]{1,64}`, values printable ASCII ≤ 512 chars without `"`.
Max 20 each. Hop-by-hop / Host / Content-Length are rejected.

### hotlink
```json
{"enabled": false, "extensions": ["jpg","jpeg","png","gif","webp","svg","mp4"],
 "allowed_referers": ["example.com", "*.example.com", "google.com"], "allow_empty": true}
```

### image
```json
{"enabled": false, "quality": 85, "max_width": 2000}
```
When enabled, jpg/png/gif/webp URLs accept `?width=N&height=N` (either one) and
are resized at the edge (result is cached). Requires `features.image_optimization`.

### errorpages
```json
{"5xx": "<html>…</html>" | null, "4xx": "<html>…</html>" | null}   // ≤ 64 KB each
```

---------------------------------------------------------------------------
## 3. Records (additions)

Record object gains:
- `pool`: string|null — only for proxied A/AAAA/CNAME. When set the edge sends
  this hostname's traffic to that load-balancer pool; `content` stays as the
  DNS fallback when no edge is online.
- `origin_port`: int|null — port on the origin for proxied records without pool
  (default 80/443 by protocol).
- `health_check`: bool — only for NON-proxied A/AAAA. When several records of the
  same name+type exist and any has `health_check=true`, PowerDNS returns only the
  addresses whose TCP port `health_port` (default 80) answers.
- `health_port`: int|null.
- new type `ALIAS` (CNAME-like, allowed on `@`, resolved by PowerDNS, never proxied).

Import / export:
- `POST /api/v1/sites/{d}/records/import {"zone": "<BIND text>", "replace": false}` →
  `{"imported": n, "skipped": [{"line": "...", "reason": "..."}]}`
- `GET /api/v1/sites/{d}/records/export` → `{"zone": "<BIND text>"}`

DNSSEC:
- `POST /api/v1/sites/{d}/dnssec {"enabled": true}` → `{"enabled": true, "ds": ["12345 13 2 ABCD…"], "dnskey": "257 3 13 …"}`
- `GET /api/v1/sites/{d}/dnssec` → same shape (`enabled:false, ds:[]` when off).

---------------------------------------------------------------------------
## 4. Analytics & security events

- `GET /api/v1/sites/{d}/analytics?period=24h|7d|30d` →
```json
{
  "period": "24h",
  "totals": {"requests": 0, "bytes": 0, "cache_hits": 0,
             "status": {"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0},
             "security": {"waf": 0, "firewall": 0, "ratelimit": 0, "challenge": 0, "ddos": 0, "hotlink": 0}},
  "series": [ {"t": "2026-09-28T10:00:00Z", "requests": 0, "bytes": 0, "cache_hits": 0} ],   // hourly for 24h, daily otherwise
  "countries": [ {"code": "IR", "requests": 0} ],   // top 20
  "paths": [ {"path": "/", "requests": 0} ],         // top 20
  "status_codes": [ {"code": 200, "requests": 0} ]   // top 10
}
```
- `GET /api/v1/sites/{d}/events?limit=100` → newest first:
```json
[ {"t": "…Z", "ip": "1.2.3.4", "country": "IR", "method": "GET", "host": "example.com",
   "path": "/x?y", "action": "block", "source": "waf", "rule": "942100", "user_agent": "…"} ]
```
`source` ∈ waf | firewall | ratelimit | ddos | hotlink. `action` ∈ block | challenge | captcha | log.
Controller keeps the newest 1000 events per site.

---------------------------------------------------------------------------
## 5. Edge ↔ controller

### GET /edge/v1/config (ETag / If-None-Match as in v1)
```json
{
  "version": "<sha256>",
  "sites": [
    {
      "id": 7,
      "domain": "example.com",
      "status": "active",                 // active | pending_ns | suspended | over_quota
      "secret": "<64 hex>",               // per-site HMAC key for challenge cookies
      "hosts": [
        {"name": "example.com", "origin": {"address": "185.1.2.3", "port": null}},
        {"name": "www.example.com", "origin": {"pool": "main"}}
      ],
      "ssl": {"cert": "PEM", "key": "PEM"} | null,
      "rate_limit_rps": 0,
      "blocked_ips": ["1.2.3.4/32"],
      "cache": {...section...},           // dev_mode already folded in: enabled=false when dev_mode
      "ssl_options": {...ssl section...}, // force_https is false when there is no certificate
      "waf": {...} ,                       // mode "off" when feature disabled
      "ddos": {...},
      "firewall": {...},
      "ratelimit": {...},
      "pagerules": {...},
      "pools": {...},
      "headers": {...},
      "hotlink": {...},
      "image": {...},                      // enabled false when feature disabled
      "errorpages": {...}
    }
  ]
}
```
Only sites with at least one proxied host are included (as in v1).
Hosts are fully-qualified; `origin.address` is an IPv4, `[IPv6]` or hostname.

### POST /edge/v1/usage
```json
{
  "items": [
    {"host": "example.com", "hour": "2026-09-28T10:00:00Z",
     "bytes": 1234, "requests": 10, "cache_hits": 7,
     "status": {"2xx": 9, "4xx": 1},
     "codes": {"200": 9, "404": 1},
     "countries": {"IR": 8, "DE": 2},
     "paths": {"/": 6, "/a.css": 4},        // edge keeps at most 50 paths per host-hour
     "security": {"waf": 1}}
  ],
  "events": [
    {"t": "…Z", "host": "example.com", "ip": "…", "country": "IR", "method": "GET",
     "path": "/?id=1'or'1", "action": "block", "source": "waf", "rule": "942100", "user_agent": "…"}
  ]
}
```
`status/codes/countries/paths/security` and `events` are optional (v1 agents omit them).
Max 20 000 items and 2 000 events per request.

### Edge access log (nginx `log_format pcdn`, one JSON object per line)
`{"t", "h" host, "b" bytes_sent, "s" status, "c" upstream_cache_status,
  "ip", "cc" country, "m" method, "u" request_uri, "ua" user agent,
  "v" verdict}` where verdict is `ok` or `<action>:<source>:<rule>`
(e.g. `block:waf:942100`, `challenge:ddos:auto`, `block:ratelimit:login`,
`log:firewall:r3`). The agent derives security counters and events from `v`.
Wave 6D appends (older lines without them stay valid): `"us"` upstream status (`""` = no upstream
contacted), `"pg"` (`site` for the suspended / over-quota page), `"sc"` scheme, `"pr"` protocol,
`"rf"` referer — see §14.3.1 / §14.3.2.

### Reload discipline (how the edge applies a new config)
The config body is the unit of propagation, but applying it must not send a GOAWAY to every HTTP/2
tunnel on each site edit. The agent therefore:
- **Coalesces reloads** (F5): a new `version` is applied only once it has *settled* (seen on two
  polls, or pending for `RELOAD_MIN_INTERVAL`, default 120 s) and never more often than
  `RELOAD_MIN_INTERVAL`; a freshly-seen version first waits `RELOAD_DEBOUNCE` (5 s). A burst of edits
  collapses into one reload; config latency stays roughly 20-140 s. First boot (no tree yet) applies
  immediately. The controller additionally rate-limits config/record *writes* on the customer API
  (`CAPI_CONFIG_RATE`, default 6/min, on top of `CAPI_RATE`) so a client cannot herd fleet-wide
  reloads; reads, purges and stats stay on `CAPI_RATE`.
- **Skips no-op reloads** (F20): the agent renders first and compares a SHA-256 digest of the whole
  tree; a byte-identical result is not written, tested or reloaded (this absorbs version bumps from
  fields the agent never renders, and agent upgrades). Rendering is deterministic. The digest is
  recorded only after a successful reload, so a failed apply never suppresses a later corrective one.
- **Defers foreign-group changes** (F21): every node still receives every site's config (DNS
  fail-open needs it), but when every changed site belongs to another edge group — and no global file
  (`http.conf`/`pcdn.js`) changed and no site was added, removed, suspended or had its cert rotated —
  the apply is deferred up to `FOREIGN_DEFER` (900 s) and folded into the next own-group reload, so a
  tunnel-role node does not reload for general-website edits. The node keeps heartbeating during the
  deferral so it is not marked stale.
- **Bounds draining workers** (F6): `worker_shutdown_timeout` (default `1h`, install flag
  `--shutdown-timeout`) caps how many generations of draining workers a reload leaves pinned by
  long-lived tunnels before they are reclaimed. It is main-context (global) and must never be set in
  seconds (that turns every reload into a hard cut of every tunnel); lower to 20-30m on ≤4 GB nodes.
- **Verifies the reload** (F29): after the reload command the agent polls a localhost-only
  `/__pcdn/confver` (which returns the tree digest) for a few seconds; if the nginx master rejected
  the reload the agent does **not** store the ETag, reports the error in the heartbeat and retries on
  the next poll, instead of reporting a rejected reload as applied. `RELOAD_VERIFY=no` disables it.

---------------------------------------------------------------------------
## 6. Platform-wide (WHMCS admin panel)

- `GET /api/v1/overview` →
```json
{"sites": {"total": 12, "by_status": {"active": 9, "pending_ns": 2, "suspended": 1}},
 "edges": {"total": 3, "enabled": 3, "online": 2, "with_errors": 0, "shed": 0,
           "list": [{"id": 1, "name": "ir1", "group": "tunnel", "enabled": true, "online": true, "shed": false,
                     "capacity_mbps": 1000, "metrics": {...}|null, "uptime": {"h24": 100.0, "d30": 99.8}}]},
 "month": {"start": "2026-09-01T00:00:00Z", "bytes": 0, "requests": 0, "security": {"waf": 0}},
 "top_sites": [{"domain": "example.com", "bytes": 0, "requests": 0}],
 "nameservers": ["ns1.pasargadmizban.com", "ns2.pasargadmizban.com"]}
```
- `GET /api/v1/events?limit=100&source=waf` → like §4 events, newest first, across all sites, each with `"domain"`.
- `GET /api/v1/edges/{id}/uptime?days=30` → `{"days": [{"day": "YYYY-MM-DD", "uptime": <%>|null}, ...],
  "overall": <%>|null}` (uptime is null for a day/window with no samples). Availability is sampled every
  scheduler tick into a per-edge/per-hour rollup; % = online samples / total samples.
- Existing: `GET /api/v1/sites` (domain, status, external_id), `GET /api/v1/usage?month=YYYY-MM`,
  `GET/POST /api/v1/edges`, `PATCH /api/v1/edges/{id}?enabled=true|false`,
  `POST /api/v1/edges/{id}/rotate-token`, `DELETE /api/v1/edges/{id}`, `GET /api/v1/ping`.
  Edge object: `{id, name, ipv4, ipv6, region ("home"|"global"), enabled, last_seen_at, applied_version,
  last_error, group, capacity_mbps, metrics, shed, uptime: {"h24": <%>|null, "d30": <%>|null}}`;
  create/rotate responses include `"token"` exactly once. An edge is "online" when last_seen_at is
  within EDGE_OFFLINE_SECONDS (default 180 s); the "node offline" alert fires earlier, at
  EDGE_ALERT_SECONDS. `edge_health:{id}` alerts on sustained high CPU load or (with a recent agent)
  a full disk/memory.

---------------------------------------------------------------------------
## 7. Tunnel mode (VPN-over-CDN: WebSocket, HTTPUpgrade, gRPC, XHTTP, raw HTTP/2)

Goal: customers run Xray/V2Ray/sing-box behind the CDN. Visitors (mostly in Iran)
reach a domestic edge; the edge relays long-lived streams to the customer's origin
with no buffering, no caching and no security filters in the way.

### 7.1 Plan features (additions to §1 `features`)
```json
{
  "tunnel": false,                 // section `tunnel` may be enabled
  "max_tunnel_paths": 10,          // 0..50
  "max_tunnel_connections": 0,     // per site per edge (concurrent), 0 = unlimited
  "tunnel_max_mbps": 0,            // cap for tunnel.per_connection_mbps, 0 = no cap
  "edge_group": "general"          // "general" | "tunnel": which edges DNS answers with (§7.4)
}
```
Defaults above apply to existing sites (tunnel off, group general).

**Product packaging (WHMCS):** tunnel is bundled into every shipped CDN plan — the WHMCS
plans wizard enables `features.tunnel` (with per-tier `max_tunnel_paths`/`max_tunnel_connections`)
on all CDN plans, all on the `general` edge group (served by every node), and no longer creates a
separate tunnel product. So buying any CDN service also grants tunnel, with tunnel traffic billed
from the same plan's bandwidth/wallet — no separate purchase or cost. An admin bulk action turns
tunnel on for already-provisioned CDN services. `edge_group` stays configurable for operators who
later want to dedicate `tunnel` nodes; the platform still supports both groups (§7.4).

### 7.2 Section `tunnel` (requires `features.tunnel`, else PUT → 403 and edge gets `enabled:false`)
```json
{
  "enabled": false,
  "paths": [
    {
      "id": "grpc1",                    // [a-z0-9_-]{1,32}, unique
      "path": "/my-secret-service",     // prefix match, "/" + [A-Za-z0-9._~/-]{1,200}, unique, not "/" alone,
                                        // must not start with "/__pcdn"
      "protocol": "grpc",               // "ws" | "httpupgrade" | "grpc" | "xhttp" | "h2"
      "origin": null,                   // null = the host's own origin (record content / pool)
                                        // or {"address": "1.2.3.4"|"host.name"|"[v6]", "port": 1..65535,
                                        //     "tls": false, "sni": null, "verify": false}
                                        // (port omitted → 443 when tls else 80; stored normalised)
      "pool": null                      // or a pool name from section `pools` (mutually exclusive with origin)
    }
  ],
  "idle_timeout": 3600,                 // seconds 60..86400: read/send timeout of tunnel streams
  "per_connection_mbps": 0,             // 0 = unlimited; <= features.tunnel_max_mbps when that is > 0
  "max_connections_per_ip": 0,          // 0 = unlimited, 0..10000 (per edge)
  "allowed_countries": [],              // ISO codes; [] = everyone. Others get 403 on tunnel paths
  "fallback": "origin"                  // other paths: "origin" (normal site) | "decoy" (built-in neutral
                                        // page, 200) | "404"
}
```
Max `features.max_tunnel_paths` paths. Controller validates everything above (Persian `detail` on
error; like the other sections: 422 for invalid values, 403 for plan limits — too many paths,
`per_connection_mbps` above `tunnel_max_mbps`, or enabling without `features.tunnel`).
`per_connection_mbps: 0` is accepted; when the plan has a cap the edge config carries the cap instead.
A pool referenced by a tunnel path cannot be removed from section `pools` (422). Protocol semantics on the edge:
- `ws` / `httpupgrade`: HTTP/1.1 `proxy_pass` with `Upgrade`/`Connection` forwarded.
- `grpc`: `grpc_pass grpc://` (or `grpcs://` when origin.tls) — client side needs HTTP/2 (TLS).
- `xhttp`: HTTP/1.1 `proxy_pass`, `proxy_buffering off`, `proxy_request_buffering off`,
  `proxy_http_version 1.1`, chunked both ways (XHTTP packet-up / stream-up over HTTP/1.1).
- `h2`: raw HTTP/2 streams to an h2c/h2 origin through `grpc_pass` (XHTTP stream-one/stream-up
  with an h2c inbound).
All tunnel locations: no cache, no WAF/DDoS challenge/firewall-challenge/ratelimit/hotlink/image/
headers-response rewriting/gzip/brotli; firewall *block* rules and `blocked_ips` still apply;
`client_max_body_size 0`; timeouts = idle_timeout; `limit_rate` = per_connection_mbps;
`limit_conn` per site (`features.max_tunnel_connections`) and per IP (`max_connections_per_ip`);
TCP_NODELAY; upstream keepalive where the protocol allows.

**Session affinity (xhttp/h2 on multi-origin pools).** For `xhttp` and `h2` paths the edge selects
the origin per *session*, not per request: it hashes a session id parsed from the request path
(weighted rendezvous / HRW, so an origin health change only moves the sessions that were on the
failed origin) and falls back to the client IP when no id can be parsed. This keeps every packet-up
POST and every stream of one session on one origin. It therefore **requires the client to carry a
session id in the path** — Xray's XHTTP does, as `/<base>/<session>/<seq>`. A multi-origin `pool`
(explicit on the path or inherited from the host) or a multi-A origin hostname *without* a path
session id would otherwise split one session across origins. `ws` and `grpc` are unaffected (each is
one TCP connection / stream), and a single-origin path needs nothing. The controller returns a
Persian warning on PUT `tunnel` when an `xhttp`/`h2` path uses a pool with more than one non-backup
origin.

### 7.3 Edge config (§5) additions
Per site: `"tunnel": {...section..., "max_connections": <features.max_tunnel_connections>}`
(`enabled:false` when the feature is off or the site is not active; `per_connection_mbps` already
capped by `features.tunnel_max_mbps`; paths beyond `max_tunnel_paths` or whose pool is not in the
site's `pools` are left out). Tunnel requests are logged with
two extra access-log fields: `"tn"` protocol, `"rt"` request_time seconds, and `"bu"` bytes received
from the client (`$request_length` + upstream-bound bytes where nginx reports them); `"b"` stays bytes
sent to the client. Usage item optional field:
`"tunnel": {"sessions": 3, "seconds": 5400, "bytes_up": 123, "bytes_down": 456, "by_protocol": {"grpc": 579}}`.
For billing, the controller adds `bytes_up` of tunnel traffic to `bytes` (both directions are charged).
`by_protocol` values are bytes (up + down); keys other than the five protocols are ignored.

### 7.4 Edge groups and load-aware DNS
- Edge object gains `"group": "general" | "tunnel"` (default general) and `"capacity_mbps"` (int, 0 = unknown).
  `POST /api/v1/edges` accepts both; `PATCH /api/v1/edges/{id}` accepts JSON body
  `{"enabled"?, "group"?, "capacity_mbps"?, "region"?}` (query `?enabled=` keeps working).
- Every edge still receives every site's config. DNS answers for a site use only online edges of the
  site's `features.edge_group`; if that group has no online edge, all online edges are used (fail open).
- Heartbeat (`POST /edge/v1/heartbeat`) optional metrics:
  `{"metrics": {"rx_mbps": 12.5, "tx_mbps": 80.1, "connections": 1532, "load1": 0.8, "cpus": 4,
   "disk_pct": 41.0, "mem_pct": 63.5}}`. `disk_pct` (cache/nginx filesystem) and `mem_pct` are
  optional — older agents omit them and the controller then raises no disk/memory alert for that edge.
  Controller keeps the latest per edge (edge object: `"metrics": {..., "at": "…Z"}` or null, plus
  `"shed": bool`). PATCH responses are `{"ok": true, "dns_failed": n, "edge": {...edge object...}}`.
- Load shedding: an edge whose `max(rx,tx)_mbps >= EDGE_SHED_PERCENT (default 90) % of capacity_mbps`
  (capacity > 0) is left out of DNS answers while at least one other edge of the same group+region pool
  stays in; it returns below `EDGE_SHED_PERCENT - 15`%. Alert `edge_saturated:{id}` when shed or > 80 % for
  3 consecutive heartbeat metric reports. Metrics older than EDGE_OFFLINE_SECONDS never shed an edge.

### 7.5 Customer API (through the WHMCS proxy, same as other sections)
`GET/PUT /api/v1/sites/{domain}/config/tunnel`.
`GET /api/v1/sites/{domain}/tunnel/stats?hours=24` →
`{"hours": [{"hour": "…Z", "sessions": 3, "seconds": 5400, "bytes_up": 1, "bytes_down": 2}],
  "by_protocol": {"grpc": 579}, "totals": {"sessions": 3, "bytes_up": 1, "bytes_down": 2}}`.
`POST /api/v1/sites/{domain}/tunnel/check` → `{"results": [{"id": "grpc1", "ok": true, "ms": 42,
 "error": null}]}`: the controller opens a TCP (and TLS when origin.tls) connection to each path's
effective origin (timeout 5 s) so customers can see whether their VPN server is reachable.
Effective origin: `origin`; else every origin of `pool` (ok when any answers; TLS when the pool's
protocol is https); else the apex's proxied record (or the first proxied host). SNI = `origin.sni` or
the site domain. Addresses that are not public (after DNS resolution) are never contacted.
`hours` is clamped to 1..744; `hours` has one zero-filled entry per hour, oldest first.

---------------------------------------------------------------------------
## 8. Reliability: synthetic edge probes, public status, incidents (WAVE 1)

Goal: catch a node that still heartbeats but serves errors (e.g. a bad `nginx -t`), give
customers a public status page, and let the operator post incidents.

### 8.1 Synthetic edge probes
- A scheduler job (`job_probe`, every ~60s, leader only) requests `http://<edge.ipv4>/__pcdn/health`
  with `Host: health.pcdn` for every ENABLED edge, records latency and ok/fail, and (when the edge
  also has IPv6 and PROBE_IPV6) the v6 address too. Timeout `PROBE_TIMEOUT` (default 5s). Never raises.
- Stored on the Edge object as transient fields (not a new table): `probe_ok` (bool|null),
  `probe_ms` (int|null), `probe_at` (iso|null), `probe_error` (str|null). Migration 0005 adds them.
- Alert `edge_probe:{id}` (warning) when an edge is heartbeating (last_seen fresh) but its probe has
  failed `PROBE_FAIL_CHECKS` (default 3) times in a row — i.e. "reporting but broken". Resolves when a
  probe succeeds. Distinct from `edge_offline` (no heartbeat) and `edge_saturated`/`edge_health`.
- `GET /api/v1/edges` edge object gains `probe: {ok, ms, at, error}`; `/healthz/deep` `edges` block
  gains `probe_failing` (count).

### 8.2 Public status (no auth, no secrets)
- `GET /status.json` (public, on the health_router, never requires the admin key) →
```json
{"status": "operational|degraded|maintenance|major_outage",
 "updated_at": "…Z",
 "nodes": {"total": 6, "online": 6},          // counts only, NEVER IPs/names/locations
 "components": [{"name": "شبکه توزیع محتوا (CDN)", "status": "operational"},
                {"name": "سرویس تونل", "status": "operational"},
                {"name": "DNS", "status": "operational"}],
 "incidents": [{"id": 3, "title": "...", "body": "...", "severity": "minor|major|maintenance",
                "status": "investigating|identified|monitoring|resolved",
                "created_at": "…Z", "updated_at": "…Z",
                "updates": [{"at": "…Z", "status": "...", "body": "..."}]}]}   // open + last 10 resolved
```
  Overall status = worst of: open incidents' severity, DNS reachability, and node availability
  (major_outage when 0 nodes online, degraded when some down or a component degraded). It exposes
  only aggregate counts and operator-written incident text — never a node IP, name, region, customer
  domain, or any metric that could identify infrastructure.
- A standalone static page `status/index.html` (in the repo, self-contained, RTL Persian, light/dark)
  polls `/status.json` and renders it. The operator hosts it on any domain (or the WHMCS host).

### 8.3 Incidents (admin)
- Model `Incident` (id, title, body, severity, status, created_at, updated_at) and `IncidentUpdate`
  (incident_id, status, body, created_at). Migration 0005.
- Admin API (needs the admin key):
  - `GET /api/v1/incidents?all=1` (open, or all with `all=1`, newest first),
  - `POST /api/v1/incidents` {title, body, severity, status?},
  - `POST /api/v1/incidents/{id}/updates` {status, body} (also moves the incident's status),
  - `PATCH /api/v1/incidents/{id}` {title?, body?, severity?, status?}.
  Resolving (`status: resolved`) sets updated_at; resolved incidents drop off `/status.json` after 10.
- WHMCS admin: an "وضعیت و رخدادها" page to create/update/resolve incidents and see the public status.

---------------------------------------------------------------------------
## 9. CDN features wave 2: platform analytics + prefix/everything purge

### 9.1 Platform-wide analytics (admin)
`GET /api/v1/analytics?period=24h|7d|30d` (admin key) → same shape as §4 site analytics but
aggregated across ALL sites, plus `sites` (top sites by requests):
```json
{"period": "24h",
 "totals": {"requests": 0, "bytes": 0, "cache_hits": 0,
            "status": {"2xx":0,"3xx":0,"4xx":0,"5xx":0},
            "security": {"waf":0,"firewall":0,"ratelimit":0,"challenge":0,"ddos":0,"hotlink":0}},
 "series": [{"t":"…Z","requests":0,"bytes":0,"cache_hits":0}],   // hourly for 24h, daily otherwise
 "countries": [{"code":"IR","requests":0}],   // top 20
 "sites": [{"domain":"example.com","requests":0,"bytes":0}],     // top 20
 "security_series": [{"t":"…Z","events":0}]}                     // total security events per bucket
```
Computed from UsageHourly (same store the per-site analytics uses); one pass, bounded.

### 9.2 Purge by prefix / everything
`POST /api/v1/sites/{d}/purge` body extends: `{"urls": [...], "prefixes": ["/blog/", "https://ex.com/img/"],
"everything": false}`. `everything:true` purges the whole site cache (already the `urls:[]` behaviour).
`prefixes` are path prefixes (with optional scheme+host); each ≤ 200, up to 20.
- Purge object / `/edge/v1/purges` item gains `prefixes: [...]` and `everything: bool`.
- Edge `do_purge`: for `everything` (or empty urls with everything flag) wipe the site cache dir
  (existing behaviour). For `prefixes`, scan the site's cache files, read each file's `KEY:` header
  line (nginx writes `KEY: <scheme>://<host><uri>` near the top of every cache file) and delete files
  whose key path starts with a requested prefix (match against the path part, host optional). Bounded:
  cap files scanned at `PURGE_SCAN_MAX` (default 500000); if exceeded, fall back to a full-site purge
  and report it. Never raises. Exact-URL purges keep the existing fast hashed-key delete.
- The controller counts a prefix/everything purge toward the same 100-item limit and validates prefixes
  like URLs (Persian errors).

---------------------------------------------------------------------------
## 10. Wave 3: customer API, smart usage, reseller, billing & email

### 10.1 Customer API (per-service key)
- New model `ApiKey` (id, site_id FK, key_hash, name, scopes JSON, last_used_at, created_at,
  revoked bool). Migration 0007. A site may have up to 5 keys.
- Admin/customer (through the WHMCS proxy) manages keys:
  `GET /api/v1/sites/{d}/apikeys`, `POST /api/v1/sites/{d}/apikeys {name, scopes}` → returns the
  plaintext key ONCE (prefix `pcdn_` + 40 hex), `DELETE /api/v1/sites/{d}/apikeys/{id}`.
- A NEW public API surface `/capi/v1/*` authenticated by `Authorization: Bearer pcdn_...` (NOT the
  admin key). The key resolves to its site; every call is scoped to that site only. Scopes:
  `purge`, `stats`, `dns`. Endpoints:
  - `POST /capi/v1/purge {urls?, prefixes?, everything?}` (scope purge) — same as §9.2 for that site.
  - `GET /capi/v1/analytics?period=` , `GET /capi/v1/events?limit=` (scope stats) — §4 for that site.
  - `GET/POST/PATCH/DELETE /capi/v1/records...` and `GET/PUT /capi/v1/config/{section}` (scope dns) —
    the same record/section operations as the admin API, restricted to that site.
  Rate-limited per key (`CAPI_RATE`, default 60/min, 429 on excess). `last_used_at` updated. A revoked
  or unknown key → 401. Never exposes other sites. Errors: JSON `{"detail": "..."}` (English or Persian).
- Docs: `docs/API.md` (Persian + English) with examples (curl) for each scope.

### 10.2 Smart usage alerts + upgrade suggestion (WHMCS)
- The prepaid engine already buys traffic / cuts at cap. Add, without changing billing correctness:
  - A per-service usage-forecast: from the last N days' daily usage, estimate days-to-cap; when a
    service is predicted to exhaust its month's included traffic early (configurable threshold), send
    ONE Persian "پیش‌بینی اتمام ترافیک" email and show a banner in the client app.
  - Upgrade suggestion: when a service buys traffic (top-up) more than K times in a month, or its
    usage exceeds its plan's included traffic by a margin, show a client-app suggestion to move to a
    bigger plan (with the WHMCS upgrade link) and, optionally, an admin flag on the service list.
  - All new emails go through the same WHMCS mail path; dedupe so a customer isn't spammed (once per
    service per month per alert type, tracked in the module's state table).

### 10.3 Live-er usage in the client app
- The client overview + a usage page show current-month used/included/remaining with a live-updating
  bar, today's usage, and a small forecast line ("با این روند، ترافیک شما حدود X روز دیگر تمام می‌شود").
  Uses existing analytics/usage data; no new controller endpoint required beyond §4/§9.

### 10.4 Billing & invoices
- Clearer Persian invoice/line-item descriptions for traffic top-ups (date range, GB, rate) and a
  client "صورت‌حساب و مصرف" statement view combining top-ups + usage. Admin usage report gains a
  per-service revenue column (sum of top-up invoices) and CSV export of it.

### 10.5 Reseller (WHMCS)
- A WHMCS client can be marked a **reseller** (admin toggles it; stored in the module's state/table).
- Resellers get a dedicated client-area panel (a page in the CDN client module, shown only to reseller
  accounts) to provision and manage CDN sites for their OWN end-customers: create a site (domain +
  origin), manage its DNS/config/cache/tunnel exactly like a normal service, and see per-site usage.
  Each reseller sub-site is a controller Site tagged with the reseller's WHMCS client id and a free-text
  end-customer label; it does NOT create a separate WHMCS login.
- Wholesale billing: reseller sites bill the reseller's wallet at a configurable wholesale GB rate
  (admin sets a global reseller rate and/or per-reseller override). The prepaid engine's buy-traffic /
  cut-at-cap logic applies to the reseller's aggregate wallet. Resellers see a rolled-up usage & cost
  report across all their sub-sites, and per-sub-customer breakdown.
- Admin: a reseller list (clients flagged reseller), their sub-site counts, usage and wholesale
  revenue; set/override the wholesale rate; enable/disable a reseller.
- Guardrails: a reseller can only see/manage its own sub-sites; nothing crosses tenants. Limits:
  max sub-sites per reseller (configurable). All Persian UI.

## 11. Scale & operations wave 4: fast node provisioning, centralized logs, runbook

Goal: make adding, upgrading and troubleshooting edge nodes fast and observable, so the
platform scales to many nodes without hand-work. No anti-filtering scope. All operator/UI
text Persian; controller code English with Persian log strings where the module already does.

### 11.1 Fast node provisioning
- **One-command install.** `edge/bootstrap.sh` is a tiny remote installer: given `--controller <url>`
  and `--token edge_xxx`, it downloads the edge bundle from the controller, unpacks it and runs
  `install.sh` with the same flags. Target one-liner:
  `curl -fsSL https://<controller>/edge/bootstrap.sh | sudo PCDN_EDGE_TOKEN=edge_xxx bash -s -- --controller https://<controller>` (token via env since wave 9; `--token` still accepted)
  It passes through `--region home|global`, `--role general|tunnel` (maps to the edge group),
  `--cache-size`, `--http-port`, `--https-port`, `--no-ipv6`, `--no-geoip`, `--upgrade`.
- **Controller serves the (secret-free) bundle.** `GET /edge/bootstrap.sh` returns the bootstrap
  script (text/x-shellscript); `GET /edge/bundle.tar.gz` returns a gzip tar of the edge/ tree
  (agent, nginx/njs/pages templates, install.sh, systemd, geoip updater). No auth — the bundle is
  the open-source agent and templates and holds NO secrets, keys or tokens. The bundle is read from
  `EDGE_BUNDLE_DIR` (config; default the image's baked copy of edge/); if it is absent both routes
  return 404 with a clear message and the admin panel falls back to the manual git/scp instructions.
  `GET /edge/install?token=...&region=...&role=...` (admin-token authenticated) returns the ready
  copy-paste one-liner for a specific node.
- **Batch add.** `POST /api/v1/edges/batch` (admin) creates N edges in one call
  (`{count, region, group, name_prefix, capacity_mbps}`) and returns each new edge with its
  one-time token and its install one-liner, so an operator can bring up several nodes at once.
- **Version signalling.** `GET /edge/version` returns the bundle version (a short hash/mtime string);
  the agent records the running bundle version and reports it, and the admin panel flags nodes whose
  running version is behind the controller's current bundle (an "update available" badge). The upgrade
  itself is the operator re-running bootstrap with `--upgrade` (documented) — no remote code push.

### 11.2 Centralized node logs
- **Edge model** gains a capped rolling log buffer: `logs` (Text, JSON list of the most recent
  lines, hard-capped ~16 KiB / ~120 lines, oldest dropped) and `logs_at` (DateTime). Migration adds them.
- **Agent ships recent problems only.** The agent tails the nginx error log and its own agent log and,
  on each heartbeat (or when new error/warn lines appear), POSTs the new WARN/ERROR/crit lines
  (de-duplicated, each line length-capped, at most ~40 per report) to `POST /edge/v1/logs`
  `{lines: [{t, level, msg}]}`. It never ships access logs, request bodies, IPs of visitors, tokens
  or keys — operational error/warn text only. Size-capped so a noisy node cannot flood the controller.
- **Controller** stores them into the edge ring (newest last, capped) and exposes
  `GET /api/v1/edges/{id}/logs` (admin) → `{name, logs_at, lines:[...]}`. `edge_to_dict` gains a
  small `logs_at` / `has_logs` hint (not the full lines).
- **WHMCS admin** Edges page gains a per-node «لاگ‌ها» view (modal or panel) that fetches the lines and
  shows them newest-first with level colouring; empty state when a node has reported none.

### 11.3 Operator UX (WHMCS admin, Edges page)
- Each node shows its copy-paste one-command install (with its one-time token, shown once at creation
  like today) and, for an existing node, the `--upgrade` one-liner and an «به‌روزرسانی موجود است» badge
  when behind the current bundle version.
- A «افزودن گروهی» (batch add) form: count + region + role → a list of ready one-liners to copy.
- Existing add/enable/disable/rotate/delete stay; nothing about billing changes.

### 11.4 Docs (Persian)
- `docs/NODES.md` — node operations runbook: prerequisites, the one-command install, batch add,
  region/role, reading node logs, upgrading a node, decommissioning, and a troubleshooting table
  (node offline, probe failing, config error, saturated/shed, cert issues) cross-linking OPERATIONS.md.
- `edge/cloud-init.yaml.example` — an unattended first-boot template that runs the one-command install.
- Update `docs/OPERATIONS.md` and `docs/EDGE.md` to point at the one-command flow and the log view.

## 12. Multi-address edges & health-based failover (wave: reliability)

Goal: a node can carry more than one address, and traffic automatically stays on a WORKING address
so services do not drop when one address of a node stops responding. Failover is driven ONLY by
health/reachability (the synthetic probe of §8.1), never by any "switch now" control and never by any
signal of filtering/blocking. This is a redundancy/uptime feature for genuinely unreachable addresses;
the controller's probe measures reachability from the controller, so it does not act on filtering.

### 12.1 Data model
- The edge keeps its existing `ipv4` / `ipv6` as its **primary** address (unchanged; editable as today).
- New table `edge_addresses` for **additional** addresses of the same node:
  `id, edge_id (FK edges CASCADE, index), family (4|6), ip (unique per family+ip), label (str<=64),
  enabled (bool, default true), probe_ok (bool|null), probe_ms (int|null), probe_at (dt|null),
  probe_error (text|null), probe_fail (int, default 0), created_at`.
- An address (primary or additional) is **advertised** in DNS when it is `enabled` AND
  (`probe_ok` is true OR `probe_ok` is null, i.e. never probed yet). It is **withdrawn** once its
  `probe_fail >= PROBE_FAIL_CHECKS` (same threshold as the §8.1 alert), and restored on the next
  healthy probe. `enabled=false` (operator maintenance) withdraws it immediately.

### 12.2 Health probing (extends §8.1)
- The scheduler probe job probes EVERY enabled address of every enabled edge (primary + additional),
  each family, storing per-address `probe_ok/ms/at/error/fail`. The edge-level `probe_ok` stays
  "any address of the edge answered" (so the existing edge alert semantics are unchanged).
- A per-address `edge_address_down` alert (dedup/resolve like other alerts) fires when an additional
  address crosses `PROBE_FAIL_CHECKS` and resolves when it recovers. The primary keeps the existing
  edge probe alert.

### 12.3 DNS (extends §7.4 / dnsbuild)
- `edge_pools(edges, family)` collects, per edge, ALL advertised addresses of that family (primary +
  additional), not just the single primary. Load shedding (`is_shed`) and edge group/region rules are
  unchanged and apply at the edge level.
- **Fail-open, always:** if applying health withdrawal would leave a family's pool (for the visitor's
  region/group) EMPTY, the withdrawal is ignored for that pool and the known addresses are advertised
  anyway — the zone is never emptied by health state. This mirrors the existing "if none looks healthy,
  answer anyway" behaviour and must be covered by a test.

### 12.4 Admin API (controller)
- `GET /api/v1/edges/{id}/addresses` → primary + additional with per-address health.
- `POST /api/v1/edges/{id}/addresses` `{family, ip, label?}` — add an additional address (validate IP,
  family match, reject duplicates of any edge's address).
- `PATCH /api/v1/edges/{id}/addresses/{aid}` `{ip?, label?, enabled?}` — edit/enable/disable.
- `DELETE /api/v1/edges/{id}/addresses/{aid}` — remove an additional address.
- Editing the PRIMARY address stays the existing `PATCH /api/v1/edges/{id}` path; document that the
  primary cannot be deleted (it is the node's identity address).
- `edge_to_dict` gains `addresses` (list with health) and per-family `advertised` counts.

### 12.5 WHMCS admin (Edges page)
- Per node, an «آدرس‌ها» panel: shows the primary and any additional addresses with per-address health
  (سالم / در حال بررسی / قطع) and whether each is currently advertised in DNS. Operator can add an
  address, edit/rename it, enable/disable it for maintenance, and remove an additional one; correcting
  the primary uses the existing edit-node form. Persian UI. This is address management + visibility of
  the automatic health-based failover — there is NO "force this IP now" control.

## 13. Observability, audit & operations (wave 5)

Goal: make the platform observable and auditable, and finish the operator documentation. No
anti-filtering scope. Controller code English; operator/UI text Persian.

### 13.1 Prometheus metrics
- `GET /metrics` on the controller: Prometheus text format, exposing NO secrets or per-customer
  identifiers — platform aggregates only: edges total/online/shed/probe_failing; sites total and by
  effective_status; ssl by status + certs expiring ≤ ALERT_CERT_DAYS; dns last-sync age + error count;
  scheduler last-run age per job; usage batches ingested (counter); active alerts (gauge); backup
  last-success age. Auth: if `METRICS_TOKEN` is set, require `Authorization: Bearer <token>`; otherwise
  the endpoint is open (intended for an internal scrape network). Never lists domains, IPs, tokens.

### 13.2 Audit log
- `audit_log` table (migration): `id, at, actor` (admin-key label / customer-key id / "system"),
  `actor_kind` (admin|capi|system), `action` (e.g. site.create, site.plan, site.delete, edge.add,
  edge.rotate, edge.patch, edge.delete, edge.address.add/del, purge, reseller.flag, reseller.rate,
  tunnel.enable_existing), `target` (domain/edge name/…), `detail` (JSON, no secrets), `ip`.
- Admin and customer-API **mutations** are recorded (writes only; reads are not). Secrets, tokens and
  private keys are never stored in `detail`.
- `GET /api/v1/audit?limit=&since=&action=&actor=` (admin) returns recent entries newest-first.
- A scheduler job prunes entries older than `AUDIT_RETENTION_DAYS` (default 90).

### 13.3 Operations
- `manage backup-verify`: restore the most recent backup into a throwaway database and assert the
  schema/head and row sanity, so backups are known-restorable. Documented in OPERATIONS.md.
- A security hardening checklist (docs/SECURITY.md).

### 13.4 Documentation (Persian)
- `docs/ARCHITECTURE.md` — components (controller, edges, PowerDNS/GeoDNS, Caddy, WHMCS), request &
  data flow, ports, trust boundaries, tunnel path, HA.
- `docs/DISASTER_RECOVERY.md` — controller loss, node loss, PostgreSQL restore, encryption-key and
  PDNS-key handling, DNS failover, step-by-step with the `manage` commands.
- `docs/SECURITY.md` — hardening checklist (secrets, network, tokens, TLS, backups, least privilege).
- README gains a short architecture summary + links to the above.

### 13.5 WHMCS admin
- An «حسابرسی» (audit) page surfacing `GET /api/v1/audit` with filters (action/actor/time), Persian UI.
- A health panel summarising `GET /healthz/deep` and the key `/metrics` numbers (edges online, ssl
  expiring, dns sync, backup age) with clear OK/warn colouring.

## 14. Wave 6: performance, rules & security, analytics & platform

General CDN capabilities for website customers. Defaults keep today's behaviour unless stated.

### 14.1 Edge performance & cache (6A)
- **HTTP/3 (opt-in per node, capability-detected).** The agent detects `--with-http_v3_module` in
  `nginx -V` (and the nginx version) and reports `capabilities: {http3, early_hints}` in the heartbeat.
  Only on capable nodes it renders `listen <https_port> quic reuseport` once on the default server,
  `listen <https_port> quic` on site servers, `http3 on;` and
  `add_header Alt-Svc 'h3=":<https_port>"; ma=86400' always;`. Site toggle `ssl.http3` (default true).
  `install.sh --http3` installs nginx from the nginx.org mainline repository plus the nginx.org
  dynamic modules that exist there (njs, image-filter); modules not available for that build
  (e.g. geoip2, brotli) are detected by the agent (module file present) and their directives are
  only rendered when loaded. The default install path (distro nginx 1.24, no HTTP/3) is unchanged.
  Operators must allow UDP/<https_port>.
- **Origin shield (tiered cache).** Edge flag `shield` (admin-set). Site setting `cache.shield`
  (default false). When on and the site's edge group has ≥1 enabled, online shield edge, non-shield
  edges send cache misses to the shield edges (consistent hash on the cache key), which fetch from
  the origin. Shield hops carry `X-Pcdn-Shield: <hmac>` (per-node secret derived by the controller);
  a shield only accepts shield-mode requests carrying a valid value, never re-shields, and if all
  shields are unreachable edges fall back to the origin directly. Shield edges still serve their own
  visitors normally.
- **Stale content.** `cache.stale_while_revalidate` (bool, default true) and
  `cache.stale_if_error` (seconds 0..604800, default 86400) map onto `proxy_cache_use_stale` /
  `proxy_cache_background_update`; origin `Cache-Control: stale-while-revalidate / stale-if-error`
  extensions are honoured.
- **Cache key options.** `cache.key_device` (bool: separate desktop/mobile variants),
  `cache.key_cookies` (≤10 cookie names whose values join the key), `cache.key_query_allow`
  (≤50 parameter names; when set, only these query params are part of the key; conflicts with
  `ignore_query=true` → 422).
- **WebP.** `image.auto_webp` (bool, default false): when the client sends `Accept: image/webp`,
  serve WebP for JPEG/PNG images — via conversion if the edge's nginx can produce WebP from those
  inputs, otherwise by keying the cache on WebP capability (`Vary: Accept` semantics) so origins
  that negotiate formats are cached correctly. The agent documents which mode a node uses.
- **Preload / Early Hints.** Page-rule field `preload` (≤10 entries `{url, as}`; `as` in
  script|style|image|font|fetch) renders `Link: <url>; rel=preload; as=<as>` headers; on nodes
  reporting `early_hints` capability the same links are sent as a 103 response.
- **TCP congestion control.** Node tunable `TCP_CC` (bbr|cubic, default bbr), applied by install.sh.

### 14.2 Rules & security (6B)
- **Transform rules** — section `transform`: list of `{id, enabled, match:{path (pattern),
  methods[], countries[]}, actions:[{type: set_request_header|remove_request_header|
  set_response_header|remove_response_header|rewrite_path, name?, value?, regex?, replacement?}]}`.
  Plan limit `features.max_transform_rules` (default 10). Reserved/hop-by-hop headers rejected (422).
- **Redirect rules** — section `redirects`: list of `{id, enabled, source, match: exact|prefix|regex,
  target (may use $1..$9 for regex), status: 301|302|307|308, preserve_query}`. Plan limit
  `features.max_redirects` (default 100). Bulk CSV import in the client app.
- **Managed WAF packs** — `waf.packs`: subset of `generic, wordpress, joomla, drupal, laravel, api`;
  each pack is a versioned rule set with stable rule ids, honouring existing `waf.exclusions` and
  `waf.mode` (log|block).
- **Bot management** — section `bots`: `{mode: off|log|challenge|block, allow_verified: true,
  block_empty_ua: true}`. Verified bots = published IP ranges of major search engines (fetched and
  cached by the agent, refreshed daily) AND a matching User-Agent; unverified automation signals
  (empty/library UAs, headless markers) get `mode`. Bot decisions appear in security events.
- **Authenticated origin pulls (mTLS)** — `ssl.origin_client_auth`: `off | platform | custom`.
  `platform` presents a platform client certificate (CA cert downloadable from the client app so
  origins can verify requests come from the CDN); `custom` uses a customer-uploaded cert+key
  (encrypted at rest like custom SSL keys).
- **HSTS presets** — client-app presets (basic / strict / preload-ready) filling existing `ssl.hsts`.

### 14.3 Analytics & platform (6D)
- **Near-real-time analytics** — edges send 1-minute aggregates per site (requests, bytes, cache hits,
  status classes, top paths, top countries); the controller keeps minute buckets for 24 h and serves
  `GET /api/v1/sites/{domain}/analytics/live?minutes=1..1440`; client app shows an auto-refreshing chart.
- **Log export** — section `logs`: `{enabled, s3_endpoint, bucket, prefix, access_key, secret_key
  (encrypted, write-only), anonymize_ip: true, sample_rate: 0.01..1}`; edges ship that site's access
  log records to the controller which uploads gzip JSON-lines objects hourly to the customer's
  S3-compatible bucket. Per-site hourly cap; failures retried and surfaced in the client app.
- **Webhooks** — section `webhooks`: ≤10 `{id, url (https), events[], enabled}` with a
  controller-generated signing secret (shown once). Events: purge.completed, ssl.issued, ssl.failed,
  quota.warning, quota.exceeded, site.suspended, site.unsuspended, attack.detected. Body JSON,
  header `X-Pcdn-Signature: sha256=<hmac>`, retries with backoff (≤24 h), recent deliveries visible.
- **Team access** — the WHMCS client app honours WHMCS user permissions: users without the product
  management permission get a read-only view; all writes require it.
- **SLA report** — per-site monthly availability (edge-side success ratio excluding origin errors +
  platform edge uptime), shown in the client app with CSV export and a printable page.
- **OpenAPI + Terraform** — `GET /capi/v1/openapi.json` (customer API only); a Terraform provider
  (`terraform-provider-pcdn/`, Go, terraform-plugin-framework) with resources `pcdn_record`,
  `pcdn_config_section`, `pcdn_purge` and data source `pcdn_site`, authenticated with a customer API key.

#### 14.3.1 Live analytics — contract
- `POST /edge/v1/usage` gains an optional `live` list (≤5000, same `batch_id` dedup as the rest of the
  batch): `{host, minute (ISO, seconds = 0, UTC), requests, bytes, cache_hits, status: {"2xx": n, "3xx",
  "4xx", "5xx"}, countries: {cc: n} (top ≤20), paths: {path-without-query: n} (top ≤20)}`. Pre-6D agents
  omit it. Each `UsageItem` also gains `platform_errors` (≥0, default 0): responses with status ≥500
  that the edge produced itself — no upstream status and no security action (WAF/rate-limit/DDoS/bot
  blocks are not errors); origin errors (any upstream status present) never count. 501 and 505 are
  excluded (any visitor can provoke them with a malformed request), as are cache-served responses and
  the suspended/over-quota page.
- Controller table `analytics_minute` `(site_id, minute)` PK, `requests, bytes, cache_hits, details`
  (JSON: status/countries/paths, capped like hourly details). Rows older than 24 h are deleted by a
  leader job. Hosts map to sites exactly like hourly usage.
- `GET /api/v1/sites/{domain}/analytics/live?minutes=60` (1..1440; other → 422) and the same on
  `GET /capi/v1/analytics/live` (scope `stats`) →
  `{minutes, from, to, series: [{t, requests, bytes, cache_hits, status: {...}}] (one per minute,
  zero-filled, oldest first; the current minute may be partial), totals: {requests, bytes, cache_hits,
  hit_ratio (0..1 | null), status}, top_paths: [[path, n]] ≤10, top_countries: [[cc, n]] ≤10}`.

#### 14.3.2 Log export — contract
- Plan feature `log_export` (bool, default true). Section `logs`: `{enabled: false, s3_endpoint: ""
  (https URL, host must resolve only to public addresses), region: "us-east-1", bucket: "" (S3 bucket
  name rules), prefix: "" (≤128, `[A-Za-z0-9/_.-]`, no `..`), access_key: "" (≤128), secret_key
  (write-only: GET returns `""` plus `secret_key_set: bool`; PUT with `""`/omitted keeps the stored
  one), anonymize_ip: true, sample_rate: 1.0 (0.01..1)}`. `enabled: true` needs endpoint, bucket and
  both keys (else 422). Secret stored encrypted; never in edge config, audit or logs.
- Edge config per site: `logs: {enabled, sample_rate, anonymize_ip}` only. The edge samples that site's
  access-log records and posts them: `POST /edge/v1/logship {batch_id (32 hex), records: [{host, t
  (ISO), ip, method, scheme, path (query stripped, ≤2048), status, bytes, rt (seconds), cache, country,
  ua (≤512), referer (≤1024, query stripped), proto}]}` ≤5000 records per POST. With `anonymize_ip` the
  edge zeroes the last IPv4 octet / all but the first 48 bits of IPv6 before sending; the controller
  re-applies it (idempotent) and drops records of sites without `logs.enabled`.
- Controller spools gzip JSON-lines chunks per site/hour (`log_spool` table) with a per-site hourly cap
  `LOG_EXPORT_MAX_PER_HOUR` (default 500000; excess counted as dropped). A leader job uploads every
  completed hour as one object `{prefix}{domain}/YYYY/MM/DD/HH-<8hex>.jsonl.gz` (concatenated gzip
  members) with SigV4 (path-style, like backups); failures keep the chunks and retry every 10 min;
  chunks older than 72 h are dropped (counted).
- `GET /api/v1/sites/{domain}/logs/status` → `{enabled, last_upload_at, last_object, last_error,
  last_error_at, pending_records, dropped_records}`; `POST /api/v1/sites/{domain}/logs/test` → writes a
  tiny `{prefix}{domain}/.pcdn-test` object → `{ok, error}` (rate-limited like config writes).

#### 14.3.3 Webhooks — contract
- Plan feature `max_webhooks` (int, default 10; 0 = none). Section `webhooks`: `{items: [{id
  ("wh_" + 8 hex; assigned by the controller when missing/unknown), url (https, ≤512, host must resolve
  only to public addresses at save and at every delivery), events: [non-empty subset of purge.completed,
  ssl.issued, ssl.failed, quota.warning, quota.exceeded, site.suspended, site.unsuspended,
  attack.detected], enabled: true, description: "" (≤100)}]}`. GET adds `secret_set: true` per item and
  never returns a secret. A PUT that creates items returns them as usual plus `new_secrets: {id:
  "whsec_" + 40 hex}` — the only time a secret is shown. Removing an item deletes its secret.
- `POST /api/v1/sites/{domain}/webhooks/{id}/rotate` → `{id, secret}`;
  `POST /api/v1/sites/{domain}/webhooks/{id}/test` → sends a `ping` event now → `{ok, status_code,
  error}`; `GET /api/v1/sites/{domain}/webhooks/deliveries?limit=50` (≤200, last 7 days) →
  `[{id, hook_id, event, status: pending|ok|failed, attempts, last_code, last_error, created_at,
  delivered_at, next_attempt_at}]`.
- Delivery: `POST url`, body `{id: "evt_" + 16 hex, type, created_at, site, data}`; headers
  `Content-Type: application/json`, `User-Agent: PasargadCDN-Webhooks/1`, `X-Pcdn-Event`,
  `X-Pcdn-Delivery`, `X-Pcdn-Timestamp` (unix seconds), `X-Pcdn-Signature: sha256=<hex HMAC-SHA256(secret,
  timestamp + "." + raw body)>`. 2xx = delivered. 10 s timeout, redirects not followed, response body
  read ≤4 KB and discarded. Retries (leader job): 1 m, 5 m, 30 m, 2 h, 6 h, then every 6 h until 24 h
  after creation → `failed`. Delivery rows kept 7 days.
- Emitted from: purge creation (`purge.completed` once the purge is queued for all edges), certificate
  issue success/failure, quota transitions (warning at 80 %, exceeded), admin suspend/unsuspend,
  `attack.detected` (security events for the site above `ATTACK_EVENTS_PER_5M`, default 1000, at most
  once per hour per site).

#### 14.3.4 SLA report — contract
- `GET /api/v1/sites/{domain}/sla?month=YYYY-MM` (default: current UTC month; ≤12 months back) →
  `{month, domain, requests, platform_errors, request_success_pct, edge_uptime_pct, availability_pct,
  target_pct, met, days: [{date, requests, platform_errors, request_success_pct, edge_uptime_pct}]}`.
  `request_success_pct = 100 × (1 − platform_errors / requests)`; `edge_uptime_pct` = mean probe uptime
  of the edges in the site's edge group for that day/month; `availability_pct` = the lower of the two
  non-null values; percentages have 3 decimals, null without data. `target_pct` = plan feature
  `sla_target` (default 99.9); `met` = availability ≥ target (null without data).

#### 14.3.5 Customer API additions & OpenAPI
- `GET /capi/v1/site` (any scope) → `{domain, status, suspended, plan, nameservers, cname_target,
  ssl_status}`. `GET /capi/v1/openapi.json` (no auth): OpenAPI 3 for the `/capi/v1` routes only, with a
  bearer security scheme; no admin/edge paths.

#### 14.3.6 Terraform provider
- `terraform-provider-pcdn/` (Go, terraform-plugin-framework), provider `pcdn` with `endpoint`
  (or `PCDN_ENDPOINT`) and sensitive `api_key` (or `PCDN_API_KEY`). Resources: `pcdn_record` (CRUD via
  `/capi/v1/records`, PATCH on update, import by id), `pcdn_config_section` (`section` + `config` JSON
  string; PUT on create/update, delete = no-op with a warning, plan diff on normalized JSON),
  `pcdn_purge` (`urls`/`prefixes`/`everything` + `triggers` map; every change → replace → new purge).
  Data source `pcdn_site`. Unit tests against an httptest server; CI job `terraform` (go vet, go test,
  go build).

#### 14.3.7 Team access (WHMCS only)
- In the client area, a logged-in WHMCS user who is not the account owner and lacks the
  "manage products" permission gets a read-only app: the boot payload carries `readonly: true`, write
  controls are hidden/disabled, and `api.php` refuses every non-GET call with 403 for that user (server
  side, independent of the UI). Owners and WHMCS versions without sub-users keep full access.

## 15. Wave 7: tunnel quality, diagnostics & usability

Scope: quality, reliability, transparency and ease of setup for tunnel (VPN-over-CDN) customers.
Explicitly out of scope: anything whose purpose is evading filtering/blocking, hiding or rotating
node addresses, or choosing nodes by "what is not blocked". Node selection stays health/load driven.

### 15.1 Edge: tunnel quality telemetry
Per host-hour, per tunnel **path id**, the edge adds to the usage item's `tunnel` object:
```json
"paths": {"grpc1": {"sessions": 12, "seconds": 5400, "bytes_up": 1, "bytes_down": 2,
                     "abnormal": 1, "connect_ms_sum": 840, "connect_n": 12,
                     "errors": {"origin_refused": 0, "origin_timeout": 1, "origin_error": 0,
                                "limit": 0, "country": 0, "protocol": 0, "edge": 0}}}
```
- A request is attributed to a path id by the edge (it knows which tunnel location matched; log field
  `"tp"` = path id, `""` for non-tunnel requests). ≤ 50 path ids per host-hour.
- `sessions`: tunnel requests that reached the origin and were accepted (101 / 2xx).
- `abnormal`: accepted sessions that ended with a non-clean end (nginx `$status` 499 after an
  accepted upgrade is a client close and is NOT abnormal; abnormal = upstream reset/timeout on an
  established session: `$upstream_status` 502/504 after bytes were exchanged, or `rt` ≥ idle_timeout
  − 1 s with an upstream error). Keep the rule simple, documented and unit-tested.
- `connect_ms_sum` / `connect_n`: sum / count of `$upstream_connect_time` (ms) for tunnel requests
  that connected (log field `"uct"`).
- `errors` (each a request count), classification:
  - `origin_refused`: no connection to the origin (upstream status 502 with no upstream connect
    time / connection refused or reset before response);
  - `origin_timeout`: upstream status 504 or connect timeout;
  - `origin_error`: the origin answered but not with 101/2xx (e.g. 400/404/5xx from origin);
  - `limit`: 429/503 produced by limit_conn / limit_req / the per-site or per-IP connection caps;
  - `country`: 403 from `allowed_countries`;
  - `protocol`: the client spoke the wrong protocol for the path (e.g. no `Upgrade` on ws/httpupgrade,
    non-HTTP/2 on grpc/h2) — 400/426 produced by the edge;
  - `edge`: any other edge-generated 5xx on a tunnel path.
- Pre-wave-7 agents omit `paths`; the controller treats it as optional. Old log lines without
  `tp`/`uct` still parse.

### 15.2 Edge: fair share & tunnel stream hygiene
- New edge config per site `tunnel.fair_share` (bool, default true): tunnel `limit_rate` is never
  above the plan cap, and when the node is above 85 % of its capacity (from its own heartbeat
  metrics: tx_mbps vs the edge capacity in the config) new tunnel connections of a site that holds
  more than `fair_share_pct` (node config, default 25) % of the node's tunnel connections get
  `limit_rate` = max(per_connection cap, node capacity / active tunnel connections). Implemented
  with an njs/agent-rendered map; must never drop established connections.
- install.sh: default qdisc `fq` (already needed by bbr) stays; document it.

### 15.3 Controller: tunnel quality API
- Store `tunnel.paths` per hourly usage (merge like other details, ≤ 50 path ids).
- `GET /api/v1/sites/{domain}/tunnel/quality?hours=24` (1..744) and `GET /capi/v1/tunnel/quality`
  (scope stats) →
```json
{"hours": 24, "paths": [{"id": "grpc1", "path": "/x", "protocol": "grpc", "sessions": 12,
  "avg_session_s": 450.0, "abnormal_pct": 8.333, "connect_ms_avg": 70.0,
  "errors": {...}, "error_total": 1, "success_pct": 92.308,
  "top_issue": "origin_timeout" | null, "advice": "<Persian, one sentence>" | null}],
 "edges": [{"name": "edge-1", "sessions": 7, "abnormal_pct": 0.0, "connect_ms_avg": 60.0,
            "error_total": 0}],
 "series": [{"t": "<hour ISO>", "sessions": 3, "errors": 0, "abnormal": 0}]}
```
  `success_pct = 100 × sessions / (sessions + error_total)` (null without data); `advice` maps the
  dominant error to a fixed Persian sentence (e.g. origin_refused → «سرور شما روی پورت مسیر اتصال را
  رد می‌کند؛ سرویس Xray/sing-box و پورت را بررسی کنید.»). Path ids no longer configured are reported
  with `"removed": true`.
- `GET /api/v1/sites/{domain}/tunnel/usage?days=30` (1..90) and capi equivalent →
  `{"days": [{"date", "bytes_up", "bytes_down", "sessions", "by_protocol": {...}, "by_path": {...}}],
    "month": {"used_bytes", "limit_bytes" | null, "forecast_bytes", "forecast_exhaust_date" | null}}`.
  Forecast = month-to-date average daily total × days in month (null limit → no exhaust date).

### 15.4 Controller: origin-down detection & notifications
- Leader job every minute over the hourly + live data of the last 5 minutes per tunnel site: when
  ≥ 10 tunnel attempts and ≥ 80 % of them are `origin_refused`/`origin_timeout`, the site's tunnel
  origin is DOWN (state per site in `state`); when attempts in the last 5 min are ≥ 5 and origin
  errors < 20 %, it is UP again. Edges send the live per-minute `tunnel_errors` / `tunnel_attempts`
  counters in their `live` items (new optional fields) so detection uses minute data.
- Transitions emit webhook events `tunnel.origin_down` / `tunnel.origin_up` (added to the webhooks
  event list, data `{paths: [...ids], attempts, origin_errors, since}`) and are listed in
  `GET /api/v1/events?type=tunnel` (new event type, admin) so WHMCS can e-mail the client.
  At most one down notification per site per 30 min (flapping guard).
- `GET /api/v1/sites/{domain}/tunnel/health` → `{state: "up"|"down"|"unknown", since, last_check}`.

### 15.5 Controller: capacity alert (operator)
- Leader job daily: for each edge group, the 95th percentile of hourly tunnel+total tx over the last
  3 days vs the group's summed capacity. ≥ 70 % → admin alert (Telegram/SMTP, existing alert
  system, dedup) «ظرفیت گروه X به ۷۰٪ رسیده؛ نود اضافه کنید»; resolves below 60 %. Also exposed on
  `GET /api/v1/overview` as `capacity: [{group, p95_mbps, capacity_mbps, pct}]`.

### 15.6 Speed test (diagnostics only)
- Edge serves, on every site that has tunnel enabled or always (cheap):
  `GET /__pcdn/speed/ping` → 204, `GET /__pcdn/speed/down?bytes=N` (N ≤ 10 MB, random-ish
  incompressible body, `Cache-Control: no-store`), `POST /__pcdn/speed/up` (body ≤ 10 MB discarded,
  204). Rate-limited per IP (e.g. 6 tests/min), not logged as usage-billable? → they ARE counted as
  normal traffic (simplest, honest). Response header `X-Pcdn-Node: <edge name hash, not IP>`.
- The client app page measures latency (10 pings), download and upload against the customer's own
  domain (whatever node DNS gives) and shows results with plain-language interpretation. It never
  lists, probes or recommends specific node addresses.

### 15.7 WHMCS client area
- **کیفیت تونل** page: per-path cards (success %, abnormal %, connect latency, top issue + advice),
  per-edge table, hourly chart; period 24h/7d/30d.
- **مصرف تونل**: daily chart by protocol/path, month forecast and exhaust date.
- **بررسی کانفیگ سرور**: the customer pastes an Xray or sing-box server JSON; it is parsed **in the
  browser only** (never sent to WHMCS or the controller; nothing stored) and checked against the
  site's tunnel paths: inbound protocol/transport ↔ path protocol, path/serviceName match, listen
  port ↔ path origin port, TLS expectations (origin.tls), xhttp mode hints, common mistakes. Findings
  in Persian with fix suggestions. Private keys/UUIDs are never displayed back in full.
- **تست سرعت** page (15.6).
- **App templates**: client setup tutorials/QR for v2rayNG, NekoBox, Hiddify, Streisand, v2rayN,
  sing-box, Shadowrocket (existing tutorials extended), each with short steps.
- **Origin-down e-mail**: WHMCS cron reads `GET /api/v1/events?type=tunnel&since=` and sends the
  service owner the e-mail template «قطعی سرور پشت تونل» / «اتصال دوباره برقرار شد» (created by the
  wizard), deduped per event id.
- **Tunnel traffic add-on**: wizard creates an add-on product «بسته‌ی ترافیک افزوده» with
  configurable sizes (10/50/100 GB, admin-priced); when its invoice is paid the service's controller
  cap for the current month is raised by that amount (same mechanism as prepaid top-ups, logged,
  idempotent per invoice item), shown on the wallet card and statement.

### 15.8 Implementation notes (as built)
- Log fields: `"tp"` tunnel path id, `"uct"` `$upstream_connect_time` (appended after `"rf"`).
- `ws` / `httpupgrade` paths answer **426** when the request has no `Upgrade` header (never reaches
  the origin); gRPC over HTTP/1.x is classified `protocol`. xhttp/h2/grpc semantics are unchanged.
- `abnormal` cannot be observed in the access log (an origin reset on an established session logs the
  same status as a clean end), so the edge counts nginx error-log `[error]` lines ending in
  "while proxying upgraded connection" / "while reading upstream", attributed by host + longest tunnel
  prefix. An origin that itself answers 502/504 counts as refused/timeout.
- Fair share is **admission control**, not `limit_rate` (nginx 1.24 ignores `limit_rate` on
  upgraded/unbuffered proxying): while the node is hot (≥ 85 % of `node.capacity_mbps`, cleared below
  80 %), a site's NEW sessions get 429 only when, over the last 1–2 minutes, it has ≥ 30 opens, the
  other sites together ≥ 10, its share is above `node.fair_share_pct` AND it has more opens than all
  other sites combined. Established sessions and xhttp POSTs are never touched; any error fails open;
  the hot flag expires after 180 s without an agent heartbeat. Edge config gains
  `node: {name, capacity_mbps, fair_share_pct}` per requesting edge and `tunnel.fair_share` (default
  true); `capacity_mbps` 0 = never hot.
- Speed test: `/__pcdn/speed/ping` (2/s per IP, burst 20), `/down?bytes=1..10485760` (default 1 MB,
  400 if invalid; ≥ 64 bytes served from a pre-generated random file via the flv module, so the first
  13 bytes are an FLV header), `/up` (≤ 10 MB, 413 above, 405 other methods); down+up share 12/min
  per IP; CORS `Access-Control-Allow-Origin: *` (the WHMCS client area is another origin); headers
  `Cache-Control: no-store, no-transform`, `X-Pcdn-Node` = first 8 hex of sha256(node name).
- `tunnel_attempts` in live items = every tunnel request with a path id that minute.
- Add-on traffic is one WHMCS add-on per size (WHMCS add-ons take no configurable options).

## 16. Wave 8: production readiness & new products

Not code (operator's responsibility, documented only): third-party penetration test, network-level
(L3/L4) DDoS scrubbing from the datacenter, more PoPs, 24/7 on-call, pricing and the SLA commitment.
This wave ships the tooling and products that code CAN deliver. Same boundary as always: nothing whose
purpose is evading filtering or hiding/rotating node addresses.

### 16.1 Load-test kit (`tools/loadtest/`)
Self-contained Python 3 (asyncio, stdlib + `aiohttp` optional) tool `pcdn-loadtest` with scenarios:
`http` (cache hit/miss mix, configurable RPS/concurrency/duration), `ws`, `httpupgrade`, `grpc`
(h2 streams), `xhttp` (long-lived tunnel sessions with bidirectional traffic at a target Mbps each),
`ramp` (step up connections until error rate or p99 latency crosses a threshold). Output: JSON + a
Persian summary (max sustainable connections, Mbps, p50/p95/p99, error breakdown). Runs from a
separate client machine against ONE node the operator owns (target IP + Host header), never against
third parties; refuses targets not given explicitly. A tiny echo origin (`tools/loadtest/origin.py`)
for ws/grpc/xhttp sinks. Runbook `docs/LOADTEST.md` (Persian): how to size `capacity_mbps`.

### 16.2 CLI (`cli/pcdn`, Go) + provider release
`pcdn` command for the customer API: `site`, `records list|add|update|delete`, `config get|set <section> [file]`,
`purge --url/--prefix/--everything`, `analytics`, `tunnel quality|usage`,
`--endpoint/--api-key` flags or env (same as Terraform), JSON or table output. GoReleaser config for
both the CLI and `terraform-provider-pcdn` (signed checksums, registry manifest) and a GitHub Actions
`release.yml` triggered by tags `cli/v*` / `provider/v*` (the GPG key comes from repository secrets,
never committed). CI job builds and tests `cli/`.

### 16.3 Edge host hardening (opt-in, L3/L4 first line)
`install.sh --harden-net`: nftables table `pcdn_guard` — SYN rate limit per source /24 and global,
SYN-proxy for 80/443 when the kernel supports it, drop invalid conntrack, UDP/443 rate limit per
source (QUIC), ICMP rate limit; values in agent.conf (`GUARD_*`). Never blocks the controller or SSH
(allow-list first). `--no-harden-net` removes it. Documented as a complement to — not a replacement
for — datacenter scrubbing.

### 16.4 TCP/UDP proxy product ("Spectrum")
- Plan feature `l4_proxy` (bool, default false), `max_l4_apps` (default 0). Section `l4`: `{apps:
  [{id, protocol: "tcp"|"udp", edge_port (1024..65535, not 80/443/controller ports, unique per
  edge group), origin: {address, port}, proxy_protocol: "off"|"v1"|"v2" (tcp only), ip_allow: [cidr],
  idle_timeout: 10..3600, enabled}]}`. The controller allocates `edge_port` uniqueness across all
  sites of the same edge group (409 on conflict) and returns `hostname` (= the site's proxied host or
  an `l4-<id>.<domain>` record it creates).
- Edge: nginx `stream {}` block rendered into its own file, one `server { listen <port> [udp]
  reuseport; proxy_pass <origin>; proxy_timeout; proxy_protocol; allow/deny }` per app; stream access
  log (JSON) → usage `l4: {app_id: {bytes_in, bytes_out, sessions}}` billed like HTTP bytes.
  install.sh enables the stream module (`libnginx-mod-stream` or nginx.org built-in).
- Firewall note: the operator must open the allocated port range (`L4_PORT_RANGE`, default
  20000-29999) on edges; edge_port must fall inside it.

### 16.5 Video delivery (HLS/DASH)
Section `video`: `{enabled, segment_ttl (s, default 86400), manifest_ttl (default 2), prefetch_next:
true}`. Edge: separate cache rules for `*.m3u8|*.mpd` (short TTL, stale-while-revalidate) and
segments `*.ts|*.m4s|*.mp4|*.aac` (long TTL, `slice` module 1 MB for byte-range on large mp4, cache
lock), CORS `*` for media, and optional prefetch: on a segment MISS the agent-side njs triggers a
subrequest for the next segment number when the name ends in a number (bounded, once). Analytics:
video bytes counted under `video` in usage details.

### 16.6 Images v2
Section `image` gains `avif: false` (convert to AVIF when the client accepts it and the node has
`avifenc`/libavif — capability `avif`), URL transform params `?w=&h=&fit=cover|contain&q=&fmt=webp|avif|jpeg`
(bounded: w,h ≤ 4096, q 1..100; signed-URL option `transform_secret` so third parties cannot generate
unlimited variants), and `smart_crop: false` (center-weighted entropy crop via the resizer).
Unsupported features degrade gracefully (serve original).

### 16.7 DNS: secondary + weighted/failover records
- Record fields: `weight` (0..100, A/AAAA/CNAME non-proxied only), `health_check` reused for
  non-proxied records too (HTTP/HTTPS/TCP probe from the controller every 60 s; unhealthy members are
  withdrawn, never all — fail-open).
- Secondary DNS: section `dns_secondary`: `{mode: "off"|"primary_elsewhere", primaries: [ip], tsig?:
  {name, algorithm, secret(write-only)}}` → PowerDNS slave zone (AXFR from the customer's primary);
  and `allow_axfr: [ip]` to let the customer's own secondary transfer from us (with TSIG).

### 16.8 Object storage
`deploy/storage/`: docker-compose for MinIO (single node or 4-disk erasure), Caddy TLS, behind the
CDN as an origin type. Controller: plan feature `storage_gb` (0 = none); `POST /api/v1/sites/{d}/
storage/buckets {name}` creates a bucket + scoped access key via the MinIO admin API (secret shown
once, stored encrypted), `GET` lists buckets with usage, `DELETE` (only empty). Usage collected
hourly and billed via WHMCS (GB-month). A record/origin shortcut `origin: {storage: "<bucket>"}`
makes a bucket a CDN origin. Customer app page «فضای ذخیره‌سازی».

### 16.9 Edge Functions (isolated)
Customer JavaScript at the edge is untrusted multi-tenant code; it must NOT run inside nginx/njs.
Design: separate service `pcdn-fn` on each node — a pool of sandboxed workers (QuickJS or another
embeddable engine runnable on Ubuntu 24.04 without internet at runtime), each invocation with a
memory cap, CPU-time cap (50 ms default), no filesystem, no network except a `fetch()` restricted to
the site's own origin, run under systemd sandboxing (DynamicUser, ProtectSystem=strict,
PrivateNetwork except a unix socket, MemoryMax, SystemCallFilter). nginx reaches it over a unix
socket only for routes the customer bound (`functions: [{id, route, code, enabled}]`, code ≤ 256 KB,
plan feature `edge_functions`). API: request in → `{status, headers, body}` out or `pass` to continue
to the origin. If a safe sandbox is not achievable with available packages, ship the feature disabled
with a precise report rather than a weaker isolation.

### 16.10 English client app
The WHMCS client app gains full English (LTR) alongside Persian, selected from the WHMCS client
language (fallback Persian), all strings through one dictionary; numbers/dates localized.

### 16.11 Implementation notes (as built)
- L4: edges render stream servers from the node-wide `l4` list; PROXY protocol `off|v1` only (nginx
  stream); unsafe/busy ports are skipped so a reload never fails; ports 8089/8090/8091 (edge loopback
  services) are never allocated.
- Images v2: signature = HMAC over the transform params in the fixed order `w,h,fit,q,fmt,width,height`
  (present ones, raw values), no expiry; bad/missing signature → 403; transforms run in the sandboxed
  `pcdn-imaged` service with image_filter / original fallback.
- Video: prefetch via nginx `mirror`, once per segment per 600 s, ≤ 100/s per node; video bytes are
  attributed agent-side by media extension.
- DNS: weighted sets use PowerDNS LUA `pickwrandom` when weights differ; outbound AXFR carries proxied
  names as LUA records (PowerDNS-specific).
- Storage: MinIO admin via the controller's own SigV4 + madmin client; per-bucket service accounts;
  bucket read by the CDN through a Referer-token policy; edges reach it via `origin.storage`, GET/HEAD
  only, visitor credentials stripped, path escapes 400; suspension does not cut S3 key access.
- Edge Functions: QuickJS per invocation under Landlock (ABI 1..7 handled; none → fail closed) +
  seccomp + no_new_privs + MDWE + rlimits inside a DynamicUser/PrivateNetwork unit; fetch only to the
  site's own origin through a local socket; WHMCS accepts up to 9 MB bodies only for PUT
  config/functions.
- English client app: Persian source strings are the dictionary keys; English sent only to English
  viewers; admin addon stays Persian.

## 17. Wave 9: WAF learning mode (auto-tuning)

Goal: fewer false positives and sensible rate limits without manual tuning. Learning never blocks;
it only observes and proposes; the customer applies proposals explicitly.

### 17.1 Edge
- Section `waf` gains `learning: {enabled: false, until: ISO|null}` (controller-managed end time,
  default 7 days after enabling). While learning, the edge evaluates WAF/packs exactly as in `log`
  mode for that site (never blocks/challenges on WAF verdicts; firewall/ratelimit/DDoS unchanged).
- Per host-hour usage item adds optional `waf_learn`: `{rules: {rule_id: {hits, paths: {path_prefix: n}
  (top 10, first two segments), methods: {M: n}}} (≤100 rules), paths: {path_prefix: {req, p95_rps_min,
  methods: {...}}} (top 50 prefixes; p95 of per-minute request counts per client IP /24 bucket… keep it
  simple: max per-minute requests from a single client IP seen for that prefix, and total), clients:
  {max_rpm: n, p95_rpm: n}}`. Bounded memory; only for sites in learning.

### 17.2 Controller
- `waf.learning` validated; enabling sets `until` = now + `days` (1..30, default 7) and records
  `started_at`; ends automatically (job) → state `learned`.
- `GET /api/v1/sites/{d}/waf/learning` (+ capi, scope stats) → `{state: off|learning|learned, started_at,
  until, requests_observed, proposals: [{id, kind: "waf_exclusion"|"rate_limit"|"pack_off", summary
  (Persian), detail (en), confidence: 0..1, change: <exact section patch>}]}`.
  - waf_exclusion: a rule hit on ≥ 0.5% of requests to a path prefix, by ≥ 20 distinct clients, with
    no other attack signals on those requests → propose a WAF exclusion for (rule, path prefix).
  - rate_limit: per path prefix with ≥ 1000 requests: propose a limit at max(3 × p95 per-client rpm,
    observed max × 1.5) with action challenge; never below 30 rpm.
  - pack_off: a pack whose rules never matched attack-like traffic but produced only proposals above.
- `POST /api/v1/sites/{d}/waf/learning/apply {ids: [...]}` applies chosen proposals via the normal
  section validation (audit-logged), returns the updated sections; idempotent.
- No proposal is ever applied automatically.

### 17.3 WHMCS
- WAF page: «حالت یادگیری» card (start with days, progress, stop), proposals list with Persian
  explanation, confidence, preview of the exact change, apply selected; bilingual.

### 17.4 As built
- Edge config: `waf.learning = {enabled, until}` (ISO, `Z`); `enabled` is false when the plan has no WAF.
  The edge renders `learn_until` (epoch) into sites.js and njs compares per request, so learning ends on
  time without a re-render. While learning every WAF/pack verdict is `log:waf:<id>` (even in mode `off`);
  `log:waf:<id>:a` marks a request that also carried another attack signal (other WAF group, firewall/bot
  log verdict). Firewall, rate limits, bots and DDoS are unchanged.
- Wire shape (per host-hour usage item, learning hosts only):
  `waf_learn: {rules: {"<id>": {hits, clients, attack, methods: {M: n}, paths: {"<prefix>": {hits,
  clients, attack}}}}, paths: {"<prefix>": {req, max_rpm, p95_rpm, p95_rps_min, methods}}, clients:
  {max_rpm, p95_rpm}}`. Prefix = first two path segments, no query. Caps: 100 rules, 10 prefixes per
  rule, 50 path prefixes, 10 methods (`OTHER` for the rest). `hits/attack/req/methods` are deltas per push;
  `clients` (linear-counting estimate), `max_rpm`, `p95_rpm` are hour-to-date values, merged by maximum.
  `p95_rps_min` is kept as an alias of `max_rpm`.
- Controller: learning is `PUT config/waf` with `learning: {enabled, days 1..30}` (`started_at`/`until`
  set by the controller). Proposal `id` = `p_` + 16 hex; `change = {section, op: add_exclusion|add_rule|
  remove_pack, value}`; proposals also carry `evidence` and `applied`. An exclusion needs ≥ 20 distinct
  clients and no attack hits; the rate limit is max(3 × p95, ceil(1.5 × max), 30). Apply returns
  `{applied, unchanged, changed, sections}`; unknown/stale ids → 422, nothing applied. No migration
  (state in the site config, data in the hourly usage details).
- WHMCS proxy forwards apply bodies of exactly `{ids}` (1..100 ids matching `^p_[0-9a-f]{16}$`).

## 18. Wave 10: production rollout, access control, waiting room, statements, growth

Hard rules carried over: no feature selects, hides or rotates node addresses to avoid filtering;
secrets are shown once, encrypted at rest, never logged; nothing is applied to a customer site
without the customer's action; every new section is plan-gated and validated on controller AND edge.

### 18.1 Waiting room (section `waiting_room`, plan feature `waiting_room`)
- Config: `{enabled: false, paths: ["/"] (prefixes, ≤20), max_active: 1..1_000_000 (site-wide active
  visitors), session_minutes: 1..120 (default 10, idle timeout), queue_page: {title_fa, title_en,
  message_fa, message_en} (plain text ≤500 each, escaped), bypass: {verified_bots: true, paths: [] (≤20,
  e.g. /api/), ips: [] (CIDR ≤50)}, mode: "queue"|"off"}`.
- Controller sends each serving edge `waiting_room.node_max = ceil(max_active × node_share)` where
  node_share = 1 / (number of healthy enabled edges serving the site's group) (min 1). Health/load only.
- Edge (njs + js_shared_dict, zone sized for ≥200k entries): a visitor is *active* while it holds a
  valid signed cookie `__pcdn_wr` (HMAC-SHA256 with the site's `wr_secret`, fields: ticket, issued,
  last_seen, state a|q) and was seen within session_minutes. New visitor on a covered path: if the
  node's active count < node_max → admitted; else gets a queue ticket (monotonic per node) and a
  200 HTML queue page (Persian/English by Accept-Language, `Cache-Control: no-store`,
  `Retry-After`, meta refresh 15–30 s with jitter, estimated position = ticket − last admitted).
  Admission FIFO by ticket as slots free. Non-HTML requests (Accept not text/html, or XHR) from queued
  visitors get 503 + Retry-After. Bypass rules first. Never applies to tunnel or `/__pcdn/` paths.
- Usage item `waiting_room: {admitted, queued, max_wait_s, peak_active}` per host-hour; controller stats
  `GET /api/v1/sites/{d}/waiting-room` (+capi, scope stats) → `{enabled, active_estimate, queued_estimate,
  last_hour: {...}, hourly: [...]}`; edge heartbeats report per-site `{active, queued}` (bounded).

### 18.2 Access (protect paths with a login; section `access`, plan feature `access`)
- Config: `{enabled: false, apps: [ {id (slug), name, paths: [prefix] (≤20), methods: "otp"|"ip"|
  "otp_or_ip", emails: ["a@b.com" or "@company.com"] (≤200), ips: [CIDR] (≤100),
  session_hours: 1..720 (default 24)} ] (≤20 apps)}`. Paths of different apps must not overlap
  (validated). `/__pcdn/` paths are never protected by an app.
- Secrets: per site `access_secret` (32 bytes, generated by the controller, encrypted at rest, sent
  to edges in the site config like other site secrets, rotatable via
  `POST /api/v1/sites/{d}/access/rotate` → all sessions invalid).
- Edge flow (all on the site's own host):
  - Unauthenticated request to a protected path → `ip` allowed → pass; else HTML login page at
    `/__pcdn/access/login?app=<id>&next=<path>` (302 for GET HTML, 401 JSON for others).
  - POST `/__pcdn/access/send {app, email}` → njs checks the email against the app's list
    (case-insensitive; `@domain` matches the exact domain), then calls the controller via an internal
    location: `POST {controller}/edge/v1/access/otp {domain, app, email}` with the edge token taken from
    an nginx include readable only by root (`/etc/nginx/pcdn/edge-auth.conf`, mode 0600, rendered by the
    agent). Always answers the same neutral message whether or not the email is allowed (no
    enumeration). Rate limits on edge: 5/min per client IP per site.
  - Controller generates a 6-digit code = HMAC(access_secret, "otp|"+app+"|"+lower(email)+"|"+window)
    mod 10^6 where window = floor(unix/300); accepts current and previous window; e-mails it via SMTP
    (Persian+English template, site name, never the secret). Controller limits: 5 codes / email / hour,
    50 / site / hour, 429 beyond. Audited as `access.otp_sent` (email hashed in the audit detail).
  - POST `/__pcdn/access/verify {app, email, code, next}` → edge recomputes the code locally (no
    controller call), constant-time compare, 10 failed tries per IP per 10 min → locked 10 min.
    Success → cookie `__pcdn_access_<app>` = base64url(app|email|exp) + "." + HMAC (Secure, HttpOnly,
    SameSite=Lax, Path=/), 302 to `next` (same-host relative path only; anything else → "/").
  - Origin receives header `X-PCDN-Access-Email: <email>` (stripped from client requests always).
  - `/__pcdn/access/logout` clears the cookie.
- Controller stats: `GET /api/v1/sites/{d}/access/log` (+capi stats) → last 200 sign-ins/failed
  attempts reported by edges through usage items `access: {ok: n, fail: n, otp: n}` and a bounded
  event list `access_events: [{t, app, email_hash, ok}]` (≤50 per item).

### 18.3 Monthly statements (PDF/CSV) and audit export
- `GET /api/v1/sites/{d}/statement?month=YYYY-MM&format=pdf|csv|json&lang=fa|en` (+capi, scope stats):
  traffic (GB) by day, requests, cache hit ratio, tunnel GB, storage GB-month, functions invocations,
  L4 GB, security events summary, plan name, quota and overage blocks consumed. PDF: A4, generated in
  the controller (fpdf2 + bundled Vazirmatn font, OFL licence file committed; RTL shaping for Persian),
  ≤ 2 MB, deterministic for the same data. No customer IPs. A month in the future → 422; current month
  = month-to-date, marked as such.
- `GET /api/v1/sites/{d}/audit?from&to&format=json|csv` (+capi, scope stats): the site's audit
  entries (actor masked to kind + short label; no secrets — detail already stripped), ≤ 10 000 rows,
  CSV with UTF-8 BOM for Excel. Admin: `GET /api/v1/audit/export?from&to&format=csv` (all).
- WHMCS: client app «صورت‌حساب مصرف» page (pick month → download PDF/CSV; reseller: per sub-site),
  «گزارش تغییرات» page (audit list + CSV); admin addon: audit CSV export button.

### 18.4 Error tracking (opt-in)
- Controller: `SENTRY_DSN` (empty = off), `SENTRY_ENVIRONMENT`, `SENTRY_TRACES_SAMPLE_RATE` (0).
  sentry-sdk only when the DSN is set; `send_default_pii=False`; a `before_send` scrubber removes
  Authorization/Cookie/X-*-Token headers, query strings, request bodies, and any value matching key/
  secret/token/password patterns. Unit-tested scrubber.
- WHMCS client app: global `window.onerror`/`unhandledrejection` handler posts `{message, source
  (path only), line, col, stack (≤4 KB, query strings stripped), page, ua}` to the module proxy
  `client-error` action (rate-limited 10/min per session, CSRF-checked), which writes WHMCS module log
  and forwards to the controller `POST /api/v1/client-errors` (admin key) → counted in
  `/metrics` (`pcdn_client_errors_total{page}`) and forwarded to Sentry when configured. No customer
  data beyond the message/stack.
- Edge: agent exceptions already logged; heartbeat carries `errors_last_hour` (count) → node page.

### 18.5 Pricing page and referral programme (WHMCS addon)
- Public pricing/comparison page: addon client-area route `index.php?m=pasargadcdn_admin&page=pricing`
  (no login): plans from the WHMCS products the wizard manages (name, monthly/annual price in the
  client's currency via WHMCS pricing, traffic quota, features matrix from the plan features), order
  buttons to the WHMCS cart, fa/en, responsive, cache 10 min. Admin setting to enable/disable and to
  hide plans. Embeddable JSON `…&page=pricing&format=json` for the marketing site.
- Referral: each client gets a referral code (client area card: link `…/cart.php?ref=<code>`, counts,
  credit earned). The `ref` is stored in the session/cookie (30 days) and attached to the new client's
  first CDN order. When the referred client's first CDN invoice is paid (InvoicePaid hook): both get
  WHMCS credit (AddCredit) — amounts and currency set in addon settings (default off), once per
  referred client. Anti-abuse: no self-referral (same client, same email domain unless public mail
  provider list, same signup IP as referrer), max N rewards per referrer per month (setting), reward
  only after the invoice has been paid for ≥ X days (setting, default 7; a daily cron pays out), refunds
  before payout cancel it. Admin page: referrals list, pending/paid/cancelled, manual cancel. Ledger
  table `mod_pasargadcdn_referrals`. Uses WHMCS's own credit — no separate wallet.

### 18.6 Production rollout tooling
- `tools/preflight/preflight.py` (stdlib only): checks a live deployment from the operator's machine
  or the controller host: controller /healthz + /healthz/deep, migration head, each node's version vs
  bundle, node heartbeats fresh, ns1/ns2 answer SOA for a sample zone and serials match, controller TLS
  certificate days left, PowerDNS API not reachable from the public internet (best effort), backup age,
  alert channel test (optional flag), metrics endpoint protected (warn if open). Output: table + exit
  code; `--json`. Admin API key via env `PCDN_ADMIN_KEY`, never argv.
- `docs/ROLLOUT.md` (Persian): staged rollout (staging → one canary node + internal customers → all),
  WHMCS staging checklist (every item from docs/WHMCS.md "to verify"), rollback per component,
  go/no-go criteria, versioning and release process (tag vX.Y.Z on main, CHANGELOG.md).
- `CHANGELOG.md` (Keep a Changelog), version 2.0.0 for this PR's contents (waves 1–10, summarised).

### 18.7 As built
- Secrets travel inside the blocks as `waiting_room.secret` / `access.secret` (64 hex; HMAC key = raw
  bytes). Access enabled without a readable secret fails closed on the edge.
- OTP code: RFC 4226 dynamic truncation over HMAC-SHA256 of
  `"otp|"+app+"|"+lower(trim(email))+"|"+window` (window = unix/300, current and previous accepted);
  reference `controller/app/access.py::otp_code` with test vectors shared by the edge tests. Codes are
  single-use on the edge; 10 failures / 10 min lock the IP for 10 min.
- `node_max = ceil(max_active / n)`, n = edges DNS currently answers with for the site (≥1). The edge also
  caps new waiting-room sessions at 30 per IP per minute and skips abandoned tickets after 45 s.
- Statements: WHMCS passes `plan` (product name) and `block_gb` (prepaid block size); the PDF is
  deterministic (creation date = month start). Audit export masks actors for customers.
- WHMCS products get options `Waiting room` / `Protected access` (auto|on|off; `auto` sends nothing).
  Referral rewards over the monthly cap are deferred to the next month, not cancelled.

## 19. Operator domains and domain transfer

### 19.1 Operator (admin-owned) sites
The operator can run the platform's own domains on the CDN without a WHMCS service.
- Controller: `Site.owner_kind` = `client` | `reseller` | `operator` (migration; existing rows derived:
  reseller_client_id → reseller, else client). Operator sites have `client_id` = `reseller_client_id` =
  `external_id` = null, `operator_note` (≤200 chars, admin-only). Tenancy: all operator sites share one
  owner identity (`"operator"`), distinct from every client, so a customer can never add a parent/child
  of an operator domain and vice versa (same rule as C1).
- `POST /api/v1/sites` accepts `{"operator": true, "operator_note"?}` (then client_id / reseller fields /
  external_id must be absent → 422 otherwise). `GET /api/v1/sites?owner=operator|client|reseller`.
  `site_to_dict` exposes `owner_kind`, `operator_note`. `POST /api/v1/domain-check` accepts `operator`.
- Plans: an operator site takes any `plan` like other sites; the WHMCS page offers the wizard's plans as
  templates plus «داخلی — همه امکانات» (all features on, `bandwidth_limit_gb` 0 = unlimited, plan caps
  at their maximum validated values). Operator sites are never billed, never prepaid-cut and never
  suspended for quota by WHMCS (the controller quota still applies if a limit is set).
- WHMCS admin addon page «دامنه‌های اپراتور» (new tab):
  - add: domain (checked with domain-check), optional origin IP (proxied @ + www), plan template, note;
    shows the nameservers to set at the registrar and the NS status.
  - list: domain, status, NS, SSL, month traffic, plan, note; actions: **manage** (full client app in the
    admin area, below), NS recheck, purge all, suspend/unsuspend, change plan, delete (type the domain to
    confirm), **transfer** (§19.2).
  - **Manage in admin:** the server module's client app (all pages, both languages) is rendered inside
    the addon page in an admin context. Its API calls go to an addon proxy action that requires a WHMCS
    admin session with access to this addon plus the addon's CSRF token, and reuses the module's
    ClientApi whitelist/validation with a synthetic context (domain, the site's own features from the
    controller, never another site). Admin actions are audited with the admin username.
  - Operator sites are excluded from the sync report's "orphan" list, OwnerSync, prepaid, overage,
    storage billing, referral and trial logic, and are counted separately on the dashboard.

### 19.2 Domain transfer (complete move to another owner)
Directions: client → client, operator → client, client → operator. Reseller sub-sites are transferred
by their reseller tooling only (422 here, clear message).
- Controller: `POST /api/v1/sites/{d}/transfer`
  `{to: {kind: "client"|"operator", client_id?, external_id?}, reset_billing_anchor: bool,
    revoke_credentials: true, pause_integrations: true, include_related: false, dry_run: false}`
  - Tenancy check for the new owner (C1); parent/child sites with the old owner block the transfer
    unless `include_related` (then all of them move together, listed in the response).
  - In one transaction: owner fields + external_id updated; **customer API keys of the site revoked**
    (`revoke_credentials`); webhook endpoints and log export disabled and their stored secrets cleared
    (`pause_integrations`; settings kept so the new owner can re-enable with their own secrets);
    access-app secret rotated (old sessions end); everything else (DNS records, all config sections,
    SSL, rules, WAF, functions, storage buckets, analytics and usage history) stays with the site.
  - `reset_billing_anchor`: sets `Site.billing_since` = now; quota (`refresh_quota`) and the usage
    reported to WHMCS (`/api/v1/usage`, month bytes) then count from max(month start, billing_since).
    Used for operator → client so the new customer does not pay for the operator's traffic.
  - `dry_run` returns what would change (related sites, keys to revoke, integrations to pause).
  - Audited `site.transfer` {from, to, related, revoked_keys, paused}; webhook `site.transferred` is
    NOT sent to the old owner's endpoint (integrations are paused first).
- WHMCS (admin addon, «انتقال دامنه» wizard reachable from operator sites, the Sites page and a button
  on the admin service page):
  1. pick the destination client (search) or «اپراتور»;
  2. **client → client:** the WHMCS service itself moves to the new client — `tblhosting.userid`, its
     addons (`tblhostingaddons`), and module tables keyed by client; the service keeps its product,
     billing cycle, next due date, configurable options, prepaid ledger and this month's usage (the
     whole service moves). Options: move **unpaid** invoices that contain only this service's items
     (default on); move paid invoices of this service (default off, warning: changes the old client's
     accounting history); transfer an amount of credit from old to new client (default 0, uses
     AddCredit/negative credit with descriptions on both sides). Invoices mixing other items are never
     moved; they are listed.
  3. **operator → client:** creates a WHMCS service for the client on the chosen product + billing
     cycle without running the module's Create (the site already exists): status Active, domain,
     server, next due date chosen by the admin; optional first invoice (default: generate); then
     transfer with `reset_billing_anchor`.
  4. **client → operator:** transfer first, then the WHMCS service is set to Cancelled (never
     Terminate — the module's Terminate must not delete the site; a guard marks the service so a later
     Terminate skips the controller delete); optional pro-rata credit to the old client (amount entered).
  5. Preview step (controller `dry_run` + WHMCS changes), explicit confirmation, then execution;
     failure after the controller step rolls the WHMCS side back in a DB transaction and re-transfers
     the site back; every step logged (logActivity + controller audit).
  6. Optional e-mails to old and new client (templates «انتقال دامنه — مبدأ / مقصد», fa/en).
- Old owner's WHMCS team members lose access automatically (the service is no longer theirs); the
  client app shows the new owner a one-time banner: «این دامنه به حساب شما منتقل شد — کلید API،
  وب‌هوک‌ها و ارسال لاگ را دوباره تنظیم کنید».

### 19.3 Customer-initiated transfer (client area)
The owner of a CDN service can start a transfer to another client account from the client app; the
recipient must accept; the same complete client→client transfer as §19.2 then runs.
- Page «انتقال دامنه» in the client app (owner, and owner-side team members with manage rights only;
  never shared members or read-only team users; not for reseller sub-sites, operator sites or a
  service that is not Active). Form: recipient e-mail, optional message (≤300 chars, plain text),
  explicit confirmation checkbox, then a summary of what moves (service, billing cycle, next due date,
  recurring amount, unpaid invoices of this service, all settings) and what is revoked (API keys,
  webhooks/log export secrets, access sessions, storage keys, domain shares by default).
- One open request per service. Token 32 random bytes (stored hashed), 7-day expiry, single use.
  The owner can cancel it until accepted. Limits: 5 requests per owner per day.
- Recipient: must be an existing WHMCS client whose primary e-mail matches (case-insensitive); not the
  owner itself. Gets an e-mail (accept link, what will move to them incl. next due date and amount)
  and a client-area home card; the page shows the same summary and Accept / Decline (session + CSRF).
- Accept executes the §19.2 client→client transfer with the customer defaults: unpaid invoices that
  contain only this service move with it; paid invoices and credit never move; shares revoked; no
  billing anchor reset (the whole service with its month moves). Errors roll back as in §19.2.
- Addon setting «انتقال توسط مشتری» (on by default) and «تأیید مدیر لازم است» (off by default): when
  on, an accepted request waits in the admin «انتقال دامنه» tab (approve / reject) before executing.
- E-mails: request to the recipient, result to the owner (accepted/declined/expired/approved/rejected),
  admin notice. Every step logged (activity log of both clients + transfer ledger with
  `initiated_by: client`), visible in the admin «انتقال‌های اخیر» history.

## 20. Domain sharing (collaborators from other accounts)
The owner of a CDN service (or the operator, for operator sites) can share one domain with another
WHMCS client account so that person manages the domain's settings from their own client area — like
Arvan's domain members. Billing and ownership never move (that is §19 transfer).

### 20.1 Roles
| role | can | cannot |
|---|---|---|
| `viewer` | see every page, analytics, logs, download statements | change anything |
| `dns` | viewer + DNS records (incl. secondary DNS settings, DNSSEC view) | anything else |
| `editor` | every configuration page (DNS, SSL, cache, rules, WAF/firewall/bots, rate limit, access, waiting room, tunnel, functions, storage objects, L4, video/images, purge, webhooks/log export with their own secrets) | billing/upgrade/addon purchase, cancel/terminate, transfer, sharing management, customer API keys, team access, deleting the site, storage bucket key rotation |
Plan gating still applies (a shared user never gets a feature the plan lacks). A suspended service is
read-only for collaborators exactly as for the owner.

### 20.2 Invitations
- Owner (client area page «اشتراک دامنه», owner and owner-side team members with manage rights only)
  invites by e-mail + role; ≤ 20 active members per domain (setting), ≤ 50 pending invites per owner.
- If a WHMCS client with that e-mail exists, the invite shows on their client-area home (card «دعوت به
  مدیریت دامنه») and an e-mail with an accept link is sent; otherwise the e-mail invites them to
  register — the invite is bound to the e-mail and can only be accepted by a logged-in client whose
  primary e-mail matches (case-insensitive). Token: 32 random bytes, stored hashed, expires in 7 days,
  single use; accept/decline both need the client session + CSRF.
- The owner cannot invite themselves (same client id); inviting a member of their own team is refused
  with a hint to use WHMCS team access.
- Owner can change a member's role, revoke a member or a pending invite at any time (effective
  immediately — every proxied request re-checks the membership). A member can leave.
- Transfers (§19) revoke all shares and pending invites of the moved site by default (wizard option to
  keep); terminating/deleting the service or site removes them. Operator sites can be shared by the
  admin from the operator page (same roles).

### 20.3 Access path
- Members see «دامنه‌های اشتراکی» in the client area (addon client-area route
  `index.php?m=pasargadcdn_admin&page=shared`): list of domains shared with them (domain, role, owner's
  display name — company or first name only, never the owner's e-mail/contact data), and «مدیریت» opens
  the module's client app bound to that one domain in a `shared` context: same ClientApi whitelist,
  plus a per-role allow-list of operations (deny by default; an op not in the role's list → 403 with a
  Persian message). The app hides controls the role cannot use and shows a role badge.
- No billing data of the owner is exposed (invoices, credit, prices, prepaid wallet, upgrade links,
  addon purchases): those boot fields are omitted in the shared context.
- Every write by a member is audited: WHMCS module log + addon activity with
  `share:<member client id>:<role>`, and forwarded to the controller as header
  `X-PCDN-Actor: share:<id>:<role>` (controller records it in the audit detail as `on_behalf_of`;
  validated ≤ 64 chars, `[a-z0-9:_-]`, ignored when malformed). The owner's «گزارش تغییرات» shows who did it.
- Owner gets an e-mail when an invite is accepted (setting, default on).
- Data: table `mod_pasargadcdn_shares` (id, service_id nullable, operator_domain nullable, domain,
  owner_client_id nullable, member_client_id nullable until accepted, email, role, status
  pending|active|revoked|declined|expired|left, token_hash, expires_at, created_by, created_at,
  accepted_at, revoked_at) with indexes; a daily cron expires old invites.

### 20.4 Admin
- Addon page «اشتراک‌ها»: all shares with filters, revoke, and the audit trail; service tab shows the
  service's members.

### 20.5 As built
- Roles are enforced by a deny-by-default allow-list in WHMCS (`ClientApi::shareAllows`); billing,
  upgrade, cancel, transfer, sharing, team access, customer API keys, site delete and bucket key
  rotation are never proxied for members. Editors may create/delete storage buckets (storage is billed
  to the owner's service).
- WHMCS SendEmail reaches existing clients only: for an e-mail without an account the owner is shown
  the register-then-accept link once to forward it.
- Controller: admin DNS record writes are audited (they were not before) and the validated
  `X-PCDN-Actor` header is stored as `on_behalf_of` in the audit detail.
- §19 as built: controller head `0021`; transfers with `revoke_credentials` also rotate the image
  signing key, the secondary-DNS TSIG secret and storage bucket keys (after commit, retried by a
  scheduler job, deep-health warning while pending).

## 21. Per-domain feature overrides (admin)
Every feature is normally decided by the product plan (`pasargadcdn_plan()` → `plan.features`). The
operator can override any of them for one domain without changing the product.
- Scope: one CDN service (keyed by service id) or one operator site (keyed by domain). Stored in
  `mod_pasargadcdn_feature_overrides` (key, overrides JSON, admin id, updated_at), created idempotently.
- Editor «امکانات اختصاصی» (admin addon; reachable from the Sites row menu, the operator domains
  list, the admin service tab and the «انتقال دامنه»-style search of a new «امکانات اختصاصی» tab):
  every plan field of the controller's plan model — the top-level ones (bandwidth_limit_gb,
  max_records, ssl_allowed, rate_limit_rps) and every key of `features` (booleans, numeric limits,
  edge_group, sla_target; the list comes from the controller's DEFAULT_FEATURES via the site's plan, so
  new features appear automatically) — each with «طبق پلن» (inherit) or an explicit value; shows the
  plan value next to it and the effective value. Quick actions: «همه امکانات روشن» (every boolean on;
  limits untouched), «بازگشت به پلن» (clear all). Numeric inputs validated against the controller's
  ranges (422 messages shown).
- Effect: saving stores the overrides and immediately pushes the merged plan with
  `PATCH /api/v1/sites/{d}/plan`; every module path that sends a plan (Create, ChangePackage, renew /
  unsuspend resync, wizard re-runs, upgrades) merges overrides on top of the product plan, so an
  override survives plan changes until it is cleared. Turning a feature off keeps the site's saved
  section settings (the controller already ignores sections the plan lacks).
- Visibility: the client app shows overridden features as normal (no upsell lock); the admin service
  tab and Sites list show a badge «امکانات اختصاصی (n)». Audited: activity log with admin username +
  controller `site.plan` audit.
- Transfers (§19): overrides move with the domain (service id re-keyed / operator domain key moved);
  the transfer wizard shows them in the preview with an option to drop them.
- Billing: overrides never create invoices; storage_gb / addon traffic billing keep their own rules.
