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
  `curl -fsSL https://<controller>/edge/bootstrap.sh | sudo bash -s -- --controller https://<controller> --token edge_xxx`
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
