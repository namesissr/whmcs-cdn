# Edge node (v2)

The edge is stock **Ubuntu 24.04 nginx 1.24** plus the distro dynamic modules
`libnginx-mod-http-js` (njs 0.8.2), `-geoip2`, `-image-filter` and `-brotli-filter`,
driven by `pcdn-agent` (stdlib-only Python). The controller contract is `docs/SPEC.md` §5.

## Files

| Source (repo) | Installed to | Purpose |
|---|---|---|
| `edge/pcdn-agent.py` | `/usr/local/bin/pcdn-agent` | sync loop: config → nginx, purges, usage/events |
| `edge/nginx/pcdn-base.conf` | `/usr/share/pcdn/nginx/` | **template** of the http-context config |
| `edge/njs/pcdn.js` | `/usr/share/pcdn/njs/` | request logic (verdict, LB, challenge pages, health checks) |
| `edge/pages/*.html` | `/usr/share/pcdn/pages/` | suspended / over-quota pages, `decoy.html` (tunnel fallback) |
| `edge/pcdn-geoip-update.sh` + `systemd/pcdn-geoip.{service,timer}` | `/usr/local/sbin/pcdn-geoip-update` | monthly DB-IP Country Lite download |
| — | `/etc/nginx/conf.d/00-pcdn.conf` | one line: `include /etc/nginx/pcdn/http.conf;` |

Everything under `/etc/nginx/pcdn/` is rendered by the agent and swapped in atomically
(`pcdn.new` → rename → `nginx -t` → reload, rollback on failure):

```
http.conf           base config rendered from the template (ports, resolver, GeoIP on/off, njs zones)
js/pcdn.js          copy of the njs code (so code + data change together)
js/sites.js         `export default {<site id>: {...}}` — per-site security/LB data (mode 0600, has HMAC secrets)
sites/<id>.conf     proxy_cache_path, per-site maps, one `server` per proxied host
certs/<id>.crt|key  certificates
errors/<id>-5xx.html, errors/<id>-4xx.html   custom error pages
```

`pcdn-agent bootstrap` writes an empty tree so nginx can start before the first sync
(the installer runs it). The agent re-renders even on an unchanged ETag when its own
inputs change (agent/njs/template upgrade, GeoIP database appearing, local settings).

## Request flow in a site `server`

1. `set $pcdn_site`, `$pcdn_proto`, `$pcdn_target` (`host:port`, or `$pcdn_upstream` for pools).
2. `if ($pcdn_verdict !~ "^(?:ok|log:)") { rewrite ^ /__pcdn/deny/$pcdn_verdict? last; }`
   `js_set $pcdn_verdict pcdn.verdict` evaluates, in order: `/__pcdn/*` → ok; `min_tls`
   (see below); legacy `blocked_ips`; firewall rules (first match, `allow` ends evaluation,
   `log` records and continues, `challenge`/`captcha` are satisfied by a clearance cookie);
   `default_action` (on tunnel paths evaluation stops here, see below); hotlink; rate-limit rules (fixed windows in `js_shared_dict_zone`);
   DDoS mode; WAF. The result is memoised in `js_var $pcdn_vmemo`, which survives internal
   redirects, so counters run exactly once per request (deny pages, error pages and the
   access log reuse it).
3. `force_https` redirect, image-resize rewrite, legacy `limit_req`.
4. Locations: `/__pcdn/*` (health, deny, verify, captcha, err, img — everything else 404),
   tunnel paths (`location ^~`), page rules as regex locations in order, static-file location,
   `location /`.

Verdict: `ok` or `<action>:<source>:<rule>` (`block:waf:942100`, `challenge:ddos:auto`,
`captcha:firewall:r2`, `block:ratelimit:login`, `log:firewall:r3`, `block:hotlink:referer`,
`block:firewall:blocked_ips`, `block:firewall:min_tls`, `block:firewall:default`).

Deny pages (Persian RTL + an English line, same style as `pages/suspended.html`):
403 block, 429 rate limit (with `Retry-After`), JS challenge, captcha.

* **JS challenge** — the page gets a token `exp.nonce.difficulty.HMAC(secret, ip|ua|exp|nonce|difficulty)`
  and finds `n` with `sha256(nonce + ":" + n)` starting with 4 hex zeros (pure-JS SHA-256, works
  on plain http). `GET /__pcdn/verify?t&n&r` checks it (single use), sets
  `__pcdn_clr=exp.js.HMAC(secret, clr|ip|ua|exp|js)` for `ddos.clearance_ttl` and redirects
  to `r` (local paths only).
* **Captcha** — server-rendered SVG of distorted stroke glyphs (no `<text>`). The answer is
  derived from `HMAC(secret, "capans|" + nonce)`, so nothing is stored; `POST /__pcdn/captcha`
  burns the token on any attempt (one guess per image). Captcha clearance (`cap`) also
  satisfies JS challenges; JS clearance does not satisfy captcha.

## WAF

Signatures in `njs/pcdn.js` (CRS-style ids): sqli 942xxx, xss 941xxx, lfi 930xxx, rce 932xxx,
php 933xxx, scanner 913xxx, protocol 920xxx; each has a paranoia level 1–3. Inputs: decoded
path, query arg names/values (double-decoded when still percent-encoded), cookie values,
User-Agent, Referer. Exclusions (`rule_id` + wildcard path, `0` = all rules) and page rules
with `waf: false` are honoured; `detect` logs `log:waf:<id>` and passes. The request **body is
not inspected** (njs `js_set` runs before the body is read).

## Load balancing

`js_set $pcdn_upstream pcdn.upstream` picks from the pool: weighted random or `ip_hash`
(FNV of the client IP), only healthy non-backup origins, then healthy backups, then fail
open to the non-backup origins. `js_periodic pcdn.health` (worker 0) fetches
`protocol://origin/path` with the pool's Host; state lives in `js_shared_dict_zone pcdn_hc`
(down after 2 consecutive failures, up after 1 success). A check is counted as failed
before it starts because njs kills a periodic instance still running at the next tick; the
tick is therefore rendered as `max(pool timeout) + 1` seconds.

## Cache

Key `$scheme://$host$request_uri`, or `$scheme://$host$pcdn_path` (no query) when
`ignore_query`; purges remove both variants of a URL, so purging `/a.css?v=1` also drops
`/a.css`. `standard` honours origin headers on dynamic paths and force-caches static
extensions (as v1); `aggressive` / page-rule `everything` cache 200/206/301 for `edge_ttl`
ignoring Cache-Control/Expires, **but never store a response carrying Set-Cookie** (it would
leak one visitor's session). `bypass_cookies` → `proxy_cache_bypass` + `proxy_no_cache` on
dynamic paths. `always_online` → `proxy_cache_use_stale error timeout http_5xx`. Response
header rules, HSTS, `X-Cache`, `X-Served-By` and all `proxy_set_header`s are emitted in every
proxying location because nginx drops inherited ones as soon as a location sets any.
`X-Country-Code` is sent to the origin.

## Images

With `image.enabled`, `*.jpg|jpeg|png|gif|webp?width=N&height=N` is rewritten to
`/__pcdn/img/…`, cached in the site zone (key includes the args) and proxied to a loopback
resize server (`RESIZE_PORT`, default 8089) that fetches the original from the origin
(without the resize args) through `image_filter resize` (+ jpeg/webp quality). Dimensions are
capped at `max_width`; images are never enlarged. Purging a resized variant needs its exact
URL (or a full purge).

## TLS

Per-server `ssl_protocols` is **not** honoured for SNI virtual hosts on nginx 1.24 (verified:
a TLSv1.3-only vhost still negotiated TLSv1.2), so `min_tls: "1.3"` is enforced in njs from
`$ssl_protocol` (`block:firewall:min_tls`). HSTS is sent over https only.

## GeoIP

`GEOIP_DB` (default `/usr/share/pcdn/geo/country.mmdb`, DB-IP Country Lite, CC BY 4.0) is
wired with `geoip2 … auto_reload 60m` only when the file exists; otherwise `$pcdn_country`
is empty and country conditions match neither `in` nor `not_in`. `pcdn-geoip.timer` refreshes
it monthly (current month, falling back to the previous one).

## Tunnel mode (SPEC §7)

For a site whose `tunnel.enabled` is true (the controller sends `enabled: false` when the plan
feature is off or the site is not active) every proxied host gets one location per tunnel path:

```
location ^~ "/my-secret-service" {
    set $pcdn_tn grpc;                                   # access log "tn"
    if ($pcdn_tcc_7 = 0) { return 403; }                 # allowed_countries (map on $pcdn_country)
    limit_conn pcdn_tn_site 500;  limit_conn pcdn_tn_ip 8;  limit_conn_status 429;
    client_max_body_size 0;  client_body_timeout / send_timeout = idle_timeout;
    tcp_nodelay on;  gzip off;  brotli off;
    grpc_set_header Host $host; X-Real-IP, X-Forwarded-*, X-Country-Code, request header rules
    grpc_read_timeout / grpc_send_timeout = idle_timeout;  grpc_socket_keepalive on;
    grpc_pass grpc://pcdn_tn_7_0;                        # or grpcs://, or a variable (see below)
}
```

* **Precedence.** `^~` prefix locations are matched before any regex location, so neither page
  rules nor the static-file location can take a tunnel path; the path is a plain prefix
  (`/ws` also matches `/ws2` and `/ws/x`). Paths are validated again on the edge
  (`/[A-Za-z0-9._~/-]{1,200}`, not `/__pcdn…`, unique, known protocol and pool).
* **Protocols.** `ws` / `httpupgrade`: `proxy_pass` HTTP/1.1 with `Upgrade` / `Connection`
  forwarded. `xhttp`: `proxy_pass` HTTP/1.1, `Connection ""`, `proxy_buffering off`,
  `proxy_request_buffering off` (chunked both ways, verified with a real streaming upload and
  download). `grpc` and `h2`: `grpc_pass` (`grpcs://` when the origin uses TLS, with
  `grpc_ssl_server_name on` and `grpc_ssl_name` = `origin.sni` or the host name;
  `grpc_ssl_verify` only with `origin.verify`). `grpc_pass` forwards any HTTP/2 stream, so it
  also carries XHTTP stream-one/stream-up to an h2c inbound. `grpc_set_header Host $host`
  makes nginx send a `host` header instead of `:authority` (nginx and Go h2 servers use it as the
  authority; verified against an nginx h2c origin).
* **Origin.** `origin` of the path, else `pool` (the same njs pool selection and health checks as
  hosts, through `js_set $pcdn_tn_upstream` reading `$pcdn_tn_pool`), else the host's own origin
  (record address or pool, host protocol). IP-literal origins of `xhttp` / `grpc` / `h2` paths get
  an `upstream pcdn_tn_<site>_<n> { server …; keepalive 16; }` block (separate blocks for HTTP/1.1
  and HTTP/2 so a cached connection never changes protocol); hostnames and pools stay variables
  so they are resolved at request time (`resolver`), without keepalive. Upgraded `ws` /
  `httpupgrade` connections are never reused, so they never use an upstream block.
* **Security.** Firewall **block** rules, `default_action: block`, `blocked_ips` and `min_tls`
  still apply; `allow` and `log` rules work as usual. njs (`tunnelVerdict`) skips firewall
  challenge/captcha rules, hotlink, rate-limit rules, the DDoS challenge and the WAF for URIs
  under a tunnel path (`tunnel_paths` in `sites.js`, same prefix test as nginx on the normalised
  `$uri`). The legacy `rate_limit_rps` `limit_req` runs in `limit_req_dry_run` mode there. No
  cache, no response header rules / HSTS / `X-Served-By`, no image rewrite, no gzip/brotli,
  `proxy_intercept_errors off`, `proxy_next_upstream off` (a stream is never replayed).
* **Limits.** `limit_conn_zone $pcdn_site` (`pcdn_tn_site`, `tunnel.max_connections`) and
  `$pcdn_site|$binary_remote_addr` (`pcdn_tn_ip`, `max_connections_per_ip`) are shared zones
  whose keys include the site id, so sites never share counters. Both count concurrent
  requests: a WebSocket/HTTPUpgrade session, one gRPC/h2 stream (not one TCP connection), one
  XHTTP request. Over the limit → 429.
* **per_connection_mbps is not enforced on nginx 1.24.** nginx resets `limit_rate` to 0 for
  unbuffered responses (`proxy_buffering off` and every `grpc_pass`, see
  `ngx_http_upstream_send_response`) and never applies it to upgraded connections; worse, a
  `limit_rate` delay on the `101` response made nginx miss the client's close, keeping the
  session (and its `limit_conn` slot) until the idle timeout. The value is validated but not
  rendered; `test_unbuffered_proxying_ignores_limit_rate_on_nginx_124` fails once an nginx
  honours it.
* **Timeouts.** `idle_timeout` is the upstream read/send timeout (`proxy_*` / `grpc_*`), the
  client body timeout and `send_timeout`. The HTTP/2 connection itself is idle-closed after
  `keepalive_timeout` (75 s) only when it has no open stream.
* **Fallback** for all other paths of the host: `origin` = the normal site; `decoy` =
  `pages/decoy.html` (a neutral "new website coming soon" page titled after the domain's first
  label, returned with 200 for every method, no image rewrite, no origin request); `404` =
  `return 404`. Security verdicts still run on those paths.
* **Listeners.** Every TLS listener is `listen 443 ssl http2` (nginx 1.24 syntax), so gRPC /
  h2 work on any site with a certificate, while ALPN `http/1.1` clients keep WebSocket /
  HTTPUpgrade / XHTTP. nginx cannot proxy WebSocket over HTTP/2 (RFC 8441), so ws/httpupgrade
  clients must negotiate HTTP/1.1 (Xray does). Plain port 80 speaks HTTP/1.1 only: gRPC / h2
  paths need a certificate.

## Access log

```
{"t","h","b","s","c","ip","cc","m","u","ua","v",   SPEC §5
 "tn": "grpc",      $pcdn_tn: tunnel protocol, "" for normal requests (map default, set in the location)
 "rt": 1800.25,     $request_time: the whole session for ws/httpupgrade, the stream for grpc/h2
 "bu": 188,         $request_length
 "ub": "20291"}     $upstream_bytes_sent (string: "" without upstream, "a, b" after retries)
```

Measured with real nginx 1.24 (`test_tunnel_log_fields_and_usage`): for a WebSocket session
that echoed 20 000 bytes, `b` = 20 201 (downstream frames are counted), `bu` = 188 (request
head only — frames after the 101 are **not** part of `$request_length`) and `ub` = 20 291
(the upgraded frames **are** counted: nginx takes it from the upstream connection's byte
counter, which the keepalive module resets on reuse). For a gRPC stream that uploaded 30 000
bytes, `bu` = 30 141 (HTTP/2 DATA is counted in `$request_length`) and `ub` = 30 275. The agent
therefore uses `bytes_up = max(bu, sum(ub))` per line (both contain the request head, so adding
them would double count), `bytes_down = b`.

The agent aggregates tunnel lines (`tn` non-empty) per host-hour into the usage item's optional
`tunnel` object: `sessions` (lines with status 101 or 2xx), `seconds` (sum of `rt`, rounded per
item), `bytes_up`, `bytes_down`, `by_protocol` (protocol → up + down). Tunnel lines still count
in `bytes` / `requests` like any request; the controller adds `bytes_up` for billing. Refused
tunnel requests (403 country, 429 limit) add bytes but no session; requests refused by a
security verdict are rewritten to the deny location before the tunnel location runs, so they
are logged as normal requests with their verdict.

## Heartbeat metrics (SPEC §7.4)

Every `HEARTBEAT_INTERVAL` seconds (60) the agent POSTs `/edge/v1/heartbeat` with the applied
version, the last apply error and `metrics`:

* `rx_mbps` / `tx_mbps` — `/proc/net/dev` byte deltas of the IPv4 default-route interface
  (`/proc/net/route`) between two heartbeats (the first one measures over one second); without a
  default route, the sum of all interfaces except `lo`, `docker*`, `veth*`, `br-*`, tunnels and
  other virtual ones. Counter resets give 0.
* `connections` — ESTABLISHED TCP sockets whose local port is `HTTP_PORT` / `HTTPS_PORT`
  (`/proc/net/tcp` + `tcp6`), i.e. client connections (upstream sockets are not counted).
* `load1` (`os.getloadavg`), `cpus` (`os.cpu_count`).

Every part is guarded: an unreadable file gives 0, a failed heartbeat is logged and retried at
the next tick; the agent never stops for metrics.

## System tuning (install.sh, idempotent)

* `/etc/sysctl.d/99-pcdn.conf`: BBR + `fq`, `somaxconn` / `tcp_max_syn_backlog` 65535,
  `netdev_max_backlog` 65536, `tcp_fastopen = 3`, `ip_local_port_range 10240 65535`,
  `tcp_tw_reuse`, `tcp_fin_timeout 15`, `tcp_slow_start_after_idle 0`, `tcp_mtu_probing 1`,
  64 MB `rmem_max`/`wmem_max` and `tcp_rmem`/`tcp_wmem` maxima, `tcp_notsent_lowat 128k`,
  keepalive 300 s / 30 s × 5 (dead VPN peers are noticed; `proxy_socket_keepalive` /
  `grpc_socket_keepalive` use it towards origins), `fs.file-max` / `fs.nr_open` 2 M.
  `tcp_bbr` is loaded now and at boot (`/etc/modules-load.d/pcdn-bbr.conf`).
  `/etc/sysctl.d/99-pcdn-conntrack.conf` (`nf_conntrack_max` 1 M, established timeout 1 day) is
  written only when conntrack is loaded.
* `/etc/systemd/system/nginx.service.d/pcdn-limits.conf`: `LimitNOFILE=1048576`.
* `nginx.conf` (main/events context, between the `# >>> nginx.conf edits` markers):
  `worker_rlimit_nofile 524288`, `worker_connections 65535`, `multi_accept on`; stock
  `gzip on`, `ssl_protocols`, `ssl_prefer_server_ciphers`, `keepalive_timeout` are commented out
  because http.conf sets them.
* http.conf (http context): `keepalive_timeout 75s`, `keepalive_requests 100000` (also the
  per-connection stream cap of HTTP/2 since nginx 1.19.7), `http2_max_concurrent_streams 512`,
  `reset_timedout_connection on`.

## Agent settings (`/etc/pcdn/agent.conf`, or `PCDN_<KEY>` env)

v1 keys plus `HTTP_PORT` (80), `HTTPS_PORT` (443), `RESIZE_PORT` (8089), `RESOLVER`
(`1.1.1.1 8.8.8.8`), `GEOIP_DB`, `NJS_FILE`, `BASE_TEMPLATE`, `CA_BUNDLE` (origin_verify),
`DICT_SIZE` (rate-limit/DDoS counter zone, 32m), `HEARTBEAT_INTERVAL` (60 s).

## Usage / events

The access log line (`log_format pcdn`) is SPEC §5. Per host-hour the agent aggregates bytes,
requests, cache hits, status classes, codes, countries, top-50 paths and `security` counters
by verdict source (plus `challenge` for challenge/captcha actions); every non-ok verdict becomes
an event. Items (≤ 20 000) and events (≤ 2 000) are POSTed in batches; unacknowledged data
stays in the state file (events backlog capped at 10 000, newest kept). v1 state files and log
rotation handling keep working.

## Tests

```
cd edge && python3 -m pytest -q tests/
```

`test_agent.py` (rendering, escaping, purge, usage, tunnel rendering/usage, heartbeat metrics,
installer edits against the stock `nginx.conf`), `test_njs_logic.py` (pcdn.js logic under node
with mocks: CIDR/IPv6, WAF signatures and false positives, pool selection, tunnel verdicts),
`test_nginx_e2e.py` (real nginx + njs on high ports with python origins and a generated mmdb
mapping 127.0.0.0/8 → CN) and `test_tunnel_e2e.py` (real nginx: WebSocket and HTTPUpgrade echo,
XHTTP streaming upload/download, gRPC and raw h2 bidirectional streams, security bypass vs.
blocks, allowed countries, per-IP/per-site `limit_conn`, decoy/404 fallback, log fields and
usage). The tunnel origins are stdlib stand-ins in `tests/tunnel_kit.py` (WebSocket framing,
an h2c echo server and an HTTP/2-over-TLS client that never need HPACK Huffman decoding) plus
an nginx h2c server, so CI needs no extra packages. Tests skip
when nginx, the modules or node are missing; the e2e nginx runs `user root` because pytest
temp dirs are not traversable by unprivileged workers.
