# Edge node (v2)

The edge is stock **Ubuntu 24.04 nginx 1.24** plus the distro dynamic modules
`libnginx-mod-http-js` (njs 0.8.2), `-geoip2`, `-image-filter` and `-brotli-filter`,
driven by `pcdn-agent` (stdlib-only Python). The controller contract is `docs/SPEC.md` §5.

## Files

| Source (repo) | Installed to | Purpose |
|---|---|---|
| `edge/pcdn-agent.py` | `/usr/local/bin/pcdn-agent` | sync loop: config → nginx, purges, usage/events |
| `edge/pcdn_agent/` | `/usr/local/lib/pcdn/pcdn_agent/` | the agent package (settings, validation, render/*, usage, logship, apply, cli); `pcdn-agent` is its launcher |
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
`/a.css`. A purge item may also carry `prefixes` and `everything`: `everything` (or the legacy
empty `urls`) wipes the whole site cache dir; a `prefix` (`/blog/` for any host, or
`https://ex.com/img/` to pin the host) is applied by scanning the site's cache files and reading
each file's `KEY: <scheme>://<host><uri>` header line, deleting the files whose key path starts
with the prefix. Exact URLs keep the fast hashed-key delete. The scan is capped at
`PURGE_SCAN_MAX` files (default 500000); past the cap it falls back to a full-site purge, and it
never raises. `standard` honours origin headers on dynamic paths and force-caches static
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
  an `upstream pcdn_tn_<site>_<n> { server …; keepalive <TUNNEL_KEEPALIVE, default 64>;
  keepalive_timeout 300s; keepalive_requests 1000000; keepalive_time 1h; }` block (separate blocks
  for HTTP/1.1 and HTTP/2 so a cached connection never changes protocol). A warm pool of idle
  connections to the VPN origin removes the cross-border TCP+TLS handshake from the next
  stream/request, and the high `keepalive_requests`/`keepalive_time` stop a long VPN session from
  recycling a working upstream connection mid-use. Hostnames and pools stay variables so they are
  resolved at request time (`resolver`), without keepalive. Upgraded `ws` / `httpupgrade`
  connections are never reused, so they never use an upstream block.
* **Security.** Firewall **block** rules, `default_action: block`, `blocked_ips` and `min_tls`
  still apply; `allow` and `log` rules work as usual. njs (`tunnelVerdict`) skips firewall
  challenge/captcha rules, hotlink, rate-limit rules, the DDoS challenge and the WAF for URIs
  under a tunnel path (`tunnel_paths` in `sites.js`, same prefix test as nginx on the normalised
  `$uri`). The legacy `rate_limit_rps` `limit_req` runs in `limit_req_dry_run` mode there. No
  cache, no response header rules / HSTS / `X-Served-By`, no image rewrite, no gzip/brotli,
  `proxy_intercept_errors off`. On a **connect** failure only, tunnel origins fail over to the next
  peer — `proxy_next_upstream error timeout` / `grpc_next_upstream error timeout`, `*_tries 2`,
  `*_timeout 15s`; never `non_idempotent` or `http_5xx`, so an in-flight stream is still never
  replayed (F28). This is a no-op for a single-peer target (one host:port, `max_fails=0`).
* **Limits.** `limit_conn_zone $pcdn_tn_ckey` (`pcdn_tn_site2`, `tunnel.max_connections`) and
  `$pcdn_tn_ipkey` = `$pcdn_tn_ckey|$binary_remote_addr` (`pcdn_tn_ip2`, `max_connections_per_ip`)
  are shared zones whose keys include the site id, so sites never share counters. They count
  concurrent tunnel **sessions**, not every request (F13): a WebSocket/HTTPUpgrade session and each
  gRPC/h2 stream count one; for XHTTP only the downlink GET is keyed (`$pcdn_tn_ckey =
  $pcdn_tn_isget`), so a packet-up POST consumes no slot and reaching the limit refuses a *new*
  session instead of tearing down an established one. Over the limit → 429. (The zone names carry a
  `2` suffix because nginx refuses a reload that changes an existing zone's key — a mismatch
  `nginx -t` does not catch.)
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

## Tunnel data-path tunables (buffers & timeouts)

Buffers and timeouts on the tunnel data path are `agent.conf` keys. Defaults suit a mixed
general/tunnel node; `install.sh --role tunnel` raises the throughput-oriented ones (it writes
`SSL_BUFFER_SIZE=16k` and `TUNNEL_H2_BODY_BUFFER=512k`). Raise them on dedicated tunnel nodes with
spare RAM; lower the per-stream buffer on small nodes.

* `TUNNEL_H2_BODY_BUFFER` (default `256k`, F3): per-stream `client_body_buffer_size` for HTTP/2
  tunnel uploads (gRPC/h2/XHTTP). The default HTTP/2 window is only 64k, which caps a single
  stream's in-flight upload at 64 KiB; this raises it. The buffer is allocated per active stream
  whose body has no `Content-Length`, so cost ≈ concurrent streams × size (≈ 2.5 GB for 10k gRPC
  streams at 256k). Use `128k` on ≤2 GB nodes. Applied only at tunnel locations, never as a
  server/http-level `http2_body_preread_size`.
* `TUNNEL_RELAY_BUFFER` (default `16k`, F14): the relay buffer on the tunnel data path
  (`proxy_buffer_size` / `grpc_buffer_size` and the location-level `http2_chunk_size`). The old 4k
  buffers cost about 2.3× the CPU per tunneled byte. Costs about +12k per active TLS connection
  (freed while idle), ≈ 240 MB per 10k WebSocket sessions.
* `SSL_BUFFER_SIZE` (default `4k`, F14): the http-level `ssl_buffer_size`. Pure-tunnel hosts (whose
  `tunnel.fallback` is `decoy` or `404`) additionally get `ssl_buffer_size 16k` in their server
  block. `--role tunnel` sets this to `16k` node-wide; general web nodes keep `4k` for faster TLS
  first byte.
* `TUNNEL_CONNECT_TIMEOUT` (default `10`, clamped 3-30 s, F12): drives **both**
  `proxy_connect_timeout` and `grpc_connect_timeout` for tunnel origins, so a dead origin fails fast
  instead of hanging on nginx's 60 s gRPC default. Raise to ~15 on a lossy path.
* `TUNNEL_KEEPALIVE_REQUESTS` (default `10000000`, N2/F27): client-facing HTTP/2 stream cap per
  connection, emitted in the tunnel server block only (overriding the http-level
  `keepalive_requests 100000`). A low value forces a mid-session GOAWAY + reconnect for stream-heavy
  XHTTP/gRPC tunnels; non-tunnel hosts keep the bounded default.

(`TUNNEL_KEEPALIVE`, default 64, is the number of idle **upstream** keepalive connections kept per
worker to each IP-literal tunnel origin — see the **Origin** bullet above.)

## Access log

```
{"t","h","b","s","c","ip","cc","m","u","ua","v",   SPEC §5
 "tn": "grpc",      $pcdn_tn: tunnel protocol, "" for normal requests (map default, set in the location)
 "rt": 1800.25,     $request_time: the whole session for ws/httpupgrade, the stream for grpc/h2
 "bu": 188,         $request_length
 "ub": "20291",     $upstream_bytes_sent (string: "" without upstream, "a, b" after retries)
 "us": "200",       $upstream_status ("" = no upstream contacted; SPEC §14.3.1 platform_errors)
 "pg": "",          $pcdn_page: "site" for the suspended / over-quota page
 "sc": "https",     $scheme            (log export, SPEC §14.3.2)
 "pr": "HTTP/2.0",  $server_protocol   (log export)
 "rf": "...",       $http_referer      (log export; query stripped before shipping)
 "tp": "grpc1",     $pcdn_tp: tunnel path id ("" for normal requests; SPEC §15.1)
 "uct": "0.012"}    $upstream_connect_time ("-" when the connect failed)
```

The 6D fields are appended at the end, so the parser still accepts lines written before an upgrade
(they simply never count as platform errors and carry no scheme/protocol/referer).

Measured with real nginx 1.24 (`test_tunnel_log_fields_and_usage`): for a WebSocket session
that echoed 20 000 bytes, `b` = 20 201 (downstream frames are counted), `bu` = 188 (request
head only — frames after the 101 are **not** part of `$request_length`) and `ub` = 20 291
(the upgraded frames **are** counted: nginx takes it from the upstream connection's byte
counter, which the keepalive module resets on reuse). For a gRPC stream that uploaded 30 000
bytes, `bu` = 30 141 (HTTP/2 DATA is counted in `$request_length`) and `ub` = 30 275. The agent
therefore sets `bytes_up` per line **by protocol** (F37): `ws` / `httpupgrade` use
`max(bu, sum(ub))`, because frames after the 101 are not in `$request_length` and only `ub` counts
them; `grpc` / `h2` / `xhttp` use `bu` alone (`$request_length`), because for those `ub` also counts
the headers the edge injects toward the origin and any retry re-sends, which would over-bill the
customer. `bytes_down = b`. The client's own forwarded request head is still billed via
`$request_length` (unavoidable); only the edge-added header delta is removed.

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

The heartbeat also carries `bundle_version` (the running edge bundle version, SPEC §11.1; from
`BUNDLE_VERSION_FILE` written by `bootstrap.sh`, else a hash of the agent file) and, on the
**first** contact of a fresh node, `region`/`group` from the config, so the node self-registers
into the right pool. The controller applies region/group only on first contact and never
overrides a later operator edit.

## One-command install & bundle (SPEC §11.1)

The controller serves the secret-free edge tree so a node is brought up with one command:

```
curl -fsSL https://<controller>/edge/bootstrap.sh | sudo PCDN_EDGE_TOKEN=edge_xxx bash -s -- \
    --controller https://<controller> [--region home|global] [--role general|tunnel] ...
# token also via --token-file F or a no-echo prompt; --token still works; https only unless --insecure-http
```

`edge/bootstrap.sh` downloads `GET /edge/bundle.tar.gz` (a gzip tar of `edge/` built on the fly
from `EDGE_BUNDLE_DIR`, excluding `__pycache__`/`*.pyc`/`tests/`), unpacks it and runs `install.sh`
with the same flags. `GET /edge/version` returns the bundle hash (`bootstrap.sh` records it to
`/etc/pcdn/bundle.version`). All three routes are unauthenticated and hold no secrets; when
`EDGE_BUNDLE_DIR` is unset/missing they return 404 and the panel falls back to manual git/scp.
`install.sh` gains `--region` and `--role` (persisted to `/etc/pcdn/agent.conf` as `REGION` /
`GROUP`). See `docs/NODES.md` for the operator runbook (batch add, upgrade with `--upgrade`,
decommission, troubleshooting) and `edge/cloud-init.yaml.example` for unattended first-boot.

## Centralized logs (SPEC §11.2)

On the heartbeat cadence the agent tails the nginx error log (`ERROR_LOG`) and its own WARN/ERROR
lines and POSTs only new `warn`/`error`/`crit` lines to `POST /edge/v1/logs`
(`{lines:[{t,level,msg}]}`). It de-duplicates against the last batch, tracks a file offset (with
rotation/truncation handling like the access log), caps ~40 lines/report and ~500 chars/line, and
**redacts** IPs, `client:` fields and `edge_`/`pcdn_` tokens — it never ships access logs, request
bodies, visitor IPs, tokens or keys. Log shipping is fail-soft: it never crashes the agent or
blocks the heartbeat. The controller keeps a capped ring (~120 lines / ~16 KiB) per edge, exposed
at `GET /api/v1/edges/{id}/logs`.

## System tuning (install.sh, idempotent)

* `/etc/sysctl.d/999-pcdn.conf` (F30: numbered so it sorts after `99-sysctl.conf`; the old
  `99-pcdn.conf` is `rm`'d on `--upgrade`): BBR + `fq`, `somaxconn` / `tcp_max_syn_backlog` 65535,
  `netdev_max_backlog` 65536, `tcp_fastopen = 3`, `ip_local_port_range 10240 65535`,
  `tcp_tw_reuse`, `tcp_fin_timeout 15`, `tcp_slow_start_after_idle 0`, `tcp_mtu_probing 1`,
  64 MB `rmem_max`/`wmem_max` and `tcp_rmem`/`tcp_wmem` maxima, `tcp_notsent_lowat 128k`,
  keepalive 300 s / 30 s × 5 (dead VPN peers are noticed; `proxy_socket_keepalive` /
  `grpc_socket_keepalive` use it towards origins), `tcp_no_metrics_save 1` and `tcp_sack 1` so a
  bad congestion window from the lossy cross-border path is not cached onto the next connection,
  `fs.file-max = 9223372036854775807` with `fs.nr_open` left at the systemd default (F31: the old
  2 M cap sat below systemd's own defaults; the per-process `LimitNOFILE` / `worker_rlimit_nofile`
  are the real limit). After `sysctl --system`, install.sh reads each key back with `sysctl -n`
  and prints a `warning:` on any mismatch (e.g. a value overridden by `/etc/sysctl.conf`), and
  attaches `fq` to the default-route interface immediately when it is single-queue (a multiqueue
  NIC prints a `warning:` to reboot so `default_qdisc=fq` attaches per hardware queue instead).
  `tcp_bbr` is loaded now and at boot (`/etc/modules-load.d/pcdn-bbr.conf`).
  `/etc/sysctl.d/999-pcdn-conntrack.conf` (`nf_conntrack_max` 1 M, established timeout 1 day) is
  written unconditionally, and `nf_conntrack` is pinned at boot
  (`/etc/modules-load.d/pcdn-conntrack.conf`) with `hashsize 262144`
  (`/etc/modprobe.d/pcdn-conntrack.conf`, also applied live via `/sys`), so conntrack tuning
  survives netfilter loading after install or a reboot (F19); the old `99-pcdn-conntrack.conf` is
  removed on `--upgrade`.
* Default-server `listen` lines (pcdn-base.conf, both HTTP and HTTPS, IPv4 + IPv6):
  `reuseport backlog=65535 so_keepalive=120s:30s:4`. `reuseport` spreads long-lived tunnel
  connections across all workers (F4), `backlog=65535` lets the `somaxconn` / `tcp_max_syn_backlog`
  tuning actually take effect (F16), and `so_keepalive` detects a dead or NAT-expired client after
  ~4 min and frees its `limit_conn` slot (F17). These options sit only on the `default_server`
  listens; per-site `listen` lines stay bare, or nginx rejects the reload with "duplicate listen
  options".
* `/etc/systemd/system/nginx.service.d/pcdn-limits.conf`: `LimitNOFILE=1048576`.
* `nginx.conf` (main/events context, between the `# >>> nginx.conf edits` markers):
  `worker_rlimit_nofile 524288`, `worker_connections 65535`, `multi_accept off` (F4: forcing it
  **on** piled long-lived tunnel connections onto one worker, capping the node at one core and one
  65535-connection budget) and `worker_shutdown_timeout 1h` (`--shutdown-timeout`; F6: bounds how
  many draining worker generations a reload leaves pinned by long-lived tunnels — lower to 20-30m on
  ≤4 GB nodes, never a value in seconds, which would hard-cut every tunnel on each reload); stock
  `gzip on`, `ssl_protocols`, `ssl_prefer_server_ciphers`, `keepalive_timeout` are commented out
  because http.conf sets them.
* http.conf (http context): `keepalive_timeout 75s`, `keepalive_requests 100000` (also the
  per-connection stream cap of HTTP/2 since nginx 1.19.7; tunnel hosts override it per server with
  `TUNNEL_KEEPALIVE_REQUESTS`), `http2_max_concurrent_streams 512`, `reset_timedout_connection on`,
  and `proxy_connect_timeout` / `grpc_connect_timeout` = `TUNNEL_CONNECT_TIMEOUT` (10 s, F12).

## Agent settings (`/etc/pcdn/agent.conf`, or `PCDN_<KEY>` env)

v1 keys plus `HTTP_PORT` (80), `HTTPS_PORT` (443), `RESIZE_PORT` (8089), `RESOLVER`
(`1.1.1.1 8.8.8.8`), `GEOIP_DB`, `NJS_FILE`, `BASE_TEMPLATE`, `CA_BUNDLE` (origin_verify),
`DICT_SIZE` (rate-limit/DDoS counter zone, 32m), `HEARTBEAT_INTERVAL` (60 s),
`PURGE_SCAN_MAX` (max cache files scanned per prefix purge before falling back to a full-site
purge, 500000), `ERROR_LOG` (nginx error log tailed for centralized logs, `/var/log/nginx/error.log`),
`BUNDLE_VERSION_FILE` (`/etc/pcdn/bundle.version`), `REGION` / `GROUP` (reported on first heartbeat).

Tunnel data-path keys are listed under **Tunnel data-path tunables** above
(`TUNNEL_H2_BODY_BUFFER` 256k, `TUNNEL_RELAY_BUFFER` 16k, `SSL_BUFFER_SIZE` 4k,
`TUNNEL_CONNECT_TIMEOUT` 10, `TUNNEL_KEEPALIVE_REQUESTS` 10000000, `TUNNEL_KEEPALIVE` 64). Reload
and usage keys: `RELOAD_MIN_INTERVAL` (reload-coalescing floor, 120 s, F5), `RELOAD_DEBOUNCE` (a
freshly-seen version settles this long before applying so sub-debounce bursts coalesce, 5 s, F5),
`RELOAD_VERIFY` (after a reload, poll `/__pcdn/confver` and retry if the master rejected the reload,
`yes`, F29), `USAGE_TIMEOUT` (usage POST timeout, 150 s — strictly above Caddy's 120 s header
timeout so a batch is never replayed, F7), `USAGE_OUTBOX_MAX_DAYS` (drop an unacknowledged usage
batch older than this, 6 days — inside the controller's 7-day `batch_id` dedup window, F7),
`FOREIGN_DEFER` (defer a reload up to this long when only another edge group's sites changed and no
global file changed, 900 s, F21).

Log export keys (SPEC §14.3.2): `LOGSHIP_SPOOL_DIR` (default: `logship/` next to `STATE_FILE`, dir
0700 / files 0600), `LOGSHIP_SPOOL_MAX_MB` (256 — oldest batches dropped beyond it, and anything
older than 72 h), `LOGSHIP_INTERVAL` (30 s), `LOGSHIP_TIMEOUT` (30 s per POST). `install.sh --upgrade`
keeps these if an operator set them.

## Usage / events

The access log line (`log_format pcdn`) is SPEC §5. Per host-hour the agent aggregates bytes,
requests, cache hits, status classes, codes, countries, top-50 paths and `security` counters
by verdict source (plus `challenge` for challenge/captcha actions); every non-ok verdict becomes
an event. Items (≤ 20 000) and events (≤ 2 000) are POSTed in batches; unacknowledged data
stays in the state file (events backlog capped at 10 000, newest kept). v1 state files and log
rotation handling keep working.

**Live analytics (SPEC §14.3.1).** The same log pass also buckets per host-minute: requests, bytes,
cache hits, status classes, top-20 countries and top-20 paths (query stripped). They ride in the
same usage POST as `live` (same outbox entry and `batch_id`), ≤ 5 000 items / ~2 MiB per POST and
20 000 items / 8 MiB across the outbox, oldest minutes dropped first, nothing older than 24 h. If
the controller rejects a POST carrying `live` (400/413/422) it is resent once without it under the
same `batch_id`, so hourly usage is never held back by live data.

**platform_errors (SPEC §14.3.1).** Counted per host-hour when the status is 500–599 except 501
and 505 (any visitor can provoke those with a malformed request, which would let anyone lower a
site's SLA), `us` is present and empty (no upstream contacted — any upstream status is an origin
error), the response was not served from cache, the verdict is not block/challenge/captcha and
`pg` is not `site`. Known limit: an origin *hostname* that fails to resolve is logged without an
upstream, so it counts as a platform error even when the cause is the customer's own DNS.

**Log export (SPEC §14.3.2).** For sites whose config has `logs.enabled`, a line is kept when
`blake2b-64(raw line) / 2^64 < sample_rate` (deterministic). Tunnel traffic and `/__pcdn/`
requests are excluded; with `anonymize_ip` the IP is reduced (IPv4 /24, IPv6 /48) before anything
is written to the spool. Records are spooled on disk in batches (stable 32-hex `batch_id` = file
name, reused verbatim on retries) and POSTed to `/edge/v1/logship` (≤ 5 000 records / ~2 MiB)
on their own cadence with a time box, backoff 30 s → 15 min; a 404 (older controller) pauses
shipping until the config version changes; a 400/413/422 drops that one batch (counted). The
heartbeat reports `capabilities.live_analytics` / `capabilities.logship` and a `logship` block
(sites, spool size, dropped, disabled).

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

## Tunnel quality, fair share & speed test (SPEC §15)

**Per-path telemetry.** Per host-hour the usage item's `tunnel.paths` carries, per path id (≤ 50):
sessions, seconds, bytes, `abnormal`, `connect_ms_sum`/`connect_n` and classified `errors`
(`classify_tunnel`, first match wins): gRPC over HTTP/1.x → `protocol`; 101/2xx → session; 499 after
an accepted upgrade → session (client close); no upstream contacted: 429/503 → `limit`, 403 →
`country`, 400/426 → `protocol`, other 5xx → `edge`; last upstream 502 → `origin_refused`, 504 →
`origin_timeout`; any other upstream status → `origin_error`. `abnormal` comes from the nginx error log
(`[error]` … "while proxying upgraded connection" / "while reading upstream"), because the access log
cannot tell an origin reset from a clean end. Live minute items add `tunnel_attempts`/`tunnel_errors`.

**426 for ws/httpupgrade without `Upgrade`.** The edge answers before the origin is contacted, so a
client configured with the wrong protocol shows up as `protocol` instead of an opaque origin error.

**Fair share (admission only).** nginx 1.24 cannot rate-limit upgraded/unbuffered streams, so fair share
refuses NEW sessions (429) of one dominant site while the node is hot (≥ 85 % of `node.capacity_mbps`,
cleared below 80 %); see SPEC §15.8 for the exact rule. Established sessions are never touched; the hot
flag lives in the `pcdn_fair` shared dict, is refreshed on every heartbeat and expires after 180 s.
Capacity comes from the controller (`node.capacity_mbps`, set per node in the panel) or `CAPACITY_MBPS`
in agent.conf; 0 = never hot.

**Speed test.** `/__pcdn/speed/{ping,down,up}` on every active site (CORS `*`, no-store, rate-limited
per IP, counted as normal traffic). Downloads are served from `SPEED_FILE` (random data written once,
10 MiB) via the flv module (`--with-http_flv_module`); `X-Pcdn-Node` is a hash of the node name, never
an address.

New agent.conf keys (kept by `--upgrade`): `CAPACITY_MBPS` (0), `FAIR_SHARE_PCT` (25), `NODE_NAME`
(hostname), `SPEED_FILE` (`speed.bin` next to the state file).


## Wave 8 (SPEC §16)

- **L4 proxy:** `l4/stream.conf` (stream block, JSON log `L4_ACCESS_LOG`) + `l4/sites/<sid>.conf`, rendered
  from the node-wide `l4` list; needs `libnginx-mod-stream` and `include /etc/nginx/pcdn/l4/*.conf;` in the
  main context of nginx.conf (install.sh adds both). Apps outside `L4_PORT_RANGE`, on node ports or on busy
  ports are skipped with a warning. Usage `l4: {app: {bytes_in, bytes_out, sessions}}` (not in `bytes`).
- **Video:** manifest/segment cache rules, `slice 1m` for mp4, media CORS `*`, bounded mirror prefetch.
- **Images v2:** signed `w,h,fit,q,fmt` transforms (403 on bad signature), AVIF via `avifenc`/Pillow,
  smart crop; transformer `pcdn-imaged` (systemd sandbox, loopback `IMAGE_PORT`).
- **Net guard:** `pcdn-agent guard` renders nftables `inet pcdn_guard`; `install.sh --harden-net` applies it
  (`GUARD_*` keys, SSH/allow-list first, optional SYN proxy).
- **Storage origins:** `origin.storage` hosts proxied with SNI + verification, bucket Host, Referer token
  (0600 `storage/<sid>.conf`), GET/HEAD only, no visitor credentials, loopback `STORAGE_FETCH_PORT` (8091)
  for the image paths.
- **Edge Functions:** `pcdn-fn` (edge/pcdn-fn.py, runtime edge/fn/runtime.js, unit edge/systemd/pcdn-fn.service)
  runs one QuickJS process per invocation under Landlock + seccomp + no_new_privs + MDWE + rlimits; nginx
  routes bound paths to it over a unix socket; `fetch()` goes back through `/run/pcdn-fnfetch/fetch.sock`
  to the site's own origin only. Capability `edge_functions` only after the self-test passes. Usage
  `functions: {invocations, cpu_ms, errors, timeouts}`.
- New agent.conf keys: `L4_PORT_RANGE`, `L4_ACCESS_LOG`, `NGINX_CONF`, `IMAGED`, `IMAGE_PORT`,
  `IMAGE_WORKERS`, `IMAGE_MAX_SOURCE_MB`, `GUARD*`, `AVIF`, `STORAGE_FETCH_PORT`, `FUNCTIONS`, `FN_*`
  (all kept by `--upgrade`).
