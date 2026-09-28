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
| `edge/pages/*.html` | `/usr/share/pcdn/pages/` | suspended / over-quota pages |
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
   `default_action`; hotlink; rate-limit rules (fixed windows in `js_shared_dict_zone`);
   DDoS mode; WAF. The result is memoised in `js_var $pcdn_vmemo`, which survives internal
   redirects, so counters run exactly once per request (deny pages, error pages and the
   access log reuse it).
3. `force_https` redirect, image-resize rewrite, legacy `limit_req`.
4. Locations: `/__pcdn/*` (health, deny, verify, captcha, err, img — everything else 404),
   page rules as regex locations in order, static-file location, `location /`.

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

## Agent settings (`/etc/pcdn/agent.conf`, or `PCDN_<KEY>` env)

v1 keys plus `HTTP_PORT` (80), `HTTPS_PORT` (443), `RESIZE_PORT` (8089), `RESOLVER`
(`1.1.1.1 8.8.8.8`), `GEOIP_DB`, `NJS_FILE`, `BASE_TEMPLATE`, `CA_BUNDLE` (origin_verify),
`DICT_SIZE` (rate-limit/DDoS counter zone, 32m).

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

`test_agent.py` (rendering, escaping, purge, usage, installer edits against the stock
`nginx.conf`), `test_njs_logic.py` (pcdn.js logic under node with mocks: CIDR/IPv6, WAF
signatures and false positives, pool selection) and `test_nginx_e2e.py` (real nginx + njs on
high ports with python origins and a generated mmdb mapping 127.0.0.0/8 → CN). Tests skip
when nginx, the modules or node are missing; the e2e nginx runs `user root` because pytest
temp dirs are not traversable by unprivileged workers.
