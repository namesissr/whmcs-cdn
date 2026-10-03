# Changelog

All notable changes to Pasargad CDN (controller, edge, WHMCS modules, CLI, Terraform provider, deploy
kit and docs) are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The platform version (`vX.Y.Z` tag on `main`) covers the controller, edge bundle, WHMCS modules and
deploy kit, which are released together. The `pcdn` CLI (`cli/vX.Y.Z`) and the Terraform provider
(`provider/vX.Y.Z`) keep their own tags and release notes (`.github/workflows/release.yml`). The release
process is described in [docs/ROLLOUT.md](docs/ROLLOUT.md).

## [Unreleased]

### Added — wave 13: tunnel speed and stability (SPEC §22), controller

Migration `0022` (edges drain / probe / reload / tuning / `http3_enabled` / `dns_weight_level` columns,
`sites.ssl_cert_rsa` + encrypted `ssl_key_rsa`, table `edge_events`). Every new switch defaults to the
previous behaviour. Node selection stays health / load / capacity driven; DNS answers of tunnel sites are
never truncated or sampled.

- **Node drain** (§22.1): `POST|DELETE /api/v1/edges/{id}/drain` (409 `last_edge` unless `force`,
  409 `already_draining`), edge self-drain `POST /edge/v1/drain` (rate limited), `node.drain` in the edge
  config, heartbeat `drain` (`drained`), automatic `drained` at `drain_until` and auto-undrain after
  `DRAIN_MAX_HOLD_MINUTES` (alert `edge_drain_stuck`). Draining edges leave DNS answers and shield peers
  without ever emptying a group+region pool. Env: `DRAIN_DEFAULT_MINUTES`, `DRAIN_MAX_HOLD_MINUTES`.
- **Reload metrics** (§22.2): heartbeat `metrics.draining_workers` / `sock_tcp` / `sock_tw` are stored
  (they were dropped before), heartbeat `reloads` stored and shown; `/metrics` gains
  `pcdn_edge_reloads_1h{edge}`, `pcdn_edge_draining_workers{edge}`, `pcdn_edges_draining`,
  `pcdn_edges_tunnel_degraded`; alerts `edge_reload_storm`, `edge_draining_pileup`.
- **Synthetic tunnel probe** (§22.3): heartbeat `tunnel_probe` with fail/ok hysteresis
  (`TUNNEL_PROBE_FAIL_CHECKS`, `TUNNEL_PROBE_OK_CHECKS`, ≥ 10 min), tunnel-degraded edges leave tunnel
  sites' answers within `TUNNEL_DEGRADED_MAX_FRACTION` per pool (fail-open), alert
  `edge_tunnel_degraded`, `overview.tunnel_degraded`, optional `TUNNEL_PROBE_ORIGIN` (`node.probe`).
- **Multiple origins per tunnel path** (§22.4): `origins` (2..10) with `balance` failover / round_robin /
  sticky_ip and `health` tcp / http; plan feature `max_tunnel_origins` (default 1); downgrade truncation and
  the compatibility `origin` for older agents; pools `health.type`.
- **Timeouts and client guide** (§22.5 / §22.11): per-path `idle_timeout`; `GET …/tunnel/profile` (admin
  and `/capi/v1`, scope stats) with the edge timer contract and recommended keepalive / mux / xmux / gRPC
  values.
- **Kernel tuning report** (§22.6): heartbeat `tuning` stored; info alert `edge_tuning`.
- **Upstream reuse** (§22.7): usage `reused_n`; `/tunnel/quality` paths gain `reuse_pct`.
- **Faster TLS** (§22.8): shared TLS session ticket keys (`TLS_TICKETS`, `TLS_TICKET_ROTATE_HOURS`;
  encrypted at rest, leader rotation, never logged or returned), optional RSA-2048 certificate
  (`ACME_DUAL_RSA`), `ssl.ocsp` only for certificates with an OCSP responder; site `ssl_key_type`,
  `ssl_dual_rsa`.
- **HTTP/3 per node** (§22.9): `PATCH /api/v1/edges/{id}` `http3_enabled`, `node.http3`, HTTP/3
  availability in the tunnel profile.
- **Capacity-weighted DNS** (§22.10): `DNS_WEIGHTS=capacity` (default `off` = byte-identical zones),
  quantised weights with a load-level hysteresis, `pickwrandom` / `pickwhashed`.
- **"Why did my connection drop?"** (§22.12): usage `ends` per path, `GET …/tunnel/drops` (admin and
  `/capi/v1`) with reasons, rejected attempts, hourly series and node maintenance times without node
  identity.

## [2.0.0] - Unreleased

First production release of the v2 platform: everything built in waves 1–10 on top of the original
self-hosted CDN + WHMCS provisioning module (1.x). Contract details per feature are in
[docs/SPEC.md](docs/SPEC.md) (section numbers below); operator steps are in
[docs/UPGRADE.md](docs/UPGRADE.md). Database migrations run up to `0020`.

### Added

- **v2 CDN core** (SPEC §1–§6): per-site configuration sections (cache, SSL, WAF, DDoS, page rules,
  firewall, rate limits, load balancer pools, image optimisation, DNSSEC), records extensions,
  analytics and security events, edge ↔ controller sync protocol, platform-wide WHMCS admin panel.
  GeoDNS on PowerDNS (geoip backend, DB-IP country database, ns2 deploy kit).
- **Tunnel mode / VPN-over-CDN** (§7): WebSocket, HTTPUpgrade, gRPC, XHTTP and raw HTTP/2 paths,
  included in every CDN plan; customer setup guides with QR codes.
- **Wave 1 – reliability** (§8): synthetic edge probes, public status page (`/status.json`) and
  operator incidents.
- **Wave 2** (§9): platform analytics and prefix / purge-everything cache purge.
- **Wave 3 – customer API & billing** (§10): per-service API keys with scopes (purge, stats, dns,
  config, functions), usage forecast and upgrade suggestions, live usage, reseller panel with wholesale
  roll-up, clearer traffic invoices, prepaid wallet billing and overage invoices.
- **Wave 4 – operations** (§11): one-command node install and `--upgrade`, batch node add, centralised
  node logs, update-available badge, node runbook.
- **Multi-address edges** (§12): additional IPv4/IPv6 addresses per node with health-based DNS
  failover.
- **Wave 5 – observability** (§13): Prometheus `/metrics` (platform aggregates only), audit log,
  `backup-verify`, deep health `/healthz/deep`, WHMCS «حسابرسی» and «سلامت سامانه» pages, architecture,
  security and disaster-recovery docs.
- **Wave 6 – performance, rules, analytics** (§14): HTTP/3 opt-in, origin shield, cache variants and
  preload; redirects, transform rules, WAF packs, bot management, origin mTLS; live analytics, log
  export, webhooks, SLA report, OpenAPI for the customer API, Terraform provider `pcdn`, WHMCS 8 team
  (read-only) access.
- **Wave 7 – tunnel quality** (§15): per-path tunnel telemetry, fair-share admission, speed test,
  config checker, origin-down e-mails, add-on traffic packs, capacity alerts.
- **Wave 8 – production readiness & new products** (§16): `pcdn-loadtest` kit and capacity runbook,
  `pcdn` CLI with signed releases, L4 TCP/UDP proxy, video delivery, images v2 (AVIF, smart crop),
  weighted / health-checked DNS records and secondary DNS, object storage on MinIO, sandboxed Edge
  Functions (`pcdn-fn`), full English (LTR) client app.
- **Wave 9 – staging, ops & growth**: one-command staging stack with end-to-end tests and CI job,
  Prometheus / Grafana / Alertmanager kit, separate status-page mirror, documentation site
  (`mkdocs build --strict`), monthly DR drill and upgrade-path tests from old revisions, free trial,
  onboarding guide, scheduled e-mail reports, reseller white-label / bulk / export.
- **WAF learning mode** (§17): log-only observation, proposed exclusions / rate limits / pack-off,
  applied only on the customer's request.
- **Wave 10** (§18): waiting room, access (OTP e-mail / IP login for protected paths), monthly
  statements (PDF / CSV / JSON) and audit export, opt-in error tracking (Sentry, scrubbed), public
  pricing page and referral programme in WHMCS, production rollout tooling
  (`tools/preflight/preflight.py`, [docs/ROLLOUT.md](docs/ROLLOUT.md), this changelog).

### Changed

- CDN and tunnel are one product: tunnel is included in every CDN plan (no separate purchase).
- WHMCS client panel redesigned; adopts the host WHMCS theme (dark/light, brand colour, font).
- Edge agent split into the `pcdn_agent` package; nginx reloads are coalesced, diffed and verified;
  usage reports are idempotent.
- Iranian visitors are routed reliably to home edges (resolver-without-ECS handling,
  `GEO_NO_ECS_COUNTRIES`).
- The node install one-liner takes the token from the environment (`PCDN_EDGE_TOKEN`), not argv.

### Security

- Site ownership (`client_id`) enforced by the controller: no parent/child sites across owners, no
  public-suffix sites, `POST /api/v1/domain-check` used by the WHMCS cart; ownership sync for existing
  services.
- Customer-supplied regexes are validated for safety on controller and edge; origin address guard
  blocks private / loopback origins.
- Secrets encrypted at rest (`DATA_ENCRYPTION_KEY`), shown once, never logged; PowerDNS API restricted
  to the controller (ns2 firewall, `DOCKER-USER` rules); edge network guard and sandboxed functions.
- Secondary DNS is a plan feature (off by default); suspended services are read-only for API keys.
- Controller review findings C1, H1, H2, M1–M3, M5 and lows fixed (commit `46a7800`).

### Fixed

- Tunnel stability: audit findings F1–F40 / N2 / N4 across controller and edge (keep-alives, buffers,
  upstream pools, reload races).
- `install.sh` restarts `pcdn-agent` on upgrade; Pillow "Unknown feature 'avif'" warning silenced on
  Pillow < 11.2; flaky edge and load-test tests hardened.

[Unreleased]: https://github.com/namesissr/whmcs-cdn/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/namesissr/whmcs-cdn/releases/tag/v2.0.0
