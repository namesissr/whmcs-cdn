# Changelog

All notable changes to Pasargad CDN (controller, edge, WHMCS modules, CLI, Terraform provider, deploy
kit and docs) are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The platform version (`vX.Y.Z` tag on `main`) covers the controller, edge bundle, WHMCS modules and
deploy kit, which are released together. The `pcdn` CLI (`cli/vX.Y.Z`) and the Terraform provider
(`provider/vX.Y.Z`) keep their own tags and release notes (`.github/workflows/release.yml`). The release
process is described in [docs/ROLLOUT.md](docs/ROLLOUT.md).

## [Unreleased]

### Added — wave 14: release safety, operations and customer experience (SPEC §23), controller

Migration `0023` (`edges.display_city|display_city_en|release|upgrade_state`, `sites.abuse_suspended`, tables
`site_config_versions`/`site_config_values`, `backup_runs`, `pcdn_live_marker`, `notification_subscriptions`/
`_targets`/`_link_codes`/`_outbox`, `import_sessions`, `rum_hourly`, `abuse_reports`/`abuse_events`,
`slo_buckets`, `rollouts`/`rollout_edges`, `edge_join_tokens`, `provision_proposals`). Every new switch defaults
to today's behaviour; node selection stays health / load / capacity driven (RUM / ISP data is never read by
DNS, rollouts or provisioning — enforced by an import test).

- **Versions and pinned edge releases** (§23.1): `PCDN_VERSION` / `VERSION` file in `/healthz`,
  `/healthz/deep` (`version`, `environment` from `PCDN_ENVIRONMENT`) and `pcdn_build_info`; `EDGE_RELEASES_DIR`
  + `EDGE_RELEASE`: `GET /edge/releases`, `GET /edge/releases/vX.Y.Z.sha256`, `bundle.tar.gz?version=&group=`
  (streamed), `/edge/version` `release`; group pins advanced by completed rollouts; install one-liner
  `--version`; edge dict `release`, `pinned_release`, `release_ok`, `upgrade`.
- **Staged rollouts with automatic rollback** (§23.2): `GET /api/v1/releases`, `/api/v1/rollouts` (dry run,
  rings: canary / ring % / rest, `manual` edges, `no_rollback_release`), start / pause / resume / abort /
  rollback, per-edge skip / force / retry; `job_rollout` with per-pool parallelism, last-edge block, health gate
  (heartbeat, config applied, probe, tunnel probe, platform error % vs baseline), auto rollback; `node.upgrade`
  (non-rendered); alerts `rollout_blocked`, `rollout_failed`; metrics `pcdn_rollout_state`, `pcdn_rollout_edges`.
  Env `ROLLOUT_*`.
- **Off-site backups and weekly restore test** (§23.3): `BACKUP_ENCRYPTION_KEY` (alias, conflict and
  equal-to-data-key refusal), `BACKUP_REQUIRE_ENCRYPTION`, S3 `HEAD` + `x-amz-meta-sha256` read-back,
  `BACKUP_S3_KEEP_DAYS`, manifest `counts` / `app_version` / member sha256, `job_backup_verify`
  (`BACKUP_VERIFY_*`, full SQLite / PostgreSQL scratch restore with live-marker guard, partial level), run
  history, `GET /api/v1/backups`, `POST /api/v1/backups/run|verify`, `backup.scrub()`; alerts
  `backup_not_offsite`, `backup_unencrypted_offsite`, `backup_verify_failed`, `backup_verify_partial`.
- **Config history** (§23.4): automatic versions of every section write (before_flush capture, actor from
  `X-PCDN-Actor` / capi key / scheduler job), redacted diffs, restore under the current plan (feature drops,
  list truncation, logs / webhook secret rules, 10/hour), admin + capi endpoints, retention
  `CONFIG_HISTORY_*`.
- **Customer alert channels** (§23.5): subscriptions per WHMCS account, SMS (Kavenegar / SMS.ir / Melipayamak),
  Bale and Telegram customer bots (link codes, `/stop`), e-mail outbox for the WHMCS cron, dedup, rate limits
  with digests, Tehran quiet hours, retries and permanent-failure disabling, encrypted targets; new events
  `origin.down` / `origin.up` (from live `oe`), `ssl.expiring`, `incident.opened` / `incident.resolved`;
  plan features `alert_sms`, `alert_messengers`, `max_alert_subscriptions`.
- **Migration from ArvanCloud and Cloudflare** (§23.6): import preview / apply / delete (admin + capi), the
  provider key used only inside the request (never stored, logged or echoed), encrypted short-lived sessions,
  fixture-tested mappers for DNS, caching, HTTPS, firewall, page rules, DDoS and rate limits.
- **RUM** (§23.7): section `rum` (plan feature `rum`), usage `rum` histograms merged into `rum_hourly`, p75 /
  good / poor / breakdowns by country / ISP / region / device / path, CDN impact, `GET …/rum` (+ capi).
- **Diagnostics report** (§23.8): `GET …/diagnostics` (+ capi) with secrets, origins, tunnel paths, node names
  and addresses redacted; admin audience `internal` block.
- **Provisioning and join tokens** (§23.9): capacity-sized proposals, two approvals, provisioner API (bearer
  `PROVISIONER_TOKEN`), one-time join tokens (`POST /edge/v1/join`, `POST /api/v1/edges/{id}/join-token`).
- **Abuse desk** (§23.10): public intake with proof of work (`ABUSE_ENABLED`), admin queue, owner notice via
  the e-mail outbox, abuse suspension independent of billing (`abuse_suspended`), overdue alerts, retention.
- **SLO dashboard** (§23.11): availability / latency / error SLIs per edge group, `GET /api/v1/slo`, burn-rate
  alerts and `pcdn_slo_*` metrics (`SLO_*`).
- **Customer-visible node naming** (§23.12): `display_city` labels («نود تهران ۱» / "Tehran node 1"), keyed
  public tag (`node.public_tag`, `GET /api/v1/edges?tag=`), tunnel quality shows labels instead of internal
  names; `edge_ips` sorted and unlabeled.

### Added — wave 14, edge

- Self-upgrade from `node.upgrade` (systemd-run, sha256-verified bundle, rollback cache of the last 3 releases);
  `bootstrap.sh --version` pinned install with sha256 check, following the group pin of `/edge/releases`;
  one-time join tokens (`--join-token-file` / `PCDN_JOIN_TOKEN`); `/etc/pcdn/release`.
- `X-Served-By` now carries the node's public tag instead of the host name.
- RUM beacon (`/__pcdn/rum.js`, `/__pcdn/rum`), auto / manual injection, privacy-preserving ingestion (no IP),
  aggregated into usage; live `oe` / `pe` error counters; `pcdn-geoip-update --asn`.

### Added — wave 14, release and ops tooling

- `VERSION` file and `tools/release/*` (prepare.sh, changelog-section.sh, build-edge-bundle.sh,
  fetch-edge-release.sh, staging-verify.sh, security-check.sh, check-meta.sh);
  `.github/workflows/release-platform.yml` (on a `vX.Y.Z` tag: CI again, deterministic
  `pcdn-edge-vX.Y.Z.tar.gz` + `.sha256`, a DRAFT GitHub release — merge / tag / publish stay owner decisions);
  CI jobs `release-meta`, provisioning, status page.
- `terraform/` (module `pcdn-edge-node`, `providers/hcloud` example, `providers/fake`) and
  `tools/provision/pcdn-provision` (approved jobs only, one-time join tokens, masked tokens, never destroys).
- CLI `pcdn config history|diff|restore`; `status/abuse.html` public abuse report page with in-browser proof
  of work; Prometheus SLO burn-rate rules `pcdn-slo.yml` + promtool tests + Grafana dashboard `pcdn-slo`;
  loadtest `--max-error-pct` / `--max-p99-ms` (exit 3); preflight `backup verify age`; staging stack sets
  `PCDN_ENVIRONMENT=staging` and `PCDN_VERSION`; docs `RELEASE.md` (new), ROLLOUT / LOADTEST / STAGING /
  TERRAFORM / CLI updated.

### Added — wave 14, WHMCS
- Settings history page with version diff and restore (shared domains: editor role only).
- Customer alerts page (e-mail / SMS / Bale / Telegram channels, subscriptions, quiet hours) and an
  AlertMail cron that delivers the controller's e-mail outbox.
- ArvanCloud / Cloudflare import wizard with a dry-run mapping report (the API key is only passed through).
- RUM page with charts and settings (auto/manual injection, SPA).
- Diagnostics report the customer reviews before it opens a support ticket.
- Tunnel quality table shows city labels («نود تهران») instead of node names; owner edits made in the
  panel appear as «شما» in the change log.
- Addon 1.7.0: «عملیات» tab (releases/rollouts with pause/resume/abort/rollback, backups, abuse desk,
  SLO, provisioning approve/reject), public abuse report page, node version and display-city columns,
  plan feature labels / pricing rows for rum, alert_sms, alert_messengers, max_alert_subscriptions,
  fa/en alert e-mail templates, settings alert_email / support_department / abuse_page.
- Repo-local customer-text test (`node --test whmcs/tests/*.test.js`).

### Changed — wave 14

- Docs: API, OPERATIONS (§۱۰), MONITORING, SECURITY (§۱۲), UPGRADE («۱۲) موج ۱۴ — انتشار ایمن، عملیات و
  تجربهٔ مشتری»), DISASTER_RECOVERY (weekly restore test), NODES (§۱۴); `.env.example` wave 14 block.

### Changed — object storage moved from MinIO to SeaweedFS

MinIO's community edition was archived (2026-02-13) and its images were removed from Docker Hub
(2026-09-11), with anonymous pulls from quay.io closed days later, so `deploy/storage` could no longer
start at all.

- Controller: new `app/seaweed_client.py` behind the same client interface — bucket quota via the
  `PUT /{bucket}?seaweedfs-quota` extension, a customer's access key via the IAM API on the S3 port
  (CreateUser + PutUserPolicy + CreateAccessKey with the key pair we generate; the server keeps it in
  the filer, so it survives restarts), usage from the gateway's per-bucket Prometheus gauges. The two
  multipart action names SeaweedFS spells differently are translated. `STORAGE_BACKEND`
  (`seaweedfs`|`minio`, default `minio` so an existing install is not switched by an upgrade) and
  `STORAGE_METRICS_PATH` are new; `app/minio_client.py` is unchanged apart from a `service` argument
  on its signer and error parsing that now also reads the IAM API's nested `<Error><Code>`.
- `deploy/storage/`: SeaweedFS compose (one container: master + volume + filer + S3 gateway), Caddy
  with the metrics path and the IAM POST limited to the controller's addresses, and a `bootstrap.sh`
  that writes the operator admin identity plus the scoped `pcdn-controller` identity and prints the
  controller's credentials once. `-volume.max=0` with a 1 GiB volume size, because every bucket is
  its own collection and the default of 8 volumes caps the server at a handful of buckets. The MinIO
  kit moved to `deploy/storage/minio/` for servers that still run it.
- Staging: the `storage` profile runs SeaweedFS with the same identities (`deploy/staging/seaweed-s3.json`).
- Tests: `controller/tests/test_storage_seaweed.py` — the quota / IAM / usage calls and the backend
  switch against a fake server, plus `test_real_seaweed`, which starts a real `weed` binary with the
  identities `bootstrap.sh` writes (skipped without one: `PCDN_TEST_WEED_BIN` or `weed` on PATH) and
  runs the whole bucket flow, including that the customer key reaches nothing but its own bucket and
  that the edges' Referer-conditioned anonymous GET works while listing stays denied.
- Docs: STORAGE.md rewritten (setup, policy, backup, upgrade, troubleshooting, and §11 on the MinIO
  path and how to migrate off it), SPEC §16.8, UPGRADE, `.env.example`.

### Added — the storage server's capacity in the admin dashboard

A card «فضای ذخیره‌سازی (سرور S3)» showing three numbers that differ on purpose: the server's own
disk (total / used / free, with a bar), the customers' data (buckets and files), and the space sold
(the sum of every plan's `storage_gb`, flagged when it exceeds the disk). From 85 % full the
dashboard's warning list says so, red from 95 %.

- Controller: `GET /api/v1/storage/capacity`, cached 30 s, refreshing the bucket usage live so the
  operator's figure and the customer's page never disagree within a minute. The disk comes from the
  data server's `/status` (`STORAGE_STATUS_PATH`, default `/__pcdn/storage-status`) because no metric
  carries the size of a disk; `SeaweedClient.disk_status()` sums the data directories and
  `MinioClient.disk_status()` reads admin/v3/storageinfo, skipping offline drives. When neither is
  reachable, `STORAGE_CAPACITY_GB` stands in for the total and the answer says `"source"`.
- `deploy/storage`: the Caddyfile proxies that path to the volume server for `ADMIN_ALLOW_IPS` only,
  exactly like the metrics path, and the compose file exposes the port to it.
- Tests: the disk report against a real `weed` binary (`test_real_seaweed_disk_status`), the panel's
  three numbers and the configured-capacity fallback against a fake server, and the MinIO drive
  parsing including an offline drive.

### Fixed — the file manager's listing came back 404

- The drawer asked for `storage/buckets/<b>/objects?prefix=…`, but `api()` sends the sub-path as one
  encoded value, so the `?` arrived inside the path and matched no route in the client proxy's
  whitelist: every listing failed with «فهرست فایل‌ها خوانده نشد». The query now goes through
  `api()`'s own parameter, and `ClientApi::QUERY_RE` whitelists `prefix` / `token` / `limit` for that
  route — without which paging and folders would have been dropped silently.
- A shared domain's roles (SPEC §20) can now use the manager the button offers them: listing and a
  download link are reads for every role, while upload, folder, rename and delete need `editor`. A
  bucket's access key still stays with the owner.
- New `whmcs/tests/routes.php` exercises `ClientApi::allowed()`, `::query()` and `::shareAllows()`
  directly (57 checks, run by the `whmcs` CI job), and `fm.test.js` now fails if any `api()` call
  glues a query string onto its path.
- Docs: STORAGE.md had the multipart `urls` shape wrong (it is a list of `{part, url}`).

### Added — a file manager in the customer's storage section

A customer who buys storage no longer needs `aws`/`rclone` to put a file there and hand out its link.

- Controller: `.../storage/buckets/{name}/objects` — list (folders + objects, paged), presigned
  download (and the permanent CDN URL when the bucket is a proxied record's origin), presigned upload,
  multipart start / parts / complete / abort, folder, rename and delete (keys or whole prefixes, 200
  per call). The bytes never pass through the controller: it issues SigV4 **query**-presigned URLs
  (`UNSIGNED-PAYLOAD`) and the browser talks to the storage server, so the first upload to a bucket
  also writes its CORS rule (`STORAGE_CORS_ORIGINS`, default `*`). `STORAGE_MAX_UPLOAD_GB` (default
  **7**) caps one file, on top of the plan's own free-space check. Keys are validated (no control
  character, no `..`, ≤ 1024 bytes) and the delete audit entry counts files instead of listing them.
- `app/minio_client.py` gained the presigner and the object calls both backends share
  (`list_objects`, `presign`, `put/delete/copy_object`, multipart, `put_bucket_cors`).
- WHMCS client app: a «فایل‌ها» button per bucket opens the manager — breadcrumb browsing, drag & drop
  or picked uploads in a queue with progress and cancel (one PUT up to 32 MiB, multipart above it with
  32 MiB parts and 3 parallel lanes, so multi-gigabyte files work), download, link dialog (permanent
  CDN link, or 1 h / 1 d / 7 d presigned), new folder, rename and delete. A customer's file name
  becomes exactly one key segment inside the folder on screen. English strings included.
- Tests: `controller/tests/test_storage_seaweed.py::test_real_seaweed_file_manager` drives the whole
  flow against a real `weed` binary; `whmcs/tests/fm.test.js` covers the key and upload-shape helpers,
  and the `whmcs` CI job now runs the JS tests and `node --check` on every asset.
- Docs: STORAGE.md (§۴ endpoints and the customer page), SPEC §16.8, `.env.example`.

### Fixed — node stability under memory pressure and a broken nginx pid file

- Edge: a reload that fails while `NGINX_PID_FILE` does not point at a live master (an empty or stale
  `/run/nginx.pid` → `invalid PID number ""`, reported without any `nginx -t` or `emerg` error while nginx
  keeps serving the old config) now rewrites that file from the running master, retries, and falls back to
  `SIGHUP`, with a WARN either way. Before, such a node silently never loaded another config change — new
  sites, rotated certificates and the tunnel self-probe's server blocks included.
- Edge: the memory guard gained a critical tier (`MEM_GUARD_HARD_PCT` 97, `MEM_GUARD_MAX_KILLS` 3,
  `MEM_GUARD_KILL_GRACE_S` 60): it acts on the first heartbeat, stops several draining generations at once,
  and escalates to `SIGKILL`; a worker already signalled is skipped. While a generation drains at that
  memory level the reload back-pressure goes to its 600 s ceiling (`RELOAD_MAX_WAIT` still forces the
  pending version). Rationale: the kernel's OOM killer picks its own victim, which can be the nginx master
  — every tunnel on the node goes with it.
- Controller: the memory part of `edge_health:<id>` gained hysteresis (`EDGE_MEM_ALERT` for 3 heartbeats,
  resolving 10 points lower) and a `critical` tier from 97 % on the first report, naming the node's draining
  generations and the remedies.
- Edge: the nginx drop-in gained `Restart=on-failure` + `RestartSec=2` (and the drop-in is now
  followed by a `systemctl daemon-reload`, which only happened in conditional blocks further down).
  The distribution's unit has no restart policy, so an OOM-killed or crashed master left the node
  answering nothing until someone noticed; a clean `systemctl stop` still stays stopped.
- Docs: NODES (§۱۳-۱-۱ node memory and worker generations, troubleshooting row for the empty pid file),
  EDGE, MONITORING, SPEC (§6, §22.2).

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
