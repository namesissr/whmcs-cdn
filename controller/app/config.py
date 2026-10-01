import os
from dataclasses import dataclass, field


def _bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


def _list(name: str, default: str) -> list[str]:
    return [x.strip().lower().rstrip(".") for x in os.getenv(name, default).split(",") if x.strip()]


def _raw_list(name: str) -> list[str]:
    return [x.strip() for x in os.getenv(name, "").split(",") if x.strip()]


def _default_edge_dir() -> str:
    """The repo's edge/ tree resolved relative to this package: <repo>/edge (controller/app -> ../../edge)."""
    return os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "edge"))


@dataclass
class Settings:
    database_url: str = field(default_factory=lambda: os.getenv("DATABASE_URL", "sqlite:///./cdn.db"))
    admin_api_key: str = field(default_factory=lambda: os.getenv("ADMIN_API_KEY", ""))
    # Public hostname of the controller API (as in .env.example, CONTROLLER_DOMAIN). Used to build
    # the one-command edge install one-liner (SPEC §11.1); no scheme, https:// is prepended.
    controller_domain: str = field(default_factory=lambda: os.getenv("CONTROLLER_DOMAIN", "").strip().rstrip("/"))
    # directory the controller serves the (secret-free) edge bundle from (SPEC §11.1); default the
    # repo's edge/ tree resolved relative to this package (<repo>/edge). In the container the image
    # bakes edge/ there (set EDGE_BUNDLE_DIR to the baked path). Missing -> bundle routes return 404.
    edge_bundle_dir: str = field(
        default_factory=lambda: os.getenv("EDGE_BUNDLE_DIR", "").strip() or _default_edge_dir())

    # comma separated: every zone is written to all of them (ns1, ns2, ...)
    pdns_api_url: str = field(default_factory=lambda: os.getenv("PDNS_API_URL", "http://pdns:8081"))
    pdns_api_key: str = field(default_factory=lambda: os.getenv("PDNS_API_KEY", ""))
    pdns_server_id: str = field(default_factory=lambda: os.getenv("PDNS_SERVER_ID", "localhost"))

    nameservers: list[str] = field(
        default_factory=lambda: _list("NAMESERVERS", "ns1.pasargadmizban.com,ns2.pasargadmizban.com")
    )
    soa_email: str = field(default_factory=lambda: os.getenv("SOA_EMAIL", "hostmaster.pasargadmizban.com"))
    default_ttl: int = field(default_factory=lambda: int(os.getenv("DEFAULT_TTL", "300")))
    proxied_ttl: int = field(default_factory=lambda: int(os.getenv("PROXIED_TTL", "60")))

    # GeoIP: requires the PowerDNS geoip backend + country DB on EVERY nameserver (see README).
    geoip_enabled: bool = field(default_factory=lambda: _bool("GEOIP_ENABLED", False))
    # comma separated ISO codes served by "home" edges
    geo_home_countries: list[str] = field(
        default_factory=lambda: [c.upper() for c in _raw_list("GEO_HOME_COUNTRY") or ["IR"]])
    # Resolvers that never send the visitor's subnet (EDNS Client Subnet), so their own
    # (foreign) location would decide: Cloudflare 1.1.1.1 by default. home | global | geo
    geo_no_ecs_pool: str = field(default_factory=lambda: (os.getenv("GEO_NO_ECS_POOL") or "home").strip().lower())
    geo_no_ecs_resolvers: list[str] = field(default_factory=lambda: _raw_list("GEO_NO_ECS_RESOLVERS") or [
        # Cloudflare (1.1.1.1 / 1.0.0.1 egress) - https://www.cloudflare.com/ips/
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
        "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
        "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
        "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
        "2a06:98c0::/29", "2c0f:f248::/32",
        # Quad9 (9.9.9.9 / 149.112.112.112; egress from WoodyNet/PCH, AS42), no ECS by default.
        # Seen in production: an Iranian ISP's queries left through Quad9 in Bulgaria/Germany.
        "74.63.16.0/20", "74.80.64.0/18", "9.9.9.0/24", "149.112.112.0/24", "149.112.149.0/24",
        "2620:fe::/48", "2620:171::/32",
    ])
    # optional: apply GEO_NO_ECS_POOL only when such a resolver answers from one of these countries
    # (where Iranian traffic lands, e.g. DE,BG,TR); its users in other countries follow their location
    geo_no_ecs_countries: list[str] = field(
        default_factory=lambda: [c.upper() for c in _raw_list("GEO_NO_ECS_COUNTRIES")])
    # visitors whose country is unknown to the database: home | global
    geo_unknown_pool: str = field(default_factory=lambda: (os.getenv("GEO_UNKNOWN_POOL") or "home").strip().lower())
    # log every GeoDNS decision in the PowerDNS log ("pcdn-geo ..."): for diagnosing a location
    geo_log: bool = field(default_factory=lambda: _bool("GEO_LOG", False))
    # periodic check that every nameserver geolocates a home and a foreign subnet correctly
    geo_check_enabled: bool = field(default_factory=lambda: _bool("GEO_CHECK", True))
    geo_check_home_subnet: str = field(default_factory=lambda: os.getenv("GEO_CHECK_HOME_SUBNET") or "2.176.0.0/24")
    geo_check_foreign_subnet: str = field(
        default_factory=lambda: os.getenv("GEO_CHECK_FOREIGN_SUBNET") or "8.8.8.0/24")
    # DNS addresses of the nameservers for that check; default: the hosts in PDNS_API_URL, port 53
    pdns_dns_addrs: list[str] = field(default_factory=lambda: _raw_list("PDNS_DNS_ADDRS"))
    # Which edge answers inside the chosen pool. Moving a visitor between the home and
    # global pools only follows the controller's view of the edges (agent heartbeats), so
    # ns1 and ns2 always agree; EDGE_PROBE adds PowerDNS's own checks inside the pool.
    lua_selector: str = field(default_factory=lambda: os.getenv("LUA_SELECTOR", "random"))
    # selector for tunnel sites (F33): tunnel clients need MORE than one edge address so a Go/
    # Xray/sing-box dialer can fail over immediately and keep TLS resumption. "all" answers with
    # every healthy edge of the pool; general (non-tunnel) sites keep LUA_SELECTOR.
    tunnel_lua_selector: str = field(default_factory=lambda: os.getenv("TUNNEL_LUA_SELECTOR", "all"))
    edge_probe: bool = field(default_factory=lambda: _bool("EDGE_PROBE", True))
    health_url: str = field(default_factory=lambda: os.getenv("EDGE_HEALTH_URL", "http://health.pcdn/__pcdn/health"))

    acme_email: str = field(default_factory=lambda: os.getenv("ACME_EMAIL", ""))
    acme_server: str = field(default_factory=lambda: os.getenv("ACME_SERVER", "letsencrypt"))
    acme_home: str = field(default_factory=lambda: os.getenv("ACME_HOME", "/data/acme"))
    acme_sh: str = field(default_factory=lambda: os.getenv("ACME_SH", "/root/.acme.sh/acme.sh"))

    edge_offline_seconds: int = field(default_factory=lambda: int(os.getenv("EDGE_OFFLINE_SECONDS", "180")))
    # an edge silent this long raises the offline *alert* (the node is still in DNS until
    # EDGE_OFFLINE_SECONDS); keep it >= one heartbeat interval to avoid flapping
    edge_alert_seconds: int = field(default_factory=lambda: int(os.getenv("EDGE_ALERT_SECONDS", "90")))
    # CPU: warn when load1/cpus stays above this for LOAD_ALERT_CHECKS heartbeats
    edge_cpu_alert: float = field(default_factory=lambda: float(os.getenv("EDGE_CPU_ALERT") or 4))
    # warn when a node reports disk/memory usage above these percentages (needs a recent agent)
    edge_disk_alert: float = field(default_factory=lambda: float(os.getenv("EDGE_DISK_ALERT") or 90))
    edge_mem_alert: float = field(default_factory=lambda: float(os.getenv("EDGE_MEM_ALERT") or 95))
    # load shedding (SPEC §7.4): an edge using this % of its capacity_mbps leaves DNS answers
    # (while another edge of its pool stays) and comes back below this value - 15
    edge_shed_percent: float = field(default_factory=lambda: float(os.getenv("EDGE_SHED_PERCENT") or 90))
    # load shedding hysteresis (F25): shed only after this many consecutive reports at/above
    # EDGE_SHED_PERCENT, and keep an edge shed for at least EDGE_SHED_HOLD seconds, so a single
    # 60s sample cannot herd a whole region onto one edge
    edge_shed_checks: int = field(default_factory=lambda: max(1, int(os.getenv("EDGE_SHED_CHECKS") or 3)))
    edge_shed_hold: int = field(default_factory=lambda: int(os.getenv("EDGE_SHED_HOLD") or 300))
    # optional second shed signal (F25): load1/cpus at/above this for EDGE_SHED_CHECKS reports also
    # sheds; 0 disables the CPU signal (bandwidth stays the only trigger)
    edge_cpu_shed: float = field(default_factory=lambda: float(os.getenv("EDGE_CPU_SHED") or 0))
    # control-plane outage guard (F10): if the online (heartbeating) edge set shrinks by more than
    # this fraction in one scheduler tick, keep publishing the last-known DNS and alert instead of
    # emptying/shrinking the pool — a bulk "went silent" is treated as a controller-path outage, not
    # as many simultaneous node deaths. Only active when EDGE_PROBE is on (PowerDNS ifurlup still
    # removes genuinely-dead edges within ~5s). 0 disables the guard.
    edge_silent_guard_fraction: float = field(
        default_factory=lambda: float(os.getenv("EDGE_SILENT_GUARD_FRACTION") or 0.5))
    # synthetic edge probes (SPEC §8.1): the controller fetches /__pcdn/health from each edge
    probe_enabled: bool = field(default_factory=lambda: _bool("PROBE_ENABLED", True))
    probe_timeout: float = field(default_factory=lambda: float(os.getenv("PROBE_TIMEOUT") or 5))
    probe_ipv6: bool = field(default_factory=lambda: _bool("PROBE_IPV6", True))
    # consecutive probe failures before the edge_probe alert opens (edge still heartbeating)
    probe_fail_checks: int = field(default_factory=lambda: int(os.getenv("PROBE_FAIL_CHECKS") or 3))
    # probe-based DNS withdrawal budget (F26): on probe evidence alone, withdraw at most this
    # fraction of a group+region+family pool's addresses; beyond that keep the rest advertised and
    # alert (a wide "probe says down" is more likely a bad vantage point than real mass death)
    probe_withdraw_max_fraction: float = field(
        default_factory=lambda: float(os.getenv("PROBE_WITHDRAW_MAX_FRACTION") or 0.34))
    ns_check_interval: int = field(default_factory=lambda: int(os.getenv("NS_CHECK_INTERVAL", "600")))
    ns_resolvers: list[str] = field(default_factory=lambda: _list("NS_RESOLVERS", "8.8.8.8,1.1.1.1"))
    scheduler_enabled: bool = field(default_factory=lambda: _bool("SCHEDULER_ENABLED", True))
    scheduler_interval: int = field(default_factory=lambda: int(os.getenv("SCHEDULER_INTERVAL", "60")))
    pdns_enabled: bool = field(default_factory=lambda: _bool("PDNS_ENABLED", True))

    # ---- operations (docs/OPERATIONS.md) ---------------------------------
    # comma separated Fernet keys; the first one encrypts, all of them decrypt (rotation)
    data_encryption_key: str = field(default_factory=lambda: os.getenv("DATA_ENCRYPTION_KEY", ""))

    # alerts: Telegram and/or e-mail, both optional
    telegram_bot_token: str = field(default_factory=lambda: os.getenv("TELEGRAM_BOT_TOKEN", ""))
    telegram_chat_ids: list[str] = field(default_factory=lambda: _raw_list("TELEGRAM_CHAT_IDS"))
    telegram_api_url: str = field(
        default_factory=lambda: (os.getenv("TELEGRAM_API_URL") or "https://api.telegram.org").rstrip("/"))
    smtp_host: str = field(default_factory=lambda: os.getenv("SMTP_HOST", ""))
    smtp_port: int = field(default_factory=lambda: int(os.getenv("SMTP_PORT", "0") or 0))
    smtp_user: str = field(default_factory=lambda: os.getenv("SMTP_USER", ""))
    smtp_password: str = field(default_factory=lambda: os.getenv("SMTP_PASSWORD", ""))
    smtp_from: str = field(default_factory=lambda: os.getenv("SMTP_FROM", ""))
    # starttls | ssl | none
    smtp_security: str = field(default_factory=lambda: (os.getenv("SMTP_SECURITY") or "starttls").strip().lower())
    alert_emails: list[str] = field(default_factory=lambda: _raw_list("ALERT_EMAILS"))
    alert_reminder_hours: float = field(default_factory=lambda: float(os.getenv("ALERT_REMINDER_HOURS") or 6))
    alert_timeout: float = field(default_factory=lambda: min(float(os.getenv("ALERT_TIMEOUT") or 10), 10.0))
    alert_cert_days: int = field(default_factory=lambda: int(os.getenv("ALERT_CERT_DAYS") or 7))
    alert_subject_prefix: str = field(default_factory=lambda: os.getenv("ALERT_SUBJECT_PREFIX") or "[Pasargad CDN]")

    # backups
    backup_enabled: bool = field(default_factory=lambda: _bool("BACKUP_ENABLED", False))
    backup_hour: int = field(default_factory=lambda: int(os.getenv("BACKUP_HOUR") or 2))
    backup_keep: int = field(default_factory=lambda: int(os.getenv("BACKUP_KEEP") or 14))
    backup_dir: str = field(default_factory=lambda: os.getenv("BACKUP_DIR") or "/data/backups")
    backup_passphrase: str = field(default_factory=lambda: os.getenv("BACKUP_PASSPHRASE", ""))
    backup_pdns_db: str = field(default_factory=lambda: os.getenv("BACKUP_PDNS_DB", "/pdns-data/pdns.sqlite3"))
    backup_s3_endpoint: str = field(default_factory=lambda: os.getenv("BACKUP_S3_ENDPOINT", "").rstrip("/"))
    backup_s3_bucket: str = field(default_factory=lambda: os.getenv("BACKUP_S3_BUCKET", ""))
    backup_s3_access_key: str = field(default_factory=lambda: os.getenv("BACKUP_S3_ACCESS_KEY", ""))
    backup_s3_secret_key: str = field(default_factory=lambda: os.getenv("BACKUP_S3_SECRET_KEY", ""))
    backup_s3_region: str = field(default_factory=lambda: os.getenv("BACKUP_S3_REGION") or "us-east-1")
    backup_s3_prefix: str = field(default_factory=lambda: os.getenv("BACKUP_S3_PREFIX", "pcdn-backups/"))
    backup_s3_keep: int = field(default_factory=lambda: int(os.getenv("BACKUP_S3_KEEP", "0") or 0))  # 0 = BACKUP_KEEP

    # high availability
    instance_name: str = field(default_factory=lambda: os.getenv("INSTANCE_NAME", ""))

    # observability (SPEC §13): optional bearer token guarding GET /metrics (empty = open, for an
    # internal scrape network). The audit log is pruned after this many days.
    metrics_token: str = field(default_factory=lambda: os.getenv("METRICS_TOKEN", ""))
    audit_retention_days: int = field(default_factory=lambda: int(os.getenv("AUDIT_RETENTION_DAYS") or 90))

    # customer API (SPEC §10.1): per-key requests allowed per minute (in-process sliding window)
    capi_rate: int = field(default_factory=lambda: int(os.getenv("CAPI_RATE", "60")))
    # a tighter per-key limit for config/record *writes* only (F5): a burst of these bumps the edge
    # config version and, without coalescing on the edge, can herd fleet-wide reloads. Reads, purges
    # and stats stay governed by CAPI_RATE. Applied in addition to CAPI_RATE.
    capi_config_rate: int = field(default_factory=lambda: int(os.getenv("CAPI_CONFIG_RATE", "6")))

    # bot management (SPEC §14.2): the scheduler leader fetches Google's and Bing's published crawler
    # IP ranges daily (outbound through HTTPS_PROXY / ALL_PROXY like the alerts) for the edges'
    # verified-bot check; a warning alert opens when they could not be refreshed for N days (0 = never)
    bot_ranges_enabled: bool = field(default_factory=lambda: _bool("BOT_RANGES_ENABLED", True))
    bot_ranges_stale_days: int = field(default_factory=lambda: int(os.getenv("BOT_RANGES_STALE_DAYS") or 3))

    # analytics & platform (SPEC §14.3): per-site hourly cap on access-log records spooled for the
    # customer's log export (excess is counted as dropped), and the number of security events per
    # 5 minutes above which a site's `attack.detected` webhook fires (at most once per hour per site)
    log_export_max_per_hour: int = field(
        default_factory=lambda: max(0, int(os.getenv("LOG_EXPORT_MAX_PER_HOUR") or 500000)))
    attack_events_per_5m: int = field(
        default_factory=lambda: max(1, int(os.getenv("ATTACK_EVENTS_PER_5M") or 1000)))


settings = Settings()
