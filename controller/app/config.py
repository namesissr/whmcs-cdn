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


@dataclass
class Settings:
    database_url: str = field(default_factory=lambda: os.getenv("DATABASE_URL", "sqlite:///./cdn.db"))
    admin_api_key: str = field(default_factory=lambda: os.getenv("ADMIN_API_KEY", ""))

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


settings = Settings()
