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

    # GeoIP: requires the PowerDNS geoip backend + MaxMind DB (see README).
    geoip_enabled: bool = field(default_factory=lambda: _bool("GEOIP_ENABLED", False))
    geo_home_country: str = field(default_factory=lambda: os.getenv("GEO_HOME_COUNTRY", "IR"))
    lua_selector: str = field(default_factory=lambda: os.getenv("LUA_SELECTOR", "random"))
    health_url: str = field(default_factory=lambda: os.getenv("EDGE_HEALTH_URL", "http://health.pcdn/__pcdn/health"))

    acme_email: str = field(default_factory=lambda: os.getenv("ACME_EMAIL", ""))
    acme_server: str = field(default_factory=lambda: os.getenv("ACME_SERVER", "letsencrypt"))
    acme_home: str = field(default_factory=lambda: os.getenv("ACME_HOME", "/data/acme"))
    acme_sh: str = field(default_factory=lambda: os.getenv("ACME_SH", "/root/.acme.sh/acme.sh"))

    edge_offline_seconds: int = field(default_factory=lambda: int(os.getenv("EDGE_OFFLINE_SECONDS", "180")))
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
