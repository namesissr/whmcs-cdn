import os
from dataclasses import dataclass, field


def _bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


def _list(name: str, default: str) -> list[str]:
    return [x.strip().lower().rstrip(".") for x in os.getenv(name, default).split(",") if x.strip()]


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


settings = Settings()
