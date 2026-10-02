"""Realistic operator data for the upgrade-path tests (tests/test_upgrade_path.py).

`seed(conn, revision, ...)` fills a database that was migrated to `revision` (one of the old
revisions an operator database can still be at, e.g. 0004, 0012, 0015) with the rows the controller
of that era wrote: sites with plan features and section configs (cache, ssl, pools, tunnel...),
proxied / pooled / health-checked DNS records, edges of both groups with heartbeat metrics and probe
state, extra edge addresses, hourly usage with the full `details` document (status, countries,
paths, security, tunnel), uptime rollups, security events, purges, incidents, customer API keys,
usage batches, audit rows, live analytics, spooled logs, webhook deliveries and encrypted secrets.

Every row is written with RAW SQL listing only the columns that exist at `revision`, so a seed
that names a column added later (or leaves out a NOT NULL column without a default) fails right
away, the way an old controller would have failed. Ids are never given explicitly: PostgreSQL
sequences must advance exactly as they did in production, so inserts after the upgrade keep
working. Natural keys (domain, edge name) are looked up instead.

`seed` returns the plaintext values (edge tokens, API keys, site secrets, private keys) and the
expected counts the tests assert against after the upgrade.
"""

import datetime as dt
import hashlib
import json

import sqlalchemy as sa
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

# test-only Fernet key (never used anywhere real): the seeded secrets are encrypted with it, the
# tests set DATA_ENCRYPTION_KEY to it before reading them back through the app
FERNET_KEY = "dGVzdC1vbmx5LXVwZ3JhZGUtcGF0aC1rZXktMzJieXQ="  # base64("test-only-upgrade-path-key-32byt")

SEED_REVISIONS = ("0004", "0012", "0015")


def at_least(revision: str, needed: str) -> bool:
    """Revisions are zero-padded 4-digit strings, so string order is history order."""
    return revision >= needed


def sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def make_cert(cn: str, names: list[str], days: int = 90, client: bool = False) -> tuple[str, str]:
    """Self-signed EC certificate + PKCS#8 key (PEM) valid for `days` from now."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = dt.datetime.now(dt.timezone.utc)
    b = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
         .serial_number(x509.random_serial_number())
         .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=days)))
    if names:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
    if client:
        from cryptography.x509.oid import ExtendedKeyUsageOID

        b = b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
    cert = b.sign(key, hashes.SHA256())
    return (cert.public_bytes(serialization.Encoding.PEM).decode(),
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()).decode())


def _encrypt(value: str) -> str:
    from cryptography.fernet import Fernet

    return "enc:v1:" + Fernet(FERNET_KEY.encode()).encrypt(value.encode()).decode()


def insert(conn, table: str, row: dict):
    """INSERT one row with bound parameters; datetimes / bytes get explicit bind types so both
    SQLite and PostgreSQL store them exactly as the ORM of that era did."""
    cols = list(row)
    quoted = ", ".join(f'"{c}"' for c in cols)
    stmt = sa.text(f'INSERT INTO "{table}" ({quoted}) VALUES ({", ".join(":" + c for c in cols)})')
    binds = []
    for c, v in row.items():
        if isinstance(v, dt.datetime):
            binds.append(sa.bindparam(c, type_=sa.DateTime()))
        elif isinstance(v, bytes):
            binds.append(sa.bindparam(c, type_=sa.LargeBinary()))
    if binds:
        stmt = stmt.bindparams(*binds)
    conn.execute(stmt, row)


def _id(conn, table: str, col: str, value) -> int:
    return conn.execute(sa.text(f'SELECT id FROM "{table}" WHERE "{col}" = :v'), {"v": value}).scalar_one()


# ------------------------------------------------------------------ the data

SHOP, TUNNEL, SUSPENDED = "shop.example.ir", "tunnel.example.com", "suspended.example.org"

SHOP_FEATURES = {"load_balancer": True, "max_pools": 3, "dnssec": True}
TUNNEL_FEATURES = {"tunnel": True, "edge_group": "tunnel", "max_tunnel_paths": 5, "tunnel_max_mbps": 50,
                   "max_tunnel_connections": 200}

SHOP_CONFIG = {
    "cache": {"enabled": True, "edge_ttl": 3600, "browser_ttl": 600, "bypass_cookies": ["sessionid"]},
    "ssl": {"force_https": True, "hsts": {"enabled": True, "max_age": 31536000}},
    "pools": {"pools": [{"name": "web", "method": "weighted", "origins": [
        {"address": "185.143.233.10", "port": 8080, "weight": 3},
        {"address": "185.143.233.11", "port": 8080, "backup": True}]}]},
    "waf": {"mode": "block"},
}
TUNNEL_CONFIG = {
    "tunnel": {"enabled": True, "idle_timeout": 7200, "per_connection_mbps": 0,
               "allowed_countries": ["IR"], "fallback": "decoy", "paths": [
                   {"id": "p1", "path": "/ws-secret", "protocol": "ws",
                    "origin": {"address": "91.99.1.2", "port": 8443, "tls": True, "sni": "origin.tunnel.example.com"}},
                   {"id": "p2", "path": "/grpc-x", "protocol": "grpc", "pool": "tun"}]},
    "pools": {"pools": [{"name": "tun", "protocol": "https", "origins": [{"address": "91.99.1.3", "port": 443}]}]},
}
SUSPENDED_CONFIG = {"cache": {"dev_mode": True}}

# (name, ipv4, ipv6, region, group, capacity)
EDGES = [
    ("ir-thr-1", "5.160.1.10", "2a01:5ec0::10", "home", "general", 1000),
    ("de-fsn-1", "88.99.1.10", None, "global", "general", 10000),
    ("ir-tun-1", "5.160.2.10", None, "home", "tunnel", 500),
]


def seed(conn, revision: str, now: dt.datetime | None = None) -> dict:
    """Write the data set into a database at `revision`; returns the plaintexts and counts."""
    now = (now or dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)).replace(microsecond=0)
    hour = now.replace(minute=0, second=0)
    r = revision
    exp: dict = {"revision": r, "now": now, "tokens": {}, "secrets": {}, "ssl_keys": {}, "api_keys": {},
                 "counts": {}}

    # ---------------- sites
    shop_cert, shop_key = make_cert(SHOP, [SHOP, "www." + SHOP])
    sites = [
        dict(domain=SHOP, external_id="1001", status="active", suspended=False, over_quota=False,
             ns_verified_at=now - dt.timedelta(days=30), ns_checked_at=now - dt.timedelta(hours=1),
             ns_found=json.dumps(["ns1.example-cdn.com", "ns2.example-cdn.com"]),
             bandwidth_limit_gb=500, max_records=200, ssl_allowed=True, rate_limit_rps=50,
             features=json.dumps(SHOP_FEATURES), config=json.dumps(SHOP_CONFIG),
             blocked_ips=json.dumps(["45.12.0.0/16", "103.21.244.7"]),
             secret=_encrypt("a1" * 32), dnssec_enabled=True, ssl_status="active", ssl_cert=shop_cert,
             ssl_key=_encrypt(shop_key), ssl_expires_at=now + dt.timedelta(days=89), ssl_error=None,
             ssl_source="letsencrypt", created_at=now - dt.timedelta(days=60), updated_at=now - dt.timedelta(days=1)),
        dict(domain=TUNNEL, external_id="1002", status="active", suspended=False, over_quota=False,
             ns_verified_at=now - dt.timedelta(days=10), ns_checked_at=now, ns_found="[]",
             bandwidth_limit_gb=0, max_records=100, ssl_allowed=True, rate_limit_rps=0,
             features=json.dumps(TUNNEL_FEATURES), config=json.dumps(TUNNEL_CONFIG), blocked_ips="[]",
             secret=_encrypt("b2" * 32), dnssec_enabled=False, ssl_status="none", ssl_cert=None, ssl_key=None,
             ssl_expires_at=None, ssl_error=None, ssl_source=None,
             created_at=now - dt.timedelta(days=20), updated_at=now - dt.timedelta(days=2)),
        # a row from before DATA_ENCRYPTION_KEY was configured: plaintext secret (still valid)
        dict(domain=SUSPENDED, external_id=None, status="active", suspended=True, over_quota=False,
             ns_verified_at=None, ns_checked_at=None, ns_found="[]", bandwidth_limit_gb=10, max_records=50,
             ssl_allowed=False, rate_limit_rps=0, features="{}", config=json.dumps(SUSPENDED_CONFIG),
             blocked_ips="[]", secret="c3" * 32, dnssec_enabled=False, ssl_status="failed", ssl_cert=None,
             ssl_key=None, ssl_expires_at=None, ssl_error="CAA forbids letsencrypt", ssl_source=None,
             created_at=now - dt.timedelta(days=400), updated_at=now - dt.timedelta(days=100)),
    ]
    exp["secrets"] = {SHOP: "a1" * 32, TUNNEL: "b2" * 32, SUSPENDED: "c3" * 32}
    exp["ssl_keys"][SHOP] = shop_key
    if at_least(r, "0008"):
        sites[0].update(reseller_client_id=42, reseller_label="Reseller A — shop")
        sites[1].update(reseller_client_id=None, reseller_label=None)
    if at_least(r, "0014"):
        cc, ck = make_cert("pcdn-client", [], days=365, client=True)
        sites[0].update(origin_client_cert=cc, origin_client_key=_encrypt(ck),
                        origin_client_expires_at=now + dt.timedelta(days=364))
        exp["origin_client_key"] = ck
        cfg = json.loads(sites[0]["config"])
        cfg["ssl"]["origin_client_auth"] = "custom"
        sites[0]["config"] = json.dumps(cfg)
    if at_least(r, "0015"):
        sites[0].update(
            integration_secrets=json.dumps({"logs": _encrypt("LOGS-S3-SECRET"),
                                            "webhooks": {"wh_0123abcd": _encrypt("whsec-shop")}}, sort_keys=True),
            quota_warned_at=now - dt.timedelta(days=3))
        cfg = json.loads(sites[0]["config"])
        cfg["webhooks"] = {"items": [{"id": "wh_0123abcd", "url": "https://hooks.example.net/pcdn",
                                      "events": ["quota.exceeded", "ssl.issued"], "description": "ops"}]}
        sites[0]["config"] = json.dumps(cfg)
    for s in sites:
        insert(conn, "sites", s)
    sid = {d: _id(conn, "sites", "domain", d) for d in (SHOP, TUNNEL, SUSPENDED)}
    exp["site_ids"] = sid

    # ---------------- records
    recs = [
        (SHOP, "@", "A", "185.143.233.10", 300, None, True, None, None, False, None),
        (SHOP, "@", "AAAA", "2a01:4f8:1:2::10", 300, None, True, None, 8080, False, None),
        (SHOP, "www", "CNAME", SHOP, 300, None, True, None, None, False, None),
        (SHOP, "api", "A", "185.143.233.12", 120, None, True, "web", None, False, None),
        (SHOP, "mail", "A", "185.143.233.20", 3600, None, False, None, None, True, 25),
        (SHOP, "@", "MX", "mail." + SHOP, 3600, 10, False, None, None, False, None),
        (SHOP, "@", "TXT", "v=spf1 mx -all", 3600, None, False, None, None, False, None),
        (SHOP, "_dmarc", "TXT", "v=DMARC1; p=reject", 3600, None, False, None, None, False, None),
        (TUNNEL, "@", "A", "91.99.1.2", 300, None, True, None, None, False, None),
        (TUNNEL, "vpn", "A", "91.99.1.3", 300, None, True, "tun", None, False, None),
        (TUNNEL, "@", "CAA", '0 issue "letsencrypt.org"', 3600, None, False, None, None, False, None),
        (SUSPENDED, "@", "A", "185.143.233.30", 300, None, True, None, None, False, None),
    ]
    for (dom, name, typ, content, ttl, prio, proxied, pool, port, hc, hport) in recs:
        insert(conn, "records", dict(site_id=sid[dom], name=name, type=typ, content=content, ttl=ttl,
                                     priority=prio, proxied=proxied, pool=pool, origin_port=port,
                                     health_check=hc, health_port=hport))
    exp["records"] = {d: sum(1 for x in recs if x[0] == d) for d in sid}

    # ---------------- edges
    for i, (name, v4, v6, region, group, cap) in enumerate(EDGES):
        token = f"edge_{name}_{'x' * 24}"
        exp["tokens"][name] = token
        row = dict(name=name, ipv4=v4, ipv6=v6, region=region, token_hash=sha256(token), enabled=True,
                   last_seen_at=now - dt.timedelta(seconds=20), applied_version="v" + "0" * 63,
                   last_error=None, created_at=now - dt.timedelta(days=90 - i))
        if at_least(r, "0003"):
            row.update(group=group, capacity_mbps=cap, shed=False, load_high=0,
                       metrics=json.dumps({"rx_mbps": 120.5, "tx_mbps": 340.25, "connections": 1800,
                                           "load1": 1.5, "cpus": 8}),
                       metrics_at=now - dt.timedelta(seconds=20))
        if at_least(r, "0004"):
            row.update(cpu_high=0)
        if at_least(r, "0005"):
            row.update(probe_ok=True, probe_ms=12 + i, probe_at=now - dt.timedelta(seconds=30), probe_error=None,
                       probe_fail=0)
        if at_least(r, "0009"):
            row.update(logs=json.dumps(["2026/09/30 nginx: [warn] upstream slow"]), logs_at=now,
                       bundle_version="2026.09.1")
        if at_least(r, "0011"):
            row.update(probe_ok4=True, probe_fail4=0, probe_ok6=(True if v6 else None), probe_fail6=0,
                       shed_high=0, shed_since=None)
        if at_least(r, "0013"):
            row.update(shield=(name == "de-fsn-1"),
                       capabilities=json.dumps({"http3": True, "early_hints": False, "webp_convert": True,
                                                "modules": ["brotli"]}))
        insert(conn, "edges", row)
    eid = {name: _id(conn, "edges", "name", name) for name, *_ in EDGES}
    exp["edge_ids"] = eid

    if at_least(r, "0010"):
        insert(conn, "edge_addresses", dict(edge_id=eid["ir-thr-1"], family=4, ip="5.160.1.11", label="isp-b",
                                            enabled=True, probe_ok=True, probe_ms=9, probe_at=now,
                                            probe_error=None, probe_fail=0, created_at=now - dt.timedelta(days=5)))
        insert(conn, "edge_addresses", dict(edge_id=eid["ir-thr-1"], family=4, ip="5.160.1.12", label="isp-c",
                                            enabled=False, probe_ok=False, probe_ms=None, probe_at=now,
                                            probe_error="timeout", probe_fail=4,
                                            created_at=now - dt.timedelta(days=5)))

    # ---------------- usage (last 6 hours + one row 40 days ago, outside every analytics window)
    usage = []
    for k in range(6):
        for dom, edge in ((SHOP, "ir-thr-1"), (SHOP, "de-fsn-1"), (TUNNEL, "ir-tun-1")):
            details = {"status": {"2xx": 900 - k, "3xx": 50, "4xx": 40, "5xx": 10},
                       "codes": {"200": 900 - k, "304": 50, "404": 40, "502": 10},
                       "countries": {"IR": 700, "DE": 300 - k},
                       "paths": {"/": 500, "/static/app.js": 300},
                       "security": {"waf": 3, "ratelimit": 1}}
            if dom == TUNNEL:
                details["tunnel"] = {"sessions": 10 + k, "seconds": 3600, "bytes_up": 1_000_000,
                                     "bytes_down": 9_000_000, "by_protocol": {"ws": 7, "grpc": 3 + k}}
            usage.append(dict(site_id=sid[dom], edge_id=eid[edge], hour=hour - dt.timedelta(hours=k),
                              bytes=(5 + k) * 1024**3, requests=1000 - k, cache_hits=600, details=json.dumps(details)))
    usage.append(dict(site_id=sid[SHOP], edge_id=eid["ir-thr-1"], hour=hour - dt.timedelta(days=40),
                      bytes=1, requests=7, cache_hits=0, details="{}"))
    for u in usage:
        insert(conn, "usage_hourly", u)
    exp["usage"] = [(u["site_id"], u["hour"], u["bytes"], u["requests"], u["cache_hits"]) for u in usage]

    for k in range(3):
        insert(conn, "security_events", dict(site_id=sid[SHOP], edge_id=eid["ir-thr-1"],
                                             ts=now - dt.timedelta(minutes=5 * k), ip="45.12.3.4", country="NL",
                                             method="POST", host=SHOP, path="/wp-login.php", action="block",
                                             source="waf", rule="941100", user_agent="curl/8.0"))
    purge = dict(site_id=sid[SHOP], urls=json.dumps([f"https://{SHOP}/index.html"]), created_at=now)
    if at_least(r, "0006"):
        purge.update(prefixes=json.dumps(["/static/"]), everything=False)
    insert(conn, "purges", purge)
    for key, value in (("dns_dirty", "1"), ("last_backup_ok", (now - dt.timedelta(hours=3)).isoformat()),
                       ("bundle_version", "2026.09.1")):
        insert(conn, "state", {"key": key, "value": value})

    if at_least(r, "0004"):
        for name in eid:
            for k in range(3):
                insert(conn, "edge_uptime", dict(edge_id=eid[name], hour=hour - dt.timedelta(hours=k),
                                                 samples_total=60, samples_online=60 - k))
    if at_least(r, "0005"):
        insert(conn, "incidents", dict(title="اختلال در نود تهران", body="در حال بررسی", severity="minor",
                                       status="resolved", created_at=now - dt.timedelta(days=2),
                                       updated_at=now - dt.timedelta(days=1)))
        iid = conn.execute(sa.text("SELECT max(id) FROM incidents")).scalar_one()
        for st in ("investigating", "resolved"):
            insert(conn, "incident_updates", dict(incident_id=iid, status=st, body=st,
                                                  created_at=now - dt.timedelta(days=1)))
    if at_least(r, "0007"):
        for dom, scopes, revoked in ((SHOP, ["purge", "stats", "dns"], False), (SHOP, ["stats"], True),
                                     (TUNNEL, ["stats"], False)):
            plain = f"pcdn_{sha256(dom + str(revoked) + str(scopes))[:40]}"
            insert(conn, "api_keys", dict(site_id=sid[dom], key_hash=sha256(plain), name="ci",
                                          scopes=json.dumps(scopes), last_used_at=None,
                                          created_at=now - dt.timedelta(days=7), revoked=revoked))
            if not revoked:
                exp["api_keys"][dom] = plain
    if at_least(r, "0011"):
        for k in range(4):
            insert(conn, "usage_batches", dict(edge_id=eid["ir-thr-1"], batch_id=f"b{k:031d}",
                                               received_at=now - dt.timedelta(minutes=k)))
    if at_least(r, "0012"):
        for action, target in (("site.create", SHOP), ("edge.add", "ir-thr-1"), ("purge", SHOP),
                               ("config.update", TUNNEL)):
            insert(conn, "audit_log", dict(at=now - dt.timedelta(hours=1), actor="whmcs", actor_kind="admin",
                                           action=action, target=target,
                                           detail=json.dumps({"section": "tunnel"} if action == "config.update" else {}),
                                           ip="10.0.0.5"))
    if at_least(r, "0015"):
        minute = now.replace(second=0)
        for k in range(5):
            insert(conn, "analytics_minute", dict(site_id=sid[SHOP], minute=minute - dt.timedelta(minutes=k),
                                                  requests=100 + k, bytes=10_000 * (k + 1), cache_hits=60,
                                                  details=json.dumps({"status": {"2xx": 95, "5xx": 5 + k},
                                                                      "countries": {"IR": 80},
                                                                      "paths": {"/": 100}})))
        insert(conn, "log_spool", dict(site_id=sid[SHOP], hour=hour, records=2,
                                       data=b"\x1f\x8b\x08\x00binary-gzip-chunk\x00\xff", created_at=now))
        insert(conn, "webhook_delivery", dict(delivery_id="dlv_00112233445566aa", site_id=sid[SHOP],
                                              hook_id="wh_0123abcd", event="quota.warning",
                                              event_id="evt_00112233445566aa", payload=json.dumps({"x": 1}),
                                              status="ok", attempts=1, last_code=200, last_error=None,
                                              created_at=now - dt.timedelta(hours=2),
                                              delivered_at=now - dt.timedelta(hours=2), next_attempt_at=None))
        exp["live_requests"] = sum(100 + k for k in range(5))
    return exp
