"""Minimal PowerDNS Authoritative HTTP API client.

Every zone is written to all servers in PDNS_API_URL (comma separated), so
ns1 and ns2 can run on separate machines without zone transfers.
"""

import ipaddress
import logging

import httpx

from .config import settings
from .dnsbuild import build_rrsets, dot, soa_content

log = logging.getLogger("pcdn.pdns")

# rrsets we never delete during sync (written by the ACME hook while issuing certs)
PROTECTED_PREFIXES = ("_acme-challenge.",)
# per-zone override of the server-wide enable-lua-records (PowerDNS >= 4.2 zone metadata)
LUA_META = "ENABLE-LUA-RECORDS"


class PdnsError(RuntimeError):
    def __init__(self, message: str, servers: dict[int, str] | None = None):
        super().__init__(message)
        # index in PDNS_API_URL -> error, for per-server alerts
        self.servers = servers or {}


class PdnsClient:
    def __init__(self, base_url: str, api_key: str | None = None, server_id: str | None = None,
                 transport: httpx.BaseTransport | None = None):
        self.base = f"{base_url.rstrip('/')}/api/v1/servers/{server_id or settings.pdns_server_id}"
        self.http = httpx.Client(
            headers={"X-API-Key": api_key if api_key is not None else settings.pdns_api_key},
            timeout=15,
            transport=transport,
        )

    def _req(self, method: str, path: str, **kw) -> httpx.Response:
        r = self.http.request(method, self.base + path, **kw)
        if r.status_code >= 400 and r.status_code != 404:
            raise PdnsError(f"PowerDNS {method} {path}: {r.status_code} {r.text[:300]}")
        return r

    def get_zone(self, domain: str) -> dict | None:
        r = self._req("GET", f"/zones/{dot(domain)}")
        return None if r.status_code == 404 else r.json()

    def create_zone(self, domain: str, kind: str = "Native", masters: list[str] | None = None):
        if kind == "Slave":  # secondary DNS (SPEC §16.7): the content comes from the masters (AXFR)
            body = {"name": dot(domain), "kind": "Slave", "masters": list(masters or []), "nameservers": []}
            self._req("POST", "/zones", json=body)
            # H1: content written by the customer's primary never runs as LUA on our nameservers
            self.set_metadata(domain, LUA_META, ["0"])
            return
        else:
            body = {
                "name": dot(domain),
                "kind": "Native",
                "nameservers": [],
                "soa_edit_api": "INCEPTION-INCREMENT",
                "rrsets": [{
                    "name": dot(domain), "type": "SOA", "ttl": 3600,
                    "records": [{"content": soa_content(domain), "disabled": False}],
                }],
            }
        self._req("POST", "/zones", json=body)

    def delete_zone(self, domain: str):
        self._req("DELETE", f"/zones/{dot(domain)}")

    def patch(self, domain: str, rrsets: list[dict]):
        self._req("PATCH", f"/zones/{dot(domain)}", json={"rrsets": rrsets})

    def sync_zone(self, site, edges, force_secondary: bool = False) -> None:
        from .dns_secondary import configured as secondary_configured
        from .dns_secondary import spec as secondary_spec

        sec = secondary_spec(site, force=force_secondary)
        zone = self.get_zone(site.domain)
        if zone is None:
            kind = sec["kind"] if sec else "Native"
            self.create_zone(site.domain, kind, sec["masters"] if sec else None)
            zone = self.get_zone(site.domain) or {"rrsets": [], "kind": kind}
        if sec is not None or zone.get("kind") == "Slave":
            from .dns_secondary import OFF

            sec = sec or dict(OFF)
            self.sync_secondary(site.domain, zone, sec)
            if sec["kind"] == "Slave":
                return  # a slave zone's content comes from the customer's primaries
        desired = build_rrsets(site, edges)
        want = {(r["name"], r["type"]) for r in desired}
        patch = [dict(r, changetype="REPLACE") for r in desired]
        for rr in zone.get("rrsets", []):
            key = (rr["name"], rr["type"])
            if rr["type"] == "SOA" or key in want or rr["name"].startswith(PROTECTED_PREFIXES):
                continue
            patch.append({"name": rr["name"], "type": rr["type"], "changetype": "DELETE"})
        self.patch(site.domain, patch)
        if sec is not None or secondary_configured(site):
            # H1: a zone that is (or was) a slave is Native and fully controller-written from here on:
            # lift the ENABLE-LUA-RECORDS=0 override only now that the transferred records are gone
            # (also on later syncs, in case this step failed after the kind change)
            self.set_metadata(site.domain, LUA_META, [])

    # --- secondary DNS (SPEC §16.7) ---------------------------------------
    def set_zone_kind(self, domain: str, kind: str, masters: list[str]):
        self._req("PUT", f"/zones/{dot(domain)}", json={"kind": kind, "masters": list(masters)})

    def axfr_retrieve(self, domain: str):
        self._req("PUT", f"/zones/{dot(domain)}/axfr-retrieve")

    def set_metadata(self, domain: str, kind: str, values: list[str]):
        """Replace one zone metadata kind; an empty list removes it."""
        if values:
            self._req("PUT", f"/zones/{dot(domain)}/metadata/{kind}", json={"kind": kind, "metadata": list(values)})
        else:
            self._req("DELETE", f"/zones/{dot(domain)}/metadata/{kind}")

    def ensure_tsigkey(self, name: str, algorithm: str, secret: str):
        r = self._req("GET", f"/tsigkeys/{dot(name)}")
        body = {"name": name, "algorithm": algorithm, "key": secret}
        if r.status_code == 404:
            self._req("POST", "/tsigkeys", json=body)
            return
        cur = r.json()
        if cur.get("algorithm", "").rstrip(".").lower() != algorithm or cur.get("key") != secret:
            self._req("PUT", f"/tsigkeys/{cur.get('id') or dot(name)}", json=body)

    def delete_tsigkey(self, name: str):
        self._req("DELETE", f"/tsigkeys/{dot(name)}")

    def sync_secondary(self, domain: str, zone: dict, sec: dict):
        """Zone kind / masters, TSIG key and transfer metadata as `sec` (dns_secondary.spec) says."""
        tsig = sec.get("tsig")
        if tsig:
            self.ensure_tsigkey(tsig["name"], tsig["algorithm"], tsig["secret"])
        kind, masters = sec["kind"], sec["masters"]
        # H1 (security review): a Slave zone's records come from the customer's primary, so LUA records
        # are switched off for it (zone metadata ENABLE-LUA-RECORDS=0 overrides the server-wide
        # enable-lua-records=yes the controller's own zones need). Set on EVERY sync of a slave zone,
        # BEFORE a kind change / transfer, so zones made slaves by an older controller get it too. A
        # zone going back to Native keeps it until sync_zone has replaced the transferred records.
        if kind == "Slave":
            self.set_metadata(domain, LUA_META, ["0"])
        if zone.get("kind", "Native") != kind or _masters(zone.get("masters")) != _masters(masters):
            self.set_zone_kind(domain, kind, masters)
            if kind == "Slave":
                try:
                    self.axfr_retrieve(domain)  # first transfer now rather than at the next refresh
                except PdnsError:
                    log.warning("axfr-retrieve of %s failed; PowerDNS retries on its own", domain)
        self.set_metadata(domain, "ALLOW-AXFR-FROM", sec["allow_axfr"])
        self.set_metadata(domain, "TSIG-ALLOW-AXFR", [tsig["name"]] if tsig and sec["allow_axfr"] else [])
        self.set_metadata(domain, "AXFR-MASTER-TSIG", [tsig["name"]] if tsig and kind == "Slave" else [])

    def set_txt(self, zone: str, name: str, values: list[str]):
        if values:
            rr = {"name": dot(name), "type": "TXT", "ttl": 60, "changetype": "REPLACE",
                  "records": [{"content": f'"{v}"', "disabled": False} for v in values]}
        else:
            rr = {"name": dot(name), "type": "TXT", "changetype": "DELETE"}
        self.patch(zone, [rr])

    def get_txt(self, zone: str, name: str) -> list[str]:
        z = self.get_zone(zone) or {}
        for rr in z.get("rrsets", []):
            if rr["name"] == dot(name) and rr["type"] == "TXT":
                return [r["content"].strip('"') for r in rr["records"]]
        return []


    # --- DNSSEC ---------------------------------------------------------
    def cryptokeys(self, domain: str) -> list[dict]:
        r = self._req("GET", f"/zones/{dot(domain)}/cryptokeys")
        return [] if r.status_code == 404 else r.json()

    def cryptokey(self, domain: str, key_id: int) -> dict:
        return self._req("GET", f"/zones/{dot(domain)}/cryptokeys/{key_id}").json()

    def add_cryptokey(self, domain: str, privatekey: str | None = None) -> dict:
        body = {"keytype": "csk", "active": True, "published": True}
        if privatekey:
            body["privatekey"] = privatekey
        else:
            body["algorithm"] = "ECDSAP256SHA256"
        return self._req("POST", f"/zones/{dot(domain)}/cryptokeys", json=body).json()

    def delete_cryptokeys(self, domain: str):
        for k in self.cryptokeys(domain):
            self._req("DELETE", f"/zones/{dot(domain)}/cryptokeys/{k['id']}")


class PdnsCluster:
    """Fans every write out to all PowerDNS servers; fails if any server fails."""

    def __init__(self, clients: list[PdnsClient]):
        self.clients = clients

    def _each(self, fn):
        errors = {}
        for i, c in enumerate(self.clients):
            try:
                fn(c)
            except Exception as e:  # noqa: BLE001
                errors[i] = f"{c.base}: {e}"
        if errors:
            raise PdnsError("; ".join(errors.values()), errors)

    def sync_zone(self, site, edges, force_secondary: bool = False):
        self._each(lambda c: c.sync_zone(site, edges, force_secondary))

    def delete_tsigkey(self, name: str):
        self._each(lambda c: c.delete_tsigkey(name))

    def delete_zone(self, domain: str):
        self._each(lambda c: c.delete_zone(domain))

    def find_zone(self, fqdn_name: str) -> str | None:
        labels = fqdn_name.rstrip(".").split(".")
        for i in range(len(labels) - 1):
            cand = ".".join(labels[i:])
            if self.clients[0].get_zone(cand) is not None:
                return cand
        return None

    def add_txt(self, name: str, value: str):
        zone = self.find_zone(name)
        if zone is None:
            raise PdnsError(f"no zone for {name}")

        def add(c: PdnsClient):
            vals = c.get_txt(zone, name)
            if value not in vals:
                c.set_txt(zone, name, vals + [value])

        self._each(add)

    def remove_txt(self, name: str, value: str):
        zone = self.find_zone(name)
        if zone is None:
            return
        self._each(lambda c: c.set_txt(zone, name, [v for v in c.get_txt(zone, name) if v != value]))


    def enable_dnssec(self, domain: str) -> dict:
        """Sign the zone with ONE key shared by every server (so all NS serve valid signatures)."""
        first, rest = self.clients[0], self.clients[1:]
        keys = [k for k in first.cryptokeys(domain) if k.get("active")]
        key = first.cryptokey(domain, keys[0]["id"]) if keys else first.add_cryptokey(domain)
        if "privatekey" not in key:
            key = first.cryptokey(domain, key["id"])

        def mirror(c: PdnsClient):
            c.delete_cryptokeys(domain)
            c.add_cryptokey(domain, key["privatekey"])

        for c in rest:
            mirror(c)
        return self.dnssec_info(domain)

    def disable_dnssec(self, domain: str):
        self._each(lambda c: c.delete_cryptokeys(domain))

    def dnssec_info(self, domain: str) -> dict:
        keys = [k for k in self.clients[0].cryptokeys(domain) if k.get("active")]
        if not keys:
            return {"enabled": False, "ds": [], "dnskey": None}
        k = keys[0]
        # prefer SHA-256 digests (digest type 2)
        ds = [d for d in k.get("ds", []) if d.split()[2:3] == ["2"]] or k.get("ds", [])
        return {"enabled": True, "ds": ds, "dnskey": k.get("dnskey")}


def _masters(values) -> list[str]:
    """Comparable master list: PowerDNS may report "ip:53" for an address configured as "ip"."""
    out = []
    for v in values or []:
        v = str(v).strip()
        if v.startswith("[") and v.endswith("]:53"):
            v = v[1:-4]
        elif v.count(":") == 1 and v.endswith(":53"):
            v = v[:-3]
        out.append(v.strip("[]"))
    return sorted(out)


def ping(c: PdnsClient, timeout: float = 5) -> str | None:
    """None when the server's API answers, else a short error (never contains the API key)."""
    try:
        r = c.http.get(c.base, timeout=timeout)
    except httpx.HTTPError as e:
        return f"{type(e).__name__}: {e}"[:300]
    if r.status_code != 200:
        return f"HTTP {r.status_code}"
    return None


def insecure_api_urls(raw: str | None = None) -> list[str]:
    """PDNS_API_URL entries whose API key would travel in clear over a public network (security
    review M5): plain http:// to a public IP literal or to a dotted host name (cannot be told
    private without DNS). Fine: https://, private / loopback IP literals, single-label Docker
    service names such as http://pdns:8081."""
    from .netguard import is_public_ip

    out = []
    for u in (raw if raw is not None else settings.pdns_api_url).split(","):
        u = u.strip()
        if not u:
            continue
        try:
            url = httpx.URL(u)
        except Exception:  # noqa: BLE001
            out.append(u)
            continue
        if url.scheme == "https":
            continue
        host = (url.host or "").strip("[]")
        try:
            ipaddress.ip_address(host)
            if is_public_ip(host):
                out.append(u)
            continue
        except ValueError:
            pass
        if "." in host and host != "localhost":
            out.append(u)
    return out


def check_transport() -> None:
    """At startup: warn about (or, with PDNS_API_REQUIRE_PRIVATE, refuse) a plain-HTTP PowerDNS API
    on a public network (M5)."""
    bad = insecure_api_urls() if settings.pdns_enabled else []
    if not bad:
        return
    msg = (f"PDNS_API_URL uses plain http:// over a possibly public network: {', '.join(bad)}. The PowerDNS "
           "API key travels in clear; use a private network (WireGuard) or https (docs/SECURITY.md)")
    if settings.pdns_api_require_private:
        raise RuntimeError(msg)
    log.warning(msg)


_client: PdnsCluster | None = None


def client() -> PdnsCluster:
    global _client
    if _client is None:
        urls = [u.strip() for u in settings.pdns_api_url.split(",") if u.strip()]
        _client = PdnsCluster([PdnsClient(u) for u in urls])
    return _client


def set_client(c):
    global _client
    _client = c if c is None or isinstance(c, PdnsCluster) else PdnsCluster([c])
