"""Minimal PowerDNS Authoritative HTTP API client.

Every zone is written to all servers in PDNS_API_URL (comma separated), so
ns1 and ns2 can run on separate machines without zone transfers.
"""

import logging

import httpx

from .config import settings
from .dnsbuild import build_rrsets, dot, soa_content

log = logging.getLogger("pcdn.pdns")

# rrsets we never delete during sync (written by the ACME hook while issuing certs)
PROTECTED_PREFIXES = ("_acme-challenge.",)


class PdnsError(RuntimeError):
    pass


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

    def create_zone(self, domain: str):
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

    def sync_zone(self, site, edges) -> None:
        zone = self.get_zone(site.domain)
        if zone is None:
            self.create_zone(site.domain)
            zone = self.get_zone(site.domain) or {"rrsets": []}
        desired = build_rrsets(site, edges)
        want = {(r["name"], r["type"]) for r in desired}
        patch = [dict(r, changetype="REPLACE") for r in desired]
        for rr in zone.get("rrsets", []):
            key = (rr["name"], rr["type"])
            if rr["type"] == "SOA" or key in want or rr["name"].startswith(PROTECTED_PREFIXES):
                continue
            patch.append({"name": rr["name"], "type": rr["type"], "changetype": "DELETE"})
        self.patch(site.domain, patch)

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
        errors = []
        for c in self.clients:
            try:
                fn(c)
            except Exception as e:  # noqa: BLE001
                errors.append(f"{c.base}: {e}")
        if errors:
            raise PdnsError("; ".join(errors))

    def sync_zone(self, site, edges):
        self._each(lambda c: c.sync_zone(site, edges))

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
