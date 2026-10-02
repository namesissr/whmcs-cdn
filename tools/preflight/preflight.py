#!/usr/bin/env python3
"""Pasargad CDN production preflight (SPEC §18.6) — Python 3 standard library only.

Checks a live deployment from the operator's machine or the controller host and prints a table
(or JSON) of OK / WARN / FAIL / SKIP rows:

  controller   GET /healthz, GET /healthz/deep (status, warnings), database revision == head,
               backup age, alert channels configured
  nodes        GET /api/v1/edges (admin key): every enabled node's heartbeat is fresh and its
               bundle_version equals GET /edge/version
  dns          ns1/ns2 (--ns) answer SOA for a sample zone authoritatively, and the serials match
  tls          days left on the controller's certificate (or --tls-host)
  pdns-api     the PowerDNS HTTP API (port 8081) is NOT reachable from here (best effort; run it
               from a machine outside your private network)
  metrics      GET /metrics without credentials is refused (WARN if open)
  alert-test   POST /api/v1/alerts/test (only with --alert-test; really sends a test message)

Exit code: 0 all OK (or only WARN without --strict), 1 a WARN with --strict, 2 any FAIL.
The admin API key is read ONLY from the environment variable PCDN_ADMIN_KEY (never argv) and
is never printed.

  PCDN_ADMIN_KEY=... tools/preflight/preflight.py --controller https://cdn-api.example.com \\
      --ns ns1.example.com --ns ns2.example.com [--zone example.org] [--alert-test] [--json]
"""

from __future__ import annotations

import argparse
import json
import os
import random
import socket
import ssl
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

OK, WARN, FAIL, SKIP = "OK", "WARN", "FAIL", "SKIP"
KEY_ENV = "PCDN_ADMIN_KEY"
USER_AGENT = "pcdn-preflight/1.0"


class Check:
    __slots__ = ("name", "status", "detail", "data")

    def __init__(self, name: str, status: str, detail: str = "", data: dict | None = None):
        self.name, self.status, self.detail, self.data = name, status, detail, data

    def as_dict(self) -> dict:
        d = {"name": self.name, "status": self.status, "detail": self.detail}
        if self.data:
            d["data"] = self.data
        return d


# ---------------------------------------------------------------------------------------- HTTP

class Http:
    """Tiny JSON HTTP client bound to the controller; the key goes only into the header."""

    def __init__(self, base: str, key: str | None, timeout: float, ca_file: str | None = None):
        self.base = base.rstrip("/")
        self.key = key
        self.timeout = timeout
        self.ctx = ssl.create_default_context(cafile=ca_file) if ca_file else ssl.create_default_context()

    def request(self, method: str, path: str, *, admin: bool = False, auth: bool = True):
        """-> (status_code, parsed JSON or text). Network errors raise OSError."""
        req = urllib.request.Request(self.base + path, method=method, headers={"User-Agent": USER_AGENT,
                                                                               "Accept": "application/json"})
        if admin and auth and self.key:
            req.add_header("Authorization", "Bearer " + self.key)
        if method == "POST":
            req.data = b"{}"
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as r:
                code, raw = r.status, r.read(4 << 20)
        except urllib.error.HTTPError as e:
            code, raw = e.code, e.read(1 << 20) if e.fp else b""
        text = raw.decode("utf-8", "replace")
        try:
            return code, json.loads(text)
        except ValueError:
            return code, text


def _short(body, limit: int = 160) -> str:
    if isinstance(body, dict) and "detail" in body:
        body = body["detail"]
    s = body if isinstance(body, str) else json.dumps(body, ensure_ascii=False)
    s = " ".join(s.split())
    return s if len(s) <= limit else s[: limit - 1] + "…"


def _err(e: BaseException) -> str:
    if isinstance(e, urllib.error.URLError) and getattr(e, "reason", None) is not None:
        e = e.reason if isinstance(e.reason, BaseException) else e
    return f"{type(e).__name__}: {e}"


def _parse_ts(iso: str | None) -> datetime | None:
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# ----------------------------------------------------------------------------------- controller

def check_controller(http: Http, opts) -> tuple[list[Check], dict | None]:
    out: list[Check] = []
    try:
        code, body = http.request("GET", "/healthz")
        if code == 200 and isinstance(body, dict) and body.get("ok") is True:
            out.append(Check("controller /healthz", OK, "ok"))
        else:
            out.append(Check("controller /healthz", FAIL, f"HTTP {code}: {_short(body)}"))
    except OSError as e:
        out.append(Check("controller /healthz", FAIL, _err(e)))
        return out, None  # unreachable: the deep check would only repeat the error

    deep = None
    try:
        code, body = http.request("GET", "/healthz/deep")
    except OSError as e:
        out.append(Check("controller /healthz/deep", FAIL, _err(e)))
        return out, None
    if not isinstance(body, dict):
        out.append(Check("controller /healthz/deep", FAIL, f"HTTP {code}: {_short(body)}"))
        return out, None
    deep = body
    status = body.get("status")
    warnings = [str(w) for w in body.get("warnings") or []]
    if code == 200 and status == "ok":
        st = WARN if warnings else OK
        out.append(Check("controller /healthz/deep", st, "ok" + (": " + "; ".join(warnings) if warnings else ""),
                         {"warnings": warnings}))
    elif code == 200 and status == "degraded":
        out.append(Check("controller /healthz/deep", WARN, "degraded: " + "; ".join(warnings), {"warnings": warnings}))
    else:
        out.append(Check("controller /healthz/deep", FAIL, f"HTTP {code} status={status}: " + "; ".join(warnings)))

    db = body.get("database") or {}
    if not db.get("ok"):
        out.append(Check("database migrations", FAIL, f"database not reachable ({db.get('error', 'unknown')})"))
    elif db.get("revision") == db.get("head"):
        out.append(Check("database migrations", OK, f"at head {db.get('head')}",
                         {"revision": db.get("revision"), "head": db.get("head")}))
    else:
        out.append(Check("database migrations", FAIL, f"revision {db.get('revision')} != head {db.get('head')} "
                         "(run: python -m app.manage upgrade)", {"revision": db.get("revision"), "head": db.get("head")}))

    b = body.get("backup")
    if b is None:
        out.append(Check("backup age", SKIP, "not reported by this controller"))
    elif not b.get("enabled"):
        out.append(Check("backup age", WARN, "automatic backups are disabled (BACKUP_ENABLED)"))
    else:
        age = b.get("last_success_age_hours")
        if age is None:
            out.append(Check("backup age", FAIL, "no successful backup recorded"))
        elif age > opts.backup_max_hours:
            out.append(Check("backup age", FAIL, f"last success {age} h ago (> {opts.backup_max_hours} h)",
                             {"age_hours": age}))
        else:
            note = " (an earlier run failed; see the controller log)" if b.get("failing") else ""
            out.append(Check("backup age", OK, f"last success {age} h ago{note}", {"age_hours": age}))

    a = body.get("alerts")
    if a is not None:
        chans = a.get("channels") or []
        if chans:
            extra = f", {a.get('open', 0)} open ({a.get('critical', 0)} critical)"
            st = WARN if a.get("critical") else OK
            out.append(Check("alert channels", st, ", ".join(map(str, chans)) + extra))
        else:
            out.append(Check("alert channels", WARN, "no alert channel (Telegram / e-mail) configured"))
    return out, deep


def check_nodes(http: Http, opts) -> list[Check]:
    if not http.key:
        return [Check("nodes", WARN, f"{KEY_ENV} not set: node heartbeat/version checks skipped")]
    try:
        code, edges = http.request("GET", "/api/v1/edges", admin=True)
    except OSError as e:
        return [Check("nodes", FAIL, _err(e))]
    if code == 401:
        return [Check("nodes", FAIL, f"admin API refused the key in {KEY_ENV} (HTTP 401)")]
    if code != 200 or not isinstance(edges, list):
        return [Check("nodes", FAIL, f"GET /api/v1/edges: HTTP {code}: {_short(edges)}")]

    bundle = None
    try:
        bcode, bbody = http.request("GET", "/edge/version")
        if bcode == 200 and isinstance(bbody, dict):
            bundle = bbody.get("version")
    except OSError:
        pass

    enabled = [e for e in edges if isinstance(e, dict) and e.get("enabled", True)]
    out: list[Check] = []
    if not enabled:
        return [Check("nodes", FAIL, "no enabled edge node")]
    now = datetime.now(timezone.utc)
    if bundle is None:
        out.append(Check("edge bundle version", WARN, "GET /edge/version gave no version; node versions not compared"))
    for e in enabled:
        name = f"node {e.get('name') or e.get('id')}"
        seen = _parse_ts(e.get("last_seen_at"))
        ver = e.get("bundle_version")
        data = {"id": e.get("id"), "last_seen_at": e.get("last_seen_at"), "bundle_version": ver, "bundle": bundle}
        problems_fail, problems_warn = [], []
        if seen is None:
            problems_fail.append("never sent a heartbeat")
            age = None
        else:
            age = int((now - seen).total_seconds())
            data["heartbeat_age_s"] = age
            if age > opts.heartbeat_max:
                problems_fail.append(f"heartbeat {age}s ago (> {opts.heartbeat_max}s)")
        if bundle is not None:
            if not ver:
                problems_warn.append("bundle version unknown")
            elif ver != bundle:
                problems_warn.append(f"runs {ver}, bundle is {bundle} (bootstrap.sh --upgrade)")
        if e.get("last_error"):
            problems_warn.append("last error: " + _short(e["last_error"], 80))
        probe = e.get("probe") or {}
        if probe.get("ok") is False:
            problems_warn.append("health probe failing")
        if problems_fail:
            out.append(Check(name, FAIL, "; ".join(problems_fail + problems_warn), data))
        elif problems_warn:
            out.append(Check(name, WARN, "; ".join(problems_warn), data))
        else:
            out.append(Check(name, OK, f"heartbeat {age}s ago, version {ver or '-'}", data))
    return out


def pick_zone(http: Http) -> str | None:
    if not http.key:
        return None
    try:
        code, sites = http.request("GET", "/api/v1/sites", admin=True)
    except OSError:
        return None
    if code != 200 or not isinstance(sites, list):
        return None
    for s in sites:
        if isinstance(s, dict) and s.get("domain") and s.get("status") in (None, "active"):
            return s["domain"]
    return None


def check_metrics(http: Http) -> Check:
    try:
        code, _ = http.request("GET", "/metrics")
    except OSError as e:
        return Check("metrics protected", WARN, "GET /metrics failed: " + _err(e))
    if code in (401, 403):
        return Check("metrics protected", OK, f"unauthenticated scrape refused (HTTP {code})")
    if code == 200:
        return Check("metrics protected", WARN, "GET /metrics is open without a token (set METRICS_TOKEN or "
                     "restrict it in the reverse proxy)")
    if code == 404:
        return Check("metrics protected", OK, "not exposed here (HTTP 404)")
    return Check("metrics protected", WARN, f"unexpected HTTP {code}")


def check_alert_test(http: Http) -> Check:
    if not http.key:
        return Check("alert test", FAIL, f"--alert-test needs {KEY_ENV}")
    try:
        code, body = http.request("POST", "/api/v1/alerts/test", admin=True)
    except OSError as e:
        return Check("alert test", FAIL, _err(e))
    if code == 409:
        return Check("alert test", FAIL, "no alert channel configured")
    if code != 200 or not isinstance(body, dict):
        return Check("alert test", FAIL, f"HTTP {code}: {_short(body)}")
    results = body.get("results") or {}
    if body.get("ok"):
        return Check("alert test", OK, "sent via " + ", ".join(sorted(results)) + " — confirm it arrived", results)
    bad = [f"{k}: {v}" for k, v in results.items() if v != "ok"]
    st = WARN if len(bad) < len(results) else FAIL
    return Check("alert test", st, "; ".join(bad) or "not delivered", results)


# ------------------------------------------------------------------------------------------ TLS

def check_tls(host: str, port: int, timeout: float, ca_file: str | None, warn_days: int, fail_days: int) -> Check:
    name = "controller TLS"
    ctx = ssl.create_default_context(cafile=ca_file) if ca_file else ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                cert = s.getpeercert()
    except ssl.SSLCertVerificationError as e:
        return Check(name, FAIL, f"{host}:{port}: certificate not valid: {e.verify_message or e}")
    except (OSError, ssl.SSLError) as e:
        return Check(name, FAIL, f"{host}:{port}: {_err(e)}")
    not_after = cert.get("notAfter")
    if not not_after:
        return Check(name, WARN, "certificate has no notAfter")
    expires = ssl.cert_time_to_seconds(not_after)
    days = int((expires - time.time()) // 86400)
    data = {"host": host, "port": port, "not_after": not_after, "days_left": days}
    if days < fail_days:
        return Check(name, FAIL, f"expires in {days} days ({not_after})", data)
    if days < warn_days:
        return Check(name, WARN, f"expires in {days} days ({not_after}); is ACME renewal running?", data)
    return Check(name, OK, f"{days} days left", data)


# ------------------------------------------------------------------------------------------ DNS

QTYPE_SOA = 6
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


class DnsError(Exception):
    pass


def _encode_name(name: str) -> bytes:
    out = b""
    for label in name.strip(".").split("."):
        if label:
            b = label.encode("idna")
            if len(b) > 63:
                raise DnsError("label too long")
            out += bytes([len(b)]) + b
    return out + b"\0"


def _read_name(msg: bytes, off: int) -> tuple[str, int]:
    labels, jumped, end, hops = [], False, off, 0
    while True:
        if off >= len(msg):
            raise DnsError("truncated name")
        ln = msg[off]
        if ln & 0xC0 == 0xC0:
            if off + 1 >= len(msg):
                raise DnsError("truncated pointer")
            ptr = ((ln & 0x3F) << 8) | msg[off + 1]
            if not jumped:
                end = off + 2
            jumped, off, hops = True, ptr, hops + 1
            if hops > 32:
                raise DnsError("compression loop")
            continue
        off += 1
        if ln == 0:
            break
        labels.append(msg[off:off + ln].decode("ascii", "replace"))
        off += ln
    return ".".join(labels), (end if jumped else off)


def build_query(qid: int, zone: str, qtype: int = QTYPE_SOA) -> bytes:
    # flags 0: standard query, RD off (we ask the authoritative server itself)
    return struct.pack(">HHHHHH", qid, 0, 1, 0, 0, 0) + _encode_name(zone) + struct.pack(">HH", qtype, 1)


def parse_soa_response(msg: bytes, qid: int) -> dict:
    if len(msg) < 12:
        raise DnsError("short response")
    rid, flags, qd, an, _ns, _ar = struct.unpack(">HHHHHH", msg[:12])
    if rid != qid:
        raise DnsError("response id mismatch")
    rcode = flags & 0xF
    res = {"rcode": RCODES.get(rcode, str(rcode)), "aa": bool(flags & 0x0400), "tc": bool(flags & 0x0200),
           "serial": None, "mname": None}
    off = 12
    for _ in range(qd):
        _, off = _read_name(msg, off)
        off += 4
    for _ in range(an):
        _, off = _read_name(msg, off)
        if off + 10 > len(msg):
            raise DnsError("truncated record")
        rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", msg[off:off + 10])
        off += 10
        if rtype == QTYPE_SOA:
            mname, p = _read_name(msg, off)
            _rname, p = _read_name(msg, p)
            if p + 20 > len(msg):
                raise DnsError("truncated SOA")
            res["serial"] = struct.unpack(">I", msg[p:p + 4])[0]
            res["mname"] = mname
            break
        off += rdlen
    return res


def query_soa(server: str, port: int, zone: str, timeout: float, tries: int = 2) -> dict:
    infos = socket.getaddrinfo(server, port, type=socket.SOCK_DGRAM)
    family, _, _, _, addr = infos[0]
    last: Exception | None = None
    for _ in range(tries):
        qid = random.randint(0, 0xFFFF)
        with socket.socket(family, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            try:
                s.sendto(build_query(qid, zone), addr)
                deadline = time.monotonic() + timeout
                while True:
                    s.settimeout(max(0.01, deadline - time.monotonic()))
                    data, src = s.recvfrom(4096)
                    if src[0] != addr[0]:
                        continue
                    try:
                        return parse_soa_response(data, qid)
                    except DnsError as e:
                        if "id mismatch" in str(e):
                            continue
                        raise
            except socket.timeout as e:
                last = e
    raise DnsError(f"no answer within {timeout}s ({type(last).__name__})")


def _host_port(spec: str, default_port: int) -> tuple[str, int]:
    if spec.startswith("["):  # [v6]:port
        host, _, rest = spec[1:].partition("]")
        return host, int(rest[1:]) if rest.startswith(":") else default_port
    if spec.count(":") == 1:
        host, port = spec.split(":")
        return host, int(port)
    return spec, default_port


def check_dns(ns_list: list[str], zone: str | None, timeout: float) -> list[Check]:
    if not ns_list:
        return [Check("dns SOA", SKIP, "no --ns given")]
    if not zone:
        return [Check("dns SOA", WARN, "no sample zone (pass --zone, or set PCDN_ADMIN_KEY to pick one)")]
    out, serials = [], {}
    for spec in ns_list:
        host, port = _host_port(spec, 53)
        name = f"dns {spec} SOA {zone}"
        try:
            r = query_soa(host, port, zone, timeout)
        except (OSError, DnsError) as e:
            out.append(Check(name, FAIL, _err(e)))
            continue
        if r["rcode"] != "NOERROR":
            out.append(Check(name, FAIL, f"rcode {r['rcode']}", r))
        elif r["serial"] is None:
            out.append(Check(name, FAIL, "NOERROR but no SOA in the answer", r))
        elif not r["aa"]:
            serials[spec] = r["serial"]
            out.append(Check(name, WARN, f"serial {r['serial']} but answer not authoritative (AA=0)", r))
        else:
            serials[spec] = r["serial"]
            out.append(Check(name, OK, f"serial {r['serial']}", r))
    if len(serials) >= 2:
        distinct = set(serials.values())
        if len(distinct) == 1:
            out.append(Check("dns serials match", OK, f"{len(serials)} servers at {distinct.pop()}"))
        else:
            out.append(Check("dns serials match", WARN, "serials differ: " +
                             ", ".join(f"{k}={v}" for k, v in serials.items()) +
                             " (zone transfer/replication lag? re-run in a minute)", {"serials": serials}))
    return out


# -------------------------------------------------------------------------------------- PowerDNS

def check_pdns_public(targets: list[str], timeout: float) -> list[Check]:
    """Best effort: from THIS machine, the PowerDNS HTTP API must not accept connections."""
    out = []
    for spec in targets:
        if "://" in spec:
            u = urllib.parse.urlsplit(spec)
            host, port = u.hostname or "", u.port or (443 if u.scheme == "https" else 8081)
        else:
            host, port = _host_port(spec, 8081)
        name = f"pdns API {host}:{port} closed"
        try:
            with socket.create_connection((host, port), timeout=timeout):
                pass
        except socket.timeout:
            out.append(Check(name, OK, "filtered (connect timed out)"))
            continue
        except ConnectionRefusedError:
            out.append(Check(name, OK, "refused"))
            continue
        except OSError as e:
            out.append(Check(name, OK, f"not reachable ({type(e).__name__})"))
            continue
        out.append(Check(name, FAIL, "accepts connections from this machine — if this machine is on the public "
                         "internet, firewall port 8081 (deploy/ns2-firewall.sh); use --skip-pdns from the private "
                         "network"))
    return out


# ------------------------------------------------------------------------------------------ main

def run(opts, key: str | None) -> list[Check]:
    http = Http(opts.controller, key, opts.timeout, opts.ca_file)
    checks, _deep = check_controller(http, opts)
    checks += check_nodes(http, opts)

    zone = opts.zone or pick_zone(http)
    checks += check_dns(opts.ns, zone, opts.dns_timeout)

    u = urllib.parse.urlsplit(opts.controller)
    if opts.tls_host:
        h, p = _host_port(opts.tls_host, 443)
        checks.append(check_tls(h, p, opts.timeout, opts.ca_file, opts.tls_warn_days, opts.tls_fail_days))
    elif u.scheme == "https":
        checks.append(check_tls(u.hostname, u.port or 443, opts.timeout, opts.ca_file,
                                opts.tls_warn_days, opts.tls_fail_days))
    else:
        checks.append(Check("controller TLS", WARN, "controller URL is not https (pass --tls-host to check the "
                            "public certificate)"))

    if not opts.skip_pdns:
        targets = opts.pdns_api or [_host_port(n, 53)[0] for n in opts.ns]
        if targets:
            checks += check_pdns_public(targets, opts.pdns_timeout)
        else:
            checks.append(Check("pdns API closed", SKIP, "no --ns / --pdns-api given"))

    checks.append(check_metrics(http))
    if opts.alert_test:
        checks.append(check_alert_test(http))
    return checks


def exit_code(checks: list[Check], strict: bool) -> int:
    if any(c.status == FAIL for c in checks):
        return 2
    if strict and any(c.status == WARN for c in checks):
        return 1
    return 0


def redact(text: str, key: str | None) -> str:
    return text.replace(key, "***") if key and len(key) >= 4 else text


def render_table(checks: list[Check]) -> str:
    w = max([len(c.name) for c in checks] + [5])
    lines = [f"{'CHECK'.ljust(w)}  STATUS  DETAIL", f"{'-' * w}  ------  ------"]
    for c in checks:
        lines.append(f"{c.name.ljust(w)}  {c.status.ljust(6)}  {c.detail}")
    counts = {s: sum(1 for c in checks if c.status == s) for s in (OK, WARN, FAIL, SKIP)}
    lines.append("")
    lines.append("  ".join(f"{k}={v}" for k, v in counts.items()))
    return "\n".join(lines)


def parse_args(argv):
    p = argparse.ArgumentParser(description="Pasargad CDN production preflight (SPEC §18.6). "
                                f"Admin API key: environment variable {KEY_ENV} only.")
    p.add_argument("--controller", default=os.environ.get("PCDN_CONTROLLER_URL"),
                   help="controller base URL, e.g. https://cdn-api.example.com (env PCDN_CONTROLLER_URL)")
    p.add_argument("--ns", action="append", default=[], metavar="HOST[:PORT]",
                   help="authoritative nameserver to query (repeat for ns1, ns2)")
    p.add_argument("--zone", help="sample zone for the SOA check (default: first active site)")
    p.add_argument("--tls-host", metavar="HOST[:PORT]", help="check this certificate instead of the controller URL's")
    p.add_argument("--ca-file", help="extra CA bundle (PEM) for HTTPS/TLS checks")
    p.add_argument("--pdns-api", action="append", default=[], metavar="HOST[:PORT]|URL",
                   help="PowerDNS API endpoints that must be closed (default: each --ns host on 8081)")
    p.add_argument("--skip-pdns", action="store_true", help="skip the PowerDNS exposure check (e.g. on the controller host)")
    p.add_argument("--alert-test", action="store_true", help="send a real test alert (POST /api/v1/alerts/test)")
    p.add_argument("--heartbeat-max", type=int, default=180, metavar="S", help="max node heartbeat age (180)")
    p.add_argument("--backup-max-hours", type=float, default=26, metavar="H", help="max backup age (26)")
    p.add_argument("--tls-warn-days", type=int, default=21)
    p.add_argument("--tls-fail-days", type=int, default=7)
    p.add_argument("--timeout", type=float, default=10, help="HTTP/TLS timeout in seconds (10)")
    p.add_argument("--dns-timeout", type=float, default=3)
    p.add_argument("--pdns-timeout", type=float, default=2)
    p.add_argument("--strict", action="store_true", help="exit 1 when any check is WARN")
    p.add_argument("--json", action="store_true", help="print JSON instead of the table")
    opts = p.parse_args(argv)
    if not opts.controller:
        p.error("--controller (or PCDN_CONTROLLER_URL) is required")
    if urllib.parse.urlsplit(opts.controller).scheme not in ("http", "https"):
        p.error("--controller must be an http(s):// URL")
    return opts


def main(argv=None) -> int:
    opts = parse_args(sys.argv[1:] if argv is None else argv)
    key = os.environ.get(KEY_ENV) or None
    checks = run(opts, key)
    code = exit_code(checks, opts.strict)
    if opts.json:
        counts = {s.lower(): sum(1 for c in checks if c.status == s) for s in (OK, WARN, FAIL, SKIP)}
        text = json.dumps({"controller": opts.controller, "checked_at": datetime.now(timezone.utc).isoformat(),
                           "checks": [c.as_dict() for c in checks], "summary": counts, "exit_code": code},
                          ensure_ascii=False, indent=2)
    else:
        text = render_table(checks)
    print(redact(text, key))
    return code


if __name__ == "__main__":
    sys.exit(main())
