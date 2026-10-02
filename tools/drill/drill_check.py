#!/usr/bin/env python3
"""Disaster-recovery drill helper (used by tools/drill/dr-drill.sh; see docs/DISASTER_RECOVERY.md).

Runs inside the controller image (the `app` package must be importable: /srv in the container, or
controller/ of this repository) EXCEPT `report`, which needs only the standard library.

    drill_check.py fetch    --source latest|FILE|s3:KEY [--backup-dir DIR] --out DIR
        copy / download the backup to restore into DIR; prints the file name
    drill_check.py expected --archive FILE [--passphrase P] --out expected.json
        decrypt the archive and read the EXPECTED state from the dump inside it (site domains,
        record counts, edge token hashes, DNSSEC sites, schema revision) - independent of the restore
    drill_check.py check    --expected expected.json [--pdns-db F] [--acme DIR] [--controller URL]
                            [--pdns-api URL --pdns-key K] [--dns-server HOST] [--sample-zone Z]
                            [--edge-tokens-file F] --out checks.json
        verify the RESTORED stack (DATABASE_URL = the drill database) against expected.json
    drill_check.py report   --phases phases.tsv --checks checks.json [--expected expected.json] --out DIR
        write report.md + report.json (pass/fail, per-phase timings, RTO); exit 1 on failure

Every check yields {"name", "status": pass|fail|warn|skip, "detail", "seconds"}. Nothing here ever
writes to a production system: the only writes are the edge config polls (last_seen_at) into the
drill database.
"""

import argparse
import datetime as dt
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))


def _app_path():
    """Make `app` importable: PCDN_APP_DIR, the image's /srv, or this repository's controller/."""
    for d in (os.environ.get("PCDN_APP_DIR"), "/srv", os.path.join(HERE, "..", "..", "controller")):
        if d and os.path.exists(os.path.join(d, "app", "__init__.py")):
            d = os.path.abspath(d)
            if d not in sys.path:
                sys.path.insert(0, d)
            return d
    raise SystemExit("drill_check: cannot find the controller `app` package (set PCDN_APP_DIR)")


# ------------------------------------------------------------------ results

def _result(name, status, detail="", seconds=0.0, **extra):
    return {"name": name, "status": status, "detail": detail, "seconds": round(seconds, 3), **extra}


def _run_check(results, name, fn):
    """fn() -> (status, detail[, extra dict]); exceptions are a FAIL with the error."""
    t0 = time.monotonic()
    try:
        out = fn()
        status, detail = out[0], out[1]
        extra = out[2] if len(out) > 2 else {}
    except Exception as e:  # noqa: BLE001 - a drill reports every failure instead of stopping
        status, detail, extra = "fail", f"{type(e).__name__}: {e}"[:600], {}
    results.append(_result(name, status, detail, time.monotonic() - t0, **extra))
    return results[-1]


# ------------------------------------------------------------------ fetch

def fetch(source: str, backup_dir: str | None, out_dir: str) -> str:
    _app_path()
    from app import backup
    from app.config import settings

    os.makedirs(out_dir, exist_ok=True)
    if source == "latest":
        names = backup.list_local(backup_dir) if backup_dir else []
        if names:
            src = os.path.join(backup_dir, names[-1])
        else:
            s3 = backup.S3Client.from_settings()
            if s3 is None:
                raise SystemExit("no local backup found and BACKUP_S3_* is not configured")
            prefix = settings.backup_s3_prefix
            keys = sorted(o["key"] for o in s3.list(prefix) if backup.NAME_RE.match(o["key"][len(prefix):]))
            if not keys:
                raise SystemExit("no backups found locally or in object storage")
            dst = os.path.join(out_dir, os.path.basename(keys[-1]))
            s3.download(keys[-1], dst)
            return os.path.basename(dst)
    elif source.startswith("s3:"):
        s3 = backup.S3Client.from_settings()
        if s3 is None:
            raise SystemExit("BACKUP_S3_* is not configured")
        dst = os.path.join(out_dir, os.path.basename(source[3:]))
        s3.download(source[3:], dst)
        return os.path.basename(dst)
    else:
        src = source if os.path.isabs(source) or not backup_dir else os.path.join(backup_dir, source)
    if not os.path.isfile(src):
        raise SystemExit(f"backup not found: {src}")
    dst = os.path.join(out_dir, os.path.basename(src))
    shutil.copy2(src, dst)  # the original stays untouched (read-only mount)
    return os.path.basename(dst)


# ------------------------------------------------------------------ expected state from the dump

def _copy_unescape(v: str):
    if v == "\\N":
        return None
    if "\\" not in v:
        return v
    out, i = [], 0
    table = {"t": "\t", "n": "\n", "r": "\r", "\\": "\\", "b": "\b", "f": "\f", "v": "\v"}
    while i < len(v):
        ch = v[i]
        if ch == "\\" and i + 1 < len(v):
            out.append(table.get(v[i + 1], v[i + 1]))
            i += 2
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def _pg_tables(dump: str, tables: list[str]) -> dict[str, list[dict]]:
    """Rows of `tables` from a pg_dump -Fc file, through `pg_restore --data-only -f -` (COPY text)."""
    cmd = ["pg_restore", "--data-only", "--file", "-"]
    for t in tables:
        cmd += ["--table", t]
    p = subprocess.run(cmd + [dump], capture_output=True, text=True, timeout=1800)
    if p.returncode != 0:
        raise RuntimeError(f"pg_restore failed: {p.stderr.strip()[-500:]}")
    out: dict[str, list[dict]] = {t: [] for t in tables}
    cur, cols = None, []
    for line in p.stdout.splitlines():
        if cur is None:
            if line.startswith("COPY "):
                head = line[5:]
                name = head.split(" ", 1)[0].split(".")[-1].strip('"')
                cols = [c.strip().strip('"') for c in head[head.index("(") + 1:head.rindex(")")].split(",")]
                cur = name if name in out else None
                if cur is None:
                    cur = "__skip__"
            continue
        if line == "\\.":
            cur = None
            continue
        if cur != "__skip__":
            out[cur].append(dict(zip(cols, (_copy_unescape(v) for v in line.split("\t")))))
    return out


def _sqlite_tables(path: str, tables: list[str]) -> dict[str, list[dict]]:
    import sqlite3

    c = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    c.row_factory = sqlite3.Row
    try:
        have = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        return {t: [dict(r) for r in c.execute(f'SELECT * FROM "{t}"')] if t in have else [] for t in tables}
    finally:
        c.close()


def _truthy(v) -> bool:
    return v in (True, 1, "1", "t", "true", "True")


def expected_from_archive(archive: str, passphrase: str | None, workdir: str | None = None) -> dict:
    """What the restored database must contain, read from the dump in the archive itself."""
    _app_path()
    from app import backup

    own_tmp = workdir is None
    workdir = workdir or tempfile.mkdtemp(prefix="pcdn-drill-")
    os.makedirs(workdir, exist_ok=True)
    try:
        out, manifest = backup.open_archive(archive, passphrase, workdir)
        contents = manifest.get("contents", {})
        ctl = contents.get("controller")
        if not ctl:
            raise RuntimeError("backup has no controller database")
        dump = os.path.join(out, ctl["file"])
        tables = ["alembic_version", "sites", "records", "edges"]
        rows = _pg_tables(dump, tables) if ctl["kind"] == "postgresql" else _sqlite_tables(dump, tables)
        sites = {str(r["id"]): r for r in rows["sites"]}
        per_domain: dict[str, int] = {}
        for r in rows["records"]:
            dom = sites.get(str(r["site_id"]), {}).get("domain", "?")
            per_domain[dom] = per_domain.get(dom, 0) + 1
        return {
            "archive": os.path.basename(archive),
            "archive_bytes": os.path.getsize(archive),
            "created_at": manifest.get("created_at"),
            "manifest_revision": manifest.get("alembic_revision"),
            "revision": (rows["alembic_version"][0]["version_num"] if rows["alembic_version"] else None),
            "kind": ctl["kind"],
            "has_pdns": "pdns" in contents,
            "has_acme": "acme" in contents,
            "warnings": manifest.get("warnings", []),
            "sites": {"count": len(sites), "domains": sorted(s["domain"] for s in sites.values())},
            "records": {"count": len(rows["records"]), "per_domain": per_domain},
            "edges": {"count": len(rows["edges"]),
                      "tokens": sorted([e["name"], e["token_hash"]] for e in rows["edges"]),
                      "enabled": sorted(e["name"] for e in rows["edges"] if _truthy(e.get("enabled")))},
            "dnssec_domains": sorted(s["domain"] for s in sites.values() if _truthy(s.get("dnssec_enabled"))),
            "active_domains": sorted(s["domain"] for s in sites.values()
                                     if s.get("status") == "active" and not _truthy(s.get("suspended"))),
        }
    finally:
        if own_tmp:
            shutil.rmtree(workdir, ignore_errors=True)


# ------------------------------------------------------------------ checks of the restored database

def _pdns_zones(pdns_db: str) -> tuple[set[str], dict[str, int]]:
    """(zone names, active DNSSEC key count per zone) of a PowerDNS gsqlite3 database."""
    import sqlite3

    c = sqlite3.connect(f"file:{pdns_db}?mode=ro", uri=True)
    try:
        zones = {r[0].rstrip(".").lower() for r in c.execute("SELECT name FROM domains")}
        keys: dict[str, int] = {}
        for name, n in c.execute("SELECT d.name, count(k.id) FROM domains d JOIN cryptokeys k ON k.domain_id = d.id "
                                 "WHERE k.active = 1 OR k.active IS NULL GROUP BY d.name"):
            keys[name.rstrip(".").lower()] = n
        return zones, keys
    finally:
        c.close()


def run_db_checks(engine, expected: dict, pdns_db: str | None = None, acme_dir: str | None = None) -> list[dict]:
    _app_path()
    from sqlalchemy import select
    from sqlalchemy.orm import Session

    from app import crypto, migrate, services
    from app.models import Edge, Record, Site

    results: list[dict] = []

    def head():
        cur, h = migrate.current_revision(engine), migrate.head_revision()
        detail = f"database at {cur}, head {h}; backup was taken at {expected.get('revision')}"
        return ("pass" if cur == h else "fail"), detail

    _run_check(results, "migrations_at_head", head)

    with Session(engine) as db:
        def sites_match():
            got = sorted(db.scalars(select(Site.domain)))
            want = expected["sites"]["domains"]
            if got == want:
                return "pass", f"{len(got)} sites"
            missing, extra = sorted(set(want) - set(got)), sorted(set(got) - set(want))
            return "fail", f"restored {len(got)} sites, backup has {len(want)}; missing {missing[:10]} extra {extra[:10]}"

        def records_match():
            per: dict[str, int] = {}
            for dom, in db.execute(select(Site.domain).join(Record, Record.site_id == Site.id)):
                per[dom] = per.get(dom, 0) + 1
            want = expected["records"]["per_domain"]
            total = sum(per.values())
            if per == want and total == expected["records"]["count"]:
                return "pass", f"{total} records in {len(per)} zones"
            diff = sorted(d for d in set(per) | set(want) if per.get(d) != want.get(d))
            return "fail", f"restored {total} records, backup has {expected['records']['count']}; differing: " + \
                ", ".join(f"{d} ({per.get(d, 0)} vs {want.get(d, 0)})" for d in diff[:10])

        def tokens_match():
            got = sorted([e.name, e.token_hash] for e in db.scalars(select(Edge)))
            want = expected["edges"]["tokens"]
            if got == want:
                return "pass", f"{len(got)} edges; every existing edge token authenticates unchanged"
            return "fail", f"edge token hashes differ ({len(got)} restored vs {len(want)} in the backup)"

        def secrets():
            st = crypto.status(db)
            if not st["readable"]:
                return "fail", f"stored secrets cannot be decrypted: {st['error']} (wrong DATA_ENCRYPTION_KEY?)"
            bad = []
            for s in db.scalars(select(Site)):
                try:
                    _ = s.secret, s.ssl_key, s.origin_client_key
                except crypto.CryptoError:
                    bad.append(s.domain)
            if bad:
                return "fail", f"undecryptable secrets of {bad[:10]}"
            status = "pass" if st["key_configured"] or not st["encrypted"] else "fail"
            return status, f"{st['encrypted']} encrypted, {st['plaintext']} plaintext, key configured={st['key_configured']}"

        def edge_config():
            edges = list(db.scalars(select(Edge).where(Edge.enabled.is_(True))))
            if not edges:
                return "warn", "no enabled edge in the backup"
            sizes = []
            for e in edges:
                cfg = services.build_edge_config(db, e)
                sizes.append(len(cfg["sites"]))
            db.rollback()
            return "pass", f"config built for {len(edges)} edges ({max(sizes)} sites served)"

        _run_check(results, "sites_match", sites_match)
        _run_check(results, "records_match", records_match)
        _run_check(results, "edge_tokens_match", tokens_match)
        _run_check(results, "secrets_readable", secrets)
        _run_check(results, "edge_config_builds", edge_config)

    def zones():
        if not pdns_db:
            return "skip", "no PowerDNS database given"
        if not os.path.exists(pdns_db):
            return "fail", f"{pdns_db} missing (backup has pdns: {expected.get('has_pdns')})"
        have, _ = _pdns_zones(pdns_db)
        missing = sorted(set(expected["sites"]["domains"]) - have)
        if missing:
            return "fail", f"{len(missing)} zones missing in PowerDNS: {missing[:10]} (run: manage dns-sync)"
        return "pass", f"{len(expected['sites']['domains'])} zones present ({len(have)} in PowerDNS)"

    def dnssec():
        want = expected.get("dnssec_domains", [])
        if not pdns_db or not os.path.exists(pdns_db):
            return "skip", "no PowerDNS database given"
        if not want:
            return "pass", "no DNSSEC-signed zone in the backup"
        _, keys = _pdns_zones(pdns_db)
        missing = [d for d in want if not keys.get(d)]
        if missing:
            return "fail", f"DNSSEC keys missing for {missing[:10]}: the DS at the registrar would break"
        return "pass", f"active keys for all {len(want)} signed zones"

    def acme():
        if acme_dir is None:
            return "skip", "no acme home given"
        if not expected.get("has_acme"):
            return "warn", "the backup contains no acme.sh home"
        ok = os.path.isfile(os.path.join(acme_dir, "account.conf")) or os.path.isdir(os.path.join(acme_dir, "ca"))
        return ("pass", f"acme.sh home restored at {acme_dir}") if ok else ("fail", f"{acme_dir} has no acme account")

    _run_check(results, "pdns_zones_present", zones)
    _run_check(results, "dnssec_keys_present", dnssec)
    _run_check(results, "acme_present", acme)
    return results


# ------------------------------------------------------------------ checks of the running stack

def run_live_checks(expected: dict, controller: str | None, pdns_api: str | None, pdns_key: str | None,
                    dns_server: str | None, sample_zone: str | None, edge_tokens: list[str]) -> list[dict]:
    import httpx

    results: list[dict] = []
    http = httpx.Client(timeout=15, trust_env=False)

    def health():
        if not controller:
            return "skip", "no controller URL"
        r = http.get(controller.rstrip("/") + "/healthz")
        return ("pass" if r.status_code == 200 else "fail"), f"GET /healthz -> {r.status_code}"

    def edge_http():
        if not controller:
            return "skip", "no controller URL"
        r = http.get(controller.rstrip("/") + "/edge/v1/config", headers={"Authorization": "Bearer edge_drill_invalid"})
        if r.status_code != 401:
            return "fail", f"an unknown token got HTTP {r.status_code} (expected 401)"
        if not edge_tokens:
            return "warn", ("no edge token given (--edge-token): tokens are stored hashed only; the hashes "
                            "match the backup (edge_tokens_match) and the config builds (edge_config_builds)")
        bad, n = [], 0
        for tok in edge_tokens:
            r = http.get(controller.rstrip("/") + "/edge/v1/config", headers={"Authorization": f"Bearer {tok}"})
            if r.status_code != 200:
                bad.append(f"token …{tok[-4:]}: HTTP {r.status_code}")
            else:
                n = max(n, len(r.json().get("sites", [])))
        if bad:
            return "fail", "; ".join(bad)
        return "pass", f"{len(edge_tokens)} existing edge token(s) fetched their config ({n} sites)"

    def pdns_up():
        if not pdns_api:
            return "skip", "no PowerDNS API URL"
        r = http.get(pdns_api.rstrip("/") + "/api/v1/servers/localhost", headers={"X-API-Key": pdns_key or ""})
        return ("pass" if r.status_code == 200 else "fail"), f"PowerDNS API -> {r.status_code}"

    def pdns_dnssec():
        if not pdns_api:
            return "skip", "no PowerDNS API URL"
        want = expected.get("dnssec_domains", [])
        missing = []
        for d in want:
            r = http.get(f"{pdns_api.rstrip('/')}/api/v1/servers/localhost/zones/{d}./cryptokeys",
                         headers={"X-API-Key": pdns_key or ""})
            if r.status_code != 200 or not [k for k in r.json() if k.get("active")]:
                missing.append(d)
        if missing:
            return "fail", f"PowerDNS serves no active key for {missing[:10]}"
        return "pass", f"PowerDNS loaded the keys of {len(want)} signed zone(s)"

    def zone_answers():
        if not dns_server:
            return "skip", "no DNS server"
        import socket

        import dns.flags
        import dns.message
        import dns.query
        import dns.rcode
        import dns.rdatatype

        zone = sample_zone or next(iter(expected.get("active_domains") or expected["sites"]["domains"]), None)
        if not zone:
            return "skip", "the backup has no site"
        ip = socket.gethostbyname(dns_server)
        q = dns.message.make_query(zone + ".", "SOA")
        a = dns.query.udp(q, ip, timeout=5)
        if a.rcode() != dns.rcode.NOERROR or not a.answer or not (a.flags & dns.flags.AA):
            return "fail", f"{zone} SOA @{dns_server}: rcode {dns.rcode.to_text(a.rcode())}, {len(a.answer)} answers"
        detail = f"{zone} SOA answered authoritatively by {dns_server}"
        if zone in expected.get("dnssec_domains", []):
            q = dns.message.make_query(zone + ".", "DNSKEY", want_dnssec=True)
            a = dns.query.tcp(q, ip, timeout=5)
            types = {dns.rdatatype.to_text(rr.rdtype) for rr in a.answer}
            if "DNSKEY" not in types or "RRSIG" not in types:
                return "fail", f"{zone} is DNSSEC-signed but DNSKEY/RRSIG are not served ({sorted(types)})"
            detail += "; DNSKEY + RRSIG served"
        return "pass", detail, {"zone": zone}

    _run_check(results, "controller_healthy", health)
    _run_check(results, "edges_fetch_config", edge_http)
    _run_check(results, "pdns_api_up", pdns_up)
    _run_check(results, "pdns_dnssec_keys_loaded", pdns_dnssec)
    _run_check(results, "sample_zone_answers", zone_answers)
    http.close()
    return results


# ------------------------------------------------------------------ report

def _fmt_s(s: float) -> str:
    s = float(s)
    return f"{int(s // 60)}m{s % 60:04.1f}s" if s >= 60 else f"{s:.1f}s"


def build_report(phases: list[dict], checks: list[dict], expected: dict | None) -> dict:
    failed = [c for c in checks if c["status"] == "fail"]
    failed_phases = [p for p in phases if p.get("status") != "ok"]
    by = {p["name"]: p for p in phases}
    total = sum(p["seconds"] for p in phases)
    # RTO: from the start of the restore work (fetch included: a real recovery downloads too) until
    # the restored controller answers healthy; the verification afterwards is not part of the RTO
    rto_phases = [p for p in phases if p.get("rto", True)]
    return {
        "result": "PASS" if not failed and not failed_phases and phases else "FAIL",
        "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "rto_seconds": round(sum(p["seconds"] for p in rto_phases), 1),
        "total_seconds": round(total, 1),
        "rpo": {"backup_created_at": (expected or {}).get("created_at"),
                "backup_age_hours": _age_hours((expected or {}).get("created_at"))},
        "backup": {k: (expected or {}).get(k) for k in ("archive", "archive_bytes", "kind", "revision",
                                                         "has_pdns", "has_acme", "warnings")},
        "phases": phases,
        "checks": checks,
        "failed_checks": [c["name"] for c in failed],
        "failed_phases": [p["name"] for p in failed_phases],
        "verify_seconds": by.get("verify", {}).get("seconds"),
    }


def _age_hours(created):
    if not created:
        return None
    try:
        t = dt.datetime.fromisoformat(created)
    except ValueError:
        return None
    if t.tzinfo is None:
        t = t.replace(tzinfo=dt.timezone.utc)
    return round((dt.datetime.now(dt.timezone.utc) - t).total_seconds() / 3600, 1)


def render_markdown(rep: dict) -> str:
    icon = {"pass": "PASS", "fail": "FAIL", "warn": "WARN", "skip": "skip", "ok": "ok"}
    lines = [f"# DR drill: {rep['result']}", "",
             f"- finished: {rep['finished_at']}",
             f"- RTO (fetch -> controller healthy): **{_fmt_s(rep['rto_seconds'])}**",
             f"- total incl. verification: {_fmt_s(rep['total_seconds'])}",
             f"- backup: `{rep['backup'].get('archive')}` ({rep['backup'].get('kind')}, revision "
             f"{rep['backup'].get('revision')}), created {rep['rpo']['backup_created_at']} "
             f"(age {rep['rpo']['backup_age_hours']} h = RPO if the disaster were now)", "",
             "## Phases", "", "| phase | status | time |", "|---|---|---|"]
    for p in rep["phases"]:
        lines.append(f"| {p['name']} | {icon.get(p.get('status'), p.get('status'))} | {_fmt_s(p['seconds'])} |")
    lines += ["", "## Checks", "", "| check | result | time | detail |", "|---|---|---|---|"]
    for c in rep["checks"]:
        detail = str(c.get("detail", "")).replace("|", "\\|").replace("\n", " ")
        lines.append(f"| {c['name']} | {icon.get(c['status'], c['status'])} | {_fmt_s(c['seconds'])} | {detail} |")
    if rep["failed_checks"] or rep["failed_phases"]:
        lines += ["", f"**Failed:** {', '.join(rep['failed_phases'] + rep['failed_checks'])}"]
    return "\n".join(lines) + "\n"


def read_phases(path: str) -> list[dict]:
    """phases.tsv lines: name<TAB>status<TAB>seconds[<TAB>rto(1|0)]"""
    out = []
    if not os.path.exists(path):
        return out
    with open(path) as f:
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 3 or not parts[0]:
                continue
            out.append({"name": parts[0], "status": parts[1], "seconds": float(parts[2]),
                        "rto": (parts[3] != "0") if len(parts) > 3 else True})
    return out


# ------------------------------------------------------------------ CLI

def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("fetch")
    s.add_argument("--source", default="latest")
    s.add_argument("--backup-dir")
    s.add_argument("--out", required=True)
    s = sub.add_parser("expected")
    s.add_argument("--archive", required=True)
    s.add_argument("--passphrase", default=None, help="default BACKUP_PASSPHRASE")
    s.add_argument("--out", required=True)
    s = sub.add_parser("check")
    s.add_argument("--expected", required=True)
    s.add_argument("--pdns-db")
    s.add_argument("--acme")
    s.add_argument("--controller")
    s.add_argument("--pdns-api")
    s.add_argument("--pdns-key", default=os.environ.get("PDNS_API_KEY"))
    s.add_argument("--dns-server")
    s.add_argument("--sample-zone")
    s.add_argument("--edge-tokens-file")
    s.add_argument("--out", required=True)
    s = sub.add_parser("report")
    s.add_argument("--phases", required=True)
    s.add_argument("--checks", required=True)
    s.add_argument("--expected")
    s.add_argument("--out", required=True)
    a = p.parse_args(argv)

    if a.cmd == "fetch":
        print(fetch(a.source, a.backup_dir, a.out))
        return 0
    if a.cmd == "expected":
        _app_path()
        from app.config import settings

        exp = expected_from_archive(a.archive, a.passphrase if a.passphrase is not None else settings.backup_passphrase)
        with open(a.out, "w") as f:
            json.dump(exp, f, indent=2, ensure_ascii=False)
        print(f"backup {exp['archive']}: revision {exp['revision']}, {exp['sites']['count']} sites, "
              f"{exp['records']['count']} records, {exp['edges']['count']} edges, "
              f"{len(exp['dnssec_domains'])} DNSSEC zones")
        return 0
    if a.cmd == "check":
        _app_path()
        from app.db import engine

        with open(a.expected) as f:
            exp = json.load(f)
        tokens = []
        if a.edge_tokens_file and os.path.exists(a.edge_tokens_file):
            with open(a.edge_tokens_file) as f:
                tokens = [t.strip() for t in f if t.strip() and not t.startswith("#")]
        results = run_db_checks(engine, exp, a.pdns_db, a.acme)
        results += run_live_checks(exp, a.controller, a.pdns_api, a.pdns_key, a.dns_server, a.sample_zone, tokens)
        with open(a.out, "w") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        for r in results:
            print(f"  [{r['status'].upper():4}] {r['name']}: {r['detail']}")
        return 1 if any(r["status"] == "fail" for r in results) else 0
    if a.cmd == "report":
        checks = []
        if os.path.exists(a.checks):
            with open(a.checks) as f:
                checks = json.load(f)
        else:
            checks = [_result("verification", "fail", "no check results (verification did not run)")]
        exp = None
        if a.expected and os.path.exists(a.expected):
            with open(a.expected) as f:
                exp = json.load(f)
        rep = build_report(read_phases(a.phases), checks, exp)
        os.makedirs(a.out, exist_ok=True)
        with open(os.path.join(a.out, "report.json"), "w") as f:
            json.dump(rep, f, indent=2, ensure_ascii=False)
        md = render_markdown(rep)
        with open(os.path.join(a.out, "report.md"), "w") as f:
            f.write(md)
        print(md)
        return 0 if rep["result"] == "PASS" else 1
    return 2


if __name__ == "__main__":
    sys.exit(main())
