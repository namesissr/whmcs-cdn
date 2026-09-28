"""Backups of everything needed to rebuild the control plane.

One archive (pcdn-backup-YYYYmmddTHHMMSSZ.tar.gz[.enc]) contains:
  manifest.json          what is inside, schema revision, versions
  controller.pgdump      `pg_dump -Fc` of the controller database   (PostgreSQL)
  controller.sqlite3     online-backup copy of the controller DB     (SQLite)
  pdns.sqlite3           consistent copy of PowerDNS' gsqlite3 DB (zones + DNSSEC keys)
  acme/                  acme.sh home (ACME account key, issued certs)

With BACKUP_PASSPHRASE the archive is encrypted (AES-256-GCM in 1 MiB chunks, key from
scrypt(passphrase, random salt)). With BACKUP_S3_* it is uploaded to S3-compatible object
storage (ArvanCloud, MinIO, AWS...) using AWS SigV4, path-style URLs. Old archives are
rotated locally (BACKUP_KEEP) and remotely (BACKUP_S3_KEEP, default BACKUP_KEEP).

Restore: `python -m app.manage restore <file|s3:KEY> --yes [...]` (docs/OPERATIONS.md).
"""

import datetime as dt
import hashlib
import hmac
import io
import json
import logging
import os
import re
import shutil
import sqlite3
import struct
import subprocess
import tarfile
import tempfile
from urllib.parse import quote
from xml.etree import ElementTree

import httpx
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from sqlalchemy.engine import make_url

from .config import settings

log = logging.getLogger("pcdn.backup")

NAME_RE = re.compile(r"^pcdn-backup-(\d{8}T\d{6}Z)\.tar\.gz(\.enc)?$")
FORMAT_VERSION = 1


class BackupError(RuntimeError):
    pass


# ================================================================== encryption
#
# header:  b"PCDNBAK" | version(1) | salt(16) | log2(n)(1) | r(1) | p(1) | nonce_prefix(8)
# chunks:  length(4, big endian) | AES-GCM ciphertext+tag
#          nonce = nonce_prefix | counter(4);  aad = header | counter(8) | is_last(1)
# The is_last flag in the AAD makes truncation or chunk reordering detectable.

MAGIC = b"PCDNBAK"
ENC_VERSION = 1
CHUNK = 1024 * 1024
HEADER_LEN = len(MAGIC) + 1 + 16 + 3 + 8
SCRYPT_LOG2N, SCRYPT_R, SCRYPT_P = 15, 8, 1


def _derive(passphrase: str, salt: bytes, log2n: int, r: int, p: int) -> bytes:
    if not passphrase:
        raise BackupError("empty passphrase")
    return Scrypt(salt=salt, length=32, n=2 ** log2n, r=r, p=p).derive(passphrase.encode())


def is_encrypted_file(path: str) -> bool:
    with open(path, "rb") as f:
        return f.read(len(MAGIC)) == MAGIC


def encrypt_file(src: str, dst: str, passphrase: str):
    salt, prefix = os.urandom(16), os.urandom(8)
    header = MAGIC + bytes([ENC_VERSION]) + salt + bytes([SCRYPT_LOG2N, SCRYPT_R, SCRYPT_P]) + prefix
    aes = AESGCM(_derive(passphrase, salt, SCRYPT_LOG2N, SCRYPT_R, SCRYPT_P))
    with open(src, "rb") as fin, open(dst, "wb") as fout:
        fout.write(header)
        counter = 0
        chunk = fin.read(CHUNK)
        while True:
            nxt = fin.read(CHUNK)
            last = not nxt
            aad = header + struct.pack(">QB", counter, int(last))
            ct = aes.encrypt(prefix + struct.pack(">I", counter), chunk, aad)
            fout.write(struct.pack(">I", len(ct)) + ct)
            if last:
                break
            chunk, counter = nxt, counter + 1


def decrypt_file(src: str, dst: str, passphrase: str):
    with open(src, "rb") as fin:
        header = fin.read(HEADER_LEN)
        if len(header) != HEADER_LEN or not header.startswith(MAGIC):
            raise BackupError("not an encrypted Pasargad CDN backup")
        if header[len(MAGIC)] != ENC_VERSION:
            raise BackupError(f"unsupported backup encryption version {header[len(MAGIC)]}")
        off = len(MAGIC) + 1
        salt = header[off:off + 16]
        log2n, r, p = header[off + 16:off + 19]
        prefix = header[off + 19:off + 27]
        aes = AESGCM(_derive(passphrase, salt, log2n, r, p))
        with open(dst, "wb") as fout:
            counter, done = 0, False
            while True:
                raw = fin.read(4)
                if not raw:
                    break
                if done:
                    raise BackupError("unexpected data after the last chunk")
                (n,) = struct.unpack(">I", raw)
                if n > CHUNK + 16:
                    raise BackupError("corrupted backup (bad chunk length)")
                ct = fin.read(n)
                nonce = prefix + struct.pack(">I", counter)
                pt = None
                for last in (False, True):
                    try:
                        pt = aes.decrypt(nonce, ct, header + struct.pack(">QB", counter, int(last)))
                        done = last
                        break
                    except InvalidTag:
                        continue
                if pt is None:
                    if counter == 0:
                        raise BackupError("wrong passphrase or corrupted backup")
                    raise BackupError("corrupted backup (authentication failed)")
                fout.write(pt)
                counter += 1
            if not done:
                raise BackupError("backup file is truncated")


# ================================================================== S3 (SigV4, path-style)

def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


class S3Client:
    def __init__(self, endpoint: str, bucket: str, access_key: str, secret_key: str,
                 region: str = "us-east-1", transport: httpx.BaseTransport | None = None, timeout: float = 120):
        self.endpoint = endpoint.rstrip("/")
        self.bucket = bucket
        self.access_key = access_key
        self.secret_key = secret_key
        self.region = region or "us-east-1"
        self.http = httpx.Client(timeout=timeout, transport=transport)

    @classmethod
    def from_settings(cls, transport=None) -> "S3Client | None":
        s = settings
        if not (s.backup_s3_endpoint and s.backup_s3_bucket and s.backup_s3_access_key and s.backup_s3_secret_key):
            return None
        return cls(s.backup_s3_endpoint, s.backup_s3_bucket, s.backup_s3_access_key, s.backup_s3_secret_key,
                   s.backup_s3_region, transport=transport)

    def _url_and_path(self, key: str = "") -> tuple[str, str]:
        base = httpx.URL(self.endpoint)
        prefix = base.path.rstrip("/")
        path = f"{prefix}/{quote(self.bucket, safe='')}"
        if key:
            path += "/" + quote(key, safe="/-_.~")
        return f"{base.scheme}://{base.netloc.decode()}{path}", path

    def sign(self, method: str, url: str, path: str, query: dict[str, str], payload_hash: str,
             now: dt.datetime | None = None) -> dict[str, str]:
        now = now or dt.datetime.now(dt.timezone.utc)
        amz_date, day = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
        u = httpx.URL(url)
        host = u.host + (f":{u.port}" if u.port else "")
        headers = {"host": host, "x-amz-content-sha256": payload_hash, "x-amz-date": amz_date}
        signed = ";".join(sorted(headers))
        canonical_query = "&".join(
            f"{quote(k, safe='-_.~')}={quote(v, safe='-_.~')}" for k, v in sorted(query.items()))
        canonical = "\n".join([
            method, path, canonical_query,
            "".join(f"{k}:{headers[k]}\n" for k in sorted(headers)), signed, payload_hash,
        ])
        scope = f"{day}/{self.region}/s3/aws4_request"
        to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope, hashlib.sha256(canonical.encode()).hexdigest()])
        k = _hmac(("AWS4" + self.secret_key).encode(), day)
        k = _hmac(_hmac(_hmac(k, self.region), "s3"), "aws4_request")
        sig = hmac.new(k, to_sign.encode(), hashlib.sha256).hexdigest()
        out = {"x-amz-content-sha256": payload_hash, "x-amz-date": amz_date,
               "Authorization": f"AWS4-HMAC-SHA256 Credential={self.access_key}/{scope}, "
                                f"SignedHeaders={signed}, Signature={sig}"}
        return out

    def _request(self, method: str, key: str = "", query: dict | None = None, content=None,
                 payload_hash: str | None = None, stream_to: str | None = None) -> httpx.Response:
        query = query or {}
        url, path = self._url_and_path(key)
        payload_hash = payload_hash or hashlib.sha256(content if isinstance(content, bytes) else b"").hexdigest()
        headers = self.sign(method, url, path, query, payload_hash)
        if stream_to:
            with self.http.stream(method, url, params=query, headers=headers) as r:
                if r.status_code >= 300:
                    r.read()
                    raise BackupError(f"S3 {method} {key}: HTTP {r.status_code} {r.text[:300]}")
                with open(stream_to, "wb") as f:
                    for block in r.iter_bytes():
                        f.write(block)
                return r
        r = self.http.request(method, url, params=query, headers=headers, content=content)
        if r.status_code >= 300:
            raise BackupError(f"S3 {method} {key or self.bucket}: HTTP {r.status_code} {r.text[:300]}")
        return r

    def put_file(self, key: str, path: str):
        digest = _sha256_file(path)
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            url, upath = self._url_and_path(key)
            headers = self.sign("PUT", url, upath, {}, digest)
            headers["Content-Length"] = str(size)
            headers["Content-Type"] = "application/octet-stream"
            r = self.http.put(url, headers=headers, content=f)
        if r.status_code >= 300:
            raise BackupError(f"S3 PUT {key}: HTTP {r.status_code} {r.text[:300]}")

    def list(self, prefix: str = "") -> list[dict]:
        out, token = [], None
        while True:
            q = {"list-type": "2", "prefix": prefix}
            if token:
                q["continuation-token"] = token
            root = ElementTree.fromstring(self._request("GET", query=q).content)
            ns = root.tag.split("}")[0] + "}" if root.tag.startswith("{") else ""
            for c in root.findall(f"{ns}Contents"):
                out.append({"key": c.findtext(f"{ns}Key"), "size": int(c.findtext(f"{ns}Size") or 0),
                            "last_modified": c.findtext(f"{ns}LastModified")})
            if (root.findtext(f"{ns}IsTruncated") or "").lower() == "true":
                token = root.findtext(f"{ns}NextContinuationToken")
                if not token:
                    break
            else:
                break
        return out

    def delete(self, key: str):
        self._request("DELETE", key)

    def download(self, key: str, path: str):
        self._request("GET", key, stream_to=path)


# ================================================================== creating backups

def _db_kind(url: str) -> str:
    return make_url(url).get_backend_name()


def _pg_env(url: str) -> dict:
    """libpq environment for pg_dump / pg_restore, including multi-host HA URLs
    (postgresql+psycopg://u:p@/db?host=a:5432&host=b:5432&target_session_attrs=read-write)."""
    u = make_url(url)
    env = dict(os.environ)
    values = {"PGUSER": u.username, "PGPASSWORD": u.password, "PGDATABASE": u.database,
              "PGHOST": u.host, "PGPORT": u.port}
    hosts = u.query.get("host")
    if hosts:
        hosts = [hosts] if isinstance(hosts, str) else list(hosts)
        values["PGHOST"] = ",".join(h.rsplit(":", 1)[0] if ":" in h else h for h in hosts)
        values["PGPORT"] = ",".join(h.rsplit(":", 1)[1] if ":" in h else "5432" for h in hosts)
    for key, var in (("target_session_attrs", "PGTARGETSESSIONATTRS"), ("sslmode", "PGSSLMODE"),
                     ("connect_timeout", "PGCONNECT_TIMEOUT")):
        v = u.query.get(key)
        if v:
            values[var] = v if isinstance(v, str) else v[0]
    env.update({k: str(v) for k, v in values.items() if v})
    return env


def _run(cmd: list[str], env: dict, timeout: int = 3600):
    try:
        p = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        raise BackupError(f"{cmd[0]} is not installed (the controller image ships postgresql-client)") from None
    if p.returncode != 0:
        raise BackupError(f"{cmd[0]} failed: {(p.stderr or p.stdout).strip()[-800:]}")
    return p


def sqlite_copy(src: str, dst: str):
    """Consistent copy of a live SQLite database through the online-backup API.

    The source is opened read-only (the PowerDNS volume is mounted read-only). If SQLite
    cannot open it that way (a WAL database whose -shm file cannot be created on a
    read-only mount), the files are copied to a temporary directory first and the copy
    is checkpointed; PowerDNS writes rarely, and the result is verified with
    PRAGMA integrity_check either way.
    """
    try:
        source = sqlite3.connect(f"file:{src}?mode=ro", uri=True, timeout=30)
        try:
            dest = sqlite3.connect(dst)
            with dest:
                source.backup(dest)
            dest.close()
        finally:
            source.close()
    except sqlite3.Error as e:
        log.info("read-only open of %s failed (%s); copying the files first", src, e)
        with tempfile.TemporaryDirectory() as tmp:
            tmp_db = os.path.join(tmp, "copy.sqlite3")
            shutil.copy2(src, tmp_db)
            for suffix in ("-wal",):
                if os.path.exists(src + suffix):
                    shutil.copy2(src + suffix, tmp_db + suffix)
            source = sqlite3.connect(tmp_db)
            dest = sqlite3.connect(dst)
            with dest:
                source.backup(dest)
            source.close()
            dest.close()
    check = sqlite3.connect(dst)
    try:
        res = check.execute("PRAGMA integrity_check").fetchone()[0]
    finally:
        check.close()
    if res != "ok":
        raise BackupError(f"copy of {src} failed integrity_check: {res}")


def _alembic_revision() -> str | None:
    try:
        from . import migrate
        from .db import engine

        return migrate.current_revision(engine)
    except Exception:  # noqa: BLE001
        return None


def dump_controller_db(out_dir: str, url: str | None = None) -> str:
    url = url or settings.database_url
    kind = _db_kind(url)
    if kind == "postgresql":
        path = os.path.join(out_dir, "controller.pgdump")
        _run(["pg_dump", "--format=custom", "--no-owner", "--no-privileges", "--file", path], _pg_env(url))
        return path
    if kind == "sqlite":
        src = make_url(url).database
        if not src or src == ":memory:":
            raise BackupError("in-memory SQLite database cannot be backed up")
        path = os.path.join(out_dir, "controller.sqlite3")
        sqlite_copy(src, path)
        return path
    raise BackupError(f"unsupported database {kind}")


def backup_name(now: dt.datetime | None = None, encrypted: bool = False) -> str:
    now = now or dt.datetime.now(dt.timezone.utc)
    return f"pcdn-backup-{now:%Y%m%dT%H%M%SZ}.tar.gz" + (".enc" if encrypted else "")


def create_backup(out_dir: str | None = None, passphrase: str | None = None, upload: bool = True,
                  s3: S3Client | None = None, now: dt.datetime | None = None) -> dict:
    """Write one archive to out_dir (BACKUP_DIR), rotate, upload. Raises BackupError."""
    out_dir = out_dir or settings.backup_dir
    passphrase = settings.backup_passphrase if passphrase is None else passphrase
    os.makedirs(out_dir, mode=0o700, exist_ok=True)
    name = backup_name(now, encrypted=bool(passphrase))
    final = os.path.join(out_dir, name)
    warnings = []
    with tempfile.TemporaryDirectory(dir=out_dir, prefix=".tmp-") as tmp:
        stage = os.path.join(tmp, "stage")
        os.mkdir(stage)
        contents = {}
        db_file = dump_controller_db(stage)
        contents["controller"] = {"file": os.path.basename(db_file), "kind": _db_kind(settings.database_url)}

        pdns_db = settings.backup_pdns_db
        if pdns_db and os.path.exists(pdns_db):
            sqlite_copy(pdns_db, os.path.join(stage, "pdns.sqlite3"))
            contents["pdns"] = {"file": "pdns.sqlite3", "source": pdns_db}
        elif pdns_db:
            warnings.append(f"PowerDNS database {pdns_db} not found (not included)")

        acme = settings.acme_home
        if acme and os.path.isdir(acme):
            contents["acme"] = {"dir": "acme", "source": acme}
        elif acme:
            warnings.append(f"acme home {acme} not found (not included)")

        manifest = {
            "format": FORMAT_VERSION,
            "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "alembic_revision": _alembic_revision(),
            "contents": contents,
            "warnings": warnings,
        }
        tar_path = os.path.join(tmp, "backup.tar.gz")
        with tarfile.open(tar_path, "w:gz") as tar:
            data = json.dumps(manifest, indent=2).encode()
            info = tarfile.TarInfo("manifest.json")
            info.size, info.mtime, info.mode = len(data), int(dt.datetime.now().timestamp()), 0o600
            tar.addfile(info, io.BytesIO(data))
            for f in sorted(os.listdir(stage)):
                tar.add(os.path.join(stage, f), arcname=f)
            if "acme" in contents:
                tar.add(acme, arcname="acme")
        if passphrase:
            enc = os.path.join(tmp, "backup.enc")
            encrypt_file(tar_path, enc, passphrase)
            tar_path = enc
        os.chmod(tar_path, 0o600)
        os.replace(tar_path, final)
    for w in warnings:
        log.warning("backup: %s", w)
    result = {"path": final, "name": name, "size": os.path.getsize(final), "encrypted": bool(passphrase),
              "warnings": warnings, "uploaded": False, "pruned_local": prune_local(out_dir, settings.backup_keep)}
    if upload:
        s3 = s3 or S3Client.from_settings()
        if s3 is not None:
            key = settings.backup_s3_prefix + name
            s3.put_file(key, final)
            result["uploaded"] = True
            result["remote_key"] = key
            result["pruned_remote"] = prune_remote(s3, settings.backup_s3_prefix,
                                                   settings.backup_s3_keep or settings.backup_keep)
    log.info("backup written: %s (%d bytes, encrypted=%s, uploaded=%s)",
             final, result["size"], result["encrypted"], result["uploaded"])
    return result


def list_local(out_dir: str | None = None) -> list[str]:
    out_dir = out_dir or settings.backup_dir
    if not os.path.isdir(out_dir):
        return []
    return sorted(f for f in os.listdir(out_dir) if NAME_RE.match(f))


def prune_local(out_dir: str, keep: int) -> list[str]:
    if keep <= 0:
        return []
    names = list_local(out_dir)
    removed = names[:-keep] if len(names) > keep else []
    for n in removed:
        os.remove(os.path.join(out_dir, n))
    return removed


def prune_remote(s3: S3Client, prefix: str, keep: int) -> list[str]:
    if keep <= 0:
        return []
    keys = sorted(o["key"] for o in s3.list(prefix) if NAME_RE.match(o["key"][len(prefix):]))
    removed = keys[:-keep] if len(keys) > keep else []
    for k in removed:
        s3.delete(k)
    return removed


# ================================================================== restore

def _safe_extract(archive: str, dest: str):
    with tarfile.open(archive, "r:gz") as tar:
        for m in tar.getmembers():
            if m.name.startswith("/") or ".." in m.name.split("/"):
                raise BackupError(f"unsafe path in archive: {m.name}")
        tar.extractall(dest, filter="data")


def open_archive(path: str, passphrase: str | None, workdir: str) -> tuple[str, dict]:
    """Decrypt (if needed) and extract into workdir. Returns (extracted dir, manifest)."""
    tar_path = path
    if is_encrypted_file(path):
        if not passphrase:
            raise BackupError("this backup is encrypted: pass --passphrase or set BACKUP_PASSPHRASE")
        tar_path = os.path.join(workdir, "backup.tar.gz")
        decrypt_file(path, tar_path, passphrase)
    out = os.path.join(workdir, "extract")
    os.mkdir(out)
    try:
        _safe_extract(tar_path, out)
    except tarfile.TarError as e:
        raise BackupError(f"not a valid backup archive: {e}") from None
    try:
        with open(os.path.join(out, "manifest.json")) as f:
            manifest = json.load(f)
    except (OSError, ValueError):
        raise BackupError("manifest.json missing: not a Pasargad CDN backup") from None
    return out, manifest


def restore_controller_db(src: str, kind: str, url: str | None = None):
    url = url or settings.database_url
    target_kind = _db_kind(url)
    if kind != target_kind:
        raise BackupError(f"backup holds a {kind} database but DATABASE_URL is {target_kind}")
    if kind == "postgresql":
        _run(["pg_restore", "--clean", "--if-exists", "--no-owner", "--no-privileges", "--single-transaction",
              "--exit-on-error", "--dbname", make_url(url).database, src], _pg_env(url))
        return
    target = make_url(url).database
    source = sqlite3.connect(f"file:{src}?mode=ro", uri=True)
    dest = sqlite3.connect(target, timeout=30)
    try:
        with dest:
            source.backup(dest)
    finally:
        source.close()
        dest.close()


def restore_file_db(src: str, target: str):
    """Replace an SQLite file (PowerDNS must be stopped). Keeps the old file as .before-restore."""
    os.makedirs(os.path.dirname(os.path.abspath(target)), exist_ok=True)
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    if os.path.exists(target):
        shutil.copy2(target, f"{target}.before-restore-{stamp}")
    tmp = target + ".restore-tmp"
    shutil.copy2(src, tmp)
    if os.path.exists(target):  # keep the owner PowerDNS runs as (uid 953 in the official image)
        st = os.stat(target)
        try:
            os.chown(tmp, st.st_uid, st.st_gid)
            os.chmod(tmp, st.st_mode & 0o777)
        except PermissionError:
            log.warning("could not copy ownership of %s; check that PowerDNS can write it", target)
    for suffix in ("-wal", "-shm", "-journal"):  # stale WAL/SHM of the old DB would corrupt the new one
        if os.path.exists(target + suffix):
            os.remove(target + suffix)
    os.replace(tmp, target)


def restore_dir(src: str, target: str):
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    if os.path.exists(target):
        os.rename(target, f"{target.rstrip('/')}.before-restore-{stamp}")
    shutil.copytree(src, target)


def restore(path: str, passphrase: str | None = None, controller: bool = True, pdns_target: str | None = None,
            acme_target: str | None = None, extract_to: str | None = None, url: str | None = None) -> dict:
    """Restore selected parts of a backup. Callers must have confirmed (--yes)."""
    passphrase = settings.backup_passphrase if passphrase is None else passphrase
    done = []
    with tempfile.TemporaryDirectory(prefix="pcdn-restore-") as work:
        out, manifest = open_archive(path, passphrase, work)
        contents = manifest.get("contents", {})
        if extract_to:
            os.makedirs(extract_to, exist_ok=True)
            for name in os.listdir(out):
                s, d = os.path.join(out, name), os.path.join(extract_to, name)
                (shutil.copytree if os.path.isdir(s) else shutil.copy2)(s, d)
            done.append(f"extracted to {extract_to}")
        if controller:
            c = contents.get("controller")
            if not c:
                raise BackupError("backup has no controller database")
            restore_controller_db(os.path.join(out, c["file"]), c["kind"], url)
            done.append("controller database")
        if pdns_target:
            if "pdns" not in contents:
                raise BackupError("backup has no PowerDNS database")
            restore_file_db(os.path.join(out, "pdns.sqlite3"), pdns_target)
            done.append(f"PowerDNS database -> {pdns_target}")
        if acme_target:
            if "acme" not in contents:
                raise BackupError("backup has no acme.sh directory")
            restore_dir(os.path.join(out, "acme"), acme_target)
            done.append(f"acme.sh home -> {acme_target}")
    return {"manifest": manifest, "restored": done}
