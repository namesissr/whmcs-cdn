"""Controller management commands.

    python -m app.manage migrate [--revision head]    apply database migrations
    python -m app.manage current | heads | history    show migration state
    python -m app.manage stamp <revision>             mark the DB as being at <revision> (no SQL run)
    python -m app.manage downgrade <revision>         undo migrations (careful)
    python -m app.manage makemigration -m "message"   new migration from model changes (developers)

    python -m app.manage backup [--no-upload]         write a backup now (BACKUP_DIR, S3)
    python -m app.manage backups                      list local and remote backups
    python -m app.manage restore <file|s3:KEY> --yes [--passphrase P] [--no-controller]
                                  [--pdns [PATH]] [--acme [PATH]] [--extract DIR]

    python -m app.manage gen-key                      print a new DATA_ENCRYPTION_KEY
    python -m app.manage encryption-status            plaintext / encrypted secret counts
    python -m app.manage encrypt-secrets              encrypt plaintext secrets with the current key
    python -m app.manage rotate-key                   re-encrypt everything with the first key
    python -m app.manage drop-unreadable-secrets --yes  (key lost) forget undecryptable keys/secrets

    python -m app.manage dns-sync                     rewrite every zone on every PowerDNS server

    python -m app.manage alerts-test                  send a test alert on every channel
    python -m app.manage health                       print /healthz/deep for this process

See docs/OPERATIONS.md for the runbooks.
"""

import argparse
import getpass
import json
import logging
import os
import sys
import tempfile


def _engine():
    from .db import engine

    return engine


def cmd_migrate(a):
    from . import migrate

    rev = migrate.upgrade(_engine(), a.revision)
    print(f"database at revision {rev}")


def cmd_current(a):
    from . import migrate

    cur, head = migrate.current_revision(_engine()), migrate.head_revision()
    print(f"current: {cur or '(none)'}  head: {head}" + ("" if cur == head else "  -> run: python -m app.manage migrate"))


def cmd_heads(a):
    from alembic import command

    from . import migrate

    command.heads(migrate.alembic_config(), verbose=True)


def cmd_history(a):
    from alembic import command

    from . import migrate

    command.history(migrate.alembic_config(), verbose=a.verbose)


def cmd_stamp(a):
    from . import migrate

    migrate.stamp(_engine(), a.revision)
    print(f"stamped {a.revision}")


def cmd_downgrade(a):
    from . import migrate

    if not a.yes:
        sys.exit("downgrade can drop data; re-run with --yes after taking a backup")
    migrate.downgrade(_engine(), a.revision)
    print(f"downgraded to {a.revision}")


def cmd_makemigration(a):
    from alembic import command

    from . import migrate

    command.revision(migrate.alembic_config(), message=a.message, autogenerate=not a.empty, rev_id=a.rev_id)


def cmd_backup(a):
    from . import backup

    res = backup.create_backup(out_dir=a.dir, upload=not a.no_upload)
    print(json.dumps(res, indent=2, ensure_ascii=False))


def cmd_backups(a):
    from . import backup
    from .config import settings

    print(f"local ({a.dir or settings.backup_dir}):")
    for n in backup.list_local(a.dir):
        p = os.path.join(a.dir or settings.backup_dir, n)
        print(f"  {n}  {os.path.getsize(p):>12} bytes")
    s3 = backup.S3Client.from_settings()
    if s3 is not None:
        print(f"remote (s3://{settings.backup_s3_bucket}/{settings.backup_s3_prefix}):")
        for o in s3.list(settings.backup_s3_prefix):
            print(f"  s3:{o['key']}  {o['size']:>12} bytes  {o['last_modified']}")


def cmd_restore(a):
    from . import backup, migrate
    from .config import settings

    if not a.yes:
        sys.exit("restore overwrites the database. Stop the other controllers (and PowerDNS when using --pdns), "
                 "take a fresh backup, then re-run with --yes")
    passphrase = a.passphrase
    if passphrase == "-":
        passphrase = getpass.getpass("backup passphrase: ")
    with tempfile.TemporaryDirectory(prefix="pcdn-dl-") as tmp:
        path = a.file
        if path.startswith("s3:"):
            s3 = backup.S3Client.from_settings()
            if s3 is None:
                sys.exit("BACKUP_S3_* is not configured")
            key = path[3:]
            path = os.path.join(tmp, os.path.basename(key))
            print(f"downloading s3:{key} ...")
            s3.download(key, path)
        res = backup.restore(
            path, passphrase=passphrase, controller=not a.no_controller,
            pdns_target=(a.pdns or settings.backup_pdns_db) if a.pdns is not None else None,
            acme_target=(a.acme or settings.acme_home) if a.acme is not None else None,
            extract_to=a.extract,
        )
    if not a.no_controller:
        rev = migrate.upgrade(_engine())
        res["restored"].append(f"migrated to {rev}")
    print(json.dumps({"restored": res["restored"], "backup_created_at": res["manifest"].get("created_at"),
                      "warnings": res["manifest"].get("warnings", [])}, indent=2, ensure_ascii=False))
    print("next: start the controllers and re-sync DNS (see docs/OPERATIONS.md)")


def cmd_gen_key(a):
    from . import crypto

    print(crypto.generate_key())


def _db():
    from .db import SessionLocal

    return SessionLocal()


def cmd_encryption_status(a):
    from . import crypto

    with _db() as db:
        print(json.dumps(crypto.status(db), indent=2))


def cmd_encrypt_secrets(a):
    from . import crypto

    with _db() as db:
        print(f"encrypted {crypto.encrypt_existing(db)} value(s)")


def cmd_rotate_key(a):
    from . import crypto

    with _db() as db:
        print(f"re-encrypted {crypto.rotate_all(db)} value(s) with the first key of DATA_ENCRYPTION_KEY")


def cmd_dns_sync(a):
    from .services import sync_all_dns

    with _db() as db:
        errors: dict[int, str] = {}
        failed = sync_all_dns(db, errors)
        if failed == 0:
            from .models import State
            from .services import DNS_DIRTY_KEY

            row = db.get(State, DNS_DIRTY_KEY)
            if row is not None:
                db.delete(row)
                db.commit()
    print(f"zones failed: {failed}")
    for idx, err in errors.items():
        print(f"  server #{idx + 1}: {err[:300]}")
    if failed:
        sys.exit(1)


def cmd_drop_unreadable(a):
    from . import crypto

    if not a.yes:
        sys.exit("this permanently forgets private keys that cannot be decrypted; re-run with --yes")
    with _db() as db:
        domains = crypto.drop_unreadable(db)
    print(f"{len(domains)} site(s) reset: {', '.join(domains) or '-'}")


def cmd_alerts_test(a):
    from . import alerts

    if not alerts.configured_channels():
        sys.exit("no alert channel configured (TELEGRAM_* / SMTP_* + ALERT_EMAILS)")
    res = alerts.send("info", "پیام آزمایشی", "این یک پیام آزمایشی از کنترلر CDN پاسارگاد است.")
    print(json.dumps(res, indent=2, ensure_ascii=False))
    if any(v != "ok" for v in res.values()):
        sys.exit(1)


def cmd_health(a):
    from .routes_ops import deep_health

    body, code = deep_health()
    print(json.dumps(body, indent=2, ensure_ascii=False))
    sys.exit(0 if code == 200 and body.get("status") == "ok" else 1)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m app.manage", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("migrate", help="apply migrations")
    s.add_argument("--revision", default="head")
    s.set_defaults(fn=cmd_migrate)
    sub.add_parser("current", help="show current revision").set_defaults(fn=cmd_current)
    sub.add_parser("heads", help="show head revision").set_defaults(fn=cmd_heads)
    s = sub.add_parser("history", help="list migrations")
    s.add_argument("-v", "--verbose", action="store_true")
    s.set_defaults(fn=cmd_history)
    s = sub.add_parser("stamp", help="set revision without running migrations")
    s.add_argument("revision")
    s.set_defaults(fn=cmd_stamp)
    s = sub.add_parser("downgrade", help="undo migrations")
    s.add_argument("revision")
    s.add_argument("--yes", action="store_true")
    s.set_defaults(fn=cmd_downgrade)
    s = sub.add_parser("makemigration", help="create a migration file (developers)")
    s.add_argument("-m", "--message", required=True)
    s.add_argument("--rev-id", help="e.g. 0003 (default: random)")
    s.add_argument("--empty", action="store_true", help="do not autogenerate from the models")
    s.set_defaults(fn=cmd_makemigration)

    s = sub.add_parser("backup", help="create a backup now")
    s.add_argument("--dir", help="output directory (default BACKUP_DIR)")
    s.add_argument("--no-upload", action="store_true")
    s.set_defaults(fn=cmd_backup)
    s = sub.add_parser("backups", help="list backups")
    s.add_argument("--dir")
    s.set_defaults(fn=cmd_backups)
    s = sub.add_parser("restore", help="restore a backup")
    s.add_argument("file", help="archive path, or s3:<key> to download it first")
    s.add_argument("--passphrase", help="decryption passphrase ('-' to prompt; default BACKUP_PASSPHRASE)")
    s.add_argument("--no-controller", action="store_true", help="do not restore the controller database")
    s.add_argument("--pdns", nargs="?", const="", default=None, metavar="PATH",
                   help="also restore the PowerDNS sqlite DB (default path BACKUP_PDNS_DB; PowerDNS must be stopped)")
    s.add_argument("--acme", nargs="?", const="", default=None, metavar="PATH",
                   help="also restore the acme.sh home (default ACME_HOME)")
    s.add_argument("--extract", metavar="DIR", help="also copy the decrypted contents to DIR")
    s.add_argument("--yes", action="store_true", help="confirm overwriting data")
    s.set_defaults(fn=cmd_restore)

    sub.add_parser("gen-key", help="print a new Fernet key").set_defaults(fn=cmd_gen_key)
    sub.add_parser("encryption-status", help="secret encryption status").set_defaults(fn=cmd_encryption_status)
    sub.add_parser("encrypt-secrets", help="encrypt plaintext secrets").set_defaults(fn=cmd_encrypt_secrets)
    sub.add_parser("rotate-key", help="re-encrypt with the primary key").set_defaults(fn=cmd_rotate_key)
    s = sub.add_parser("drop-unreadable-secrets", help="forget secrets the current keys cannot decrypt")
    s.add_argument("--yes", action="store_true")
    s.set_defaults(fn=cmd_drop_unreadable)
    sub.add_parser("dns-sync", help="rewrite every zone in PowerDNS").set_defaults(fn=cmd_dns_sync)
    sub.add_parser("alerts-test", help="send a test alert").set_defaults(fn=cmd_alerts_test)
    sub.add_parser("health", help="deep health report").set_defaults(fn=cmd_health)
    return p


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    logging.getLogger("alembic.runtime").setLevel(logging.WARNING)
    args = build_parser().parse_args(argv)
    from .backup import BackupError
    from .crypto import CryptoError

    try:
        args.fn(args)
    except (BackupError, CryptoError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
