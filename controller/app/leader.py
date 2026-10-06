"""Leader election for the background scheduler (several controllers, one scheduler).

* PostgreSQL: session-level advisory lock (pg_try_advisory_lock) held on a dedicated
  connection for as long as this instance leads. Every tick the leader verifies that its
  connection is alive and still owns the lock (pg_locks); followers try to take the lock.
  If the leader dies or loses its connection, PostgreSQL drops the lock and another
  instance takes over on its next tick. TCP keepalives / tcp_user_timeout bound how long
  a half-open connection can keep a lock.
* SQLite: only one controller may use a SQLite file, but a second process (e.g. a manual
  `uvicorn` next to the container) must not run jobs too, so an exclusive flock() on
  "<db>.scheduler.lock" decides.
* Anything else (in-memory SQLite): always leader.
"""

import fcntl
import logging
import os
import socket

from sqlalchemy import create_engine, pool, text
from sqlalchemy.engine import make_url

from .config import settings

log = logging.getLogger("pcdn.leader")

SCHEDULER_LOCK_ID = 0x70636E00  # distinct from migrate.MIGRATION_LOCK_ID


def instance_id() -> str:
    return settings.instance_name or f"{socket.gethostname()}:{os.getpid()}"


class AlwaysLeader:
    kind = "single"

    def __init__(self):
        self.is_leader = False

    def check(self) -> bool:
        self.is_leader = True
        return True

    def release(self):
        self.is_leader = False


class FileLeader:
    """Exclusive, non-blocking flock(); the kernel releases it when the process dies."""

    kind = "file"

    def __init__(self, path: str):
        self.path = path
        self.fh = None
        self.is_leader = False

    def check(self) -> bool:
        if self.fh is not None:
            self.is_leader = True
            return True
        fh = open(self.path, "a+")
        try:
            fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            fh.close()
            self.is_leader = False
            return False
        fh.seek(0)
        fh.truncate()
        fh.write(instance_id() + "\n")
        fh.flush()
        self.fh = fh
        self.is_leader = True
        return True

    def release(self):
        if self.fh is not None:
            try:
                fcntl.flock(self.fh, fcntl.LOCK_UN)
            finally:
                self.fh.close()
                self.fh = None
        self.is_leader = False


class PgLeader:
    kind = "postgresql"

    def __init__(self, url: str, lock_id: int = SCHEDULER_LOCK_ID):
        self.lock_id = lock_id
        self.conn = None
        self.is_leader = False
        connect_args = {
            "connect_timeout": 5,
            "keepalives": 1, "keepalives_idle": 10, "keepalives_interval": 5, "keepalives_count": 3,
            "tcp_user_timeout": 20000,
            "application_name": f"pcdn-leader {instance_id()}"[:63],
        }
        self.engine = create_engine(url, poolclass=pool.NullPool, connect_args=connect_args)

    def _drop(self):
        if self.conn is not None:
            try:
                self.conn.close()
            except Exception:  # noqa: BLE001
                pass
        self.conn = None
        self.is_leader = False

    def _still_leading(self) -> bool:
        try:
            held = self.conn.execute(text(
                "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND pid = pg_backend_pid() "
                "AND granted AND classid = 0 AND objid = :k AND objsubid = 1"
            ), {"k": self.lock_id}).scalar()
            return bool(held)
        except Exception as e:  # noqa: BLE001
            log.warning("leader connection lost: %s", type(e).__name__)
            return False

    def check(self) -> bool:
        if self.conn is not None:
            if self._still_leading():
                self.is_leader = True
                return True
            log.warning("scheduler leadership lost")
            self._drop()
        try:
            conn = self.engine.connect().execution_options(isolation_level="AUTOCOMMIT")
        except Exception as e:  # noqa: BLE001
            log.warning("cannot connect for leader election: %s", type(e).__name__)
            self.is_leader = False
            return False
        try:
            got = conn.execute(text("SELECT pg_try_advisory_lock(:k)"), {"k": self.lock_id}).scalar()
        except Exception as e:  # noqa: BLE001
            log.warning("leader election query failed: %s", type(e).__name__)
            got = False
        if got:
            self.conn = conn
            self.is_leader = True
            return True
        conn.close()
        self.is_leader = False
        return False

    def release(self):
        if self.conn is not None:
            try:
                self.conn.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": self.lock_id})
            except Exception:  # noqa: BLE001
                pass
        self._drop()
        self.engine.dispose()


def make_elector(url: str | None = None):
    url = url or settings.database_url
    u = make_url(url)
    if u.get_backend_name() == "postgresql":
        return PgLeader(url)
    if u.get_backend_name() == "sqlite" and u.database and u.database != ":memory:":
        return FileLeader(os.path.abspath(u.database) + ".scheduler.lock")
    return AlwaysLeader()
