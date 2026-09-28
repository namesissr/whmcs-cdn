"""Leader election: exactly one scheduler runs jobs; another takes over when the leader dies."""

import os
import signal
import subprocess
import sys
import textwrap
import time

import pytest
from sqlalchemy import create_engine, text

from app import leader, scheduler

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _spawn_holder(code: str) -> subprocess.Popen:
    """Run `code` in a child process that prints READY once it holds the lock, then sleeps."""
    p = subprocess.Popen([sys.executable, "-c", textwrap.dedent(code)], cwd=ROOT, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, text=True, env={**os.environ, "SCHEDULER_ENABLED": "false"})
    line = p.stdout.readline().strip()
    if line != "READY":
        p.kill()
        raise AssertionError(f"holder did not start: {line!r} {p.stderr.read()}")
    return p


def _kill(p: subprocess.Popen):
    p.send_signal(signal.SIGKILL)
    p.wait(10)


class Counter:
    def __init__(self):
        self.runs = 0

    def __call__(self):
        self.runs += 1


def _schedulers(make, monkeypatch):
    monkeypatch.setattr(scheduler, "record_run", lambda: None)
    a, b = Counter(), Counter()
    return (scheduler.Scheduler(elector=make(), interval=0.01, work=a), a,
            scheduler.Scheduler(elector=make(), interval=0.01, work=b), b)


# ------------------------------------------------------------------ SQLite: file lock

def test_file_lock_one_leader_and_takeover(tmp_path, monkeypatch):
    path = str(tmp_path / "cdn.db.scheduler.lock")
    s1, c1, s2, c2 = _schedulers(lambda: leader.FileLeader(path), monkeypatch)
    for _ in range(3):
        s1.tick()
        s2.tick()
    assert (c1.runs, c2.runs) == (3, 0) and s1.is_leader and not s2.is_leader
    s1.release()  # graceful shutdown hands over on the follower's next tick
    assert s2.tick() and c2.runs == 1
    assert not s1.tick()


def test_file_lock_taken_over_when_the_leader_process_is_killed(tmp_path):
    path = str(tmp_path / "cdn.db.scheduler.lock")
    holder = _spawn_holder(f"""
        import time
        from app.leader import FileLeader
        e = FileLeader({path!r})
        assert e.check()
        print("READY", flush=True)
        time.sleep(60)
    """)
    try:
        follower = leader.FileLeader(path)
        assert follower.check() is False
    finally:
        _kill(holder)
    assert follower.check() is True  # next tick after the kill
    follower.release()


def test_make_elector_kinds(tmp_path):
    assert isinstance(leader.make_elector(f"sqlite:///{tmp_path}/x.db"), leader.FileLeader)
    assert isinstance(leader.make_elector("sqlite://"), leader.AlwaysLeader)
    assert isinstance(leader.make_elector("postgresql+psycopg://u:p@h/db"), leader.PgLeader)


def test_scheduler_thread_releases_on_stop(tmp_path, monkeypatch):
    path = str(tmp_path / "l.lock")
    monkeypatch.setattr(scheduler, "record_run", lambda: None)
    c = Counter()
    s = scheduler.Scheduler(elector=leader.FileLeader(path), interval=0.01, work=c)
    s.start()
    deadline = time.time() + 5
    while c.runs == 0 and time.time() < deadline:
        time.sleep(0.01)
    s.stop()
    assert c.runs > 0 and not s.is_alive()
    assert leader.FileLeader(path).check()  # lock released


def test_record_run_is_visible_in_deep_health(client, monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "scheduler_enabled", True)
    s = scheduler.Scheduler(elector=leader.AlwaysLeader(), work=lambda: None)
    monkeypatch.setattr(scheduler, "current", s)
    monkeypatch.setattr(s, "is_alive", lambda: True)
    assert s.tick()
    body = client.get("/healthz/deep").json()
    assert body["scheduler"]["role"] == "leader"
    assert body["scheduler"]["last_run_age_seconds"] <= 5
    assert body["scheduler"]["leader"] == leader.instance_id()


# ------------------------------------------------------------------ PostgreSQL: advisory lock

def test_pg_exactly_one_leader_and_graceful_handover(pg_url, monkeypatch):
    s1, c1, s2, c2 = _schedulers(lambda: leader.PgLeader(pg_url), monkeypatch)
    try:
        for _ in range(3):
            s1.tick()
            s2.tick()
        assert (c1.runs, c2.runs) == (3, 0)
        s1.release()
        assert s2.tick() and c2.runs == 1
        assert not s1.tick()
    finally:
        s1.release()
        s2.release()


def test_pg_leader_connection_killed(pg_url):
    a, b = leader.PgLeader(pg_url), leader.PgLeader(pg_url)
    try:
        assert a.check() and not b.check()
        pid = a.conn.execute(text("SELECT pg_backend_pid()")).scalar()
        admin = create_engine(pg_url, isolation_level="AUTOCOMMIT")
        with admin.connect() as c:
            c.execute(text("SELECT pg_terminate_backend(:p)"), {"p": pid})
        admin.dispose()
        assert b.check()           # the follower takes over on its next tick
        assert a.check() is False  # the old leader notices it lost the lock
        assert a.is_leader is False and b.is_leader is True
    finally:
        a.release()
        b.release()


def test_pg_leader_process_killed(pg_url):
    holder = _spawn_holder(f"""
        import time
        from app.leader import PgLeader
        e = PgLeader({pg_url!r})
        assert e.check()
        print("READY", flush=True)
        time.sleep(60)
    """)
    follower = leader.PgLeader(pg_url)
    try:
        assert follower.check() is False
        _kill(holder)
        deadline = time.time() + 5  # PostgreSQL notices the closed socket almost immediately
        while not follower.check() and time.time() < deadline:
            time.sleep(0.1)
        assert follower.is_leader
    finally:
        if holder.poll() is None:
            _kill(holder)
        follower.release()


def test_pg_migrations_serialized_between_instances(pg_url):
    """Two controllers starting at once: both call upgrade, one migrates, the other waits."""
    import threading

    from app import migrate

    engines = [create_engine(pg_url), create_engine(pg_url)]
    errors, revs = [], []

    def run(e):
        try:
            revs.append(migrate.upgrade(e))
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=run, args=(e,)) for e in engines]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    for e in engines:
        e.dispose()
    assert errors == [] and revs == [migrate.head_revision()] * 2


@pytest.mark.parametrize("n", [3])
def test_pg_many_contenders(pg_url, n):
    electors = [leader.PgLeader(pg_url) for _ in range(n)]
    try:
        results = [e.check() for e in electors]
        assert results.count(True) == 1
        assert sum(e.check() for e in electors) == 1  # stable on the next tick
    finally:
        for e in electors:
            e.release()
