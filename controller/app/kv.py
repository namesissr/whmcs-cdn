"""Small helpers over the `state` key/value table (JSON documents and counters), plus a
race-free "make sure this row exists" insert shared with the minute buckets."""

import json

from sqlalchemy import BigInteger, String, cast, select, update
from sqlalchemy.orm import Session

from .models import State


def insert_ignore(db: Session, model, values: dict) -> None:
    """INSERT … ON CONFLICT DO NOTHING (PostgreSQL / SQLite): concurrent writers that both create
    the same row never fail; the loser simply finds it. Caller then locks/updates the row."""
    name = db.get_bind().dialect.name
    if name == "postgresql":
        from sqlalchemy.dialects.postgresql import insert
    elif name == "sqlite":
        from sqlalchemy.dialects.sqlite import insert
    else:  # pragma: no cover - only PostgreSQL and SQLite are supported
        pk = tuple(values[c.name] for c in model.__table__.primary_key.columns)
        if db.get(model, pk if len(pk) > 1 else pk[0]) is None:
            db.add(model(**values))
            db.flush()
        return
    db.execute(insert(model.__table__).values(**values).on_conflict_do_nothing())


def get_json(db: Session, key: str, fresh: bool = False) -> dict:
    """The JSON document at `key` ({} when missing); `fresh` re-reads a row already loaded in this
    session (sessions keep values across commits: expire_on_commit=False)."""
    row = db.get(State, key, populate_existing=True) if fresh else db.get(State, key)
    if row is None:
        return {}
    try:
        doc = json.loads(row.value or "{}")
    except ValueError:
        return {}
    return doc if isinstance(doc, dict) else {}


def lock_json(db: Session, key: str) -> dict:
    """The JSON document at `key`, row-locked (SELECT … FOR UPDATE) until the caller commits, so
    concurrent read-modify-write cycles serialize. The row is created ("{}") when missing."""
    insert_ignore(db, State, {"key": key, "value": "{}"})
    row = db.scalar(select(State).where(State.key == key).with_for_update().execution_options(
        populate_existing=True))
    try:
        doc = json.loads(row.value or "{}") if row is not None else {}
    except ValueError:
        return {}
    return doc if isinstance(doc, dict) else {}


def set_json(db: Session, key: str, doc: dict) -> None:
    value = json.dumps(doc, sort_keys=True)
    row = db.get(State, key)
    if row is None:
        db.add(State(key=key, value=value))
    else:
        row.value = value


def get_int(db: Session, key: str) -> int:
    row = db.get(State, key)
    try:
        return int(row.value) if row is not None and row.value else 0
    except ValueError:
        return 0


def incr(db: Session, key: str, n: int) -> None:
    """Atomic `value += n`: the row is created if missing (race-free), then one UPDATE adds n, so
    concurrent writers never lose increments. Caller commits."""
    if n == 0:
        return
    insert_ignore(db, State, {"key": key, "value": "0"})
    t = State.__table__
    db.execute(update(t).where(t.c.key == key).values(value=cast(cast(t.c.value, BigInteger) + n, String)))
    for obj in list(db.identity_map.values()):  # a loaded copy of the row is now stale
        if isinstance(obj, State) and obj.key == key:
            db.expire(obj)
