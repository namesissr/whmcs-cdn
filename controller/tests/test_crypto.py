"""Encryption at rest of certificate private keys and site secrets (DATA_ENCRYPTION_KEY)."""

import logging

import pytest
from sqlalchemy import text

from app import crypto
from app.config import settings
from app.db import SessionLocal, engine
from app.main import secrets_at_rest
from tests.test_api import add_edge, edge_get
from tests.test_v2 import S, _cert, site

K1 = crypto.generate_key()
K2 = crypto.generate_key()


@pytest.fixture()
def key(monkeypatch):
    def set_key(value: str):
        monkeypatch.setattr(settings, "data_encryption_key", value)

    set_key("")
    return set_key


def raw_row(domain="example.com"):
    with engine.connect() as c:
        return c.execute(text("SELECT ssl_key, secret FROM sites WHERE domain = :d"), {"d": domain}).one()


def upload(client, tmp_path):
    cert, pem = _cert(tmp_path, "example.com")
    r = client.put(f"{S}/ssl/custom", json={"cert": cert, "key": pem})
    assert r.status_code == 200, r.text
    return pem


def test_private_key_and_secret_are_encrypted_and_edges_get_plaintext(client, tmp_path, key):
    key(K1)
    site(client)
    pem = upload(client, tmp_path)
    stored_key, stored_secret = raw_row()
    assert stored_key.startswith("enc:v1:") and "PRIVATE KEY" not in stored_key
    assert stored_secret.startswith("enc:v1:")

    token = add_edge(client)
    cfg = edge_get(client, token, "/edge/v1/config").json()["sites"][0]
    assert cfg["ssl"]["key"] == pem.strip() + "\n"
    assert len(cfg["secret"]) == 64 and not cfg["secret"].startswith("enc:")
    # the admin API never exposes either value
    body = client.get(S).text
    assert "PRIVATE KEY" not in body and cfg["secret"] not in body and "enc:v1:" not in body


def test_without_key_values_stay_plaintext_and_can_be_encrypted_later(client, tmp_path, key, caplog):
    site(client)
    pem = upload(client, tmp_path)
    stored_key, stored_secret = raw_row()
    assert stored_key.startswith("-----BEGIN") and len(stored_secret) == 64
    token = add_edge(client)
    assert edge_get(client, token, "/edge/v1/config").json()["sites"][0]["ssl"]["key"].startswith("-----BEGIN")

    with caplog.at_level(logging.WARNING, logger="pcdn"):
        secrets_at_rest()
    assert "PLAINTEXT" in caplog.text
    deep = client.get("/healthz/deep").json()
    assert deep["encryption"]["enabled"] is False
    assert any("DATA_ENCRYPTION_KEY" in w for w in deep["warnings"])

    # turning a key on: startup encrypts the existing rows, edges see no difference
    key(K1)
    secrets_at_rest()
    stored_key2, stored_secret2 = raw_row()
    assert stored_key2.startswith("enc:v1:") and stored_secret2.startswith("enc:v1:")
    cfg = edge_get(client, token, "/edge/v1/config").json()["sites"][0]
    assert cfg["ssl"]["key"] == pem.strip() + "\n" and cfg["secret"] == stored_secret
    with SessionLocal() as db:
        assert crypto.status(db) == {"key_configured": True, "plaintext": 0, "encrypted": 2,
                                     "readable": True, "error": None}


def test_rotation(client, tmp_path, key):
    key(K1)
    site(client)
    pem = upload(client, tmp_path)
    before = raw_row()

    key(f"{K2},{K1}")  # new primary first, old key still accepted
    token = add_edge(client)
    assert edge_get(client, token, "/edge/v1/config").json()["sites"][0]["ssl"]["key"] == pem.strip() + "\n"
    with SessionLocal() as db:
        assert crypto.rotate_all(db) == 2
    after = raw_row()
    assert after != before

    key(K2)  # old key removed: everything still readable
    cfg = edge_get(client, token, "/edge/v1/config").json()["sites"][0]
    assert cfg["ssl"]["key"] == pem.strip() + "\n"

    key(K1)  # only the retired key: clear error
    with SessionLocal() as db:
        s = db.query(crypto_site()).one()
        with pytest.raises(crypto.CryptoError, match="does not contain the key"):
            _ = s.ssl_key


def crypto_site():
    from app.models import Site

    return Site


def test_wrong_or_missing_key_is_a_clear_error(client, tmp_path, key):
    key(K1)
    site(client)
    upload(client, tmp_path)

    key(K2)
    with SessionLocal() as db:
        st = crypto.status(db)
        assert st["readable"] is False and "does not contain the key" in st["error"]
    deep = client.get("/healthz/deep").json()
    assert deep["status"] == "degraded" and deep["encryption"]["readable"] is False

    key("")
    with pytest.raises(crypto.CryptoError, match="not set"):
        crypto.decrypt(raw_row()[0])

    key("not-a-fernet-key")
    with pytest.raises(crypto.CryptoError, match="not a valid Fernet key"):
        crypto.encrypt("x")


def test_key_material_is_never_in_error_messages(key):
    key(f"{K1},{K2}")
    token = crypto.encrypt("secret")
    key(crypto.generate_key())
    with pytest.raises(crypto.CryptoError) as e:
        crypto.decrypt(token)
    assert K1 not in str(e.value) and K2 not in str(e.value)
    key("A" * 10)
    with pytest.raises(crypto.CryptoError) as e:
        crypto.encrypt("x")
    assert "AAAAAAAAAA" not in str(e.value)


def test_manage_commands(client, tmp_path, key, capsys):
    from app import manage

    site(client)
    upload(client, tmp_path)
    key(K1)
    assert manage.main(["encrypt-secrets"]) == 0
    assert "encrypted 2 value(s)" in capsys.readouterr().out
    key(f"{K2},{K1}")
    assert manage.main(["rotate-key"]) == 0
    key(K2)
    assert manage.main(["encryption-status"]) == 0
    assert '"readable": true' in capsys.readouterr().out
    assert manage.main(["gen-key"]) == 0
    new = capsys.readouterr().out.strip()
    key(new)
    assert crypto.decrypt(crypto.encrypt("hello")) == "hello"


def test_drop_unreadable_after_key_loss(client, tmp_path, key, capsys):
    from app import manage
    from app.models import Site

    key(K1)
    site(client)
    upload(client, tmp_path)
    key(K2)  # K1 lost
    token = add_edge(client)
    with pytest.raises(crypto.CryptoError):
        edge_get(client, token, "/edge/v1/config")
    with pytest.raises(SystemExit):
        manage.main(["drop-unreadable-secrets"])
    assert manage.main(["drop-unreadable-secrets", "--yes"]) == 0
    assert "1 site(s) reset: example.com" in capsys.readouterr().out
    with SessionLocal() as db:
        s = db.query(Site).one()
        assert s.ssl_status == "none" and s.ssl_key is None and len(s.secret) == 64
    cfg = edge_get(client, token, "/edge/v1/config").json()["sites"][0]
    assert cfg["ssl"] is None
