"""Wave 6B (SPEC §14.2) controller side: transform rules, redirect rules (+ CSV import), managed WAF
packs, bot management (+ the verified crawler IP ranges job) and authenticated origin pulls
(platform CA / client certificate and customer-uploaded client certificates)."""

import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from sqlalchemy import text

from app import alerts, botranges, crypto, origin_pull, routes_capi, scheduler, sections
from app.config import settings
from app.db import SessionLocal, engine
from app.models import Site, State, utcnow
from tests.test_api import add_edge, edge_get

S = "/api/v1/sites/example.com"
CAPI = "/capi/v1"
K1 = crypto.generate_key()


# ------------------------------------------------------------------ helpers

def mk_site(client, domain="example.com", **features):
    r = client.post("/api/v1/sites", json={"domain": domain, "origin_ip": "93.184.216.34",
                                           "plan": {"features": features}})
    assert r.status_code == 201, r.text
    return r.json()


def edge_cfg(client, token=None):
    token = token or add_edge(client)
    r = edge_get(client, token, "/edge/v1/config")
    assert r.status_code == 200, r.text
    return r.json()


def site_of(cfg, domain="example.com"):
    return next(s for s in cfg["sites"] if s["domain"] == domain)


def audit(client, **params):
    return client.get("/api/v1/audit", params=params).json()


def msg_of(r) -> str:
    return json.dumps(r.json(), ensure_ascii=False)


@pytest.fixture()
def enc_key(monkeypatch):
    monkeypatch.setattr(settings, "data_encryption_key", K1)
    return K1


@pytest.fixture()
def no_key(monkeypatch):
    monkeypatch.setattr(settings, "data_encryption_key", "")


def _client_cert(days=30, eku=(ExtendedKeyUsageOID.CLIENT_AUTH,), key=None, cn="origin-client.example.com",
                 not_after=None):
    """A self-signed client certificate + key (PEM strings)."""
    key = key or ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.now(timezone.utc)
    b = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=2))
         .not_valid_after(not_after or now + timedelta(days=days)))
    if eku is not None:
        b = b.add_extension(x509.ExtendedKeyUsage(list(eku)), critical=False)
    cert = b.sign(key, hashes.SHA256())
    return (cert.public_bytes(serialization.Encoding.PEM).decode(),
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()).decode())


# ------------------------------------------------------------------ defaults / GET == PUT

def test_new_sections_defaults_and_legacy_configs(client):
    s = mk_site(client)
    c = s["config"]
    assert c["transform"] == {"rules": []}
    assert c["redirects"] == {"rules": []}
    assert c["bots"] == {"mode": "off", "allow_verified": True, "block_empty_ua": True}
    assert c["waf"]["packs"] == []
    assert c["ssl"]["origin_client_auth"] == "off"
    feats = s["plan"]["features"]
    assert feats["max_transform_rules"] == 10 and feats["max_redirects"] == 100
    assert s["origin_client"] == {"mode": "off", "effective": "off", "custom": None, "ca_url": "/origin-pull-ca.pem"}
    # a config stored before Wave 6B (no new keys / sections) still reads with the defaults
    with SessionLocal() as db:
        site = db.query(Site).filter_by(domain="example.com").one()
        site.config = json.dumps({"waf": {"mode": "block"}, "ssl": {"force_https": True}})
        db.commit()
    c = client.get(f"{S}/config").json()
    assert c["waf"]["mode"] == "block" and c["waf"]["packs"] == []
    assert c["ssl"]["force_https"] is True and c["ssl"]["origin_client_auth"] == "off"
    assert c["bots"]["mode"] == "off" and c["redirects"]["rules"] == []
    # every section's GET body can be PUT back unchanged
    for name in ("transform", "redirects", "bots", "waf", "ssl"):
        body = client.get(f"{S}/config/{name}").json()
        r = client.put(f"{S}/config/{name}", json=body)
        assert r.status_code == 200 and r.json() == body, (name, r.text)


# ------------------------------------------------------------------ transform rules

TRANSFORM = {"rules": [
    {"id": "t1", "match": {"path": "/api/*", "methods": ["GET", "POST", "GET"], "countries": ["ir", " de ", "IR"]},
     "actions": [{"type": "set_request_header", "name": "X-Client", "value": 'a "quoted" $value\\'},
                 {"type": "remove_request_header", "name": "Cookie", "value": "ignored"},
                 {"type": "set_response_header", "name": "X-Frame-Options", "value": "DENY"},
                 {"type": "remove_response_header", "name": "Set-Cookie"},
                 {"type": "rewrite_path", "regex": "^/api/v1/(.*)$", "replacement": "/v2/$1?src=cdn",
                  "name": "dropped"}]},
    {"id": "t2", "enabled": False, "actions": [{"type": "set_response_header", "name": "X-A", "value": "1"}]},
]}


def test_transform_roundtrip_and_normalisation(client):
    mk_site(client)
    r = client.put(f"{S}/config/transform", json=TRANSFORM)
    assert r.status_code == 200, r.text
    got = r.json()
    t1 = got["rules"][0]
    assert t1["match"] == {"path": "/api/*", "methods": ["GET", "POST"], "countries": ["IR", "DE"]}
    assert t1["actions"][0] == {"type": "set_request_header", "name": "X-Client", "value": 'a "quoted" $value\\',
                                "regex": None, "replacement": None}
    # fields that do not apply to the action type are normalised to null
    assert t1["actions"][1] == {"type": "remove_request_header", "name": "Cookie", "value": None, "regex": None,
                                "replacement": None}
    assert t1["actions"][4] == {"type": "rewrite_path", "name": None, "value": None, "regex": "^/api/v1/(.*)$",
                                "replacement": "/v2/$1?src=cdn"}
    assert got["rules"][1]["match"] == {"path": "/*", "methods": [], "countries": []}
    assert client.get(f"{S}/config/transform").json() == got
    assert client.put(f"{S}/config/transform", json=got).json() == got


def _action(**a):
    return {"rules": [{"id": "t", "actions": [a]}]}


@pytest.mark.parametrize("name", ["Host", "host", "Connection", "Keep-Alive", "Transfer-Encoding", "Upgrade", "TE",
                                  "Trailer", "Content-Length", "Proxy-Authorization", "Proxy-Connection",
                                  "X-Pcdn-Shield", "x-pcdn-anything", "X-Forwarded-For", "X-Forwarded-Proto",
                                  "X-Real-IP", "Forwarded"])
@pytest.mark.parametrize("kind", ["set_request_header", "remove_request_header", "set_response_header",
                                  "remove_response_header"])
def test_transform_reserved_headers_rejected(client, name, kind):
    mk_site(client)
    r = client.put(f"{S}/config/transform", json=_action(type=kind, name=name, value="v"))
    assert r.status_code == 422, r.text
    assert "رزرو" in msg_of(r)


@pytest.mark.parametrize("name", ["Cookie", "Set-Cookie", "set-cookie"])
def test_transform_cookies_may_only_be_removed(client, name):
    mk_site(client)
    for kind in ("set_request_header", "set_response_header"):
        r = client.put(f"{S}/config/transform", json=_action(type=kind, name=name, value="a=b"))
        assert r.status_code == 422 and "فقط می‌توان حذف کرد" in msg_of(r)
    for kind in ("remove_request_header", "remove_response_header"):
        assert client.put(f"{S}/config/transform", json=_action(type=kind, name=name)).status_code == 200


@pytest.mark.parametrize("action", [
    {"type": "set_request_header", "name": "X-A", "value": "a\r\nX-Injected: 1"},
    {"type": "set_request_header", "name": "X-A", "value": "a\nb"},
    {"type": "set_response_header", "name": "X-A", "value": "tab\there"},
    {"type": "set_response_header", "name": "X-A", "value": "x" * 1025},
    {"type": "set_response_header", "name": "X-A", "value": "سلام"},
    {"type": "set_response_header", "name": "X-A"},
    {"type": "set_response_header", "name": "X-A", "value": ""},
    {"type": "set_response_header", "name": "X A", "value": "v"},
    {"type": "set_response_header", "name": "X:A", "value": "v"},
    {"type": "set_response_header", "name": "x" * 65, "value": "v"},
    {"type": "remove_response_header"},
    {"type": "add_header", "name": "X-A", "value": "v"},
    {"type": "rewrite_path", "replacement": "/x"},
    {"type": "rewrite_path", "regex": "^/a$"},
    {"type": "rewrite_path", "regex": "(", "replacement": "/x"},
    {"type": "rewrite_path", "regex": "(a+)+$", "replacement": "/x"},
    {"type": "rewrite_path", "regex": "^/(a|ab)*$", "replacement": "/x"},
    {"type": "rewrite_path", "regex": "^/(.)\\1$", "replacement": "/x"},
    {"type": "rewrite_path", "regex": "^/" + "a" * 260, "replacement": "/x"},
    {"type": "rewrite_path", "regex": "^/a b$", "replacement": "/x"},
    {"type": "rewrite_path", "regex": "^/(a)$", "replacement": "new/$1"},
    {"type": "rewrite_path", "regex": "^/(a)$", "replacement": "//evil.example/$1"},
    {"type": "rewrite_path", "regex": "^/(a)$", "replacement": "/x/$2"},
    {"type": "rewrite_path", "regex": "^/(a)$", "replacement": "/x/$0"},
    {"type": "rewrite_path", "regex": "^/(a)$", "replacement": "/x/$10"},
    {"type": "rewrite_path", "regex": "^/(a)$", "replacement": "/x/$host"},
    {"type": "rewrite_path", "regex": "^/(a)$", "replacement": "/x y"},
    {"type": "rewrite_path", "regex": "^/(a)$", "replacement": "/x\r\n"},
    {"type": "rewrite_path", "regex": "^/(a)$", "replacement": "/__pcdn/health"},
    {"type": "rewrite_path", "regex": "^/(a)$", "replacement": "/%zz"},
])
def test_transform_action_validation(client, action):
    mk_site(client)
    r = client.put(f"{S}/config/transform", json={"rules": [{"id": "t", "actions": [action]}]})
    assert r.status_code == 422, (action, r.text)


@pytest.mark.parametrize("rule", [
    {"id": "t", "actions": []},
    {"id": "t", "actions": [{"type": "remove_response_header", "name": f"X-{i}"} for i in range(11)]},
    {"id": "Bad Id", "actions": [{"type": "remove_response_header", "name": "X-A"}]},
    {"id": "t", "match": {"path": "no-slash"}, "actions": [{"type": "remove_response_header", "name": "X-A"}]},
    {"id": "t", "match": {"methods": ["TRACE"]}, "actions": [{"type": "remove_response_header", "name": "X-A"}]},
    {"id": "t", "match": {"countries": ["IRN"]}, "actions": [{"type": "remove_response_header", "name": "X-A"}]},
    {"id": "t", "match": {"countries": [f"A{chr(65 + i % 26)}" for i in range(51)]},
     "actions": [{"type": "remove_response_header", "name": "X-A"}]},
    {"id": "t", "bogus": 1, "actions": [{"type": "remove_response_header", "name": "X-A"}]},
])
def test_transform_rule_validation(client, rule):
    mk_site(client)
    assert client.put(f"{S}/config/transform", json={"rules": [rule]}).status_code == 422, rule
    dup = {"rules": [{"id": "t", "actions": [{"type": "remove_response_header", "name": "X-A"}]}] * 2}
    r = client.put(f"{S}/config/transform", json=dup)
    assert r.status_code == 422 and "یکتا" in msg_of(r)


def test_safe_regex_heuristics():
    for ok in [r"^/blog/(\d+)/(.*)$", r"(?:/[a-z0-9-]+)*", r"([^/]+/)*x", r"(\w+\.)*com", r"^/(fa|en)/p-(\d+)$",
               r"(?:jpg|jpeg|png)$", r"(ab|cd)+", "^/مقاله/(\\d+)$"]:
        sections._safe_regex(ok)
    for bad in [r"(a+)+", r"(a*)*", r"(.*)+", r"(.*/)+", r"(a+a)+", r"(x{1,100}){1,100}", r"(a|a)+", r"(a|ab)+c",
                r"(x|)+", r"(?:/?[a-z]+)*", r"(a)\1", "(?P<n>a)", ".*" * 11, "(", "a b", "a\nb"]:
        with pytest.raises(ValueError):
            sections._safe_regex(bad)


# ------------------------------------------------------------------ plan limits

def test_plan_limits_transform_and_redirects(client):
    mk_site(client, max_transform_rules=1, max_redirects=2)
    act = [{"type": "remove_response_header", "name": "X-A"}]
    two = {"rules": [{"id": "a", "actions": act}, {"id": "b", "actions": act}]}
    r = client.put(f"{S}/config/transform", json=two)
    assert r.status_code == 403 and "پلن" in r.json()["detail"]
    assert client.put(f"{S}/config/transform", json={"rules": two["rules"][:1]}).status_code == 200
    three = {"rules": [{"id": f"r{i}", "source": f"/o{i}", "target": f"/n{i}"} for i in range(3)]}
    r = client.put(f"{S}/config/redirects", json=three)
    assert r.status_code == 403 and "پلن" in r.json()["detail"]
    assert client.put(f"{S}/config/redirects", json={"rules": three["rules"][:2]}).status_code == 200
    # plan bounds
    assert client.patch(f"{S}/plan", json={"features": {"max_transform_rules": 1001}}).status_code == 422
    assert client.patch(f"{S}/plan", json={"features": {"max_redirects": 10001}}).status_code == 422
    # a plan lowered after the fact: the edges only get what the plan allows
    assert client.patch(f"{S}/plan", json={"features": {"max_transform_rules": 0, "max_redirects": 1}}).status_code == 200
    s = site_of(edge_cfg(client))
    assert s["transform"]["rules"] == [] and [r["id"] for r in s["redirects"]["rules"]] == ["r0"]
    # the stored config is untouched (raising the plan again restores it)
    assert len(client.get(f"{S}/config/redirects").json()["rules"]) == 2


# ------------------------------------------------------------------ redirect rules

def test_redirects_roundtrip_and_normalisation(client):
    mk_site(client)
    body = {"rules": [
        {"id": "a", "source": "/مقاله قدیمی", "target": "/new page?x=1&y=%2F", "status": 302},
        {"id": "b", "source": "/shop", "match": "prefix", "target": "https://Shop.Example.COM", "preserve_query": True},
        {"id": "c", "source": "^/blog/(\\d+)/(.*)$", "match": "regex", "target": "https://blog.example.com/$1/$2",
         "status": 308},
        {"id": "d", "source": "/old", "target": "https://exämple.ir/p", "enabled": False},
    ]}
    r = client.put(f"{S}/config/redirects", json=body)
    assert r.status_code == 200, r.text
    rules = r.json()["rules"]
    assert rules[0] == {"id": "a", "enabled": True,
                        "source": "/%D9%85%D9%82%D8%A7%D9%84%D9%87%20%D9%82%D8%AF%DB%8C%D9%85%DB%8C",
                        "match": "exact", "target": "/new%20page?x=1&y=%2F", "status": 302, "preserve_query": False}
    assert rules[1]["target"] == "https://shop.example.com" and rules[1]["preserve_query"] is True
    assert rules[2]["target"] == "https://blog.example.com/$1/$2" and rules[2]["status"] == 308
    assert rules[3]["target"] == "https://xn--exmple-cua.ir/p"
    got = client.get(f"{S}/config/redirects").json()
    assert got == r.json() and client.put(f"{S}/config/redirects", json=got).json() == got


@pytest.mark.parametrize("rule", [
    {"source": "/a", "target": "/b/$1"},                                   # $n without regex
    {"source": "^/(a)$", "match": "regex", "target": "/b/$2"},             # group does not exist
    {"source": "^/(a)$", "match": "regex", "target": "/b/$host"},          # nginx variable
    {"source": "/a", "target": "/b\r\nSet-Cookie: x=1"},                   # CR/LF
    {"source": "/a\nb", "target": "/b"},
    {"source": "/a", "target": "javascript:alert(1)"},
    {"source": "/a", "target": "//evil.example"},
    {"source": "/a", "target": "https://user:pw@evil.example/"},
    {"source": "/a", "target": "https://bad_host/"},
    {"source": "/a", "target": "https://example.com:99999/"},
    {"source": "/a", "target": ""},
    {"source": "a", "target": "/b"},
    {"source": "/a?x=1", "target": "/b"},
    {"source": "/a%zz", "target": "/b"},
    {"source": "/a", "target": "/a"},                                      # exact loop
    {"source": "/a", "match": "prefix", "target": "/a/b"},                 # prefix loop
    {"source": "/", "match": "prefix", "target": "/home"},
    {"source": "^/x/.*$", "match": "regex", "target": "/x/y"},             # regex loop
    {"source": "(a+)+", "match": "regex", "target": "/b"},                 # catastrophic regex
    {"source": "(", "match": "regex", "target": "/b"},
    {"source": "/a", "target": "/b", "status": 303},
    {"source": "/a", "target": "/b", "match": "glob"},
])
def test_redirect_validation(client, rule):
    mk_site(client)
    r = client.put(f"{S}/config/redirects", json={"rules": [{"id": "r", **rule}]})
    assert r.status_code == 422, (rule, r.text)


def test_redirect_duplicate_sources_rejected(client):
    mk_site(client)
    dup = {"rules": [{"id": "a", "source": "/x", "target": "/y"}, {"id": "b", "source": "/x", "target": "/z"}]}
    r = client.put(f"{S}/config/redirects", json=dup)
    assert r.status_code == 422 and "بیش از یک بار" in msg_of(r)
    # the same path with another match type is a different rule
    dup["rules"][1]["match"] = "prefix"
    assert client.put(f"{S}/config/redirects", json=dup).status_code == 200


# ------------------------------------------------------------------ redirects CSV import

CSV_OK = "﻿source,target,status,match,preserve_query\n" \
         "/old-1,/new-1,301\n" \
         "\n" \
         "# a comment line\n" \
         "/old-2,https://example.org/n2,302,prefix,true\n" \
         "\"^/p/(\\d+)$\",/post/$1,308,regex,no\n"


def test_csv_import_append_and_replace(client):
    mk_site(client)
    client.put(f"{S}/config/redirects", json={"rules": [{"id": "csv-1", "source": "/keep", "target": "/kept"}]})
    r = client.post(f"{S}/redirects/import", json={"csv": CSV_OK})  # default mode: append
    assert r.status_code == 200, r.text
    assert r.json() == {"imported": 3, "total": 4, "mode": "append"}
    rules = client.get(f"{S}/config/redirects").json()["rules"]
    assert [x["id"] for x in rules] == ["csv-1", "csv-2", "csv-3", "csv-4"]  # no id collision
    assert rules[2] == {"id": "csv-3", "enabled": True, "source": "/old-2", "match": "prefix",
                        "target": "https://example.org/n2", "status": 302, "preserve_query": True}
    assert rules[3]["match"] == "regex" and rules[3]["target"] == "/post/$1" and rules[3]["preserve_query"] is False

    # raw text/csv body + ?mode=replace
    r = client.post(f"{S}/redirects/import?mode=replace", content="/x,/y\n/z,/w,307".encode(),
                    headers={"Content-Type": "text/csv"})
    assert r.status_code == 200, r.text
    assert r.json() == {"imported": 2, "total": 2, "mode": "replace"}
    rules = client.get(f"{S}/config/redirects").json()["rules"]
    assert [(x["id"], x["source"], x["status"]) for x in rules] == [("csv-1", "/x", 301), ("csv-2", "/z", 307)]

    entries = audit(client, action="redirects.import")
    assert [e["detail"] for e in entries] == [{"count": 2, "mode": "replace"}, {"count": 3, "mode": "append"}]
    assert entries[0]["target"] == "example.com" and entries[0]["actor_kind"] == "admin"


def test_csv_import_is_all_or_nothing_with_row_errors(client):
    mk_site(client)
    client.put(f"{S}/config/redirects", json={"rules": [{"id": "a", "source": "/exists", "target": "/e"}]})
    before = client.get(f"{S}/config/redirects").json()
    bad = ("source,target,status\n"
           "/ok,/fine,301\n"            # line 2: fine
           "/bad,javascript:x,301\n"    # line 3: bad target
           "/ok2,/fine2,303\n"          # line 4: bad status
           "/exists,/dup,301\n"         # line 5: duplicates an existing rule (append)
           "/ok,/again,302\n"           # line 6: duplicates line 2
           "/r,/s,301,glob\n"           # line 7: bad match
           "/q,/t,301,exact,maybe\n"    # line 8: bad preserve_query
           "only-one-column\n"          # line 9
           "/loop,/loop\n"              # line 10: loop
           "/e,/f,301,exact,no,perhaps\n"  # line 11: bad enabled
           "/g,/h,301,exact,no,true,x\n")  # line 12: too many columns
    r = client.post(f"{S}/redirects/import", json={"csv": bad, "mode": "append"})
    assert r.status_code == 422, r.text
    errors = r.json()["detail"]
    assert [e["line"] for e in errors] == [3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
    assert all(e["loc"] == ["csv", e["line"]] and e["msg"] for e in errors)
    assert "301، 302، 307 یا 308" in errors[1]["msg"] and "تکراری" in errors[2]["msg"]
    assert client.get(f"{S}/config/redirects").json() == before  # nothing saved
    assert audit(client, action="redirects.import") == []
    # in replace mode the existing rules do not count as duplicates
    r = client.post(f"{S}/redirects/import", json={"csv": "/exists,/dup", "mode": "replace"})
    assert r.status_code == 200 and r.json()["total"] == 1


def test_csv_import_accepts_the_client_app_export(client):
    """The client app exports `source,target,status,match,preserve_query,enabled`; importing that file
    back (replace) restores the same rules."""
    mk_site(client)
    rules = [{"id": "a", "source": "/a", "target": "/b", "status": 302, "match": "prefix", "preserve_query": True,
              "enabled": False},
             {"id": "b", "source": "^/p/(\\d+)$", "match": "regex", "target": "https://x.example/$1"}]
    client.put(f"{S}/config/redirects", json={"rules": rules})
    before = client.get(f"{S}/config/redirects").json()["rules"]
    lines = ["source,target,status,match,preserve_query,enabled"]
    for r in before:
        lines.append(",".join(['"' + str(r[k]).replace('"', '""') + '"' if k == "source" else
                               ("true" if r[k] is True else "false" if r[k] is False else str(r[k]))
                               for k in ("source", "target", "status", "match", "preserve_query", "enabled")]))
    r = client.post(f"{S}/redirects/import", json={"csv": "\r\n".join(lines), "mode": "replace"})
    assert r.status_code == 200, r.text
    after = client.get(f"{S}/config/redirects").json()["rules"]
    strip = [{k: v for k, v in x.items() if k != "id"} for x in after]
    assert strip == [{k: v for k, v in x.items() if k != "id"} for x in before]
    assert after[0]["enabled"] is False and after[1]["enabled"] is True


def test_csv_import_limits_and_bad_requests(client):
    mk_site(client, max_redirects=2)
    r = client.post(f"{S}/redirects/import", json={"csv": "/a,/b\n/c,/d\n/e,/f"})
    assert r.status_code == 403 and "پلن" in r.json()["detail"]
    assert client.get(f"{S}/config/redirects").json()["rules"] == []
    assert client.post(f"{S}/redirects/import", json={"csv": "/a,/b", "mode": "merge"}).status_code == 422
    assert client.post(f"{S}/redirects/import", json={"csv": "source,target\n\n"}).status_code == 422
    assert client.post(f"{S}/redirects/import", json={"text": "/a,/b"}).status_code == 422
    r = client.post(f"{S}/redirects/import", content=b"\xff\xfe/a,/b", headers={"Content-Type": "text/csv"})
    assert r.status_code == 422 and "UTF-8" in r.json()["detail"]
    big = "/a,/b\n" * 400_000
    assert client.post(f"{S}/redirects/import", content=big.encode(),
                       headers={"Content-Type": "text/csv"}).status_code == 413
    assert client.post("/api/v1/sites/nope.com/redirects/import", json={"csv": "/a,/b"}).status_code == 404


def test_csv_import_via_customer_api(client):
    mk_site(client)
    routes_capi._hits.clear()
    routes_capi._config_hits.clear()
    full = client.post(f"{S}/apikeys", json={"name": "ci", "scopes": ["dns"]}).json()["key"]
    stats = client.post(f"{S}/apikeys", json={"name": "ro", "scopes": ["stats"]}).json()["key"]
    r = client.post(f"{CAPI}/redirects/import", json={"csv": "/a,/b"}, headers={"Authorization": f"Bearer {stats}"})
    assert r.status_code == 403
    r = client.post(f"{CAPI}/redirects/import?mode=replace", content=b"/a,/b\n/c,/d,302",
                    headers={"Authorization": f"Bearer {full}", "Content-Type": "text/csv"})
    assert r.status_code == 200, r.text
    assert r.json() == {"imported": 2, "total": 2, "mode": "replace"}
    r = client.post(f"{CAPI}/redirects/import", json={"csv": "/x,javascript:1"},
                    headers={"Authorization": f"Bearer {full}"})
    assert r.status_code == 422 and r.json()["detail"][0]["line"] == 1
    e = audit(client, action="redirects.import")[0]
    assert e["actor_kind"] == "capi" and e["actor"] == "ci" and e["detail"] == {"count": 2, "mode": "replace"}
    # the section itself is reachable with the same scope
    got = client.get(f"{CAPI}/config/redirects", headers={"Authorization": f"Bearer {full}"}).json()
    assert [x["source"] for x in got["rules"]] == ["/a", "/c"]
    routes_capi._hits.clear()
    routes_capi._config_hits.clear()


# ------------------------------------------------------------------ WAF packs + bots

def test_waf_packs(client):
    mk_site(client)
    r = client.put(f"{S}/config/waf", json={"mode": "block", "packs": ["wordpress", "generic", "wordpress", "api"],
                                           "exclusions": [{"rule_id": 942100, "path": "/wp-admin/*"}]})
    assert r.status_code == 200, r.text
    assert r.json()["packs"] == ["wordpress", "generic", "api"]
    assert client.put(f"{S}/config/waf", json={"packs": ["magento"]}).status_code == 422
    assert client.put(f"{S}/config/waf", json={"packs": "wordpress"}).status_code == 422
    waf = site_of(edge_cfg(client))["waf"]
    assert waf["packs"] == ["wordpress", "generic", "api"] and waf["mode"] == "block"
    assert waf["exclusions"] == [{"rule_id": 942100, "path": "/wp-admin/*"}]
    # a plan without WAF turns the mode off but the packs travel unchanged (the edge needs mode)
    client.patch(f"{S}/plan", json={"features": {"waf": False}})
    assert site_of(edge_cfg(client, add_edge(client, name="e2", ip="5.160.1.11")))["waf"]["mode"] == "off"


def test_bots_section(client):
    mk_site(client)
    r = client.put(f"{S}/config/bots", json={"mode": "challenge", "allow_verified": False})
    assert r.status_code == 200 and r.json() == {"mode": "challenge", "allow_verified": False, "block_empty_ua": True}
    for body in ({"mode": "captcha"}, {"allow_verified": "maybe"}, {"extra": 1}):
        assert client.put(f"{S}/config/bots", json=body).status_code == 422, body
    assert site_of(edge_cfg(client))["bots"] == {"mode": "challenge", "allow_verified": False, "block_empty_ua": True}


def test_edge_config_shapes(client):
    mk_site(client)
    client.put(f"{S}/config/transform", json=TRANSFORM)
    client.put(f"{S}/config/redirects", json={"rules": [{"id": "r", "source": "/a", "target": "/b"}]})
    cfg = edge_cfg(client)
    s = site_of(cfg)
    assert s["transform"] == client.get(f"{S}/config/transform").json()
    assert s["redirects"] == {"rules": [{"id": "r", "enabled": True, "source": "/a", "match": "exact",
                                         "target": "/b", "status": 301, "preserve_query": False}]}
    assert s["bots"] == {"mode": "off", "allow_verified": True, "block_empty_ua": True}
    assert s["ssl_options"]["origin_client_auth"] == "off" and s["ssl_options"]["origin_client"] == {"mode": "off"}
    # node-wide blocks: no ranges fetched yet, nobody uses the platform client certificate
    assert cfg["bots"] == {"verified": {}, "fetched_at": None}
    assert cfg["origin_pull"] is None
    with SessionLocal() as db:
        assert db.get(State, origin_pull.STATE_KEY) is None  # nothing created just by building


# ------------------------------------------------------------------ verified crawler IP ranges

GOOGLE = {"creationTime": "2026-09-30T23:00:00", "prefixes": [
    {"ipv6Prefix": "2001:4860:4801:10::/64"},
    {"ipv4Prefix": "66.249.66.0/27"},
    {"ipv4Prefix": "66.249.64.0/27"},
    {"ipv4Prefix": "66.249.64.0/27"},            # duplicate
    {"ipv4Prefix": "66.249.64.5/27"},            # host bits set: normalised (and a duplicate)
    {"ipv4Prefix": "not-a-cidr"},
    {"ipv4Prefix": "0.0.0.0/0"},                 # far too broad: never "verified"
    {"ipv4Prefix": "8.0.0.0/8"},
    {"ipv4Prefix": "10.1.2.0/24"},               # not public
    {"ipv6Prefix": "2001:db8::/48"},             # documentation range
    "junk",
]}
BING = {"prefixes": [{"ipv4Prefix": "157.55.39.0/24"}, {"ipv4Prefix": "40.77.167.0/24"}]}


class Feeds:
    def __init__(self, google=GOOGLE, bing=BING):
        self.docs = {botranges.SOURCES["google"]: google, botranges.SOURCES["bing"]: bing}
        self.calls: list[str] = []

    def __call__(self, url):
        self.calls.append(url)
        doc = self.docs[url]
        if isinstance(doc, Exception):
            raise doc
        return doc


def test_parse_ranges():
    assert botranges.parse(GOOGLE) == ["66.249.64.0/27", "66.249.66.0/27", "2001:4860:4801:10::/64"]
    with pytest.raises(ValueError):
        botranges.parse({"prefixes": [{"ipv4Prefix": "0.0.0.0/0"}]})
    with pytest.raises(ValueError):
        botranges.parse({"items": []})
    with pytest.raises(ValueError):
        botranges.parse([])


def test_parse_ranges_is_capped(monkeypatch):
    monkeypatch.setattr(botranges, "MAX_PREFIXES", 5)
    doc = {"prefixes": [{"ipv4Prefix": f"66.249.{i}.0/24"} for i in range(20)]}
    assert botranges.parse(doc) == [f"66.249.{i}.0/24" for i in range(5)]


@pytest.fixture()
def ranges_on(monkeypatch, alert_settings):
    monkeypatch.setattr(settings, "bot_ranges_enabled", True)
    monkeypatch.setattr(settings, "bot_ranges_stale_days", 3)


def test_ranges_job_fetches_on_start_then_daily(client, ranges_on, monkeypatch):
    feeds = Feeds()
    monkeypatch.setattr(botranges, "fetcher", feeds)
    t0 = utcnow()
    with SessionLocal() as db:
        scheduler.job_bot_ranges(db, now=t0)  # nothing stored yet: runs right away
    assert len(feeds.calls) == 2
    with SessionLocal() as db:
        block = botranges.edge_block(db)
    assert block == {"verified": {"google": ["66.249.64.0/27", "66.249.66.0/27", "2001:4860:4801:10::/64"],
                                  "bing": ["40.77.167.0/24", "157.55.39.0/24"]},
                     "fetched_at": t0.isoformat() + "Z"}
    with SessionLocal() as db:
        scheduler.job_bot_ranges(db, now=t0 + timedelta(hours=23))  # not due yet
    assert len(feeds.calls) == 2
    with SessionLocal() as db:
        scheduler.job_bot_ranges(db, now=t0 + timedelta(days=1, minutes=1))
    assert len(feeds.calls) == 4
    # the edges get the block node-wide
    mk_site(client)
    cfg = edge_cfg(client)
    assert cfg["bots"]["verified"]["bing"] == ["40.77.167.0/24", "157.55.39.0/24"]
    assert cfg["bots"]["fetched_at"] == (t0 + timedelta(days=1, minutes=1)).isoformat() + "Z"


def test_ranges_failure_keeps_last_good_and_retries(client, ranges_on, monkeypatch):
    t0 = utcnow()
    with SessionLocal() as db:
        botranges.refresh(db, now=t0, fetch=Feeds())
    broken = Feeds(google=RuntimeError("connection refused"), bing={"prefixes": [{"ipv4Prefix": "207.46.13.0/24"}]})
    t1 = t0 + timedelta(days=1, minutes=1)
    with SessionLocal() as db:
        state = botranges.refresh(db, now=t1, fetch=broken)
    assert "connection refused" in state["errors"]["google"]
    assert state["sources"]["google"] == {"cidrs": ["66.249.64.0/27", "66.249.66.0/27", "2001:4860:4801:10::/64"],
                                          "fetched_at": t0.isoformat()}
    assert state["sources"]["bing"] == {"cidrs": ["207.46.13.0/24"], "fetched_at": t1.isoformat()}
    with SessionLocal() as db:
        block = botranges.edge_block(db)
    assert block["verified"]["google"][0] == "66.249.64.0/27" and block["fetched_at"] == t0.isoformat() + "Z"
    # a failed source is retried after RETRY (not a day later), and garbage is a failure too
    garbage = Feeds(google={"no": "prefixes"})
    with SessionLocal() as db:
        botranges.refresh(db, now=t1 + timedelta(minutes=30), fetch=garbage)
    assert garbage.calls == []
    with SessionLocal() as db:
        state = botranges.refresh(db, now=t1 + botranges.RETRY, fetch=garbage)
    assert len(garbage.calls) == 2 and "prefixes" in state["errors"]["google"]
    assert state["sources"]["google"]["fetched_at"] == t0.isoformat()  # still the last good list
    assert alerts.open_alerts() == []  # not stale for long enough yet


def test_ranges_stale_alert_and_recovery(client, ranges_on, monkeypatch):
    t0 = utcnow() - timedelta(days=5)
    down = Feeds(google=RuntimeError("timeout"), bing=RuntimeError("timeout"))
    with SessionLocal() as db:
        botranges.refresh(db, now=t0, fetch=down)  # never succeeded
    assert alerts.open_alerts() == []
    with SessionLocal() as db:
        botranges.refresh(db, now=t0 + timedelta(days=4), fetch=down)
    keys = [c["key"] for c in alerts.open_alerts()]
    assert keys == ["bot_ranges:stale"]
    assert "google" in alerts.open_alerts()[0]["text"] and alerts.open_alerts()[0]["severity"] == "warning"
    with SessionLocal() as db:
        botranges.refresh(db, now=t0 + timedelta(days=5), fetch=Feeds())
    assert alerts.open_alerts() == []


def test_ranges_job_disabled_does_nothing(client, monkeypatch):
    feeds = Feeds()
    monkeypatch.setattr(botranges, "fetcher", feeds)
    assert settings.bot_ranges_enabled is False  # conftest: no outbound fetch in tests
    with SessionLocal() as db:
        scheduler.job_bot_ranges(db)
        assert db.get(State, botranges.STATE_KEY) is None
    assert feeds.calls == []
    assert scheduler.job_bot_ranges in scheduler.JOBS and scheduler.job_origin_pull in scheduler.JOBS


# ------------------------------------------------------------------ platform origin pull CA

def _load(pem):
    return x509.load_pem_x509_certificate(pem.encode())


def test_platform_ca_and_client_certificate(client, enc_key):
    doc = origin_pull.ensure()
    ca, cl = _load(doc["ca_cert"]), _load(doc["client_cert"])
    # CA: EC P-256, CA:TRUE, ~10 years; client: EC P-256, clientAuth, ~2 years, signed by the CA
    assert isinstance(ca.public_key(), ec.EllipticCurvePublicKey) and ca.public_key().curve.name == "secp256r1"
    assert ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is True
    assert 3640 <= (ca.not_valid_after_utc - ca.not_valid_before_utc).days <= 3651
    assert cl.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
    assert ExtendedKeyUsageOID.CLIENT_AUTH in cl.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert 725 <= (cl.not_valid_after_utc - cl.not_valid_before_utc).days <= 731
    cl.verify_directly_issued_by(ca)
    # both private keys are encrypted at rest; created once
    with engine.connect() as c:
        raw = c.execute(text("SELECT value FROM state WHERE key = :k"), {"k": origin_pull.STATE_KEY}).scalar()
    assert "PRIVATE KEY" not in raw
    stored = json.loads(raw)
    assert stored["ca_key"].startswith("enc:v1:") and stored["client_key"].startswith("enc:v1:")
    assert origin_pull.ensure()["ca_cert"] == doc["ca_cert"]
    pair = origin_pull.client_pair()
    assert pair["cert"] == doc["client_cert"] and "PRIVATE KEY" in pair["key"]
    key = serialization.load_pem_private_key(pair["key"].encode(), password=None)
    assert key.public_key().public_numbers() == cl.public_key().public_numbers()


def test_public_ca_endpoint(client):
    r = client.get("/origin-pull-ca.pem", headers={"Authorization": "Bearer not-a-key"})  # no auth needed
    assert r.status_code == 200 and r.headers["content-type"].startswith("application/x-pem-file")
    assert r.text.count("BEGIN CERTIFICATE") == 1 and "PRIVATE KEY" not in r.text
    assert _load(r.text).extensions.get_extension_for_class(x509.BasicConstraints).value.ca is True
    assert client.get("/origin-pull-ca.pem").text == r.text  # created once, stable
    with SessionLocal() as db:
        assert json.loads(db.get(State, origin_pull.STATE_KEY).value)["ca_cert"] == r.text


def test_platform_mode_edge_config_never_carries_the_ca_key(client, enc_key):
    mk_site(client)
    mk_site(client, domain="other.com")
    r = client.put(f"{S}/config/ssl", json={"origin_client_auth": "platform", "origin_protocol": "https"})
    assert r.status_code == 200 and "X-Pcdn-Warnings" not in r.headers
    with SessionLocal() as db:
        assert db.get(State, origin_pull.STATE_KEY) is not None  # CA created when the mode was chosen
    ca_pem = client.get("/origin-pull-ca.pem").text
    token = add_edge(client)
    cfg = edge_cfg(client, token)
    doc = origin_pull.ensure()
    ca_key = crypto.decrypt(doc["ca_key"])
    assert cfg["origin_pull"] == {"cert": doc["client_cert"], "key": crypto.decrypt(doc["client_key"])}
    assert _load(cfg["origin_pull"]["cert"]).issuer == _load(ca_pem).subject
    blob = json.dumps(cfg)
    assert ca_key not in blob and ca_key.strip().splitlines()[1] not in blob
    assert blob.count("PRIVATE KEY-----") == 2  # BEGIN + END of the client key only
    assert site_of(cfg)["ssl_options"]["origin_client"] == {"mode": "platform"}
    assert site_of(cfg, "other.com")["ssl_options"]["origin_client"] == {"mode": "off"}
    # back to off: the node-wide block disappears
    client.put(f"{S}/config/ssl", json={"origin_client_auth": "off"})
    assert edge_cfg(client, token)["origin_pull"] is None


def test_platform_warning_without_https_origin(client):
    mk_site(client)
    r = client.put(f"{S}/config/ssl", json={"origin_client_auth": "platform"})
    assert r.status_code == 200
    warnings = json.loads(r.headers["X-Pcdn-Warnings"])
    assert any("origin_client_auth" in w and "HTTPS" in w for w in warnings)


def test_platform_client_renewal(client, no_key):
    t0 = utcnow()
    doc = origin_pull.ensure(now=t0)
    na = datetime.fromisoformat(doc["client_not_after"])
    assert origin_pull.ensure(now=na - timedelta(days=31)) == doc  # not due yet
    renewed = origin_pull.ensure(now=na - timedelta(days=29))
    assert renewed["client_cert"] != doc["client_cert"] and renewed["ca_cert"] == doc["ca_cert"]
    assert renewed["ca_key"] == doc["ca_key"]
    assert datetime.fromisoformat(renewed["client_not_after"]) > na
    _load(renewed["client_cert"]).verify_directly_issued_by(_load(doc["ca_cert"]))
    # renewed once only
    assert origin_pull.ensure(now=na - timedelta(days=28)) == renewed
    # the scheduler job renews too, and never creates a CA that nobody asked for
    with SessionLocal() as db:
        db.delete(db.get(State, origin_pull.STATE_KEY))
        db.commit()
        scheduler.job_origin_pull(db)
        assert db.get(State, origin_pull.STATE_KEY) is None
    doc = origin_pull.ensure(now=t0)
    later = datetime.fromisoformat(doc["client_not_after"]) - timedelta(days=10)
    with SessionLocal() as db:
        scheduler.job_origin_pull(db, now=later)
    assert origin_pull.ensure(now=later)["client_cert"] != doc["client_cert"]


def test_platform_creation_and_renewal_races(client, no_key, monkeypatch):
    """Two controllers creating / renewing at the same time end up with ONE CA and one client cert."""
    real_new = origin_pull._new_doc
    theirs = {}

    def racing_new(now):
        mine = real_new(now)
        theirs.update(real_new(now))  # the other controller commits first
        with SessionLocal() as db:
            db.add(State(key=origin_pull.STATE_KEY, value=json.dumps(theirs)))
            db.commit()
        return mine

    monkeypatch.setattr(origin_pull, "_new_doc", racing_new)
    got = origin_pull.ensure()
    assert got["ca_cert"] == theirs["ca_cert"]
    monkeypatch.setattr(origin_pull, "_new_doc", real_new)

    real_renewed = origin_pull._renewed
    other = {}

    def racing_renewed(doc, now):
        mine = real_renewed(doc, now)
        other.update(real_renewed(doc, now))
        with SessionLocal() as db:
            db.get(State, origin_pull.STATE_KEY).value = json.dumps(other)
            db.commit()
        return mine

    monkeypatch.setattr(origin_pull, "_renewed", racing_renewed)
    due = datetime.fromisoformat(got["client_not_after"]) - timedelta(days=5)
    result = origin_pull.ensure(now=due)
    assert result["client_cert"] == other["client_cert"]
    with SessionLocal() as db:
        assert json.loads(db.get(State, origin_pull.STATE_KEY).value)["client_cert"] == other["client_cert"]


# ------------------------------------------------------------------ custom origin client certificate

def test_custom_origin_client_upload_encrypt_and_edge_config(client, enc_key):
    mk_site(client)
    mk_site(client, domain="other.com")
    token = add_edge(client)
    cert, key = _client_cert()
    # custom chosen before an upload: saved, warned, folded to off on the edges
    r = client.put(f"{S}/config/ssl", json={"origin_client_auth": "custom", "origin_protocol": "https"})
    assert r.status_code == 200 and any("custom" in w for w in json.loads(r.headers["X-Pcdn-Warnings"]))
    assert site_of(edge_cfg(client, token))["ssl_options"]["origin_client"] == {"mode": "off"}

    r = client.put(f"{S}/ssl/origin-client", json={"cert": cert, "key": key})
    assert r.status_code == 200, r.text
    info = r.json()
    assert info["mode"] == "custom" and info["effective"] == "custom"
    assert info["custom"]["subject"] == "CN=origin-client.example.com" and info["custom"]["expired"] is False
    assert info["custom"]["expires_at"].endswith("Z")
    assert client.get(f"{S}/ssl/origin-client").json() == info
    # encrypted at rest; never returned by the admin API
    with engine.connect() as c:
        stored = c.execute(text("SELECT origin_client_key, origin_client_cert FROM sites WHERE domain = 'example.com'")
                           ).one()
    assert stored[0].startswith("enc:v1:") and "PRIVATE KEY" not in stored[0]
    assert stored[1].strip() == cert.strip()
    assert "PRIVATE KEY" not in client.get(S).text and "PRIVATE KEY" not in json.dumps(info)
    assert client.get(S).json()["origin_client"]["effective"] == "custom"

    cfg = edge_cfg(client, token)
    assert site_of(cfg)["ssl_options"]["origin_client"] == {"mode": "custom", "cert": cert.strip() + "\n",
                                                            "key": key.strip() + "\n"}
    assert site_of(cfg, "other.com")["ssl_options"]["origin_client"] == {"mode": "off"}
    assert key.strip() not in json.dumps(site_of(cfg, "other.com")) and cfg["origin_pull"] is None
    # a warning-free save now
    r = client.put(f"{S}/config/ssl", json={"origin_client_auth": "custom", "origin_protocol": "https"})
    assert "X-Pcdn-Warnings" not in r.headers

    # remove: the setting falls back to off
    r = client.delete(f"{S}/ssl/origin-client")
    assert r.status_code == 200 and r.json()["custom"] is None and r.json()["mode"] == "off"
    assert client.get(f"{S}/config/ssl").json()["origin_client_auth"] == "off"
    assert site_of(edge_cfg(client, token))["ssl_options"]["origin_client"] == {"mode": "off"}
    assert client.delete(f"{S}/ssl/origin-client").status_code == 404

    actions = [e["action"] for e in audit(client, limit=50)]
    assert "ssl.origin_client.upload" in actions and "ssl.origin_client.remove" in actions
    blob = json.dumps(audit(client, limit=50))
    assert "PRIVATE KEY" not in blob and "BEGIN CERTIFICATE" not in blob


def test_custom_origin_client_validation(client):
    mk_site(client)
    cert, key = _client_cert()
    _, other_key = _client_cert()
    expired_cert, expired_key = _client_cert(not_after=datetime.now(timezone.utc) - timedelta(days=1))
    server_cert, server_key = _client_cert(eku=(ExtendedKeyUsageOID.SERVER_AUTH,))
    small = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    small_cert, small_key = _client_cert(key=small)
    enc_key_pem = serialization.load_pem_private_key(key.encode(), password=None).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"pw")).decode()
    cases = [
        ({"cert": cert, "key": other_key}, "مطابقت"),
        ({"cert": expired_cert, "key": expired_key}, "منقضی"),
        ({"cert": server_cert, "key": server_key}, "clientAuth"),
        ({"cert": small_cert, "key": small_key}, "۲۰۴۸"),
        ({"cert": cert, "key": enc_key_pem}, "رمزگذاری"),
        ({"cert": "junk", "key": "junk"}, "PEM"),
        ({"cert": "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----", "key": key}, "قابل خواندن"),
        ({"cert": cert, "key": "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----"}, "قابل خواندن"),
    ]
    for body, needle in cases:
        r = client.put(f"{S}/ssl/origin-client", json=body)
        assert r.status_code == 422 and needle in r.json()["detail"], (needle, r.text)
    # size limits
    assert client.put(f"{S}/ssl/origin-client", json={"cert": cert + "x" * 70000, "key": key}).status_code == 422
    assert client.put(f"{S}/ssl/origin-client", json={"cert": cert, "key": key + "x" * 17000}).status_code == 422
    # no EKU at all is accepted (many private CAs omit it), and a chain is kept as uploaded
    plain_cert, plain_key = _client_cert(eku=None)
    ca_cert, _ = _client_cert(cn="some intermediate")
    r = client.put(f"{S}/ssl/origin-client", json={"cert": plain_cert + ca_cert, "key": plain_key})
    assert r.status_code == 200, r.text
    with SessionLocal() as db:
        assert db.query(Site).one().origin_client_cert.count("BEGIN CERTIFICATE") == 2
    assert client.get(f"{S}/ssl/origin-client").json()["effective"] == "off"  # mode is still off


def test_expired_custom_certificate_is_folded_to_off(client, no_key):
    mk_site(client)
    cert, key = _client_cert()
    client.put(f"{S}/ssl/origin-client", json={"cert": cert, "key": key})
    client.put(f"{S}/config/ssl", json={"origin_client_auth": "custom", "origin_protocol": "https"})
    token = add_edge(client)
    assert site_of(edge_cfg(client, token))["ssl_options"]["origin_client"]["mode"] == "custom"
    with SessionLocal() as db:
        db.query(Site).one().origin_client_expires_at = utcnow() - timedelta(minutes=1)
        db.commit()
    assert site_of(edge_cfg(client, token))["ssl_options"]["origin_client"] == {"mode": "off"}
    assert client.get(f"{S}/ssl/origin-client").json()["custom"]["expired"] is True


def test_encryption_bulk_operations_cover_new_secrets(client, monkeypatch):
    from app import manage

    monkeypatch.setattr(settings, "data_encryption_key", "")
    mk_site(client)
    cert, key = _client_cert()
    client.put(f"{S}/ssl/origin-client", json={"cert": cert, "key": key})
    origin_pull.ensure()
    with SessionLocal() as db:
        st = crypto.status(db)
    assert st["plaintext"] == 4 and st["encrypted"] == 0  # site secret + origin client key + 2 platform keys

    monkeypatch.setattr(settings, "data_encryption_key", K1)
    with SessionLocal() as db:
        assert crypto.encrypt_existing(db) == 4
        st = crypto.status(db)
    assert st["plaintext"] == 0 and st["encrypted"] == 4 and st["readable"] is True
    with engine.connect() as c:
        raw = c.execute(text("SELECT value FROM state WHERE key = :k"), {"k": origin_pull.STATE_KEY}).scalar()
    assert "PRIVATE KEY" not in raw
    assert origin_pull.client_pair()["key"].startswith("-----BEGIN PRIVATE KEY")

    k2 = crypto.generate_key()
    monkeypatch.setattr(settings, "data_encryption_key", f"{k2},{K1}")
    with SessionLocal() as db:
        assert crypto.rotate_all(db) == 4
    monkeypatch.setattr(settings, "data_encryption_key", k2)
    with SessionLocal() as db:
        assert db.query(Site).one().origin_client_key == key.strip() + "\n"
    assert "PRIVATE KEY" in origin_pull.client_pair()["key"]

    # key lost: drop-unreadable forgets the custom pair and the platform CA (recreated on use)
    monkeypatch.setattr(settings, "data_encryption_key", K1)
    old_ca = origin_pull.ensure()["ca_cert"]
    assert manage.main(["drop-unreadable-secrets", "--yes"]) == 0
    with SessionLocal() as db:
        s = db.query(Site).one()
        assert s.origin_client_cert is None and s.origin_client_key_stored is None
        assert db.get(State, origin_pull.STATE_KEY) is None
    assert origin_pull.ca_cert_pem() != old_ca
