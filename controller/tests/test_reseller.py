"""Reseller sub-site tag on Sites (SPEC §10.5)."""


def _create(client, domain, **body):
    r = client.post("/api/v1/sites", json={"domain": domain, **body})
    assert r.status_code == 201, r.text
    return r.json()


def test_create_with_reseller_fields(client):
    site = _create(client, "sub1.example.com", reseller_client_id=42,
                   reseller_label="  Acme Ltd  ")
    assert site["reseller_client_id"] == 42
    assert site["reseller_label"] == "Acme Ltd"  # stripped
    # read back
    got = client.get("/api/v1/sites/sub1.example.com").json()
    assert got["reseller_client_id"] == 42
    assert got["reseller_label"] == "Acme Ltd"


def test_non_reseller_site_has_null_fields(client):
    site = _create(client, "plain.example.com")
    assert site["reseller_client_id"] is None
    assert site["reseller_label"] is None
    # empty-string label collapses to None
    s2 = _create(client, "plain2.example.com", reseller_label="   ")
    assert s2["reseller_label"] is None


def test_label_truncated_to_120(client):
    site = _create(client, "long.example.com", reseller_client_id=1,
                   reseller_label="x" * 200)
    assert len(site["reseller_label"]) == 120


def test_patch_reseller_set_then_clear(client):
    _create(client, "tag.example.com")
    # set
    r = client.patch("/api/v1/sites/tag.example.com/reseller",
                     json={"reseller_client_id": 7, "reseller_label": "Cust"})
    assert r.status_code == 200, r.text
    assert r.json()["reseller_client_id"] == 7
    assert r.json()["reseller_label"] == "Cust"
    # only label changes when only label provided
    r = client.patch("/api/v1/sites/tag.example.com/reseller",
                     json={"reseller_label": "New"})
    assert r.json()["reseller_client_id"] == 7
    assert r.json()["reseller_label"] == "New"
    # clear by explicit null
    r = client.patch("/api/v1/sites/tag.example.com/reseller",
                     json={"reseller_client_id": None, "reseller_label": None})
    assert r.json()["reseller_client_id"] is None
    assert r.json()["reseller_label"] is None


def test_list_filtered_by_reseller(client):
    _create(client, "r1a.example.com", reseller_client_id=100, reseller_label="A")
    _create(client, "r1b.example.com", reseller_client_id=100, reseller_label="B")
    _create(client, "r2.example.com", reseller_client_id=200, reseller_label="C")
    _create(client, "direct.example.com")

    all_sites = client.get("/api/v1/sites").json()
    assert len(all_sites) == 4
    # unfiltered rows carry the reseller fields
    direct = next(s for s in all_sites if s["domain"] == "direct.example.com")
    assert direct["reseller_client_id"] is None

    only100 = client.get("/api/v1/sites?reseller=100").json()
    assert {s["domain"] for s in only100} == {"r1a.example.com", "r1b.example.com"}
    # roll-up fields present
    row = only100[0]
    assert set(row) >= {"domain", "reseller_label", "status", "bandwidth_limit_gb",
                        "over_quota", "suspended"}

    only200 = client.get("/api/v1/sites?reseller=200").json()
    assert {s["domain"] for s in only200} == {"r2.example.com"}

    assert client.get("/api/v1/sites?reseller=999").json() == []
