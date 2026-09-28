from types import SimpleNamespace

from app import dnsbuild
from app.config import settings
from app.nscheck import is_delegated


def rec(name, type_, content, proxied=False, priority=None, ttl=300):
    return SimpleNamespace(name=name, type=type_, content=content, proxied=proxied, priority=priority, ttl=ttl)


def edge(ip, region, ipv6=None):
    return SimpleNamespace(ipv4=ip, ipv6=ipv6, region=region)


def test_lua_geo_split(monkeypatch):
    monkeypatch.setattr(settings, "geoip_enabled", True)
    expr = dnsbuild.lua_expression(["5.5.5.5"], ["8.8.4.4"])
    assert expr.startswith(";local c=countryCode() local home=(c=='ir')")
    # never falls over to the other pool on this nameserver's own probes
    assert "if home then return ifurlup('http://health.pcdn/__pcdn/health', {{'5.5.5.5'}}" in expr
    assert "else return ifurlup('http://health.pcdn/__pcdn/health', {{'8.8.4.4'}}" in expr
    assert "backupSelector='all'" in expr
    # visitors of resolvers without ECS (Cloudflare) and unknown addresses go home
    assert "if ecswho==nil and netmask({'173.245.48.0/20'" in expr and "then home=true end" in expr
    assert "if c=='--' or c=='' then home=true end" in expr


def test_lua_geo_policies(monkeypatch):
    monkeypatch.setattr(settings, "geoip_enabled", True)
    monkeypatch.setattr(settings, "geo_home_countries", ["IR", "AF", "x;y"])
    monkeypatch.setattr(settings, "geo_no_ecs_pool", "global")
    monkeypatch.setattr(settings, "geo_no_ecs_resolvers", ["10.0.0.0/8", "bad'); os.exit(", "2001:db8::/32"])
    monkeypatch.setattr(settings, "geo_unknown_pool", "geo")
    monkeypatch.setattr(settings, "edge_probe", False)
    monkeypatch.setattr(settings, "lua_selector", "all")
    expr = dnsbuild.lua_expression(["5.5.5.5", "5.5.5.6"], ["8.8.4.4"])
    assert "home=(c=='ir' or c=='af')" in expr and "x;y" not in expr
    assert "netmask({'10.0.0.0/8','2001:db8::/32'}) then home=false end" in expr and "os.exit" not in expr
    assert "c=='--'" not in expr
    assert "if home then return {'5.5.5.5','5.5.5.6'} else return {'8.8.4.4'} end" in expr
    monkeypatch.setattr(settings, "lua_selector", "evil'")
    assert "pickrandom({'8.8.4.4'})" in dnsbuild.lua_expression(["5.5.5.5"], ["8.8.4.4"])


def test_lua_ipv6_follows_the_ipv4_pool(monkeypatch):
    """An IPv4-only home pool must not hand Iranian visitors the foreign IPv6 edges."""
    monkeypatch.setattr(settings, "geoip_enabled", True)
    expr = dnsbuild.lua_expression([], ["2a01::1"], home_alive=True, global_alive=True)
    assert "if home then return {} else return ifurlup(" in expr and "{{'2a01::1'}}" in expr
    # the home pool is offline (controller view): everyone gets the foreign edges
    expr = dnsbuild.lua_expression([], ["2a01::1"], home_alive=False, global_alive=True)
    assert expr.startswith(";return ifurlup(") and "countryCode" not in expr


def test_lua_single_pool():
    expr = dnsbuild.lua_expression(["5.5.5.5"], ["8.8.4.4"])
    assert expr.startswith(";return ifurlup(") and "{{'5.5.5.5','8.8.4.4'}}" in expr


def test_diag_record(monkeypatch):
    site = SimpleNamespace(domain="ex.com", records=[rec("@", "A", "1.2.3.4", proxied=True)])
    edges = [edge("5.5.5.5", "home"), edge("8.8.4.4", "global")]
    rr = {(r["name"], r["type"]): r for r in dnsbuild.build_rrsets(site, edges)}
    txt = rr[("_pcdn-geo.ex.com.", "LUA")]["records"][0]["content"]
    assert txt.startswith('TXT ";local c=countryCode()') and "pool='..'all'" in txt
    monkeypatch.setattr(settings, "geoip_enabled", True)
    rr = {(r["name"], r["type"]): r for r in dnsbuild.build_rrsets(site, edges)}
    assert "(home and 'home' or 'global')" in rr[("_pcdn-geo.ex.com.", "LUA")]["records"][0]["content"]
    rr = {(r["name"], r["type"]): r for r in dnsbuild.build_rrsets(site, edges[1:])}
    assert "'global-only'" in rr[("_pcdn-geo.ex.com.", "LUA")]["records"][0]["content"]
    # no proxied record: no diagnostic record either
    plain = SimpleNamespace(domain="ex.com", records=[rec("@", "A", "1.2.3.4")])
    assert not any(r["name"].startswith("_pcdn-geo") for r in dnsbuild.build_rrsets(plain, edges))


def test_build_rrsets_mix():
    site = SimpleNamespace(domain="ex.com", records=[
        rec("@", "A", "1.2.3.4", proxied=True),
        rec("www", "CNAME", "ex.com", proxied=True),
        rec("@", "MX", "mail.ex.com", priority=5),
        rec("_sip._tcp", "SRV", "10 5060 sip.ex.com", priority=1),
        rec("@", "TXT", "x" * 300),
    ])
    rr = {(r["name"], r["type"]): r for r in dnsbuild.build_rrsets(site, [edge("9.9.9.9", "global", "2a01::1")])}
    assert rr[("ex.com.", "MX")]["records"][0]["content"] == "5 mail.ex.com."
    assert rr[("_sip._tcp.ex.com.", "SRV")]["records"][0]["content"] == "1 10 5060 sip.ex.com."
    assert rr[("ex.com.", "TXT")]["records"][0]["content"].count('"') == 4
    lua = [r["content"] for r in rr[("ex.com.", "LUA")]["records"]]
    assert lua[0].startswith('A "') and lua[1].startswith('AAAA "') and "2a01::1" in lua[1]
    assert ("www.ex.com.", "LUA") in rr and ("www.ex.com.", "CNAME") not in rr


def test_is_delegated():
    assert is_delegated(["ns1.example-cdn.com", "ns2.example-cdn.com"])
    assert not is_delegated([])
    assert not is_delegated(["ns1.example-cdn.com", "ns.other.com"])


def test_acme_hook_writes_all_servers(fake_pdns):
    import httpx

    from app import acme_hook, pdns
    from tests.conftest import FakePdns

    second = FakePdns()
    cluster = pdns.PdnsCluster([
        pdns.PdnsClient("http://a", "k", "localhost", transport=httpx.MockTransport(fake_pdns.handler)),
        pdns.PdnsClient("http://b", "k", "localhost", transport=httpx.MockTransport(second.handler)),
    ])
    pdns.set_client(cluster)
    for f in (fake_pdns, second):
        f.zones["ex.com."] = {"name": "ex.com.", "rrsets": []}
    assert acme_hook.main(["add", "_acme-challenge.ex.com", "v1"]) == 0
    assert acme_hook.main(["add", "_acme-challenge.ex.com", "v2"]) == 0  # apex + wildcard
    for f in (fake_pdns, second):
        vals = [r["content"] for r in f.rrset("ex.com.", "_acme-challenge.ex.com.", "TXT")["records"]]
        assert vals == ['"v1"', '"v2"']
    assert acme_hook.main(["rm", "_acme-challenge.ex.com", "v1"]) == 0
    assert acme_hook.main(["rm", "_acme-challenge.ex.com", "v2"]) == 0
    assert second.rrset("ex.com.", "_acme-challenge.ex.com.", "TXT") is None
    assert acme_hook.main(["add", "_acme-challenge.nozone.org", "x"]) == 1
