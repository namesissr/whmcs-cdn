"""deploy/geoip-build.py: DB-IP + RIPE registrations -> the nameservers' country database."""

import importlib.util
import ipaddress
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "deploy" / "geoip-build.py"


@pytest.fixture(scope="module")
def gb():
    spec = importlib.util.spec_from_file_location("geoip_build", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def cc(data, cont):
    return {"country": {"iso_code": data, "names": {"en": data}}, "continent": {"code": cont}}


def test_ripe_home_ranges_override_dbip(gb, tmp_path):
    src = tmp_path / "dbip.mmdb"
    net = ipaddress.ip_network
    gb.write_mmdb(str(src), [
        (net("2.176.0.0/12"), cc("IR", "AS")),
        (net("194.88.0.0/16"), cc("DE", "EU")),      # a leased Iranian /24 inside is placed in DE
        (net("8.8.8.0/24"), cc("US", "NA")),
        (net("2a00:1ce0::/32"), cc("DE", "EU")),
        (net("2a01:4f8::/32"), cc("DE", "EU")),
    ], "test source")
    ripe = tmp_path / "ripe.txt"
    ripe.write_text(
        "2|ripencc|20260928|5|19830705|20260927|+0100\n"
        "ripencc|IR|ipv4|194.88.232.0|256|20250806|allocated|x\n"
        "ripencc|IR|ipv6|2a00:1ce0::|32|20120101|allocated|x\n"
        "ripencc|DE|ipv4|91.98.0.0|65536|20060911|allocated|x\n"
        "ripencc|IR|ipv4|5.160.0.0|768|20120101|assigned|x\n")   # 3 x /24, not a power of two
    over = tmp_path / "overrides.txt"
    over.write_text("# comment\n8.8.8.0/25 IR\n")
    out = tmp_path / "country.mmdb"
    rc = gb.main(["--dbip", str(src), "--ripe", str(ripe), "--overrides", str(over), "--out", str(out),
                  "--expect", "194.88.232.145=IR", "--expect", "194.88.233.1=DE"])
    assert rc == 0
    r = gb.Reader(str(out))

    def look(ip):
        return (r.lookup(ip) or {}).get("country", {}).get("iso_code")

    assert look("2.176.0.1") == "IR"
    assert look("194.88.232.145") == "IR" and look("194.88.231.255") == "DE" and look("194.88.233.0") == "DE"
    assert look("5.160.2.9") == "IR" and look("5.160.3.0") is None
    assert look("8.8.8.1") == "IR" and look("8.8.8.200") == "US"
    assert look("2a00:1ce0::1") == "IR" and look("2a01:4f8::1") == "DE"
    assert look("9.9.9.9") is None
    # PowerDNS reads only the codes: the rest is dropped
    assert r.lookup("2.176.0.1") == {"country": {"iso_code": "IR"}, "continent": {"code": "AS"}}
    assert r.meta["ip_version"] == 6 and r.meta["record_size"] in (24, 32)


def test_self_check_fails_on_wrong_expectation(gb, tmp_path):
    src = tmp_path / "dbip.mmdb"
    gb.write_mmdb(str(src), [(ipaddress.ip_network("8.8.8.0/24"), cc("US", "NA"))], "t")
    assert gb.main(["--dbip", str(src), "--out", str(tmp_path / "o.mmdb"), "--expect", "8.8.8.8=IR"]) == 1


def test_missing_home_country_in_ripe_file_fails(gb, tmp_path):
    src = tmp_path / "dbip.mmdb"
    gb.write_mmdb(str(src), [(ipaddress.ip_network("8.8.8.0/24"), cc("US", "NA"))], "t")
    ripe = tmp_path / "ripe.txt"
    ripe.write_text("ripencc|DE|ipv4|91.98.0.0|65536|20060911|allocated|x\n")
    assert gb.main(["--dbip", str(src), "--ripe", str(ripe), "--out", str(tmp_path / "o.mmdb")]) == 1
