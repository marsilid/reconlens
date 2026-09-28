from reconlens.models import Severity
from reconlens.modules.netinfo import (
    is_cdn_asname,
    parse_cymru_asname,
    parse_cymru_origin,
    reverse_ip_arpa,
)
from reconlens.modules.shodan_ports import evaluate_ports


def test_reverse_ip_arpa():
    assert reverse_ip_arpa("1.2.3.4") == "4.3.2.1"
    assert reverse_ip_arpa("not-an-ip") is None
    assert reverse_ip_arpa("2606:4700::1") is None  # IPv4 only


def test_parse_cymru_origin():
    info = parse_cymru_origin('"13335 | 1.1.1.0/24 | US | arin | 2010-07-14"')
    assert info == {"asn": "13335", "prefix": "1.1.1.0/24", "country": "US", "registry": "arin"}


def test_parse_cymru_origin_malformed():
    assert parse_cymru_origin("garbage") == {}


def test_parse_cymru_asname():
    assert (
        parse_cymru_asname('"13335 | US | arin | 2010 | CLOUDFLARENET, US"') == "CLOUDFLARENET, US"
    )


def test_is_cdn_asname():
    assert is_cdn_asname("CLOUDFLARENET, US")
    assert is_cdn_asname("DDOS-GUARD LTD")
    assert is_cdn_asname("AKAMAI-AS")
    assert not is_cdn_asname("SELECTEL, RU")
    assert not is_cdn_asname(None)


def test_evaluate_ports_flags_risky():
    findings = evaluate_ports([80, 443, 3306, 22], [])
    risky = next(f for f in findings if "sensitive port" in f.title)
    assert risky.severity == Severity.MEDIUM
    assert "MySQL" in risky.description and "SSH" in risky.description


def test_evaluate_ports_clean():
    assert evaluate_ports([80, 443], []) == []


def test_evaluate_ports_cve_is_high():
    findings = evaluate_ports([443], ["CVE-2021-44228"])
    assert any(f.severity == Severity.HIGH and "CVE" in f.title for f in findings)
