from datetime import datetime, timedelta, timezone

from reconlens.models import Severity
from reconlens.modules.whois import evaluate_registration, parse_rdap, parse_whois

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)

RU_WHOIS = """% TCI Whois Service. Terms of use:
domain:        EXAMPLE.RU
nserver:       ns1.example.ru. 192.0.2.1
nserver:       ns2.example.ru.
state:         REGISTERED, DELEGATED, VERIFIED
org:           OOO "Example"
registrar:     RU-CENTER-RU
created:       2004-06-08T20:00:00Z
paid-till:     2026-06-09T21:00:00Z
"""

RDAP = {
    "ldhName": "EXAMPLE.COM",
    "status": ["client transfer prohibited"],
    "events": [
        {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2026-08-13T04:00:00Z"},
    ],
    "entities": [
        {
            "roles": ["registrar"],
            "vcardArray": [
                "vcard",
                [["version", {}, "text", "4.0"], ["fn", {}, "text", "Registrar Inc."]],
            ],
        }
    ],
    "nameservers": [{"ldhName": "A.IANA-SERVERS.NET"}],
}


def test_parse_ru_whois():
    info = parse_whois(RU_WHOIS)
    assert info["registrar"] == "RU-CENTER-RU"
    assert info["expires"] == "2026-06-09T21:00:00Z"
    assert info["nameservers"] == ["ns1.example.ru", "ns2.example.ru"]
    assert info["status"] == ["REGISTERED", "DELEGATED", "VERIFIED"]


def test_parse_rdap():
    info = parse_rdap(RDAP)
    assert info["registrar"] == "Registrar Inc."
    assert info["created"] == "1995-08-14T04:00:00Z"
    assert info["nameservers"] == ["a.iana-servers.net"]


def test_healthy_registration_has_no_findings():
    assert evaluate_registration(parse_rdap(RDAP), NOW) == []


def test_expiring_soon_is_high():
    info = {"source": "rdap", "expires": (NOW + timedelta(days=5)).isoformat()}
    [finding] = evaluate_registration(info, NOW)
    assert finding.severity == Severity.HIGH


def test_expired_is_critical():
    info = {"source": "whois", "expires": "2025-12-01T00:00:00Z"}
    [finding] = evaluate_registration(info, NOW)
    assert finding.severity == Severity.CRITICAL


def test_missing_transfer_lock():
    info = {**parse_rdap(RDAP), "status": ["active"]}
    assert any(f.title == "No registrar transfer lock" for f in evaluate_registration(info, NOW))


def test_transfer_lock_not_checked_for_raw_whois():
    # .ru statuses like REGISTERED/DELEGATED have no EPP transfer lock concept.
    assert evaluate_registration(parse_whois(RU_WHOIS), NOW) == []
