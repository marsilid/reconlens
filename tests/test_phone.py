import pytest

from reconlens.errors import InvalidTargetError
from reconlens.phone import analyze_phone


def test_russian_mobile():
    r = analyze_phone("+7 900 123 45 67")
    assert r.kind == "phone"
    assert r.target == "+79001234567"
    assert r.summary["Valid"] == "yes"
    assert r.summary["Line type"] == "mobile"
    assert "Russia" in r.summary["Country"] or r.summary["Country"] == "RU"


def test_national_number_uses_default_region():
    r = analyze_phone("495 123 45 67", default_region="RU")
    details = r.sections[0].data
    assert details["country_code"] == "+7"
    assert details["region_code"] == "RU"


def test_us_number():
    r = analyze_phone("+1 650 253 0000")
    assert r.sections[0].data["region_code"] == "US"
    assert any("Los_Angeles" in z for z in r.sections[0].data["time_zones"])


def test_formats_present():
    formats = analyze_phone("+7 900 123 45 67").sections[1].data
    assert formats["e164"] == "+79001234567"
    assert formats["international"].startswith("+7 900")


def test_invalid_but_possible_length():
    r = analyze_phone("+7 900 000 00 00")
    # right length for RU mobile, so parseable; validity depends on allocation
    assert r.summary["Valid"] in {"yes", "possible but not valid"}


def test_garbage_rejected():
    with pytest.raises(InvalidTargetError):
        analyze_phone("not-a-number")


def test_offline_no_network(monkeypatch):
    # Guard: analyze_phone must never open a socket.
    import socket

    def boom(*a, **k):
        raise AssertionError("phone lookup made a network call")

    monkeypatch.setattr(socket, "socket", boom)
    analyze_phone("+7 900 123 45 67")
