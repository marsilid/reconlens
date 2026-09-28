import json
from datetime import datetime, timezone

import httpx
import pytest

from reconlens.dnsutil import DnsLookupError, parse_doh_answer
from reconlens.errors import InvalidTargetError, UnknownModuleError
from reconlens.models import Finding, ModuleResult, ScanReport, Severity
from reconlens.modules import ALL_MODULES, get_modules
from reconlens.modules.dns_records import evaluate_dns
from reconlens.modules.subdomains import clean_name, is_sensitive, parse_crtsh
from reconlens.report import render_html
from reconlens.scoring import compute_score, grade_for
from reconlens.usernames import is_bot_challenge, validate_username
from reconlens.utils import normalize_domain, parse_date, registrable_domain


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Example.COM", "example.com"),
        ("https://www.example.com/path?q=1", "www.example.com"),
        ("example.com:8443", "example.com"),
        ("example.com.", "example.com"),
        ("пример.рф", "xn--e1afmkfd.xn--p1ai"),
    ],
)
def test_normalize_domain(raw, expected):
    assert normalize_domain(raw) == expected


@pytest.mark.parametrize("raw", ["localhost", "1.2.3.4", "-bad-.com", "exa mple.com", ""])
def test_normalize_domain_rejects_garbage(raw):
    with pytest.raises(InvalidTargetError):
        normalize_domain(raw)


def test_registrable_domain():
    assert registrable_domain("a.b.example.com") == "example.com"
    assert registrable_domain("shop.example.co.uk") == "example.co.uk"
    assert registrable_domain("mail.example.msk.ru") == "example.msk.ru"


def test_parse_date_formats():
    assert parse_date("2026-06-09T21:00:00Z") == datetime(2026, 6, 9, 21, tzinfo=timezone.utc)
    assert parse_date("09.06.2026").year == 2026
    assert parse_date("not a date") is None


def test_score_and_grade():
    assert compute_score([]) == 100
    assert compute_score([Severity.CRITICAL, Severity.HIGH]) == 60
    assert compute_score([Severity.CRITICAL] * 10) == 0
    assert [grade_for(s) for s in (95, 85, 70, 55, 10)] == ["A", "B", "C", "D", "F"]


def test_module_registry():
    assert len(get_modules()) == len(ALL_MODULES)
    assert [m.name for m in get_modules(["tls", "dns", "tls"])] == ["tls", "dns"]
    with pytest.raises(UnknownModuleError):
        get_modules(["nope"])


def test_doh_parsing_skips_cname_and_joins_txt():
    payload = {
        "Status": 0,
        "Answer": [
            {"type": 5, "data": "alias.example.net."},
            {"type": 16, "data": '"v=spf1 include:a" " -all"'},
        ],
    }
    assert parse_doh_answer(payload, "TXT") == ["v=spf1 include:a -all"]
    assert parse_doh_answer({"Status": 3}, "A") == []
    with pytest.raises(DnsLookupError):
        parse_doh_answer({"Status": 2}, "A")


def test_crtsh_parsing():
    entries = [
        {"name_value": "*.example.com\nwww.example.com"},
        {"name_value": "dev.example.com"},
        {"name_value": "evil-example.com"},
    ]
    assert parse_crtsh(entries, "example.com") == {
        "example.com",
        "www.example.com",
        "dev.example.com",
    }
    assert clean_name("notexample.com", "example.com") is None


def test_sensitive_subdomains():
    assert is_sensitive("jenkins.example.com", "example.com")
    assert is_sensitive("admin-panel.eu.example.com", "example.com")
    assert not is_sensitive("www.example.com", "example.com")


def test_dns_findings():
    records = {"A": ["1.2.3.4"], "NS": ["ns1.example.com."], "CAA": ['0 issue "letsencrypt.org"']}
    got = {f.title for f in evaluate_dns(records, dnssec=True)}
    assert got == {"Single authoritative name server"}


def test_username_validation():
    assert validate_username("@torvalds") == "torvalds"
    with pytest.raises(InvalidTargetError):
        validate_username("../etc/passwd")


def test_bot_challenge_is_not_a_profile():
    page = httpx.Response(
        200, headers={"content-type": "text/html"}, text="<html><title>Client Challenge</title>"
    )
    assert is_bot_challenge(page)
    profile = httpx.Response(
        200, headers={"content-type": "text/html"}, text="<title>Profile</title>"
    )
    assert not is_bot_challenge(profile)


def _sample_report():
    result = ModuleResult(name="http", title="HTTP security", data={"server": "<script>x</script>"})
    result.findings.append(Finding("Missing HSTS", Severity.MEDIUM, "why", "fix", module="http"))
    return ScanReport(
        target="example.com",
        started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        finished_at=datetime(2026, 1, 1, 0, 0, 5, tzinfo=timezone.utc),
        results=[result],
    )


def test_html_report_renders_and_escapes():
    html = render_html(_sample_report())
    assert "example.com" in html
    assert "Missing HSTS" in html
    assert "<script>x</script>" not in html  # data from the target must be escaped
    assert "&lt;script&gt;" in html


def test_codespans_escape_before_formatting():
    report = _sample_report()
    report.results[0].findings[0].recommendation = "Use `-all`, not <b>`+all`</b>"
    html = render_html(report)
    assert "<code>-all</code>" in html
    assert "&lt;b&gt;<code>+all</code>&lt;/b&gt;" in html


def test_report_serialises_to_json():
    data = json.loads(json.dumps(_sample_report().to_dict()))
    assert data["score"] == 93
    assert data["grade"] == "A"
    assert data["severity_counts"]["medium"] == 1
