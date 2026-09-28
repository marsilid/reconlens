from reconlens.models import Severity
from reconlens.modules.email_security import (
    dkim_has_key,
    evaluate_email,
    is_null_mx,
    parse_dmarc,
    parse_spf,
    spoofing_risk,
)


def titles(findings):
    return {f.title for f in findings}


def test_parse_spf_counts_lookups_and_all():
    spf = parse_spf("v=spf1 ip4:1.2.3.4 include:_spf.google.com mx a:mail.example.com ~all")
    assert spf["all"] == "~"
    assert spf["dns_lookups"] == 3
    assert spf["uses_ptr"] is False


def test_parse_spf_redirect():
    spf = parse_spf("v=spf1 redirect=_spf.example.com")
    assert spf["redirect"] == "_spf.example.com"
    assert spf["all"] is None


def test_parse_dmarc_tags():
    tags = parse_dmarc("v=DMARC1; p=reject; rua=mailto:d@example.com; pct=50")
    assert tags == {"v": "DMARC1", "p": "reject", "rua": "mailto:d@example.com", "pct": "50"}


def test_missing_everything_is_high_risk():
    data, findings = evaluate_email(True, [], [], [])
    assert data["spoofing_risk"] == "high"
    high = {f.title for f in findings if f.severity == Severity.HIGH}
    assert high == {"No SPF record", "No DMARC policy"}


def test_well_configured_domain_has_no_real_findings():
    data, findings = evaluate_email(
        True,
        ["v=spf1 include:_spf.google.com -all"],
        ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"],
        ["google"],
    )
    assert data["spoofing_risk"] == "low"
    assert findings == []


def test_plus_all_is_flagged():
    _, findings = evaluate_email(True, ["v=spf1 +all"], ["v=DMARC1; p=reject; rua=mailto:x@y"], [])
    assert "SPF allows any sender (+all)" in titles(findings)


def test_multiple_spf_records():
    _, findings = evaluate_email(True, ["v=spf1 -all", "v=spf1 mx -all"], [], [])
    assert "Multiple SPF records" in titles(findings)


def test_too_many_spf_lookups():
    record = "v=spf1 " + " ".join(f"include:s{i}.example.com" for i in range(11)) + " -all"
    _, findings = evaluate_email(True, [record], ["v=DMARC1; p=reject; rua=mailto:x@y"], [])
    assert "SPF needs 11 DNS lookups (limit is 10)" in titles(findings)


def test_dmarc_none_policy_is_medium():
    _, findings = evaluate_email(True, ["v=spf1 -all"], ["v=DMARC1; p=none; rua=mailto:x@y"], [])
    medium = {f.title for f in findings if f.severity == Severity.MEDIUM}
    assert "DMARC policy is 'none' (monitoring only)" in medium


def test_missing_spf_is_low_when_dmarc_enforces():
    _, findings = evaluate_email(True, [], ["v=DMARC1; p=reject; rua=mailto:x@y"], [])
    spf = next(f for f in findings if f.title == "No SPF record")
    assert spf.severity == Severity.LOW


def test_inherited_dmarc_uses_subdomain_policy():
    data, findings = evaluate_email(
        False,
        [],
        ["v=DMARC1; p=reject; sp=none; rua=mailto:x@y"],
        [],
        dmarc_inherited_from="example.com",
    )
    assert data["dmarc_inherited_from"] == "example.com"
    assert data["spoofing_risk"] == "high"  # sp=none wins for the subdomain
    assert "DMARC policy is 'none' (monitoring only)" in titles(findings)


def test_null_mx_skips_reporting_advice():
    _, findings = evaluate_email(False, ["v=spf1 -all"], ["v=DMARC1; p=reject"], [], null_mx=True)
    assert "DMARC aggregate reports are not collected" not in titles(findings)


def test_null_mx_detection():
    assert is_null_mx(["0 ."])
    assert not is_null_mx(["10 mx.example.com."])
    assert not is_null_mx([])


def test_revoked_dkim_key_is_not_a_key():
    # example.com publishes this wildcard to say "no DKIM here".
    assert not dkim_has_key("v=DKIM1; p=")
    assert dkim_has_key("v=DKIM1; k=rsa; p=MIIBIjANBgkqh")


def test_spoofing_risk_levels():
    assert spoofing_risk(None, {"p": "reject"}) == "low"
    assert spoofing_risk(parse_spf("v=spf1 -all"), None) == "medium"
    assert spoofing_risk(parse_spf("v=spf1 ~all"), {"p": "none"}) == "high"
