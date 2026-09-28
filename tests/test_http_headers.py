from reconlens.models import Severity
from reconlens.modules.http_headers import analyze_headers, parse_cookie, parse_robots

GOOD_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=()",
    "Server": "nginx",
}


def test_hardened_site_has_no_findings():
    data, findings = analyze_headers(GOOD_HEADERS, [], https=True)
    assert findings == []
    assert data["missing"] == []


def test_frame_ancestors_replaces_x_frame_options():
    data, _ = analyze_headers(GOOD_HEADERS, [], https=True)
    assert "x-frame-options" not in data["missing"]


def test_bare_site_reports_missing_headers():
    data, findings = analyze_headers({}, [], https=True)
    assert "strict-transport-security" in data["missing"]
    assert any(f.title == "Missing Content-Security-Policy header" for f in findings)


def test_hsts_not_required_over_plain_http():
    data, _ = analyze_headers({}, [], https=False)
    assert "strict-transport-security" not in data["missing"]


def test_header_lookup_is_case_insensitive():
    data, _ = analyze_headers({"x-content-type-options": "nosniff"}, [], https=True)
    assert "x-content-type-options" not in data["missing"]


def test_version_disclosure():
    _, findings = analyze_headers(
        {"Server": "Apache/2.4.29 (Ubuntu)", "X-Powered-By": "PHP/7.2.1"}, [], https=True
    )
    got = {f.title for f in findings}
    assert "Server version disclosed" in got
    assert "Technology stack disclosed in headers" in got


def test_short_hsts():
    _, findings = analyze_headers(
        {**GOOD_HEADERS, "Strict-Transport-Security": "max-age=300"}, [], https=True
    )
    assert [f.title for f in findings] == ["HSTS max-age is short"]


def test_insecure_cookie_flagged():
    _, findings = analyze_headers(GOOD_HEADERS, ["sid=abc; Path=/"], https=True)
    cookie = next(f for f in findings if "Cookies" in f.title)
    assert cookie.severity == Severity.LOW
    assert "sid" in cookie.description


def test_parse_cookie_flags():
    c = parse_cookie("session=1; Secure; HttpOnly; SameSite=Lax; Path=/")
    assert c == {"name": "session", "secure": True, "httponly": True, "samesite": True}


def test_parse_robots():
    text = "User-agent: *\nDisallow: /admin/\nDisallow:\nAllow: /public\nDisallow: /backup"
    assert parse_robots(text) == ["/admin/", "/backup"]
