from reconlens.models import Severity
from reconlens.modules.tech import detect, evaluate_tech


def names(techs):
    return {t["name"] for t in techs}


def test_detects_server_and_version_from_headers():
    techs, _ = detect({"Server": "nginx/1.18.0"}, [], "")
    nginx = next(t for t in techs if t["name"] == "nginx")
    assert nginx["version"] == "1.18.0"
    assert nginx["evidence"] == "header server"


def test_detects_wordpress_and_generator():
    html = '<meta name="generator" content="WordPress 6.4.2"><link href="/wp-content/x.css">'
    techs, generator = detect({}, [], html)
    wp = next(t for t in techs if t["name"] == "WordPress")
    assert wp["version"] == "6.4.2"
    assert generator == "WordPress 6.4.2"


def test_detects_bitrix_by_cookie():
    techs, _ = detect({}, ["BITRIX_SM_GUEST_ID=1; path=/"], "")
    assert "1C-Bitrix" in names(techs)


def test_jquery_version_parsing():
    techs, _ = detect({}, [], '<script src="/js/jquery-3.4.1.min.js"></script>')
    jq = next(t for t in techs if t["name"] == "jQuery")
    assert jq["version"] == "3.4.1"


def test_jquery_without_version():
    techs, _ = detect({}, [], '<script src="/js/jquery.min.js"></script>')
    jq = next(t for t in techs if t["name"] == "jQuery")
    assert jq["version"] is None


def test_outdated_jquery_is_medium():
    techs, _ = detect({}, [], '<script src="jquery-1.12.4.min.js"></script>')
    findings = evaluate_tech(techs)
    assert any(f.severity == Severity.MEDIUM and "jQuery 1.12.4" in f.title for f in findings)


def test_current_jquery_is_fine():
    techs, _ = detect({}, [], '<script src="jquery-3.7.1.min.js"></script>')
    assert not any("jQuery" in f.title for f in evaluate_tech(techs))


def test_cdn_detection():
    techs, _ = detect({"Server": "cloudflare", "CF-RAY": "abc"}, [], "")
    assert "Cloudflare" in names(techs)
    assert any("behind Cloudflare" in f.title for f in evaluate_tech(techs))


def test_nothing_detected_on_empty_page():
    assert detect({}, [], "") == ([], None)
