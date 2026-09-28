import httpx

from reconlens.usernames import (
    SITES,
    UsernameResult,
    by_status,
    is_bot_challenge,
    json_nonempty_list,
    text_absent,
    text_present,
    username_report,
)


def _resp(status=200, text="", ctype="text/html"):
    return httpx.Response(status, headers={"content-type": ctype}, text=text)


def test_all_sites_have_placeholder_and_category():
    for s in SITES:
        assert "{}" in s.check_url and "{}" in s.profile_url
        assert s.category


def test_no_duplicate_site_names():
    names = [s.name for s in SITES]
    assert len(names) == len(set(names))


def test_by_status():
    assert by_status(_resp(200)) is True
    assert by_status(_resp(404)) is False
    assert by_status(_resp(403)) is None


def test_text_present_and_absent_are_opposites():
    exists = _resp(200, "…tgme_page_title…")
    missing = _resp(200, "nothing here")
    assert text_present("tgme_page_title")(exists) is True
    assert text_present("tgme_page_title")(missing) is False
    assert text_absent("could not be found")(_resp(200, "profile page")) is True
    assert text_absent("could not be found")(_resp(200, "could not be found")) is False


def test_json_nonempty_list():
    assert json_nonempty_list(_resp(200, "[{}]", "application/json")) is True
    assert json_nonempty_list(_resp(200, "[]", "application/json")) is False


def test_bot_challenge_detection():
    assert is_bot_challenge(_resp(200, "<title>Just a moment...</title>"))
    assert not is_bot_challenge(_resp(200, "<title>torvalds</title>"))


def test_username_report_counts_and_notes():
    results = [
        UsernameResult("GitHub", "https://github.com/x", "found", "", "Dev"),
        UsernameResult("Steam", "https://steam/x", "not found", "", "Gaming"),
        UsernameResult("Reddit", "https://reddit/x", "unknown", "HTTP 403", "Community"),
    ]
    report = username_report("x", results)
    assert report.summary["Found on"] == "1 of 3 sites"
    assert report.sections[0].rows[0]["site"] == "GitHub"  # found sorts first
    assert report.notes  # carries the "names collide" caveat
