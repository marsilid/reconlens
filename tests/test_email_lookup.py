import pytest

from reconlens.email_lookup import EMAIL_RE, gravatar_hash


@pytest.mark.parametrize(
    "addr",
    ["user@example.com", "a.b+tag@sub.example.co.uk", "name_1@mail.ru"],
)
def test_email_regex_accepts_valid(addr):
    assert EMAIL_RE.match(addr)


@pytest.mark.parametrize("addr", ["nope", "a@b", "@example.com", "user@", "a b@example.com"])
def test_email_regex_rejects_invalid(addr):
    assert not EMAIL_RE.match(addr)


def test_gravatar_hash_is_normalised_md5():
    # Known Gravatar test vector: trimmed + lowercased, then md5.
    assert gravatar_hash("  MyEmailAddress@example.com ") == gravatar_hash(
        "myemailaddress@example.com"
    )
    assert len(gravatar_hash("x@y.com")) == 32
