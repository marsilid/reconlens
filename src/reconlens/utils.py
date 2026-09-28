"""Small helpers shared across modules."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from urllib.parse import urlsplit

from reconlens.errors import InvalidTargetError

_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")

# Public suffixes with two labels that are common enough to matter. A full
# Public Suffix List would be more accurate; this keeps the tool dependency-free.
_TWO_LABEL_SUFFIXES = frozenset(
    {
        "co.uk",
        "org.uk",
        "ac.uk",
        "gov.uk",
        "com.au",
        "net.au",
        "org.au",
        "co.jp",
        "com.br",
        "com.tr",
        "com.cn",
        "co.il",
        "com.ua",
        "org.ua",
        "com.kz",
        "org.kz",
        "com.ru",
        "net.ru",
        "org.ru",
        "pp.ru",
        "msk.ru",
        "spb.ru",
        "com.by",
    }
)

_DATE_FORMATS = ("%Y.%m.%d", "%d-%b-%Y", "%Y/%m/%d", "%d.%m.%Y", "%Y-%m-%d %H:%M:%S")


def normalize_domain(raw: str) -> str:
    """Accept a domain or URL (IDN allowed) and return a lowercase ASCII hostname."""
    value = raw.strip().lower()
    if "://" in value:
        value = urlsplit(value).hostname or ""
    else:
        value = value.split("/", 1)[0].split(":", 1)[0]
    value = value.rstrip(".")

    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise InvalidTargetError(f"'{raw}' is not a valid domain name") from exc

    labels = value.split(".")
    if (
        len(labels) < 2
        or not all(_LABEL_RE.match(label) for label in labels)
        or labels[-1].isdigit()
    ):
        raise InvalidTargetError(f"'{raw}' is not a valid domain name")
    return value


def registrable_domain(domain: str) -> str:
    """Best-effort 'example.co.uk' from 'www.shop.example.co.uk'."""
    labels = domain.split(".")
    size = 3 if ".".join(labels[-2:]) in _TWO_LABEL_SUFFIXES else 2
    return ".".join(labels[-size:])


def parse_date(value: str | None) -> datetime | None:
    """Parse the zoo of date formats found in WHOIS/RDAP into an aware datetime."""
    if not value:
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        for fmt in _DATE_FORMATS:
            try:
                parsed = datetime.strptime(text, fmt)
                break
            except ValueError:
                continue
        else:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed
