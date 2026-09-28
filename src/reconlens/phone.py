"""Offline phone-number intelligence built on Google's libphonenumber data.

Everything here is computed from the metadata bundled with the ``phonenumbers``
package: no network request is ever made, and no personal data is looked up.
It tells you *about the number itself* (country, region, original carrier,
line type, time zones) — not who owns it.

The carrier and region come from the number's allocation block. Since numbers
can be ported between carriers, the carrier is the one it was *issued* by, not
necessarily the current one; the report says so.
"""

from __future__ import annotations

from typing import Any

import phonenumbers
from phonenumbers import (
    NumberParseException,
    PhoneNumberType,
    carrier,
    geocoder,
    is_valid_number,
    number_type,
    region_code_for_number,
    timezone,
)

from reconlens.errors import InvalidTargetError
from reconlens.models import LookupReport, LookupSection

DISCLAIMER = (
    "All data is derived offline from the public libphonenumber dataset and describes the "
    "number's allocation only. It does not identify the subscriber. Ported numbers may now "
    "belong to a different carrier. Look up numbers only for a lawful purpose."
)

_TYPE_LABEL = {
    PhoneNumberType.MOBILE: "mobile",
    PhoneNumberType.FIXED_LINE: "fixed line",
    PhoneNumberType.FIXED_LINE_OR_MOBILE: "fixed line or mobile",
    PhoneNumberType.TOLL_FREE: "toll-free",
    PhoneNumberType.PREMIUM_RATE: "premium rate",
    PhoneNumberType.SHARED_COST: "shared cost",
    PhoneNumberType.VOIP: "VoIP",
    PhoneNumberType.PERSONAL_NUMBER: "personal number",
    PhoneNumberType.PAGER: "pager",
    PhoneNumberType.UAN: "UAN",
    PhoneNumberType.VOICEMAIL: "voicemail",
    PhoneNumberType.UNKNOWN: "unknown",
}


def analyze_phone(raw: str, default_region: str = "RU", lang: str = "en") -> LookupReport:
    """Parse and describe a phone number entirely offline."""
    cleaned = raw.strip()
    try:
        # A leading '+' means the number is already international; otherwise we
        # interpret it in ``default_region``.
        number = phonenumbers.parse(cleaned, None if cleaned.startswith("+") else default_region)
    except NumberParseException as exc:
        raise InvalidTargetError(f"could not parse '{raw}' as a phone number: {exc}") from exc

    valid = is_valid_number(number)
    possible = phonenumbers.is_possible_number(number)
    region = region_code_for_number(number)
    ntype = number_type(number)
    issued_carrier = carrier.name_for_number(number, lang) or None
    location = geocoder.description_for_number(number, lang) or None
    zones = list(timezone.time_zones_for_number(number))
    if zones == ["Etc/Unknown"]:
        zones = []

    formats = {
        "e164": phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.E164),
        "international": phonenumbers.format_number(
            number, phonenumbers.PhoneNumberFormat.INTERNATIONAL
        ),
        "national": phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.NATIONAL),
        "rfc3966": phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.RFC3966),
    }

    summary: dict[str, Any] = {
        "Valid": "yes" if valid else ("possible but not valid" if possible else "no"),
        "Country": _country(region, number.country_code),
        "Line type": _TYPE_LABEL.get(ntype, "unknown"),
    }
    if location:
        summary["Region"] = location
    if issued_carrier:
        summary["Carrier (at issue)"] = issued_carrier

    details = {
        "input": raw,
        "country_code": f"+{number.country_code}",
        "region_code": region,
        "national_number": str(number.national_number),
        "valid": valid,
        "possible": possible,
        "line_type": _TYPE_LABEL.get(ntype, "unknown"),
        "issued_carrier": issued_carrier,
        "location": location,
        "time_zones": zones,
    }

    notes: list[str] = []
    if not valid and possible:
        notes.append(
            "The number has a plausible length for its country but is not in an assigned range — "
            "it may be fictional, mistyped, or not yet allocated."
        )
    if issued_carrier and ntype == PhoneNumberType.MOBILE:
        notes.append(
            "Carrier reflects the original allocation block. If the number was ported, the "
            "current operator may differ."
        )

    sections = [
        LookupSection("Number details", data=details),
        LookupSection("Formats", data=formats),
    ]
    if zones:
        sections.append(LookupSection("Time zones", rows=[{"time_zone": z} for z in zones]))

    return LookupReport(
        kind="phone",
        target=formats["e164"] if valid or possible else raw,
        summary=summary,
        sections=sections,
        notes=notes,
        disclaimer=DISCLAIMER,
    )


def _country(region: str | None, code: int) -> str:
    if not region:
        return f"+{code}"
    try:
        import pycountry  # optional; nicer country names when installed

        match = pycountry.countries.get(alpha_2=region)
        if match:
            return f"{match.name} ({region})"
    except Exception:
        pass
    return region
