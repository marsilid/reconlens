"""E-mail address intelligence from public signals only.

Checks the *domain* an address belongs to (does mail even route there, is it a
free or disposable provider, what does its anti-spoofing posture look like) plus
whether a public Gravatar exists for the address hash. It never sends mail, never
tries SMTP ``VRFY``, and cannot confirm that a specific mailbox exists — only that
the domain can receive mail.
"""

from __future__ import annotations

import hashlib
import re

import httpx

from reconlens.dnsutil import DnsLookupError, create_resolver
from reconlens.errors import InvalidTargetError
from reconlens.models import LookupReport, LookupSection
from reconlens.scanner import _client

# Deliberately simple: a full RFC 5322 validator is overkill for a triage tool.
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})$")

FREE_PROVIDERS = frozenset(
    {
        "gmail.com",
        "googlemail.com",
        "yahoo.com",
        "ymail.com",
        "outlook.com",
        "hotmail.com",
        "live.com",
        "msn.com",
        "icloud.com",
        "me.com",
        "aol.com",
        "protonmail.com",
        "proton.me",
        "gmx.com",
        "gmx.net",
        "zoho.com",
        "yandex.ru",
        "yandex.com",
        "ya.ru",
        "mail.ru",
        "bk.ru",
        "list.ru",
        "inbox.ru",
        "internet.ru",
        "rambler.ru",
        "tutanota.com",
    }
)
DISPOSABLE_PROVIDERS = frozenset(
    {
        "mailinator.com",
        "guerrillamail.com",
        "10minutemail.com",
        "temp-mail.org",
        "tempmail.com",
        "throwawaymail.com",
        "yopmail.com",
        "getnada.com",
        "trashmail.com",
        "sharklasers.com",
        "maildrop.cc",
        "dispostable.com",
        "fakeinbox.com",
        "mvrht.com",
        "mohmal.com",
        "1secmail.com",
        "emailondeck.com",
        "spam4.me",
        "vpmm.ru",
        "temp-mail.ru",
    }
)


def gravatar_hash(email: str) -> str:
    return hashlib.md5(email.strip().lower().encode()).hexdigest()


async def _has_gravatar(client: httpx.AsyncClient, email: str) -> bool | None:
    """d=404 makes Gravatar 404 when there is no custom avatar for the hash."""
    url = f"https://www.gravatar.com/avatar/{gravatar_hash(email)}?d=404"
    try:
        resp = await client.get(url)
    except httpx.HTTPError:
        return None
    if resp.status_code == 200:
        return True
    if resp.status_code == 404:
        return False
    return None


async def analyze_email(raw: str, *, timeout: float = 10.0) -> LookupReport:
    match = EMAIL_RE.match(raw.strip())
    if not match:
        raise InvalidTargetError(f"'{raw}' is not a valid e-mail address")
    email = raw.strip()
    domain = match.group(1).lower()

    async with _client(timeout, verify=True) as client:
        resolver, note = await create_resolver("auto", timeout, client)
        try:
            mx = await resolver.resolve(domain, "MX")
        except DnsLookupError:
            mx = []
        try:
            spf = [
                r for r in await resolver.resolve(domain, "TXT") if r.lower().startswith("v=spf1")
            ]
        except DnsLookupError:
            spf = []
        try:
            dmarc = [
                r
                for r in await resolver.resolve(f"_dmarc.{domain}", "TXT")
                if r.lower().startswith("v=dmarc1")
            ]
        except DnsLookupError:
            dmarc = []
        gravatar = await _has_gravatar(client, email)

    is_free = domain in FREE_PROVIDERS
    is_disposable = domain in DISPOSABLE_PROVIDERS
    deliverable = bool(mx)

    provider = (
        "disposable" if is_disposable else "free webmail" if is_free else "custom / corporate"
    )
    summary = {
        "Domain": domain,
        "Provider type": provider,
        "Domain can receive mail": "yes" if deliverable else "no (no MX record)",
        "Public Gravatar": {True: "yes", False: "no", None: "unknown"}[gravatar],
    }

    details = {
        "address": email,
        "domain": domain,
        "free_provider": is_free,
        "disposable_provider": is_disposable,
        "deliverable_domain": deliverable,
        "mx_records": sorted(mx),
        "has_spf": bool(spf),
        "has_dmarc": bool(dmarc),
        "gravatar": gravatar,
        "gravatar_hash": gravatar_hash(email),
    }

    notes: list[str] = [
        "This describes the address's domain, not the mailbox. It cannot confirm that "
        f"'{email}' specifically exists — only that {domain} is set up to receive mail.",
    ]
    if note:
        notes.append(note)
    if is_disposable:
        notes.append("The domain is a known disposable/temporary e-mail provider.")
    if not deliverable:
        notes.append("No MX record: mail sent to this domain would bounce.")

    return LookupReport(
        kind="email",
        target=email,
        summary=summary,
        sections=[LookupSection("Details", data=details)],
        notes=notes,
        disclaimer=(
            "Uses public DNS and the public Gravatar API only. No mail is sent and no mailbox "
            "is probed. Use for a lawful purpose."
        ),
    )
