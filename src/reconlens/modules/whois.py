"""Domain registration data via RDAP, with a raw WHOIS (port 43) fallback.

RDAP is the structured JSON successor of WHOIS, but some registries (including
.ru/.рф) still only speak classic WHOIS, so both are supported.
"""

from __future__ import annotations

import asyncio
import contextlib
from datetime import datetime, timezone
from typing import Any

import httpx

from reconlens.context import ScanContext
from reconlens.errors import ModuleError
from reconlens.models import Finding, ModuleResult, Severity
from reconlens.modules.base import Module
from reconlens.utils import parse_date, registrable_domain

RDAP_URL = "https://rdap.org/domain/{}"
IANA_WHOIS = "whois.iana.org"

WHOIS_FIELDS: dict[str, tuple[str, ...]] = {
    "registrar": ("registrar", "sponsoring registrar", "registrar name"),
    "created": ("creation date", "created", "registration time", "domain registration date"),
    "expires": (
        "registry expiry date",
        "registrar registration expiration date",
        "expiration date",
        "expiry date",
        "paid-till",
        "expires",
        "expire date",
    ),
    "updated": ("updated date", "last updated", "last-modified", "changed"),
    "status": ("domain status", "status", "state"),
    "nameservers": ("name server", "nserver", "nameserver"),
    "org": ("registrant organization", "org"),
}
_LIST_FIELDS = ("status", "nameservers")


def parse_rdap(doc: dict[str, Any]) -> dict[str, Any]:
    events = {e.get("eventAction"): e.get("eventDate") for e in doc.get("events", [])}
    registrar = None
    for entity in doc.get("entities", []):
        if "registrar" in entity.get("roles", []):
            registrar = _vcard_name(entity) or entity.get("handle")
    nameservers = sorted(
        ns["ldhName"].lower().rstrip(".") for ns in doc.get("nameservers", []) if ns.get("ldhName")
    )
    return {
        "source": "rdap",
        "registrar": registrar,
        "created": events.get("registration"),
        "updated": events.get("last changed"),
        "expires": events.get("expiration"),
        "status": doc.get("status", []),
        "nameservers": nameservers,
    }


def _vcard_name(entity: dict[str, Any]) -> str | None:
    vcard = entity.get("vcardArray")
    if isinstance(vcard, list) and len(vcard) == 2:
        for item in vcard[1]:
            if item and item[0] == "fn":
                return str(item[3])
    return None


def parse_whois(text: str) -> dict[str, Any]:
    info: dict[str, Any] = {"source": "whois", "status": [], "nameservers": []}
    for line in text.splitlines():
        stripped = line.strip()
        if ":" not in stripped or stripped.startswith(("%", "#", ">>>")):
            continue
        key, _, value = stripped.partition(":")
        key, value = key.strip().lower(), value.strip()
        if not value:
            continue
        for field_name, keys in WHOIS_FIELDS.items():
            if key not in keys:
                continue
            if field_name == "nameservers":
                ns = value.split()[0].lower().rstrip(".")
                if ns not in info["nameservers"]:
                    info["nameservers"].append(ns)
            elif field_name == "status":
                # "clientTransferProhibited https://icann.org/..." or "REGISTERED, DELEGATED"
                parts = (
                    [p.strip() for p in value.split(",")] if "," in value else [value.split()[0]]
                )
                info["status"].extend(p for p in parts if p)
            else:
                info.setdefault(field_name, value)
    return info


def evaluate_registration(info: dict[str, Any], now: datetime) -> list[Finding]:
    findings: list[Finding] = []

    expires = parse_date(info.get("expires"))
    if expires is not None:
        days_left = (expires - now).days
        info["days_until_expiry"] = days_left
        if days_left < 0:
            findings.append(
                Finding(
                    "Domain registration has expired",
                    Severity.CRITICAL,
                    f"The registration expired {-days_left} days ago; the domain can be "
                    "taken over by anyone once it is released.",
                    "Renew the domain immediately and enable auto-renewal.",
                )
            )
        elif days_left < 14:
            findings.append(
                Finding(
                    f"Domain expires in {days_left} days",
                    Severity.HIGH,
                    "An expired domain takes the website and e-mail offline and can be "
                    "re-registered by a third party.",
                    "Renew the domain and enable auto-renewal.",
                )
            )
        elif days_left < 45:
            findings.append(
                Finding(
                    f"Domain expires in {days_left} days",
                    Severity.MEDIUM,
                    "The renewal date is close.",
                    "Make sure auto-renewal is on and the payment method is valid.",
                )
            )

    created = parse_date(info.get("created"))
    if created is not None:
        age = (now - created).days
        info["age_days"] = age
        if age < 30:
            findings.append(
                Finding(
                    f"Recently registered domain ({age} days old)",
                    Severity.INFO,
                    "Freshly registered domains are a common trait of phishing campaigns. "
                    "Relevant when you are investigating a suspicious domain.",
                )
            )

    if info.get("source") == "rdap" and info.get("status"):
        normalized = {s.replace(" ", "").lower() for s in info["status"]}
        if not any("transferprohibited" in s for s in normalized):
            findings.append(
                Finding(
                    "No registrar transfer lock",
                    Severity.LOW,
                    "Without clientTransferProhibited the domain is easier to hijack via a "
                    "fraudulent transfer request.",
                    "Enable the transfer lock (a.k.a. registrar lock) in the registrar panel.",
                )
            )
    return findings


async def whois_query(server: str, query: str, timeout: float) -> str:
    reader, writer = await asyncio.wait_for(asyncio.open_connection(server, 43), timeout)
    try:
        writer.write(f"{query}\r\n".encode())
        await writer.drain()
        data = await asyncio.wait_for(reader.read(), timeout)
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
    return data.decode("utf-8", errors="replace")


class WhoisModule(Module):
    name = "whois"
    title = "WHOIS / RDAP"
    description = "Registrar, registration and expiry dates, domain status"

    async def run(self, ctx: ScanContext, result: ModuleResult) -> None:
        domain = registrable_domain(ctx.domain)
        info = await self._rdap(ctx, domain) or await self._whois(ctx, domain)
        info["domain"] = domain
        result.findings.extend(evaluate_registration(info, datetime.now(timezone.utc)))
        result.data = info

    async def _rdap(self, ctx: ScanContext, domain: str) -> dict[str, Any] | None:
        try:
            resp = await ctx.client.get(RDAP_URL.format(domain))
        except httpx.HTTPError:
            return None
        if resp.status_code != 200:
            return None
        try:
            return parse_rdap(resp.json())
        except ValueError:
            return None

    async def _whois(self, ctx: ScanContext, domain: str) -> dict[str, Any]:
        tld = domain.rsplit(".", 1)[-1]
        try:
            iana = await whois_query(IANA_WHOIS, tld, ctx.timeout)
            server = next(
                (
                    line.split(":", 1)[1].strip()
                    for line in iana.splitlines()
                    if line.lower().startswith(("refer:", "whois:"))
                ),
                None,
            )
            if not server:
                raise ModuleError(f"no WHOIS server known for .{tld}")
            raw = await whois_query(server, domain, ctx.timeout)
        except (OSError, TimeoutError) as exc:
            raise ModuleError(f"WHOIS lookup failed: {exc or type(exc).__name__}") from exc
        info = parse_whois(raw)
        info["whois_server"] = server
        return info
