"""Subdomain discovery from Certificate Transparency logs (fully passive).

Every publicly trusted TLS certificate is logged in CT, so the names on those
certificates reveal a lot of infrastructure without sending a single packet to
the target.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Iterable
from typing import Any

import httpx

from reconlens.context import ScanContext
from reconlens.dnsutil import DnsLookupError
from reconlens.errors import ModuleError
from reconlens.models import Finding, ModuleResult, Severity
from reconlens.modules.base import Module

MAX_RESOLVE = 250
RESOLVE_CONCURRENCY = 25

SENSITIVE_TOKENS = frozenset(
    {
        "admin",
        "dev",
        "develop",
        "test",
        "testing",
        "stage",
        "staging",
        "stg",
        "uat",
        "qa",
        "beta",
        "old",
        "backup",
        "bak",
        "vpn",
        "jenkins",
        "gitlab",
        "git",
        "jira",
        "confluence",
        "grafana",
        "kibana",
        "elastic",
        "prometheus",
        "db",
        "sql",
        "mysql",
        "internal",
        "intranet",
        "owa",
        "remote",
        "rdp",
        "ftp",
        "sftp",
        "monitor",
        "debug",
        "sandbox",
    }
)
_VALID_NAME = re.compile(r"^[a-z0-9.-]+$")


def clean_name(name: str, domain: str) -> str | None:
    candidate = name.strip().lower().lstrip("*.").rstrip(".")
    if not _VALID_NAME.match(candidate):
        return None
    if candidate == domain or candidate.endswith("." + domain):
        return candidate
    return None


def parse_crtsh(entries: Iterable[dict[str, Any]], domain: str) -> set[str]:
    names: set[str] = set()
    for entry in entries:
        for raw in str(entry.get("name_value", "")).split("\n"):
            if cleaned := clean_name(raw, domain):
                names.add(cleaned)
    return names


def parse_certspotter(entries: Iterable[dict[str, Any]], domain: str) -> set[str]:
    names: set[str] = set()
    for entry in entries:
        for raw in entry.get("dns_names", []):
            if cleaned := clean_name(raw, domain):
                names.add(cleaned)
    return names


def is_sensitive(name: str, domain: str) -> bool:
    prefix = name[: -len(domain)].rstrip(".")
    tokens = re.split(r"[.\-_]", prefix)
    return any(token in SENSITIVE_TOKENS for token in tokens)


class SubdomainsModule(Module):
    name = "subdomains"
    title = "Subdomains (CT logs)"
    description = "Subdomains from Certificate Transparency logs (crt.sh, CertSpotter)"

    async def run(self, ctx: ScanContext, result: ModuleResult) -> None:
        names, source = await self._collect(ctx)
        names.discard(ctx.domain)

        ordered = sorted(names)
        to_resolve = ordered[:MAX_RESOLVE]
        semaphore = asyncio.Semaphore(RESOLVE_CONCURRENCY)

        async def lookup(host: str) -> list[str]:
            async with semaphore:
                try:
                    return await ctx.resolver.resolve(host, "A")
                except DnsLookupError:
                    return []

        ips = await asyncio.gather(*(lookup(h) for h in to_resolve))
        rows = [{"name": h, "ips": addrs} for h, addrs in zip(to_resolve, ips, strict=True)]
        resolved = [row for row in rows if row["ips"]]

        result.data = {
            "source": source,
            "total": len(ordered),
            "resolved": len(resolved),
            "resolve_limit": MAX_RESOLVE if len(ordered) > MAX_RESOLVE else None,
            "subdomains": rows,
        }

        if ordered:
            result.findings.append(
                Finding(
                    f"{len(ordered)} subdomains found in Certificate Transparency logs",
                    Severity.INFO,
                    f"{len(resolved)} of the checked names currently resolve to an IP address.",
                )
            )
        sensitive = [row["name"] for row in resolved if is_sensitive(row["name"], ctx.domain)]
        if sensitive:
            shown = ", ".join(sensitive[:10]) + (" …" if len(sensitive) > 10 else "")
            result.findings.append(
                Finding(
                    f"{len(sensitive)} potentially sensitive subdomains are publicly resolvable",
                    Severity.LOW,
                    f"Names that look like admin, dev or internal services: {shown}",
                    "Make sure these hosts are meant to be public; restrict internal tools "
                    "with VPN/IP allow-lists and remove stale DNS records.",
                )
            )

    async def _collect(self, ctx: ScanContext) -> tuple[set[str], str]:
        slow_timeout = max(ctx.timeout, 30.0)
        errors = []
        try:
            resp = await ctx.client.get(
                "https://crt.sh/",
                params={"q": f"%.{ctx.domain}", "output": "json"},
                timeout=slow_timeout,
            )
            resp.raise_for_status()
            return parse_crtsh(resp.json(), ctx.domain), "crt.sh"
        except (httpx.HTTPError, ValueError) as exc:
            errors.append(f"crt.sh: {type(exc).__name__}")

        try:
            resp = await ctx.client.get(
                "https://api.certspotter.com/v1/issuances",
                params={
                    "domain": ctx.domain,
                    "include_subdomains": "true",
                    "expand": "dns_names",
                },
                timeout=slow_timeout,
            )
            resp.raise_for_status()
            return parse_certspotter(resp.json(), ctx.domain), "certspotter"
        except (httpx.HTTPError, ValueError) as exc:
            errors.append(f"certspotter: {type(exc).__name__}")

        raise ModuleError("all CT sources failed (" + "; ".join(errors) + ")")
