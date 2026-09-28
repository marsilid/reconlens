"""DNS records and basic DNS hygiene checks."""

from __future__ import annotations

import asyncio

from reconlens.context import ScanContext
from reconlens.models import Finding, ModuleResult, Severity
from reconlens.modules.base import Module

RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CAA", "SOA")


def evaluate_dns(records: dict[str, list[str]], *, dnssec: bool) -> list[Finding]:
    findings: list[Finding] = []
    if not records.get("A") and not records.get("AAAA"):
        findings.append(
            Finding(
                "Domain has no A/AAAA records",
                Severity.INFO,
                "The name does not point to any IP address, so there is no website on it.",
            )
        )
    if not records.get("CAA"):
        findings.append(
            Finding(
                "No CAA record",
                Severity.LOW,
                "Any certificate authority is allowed to issue certificates for this domain, "
                "which widens the options for a mis-issued certificate.",
                'Publish a CAA record for the CA you use, e.g. `0 issue "letsencrypt.org"`.',
            )
        )
    if len(records.get("NS", [])) == 1:
        findings.append(
            Finding(
                "Single authoritative name server",
                Severity.LOW,
                "If this server goes down, the whole domain stops resolving.",
                "Use at least two name servers on different networks (RFC 2182).",
            )
        )
    if not dnssec:
        findings.append(
            Finding(
                "DNSSEC is not enabled",
                Severity.LOW,
                "DNS answers are not signed, so resolvers cannot detect spoofed responses.",
                "Enable DNSSEC at your DNS provider and publish the DS record at the registrar.",
            )
        )
    return findings


class DnsModule(Module):
    name = "dns"
    title = "DNS records"
    description = "A, AAAA, MX, NS, TXT, CAA, SOA records and DNSSEC status"

    async def run(self, ctx: ScanContext, result: ModuleResult) -> None:
        answers = await asyncio.gather(
            *(ctx.resolver.resolve(ctx.domain, rtype) for rtype in RECORD_TYPES)
        )
        records = {
            rtype: sorted(values)
            for rtype, values in zip(RECORD_TYPES, answers, strict=True)
            if values
        }
        dnssec = bool(await ctx.resolver.resolve(ctx.domain, "DNSKEY"))

        result.data = {"records": records, "dnssec": dnssec}
        result.findings.extend(evaluate_dns(records, dnssec=dnssec))
