"""Network intelligence: ASN, hosting country, CDN/WAF classification and — when
the site sits behind a CDN — a search for the real origin IP that leaks through
adjacent DNS records.

ASN and network data come from Team Cymru's free public IP-to-ASN service, which
answers over DNS (no API key, designed for exactly this). Origin-leak hunting is
fully passive: it resolves a short list of hostnames the operator already
publishes (MX, and conventional names like ``direct``/``origin``/``cpanel``) and
notices when one points to an IP in a *different* network than the CDN — a
classic way a real server address escapes from behind Cloudflare.
"""

from __future__ import annotations

import asyncio
import ipaddress
from typing import Any

from reconlens.context import ScanContext
from reconlens.dnsutil import DnsLookupError
from reconlens.models import Finding, ModuleResult, Severity
from reconlens.modules.base import Module

# AS-name fragments for a true reverse-proxy CDN / WAF / anti-DDoS front. Only
# these hide an origin, so only these justify an origin-leak search. General
# cloud hosting (AWS/GCP/Azure) IS the origin, so it is tracked separately below.
CDN_AS_MARKERS = (
    "cloudflare",
    "akamai",
    "fastly",
    "incapsula",
    "imperva",
    "sucuri",
    "stackpath",
    "cloudfront",
    "ddos-guard",
    "qrator",
    "g-core",
    "gcore",
    "limelight",
    "edgecast",
    "bunny",
    "keycdn",
    "cdn77",
)
# Cloud/hosting providers: reported for context, but not treated as a CDN front.
CLOUD_AS_MARKERS = (
    "amazon",
    "google",
    "microsoft",
    "azure",
    "digitalocean",
    "hetzner",
    "ovh",
    "linode",
    "selectel",
    "timeweb",
    "reg.ru",
    "yandex",
)
# Hostnames that operators often leave pointing straight at the origin server.
ORIGIN_HINT_HOSTS = (
    "direct",
    "origin",
    "cpanel",
    "webmail",
    "mail",
    "ftp",
    "direct-connect",
    "server",
    "host",
    "vps",
    "web",
    "portal",
    "old",
)
RESOLVE_CONCURRENCY = 15


def reverse_ip_arpa(ip: str) -> str | None:
    """'1.2.3.4' -> '4.3.2.1' for the Cymru origin.asn.cymru.com query."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.version != 4:
        return None  # Cymru IPv6 uses a different zone; keep it simple, IPv4 only
    return ".".join(reversed(ip.split(".")))


def parse_cymru_origin(txt: str) -> dict[str, str]:
    """Parse '13335 | 1.1.1.0/24 | US | arin | 2010-07-14' from origin.asn.cymru.com."""
    parts = [p.strip() for p in txt.strip('"').split("|")]
    if len(parts) < 5:
        return {}
    return {"asn": parts[0], "prefix": parts[1], "country": parts[2], "registry": parts[3]}


def parse_cymru_asname(txt: str) -> str | None:
    """Parse '13335 | US | arin | ... | CLOUDFLARENET, US' from AS<n>.asn.cymru.com."""
    parts = [p.strip() for p in txt.strip('"').split("|")]
    return parts[-1] if parts else None


def is_cdn_asname(as_name: str | None) -> bool:
    name = (as_name or "").lower()
    return any(marker in name for marker in CDN_AS_MARKERS)


def is_cloud_asname(as_name: str | None) -> bool:
    name = (as_name or "").lower()
    return any(marker in name for marker in CLOUD_AS_MARKERS)


class NetInfoModule(Module):
    name = "netinfo"
    title = "Network / ASN"
    description = "Hosting ASN, country and network owner; CDN detection; origin-IP leak search"

    async def run(self, ctx: ScanContext, result: ModuleResult) -> None:
        front_ips = await ctx.resolver.resolve(ctx.domain, "A")
        if not front_ips:
            result.data = {"note": "domain has no A record"}
            return

        front = await self._describe_ips(ctx, front_ips)
        behind_cdn = any(row["is_cdn"] for row in front)
        result.data = {
            "front_ips": front,
            "behind_cdn": behind_cdn,
            "hosting_country": _first_country(front),
        }

        cdn_asns = {row["asn"] for row in front if row["is_cdn"] and row["asn"]}
        if behind_cdn:
            cdn_names = sorted(
                {row["as_name"] for row in front if row["is_cdn"] and row["as_name"]}
            )
            result.findings.append(
                Finding(
                    f"Site is fronted by a CDN/WAF ({', '.join(cdn_names) or 'unknown'})",
                    Severity.INFO,
                    "The visible IP belongs to a CDN, which hides the origin server. The origin "
                    "can still leak through DNS records that point straight at it.",
                )
            )
            leaks = await self._find_origin_leaks(ctx, cdn_asns)
            result.data["origin_candidates"] = leaks
            if leaks:
                shown = ", ".join(f"{r['host']} → {r['ip']} ({r['as_name']})" for r in leaks[:5])
                result.findings.append(
                    Finding(
                        f"Possible origin IP behind the CDN ({len(leaks)} candidate(s))",
                        Severity.MEDIUM,
                        "These hostnames resolve to IPs outside the CDN network, so they may be "
                        f"the real origin server, letting an attacker bypass the CDN/WAF: {shown}",
                        "Proxy every public hostname through the CDN, move mail to a separate "
                        "domain, and firewall the origin to accept traffic only from the CDN.",
                    )
                )
        else:
            result.findings.append(
                Finding(
                    "Server is directly exposed (no CDN/WAF in front)",
                    Severity.INFO,
                    "The website IP is reachable directly, with no CDN or anti-DDoS layer.",
                )
            )

    async def _describe_ips(self, ctx: ScanContext, ips: list[str]) -> list[dict[str, Any]]:
        rows = await asyncio.gather(*(self._asn_for_ip(ctx, ip) for ip in sorted(set(ips))))
        return [r for r in rows if r]

    async def _asn_for_ip(self, ctx: ScanContext, ip: str) -> dict[str, Any] | None:
        arpa = reverse_ip_arpa(ip)
        if arpa is None:
            return {"ip": ip, "asn": None, "as_name": None, "country": None, "is_cdn": False}
        try:
            origin = await ctx.resolver.resolve(f"{arpa}.origin.asn.cymru.com", "TXT")
        except DnsLookupError:
            origin = []
        info = parse_cymru_origin(origin[0]) if origin else {}
        asn = info.get("asn", "").split()[0] if info.get("asn") else None
        as_name = None
        if asn:
            try:
                name_txt = await ctx.resolver.resolve(f"AS{asn}.asn.cymru.com", "TXT")
                as_name = parse_cymru_asname(name_txt[0]) if name_txt else None
            except DnsLookupError:
                pass
        return {
            "ip": ip,
            "asn": f"AS{asn}" if asn else None,
            "as_name": as_name,
            "country": info.get("country"),
            "is_cdn": is_cdn_asname(as_name),
        }

    async def _find_origin_leaks(
        self, ctx: ScanContext, cdn_asns: set[str]
    ) -> list[dict[str, Any]]:
        semaphore = asyncio.Semaphore(RESOLVE_CONCURRENCY)

        async def probe(host: str) -> list[str]:
            async with semaphore:
                try:
                    return await ctx.resolver.resolve(host, "A")
                except DnsLookupError:
                    return []

        names = [f"{h}.{ctx.domain}" for h in ORIGIN_HINT_HOSTS]
        mx = await self._mx_hosts(ctx)
        names.extend(mx)
        answers = await asyncio.gather(*(probe(h) for h in names))

        candidates: list[dict[str, Any]] = []
        seen: set[str] = set()
        for host, ips in zip(names, answers, strict=True):
            for ip in ips:
                if ip in seen:
                    continue
                seen.add(ip)
                row = await self._asn_for_ip(ctx, ip)
                # A different, non-CDN ASN is the interesting case.
                if row and not row["is_cdn"] and row["asn"] and row["asn"] not in cdn_asns:
                    candidates.append({"host": host, **row})
        return candidates

    async def _mx_hosts(self, ctx: ScanContext) -> list[str]:
        try:
            mx = await ctx.resolver.resolve(ctx.domain, "MX")
        except DnsLookupError:
            return []
        hosts = []
        for record in mx:
            parts = record.split()
            if len(parts) == 2 and parts[1] not in (".", ""):
                hosts.append(parts[1].rstrip("."))
        return hosts


def _first_country(rows: list[dict[str, Any]]) -> str | None:
    for row in rows:
        if row.get("country"):
            return row["country"]
    return None
