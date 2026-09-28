"""Open ports and services from Shodan's InternetDB — a free, key-less endpoint.

InternetDB (https://internetdb.shodan.io) returns whatever Shodan already knows
about an IP from its own periodic scanning. We do not scan anything ourselves:
the port data was collected by Shodan, and we just look it up, which keeps the
tool passive. Only the site's own front IP is queried.
"""

from __future__ import annotations

import httpx

from reconlens.context import ScanContext
from reconlens.models import Finding, ModuleResult, Severity
from reconlens.modules.base import Module

INTERNETDB = "https://internetdb.shodan.io/{}"

# Ports that should almost never be open to the whole Internet on a web host.
RISKY_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    135: "MSRPC",
    139: "NetBIOS",
    445: "SMB",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
}


def evaluate_ports(ports: list[int], vulns: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    risky = {p: RISKY_PORTS[p] for p in ports if p in RISKY_PORTS}
    if risky:
        shown = ", ".join(f"{svc} ({port})" for port, svc in sorted(risky.items()))
        findings.append(
            Finding(
                f"{len(risky)} sensitive port(s) exposed to the Internet",
                Severity.MEDIUM,
                f"Shodan reports these management/database ports open: {shown}. Databases and "
                "remote-access services should not be reachable from the whole Internet.",
                "Firewall these ports to trusted IPs or a VPN; expose only 80/443 publicly.",
            )
        )
    if vulns:
        shown = ", ".join(sorted(vulns)[:10])
        findings.append(
            Finding(
                f"Shodan flags {len(vulns)} known CVE(s) on this host",
                Severity.HIGH,
                f"Shodan matched service banners to known vulnerabilities: {shown}. These are "
                "heuristic matches from banners, so confirm before acting.",
                "Patch the affected services and re-check.",
            )
        )
    return findings


class ShodanModule(Module):
    name = "shodan"
    title = "Open ports (Shodan)"
    description = "Open ports and known CVEs from Shodan InternetDB (no scanning, no key)"

    async def run(self, ctx: ScanContext, result: ModuleResult) -> None:
        ips = await ctx.resolver.resolve(ctx.domain, "A")
        if not ips:
            result.data = {"note": "domain has no A record"}
            return
        ip = ips[0]
        try:
            resp = await ctx.client.get(INTERNETDB.format(ip))
        except httpx.HTTPError as exc:
            result.error = f"InternetDB unreachable: {type(exc).__name__}"
            return
        if resp.status_code == 404:
            result.data = {"ip": ip, "note": "Shodan has no data for this IP"}
            return
        if resp.status_code != 200:
            result.error = f"InternetDB returned HTTP {resp.status_code}"
            return
        try:
            data = resp.json()
        except ValueError:
            result.error = "InternetDB returned invalid JSON"
            return

        ports = sorted(data.get("ports", []))
        vulns = data.get("vulns", [])
        result.data = {
            "ip": ip,
            "ports": ports,
            "hostnames": data.get("hostnames", []),
            "cpes": data.get("cpes", []),
            "vulns": vulns,
        }
        result.findings.extend(evaluate_ports(ports, vulns))
