"""Module registry. To add a module, implement :class:`Module` and list it here."""

from __future__ import annotations

from collections.abc import Iterable

from reconlens.errors import UnknownModuleError
from reconlens.modules.base import Module
from reconlens.modules.dns_records import DnsModule
from reconlens.modules.email_security import EmailSecurityModule
from reconlens.modules.http_headers import HttpModule
from reconlens.modules.netinfo import NetInfoModule
from reconlens.modules.shodan_ports import ShodanModule
from reconlens.modules.subdomains import SubdomainsModule
from reconlens.modules.tech import TechModule
from reconlens.modules.tls_cert import TlsModule
from reconlens.modules.whois import WhoisModule

ALL_MODULES: tuple[type[Module], ...] = (
    DnsModule,
    WhoisModule,
    SubdomainsModule,
    EmailSecurityModule,
    TlsModule,
    HttpModule,
    TechModule,
    NetInfoModule,
    ShodanModule,
)

__all__ = ["ALL_MODULES", "Module", "get_modules"]


def get_modules(names: Iterable[str] | None = None) -> list[Module]:
    registry = {cls.name: cls for cls in ALL_MODULES}
    wanted = [n.strip().lower() for n in names or () if n.strip()]
    if not wanted:
        return [cls() for cls in ALL_MODULES]
    unknown = [n for n in wanted if n not in registry]
    if unknown:
        raise UnknownModuleError(
            f"unknown module(s): {', '.join(unknown)}. Available: {', '.join(registry)}"
        )
    return [registry[n]() for n in dict.fromkeys(wanted)]
