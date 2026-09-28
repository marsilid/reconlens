"""Runs the selected modules concurrently against one domain."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable, Sequence
from datetime import datetime, timezone

import httpx

from reconlens import __version__
from reconlens.context import ScanContext
from reconlens.dnsutil import ResolverMode, create_resolver
from reconlens.errors import ModuleError, TargetNotFoundError
from reconlens.models import ModuleResult, ScanReport
from reconlens.modules.base import Module

USER_AGENT = f"Mozilla/5.0 (compatible; ReconLens/{__version__}; passive OSINT scanner)"
DEFAULT_HEADERS = {"User-Agent": USER_AGENT, "Accept": "*/*"}

ResultCallback = Callable[[ModuleResult], None]


def _client(timeout: float, *, verify: bool) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=True,
        verify=verify,
        headers=DEFAULT_HEADERS,
        limits=httpx.Limits(max_connections=30),
    )


async def scan_domain(
    domain: str,
    modules: Sequence[Module],
    *,
    timeout: float = 10.0,
    resolver_mode: ResolverMode = "auto",
    on_result: ResultCallback | None = None,
) -> ScanReport:
    report = ScanReport(target=domain, started_at=datetime.now(timezone.utc))

    async with _client(timeout, verify=True) as client, _client(timeout, verify=False) as insecure:
        resolver, note = await create_resolver(resolver_mode, timeout, client)
        report.dns_backend = resolver.kind
        if note:
            report.notes.append(note)
        if not await resolver.exists(domain):
            raise TargetNotFoundError(f"{domain} does not exist (NXDOMAIN)")

        ctx = ScanContext(
            domain=domain,
            client=client,
            insecure_client=insecure,
            resolver=resolver,
            timeout=timeout,
        )
        # A generous hard cap so one hanging data source cannot stall the report.
        module_timeout = max(60.0, timeout * 6)
        results = await asyncio.gather(
            *(_run_module(m, ctx, module_timeout, on_result) for m in modules)
        )

    report.results = list(results)
    report.finished_at = datetime.now(timezone.utc)
    return report


async def _run_module(
    module: Module,
    ctx: ScanContext,
    module_timeout: float,
    on_result: ResultCallback | None,
) -> ModuleResult:
    result = ModuleResult(name=module.name, title=module.title)
    started = time.perf_counter()
    try:
        await asyncio.wait_for(module.run(ctx, result), module_timeout)
    except ModuleError as exc:
        result.error = str(exc)
    except TimeoutError:
        result.error = f"timed out after {module_timeout:.0f}s"
    except Exception as exc:  # one broken module must never kill the whole scan
        result.error = f"{type(exc).__name__}: {exc}"
    result.duration = time.perf_counter() - started
    for finding in result.findings:
        finding.module = module.name
    if on_result is not None:
        on_result(result)
    return result
