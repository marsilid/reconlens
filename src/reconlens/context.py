"""Shared state handed to every module during a scan."""

from __future__ import annotations

import asyncio
import ssl
from dataclasses import dataclass, field

import httpx

from reconlens.dnsutil import DnsResolver
from reconlens.errors import ModuleError

MAX_HTML_CHARS = 1_000_000


def _is_tls_error(exc: BaseException | None) -> bool:
    """Walk the exception chain: httpx wraps ssl errors in ConnectError."""
    while exc is not None:
        if isinstance(exc, ssl.SSLError):
            return True
        exc = exc.__cause__ or exc.__context__
    return False


@dataclass(slots=True)
class HomePage:
    url: str
    status: int
    headers: httpx.Headers
    cookies: list[str]
    html: str
    https: bool
    tls_verified: bool


@dataclass
class ScanContext:
    domain: str
    client: httpx.AsyncClient
    insecure_client: httpx.AsyncClient
    resolver: DnsResolver
    timeout: float
    _homepage: HomePage | None = field(default=None, init=False, repr=False)
    _homepage_error: str | None = field(default=None, init=False, repr=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False, repr=False)

    async def homepage(self) -> HomePage:
        """Fetch the site's main page once and share it between modules."""
        async with self._lock:
            if self._homepage is None and self._homepage_error is None:
                try:
                    self._homepage = await self._fetch_homepage()
                except ModuleError as exc:
                    self._homepage_error = str(exc)
        if self._homepage_error is not None:
            raise ModuleError(self._homepage_error)
        assert self._homepage is not None
        return self._homepage

    async def _fetch_homepage(self) -> HomePage:
        # Try a properly verified HTTPS first, then tolerate a broken certificate
        # (the TLS module reports it), then fall back to plain HTTP.
        attempts = (
            (self.client, f"https://{self.domain}/", True),
            (self.insecure_client, f"https://{self.domain}/", False),
            (self.insecure_client, f"http://{self.domain}/", False),
        )
        last_error: Exception | None = None
        for client, url, verified in attempts:
            if not verified and url.startswith("https") and not _is_tls_error(last_error):
                continue  # port 443 is closed/filtered: retrying without verification won't help
            try:
                resp = await client.get(url)
            except httpx.HTTPError as exc:
                last_error = exc
                continue
            is_https = resp.url.scheme == "https"
            return HomePage(
                url=str(resp.url),
                status=resp.status_code,
                headers=resp.headers,
                cookies=resp.headers.get_list("set-cookie"),
                html=resp.text[:MAX_HTML_CHARS],
                https=is_https,
                tls_verified=verified and is_https,
            )
        raise ModuleError(f"website is unreachable ({type(last_error).__name__}: {last_error})")
