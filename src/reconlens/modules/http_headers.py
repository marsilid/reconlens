"""HTTP security headers, cookies, redirects, security.txt and robots.txt."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

import httpx

from reconlens.context import ScanContext
from reconlens.models import Finding, ModuleResult, Severity
from reconlens.modules.base import Module

HSTS_MIN_AGE = 15_552_000  # 180 days
ROBOTS_INTERESTING = re.compile(
    r"admin|backup|private|secret|internal|login|config|\.git|\.env|api|dump|old|test", re.I
)


# (header, severity when missing, why it matters, recommended value)
SECURITY_HEADERS: tuple[tuple[str, Severity, str, str], ...] = (
    (
        "strict-transport-security",
        Severity.MEDIUM,
        "Browsers may be downgraded to plain HTTP by an attacker on the network.",
        "Strict-Transport-Security: max-age=31536000; includeSubDomains",
    ),
    (
        "content-security-policy",
        Severity.MEDIUM,
        "No second line of defence against XSS and injected third-party scripts.",
        "Start with Content-Security-Policy-Report-Only and tighten it iteratively.",
    ),
    (
        "x-frame-options",
        Severity.LOW,
        "The site can be embedded in a frame on another site (clickjacking).",
        "X-Frame-Options: DENY (or CSP frame-ancestors 'none').",
    ),
    (
        "x-content-type-options",
        Severity.LOW,
        "Browsers may MIME-sniff responses and execute uploaded files as scripts.",
        "X-Content-Type-Options: nosniff",
    ),
    (
        "referrer-policy",
        Severity.LOW,
        "Full URLs, including tokens in query strings, may leak to third-party sites.",
        "Referrer-Policy: strict-origin-when-cross-origin",
    ),
    (
        "permissions-policy",
        Severity.INFO,
        "Embedded content is not restricted from using camera, microphone, geolocation, etc.",
        "Permissions-Policy: camera=(), microphone=(), geolocation=()",
    ),
)


def parse_cookie(raw: str) -> dict[str, Any]:
    parts = [p.strip() for p in raw.split(";")]
    name = parts[0].split("=", 1)[0]
    attrs = {p.split("=", 1)[0].lower() for p in parts[1:]}
    return {
        "name": name,
        "secure": "secure" in attrs,
        "httponly": "httponly" in attrs,
        "samesite": "samesite" in attrs,
    }


def analyze_headers(
    headers: Mapping[str, str], set_cookies: list[str], *, https: bool
) -> tuple[dict[str, Any], list[Finding]]:
    h = {k.lower(): v for k, v in headers.items()}
    findings: list[Finding] = []
    present: dict[str, str] = {}
    missing: list[str] = []

    csp = h.get("content-security-policy", "")
    for header, severity, why, recommendation in SECURITY_HEADERS:
        if header in h:
            present[header] = h[header]
            continue
        if header == "strict-transport-security" and not https:
            continue  # HSTS is meaningless over plain HTTP
        if header == "x-frame-options" and "frame-ancestors" in csp.lower():
            continue  # CSP frame-ancestors supersedes X-Frame-Options
        missing.append(header)
        findings.append(Finding(f"Missing {_pretty(header)} header", severity, why, recommendation))

    hsts = h.get("strict-transport-security")
    if hsts:
        match = re.search(r"max-age\s*=\s*(\d+)", hsts, re.I)
        if match and int(match.group(1)) < HSTS_MIN_AGE:
            findings.append(
                Finding(
                    "HSTS max-age is short",
                    Severity.LOW,
                    f"max-age={match.group(1)} seconds is less than the recommended 180 days.",
                    "Use max-age=31536000 (one year).",
                )
            )

    server = h.get("server", "")
    if re.search(r"\d", server):
        findings.append(
            Finding(
                "Server version disclosed",
                Severity.LOW,
                f"The Server header reveals '{server}', which helps an attacker pick exploits.",
                "Hide version numbers (nginx: server_tokens off; Apache: ServerTokens Prod).",
            )
        )
    leaking = {
        k: h[k] for k in ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version") if k in h
    }
    if leaking:
        shown = ", ".join(f"{_pretty(k)}: {v}" for k, v in leaking.items())
        findings.append(
            Finding(
                "Technology stack disclosed in headers",
                Severity.LOW,
                f"Response headers reveal {shown}.",
                "Remove X-Powered-By and similar headers in the application or proxy.",
            )
        )

    if h.get("access-control-allow-origin") == "*":
        findings.append(
            Finding(
                "CORS allows any origin",
                Severity.INFO,
                "Access-Control-Allow-Origin: * on the main page. Harmless for public "
                "content, dangerous if the same policy is applied to authenticated APIs.",
            )
        )

    cookies = [parse_cookie(c) for c in set_cookies]
    weak = [
        c["name"]
        for c in cookies
        if not c["httponly"] or not c["samesite"] or (https and not c["secure"])
    ]
    if weak:
        findings.append(
            Finding(
                "Cookies without Secure/HttpOnly/SameSite flags",
                Severity.LOW,
                f"Cookies missing protective attributes: {', '.join(sorted(set(weak)))}.",
                "Set Secure, HttpOnly and SameSite=Lax (or Strict) on session cookies.",
            )
        )

    data = {
        "server": server or None,
        "present": present,
        "missing": missing,
        "cookies": cookies,
    }
    return data, findings


def parse_robots(text: str) -> list[str]:
    paths = []
    for line in text.splitlines():
        key, _, value = line.partition(":")
        if key.strip().lower() == "disallow" and value.strip():
            paths.append(value.strip())
    return paths


def _pretty(header: str) -> str:
    return "-".join(part.capitalize() for part in header.split("-"))


class HttpModule(Module):
    name = "http"
    title = "HTTP security"
    description = "Security headers, cookies, HTTP→HTTPS redirect, security.txt, robots.txt"

    async def run(self, ctx: ScanContext, result: ModuleResult) -> None:
        page = await ctx.homepage()
        data, findings = analyze_headers(page.headers, page.cookies, https=page.https)
        data = {"url": page.url, "status": page.status, **data}

        if not page.https:
            findings.append(
                Finding(
                    "Website is served without HTTPS",
                    Severity.HIGH,
                    "Traffic, including logins and cookies, travels in clear text.",
                    "Obtain a free certificate (Let's Encrypt) and redirect all HTTP to HTTPS.",
                )
            )
        else:
            data["http_redirects_to_https"] = await self._redirects_to_https(ctx)
            if data["http_redirects_to_https"] is False:
                findings.append(
                    Finding(
                        "HTTP does not redirect to HTTPS",
                        Severity.MEDIUM,
                        "Visitors who type the bare domain stay on unencrypted HTTP.",
                        "Return a 301 redirect from http:// to https:// for every path.",
                    )
                )

        base = f"{'https' if page.https else 'http'}://{ctx.domain}"
        security_txt = await self._get_text(ctx, f"{base}/.well-known/security.txt")
        data["security_txt"] = bool(security_txt and "contact:" in security_txt.lower())
        if not data["security_txt"]:
            findings.append(
                Finding(
                    "No security.txt",
                    Severity.INFO,
                    "Researchers have no documented way to report vulnerabilities.",
                    "Publish /.well-known/security.txt with Contact and Expires (RFC 9116).",
                )
            )

        robots = await self._get_text(ctx, f"{base}/robots.txt")
        if robots and "user-agent" in robots.lower():
            disallowed = parse_robots(robots)
            data["robots_disallow"] = disallowed[:50]
            interesting = [p for p in disallowed if ROBOTS_INTERESTING.search(p)]
            if interesting:
                findings.append(
                    Finding(
                        "robots.txt reveals interesting paths",
                        Severity.INFO,
                        "robots.txt is public and is read by attackers too: "
                        + ", ".join(interesting[:10]),
                        "Do not rely on robots.txt to hide anything; protect these paths "
                        "with authentication.",
                    )
                )

        result.data = data
        result.findings.extend(findings)

    @staticmethod
    async def _redirects_to_https(ctx: ScanContext) -> bool | None:
        try:
            resp = await ctx.insecure_client.get(f"http://{ctx.domain}/")
        except httpx.HTTPError:
            return None  # port 80 closed: nothing to redirect
        return resp.url.scheme == "https"

    @staticmethod
    async def _get_text(ctx: ScanContext, url: str) -> str | None:
        try:
            resp = await ctx.insecure_client.get(url)
        except httpx.HTTPError:
            return None
        if resp.status_code != 200:
            return None
        return resp.text[:100_000]
