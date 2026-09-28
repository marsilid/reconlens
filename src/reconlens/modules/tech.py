"""Technology fingerprinting from headers, cookies and page markup."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from reconlens.context import ScanContext
from reconlens.models import Finding, ModuleResult, Severity
from reconlens.modules.base import Module


@dataclass(frozen=True)
class Signature:
    """How to recognise one technology. A regex group, if any, captures the version."""

    name: str
    category: str
    headers: Mapping[str, str] = field(default_factory=dict)
    html: tuple[str, ...] = ()
    cookies: tuple[str, ...] = ()


SIGNATURES: tuple[Signature, ...] = (
    # Web servers
    Signature("nginx", "Web server", headers={"server": r"nginx(?:/([\d.]+))?"}),
    Signature("Apache", "Web server", headers={"server": r"apache(?:/([\d.]+))?"}),
    Signature("Microsoft IIS", "Web server", headers={"server": r"microsoft-iis(?:/([\d.]+))?"}),
    Signature("LiteSpeed", "Web server", headers={"server": r"litespeed"}),
    Signature("OpenResty", "Web server", headers={"server": r"openresty(?:/([\d.]+))?"}),
    # CDN / WAF / anti-DDoS
    Signature("Cloudflare", "CDN / WAF", headers={"server": r"cloudflare", "cf-ray": r"."}),
    Signature("DDoS-Guard", "CDN / WAF", headers={"server": r"ddos-guard"}),
    Signature("Qrator", "CDN / WAF", headers={"server": r"qrator"}),
    Signature("Varnish", "Cache", headers={"via": r"varnish", "x-varnish": r"."}),
    # Languages and frameworks
    Signature(
        "PHP", "Language", headers={"x-powered-by": r"php(?:/([\d.]+))?"}, cookies=("PHPSESSID",)
    ),
    Signature(
        "ASP.NET",
        "Framework",
        headers={"x-aspnet-version": r"([\d.]+)", "x-powered-by": r"asp\.net"},
        cookies=("ASP.NET_SessionId",),
    ),
    Signature("Express", "Framework", headers={"x-powered-by": r"express"}),
    Signature("Laravel", "Framework", cookies=("laravel_session",)),
    Signature("Django", "Framework", html=(r"csrfmiddlewaretoken",)),
    Signature(
        "Next.js",
        "Framework",
        headers={"x-powered-by": r"next\.js"},
        html=(r"__NEXT_DATA__", r"/_next/static/"),
    ),
    Signature("Nuxt", "Framework", html=(r"__NUXT__", r"/_nuxt/")),
    # CMS and site builders
    Signature(
        "WordPress",
        "CMS",
        html=(r"<meta[^>]+content=[\"']WordPress ([\d.]+)", r"/wp-content/", r"/wp-includes/"),
    ),
    Signature("Joomla", "CMS", html=(r"<meta[^>]+content=[\"']Joomla", r"/media/jui/")),
    Signature(
        "Drupal",
        "CMS",
        headers={"x-generator": r"drupal\s?(\d+)?"},
        html=(r"drupal-settings-json", r"/sites/default/files/"),
    ),
    Signature(
        "1C-Bitrix",
        "CMS",
        headers={"x-powered-cms": r"bitrix"},
        html=(r"/bitrix/(?:js|templates|cache)/",),
        cookies=("BITRIX_SM",),
    ),
    Signature("MODX", "CMS", headers={"x-powered-by": r"modx"}),
    Signature("Tilda", "Site builder", html=(r"tildacdn\.com", r"tilda-blocks")),
    Signature("Wix", "Site builder", headers={"x-wix-request-id": r"."}, html=(r"wixstatic\.com",)),
    Signature("Nethouse", "Site builder", html=(r"nethouse\.ru",)),
    Signature("uKit / uCoz", "Site builder", html=(r"ucoz\.(?:net|ru)", r"uapp\.ukit")),
    Signature("Shopify", "E-commerce", headers={"x-shopid": r"."}, html=(r"cdn\.shopify\.com",)),
    Signature("InSales", "E-commerce", html=(r"insales(?:-cdn)?\.(?:ru|com)",)),
    Signature(
        "OpenCart", "E-commerce", html=(r"catalog/view/(?:theme|javascript)/", r"route=product")
    ),
    Signature(
        "WooCommerce", "E-commerce", html=(r"woocommerce(?:\.min)?\.(?:js|css)", r"wc-block")
    ),
    Signature("Magento", "E-commerce", cookies=("X-Magento-Vary",), html=(r"/static/version\d+/",)),
    # Front-end libraries
    Signature("Angular", "JS framework", html=(r"ng-version=[\"']([\d.]+)",)),
    Signature(
        "React", "JS framework", html=(r"data-reactroot", r"react(?:-dom)?\.production\.min\.js")
    ),
    Signature(
        "Vue.js", "JS framework", html=(r"data-v-[0-9a-f]{8}", r"vue(?:\.runtime)?(?:\.min)?\.js")
    ),
    Signature("jQuery", "JS library", html=(r"jquery[.-]?([\d.]+)?(?:\.min)?\.js",)),
    Signature(
        "Bootstrap", "UI framework", html=(r"bootstrap@([\d.]+)", r"bootstrap(?:\.min)?\.css")
    ),
    # Analytics
    Signature("Yandex.Metrika", "Analytics", html=(r"mc\.yandex\.ru/metrika", r"\bym\(\d+")),
    Signature(
        "Google Analytics / GTM",
        "Analytics",
        html=(r"googletagmanager\.com", r"google-analytics\.com"),
    ),
)

_GENERATOR_RE = re.compile(r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']([^\"']+)", re.I)


def _version(match: re.Match[str]) -> str | None:
    if match.groups() and match.group(1) and any(ch.isdigit() for ch in match.group(1)):
        return match.group(1).strip(".")
    return None


def detect(
    headers: Mapping[str, str], cookies: list[str], html: str
) -> tuple[list[dict[str, Any]], str | None]:
    h = {k.lower(): v for k, v in headers.items()}
    cookie_names = {c.split("=", 1)[0].strip() for c in cookies}
    found: list[dict[str, Any]] = []

    for sig in SIGNATURES:
        version: str | None = None
        evidence: str | None = None
        for header, pattern in sig.headers.items():
            if header in h and (m := re.search(pattern, h[header], re.I)):
                evidence = f"header {header}"
                version = version or _version(m)
        for pattern in sig.html:
            if m := re.search(pattern, html, re.I):
                evidence = evidence or "page markup"
                version = version or _version(m)
        for cookie in sig.cookies:
            # Prefix match: Bitrix sets BITRIX_SM_GUEST_ID, BITRIX_SM_LOGIN, ...
            if any(name.startswith(cookie) for name in cookie_names):
                evidence = evidence or f"cookie {cookie}"
        if evidence:
            found.append(
                {
                    "name": sig.name,
                    "category": sig.category,
                    "version": version,
                    "evidence": evidence,
                }
            )

    generator = _GENERATOR_RE.search(html)
    return found, generator.group(1).strip() if generator else None


def _version_tuple(version: str) -> tuple[int, ...]:
    return tuple(int(p) for p in re.findall(r"\d+", version)[:3])


def evaluate_tech(technologies: list[dict[str, Any]]) -> list[Finding]:
    findings: list[Finding] = []
    by_name = {t["name"]: t for t in technologies}

    jquery = by_name.get("jQuery")
    if jquery and jquery["version"] and _version_tuple(jquery["version"]) < (3, 5, 0):
        findings.append(
            Finding(
                f"Outdated jQuery {jquery['version']}",
                Severity.MEDIUM,
                "jQuery before 3.5.0 is affected by XSS issues CVE-2020-11022 and "
                "CVE-2020-11023 in its HTML manipulation methods.",
                "Upgrade jQuery to the latest 3.x release.",
            )
        )

    waf = [t["name"] for t in technologies if t["category"] == "CDN / WAF"]
    if waf:
        findings.append(
            Finding(
                f"Site is behind {', '.join(waf)}",
                Severity.INFO,
                "A CDN/WAF hides the origin server IP. Origin IPs can still leak through "
                "DNS history, subdomains or e-mail headers.",
            )
        )

    for cms in ("WordPress", "Joomla", "Drupal", "1C-Bitrix"):
        if cms in by_name:
            findings.append(
                Finding(
                    f"{cms} CMS detected",
                    Severity.INFO,
                    "Popular CMSes are mostly compromised through outdated plugins/modules "
                    "and weak admin passwords.",
                    "Keep core and plugins updated and protect the admin panel "
                    "(2FA, IP allow-list).",
                )
            )
    return findings


class TechModule(Module):
    name = "tech"
    title = "Technologies"
    description = "Web server, CDN/WAF, CMS, frameworks and libraries"

    async def run(self, ctx: ScanContext, result: ModuleResult) -> None:
        page = await ctx.homepage()
        technologies, generator = detect(page.headers, page.cookies, page.html)
        result.data = {"technologies": technologies, "generator": generator}
        result.findings.extend(evaluate_tech(technologies))
