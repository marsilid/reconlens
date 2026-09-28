"""E-mail anti-spoofing posture: SPF, DMARC and DKIM."""

from __future__ import annotations

import asyncio
import re
import secrets
from typing import Any

from reconlens.context import ScanContext
from reconlens.models import Finding, ModuleResult, Severity
from reconlens.modules.base import Module
from reconlens.utils import registrable_domain

# Selectors used by popular providers (Google, Microsoft 365, Yandex, Mail.ru, etc.).
# DKIM keys live at <selector>._domainkey.<domain>, and the selector is not public,
# so we can only confirm DKIM exists, never prove that it does not.
COMMON_DKIM_SELECTORS = (
    "default",
    "google",
    "selector1",
    "selector2",
    "k1",
    "k2",
    "mail",
    "dkim",
    "s1",
    "s2",
    "smtp",
    "mx",
    "yandex",
    "mailru",
    "sendgrid",
    "mandrill",
)
_SPF_LOOKUP_MECHANISMS = frozenset({"include", "a", "mx", "ptr", "exists"})
SPF_LOOKUP_LIMIT = 10


def parse_spf(record: str) -> dict[str, Any]:
    all_qualifier: str | None = None
    redirect: str | None = None
    lookups = 0
    has_ptr = False
    for term in record.split()[1:]:
        lowered = term.lower()
        if lowered.startswith("redirect="):
            redirect = lowered.split("=", 1)[1]
            lookups += 1
            continue
        if "=" in lowered:  # other modifiers such as exp=
            continue
        qualifier = lowered[0] if lowered[0] in "+-~?" else "+"
        mechanism = re.split(r"[:/]", lowered.lstrip("+-~?"), maxsplit=1)[0]
        if mechanism == "all":
            all_qualifier = qualifier
        elif mechanism in _SPF_LOOKUP_MECHANISMS:
            lookups += 1
            has_ptr = has_ptr or mechanism == "ptr"
    return {
        "record": record,
        "all": all_qualifier,
        "redirect": redirect,
        "dns_lookups": lookups,
        "uses_ptr": has_ptr,
    }


def parse_dmarc(record: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for part in record.split(";"):
        if "=" in part:
            key, value = part.split("=", 1)
            tags[key.strip().lower()] = value.strip()
    return tags


def dkim_has_key(record: str) -> bool:
    """True if a DKIM TXT record carries a public key (an empty ``p=`` means revoked)."""
    return bool(parse_dmarc(record).get("p"))  # same tag=value; syntax as DMARC


def is_null_mx(mx_records: list[str]) -> bool:
    """RFC 7505: a single ``0 .`` MX means the domain accepts no e-mail at all."""
    return [r.strip() for r in mx_records] == ["0 ."]


def spoofing_risk(spf: dict[str, Any] | None, dmarc: dict[str, str] | None) -> str:
    """How easy it is to send mail that appears to come from this domain."""
    policy = (dmarc or {}).get("p", "").lower()
    if policy in ("reject", "quarantine"):
        return "low"
    if spf and spf["all"] == "-":
        return "medium"
    return "high"


def evaluate_email(
    has_mx: bool,
    spf_records: list[str],
    dmarc_records: list[str],
    dkim_selectors: list[str],
    *,
    null_mx: bool = False,
    dmarc_inherited_from: str | None = None,
) -> tuple[dict[str, Any], list[Finding]]:
    """Evaluate the mail records.

    ``dmarc_inherited_from`` is set when the domain has no DMARC record of its own and
    the organisational domain's record applies instead (RFC 7489 §6.6.3); in that case
    the ``sp=`` tag, falling back to ``p=``, is the policy in force.
    """
    findings: list[Finding] = []
    spf = parse_spf(spf_records[0]) if len(spf_records) == 1 else None
    dmarc = parse_dmarc(dmarc_records[0]) if len(dmarc_records) == 1 else None
    if dmarc is not None and dmarc_inherited_from:
        dmarc = {**dmarc, "p": dmarc.get("sp", dmarc.get("p", ""))}
    enforced = (dmarc or {}).get("p", "").lower() in ("reject", "quarantine")

    # --- SPF -------------------------------------------------------------------
    if not spf_records:
        findings.append(
            Finding(
                "No SPF record",
                # An enforcing DMARC policy still rejects spoofed mail without SPF.
                Severity.LOW if enforced else Severity.HIGH,
                "Receiving servers cannot check which hosts may send mail for this domain"
                + (" (the enforcing DMARC policy still blocks spoofing)." if enforced else "."),
                "Publish an SPF record listing your mail senders and ending in `-all`"
                + ("" if has_mx else "; for a domain that sends no mail use `v=spf1 -all`")
                + ".",
            )
        )
    elif len(spf_records) > 1:
        findings.append(
            Finding(
                "Multiple SPF records",
                Severity.MEDIUM,
                "RFC 7208 allows only one SPF record; with several, SPF fails (permerror).",
                "Merge them into a single `v=spf1 ...` record.",
            )
        )
    elif spf is not None:
        qualifier = spf["all"]
        if qualifier == "+":
            findings.append(
                Finding(
                    "SPF allows any sender (+all)",
                    Severity.HIGH,
                    "`+all` explicitly authorises every server on the Internet.",
                    "Replace `+all` with `-all` (or `~all` while testing).",
                )
            )
        elif qualifier == "?":
            findings.append(
                Finding(
                    "SPF ends with neutral ?all",
                    Severity.MEDIUM,
                    "`?all` gives receivers no instruction about unauthorised senders.",
                    "Use `-all` once all legitimate senders are listed.",
                )
            )
        elif qualifier is None and not spf["redirect"]:
            findings.append(
                Finding(
                    "SPF record has no 'all' mechanism",
                    Severity.MEDIUM,
                    "Without a terminating `all`, the default result is neutral.",
                    "End the record with `-all`.",
                )
            )
        if spf["dns_lookups"] > SPF_LOOKUP_LIMIT:
            findings.append(
                Finding(
                    f"SPF needs {spf['dns_lookups']} DNS lookups (limit is 10)",
                    Severity.MEDIUM,
                    "Exceeding the limit makes SPF evaluation fail (permerror).",
                    "Flatten includes or remove unused senders.",
                )
            )
        if spf["uses_ptr"]:
            findings.append(
                Finding(
                    "SPF uses the deprecated 'ptr' mechanism",
                    Severity.LOW,
                    "`ptr` is slow, unreliable and discouraged by RFC 7208.",
                    "Replace `ptr` with explicit `ip4:`/`ip6:` or `include:` terms.",
                )
            )

    # --- DMARC -----------------------------------------------------------------
    if not dmarc_records:
        findings.append(
            Finding(
                "No DMARC policy",
                Severity.HIGH,
                "Nothing tells receivers what to do with mail that fails SPF/DKIM, so the "
                "domain can be spoofed in the visible From: header.",
                "Publish `_dmarc` TXT: start with `v=DMARC1; p=none; rua=mailto:...`, "
                "review reports, then move to `p=quarantine` or `p=reject`.",
            )
        )
    elif len(dmarc_records) > 1:
        findings.append(
            Finding(
                "Multiple DMARC records",
                Severity.MEDIUM,
                "With more than one record, receivers ignore DMARC entirely.",
                "Keep a single `_dmarc` TXT record.",
            )
        )
    elif dmarc is not None:
        policy = dmarc.get("p", "").lower()
        if policy not in ("none", "quarantine", "reject"):
            findings.append(
                Finding(
                    "DMARC record has no valid policy",
                    Severity.MEDIUM,
                    f"The `p=` tag is missing or invalid ({policy or 'empty'}).",
                    "Set `p=quarantine` or `p=reject`.",
                )
            )
        elif policy == "none":
            findings.append(
                Finding(
                    "DMARC policy is 'none' (monitoring only)",
                    Severity.MEDIUM,
                    "Spoofed messages are still delivered; the policy only collects reports.",
                    "After reviewing reports, move to `p=quarantine`, then `p=reject`.",
                )
            )
        pct = dmarc.get("pct")
        if pct and pct.isdigit() and int(pct) < 100:
            findings.append(
                Finding(
                    f"DMARC applies to only {pct}% of messages",
                    Severity.LOW,
                    "The rest of the failing messages are treated as if no policy existed.",
                    "Raise `pct` to 100 (or remove the tag).",
                )
            )
        if "rua" not in dmarc and not null_mx:
            findings.append(
                Finding(
                    "DMARC aggregate reports are not collected",
                    Severity.LOW,
                    "Without `rua=` you never learn who sends mail on your behalf.",
                    "Add `rua=mailto:dmarc@your-domain` or use a DMARC report service.",
                )
            )

    # --- DKIM ------------------------------------------------------------------
    if not dkim_selectors and has_mx:
        findings.append(
            Finding(
                "DKIM key not found among common selectors",
                Severity.INFO,
                "DKIM may still be configured under a custom selector; check the "
                "`DKIM-Signature: s=` header of a real message to confirm.",
            )
        )

    data = {
        "mx": has_mx,
        "spf": spf or spf_records,
        "dmarc": dmarc or dmarc_records,
        "dkim_selectors_found": dkim_selectors,
        "spoofing_risk": spoofing_risk(spf, dmarc),
    }
    if dmarc_inherited_from:
        data["dmarc_inherited_from"] = dmarc_inherited_from
    return data, findings


class EmailSecurityModule(Module):
    name = "email"
    title = "E-mail security"
    description = "SPF, DMARC and DKIM configuration and spoofing risk"

    async def run(self, ctx: ScanContext, result: ModuleResult) -> None:
        domain = ctx.domain
        mx, txt, dmarc_txt = await asyncio.gather(
            ctx.resolver.resolve(domain, "MX"),
            ctx.resolver.resolve(domain, "TXT"),
            ctx.resolver.resolve(f"_dmarc.{domain}", "TXT"),
        )
        # The last probe uses a selector nobody would configure: if it answers,
        # _domainkey has a wildcard and per-selector hits prove nothing.
        selectors = (*COMMON_DKIM_SELECTORS, f"reconlens-{secrets.token_hex(4)}")
        # A failed DKIM probe only means "not confirmed", so it must not fail the module.
        dkim_answers = await asyncio.gather(
            *(ctx.resolver.resolve(f"{sel}._domainkey.{domain}", "TXT") for sel in selectors),
            return_exceptions=True,
        )
        with_key = [
            sel
            for sel, answer in zip(selectors, dkim_answers, strict=True)
            if isinstance(answer, list) and any(dkim_has_key(r) for r in answer)
        ]
        wildcard = with_key and with_key[-1] == selectors[-1]
        dkim_found = [] if wildcard else with_key

        spf_records = [r for r in txt if r.lower().startswith("v=spf1")]
        dmarc_records = [r for r in dmarc_txt if r.lower().startswith("v=dmarc1")]
        inherited_from = None
        org_domain = registrable_domain(domain)
        if not dmarc_records and org_domain != domain:
            org_txt = await ctx.resolver.resolve(f"_dmarc.{org_domain}", "TXT")
            dmarc_records = [r for r in org_txt if r.lower().startswith("v=dmarc1")]
            inherited_from = org_domain if dmarc_records else None
        null_mx = is_null_mx(mx)

        data, findings = evaluate_email(
            bool(mx) and not null_mx,
            spf_records,
            dmarc_records,
            dkim_found,
            null_mx=null_mx,
            dmarc_inherited_from=inherited_from,
        )
        data["mx_records"] = sorted(mx)
        data["null_mx"] = null_mx
        if wildcard:
            data["dkim_wildcard"] = True
        if null_mx:
            findings.append(
                Finding(
                    "Domain declares it accepts no e-mail (Null MX)",
                    Severity.INFO,
                    "An MX of `0 .` (RFC 7505) tells senders not to deliver mail here. "
                    "Together with `v=spf1 -all` and DMARC `p=reject` this is the correct "
                    "setup for a domain that does not use e-mail.",
                )
            )
        result.data = data
        result.findings.extend(findings)
