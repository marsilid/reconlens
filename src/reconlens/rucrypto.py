"""Recognition of Russian national TLS: the НУЦ Минцифры CA and GOST cryptography.

Since 2022 many Russian sites (banks, government portals) serve certificates from
the Russian national CA ("Национальный удостоверяющий центр Минцифры России" /
Russian Trusted CA). That root is not in the Mozilla/Microsoft/Apple trust
stores, so browsers outside Russia — and generic scanners like SSL Labs — report
these certificates as "untrusted", which is misleading: they are valid, just
issued by a CA a foreign trust store does not carry.

Some of those certificates also use GOST cryptography (GOST R 34.10-2012 keys and
GOST R 34.11-2012 signatures) instead of RSA/ECDSA. Standard OpenSSL cannot
complete a GOST handshake, but the certificate itself names the algorithm by OID,
so we can identify it from the certificate we already downloaded.

All detection here is offline string/OID matching on a certificate that was
fetched exactly the way a browser fetches it — no extra requests, no gov site
poking beyond the single TLS connection the tls module already makes.
"""

from __future__ import annotations

from typing import Any

# Issuer markers for the Russian national CA. Matched case-insensitively against
# the certificate issuer's Organization and Common Name.
RU_CA_ORG_MARKERS = (
    "the ministry of digital development",
    "минцифры",
    "министерство цифрового развития",
)
RU_CA_CN_MARKERS = (
    "russian trusted",
    "russian national",
)

# GOST algorithm OIDs (dotted strings), as they appear in the certificate.
GOST_PUBLIC_KEY_OIDS = {
    "1.2.643.2.2.19": "GOST R 34.10-2001",
    "1.2.643.7.1.1.1.1": "GOST R 34.10-2012 (256-bit)",
    "1.2.643.7.1.1.1.2": "GOST R 34.10-2012 (512-bit)",
}
GOST_SIGNATURE_OIDS = {
    "1.2.643.2.2.3": "GOST R 34.11-94 with GOST R 34.10-2001",
    "1.2.643.7.1.1.3.2": "GOST R 34.11-2012 / 34.10-2012 (256-bit)",
    "1.2.643.7.1.1.3.3": "GOST R 34.11-2012 / 34.10-2012 (512-bit)",
}


def detect_russian_ca(issuer_org: str | None, issuer_cn: str | None) -> str | None:
    """Return a human name for the Russian national CA if the issuer is one, else None."""
    org = (issuer_org or "").lower()
    cn = (issuer_cn or "").lower()
    if any(m in org for m in RU_CA_ORG_MARKERS) or any(m in cn for m in RU_CA_CN_MARKERS):
        # Prefer the CN (e.g. "Russian Trusted Sub CA"); fall back to a generic label.
        return (issuer_cn or issuer_org or "Russian national CA").strip()
    return None


def detect_gost(signature_oid: str | None, public_key_oid: str | None) -> dict[str, str] | None:
    """Return which GOST algorithms a certificate uses, or None if it is not GOST."""
    result: dict[str, str] = {}
    if public_key_oid in GOST_PUBLIC_KEY_OIDS:
        result["public_key"] = GOST_PUBLIC_KEY_OIDS[public_key_oid]
    if signature_oid in GOST_SIGNATURE_OIDS:
        result["signature"] = GOST_SIGNATURE_OIDS[signature_oid]
    return result or None


def annotate(info: dict[str, Any]) -> dict[str, Any]:
    """Add ``russian_ca`` and ``gost`` keys to a parsed-certificate dict, in place."""
    ru_ca = detect_russian_ca(info.get("issuer_org"), info.get("issuer_cn"))
    gost = detect_gost(info.get("signature_oid"), info.get("public_key_oid"))
    if ru_ca:
        info["russian_ca"] = ru_ca
    if gost:
        info["gost"] = gost
    return info
