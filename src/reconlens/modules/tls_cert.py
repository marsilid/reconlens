"""TLS certificate and protocol checks on port 443."""

from __future__ import annotations

import asyncio
import contextlib
import ssl
import warnings
from datetime import datetime, timezone
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import NameOID

from reconlens import rucrypto
from reconlens.context import ScanContext
from reconlens.models import Finding, ModuleResult, Severity
from reconlens.modules.base import Module

PORT = 443
MAX_SAN_SHOWN = 50
WEAK_SIGNATURES = frozenset({"md5", "sha1"})


def _name_attr(name: x509.Name, oid: x509.ObjectIdentifier) -> str | None:
    attrs = name.get_attributes_for_oid(oid)
    return str(attrs[0].value) if attrs else None


def _describe_key(key: object) -> tuple[str, int | None]:
    if isinstance(key, rsa.RSAPublicKey):
        return "RSA", key.key_size
    if isinstance(key, ec.EllipticCurvePublicKey):
        return f"EC {key.curve.name}", key.key_size
    if isinstance(key, dsa.DSAPublicKey):
        return "DSA", key.key_size
    if isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        return type(key).__name__.replace("PublicKey", ""), None
    return type(key).__name__, None


def parse_certificate(der: bytes, now: datetime) -> dict[str, Any]:
    """Parse the raw certificate; works even when chain verification failed."""
    cert = x509.load_der_x509_certificate(der)
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        san = []

    issuer_org = _name_attr(cert.issuer, NameOID.ORGANIZATION_NAME)
    issuer_cn = _name_attr(cert.issuer, NameOID.COMMON_NAME)

    # public_key() raises UnsupportedAlgorithm for GOST keys, which OpenSSL can't
    # load; read the algorithm OID from the certificate structure instead.
    public_key_oid = _public_key_oid(cert)
    try:
        key_type, key_size = _describe_key(cert.public_key())
    except Exception:
        key_type, key_size = "unsupported (see public_key_oid)", None

    signature_hash = None
    with contextlib.suppress(Exception):  # GOST signatures have no libcrypto hash object
        if cert.signature_hash_algorithm:
            signature_hash = cert.signature_hash_algorithm.name

    not_after = cert.not_valid_after_utc
    info = {
        "subject": _name_attr(cert.subject, NameOID.COMMON_NAME),
        "issuer": " / ".join(v for v in (issuer_org, issuer_cn) if v),
        "issuer_org": issuer_org,
        "issuer_cn": issuer_cn,
        "self_signed": cert.issuer == cert.subject,
        "valid_from": cert.not_valid_before_utc.isoformat(),
        "valid_to": not_after.isoformat(),
        "days_left": (not_after - now).days,
        "key_type": key_type,
        "key_size": key_size,
        "signature_hash": signature_hash,
        "signature_oid": cert.signature_algorithm_oid.dotted_string,
        "public_key_oid": public_key_oid,
        "san_count": len(san),
        "san": san[:MAX_SAN_SHOWN],
    }
    return rucrypto.annotate(info)


def _public_key_oid(cert: x509.Certificate) -> str | None:
    # cryptography >= 43 exposes this directly; older versions do not, so guard it.
    oid = getattr(cert, "public_key_algorithm_oid", None)
    return oid.dotted_string if oid is not None else None


def evaluate_tls(info: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    days_left = info.get("days_left")
    expired = days_left is not None and days_left < 0

    if expired:
        findings.append(
            Finding(
                "TLS certificate has expired",
                Severity.CRITICAL,
                f"The certificate expired {-days_left} days ago ({info['valid_to']}); browsers "
                "show a full-page warning.",
                "Renew the certificate and automate renewal (e.g. certbot / ACME).",
            )
        )
    elif info.get("trusted") is False and info.get("russian_ca"):
        # Not a misconfiguration: this is the Russian national CA, which foreign
        # trust stores (and generic scanners) simply do not carry.
        findings.append(
            Finding(
                f"Certificate issued by the Russian national CA ({info['russian_ca']})",
                Severity.LOW,
                "The certificate is signed by the НУЦ Минцифры (Russian Trusted CA). It is "
                "valid, but its root is absent from the Mozilla/Microsoft/Apple stores, so "
                "browsers outside Russia show a warning unless the Russian root is installed. "
                "Common for RU banking and government sites.",
                "For an audience outside Russia, additionally serve a certificate from a "
                "globally trusted CA (e.g. via SNI/dual-cert), or guide users to install the "
                "Russian root from gosuslugi.ru.",
            )
        )
    elif info.get("trusted") is False:
        reason = info.get("verify_error", "verification failed")
        if info.get("self_signed"):
            reason = "the certificate is self-signed"
        findings.append(
            Finding(
                "TLS certificate is not trusted",
                Severity.HIGH,
                f"Browsers reject it: {reason}. Users learn to click through warnings, which "
                "makes real man-in-the-middle attacks invisible.",
                "Install a certificate from a public CA that covers this hostname, "
                "including the full intermediate chain.",
            )
        )

    if info.get("gost"):
        algos = ", ".join(f"{k}: {v}" for k, v in info["gost"].items())
        findings.append(
            Finding(
                "GOST cryptography certificate (Russian national algorithms)",
                Severity.INFO,
                f"The certificate uses Russian GOST cryptography ({algos}) instead of RSA/ECDSA. "
                "Standard browsers and OpenSSL cannot complete the handshake without GOST "
                "support (e.g. a CryptoPro/gost-engine client). Expected for some RU "
                "government systems and required under certain ФСТЭК/ГОСТ compliance regimes.",
                "Confirm this matches your compliance requirement; for a general-purpose site, "
                "also offer an RSA/ECDSA certificate so mainstream clients can connect.",
            )
        )

    if days_left is not None and not expired:
        if days_left < 14:
            findings.append(
                Finding(
                    f"TLS certificate expires in {days_left} days",
                    Severity.HIGH,
                    "Renewal is overdue for an automated setup, which suggests it is manual.",
                    "Renew now and automate renewal via ACME.",
                )
            )
        elif days_left < 30:
            findings.append(
                Finding(
                    f"TLS certificate expires in {days_left} days",
                    Severity.MEDIUM,
                    "The certificate will expire soon.",
                    "Check that automatic renewal is working.",
                )
            )

    if info.get("key_type") == "RSA" and (info.get("key_size") or 0) < 2048:
        findings.append(
            Finding(
                f"Weak RSA key ({info['key_size']} bits)",
                Severity.HIGH,
                "RSA keys shorter than 2048 bits are considered breakable.",
                "Reissue the certificate with RSA 2048+ or an ECDSA P-256 key.",
            )
        )
    if info.get("signature_hash") in WEAK_SIGNATURES:
        findings.append(
            Finding(
                f"Certificate signed with {info['signature_hash'].upper()}",
                Severity.HIGH,
                "MD5 and SHA-1 signatures are vulnerable to collision attacks.",
                "Reissue the certificate with a SHA-256 signature.",
            )
        )

    protocol = info.get("protocol")
    if protocol == "TLSv1.2":
        findings.append(
            Finding(
                "TLS 1.3 is not supported",
                Severity.INFO,
                "TLS 1.3 is faster and removes legacy cryptography.",
                "Enable TLS 1.3 in the web server configuration.",
            )
        )
    elif protocol in ("TLSv1", "TLSv1.1", "SSLv3"):
        findings.append(
            Finding(
                f"Server negotiates obsolete {protocol}",
                Severity.HIGH,
                "TLS 1.0/1.1 were deprecated by RFC 8996.",
                "Allow only TLS 1.2 and 1.3.",
            )
        )

    if info.get("legacy_tls") is True and protocol not in ("TLSv1", "TLSv1.1", "SSLv3"):
        findings.append(
            Finding(
                "Legacy TLS 1.0/1.1 is still accepted",
                Severity.MEDIUM,
                "Old protocol versions are deprecated by RFC 8996 and weaken the connection "
                "for clients that can be downgraded.",
                "Disable TLS 1.0 and 1.1 on the server.",
            )
        )
    return findings


async def handshake(
    host: str, context: ssl.SSLContext, timeout: float
) -> tuple[bytes | None, str | None, tuple[str, str, int] | None]:
    """Connect and return (DER certificate, protocol version, cipher)."""
    _reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, PORT, ssl=context, server_hostname=host), timeout
    )
    try:
        sslobj = writer.get_extra_info("ssl_object")
        return sslobj.getpeercert(binary_form=True), sslobj.version(), sslobj.cipher()
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


def _unverified_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _legacy_context() -> ssl.SSLContext | None:
    """A client that offers only TLS 1.0/1.1; None if the local OpenSSL refuses to."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            context = _unverified_context()
            context.minimum_version = ssl.TLSVersion.TLSv1
            context.maximum_version = ssl.TLSVersion.TLSv1_1
            context.set_ciphers("ALL:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        return None
    return context


class TlsModule(Module):
    name = "tls"
    title = "TLS certificate"
    description = (
        "Certificate validity, issuer, key, SAN, protocol version, legacy TLS, "
        "Russian CA (НУЦ Минцифры) and GOST detection"
    )

    async def run(self, ctx: ScanContext, result: ModuleResult) -> None:
        info: dict[str, Any] = {"port": PORT}
        try:
            der, protocol, cipher = await handshake(
                ctx.domain, ssl.create_default_context(), ctx.timeout
            )
            info["trusted"] = True
        except ssl.SSLCertVerificationError as exc:
            info["trusted"] = False
            info["verify_error"] = exc.verify_message or str(exc)
            try:
                der, protocol, cipher = await handshake(
                    ctx.domain, _unverified_context(), ctx.timeout
                )
            except (OSError, TimeoutError, ssl.SSLError):
                der, protocol, cipher = None, None, None
        except (OSError, TimeoutError, ssl.SSLError) as exc:
            result.data = {"port": PORT, "https": False, "error": str(exc) or type(exc).__name__}
            result.findings.append(
                Finding(
                    "HTTPS is not available",
                    Severity.MEDIUM,
                    f"Could not complete a TLS handshake on port {PORT}.",
                    "Serve the site over HTTPS with a certificate from a public CA.",
                )
            )
            return

        info["https"] = True
        info["protocol"] = protocol
        if cipher:
            info["cipher"] = cipher[0]
            info["cipher_bits"] = cipher[2]
        if der:
            info.update(parse_certificate(der, datetime.now(timezone.utc)))

        legacy = _legacy_context()
        if legacy is None:
            info["legacy_tls"] = "not tested (unsupported by local OpenSSL)"
        else:
            try:
                await handshake(ctx.domain, legacy, ctx.timeout)
                info["legacy_tls"] = True
            except (OSError, TimeoutError, ssl.SSLError):
                info["legacy_tls"] = False

        result.data = info
        result.findings.extend(evaluate_tls(info))
