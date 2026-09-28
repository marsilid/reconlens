from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from reconlens.models import Severity
from reconlens.modules.tls_cert import evaluate_tls, parse_certificate
from reconlens.rucrypto import annotate, detect_gost, detect_russian_ca


def test_detect_russian_ca_by_cn():
    assert (
        detect_russian_ca(
            "The Ministry of Digital Development and Communications", "Russian Trusted Sub CA"
        )
        == "Russian Trusted Sub CA"
    )


def test_detect_russian_ca_cyrillic_org():
    assert detect_russian_ca("Минцифры России", None)


def test_detect_russian_ca_negative():
    assert detect_russian_ca("Let's Encrypt", "R3") is None
    assert detect_russian_ca(None, None) is None


def test_detect_gost_2012():
    gost = detect_gost("1.2.643.7.1.1.3.2", "1.2.643.7.1.1.1.1")
    assert gost == {
        "signature": "GOST R 34.11-2012 / 34.10-2012 (256-bit)",
        "public_key": "GOST R 34.10-2012 (256-bit)",
    }


def test_detect_gost_negative_for_rsa():
    # sha256WithRSAEncryption + rsaEncryption
    assert detect_gost("1.2.840.113549.1.1.11", "1.2.840.113549.1.1.1") is None


def test_annotate_adds_keys():
    info = annotate(
        {
            "issuer_org": "The Ministry of Digital Development and Communications",
            "issuer_cn": "Russian Trusted Sub CA",
            "signature_oid": "1.2.643.7.1.1.3.3",
            "public_key_oid": "1.2.643.7.1.1.1.2",
        }
    )
    assert info["russian_ca"] == "Russian Trusted Sub CA"
    assert "512-bit" in info["gost"]["public_key"]


def test_russian_ca_is_low_not_high():
    info = {"trusted": False, "russian_ca": "Russian Trusted Sub CA", "days_left": 100}
    findings = evaluate_tls(info)
    ca = next(f for f in findings if "Russian national CA" in f.title)
    assert ca.severity == Severity.LOW
    # and the generic "not trusted" HIGH must NOT also fire
    assert not any(f.title == "TLS certificate is not trusted" for f in findings)


def test_gost_produces_info_finding():
    info = {
        "trusted": True,
        "days_left": 100,
        "gost": {"public_key": "GOST R 34.10-2012 (256-bit)"},
    }
    findings = evaluate_tls(info)
    assert any(f.severity == Severity.INFO and "GOST" in f.title for f in findings)


def test_ordinary_untrusted_still_high():
    info = {"trusted": False, "days_left": 100, "verify_error": "unable to get local issuer"}
    findings = evaluate_tls(info)
    assert any(
        f.title == "TLS certificate is not trusted" and f.severity == Severity.HIGH
        for f in findings
    )


def _self_signed_der(cn="example.test"):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=90))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def test_parse_certificate_fields():
    info = parse_certificate(_self_signed_der(), datetime.now(timezone.utc))
    assert info["key_type"] == "RSA"
    assert info["key_size"] == 2048
    assert info["self_signed"] is True
    assert info["signature_oid"] == "1.2.840.113549.1.1.11"  # sha256WithRSAEncryption
    assert info["san"] == ["example.test"]
    assert "russian_ca" not in info  # ordinary cert is not flagged
    assert "gost" not in info


FIXTURES = Path(__file__).parent / "fixtures"


def _load_pem_der(name: str) -> bytes:
    from cryptography.hazmat.primitives.serialization import Encoding

    cert = x509.load_pem_x509_certificate((FIXTURES / name).read_bytes())
    return cert.public_bytes(Encoding.DER)


@pytest.mark.parametrize(
    ("fixture", "bits"),
    [("gost2012_256_cert.pem", "256-bit"), ("gost2012_512_cert.pem", "512-bit")],
)
def test_parse_real_gost_certificate(fixture, bits):
    """Regression: real GOST certs (TC26 test suite) must parse and be flagged, not crash."""
    info = parse_certificate(_load_pem_der(fixture), datetime.now(timezone.utc))
    assert info["gost"] is not None
    assert bits in info["gost"]["public_key"]
    assert info["signature_oid"].startswith("1.2.643")  # GOST OID arc
    findings = evaluate_tls({**info, "trusted": True, "days_left": 100})
    assert any("GOST" in f.title for f in findings)
