"""测试辅助：离线生成 CA / 中间证书 / 叶子证书。"""
from __future__ import annotations

from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

UTC = timezone.utc


def t(s: str) -> datetime:
    return datetime.fromisoformat(s).replace(tzinfo=UTC)


def _key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _ca_key_usage() -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=False,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=True,
        crl_sign=True,
        encipher_only=None,
        decipher_only=None,
    )


def make_ca(cn="Test Root CA", nb="2025-01-01", na="2035-01-01", path_length=None):
    key = _key()
    name = _name(cn)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(t(nb))
        .not_valid_after(t(na))
        .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
        .add_extension(_ca_key_usage(), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert, key


def make_cert(
    issuer_cert,
    issuer_key,
    cn,
    nb="2026-01-01",
    na="2027-01-01",
    sans=None,
    is_ca=False,
    path_length=None,
):
    key = _key()
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(issuer_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(t(nb))
        .not_valid_after(t(na))
        .add_extension(
            x509.BasicConstraints(ca=is_ca, path_length=path_length if is_ca else None),
            critical=True,
        )
    )
    if is_ca:
        builder = builder.add_extension(_ca_key_usage(), critical=True)
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]),
            critical=False,
        )
    return builder.sign(issuer_key, hashes.SHA256()), key


def pem(*certs) -> str:
    return "".join(
        c.public_bytes(serialization.Encoding.PEM).decode("ascii") for c in certs
    )


def fingerprint(pem_str: str) -> str:
    import hashlib
    import re

    block = re.search(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem_str, re.S
    ).group(0)
    cert = x509.load_pem_x509_certificate(block.encode())
    return cert.fingerprint(hashes.SHA256()).hex()
