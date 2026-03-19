from __future__ import annotations

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from micropki.templates import (
    TemplateValidationError,
    build_leaf_extensions,
    parse_san_entries,
    validate_template_sans,
)


def test_parse_san_entries_success():
    san_objects = parse_san_entries([
        "dns:example.com",
        "ip:192.168.1.10",
        "email:alice@example.com",
        "uri:https://example.com/app",
    ])

    assert len(san_objects) == 4
    assert any(isinstance(x, x509.DNSName) for x in san_objects)
    assert any(isinstance(x, x509.IPAddress) for x in san_objects)
    assert any(isinstance(x, x509.RFC822Name) for x in san_objects)
    assert any(isinstance(x, x509.UniformResourceIdentifier) for x in san_objects)


def test_parse_san_entries_invalid_format():
    with pytest.raises(TemplateValidationError):
        parse_san_entries(["example.com"])


def test_parse_san_entries_invalid_ip():
    with pytest.raises(TemplateValidationError):
        parse_san_entries(["ip:not_an_ip"])


def test_server_requires_san():
    with pytest.raises(TemplateValidationError):
        validate_template_sans("server", [])


def test_server_rejects_email_san():
    san_objects = parse_san_entries(["email:alice@example.com"])
    with pytest.raises(TemplateValidationError):
        validate_template_sans("server", san_objects)


def test_client_accepts_email_and_dns():
    san_objects = parse_san_entries([
        "email:alice@example.com",
        "dns:client.example.com",
    ])
    validate_template_sans("client", san_objects)


def test_code_signing_rejects_ip():
    san_objects = parse_san_entries(["ip:10.0.0.1"])
    with pytest.raises(TemplateValidationError):
        validate_template_sans("code_signing", san_objects)


def test_build_server_extensions_for_rsa():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    san_objects = parse_san_entries(["dns:example.com"])

    exts = build_leaf_extensions("server", key.public_key(), san_objects)

    assert any(isinstance(e, x509.BasicConstraints) for e in exts)
    assert any(isinstance(e, x509.KeyUsage) for e in exts)
    assert any(isinstance(e, x509.ExtendedKeyUsage) for e in exts)
    assert any(isinstance(e, x509.SubjectAlternativeName) for e in exts)


def test_build_client_extensions_for_ecc():
    key = ec.generate_private_key(ec.SECP256R1())
    san_objects = parse_san_entries(["email:alice@example.com"])

    exts = build_leaf_extensions("client", key.public_key(), san_objects)

    ku = next(e for e in exts if isinstance(e, x509.KeyUsage))
    assert ku.digital_signature is True