from __future__ import annotations

import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from micropki.ca import init_ca, issue_intermediate_ca, issue_end_entity_certificate
from micropki.chain import verify_chain
from micropki.crypto_utils import load_private_key_encrypted, load_cert_pem
from micropki.templates import TemplateValidationError


@pytest.mark.skipif(shutil.which("openssl") is None, reason="OpenSSL not installed")
def test_openssl_verify_intermediate_and_leaf_chain(tmp_path: Path):
    root_pass = b"rootpass"
    inter_pass = b"interpass"
    out_dir = tmp_path / "pki"

    init_ca(
        subject="CN=Test Root CA,O=Test,C=DE",
        key_type="rsa",
        key_size=4096,
        passphrase=root_pass,
        out_dir=out_dir,
        force=False,
        logger=None,
    )

    issue_intermediate_ca(
        root_cert_path=out_dir / "certs" / "ca.cert.pem",
        root_key_path=out_dir / "private" / "ca.key.pem",
        root_passphrase=root_pass,
        subject="CN=Test Intermediate CA,O=Test,C=DE",
        key_type="rsa",
        key_size=4096,
        intermediate_passphrase=inter_pass,
        out_dir=out_dir,
        logger=None,
    )

    leaf_result = issue_end_entity_certificate(
        ca_cert_path=out_dir / "certs" / "intermediate.cert.pem",
        ca_key_path=out_dir / "private" / "intermediate.key.pem",
        ca_passphrase=inter_pass,
        template="server",
        subject="CN=example.com,O=Test,C=DE",
        san_entries=["dns:example.com", "dns:www.example.com"],
        out_dir=out_dir / "certs",
        logger=None,
    )

    root_cert = out_dir / "certs" / "ca.cert.pem"
    inter_cert = out_dir / "certs" / "intermediate.cert.pem"
    leaf_cert = leaf_result["cert"]

    r1 = subprocess.run(
        ["openssl", "verify", "-CAfile", str(root_cert), str(inter_cert)],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert r1.returncode == 0, r1.stdout + r1.stderr
    assert ": OK" in (r1.stdout + r1.stderr)

    r2 = subprocess.run(
        [
            "openssl",
            "verify",
            "-CAfile",
            str(root_cert),
            "-untrusted",
            str(inter_cert),
            str(leaf_cert),
        ],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert r2.returncode == 0, r2.stdout + r2.stderr
    assert ": OK" in (r2.stdout + r2.stderr)


@pytest.mark.skipif(shutil.which("openssl") is None, reason="OpenSSL not installed")
def test_openssl_extensions_present_for_server_cert(tmp_path: Path):
    root_pass = b"rootpass"
    inter_pass = b"interpass"
    out_dir = tmp_path / "pki"

    init_ca(
        subject="CN=Root CA,O=Test,C=DE",
        key_type="rsa",
        key_size=4096,
        passphrase=root_pass,
        out_dir=out_dir,
        force=False,
        logger=None,
    )

    issue_intermediate_ca(
        root_cert_path=out_dir / "certs" / "ca.cert.pem",
        root_key_path=out_dir / "private" / "ca.key.pem",
        root_passphrase=root_pass,
        subject="CN=Intermediate CA,O=Test,C=DE",
        key_type="rsa",
        key_size=4096,
        intermediate_passphrase=inter_pass,
        out_dir=out_dir,
        logger=None,
    )

    leaf_result = issue_end_entity_certificate(
        ca_cert_path=out_dir / "certs" / "intermediate.cert.pem",
        ca_key_path=out_dir / "private" / "intermediate.key.pem",
        ca_passphrase=inter_pass,
        template="server",
        subject="CN=example.com,O=Test,C=DE",
        san_entries=["dns:example.com", "ip:127.0.0.1"],
        out_dir=out_dir / "certs",
        logger=None,
    )

    cert_path = leaf_result["cert"]

    r = subprocess.run(
        ["openssl", "x509", "-in", str(cert_path), "-text", "-noout"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert r.returncode == 0, r.stdout + r.stderr
    text = r.stdout + r.stderr

    assert "X509v3 Basic Constraints: critical" in text
    assert "CA:FALSE" in text
    assert "X509v3 Key Usage: critical" in text
    assert "Digital Signature" in text
    assert "X509v3 Extended Key Usage" in text
    assert "TLS Web Server Authentication" in text
    assert "X509v3 Subject Alternative Name" in text
    assert "DNS:example.com" in text
    assert "IP Address:127.0.0.1" in text


def test_verify_chain_command_logic(tmp_path: Path):
    root_pass = b"rootpass"
    inter_pass = b"interpass"
    out_dir = tmp_path / "pki"

    init_ca(
        subject="CN=Root CA,O=Test,C=DE",
        key_type="rsa",
        key_size=4096,
        passphrase=root_pass,
        out_dir=out_dir,
        force=False,
        logger=None,
    )

    issue_intermediate_ca(
        root_cert_path=out_dir / "certs" / "ca.cert.pem",
        root_key_path=out_dir / "private" / "ca.key.pem",
        root_passphrase=root_pass,
        subject="CN=Intermediate CA,O=Test,C=DE",
        key_type="rsa",
        key_size=4096,
        intermediate_passphrase=inter_pass,
        out_dir=out_dir,
        logger=None,
    )

    leaf_result = issue_end_entity_certificate(
        ca_cert_path=out_dir / "certs" / "intermediate.cert.pem",
        ca_key_path=out_dir / "private" / "intermediate.key.pem",
        ca_passphrase=inter_pass,
        template="server",
        subject="CN=example.com,O=Test,C=DE",
        san_entries=["dns:example.com"],
        out_dir=out_dir / "certs",
        logger=None,
    )

    result = verify_chain(
        root_cert_path=out_dir / "certs" / "ca.cert.pem",
        intermediate_cert_path=out_dir / "certs" / "intermediate.cert.pem",
        leaf_cert_path=leaf_result["cert"],
        template="server",
    )

    assert "Root CA" in result["root_subject"]
    assert "Intermediate CA" in result["intermediate_subject"]
    assert "example.com" in result["leaf_subject"]


def test_negative_server_without_san_fails(tmp_path: Path):
    root_pass = b"rootpass"
    inter_pass = b"interpass"
    out_dir = tmp_path / "pki"

    init_ca(
        subject="CN=Root CA,O=Test",
        key_type="rsa",
        key_size=4096,
        passphrase=root_pass,
        out_dir=out_dir,
        force=False,
        logger=None,
    )

    issue_intermediate_ca(
        root_cert_path=out_dir / "certs" / "ca.cert.pem",
        root_key_path=out_dir / "private" / "ca.key.pem",
        root_passphrase=root_pass,
        subject="CN=Intermediate CA,O=Test",
        key_type="rsa",
        key_size=4096,
        intermediate_passphrase=inter_pass,
        out_dir=out_dir,
        logger=None,
    )

    with pytest.raises(TemplateValidationError):
        issue_end_entity_certificate(
            ca_cert_path=out_dir / "certs" / "intermediate.cert.pem",
            ca_key_path=out_dir / "private" / "intermediate.key.pem",
            ca_passphrase=inter_pass,
            template="server",
            subject="CN=nosan.example.com,O=Test",
            san_entries=[],
            out_dir=out_dir / "certs",
            logger=None,
        )


def test_negative_code_signing_with_ip_san_fails(tmp_path: Path):
    root_pass = b"rootpass"
    inter_pass = b"interpass"
    out_dir = tmp_path / "pki"

    init_ca(
        subject="CN=Root CA,O=Test",
        key_type="rsa",
        key_size=4096,
        passphrase=root_pass,
        out_dir=out_dir,
        force=False,
        logger=None,
    )

    issue_intermediate_ca(
        root_cert_path=out_dir / "certs" / "ca.cert.pem",
        root_key_path=out_dir / "private" / "ca.key.pem",
        root_passphrase=root_pass,
        subject="CN=Intermediate CA,O=Test",
        key_type="rsa",
        key_size=4096,
        intermediate_passphrase=inter_pass,
        out_dir=out_dir,
        logger=None,
    )

    with pytest.raises(TemplateValidationError):
        issue_end_entity_certificate(
            ca_cert_path=out_dir / "certs" / "intermediate.cert.pem",
            ca_key_path=out_dir / "private" / "intermediate.key.pem",
            ca_passphrase=inter_pass,
            template="code_signing",
            subject="CN=Code Signer,O=Test",
            san_entries=["ip:127.0.0.1"],
            out_dir=out_dir / "certs",
            logger=None,
        )


def test_negative_wrong_intermediate_passphrase_fails(tmp_path: Path):
    root_pass = b"rootpass"
    inter_pass = b"interpass"
    out_dir = tmp_path / "pki"

    init_ca(
        subject="CN=Root CA,O=Test",
        key_type="rsa",
        key_size=4096,
        passphrase=root_pass,
        out_dir=out_dir,
        force=False,
        logger=None,
    )

    issue_intermediate_ca(
        root_cert_path=out_dir / "certs" / "ca.cert.pem",
        root_key_path=out_dir / "private" / "ca.key.pem",
        root_passphrase=root_pass,
        subject="CN=Intermediate CA,O=Test",
        key_type="rsa",
        key_size=4096,
        intermediate_passphrase=inter_pass,
        out_dir=out_dir,
        logger=None,
    )

    with pytest.raises(ValueError):
        issue_end_entity_certificate(
            ca_cert_path=out_dir / "certs" / "intermediate.cert.pem",
            ca_key_path=out_dir / "private" / "intermediate.key.pem",
            ca_passphrase=b"wrong-passphrase",
            template="server",
            subject="CN=example.com,O=Test",
            san_entries=["dns:example.com"],
            out_dir=out_dir / "certs",
            logger=None,
        )


def test_negative_csr_with_ca_true_fails(tmp_path: Path):
    root_pass = b"rootpass"
    inter_pass = b"interpass"
    out_dir = tmp_path / "pki"

    init_ca(
        subject="CN=Root CA,O=Test",
        key_type="rsa",
        key_size=4096,
        passphrase=root_pass,
        out_dir=out_dir,
        force=False,
        logger=None,
    )

    issue_intermediate_ca(
        root_cert_path=out_dir / "certs" / "ca.cert.pem",
        root_key_path=out_dir / "private" / "ca.key.pem",
        root_passphrase=root_pass,
        subject="CN=Intermediate CA,O=Test",
        key_type="rsa",
        key_size=4096,
        intermediate_passphrase=inter_pass,
        out_dir=out_dir,
        logger=None,
    )

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([
                x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "badcsr.example.com"),
            ])
        )
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )

    csr_path = tmp_path / "bad_leaf.csr.pem"
    csr_path.write_bytes(csr.public_bytes(serialization.Encoding.PEM))

    with pytest.raises(ValueError, match="CA=TRUE"):
        issue_end_entity_certificate(
            ca_cert_path=out_dir / "certs" / "intermediate.cert.pem",
            ca_key_path=out_dir / "private" / "intermediate.key.pem",
            ca_passphrase=inter_pass,
            template="server",
            subject="CN=badcsr.example.com,O=Test",
            san_entries=["dns:badcsr.example.com"],
            out_dir=out_dir / "certs",
            csr_path=csr_path,
            logger=None,
        )


def test_issue_leaf_from_external_csr_does_not_store_private_key(tmp_path: Path):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([
                x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "csr.example.com"),
            ])
        )
        .sign(private_key, hashes.SHA256())
    )

    csr_path = tmp_path / "leaf.csr.pem"
    csr_path.write_bytes(csr.public_bytes(serialization.Encoding.PEM))

    root_pass = b"rootpass"
    inter_pass = b"interpass"
    out_dir = tmp_path / "pki"

    init_ca(
        subject="CN=Root CA,O=Test",
        key_type="rsa",
        key_size=4096,
        passphrase=root_pass,
        out_dir=out_dir,
        force=False,
        logger=None,
    )

    issue_intermediate_ca(
        root_cert_path=out_dir / "certs" / "ca.cert.pem",
        root_key_path=out_dir / "private" / "ca.key.pem",
        root_passphrase=root_pass,
        subject="CN=Intermediate CA,O=Test",
        key_type="rsa",
        key_size=4096,
        intermediate_passphrase=inter_pass,
        out_dir=out_dir,
        logger=None,
    )

    result = issue_end_entity_certificate(
        ca_cert_path=out_dir / "certs" / "intermediate.cert.pem",
        ca_key_path=out_dir / "private" / "intermediate.key.pem",
        ca_passphrase=inter_pass,
        template="server",
        subject="CN=csr.example.com",
        san_entries=["dns:csr.example.com"],
        out_dir=out_dir / "certs",
        csr_path=csr_path,
        logger=None,
    )

    assert result["cert"].exists()
    assert result["key"] is None


def test_root_key_can_be_loaded_and_matches_certificate(tmp_path: Path):
    out_dir = tmp_path / "pki"
    passphrase = b"supersecret"

    cert = init_ca(
        subject="CN=Root CA,O=Test,C=DE",
        key_type="rsa",
        key_size=4096,
        passphrase=passphrase,
        out_dir=out_dir,
        force=False,
        logger=None,
    )

    key = load_private_key_encrypted(out_dir / "private" / "ca.key.pem", passphrase)
    cert_pub = cert.public_key()
    key_pub = key.public_key()

    cert_numbers = cert_pub.public_numbers()
    key_numbers = key_pub.public_numbers()
    assert cert_numbers == key_numbers


@pytest.mark.skipif(shutil.which("openssl") is None, reason="OpenSSL not installed")
@pytest.mark.skipif(sys.platform == "win32", reason="TLS round-trip shell test is Unix-oriented")
def test_tls_roundtrip(tmp_path: Path):
    root_pass = b"rootpass"
    inter_pass = b"interpass"
    out_dir = tmp_path / "pki"

    init_ca(
        subject="CN=Test Root CA,O=Test,C=DE",
        key_type="rsa",
        key_size=4096,
        passphrase=root_pass,
        out_dir=out_dir,
        force=False,
        logger=None,
    )

    issue_intermediate_ca(
        root_cert_path=out_dir / "certs" / "ca.cert.pem",
        root_key_path=out_dir / "private" / "ca.key.pem",
        root_passphrase=root_pass,
        subject="CN=Test Intermediate CA,O=Test,C=DE",
        key_type="rsa",
        key_size=4096,
        intermediate_passphrase=inter_pass,
        out_dir=out_dir,
        logger=None,
    )

    result = issue_end_entity_certificate(
        ca_cert_path=out_dir / "certs" / "intermediate.cert.pem",
        ca_key_path=out_dir / "private" / "intermediate.key.pem",
        ca_passphrase=inter_pass,
        template="server",
        subject="CN=localhost,O=Test",
        san_entries=["dns:localhost", "ip:127.0.0.1"],
        out_dir=out_dir / "certs",
        key_type="rsa",
        key_size=2048,
        logger=None,
    )

    cert_path = result["cert"]
    key_path = result["key"]
    root_cert = out_dir / "certs" / "ca.cert.pem"

    server = subprocess.Popen(
        [
            "openssl",
            "s_server",
            "-accept",
            "8443",
            "-cert",
            str(cert_path),
            "-key",
            str(key_path),
            "-cert_chain",
            str(out_dir / "certs" / "intermediate.cert.pem"),
            "-www",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    try:
        time.sleep(2)
        result = subprocess.run(
            [
                "openssl",
                "s_client",
                "-connect",
                "127.0.0.1:8443",
                "-servername",
                "localhost",
                "-CAfile",
                str(root_cert),
                "-verify_return_error",
            ],
            input="GET /\n",
            capture_output=True,
            text=True,
            timeout=15,
        )
    finally:
        server.kill()
        server.wait(timeout=5)

    combined = result.stdout + "\n" + result.stderr
    assert "Verify return code: 0 (ok)" in combined
    assert result.returncode == 0


def test_leaf_cert_and_key_match_when_generated_internally(tmp_path: Path):
    root_pass = b"rootpass"
    inter_pass = b"interpass"
    out_dir = tmp_path / "pki"

    init_ca(
        subject="CN=Root CA,O=Test",
        key_type="rsa",
        key_size=4096,
        passphrase=root_pass,
        out_dir=out_dir,
        force=False,
        logger=None,
    )

    issue_intermediate_ca(
        root_cert_path=out_dir / "certs" / "ca.cert.pem",
        root_key_path=out_dir / "private" / "ca.key.pem",
        root_passphrase=root_pass,
        subject="CN=Intermediate CA,O=Test",
        key_type="rsa",
        key_size=4096,
        intermediate_passphrase=inter_pass,
        out_dir=out_dir,
        logger=None,
    )

    result = issue_end_entity_certificate(
        ca_cert_path=out_dir / "certs" / "intermediate.cert.pem",
        ca_key_path=out_dir / "private" / "intermediate.key.pem",
        ca_passphrase=inter_pass,
        template="server",
        subject="CN=match.example.com,O=Test",
        san_entries=["dns:match.example.com"],
        out_dir=out_dir / "certs",
        logger=None,
    )

    cert = load_cert_pem(result["cert"])
    key = serialization.load_pem_private_key(result["key"].read_bytes(), password=None)

    assert cert.public_key().public_numbers() == key.public_key().public_numbers()