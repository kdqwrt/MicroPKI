from pathlib import Path

from cryptography import x509

from micropki.ca import init_ca, issue_intermediate_ca, issue_end_entity_certificate


def test_full_server_leaf_pipeline(tmp_path: Path):
    root_pass = b"rootpass"
    inter_pass = b"interpass"

    out_dir = tmp_path / "pki"

    init_ca(
        subject="CN=Root CA,O=MicroPKI,C=DE",
        key_type="rsa",
        key_size=4096,
        passphrase=root_pass,
        out_dir=out_dir,
        force=False,
        validity_days=3650,
        logger=None,
    )

    issue_intermediate_ca(
        root_cert_path=out_dir / "certs" / "ca.cert.pem",
        root_key_path=out_dir / "private" / "ca.key.pem",
        root_passphrase=root_pass,
        subject="CN=Intermediate CA,O=MicroPKI,C=DE",
        key_type="rsa",
        key_size=4096,
        intermediate_passphrase=inter_pass,
        out_dir=out_dir,
        validity_days=1825,
        pathlen=0,
        logger=None,
    )

    result = issue_end_entity_certificate(
        ca_cert_path=out_dir / "certs" / "intermediate.cert.pem",
        ca_key_path=out_dir / "private" / "intermediate.key.pem",
        ca_passphrase=inter_pass,
        template="server",
        subject="CN=example.com,O=MicroPKI,C=DE",
        san_entries=["dns:example.com", "dns:www.example.com"],
        out_dir=out_dir / "certs",
        validity_days=365,
        key_type="rsa",
        key_size=2048,
        logger=None,
    )

    assert result["cert"].exists()
    assert result["key"].exists()

    cert = x509.load_pem_x509_certificate(result["cert"].read_bytes())

    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca is False

    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert len(san) >= 1