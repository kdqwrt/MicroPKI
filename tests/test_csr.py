from __future__ import annotations

from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from micropki.csr import (
    CSRValidationError,
    build_intermediate_csr,
    load_csr_pem,
    save_csr_pem,
    verify_csr_signature,
)


@pytest.mark.parametrize("key_type", ["rsa", "ecc"])
def test_build_intermediate_csr_success(tmp_path: Path, key_type: str):
    if key_type == "rsa":
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    else:
        private_key = ec.generate_private_key(ec.SECP384R1())

    csr = build_intermediate_csr(
        subject="CN=MicroPKI Intermediate CA,O=MicroPKI,C=DE",
        private_key=private_key,
        pathlen=0,
    )

    assert isinstance(csr, x509.CertificateSigningRequest)
    assert csr.subject.rfc4514_string()

    bc = csr.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca is True
    assert bc.path_length == 0

    verify_csr_signature(csr)


def test_build_intermediate_csr_rejects_negative_pathlen():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

    with pytest.raises(CSRValidationError):
        build_intermediate_csr(
            subject="CN=Bad Intermediate CA",
            private_key=private_key,
            pathlen=-1,
        )


def test_save_and_load_csr_pem(tmp_path: Path):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

    csr = build_intermediate_csr(
        subject="CN=MicroPKI Intermediate CA,O=MicroPKI",
        private_key=private_key,
        pathlen=0,
    )

    csr_path = tmp_path / "csrs" / "intermediate.csr.pem"
    save_csr_pem(csr, csr_path)

    assert csr_path.exists()

    loaded = load_csr_pem(csr_path)
    assert isinstance(loaded, x509.CertificateSigningRequest)
    assert loaded.subject == csr.subject

    verify_csr_signature(loaded)