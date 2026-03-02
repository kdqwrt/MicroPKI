from __future__ import annotations

from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, ec

from micropki.ca import init_ca
from micropki.crypto_utils import load_cert_pem, load_private_key_encrypted


def _verify_self_signed_signature(cert: x509.Certificate) -> None:
    pub = cert.public_key()
    signature = cert.signature
    data = cert.tbs_certificate_bytes
    alg = cert.signature_hash_algorithm

    if isinstance(pub, ec.EllipticCurvePublicKey):
        pub.verify(signature, data, ec.ECDSA(alg))
    else:
        pub.verify(signature, data, padding.PKCS1v15(), alg)


@pytest.mark.parametrize("key_type,key_size", [("rsa", 4096), ("ecc", 384)])
def test_root_ca_outputs_extensions_and_self_signature(tmp_path: Path, key_type: str, key_size: int):
    passphrase = b"supersecret"
    out_dir = tmp_path / "pki"

    init_ca(
        subject="CN=MicroPKI Root CA,O=MicroPKI,C=DE",
        key_type=key_type,
        key_size=key_size,
        passphrase=passphrase,
        out_dir=out_dir,
        force=False,
        validity_days=3650,
        logger=None,
    )

    cert_path = out_dir / "certs" / "ca.cert.pem"
    key_path = out_dir / "private" / "ca.key.pem"
    policy_path = out_dir / "policy.txt"

    assert cert_path.exists()
    assert key_path.exists()
    assert policy_path.exists()

    cert = load_cert_pem(cert_path)

    # self-issued
    assert cert.subject == cert.issuer

    # extensions
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca is True
    assert bc.path_length is None

    ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    assert ku.key_cert_sign is True
    assert ku.crl_sign is True

    # verify certificate signature using its own public key
    _verify_self_signed_signature(cert)


@pytest.mark.parametrize("key_type,key_size", [("rsa", 4096), ("ecc", 384)])
def test_private_key_matches_certificate_public_key(tmp_path: Path, key_type: str, key_size: int):
    passphrase = b"supersecret"
    out_dir = tmp_path / "pki"

    init_ca(
        subject="CN=MicroPKI Root CA",
        key_type=key_type,
        key_size=key_size,
        passphrase=passphrase,
        out_dir=out_dir,
        force=False,
        validity_days=3650,
        logger=None,
    )

    cert = load_cert_pem(out_dir / "certs" / "ca.cert.pem")
    priv = load_private_key_encrypted(out_dir / "private" / "ca.key.pem", passphrase)

    msg = b"microPKI-test-message"

    # TEST-2: sign with private key, verify with cert public key
    if key_type == "rsa":
        sig = priv.sign(msg, padding.PKCS1v15(), hashes.SHA256())
        cert.public_key().verify(sig, msg, padding.PKCS1v15(), hashes.SHA256())
    else:
        sig = priv.sign(msg, ec.ECDSA(hashes.SHA384()))
        cert.public_key().verify(sig, msg, ec.ECDSA(hashes.SHA384()))


def test_encrypted_key_loading_fails_with_wrong_passphrase(tmp_path: Path):
    passphrase = b"supersecret"
    out_dir = tmp_path / "pki"

    init_ca(
        subject="CN=MicroPKI Root CA",
        key_type="rsa",
        key_size=4096,
        passphrase=passphrase,
        out_dir=out_dir,
        force=False,
        validity_days=3650,
        logger=None,
    )

    key_path = out_dir / "private" / "ca.key.pem"

    # TEST-3 negative: wrong passphrase must fail
    with pytest.raises((TypeError, ValueError)):
        load_private_key_encrypted(key_path, b"wrongpass")