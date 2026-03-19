from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa

from micropki.csr import build_intermediate_csr
from micropki.certificates import issue_intermediate_certificate
from micropki.ca import init_ca


def test_issue_intermediate_certificate(tmp_path):
    passphrase = b"rootpass"
    out_dir = tmp_path / "pki"

    init_ca(
        subject="CN=Root CA,O=MicroPKI,C=DE",
        key_type="rsa",
        key_size=4096,
        passphrase=passphrase,
        out_dir=out_dir,
        force=False,
        validity_days=3650,
        logger=None,
    )

    root_cert = x509.load_pem_x509_certificate(
        (out_dir / "certs" / "ca.cert.pem").read_bytes()
    )

    from micropki.crypto_utils import load_private_key_encrypted

    root_key = load_private_key_encrypted(
        out_dir / "private" / "ca.key.pem",
        passphrase,
    )

    intermediate_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )

    csr = build_intermediate_csr(
        subject="CN=Intermediate CA,O=MicroPKI,C=DE",
        private_key=intermediate_key,
        pathlen=0,
    )

    cert = issue_intermediate_certificate(
        csr=csr,
        root_cert=root_cert,
        root_private_key=root_key,
        validity_days=1825,
        pathlen=0,
    )

    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value

    assert bc.ca is True
    assert bc.path_length == 0