from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec


def generate_self_signed_ca_certificate(
    private_key,
    subject_name: x509.Name,
    validity_days: int,
):
    """
    Generate self-signed X.509 v3 Root CA certificate.

    Covers:
    - PKI-2
    - PKI-3
    """

    public_key = private_key.public_key()

    # Serial number (CSPRNG, >= 20 bits entropy)
    serial_number = x509.random_serial_number()

    not_before = datetime.now(timezone.utc)
    not_after = not_before + timedelta(days=validity_days)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(subject_name)
        .public_key(public_key)
        .serial_number(serial_number)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )

    # === Extensions (PKI-3) ===

    # Basic Constraints (critical)
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    )

    # Key Usage (critical)
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )

    # Subject Key Identifier
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(public_key),
        critical=False,
    )

    # Authority Key Identifier (self-signed → same as SKI)
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key),
        critical=False,
    )

    # === Signature Algorithm (PKI-2) ===

    if isinstance(private_key, rsa.RSAPrivateKey):
        algorithm = hashes.SHA256()
    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
        algorithm = hashes.SHA384()
    else:
        raise ValueError("Unsupported key type for signing")

    certificate = builder.sign(
        private_key=private_key,
        algorithm=algorithm,
    )

    return certificate


def save_certificate(
    certificate: x509.Certificate,
    out_dir: Path,
    logger=None,
) -> Path:
    """
    Save certificate as:
    <out-dir>/certs/ca.cert.pem

    Covers:
    - PKI-4
    - PKI-5
    - LOG-2 (save event)
    """

    certs_dir = out_dir / "certs"
    certs_dir.mkdir(parents=True, exist_ok=True)

    cert_path = certs_dir / "ca.cert.pem"

    pem_data = certificate.public_bytes(
        encoding=serialization.Encoding.PEM
    )

    with cert_path.open("wb") as f:
        f.write(pem_data)

    if logger:
        logger.info(f"Certificate saved at {cert_path}")

    return cert_path