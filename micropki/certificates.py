from datetime import datetime, timedelta, timezone
from pathlib import Path
from .serials import generate_certificate_serial_number
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from .csr import verify_csr_signature

from .dn_parser import parse_dn
from .templates import build_leaf_extensions

def generate_self_signed_ca_certificate(
    private_key,
    subject_name: x509.Name,
    validity_days: int,
):


    public_key = private_key.public_key()


    serial_number = generate_certificate_serial_number()

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




    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    )


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


    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(public_key),
        critical=False,
    )


    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key),
        critical=False,
    )


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

def issue_intermediate_certificate(
    csr: x509.CertificateSigningRequest,
    root_cert: x509.Certificate,
    root_private_key,
    validity_days: int = 1825,
    pathlen: int = 0,
) -> x509.Certificate:

    if validity_days <= 0:
        raise ValueError("Validity days must be positive.")

    if pathlen < 0:
        raise ValueError("Path length constraint must be >= 0.")


    verify_csr_signature(csr)

    serial = generate_certificate_serial_number()
    now = datetime.now(timezone.utc)

    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(root_cert.subject)
        .public_key(csr.public_key())
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=validity_days))
    )

    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=pathlen),
        critical=True,
    )

    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=False,
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

    ski = x509.SubjectKeyIdentifier.from_public_key(csr.public_key())
    builder = builder.add_extension(ski, critical=False)

    try:
        root_ski = root_cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_KEY_IDENTIFIER
        ).value

        aki = x509.AuthorityKeyIdentifier(
            key_identifier=root_ski.digest,
            authority_cert_issuer=None,
            authority_cert_serial_number=None,
        )
    except x509.ExtensionNotFound:
        aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(
            root_private_key.public_key()
        )

    builder = builder.add_extension(aki, critical=False)

    if isinstance(root_private_key, rsa.RSAPrivateKey):
        algorithm = hashes.SHA256()
    elif isinstance(root_private_key, ec.EllipticCurvePrivateKey):
        algorithm = hashes.SHA384()
    else:
        raise ValueError("Unsupported Root private key type.")

    return builder.sign(
        private_key=root_private_key,
        algorithm=algorithm,
    )

def issue_leaf_certificate(
    ca_cert: x509.Certificate,
    ca_private_key,
    subject: str,
    public_key,
    template: str,
    san_objects,
    validity_days: int = 365,
) -> x509.Certificate:

    if validity_days <= 0:
        raise ValueError("Validity days must be positive.")

    subject_name = parse_dn(subject)

    serial = x509.random_serial_number()
    now = datetime.now(timezone.utc)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(ca_cert.subject)
        .public_key(public_key)
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=validity_days))
    )

    extensions = build_leaf_extensions(
        template=template,
        public_key=public_key,
        san_objects=san_objects,
    )

    for ext in extensions:
        if isinstance(ext, x509.BasicConstraints):
            builder = builder.add_extension(ext, critical=True)
        elif isinstance(ext, x509.KeyUsage):
            builder = builder.add_extension(ext, critical=True)
        elif isinstance(ext, x509.ExtendedKeyUsage):
            builder = builder.add_extension(ext, critical=False)
        elif isinstance(ext, x509.SubjectAlternativeName):
            builder = builder.add_extension(ext, critical=False)
        else:
            raise ValueError(f"Unsupported extension type: {type(ext)!r}")


    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(public_key),
        critical=False,
    )


    try:
        issuer_ski = ca_cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_KEY_IDENTIFIER
        ).value
        aki = x509.AuthorityKeyIdentifier(
            key_identifier=issuer_ski.digest,
            authority_cert_issuer=None,
            authority_cert_serial_number=None,
        )
    except x509.ExtensionNotFound:
        aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(
            ca_private_key.public_key()
        )

    builder = builder.add_extension(aki, critical=False)


    if isinstance(ca_private_key, rsa.RSAPrivateKey):
        algorithm = hashes.SHA256()
    elif isinstance(ca_private_key, ec.EllipticCurvePrivateKey):
        algorithm = hashes.SHA384()
    else:
        raise ValueError("Unsupported Intermediate CA private key type.")

    return builder.sign(
        private_key=ca_private_key,
        algorithm=algorithm,
    )

def load_cert_pem(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(Path(path).read_bytes())