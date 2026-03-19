from __future__ import annotations

from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from .dn_parser import parse_dn


class CSRValidationError(ValueError):
    """Raised when a CSR is invalid or its signature cannot be verified."""


def build_intermediate_csr(
    subject: str,
    private_key,
    pathlen: int = 0,
) -> x509.CertificateSigningRequest:

    if pathlen < 0:
        raise CSRValidationError("Path length constraint must be >= 0.")

    subject_name = parse_dn(subject)

    builder = x509.CertificateSigningRequestBuilder().subject_name(subject_name)

    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=pathlen),
        critical=True,
    )

    if isinstance(private_key, rsa.RSAPrivateKey):
        algorithm = hashes.SHA256()
    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
        algorithm = hashes.SHA384()
    else:
        raise CSRValidationError("Unsupported private key type for CSR generation.")

    return builder.sign(private_key=private_key, algorithm=algorithm)


def save_csr_pem(csr: x509.CertificateSigningRequest, path: Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(csr.public_bytes(serialization.Encoding.PEM))
    return path


def load_csr_pem(path: Path) -> x509.CertificateSigningRequest:
    data = Path(path).read_bytes()
    return x509.load_pem_x509_csr(data)


def verify_csr_signature(csr: x509.CertificateSigningRequest) -> None:
    public_key = csr.public_key()

    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                csr.signature,
                csr.tbs_certrequest_bytes,
                padding.PKCS1v15(),
                csr.signature_hash_algorithm,
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(
                csr.signature,
                csr.tbs_certrequest_bytes,
                ec.ECDSA(csr.signature_hash_algorithm),
            )
        else:
            raise CSRValidationError("Unsupported public key type in CSR.")

    except Exception as e:
        raise CSRValidationError("CSR signature verification failed.") from e