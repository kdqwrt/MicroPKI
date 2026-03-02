from pathlib import Path
from typing import Union
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key

def generate_private_key(key_type: str, key_size: int):
    """
    Generate RSA 4096 or ECC P-384 private key.
    Covers PKI-1 requirement.
    """
    if key_type == "rsa":
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )

    if key_type == "ecc":
        return ec.generate_private_key(
            ec.SECP384R1(),
            backend=default_backend()
        )

    raise ValueError("Unsupported key type")


def serialize_private_key_encrypted(private_key, passphrase: bytes) -> bytes:
    """
    Serialize private key to encrypted PKCS#8 PEM.
    Covers KEY-1 requirement.
    """
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase)
    )


def save_private_key(
    private_key,
    passphrase: bytes,
    out_dir: Path,
    logger=None
) -> Path:
    """
    Save encrypted private key to:
    <out-dir>/private/ca.key.pem
    Covers KEY-2 requirement.
    """

    private_dir = out_dir / "private"
    private_dir.mkdir(parents=True, exist_ok=True)

    key_path = private_dir / "ca.key.pem"

    pem_data = serialize_private_key_encrypted(private_key, passphrase)

    with key_path.open("wb") as f:
        f.write(pem_data)

    if logger:
        logger.info(f"Private key saved to {key_path}")

    return key_path

def cert_to_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)

def cert_to_der(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)

def load_cert_pem(path: Path) -> x509.Certificate:
    data = path.read_bytes()
    return x509.load_pem_x509_certificate(data)

def load_cert_der(path: Path) -> x509.Certificate:
    data = path.read_bytes()
    return x509.load_der_x509_certificate(data)

def public_key_to_pem(public_key) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

def public_key_to_der(public_key) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

def load_private_key_encrypted(path: Path, passphrase: bytes):
    """
    Load encrypted private key from PEM (TEST-3).
    """
    data = Path(path).read_bytes()
    return load_pem_private_key(data, password=passphrase)