from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key


def generate_private_key(key_type: str, key_size: int):

    if key_type == "rsa":
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )

    if key_type == "ecc":

        if key_size == 384:
            return ec.generate_private_key(ec.SECP384R1())
        if key_size == 256:
            return ec.generate_private_key(ec.SECP256R1())

        raise ValueError("Unsupported ECC key size. Use 384 (P-384) or 256 (P-256).")

    raise ValueError("Unsupported key type")


def serialize_private_key_encrypted(private_key, passphrase: bytes) -> bytes:

    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
    )


def serialize_private_key_unencrypted(private_key) -> bytes:

    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def save_private_key(
    private_key,
    passphrase: bytes,
    out_dir: Path,
    logger=None,
) -> Path:

    private_dir = Path(out_dir) / "private"
    private_dir.mkdir(parents=True, exist_ok=True)

    key_path = private_dir / "ca.key.pem"
    pem_data = serialize_private_key_encrypted(private_key, passphrase)

    key_path.write_bytes(pem_data)

    if logger:
        logger.info(f"Private key saved to {key_path}")

    return key_path


def save_private_key_encrypted_to_path(
    private_key,
    passphrase: bytes,
    path: Path,
    logger=None,
) -> Path:

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    pem_data = serialize_private_key_encrypted(private_key, passphrase)
    path.write_bytes(pem_data)

    if logger:
        logger.info(f"Encrypted private key saved to {path}")

    return path


def save_private_key_unencrypted(
    private_key,
    path: Path,
    logger=None,
) -> Path:

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    pem_data = serialize_private_key_unencrypted(private_key)
    path.write_bytes(pem_data)

    if logger:
        logger.warning(
            f"Unencrypted private key saved to {path}. "
            f"Protect this file with filesystem permissions."
        )

    return path


def cert_to_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def cert_to_der(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def load_cert_pem(path: Path) -> x509.Certificate:
    data = Path(path).read_bytes()
    return x509.load_pem_x509_certificate(data)


def load_cert_der(path: Path) -> x509.Certificate:
    data = Path(path).read_bytes()
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

    data = Path(path).read_bytes()
    return load_pem_private_key(data, password=passphrase)