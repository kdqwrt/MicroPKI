import os
from pathlib import Path
from typing import Optional

from cryptography import x509

from .crypto_utils import generate_private_key, save_private_key
from .certificates import generate_self_signed_ca_certificate, save_certificate
from .dn_parser import parse_dn
from .policy import save_policy_file


def init_ca(
    subject: str,
    key_type: str,
    key_size: int,
    passphrase: bytes,
    out_dir: Path,
    force: bool,
    logger=None,
    validity_days: int = 3650,
) -> x509.Certificate:
    """
    Initialize Root CA (Milestone 1).

    Responsibilities:
    - Validate inputs (Root CA key requirements)
    - Create folder structure: <out_dir>/private, <out_dir>/certs
    - Generate private key (RSA 4096 or ECC P-384)
    - Store encrypted private key (PKCS#8 PEM)
    - Issue self-signed Root CA certificate with correct X.509 extensions
    - Save certificate
    - Write policy.txt
    """

    # ---- Basic validation ----
    if key_type not in ("rsa", "ecc"):
        raise ValueError("key_type must be 'rsa' or 'ecc'.")

    # Root CA requirements (defense-in-depth: validate here, not only in CLI)
    if key_type == "rsa" and key_size != 4096:
        raise ValueError("Root CA RSA key size must be exactly 4096 bits.")
    if key_type == "ecc" and key_size != 384:
        raise ValueError("Root CA ECC curve must be P-384 (key_size=384).")

    if validity_days <= 0:
        raise ValueError("validity_days must be a positive integer.")

    if not passphrase or not isinstance(passphrase, (bytes, bytearray)):
        raise ValueError("passphrase must be non-empty bytes.")

    out_dir = Path(out_dir)

    private_dir = out_dir / "private"
    certs_dir = out_dir / "certs"

    # ---- Create directory structure ----
    private_dir.mkdir(parents=True, exist_ok=True)
    certs_dir.mkdir(parents=True, exist_ok=True)

    # ---- Permissions (best effort) ----
    if os.name != "nt":
        try:
            os.chmod(private_dir, 0o700)
        except Exception:
            # do not fail init on chmod issues
            if logger:
                logger.warning("Unable to chmod private directory to 700.")
    else:
        if logger:
            logger.warning("Windows: POSIX chmod is not fully supported; rely on NTFS ACLs.")

    key_path = private_dir / "ca.key.pem"
    cert_path = certs_dir / "ca.cert.pem"

    # ---- Overwrite protection / force ----
    if (key_path.exists() or cert_path.exists()) and not force:
        existing = []
        if key_path.exists():
            existing.append(str(key_path))
        if cert_path.exists():
            existing.append(str(cert_path))
        raise FileExistsError(
            "Output already exists (use --force to overwrite): " + ", ".join(existing)
        )

    if force:
        # Explicitly remove old outputs to avoid mixing old/new artifacts
        for p in (key_path, cert_path):
            if p.exists():
                try:
                    p.unlink()
                except Exception as e:
                    raise PermissionError(f"Unable to remove existing file {p}: {e}")

    # ---- Generate private key ----
    if logger:
        logger.info("Generating Root CA private key...")
    private_key = generate_private_key(key_type, key_size)
    if logger:
        logger.info("Private key generated.")

    # ---- Save encrypted private key ----
    if logger:
        logger.info("Saving encrypted private key...")
    saved_key_path = save_private_key(private_key, passphrase, out_dir, logger=logger)

    if os.name != "nt":
        try:
            os.chmod(saved_key_path, 0o600)
        except Exception:
            if logger:
                logger.warning("Unable to chmod private key file to 600.")

    # ---- Parse subject DN ----
    subject_name = parse_dn(subject)

    # ---- Generate self-signed Root CA certificate ----
    if logger:
        logger.info("Generating self-signed Root CA certificate...")
    certificate = generate_self_signed_ca_certificate(
        private_key=private_key,
        subject_name=subject_name,
        validity_days=validity_days,
    )
    if logger:
        logger.info("Root CA certificate generated and signed.")

    # ---- Save certificate ----
    save_certificate(certificate, out_dir, logger=logger)

    # ---- Write policy file ----
    save_policy_file(
        certificate=certificate,
        key_type=key_type,
        key_size=key_size,
        out_dir=out_dir,
        logger=logger,
    )

    if logger:
        logger.info("Root CA initialization completed successfully.")

    return certificate