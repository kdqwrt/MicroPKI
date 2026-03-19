import os
from pathlib import Path
from typing import Optional
from cryptography.x509.oid import ExtensionOID
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
from .crypto_utils import (
    generate_private_key,
    save_private_key,
    save_private_key_unencrypted,
    load_private_key_encrypted,
    load_cert_pem,
)
from .certificates import (
    generate_self_signed_ca_certificate,
    save_certificate,
    issue_intermediate_certificate,
)
from .dn_parser import parse_dn
from .policy import save_policy_file, append_intermediate_policy
from .csr import build_intermediate_csr, save_csr_pem

from .templates import parse_san_entries, validate_template_sans

from .certificates import issue_leaf_certificate

def _save_encrypted_private_key_to_path(private_key, passphrase: bytes, path: Path) -> Path:

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
    )

    path.write_bytes(pem)
    return path


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
    Initialize Root CA

    Responsibilities:
    - Validate inputs (Root CA key requirements)
    - Create folder structure: <out_dir>/private, <out_dir>/certs
    - Generate private key (RSA 4096 or ECC P-384)
    - Store encrypted private key (PKCS#8 PEM)
    - Issue self-signed Root CA certificate with correct X.509 extensions
    - Save certificate
    - Write policy.txt
    """


    if key_type not in ("rsa", "ecc"):
        raise ValueError("key_type must be 'rsa' or 'ecc'.")

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


    private_dir.mkdir(parents=True, exist_ok=True)
    certs_dir.mkdir(parents=True, exist_ok=True)


    if os.name != "nt":
        try:
            os.chmod(private_dir, 0o700)
        except Exception:
            if logger:
                logger.warning("Unable to chmod private directory to 700.")
    else:
        if logger:
            logger.warning("Windows: POSIX chmod is not fully supported; rely on NTFS ACLs.")

    key_path = private_dir / "ca.key.pem"
    cert_path = certs_dir / "ca.cert.pem"


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
        for p in (key_path, cert_path):
            if p.exists():
                try:
                    p.unlink()
                except Exception as e:
                    raise PermissionError(f"Unable to remove existing file {p}: {e}")


    if logger:
        logger.info("Generating Root CA private key...")
    private_key = generate_private_key(key_type, key_size)
    if logger:
        logger.info("Private key generated.")


    if logger:
        logger.info("Saving encrypted private key...")
    saved_key_path = save_private_key(private_key, passphrase, out_dir, logger=logger)

    if os.name != "nt":
        try:
            os.chmod(saved_key_path, 0o600)
        except Exception:
            if logger:
                logger.warning("Unable to chmod private key file to 600.")


    subject_name = parse_dn(subject)


    if logger:
        logger.info("Generating self-signed Root CA certificate...")
    certificate = generate_self_signed_ca_certificate(
        private_key=private_key,
        subject_name=subject_name,
        validity_days=validity_days,
    )
    if logger:
        logger.info("Root CA certificate generated and signed.")


    save_certificate(certificate, out_dir, logger=logger)


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


def issue_intermediate_ca(
    root_cert_path: Path,
    root_key_path: Path,
    root_passphrase: bytes,
    subject: str,
    key_type: str,
    key_size: int,
    intermediate_passphrase: bytes,
    out_dir: Path,
    validity_days: int = 1825,
    pathlen: int = 0,
    force: bool = False,
    logger=None,
):

    if key_type not in ("rsa", "ecc"):
        raise ValueError("key_type must be 'rsa' or 'ecc'.")

    if key_type == "rsa" and key_size != 4096:
        raise ValueError("Intermediate CA RSA key size must be exactly 4096 bits.")
    if key_type == "ecc" and key_size != 384:
        raise ValueError("Intermediate CA ECC curve must be P-384 (key_size=384).")

    if validity_days <= 0:
        raise ValueError("validity_days must be a positive integer.")

    if pathlen < 0:
        raise ValueError("pathlen must be >= 0.")

    if not root_passphrase or not isinstance(root_passphrase, (bytes, bytearray)):
        raise ValueError("root_passphrase must be non-empty bytes.")

    if not intermediate_passphrase or not isinstance(intermediate_passphrase, (bytes, bytearray)):
        raise ValueError("intermediate_passphrase must be non-empty bytes.")

    out_dir = Path(out_dir)
    root_cert_path = Path(root_cert_path)
    root_key_path = Path(root_key_path)

    if not root_cert_path.exists():
        raise FileNotFoundError(f"Root certificate not found: {root_cert_path}")
    if not root_key_path.exists():
        raise FileNotFoundError(f"Root private key not found: {root_key_path}")


    parse_dn(subject)

    private_dir = out_dir / "private"
    certs_dir = out_dir / "certs"
    csrs_dir = out_dir / "csrs"

    private_dir.mkdir(parents=True, exist_ok=True)
    certs_dir.mkdir(parents=True, exist_ok=True)
    csrs_dir.mkdir(parents=True, exist_ok=True)

    if os.name != "nt":
        try:
            os.chmod(private_dir, 0o700)
        except Exception:
            if logger:
                logger.warning("Unable to chmod private directory to 700.")
    else:
        if logger:
            logger.warning("Windows: POSIX chmod is not fully supported; rely on NTFS ACLs.")

    intermediate_key_path = private_dir / "intermediate.key.pem"
    intermediate_cert_path = certs_dir / "intermediate.cert.pem"
    intermediate_csr_path = csrs_dir / "intermediate.csr.pem"


    existing_outputs = [
        p for p in (intermediate_key_path, intermediate_cert_path, intermediate_csr_path) if p.exists()
    ]
    if existing_outputs and not force:
        raise FileExistsError(
            "Output already exists (use --force to overwrite): "
            + ", ".join(str(p) for p in existing_outputs)
        )

    if force:
        for p in (intermediate_key_path, intermediate_cert_path, intermediate_csr_path):
            if p.exists():
                try:
                    p.unlink()
                except Exception as e:
                    raise PermissionError(f"Unable to remove existing file {p}: {e}")


    if logger:
        logger.info("Generating Intermediate CA private key...")
    intermediate_key = generate_private_key(key_type, key_size)
    if logger:
        logger.info("Intermediate CA private key generated.")


    if logger:
        logger.info("Saving Intermediate CA encrypted private key...")
    _save_encrypted_private_key_to_path(
        intermediate_key,
        intermediate_passphrase,
        intermediate_key_path,
    )

    if os.name != "nt":
        try:
            os.chmod(intermediate_key_path, 0o600)
        except Exception:
            if logger:
                logger.warning("Unable to chmod Intermediate key file to 600.")

    if logger:
        logger.info(f"Intermediate key saved to {intermediate_key_path}")


    root_cert = x509.load_pem_x509_certificate(root_cert_path.read_bytes())
    root_key = load_private_key_encrypted(root_key_path, root_passphrase)


    if logger:
        logger.info("Generating Intermediate CA CSR...")
    csr = build_intermediate_csr(
        subject=subject,
        private_key=intermediate_key,
        pathlen=pathlen,
    )
    save_csr_pem(csr, intermediate_csr_path)
    if logger:
        logger.info(f"Intermediate CSR saved to {intermediate_csr_path}")


    if logger:
        logger.info("Signing Intermediate CA certificate with Root CA...")
    intermediate_cert = issue_intermediate_certificate(
        csr=csr,
        root_cert=root_cert,
        root_private_key=root_key,
        validity_days=validity_days,
        pathlen=pathlen,
    )

    intermediate_cert_path.write_bytes(
        intermediate_cert.public_bytes(serialization.Encoding.PEM)
    )

    if logger:
        logger.info(f"Intermediate certificate saved to {intermediate_cert_path}")


    append_intermediate_policy(
        policy_path=out_dir / "policy.txt",
        intermediate_cert=intermediate_cert,
        issuer=root_cert.subject.rfc4514_string(),
        key_type=key_type,
        key_size=key_size,
        pathlen=pathlen,
    )

    if logger:
        logger.info("policy.txt updated with Intermediate CA section")
        logger.info("Intermediate CA certificate issuance completed successfully.")

    return {
        "key": intermediate_key_path,
        "csr": intermediate_csr_path,
        "cert": intermediate_cert_path,
    }

def issue_end_entity_certificate(
    ca_cert_path: Path,
    ca_key_path: Path,
    ca_passphrase: bytes,
    template: str,
    subject: str,
    san_entries,
    out_dir: Path,
    validity_days: int = 365,
    key_type: str = "rsa",
    key_size: int = 2048,
    csr_path: Optional[Path] = None,
    logger=None,
):

    if validity_days <= 0:
        raise ValueError("validity_days must be a positive integer.")

    if key_type not in ("rsa", "ecc"):
        raise ValueError("key_type must be 'rsa' or 'ecc'.")

    if key_type == "rsa" and key_size < 2048:
        raise ValueError("Leaf RSA key size must be at least 2048 bits.")

    if key_type == "ecc" and key_size != 256:
        raise ValueError("Leaf ECC key size must be 256 bits (P-256).")

    if not ca_passphrase or not isinstance(ca_passphrase, (bytes, bytearray)):
        raise ValueError("ca_passphrase must be non-empty bytes.")

    out_dir = Path(out_dir)
    ca_cert_path = Path(ca_cert_path)
    ca_key_path = Path(ca_key_path)

    if not ca_cert_path.exists():
        raise FileNotFoundError(f"Intermediate CA certificate not found: {ca_cert_path}")
    if not ca_key_path.exists():
        raise FileNotFoundError(f"Intermediate CA private key not found: {ca_key_path}")

    if csr_path is not None:
        csr_path = Path(csr_path)
        if not csr_path.exists():
            raise FileNotFoundError(f"CSR not found: {csr_path}")


    parse_dn(subject)

    out_dir.mkdir(parents=True, exist_ok=True)


    ca_cert = load_cert_pem(ca_cert_path)
    ca_key = load_private_key_encrypted(ca_key_path, ca_passphrase)

    csr = None
    if csr_path is not None:
        csr = x509.load_pem_x509_csr(Path(csr_path).read_bytes())

        if not csr.is_signature_valid:
            raise ValueError("CSR signature verification failed.")

        try:
            csr_bc = csr.extensions.get_extension_for_oid(
                ExtensionOID.BASIC_CONSTRAINTS
            ).value
            if csr_bc.ca:
                raise ValueError("CSR requests CA=TRUE for end-entity certificate.")
        except x509.ExtensionNotFound:
            pass


    san_objects = parse_san_entries(san_entries or [])
    validate_template_sans(template, san_objects)

    if logger:
        logger.info(
            f"Issuing end-entity certificate: template={template}, subject={subject}, "
            f"sans={[str(x.value) if hasattr(x, 'value') else str(x) for x in san_objects]}"
        )


    leaf_key = None

    if csr is None:
        if logger:
            logger.info("Generating end-entity private key...")
        leaf_key = generate_private_key(key_type, key_size)
        leaf_public_key = leaf_key.public_key()
    else:
        if logger:
            logger.info(f"Using public key from CSR: {csr_path}")
        leaf_public_key = csr.public_key()


    leaf_cert = issue_leaf_certificate(
        ca_cert=ca_cert,
        ca_private_key=ca_key,
        subject=subject,
        public_key=leaf_public_key,
        template=template,
        san_objects=san_objects,
        validity_days=validity_days,
    )


    subject_name = parse_dn(subject)
    common_names = subject_name.get_attributes_for_oid(NameOID.COMMON_NAME)
    if common_names:
        base_name = common_names[0].value.strip()
    else:
        base_name = f"cert-{leaf_cert.serial_number:x}"

    safe_base_name = "".join(
        ch if ch.isalnum() or ch in ("-", "_", ".") else "_"
        for ch in base_name
    )

    cert_path = out_dir / f"{safe_base_name}.cert.pem"
    key_path = out_dir / f"{safe_base_name}.key.pem"


    cert_path.write_bytes(
        leaf_cert.public_bytes(serialization.Encoding.PEM)
    )


    if leaf_key is not None:

        save_private_key_unencrypted(
            leaf_key,
            key_path,
            logger=logger,
        )

        if os.name != "nt":
            try:
                os.chmod(key_path, 0o600)
            except Exception:
                if logger:
                    logger.warning("Unable to chmod end-entity private key file to 600.")
        else:
            if logger:
                logger.warning(
                    "Windows: end-entity private key is stored unencrypted; rely on NTFS ACLs."
                )
    else:
        key_path = None

    if logger:
        issued_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        logger.info(f"End-entity certificate saved to {cert_path}")
        if key_path is not None:
            logger.warning("End-entity private key is stored unencrypted.")
        logger.info(
            "Issued certificate serial=%s subject=%s template=%s issued_at=%s",
            hex(leaf_cert.serial_number),
            leaf_cert.subject.rfc4514_string(),
            template,
            issued_at,
        )

    return {
        "cert": cert_path,
        "key": key_path,
        "certificate": leaf_cert,
    }