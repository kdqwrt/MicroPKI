import os
import time
from pathlib import Path
from typing import Optional
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

from .crypto_utils import (
    generate_private_key,
    load_private_key_encrypted,
    load_cert_pem,
)
from .certificates import (
    generate_self_signed_ca_certificate,
    issue_intermediate_certificate,
    issue_leaf_certificate,
)
from .dn_parser import parse_dn
from .policy import save_policy_file, append_intermediate_policy
from .csr import build_intermediate_csr, save_csr_pem
from .templates import parse_san_entries, validate_template_sans


if os.name != 'nt':
    import fcntl
else:
    class fcntl:
        LOCK_EX = 0
        LOCK_UN = 0

        @staticmethod
        def flock(f, flags):
            pass


def _write_file_with_lock(file_path: Path, content: bytes, logger=None, max_retries: int = 3) -> bool:
    file_path.parent.mkdir(parents=True, exist_ok=True)

    for attempt in range(max_retries):
        try:

            temp_path = file_path.with_suffix('.tmp')

            with open(temp_path, 'wb') as f:
                if hasattr(fcntl, 'flock') and os.name != 'nt':
                    try:
                        fcntl.flock(f, fcntl.LOCK_EX)
                    except Exception:
                        pass

                f.write(content)
                f.flush()
                os.fsync(f.fileno())

            temp_path.replace(file_path)


            if file_path.exists() and file_path.stat().st_size == len(content):
                if logger:
                    logger.debug(f"File written successfully: {file_path}")
                return True

            raise IOError(f"File size mismatch after write: {file_path}")

        except Exception as e:
            if attempt == max_retries - 1:
                if logger:
                    logger.error(f"Failed to write file after {max_retries} attempts: {e}")
                raise
            time.sleep(0.1 * (attempt + 1))

    return False



def _verify_certificate_file(cert_path: Path, expected_cert: x509.Certificate, logger=None) -> bool:
    try:
        with open(cert_path, 'rb') as f:
            written_cert = x509.load_pem_x509_certificate(f.read())


        if written_cert.serial_number != expected_cert.serial_number:
            raise ValueError(
                f"Serial number mismatch: expected {hex(expected_cert.serial_number)}, "
                f"got {hex(written_cert.serial_number)}"
            )


        if written_cert.subject != expected_cert.subject:
            raise ValueError("Subject DN mismatch")

        from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

        pub_key = written_cert.public_key()

        if isinstance(pub_key, rsa.RSAPublicKey):

            expected_pub_key = expected_cert.public_key()
            if isinstance(expected_pub_key, rsa.RSAPublicKey):
                if pub_key.public_numbers() != expected_pub_key.public_numbers():
                    raise ValueError("Public key mismatch")
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            expected_pub_key = expected_cert.public_key()
            if isinstance(expected_pub_key, ec.EllipticCurvePublicKey):
                if pub_key.public_numbers() != expected_pub_key.public_numbers():
                    raise ValueError("Public key mismatch")

        if logger:
            logger.debug(f"Certificate file integrity verified: {cert_path}")

        return True

    except Exception as e:
        if logger:
            logger.error(f"Certificate file verification failed: {e}")
        raise ValueError(f"Certificate file verification failed: {e}")


def init_ca(
        subject: str,
        key_type: str,
        key_size: int,
        passphrase: bytes,
        out_dir: Path,
        force: bool,
        db_path: Optional[Path] = None,
        logger=None,
        validity_days: int = 3650,
) -> x509.Certificate:

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


    subject_name = parse_dn(subject)
    certificate = generate_self_signed_ca_certificate(
        private_key=private_key,
        subject_name=subject_name,
        validity_days=validity_days,
    )
    if logger:
        logger.info("Root CA certificate generated and signed.")

    cert_pem = certificate.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
    )

    cert_id = None
    files_written = False
    repo = None

    try:
        if db_path:
            from .repository import CertificateRepository
            repo = CertificateRepository(db_path, logger)
            cert_id = repo.insert_certificate(certificate, cert_pem, "valid")
            if logger:
                logger.info(f"Root CA record created in database: id={cert_id}")

        try:
            _write_file_with_lock(key_path, key_pem, logger)
            if os.name != "nt":
                try:
                    os.chmod(key_path, 0o600)
                except Exception:
                    if logger:
                        logger.warning("Unable to chmod private key file to 600.")

            _write_file_with_lock(cert_path, certificate.public_bytes(serialization.Encoding.PEM), logger)

            files_written = True

        except Exception as file_error:
            if cert_id is not None and repo:
                try:
                    repo.delete_certificate(hex(certificate.serial_number))
                    if logger:
                        logger.warning(f"Database record {cert_id} deleted due to file write error")
                except Exception as db_error:
                    if logger:
                        logger.error(f"Failed to rollback database record: {db_error}")
            raise file_error

        _verify_certificate_file(cert_path, certificate, logger)

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

    except Exception as e:
        if files_written:
            try:
                if cert_path.exists():
                    cert_path.unlink()
                if key_path.exists():
                    key_path.unlink()
                if logger:
                    logger.warning(f"Cleaned up files after error: {e}")
            except Exception as cleanup_error:
                if logger:
                    logger.error(f"Failed to cleanup files: {cleanup_error}")

        if logger:
            logger.error(f"Root CA initialization failed: {e}")
        raise


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
        db_path: Optional[Path] = None,
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


    root_cert = x509.load_pem_x509_certificate(root_cert_path.read_bytes())
    root_key = load_private_key_encrypted(root_key_path, root_passphrase)

    if logger:
        logger.info("Generating Intermediate CA private key...")
    intermediate_key = generate_private_key(key_type, key_size)


    if logger:
        logger.info("Generating Intermediate CA CSR...")
    csr = build_intermediate_csr(
        subject=subject,
        private_key=intermediate_key,
        pathlen=pathlen,
    )


    if logger:
        logger.info("Signing Intermediate CA certificate with Root CA...")
    intermediate_cert = issue_intermediate_certificate(
        csr=csr,
        root_cert=root_cert,
        root_private_key=root_key,
        validity_days=validity_days,
        pathlen=pathlen,
    )

    cert_pem = intermediate_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    key_pem = intermediate_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(intermediate_passphrase),
    )

    cert_id = None
    files_written = False
    repo = None

    try:
        if db_path:
            from .repository import CertificateRepository
            repo = CertificateRepository(db_path, logger)
            cert_id = repo.insert_certificate(intermediate_cert, cert_pem, "valid")
            if logger:
                logger.info(f"Intermediate CA record created in database: id={cert_id}")


        try:
            _write_file_with_lock(intermediate_key_path, key_pem, logger)
            if os.name != "nt":
                try:
                    os.chmod(intermediate_key_path, 0o600)
                except Exception:
                    if logger:
                        logger.warning("Unable to chmod intermediate key file to 600.")

            _write_file_with_lock(intermediate_csr_path, csr_pem, logger)
            _write_file_with_lock(
                intermediate_cert_path,
                intermediate_cert.public_bytes(serialization.Encoding.PEM),
                logger
            )

            files_written = True

        except Exception as file_error:
            if cert_id is not None and repo:
                try:
                    repo.delete_certificate(hex(intermediate_cert.serial_number))
                    if logger:
                        logger.warning(f"Database record {cert_id} deleted due to file write error")
                except Exception as db_error:
                    if logger:
                        logger.error(f"Failed to rollback database record: {db_error}")
            raise file_error

        _verify_certificate_file(intermediate_cert_path, intermediate_cert, logger)

        append_intermediate_policy(
            policy_path=out_dir / "policy.txt",
            intermediate_cert=intermediate_cert,
            issuer=root_cert.subject.rfc4514_string(),
            key_type=key_type,
            key_size=key_size,
            pathlen=pathlen,
        )

        if logger:
            logger.info(f"Intermediate certificate saved to {intermediate_cert_path}")
            logger.info("Intermediate CA issuance completed successfully.")

        return {
            "key": intermediate_key_path,
            "csr": intermediate_csr_path,
            "cert": intermediate_cert_path,
            "db_id": cert_id,
        }

    except Exception as e:

        if files_written:
            try:
                if intermediate_cert_path.exists():
                    intermediate_cert_path.unlink()
                if intermediate_key_path.exists():
                    intermediate_key_path.unlink()
                if intermediate_csr_path.exists():
                    intermediate_csr_path.unlink()
                if logger:
                    logger.warning(f"Cleaned up files after error: {e}")
            except Exception as cleanup_error:
                if logger:
                    logger.error(f"Failed to cleanup files: {cleanup_error}")

        if logger:
            logger.error(f"Intermediate CA issuance failed: {e}")
        raise


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
        db_path: Optional[Path] = None,
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
        raise FileNotFoundError(f"CA certificate not found: {ca_cert_path}")
    if not ca_key_path.exists():
        raise FileNotFoundError(f"CA private key not found: {ca_key_path}")

    if csr_path is not None:
        csr_path = Path(csr_path)
        if not csr_path.exists():
            raise FileNotFoundError(f"CSR not found: {csr_path}")

    parse_dn(subject)
    out_dir.mkdir(parents=True, exist_ok=True)


    ca_cert = load_cert_pem(ca_cert_path)
    ca_key = load_private_key_encrypted(ca_key_path, ca_passphrase)


    csr = None
    leaf_key = None

    if csr_path is not None:
        csr = x509.load_pem_x509_csr(Path(csr_path).read_bytes())
        if not csr.is_signature_valid:
            raise ValueError("CSR signature verification failed.")


        try:
            from cryptography.x509.oid import ExtensionOID
            csr_bc = csr.extensions.get_extension_for_oid(
                ExtensionOID.BASIC_CONSTRAINTS
            ).value
            if csr_bc.ca:
                raise ValueError("CSR requests CA=TRUE for end-entity certificate.")
        except x509.ExtensionNotFound:
            pass

        leaf_public_key = csr.public_key()
        if logger:
            logger.info(f"Using public key from CSR: {csr_path}")
    else:
        if logger:
            logger.info("Generating end-entity private key...")
        leaf_key = generate_private_key(key_type, key_size)
        leaf_public_key = leaf_key.public_key()


    san_objects = parse_san_entries(san_entries or [])
    validate_template_sans(template, san_objects)

    if logger:
        logger.info(
            f"Issuing end-entity certificate: template={template}, subject={subject}, "
            f"sans={[str(x.value) if hasattr(x, 'value') else str(x) for x in san_objects]}"
        )

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
    key_path = out_dir / f"{safe_base_name}.key.pem" if leaf_key else None

    cert_pem = leaf_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')

    cert_id = None
    files_written = False
    repo = None

    try:
        if db_path:
            from .repository import CertificateRepository
            repo = CertificateRepository(db_path, logger)
            cert_id = repo.insert_certificate(leaf_cert, cert_pem, "valid")
            if logger:
                logger.info(
                    f"Certificate record created in database: id={cert_id}, serial={hex(leaf_cert.serial_number)}")


        try:
            _write_file_with_lock(cert_path, leaf_cert.public_bytes(serialization.Encoding.PEM), logger)

            if leaf_key is not None:
                key_pem = leaf_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
                _write_file_with_lock(key_path, key_pem, logger)

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

            files_written = True

        except Exception as file_error:

            if cert_id is not None and repo:
                try:
                    repo.delete_certificate(hex(leaf_cert.serial_number))
                    if logger:
                        logger.warning(f"Database record {cert_id} deleted due to file write error")
                except Exception as db_error:
                    if logger:
                        logger.error(f"Failed to rollback database record: {db_error}")
            raise file_error


        _verify_certificate_file(cert_path, leaf_cert, logger)


        issued_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        if logger:
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
            "db_id": cert_id,
        }

    except Exception as e:
        if files_written:
            try:
                if cert_path.exists():
                    cert_path.unlink()
                if key_path and key_path.exists():
                    key_path.unlink()
                if logger:
                    logger.warning(f"Cleaned up files after error: {e}")
            except Exception as cleanup_error:
                if logger:
                    logger.error(f"Failed to cleanup files: {cleanup_error}")

        if cert_id is not None and repo:
            try:
                repo.mark_issuance_failed(hex(leaf_cert.serial_number), str(e))
                if logger:
                    logger.warning(f"Database record {cert_id} marked as issuance_failed")
            except Exception:
                pass

        if logger:
            logger.error(f"Certificate issuance failed: {e}")
        raise