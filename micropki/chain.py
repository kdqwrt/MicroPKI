from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtensionOID, ExtendedKeyUsageOID

from .certificates import load_cert_pem


class ChainValidationError(Exception):
    """Raised when certificate chain validation fails."""


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _cert_time_ok(cert: x509.Certificate, now: datetime) -> bool:
    not_before = getattr(cert, "not_valid_before_utc", None)
    not_after = getattr(cert, "not_valid_after_utc", None)

    if not_before is None:
        not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
    if not_after is None:
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)

    return not_before <= now <= not_after


def _verify_signature(issuer_cert: x509.Certificate, child_cert: x509.Certificate) -> None:
    pub = issuer_cert.public_key()

    if isinstance(pub, rsa.RSAPublicKey):
        pub.verify(
            child_cert.signature,
            child_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            child_cert.signature_hash_algorithm,
        )
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        pub.verify(
            child_cert.signature,
            child_cert.tbs_certificate_bytes,
            ec.ECDSA(child_cert.signature_hash_algorithm),
        )
    else:
        raise ChainValidationError("Unsupported issuer public key algorithm.")


def _require_basic_constraints(cert: x509.Certificate, who: str) -> x509.BasicConstraints:
    try:
        return cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        ).value
    except x509.ExtensionNotFound:
        raise ChainValidationError(f"{who} certificate is missing Basic Constraints.")


def _require_key_usage(cert: x509.Certificate, who: str) -> x509.KeyUsage:
    try:
        return cert.extensions.get_extension_for_oid(
            ExtensionOID.KEY_USAGE
        ).value
    except x509.ExtensionNotFound:
        raise ChainValidationError(f"{who} certificate is missing Key Usage.")


def _check_eku_for_template(cert: x509.Certificate, template: str) -> None:
    try:
        eku = cert.extensions.get_extension_for_oid(
            ExtensionOID.EXTENDED_KEY_USAGE
        ).value
    except x509.ExtensionNotFound:
        raise ChainValidationError("Leaf certificate is missing Extended Key Usage.")

    if template == "server" and ExtendedKeyUsageOID.SERVER_AUTH not in eku:
        raise ChainValidationError("Leaf certificate is missing serverAuth EKU.")

    if template == "client" and ExtendedKeyUsageOID.CLIENT_AUTH not in eku:
        raise ChainValidationError("Leaf certificate is missing clientAuth EKU.")

    if template == "code_signing" and ExtendedKeyUsageOID.CODE_SIGNING not in eku:
        raise ChainValidationError("Leaf certificate is missing codeSigning EKU.")


def verify_chain(
    root_cert_path: Path,
    intermediate_cert_path: Path,
    leaf_cert_path: Path,
    template: str | None = None,
) -> dict[str, str]:

    root = load_cert_pem(root_cert_path)
    intermediate = load_cert_pem(intermediate_cert_path)
    leaf = load_cert_pem(leaf_cert_path)

    now = _now_utc()

    if not _cert_time_ok(root, now):
        raise ChainValidationError("Root certificate is not currently valid.")
    if not _cert_time_ok(intermediate, now):
        raise ChainValidationError("Intermediate certificate is not currently valid.")
    if not _cert_time_ok(leaf, now):
        raise ChainValidationError("Leaf certificate is not currently valid.")

    if root.issuer != root.subject:
        raise ChainValidationError("Root certificate is not self-issued.")

    if intermediate.issuer != root.subject:
        raise ChainValidationError("Intermediate issuer does not match Root subject.")

    if leaf.issuer != intermediate.subject:
        raise ChainValidationError("Leaf issuer does not match Intermediate subject.")

    try:
        _verify_signature(root, intermediate)
    except Exception as e:
        raise ChainValidationError(
            f"Intermediate certificate signature verification failed: {e}"
        )

    try:
        _verify_signature(intermediate, leaf)
    except Exception as e:
        raise ChainValidationError(
            f"Leaf certificate signature verification failed: {e}"
        )

    root_bc = _require_basic_constraints(root, "Root")
    inter_bc = _require_basic_constraints(intermediate, "Intermediate")
    leaf_bc = _require_basic_constraints(leaf, "Leaf")

    if not root_bc.ca:
        raise ChainValidationError("Root certificate is not marked as CA.")
    if not inter_bc.ca:
        raise ChainValidationError("Intermediate certificate is not marked as CA.")
    if leaf_bc.ca:
        raise ChainValidationError("Leaf certificate must have CA=FALSE.")


    if root_bc.path_length is not None:
        raise ChainValidationError(
            "Root certificate must not include a path length constraint."
        )


    if inter_bc.path_length is not None and inter_bc.path_length < 0:
        raise ChainValidationError("Intermediate certificate has invalid path length.")

    root_ku = _require_key_usage(root, "Root")
    inter_ku = _require_key_usage(intermediate, "Intermediate")

    if not root_ku.key_cert_sign or not root_ku.crl_sign:
        raise ChainValidationError(
            "Root certificate Key Usage must include keyCertSign and cRLSign."
        )

    if not inter_ku.key_cert_sign or not inter_ku.crl_sign:
        raise ChainValidationError(
            "Intermediate certificate Key Usage must include keyCertSign and cRLSign."
        )

    if template is not None:
        _check_eku_for_template(leaf, template)

    return {
        "root_subject": root.subject.rfc4514_string(),
        "intermediate_subject": intermediate.subject.rfc4514_string(),
        "leaf_subject": leaf.subject.rfc4514_string(),
    }