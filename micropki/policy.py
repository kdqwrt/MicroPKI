from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509


def _dt_iso_utc(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def save_policy_file(
    certificate: x509.Certificate,
    key_type: str,
    key_size: int,
    out_dir: Path,
    logger=None,
    *,
    purpose: str = "Root CA for MicroPKI demonstration",
    policy_version: str = "1.0",
) -> Path:

    out_dir = Path(out_dir)
    policy_path = out_dir / "policy.txt"

    subject_dn = certificate.subject.rfc4514_string()
    serial_hex = hex(certificate.serial_number)

    not_before = getattr(certificate, "not_valid_before_utc", None) or certificate.not_valid_before
    not_after = getattr(certificate, "not_valid_after_utc", None) or certificate.not_valid_after
    created = datetime.now(timezone.utc)

    if key_type == "rsa":
        algo = f"RSA-{key_size}"
    else:
        algo = "ECC-P384"

    try:
        with policy_path.open("w", encoding="utf-8") as f:
            f.write("MicroPKI Root CA Policy\n")
            f.write("========================\n\n")
            f.write(f"CA Name (Subject DN): {subject_dn}\n")
            f.write(f"Certificate Serial Number (hex): {serial_hex}\n")
            f.write(f"Validity NotBefore (UTC): {_dt_iso_utc(not_before)}\n")
            f.write(f"Validity NotAfter  (UTC): {_dt_iso_utc(not_after)}\n")
            f.write(f"Key Algorithm and Size: {algo}\n")
            f.write(f"Purpose: {purpose}\n")
            f.write(f"Policy Version: {policy_version}\n")
            f.write(f"Creation Date (UTC): {_dt_iso_utc(created)}\n")

        if logger:
            logger.info(f"Generated policy.txt: {policy_path}")

        return policy_path

    except Exception as e:
        if logger:
            logger.error(f"Failed to create policy.txt: {e}")
        raise

def append_intermediate_policy(
    policy_path,
    intermediate_cert,
    issuer: str,
    key_type: str,
    key_size: int,
    pathlen: int,
):
    serial_hex = hex(intermediate_cert.serial_number)

    not_before = getattr(intermediate_cert, "not_valid_before_utc", None) or intermediate_cert.not_valid_before
    not_after = getattr(intermediate_cert, "not_valid_after_utc", None) or intermediate_cert.not_valid_after

    not_before = _dt_iso_utc(not_before)
    not_after = _dt_iso_utc(not_after)

    subject = intermediate_cert.subject.rfc4514_string()

    section = f"""

Intermediate CA Policy
======================

Subject DN: {subject}
Serial Number (hex): {serial_hex}
Validity NotBefore (UTC): {not_before}
Validity NotAfter  (UTC): {not_after}
Key Algorithm and Size: {key_type.upper()}-{key_size}
Path Length Constraint: {pathlen}
Issuer (Root CA): {issuer}

"""

    with open(policy_path, "a", encoding="utf-8") as f:
        f.write(section)