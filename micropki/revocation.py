from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from .crl import REASON_CODES, build_crl, save_crl_pem, CRLMetadataRepository
from .crypto_utils import load_cert_pem, load_private_key_encrypted
from .repository import CertificateRepository


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def revoke_certificate(
    repo: CertificateRepository,
    serial_hex: str,
    reason: str = "unspecified",
    logger=None,
) -> bool:

    if not serial_hex.startswith("0x"):
        serial_hex = f"0x{serial_hex}"

    reason_lower = reason.lower()
    if reason_lower not in REASON_CODES:
        raise ValueError(f"Unsupported revocation reason: {reason}")

    cert_data = repo.get_certificate_by_serial(serial_hex)
    if not cert_data:
        raise ValueError(f"Certificate with serial {serial_hex} not found")

    if cert_data["status"] == "revoked":
        if logger:
            logger.warning(f"Certificate {serial_hex} is already revoked")
        return False

    success = repo.update_certificate_status(
        serial_hex,
        "revoked",
        revocation_reason=reason,
    )

    if success and logger:
        logger.info(f"Certificate {serial_hex} revoked with reason: {reason}")

    return success


def get_revoked_certificates_for_ca(
    repo: CertificateRepository,
    issuer_dn: str,
) -> list:
    all_revoked = repo.get_revoked_certificates()
    return [c for c in all_revoked if c["issuer"] == issuer_dn]


def generate_crl_for_ca(
    ca_cert_path: Path,
    ca_key_path: Path,
    ca_passphrase: bytes,
    repo: CertificateRepository,
    out_dir: Path,
    ca_name: str,
    next_update_days: int = 7,
    out_file: Optional[Path] = None,
    logger=None,
) -> Path:

    ca_cert = load_cert_pem(ca_cert_path)
    ca_key = load_private_key_encrypted(ca_key_path, ca_passphrase)

    issuer_dn = ca_cert.subject.rfc4514_string()

    revoked_certs_data = get_revoked_certificates_for_ca(repo, issuer_dn)

    revoked_entries = []
    for cert_data in revoked_certs_data:
        serial_hex = cert_data["serial_hex"]
        if serial_hex.startswith("0x"):
            serial_int = int(serial_hex, 16)
        else:
            serial_int = int(serial_hex, 16)

        rev_date_str = cert_data.get("revocation_date")
        if rev_date_str:
            rev_date = datetime.fromisoformat(rev_date_str.replace("Z", "+00:00"))
        else:
            rev_date = _now_utc()

        reason = cert_data.get("revocation_reason")
        revoked_entries.append((serial_int, rev_date, reason))

    db = repo.db
    metadata_repo = CRLMetadataRepository(db)
    metadata_repo.init_table()

    ca_subject = ca_cert.subject.rfc4514_string()
    new_crl_number = metadata_repo.increment_and_get_crl_number(ca_subject)

    this_update = _now_utc()
    crl = build_crl(
        ca_cert=ca_cert,
        ca_private_key=ca_key,
        revoked_certs=revoked_entries,
        crl_number=new_crl_number,
        this_update=this_update,
        next_update_days=next_update_days,
    )

    if out_file is None:
        crl_dir = out_dir / "crl"
        crl_dir.mkdir(parents=True, exist_ok=True)
        out_file = crl_dir / f"{ca_name}.crl.pem"

    save_crl_pem(crl, out_file)

    next_update = this_update + timedelta(days=next_update_days)
    metadata_repo.update_crl_metadata(
        ca_subject=ca_subject,
        crl_number=new_crl_number,
        last_generated=this_update,
        next_update=next_update,
        crl_path=str(out_file),
    )

    if logger:
        logger.info(
            f"CRL generated for {ca_name}: "
            f"number={new_crl_number}, "
            f"revoked_count={len(revoked_entries)}, "
            f"next_update={next_update.isoformat()}"
        )

    return out_file