from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtensionOID


from .database import CertificateDatabase


REASON_CODES = {
    "unspecified": x509.ReasonFlags.unspecified,
    "keycompromise": x509.ReasonFlags.key_compromise,
    "cacompromise": x509.ReasonFlags.ca_compromise,
    "affiliationchanged": x509.ReasonFlags.affiliation_changed,
    "superseded": x509.ReasonFlags.superseded,
    "cessationofoperation": x509.ReasonFlags.cessation_of_operation,
    "certificatehold": x509.ReasonFlags.certificate_hold,
    "removefromcrl": x509.ReasonFlags.remove_from_crl,
    "privilegewithdrawn": x509.ReasonFlags.privilege_withdrawn,
    "aacompromise": x509.ReasonFlags.aa_compromise,
}


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _get_aki_from_cert(cert: x509.Certificate) -> bytes:
    try:
        ski = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_KEY_IDENTIFIER
        )
        return ski.value.digest
    except x509.ExtensionNotFound:
        raise ValueError("CA certificate does not have SubjectKeyIdentifier extension")


def _get_signing_algorithm(private_key) -> hashes.HashAlgorithm:
    if isinstance(private_key, rsa.RSAPrivateKey):
        return hashes.SHA256()
    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
        return hashes.SHA384()
    else:
        raise ValueError("Unsupported private key type")


def build_crl(
    ca_cert: x509.Certificate,
    ca_private_key,
    revoked_certs: List[Tuple[int, datetime, Optional[str]]],
    crl_number: int,
    this_update: Optional[datetime] = None,
    next_update_days: int = 7,
) -> x509.CertificateRevocationList:

    if this_update is None:
        this_update = _now_utc()

    next_update = this_update + timedelta(days=next_update_days)

    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.last_update(this_update)
    builder = builder.next_update(next_update)

    for serial, rev_date, reason_str in revoked_certs:
        revoked_builder = x509.RevokedCertificateBuilder()
        revoked_builder = revoked_builder.serial_number(serial)
        revoked_builder = revoked_builder.revocation_date(rev_date)

        if reason_str:
            reason_lower = reason_str.lower()
            if reason_lower in REASON_CODES:
                reason_flag = REASON_CODES[reason_lower]
                revoked_builder = revoked_builder.add_extension(
                    x509.CRLReason(reason_flag),
                    critical=False,
                )

        revoked_cert = revoked_builder.build()
        builder = builder.add_revoked_certificate(revoked_cert)

    aki = _get_aki_from_cert(ca_cert)
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier(
            key_identifier=aki,
            authority_cert_issuer=None,
            authority_cert_serial_number=None,
        ),
        critical=False,
    )

    builder = builder.add_extension(
        x509.CRLNumber(crl_number),
        critical=False,
    )

    algorithm = _get_signing_algorithm(ca_private_key)
    crl = builder.sign(private_key=ca_private_key, algorithm=algorithm)

    return crl


def save_crl_pem(crl: x509.CertificateRevocationList, path: Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    pem_data = crl.public_bytes(serialization.Encoding.PEM)
    path.write_bytes(pem_data)
    return path


def load_crl_pem(path: Path) -> x509.CertificateRevocationList:
    data = Path(path).read_bytes()
    return x509.load_pem_x509_crl(data)


class CRLMetadataRepository:
    def __init__(self, db: CertificateDatabase):
        self.db = db

    def init_table(self):
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS crl_metadata (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ca_subject TEXT UNIQUE NOT NULL,
                crl_number INTEGER NOT NULL,
                last_generated TEXT NOT NULL,
                next_update TEXT NOT NULL,
                crl_path TEXT NOT NULL
            )
        """)
        self.db.execute("CREATE INDEX IF NOT EXISTS idx_ca_subject ON crl_metadata(ca_subject)")
        self.db.commit()

    def get_crl_number(self, ca_subject: str) -> int:
        result = self.db.execute(
            "SELECT crl_number FROM crl_metadata WHERE ca_subject = ?",
            (ca_subject,)
        ).fetchone()
        if result:
            return result["crl_number"]
        return 0

    def update_crl_metadata(
        self,
        ca_subject: str,
        crl_number: int,
        last_generated: datetime,
        next_update: datetime,
        crl_path: str,
    ):
        last_gen_str = last_generated.isoformat(timespec="seconds").replace("+00:00", "Z")
        next_upd_str = next_update.isoformat(timespec="seconds").replace("+00:00", "Z")

        self.db.execute("""
            INSERT INTO crl_metadata (ca_subject, crl_number, last_generated, next_update, crl_path)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(ca_subject) DO UPDATE SET
                last_generated = excluded.last_generated,
                next_update = excluded.next_update,
                crl_path = excluded.crl_path
        """, (ca_subject, crl_number, last_gen_str, next_upd_str, crl_path))
        self.db.commit()

    def increment_and_get_crl_number(self, ca_subject: str) -> int:
        result = self.db.execute(
            "SELECT crl_number FROM crl_metadata WHERE ca_subject = ?",
            (ca_subject,)
        ).fetchone()
        current = result["crl_number"] if result else 0
        new_number = current + 1
        self.db.execute("""
            INSERT INTO crl_metadata (ca_subject, crl_number, last_generated, next_update, crl_path)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(ca_subject) DO UPDATE SET 
                crl_number = excluded.crl_number,
                last_generated = excluded.last_generated,
                next_update = excluded.next_update,
                crl_path = excluded.crl_path
        """, (ca_subject, new_number, "", "", ""))
        self.db.commit()
        return new_number