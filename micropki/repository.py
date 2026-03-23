from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, Dict, Any

from cryptography import x509

from .database import CertificateDatabase
from .serials import SerialNumberGenerator


class CertificateRepository:

    def __init__(self, db_path: Path, logger: Optional[logging.Logger] = None):
        self.db_path = Path(db_path)
        self.logger = logger or logging.getLogger("micropki.repo")
        self.db = CertificateDatabase(self.db_path, self.logger)
        self.serial_generator = SerialNumberGenerator(self.db)

    def init_db(self, force: bool = False) -> bool:
        return self.db.init_schema(force)

    def insert_certificate(
            self,
            certificate: x509.Certificate,
            cert_pem: str,
            status: str = "valid"
    ) -> int:
        serial_hex = hex(certificate.serial_number)

        if hasattr(certificate, 'not_valid_before_utc'):
            not_before = certificate.not_valid_before_utc
            not_after = certificate.not_valid_after_utc
        else:
            not_before = certificate.not_valid_before
            not_after = certificate.not_valid_after

        not_before_str = self._to_iso(not_before)
        not_after_str = self._to_iso(not_after)
        created_at = self._now_iso()

        subject_dn = certificate.subject.rfc4514_string()
        issuer_dn = certificate.issuer.rfc4514_string()

        try:
            self.db.connect()

            existing = self.db.execute(
                "SELECT id FROM certificates WHERE serial_hex = ?",
                (serial_hex,)
            ).fetchone()

            if existing:
                raise ValueError(
                    f"Certificate with serial {serial_hex} already exists in database"
                )

            cursor = self.db.execute("""
                INSERT INTO certificates (
                    serial_hex, subject, issuer, not_before, not_after,
                    cert_pem, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                serial_hex, subject_dn, issuer_dn, not_before_str, not_after_str,
                cert_pem, status, created_at
            ))

            self.db.commit()
            cert_id = cursor.lastrowid

            self.logger.info(
                f"Certificate inserted into database: serial={serial_hex}, "
                f"subject={subject_dn}, status={status}, id={cert_id}"
            )

            return cert_id

        except Exception as e:
            self.db.rollback()
            self.logger.error(f"Failed to insert certificate: {e}")
            raise
        finally:
            self.db.close()

    def get_certificate_by_serial(self, serial_hex: str) -> Optional[Dict[str, Any]]:
        original_serial = serial_hex
        if not serial_hex.startswith("0x"):
            serial_hex = f"0x{serial_hex}"

        try:
            self.db.connect()
            result = self.db.execute(
                "SELECT * FROM certificates WHERE serial_hex = ?",
                (serial_hex,)
            ).fetchone()

            if result:
                self.logger.info(f"Certificate retrieved from database: serial={original_serial}")
                return dict(result)

            self.logger.info(f"Certificate not found: serial={original_serial}")
            return None

        except Exception as e:
            self.logger.error(f"Failed to get certificate by serial: {e}")
            raise
        finally:
            self.db.close()

    def list_certificates(
            self,
            status: Optional[str] = None,
            issuer: Optional[str] = None,
            limit: int = 100,
            offset: int = 0
    ) -> List[Dict[str, Any]]:
        query = "SELECT * FROM certificates WHERE 1=1"
        params = []

        if status:
            query += " AND status = ?"
            params.append(status)

        if issuer:
            query += " AND issuer = ?"
            params.append(issuer)

        query += " ORDER BY not_before DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        try:
            self.db.connect()
            results = self.db.execute(query, tuple(params)).fetchall()
            return [dict(row) for row in results]

        except Exception as e:
            self.logger.error(f"Failed to list certificates: {e}")
            raise
        finally:
            self.db.close()

    def update_certificate_status(
            self,
            serial_hex: str,
            status: str,
            revocation_reason: Optional[str] = None
    ) -> bool:
        if not serial_hex.startswith("0x"):
            serial_hex = f"0x{serial_hex}"

        try:
            self.db.connect()

            if status == "revoked" and revocation_reason:
                cursor = self.db.execute("""
                    UPDATE certificates 
                    SET status = ?, revocation_reason = ?, revocation_date = ?
                    WHERE serial_hex = ?
                """, (status, revocation_reason, self._now_iso(), serial_hex))
            else:
                cursor = self.db.execute(
                    "UPDATE certificates SET status = ? WHERE serial_hex = ?",
                    (status, serial_hex)
                )

            self.db.commit()
            updated = cursor.rowcount > 0

            if updated:
                self.logger.info(
                    f"Certificate status updated: serial={serial_hex}, status={status}"
                )

            return updated

        except Exception as e:
            self.db.rollback()
            self.logger.error(f"Failed to update certificate status: {e}")
            raise
        finally:
            self.db.close()

    def get_revoked_certificates(self) -> List[Dict[str, Any]]:
        try:
            self.db.connect()
            results = self.db.execute(
                "SELECT * FROM certificates WHERE status = 'revoked'"
            ).fetchall()
            return [dict(row) for row in results]

        except Exception as e:
            self.logger.error(f"Failed to get revoked certificates: {e}")
            raise
        finally:
            self.db.close()

    def cleanup_expired(self) -> int:
        now = self._now_iso()

        try:
            self.db.connect()
            cursor = self.db.execute("""
                UPDATE certificates 
                SET status = 'expired' 
                WHERE not_after < ? AND status = 'valid'
            """, (now,))

            self.db.commit()
            count = cursor.rowcount

            if count > 0:
                self.logger.info(f"Marked {count} certificates as expired")

            return count

        except Exception as e:
            self.db.rollback()
            self.logger.error(f"Failed to cleanup expired certificates: {e}")
            raise
        finally:
            self.db.close()

    def get_serial_generator(self) -> SerialNumberGenerator:
        return self.serial_generator

    @staticmethod
    def _to_iso(dt: datetime) -> str:
        if dt.tzinfo is not None and dt.tzinfo != timezone.utc:
            dt = dt.astimezone(timezone.utc)
        elif dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        return dt.isoformat(timespec="seconds").replace("+00:00", "Z")

    @staticmethod
    def _now_iso() -> str:
        """Get current UTC time in ISO 8601 format."""
        return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")

    def delete_certificate(self, serial_hex: str) -> bool:
        if not serial_hex.startswith("0x"):
            serial_hex = f"0x{serial_hex}"

        try:
            self.db.connect()

            existing = self.db.execute(
                "SELECT id FROM certificates WHERE serial_hex = ?",
                (serial_hex,)
            ).fetchone()

            if not existing:
                return False

            cursor = self.db.execute(
                "DELETE FROM certificates WHERE serial_hex = ?",
                (serial_hex,)
            )
            self.db.commit()

            self.logger.warning(f"Certificate record deleted: serial={serial_hex}")
            return True

        except Exception as e:
            self.db.rollback()
            self.logger.error(f"Failed to delete certificate: {e}")
            raise
        finally:
            self.db.close()

    def mark_issuance_failed(self, serial_hex: str, reason: str) -> bool:
        return self.update_certificate_status(
            serial_hex,
            "revoked",
            f"issuance_failed: {reason[:200]}"
        )