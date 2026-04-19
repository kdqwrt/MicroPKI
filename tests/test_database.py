import pytest
import sqlite3
import tempfile
from pathlib import Path


from micropki.database import CertificateDatabase


class TestCertificateDatabase:
    """Test suite for CertificateDatabase class."""

    @pytest.fixture
    def temp_db_path(self):
        """Create temporary database path."""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
            tmp_path = Path(tmp.name)

        yield tmp_path

        # Cleanup - несколько попыток с задержкой
        import time
        for _ in range(3):
            try:
                if tmp_path.exists():
                    tmp_path.unlink()
                break
            except PermissionError:
                time.sleep(0.1)
                continue

    @pytest.fixture
    def db(self, temp_db_path):
        """Create database instance."""
        db = CertificateDatabase(temp_db_path)
        yield db
        # Убеждаемся, что соединение закрыто
        if hasattr(db, 'conn') and db.conn:
            db.close()

    def test_init_db_creates_tables(self, db):
        """Test that database initialization creates required tables."""
        db.init_schema(force=True)

        with db.connect() as conn:
            # Check certificates table exists
            result = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='certificates'"
            ).fetchone()
            assert result is not None

            # Check metadata table exists
            result = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='metadata'"
            ).fetchone()
            assert result is not None

            # Check indexes
            result = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index'"
            ).fetchall()
            index_names = [r[0] for r in result]
            assert 'idx_serial' in index_names
            assert 'idx_status' in index_names

    def test_init_db_is_idempotent(self, db):
        """Test that init_schema can be called multiple times."""
        db.init_schema(force=True)
        db.init_schema(force=False)  # Should not raise error

    def test_init_db_force_drops_tables(self, db):
        """Test that force=True recreates tables."""
        db.init_schema(force=True)

        # Insert test data
        with db.connect() as conn:
            conn.execute("""
                INSERT INTO certificates (
                    serial_hex, subject, issuer, not_before, not_after,
                    cert_pem, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, ('0x1234', 'CN=Test', 'CN=Root', '2024-01-01', '2025-01-01',
                  'test_pem', 'valid', '2024-01-01'))
            conn.commit()

        # Reinitialize with force
        db.init_schema(force=True)

        # Verify data is gone
        with db.connect() as conn:
            result = conn.execute("SELECT COUNT(*) FROM certificates").fetchone()
            assert result[0] == 0

    def test_schema_version(self, db):
        """Test schema version is set correctly."""
        db.init_schema(force=True)

        version = db.get_schema_version()
        assert version == CertificateDatabase.SCHEMA_VERSION

    def test_migrate_schema(self, db):
        """Test schema migration."""
        # Create old schema without certificates table
        with db.connect() as conn:
            conn.execute("CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT)")
            conn.execute(
                "INSERT INTO metadata (key, value) VALUES ('schema_version', '0')"
            )
            conn.commit()

        # Run migration
        db.migrate_schema()

        # Check version updated
        version = db.get_schema_version()
        assert version == CertificateDatabase.SCHEMA_VERSION

        # Check tables exist
        with db.connect() as conn:
            result = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='certificates'"
            ).fetchone()
            assert result is not None

    def test_execute_method(self, db):
        """Test execute convenience method."""
        db.init_schema(force=True)

        db.execute(
            "INSERT INTO metadata (key, value) VALUES (?, ?)",
            ('test_key', 'test_value')
        )
        db.commit()

        result = db.execute("SELECT value FROM metadata WHERE key = ?", ('test_key',))
        row = result.fetchone()
        assert row is not None
        assert row['value'] == 'test_value'

    def test_rollback_on_error(self, db):
        """Test that rollback works on error."""
        db.init_schema(force=True)

        # Start transaction
        db.connect()
        try:
            db.execute(
                "INSERT INTO metadata (key, value) VALUES (?, ?)",
                ('test_key', 'test_value')
            )

            # This will fail due to UNIQUE constraint on PRIMARY KEY
            with pytest.raises(sqlite3.IntegrityError):
                db.execute(
                    "INSERT INTO metadata (key, value) VALUES (?, ?)",
                    ('test_key', 'duplicate')
                )
                db.commit()
        finally:
            db.rollback()
            db.close()

        # Verify no data was inserted
        db.connect()
        result = db.execute("SELECT COUNT(*) FROM metadata WHERE key = 'test_key'")
        assert result.fetchone()[0] == 0
        db.close()

    def test_context_manager(self, temp_db_path):
        """Test that database works as context manager."""
        db = CertificateDatabase(temp_db_path)

        with db as conn:
            conn.execute("CREATE TABLE test (id INTEGER)")
            conn.execute("INSERT INTO test VALUES (1)")
            conn.commit()

        # Connection should be closed
        assert db.conn is None

        # Data should persist
        db.connect()
        result = db.execute("SELECT * FROM test").fetchone()
        assert result[0] == 1
        db.close()

    def test_duplicate_serial_prevented(self, db):
        """Test that UNIQUE constraint prevents duplicate serial numbers."""
        db.init_schema(force=True)

        db.connect()

        # Insert first certificate
        db.execute("""
            INSERT INTO certificates 
            (serial_hex, subject, issuer, not_before, not_after, cert_pem, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            "0xABC123",
            "CN=test1.example.com",
            "CN=Test CA",
            "2024-01-01T00:00:00Z",
            "2025-01-01T00:00:00Z",
            "-----BEGIN CERTIFICATE-----\nMIID...test1\n-----END CERTIFICATE-----",
            "valid",
            "2024-01-01T00:00:00Z"
        ))
        db.commit()

        # Try to insert duplicate serial - should fail with IntegrityError
        with pytest.raises(sqlite3.IntegrityError) as exc_info:
            db.execute("""
                INSERT INTO certificates 
                (serial_hex, subject, issuer, not_before, not_after, cert_pem, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                "0xABC123",  # Same serial!
                "CN=test2.example.com",
                "CN=Test CA",
                "2024-01-01T00:00:00Z",
                "2025-01-01T00:00:00Z",
                "-----BEGIN CERTIFICATE-----\nMIID...test2\n-----END CERTIFICATE-----",
                "valid",
                "2024-01-01T00:00:00Z"
            ))
            db.commit()

        # Verify error message indicates UNIQUE constraint
        assert "UNIQUE constraint failed" in str(exc_info.value)

        # Verify only one record exists
        cursor = db.execute("SELECT COUNT(*) FROM certificates WHERE serial_hex = ?", ("0xABC123",))
        count = cursor.fetchone()[0]
        assert count == 1

        db.close()

    def test_duplicate_serial_case_sensitive(self, db):
        """Test that serial uniqueness is case-sensitive in SQLite.

        SQLite treats '0xabc123' and '0xABC123' as DIFFERENT strings,
        so both can be inserted without UNIQUE constraint violation.
        This test verifies the actual SQLite behavior.
        """
        db.init_schema(force=True)

        db.connect()

        # Insert with lowercase
        db.execute("""
            INSERT INTO certificates 
            (serial_hex, subject, issuer, not_before, not_after, cert_pem, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            "0xabc123",
            "CN=test1.example.com",
            "CN=Test CA",
            "2024-01-01T00:00:00Z",
            "2025-01-01T00:00:00Z",
            "pem1",
            "valid",
            "2024-01-01T00:00:00Z"
        ))
        db.commit()

        # Insert same serial with UPPERCASE - should SUCCEED (different string in SQLite)
        db.execute("""
            INSERT INTO certificates 
            (serial_hex, subject, issuer, not_before, not_after, cert_pem, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            "0xABC123",  # Different case - SQLite treats as different string
            "CN=test2.example.com",
            "CN=Test CA",
            "2024-01-01T00:00:00Z",
            "2025-01-01T00:00:00Z",
            "pem2",
            "valid",
            "2024-01-01T00:00:00Z"
        ))
        db.commit()

        # Verify both records exist
        cursor = db.execute("SELECT COUNT(*) FROM certificates")
        count = cursor.fetchone()[0]
        assert count == 2, f"Expected 2 records, found {count}"

        # Verify they have different serial_hex values
        cursor = db.execute("SELECT serial_hex FROM certificates ORDER BY serial_hex")
        serials = [row[0] for row in cursor.fetchall()]
        assert "0xABC123" in serials
        assert "0xabc123" in serials

        db.close()

    def test_serial_with_and_without_0x_prefix(self, db):
        """Test that serials with and without 0x are treated as different strings.

        SQLite treats '0x123456' and '123456' as DIFFERENT strings,
        so both can be inserted. This test verifies actual behavior and
        highlights the importance of consistent serial formatting.
        """
        db.init_schema(force=True)

        db.connect()

        # Insert with 0x prefix
        db.execute("""
            INSERT INTO certificates 
            (serial_hex, subject, issuer, not_before, not_after, cert_pem, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            "0x123456",
            "CN=test1.example.com",
            "CN=Test CA",
            "2024-01-01T00:00:00Z",
            "2025-01-01T00:00:00Z",
            "pem1",
            "valid",
            "2024-01-01T00:00:00Z"
        ))
        db.commit()

        # Insert without 0x prefix - should SUCCEED (different string)
        db.execute("""
            INSERT INTO certificates 
            (serial_hex, subject, issuer, not_before, not_after, cert_pem, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            "123456",  # No 0x prefix - SQLite treats as different string
            "CN=test2.example.com",
            "CN=Test CA",
            "2024-01-01T00:00:00Z",
            "2025-01-01T00:00:00Z",
            "pem2",
            "valid",
            "2024-01-01T00:00:00Z"
        ))
        db.commit()

        # Verify both records exist
        cursor = db.execute("SELECT COUNT(*) FROM certificates")
        count = cursor.fetchone()[0]
        assert count == 2, f"Expected 2 records, found {count}"

        # Verify they have different serial_hex values
        cursor = db.execute("SELECT serial_hex FROM certificates")
        serials = [row[0] for row in cursor.fetchall()]
        assert "0x123456" in serials
        assert "123456" in serials

        db.close()

    def test_exact_duplicate_serial_fails(self, db):
        """Test that EXACT duplicate serial (same case, same format) fails.

        This is the core TEST-18 requirement - verifying that identical
        serial numbers cannot be inserted twice.
        """
        db.init_schema(force=True)

        db.connect()

        # Insert first certificate
        db.execute("""
            INSERT INTO certificates 
            (serial_hex, subject, issuer, not_before, not_after, cert_pem, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            "0xABC123DEF456",
            "CN=test1.example.com",
            "CN=Test CA",
            "2024-01-01T00:00:00Z",
            "2025-01-01T00:00:00Z",
            "pem1",
            "valid",
            "2024-01-01T00:00:00Z"
        ))
        db.commit()

        # Try to insert EXACT same serial - MUST fail
        with pytest.raises(sqlite3.IntegrityError) as exc_info:
            db.execute("""
                INSERT INTO certificates 
                (serial_hex, subject, issuer, not_before, not_after, cert_pem, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                "0xABC123DEF456",  # EXACT same string
                "CN=test2.example.com",
                "CN=Test CA",
                "2024-01-01T00:00:00Z",
                "2025-01-01T00:00:00Z",
                "pem2",
                "valid",
                "2024-01-01T00:00:00Z"
            ))
            db.commit()

        assert "UNIQUE constraint failed" in str(exc_info.value)

        # Verify only one record exists
        cursor = db.execute("SELECT COUNT(*) FROM certificates WHERE serial_hex = ?", ("0xABC123DEF456",))
        count = cursor.fetchone()[0]
        assert count == 1

        db.close()