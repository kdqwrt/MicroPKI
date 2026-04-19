import pytest
import time
from micropki.serials import generate_certificate_serial_number, SerialNumberGenerator


class MockDatabase:
    """Mock database for testing SerialNumberGenerator."""

    def __init__(self):
        self.serials = set()
        self.called = False

    def execute(self, query, params):
        class Cursor:
            def __init__(self, parent):
                self.parent = parent

            def fetchone(self):
                serial = self.parent.params[0] if hasattr(self.parent, 'params') else None
                if serial and serial in self.parent.serials:
                    return (1,)
                return None

        class Wrapper:
            def __init__(self, parent):
                self.parent = parent
                self.params = params

            def fetchone(self):
                if self.params[0] in self.parent.serials:
                    return (1,)
                return None

        self.called = True
        return Wrapper(self)


class TestSerialNumberGenerator:
    """Test suite for serial number generation."""

    def test_generate_returns_positive_integer(self):
        """Test that generated serial is positive integer."""
        serial = generate_certificate_serial_number()
        assert isinstance(serial, int)
        assert serial > 0

    def test_generate_unique_serial(self):
        """Test that serial numbers are unique."""
        serials = set()
        for _ in range(100):
            serial = generate_certificate_serial_number()
            assert serial not in serials
            serials.add(serial)

    def test_serial_number_generator_class_without_db(self):
        """Test SerialNumberGenerator without database."""
        gen = SerialNumberGenerator()

        serials = set()
        for _ in range(100):
            serial = gen.generate()
            assert serial not in serials
            serials.add(serial)

    def test_serial_number_generator_timestamp_component(self):
        """Test that serial includes timestamp component."""
        gen = SerialNumberGenerator()

        before = int(time.time())
        serial = gen.generate()
        after = int(time.time())

        timestamp_part = serial >> 32
        assert before <= timestamp_part <= after + 1  # Allow small clock drift

    def test_serial_number_generator_random_component(self):
        """Test that serial includes random component."""
        gen = SerialNumberGenerator()

        serials = []
        for _ in range(100):
            serials.append(gen.generate())

        # Check that lower 32 bits vary
        lower_bits = [s & 0xFFFFFFFF for s in serials]
        assert len(set(lower_bits)) > 50  # Should have good variety

    def test_serial_generator_high_bit_cleared(self):
        """Test that serial has high bit cleared (positive integer)."""
        for _ in range(100):
            serial = generate_certificate_serial_number()
            # Most significant bit of 20-byte number should be 0
            assert (serial >> 159) == 0

    def test_serial_uniqueness_with_database(self, tmp_path):
        """Test that 100 serial numbers are unique when stored to database."""
        from micropki.database import CertificateDatabase

        db_path = tmp_path / "test.db"
        db = CertificateDatabase(db_path)
        db.init_schema()

        gen = SerialNumberGenerator()
        db.connect()

        serials_generated = []

        # Generate and store 100 certificates with unique serials
        for i in range(100):
            serial = gen.generate()
            serials_generated.append(serial)
            serial_hex = f"0x{serial:x}"

            db.execute("""
                INSERT INTO certificates 
                (serial_hex, subject, issuer, not_before, not_after, cert_pem, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                serial_hex,
                f"CN=test{i}.example.com",
                "CN=Test CA",
                "2024-01-01T00:00:00Z",
                "2025-01-01T00:00:00Z",
                f"-----BEGIN CERTIFICATE-----\nMIID...test{i}\n-----END CERTIFICATE-----",
                "valid",
                "2024-01-01T00:00:00Z"
            ))
            db.commit()

        # Verify all 100 records were inserted
        cursor = db.execute("SELECT COUNT(*) FROM certificates")
        count = cursor.fetchone()[0]
        assert count == 100, f"Expected 100 certificates, found {count}"

        # Verify all serials in DB are unique
        cursor = db.execute("SELECT serial_hex FROM certificates")
        db_serials = [row[0] for row in cursor.fetchall()]
        assert len(db_serials) == len(set(db_serials)), "Duplicate serials found in database"

        # Verify our generated serials match what's in DB
        for serial in serials_generated:
            serial_hex = f"0x{serial:x}"
            cursor = db.execute("SELECT * FROM certificates WHERE serial_hex = ?", (serial_hex,))
            assert cursor.fetchone() is not None, f"Serial {serial_hex} not found in database"

        db.close()