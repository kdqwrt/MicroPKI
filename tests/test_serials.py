
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