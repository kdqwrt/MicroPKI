from __future__ import annotations

import secrets
import time



def generate_certificate_serial_number() -> int:
    serial = int.from_bytes(secrets.token_bytes(20), "big") >> 1
    if serial == 0:
        serial = 1
    return serial



class SerialNumberGenerator:


    def __init__(self, db=None):

        self.db = db
        self._counter = 0

    def generate(self) -> int:

        max_attempts = 10

        for attempt in range(max_attempts):
            timestamp = int(time.time()) & 0xFFFFFFFF

            random_part = int.from_bytes(secrets.token_bytes(4), 'big') & 0xFFFFFFFF

            serial = (timestamp << 32) | random_part


            if serial <= 0:
                continue


            if self.db and self._is_duplicate(serial):

                continue

            return serial

        self._counter += 1
        timestamp = int(time.time()) & 0xFFFFFFFF
        return (timestamp << 32) | (self._counter & 0xFFFFFFFF)

    def _is_duplicate(self, serial: int) -> bool:
        if not self.db:
            return False

        try:
            cursor = self.db.execute(
                "SELECT 1 FROM certificates WHERE serial_hex = ? LIMIT 1",
                (hex(serial),)
            )
            result = cursor.fetchone()
            return result is not None
        except Exception:
            return False