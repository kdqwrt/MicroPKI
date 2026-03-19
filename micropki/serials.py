from __future__ import annotations

import secrets


def generate_certificate_serial_number() -> int:
    serial = int.from_bytes(secrets.token_bytes(20), "big") >> 1
    if serial == 0:
        serial = 1
    return serial