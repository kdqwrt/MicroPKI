from cryptography import x509
from cryptography.x509.oid import NameOID


OID_MAP = {
    "CN": NameOID.COMMON_NAME,
    "O": NameOID.ORGANIZATION_NAME,
    "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
    "C": NameOID.COUNTRY_NAME,
    "L": NameOID.LOCALITY_NAME,
    "ST": NameOID.STATE_OR_PROVINCE_NAME,
}


def parse_dn(dn_string: str) -> x509.Name:
    """
    Parse DN string into x509.Name.

    Covers:
    - PKI-2 (Subject handling)
    - CLI-4 (validation)
    """

    if not dn_string or not dn_string.strip():
        raise ValueError("Distinguished Name (--subject) must not be empty.")

    dn_string = dn_string.strip()

    # Determine format
    if dn_string.startswith("/"):
        # Slash format
        parts = dn_string.split("/")[1:]  # first is empty
    else:
        # Comma format
        parts = dn_string.split(",")

    attributes = []

    for part in parts:
        part = part.strip()

        if not part:
            raise ValueError("Invalid DN format: empty component.")

        if "=" not in part:
            raise ValueError(f"Invalid DN component: '{part}'. Expected KEY=VALUE.")

        key, value = part.split("=", 1)

        key = key.strip().upper()
        value = value.strip()

        if not value:
            raise ValueError(f"DN attribute '{key}' has empty value.")

        if key not in OID_MAP:
            raise ValueError(f"Unsupported DN attribute: '{key}'.")

        if key == "C" and len(value) != 2:
            raise ValueError("Country code (C) must be exactly 2 characters.")

        attributes.append(
            x509.NameAttribute(OID_MAP[key], value)
        )

    if not attributes:
        raise ValueError("DN must contain at least one attribute.")

    return x509.Name(attributes)