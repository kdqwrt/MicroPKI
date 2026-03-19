from __future__ import annotations

from ipaddress import ip_address
from typing import Iterable, List

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID


SUPPORTED_TEMPLATES = {"server", "client", "code_signing"}
SUPPORTED_SAN_TYPES = {"dns", "ip", "email", "uri"}


class TemplateValidationError(ValueError):
    """Raised when certificate template or SAN combination is invalid."""


def parse_san_entries(san_strings: Iterable[str]) -> List[x509.GeneralName]:
    result: List[x509.GeneralName] = []

    for raw in san_strings:
        if not raw or ":" not in raw:
            raise TemplateValidationError(
                f"Invalid SAN entry '{raw}'. Expected format type:value."
            )

        san_type, san_value = raw.split(":", 1)
        san_type = san_type.strip().lower()
        san_value = san_value.strip()

        if not san_value:
            raise TemplateValidationError(
                f"Invalid SAN entry '{raw}'. SAN value must be non-empty."
            )

        if san_type not in SUPPORTED_SAN_TYPES:
            raise TemplateValidationError(
                f"Unsupported SAN type '{san_type}'. "
                f"Supported types: {', '.join(sorted(SUPPORTED_SAN_TYPES))}."
            )

        if san_type == "dns":
            result.append(x509.DNSName(san_value))
        elif san_type == "ip":
            try:
                result.append(x509.IPAddress(ip_address(san_value)))
            except ValueError as e:
                raise TemplateValidationError(
                    f"Invalid IP SAN value '{san_value}'."
                ) from e
        elif san_type == "email":
            result.append(x509.RFC822Name(san_value))
        elif san_type == "uri":
            result.append(x509.UniformResourceIdentifier(san_value))

    return result


def _classify_sans(san_objects: Iterable[x509.GeneralName]) -> set[str]:
    san_types: set[str] = set()

    for san in san_objects:
        if isinstance(san, x509.DNSName):
            san_types.add("dns")
        elif isinstance(san, x509.IPAddress):
            san_types.add("ip")
        elif isinstance(san, x509.RFC822Name):
            san_types.add("email")
        elif isinstance(san, x509.UniformResourceIdentifier):
            san_types.add("uri")

    return san_types


def validate_template_sans(template: str, san_objects: Iterable[x509.GeneralName]) -> None:

    if template not in SUPPORTED_TEMPLATES:
        raise TemplateValidationError(
            f"Unsupported template '{template}'. "
            f"Supported templates: {', '.join(sorted(SUPPORTED_TEMPLATES))}."
        )

    san_objects = list(san_objects)
    san_types = _classify_sans(san_objects)

    if template == "server":
        if not san_objects:
            raise TemplateValidationError(
                "Server certificate requires at least one SAN entry."
            )
        if not ({"dns", "ip"} & san_types):
            raise TemplateValidationError(
                "Server certificate requires at least one DNS or IP SAN."
            )
        invalid = san_types - {"dns", "ip"}
        if invalid:
            raise TemplateValidationError(
                f"Server certificate does not support SAN types: {', '.join(sorted(invalid))}."
            )

    elif template == "client":
        if not san_objects:
            raise TemplateValidationError(
                "Client certificate should contain at least one SAN entry."
            )
        invalid = san_types - {"email", "dns"}
        if invalid:
            raise TemplateValidationError(
                f"Client certificate does not support SAN types: {', '.join(sorted(invalid))}."
            )

    elif template == "code_signing":
        invalid = san_types - {"dns", "uri"}
        if invalid:
            raise TemplateValidationError(
                f"Code signing certificate does not support SAN types: {', '.join(sorted(invalid))}."
            )


def build_leaf_extensions(
    template: str,
    public_key,
    san_objects: Iterable[x509.GeneralName],
) -> list[x509.ExtensionType]:

    san_objects = list(san_objects)
    validate_template_sans(template, san_objects)

    is_rsa = isinstance(public_key, rsa.RSAPublicKey)
    is_ecc = isinstance(public_key, ec.EllipticCurvePublicKey)

    if not (is_rsa or is_ecc):
        raise TemplateValidationError("Unsupported public key type for leaf certificate.")

    extensions: list[x509.ExtensionType] = []


    extensions.append(
        x509.BasicConstraints(ca=False, path_length=None)
    )


    if template == "server":
        key_usage = x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=is_rsa,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        )
        eku = x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH])

    elif template == "client":
        key_usage = x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=is_ecc,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        )
        eku = x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH])

    elif template == "code_signing":
        key_usage = x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        )
        eku = x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING])

    else:
        raise TemplateValidationError(f"Unsupported template '{template}'.")

    extensions.append(key_usage)
    extensions.append(eku)

    if san_objects:
        extensions.append(x509.SubjectAlternativeName(san_objects))

    return extensions