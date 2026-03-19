from __future__ import annotations
from .chain import ChainValidationError, verify_chain
import argparse
import sys
from pathlib import Path

from .ca import init_ca, issue_intermediate_ca, issue_end_entity_certificate
from .logger import setup_logger


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="micropki",
        description="MicroPKI - Minimal PKI",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)


    ca_parser = subparsers.add_parser("ca", help="CA operations")
    ca_sub = ca_parser.add_subparsers(dest="ca_command", required=True)


    init_p = ca_sub.add_parser("init", help="Initialize Root CA")
    init_p.add_argument("--subject", required=True)
    init_p.add_argument("--key-type", choices=["rsa", "ecc"], default="rsa")
    init_p.add_argument("--key-size", type=int, required=True)
    init_p.add_argument("--passphrase-file", required=True)
    init_p.add_argument("--out-dir", default="./pki")
    init_p.add_argument("--validity-days", type=int, default=3650)
    init_p.add_argument("--log-file")
    init_p.add_argument("--force", action="store_true")


    inter_p = ca_sub.add_parser("issue-intermediate", help="Issue Intermediate CA")
    inter_p.add_argument("--root-cert", required=True)
    inter_p.add_argument("--root-key", required=True)
    inter_p.add_argument("--root-pass-file", required=True)
    inter_p.add_argument("--subject", required=True)
    inter_p.add_argument("--key-type", choices=["rsa", "ecc"], default="rsa")
    inter_p.add_argument("--key-size", type=int, required=True)
    inter_p.add_argument("--passphrase-file", required=True)
    inter_p.add_argument("--out-dir", default="./pki")
    inter_p.add_argument("--validity-days", type=int, default=1825)
    inter_p.add_argument("--pathlen", type=int, default=0)
    inter_p.add_argument("--log-file")
    inter_p.add_argument("--force", action="store_true")


    cert_p = ca_sub.add_parser("issue-cert", help="Issue end-entity certificate")
    cert_p.add_argument("--ca-cert", required=True)
    cert_p.add_argument("--ca-key", required=True)
    cert_p.add_argument("--ca-pass-file", required=True)
    cert_p.add_argument(
        "--template",
        required=True,
        choices=["server", "client", "code_signing"],
    )
    cert_p.add_argument("--subject", required=True)
    cert_p.add_argument("--san", action="append", default=[])
    cert_p.add_argument("--out-dir", default="./pki/certs")
    cert_p.add_argument("--validity-days", type=int, default=365)
    cert_p.add_argument("--log-file")
    cert_p.add_argument("--key-type", choices=["rsa", "ecc"], default="rsa")
    cert_p.add_argument("--key-size", type=int, default=2048)
    cert_p.add_argument("--csr")


    verify_p = ca_sub.add_parser("verify-chain", help="Validate leaf -> intermediate -> root chain")
    verify_p.add_argument("--root-cert", required=True)
    verify_p.add_argument("--intermediate-cert", required=True)
    verify_p.add_argument("--leaf-cert", required=True)
    verify_p.add_argument("--template", choices=["server", "client", "code_signing"])
    verify_p.add_argument("--log-file")

    return parser


def _die(msg: str, logger=None, code: int = 1) -> None:
    if logger:
        logger.error(msg)
    sys.stderr.write(f"ERROR: {msg}\n")
    raise SystemExit(code)


def _read_passphrase_file(path_str: str, logger=None) -> bytes:
    path = Path(path_str)

    if not path.exists():
        _die(f"Passphrase file does not exist: {path}", logger)
    if not path.is_file():
        _die(f"Passphrase path is not a file: {path}", logger)

    try:
        passphrase = path.read_bytes().rstrip(b"\r\n")
    except Exception:
        _die(f"Unable to read passphrase file: {path}", logger)

    if not passphrase:
        _die(f"Passphrase file is empty: {path}", logger)

    return passphrase


def _validate_writable_dir(path_str: str, logger=None) -> Path:
    out_dir = Path(path_str)

    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        _die(f"Unable to create output directory: {out_dir}", logger)

    if not out_dir.is_dir():
        _die(f"Output path is not a directory: {out_dir}", logger)

    try:
        probe = out_dir / ".micropki_write_test"
        probe.write_bytes(b"1")
        probe.unlink()
    except Exception:
        _die(f"No write permission for output directory: {out_dir}", logger)

    return out_dir


def validate_init_args(args: argparse.Namespace, logger=None) -> bytes:
    if not args.subject or not args.subject.strip():
        _die("--subject must be provided and non-empty.", logger)

    if args.key_type == "rsa" and args.key_size != 4096:
        _die("RSA key size must be 4096 bits.", logger)

    if args.key_type == "ecc" and args.key_size != 384:
        _die("ECC key size must be 384 bits (P-384).", logger)

    if args.validity_days <= 0:
        _die("--validity-days must be a positive integer.", logger)

    _validate_writable_dir(args.out_dir, logger)
    return _read_passphrase_file(args.passphrase_file, logger)


def validate_issue_intermediate_args(args: argparse.Namespace, logger=None) -> tuple[bytes, bytes]:
    if not args.subject or not args.subject.strip():
        _die("--subject must be provided and non-empty.", logger)

    if not Path(args.root_cert).exists():
        _die(f"Root certificate not found: {args.root_cert}", logger)

    if not Path(args.root_key).exists():
        _die(f"Root private key not found: {args.root_key}", logger)

    if args.key_type == "rsa" and args.key_size != 4096:
        _die("Intermediate CA RSA key size must be 4096 bits.", logger)

    if args.key_type == "ecc" and args.key_size != 384:
        _die("Intermediate CA ECC key size must be 384 bits (P-384).", logger)

    if args.validity_days <= 0:
        _die("--validity-days must be a positive integer.", logger)

    if args.pathlen < 0:
        _die("--pathlen must be >= 0.", logger)

    _validate_writable_dir(args.out_dir, logger)

    root_passphrase = _read_passphrase_file(args.root_pass_file, logger)
    intermediate_passphrase = _read_passphrase_file(args.passphrase_file, logger)

    return root_passphrase, intermediate_passphrase


def validate_issue_cert_args(args: argparse.Namespace, logger=None) -> bytes:
    if not args.subject or not args.subject.strip():
        _die("--subject must be provided and non-empty.", logger)

    if not Path(args.ca_cert).exists():
        _die(f"Intermediate CA certificate not found: {args.ca_cert}", logger)

    if not Path(args.ca_key).exists():
        _die(f"Intermediate CA private key not found: {args.ca_key}", logger)

    if args.csr and not Path(args.csr).exists():
        _die(f"CSR not found: {args.csr}", logger)

    if args.validity_days <= 0:
        _die("--validity-days must be a positive integer.", logger)

    _validate_writable_dir(args.out_dir, logger)

    # Template/SAN validation policy
    san_entries = args.san or []

    if args.template == "server":
        if not san_entries:
            _die("Server certificate requires at least one --san entry.", logger)

    if args.template == "code_signing":
        for san in san_entries:
            if san.lower().startswith("ip:") or san.lower().startswith("email:"):
                _die(
                    "Code signing certificate supports only DNS or URI SAN types.",
                    logger,
                )

    if args.template == "client":
        for san in san_entries:
            if san.lower().startswith("ip:"):
                _die(
                    "Client certificate does not support IP SAN types.",
                    logger,
                )

    return _read_passphrase_file(args.ca_pass_file, logger)


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    logger = setup_logger(getattr(args, "log_file", None))

    if args.command == "ca" and args.ca_command == "init":
        passphrase = validate_init_args(args, logger=logger)

        init_ca(
            subject=args.subject,
            key_type=args.key_type,
            key_size=args.key_size,
            passphrase=passphrase,
            out_dir=Path(args.out_dir),
            force=args.force,
            validity_days=args.validity_days,
            logger=logger,
        )
        return

    if args.command == "ca" and args.ca_command == "issue-intermediate":
        root_passphrase, intermediate_passphrase = validate_issue_intermediate_args(
            args,
            logger=logger,
        )

        issue_intermediate_ca(
            root_cert_path=Path(args.root_cert),
            root_key_path=Path(args.root_key),
            root_passphrase=root_passphrase,
            subject=args.subject,
            key_type=args.key_type,
            key_size=args.key_size,
            intermediate_passphrase=intermediate_passphrase,
            out_dir=Path(args.out_dir),
            validity_days=args.validity_days,
            pathlen=args.pathlen,
            force=args.force,
            logger=logger,
        )
        return

    if args.command == "ca" and args.ca_command == "verify-chain":
        try:
            result = verify_chain(
                root_cert_path=Path(args.root_cert),
                intermediate_cert_path=Path(args.intermediate_cert),
                leaf_cert_path=Path(args.leaf_cert),
                template=args.template,
            )
        except ChainValidationError as e:
            _die(str(e), logger)

        logger.info("Certificate chain validation successful.")
        sys.stdout.write(
            "Chain OK\n"
            f"Root: {result['root_subject']}\n"
            f"Intermediate: {result['intermediate_subject']}\n"
            f"Leaf: {result['leaf_subject']}\n"
        )
        return


    if args.command == "ca" and args.ca_command == "issue-cert":
        ca_passphrase = validate_issue_cert_args(args, logger=logger)

        issue_end_entity_certificate(
            ca_cert_path=Path(args.ca_cert),
            ca_key_path=Path(args.ca_key),
            ca_passphrase=ca_passphrase,
            template=args.template,
            subject=args.subject,
            san_entries=args.san,
            out_dir=Path(args.out_dir),
            validity_days=args.validity_days,
            key_type=args.key_type,
            key_size=args.key_size,
            csr_path=Path(args.csr) if args.csr else None,
            logger=logger,
        )
        return

    parser.print_help()
    raise SystemExit(1)