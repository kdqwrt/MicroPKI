from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .ca import init_ca
from .logger import setup_logger


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="micropki", description="MicroPKI - Minimal PKI")
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

    return parser


def _die(msg: str, logger=None, code: int = 1) -> None:
    if logger:
        logger.error(msg)
    sys.stderr.write(f"ERROR: {msg}\n")
    raise SystemExit(code)


def validate_args(args: argparse.Namespace, logger=None) -> bytes:
    if not args.subject.strip():
        _die("--subject must be provided and non-empty.", logger)

    if args.key_type == "rsa" and args.key_size != 4096:
        _die("RSA key size must be 4096 bits.", logger)

    if args.key_type == "ecc" and args.key_size != 384:
        _die("ECC key size must be 384 bits (P-384).", logger)

    if args.validity_days <= 0:
        _die("--validity-days must be a positive integer.", logger)

    pass_path = Path(args.passphrase_file)
    if not pass_path.exists():
        _die("Passphrase file does not exist.", logger)
    if not pass_path.is_file():
        _die("Passphrase path is not a file.", logger)

    try:
        passphrase = pass_path.read_bytes().rstrip(b"\r\n")
    except Exception:
        _die("Unable to read passphrase file (check permissions).", logger)

    if not passphrase:
        _die("Passphrase file is empty.", logger)

    out_dir = Path(args.out_dir)
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        _die("Unable to create output directory.", logger)

    if not out_dir.is_dir():
        _die("--out-dir is not a directory.", logger)

    # strong writable test
    try:
        probe = out_dir / ".micropki_write_test"
        probe.write_bytes(b"1")
        probe.unlink()
    except Exception:
        _die("No write permission for output directory.", logger)

    return passphrase


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    logger = setup_logger(getattr(args, "log_file", None))

    if args.command == "ca" and args.ca_command == "init":
        passphrase = validate_args(args, logger=logger)
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

    parser.print_help()
    raise SystemExit(1)