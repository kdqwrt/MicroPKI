from __future__ import annotations
from .chain import ChainValidationError, verify_chain
import argparse
import sys
from pathlib import Path

from .ca import init_ca, issue_intermediate_ca, issue_end_entity_certificate
from .logger import setup_logger

from .repository import CertificateRepository
from .server import start_server
import csv
import json
from datetime import datetime


def _format_certificates_table(certs: list) -> str:
    if not certs:
        return "No certificates found.\n"

    headers = ["Serial (hex)", "Subject", "Status", "Expiration"]
    rows = []

    for cert in certs:
        serial = cert['serial_hex'].replace('0x', '')[:16]
        subject = cert['subject'][:50]  # Обрезаем длинные строки
        status = cert['status']
        not_after = cert['not_after'][:10]  # Только дата

        rows.append([serial, subject, status, not_after])

    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, col in enumerate(row):
            col_widths[i] = max(col_widths[i], len(str(col)))

    result = []
    sep = "+" + "+".join("-" * (w + 2) for w in col_widths) + "+\n"

    header_line = "|"
    for i, h in enumerate(headers):
        header_line += f" {h:<{col_widths[i]}} |"
    result.append(sep + header_line + "\n" + sep)

    for row in rows:
        line = "|"
        for i, col in enumerate(row):
            line += f" {str(col):<{col_widths[i]}} |"
        result.append(line + "\n")

    result.append(sep)
    result.append(f"\nTotal: {len(certs)} certificates\n")

    return "".join(result)


def _format_certificates_json(certs: list) -> str:
    return json.dumps(certs, indent=2, default=str)


def _format_certificates_csv(certs: list) -> str:
    if not certs:
        return ""

    output = []
    writer = csv.DictWriter(output, fieldnames=certs[0].keys())
    writer.writeheader()
    writer.writerows(certs)
    return "".join(output)


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
    init_p.add_argument("--db-path", default="./pki/micropki.db", help="Database path for automatic insertion")

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
    inter_p.add_argument("--db-path", default="./pki/micropki.db", help="Database path for automatic insertion")

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
    cert_p.add_argument("--db-path", default="./pki/micropki.db", help="Database path for automatic insertion")

    # ca list-certs
    list_certs = ca_sub.add_parser("list-certs", help="List issued certificates")
    list_certs.add_argument("--status", choices=["valid", "revoked", "expired"], help="Filter by status")
    list_certs.add_argument("--issuer", help="Filter by issuer DN")
    list_certs.add_argument("--format", choices=["table", "json", "csv"], default="table", help="Output format")
    list_certs.add_argument("--limit", type=int, default=100, help="Maximum records")
    list_certs.add_argument("--db-path", default="./pki/micropki.db", help="Database path")
    list_certs.add_argument("--log-file", help="Log file path")

    # ca show-cert
    show_cert = ca_sub.add_parser("show-cert", help="Show certificate by serial")
    show_cert.add_argument("serial", help="Certificate serial number (hex)")
    show_cert.add_argument("--format", choices=["pem", "text"], default="pem", help="Output format")
    show_cert.add_argument("--db-path", default="./pki/micropki.db", help="Database path")
    show_cert.add_argument("--log-file", help="Log file path")

    verify_p = ca_sub.add_parser("verify-chain", help="Validate leaf -> intermediate -> root chain")
    verify_p.add_argument("--root-cert", required=True)
    verify_p.add_argument("--intermediate-cert", required=True)
    verify_p.add_argument("--leaf-cert", required=True)
    verify_p.add_argument("--template", choices=["server", "client", "code_signing"])
    verify_p.add_argument("--log-file")

    db_parser = subparsers.add_parser("db", help="Database operations")
    db_sub = db_parser.add_subparsers(dest="db_command", required=True)

    # db init
    db_init = db_sub.add_parser("init", help="Initialize certificate database")
    db_init.add_argument("--db-path", default="./pki/micropki.db", help="SQLite database path")
    db_init.add_argument("--force", action="store_true", help="Force reinitialization")
    db_init.add_argument("--log-file", help="Log file path")

    repo_parser = subparsers.add_parser("repo", help="Repository operations")
    repo_sub = repo_parser.add_subparsers(dest="repo_command", required=True)

    # repo serve
    repo_serve = repo_sub.add_parser("serve", help="Start HTTP repository server")
    repo_serve.add_argument("--host", default="127.0.0.1", help="Bind address")
    repo_serve.add_argument("--port", type=int, default=8080, help="TCP port")
    repo_serve.add_argument("--db-path", default="./pki/micropki.db", help="SQLite database path")
    repo_serve.add_argument("--cert-dir", default="./pki/certs", help="Directory with CA certificates")
    repo_serve.add_argument("--log-file", help="Log file path")

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


def validate_issue_cert_args(args: argparse.Namespace, logger=None) -> tuple[bytes, Path]:
    """
    Валидирует аргументы для issue-cert.

    Returns:
        tuple[bytes, Path]: (passphrase, db_path)
    """
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

    # Валидация SAN
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

    # Получаем passphrase
    passphrase = _read_passphrase_file(args.ca_pass_file, logger)

    # Получаем путь к БД
    db_path = Path(getattr(args, 'db_path', './pki/micropki.db'))

    # Проверяем существование БД и валидность схемы
    if db_path.exists():
        try:
            from .repository import CertificateRepository
            repo = CertificateRepository(db_path, logger)
            with repo.db:
                repo.db.connect()
                if not repo.db._table_exists('certificates'):
                    logger.warning(f"Database {db_path} exists but has no certificates table")
        except Exception as e:
            logger.warning(f"Database check failed: {e}")

    return passphrase, db_path


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    logger = setup_logger(getattr(args, "log_file", None))


    if args.command == "db" and args.db_command == "init":
        db_path = Path(args.db_path)
        repo = CertificateRepository(db_path, logger)

        try:
            repo.init_db(force=args.force)
            logger.info(f"Database initialized successfully at {db_path}")
            print(f"Database initialized: {db_path}")
        except Exception as e:
            logger.error(f"Database initialization failed: {e}")
            _die(f"Database initialization failed: {e}", logger)
        return



    if args.command == "repo" and args.repo_command == "serve":
        db_path = Path(args.db_path)
        cert_dir = Path(args.cert_dir)


        if not cert_dir.exists():
            _die(f"Certificate directory not found: {cert_dir}", logger)


        repo = CertificateRepository(db_path, logger)

        if not db_path.exists():
            logger.warning(f"Database {db_path} does not exist. Creating...")
            try:
                repo.init_db()
            except Exception as e:
                _die(f"Failed to initialize database: {e}", logger)


        try:
            from .server import start_server
            start_server(
                host=args.host,
                port=args.port,
                repo=repo,
                cert_dir=cert_dir,
                logger=logger
            )
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
        except Exception as e:
            _die(f"Failed to start server: {e}", logger)
        return



    if args.command == "ca" and args.ca_command == "init":
        passphrase = validate_init_args(args, logger=logger)
        db_path = Path(getattr(args, 'db_path', './pki/micropki.db'))

        try:
            init_ca(
                subject=args.subject,
                key_type=args.key_type,
                key_size=args.key_size,
                passphrase=passphrase,
                out_dir=Path(args.out_dir),
                force=args.force,
                validity_days=args.validity_days,
                db_path=db_path,
                logger=logger,
            )
            print(f"Root CA initialized successfully")
        except Exception as e:
            _die(f"Root CA initialization failed: {e}", logger)
        return


    if args.command == "ca" and args.ca_command == "issue-intermediate":
        root_passphrase, intermediate_passphrase = validate_issue_intermediate_args(
            args,
            logger=logger,
        )
        db_path = Path(getattr(args, 'db_path', './pki/micropki.db'))

        try:
            result = issue_intermediate_ca(
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
                db_path=db_path,
                logger=logger,
            )
            print(f"Intermediate CA issued successfully")
            print(f"   Certificate: {result['cert']}")
            print(f"   Private key: {result['key']}")
            print(f"   CSR: {result['csr']}")
        except Exception as e:
            _die(f"Intermediate CA issuance failed: {e}", logger)
        return


    if args.command == "ca" and args.ca_command == "issue-cert":
        ca_passphrase, db_path = validate_issue_cert_args(args, logger=logger)

        try:
            result = issue_end_entity_certificate(
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
                db_path=db_path,
                logger=logger,
            )
            print(f"Certificate issued successfully")
            print(f"   Certificate: {result['cert']}")
            if result['key']:
                print(f"   Private key: {result['key']}")
            if result.get('db_id'):
                print(f"   Database ID: {result['db_id']}")
        except Exception as e:
            _die(f"Certificate issuance failed: {e}", logger)
        return

    if args.command == "ca" and args.ca_command == "list-certs":
        db_path = Path(args.db_path)

        if not db_path.exists():
            _die(f"Database not found: {db_path}. Run 'micropki db init' first.", logger)

        repo = CertificateRepository(db_path, logger)

        try:
            certs = repo.list_certificates(
                status=args.status,
                issuer=args.issuer,
                limit=args.limit
            )

            if args.format == "table":
                output = _format_certificates_table(certs)
            elif args.format == "json":
                output = _format_certificates_json(certs)
            elif args.format == "csv":
                output = _format_certificates_csv(certs)
            else:
                output = _format_certificates_table(certs)

            print(output)

        except Exception as e:
            _die(f"Failed to list certificates: {e}", logger)
        return


    if args.command == "ca" and args.ca_command == "show-cert":
        db_path = Path(args.db_path)

        if not db_path.exists():
            _die(f"Database not found: {db_path}. Run 'micropki db init' first.", logger)

        repo = CertificateRepository(db_path, logger)

        try:
            cert_data = repo.get_certificate_by_serial(args.serial)

            if not cert_data:
                _die(f"Certificate with serial {args.serial} not found", logger)

            if args.format == "pem":
                print(cert_data['cert_pem'])
            else:  # text format
                print("=" * 60)
                print("CERTIFICATE DETAILS")
                print("=" * 60)
                print(f"Serial (hex):     {cert_data['serial_hex']}")
                print(f"Subject:          {cert_data['subject']}")
                print(f"Issuer:           {cert_data['issuer']}")
                print(f"Status:           {cert_data['status']}")
                print(f"Valid From:       {cert_data['not_before']}")
                print(f"Valid Until:      {cert_data['not_after']}")
                print(f"Created At:       {cert_data['created_at']}")
                if cert_data.get('revocation_reason'):
                    print(f"Revoked:          {cert_data['revocation_date']}")
                    print(f"Revocation Reason: {cert_data['revocation_reason']}")
                print("=" * 60)

        except Exception as e:
            _die(f"Failed to get certificate: {e}", logger)
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
        print("Chain validation successful")
        print(f"   Root: {result['root_subject']}")
        print(f"   Intermediate: {result['intermediate_subject']}")
        print(f"   Leaf: {result['leaf_subject']}")
        return

    # Если команда не распознана
    parser.print_help()
    raise SystemExit(1)