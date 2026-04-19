from __future__ import annotations

import logging
import re
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse, parse_qs


class CertificateHTTPHandler(BaseHTTPRequestHandler):

    server_version = "MicroPKI/0.1.0"

    def __init__(self, *args, **kwargs):
        self.repo = None
        self.cert_dir = None
        self.logger = None
        super().__init__(*args, **kwargs)

    def setup(self):
        super().setup()

        self.repo = getattr(self.server, 'repo', None)
        self.cert_dir = getattr(self.server, 'cert_dir', None)
        self.logger = getattr(self.server, 'logger', logging.getLogger("micropki.http"))

    def log_message(self, format, *args):
        if self.logger:
            message = f"[HTTP] {self.address_string()} - {format % args}"
            self.logger.info(message)

    def _send_response(
            self,
            status_code: int,
            content: bytes,
            content_type: str = "text/plain",
            extra_headers: dict = None
    ):
        self.send_response(status_code)
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(content)))
        if extra_headers:
            for key, value in extra_headers.items():
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(content)

    def _send_error_response(self, status_code: int, message: str):
        self._send_response(status_code, message.encode("utf-8"))

    def _is_valid_hex(self, s: str) -> bool:
        s = s.replace("0x", "")
        return bool(re.match(r"^[0-9a-fA-F]+$", s)) and len(s) > 0

    def _get_crl_cache_headers(self, crl_path: Path) -> dict:
        headers = {}
        if crl_path.exists():
            stat = crl_path.stat()
            headers["Last-Modified"] = self.date_time_string(stat.st_mtime)
            headers["Cache-Control"] = "max-age=3600"
            headers["ETag"] = f'"{stat.st_mtime}-{stat.st_size}"'
        return headers

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query_params = parse_qs(parsed.query)

        if path.startswith("/certificate/"):
            serial = path.split("/")[-1]

            if not self._is_valid_hex(serial):
                self._send_error_response(
                    400,
                    "Invalid serial number format. Expected hexadecimal."
                )
                return

            if not serial.startswith("0x"):
                serial_db = f"0x{serial}"
            else:
                serial_db = serial

            cert_pem = None

            try:
                cert_data = self.repo.get_certificate_by_serial(serial_db) if self.repo else None
                if cert_data and cert_data.get("cert_pem"):
                    cert_pem = cert_data["cert_pem"]
                    if self.logger:
                        self.logger.info(f"Certificate {serial} served from database")
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Database error looking up certificate {serial}: {e}")

            if not cert_pem and self.cert_dir:
                clean_serial = serial.replace("0x", "").replace("0X", "").lower()

                possible_names = [
                    f"{serial}.pem",
                    f"{serial}.cert.pem",
                    f"{clean_serial}.pem",
                    f"{clean_serial}.cert.pem",
                    f"cert_{clean_serial}.pem",
                    f"{clean_serial}.crt",
                ]

                for name in possible_names:
                    cert_path = self.cert_dir / name
                    if cert_path.exists():
                        try:
                            cert_pem = cert_path.read_text()
                            if self.logger:
                                self.logger.info(f"Certificate {serial} served from filesystem: {cert_path}")
                            break
                        except Exception as e:
                            if self.logger:
                                self.logger.error(f"Failed to read certificate file {cert_path}: {e}")
                            continue

            if cert_pem:
                self._send_response(
                    200,
                    cert_pem.encode("utf-8"),
                    "application/x-pem-file"
                )
            else:
                self._send_error_response(
                    404,
                    f"Certificate with serial {serial} not found in database or filesystem"
                )

        elif path.startswith("/ca/"):
            parts = path.split("/")
            if len(parts) != 3:
                self._send_error_response(
                    404,
                    f"Invalid CA endpoint. Use /ca/root or /ca/intermediate"
                )
                return

            level = parts[2]

            if level not in ["root", "intermediate"]:
                self._send_error_response(
                    404,
                    f"CA level '{level}' not found. Available: root, intermediate"
                )
                return

            filename = "ca.cert.pem" if level == "root" else "intermediate.cert.pem"
            cert_path = self.cert_dir / filename if self.cert_dir else None

            if cert_path and cert_path.exists():
                try:
                    content = cert_path.read_bytes()
                    self._send_response(200, content, "application/x-pem-file")
                except Exception as e:
                    self.logger.error(f"Failed to read CA certificate: {e}")
                    self._send_error_response(500, "Failed to read certificate file")
            else:
                self._send_error_response(
                    404,
                    f"CA certificate for {level} not found"
                )

        elif path == "/crl":
            ca_param = query_params.get("ca", ["intermediate"])[0]

            if ca_param not in ["root", "intermediate"]:
                self._send_error_response(
                    400,
                    "Invalid CA parameter. Use ?ca=root or ?ca=intermediate"
                )
                return

            crl_dir = self.cert_dir.parent / "crl" if self.cert_dir else None
            if crl_dir is None:
                self._send_error_response(500, "CRL directory not configured")
                return

            crl_filename = f"{ca_param}.crl.pem"
            crl_path = crl_dir / crl_filename

            if crl_path.exists():
                try:
                    content = crl_path.read_bytes()
                    headers = self._get_crl_cache_headers(crl_path)
                    self._send_response(200, content, "application/pkix-crl", headers)
                    if self.logger:
                        self.logger.info(f"CRL served: {ca_param}")
                except Exception as e:
                    self.logger.error(f"Failed to read CRL file: {e}")
                    self._send_error_response(500, "Failed to read CRL file")
            else:
                self._send_error_response(
                    404,
                    f"CRL for {ca_param} not found. Generate it first with 'micropki ca gen-crl --ca {ca_param}'"
                )

        elif path.startswith("/crl/") and path.endswith(".crl"):
            parts = path.split("/")
            filename = parts[-1]

            if filename not in ["root.crl", "intermediate.crl"]:
                self._send_error_response(404, f"CRL file {filename} not found")
                return

            crl_dir = self.cert_dir.parent / "crl" if self.cert_dir else None
            if crl_dir is None:
                self._send_error_response(500, "CRL directory not configured")
                return

            crl_path = crl_dir / filename.replace(".crl", ".crl.pem")

            if crl_path.exists():
                try:
                    content = crl_path.read_bytes()
                    headers = self._get_crl_cache_headers(crl_path)
                    self._send_response(200, content, "application/pkix-crl", headers)
                    if self.logger:
                        self.logger.info(f"CRL served: {filename}")
                except Exception as e:
                    self.logger.error(f"Failed to read CRL file: {e}")
                    self._send_error_response(500, "Failed to read CRL file")
            else:
                self._send_error_response(
                    404,
                    f"CRL file {filename} not found"
                )

        else:
            self._send_error_response(
                404,
                f"Endpoint {path} not found. Available: /certificate/<serial>, /ca/root, /ca/intermediate, /crl"
            )

    def do_HEAD(self):
        self.do_GET()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()


class CertificateHTTPServer(HTTPServer):

    def __init__(
            self,
            server_address,
            RequestHandlerClass,
            repo=None,
            cert_dir=None,
            logger=None
    ):
        super().__init__(server_address, RequestHandlerClass)
        self.repo = repo
        self.cert_dir = cert_dir
        self.logger = logger

    def serve_forever(self, poll_interval=0.5):
        if self.logger:
            self.logger.info(
                f"Starting HTTP repository server on {self.server_address[0]}:{self.server_address[1]}"
            )
            self.logger.info(f"Certificate directory: {self.cert_dir}")
            self.logger.info(f"Database path: {self.repo.db_path if self.repo else 'Not configured'}")
        super().serve_forever(poll_interval)


def start_server(
        host: str,
        port: int,
        repo,
        cert_dir: Path,
        logger: logging.Logger
) -> None:

    server_address = (host, port)

    httpd = CertificateHTTPServer(
        server_address,
        CertificateHTTPHandler,
        repo=repo,
        cert_dir=cert_dir,
        logger=logger
    )

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down HTTP repository server...")
        httpd.shutdown()