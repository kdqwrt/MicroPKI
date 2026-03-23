from __future__ import annotations

import logging
import re
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse



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
            content_type: str = "text/plain"
    ):

        self.send_response(status_code)
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _send_error_response(self, status_code: int, message: str):

        self._send_response(status_code, message.encode("utf-8"))

    def _is_valid_hex(self, s: str) -> bool:
        s = s.replace("0x", "")
        return bool(re.match(r"^[0-9a-fA-F]+$", s)) and len(s) > 0

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

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

            try:
                cert_data = self.repo.get_certificate_by_serial(serial_db) if self.repo else None

                if cert_data and cert_data.get("cert_pem"):
                    self._send_response(
                        200,
                        cert_data["cert_pem"].encode("utf-8"),
                        "application/x-pem-file"
                    )
                else:
                    self._send_error_response(
                        404,
                        f"Certificate with serial {serial} not found"
                    )

            except Exception as e:
                self.logger.error(f"Database error in /certificate: {e}")
                self._send_error_response(500, "Internal server error")

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

        # Эндпоинт: GET /crl
        elif path == "/crl":
            self._send_response(
                501,
                b"CRL generation not yet implemented",
                "application/pkix-crl"
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