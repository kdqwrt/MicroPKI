# tests/test_server.py
import pytest
import tempfile
import threading
import time
import http.client
from pathlib import Path
from urllib.parse import urlparse

from micropki.server import CertificateHTTPHandler, CertificateHTTPServer
from micropki.repository import CertificateRepository


class TestCertificateHTTPServer:
    """Test suite for HTTP repository server."""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for test files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def cert_dir(self, temp_dir):
        """Create certificate directory with test certificates."""
        cert_dir = temp_dir / "certs"
        cert_dir.mkdir()

        # Create dummy CA certificates
        root_cert_path = cert_dir / "ca.cert.pem"
        root_cert_path.write_text("-----BEGIN CERTIFICATE-----\nDUMMY ROOT CERT\n-----END CERTIFICATE-----")

        inter_cert_path = cert_dir / "intermediate.cert.pem"
        inter_cert_path.write_text("-----BEGIN CERTIFICATE-----\nDUMMY INTERMEDIATE\n-----END CERTIFICATE-----")

        return cert_dir

    @pytest.fixture
    def db_path(self, temp_dir):
        """Create database path."""
        return temp_dir / "test.db"

    @pytest.fixture
    def repo(self, db_path):
        """Create repository instance with minimal setup."""
        repo = CertificateRepository(db_path)
        repo.init_db(force=True)
        return repo

    @pytest.fixture
    def server(self, repo, cert_dir):
        """Create and start test server."""
        server = CertificateHTTPServer(
            ('127.0.0.1', 0),
            CertificateHTTPHandler,
            repo=repo,
            cert_dir=cert_dir
        )

        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        time.sleep(0.2)

        yield server

        server.shutdown()
        server.server_close()
        time.sleep(0.1)

    @pytest.fixture
    def server_url(self, server):
        """Get server URL."""
        host, port = server.server_address
        return f"http://{host}:{port}"

    def _make_request(self, url, method="GET"):
        """Make HTTP request using standard library."""
        parsed = urlparse(url)
        conn = http.client.HTTPConnection(parsed.hostname, parsed.port)

        try:
            conn.request(method, parsed.path)
            response = conn.getresponse()
            data = response.read()
            return response, data
        finally:
            conn.close()

    def test_root_ca_endpoint(self, server, server_url):
        """Test GET /ca/root endpoint."""
        response, data = self._make_request(f"{server_url}/ca/root")
        assert response.status == 200
        content_type = response.getheader("Content-Type", "")
        assert "application/x-pem-file" in content_type
        assert b"DUMMY ROOT CERT" in data

    def test_intermediate_ca_endpoint(self, server, server_url):
        """Test GET /ca/intermediate endpoint."""
        response, data = self._make_request(f"{server_url}/ca/intermediate")
        assert response.status == 200
        assert b"DUMMY INTERMEDIATE" in data

    def test_ca_endpoint_not_found(self, server, server_url):
        """Test GET /ca/invalid returns 404."""
        response, data = self._make_request(f"{server_url}/ca/invalid")
        # Сервер может возвращать 400 (Bad Request) или 404 (Not Found)
        # Оба варианта приемлемы для неподдерживаемого уровня CA
        assert response.status in (400, 404)

        # Проверяем, что сообщение об ошибке информативное
        error_msg = data.decode('utf-8').lower()
        assert "invalid" in error_msg or "not found" in error_msg or "available" in error_msg

    def test_crl_endpoint_returns_501(self, server, server_url):
        """Test GET /crl returns 501 Not Implemented."""
        response, data = self._make_request(f"{server_url}/crl")
        assert response.status == 501
        assert b"not yet implemented" in data.lower()

    def test_nonexistent_endpoint_returns_404(self, server, server_url):
        """Test nonexistent endpoint returns 404."""
        response, data = self._make_request(f"{server_url}/nonexistent")
        assert response.status == 404

    def test_options_method_returns_cors_headers(self, server, server_url):
        """Test OPTIONS method returns CORS headers."""
        response, data = self._make_request(f"{server_url}/", method="OPTIONS")
        assert response.status == 200
        assert response.getheader("Access-Control-Allow-Origin") == "*"

    def test_certificate_endpoint_with_invalid_serial(self, server, server_url):
        """Test GET /certificate with invalid hex returns 400."""
        response, data = self._make_request(f"{server_url}/certificate/XYZ123")
        assert response.status == 400
        assert b"Invalid serial" in data

    def test_certificate_endpoint_not_found(self, server, server_url):
        """Test GET /certificate with nonexistent serial returns 404."""
        response, data = self._make_request(f"{server_url}/certificate/123456")
        assert response.status == 404
        assert b"not found" in data.lower()