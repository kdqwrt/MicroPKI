from __future__ import annotations

import subprocess
import sys

import threading
import time


import pytest
import requests
from cryptography import x509


from micropki.ca import init_ca, issue_intermediate_ca, issue_end_entity_certificate
from micropki.repository import CertificateRepository
from micropki.revocation import revoke_certificate, generate_crl_for_ca
from micropki.crl import load_crl_pem, REASON_CODES
from micropki.crypto_utils import load_private_key_encrypted
from micropki.server import CertificateHTTPServer, CertificateHTTPHandler


class TestRevocationLifecycle:

    @pytest.fixture
    def pki_env(self, tmp_path):
        out_dir = tmp_path / "pki"
        secrets_dir = tmp_path / "secrets"
        secrets_dir.mkdir()

        root_pass = secrets_dir / "ca.pass"
        root_pass.write_bytes(b"rootpass")
        inter_pass = secrets_dir / "intermediate.pass"
        inter_pass.write_bytes(b"interpass")

        db_path = out_dir / "micropki.db"

        repo = CertificateRepository(db_path)
        repo.init_db(force=True)

        return {
            "out_dir": out_dir,
            "secrets_dir": secrets_dir,
            "root_pass": root_pass,
            "inter_pass": inter_pass,
            "db_path": db_path,
        }

    def test_full_revocation_lifecycle(self, pki_env):
        out_dir = pki_env["out_dir"]
        db_path = pki_env["db_path"]

        init_ca(
            subject="CN=Root CA,O=Test,C=DE",
            key_type="rsa",
            key_size=4096,
            passphrase=b"rootpass",
            out_dir=out_dir,
            force=False,
            validity_days=3650,
            db_path=db_path,
            logger=None,
        )

        issue_intermediate_ca(
            root_cert_path=out_dir / "certs" / "ca.cert.pem",
            root_key_path=out_dir / "private" / "ca.key.pem",
            root_passphrase=b"rootpass",
            subject="CN=Intermediate CA,O=Test,C=DE",
            key_type="rsa",
            key_size=4096,
            intermediate_passphrase=b"interpass",
            out_dir=out_dir,
            validity_days=1825,
            pathlen=0,
            db_path=db_path,
            logger=None,
        )

        result = issue_end_entity_certificate(
            ca_cert_path=out_dir / "certs" / "intermediate.cert.pem",
            ca_key_path=out_dir / "private" / "intermediate.key.pem",
            ca_passphrase=b"interpass",
            template="server",
            subject="CN=test.example.com,O=Test,C=DE",
            san_entries=["dns:test.example.com"],
            out_dir=out_dir / "certs",
            validity_days=365,
            db_path=db_path,
            logger=None,
        )

        cert = x509.load_pem_x509_certificate(result["cert"].read_bytes())
        serial_hex = hex(cert.serial_number)

        repo = CertificateRepository(db_path)
        cert_data = repo.get_certificate_by_serial(serial_hex)
        assert cert_data["status"] == "valid"

        revoke_certificate(
            repo=repo,
            serial_hex=serial_hex,
            reason="keyCompromise",
            logger=None,
        )

        cert_data = repo.get_certificate_by_serial(serial_hex)
        assert cert_data["status"] == "revoked"
        assert cert_data["revocation_reason"] == "keyCompromise"
        assert cert_data["revocation_date"] is not None

        crl_path = generate_crl_for_ca(
            ca_cert_path=out_dir / "certs" / "intermediate.cert.pem",
            ca_key_path=out_dir / "private" / "intermediate.key.pem",
            ca_passphrase=b"interpass",
            repo=repo,
            out_dir=out_dir,
            ca_name="intermediate",
            next_update_days=7,
            logger=None,
        )

        assert crl_path.exists()

        crl = load_crl_pem(crl_path)
        revoked_serials = [hex(entry.serial_number) for entry in crl]
        assert serial_hex in revoked_serials


class TestCRLSigningVerification:

    @pytest.fixture
    def pki_with_crl(self, tmp_path):
        out_dir = tmp_path / "pki"
        db_path = out_dir / "micropki.db"

        repo = CertificateRepository(db_path)
        repo.init_db(force=True)

        init_ca(
            subject="CN=Root CA,O=Test,C=DE",
            key_type="rsa",
            key_size=4096,
            passphrase=b"rootpass",
            out_dir=out_dir,
            force=False,
            validity_days=3650,
            db_path=db_path,
            logger=None,
        )

        issue_intermediate_ca(
            root_cert_path=out_dir / "certs" / "ca.cert.pem",
            root_key_path=out_dir / "private" / "ca.key.pem",
            root_passphrase=b"rootpass",
            subject="CN=Intermediate CA,O=Test,C=DE",
            key_type="rsa",
            key_size=4096,
            intermediate_passphrase=b"interpass",
            out_dir=out_dir,
            validity_days=1825,
            pathlen=0,
            db_path=db_path,
            logger=None,
        )

        result = issue_end_entity_certificate(
            ca_cert_path=out_dir / "certs" / "intermediate.cert.pem",
            ca_key_path=out_dir / "private" / "intermediate.key.pem",
            ca_passphrase=b"interpass",
            template="server",
            subject="CN=revoked.example.com,O=Test,C=DE",
            san_entries=["dns:revoked.example.com"],
            out_dir=out_dir / "certs",
            validity_days=365,
            db_path=db_path,
            logger=None,
        )

        cert = x509.load_pem_x509_certificate(result["cert"].read_bytes())
        serial_hex = hex(cert.serial_number)

        repo = CertificateRepository(db_path)
        revoke_certificate(repo, serial_hex, "keyCompromise")

        crl_path = generate_crl_for_ca(
            ca_cert_path=out_dir / "certs" / "intermediate.cert.pem",
            ca_key_path=out_dir / "private" / "intermediate.key.pem",
            ca_passphrase=b"interpass",
            repo=repo,
            out_dir=out_dir,
            ca_name="intermediate",
            next_update_days=7,
        )

        return {
            "out_dir": out_dir,
            "crl_path": crl_path,
            "intermediate_cert": out_dir / "certs" / "intermediate.cert.pem",
        }

    def test_openssl_verify_crl_signature(self, pki_with_crl):
        import shutil
        if shutil.which("openssl") is None:
            pytest.skip("OpenSSL not installed")

        result = subprocess.run(
            [
                "openssl", "crl",
                "-in", str(pki_with_crl["crl_path"]),
                "-inform", "PEM",
                "-CAfile", str(pki_with_crl["intermediate_cert"]),
                "-noout",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )

        assert result.returncode == 0
        assert "verify OK" in result.stderr or "verify OK" in result.stdout


class TestCRLNumberIncrement:

    def test_crl_number_increments(self, tmp_path):
        out_dir = tmp_path / "pki"
        db_path = out_dir / "micropki.db"

        repo = CertificateRepository(db_path)
        repo.init_db(force=True)

        unique_cn = f"CN=Root CA CRL Incr {int(time.time())},O=Test,C=DE"

        init_ca(
            subject=unique_cn,
            key_type="rsa",
            key_size=4096,
            passphrase=b"rootpass",
            out_dir=out_dir,
            force=False,
            validity_days=3650,
            db_path=db_path,
            logger=None,
        )

        crl_path1 = generate_crl_for_ca(
            ca_cert_path=out_dir / "certs" / "ca.cert.pem",
            ca_key_path=out_dir / "private" / "ca.key.pem",
            ca_passphrase=b"rootpass",
            repo=repo,
            out_dir=out_dir,
            ca_name="root",
            next_update_days=7,
        )
        crl1 = load_crl_pem(crl_path1)  # Читаем сразу!

        crl_path2 = generate_crl_for_ca(
            ca_cert_path=out_dir / "certs" / "ca.cert.pem",
            ca_key_path=out_dir / "private" / "ca.key.pem",
            ca_passphrase=b"rootpass",
            repo=repo,
            out_dir=out_dir,
            ca_name="root",
            next_update_days=7,
        )
        crl2 = load_crl_pem(crl_path2)

        ext1 = crl1.extensions.get_extension_for_oid(x509.oid.ExtensionOID.CRL_NUMBER)
        ext2 = crl2.extensions.get_extension_for_oid(x509.oid.ExtensionOID.CRL_NUMBER)

        assert ext1.value.crl_number == 1
        assert ext2.value.crl_number == 2




class TestNegativeRevocation:

    @pytest.fixture
    def repo_with_cert(self, tmp_path):
        out_dir = tmp_path / "pki"
        db_path = out_dir / "micropki.db"

        repo = CertificateRepository(db_path)
        repo.init_db(force=True)

        init_ca(
            subject="CN=Root CA,O=Test,C=DE",
            key_type="rsa",
            key_size=4096,
            passphrase=b"rootpass",
            out_dir=out_dir,
            force=False,
            validity_days=3650,
            db_path=db_path,
            logger=None,
        )

        result = issue_end_entity_certificate(
            ca_cert_path=out_dir / "certs" / "ca.cert.pem",
            ca_key_path=out_dir / "private" / "ca.key.pem",
            ca_passphrase=b"rootpass",
            template="server",
            subject="CN=test.example.com,O=Test,C=DE",
            san_entries=["dns:test.example.com"],
            out_dir=out_dir / "certs",
            validity_days=365,
            db_path=db_path,
            logger=None,
        )

        cert = x509.load_pem_x509_certificate(result["cert"].read_bytes())
        serial_hex = hex(cert.serial_number)

        repo = CertificateRepository(db_path)

        return {"repo": repo, "serial_hex": serial_hex}

    def test_revoke_nonexistent_certificate(self, repo_with_cert):
        repo = repo_with_cert["repo"]

        with pytest.raises(ValueError) as exc_info:
            revoke_certificate(repo, "0xDEADBEEF12345678", "keyCompromise")

        assert "not found" in str(exc_info.value)

    def test_revoke_already_revoked_certificate(self, repo_with_cert):
        repo = repo_with_cert["repo"]
        serial = repo_with_cert["serial_hex"]

        result1 = revoke_certificate(repo, serial, "keyCompromise")
        assert result1 is True

        result2 = revoke_certificate(repo, serial, "superseded")
        assert result2 is False

        cert_data = repo.get_certificate_by_serial(serial)
        assert cert_data["revocation_reason"] == "keyCompromise"


class TestCRLDistribution:

    def test_crl_distribution(self, tmp_path):
        out_dir = tmp_path / "pki"
        certs_dir = out_dir / "certs"
        db_path = out_dir / "micropki.db"

        repo = CertificateRepository(db_path)
        repo.init_db(force=True)

        init_ca(
            subject="CN=Root CA,O=Test,C=DE",
            key_type="rsa",
            key_size=4096,
            passphrase=b"rootpass",
            out_dir=out_dir,
            force=False,
            validity_days=3650,
            db_path=db_path,
            logger=None,
        )

        repo = CertificateRepository(db_path)

        crl_path = generate_crl_for_ca(
            ca_cert_path=out_dir / "certs" / "ca.cert.pem",
            ca_key_path=out_dir / "private" / "ca.key.pem",
            ca_passphrase=b"rootpass",
            repo=repo,
            out_dir=out_dir,
            ca_name="root",
            next_update_days=7,
        )

        server = CertificateHTTPServer(
            ("127.0.0.1", 0),
            CertificateHTTPHandler,
            repo=repo,
            cert_dir=certs_dir,
        )

        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        time.sleep(0.5)

        host, port = server.server_address

        try:
            response = requests.get(f"http://{host}:{port}/crl?ca=root", timeout=5)
            assert response.status_code == 200
            assert response.headers.get("Content-Type") == "application/pkix-crl"

            fetched_crl = response.content
            local_crl = crl_path.read_bytes()
            assert fetched_crl == local_crl

        finally:
            server.shutdown()
            server.server_close()


class TestReasonCodes:

    def test_all_reason_codes_present(self):
        expected_codes = {
            "unspecified",
            "keycompromise",
            "cacompromise",
            "affiliationchanged",
            "superseded",
            "cessationofoperation",
            "certificatehold",
            "removefromcrl",
            "privilegewithdrawn",
            "aacompromise",
        }

        assert set(REASON_CODES.keys()) == expected_codes

    def test_invalid_reason_raises_error(self, tmp_path):
        out_dir = tmp_path / "pki"
        db_path = out_dir / "micropki.db"

        repo = CertificateRepository(db_path)
        repo.init_db(force=True)

        init_ca(
            subject="CN=Root CA,O=Test,C=DE",
            key_type="rsa",
            key_size=4096,
            passphrase=b"rootpass",
            out_dir=out_dir,
            force=False,
            validity_days=3650,
            db_path=db_path,
            logger=None,
        )

        result = issue_end_entity_certificate(
            ca_cert_path=out_dir / "certs" / "ca.cert.pem",
            ca_key_path=out_dir / "private" / "ca.key.pem",
            ca_passphrase=b"rootpass",
            template="server",
            subject="CN=test.example.com,O=Test,C=DE",
            san_entries=["dns:test.example.com"],
            out_dir=out_dir / "certs",
            validity_days=365,
            db_path=db_path,
            logger=None,
        )

        cert = x509.load_pem_x509_certificate(result["cert"].read_bytes())
        serial_hex = hex(cert.serial_number)

        repo = CertificateRepository(db_path)

        with pytest.raises(ValueError) as exc_info:
            revoke_certificate(repo, serial_hex, "invalid_reason")

        assert "Unsupported revocation reason" in str(exc_info.value)


class TestCRLMetadataTable:

    def test_crl_metadata_table_exists(self, tmp_path):
        out_dir = tmp_path / "pki"
        db_path = out_dir / "micropki.db"

        repo = CertificateRepository(db_path)
        repo.init_db(force=True)

        init_ca(
            subject="CN=Root CA,O=Test,C=DE",
            key_type="rsa",
            key_size=4096,
            passphrase=b"rootpass",
            out_dir=out_dir,
            force=False,
            validity_days=3650,
            db_path=db_path,
            logger=None,
        )

        repo = CertificateRepository(db_path)

        generate_crl_for_ca(
            ca_cert_path=out_dir / "certs" / "ca.cert.pem",
            ca_key_path=out_dir / "private" / "ca.key.pem",
            ca_passphrase=b"rootpass",
            repo=repo,
            out_dir=out_dir,
            ca_name="root",
            next_update_days=7,
        )

        db = repo.db
        db.connect()
        result = db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='crl_metadata'"
        ).fetchone()
        db.close()

        assert result is not None

        db.connect()
        row = db.execute("SELECT * FROM crl_metadata").fetchone()
        db.close()

        assert row is not None
        assert row["crl_number"] == 1


class TestCLIRevokeAndGenCRL:

    def test_cli_revoke_command(self, tmp_path):
        out_dir = tmp_path / "pki"
        secrets_dir = tmp_path / "secrets"
        secrets_dir.mkdir()
        (secrets_dir / "ca.pass").write_bytes(b"rootpass")
        (secrets_dir / "intermediate.pass").write_bytes(b"interpass")

        db_path = out_dir / "micropki.db"

        subprocess.run(
            [
                sys.executable, "-m", "micropki", "db", "init",
                "--db-path", str(db_path),
                "--force",
            ],
            capture_output=True,
            timeout=30,
        )

        subprocess.run(
            [
                sys.executable, "-m", "micropki", "ca", "init",
                "--subject", "CN=Root CA,O=Test,C=DE",
                "--key-type", "rsa",
                "--key-size", "4096",
                "--passphrase-file", str(secrets_dir / "ca.pass"),
                "--out-dir", str(out_dir),
                "--db-path", str(db_path),
                "--force",
            ],
            capture_output=True,
            timeout=30,
        )

        subprocess.run(
            [
                sys.executable, "-m", "micropki", "ca", "issue-intermediate",
                "--root-cert", str(out_dir / "certs" / "ca.cert.pem"),
                "--root-key", str(out_dir / "private" / "ca.key.pem"),
                "--root-pass-file", str(secrets_dir / "ca.pass"),
                "--subject", "CN=Intermediate CA,O=Test,C=DE",
                "--key-type", "rsa",
                "--key-size", "4096",
                "--passphrase-file", str(secrets_dir / "intermediate.pass"),
                "--out-dir", str(out_dir),
                "--db-path", str(db_path),
                "--force",
            ],
            capture_output=True,
            timeout=30,
        )

        result = subprocess.run(
            [
                sys.executable, "-m", "micropki", "ca", "issue-cert",
                "--ca-cert", str(out_dir / "certs" / "intermediate.cert.pem"),
                "--ca-key", str(out_dir / "private" / "intermediate.key.pem"),
                "--ca-pass-file", str(secrets_dir / "intermediate.pass"),
                "--template", "server",
                "--subject", "CN=cli-test.example.com,O=Test,C=DE",
                "--san", "dns:cli-test.example.com",
                "--out-dir", str(out_dir / "certs"),
                "--db-path", str(db_path),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0

        list_result = subprocess.run(
            [
                sys.executable, "-m", "micropki", "ca", "list-certs",
                "--db-path", str(db_path),
                "--format", "json",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert list_result.returncode == 0
        import json
        certs = json.loads(list_result.stdout)
        serial = certs[0]["serial_hex"]

        revoke_result = subprocess.run(
            [
                sys.executable, "-m", "micropki", "ca", "revoke",
                serial.replace("0x", ""),
                "--reason", "keyCompromise",
                "--force",
                "--db-path", str(db_path),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert revoke_result.returncode == 0
        assert "revoked successfully" in revoke_result.stdout

        gen_crl_result = subprocess.run(
            [
                sys.executable, "-m", "micropki", "ca", "gen-crl",
                "--ca", "intermediate",
                "--out-dir", str(out_dir),
                "--db-path", str(db_path),
                "--ca-pass-file", str(secrets_dir / "intermediate.pass"),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert gen_crl_result.returncode == 0
        assert "CRL generated successfully" in gen_crl_result.stdout
        assert (out_dir / "crl" / "intermediate.crl.pem").exists()


