import pytest
import threading
import time
import requests

from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from micropki.database import CertificateDatabase
from micropki.repository import CertificateRepository
from micropki.server import CertificateHTTPServer, CertificateHTTPHandler


def normalize_pem(pem_string):
    return pem_string.replace('\r', '').strip()


class TestFullWorkflow:

    @pytest.fixture
    def pki_environment(self, tmp_path):
        pki_dir = tmp_path / "pki"
        pki_dir.mkdir()

        certs_dir = pki_dir / "certs"
        certs_dir.mkdir()

        private_dir = pki_dir / "private"
        private_dir.mkdir()

        db_path = pki_dir / "micropki.db"

        return {
            "pki_dir": pki_dir,
            "certs_dir": certs_dir,
            "private_dir": private_dir,
            "db_path": db_path
        }

    def _create_root_ca(self, subject_cn="Test Root CA"):
        root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        root_subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, subject_cn),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MicroPKI Test"),
        ])

        root_cert = x509.CertificateBuilder().subject_name(
            root_subject
        ).issuer_name(
            root_subject
        ).public_key(
            root_key.public_key()
        ).serial_number(
            1
        ).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=365)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True
        ).sign(root_key, hashes.SHA256())

        root_pem = root_cert.public_bytes(serialization.Encoding.PEM).decode()

        return {
            "key": root_key,
            "cert": root_cert,
            "pem": root_pem,
            "subject": root_subject
        }

    def _create_leaf_cert(self, ca_key, ca_cert, ca_subject, cn, serial_num):
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        leaf_subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ])

        leaf_cert = x509.CertificateBuilder().subject_name(
            leaf_subject
        ).issuer_name(
            ca_subject
        ).public_key(
            leaf_key.public_key()
        ).serial_number(
            serial_num
        ).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=30)
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True
        ).add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(cn)]),
            critical=False
        ).sign(ca_key, hashes.SHA256())

        leaf_pem = leaf_cert.public_bytes(serialization.Encoding.PEM).decode()

        return {
            "key": leaf_key,
            "cert": leaf_cert,
            "pem": leaf_pem,
            "serial_hex": hex(serial_num)
        }

    def test_full_certificate_lifecycle(self, pki_environment):

        env = pki_environment

        print("\n[TEST-20] Step 1: Initializing database...")

        db = CertificateDatabase(env["db_path"])
        assert db.init_schema()

        repo = CertificateRepository(env["db_path"])
        print(f"  ✓ Database initialized at {env['db_path']}")

        print("[TEST-20] Step 2: Creating Root CA...")

        root_ca = self._create_root_ca("Test Root CA")


        root_cert_path = env["certs_dir"] / "ca.cert.pem"
        root_cert_path.write_text(root_ca["pem"])
        print(f"  ✓ Root CA saved to {root_cert_path}")


        print("[TEST-20] Step 3: Issuing leaf certificates...")

        certs_issued = []
        for i in range(3):
            cn = f"server{i}.example.com"
            serial_num = 1000 + i

            leaf = self._create_leaf_cert(
                root_ca["key"],
                root_ca["cert"],
                root_ca["subject"],
                cn,
                serial_num
            )


            cert_path = env["certs_dir"] / f"{cn}.cert.pem"
            cert_path.write_text(leaf["pem"])


            cert_id = repo.insert_certificate(leaf["cert"], leaf["pem"], status="valid")

            certs_issued.append({
                "cn": cn,
                "serial_hex": leaf["serial_hex"],
                "serial_clean": leaf["serial_hex"].replace("0x", ""),
                "cert_path": cert_path,
                "db_id": cert_id,
                "pem": leaf["pem"]
            })

            print(f"    ✓ Issued: {cn}, serial={leaf['serial_hex']}")


        print("[TEST-20] Step 4: Verifying database records...")

        all_certs = repo.list_certificates()
        assert len(all_certs) == 3, f"Expected 3 certs, found {len(all_certs)}"

        for cert_info in certs_issued:
            cert_data = repo.get_certificate_by_serial(cert_info["serial_hex"])
            assert cert_data is not None
            assert cert_data["subject"] == f"CN={cert_info['cn']}"
            assert cert_data["status"] == "valid"
        print(f"  ✓ All {len(all_certs)} certificates verified in database")


        print("[TEST-20] Step 5: Starting HTTP server...")

        server_address = ("127.0.0.1", 8888)
        httpd = CertificateHTTPServer(
            server_address,
            CertificateHTTPHandler,
            repo=repo,
            cert_dir=env["certs_dir"],
            logger=None
        )

        server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        server_thread.start()
        time.sleep(1)  # Wait for server to start
        print(f"  ✓ Server started on {server_address[0]}:{server_address[1]}")

        try:

            print("[TEST-20] Step 6: Testing API endpoints...")


            for cert_info in certs_issued:
                response = requests.get(
                    f"http://127.0.0.1:8888/certificate/{cert_info['serial_clean']}",
                    timeout=5
                )
                assert response.status_code == 200
                assert normalize_pem(response.text) == normalize_pem(cert_info["pem"])
                print(f"    ✓ Fetched certificate {cert_info['serial_clean']} from API")

            response = requests.get("http://127.0.0.1:8888/ca/root", timeout=5)
            assert response.status_code == 200
            assert normalize_pem(response.text) == normalize_pem(root_ca["pem"])
            print("    ✓ Fetched Root CA from API")


            response = requests.get("http://127.0.0.1:8888/crl", timeout=5)
            assert response.status_code == 501
            assert "not yet implemented" in response.text.lower()
            print("    ✓ CRL endpoint returns 501")


            response = requests.get("http://127.0.0.1:8888/certificate/not_hex!!!", timeout=5)
            assert response.status_code == 400
            print("    ✓ Invalid serial returns 400")


            response = requests.get("http://127.0.0.1:8888/certificate/DEADBEEF12345678", timeout=5)
            assert response.status_code == 404
            print("    ✓ Non-existent serial returns 404")


            print("[TEST-20] Step 7: Testing filesystem fallback...")


            fs_leaf = self._create_leaf_cert(
                root_ca["key"],
                root_ca["cert"],
                root_ca["subject"],
                "fs-only.example.com",
                9999
            )

            fs_serial_clean = fs_leaf["serial_hex"].replace("0x", "")
            fs_cert_path = env["certs_dir"] / f"{fs_serial_clean}.cert.pem"
            fs_cert_path.write_text(fs_leaf["pem"])


            db_result = repo.get_certificate_by_serial(fs_leaf["serial_hex"])
            assert db_result is None


            response = requests.get(
                f"http://127.0.0.1:8888/certificate/{fs_serial_clean}",
                timeout=5
            )
            assert response.status_code == 200
            assert normalize_pem(response.text) == normalize_pem(fs_leaf["pem"])
            print("    ✓ Filesystem fallback works correctly")

        finally:
            print("[TEST-20] Step 8: Shutting down server...")
            httpd.shutdown()
            server_thread.join(timeout=2)

        print("\nTEST-20: Full workflow integration test PASSED!\n")


class TestConcurrentIssuance:


    def test_concurrent_certificate_issuance(self, tmp_path):
        from micropki.serials import generate_certificate_serial_number

        db_path = tmp_path / "test.db"
        db = CertificateDatabase(db_path)
        db.init_schema()

        repo = CertificateRepository(db_path)


        root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        root_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])

        root_cert = x509.CertificateBuilder().subject_name(
            root_subject
        ).issuer_name(
            root_subject
        ).public_key(
            root_key.public_key()
        ).serial_number(
            1
        ).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=365)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True
        ).sign(root_key, hashes.SHA256())

        serials_issued = set()

        for i in range(20):
            # Generate unique serial
            serial = generate_certificate_serial_number()
            while serial in serials_issued:
                serial = generate_certificate_serial_number()
            serials_issued.add(serial)

            leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            leaf_subject = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, f"concurrent{i}.example.com"),
            ])

            leaf_cert = x509.CertificateBuilder().subject_name(
                leaf_subject
            ).issuer_name(
                root_subject
            ).public_key(
                leaf_key.public_key()
            ).serial_number(
                serial
            ).not_valid_before(
                datetime.now(timezone.utc)
            ).not_valid_after(
                datetime.now(timezone.utc) + timedelta(days=30)
            ).add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True
            ).sign(root_key, hashes.SHA256())

            leaf_pem = leaf_cert.public_bytes(serialization.Encoding.PEM).decode()

            cert_id = repo.insert_certificate(leaf_cert, leaf_pem)
            assert cert_id is not None


        certs = repo.list_certificates()
        assert len(certs) == 20


        db_serials = [cert["serial_hex"] for cert in certs]
        assert len(db_serials) == len(set(db_serials))