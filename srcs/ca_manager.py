"""
Module Quản lý Hạ tầng Khóa Công khai Nội bộ (Private PKI / CA Manager)
Đề tài 1.2: Triển khai hạ tầng Khóa công khai nội bộ
Ràng buộc lồng ghép 4 MSSV:
- Common Name (CN): CA-Root-2213444-2310930-2311523-2333464
- Organizational Unit (OU): Faculty of Computer Science and Engineer – 2213444-2310930-2311523-2333464
"""
import datetime
import ipaddress
import os
import sys
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

OFFICIAL_MSSV = ["2213444", "2310930", "2311523", "2333464"]
MSSV_STRING = "-".join(OFFICIAL_MSSV)


class PrivatePKIManager:
    def __init__(self, certs_dir: str = "pki_store"):
        self.certs_dir = certs_dir
        os.makedirs(self.certs_dir, exist_ok=True)
        self.root_ca_key_path = os.path.join(self.certs_dir, "root_ca.key")
        self.root_ca_cert_path = os.path.join(self.certs_dir, "root_ca.crt")
        self.server_key_path = os.path.join(self.certs_dir, "server.key")
        self.server_cert_path = os.path.join(self.certs_dir, "server.crt")
        self.crl_path = os.path.join(self.certs_dir, "crl.pem")

    def generate_rsa_key(self, key_size: int = 2048) -> rsa.RSAPrivateKey:
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )

    def create_root_ca(self) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
        """Tạo Root CA tự ký X.509 v3 với Subject chứa 4 MSSV chuẩn đề bài."""
        ca_key = self.generate_rsa_key(key_size=2048)
        
        cn = f"CA-Root-{MSSV_STRING}"
        ou = f"Faculty of Computer Science and Engineer – {MSSV_STRING}"
        
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Ho Chi Minh"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Ho Chi Minh City University of Technology - VNU-HCM"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ])

        now = datetime.datetime.now(datetime.timezone.utc)
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))  # 10 năm
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )

        # Lưu file khóa riêng và chứng chỉ Root CA
        with open(self.root_ca_key_path, "wb") as f:
            f.write(ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))

        with open(self.root_ca_cert_path, "wb") as f:
            f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

        return ca_key, ca_cert

    def issue_web_server_certificate(
        self,
        ca_key: rsa.RSAPrivateKey,
        ca_cert: x509.Certificate,
        domain: str = "localhost",
        ip: str = "127.0.0.1",
    ) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
        """Cấp phát chứng chỉ X.509 cho Web Server HTTPS/TLS kèm mở rộng SAN."""
        server_key = self.generate_rsa_key(key_size=2048)

        server_subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "HCMUT E2EE Web Service"),
            x509.NameAttribute(NameOID.COMMON_NAME, domain),
        ])

        now = datetime.datetime.now(datetime.timezone.utc)
        san_list = [
            x509.DNSName(domain),
            x509.IPAddress(ipaddress.IPv4Address(ip)),
        ]

        server_cert = (
            x509.CertificateBuilder()
            .subject_name(server_subject)
            .issuer_name(ca_cert.subject)
            .public_key(server_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))  # 1 năm
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=False,
            )
            .add_extension(
                x509.SubjectAlternativeName(san_list),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )

        with open(self.server_key_path, "wb") as f:
            f.write(server_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))

        with open(self.server_cert_path, "wb") as f:
            f.write(server_cert.public_bytes(serialization.Encoding.PEM))

        return server_key, server_cert

    def generate_crl(
        self,
        ca_key: rsa.RSAPrivateKey,
        ca_cert: x509.Certificate,
        revoked_serials: list[int] = None,
    ) -> x509.CertificateRevocationList:
        """Tạo Danh sách Thu hồi Chứng chỉ (CRL - Certificate Revocation List)."""
        now = datetime.datetime.now(datetime.timezone.utc)
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(ca_cert.subject)
            .last_update(now)
            .next_update(now + datetime.timedelta(days=7))
        )

        if revoked_serials:
            for serial in revoked_serials:
                revoked_cert = (
                    x509.RevokedCertificateBuilder()
                    .serial_number(serial)
                    .revocation_date(now)
                    .add_extension(
                        x509.CRLReason(x509.ReasonFlags.key_compromise),
                        critical=False,
                    )
                    .build()
                )
                builder = builder.add_revoked_certificate(revoked_cert)

        crl = builder.sign(ca_key, hashes.SHA256())

        with open(self.crl_path, "wb") as f:
            f.write(crl.public_bytes(serialization.Encoding.PEM))

        return crl

    @staticmethod
    def is_certificate_revoked(cert: x509.Certificate, crl: x509.CertificateRevocationList) -> bool:
        """Kiểm tra xem chứng chỉ có nằm trong danh sách thu hồi CRL hay không."""
        return crl.get_revoked_certificate_by_serial_number(cert.serial_number) is not None


if __name__ == "__main__":
    print("=" * 70)
    print("  KHỞI TẠO DỊCH VỤ CHỨNG THỰC SỐ (PRIVATE CA) - ĐỀ TÀI 1.2")
    print(f"  DANH SÁCH 4 MSSV NHÓM: {', '.join(OFFICIAL_MSSV)}")
    print("=" * 70)

    pki = PrivatePKIManager(certs_dir="pki_store")

    print("\n[1] Đang sinh Root CA tự ký X.509 v3...")
    ca_key, ca_cert = pki.create_root_ca()
    print(f"[✓] Root CA đã được tạo:")
    for attr in ca_cert.subject:
        print(f"    - {attr.oid._name}: {attr.value}")
    print(f"    - Serial Number: {hex(ca_cert.serial_number)}")
    print(f"    - File Root CA Cert: {pki.root_ca_cert_path}")

    print("\n[2] Đang cấp phát chứng chỉ cho Web Server (HTTPS)...")
    srv_key, srv_cert = pki.issue_web_server_certificate(ca_key, ca_cert, domain="localhost", ip="127.0.0.1")
    print(f"[✓] Web Server Certificate đã được cấp:")
    print(f"    - Subject: {srv_cert.subject.rfc4514_string()}")
    print(f"    - Issuer (Root CA): {srv_cert.issuer.rfc4514_string()}")
    print(f"    - Serial Number: {hex(srv_cert.serial_number)}")
    print(f"    - File Server Cert: {pki.server_cert_path}")

    print("\n[3] Đang khởi tạo Danh sách Thu hồi Chứng chỉ (CRL)...")
    crl_clean = pki.generate_crl(ca_key, ca_cert, revoked_serials=[])
    print(f"[✓] CRL rỗng đã tạo thành công ({len(crl_clean)} chứng chỉ bị thu hồi).")
    print(f"    - File CRL: {pki.crl_path}")

    print("\n[✓] HẠ TẦNG KHÓA CÔNG KHAI NỘI BỘ (PKI) ĐÃ SẴN SÀNG 100%!")

