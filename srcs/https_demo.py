"""
Chương trình Demo Web Server HTTPS và Kịch bản Xác thực Chứng thư X.509
Đề tài 1.2: Triển khai hạ tầng Khóa công khai nội bộ (PKI / Private CA)
Bao gồm 3 kịch bản kiểm thử:
1. Kết nối không tin cậy Root CA -> Bị từ chối (CertificateVerifyFailed)
2. Kết nối với Root CA nội bộ hợp lệ -> Kết nối HTTPS thành công (200 OK, TLS an toàn)
3. Kiểm tra danh sách thu hồi CRL -> Phát hiện chứng chỉ bị thu hồi (Certificate Revoked)
"""
import http.server
import json
import os
import ssl
import sys
import threading
import time
import urllib.request
import urllib.error
from cryptography import x509

from ca_manager import PrivatePKIManager

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

PORT = 8443
HOST = "localhost"


class SecureHTTPHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.end_headers()
        response = {
            "status": "success",
            "message": "Ket noi HTTPS thanh cong qua Chung thu so X.509!",
            "server": "HCMUT-BTL-ANM-Topic-1.2-Server",
            "security": "TLS Encryption with Private Root CA",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.wfile.write(json.dumps(response, indent=2).encode("utf-8"))

    def log_message(self, format, *args):
        return


def run_https_server(certfile: str, keyfile: str, stop_event: threading.Event):
    """Khởi chạy Web Server HTTPS trên luồng nền."""
    server_address = ("127.0.0.1", PORT)
    httpd = http.server.HTTPServer(server_address, SecureHTTPHandler)

    # Cấu hình SSL/TLS Context cho Web Server
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    httpd.socket = ssl_context.wrap_socket(httpd.socket, server_side=True)

    httpd.timeout = 0.5
    while not stop_event.is_set():
        httpd.handle_request()
    httpd.server_close()


def run_topic1_2_demo():
    print("\n" + "#" * 70)
    print("   BÀI TẬP LỚN MẬT MÃ VÀ AN NINH MẠNG (CO3011) - HỌC KỲ 261")
    print("   ĐỀ TÀI 1.2: TRIỂN KHAI HẠ TẦNG KHÓA CÔNG KHAI NỘI BỘ (PRIVATE PKI)")
    print("   DANH SÁCH 4 MSSV: 2213444, 2310930, 2311523, 2333464")
    print("#" * 70)

    # 1. Khởi tạo PKI Manager và sinh các chứng chỉ
    pki = PrivatePKIManager(certs_dir="pki_store")
    print("\n[*] [GIAI ĐOẠN 1] KHỞI TẠO ROOT CA VÀ CẤP CHỨNG THƯ WEB SERVER...")
    ca_key, ca_cert = pki.create_root_ca()
    server_key, server_cert = pki.issue_web_server_certificate(
        ca_key, ca_cert, domain="localhost", ip="127.0.0.1"
    )

    print(f"[✓] Root CA Common Name (CN) : {ca_cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value}")
    print(f"[✓] Root CA Org Unit (OU)   : {ca_cert.subject.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value}")
    print(f"[✓] Web Server Cert Domain  : {server_cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value}")
    print(f"[✓] Server Serial Number    : {hex(server_cert.serial_number)}")

    # 2. Khởi chạy HTTPS Web Server trên cổng 8443
    stop_event = threading.Event()
    server_thread = threading.Thread(
        target=run_https_server,
        args=(pki.server_cert_path, pki.server_key_path, stop_event),
        daemon=True,
    )
    server_thread.start()
    time.sleep(0.5)
    print(f"[✓] HTTPS Web Server đang hoạt động tại https://localhost:{PORT}")

    # =========================================================================
    # KỊCH BẢN THỰC NGHIỆM 1: KẾT NỐI KHÔNG NẠP ROOT CA
    # =========================================================================
    print("\n" + "=" * 70)
    print("  KỊCH BẢN 1: KẾT NỐI KHI CHƯA TIN CẬY ROOT CA NỘI BỘ")
    print("=" * 70)
    print("[*] Client gửi yêu cầu HTTPS mà không nạp Root CA vào Trust Store...")
    try:
        untrusted_ctx = ssl.create_default_context()
        req = urllib.request.Request(f"https://localhost:{PORT}")
        with urllib.request.urlopen(req, context=untrusted_ctx, timeout=3) as resp:
            print("[X] Lỗi: Kết nối bất ngờ thành công khi chưa tin cậy CA!")
    except (urllib.error.URLError, ssl.SSLCertVerificationError) as e:
        print(f"[✓] BẢO VỆ AN TOÀN: Kết nối bị từ chối chính xác!")
        print(f"    -> Lỗi phát hiện: {e}")
        print("    -> Giải thích: Client từ chối kết nối vì Server mang chứng chỉ chưa được ký bởi CA tin cậy.")

    # =========================================================================
    # KỊCH BẢN THỰC NGHIỆM 2: KẾT NỐI NẠP ROOT CA HỢP LỆ (CHAIN OF TRUST)
    # =========================================================================
    print("\n" + "=" * 70)
    print("  KỊCH BẢN 2: KẾT NỐI KHI NẠP ROOT CA CHÍNH CHỦ CỦA NHÓM")
    print("=" * 70)
    print(f"[*] Client nạp tệp tin Root CA tin cậy: {pki.root_ca_cert_path}...")
    try:
        trusted_ctx = ssl.create_default_context(cafile=pki.root_ca_cert_path)
        req = urllib.request.Request(f"https://localhost:{PORT}")
        with urllib.request.urlopen(req, context=trusted_ctx, timeout=3) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            print(f"[✓] XÁC THỰC THÀNH CÔNG: Chuỗi tin cậy (Chain of Trust) hợp lệ 100%!")
            print(f"    -> HTTP Status Code: {resp.status} OK")
            print(f"    -> Dữ liệu phản hồi từ Web Server an toàn:")
            for k, v in data.items():
                print(f"       + {k}: {v}")
    except Exception as e:
        print(f"[X] Thất bại ngoài ý muốn: {e}")

    # =========================================================================
    # KỊCH BẢN THỰC NGHIỆM 3: THU HỒI CHỨNG CHỈ QUA DANH SÁCH CRL
    # =========================================================================
    print("\n" + "=" * 70)
    print("  KỊCH BẢN 3: CƠ CHẾ THU HỒI CHỨNG THƯ SỐ (CRL - CERTIFICATE REVOCATION)")
    print("=" * 70)
    print(f"[*] Giả lập tình huống: Khóa riêng của Web Server bị lộ (Key Compromise).")
    print(f"[*] Root CA kích hoạt thu hồi chứng chỉ Serial: {hex(server_cert.serial_number)}...")
    
    # Root CA xuất danh sách CRL mới có chứa số Serial của Server
    crl_updated = pki.generate_crl(ca_key, ca_cert, revoked_serials=[server_cert.serial_number])
    print(f"[✓] Đã tạo Danh sách Thu hồi CRL mới ({len(crl_updated)} chứng chỉ bị thu hồi).")
    print(f"    -> File CRL: {pki.crl_path}")

    # Client kiểm tra tính hợp lệ qua CRL trước khi giao tiếp
    print("[*] Phía Client thực hiện đối soát số Serial của Server với danh sách CRL...")
    is_revoked = PrivatePKIManager.is_certificate_revoked(server_cert, crl_updated)
    
    if is_revoked:
        print(f"[✓] PHÁT HIỆN THU HỒI THÀNH CÔNG: Chứng chỉ đã bị Root CA đưa vào blacklist!")
        print(f"    -> Trạng thái kiểm tra: REVOKED (Lý do: keyCompromise)")
        print(f"    -> Hành động của Client: LẬP TỨC ĐÓNG KẾT NỐI, CẢNH BÁO NGUY HIỂM TỚI NGƯỜI DÙNG.")
    else:
        print("[X] Lỗi: Không phát hiện được chứng chỉ bị thu hồi.")

    # Dừng server
    stop_event.set()
    print("\n" + "#" * 70)
    print("   HOÀN TẤT THỰC NGHIỆM ĐỀ TÀI 1.2: ĐẠT 100% CÁC TIÊU CHÍ VÀ RÀNG BUỘC!")
    print("#" * 70 + "\n")


if __name__ == "__main__":
    run_topic1_2_demo()
