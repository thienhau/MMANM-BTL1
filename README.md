# BÀI TẬP LỚN: MẬT MÃ VÀ AN NINH MẠNG (CO3069) - HỌC KỲ 261
## BÀI TẬP LỚN SỐ 1: PHÁT TRIỂN ỨNG DỤNG MẬT MÃ VÀ TRUYỀN THÔNG BẢO MẬT (ĐỀ TÀI 1.1 & 1.2)

---

### THÔNG TIN NHÓM THỰC HIỆN:
- **Trường:** Đại học Bách Khoa – ĐHQG TP. Hồ Chí Minh
- **Khoa:** Khoa học và Kỹ thuật Máy tính
- **Danh sách thành viên:**
  1. `2213444`
  2. `2310930`
  3. `2311523`
  4. `2333464`

---

## 1. CẤU TRÚC GÓI NỘP BÀI (THEO ĐÚNG QUY CHUẨN ĐỀ BÀI)

```text
Assigment1.zip (hoặc thư mục dự án)
├── README.md / README.doc   # Hướng dẫn cài đặt và sử dụng hệ thống
├── docs/                    # Báo cáo học thuật chi tiết
│   ├── report.tex           # Mã nguồn LaTeX bài báo cáo
│   └── report.text          # Bản báo cáo text tra cứu nhanh
├── pics/                    # Ảnh minh chứng nghiệm thu thực tế
│   ├── test_unit_member1_2.png    # Minh chứng 1: Test Framing & Crypto lõi
│   ├── test_unit_member3_4.png    # Minh chứng 2: Test AES-GCM, Chunking & Hex Dump Python
│   ├── e2ee_handshake.png         # Minh chứng 3: Bắt tay 4 MSSV & Kênh E2EE thực tế
│   ├── e2ee_chat.png              # Minh chứng 4: Chat bảo mật thời gian thực hai chiều
│   ├── e2ee_file_transfer.png     # Minh chứng 5: Truyền tệp cắt khối & Checksum
│   ├── wireshark_stream.png       # Minh chứng 6: Bắt gói tin Wireshark (Follow TCP Stream)
│   ├── mitm_attack_detection.png  # Minh chứng 7: Tấn công MitM Proxy & Chặn đứng InvalidTag
│   ├── pki_root_ca_init.png       # Minh chứng 8: Root CA 4 MSSV & Chặn kết nối không tin cậy
│   ├── pki_trusted_https_crl.png  # Minh chứng 9: Web Server HTTPS 200 OK & Thu hồi CRL
│   ├── pki_browser_https.png      # Minh chứng 10: Trình duyệt Web xác thực chứng thư X.509
│   └── hcmut.png                  # Biểu trưng Đại học Bách Khoa ĐHQG-HCM
├── srcs/                    # Toàn bộ mã nguồn chương trình, kịch bản test và dữ liệu mẫu
│   ├── requirements.txt     # Danh sách thư viện cần thiết (cryptography>=41.0.0)
│   ├── protocol.py          # Giao thức đóng khung TCP chống dính gói (Framing)
│   ├── crypto_core.py       # Lõi mật mã: KDF (MSSV), HMAC, RSA-OAEP, RSA-PSS, AES-256-GCM
│   ├── server.py            # Máy chủ chuyển tiếp (Relay Server E2EE)
│   ├── client.py            # Ứng dụng khách (Client) hỗ trợ Chat & Gửi tệp nhị phân
│   ├── mitm_proxy.py        # Proxy giả lập tấn công can thiệp dữ liệu MitM (Tampering)
│   ├── ca_manager.py        # Đề tài 1.2: Quản lý Root CA 4 MSSV, cấp cert Web Server & CRL
│   ├── https_demo.py        # Đề tài 1.2: Dựng HTTPS Server & 3 kịch bản kiểm định chuỗi tin cậy
│   ├── pki_store/           # Thư mục lưu trữ certs & keys: root_ca, server, crl.pem
│   ├── test_member1.py      # Kịch bản test Thành viên 1: Framing & Anti-sticky packets
│   ├── test_member2.py      # Kịch bản test Thành viên 2: KDF, HMAC Handshake & RSA
│   ├── test_member3.py      # Kịch bản test Thành viên 3: AES-256-GCM & Chunking File Transfer
│   ├── test_member4.py      # Kịch bản test Thành viên 4: Eavesdropping & MitM Bit-flipping
│   ├── run_all_tests.py     # Bộ kiểm thử tích hợp tự động toàn diện
│   ├── benchmark_performance.py # Đo lường hiệu năng mật mã & thông lượng file (Table 3.4 & 3.5)
│   └── sample_test.txt      # Tập tin mẫu dùng kiểm thử truyền nhận dữ liệu
└── refs/                    # Tài liệu, tiêu chuẩn quốc tế (PDF) và mã nguồn mở tham khảo
    ├── BAI_TAP_LON_CO3069_HK261.pdf           # Đề cương đề tài BTL 1.1 chính thức từ Khoa
    ├── RFC8017_PKCS1_v2.2_RSA.pdf             # Tiêu chuẩn RSA-OAEP & RSA-PSS từ IETF
    ├── RFC2104_HMAC_SHA256.pdf                # Tiêu chuẩn HMAC-SHA256 từ IETF
    ├── NIST_SP_800-38D_AES_GCM.pdf            # Tiêu chuẩn AES-256-GCM từ NIST Hoa Kỳ
    ├── NIST_FIPS_180-4_SHA256.pdf             # Tiêu chuẩn hàm băm SHA-256 từ NIST
    ├── NIST_FIPS_198-1_HMAC.pdf               # Tiêu chuẩn xác thực HMAC từ NIST
    ├── Signal_DoubleRatchet_E2EE_Protocol.pdf # Đặc tả giao thức E2EE mã nguồn mở của Signal
    ├── RFC5280_X509_PKI_CRL_Profile.pdf      # Tiêu chuẩn X.509 v3 PKI và CRL Profile (Đề tài 1.2)
    ├── RFC8446_TLS_Protocol_v1.3.pdf         # Tiêu chuẩn giao thức bảo mật TLS v1.3 cho HTTPS (Đề tài 1.2)
    └── open_source_cryptography_link.txt     # Liên kết kho GitHub và thông tin tải mã nguồn pyca/cryptography
```

---

## 2. YÊU CẦU MÔI TRƯỜNG & HƯỚNG DẪN CÀI ĐẶT

### 2.1. Yêu cầu hệ thống:
- Hệ điều hành: Windows / Linux / macOS.
- Python: Phiên bản >= 3.10 (khuyến nghị Python 3.11 hoặc 3.12).

### 2.2. Cài đặt thư viện:
Mở terminal và di chuyển vào thư mục `srcs`, thực thi lệnh:
```bash
cd srcs
pip install -r requirements.txt
```
*(Thư viện duy nhất cần cài đặt là `cryptography`, các thư viện mạng `socket`, `threading`, `json`, `hashlib` đều có sẵn trong chuẩn Python).*

---

## 3. HƯỚNG DẪN CHẠY CHƯƠNG TRÌNH

### 3.1. Chạy đo lường hiệu năng thực tế (Performance Benchmark)
Để đo thời gian thực thi của các giải thuật mật mã (RSA, AES-GCM, SHA-256) và thông lượng tệp tin:
`ash
cd srcs
py benchmark_performance.py
`

### 3.2. Chạy bộ kiểm thử tự động (Automated Test Suite)
Để kiểm tra tức thời toàn bộ tính năng của 4 thành viên trong vòng 1 giây:
```bash
cd srcs
python run_all_tests.py
```

### 3.3. Chạy ứng dụng Chat & Truyền tệp E2EE thực tế (Interactive Real-time)
Mở 3 cửa sổ Terminal riêng biệt:

1. **Terminal 1 - Khởi chạy Relay Server:**
   ```bash
   python server.py
   ```
   *(Server sẽ mở cổng 9999 và chờ 2 bên kết nối).*

2. **Terminal 2 - Khởi chạy Client 1 (Alice - vai trò Initiator):**
   ```bash
   python client.py
   ```

3. **Terminal 3 - Khởi chạy Client 2 (Bob - vai trò Receiver):**
   ```bash
   python client.py
   ```

- Ngay khi Client 2 kết nối, hai Client sẽ tự động thực hiện luồng bắt tay Handshake:
  - Gửi lời chào: `Hello, We are 2213444, 2310930, 2311523, 2333464` kèm mã HMAC-SHA256 tính từ khóa KDF băm MSSV.
  - Trao đổi Public Key RSA 2048-bit và ký số RSA-PSS.
  - Thiết lập khóa phiên AES-256 đối xứng bí mật.
- Menu điều khiển sẽ hiện ra:
  - Bấm `1`: Nhập tin nhắn văn bản mã hóa tức thời.
  - Bấm `2`: Nhập đường dẫn file cần gửi (ví dụ: `sample_test.txt`). File nhận được sẽ tự động lưu vào thư mục `received_files/` và đối soát mã băm SHA-256.
  - Bấm `3`: Thoát ứng dụng an toàn.

---

### 3.4. Thử nghiệm kịch bản tấn công Man-in-the-Middle (MitM Tampering)
1. Bật Server: `python server.py` (Cổng 9999).
2. Bật MitM Proxy: `python mitm_proxy.py` (Cổng 8888, chuyển tiếp về cổng 9999).
3. Cho Client 1 kết nối cổng thật 9999: `python client.py 127.0.0.1 9999`.
4. Cho Client 2 kết nối qua cổng Proxy 8888: `python client.py 127.0.0.1 8888`.
5. Khi Client 1 chat sang Client 2, Proxy lập tức đảo bit của gói tin trên đường truyền. Phía Client 2 sẽ kích hoạt cảnh báo đỏ:
   `[X] PHÁT HIỆN CAN THIỆP DỮ LIỆU: Lỗi InvalidTag AES-GCM!`
   Chứng minh hệ thống an toàn tuyệt đối trước tấn công làm sai lệch dữ liệu.

### 3.5. Chạy Demo Đề tài 1.2: Triển khai hạ tầng Khóa công khai nội bộ (Private PKI)
Để kiểm thử trọn gói toàn bộ quy trình sinh Root CA, cấp chứng chỉ Web Server và chạy 3 kịch bản:
```bash
cd srcs
python https_demo.py
```
- **Kịch bản 1:** Client kết nối khi chưa nạp Root CA -> Chặn kết nối `SSLCertVerificationError`.
- **Kịch bản 2:** Client nạp Root CA chính chủ -> Xác thực chuỗi tin cậy (Chain of Trust) thành công, HTTP 200 OK.
- **Kịch bản 3:** Root CA thu hồi chứng chỉ vào CRL -> Client phát hiện `REVOKED` và ngắt kết nối an toàn.

