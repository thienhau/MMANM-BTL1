"""
Ứng dụng Khách E2EE (E2EE Client)
Tích hợp đầy đủ:
1. Bắt tay Handshake chứa chuỗi yêu cầu: "Hello, We are 2213444, 2310930, 2311523, 2333464"
2. Dẫn xuất khóa KDF = SHA256(MSSV_1 || MSSV_2 || MSSV_3 || MSSV_4)
3. Xác thực nguồn gốc bằng HMAC-SHA256
4. Trao đổi Session Key an toàn bằng RSA-OAEP + Ký số RSA-PSS
5. Chat tức thời mã hóa AES-256-GCM
6. Truyền tập tin cắt khối (Chunking 64KB) + Checksum SHA-256 đối soát toàn vẹn
"""
import base64
import os
import socket
import sys
import threading

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from crypto_core import CryptoCore, OFFICIAL_GROUP_MSSV
from protocol import recv_json, send_json

SERVER_IP = "127.0.0.1"
SERVER_PORT = 9999
CHUNK_SIZE = 64 * 1024


class E2EEClient:
    def __init__(self, host: str = SERVER_IP, port: int = SERVER_PORT, mssv_list: list = None):
        self.host = host
        self.port = port
        self.mssv_list = mssv_list if mssv_list else OFFICIAL_GROUP_MSSV
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Tạo cặp khóa RSA 2048-bit riêng cho phiên làm việc
        self.private_rsa, self.public_rsa = CryptoCore.generate_rsa_keypair()
        self.peer_public_rsa = None
        self.session_key = None
        
        # Khóa KDF dẫn xuất từ MSSV
        self.kdf_master_key = CryptoCore.derive_kdf_from_mssv(self.mssv_list)
        self.role = None
        self.receiving_files = {}
        self.is_running = True

    def start(self):
        print(f"[*] Đang kết nối tới Relay Server {self.host}:{self.port}...")
        try:
            self.sock.connect((self.host, self.port))
        except Exception as e:
            print(f"[X] Không thể kết nối tới Server: {e}")
            return

        print(f"[✓] Đã kết nối tới Server.")
        print(f"[*] Danh sách MSSV: {', '.join(self.mssv_list)}")
        print(f"[*] KDF Master Key (SHA-256): {self.kdf_master_key.hex()}")

        # Nhận phân vai từ Relay Server
        init_msg = recv_json(self.sock)
        if not init_msg or "role" not in init_msg:
            print("[X] Lỗi nhận diện vai trò từ Server.")
            return

        self.role = init_msg.get("role")
        print(f"[*] Vai trò được gán: {self.role.upper()}")

        if self.role == "initiator":
            self.do_handshake_as_initiator()
        else:
            self.do_handshake_as_receiver()

        # Khởi chạy luồng nền lắng nghe tin nhắn & file từ đối tác
        threading.Thread(target=self.receive_listener, daemon=True).start()
        self.interactive_menu()

    def do_handshake_as_initiator(self):
        """Khởi tạo bắt tay: Gửi lời chào MSSV + HMAC + RSA Public Key."""
        handshake_text = f"Hello, We are {', '.join(self.mssv_list)}"
        mac = CryptoCore.compute_hmac(self.kdf_master_key, handshake_text.encode("utf-8"))
        
        print("\n--- BẮT ĐẦU BẮT TAY (INITIATOR) ---")
        print(f"[>] Gửi Handshake Plaintext: '{handshake_text}'")
        print(f"[>] Gửi HMAC-SHA256: {mac.hex()}")

        send_json(self.sock, {
            "type": "HANDSHAKE_HELLO",
            "plaintext": handshake_text,
            "hmac": base64.b64encode(mac).decode("utf-8"),
            "pubkey": CryptoCore.export_public_key_pem(self.public_rsa),
        })

        # Chờ đối tác phản hồi Public Key của họ
        res = recv_json(self.sock)
        if not res or res.get("type") != "HANDSHAKE_REPLY":
            print("[X] Phản hồi bắt tay không hợp lệ!")
            sys.exit(1)

        self.peer_public_rsa = CryptoCore.load_public_key_pem(res["pubkey"])
        print("[<] Đã nhận Public Key RSA của đối tác.")

        # Sinh ngẫu nhiên Session Key AES-256
        self.session_key = CryptoCore.generate_aes_key()
        # Mã hóa khóa phiên bằng Public Key của đối tác (RSA-OAEP)
        enc_session_key = CryptoCore.rsa_encrypt(self.peer_public_rsa, self.session_key)
        # Ký số lên khóa phiên đã mã hóa bằng Private Key của mình (RSA-PSS)
        signature = CryptoCore.rsa_sign(self.private_rsa, enc_session_key)

        print(f"[>] Đã sinh khóa phiên AES-256: {self.session_key.hex()}")
        print("[>] Gửi Session Key đã mã hóa RSA-OAEP kèm Chữ ký số RSA-PSS.")

        send_json(self.sock, {
            "type": "SESSION_KEY_EXCHANGE",
            "enc_key": base64.b64encode(enc_session_key).decode("utf-8"),
            "signature": base64.b64encode(signature).decode("utf-8"),
        })

        print("=" * 60)
        print(f"[✓] KÊNH BẢO MẬT E2EE ĐÃ THIẾT LẬP THÀNH CÔNG!")
        print(f"[✓] Khóa phiên hoạt động: {self.session_key.hex()}")
        print("=" * 60 + "\n")

    def do_handshake_as_receiver(self):
        """Bên nhận bắt tay: Xác thực lời chào MSSV qua HMAC, đối soát và giải mã Session Key."""
        print("\n--- CHỜ BẮT ĐẦU BẮT TAY (RECEIVER) ---")
        req = recv_json(self.sock)
        if not req or req.get("type") != "HANDSHAKE_HELLO":
            print("[X] Bản tin bắt tay không hợp lệ!")
            sys.exit(1)

        plaintext = req["plaintext"]
        expected_mac = base64.b64decode(req["hmac"])
        print(f"[<] Nhận Handshake Plaintext: '{plaintext}'")

        # 1. Xác thực HMAC với KDF từ MSSV
        is_valid = CryptoCore.verify_hmac(self.kdf_master_key, plaintext.encode("utf-8"), expected_mac)
        if not is_valid:
            print("[X] CẢNH BÁO BẢO MẬT: Lỗi xác thực HMAC! Dữ liệu giả mạo.")
            sys.exit(1)
        print("[✓] Xác thực HMAC thành công: Nguồn gốc hợp lệ chuẩn MSSV nhóm.")

        self.peer_public_rsa = CryptoCore.load_public_key_pem(req["pubkey"])

        # Phản hồi lại Public Key của mình
        send_json(self.sock, {
            "type": "HANDSHAKE_REPLY",
            "pubkey": CryptoCore.export_public_key_pem(self.public_rsa),
        })

        # Nhận gói Session Key đã mã hóa và chữ ký số
        key_pkg = recv_json(self.sock)
        enc_key = base64.b64decode(key_pkg["enc_key"])
        signature = base64.b64decode(key_pkg["signature"])

        # 2. Kiểm tra chữ ký số RSA-PSS
        if not CryptoCore.rsa_verify(self.peer_public_rsa, signature, enc_key):
            print("[X] CẢNH BÁO BẢO MẬT: Chữ ký số không khớp! Có nguy cơ MitM.")
            sys.exit(1)
        print("[✓] Chữ ký số RSA-PSS hợp lệ. Khóa phiên đúng từ đối tác gửi.")

        # 3. Giải mã lấy Session Key (RSA-OAEP)
        self.session_key = CryptoCore.rsa_decrypt(self.private_rsa, enc_key)

        print("=" * 60)
        print(f"[✓] KÊNH BẢO MẬT E2EE ĐÃ THIẾT LẬP THÀNH CÔNG!")
        print(f"[✓] Khóa phiên hoạt động: {self.session_key.hex()}")
        print("=" * 60 + "\n")

    def receive_listener(self):
        """Lắng nghe và giải mã các gói tin AES-GCM (Chat / File)."""
        os.makedirs("received_files", exist_ok=True)
        try:
            while self.is_running:
                msg = recv_json(self.sock)
                if msg is None:
                    print("\n[-] Đối tác đã ngắt kết nối.")
                    break

                mtype = msg.get("type")

                if mtype == "CHAT":
                    nonce = base64.b64decode(msg["nonce"])
                    ciphertext = base64.b64decode(msg["data"])
                    try:
                        plaintext_bytes = CryptoCore.aes_gcm_decrypt(self.session_key, nonce, ciphertext)
                        text = plaintext_bytes.decode("utf-8")
                        print(f"\n[Bạn chat]: {text}\n> ", end="", flush=True)
                    except Exception as e:
                        print(f"\n[X] PHÁT HIỆN CAN THIỆP DỮ LIỆU: Lỗi InvalidTag AES-GCM! {e}\n> ", end="", flush=True)

                elif mtype == "FILE_META":
                    nonce = base64.b64decode(msg["nonce"])
                    ciphertext = base64.b64decode(msg["data"])
                    meta_bytes = CryptoCore.aes_gcm_decrypt(self.session_key, nonce, ciphertext)
                    filename, filesize, expected_hash = meta_bytes.decode("utf-8").split("|")
                    save_path = os.path.join("received_files", f"received_{filename}")
                    self.receiving_files = {
                        "filename": filename,
                        "save_path": save_path,
                        "file_obj": open(save_path, "wb"),
                        "expected_hash": expected_hash,
                        "filesize": int(filesize),
                    }
                    print(f"\n[*] Đang nhận tập tin: {filename} ({filesize} bytes)...")

                elif mtype == "FILE_CHUNK":
                    nonce = base64.b64decode(msg["nonce"])
                    ciphertext = base64.b64decode(msg["data"])
                    try:
                        chunk = CryptoCore.aes_gcm_decrypt(self.session_key, nonce, ciphertext)
                        if self.receiving_files and "file_obj" in self.receiving_files:
                            self.receiving_files["file_obj"].write(chunk)
                    except Exception:
                        print("\n[X] Lỗi giải mã khối tập tin (Chunk corrupted)!")

                elif mtype == "FILE_END":
                    if self.receiving_files and "file_obj" in self.receiving_files:
                        self.receiving_files["file_obj"].close()
                        save_path = self.receiving_files["save_path"]
                        calc_hash = CryptoCore.calculate_file_hash(save_path)
                        expected_hash = self.receiving_files["expected_hash"]
                        if calc_hash == expected_hash:
                            print(f"\n[✓] Nhận tập tin thành công và toàn vẹn!")
                            print(f"[✓] Lưu tại: {save_path}")
                            print(f"[✓] Checksum SHA-256: {calc_hash}\n> ", end="", flush=True)
                        else:
                            print(f"\n[X] Toàn vẹn tập tin thất bại! Hash không khớp.\n> ", end="", flush=True)
                        self.receiving_files = {}

        except Exception as e:
            if self.is_running:
                print(f"\n[!] Lỗi kênh nhận: {e}")

    def send_chat(self, text: str):
        """Mã hóa tin nhắn bằng AES-256-GCM với Nonce ngẫu nhiên và gửi đi."""
        nonce, ciphertext = CryptoCore.aes_gcm_encrypt(self.session_key, text.encode("utf-8"))
        send_json(self.sock, {
            "type": "CHAT",
            "nonce": base64.b64encode(nonce).decode("utf-8"),
            "data": base64.b64encode(ciphertext).decode("utf-8"),
        })

    def send_file(self, filepath: str):
        """Cắt nhỏ tập tin thành các Chunk 64KB, mã hóa AES-GCM từng khối và gửi."""
        if not os.path.exists(filepath):
            print(f"[X] Đường dẫn tệp không tồn tại: {filepath}")
            return

        filename = os.path.basename(filepath)
        filesize = os.path.getsize(filepath)
        file_hash = CryptoCore.calculate_file_hash(filepath)

        print(f"[*] Bắt đầu gửi file '{filename}' ({filesize} bytes)...")
        print(f"[*] SHA-256 gốc của file: {file_hash}")

        # 1. Gửi gói metadata mã hóa
        meta_str = f"{filename}|{filesize}|{file_hash}"
        nonce_m, ct_m = CryptoCore.aes_gcm_encrypt(self.session_key, meta_str.encode("utf-8"))
        send_json(self.sock, {
            "type": "FILE_META",
            "nonce": base64.b64encode(nonce_m).decode("utf-8"),
            "data": base64.b64encode(ct_m).decode("utf-8"),
        })

        # 2. Cắt chunk và gửi tuần tự
        sent_bytes = 0
        with open(filepath, "rb") as f:
            while chunk := f.read(CHUNK_SIZE):
                n, ct = CryptoCore.aes_gcm_encrypt(self.session_key, chunk)
                send_json(self.sock, {
                    "type": "FILE_CHUNK",
                    "nonce": base64.b64encode(n).decode("utf-8"),
                    "data": base64.b64encode(ct).decode("utf-8"),
                })
                sent_bytes += len(chunk)
                progress = (sent_bytes / filesize) * 100
                print(f"\r[*] Tiến độ gửi: {progress:.1f}% ({sent_bytes}/{filesize} bytes)", end="")

        # 3. Gửi tín hiệu hoàn tất
        send_json(self.sock, {"type": "FILE_END"})
        print(f"\n[✓] Đã gửi hoàn tất tập tin '{filename}'.")

    def interactive_menu(self):
        """Menu tương tác qua dòng lệnh."""
        while self.is_running:
            try:
                cmd = input("\n[1] Gửi tin nhắn Chat | [2] Gửi tập tin | [3] Thoát\n> ").strip()
                if cmd == "1":
                    text = input("Nhập nội dung tin nhắn: ")
                    if text:
                        self.send_chat(text)
                elif cmd == "2":
                    fpath = input("Nhập đường dẫn tập tin cần gửi: ").strip('"').strip("'")
                    self.send_file(fpath)
                elif cmd == "3":
                    self.is_running = False
                    self.sock.close()
                    print("[*] Đã đóng kết nối.")
                    break
            except (KeyboardInterrupt, EOFError):
                self.is_running = False
                self.sock.close()
                break


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else SERVER_IP
    port = int(sys.argv[2]) if len(sys.argv) > 2 else SERVER_PORT
    client = E2EEClient(host, port)
    client.start()
