"""
Proxy Giả Lập Tấn Công Nghe Lén và Can Thiệp (MitM Proxy)
Mục đích:
- Đóng vai trò Man-in-the-Middle (MitM) đứng giữa Client và Server.
- Lắng nghe trên cổng 8888, kết nối tới Server thật trên cổng 9999.
- Thực hiện kịch bản tấn công Tampering: Can thiệp sửa đổi 1 byte trong Ciphertext
  của tin nhắn CHAT để kiểm chứng khả năng phát hiện của AES-GCM (InvalidTag) và HMAC.
"""
import base64
import json
import socket
import sys
import threading

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from protocol import recv_frame, send_frame

LISTEN_PORT = 8888
REAL_SERVER_PORT = 9999


def handle_tamper(src_sock: socket.socket, dst_sock: socket.socket, is_tampering_active: bool = True):
    """Bắt và sửa đổi payload nếu cờ `is_tampering_active` bật."""
    while True:
        try:
            frame = recv_frame(src_sock)
            if not frame:
                break

            if is_tampering_active:
                try:
                    data = json.loads(frame.decode("utf-8"))
                    if data.get("type") == "CHAT":
                        print("\n" + "!" * 60)
                        print("[MITM ATTACK] Bắt được gói tin CHAT trên đường truyền!")
                        raw_ct = bytearray(base64.b64decode(data["data"]))
                        original_byte = raw_ct[0]
                        raw_ct[0] ^= 0xFF  # Đảo bit đầu tiên
                        print(f"[*] Can thiệp Bit-flipping byte [0]: 0x{original_byte:02x} -> 0x{raw_ct[0]:02x}")
                        data["data"] = base64.b64encode(bytes(raw_ct)).decode("utf-8")
                        frame = json.dumps(data).encode("utf-8")
                        print("[*] Đã tiêm payload độc hại vào đường truyền forward tới nạn nhân.")
                        print("!" * 60 + "\n")
                except Exception:
                    pass

            send_frame(dst_sock, frame)
        except Exception:
            break


def main():
    proxy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    proxy.bind(("0.0.0.0", LISTEN_PORT))
    proxy.listen(2)
    print("=" * 60)
    print(f"[*] MITM PROXY ATTACKER ĐANG LẮNG NGHE TẠI CỔNG {LISTEN_PORT}")
    print(f"[*] Chuyển tiếp tới Relay Server thật tại 127.0.0.1:{REAL_SERVER_PORT}")
    print("=" * 60)

    while True:
        client_sock, addr = proxy.accept()
        print(f"[+] Nạn nhân kết nối vào cổng Proxy: {addr}")
        try:
            real_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            real_server.connect(("127.0.0.1", REAL_SERVER_PORT))
        except Exception as e:
            print(f"[X] Không thể kết nối tới Server thật: {e}")
            client_sock.close()
            continue

        # Luồng 1: Client -> Server (Giữ nguyên hoặc can thiệp)
        threading.Thread(target=handle_tamper, args=(client_sock, real_server, False), daemon=True).start()
        # Luồng 2: Server -> Client (Can thiệp sửa đổi gói tin)
        threading.Thread(target=handle_tamper, args=(real_server, client_sock, True), daemon=True).start()


if __name__ == "__main__":
    main()
