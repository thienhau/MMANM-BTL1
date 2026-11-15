"""
Kịch bản kiểm thử: Thành viên 1 - Hạ tầng Mạng & Framing Protocol
Nội dung:
- Kiểm thử cơ chế đóng gói tiền tố độ dài 4-byte (Length-prefixed framing).
- Chứng minh khắc phục hiện tượng dính gói (Sticky Packets) khi truyền nhiều thông điệp liên tiếp.
- Đảm bảo đầu nhận phân tách chính xác 100% dữ liệu gốc.
"""
import socket
import sys

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from protocol import recv_frame, send_frame


def run_member1_tests():
    print("=" * 65)
    print("TEST THÀNH VIÊN 1: HẠ TẦNG MẠNG & PHÂN TÁCH KHUNG DỮ LIỆU (FRAMING)")
    print("=" * 65)

    s1, s2 = socket.socketpair()

    messages = [
        b"Goi_1: Bat tay Handshake",
        b"Goi_2: Session Key Exchange rat dai voi nhieu byte RSA ciphertext " * 3,
        b"Goi_3: Tin nhan ngan",
        b"Goi_4: Chunk du lieu tep tin nhi phan",
    ]

    print(f"[*] Bắn liên tiếp {len(messages)} gói tin vào socket qua cơ chế Framing...")
    for idx, msg in enumerate(messages, 1):
        send_frame(s1, msg)
        print(f"  -> Gửi gói {idx} (Độ dài {len(msg)} bytes): {msg[:35]}...")

    print("\n[*] Đầu nhận giải phóng buffer và phân tách từng frame:")
    received = []
    for idx in range(len(messages)):
        frame = recv_frame(s2)
        received.append(frame)
        print(f"  <- Nhận gói {idx+1} (Độ dài {len(frame)} bytes): {frame[:35]}...")

    assert received == messages, "LỖI: Dữ liệu nhận không khớp với dữ liệu gửi!"
    print("\n[✓] THÀNH CÔNG: Cơ chế Framing chống dính gói (Anti-Sticky Packets) hoạt động hoàn hảo 100%! ")
    s1.close()
    s2.close()


if __name__ == "__main__":
    run_member1_tests()
