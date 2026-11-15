"""
Kịch bản kiểm thử: Thành viên 4 - Kiểm định An toàn & Kháng Tấn công Nghe lén / MitM
Nội dung:
- Phân tích Hex Dump trên đường truyền mạng: Chứng minh chống nghe lén (Eavesdropping).
- Mô phỏng tấn công MitM Bit-flipping: Đảo 1 bit bất kỳ trong Ciphertext.
- Chứng minh AES-GCM tự động phát hiện giả mạo và ném ngoại lệ InvalidTag (chống Tampering).
"""
import base64
import json
import sys

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from crypto_core import CryptoCore


def run_member4_tests():
    print("=" * 65)
    print("TEST THÀNH VIÊN 4: ĐÁNH GIÁ AN TOÀN TRƯỚC NGHE LÉN & TẤN CÔNG MITM")
    print("=" * 65)

    session_key = CryptoCore.generate_aes_key()
    secret_text = "THÔNG TIN MẬT QUÂN SỰ / TÀI KHOẢN NGÂN HÀNG: 999999999"
    nonce, ct = CryptoCore.aes_gcm_encrypt(session_key, secret_text.encode("utf-8"))

    # 1. Kiểm tra an toàn trước tấn công Nghe lén (Eavesdropping)
    packet_payload = json.dumps({
        "type": "CHAT",
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "data": base64.b64encode(ct).decode("utf-8"),
    }).encode("utf-8")

    print("[*] Gói tin tuần tự hóa truyền trên dây cáp mạng:")
    hex_repr = " ".join(f"{b:02x}" for b in packet_payload[:40]) + " ..."
    print(f"  Hex Dump: {hex_repr}")

    assert secret_text.encode("utf-8") not in packet_payload
    print("[✓] CHỐNG NGHE LÉN: Chuỗi tin nhắn gốc hoàn toàn không xuất hiện trên đường truyền!")

    # 2. Thử nghiệm tấn công Man-in-the-Middle (MitM) Tampering
    print("\n[*] Giả lập kẻ tấn công MitM chặn gói tin và đảo 1 bit trong Ciphertext...")
    tampered_ct = bytearray(ct)
    tampered_ct[0] ^= 0x01  # Bit-flipping đúng 1 bit

    print(f"  Byte gốc: 0x{ct[0]:02x} -> Byte bị sửa đổi: 0x{tampered_ct[0]:02x}")

    # Đầu nhận tiến hành giải mã với ciphertext đã bị can thiệp
    attack_detected = False
    try:
        CryptoCore.aes_gcm_decrypt(session_key, nonce, bytes(tampered_ct))
    except Exception as e:
        attack_detected = True
        print(f"[✓] PHÁT HIỆN TẤN CÔNG THÀNH CÔNG: Ngoại lệ '{type(e).__name__}' được kích hoạt!")
        print(f"  Chi tiết: Đầu nhận từ chối dữ liệu rác/giả mạo của kẻ tấn công.")

    assert attack_detected, "LỖI: Hệ thống không phát hiện ra gói tin đã bị sửa đổi!"
    print("\n[✓] THÀNH CÔNG: Hệ thống kháng 100% tấn công can thiệp dữ liệu MitM!")


if __name__ == "__main__":
    run_member4_tests()
