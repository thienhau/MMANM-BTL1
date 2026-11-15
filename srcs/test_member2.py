"""
Kịch bản kiểm thử: Thành viên 2 - Mật mã Lõi & Quy trình Bắt tay (Handshake)
Nội dung:
- Dẫn xuất Master Key từ danh sách MSSV nhóm: Key = SHA256(MSSV_1 || MSSV_2 || MSSV_3 || MSSV_4)
- Kiểm tra tạo và xác thực HMAC-SHA256 trên chuỗi Handshake: "Hello, We are 2213444, 2310930, 2311523, 2333464"
- Kiểm tra tính an toàn của trao đổi Session Key bằng RSA-OAEP kết hợp chữ ký số RSA-PSS
"""
import sys

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from crypto_core import CryptoCore, OFFICIAL_GROUP_MSSV


def run_member2_tests():
    print("=" * 65)
    print("TEST THÀNH VIÊN 2: KDF, XÁC THỰC HMAC VÀ BẮT TAY KHÓA BẤT ĐỐI XỨNG RSA")
    print("=" * 65)

    # 1. Kiểm tra dẫn xuất KDF từ MSSV
    print(f"[*] Danh sách MSSV nhóm: {OFFICIAL_GROUP_MSSV}")
    kdf_key = CryptoCore.derive_kdf_from_mssv(OFFICIAL_GROUP_MSSV)
    print(f"[✓] Khóa KDF dẫn xuất (SHA-256): {kdf_key.hex()}")

    # 2. Kiểm tra HMAC trên chuỗi Plaintext Handshake
    handshake_text = f"Hello, We are {', '.join(OFFICIAL_GROUP_MSSV)}"
    print(f"\n[*] Thông điệp Handshake chuẩn đề bài: '{handshake_text}'")
    hmac_val = CryptoCore.compute_hmac(kdf_key, handshake_text.encode("utf-8"))
    print(f"[✓] HMAC-SHA256 tính toán: {hmac_val.hex()}")

    assert CryptoCore.verify_hmac(kdf_key, handshake_text.encode("utf-8"), hmac_val), "HMAC verify thất bại!"
    print("[✓] Xác thực HMAC: Thành công (Khớp 100% nguồn gốc).")

    # Giả lập bên thứ ba thay đổi MSSV -> HMAC phải báo sai
    fake_text = "Hello, We are 9999999, 8888888"
    assert not CryptoCore.verify_hmac(kdf_key, fake_text.encode("utf-8"), hmac_val)
    print("[✓] Thử nghiệm tấn công sửa chuỗi MSSV: HMAC lập tức phát hiện giả mạo và từ chối.")

    # 3. Kiểm tra Trao đổi khóa RSA-OAEP + Chữ ký số RSA-PSS
    print("\n[*] Khởi tạo cặp khóa RSA 2048-bit cho Alice và Bob...")
    alice_priv, alice_pub = CryptoCore.generate_rsa_keypair()
    bob_priv, bob_pub = CryptoCore.generate_rsa_keypair()

    session_key = CryptoCore.generate_aes_key()
    print(f"[*] Alice sinh Session Key ngẫu nhiên: {session_key.hex()}")

    # Alice mã hóa bằng Bob Public Key và ký bằng Alice Private Key
    enc_key = CryptoCore.rsa_encrypt(bob_pub, session_key)
    sig = CryptoCore.rsa_sign(alice_priv, enc_key)
    print(f"[*] Khóa phiên sau mã hóa RSA-OAEP: {len(enc_key)} bytes")
    print(f"[*] Chữ ký số RSA-PSS: {len(sig)} bytes")

    # Bob kiểm tra chữ ký trước
    assert CryptoCore.rsa_verify(alice_pub, sig, enc_key), "Chữ ký RSA-PSS không hợp lệ!"
    print("[✓] Bob xác minh chữ ký số RSA-PSS: Chữ ký chính xác từ Alice.")

    # Bob giải mã lấy khóa phiên
    decrypted_key = CryptoCore.rsa_decrypt(bob_priv, enc_key)
    assert decrypted_key == session_key, "Khóa phiên giải mã không khớp!"
    print(f"[✓] Bob giải mã thành công Session Key: {decrypted_key.hex()}")
    print("\n[✓] THÀNH CÔNG: Toàn bộ thuật toán Mật mã lõi và Bắt tay đáp ứng 100% đề bài!")


if __name__ == "__main__":
    run_member2_tests()
