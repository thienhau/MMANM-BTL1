"""
Kịch bản kiểm thử: Thành viên 3 - Mã hóa Dữ liệu (AES-GCM) & Truyền Tệp Cắt Khối
Nội dung:
- Kiểm thử tính ngẫu nhiên (Semantic Security) của AES-256-GCM qua Nonce 96-bit khác nhau.
- Thử nghiệm cắt khối (Chunking 64KB) và tái tạo tập tin nhị phân.
- Đối soát mã băm SHA-256 trước và sau truyền tệp đảm bảo tính toàn vẹn tuyệt đối.
"""
import os
import sys

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from crypto_core import CryptoCore


def run_member3_tests():
    print("=" * 65)
    print("TEST THÀNH VIÊN 3: MÃ HÓA AES-256-GCM & TRUYỀN TẬP TIN CẮT KHỐI (CHUNKING)")
    print("=" * 65)

    session_key = CryptoCore.generate_aes_key()
    message = "Báo cáo Mật mã & An ninh mạng Đề tài 1.1 - Nhóm sinh viên Bách Khoa".encode("utf-8")

    # 1. Kiểm tra Semantic Security của AES-GCM
    print(f"[*] Mã hóa cùng 1 thông điệp 2 lần liên tiếp:")
    nonce1, ct1 = CryptoCore.aes_gcm_encrypt(session_key, message)
    nonce2, ct2 = CryptoCore.aes_gcm_encrypt(session_key, message)

    print(f"  Lần 1 -> Nonce: {nonce1.hex()} | Ciphertext: {ct1[:20].hex()}...")
    print(f"  Lần 2 -> Nonce: {nonce2.hex()} | Ciphertext: {ct2[:20].hex()}...")

    assert nonce1 != nonce2, "LỖI: Nonce bị lặp lại!"
    assert ct1 != ct2, "LỖI: Bản mã bị trùng lặp!"
    print("[✓] Nonce độc nhất ngẫu nhiên, Ciphertext biến đổi hoàn toàn (Semantic Security đạt chuẩn).")

    # 2. Giải mã và phục hồi dữ liệu gốc
    pt1 = CryptoCore.aes_gcm_decrypt(session_key, nonce1, ct1)
    assert pt1 == message
    print(f"[✓] Giải mã thành công dữ liệu gốc: '{pt1.decode('utf-8')}'")

    # 3. Kiểm thử truyền tập tin nhị phân lớn bằng Chunking
    test_src = "test_source_file.bin"
    test_dst = "test_reconstructed_file.bin"
    chunk_size = 64 * 1024  # 64 KB
    total_size = 200 * 1024  # 200 KB (> 3 chunks)

    # Tạo tệp tin nhị phân mẫu ngẫu nhiên
    with open(test_src, "wb") as f:
        f.write(os.urandom(total_size))

    original_hash = CryptoCore.calculate_file_hash(test_src)
    print(f"\n[*] Tạo tệp thử nghiệm dung lượng: {total_size} bytes (3 chunks 64KB)")
    print(f"[*] Checksum SHA-256 gốc của tệp: {original_hash}")

    # Cắt khối, mã hóa từng khối và ghi vào file đích
    encrypted_chunks = []
    with open(test_src, "rb") as f:
        while chunk := f.read(chunk_size):
            n, ct = CryptoCore.aes_gcm_encrypt(session_key, chunk)
            encrypted_chunks.append((n, ct))

    print(f"[*] Đã cắt và mã hóa thành công {len(encrypted_chunks)} chunks.")

    with open(test_dst, "wb") as f:
        for n, ct in encrypted_chunks:
            decrypted_chunk = CryptoCore.aes_gcm_decrypt(session_key, n, ct)
            f.write(decrypted_chunk)

    reconstructed_hash = CryptoCore.calculate_file_hash(test_dst)
    print(f"[*] Checksum SHA-256 của tệp tái tạo: {reconstructed_hash}")

    assert original_hash == reconstructed_hash, "LỖI: Checksum không khớp!"
    print("[✓] Toàn vẹn tập tin sau khi cắt khối và giải mã khớp 100%!")

    # Dọn dẹp tệp thử nghiệm
    if os.path.exists(test_src):
        os.remove(test_src)
    if os.path.exists(test_dst):
        os.remove(test_dst)

    print("\n[✓] THÀNH CÔNG: Mô-đun truyền nhận dữ liệu và tập tin hoạt động hoàn hảo!")


if __name__ == "__main__":
    run_member3_tests()
