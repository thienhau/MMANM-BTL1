"""
Mô-đun Mật mã Lõi (Crypto Core Module)
Hiện thực các tiêu chuẩn mật mã học công nghiệp:
- KDF từ danh sách MSSV nhóm: Key = SHA256(MSSV_1 || MSSV_2 || MSSV_3 || MSSV_4)
- Xác thực toàn vẹn & Nguồn gốc: HMAC-SHA256 (RFC 2104)
- Trao đổi khóa bất đối xứng: RSA-OAEP 2048-bit (RFC 8017)
- Chữ ký số chống giả mạo: RSA-PSS với SHA-256 (RFC 8017)
- Mã hóa đối xứng luồng dữ liệu & tệp tin: AES-256-GCM (RFC 5116)
"""
import hashlib
import hmac
import os
from typing import List, Tuple
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Danh sách MSSV chính thức của nhóm
OFFICIAL_GROUP_MSSV = ["2213444", "2310930", "2311523", "2333464"]


class CryptoCore:
    @staticmethod
    def derive_kdf_from_mssv(mssv_list: List[str] = None) -> bytes:
        """
        Dẫn xuất khóa bí mật khởi tạo (KDF) từ MSSV theo yêu cầu đề bài:
        Key = SHA256(MSSV_1 || MSSV_2 || ...)
        """
        if mssv_list is None:
            mssv_list = OFFICIAL_GROUP_MSSV
        combined = "".join(mssv_list).encode("utf-8")
        return hashlib.sha256(combined).digest()

    @staticmethod
    def compute_hmac(key: bytes, message: bytes) -> bytes:
        """Tính mã xác thực HMAC-SHA256 (RFC 2104)."""
        return hmac.new(key, message, hashlib.sha256).digest()

    @staticmethod
    def verify_hmac(key: bytes, message: bytes, expected_hmac: bytes) -> bool:
        """Kiểm tra HMAC chống tấn công Timing Attack bằng so sánh hằng thời gian."""
        mac = hmac.new(key, message, hashlib.sha256).digest()
        return hmac.compare_digest(mac, expected_hmac)

    @staticmethod
    def generate_rsa_keypair() -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """Tạo cặp khóa RSA 2048-bit với số mũ công khai e = 65537."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def export_public_key_pem(public_key: rsa.RSAPublicKey) -> str:
        """Xuất khóa công khai sang định dạng chuỗi PEM (SubjectPublicKeyInfo)."""
        pem_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return pem_bytes.decode("utf-8")

    @staticmethod
    def load_public_key_pem(pem_str: str) -> rsa.RSAPublicKey:
        """Đọc và nạp khóa công khai từ chuỗi định dạng PEM."""
        return serialization.load_pem_public_key(pem_str.encode("utf-8"))

    @staticmethod
    def rsa_encrypt(public_key: rsa.RSAPublicKey, plaintext: bytes) -> bytes:
        """
        Mã hóa bất đối xứng Session Key bằng RSA-OAEP với MGF1(SHA-256).
        Khắc phục hoàn toàn các điểm yếu của PKCS#1 v1.5.
        """
        return public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    @staticmethod
    def rsa_decrypt(private_key: rsa.RSAPrivateKey, ciphertext: bytes) -> bytes:
        """Giải mã khóa bí mật RSA-OAEP bằng Private Key."""
        return private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    @staticmethod
    def rsa_sign(private_key: rsa.RSAPrivateKey, data: bytes) -> bytes:
        """Tạo chữ ký số RSA-PSS với cơ chế muối cực đại (MAX_LENGTH)."""
        return private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

    @staticmethod
    def rsa_verify(public_key: rsa.RSAPublicKey, signature: bytes, data: bytes) -> bool:
        """Xác thực chữ ký số RSA-PSS."""
        try:
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return True
        except Exception:
            return False

    @staticmethod
    def generate_aes_key() -> bytes:
        """Sinh ngẫu nhiên khóa phiên AES-256 (32 bytes = 256 bits an toàn cao)."""
        return AESGCM.generate_key(bit_length=256)

    @staticmethod
    def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = None) -> Tuple[bytes, bytes]:
        """
        Mã hóa xác thực AEAD AES-256-GCM.
        Nonce 12 bytes ngẫu nhiên chuẩn NIST SP 800-38D.
        Trả về: (nonce, ciphertext_kem_auth_tag_16_bytes)
        """
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext_and_tag = aesgcm.encrypt(nonce, plaintext, aad)
        return nonce, ciphertext_and_tag

    @staticmethod
    def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext_and_tag: bytes, aad: bytes = None) -> bytes:
        """
        Giải mã và kiểm tra tính toàn vẹn (Authentication Tag) của AES-GCM.
        Tự động ném ngoại lệ InvalidTag nếu dữ liệu bị kẻ tấn công sửa đổi dù chỉ 1 bit.
        """
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext_and_tag, aad)

    @staticmethod
    def calculate_file_hash(filepath: str) -> str:
        """Tính mã băm SHA-256 của tập tin để đối soát toàn vẹn đầu cuối."""
        hasher = hashlib.sha256()
        with open(filepath, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()

