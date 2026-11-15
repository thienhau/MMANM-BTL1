"""
Giao thức đóng khung dữ liệu (Framing Protocol) qua TCP Socket
Giải quyết triệt để vấn đề phân mảnh (Fragmentation) và dính gói (Sticky Packets).
Mỗi frame gồm: [4 bytes Length (Big-Endian)] + [Payload Data]
"""
import json
import socket


def send_frame(sock: socket.socket, payload: bytes):
    """Gửi một khung dữ liệu kèm tiền tố 4 byte độ dài."""
    length_prefix = len(payload).to_bytes(4, byteorder="big")
    sock.sendall(length_prefix + payload)


def recv_exact(sock: socket.socket, length: int) -> bytes:
    """Nhận chính xác `length` bytes từ socket, tránh nhận thiếu byte."""
    buf = bytearray()
    while len(buf) < length:
        chunk = sock.recv(length - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


def recv_frame(sock: socket.socket) -> bytes:
    """Đọc 4 byte độ dài rồi đọc trọn vẹn payload của frame."""
    length_bytes = recv_exact(sock, 4)
    if not length_bytes:
        return None
    length = int.from_bytes(length_bytes, byteorder="big")
    return recv_exact(sock, length)


def send_json(sock: socket.socket, data: dict):
    """Tuần tự hóa dict thành JSON UTF-8 và gửi qua framing."""
    payload = json.dumps(data).encode("utf-8")
    send_frame(sock, payload)


def recv_json(sock: socket.socket) -> dict:
    """Nhận trọn vẹn frame và giải tuần tự hóa thành dict JSON."""
    payload = recv_frame(sock)
    if payload is None:
        return None
    return json.loads(payload.decode("utf-8"))

