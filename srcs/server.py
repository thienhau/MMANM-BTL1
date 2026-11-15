"""
Máy chủ Chuyển tiếp (Relay Server E2EE)
Nhiệm vụ:
- Lắng nghe và chấp nhận 2 Client kết nối (Alice & Bob).
- Phân định vai trò: Client 1 là 'initiator' (khởi tạo), Client 2 là 'receiver' (nhận).
- Đóng vai trò Relay (chuyển tiếp mù): Forward các frame dữ liệu giữa 2 bên.
- Server HOÀN TOÀN KHÔNG GIẢI MÃ ĐƯỢC NỘI DUNG (True End-to-End Encryption).
"""
import socket
import sys
import threading

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from protocol import recv_frame, send_frame, send_json

HOST = "0.0.0.0"
PORT = 9999
clients = []


def relay_worker(source_sock: socket.socket, target_sock: socket.socket, client_id: int):
    """Luồng chuyển tiếp frame hai chiều giữa Alice và Bob."""
    try:
        while True:
            frame = recv_frame(source_sock)
            if frame is None:
                print(f"[-] Client {client_id} đã ngắt kết nối.")
                break
            send_frame(target_sock, frame)
    except Exception as e:
        print(f"[!] Lỗi chuyển tiếp từ Client {client_id}: {e}")
    finally:
        try:
            source_sock.close()
        except Exception:
            pass
        try:
            target_sock.close()
        except Exception:
            pass


def main():
    global clients
    clients = []
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(2)
    print("=" * 60)
    print(f"[*] RELAY SERVER E2EE ĐANG LẮNG NGHE TẠI {HOST}:{PORT}")
    print("[*] Đang chờ 2 Client kết nối...")
    print("=" * 60)

    while len(clients) < 2:
        sock, addr = server.accept()
        cid = len(clients) + 1
        print(f"[+] Client {cid} kết nối thành công từ {addr}")
        clients.append(sock)

    print("\n[*] Đã đủ 2 Client. Tiến hành kích hoạt phiên E2EE...")
    # Client 1 khởi tạo bắt tay, Client 2 chờ nhận bắt tay
    send_json(clients[0], {"type": "INIT_START", "role": "initiator"})
    send_json(clients[1], {"type": "INIT_START", "role": "receiver"})

    t1 = threading.Thread(target=relay_worker, args=(clients[0], clients[1], 1), daemon=True)
    t2 = threading.Thread(target=relay_worker, args=(clients[1], clients[0], 2), daemon=True)
    t1.start()
    t2.start()

    print("[*] Luồng chuyển tiếp (Relay) đang hoạt động. Server chỉ forward ciphertext.")
    t1.join()
    t2.join()
    print("[*] Phiên kết thúc. Server đóng kết nối.")
    server.close()


if __name__ == "__main__":
    main()
