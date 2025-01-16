import socket
import threading

TCP_PORT = 9000
UDP_PORT = 9000


def tcp_server():
    """TCP Echo Server: lắng nghe, khi client gửi chuỗi thì gửi lại (echo)."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(('0.0.0.0', TCP_PORT))
    srv.listen(5)
    print(f"TCP Echo Server listening on 0.0.0.0:{TCP_PORT}")

    while True:
        client_sock, addr = srv.accept()
        print(f"[TCP] Got connection from {addr}")
        threading.Thread(target=tcp_handle_client, args=(client_sock, addr)).start()


def tcp_handle_client(client_sock, addr):
    with client_sock:
        while True:
            data = client_sock.recv(1024)
            if not data:
                break
            print(f"[TCP] Received from {addr}: {data}")
            # Echo back
            client_sock.sendall(data)
    print(f"[TCP] Client {addr} disconnected")


def udp_server():
    """UDP Echo Server: lắng nghe, khi client gửi gói thì gửi lại (echo)."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(('0.0.0.0', UDP_PORT))
    print(f"UDP Echo Server listening on 0.0.0.0:{UDP_PORT}")

    while True:
        data, client_addr = srv.recvfrom(2048)
        print(f"[UDP] Received from {client_addr}: {data}")
        # Echo back
        srv.sendto(data, client_addr)


def main():
    # Chạy server TCP và UDP song song
    t_tcp = threading.Thread(target=tcp_server, daemon=True)
    t_tcp.start()

    t_udp = threading.Thread(target=udp_server, daemon=True)
    t_udp.start()

    print("Echo Server is running (TCP & UDP)... Press Ctrl+C to stop.")
    t_tcp.join()  # chờ thread TCP
    t_udp.join()  # chờ thread UDP


if __name__ == "__main__":
    main()
