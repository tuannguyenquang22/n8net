import socket
import struct

# SOCKS5 Constants
SOCKS5_VERSION = 0x05
AUTH_METHOD_USERNAME_PASSWORD = 0x02
AUTH_SUCCESS = 0x00
CMD_CONNECT = 0x01
ATYP_IPV4 = 0x01

def test_socks5_proxy(proxy_host, proxy_port, username, password, target_host, target_port):
    try:
        # Kết nối tới proxy server
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((proxy_host, proxy_port))
        print(f"Connected to proxy server at {proxy_host}:{proxy_port}")

        # Gửi yêu cầu handshake
        handshake = struct.pack("!BBB", SOCKS5_VERSION, 1, AUTH_METHOD_USERNAME_PASSWORD)
        client.sendall(handshake)
        response = client.recv(2)

        if response[0] != SOCKS5_VERSION or response[1] != AUTH_METHOD_USERNAME_PASSWORD:
            print("Handshake failed or method not supported")
            return

        print("Handshake successful, proceeding with authentication")

        # Gửi thông tin xác thực username/password
        username_len = len(username)
        password_len = len(password)
        auth_request = struct.pack(f"!BB{username_len}sB{password_len}s", 0x01, username_len, username.encode(), password_len, password.encode())
        client.sendall(auth_request)

        auth_response = client.recv(2)
        if auth_response[1] != AUTH_SUCCESS:
            print("Authentication failed")
            return

        print("Authentication successful, sending connect request")

        # Gửi yêu cầu CMD_CONNECT
        target_ip = socket.gethostbyname(target_host)
        target_port = struct.pack("!H", target_port)
        connect_request = struct.pack(f"!BBBB4s2s", SOCKS5_VERSION, CMD_CONNECT, 0x00, ATYP_IPV4, socket.inet_aton(target_ip), target_port)
        client.sendall(connect_request)

        connect_response = client.recv(10)
        if connect_response[1] != 0x00:
            print("Connection to target failed")
            return

        print(f"Successfully connected to {target_host}:{target_port} through proxy")

        client.sendall(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        data = client.recv(1024)
        print("Received data from target server:")
        print(data.decode('utf-8', errors='ignore'))

    except Exception as e:
        print(f"Error: {e}")
    finally:
        client.close()

proxy_host = "127.0.0.1"
proxy_port = 5000
username = "username1"
password = "password1"
target_host = "example.com"
target_port = 80

test_socks5_proxy(proxy_host, proxy_port, username, password, target_host, target_port)
