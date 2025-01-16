#!/usr/bin/env python3
import socket
import socks
from flask import Flask, request, render_template_string

app = Flask(__name__)

# HTML template nhỏ gọn viết trực tiếp trong code:
HTML_TEMPLATE = """
<!doctype html>
<html>
<head>
    <title>Echo Client via SOCKS5 Proxy</title>
</head>
<body>
    <h1>Echo Client with SOCKS5 Proxy</h1>
    <form method="POST">
        <label>Proxy Host:</label>
        <input type="text" name="proxy_host" value="{{ proxy_host }}"><br><br>

        <label>Proxy Port:</label>
        <input type="text" name="proxy_port" value="{{ proxy_port }}"><br><br>

        <label>Server Host:</label>
        <input type="text" name="server_host" value="{{ server_host }}"><br><br>

        <label>Server Port:</label>
        <input type="text" name="server_port" value="{{ server_port }}"><br><br>

        <label>Protocol (TCP/UDP):</label>
        <select name="proto">
            <option value="TCP" {% if proto == "TCP" %}selected{% endif %}>TCP</option>
            <option value="UDP" {% if proto == "UDP" %}selected{% endif %}>UDP</option>
        </select>
        <br><br>

        <label>Message:</label>
        <input type="text" name="msg" value="{{ msg }}"><br><br>

        <input type="submit" value="Send">
    </form>

    {% if result %}
    <hr>
    <h2>Result:</h2>
    <pre>{{ result }}</pre>
    {% endif %}
</body>
</html>
"""


def send_tcp_over_socks5(proxy_host, proxy_port, server_host, server_port, msg):
    """
    Kết nối TCP tới echo server qua SOCKS5 proxy, gửi 'msg' và nhận echo trả về.
    Trả về chuỗi kết quả.
    """
    s = socks.socksocket()
    s.set_proxy(socks.SOCKS5, proxy_host, int(proxy_port))
    try:
        s.connect((server_host, int(server_port)))
        s.sendall(msg.encode('utf-8'))
        data = s.recv(1024)
        return f"Sent: {msg}\nReceived: {data.decode('utf-8', errors='replace')}"
    except Exception as e:
        return f"TCP Error: {str(e)}"
    finally:
        s.close()


def send_udp_over_socks5(proxy_host, proxy_port, server_host, server_port, msg):
    """
    Gửi/nhận gói UDP tới echo server qua SOCKS5 proxy (UDP_ASSOCIATE).
    Trả về chuỗi kết quả.
    """
    s = socks.socksocket(socket.AF_INET, socket.SOCK_DGRAM)
    s.set_proxy(socks.SOCKS5, proxy_host, int(proxy_port), rdns=False)
    s.settimeout(3.0)  # timeout 3s để tránh treo
    try:
        s.sendto(msg.encode('utf-8'), (server_host, int(server_port)))
        data, addr = s.recvfrom(1024)
        return f"Sent: {msg}\nReceived from {addr}: {data.decode('utf-8', errors='replace')}"
    except socket.timeout:
        return "UDP Error: Timeout, no response."
    except Exception as e:
        return f"UDP Error: {str(e)}"
    finally:
        s.close()


@app.route("/", methods=["GET", "POST"])
def index():
    # Giá trị mặc định cho form
    default_data = {
        "proxy_host": "127.0.0.1",
        "proxy_port": "1080",
        "server_host": "127.0.0.1",
        "server_port": "9000",
        "msg": "hello",
        "proto": "TCP",
        "result": None
    }

    if request.method == "POST":
        # Lấy dữ liệu từ form
        proxy_host = request.form.get("proxy_host", "127.0.0.1")
        proxy_port = request.form.get("proxy_port", "1080")
        server_host = request.form.get("server_host", "127.0.0.1")
        server_port = request.form.get("server_port", "9000")
        msg = request.form.get("msg", "hello")
        proto = request.form.get("proto", "TCP")

        # Gọi hàm gửi theo TCP / UDP
        if proto == "TCP":
            result = send_tcp_over_socks5(proxy_host, proxy_port, server_host, server_port, msg)
        else:
            result = send_udp_over_socks5(proxy_host, proxy_port, server_host, server_port, msg)

        # Cập nhật form và kết quả
        default_data.update({
            "proxy_host": proxy_host,
            "proxy_port": proxy_port,
            "server_host": server_host,
            "server_port": server_port,
            "msg": msg,
            "proto": proto,
            "result": result
        })

    return render_template_string(HTML_TEMPLATE, **default_data)


if __name__ == "__main__":
    # Chạy Flask
    # Truy cập: http://127.0.0.1:6125
    app.run(debug=True, port=6125)