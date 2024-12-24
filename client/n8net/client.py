import os

# gcc -shared -o socket_socks5.so -fPIC socket_socks5.c
# socks5_lib = ctypes.CDLL('./socket_socks5.so')

_PROXY_SERVER = os.getenv("N8_SERVER")


class _N8Socket:
    def __init__(self):
        pass

    def connect(self):
        pass

    def listen(self):
        pass

    def close(self):
        pass

    def send(self, data):
        pass

    def recv(self):
        pass



class N8Client:
    def __init__(self, username: str, password: str):
        socket = _N8Socket()
        is_authenticated = self.auth(username, password)


    @staticmethod
    def auth(username: str, password: str):
        return True