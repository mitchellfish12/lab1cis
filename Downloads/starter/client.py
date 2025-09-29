import socket
import hashlib
from aes import AES
from key import Key

class Client:
    def __init__(self, addr, port=14167, buffer_size=1024):
        self.addr = addr
        self.port = port
        self.buffer_size = buffer_size

        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((self.addr, self.port))

    def send(self, msg_bytes: bytes):
        self.s.send(msg_bytes)

    def recv(self, buffer_size=None) -> bytes:
        if buffer_size is None:
            buffer_size = self.buffer_size
        msg_bytes = self.s.recv(self.buffer_size)

        return msg_bytes

    def close(self):
        self.s.close()


if __name__ == '__main__':
    client = Client('localhost', 14167)
    while True:
        msg = input('> ')
        client.send(msg.encode())
        if msg == 'exit':
            break
        msg = client.recv(1024).decode()
        if not msg or msg == 'exit':
            print('Server terminated chat')
            break
        print('Response from server:', msg)

        # TODO: your code here
    client.close()
