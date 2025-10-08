import socket
import hashlib
from aes import AES
from key import Key
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

class Server:
    def __init__(self, addr, port=14167, buffer_size=1024):
        self.addr = addr
        self.port = port
        self.buffer_size = buffer_size

        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.bind((self.addr, self.port))
        self.s.listen(1)
        self.conn, self.addr = self.s.accept()

    def send(self, msg_bytes: bytes):
        self.conn.send(msg_bytes)

    def recv(self, buffer_size=None) -> bytes:
        if buffer_size is None:
            buffer_size = self.buffer_size
        msg_bytes = self.conn.recv(buffer_size)
        return msg_bytes

    def close(self):
        self.conn.close()


if __name__ == '__main__':

    server = Server('localhost', 14167)
    private_key = rsa.generate_private_key(public_exponent= 3, key_size=2048)
    public_key = private_key.public_key()
    public_dev = public_key.public_bytes(
        encoding = serialization.Encoding.PEM,
        format = serialization.PublicFormat.SubjectPublicKeyInfo
    )
    server.send(public_dev)

    encrypted_key = server.recv(4096)
    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf = padding.MGF1(algorithm = hashes.SHA256()),
            algorithm = hashes.SHA256(),
            label = None
        )
    )

    aes = AES(aes_key)

    #Looped chat
    while True:
        data = server.recv(4096)
        if not data:
            print("Client disconnected.")
            break

        try:
            ciphertext_recv, digest_recv = data.split(b'||')
        except ValueError:
            print("Received malformed message (missing delimiter).")
            continue

        # Verify integrity
        new_digest = hashlib.sha256(ciphertext_recv).digest()
        if new_digest != digest_recv:
            print("Message integrity check FAILED!")
            continue

        # Decrypt message
        msg_recv = aes.decrypt(ciphertext_recv)
        print("From connected client:", msg_recv)

        if msg_recv.lower() == 'exit':
            print("Client exited chat.")
            break

        # Input server response
        msg_send = input('> ')
        ciphertext = aes.encrypt(msg_send)
        digest = hashlib.sha256(ciphertext).digest()
        server.send(ciphertext + b'||' + digest)

        if msg_send.lower() == 'exit':
            print("Exiting chat...")
            break

    server.close()
