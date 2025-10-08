import socket
import hashlib
import os
from aes import AES
from key import Key
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

class Client:
    def __init__(self, addr, port=14167, buffer_size=4096):
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
        return self.s.recv(buffer_size)

    def close(self):
        self.s.close()


if __name__ == '__main__':

    client = Client('localhost', 14167)
    public_bytes = client.recv()
    public_key = serialization.load_pem_public_key(public_bytes)
    aes_key = os.urandom(32)
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf = padding.MGF1(algorithm = hashes.SHA256()),
            algorithm = hashes.SHA256(),
            label = None
        )
    )
    client.send(encrypted_key)

    aes = AES(aes_key)

    print("=== Secure Chat Started ===")
    print("Type 'exit' to quit.\n")

    while True:
        # Input message from user
        msg = input('You: ')

        if msg.lower() == 'exit':
            print("Exiting chat...")
            break

        # Encrypt message
        ciphertext = aes.encrypt(msg)


        # Compute SHA256 hash of ciphertext for integrity
        digest = hashlib.sha256(ciphertext).digest()

        # Optional pause to test Step 5 tampering
        #input("Paused before sending. Press Enter to send...")
        # To simulate tampering, uncomment the next line:
        #ciphertext = ciphertext[:-1] + b'\x00'  

        # Send ciphertext + hash
        client.send(ciphertext + b'||' + digest)

        # Receive response
        data = client.recv()
        if not data:
            print("Server disconnected.")
            break

        try:
            ciphertext_recv, digest_recv = data.split(b'||')
        except ValueError:
            print("Received malformed message (missing delimiter).")
            continue

        # Verify integrity
        if hashlib.sha256(ciphertext_recv).digest() != digest_recv:
            print("Message integrity check FAILED!")
            continue

        # Decrypt and display server message
        msg_recv = aes.decrypt(ciphertext_recv)
        print("Server:", msg_recv)

    client.close()