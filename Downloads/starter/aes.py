import random
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class AES:
    """
    A simple AES ECB wrapper for encryption and decryption.
    Padding is handled by adding null bytes to the end of the plaintext.
    Trailing whitespace in messages is removed after decryption.
    """

    def __init__(self, key: bytes):
        self.key = key
        self.key_len = len(key) * 8
        self.cipher = Cipher(algorithms.AES(key), modes.ECB())

    def encrypt(self, plaintext: str) -> bytes:
        plaintext_bytes = bytes(plaintext, 'ascii')
        block_size = self.key_len // 8
        plaintext_bytes += b'\x00' * (block_size - len(plaintext_bytes) % block_size)
        encryptor = self.cipher.encryptor()  # <-- create new encryptor each call
        return encryptor.update(plaintext_bytes) + encryptor.finalize()

    def decrypt(self, ciphertext: bytes) -> str:
        decryptor = self.cipher.decryptor()  # <-- create new decryptor each call
        decrypted_bytes = decryptor.update(ciphertext) + decryptor.finalize()
        return bytes.decode(decrypted_bytes, 'ascii').rstrip('\x00')

if __name__ == '__main__':
    key_len = 256
    key = bytes([random.randint(0, 255) for _ in range(key_len // 8)])
    cryptor = AES(key)
    plaintext = "Hello! I am Mitchell"
    ciphertext = cryptor.encrypt(plaintext)
    decrypted = cryptor.decrypt(ciphertext)
    print(f"plaintext: {plaintext}")
    print(f"ciphertext: {ciphertext.hex()}")
    print(f"decrypted: {decrypted}")
    assert plaintext == decrypted, "Incorrect decryption!"
