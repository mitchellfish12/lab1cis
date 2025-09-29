
import random
import secrets


class Key:
    """
    A simple key class that generates, reads, and writes keys.
    """

    def __init__(self):
        self.key = None
        # do we need to initialize anything?

    def gen(self, key_len: int) -> bytes:
        # TODO: generate a random key
        array_size = key_len // 8
        return secrets.token_bytes(array_size)
    
    def read(self, key_file: str) -> bytes:
        # TODO: read key from file
        with open(key_file, 'rb') as b:
            return b.read()

    def write(self, key: bytes, key_file: str) -> None:
        # TODO: write key to file
        with open(key_file, 'wb') as b:
            b.write(key)


if __name__ == '__main__':
    key = Key()
    key_len = 256

    # generate a random key
    key_bytes = key.gen(key_len)
    print("Generated key:")
    print(key_bytes.hex())

    # write the key to a file
    key_file = 'key.bytes'
    key.write(key_bytes, key_file)
    print("Key written to file:", key_file)

    # read the key from a file
    key_bytes = key.read(key_file)
    print("Read key from file:", key_file)
    print("Key:")
    print(key_bytes.hex())
