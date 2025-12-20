from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


class AESCipher:
    @staticmethod
    def encrypt(text, key):
        if isinstance(key, str):
            key = key.encode()

        key = key.ljust(16, b'\x00')[:16]

        cipher = AES.new(key, AES.MODE_ECB)
        encrypted = cipher.encrypt(pad(text.encode(), AES.block_size))
        return encrypted

    @staticmethod
    def decrypt(cipher_bytes, key):
        if isinstance(key, str):
            key = key.encode()

        key = key.ljust(16, b'\x00')[:16]

        cipher = AES.new(key, AES.MODE_ECB)
        decrypted = unpad(cipher.decrypt(cipher_bytes), AES.block_size)
        return decrypted.decode()
