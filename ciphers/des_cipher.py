from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad


class DESCipher:
    @staticmethod
    def encrypt(text, key):
        if isinstance(key, str):
            key = key.encode()

        key = key.ljust(8, b'\x00')[:8]

        cipher = DES.new(key, DES.MODE_ECB)
        encrypted = cipher.encrypt(pad(text.encode(), DES.block_size))
        return encrypted

    @staticmethod
    def decrypt(cipher_bytes, key):
        if isinstance(key, str):
            key = key.encode()

        key = key.ljust(8, b'\x00')[:8]

        cipher = DES.new(key, DES.MODE_ECB)
        decrypted = unpad(cipher.decrypt(cipher_bytes), DES.block_size)
        return decrypted.decode()
