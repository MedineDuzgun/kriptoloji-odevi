from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

class AESCipher:
    @staticmethod
    def encrypt(text, key):
        key = key.ljust(16, "0")[:16].encode()
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.encrypt(pad(text.encode(), 16)).hex()

    @staticmethod
    def decrypt(text, key):
        key = key.ljust(16, "0")[:16].encode()
        cipher = AES.new(key, AES.MODE_ECB)
        data = bytes.fromhex(text)
        return unpad(cipher.decrypt(data), 16).decode()
