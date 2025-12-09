from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

class DESCipher:
    @staticmethod
    def encrypt(text, key):
        key = key.ljust(8, "0")[:8].encode()
        cipher = DES.new(key, DES.MODE_ECB)
        return cipher.encrypt(pad(text.encode(), 8)).hex()

    @staticmethod
    def decrypt(text, key):
        key = key.ljust(8, "0")[:8].encode()
        cipher = DES.new(key, DES.MODE_ECB)
        data = bytes.fromhex(text)
        return unpad(cipher.decrypt(data), 8).decode()
