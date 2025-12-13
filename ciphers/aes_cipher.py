# ciphers/aes_cipher.py
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

class AESCipher:
    @staticmethod
    def encrypt(text, key):
        """
        text: string
        key: string (kullanıcıdan alınan)
        return: bytes
        """
        # AES → 16 byte key
        key_bytes = key.ljust(16, "0")[:16].encode()
        cipher = AES.new(key_bytes, AES.MODE_ECB)
        encrypted = cipher.encrypt(pad(text.encode(), AES.block_size))
        return encrypted

    @staticmethod
    def decrypt(cipher_bytes, key):
        """
        cipher_bytes: bytes
        key: string (kullanıcıdan alınan)
        return: string (decrypt edilmiş)
        """
        key_bytes = key.ljust(16, "0")[:16].encode()
        cipher = AES.new(key_bytes, AES.MODE_ECB)
        decrypted = unpad(cipher.decrypt(cipher_bytes), AES.block_size)
        return decrypted.decode()
