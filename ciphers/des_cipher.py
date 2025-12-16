from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

class DESCipher:
    @staticmethod
    def encrypt(text, key):
        """
        text: string
        key: string (kullanıcıdan alınan)
        return: bytes
        """
        key_bytes = key.ljust(8, "0")[:8].encode()
        cipher = DES.new(key_bytes, DES.MODE_ECB)
        encrypted = cipher.encrypt(pad(text.encode(), DES.block_size))
        return encrypted

    @staticmethod
    def decrypt(cipher_bytes, key):
        """
        cipher_bytes: bytes
        key: string (kullanıcıdan alınan)
        return: string (decrypt edilmiş)
        """
        key_bytes = key.ljust(8, "0")[:8].encode()
        cipher = DES.new(key_bytes, DES.MODE_ECB)
        decrypted = unpad(cipher.decrypt(cipher_bytes), DES.block_size)
        return decrypted.decode()
