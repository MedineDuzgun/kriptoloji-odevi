from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os


class RSACipher:
    PRIVATE_KEY_FILE = "private.pem"
    PUBLIC_KEY_FILE = "public.pem"

    @staticmethod
    def generate_keys():
        if os.path.exists(RSACipher.PRIVATE_KEY_FILE):
            return

        key = RSA.generate(2048)

        with open(RSACipher.PRIVATE_KEY_FILE, "wb") as f:
            f.write(key.export_key())

        with open(RSACipher.PUBLIC_KEY_FILE, "wb") as f:
            f.write(key.publickey().export_key())

    @staticmethod
    def encrypt(data: bytes) -> bytes:
        with open(RSACipher.PUBLIC_KEY_FILE, "rb") as f:
            pub_key = RSA.import_key(f.read())

        cipher = PKCS1_OAEP.new(pub_key)
        return cipher.encrypt(data)

    @staticmethod
    def decrypt(data: bytes) -> bytes:
        with open(RSACipher.PRIVATE_KEY_FILE, "rb") as f:
            priv_key = RSA.import_key(f.read())

        cipher = PKCS1_OAEP.new(priv_key)
        return cipher.decrypt(data)
