
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

class RSACipher:
    PRIVATE_KEY = None
    PUBLIC_KEY = None

    @staticmethod
    def generate_keys():
        key = RSA.generate(2048)
        RSACipher.PRIVATE_KEY = key
        RSACipher.PUBLIC_KEY = key.publickey()

    @staticmethod
    def encrypt(text, key=None):
        if RSACipher.PUBLIC_KEY is None:
            RSACipher.generate_keys()

        cipher = PKCS1_OAEP.new(RSACipher.PUBLIC_KEY)
        encrypted = cipher.encrypt(text.encode())
        return base64.b64encode(encrypted).decode()

    @staticmethod
    def decrypt(text, key=None):
        if RSACipher.PRIVATE_KEY is None:
            RSACipher.generate_keys()

        cipher = PKCS1_OAEP.new(RSACipher.PRIVATE_KEY)
        data = base64.b64decode(text.encode())
        return cipher.decrypt(data).decode()
