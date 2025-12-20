from ciphers.rsa_cipher import RSACipher


class RSAMessageCipher:

    MAX_LEN = 190

    @staticmethod
    def encrypt(text: str, key=None) -> bytes:
        data = text.encode("utf-8")

        if len(data) > RSAMessageCipher.MAX_LEN:
            raise ValueError(
                "RSA ile şifreleme için mesaj çok uzun."
            )

        return RSACipher.encrypt(data)

    @staticmethod
    def decrypt(ciphertext: bytes, key=None) -> str:
        decrypted = RSACipher.decrypt(ciphertext)
        return decrypted.decode("utf-8")
