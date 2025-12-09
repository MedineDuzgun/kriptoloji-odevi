class VernamCipher:
    @staticmethod
    def encrypt(text, key):
        return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(text, key))

    @staticmethod
    def decrypt(text, key):
        return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(text, key))
