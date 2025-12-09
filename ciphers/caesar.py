import string
LETTERS = string.ascii_uppercase

class CaesarCipher:
    @staticmethod
    def encrypt(text, key):
        key = int(key)
        return ''.join(LETTERS[(LETTERS.index(c) + key) % 26] if c in LETTERS else c for c in text.upper())

    @staticmethod
    def decrypt(text, key):
        key = int(key)
        return ''.join(LETTERS[(LETTERS.index(c) - key) % 26] if c in LETTERS else c for c in text.upper())
