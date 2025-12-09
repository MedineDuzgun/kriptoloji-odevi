import string
LETTERS = string.ascii_uppercase

class AffineCipher:
    @staticmethod
    def encrypt(text, key):
        a, b = map(int, key.split(","))
        return ''.join(
            LETTERS[(a * LETTERS.index(c) + b) % 26] if c in LETTERS else c
            for c in text.upper()
        )

    @staticmethod
    def decrypt(text, key):
        a, b = map(int, key.split(","))
        a_inv = pow(a, -1, 26)
        return ''.join(
            LETTERS[(a_inv * (LETTERS.index(c) - b)) % 26] if c in LETTERS else c
            for c in text.upper()
        )
