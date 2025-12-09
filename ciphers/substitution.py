import string
LETTERS = string.ascii_uppercase

class SubstitutionCipher:
    @staticmethod
    def encrypt(text, key):
        key = key.upper()
        table = {LETTERS[i]: key[i] for i in range(26)}
        return ''.join(table.get(c, c) for c in text.upper())

    @staticmethod
    def decrypt(text, key):
        key = key.upper()
        table = {key[i]: LETTERS[i] for i in range(26)}
        return ''.join(table.get(c, c) for c in text.upper())
